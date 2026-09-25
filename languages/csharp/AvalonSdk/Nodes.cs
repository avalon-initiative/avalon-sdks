// GET /nodes/status — public, unauthenticated.

using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using ProbeRequest = Avalon.Sdk.Generated.ProbeRequest;
using ProbeResponse = Avalon.Sdk.Generated.ProbeResponse;
using TopologyResponse = Avalon.Sdk.Generated.TopologyResponse;
using TraceRequest = Avalon.Sdk.Generated.TraceRequest;
using TraceResponse = Avalon.Sdk.Generated.TraceResponse;

namespace Avalon.Sdk
{
    /// <summary>GET /nodes/status's wire response — matches
    /// crates/server/src/nodes.rs::NodeStatusResponse. Only the fields this
    /// SDK exposes; the real response also carries resources and
    /// own_shard_replication, omitted here since nothing in this SDK reads
    /// them.</summary>
    public sealed class NodeStatus
    {
        [JsonPropertyName("protocol_version")]
        public string ProtocolVersion { get; set; } = "";

        [JsonPropertyName("network_id")]
        public string NetworkId { get; set; } = "";

        /// <summary>This node's configured AVALON_NODE_ROLES — "combined"
        /// reported as-is, not expanded.</summary>
        [JsonPropertyName("roles")]
        public List<string> Roles { get; set; } = new List<string>();

        [JsonPropertyName("stale")]
        public bool Stale { get; set; }

        [JsonPropertyName("newest_known_peer_version")]
        public string? NewestKnownPeerVersion { get; set; }
    }

    public sealed partial class AvalonClient
    {
        /// <summary>GET /nodes/status for this client's configured server —
        /// Roles reports which of settlement/indexer/realtime/gateway this
        /// node runs.</summary>
        public async Task<NodeStatus> GetNodeStatusAsync(CancellationToken ct = default)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"{_config.ServerUrl}/nodes/status");
            using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw await Session.ServerErrorAsync(response).ConfigureAwait(false);
            }
            return await Session.ReadJsonAsync<NodeStatus>(response, ct).ConfigureAwait(false);
        }

        /// <summary>GET /nodes/topology on <paramref name="nodeUrl"/>, or on this client's
        /// configured server when null: that node's own view of its neighbors, known peers and
        /// mirror sources. Unauthenticated and read-only.</summary>
        public async Task<TopologyResponse> TopologyAsync(string? nodeUrl = null, CancellationToken ct = default)
        {
            var baseUrl = (nodeUrl ?? _config.ServerUrl).TrimEnd('/');
            using var request = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/nodes/topology");
            return await SendNodeRequestAsync<TopologyResponse>(request, ct).ConfigureAwait(false);
        }

        /// <summary>POST /nodes/probe: this node measures its round trip to
        /// <paramref name="target"/>, which must be in its peer table. samples is 1 to 3 (server
        /// default 1).</summary>
        public async Task<ProbeResponse> ProbeAsync(string target, int? samples = null, CancellationToken ct = default)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, $"{_config.ServerUrl}/nodes/probe") { Content = NodeJson(new ProbeRequest { Target = target, Samples = samples }) };
            return await SendNodeRequestAsync<ProbeResponse>(request, ct).ConfigureAwait(false);
        }

        /// <summary>POST /nodes/trace: the overlay route from this node to <paramref name="target"/>.
        /// Every hop is self-reported by the node it names, so the path is advisory and not
        /// verified. ttl is 1 to 16 (server default 12).</summary>
        public async Task<TraceResponse> TraceAsync(string target, int? ttl = null, CancellationToken ct = default)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, $"{_config.ServerUrl}/nodes/trace") { Content = NodeJson(new TraceRequest { Target = target, Ttl = ttl }) };
            return await SendNodeRequestAsync<TraceResponse>(request, ct).ConfigureAwait(false);
        }

        private static StringContent NodeJson<TBody>(TBody body) =>
            new StringContent(JsonSerializer.Serialize(body, NodeRequestOptions), Encoding.UTF8, "application/json");

        private static readonly JsonSerializerOptions NodeRequestOptions = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        };

        private async Task<T> SendNodeRequestAsync<T>(HttpRequestMessage request, CancellationToken ct) where T : class
        {
            using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw await Session.ServerErrorAsync(response).ConfigureAwait(false);
            }
            return await Session.ReadJsonAsync<T>(response, ct).ConfigureAwait(false);
        }
    }
}
