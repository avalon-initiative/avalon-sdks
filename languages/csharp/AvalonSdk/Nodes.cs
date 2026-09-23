// GET /nodes/status — public, unauthenticated.

using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

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
    }
}
