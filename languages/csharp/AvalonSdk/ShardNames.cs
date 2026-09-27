// Shard names: domain-proven names bound to self-certifying shard ids.

using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using NameClaimRequest = Avalon.Sdk.Generated.NameClaimRequest;
using NameClaimResponse = Avalon.Sdk.Generated.NameClaimResponse;

namespace Avalon.Sdk
{
    public sealed partial class AvalonClient
    {
        /// <summary>GET /shards/name/{name} on <paramref name="nodeUrl"/>, or on this client's
        /// configured server when null: the shard whose owner has proven control of the name.
        /// Unauthenticated.</summary>
        public async Task<NameClaimResponse> ResolveNameAsync(string name, string? nodeUrl = null, CancellationToken ct = default)
        {
            var baseUrl = (nodeUrl ?? _config.ServerUrl).TrimEnd('/');
            var encoded = System.Uri.EscapeDataString(name);
            var url = $"{baseUrl}/shards/name/{encoded}";
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            return await SendNodeRequestAsync<NameClaimResponse>(request, ct).ConfigureAwait(false);
        }

        /// <summary>GET /shards/{id}/name-claims: the names bound to a self-certifying shard id.</summary>
        public async Task<List<NameClaimResponse>> ListShardNamesAsync(string selfCertifyingId, string? nodeUrl = null, CancellationToken ct = default)
        {
            var baseUrl = (nodeUrl ?? _config.ServerUrl).TrimEnd('/');
            var encoded = System.Uri.EscapeDataString(selfCertifyingId);
            var url = $"{baseUrl}/shards/{encoded}/name-claims";
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            return await SendNodeRequestAsync<List<NameClaimResponse>>(request, ct).ConfigureAwait(false);
        }

        /// <summary>POST /shards/{id}/name-claims: submits an already-signed claim binding the
        /// claim's name to the shard. The claim must be signed with the shard's own key; the node
        /// checks the proof itself.</summary>
        public async Task<NameClaimResponse> SubmitNameClaimAsync(NameClaimRequest claim, string? nodeUrl = null, CancellationToken ct = default)
        {
            var baseUrl = (nodeUrl ?? _config.ServerUrl).TrimEnd('/');
            var encoded = System.Uri.EscapeDataString(claim.SelfCertifyingId);
            var url = $"{baseUrl}/shards/{encoded}/name-claims";
            using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = NodeJson(claim) };
            return await SendNodeRequestAsync<NameClaimResponse>(request, ct).ConfigureAwait(false);
        }
    }
}
