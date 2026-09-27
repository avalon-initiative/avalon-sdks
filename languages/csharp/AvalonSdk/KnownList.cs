// Client-built known list of witnesses: advert proof verification, the diversity prefix and
// selection rules, discovery through the trust-anchor seeds, and an equivocation cross-check.
// conformance/vectors/witness-announce.json and known-list-selection.json are the arbiters.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Avalon.Sdk
{
    /// <summary>One discovered witness, keyed by the witness key its advert proved.</summary>
    public sealed class KnownListCandidate
    {
        public KnownListCandidate(string witnessKeyId, string baseUrl, bool isAnchor)
        {
            WitnessKeyId = witnessKeyId;
            BaseUrl = baseUrl;
            IsAnchor = isAnchor;
        }

        public string WitnessKeyId { get; }
        public string BaseUrl { get; }
        public bool IsAnchor { get; }
    }

    /// <summary>Tunables for building a known list; the defaults are the protocol's.</summary>
    public sealed class KnownListOptions
    {
        public int Capacity { get; set; } = KnownListRules.DefaultCapacity;
        public int AnchorCapacity { get; set; } = KnownListRules.DefaultAnchorCapacity;
        public int MaxPerPrefix { get; set; } = KnownListRules.DefaultMaxPerPrefix;

        /// <summary>Per-request timeout for discovery, reachability and cross-check requests.</summary>
        public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(5);

        /// <summary>Upper-exclusive random integer source used to shuffle non-anchor candidates;
        /// cryptographically secure by default, injectable for deterministic tests.</summary>
        public Func<int, int> RandomInt { get; set; } = upper => RandomNumberGenerator.GetInt32(upper);

        /// <summary>The clock advert freshness is judged against.</summary>
        public Func<DateTimeOffset> Clock { get; set; } = () => DateTimeOffset.UtcNow;
    }

    /// <summary>How network verification treats witness cosignatures.</summary>
    public sealed class WitnessPolicy
    {
        private WitnessPolicy(string kind, IReadOnlyList<KnownWitness>? list, KnownListOptions? options)
        {
            Kind = kind;
            List = list;
            Options = options;
        }

        internal string Kind { get; }
        internal IReadOnlyList<KnownWitness>? List { get; }
        internal KnownListOptions? Options { get; }
        internal bool IsNone => Kind == "none";

        /// <summary>Build the known list from the trust-anchor seeds and verified adverts (default).</summary>
        public static WitnessPolicy Auto { get; } = new WitnessPolicy("auto", null, null);

        /// <summary>Build automatically with non-default limits.</summary>
        public static WitnessPolicy AutoWith(KnownListOptions options) => new WitnessPolicy("auto", null, options);

        /// <summary>Only the author-signature check.</summary>
        public static WitnessPolicy None { get; } = new WitnessPolicy("none", null, null);

        /// <summary>The caller's own known list.</summary>
        public static WitnessPolicy Explicit(IReadOnlyList<KnownWitness> list) => new WitnessPolicy("explicit", list, null);
    }

    /// <summary>Two author-signed heads of one network and tree size with different roots.</summary>
    public sealed class EquivocationEvidence
    {
        public EquivocationEvidence(long treeSize, string rootA, string rootB, IReadOnlyList<string> sources, IReadOnlyList<string> witnesses)
        {
            TreeSize = treeSize;
            RootA = rootA;
            RootB = rootB;
            Sources = sources;
            Witnesses = witnesses;
        }

        public long TreeSize { get; }

        /// <summary>The accepted head's root.</summary>
        public string RootA { get; }

        /// <summary>The conflicting root.</summary>
        public string RootB { get; }

        /// <summary>Base urls that served the conflicting head.</summary>
        public IReadOnlyList<string> Sources { get; }

        /// <summary>Witnesses that validly cosigned both heads, per <see cref="WitnessCosigning.FindEquivocatingWitnesses"/>.</summary>
        public IReadOnlyList<string> Witnesses { get; }
    }

    /// <summary>Advert proofs, the diversity prefix and the deterministic selection rule.</summary>
    public static class KnownListRules
    {
        public const int DefaultCapacity = 5;
        public const int DefaultAnchorCapacity = 2;
        public const int DefaultMaxPerPrefix = 2;

        /// <summary>How far an advert's timestamp may differ from the verifier's clock.</summary>
        public static readonly TimeSpan AnnounceMaxSkew = TimeSpan.FromHours(1);

        /// <summary>The exact bytes a witness announce proof covers.</summary>
        public static byte[] WitnessAnnounceMessage(string baseUrl, string witnessKeyId, DateTimeOffset announcedAt)
        {
            var message = new List<byte>();
            message.AddRange(Encoding.UTF8.GetBytes("avalon-witness-announce-v1"));
            WitnessCosigning.AddLengthPrefixed(message, baseUrl);
            WitnessCosigning.AddLengthPrefixed(message, witnessKeyId);
            message.AddRange(WitnessCosigning.BigEndian(announcedAt.ToUnixTimeSeconds()));
            return message.ToArray();
        }

        /// <summary>Verifies an advert proof; false for any malformed or stale input, never throws.</summary>
        public static bool VerifyWitnessAnnounce(
            string baseUrl, string witnessKeyId, DateTimeOffset announcedAt, string proofHex, DateTimeOffset now)
        {
            try
            {
                if ((now - announcedAt).Duration() > AnnounceMaxSkew)
                {
                    return false;
                }
                var key = WitnessCosigning.TryHex(witnessKeyId);
                var signature = WitnessCosigning.TryHex(proofHex);
                if (key == null || key.Length != 32 || signature == null || signature.Length != 64)
                {
                    return false;
                }
                var message = WitnessAnnounceMessage(baseUrl, witnessKeyId, announcedAt);
                var signer = new Ed25519Signer();
                signer.Init(false, new Ed25519PublicKeyParameters(key, 0));
                signer.BlockUpdate(message, 0, message.Length);
                return signer.VerifySignature(signature);
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>The diversity prefix for <paramref name="baseUrl"/>, or null when it is not an
        /// acceptable node url. No DNS: IPv4 gives its /24, IPv6 its /48, a hostname its last two labels.</summary>
        public static string? DiversityPrefixForUrl(string baseUrl)
        {
            if (baseUrl == null || baseUrl.Any(c => c > 127 || c <= 0x20 || c == 0x7f))
            {
                return null;
            }
            var lower = baseUrl.ToLowerInvariant();
            string rest;
            if (lower.StartsWith("http://", StringComparison.Ordinal))
            {
                rest = lower.Substring(7);
            }
            else if (lower.StartsWith("https://", StringComparison.Ordinal))
            {
                rest = lower.Substring(8);
            }
            else
            {
                return null;
            }
            string authority;
            var cut = rest.IndexOfAny(new[] { '/', '?', '#' });
            if (cut >= 0)
            {
                if (rest.Substring(cut) != "/")
                {
                    return null;
                }
                authority = rest.Substring(0, cut);
            }
            else
            {
                authority = rest;
            }
            if (authority.Length == 0 || authority.Contains('@'))
            {
                return null;
            }

            string host;
            string? port;
            if (authority.StartsWith("[", StringComparison.Ordinal))
            {
                var close = authority.IndexOf(']');
                if (close < 0)
                {
                    return null;
                }
                host = authority.Substring(0, close + 1);
                var tail = authority.Substring(close + 1);
                if (tail.Length == 0)
                {
                    port = null;
                }
                else if (tail.StartsWith(":", StringComparison.Ordinal))
                {
                    port = tail.Substring(1);
                }
                else
                {
                    return null;
                }
            }
            else
            {
                var parts = authority.Split(':');
                if (parts.Length > 2)
                {
                    return null;
                }
                host = parts[0];
                port = parts.Length == 2 ? parts[1] : null;
            }
            if (port != null && !ValidPort(port))
            {
                return null;
            }

            if (host.StartsWith("[", StringComparison.Ordinal) && host.EndsWith("]", StringComparison.Ordinal))
            {
                var inner = host.Substring(1, host.Length - 2);
                if (inner.Contains('.'))
                {
                    return null;
                }
                var groups = ParseIpv6(inner);
                if (groups == null)
                {
                    return null;
                }
                return $"v6:{groups[0]:x}:{groups[1]:x}:{groups[2]:x}::/48";
            }

            if (host.EndsWith(".", StringComparison.Ordinal))
            {
                host = host.Substring(0, host.Length - 1);
            }
            if (host.Length > 0 && host.All(c => (c >= '0' && c <= '9') || c == '.') && host.Contains('.'))
            {
                var octets = ParseIpv4(host);
                return octets == null ? null : $"v4:{octets[0]}.{octets[1]}.{octets[2]}.0/24";
            }
            if (!ValidHostname(host))
            {
                return null;
            }
            var labels = host.Split('.');
            var keep = labels.Length >= 2 ? labels.Skip(labels.Length - 2) : labels;
            return "host:" + string.Join(".", keep);
        }

        /// <summary>Admitted witness key ids in admission order. Anchors are considered first in the
        /// order given, then the rest in the order given; a candidate without a prefix is skipped;
        /// admission is refused for a duplicate key id, a full anchor quota, a full list or a full prefix.</summary>
        public static IReadOnlyList<string> SelectKnownList(
            IReadOnlyList<KnownListCandidate> candidates,
            int capacity = DefaultCapacity,
            int anchorCapacity = DefaultAnchorCapacity,
            int maxPerPrefix = DefaultMaxPerPrefix)
        {
            anchorCapacity = Math.Min(anchorCapacity, capacity);
            var admitted = new List<(string Id, string Prefix, bool Anchor)>();
            foreach (var pass in new[] { true, false })
            {
                foreach (var candidate in candidates.Where(c => c.IsAnchor == pass))
                {
                    var prefix = DiversityPrefixForUrl(candidate.BaseUrl);
                    if (prefix == null
                        || admitted.Any(a => a.Id == candidate.WitnessKeyId)
                        || (candidate.IsAnchor && admitted.Count(a => a.Anchor) >= anchorCapacity)
                        || admitted.Count >= capacity
                        || admitted.Count(a => a.Prefix == prefix) >= maxPerPrefix)
                    {
                        continue;
                    }
                    admitted.Add((candidate.WitnessKeyId, prefix, candidate.IsAnchor));
                }
            }
            return admitted.Select(a => a.Id).ToList();
        }

        private static bool ValidPort(string port) =>
            port.Length >= 1 && port.Length <= 5 && port.All(c => c >= '0' && c <= '9')
            && int.Parse(port) >= 1 && int.Parse(port) <= 65535;

        private static bool ValidHostname(string host) =>
            host.Length > 0 && host.Split('.').All(label =>
                label.Length > 0
                && label.All(c => (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')
                && label[0] != '-' && label[label.Length - 1] != '-');

        private static int[]? ParseIpv4(string host)
        {
            var parts = host.Split('.');
            if (parts.Length != 4)
            {
                return null;
            }
            var octets = new int[4];
            for (var i = 0; i < 4; i++)
            {
                var p = parts[i];
                if (p.Length == 0 || p.Length > 3 || (p.Length > 1 && p[0] == '0') || !p.All(c => c >= '0' && c <= '9'))
                {
                    return null;
                }
                octets[i] = int.Parse(p);
                if (octets[i] > 255)
                {
                    return null;
                }
            }
            return octets;
        }

        private static int[]? ParseIpv6(string text)
        {
            var double_ = text.IndexOf("::", StringComparison.Ordinal);
            if (double_ >= 0 && text.IndexOf("::", double_ + 1, StringComparison.Ordinal) >= 0)
            {
                return null;
            }
            List<int>? Groups(string part)
            {
                var result = new List<int>();
                if (part.Length == 0)
                {
                    return result;
                }
                foreach (var g in part.Split(':'))
                {
                    if (g.Length < 1 || g.Length > 4 || !g.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                    {
                        return null;
                    }
                    result.Add(Convert.ToInt32(g, 16));
                }
                return result;
            }
            if (double_ < 0)
            {
                var all = Groups(text);
                return all != null && all.Count == 8 ? all.ToArray() : null;
            }
            var head = Groups(text.Substring(0, double_));
            var tail = Groups(text.Substring(double_ + 2));
            if (head == null || tail == null || head.Count + tail.Count > 7)
            {
                return null;
            }
            var full = new int[8];
            head.CopyTo(full, 0);
            tail.CopyTo(full, 8 - tail.Count);
            return full;
        }
    }

    /// <summary>Discovers witnesses through a network's trust-anchor seeds, filters them by
    /// liveness and diversity, and cross-checks accepted heads.</summary>
    public static class KnownListBuilder
    {
        private sealed class Advert
        {
            public string BaseUrl = "";
            public string KeyId = "";
        }

        /// <summary>Lowercases scheme and host and strips one trailing slash.</summary>
        internal static string NormalizeUrl(string url)
        {
            var trimmed = url.EndsWith("/", StringComparison.Ordinal) ? url.Substring(0, url.Length - 1) : url;
            var schemeEnd = trimmed.IndexOf("://", StringComparison.Ordinal);
            if (schemeEnd < 0)
            {
                return trimmed.ToLowerInvariant();
            }
            var pathStart = trimmed.IndexOf('/', schemeEnd + 3);
            return pathStart < 0
                ? trimmed.ToLowerInvariant()
                : trimmed.Substring(0, pathStart).ToLowerInvariant() + trimmed.Substring(pathStart);
        }

        /// <summary>Queries every seed of <paramref name="entry"/> and returns the adverts that
        /// pass: right network, valid proof for that exact url and key, first seen per key id.
        /// A failed seed is skipped.</summary>
        public static async Task<IReadOnlyList<KnownListCandidate>> DiscoverCandidatesAsync(
            HttpClient http, TrustAnchorEntry entry, KnownListOptions? options = null, CancellationToken ct = default)
        {
            options ??= new KnownListOptions();
            var seeds = entry.SeedNodes;
            var perSeed = await Task.WhenAll(seeds.Select(seed => FetchPeersAsync(http, seed, options, ct))).ConfigureAwait(false);
            var seedIndex = new Dictionary<string, int>();
            for (var i = 0; i < seeds.Count; i++)
            {
                var key = NormalizeUrl(seeds[i]);
                if (!seedIndex.ContainsKey(key))
                {
                    seedIndex[key] = i;
                }
            }
            var now = options.Clock();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            var found = new List<(KnownListCandidate Candidate, int Anchor)>();
            foreach (var peers in perSeed)
            {
                foreach (var peer in peers)
                {
                    var admitted = TryAdmit(peer, entry.NetworkId, now);
                    if (admitted == null || !seen.Add(admitted.KeyId))
                    {
                        continue;
                    }
                    var anchor = seedIndex.TryGetValue(NormalizeUrl(admitted.BaseUrl), out var index) ? index : -1;
                    found.Add((new KnownListCandidate(admitted.KeyId, admitted.BaseUrl, anchor >= 0), anchor));
                }
            }
            return found.Select(f => f.Candidate).ToList();
        }

        private static Advert? TryAdmit(JsonElement peer, string networkId, DateTimeOffset now)
        {
            try
            {
                if (peer.ValueKind != JsonValueKind.Object
                    || !peer.TryGetProperty("network_id", out var net) || net.GetString() != networkId
                    || !peer.TryGetProperty("base_url", out var urlEl) || urlEl.ValueKind != JsonValueKind.String
                    || !peer.TryGetProperty("witness", out var w) || w.ValueKind != JsonValueKind.Object)
                {
                    return null;
                }
                var baseUrl = urlEl.GetString()!;
                var keyId = w.GetProperty("key_id").GetString()!;
                var proof = w.GetProperty("proof").GetString()!;
                var announcedAt = DateTimeOffset.Parse(
                    w.GetProperty("announced_at").GetString()!, System.Globalization.CultureInfo.InvariantCulture);
                return KnownListRules.VerifyWitnessAnnounce(baseUrl, keyId, announcedAt, proof, now)
                    ? new Advert { BaseUrl = baseUrl, KeyId = keyId }
                    : null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        private static async Task<List<JsonElement>> FetchPeersAsync(
            HttpClient http, string seed, KnownListOptions options, CancellationToken ct)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(options.RequestTimeout);
                using var response = await http.GetAsync($"{seed.TrimEnd('/')}/nodes/discover", cts.Token).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                {
                    return new List<JsonElement>();
                }
                var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                using var doc = JsonDocument.Parse(body);
                if (!doc.RootElement.TryGetProperty("peers", out var peers) || peers.ValueKind != JsonValueKind.Array)
                {
                    return new List<JsonElement>();
                }
                return peers.EnumerateArray().Select(p => p.Clone()).ToList();
            }
            catch (Exception) when (!ct.IsCancellationRequested)
            {
                return new List<JsonElement>();
            }
        }

        /// <summary>Gathers candidates, orders them (anchors in seed order, the rest shuffled),
        /// probes for liveness in that order, then selects. Never throws for network failures.</summary>
        public static async Task<IReadOnlyList<KnownWitness>> BuildKnownListAsync(
            HttpClient http, TrustAnchorEntry entry, KnownListOptions? options = null, CancellationToken ct = default)
        {
            options ??= new KnownListOptions();
            var candidates = await DiscoverCandidatesAsync(http, entry, options, ct).ConfigureAwait(false);
            var seedOrder = entry.SeedNodes.Select(NormalizeUrl).ToList();
            var anchors = candidates.Where(c => c.IsAnchor)
                .OrderBy(c => seedOrder.IndexOf(NormalizeUrl(c.BaseUrl))).ToList();
            var rest = candidates.Where(c => !c.IsAnchor).ToList();
            for (var i = rest.Count - 1; i > 0; i--)
            {
                var j = options.RandomInt(i + 1);
                (rest[i], rest[j]) = (rest[j], rest[i]);
            }
            var ordered = anchors.Concat(rest).ToList();

            var alive = new List<KnownListCandidate>();
            IReadOnlyList<string> selected = Array.Empty<string>();
            var budget = Math.Min(ordered.Count, 3 * options.Capacity);
            for (var offset = 0; offset < budget; offset += 4)
            {
                var chunk = ordered.Skip(offset).Take(Math.Min(4, budget - offset)).ToList();
                var results = await Task.WhenAll(chunk.Select(c => ServesNetworkAsync(http, c.BaseUrl, entry.NetworkId, options, ct)))
                    .ConfigureAwait(false);
                for (var i = 0; i < chunk.Count; i++)
                {
                    if (results[i])
                    {
                        alive.Add(chunk[i]);
                    }
                }
                selected = KnownListRules.SelectKnownList(alive, options.Capacity, options.AnchorCapacity, options.MaxPerPrefix);
                if (selected.Count >= options.Capacity)
                {
                    break;
                }
            }
            var byId = alive.ToDictionary(c => c.WitnessKeyId);
            return selected.Select(id => new KnownWitness(id, id, byId[id].BaseUrl)).ToList();
        }

        private static async Task<bool> ServesNetworkAsync(
            HttpClient http, string baseUrl, string networkId, KnownListOptions options, CancellationToken ct)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(options.RequestTimeout);
                using var response = await http.GetAsync(
                    $"{baseUrl.TrimEnd('/')}/ledger/sth/latest?shard_id=core", cts.Token).ConfigureAwait(false);
                if (response.StatusCode != HttpStatusCode.OK)
                {
                    return false;
                }
                var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                using var doc = JsonDocument.Parse(body);
                return doc.RootElement.TryGetProperty("network_id", out var net) && net.GetString() == networkId;
            }
            catch (Exception) when (!ct.IsCancellationRequested)
            {
                return false;
            }
        }

        /// <summary>Asks each listed witness's node for the head at the accepted tree size and
        /// reports author-signed heads with a different root. Reports only: never throws and never
        /// changes a verification result.</summary>
        public static async Task<IReadOnlyList<EquivocationEvidence>> CrossCheckHeadAsync(
            HttpClient http,
            string authorVerifyKeyHex,
            IReadOnlyList<KnownWitness> knownList,
            CosignedTreeHead acceptedHead,
            KnownListOptions? options = null,
            CancellationToken ct = default)
        {
            try
            {
                options ??= new KnownListOptions();
                var targets = knownList.Where(w => w.BaseUrl != null).Take(3 * Math.Max(knownList.Count, 1)).ToList();
                using var gate = new SemaphoreSlim(4);
                var fetched = await Task.WhenAll(targets.Select(async w =>
                {
                    await gate.WaitAsync(ct).ConfigureAwait(false);
                    try
                    {
                        return (Source: w.BaseUrl!, Head: await FetchHeadAsync(http, w.BaseUrl!, acceptedHead.Sth.TreeSize, options, ct).ConfigureAwait(false));
                    }
                    finally
                    {
                        gate.Release();
                    }
                })).ConfigureAwait(false);

                var now = options.Clock();
                var cutoff = now - WitnessCosigning.DefaultFreshnessWindow;
                var evidence = new List<EquivocationEvidence>();
                foreach (var group in fetched.Where(f => f.Head != null).GroupBy(f => f.Head!.Sth.RootHash))
                {
                    var head = group.First().Head!;
                    if (head.Sth.NetworkId != acceptedHead.Sth.NetworkId
                        || head.Sth.TreeSize != acceptedHead.Sth.TreeSize
                        || head.Sth.RootHash == acceptedHead.Sth.RootHash
                        || !AvalonClient.VerifyTreeHeadHex(authorVerifyKeyHex, head.Sth))
                    {
                        continue;
                    }
                    var shared = WitnessCosigning.FindEquivocatingWitnesses(
                        authorVerifyKeyHex, knownList, cutoff, now, acceptedHead, head);
                    evidence.Add(new EquivocationEvidence(
                        head.Sth.TreeSize, acceptedHead.Sth.RootHash, head.Sth.RootHash,
                        group.Select(g => g.Source).ToList(), shared));
                }
                return evidence;
            }
            catch (Exception)
            {
                return Array.Empty<EquivocationEvidence>();
            }
        }

        private static async Task<CosignedTreeHead?> FetchHeadAsync(
            HttpClient http, string baseUrl, long treeSize, KnownListOptions options, CancellationToken ct)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(options.RequestTimeout);
                using var response = await http.GetAsync(
                    $"{baseUrl.TrimEnd('/')}/ledger/sth/{treeSize}?shard_id=core&witnesses=1", cts.Token).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                {
                    return null;
                }
                var wire = await Session.ReadJsonAsync<CosignedTreeHeadWire>(response, cts.Token).ConfigureAwait(false);
                return wire.ToCosignedTreeHead();
            }
            catch (Exception) when (!ct.IsCancellationRequested)
            {
                return null;
            }
        }
    }

    /// <summary>Per-client cache of the automatically built known list, one build per network.</summary>
    internal sealed class KnownListCache
    {
        private readonly object _gate = new object();
        private readonly Dictionary<string, Task<IReadOnlyList<KnownWitness>>> _lists = new Dictionary<string, Task<IReadOnlyList<KnownWitness>>>();

        public Task<IReadOnlyList<KnownWitness>> GetAsync(
            HttpClient http, TrustAnchorEntry entry, KnownListOptions? options)
        {
            lock (_gate)
            {
                if (!_lists.TryGetValue(entry.NetworkId, out var task))
                {
                    task = KnownListBuilder.BuildKnownListAsync(http, entry, options, CancellationToken.None);
                    _lists[entry.NetworkId] = task;
                }
                return task;
            }
        }
    }
}
