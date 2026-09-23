// STH-based network trust verification, zero-URL discovery — mirrors
// languages/rust/src/network.rs field-for-field and behavior-for-behavior.
// network_id alone is never sufficient to trust a server, since it is a
// plain string with zero cryptographic authority — only a Signed Tree Head
// (GET /ledger/sth/latest) that verifies against the claimed network's
// pinned verify_key actually establishes which network a server is.
//
// docs/trusted-networks.json is the single canonical trust-anchor list,
// embedded at build time rather than hand-copied.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Runtime.Serialization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Avalon.Sdk
{
    /// <summary>Which deployment tier a <see cref="TrustAnchorEntry"/> pins, matching
    /// docs/trusted-networks.json's "environment" field.</summary>
    public enum NetworkEnvironment
    {
        /// <summary>No real deployment — a freely-generated key checked in only to exercise the
        /// trust-anchor mechanism end to end.</summary>
        [EnumMember(Value = "local-dev")]
        LocalDev,

        /// <summary>A real, non-production, single-node deployment.</summary>
        [EnumMember(Value = "dev")]
        Dev,

        /// <summary>A real, non-production, 1-5 node interconnected test bed.</summary>
        [EnumMember(Value = "int")]
        Int,

        /// <summary>A real mainnet deployment.</summary>
        [EnumMember(Value = "prod")]
        Prod,
    }

    /// <summary>One entry of docs/trusted-networks.json.</summary>
    public sealed class TrustAnchorEntry
    {
        /// <summary>Human-readable name for the network.</summary>
        [JsonPropertyName("label")]
        public string Label { get; set; } = "";

        /// <summary>The exact string a server sets AVALON_NETWORK_ID to.</summary>
        [JsonPropertyName("network_id")]
        public string NetworkId { get; set; } = "";

        /// <summary>Lowercase hex-encoded Ed25519 public key — the settlement operator's STH
        /// verify key for this network.</summary>
        [JsonPropertyName("verify_key")]
        public string VerifyKey { get; set; } = "";

        /// <summary>Which key generation this is, matching a Signed Tree Head's own
        /// signing_key_id.</summary>
        [JsonPropertyName("signing_key_id")]
        public string SigningKeyId { get; set; } = "";

        /// <summary>The server URL this network is reachable at, if published.</summary>
        [JsonPropertyName("server_url")]
        public string? ServerUrl { get; set; }

        /// <summary>Which deployment tier this is.</summary>
        [JsonPropertyName("environment")]
        public NetworkEnvironment Environment { get; set; }

        /// <summary>Base URLs of this network's always-on anchor node(s) — the default
        /// bootstrap/discovery candidates for this network_id. Empty for a network with no
        /// anchor yet.</summary>
        [JsonPropertyName("seed_nodes")]
        public List<string> SeedNodes { get; set; } = new List<string>();

        /// <summary>Free-text notes.</summary>
        [JsonPropertyName("notes")]
        public string? Notes { get; set; }
    }

    internal sealed class TrustedNetworksFile
    {
        [JsonPropertyName("networks")]
        public List<TrustAnchorEntry> Networks { get; set; } = new List<TrustAnchorEntry>();
    }

    /// <summary>Every network this SDK build was bundled with a pinned key for.</summary>
    public static class TrustAnchors
    {
        private static readonly JsonSerializerOptions ParseOptions = new JsonSerializerOptions
        {
            Converters = { new EnumMemberJsonConverterFactory() },
        };

        private static readonly Lazy<IReadOnlyList<TrustAnchorEntry>> Cached =
            new Lazy<IReadOnlyList<TrustAnchorEntry>>(Load);

        /// <summary>Parsed once from the embedded docs/trusted-networks.json and cached.</summary>
        public static IReadOnlyList<TrustAnchorEntry> Bundled => Cached.Value;

        /// <summary>Where the canonical trust-anchor list is published.</summary>
        public const string PublishedUrl =
            "https://raw.githubusercontent.com/avalon-initiative/avalon-protocol/main/docs/trusted-networks.json";

        /// <summary>Fetches and parses the published trust-anchor list from <paramref name="url"/>.</summary>
        public static async Task<IReadOnlyList<TrustAnchorEntry>> FetchAsync(
            HttpClient http, string url = PublishedUrl, CancellationToken ct = default)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            using var response = await http.GetAsync(url, timeout.Token).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            var file = JsonSerializer.Deserialize<TrustedNetworksFile>(json, ParseOptions)
                ?? throw new InvalidOperationException("trust-anchor list must match TrustedNetworksFile");
            return file.Networks;
        }

        /// <summary>The published list when reachable, otherwise <see cref="Bundled"/>.</summary>
        public static async Task<IReadOnlyList<TrustAnchorEntry>> ResolveAsync(
            HttpClient http, string url = PublishedUrl, CancellationToken ct = default)
        {
            try
            {
                var anchors = await FetchAsync(http, url, ct).ConfigureAwait(false);
                if (anchors.Count > 0) return anchors;
            }
            catch (Exception) when (!ct.IsCancellationRequested)
            {
                // fall through to the bundled copy
            }
            return Bundled;
        }

        private static List<TrustAnchorEntry> Load()
        {
            var assembly = Assembly.GetExecutingAssembly();
            using var stream = assembly.GetManifestResourceStream("Avalon.Sdk.trusted-networks.json")
                ?? throw new InvalidOperationException(
                    "embedded resource Avalon.Sdk.trusted-networks.json not found");
            using var reader = new StreamReader(stream, Encoding.UTF8);
            var json = reader.ReadToEnd();
            var file = JsonSerializer.Deserialize<TrustedNetworksFile>(json, ParseOptions)
                ?? throw new InvalidOperationException(
                    "docs/trusted-networks.json must be valid JSON matching TrustedNetworksFile");
            return file.Networks;
        }
    }

    /// <summary>GET /ledger/sth/latest's wire shape.</summary>
    internal sealed class SignedTreeHeadWire
    {
        [JsonPropertyName("tree_size")]
        public long TreeSize { get; set; }

        [JsonPropertyName("root_hash")]
        public string RootHash { get; set; } = "";

        [JsonPropertyName("network_id")]
        public string NetworkId { get; set; } = "";

        [JsonPropertyName("signing_key_id")]
        public string SigningKeyId { get; set; } = "";

        [JsonPropertyName("signature")]
        public string Signature { get; set; } = "";

        [JsonPropertyName("created_at")]
        public DateTimeOffset CreatedAt { get; set; }
    }

    /// <summary>Which of the four outcomes a <see cref="NetworkTrustStatus"/> is. A caller must
    /// never treat anything but <see cref="Verified"/> as "connected to the real network."</summary>
    public enum NetworkTrustStatusKind
    {
        /// <summary>The claimed network_id is pinned and the STH signature checks out — this
        /// really is the network it says it is.</summary>
        Verified,

        /// <summary>The claimed network_id is pinned, but the signature does NOT verify against
        /// the pinned key — the impostor case this exists to catch. Never silently downgraded
        /// to <see cref="UnknownNetwork"/>.</summary>
        Mismatch,

        /// <summary>The claimed network_id isn't in the bundled trust-anchor list at all.</summary>
        UnknownNetwork,

        /// <summary>Fetching or parsing the server's latest Signed Tree Head itself failed.</summary>
        Unreachable,
    }

    /// <summary>The invariant this type exists for: network_id alone is never sufficient. Given
    /// a fetched Signed Tree Head and every network this build has a pinned key for, exactly one
    /// of <see cref="NetworkTrustStatusKind"/>'s four states applies — a caller must never treat
    /// anything but <see cref="Kind"/> == <see cref="NetworkTrustStatusKind.Verified"/> as
    /// "connected to the real network." netstandard2.1 has no native sum type, so this is a
    /// small class with a discriminating <see cref="Kind"/> plus only the fields that kind
    /// defines.</summary>
    public sealed class NetworkTrustStatus
    {
        private NetworkTrustStatus(NetworkTrustStatusKind kind, TrustAnchorEntry? entry, string? claimedNetworkId, string? detail)
        {
            Kind = kind;
            Entry = entry;
            ClaimedNetworkId = claimedNetworkId;
            Detail = detail;
        }

        public NetworkTrustStatusKind Kind { get; }

        /// <summary>The pinned trust-anchor entry the server's STH verified (or failed to
        /// verify) against. Present for <see cref="NetworkTrustStatusKind.Verified"/> and
        /// <see cref="NetworkTrustStatusKind.Mismatch"/> only.</summary>
        public TrustAnchorEntry? Entry { get; }

        /// <summary>The network_id the server's STH claimed. Present for
        /// <see cref="NetworkTrustStatusKind.Mismatch"/> and
        /// <see cref="NetworkTrustStatusKind.UnknownNetwork"/> only.</summary>
        public string? ClaimedNetworkId { get; }

        /// <summary>A human-readable description of what went wrong. Present for
        /// <see cref="NetworkTrustStatusKind.Unreachable"/> only.</summary>
        public string? Detail { get; }

        public static NetworkTrustStatus Verified(TrustAnchorEntry entry) =>
            new NetworkTrustStatus(NetworkTrustStatusKind.Verified, entry, null, null);

        public static NetworkTrustStatus Mismatch(TrustAnchorEntry entry, string claimedNetworkId) =>
            new NetworkTrustStatus(NetworkTrustStatusKind.Mismatch, entry, claimedNetworkId, null);

        public static NetworkTrustStatus UnknownNetwork(string claimedNetworkId) =>
            new NetworkTrustStatus(NetworkTrustStatusKind.UnknownNetwork, null, claimedNetworkId, null);

        public static NetworkTrustStatus Unreachable(string detail) =>
            new NetworkTrustStatus(NetworkTrustStatusKind.Unreachable, null, null, detail);
    }

    /// <summary>One of the three real deployment tiers a caller can declare intent for without
    /// spelling out an exact network_id — resolved against whichever pinned entry the server's
    /// STH actually verified against, never guessed from the server URL alone. Deliberately only
    /// three variants: <see cref="NetworkEnvironment.LocalDev"/> isn't one of them, so a caller
    /// targeting it declares its exact network_id via <see cref="TargetNetwork.ForNetworkId"/>
    /// instead.</summary>
    public enum TargetNetworkTier
    {
        /// <summary>A real, non-production, single-node deployment.</summary>
        Dev,

        /// <summary>A real, non-production, 1-5 node interconnected test bed.</summary>
        Int,

        /// <summary>The real mainnet deployment.</summary>
        Mainnet,
    }

    internal static class TargetNetworkTierExtensions
    {
        public static bool Matches(this TargetNetworkTier tier, NetworkEnvironment environment) =>
            (tier, environment) switch
            {
                (TargetNetworkTier.Dev, NetworkEnvironment.Dev) => true,
                (TargetNetworkTier.Int, NetworkEnvironment.Int) => true,
                (TargetNetworkTier.Mainnet, NetworkEnvironment.Prod) => true,
                _ => false,
            };

        public static string Label(this TargetNetworkTier tier) =>
            tier switch
            {
                TargetNetworkTier.Dev => "dev",
                TargetNetworkTier.Int => "int",
                TargetNetworkTier.Mainnet => "mainnet",
                _ => tier.ToString(),
            };
    }

    /// <summary>Which of <see cref="TargetNetwork"/>'s two shapes this instance is.</summary>
    public enum TargetNetworkKind
    {
        /// <summary>An exact network_id string.</summary>
        NetworkId,

        /// <summary>A deployment-tier shorthand.</summary>
        Env,
    }

    /// <summary>The network a caller must explicitly declare intent for before a write that's
    /// gated by network identity — registering an issuer, most immediately. No implicit default
    /// is ever inferred from the server URL alone; see <see cref="AvalonClient.CheckTargetNetwork"/>.</summary>
    public sealed class TargetNetwork
    {
        private TargetNetwork(TargetNetworkKind kind, string? networkId, TargetNetworkTier? tier)
        {
            Kind = kind;
            NetworkId = networkId;
            Tier = tier;
        }

        public TargetNetworkKind Kind { get; }

        /// <summary>Present only when <see cref="Kind"/> is <see cref="TargetNetworkKind.NetworkId"/>.</summary>
        public string? NetworkId { get; }

        /// <summary>Present only when <see cref="Kind"/> is <see cref="TargetNetworkKind.Env"/>.</summary>
        public TargetNetworkTier? Tier { get; }

        public static TargetNetwork ForNetworkId(string networkId) =>
            new TargetNetwork(TargetNetworkKind.NetworkId, networkId, null);

        public static TargetNetwork ForTier(TargetNetworkTier tier) =>
            new TargetNetwork(TargetNetworkKind.Env, null, tier);

        public override string ToString() =>
            Kind == TargetNetworkKind.NetworkId ? NetworkId! : $"{Tier!.Value.Label()} (declared by tier)";

        internal bool Matches(TrustAnchorEntry entry) =>
            Kind == TargetNetworkKind.NetworkId ? entry.NetworkId == NetworkId : Tier!.Value.Matches(entry.Environment);
    }

    /// <summary>Why a declared <see cref="TargetNetwork"/> failed
    /// <see cref="AvalonClient.CheckTargetNetwork"/> — never a silent proceed.</summary>
    public enum NetworkTargetErrorKind
    {
        /// <summary>The server's network was independently verified, but it isn't the one the
        /// caller declared intent for.</summary>
        Mismatch,

        /// <summary>The server's claimed network couldn't be independently verified at all
        /// (unknown, key mismatch, or unreachable) — refused regardless of what was declared,
        /// since there's nothing to compare it against.</summary>
        Unverified,
    }

    /// <summary>Thrown by <see cref="AvalonClient.CheckTargetNetwork"/> when a declared
    /// <see cref="TargetNetwork"/> doesn't hold.</summary>
    public sealed class NetworkTargetException : Exception
    {
        private NetworkTargetException(string message, NetworkTargetErrorKind kind) : base(message)
        {
            Kind = kind;
        }

        public NetworkTargetErrorKind Kind { get; }

        internal static NetworkTargetException Mismatch(string declared, string actual) =>
            new NetworkTargetException(
                $"declared target network {declared} does not match the server's verified network {actual}",
                NetworkTargetErrorKind.Mismatch);

        internal static NetworkTargetException Unverified(string reason) =>
            new NetworkTargetException(
                $"server's network could not be independently verified: {reason}",
                NetworkTargetErrorKind.Unverified);
    }

    /// <summary>Why <see cref="AvalonClient.DiscoverAsync"/>/<see cref="AvalonClient.ConnectAsync"/>
    /// couldn't resolve a target to a live, verified server.</summary>
    public enum DiscoveryErrorKind
    {
        /// <summary>No bundled trust anchor matches the target at all, so there was nothing to
        /// even attempt a connection to.</summary>
        NoCandidates,

        /// <summary>At least one candidate URL was tried, but none of them verified as the
        /// target.</summary>
        NoneVerified,
    }

    /// <summary>Thrown by <see cref="AvalonClient.DiscoverAsync"/>/<see cref="AvalonClient.ConnectAsync"/>
    /// when no candidate server resolves the target.</summary>
    public sealed class DiscoveryException : Exception
    {
        private DiscoveryException(string message, DiscoveryErrorKind kind, string target, IReadOnlyList<(string CandidateUrl, string Outcome)> attempts)
            : base(message)
        {
            Kind = kind;
            Target = target;
            Attempts = attempts;
        }

        public DiscoveryErrorKind Kind { get; }
        public string Target { get; }

        /// <summary>(candidate URL, human-readable outcome) for every URL tried. Empty for
        /// <see cref="DiscoveryErrorKind.NoCandidates"/>.</summary>
        public IReadOnlyList<(string CandidateUrl, string Outcome)> Attempts { get; }

        internal static DiscoveryException NoCandidates(string target) =>
            new DiscoveryException(
                $"no bundled trust anchor matches target network {target}",
                DiscoveryErrorKind.NoCandidates,
                target,
                Array.Empty<(string, string)>());

        internal static DiscoveryException NoneVerified(string target, List<(string CandidateUrl, string Outcome)> attempts) =>
            new DiscoveryException(
                $"no candidate server for target network {target} verified",
                DiscoveryErrorKind.NoneVerified,
                target,
                attempts);
    }

    /// <summary>Everything <see cref="AvalonClient.ConnectAsync"/> needs besides the server URL
    /// itself, since discovery is what supplies that field. Mirrors <see cref="AvalonConfig"/>
    /// minus <see cref="AvalonConfig.ServerUrl"/>.</summary>
    public sealed class DiscoveryConfig
    {
        public DiscoveryConfig(string integratorCredentialKeyId, string? integratorSlug = null, byte[]? signingKey = null)
        {
            IntegratorCredentialKeyId = integratorCredentialKeyId;
            IntegratorSlug = integratorSlug;
            SigningKey = signingKey;
        }

        /// <summary>See <see cref="AvalonConfig.IntegratorCredentialKeyId"/>.</summary>
        public string IntegratorCredentialKeyId { get; }

        /// <summary>See <see cref="AvalonConfig.IntegratorSlug"/>.</summary>
        public string? IntegratorSlug { get; }

        /// <summary>See <see cref="AvalonConfig.SigningKey"/>.</summary>
        public byte[]? SigningKey { get; }
    }

    public sealed partial class AvalonClient
    {
        /// <summary>Fetches GET /ledger/sth/latest from this client's configured server and
        /// verifies it against <see cref="TrustAnchors.Bundled"/> — the check an integrator
        /// should run before registering an issuer or submitting any write, so a call never
        /// lands on a server merely claiming to be the network it targets.
        ///
        /// Never throws: an unreachable/unparseable server is itself
        /// <see cref="NetworkTrustStatusKind.Unreachable"/>, since "is this the real network" is
        /// a question with an answer even when that answer is "no signal at all."</summary>
        public async Task<NetworkTrustStatus> VerifyNetworkAsync(CancellationToken ct = default) =>
            await FetchNetworkTrustStatusAsync(
                await TrustAnchors.ResolveAsync(_http, ct: ct).ConfigureAwait(false),
                _http, _config.ServerUrl, ct).ConfigureAwait(false);

        /// <summary>The check a declared <see cref="TargetNetwork"/> exists for: it only ever
        /// proceeds against a server whose <see cref="NetworkTrustStatus"/> is
        /// <see cref="NetworkTrustStatusKind.Verified"/> AND whose verified entry matches what
        /// was declared. Returns the matching <see cref="TrustAnchorEntry"/> on success so a
        /// caller can read back the exact network_id it just confirmed it's talking to.
        /// Throws <see cref="NetworkTargetException"/> otherwise.</summary>
        public static TrustAnchorEntry CheckTargetNetwork(NetworkTrustStatus status, TargetNetwork target)
        {
            TrustAnchorEntry entry;
            switch (status.Kind)
            {
                case NetworkTrustStatusKind.Verified:
                    entry = status.Entry!;
                    break;
                case NetworkTrustStatusKind.Mismatch:
                    throw NetworkTargetException.Unverified(
                        $"the server's STH does not verify against the pinned key for {status.ClaimedNetworkId}");
                case NetworkTrustStatusKind.UnknownNetwork:
                    throw NetworkTargetException.Unverified($"{status.ClaimedNetworkId} is not a pinned/known network");
                case NetworkTrustStatusKind.Unreachable:
                    throw NetworkTargetException.Unverified(status.Detail!);
                default:
                    throw new InvalidOperationException($"unhandled NetworkTrustStatusKind: {status.Kind}");
            }

            if (target.Matches(entry))
            {
                return entry;
            }
            throw NetworkTargetException.Mismatch(target.ToString(), entry.NetworkId);
        }

        /// <summary>Resolves <paramref name="target"/> to a live, independently-verified
        /// (server URL, entry) with no server URL supplied up front — a caller who only knows
        /// which network they want to join, not which of its nodes to talk to.
        ///
        /// Candidates come only from <see cref="TrustAnchors.Bundled"/>'s own ServerUrl/
        /// SeedNodes fields for every entry matching <paramref name="target"/> — never anywhere
        /// else, so discovery can't be tricked into contacting an unpinned host. Each candidate
        /// is fetched and verified exactly like <see cref="VerifyNetworkAsync"/> would; the
        /// first one whose STH verifies against target's own matching entry wins. Entries are
        /// tried in <see cref="TrustAnchors.Bundled"/>'s order, and each entry's ServerUrl
        /// before its SeedNodes, so results are deterministic across runs of the same SDK
        /// build.</summary>
        public static async Task<(string ServerUrl, TrustAnchorEntry Entry)> DiscoverAsync(
            TargetNetwork target, HttpClient? httpClient = null, CancellationToken ct = default)
        {
            var http = httpClient ?? new HttpClient();
            var anchors = await TrustAnchors.ResolveAsync(http, ct: ct).ConfigureAwait(false);
            return await DiscoverAmongAsync(anchors, target, http, ct).ConfigureAwait(false);
        }

        /// <summary>Builds and returns a client with no server URL supplied up front — resolves
        /// <paramref name="target"/> to a live, verified server via <see cref="DiscoverAsync"/>,
        /// then constructs exactly as the <see cref="AvalonClient"/> constructor would with the
        /// discovered URL.</summary>
        public static async Task<AvalonClient> ConnectAsync(
            TargetNetwork target, DiscoveryConfig config, HttpClient? httpClient = null, CancellationToken ct = default)
        {
            var http = httpClient ?? new HttpClient();
            var (serverUrl, _) = await DiscoverAsync(target, http, ct).ConfigureAwait(false);
            return new AvalonClient(
                new AvalonConfig(serverUrl, config.IntegratorCredentialKeyId, config.IntegratorSlug, config.SigningKey),
                http);
        }

        /// <summary>[`DiscoverAsync`]'s actual logic, taking <paramref name="anchors"/>
        /// explicitly rather than always reading <see cref="TrustAnchors.Bundled"/> — split out
        /// so tests can supply a mock server's own key instead of needing to forge a signature
        /// for a real bundled entry.</summary>
        internal static async Task<(string, TrustAnchorEntry)> DiscoverAmongAsync(
            IReadOnlyList<TrustAnchorEntry> anchors, TargetNetwork target, HttpClient http, CancellationToken ct)
        {
            var attempts = new List<(string CandidateUrl, string Outcome)>();
            var triedAny = false;

            foreach (var entry in anchors)
            {
                if (!target.Matches(entry))
                {
                    continue;
                }

                var candidates = new List<string>();
                if (entry.ServerUrl != null)
                {
                    candidates.Add(entry.ServerUrl);
                }
                candidates.AddRange(entry.SeedNodes);

                foreach (var candidate in candidates)
                {
                    triedAny = true;
                    var status = await FetchNetworkTrustStatusAsync(anchors, http, candidate, ct).ConfigureAwait(false);
                    try
                    {
                        var verifiedEntry = CheckTargetNetwork(status, target);
                        return (candidate, verifiedEntry);
                    }
                    catch (NetworkTargetException ex)
                    {
                        attempts.Add((candidate, ex.Message));
                    }
                }
            }

            if (!triedAny)
            {
                throw DiscoveryException.NoCandidates(target.ToString());
            }
            throw DiscoveryException.NoneVerified(target.ToString(), attempts);
        }

        /// <summary>Fetches GET /ledger/sth/latest from <paramref name="serverUrl"/> and
        /// evaluates it against <paramref name="anchors"/> — the shared fetch-then-evaluate path
        /// behind both <see cref="VerifyNetworkAsync"/> (a known server) and
        /// <see cref="DiscoverAmongAsync"/> (candidate servers with no known-good one yet). Never
        /// throws: any failure becomes <see cref="NetworkTrustStatusKind.Unreachable"/>.</summary>
        internal static async Task<NetworkTrustStatus> FetchNetworkTrustStatusAsync(
            IReadOnlyList<TrustAnchorEntry> anchors, HttpClient http, string serverUrl, CancellationToken ct)
        {
            HttpResponseMessage response;
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, $"{serverUrl}/ledger/sth/latest");
                response = await http.SendAsync(request, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                return NetworkTrustStatus.Unreachable(ex.Message);
            }

            using (response)
            {
                if (!response.IsSuccessStatusCode)
                {
                    return NetworkTrustStatus.Unreachable($"server returned {response.StatusCode}");
                }

                SignedTreeHeadWire wire;
                try
                {
                    wire = await Session.ReadJsonAsync<SignedTreeHeadWire>(response, ct).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    return NetworkTrustStatus.Unreachable(ex.Message);
                }

                return EvaluateNetworkTrust(anchors, wire);
            }
        }

        /// <summary>Decides which of <see cref="NetworkTrustStatusKind"/>'s first three states
        /// applies to <paramref name="wire"/> against <paramref name="anchors"/>. Split out from
        /// <see cref="FetchNetworkTrustStatusAsync"/> so the pure decision logic is directly
        /// unit-testable.</summary>
        internal static NetworkTrustStatus EvaluateNetworkTrust(IReadOnlyList<TrustAnchorEntry> anchors, SignedTreeHeadWire wire)
        {
            var entry = anchors.FirstOrDefault(candidate => candidate.NetworkId == wire.NetworkId);
            if (entry == null)
            {
                return NetworkTrustStatus.UnknownNetwork(wire.NetworkId);
            }
            if (!VerifyTreeHeadHex(entry.VerifyKey, wire))
            {
                return NetworkTrustStatus.Mismatch(entry, wire.NetworkId);
            }
            return NetworkTrustStatus.Verified(entry);
        }

        /// <summary>Verifies <paramref name="verifyKeyHex"/> (lowercase hex, 32 bytes) against
        /// <paramref name="wire"/>'s signature — false for any malformed input (bad hex,
        /// wrong-length key) as well as an outright-invalid signature, never throws.</summary>
        internal static bool VerifyTreeHeadHex(string verifyKeyHex, SignedTreeHeadWire wire)
        {
            byte[] keyBytes;
            byte[] signatureBytes;
            try
            {
                keyBytes = HexDecode(verifyKeyHex);
                signatureBytes = HexDecode(wire.Signature);
            }
            catch (FormatException)
            {
                return false;
            }
            if (keyBytes.Length != 32 || signatureBytes.Length != 64)
            {
                return false;
            }

            try
            {
                var publicKey = new Ed25519PublicKeyParameters(keyBytes, 0);
                var signer = new Ed25519Signer();
                signer.Init(false, publicKey);
                var message = SthSigningMessage(wire.TreeSize, wire.RootHash, wire.NetworkId, wire.CreatedAt);
                signer.BlockUpdate(message, 0, message.Length);
                return signer.VerifySignature(signatureBytes);
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>The exact bytes an STH's signature covers: a fixed domain tag, tree_size and
        /// the unix timestamp as fixed-width big-endian integers, and root_hash explicitly
        /// length-prefixed ahead of its bytes, followed by the raw network_id bytes. Must stay
        /// byte-for-byte identical to the server's and the Rust SDK's own construction —
        /// conformance/vectors/signed-tree-head.json is what proves it still is.</summary>
        internal static byte[] SthSigningMessage(long treeSize, string rootHashHex, string networkId, DateTimeOffset createdAt)
        {
            var message = new List<byte>();
            message.AddRange(Encoding.UTF8.GetBytes("avalon-settlement-sth-v1"));
            message.AddRange(BigEndian(treeSize));
            message.AddRange(BigEndian((uint)rootHashHex.Length));
            message.AddRange(Encoding.UTF8.GetBytes(rootHashHex));
            message.AddRange(Encoding.UTF8.GetBytes(networkId));
            message.AddRange(BigEndian(createdAt.ToUnixTimeSeconds()));
            return message.ToArray();
        }

        private static byte[] BigEndian(long value)
        {
            var bytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }
            return bytes;
        }

        private static byte[] BigEndian(uint value)
        {
            var bytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }
            return bytes;
        }

        private static byte[] HexDecode(string hex)
        {
            if (hex.Length % 2 != 0)
            {
                throw new FormatException("odd-length hex string");
            }
            var bytes = new byte[hex.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
    }
}
