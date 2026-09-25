using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Xunit;

namespace Avalon.Sdk.Tests;

public class NetworkTests
{
    private static Ed25519PrivateKeyParameters GenerateKey()
    {
        var generator = new Ed25519KeyPairGenerator();
        generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        return (Ed25519PrivateKeyParameters)generator.GenerateKeyPair().Private;
    }

    private static string HexEncode(byte[] bytes) => string.Concat(bytes.Select(b => b.ToString("x2")));

    private static string PublicKeyHex(Ed25519PrivateKeyParameters privateKey) =>
        HexEncode(privateKey.GeneratePublicKey().GetEncoded());

    private static TrustAnchorEntry Anchor(
        string networkId,
        string verifyKeyHex,
        string? serverUrl = null,
        List<string>? seedNodes = null,
        NetworkEnvironment environment = NetworkEnvironment.LocalDev) =>
        new TrustAnchorEntry
        {
            Label = networkId,
            NetworkId = networkId,
            VerifyKey = verifyKeyHex,
            SigningKeyId = "test-key",
            ServerUrl = serverUrl,
            Environment = environment,
            SeedNodes = seedNodes ?? new List<string>(),
        };

    /// <summary>Signs a Signed Tree Head with <paramref name="signingKey"/>, using the exact
    /// byte layout <see cref="AvalonClient.SthSigningMessage"/> verifies against — a domain
    /// tag, big-endian tree_size, length-prefixed root_hash, raw network_id bytes, and a
    /// big-endian unix timestamp.</summary>
    private static SignedTreeHeadWire SignedSth(
        Ed25519PrivateKeyParameters signingKey, string networkId, long treeSize = 42, string? rootHash = null)
    {
        rootHash ??= string.Concat(Enumerable.Repeat("ab", 32));
        var createdAt = DateTimeOffset.FromUnixTimeSeconds(0);
        var message = AvalonClient.SthSigningMessage(treeSize, rootHash, networkId, createdAt);

        var signer = new Ed25519Signer();
        signer.Init(true, signingKey);
        signer.BlockUpdate(message, 0, message.Length);
        var signature = signer.GenerateSignature();

        return new SignedTreeHeadWire
        {
            TreeSize = treeSize,
            RootHash = rootHash,
            NetworkId = networkId,
            SigningKeyId = "test-key",
            Signature = HexEncode(signature),
            CreatedAt = createdAt,
        };
    }

    private static string SthJson(SignedTreeHeadWire wire) => JsonSerializer.Serialize(wire);

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        private readonly string _body;

        public StubHandler(HttpStatusCode status, string body) { _status = status; _body = body; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(_status) { Content = new StringContent(_body) });
    }

    [Fact]
    public async Task FetchAsync_ParsesThePublishedFile()
    {
        var json = "{\"networks\":[{\"label\":\"n\",\"network_id\":\"n\",\"verify_key\":\"ab\",\"signing_key_id\":\"k\",\"environment\":\"dev\"}]}";
        using var http = new HttpClient(new StubHandler(HttpStatusCode.OK, json));
        var anchors = await TrustAnchors.FetchAsync(http, "http://x");
        Assert.Equal("n", Assert.Single(anchors).NetworkId);
    }

    [Fact]
    public async Task FetchAsync_ThrowsOnAFailingResponse()
    {
        using var http = new HttpClient(new StubHandler(HttpStatusCode.InternalServerError, ""));
        await Assert.ThrowsAsync<HttpRequestException>(() => TrustAnchors.FetchAsync(http, "http://x"));
    }

    [Fact]
    public void ValidSth_AgainstItsPinnedKey_Verifies()
    {
        var signingKey = GenerateKey();
        var entry = Anchor("avalon-test", PublicKeyHex(signingKey));
        var sth = SignedSth(signingKey, "avalon-test");

        var status = AvalonClient.EvaluateNetworkTrust(new[] { entry }, sth);

        Assert.Equal(NetworkTrustStatusKind.Verified, status.Kind);
        Assert.Same(entry, status.Entry);
    }

    [Fact]
    public void SthSignedByADifferentKey_IsFlaggedAsMismatch_NotSilentlyTrusted()
    {
        var realKey = GenerateKey();
        var impostorKey = GenerateKey();
        var entry = Anchor("avalon-test", PublicKeyHex(realKey));
        // A server signing under the real network's name, but with a different key — the exact
        // impostor case this module exists for.
        var forgedSth = SignedSth(impostorKey, "avalon-test");

        var status = AvalonClient.EvaluateNetworkTrust(new[] { entry }, forgedSth);

        Assert.Equal(NetworkTrustStatusKind.Mismatch, status.Kind);
        Assert.Same(entry, status.Entry);
        Assert.Equal("avalon-test", status.ClaimedNetworkId);
    }

    [Fact]
    public void UnpinnedNetworkId_ReportsUnknown_NotTrustedByDefault()
    {
        var signingKey = GenerateKey();
        var sth = SignedSth(signingKey, "avalon-unpinned");

        var status = AvalonClient.EvaluateNetworkTrust(Array.Empty<TrustAnchorEntry>(), sth);

        Assert.Equal(NetworkTrustStatusKind.UnknownNetwork, status.Kind);
        Assert.Equal("avalon-unpinned", status.ClaimedNetworkId);
    }

    private static NetworkTrustStatus VerifiedDev(string networkId) =>
        NetworkTrustStatus.Verified(Anchor(networkId, "ab".PadRight(64, 'b'), environment: NetworkEnvironment.Dev));

    [Fact]
    public void CheckTargetNetwork_ProceedsWhenTheDeclaredNetworkIdMatches()
    {
        var status = VerifiedDev("avalon-dev-1");
        var target = TargetNetwork.ForNetworkId("avalon-dev-1");

        var entry = AvalonClient.CheckTargetNetwork(status, target);

        Assert.Equal("avalon-dev-1", entry.NetworkId);
    }

    [Fact]
    public void CheckTargetNetwork_ProceedsWhenTheDeclaredTierMatches()
    {
        var status = VerifiedDev("avalon-dev-1");
        var target = TargetNetwork.ForTier(TargetNetworkTier.Dev);

        var entry = AvalonClient.CheckTargetNetwork(status, target);

        Assert.Equal("avalon-dev-1", entry.NetworkId);
    }

    [Fact]
    public void CheckTargetNetwork_RejectsAMismatchedNetworkId()
    {
        var status = VerifiedDev("avalon-dev-1");
        var target = TargetNetwork.ForNetworkId("avalon-mainnet-1");

        var ex = Assert.Throws<NetworkTargetException>(() => AvalonClient.CheckTargetNetwork(status, target));

        Assert.Equal(NetworkTargetErrorKind.Mismatch, ex.Kind);
    }

    [Fact]
    public void CheckTargetNetwork_RejectsAMismatchedTier()
    {
        var status = VerifiedDev("avalon-dev-1");
        var target = TargetNetwork.ForTier(TargetNetworkTier.Mainnet);

        var ex = Assert.Throws<NetworkTargetException>(() => AvalonClient.CheckTargetNetwork(status, target));

        Assert.Equal(NetworkTargetErrorKind.Mismatch, ex.Kind);
    }

    [Fact]
    public void CheckTargetNetwork_NeverProceedsAgainstAnUnverifiedNetwork()
    {
        var target = TargetNetwork.ForNetworkId("avalon-dev-1");

        var unknown = NetworkTrustStatus.UnknownNetwork("avalon-dev-1");
        Assert.Equal(
            NetworkTargetErrorKind.Unverified,
            Assert.Throws<NetworkTargetException>(() => AvalonClient.CheckTargetNetwork(unknown, target)).Kind);

        var unreachable = NetworkTrustStatus.Unreachable("connection refused");
        Assert.Equal(
            NetworkTargetErrorKind.Unverified,
            Assert.Throws<NetworkTargetException>(() => AvalonClient.CheckTargetNetwork(unreachable, target)).Kind);

        var verified = VerifiedDev("avalon-dev-1");
        var mismatch = NetworkTrustStatus.Mismatch(verified.Entry!, "avalon-dev-1");
        Assert.Equal(
            NetworkTargetErrorKind.Unverified,
            Assert.Throws<NetworkTargetException>(() => AvalonClient.CheckTargetNetwork(mismatch, target)).Kind);
    }

    [Fact]
    public async Task VerifyNetworkAsync_FetchesAndVerifiesARealSth_EndToEnd()
    {
        var signingKey = GenerateKey();
        var sth = SignedSth(signingKey, "avalon-test");
        var handler = new StubHttpMessageHandler().Enqueue("{\"networks\":[]}").Enqueue(SthJson(sth));
        var client = new AvalonClient(new AvalonConfig("https://example.invalid", "test-integrator"), handler.ToHttpClient());

        // "avalon-test" has no entry in the published list, so the real end-to-end path
        // (fetch -> deserialize -> evaluate) still correctly reports unknown rather than erroring.
        var status = await client.VerifyNetworkAsync();

        Assert.Equal(NetworkTrustStatusKind.UnknownNetwork, status.Kind);
        Assert.Equal("avalon-test", status.ClaimedNetworkId);
    }

    [Fact]
    public async Task VerifyNetworkAsync_ReportsUnreachable_WhenTheServerReturnsAnError()
    {
        var handler = new StubHttpMessageHandler().Enqueue(HttpStatusCode.ServiceUnavailable, "{}");
        var client = new AvalonClient(new AvalonConfig("https://example.invalid", "test-integrator"), handler.ToHttpClient());

        var status = await client.VerifyNetworkAsync();

        Assert.Equal(NetworkTrustStatusKind.Unreachable, status.Kind);
    }

    [Fact]
    public async Task VerifyNetworkAsync_ReportsUnreachable_WhenTheServerIsDown()
    {
        // No response queued: the stub handler itself throws, exercising the same
        // transport-failure path a real dropped connection would.
        var handler = new StubHttpMessageHandler();
        var client = new AvalonClient(new AvalonConfig("https://example.invalid", "test-integrator"), handler.ToHttpClient());

        var status = await client.VerifyNetworkAsync();

        Assert.Equal(NetworkTrustStatusKind.Unreachable, status.Kind);
    }

    [Fact]
    public async Task DiscoverAsync_FindsTheFirstVerifiedCandidate_WhenAnEarlierOneIsDeadOrWrongKey()
    {
        var signingKey = GenerateKey();
        var wrongKey = GenerateKey();
        var deadCandidateSth = SignedSth(wrongKey, "avalon-test"); // wrong key -> mismatch, not verified
        var liveCandidateSth = SignedSth(signingKey, "avalon-test");

        var handler = new StubHttpMessageHandler()
            .Enqueue(HttpStatusCode.ServiceUnavailable, "{}") // first candidate: dead
            .Enqueue(SthJson(liveCandidateSth)); // second candidate: live and verifies
        var entry = Anchor(
            "avalon-test",
            PublicKeyHex(signingKey),
            seedNodes: new List<string> { "http://candidate-a.invalid", "http://candidate-b.invalid" });

        var (serverUrl, resolved) = await AvalonClient.DiscoverAmongAsync(
            new[] { entry }, TargetNetwork.ForNetworkId("avalon-test"), handler.ToHttpClient(), default);

        Assert.Equal("http://candidate-b.invalid", serverUrl);
        Assert.Equal("avalon-test", resolved.NetworkId);
    }

    [Fact]
    public async Task DiscoverAsync_ReportsNoCandidates_ForAnUnpinnedTarget()
    {
        var handler = new StubHttpMessageHandler();
        var target = TargetNetwork.ForNetworkId("avalon-nowhere");

        var ex = await Assert.ThrowsAsync<DiscoveryException>(() =>
            AvalonClient.DiscoverAmongAsync(Array.Empty<TrustAnchorEntry>(), target, handler.ToHttpClient(), default));

        Assert.Equal(DiscoveryErrorKind.NoCandidates, ex.Kind);
    }

    [Fact]
    public async Task DiscoverAsync_ReportsNoneVerified_WhenEveryCandidateFails()
    {
        var signingKey = GenerateKey();
        var impostorKey = GenerateKey();
        // Pinned entry's key won't match this server's forged STH.
        var forgedSth = SignedSth(impostorKey, "avalon-test");

        var handler = new StubHttpMessageHandler().Enqueue(SthJson(forgedSth));
        var entry = Anchor(
            "avalon-test", PublicKeyHex(signingKey), seedNodes: new List<string> { "http://candidate.invalid" });

        var ex = await Assert.ThrowsAsync<DiscoveryException>(() =>
            AvalonClient.DiscoverAmongAsync(
                new[] { entry }, TargetNetwork.ForNetworkId("avalon-test"), handler.ToHttpClient(), default));

        Assert.Equal(DiscoveryErrorKind.NoneVerified, ex.Kind);
        Assert.Single(ex.Attempts);
    }

    private sealed class NodeSpec
    {
        public bool ForgedSth { get; init; }
        public int SthDelayMs { get; init; }
        public int? StatusDelayMs { get; init; } // null: /nodes/status answers 500
    }

    private sealed class RoutingHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, NodeSpec> _nodes;
        private readonly string _good;
        private readonly string _forged;
        public List<string> Requests { get; } = new();

        public RoutingHandler(Dictionary<string, NodeSpec> nodes, string good, string forged)
        {
            _nodes = nodes;
            _good = good;
            _forged = forged;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken ct)
        {
            var uri = request.RequestUri!;
            lock (Requests) { Requests.Add($"{uri.Scheme}://{uri.Host}{uri.AbsolutePath}"); }
            var spec = _nodes[$"{uri.Scheme}://{uri.Host}"];
            if (uri.AbsolutePath == "/ledger/sth/latest")
            {
                await Task.Delay(spec.SthDelayMs, ct);
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(spec.ForgedSth ? _forged : _good) };
            }
            if (spec.StatusDelayMs is not int delay)
            {
                return new HttpResponseMessage(HttpStatusCode.InternalServerError);
            }
            await Task.Delay(delay, ct);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") };
        }
    }

    private static readonly string[] Hosts = { "http://a.invalid", "http://b.invalid", "http://c.invalid" };

    private static async Task<(DiscoveryResult Result, RoutingHandler Handler)> Rank(
        Dictionary<string, NodeSpec> nodes, DiscoveryRankOptions? options = null)
    {
        var key = GenerateKey();
        var handler = new RoutingHandler(
            nodes, SthJson(SignedSth(key, "avalon-test")), SthJson(SignedSth(GenerateKey(), "avalon-test")));
        var entry = Anchor("avalon-test", PublicKeyHex(key), seedNodes: nodes.Keys.ToList());
        var result = await AvalonClient.DiscoverAmongAsync(
            new[] { entry }, TargetNetwork.ForNetworkId("avalon-test"), new HttpClient(handler), default, options);
        return (result, handler);
    }

    private static DiscoveryRankOptions Options(int maxTimed = 5, int probeMs = 300, int windowMs = 300) =>
        new() { MaxTimed = maxTimed, ProbeTimeout = TimeSpan.FromMilliseconds(probeMs), CollectWindow = TimeSpan.FromMilliseconds(windowMs) };

    [Fact]
    public async Task Ranking_ChoosesTheFastestVerifiedCandidate()
    {
        var (result, _) = await Rank(new()
        {
            [Hosts[0]] = new NodeSpec { StatusDelayMs = 120 },
            [Hosts[1]] = new NodeSpec { StatusDelayMs = 1 },
            [Hosts[2]] = new NodeSpec { StatusDelayMs = 50 },
        }, Options());

        Assert.Equal(Hosts[1], result.ServerUrl);
        Assert.Equal(new[] { Hosts[1], Hosts[2], Hosts[0] }, result.Verified.Select(v => v.ServerUrl));
        Assert.All(result.Verified, v => Assert.NotNull(v.Latency));
    }

    [Fact]
    public async Task Ranking_NeverChoosesAnUnverifiedFastCandidate()
    {
        var (result, handler) = await Rank(new()
        {
            [Hosts[0]] = new NodeSpec { ForgedSth = true, StatusDelayMs = 1 },
            [Hosts[1]] = new NodeSpec { StatusDelayMs = 60 },
            [Hosts[2]] = new NodeSpec { StatusDelayMs = 20 },
        }, Options());

        Assert.Equal(Hosts[2], result.ServerUrl);
        Assert.DoesNotContain(handler.Requests, r => r == Hosts[0] + "/nodes/status");
    }

    [Fact]
    public async Task Ranking_SingleVerifiedCandidate_MakesNoExtraRequest()
    {
        var (result, handler) = await Rank(new()
        {
            [Hosts[0]] = new NodeSpec { ForgedSth = true },
            [Hosts[1]] = new NodeSpec { StatusDelayMs = 1 },
        }, Options());

        Assert.Equal(Hosts[1], result.ServerUrl);
        Assert.DoesNotContain(handler.Requests, r => r.EndsWith("/nodes/status"));
    }

    [Fact]
    public async Task Ranking_FailedProbesFallBackToCandidateOrder_AndStayEligible()
    {
        var (allFailed, _) = await Rank(new()
        {
            [Hosts[0]] = new NodeSpec(),
            [Hosts[1]] = new NodeSpec(),
        }, Options());
        Assert.Equal(Hosts[0], allFailed.ServerUrl);
        Assert.All(allFailed.Verified, v => Assert.Null(v.Latency));

        var (mixed, _) = await Rank(new()
        {
            [Hosts[0]] = new NodeSpec(),
            [Hosts[1]] = new NodeSpec { StatusDelayMs = 5 },
        }, Options());
        Assert.Equal(Hosts[1], mixed.ServerUrl);
        Assert.Equal(Hosts[0], mixed.Verified[1].ServerUrl);
    }

    [Fact]
    public async Task Ranking_BoundsTimedCandidatesAndProbeTime()
    {
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var (result, handler) = await Rank(new()
        {
            [Hosts[0]] = new NodeSpec { StatusDelayMs = 5000 },
            [Hosts[1]] = new NodeSpec { StatusDelayMs = 5000 },
            [Hosts[2]] = new NodeSpec { StatusDelayMs = 5000 },
        }, Options(maxTimed: 2, probeMs: 50));

        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(2));
        Assert.Equal(Hosts[0], result.ServerUrl);
        Assert.DoesNotContain(handler.Requests, r => r == Hosts[2] + "/nodes/status");
    }

    [Fact]
    public async Task Ranking_StopsCollectingAfterTheWindowFollowingTheFirstVerification()
    {
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var (result, _) = await Rank(new()
        {
            [Hosts[0]] = new NodeSpec { StatusDelayMs = 5 },
            [Hosts[1]] = new NodeSpec { SthDelayMs = 2000, StatusDelayMs = 1 },
        }, Options(windowMs: 50));

        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(1));
        Assert.Equal(Hosts[0], result.ServerUrl);
        Assert.Single(result.Verified);
    }
}
