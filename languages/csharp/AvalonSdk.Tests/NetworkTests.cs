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

    [Fact]
    public void BundledTrustAnchors_ParsesTheRealCheckedInFile()
    {
        var anchors = TrustAnchors.Bundled;
        Assert.Contains(anchors, a => a.NetworkId == "avalon-dev-local");
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
        var handler = new StubHttpMessageHandler().Enqueue(SthJson(sth));
        var client = new AvalonClient(new AvalonConfig("https://example.invalid", "test-integrator"), handler.ToHttpClient());

        // No bundled trust anchor for "avalon-test" in this build, so the real end-to-end path
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
}
