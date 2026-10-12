using System;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Xunit;

namespace Avalon.Sdk.Tests;

/// <summary>The network id a signed action binds is declared or verified, never the node's own claim.</summary>
public class NetworkIdTests
{
    private const string Net = "avalon-id-net";

    private sealed class Rig
    {
        public StubHttpMessageHandler Verify { get; } = new StubHttpMessageHandler();
        public StubHttpMessageHandler Server { get; } = new StubHttpMessageHandler();
        public Ed25519PrivateKeyParameters Author { get; } = NetworkTests.GenerateKey();
        public Ed25519PrivateKeyParameters Key { get; } = new Ed25519PrivateKeyParameters(new SecureRandom());
        public IdentityId Identity { get; } = IdentityId.RandomForTests();
        public Guid KeyId { get; } = Guid.NewGuid();

        public AccountSession Session(string? declared, string verifyKeyHex)
        {
            var client = new AvalonClient(new AvalonConfig("https://example.invalid", "i"), Verify.ToHttpClient());
            return AccountSession.ForTesting(
                Server.ToHttpClient(), identityId: Identity, signing: new AccountSession.SigningKeyMaterial(Key, KeyId),
                networkId: declared, verifyNetwork: ct => client.VerifyNetworkAsync(ct: ct));
        }

        public string Anchors(string verifyKeyHex, string networkId = Net) =>
            "{\"networks\":[{\"label\":\"n\",\"network_id\":\"" + networkId + "\",\"verify_key\":\"" + verifyKeyHex +
            "\",\"signing_key_id\":\"test-key\",\"environment\":\"local-dev\"}]}";

        public string Head(string networkId = Net) => NetworkTests.SthJson(NetworkTests.SignedSth(Author, networkId));
    }

    private static Task Revoke(AccountSession session) => session.RevokeDeviceAsync(Guid.NewGuid());

    [Fact]
    public async Task ADeclaredNetworkId_IsUsedWithNoVerificationCall()
    {
        var rig = new Rig();
        rig.Server.Enqueue("{}");

        await Revoke(rig.Session(Net, NetworkTests.PublicKeyHex(rig.Author)));

        Assert.Empty(rig.Verify.Requests);
        var body = JsonDocument.Parse(rig.Server.Requests[0].Body!).RootElement;
        var bytes = IdentitySigning.SigningKeyRevokedSigningBytes(
            Net, rig.Identity, Guid.Parse(rig.Server.Requests[0].Url.Split('/')[^2]), rig.KeyId, 1, null);
        var publicKey = rig.Key.GeneratePublicKey().GetEncoded();
        Assert.True(IdentitySigning.VerifyStrict(publicKey, bytes, Convert.FromBase64String(body.GetProperty("signature").GetString()!)));
    }

    [Fact]
    public async Task AVerifiedNetwork_SuppliesTheEntrysIdAndIsResolvedOnce()
    {
        var rig = new Rig();
        var keyHex = NetworkTests.PublicKeyHex(rig.Author);
        rig.Verify.Enqueue(rig.Anchors(keyHex)).Enqueue(rig.Head());
        rig.Server.Enqueue("{}").Enqueue("{}");
        var session = rig.Session(null, keyHex);

        await Revoke(session);
        await Revoke(session);

        Assert.Equal(2, rig.Verify.Requests.Count);
        Assert.Equal(2, rig.Server.Requests.Count);
    }

    [Fact]
    public async Task AMismatch_ThrowsBeforeAnythingIsSent()
    {
        var rig = new Rig();
        var otherKey = NetworkTests.PublicKeyHex(NetworkTests.GenerateKey());
        rig.Verify.Enqueue(rig.Anchors(otherKey)).Enqueue(rig.Head());

        var ex = await Assert.ThrowsAsync<NetworkNotVerifiedException>(() => Revoke(rig.Session(null, otherKey)));

        Assert.Equal(NetworkTrustStatusKind.Mismatch, ex.Status.Kind);
        Assert.Empty(rig.Server.Requests);
    }

    [Fact]
    public async Task AnUnknownNetwork_ThrowsBeforeAnythingIsSent()
    {
        var rig = new Rig();
        rig.Verify.Enqueue("{\"networks\":[]}").Enqueue(rig.Head());

        var ex = await Assert.ThrowsAsync<NetworkNotVerifiedException>(() => Revoke(rig.Session(null, "")));

        Assert.Equal(NetworkTrustStatusKind.UnknownNetwork, ex.Status.Kind);
        Assert.Empty(rig.Server.Requests);
    }

    [Fact]
    public async Task AnUnreachableServer_ThrowsBeforeAnythingIsSent()
    {
        var rig = new Rig();
        var keyHex = NetworkTests.PublicKeyHex(rig.Author);
        rig.Verify.Enqueue(rig.Anchors(keyHex)).Enqueue(HttpStatusCode.ServiceUnavailable, "{}");

        var ex = await Assert.ThrowsAsync<NetworkNotVerifiedException>(() => Revoke(rig.Session(null, keyHex)));

        Assert.Equal(NetworkTrustStatusKind.Unreachable, ex.Status.Kind);
        Assert.Empty(rig.Server.Requests);
    }

    [Fact]
    public async Task AttestationIssuance_ThrowsBeforeTheChallengeWhenTheNetworkIsNotVerified()
    {
        var handler = new StubHttpMessageHandler();
        var session = Session.ForTesting(
            new[] { "achievements.issue" }, handler.ToHttpClient(), integratorKeyId: Guid.NewGuid().ToString(),
            integratorSlug: "dragons-inc", signingKey: new byte[32],
            verifyNetwork: _ => Task.FromResult(NetworkTrustStatus.UnknownNetwork("x")));

        await Assert.ThrowsAsync<NetworkNotVerifiedException>(() => session.IssueAchievementAsync("k"));

        Assert.Empty(handler.Requests);
    }
}
