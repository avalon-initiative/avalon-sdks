using System;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Xunit;

namespace Avalon.Sdk.Tests;

public class DeviceGrantTests
{
    private static AccountSession SessionWithKey(StubHttpMessageHandler handler) =>
        AccountSession.ForTesting(
            handler.ToHttpClient(),
            signing: new AccountSession.SigningKeyMaterial(new Ed25519PrivateKeyParameters(new SecureRandom()), Guid.NewGuid()));

    private static string Base64(int length, int at = -1, byte value = 0)
    {
        var bytes = new byte[length];
        if (at >= 0)
        {
            bytes[at] = value;
        }
        return Convert.ToBase64String(bytes);
    }

    [Theory]
    [InlineData("AAAA")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=")] // non-canonical trailing bits
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= ")] // surrounding whitespace
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nAAAAAAA=")] // embedded whitespace
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")] // unpadded
    public async Task ApproveDeviceGrantAsync_RejectsAKeyThatIsNotCanonicalBase64Of32Bytes(string key)
    {
        var handler = new StubHttpMessageHandler();
        var session = SessionWithKey(handler);

        await Assert.ThrowsAsync<ArgumentException>(() => session.ApproveDeviceGrantAsync(Guid.NewGuid(), key));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task ApproveDeviceGrantAsync_RejectsASmallOrderKeyBeforeAnyRequest()
    {
        var handler = new StubHttpMessageHandler();
        var session = SessionWithKey(handler);

        // y = 1 is the identity point.
        await Assert.ThrowsAsync<ArgumentException>(
            () => session.ApproveDeviceGrantAsync(Guid.NewGuid(), Base64(32, 0, 1)));
        Assert.Empty(handler.Requests);
    }

    private sealed class Harness
    {
        public StubHttpMessageHandler Handler { get; } = new StubHttpMessageHandler();
        public Ed25519PrivateKeyParameters Key { get; } = new Ed25519PrivateKeyParameters(new SecureRandom());
        public Guid KeyId { get; } = Guid.NewGuid();
        public IdentityId Identity { get; } = IdentityId.RandomForTests();
        public byte[] PublicKey => Key.GeneratePublicKey().GetEncoded();
        public AccountSession Session => AccountSession.ForTesting(
            Handler.ToHttpClient(), identityId: Identity, signing: new AccountSession.SigningKeyMaterial(Key, KeyId));

        public (long Seq, string? PrevHash, byte[] Signature, JsonElement Body) Sent(int index)
        {
            var body = JsonDocument.Parse(Handler.Requests[index].Body!).RootElement.Clone();
            var prev = body.GetProperty("prev_hash");
            return (
                body.GetProperty("seq").GetInt64(),
                prev.ValueKind == JsonValueKind.Null ? null : prev.GetString(),
                Convert.FromBase64String(body.GetProperty("signature").GetString()!),
                body);
        }
    }

    private const string Head = "a102d9b032710b8e61fe255b559f5cbc831adb3bd7efdd37c289bc7dde6f88f5";

    private static string Stale(long headSeq, string? headHash) =>
        JsonSerializer.Serialize(new { error = "stale", code = "IDENTITY_CHAIN_POSITION_STALE", head_seq = headSeq, head_hash = headHash });

    private static string DeviceJson(Guid id, string key) =>
        JsonSerializer.Serialize(new { id, public_key = key, added_at = "2026-01-01T00:00:00Z" });

    private static byte[] NewDeviceKey() => new Ed25519PrivateKeyParameters(new SecureRandom()).GeneratePublicKey().GetEncoded();

    [Fact]
    public async Task ApproveDeviceGrantAsync_SignsTheFirstChainPosition()
    {
        var h = new Harness();
        var grant = Guid.NewGuid();
        var requested = NewDeviceKey();
        h.Handler.Enqueue(DeviceJson(grant, Convert.ToBase64String(requested)));

        var device = await h.Session.ApproveDeviceGrantAsync(grant, Convert.ToBase64String(requested));

        Assert.Equal(grant, device.Id);
        var sent = h.Sent(0);
        Assert.Equal(1, sent.Seq);
        Assert.Null(sent.PrevHash);
        Assert.Equal(h.KeyId, sent.Body.GetProperty("approver_signing_key_id").GetGuid());
        var bytes = IdentitySigning.DeviceGrantApprovalSigningBytes(grant, h.Identity, h.KeyId, requested, 1, null);
        Assert.True(IdentitySigning.VerifyStrict(h.PublicKey, bytes, sent.Signature));
        Assert.EndsWith($"/me/devices/grants/{grant}/approve", h.Handler.Requests[0].Url);
    }

    [Fact]
    public async Task ApproveDeviceGrantAsync_ResignsOnceAtTheHeadTheServerReturns()
    {
        var h = new Harness();
        var grant = Guid.NewGuid();
        var requested = NewDeviceKey();
        h.Handler.Enqueue(HttpStatusCode.Conflict, Stale(4, Head)).Enqueue(DeviceJson(grant, Convert.ToBase64String(requested)));

        await h.Session.ApproveDeviceGrantAsync(grant, Convert.ToBase64String(requested));

        Assert.Equal(2, h.Handler.Requests.Count);
        var retry = h.Sent(1);
        Assert.Equal(5, retry.Seq);
        Assert.Equal(Head, retry.PrevHash);
        var bytes = IdentitySigning.DeviceGrantApprovalSigningBytes(grant, h.Identity, h.KeyId, requested, 5, LedgerEntry.ParseHash("h", Head));
        Assert.True(IdentitySigning.VerifyStrict(h.PublicKey, bytes, retry.Signature));
        Assert.False(IdentitySigning.VerifyStrict(h.PublicKey, bytes, h.Sent(0).Signature));
    }

    [Fact]
    public async Task ApproveDeviceGrantAsync_ASecondStaleAnswerIsSurfaced()
    {
        var h = new Harness();
        h.Handler.Enqueue(HttpStatusCode.Conflict, Stale(4, Head)).Enqueue(HttpStatusCode.Conflict, Stale(5, Head));

        var ex = await Assert.ThrowsAsync<AvalonChainPositionStaleException>(
            () => h.Session.ApproveDeviceGrantAsync(Guid.NewGuid(), Convert.ToBase64String(NewDeviceKey())));

        Assert.Equal(5, ex.HeadSeq);
        Assert.Equal(2, h.Handler.Requests.Count);
    }

    [Fact]
    public async Task RevokeDeviceAsync_ResignsAtAnEmptyChainHead()
    {
        var h = new Harness();
        var target = Guid.NewGuid();
        h.Handler.Enqueue(HttpStatusCode.Conflict, Stale(0, null)).Enqueue("{}");

        await h.Session.RevokeDeviceAsync(target);

        Assert.Equal(2, h.Handler.Requests.Count);
        var sent = h.Sent(1);
        Assert.Equal(1, sent.Seq);
        Assert.Null(sent.PrevHash);
        Assert.Equal(h.KeyId, sent.Body.GetProperty("revoked_by_signing_key_id").GetGuid());
        var bytes = IdentitySigning.SigningKeyRevokedSigningBytes(h.Identity, target, h.KeyId, 1, null);
        Assert.True(IdentitySigning.VerifyStrict(h.PublicKey, bytes, sent.Signature));
        Assert.EndsWith($"/me/devices/{target}/revoke", h.Handler.Requests[1].Url);
    }

    [Fact]
    public async Task RevokeDeviceAsync_SignsTheReturnedHeadOnRetry()
    {
        var h = new Harness();
        var target = Guid.NewGuid();
        h.Handler.Enqueue(HttpStatusCode.Conflict, Stale(2, Head)).Enqueue("{}");

        await h.Session.RevokeDeviceAsync(target);

        var sent = h.Sent(1);
        Assert.Equal(3, sent.Seq);
        Assert.Equal(Head, sent.PrevHash);
        var bytes = IdentitySigning.SigningKeyRevokedSigningBytes(h.Identity, target, h.KeyId, 3, LedgerEntry.ParseHash("h", Head));
        Assert.True(IdentitySigning.VerifyStrict(h.PublicKey, bytes, sent.Signature));
    }

    [Fact]
    public async Task OtherConflicts_AreNotRetried()
    {
        var h = new Harness();
        h.Handler.Enqueue(HttpStatusCode.Conflict, "{\"error\":\"forked\",\"code\":\"IDENTITY_CHAIN_FORKED\"}");

        var ex = await Assert.ThrowsAsync<AvalonRequestException>(() => h.Session.RevokeDeviceAsync(Guid.NewGuid()));

        Assert.Equal("IDENTITY_CHAIN_FORKED", ex.Code);
        Assert.Single(h.Handler.Requests);
    }

    [Theory]
    [InlineData(0L, Head)]
    [InlineData(3L, null)]
    [InlineData(3L, "ABCD")]
    public async Task AnInconsistentHeadIsAProtocolError(long headSeq, string? headHash)
    {
        var h = new Harness();
        h.Handler.Enqueue(HttpStatusCode.Conflict, Stale(headSeq, headHash));

        await Assert.ThrowsAsync<AvalonProtocolException>(() => h.Session.RevokeDeviceAsync(Guid.NewGuid()));

        Assert.Single(h.Handler.Requests);
    }

    [Fact]
    public async Task ApproveAndRevoke_RequireALocalSigningKeyBeforeAnyRequest()
    {
        var handler = new StubHttpMessageHandler();
        var session = AccountSession.ForTesting(handler.ToHttpClient());

        await Assert.ThrowsAsync<InvalidOperationException>(() => session.RevokeDeviceAsync(Guid.NewGuid()));
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => session.ApproveDeviceGrantAsync(Guid.NewGuid(), Convert.ToBase64String(NewDeviceKey())));
        Assert.Empty(handler.Requests);
    }
}
