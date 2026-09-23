using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Xunit;

namespace Avalon.Sdk.Tests;

public class RollbackTests
{
    private const string Since = "2026-09-01T00:00:00Z";

    [Fact]
    public async Task GetRollbackCandidatesAsync_DecodesResponseAndSendsSince()
    {
        var eventId = Guid.NewGuid();
        var requestId = Guid.NewGuid();
        var handler = new StubHttpMessageHandler().Enqueue(
            @"{""recovery_request_id"":""" + requestId + @""",""recovery_completed_at"":""2026-09-10T12:00:00Z"",""candidates"":[" +
            @"{""event_id"":""" + eventId + @""",""kind"":""friend.added"",""occurred_at"":""2026-09-05T00:00:00Z"",""summary"":""s"",""reversible"":false,""reason"":""nope"",""already_reversed"":true}]}");
        var session = AccountSession.ForTesting(handler.ToHttpClient());

        var result = await session.GetRollbackCandidatesAsync(Since);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.EndsWith("/me/rollback/candidates?since=" + Uri.EscapeDataString(Since), request.Url);
        Assert.Equal(requestId, result.RecoveryRequestId);
        var candidate = Assert.Single(result.Candidates);
        Assert.Equal(eventId, candidate.EventId);
        Assert.Equal("friend.added", candidate.Kind);
        Assert.False(candidate.Reversible);
        Assert.Equal("nope", candidate.Reason);
        Assert.True(candidate.AlreadyReversed);
    }

    [Fact]
    public async Task ReverseRollbackEventAsync_SignsCanonicalMessageAndReturnsReversalId()
    {
        var privateKey = new Ed25519PrivateKeyParameters(new SecureRandom());
        var publicKey = privateKey.GeneratePublicKey();
        var signingKeyId = Guid.NewGuid();
        var identityId = Guid.NewGuid();
        var eventId = Guid.NewGuid();
        var reversalId = Guid.NewGuid();
        var handler = new StubHttpMessageHandler().Enqueue(@"{""reversal_event_id"":""" + reversalId + @"""}");
        var session = AccountSession.ForTesting(
            handler.ToHttpClient(), identityId: identityId,
            signing: new AccountSession.SigningKeyMaterial(privateKey, signingKeyId));

        var result = await session.ReverseRollbackEventAsync(eventId, Since);

        Assert.Equal(reversalId, result);
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.EndsWith($"/me/rollback/{eventId}/reverse", request.Url);
        using var body = JsonDocument.Parse(request.Body!);
        Assert.Equal(Since, body.RootElement.GetProperty("since").GetString());
        Assert.Equal(signingKeyId, body.RootElement.GetProperty("signing_key_id").GetGuid());
        var signature = Convert.FromBase64String(body.RootElement.GetProperty("signature").GetString()!);
        var message = Encoding.UTF8.GetBytes($"avalon:rollback.reverse:v1:{eventId}:{identityId}:{Since}");
        var verifier = new Ed25519Signer();
        verifier.Init(false, publicKey);
        verifier.BlockUpdate(message, 0, message.Length);
        Assert.True(verifier.VerifySignature(signature));
    }

    [Theory]
    [InlineData(HttpStatusCode.Conflict, "ROLLBACK_NO_COMPLETED_RECOVERY")]
    [InlineData(HttpStatusCode.BadRequest, "INVALID_ROLLBACK_WINDOW")]
    public async Task GetRollbackCandidatesAsync_ErrorStatus_MapsToRequestException(HttpStatusCode status, string code)
    {
        var handler = new StubHttpMessageHandler().Enqueue(status, @"{""error"":""x"",""code"":""" + code + @"""}");
        var session = AccountSession.ForTesting(handler.ToHttpClient());

        var ex = await Assert.ThrowsAsync<AvalonRequestException>(() => session.GetRollbackCandidatesAsync(Since));

        Assert.Equal(status, ex.StatusCode);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound, "ROLLBACK_EVENT_NOT_ELIGIBLE")]
    [InlineData(HttpStatusCode.Conflict, "ROLLBACK_NOT_REVERSIBLE")]
    [InlineData(HttpStatusCode.Conflict, "ROLLBACK_ALREADY_REVERSED")]
    [InlineData(HttpStatusCode.BadRequest, "INVALID_ROLLBACK_WINDOW")]
    public async Task ReverseRollbackEventAsync_ErrorStatus_MapsToRequestException(HttpStatusCode status, string code)
    {
        var handler = new StubHttpMessageHandler().Enqueue(status, @"{""error"":""x"",""code"":""" + code + @"""}");
        var session = AccountSession.ForTesting(handler.ToHttpClient());

        var ex = await Assert.ThrowsAsync<AvalonRequestException>(() => session.ReverseRollbackEventAsync(Guid.NewGuid(), Since));

        Assert.Equal(status, ex.StatusCode);
    }
}
