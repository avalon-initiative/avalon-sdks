using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Xunit;

namespace Avalon.Sdk.Tests;

public class SessionsTests
{
    [Fact]
    public async Task ListSessionsAsync_DecodesEnvelopeAndMarksCurrent()
    {
        var a = Guid.NewGuid();
        var b = Guid.NewGuid();
        var passkey = Guid.NewGuid();
        var key = Guid.NewGuid();
        var handler = new StubHttpMessageHandler().Enqueue(
            @"{""sessions"":[" +
            @"{""id"":""" + a + @""",""created_at"":""2026-10-02T00:00:00Z"",""expires_at"":""2026-11-01T00:00:00Z"",""current"":true,""origin_passkey_id"":""" + passkey + @""",""origin_signing_key_id"":null}," +
            @"{""id"":""" + b + @""",""created_at"":""2026-10-01T00:00:00Z"",""expires_at"":""2026-10-31T00:00:00Z"",""current"":false,""origin_signing_key_id"":""" + key + @"""}]}");
        var session = AccountSession.ForTesting(handler.ToHttpClient());

        var sessions = await session.ListSessionsAsync();

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.EndsWith("/me/sessions", request.Url);
        Assert.Equal("test-token", request.AuthorizationToken);
        Assert.Equal(2, sessions.Count);
        Assert.Equal(a, sessions[0].Id);
        Assert.True(sessions[0].Current);
        Assert.Equal(passkey, sessions[0].OriginPasskeyId);
        Assert.Null(sessions[0].OriginSigningKeyId);
        Assert.Equal(DateTimeOffset.Parse("2026-10-02T00:00:00Z"), sessions[0].CreatedAt);
        Assert.Equal(DateTimeOffset.Parse("2026-11-01T00:00:00Z"), sessions[0].ExpiresAt);
        Assert.False(sessions[1].Current);
        Assert.Null(sessions[1].OriginPasskeyId);
        Assert.Equal(key, sessions[1].OriginSigningKeyId);
    }

    [Fact]
    public async Task RevokeSessionAsync_PostsToTheSessionRevokeRoute()
    {
        var id = Guid.NewGuid();
        var handler = new StubHttpMessageHandler().Enqueue("");
        var session = AccountSession.ForTesting(handler.ToHttpClient());

        await session.RevokeSessionAsync(id);

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.EndsWith($"/me/sessions/{id}/revoke", request.Url);
        Assert.Equal("test-token", request.AuthorizationToken);
    }

    [Fact]
    public async Task RevokeSessionAsync_SessionNotFound_MapsToRequestException()
    {
        var handler = new StubHttpMessageHandler().Enqueue(
            HttpStatusCode.NotFound, @"{""error"":""session not found"",""code"":""SESSION_NOT_FOUND""}");
        var session = AccountSession.ForTesting(handler.ToHttpClient());

        var ex = await Assert.ThrowsAsync<AvalonRequestException>(() => session.RevokeSessionAsync(Guid.NewGuid()));

        Assert.Equal(HttpStatusCode.NotFound, ex.StatusCode);
        Assert.Equal("SESSION_NOT_FOUND", ex.Code);
    }

    [Fact]
    public async Task LogoutAsync_PostsWithTheSessionToken()
    {
        var handler = new StubHttpMessageHandler().Enqueue("");
        var session = AccountSession.ForTesting(handler.ToHttpClient());

        await session.LogoutAsync();

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.EndsWith("/sessions/logout", request.Url);
        Assert.Equal("test-token", request.AuthorizationToken);
    }
}
