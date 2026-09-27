using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Avalon.Sdk;
using Avalon.Sdk.Generated;
using Xunit;

namespace Avalon.Sdk.Tests;

public class ShardNamesTests
{
    private const string Claim = """
        {"name":"example.org","self_certifying_id":"node:ab12","proof_method":"dns-txt","verified_at":"2026-09-25T00:00:00Z"}
        """;

    private static AvalonClient ClientFor(StubHttpMessageHandler handler) =>
        new(new AvalonConfig("https://example.invalid", "test-key"), handler.ToHttpClient());

    [Fact]
    public async Task ResolveNameAsync_GetsTheNameAndSendsNoCredentials()
    {
        var handler = new StubHttpMessageHandler().Enqueue(Claim);

        var got = await ClientFor(handler).ResolveNameAsync("example.org");

        Assert.Equal("node:ab12", got.SelfCertifyingId);
        Assert.Equal(HttpMethod.Get, handler.Requests[0].Method);
        Assert.Equal("https://example.invalid/shards/name/example.org", handler.Requests[0].Url);
        Assert.Null(handler.Requests[0].AuthorizationToken);
    }

    [Fact]
    public async Task ListShardNamesAsync_EncodesTheShardId()
    {
        var handler = new StubHttpMessageHandler().Enqueue("[" + Claim + "]");

        var got = await ClientFor(handler).ListShardNamesAsync("node:ab12");

        Assert.Single(got);
        Assert.Equal("https://example.invalid/shards/node%3Aab12/name-claims", handler.Requests[0].Url);
    }

    [Fact]
    public async Task SubmitNameClaimAsync_PostsTheSignedClaimAsJson()
    {
        var handler = new StubHttpMessageHandler().Enqueue(Claim);
        var claim = new NameClaimRequest
        {
            SelfCertifyingId = "node:ab12",
            PublicKey = new string('a', 64),
            Name = "example.org",
            CreatedAt = System.DateTimeOffset.Parse("2026-09-25T00:00:00Z"),
            Signature = new string('b', 128),
        };

        var got = await ClientFor(handler).SubmitNameClaimAsync(claim);

        Assert.Equal("example.org", got.Name);
        Assert.Equal(HttpMethod.Post, handler.Requests[0].Method);
        Assert.Equal("https://example.invalid/shards/node%3Aab12/name-claims", handler.Requests[0].Url);
        using var body = JsonDocument.Parse(handler.Requests[0].Body!);
        Assert.Equal("node:ab12", body.RootElement.GetProperty("self_certifying_id").GetString());
        Assert.Equal("example.org", body.RootElement.GetProperty("name").GetString());
    }

    [Fact]
    public async Task ResolveNameAsync_SurfacesANotFoundRefusal()
    {
        var handler = new StubHttpMessageHandler().Enqueue(HttpStatusCode.NotFound, """{"code":"not_found"}""");

        var error = await Assert.ThrowsAsync<AvalonRequestException>(() => ClientFor(handler).ResolveNameAsync("missing.example"));

        Assert.Equal(HttpStatusCode.NotFound, error.StatusCode);
    }
}
