using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Avalon.Sdk;
using Xunit;

namespace Avalon.Sdk.Tests;

public class NodesTests
{
    [Fact]
    public async Task GetNodeStatusAsync_ReturnsRoles()
    {
        var handler = new StubHttpMessageHandler()
            .Enqueue("""
            {
                "protocol_version": "0.1.0",
                "network_id": "avalon-dev-local",
                "roles": ["combined"],
                "stale": false,
                "newest_known_peer_version": "0.1.0"
            }
            """);
        var client = new AvalonClient(new AvalonConfig("https://example.invalid", "test-key"), handler.ToHttpClient());

        var status = await client.GetNodeStatusAsync();

        Assert.Equal(new[] { "combined" }, status.Roles);
        Assert.Equal("0.1.0", status.ProtocolVersion);
    }

    private static string Fixture(string name)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "conformance", "fixtures", "nodes")))
        {
            dir = dir.Parent;
        }
        Assert.NotNull(dir);
        return File.ReadAllText(Path.Combine(dir!.FullName, "conformance", "fixtures", "nodes", name + ".json"));
    }

    private static AvalonClient ClientFor(HttpMessageHandler handler) =>
        new(new AvalonConfig("https://example.invalid", "test-key"), new HttpClient(handler));

    private sealed class RateLimitedHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var response = new HttpResponseMessage((HttpStatusCode)429)
            {
                Content = new StringContent("{\"error\":\"slow down\",\"code\":\"RATE_LIMITED\"}"),
            };
            response.Headers.TryAddWithoutValidation("Retry-After", "7");
            return Task.FromResult(response);
        }
    }

    [Fact]
    public async Task TopologyAsync_DecodesRecordedResponse()
    {
        var handler = new StubHttpMessageHandler().Enqueue(Fixture("topology"));
        var topology = await ClientFor(handler).TopologyAsync("https://node.test:8080/");

        Assert.Equal("https://node.test:8080/nodes/topology", handler.Requests[0].Url);
        Assert.Null(handler.Requests[0].AuthorizationToken);
        Assert.Equal("avalon-dev-local", topology.Self.NetworkId);
        Assert.Equal(3, topology.Self.Coordinate.Vector.Count);
        Assert.Contains(topology.Neighbors, n => n.Latency != null && n.Coordinate != null);
        Assert.Single(topology.Mirrors);
    }

    [Fact]
    public async Task TopologyAsync_DefaultsToConfiguredServer()
    {
        var handler = new StubHttpMessageHandler().Enqueue(Fixture("topology"));
        await ClientFor(handler).TopologyAsync();
        Assert.Equal("https://example.invalid/nodes/topology", handler.Requests[0].Url);
    }

    [Fact]
    public async Task ProbeAsync_DecodesRecordedResponse()
    {
        var handler = new StubHttpMessageHandler().Enqueue(Fixture("probe"));
        var result = await ClientFor(handler).ProbeAsync("http://other:8080", 3);

        Assert.Equal(HttpMethod.Post, handler.Requests[0].Method);
        Assert.Equal("https://example.invalid/nodes/probe", handler.Requests[0].Url);
        Assert.Equal("{\"samples\":3,\"target\":\"http://other:8080\"}", Canonical(handler.Requests[0].Body!));
        Assert.True(result.Ok);
        Assert.Equal(3, result.SamplesMs.Count);
        Assert.NotNull(result.MedianMs);
    }

    [Fact]
    public async Task TraceAsync_DecodesRecordedResponse()
    {
        var handler = new StubHttpMessageHandler().Enqueue(Fixture("trace"));
        var result = await ClientFor(handler).TraceAsync("http://other:8080");

        Assert.Equal("{\"target\":\"http://other:8080\"}", Canonical(handler.Requests[0].Body!));
        Assert.True(result.Reached);
        Assert.Equal(new[] { 0, 1 }, result.Hops.Select(h => h.Index).ToArray());
        Assert.NotNull(result.Hops.First().ToNextMs);
        Assert.Null(result.Hops.Last().ToNextMs);
    }

    [Fact]
    public async Task TraceAsync_SendsTtl()
    {
        var handler = new StubHttpMessageHandler().Enqueue(Fixture("trace"));
        await ClientFor(handler).TraceAsync("http://other:8080", 4);
        Assert.Equal("{\"target\":\"http://other:8080\",\"ttl\":4}", Canonical(handler.Requests[0].Body!));
    }

    [Fact]
    public async Task NodeCalls_SurfaceRateLimitWithRetryAfter()
    {
        var client = ClientFor(new RateLimitedHandler());
        var calls = new Func<Task>[]
        {
            () => client.TopologyAsync(),
            () => client.ProbeAsync("http://other:8080"),
            () => client.TraceAsync("http://other:8080"),
        };
        foreach (var call in calls)
        {
            var ex = await Assert.ThrowsAsync<AvalonRequestException>(call);
            Assert.True(ex.IsRateLimited);
            Assert.Equal(TimeSpan.FromSeconds(7), ex.RetryAfter);
        }
    }

    [Fact]
    public async Task NodeCalls_RejectMalformedBodies()
    {
        var handler = new StubHttpMessageHandler().Enqueue("not json").Enqueue("{\"target\":").Enqueue("null");
        var client = ClientFor(handler);
        await Assert.ThrowsAnyAsync<System.Text.Json.JsonException>(() => client.TopologyAsync());
        await Assert.ThrowsAnyAsync<System.Text.Json.JsonException>(() => client.ProbeAsync("http://o:1"));
        await Assert.ThrowsAnyAsync<System.Text.Json.JsonException>(() => client.TraceAsync("http://o:1"));
    }

    private static string Canonical(string json)
    {
        var doc = System.Text.Json.JsonDocument.Parse(json);
        var props = doc.RootElement.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal);
        return "{" + string.Join(",", props.Select(p => $"\"{p.Name}\":{p.Value.GetRawText()}")) + "}";
    }
}
