using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using Avalon.Sdk;
using Xunit;

namespace Avalon.Sdk.Tests;

public class TopologyWalkTests
{
    private const string A = "http://a.test:8080";
    private const string B = "http://b.test:8080";
    private const string C = "http://c.test:8080";
    private const string D = "http://d.test:8080";

    private static readonly JsonNode Fixture = JsonNode.Parse(LoadFixture())!;

    private static string LoadFixture()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "conformance", "fixtures", "nodes")))
        {
            dir = dir.Parent;
        }
        return File.ReadAllText(Path.Combine(dir!.FullName, "conformance", "fixtures", "nodes", "topology.json"));
    }

    private sealed class Links
    {
        public List<(string Url, double Ms)> Neighbors { get; } = new();
        public List<string> Known { get; } = new();
        public List<string> Mirrors { get; } = new();
    }

    private static Links L(params string[] neighbors)
    {
        var links = new Links();
        foreach (var n in neighbors) links.Neighbors.Add((n, 2.0));
        return links;
    }

    private static string Body(string origin, Links links)
    {
        var value = JsonNode.Parse(Fixture.ToJsonString())!;
        value["self"]!["base_url"] = origin;
        var latency = Fixture["neighbors"]!.AsArray().Select(n => n!["latency"]).First(l => l != null)!;
        var neighbors = new JsonArray();
        foreach (var (url, ms) in links.Neighbors)
        {
            var l = JsonNode.Parse(latency.ToJsonString())!;
            l["last_ms"] = ms;
            neighbors.Add(new JsonObject { ["base_url"] = url, ["bootstrap"] = false, ["roles"] = new JsonArray(), ["last_announced_at"] = null, ["latency"] = l });
        }
        value["neighbors"] = neighbors;
        var known = new JsonArray();
        foreach (var k in links.Known)
        {
            known.Add(new JsonObject { ["base_url"] = k, ["last_announced_at"] = "2026-01-01T00:00:00Z", ["protocol_version"] = "0.1.0", ["roles"] = new JsonArray() });
        }
        value["known"] = known;
        var mirrors = new JsonArray();
        foreach (var m in links.Mirrors)
        {
            var mirror = JsonNode.Parse(Fixture["mirrors"]![0]!.ToJsonString())!;
            mirror["source_url"] = m;
            mirrors.Add(mirror);
        }
        value["mirrors"] = mirrors;
        return value.ToJsonString();
    }

    private delegate Task<HttpResponseMessage> Responder(int call, CancellationToken ct);

    private sealed class FakeNetwork : HttpMessageHandler
    {
        private readonly Dictionary<string, Responder> _nodes = new();
        private readonly Dictionary<string, int> _calls = new();
        private readonly object _gate = new();

        public FakeNetwork Node(string origin, Links links)
        {
            _nodes[origin] = (_, _) => Task.FromResult(Json(Body(origin, links)));
            return this;
        }

        public FakeNetwork Node(string origin, Responder responder)
        {
            _nodes[origin] = responder;
            return this;
        }

        public int Calls(string origin)
        {
            lock (_gate) return _calls.GetValueOrDefault(origin);
        }

        public static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK) =>
            new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var origin = request.RequestUri!.GetLeftPart(UriPartial.Authority);
            int call;
            lock (_gate)
            {
                call = _calls[origin] = _calls.GetValueOrDefault(origin) + 1;
            }
            if (!_nodes.TryGetValue(origin, out var responder))
            {
                throw new HttpRequestException("connection refused");
            }
            return responder(call, ct);
        }
    }

    private static AvalonClient ClientFor(HttpMessageHandler handler) =>
        new(new AvalonConfig("https://example.invalid", "test-key"), new HttpClient(handler));

    private static Task<HttpResponseMessage> Hang(int _, CancellationToken ct) =>
        Task.Delay(Timeout.Infinite, ct).ContinueWith<HttpResponseMessage>(_ => throw new OperationCanceledException(ct), TaskScheduler.Default);

    private static Responder RateLimited(string retryAfter) => (_, _) =>
    {
        var response = FakeNetwork.Json("{\"code\":\"RATE_LIMITED\"}", (HttpStatusCode)429);
        response.Headers.TryAddWithoutValidation("Retry-After", retryAfter);
        return Task.FromResult(response);
    };

    private static WalkNode NodeOf(TopologyGraph graph, string url) => graph.Nodes.Single(n => n.Url == url);

    [Fact]
    public void NormalizeNodeUrl_LowercasesAndTrims()
    {
        Assert.Equal(A, AvalonClient.NormalizeNodeUrl("HTTP://A.Test:8080/"));
        Assert.Equal(A, AvalonClient.NormalizeNodeUrl(" http://a.test:8080// "));
        Assert.Equal("http://a.test", AvalonClient.NormalizeNodeUrl("http://a.test:80/"));
        Assert.Null(AvalonClient.NormalizeNodeUrl("ftp://a.test"));
        Assert.Null(AvalonClient.NormalizeNodeUrl("nonsense"));
    }

    [Fact]
    public async Task WalksAConnectedGraphWithTypedEdgesAndPerReporterLatency()
    {
        var a = new Links();
        a.Neighbors.Add((B, 3.0));
        a.Known.Add(C);
        a.Mirrors.Add(B);
        var b = new Links();
        b.Neighbors.Add((A, 4.0));
        b.Neighbors.Add((C, 5.0));
        var net = new FakeNetwork().Node(A, a).Node(B, b).Node(C, new Links());
        var events = new List<WalkEvent>();

        var graph = await ClientFor(net).WalkTopologyAsync(new[] { A }, new WalkOptions { OnProgress = events.Add });

        Assert.Equal(new[] { A, B, C }, graph.Nodes.Select(n => n.Url).ToArray());
        Assert.All(graph.Nodes, n => Assert.Equal(WalkNodeStatus.Visited, n.Status));
        Assert.Equal(new[] { 0, 1, 1 }, graph.Nodes.Select(n => n.Depth).ToArray());
        Assert.False(graph.Cancelled);
        Assert.False(graph.Truncated.MaxNodes || graph.Truncated.MaxDepth);
        Assert.Equal(5, graph.Edges.Count);
        var ab = graph.Edges.Single(e => e.From == A && e.To == B && e.Kind == WalkEdgeKind.Active);
        var ba = graph.Edges.Single(e => e.From == B && e.To == A);
        Assert.Equal(A, ab.Latency!.ObservedBy);
        Assert.Equal(3.0, ab.Latency.LastMs);
        Assert.Equal(B, ba.Latency!.ObservedBy);
        Assert.Equal(4.0, ba.Latency.LastMs);
        Assert.Contains(graph.Edges, e => e.Kind == WalkEdgeKind.Mirror && e.Mirror != null && e.To == B);
        Assert.Contains(graph.Edges, e => e.Kind == WalkEdgeKind.Known && e.To == C);
        Assert.Equal(new[] { A, B }, NodeOf(graph, C).ReportedBy.OrderBy(x => x).ToArray());
        Assert.Equal(3, events.Count(e => e.Discovered));
        Assert.Equal(3, events.Count(e => !e.Discovered));
    }

    [Fact]
    public async Task APartitionedGraphYieldsTheReachableComponentAndSeedsCoverBoth()
    {
        var net = new FakeNetwork().Node(A, L(B)).Node(B, L()).Node(C, L(D)).Node(D, L());
        var single = await ClientFor(net).WalkTopologyAsync(new[] { A });
        Assert.Equal(new[] { A, B }, single.Nodes.Select(n => n.Url).ToArray());
        var both = await ClientFor(net).WalkTopologyAsync(new[] { A, C });
        Assert.Equal(new[] { A, B, C, D }, both.Nodes.Select(n => n.Url).OrderBy(x => x).ToArray());
        Assert.Equal(new[] { A, C }, both.Seeds.ToArray());
    }

    [Fact]
    public async Task AnUnreachableNodeIsRecordedAndTheWalkContinues()
    {
        var net = new FakeNetwork().Node(A, L(B, C)).Node(C, L());
        var graph = await ClientFor(net).WalkTopologyAsync(new[] { A });
        Assert.Equal(WalkNodeStatus.Unreachable, NodeOf(graph, B).Status);
        Assert.Equal(WalkFailureReason.Network, NodeOf(graph, B).Failure!.Reason);
        Assert.Equal(WalkNodeStatus.Visited, NodeOf(graph, C).Status);
    }

    [Fact]
    public async Task ClassifiesHttpStatusAndMalformedBodies()
    {
        var net = new FakeNetwork()
            .Node(A, L(B, C))
            .Node(B, (_, _) => Task.FromResult(FakeNetwork.Json("{\"error\":\"boom\"}", HttpStatusCode.InternalServerError)))
            .Node(C, (_, _) => Task.FromResult(FakeNetwork.Json("not json")));
        var graph = await ClientFor(net).WalkTopologyAsync(new[] { A });
        Assert.Equal(WalkFailureReason.HttpStatus, NodeOf(graph, B).Failure!.Reason);
        Assert.Equal(500, NodeOf(graph, B).Failure!.Status);
        Assert.Equal(WalkFailureReason.ProtocolError, NodeOf(graph, C).Failure!.Reason);
    }

    [Fact]
    public async Task ANodeThatTimesOutIsRecordedWithoutStoppingTheWalk()
    {
        var net = new FakeNetwork().Node(A, L(B, C)).Node(B, Hang).Node(C, L());
        var graph = await ClientFor(net).WalkTopologyAsync(new[] { A }, new WalkOptions { RequestTimeout = TimeSpan.FromMilliseconds(50) });
        Assert.Equal(WalkFailureReason.Timeout, NodeOf(graph, B).Failure!.Reason);
        Assert.Equal(WalkNodeStatus.Visited, NodeOf(graph, C).Status);
        Assert.False(graph.Cancelled);
    }

    [Fact]
    public async Task HonorsRetryAfterOnceAndThenSucceeds()
    {
        var net = new FakeNetwork().Node(A, L(B)).Node(B, (call, ct) => call == 1 ? RateLimited("0")(call, ct) : Task.FromResult(FakeNetwork.Json(Body(B, new Links()))));
        var graph = await ClientFor(net).WalkTopologyAsync(new[] { A });
        Assert.Equal(2, net.Calls(B));
        Assert.Equal(WalkNodeStatus.Visited, NodeOf(graph, B).Status);
    }

    [Fact]
    public async Task RecordsRateLimitedWhenTheWaitExceedsTheBudgetOrASecond429Follows()
    {
        var net = new FakeNetwork().Node(A, L(B, C)).Node(B, RateLimited("3600")).Node(C, RateLimited("0"));
        var graph = await ClientFor(net).WalkTopologyAsync(new[] { A });
        Assert.Equal(1, net.Calls(B));
        var b = NodeOf(graph, B).Failure!;
        Assert.Equal(WalkFailureReason.RateLimited, b.Reason);
        Assert.Equal(429, b.Status);
        Assert.Equal(3600, b.RetryAfterSeconds);
        Assert.Equal(2, net.Calls(C));
        Assert.Equal(WalkFailureReason.RateLimited, NodeOf(graph, C).Failure!.Reason);
    }

    [Fact]
    public async Task StopsAtMaxNodes()
    {
        var net = new FakeNetwork().Node(A, L(B, C, D)).Node(B, L()).Node(C, L()).Node(D, L());
        var graph = await ClientFor(net).WalkTopologyAsync(new[] { A }, new WalkOptions { MaxNodes = 2, Concurrency = 1 });
        Assert.Equal(new[] { A, B }, graph.Nodes.Select(n => n.Url).ToArray());
        Assert.True(graph.Truncated.MaxNodes);
        Assert.DoesNotContain(graph.Edges, e => e.To == C || e.To == D);
    }

    [Fact]
    public async Task StopsAtMaxDepthAndLeavesDeeperNodesUnvisited()
    {
        var net = new FakeNetwork().Node(A, L(B)).Node(B, L(C)).Node(C, L(D)).Node(D, L());
        var graph = await ClientFor(net).WalkTopologyAsync(new[] { A }, new WalkOptions { MaxDepth = 1 });
        Assert.Equal(0, net.Calls(C));
        Assert.Equal(3, graph.Nodes.Count);
        Assert.Equal(WalkNodeStatus.Unvisited, NodeOf(graph, C).Status);
        Assert.True(graph.Truncated.MaxDepth);
    }

    [Fact]
    public async Task DefaultLimitsBoundAnUnboundedGraph()
    {
        var hosts = Enumerable.Range(0, 200).Select(i => $"http://n{i}.test:8080").ToArray();
        var net = new FakeNetwork();
        for (var i = 0; i < hosts.Length; i++)
        {
            var links = new Links();
            foreach (var next in hosts.Skip(i + 1).Take(3)) links.Neighbors.Add((next, 1.0));
            net.Node(hosts[i], links);
        }
        var graph = await ClientFor(net).WalkTopologyAsync(new[] { hosts[0] });
        Assert.True(graph.Nodes.Count <= 64);
        Assert.True(graph.Nodes.Max(n => n.Depth) <= 5);
        Assert.True(graph.Truncated.MaxNodes || graph.Truncated.MaxDepth);
    }

    [Fact]
    public async Task DedupesUrlVariantsOfTheSameNode()
    {
        var a = new Links();
        a.Neighbors.Add(("HTTP://B.test:8080/", 1.0));
        a.Neighbors.Add((B, 1.0));
        a.Known.Add("http://b.test:8080//");
        var b = new Links();
        b.Neighbors.Add(("http://A.TEST:8080/", 1.0));
        var net = new FakeNetwork().Node(A, a).Node(B, b);
        var graph = await ClientFor(net).WalkTopologyAsync(new[] { A + "/", "HTTP://A.TEST:8080" });
        Assert.Equal(new[] { A, B }, graph.Nodes.Select(n => n.Url).ToArray());
        Assert.Equal(new[] { A }, graph.Seeds.ToArray());
        Assert.Equal(1, net.Calls(A));
        Assert.Equal(1, net.Calls(B));
        Assert.Equal(new[] { A }, graph.Nodes[1].ReportedBy.ToArray());
    }

    [Fact]
    public async Task CancellationReturnsThePartialGraph()
    {
        using var cts = new CancellationTokenSource();
        var net = new FakeNetwork().Node(A, L(B, C)).Node(B, Hang).Node(C, Hang);
        var graph = await ClientFor(net).WalkTopologyAsync(new[] { A }, new WalkOptions
        {
            OnProgress = e =>
            {
                if (!e.Discovered && e.Node.Url == A) cts.CancelAfter(20);
            },
        }, cts.Token);
        Assert.True(graph.Cancelled);
        Assert.Equal(WalkNodeStatus.Visited, NodeOf(graph, A).Status);
        Assert.Equal(WalkNodeStatus.Unvisited, NodeOf(graph, B).Status);
    }

    [Fact]
    public async Task AnAlreadyCancelledWalkMakesNoRequest()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var net = new FakeNetwork().Node(A, L());
        var graph = await ClientFor(net).WalkTopologyAsync(new[] { A }, null, cts.Token);
        Assert.True(graph.Cancelled);
        Assert.Equal(0, net.Calls(A));
    }

    [Fact]
    public async Task RecordsAnInvalidSeedAsUnreachable()
    {
        var graph = await ClientFor(new FakeNetwork()).WalkTopologyAsync(new[] { "not a url" });
        Assert.Equal(WalkNodeStatus.Unreachable, graph.Nodes.Single().Status);
    }
}
