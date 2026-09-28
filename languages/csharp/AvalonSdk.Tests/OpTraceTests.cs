using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Avalon.Sdk;
using Xunit;

namespace Avalon.Sdk.Tests;

public class OpTraceTests
{
    private const string Status = """{"protocol_version":"0.1.0","network_id":"n","roles":["combined"],"stale":false}""";

    // Answers like a tracing node: Make builds the hops header from the request's trace id.
    private sealed class TracingNode : HttpMessageHandler
    {
        private readonly Func<string, string?> _make;
        public string? SentId;

        public TracingNode(Func<string, string?> make) { _make = make; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            SentId = request.Headers.TryGetValues("X-Avalon-Trace", out var v) ? v.First() : null;
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(Status, Encoding.UTF8, "application/json") };
            var header = SentId is null ? null : _make(SentId);
            if (header is not null) response.Headers.TryAddWithoutValidation("X-Avalon-Trace-Hops", header);
            return Task.FromResult(response);
        }
    }

    private static string B64(string s) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(s)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Hop(int i, string extra = "") =>
        $$"""{"index":{{i}},"base_url":"http://n","roles":["combined"],"protocol_version":"0.1.0","processing_ms":1.5{{extra}}}""";

    private static AvalonClient ClientFor(HttpMessageHandler node) =>
        new AvalonClient(new AvalonConfig("https://example.invalid", "test-key"), new HttpClient(new AvalonTraceHandler(node)));

    private static string FixtureText()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "conformance", "fixtures", "nodes")))
        {
            dir = dir.Parent;
        }
        return File.ReadAllText(Path.Combine(dir!.FullName, "conformance", "fixtures", "nodes", "op-trace.json"));
    }

    [Fact]
    public async Task TracedCallReturnsResultAndHopsWithExtraFields()
    {
        var node = new TracingNode(id => B64($$"""{"trace_id":"{{id}}","branches":[{"target":"","outcome":"ok","hops":[{{Hop(0, ",\"path_type\":\"relayed\"")}}]}],"future":1}"""));
        var out1 = await AvalonTrace.WithTraceAsync(() => ClientFor(node).GetNodeStatusAsync());

        Assert.Equal("n", out1.Value.NetworkId);
        var req = Assert.Single(out1.Requests);
        Assert.Equal(node.SentId, req.TraceId.ToString());
        Assert.Null(req.Problem);
        var hop = req.Trace!.Branches[0].Hops[0];
        Assert.Equal("http://n", hop.BaseUrl);
        Assert.Equal("relayed", hop.Extra["path_type"].GetString());
    }

    [Fact]
    public async Task NoHeaderIsSentOutsideWithTrace()
    {
        var node = new TracingNode(_ => null);
        await ClientFor(node).GetNodeStatusAsync();
        Assert.Null(node.SentId);
    }

    [Fact]
    public async Task MissingOrUnreadableHeaderLeavesTheCallIntact()
    {
        var out1 = await AvalonTrace.WithTraceAsync(() => ClientFor(new TracingNode(_ => null)).GetNodeStatusAsync());
        Assert.Equal("n", out1.Value.NetworkId);
        Assert.Null(out1.Requests[0].Trace);
        Assert.Equal(TraceProblem.Missing, out1.Requests[0].Problem);
    }

    [Theory]
    [InlineData("***", TraceProblem.Malformed)]
    [InlineData("QUJD=", TraceProblem.Malformed)]
    [InlineData("bm90IGpzb24", TraceProblem.Malformed)]
    [InlineData("eyJ0cmFjZV9pZCI6InggfQ", TraceProblem.Malformed)]
    public async Task BadHeaderNeverFailsTheCall(string header, TraceProblem problem)
    {
        var out1 = await AvalonTrace.WithTraceAsync(() => ClientFor(new TracingNode(_ => header)).GetNodeStatusAsync());
        Assert.Equal("n", out1.Value.NetworkId);
        Assert.Equal(problem, out1.Requests[0].Problem);
    }

    [Fact]
    public async Task WrongShapeOversizedAndForeignIdAreClassified()
    {
        var wrongShape = await AvalonTrace.WithTraceAsync(() => ClientFor(new TracingNode(id => B64($$"""{"trace_id":"{{id}}","branches":"x"}"""))).GetNodeStatusAsync());
        Assert.Equal(TraceProblem.Malformed, wrongShape.Requests[0].Problem);
        var badHop = await AvalonTrace.WithTraceAsync(() => ClientFor(new TracingNode(id => B64($$"""{"trace_id":"{{id}}","branches":[{"hops":[{"index":0}]}]}"""))).GetNodeStatusAsync());
        Assert.Equal(TraceProblem.Malformed, badHop.Requests[0].Problem);
        var big = await AvalonTrace.WithTraceAsync(() => ClientFor(new TracingNode(_ => new string('A', 9000))).GetNodeStatusAsync());
        Assert.Equal(TraceProblem.Oversized, big.Requests[0].Problem);
        var foreign = await AvalonTrace.WithTraceAsync(() => ClientFor(new TracingNode(_ => B64($$"""{"trace_id":"{{Guid.NewGuid()}}","branches":[]}"""))).GetNodeStatusAsync());
        Assert.Equal(TraceProblem.TraceIdMismatch, foreign.Requests[0].Problem);
    }

    [Fact]
    public void ExcessBranchesAndHopsAreCapped()
    {
        var id = Guid.NewGuid();
        var hops = string.Join(",", Enumerable.Range(0, 12).Select(i => Hop(i)));
        var t = AvalonTrace.Decode(B64($$"""{"trace_id":"{{id}}","branches":[{"hops":[{{hops}}]}]}"""), id).Trace!;
        Assert.Equal(8, t.Branches[0].Hops.Count);
        Assert.True(t.Truncated);
        var many = string.Join(",", Enumerable.Range(0, 10).Select(_ => $$"""{"hops":[{{Hop(0)}}]}"""));
        var t2 = AvalonTrace.Decode(B64($$"""{"trace_id":"{{id}}","branches":[{{many}}]}"""), id).Trace!;
        Assert.Equal(8, t2.Branches.Count);
    }

    [Fact]
    public void RecordedHeaderDecodes()
    {
        using var doc = JsonDocument.Parse(FixtureText());
        var id = Guid.Parse(doc.RootElement.GetProperty("request_trace_id").GetString()!);
        var result = AvalonTrace.Decode(doc.RootElement.GetProperty("header").GetString()!, id);

        Assert.Null(result.Problem);
        var t = result.Trace!;
        Assert.Equal(2, t.Branches.Count);
        Assert.Equal("http://192.168.7.183:8080", t.Branches[0].Hops[1].BaseUrl);
        Assert.Equal(234.655411, t.Branches[0].Hops[0].ToNextMs!.Value, 6);
        Assert.Equal("timeout", t.Branches[1].Outcome);
        Assert.False(t.Truncated);
    }

    [Fact]
    public async Task ConcurrentOperationsStayApart()
    {
        var node = new TracingNode(id => B64($$"""{"trace_id":"{{id}}","branches":[{"hops":[{{Hop(0)}}]}]}"""));
        var a = AvalonTrace.WithTraceAsync(() => ClientFor(node).GetNodeStatusAsync());
        var b = AvalonTrace.WithTraceAsync(() => ClientFor(node).GetNodeStatusAsync());
        var results = await Task.WhenAll(a, b);
        Assert.Single(results[0].Requests);
        Assert.Single(results[1].Requests);
        Assert.NotEqual(results[0].Requests[0].TraceId, results[1].Requests[0].TraceId);
    }
}
