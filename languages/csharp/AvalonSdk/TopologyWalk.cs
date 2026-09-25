// Bounded breadth-first walk of the overlay, assembled from each node's own GET /nodes/topology view.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Avalon.Sdk.Generated;

namespace Avalon.Sdk
{
    /// <summary>How a reporting node relates to the node it names.</summary>
    public enum WalkEdgeKind
    {
        /// <summary>An active link (neighbor).</summary>
        Active,
        /// <summary>The reporter mirrors a shard from the target.</summary>
        Mirror,
        /// <summary>The reporter only knows the target from its peer table.</summary>
        Known,
    }

    /// <summary>Why a node could not be read.</summary>
    public enum WalkFailureReason
    {
        /// <summary>No response within the request timeout.</summary>
        Timeout,
        /// <summary>A non-success status other than 429.</summary>
        HttpStatus,
        /// <summary>429, and no retry was possible within the wait budget or the retry also got 429.</summary>
        RateLimited,
        /// <summary>A success response whose body is not a topology view.</summary>
        ProtocolError,
        /// <summary>Connection-level failure.</summary>
        Network,
    }

    /// <summary>Whether a node was read.</summary>
    public enum WalkNodeStatus
    {
        /// <summary>Its topology view was read.</summary>
        Visited,
        /// <summary>Every attempt failed; see <see cref="WalkNode.Failure"/>.</summary>
        Unreachable,
        /// <summary>Discovered but not queried: a limit was reached or the walk was cancelled.</summary>
        Unvisited,
    }

    /// <summary>A node that could not be read, and why.</summary>
    public sealed class WalkFailure
    {
        public WalkFailureReason Reason { get; set; }

        /// <summary>HTTP status for HttpStatus and RateLimited.</summary>
        public int? Status { get; set; }

        /// <summary>The Retry-After the node sent, for RateLimited.</summary>
        public long? RetryAfterSeconds { get; set; }

        public string Message { get; set; } = "";
    }

    /// <summary>One observation: <see cref="From"/> reported <see cref="To"/>. Latency and coordinate are as
    /// measured and reported by From, not a symmetric property of the link.</summary>
    public sealed class WalkEdge
    {
        public string From { get; set; } = "";
        public string To { get; set; } = "";
        public WalkEdgeKind Kind { get; set; }

        /// <summary>Round-trip stats measured by From, labeled with it as ObservedBy.</summary>
        public ObservedLatency? Latency { get; set; }

        /// <summary>The target's coordinate as reported by From.</summary>
        public Coordinate? Coordinate { get; set; }

        /// <summary>Set on Mirror edges: the shard mirrored from the target.</summary>
        public MirrorSource? Mirror { get; set; }
    }

    /// <summary>One node in the graph.</summary>
    public sealed class WalkNode
    {
        /// <summary>Normalized base URL, the node's identity in the graph.</summary>
        public string Url { get; set; } = "";

        /// <summary>Hops from the nearest seed.</summary>
        public int Depth { get; set; }

        public WalkNodeStatus Status { get; set; } = WalkNodeStatus.Unvisited;

        /// <summary>The node's own view of itself, when it was visited.</summary>
        public SelfView? Self { get; set; }

        public WalkFailure? Failure { get; set; }

        /// <summary>Every node that reported this one, in report order.</summary>
        public List<string> ReportedBy { get; } = new List<string>();
    }

    /// <summary>Which limits cut the walk short.</summary>
    public sealed class WalkTruncation
    {
        /// <summary>Nodes were dropped because the graph was full.</summary>
        public bool MaxNodes { get; set; }

        /// <summary>Nodes beyond the depth limit were left unvisited.</summary>
        public bool MaxDepth { get; set; }
    }

    /// <summary>The graph assembled by a walk.</summary>
    public sealed class TopologyGraph
    {
        /// <summary>Distinct normalized seed URLs.</summary>
        public List<string> Seeds { get; } = new List<string>();

        /// <summary>Every discovered node, in discovery order.</summary>
        public List<WalkNode> Nodes { get; } = new List<WalkNode>();

        /// <summary>Every observation; a node reported by several neighbors appears in several edges.</summary>
        public List<WalkEdge> Edges { get; } = new List<WalkEdge>();

        public WalkTruncation Truncated { get; } = new WalkTruncation();

        /// <summary>The walk stopped because it was cancelled.</summary>
        public bool Cancelled { get; set; }
    }

    /// <summary>Progress reported while a walk runs.</summary>
    public sealed class WalkEvent
    {
        /// <summary>True when the node was first seen; false when its visit finished.</summary>
        public bool Discovered { get; set; }

        /// <summary>The node, live: later events may update it.</summary>
        public WalkNode Node { get; set; } = new WalkNode();

        /// <summary>Edges reported by the node, on a finished visit.</summary>
        public IReadOnlyList<WalkEdge> Edges { get; set; } = Array.Empty<WalkEdge>();
    }

    /// <summary>Limits and hooks for <see cref="AvalonClient.WalkTopologyAsync"/>. Every limit has a default
    /// and a hard ceiling.</summary>
    public sealed class WalkOptions
    {
        /// <summary>Most distinct nodes kept in the graph (default 64, ceiling 1000).</summary>
        public int MaxNodes { get; set; } = 64;

        /// <summary>Deepest hop count queried; seeds are depth 0 (default 4, ceiling 16).</summary>
        public int MaxDepth { get; set; } = 4;

        /// <summary>Simultaneous requests (default 4, ceiling 32).</summary>
        public int Concurrency { get; set; } = 4;

        /// <summary>Timeout of each request (default 10 s).</summary>
        public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(10);

        /// <summary>Longest Retry-After honored before one retry; a longer one is recorded as RateLimited (default 10 s).</summary>
        public TimeSpan MaxRetryAfter { get; set; } = TimeSpan.FromSeconds(10);

        /// <summary>Called as nodes are discovered and as each visit completes, one call at a time.</summary>
        public Action<WalkEvent>? OnProgress { get; set; }
    }

    public sealed partial class AvalonClient
    {
        private const int WalkCeilingMaxNodes = 1000;
        private const int WalkCeilingMaxDepth = 16;
        private const int WalkCeilingConcurrency = 32;
        private static readonly TimeSpan WalkCeilingDuration = TimeSpan.FromSeconds(120);
        private static readonly TimeSpan WalkFallbackRetryAfter = TimeSpan.FromSeconds(1);

        /// <summary>Lowercased scheme and host, default port dropped, no trailing slash; null when not an http(s) URL.</summary>
        public static string? NormalizeNodeUrl(string raw)
        {
            if (!Uri.TryCreate(raw.Trim(), UriKind.Absolute, out var uri))
            {
                return null;
            }
            if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            {
                return null;
            }
            return uri.GetLeftPart(UriPartial.Authority) + uri.AbsolutePath.TrimEnd('/');
        }

        /// <summary>
        /// Walks the overlay outward from <paramref name="seeds"/>, breadth-first, by asking each node for its own
        /// GET /nodes/topology view. No node holds the whole graph, so the result is the union of what the reachable
        /// nodes report. Read-only and always bounded. An unreachable node is recorded with a reason and never stops the
        /// walk; a 429 is retried once after its Retry-After when that wait is within MaxRetryAfter. Cancelling
        /// <paramref name="ct"/> returns the partial graph with Cancelled set rather than throwing.
        /// </summary>
        public async Task<TopologyGraph> WalkTopologyAsync(IEnumerable<string> seeds, WalkOptions? options = null, CancellationToken ct = default)
        {
            options ??= new WalkOptions();
            var maxNodes = Math.Min(Math.Max(options.MaxNodes, 1), WalkCeilingMaxNodes);
            var maxDepth = Math.Min(Math.Max(options.MaxDepth, 0), WalkCeilingMaxDepth);
            var concurrency = Math.Min(Math.Max(options.Concurrency, 1), WalkCeilingConcurrency);
            var timeout = Clamp(options.RequestTimeout, TimeSpan.FromMilliseconds(1), WalkCeilingDuration);
            var maxRetryAfter = Clamp(options.MaxRetryAfter, TimeSpan.Zero, WalkCeilingDuration);

            var graph = new TopologyGraph();
            var index = new Dictionary<string, WalkNode>();
            var gate = new object();

            void Emit(WalkEvent e) => options!.OnProgress?.Invoke(e);

            WalkNode? Discover(string raw, int depth, string? reporter)
            {
                var url = NormalizeNodeUrl(raw);
                if (url == null)
                {
                    return null;
                }
                if (!index.TryGetValue(url, out var node))
                {
                    if (graph.Nodes.Count >= maxNodes)
                    {
                        graph.Truncated.MaxNodes = true;
                        return null;
                    }
                    node = new WalkNode { Url = url, Depth = depth };
                    index[url] = node;
                    graph.Nodes.Add(node);
                    Emit(new WalkEvent { Discovered = true, Node = node });
                }
                if (reporter != null && !node.ReportedBy.Contains(reporter))
                {
                    node.ReportedBy.Add(reporter);
                }
                return node;
            }

            var level = new List<WalkNode>();
            foreach (var seed in seeds)
            {
                var node = Discover(seed, 0, null);
                if (node != null)
                {
                    if (!graph.Seeds.Contains(node.Url))
                    {
                        graph.Seeds.Add(node.Url);
                    }
                    if (!level.Contains(node))
                    {
                        level.Add(node);
                    }
                }
                else if (NormalizeNodeUrl(seed) == null)
                {
                    var raw = seed.Trim();
                    if (!index.ContainsKey(raw) && graph.Nodes.Count < maxNodes)
                    {
                        var invalid = new WalkNode
                        {
                            Url = raw,
                            Status = WalkNodeStatus.Unreachable,
                            Failure = new WalkFailure { Reason = WalkFailureReason.ProtocolError, Message = "not an http(s) URL" },
                        };
                        index[raw] = invalid;
                        graph.Nodes.Add(invalid);
                        graph.Seeds.Add(raw);
                        Emit(new WalkEvent { Discovered = true, Node = invalid });
                        Emit(new WalkEvent { Node = invalid });
                    }
                }
            }

            void Report(WalkNode from, string target, List<WalkNode> next, List<WalkEdge> produced, WalkEdge edge)
            {
                var child = Discover(target, from.Depth + 1, from.Url);
                if (child == null || child == from)
                {
                    return;
                }
                edge.From = from.Url;
                edge.To = child.Url;
                produced.Add(edge);
                graph.Edges.Add(edge);
                if (child.Status == WalkNodeStatus.Unvisited && child.Depth == from.Depth + 1 && !next.Contains(child))
                {
                    if (child.Depth > maxDepth)
                    {
                        graph.Truncated.MaxDepth = true;
                    }
                    else
                    {
                        next.Add(child);
                    }
                }
            }

            async Task VisitAsync(WalkNode node, List<WalkNode> next)
            {
                var (topology, failure) = await FetchWithRetryAsync(node.Url, timeout, maxRetryAfter, ct).ConfigureAwait(false);
                lock (gate)
                {
                    if (ct.IsCancellationRequested)
                    {
                        return;
                    }
                    if (topology == null)
                    {
                        node.Status = WalkNodeStatus.Unreachable;
                        node.Failure = failure;
                        Emit(new WalkEvent { Node = node });
                        return;
                    }
                    node.Status = WalkNodeStatus.Visited;
                    node.Self = topology.Self;
                    var produced = new List<WalkEdge>();
                    foreach (var n in topology.Neighbors ?? new List<Neighbor>())
                    {
                        if (n.Latency != null)
                        {
                            n.Latency.ObservedBy = node.Url;
                        }
                        Report(node, n.BaseUrl, next, produced, new WalkEdge { Kind = WalkEdgeKind.Active, Latency = n.Latency, Coordinate = n.Coordinate });
                    }
                    foreach (var m in topology.Mirrors ?? new List<MirrorSource>())
                    {
                        Report(node, m.SourceUrl, next, produced, new WalkEdge { Kind = WalkEdgeKind.Mirror, Mirror = m });
                    }
                    foreach (var k in topology.Known ?? new List<KnownPeer>())
                    {
                        Report(node, k.BaseUrl, next, produced, new WalkEdge { Kind = WalkEdgeKind.Known });
                    }
                    Emit(new WalkEvent { Node = node, Edges = produced });
                }
            }

            while (level.Count > 0 && !ct.IsCancellationRequested)
            {
                var queue = level.Where(n => n.Status == WalkNodeStatus.Unvisited && n.Depth <= maxDepth).ToList();
                var next = new List<WalkNode>();
                using (var slots = new SemaphoreSlim(concurrency))
                {
                    var tasks = queue.Select(async node =>
                    {
                        try
                        {
                            await slots.WaitAsync(ct).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException)
                        {
                            return;
                        }
                        try
                        {
                            await VisitAsync(node, next).ConfigureAwait(false);
                        }
                        finally
                        {
                            slots.Release();
                        }
                    }).ToList();
                    await Task.WhenAll(tasks).ConfigureAwait(false);
                }
                level = next;
            }

            graph.Cancelled = ct.IsCancellationRequested;
            return graph;
        }

        private static TimeSpan Clamp(TimeSpan value, TimeSpan min, TimeSpan max) =>
            value < min ? min : value > max ? max : value;

        /// <summary>Fetches one node's topology, retrying once after a bounded Retry-After wait on 429. Returns
        /// (null, null) when cancelled.</summary>
        private async Task<(TopologyResponse? Topology, WalkFailure? Failure)> FetchWithRetryAsync(string url, TimeSpan timeout, TimeSpan maxRetryAfter, CancellationToken ct)
        {
            for (var attempt = 0; ; attempt++)
            {
                if (ct.IsCancellationRequested)
                {
                    return (null, null);
                }
                using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutSource.CancelAfter(timeout);
                WalkFailure failure;
                try
                {
                    var topology = await TopologyAsync(url, timeoutSource.Token).ConfigureAwait(false);
                    if (topology == null)
                    {
                        throw new AvalonProtocolException("topology response is empty");
                    }
                    return (topology, null);
                }
                catch (OperationCanceledException)
                {
                    if (ct.IsCancellationRequested)
                    {
                        return (null, null);
                    }
                    failure = new WalkFailure { Reason = WalkFailureReason.Timeout, Message = "no response within " + (long)timeout.TotalMilliseconds + " ms" };
                }
                catch (AvalonRequestException e) when (e.IsRateLimited)
                {
                    failure = new WalkFailure { Reason = WalkFailureReason.RateLimited, Status = 429, RetryAfterSeconds = e.RetryAfter.HasValue ? (long?)e.RetryAfter.Value.TotalSeconds : null, Message = e.Message };
                }
                catch (AvalonRequestException e)
                {
                    failure = new WalkFailure { Reason = WalkFailureReason.HttpStatus, Status = (int)e.StatusCode, Message = e.Message };
                }
                catch (AvalonProtocolException e)
                {
                    failure = new WalkFailure { Reason = WalkFailureReason.ProtocolError, Message = e.Message };
                }
                catch (HttpRequestException e)
                {
                    failure = new WalkFailure { Reason = WalkFailureReason.Network, Message = e.Message };
                }
                catch (Exception e) when (!(e is OutOfMemoryException))
                {
                    failure = new WalkFailure { Reason = WalkFailureReason.Network, Message = e.Message };
                }

                if (failure.Reason != WalkFailureReason.RateLimited || attempt > 0)
                {
                    return (null, failure);
                }
                var wait = failure.RetryAfterSeconds.HasValue ? TimeSpan.FromSeconds(failure.RetryAfterSeconds.Value) : WalkFallbackRetryAfter;
                if (wait > maxRetryAfter)
                {
                    return (null, failure);
                }
                try
                {
                    await Task.Delay(wait, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return (null, null);
                }
            }
        }
    }
}
