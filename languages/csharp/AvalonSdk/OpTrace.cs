// Opt-in path tracing for real SDK calls. Inside AvalonTrace.WithTraceAsync, every request sent
// through an HttpClient built on AvalonTraceHandler carries X-Avalon-Trace, and the decoded
// X-Avalon-Trace-Hops answer is returned next to the call's result. Hops are self-reported by
// the nodes on the path and are advisory; a missing, oversized or malformed header never fails a call.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Avalon.Sdk.Generated;

namespace Avalon.Sdk
{
    /// <summary>A hop as TraceAsync returns it, plus any field a newer node adds, kept in
    /// <see cref="Extra"/> as it arrived.</summary>
    public sealed class PathHop : TraceHop
    {
        [JsonExtensionData]
        public Dictionary<string, JsonElement> Extra { get; set; } = new Dictionary<string, JsonElement>();
    }

    /// <summary>One path from the originating node to a node that handled the request.</summary>
    public sealed class TraceBranch
    {
        /// <summary>Base URL the originating node sent to; empty for the node's own record.</summary>
        [JsonPropertyName("target")]
        public string Target { get; set; } = "";

        /// <summary>"ok", "timeout" or "unreachable"; other values pass through.</summary>
        [JsonPropertyName("outcome")]
        public string Outcome { get; set; } = "ok";

        /// <summary>Nodes in the order traveled.</summary>
        [JsonPropertyName("hops")]
        public List<PathHop> Hops { get; set; } = new List<PathHop>();
    }

    /// <summary>The decoded X-Avalon-Trace-Hops value. A fan-out reports one branch per target.</summary>
    public sealed class OperationTrace
    {
        [JsonPropertyName("trace_id")]
        public Guid TraceId { get; set; }

        [JsonPropertyName("branches")]
        public List<TraceBranch> Branches { get; set; } = new List<TraceBranch>();

        /// <summary>Set when the node dropped branches or hops to stay within its size caps.</summary>
        [JsonPropertyName("truncated")]
        public bool Truncated { get; set; }
    }

    /// <summary>Why a request has no decoded path.</summary>
    public enum TraceProblem
    {
        /// <summary>No hops header: the node did not trace the request, or the header is not readable.</summary>
        Missing,
        /// <summary>The header exceeds the size cap.</summary>
        Oversized,
        /// <summary>Not unpadded base64url JSON of the expected shape.</summary>
        Malformed,
        /// <summary>The header names a different trace id than the request sent.</summary>
        TraceIdMismatch,
    }

    /// <summary>The traced path of one HTTP request made inside AvalonTrace.WithTraceAsync.</summary>
    public sealed class RequestTrace
    {
        public RequestTrace(Guid traceId, OperationTrace? trace, TraceProblem? problem)
        {
            TraceId = traceId;
            Trace = trace;
            Problem = problem;
        }

        /// <summary>The id sent in X-Avalon-Trace.</summary>
        public Guid TraceId { get; }

        /// <summary>The decoded path, when the response carried a valid one.</summary>
        public OperationTrace? Trace { get; }

        /// <summary>Why <see cref="Trace"/> is null.</summary>
        public TraceProblem? Problem { get; }
    }

    /// <summary>A call's result and the traced path of each request it made, in order.</summary>
    public sealed class Traced<T>
    {
        public Traced(T value, IReadOnlyList<RequestTrace> requests)
        {
            Value = value;
            Requests = requests;
        }

        public T Value { get; }
        public IReadOnlyList<RequestTrace> Requests { get; }
    }

    /// <summary>Turns tracing on for the calls made inside <see cref="WithTraceAsync{T}"/>.</summary>
    public static class AvalonTrace
    {
        internal const string TraceHeader = "X-Avalon-Trace";
        internal const string HopsHeader = "X-Avalon-Trace-Hops";
        private const int MaxHeaderBytes = 8 * 1024;
        private const int MaxBranches = 8;
        private const int MaxHopsPerBranch = 8;

        internal sealed class Scope
        {
            public readonly List<RequestTrace> Requests = new List<RequestTrace>();
        }

        private static readonly AsyncLocal<Scope?> Current = new AsyncLocal<Scope?>();

        internal static Scope? CurrentScope => Current.Value;

        /// <summary>Runs <paramref name="operation"/> with tracing on and returns its result with
        /// the traced path of each request it made. Requests are traced only when they go through
        /// an HttpClient built on <see cref="AvalonTraceHandler"/>, which the SDK's own default
        /// clients are; a caller-supplied HttpClient needs its handler wrapped.</summary>
        public static async Task<Traced<T>> WithTraceAsync<T>(Func<Task<T>> operation)
        {
            var previous = Current.Value;
            var scope = new Scope();
            Current.Value = scope;
            try
            {
                var value = await operation().ConfigureAwait(false);
                return new Traced<T>(value, Snapshot(scope));
            }
            finally
            {
                Current.Value = previous;
            }
        }

        private static IReadOnlyList<RequestTrace> Snapshot(Scope scope)
        {
            lock (scope.Requests)
            {
                return scope.Requests.ToList();
            }
        }

        internal static void Record(Scope scope, Guid id, System.Net.Http.Headers.HttpResponseHeaders headers)
        {
            RequestTrace entry;
            try
            {
                entry = headers.TryGetValues(HopsHeader, out var values)
                    ? Decode(values.FirstOrDefault() ?? "", id)
                    : new RequestTrace(id, null, TraceProblem.Missing);
            }
            catch (Exception)
            {
                entry = new RequestTrace(id, null, TraceProblem.Malformed);
            }
            lock (scope.Requests)
            {
                scope.Requests.Add(entry);
            }
        }

        /// <summary>Decodes an X-Avalon-Trace-Hops value for the request sent with <paramref name="expected"/>.</summary>
        public static RequestTrace Decode(string value, Guid expected)
        {
            if (value.Length > MaxHeaderBytes)
            {
                return new RequestTrace(expected, null, TraceProblem.Oversized);
            }
            var text = value.Trim();
            OperationTrace? trace;
            try
            {
                var b64 = text.Replace('-', '+').Replace('_', '/');
                if (text.Contains("=") || text.Any(c => !(char.IsLetterOrDigit(c) && c < 128) && c != '-' && c != '_'))
                {
                    return new RequestTrace(expected, null, TraceProblem.Malformed);
                }
                b64 = b64.PadRight(b64.Length + (4 - b64.Length % 4) % 4, '=');
                var json = new UTF8Encoding(false, true).GetString(Convert.FromBase64String(b64));
                trace = JsonSerializer.Deserialize<OperationTrace>(json);
            }
            catch (Exception ex) when (ex is FormatException || ex is JsonException || ex is ArgumentException)
            {
                return new RequestTrace(expected, null, TraceProblem.Malformed);
            }
            if (trace is null || trace.Branches is null || trace.Branches.Any(b => b is null || b.Hops is null || b.Hops.Any(IsInvalid)))
            {
                return new RequestTrace(expected, null, TraceProblem.Malformed);
            }
            if (trace.TraceId != expected)
            {
                return new RequestTrace(expected, null, TraceProblem.TraceIdMismatch);
            }
            if (trace.Branches.Count > MaxBranches)
            {
                trace.Branches = trace.Branches.Take(MaxBranches).ToList();
                trace.Truncated = true;
            }
            foreach (var branch in trace.Branches)
            {
                if (branch.Hops.Count > MaxHopsPerBranch)
                {
                    branch.Hops = branch.Hops.Take(MaxHopsPerBranch).ToList();
                    trace.Truncated = true;
                }
            }
            return new RequestTrace(expected, trace, null);
        }

        private static bool IsInvalid(PathHop? h) =>
            h is null || h.BaseUrl is null || h.ProtocolVersion is null || h.Roles is null;
    }

    /// <summary>Adds X-Avalon-Trace to each request made inside AvalonTrace.WithTraceAsync and
    /// records the decoded answer; a pass-through otherwise. Wrap a caller-supplied HttpClient's
    /// handler with it to trace the calls made through that client.</summary>
    public sealed class AvalonTraceHandler : DelegatingHandler
    {
        public AvalonTraceHandler() : base(new HttpClientHandler()) { }

        public AvalonTraceHandler(HttpMessageHandler inner) : base(inner) { }

        internal static HttpClient NewDefaultClient() => new HttpClient(new AvalonTraceHandler());

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var scope = AvalonTrace.CurrentScope;
            if (scope is null)
            {
                return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
            }
            var id = Guid.NewGuid();
            request.Headers.Remove(AvalonTrace.TraceHeader);
            request.Headers.TryAddWithoutValidation(AvalonTrace.TraceHeader, id.ToString());
            var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
            AvalonTrace.Record(scope, id, response.Headers);
            return response;
        }
    }
}
