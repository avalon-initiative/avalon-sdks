using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Xunit;

namespace Avalon.Sdk.Tests;

public class KnownListTests
{
    private const string Net = "avalon-test";
    private const string Seed = "http://seed.s0.example";
    private static readonly string Root = string.Concat(Enumerable.Repeat("ab", 32));

    private sealed class FuncHandler : HttpMessageHandler
    {
        private readonly Func<Uri, (HttpStatusCode, string)> _route;
        public List<string> Urls { get; } = new();
        private int _inFlight;
        public int MaxInFlight { get; private set; }

        public FuncHandler(Func<Uri, (HttpStatusCode, string)> route) => _route = route;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            lock (Urls)
            {
                Urls.Add(request.RequestUri!.ToString());
                MaxInFlight = Math.Max(MaxInFlight, ++_inFlight);
            }
            await Task.Delay(5, ct);
            lock (Urls) { _inFlight--; }
            var (status, body) = _route(request.RequestUri!);
            return new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        }

        public int Count(string contains) { lock (Urls) { return Urls.Count(u => u.Contains(contains)); } }
    }

    private static Ed25519PrivateKeyParameters NewKey()
    {
        var generator = new Ed25519KeyPairGenerator();
        generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        return (Ed25519PrivateKeyParameters)generator.GenerateKeyPair().Private;
    }

    private static string Hex(byte[] bytes) => string.Concat(bytes.Select(b => b.ToString("x2")));
    private static string PubHex(Ed25519PrivateKeyParameters key) => Hex(key.GeneratePublicKey().GetEncoded());

    private static byte[] Sign(Ed25519PrivateKeyParameters key, byte[] message)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, key);
        signer.BlockUpdate(message, 0, message.Length);
        return signer.GenerateSignature();
    }

    private sealed class Witness
    {
        public Ed25519PrivateKeyParameters Key = NewKey();
        public string Id => PubHex(Key);
        public string Url = "";
        public string Network = Net;
        public string? ProofFor;
        public bool Alive = true;

        public object Peer(DateTimeOffset now)
        {
            var proof = Hex(Sign(Key, KnownListRules.WitnessAnnounceMessage(ProofFor ?? Url, Id, now)));
            return new Dictionary<string, object>
            {
                ["base_url"] = Url,
                ["network_id"] = Network,
                ["witness"] = new Dictionary<string, object>
                {
                    ["key_id"] = Id,
                    ["announced_at"] = now.ToString("o"),
                    ["proof"] = proof,
                },
            };
        }
    }

    private static Witness W(int i, string? host = null) => new Witness { Url = $"http://{host ?? $"w{i}.d{i}.example"}" };

    private static TrustAnchorEntry Entry(string key, params string[] seeds) => new TrustAnchorEntry
    {
        NetworkId = Net,
        VerifyKey = key,
        SeedNodes = seeds.ToList(),
    };

    private static KnownListOptions Options(int capacity = 5) => new KnownListOptions
    {
        Capacity = capacity,
        RandomInt = _ => 0,
        RequestTimeout = TimeSpan.FromSeconds(2),
    };

    private static string SeedBody(IEnumerable<object> peers) =>
        JsonSerializer.Serialize(new { self_status = new { }, peers });

    private static string LatestBody(string network) =>
        JsonSerializer.Serialize(new { network_id = network, tree_size = 5 });

    private static Func<Uri, (HttpStatusCode, string)> Network(
        Dictionary<string, IEnumerable<Witness>> seeds, IEnumerable<Witness> all, Func<Uri, (HttpStatusCode, string)?>? extra = null)
    {
        var now = DateTimeOffset.UtcNow;
        var list = all.ToList();
        return uri =>
        {
            var origin = $"{uri.Scheme}://{uri.Host}";
            if (extra?.Invoke(uri) is { } custom)
            {
                return custom;
            }
            if (uri.AbsolutePath == "/nodes/discover")
            {
                return seeds.TryGetValue(origin, out var peers)
                    ? (HttpStatusCode.OK, SeedBody(peers.Select(p => p.Peer(now))))
                    : (HttpStatusCode.InternalServerError, "");
            }
            var w = list.FirstOrDefault(x => x.Url == origin);
            if (w != null && w.Alive && uri.AbsolutePath == "/ledger/sth/latest")
            {
                return (HttpStatusCode.OK, LatestBody(w.Network));
            }
            return (HttpStatusCode.ServiceUnavailable, "");
        };
    }

    [Fact]
    public async Task Discovery_UnionsSeeds_DedupesByKey_AndFiltersNetworkAndBadProofs()
    {
        var a = W(1); var b = W(2); var c = W(3); var otherNet = W(4); otherNet.Network = "other";
        var badProof = W(5); badProof.ProofFor = "http://elsewhere.example";
        var seed2 = "http://seed.s1.example";
        var handler = new FuncHandler(Network(
            new() { [Seed] = new[] { a, b, otherNet, badProof }, [seed2] = new[] { b, c } },
            new[] { a, b, c }));
        var found = await KnownListBuilder.DiscoverCandidatesAsync(
            new HttpClient(handler), Entry("aa", Seed, seed2), Options());
        Assert.Equal(new[] { a.Id, b.Id, c.Id }, found.Select(f => f.WitnessKeyId));
    }

    [Fact]
    public async Task Discovery_SkipsAFailedSeed_AndAllFailedIsEmpty()
    {
        var a = W(1);
        var handler = new FuncHandler(Network(new() { [Seed] = new[] { a } }, new[] { a }));
        var down = "http://down.s9.example";
        var found = await KnownListBuilder.DiscoverCandidatesAsync(
            new HttpClient(handler), Entry("aa", down, Seed), Options());
        Assert.Single(found);
        var none = await KnownListBuilder.DiscoverCandidatesAsync(new HttpClient(handler), Entry("aa", down), Options());
        Assert.Empty(none);
    }

    [Fact]
    public async Task Discovery_MarksACandidateAtASeedUrlAsAnAnchor()
    {
        var a = W(1, "SEED.s0.example:8080"); a.Url = "http://seed.s0.example:8080";
        var b = W(2);
        var handler = new FuncHandler(Network(new() { ["http://seed.s0.example"] = new[] { b, a } }, new[] { a, b }));
        var entry = Entry("aa", "http://seed.s0.example", "HTTP://Seed.S0.example:8080/");
        var found = await KnownListBuilder.DiscoverCandidatesAsync(new HttpClient(handler), entry, Options());
        Assert.True(found.Single(f => f.WitnessKeyId == a.Id).IsAnchor);
        Assert.False(found.Single(f => f.WitnessKeyId == b.Id).IsAnchor);
    }

    [Fact]
    public async Task Build_DropsUnreachableCandidates_AndKeepsAnchorsFirstInSeedOrder()
    {
        var dead = W(1); dead.Alive = false;
        var live = W(2);
        var anchor = new Witness { Url = "http://seed.s0.example" };
        var handler = new FuncHandler(Network(new() { [Seed] = new[] { dead, live, anchor } }, new[] { dead, live, anchor }));
        var list = await KnownListBuilder.BuildKnownListAsync(new HttpClient(handler), Entry("aa", Seed), Options());
        Assert.Equal(new[] { anchor.Id, live.Id }, list.Select(w => w.WitnessKeyId));
        Assert.All(list, w => Assert.Equal(w.WitnessKeyId, w.VerifyKeyHex));
        Assert.Equal(anchor.Url, list[0].BaseUrl);
    }

    [Fact]
    public async Task Build_ProbesAtMostThreeTimesCapacity_WithFourInFlight()
    {
        var all = Enumerable.Range(0, 12).Select(i => { var w = W(i); w.Alive = false; return w; }).ToList();
        var handler = new FuncHandler(Network(new() { [Seed] = all }, all));
        var list = await KnownListBuilder.BuildKnownListAsync(new HttpClient(handler), Entry("aa", Seed), Options(2));
        Assert.Empty(list);
        Assert.Equal(6, handler.Count("/ledger/sth/latest?shard_id=core"));
        Assert.True(handler.MaxInFlight <= 4);
    }

    [Fact]
    public async Task Build_StopsProbingOnceTheListIsFull()
    {
        var all = Enumerable.Range(0, 12).Select(i => W(i)).ToList();
        var handler = new FuncHandler(Network(new() { [Seed] = all }, all));
        var list = await KnownListBuilder.BuildKnownListAsync(new HttpClient(handler), Entry("aa", Seed), Options(2));
        Assert.Equal(2, list.Count);
        Assert.Equal(4, handler.Count("/ledger/sth/latest?shard_id=core"));
    }

    [Fact]
    public async Task Build_ShufflesNonAnchorsWithTheInjectedSource()
    {
        var all = Enumerable.Range(0, 4).Select(i => W(i)).ToList();
        var handler = new FuncHandler(Network(new() { [Seed] = all }, all));
        var options = Options(4);
        var list = await KnownListBuilder.BuildKnownListAsync(new HttpClient(handler), Entry("aa", Seed), options);
        Assert.Equal(new[] { all[1], all[2], all[3], all[0] }.Select(w => w.Id), list.Select(w => w.WitnessKeyId));
    }

    // Verification integration

    private sealed class NetFixture
    {
        public Ed25519PrivateKeyParameters Author = NewKey();
        public List<Witness> Witnesses = Enumerable.Range(0, 3).Select(i => W(i)).ToList();
        public DateTimeOffset CreatedAt = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        public int Cosigners = 2;
        public FuncHandler Handler = null!;

        public SignedTreeHeadWire Sth(string root = "", long size = 5)
        {
            root = root == "" ? Root : root;
            return new SignedTreeHeadWire
            {
                TreeSize = size, RootHash = root, NetworkId = Net, SigningKeyId = "author", CreatedAt = CreatedAt,
                Signature = Hex(Sign(Author, AvalonClient.SthSigningMessage(size, root, Net, CreatedAt))),
            };
        }

        public string HeadJson(SignedTreeHeadWire sth, IEnumerable<Witness> cosigners)
        {
            var body = JsonSerializer.Serialize(sth);
            var extra = string.Join(",", cosigners.Select(w =>
            {
                var sig = Hex(Sign(w.Key, WitnessCosigning.WitnessSigningMessage(
                    sth.TreeSize, sth.RootHash, Net, sth.CreatedAt, w.Id, CreatedAt)));
                return "{\"witness_key_id\":\"" + w.Id + "\",\"observed_at\":\"" + CreatedAt.ToString("o") + "\",\"signature\":\"" + sig + "\"}";
            }));
            return body.TrimEnd('}') + ",\"cosignatures\":[" + extra + "]}";
        }

        public AvalonClient Client(IEnumerable<Witness>? witnesses = null)
        {
            var list = (witnesses ?? Witnesses).ToList();
            var trust = "{\"networks\":[{\"label\":\"n\",\"network_id\":\"" + Net + "\",\"verify_key\":\"" + PubHex(Author) +
                "\",\"signing_key_id\":\"k\",\"environment\":\"local-dev\",\"seed_nodes\":[\"" + Seed + "\"]}]}";
            var inner = Network(new() { [Seed] = list }, list);
            Handler = new FuncHandler(uri =>
            {
                if (uri.Host == "raw.githubusercontent.com")
                {
                    return (HttpStatusCode.OK, trust);
                }
                if (uri.Host == "node.n0.example" && uri.AbsolutePath == "/ledger/sth/latest")
                {
                    return (HttpStatusCode.OK, HeadJson(Sth(), Witnesses.Take(Cosigners)));
                }
                return inner(uri);
            });
            return new AvalonClient(new AvalonConfig("http://node.n0.example", "i"), new HttpClient(Handler));
        }
    }

    [Fact]
    public async Task VerifyNetwork_AutoBuildsOnceAndRequiresTheCosignedMajority()
    {
        var f = new NetFixture();
        var client = f.Client();
        Assert.Equal(NetworkTrustStatusKind.Verified, (await client.VerifyNetworkAsync()).Kind);
        Assert.Equal(NetworkTrustStatusKind.Verified, (await client.VerifyNetworkAsync()).Kind);
        Assert.Equal(1, f.Handler.Count("/nodes/discover"));

        f.Cosigners = 1;
        Assert.Equal(NetworkTrustStatusKind.Mismatch, (await client.VerifyNetworkAsync()).Kind);
    }

    [Fact]
    public async Task VerifyNetwork_NoneAndExplicitBehaveAsBefore()
    {
        var f = new NetFixture { Cosigners = 0 };
        var client = f.Client();
        var none = await client.VerifyNetworkAsync(witnessPolicy: WitnessPolicy.None);
        Assert.Equal(NetworkTrustStatusKind.Verified, none.Kind);
        Assert.Equal(0, f.Handler.Count("/nodes/discover"));
        Assert.Equal(0, f.Handler.Count("witnesses=1"));

        var known = f.Witnesses.Select(w => new KnownWitness(w.Id, w.Id)).ToList();
        Assert.Equal(NetworkTrustStatusKind.Mismatch, (await client.VerifyNetworkAsync(known)).Kind);
        Assert.Equal(0, f.Handler.Count("/nodes/discover"));
    }

    [Fact]
    public async Task VerifyNetwork_AutoWithFewerThanTwoWitnesses_IsThePlainCheck()
    {
        var f = new NetFixture { Cosigners = 0 };
        Assert.Equal(NetworkTrustStatusKind.Verified, (await f.Client(f.Witnesses.Take(1)).VerifyNetworkAsync()).Kind);
        Assert.Equal(NetworkTrustStatusKind.Verified, (await f.Client(new List<Witness>()).VerifyNetworkAsync()).Kind);
    }

    // Cross-check

    [Fact]
    public async Task CrossCheck_ReportsAConflictingAuthorSignedHead_AndNothingElse()
    {
        var f = new NetFixture();
        var accepted = f.Sth();
        var acceptedHead = new CosignedTreeHead(accepted, f.Witnesses.Take(2).Select(w => Cosig(f, w, accepted)).ToList());
        var otherRoot = string.Concat(Enumerable.Repeat("cd", 32));
        var fork = f.Sth(otherRoot);
        var known = f.Witnesses.Select(w => new KnownWitness(w.Id, w.Id, w.Url)).ToList();

        var handler = new FuncHandler(uri =>
        {
            var origin = $"{uri.Scheme}://{uri.Host}";
            Assert.EndsWith("/ledger/sth/5?shard_id=core&witnesses=1", uri.PathAndQuery);
            if (origin == f.Witnesses[0].Url) { return (HttpStatusCode.OK, f.HeadJson(fork, f.Witnesses.Take(2))); }
            if (origin == f.Witnesses[1].Url) { return (HttpStatusCode.OK, f.HeadJson(accepted, f.Witnesses.Take(2))); }
            return (HttpStatusCode.NotFound, "");
        });
        var evidence = await KnownListBuilder.CrossCheckHeadAsync(new HttpClient(handler), PubHex(f.Author), known, acceptedHead, Options());
        var e = Assert.Single(evidence);
        Assert.Equal(5, e.TreeSize);
        Assert.Equal(Root, e.RootA);
        Assert.Equal(otherRoot, e.RootB);
        Assert.Equal(new[] { f.Witnesses[0].Url }, e.Sources);
        Assert.Equal(new[] { f.Witnesses[0].Id, f.Witnesses[1].Id }.OrderBy(x => x, StringComparer.Ordinal), e.Witnesses);

        var forged = new FuncHandler(_ => (HttpStatusCode.OK, f.HeadJson(new SignedTreeHeadWire
        {
            TreeSize = 5, RootHash = otherRoot, NetworkId = Net, SigningKeyId = "a", CreatedAt = f.CreatedAt, Signature = new string('0', 128),
        }, new List<Witness>())));
        Assert.Empty(await KnownListBuilder.CrossCheckHeadAsync(new HttpClient(forged), PubHex(f.Author), known, acceptedHead, Options()));
        var down = new FuncHandler(_ => (HttpStatusCode.InternalServerError, ""));
        Assert.Empty(await KnownListBuilder.CrossCheckHeadAsync(new HttpClient(down), PubHex(f.Author), known, acceptedHead, Options()));
    }

    private static WitnessCosignature Cosig(NetFixture f, Witness w, SignedTreeHeadWire sth) => new WitnessCosignature
    {
        TreeSize = sth.TreeSize, RootHash = sth.RootHash, NetworkId = Net, AuthorCreatedAt = sth.CreatedAt,
        WitnessKeyId = w.Id, ObservedAt = f.CreatedAt,
        Signature = Hex(Sign(w.Key, WitnessCosigning.WitnessSigningMessage(
            sth.TreeSize, sth.RootHash, Net, sth.CreatedAt, w.Id, f.CreatedAt))),
    };
}
