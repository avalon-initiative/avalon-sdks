using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Avalon.Sdk.Tests;

public class DiscoveryWitnessTests
{
    private const string C1 = "http://c1.s1.example";
    private const string C2 = "http://c2.s2.example";
    private static readonly TargetNetwork Target = TargetNetwork.ForNetworkId(KnownListTests.Net);

    private sealed class World
    {
        public KnownListTests.NetFixture Fixture = new();
        public Dictionary<string, int> CosignersByCandidate = new() { [C1] = 2, [C2] = 2 };
        public KnownListTests.FuncHandler Handler = null!;
        public TrustAnchorEntry Entry = null!;

        public World(int witnessCount = 3)
        {
            Fixture.Witnesses = Enumerable.Range(0, witnessCount).Select(i => KnownListTests.W(i)).ToList();
            Entry = new TrustAnchorEntry
            {
                NetworkId = KnownListTests.Net,
                VerifyKey = KnownListTests.PubHex(Fixture.Author),
                SeedNodes = new List<string> { C1, C2 },
            };
            var trust = "{\"networks\":[{\"label\":\"n\",\"network_id\":\"" + KnownListTests.Net + "\",\"verify_key\":\"" + Entry.VerifyKey +
                "\",\"signing_key_id\":\"k\",\"environment\":\"local-dev\",\"seed_nodes\":[\"" + C1 + "\",\"" + C2 + "\"]}]}";
            var seeds = new Dictionary<string, IEnumerable<KnownListTests.Witness>> { [C1] = Fixture.Witnesses, [C2] = Fixture.Witnesses };
            var inner = KnownListTests.Network(seeds, Fixture.Witnesses, uri =>
            {
                var origin = $"{uri.Scheme}://{uri.Host}";
                if (uri.Host == "raw.githubusercontent.com")
                {
                    return (HttpStatusCode.OK, trust);
                }
                if (CosignersByCandidate.TryGetValue(origin, out var n) && uri.AbsolutePath == "/ledger/sth/latest")
                {
                    return (HttpStatusCode.OK, Fixture.HeadJson(Fixture.Sth(), Fixture.Witnesses.Take(n)));
                }
                return null;
            });
            Handler = new KnownListTests.FuncHandler(inner);
        }

        public HttpClient Http() => new HttpClient(Handler);

        public Task<DiscoveryResult> Discover(WitnessPolicy? policy, KnownListCache? cache = null) =>
            AvalonClient.DiscoverAmongAsync(new[] { Entry }, Target, Http(), CancellationToken.None, null, policy, cache);
    }

    [Fact]
    public async Task Auto_SkipsACandidateWithoutTheMajority_AndChoosesTheNextVerified()
    {
        var w = new World();
        w.CosignersByCandidate[C1] = 1;
        var found = await w.Discover(WitnessPolicy.Auto);
        Assert.Equal(C2, found.ServerUrl);
        Assert.Equal(new[] { C2 }, found.Verified.Select(v => v.ServerUrl));
    }

    [Fact]
    public async Task Auto_WhenEveryCandidateFailsTheMajority_ReportsEveryAttempt()
    {
        var w = new World();
        w.CosignersByCandidate[C1] = 0;
        w.CosignersByCandidate[C2] = 1;
        var ex = await Assert.ThrowsAsync<DiscoveryException>(() => w.Discover(WitnessPolicy.Auto));
        Assert.Equal(DiscoveryErrorKind.NoneVerified, ex.Kind);
        Assert.Equal(new[] { C1, C2 }, ex.Attempts.Select(a => a.CandidateUrl));
    }

    [Fact]
    public async Task Connect_BuildsTheListOnce_AndTheReturnedClientReusesIt()
    {
        var w = new World();
        var client = await AvalonClient.ConnectAsync(Target, new DiscoveryConfig("i"), w.Http());
        var built = w.Handler.Count("/nodes/discover");
        Assert.Equal(2, built);
        Assert.Equal(NetworkTrustStatusKind.Verified, (await client.VerifyNetworkAsync()).Kind);
        Assert.Equal(built, w.Handler.Count("/nodes/discover"));
    }

    [Fact]
    public async Task Connect_RejectsWhenNoCandidateHasTheMajority()
    {
        var w = new World();
        w.CosignersByCandidate[C1] = 0;
        w.CosignersByCandidate[C2] = 0;
        await Assert.ThrowsAsync<DiscoveryException>(() => AvalonClient.ConnectAsync(Target, new DiscoveryConfig("i"), w.Http()));
    }

    [Fact]
    public async Task None_MakesNoListRequests()
    {
        var w = new World();
        w.CosignersByCandidate[C1] = 0;
        var found = await w.Discover(WitnessPolicy.None);
        Assert.Equal(C1, found.ServerUrl);
        Assert.Equal(0, w.Handler.Count("/nodes/discover"));
        Assert.Equal(0, w.Handler.Count("witnesses=1"));
    }

    [Fact]
    public async Task Explicit_OneOrZeroIsThePlainCheck_TwoOrMoreRequiresTheMajority()
    {
        var w = new World();
        w.CosignersByCandidate[C1] = 0;
        w.CosignersByCandidate[C2] = 0;
        var all = w.Fixture.Witnesses.Select(x => new KnownWitness(x.Id, x.Id)).ToList();

        Assert.Equal(C1, (await w.Discover(WitnessPolicy.Explicit(all.Take(1).ToList()))).ServerUrl);
        Assert.Equal(C1, (await w.Discover(WitnessPolicy.Explicit(new List<KnownWitness>()))).ServerUrl);
        Assert.Equal(0, w.Handler.Count("witnesses=1"));
        Assert.Equal(0, w.Handler.Count("/nodes/discover"));

        await Assert.ThrowsAsync<DiscoveryException>(() => w.Discover(WitnessPolicy.Explicit(all)));
        w.CosignersByCandidate[C1] = 2;
        Assert.Equal(C1, (await w.Discover(WitnessPolicy.Explicit(all))).ServerUrl);
        Assert.Equal(0, w.Handler.Count("/nodes/discover"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public async Task SingleSignerNetwork_ConnectsAsBefore(int witnesses)
    {
        var w = new World(witnesses);
        w.CosignersByCandidate[C1] = 0;
        w.CosignersByCandidate[C2] = 0;
        var client = await AvalonClient.ConnectAsync(Target, new DiscoveryConfig("i"), w.Http());
        Assert.Equal(NetworkTrustStatusKind.Verified, (await client.VerifyNetworkAsync()).Kind);
        Assert.Equal(C1, (await w.Discover(WitnessPolicy.Auto)).ServerUrl);
    }
}
