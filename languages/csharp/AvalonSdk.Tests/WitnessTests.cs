using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Xunit;

namespace Avalon.Sdk.Tests;

public class WitnessTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(10_000);
    private static readonly DateTimeOffset Cutoff = Now - TimeSpan.FromMinutes(10);
    private const string Net = "avalon-test";
    private static readonly string Root = string.Concat(Enumerable.Repeat("ab", 32));

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

    private static SignedTreeHeadWire Head(Ed25519PrivateKeyParameters author, long size = 5)
    {
        var createdAt = Now;
        return new SignedTreeHeadWire
        {
            TreeSize = size,
            RootHash = Root,
            NetworkId = Net,
            SigningKeyId = "author",
            CreatedAt = createdAt,
            Signature = Hex(Sign(author, AvalonClient.SthSigningMessage(size, Root, Net, createdAt))),
        };
    }

    private static WitnessCosignature Cosign(
        Ed25519PrivateKeyParameters key, string id, SignedTreeHeadWire sth, DateTimeOffset? observedAt = null)
    {
        var observed = observedAt ?? Now;
        var message = WitnessCosigning.WitnessSigningMessage(
            sth.TreeSize, sth.RootHash, sth.NetworkId, sth.CreatedAt, id, observed);
        return new WitnessCosignature
        {
            TreeSize = sth.TreeSize,
            RootHash = sth.RootHash,
            NetworkId = sth.NetworkId,
            AuthorCreatedAt = sth.CreatedAt,
            WitnessKeyId = id,
            ObservedAt = observed,
            Signature = Hex(Sign(key, message)),
        };
    }

    private sealed class Fixture
    {
        public Ed25519PrivateKeyParameters Author = NewKey();
        public List<(string Id, Ed25519PrivateKeyParameters Key)> Witnesses = new();
        public List<KnownWitness> Known = new();

        public Fixture(int count)
        {
            for (var i = 0; i < count; i++)
            {
                var key = NewKey();
                Witnesses.Add(($"witness-{i}", key));
                Known.Add(new KnownWitness($"witness-{i}", PubHex(key)));
            }
        }

        public string AuthorHex => PubHex(Author);
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(1, 1)]
    [InlineData(2, 2)]
    [InlineData(3, 2)]
    [InlineData(4, 3)]
    [InlineData(5, 3)]
    public void MajorityThreshold_IsHalfPlusOne_AndZeroForEmpty(int size, int expected)
    {
        Assert.Equal(expected, WitnessCosigning.MajorityThreshold(size));
        Assert.True(WitnessCosigning.IsCosignedByMajority(size, expected));
        if (expected > 0)
        {
            Assert.False(WitnessCosigning.IsCosignedByMajority(size, expected - 1));
        }
    }

    [Fact]
    public void SigningMessage_HasTheDocumentedLayout()
    {
        var message = WitnessCosigning.WitnessSigningMessage(
            1, "ab", "n", DateTimeOffset.FromUnixTimeSeconds(2), "w", DateTimeOffset.FromUnixTimeSeconds(3));
        var expected = new List<byte>();
        expected.AddRange(System.Text.Encoding.UTF8.GetBytes("avalon-witness-cosign-v1"));
        expected.AddRange(new byte[] { 0, 0, 0, 0, 0, 0, 0, 1 });
        expected.AddRange(new byte[] { 0, 0, 0, 2, (byte)'a', (byte)'b' });
        expected.AddRange(new byte[] { 0, 0, 0, 1, (byte)'n' });
        expected.AddRange(new byte[] { 0, 0, 0, 0, 0, 0, 0, 2 });
        expected.AddRange(new byte[] { 0, 0, 0, 1, (byte)'w' });
        expected.AddRange(new byte[] { 0, 0, 0, 0, 0, 0, 0, 3 });
        Assert.Equal(expected.ToArray(), message);
    }

    [Fact]
    public void VerifyCosignature_RoundTrips_AndRejectsMalformedInput()
    {
        var f = new Fixture(1);
        var sth = Head(f.Author);
        var cosig = Cosign(f.Witnesses[0].Key, "w", sth);
        var keyHex = f.Known[0].VerifyKeyHex;
        Assert.True(WitnessCosigning.VerifyWitnessCosignature(keyHex, cosig));

        cosig.Signature = "zz" + cosig.Signature.Substring(2);
        Assert.False(WitnessCosigning.VerifyWitnessCosignature(keyHex, cosig));
        cosig.Signature = "abc";
        Assert.False(WitnessCosigning.VerifyWitnessCosignature(keyHex, cosig));
        cosig.Signature = cosig.Signature.Substring(0, 0);
        Assert.False(WitnessCosigning.VerifyWitnessCosignature(keyHex, cosig));
        cosig = Cosign(f.Witnesses[0].Key, "w", sth);
        cosig.Signature = cosig.Signature.Substring(0, 126);
        Assert.False(WitnessCosigning.VerifyWitnessCosignature(keyHex, cosig));
        cosig = Cosign(f.Witnesses[0].Key, "w", sth);
        Assert.False(WitnessCosigning.VerifyWitnessCosignature("nothex", cosig));
        Assert.False(WitnessCosigning.VerifyWitnessCosignature(keyHex.Substring(2), cosig));
        Assert.False(WitnessCosigning.VerifyWitnessCosignature(PubHex(NewKey()), cosig));
        cosig.ObservedAt += TimeSpan.FromSeconds(1);
        Assert.False(WitnessCosigning.VerifyWitnessCosignature(keyHex, cosig));
    }

    [Fact]
    public void Verify_EmptyOrSingleList_ReturnsJustTheAuthorCheck()
    {
        var f = new Fixture(1);
        var head = new CosignedTreeHead(Head(f.Author), new List<WitnessCosignature>());
        Assert.True(WitnessCosigning.VerifyCosignedTreeHead(f.AuthorHex, head, new List<KnownWitness>(), Cutoff, Now));
        Assert.True(WitnessCosigning.VerifyCosignedTreeHead(f.AuthorHex, head, f.Known, Cutoff, Now));
        Assert.False(WitnessCosigning.VerifyCosignedTreeHead(PubHex(NewKey()), head, f.Known, Cutoff, Now));
        Assert.False(WitnessCosigning.VerifyCosignedTreeHead("garbage", head, f.Known, Cutoff, Now));
    }

    [Fact]
    public void Verify_MajorityWithFreshnessBoundsAndDedup()
    {
        var f = new Fixture(3);
        var sth = Head(f.Author);
        List<WitnessCosignature> Sigs(params int[] who) =>
            who.Select(i => Cosign(f.Witnesses[i].Key, f.Witnesses[i].Id, sth)).ToList();
        bool Check(List<WitnessCosignature> sigs) =>
            WitnessCosigning.VerifyCosignedTreeHead(f.AuthorHex, new CosignedTreeHead(sth, sigs), f.Known, Cutoff, Now);

        Assert.True(Check(Sigs(0, 1)));
        Assert.False(Check(Sigs(0)));
        Assert.False(Check(Sigs(0, 0, 0)));

        var atCutoff = Cosign(f.Witnesses[1].Key, "witness-1", sth, Cutoff);
        Assert.True(Check(new List<WitnessCosignature> { Sigs(0)[0], atCutoff }));
        var stale = Cosign(f.Witnesses[1].Key, "witness-1", sth, Cutoff - TimeSpan.FromSeconds(1));
        Assert.False(Check(new List<WitnessCosignature> { Sigs(0)[0], stale }));
        var future = Cosign(f.Witnesses[1].Key, "witness-1", sth, Now + TimeSpan.FromSeconds(1));
        Assert.False(Check(new List<WitnessCosignature> { Sigs(0)[0], future }));

        var wrongSize = Sigs(1)[0];
        wrongSize.TreeSize++;
        Assert.False(Check(new List<WitnessCosignature> { Sigs(0)[0], wrongSize }));
        var wrongNetwork = Sigs(1)[0];
        wrongNetwork.NetworkId = "other";
        Assert.False(Check(new List<WitnessCosignature> { Sigs(0)[0], wrongNetwork }));
        var wrongAuthorTime = Sigs(1)[0];
        wrongAuthorTime.AuthorCreatedAt += TimeSpan.FromSeconds(1);
        Assert.False(Check(new List<WitnessCosignature> { Sigs(0)[0], wrongAuthorTime }));

        var badSig = Sigs(1)[0];
        badSig.Signature = "00";
        Assert.False(Check(new List<WitnessCosignature> { Sigs(0)[0], badSig }));
    }

    [Fact]
    public void Verify_AuthorKeyListedAsWitness_CountsWithoutACosignature()
    {
        var f = new Fixture(1);
        var known = new List<KnownWitness> { f.Known[0], new KnownWitness("author-as-witness", f.AuthorHex) };
        var sth = Head(f.Author);
        var alone = new CosignedTreeHead(sth, new List<WitnessCosignature>());
        Assert.False(WitnessCosigning.VerifyCosignedTreeHead(f.AuthorHex, alone, known, Cutoff, Now));
        var withOne = new CosignedTreeHead(sth, new List<WitnessCosignature> { Cosign(f.Witnesses[0].Key, "witness-0", sth) });
        Assert.True(WitnessCosigning.VerifyCosignedTreeHead(f.AuthorHex, withOne, known, Cutoff, Now));
    }

    [Fact]
    public void FindEquivocating_EmptyUnlessBothHeadsAcceptedAtOneSizeWithDifferentRoots()
    {
        var f = new Fixture(3);
        var a = Head(f.Author);
        var otherRoot = string.Concat(Enumerable.Repeat("cd", 32));
        var b = new SignedTreeHeadWire
        {
            TreeSize = a.TreeSize, RootHash = otherRoot, NetworkId = Net, SigningKeyId = "author", CreatedAt = a.CreatedAt,
            Signature = Hex(Sign(f.Author, AvalonClient.SthSigningMessage(a.TreeSize, otherRoot, Net, a.CreatedAt))),
        };
        var headA = new CosignedTreeHead(a, new[] { 0, 1 }.Select(i => Cosign(f.Witnesses[i].Key, f.Witnesses[i].Id, a)).ToList());
        var headB = new CosignedTreeHead(b, new[] { 1, 2 }.Select(i => Cosign(f.Witnesses[i].Key, f.Witnesses[i].Id, b)).ToList());

        Assert.Equal(new[] { "witness-1" }, WitnessCosigning.FindEquivocatingWitnesses(f.AuthorHex, f.Known, Cutoff, Now, headA, headB));
        Assert.Empty(WitnessCosigning.FindEquivocatingWitnesses(f.AuthorHex, f.Known, Cutoff, Now, headA, headA));
        Assert.Empty(WitnessCosigning.FindEquivocatingWitnesses(f.AuthorHex, new List<KnownWitness>(), Cutoff, Now, headA, headB));
        var unsigned = new CosignedTreeHead(b, new List<WitnessCosignature>());
        Assert.Empty(WitnessCosigning.FindEquivocatingWitnesses(f.AuthorHex, f.Known, Cutoff, Now, headA, unsigned));
    }

    private static string AnchorsJson(string networkId, string keyHex) =>
        "{\"networks\":[{\"label\":\"n\",\"network_id\":\"" + networkId + "\",\"verify_key\":\"" + keyHex +
        "\",\"signing_key_id\":\"k\",\"environment\":\"local-dev\"}]}";

    private static string HeadJson(SignedTreeHeadWire sth, IEnumerable<WitnessCosignature> cosigs)
    {
        var body = System.Text.Json.JsonSerializer.Serialize(sth);
        var extra = string.Join(",", cosigs.Select(c =>
            "{\"witness_key_id\":\"" + c.WitnessKeyId + "\",\"observed_at\":\"" +
            c.ObservedAt.ToString("o") + "\",\"signature\":\"" + c.Signature + "\"}"));
        return body.TrimEnd('}') + ",\"cosignatures\":[" + extra + "]}";
    }

    [Fact]
    public async Task VerifyNetworkAsync_WithAKnownList_RequiresTheCosignedMajority()
    {
        var f = new Fixture(3);
        var now = DateTimeOffset.UtcNow;
        var createdAt = DateTimeOffset.FromUnixTimeSeconds(now.ToUnixTimeSeconds());
        var sth = new SignedTreeHeadWire
        {
            TreeSize = 5, RootHash = Root, NetworkId = Net, SigningKeyId = "author", CreatedAt = createdAt,
            Signature = Hex(Sign(f.Author, AvalonClient.SthSigningMessage(5, Root, Net, createdAt))),
        };
        var sigs = new[] { 0, 1 }.Select(i => Cosign(f.Witnesses[i].Key, f.Witnesses[i].Id, sth, createdAt)).ToList();

        async Task<(NetworkTrustStatus, StubHttpMessageHandler)> Run(IEnumerable<WitnessCosignature> use, List<KnownWitness>? known)
        {
            var handler = new StubHttpMessageHandler().Enqueue(AnchorsJson(Net, f.AuthorHex)).Enqueue(HeadJson(sth, use));
            var client = new AvalonClient(new AvalonConfig("https://example.invalid", "i"), handler.ToHttpClient());
            return (await client.VerifyNetworkAsync(known), handler);
        }

        var (ok, handler) = await Run(sigs, f.Known);
        Assert.Equal(NetworkTrustStatusKind.Verified, ok.Kind);
        Assert.EndsWith("/ledger/sth/latest?witnesses=1", handler.Requests[1].Url);

        Assert.Equal(NetworkTrustStatusKind.Mismatch, (await Run(sigs.Take(1), f.Known)).Item1.Kind);

        var (single, singleHandler) = await Run(new List<WitnessCosignature>(), f.Known.Take(1).ToList());
        Assert.Equal(NetworkTrustStatusKind.Verified, single.Kind);
        Assert.EndsWith("/ledger/sth/latest", singleHandler.Requests[1].Url);
    }

    [Fact]
    public async Task GetCosignedTreeHeadAsync_RequestsWitnessesAndBindsCosignaturesToTheHead()
    {
        var f = new Fixture(2);
        var sth = Head(f.Author, 7);
        var cosig = Cosign(f.Witnesses[0].Key, "witness-0", sth);
        var handler = new StubHttpMessageHandler().Enqueue(HeadJson(sth, new[] { cosig }));
        var client = new AvalonClient(new AvalonConfig("https://example.invalid", "i"), handler.ToHttpClient());

        var head = await client.GetCosignedTreeHeadAsync("core", 7);

        Assert.EndsWith("/ledger/sth/7?shard_id=core&witnesses=1", handler.Requests[0].Url);
        var got = Assert.Single(head.Cosignatures);
        Assert.Equal(7, got.TreeSize);
        Assert.True(WitnessCosigning.VerifyWitnessCosignature(f.Known[0].VerifyKeyHex, got));
    }
}
