using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Avalon.Sdk;
using Xunit;

namespace Avalon.Sdk.Tests;

/// <summary>Runs every vector in the shared witness-cosigned-tree-head.json. Not gated on
/// supportedIn: the vectors are the acceptance criteria for this implementation.</summary>
public class WitnessConformanceTests
{
    private static JsonDocument Load()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "conformance", "vectors")))
        {
            dir = dir.Parent;
        }
        Assert.NotNull(dir);
        return JsonDocument.Parse(File.ReadAllText(
            Path.Combine(dir!.FullName, "conformance", "vectors", "witness-cosigned-tree-head.json")));
    }

    private static byte[] Hex(string hex) => StructuredConformanceTests.Hex(hex);

    private static CosignedTreeHead ParseHead(JsonElement head, string networkId, JsonElement keys)
    {
        var sthJson = head.GetProperty("sth");
        var createdAt = DateTimeOffset.FromUnixTimeSeconds(sthJson.GetProperty("createdAtUnixSeconds").GetInt64());
        var sth = new SignedTreeHeadWire
        {
            TreeSize = sthJson.GetProperty("treeSize").GetInt64(),
            RootHash = sthJson.GetProperty("rootHashHex").GetString()!,
            NetworkId = networkId,
            SigningKeyId = sthJson.GetProperty("signingKeyId").GetString()!,
            Signature = sthJson.GetProperty("signatureHex").GetString()!,
            CreatedAt = createdAt,
        };
        var cosigs = new List<WitnessCosignature>();
        foreach (var c in head.GetProperty("cosignatures").EnumerateArray())
        {
            var witnessId = c.GetProperty("witnessKeyId").GetString()!;
            var wire = new WitnessCosignatureWire();
            if (c.TryGetProperty("envelope", out var env))
            {
                wire.LayoutVersion = env.GetProperty("layoutVersion").GetInt64();
                wire.RulesVersion = env.GetProperty("rulesVersion").GetInt64();
                wire.HashAlgo = env.GetProperty("hashAlgo").GetInt32();
                wire.Extensions = env.GetProperty("extensions").GetString()!;
            }
            Envelope envelope;
            try
            {
                envelope = wire.ToEnvelope(DomainTags.WitnessCosign);
            }
            catch (SigningBytesException)
            {
                continue;
            }
            var cosig = new WitnessCosignature
            {
                TreeSize = sth.TreeSize,
                RootHash = sth.RootHash,
                NetworkId = networkId,
                AuthorCreatedAt = createdAt,
                AuthorSigningKeyId = sth.SigningKeyId,
                AuthorSignature = sth.Signature,
                WitnessKeyId = witnessId,
                ObservedAt = DateTimeOffset.FromUnixTimeSeconds(c.GetProperty("observedAtUnixSeconds").GetInt64()),
                Signature = c.GetProperty("signatureHex").GetString()!,
                Envelope = envelope,
            };
            if (c.TryGetProperty("signingBytesHex", out var bytesHex) && keys.TryGetProperty(witnessId, out var key))
            {
                var bytes = WitnessCosigning.WitnessSigningMessage(cosig, Hex(key.GetString()!));
                Assert.True(bytesHex.GetString() == StructuredConformanceTests.ToHex(bytes), $"cosignature bytes of {witnessId}");
            }
            cosigs.Add(cosig);
        }
        return new CosignedTreeHead(sth, cosigs);
    }

    [Fact]
    public void WitnessCosignedTreeHead_MatchesSharedVectors()
    {
        using var doc = Load();
        var root = doc.RootElement;
        var authorKey = root.GetProperty("authorVerifyingKeyHex").GetString()!;
        var networkId = root.GetProperty("networkId").GetString()!;
        var keys = root.GetProperty("witnessVerifyingKeysHex");
        var vectors = root.GetProperty("vectors").EnumerateArray().ToList();
        Assert.NotEmpty(vectors);

        foreach (var vector in vectors)
        {
            var name = vector.GetProperty("name").GetString();
            var input = vector.GetProperty("input");
            var expected = vector.GetProperty("expected");
            var known = input.GetProperty("knownList").EnumerateArray()
                .Select(id => new KnownWitness(id.GetString()!, keys.GetProperty(id.GetString()!).GetString()!))
                .ToList();
            var cutoff = DateTimeOffset.FromUnixTimeSeconds(input.GetProperty("freshnessCutoffUnixSeconds").GetInt64());
            var now = DateTimeOffset.FromUnixTimeSeconds(input.GetProperty("nowUnixSeconds").GetInt64());

            if (input.TryGetProperty("headA", out var a))
            {
                var headA = ParseHead(a, networkId, keys);
                var headB = ParseHead(input.GetProperty("headB"), networkId, keys);
                Assert.True(
                    expected.GetProperty("headAAccepted").GetBoolean()
                        == WitnessCosigning.VerifyCosignedTreeHead(authorKey, headA, known, cutoff, now),
                    $"[{name}] head A acceptance");
                Assert.True(
                    expected.GetProperty("headBAccepted").GetBoolean()
                        == WitnessCosigning.VerifyCosignedTreeHead(authorKey, headB, known, cutoff, now),
                    $"[{name}] head B acceptance");
                var want = expected.GetProperty("equivocatingWitnesses").EnumerateArray().Select(e => e.GetString()!).ToList();
                Assert.Equal(want, WitnessCosigning.FindEquivocatingWitnesses(authorKey, known, cutoff, now, headA, headB));
            }
            else
            {
                var head = ParseHead(input, networkId, keys);
                Assert.True(
                    expected.GetProperty("accepted").GetBoolean()
                        == WitnessCosigning.VerifyCosignedTreeHead(authorKey, head, known, cutoff, now),
                    $"[{name}] acceptance");
            }
        }
    }

    [Fact]
    public void WitnessCosignature_ReadRejectVectors_FailWithTheExpectedError()
    {
        using var doc = Load();
        var rejects = doc.RootElement.GetProperty("readRejectVectors").EnumerateArray().ToList();
        Assert.Equal(6, rejects.Count);
        foreach (var vector in rejects)
        {
            StructuredConformanceTests.AssertReadRejects(vector);
        }
    }
}
