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

    private static CosignedTreeHead ParseHead(JsonElement head, string networkId)
    {
        var sthJson = head.GetProperty("sth");
        var createdAt = DateTimeOffset.FromUnixTimeSeconds(sthJson.GetProperty("createdAtUnixSeconds").GetInt64());
        var sth = new SignedTreeHeadWire
        {
            TreeSize = sthJson.GetProperty("treeSize").GetInt64(),
            RootHash = sthJson.GetProperty("rootHashHex").GetString()!,
            NetworkId = networkId,
            SigningKeyId = "vector-author",
            Signature = sthJson.GetProperty("signatureHex").GetString()!,
            CreatedAt = createdAt,
        };
        var cosigs = head.GetProperty("cosignatures").EnumerateArray().Select(c => new WitnessCosignature
        {
            TreeSize = sth.TreeSize,
            RootHash = sth.RootHash,
            NetworkId = networkId,
            AuthorCreatedAt = createdAt,
            WitnessKeyId = c.GetProperty("witnessKeyId").GetString()!,
            ObservedAt = DateTimeOffset.FromUnixTimeSeconds(c.GetProperty("observedAtUnixSeconds").GetInt64()),
            Signature = c.GetProperty("signatureHex").GetString()!,
        }).ToList();
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
                var headA = ParseHead(a, networkId);
                var headB = ParseHead(input.GetProperty("headB"), networkId);
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
                var head = ParseHead(input, networkId);
                Assert.True(
                    expected.GetProperty("accepted").GetBoolean()
                        == WitnessCosigning.VerifyCosignedTreeHead(authorKey, head, known, cutoff, now),
                    $"[{name}] acceptance");
            }
        }
    }
}
