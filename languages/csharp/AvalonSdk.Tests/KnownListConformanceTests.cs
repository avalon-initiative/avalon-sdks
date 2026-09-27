using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Avalon.Sdk;
using Xunit;

namespace Avalon.Sdk.Tests;

/// <summary>Runs every vector in the shared known-list-selection.json and witness-announce.json.
/// Not gated on supportedIn: the vectors are the acceptance criteria for this implementation.</summary>
public class KnownListConformanceTests
{
    private static JsonDocument Load(string name)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "conformance", "vectors")))
        {
            dir = dir.Parent;
        }
        Assert.NotNull(dir);
        return JsonDocument.Parse(File.ReadAllText(Path.Combine(dir!.FullName, "conformance", "vectors", name)));
    }

    [Fact]
    public void PrefixVectors_MatchTheSharedVectors()
    {
        using var doc = Load("known-list-selection.json");
        var vectors = doc.RootElement.GetProperty("prefixVectors").EnumerateArray().ToList();
        Assert.NotEmpty(vectors);
        foreach (var v in vectors)
        {
            var expected = v.GetProperty("expected").GetProperty("prefix");
            var actual = KnownListRules.DiversityPrefixForUrl(v.GetProperty("input").GetProperty("baseUrl").GetString()!);
            Assert.True(
                expected.ValueKind == JsonValueKind.Null ? actual == null : actual == expected.GetString(),
                $"{v.GetProperty("name").GetString()}: got {actual ?? "null"}");
        }
    }

    [Fact]
    public void SelectionVectors_MatchTheSharedVectors()
    {
        using var doc = Load("known-list-selection.json");
        var vectors = doc.RootElement.GetProperty("selectionVectors").EnumerateArray().ToList();
        Assert.NotEmpty(vectors);
        foreach (var v in vectors)
        {
            var input = v.GetProperty("input");
            var candidates = input.GetProperty("candidates").EnumerateArray().Select(c => new KnownListCandidate(
                c.GetProperty("witnessKeyId").GetString()!,
                c.GetProperty("baseUrl").GetString()!,
                c.GetProperty("isAnchor").GetBoolean())).ToList();
            var actual = KnownListRules.SelectKnownList(
                candidates,
                input.GetProperty("capacity").GetInt32(),
                input.GetProperty("anchorCapacity").GetInt32(),
                input.GetProperty("maxPerPrefix").GetInt32());
            var expected = v.GetProperty("expected").EnumerateArray().Select(e => e.GetString()!).ToList();
            Assert.True(expected.SequenceEqual(actual), v.GetProperty("name").GetString());
        }
    }

    [Fact]
    public void AnnounceVectors_MatchTheSharedVectors()
    {
        using var doc = Load("witness-announce.json");
        var vectors = doc.RootElement.GetProperty("vectors").EnumerateArray().ToList();
        Assert.NotEmpty(vectors);
        foreach (var v in vectors)
        {
            var input = v.GetProperty("input");
            var baseUrl = input.GetProperty("baseUrl").GetString()!;
            var keyId = input.GetProperty("witnessKeyId").GetString()!;
            var announcedAt = DateTimeOffset.Parse(input.GetProperty("announcedAt").GetString()!);
            var now = DateTimeOffset.Parse(input.GetProperty("now").GetString()!);
            var name = v.GetProperty("name").GetString();
            if (input.TryGetProperty("messageHex", out var messageHex))
            {
                var actual = string.Concat(KnownListRules.WitnessAnnounceMessage(baseUrl, keyId, announcedAt).Select(b => b.ToString("x2")));
                Assert.True(messageHex.GetString() == actual, $"{name}: message bytes");
            }
            Assert.True(
                v.GetProperty("expected").GetProperty("accepted").GetBoolean()
                    == KnownListRules.VerifyWitnessAnnounce(baseUrl, keyId, announcedAt, input.GetProperty("proofHex").GetString()!, now),
                name);
        }
    }
}
