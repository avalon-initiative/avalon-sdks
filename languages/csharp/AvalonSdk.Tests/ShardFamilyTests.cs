using System;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Avalon.Sdk;
using Xunit;

namespace Avalon.Sdk.Tests;

public class ShardFamilyTests
{
    private static FamilyHead Head(JsonElement h) => new FamilyHead
    {
        ShardId = h.GetProperty("shardId").GetString()!,
        // Decimal strings carry tree sizes beyond 2^53.
        TreeSize = h.GetProperty("treeSize").ValueKind == JsonValueKind.String
            ? long.Parse(h.GetProperty("treeSize").GetString()!)
            : h.GetProperty("treeSize").GetInt64(),
        RootHash = h.GetProperty("rootHashHex").GetString()!,
        SigningKeyId = h.GetProperty("signingKeyId").GetString()!,
        Signature = h.GetProperty("signatureHex").GetString()!,
    };

    [Fact]
    public void MatchesTheSharedVectors()
    {
        using var doc = ConformanceTests.LoadVector("shard-family-head.json");
        var root = doc.RootElement;
        Assert.Contains("csharp", root.GetProperty("supportedIn").EnumerateArray().Select(e => e.GetString()));

        foreach (var v in root.GetProperty("familyVectors").EnumerateArray())
        {
            var heads = v.GetProperty("input").GetProperty("heads").EnumerateArray().Select(Head).ToList();
            Assert.True(
                v.GetProperty("expected").GetProperty("rootHashHex").GetString()
                    == ShardFamily.Root(v.GetProperty("input").GetProperty("owner").GetString()!, heads),
                $"[{v.GetProperty("name").GetString()}] family root");
        }

        foreach (var v in root.GetProperty("proofVectors").EnumerateArray())
        {
            var input = v.GetProperty("input");
            var head = Head(input.GetProperty("head"));
            head.ShardId = input.GetProperty("shardId").GetString()!;
            var p = input.GetProperty("proof");
            var proof = new FamilyProof
            {
                ShardId = head.ShardId,
                LeafIndex = p.GetProperty("leafIndex").GetInt64(),
                TreeSize = p.GetProperty("treeSize").GetInt64(),
                Path = p.GetProperty("pathHex").EnumerateArray().Select(e => e.GetString()!).ToList(),
            };
            var verified = ShardFamily.VerifyInclusion(
                input.GetProperty("owner").GetString()!, input.GetProperty("rootHashHex").GetString()!, proof, head);
            Assert.True(
                v.GetProperty("expected").GetProperty("verified").GetBoolean() == verified,
                $"[{v.GetProperty("name").GetString()}] verified");
        }

        foreach (var v in root.GetProperty("familyOwnerVectors").EnumerateArray())
        {
            var id = v.GetProperty("shardId").GetString();
            var expected = v.GetProperty("expectedOwner");
            Assert.True(
                (expected.ValueKind == JsonValueKind.Null ? null : expected.GetString()) == ShardFamily.OwnerOf(id),
                $"[owner of {id}]");
        }

        foreach (var v in root.GetProperty("ownerIdVectors").EnumerateArray())
        {
            var id = v.GetProperty("owner").GetString();
            Assert.True(v.GetProperty("expected").GetBoolean() == ShardFamily.IsOwnerId(id), $"[owner id {id}]");
        }

        foreach (var v in root.GetProperty("memberVectors").EnumerateArray())
        {
            var owner = v.GetProperty("owner").GetString();
            var id = v.GetProperty("shardId").GetString();
            Assert.True(v.GetProperty("expected").GetBoolean() == ShardFamily.IsMember(owner, id), $"[member {owner} {id}]");
        }
    }

    // The server's JSON for the "two members" vector, with the proof for the member when given.
    private static string Body(string? member, bool tamper = false)
    {
        using var doc = ConformanceTests.LoadVector("shard-family-head.json");
        var fam = doc.RootElement.GetProperty("familyVectors").EnumerateArray()
            .First(v => v.GetProperty("name").GetString() == "two members");
        var owner = fam.GetProperty("input").GetProperty("owner").GetString()!;
        var rootHash = fam.GetProperty("expected").GetProperty("rootHashHex").GetString()!;
        var members = fam.GetProperty("expected").GetProperty("memberShardIds").EnumerateArray()
            .Select(id => fam.GetProperty("input").GetProperty("heads").EnumerateArray()
                .First(h => h.GetProperty("shardId").GetString() == id.GetString()))
            .Select(h => new
            {
                shard_id = h.GetProperty("shardId").GetString(),
                tree_size = h.GetProperty("treeSize").GetInt64(),
                root_hash = h.GetProperty("rootHashHex").GetString(),
                signing_key_id = h.GetProperty("signingKeyId").GetString(),
                signature = tamper ? "00" : h.GetProperty("signatureHex").GetString(),
                created_at = "2023-11-14T22:13:20Z",
            }).ToList();
        object? proof = null;
        if (member != null)
        {
            var p = doc.RootElement.GetProperty("proofVectors").EnumerateArray().First(v =>
                v.GetProperty("input").GetProperty("owner").GetString() == owner
                && v.GetProperty("input").GetProperty("shardId").GetString() == member
                && v.GetProperty("input").GetProperty("rootHashHex").GetString() == rootHash
                && v.GetProperty("expected").GetProperty("verified").GetBoolean()).GetProperty("input").GetProperty("proof");
            proof = new
            {
                shard_id = member,
                leaf_index = p.GetProperty("leafIndex").GetInt64(),
                tree_size = p.GetProperty("treeSize").GetInt64(),
                path = p.GetProperty("pathHex").EnumerateArray().Select(e => e.GetString()).ToList(),
            };
        }
        return JsonSerializer.Serialize(new
        {
            owner,
            root_hash = rootHash,
            shard_count = members.Count,
            partial = false,
            missing_shard_ids = new string[0],
            members,
            proof,
        });
    }

    private static AvalonClient ClientFor(StubHttpMessageHandler handler) =>
        new(new AvalonConfig("https://example.invalid", "test-key"), handler.ToHttpClient());

    [Fact]
    public async Task GetShardFamilyAsync_RequestsTheOwnerAndMemberAndTheResponseVerifies()
    {
        var handler = new StubHttpMessageHandler().Enqueue(Body("game:x/2")).Enqueue(Body(null));
        var client = ClientFor(handler);

        var withProof = await client.GetShardFamilyAsync("game:x", "game:x/2");
        var without = await client.GetShardFamilyAsync("game:x");

        Assert.Equal("https://example.invalid/ledger/shard-family?owner=game%3Ax&member=game%3Ax%2F2", handler.Requests[0].Url);
        Assert.Equal("https://example.invalid/ledger/shard-family?owner=game%3Ax", handler.Requests[1].Url);
        Assert.Equal(2, withProof.ShardCount);
        Assert.True(withProof.RootMatches());
        Assert.True(withProof.ProofVerifies());
        Assert.Null(without.Proof);
        Assert.False(without.ProofVerifies());
    }

    [Fact]
    public async Task ATamperedMemberIsDetected()
    {
        var handler = new StubHttpMessageHandler().Enqueue(Body("game:x/2", tamper: true));
        var family = await ClientFor(handler).GetShardFamilyAsync("game:x", "game:x/2");
        Assert.False(family.RootMatches());
        Assert.False(family.ProofVerifies());
    }
}
