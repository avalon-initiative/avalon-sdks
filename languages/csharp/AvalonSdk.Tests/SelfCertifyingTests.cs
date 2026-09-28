using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Avalon.Sdk;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Xunit;

namespace Avalon.Sdk.Tests;

public class SelfCertifyingTests
{
    private static byte[] Seed(byte b) => Enumerable.Repeat(b, 32).ToArray();

    private static byte[] PublicKey(byte seed) => new Ed25519PrivateKeyParameters(Seed(seed), 0).GeneratePublicKey().GetEncoded();

    private static string HexOf(byte[] bytes) => string.Concat(bytes.Select(b => b.ToString("x2")));

    private static SignedTreeHeadWire SignedHead(byte seed)
    {
        var head = new SignedTreeHeadWire
        {
            TreeSize = 9,
            RootHash = new string('a', 32) + new string('b', 32),
            NetworkId = "avalon-test",
            SigningKeyId = "node-key-1",
            CreatedAt = DateTimeOffset.FromUnixTimeSeconds(1780000000),
        };
        var message = AvalonClient.SthSigningMessage(head.TreeSize, head.RootHash, head.NetworkId, head.CreatedAt);
        var signer = new Ed25519Signer();
        signer.Init(true, new Ed25519PrivateKeyParameters(Seed(seed), 0));
        signer.BlockUpdate(message, 0, message.Length);
        head.Signature = HexOf(signer.GenerateSignature());
        return head;
    }

    private static readonly string IdA = SelfCertifying.IdFor(PublicKey(1));
    private static readonly string KeyA = HexOf(PublicKey(1));
    private static readonly string KeyB = HexOf(PublicKey(2));

    private static void AssertFails(SelfCertifyingFailure expected, SelfCertifyingResult result)
    {
        Assert.False(result.Verified);
        Assert.Equal(expected, result.Failure);
    }

    [Fact]
    public void Verify_AcceptsAMatchingKeyAndHead_GivenOrCarriedOnTheHead()
    {
        var head = SignedHead(1);
        Assert.True(SelfCertifying.Verify(IdA, head, KeyA).Verified);
        head.SigningPublicKey = KeyA;
        var result = SelfCertifying.Verify(IdA, head);
        Assert.True(result.Verified);
        Assert.Null(result.Failure);
    }

    [Fact]
    public void Verify_RejectsAKeyThatDoesNotHashToTheId()
    {
        AssertFails(SelfCertifyingFailure.KeyIdMismatch, SelfCertifying.Verify(IdA, SignedHead(2), KeyB));
    }

    [Fact]
    public void Verify_RejectsAHeadSignedByADifferentKey()
    {
        AssertFails(SelfCertifyingFailure.BadSignature, SelfCertifying.Verify(IdA, SignedHead(2), KeyA));
    }

    [Fact]
    public void Verify_RejectsATamperedHead()
    {
        var head = SignedHead(1);
        head.TreeSize = 10;
        AssertFails(SelfCertifyingFailure.BadSignature, SelfCertifying.Verify(IdA, head, KeyA));
    }

    [Fact]
    public void Verify_ReportsAMissingOrMalformedKey()
    {
        var head = SignedHead(1);
        AssertFails(SelfCertifyingFailure.MissingKey, SelfCertifying.Verify(IdA, head));
        foreach (var bad in new[] { KeyA.ToUpperInvariant(), KeyA.Substring(2), KeyA + "00", "", new string('z', 64), KeyA + "\n" })
        {
            AssertFails(SelfCertifyingFailure.MalformedKey, SelfCertifying.Verify(IdA, head, bad));
        }
    }

    [Fact]
    public void Verify_RejectsIdsThatAreNotSelfCertifying()
    {
        var head = SignedHead(1);
        foreach (var id in new[] { "core", "game:wow-demo/1", "node:", "node:ab", IdA.ToUpperInvariant(), IdA + "\n", "" })
        {
            AssertFails(SelfCertifyingFailure.NotSelfCertifying, SelfCertifying.Verify(id, head, KeyA));
        }
    }

    [Fact]
    public void ShardCheckFor_NamesTheVerificationThatApplies()
    {
        Assert.Equal(ShardCheck.SelfCertifying, SelfCertifying.ShardCheckFor(IdA));
        Assert.Equal(ShardCheck.CoreNetwork, SelfCertifying.ShardCheckFor("core"));
        foreach (var other in new[] { "game:wow-demo/1", "app:notes", "service:x", "node:ab", "" })
        {
            Assert.Equal(ShardCheck.Unsupported, SelfCertifying.ShardCheckFor(other));
        }
    }

    [Fact]
    public void NullInputsAreTypedFailuresNotExceptions()
    {
        var head = SignedHead(1);
        Assert.Equal(ShardCheck.Unsupported, SelfCertifying.ShardCheckFor(null!));
        AssertFails(SelfCertifyingFailure.NotSelfCertifying, SelfCertifying.Verify(null!, head, KeyA));
        AssertFails(SelfCertifyingFailure.MissingKey, SelfCertifying.Verify(IdA, head, null));
        AssertFails(SelfCertifyingFailure.MissingKey, SelfCertifying.Verify(IdA, null!, null));
        AssertFails(SelfCertifyingFailure.BadSignature, SelfCertifying.Verify(IdA, null!, KeyA));
        head.Signature = null!;
        AssertFails(SelfCertifyingFailure.BadSignature, SelfCertifying.Verify(IdA, head, KeyA));
        head.Signature = "";
        head.RootHash = null!;
        AssertFails(SelfCertifyingFailure.BadSignature, SelfCertifying.Verify(IdA, head, KeyA));
    }

    private static string HeadJson(SignedTreeHeadWire head, string? key)
    {
        var extra = key == null ? "" : $",\"signing_public_key\":\"{key}\"";
        return $"{{\"tree_size\":{head.TreeSize},\"root_hash\":\"{head.RootHash}\",\"network_id\":\"{head.NetworkId}\","
            + $"\"signing_key_id\":\"{head.SigningKeyId}\",\"signature\":\"{head.Signature}\","
            + $"\"created_at\":\"2026-05-28T20:26:40Z\",\"protocol_version\":\"0.1\",\"unknown\":1{extra}}}";
    }

    private static AvalonClient ClientFor(StubHttpMessageHandler handler) =>
        new(new AvalonConfig("https://example.invalid", "test-key"), handler.ToHttpClient());

    [Fact]
    public async Task GetShardTreeHeadAsync_RequestsTheShardAndReturnsTheServedKey()
    {
        var handler = new StubHttpMessageHandler()
            .Enqueue(HeadJson(SignedHead(1), KeyA))
            .Enqueue(HeadJson(SignedHead(1), null));
        var client = ClientFor(handler);

        var latest = await client.GetShardTreeHeadAsync(IdA);
        var bySize = await client.GetShardTreeHeadAsync(IdA, 9);

        Assert.Equal($"https://example.invalid/ledger/sth/latest?shard_id={Uri.EscapeDataString(IdA)}", handler.Requests[0].Url);
        Assert.Equal($"https://example.invalid/ledger/sth/9?shard_id={Uri.EscapeDataString(IdA)}", handler.Requests[1].Url);
        Assert.Equal(KeyA, latest.SigningPublicKey);
        Assert.True(SelfCertifying.Verify(IdA, latest).Verified);
        Assert.Null(bySize.SigningPublicKey);
        AssertFails(SelfCertifyingFailure.MissingKey, SelfCertifying.Verify(IdA, bySize));
    }

    [Fact]
    public void CosignedHeadKeepsTheServedKey()
    {
        var json = HeadJson(SignedHead(1), KeyA).Replace("\"unknown\":1", "\"cosignatures\":[]");
        var wire = JsonSerializer.Deserialize<CosignedTreeHeadWire>(json)!;
        Assert.Equal(KeyA, wire.ToCosignedTreeHead().Sth.SigningPublicKey);
    }

    private static JsonDocument LoadVectors()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "conformance", "vectors")))
        {
            dir = dir.Parent;
        }
        Assert.NotNull(dir);
        return JsonDocument.Parse(File.ReadAllText(
            Path.Combine(dir!.FullName, "conformance", "vectors", "self-certifying-tree-head.json")));
    }

    [Fact]
    public void SelfCertifyingTreeHead_MatchesSharedVectors()
    {
        using var doc = LoadVectors();
        var root = doc.RootElement;
        Assert.Contains("csharp", root.GetProperty("supportedIn").EnumerateArray().Select(v => v.GetString()));
        Assert.Equal(root.GetProperty("selfCertifyingId").GetString(),
            SelfCertifying.IdFor(WitnessCosigning.TryHex(root.GetProperty("signingPublicKeyHex").GetString())!));
        Assert.Equal(root.GetProperty("otherSelfCertifyingId").GetString(),
            SelfCertifying.IdFor(WitnessCosigning.TryHex(root.GetProperty("otherPublicKeyHex").GetString())!));

        var failures = new System.Collections.Generic.List<string>();
        foreach (var vector in root.GetProperty("vectors").EnumerateArray())
        {
            var name = vector.GetProperty("name").GetString();
            var input = vector.GetProperty("input");
            var expected = vector.GetProperty("expected");
            var head = input.GetProperty("head");
            // Built as wire JSON so the tree size and the RFC 3339 timestamp go through the SDK's own parsing.
            var treeSize = head.GetProperty("treeSize");
            var treeSizeText = treeSize.ValueKind == JsonValueKind.String ? treeSize.GetString()! : treeSize.GetRawText();
            var wireJson = "{\"tree_size\":" + treeSizeText
                + ",\"root_hash\":" + JsonSerializer.Serialize(head.GetProperty("rootHashHex").GetString())
                + ",\"network_id\":" + JsonSerializer.Serialize(head.GetProperty("networkId").GetString())
                + ",\"signing_key_id\":" + JsonSerializer.Serialize(head.GetProperty("signingKeyId").GetString())
                + ",\"signature\":" + JsonSerializer.Serialize(head.GetProperty("signatureHex").GetString())
                + ",\"created_at\":" + JsonSerializer.Serialize(head.GetProperty("createdAtRfc3339").GetString()) + "}";
            var sth = JsonSerializer.Deserialize<SignedTreeHeadWire>(wireJson)!;
            if (head.GetProperty("createdAtUnixSeconds").GetInt64() != sth.CreatedAt.ToUnixTimeSeconds())
            {
                failures.Add($"[{name}] createdAtRfc3339 floors to createdAtUnixSeconds");
            }
            var shardId = input.GetProperty("shardId").GetString()!;
            var key = input.TryGetProperty("signingPublicKeyHex", out var k) ? k.GetString() : null;

            var expectedCheck = expected.GetProperty("check").GetString() switch
            {
                "self_certifying" => ShardCheck.SelfCertifying,
                "core_network" => ShardCheck.CoreNetwork,
                "unsupported" => ShardCheck.Unsupported,
                var other => throw new InvalidOperationException(other),
            };
            if (expectedCheck != SelfCertifying.ShardCheckFor(shardId))
            {
                failures.Add($"[{name}] check");
            }

            var result = SelfCertifying.Verify(shardId, sth, key);
            if (expected.GetProperty("verified").GetBoolean() != result.Verified)
            {
                failures.Add($"[{name}] verified");
            }
            var expectedFailure = expected.GetProperty("failure").ValueKind == JsonValueKind.Null
                ? null
                : expected.GetProperty("failure").GetString();
            var actualFailure = result.Failure switch
            {
                null => null,
                SelfCertifyingFailure.NotSelfCertifying => "not_self_certifying",
                SelfCertifyingFailure.MissingKey => "missing_key",
                SelfCertifyingFailure.MalformedKey => "malformed_key",
                SelfCertifyingFailure.KeyIdMismatch => "key_id_mismatch",
                SelfCertifyingFailure.BadSignature => "bad_signature",
                _ => "unknown",
            };
            if (expectedFailure != actualFailure)
            {
                failures.Add($"[{name}] failure: expected {expectedFailure}, got {actualFailure}");
            }
        }
        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }
}
