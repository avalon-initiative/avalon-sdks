using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using Avalon.Sdk;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Xunit;

namespace Avalon.Sdk.Tests;

/// <summary>Asserts identity-id.json, identity-created-signing.json, device-grant-approval.json
/// and signing-key-revoked.json against <see cref="IdentityId"/> and
/// <see cref="IdentitySigning"/>.</summary>
public class IdentityConformanceTests
{
    private static byte[] Hex(string hex)
    {
        Assert.Equal(0, hex.Length % 2);
        var bytes = new byte[hex.Length / 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }

    private static string ToHex(byte[] bytes) => string.Concat(bytes.Select(b => b.ToString("x2")));

    private static byte[] PublicKeyOfSeed(string seedHex) =>
        new Ed25519PrivateKeyParameters(Hex(seedHex), 0).GeneratePublicKey().GetEncoded();

    private static string Sign(string seedHex, byte[] message)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, new Ed25519PrivateKeyParameters(Hex(seedHex), 0));
        signer.BlockUpdate(message, 0, message.Length);
        return ToHex(signer.GenerateSignature());
    }

    public static IEnumerable<object[]> IdentityIdVectors()
    {
        using var doc = ConformanceTests.LoadVector("identity-id.json");
        return doc.RootElement.GetProperty("vectors").EnumerateArray()
            .Select(v => new object[] { v.GetProperty("name").GetString()! }).ToList();
    }

    [Theory]
    [MemberData(nameof(IdentityIdVectors))]
    public void IdentityId_MatchesSharedVector(string vectorName)
    {
        using var doc = ConformanceTests.LoadVector("identity-id.json");
        var vector = doc.RootElement.GetProperty("vectors").EnumerateArray()
            .Single(v => v.GetProperty("name").GetString() == vectorName);
        var input = vector.GetProperty("input");
        var expected = vector.GetProperty("expected");
        switch (vector.GetProperty("kind").GetString())
        {
            case "derive":
                var publicKey = PublicKeyOfSeed(input.GetProperty("seedHex").GetString()!);
                Assert.Equal(input.GetProperty("publicKeyHex").GetString(), ToHex(publicKey));
                var id = IdentityId.Derive(publicKey);
                Assert.Equal(expected.GetProperty("identityId").GetString(), id.ToString());
                Assert.True(id.MatchesKey(publicKey));
                break;
            case "parse":
                var text = input.GetProperty("identityId").GetString();
                Assert.Equal(expected.GetProperty("valid").GetBoolean(), IdentityId.TryParse(text, out _));
                break;
            case "key_acceptability":
                Assert.Equal(
                    expected.GetProperty("acceptable").GetBoolean(),
                    IdentitySigning.IsAcceptableKey(Hex(input.GetProperty("publicKeyHex").GetString()!)));
                break;
            case "distinct_from_shard_id":
                var key = Hex(input.GetProperty("publicKeyHex").GetString()!);
                Assert.Equal(expected.GetProperty("identityId").GetString(), IdentityId.Derive(key).ToString());
                Assert.Equal(expected.GetProperty("nodeShardId").GetString(), SelfCertifying.IdFor(key));
                Assert.NotEqual(IdentityId.Derive(key).ToString(), SelfCertifying.IdFor(key));
                Assert.False(expected.GetProperty("equal").GetBoolean());
                break;
            case "strict_verify":
                Assert.Equal(
                    expected.GetProperty("valid").GetBoolean(),
                    IdentitySigning.VerifyStrict(
                        Hex(input.GetProperty("publicKeyHex").GetString()!),
                        Hex(input.GetProperty("messageHex").GetString()!),
                        Hex(input.GetProperty("signatureHex").GetString()!)));
                break;
            default:
                throw new InvalidOperationException("unknown identity-id vector kind");
        }
    }

    private static string Str(JsonElement e, string name) => e.GetProperty(name).GetString()!;

    private static byte[]? PrevHash(JsonElement input) =>
        input.GetProperty("prevHashHex").ValueKind == JsonValueKind.Null
            ? null
            : LedgerEntry.ParseHash("prevHashHex", Str(input, "prevHashHex"));

    /// <summary>Runs one key-event file: every vector reproduces its bytes and signature, every replay
    /// signature fails for its input, and the retired text layout's signature fails over the new bytes.
    /// Returns the vector counts.</summary>
    private static (int Vectors, int Replays, int Legacy) RunKeyEventFile(string file, Func<JsonElement, byte[]> bytesOf)
    {
        using var doc = ConformanceTests.LoadVector(file);
        var root = doc.RootElement;
        var seed = Str(root, "signingKeySeedHex");
        var publicKey = PublicKeyOfSeed(seed);
        Assert.Equal(Str(root, "signingPublicKeyHex"), ToHex(publicKey));

        var vectors = root.GetProperty("vectors").EnumerateArray().ToList();
        foreach (var vector in vectors)
        {
            var bytes = bytesOf(vector.GetProperty("input"));
            var expected = vector.GetProperty("expected");
            var name = Str(vector, "name");
            Assert.True(Str(expected, "signingBytesHex") == ToHex(bytes), $"[{file}: {name}] bytes diverged");
            Assert.True(Str(expected, "signatureHex") == Sign(seed, bytes), $"[{file}: {name}] signature diverged");
            Assert.True(IdentitySigning.VerifyStrict(publicKey, bytes, Hex(Str(expected, "signatureHex"))), $"[{file}: {name}] does not verify");
        }
        var replays = root.GetProperty("replayVectors").EnumerateArray().ToList();
        foreach (var vector in replays)
        {
            var bytes = bytesOf(vector.GetProperty("input"));
            Assert.False(vector.GetProperty("expected").GetProperty("valid").GetBoolean());
            Assert.False(
                IdentitySigning.VerifyStrict(publicKey, bytes, Hex(Str(vector, "signatureHex"))),
                $"[{file}: {Str(vector, "name")}] a replayed signature verified");
        }
        var legacy = root.GetProperty("legacyLayoutVectors").EnumerateArray().ToList();
        foreach (var vector in legacy)
        {
            var signature = Hex(Str(vector, "signatureHex"));
            Assert.False(vector.GetProperty("expected").GetProperty("valid").GetBoolean());
            Assert.True(IdentitySigning.VerifyStrict(publicKey, Encoding.UTF8.GetBytes(Str(vector, "legacySigningBytesUtf8")), signature));
            Assert.False(IdentitySigning.VerifyStrict(publicKey, bytesOf(vector.GetProperty("input")), signature));
        }
        return (vectors.Count, replays.Count, legacy.Count);
    }

    [Fact]
    public void IdentityCreatedSigning_MatchesSharedVectors()
    {
        using var doc = ConformanceTests.LoadVector("identity-created-signing.json");
        var id = IdentityId.Parse(Str(doc.RootElement, "identityId"));
        var publicKey = Hex(Str(doc.RootElement, "signingPublicKeyHex"));
        Assert.True(id.MatchesKey(publicKey));
        var counts = RunKeyEventFile("identity-created-signing.json", input =>
            IdentitySigning.IdentityCreatedSigningBytes(
                Str(input, "networkId"), Str(input, "shardId"), Guid.Parse(Str(input, "ticketId")), id, publicKey, Str(input, "displayName")));
        Assert.Equal((6, 6, 1), counts);
    }

    [Fact]
    public void DeviceGrantApproval_MatchesSharedVectors()
    {
        using var doc = ConformanceTests.LoadVector("device-grant-approval.json");
        Assert.Equal(
            Str(doc.RootElement, "requestedPublicKeyHex"),
            ToHex(PublicKeyOfSeed(Str(doc.RootElement, "requestedKeySeedHex"))));
        var counts = RunKeyEventFile("device-grant-approval.json", input =>
            IdentitySigning.DeviceGrantApprovalSigningBytes(
                Guid.Parse(Str(input, "grantId")),
                IdentityId.Parse(Str(input, "identityId")),
                Guid.Parse(Str(input, "approverSigningKeyId")),
                Hex(Str(input, "requestedPublicKeyHex")),
                ulong.Parse(Str(input, "seq")),
                PrevHash(input)));
        Assert.Equal((4, 7, 1), counts);
    }

    [Fact]
    public void SigningKeyRevoked_MatchesSharedVectors()
    {
        var counts = RunKeyEventFile("signing-key-revoked.json", input =>
            IdentitySigning.SigningKeyRevokedSigningBytes(
                IdentityId.Parse(Str(input, "identityId")),
                Guid.Parse(Str(input, "signingKeyId")),
                Guid.Parse(Str(input, "revokedBySigningKeyId")),
                ulong.Parse(Str(input, "seq")),
                PrevHash(input)));
        Assert.Equal((6, 6, 1), counts);
    }
}
