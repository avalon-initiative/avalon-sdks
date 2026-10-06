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

    private static bool Supported(JsonElement root) =>
        root.GetProperty("supportedIn").EnumerateArray().Any(v => v.GetString() == "csharp");

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
        Assert.True(Supported(doc.RootElement));
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

    private static byte[] CreatedBytes(JsonElement input, IdentityId id, byte[] publicKey) =>
        IdentitySigning.IdentityCreatedSigningBytesV2(
            input.GetProperty("networkId").GetString()!,
            input.GetProperty("shardId").GetString()!,
            Guid.Parse(input.GetProperty("ticketId").GetString()!),
            id,
            publicKey,
            input.GetProperty("displayName").GetString()!);

    [Fact(Skip = "pending v3 structured signing in the C# SDK (avalon-sdks #101); the vector is protocol-crate only until then")]
    public void IdentityCreatedSigning_MatchesSharedVectors()
    {
        using var doc = ConformanceTests.LoadVector("identity-created-signing.json");
        var root = doc.RootElement;
        Assert.True(Supported(root));
        var seed = root.GetProperty("signingKeySeedHex").GetString()!;
        var publicKey = PublicKeyOfSeed(seed);
        Assert.Equal(root.GetProperty("signingPublicKeyHex").GetString(), ToHex(publicKey));
        var id = IdentityId.Parse(root.GetProperty("identityId").GetString()!);
        Assert.True(id.MatchesKey(publicKey));

        foreach (var vector in root.GetProperty("vectors").EnumerateArray())
        {
            var bytes = CreatedBytes(vector.GetProperty("input"), id, publicKey);
            var expected = vector.GetProperty("expected");
            Assert.Equal(expected.GetProperty("signingBytesHex").GetString(), ToHex(bytes));
            Assert.Equal(expected.GetProperty("signingBytesUtf8").GetString(), Encoding.UTF8.GetString(bytes));
            Assert.Equal(expected.GetProperty("signatureHex").GetString(), Sign(seed, bytes));
            Assert.True(IdentitySigning.VerifyStrict(publicKey, bytes, Hex(expected.GetProperty("signatureHex").GetString()!)));
        }
        foreach (var vector in root.GetProperty("replayVectors").EnumerateArray())
        {
            var input = vector.GetProperty("input");
            var bytes = CreatedBytes(input, id, publicKey);
            Assert.Equal(
                vector.GetProperty("expected").GetProperty("valid").GetBoolean(),
                IdentitySigning.VerifyStrict(publicKey, bytes, Hex(input.GetProperty("signatureHex").GetString()!)));
        }
        foreach (var vector in root.GetProperty("domainSeparationVectors").EnumerateArray())
        {
            var input = vector.GetProperty("input");
            var expected = vector.GetProperty("expected");
            var v2 = CreatedBytes(input, IdentityId.Parse(input.GetProperty("identityId").GetString()!), publicKey);
            Assert.Equal(expected.GetProperty("v2SigningBytesHex").GetString(), ToHex(v2));
            Assert.NotEqual(expected.GetProperty("v1SigningBytesUtf8").GetString(), Encoding.UTF8.GetString(v2));
            Assert.False(expected.GetProperty("equal").GetBoolean());
        }
    }

    [Fact(Skip = "pending v3 structured signing in the C# SDK (avalon-sdks #101); the vector is protocol-crate only until then")]
    public void DeviceGrantApproval_MatchesSharedVectors()
    {
        using var doc = ConformanceTests.LoadVector("device-grant-approval.json");
        var root = doc.RootElement;
        Assert.True(Supported(root));
        var seed = root.GetProperty("signingKeySeedHex").GetString()!;
        Assert.Equal(root.GetProperty("signingPublicKeyHex").GetString(), ToHex(PublicKeyOfSeed(seed)));
        Assert.Equal(
            root.GetProperty("requestedPublicKeyHex").GetString(),
            ToHex(PublicKeyOfSeed(root.GetProperty("requestedKeySeedHex").GetString()!)));
        foreach (var vector in root.GetProperty("vectors").EnumerateArray())
        {
            var input = vector.GetProperty("input");
            var bytes = IdentitySigning.DeviceGrantApprovalSigningBytesV2(
                Guid.Parse(input.GetProperty("grantId").GetString()!),
                IdentityId.Parse(input.GetProperty("identityId").GetString()!),
                Hex(input.GetProperty("requestedPublicKeyHex").GetString()!));
            var expected = vector.GetProperty("expected");
            Assert.Equal(expected.GetProperty("signingBytesHex").GetString(), ToHex(bytes));
            Assert.Equal(expected.GetProperty("signingBytesUtf8").GetString(), Encoding.UTF8.GetString(bytes));
            Assert.Equal(expected.GetProperty("signatureHex").GetString(), Sign(seed, bytes));
        }
    }

    [Fact(Skip = "pending v3 structured signing in the C# SDK (avalon-sdks #101); the vector is protocol-crate only until then")]
    public void SigningKeyRevoked_MatchesSharedVectors()
    {
        using var doc = ConformanceTests.LoadVector("signing-key-revoked.json");
        var root = doc.RootElement;
        Assert.True(Supported(root));
        var seed = root.GetProperty("signingKeySeedHex").GetString()!;
        Assert.Equal(root.GetProperty("signingPublicKeyHex").GetString(), ToHex(PublicKeyOfSeed(seed)));
        foreach (var vector in root.GetProperty("vectors").EnumerateArray())
        {
            var input = vector.GetProperty("input");
            var bytes = IdentitySigning.SigningKeyRevokedSigningBytesV2(
                IdentityId.Parse(input.GetProperty("identityId").GetString()!),
                Guid.Parse(input.GetProperty("signingKeyId").GetString()!),
                Guid.Parse(input.GetProperty("revokedBySigningKeyId").GetString()!));
            var expected = vector.GetProperty("expected");
            Assert.Equal(expected.GetProperty("signingBytesHex").GetString(), ToHex(bytes));
            Assert.Equal(expected.GetProperty("signingBytesUtf8").GetString(), Encoding.UTF8.GetString(bytes));
            Assert.Equal(expected.GetProperty("signatureHex").GetString(), Sign(seed, bytes));
        }
    }
}
