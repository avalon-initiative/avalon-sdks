using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Avalon.Sdk;
using Xunit;

namespace Avalon.Sdk.Tests;

/// <summary>
/// Cross-SDK conformance suite — loads the shared test vectors under
/// <c>conformance/vectors/</c> (repo root) and asserts this SDK's real implementation produces
/// byte-for-byte identical output to the Rust/TypeScript SDKs for the same input. Offline, no
/// server needed — runs in the default <c>dotnet test</c> job alongside every other unit test
/// here.
///
/// Client-side wire-shape codegen already covers plain request/response shapes;
/// this suite exists for "smart client" behavior codegen can't produce — see
/// <c>conformance/vectors/SCHEMA.md</c> for the full rationale and the standing
/// "add a vector when you add smart-client behavior" requirement.
///
/// Where this SDK has no client-side implementation of a vector's behavior at all
/// (<c>notSupported.csharp</c> in the vector file), this class documents the gap with an
/// explicit, passing skip test rather than fabricating an implementation to satisfy its own
/// suite — see each such test's own body for exactly what's missing.
/// </summary>
public class ConformanceTests
{
    internal static string VectorsDir()
    {
        // bin/Debug/net10.0 (or similar) under AvalonSdk.Tests -> walk up to the repo root,
        // then into conformance/vectors. AppContext.BaseDirectory is the build output dir.
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "conformance", "vectors")))
        {
            dir = dir.Parent;
        }
        if (dir is null)
        {
            throw new InvalidOperationException(
                $"could not find conformance/vectors/ walking up from {AppContext.BaseDirectory}");
        }
        return Path.Combine(dir.FullName, "conformance", "vectors");
    }

    internal static JsonDocument LoadVector(string name)
    {
        var path = Path.Combine(VectorsDir(), name);
        return JsonDocument.Parse(File.ReadAllText(path));
    }

    private static bool SupportedIn(JsonElement root, string lang)
    {
        foreach (var v in root.GetProperty("supportedIn").EnumerateArray())
        {
            if (v.GetString() == lang) return true;
        }
        return false;
    }

    private static byte[] HexToBytes(string hex)
    {
        var bytes = new byte[hex.Length / 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }

    private static string ToLowerHex(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    // Invokes AvalonClient's private static CrossNodeLoginSigningBytes/SignWithIdentityKey via
    // reflection, so this test drives the exact production implementation
    // (bindings/csharp/AvalonSdk/CrossNodeLogin.cs) with the shared vectors' fixed inputs,
    // rather than reimplementing the signing-bytes format here — issue #725 is concurrently
    // migrating AvalonSdk/*.cs's own DTOs onto generated types, so this test avoids touching
    // that file directly and reaches its private members through reflection instead.
    private static byte[] InvokeCrossNodeLoginSigningBytes(
        IdentityId identityId, Guid signingKeyId, string destinationBaseUrl, string requestingContext,
        Guid nonce, DateTimeOffset issuedAt, DateTimeOffset expiresAt)
    {
        var method = typeof(AvalonClient).GetMethod(
            "CrossNodeLoginSigningBytes", BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException(
                "AvalonClient.CrossNodeLoginSigningBytes not found by reflection — did CrossNodeLogin.cs rename it?");
        var result = method.Invoke(null, new object[]
        {
            identityId, signingKeyId, destinationBaseUrl, requestingContext, nonce, issuedAt, expiresAt,
        });
        return (byte[])result!;
    }

    private static byte[] InvokeSignWithIdentityKey(byte[] signingKeySeed, byte[] message)
    {
        var method = typeof(AvalonClient).GetMethod(
            "SignWithIdentityKey", BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException(
                "AvalonClient.SignWithIdentityKey not found by reflection — did CrossNodeLogin.cs rename it?");
        var result = method.Invoke(null, new object[] { signingKeySeed, message });
        return (byte[])result!;
    }

    public static IEnumerable<object[]> CrossNodeLoginVectors()
    {
        using var doc = LoadVector("cross-node-login.json");
        var vectors = new List<object[]>();
        foreach (var v in doc.RootElement.GetProperty("vectors").EnumerateArray())
        {
            vectors.Add(new object[] { v.GetProperty("name").GetString()! });
        }
        return vectors;
    }

    [Fact]
    public void CrossNodeLogin_VectorFile_ListsCSharpAsSupported()
    {
        using var doc = LoadVector("cross-node-login.json");
        Assert.True(
            SupportedIn(doc.RootElement, "csharp"),
            "cross-node-login.json must list csharp in supportedIn — CrossNodeLogin.cs implements it");
    }

    [Theory]
    [MemberData(nameof(CrossNodeLoginVectors))]
    public void CrossNodeLogin_SigningMatchesSharedVector(string vectorName)
    {
        using var doc = LoadVector("cross-node-login.json");
        var root = doc.RootElement;
        var secretKey = HexToBytes(root.GetProperty("signingKeySeedHex").GetString()!);

        JsonElement? found = null;
        foreach (var v in root.GetProperty("vectors").EnumerateArray())
        {
            if (v.GetProperty("name").GetString() == vectorName) { found = v; break; }
        }
        Assert.True(found.HasValue, $"vector '{vectorName}' not found in cross-node-login.json");
        var vector = found!.Value;
        var input = vector.GetProperty("input");
        var expected = vector.GetProperty("expected");

        var identityId = IdentityId.Parse(input.GetProperty("identityId").GetString()!);
        var signingKeyId = Guid.Parse(input.GetProperty("signingKeyId").GetString()!);
        var destinationBaseUrl = input.GetProperty("destinationBaseUrl").GetString()!;
        var requestingContext = input.GetProperty("requestingContext").GetString()!;
        var nonce = Guid.Parse(input.GetProperty("nonce").GetString()!);
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(input.GetProperty("issuedAtUnixSeconds").GetInt64());
        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(input.GetProperty("expiresAtUnixSeconds").GetInt64());

        var bytes = InvokeCrossNodeLoginSigningBytes(
            identityId, signingKeyId, destinationBaseUrl, requestingContext, nonce, issuedAt, expiresAt);

        Assert.Equal(expected.GetProperty("signingBytesUtf8").GetString(), Encoding.UTF8.GetString(bytes));

        var signature = InvokeSignWithIdentityKey(secretKey, bytes);
        Assert.Equal(
            expected.GetProperty("signatureHex").GetString(),
            ToLowerHex(signature));
    }

    [Fact]
    public void SessionContinuation_IsAKnownCSharpSdkGap()
    {
        using var doc = LoadVector("session-continuation.json");
        var root = doc.RootElement;
        Assert.False(
            SupportedIn(root, "csharp"),
            "session-continuation.json now lists csharp in supportedIn, but this test only " +
            "documents the gap — implement real ContinuationToken minting in AvalonSdk and real " +
            "assertions here before flipping supportedIn");
        var gap = root.GetProperty("notSupported").GetProperty("csharp").GetString();
        Assert.False(string.IsNullOrWhiteSpace(gap), "notSupported.csharp must explain the gap");
    }

    [Fact]
    public void WebSocketInterestClaim_IsAKnownCSharpSdkGap()
    {
        using var doc = LoadVector("websocket-interest-claim.json");
        var root = doc.RootElement;
        Assert.False(
            SupportedIn(root, "csharp"),
            "websocket-interest-claim.json now lists csharp in supportedIn, but this test only " +
            "documents the gap — implement real AccountSession websocket subscribe + interest-claim " +
            "minting and real assertions here before flipping supportedIn");
        var gap = root.GetProperty("notSupported").GetProperty("csharp").GetString();
        Assert.False(string.IsNullOrWhiteSpace(gap), "notSupported.csharp must explain the gap");
    }

    [Fact]
    public void Bip39Mnemonic_IsAKnownCSharpSdkGap()
    {
        using var doc = LoadVector("bip39-mnemonic.json");
        var root = doc.RootElement;
        Assert.False(
            SupportedIn(root, "csharp"),
            "bip39-mnemonic.json now lists csharp in supportedIn, but this test only documents " +
            "the gap — add a real BIP39 dependency/derivation and real assertions here before " +
            "flipping supportedIn");
        var gap = root.GetProperty("notSupported").GetProperty("csharp").GetString();
        Assert.False(string.IsNullOrWhiteSpace(gap), "notSupported.csharp must explain the gap");
    }

    // Same reflection approach as CrossNodeLoginSigningBytes above, for Session's three
    // attestation signing-byte constructions (bindings/csharp/AvalonSdk/Achievements.cs).
    // Those are private because nothing outside the SDK should be hand-rolling a signature;
    // this suite still has to drive the real implementation rather than a copy of it.
    private static byte[] InvokeSessionSigningBytes(string name, params object[] args)
    {
        var method = typeof(Session).GetMethod(name, BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException(
                $"Session.{name} not found by reflection — did Achievements.cs rename it?");
        return (byte[])method.Invoke(null, args)!;
    }

    public static IEnumerable<object[]> AttestationSigningVectors()
    {
        using var doc = LoadVector("attestation-signing.json");
        var vectors = new List<object[]>();
        foreach (var v in doc.RootElement.GetProperty("vectors").EnumerateArray())
        {
            vectors.Add(new object[] { v.GetProperty("name").GetString()! });
        }
        return vectors;
    }

    private static byte[] AttestationBytes(JsonElement input)
    {
        var networkId = input.GetProperty("networkId").GetString()!;
        var claimKind = input.GetProperty("claimKind").GetString()!;
        var issuerRef = input.GetProperty("issuerRef").GetString()!;
        var keyId = Guid.Parse(input.GetProperty("signingKeyId").GetString()!);
        var operation = input.GetProperty("operation").GetString()!;

        switch (operation)
        {
            case "issue":
                return InvokeSessionSigningBytes(
                    "AttestationSigningBytes",
                    networkId, claimKind, issuerRef, keyId, IdentityId.Parse(input.GetProperty("subject").GetString()!),
                    input.GetProperty("achievement").GetString()!, input.GetProperty("issuedAtMicros").GetInt64());
            case "bulk_issue":
                var refs = new List<string>();
                foreach (var a in input.GetProperty("achievements").EnumerateArray())
                {
                    refs.Add(a.GetString()!);
                }
                return InvokeSessionSigningBytes(
                    "BulkAttestationSigningBytes",
                    networkId, claimKind, issuerRef, keyId, IdentityId.Parse(input.GetProperty("subject").GetString()!),
                    (IReadOnlyList<string>)refs, input.GetProperty("issuedAtMicros").GetInt64());
            case "revoke":
                return InvokeSessionSigningBytes(
                    "RevocationSigningBytes",
                    networkId, claimKind, issuerRef, keyId, Guid.Parse(input.GetProperty("attestationId").GetString()!),
                    input.GetProperty("reasonCode").GetString()!, input.GetProperty("reason").GetString()!);
            default:
                throw new InvalidOperationException($"unknown operation {operation}");
        }
    }

    [Fact]
    public void AttestationSigning_MatchesSharedVectors()
    {
        using var doc = LoadVector("attestation-signing.json");
        var root = doc.RootElement;
        var secretKey = HexToBytes(root.GetProperty("signingKeySeedHex").GetString()!);
        var publicKey = HexToBytes(root.GetProperty("signingPublicKeyHex").GetString()!);

        var count = 0;
        foreach (var vector in root.GetProperty("vectors").EnumerateArray())
        {
            var name = vector.GetProperty("name").GetString();
            var expected = vector.GetProperty("expected");
            var bytes = AttestationBytes(vector.GetProperty("input"));
            Assert.True(expected.GetProperty("signingBytesHex").GetString() == ToLowerHex(bytes), $"[{name}] signing bytes");
            Assert.True(
                expected.GetProperty("signatureHex").GetString() == ToLowerHex(InvokeSignWithIdentityKey(secretKey, bytes)),
                $"[{name}] signature");
            count++;
        }
        Assert.Equal(18, count);

        var replays = 0;
        foreach (var vector in root.GetProperty("replayVectors").EnumerateArray())
        {
            Assert.False(
                IdentitySigning.VerifyStrict(publicKey, AttestationBytes(vector.GetProperty("input")), HexToBytes(vector.GetProperty("signatureHex").GetString()!)),
                $"[{vector.GetProperty("name").GetString()}] a replayed signature verified");
            replays++;
        }
        Assert.Equal(21, replays);

        var legacy = 0;
        foreach (var vector in root.GetProperty("legacyLayoutVectors").EnumerateArray())
        {
            var signature = HexToBytes(vector.GetProperty("signatureHex").GetString()!);
            Assert.True(IdentitySigning.VerifyStrict(publicKey, Encoding.UTF8.GetBytes(vector.GetProperty("legacySigningBytesUtf8").GetString()!), signature));
            Assert.False(IdentitySigning.VerifyStrict(publicKey, AttestationBytes(vector.GetProperty("input")), signature));
            legacy++;
        }
        Assert.Equal(3, legacy);
    }

    private static long TreeSizeOf(JsonElement input)
    {
        var size = input.GetProperty("treeSize");
        return size.ValueKind == JsonValueKind.String ? long.Parse(size.GetString()!) : size.GetInt64();
    }

    [Fact]
    public void SignedTreeHead_SigningMatchesSharedVectors()
    {
        using var doc = LoadVector("signed-tree-head.json");
        var root = doc.RootElement;
        var publicKeyHex = root.GetProperty("signingPublicKeyHex").GetString()!;

        var count = 0;
        foreach (var vector in root.GetProperty("vectors").EnumerateArray())
        {
            var name = vector.GetProperty("name").GetString();
            var input = vector.GetProperty("input");
            var expected = vector.GetProperty("expected");
            var createdAt = DateTimeOffset.FromUnixTimeSeconds(input.GetProperty("createdAtUnixSeconds").GetInt64());
            Assert.Equal(createdAt, DateTimeOffset.Parse(input.GetProperty("createdAtRfc3339").GetString()!, System.Globalization.CultureInfo.InvariantCulture));

            var wire = new SignedTreeHeadWire
            {
                TreeSize = TreeSizeOf(input),
                RootHash = input.GetProperty("rootHashHex").GetString()!,
                NetworkId = input.GetProperty("networkId").GetString()!,
                SigningKeyId = input.GetProperty("signingKeyId").GetString()!,
                CreatedAt = createdAt,
                Signature = expected.GetProperty("signatureHex").GetString()!,
            };
            var bytes = AvalonClient.SthSigningMessage(wire);
            Assert.True(
                expected.GetProperty("signingBytesHex").GetString() == ToLowerHex(bytes),
                $"[{name}] signing bytes diverged from the shared vector");
            Assert.True(AvalonClient.VerifyTreeHeadHex(publicKeyHex, wire), $"[{name}] vector signature does not verify");
            count++;
        }
        Assert.Equal(10, count);
    }

    [Fact]
    public void SignedTreeHead_RejectedRootHashesProduceNoBytesAndNeverVerify()
    {
        using var doc = LoadVector("signed-tree-head.json");
        var root = doc.RootElement;
        var publicKeyHex = root.GetProperty("signingPublicKeyHex").GetString()!;
        var count = 0;
        foreach (var vector in root.GetProperty("rejectedVectors").EnumerateArray())
        {
            var input = vector.GetProperty("input");
            Assert.Equal("invalid_root_hash", vector.GetProperty("expected").GetProperty("error").GetString());
            var wire = new SignedTreeHeadWire
            {
                TreeSize = TreeSizeOf(input),
                RootHash = input.GetProperty("rootHashHex").GetString()!,
                NetworkId = input.GetProperty("networkId").GetString()!,
                SigningKeyId = input.GetProperty("signingKeyId").GetString()!,
                CreatedAt = DateTimeOffset.FromUnixTimeSeconds(input.GetProperty("createdAtUnixSeconds").GetInt64()),
                Signature = new string('0', 128),
            };
            Assert.Throws<ArgumentException>(() => AvalonClient.SthSigningMessage(wire));
            Assert.False(AvalonClient.VerifyTreeHeadHex(publicKeyHex, wire));
            count++;
        }
        Assert.Equal(5, count);
    }

    [Fact]
    public void SignedTreeHead_ReadRejectVectors_FailWithTheExpectedError()
    {
        using var doc = LoadVector("signed-tree-head.json");
        var count = 0;
        foreach (var vector in doc.RootElement.GetProperty("readRejectVectors").EnumerateArray())
        {
            StructuredConformanceTests.AssertReadRejects(vector);
            count++;
        }
        Assert.Equal(5, count);
    }

    // Vector files with no runner in this SDK yet, each with the reason it is skipped.
    private static readonly Dictionary<string, string> NoRunner = new()
    {
        ["identity-chain.json"] = "identity chain resolution is protocol-side only",
        ["name-binding.json"] = "no SDK verifies name binding claims yet; supportedIn is empty",
        ["node-request.json"] = "node-to-node route, not in OpenAPI; supportedIn is empty",
    };

    /// <summary>Every vector file is either referenced by a runner in this test project or listed in
    /// <c>NoRunner</c>, so a new protocol vector cannot be synced in and silently go untested.</summary>
    [Fact]
    public void EveryVectorFile_HasARunnerOrIsListedAsPending()
    {
        var sources = Directory.GetFiles(
            Path.Combine(Path.GetDirectoryName(Path.GetDirectoryName(VectorsDir())!)!, "languages", "csharp", "AvalonSdk.Tests"),
            "*.cs");
        // Quoted file names elsewhere in the test project count as a runner; this file's own list does not.
        var text = string.Concat(sources.Where(f => Path.GetFileName(f) != "ConformanceTests.cs").Select(File.ReadAllText));
        text += string.Join("\n", File.ReadAllLines(Path.Combine(Path.GetDirectoryName(sources[0])!, "ConformanceTests.cs"))
            .Where(l => l.Contains("LoadVector(")));
        foreach (var file in Directory.GetFiles(VectorsDir(), "*.json").Select(Path.GetFileName))
        {
            var name = file!;
            if (NoRunner.ContainsKey(name))
            {
                Assert.DoesNotContain($"\"{name}\"", text);
            }
            else
            {
                Assert.True(text.Contains($"\"{name}\""), $"{name} has no runner and is not listed in NoRunner");
            }
        }
    }
}
