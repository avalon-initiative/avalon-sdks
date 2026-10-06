using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Avalon.Sdk;
using Xunit;

namespace Avalon.Sdk.Tests;

/// <summary>Runs structured-signing-bytes.json, domain-tags.json, canonical-payload.json and
/// ledger-entry-hash.json against the SDK. Not gated on supportedIn: the vectors are the acceptance
/// criteria for these implementations.</summary>
public class StructuredConformanceTests
{
    internal static byte[] Hex(string hex)
    {
        Assert.Equal(0, hex.Length % 2);
        var bytes = new byte[hex.Length / 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }

    internal static string ToHex(byte[] bytes) => string.Concat(bytes.Select(b => b.ToString("x2", CultureInfo.InvariantCulture)));

    private static string Str(JsonElement e, string name) => e.GetProperty(name).GetString()!;

    private static string Utf8Of(JsonElement f) =>
        f.TryGetProperty("repeatUtf8", out var unit)
            ? string.Concat(Enumerable.Repeat(unit.GetString()!, f.GetProperty("count").GetInt32()))
            : Str(f, "utf8");

    private static byte[] BytesOf(JsonElement f) =>
        f.TryGetProperty("repeatByteHex", out var unit)
            ? Enumerable.Repeat(Hex(unit.GetString()!), f.GetProperty("count").GetInt32()).SelectMany(b => b).ToArray()
            : Hex(Str(f, "hex"));

    private static void Apply(SigningBytesBuilder b, JsonElement f)
    {
        switch (Str(f, "type"))
        {
            case "str": b.Str(Utf8Of(f)); break;
            case "bytes": b.Bytes(BytesOf(f)); break;
            case "key": b.Key(Hex(Str(f, "hex"))); break;
            case "hash": b.Hash(Hex(Str(f, "hex"))); break;
            case "fixed": b.Fixed(Hex(Str(f, "hex"))); break;
            case "uuid": b.Uuid(Guid.Parse(Str(f, "value"))); break;
            case "u8": b.U8(byte.Parse(Str(f, "value"), CultureInfo.InvariantCulture)); break;
            case "u16": b.U16(ushort.Parse(Str(f, "value"), CultureInfo.InvariantCulture)); break;
            case "u32": b.U32(uint.Parse(Str(f, "value"), CultureInfo.InvariantCulture)); break;
            case "u64": b.U64(ulong.Parse(Str(f, "value"), CultureInfo.InvariantCulture)); break;
            case "i64": b.I64(long.Parse(Str(f, "value"), CultureInfo.InvariantCulture)); break;
            default: throw new InvalidOperationException("unknown field type " + Str(f, "type"));
        }
    }

    private static void ReadBack(SigningBytesReader r, JsonElement f)
    {
        switch (Str(f, "type"))
        {
            case "str": Assert.Equal(Utf8Of(f), r.Str()); break;
            case "bytes": Assert.Equal(BytesOf(f), r.Bytes()); break;
            case "key":
            case "hash": Assert.Equal(Hex(Str(f, "hex")), r.Fixed(32)); break;
            case "fixed": Assert.Equal(Hex(Str(f, "hex")), r.Fixed(Hex(Str(f, "hex")).Length)); break;
            case "uuid": Assert.Equal(Guid.Parse(Str(f, "value")), r.Uuid()); break;
            case "u8": Assert.Equal(byte.Parse(Str(f, "value")), r.U8()); break;
            case "u16": Assert.Equal(ushort.Parse(Str(f, "value")), r.U16()); break;
            case "u32": Assert.Equal(uint.Parse(Str(f, "value")), r.U32()); break;
            case "u64": Assert.Equal(ulong.Parse(Str(f, "value")), r.U64()); break;
            case "i64": Assert.Equal(long.Parse(Str(f, "value")), r.I64()); break;
            default: throw new InvalidOperationException("unknown field type " + Str(f, "type"));
        }
    }

    private static void SkipRead(SigningBytesReader r, string type)
    {
        switch (type)
        {
            case "str": r.Str(); break;
            case "bytes": r.Bytes(); break;
            case "key":
            case "hash": r.Fixed(32); break;
            case "fixed": r.Fixed(4); break;
            case "uuid": r.Uuid(); break;
            case "u8": r.U8(); break;
            case "u16": r.U16(); break;
            case "u32": r.U32(); break;
            case "u64": r.U64(); break;
            case "i64": r.I64(); break;
            default: throw new InvalidOperationException("unknown read type " + type);
        }
    }

    private static string Snake(string error) => Regex.Replace(error, "(?<!^)([A-Z])", "_$1").ToLowerInvariant();

    [Fact]
    public void StructuredSigningBytes_BuildVectors_MatchAndReadBack()
    {
        using var doc = ConformanceTests.LoadVector("structured-signing-bytes.json");
        var count = 0;
        foreach (var vector in doc.RootElement.GetProperty("vectors").EnumerateArray())
        {
            var name = Str(vector, "name");
            var input = vector.GetProperty("input");
            var tag = new DomainTag(Str(input, "tag"));
            var version = ushort.Parse(input.GetProperty("version").GetRawText(), CultureInfo.InvariantCulture);
            var builder = new SigningBytesBuilder(tag, version);
            var fields = input.GetProperty("fields").EnumerateArray().ToList();
            foreach (var f in fields)
            {
                Apply(builder, f);
            }
            var bytes = builder.Finish();
            var expected = vector.GetProperty("expected");
            if (expected.TryGetProperty("signingBytesHex", out var hex))
            {
                Assert.True(hex.GetString() == ToHex(bytes), $"[{name}] bytes diverged");
            }
            else
            {
                Assert.Equal(expected.GetProperty("signingBytesLength").GetInt32(), bytes.Length);
                using var sha = SHA256.Create();
                Assert.Equal(Str(expected, "signingBytesSha256Hex"), ToHex(sha.ComputeHash(bytes)));
            }
            var reader = new SigningBytesReader(tag, bytes);
            Assert.Equal(version, reader.Version);
            foreach (var f in fields)
            {
                ReadBack(reader, f);
            }
            reader.Finish();
            count++;
        }
        Assert.Equal(23, count);
    }

    [Fact]
    public void StructuredSigningBytes_RejectVectors_FailWithTheExpectedError()
    {
        using var doc = ConformanceTests.LoadVector("structured-signing-bytes.json");
        var count = 0;
        foreach (var vector in doc.RootElement.GetProperty("rejectVectors").EnumerateArray())
        {
            var name = Str(vector, "name");
            var input = vector.GetProperty("input");
            var tag = new DomainTag(Str(input, "tag"));
            var message = Hex(Str(input, "messageHex"));
            var types = input.GetProperty("read").EnumerateArray().Select(t => t.GetString()!).ToList();
            var ex = Assert.Throws<SigningBytesException>(() =>
            {
                var reader = new SigningBytesReader(tag, message);
                foreach (var t in types)
                {
                    SkipRead(reader, t);
                }
                reader.Finish();
            });
            Assert.True(Str(vector.GetProperty("expected"), "error") == Snake(ex.Error.ToString()), $"[{name}] got {ex.Error}");
            count++;
        }
        Assert.Equal(12, count);
    }

    [Fact]
    public void DomainTags_RegistryMatchesTheSharedList()
    {
        using var doc = ConformanceTests.LoadVector("domain-tags.json");
        var expected = doc.RootElement.GetProperty("tags").EnumerateArray()
            .ToDictionary(t => Str(t, "kind"), t => Str(t, "tag"));
        var actual = typeof(DomainTags).GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(f => f.FieldType == typeof(DomainTag))
            .ToDictionary(f => Snake(f.Name), f => ((DomainTag)f.GetValue(null)!).Value);
        Assert.Equal(expected.OrderBy(p => p.Key).ToList(), actual.OrderBy(p => p.Key).ToList());
        Assert.Equal(expected.Count, DomainTags.All.Count);
        Assert.Equal(expected.Values.OrderBy(v => v, StringComparer.Ordinal), DomainTags.All.Select(t => t.Value).OrderBy(v => v, StringComparer.Ordinal));
    }

    [Fact]
    public void DomainTags_ArePrefixFree()
    {
        for (var i = 0; i < DomainTags.All.Count; i++)
        {
            for (var j = i + 1; j < DomainTags.All.Count; j++)
            {
                var a = DomainTags.All[i].Value;
                var b = DomainTags.All[j].Value;
                Assert.False(a.StartsWith(b, StringComparison.Ordinal) || b.StartsWith(a, StringComparison.Ordinal), $"{a} and {b} share a prefix");
            }
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData("Avalon.x")]
    [InlineData("avalon-x")]
    [InlineData("avalon.é")]
    public void DomainTag_RejectsBytesOutsideTheAlphabet(string tag) => Assert.Throws<ArgumentException>(() => new DomainTag(tag));

    [Fact]
    public void SigningBytes_RoundTripsEveryFieldType()
    {
        var id = Guid.Parse("00112233-4455-6677-8899-aabbccddeeff");
        var msg = new SigningBytesBuilder(DomainTags.Conformance, 3)
            .Str("a:b,c\0d").Bytes(new byte[0]).Key(new byte[32]).Uuid(id).U8(1).U16(2).U32(3).U64(ulong.MaxValue).I64(long.MinValue).Finish();
        var r = new SigningBytesReader(DomainTags.Conformance, msg);
        Assert.Equal(3, r.Version);
        Assert.Equal("a:b,c\0d", r.Str());
        Assert.Empty(r.Bytes());
        Assert.Equal(new byte[32], r.Fixed(32));
        Assert.Equal(id, r.Uuid());
        Assert.Equal(1, r.U8());
        Assert.Equal(2, r.U16());
        Assert.Equal(3u, r.U32());
        Assert.Equal(ulong.MaxValue, r.U64());
        Assert.Equal(long.MinValue, r.I64());
        r.Finish();
        // UUIDs are written in RFC 4122 order.
        Assert.Equal("00112233445566778899aabbccddeeff", ToHex(new SigningBytesBuilder(DomainTags.Conformance, 0).Uuid(id).Finish().Skip(DomainTags.Conformance.Value.Length + 2).ToArray()));
    }

    [Fact]
    public void SigningBytesBuilder_RejectsWrongWidthKeysAndHashes()
    {
        var b = new SigningBytesBuilder(DomainTags.Conformance, 1);
        Assert.Throws<ArgumentException>(() => b.Key(new byte[31]));
        Assert.Throws<ArgumentException>(() => b.Hash(new byte[33]));
        Assert.Throws<ArgumentException>(() => b.Str("\ud800"));
    }

    [Fact]
    public void CanonicalPayload_Vectors_MatchExactly()
    {
        using var doc = ConformanceTests.LoadVector("canonical-payload.json");
        var count = 0;
        foreach (var vector in doc.RootElement.GetProperty("vectors").EnumerateArray())
        {
            var name = Str(vector, "name");
            var json = Str(vector.GetProperty("input"), "jsonUtf8");
            var expected = vector.GetProperty("expected");
            if (expected.TryGetProperty("canonicalUtf8", out var canonical))
            {
                Assert.True(canonical.GetString() == CanonicalPayload.Canonicalize(json), $"[{name}] output diverged");
            }
            else
            {
                var ex = Assert.Throws<CanonicalPayloadException>(() => CanonicalPayload.Canonicalize(json));
                Assert.True(Str(expected, "error") == Snake(ex.Error.ToString()), $"[{name}] got {ex.Error}");
            }
            count++;
        }
        Assert.Equal(100, count);
    }

    [Fact]
    public void CanonicalPayload_DepthIsCappedAtTheProtocolLimit()
    {
        string Nest(int levels) => new string('[', levels) + new string(']', levels);
        Assert.Equal(Nest(129), CanonicalPayload.Canonicalize(Nest(129)));
        Assert.Equal(CanonicalPayloadError.TooDeep, Assert.Throws<CanonicalPayloadException>(() => CanonicalPayload.Canonicalize(Nest(130))).Error);
        var obj = string.Concat(Enumerable.Repeat("{\"a\":", 130)) + "1" + new string('}', 130);
        Assert.Equal(CanonicalPayloadError.TooDeep, Assert.Throws<CanonicalPayloadException>(() => CanonicalPayload.Canonicalize(obj)).Error);
    }

    [Theory]
    [InlineData("[1e-7]", "[1e-7]")]
    [InlineData("[1.5e-300]", "[1.5e-300]")]
    [InlineData("[0.000001]", "[0.000001]")]
    [InlineData("[5e-324]", "[5e-324]")]
    [InlineData("[1.5e300]", null)]
    [InlineData("[1.79769313486231e308]", null)]
    [InlineData("[123456789012345.5]", null)]
    [InlineData("[3e-324]", null)]
    [InlineData("[1e-400]", null)]
    [InlineData("[0.5e1]", null)]
    [InlineData("[1e-99999999999999999999]", null)]
    [InlineData("[0.0000001]", null)]
    [InlineData("[1.5e+300", null)]
    public void CanonicalPayload_NumberEdges(string json, string? expected)
    {
        if (expected == null)
        {
            Assert.Throws<CanonicalPayloadException>(() => CanonicalPayload.Canonicalize(json));
        }
        else
        {
            Assert.Equal(expected, CanonicalPayload.Canonicalize(json));
        }
    }

    [Fact]
    public void CanonicalPayload_AJsonElementIsJudgedByItsWrittenText()
    {
        using var ok = JsonDocument.Parse("{\"b\":1,\"a\":[true,null]}");
        Assert.Equal("{\"a\":[true,null],\"b\":1}", CanonicalPayload.Canonicalize(ok.RootElement));
        using var dup = JsonDocument.Parse("{\"a\":1,\"a\":2}");
        Assert.Equal(CanonicalPayloadError.DuplicateKey, Assert.Throws<CanonicalPayloadException>(() => CanonicalPayload.Canonicalize(dup.RootElement)).Error);
    }

    [Fact]
    public void CanonicalPayload_NulIsRejectedInStringsAndKeys_ButARawNulIsMalformed()
    {
        foreach (var json in new[] { "[\"a\\u0000b\"]", "{\"a\\u0000\":1}", "{\"a\":{\"\\u0000\":1}}", "\"\\u0000\"" })
        {
            Assert.Equal(CanonicalPayloadError.NulCharacter, Assert.Throws<CanonicalPayloadException>(() => CanonicalPayload.Canonicalize(json)).Error);
        }
        using var el = JsonDocument.Parse("{\"k\":[\"x\\u0000\"]}");
        Assert.Equal(CanonicalPayloadError.NulCharacter, Assert.Throws<CanonicalPayloadException>(() => CanonicalPayload.Canonicalize(el.RootElement)).Error);
        Assert.Equal(CanonicalPayloadError.Malformed, Assert.Throws<CanonicalPayloadException>(() => CanonicalPayload.Canonicalize("[\"a\0b\"]")).Error);
        Assert.Equal(CanonicalPayloadError.NulCharacter, Assert.Throws<CanonicalPayloadException>(() => CanonicalPayload.Canonicalize("[\"\\u0000\", 1.0]")).Error);
    }

    private static LedgerEntryHashInput EntryInput(JsonElement input, out string? payloadJson)
    {
        payloadJson = input.TryGetProperty("payloadJsonUtf8", out var p) ? p.GetString() : null;
        var seq = BigIntegerOrThrow(Str(input, "seq"));
        var entry = new LedgerEntryHashInput
        {
            NetworkId = Str(input, "networkId"),
            ShardId = Str(input, "shardId"),
            Seq = seq,
            PrevHash = LedgerEntry.ParseHash("prev_hash", Str(input, "prevHashHex")),
            EventId = Guid.Parse(Str(input, "eventId")),
            Kind = Str(input, "kind"),
            Issuer = Str(input, "issuer"),
            Subject = Str(input, "subject"),
            Version = LedgerEntry.LayoutVersion(input.GetProperty("version").GetInt64()),
            TimestampMicros = long.Parse(Str(input, "timestampUnixMicros"), CultureInfo.InvariantCulture),
        };
        entry.PayloadHash = payloadJson != null
            ? LedgerEntry.PayloadHash(payloadJson)
            : LedgerEntry.ParseHash("payload_hash", Str(input, "payloadHashHex"));
        return entry;
    }

    private static ulong BigIntegerOrThrow(string seq)
    {
        if (!System.Numerics.BigInteger.TryParse(seq, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var n)
            || n < 0 || n > ulong.MaxValue)
        {
            throw new LedgerEntryException(LedgerEntryError.OutOfRange, "seq");
        }
        return (ulong)n;
    }

    [Fact]
    public void LedgerEntryHash_Vectors_MatchExactly()
    {
        using var doc = ConformanceTests.LoadVector("ledger-entry-hash.json");
        var count = 0;
        foreach (var vector in doc.RootElement.GetProperty("vectors").EnumerateArray())
        {
            var name = Str(vector, "name");
            var input = vector.GetProperty("input");
            var expected = vector.GetProperty("expected");
            var entry = EntryInput(input, out var payloadJson);
            var time = DateTimeOffset.Parse(Str(input, "eventTimestampRfc3339"), CultureInfo.InvariantCulture);
            Assert.True(entry.TimestampMicros == LedgerEntry.TimestampMicros(time), $"[{name}] timestamp micros");
            Assert.Equal(entry.TimestampMicros, LedgerEntry.TimestampMicros(LedgerEntry.FloorToMicros(time)));
            if (payloadJson != null)
            {
                Assert.Equal(Str(expected, "payloadCanonicalUtf8"), CanonicalPayload.Canonicalize(payloadJson));
                Assert.Equal(Str(expected, "payloadHashHex"), ToHex(entry.PayloadHash));
            }
            var bytes = LedgerEntry.SigningBytes(entry);
            Assert.True(Str(expected, "signingBytesHex") == ToHex(bytes), $"[{name}] signing bytes");
            Assert.True(Str(expected, "entryHashHex") == ToHex(LedgerEntry.Hash(entry)), $"[{name}] entry hash");
            count++;
        }
        Assert.Equal(26, count);
    }

    [Fact]
    public void LedgerEntryHash_RejectVectors_FailWithTheExpectedError()
    {
        using var doc = ConformanceTests.LoadVector("ledger-entry-hash.json");
        var count = 0;
        foreach (var vector in doc.RootElement.GetProperty("rejectVectors").EnumerateArray())
        {
            var name = Str(vector, "name");
            var ex = Assert.Throws<LedgerEntryException>(() => LedgerEntry.Hash(EntryInput(vector.GetProperty("input"), out _)));
            Assert.True(Str(vector.GetProperty("expected"), "error") == Snake(ex.Error.ToString()), $"[{name}] got {ex.Error} on {ex.Field}");
            count++;
        }
        Assert.Equal(8, count);
    }

    [Fact]
    public void FloorToMicros_FloorsTowardNegativeInfinity()
    {
        var before = new DateTimeOffset(1969, 12, 31, 23, 59, 59, TimeSpan.Zero).AddTicks(9999995);
        Assert.Equal(-1, LedgerEntry.TimestampMicros(before));
        Assert.Equal(before.AddTicks(-5), LedgerEntry.FloorToMicros(before));
        var after = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero).AddTicks(1234567);
        Assert.Equal(1767323045123456, LedgerEntry.TimestampMicros(after));
        Assert.Equal(after.AddTicks(-7), LedgerEntry.FloorToMicros(after));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("0000000000000000000000000000000000000000000000000000000000000G00")]
    [InlineData("AB00000000000000000000000000000000000000000000000000000000000000")]
    public void ParseHash_RejectsAnythingButSixtyFourLowercaseHexCharacters(string? text) =>
        Assert.Equal(LedgerEntryError.InvalidHash, Assert.Throws<LedgerEntryException>(() => LedgerEntry.ParseHash("h", text!)).Error);
}
