// The ledger entry hash: the digest of the structured layout tag avalon.ledger.entry (envelope header, network id,
// shard id, seq, event id, kind, issuer, subject, event version, event time in unix microseconds, hash algo, hashes).
// Mirrors crates/protocol/src/ledger_entry.rs; conformance/vectors/ledger-entry-hash.json is the shared arbiter.

using System;
using System.Security.Cryptography;

namespace Avalon.Sdk
{
    /// <summary>Why an entry hash could not be computed.</summary>
    public enum LedgerEntryError
    {
        /// <summary>A hash is not 32 bytes of lowercase hex.</summary>
        InvalidHash,
        /// <summary>A value does not fit the entry layout.</summary>
        OutOfRange,
    }

    /// <summary>An entry hash input the layout cannot carry.</summary>
    public sealed class LedgerEntryException : Exception
    {
        public LedgerEntryException(LedgerEntryError error, string field)
            : base(error == LedgerEntryError.InvalidHash
                ? field + " is not a 32-byte lowercase hex hash"
                : field + " is out of range for the entry layout")
        {
            Error = error;
            Field = field;
        }

        public LedgerEntryError Error { get; }

        public string Field { get; }
    }

    /// <summary>Every field the entry hash covers.</summary>
    public sealed class LedgerEntryHashInput
    {
        public string NetworkId { get; set; } = "";
        public string ShardId { get; set; } = "";
        public ulong Seq { get; set; }

        /// <summary>The previous entry's hash, 32 raw bytes.</summary>
        public byte[] PrevHash { get; set; } = new byte[32];

        public Guid EventId { get; set; }
        public string Kind { get; set; } = "";
        public string Issuer { get; set; } = "";
        public string Subject { get; set; } = "";

        /// <summary>SHA-256 of the canonical payload, 32 raw bytes (see <see cref="LedgerEntry.PayloadHash"/>).</summary>
        public byte[] PayloadHash { get; set; } = new byte[32];

        /// <summary>Unix microseconds (see <see cref="LedgerEntry.TimestampMicros"/>).</summary>
        public long TimestampMicros { get; set; }

        /// <summary>The payload schema version of <see cref="Kind"/>, not the layout version.</summary>
        public uint EventVersion { get; set; }

        /// <summary>Layout version, rules version, hash algorithm and extensions as stored with the entry.</summary>
        public Envelope Envelope { get; set; } = Avalon.Sdk.Envelope.Current(DomainTags.LedgerEntry);
    }

    public static class LedgerEntry
    {
        private const long UnixEpochTicks = 621355968000000000L;

        /// <summary>SHA-256 of the canonical payload bytes: what an entry commits to in place of the payload.</summary>
        public static byte[] PayloadHash(string payloadJson)
        {
            using (var sha = SHA256.Create())
            {
                return sha.ComputeHash(CanonicalPayload.CanonicalizeToBytes(payloadJson));
            }
        }

        /// <summary>Unix microseconds, truncated toward negative infinity.</summary>
        public static long TimestampMicros(DateTimeOffset time)
        {
            var ticks = time.UtcTicks - UnixEpochTicks;
            var micros = ticks / 10;
            return ticks % 10 < 0 ? micros - 1 : micros;
        }

        /// <summary>The instant floored to whole microseconds: the value that is both hashed and stored.</summary>
        public static DateTimeOffset FloorToMicros(DateTimeOffset time) =>
            new DateTimeOffset(UnixEpochTicks + TimestampMicros(time) * 10, TimeSpan.Zero);

        /// <summary>An event version as the layout's u32; anything outside 0..2^32-1 is out of range.</summary>
        public static uint EventVersion(long version)
        {
            if (version < 0 || version > uint.MaxValue)
            {
                throw new LedgerEntryException(LedgerEntryError.OutOfRange, "event_version");
            }
            return (uint)version;
        }

        /// <summary>Parses exactly 64 lowercase hex characters into 32 bytes.</summary>
        public static byte[] ParseHash(string name, string text)
        {
            if (text == null || text.Length != 64)
            {
                throw new LedgerEntryException(LedgerEntryError.InvalidHash, name);
            }
            var bytes = new byte[32];
            for (var i = 0; i < 32; i++)
            {
                var hi = HexValue(text[i * 2]);
                var lo = HexValue(text[i * 2 + 1]);
                if (hi < 0 || lo < 0)
                {
                    throw new LedgerEntryException(LedgerEntryError.InvalidHash, name);
                }
                bytes[i] = (byte)((hi << 4) | lo);
            }
            return bytes;
        }

        /// <summary>Lowercase hex of <paramref name="bytes"/>.</summary>
        internal static string ToHex(byte[] bytes)
        {
            var chars = new char[bytes.Length * 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                chars[i * 2] = "0123456789abcdef"[bytes[i] >> 4];
                chars[i * 2 + 1] = "0123456789abcdef"[bytes[i] & 15];
            }
            return new string(chars);
        }

        private static int HexValue(char c) =>
            c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;

        /// <summary>The exact bytes the entry hash is the digest of.</summary>
        public static byte[] SigningBytes(LedgerEntryHashInput input) =>
            SigningBytesBuilder.WithEnvelope(DomainTags.LedgerEntry, input.Envelope)
                .Str(input.NetworkId)
                .Str(input.ShardId)
                .U64(input.Seq)
                .Uuid(input.EventId)
                .Str(input.Kind)
                .Str(input.Issuer)
                .Str(input.Subject)
                .U32(input.EventVersion)
                .I64(input.TimestampMicros)
                .HashAlgo(input.Envelope.HashAlgo)
                .Hash(input.PrevHash)
                .Hash(input.PayloadHash)
                .Finish();

        /// <summary>The entry hash: the envelope's hash algorithm over <see cref="SigningBytes"/>.</summary>
        public static byte[] Hash(LedgerEntryHashInput input) =>
            Avalon.Sdk.SigningBytes.Digest(input.Envelope.HashAlgo, SigningBytes(input));
    }
}
