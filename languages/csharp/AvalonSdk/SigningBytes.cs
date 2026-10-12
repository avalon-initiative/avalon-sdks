// Structured signing bytes: tag | u16 BE version | fields in a fixed order (u32 BE length-prefixed strings
// and bytes, raw keys/hashes/UUIDs, fixed-width big-endian integers). Mirrors crates/protocol/src/signing_bytes.rs;
// conformance/vectors/structured-signing-bytes.json and domain-tags.json are the shared arbiters.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Avalon.Sdk
{
    /// <summary>Why a structured message could not be built or read.</summary>
    public enum SigningBytesError
    {
        /// <summary>A field is longer than a u32 length prefix can carry.</summary>
        FieldTooLong,
        /// <summary>The message does not start with the expected domain tag.</summary>
        TagMismatch,
        /// <summary>The message ends before the field does.</summary>
        Truncated,
        /// <summary>A string field is not valid UTF-8.</summary>
        InvalidUtf8,
        /// <summary>Bytes remain after the extensions region.</summary>
        TrailingBytes,
        /// <summary>The message needs a layout, rules version, algorithm or extension this SDK lacks; nothing is verified.</summary>
        NeedsNewerVersion,
        /// <summary>A layout or rules version below the supported range.</summary>
        UnsupportedVersion,
        /// <summary>Extensions are not in ascending type order.</summary>
        ExtensionsUnsorted,
        /// <summary>Two extensions share a type.</summary>
        ExtensionDuplicate,
        /// <summary>An extension sets a reserved flag bit.</summary>
        ExtensionReservedFlags,
        /// <summary>The extension entries exceed the cap of the message's rules version.</summary>
        ExtensionsTooLarge,
    }

    /// <summary>Which part of a message needs a newer version.</summary>
    public enum VersionKind
    {
        Layout,
        Rules,
        HashAlgo,
        /// <summary>An unknown key or signature algorithm byte.</summary>
        SigAlgo,
        /// <summary>A critical extension the tag does not understand; the value is its type.</summary>
        CriticalExtension,
    }

    /// <summary>A malformed structured message; <see cref="Error"/> is the stable reason.</summary>
    public sealed class SigningBytesException : Exception
    {
        public SigningBytesException(SigningBytesError error)
            : this(error, null, 0)
        {
        }

        public SigningBytesException(SigningBytesError error, VersionKind? kind, uint value)
            : base(error + (kind == null ? "" : " " + kind + " " + value))
        {
            Error = error;
            Kind = kind;
            Value = value;
        }

        public SigningBytesError Error { get; }

        /// <summary>The version part behind <see cref="SigningBytesError.NeedsNewerVersion"/> or <see cref="SigningBytesError.UnsupportedVersion"/>.</summary>
        public VersionKind? Kind { get; }

        /// <summary>The required version, algorithm id or extension type, or the unsupported value.</summary>
        public uint Value { get; }
    }

    /// <summary>The hash algorithm named by a layout's <c>hash_algo</c> byte.</summary>
    public enum HashAlgo : byte
    {
        Sha256 = 1,
    }

    /// <summary>One extension entry; reserved flag bits are not representable.</summary>
    public sealed class SigningExtension
    {
        public SigningExtension(ushort type, bool critical, byte[] value)
        {
            Type = type;
            Critical = critical;
            Value = value ?? throw new ArgumentNullException(nameof(value));
        }

        public ushort Type { get; }

        public bool Critical { get; }

        public byte[] Value { get; }
    }

    /// <summary>The header values of a stored or received message: layout and rules version, hash algorithm and extensions.</summary>
    public sealed class Envelope
    {
        public Envelope(ushort layoutVersion, uint rulesVersion, HashAlgo hashAlgo, IReadOnlyList<SigningExtension> extensions)
        {
            LayoutVersion = layoutVersion;
            RulesVersion = rulesVersion;
            HashAlgo = hashAlgo;
            Extensions = extensions;
        }

        public ushort LayoutVersion { get; }

        public uint RulesVersion { get; }

        public HashAlgo HashAlgo { get; }

        public IReadOnlyList<SigningExtension> Extensions { get; }

        /// <summary>What this SDK authors for <paramref name="tag"/>: its newest layout, the current rules version, SHA-256, no extensions.</summary>
        public static Envelope Current(DomainTag tag) =>
            new Envelope(SigningBytes.NewestLayout(tag), SigningBytes.RulesVersion, HashAlgo.Sha256, new SigningExtension[0]);

        /// <summary>Rebuilds from stored or wire values, checking each against this SDK's ranges in the protocol's order:
        /// layout, rules, extensions, then the hash algorithm byte.</summary>
        public static Envelope FromParts(
            DomainTag tag, long layoutVersion, long rulesVersion, int hashAlgo, IReadOnlyList<SigningExtension> extensions)
        {
            SigningBytes.CheckLayout(tag, layoutVersion);
            SigningBytes.CheckRules(rulesVersion);
            SigningBytes.ValidateExtensions(extensions, (uint)rulesVersion);
            SigningBytes.RequireUnderstood(extensions);
            if (hashAlgo != (int)HashAlgo.Sha256)
            {
                throw new SigningBytesException(SigningBytesError.NeedsNewerVersion, VersionKind.HashAlgo, (uint)hashAlgo);
            }
            return new Envelope((ushort)layoutVersion, (uint)rulesVersion, HashAlgo.Sha256, extensions);
        }
    }

    /// <summary>Header ranges, caps and extension rules shared by every structured layout.</summary>
    public static class SigningBytes
    {
        /// <summary>The rules version this SDK authors under.</summary>
        public const uint RulesVersion = 1;

        /// <summary>The lowest rules version still verified.</summary>
        public const uint RulesVersionMin = 1;

        /// <summary>The highest rules version understood; anything above is <see cref="SigningBytesError.NeedsNewerVersion"/>.</summary>
        public const uint RulesVersionMax = 1;

        private const int ExtensionEntryHeader = 7;

        /// <summary>The cap on extension entry bytes (7 header bytes each) for a message authored under <paramref name="rulesVersion"/>.</summary>
        public static int MaxExtensionBytes(uint rulesVersion) => 4096;

        /// <summary>The supported layout versions of <paramref name="tag"/>: 1 to its newest.</summary>
        internal static ushort NewestLayout(DomainTag tag)
        {
            if (tag.Equals(DomainTags.Conformance))
            {
                return 2;
            }
            if (!DomainTags.All.Contains(tag))
            {
                throw new ArgumentException("unregistered tag", nameof(tag));
            }
            return 1;
        }

        internal static void CheckLayout(DomainTag tag, long version)
        {
            if (version > NewestLayout(tag))
            {
                throw new SigningBytesException(SigningBytesError.NeedsNewerVersion, VersionKind.Layout, (uint)version);
            }
            if (version < 1)
            {
                throw new SigningBytesException(SigningBytesError.UnsupportedVersion, VersionKind.Layout, (uint)version);
            }
        }

        internal static void CheckRules(long version)
        {
            if (version > RulesVersionMax)
            {
                throw new SigningBytesException(SigningBytesError.NeedsNewerVersion, VersionKind.Rules, (uint)version);
            }
            if (version < RulesVersionMin)
            {
                throw new SigningBytesException(SigningBytesError.UnsupportedVersion, VersionKind.Rules, (uint)version);
            }
        }

        // Per entry the running size against the cap, then order and duplicates by position.
        internal static void ValidateExtensions(IReadOnlyList<SigningExtension> entries, uint rulesVersion)
        {
            var max = MaxExtensionBytes(rulesVersion);
            long total = 0;
            foreach (var e in entries)
            {
                total += ExtensionEntryHeader + e.Value.Length;
                if (total > max)
                {
                    throw new SigningBytesException(SigningBytesError.ExtensionsTooLarge);
                }
            }
            if (entries.Count > ushort.MaxValue)
            {
                throw new SigningBytesException(SigningBytesError.ExtensionsTooLarge);
            }
            for (var i = 1; i < entries.Count; i++)
            {
                if (entries[i - 1].Type == entries[i].Type)
                {
                    throw new SigningBytesException(SigningBytesError.ExtensionDuplicate);
                }
                if (entries[i - 1].Type > entries[i].Type)
                {
                    throw new SigningBytesException(SigningBytesError.ExtensionsUnsorted);
                }
            }
        }

        // No critical extension is understood by any tag yet.
        internal static void RequireUnderstood(IReadOnlyList<SigningExtension> entries)
        {
            foreach (var e in entries)
            {
                if (e.Critical)
                {
                    throw new SigningBytesException(SigningBytesError.NeedsNewerVersion, VersionKind.CriticalExtension, e.Type);
                }
            }
        }

        internal static byte[] EncodeExtensions(IReadOnlyList<SigningExtension> entries)
        {
            var b = new List<byte> { (byte)(entries.Count >> 8), (byte)entries.Count };
            foreach (var e in entries)
            {
                b.Add((byte)(e.Type >> 8));
                b.Add((byte)e.Type);
                b.Add(e.Critical ? (byte)1 : (byte)0);
                var len = (uint)e.Value.Length;
                b.Add((byte)(len >> 24));
                b.Add((byte)(len >> 16));
                b.Add((byte)(len >> 8));
                b.Add((byte)len);
                b.AddRange(e.Value);
            }
            return b.ToArray();
        }

        /// <summary>The digest of <paramref name="data"/> under <paramref name="algo"/>.</summary>
        public static byte[] Digest(HashAlgo algo, byte[] data)
        {
            using (var sha = System.Security.Cryptography.SHA256.Create())
            {
                return sha.ComputeHash(data);
            }
        }
    }

    /// <summary>A registered domain tag: ASCII <c>[a-z0-9._]</c>, 1 to 255 bytes, written with no length prefix.</summary>
    public readonly struct DomainTag : IEquatable<DomainTag>
    {
        private readonly string? _value;

        public DomainTag(string value)
        {
            if (string.IsNullOrEmpty(value) || value.Length > 255)
            {
                throw new ArgumentException("a domain tag is 1 to 255 bytes", nameof(value));
            }
            foreach (var c in value)
            {
                if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_'))
                {
                    throw new ArgumentException("domain tag bytes must be [a-z0-9._]", nameof(value));
                }
            }
            _value = value;
        }

        /// <summary>The tag text; throws for <c>default</c>.</summary>
        public string Value => _value ?? throw new InvalidOperationException("default(DomainTag) is not a valid tag");

        public byte[] ToBytes() => Encoding.ASCII.GetBytes(Value);

        public bool Equals(DomainTag other) => string.Equals(_value, other._value, StringComparison.Ordinal);

        public override bool Equals(object? obj) => obj is DomainTag other && Equals(other);

        public override int GetHashCode() => _value == null ? 0 : StringComparer.Ordinal.GetHashCode(_value);

        public override string ToString() => Value;
    }

    /// <summary>The registry of domain tags, one per signed kind. Registered tags are prefix-free and
    /// never reused for another kind.</summary>
    public static class DomainTags
    {
        public static readonly DomainTag IdentityCreated = new DomainTag("avalon.identity.created");
        public static readonly DomainTag DeviceGrantApproved = new DomainTag("avalon.device_grant.approved");
        public static readonly DomainTag IdentitySigningKeyRevoked = new DomainTag("avalon.identity.signing_key_revoked");
        public static readonly DomainTag CrossNodeLogin = new DomainTag("avalon.cross_node_login");
        public static readonly DomainTag SessionContinuation = new DomainTag("avalon.session_continuation");
        public static readonly DomainTag InterestClaim = new DomainTag("avalon.interest_claim");
        public static readonly DomainTag AttestationIssue = new DomainTag("avalon.attestation.issue");
        public static readonly DomainTag AttestationBulkIssue = new DomainTag("avalon.attestation.bulk_issue");
        public static readonly DomainTag AttestationRevoke = new DomainTag("avalon.attestation.revoke");
        public static readonly DomainTag IssuerRegistered = new DomainTag("avalon.issuer.registered");
        public static readonly DomainTag SignatureGateAction = new DomainTag("avalon.signature_gate.action");
        public static readonly DomainTag IntegratorNonceChallenge = new DomainTag("avalon.integrator.nonce_challenge");
        public static readonly DomainTag LedgerEntry = new DomainTag("avalon.ledger.entry");
        public static readonly DomainTag IdentityChainEvent = new DomainTag("avalon.identity.chain_event");
        public static readonly DomainTag IdentityKeyEvent = new DomainTag("avalon.identity.key_event");
        public static readonly DomainTag SettlementSth = new DomainTag("avalon.settlement.sth");
        public static readonly DomainTag WitnessCosign = new DomainTag("avalon.witness.cosign");
        public static readonly DomainTag WitnessAnnounce = new DomainTag("avalon.witness.announce");

        /// <summary>Reserved for conformance vectors; never signed in production.</summary>
        public static readonly DomainTag Conformance = new DomainTag("avalon.conformance.vector");

        public static readonly IReadOnlyList<DomainTag> All = new[]
        {
            IdentityCreated, DeviceGrantApproved, IdentitySigningKeyRevoked, CrossNodeLogin, SessionContinuation,
            InterestClaim, AttestationIssue, AttestationBulkIssue, AttestationRevoke, IssuerRegistered,
            SignatureGateAction, IntegratorNonceChallenge, LedgerEntry,
            IdentityChainEvent, IdentityKeyEvent, SettlementSth, WitnessCosign, WitnessAnnounce, Conformance,
        };
    }

    /// <summary>Raw UUID bytes (RFC 4122 order, not .NET's mixed-endian layout).</summary>
    internal static class UuidBytes
    {
        public static byte[] Of(Guid value)
        {
            var b = value.ToByteArray();
            Array.Reverse(b, 0, 4);
            Array.Reverse(b, 4, 2);
            Array.Reverse(b, 6, 2);
            return b;
        }

        public static Guid From(byte[] raw)
        {
            var b = (byte[])raw.Clone();
            Array.Reverse(b, 0, 4);
            Array.Reverse(b, 4, 2);
            Array.Reverse(b, 6, 2);
            return new Guid(b);
        }
    }

    /// <summary>Builds a structured message: <c>new SigningBytesBuilder(tag, layout).Str(..).Key(..).Finish()</c>. The header
    /// is written first and the extensions region last, by <see cref="Finish"/>.</summary>
    public sealed class SigningBytesBuilder
    {
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        private readonly List<byte> _out = new List<byte>();
        private readonly List<SigningExtension> _extensions = new List<SigningExtension>();
        private readonly uint _rulesVersion;

        public SigningBytesBuilder(DomainTag tag, ushort layoutVersion)
            : this(tag, layoutVersion, SigningBytes.RulesVersion)
        {
        }

        /// <summary>A header with an explicit rules version, for rebuilding a stored message. A version outside the
        /// supported ranges throws <see cref="SigningBytesException"/>.</summary>
        public SigningBytesBuilder(DomainTag tag, ushort layoutVersion, uint rulesVersion)
        {
            SigningBytes.CheckLayout(tag, layoutVersion);
            SigningBytes.CheckRules(rulesVersion);
            _rulesVersion = rulesVersion;
            _out.AddRange(tag.ToBytes());
            U16(layoutVersion);
            U32(rulesVersion);
        }

        /// <summary>The header and extensions of a stored <see cref="Envelope"/>; its hash algorithm is written by
        /// <see cref="HashAlgo"/> where the layout places it.</summary>
        public static SigningBytesBuilder WithEnvelope(DomainTag tag, Envelope envelope)
        {
            var builder = new SigningBytesBuilder(tag, envelope.LayoutVersion, envelope.RulesVersion);
            builder._extensions.AddRange(envelope.Extensions);
            return builder;
        }

        /// <summary>The hash algorithm byte; call it immediately before the first hash-valued field.</summary>
        public SigningBytesBuilder HashAlgo(HashAlgo algo) => U8((byte)algo);

        /// <summary>Adds an extension; entries must be added in ascending type order.</summary>
        public SigningBytesBuilder Extension(ushort type, bool critical, byte[] value)
        {
            _extensions.Add(new SigningExtension(type, critical, value));
            return this;
        }

        /// <summary>A UTF-8 string with a u32 BE length prefix. A string with a lone surrogate throws <see cref="ArgumentException"/>.</summary>
        public SigningBytesBuilder Str(string value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            try
            {
                return Bytes(StrictUtf8.GetBytes(value));
            }
            catch (EncoderFallbackException)
            {
                throw new ArgumentException("string is not valid Unicode (lone surrogate)", nameof(value));
            }
        }

        public SigningBytesBuilder Bytes(byte[] value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            U32((uint)value.Length);
            _out.AddRange(value);
            return this;
        }

        /// <summary>Raw bytes of a width the layout fixes; never caller-sized data.</summary>
        public SigningBytesBuilder Fixed(byte[] value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            _out.AddRange(value);
            return this;
        }

        /// <summary>An Ed25519 public key: algorithm byte 1, then 32 raw bytes.</summary>
        public SigningBytesBuilder Key(byte[] value) => U8(1).Fixed(Exactly(value, 32, nameof(value)));

        /// <summary>An Ed25519 signature: algorithm byte 1, then 64 raw bytes.</summary>
        public SigningBytesBuilder Signature(byte[] value) => U8(1).Fixed(Exactly(value, 64, nameof(value)));

        /// <summary>A 32-byte hash, raw.</summary>
        public SigningBytesBuilder Hash(byte[] value) => Fixed(Exactly(value, 32, nameof(value)));

        public SigningBytesBuilder Uuid(Guid value) => Fixed(UuidBytes.Of(value));

        public SigningBytesBuilder U8(byte value) => Fixed(new[] { value });

        public SigningBytesBuilder U16(ushort value) => Fixed(new[] { (byte)(value >> 8), (byte)value });

        public SigningBytesBuilder U32(uint value) => Fixed(BigEndian(value, 4));

        public SigningBytesBuilder U64(ulong value) => Fixed(BigEndian(value, 8));

        public SigningBytesBuilder I64(long value) => Fixed(BigEndian(unchecked((ulong)value), 8));

        /// <summary>Appends the extensions region and returns the bytes.</summary>
        public byte[] Finish()
        {
            SigningBytes.ValidateExtensions(_extensions, _rulesVersion);
            SigningBytes.RequireUnderstood(_extensions);
            var result = new List<byte>(_out);
            result.AddRange(SigningBytes.EncodeExtensions(_extensions));
            return result.ToArray();
        }

        private static byte[] Exactly(byte[] value, int width, string name)
        {
            if (value == null || value.Length != width)
            {
                throw new ArgumentException("expected exactly " + width + " bytes", name);
            }
            return value;
        }

        private static byte[] BigEndian(ulong value, int width)
        {
            var b = new byte[width];
            for (var i = width - 1; i >= 0; i--)
            {
                b[i] = (byte)value;
                value >>= 8;
            }
            return b;
        }
    }

    /// <summary>Reads a structured message back field by field, in the order it was built.</summary>
    public sealed class SigningBytesReader
    {
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        private readonly byte[] _message;
        private int _pos;

        /// <summary>Checks the tag, then the layout and rules versions; a version above the supported range is
        /// <see cref="SigningBytesError.NeedsNewerVersion"/> before any field is read.</summary>
        public SigningBytesReader(DomainTag tag, byte[] message)
        {
            _message = message ?? throw new ArgumentNullException(nameof(message));
            var tagBytes = tag.ToBytes();
            if (message.Length < tagBytes.Length)
            {
                throw new SigningBytesException(SigningBytesError.TagMismatch);
            }
            for (var i = 0; i < tagBytes.Length; i++)
            {
                if (message[i] != tagBytes[i])
                {
                    throw new SigningBytesException(SigningBytesError.TagMismatch);
                }
            }
            _pos = tagBytes.Length;
            LayoutVersion = U16();
            SigningBytes.CheckLayout(tag, LayoutVersion);
            RulesVersion = U32();
            SigningBytes.CheckRules(RulesVersion);
        }

        public ushort LayoutVersion { get; }

        public uint RulesVersion { get; }

        private byte[] Take(long len)
        {
            if (len > _message.Length - _pos)
            {
                throw new SigningBytesException(SigningBytesError.Truncated);
            }
            var b = new byte[len];
            Buffer.BlockCopy(_message, _pos, b, 0, (int)len);
            _pos += (int)len;
            return b;
        }

        private ulong Be(int width)
        {
            ulong v = 0;
            foreach (var b in Take(width))
            {
                v = (v << 8) | b;
            }
            return v;
        }

        public byte[] Bytes() => Take(U32());

        public string Str()
        {
            try
            {
                return StrictUtf8.GetString(Bytes());
            }
            catch (ArgumentException)
            {
                throw new SigningBytesException(SigningBytesError.InvalidUtf8);
            }
        }

        public byte[] Fixed(int width) => Take(width);

        /// <summary>A public key; an unknown algorithm byte is <see cref="SigningBytesError.NeedsNewerVersion"/>.</summary>
        public byte[] Key() => AfterAlgorithm(32);

        /// <summary>A signature; an unknown algorithm byte is <see cref="SigningBytesError.NeedsNewerVersion"/>.</summary>
        public byte[] Signature() => AfterAlgorithm(64);

        /// <summary>A 32-byte hash, raw.</summary>
        public byte[] Hash() => Take(32);

        /// <summary>The hash algorithm byte; an unknown value is <see cref="SigningBytesError.NeedsNewerVersion"/>.</summary>
        public HashAlgo HashAlgo()
        {
            var id = U8();
            if (id != (byte)Avalon.Sdk.HashAlgo.Sha256)
            {
                throw new SigningBytesException(SigningBytesError.NeedsNewerVersion, VersionKind.HashAlgo, id);
            }
            return Avalon.Sdk.HashAlgo.Sha256;
        }

        private byte[] AfterAlgorithm(int width)
        {
            var id = U8();
            if (id != 1)
            {
                throw new SigningBytesException(SigningBytesError.NeedsNewerVersion, VersionKind.SigAlgo, id);
            }
            return Take(width);
        }

        public Guid Uuid() => UuidBytes.From(Take(16));

        public byte U8() => (byte)Be(1);

        public ushort U16() => (ushort)Be(2);

        public uint U32() => (uint)Be(4);

        public ulong U64() => Be(8);

        public long I64() => unchecked((long)Be(8));

        /// <summary>Reads the extensions region, which must be all that remains, and returns its entries (unknown
        /// non-critical ones included, for the caller to keep). An unknown critical extension is
        /// <see cref="SigningBytesError.NeedsNewerVersion"/>; bytes after the region are <see cref="SigningBytesError.TrailingBytes"/>.</summary>
        public IReadOnlyList<SigningExtension> Finish()
        {
            var max = SigningBytes.MaxExtensionBytes(RulesVersion);
            var count = U16();
            var entries = new List<SigningExtension>();
            long total = 0;
            for (var i = 0; i < count; i++)
            {
                var type = U16();
                var flags = U8();
                if ((flags & ~1) != 0)
                {
                    throw new SigningBytesException(SigningBytesError.ExtensionReservedFlags);
                }
                var len = U32();
                total += 7 + (long)len;
                if (total > max)
                {
                    throw new SigningBytesException(SigningBytesError.ExtensionsTooLarge);
                }
                entries.Add(new SigningExtension(type, flags == 1, Take(len)));
            }
            SigningBytes.ValidateExtensions(entries, RulesVersion);
            if (_pos != _message.Length)
            {
                throw new SigningBytesException(SigningBytesError.TrailingBytes);
            }
            SigningBytes.RequireUnderstood(entries);
            return entries;
        }
    }
}
