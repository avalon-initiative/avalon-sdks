// Structured signing bytes: tag | u16 BE version | fields in a fixed order (u32 BE length-prefixed strings
// and bytes, raw keys/hashes/UUIDs, fixed-width big-endian integers). Mirrors crates/protocol/src/signing_bytes.rs;
// conformance/vectors/structured-signing-bytes.json and domain-tags.json are the shared arbiters.

using System;
using System.Collections.Generic;
using System.Text;

namespace Avalon.Sdk
{
    /// <summary>Why a structured message could not be read.</summary>
    public enum SigningBytesError
    {
        /// <summary>The message does not start with the expected domain tag.</summary>
        TagMismatch,
        /// <summary>The message ends before the field does.</summary>
        Truncated,
        /// <summary>A string field is not valid UTF-8.</summary>
        InvalidUtf8,
        /// <summary>Bytes remain after the last field.</summary>
        TrailingBytes,
    }

    /// <summary>A malformed structured message; <see cref="Error"/> is the stable reason.</summary>
    public sealed class SigningBytesException : Exception
    {
        public SigningBytesException(SigningBytesError error)
            : base(error switch
            {
                SigningBytesError.TagMismatch => "message does not start with the expected domain tag",
                SigningBytesError.Truncated => "message ends before the field does",
                SigningBytesError.InvalidUtf8 => "string field is not valid UTF-8",
                _ => "bytes remain after the last field",
            })
        {
            Error = error;
        }

        public SigningBytesError Error { get; }
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

        /// <summary>Reserved for conformance vectors; never signed in production.</summary>
        public static readonly DomainTag Conformance = new DomainTag("avalon.conformance.vector");

        public static readonly IReadOnlyList<DomainTag> All = new[]
        {
            IdentityCreated, DeviceGrantApproved, IdentitySigningKeyRevoked, CrossNodeLogin, SessionContinuation,
            InterestClaim, AttestationIssue, AttestationBulkIssue, AttestationRevoke, IssuerRegistered,
            SignatureGateAction, IntegratorNonceChallenge, LedgerEntry,
            IdentityChainEvent, Conformance,
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

    /// <summary>Builds a structured message: <c>new SigningBytesBuilder(tag, version).Str(..).Key(..).Finish()</c>.</summary>
    public sealed class SigningBytesBuilder
    {
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        private readonly List<byte> _out = new List<byte>();

        public SigningBytesBuilder(DomainTag tag, ushort version)
        {
            _out.AddRange(tag.ToBytes());
            U16(version);
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

        /// <summary>A 32-byte public key, raw.</summary>
        public SigningBytesBuilder Key(byte[] value) => Exactly32(value, nameof(value));

        /// <summary>A 32-byte hash, raw.</summary>
        public SigningBytesBuilder Hash(byte[] value) => Exactly32(value, nameof(value));

        public SigningBytesBuilder Uuid(Guid value) => Fixed(UuidBytes.Of(value));

        public SigningBytesBuilder U8(byte value) => Fixed(new[] { value });

        public SigningBytesBuilder U16(ushort value) => Fixed(new[] { (byte)(value >> 8), (byte)value });

        public SigningBytesBuilder U32(uint value) => Fixed(BigEndian(value, 4));

        public SigningBytesBuilder U64(ulong value) => Fixed(BigEndian(value, 8));

        public SigningBytesBuilder I64(long value) => Fixed(BigEndian(unchecked((ulong)value), 8));

        public byte[] Finish() => _out.ToArray();

        private SigningBytesBuilder Exactly32(byte[] value, string name)
        {
            if (value == null || value.Length != 32)
            {
                throw new ArgumentException("a key or hash is exactly 32 bytes", name);
            }
            return Fixed(value);
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
            Version = U16();
        }

        /// <summary>The message's version slot.</summary>
        public ushort Version { get; }

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

        public Guid Uuid() => UuidBytes.From(Take(16));

        public byte U8() => (byte)Be(1);

        public ushort U16() => (ushort)Be(2);

        public uint U32() => (uint)Be(4);

        public ulong U64() => Be(8);

        public long I64() => unchecked((long)Be(8));

        /// <summary>Fails with <see cref="SigningBytesError.TrailingBytes"/> if any bytes remain.</summary>
        public void Finish()
        {
            if (_pos != _message.Length)
            {
                throw new SigningBytesException(SigningBytesError.TrailingBytes);
            }
        }
    }
}
