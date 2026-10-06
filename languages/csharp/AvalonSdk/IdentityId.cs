// Self-certifying identity ids: lowercase hex SHA-256 of "avalon-identity-id-v1" and the
// identity's inception Ed25519 public key. Mirrors languages/rust/src/types/ids.rs;
// conformance/vectors/identity-id.json is the shared arbiter.

using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Avalon.Sdk
{
    /// <summary>A self-certifying identity id: exactly 64 lowercase hex characters. Parsing is
    /// strict and never normalises: uppercase, any other length, <c>id:</c>/<c>node:</c>
    /// prefixes, UUID text and surrounding whitespace are all rejected. <c>default</c> is not a
    /// valid id and throws on use.</summary>
    [JsonConverter(typeof(IdentityIdJsonConverter))]
    public readonly struct IdentityId : IEquatable<IdentityId>, IComparable<IdentityId>
    {
        /// <summary>The length of an id in characters.</summary>
        public const int Length = 64;

        private static readonly byte[] DomainTag = Encoding.ASCII.GetBytes("avalon-identity-id-v1");

        private readonly string? _value;

        private IdentityId(string value)
        {
            _value = value;
        }

        /// <summary>The canonical text of this id.</summary>
        public string Value => _value ?? throw new InvalidOperationException("default(IdentityId) is not a valid identity id");

        /// <summary>Parses the canonical form; throws <see cref="FormatException"/> otherwise.</summary>
        public static IdentityId Parse(string? text)
        {
            if (!TryParse(text, out var id))
            {
                throw new FormatException("identity id must be exactly 64 lowercase hex characters [0-9a-f]");
            }
            return id;
        }

        /// <summary>Strictly parses the canonical form; nothing is trimmed or lowercased.</summary>
        public static bool TryParse(string? text, out IdentityId id)
        {
            id = default;
            if (text == null || text.Length != Length)
            {
                return false;
            }
            foreach (var c in text)
            {
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                {
                    return false;
                }
            }
            id = new IdentityId(text);
            return true;
        }

        /// <summary>Derives the id of the identity whose inception key is
        /// <paramref name="publicKey"/> (32 raw bytes). A pure hash: it does not check key
        /// acceptability, see <see cref="IdentitySigning.IsAcceptableKey"/>.</summary>
        public static IdentityId Derive(byte[] publicKey)
        {
            if (publicKey == null || publicKey.Length != 32)
            {
                throw new ArgumentException("an Ed25519 public key is exactly 32 bytes", nameof(publicKey));
            }
            var preimage = new byte[DomainTag.Length + 32];
            Buffer.BlockCopy(DomainTag, 0, preimage, 0, DomainTag.Length);
            Buffer.BlockCopy(publicKey, 0, preimage, DomainTag.Length, 32);
            using var sha = SHA256.Create();
            return new IdentityId(LedgerEntry.ToHex(sha.ComputeHash(preimage)));
        }

        /// <summary>A fresh id from a random key, for tests that never verify a signature against it.</summary>
        internal static IdentityId RandomForTests() => RandomWithKeyForTests().Id;

        /// <summary>A fresh random inception key and its derived id, for seeding <c>identities</c> rows.</summary>
        internal static (IdentityId Id, byte[] Key) RandomWithKeyForTests()
        {
            var key = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(key);
            return (Derive(key), key);
        }

        /// <summary>The id as its 32 raw bytes, the form signing bytes carry.</summary>
        public byte[] ToBytes()
        {
            var text = Value;
            var bytes = new byte[32];
            for (var i = 0; i < 32; i++)
            {
                bytes[i] = Convert.ToByte(text.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        /// <summary>Whether this id is the one derived from <paramref name="publicKey"/>.</summary>
        public bool MatchesKey(byte[] publicKey) => Equals(Derive(publicKey));

        public bool Equals(IdentityId other) => string.Equals(_value, other._value, StringComparison.Ordinal);

        public override bool Equals(object? obj) => obj is IdentityId other && Equals(other);

        public override int GetHashCode() => _value == null ? 0 : StringComparer.Ordinal.GetHashCode(_value);

        public int CompareTo(IdentityId other) => string.CompareOrdinal(_value, other._value);

        public static bool operator ==(IdentityId left, IdentityId right) => left.Equals(right);

        public static bool operator !=(IdentityId left, IdentityId right) => !left.Equals(right);

        /// <summary>The canonical text; throws for <c>default</c>.</summary>
        public override string ToString() => Value;
    }

    internal sealed class IdentityIdJsonConverter : JsonConverter<IdentityId>
    {
        public override IdentityId Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.String || !IdentityId.TryParse(reader.GetString(), out var id))
            {
                throw new JsonException("identity id must be a string of exactly 64 lowercase hex characters");
            }
            return id;
        }

        public override void Write(Utf8JsonWriter writer, IdentityId value, JsonSerializerOptions options) =>
            writer.WriteStringValue(value.Value);
    }
}
