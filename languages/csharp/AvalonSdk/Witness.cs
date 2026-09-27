// Witness cosigning: cosignature signing bytes and verification, and cosigned tree head
// acceptance against a caller-supplied known witness list. Mirrors the Rust SDK behavior;
// conformance/vectors/witness-cosigned-tree-head.json is the shared arbiter.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Avalon.Sdk
{
    /// <summary>One witness's cosignature over an author-signed tree head.</summary>
    public sealed class WitnessCosignature
    {
        /// <summary>Tree size the cosignature covers.</summary>
        public long TreeSize { get; set; }

        /// <summary>Hex root hash the cosignature covers.</summary>
        public string RootHash { get; set; } = "";

        /// <summary>Network the cosigned head belongs to.</summary>
        public string NetworkId { get; set; } = "";

        /// <summary>The author's own tree head timestamp this cosignature is bound to.</summary>
        public DateTimeOffset AuthorCreatedAt { get; set; }

        /// <summary>Lowercase hex Ed25519 public key identifying the witness.</summary>
        public string WitnessKeyId { get; set; } = "";

        /// <summary>When the witness produced the cosignature; freshness checks use this.</summary>
        public DateTimeOffset ObservedAt { get; set; }

        /// <summary>Lowercase hex Ed25519 signature (64 bytes).</summary>
        public string Signature { get; set; } = "";
    }

    /// <summary>A verifier-chosen witness: the id cosignatures name and the hex Ed25519 key
    /// that must verify them.</summary>
    public sealed class KnownWitness
    {
        public KnownWitness(string witnessKeyId, string verifyKeyHex, string? baseUrl = null)
        {
            WitnessKeyId = witnessKeyId;
            VerifyKeyHex = verifyKeyHex;
            BaseUrl = baseUrl;
        }

        /// <summary>Where this witness's node was found, when the list was built by discovery.</summary>
        public string? BaseUrl { get; }

        /// <summary>The id cosignatures use to name this witness.</summary>
        public string WitnessKeyId { get; }

        /// <summary>Hex Ed25519 public key (32 bytes).</summary>
        public string VerifyKeyHex { get; }
    }

    /// <summary>An author-signed tree head together with the cosignatures presented with it.</summary>
    public sealed class CosignedTreeHead
    {
        public CosignedTreeHead(SignedTreeHeadWire sth, IReadOnlyList<WitnessCosignature> cosignatures)
        {
            Sth = sth;
            Cosignatures = cosignatures;
        }

        /// <summary>The author-signed tree head.</summary>
        public SignedTreeHeadWire Sth { get; }

        /// <summary>The cosignatures presented with the head.</summary>
        public IReadOnlyList<WitnessCosignature> Cosignatures { get; }
    }

    /// <summary>One cosignature as served with <c>?witnesses=1</c>; the bound head fields come
    /// from the enclosing tree head.</summary>
    public sealed class WitnessCosignatureWire
    {
        [JsonPropertyName("witness_key_id")]
        public string WitnessKeyId { get; set; } = "";

        [JsonPropertyName("observed_at")]
        public DateTimeOffset ObservedAt { get; set; }

        [JsonPropertyName("signature")]
        public string Signature { get; set; } = "";
    }

    /// <summary>A tree head fetched with <c>?witnesses=1</c>.</summary>
    public sealed class CosignedTreeHeadWire : SignedTreeHeadWire
    {
        [JsonPropertyName("cosignatures")]
        public List<WitnessCosignatureWire>? Cosignatures { get; set; }

        /// <summary>Binds each served cosignature to this head's own signed fields.</summary>
        public CosignedTreeHead ToCosignedTreeHead()
        {
            var sth = new SignedTreeHeadWire
            {
                TreeSize = TreeSize,
                RootHash = RootHash,
                NetworkId = NetworkId,
                SigningKeyId = SigningKeyId,
                Signature = Signature,
                CreatedAt = CreatedAt,
            };
            var cosignatures = (Cosignatures ?? new List<WitnessCosignatureWire>())
                .Select(c => new WitnessCosignature
                {
                    TreeSize = TreeSize,
                    RootHash = RootHash,
                    NetworkId = NetworkId,
                    AuthorCreatedAt = CreatedAt,
                    WitnessKeyId = c.WitnessKeyId,
                    ObservedAt = c.ObservedAt,
                    Signature = c.Signature,
                })
                .ToList();
            return new CosignedTreeHead(sth, cosignatures);
        }
    }

    /// <summary>Cosignature verification and cosigned tree head acceptance. Every method
    /// treats its inputs as attacker-controlled: malformed input is a false or empty result,
    /// never an exception.</summary>
    public static class WitnessCosigning
    {
        /// <summary>Freshness window applied when a caller supplies a known list but no window.</summary>
        public static readonly TimeSpan DefaultFreshnessWindow = TimeSpan.FromSeconds(600);

        /// <summary>Distinct witnesses needed out of a list of <paramref name="listSize"/>.</summary>
        public static int MajorityThreshold(int listSize) => listSize <= 0 ? 0 : listSize / 2 + 1;

        /// <summary>True when <paramref name="distinctWitnesses"/> reaches the majority of a list.</summary>
        public static bool IsCosignedByMajority(int listSize, int distinctWitnesses) =>
            distinctWitnesses >= MajorityThreshold(listSize);

        /// <summary>The exact bytes a witness signs.</summary>
        public static byte[] WitnessSigningMessage(
            long treeSize,
            string rootHashHex,
            string networkId,
            DateTimeOffset authorCreatedAt,
            string witnessKeyId,
            DateTimeOffset observedAt)
        {
            var message = new List<byte>();
            message.AddRange(Encoding.UTF8.GetBytes("avalon-witness-cosign-v1"));
            message.AddRange(BigEndian(treeSize));
            AddLengthPrefixed(message, rootHashHex);
            AddLengthPrefixed(message, networkId);
            message.AddRange(BigEndian(authorCreatedAt.ToUnixTimeSeconds()));
            AddLengthPrefixed(message, witnessKeyId);
            message.AddRange(BigEndian(observedAt.ToUnixTimeSeconds()));
            return message.ToArray();
        }

        /// <summary>Verifies a cosignature under <paramref name="witnessVerifyKeyHex"/>; false
        /// for malformed hex, wrong lengths or a bad signature.</summary>
        public static bool VerifyWitnessCosignature(string witnessVerifyKeyHex, WitnessCosignature cosignature)
        {
            try
            {
                var key = TryHex(witnessVerifyKeyHex);
                var signature = TryHex(cosignature.Signature);
                if (key == null || key.Length != 32 || signature == null || signature.Length != 64)
                {
                    return false;
                }
                var message = WitnessSigningMessage(
                    cosignature.TreeSize,
                    cosignature.RootHash,
                    cosignature.NetworkId,
                    cosignature.AuthorCreatedAt,
                    cosignature.WitnessKeyId,
                    cosignature.ObservedAt);
                var signer = new Ed25519Signer();
                signer.Init(false, new Ed25519PublicKeyParameters(key, 0));
                signer.BlockUpdate(message, 0, message.Length);
                return signer.VerifySignature(signature);
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>Accepts a head only when its author signature verifies and, for a known
        /// list of two or more, a majority of distinct listed witnesses (the author's own key
        /// counts if listed) cosigned it within [<paramref name="freshnessCutoff"/>,
        /// <paramref name="now"/>].</summary>
        public static bool VerifyCosignedTreeHead(
            string authorVerifyKeyHex,
            CosignedTreeHead head,
            IReadOnlyList<KnownWitness> knownList,
            DateTimeOffset freshnessCutoff,
            DateTimeOffset now)
        {
            try
            {
                if (!AvalonClient.VerifyTreeHeadHex(authorVerifyKeyHex, head.Sth))
                {
                    return false;
                }
                if (knownList.Count <= 1)
                {
                    return true;
                }
                var verified = ValidFreshWitnessIds(authorVerifyKeyHex, head, knownList, freshnessCutoff, now);
                return IsCosignedByMajority(knownList.Count, verified.Count);
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>Witnesses that validly and freshly cosigned two different roots at the same
        /// tree size of one network, both heads independently accepted; otherwise empty.</summary>
        public static IReadOnlyList<string> FindEquivocatingWitnesses(
            string authorVerifyKeyHex,
            IReadOnlyList<KnownWitness> knownList,
            DateTimeOffset freshnessCutoff,
            DateTimeOffset now,
            CosignedTreeHead headA,
            CosignedTreeHead headB)
        {
            try
            {
                if (headA.Sth.NetworkId != headB.Sth.NetworkId
                    || headA.Sth.TreeSize != headB.Sth.TreeSize
                    || headA.Sth.RootHash == headB.Sth.RootHash)
                {
                    return Array.Empty<string>();
                }
                if (!VerifyCosignedTreeHead(authorVerifyKeyHex, headA, knownList, freshnessCutoff, now)
                    || !VerifyCosignedTreeHead(authorVerifyKeyHex, headB, knownList, freshnessCutoff, now))
                {
                    return Array.Empty<string>();
                }
                var a = ValidFreshWitnessIds(authorVerifyKeyHex, headA, knownList, freshnessCutoff, now);
                var b = ValidFreshWitnessIds(authorVerifyKeyHex, headB, knownList, freshnessCutoff, now);
                a.IntersectWith(b);
                return a.OrderBy(id => id, StringComparer.Ordinal).ToList();
            }
            catch (Exception)
            {
                return Array.Empty<string>();
            }
        }

        private static SortedSet<string> ValidFreshWitnessIds(
            string authorVerifyKeyHex,
            CosignedTreeHead head,
            IReadOnlyList<KnownWitness> knownList,
            DateTimeOffset freshnessCutoff,
            DateTimeOffset now)
        {
            var verified = new SortedSet<string>(StringComparer.Ordinal);
            var authorKey = TryHex(authorVerifyKeyHex);
            if (authorKey != null)
            {
                foreach (var witness in knownList)
                {
                    var key = TryHex(witness.VerifyKeyHex);
                    if (key != null && key.AsSpan().SequenceEqual(authorKey))
                    {
                        verified.Add(witness.WitnessKeyId);
                    }
                }
            }
            foreach (var cosig in head.Cosignatures)
            {
                if (cosig.TreeSize != head.Sth.TreeSize
                    || cosig.RootHash != head.Sth.RootHash
                    || cosig.NetworkId != head.Sth.NetworkId
                    || cosig.AuthorCreatedAt.ToUnixTimeSeconds() != head.Sth.CreatedAt.ToUnixTimeSeconds())
                {
                    continue;
                }
                if (cosig.ObservedAt < freshnessCutoff || cosig.ObservedAt > now)
                {
                    continue;
                }
                var listed = knownList.FirstOrDefault(w => w.WitnessKeyId == cosig.WitnessKeyId);
                if (listed == null)
                {
                    continue;
                }
                if (VerifyWitnessCosignature(listed.VerifyKeyHex, cosig))
                {
                    verified.Add(cosig.WitnessKeyId);
                }
            }
            return verified;
        }

        internal static void AddLengthPrefixed(List<byte> message, string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            var length = BitConverter.GetBytes((uint)bytes.Length);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(length);
            }
            message.AddRange(length);
            message.AddRange(bytes);
        }

        internal static byte[] BigEndian(long value)
        {
            var bytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(bytes);
            }
            return bytes;
        }

        internal static byte[]? TryHex(string? hex)
        {
            if (hex == null || hex.Length % 2 != 0)
            {
                return null;
            }
            var bytes = new byte[hex.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                var hi = Nibble(hex[i * 2]);
                var lo = Nibble(hex[i * 2 + 1]);
                if (hi < 0 || lo < 0)
                {
                    return null;
                }
                bytes[i] = (byte)(hi << 4 | lo);
            }
            return bytes;
        }

        private static int Nibble(char c) =>
            c >= '0' && c <= '9' ? c - '0'
            : c >= 'a' && c <= 'f' ? c - 'a' + 10
            : c >= 'A' && c <= 'F' ? c - 'A' + 10
            : -1;
    }
}
