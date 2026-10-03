// The shard family head: one owner's sibling shards ({namespace}:{slug} and
// {namespace}:{slug}/{instance}) committed under a single recomputable root, served by
// GET /ledger/shard-family. Nothing signs the root; anyone recomputes it from the member heads.
// Mirrors languages/rust/src/shard_family.rs; conformance/vectors/shard-family-head.json is the
// shared arbiter.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace Avalon.Sdk
{
    /// <summary>The fields of a member's head that its leaf commits to.</summary>
    public class FamilyHead
    {
        /// <summary>The member shard id.</summary>
        [JsonPropertyName("shard_id")]
        public string ShardId { get; set; } = "";

        /// <summary>Entries in the member's log.</summary>
        [JsonPropertyName("tree_size")]
        public long TreeSize { get; set; }

        /// <summary>The member's own Merkle root, lowercase hex.</summary>
        [JsonPropertyName("root_hash")]
        public string RootHash { get; set; } = "";

        /// <summary>Label of the key that signed the member's head.</summary>
        [JsonPropertyName("signing_key_id")]
        public string SigningKeyId { get; set; } = "";

        /// <summary>The member head's signature, lowercase hex.</summary>
        [JsonPropertyName("signature")]
        public string Signature { get; set; } = "";
    }

    /// <summary>A member head as the node serves it.</summary>
    public sealed class FamilyMember : FamilyHead
    {
        /// <summary>Head timestamp; not part of the leaf.</summary>
        [JsonPropertyName("created_at")]
        public DateTimeOffset CreatedAt { get; set; }
    }

    /// <summary>An RFC 6962 inclusion proof of one member head against the family root.</summary>
    public sealed class FamilyProof
    {
        /// <summary>The member the proof is for.</summary>
        [JsonPropertyName("shard_id")]
        public string ShardId { get; set; } = "";

        /// <summary>Position of the member in shard id order.</summary>
        [JsonPropertyName("leaf_index")]
        public long LeafIndex { get; set; }

        /// <summary>Number of members the root commits to.</summary>
        [JsonPropertyName("tree_size")]
        public long TreeSize { get; set; }

        /// <summary>Hex sibling hashes, leaf to root.</summary>
        [JsonPropertyName("path")]
        public List<string> Path { get; set; } = new List<string>();
    }

    /// <summary>GET /ledger/shard-family response.</summary>
    public sealed class ShardFamilyResponse
    {
        /// <summary>The family owner id.</summary>
        [JsonPropertyName("owner")]
        public string Owner { get; set; } = "";

        /// <summary>Family root, lowercase hex.</summary>
        [JsonPropertyName("root_hash")]
        public string RootHash { get; set; } = "";

        /// <summary>Number of members in <see cref="Members"/>.</summary>
        [JsonPropertyName("shard_count")]
        public long ShardCount { get; set; }

        /// <summary>A known family member has no head here, so <see cref="Members"/> may be
        /// incomplete.</summary>
        [JsonPropertyName("partial")]
        public bool Partial { get; set; }

        /// <summary>Known family members without a head here.</summary>
        [JsonPropertyName("missing_shard_ids")]
        public List<string> MissingShardIds { get; set; } = new List<string>();

        /// <summary>The exact heads <see cref="RootHash"/> commits to, in shard id order.</summary>
        [JsonPropertyName("members")]
        public List<FamilyMember> Members { get; set; } = new List<FamilyMember>();

        /// <summary>Present only when a member was requested.</summary>
        [JsonPropertyName("proof")]
        public FamilyProof? Proof { get; set; }

        /// <summary>Whether <see cref="RootHash"/> is what <see cref="ShardFamily.Root"/> gives
        /// for the served members.</summary>
        public bool RootMatches() => ShardFamily.Root(Owner, Members) == RootHash;

        /// <summary>Whether the served proof verifies for its member against
        /// <see cref="RootHash"/>; false when absent.</summary>
        public bool ProofVerifies()
        {
            if (Proof == null)
            {
                return false;
            }
            var member = Members.FirstOrDefault(m => m.ShardId == Proof.ShardId);
            return member != null && ShardFamily.VerifyInclusion(Owner, RootHash, Proof, member);
        }
    }

    /// <summary>Shard family helpers. Every method treats its inputs as attacker-controlled:
    /// malformed input is a failure, never an exception.</summary>
    public static class ShardFamily
    {
        private const string LeafTag = "avalon-shard-family-leaf-v1";
        private const string EmptyTag = "avalon-shard-family-empty-v1";
        private const int MaxInstanceLen = 64;

        /// <summary>The owner id ({namespace}:{slug}) a shard id belongs to; <c>core</c>,
        /// <c>node:</c> ids and anything that does not parse have no family (null).</summary>
        public static string? OwnerOf(string? shardId)
        {
            if (shardId == null)
            {
                return null;
            }
            var colon = shardId.IndexOf(':');
            if (colon < 0)
            {
                return null;
            }
            var ns = shardId.Substring(0, colon);
            if (ns != "game" && ns != "app" && ns != "service")
            {
                return null;
            }
            var rest = shardId.Substring(colon + 1);
            var slash = rest.IndexOf('/');
            var owner = slash < 0 ? rest : rest.Substring(0, slash);
            if (owner.Length == 0 || owner.Any(c => IsWhiteSpace(c) || c == ':'))
            {
                return null;
            }
            if (slash >= 0 && !ValidInstance(rest.Substring(slash + 1)))
            {
                return null;
            }
            return ns + ":" + owner;
        }

        /// <summary>Whether <paramref name="owner"/> is a well-formed family owner id: an owned
        /// shard id with no instance.</summary>
        public static bool IsOwnerId(string? owner) => owner != null && OwnerOf(owner) == owner;

        /// <summary>Whether <paramref name="shardId"/> belongs to the family owned by
        /// <paramref name="owner"/>.</summary>
        public static bool IsMember(string? owner, string? shardId)
        {
            var found = OwnerOf(shardId);
            return found != null && found == owner;
        }

        // Unicode White_Space, as in Rust char::is_whitespace (char.IsWhiteSpace differs).
        private static bool IsWhiteSpace(char c) =>
            (c >= '\t' && c <= '\r') || c == ' ' || c == '\u0085' || c == '\u00a0' || c == '\u1680'
            || (c >= '\u2000' && c <= '\u200a') || c == '\u2028' || c == '\u2029' || c == '\u202f'
            || c == '\u205f' || c == '\u3000';

        private static bool ValidInstance(string s)
        {
            if (s.Length == 0 || s.Length > MaxInstanceLen)
            {
                return false;
            }
            for (var i = 0; i < s.Length; i++)
            {
                var c = s[i];
                var alnum = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
                if (!(alnum || (i > 0 && c == '-')))
                {
                    return false;
                }
            }
            return true;
        }

        private static void Put(List<byte> bytes, string text)
        {
            var utf8 = Encoding.UTF8.GetBytes(text);
            bytes.AddRange(BigEndian((ulong)utf8.Length, 4));
            bytes.AddRange(utf8);
        }

        private static byte[] BigEndian(ulong value, int width)
        {
            var bytes = new byte[width];
            for (var i = 0; i < width; i++)
            {
                bytes[width - 1 - i] = (byte)(value >> (8 * i));
            }
            return bytes;
        }

        private static byte[] LeafBytes(string owner, FamilyHead head)
        {
            var bytes = new List<byte>(Encoding.UTF8.GetBytes(LeafTag));
            Put(bytes, owner);
            Put(bytes, head.ShardId);
            bytes.AddRange(BigEndian(unchecked((ulong)head.TreeSize), 8));
            Put(bytes, head.RootHash);
            Put(bytes, head.SigningKeyId);
            Put(bytes, head.Signature);
            return bytes.ToArray();
        }

        private static byte[] Sha(params byte[][] parts)
        {
            using var sha = SHA256.Create();
            return sha.ComputeHash(parts.SelectMany(p => p).ToArray());
        }

        private static byte[] LeafHash(byte[] data) => Sha(new byte[] { 0 }, data);

        private static byte[] NodeHash(byte[] left, byte[] right) => Sha(new byte[] { 1 }, left, right);

        // The largest power of two strictly below n (n >= 2).
        private static long SplitPoint(long n)
        {
            long k = 1;
            while (k <= (n - 1) / 2)
            {
                k *= 2;
            }
            return k;
        }

        private static byte[] Mth(IReadOnlyList<byte[]> leaves)
        {
            if (leaves.Count == 1)
            {
                return LeafHash(leaves[0]);
            }
            var k = (int)SplitPoint(leaves.Count);
            return NodeHash(Mth(leaves.Take(k).ToList()), Mth(leaves.Skip(k).ToList()));
        }

        private static int CompareUtf8(string a, string b)
        {
            var x = Encoding.UTF8.GetBytes(a);
            var y = Encoding.UTF8.GetBytes(b);
            for (var i = 0; i < Math.Min(x.Length, y.Length); i++)
            {
                if (x[i] != y[i])
                {
                    return x[i] - y[i];
                }
            }
            return x.Length - y.Length;
        }

        private static string Hex(byte[] bytes) => string.Concat(bytes.Select(b => b.ToString("x2")));

        /// <summary>The family root over <paramref name="heads"/>: heads of other owners are
        /// ignored, the rest are ordered by shard id bytes, so the input order does not matter.
        /// Lowercase hex.</summary>
        public static string Root(string owner, IEnumerable<FamilyHead> heads)
        {
            var members = heads.Where(h => IsMember(owner, h.ShardId)).ToList();
            members.Sort((a, b) => CompareUtf8(a.ShardId, b.ShardId));
            if (members.Count == 0)
            {
                var empty = new List<byte>(Encoding.UTF8.GetBytes(EmptyTag));
                Put(empty, owner);
                return Hex(Sha(empty.ToArray()));
            }
            return Hex(Mth(members.Select(h => LeafBytes(owner, h)).ToList()));
        }

        private static byte[]? Decode32(string? hex)
        {
            var bytes = hex == null ? null : WitnessCosigning.TryHex(hex);
            return bytes != null && bytes.Length == 32 ? bytes : null;
        }

        private static byte[]? VerifyPath(long m, long n, byte[] leaf, IReadOnlyList<byte[]> proof, int count)
        {
            if (n <= 1)
            {
                return count == 0 ? leaf : null;
            }
            if (count == 0)
            {
                return null;
            }
            var k = SplitPoint(n);
            var last = proof[count - 1];
            if (m < k)
            {
                var left = VerifyPath(m, k, leaf, proof, count - 1);
                return left == null ? null : NodeHash(left, last);
            }
            var right = VerifyPath(m - k, n - k, leaf, proof, count - 1);
            return right == null ? null : NodeHash(last, right);
        }

        /// <summary>Verifies that <paramref name="head"/> (a head of its
        /// <see cref="FamilyHead.ShardId"/>) is a member of <paramref name="owner"/>'s family
        /// whose root is <paramref name="rootHash"/>. Any malformed input is a failure.</summary>
        public static bool VerifyInclusion(string owner, string rootHash, FamilyProof proof, FamilyHead head)
        {
            try
            {
                if (!IsMember(owner, head.ShardId) || proof.LeafIndex < 0 || proof.LeafIndex >= proof.TreeSize)
                {
                    return false;
                }
                var root = Decode32(rootHash);
                if (root == null)
                {
                    return false;
                }
                var path = new List<byte[]>();
                foreach (var element in proof.Path)
                {
                    var decoded = Decode32(element);
                    if (decoded == null)
                    {
                        return false;
                    }
                    path.Add(decoded);
                }
                var rebuilt = VerifyPath(proof.LeafIndex, proof.TreeSize, LeafHash(LeafBytes(owner, head)), path, path.Count);
                return rebuilt != null && rebuilt.SequenceEqual(root);
            }
            catch (Exception)
            {
                return false;
            }
        }
    }

    public sealed partial class AvalonClient
    {
        /// <summary>GET /ledger/shard-family for <paramref name="owner"/>, with an inclusion proof
        /// for <paramref name="member"/> when given. Nothing here verifies the result; see
        /// <see cref="ShardFamilyResponse.RootMatches"/> and
        /// <see cref="ShardFamilyResponse.ProofVerifies"/>.</summary>
        public async Task<ShardFamilyResponse> GetShardFamilyAsync(
            string owner, string? member = null, CancellationToken ct = default)
        {
            var url = $"{_config.ServerUrl}/ledger/shard-family?owner={Uri.EscapeDataString(owner)}";
            if (member != null)
            {
                url += $"&member={Uri.EscapeDataString(member)}";
            }
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw await Session.ServerErrorAsync(response).ConfigureAwait(false);
            }
            return await Session.ReadJsonAsync<ShardFamilyResponse>(response, ct).ConfigureAwait(false);
        }
    }
}
