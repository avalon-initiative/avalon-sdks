// Verification of tree heads of self-certifying node:<sha256-of-key> shards. The id is "node:"
// plus the lowercase hex SHA-256 of the raw 32-byte Ed25519 public key that signs the shard's
// heads; a node serves that key as the optional signing_public_key next to a head (outside the
// signed bytes). The key must hash to the id and must have signed the head: no trust anchor,
// registry or witness list is involved. Mirrors languages/rust/src/self_certifying.rs;
// conformance/vectors/self-certifying-tree-head.json is the shared arbiter.

using System;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Avalon.Sdk
{
    /// <summary>Why a self-certifying head was not verified. Checks run in this order and the
    /// first failure is reported.</summary>
    public enum SelfCertifyingFailure
    {
        /// <summary>The shard id is not a valid <c>node:&lt;64 lowercase hex&gt;</c> id.</summary>
        NotSelfCertifying,

        /// <summary>No signing key was presented with the head.</summary>
        MissingKey,

        /// <summary>The key is not exactly 64 lowercase hex characters decoding to a canonical
        /// Ed25519 point of non-small order.</summary>
        MalformedKey,

        /// <summary>SHA-256 of the key does not equal the hash in the shard id.</summary>
        KeyIdMismatch,

        /// <summary>The key did not sign this head.</summary>
        BadSignature,
    }

    /// <summary>Which verification applies to a shard id.</summary>
    public enum ShardCheck
    {
        /// <summary><c>node:&lt;hash&gt;</c>: <see cref="SelfCertifying.Verify"/>.</summary>
        SelfCertifying,

        /// <summary><c>core</c>: the network and witness verification
        /// (<see cref="AvalonClient.VerifyNetworkAsync"/>).</summary>
        CoreNetwork,

        /// <summary>Any other id kind, and any malformed id. Nothing here verifies these.</summary>
        Unsupported,
    }

    /// <summary>The outcome of <see cref="SelfCertifying.Verify"/>.</summary>
    public sealed class SelfCertifyingResult
    {
        private SelfCertifyingResult(bool verified, SelfCertifyingFailure? failure)
        {
            Verified = verified;
            Failure = failure;
        }

        /// <summary>True only when the key hashes to the id and signed the head.</summary>
        public bool Verified { get; }

        /// <summary>The first failing check; null when <see cref="Verified"/>.</summary>
        public SelfCertifyingFailure? Failure { get; }

        internal static SelfCertifyingResult Ok() => new SelfCertifyingResult(true, null);

        internal static SelfCertifyingResult Fail(SelfCertifyingFailure failure) =>
            new SelfCertifyingResult(false, failure);
    }

    /// <summary>Self-certifying <c>node:</c> shard head verification. Every method treats its
    /// inputs as attacker-controlled: malformed input is a failure result, never an
    /// exception.</summary>
    public static class SelfCertifying
    {
        private static readonly Regex NodeId = new Regex("^node:([0-9a-f]{64})\\z", RegexOptions.CultureInvariant);
        private static readonly Regex LowercaseKey = new Regex("^[0-9a-f]{64}\\z", RegexOptions.CultureInvariant);

        /// <summary>Which check applies to <paramref name="shardId"/>; an unsupported kind is
        /// reported, never passed.</summary>
        public static ShardCheck ShardCheckFor(string shardId)
        {
            if (shardId == "core")
            {
                return ShardCheck.CoreNetwork;
            }
            return NodeId.IsMatch(shardId ?? "") ? ShardCheck.SelfCertifying : ShardCheck.Unsupported;
        }

        /// <summary>The <c>node:</c> id a 32-byte Ed25519 public key certifies.</summary>
        public static string IdFor(byte[] publicKey)
        {
            using var sha = SHA256.Create();
            return "node:" + Hex(sha.ComputeHash(publicKey));
        }

        /// <summary>Verifies <paramref name="sth"/> as a head of the self-certifying shard
        /// <paramref name="shardId"/> using only the presented key:
        /// <paramref name="signingPublicKey"/> when given, otherwise
        /// <see cref="SignedTreeHeadWire.SigningPublicKey"/>.</summary>
        public static SelfCertifyingResult Verify(string shardId, SignedTreeHeadWire sth, string? signingPublicKey = null)
        {
            var match = NodeId.Match(shardId ?? "");
            if (!match.Success)
            {
                return SelfCertifyingResult.Fail(SelfCertifyingFailure.NotSelfCertifying);
            }
            var keyHex = signingPublicKey ?? sth?.SigningPublicKey;
            if (keyHex == null)
            {
                return SelfCertifyingResult.Fail(SelfCertifyingFailure.MissingKey);
            }
            var key = ParseKey(keyHex);
            if (key == null)
            {
                return SelfCertifyingResult.Fail(SelfCertifyingFailure.MalformedKey);
            }
            using (var sha = SHA256.Create())
            {
                if (Hex(sha.ComputeHash(key)) != match.Groups[1].Value)
                {
                    return SelfCertifyingResult.Fail(SelfCertifyingFailure.KeyIdMismatch);
                }
            }
            return sth != null && AvalonClient.VerifyTreeHeadHex(keyHex, sth)
                ? SelfCertifyingResult.Ok()
                : SelfCertifyingResult.Fail(SelfCertifyingFailure.BadSignature);
        }

        private static byte[]? ParseKey(string? keyHex)
        {
            if (keyHex == null || !LowercaseKey.IsMatch(keyHex))
            {
                return null;
            }
            var bytes = WitnessCosigning.TryHex(keyHex);
            if (bytes == null || bytes.Length != 32)
            {
                return null;
            }
            return StrictEd25519.IsAcceptableShardKey(bytes) ? bytes : null;
        }

        private static string Hex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes)
            {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }
    }

    public sealed partial class AvalonClient
    {
        /// <summary>GET /ledger/sth/latest, or /ledger/sth/{treeSize} when given, for
        /// <paramref name="shardId"/>, with <see cref="SignedTreeHeadWire.SigningPublicKey"/> when
        /// the node serves one. Nothing here verifies the result; see
        /// <see cref="SelfCertifying.Verify"/>.</summary>
        public async Task<SignedTreeHeadWire> GetShardTreeHeadAsync(
            string shardId, long? treeSize = null, CancellationToken ct = default)
        {
            var path = treeSize.HasValue ? $"/ledger/sth/{treeSize.Value}" : "/ledger/sth/latest";
            using var request = new HttpRequestMessage(
                HttpMethod.Get, $"{_config.ServerUrl}{path}?shard_id={Uri.EscapeDataString(shardId)}");
            using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw await Session.ServerErrorAsync(response).ConfigureAwait(false);
            }
            return await Session.ReadJsonAsync<SignedTreeHeadWire>(response, ct).ConfigureAwait(false);
        }
    }
}
