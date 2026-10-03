// The v2 signing bytes that carry self-certifying identity ids. A public key is lowercase
// hex inside every signing-byte string and standard base64 on the wire. Mirrors
// languages/rust/src/identity_signing.rs; conformance/vectors/identity-id.json,
// identity-created-signing.json, device-grant-approval.json and signing-key-revoked.json are
// the shared arbiters.

using System;
using System.Globalization;
using System.Text;

namespace Avalon.Sdk
{
    /// <summary>Signing bytes and key policy for self-certifying identities.</summary>
    public static class IdentitySigning
    {
        /// <summary>Whether <paramref name="publicKey"/> may be committed to by an identity id:
        /// a canonical encoding of a curve point that is not of small order.</summary>
        public static bool IsAcceptableKey(byte[] publicKey) => StrictEd25519.IsAcceptableShardKey(publicKey);

        /// <summary>Strict Ed25519 verification: cofactorless, S below the group order, and no
        /// small-order key or R. False for every failure, never throws.</summary>
        public static bool VerifyStrict(byte[] publicKey, byte[] message, byte[] signature) =>
            StrictEd25519.VerifyStrict(publicKey, message, signature);

        /// <summary><c>avalon:identity.created:v2:{len(network_id)}:{network_id}:{len(shard_id)}:{shard_id}:{ticket_id}:{identity_id}:{public_key_hex}:{display_name}</c>
        /// with <c>len</c> the decimal UTF-8 byte length.</summary>
        public static byte[] IdentityCreatedSigningBytesV2(
            string networkId, string shardId, Guid ticketId, IdentityId identityId, byte[] publicKey, string displayName)
        {
            RequireKey(publicKey);
            var text = string.Format(
                CultureInfo.InvariantCulture,
                "avalon:identity.created:v2:{0}:{1}:{2}:{3}:{4}:{5}:{6}:{7}",
                Encoding.UTF8.GetByteCount(networkId),
                networkId,
                Encoding.UTF8.GetByteCount(shardId),
                shardId,
                ticketId.ToString("D"),
                identityId,
                Hex(publicKey),
                displayName);
            return Encoding.UTF8.GetBytes(text);
        }

        /// <summary><c>avalon:device_grant.approved:v2:{grant_id}:{identity_id}:{requested_public_key_hex}</c>.</summary>
        public static byte[] DeviceGrantApprovalSigningBytesV2(Guid grantId, IdentityId identityId, byte[] requestedPublicKey)
        {
            RequireKey(requestedPublicKey);
            return Encoding.UTF8.GetBytes(string.Format(
                CultureInfo.InvariantCulture,
                "avalon:device_grant.approved:v2:{0}:{1}:{2}",
                grantId.ToString("D"),
                identityId,
                Hex(requestedPublicKey)));
        }

        /// <summary><c>avalon:identity.signing_key_revoked:v2:{identity_id}:{signing_key_id}:{revoked_by_signing_key_id}</c>.</summary>
        public static byte[] SigningKeyRevokedSigningBytesV2(IdentityId identityId, Guid signingKeyId, Guid revokedBySigningKeyId) =>
            Encoding.UTF8.GetBytes(string.Format(
                CultureInfo.InvariantCulture,
                "avalon:identity.signing_key_revoked:v2:{0}:{1}:{2}",
                identityId,
                signingKeyId.ToString("D"),
                revokedBySigningKeyId.ToString("D")));

        private static void RequireKey(byte[] key)
        {
            if (key == null || key.Length != 32)
            {
                throw new ArgumentException("an Ed25519 public key is exactly 32 bytes");
            }
        }

        private static string Hex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes)
            {
                sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
            }
            return sb.ToString();
        }
    }
}
