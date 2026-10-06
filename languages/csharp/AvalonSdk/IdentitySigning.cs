// The structured signing bytes of identity key events, and key policy for self-certifying identities. Mirrors
// crates/protocol/src/identity_id.rs; conformance/vectors/identity-id.json, identity-created-signing.json,
// device-grant-approval.json and signing-key-revoked.json are the shared arbiters.

using System;

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

        /// <summary>Bytes signed for <c>identity.created</c>: tag <c>avalon.identity.created</c>, version 1, then
        /// network id, shard id, ticket id (also the inception key's id), identity id, inception public key and
        /// display name. The event is unchained, so no position is signed.</summary>
        public static byte[] IdentityCreatedSigningBytes(
            string networkId, string shardId, Guid ticketId, IdentityId identityId, byte[] publicKey, string displayName) =>
            new SigningBytesBuilder(DomainTags.IdentityCreated, 1)
                .Str(networkId)
                .Str(shardId)
                .Uuid(ticketId)
                .Fixed(identityId.ToBytes())
                .Key(publicKey)
                .Str(displayName)
                .Finish();

        /// <summary>Bytes the approving device signs for a grant: tag <c>avalon.device_grant.approved</c>, version 1,
        /// then grant id (also the new key's id), identity id, approver signing key id, requested public key and the
        /// chain position (<paramref name="seq"/>, <paramref name="prevHash"/>, null for the first chained event).</summary>
        public static byte[] DeviceGrantApprovalSigningBytes(
            Guid grantId, IdentityId identityId, Guid approverSigningKeyId, byte[] requestedPublicKey, ulong seq, byte[]? prevHash) =>
            WithPosition(
                new SigningBytesBuilder(DomainTags.DeviceGrantApproved, 1)
                    .Uuid(grantId)
                    .Fixed(identityId.ToBytes())
                    .Uuid(approverSigningKeyId)
                    .Key(requestedPublicKey),
                seq,
                prevHash).Finish();

        /// <summary>Bytes a signing-key revocation signs: tag <c>avalon.identity.signing_key_revoked</c>, version 1,
        /// then identity id, revoked key id, revoking key id and the chain position as for a grant.</summary>
        public static byte[] SigningKeyRevokedSigningBytes(
            IdentityId identityId, Guid signingKeyId, Guid revokedBySigningKeyId, ulong seq, byte[]? prevHash) =>
            WithPosition(
                new SigningBytesBuilder(DomainTags.IdentitySigningKeyRevoked, 1)
                    .Fixed(identityId.ToBytes())
                    .Uuid(signingKeyId)
                    .Uuid(revokedBySigningKeyId),
                seq,
                prevHash).Finish();

        // seq u64, then prev_hash as a flag byte (0 none, 1 followed by the 32-byte head hash).
        private static SigningBytesBuilder WithPosition(SigningBytesBuilder builder, ulong seq, byte[]? prevHash)
        {
            builder.U64(seq);
            return prevHash == null ? builder.U8(0) : builder.U8(1).Hash(prevHash);
        }
    }
}
