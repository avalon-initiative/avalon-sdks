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

        /// <summary>Bytes signed for <c>identity.created</c>: tag <c>avalon.identity.created</c>, layout 1, then
        /// network id, ticket id (also the inception key's id), identity id, inception public key and display name.
        /// The shard id is not signed and the event is unchained, so no position is signed.</summary>
        public static byte[] IdentityCreatedSigningBytes(
            string networkId, Guid ticketId, IdentityId identityId, byte[] publicKey, string displayName) =>
            new SigningBytesBuilder(DomainTags.IdentityCreated, 1)
                .Str(networkId)
                .Uuid(ticketId)
                .Fixed(identityId.ToBytes())
                .Key(publicKey)
                .Str(displayName)
                .Finish();

        /// <summary>Bytes the approving device signs for a grant: tag <c>avalon.device_grant.approved</c>, layout 1,
        /// then network id, grant id (also the new key's id), identity id, approver signing key id, requested public key
        /// and the chain position (<paramref name="seq"/>, <paramref name="prevHash"/>, null for the first chained event).</summary>
        public static byte[] DeviceGrantApprovalSigningBytes(
            string networkId, Guid grantId, IdentityId identityId, Guid approverSigningKeyId, byte[] requestedPublicKey, ulong seq, byte[]? prevHash) =>
            WithPosition(
                new SigningBytesBuilder(DomainTags.DeviceGrantApproved, 1)
                    .Str(networkId)
                    .Uuid(grantId)
                    .Fixed(identityId.ToBytes())
                    .Uuid(approverSigningKeyId)
                    .Key(requestedPublicKey),
                seq,
                prevHash).Finish();

        /// <summary>Bytes a signing-key revocation signs: tag <c>avalon.identity.signing_key_revoked</c>, layout 1,
        /// then network id, identity id, revoked key id, revoking key id and the chain position as for a grant.</summary>
        public static byte[] SigningKeyRevokedSigningBytes(
            string networkId, IdentityId identityId, Guid signingKeyId, Guid revokedBySigningKeyId, ulong seq, byte[]? prevHash) =>
            WithPosition(
                new SigningBytesBuilder(DomainTags.IdentitySigningKeyRevoked, 1)
                    .Str(networkId)
                    .Fixed(identityId.ToBytes())
                    .Uuid(signingKeyId)
                    .Uuid(revokedBySigningKeyId),
                seq,
                prevHash).Finish();

        // seq u64, the hash algorithm byte, then prev_hash as a flag byte (0 none, 1 followed by the 32-byte head hash).
        private static SigningBytesBuilder WithPosition(SigningBytesBuilder builder, ulong seq, byte[]? prevHash)
        {
            builder.U64(seq).HashAlgo(HashAlgo.Sha256);
            return prevHash == null ? builder.U8(0) : builder.U8(1).Hash(prevHash);
        }
    }
}
