//! Globally unique identifiers, as they appear on the wire.
//!
//! Every one of these is a transparent newtype over the exact JSON the
//! server sends (a UUID string, or the `<namespace>:<owner>:<kind>:<key>`
//! text of a [`GlobalId`]) — they exist so a call site can't pass a guild
//! id where an identity id belongs, not to add any encoding of their own.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Why a string is not a canonical identity id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdentityIdParseError {
    /// Not 64 bytes long: possibly an id from a newer scheme this build cannot read.
    #[error("unknown identity id scheme: {length} characters; this version only reads 64-character ids, a newer version may be required")]
    UnknownScheme {
        /// The UTF-8 byte length of the rejected text.
        length: usize,
    },
    /// 64 bytes long but not lowercase hex.
    #[error("identity id must be lowercase hex [0-9a-f]")]
    NotLowercaseHex,
}

/// A self-certifying identity id: 64 lowercase hex characters, `SHA-256("avalon-identity-id-v1" || key)`
/// of the identity's inception Ed25519 public key. Parsing (`FromStr`, serde) is strict and never normalises.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct IdentityId(String);

impl std::str::FromStr for IdentityId {
    type Err = IdentityIdParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.len() != 64 {
            return Err(IdentityIdParseError::UnknownScheme { length: text.len() });
        }
        if !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(IdentityIdParseError::NotLowercaseHex);
        }
        Ok(Self(text.to_owned()))
    }
}

impl TryFrom<&str> for IdentityId {
    type Error = IdentityIdParseError;

    fn try_from(text: &str) -> Result<Self, Self::Error> {
        text.parse()
    }
}

impl TryFrom<String> for IdentityId {
    type Error = IdentityIdParseError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

impl<'de> Deserialize<'de> for IdentityId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl std::ops::Deref for IdentityId {
    type Target = String;

    fn deref(&self) -> &String {
        &self.0
    }
}

impl From<IdentityId> for String {
    fn from(id: IdentityId) -> Self {
        id.0
    }
}

/// Domain-separation tag hashed ahead of the inception key when deriving an identity id.
pub const IDENTITY_ID_DOMAIN_TAG: &[u8] = b"avalon-identity-id-v1";

impl IdentityId {
    /// Derives the id for an inception public key (a pure hash; the caller gates key acceptability).
    pub fn derive(public_key: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(IDENTITY_ID_DOMAIN_TAG);
        hasher.update(public_key);
        hex::encode(hasher.finalize())
            .parse()
            .expect("a SHA-256 digest is 64 lowercase hex characters")
    }

    /// A fresh id from a random key, for tests that never verify a signature against it.
    #[cfg(any(test, feature = "test-util"))]
    pub fn random_for_tests() -> Self {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rng());
        Self::derive(key.verifying_key().as_bytes())
    }

    /// A fresh random inception key and the id derived from it, for seeding `identities` rows
    /// (`id` and `inception_public_key`) in live tests.
    #[cfg(any(test, feature = "test-util"))]
    pub fn random_with_key_for_tests() -> (Self, [u8; 32]) {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rng())
            .verifying_key()
            .to_bytes();
        (Self::derive(&key), key)
    }

    /// The raw 32-byte digest the id's hex text encodes.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex::decode_to_slice(self.to_string(), &mut out)
            .expect("an identity id is 64 lowercase hex characters");
        out
    }

    /// Whether this id is the one derived from `public_key`.
    pub fn matches_key(&self, public_key: &[u8; 32]) -> bool {
        Self::derive(public_key) == *self
    }
}

/// A registered integrator (game, app, or service).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IntegratorId(
    /// The integrator's UUID, exactly as it appears on the wire.
    pub Uuid,
);

impl fmt::Display for IntegratorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A guild, which exists independently of any one integrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GuildId(
    /// The guild's UUID, exactly as it appears on the wire.
    pub Uuid,
);

impl fmt::Display for GuildId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A namespaced, human-readable identifier: `<namespace>:<owner>:<kind>:<key>`.
///
/// Example: `game:ashen-realms:achievement:dragon_slayer`. Two different
/// integrators can both define `dragon_slayer` without colliding, because
/// the integrator's own slug is part of the identifier, not just the
/// achievement key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GlobalId(String);

impl GlobalId {
    /// Builds `<namespace>:<owner>:<kind>:<key>`.
    pub fn new(namespace: &str, owner: &str, kind: &str, key: &str) -> Self {
        Self(format!("{namespace}:{owner}:{kind}:{key}"))
    }

    /// The full identifier text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GlobalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for IdentityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "7c26a0e34260b2c5bb6a795e29cdfe878c907df4bf8c7425c5a8ce00235558e9";

    #[test]
    fn parse_is_strict() {
        assert!(ID.parse::<IdentityId>().is_ok());
        for bad in [
            &ID.to_uppercase(),
            &ID[..63],
            &format!("{ID}0"),
            &format!("id:{ID}"),
            &format!("{ID}\n"),
            &format!(" {ID}"),
            "0b7a2c1e-5d4f-4a3b-9c8d-1e2f3a4b5c6d",
            "",
        ] {
            assert!(bad.parse::<IdentityId>().is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn length_other_than_64_is_an_unknown_scheme() {
        assert_eq!(
            ID[..63].parse::<IdentityId>(),
            Err(IdentityIdParseError::UnknownScheme { length: 63 })
        );
        assert_eq!(
            format!("{ID}\n").parse::<IdentityId>(),
            Err(IdentityIdParseError::UnknownScheme { length: 65 })
        );
        assert_eq!(
            "".parse::<IdentityId>(),
            Err(IdentityIdParseError::UnknownScheme { length: 0 })
        );
        // 32 two-byte characters: 64 bytes, so a malformed id rather than another scheme.
        assert_eq!(
            "é".repeat(32).parse::<IdentityId>(),
            Err(IdentityIdParseError::NotLowercaseHex)
        );
        assert_eq!(
            "é".repeat(33).parse::<IdentityId>(),
            Err(IdentityIdParseError::UnknownScheme { length: 66 })
        );
        assert_eq!(
            ID.to_uppercase().parse::<IdentityId>(),
            Err(IdentityIdParseError::NotLowercaseHex)
        );
    }

    #[test]
    fn serde_rejects_a_uuid() {
        assert!(
            serde_json::from_str::<IdentityId>("\"0b7a2c1e-5d4f-4a3b-9c8d-1e2f3a4b5c6d\"").is_err()
        );
        assert!(serde_json::from_str::<IdentityId>(&format!("\"{ID}\"")).is_ok());
    }

    #[test]
    fn derive_matches_the_shared_vector() {
        let key: [u8; 32] =
            hex::decode("d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48")
                .unwrap()
                .try_into()
                .unwrap();
        let id = IdentityId::derive(&key);
        assert_eq!(id.to_string(), ID);
        assert!(id.matches_key(&key));
        assert!(!id.matches_key(&[1u8; 32]));
    }
}
