//! Structured signing bytes: one fixed binary layout for every signed or hashed message.
//!
//! Layout: `tag` (ASCII, no length) | `layout_version: u16 BE` | `rules_version: u32 BE` | fields |
//! extensions region (`count u16`, then `ext_type u16`, `flags u8`, `len u32`, value per entry).
//! Strings and byte strings are `u32 BE` length + bytes, keys and signatures carry an algorithm
//! byte, hashes and UUIDs are raw, integers are fixed-width big-endian. Mirrors
//! `avalon_protocol::signing_bytes`, pinned by `structured-signing-bytes.json`, `envelope.json`
//! and `domain-tags.json`. Tags are prefix-free, and a new field set means a new layout version.

use std::ops::RangeInclusive;

use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// The rules version this SDK authors under. Emitted in every header.
pub const RULES_VERSION: u32 = 1;
/// The lowest rules version a reader still verifies.
pub const RULES_VERSION_MIN: u32 = 1;
/// The highest rules version a reader understands; anything above is [`SigningBytesError::NeedsNewerVersion`].
pub const RULES_VERSION_MAX: u32 = 1;

const EXTENSION_ENTRY_HEADER: usize = 7;
const CRITICAL_FLAG: u8 = 0x01;

/// Consensus size caps, always read through [`caps_for`] for the message's own rules version.
/// A cap may be raised only for entries authored under a newer rules version; a lower cap never
/// invalidates what an older rules version already allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// Upper bound on the extension entries of one message (each entry counts its 7 header bytes).
    pub max_extension_bytes: usize,
}

/// `(first rules version, caps)` rows, ascending. A version uses the last row at or below it.
const CAPS_TABLE: &[(u32, Caps)] = &[(
    1,
    Caps {
        max_extension_bytes: 4096,
    },
)];

/// The caps that apply to a message authored under `rules_version`.
pub fn caps_for(rules_version: u32) -> Caps {
    caps_in(CAPS_TABLE, rules_version)
}

fn caps_in(table: &[(u32, Caps)], rules_version: u32) -> Caps {
    table
        .iter()
        .rev()
        .find(|(from, _)| *from <= rules_version)
        .or(table.first())
        .map(|(_, caps)| *caps)
        .expect("caps table has a row")
}

/// Which part of a message needs a newer version than this node has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionKind {
    /// The layout version.
    Layout,
    /// The rules version.
    Rules,
    /// The hash algorithm byte.
    HashAlgo,
    /// An unknown key or signature algorithm tag.
    SigAlgo,
    /// A critical extension this node does not understand; `required` is its `ext_type`.
    CriticalExtension,
}

/// Why building or reading structured signing bytes failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SigningBytesError {
    #[error("a field is longer than u32::MAX bytes")]
    /// A string or byte field exceeds the `u32` length prefix.
    FieldTooLong,
    #[error("message does not start with the expected domain tag")]
    /// The message does not begin with the expected tag.
    TagMismatch,
    #[error("message ends before the field does")]
    /// The message ends before a field does.
    Truncated,
    #[error("string field is not valid UTF-8")]
    /// A string field is not valid UTF-8.
    InvalidUtf8,
    #[error("bytes remain after the last field")]
    /// Bytes remain after the extensions region.
    TrailingBytes,
    /// Nothing was verified: the message needs a layout, rules version, hash algorithm or
    /// extension this node does not have.
    #[error("needs a newer version: {what:?} {required}")]
    NeedsNewerVersion {
        /// Which part needs the newer version.
        what: VersionKind,
        /// The version, algorithm id or extension type that is required.
        required: u32,
    },
    /// A layout or rules version below what this node still supports.
    #[error("unsupported {what:?} {value}")]
    UnsupportedVersion {
        /// Which part is below the supported range.
        what: VersionKind,
        /// The unsupported value.
        value: u32,
    },
    #[error("extensions are not in ascending ext_type order")]
    /// Extensions are not in ascending type order.
    ExtensionsUnsorted,
    #[error("duplicate extension type {0}")]
    /// Two extensions share a type.
    ExtensionDuplicate(u16),
    #[error("extension flags {0:#04x} set a reserved bit")]
    /// An extension sets a reserved flag bit.
    ExtensionReservedFlags(u8),
    #[error("extensions exceed the size bound")]
    /// The extension entries exceed the size cap.
    ExtensionsTooLarge,
    /// A wire or stored hex field is not lowercase hex of whole bytes.
    #[error("not lowercase hex")]
    InvalidHex,
}

impl SigningBytesError {
    /// The typed "needs a newer version" result, when that is what this error is.
    pub fn needs_newer_version(&self) -> Option<(VersionKind, u32)> {
        match self {
            Self::NeedsNewerVersion { what, required } => Some((*what, *required)),
            _ => None,
        }
    }
}

/// Hash algorithm named by a layout's `hash_algo` byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    /// SHA-256.
    Sha256,
}

impl HashAlgo {
    /// The algorithm byte.
    pub const fn id(self) -> u8 {
        match self {
            Self::Sha256 => 0x01,
        }
    }

    /// Any other value is a hash algorithm this node does not know.
    pub fn from_id(id: u8) -> Result<Self, SigningBytesError> {
        match id {
            0x01 => Ok(Self::Sha256),
            other => Err(SigningBytesError::NeedsNewerVersion {
                what: VersionKind::HashAlgo,
                required: u32::from(other),
            }),
        }
    }

    /// Hashes `data` with this algorithm.
    pub fn digest(self, data: &[u8]) -> [u8; 32] {
        match self {
            Self::Sha256 => Sha256::digest(data).into(),
        }
    }
}

/// Algorithm tag written next to every public key and signature (`0x01` = Ed25519).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAlgo {
    /// Ed25519.
    Ed25519,
}

impl SigAlgo {
    /// The algorithm byte.
    pub const fn id(self) -> u8 {
        match self {
            Self::Ed25519 => 0x01,
        }
    }

    /// Any other value is an algorithm this node does not know.
    pub fn from_id(id: u8) -> Result<Self, SigningBytesError> {
        match id {
            0x01 => Ok(Self::Ed25519),
            other => Err(SigningBytesError::NeedsNewerVersion {
                what: VersionKind::SigAlgo,
                required: u32::from(other),
            }),
        }
    }
}

/// One extension entry. Reserved flag bits are not representable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// The extension type.
    pub ext_type: u16,
    /// Whether a reader that does not understand it must refuse the message.
    pub critical: bool,
    /// The extension value bytes.
    pub value: Vec<u8>,
}

/// The extensions region: entries strictly ascending by type, bounded by [`Caps::max_extension_bytes`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Extensions(Vec<Extension>);

impl Extensions {
    /// No extensions.
    pub fn none() -> Self {
        Self::default()
    }

    /// Validates order, uniqueness and the size bound for `rules_version`.
    pub fn new(entries: Vec<Extension>, rules_version: u32) -> Result<Self, SigningBytesError> {
        // Same order as the reader: size per entry first, then ascending order and duplicates.
        let max = caps_for(rules_version).max_extension_bytes;
        let mut total = 0usize;
        for e in &entries {
            total = total.saturating_add(EXTENSION_ENTRY_HEADER.saturating_add(e.value.len()));
            if total > max {
                return Err(SigningBytesError::ExtensionsTooLarge);
            }
        }
        if entries.len() > usize::from(u16::MAX) {
            return Err(SigningBytesError::ExtensionsTooLarge);
        }
        for pair in entries.windows(2) {
            if pair[0].ext_type == pair[1].ext_type {
                return Err(SigningBytesError::ExtensionDuplicate(pair[1].ext_type));
            }
            if pair[0].ext_type > pair[1].ext_type {
                return Err(SigningBytesError::ExtensionsUnsorted);
            }
        }
        Ok(Self(entries))
    }

    /// Entries.
    pub fn entries(&self) -> &[Extension] {
        &self.0
    }

    /// Is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The region as hashed: `count u16` then each entry.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.0.len() as u16).to_be_bytes());
        for e in &self.0 {
            out.extend_from_slice(&e.ext_type.to_be_bytes());
            out.push(if e.critical { CRITICAL_FLAG } else { 0 });
            out.extend_from_slice(&(e.value.len() as u32).to_be_bytes());
            out.extend_from_slice(&e.value);
        }
        out
    }

    /// Parses a whole region; bytes after the last entry are an error.
    pub fn decode(bytes: &[u8], rules_version: u32) -> Result<Self, SigningBytesError> {
        let mut reader = ByteCursor { rest: bytes };
        let ext = reader.extensions(rules_version)?;
        if reader.rest.is_empty() {
            Ok(ext)
        } else {
            Err(SigningBytesError::TrailingBytes)
        }
    }

    /// Errors with the typed result for the first critical extension `tag` does not understand.
    pub fn require_understood(&self, tag: DomainTag) -> Result<(), SigningBytesError> {
        match self
            .0
            .iter()
            .find(|e| e.critical && !understood_extensions(tag).contains(&e.ext_type))
        {
            Some(e) => Err(SigningBytesError::NeedsNewerVersion {
                what: VersionKind::CriticalExtension,
                required: u32::from(e.ext_type),
            }),
            None => Ok(()),
        }
    }
}

/// Critical extension types each tag understands. None are defined yet.
pub fn understood_extensions(_tag: DomainTag) -> &'static [u16] {
    &[]
}

/// The header values of a stored or received message, recorded next to it so verification
/// never guesses a layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The layout version written in the header.
    pub layout_version: u16,
    /// The rules version written in the header.
    pub rules_version: u32,
    /// The `hash_algo` byte.
    pub hash_algo: HashAlgo,
    /// Extensions.
    pub extensions: Extensions,
}

impl Envelope {
    /// What this node authors for `tag`: its newest layout, [`RULES_VERSION`], SHA-256, no extensions.
    pub fn current(tag: DomainTag) -> Self {
        Self {
            layout_version: *layout_versions(tag).end(),
            rules_version: RULES_VERSION,
            hash_algo: HashAlgo::Sha256,
            extensions: Extensions::none(),
        }
    }

    /// Rebuilds from stored or wire values, checking `layout_version` and `rules_version`
    /// against this node's ranges, the hash algorithm and the extension region.
    pub fn from_parts(
        tag: DomainTag,
        layout_version: u16,
        rules_version: u32,
        hash_algo: u8,
        extensions: &[u8],
    ) -> Result<Self, SigningBytesError> {
        check_layout(tag, layout_version)?;
        check_rules(rules_version)?;
        let extensions = Extensions::decode(extensions, rules_version)?;
        extensions.require_understood(tag)?;
        Ok(Self {
            layout_version,
            rules_version,
            hash_algo: HashAlgo::from_id(hash_algo)?,
            extensions,
        })
    }
}

/// An [`Envelope`] as it travels in JSON and sits in stored rows: plain integers and hex.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EnvelopeWire {
    /// The layout version written in the header.
    pub layout_version: u16,
    /// The rules version written in the header.
    pub rules_version: u32,
    /// The `hash_algo` byte.
    pub hash_algo: u8,
    /// Hex of the extensions region; `0000` when there are none.
    pub extensions: String,
}

impl From<&Envelope> for EnvelopeWire {
    fn from(envelope: &Envelope) -> Self {
        Self {
            layout_version: envelope.layout_version,
            rules_version: envelope.rules_version,
            hash_algo: envelope.hash_algo.id(),
            extensions: hex::encode(envelope.extensions.encode()),
        }
    }
}

/// Decodes lowercase hex of whole bytes; uppercase, odd length and non-hex are [`SigningBytesError::InvalidHex`],
/// so a wire field has exactly one spelling.
pub fn decode_lower_hex(text: &str) -> Result<Vec<u8>, SigningBytesError> {
    if text.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(SigningBytesError::InvalidHex);
    }
    hex::decode(text).map_err(|_| SigningBytesError::InvalidHex)
}

impl EnvelopeWire {
    /// Checks every part against this node's ranges; the typed "needs a newer version" result
    /// for anything above them.
    pub fn to_envelope(&self, tag: DomainTag) -> Result<Envelope, SigningBytesError> {
        let extensions = decode_lower_hex(&self.extensions)?;
        Envelope::from_parts(
            tag,
            self.layout_version,
            self.rules_version,
            self.hash_algo,
            &extensions,
        )
    }
}

/// Supported layout versions per tag. Lower versions stay verifiable forever; a tag's first
/// version is 1. Every registered tag has a row (a test enforces it).
pub fn layout_versions(tag: DomainTag) -> RangeInclusive<u16> {
    // The conformance tag spans 1..=2 so vectors can show an older layout verifying beside the newest.
    if tag == tags::CONFORMANCE {
        return 1..=2;
    }
    assert!(tags::ALL.contains(&tag), "unregistered tag");
    1..=1
}

/// The highest layout version each tag has a builder for (0 = no builder yet, the tag still
/// builds legacy text). Raising a tag's range in [`layout_versions`] above 1 requires a builder that
/// emits that version's field order, selected by `match layout_version`, and a bump here.
pub const BUILT_LAYOUT_VERSIONS: &[(DomainTag, u16)] = &[
    (tags::IDENTITY_CREATED, 1),
    (tags::DEVICE_GRANT_APPROVED, 1),
    (tags::IDENTITY_SIGNING_KEY_REVOKED, 1),
    (tags::CROSS_NODE_LOGIN, 0),
    (tags::SESSION_CONTINUATION, 0),
    (tags::INTEREST_CLAIM, 0),
    (tags::ATTESTATION_ISSUE, 1),
    (tags::ATTESTATION_BULK_ISSUE, 1),
    (tags::ATTESTATION_REVOKE, 1),
    (tags::ISSUER_REGISTERED, 0),
    (tags::SIGNATURE_GATE_ACTION, 0),
    (tags::INTEGRATOR_NONCE_CHALLENGE, 0),
    (tags::LEDGER_ENTRY, 1),
    (tags::IDENTITY_CHAIN_EVENT, 1),
    (tags::IDENTITY_KEY_EVENT, 1),
    (tags::SETTLEMENT_STH, 1),
    (tags::WITNESS_COSIGN, 1),
    (tags::WITNESS_ANNOUNCE, 1),
    // The conformance tag is built by the generic Builder at any layout version in its range.
    (tags::CONFORMANCE, 2),
];

fn check_layout(tag: DomainTag, version: u16) -> Result<(), SigningBytesError> {
    let range = layout_versions(tag);
    if version > *range.end() {
        Err(SigningBytesError::NeedsNewerVersion {
            what: VersionKind::Layout,
            required: u32::from(version),
        })
    } else if version < *range.start() {
        Err(SigningBytesError::UnsupportedVersion {
            what: VersionKind::Layout,
            value: u32::from(version),
        })
    } else {
        Ok(())
    }
}

fn check_rules(version: u32) -> Result<(), SigningBytesError> {
    if version > RULES_VERSION_MAX {
        Err(SigningBytesError::NeedsNewerVersion {
            what: VersionKind::Rules,
            required: version,
        })
    } else if version < RULES_VERSION_MIN {
        Err(SigningBytesError::UnsupportedVersion {
            what: VersionKind::Rules,
            value: version,
        })
    } else {
        Ok(())
    }
}

/// The registry of domain tags: one distinct tag per signed kind.
pub mod tags {
    use super::DomainTag;

    /// Identity created.
    pub const IDENTITY_CREATED: DomainTag = DomainTag::new("avalon.identity.created");
    /// Device grant approved.
    pub const DEVICE_GRANT_APPROVED: DomainTag = DomainTag::new("avalon.device_grant.approved");
    /// Identity signing key revoked.
    pub const IDENTITY_SIGNING_KEY_REVOKED: DomainTag =
        DomainTag::new("avalon.identity.signing_key_revoked");
    /// Cross node login.
    pub const CROSS_NODE_LOGIN: DomainTag = DomainTag::new("avalon.cross_node_login");
    /// Session continuation.
    pub const SESSION_CONTINUATION: DomainTag = DomainTag::new("avalon.session_continuation");
    /// Interest claim.
    pub const INTEREST_CLAIM: DomainTag = DomainTag::new("avalon.interest_claim");
    /// Attestation issue.
    pub const ATTESTATION_ISSUE: DomainTag = DomainTag::new("avalon.attestation.issue");
    /// Attestation bulk issue.
    pub const ATTESTATION_BULK_ISSUE: DomainTag = DomainTag::new("avalon.attestation.bulk_issue");
    /// Attestation revoke.
    pub const ATTESTATION_REVOKE: DomainTag = DomainTag::new("avalon.attestation.revoke");
    /// Issuer registered.
    pub const ISSUER_REGISTERED: DomainTag = DomainTag::new("avalon.issuer.registered");
    /// Signature gate action.
    pub const SIGNATURE_GATE_ACTION: DomainTag = DomainTag::new("avalon.signature_gate.action");
    /// Integrator nonce challenge.
    pub const INTEGRATOR_NONCE_CHALLENGE: DomainTag =
        DomainTag::new("avalon.integrator.nonce_challenge");
    /// Ledger entry.
    pub const LEDGER_ENTRY: DomainTag = DomainTag::new("avalon.ledger.entry");
    /// Identity chain event.
    pub const IDENTITY_CHAIN_EVENT: DomainTag = DomainTag::new("avalon.identity.chain_event");
    /// Identity key event.
    pub const IDENTITY_KEY_EVENT: DomainTag = DomainTag::new("avalon.identity.key_event");
    /// Settlement sth.
    pub const SETTLEMENT_STH: DomainTag = DomainTag::new("avalon.settlement.sth");
    /// Witness cosign.
    pub const WITNESS_COSIGN: DomainTag = DomainTag::new("avalon.witness.cosign");
    /// Witness announce.
    pub const WITNESS_ANNOUNCE: DomainTag = DomainTag::new("avalon.witness.announce");
    /// Reserved for conformance vectors; no key ever signs it in production.
    pub const CONFORMANCE: DomainTag = DomainTag::new("avalon.conformance.vector");

    /// Every registered tag; the uniqueness test walks this list.
    pub const ALL: &[DomainTag] = &[
        IDENTITY_CREATED,
        DEVICE_GRANT_APPROVED,
        IDENTITY_SIGNING_KEY_REVOKED,
        CROSS_NODE_LOGIN,
        SESSION_CONTINUATION,
        INTEREST_CLAIM,
        ATTESTATION_ISSUE,
        ATTESTATION_BULK_ISSUE,
        ATTESTATION_REVOKE,
        ISSUER_REGISTERED,
        SIGNATURE_GATE_ACTION,
        INTEGRATOR_NONCE_CHALLENGE,
        LEDGER_ENTRY,
        IDENTITY_CHAIN_EVENT,
        IDENTITY_KEY_EVENT,
        SETTLEMENT_STH,
        WITNESS_COSIGN,
        WITNESS_ANNOUNCE,
        CONFORMANCE,
    ];
}

/// A registered domain tag. Only [`tags`] can construct one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainTag(&'static str);

impl DomainTag {
    /// Checked at compile time: 1 to 255 bytes of `[a-z0-9._]`.
    const fn new(tag: &'static str) -> Self {
        let bytes = tag.as_bytes();
        assert!(!bytes.is_empty() && bytes.len() <= 255, "bad tag length");
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            assert!(
                b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_',
                "tag bytes must be [a-z0-9._]"
            );
            i += 1;
        }
        Self(tag)
    }

    /// As str.
    pub const fn as_str(&self) -> &'static str {
        self.0
    }

    /// As bytes.
    pub const fn as_bytes(&self) -> &'static [u8] {
        self.0.as_bytes()
    }
}

fn length_prefix(len: usize) -> Result<u32, SigningBytesError> {
    u32::try_from(len).map_err(|_| SigningBytesError::FieldTooLong)
}

/// Writes the header, then fields in call order, then the extensions region. The first error
/// sticks and is returned by [`Builder::finish`].
#[derive(Debug)]
pub struct Builder {
    tag: DomainTag,
    rules_version: u32,
    out: Vec<u8>,
    extensions: Vec<Extension>,
    error: Option<SigningBytesError>,
}

impl Builder {
    /// A header at this node's [`RULES_VERSION`].
    pub fn new(tag: DomainTag, layout_version: u16) -> Self {
        Self::with_rules(tag, layout_version, RULES_VERSION)
    }

    /// A header with an explicit rules version, for rebuilding a stored message.
    pub fn with_rules(tag: DomainTag, layout_version: u16, rules_version: u32) -> Self {
        let mut out = Vec::with_capacity(tag.as_bytes().len() + 6);
        out.extend_from_slice(tag.as_bytes());
        out.extend_from_slice(&layout_version.to_be_bytes());
        out.extend_from_slice(&rules_version.to_be_bytes());
        let error = check_layout(tag, layout_version)
            .and_then(|()| check_rules(rules_version))
            .err();
        Self {
            tag,
            rules_version,
            out,
            extensions: Vec::new(),
            error,
        }
    }

    /// The header and extensions of a stored [`Envelope`]; its `hash_algo` is written by
    /// [`Builder::hash_algo`] where the layout places it.
    pub fn with_envelope(tag: DomainTag, envelope: &Envelope) -> Self {
        let mut builder = Self::with_rules(tag, envelope.layout_version, envelope.rules_version);
        builder.extensions = envelope.extensions.0.clone();
        builder
    }

    /// The hash algorithm byte; call it immediately before the first hash-valued field.
    pub fn hash_algo(self, algo: HashAlgo) -> Self {
        self.u8(algo.id())
    }

    /// Adds an extension. Entries must be added in ascending `ext_type` order.
    pub fn extension(mut self, ext_type: u16, critical: bool, value: &[u8]) -> Self {
        self.extensions.push(Extension {
            ext_type,
            critical,
            value: value.to_vec(),
        });
        self
    }

    /// UTF-8 text, `u32 BE` length then bytes.
    pub fn str(self, value: &str) -> Self {
        self.bytes(value.as_bytes())
    }

    /// Variable-length bytes, `u32 BE` length then bytes.
    pub fn bytes(mut self, value: &[u8]) -> Self {
        match length_prefix(value.len()) {
            Ok(len) => {
                self.out.extend_from_slice(&len.to_be_bytes());
                self.out.extend_from_slice(value);
            }
            Err(e) => self.error = self.error.or(Some(e)),
        }
        self
    }

    /// A fixed-width field written raw with no length (`N` is part of the layout).
    pub fn fixed<const N: usize>(mut self, value: &[u8; N]) -> Self {
        self.out.extend_from_slice(value);
        self
    }

    /// An Ed25519 public key: `alg u8` then 32 raw bytes. The only place keys are written.
    pub fn key(self, value: &[u8; 32]) -> Self {
        self.u8(SigAlgo::Ed25519.id()).fixed(value)
    }

    /// An Ed25519 signature: `alg u8` then 64 raw bytes. The only place signatures are written.
    pub fn signature(self, value: &[u8; 64]) -> Self {
        self.u8(SigAlgo::Ed25519.id()).fixed(value)
    }

    /// A 32-byte hash, raw.
    pub fn hash(self, value: &[u8; 32]) -> Self {
        self.fixed(value)
    }

    /// A UUID as its 16 raw bytes.
    pub fn uuid(self, value: Uuid) -> Self {
        self.fixed(value.as_bytes())
    }

    /// Writes a `u8`.
    pub fn u8(self, value: u8) -> Self {
        self.fixed(&[value])
    }

    /// Writes a `u16` BE.
    pub fn u16(self, value: u16) -> Self {
        self.fixed(&value.to_be_bytes())
    }

    /// Writes a `u32` BE.
    pub fn u32(self, value: u32) -> Self {
        self.fixed(&value.to_be_bytes())
    }

    /// Writes a `u64` BE.
    pub fn u64(self, value: u64) -> Self {
        self.fixed(&value.to_be_bytes())
    }

    /// Writes an `i64` BE.
    pub fn i64(self, value: i64) -> Self {
        self.fixed(&value.to_be_bytes())
    }

    /// Appends the extensions region and returns the bytes. Fails with the typed result when
    /// a critical extension is not understood for the tag.
    pub fn finish(mut self) -> Result<Vec<u8>, SigningBytesError> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let extensions = Extensions::new(self.extensions, self.rules_version)?;
        extensions.require_understood(self.tag)?;
        self.out.extend_from_slice(&extensions.encode());
        Ok(self.out)
    }
}

#[derive(Debug)]
struct ByteCursor<'a> {
    rest: &'a [u8],
}

impl<'a> ByteCursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], SigningBytesError> {
        if self.rest.len() < len {
            return Err(SigningBytesError::Truncated);
        }
        let (head, tail) = self.rest.split_at(len);
        self.rest = tail;
        Ok(head)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], SigningBytesError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn extensions(&mut self, rules_version: u32) -> Result<Extensions, SigningBytesError> {
        let max = caps_for(rules_version).max_extension_bytes;
        let count = u16::from_be_bytes(self.take_array()?);
        let mut entries = Vec::new();
        let mut total = 0usize;
        for _ in 0..count {
            let ext_type = u16::from_be_bytes(self.take_array()?);
            let [flags] = self.take_array()?;
            if flags & !CRITICAL_FLAG != 0 {
                return Err(SigningBytesError::ExtensionReservedFlags(flags));
            }
            let len = u32::from_be_bytes(self.take_array()?) as usize;
            total = total.saturating_add(EXTENSION_ENTRY_HEADER.saturating_add(len));
            if total > max {
                return Err(SigningBytesError::ExtensionsTooLarge);
            }
            entries.push(Extension {
                ext_type,
                critical: flags & CRITICAL_FLAG != 0,
                value: self.take(len)?.to_vec(),
            });
        }
        Extensions::new(entries, rules_version)
    }
}

/// Reads fields in the order the layout defines. Never allocates from a
/// declared length before checking it fits in the remaining bytes.
#[derive(Debug)]
pub struct Reader<'a> {
    tag: DomainTag,
    cur: ByteCursor<'a>,
    layout_version: u16,
    rules_version: u32,
}

impl<'a> Reader<'a> {
    /// Checks the tag, then the layout and rules versions against this node's ranges. A version
    /// above them is [`SigningBytesError::NeedsNewerVersion`] before any field is read.
    pub fn new(tag: DomainTag, message: &'a [u8]) -> Result<Self, SigningBytesError> {
        let rest = message
            .strip_prefix(tag.as_bytes())
            .ok_or(SigningBytesError::TagMismatch)?;
        let mut reader = Self {
            tag,
            cur: ByteCursor { rest },
            layout_version: 0,
            rules_version: 0,
        };
        reader.layout_version = u16::from_be_bytes(reader.take_array()?);
        check_layout(tag, reader.layout_version)?;
        reader.rules_version = u32::from_be_bytes(reader.take_array()?);
        check_rules(reader.rules_version)?;
        Ok(reader)
    }

    /// The layout version read from the header.
    pub fn layout_version(&self) -> u16 {
        self.layout_version
    }

    /// The rules version read from the header.
    pub fn rules_version(&self) -> u32 {
        self.rules_version
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], SigningBytesError> {
        self.cur.take(len)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], SigningBytesError> {
        self.cur.take_array()
    }

    /// Reads length-prefixed bytes.
    pub fn bytes(&mut self) -> Result<&'a [u8], SigningBytesError> {
        let len = u32::from_be_bytes(self.take_array()?);
        self.take(len as usize)
    }

    /// Reads length-prefixed UTF-8 text.
    pub fn str(&mut self) -> Result<&'a str, SigningBytesError> {
        std::str::from_utf8(self.bytes()?).map_err(|_| SigningBytesError::InvalidUtf8)
    }

    /// Fixed.
    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N], SigningBytesError> {
        self.take_array()
    }

    /// A public key; an unknown algorithm tag is the typed "needs a newer version" result.
    pub fn key(&mut self) -> Result<[u8; 32], SigningBytesError> {
        SigAlgo::from_id(self.u8()?)?;
        self.take_array()
    }

    /// A signature; an unknown algorithm tag is the typed "needs a newer version" result.
    pub fn signature(&mut self) -> Result<[u8; 64], SigningBytesError> {
        SigAlgo::from_id(self.u8()?)?;
        self.take_array()
    }

    /// A 32-byte hash, raw.
    pub fn hash(&mut self) -> Result<[u8; 32], SigningBytesError> {
        self.take_array()
    }

    /// The `hash_algo` byte; an unknown value is the typed "needs a newer version" result.
    pub fn hash_algo(&mut self) -> Result<HashAlgo, SigningBytesError> {
        HashAlgo::from_id(self.u8()?)
    }

    /// Reads a UUID from 16 raw bytes.
    pub fn uuid(&mut self) -> Result<Uuid, SigningBytesError> {
        Ok(Uuid::from_bytes(self.take_array()?))
    }

    /// Reads a `u8`.
    pub fn u8(&mut self) -> Result<u8, SigningBytesError> {
        Ok(u8::from_be_bytes(self.take_array()?))
    }

    /// Reads a `u16` BE.
    pub fn u16(&mut self) -> Result<u16, SigningBytesError> {
        Ok(u16::from_be_bytes(self.take_array()?))
    }

    /// Reads a `u32` BE.
    pub fn u32(&mut self) -> Result<u32, SigningBytesError> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    /// Reads a `u64` BE.
    pub fn u64(&mut self) -> Result<u64, SigningBytesError> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }

    /// Reads an `i64` BE.
    pub fn i64(&mut self) -> Result<i64, SigningBytesError> {
        Ok(i64::from_be_bytes(self.take_array()?))
    }

    /// Reads the extensions region, which must be all that remains. Unknown critical extensions
    /// are the typed "needs a newer version" result; unknown non-critical ones are returned
    /// for the caller to keep.
    pub fn finish(mut self) -> Result<Extensions, SigningBytesError> {
        let extensions = self.cur.extensions(self.rules_version)?;
        if !self.cur.rest.is_empty() {
            return Err(SigningBytesError::TrailingBytes);
        }
        extensions.require_understood(self.tag)?;
        Ok(extensions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_unique_and_prefix_free() {
        for (i, a) in tags::ALL.iter().enumerate() {
            for b in &tags::ALL[i + 1..] {
                assert!(
                    !a.as_bytes().starts_with(b.as_bytes())
                        && !b.as_bytes().starts_with(a.as_bytes()),
                    "{} and {} collide or share a prefix",
                    a.as_str(),
                    b.as_str()
                );
            }
        }
    }

    #[test]
    fn round_trips_every_field_type() {
        let id = Uuid::from_u128(7);
        let msg = Builder::new(tags::CONFORMANCE, 2)
            .str("a:b,c\0d")
            .bytes(&[])
            .key(&[9; 32])
            .uuid(id)
            .u8(1)
            .u16(2)
            .u32(3)
            .u64(u64::MAX)
            .i64(i64::MIN)
            .finish()
            .unwrap();
        let mut r = Reader::new(tags::CONFORMANCE, &msg).unwrap();
        assert_eq!(r.layout_version(), 2);
        assert_eq!(r.rules_version(), RULES_VERSION);
        assert_eq!(r.str().unwrap(), "a:b,c\0d");
        assert_eq!(r.bytes().unwrap(), b"");
        assert_eq!(r.key().unwrap(), [9; 32]);
        assert_eq!(r.uuid().unwrap(), id);
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(r.u16().unwrap(), 2);
        assert_eq!(r.u32().unwrap(), 3);
        assert_eq!(r.u64().unwrap(), u64::MAX);
        assert_eq!(r.i64().unwrap(), i64::MIN);
        assert!(r.finish().unwrap().is_empty());
    }

    #[test]
    fn reader_rejects_malformed_input() {
        let ok = Builder::new(tags::CONFORMANCE, 1)
            .str("ab")
            .finish()
            .unwrap();
        assert_eq!(
            Reader::new(tags::INTEREST_CLAIM, &ok).unwrap_err(),
            SigningBytesError::TagMismatch
        );
        let mut r = Reader::new(tags::CONFORMANCE, &ok[..ok.len() - 3]).unwrap();
        assert_eq!(r.str().unwrap_err(), SigningBytesError::Truncated);
        let r = Reader::new(tags::CONFORMANCE, &ok).unwrap();
        assert_eq!(r.finish().unwrap_err(), SigningBytesError::TrailingBytes);
    }

    #[test]
    fn newer_layout_is_reported_before_fields() {
        let mut msg = tags::CONFORMANCE.as_bytes().to_vec();
        msg.extend_from_slice(&[0, 3, 0, 0, 0, 1]);
        assert_eq!(
            Reader::new(tags::CONFORMANCE, &msg)
                .unwrap_err()
                .needs_newer_version(),
            Some((VersionKind::Layout, 3))
        );
    }

    #[test]
    fn length_prefix_rejects_over_u32() {
        assert_eq!(length_prefix(u32::MAX as usize), Ok(u32::MAX));
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            length_prefix(u32::MAX as usize + 1),
            Err(SigningBytesError::FieldTooLong)
        );
    }
}
