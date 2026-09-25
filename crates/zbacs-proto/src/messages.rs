//! The messages themselves (spec §4). Field names match the CBOR keys on the wire.

use serde::{Deserialize, Serialize};

/// Message kind. Part of the signed bytes, so one message's signature cannot be replayed as
/// another kind (spec §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// [`DeviceAnnounce`]
    Announce,
    /// [`AccessRequest`]
    Req,
    /// [`GrantMsg`]
    Grant,
    /// [`Revoke`]
    Revoke,
    /// [`Subscribe`]
    Sub,
    /// [`Ack`]
    Ack,
    /// [`VersionMsg`]
    Version,
}

impl Kind {
    /// The wire string mixed into the signature.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announce => "announce",
            Self::Req => "req",
            Self::Grant => "grant",
            Self::Revoke => "revoke",
            Self::Sub => "sub",
            Self::Ack => "ack",
            Self::Version => "version",
        }
    }
}

/// Implemented by every payload so [`crate::Signed`] can bind the right kind.
pub trait Message: Serialize + for<'de> Deserialize<'de> {
    /// Kind mixed into the signature.
    const KIND: Kind;
}

/// Registers (or refreshes) a device's public keys with the relay (spec §4.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAnnounce {
    /// X25519 public key that receives DEK envelopes.
    #[serde(with = "serde_bytes")]
    pub x25519_pub: [u8; 32],
    /// Ed25519 public key that signs relay envelopes.
    #[serde(with = "serde_bytes")]
    pub ed25519_pub: [u8; 32],
    /// Human label for the "my devices" list, e.g. "업무용 노트북". At most 32 bytes.
    pub label: Option<String>,
    /// Unix seconds.
    pub ts: u64,
}

impl Message for DeviceAnnounce {
    const KIND: Kind = Kind::Announce;
}

/// A recipient asking the owner to open a specific sealed version (spec §4.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRequest {
    /// Container file id.
    #[serde(with = "serde_bytes")]
    pub fid: [u8; 32],
    /// Header hash of the version being opened; the grant is bound to it (T19).
    #[serde(with = "serde_bytes")]
    pub header_hash: [u8; 32],
    /// Owner account identifier, copied from the container header. The relay routes on it.
    #[serde(with = "serde_bytes")]
    pub owner: Vec<u8>,
    /// Requesting device's key id.
    #[serde(with = "serde_bytes")]
    pub device_kid: [u8; 16],
    /// Requesting device's X25519 public key (the DEK envelope target).
    #[serde(with = "serde_bytes")]
    pub x25519_pub: [u8; 32],
    /// Requesting device's Ed25519 public key. With `x25519_pub` it forms the grant's
    /// `deviceKeyHash`, and it lets the owner verify this envelope itself rather than trust the
    /// relay's word (T05). Must hash to `device_kid`.
    #[serde(with = "serde_bytes")]
    pub ed25519_pub: [u8; 32],
    /// 1 = ReadOnly, 2 = Edit.
    pub requested: u8,
    /// Request nonce; the owner copies it into the grant so the answer cannot be re-aimed.
    #[serde(with = "serde_bytes")]
    pub nonce: [u8; 16],
    /// Display hint for the owner (name / device). Encrypted to the owner from Phase 2 (§7).
    #[serde(with = "serde_bytes")]
    pub hint: Option<Vec<u8>>,
    /// Unix seconds.
    pub ts: u64,
}

impl Message for AccessRequest {
    const KIND: Kind = Kind::Req;
}

/// The owner's answer (spec §4.3). `decision == 0` is a refusal and carries no envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantMsg {
    /// Which request this answers.
    #[serde(with = "serde_bytes")]
    pub request_nonce: [u8; 16],
    /// CBOR of the EIP-712 `AccessGrant` the owner signed (approval_protocol §1.2).
    #[serde(with = "serde_bytes")]
    pub grant: Option<Vec<u8>>,
    /// `OwnerSig`: a WebAuthn assertion or a raw P-256 signature (approval_protocol §1.5).
    #[serde(with = "serde_bytes")]
    pub owner_sig: Option<Vec<u8>>,
    /// HPKE envelope carrying the DEK to the requesting device.
    #[serde(with = "serde_bytes")]
    pub envelope: Option<Vec<u8>>,
    /// Hash of the on-chain grant transaction, when one was submitted.
    #[serde(with = "serde_bytes")]
    pub tx_hash: Option<[u8; 32]>,
    /// 0 = Deny, 1 = ReadOnly, 2 = Edit.
    pub decision: u8,
    /// Unix seconds.
    pub ts: u64,
}

impl Message for GrantMsg {
    const KIND: Kind = Kind::Grant;
}

/// Owner pulling access back before expiry (spec §4.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revoke {
    /// EIP-712 struct hash of the grant being revoked.
    #[serde(with = "serde_bytes")]
    pub grant_id: [u8; 32],
    /// File the grant was for.
    #[serde(with = "serde_bytes")]
    pub fid: [u8; 32],
    /// Unix seconds.
    pub ts: u64,
}

impl Message for Revoke {
    const KIND: Kind = Kind::Revoke;
}

/// A recipient tells the owner that it resealed a file as a new version (spec §4.6, Z-1.G.8).
///
/// Carries everything the owner needs to accept the version without the file: the new header
/// hash (what a later grant must name, T19), the previous one (so the owner can check the
/// chain from the version it knew), the grant this edit happened under, and the owner
/// envelope of the new version — the DEK wrapped to the owner's `opub`, so the owner can open
/// or re-grant the new version it has never seen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionMsg {
    /// Container file id.
    #[serde(with = "serde_bytes")]
    pub fid: [u8; 32],
    /// Owner account identifier, copied from the container header. The relay routes on it.
    #[serde(with = "serde_bytes")]
    pub owner: Vec<u8>,
    /// Header hash of the version the recipient started from.
    #[serde(with = "serde_bytes")]
    pub prev_header_hash: [u8; 32],
    /// Header hash of the version it wrote.
    #[serde(with = "serde_bytes")]
    pub header_hash: [u8; 32],
    /// Container version number written.
    pub ver: u32,
    /// EIP-712 struct hash of the grant the edit was made under.
    #[serde(with = "serde_bytes")]
    pub grant_id: [u8; 32],
    /// The new version's owner envelope (`zbacs_core::Envelope`, CBOR), AAD = `fid`.
    #[serde(with = "serde_bytes")]
    pub owner_envelope: Vec<u8>,
    /// Signing device's Ed25519 public key; must hash to the envelope's `kid` (T05).
    #[serde(with = "serde_bytes")]
    pub ed25519_pub: [u8; 32],
    /// Unix seconds.
    pub ts: u64,
}

impl Message for VersionMsg {
    const KIND: Kind = Kind::Version;
}

/// First WebSocket frame (spec §4.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscribe {
    /// Resume cursor from a previous session.
    #[serde(with = "serde_bytes")]
    pub since: Option<Vec<u8>>,
    /// Kinds this client wants.
    pub kinds: Vec<Kind>,
    /// Unix seconds.
    pub ts: u64,
}

impl Message for Subscribe {
    const KIND: Kind = Kind::Sub;
}

/// Relay's answer to a submission (spec §4.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ack {
    /// Whether the relay accepted the message.
    pub ok: bool,
    /// Queue id assigned to it.
    #[serde(with = "serde_bytes")]
    pub id: Option<[u8; 16]>,
    /// Why it was refused.
    pub error: Option<ErrorCode>,
}

impl Message for Ack {
    const KIND: Kind = Kind::Ack;
}

/// One queued message as delivered to a subscriber. `body` is the original signed bytes, so
/// the receiver verifies the sender itself and never has to trust the relay (spec §4.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Queue id.
    #[serde(with = "serde_bytes")]
    pub id: [u8; 16],
    /// Kind of the wrapped message.
    pub kind: Kind,
    /// CBOR of the original `Signed<T>`.
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    /// When the relay queued it (Unix seconds).
    pub queued_at: u64,
}

/// Wire error codes (spec §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Signature missing or invalid.
    Unauthenticated,
    /// Signing key id is not registered.
    UnknownDevice,
    /// Timestamp outside the accepted window.
    Stale,
    /// Nonce already seen.
    Replayed,
    /// Unparseable or out-of-range fields.
    Malformed,
    /// Body over the size limit.
    TooLarge,
    /// Quota exceeded.
    RateLimited,
    /// No such cursor or message.
    NotFound,
    /// Relay fault.
    Internal,
}

impl ErrorCode {
    /// HTTP status a relay returns with this code (spec §5).
    pub fn http_status(self) -> u16 {
        match self {
            Self::Unauthenticated | Self::UnknownDevice => 401,
            Self::Stale | Self::Malformed => 400,
            Self::Replayed => 409,
            Self::TooLarge => 413,
            Self::RateLimited => 429,
            Self::NotFound => 404,
            Self::Internal => 500,
        }
    }
}
