//! Z-BACS relay wire protocol: the CBOR messages agents exchange through an untrusted relay,
//! and the Ed25519 envelope that authenticates them.
//!
//! Spec: `docs/specs/relay_protocol.md`. Task: Z-1.R.1.
//!
//! The relay routes on a few outer fields and never needs to understand a payload. Security
//! comes from two places that bypass it entirely: the owner's EIP-712 `AccessGrant` signature
//! and the HPKE envelope that only the requesting device can open (T04, T05). Everything here
//! is therefore about *authenticating the sender* and *refusing replays*, not about trust.
//!
//! ```
//! use zbacs_proto::{AccessRequest, DeviceIdentity, Signed};
//! let device = DeviceIdentity::generate().unwrap();
//! let req = AccessRequest {
//!     fid: [1; 32],
//!     header_hash: [2; 32],
//!     owner: b"eip155:8453:0xA11CE".to_vec(),
//!     device_kid: device.kid(),
//!     x25519_pub: device.x25519_pub(),
//!     ed25519_pub: device.ed25519_pub(),
//!     requested: 1,
//!     nonce: [3; 16],
//!     hint: None,
//!     ts: 1_700_000_000,
//! };
//! let signed = Signed::sign(&device, &req, 1_700_000_000, [4; 16]).unwrap();
//! let (verified, _) = signed.verify::<AccessRequest>(&device.ed25519_pub(), 1_700_000_030).unwrap();
//! assert_eq!(verified.fid, [1; 32]);
//! ```

#![warn(missing_docs)]

pub mod error;
pub mod grant;
pub mod identity;
pub mod messages;
pub mod signed;

pub use error::ProtoError;
pub use grant::{device_key_hash, AccessGrantTerms};
pub use identity::DeviceIdentity;
pub use messages::{
    AccessRequest, Ack, DeviceAnnounce, Envelope, ErrorCode, GrantMsg, Kind, Revoke, Subscribe, VersionMsg,
};
pub use signed::Signed;

/// Domain separation prefix for relay envelope signatures (spec §3).
pub const RELAY_SIG_DOMAIN: &[u8] = b"ZBACS-RLY-v1";
/// Maximum accepted body size, envelope included (spec §6).
pub const MAX_BODY_LEN: usize = 64 * 1024;
/// Accepted clock skew for `ts`, in seconds (spec §1).
pub const MAX_SKEW_SECS: u64 = 120;
/// How long a relay remembers nonces, in seconds (spec §6).
pub const NONCE_MEMORY_SECS: u64 = 300;
