//! Z-BACS core: `.zbacs` container format v1, chunked XChaCha20-Poly1305 streams,
//! HPKE (RFC 9180) key envelopes and Ed25519-signed headers.
//!
//! Spec: `docs/specs/container_format.md`. Tasks: Z-0.C.1 (container PoC), Z-0.C.2 (HPKE envelope).
//!
//! Security notes
//! - All key material lives in [`zeroize`]-on-drop wrappers.
//! - No cryptographic primitive is implemented here; only composition (ADR-0002).
//! - Never log plaintext, DEKs or private keys.

pub mod container;
pub mod envelope;
pub mod error;
pub mod header;
pub mod keys;

pub use container::{open, seal, seal_to_path, Opened, SealOptions};
pub use error::Error;
pub use header::{Header, HeaderBody, Permission, Policy, MAGIC, VERSION_MAJOR, VERSION_MINOR};
pub use keys::{Dek, DeviceKeys, OwnerKeys, SigningKeys};

/// Default plaintext chunk size (64 KiB) — spec §2.2 `chunk`.
pub const DEFAULT_CHUNK: usize = 64 * 1024;
/// Upper bound accepted for a serialized header (spec §4 step 1).
pub const MAX_HEADER_LEN: usize = 1024 * 1024;
/// Domain separation prefix for header signatures (spec §2.2 `sig`).
pub const HDR_SIG_DOMAIN: &[u8] = b"ZBACS-HDR-v1";
/// HPKE `info` string for DEK envelopes (spec §3 step 3).
pub const DEK_INFO: &[u8] = b"zbacs-dek-v1";
