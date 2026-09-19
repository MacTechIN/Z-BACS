//! Z-BACS core: `.zbacs` container format v1, chunked XChaCha20-Poly1305 streams,
//! HPKE (RFC 9180) key envelopes and Ed25519-signed headers.
//!
//! Spec: `docs/specs/container_format.md`. Tasks: Z-0.C.1/C.2 (PoC), Z-1.C.1 (this API).
//!
//! # Entry points
//! - [`seal`] / [`seal_to_path`] — owner seals a plaintext; the DEK is wrapped in the owner's
//!   self-envelope (and any extra recipients).
//! - [`open`] — decrypt through an embedded envelope; [`open_with_dek`] — decrypt with a DEK
//!   received out-of-band in a grant; [`inspect`] — read the header without any key.
//! - [`reseal_to_path`] — write the edited plaintext back as the next version (new DEK,
//!   `ver + 1`, atomic replace); [`verify_version_chain`] — check a `v1 → v2 → …` chain.
//! - [`Sealer`] / [`Opener`] — object-safe traits over the above for the Agent.
//!
//! # Security notes
//! - All key material lives in [`zeroize`]-on-drop wrappers.
//! - No cryptographic primitive is implemented here; only composition (ADR-0002).
//! - Never log plaintext, DEKs or private keys. [`Error`] carries none of them.

#![warn(missing_docs)]

pub mod container;
pub mod envelope;
pub mod error;
pub mod header;
pub mod keys;
pub mod traits;
pub mod types;

pub use container::{
    decrypt_name, inspect, open, open_with_dek, read_header, reseal_to_path, seal, seal_to_path,
    verify_version_chain, Opened, PrevVersion, SealOptions,
};
pub use envelope::Envelope;
pub use error::{Error, Result};
pub use header::{Header, HeaderBody, Permission, Policy, MAGIC, VERSION_MAJOR, VERSION_MINOR};
pub use keys::{key_id_of, Dek, DeviceKeys, OwnerKeys, SigningKeys};
pub use traits::{GrantedDek, Opener, ReadSeek, Sealer};
pub use types::{FileId, HeaderHash, KeyId, NoncePrefix, PolicyHash, Salt};

/// Default plaintext chunk size (64 KiB) — spec §2.2 `chunk`.
pub const DEFAULT_CHUNK: usize = 64 * 1024;
/// Upper bound accepted for a serialized header (spec §4 step 1).
pub const MAX_HEADER_LEN: usize = 1024 * 1024;
/// Domain separation prefix for header signatures (spec §2.2 `sig`).
pub const HDR_SIG_DOMAIN: &[u8] = b"ZBACS-HDR-v1";
/// Domain separation prefix for policy hashes (spec §2.2a).
pub const POL_HASH_DOMAIN: &[u8] = b"ZBACS-POL-v1";
/// HPKE `info` string for DEK envelopes (spec §3 step 3).
pub const DEK_INFO: &[u8] = b"zbacs-dek-v1";
