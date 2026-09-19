//! Error type for every fallible operation in the crate. Variants never carry key material or
//! plaintext, so they are safe to log.

use thiserror::Error;

/// Container, envelope and key errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Underlying file / stream error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Input does not start with [`crate::MAGIC`].
    #[error("not a Z-BACS container (bad magic)")]
    BadMagic,
    /// Major version differs from [`crate::VERSION_MAJOR`] (T19 downgrade guard).
    #[error("unsupported container version {0}.{1}")]
    UnsupportedVersion(u8, u8),
    /// Header length field or encoding exceeds [`crate::MAX_HEADER_LEN`] (T18).
    #[error("header too large ({0} bytes)")]
    HeaderTooLarge(usize),
    /// CBOR serialization failed.
    #[error("header encoding: {0}")]
    HeaderEncode(String),
    /// CBOR parsing failed or a field has the wrong shape.
    #[error("header decoding: {0}")]
    HeaderDecode(String),
    /// Ed25519 signature or signer key invalid (T02 tamper guard).
    #[error("header signature invalid")]
    HeaderSignature,
    /// `cipher` id is not one this build supports.
    #[error("unsupported cipher id {0}")]
    UnsupportedCipher(u8),
    /// Chunk size is zero or above the 16 MiB bound.
    #[error("invalid chunk size {0}")]
    BadChunkSize(u32),
    /// Chunk `index` failed AEAD authentication (tamper or reorder, T18).
    #[error("chunk {0} failed authentication")]
    ChunkAuth(u64),
    /// Stream ended early, has trailing bytes, or the trailer does not match (T19).
    #[error("container truncated or trailer mismatch")]
    Truncated,
    /// No embedded envelope for this device key (the DEK must come from a grant).
    #[error("no envelope for key id")]
    NoEnvelope,
    /// HPKE open failed: wrong key, wrong AAD, or unknown suite (T04).
    #[error("envelope open failed")]
    EnvelopeOpen,
    /// HPKE seal failed (malformed recipient key).
    #[error("envelope seal failed")]
    EnvelopeSeal,
    /// Encrypted file name failed authentication.
    #[error("filename decryption failed")]
    NameAuth,
    /// A key or identifier has the wrong length.
    #[error("key material has wrong length")]
    KeyLength,
}

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;
