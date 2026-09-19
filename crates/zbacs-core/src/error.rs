use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("not a Z-BACS container (bad magic)")]
    BadMagic,
    #[error("unsupported container version {0}.{1}")]
    UnsupportedVersion(u8, u8),
    #[error("header too large ({0} bytes)")]
    HeaderTooLarge(usize),
    #[error("header encoding: {0}")]
    HeaderEncode(String),
    #[error("header decoding: {0}")]
    HeaderDecode(String),
    #[error("header signature invalid")]
    HeaderSignature,
    #[error("unsupported cipher id {0}")]
    UnsupportedCipher(u8),
    #[error("invalid chunk size {0}")]
    BadChunkSize(u32),
    #[error("chunk {0} failed authentication")]
    ChunkAuth(u64),
    #[error("container truncated or trailer mismatch")]
    Truncated,
    #[error("no envelope for key id")]
    NoEnvelope,
    #[error("envelope open failed")]
    EnvelopeOpen,
    #[error("envelope seal failed")]
    EnvelopeSeal,
    #[error("filename decryption failed")]
    NameAuth,
    #[error("key material has wrong length")]
    KeyLength,
}

pub type Result<T> = std::result::Result<T, Error>;
