//! Protocol errors. These map 1:1 to the wire error codes in spec §5.

use thiserror::Error;

use crate::messages::ErrorCode;

/// Something was wrong with a message. Carries no secrets — safe to log and to return.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtoError {
    /// Signature missing or not valid for the claimed key.
    #[error("signature verification failed")]
    BadSignature,
    /// `ts` is outside the accepted skew (spec §1).
    #[error("timestamp {ts} is outside the accepted window (now {now})")]
    Stale {
        /// Timestamp carried by the message.
        ts: u64,
        /// Receiver's clock.
        now: u64,
    },
    /// CBOR could not be parsed, or a field broke a length rule.
    #[error("malformed message: {0}")]
    Malformed(&'static str),
    /// Body exceeds [`crate::MAX_BODY_LEN`].
    #[error("body too large ({0} bytes)")]
    TooLarge(usize),
    /// CBOR serialization failed.
    #[error("encoding: {0}")]
    Encode(String),
    /// Key material has the wrong length.
    #[error("key material has wrong length")]
    KeyLength,
}

impl ProtoError {
    /// The wire error code a relay returns for this error (spec §5).
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::BadSignature => ErrorCode::Unauthenticated,
            Self::Stale { .. } => ErrorCode::Stale,
            Self::Malformed(_) | Self::Encode(_) | Self::KeyLength => ErrorCode::Malformed,
            Self::TooLarge(_) => ErrorCode::TooLarge,
        }
    }
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, ProtoError>;
