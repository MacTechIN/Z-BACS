//! Client errors, split by what the agent should do about them.

use thiserror::Error;
use zbacs_proto::ErrorCode;

/// Something went wrong talking to a relay.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The relay refused the message and will refuse it again: a bad signature, an unknown
    /// device, a malformed or oversized body. The agent must fix something, not retry.
    #[error("relay refused the message: {0:?}")]
    Refused(ErrorCode),
    /// Every endpoint failed after the configured attempts. Carries the last thing that went
    /// wrong so the UI can say something useful.
    #[error("no relay could be reached: {0}")]
    Unreachable(String),
    /// The relay answered something that is not a valid protocol response.
    #[error("relay answered with {0}")]
    BadResponse(String),
    /// Building or signing the message failed.
    #[error("protocol: {0}")]
    Proto(#[from] zbacs_proto::ProtoError),
}

impl ClientError {
    /// Whether a later attempt could plausibly succeed.
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Unreachable(_))
    }
}

/// Whether this wire error is worth another attempt.
pub(crate) fn retryable(code: ErrorCode) -> bool {
    match code {
        // the relay is overloaded or broken; both pass
        ErrorCode::RateLimited | ErrorCode::Internal => true,
        // our clock was off when we signed; a fresh envelope may work, but this one will not
        ErrorCode::Stale => false,
        ErrorCode::Unauthenticated
        | ErrorCode::UnknownDevice
        | ErrorCode::Replayed
        | ErrorCode::Malformed
        | ErrorCode::TooLarge
        | ErrorCode::NotFound => false,
    }
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, ClientError>;
