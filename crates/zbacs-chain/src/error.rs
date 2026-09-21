//! Chain errors. The distinction that matters to a caller is "the chain said no" versus
//! "I could not reach the chain", because only the second one may be papered over with a
//! cached answer.

use thiserror::Error;

/// Something went wrong talking to the chain.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ChainError {
    /// The node could not be reached, or answered nonsense. A cached answer may be used in its
    /// place for a non-strict file (spec §2.6).
    #[error("chain unreachable: {0}")]
    Unreachable(String),
    /// The chain answered, and the answer was no: a revert, or a record that does not exist.
    #[error("rejected on chain: {0}")]
    Rejected(String),
    /// A value from the chain did not fit the shape we expect.
    #[error("unexpected chain data: {0}")]
    Malformed(String),
    /// A local signer or configuration problem.
    #[error("configuration: {0}")]
    Config(String),
}

impl ChainError {
    /// Whether a cached answer is an acceptable substitute for this failure.
    pub fn is_unreachable(&self) -> bool {
        matches!(self, Self::Unreachable(_))
    }
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, ChainError>;
