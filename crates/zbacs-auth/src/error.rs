use thiserror::Error;

use crate::types::{Confirmation, SignerKind};

#[derive(Debug, Error)]
pub enum AuthError {
    /// The person dismissed the OS prompt (Windows Hello cancel, biometric timeout).
    #[error("approval cancelled by user")]
    Cancelled,
    /// The policy demanded a confirmation this signer cannot provide (e.g. a DeviceKey
    /// without OS user verification on a device that has no authenticator).
    #[error("signer {0:?} cannot provide {1:?}")]
    ConfirmationUnavailable(SignerKind, Confirmation),
    /// Hardware / OS API failure. The message is safe to show in logs (no key material).
    #[error("authenticator error: {0}")]
    Hardware(String),
    #[error("signer kind {0:?} is not available on this device")]
    Unsupported(SignerKind),
    #[error("assertion is malformed: {0}")]
    Malformed(&'static str),
    #[error("assertion does not verify against the registered key")]
    InvalidSignature,
    /// `s` is in the upper half of the curve order (T03/T14 malleability guard).
    #[error("signature is not low-s normalised")]
    HighS,
    /// The WebAuthn client data carries a different challenge than the one requested.
    #[error("client data challenge mismatch")]
    ChallengeMismatch,
    /// `UP`/`UV` flags missing from authenticator data.
    #[error("authenticator did not report user presence/verification")]
    UserVerificationMissing,
    #[error("encoding: {0}")]
    Encode(String),
}

pub type Result<T> = std::result::Result<T, AuthError>;
