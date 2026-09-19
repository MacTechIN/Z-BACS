//! The `AuthProvider` trait every signer path implements (ADR-0003, ADR-0006).

use crate::error::Result;
use crate::types::{ApprovalAssertion, ApprovalChallenge, Confirmation, KeyId, P256PublicKey, SignerKind};

/// One registered signer on the owner's account, backed by hardware on this device.
///
/// Implementations (Phase 1): `PasskeyProvider` (Windows Hello via `webauthn.dll`, Z-1.A.2),
/// `DeviceKeyProvider` (TPM / Keystore / Secure Enclave P-256, Z-1.A.7), `BsaProvider`
/// (Z-1.A.5), `OtakProvider` (Z-1.A.6). Software stand-ins live in the `software` module (feature `software-signer`).
///
/// `sign` may block on an OS prompt; callers run it off the UI thread. It must never expose
/// key material and must return [`crate::AuthError::Cancelled`] when the person dismisses
/// the prompt so the UI can show "취소됨" rather than an error.
pub trait AuthProvider: Send + Sync {
    fn kind(&self) -> SignerKind;

    /// `keccak256(x || y)` of the registered public key.
    fn key_id(&self) -> KeyId;

    /// The P-256 public key for on-chain registration. `None` for BSA/OTAK signers whose
    /// verification is off chain.
    fn public_key(&self) -> Option<P256PublicKey>;

    /// Whether this signer can gate key use behind an OS biometric/PIN prompt. Always true
    /// for a platform passkey; for a DeviceKey it depends on the device (T23 policy).
    fn supports_os_confirmation(&self) -> bool;

    /// Sign the challenge, obtaining `confirmation` from the person first if required.
    fn sign(&self, challenge: &ApprovalChallenge, confirmation: Confirmation) -> Result<ApprovalAssertion>;
}
