//! Z-BACS owner approval signers.
//!
//! An owner approves an access request by signing an EIP-712 `AccessGrant` digest (or, for
//! smart-account operations, a UserOperation hash). ADR-0006 allows two signer paths per
//! registered device, chosen by the owner without ever seeing a key:
//!
//! - **PlatformPasskey** — the OS authenticator (Windows Hello, Touch ID, Android biometrics).
//!   Produces a WebAuthn assertion; the on-chain account verifies it with its WebAuthn validator.
//! - **DeviceKey** — a non-exportable P-256 key the Agent created inside the device's hardware
//!   store (TPM, Keystore, Secure Enclave). Produces a raw P-256 signature; verified on chain by
//!   `P256Validator`.
//!
//! Both yield an [`ApprovalAssertion`] over the same [`ApprovalChallenge`]; everything downstream
//! (Relay message, ERC-1271 check on the recipient side) is identical.
//!
//! Spec: `docs/specs/approval_protocol.md` §1.5. Tasks: Z-1.A.1 (this crate's API),
//! Z-1.A.2 (`PasskeyProvider`), Z-1.A.7 (`DeviceKeyProvider`).
//!
//! Security notes
//! - No cryptographic primitive is implemented here; P-256/SHA-2/Keccak come from RustCrypto.
//! - Signatures are rejected unless `s` is in the lower half of the curve order (malleability,
//!   T03/T14) — the P256VERIFY precompile does not enforce this itself (Z-0.H.2 finding).
//! - Private keys never leave hardware in production providers; the software signers behind
//!   the `software-signer` feature exist for tests and demos only.

pub mod bsa;
pub mod error;
pub mod otak;
pub mod policy;
pub mod provider;
#[cfg(feature = "software-signer")]
pub mod software;
pub mod store;
pub mod types;
pub mod webauthn;
#[cfg(windows)]
pub mod windows;

pub use bsa::{BsaClient, BsaProvider, MockBsaClient};
pub use error::AuthError;
pub use otak::{OtakProvider, OtakSeed, OtakVerifier};
pub use policy::ConfirmationPolicy;
pub use provider::AuthProvider;
pub use store::{KeyStore, MemoryKeyStore};
pub use types::{
    ApprovalAssertion, ApprovalChallenge, ApprovalContext, Confirmation, DeviceEnroll, DeviceRevoke, KeyId,
    P256PublicKey, SignerKind,
};
pub use webauthn::{verify_assertion, AuthenticatorData, AuthenticatorFlags};

/// Domain prefix for `DeviceEnroll` signing bytes (spec §1.5).
pub const ENROLL_DOMAIN: &[u8] = b"ZBACS-ENROLL-v1";
/// Domain prefix for `DeviceRevoke` signing bytes (spec §1.5).
pub const REVOKE_DOMAIN: &[u8] = b"ZBACS-REVOKE-v1";
