//! Software signers (feature `software-signer`): stand-ins for Windows Hello and TPM keys so
//! the full approval path can run in tests, CI and demos. Same shape as
//! `spikes/aa-passkey/scripts/virtual-authenticator.mjs`. **Never ship in a release build.**

use base64::Engine;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU32, Ordering};

use crate::error::{AuthError, Result};
use crate::provider::AuthProvider;
use crate::types::{ApprovalAssertion, ApprovalChallenge, Confirmation, KeyId, P256PublicKey, SignerKind};

fn public_key_of(sk: &SigningKey) -> P256PublicKey {
    let point = sk.verifying_key().to_encoded_point(false);
    P256PublicKey::from_sec1(point.as_bytes()).expect("uncompressed point")
}

/// Sign a prehashed digest and return low-s normalised `(r, s)`.
fn sign_low_s(sk: &SigningKey, digest: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let sig: Signature = sk.sign_prehash(digest).expect("p256 sign");
    let sig = sig.normalize_s().unwrap_or(sig);
    (sig.r().to_bytes().into(), sig.s().to_bytes().into())
}

/// A DeviceKey held in process memory instead of a TPM. `os_confirmation` mimics a device
/// that can (or cannot) put a biometric prompt in front of key use.
pub struct SoftwareDeviceKey {
    // ecdsa::SigningKey zeroizes its scalar on drop.
    sk: SigningKey,
    public: P256PublicKey,
    os_confirmation: bool,
}

impl SoftwareDeviceKey {
    pub fn generate(os_confirmation: bool) -> Self {
        let sk = SigningKey::random(&mut OsRng);
        let public = public_key_of(&sk);
        Self { sk, public, os_confirmation }
    }
}

impl AuthProvider for SoftwareDeviceKey {
    fn kind(&self) -> SignerKind {
        SignerKind::DeviceKey
    }
    fn key_id(&self) -> KeyId {
        self.public.key_id()
    }
    fn public_key(&self) -> Option<P256PublicKey> {
        Some(self.public)
    }
    fn supports_os_confirmation(&self) -> bool {
        self.os_confirmation
    }
    fn sign(&self, challenge: &ApprovalChallenge, confirmation: Confirmation) -> Result<ApprovalAssertion> {
        if confirmation == Confirmation::OsUserVerification && !self.os_confirmation {
            return Err(AuthError::ConfirmationUnavailable(SignerKind::DeviceKey, confirmation));
        }
        let (r, s) = sign_low_s(&self.sk, &challenge.digest);
        Ok(ApprovalAssertion::P256Raw { key_id: self.key_id(), r, s })
    }
}

/// A platform passkey emulated in software: produces WebAuthn assertions exactly as a
/// synced platform authenticator would (flags UP|UV|BE|BS, rpIdHash, counter).
pub struct SoftwarePasskey {
    // ecdsa::SigningKey zeroizes its scalar on drop.
    sk: SigningKey,
    public: P256PublicKey,
    rp_id: String,
    origin: String,
    synced: bool,
    counter: AtomicU32,
}

impl SoftwarePasskey {
    /// `synced` sets the BE/BS flags (cloud-synced passkey, T22).
    pub fn generate(rp_id: &str, origin: &str, synced: bool) -> Self {
        let sk = SigningKey::random(&mut OsRng);
        let public = public_key_of(&sk);
        Self {
            sk,
            public,
            rp_id: rp_id.to_string(),
            origin: origin.to_string(),
            synced,
            counter: AtomicU32::new(0),
        }
    }
}

impl AuthProvider for SoftwarePasskey {
    fn kind(&self) -> SignerKind {
        SignerKind::PlatformPasskey
    }
    fn key_id(&self) -> KeyId {
        self.public.key_id()
    }
    fn public_key(&self) -> Option<P256PublicKey> {
        Some(self.public)
    }
    fn supports_os_confirmation(&self) -> bool {
        true
    }
    fn sign(&self, challenge: &ApprovalChallenge, _confirmation: Confirmation) -> Result<ApprovalAssertion> {
        // A platform authenticator always verifies the user; the prompt is implicit here.
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge.digest),
            self.origin
        );
        let flags = 0x01 | 0x04 | if self.synced { 0x08 | 0x10 } else { 0 };
        let count = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        let mut authenticator_data = Vec::with_capacity(37);
        authenticator_data.extend_from_slice(&Sha256::digest(self.rp_id.as_bytes()));
        authenticator_data.push(flags);
        authenticator_data.extend_from_slice(&count.to_be_bytes());

        let digest = crate::webauthn::webauthn_signed_digest(&authenticator_data, &client_data_json);
        let (r, s) = sign_low_s(&self.sk, &digest);
        Ok(ApprovalAssertion::WebAuthn { authenticator_data, client_data_json, r, s })
    }
}
