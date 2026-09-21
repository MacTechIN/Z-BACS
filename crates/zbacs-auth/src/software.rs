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

    /// Rebuild from a stored 32-byte scalar, so a demo keeps the same key across runs the way
    /// a real TPM key would. Real device keys have nothing to store — see `windows::device_key`.
    pub fn from_secret(secret: &[u8], os_confirmation: bool) -> Result<Self> {
        let sk = SigningKey::from_slice(secret).map_err(|_| AuthError::Malformed("not a P-256 scalar"))?;
        let public = public_key_of(&sk);
        Ok(Self { sk, public, os_confirmation })
    }

    /// The 32-byte scalar, for the stand-in's own storage. Never exists for a hardware key.
    pub fn secret_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        zeroize::Zeroizing::new(self.sk.to_bytes().to_vec())
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

    /// Rebuild from a stored 32-byte scalar so the credential survives a restart.
    pub fn from_secret(secret: &[u8], rp_id: &str, origin: &str, synced: bool) -> Result<Self> {
        let sk = SigningKey::from_slice(secret).map_err(|_| AuthError::Malformed("not a P-256 scalar"))?;
        let public = public_key_of(&sk);
        Ok(Self {
            sk,
            public,
            rp_id: rp_id.to_string(),
            origin: origin.to_string(),
            synced,
            counter: AtomicU32::new(0),
        })
    }

    /// The 32-byte scalar, for the stand-in's own storage.
    pub fn secret_bytes(&self) -> zeroize::Zeroizing<Vec<u8>> {
        zeroize::Zeroizing::new(self.sk.to_bytes().to_vec())
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

/// A [`SignerFactory`](crate::setup::SignerFactory) built from the software stand-ins, for
/// tests, demos and a Linux developer box that has no TPM.
///
/// It reports honestly: `hardware_backed` is false, so setup records
/// [`Pending::SoftwareSigner`](crate::setup::Pending::SoftwareSigner) and the Agent can say the
/// key is not protected by this machine's hardware.
pub struct SoftwareSignerFactory {
    store: std::sync::Arc<dyn crate::store::KeyStore>,
    rp_id: String,
    origin: String,
    /// What the device claims to have, so a test can pretend to be a machine without Hello.
    capabilities: crate::setup::DeviceCapabilities,
}

impl SoftwareSignerFactory {
    /// A factory that offers both styles.
    pub fn new(store: std::sync::Arc<dyn crate::store::KeyStore>, rp_id: &str) -> Self {
        Self {
            store,
            rp_id: rp_id.to_string(),
            origin: format!("https://{rp_id}"),
            capabilities: crate::setup::DeviceCapabilities {
                os_authenticator: true,
                hardware_key: false,
                persistent_store: false,
            },
        }
    }

    /// Override what this device claims to offer (a machine with no OS authenticator, say).
    pub fn with_capabilities(mut self, capabilities: crate::setup::DeviceCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    fn scalar(&self) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        if let Some(found) = self.store.get(crate::store::entry::APPROVAL_SOFTWARE)? {
            return Ok(found);
        }
        let fresh = zeroize::Zeroizing::new(SigningKey::random(&mut OsRng).to_bytes().to_vec());
        self.store.put(crate::store::entry::APPROVAL_SOFTWARE, &fresh)?;
        Ok(fresh)
    }

    fn build(
        &self,
        style: crate::setup::ApprovalStyle,
        require_os_confirm: bool,
    ) -> Result<std::sync::Arc<dyn AuthProvider>> {
        let scalar = self.scalar()?;
        Ok(match style {
            crate::setup::ApprovalStyle::Biometric => {
                std::sync::Arc::new(SoftwarePasskey::from_secret(&scalar, &self.rp_id, &self.origin, false)?)
            }
            // A stand-in can always show a prompt, so it never refuses an OS confirmation.
            crate::setup::ApprovalStyle::ThisDevice => {
                std::sync::Arc::new(SoftwareDeviceKey::from_secret(&scalar, require_os_confirm)?)
            }
        })
    }
}

impl crate::setup::SignerFactory for SoftwareSignerFactory {
    fn capabilities(&self) -> crate::setup::DeviceCapabilities {
        self.capabilities
    }

    fn create(
        &self,
        style: crate::setup::ApprovalStyle,
        require_os_confirm: bool,
    ) -> Result<crate::setup::CreatedSigner> {
        let provider = self.build(style, require_os_confirm)?;
        Ok(crate::setup::CreatedSigner { provider, credential: None, hardware_backed: false })
    }

    fn reopen(&self, profile: &crate::setup::DeviceProfile) -> Result<std::sync::Arc<dyn AuthProvider>> {
        self.build(profile.style, profile.require_os_confirm)
    }
}
