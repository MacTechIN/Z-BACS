//! The device identity that signs relay envelopes: the Ed25519 key from `zbacs-core`, plus the
//! X25519 key that receives DEK envelopes.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use zbacs_core::{DeviceKeys, SigningKeys};

use crate::error::{ProtoError, Result};

/// A device's key pair bundle. Wraps `zbacs-core` types so relay code never touches raw bytes.
pub struct DeviceIdentity {
    /// Receives HPKE DEK envelopes.
    pub keys: DeviceKeys,
    /// Signs relay envelopes.
    pub signing: SigningKeys,
}

impl DeviceIdentity {
    /// Fresh random identity (onboarding, Z-1.A.3 stores it in the OS keychain).
    pub fn generate() -> Result<Self> {
        Ok(Self {
            keys: DeviceKeys::generate().map_err(|_| ProtoError::KeyLength)?,
            signing: SigningKeys::generate(),
        })
    }

    /// Rebuild from stored secrets.
    pub fn from_secrets(x25519_sk: &[u8], ed25519_sk: &[u8]) -> Result<Self> {
        Ok(Self {
            keys: DeviceKeys::from_secret(x25519_sk).map_err(|_| ProtoError::KeyLength)?,
            signing: SigningKeys::from_secret(ed25519_sk).map_err(|_| ProtoError::KeyLength)?,
        })
    }

    /// `SHA-256(ed25519_pub)[..16]` — the relay's routing key for this device (spec §3).
    ///
    /// Note this is the *signing* key id, while `zbacs-core`'s envelope `kid` hashes the X25519
    /// key: one identifies who speaks, the other who can open an envelope.
    pub fn kid(&self) -> [u8; 16] {
        kid_of(&self.ed25519_pub())
    }

    /// X25519 public key (DEK envelope target).
    pub fn x25519_pub(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.keys.public_key());
        out
    }

    /// Ed25519 public key (envelope signatures).
    pub fn ed25519_pub(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub(crate) fn sign_raw(&self, msg: &[u8]) -> [u8; 64] {
        let sk: &SigningKey = &self.signing_key();
        sk.sign(msg).to_bytes()
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.signing.secret_bytes())
    }
}

/// `SHA-256(ed25519_pub)[..16]`.
pub fn kid_of(ed25519_pub: &[u8; 32]) -> [u8; 16] {
    let h = Sha256::digest(ed25519_pub);
    let mut kid = [0u8; 16];
    kid.copy_from_slice(&h[..16]);
    kid
}

pub(crate) fn verify_raw(ed25519_pub: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(ed25519_pub).map_err(|_| ProtoError::BadSignature)?;
    let sig = Signature::from_bytes(sig);
    vk.verify(msg, &sig).map_err(|_| ProtoError::BadSignature)
}
