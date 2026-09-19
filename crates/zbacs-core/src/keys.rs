//! Key material wrappers. Everything here zeroizes on drop.

use crate::error::{Error, Result};
use crate::types::KeyId;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hpke_rs::Hpke;
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 32-byte file data encryption key (spec §3 step 1). Random per seal; never derived from a
/// password (T01).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Dek(pub(crate) [u8; 32]);

impl Dek {
    /// Fresh random key from the OS RNG.
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        Self(k)
    }
    /// Wrap 32 raw bytes (e.g. after opening an out-of-band envelope).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = b.try_into().map_err(|_| Error::KeyLength)?;
        Ok(Self(arr))
    }
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for Dek {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub(crate) fn hpke() -> Hpke<HpkeRustCrypto> {
    Hpke::<HpkeRustCrypto>::new(
        hpke_rs::Mode::Base,
        KemAlgorithm::DhKem25519,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::ChaCha20Poly1305,
    )
}

/// X25519 key pair used to receive DEK envelopes (owner sealing key or recipient device key).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DeviceKeys {
    pub(crate) x25519_sk: Vec<u8>,
    pub(crate) x25519_pk: Vec<u8>,
}

impl DeviceKeys {
    /// Fresh random key pair.
    pub fn generate() -> Result<Self> {
        let mut sk = [0u8; 32];
        OsRng.fill_bytes(&mut sk);
        let me = Self::from_secret(&sk);
        sk.zeroize();
        me
    }
    /// Rebuild from a stored 32-byte secret (OS keychain, Z-1.A.3).
    pub fn from_secret(sk: &[u8]) -> Result<Self> {
        if sk.len() != 32 {
            return Err(Error::KeyLength);
        }
        let pk = x25519_public(sk)?;
        Ok(Self { x25519_sk: sk.to_vec(), x25519_pk: pk })
    }
    /// 32-byte X25519 public key.
    pub fn public_key(&self) -> &[u8] {
        &self.x25519_pk
    }
    /// 32-byte X25519 secret. Callers must not log or persist it unprotected.
    pub fn secret_key(&self) -> &[u8] {
        &self.x25519_sk
    }
    /// Envelope recipient id (see [`key_id_of`]).
    pub fn key_id(&self) -> KeyId {
        key_id_of(&self.x25519_pk)
    }
}

/// `SHA-256(pk)[..16]` — envelope recipient id (spec §2.2 `env.kid`).
pub fn key_id_of(pk: &[u8]) -> KeyId {
    let h = Sha256::digest(pk);
    let mut kid = [0u8; 16];
    kid.copy_from_slice(&h[..16]);
    KeyId(kid)
}

fn x25519_public(sk: &[u8]) -> Result<Vec<u8>> {
    let arr: [u8; 32] = sk.try_into().map_err(|_| Error::KeyLength)?;
    let secret = x25519_dalek::StaticSecret::from(arr);
    Ok(x25519_dalek::PublicKey::from(&secret).to_bytes().to_vec())
}

/// Ed25519 key pair used by the owner to sign container headers.
#[derive(ZeroizeOnDrop)]
pub struct SigningKeys {
    pub(crate) sk: SigningKey,
}

impl SigningKeys {
    /// Fresh random key pair.
    pub fn generate() -> Self {
        Self { sk: SigningKey::generate(&mut OsRng) }
    }
    /// Rebuild from a stored 32-byte secret.
    pub fn from_secret(b: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = b.try_into().map_err(|_| Error::KeyLength)?;
        Ok(Self { sk: SigningKey::from_bytes(&arr) })
    }
    /// 32-byte secret for keychain storage. Never log it.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.sk.to_bytes()
    }
    /// Public verifying key embedded in signed headers (`sigk`).
    pub fn verifying_key(&self) -> VerifyingKey {
        self.sk.verifying_key()
    }
}

/// Owner key bundle: sealing (X25519, self-envelope) + header signing (Ed25519).
pub struct OwnerKeys {
    /// Receives the owner's self-envelope so the owner can always reopen their own file.
    pub sealing: DeviceKeys,
    /// Signs container headers.
    pub signing: SigningKeys,
}

impl OwnerKeys {
    /// Fresh random bundle.
    pub fn generate() -> Result<Self> {
        Ok(Self { sealing: DeviceKeys::generate()?, signing: SigningKeys::generate() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_roundtrip_and_reject_bad_lengths() {
        let d = DeviceKeys::generate().unwrap();
        let again = DeviceKeys::from_secret(d.secret_key()).unwrap();
        assert_eq!(again.public_key(), d.public_key());
        assert_eq!(again.key_id(), d.key_id());
        assert!(matches!(DeviceKeys::from_secret(&[0; 31]), Err(Error::KeyLength)));

        let s = SigningKeys::generate();
        let again = SigningKeys::from_secret(&s.secret_bytes()).unwrap();
        assert_eq!(again.verifying_key(), s.verifying_key());
        assert!(matches!(SigningKeys::from_secret(&[0; 33]), Err(Error::KeyLength)));

        assert!(matches!(Dek::from_bytes(&[0; 16]), Err(Error::KeyLength)));
        assert_eq!(Dek::from_bytes(&[7; 32]).unwrap().as_bytes(), &[7; 32]);
    }

    #[test]
    fn key_id_is_sha256_prefix() {
        let pk = [5u8; 32];
        let h = Sha256::digest(pk);
        assert_eq!(key_id_of(&pk).as_bytes(), &h[..16]);
    }
}
