//! Key material wrappers. Everything here zeroizes on drop.

use crate::error::{Error, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hpke_rs::Hpke;
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 32-byte file data encryption key (spec §3 step 1).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Dek(pub(crate) [u8; 32]);

impl Dek {
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        Self(k)
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = b.try_into().map_err(|_| Error::KeyLength)?;
        Ok(Self(arr))
    }
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
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

/// X25519 key pair used to receive DEK envelopes (owner sealing key or device key).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DeviceKeys {
    pub(crate) x25519_sk: Vec<u8>,
    pub(crate) x25519_pk: Vec<u8>,
}

impl DeviceKeys {
    pub fn generate() -> Result<Self> {
        let mut sk = [0u8; 32];
        OsRng.fill_bytes(&mut sk);
        let me = Self::from_secret(&sk);
        sk.zeroize();
        me
    }
    pub fn from_secret(sk: &[u8]) -> Result<Self> {
        if sk.len() != 32 {
            return Err(Error::KeyLength);
        }
        let pk = x25519_public(sk)?;
        Ok(Self { x25519_sk: sk.to_vec(), x25519_pk: pk })
    }
    pub fn public_key(&self) -> &[u8] {
        &self.x25519_pk
    }
    pub fn secret_key(&self) -> &[u8] {
        &self.x25519_sk
    }
    /// 16-byte key id = SHA-256(pk)[..16] (spec §2.2 `env.kid`).
    pub fn key_id(&self) -> [u8; 16] {
        key_id_of(&self.x25519_pk)
    }
}

pub fn key_id_of(pk: &[u8]) -> [u8; 16] {
    let h = Sha256::digest(pk);
    let mut kid = [0u8; 16];
    kid.copy_from_slice(&h[..16]);
    kid
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
    pub fn generate() -> Self {
        Self { sk: SigningKey::generate(&mut OsRng) }
    }
    pub fn from_secret(b: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = b.try_into().map_err(|_| Error::KeyLength)?;
        Ok(Self { sk: SigningKey::from_bytes(&arr) })
    }
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.sk.to_bytes()
    }
    pub fn verifying_key(&self) -> VerifyingKey {
        self.sk.verifying_key()
    }
}

/// Owner key bundle: sealing (X25519) + header signing (Ed25519).
pub struct OwnerKeys {
    pub sealing: DeviceKeys,
    pub signing: SigningKeys,
}

impl OwnerKeys {
    pub fn generate() -> Result<Self> {
        Ok(Self { sealing: DeviceKeys::generate()?, signing: SigningKeys::generate() })
    }
}
