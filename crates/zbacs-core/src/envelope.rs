//! DEK envelopes: HPKE Base mode, DHKEM(X25519) + HKDF-SHA256 + ChaCha20-Poly1305 (ADR-0002).

use crate::error::{Error, Result};
use crate::keys::{hpke, key_id_of, Dek, DeviceKeys};
use crate::DEK_INFO;
use hpke_rs::{HpkePrivateKey, HpkePublicKey};
use serde::{Deserialize, Serialize};

pub const ALG_HPKE_X25519_CHACHA: &str = "hpke-x25519-chacha";

/// Spec §2.2 `env[]` entry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    #[serde(with = "serde_bytes")]
    pub kid: Vec<u8>,
    pub alg: String,
    #[serde(with = "serde_bytes")]
    pub enc: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ct: Vec<u8>,
}

impl Envelope {
    /// Wrap `dek` for the holder of `recipient_pk`. `aad` binds the envelope to a context
    /// (the container's file id, or a grant hash when sent out-of-band).
    pub fn seal(recipient_pk: &[u8], dek: &Dek, aad: &[u8]) -> Result<Self> {
        let pk = HpkePublicKey::new(recipient_pk.to_vec());
        let (enc, ct) = hpke()
            .seal(&pk, DEK_INFO, aad, dek.as_bytes(), None, None, None)
            .map_err(|_| Error::EnvelopeSeal)?;
        Ok(Self { kid: key_id_of(recipient_pk).to_vec(), alg: ALG_HPKE_X25519_CHACHA.into(), enc, ct })
    }

    pub fn open(&self, keys: &DeviceKeys, aad: &[u8]) -> Result<Dek> {
        if self.alg != ALG_HPKE_X25519_CHACHA {
            return Err(Error::EnvelopeOpen);
        }
        let sk = HpkePrivateKey::new(keys.secret_key().to_vec());
        let pt = hpke()
            .open(&self.enc, &sk, DEK_INFO, aad, &self.ct, None, None, None)
            .map_err(|_| Error::EnvelopeOpen)?;
        let dek = Dek::from_bytes(&pt);
        // best-effort zeroize of the intermediate Vec
        let mut pt = pt;
        zeroize::Zeroize::zeroize(&mut pt);
        dek
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_aad_binding() {
        let bob = DeviceKeys::generate().unwrap();
        let dek = Dek::generate();
        let env = Envelope::seal(bob.public_key(), &dek, b"ctx").unwrap();
        assert_eq!(env.kid, bob.key_id());
        let got = env.open(&bob, b"ctx").unwrap();
        assert_eq!(got.as_bytes(), dek.as_bytes());
        assert!(matches!(env.open(&bob, b"other"), Err(Error::EnvelopeOpen)));
        let eve = DeviceKeys::generate().unwrap();
        assert!(matches!(env.open(&eve, b"ctx"), Err(Error::EnvelopeOpen)));
    }
}
