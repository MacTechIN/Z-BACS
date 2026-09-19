//! Container header (spec §2.1, §2.2): CBOR body + Ed25519 signature over
//! `HDR_SIG_DOMAIN || CBOR(body)`.

use crate::envelope::Envelope;
use crate::error::{Error, Result};
use crate::keys::SigningKeys;
use crate::{HDR_SIG_DOMAIN, MAX_HEADER_LEN};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 6] = b"ZBACS\0";
pub const VERSION_MAJOR: u8 = 1;
pub const VERSION_MINOR: u8 = 0;
pub const CIPHER_XCHACHA20_POLY1305_CHUNKED: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum Permission {
    Deny = 0,
    ReadOnly = 1,
    Edit = 2,
}

/// Spec §2.2 `pol`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    #[serde(rename = "def")]
    pub default: Permission,
    pub ttl: u32,
    pub max: u16,
    pub pin: bool,
    pub strict: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self { default: Permission::ReadOnly, ttl: 3600, max: 1, pin: true, strict: false }
    }
}

/// Everything that is signed. Field order is the canonical CBOR order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderBody {
    #[serde(with = "serde_bytes")]
    pub fid: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub salt: Vec<u8>,
    pub ver: u32,
    #[serde(with = "serde_bytes")]
    pub prev: Option<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    pub own: Vec<u8>,
    pub pol: Policy,
    pub cipher: u8,
    pub chunk: u32,
    pub plen: u64,
    /// 16-byte random nonce prefix for this version (spec §2.3).
    #[serde(with = "serde_bytes")]
    pub np: Vec<u8>,
    /// Original file name encrypted under the DEK (AAD = "name").
    #[serde(with = "serde_bytes")]
    pub name: Vec<u8>,
    pub env: Vec<Envelope>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    #[serde(flatten)]
    pub body: HeaderBody,
    #[serde(with = "serde_bytes")]
    pub sigk: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

fn cbor<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).map_err(|e| Error::HeaderEncode(e.to_string()))?;
    Ok(out)
}

impl HeaderBody {
    pub fn sign(self, keys: &SigningKeys) -> Result<Header> {
        let body_bytes = cbor(&self)?;
        let mut msg = HDR_SIG_DOMAIN.to_vec();
        msg.extend_from_slice(&body_bytes);
        let sig = keys.sk.sign(&msg);
        Ok(Header {
            body: self,
            sigk: keys.verifying_key().to_bytes().to_vec(),
            sig: sig.to_bytes().to_vec(),
        })
    }
}

impl Header {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let bytes = cbor(self)?;
        if bytes.len() > MAX_HEADER_LEN {
            return Err(Error::HeaderTooLarge(bytes.len()));
        }
        Ok(bytes)
    }

    /// Decode and verify. Returns the header and `SHA-256(header_bytes)` (spec §2.3 AAD).
    pub fn decode_verified(bytes: &[u8]) -> Result<(Self, [u8; 32])> {
        if bytes.len() > MAX_HEADER_LEN {
            return Err(Error::HeaderTooLarge(bytes.len()));
        }
        let hdr: Header = ciborium::from_reader(bytes).map_err(|e| Error::HeaderDecode(e.to_string()))?;
        hdr.verify()?;
        Ok((hdr, Sha256::digest(bytes).into()))
    }

    pub fn verify(&self) -> Result<()> {
        let vk_bytes: [u8; 32] = self.sigk.as_slice().try_into().map_err(|_| Error::HeaderSignature)?;
        let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| Error::HeaderSignature)?;
        let sig = Signature::from_slice(&self.sig).map_err(|_| Error::HeaderSignature)?;
        let body_bytes = cbor(&self.body)?;
        let mut msg = HDR_SIG_DOMAIN.to_vec();
        msg.extend_from_slice(&body_bytes);
        vk.verify(&msg, &sig).map_err(|_| Error::HeaderSignature)
    }

    pub fn header_hash(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.encode()?).into())
    }
}
