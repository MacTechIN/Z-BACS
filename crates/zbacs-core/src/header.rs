//! Container header (spec §2.1, §2.2): CBOR body + Ed25519 signature over
//! `HDR_SIG_DOMAIN || CBOR(body)`.

use crate::envelope::Envelope;
use crate::error::{Error, Result};
use crate::keys::SigningKeys;
use crate::types::{serde_opt_bytes_array, FileId, HeaderHash, NoncePrefix, Salt};
use crate::{HDR_SIG_DOMAIN, MAX_HEADER_LEN, POL_HASH_DOMAIN};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use sha2::{Digest, Sha256};

/// File magic: `ZBACS\0`.
pub const MAGIC: &[u8; 6] = b"ZBACS\0";
/// Container format major version. A different major is rejected (T19).
pub const VERSION_MAJOR: u8 = 1;
/// Container format minor version (additive changes only).
pub const VERSION_MINOR: u8 = 0;
/// `cipher` id for chunked XChaCha20-Poly1305 (the only cipher in v1).
pub const CIPHER_XCHACHA20_POLY1305_CHUNKED: u8 = 1;

/// Access permission (spec `permission_model.md`). Numeric values are the on-chain encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum Permission {
    /// Request refused; no envelope is sent.
    Deny = 0,
    /// Decrypt into a read-only workspace; edits are discarded.
    ReadOnly = 1,
    /// Decrypt for editing; the file is resealed on save/close.
    Edit = 2,
}

/// Owner policy sealed into the header (spec §2.2 `pol`) and hashed on chain (T02).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Permission the owner pre-approves; the approval UI defaults to it.
    #[serde(rename = "def")]
    pub default: Permission,
    /// Grant lifetime in seconds.
    pub ttl: u32,
    /// Maximum opens per grant (0 = unlimited).
    pub max: u16,
    /// Bind the grant to the requesting device key.
    pub pin: bool,
    /// `strict_onchain`: the recipient must wait for chain confirmation before opening.
    pub strict: bool,
}

impl Policy {
    /// `SHA-256(POL_HASH_DOMAIN || CBOR(self))` — spec §2.2a.
    ///
    /// Covers the policy only, so the approval UI can show "this file's permissions" and two
    /// versions' policies can be compared. The on-chain anchor stays [`Header::header_hash`],
    /// which covers the whole header (T02).
    pub fn policy_hash(&self) -> Result<crate::types::PolicyHash> {
        let mut h = Sha256::new();
        h.update(POL_HASH_DOMAIN);
        h.update(cbor(self)?);
        Ok(crate::types::PolicyHash(h.finalize().into()))
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self { default: Permission::ReadOnly, ttl: 3600, max: 1, pin: true, strict: false }
    }
}

/// Everything that is signed. Field order is the canonical CBOR order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderBody {
    /// File commitment (see [`FileId`]).
    pub fid: FileId,
    /// Salt mixed into `fid`.
    pub salt: Salt,
    /// Container version number, starting at 1; incremented by each reseal.
    pub ver: u32,
    /// Header hash of the previous version (reseal chain), `None` for version 1.
    #[serde(with = "serde_opt_bytes_array")]
    pub prev: Option<HeaderHash>,
    /// Owner account identifier committed on chain (opaque bytes: `chainId || address`).
    #[serde(with = "serde_bytes")]
    pub own: Vec<u8>,
    /// Owner policy.
    pub pol: Policy,
    /// Cipher id ([`CIPHER_XCHACHA20_POLY1305_CHUNKED`]).
    pub cipher: u8,
    /// Plaintext chunk size in bytes.
    pub chunk: u32,
    /// Plaintext length in bytes.
    pub plen: u64,
    /// Nonce prefix for this version (spec §2.3).
    pub np: NoncePrefix,
    /// Original file name encrypted under the DEK (AAD = `"name"`).
    #[serde(with = "serde_bytes")]
    pub name: Vec<u8>,
    /// DEK envelopes: the owner's self-envelope first, then any extra recipients.
    pub env: Vec<Envelope>,
}

/// Signed header: body + signer public key + Ed25519 signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// Signed fields.
    #[serde(flatten)]
    pub body: HeaderBody,
    /// Ed25519 verifying key of the signer (32 bytes).
    #[serde(with = "serde_bytes")]
    pub sigk: Vec<u8>,
    /// Ed25519 signature over `HDR_SIG_DOMAIN || CBOR(body)` (64 bytes).
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

fn cbor<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).map_err(|e| Error::HeaderEncode(e.to_string()))?;
    Ok(out)
}

fn signing_message(body: &HeaderBody) -> Result<Vec<u8>> {
    let mut msg = HDR_SIG_DOMAIN.to_vec();
    msg.extend_from_slice(&cbor(body)?);
    Ok(msg)
}

impl HeaderBody {
    /// Sign the body with the owner's header signing key.
    pub fn sign(self, keys: &SigningKeys) -> Result<Header> {
        let sig = keys.sk.sign(&signing_message(&self)?);
        Ok(Header {
            body: self,
            sigk: keys.verifying_key().to_bytes().to_vec(),
            sig: sig.to_bytes().to_vec(),
        })
    }
}

impl Header {
    /// Canonical CBOR encoding, bounded by [`MAX_HEADER_LEN`].
    pub fn encode(&self) -> Result<Vec<u8>> {
        let bytes = cbor(self)?;
        if bytes.len() > MAX_HEADER_LEN {
            return Err(Error::HeaderTooLarge(bytes.len()));
        }
        Ok(bytes)
    }

    /// Decode and verify the signature. Returns the header and its [`HeaderHash`]
    /// (`SHA-256(bytes)`, spec §2.3 AAD).
    pub fn decode_verified(bytes: &[u8]) -> Result<(Self, HeaderHash)> {
        if bytes.len() > MAX_HEADER_LEN {
            return Err(Error::HeaderTooLarge(bytes.len()));
        }
        let hdr: Header = ciborium::from_reader(bytes).map_err(|e| Error::HeaderDecode(e.to_string()))?;
        hdr.verify()?;
        Ok((hdr, HeaderHash(Sha256::digest(bytes).into())))
    }

    /// Verify the embedded signature against the embedded signer key.
    pub fn verify(&self) -> Result<()> {
        let vk_bytes: [u8; 32] = self.sigk.as_slice().try_into().map_err(|_| Error::HeaderSignature)?;
        let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| Error::HeaderSignature)?;
        let sig = Signature::from_slice(&self.sig).map_err(|_| Error::HeaderSignature)?;
        vk.verify(&signing_message(&self.body)?, &sig).map_err(|_| Error::HeaderSignature)
    }

    /// `SHA-256(encode())`.
    pub fn header_hash(&self) -> Result<HeaderHash> {
        Ok(HeaderHash(Sha256::digest(self.encode()?).into()))
    }

    /// Convenience for [`Policy::policy_hash`] of this header's policy.
    pub fn policy_hash(&self) -> Result<crate::types::PolicyHash> {
        self.body.pol.policy_hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> HeaderBody {
        HeaderBody {
            fid: FileId([1; 32]),
            salt: Salt([2; 16]),
            ver: 1,
            prev: None,
            own: b"acct".to_vec(),
            pol: Policy::default(),
            cipher: CIPHER_XCHACHA20_POLY1305_CHUNKED,
            chunk: 1024,
            plen: 0,
            np: NoncePrefix([3; 16]),
            name: vec![],
            env: vec![],
        }
    }

    #[test]
    fn sign_encode_decode_roundtrip_with_prev_chain() {
        let keys = SigningKeys::generate();
        let mut b = body();
        b.prev = Some(HeaderHash([9; 32]));
        b.ver = 2;
        let hdr = b.sign(&keys).unwrap();
        let bytes = hdr.encode().unwrap();
        let (back, hh) = Header::decode_verified(&bytes).unwrap();
        assert_eq!(back, hdr);
        assert_eq!(hh, hdr.header_hash().unwrap());
        assert_eq!(back.body.prev, Some(HeaderHash([9; 32])));
    }

    #[test]
    fn t02_bad_signer_key_or_signature_rejected() {
        let keys = SigningKeys::generate();
        let hdr = body().sign(&keys).unwrap();
        let mut short_key = hdr.clone();
        short_key.sigk.pop();
        assert!(matches!(short_key.verify(), Err(Error::HeaderSignature)));
        let mut bad_sig = hdr.clone();
        bad_sig.sig[0] ^= 1;
        assert!(matches!(bad_sig.verify(), Err(Error::HeaderSignature)));
        let mut short_sig = hdr;
        short_sig.sig.truncate(10);
        assert!(matches!(short_sig.verify(), Err(Error::HeaderSignature)));
    }

    #[test]
    fn policy_hash_is_stable_and_policy_specific() {
        let a = Policy::default();
        let b = Policy { ttl: 60, ..Policy::default() };
        assert_eq!(a.policy_hash().unwrap(), Policy::default().policy_hash().unwrap());
        assert_ne!(a.policy_hash().unwrap(), b.policy_hash().unwrap());
        // domain separated: not a bare hash of the CBOR
        let bare: [u8; 32] = Sha256::digest(cbor(&a).unwrap()).into();
        assert_ne!(a.policy_hash().unwrap().0, bare);
        // reachable from a signed header too
        let hdr = body().sign(&SigningKeys::generate()).unwrap();
        assert_eq!(hdr.policy_hash().unwrap(), a.policy_hash().unwrap());
    }

    #[test]
    fn decode_rejects_oversized_and_garbage() {
        let big = vec![0u8; MAX_HEADER_LEN + 1];
        assert!(matches!(Header::decode_verified(&big), Err(Error::HeaderTooLarge(_))));
        assert!(matches!(Header::decode_verified(b"\xff\xff"), Err(Error::HeaderDecode(_))));
    }
}
