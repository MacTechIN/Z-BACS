//! The signed envelope every relay message travels in (spec §3).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{ProtoError, Result};
use crate::identity::{verify_raw, DeviceIdentity};
use crate::messages::{Kind, Message};
use crate::{MAX_BODY_LEN, MAX_SKEW_SECS, RELAY_SIG_DOMAIN};

/// `Signed<T>`: CBOR payload + who signed it + replay guards + Ed25519 signature.
///
/// The signature covers the message *kind* as well as the payload hash, so an envelope signed
/// as one kind cannot be presented as another (spec §3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    /// CBOR of the payload.
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
    /// Signer's device key id (`SHA-256(ed25519_pub)[..16]`).
    #[serde(with = "serde_bytes")]
    pub kid: [u8; 16],
    /// Kind of the wrapped payload.
    pub kind: Kind,
    /// Unix seconds when the sender signed.
    pub ts: u64,
    /// Per-message nonce; relays remember it for [`crate::NONCE_MEMORY_SECS`].
    #[serde(with = "serde_bytes")]
    pub nonce: [u8; 16],
    /// Ed25519 signature over [`Signed::signing_bytes`].
    #[serde(with = "serde_bytes")]
    pub sig: [u8; 64],
}

impl Signed {
    /// `RELAY_SIG_DOMAIN || kind || ts || nonce || SHA-256(payload)` — what gets signed.
    pub fn signing_bytes(kind: Kind, ts: u64, nonce: &[u8; 16], payload: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(RELAY_SIG_DOMAIN.len() + 8 + 8 + 16 + 32);
        msg.extend_from_slice(RELAY_SIG_DOMAIN);
        msg.extend_from_slice(kind.as_str().as_bytes());
        msg.extend_from_slice(&ts.to_le_bytes());
        msg.extend_from_slice(nonce);
        msg.extend_from_slice(&Sha256::digest(payload));
        msg
    }

    /// Wrap and sign a payload.
    pub fn sign<T: Message>(device: &DeviceIdentity, payload: &T, ts: u64, nonce: [u8; 16]) -> Result<Self> {
        let mut body = Vec::new();
        ciborium::into_writer(payload, &mut body).map_err(|e| ProtoError::Encode(e.to_string()))?;
        if body.len() > MAX_BODY_LEN {
            return Err(ProtoError::TooLarge(body.len()));
        }
        let sig = device.sign_raw(&Self::signing_bytes(T::KIND, ts, &nonce, &body));
        Ok(Self { payload: body, kid: device.kid(), kind: T::KIND, ts, nonce, sig })
    }

    /// Verify the signature, the kind and the clock skew, then decode the payload.
    ///
    /// Replay protection is the relay's job (it remembers `nonce` for 5 minutes); this returns
    /// the nonce so the caller can record it.
    pub fn verify<T: Message>(&self, ed25519_pub: &[u8; 32], now: u64) -> Result<(T, [u8; 16])> {
        if self.kind != T::KIND {
            return Err(ProtoError::Malformed("envelope kind does not match the payload type"));
        }
        if self.payload.len() > MAX_BODY_LEN {
            return Err(ProtoError::TooLarge(self.payload.len()));
        }
        if now.abs_diff(self.ts) > MAX_SKEW_SECS {
            return Err(ProtoError::Stale { ts: self.ts, now });
        }
        if crate::identity::kid_of(ed25519_pub) != self.kid {
            return Err(ProtoError::BadSignature);
        }
        verify_raw(
            ed25519_pub,
            &Self::signing_bytes(self.kind, self.ts, &self.nonce, &self.payload),
            &self.sig,
        )?;
        let payload: T = ciborium::from_reader(self.payload.as_slice())
            .map_err(|_| ProtoError::Malformed("payload is not valid CBOR for this kind"))?;
        Ok((payload, self.nonce))
    }

    /// CBOR bytes of the envelope, as put on the wire.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|e| ProtoError::Encode(e.to_string()))?;
        if out.len() > MAX_BODY_LEN {
            return Err(ProtoError::TooLarge(out.len()));
        }
        Ok(out)
    }

    /// Parse an envelope received from the wire. Does not verify it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BODY_LEN {
            return Err(ProtoError::TooLarge(bytes.len()));
        }
        ciborium::from_reader(bytes).map_err(|_| ProtoError::Malformed("envelope is not valid CBOR"))
    }
}
