//! The approval's terms as they travel inside [`crate::GrantMsg::grant`]: the fields of the
//! EIP-712 `AccessGrant` (approval_protocol §1.2), CBOR-encoded.
//!
//! The recipient checks these against its own request before anything is decrypted (§2 rules
//! 1–3): the file, the version, the asking device and the request nonce must all be the ones it
//! sent. A grant for a different file or device is not an error to tolerate but a swap to
//! refuse (T05, T19).

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::error::{ProtoError, Result};

/// Fields of the EIP-712 `AccessGrant`, in struct order. Names follow the Solidity struct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessGrantTerms {
    /// Container file id.
    #[serde(with = "serde_bytes")]
    pub file_id: [u8; 32],
    /// Header hash of the version approved (T19).
    #[serde(with = "serde_bytes")]
    pub header_hash: [u8; 32],
    /// `keccak256(device_x25519_pub || device_ed25519_pub)` of the asking device (T05).
    #[serde(with = "serde_bytes")]
    pub device_key_hash: [u8; 32],
    /// 1 = ReadOnly, 2 = Edit. A refusal travels as `GrantMsg.decision == 0` with no terms.
    pub permission: u8,
    /// Unix seconds the approval becomes valid.
    pub not_before: u64,
    /// Unix seconds it expires.
    pub expiry: u64,
    /// 0 = unlimited.
    pub max_opens: u16,
    /// The recipient's request nonce, copied so the answer cannot be re-aimed.
    #[serde(with = "serde_bytes")]
    pub request_nonce: [u8; 16],
    /// Owner's sequential nonce (`uint256` on chain; sequential values fit in 64 bits).
    pub grant_nonce: u64,
}

impl AccessGrantTerms {
    /// CBOR bytes, as carried in `GrantMsg.grant`.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out).map_err(|e| ProtoError::Encode(e.to_string()))?;
        Ok(out)
    }

    /// Parse `GrantMsg.grant`.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self> {
        ciborium::from_reader(bytes).map_err(|_| ProtoError::Malformed("grant terms are not valid CBOR"))
    }
}

/// `keccak256(device_x25519_pub || device_ed25519_pub)` — how a grant names the device it is
/// for (approval_protocol §1.2 `deviceKeyHash`).
pub fn device_key_hash(x25519_pub: &[u8; 32], ed25519_pub: &[u8; 32]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(x25519_pub);
    h.update(ed25519_pub);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terms() -> AccessGrantTerms {
        AccessGrantTerms {
            file_id: [1; 32],
            header_hash: [2; 32],
            device_key_hash: [3; 32],
            permission: 1,
            not_before: 1_700_000_000,
            expiry: 1_700_003_600,
            max_opens: 1,
            request_nonce: [4; 16],
            grant_nonce: 7,
        }
    }

    #[test]
    fn terms_round_trip_through_cbor() {
        let t = terms();
        let bytes = t.to_cbor().unwrap();
        assert_eq!(AccessGrantTerms::from_cbor(&bytes).unwrap(), t);
        assert!(AccessGrantTerms::from_cbor(b"nope").is_err());
    }

    #[test]
    fn device_key_hash_is_keccak_of_both_keys_in_order() {
        let a = device_key_hash(&[1; 32], &[2; 32]);
        let b = device_key_hash(&[2; 32], &[1; 32]);
        assert_ne!(a, b, "order matters: x25519 first, then ed25519");
        let mut h = Keccak256::new();
        h.update([1u8; 32]);
        h.update([2u8; 32]);
        assert_eq!(a, <[u8; 32]>::from(h.finalize()));
    }
}
