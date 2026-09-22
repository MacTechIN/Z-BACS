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

/// EIP-712 domain name and version (`AccessPolicy` constructor).
pub const DOMAIN_NAME: &str = "Z-BACS";
/// EIP-712 domain version.
pub const DOMAIN_VERSION: &str = "1";

/// The type hash, computed from the type string so a typo shows up in the test, not on chain.
pub fn typehash() -> [u8; 32] {
    keccak(&[b"AccessGrant(bytes32 fileId,bytes32 headerHash,bytes32 deviceKeyHash,uint8 permission,uint64 notBefore,uint64 expiry,uint16 maxOpens,bytes16 requestNonce,uint256 grantNonce)"])
}

fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn word_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

fn word_bytes16(v: &[u8; 16]) -> [u8; 32] {
    // `bytes16` is left-aligned in its 32-byte word
    let mut w = [0u8; 32];
    w[..16].copy_from_slice(v);
    w
}

impl AccessGrantTerms {
    /// EIP-712 `hashStruct` — also the on-chain `grantId`, and the `aad` of the DEK envelope
    /// sent with the grant.
    pub fn struct_hash(&self) -> [u8; 32] {
        keccak(&[
            &typehash(),
            &self.file_id,
            &self.header_hash,
            &self.device_key_hash,
            &word_u64(self.permission as u64),
            &word_u64(self.not_before),
            &word_u64(self.expiry),
            &word_u64(self.max_opens as u64),
            &word_bytes16(&self.request_nonce),
            &word_u64(self.grant_nonce),
        ])
    }

    /// EIP-712 digest for `AccessPolicy` at `verifying_contract` on `chain_id` — what the owner
    /// signs (`OwnerSig`, approval_protocol §1.5).
    pub fn digest(&self, chain_id: u64, verifying_contract: &[u8; 20]) -> [u8; 32] {
        let mut contract = [0u8; 32];
        contract[12..].copy_from_slice(verifying_contract);
        let domain = keccak(&[
            &keccak(&[b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"]),
            &keccak(&[DOMAIN_NAME.as_bytes()]),
            &keccak(&[DOMAIN_VERSION.as_bytes()]),
            &word_u64(chain_id),
            &contract,
        ]);
        keccak(&[b"\x19\x01", &domain, &self.struct_hash()])
    }

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

    /// vector-1 from docs/research/contracts_eip712_grant.md, produced by the Solidity library.
    #[test]
    fn t14_struct_hash_matches_the_solidity_vector() {
        let t = AccessGrantTerms {
            file_id: [0; 31].iter().copied().chain([1]).collect::<Vec<_>>().try_into().unwrap(),
            header_hash: [0; 31].iter().copied().chain([2]).collect::<Vec<_>>().try_into().unwrap(),
            device_key_hash: [0; 31].iter().copied().chain([3]).collect::<Vec<_>>().try_into().unwrap(),
            permission: 1,
            not_before: 1_700_000_000,
            expiry: 1_700_003_600,
            max_opens: 1,
            request_nonce: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4],
            grant_nonce: 0,
        };
        assert_eq!(
            hex::encode(t.struct_hash()),
            "d57d596bf1b00f8b8cc22ada6875352e42b07bf7bc0d02db0c208083732b78fa"
        );
        // the digest changes with the chain and the contract: a grant cannot be replayed
        // across either (T03)
        let a = t.digest(31337, &[0x11; 20]);
        assert_ne!(a, t.digest(84532, &[0x11; 20]));
        assert_ne!(a, t.digest(31337, &[0x22; 20]));
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
