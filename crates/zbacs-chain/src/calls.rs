//! Calldata for the Z-BACS contracts, built by hand so the same bytes serve both write paths:
//! wrapped in a user operation from the owner's smart account ([`crate::aa`]), or sent as a
//! plain transaction by a funded key (tests, self-hosted deployments).
//!
//! Selectors are pinned in tests against `cast sig`, and the `grant` tuple layout is the
//! `AccessGrant` struct of `contracts/src/AccessGrantLib.sol` in declaration order.

use alloy::primitives::{keccak256, Bytes, FixedBytes, B256, U256};
use alloy::sol_types::SolValue;

/// The nine fields of the EIP-712 `AccessGrant`, exactly as the contract takes them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantArgs {
    /// Container file id.
    pub file_id: [u8; 32],
    /// Header hash of the version approved.
    pub header_hash: [u8; 32],
    /// `keccak256(x25519_pub ‖ ed25519_pub)` of the asking device.
    pub device_key_hash: [u8; 32],
    /// 1 read-only, 2 edit.
    pub permission: u8,
    /// Unix seconds.
    pub not_before: u64,
    /// Unix seconds.
    pub expiry: u64,
    /// 0 = unlimited.
    pub max_opens: u16,
    /// The recipient's request nonce.
    pub request_nonce: [u8; 16],
    /// The owner's sequential nonce.
    pub grant_nonce: u64,
}

fn selector(signature: &str) -> [u8; 4] {
    let h = keccak256(signature);
    [h[0], h[1], h[2], h[3]]
}

fn call(signature: &str, params: Vec<u8>) -> Bytes {
    let mut out = selector(signature).to_vec();
    out.extend_from_slice(&params);
    out.into()
}

/// `FileRegistry.register(fileId, headerHash)`.
pub fn register(file_id: [u8; 32], header_hash: [u8; 32]) -> Bytes {
    call("register(bytes32,bytes32)", (B256::from(file_id), B256::from(header_hash)).abi_encode_params())
}

/// `FileRegistry.bumpVersion(fileId, newHeaderHash)`.
pub fn bump_version(file_id: [u8; 32], new_header_hash: [u8; 32]) -> Bytes {
    call(
        "bumpVersion(bytes32,bytes32)",
        (B256::from(file_id), B256::from(new_header_hash)).abi_encode_params(),
    )
}

/// `AccessPolicy.grant(AccessGrant g, bytes ownerSig)`.
pub fn grant(g: &GrantArgs, owner_sig: &[u8]) -> Bytes {
    let tuple = (
        B256::from(g.file_id),
        B256::from(g.header_hash),
        B256::from(g.device_key_hash),
        // uint8 has no SolValue impl in alloy (reserved for bytes); a uint256 word encodes the same
        U256::from(g.permission),
        g.not_before,
        g.expiry,
        g.max_opens,
        FixedBytes::<16>::from(g.request_nonce),
        U256::from(g.grant_nonce),
    );
    call(
        "grant((bytes32,bytes32,bytes32,uint8,uint64,uint64,uint16,bytes16,uint256),bytes)",
        (tuple, Bytes::copy_from_slice(owner_sig)).abi_encode_params(),
    )
}

/// `AccessPolicy.revoke(grantId)`.
pub fn revoke(grant_id: [u8; 32]) -> Bytes {
    call("revoke(bytes32)", (B256::from(grant_id),).abi_encode_params())
}

/// `AuditLog.log(fileId, kind, actorCommit, detail)`.
pub fn audit_log(file_id: [u8; 32], kind: u8, actor_commit: [u8; 32], detail: [u8; 32]) -> Bytes {
    call(
        "log(bytes32,uint8,bytes32,bytes32)",
        (B256::from(file_id), U256::from(kind), B256::from(actor_commit), B256::from(detail))
            .abi_encode_params(),
    )
}

/// `EntryPoint.getNonce(sender, key)` — read through `eth_call`.
pub fn entry_point_get_nonce(sender: alloy::primitives::Address, key: [u8; 24]) -> Bytes {
    let mut k = [0u8; 32];
    k[8..].copy_from_slice(&key);
    call("getNonce(address,uint192)", (sender, U256::from_be_bytes(k)).abi_encode_params())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned with `cast sig`; a wrong string here would silently call a wrong function.
    #[test]
    fn selectors_match_cast_sig() {
        assert_eq!(&register([0; 32], [0; 32])[..4], &[0x2f, 0x92, 0x67, 0x32]);
        assert_eq!(&bump_version([0; 32], [0; 32])[..4], &[0x1c, 0x3e, 0x31, 0xf6]);
        assert_eq!(&revoke([0; 32])[..4], &[0xb7, 0x5c, 0x7d, 0xc6]);
        assert_eq!(&audit_log([0; 32], 0, [0; 32], [0; 32])[..4], &[0xdf, 0xdb, 0x62, 0x00]);
        assert_eq!(
            &entry_point_get_nonce(alloy::primitives::Address::ZERO, [0; 24])[..4],
            &[0x35, 0x56, 0x7e, 0x1a]
        );
        let g = GrantArgs {
            file_id: [1; 32],
            header_hash: [2; 32],
            device_key_hash: [3; 32],
            permission: 1,
            not_before: 1,
            expiry: 2,
            max_opens: 1,
            request_nonce: [4; 16],
            grant_nonce: 0,
        };
        let data = grant(&g, &[0xAA; 96]);
        assert_eq!(&data[..4], &[0x25, 0x8a, 0x51, 0x72]);
        // 4 + 9 static words + offset word + (len word + 96 bytes) = 4 + 320 + 32 + 32 + 96
        assert_eq!(data.len(), 4 + 9 * 32 + 32 + 32 + 96);
        assert_eq!(&data[4..36], &[1; 32], "fileId is the first word");
        assert_eq!(data[4 + 3 * 32 + 31], 1, "permission is a right-aligned uint8");
    }
}
