// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title AccessGrantLib
/// @notice EIP-712 struct and hashing for Z-BACS access tickets (docs/specs/approval_protocol.md §1.2).
/// @dev The struct hash is address/chain independent; the digest binds it to the domain
///      (name "Z-BACS", version "1", chainId, verifyingContract = AccessPolicy).
library AccessGrantLib {
    enum Permission {
        Deny,
        ReadOnly,
        Edit
    }

    struct AccessGrant {
        bytes32 fileId;
        bytes32 headerHash;
        bytes32 deviceKeyHash; // keccak256(device_x25519_pub || device_ed25519_pub)
        uint8 permission; // Permission
        uint64 notBefore;
        uint64 expiry;
        uint16 maxOpens;
        bytes16 requestNonce;
        uint256 grantNonce; // owner's sequential nonce (replay protection)
    }

    bytes32 internal constant ACCESS_GRANT_TYPEHASH = keccak256(
        "AccessGrant(bytes32 fileId,bytes32 headerHash,bytes32 deviceKeyHash,uint8 permission,"
        "uint64 notBefore,uint64 expiry,uint16 maxOpens,bytes16 requestNonce,uint256 grantNonce)"
    );

    /// @notice EIP-712 struct hash. Also used as `grantId`.
    function hashStruct(AccessGrant memory g) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                ACCESS_GRANT_TYPEHASH,
                g.fileId,
                g.headerHash,
                g.deviceKeyHash,
                g.permission,
                g.notBefore,
                g.expiry,
                g.maxOpens,
                g.requestNonce,
                g.grantNonce
            )
        );
    }
}
