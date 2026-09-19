// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {FileRegistry} from "../../src/FileRegistry.sol";
import {AccessPolicy} from "../../src/AccessPolicy.sol";

/// @dev Minimal smart-account stand-in: valid iff signature recovers to `signer` (stands in for a
///      passkey validator; Z-0.H.2 swaps this for Kernel + WebAuthn validator).
contract ERC1271Mock is IERC1271 {
    address public immutable signer;

    constructor(address signer_) {
        signer = signer_;
    }

    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
        (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        return
            (err == ECDSA.RecoverError.NoError && rec == signer)
                ? IERC1271.isValidSignature.selector
                : bytes4(0);
    }

    function registerFile(FileRegistry reg, bytes32 fileId, bytes32 headerHash) external {
        reg.register(fileId, headerHash);
    }

    function revokeGrant(AccessPolicy policy, bytes32 grantId) external {
        policy.revoke(grantId);
    }
}
