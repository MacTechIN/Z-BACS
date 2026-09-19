// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @dev ERC-4337 v0.7 user operation, packed form. Declared here rather than vendored from the
/// GPL-3.0 reference implementation (CLAUDE.md rule 4).
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

/// @dev ERC-7579 module base surface.
interface IERC7579Module {
    /// @notice Called by an account when it installs this module.
    function onInstall(bytes calldata data) external;
    /// @notice Called by an account when it uninstalls this module.
    function onUninstall(bytes calldata data) external;
    /// @notice Module type ids this module implements (1 = validator).
    function isModuleType(uint256 moduleTypeId) external view returns (bool);
}

/// @dev ERC-7579 validator module (type 1).
interface IERC7579Validator is IERC7579Module {
    /// @notice Validate a user operation. Returns ERC-4337 validation data
    ///         (0 = valid, 1 = signature failure).
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        returns (uint256);

    /// @notice ERC-1271 style check routed through the account.
    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata signature)
        external
        view
        returns (bytes4);
}
