// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {IERC7579Module, IERC7579Validator, PackedUserOperation} from "./interfaces/IERC7579Validator.sol";

/// @title P256Validator
/// @notice ERC-7579 validator for Z-BACS **device-bound keys** — signer path B of ADR-0006.
///         Each owner account registers one non-exportable P-256 key per device (Windows TPM,
///         Android Keystore, iOS Secure Enclave); approving a file request is then a raw P-256
///         signature over the user operation hash, with no WebAuthn wrapper.
///
///         Path A (platform passkeys: Windows Hello, Touch ID) keeps using Kernel's WebAuthn
///         validator. Both produce the same EIP-712 `AccessGrant`; recipients verify either
///         through ERC-1271 on the account and never learn which path was used.
///
/// @dev Keys are stored per account (`msg.sender` at enrol time), so one deployment serves every
///      owner. Signature encoding: `abi.encodePacked(keyId, r, s)` (96 bytes), matching
///      `OwnerSig::P256Raw` in docs/specs/approval_protocol.md §1.5.
///
///      Threats: T12 (lost device -> revoke from another device), T14 (signature forgery /
///      malleability: OZ `P256.verify` rejects `s > n/2`), T22 (device-bound keys cannot be
///      cloned to another device), T23 (`requireOsConfirm` records the owner's per-device
///      choice; the Agent enforces the prompt before the key is used, see
///      `zbacs-auth::ConfirmationPolicy`).
contract P256Validator is IERC7579Validator {
    /// @dev ERC-7579 module type id for validators.
    uint256 internal constant MODULE_TYPE_VALIDATOR = 1;
    /// @dev ERC-4337 validation results.
    uint256 internal constant VALIDATION_SUCCESS = 0;
    uint256 internal constant VALIDATION_FAILED = 1;
    /// @dev ERC-1271 magic value / failure.
    bytes4 internal constant ERC1271_MAGIC = 0x1626ba7e;
    bytes4 internal constant ERC1271_FAILED = 0xffffffff;

    /// @notice A registered device key.
    struct DeviceKey {
        bytes32 x;
        bytes32 y;
        /// @dev Owner's per-device choice: require an OS biometric/PIN prompt before signing.
        ///      Recorded on chain so the owner's other devices and audits can see it; the
        ///      prompt itself is enforced by the Agent (T23).
        bool requireOsConfirm;
        bool enrolled;
    }

    /// @dev account => keyId => key
    mapping(address => mapping(bytes32 => DeviceKey)) private _keys;
    /// @dev account => enrolled key ids (for "내 기기" listings)
    mapping(address => bytes32[]) private _keyIds;

    event DeviceEnrolled(address indexed account, bytes32 indexed keyId, bool requireOsConfirm);
    event DeviceRevoked(address indexed account, bytes32 indexed keyId);
    event ModuleInstalled(address indexed account);
    event ModuleUninstalled(address indexed account);

    error AlreadyEnrolled(bytes32 keyId);
    error NotEnrolled(bytes32 keyId);
    error InvalidPublicKey();
    error LastKeyCannotBeRevoked();
    error NoKeysOnInstall();
    error AlreadyInstalled();

    // ------------------------------------------------------------------ key id

    /// @notice `keyId = keccak256(x || y)` — the same identifier `zbacs-auth` computes off chain.
    function keyId(bytes32 x, bytes32 y) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(x, y));
    }

    // ------------------------------------------------------------------ enrolment

    /// @notice Register a device key for `msg.sender` (the owner's smart account).
    /// @dev Called through a user operation signed by an already-registered signer, so a new
    ///      device can only be added by a device the owner already controls (spec §1.5
    ///      `DeviceEnroll`). Onboarding enrols the first key via `onInstall`.
    function enrollKey(bytes32 x, bytes32 y, bool requireOsConfirm) external returns (bytes32 id) {
        id = _enroll(msg.sender, x, y, requireOsConfirm);
    }

    /// @notice Remove a device key (lost or retired device, T12/T22).
    /// @dev The last remaining key cannot be removed: that would lock the owner out of their own
    ///      account. Recovery of a sole lost device is Z-2.A.1 (social recovery).
    function revokeKey(bytes32 id) external {
        DeviceKey storage k = _keys[msg.sender][id];
        if (!k.enrolled) revert NotEnrolled(id);
        bytes32[] storage ids = _keyIds[msg.sender];
        if (ids.length == 1) revert LastKeyCannotBeRevoked();

        delete _keys[msg.sender][id];
        for (uint256 i = 0; i < ids.length; ++i) {
            if (ids[i] == id) {
                ids[i] = ids[ids.length - 1];
                ids.pop();
                break;
            }
        }
        emit DeviceRevoked(msg.sender, id);
    }

    function _enroll(address account, bytes32 x, bytes32 y, bool requireOsConfirm)
        internal
        returns (bytes32 id)
    {
        if (!P256.isValidPublicKey(x, y)) revert InvalidPublicKey();
        id = keyId(x, y);
        if (_keys[account][id].enrolled) revert AlreadyEnrolled(id);
        _keys[account][id] = DeviceKey({x: x, y: y, requireOsConfirm: requireOsConfirm, enrolled: true});
        _keyIds[account].push(id);
        emit DeviceEnrolled(account, id, requireOsConfirm);
    }

    // ------------------------------------------------------------------ views

    /// @notice The registered key, or a zeroed struct when `id` is unknown.
    function keyOf(address account, bytes32 id) external view returns (DeviceKey memory) {
        return _keys[account][id];
    }

    /// @notice Key ids registered for `account` ("내 기기" list).
    function keyIdsOf(address account) external view returns (bytes32[] memory) {
        return _keyIds[account];
    }

    /// @notice Number of registered keys.
    function keyCount(address account) external view returns (uint256) {
        return _keyIds[account].length;
    }

    /// @notice Whether this validator is initialised for `account`.
    function isInitialized(address account) public view returns (bool) {
        return _keyIds[account].length > 0;
    }

    // ------------------------------------------------------------------ ERC-7579 module

    /// @inheritdoc IERC7579Module
    /// @dev `data = abi.encodePacked(x, y, requireOsConfirm)` (65 bytes) — the first device key.
    function onInstall(bytes calldata data) external override {
        if (isInitialized(msg.sender)) revert AlreadyInstalled();
        if (data.length < 64) revert NoKeysOnInstall();
        bytes32 x = bytes32(data[0:32]);
        bytes32 y = bytes32(data[32:64]);
        bool requireOsConfirm = data.length > 64 && data[64] != 0;
        _enroll(msg.sender, x, y, requireOsConfirm);
        emit ModuleInstalled(msg.sender);
    }

    /// @inheritdoc IERC7579Module
    /// @dev Clears every key for the calling account.
    function onUninstall(bytes calldata) external override {
        bytes32[] storage ids = _keyIds[msg.sender];
        for (uint256 i = 0; i < ids.length; ++i) {
            delete _keys[msg.sender][ids[i]];
        }
        delete _keyIds[msg.sender];
        emit ModuleUninstalled(msg.sender);
    }

    /// @inheritdoc IERC7579Module
    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    // ------------------------------------------------------------------ validation

    /// @inheritdoc IERC7579Validator
    /// @dev Validation is view-only; no state is written, so the bundler's ERC-7562 rules are met.
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        return _verify(userOp.sender, userOpHash, userOp.signature) ? VALIDATION_SUCCESS : VALIDATION_FAILED;
    }

    /// @inheritdoc IERC7579Validator
    function isValidSignatureWithSender(address, bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4)
    {
        return _verify(msg.sender, hash, signature) ? ERC1271_MAGIC : ERC1271_FAILED;
    }

    /// @notice Verify `signature` (`keyId ‖ r ‖ s`) over `hash` against a key of `account`.
    /// @dev Public so the Agent can dry-run a signature before spending a user operation.
    function isValidSignatureForAccount(address account, bytes32 hash, bytes calldata signature)
        external
        view
        returns (bool)
    {
        return _verify(account, hash, signature);
    }

    function _verify(address account, bytes32 hash, bytes calldata signature) internal view returns (bool) {
        if (signature.length != 96) return false;
        bytes32 id = bytes32(signature[0:32]);
        bytes32 r = bytes32(signature[32:64]);
        bytes32 s = bytes32(signature[64:96]);
        DeviceKey storage k = _keys[account][id];
        if (!k.enrolled) return false;
        // OZ P256.verify: RIP-7212 precompile when present, Solidity fallback otherwise, and
        // rejects malleable (high-s) signatures — matching zbacs-auth's local check (T14).
        return P256.verify(hash, r, s, k.x, k.y);
    }
}
