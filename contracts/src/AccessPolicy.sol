// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {AccessGrantLib} from "./AccessGrantLib.sol";
import {FileRegistry} from "./FileRegistry.sol";
import {Upgradeable} from "./Upgradeable.sol";

/// @title AccessPolicy
/// @notice Verifies owner-signed EIP-712 `AccessGrant` tickets, records them on-chain for audit and
///         revocation. Anyone (relayer / paymaster-sponsored UserOp) may submit a valid grant.
/// @dev Threats covered: T03 replay (grantNonce + requestNonce), T14 signature checks via OZ
///      SignatureChecker (EOA ECDSA or ERC-1271 smart account), T15 time checks with on-chain
///      time, T19 version binding (the grant must name the registry's current header hash, so a
///      superseded version cannot be granted after a reseal), T20 revoke + retire.
/// @dev Deployed behind a UUPS proxy with a `TimelockController` as upgrade admin (Z-1.H.4).
///      The EIP-712 domain's `verifyingContract` is therefore the **proxy** address: OpenZeppelin's
///      cached domain separator is built for the implementation, does not match at runtime, and
///      is rebuilt with `address(this)` — which is what an off-chain signer must use too.
contract AccessPolicy is EIP712, Upgradeable {
    using AccessGrantLib for AccessGrantLib.AccessGrant;

    struct GrantRecord {
        bytes32 fileId;
        address owner;
        uint64 notBefore;
        uint64 expiry;
        uint16 maxOpens;
        uint16 opens;
        uint8 permission;
        bool revoked;
        /// @dev keccak256(device_x25519_pub || device_ed25519_pub) the grant was bound to.
        bytes32 deviceKeyHash;
        /// @dev Container header hash this grant was issued against (T19).
        bytes32 headerHash;
    }

    /// @dev Immutable, so it lives in the implementation's code rather than in a storage slot
    ///      an upgrade could quietly rewrite. The cost is that a new implementation has to be
    ///      built against the same registry proxy — which {_authorizeUpgrade} enforces.
    FileRegistry public immutable registry;

    /// @notice A replacement implementation points somewhere else.
    error RegistryMismatch(address expected, address found);

    /// @notice Set the upgrade admin. Called once, on the proxy, at deployment.
    function initialize(address admin) external initializer {
        __Upgradeable_init(admin);
    }

    /// @dev An upgrade that repoints the registry would let whoever deployed it decide who owns
    ///      which file. Fail closed: if the replacement does not answer `registry()` with the
    ///      same address, the upgrade does not happen.
    function _authorizeUpgrade(address newImplementation) internal override {
        super._authorizeUpgrade(newImplementation);
        address found = address(AccessPolicy(newImplementation).registry());
        if (found != address(registry)) revert RegistryMismatch(address(registry), found);
    }

    /// @notice Per-owner sequential nonce consumed by each grant.
    mapping(address owner => uint256) public nonces;
    /// @notice Request nonces already bound to a grant (defense in depth against relayer replays).
    mapping(bytes16 requestNonce => bool) public usedRequestNonce;
    mapping(bytes32 grantId => GrantRecord) private _grants;

    event Granted(
        bytes32 indexed grantId,
        bytes32 indexed fileId,
        bytes32 indexed deviceKeyHash,
        uint8 permission,
        uint64 expiry
    );
    event Revoked(bytes32 indexed grantId, bytes32 indexed fileId);
    event Opened(bytes32 indexed grantId, uint16 opens);

    error FileNotRegistered(bytes32 fileId);
    error FileRetired(bytes32 fileId);
    error StaleVersion(bytes32 expected, bytes32 given);
    error WrongDevice(bytes32 expected, bytes32 given);
    error InvalidSignature();
    error BadNonce(uint256 expected, uint256 given);
    error RequestNonceUsed(bytes16 requestNonce);
    error InvalidPermission(uint8 permission);
    error InvalidWindow(uint64 notBefore, uint64 expiry);
    error AlreadyExpired(uint64 expiry);
    error UnknownGrant(bytes32 grantId);
    error NotOwner(bytes32 grantId, address caller);
    error GrantNotActive(bytes32 grantId);
    error OpensExhausted(bytes32 grantId);

    constructor(FileRegistry registry_) EIP712("Z-BACS", "1") {
        registry = registry_;
    }

    // ------------------------------------------------------------------ views

    function hashGrant(AccessGrantLib.AccessGrant calldata g) external pure returns (bytes32) {
        return g.hashStruct();
    }

    /// @notice Full EIP-712 digest that the owner signs.
    function digestOf(AccessGrantLib.AccessGrant calldata g) external view returns (bytes32) {
        return _hashTypedDataV4(g.hashStruct());
    }

    function grantOf(bytes32 grantId) external view returns (GrantRecord memory) {
        return _grants[grantId];
    }

    /// @notice True while the grant exists, is not revoked, is within its time window and has opens left.
    function isValid(bytes32 grantId) public view returns (bool) {
        GrantRecord storage r = _grants[grantId];
        if (r.owner == address(0) || r.revoked) return false;
        if (block.timestamp < r.notBefore || block.timestamp >= r.expiry) return false;
        if (r.maxOpens != 0 && r.opens >= r.maxOpens) return false;
        return true;
    }

    // ------------------------------------------------------------------ writes

    /// @notice Submit an owner-signed grant. Returns grantId (= EIP-712 struct hash).
    function grant(AccessGrantLib.AccessGrant calldata g, bytes calldata ownerSig)
        external
        returns (bytes32 grantId)
    {
        address owner = registry.ownerOf(g.fileId);
        if (owner == address(0)) revert FileNotRegistered(g.fileId);
        (bytes32 currentHeader,, bool retired) = registry.currentVersion(g.fileId);
        if (retired) revert FileRetired(g.fileId);
        // T19: a grant names one sealed version; after a reseal the old one can no longer be granted.
        if (g.headerHash != currentHeader) revert StaleVersion(currentHeader, g.headerHash);
        if (g.permission > uint8(AccessGrantLib.Permission.Edit)) revert InvalidPermission(g.permission);
        if (g.notBefore >= g.expiry) revert InvalidWindow(g.notBefore, g.expiry);
        if (g.expiry <= block.timestamp) revert AlreadyExpired(g.expiry);
        if (g.grantNonce != nonces[owner]) revert BadNonce(nonces[owner], g.grantNonce);
        if (usedRequestNonce[g.requestNonce]) revert RequestNonceUsed(g.requestNonce);

        bytes32 structHash = g.hashStruct();
        bytes32 digest = _hashTypedDataV4(structHash);
        if (!SignatureChecker.isValidSignatureNow(owner, digest, ownerSig)) revert InvalidSignature();

        nonces[owner] = g.grantNonce + 1;
        usedRequestNonce[g.requestNonce] = true;
        grantId = structHash;
        _grants[grantId] = GrantRecord({
            fileId: g.fileId,
            owner: owner,
            notBefore: g.notBefore,
            expiry: g.expiry,
            maxOpens: g.maxOpens,
            opens: 0,
            permission: g.permission,
            revoked: false,
            deviceKeyHash: g.deviceKeyHash,
            headerHash: g.headerHash
        });
        // SignatureChecker uses staticcall for ERC-1271, so no state can change before this emit.
        // forge-lint: disable-next-line(reentrancy-events)
        emit Granted(grantId, g.fileId, g.deviceKeyHash, g.permission, g.expiry);
    }

    /// @notice Owner revokes an active grant (T20: recipient agents poll isValid()).
    function revoke(bytes32 grantId) external {
        GrantRecord storage r = _grants[grantId];
        if (r.owner == address(0)) revert UnknownGrant(grantId);
        if (r.owner != msg.sender) revert NotOwner(grantId, msg.sender);
        r.revoked = true;
        emit Revoked(grantId, r.fileId);
    }

    /// @notice Count one open against `maxOpens`, proving which device is opening.
    /// @param devicePubKeys `device_x25519_pub || device_ed25519_pub`; its keccak256 must equal the
    ///        `deviceKeyHash` the owner signed into the grant.
    /// @dev This binds the counter to a caller who knows the granted device's public keys. It is
    ///      not an attestation that the device itself is calling: verifying an Ed25519 device
    ///      signature on-chain needs a precompile this chain does not have, so remote attestation
    ///      stays Z-3.H.3. The counter is advisory; the recipient agent enforces `maxOpens`
    ///      locally and the chain keeps the audit trail.
    function consumeOpen(bytes32 grantId, bytes calldata devicePubKeys) external {
        GrantRecord storage r = _grants[grantId];
        if (r.owner == address(0)) revert UnknownGrant(grantId);
        if (!isValid(grantId)) revert GrantNotActive(grantId);
        bytes32 given = keccak256(devicePubKeys);
        if (given != r.deviceKeyHash) revert WrongDevice(r.deviceKeyHash, given);
        r.opens += 1;
        emit Opened(grantId, r.opens);
    }
}
