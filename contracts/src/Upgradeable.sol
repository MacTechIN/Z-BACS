// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/// @title Upgradeable
/// @notice What "we can fix this later" is allowed to mean in Z-BACS, in one place (Z-1.H.4).
///
/// @dev The bargain: the contracts that hold state a person depends on (`FileRegistry`,
///      `AccessPolicy`) can be fixed, but only through a `TimelockController`, so an upgrade is
///      announced on chain and cannot land before its delay has passed. Anyone watching can see
///      it coming and stop using the system.
///
///      Two contracts deliberately do **not** inherit this:
///
///      - `AuditLog` has no storage at all — it only emits. A change there is a new address in
///        the deployment file, not a silent swap under an existing history.
///      - `P256Validator` is installed as a validator module on **other people's** smart
///        accounts. If we could upgrade it, we could sign for every account that ever installed
///        it. That power should not exist, so it does not (ADR-0006, T12/T22).
///
///      Storage layout: the bases above come first (`AccessControl` holds one mapping;
///      `Initializable` and `UUPSUpgradeable` use ERC-7201 namespaced storage and immutables,
///      so they take no numbered slot). Never reorder the inheritance list of a deployed
///      contract, and only append new variables.
abstract contract Upgradeable is Initializable, AccessControl, UUPSUpgradeable {
    /// @notice An admin of zero would make the contract unupgradeable at birth, by accident.
    error ZeroAdmin();
    /// @notice See {renounceRole}.
    error AdminCannotBeRenounced();

    /// @dev Disables initialization of the implementation itself. The proxy has its own storage
    ///      and initializes there; the implementation must never be a usable contract.
    constructor() {
        _disableInitializers();
    }

    /// @param admin The `TimelockController`. Nothing else should hold this role.
    function __Upgradeable_init(address admin) internal onlyInitializing {
        if (admin == address(0)) revert ZeroAdmin();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /// @notice Who may upgrade this contract.
    function _authorizeUpgrade(address) internal virtual override onlyRole(DEFAULT_ADMIN_ROLE) {}

    /// @notice Renouncing the upgrade role is refused.
    /// @dev Not because immutability is wrong, but because this is the one way to reach it by
    ///      accident: a single transaction, no delay, no second signature, and the contract can
    ///      never be fixed again. Handing the role to someone else is grant-then-revoke, and
    ///      both halves go through the timelock where they can be seen and cancelled.
    function renounceRole(bytes32 role, address callerConfirmation) public virtual override {
        if (role == DEFAULT_ADMIN_ROLE) revert AdminCannotBeRenounced();
        super.renounceRole(role, callerConfirmation);
    }
}
