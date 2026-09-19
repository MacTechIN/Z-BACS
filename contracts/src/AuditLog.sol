// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title AuditLog
/// @notice Event-only contract for the steps that do not change on-chain state but must stay
///         auditable: a request being made, refused, opened or resealed (T07 traceability).
///         `AccessPolicy` already emits `Granted`/`Revoked`/`Opened` for the ticket lifecycle;
///         this contract records what the agents observed on the endpoints.
///
/// @dev Privacy (T13): no file names, no addresses of recipients, no plaintext. The actor is a
///      commitment `actorCommit = keccak256(deviceKid || salt)` chosen by the reporting agent,
///      so the same device is linkable only by whoever knows the salt. `detail` is an opaque
///      32-byte slot (e.g. a header hash for `Sealed`, a reason code for `Denied`).
///
///      Writes are permissionless and the contract is event-only: no storage, no cross-contract
///      lookup, so one entry stays inside the 30k gas budget (Z-1.H.3; a registry lookup alone
///      costs ~4.7k and pushed it over). Readers subscribe by the `fileId` they already know and
///      treat entries as claims by `reporter`, never as proof — an agent's device key cannot be
///      verified on-chain (no Ed25519 precompile), so remote attestation stays Z-3.H.3. Entries
///      for unknown file ids are simply noise nobody subscribes to; the ticket lifecycle that
///      does need authorisation lives in `AccessPolicy`.
contract AuditLog {
    /// @notice What happened. `Granted`/`Revoked` live in `AccessPolicy`, not here.
    enum Kind {
        Requested,
        Denied,
        Opened,
        Sealed,
        Failed
    }

    /// @param fileId  The file the entry is about (indexed for cheap filtering).
    /// @param kind    Which step (indexed so an agent can subscribe to `Sealed` only).
    /// @param reporter Who submitted the entry; a claim, not an attestation.
    event Logged(
        bytes32 indexed fileId,
        Kind indexed kind,
        address indexed reporter,
        bytes32 actorCommit,
        bytes32 detail
    );

    /// @notice Append one entry. Emits [`Logged`]; stores nothing.
    /// @dev One event, three indexed topics, two data words: 25,515 gas as a whole transaction
    ///      on Anvil (21k base + calldata + LOG4), inside the 30k budget (Z-1.H.3).
    function log(bytes32 fileId, Kind kind, bytes32 actorCommit, bytes32 detail) external {
        emit Logged(fileId, kind, msg.sender, actorCommit, detail);
    }
}
