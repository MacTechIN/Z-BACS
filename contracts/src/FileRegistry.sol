// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title FileRegistry (PoC, Z-0.H.1)
/// @notice Maps a file commitment (fileId = SHA-256(plaintextHash || salt)) to its owner account and
///         latest container header hash. No file names, no content, no identities on-chain (T13).
/// @dev Production version (Z-1.H.1) adds UUPS proxy, timelock and retire().
contract FileRegistry {
    struct FileRecord {
        address owner;
        bytes32 headerHash; // latest sealed version's header hash
        uint32 version;
    }

    mapping(bytes32 fileId => FileRecord) private _files;

    event Registered(bytes32 indexed fileId, address indexed owner, bytes32 headerHash);
    event VersionBumped(bytes32 indexed fileId, uint32 version, bytes32 headerHash);

    error AlreadyRegistered(bytes32 fileId);
    error NotOwner(bytes32 fileId, address caller);
    error NotRegistered(bytes32 fileId);
    error ZeroHash();

    /// @notice Register a newly sealed file. Caller becomes the owner.
    function register(bytes32 fileId, bytes32 headerHash) external {
        if (headerHash == bytes32(0)) revert ZeroHash();
        if (_files[fileId].owner != address(0)) revert AlreadyRegistered(fileId);
        _files[fileId] = FileRecord({owner: msg.sender, headerHash: headerHash, version: 1});
        emit Registered(fileId, msg.sender, headerHash);
    }

    /// @notice Record a reseal (new version). Only the owner.
    function bumpVersion(bytes32 fileId, bytes32 newHeaderHash) external {
        FileRecord storage f = _files[fileId];
        if (f.owner == address(0)) revert NotRegistered(fileId);
        if (f.owner != msg.sender) revert NotOwner(fileId, msg.sender);
        if (newHeaderHash == bytes32(0)) revert ZeroHash();
        f.version += 1;
        f.headerHash = newHeaderHash;
        emit VersionBumped(fileId, f.version, newHeaderHash);
    }

    function ownerOf(bytes32 fileId) external view returns (address) {
        return _files[fileId].owner;
    }

    function fileOf(bytes32 fileId) external view returns (FileRecord memory) {
        return _files[fileId];
    }
}
