// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title FileRegistry
/// @notice Maps a file commitment (fileId = SHA-256(plaintextHash || salt)) to its owner account and
///         latest container header hash. No file names, no content, no identities on-chain (T13).
/// @dev The header hash is what binds a grant to one specific sealed version: `AccessPolicy`
///      refuses a grant whose `headerHash` is not the current one, so an old version cannot be
///      re-granted after a reseal (T19). UUPS proxy + timelock deployment is Z-1.H.4.
contract FileRegistry {
    struct FileRecord {
        address owner;
        bytes32 headerHash; // latest sealed version's header hash
        uint32 version;
        /// @dev Owner retired the file: no further versions and no new grants.
        bool retired;
    }

    mapping(bytes32 fileId => FileRecord) private _files;

    event Registered(bytes32 indexed fileId, address indexed owner, bytes32 headerHash);
    event VersionBumped(bytes32 indexed fileId, uint32 version, bytes32 headerHash);
    event Retired(bytes32 indexed fileId);

    error AlreadyRegistered(bytes32 fileId);
    error NotOwner(bytes32 fileId, address caller);
    error NotRegistered(bytes32 fileId);
    error ZeroHash();
    error FileRetired(bytes32 fileId);
    error SameHeaderHash(bytes32 fileId);

    /// @notice Register a newly sealed file. Caller becomes the owner.
    function register(bytes32 fileId, bytes32 headerHash) external {
        if (headerHash == bytes32(0)) revert ZeroHash();
        if (_files[fileId].owner != address(0)) revert AlreadyRegistered(fileId);
        _files[fileId] = FileRecord({owner: msg.sender, headerHash: headerHash, version: 1, retired: false});
        emit Registered(fileId, msg.sender, headerHash);
    }

    /// @notice Record a reseal (new version). Only the owner.
    /// @dev The container's `fid` is stable across versions (container_format §5), so the record
    ///      keeps its key and only the header hash and version move forward.
    function bumpVersion(bytes32 fileId, bytes32 newHeaderHash) external {
        FileRecord storage f = _files[fileId];
        if (f.owner == address(0)) revert NotRegistered(fileId);
        if (f.owner != msg.sender) revert NotOwner(fileId, msg.sender);
        if (f.retired) revert FileRetired(fileId);
        if (newHeaderHash == bytes32(0)) revert ZeroHash();
        if (newHeaderHash == f.headerHash) revert SameHeaderHash(fileId);
        f.version += 1;
        f.headerHash = newHeaderHash;
        emit VersionBumped(fileId, f.version, newHeaderHash);
    }

    /// @notice Retire a file: no further versions, and `AccessPolicy` refuses new grants.
    /// @dev One-way. Existing grants are unaffected — revoke those separately (T20); the owner's
    ///      agent normally revokes and then retires.
    function retire(bytes32 fileId) external {
        FileRecord storage f = _files[fileId];
        if (f.owner == address(0)) revert NotRegistered(fileId);
        if (f.owner != msg.sender) revert NotOwner(fileId, msg.sender);
        if (f.retired) revert FileRetired(fileId);
        f.retired = true;
        emit Retired(fileId);
    }

    /// @notice Owner account, or the zero address when unknown.
    function ownerOf(bytes32 fileId) external view returns (address) {
        return _files[fileId].owner;
    }

    /// @notice Current header hash and version, and whether the file is retired.
    function currentVersion(bytes32 fileId)
        external
        view
        returns (bytes32 headerHash, uint32 version, bool retired)
    {
        FileRecord storage f = _files[fileId];
        return (f.headerHash, f.version, f.retired);
    }

    /// @notice Whole record (zeroed when unregistered).
    function fileOf(bytes32 fileId) external view returns (FileRecord memory) {
        return _files[fileId];
    }
}
