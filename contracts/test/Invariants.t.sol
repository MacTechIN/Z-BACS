// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {AccessGrantLib} from "../src/AccessGrantLib.sol";
import {AccessPolicy} from "../src/AccessPolicy.sol";
import {FileRegistry} from "../src/FileRegistry.sol";

/// @dev Z-1.H.5 — the things that must stay true whatever sequence of calls two owners make.
///      Foundry's invariant fuzzer drives this handler (the owner shortcut of ADR-0008 makes
///      `grant` callable without signatures, so the fuzzer reaches every path); the
///      `invariant_*` functions below are checked after every call.
contract Handler is Test {
    FileRegistry public reg;
    AccessPolicy public pol;

    address[2] public owners = [address(0xA1), address(0xA2)];
    bytes constant DEVICE = "bob-x25519||bob-ed25519";

    bytes32[] public files;
    mapping(bytes32 => address) public fileOwner;
    mapping(bytes32 => uint32) public expectedVersion;
    mapping(bytes32 => bool) public everRetired;

    bytes32[] public grants;
    mapping(bytes32 => bytes32) public grantFile;
    mapping(bytes32 => bool) public everRevoked;
    mapping(address => uint256) public grantsBy;
    uint256 public requestSeq;

    constructor(FileRegistry reg_, AccessPolicy pol_) {
        reg = reg_;
        pol = pol_;
        vm.warp(1_700_000_000);
    }

    function _file(uint256 seed) internal view returns (bytes32) {
        return files[seed % files.length];
    }

    function register(uint256 seed) external {
        address owner = owners[seed % 2];
        bytes32 fid = keccak256(abi.encode("file", seed % 16));
        if (fileOwner[fid] != address(0)) return;
        vm.prank(owner);
        reg.register(fid, keccak256(abi.encode(fid, uint32(1))));
        files.push(fid);
        fileOwner[fid] = owner;
        expectedVersion[fid] = 1;
    }

    function bump(uint256 seed) external {
        if (files.length == 0) return;
        bytes32 fid = _file(seed);
        if (everRetired[fid]) return;
        uint32 next = expectedVersion[fid] + 1;
        vm.prank(fileOwner[fid]);
        reg.bumpVersion(fid, keccak256(abi.encode(fid, next)));
        expectedVersion[fid] = next;
    }

    function retire(uint256 seed) external {
        if (files.length == 0) return;
        bytes32 fid = _file(seed);
        if (everRetired[fid]) return;
        vm.prank(fileOwner[fid]);
        reg.retire(fid);
        everRetired[fid] = true;
    }

    function grant(uint256 seed, uint8 perm, uint64 ttl, uint16 maxOpens) external {
        if (files.length == 0) return;
        bytes32 fid = _file(seed);
        address owner = fileOwner[fid];
        (bytes32 header,,) = reg.currentVersion(fid);
        AccessGrantLib.AccessGrant memory g = AccessGrantLib.AccessGrant({
            fileId: fid,
            headerHash: header,
            deviceKeyHash: keccak256(DEVICE),
            permission: uint8(bound(perm, 1, 2)),
            notBefore: uint64(block.timestamp),
            expiry: uint64(block.timestamp + bound(ttl, 1, 7 days)),
            maxOpens: uint16(bound(maxOpens, 0, 3)),
            requestNonce: bytes16(keccak256(abi.encode("req", requestSeq++))),
            grantNonce: pol.nonces(owner)
        });
        if (everRetired[fid]) {
            // T20: a retired file takes no new grants, from anyone
            vm.prank(owner);
            vm.expectRevert(abi.encodeWithSelector(AccessPolicy.FileRetired.selector, fid));
            pol.grant(g, "");
            return;
        }
        vm.prank(owner);
        bytes32 id = pol.grant(g, "");
        grants.push(id);
        grantFile[id] = fid;
        grantsBy[owner] += 1;
    }

    function revoke(uint256 seed) external {
        if (grants.length == 0) return;
        bytes32 id = grants[seed % grants.length];
        vm.prank(fileOwner[grantFile[id]]);
        pol.revoke(id);
        everRevoked[id] = true;
    }

    function consume(uint256 seed) external {
        if (grants.length == 0) return;
        bytes32 id = grants[seed % grants.length];
        if (!pol.isValid(id)) return;
        pol.consumeOpen(id, DEVICE);
    }

    function warp(uint32 dt) external {
        vm.warp(block.timestamp + bound(dt, 0, 1 days));
    }

    function fileCount() external view returns (uint256) {
        return files.length;
    }

    function grantCount() external view returns (uint256) {
        return grants.length;
    }
}

contract InvariantsTest is Test {
    FileRegistry reg;
    AccessPolicy pol;
    Handler handler;

    function setUp() public {
        reg = new FileRegistry();
        pol = new AccessPolicy(reg);
        handler = new Handler(reg, pol);
        targetContract(address(handler));
    }

    /// T03: the owner nonce counts exactly the grants that landed, so no terms can be replayed.
    function invariant_nonce_counts_landed_grants() public view {
        for (uint256 i = 0; i < 2; i++) {
            address owner = handler.owners(i);
            assertEq(pol.nonces(owner), handler.grantsBy(owner), "nonce == grants by owner");
        }
    }

    /// T20: once revoked, never valid again — no later call, warp or open resurrects a grant.
    function invariant_a_revoked_grant_never_becomes_valid() public view {
        uint256 n = handler.grantCount();
        for (uint256 i = 0; i < n; i++) {
            bytes32 id = handler.grants(i);
            if (handler.everRevoked(id)) assertFalse(pol.isValid(id), "revoked grant valid");
        }
    }

    /// T19/T20: versions only move forward, one at a time, and retirement is one-way.
    function invariant_versions_move_forward_and_retirement_sticks() public view {
        uint256 n = handler.fileCount();
        for (uint256 i = 0; i < n; i++) {
            bytes32 fid = handler.files(i);
            (bytes32 header, uint32 version, bool retired) = reg.currentVersion(fid);
            assertEq(version, handler.expectedVersion(fid), "version drift");
            assertEq(header, keccak256(abi.encode(fid, version)), "header of the current version");
            assertEq(retired, handler.everRetired(fid), "retirement flipped back");
            assertEq(reg.ownerOf(fid), handler.fileOwner(fid), "owner changed");
        }
    }

    /// A grant never counts more opens than the owner allowed, and each grant names the file
    /// and device it was made for.
    function invariant_opens_stay_within_the_budget() public view {
        uint256 n = handler.grantCount();
        for (uint256 i = 0; i < n; i++) {
            bytes32 id = handler.grants(i);
            AccessPolicy.GrantRecord memory r = pol.grantOf(id);
            if (r.maxOpens != 0) assertLe(r.opens, r.maxOpens, "opens over budget");
            assertEq(r.fileId, handler.grantFile(id), "grant names another file");
            assertEq(r.deviceKeyHash, keccak256("bob-x25519||bob-ed25519"), "grant names another device");
        }
    }
}
