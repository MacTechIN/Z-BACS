// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {FileRegistry} from "../src/FileRegistry.sol";

contract FileRegistryTest is Test {
    FileRegistry reg;
    address alice = address(0xA11CE);
    bytes32 constant FID = keccak256("f");

    function setUp() public {
        reg = new FileRegistry();
    }

    function test_register_and_bump() public {
        vm.startPrank(alice);
        reg.register(FID, keccak256("h1"));
        assertEq(reg.ownerOf(FID), alice);
        reg.bumpVersion(FID, keccak256("h2"));
        vm.stopPrank();
        FileRegistry.FileRecord memory f = reg.fileOf(FID);
        assertEq(f.version, 2);
        assertEq(f.headerHash, keccak256("h2"));
    }

    function test_t02_only_owner_bumps() public {
        vm.prank(alice);
        reg.register(FID, keccak256("h1"));
        vm.expectRevert(abi.encodeWithSelector(FileRegistry.NotOwner.selector, FID, address(this)));
        reg.bumpVersion(FID, keccak256("h2"));
    }

    function test_double_register_rejected() public {
        vm.prank(alice);
        reg.register(FID, keccak256("h1"));
        vm.expectRevert(abi.encodeWithSelector(FileRegistry.AlreadyRegistered.selector, FID));
        reg.register(FID, keccak256("h1"));
    }

    // ------------------------------------------------------------ Z-1.H.1 retire + version binding

    function test_retire_blocks_further_versions() public {
        vm.startPrank(alice);
        reg.register(FID, keccak256("h1"));
        vm.expectEmit(true, true, true, true);
        emit FileRegistry.Retired(FID);
        reg.retire(FID);
        vm.stopPrank();

        (,, bool retired) = reg.currentVersion(FID);
        assertTrue(retired);
        assertTrue(reg.fileOf(FID).retired);

        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(FileRegistry.FileRetired.selector, FID));
        reg.bumpVersion(FID, keccak256("v2"));
        vm.expectRevert(abi.encodeWithSelector(FileRegistry.FileRetired.selector, FID));
        reg.retire(FID);
        vm.stopPrank();
    }

    function test_retire_requires_owner_and_registration() public {
        vm.prank(alice);
        reg.register(FID, keccak256("h1"));

        vm.startPrank(address(0xBAD));
        vm.expectRevert(abi.encodeWithSelector(FileRegistry.NotOwner.selector, FID, address(0xBAD)));
        reg.retire(FID);
        vm.stopPrank();

        bytes32 unknown = keccak256("unknown");
        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(FileRegistry.NotRegistered.selector, unknown));
        reg.retire(unknown);
        vm.stopPrank();
    }

    function test_bumpVersion_rejects_an_unchanged_header_hash() public {
        vm.startPrank(alice);
        reg.register(FID, keccak256("h1"));
        vm.expectRevert(abi.encodeWithSelector(FileRegistry.SameHeaderHash.selector, FID));
        reg.bumpVersion(FID, keccak256("h1"));
        vm.stopPrank();
    }

    function test_currentVersion_tracks_reseals() public {
        vm.startPrank(alice);
        reg.register(FID, keccak256("h1"));
        (bytes32 h, uint32 v, bool retired) = reg.currentVersion(FID);
        assertEq(h, keccak256("h1"));
        assertEq(v, 1);
        assertFalse(retired);

        reg.bumpVersion(FID, keccak256("v2"));
        reg.bumpVersion(FID, keccak256("v3"));
        vm.stopPrank();
        (h, v,) = reg.currentVersion(FID);
        assertEq(h, keccak256("v3"));
        assertEq(v, 3);
    }

    function test_currentVersion_of_unknown_file_is_zeroed() public view {
        (bytes32 h, uint32 v, bool retired) = reg.currentVersion(keccak256("nope"));
        assertEq(h, bytes32(0));
        assertEq(v, 0);
        assertFalse(retired);
    }

    function test_zero_header_hash_rejected_on_register_and_bump() public {
        vm.startPrank(alice);
        vm.expectRevert(FileRegistry.ZeroHash.selector);
        reg.register(FID, bytes32(0));

        reg.register(FID, keccak256("h1"));
        vm.expectRevert(FileRegistry.ZeroHash.selector);
        reg.bumpVersion(FID, bytes32(0));
        vm.stopPrank();
    }

    function test_bump_of_unregistered_file_rejected() public {
        bytes32 unknown = keccak256("unknown");
        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(FileRegistry.NotRegistered.selector, unknown));
        reg.bumpVersion(unknown, keccak256("h2"));
        vm.stopPrank();
    }
}
