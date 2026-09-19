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
}
