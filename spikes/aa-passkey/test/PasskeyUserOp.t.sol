// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console2} from "forge-std/Test.sol";
import {IEntryPoint, PackedUserOperation} from "../src/IEntryPoint.sol";
import {Recorder} from "../src/Recorder.sol";

/// Z-0.H.2 stage 2: replay the passkey-signed UserOperation from vectors/userop.json through
/// the real EntryPoint v0.7 on a Base Sepolia fork. Kernel v3.1 (ZeroDev) is deployed via its
/// real MetaFactory, and the WebAuthn validator verifies the software passkey's assertion.
///
///   node scripts/kernel-account.mjs
///   forge test --fork-url https://sepolia.base.org --match-path test/PasskeyUserOp.t.sol -vv
contract PasskeyUserOpTest is Test {
    IEntryPoint constant ENTRY_POINT = IEntryPoint(0x0000000071727De22E5E9d8BAf0edAc6f37da032);
    address payable constant BUNDLER = payable(address(0xB0B));

    string json;
    PackedUserOperation op;
    bytes signaturePrecompiled;
    address target;
    bytes32 recorded;

    function setUp() public {
        json = vm.readFile("vectors/userop.json");
        assertEq(block.chainid, vm.parseJsonUint(json, ".chainId"), "run against a Base Sepolia fork");
        assertEq(address(ENTRY_POINT), vm.parseJsonAddress(json, ".entryPoint"), "entry point");

        target = vm.parseJsonAddress(json, ".target");
        recorded = vm.parseJsonBytes32(json, ".recorded");
        vm.etch(target, address(new Recorder()).code);

        op = PackedUserOperation({
            sender: vm.parseJsonAddress(json, ".packed.sender"),
            nonce: vm.parseJsonUint(json, ".packed.nonce"),
            initCode: vm.parseJsonBytes(json, ".packed.initCode"),
            callData: vm.parseJsonBytes(json, ".packed.callData"),
            accountGasLimits: vm.parseJsonBytes32(json, ".packed.accountGasLimits"),
            preVerificationGas: vm.parseJsonUint(json, ".packed.preVerificationGas"),
            gasFees: vm.parseJsonBytes32(json, ".packed.gasFees"),
            paymasterAndData: vm.parseJsonBytes(json, ".packed.paymasterAndData"),
            signature: vm.parseJsonBytes(json, ".packed.signature")
        });
        signaturePrecompiled = vm.parseJsonBytes(json, ".signaturePrecompiled");

        // The account pays its own gas from an EntryPoint deposit (no paymaster in the spike).
        vm.deal(address(this), 10 ether);
        ENTRY_POINT.depositTo{value: 1 ether}(op.sender);
        vm.deal(BUNDLER, 1 ether);
    }

    function _ops() internal view returns (PackedUserOperation[] memory ops) {
        ops = new PackedUserOperation[](1);
        ops[0] = op;
    }

    function _handle(PackedUserOperation[] memory ops) internal returns (uint256 gasUsed) {
        uint256 before = gasleft();
        vm.prank(BUNDLER);
        ENTRY_POINT.handleOps(ops, BUNDLER);
        gasUsed = before - gasleft();
    }

    function test_userOpHash_matches_viem() public view {
        assertEq(ENTRY_POINT.getUserOpHash(op), vm.parseJsonBytes32(json, ".userOpHash"));
    }

    function test_passkey_userop_deploys_kernel_and_executes() public {
        assertEq(op.sender.code.length, 0, "account should be counterfactual");
        uint256 depositBefore = ENTRY_POINT.balanceOf(op.sender);

        uint256 gasUsed = _handle(_ops());

        assertGt(op.sender.code.length, 0, "Kernel account not deployed");
        assertEq(Recorder(target).last(), recorded, "call not executed");
        assertEq(Recorder(target).lastCaller(), op.sender, "caller is not the smart account");
        // Kernel v3 packs validator mode/type/address into the 192-bit nonce key.
        uint192 nonceKey = uint192(op.nonce >> 64);
        assertEq(ENTRY_POINT.getNonce(op.sender, nonceKey), op.nonce + 1, "nonce not consumed");
        assertLt(ENTRY_POINT.balanceOf(op.sender), depositBefore, "gas not charged to account");
        console2.log("handleOps gas (deploy Kernel v3.1 + WebAuthn verify, Solidity P-256):", gasUsed);
    }

    function test_passkey_userop_with_rip7212_precompile() public {
        op.signature = signaturePrecompiled;
        uint256 gasUsed = _handle(_ops());
        assertEq(Recorder(target).last(), recorded, "call not executed");
        console2.log("handleOps gas (deploy Kernel v3.1 + WebAuthn verify, RIP-7212 precompile):", gasUsed);
    }

    /// T14: a tampered assertion must fail signature validation (AA24), not execute.
    function test_t14_tampered_signature_rejected() public {
        bytes memory sig = op.signature;
        sig[sig.length - 40] ^= 0x01; // inside `s`
        op.signature = sig;
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        vm.prank(BUNDLER);
        ENTRY_POINT.handleOps(_ops(), BUNDLER);
    }

    /// T03: the same signed UserOperation cannot be replayed (nonce consumed).
    function test_t03_replay_rejected() public {
        _handle(_ops());
        PackedUserOperation[] memory replay = _ops();
        replay[0].initCode = "";
        vm.expectRevert(
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA25 invalid account nonce")
        );
        vm.prank(BUNDLER);
        ENTRY_POINT.handleOps(replay, BUNDLER);
    }
}
