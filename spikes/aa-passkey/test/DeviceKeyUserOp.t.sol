// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console2} from "forge-std/Test.sol";
import {IEntryPoint, PackedUserOperation as EPUserOp} from "../src/IEntryPoint.sol";
import {Recorder} from "../src/Recorder.sol";
import {P256Validator} from "zbacs/P256Validator.sol";

interface IKernelFactory {
    function createAccount(bytes calldata data, bytes32 salt) external payable returns (address);
    function getAddress(bytes calldata data, bytes32 salt) external view returns (address);
}

interface IKernel {
    function initialize(
        bytes21 rootValidator,
        address hook,
        bytes calldata validatorData,
        bytes calldata hookData,
        bytes[] calldata initConfig
    ) external;
    function execute(bytes32 execMode, bytes calldata executionCalldata) external payable;
}

/// Z-1.H.10 integration: a Z-BACS **device-bound key** (ADR-0006 path B) drives a real Kernel
/// v3.1 account through the real EntryPoint v0.7, on a Base Sepolia fork.
///
///   forge test --fork-url https://sepolia.base.org --match-path test/DeviceKeyUserOp.t.sol -vv
///
/// Path A (platform passkey / Windows Hello) is covered by PasskeyUserOp.t.sol; this file is
/// the same journey with our own validator instead of Kernel's WebAuthn one.
contract DeviceKeyUserOpTest is Test {
    IEntryPoint constant ENTRY_POINT = IEntryPoint(0x0000000071727De22E5E9d8BAf0edAc6f37da032);
    IKernelFactory constant KERNEL_FACTORY = IKernelFactory(0x7a1dBAB750f12a90EB1B60D2Ae3aD17D4D81EfFe);
    address payable constant BUNDLER = payable(address(0xB0B));
    address constant TARGET = 0x000000000000000000000000000000000000bEEF;

    uint256 constant HALF_N = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;
    uint256 constant N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    P256Validator validator;
    address account;
    uint256 laptopPk = uint256(keccak256("zbacs-laptop-tpm"));
    uint256 phonePk = uint256(keccak256("zbacs-phone-keystore"));

    function setUp() public {
        vm.skip(block.chainid != 84532); // fork-only test
        validator = new P256Validator();
        vm.etch(TARGET, address(new Recorder()).code);

        (bytes32 x, bytes32 y) = _pub(laptopPk);
        bytes memory init = abi.encodeCall(
            IKernel.initialize,
            (
                bytes21(abi.encodePacked(bytes1(0x01), address(validator))), // root validator id
                address(0), // no hook
                abi.encodePacked(x, y, uint8(1)), // onInstall data: first device key
                "",
                new bytes[](0)
            )
        );
        account = KERNEL_FACTORY.getAddress(init, bytes32(0));
        assertEq(KERNEL_FACTORY.createAccount(init, bytes32(0)), account, "counterfactual address");
        assertGt(account.code.length, 0, "kernel deployed");
        assertEq(validator.keyCount(account), 1, "device key enrolled through onInstall");

        vm.deal(address(this), 10 ether);
        ENTRY_POINT.depositTo{value: 1 ether}(account);
        vm.deal(BUNDLER, 1 ether);
    }

    function _pub(uint256 pk) internal pure returns (bytes32 x, bytes32 y) {
        (uint256 qx, uint256 qy) = vm.publicKeyP256(pk);
        return (bytes32(qx), bytes32(qy));
    }

    function _sign(uint256 pk, bytes32 digest) internal view returns (bytes memory) {
        (bytes32 r, bytes32 s) = vm.signP256(pk, digest);
        if (uint256(s) > HALF_N) s = bytes32(N - uint256(s)); // low-s, as the Agent normalises
        (bytes32 x, bytes32 y) = _pub(pk);
        return abi.encodePacked(validator.keyId(x, y), r, s);
    }

    /// Kernel v3 nonce key: mode(1) | type(1) | identifier(20) | key(2). Root validation = 0x00/0x00.
    function _nonce() internal view returns (uint256) {
        uint192 key =
            uint192(bytes24(abi.encodePacked(bytes1(0x00), bytes1(0x00), address(validator), bytes2(0))));
        return ENTRY_POINT.getNonce(account, key);
    }

    function _op(uint256 pk, bytes32 recorded) internal view returns (EPUserOp[] memory ops) {
        bytes memory call = abi.encodeCall(Recorder.record, (recorded));
        bytes memory executionCalldata = abi.encodePacked(TARGET, uint256(0), call);
        EPUserOp memory op = EPUserOp({
            sender: account,
            nonce: _nonce(),
            initCode: "",
            callData: abi.encodeCall(IKernel.execute, (bytes32(0), executionCalldata)),
            accountGasLimits: bytes32(abi.encodePacked(uint128(500_000), uint128(300_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(0.1 gwei), uint128(1 gwei))),
            paymasterAndData: "",
            signature: ""
        });
        op.signature = _sign(pk, ENTRY_POINT.getUserOpHash(op));
        ops = new EPUserOp[](1);
        ops[0] = op;
    }

    function _handle(EPUserOp[] memory ops) internal returns (uint256 gasUsed) {
        uint256 before = gasleft();
        vm.prank(BUNDLER);
        ENTRY_POINT.handleOps(ops, BUNDLER);
        gasUsed = before - gasleft();
    }

    /// DoD: an enrolled device key drives one user operation to success.
    function test_device_key_userop_executes() public {
        bytes32 recorded = keccak256("zbacs device key approval");
        uint256 gasUsed = _handle(_op(laptopPk, recorded));
        assertEq(Recorder(TARGET).last(), recorded, "call not executed");
        assertEq(Recorder(TARGET).lastCaller(), account, "caller is not the smart account");
        console2.log("handleOps gas (device key, P256VERIFY precompile):", gasUsed);
    }

    /// T14: a key that was never enrolled cannot approve.
    function test_t14_unenrolled_device_rejected() public {
        // build first: expectRevert must be armed immediately before the reverting call
        EPUserOp[] memory ops = _op(phonePk, keccak256("nope"));
        vm.prank(BUNDLER);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ENTRY_POINT.handleOps(ops, BUNDLER);
    }

    /// T12/T22: the owner adds a phone from the laptop, then revokes the laptop from the phone.
    /// The revoked device's signature stops being accepted by the EntryPoint (AA24).
    function test_t12_enroll_second_device_then_revoke_first() public {
        (bytes32 px, bytes32 py) = _pub(phonePk);
        (bytes32 lx, bytes32 ly) = _pub(laptopPk);

        // 1. laptop signs a user operation that enrols the phone
        bytes memory enrollCall = abi.encodeCall(P256Validator.enrollKey, (px, py, false));
        _handleCall(laptopPk, address(validator), enrollCall);
        assertEq(validator.keyCount(account), 2, "phone enrolled");

        // 2. the phone can now approve
        bytes32 recorded = keccak256("approved from phone");
        _handle(_op(phonePk, recorded));
        assertEq(Recorder(TARGET).last(), recorded);

        // 3. laptop is lost: revoke it from the phone
        bytes32 laptopId = validator.keyId(lx, ly);
        _handleCall(phonePk, address(validator), abi.encodeCall(P256Validator.revokeKey, (laptopId)));
        assertEq(validator.keyCount(account), 1, "laptop revoked");
        assertFalse(validator.keyOf(account, laptopId).enrolled);

        // 4. the lost laptop can no longer approve anything
        EPUserOp[] memory stolen = _op(laptopPk, keccak256("stolen"));
        vm.prank(BUNDLER);
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ENTRY_POINT.handleOps(stolen, BUNDLER);
    }

    /// T03: a signed user operation cannot be replayed (EntryPoint nonce).
    function test_t03_replay_rejected() public {
        EPUserOp[] memory ops = _op(laptopPk, keccak256("once"));
        _handle(ops);
        vm.prank(BUNDLER);
        vm.expectRevert(
            abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA25 invalid account nonce")
        );
        ENTRY_POINT.handleOps(ops, BUNDLER);
    }

    /// Send an arbitrary call from the account, signed by `pk` (used for enrol/revoke ops).
    function _handleCall(uint256 pk, address to, bytes memory data) internal {
        EPUserOp memory op = EPUserOp({
            sender: account,
            nonce: _nonce(),
            initCode: "",
            callData: abi.encodeCall(IKernel.execute, (bytes32(0), abi.encodePacked(to, uint256(0), data))),
            accountGasLimits: bytes32(abi.encodePacked(uint128(500_000), uint128(300_000))),
            preVerificationGas: 100_000,
            gasFees: bytes32(abi.encodePacked(uint128(0.1 gwei), uint128(1 gwei))),
            paymasterAndData: "",
            signature: ""
        });
        op.signature = _sign(pk, ENTRY_POINT.getUserOpHash(op));
        EPUserOp[] memory ops = new EPUserOp[](1);
        ops[0] = op;
        _handle(ops);
    }
}
