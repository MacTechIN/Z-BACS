// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {P256Validator} from "../src/P256Validator.sol";
import {IERC7579Validator, PackedUserOperation} from "../src/interfaces/IERC7579Validator.sol";

/// Z-1.H.10 — device-bound key validator (ADR-0006 signer path B).
/// Integration through the real Kernel account + EntryPoint lives in
/// `spikes/aa-passkey/test/DeviceKeyUserOp.t.sol` (Base Sepolia fork).
contract P256ValidatorTest is Test {
    uint256 constant HALF_N = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;
    uint256 constant N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    P256Validator validator;

    // "devices": laptop is the first enrolled key, phone is added later
    uint256 laptopPk = uint256(keccak256("zbacs-laptop-tpm"));
    uint256 phonePk = uint256(keccak256("zbacs-phone-keystore"));
    address account = address(0xA11CE);

    function setUp() public {
        validator = new P256Validator();
        (bytes32 x, bytes32 y) = _pub(laptopPk);
        vm.prank(account);
        validator.onInstall(abi.encodePacked(x, y, uint8(1)));
    }

    function _pub(uint256 pk) internal pure returns (bytes32 x, bytes32 y) {
        (uint256 qx, uint256 qy) = vm.publicKeyP256(pk);
        return (bytes32(qx), bytes32(qy));
    }

    /// Sign like a hardware device would, then normalise to low-s as the Agent does.
    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes32 r, bytes32 s) {
        (r, s) = vm.signP256(pk, digest);
        if (uint256(s) > HALF_N) s = bytes32(N - uint256(s));
    }

    function _sig(uint256 pk, bytes32 digest) internal view returns (bytes memory) {
        (bytes32 x, bytes32 y) = _pub(pk);
        (bytes32 r, bytes32 s) = _sign(pk, digest);
        return abi.encodePacked(validator.keyId(x, y), r, s);
    }

    function _userOp(bytes memory signature) internal view returns (PackedUserOperation memory op) {
        op.sender = account;
        op.signature = signature;
    }

    // ------------------------------------------------------------------ enrolment

    function test_install_enrolls_first_device_key() public view {
        (bytes32 x, bytes32 y) = _pub(laptopPk);
        bytes32 id = validator.keyId(x, y);
        assertTrue(validator.isInitialized(account));
        assertEq(validator.keyCount(account), 1);
        P256Validator.DeviceKey memory k = validator.keyOf(account, id);
        assertEq(k.x, x);
        assertEq(k.y, y);
        assertTrue(k.requireOsConfirm, "owner chose biometric confirmation on this device");
        assertEq(validator.keyIdsOf(account)[0], id);
    }

    function test_keyId_matches_offchain_keccak_of_xy() public view {
        (bytes32 x, bytes32 y) = _pub(laptopPk);
        assertEq(validator.keyId(x, y), keccak256(abi.encodePacked(x, y)));
    }

    function test_install_rejects_second_install_and_empty_key() public {
        (bytes32 x, bytes32 y) = _pub(phonePk);
        vm.startPrank(account);
        vm.expectRevert(P256Validator.AlreadyInstalled.selector);
        validator.onInstall(abi.encodePacked(x, y, uint8(0)));
        vm.stopPrank();

        vm.startPrank(address(0xB0B));
        vm.expectRevert(P256Validator.NoKeysOnInstall.selector);
        validator.onInstall(hex"1234");
        vm.stopPrank();
    }

    function test_enroll_rejects_invalid_public_key_and_duplicates() public {
        (bytes32 x, bytes32 y) = _pub(laptopPk);
        bytes32 id = validator.keyId(x, y);
        vm.startPrank(account);
        vm.expectRevert(P256Validator.InvalidPublicKey.selector);
        validator.enrollKey(bytes32(uint256(1)), bytes32(uint256(2)), false);

        vm.expectRevert(abi.encodeWithSelector(P256Validator.AlreadyEnrolled.selector, id));
        validator.enrollKey(x, y, false);
        vm.stopPrank();
    }

    /// A second device is added by the account itself (i.e. by a user operation the first
    /// device signed) — spec §1.5 `DeviceEnroll`.
    function test_t12_second_device_enrolled_by_the_account_can_approve() public {
        (bytes32 px, bytes32 py) = _pub(phonePk);
        vm.startPrank(account);
        vm.expectEmit(true, true, true, true);
        emit P256Validator.DeviceEnrolled(account, validator.keyId(px, py), false);
        validator.enrollKey(px, py, false);
        vm.stopPrank();

        assertEq(validator.keyCount(account), 2);
        bytes32 digest = keccak256("AccessGrant digest");
        assertEq(validator.validateUserOp(_userOp(_sig(phonePk, digest)), digest), 0);
        assertEq(validator.validateUserOp(_userOp(_sig(laptopPk, digest)), digest), 0);
    }

    function test_t12_revoked_device_can_no_longer_approve() public {
        (bytes32 px, bytes32 py) = _pub(phonePk);
        bytes32 phoneId = validator.keyId(px, py);
        vm.startPrank(account);
        validator.enrollKey(px, py, false);
        vm.expectEmit(true, true, true, true);
        emit P256Validator.DeviceRevoked(account, phoneId);
        validator.revokeKey(phoneId);
        vm.stopPrank();

        bytes32 digest = keccak256("AccessGrant digest");
        assertEq(validator.validateUserOp(_userOp(_sig(phonePk, digest)), digest), 1, "revoked key must fail");
        assertEq(
            validator.validateUserOp(_userOp(_sig(laptopPk, digest)), digest), 0, "other key still works"
        );
        assertEq(validator.keyCount(account), 1);
        assertFalse(validator.keyOf(account, phoneId).enrolled);
    }

    function test_t12_last_key_cannot_be_revoked_and_unknown_key_reverts() public {
        (bytes32 x, bytes32 y) = _pub(laptopPk);
        bytes32 id = validator.keyId(x, y);
        vm.startPrank(account);
        vm.expectRevert(P256Validator.LastKeyCannotBeRevoked.selector);
        validator.revokeKey(id);

        vm.expectRevert(abi.encodeWithSelector(P256Validator.NotEnrolled.selector, bytes32(uint256(7))));
        validator.revokeKey(bytes32(uint256(7)));
        vm.stopPrank();
    }

    function test_revoke_keeps_the_id_list_consistent() public {
        uint256[3] memory pks = [uint256(keccak256("d1")), uint256(keccak256("d2")), uint256(keccak256("d3"))];
        bytes32[3] memory ids;
        for (uint256 i = 0; i < 3; ++i) {
            (bytes32 x, bytes32 y) = _pub(pks[i]);
            vm.prank(account);
            validator.enrollKey(x, y, false);
            ids[i] = validator.keyId(x, y);
        }
        assertEq(validator.keyCount(account), 4);
        vm.prank(account);
        validator.revokeKey(ids[0]); // swap-and-pop from the middle
        bytes32[] memory left = validator.keyIdsOf(account);
        assertEq(left.length, 3);
        for (uint256 i = 0; i < left.length; ++i) {
            assertTrue(left[i] != ids[0]);
            assertTrue(validator.keyOf(account, left[i]).enrolled);
        }
    }

    /// Accounts are isolated: one owner's device never validates for another account.
    function test_t22_keys_are_scoped_to_the_enrolling_account() public {
        address other = address(0xB0B);
        (bytes32 x, bytes32 y) = _pub(phonePk);
        vm.prank(other);
        validator.onInstall(abi.encodePacked(x, y, uint8(0)));

        bytes32 digest = keccak256("AccessGrant digest");
        // other's key does not validate for `account`
        assertEq(validator.validateUserOp(_userOp(_sig(phonePk, digest)), digest), 1);
        // ...and `account`'s key does not validate for `other`
        PackedUserOperation memory op = _userOp(_sig(laptopPk, digest));
        op.sender = other;
        assertEq(validator.validateUserOp(op, digest), 1);
    }

    // ------------------------------------------------------------------ signature validation

    function test_t14_wrong_digest_or_unknown_key_rejected() public view {
        bytes32 digest = keccak256("AccessGrant digest");
        assertEq(validator.validateUserOp(_userOp(_sig(laptopPk, digest)), keccak256("other")), 1);
        // correct signature, but the key id points at a device that was never enrolled
        (bytes32 r, bytes32 s) = _sign(phonePk, digest);
        (bytes32 px, bytes32 py) = _pub(phonePk);
        bytes memory sig = abi.encodePacked(validator.keyId(px, py), r, s);
        assertEq(validator.validateUserOp(_userOp(sig), digest), 1);
    }

    function test_t14_tampered_signature_rejected() public view {
        bytes32 digest = keccak256("AccessGrant digest");
        bytes memory sig = _sig(laptopPk, digest);
        sig[95] = bytes1(uint8(sig[95]) ^ 0x01);
        assertEq(validator.validateUserOp(_userOp(sig), digest), 1);
    }

    /// T03/T14: `(r, n-s)` verifies mathematically but must be refused (signature malleability).
    function test_t03_t14_high_s_signature_rejected() public view {
        bytes32 digest = keccak256("AccessGrant digest");
        (bytes32 x, bytes32 y) = _pub(laptopPk);
        (bytes32 r, bytes32 s) = _sign(laptopPk, digest);
        bytes memory low = abi.encodePacked(validator.keyId(x, y), r, s);
        bytes memory high = abi.encodePacked(validator.keyId(x, y), r, bytes32(N - uint256(s)));
        assertEq(validator.validateUserOp(_userOp(low), digest), 0);
        assertEq(validator.validateUserOp(_userOp(high), digest), 1, "high-s must be rejected");
    }

    function test_malformed_signature_lengths_rejected() public view {
        bytes32 digest = keccak256("AccessGrant digest");
        bytes memory sig = _sig(laptopPk, digest);
        assertEq(validator.validateUserOp(_userOp(""), digest), 1);
        assertEq(validator.validateUserOp(_userOp(abi.encodePacked(sig, uint8(0))), digest), 1);
        assertEq(validator.validateUserOp(_userOp(abi.encodePacked(bytes32(0), bytes32(0))), digest), 1);
    }

    function test_erc1271_paths() public {
        bytes32 digest = keccak256("AccessGrant digest");
        bytes memory sig = _sig(laptopPk, digest);
        vm.prank(account);
        assertEq(
            validator.isValidSignatureWithSender(address(0), digest, sig), bytes4(0x1626ba7e), "owner account"
        );
        vm.prank(address(0xB0B));
        assertEq(
            validator.isValidSignatureWithSender(address(0), digest, sig), bytes4(0xffffffff), "other account"
        );
        // dry-run helper used by the Agent before spending a user operation
        assertTrue(validator.isValidSignatureForAccount(account, digest, sig));
        assertFalse(validator.isValidSignatureForAccount(address(0xB0B), digest, sig));
    }

    function test_module_type_and_uninstall_clears_keys() public {
        assertTrue(validator.isModuleType(1));
        assertFalse(validator.isModuleType(2));

        (bytes32 px, bytes32 py) = _pub(phonePk);
        vm.startPrank(account);
        validator.enrollKey(px, py, false);
        validator.onUninstall("");
        vm.stopPrank();

        assertFalse(validator.isInitialized(account));
        assertEq(validator.keyCount(account), 0);
        bytes32 digest = keccak256("AccessGrant digest");
        assertEq(validator.validateUserOp(_userOp(_sig(laptopPk, digest)), digest), 1);
        assertEq(validator.validateUserOp(_userOp(_sig(phonePk, digest)), digest), 1);
    }

    function testFuzz_only_the_registered_key_validates(uint256 pk, bytes32 digest) public view {
        pk = bound(pk, 1, N - 1);
        vm.assume(pk != laptopPk);
        (bytes32 x, bytes32 y) = _pub(pk);
        (bytes32 r, bytes32 s) = _sign(pk, digest);
        bytes memory sig = abi.encodePacked(validator.keyId(x, y), r, s);
        assertEq(validator.validateUserOp(_userOp(sig), digest), 1);
        assertEq(validator.validateUserOp(_userOp(_sig(laptopPk, digest)), digest), 0);
    }
}
