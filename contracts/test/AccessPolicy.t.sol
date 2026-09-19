// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, console2} from "forge-std/Test.sol";
import {AccessGrantLib} from "../src/AccessGrantLib.sol";
import {AccessPolicy} from "../src/AccessPolicy.sol";
import {FileRegistry} from "../src/FileRegistry.sol";
import {ERC1271Mock} from "./mocks/ERC1271Mock.sol";

contract AccessPolicyTest is Test {
    FileRegistry registry;
    AccessPolicy policy;

    uint256 constant OWNER_PK = 0xA11CE;
    address owner;
    address relayer = address(0xBEEF);

    bytes32 constant FILE_ID = keccak256("fid");
    bytes32 constant HEADER = keccak256("hdr");
    bytes32 constant DEVICE = keccak256("bob-device");

    function setUp() public {
        owner = vm.addr(OWNER_PK);
        registry = new FileRegistry();
        policy = new AccessPolicy(registry);
        vm.prank(owner);
        registry.register(FILE_ID, HEADER);
        vm.warp(1_000_000);
    }

    function _grant(uint8 perm, uint256 nonce) internal view returns (AccessGrantLib.AccessGrant memory g) {
        g = AccessGrantLib.AccessGrant({
            fileId: FILE_ID,
            headerHash: HEADER,
            deviceKeyHash: DEVICE,
            permission: perm,
            notBefore: uint64(block.timestamp),
            expiry: uint64(block.timestamp + 3600),
            maxOpens: 1,
            requestNonce: bytes16(keccak256(abi.encode("req", nonce))),
            grantNonce: nonce
        });
    }

    function _sign(uint256 pk, AccessGrantLib.AccessGrant memory g) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, policy.digestOf(g));
        return abi.encodePacked(r, s, v);
    }

    // ------------------------------------------------------------ happy path

    function test_grant_readonly_and_isValid() public {
        AccessGrantLib.AccessGrant memory g = _grant(1, 0);
        bytes memory sig = _sign(OWNER_PK, g);

        vm.expectEmit(true, true, true, true);
        emit AccessPolicy.Granted(policy.hashGrant(g), FILE_ID, DEVICE, 1, g.expiry);
        vm.prank(relayer); // anyone can submit
        bytes32 id = policy.grant(g, sig);

        assertEq(id, policy.hashGrant(g));
        assertTrue(policy.isValid(id));
        assertEq(policy.nonces(owner), 1);
        AccessPolicy.GrantRecord memory r = policy.grantOf(id);
        assertEq(r.owner, owner);
        assertEq(r.permission, 1);
    }

    function test_consumeOpen_respects_maxOpens() public {
        AccessGrantLib.AccessGrant memory g = _grant(2, 0);
        bytes32 id = policy.grant(g, _sign(OWNER_PK, g));
        policy.consumeOpen(id);
        assertFalse(policy.isValid(id), "maxOpens=1 exhausted");
        vm.expectRevert(abi.encodeWithSelector(AccessPolicy.GrantNotActive.selector, id));
        policy.consumeOpen(id);
    }

    // ------------------------------------------------------------ T03 replay

    function test_t03_replay_same_grant_rejected() public {
        AccessGrantLib.AccessGrant memory g = _grant(1, 0);
        bytes memory sig = _sign(OWNER_PK, g);
        policy.grant(g, sig);
        vm.expectRevert(abi.encodeWithSelector(AccessPolicy.BadNonce.selector, 1, 0));
        policy.grant(g, sig);
    }

    function test_t03_request_nonce_cannot_be_reused_with_new_grant_nonce() public {
        AccessGrantLib.AccessGrant memory g0 = _grant(1, 0);
        policy.grant(g0, _sign(OWNER_PK, g0));
        AccessGrantLib.AccessGrant memory g1 = _grant(1, 1);
        g1.requestNonce = g0.requestNonce;
        bytes memory sig1 = _sign(OWNER_PK, g1);
        vm.expectRevert(abi.encodeWithSelector(AccessPolicy.RequestNonceUsed.selector, g0.requestNonce));
        policy.grant(g1, sig1);
    }

    function test_t03_signature_bound_to_chain_and_contract() public {
        AccessGrantLib.AccessGrant memory g = _grant(1, 0);
        bytes memory sig = _sign(OWNER_PK, g);
        // a second AccessPolicy (different verifyingContract) must not accept the same signature
        AccessPolicy other = new AccessPolicy(registry);
        vm.expectRevert(AccessPolicy.InvalidSignature.selector);
        other.grant(g, sig);
        // different chainId
        vm.chainId(8453);
        vm.expectRevert(AccessPolicy.InvalidSignature.selector);
        policy.grant(g, sig);
    }

    // ------------------------------------------------------------ T14 signatures

    function test_t14_wrong_signer_rejected() public {
        AccessGrantLib.AccessGrant memory g = _grant(1, 0);
        bytes memory badSig = _sign(0xBAD, g);
        vm.expectRevert(AccessPolicy.InvalidSignature.selector);
        policy.grant(g, badSig);
    }

    function test_t14_tampered_field_rejected() public {
        AccessGrantLib.AccessGrant memory g = _grant(1, 0);
        bytes memory sig = _sign(OWNER_PK, g);
        g.permission = 2; // escalate ReadOnly -> Edit after signing (T02/T06)
        vm.expectRevert(AccessPolicy.InvalidSignature.selector);
        policy.grant(g, sig);
    }

    function test_t14_erc1271_smart_account_owner() public {
        uint256 pk = 0x5A17;
        ERC1271Mock account = new ERC1271Mock(vm.addr(pk));
        bytes32 fid = keccak256("fid-1271");
        account.registerFile(registry, fid, HEADER);

        AccessGrantLib.AccessGrant memory g = _grant(2, 0);
        g.fileId = fid;
        bytes32 id = policy.grant(g, _sign(pk, g));
        assertTrue(policy.isValid(id));

        // revoke must come from the account, not the underlying EOA
        vm.prank(vm.addr(pk));
        vm.expectRevert(abi.encodeWithSelector(AccessPolicy.NotOwner.selector, id, vm.addr(pk)));
        policy.revoke(id);
        account.revokeGrant(policy, id);
        assertFalse(policy.isValid(id));
    }

    // ------------------------------------------------------------ T15 time, T20 revoke

    function test_t15_expiry_and_notBefore() public {
        AccessGrantLib.AccessGrant memory g = _grant(1, 0);
        g.notBefore = uint64(block.timestamp + 100);
        bytes32 id = policy.grant(g, _sign(OWNER_PK, g));
        assertFalse(policy.isValid(id), "not yet valid");
        vm.warp(block.timestamp + 100);
        assertTrue(policy.isValid(id));
        vm.warp(g.expiry);
        assertFalse(policy.isValid(id), "expired at expiry");
    }

    function test_t15_already_expired_grant_rejected() public {
        AccessGrantLib.AccessGrant memory g = _grant(1, 0);
        g.expiry = uint64(block.timestamp);
        bytes memory sig = _sign(OWNER_PK, g);
        vm.expectRevert(abi.encodeWithSelector(AccessPolicy.InvalidWindow.selector, g.notBefore, g.expiry));
        policy.grant(g, sig);
    }

    function test_t20_revoke_only_owner() public {
        AccessGrantLib.AccessGrant memory g = _grant(2, 0);
        bytes32 id = policy.grant(g, _sign(OWNER_PK, g));
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(AccessPolicy.NotOwner.selector, id, relayer));
        policy.revoke(id);
        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit AccessPolicy.Revoked(id, FILE_ID);
        policy.revoke(id);
        assertFalse(policy.isValid(id));
    }

    function test_unregistered_file_rejected() public {
        AccessGrantLib.AccessGrant memory g = _grant(1, 0);
        g.fileId = keccak256("nope");
        bytes memory sig = _sign(OWNER_PK, g);
        vm.expectRevert(abi.encodeWithSelector(AccessPolicy.FileNotRegistered.selector, g.fileId));
        policy.grant(g, sig);
    }

    function test_invalid_permission_rejected() public {
        AccessGrantLib.AccessGrant memory g = _grant(3, 0);
        bytes memory sig = _sign(OWNER_PK, g);
        vm.expectRevert(abi.encodeWithSelector(AccessPolicy.InvalidPermission.selector, 3));
        policy.grant(g, sig);
    }

    // ------------------------------------------------------------ fuzz

    function testFuzz_grant_roundtrip(uint8 perm, uint64 ttl, uint16 maxOpens, bytes16 reqNonce) public {
        perm = uint8(bound(perm, 0, 2));
        ttl = uint64(bound(ttl, 1, 365 days));
        AccessGrantLib.AccessGrant memory g = _grant(perm, 0);
        g.expiry = uint64(block.timestamp) + ttl;
        g.maxOpens = maxOpens;
        g.requestNonce = reqNonce;
        bytes32 id = policy.grant(g, _sign(OWNER_PK, g));
        assertTrue(policy.isValid(id));
        assertEq(policy.grantOf(id).permission, perm);
    }

    // ------------------------------------------------------------ cross-impl vector (for zbacs-chain / Rust)

    function test_vector_struct_hash() public view {
        AccessGrantLib.AccessGrant memory g = AccessGrantLib.AccessGrant({
            fileId: bytes32(uint256(1)),
            headerHash: bytes32(uint256(2)),
            deviceKeyHash: bytes32(uint256(3)),
            permission: 1,
            notBefore: 1_700_000_000,
            expiry: 1_700_003_600,
            maxOpens: 1,
            requestNonce: bytes16(uint128(4)),
            grantNonce: 0
        });
        console2.log("TYPEHASH");
        console2.logBytes32(AccessGrantLib.ACCESS_GRANT_TYPEHASH);
        console2.log("STRUCT_HASH(vector-1)");
        console2.logBytes32(policy.hashGrant(g));
        (, string memory name, string memory version,,,,) = policy.eip712Domain();
        assertEq(name, "Z-BACS");
        assertEq(version, "1");
    }
}
