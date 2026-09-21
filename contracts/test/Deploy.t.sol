// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {Deploy} from "../script/Deploy.s.sol";
import {AccessGrantLib} from "../src/AccessGrantLib.sol";
import {AccessPolicy} from "../src/AccessPolicy.sol";
import {FileRegistry} from "../src/FileRegistry.sol";
import {Upgradeable} from "../src/Upgradeable.sol";

/// A next version of the registry, to prove an upgrade actually lands and keeps its data.
contract FileRegistryV2 is FileRegistry {
    function version() external pure returns (uint256) {
        return 2;
    }
}

/// Z-1.H.4 — the deployment itself: who can change what, and how long it takes.
///
/// These run the same `deployAll` the script runs, so what is tested is what is shipped.
contract DeployTest is Test {
    Deploy deployer;
    Deploy.Addresses a;

    address proposer = address(0xA11CE);
    address stranger = address(0xBAD);
    uint256 constant DELAY = 2 days;

    uint256 constant OWNER_PK = 0xA11CE;
    bytes32 constant FILE_ID = keccak256("fid");
    bytes32 constant HEADER = keccak256("hdr");

    function setUp() public {
        deployer = new Deploy();
        a = deployer.deployAll(proposer, DELAY);
        vm.warp(1_000_000);
    }

    // ------------------------------------------------------------ what was deployed

    function test_the_proxies_are_live_and_the_timelock_is_the_only_admin() public view {
        assertTrue(
            IAccessControl(a.registry).hasRole(bytes32(0), a.timelock), "timelock administers the registry"
        );
        assertTrue(IAccessControl(a.policy).hasRole(bytes32(0), a.timelock), "and the policy");
        assertFalse(IAccessControl(a.registry).hasRole(bytes32(0), proposer), "the proposer is not an admin");
        assertFalse(IAccessControl(a.registry).hasRole(bytes32(0), address(this)), "nor is the deployer");

        assertEq(address(AccessPolicy(a.policy).registry()), a.registry, "policy points at the proxy");
        assertEq(TimelockController(payable(a.timelock)).getMinDelay(), DELAY);
    }

    /// The timelock must not have a key that skips its own delay.
    function test_the_timelock_has_no_admin_back_door() public view {
        TimelockController t = TimelockController(payable(a.timelock));
        assertTrue(t.hasRole(t.DEFAULT_ADMIN_ROLE(), a.timelock), "self-administered");
        assertFalse(t.hasRole(t.DEFAULT_ADMIN_ROLE(), address(this)));
        assertFalse(t.hasRole(t.DEFAULT_ADMIN_ROLE(), proposer));
        assertTrue(t.hasRole(t.PROPOSER_ROLE(), proposer));
        assertTrue(t.hasRole(t.EXECUTOR_ROLE(), address(0)), "anyone may execute after the delay");
    }

    /// An implementation left initializable is an implementation someone else can take over.
    function test_the_implementations_cannot_be_initialized() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        FileRegistry(a.registryImpl).initialize(stranger);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        AccessPolicy(a.policyImpl).initialize(stranger);

        // and the proxy is initialized exactly once
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        FileRegistry(a.registry).initialize(stranger);
    }

    /// A proxy initialized with no admin is unupgradeable from birth, by accident. Refuse it
    /// at deployment, where it is still cheap to fix.
    function test_a_deployment_with_no_admin_is_refused() public {
        FileRegistry impl = new FileRegistry();
        vm.expectRevert(Upgradeable.ZeroAdmin.selector);
        new ERC1967Proxy(address(impl), abi.encodeCall(FileRegistry.initialize, (address(0))));
    }

    /// AuditLog and P256Validator are deliberately plain contracts (src/Upgradeable.sol).
    function test_the_two_contracts_that_must_not_change_are_not_proxies() public view {
        assertEq(vm.load(a.audit, ERC1967Utils.IMPLEMENTATION_SLOT), bytes32(0), "AuditLog is not a proxy");
        assertEq(vm.load(a.validator, ERC1967Utils.IMPLEMENTATION_SLOT), bytes32(0), "nor is P256Validator");
    }

    // ------------------------------------------------------------ who may upgrade

    function test_nobody_can_upgrade_directly_not_even_the_proposer() public {
        address v2 = address(new FileRegistryV2());

        vm.prank(stranger);
        vm.expectRevert();
        UUPSUpgradeable(a.registry).upgradeToAndCall(v2, "");

        vm.prank(proposer);
        vm.expectRevert();
        UUPSUpgradeable(a.registry).upgradeToAndCall(v2, "");
    }

    function test_an_upgrade_waits_for_the_delay_and_then_keeps_the_data() public {
        // a file registered before the upgrade
        address owner = vm.addr(OWNER_PK);
        vm.prank(owner);
        FileRegistry(a.registry).register(FILE_ID, HEADER);

        address v2 = address(new FileRegistryV2());
        bytes memory call = abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (v2, ""));
        TimelockController t = TimelockController(payable(a.timelock));

        vm.prank(proposer);
        t.schedule(a.registry, 0, call, bytes32(0), bytes32(0), DELAY);

        // too early
        vm.expectRevert();
        t.execute(a.registry, 0, call, bytes32(0), bytes32(0));

        skip(DELAY);
        t.execute(a.registry, 0, call, bytes32(0), bytes32(0)); // anyone

        assertEq(FileRegistryV2(a.registry).version(), 2, "the new code is live");
        (bytes32 header, uint32 ver, bool retired) = FileRegistry(a.registry).currentVersion(FILE_ID);
        assertEq(header, HEADER, "the file record survived the upgrade");
        assertEq(ver, 1);
        assertFalse(retired);
        assertEq(FileRegistry(a.registry).ownerOf(FILE_ID), owner);
    }

    /// Only the proposer may queue one; a stranger cannot even start the clock.
    function test_a_stranger_cannot_queue_an_upgrade() public {
        bytes memory call =
            abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (address(new FileRegistryV2()), ""));
        vm.prank(stranger);
        vm.expectRevert();
        TimelockController(payable(a.timelock)).schedule(a.registry, 0, call, bytes32(0), bytes32(0), DELAY);
    }

    /// An upgrade that repoints the registry would decide who owns which file. Refused.
    function test_a_policy_upgrade_cannot_repoint_the_registry() public {
        FileRegistry other = new FileRegistry();
        address badImpl = address(new AccessPolicy(other));
        bytes memory call = abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (badImpl, ""));
        TimelockController t = TimelockController(payable(a.timelock));

        vm.prank(proposer);
        t.schedule(a.policy, 0, call, bytes32(0), bytes32(0), DELAY);
        skip(DELAY);
        vm.expectRevert(); // the timelock reports the inner revert
        t.execute(a.policy, 0, call, bytes32(0), bytes32(0));

        // ...and a replacement built against the same registry goes through
        address goodImpl = address(new AccessPolicy(FileRegistry(a.registry)));
        bytes memory ok = abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (goodImpl, ""));
        vm.prank(proposer);
        t.schedule(a.policy, 0, ok, bytes32(0), keccak256("second"), DELAY);
        skip(DELAY);
        t.execute(a.policy, 0, ok, bytes32(0), keccak256("second"));
        assertEq(address(AccessPolicy(a.policy).registry()), a.registry);
    }

    /// One transaction must not be able to make the system unfixable forever.
    function test_the_upgrade_role_cannot_be_renounced() public {
        vm.prank(a.timelock);
        vm.expectRevert(Upgradeable.AdminCannotBeRenounced.selector);
        IAccessControl(a.registry).renounceRole(bytes32(0), a.timelock);

        // a different role still behaves normally
        bytes32 role = keccak256("SOME_ROLE");
        vm.prank(a.timelock);
        IAccessControl(a.registry).grantRole(role, stranger);
        vm.prank(stranger);
        IAccessControl(a.registry).renounceRole(role, stranger);
        assertFalse(IAccessControl(a.registry).hasRole(role, stranger));
    }

    // ------------------------------------------------------------ EIP-712 behind a proxy

    /// The domain separator has to be built for the proxy, not the implementation, or every
    /// signature an owner makes would be rejected by the contract they are actually talking to.
    function test_a_signed_grant_verifies_against_the_proxy_address() public {
        address owner = vm.addr(OWNER_PK);
        vm.prank(owner);
        FileRegistry(a.registry).register(FILE_ID, HEADER);

        AccessPolicy policy = AccessPolicy(a.policy);
        AccessGrantLib.AccessGrant memory g = AccessGrantLib.AccessGrant({
            fileId: FILE_ID,
            headerHash: HEADER,
            deviceKeyHash: keccak256("bob device"),
            permission: 1,
            notBefore: uint64(block.timestamp),
            expiry: uint64(block.timestamp + 3600),
            maxOpens: 1,
            requestNonce: bytes16(keccak256("req")),
            grantNonce: 0
        });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, policy.digestOf(g));
        bytes32 id = policy.grant(g, abi.encodePacked(r, s, v));
        assertTrue(policy.isValid(id));

        // the same grant signed for the implementation's domain is a different digest
        assertTrue(
            policy.digestOf(g) != AccessPolicy(a.policyImpl).digestOf(g),
            "proxy and implementation must not share a domain"
        );
    }
}
