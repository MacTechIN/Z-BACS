// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Test, Vm, console2} from "forge-std/Test.sol";
import {AuditLog} from "../src/AuditLog.sol";

/// Z-1.H.3 — audit events. DoD: ≤ 30k gas per log entry.
contract AuditLogTest is Test {
    AuditLog audit;

    address owner = address(0xA11CE);
    address bobAgent = address(0xB0B);
    bytes32 constant FILE_ID = keccak256("file");
    bytes32 constant HEADER = keccak256("header v1");
    bytes32 constant ACTOR = keccak256("deviceKid||salt");

    function setUp() public {
        audit = new AuditLog();
    }

    function test_log_emits_one_event_per_step() public {
        vm.startPrank(bobAgent);
        for (uint256 k = 0; k <= uint256(type(AuditLog.Kind).max); ++k) {
            vm.expectEmit(true, true, true, true);
            emit AuditLog.Logged(FILE_ID, AuditLog.Kind(k), bobAgent, ACTOR, HEADER);
            audit.log(FILE_ID, AuditLog.Kind(k), ACTOR, HEADER);
        }
        vm.stopPrank();
    }

    /// The five kinds the architecture lists are all reachable and distinct.
    function test_kind_enum_matches_the_spec() public pure {
        assertEq(uint256(AuditLog.Kind.Requested), 0);
        assertEq(uint256(AuditLog.Kind.Denied), 1);
        assertEq(uint256(AuditLog.Kind.Opened), 2);
        assertEq(uint256(AuditLog.Kind.Sealed), 3);
        assertEq(uint256(AuditLog.Kind.Failed), 4);
    }

    /// The 30k budget (Z-1.H.3) is a property of a *real transaction*, and `gasleft()` inside a
    /// forge test frame is inflated by the harness, so the number is measured against a live
    /// Anvil node by `tools/chain-demo.sh` (it prints the receipt and fails over budget).
    /// What this test pins down instead is the structure that keeps the cost flat: exactly one
    /// event, no storage, no cross-contract call — the registry lookup an earlier draft had
    /// cost ~4.7k and pushed a real transaction to 31,030.
    function test_log_writes_no_state_and_emits_exactly_one_event() public {
        vm.record();
        vm.recordLogs();
        vm.prank(bobAgent);
        audit.log(FILE_ID, AuditLog.Kind.Opened, ACTOR, HEADER);

        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(audit));
        assertEq(writes.length, 0, "AuditLog must stay event-only");
        assertEq(reads.length, 0, "no storage reads either");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1, "exactly one event per entry");
        assertEq(logs[0].topics.length, 4, "signature + 3 indexed topics");
        assertEq(logs[0].data.length, 64, "actorCommit + detail");
    }

    /// Entries are claims by whoever submitted them; the reporter is part of the event so a
    /// reader can weigh them (T07 traceability, not proof).
    function test_reporter_is_recorded_and_anyone_may_report() public {
        vm.recordLogs();
        vm.prank(bobAgent);
        audit.log(FILE_ID, AuditLog.Kind.Opened, ACTOR, HEADER);
        vm.prank(owner);
        audit.log(FILE_ID, AuditLog.Kind.Sealed, ACTOR, keccak256("header v2"));

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 2);
        assertEq(address(uint160(uint256(logs[0].topics[3]))), bobAgent);
        assertEq(address(uint160(uint256(logs[1].topics[3]))), owner);
        assertEq(logs[0].topics[1], FILE_ID);
        assertEq(uint256(logs[1].topics[2]), uint256(AuditLog.Kind.Sealed));
    }

    function testFuzz_log_never_reverts(uint8 kind, bytes32 actor, bytes32 detail) public {
        AuditLog.Kind k = AuditLog.Kind(bound(kind, 0, uint256(type(AuditLog.Kind).max)));
        vm.prank(bobAgent);
        audit.log(FILE_ID, k, actor, detail);
    }
}
