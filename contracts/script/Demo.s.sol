// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {FileRegistry} from "../src/FileRegistry.sol";
import {AccessPolicy} from "../src/AccessPolicy.sol";
import {AccessGrantLib} from "../src/AccessGrantLib.sol";

/// @notice End-to-end walkthrough of what Z-BACS puts on chain, runnable against a local
///         Anvil node (see tools/chain-demo.sh and docs/chain_guide.md):
///         deploy -> register file -> owner signs EIP-712 grant -> submit -> recipient opens
///         -> replay is rejected -> owner revokes -> grant no longer valid.
///
///   anvil &
///   forge script script/Demo.s.sol --rpc-url http://127.0.0.1:8545 --broadcast -vv
///
/// Keys are Anvil's well-known dev accounts (never used outside a local node).
contract Demo is Script {
    // Anvil account #0 = Alice (file owner), #1 = Bob (recipient device)
    uint256 constant ALICE_PK = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 constant BOB_PK = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;

    function run() external {
        address alice = vm.addr(ALICE_PK);
        address bob = vm.addr(BOB_PK);
        console2.log("Alice (owner)    :", alice);
        console2.log("Bob   (recipient):", bob);

        // ---------------------------------------------------------------- [1] deploy
        console2.log("\n[1] Deploy FileRegistry + AccessPolicy (2 transactions)");
        vm.startBroadcast(ALICE_PK);
        FileRegistry registry = new FileRegistry();
        AccessPolicy policy = new AccessPolicy(registry);
        vm.stopBroadcast();
        console2.log("    FileRegistry :", address(registry));
        console2.log("    AccessPolicy :", address(policy));

        // ---------------------------------------------------------------- [2] seal + register
        // fileId is a salted hash: the chain never sees the file name or content (T13).
        bytes32 fileId = keccak256(abi.encodePacked("contract.docx", bytes32(uint256(0xC0FFEE))));
        bytes32 headerHash = keccak256("sealed header v1: policy=ReadOnly, ttl=1h");
        console2.log("\n[2] Alice seals a file and anchors its header hash on chain");
        vm.startBroadcast(ALICE_PK);
        registry.register(fileId, headerHash);
        vm.stopBroadcast();
        console2.log("    fileId      :", vm.toString(fileId));
        console2.log("    owner on chain == Alice:", registry.ownerOf(fileId) == alice);

        // ---------------------------------------------------------------- [3] Bob asks, Alice approves
        // Bob's device keys would arrive via the Relay; only their hash goes on chain.
        bytes memory devicePubKeys = abi.encodePacked("bob-x25519-pub", "bob-ed25519-pub");
        AccessGrantLib.AccessGrant memory g = AccessGrantLib.AccessGrant({
            fileId: fileId,
            headerHash: headerHash,
            deviceKeyHash: keccak256(devicePubKeys),
            permission: 1, // ReadOnly
            notBefore: uint64(block.timestamp),
            expiry: uint64(block.timestamp + 1 hours),
            maxOpens: 2,
            requestNonce: bytes16(keccak256("bob-request-1")),
            grantNonce: 0
        });
        bytes memory aliceSig;
        {
            bytes32 digest = policy.digestOf(g);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, digest);
            aliceSig = abi.encodePacked(r, s, v);
            console2.log("\n[3] Alice approves: ReadOnly, 1 hour, max 2 opens -> EIP-712 signature");
            console2.log("    digest signed:", vm.toString(digest));
        }

        vm.startBroadcast(ALICE_PK);
        bytes32 grantId = policy.grant(g, aliceSig);
        vm.stopBroadcast();
        console2.log("    grantId      :", vm.toString(grantId));
        console2.log("    isValid      :", policy.isValid(grantId));

        // ---------------------------------------------------------------- [4] Bob opens
        console2.log("\n[4] Bob's agent checks isValid() (free read) and records one open");
        vm.startBroadcast(BOB_PK);
        policy.consumeOpen(grantId, devicePubKeys);
        vm.stopBroadcast();
        console2.log("    opens used   :", policy.grantOf(grantId).opens);

        // ---------------------------------------------------------------- [5] replay attempt (simulated, not sent)
        console2.log("\n[5] Replay: resubmitting the same signed grant");
        try policy.grant(g, aliceSig) returns (bytes32) {
            console2.log("    !! accepted (BUG)");
        } catch {
            console2.log("    rejected: nonce already consumed (T03)");
        }

        // ---------------------------------------------------------------- [6] revoke
        console2.log("\n[6] Alice revokes");
        vm.startBroadcast(ALICE_PK);
        policy.revoke(grantId);
        vm.stopBroadcast();
        console2.log("    isValid      :", policy.isValid(grantId));

        // ---------------------------------------------------------------- addresses for cast
        string memory json = "demo";
        vm.serializeAddress(json, "registry", address(registry));
        vm.serializeAddress(json, "policy", address(policy));
        vm.serializeBytes32(json, "fileId", fileId);
        string memory out = vm.serializeBytes32(json, "grantId", grantId);
        vm.writeJson(out, "out/demo.json");
        console2.log("\nwrote out/demo.json");
    }
}
