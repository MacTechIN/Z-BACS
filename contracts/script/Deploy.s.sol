// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {AccessPolicy} from "../src/AccessPolicy.sol";
import {AuditLog} from "../src/AuditLog.sol";
import {FileRegistry} from "../src/FileRegistry.sol";
import {P256Validator} from "../src/P256Validator.sol";

/// @notice Z-1.H.4 — deploy the whole system and write down where it landed.
///
///   anvil &
///   forge script script/Deploy.s.sol --rpc-url anvil --broadcast --private-key $ANVIL_PK
///
///   # Base Sepolia
///   TIMELOCK_DELAY=172800 TIMELOCK_PROPOSER=0xYourAddress \
///     forge script script/Deploy.s.sol --rpc-url base_sepolia --broadcast --verify
///
/// The result is `deployments/<chainId>.json`, which is what every other part of the system
/// reads: the Agent (`zbacs-chain::Deployment::from_file`), the demo script, and a person
/// checking on a block explorer. Addresses that only live in a terminal scrollback are lost.
///
/// @dev What is upgradeable and what is not is decided in `src/Upgradeable.sol`, not here.
contract Deploy is Script {
    /// @notice Everything one deployment consists of.
    struct Addresses {
        address timelock;
        address registry;
        address registryImpl;
        address policy;
        address policyImpl;
        address audit;
        address validator;
        uint256 minDelay;
    }

    /// @dev Two days. Long enough that people can see an upgrade coming and stop using the
    ///      system; short enough to fix something that is actually broken.
    uint256 public constant DEFAULT_DELAY = 2 days;

    /// @notice Deploy everything. Separated from {run} so the tests exercise this exact code
    ///         rather than a copy of it that can drift.
    /// @param proposer Who may queue an upgrade (and cancel one). A person or a multisig.
    /// @param minDelay Seconds an upgrade must wait after being queued.
    function deployAll(address proposer, uint256 minDelay) public returns (Addresses memory a) {
        address[] memory proposers = new address[](1);
        proposers[0] = proposer;
        // Anyone may execute once the delay has passed: the wait is the protection, not secrecy
        // about who presses the button.
        address[] memory executors = new address[](1);
        executors[0] = address(0);
        // No admin: the timelock administers itself, so there is no key that skips the delay.
        TimelockController timelock = new TimelockController(minDelay, proposers, executors, address(0));

        FileRegistry registryImpl = new FileRegistry();
        address registry = address(
            new ERC1967Proxy(
                address(registryImpl), abi.encodeCall(FileRegistry.initialize, (address(timelock)))
            )
        );

        // The implementation is built against the registry *proxy*, so the address it holds is
        // the stable one. AccessPolicy._authorizeUpgrade refuses a replacement that disagrees.
        AccessPolicy policyImpl = new AccessPolicy(FileRegistry(registry));
        address policy = address(
            new ERC1967Proxy(
                address(policyImpl), abi.encodeCall(AccessPolicy.initialize, (address(timelock)))
            )
        );

        a = Addresses({
            timelock: address(timelock),
            registry: registry,
            registryImpl: address(registryImpl),
            policy: policy,
            policyImpl: address(policyImpl),
            audit: address(new AuditLog()),
            validator: address(new P256Validator()),
            minDelay: minDelay
        });
    }

    function run() external {
        // Before anything is broadcast. `vm.writeJson` does not create the directory, and a
        // fresh clone does not have it: deploying first and then failing to write the file
        // would leave live contracts whose addresses exist only in this terminal.
        vm.createDir(string.concat(vm.projectRoot(), "/deployments"), true);

        address proposer = vm.envOr("TIMELOCK_PROPOSER", msg.sender);
        // A local chain with a two-day delay is a local chain nobody can use.
        uint256 fallbackDelay = block.chainid == 31337 ? 0 : DEFAULT_DELAY;
        uint256 minDelay = vm.envOr("TIMELOCK_DELAY", fallbackDelay);

        vm.startBroadcast();
        Addresses memory a = deployAll(proposer, minDelay);
        vm.stopBroadcast();

        write(a, proposer);
        console2.log("chainId       ", block.chainid);
        console2.log("TimelockController", a.timelock);
        console2.log("  upgrade delay (s)", a.minDelay);
        console2.log("  may queue an upgrade", proposer);
        console2.log("FileRegistry  ", a.registry);
        console2.log("AccessPolicy  ", a.policy);
        console2.log("AuditLog      ", a.audit);
        console2.log("P256Validator ", a.validator);
    }

    /// @notice Write `deployments/<chainId>.json`.
    function write(Addresses memory a, address proposer) public {
        string memory obj = "zbacs";
        vm.serializeUint(obj, "chainId", block.chainid);
        vm.serializeAddress(obj, "timelock", a.timelock);
        vm.serializeUint(obj, "minDelay", a.minDelay);
        vm.serializeAddress(obj, "proposer", proposer);
        vm.serializeAddress(obj, "registry", a.registry);
        vm.serializeAddress(obj, "registryImplementation", a.registryImpl);
        vm.serializeAddress(obj, "policy", a.policy);
        vm.serializeAddress(obj, "policyImplementation", a.policyImpl);
        vm.serializeAddress(obj, "audit", a.audit);
        string memory json = vm.serializeAddress(obj, "p256Validator", a.validator);

        string memory path =
            string.concat(vm.projectRoot(), "/deployments/", vm.toString(block.chainid), ".json");
        vm.writeJson(json, path);
        console2.log("wrote", path);
    }
}
