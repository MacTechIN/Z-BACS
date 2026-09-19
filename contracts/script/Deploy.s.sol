// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {FileRegistry} from "../src/FileRegistry.sol";
import {AccessPolicy} from "../src/AccessPolicy.sol";

/// @notice PoC deploy. Usage (Anvil):
///   anvil &
///   forge script script/Deploy.s.sol --rpc-url anvil --broadcast --private-key $ANVIL_PK
contract Deploy is Script {
    function run() external {
        vm.startBroadcast();
        FileRegistry reg = new FileRegistry();
        AccessPolicy pol = new AccessPolicy(reg);
        vm.stopBroadcast();
        console2.log("FileRegistry", address(reg));
        console2.log("AccessPolicy", address(pol));
    }
}
