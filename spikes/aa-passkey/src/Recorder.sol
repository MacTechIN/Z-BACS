// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Call target for the passkey UserOperation. The fork test etches its runtime code at
/// the fixed address 0x...BEEF that scripts/kernel-account.mjs signed against.
contract Recorder {
    bytes32 public last;
    address public lastCaller;
    uint256 public calls;

    event Recorded(address indexed caller, bytes32 value);

    function record(bytes32 value) external {
        last = value;
        lastCaller = msg.sender;
        calls += 1;
        emit Recorded(msg.sender, value);
    }
}
