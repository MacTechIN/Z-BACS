// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console2} from "forge-std/Test.sol";

/// OR-2: exact cost and behaviour of the P256VERIFY precompile on a Base Sepolia fork, plus
/// the Daimo p256-verifier fallback, using vectors from `node scripts/p256-vector.mjs --out`.
///
///   forge test --fork-url https://sepolia.base.org --match-path test/Rip7212.t.sol -vv
contract Rip7212Test is Test {
    address constant P256VERIFY = 0x0000000000000000000000000000000000000100;
    address constant DAIMO_VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;
    uint256 constant N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    string json;

    function setUp() public {
        json = vm.readFile("vectors/p256.json");
    }

    function _plainInput() internal view returns (bytes memory) {
        return abi.encodePacked(
            vm.parseJsonBytes32(json, ".plain.hash"),
            vm.parseJsonBytes32(json, ".plain.r"),
            vm.parseJsonBytes32(json, ".plain.s"),
            vm.parseJsonBytes32(json, ".plain.x"),
            vm.parseJsonBytes32(json, ".plain.y")
        );
    }

    function _verify(address verifier, bytes memory input) internal view returns (bool ok, uint256 gasUsed) {
        uint256 before = gasleft();
        (bool success, bytes memory ret) = verifier.staticcall(input);
        gasUsed = before - gasleft();
        ok = success && ret.length == 32 && abi.decode(ret, (uint256)) == 1;
    }

    function test_or2_precompile_active_on_fork() public view {
        (bool ok, uint256 gasUsed) = _verify(P256VERIFY, _plainInput());
        assertTrue(ok, "P256VERIFY did not accept a valid signature");
        console2.log("P256VERIFY valid signature gas (incl. STATICCALL overhead):", gasUsed);
    }

    function test_or2_precompile_rejects_corrupted_signature() public view {
        bytes memory input = _plainInput();
        input[40] ^= 0x01; // flip a bit in r
        (bool ok,) = _verify(P256VERIFY, input);
        assertFalse(ok, "corrupted r accepted");
    }

    function test_or2_precompile_rejects_high_s() public view {
        // RIP-7212 does not mandate low-s, but on-chain validators must reject malleable
        // encodings themselves. Record which behaviour this chain's precompile has.
        uint256 s = uint256(vm.parseJsonBytes32(json, ".plain.s"));
        bytes memory input = abi.encodePacked(
            vm.parseJsonBytes32(json, ".plain.hash"),
            vm.parseJsonBytes32(json, ".plain.r"),
            bytes32(N - s),
            vm.parseJsonBytes32(json, ".plain.x"),
            vm.parseJsonBytes32(json, ".plain.y")
        );
        (bool ok,) = _verify(P256VERIFY, input);
        console2.log("P256VERIFY accepts high-s:", ok);
    }

    function test_or2_daimo_fallback_gas() public view {
        (bool ok, uint256 gasUsed) = _verify(DAIMO_VERIFIER, _plainInput());
        assertTrue(ok, "daimo verifier rejected a valid signature");
        console2.log("daimo p256-verifier valid signature gas:", gasUsed);
    }

    /// The exact digest a WebAuthn validator must feed the precompile:
    /// sha256(authenticatorData || sha256(clientDataJSON)).
    function test_webauthn_assertion_verifies_via_precompile() public view {
        bytes memory authenticatorData = vm.parseJsonBytes(json, ".webauthn.authenticatorData");
        string memory clientDataJSON = vm.parseJsonString(json, ".webauthn.clientDataJSON");
        bytes32 digest = sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON))));
        assertEq(digest, vm.parseJsonBytes32(json, ".webauthn.digest"), "digest mismatch vs node");

        // UP (0x01) and UV (0x04) flags must be set: user presence + verification.
        assertEq(uint8(authenticatorData[32]) & 0x05, 0x05, "UP/UV flags");

        bytes memory input = abi.encodePacked(
            digest,
            vm.parseJsonBytes32(json, ".webauthn.r"),
            vm.parseJsonBytes32(json, ".webauthn.s"),
            vm.parseJsonBytes32(json, ".webauthn.x"),
            vm.parseJsonBytes32(json, ".webauthn.y")
        );
        (bool ok, uint256 gasUsed) = _verify(P256VERIFY, input);
        assertTrue(ok, "WebAuthn assertion rejected");
        console2.log("WebAuthn assertion (sha256 x2 + P256VERIFY) gas:", gasUsed);
    }
}
