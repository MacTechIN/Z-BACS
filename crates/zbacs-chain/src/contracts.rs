//! Contract bindings, generated from the Foundry artifacts so the ABI can never drift from
//! what is actually deployed: if a contract changes and the artifact is rebuilt, this crate
//! stops compiling until the Rust side is updated too.
//!
//! The artifacts are checked-in copies in `abi/` (Foundry's `contracts/out/` is a build
//! product and not in git), so this crate builds on a machine without Foundry — the Windows
//! CI runner, a fresh clone. `tools/chain-it.sh` refreshes the copies after `forge build`,
//! and the `contracts` CI job fails if a copy's ABI no longer matches the source.

use alloy::sol;

sol!(
    #[sol(rpc)]
    #[allow(missing_docs)]
    FileRegistry,
    "abi/FileRegistry.json"
);

sol!(
    #[sol(rpc)]
    #[allow(missing_docs)]
    AccessPolicy,
    "abi/AccessPolicy.json"
);

sol!(
    #[sol(rpc)]
    #[allow(missing_docs)]
    AuditLog,
    "abi/AuditLog.json"
);

sol!(
    #[sol(rpc)]
    #[allow(missing_docs)]
    P256Validator,
    "abi/P256Validator.json"
);

// The proxy the stateful contracts live behind (Z-1.H.4). Tests deploy through it so the
// client is exercised against the same shape production runs: a proxy address, an EIP-712
// domain built for that address, and an implementation that is never called directly.
sol!(
    #[sol(rpc)]
    #[allow(missing_docs)]
    ERC1967Proxy,
    "abi/ERC1967Proxy.json"
);
