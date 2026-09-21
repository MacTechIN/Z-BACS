//! Contract bindings, generated from the Foundry artifacts so the ABI can never drift from
//! what is actually deployed: if a contract changes and the artifact is rebuilt, this crate
//! stops compiling until the Rust side is updated too.

use alloy::sol;

sol!(
    #[sol(rpc)]
    #[allow(missing_docs)]
    FileRegistry,
    "../../contracts/out/FileRegistry.sol/FileRegistry.json"
);

sol!(
    #[sol(rpc)]
    #[allow(missing_docs)]
    AccessPolicy,
    "../../contracts/out/AccessPolicy.sol/AccessPolicy.json"
);

sol!(
    #[sol(rpc)]
    #[allow(missing_docs)]
    AuditLog,
    "../../contracts/out/AuditLog.sol/AuditLog.json"
);

sol!(
    #[sol(rpc)]
    #[allow(missing_docs)]
    P256Validator,
    "../../contracts/out/P256Validator.sol/P256Validator.json"
);
