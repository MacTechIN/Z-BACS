//! A throwaway chain with the whole system on it, for tests and demos (feature `dev-chain`).
//!
//! Spawns Anvil and deploys what `script/Deploy.s.sol` deploys — the registry and policy
//! behind ERC-1967 proxies, the audit log, the P-256 validator — from the checked-in
//! artifacts, so a machine with only the `anvil` binary can run the Agent end to end
//! (Z-1.H.8 b, ADR-0008). Nothing here is used by a release build.

use alloy::network::EthereumWallet;
use alloy::node_bindings::{Anvil, AnvilInstance};
use alloy::primitives::hex;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;

use crate::contracts::{AccessPolicy, AuditLog, ERC1967Proxy, FileRegistry, P256Validator};
use crate::error::{ChainError, Result};
use crate::Deployment;

/// A running Anvil with the Z-BACS contracts deployed.
pub struct DevChain {
    /// The node; dropping it stops Anvil.
    pub anvil: AnvilInstance,
    /// HTTP endpoint.
    pub rpc: String,
    /// EIP-155 chain id (Anvil's default is 31337).
    pub deployment: Deployment,
    /// Anvil's pre-funded keys, hex, in Anvil's order. Key 0 deployed the contracts.
    pub keys: Vec<String>,
}

/// Whether `anvil` is on the PATH, so a test can skip loudly instead of failing.
pub fn anvil_present() -> bool {
    std::process::Command::new("anvil")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

impl DevChain {
    /// Start Anvil and deploy everything with its first key.
    pub async fn spawn() -> Result<Self> {
        let anvil =
            Anvil::new().try_spawn().map_err(|e| ChainError::Config(format!("cannot start anvil: {e}")))?;
        let keys: Vec<String> = anvil.keys().iter().map(|k| hex::encode(k.to_bytes())).collect();
        let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
        let deployer = signer.address();
        let rpc = anvil.endpoint();
        let provider = ProviderBuilder::new()
            .with_simple_nonce_management()
            .wallet(EthereumWallet::from(signer))
            .connect(&rpc)
            .await
            .map_err(|e| ChainError::Config(format!("connect {rpc}: {e}")))?;
        fn deploy_err(what: &'static str) -> impl Fn(alloy::contract::Error) -> ChainError {
            move |e| ChainError::Rejected(format!("deploy {what}: {e}"))
        }

        let registry_impl = FileRegistry::deploy(&provider).await.map_err(deploy_err("registry"))?;
        let registry = ERC1967Proxy::deploy(
            &provider,
            *registry_impl.address(),
            registry_impl.initialize(deployer).calldata().clone(),
        )
        .await
        .map_err(deploy_err("registry proxy"))?;
        let policy_impl =
            AccessPolicy::deploy(&provider, *registry.address()).await.map_err(deploy_err("policy"))?;
        let policy = ERC1967Proxy::deploy(
            &provider,
            *policy_impl.address(),
            policy_impl.initialize(deployer).calldata().clone(),
        )
        .await
        .map_err(deploy_err("policy proxy"))?;
        let audit = AuditLog::deploy(&provider).await.map_err(deploy_err("audit"))?;
        let validator = P256Validator::deploy(&provider).await.map_err(deploy_err("validator"))?;
        let _ = provider.get_block_number().await;

        Ok(Self {
            anvil,
            rpc,
            deployment: Deployment {
                registry: *registry.address(),
                policy: *policy.address(),
                audit: *audit.address(),
                p256_validator: Some(*validator.address()),
            },
            keys,
        })
    }

    /// The deployment as `deployments/<chainId>.json` would carry it.
    pub fn deployment_json(&self) -> String {
        serde_json::json!({
            "chainId": self.anvil.chain_id(),
            "registry": self.deployment.registry,
            "policy": self.deployment.policy,
            "audit": self.deployment.audit,
            "p256Validator": self.deployment.p256_validator,
        })
        .to_string()
    }
}
