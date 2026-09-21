//! Reading and writing the Z-BACS contracts.

use std::time::Duration;

use alloy::primitives::{Address, FixedBytes};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};

use crate::cache::{Cache, Cached, VersionRecord};
use crate::contracts::{AccessPolicy, AuditLog, FileRegistry};
use crate::error::{ChainError, Result};

/// Where the Z-BACS contracts live on one chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deployment {
    /// `FileRegistry`.
    pub registry: Address,
    /// `AccessPolicy`.
    pub policy: Address,
    /// `AuditLog`.
    pub audit: Address,
}

impl Deployment {
    /// Read `contracts/deployments/<chainId>.json`, written by `script/Deploy.s.sol` (Z-1.H.4).
    ///
    /// The Agent must not carry addresses compiled into it: a redeployment would leave every
    /// installed copy talking to contracts that no longer hold anyone's files. One file, written
    /// by the deployment and read by everything else.
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| ChainError::Config(format!("{}: {e}", path.display())))?;
        Self::from_json(&text).map_err(|e| match e {
            ChainError::Config(why) => ChainError::Config(format!("{}: {why}", path.display())),
            other => other,
        })
    }

    /// Same, from the file's contents.
    pub fn from_json(json: &str) -> Result<Self> {
        #[derive(serde::Deserialize)]
        struct File {
            registry: Address,
            policy: Address,
            audit: Address,
        }
        let f: File = serde_json::from_str(json).map_err(|e| ChainError::Config(e.to_string()))?;
        let me = Self { registry: f.registry, policy: f.policy, audit: f.audit };

        // A zero or repeated address means the deployment did not finish. Finding that out now
        // is cheaper than finding it out when someone cannot open their file.
        for (what, address) in [("registry", me.registry), ("policy", me.policy), ("audit", me.audit)] {
            if address.is_zero() {
                return Err(ChainError::Config(format!("{what} address is zero")));
            }
        }
        if me.registry == me.policy || me.registry == me.audit || me.policy == me.audit {
            return Err(ChainError::Config("two contracts share an address".into()));
        }
        Ok(me)
    }
}

/// Talks to one chain.
pub struct ChainClient {
    provider: DynProvider,
    deployment: Deployment,
    cache: Cache,
}

fn unreachable(e: impl std::fmt::Display) -> ChainError {
    ChainError::Unreachable(e.to_string())
}

impl ChainClient {
    /// Connect over HTTP (or any URL alloy understands).
    pub async fn connect(rpc_url: &str, deployment: Deployment) -> Result<Self> {
        let provider = ProviderBuilder::new()
            .connect(rpc_url)
            .await
            .map_err(|e| ChainError::Config(format!("connect {rpc_url}: {e}")))?;
        Ok(Self { provider: provider.erased(), deployment, cache: Cache::new() })
    }

    /// Use an already-built provider (tests, or an Agent that shares one).
    pub fn with_provider(provider: DynProvider, deployment: Deployment) -> Self {
        Self { provider, deployment, cache: Cache::new() }
    }

    /// The provider, for callers that need to sign their own transactions.
    pub fn provider(&self) -> &DynProvider {
        &self.provider
    }

    /// Contract addresses in use.
    pub fn deployment(&self) -> Deployment {
        self.deployment
    }

    /// The offline cache.
    pub fn cache(&self) -> &Cache {
        &self.cache
    }

    /// Current block height — the cheapest "are we online" check.
    pub async fn block_number(&self) -> Result<u64> {
        self.provider.get_block_number().await.map_err(unreachable)
    }

    /// Who owns a file, or `None` when it was never registered.
    pub async fn owner_of(&self, file_id: [u8; 32]) -> Result<Option<Address>> {
        let registry = FileRegistry::new(self.deployment.registry, &self.provider);
        let owner = registry.ownerOf(FixedBytes(file_id)).call().await.map_err(unreachable)?;
        Ok((!owner.is_zero()).then_some(owner))
    }

    /// The current sealed version: header hash, version number, and whether it is retired.
    ///
    /// The answer is cached, so a later call while offline can still say what was true.
    pub async fn current_version(&self, file_id: [u8; 32]) -> Result<VersionRecord> {
        let registry = FileRegistry::new(self.deployment.registry, &self.provider);
        let v = registry.currentVersion(FixedBytes(file_id)).call().await.map_err(unreachable)?;
        let out = (v.headerHash.0, v.version, v.retired);
        self.cache.put_version(file_id, out.0, out.1, out.2);
        Ok(out)
    }

    /// Is this grant still good?
    ///
    /// Cached on every successful answer. Use [`ChainClient::is_grant_valid_offline`] when the
    /// node may be unreachable and the file's policy allows acting on a recent answer.
    pub async fn is_grant_valid(&self, grant_id: [u8; 32]) -> Result<bool> {
        let policy = AccessPolicy::new(self.deployment.policy, &self.provider);
        let valid = policy.isValid(FixedBytes(grant_id)).call().await.map_err(unreachable)?;
        self.cache.put_grant(grant_id, valid);
        Ok(valid)
    }

    /// Ask the chain, and fall back to the cache when it cannot be reached.
    ///
    /// Returns the answer with its age so the caller can apply the file's policy: a
    /// `strict_onchain` file refuses anything but [`crate::Freshness::Fresh`], everything else
    /// may proceed on a recent answer and re-check later (spec §2.6, T16).
    pub async fn is_grant_valid_offline(
        &self,
        grant_id: [u8; 32],
        tolerance: Duration,
    ) -> Result<Cached<bool>> {
        match self.is_grant_valid(grant_id).await {
            Ok(_) => self
                .cache
                .grant(&grant_id, tolerance)
                .ok_or_else(|| ChainError::Malformed("cache did not keep a fresh answer".into())),
            Err(e) if e.is_unreachable() => self.cache.grant(&grant_id, tolerance).ok_or(e),
            Err(e) => Err(e),
        }
    }

    /// Register a newly sealed file. Sends a transaction from the provider's signer.
    pub async fn register_file(&self, file_id: [u8; 32], header_hash: [u8; 32]) -> Result<[u8; 32]> {
        let registry = FileRegistry::new(self.deployment.registry, &self.provider);
        let receipt = registry
            .register(FixedBytes(file_id), FixedBytes(header_hash))
            .send()
            .await
            .map_err(|e| ChainError::Rejected(e.to_string()))?
            .get_receipt()
            .await
            .map_err(unreachable)?;
        Ok(receipt.transaction_hash.0)
    }

    /// Record a reseal.
    pub async fn bump_version(&self, file_id: [u8; 32], new_header_hash: [u8; 32]) -> Result<[u8; 32]> {
        let registry = FileRegistry::new(self.deployment.registry, &self.provider);
        let receipt = registry
            .bumpVersion(FixedBytes(file_id), FixedBytes(new_header_hash))
            .send()
            .await
            .map_err(|e| ChainError::Rejected(e.to_string()))?
            .get_receipt()
            .await
            .map_err(unreachable)?;
        self.cache.put_version(file_id, new_header_hash, 0, false);
        Ok(receipt.transaction_hash.0)
    }

    /// Retire a file: no further versions, no new grants.
    pub async fn retire(&self, file_id: [u8; 32]) -> Result<[u8; 32]> {
        let registry = FileRegistry::new(self.deployment.registry, &self.provider);
        let receipt = registry
            .retire(FixedBytes(file_id))
            .send()
            .await
            .map_err(|e| ChainError::Rejected(e.to_string()))?
            .get_receipt()
            .await
            .map_err(unreachable)?;
        Ok(receipt.transaction_hash.0)
    }

    /// Revoke a grant.
    pub async fn revoke(&self, grant_id: [u8; 32]) -> Result<[u8; 32]> {
        let policy = AccessPolicy::new(self.deployment.policy, &self.provider);
        let receipt = policy
            .revoke(FixedBytes(grant_id))
            .send()
            .await
            .map_err(|e| ChainError::Rejected(e.to_string()))?
            .get_receipt()
            .await
            .map_err(unreachable)?;
        self.cache.put_grant(grant_id, false);
        Ok(receipt.transaction_hash.0)
    }

    /// Append an audit entry (see `AuditLog`: a claim by the reporter, not proof).
    pub async fn audit(
        &self,
        file_id: [u8; 32],
        kind: u8,
        actor_commit: [u8; 32],
        detail: [u8; 32],
    ) -> Result<[u8; 32]> {
        let audit = AuditLog::new(self.deployment.audit, &self.provider);
        let receipt = audit
            .log(FixedBytes(file_id), kind, FixedBytes(actor_commit), FixedBytes(detail))
            .send()
            .await
            .map_err(|e| ChainError::Rejected(e.to_string()))?
            .get_receipt()
            .await
            .map_err(unreachable)?;
        Ok(receipt.transaction_hash.0)
    }
}

#[cfg(test)]
mod deployment_tests {
    use super::*;

    /// The shape `script/Deploy.s.sol` actually writes (Z-1.H.4), extra fields and all.
    const REAL: &str = r#"{
      "audit": "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707",
      "chainId": 31337,
      "minDelay": 0,
      "p256Validator": "0x0165878A594ca255338adfa4d48449f69242Eb8F",
      "policy": "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9",
      "policyImplementation": "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9",
      "proposer": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
      "registry": "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",
      "registryImplementation": "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
      "timelock": "0x5FbDB2315678afecb367f032d93F642f64180aa3"
    }"#;

    #[test]
    fn the_file_the_deploy_script_writes_is_understood() {
        let d = Deployment::from_json(REAL).unwrap();
        assert_eq!(d.registry.to_string().to_lowercase(), "0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0");
        assert_ne!(d.policy, d.registry);
        assert_ne!(d.audit, d.policy);
    }

    /// The addresses are read from the proxies, not the implementations: talking to an
    /// implementation would work until the first upgrade and then silently stop.
    #[test]
    fn the_proxy_address_is_taken_not_the_implementation() {
        let d = Deployment::from_json(REAL).unwrap();
        assert_ne!(
            d.registry.to_string().to_lowercase(),
            "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
            "registryImplementation must not be mistaken for the registry"
        );
    }

    #[test]
    fn a_half_finished_deployment_is_refused() {
        let zero = REAL.replace("0x5FC8d32690cc91D4c39d9d3abcBD16989F875707", &Address::ZERO.to_string());
        assert!(Deployment::from_json(&zero).unwrap_err().to_string().contains("audit address is zero"));

        let same = REAL.replace(
            "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9",
            "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",
        );
        assert!(Deployment::from_json(&same).unwrap_err().to_string().contains("share an address"));

        assert!(Deployment::from_json("{}").is_err(), "missing fields");
        assert!(Deployment::from_json("not json").is_err());
    }

    #[test]
    fn a_missing_file_says_which_file() {
        let err = Deployment::from_file("/nonexistent/deployments/31337.json").unwrap_err();
        assert!(err.to_string().contains("31337.json"), "{err}");
        assert!(matches!(err, ChainError::Config(_)));
    }

    #[test]
    fn a_real_file_round_trips() {
        let dir = std::env::temp_dir().join(format!("zbacs-deployment-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("31337.json");
        std::fs::write(&path, REAL).unwrap();
        assert_eq!(Deployment::from_file(&path).unwrap(), Deployment::from_json(REAL).unwrap());
        std::fs::remove_dir_all(dir).ok();
    }
}
