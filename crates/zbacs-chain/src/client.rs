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
