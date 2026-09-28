//! Z-1.H.8 — the owner's writes behind one trait.
//!
//! Every write the Agent makes (`register` when a file is locked, `grant` when the owner
//! allows, `bumpVersion` when a recipient's new version is accepted, `revoke`) is the same
//! calldata ([`crate::calls`]) whichever way it travels:
//!
//! - [`SmartAccountWriter`] — the production path. The owner is a Kernel v3.1 account whose
//!   root validator is the device's approval key; each write is one user operation, signed by
//!   that key and paid by a paymaster, so the person never holds gas or knows the word.
//! - [`DirectWriter`] — a funded key sending plain transactions: Anvil, a self-hosted
//!   deployment, tests. The owner is the key's address.
//!
//! **One tap, one signature** (ADR-0008): `grant` is submitted by the owner account itself, and
//! `AccessPolicy` takes the caller's own authorisation (the user operation signature, or the
//! key's transaction) in place of a second signature over the terms.

use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::TransactionRequest;
use async_trait::async_trait;

use crate::aa::{kernel_v31, KernelAccount, ENTRY_POINT_V07};
use crate::bundler::{Bundler, RpcUserOperation, UserOpSender};
use crate::calls::{self, GrantArgs};
use crate::client::{ChainClient, Deployment};
use crate::error::{ChainError, Result};

/// Transaction hash of a landed write.
pub type TxHash = [u8; 32];

/// What a user operation is for, so the signer can apply the approval policy (T23: an Edit
/// grant asks the OS to confirm; a version bump in the background must not).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Write {
    /// A file was locked here.
    Register {
        /// Container file id.
        file_id: [u8; 32],
    },
    /// A recipient's new version was accepted.
    BumpVersion {
        /// Container file id.
        file_id: [u8; 32],
    },
    /// The owner allowed a request.
    Grant {
        /// Container file id.
        file_id: [u8; 32],
        /// 1 read-only, 2 edit.
        permission: u8,
    },
    /// The owner pulled an approval back.
    Revoke {
        /// Container file id.
        file_id: [u8; 32],
    },
}

impl Write {
    /// The file the write is about.
    pub fn file_id(&self) -> [u8; 32] {
        match *self {
            Self::Register { file_id }
            | Self::BumpVersion { file_id }
            | Self::Grant { file_id, .. }
            | Self::Revoke { file_id } => file_id,
        }
    }
}

/// One write, named so a caller can queue it and hand several over at once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    /// `FileRegistry.register`.
    Register {
        /// Container file id.
        file_id: [u8; 32],
        /// Header hash of the first version.
        header_hash: [u8; 32],
    },
    /// `FileRegistry.bumpVersion`.
    BumpVersion {
        /// Container file id.
        file_id: [u8; 32],
        /// Header hash of the new version.
        header_hash: [u8; 32],
    },
    /// `AccessPolicy.grant` from the owner account itself (no second signature, ADR-0008).
    Grant(GrantArgs),
    /// `AccessPolicy.revoke`.
    Revoke {
        /// Container file id.
        file_id: [u8; 32],
        /// EIP-712 struct hash of the grant.
        grant_id: [u8; 32],
    },
}

impl Call {
    /// Which contract, and what calldata.
    pub fn target_and_data(&self, deployment: &Deployment) -> (Address, Bytes) {
        match self {
            Self::Register { file_id, header_hash } => {
                (deployment.registry, calls::register(*file_id, *header_hash))
            }
            Self::BumpVersion { file_id, header_hash } => {
                (deployment.registry, calls::bump_version(*file_id, *header_hash))
            }
            Self::Grant(g) => (deployment.policy, calls::grant(g, &[])),
            Self::Revoke { grant_id, .. } => (deployment.policy, calls::revoke(*grant_id)),
        }
    }
}

/// The owner's writes, whichever way they travel.
#[async_trait]
pub trait ChainWriter: Send + Sync {
    /// The address that owns files on chain: the smart account, or the funded key.
    fn owner(&self) -> Address;
    /// `FileRegistry.register`.
    async fn register(&self, file_id: [u8; 32], header_hash: [u8; 32]) -> Result<TxHash>;
    /// `FileRegistry.bumpVersion`.
    async fn bump_version(&self, file_id: [u8; 32], new_header_hash: [u8; 32]) -> Result<TxHash>;
    /// `AccessPolicy.grant` from the owner account itself (no second signature, ADR-0008).
    async fn grant(&self, terms: &GrantArgs) -> Result<TxHash>;
    /// `AccessPolicy.revoke`.
    async fn revoke(&self, file_id: [u8; 32], grant_id: [u8; 32]) -> Result<TxHash>;

    /// Several writes under one authorisation where the account can (a smart account puts
    /// them in one user operation, in order, all or nothing), one after another where it
    /// cannot. `about` is the write the person actually asked for; the others were queued
    /// behind it (ADR-0008 §5). Returns the last transaction hash.
    async fn submit(&self, batch: &[Call], about: Write) -> Result<TxHash> {
        let _ = about;
        let mut last = [0u8; 32];
        for call in batch {
            last = match call {
                Call::Register { file_id, header_hash } => self.register(*file_id, *header_hash).await?,
                Call::BumpVersion { file_id, header_hash } => {
                    self.bump_version(*file_id, *header_hash).await?
                }
                Call::Grant(g) => self.grant(g).await?,
                Call::Revoke { file_id, grant_id } => self.revoke(*file_id, *grant_id).await?,
            };
        }
        Ok(last)
    }
}

// ------------------------------------------------------------------ direct

/// A funded key sending plain transactions (Anvil, self-hosted, tests).
pub struct DirectWriter {
    client: ChainClient,
    owner: Address,
}

impl DirectWriter {
    /// Wrap a client built with [`ChainClient::connect_signed`]; `owner` is that signer's address.
    pub fn new(client: ChainClient, owner: Address) -> Self {
        Self { client, owner }
    }

    /// Connect with a hex-encoded funded key (`0x`-prefixed or not). The Agent's developer
    /// path: `ZBACS_CHAIN_KEY` on an Anvil box.
    pub async fn connect(rpc_url: &str, deployment: Deployment, key_hex: &str) -> Result<Self> {
        let signer: alloy::signers::local::PrivateKeySigner = key_hex
            .trim()
            .trim_start_matches("0x")
            .parse()
            .map_err(|_| ChainError::Config("the chain key is not a 32-byte hex private key".into()))?;
        let owner = signer.address();
        Ok(Self::new(ChainClient::connect_signed(rpc_url, deployment, signer).await?, owner))
    }

    /// The client, for reads on the same connection.
    pub fn client(&self) -> &ChainClient {
        &self.client
    }
}

#[async_trait]
impl ChainWriter for DirectWriter {
    fn owner(&self) -> Address {
        self.owner
    }

    async fn register(&self, file_id: [u8; 32], header_hash: [u8; 32]) -> Result<TxHash> {
        self.client.register_file(file_id, header_hash).await
    }

    async fn bump_version(&self, file_id: [u8; 32], new_header_hash: [u8; 32]) -> Result<TxHash> {
        self.client.bump_version(file_id, new_header_hash).await
    }

    async fn grant(&self, terms: &GrantArgs) -> Result<TxHash> {
        self.client.grant(terms, &[]).await
    }

    async fn revoke(&self, _file_id: [u8; 32], grant_id: [u8; 32]) -> Result<TxHash> {
        self.client.revoke(grant_id).await
    }
}

// ------------------------------------------------------------------ smart account

/// Signs user operations with the owner's approval key. The Agent implements this over its
/// `AuthProvider`, encoding the assertion with [`crate::aa::p256_raw_signature`] or
/// [`crate::aa::webauthn_signature`].
pub trait UserOpSigner: Send + Sync {
    /// The root validator's signature over `hash`. `about` says what the operation does, so
    /// the confirmation policy can be applied (T23).
    fn sign_user_op(&self, hash: B256, about: Write) -> Result<Bytes>;
    /// A signature of the right length that fails validation, for gas estimation.
    fn stub_signature(&self) -> Bytes;
}

/// The owner's Kernel v3.1 account, writing through a bundler.
pub struct SmartAccountWriter {
    account: KernelAccount,
    provider: DynProvider,
    bundler: Arc<dyn Bundler>,
    signer: Arc<dyn UserOpSigner>,
    deployment: Deployment,
    chain_id: u64,
    /// How long to wait for a user operation to land before giving up on the receipt.
    pub inclusion_timeout: Duration,
}

impl SmartAccountWriter {
    /// Build one. `provider` is a plain (unsigned) node connection for `eth_call`/`eth_getCode`;
    /// the bundler and the signer do the rest.
    pub fn new(
        account: KernelAccount,
        provider: DynProvider,
        bundler: Arc<dyn Bundler>,
        signer: Arc<dyn UserOpSigner>,
        deployment: Deployment,
        chain_id: u64,
    ) -> Self {
        Self {
            account,
            provider,
            bundler,
            signer,
            deployment,
            chain_id,
            inclusion_timeout: Duration::from_secs(120),
        }
    }

    /// The account.
    pub fn account(&self) -> &KernelAccount {
        &self.account
    }

    /// Whether the account has been deployed (its first user operation deploys it).
    pub async fn is_deployed(&self) -> Result<bool> {
        let code = self
            .provider
            .get_code_at(self.account.address())
            .await
            .map_err(|e| ChainError::Unreachable(e.to_string()))?;
        Ok(!code.is_empty())
    }

    /// The account's next nonce for its root validator, from the entry point.
    pub async fn next_nonce(&self) -> Result<U256> {
        let key_word = self.account.nonce(0).to_be_bytes::<32>();
        let mut key = [0u8; 24];
        key.copy_from_slice(&key_word[..24]);
        let data = calls::entry_point_get_nonce(self.account.address(), key);
        let tx = TransactionRequest::default().to(ENTRY_POINT_V07).input(data.into());
        let out = self.provider.call(tx).await.map_err(|e| ChainError::Unreachable(e.to_string()))?;
        if out.len() != 32 {
            return Err(ChainError::Malformed(format!("getNonce returned {} bytes", out.len())));
        }
        Ok(U256::from_be_slice(&out))
    }

    /// One call from the account: assemble, sponsor, sign, send, wait.
    async fn send(&self, target: Address, data: Bytes, about: Write) -> Result<TxHash> {
        self.send_call_data(KernelAccount::execute_call(target, U256::ZERO, &data), about).await
    }

    async fn send_call_data(&self, call_data: Bytes, about: Write) -> Result<TxHash> {
        let (factory, factory_data) = if self.is_deployed().await? {
            (None, None)
        } else {
            (Some(kernel_v31::META_FACTORY), Some(self.account.init_code()[20..].to_vec().into()))
        };
        let op = RpcUserOperation {
            sender: self.account.address(),
            nonce: self.next_nonce().await?,
            factory,
            factory_data,
            call_data,
            call_gas_limit: U256::ZERO,
            verification_gas_limit: U256::ZERO,
            pre_verification_gas: U256::ZERO,
            max_fee_per_gas: U256::ZERO,
            max_priority_fee_per_gas: U256::ZERO,
            paymaster: None,
            paymaster_verification_gas_limit: None,
            paymaster_post_op_gas_limit: None,
            paymaster_data: None,
            signature: Bytes::new(),
        };
        let sender = UserOpSender {
            bundler: self.bundler.as_ref(),
            chain_id: self.chain_id,
            stub_signature: self.signer.stub_signature(),
        };
        let signer = self.signer.clone();
        let user_op_hash = sender.submit(op, move |hash| signer.sign_user_op(hash, about)).await?;
        let receipt = sender.wait(user_op_hash, self.inclusion_timeout).await?;
        if !receipt.success {
            return Err(ChainError::Rejected(format!("user operation {user_op_hash} reverted")));
        }
        Ok(receipt.receipt.transaction_hash.0)
    }
}

#[async_trait]
impl ChainWriter for SmartAccountWriter {
    fn owner(&self) -> Address {
        self.account.address()
    }

    async fn register(&self, file_id: [u8; 32], header_hash: [u8; 32]) -> Result<TxHash> {
        self.send(
            self.deployment.registry,
            calls::register(file_id, header_hash),
            Write::Register { file_id },
        )
        .await
    }

    async fn bump_version(&self, file_id: [u8; 32], new_header_hash: [u8; 32]) -> Result<TxHash> {
        self.send(
            self.deployment.registry,
            calls::bump_version(file_id, new_header_hash),
            Write::BumpVersion { file_id },
        )
        .await
    }

    async fn grant(&self, terms: &GrantArgs) -> Result<TxHash> {
        self.send(
            self.deployment.policy,
            calls::grant(terms, &[]),
            Write::Grant { file_id: terms.file_id, permission: terms.permission },
        )
        .await
    }

    async fn revoke(&self, file_id: [u8; 32], grant_id: [u8; 32]) -> Result<TxHash> {
        self.send(self.deployment.policy, calls::revoke(grant_id), Write::Revoke { file_id }).await
    }

    /// One user operation, one signature, every call in order (ERC-7579 batch).
    async fn submit(&self, batch: &[Call], about: Write) -> Result<TxHash> {
        match batch {
            [] => Err(ChainError::Config("nothing to submit".into())),
            [one] => {
                let (target, data) = one.target_and_data(&self.deployment);
                self.send(target, data, about).await
            }
            many => {
                let calls: Vec<(Address, U256, Bytes)> = many
                    .iter()
                    .map(|c| {
                        let (target, data) = c.target_and_data(&self.deployment);
                        (target, U256::ZERO, data)
                    })
                    .collect();
                self.send_call_data(KernelAccount::execute_batch(&calls), about).await
            }
        }
    }
}
