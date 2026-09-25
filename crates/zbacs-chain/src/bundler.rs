//! ERC-4337 bundler and paymaster over JSON-RPC (Z-1.H.8/H.9), behind a trait so the Agent
//! never names a vendor (CLAUDE.md rule 6) and so a test can stand one in.
//!
//! The owner never sees any of this: the paymaster pays, the bundler carries, and both are
//! replaceable — an outage falls back to the next endpoint or, with a deposit, to calling the
//! EntryPoint directly (T21).

use alloy::primitives::{Address, Bytes, B256, U256};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::aa::{pack_pair, PackedUserOperation, ENTRY_POINT_V07};
use crate::error::{ChainError, Result};

/// The user operation in the unpacked form the RPC methods take (v0.7 field names).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RpcUserOperation {
    /// The account.
    pub sender: Address,
    /// Kernel nonce.
    pub nonce: U256,
    /// Factory, for an undeployed account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub factory: Option<Address>,
    /// Factory calldata, for an undeployed account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub factory_data: Option<Bytes>,
    /// What the account executes.
    pub call_data: Bytes,
    /// Gas for the call.
    pub call_gas_limit: U256,
    /// Gas for validation (and deployment).
    pub verification_gas_limit: U256,
    /// Gas charged before validation.
    pub pre_verification_gas: U256,
    /// EIP-1559 max fee.
    pub max_fee_per_gas: U256,
    /// EIP-1559 priority fee.
    pub max_priority_fee_per_gas: U256,
    /// Paymaster contract, when sponsored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paymaster: Option<Address>,
    /// Paymaster validation gas.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paymaster_verification_gas_limit: Option<U256>,
    /// Paymaster post-op gas.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paymaster_post_op_gas_limit: Option<U256>,
    /// Paymaster data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paymaster_data: Option<Bytes>,
    /// The validator's signature (or the stub used for estimation).
    pub signature: Bytes,
}

impl RpcUserOperation {
    /// The packed form whose hash the owner signs.
    pub fn packed(&self) -> PackedUserOperation {
        let mut init_code = Vec::new();
        if let (Some(f), Some(d)) = (self.factory, &self.factory_data) {
            init_code.extend_from_slice(f.as_slice());
            init_code.extend_from_slice(d);
        }
        let mut paymaster_and_data = Vec::new();
        if let Some(pm) = self.paymaster {
            paymaster_and_data.extend_from_slice(pm.as_slice());
            let v = self.paymaster_verification_gas_limit.unwrap_or(U256::ZERO).to::<u128>();
            let p = self.paymaster_post_op_gas_limit.unwrap_or(U256::ZERO).to::<u128>();
            paymaster_and_data.extend_from_slice(&v.to_be_bytes()[..16]);
            paymaster_and_data.extend_from_slice(&p.to_be_bytes()[..16]);
            if let Some(data) = &self.paymaster_data {
                paymaster_and_data.extend_from_slice(data.as_ref());
            }
        }
        PackedUserOperation {
            sender: self.sender,
            nonce: self.nonce,
            init_code: init_code.into(),
            call_data: self.call_data.clone(),
            account_gas_limits: pack_pair(
                self.verification_gas_limit.to::<u128>(),
                self.call_gas_limit.to::<u128>(),
            ),
            pre_verification_gas: self.pre_verification_gas,
            gas_fees: pack_pair(
                self.max_priority_fee_per_gas.to::<u128>(),
                self.max_fee_per_gas.to::<u128>(),
            ),
            paymaster_and_data: paymaster_and_data.into(),
            signature: self.signature.clone(),
        }
    }

    /// The hash the owner's key signs.
    pub fn hash(&self, chain_id: u64) -> B256 {
        self.packed().hash(chain_id, ENTRY_POINT_V07)
    }
}

/// `eth_estimateUserOperationGas` result.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GasEstimate {
    /// Gas charged before validation.
    pub pre_verification_gas: U256,
    /// Gas for validation.
    pub verification_gas_limit: U256,
    /// Gas for the call.
    pub call_gas_limit: U256,
    /// Paymaster validation gas, when sponsored.
    #[serde(default)]
    pub paymaster_verification_gas_limit: Option<U256>,
    /// Paymaster post-op gas, when sponsored.
    #[serde(default)]
    pub paymaster_post_op_gas_limit: Option<U256>,
}

/// `pm_sponsorUserOperation` result (Pimlico shape; other paymasters map onto it).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sponsorship {
    /// Paymaster contract.
    pub paymaster: Address,
    /// Paymaster data.
    pub paymaster_data: Bytes,
    /// Paymaster validation gas.
    pub paymaster_verification_gas_limit: U256,
    /// Paymaster post-op gas.
    pub paymaster_post_op_gas_limit: U256,
    /// Some paymasters also return the account gas limits they simulated with.
    #[serde(default)]
    pub pre_verification_gas: Option<U256>,
    /// See above.
    #[serde(default)]
    pub verification_gas_limit: Option<U256>,
    /// See above.
    #[serde(default)]
    pub call_gas_limit: Option<U256>,
}

/// EIP-1559 fees the bundler will accept.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GasPrice {
    /// Max fee.
    pub max_fee_per_gas: U256,
    /// Priority fee.
    pub max_priority_fee_per_gas: U256,
}

/// `eth_getUserOperationReceipt` result, the part the Agent uses.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserOpReceipt {
    /// Whether the account's call succeeded.
    pub success: bool,
    /// Gas actually used.
    pub actual_gas_used: U256,
    /// The transaction the bundler included it in.
    pub receipt: TxReceipt,
}

/// The enclosing transaction.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxReceipt {
    /// Transaction hash — what `GrantMsg.tx_hash` carries.
    pub transaction_hash: B256,
    /// Block number.
    pub block_number: U256,
}

/// A bundler (and, optionally, its paymaster).
#[async_trait]
pub trait Bundler: Send + Sync {
    /// Fees to use now.
    async fn gas_price(&self) -> Result<GasPrice>;
    /// Gas limits for this operation.
    async fn estimate(&self, op: &RpcUserOperation) -> Result<GasEstimate>;
    /// Ask the paymaster to pay. `None` when this bundler has no paymaster configured.
    async fn sponsor(&self, op: &RpcUserOperation) -> Result<Option<Sponsorship>>;
    /// Submit; returns the user operation hash the bundler tracks.
    async fn send(&self, op: &RpcUserOperation) -> Result<B256>;
    /// The receipt once included, `None` while pending.
    async fn receipt(&self, user_op_hash: B256) -> Result<Option<UserOpReceipt>>;
}

/// A bundler reached over HTTP JSON-RPC (Pimlico, Alchemy, a self-hosted alto…), through the
/// same alloy transport the chain reads use — one HTTP stack, one TLS configuration.
pub struct JsonRpcBundler {
    provider: alloy::providers::DynProvider,
    /// Whether to call `pm_sponsorUserOperation` on the same endpoint.
    with_paymaster: bool,
    /// Which `pm_*` context to send; Pimlico wants `{"sponsorshipPolicyId": ...}` or nothing.
    sponsor_context: Option<serde_json::Value>,
}

impl JsonRpcBundler {
    /// A bundler endpoint. `with_paymaster` means the same endpoint sponsors (Pimlico does).
    pub fn new(url: &str, with_paymaster: bool) -> Result<Self> {
        let parsed: reqwest_url::Url =
            url.parse().map_err(|e| ChainError::Config(format!("bundler url: {e}")))?;
        let provider =
            alloy::providers::ProviderBuilder::new().disable_recommended_fillers().connect_http(parsed);
        Ok(Self {
            provider: alloy::providers::DynProvider::new(provider),
            with_paymaster,
            sponsor_context: None,
        })
    }

    /// Extra context for the paymaster call (Pimlico sponsorship policy id, …).
    pub fn with_sponsor_context(mut self, context: serde_json::Value) -> Self {
        self.sponsor_context = Some(context);
        self
    }

    async fn rpc<T: alloy::rpc::json_rpc::RpcRecv>(
        &self,
        method: &'static str,
        params: serde_json::Value,
    ) -> Result<T> {
        use alloy::providers::Provider;
        self.provider.raw_request::<_, T>(std::borrow::Cow::Borrowed(method), params).await.map_err(|e| {
            let text = e.to_string();
            if e.is_error_resp() {
                ChainError::Rejected(format!("{method}: {text}"))
            } else {
                ChainError::Unreachable(format!("{method}: {text}"))
            }
        })
    }
}

#[async_trait]
impl Bundler for JsonRpcBundler {
    async fn gas_price(&self) -> Result<GasPrice> {
        #[derive(Debug, Deserialize)]
        struct Tiers {
            fast: GasPrice,
        }
        // Pimlico's method; a bundler without it answers with an error and we fall back to
        // the chain's own view through the provider (the caller's job).
        let tiers: Tiers = self.rpc("pimlico_getUserOperationGasPrice", serde_json::json!([])).await?;
        Ok(tiers.fast)
    }

    async fn estimate(&self, op: &RpcUserOperation) -> Result<GasEstimate> {
        self.rpc("eth_estimateUserOperationGas", serde_json::json!([op, ENTRY_POINT_V07])).await
    }

    async fn sponsor(&self, op: &RpcUserOperation) -> Result<Option<Sponsorship>> {
        if !self.with_paymaster {
            return Ok(None);
        }
        let params = match &self.sponsor_context {
            Some(ctx) => serde_json::json!([op, ENTRY_POINT_V07, ctx]),
            None => serde_json::json!([op, ENTRY_POINT_V07]),
        };
        self.rpc("pm_sponsorUserOperation", params).await.map(Some)
    }

    async fn send(&self, op: &RpcUserOperation) -> Result<B256> {
        self.rpc("eth_sendUserOperation", serde_json::json!([op, ENTRY_POINT_V07])).await
    }

    async fn receipt(&self, user_op_hash: B256) -> Result<Option<UserOpReceipt>> {
        self.rpc("eth_getUserOperationReceipt", serde_json::json!([user_op_hash])).await
    }
}

/// Assemble, price, sponsor, sign and submit one call from the account.
///
/// `sign` turns the user operation hash into the validator's signature (the Agent's
/// `AuthProvider` plus [`crate::aa::webauthn_signature`] or [`crate::aa::p256_raw_signature`]);
/// `stub` is a same-length placeholder for gas estimation.
pub struct UserOpSender<'a> {
    /// The bundler.
    pub bundler: &'a dyn Bundler,
    /// EIP-155 chain id.
    pub chain_id: u64,
    /// A signature of the right shape that fails validation, for estimation.
    pub stub_signature: Bytes,
}

impl UserOpSender<'_> {
    /// Estimate, sponsor, sign and send. Returns the user operation hash.
    pub async fn submit<F>(&self, mut op: RpcUserOperation, sign: F) -> Result<B256>
    where
        F: FnOnce(B256) -> Result<Bytes>,
    {
        let fees = self.bundler.gas_price().await?;
        op.max_fee_per_gas = fees.max_fee_per_gas;
        op.max_priority_fee_per_gas = fees.max_priority_fee_per_gas;
        op.signature = self.stub_signature.clone();

        // A sponsoring paymaster estimates as part of sponsoring; otherwise estimate ourselves.
        match self.bundler.sponsor(&op).await? {
            Some(s) => {
                op.paymaster = Some(s.paymaster);
                op.paymaster_data = Some(s.paymaster_data);
                op.paymaster_verification_gas_limit = Some(s.paymaster_verification_gas_limit);
                op.paymaster_post_op_gas_limit = Some(s.paymaster_post_op_gas_limit);
                if let (Some(p), Some(v), Some(c)) =
                    (s.pre_verification_gas, s.verification_gas_limit, s.call_gas_limit)
                {
                    op.pre_verification_gas = p;
                    op.verification_gas_limit = v;
                    op.call_gas_limit = c;
                } else {
                    let g = self.bundler.estimate(&op).await?;
                    op.pre_verification_gas = g.pre_verification_gas;
                    op.verification_gas_limit = g.verification_gas_limit;
                    op.call_gas_limit = g.call_gas_limit;
                }
            }
            None => {
                let g = self.bundler.estimate(&op).await?;
                op.pre_verification_gas = g.pre_verification_gas;
                op.verification_gas_limit = g.verification_gas_limit;
                op.call_gas_limit = g.call_gas_limit;
            }
        }

        op.signature = sign(op.hash(self.chain_id))?;
        self.bundler.send(&op).await
    }

    /// Poll for the receipt.
    pub async fn wait(&self, user_op_hash: B256, timeout: std::time::Duration) -> Result<UserOpReceipt> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(r) = self.bundler.receipt(user_op_hash).await? {
                return Ok(r);
            }
            if std::time::Instant::now() >= deadline {
                return Err(ChainError::Unreachable("user operation not included in time".into()));
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }
}
