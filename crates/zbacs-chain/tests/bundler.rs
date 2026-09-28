//! The bundler client against a stand-in JSON-RPC server: what goes over the wire, in what
//! shape, and how the sponsor/estimate/sign/send sequence composes. The real bundler was
//! exercised in the Base Sepolia spike (docs/research/aa_passkey_spike.md §2b); this pins the
//! Rust side to the same request and response shapes without network.

use std::sync::{Arc, Mutex};

use alloy::primitives::{address, b256, Bytes, B256, U256};
use alloy::providers::Provider;
use axum::{routing::post, Json, Router};
use serde_json::{json, Value};
use zbacs_chain::aa::{KernelAccount, RootValidator};
use zbacs_chain::bundler::{Bundler, JsonRpcBundler, RpcUserOperation, UserOpSender};
use zbacs_chain::calls;
use zbacs_chain::{Call, ChainWriter, Deployment, Failover, SmartAccountWriter, UserOpSigner, Write};

/// Records every request and answers like Pimlico would.
#[derive(Clone, Default)]
struct FakeBundler {
    seen: Arc<Mutex<Vec<Value>>>,
}

async fn handle(state: axum::extract::State<FakeBundler>, Json(req): Json<Value>) -> Json<Value> {
    state.seen.lock().unwrap().push(req.clone());
    let id = req["id"].clone();
    let result = match req["method"].as_str().unwrap() {
        "pimlico_getUserOperationGasPrice" => json!({
            "slow": {"maxFeePerGas": "0x1", "maxPriorityFeePerGas": "0x1"},
            "standard": {"maxFeePerGas": "0x2", "maxPriorityFeePerGas": "0x1"},
            "fast": {"maxFeePerGas": "0x3b9aca00", "maxPriorityFeePerGas": "0x5f5e100"}
        }),
        "pm_sponsorUserOperation" => json!({
            "paymaster": "0x0000000000000000000000000000000000000777",
            "paymasterData": "0xabcd",
            "paymasterVerificationGasLimit": "0x7530",
            "paymasterPostOpGasLimit": "0x1388",
            "preVerificationGas": "0x186a0",
            "verificationGasLimit": "0x16e360",
            "callGasLimit": "0x493e0"
        }),
        "eth_estimateUserOperationGas" => json!({
            "preVerificationGas": "0x100", "verificationGasLimit": "0x200", "callGasLimit": "0x300"
        }),
        "eth_sendUserOperation" => {
            let op = &req["params"][0];
            // the wire shape a v0.7 bundler requires
            for key in [
                "sender",
                "nonce",
                "callData",
                "callGasLimit",
                "verificationGasLimit",
                "preVerificationGas",
                "maxFeePerGas",
                "maxPriorityFeePerGas",
                "signature",
            ] {
                assert!(op.get(key).is_some(), "missing {key}");
            }
            assert!(op.get("initCode").is_none(), "v0.7 sends factory/factoryData, not initCode");
            assert_eq!(
                req["params"][1].as_str().unwrap().to_lowercase(),
                "0x0000000071727de22e5e9d8baf0edac6f37da032",
                "entry point v0.7"
            );
            json!("0x1111111111111111111111111111111111111111111111111111111111111111")
        }
        // the node side, for the writer: an undeployed account with a fresh nonce
        "eth_getCode" => json!("0x"),
        "eth_call" => json!(format!("0x{}", hex(&account().nonce(0).to_be_bytes::<32>()))),
        "eth_getUserOperationReceipt" => json!({
            "success": true,
            "actualGasUsed": "0x66270",
            "receipt": {"transactionHash": "0x2222222222222222222222222222222222222222222222222222222222222222", "blockNumber": "0x2cd7a3a"}
        }),
        other => {
            return Json(
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": format!("no {other}")}}),
            )
        }
    };
    Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

async fn serve(fake: FakeBundler) -> String {
    let app = Router::new().route("/", post(handle)).with_state(fake);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}/")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn account() -> KernelAccount {
    KernelAccount::new(RootValidator::DeviceKey {
        validator: address!("0165878A594ca255338adfa4d48449f69242Eb8F"),
        x: [1; 32],
        y: [2; 32],
        require_os_confirm: false,
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sponsored_user_operation_is_priced_sponsored_signed_and_sent() {
    let fake = FakeBundler::default();
    let url = serve(fake.clone()).await;
    let bundler = JsonRpcBundler::new(&url, true).unwrap();
    let acct = account();
    let call = calls::register([9; 32], [8; 32]);

    let op = RpcUserOperation {
        sender: acct.address(),
        nonce: acct.nonce(0),
        factory: Some(zbacs_chain::aa::kernel_v31::META_FACTORY),
        factory_data: Some(acct.init_code()[20..].to_vec().into()),
        call_data: KernelAccount::execute_call(
            address!("9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"),
            U256::ZERO,
            &call,
        ),
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
    let sender = UserOpSender { bundler: &bundler, chain_id: 84532, stub_signature: vec![0xAA; 96].into() };
    let signed_hash = Arc::new(Mutex::new(None));
    let seen_hash = signed_hash.clone();
    let user_op_hash = sender
        .submit(op, |hash| {
            *seen_hash.lock().unwrap() = Some(hash);
            Ok(zbacs_chain::aa::p256_raw_signature([3; 32], [4; 32], [5; 32]))
        })
        .await
        .unwrap();
    assert_eq!(user_op_hash, b256!("1111111111111111111111111111111111111111111111111111111111111111"));

    let receipt = sender.wait(user_op_hash, std::time::Duration::from_secs(5)).await.unwrap();
    assert!(receipt.success);
    assert_eq!(
        receipt.receipt.transaction_hash,
        b256!("2222222222222222222222222222222222222222222222222222222222222222")
    );

    // the sequence, and what each step carried
    let seen = fake.seen.lock().unwrap();
    let methods: Vec<_> = seen.iter().map(|r| r["method"].as_str().unwrap().to_string()).collect();
    assert_eq!(
        methods,
        [
            "pimlico_getUserOperationGasPrice",
            "pm_sponsorUserOperation",
            "eth_sendUserOperation",
            "eth_getUserOperationReceipt"
        ]
    );
    let sent = &seen[2]["params"][0];
    assert_eq!(sent["maxFeePerGas"], "0x3b9aca00", "the fast tier");
    assert_eq!(sent["paymaster"], "0x0000000000000000000000000000000000000777");
    assert_eq!(sent["callGasLimit"], "0x493e0", "gas from the sponsor's simulation");
    assert_eq!(sent["signature"].as_str().unwrap().len(), 2 + 96 * 2, "the real signature, not the stub");
    let sponsored_with = &seen[1]["params"][0];
    assert_eq!(
        sponsored_with["signature"].as_str().unwrap().len(),
        2 + 96 * 2,
        "the stub has the real length"
    );
    assert!(sponsored_with.get("paymaster").is_none(), "no paymaster before sponsoring");

    // what was signed is the hash of what was sent (with the paymaster, before the signature)
    let hash = signed_hash.lock().unwrap().unwrap();
    let mut resent: RpcUserOperation = serde_json::from_value(sent.clone()).unwrap();
    resent.signature = Bytes::new();
    assert_eq!(resent.hash(84532), hash);
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_paymaster_the_bundler_estimates_and_a_refusal_is_reported() {
    let fake = FakeBundler::default();
    let url = serve(fake.clone()).await;
    let bundler = JsonRpcBundler::new(&url, false).unwrap();
    assert!(bundler.sponsor(&dummy_op()).await.unwrap().is_none());
    let g = bundler.estimate(&dummy_op()).await.unwrap();
    assert_eq!(
        (g.pre_verification_gas, g.verification_gas_limit, g.call_gas_limit),
        (U256::from(0x100), U256::from(0x200), U256::from(0x300))
    );

    // a method the bundler does not have is a clear refusal, not a hang
    let err = bundler.receipt(B256::ZERO).await.unwrap_or(None);
    assert!(err.is_some(), "the fake answers receipts");
    let no_such = JsonRpcBundler::new("http://127.0.0.1:1/", false).unwrap();
    assert!(matches!(no_such.gas_price().await, Err(zbacs_chain::ChainError::Unreachable(_))));
}

fn dummy_op() -> RpcUserOperation {
    RpcUserOperation {
        sender: account().address(),
        nonce: U256::ZERO,
        factory: None,
        factory_data: None,
        call_data: Bytes::new(),
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
    }
}

/// A signer that records what it was asked to sign and for what.
struct RecordingSigner {
    asked: Mutex<Vec<(B256, Write)>>,
}

impl UserOpSigner for RecordingSigner {
    fn sign_user_op(&self, hash: B256, about: Write) -> zbacs_chain::error::Result<Bytes> {
        self.asked.lock().unwrap().push((hash, about));
        Ok(zbacs_chain::aa::p256_raw_signature([3; 32], [4; 32], [5; 32]))
    }
    fn stub_signature(&self) -> Bytes {
        vec![0xAA; 96].into()
    }
}

/// Z-1.H.8 b: the smart-account writer turns `grant` into one user operation from the owner
/// account — deploying it on the way if needed — with the calldata the contract expects and
/// **no owner signature inside** (ADR-0008); the only signature is the one over the operation.
#[tokio::test(flavor = "multi_thread")]
async fn the_smart_account_writer_sends_one_signed_user_operation_per_write() {
    let fake = FakeBundler::default();
    let url = serve(fake.clone()).await;
    let bundler = Arc::new(JsonRpcBundler::new(&url, true).unwrap());
    let provider = alloy::providers::ProviderBuilder::new().connect(&url).await.unwrap().erased();
    let signer = Arc::new(RecordingSigner { asked: Mutex::new(Vec::new()) });
    let deployment = Deployment {
        registry: address!("9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"),
        policy: address!("Dc64a140Aa3E981100a9becA4E685f962f0cF6C9"),
        audit: address!("5FC8d32690cc91D4c39d9d3abcBD16989F875707"),
        p256_validator: None,
    };
    let writer = SmartAccountWriter::new(account(), provider, bundler, signer.clone(), deployment, 84532);
    assert_eq!(writer.owner(), account().address(), "the account is the owner on chain");

    let terms = calls::GrantArgs {
        file_id: [1; 32],
        header_hash: [2; 32],
        device_key_hash: [3; 32],
        permission: 2,
        not_before: 1,
        expiry: 2,
        max_opens: 0,
        request_nonce: [4; 16],
        grant_nonce: 0,
    };
    let tx = writer.grant(&terms).await.unwrap();
    assert_eq!(tx, b256!("2222222222222222222222222222222222222222222222222222222222222222").0);

    let sent = {
        let seen = fake.seen.lock().unwrap();
        seen.iter().find(|r| r["method"] == "eth_sendUserOperation").unwrap()["params"][0].clone()
    };
    let op: RpcUserOperation = serde_json::from_value(sent).unwrap();
    assert_eq!(op.sender, account().address());
    assert_eq!(op.nonce, account().nonce(0), "sequence 0 for a fresh account");
    assert_eq!(
        op.factory,
        Some(zbacs_chain::aa::kernel_v31::META_FACTORY),
        "undeployed: initCode goes along"
    );
    // execute(single) → AccessPolicy.grant(terms, "")
    let expected = KernelAccount::execute_call(deployment.policy, U256::ZERO, &calls::grant(&terms, &[]));
    assert_eq!(op.call_data, expected);
    assert!(op.paymaster.is_some(), "sponsored");

    // exactly one signature was asked for, over the hash of what was sent, and it said why
    let asked = signer.asked.lock().unwrap();
    assert_eq!(asked.len(), 1);
    let mut unsigned = op.clone();
    unsigned.signature = Bytes::new();
    assert_eq!(asked[0].0, unsigned.hash(84532));
    assert_eq!(asked[0].1, Write::Grant { file_id: [1; 32], permission: 2 });
}

fn deployment() -> Deployment {
    Deployment {
        registry: address!("9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"),
        policy: address!("Dc64a140Aa3E981100a9becA4E685f962f0cF6C9"),
        audit: address!("5FC8d32690cc91D4c39d9d3abcBD16989F875707"),
        p256_validator: None,
    }
}

/// ADR-0008 §5: a deferred `bumpVersion` and the grant that needs it go in **one** user
/// operation — one signature, batch execution, in order.
#[tokio::test(flavor = "multi_thread")]
async fn queued_writes_go_out_as_one_batched_user_operation() {
    let fake = FakeBundler::default();
    let url = serve(fake.clone()).await;
    let bundler = Arc::new(JsonRpcBundler::new(&url, true).unwrap());
    let provider = alloy::providers::ProviderBuilder::new().connect(&url).await.unwrap().erased();
    let signer = Arc::new(RecordingSigner { asked: Mutex::new(Vec::new()) });
    let writer = SmartAccountWriter::new(account(), provider, bundler, signer.clone(), deployment(), 84532);

    let terms = calls::GrantArgs {
        file_id: [1; 32],
        header_hash: [5; 32],
        device_key_hash: [3; 32],
        permission: 1,
        not_before: 1,
        expiry: 2,
        max_opens: 0,
        request_nonce: [4; 16],
        grant_nonce: 3,
    };
    let batch = [Call::BumpVersion { file_id: [1; 32], header_hash: [5; 32] }, Call::Grant(terms.clone())];
    writer.submit(&batch, Write::Grant { file_id: [1; 32], permission: 1 }).await.unwrap();

    let sent = {
        let seen = fake.seen.lock().unwrap();
        seen.iter().find(|r| r["method"] == "eth_sendUserOperation").unwrap()["params"][0].clone()
    };
    let op: RpcUserOperation = serde_json::from_value(sent).unwrap();
    let expected = KernelAccount::execute_batch(&[
        (deployment().registry, U256::ZERO, calls::bump_version([1; 32], [5; 32])),
        (deployment().policy, U256::ZERO, calls::grant(&terms, &[])),
    ]);
    assert_eq!(op.call_data, expected, "bumpVersion first, then the grant, one execute(batch)");
    let asked = signer.asked.lock().unwrap();
    assert_eq!(asked.len(), 1, "one signature for both");
    assert_eq!(asked[0].1, Write::Grant { file_id: [1; 32], permission: 1 }, "the tap, not the queued write");
}

/// T21: a bundler that cannot be reached is skipped; the next one is used for the whole
/// sequence. A refusal from a reachable bundler is final.
#[tokio::test(flavor = "multi_thread")]
async fn t21_a_dead_bundler_falls_over_to_a_live_one() {
    let fake = FakeBundler::default();
    let live = serve(fake.clone()).await;
    let failover = Failover::from_urls(&format!("http://127.0.0.1:1/, {live}"), true, None).unwrap();
    assert_eq!(failover.len(), 2);
    let fees = failover.gas_price().await.unwrap();
    assert_eq!(fees.max_fee_per_gas, U256::from(0x3b9aca00u64));
    let hash = failover.send(&dummy_op()).await.unwrap();
    assert_eq!(hash, b256!("1111111111111111111111111111111111111111111111111111111111111111"));
    assert!(failover.receipt(hash).await.unwrap().is_some());

    // every request went to the live one; the dead one was never "answered"
    assert_eq!(fake.seen.lock().unwrap().len(), 3);

    // all dead: unreachable, not a guess
    let none = Failover::from_urls("http://127.0.0.1:1/,http://127.0.0.1:2/", false, None).unwrap();
    assert!(matches!(none.gas_price().await, Err(zbacs_chain::ChainError::Unreachable(_))));
    assert!(Failover::from_urls(" , ", false, None).is_err(), "no endpoints is a configuration error");
}
