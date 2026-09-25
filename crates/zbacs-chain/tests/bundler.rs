//! The bundler client against a stand-in JSON-RPC server: what goes over the wire, in what
//! shape, and how the sponsor/estimate/sign/send sequence composes. The real bundler was
//! exercised in the Base Sepolia spike (docs/research/aa_passkey_spike.md §2b); this pins the
//! Rust side to the same request and response shapes without network.

use std::sync::{Arc, Mutex};

use alloy::primitives::{address, b256, Bytes, B256, U256};
use axum::{routing::post, Json, Router};
use serde_json::{json, Value};
use zbacs_chain::aa::{KernelAccount, RootValidator};
use zbacs_chain::bundler::{Bundler, JsonRpcBundler, RpcUserOperation, UserOpSender};
use zbacs_chain::calls;

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
