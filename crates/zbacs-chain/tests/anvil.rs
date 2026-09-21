//! Z-1.H.7 DoD — integration against a real chain.
//!
//! These spin up Anvil, deploy the real contracts from the Foundry artifacts, and drive the
//! client against them. If Anvil or the artifacts are missing the tests skip loudly rather than
//! failing, so a machine without Foundry can still run `cargo test`; CI builds the contracts
//! first, so they really run there (`tools/chain-it.sh` does the same locally).

use std::time::Duration;

use alloy::network::EthereumWallet;
use alloy::node_bindings::Anvil;
use alloy::primitives::{keccak256, Address, FixedBytes};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use zbacs_chain::contracts::{AccessGrantLib, AccessPolicy, AuditLog, FileRegistry};
use zbacs_chain::{ChainClient, ChainEvent, Deployment, EventWatcher, Freshness};

fn artifacts_present() -> bool {
    std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/out/FileRegistry.sol/FileRegistry.json"
    ))
    .exists()
}

fn anvil_present() -> bool {
    std::process::Command::new("anvil")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Skip guard. Returns false (and says why) when the environment cannot run these.
fn ready(test: &str) -> bool {
    if !anvil_present() {
        eprintln!("skipping {test}: anvil not on PATH (install Foundry)");
        return false;
    }
    if !artifacts_present() {
        eprintln!("skipping {test}: contracts/out is missing (run `cd contracts && forge build`)");
        return false;
    }
    true
}

struct Fixture {
    _anvil: alloy::node_bindings::AnvilInstance,
    client: ChainClient,
    owner: Address,
    deployment: Deployment,
    rpc: String,
}

async fn deploy() -> Fixture {
    let anvil = Anvil::new().try_spawn().expect("anvil");
    let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
    let owner = signer.address();
    let rpc = anvil.endpoint();
    // Simple (uncached) nonce management: the test drives the same account through several
    // contract handles, and a cached nonce would drift between them.
    let provider = ProviderBuilder::new()
        .with_simple_nonce_management()
        .wallet(EthereumWallet::from(signer))
        .connect(&rpc)
        .await
        .expect("provider");

    let registry = FileRegistry::deploy(&provider).await.expect("deploy registry");
    let policy = AccessPolicy::deploy(&provider, *registry.address()).await.expect("deploy policy");
    let audit = AuditLog::deploy(&provider).await.expect("deploy audit");
    let deployment =
        Deployment { registry: *registry.address(), policy: *policy.address(), audit: *audit.address() };

    let client = ChainClient::with_provider(provider.erased(), deployment);
    Fixture { _anvil: anvil, client, owner, deployment, rpc }
}

fn fid(tag: &str) -> [u8; 32] {
    keccak256(tag.as_bytes()).0
}

// ------------------------------------------------------------------ reads and writes

#[tokio::test]
async fn a_file_is_registered_resealed_and_retired() {
    if !ready("a_file_is_registered_resealed_and_retired") {
        return;
    }
    let f = deploy().await;
    let file = fid("contract.docx");

    assert_eq!(f.client.owner_of(file).await.unwrap(), None, "unknown before registration");

    f.client.register_file(file, fid("header v1")).await.unwrap();
    assert_eq!(f.client.owner_of(file).await.unwrap(), Some(f.owner));
    let (header, version, retired) = f.client.current_version(file).await.unwrap();
    assert_eq!(header, fid("header v1"));
    assert_eq!(version, 1);
    assert!(!retired);

    f.client.bump_version(file, fid("header v2")).await.unwrap();
    let (header, version, _) = f.client.current_version(file).await.unwrap();
    assert_eq!(header, fid("header v2"));
    assert_eq!(version, 2);

    f.client.retire(file).await.unwrap();
    assert!(f.client.current_version(file).await.unwrap().2, "retired");

    // the chain refuses a further version, and the client reports that as a rejection
    let err = f.client.bump_version(file, fid("header v3")).await.unwrap_err();
    assert!(!err.is_unreachable(), "a revert is not an outage: {err}");
}

#[tokio::test]
async fn an_audit_entry_is_accepted() {
    if !ready("an_audit_entry_is_accepted") {
        return;
    }
    let f = deploy().await;
    let file = fid("audited.docx");
    f.client.register_file(file, fid("header v1")).await.unwrap();
    let tx = f.client.audit(file, 2 /* Opened */, fid("actor"), fid("detail")).await.unwrap();
    assert_ne!(tx, [0u8; 32]);
}

// ------------------------------------------------------------------ the offline cache

#[tokio::test]
async fn a_cached_answer_survives_the_node_going_away() {
    if !ready("a_cached_answer_survives_the_node_going_away") {
        return;
    }
    let f = deploy().await;
    let grant = fid("some grant");

    // an unknown grant is simply invalid, and that answer is cached
    assert!(!f.client.is_grant_valid(grant).await.unwrap());
    let cached = f.client.cache().grant(&grant, Duration::from_secs(60)).unwrap();
    assert_eq!(cached.freshness, Freshness::Fresh);
    assert!(!cached.value);

    // point a second client at a dead endpoint but hand it the same cache contents
    let dead = ChainClient::connect("http://127.0.0.1:1", f.deployment).await;
    if let Ok(dead) = dead {
        dead.cache().put_grant(grant, true);
        let answer = dead.is_grant_valid_offline(grant, Duration::from_secs(60)).await.unwrap();
        assert!(answer.value, "the cached answer is used when the node cannot be reached");
        assert_eq!(answer.freshness, Freshness::Fresh);

        // ...but a strict file, which tolerates nothing, gets no usable answer
        let strict = dead.is_grant_valid_offline(grant, Duration::ZERO).await.unwrap();
        assert_eq!(strict.freshness, Freshness::Stale);
        assert_eq!(strict.if_fresh(), None);
    }
}

#[tokio::test]
async fn an_unreachable_node_without_a_cache_is_an_error_not_a_guess() {
    if !anvil_present() {
        eprintln!("skipping: anvil not on PATH");
        return;
    }
    let deployment = Deployment { registry: Address::ZERO, policy: Address::ZERO, audit: Address::ZERO };
    if let Ok(client) = ChainClient::connect("http://127.0.0.1:1", deployment).await {
        let err = client.is_grant_valid_offline(fid("x"), Duration::from_secs(60)).await.unwrap_err();
        assert!(err.is_unreachable(), "{err}");
    }
}

// ------------------------------------------------------------------ events

/// T20/T16: a revoke reaches the agent through the chain even if the relay never delivers one.
#[tokio::test]
async fn t20_the_watcher_sees_a_revoke_without_the_relay() {
    if !ready("t20_the_watcher_sees_a_revoke_without_the_relay") {
        return;
    }
    let f = deploy().await;
    let file = fid("watched.docx");
    f.client.register_file(file, fid("header v1")).await.unwrap();

    let start = f.client.block_number().await.unwrap() + 1;
    let mut watcher =
        EventWatcher::new(f.client.provider().clone(), f.deployment.policy, f.deployment.registry, start);

    // a reseal, which the watcher must report so stale versions stop being opened
    f.client.bump_version(file, fid("header v2")).await.unwrap();

    let events = watcher.poll().await.unwrap();
    assert!(
        events.iter().any(|e| matches!(
            e,
            ChainEvent::VersionBumped { file_id, version: 2, .. } if *file_id == file
        )),
        "expected a VersionBumped, got {events:?}"
    );

    // polling again yields nothing new
    assert!(watcher.poll().await.unwrap().is_empty());
}

#[tokio::test]
async fn the_watcher_does_not_skip_a_range_it_failed_to_read() {
    if !ready("the_watcher_does_not_skip_a_range_it_failed_to_read") {
        return;
    }
    let f = deploy().await;
    let before = f.client.block_number().await.unwrap();

    // a watcher pointed at a dead node must not advance past the block it could not read
    let dead = ProviderBuilder::new().connect("http://127.0.0.1:1").await;
    if let Ok(dead) = dead {
        let mut watcher =
            EventWatcher::new(dead.erased(), f.deployment.policy, f.deployment.registry, before);
        assert!(watcher.poll().await.is_err());
        assert_eq!(watcher.next_block(), before, "a failed poll must re-read the same range");
    }
}

#[tokio::test]
async fn a_grant_event_carries_what_a_session_needs() {
    if !ready("a_grant_event_carries_what_a_session_needs") {
        return;
    }
    let f = deploy().await;
    let file = fid("granted.docx");
    let header = fid("header v1");
    f.client.register_file(file, header).await.unwrap();

    // build and sign a grant the way the owner's agent does, then submit it directly
    let signer: PrivateKeySigner = f._anvil.keys()[0].clone().into();
    let provider =
        ProviderBuilder::new().wallet(EthereumWallet::from(signer.clone())).connect(&f.rpc).await.unwrap();
    let policy = AccessPolicy::new(f.deployment.policy, &provider);

    let now = provider.get_block(alloy::eips::BlockId::latest()).await.unwrap().unwrap().header.timestamp;
    let grant = AccessGrantLib::AccessGrant {
        fileId: FixedBytes(file),
        headerHash: FixedBytes(header),
        deviceKeyHash: FixedBytes(fid("bob device")),
        permission: 1,
        notBefore: now,
        expiry: now + 3600,
        maxOpens: 1,
        requestNonce: FixedBytes([7u8; 16]),
        grantNonce: alloy::primitives::U256::ZERO,
    };
    let digest = policy.digestOf(grant.clone()).call().await.unwrap();
    let signature = signer.sign_hash_sync(&digest).unwrap();

    let start = f.client.block_number().await.unwrap() + 1;
    let mut watcher =
        EventWatcher::new(f.client.provider().clone(), f.deployment.policy, f.deployment.registry, start);

    policy.grant(grant, signature.as_bytes().into()).send().await.unwrap().get_receipt().await.unwrap();

    let events = watcher.poll().await.unwrap();
    let granted = events
        .iter()
        .find_map(|e| match e {
            ChainEvent::Granted { grant_id, file_id, permission, expiry } => {
                Some((*grant_id, *file_id, *permission, *expiry))
            }
            _ => None,
        })
        .expect("a Granted event");
    assert_eq!(granted.1, file);
    assert_eq!(granted.2, 1, "ReadOnly");
    assert_eq!(granted.3, now + 3600);

    // and the session can confirm it independently
    assert!(f.client.is_grant_valid(granted.0).await.unwrap());

    // the owner revokes; the watcher reports it and validity flips
    f.client.revoke(granted.0).await.unwrap();
    let events = watcher.poll().await.unwrap();
    assert!(
        events.iter().any(|e| matches!(e, ChainEvent::Revoked { grant_id, .. } if *grant_id == granted.0)),
        "expected a Revoked, got {events:?}"
    );
    assert!(!f.client.is_grant_valid(granted.0).await.unwrap());
}
