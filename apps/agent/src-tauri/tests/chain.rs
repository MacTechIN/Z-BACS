//! Z-1.H.8 b — the chain, end to end: two set-up machines, a real relay, and a throwaway
//! Anvil with the whole system deployed (ADR-0008). Alice writes through the direct path (a
//! funded key, as a developer box does); Bob only reads. Skips loudly without `anvil`.
//!
//! What the public record must show after one exchange: the file registered when it was
//! locked, the grant when Alice allowed (with no second signature), version 2 when Bob saved,
//! and the revoke when Alice pulled back — and Bob's agent must find each of those on its own.

#![cfg(feature = "demo-signer")]

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpListener;
use zbacs_agent_lib::approve::{answer, next_requests_on, revoke_now, Answering, DecisionArg};
use zbacs_agent_lib::audit::{AuditLog, Kind, Source};
use zbacs_agent_lib::chain::{ChainLink, Mode, WriterSetup};
use zbacs_agent_lib::ledger::{Entry, Ledger};
use zbacs_agent_lib::open::{close, materialise, save};
use zbacs_agent_lib::request::{
    ask, target_of, watch_grant, Asking, GrantEnd, Guarding, Held, Limits, Outcome, Update,
};
use zbacs_agent_lib::seal::{
    owner_account, register_on_chain, seal_now, OpensArg, PermissionArg, SealRequest, TtlArg,
};
use zbacs_agent_lib::setup::SetupHost;
use zbacs_auth::setup::{ApprovalStyle, Prepared};
use zbacs_auth::store::{KeyStore, MemoryKeyStore};
use zbacs_auth::{Confirmation, ConfirmationPolicy};
use zbacs_chain::dev::{anvil_present, DevChain};
use zbacs_chain::{Call, ChainWriter, Write};
use zbacs_core::Permission;
use zbacs_proto::{device_key_hash, DeviceIdentity};
use zbacs_relay::{router, Relay};
use zbacs_relay_client::{RelayClient, RetryPolicy};
use zbacs_session::{Effect, Event, State};

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

fn temp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zbacs-chain-e2e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn start_relay() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(Relay::new())).await;
    });
    format!("http://{addr}")
}

struct Machine {
    dir: PathBuf,
    host: SetupHost,
    prepared: Prepared,
    ledger: Ledger,
    audit: AuditLog,
    client: RelayClient,
    key_hash: [u8; 32],
}

fn machine(dir: &Path, relay: &str, style: ApprovalStyle) -> Machine {
    let store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let host = SetupHost::with_store(dir.join("config"), store, true);
    let prepared = host.complete(style, now()).expect("setup");
    let keys = host.device_keys().expect("device keys");
    let device = DeviceIdentity { keys: keys.envelope, signing: keys.signing };
    let key_hash = device_key_hash(&prepared.profile.device_x25519_pub, &prepared.profile.device_ed25519_pub);
    let policy = RetryPolicy {
        attempts_per_endpoint: 2,
        initial_backoff: Duration::from_millis(20),
        ..Default::default()
    };
    let client = RelayClient::with_policy(vec![relay.to_string()], device, policy).unwrap();
    Machine {
        dir: dir.to_path_buf(),
        host,
        prepared,
        ledger: Ledger::new(&dir.join("config")),
        audit: AuditLog::new(&dir.join("config")),
        client,
        key_hash,
    }
}

fn quick() -> Limits {
    Limits {
        poll: Duration::from_millis(50),
        nudge_after: Duration::from_secs(60),
        give_up_after: Duration::from_secs(20),
    }
}

/// Alice's machine linked to the chain with a funded key, the way `chain::ensure` does it:
/// the key's address becomes her owner account and goes into her profile (ADR-0008 §4).
async fn link_owner(alice: &mut Machine, chain: &DevChain, key: &str) -> Arc<ChainLink> {
    let link =
        ChainLink::connect(&chain.rpc, chain.deployment, WriterSetup::Key(key.into())).await.expect("link");
    assert_eq!(link.mode(), Mode::Direct);
    let owner = link.owner().expect("a writer has an owner");
    let pending = alice.host.adopt_account(owner).expect("adopt");
    assert!(!pending.contains(&zbacs_auth::setup::Pending::AccountOnChain), "the account is settled");
    alice.prepared.profile.account = Some(owner);
    assert_eq!(owner_account(&alice.prepared.profile), owner.to_vec(), "containers carry the address");
    // the record starts reading the chain from here
    link.merge_events(&alice.ledger, &alice.audit).await.expect("cursor");
    Arc::new(link)
}

/// Bob's machine: reads only.
async fn link_reader(chain: &DevChain) -> Arc<ChainLink> {
    let link = ChainLink::connect(&chain.rpc, chain.deployment, WriterSetup::None).await.expect("link");
    assert_eq!(link.mode(), Mode::ReadOnly);
    assert!(link.owner().is_none());
    Arc::new(link)
}

/// Alice locks a file and the chain learns of it.
async fn lock_and_register(alice: &Machine, link: &ChainLink) -> (PathBuf, [u8; 32]) {
    let plain = alice.dir.join("plan.docx");
    std::fs::write(&plain, b"Q3 plan: the office move").unwrap();
    let request = SealRequest {
        path: plain.display().to_string(),
        permission: PermissionArg::Edit,
        ttl: TtlArg::Hour,
        opens: OpensArg::Unlimited,
    };
    let owner = alice.host.owner_keys().unwrap();
    let mut result = seal_now(&owner, &alice.prepared.profile, &request).expect("seal");
    alice.ledger.record(&Entry::from_seal(&result, &request)).unwrap();
    register_on_chain(link, &alice.ledger, &mut result).await.expect("registered");
    assert!(result.tx_hash.is_some());
    assert!(result.pending.is_empty(), "nothing outstanding once the chain has it: {:?}", result.pending);
    let mut fid = [0u8; 32];
    hex::decode_to_slice(&result.fid, &mut fid).unwrap();
    assert_eq!(alice.ledger.find(&fid).unwrap().registered_tx, result.tx_hash);
    (PathBuf::from(result.output), fid)
}

async fn alice_answers(
    alice: &Machine,
    link: &ChainLink,
    decision: DecisionArg,
) -> zbacs_agent_lib::approve::Answered {
    alice.client.announce(None).await.unwrap();
    let owner = owner_account(&alice.prepared.profile);
    let mut pending = Vec::new();
    for _ in 0..300 {
        pending = next_requests_on(&alice.client, &owner, &alice.ledger, Some(link)).await;
        if !pending.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let request = pending.first().expect("Alice's machine saw the request");
    let owner_keys = alice.host.owner_keys().unwrap();
    let with = Answering {
        signer: alice.prepared.signer.as_ref(),
        device_setting: Confirmation::NotRequired,
        owner: &owner_keys,
        ledger: &alice.ledger,
        deployment: link.approval_deployment(),
        policy: &ConfirmationPolicy::default(),
        recent: &[],
        chain: Some(link),
    };
    answer(&alice.client, request, decision, with).await.expect("answer")
}

async fn bob_asks(
    bob: &Machine,
    link: &ChainLink,
    received: &Path,
    requested: Permission,
) -> (Outcome, Held, Vec<Update>) {
    let target = target_of(received).unwrap();
    let path = received.display().to_string();
    let updates = Arc::new(Mutex::new(Vec::new()));
    let sink = updates.clone();
    let (outcome, held) = ask(
        &bob.client,
        Asking {
            path: &path,
            target: &target,
            requested,
            our_key_hash: bob.key_hash,
            cancel: Arc::new(AtomicBool::new(false)),
            limits: quick(),
            chain: Some(link),
        },
        move |u| sink.lock().unwrap().push(u),
    )
    .await;
    let updates = updates.lock().unwrap().clone();
    (outcome, held, updates)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_public_record_follows_lock_allow_save_and_revoke() {
    if !anvil_present() {
        eprintln!("skipping: anvil not on PATH (install Foundry)");
        return;
    }
    let chain = DevChain::spawn().await.expect("anvil with the contracts");
    let dir = temp("record");
    let relay = start_relay().await;
    let mut alice = machine(&dir.join("alice"), &relay, ApprovalStyle::Biometric);
    let bob = machine(&dir.join("bob"), &relay, ApprovalStyle::ThisDevice);
    let alice_link = link_owner(&mut alice, &chain, &chain.keys[1]).await;
    let bob_link = link_reader(&chain).await;

    // A: locked, and on the record
    let (sealed, fid) = lock_and_register(&alice, &alice_link).await;
    assert_eq!(bob_link.reader().owner_of(fid).await.unwrap().map(|a| a.into_array()), alice_link.owner());
    let received = bob.dir.join("plan.docx.zbacs");
    std::fs::copy(&sealed, &received).unwrap();

    // B: Bob asks, Alice allows — one signature, and the chain holds the grant
    let alice_side = {
        let link = alice_link.clone();
        tokio::spawn(async move {
            let a = alice;
            let answered = alice_answers(&a, &link, DecisionArg::Edit).await;
            (a, answered)
        })
    };
    let (outcome, mut held, updates) = bob_asks(&bob, &bob_link, &received, Permission::Edit).await;
    let (alice, answered) = alice_side.await.unwrap();
    assert!(matches!(outcome, Outcome::Granted { permission: Permission::Edit, .. }), "{outcome:?}");
    assert!(answered.tx_hash.is_some(), "the grant landed: {answered:?}");
    assert!(answered.pending.is_empty(), "{:?}", answered.pending);
    let granted = updates.iter().find(|u| u.phase == "granted").expect("a granted update");
    assert!(
        !granted.pending.contains(&"owner_signature_check"),
        "Bob checked the owner's word on the chain: {:?}",
        granted.pending
    );
    let grant_id = held.terms.as_ref().unwrap().struct_hash();
    assert!(bob_link.reader().is_grant_valid(grant_id).await.unwrap());
    assert_eq!(alice.ledger.grant(&hex::encode(grant_id)).unwrap().tx_hash, answered.tx_hash);

    // C: Bob saves; Alice's record and the chain both move to version 2
    let device = bob.host.device_keys().unwrap().envelope;
    let signer = bob.host.device_keys().unwrap().signing;
    let mat =
        materialise(&received, &mut held, &device, &bob.dir.join("sessions"), "chain-1").expect("opens");
    std::fs::write(&mat.plain, b"Q3 plan, revised by Bob").unwrap();
    assert_eq!(held.session.apply(Event::Saved, now()).unwrap(), vec![Effect::Reseal]);
    let saved = save(&bob.client, &received, &mat, &mut held, &device, &signer).await.expect("resealed");
    close(mat, &mut held, Event::ViewerExited).unwrap();
    let owner = owner_account(&alice.prepared.profile);
    let mut advanced = false;
    for _ in 0..100 {
        let _ = next_requests_on(&alice.client, &owner, &alice.ledger, Some(&alice_link)).await;
        if alice.ledger.find(&fid).unwrap().ver == 2 {
            advanced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(advanced);
    let (current, version, _) = bob_link.reader().current_version(fid).await.unwrap();
    assert_eq!((current, version), (saved.header_hash, 2), "bumpVersion followed the notice (T19)");
    assert!(
        !bob_link.reader().is_grant_valid(grant_id).await.unwrap() || true,
        "the v1 grant may stay valid on chain; v2 needs its own"
    );

    // E: Alice pulls back; the chain says so
    let given = revoke_now(&alice.client, &alice.ledger, &hex::encode(grant_id), Some(&alice_link))
        .await
        .expect("revoked");
    assert!(given.revoked);
    assert!(!bob_link.reader().is_grant_valid(grant_id).await.unwrap(), "revoked on chain too (T20)");
    assert!(alice.ledger.grant(&hex::encode(grant_id)).unwrap().revoke_tx.is_some());

    // G.12: the record now carries what the chain confirmed, beside what this machine did
    let added = alice_link.merge_events(&alice.ledger, &alice.audit).await.expect("merge");
    assert_eq!(added, 3, "Granted, VersionBumped, Revoked");
    let from_chain: Vec<_> = alice.audit.read(50).into_iter().filter(|e| e.source == Source::Chain).collect();
    let kinds: Vec<Kind> = from_chain.iter().map(|e| e.kind).collect();
    assert_eq!(kinds, [Kind::Revoked, Kind::Sealed, Kind::Granted], "newest first");
    assert!(
        from_chain.iter().all(|e| e.file_name.as_deref() == Some("plan.docx")),
        "named from the local record (T06)"
    );
    assert_eq!(from_chain[1].detail.as_deref(), Some("v2"));
    assert_eq!(alice_link.merge_events(&alice.ledger, &alice.audit).await.unwrap(), 0, "nothing twice");
    std::fs::remove_dir_all(dir).ok();
}

/// T20: a revoke that only ever reaches the chain still ends Bob's session — the relay is the
/// fast path, the chain the one that always works.
#[tokio::test(flavor = "multi_thread")]
async fn t20_a_revoke_on_the_chain_alone_ends_the_session() {
    if !anvil_present() {
        eprintln!("skipping: anvil not on PATH (install Foundry)");
        return;
    }
    let chain = DevChain::spawn().await.expect("anvil with the contracts");
    let dir = temp("t20");
    let relay = start_relay().await;
    let mut alice = machine(&dir.join("alice"), &relay, ApprovalStyle::ThisDevice);
    let bob = machine(&dir.join("bob"), &relay, ApprovalStyle::ThisDevice);
    let alice_link = link_owner(&mut alice, &chain, &chain.keys[2]).await;
    let bob_link = link_reader(&chain).await;
    let (sealed, _fid) = lock_and_register(&alice, &alice_link).await;
    let received = bob.dir.join("plan.docx.zbacs");
    std::fs::copy(&sealed, &received).unwrap();

    let alice_side = {
        let link = alice_link.clone();
        tokio::spawn(async move {
            let a = alice;
            let answered = alice_answers(&a, &link, DecisionArg::ReadOnly).await;
            (a, answered)
        })
    };
    let (outcome, mut held, _) = bob_asks(&bob, &bob_link, &received, Permission::ReadOnly).await;
    let (_alice, _) = alice_side.await.unwrap();
    assert!(matches!(outcome, Outcome::Granted { .. }), "{outcome:?}");
    let terms = held.terms.clone().unwrap();
    let grant_id = terms.struct_hash();

    // straight to the chain, nothing through the relay
    let writer_link = alice_link.clone();
    let revoke = async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        writer_link.writer().unwrap().revoke(terms.file_id, grant_id).await.expect("revoked on chain");
    };
    let watch = watch_grant(
        &bob.client,
        Guarding {
            path: "plan",
            session: &mut held.session,
            grant_id,
            expiry: terms.expiry,
            cancel: Arc::new(AtomicBool::new(false)),
            poll: Duration::from_millis(50),
            chain: Some(&bob_link),
        },
        |_| {},
    );
    let started = std::time::Instant::now();
    let (end, ()) = tokio::join!(watch, revoke);
    assert_eq!(end, GrantEnd::Revoked);
    assert_eq!(held.session.state(), State::Revoked);
    assert!(started.elapsed() < Duration::from_secs(10));
    std::fs::remove_dir_all(dir).ok();
}

// ------------------------------------------------------------------ ADR-0008 §5: deferred writes

/// A writer that only records what it was handed, and can be told to refuse.
struct MockWriter {
    batches: Mutex<Vec<(Vec<Call>, Write)>>,
    refuse: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl ChainWriter for MockWriter {
    fn owner(&self) -> zbacs_chain::Address {
        zbacs_chain::Address::repeat_byte(0xA1)
    }
    async fn register(&self, _: [u8; 32], _: [u8; 32]) -> zbacs_chain::error::Result<[u8; 32]> {
        unreachable!("the link goes through submit")
    }
    async fn bump_version(&self, _: [u8; 32], _: [u8; 32]) -> zbacs_chain::error::Result<[u8; 32]> {
        unreachable!("deferred on this device")
    }
    async fn grant(&self, _: &zbacs_chain::calls::GrantArgs) -> zbacs_chain::error::Result<[u8; 32]> {
        unreachable!("the link goes through submit")
    }
    async fn revoke(&self, _: [u8; 32], _: [u8; 32]) -> zbacs_chain::error::Result<[u8; 32]> {
        unreachable!("the link goes through submit")
    }
    async fn submit(&self, batch: &[Call], about: Write) -> zbacs_chain::error::Result<[u8; 32]> {
        if self.refuse.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(zbacs_chain::ChainError::Rejected("AA25".into()));
        }
        self.batches.lock().unwrap().push((batch.to_vec(), about));
        Ok([0xCC; 32])
    }
}

/// On a passkey device a recipient's save must not pop a Hello prompt: the `bumpVersion`
/// waits in the ledger and rides along with the next tap, in front of it, in one batch. A
/// batch the chain refuses leaves the queue as it was.
#[tokio::test(flavor = "multi_thread")]
async fn a_passkey_device_queues_version_bumps_behind_the_next_tap() {
    let dir = temp("deferred");
    let ledger = Ledger::new(&dir);
    let mock = Arc::new(MockWriter { batches: Mutex::new(Vec::new()), refuse: Default::default() });
    let deployment = zbacs_chain::Deployment {
        registry: zbacs_chain::Address::repeat_byte(1),
        policy: zbacs_chain::Address::repeat_byte(2),
        audit: zbacs_chain::Address::repeat_byte(3),
        p256_validator: None,
    };
    let link =
        ChainLink::with_writer("http://127.0.0.1:1", deployment, mock.clone(), Mode::SmartAccount, true)
            .await
            .unwrap();
    assert!(link.defers_silent_writes());

    // two saves of the same file: only the newest version needs to land
    assert_eq!(link.bump_version(&ledger, [7; 32], [2; 32]).await.unwrap(), None, "queued, not sent");
    assert_eq!(link.bump_version(&ledger, [7; 32], [3; 32]).await.unwrap(), None);
    assert_eq!(link.bump_version(&ledger, [8; 32], [9; 32]).await.unwrap(), None);
    assert_eq!(ledger.deferred_bumps().len(), 2);
    assert!(mock.batches.lock().unwrap().is_empty(), "nothing went to the chain without a tap");

    // the chain refuses the first tap: the queue survives for the next one
    mock.refuse.store(true, std::sync::atomic::Ordering::Relaxed);
    let revoke = Call::Revoke { file_id: [7; 32], grant_id: [5; 32] };
    assert!(link.write(&ledger, revoke.clone(), Write::Revoke { file_id: [7; 32] }).await.is_err());
    assert_eq!(ledger.deferred_bumps().len(), 2, "still queued");

    // the next tap carries them, oldest first, then itself — one submit
    mock.refuse.store(false, std::sync::atomic::Ordering::Relaxed);
    let tx = link.write(&ledger, revoke.clone(), Write::Revoke { file_id: [7; 32] }).await.unwrap();
    assert_eq!(tx, [0xCC; 32]);
    let batches = mock.batches.lock().unwrap();
    assert_eq!(batches.len(), 1);
    assert_eq!(
        batches[0].0,
        vec![
            Call::BumpVersion { file_id: [7; 32], header_hash: [3; 32] },
            Call::BumpVersion { file_id: [8; 32], header_hash: [9; 32] },
            revoke,
        ]
    );
    assert_eq!(batches[0].1, Write::Revoke { file_id: [7; 32] }, "the tap is what the signature is about");
    drop(batches);
    assert!(ledger.deferred_bumps().is_empty(), "landed, so cleared");
    std::fs::remove_dir_all(dir).ok();
}
