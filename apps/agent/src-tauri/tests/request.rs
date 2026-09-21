//! Z-1.G.9 DoD — asking really reaches an owner through a relay, and the answer really ends the
//! wait the right way.
//!
//! A real `zbacs-relay` runs on a free port. The recipient side is the Agent's own code path
//! ([`ask`]); the owner side is a small stand-in that reads the owner inbox and answers, which
//! is what the desktop approval screen (Z-1.G.10) will do for real.

#![cfg(feature = "demo-signer")]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpListener;
use zbacs_agent_lib::request::{ask, target_of, Asking, Limits, Outcome, Target, Update};
use zbacs_agent_lib::setup::SetupHost;
use zbacs_auth::setup::ApprovalStyle;
use zbacs_auth::store::{KeyStore, MemoryKeyStore};
use zbacs_core::Permission;
use zbacs_proto::{device_key_hash, AccessGrantTerms, AccessRequest, DeviceIdentity, GrantMsg, Signed};
use zbacs_relay::{router, Relay};
use zbacs_relay_client::{RelayClient, RetryPolicy};
use zbacs_session::State;

const OWNER: &[u8] = b"eip155:84532:alice";

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

fn quick() -> Limits {
    Limits {
        poll: Duration::from_millis(50),
        nudge_after: Duration::from_millis(300),
        give_up_after: Duration::from_secs(5),
    }
}

fn temp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zbacs-request-it-{tag}-{}", std::process::id()));
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

/// A set-up recipient machine: its relay client, its key hash and a sealed file to ask about.
struct Recipient {
    client: RelayClient,
    key_hash: [u8; 32],
    path: String,
    target: Target,
}

fn recipient(dir: &Path, relay: &str, default: Permission) -> Recipient {
    let store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let host = SetupHost::with_store(dir.join("config"), store, true);
    let prepared = host.complete(ApprovalStyle::ThisDevice, now()).expect("setup");
    let keys = host.device_keys().expect("device keys");
    let device = DeviceIdentity { keys: keys.envelope, signing: keys.signing };
    let key_hash = device_key_hash(&prepared.profile.device_x25519_pub, &prepared.profile.device_ed25519_pub);

    // the file the recipient received: sealed by some owner, default permission as given
    let plain = dir.join("brief.txt");
    let sealed = dir.join("brief.txt.zbacs");
    std::fs::write(&plain, b"for the meeting").unwrap();
    let owner = zbacs_core::OwnerKeys::generate().unwrap();
    let mut opts = zbacs_core::SealOptions::new(OWNER, "brief.txt");
    opts.policy = zbacs_core::Policy { default, ..Default::default() };
    zbacs_core::seal_to_path(&plain, &sealed, &owner, &opts).unwrap();

    let policy = RetryPolicy {
        attempts_per_endpoint: 2,
        initial_backoff: Duration::from_millis(20),
        ..Default::default()
    };
    let client = RelayClient::with_policy(vec![relay.to_string()], device, policy).unwrap();
    let target = target_of(&sealed).unwrap();
    Recipient { client, key_hash, path: sealed.display().to_string(), target }
}

/// The owner's side, as Z-1.G.10 will do it: read the request, answer by its nonce.
async fn owner_answers(
    relay: String,
    decision: u8,
    terms_for: impl Fn(&AccessRequest) -> Option<AccessGrantTerms> + Send + 'static,
) {
    let owner = DeviceIdentity::generate().unwrap();
    let client = RelayClient::new(vec![relay], owner).unwrap();
    client.announce(Some("owner-laptop")).await.unwrap();
    for _ in 0..100 {
        let inbox = client.inbox_for_owner(OWNER).await.unwrap();
        if let Some(envelope) = inbox.first() {
            let signed = Signed::from_bytes(&envelope.body).unwrap();
            let request: AccessRequest = ciborium::from_reader(signed.payload.as_slice()).unwrap();
            let grant = GrantMsg {
                request_nonce: request.nonce,
                grant: terms_for(&request).map(|t| t.to_cbor().unwrap()),
                owner_sig: None,
                envelope: if decision == 0 { None } else { Some(vec![0xEE; 48]) },
                tx_hash: None,
                decision,
                ts: now(),
            };
            client.send_grant(&grant).await.unwrap();
            return;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    panic!("the owner never saw a request");
}

fn terms(request: &AccessRequest, device_key_hash: [u8; 32], permission: u8) -> AccessGrantTerms {
    AccessGrantTerms {
        file_id: request.fid,
        header_hash: request.header_hash,
        device_key_hash,
        permission,
        not_before: now() - 5,
        expiry: now() + 3600,
        max_opens: 1,
        request_nonce: request.nonce,
        grant_nonce: 0,
    }
}

fn collect() -> (Arc<Mutex<Vec<&'static str>>>, impl FnMut(Update)) {
    let phases = Arc::new(Mutex::new(Vec::new()));
    let sink = phases.clone();
    (phases, move |u: Update| sink.lock().unwrap().push(u.phase))
}

#[tokio::test(flavor = "multi_thread")]
async fn the_owner_allows_and_the_session_is_granted() {
    let dir = temp("granted");
    let relay = start_relay().await;
    let r = recipient(&dir, &relay, Permission::ReadOnly);
    let key_hash = r.key_hash;
    tokio::spawn(owner_answers(relay.clone(), 1, move |req| Some(terms(req, key_hash, 1))));

    let (phases, sink) = collect();
    let (outcome, held) = ask(
        &r.client,
        Asking {
            path: &r.path,
            target: &r.target,
            requested: Permission::ReadOnly,
            our_key_hash: r.key_hash,
            cancel: Arc::new(AtomicBool::new(false)),
            limits: quick(),
        },
        sink,
    )
    .await;

    assert!(matches!(outcome, Outcome::Granted { permission: Permission::ReadOnly, .. }), "{outcome:?}");
    assert_eq!(held.session.state(), State::Granted);
    assert_eq!(held.session.permission(), Some(Permission::ReadOnly));
    assert!(held.envelope.is_some(), "the DEK envelope is kept for the open step");
    assert_eq!(held.terms.as_ref().map(|t| t.file_id), Some(r.target.fid));
    assert_eq!(*phases.lock().unwrap(), vec!["sent", "granted"]);
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_owner_refuses_and_the_session_is_denied() {
    let dir = temp("denied");
    let relay = start_relay().await;
    let r = recipient(&dir, &relay, Permission::Edit);
    tokio::spawn(owner_answers(relay.clone(), 0, |_| None));

    let (phases, sink) = collect();
    let (outcome, held) = ask(
        &r.client,
        Asking {
            path: &r.path,
            target: &r.target,
            requested: Permission::Edit,
            our_key_hash: r.key_hash,
            cancel: Arc::new(AtomicBool::new(false)),
            limits: quick(),
        },
        sink,
    )
    .await;

    assert_eq!(outcome, Outcome::Denied);
    assert_eq!(held.session.state(), State::Denied);
    assert!(held.envelope.is_none());
    assert_eq!(*phases.lock().unwrap(), vec!["sent", "denied"]);
    std::fs::remove_dir_all(dir).ok();
}

/// T05: an answer whose terms name another device is refused, not opened.
#[tokio::test(flavor = "multi_thread")]
async fn t05_a_grant_aimed_at_another_device_is_refused() {
    let dir = temp("swap");
    let relay = start_relay().await;
    let r = recipient(&dir, &relay, Permission::ReadOnly);
    tokio::spawn(owner_answers(relay.clone(), 1, |req| Some(terms(req, [0x42; 32], 1))));

    let (phases, sink) = collect();
    let (outcome, held) = ask(
        &r.client,
        Asking {
            path: &r.path,
            target: &r.target,
            requested: Permission::ReadOnly,
            our_key_hash: r.key_hash,
            cancel: Arc::new(AtomicBool::new(false)),
            limits: quick(),
        },
        sink,
    )
    .await;

    assert_eq!(outcome, Outcome::Failed("mismatch"));
    assert_eq!(held.session.state(), State::Failed);
    assert!(held.envelope.is_none(), "nothing from a mismatched grant is kept");
    assert_eq!(*phases.lock().unwrap(), vec!["sent", "failed"]);
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn no_answer_nudges_then_gives_up() {
    let dir = temp("expired");
    let relay = start_relay().await;
    let r = recipient(&dir, &relay, Permission::ReadOnly);
    let limits = Limits {
        poll: Duration::from_millis(30),
        nudge_after: Duration::from_millis(150),
        give_up_after: Duration::from_millis(600),
    };

    let (phases, sink) = collect();
    let (outcome, held) = ask(
        &r.client,
        Asking {
            path: &r.path,
            target: &r.target,
            requested: Permission::ReadOnly,
            our_key_hash: r.key_hash,
            cancel: Arc::new(AtomicBool::new(false)),
            limits,
        },
        sink,
    )
    .await;

    assert_eq!(outcome, Outcome::Expired);
    assert_eq!(held.session.state(), State::Closed, "an unanswered request closes the session cleanly");
    assert_eq!(*phases.lock().unwrap(), vec!["sent", "nudge", "expired"]);
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_person_can_stop_waiting() {
    let dir = temp("cancel");
    let relay = start_relay().await;
    let r = recipient(&dir, &relay, Permission::ReadOnly);
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(120)).await;
        flag.store(true, Ordering::Relaxed);
    });

    let (phases, sink) = collect();
    let (outcome, _) = ask(
        &r.client,
        Asking {
            path: &r.path,
            target: &r.target,
            requested: Permission::ReadOnly,
            our_key_hash: r.key_hash,
            cancel,
            limits: quick(),
        },
        sink,
    )
    .await;

    assert_eq!(outcome, Outcome::Cancelled);
    assert_eq!(*phases.lock().unwrap(), vec!["sent", "cancelled"]);
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn no_relay_is_reported_not_hung() {
    let dir = temp("norelay");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let r = recipient(&dir, &dead, Permission::ReadOnly);

    let (phases, sink) = collect();
    let (outcome, _) = ask(
        &r.client,
        Asking {
            path: &r.path,
            target: &r.target,
            requested: Permission::ReadOnly,
            our_key_hash: r.key_hash,
            cancel: Arc::new(AtomicBool::new(false)),
            limits: quick(),
        },
        sink,
    )
    .await;

    assert_eq!(outcome, Outcome::Failed("relay_unreachable"));
    assert_eq!(*phases.lock().unwrap(), vec!["failed"]);
    std::fs::remove_dir_all(dir).ok();
}
