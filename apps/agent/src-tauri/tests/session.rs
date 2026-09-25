//! S6 as a whole, headless: [열기] runs the application, the person saves, the file is
//! resealed and the owner told, the application quits, the workspace is gone.
//!
//! The "application" is a shell script that edits the file and exits, so this runs on the
//! Linux CI runner; the same loop drives Word or 메모장 on Windows (docs/windows_checklist.md §4).

#![cfg(all(feature = "demo-signer", unix))]

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpListener;
use zbacs_agent_lib::approve::{answer, next_requests, Answering, DecisionArg, Deployment};
use zbacs_agent_lib::ledger::{Entry, Ledger};
use zbacs_agent_lib::request::{ask, target_of, Asking, Held, Limits, Outcome};
use zbacs_agent_lib::seal::{owner_account, seal_now, OpensArg, PermissionArg, SealRequest, TtlArg};
use zbacs_agent_lib::session::{run_session, End, Running, Update, ViewerSpec};
use zbacs_agent_lib::setup::SetupHost;
use zbacs_auth::setup::{ApprovalStyle, Prepared};
use zbacs_auth::store::{KeyStore, MemoryKeyStore};
use zbacs_auth::{Confirmation, ConfirmationPolicy};
use zbacs_core::Permission;
use zbacs_proto::{device_key_hash, DeviceIdentity};
use zbacs_relay::{router, Relay};
use zbacs_relay_client::{RelayClient, RetryPolicy};
use zbacs_session::State;

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

fn temp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zbacs-session-it-{tag}-{}", std::process::id()));
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
        client,
        key_hash,
    }
}

/// A and B: Alice locks, Bob asks, Alice allows editing.
async fn granted(tag: &str) -> (PathBuf, Machine, Machine, PathBuf, Held) {
    let dir = temp(tag);
    let relay = start_relay().await;
    let alice = machine(&dir.join("alice"), &relay, ApprovalStyle::Biometric);
    let bob = machine(&dir.join("bob"), &relay, ApprovalStyle::ThisDevice);

    let plain = alice.dir.join("notes.txt");
    std::fs::write(&plain, b"first draft").unwrap();
    let request = SealRequest {
        path: plain.display().to_string(),
        permission: PermissionArg::Edit,
        ttl: TtlArg::Hour,
        opens: OpensArg::Unlimited,
    };
    let result = seal_now(&alice.host.owner_keys().unwrap(), &alice.prepared.profile, &request).unwrap();
    alice.ledger.record(&Entry::from_seal(&result, &request)).unwrap();
    let received = bob.dir.join("notes.txt.zbacs");
    std::fs::copy(&result.output, &received).unwrap();

    let alice_side = tokio::spawn(async move {
        let a = alice;
        a.client.announce(None).await.unwrap();
        let owner = owner_account(&a.prepared.profile);
        let mut pending = Vec::new();
        for _ in 0..200 {
            pending = next_requests(&a.client, &owner, &a.ledger).await;
            if !pending.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        let owner_keys = a.host.owner_keys().unwrap();
        let with = Answering {
            signer: a.prepared.signer.as_ref(),
            device_setting: Confirmation::NotRequired,
            owner: &owner_keys,
            ledger: &a.ledger,
            deployment: Deployment::DEV,
            policy: &ConfirmationPolicy::default(),
            recent: &[],
        };
        answer(&a.client, pending.first().unwrap(), DecisionArg::Edit, with).await.unwrap();
        a
    });
    let target = target_of(&received).unwrap();
    let path = received.display().to_string();
    let (outcome, held) = ask(
        &bob.client,
        Asking {
            path: &path,
            target: &target,
            requested: Permission::Edit,
            our_key_hash: bob.key_hash,
            cancel: Arc::new(AtomicBool::new(false)),
            limits: Limits {
                poll: Duration::from_millis(50),
                nudge_after: Duration::from_secs(60),
                give_up_after: Duration::from_secs(10),
            },
        },
        |_| {},
    )
    .await;
    let alice = alice_side.await.unwrap();
    assert!(matches!(outcome, Outcome::Granted { .. }));
    (dir, alice, bob, received, held)
}

/// The scripted application: waits, appends to the file (a save), exits.
fn editor_that_saves_then_quits() -> ViewerSpec {
    ViewerSpec {
        program: Some((
            "sh".into(),
            vec!["-c".into(), "sleep 0.6; printf ' + edited by the viewer' >> \"$0\"; sleep 0.8".into()],
        )),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn s6_open_save_and_quit_reseals_tells_the_owner_and_wipes() {
    let (dir, alice, bob, received, held) = granted("s6").await;
    let keys = bob.host.device_keys().unwrap();
    let phases = Arc::new(Mutex::new(Vec::new()));
    let sink = phases.clone();
    let base = bob.dir.join("sessions");
    let handle = tokio::runtime::Handle::current();
    let client = bob.client;
    let sealed = received.clone();
    let base2 = base.clone();
    let (end, held) = tokio::task::spawn_blocking(move || {
        let running = Running {
            client: &client,
            sealed: &sealed,
            held,
            device: &keys.envelope,
            signer: &keys.signing,
            base: &base2,
            viewer: editor_that_saves_then_quits(),
            cancel: Arc::new(AtomicBool::new(false)),
            outside: Arc::new(|| None),
            audit: None,
        };
        run_session(handle, running, move |u: Update| sink.lock().unwrap().push(u.phase))
    })
    .await
    .unwrap();

    assert_eq!(end, End::Closed);
    assert_eq!(held.session.state(), State::Closed);
    assert_eq!(*phases.lock().unwrap(), vec!["opened", "saved", "resealed", "closed"]);
    assert!(std::fs::read_dir(&base).map(|d| d.count() == 0).unwrap_or(true), "workspace wiped (T09)");

    // the container on Bob's disk is version 2 and Alice's record followed
    let (v2, _) = zbacs_core::inspect(std::fs::File::open(&received).unwrap()).unwrap();
    assert_eq!(v2.body.ver, 2);
    let owner = owner_account(&alice.prepared.profile);
    let mut advanced = false;
    for _ in 0..100 {
        let _ = next_requests(&alice.client, &owner, &alice.ledger).await;
        if alice.ledger.entries()[0].ver == 2 {
            advanced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(advanced, "Alice's record moved to version 2");
    std::fs::remove_dir_all(dir).ok();
}

/// 지금 잠그기 / a revoke while open: the viewer is closed and the workspace wiped at once.
#[tokio::test(flavor = "multi_thread")]
async fn s6_lock_now_and_revoke_end_the_session_immediately() {
    for (tag, revoke) in [("lock", false), ("revoke", true)] {
        let (dir, _alice, bob, received, held) = granted(tag).await;
        let keys = bob.host.device_keys().unwrap();
        let base = bob.dir.join("sessions");
        let cancel = Arc::new(AtomicBool::new(false));
        let outside_state: Arc<Mutex<Option<State>>> = Arc::new(Mutex::new(None));
        let (flag, os) = (cancel.clone(), outside_state.clone());
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if revoke {
                *os.lock().unwrap() = Some(State::Revoked);
            } else {
                flag.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        });
        let phases = Arc::new(Mutex::new(Vec::new()));
        let sink = phases.clone();
        let handle = tokio::runtime::Handle::current();
        let client = bob.client;
        let sealed = received.clone();
        let base2 = base.clone();
        let outside = outside_state.clone();
        let started = std::time::Instant::now();
        let (end, held) = tokio::task::spawn_blocking(move || {
            let running = Running {
                client: &client,
                sealed: &sealed,
                held,
                device: &keys.envelope,
                signer: &keys.signing,
                base: &base2,
                // an application that would stay open for a long time
                viewer: ViewerSpec { program: Some(("sh".into(), vec!["-c".into(), "sleep 30".into()])) },
                cancel,
                outside: Arc::new(move || *outside.lock().unwrap()),
                audit: None,
            };
            run_session(handle, running, move |u: Update| sink.lock().unwrap().push(u.phase))
        })
        .await
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(10), "did not wait for the 30 s viewer");
        if revoke {
            assert_eq!(end, End::Revoked);
            assert_eq!(held.session.state(), State::Revoked);
            assert_eq!(*phases.lock().unwrap(), vec!["opened", "revoked"]);
        } else {
            assert_eq!(end, End::Closed);
            assert_eq!(*phases.lock().unwrap(), vec!["opened", "closed"]);
        }
        assert!(std::fs::read_dir(&base).map(|d| d.count() == 0).unwrap_or(true), "wiped (T09/T20)");
        std::fs::remove_dir_all(dir).ok();
    }
}
