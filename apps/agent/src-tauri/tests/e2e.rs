//! Z-1.Q.1 — the E2E harness: scenarios A~E of project_definition §6, run between two set-up
//! machines through a real relay, headless.
//!
//! "Two machines" are two `SetupHost`s in two config directories with the software signer
//! (Windows Hello stands in are the only difference from the real thing — the checklist in
//! docs/windows_checklist.md covers that). The relay is the real `zbacs-relay`. The chain is
//! not written yet (Z-1.H.8), so nothing here asserts on it.
//!
//! Each scenario is one test, so a failure names the scenario. What the product cannot do
//! yet is marked `#[ignore]` with the task that unblocks it, so the count of ignored tests is
//! the honest distance to the MVP DoD.

#![cfg(feature = "demo-signer")]

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use zbacs_agent_lib::approve::{answer, next_requests, revoke_now, Answering, DecisionArg, Deployment};
use zbacs_agent_lib::ledger::{Entry, Ledger};
use zbacs_agent_lib::open::{close, materialise, save};
use zbacs_agent_lib::request::{
    ask, target_of, watch_grant, Asking, GrantEnd, Guarding, Held, Limits, Outcome,
};
use zbacs_agent_lib::seal::{owner_account, seal_now, OpensArg, PermissionArg, SealRequest, TtlArg};
use zbacs_agent_lib::setup::SetupHost;
use zbacs_auth::setup::{ApprovalStyle, Prepared};
use zbacs_auth::store::{KeyStore, MemoryKeyStore};
use zbacs_auth::{Confirmation, ConfirmationPolicy};
use zbacs_core::Permission;
use zbacs_proto::{device_key_hash, DeviceIdentity};
use zbacs_relay::{router, Relay};
use zbacs_relay_client::{RelayClient, RetryPolicy};
use zbacs_session::{Effect, Event, State};

const TEXT: &[u8] = b"Q3 plan: hire two, ship the beta, do not tell anyone about the office move";

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

fn temp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zbacs-e2e-{tag}-{}", std::process::id()));
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

/// One set-up PC.
struct Machine {
    dir: PathBuf,
    host: SetupHost,
    prepared: Prepared,
    ledger: Ledger,
    client: RelayClient,
    key_hash: [u8; 32],
}

fn machine(dir: &Path, relay: &str) -> Machine {
    machine_with(dir, relay, ApprovalStyle::ThisDevice)
}

/// A PC set up with the given approval style. The software stand-ins mirror the real ones:
/// `Biometric` can put an OS prompt in front of the key, `ThisDevice` cannot — so an Edit
/// approval (which T23 always confirms) needs `Biometric` here, as it needs Hello on Windows.
fn machine_with(dir: &Path, relay: &str, style: ApprovalStyle) -> Machine {
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

fn quick() -> Limits {
    Limits {
        poll: Duration::from_millis(50),
        nudge_after: Duration::from_secs(60),
        give_up_after: Duration::from_secs(10),
    }
}

/// Scenario A on Alice's machine: lock, record, and (as the person may) erase the original.
fn scenario_a(alice: &Machine, permission: PermissionArg, opens: OpensArg) -> PathBuf {
    let plain = alice.dir.join("plan.docx");
    std::fs::write(&plain, TEXT).unwrap();
    let request = SealRequest { path: plain.display().to_string(), permission, ttl: TtlArg::Hour, opens };
    let owner = alice.host.owner_keys().unwrap();
    let result = seal_now(&owner, &alice.prepared.profile, &request).expect("seal");
    alice.ledger.record(&Entry::from_seal(&result, &request)).unwrap();
    zbacs_session::secure_delete(&plain).unwrap();
    PathBuf::from(result.output)
}

fn bob_receives(sealed: &Path, bob: &Machine) -> PathBuf {
    let copy = bob.dir.join("plan.docx.zbacs");
    std::fs::copy(sealed, &copy).unwrap();
    copy
}

/// Alice's side of scenario B: see the request (from her own record), answer it.
async fn alice_answers(alice: &Machine, decision: DecisionArg) -> zbacs_agent_lib::approve::Answered {
    alice.client.announce(None).await.unwrap();
    let owner = owner_account(&alice.prepared.profile);
    let mut pending = Vec::new();
    for _ in 0..200 {
        pending = next_requests(&alice.client, &owner, &alice.ledger).await;
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
        deployment: Deployment::DEV,
        policy: &ConfirmationPolicy::default(),
        recent: &[],
    };
    answer(&alice.client, request, decision, with).await.expect("answer")
}

/// Bob's side of scenario B: ask and wait.
async fn bob_asks(bob: &Machine, received: &Path, requested: Permission) -> (Outcome, Held) {
    let target = target_of(received).unwrap();
    let path = received.display().to_string();
    ask(
        &bob.client,
        Asking {
            path: &path,
            target: &target,
            requested,
            our_key_hash: bob.key_hash,
            cancel: Arc::new(AtomicBool::new(false)),
            limits: quick(),
        },
        |_| {},
    )
    .await
}

/// A and B together, the way every later scenario starts.
async fn granted(
    tag: &str,
    permission: PermissionArg,
    opens: OpensArg,
    decision: DecisionArg,
) -> (PathBuf, Machine, Machine, PathBuf, Held) {
    let dir = temp(tag);
    let relay = start_relay().await;
    let style =
        if decision == DecisionArg::Edit { ApprovalStyle::Biometric } else { ApprovalStyle::ThisDevice };
    let alice = machine_with(&dir.join("alice"), &relay, style);
    let bob = machine(&dir.join("bob"), &relay);
    let sealed = scenario_a(&alice, permission, opens);
    let received = bob_receives(&sealed, &bob);
    let requested = if decision == DecisionArg::Edit { Permission::Edit } else { Permission::ReadOnly };
    let alice_side = tokio::spawn(async move {
        let a = alice;
        let answered = alice_answers(&a, decision).await;
        (a, answered)
    });
    let (outcome, held) = bob_asks(&bob, &received, requested).await;
    let (alice, _) = alice_side.await.unwrap();
    assert!(matches!(outcome, Outcome::Granted { .. }), "{outcome:?}");
    (dir, alice, bob, received, held)
}

// ================================================================ A

#[tokio::test(flavor = "multi_thread")]
async fn scenario_a_seal_leaves_only_ciphertext_and_a_record() {
    let dir = temp("a");
    let relay = start_relay().await;
    let alice = machine(&dir.join("alice"), &relay);
    let sealed = scenario_a(&alice, PermissionArg::ReadOnly, OpensArg::Once);

    assert!(sealed.exists() && !alice.dir.join("plan.docx").exists(), "original erased, container present");
    let bytes = std::fs::read(&sealed).unwrap();
    assert!(!bytes.windows(8).any(|w| w == &TEXT[..8]), "the container carries no plaintext");
    assert!(!bytes.windows(9).any(|w| w == b"plan.docx"), "nor the file name");
    let entries = alice.ledger.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "plan.docx");
    assert_eq!(entries[0].permission, "read_only");
    std::fs::remove_dir_all(dir).ok();
}

// ================================================================ B

#[tokio::test(flavor = "multi_thread")]
async fn scenario_b_request_and_approval_round_trip() {
    let (dir, alice, bob, _received, held) =
        granted("b", PermissionArg::ReadOnly, OpensArg::Once, DecisionArg::ReadOnly).await;
    assert_eq!(held.session.state(), State::Granted);
    assert_eq!(held.session.permission(), Some(Permission::ReadOnly));
    assert!(held.envelope.is_some());
    // the envelope opens for Bob's device and for nobody else's
    let env: zbacs_core::Envelope =
        ciborium::from_reader(held.envelope.as_ref().unwrap().as_slice()).unwrap();
    let grant_id = held.terms.as_ref().unwrap().struct_hash();
    assert!(env.open(&bob.host.device_keys().unwrap().envelope, &grant_id).is_ok());
    assert!(env.open(&alice.host.device_keys().unwrap().envelope, &grant_id).is_err());
    assert_eq!(alice.ledger.grants(true, now()).len(), 1, "Alice's list shows what she allowed");
    std::fs::remove_dir_all(dir).ok();
}

// ================================================================ D (read-only), then C

#[tokio::test(flavor = "multi_thread")]
async fn scenario_d_read_only_open_discards_changes_and_wipes() {
    let (dir, _alice, bob, received, mut held) =
        granted("d", PermissionArg::ReadOnly, OpensArg::Once, DecisionArg::ReadOnly).await;
    let device = bob.host.device_keys().unwrap().envelope;
    let base = bob.dir.join("sessions");

    let mat = materialise(&received, &mut held, &device, &base, "d-1").expect("opens");
    assert_eq!(held.session.state(), State::Open);
    assert_eq!(mat.name, "plan.docx");
    assert_eq!(std::fs::read(&mat.plain).unwrap(), TEXT, "Bob sees the file");
    assert!(mat.effects.contains(&Effect::MarkReadOnly));
    assert!(std::fs::metadata(&mat.plain).unwrap().permissions().readonly());
    assert!(std::fs::OpenOptions::new().write(true).open(&mat.plain).is_err(), "writes are refused (T07)");

    // an application that defeats the attribute still cannot produce a version
    let effects = held.session.apply(Event::Saved, now()).unwrap();
    assert!(effects.contains(&Effect::DiscardChanges));

    let plain_path = mat.plain.clone();
    let ws_path = mat.workspace.path().to_path_buf();
    let effects = close(mat, &mut held, Event::ViewerExited).unwrap();
    assert!(effects.contains(&Effect::WipeWorkspace));
    assert_eq!(held.session.state(), State::Closed);
    assert!(!plain_path.exists() && !ws_path.exists(), "nothing left (T09)");

    // the budget was one open: a second open is refused
    let mut again = Held {
        session: zbacs_session::Session::resume(Permission::ReadOnly, now() - 10, now() + 3600, 1, 1),
        ..held.clone()
    };
    assert_eq!(materialise(&received, &mut again, &device, &base, "d-2").err(), Some("opens_exhausted"));
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn scenario_c_edit_open_and_save_ask_for_a_reseal() {
    let (dir, _alice, bob, received, mut held) =
        granted("c", PermissionArg::Edit, OpensArg::Thrice, DecisionArg::Edit).await;
    let device = bob.host.device_keys().unwrap().envelope;
    let mat = materialise(&received, &mut held, &device, &bob.dir.join("sessions"), "c-1").expect("opens");
    assert!(!mat.effects.contains(&Effect::MarkReadOnly));
    assert!(!std::fs::metadata(&mat.plain).unwrap().permissions().readonly());

    // Bob edits and saves
    std::fs::write(&mat.plain, b"Q3 plan, revised by Bob").unwrap();
    let effects = held.session.apply(Event::Saved, now()).unwrap();
    assert_eq!(effects, vec![Effect::Reseal], "an Edit save must reseal (T07)");
    assert_eq!(held.session.state(), State::Resealing);

    // ...and the wipe still happens when the session ends, even mid-reseal
    let ws = mat.workspace.path().to_path_buf();
    let effects = close(mat, &mut held, Event::Revoked).unwrap();
    assert!(effects.contains(&Effect::WipeWorkspace));
    assert!(!ws.exists());
    std::fs::remove_dir_all(dir).ok();
}

/// The rest of scenario C (Z-1.G.8): Bob's save reseals his copy as version 2, Alice's machine
/// learns of it from the notice (she never sees the file), Bob's next request is for version 2,
/// and Alice can approve it — with a key from the envelope the notice carried.
#[tokio::test(flavor = "multi_thread")]
async fn scenario_c_reseal_produces_a_new_version_alice_can_approve() {
    let (dir, alice, bob, received, mut held) =
        granted("c2", PermissionArg::Edit, OpensArg::Unlimited, DecisionArg::Edit).await;
    let device = bob.host.device_keys().unwrap().envelope;
    let signer = bob.host.device_keys().unwrap().signing;
    let mat = materialise(&received, &mut held, &device, &bob.dir.join("sessions"), "c2-1").expect("opens");

    // Bob edits, saves; the container on his disk becomes version 2 and Alice is told
    std::fs::write(&mat.plain, b"Q3 plan, revised by Bob").unwrap();
    assert_eq!(held.session.apply(Event::Saved, now()).unwrap(), vec![Effect::Reseal]);
    let saved = save(&bob.client, &received, &mat, &mut held, &device, &signer).await.expect("resealed");
    assert_eq!(saved.ver, 2);
    assert_eq!(held.session.state(), State::Open, "back to Open after the reseal");
    let (v2, v2_hash) = zbacs_core::inspect(std::fs::File::open(&received).unwrap()).unwrap();
    assert_eq!(v2_hash.0, saved.header_hash);
    assert_eq!(v2.sigk, signer.verifying_key().to_bytes().to_vec(), "signed by Bob's device");
    assert!(!std::fs::read(&received).unwrap().windows(7).any(|w| w == b"revised"), "still ciphertext");
    let ws = mat.workspace.path().to_path_buf();
    close(mat, &mut held, Event::ViewerExited).unwrap();
    assert!(!ws.exists());

    // Alice's machine takes the notice into its record without ever having the file
    let owner = owner_account(&alice.prepared.profile);
    let mut entry = None;
    for _ in 0..100 {
        let _ = next_requests(&alice.client, &owner, &alice.ledger).await;
        let e = alice.ledger.entries().into_iter().next().unwrap();
        if e.ver == 2 {
            entry = Some(e);
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let entry = entry.expect("Alice's record advanced to version 2");
    assert_eq!(entry.header_hash, hex::encode(saved.header_hash));
    assert!(entry.owner_envelope.is_some(), "the notice carried Alice's envelope for v2");

    // ...and the old DEK is dead: Bob's held grant cannot open version 2 (T20/T19)
    let mut stale = Held {
        session: zbacs_session::Session::resume(Permission::Edit, now() - 10, now() + 3600, 0, 1),
        ..held.clone()
    };
    assert_eq!(
        materialise(&received, &mut stale, &device, &bob.dir.join("sessions"), "c2-x").err(),
        Some("version")
    );

    // Bob asks again — for version 2 — and Alice approves it from the stored envelope
    let alice_side = tokio::spawn(async move {
        let a = alice;
        let answered = alice_answers(&a, DecisionArg::ReadOnly).await;
        (a, answered)
    });
    let (outcome, mut held2) = bob_asks(&bob, &received, Permission::ReadOnly).await;
    let (_alice, _) = alice_side.await.unwrap();
    assert!(matches!(outcome, Outcome::Granted { permission: Permission::ReadOnly, .. }), "{outcome:?}");
    assert_eq!(held2.terms.as_ref().unwrap().header_hash, saved.header_hash, "the grant names version 2");
    let mat2 =
        materialise(&received, &mut held2, &device, &bob.dir.join("sessions"), "c2-2").expect("opens v2");
    assert_eq!(std::fs::read(&mat2.plain).unwrap(), b"Q3 plan, revised by Bob");
    close(mat2, &mut held2, Event::ViewerExited).unwrap();
    std::fs::remove_dir_all(dir).ok();
}

// ================================================================ E

#[tokio::test(flavor = "multi_thread")]
async fn scenario_e_refusal() {
    let dir = temp("e-deny");
    let relay = start_relay().await;
    let alice = machine(&dir.join("alice"), &relay);
    let bob = machine(&dir.join("bob"), &relay);
    let received = bob_receives(&scenario_a(&alice, PermissionArg::ReadOnly, OpensArg::Once), &bob);
    let alice_side = tokio::spawn(async move { alice_answers(&alice, DecisionArg::Deny).await });
    let (outcome, held) = bob_asks(&bob, &received, Permission::ReadOnly).await;
    alice_side.await.unwrap();
    assert_eq!(outcome, Outcome::Denied);
    assert_eq!(held.session.state(), State::Denied);
    assert!(held.envelope.is_none());
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn scenario_e_revoke_while_open_wipes_immediately() {
    let (dir, alice, bob, received, mut held) =
        granted("e-revoke", PermissionArg::Edit, OpensArg::Unlimited, DecisionArg::Edit).await;
    let device = bob.host.device_keys().unwrap().envelope;
    let mat = materialise(&received, &mut held, &device, &bob.dir.join("sessions"), "e-1").expect("opens");
    let ws = mat.workspace.path().to_path_buf();
    let grant_id = held.terms.as_ref().unwrap().struct_hash();
    let expiry = held.terms.as_ref().unwrap().expiry;

    // Alice pulls it back while Bob has the file open
    let grant_hex = hex::encode(grant_id);
    let alice_revokes = async {
        tokio::time::sleep(Duration::from_millis(120)).await;
        revoke_now(&alice.client, &alice.ledger, &grant_hex).await.expect("revoked")
    };
    let bob_watches = async {
        let mut session = held.session.clone();
        let end = watch_grant(
            &bob.client,
            Guarding {
                path: "plan",
                session: &mut session,
                grant_id,
                expiry,
                cancel: Arc::new(AtomicBool::new(false)),
                poll: Duration::from_millis(40),
            },
            |_| {},
        )
        .await;
        (end, session)
    };
    let ((end, session), _) = tokio::join!(bob_watches, alice_revokes);
    assert_eq!(end, GrantEnd::Revoked);
    assert_eq!(session.state(), State::Revoked);

    // the Agent's reaction to a revoke while open: close the viewer, wipe, no new version
    held.session = zbacs_session::Session::resume(Permission::Edit, now() - 10, expiry, 0, 1);
    let _ = held.session.apply(Event::Opened, now());
    let effects = close(mat, &mut held, Event::Revoked).unwrap();
    assert!(effects.contains(&Effect::RequestViewerClose) && effects.contains(&Effect::WipeWorkspace));
    assert!(!ws.exists(), "plaintext gone the moment access is pulled (T20, T09)");
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn scenario_e_expiry_closes_the_session() {
    let (dir, _alice, bob, received, mut held) =
        granted("e-expire", PermissionArg::ReadOnly, OpensArg::Once, DecisionArg::ReadOnly).await;
    let device = bob.host.device_keys().unwrap().envelope;
    let mat = materialise(&received, &mut held, &device, &bob.dir.join("sessions"), "e-2").expect("opens");
    let ws = mat.workspace.path().to_path_buf();
    let effects = close(mat, &mut held, Event::Expired).unwrap();
    assert!(effects.contains(&Effect::WipeWorkspace));
    assert_eq!(held.session.state(), State::Closed);
    assert!(!ws.exists());
    std::fs::remove_dir_all(dir).ok();
}

/// T19: a grant is for one version; a different file on disk under the same name does not open.
#[tokio::test(flavor = "multi_thread")]
async fn t19_a_grant_does_not_open_a_different_version() {
    let (dir, alice, bob, received, mut held) =
        granted("t19", PermissionArg::Edit, OpensArg::Thrice, DecisionArg::Edit).await;
    // Alice reseals her copy (a new version); Bob somehow has that file under the old grant
    let owner = alice.host.owner_keys().unwrap();
    let edited = alice.dir.join("edited.txt");
    std::fs::write(&edited, b"v2").unwrap();
    let sealed = alice.dir.join("plan.docx.zbacs");
    zbacs_core::reseal_to_path(
        &edited,
        &sealed,
        &owner,
        zbacs_core::Policy { default: Permission::Edit, ttl: 3600, max: 3, pin: true, strict: false },
    )
    .unwrap();
    std::fs::copy(&sealed, &received).unwrap();
    let device = bob.host.device_keys().unwrap().envelope;
    assert_eq!(
        materialise(&received, &mut held, &device, &bob.dir.join("sessions"), "t19").err(),
        Some("version")
    );
    assert_eq!(held.session.state(), State::Granted, "refused before the open was counted");
    std::fs::remove_dir_all(dir).ok();
}

/// T23: an Edit approval always goes through the OS prompt; a device that cannot show one can
/// only allow 읽기만, and says so instead of failing vaguely.
#[tokio::test(flavor = "multi_thread")]
async fn t23_a_device_without_os_confirmation_cannot_allow_editing() {
    let dir = temp("t23");
    let relay = start_relay().await;
    let alice = machine_with(&dir.join("alice"), &relay, ApprovalStyle::ThisDevice);
    let bob = machine(&dir.join("bob"), &relay);
    let received = bob_receives(&scenario_a(&alice, PermissionArg::Edit, OpensArg::Once), &bob);
    let policy = ConfirmationPolicy::default();
    assert!(!zbacs_agent_lib::approve::edit_supported(alice.prepared.signer.as_ref(), &policy));

    let alice_side = tokio::spawn(async move {
        alice.client.announce(None).await.unwrap();
        let owner = owner_account(&alice.prepared.profile);
        let mut pending = Vec::new();
        for _ in 0..200 {
            pending = next_requests(&alice.client, &owner, &alice.ledger).await;
            if !pending.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        let request = pending.first().expect("seen").clone();
        assert!(!request.incoming_on(false).can_allow_edit, "the screen hides 편집도 허락");
        let owner_keys = alice.host.owner_keys().unwrap();
        let with = |recent: &'static [u64]| Answering {
            signer: alice.prepared.signer.as_ref(),
            device_setting: Confirmation::NotRequired,
            owner: &owner_keys,
            ledger: &alice.ledger,
            deployment: Deployment::DEV,
            policy: &policy,
            recent,
        };
        let refused = answer(&alice.client, &request, DecisionArg::Edit, with(&[])).await;
        assert_eq!(refused.err(), Some("needs_os_confirm"));
        // ...while 읽기만 still goes through on the same device
        answer(&alice.client, &request, DecisionArg::ReadOnly, with(&[])).await.expect("read-only allowed")
    });
    let (outcome, _) = bob_asks(&bob, &received, Permission::Edit).await;
    alice_side.await.unwrap();
    assert!(matches!(outcome, Outcome::Granted { permission: Permission::ReadOnly, .. }), "{outcome:?}");
    std::fs::remove_dir_all(dir).ok();
}
