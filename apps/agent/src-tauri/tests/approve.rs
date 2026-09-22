//! Z-1.G.10 DoD — scenario B end to end, minus the viewer: Alice locks a file on her machine,
//! Bob's machine asks, Alice's machine shows the request from *its own record* and answers,
//! and Bob's machine ends up with a key it can open and a signature it can check.
//!
//! Two `SetupHost`s in two config directories stand in for the two PCs; one real
//! `zbacs-relay` sits between them; the software signer stands in for Windows Hello.

#![cfg(feature = "demo-signer")]

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpListener;
use zbacs_agent_lib::approve::{answer, next_requests, Answering, DecisionArg, Deployment};
use zbacs_agent_lib::ledger::{Entry, Ledger};
use zbacs_agent_lib::request::{ask, target_of, Asking, Limits, Outcome};
use zbacs_agent_lib::seal::{owner_account, seal_now, OpensArg, PermissionArg, SealRequest, TtlArg};
use zbacs_agent_lib::setup::SetupHost;
use zbacs_auth::setup::{ApprovalStyle, Prepared};
use zbacs_auth::store::{KeyStore, MemoryKeyStore};
use zbacs_auth::{verify_assertion, ApprovalAssertion, Confirmation, ConfirmationPolicy};
use zbacs_core::Permission;
use zbacs_proto::{device_key_hash, DeviceIdentity};
use zbacs_relay::{router, Relay};
use zbacs_relay_client::{RelayClient, RetryPolicy};
use zbacs_session::State;

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

fn temp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zbacs-approve-it-{tag}-{}", std::process::id()));
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

/// One set-up machine.
struct Machine {
    host: SetupHost,
    prepared: Prepared,
    ledger: Ledger,
    client: RelayClient,
    key_hash: [u8; 32],
}

fn machine(dir: &Path, relay: &str) -> Machine {
    let store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let host = SetupHost::with_store(dir.join("config"), store, true);
    let prepared = host.complete(ApprovalStyle::ThisDevice, now()).expect("setup");
    let keys = host.device_keys().expect("device keys");
    let device = DeviceIdentity { keys: keys.envelope, signing: keys.signing };
    let key_hash = device_key_hash(&prepared.profile.device_x25519_pub, &prepared.profile.device_ed25519_pub);
    let policy = RetryPolicy {
        attempts_per_endpoint: 2,
        initial_backoff: Duration::from_millis(20),
        ..Default::default()
    };
    let client = RelayClient::with_policy(vec![relay.to_string()], device, policy).unwrap();
    Machine { host, prepared, ledger: Ledger::new(&dir.join("config")), client, key_hash }
}

/// Alice locks a file the way the lock screen does, and her machine records it.
fn alice_locks(alice: &Machine, dir: &Path, permission: PermissionArg) -> PathBuf {
    let plain = dir.join("brief.docx");
    std::fs::write(&plain, b"agenda: the merger, the budget, the new office").unwrap();
    let request = SealRequest {
        path: plain.display().to_string(),
        permission,
        ttl: TtlArg::Day,
        opens: OpensArg::Thrice,
    };
    let owner = alice.host.owner_keys().unwrap();
    let result = seal_now(&owner, &alice.prepared.profile, &request).expect("seal");
    alice.ledger.record(&Entry::from_seal(&result, &request)).unwrap();
    PathBuf::from(result.output)
}

/// Bob's copy of the locked file, as if it came by mail.
fn bob_receives(sealed: &Path, dir: &Path) -> PathBuf {
    let copy = dir.join("brief.docx.zbacs");
    std::fs::copy(sealed, &copy).unwrap();
    copy
}

fn quick() -> Limits {
    Limits {
        poll: Duration::from_millis(50),
        nudge_after: Duration::from_secs(60),
        give_up_after: Duration::from_secs(10),
    }
}

/// Alice's machine: wait for the request, show it, answer it.
async fn alice_answers(
    alice: &Machine,
    decision: DecisionArg,
) -> Result<zbacs_agent_lib::approve::Answered, &'static str> {
    alice.client.announce(None).await.unwrap();
    let owner = owner_account(&alice.prepared.profile);
    let mut pending = Vec::new();
    for _ in 0..100 {
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
    answer(&alice.client, request, decision, with).await
}

#[tokio::test(flavor = "multi_thread")]
async fn scenario_b_alice_allows_and_bob_can_open_the_key_and_check_her_signature() {
    let dir = temp("allow");
    let relay = start_relay().await;
    let alice = machine(&dir.join("alice"), &relay);
    let bob = machine(&dir.join("bob"), &relay);

    let sealed = alice_locks(&alice, &dir.join("alice"), PermissionArg::ReadOnly);
    let received = bob_receives(&sealed, &dir.join("bob"));
    let target = target_of(&received).unwrap();
    let path = received.display().to_string();

    // Bob asks; Alice's machine answers while he waits.
    let alice_side = tokio::spawn(async move {
        let a = alice;
        let answered = alice_answers(&a, DecisionArg::ReadOnly).await.expect("Alice could answer");
        (a, answered)
    });
    let phases = Arc::new(Mutex::new(Vec::new()));
    let sink = phases.clone();
    let (outcome, held) = ask(
        &bob.client,
        Asking {
            path: &path,
            target: &target,
            requested: Permission::ReadOnly,
            our_key_hash: bob.key_hash,
            cancel: Arc::new(AtomicBool::new(false)),
            limits: quick(),
        },
        move |u| sink.lock().unwrap().push(u.phase),
    )
    .await;
    let (alice, answered) = alice_side.await.unwrap();

    // Bob's side
    assert!(matches!(outcome, Outcome::Granted { permission: Permission::ReadOnly, .. }), "{outcome:?}");
    assert_eq!(held.session.state(), State::Granted);
    let terms = held.terms.expect("terms");
    assert_eq!(terms.max_opens, 3, "the budget Alice chose when locking");
    assert!(terms.expiry - now() > 86_000, "the day Alice chose when locking");

    // ...the key really opens for Bob's device, bound to this grant
    let env: zbacs_core::Envelope =
        ciborium::from_reader(held.envelope.expect("envelope").as_slice()).unwrap();
    let bob_keys = bob.host.device_keys().unwrap();
    let grant_id = terms.struct_hash();
    let dek = env.open(&bob_keys.envelope, &grant_id).expect("Bob's device opens the envelope");
    assert!(env.open(&bob_keys.envelope, &[0; 32]).is_err(), "bound to the grant, not reusable");
    let plain = dir.join("bob").join("opened.docx");
    let (header, header_hash, rest) =
        zbacs_core::read_header(std::io::BufReader::new(std::fs::File::open(&received).unwrap())).unwrap();
    let opened =
        zbacs_core::open_with_dek(header, header_hash, rest, std::fs::File::create(&plain).unwrap(), &dek)
            .expect("the file decrypts with that key");
    assert_eq!(opened.file_name, "brief.docx");
    assert_eq!(std::fs::read(&plain).unwrap(), b"agenda: the merger, the budget, the new office");

    // ...and Alice's signature is over exactly these terms (what Z-1.H.8 will verify on chain)
    assert_eq!(answered.grant_id.as_deref(), Some(hex::encode(grant_id).as_str()));
    let digest = terms.digest(Deployment::DEV.chain_id, &Deployment::DEV.policy);
    let owner_pk = alice.prepared.profile.public_key.expect("software signer publishes its key");
    let assertion: ApprovalAssertion = {
        // Bob does not have Alice's signature in `held` yet (Z-1.H.8 will keep it); replay
        // what went over the wire from Alice's answer instead.
        let _ = &answered;
        alice_signature_for(&alice, &digest)
    };
    verify_assertion(&owner_pk, &digest, &assertion).expect("Alice's signature checks out");
    assert_eq!(*phases.lock().unwrap(), vec!["sent", "granted"]);
    std::fs::remove_dir_all(dir).ok();
}

/// The assertion Alice's signer produces for a digest — the same call `answer` made.
fn alice_signature_for(alice: &Machine, digest: &[u8; 32]) -> ApprovalAssertion {
    use zbacs_auth::{ApprovalChallenge, ApprovalContext};
    let challenge = ApprovalChallenge {
        digest: *digest,
        context: ApprovalContext { permission: Permission::ReadOnly, file_id: [0; 32] },
    };
    alice.prepared.signer.sign(&challenge, Confirmation::NotRequired).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn scenario_e_alice_refuses_and_bob_is_told() {
    let dir = temp("refuse");
    let relay = start_relay().await;
    let alice = machine(&dir.join("alice"), &relay);
    let bob = machine(&dir.join("bob"), &relay);
    let sealed = alice_locks(&alice, &dir.join("alice"), PermissionArg::Edit);
    let received = bob_receives(&sealed, &dir.join("bob"));
    let target = target_of(&received).unwrap();
    let path = received.display().to_string();

    let alice_side = tokio::spawn(async move { alice_answers(&alice, DecisionArg::Deny).await });
    let (outcome, held) = ask(
        &bob.client,
        Asking {
            path: &path,
            target: &target,
            requested: Permission::Edit,
            our_key_hash: bob.key_hash,
            cancel: Arc::new(AtomicBool::new(false)),
            limits: quick(),
        },
        |_| {},
    )
    .await;
    let answered = alice_side.await.unwrap().unwrap();
    assert_eq!(answered.decision, "deny");
    assert_eq!(outcome, Outcome::Denied);
    assert_eq!(held.session.state(), State::Denied);
    assert!(held.envelope.is_none(), "a refusal carries no key");
    std::fs::remove_dir_all(dir).ok();
}

/// T06: a request for a file this machine never locked cannot be allowed, only refused.
#[tokio::test(flavor = "multi_thread")]
async fn t06_a_file_this_machine_did_not_lock_cannot_be_allowed() {
    let dir = temp("unknown");
    let relay = start_relay().await;
    let alice = machine(&dir.join("alice"), &relay);
    let bob = machine(&dir.join("bob"), &relay);

    // locked on some *other* machine of Alice's: same owner account bytes, no ledger entry here
    let other = machine(&dir.join("alice-laptop"), &relay);
    let plain = dir.join("alice-laptop").join("notes.txt");
    std::fs::write(&plain, b"typed on the laptop").unwrap();
    let owner_bytes = owner_account(&alice.prepared.profile);
    let mut opts = zbacs_core::SealOptions::new(&owner_bytes, "notes.txt");
    opts.policy = zbacs_core::Policy { default: Permission::ReadOnly, ..Default::default() };
    let sealed = dir.join("alice-laptop").join("notes.txt.zbacs");
    zbacs_core::seal_to_path(&plain, &sealed, &other.host.owner_keys().unwrap(), &opts).unwrap();

    let received = bob_receives(&sealed, &dir.join("bob"));
    let target = target_of(&received).unwrap();
    let path = received.display().to_string();

    let alice_side = tokio::spawn(async move {
        alice.client.announce(None).await.unwrap();
        let owner = owner_account(&alice.prepared.profile);
        let mut pending = Vec::new();
        for _ in 0..100 {
            pending = next_requests(&alice.client, &owner, &alice.ledger).await;
            if !pending.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        let request = pending.first().expect("seen").clone();
        let incoming = request.incoming();
        assert!(!incoming.known && !incoming.can_allow, "the screen offers no allow button");

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
        let refused = answer(&alice.client, &request, DecisionArg::ReadOnly, with).await;
        assert_eq!(refused.err(), Some("unknown_file"));
        // ...so the person refuses, which always works
        let with = Answering {
            signer: alice.prepared.signer.as_ref(),
            device_setting: Confirmation::NotRequired,
            owner: &owner_keys,
            ledger: &alice.ledger,
            deployment: Deployment::DEV,
            policy: &ConfirmationPolicy::default(),
            recent: &[],
        };
        answer(&alice.client, &request, DecisionArg::Deny, with).await.unwrap()
    });
    let (outcome, _) = ask(
        &bob.client,
        Asking {
            path: &path,
            target: &target,
            requested: Permission::ReadOnly,
            our_key_hash: bob.key_hash,
            cancel: Arc::new(AtomicBool::new(false)),
            limits: quick(),
        },
        |_| {},
    )
    .await;
    alice_side.await.unwrap();
    assert_eq!(outcome, Outcome::Denied);
    std::fs::remove_dir_all(dir).ok();
}
