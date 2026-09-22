//! Z-1.G.9 — asking the owner, and waiting for the answer.
//!
//! The person sees one screen: a ring and "주인의 허락을 기다리는 중…" with a "취소" button
//! (ui_guideline S4). Behind it this module registers the device with the relay, signs and
//! sends an [`AccessRequest`], and polls the device inbox until one of five things happens:
//! the owner allows, the owner refuses, the person cancels, the relay cannot be reached, or
//! nobody answers in time (approval_protocol §4: a nudge after 120 s, give up at 300 s).
//!
//! What it checks before calling an answer "allowed" (approval_protocol §2 rules 1–3): the
//! grant names *this* file, *this* version, *this* device and *this* request. An answer for
//! anything else is not "wrong", it is a swap, and it is refused (T05, T19). What it does not
//! check yet: the owner's own signature on the terms, which needs the owner's approval key from
//! the chain (Z-1.H.8/H.10). That is reported as `owner_signature_check` in `pending`, shown
//! in the developer panel and never to the person as a done thing.
//!
//! Opening the file after an approval is Z-1.G.7/G.8; this module stops at "허락받았어요" and
//! keeps the [`Session`] and the envelope for that step.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use zbacs_core::Permission;
use zbacs_proto::{
    device_key_hash, AccessGrantTerms, AccessRequest, DeviceIdentity, Envelope, GrantMsg, Kind, Signed,
};
use zbacs_relay_client::{ClientError, RelayClient};
use zbacs_session::{Event, Session, State};

use crate::setup::{Identity, SetupHost};

/// Event the webview listens for while a request is in flight.
pub const REQUEST_EVENT: &str = "zbacs://request";
/// Developer override for the relay, comma-separated. There is no user-facing setting: the
/// Agent ships with its relay built in (beta_test_automation L2), and this exists so a
/// developer box can point at a local `zbacs-relay`.
pub const RELAY_ENV: &str = "ZBACS_RELAY_URL";
/// Where the Agent looks until a hosted relay exists (Z-1.H.11 will replace this constant).
pub const DEFAULT_RELAY: &str = "http://127.0.0.1:8787";

/// How often the inbox is read, and when to nudge or stop (approval_protocol §4).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Delay between inbox reads.
    pub poll: Duration,
    /// After this long with no answer the screen says so, but keeps waiting.
    pub nudge_after: Duration,
    /// After this long the request is treated as unanswered.
    pub give_up_after: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            poll: Duration::from_secs(2),
            nudge_after: Duration::from_secs(120),
            give_up_after: Duration::from_secs(300),
        }
    }
}

/// Relay endpoints in the order to try: the developer override, else the built-in one.
pub fn relay_endpoints() -> Vec<String> {
    endpoints_from(std::env::var(RELAY_ENV).ok().as_deref())
}

fn endpoints_from(configured: Option<&str>) -> Vec<String> {
    let listed: Vec<String> = configured
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if listed.is_empty() {
        vec![DEFAULT_RELAY.to_string()]
    } else {
        listed
    }
}

/// The permission the person asks for — the file's own default, never a free choice, so the
/// screen has no extra control (ux_principles rule 4).
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestedArg {
    /// 읽기만
    ReadOnly,
    /// 편집도 가능
    Edit,
}

impl From<RequestedArg> for Permission {
    fn from(a: RequestedArg) -> Self {
        match a {
            RequestedArg::ReadOnly => Permission::ReadOnly,
            RequestedArg::Edit => Permission::Edit,
        }
    }
}

/// What a request is about, read from the container header without a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Container file id.
    pub fid: [u8; 32],
    /// Header hash of the version on disk.
    pub header_hash: [u8; 32],
    /// Owner account bytes the relay routes on.
    pub owner: Vec<u8>,
}

/// Read the target from a sealed file. Fails with the same machine values the lock screen uses.
pub fn target_of(path: &Path) -> Result<Target, &'static str> {
    let file = std::fs::File::open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            "missing"
        } else {
            "unreadable"
        }
    })?;
    let (header, header_hash) = zbacs_core::inspect(std::io::BufReader::new(file)).map_err(|e| {
        log::warn!("cannot read the container to ask about it: {e}");
        "unreadable"
    })?;
    if header.body.pol.default == Permission::Deny {
        return Err("owner_denies");
    }
    Ok(Target { fid: header.body.fid.0, header_hash: header_hash.0, owner: header.body.own.clone() })
}

/// The request as it goes on the wire. `hint` stays empty: a name would be readable by the
/// relay until Phase 2 encrypts it (relay_protocol §7).
pub fn build_request(
    target: &Target,
    device: &DeviceIdentity,
    requested: Permission,
    nonce: [u8; 16],
    now: u64,
) -> AccessRequest {
    AccessRequest {
        fid: target.fid,
        header_hash: target.header_hash,
        owner: target.owner.clone(),
        device_kid: device.kid(),
        x25519_pub: device.x25519_pub(),
        ed25519_pub: device.ed25519_pub(),
        requested: requested as u8,
        nonce,
        hint: None,
        ts: now,
    }
}

/// What an inbox message means for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Not a grant, or a grant for some other request.
    NotOurs,
    /// The owner refused.
    Denied,
    /// The owner allowed, and the terms are for this file, version and device.
    Granted {
        /// Approved permission.
        permission: Permission,
        /// The terms as the owner signed them.
        terms: AccessGrantTerms,
        /// HPKE envelope with the DEK, for Z-1.G.7/G.8.
        envelope: Option<Vec<u8>>,
    },
    /// A grant with our nonce whose terms name something else. Refused, and said so.
    Mismatch(&'static str),
}

/// Decide what an envelope from the inbox means (approval_protocol §2 rules 1–3).
///
/// The relay's own signature on the envelope is not checked here: the owner's relay key is
/// not something the container carries. The binding that matters is inside — the nonce this
/// device generated, and the terms naming this device's key hash — and the owner's signature
/// over those terms is the check still to come (see the module docs).
pub fn classify(envelope: &Envelope, nonce: &[u8; 16], target: &Target, our_key_hash: &[u8; 32]) -> Answer {
    if envelope.kind != Kind::Grant {
        return Answer::NotOurs;
    }
    let Ok(signed) = Signed::from_bytes(&envelope.body) else {
        return Answer::NotOurs;
    };
    if signed.kind != Kind::Grant {
        return Answer::NotOurs;
    }
    let Ok(grant) = ciborium::from_reader::<GrantMsg, _>(signed.payload.as_slice()) else {
        return Answer::NotOurs;
    };
    if grant.request_nonce != *nonce {
        return Answer::NotOurs;
    }
    let permission = match grant.decision {
        0 => return Answer::Denied,
        1 => Permission::ReadOnly,
        2 => Permission::Edit,
        _ => return Answer::Mismatch("decision"),
    };
    let Some(bytes) = grant.grant.as_deref() else {
        return Answer::Mismatch("no_terms");
    };
    let Ok(terms) = AccessGrantTerms::from_cbor(bytes) else {
        return Answer::Mismatch("terms");
    };
    if terms.file_id != target.fid {
        return Answer::Mismatch("file");
    }
    if terms.header_hash != target.header_hash {
        return Answer::Mismatch("version");
    }
    if terms.device_key_hash != *our_key_hash {
        return Answer::Mismatch("device");
    }
    if terms.request_nonce != *nonce {
        return Answer::Mismatch("nonce");
    }
    if terms.permission != permission as u8 {
        return Answer::Mismatch("permission");
    }
    Answer::Granted { permission, terms, envelope: grant.envelope }
}

/// How a request ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Allowed; the session is in [`State::Granted`].
    Granted {
        /// Approved permission.
        permission: Permission,
        /// Unix seconds the approval expires.
        expiry: u64,
    },
    /// Refused by the owner.
    Denied,
    /// No answer within [`Limits::give_up_after`].
    Expired,
    /// The person stopped waiting.
    Cancelled,
    /// Could not ask, or the answer was unusable. Machine value for the UI.
    Failed(&'static str),
}

/// A progress report while a request is in flight. Serialised to the webview as-is.
#[derive(Debug, Clone, Serialize)]
pub struct Update {
    /// Which file this is about.
    pub path: String,
    /// `sent` | `nudge` | `granted` | `denied` | `expired` | `cancelled` | `failed`.
    pub phase: &'static str,
    /// `read_only` | `edit` once granted.
    pub decision: Option<&'static str>,
    /// Unix seconds the approval expires, once granted.
    pub expiry: Option<u64>,
    /// Machine value for what went wrong.
    pub problem: Option<&'static str>,
    /// Checks still outstanding, as machine values (developer panel only).
    pub pending: Vec<&'static str>,
}

impl Update {
    fn new(path: &str, phase: &'static str) -> Self {
        Self {
            path: path.to_string(),
            phase,
            decision: None,
            expiry: None,
            problem: None,
            pending: Vec::new(),
        }
    }
}

/// What the Agent keeps about a request after it ends, for the steps that follow.
#[derive(Debug, Clone)]
pub struct Held {
    /// The session, in `Granted` or a terminal state.
    pub session: Session,
    /// The owner's terms, when allowed.
    pub terms: Option<AccessGrantTerms>,
    /// The DEK envelope, when allowed.
    pub envelope: Option<Vec<u8>>,
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn decision_word(p: Permission) -> &'static str {
    match p {
        Permission::ReadOnly => "read_only",
        Permission::Edit => "edit",
        Permission::Deny => "deny",
    }
}

/// Everything one request needs, gathered so [`ask`] reads as the steps it takes.
pub struct Asking<'a> {
    /// The file, for progress reports.
    pub path: &'a str,
    /// What the request is about.
    pub target: &'a Target,
    /// The permission asked for.
    pub requested: Permission,
    /// `keccak256(x25519_pub || ed25519_pub)` of this device, which the terms must name.
    pub our_key_hash: [u8; 32],
    /// Set by "취소".
    pub cancel: Arc<AtomicBool>,
    /// Poll, nudge and give-up timings.
    pub limits: Limits,
}

/// Ask, then wait. Separate from the command so the whole path runs against a real relay in
/// a test with no webview: register, send, poll, classify, drive the session.
///
/// `on_update` is called for every phase change; the command forwards them to the screen.
pub async fn ask(
    client: &RelayClient,
    asking: Asking<'_>,
    mut on_update: impl FnMut(Update),
) -> (Outcome, Held) {
    let Asking { path, target, requested, our_key_hash, cancel, limits } = asking;
    let mut session = Session::new();
    let mut held = Held { session: session.clone(), terms: None, envelope: None };
    let fail = |reason: &'static str, session: &mut Session, on_update: &mut dyn FnMut(Update)| {
        let _ = session.apply(Event::Failed(reason), now());
        let mut u = Update::new(path, "failed");
        u.problem = Some(reason);
        on_update(u);
    };

    // The relay only accepts envelopes from a device it knows, and each relay keeps its own
    // list, so announcing is part of every request rather than a one-off.
    if let Err(e) = client.announce(None).await {
        let reason = relay_problem(&e);
        fail(reason, &mut session, &mut on_update);
        held.session = session;
        return (Outcome::Failed(reason), held);
    }

    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let request = build_request(target, client.device(), requested, nonce, now());
    if let Err(e) = client.send_request(&request).await {
        let reason = relay_problem(&e);
        fail(reason, &mut session, &mut on_update);
        held.session = session;
        return (Outcome::Failed(reason), held);
    }
    log::info!("asked the owner: requested={requested:?}");
    on_update(Update::new(path, "sent"));

    let started = std::time::Instant::now();
    let mut nudged = false;
    loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = session.apply(Event::Failed("cancelled"), now());
            on_update(Update::new(path, "cancelled"));
            held.session = session;
            return (Outcome::Cancelled, held);
        }
        let waited = started.elapsed();
        if waited >= limits.give_up_after {
            let _ = session.apply(Event::Expired, now());
            on_update(Update::new(path, "expired"));
            held.session = session;
            return (Outcome::Expired, held);
        }
        if !nudged && waited >= limits.nudge_after {
            nudged = true;
            on_update(Update::new(path, "nudge"));
        }

        // A relay outage here is not the end of the request: the owner may answer any moment,
        // and the client backs off on its own. Only the deadline ends the wait.
        let envelopes = match client.inbox_for_device().await {
            Ok(list) => list,
            Err(e) => {
                log::warn!("inbox read failed, still waiting: {e}");
                Vec::new()
            }
        };
        for envelope in &envelopes {
            match classify(envelope, &nonce, target, &our_key_hash) {
                Answer::NotOurs => {}
                Answer::Denied => {
                    let _ = session.apply(Event::Denied, now());
                    on_update(Update::new(path, "denied"));
                    held.session = session;
                    return (Outcome::Denied, held);
                }
                Answer::Mismatch(what) => {
                    // Refused loudly: an answer aimed at another file or device must never
                    // open this one, and the person should know something is off.
                    log::warn!("refused a grant that does not match this request: {what}");
                    fail("mismatch", &mut session, &mut on_update);
                    held.session = session;
                    return (Outcome::Failed("mismatch"), held);
                }
                Answer::Granted { permission, terms, envelope } => {
                    let event = Event::Granted {
                        permission,
                        not_before: terms.not_before,
                        expiry: terms.expiry,
                        max_opens: terms.max_opens,
                    };
                    if let Err(e) = session.apply(event, now()) {
                        // Already expired or not yet valid: the owner's clock and ours disagree
                        // by more than the terms allow (T15). Not a swap, but not usable.
                        log::warn!("grant is not usable now: {e}");
                        fail("window", &mut session, &mut on_update);
                        held.session = session;
                        return (Outcome::Failed("window"), held);
                    }
                    debug_assert_eq!(session.state(), State::Granted);
                    let mut u = Update::new(path, "granted");
                    u.decision = Some(decision_word(permission));
                    u.expiry = Some(terms.expiry);
                    u.pending = vec!["owner_signature_check", "open_file"];
                    on_update(u);
                    let expiry = terms.expiry;
                    held = Held { session, terms: Some(terms), envelope };
                    return (Outcome::Granted { permission, expiry }, held);
                }
            }
        }
        tokio::time::sleep(limits.poll).await;
    }
}

/// Machine value for a relay failure (ux_principles rule 6: every one maps to an action).
fn relay_problem(e: &ClientError) -> &'static str {
    match e {
        ClientError::Unreachable(_) => "relay_unreachable",
        ClientError::Refused(_) => "relay_refused",
        _ => "failed",
    }
}

// ------------------------------------------------------------------ Agent state

/// One request in flight or just finished, keyed by file path.
pub struct Active {
    /// Set by "취소".
    pub cancel: Arc<AtomicBool>,
    /// Filled in when the request ends.
    pub held: Option<Held>,
}

/// Requests this Agent has made, keyed by file path.
#[derive(Default)]
pub struct Requests(pub Mutex<HashMap<String, Active>>);

fn identity_of(app: &AppHandle) -> Result<(DeviceIdentity, [u8; 32]), &'static str> {
    let profile = app
        .state::<Identity>()
        .0
        .lock()
        .expect("identity mutex")
        .as_ref()
        .map(|p| p.profile.clone())
        .ok_or("not_set_up")?;
    let keys = app.state::<SetupHost>().device_keys().map_err(|e| {
        log::warn!("cannot load the device keys: {e}");
        "not_set_up"
    })?;
    let device = DeviceIdentity { keys: keys.envelope, signing: keys.signing };
    let hash = device_key_hash(&profile.device_x25519_pub, &profile.device_ed25519_pub);
    Ok((device, hash))
}

/// Ask the owner for this file. Returns as soon as the request is under way; progress arrives
/// as [`REQUEST_EVENT`]s.
#[tauri::command]
pub async fn request_access(app: AppHandle, path: String, requested: RequestedArg) -> Result<(), String> {
    let target = target_of(Path::new(&path)).map_err(str::to_string)?;
    let (device, our_key_hash) = identity_of(&app).map_err(str::to_string)?;
    let client = RelayClient::new(relay_endpoints(), device).map_err(|e| {
        log::warn!("cannot build a relay client: {e}");
        "relay_unreachable".to_string()
    })?;

    let cancel = Arc::new(AtomicBool::new(false));
    {
        let state = app.state::<Requests>();
        let mut requests = state.0.lock().expect("requests mutex");
        if let Some(active) = requests.get(&path) {
            if active.held.is_none() {
                return Err("already_asking".to_string());
            }
        }
        requests.insert(path.clone(), Active { cancel: cancel.clone(), held: None });
    }

    let handle = app.clone();
    let key = path.clone();
    tauri::async_runtime::spawn(async move {
        let emit = |u: Update| {
            if let Err(e) = handle.emit(REQUEST_EVENT, &u) {
                log::warn!("cannot report request progress: {e}");
            }
        };
        let (outcome, held) = ask(
            &client,
            Asking {
                path: &key,
                target: &target,
                requested: requested.into(),
                our_key_hash,
                cancel,
                limits: Limits::default(),
            },
            emit,
        )
        .await;
        log::info!("request ended: {outcome:?}");
        let state = handle.state::<Requests>();
        let mut requests = state.0.lock().expect("requests mutex");
        if let Some(active) = requests.get_mut(&key) {
            active.held = Some(held);
        }
    });
    Ok(())
}

/// Stop waiting for this file. The request itself cannot be withdrawn from the relay; the
/// owner may still answer, and that answer is simply never read.
#[tauri::command]
pub fn cancel_request(app: AppHandle, path: String) {
    let state = app.state::<Requests>();
    let requests = state.0.lock().expect("requests mutex");
    if let Some(active) = requests.get(&path) {
        active.cancel.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("zbacs-request-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sealed(dir: &Path, default: Permission) -> std::path::PathBuf {
        let plain = dir.join("plain.txt");
        let out = dir.join("plain.txt.zbacs");
        std::fs::write(&plain, b"for your eyes").unwrap();
        let owner = zbacs_core::OwnerKeys::generate().unwrap();
        let mut opts = zbacs_core::SealOptions::new(b"eip155:84532:alice", "plain.txt");
        opts.policy = zbacs_core::Policy { default, ..Default::default() };
        zbacs_core::seal_to_path(&plain, &out, &owner, &opts).unwrap();
        out
    }

    fn grant_envelope(owner: &DeviceIdentity, grant: &GrantMsg) -> Envelope {
        let signed = Signed::sign(owner, grant, 1_700_000_000, [9; 16]).unwrap();
        Envelope {
            id: [1; 16],
            kind: Kind::Grant,
            body: signed.to_bytes().unwrap(),
            queued_at: 1_700_000_000,
        }
    }

    fn terms_for(target: &Target, key_hash: [u8; 32], nonce: [u8; 16], permission: u8) -> AccessGrantTerms {
        AccessGrantTerms {
            file_id: target.fid,
            header_hash: target.header_hash,
            device_key_hash: key_hash,
            permission,
            not_before: 1_700_000_000,
            expiry: 1_700_003_600,
            max_opens: 1,
            request_nonce: nonce,
            grant_nonce: 0,
        }
    }

    fn grant_msg(nonce: [u8; 16], decision: u8, terms: Option<&AccessGrantTerms>) -> GrantMsg {
        GrantMsg {
            request_nonce: nonce,
            grant: terms.map(|t| t.to_cbor().unwrap()),
            owner_sig: None,
            envelope: Some(vec![0xEE; 40]),
            tx_hash: None,
            decision,
            ts: 1_700_000_000,
        }
    }

    #[test]
    fn the_relay_comes_from_the_override_or_the_built_in_default() {
        assert_eq!(endpoints_from(None), vec![DEFAULT_RELAY.to_string()]);
        assert_eq!(endpoints_from(Some("")), vec![DEFAULT_RELAY.to_string()]);
        assert_eq!(
            endpoints_from(Some(" http://a:1 , http://b:2,")),
            vec!["http://a:1".to_string(), "http://b:2".to_string()]
        );
    }

    #[test]
    fn the_target_is_read_from_the_header_without_a_key() {
        let dir = temp("target");
        let path = sealed(&dir, Permission::ReadOnly);
        let target = target_of(&path).unwrap();
        assert_eq!(target.owner, b"eip155:84532:alice".to_vec());
        let (header, hash) = zbacs_core::inspect(std::fs::File::open(&path).unwrap()).unwrap();
        assert_eq!(target.fid, header.body.fid.0);
        assert_eq!(target.header_hash, hash.0);
        assert_eq!(target_of(&dir.join("nope.zbacs")), Err("missing"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_file_the_owner_locked_shut_is_not_asked_about() {
        let dir = temp("deny");
        let path = sealed(&dir, Permission::Deny);
        assert_eq!(target_of(&path), Err("owner_denies"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn the_request_names_this_device_and_carries_no_hint() {
        let device = DeviceIdentity::generate().unwrap();
        let target = Target { fid: [1; 32], header_hash: [2; 32], owner: b"o".to_vec() };
        let req = build_request(&target, &device, Permission::Edit, [7; 16], 5);
        assert_eq!(req.device_kid, device.kid());
        assert_eq!(req.x25519_pub, device.x25519_pub());
        assert_eq!(req.requested, 2);
        assert_eq!(req.nonce, [7; 16]);
        assert!(req.hint.is_none(), "nothing readable by the relay");
    }

    /// T05: an answer to some other request, or aimed at another device, is not ours.
    #[test]
    fn t05_only_a_grant_with_our_nonce_for_our_device_counts() {
        let owner = DeviceIdentity::generate().unwrap();
        let target = Target { fid: [1; 32], header_hash: [2; 32], owner: b"o".to_vec() };
        let ours = [3; 32];
        let nonce = [4; 16];

        let terms = terms_for(&target, ours, nonce, 1);
        let good = grant_envelope(&owner, &grant_msg(nonce, 1, Some(&terms)));
        assert!(matches!(
            classify(&good, &nonce, &target, &ours),
            Answer::Granted { permission: Permission::ReadOnly, .. }
        ));

        let other_nonce = grant_envelope(&owner, &grant_msg([5; 16], 1, Some(&terms)));
        assert_eq!(classify(&other_nonce, &nonce, &target, &ours), Answer::NotOurs);

        let mut for_another_device = terms.clone();
        for_another_device.device_key_hash = [8; 32];
        let swapped = grant_envelope(&owner, &grant_msg(nonce, 1, Some(&for_another_device)));
        assert_eq!(classify(&swapped, &nonce, &target, &ours), Answer::Mismatch("device"));

        let not_a_grant = Envelope { kind: Kind::Revoke, ..good.clone() };
        assert_eq!(classify(&not_a_grant, &nonce, &target, &ours), Answer::NotOurs);
    }

    /// T19: a grant for another version of the same file does not open this one.
    #[test]
    fn t19_a_grant_for_another_version_is_refused() {
        let owner = DeviceIdentity::generate().unwrap();
        let target = Target { fid: [1; 32], header_hash: [2; 32], owner: b"o".to_vec() };
        let nonce = [4; 16];
        let mut terms = terms_for(&target, [3; 32], nonce, 1);
        terms.header_hash = [0xAA; 32];
        let env = grant_envelope(&owner, &grant_msg(nonce, 1, Some(&terms)));
        assert_eq!(classify(&env, &nonce, &target, &[3; 32]), Answer::Mismatch("version"));

        terms.header_hash = target.header_hash;
        terms.file_id = [0xBB; 32];
        let env = grant_envelope(&owner, &grant_msg(nonce, 1, Some(&terms)));
        assert_eq!(classify(&env, &nonce, &target, &[3; 32]), Answer::Mismatch("file"));
    }

    #[test]
    fn a_refusal_needs_no_terms_and_an_allowance_needs_them() {
        let owner = DeviceIdentity::generate().unwrap();
        let target = Target { fid: [1; 32], header_hash: [2; 32], owner: b"o".to_vec() };
        let nonce = [4; 16];
        let denied = grant_envelope(&owner, &grant_msg(nonce, 0, None));
        assert_eq!(classify(&denied, &nonce, &target, &[3; 32]), Answer::Denied);
        let bare = grant_envelope(&owner, &grant_msg(nonce, 2, None));
        assert_eq!(classify(&bare, &nonce, &target, &[3; 32]), Answer::Mismatch("no_terms"));
        let terms = terms_for(&target, [3; 32], nonce, 1);
        let contradicts = grant_envelope(&owner, &grant_msg(nonce, 2, Some(&terms)));
        assert_eq!(classify(&contradicts, &nonce, &target, &[3; 32]), Answer::Mismatch("permission"));
    }

    #[test]
    fn the_limits_follow_the_protocol() {
        let l = Limits::default();
        assert_eq!(l.nudge_after, Duration::from_secs(120));
        assert_eq!(l.give_up_after, Duration::from_secs(300));
        assert!(l.poll < l.nudge_after);
    }
}
