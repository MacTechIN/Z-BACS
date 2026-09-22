//! Z-1.G.10 — the owner's side: a request arrives, the person answers on this PC.
//!
//! The screen (ui_guideline S5) is a card and three buttons: what file, what the other person
//! wants, then [읽기만] [편집도 가능] or [거절]. What the card says comes from this machine's
//! own record of the files it locked ([`crate::ledger`]), not from the request — a request can
//! claim any file id, and showing its claims back to the owner is exactly the phishing the
//! threat model warns about (T06). A file this machine has no record of cannot be allowed at
//! all: its key is inside the file, and the file is not here.
//!
//! Behind an allow: the terms of the approval (`AccessGrantTerms`) are hashed the way the
//! `AccessPolicy` contract hashes them, the device's approval signer signs that digest — with
//! an OS prompt when the confirmation policy says so (T23) — the file's key is re-wrapped for
//! the asking device, and the answer goes back through the relay. Behind a refusal: just the
//! refusal.
//!
//! The chain is not written yet (that is the smart-account path, Z-1.H.8); `tx_hash` is empty
//! and the recipient's agent treats the grant as relay-only until then.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};
use zbacs_auth::{ApprovalChallenge, ApprovalContext, AuthProvider, Confirmation, ConfirmationPolicy};
use zbacs_core::{Envelope as DekEnvelope, OwnerKeys, Permission};
use zbacs_proto::{
    device_key_hash, AccessGrantTerms, AccessRequest, DeviceIdentity, Envelope, GrantMsg, Kind, Revoke,
    Signed,
};
use zbacs_relay_client::RelayClient;

use crate::ledger::{Entry, Grant, Ledger};
use crate::request::relay_endpoints;
use crate::seal::owner_account;
use crate::setup::{Identity, SetupHost};

/// Event the webview listens for when a request arrives or is answered.
pub const APPROVAL_EVENT: &str = "zbacs://approval";
/// How often the owner inbox is read while the Agent runs.
pub const WATCH_INTERVAL: Duration = Duration::from_secs(3);
/// Requests older than this are not shown: the relay keeps them for a day, but an approval
/// the recipient stopped waiting for hours ago is noise, not a decision to make.
pub const MAX_REQUEST_AGE_SECS: u64 = 24 * 3600;
/// Allowance for the two machines' clocks when a grant starts (T15).
pub const NOT_BEFORE_SLACK_SECS: u64 = 120;

/// Which `AccessPolicy` the digest is bound to. The Anvil deployment (`contracts/deployments/
/// 31337.json`) until a testnet one exists and Z-1.H.11 embeds it; the signature is worthless
/// on any other chain, which is the point (T03).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deployment {
    /// EIP-155 chain id.
    pub chain_id: u64,
    /// `AccessPolicy` proxy address.
    pub policy: [u8; 20],
}

impl Deployment {
    /// The local development chain.
    pub const DEV: Deployment = Deployment {
        chain_id: 31337,
        policy: [
            0xdc, 0x64, 0xa1, 0x40, 0xaa, 0x3e, 0x98, 0x11, 0x00, 0xa9, 0xbe, 0xca, 0x4e, 0x68, 0x5f, 0x96,
            0x2f, 0x0c, 0xf6, 0xc9,
        ],
    };
}

/// A request waiting for the person, as the screen sees it. Nothing here comes from the
/// request except *what* is asked and *when*; the file's name and policy are this machine's.
#[derive(Debug, Clone, Serialize)]
pub struct Incoming {
    /// Request nonce, hex — the handle the screen answers with.
    pub id: String,
    /// The file's name from this machine's record, if it has one.
    pub file_name: Option<String>,
    /// Whether this machine locked the file.
    pub known: bool,
    /// Whether the request is for the version this machine wrote (T19).
    pub same_version: bool,
    /// `read_only` | `edit` — what the other person asked for.
    pub requested: &'static str,
    /// The owner's pre-approved permission for this file, from the record.
    pub default_permission: Option<String>,
    /// Unix seconds the request was made.
    pub asked_at: u64,
    /// Whether an allow is possible at all (known file, same version).
    pub can_allow: bool,
}

/// One request held for the person.
#[derive(Debug, Clone)]
pub struct PendingRequest {
    /// The request as received.
    pub request: AccessRequest,
    /// This machine's record of the file, if any.
    pub entry: Option<Entry>,
}

impl PendingRequest {
    /// What the screen shows.
    pub fn incoming(&self) -> Incoming {
        let same_version =
            self.entry.as_ref().is_some_and(|e| e.header_hash == hex::encode(self.request.header_hash));
        Incoming {
            id: hex::encode(self.request.nonce),
            file_name: self.entry.as_ref().map(|e| e.name.clone()),
            known: self.entry.is_some(),
            same_version,
            requested: if self.request.requested == 2 { "edit" } else { "read_only" },
            default_permission: self.entry.as_ref().map(|e| e.permission.clone()),
            asked_at: self.request.ts,
            can_allow: self.entry.is_some() && same_version,
        }
    }
}

/// The owner's answer, as the screen sends it.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionArg {
    /// 거절
    Deny,
    /// 읽기만
    ReadOnly,
    /// 편집도 가능
    Edit,
}

impl DecisionArg {
    fn permission(self) -> Permission {
        match self {
            Self::Deny => Permission::Deny,
            Self::ReadOnly => Permission::ReadOnly,
            Self::Edit => Permission::Edit,
        }
    }

    fn word(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::ReadOnly => "read_only",
            Self::Edit => "edit",
        }
    }
}

/// What happened after the person answered.
#[derive(Debug, Clone, Serialize)]
pub struct Answered {
    /// Request nonce, hex.
    pub id: String,
    /// `deny` | `read_only` | `edit`.
    pub decision: &'static str,
    /// EIP-712 struct hash of the terms (the on-chain `grantId`), hex, when allowed.
    pub grant_id: Option<String>,
    /// Unix seconds the approval expires, when allowed.
    pub expiry: Option<u64>,
    /// Whether the OS asked the person to confirm.
    pub confirmed_by_os: bool,
    /// What is still outstanding, as machine values.
    pub pending: Vec<&'static str>,
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Read one queued envelope as a request for `owner`, verifying the sender's own signature
/// with the key the request carries (T05). `None` for anything else.
pub fn accept_request(envelope: &Envelope, owner: &[u8], now: u64) -> Option<AccessRequest> {
    if envelope.kind != Kind::Req {
        return None;
    }
    let signed = Signed::from_bytes(&envelope.body).ok()?;
    // peek for the key, then verify the whole envelope against it
    let claimed: AccessRequest = ciborium::from_reader(signed.payload.as_slice()).ok()?;
    if zbacs_proto::identity::kid_of(&claimed.ed25519_pub) != claimed.device_kid
        || claimed.device_kid != signed.kid
    {
        return None;
    }
    let (request, ts) = signed.verify_queued::<AccessRequest>(&claimed.ed25519_pub).ok()?;
    if request.owner != owner {
        return None;
    }
    if ts > now + zbacs_proto::MAX_SKEW_SECS || now.saturating_sub(ts) > MAX_REQUEST_AGE_SECS {
        return None;
    }
    if !matches!(request.requested, 1 | 2) {
        return None;
    }
    Some(request)
}

/// The terms an allow puts on the wire: this file, this version, the asking device, and the
/// window and budget the owner chose when locking (never retyped now — ux_principles rule 4).
pub fn terms_for(
    request: &AccessRequest,
    entry: &Entry,
    permission: Permission,
    grant_nonce: u64,
    now: u64,
) -> AccessGrantTerms {
    AccessGrantTerms {
        file_id: request.fid,
        header_hash: request.header_hash,
        device_key_hash: device_key_hash(&request.x25519_pub, &request.ed25519_pub),
        permission: permission as u8,
        not_before: now.saturating_sub(NOT_BEFORE_SLACK_SECS),
        expiry: now + entry.ttl.max(60),
        max_opens: entry.max_opens,
        request_nonce: request.nonce,
        grant_nonce,
    }
}

/// Re-wrap the file's key for the asking device: open this owner's own envelope in the file
/// on disk, seal a new one to the requester's key, bound to the grant (aad = struct hash).
pub fn envelope_for(
    entry: &Entry,
    request: &AccessRequest,
    owner: &OwnerKeys,
    grant_id: &[u8; 32],
) -> Result<Vec<u8>, &'static str> {
    let file = std::fs::File::open(&entry.path).map_err(|e| {
        log::warn!("the locked file is no longer where it was: {e}");
        "file_moved"
    })?;
    let (header, header_hash) = zbacs_core::inspect(std::io::BufReader::new(file)).map_err(|e| {
        log::warn!("the locked file does not read back: {e}");
        "file_moved"
    })?;
    if header_hash.0 != request.header_hash {
        return Err("version");
    }
    let mine = header.body.env.iter().find(|e| e.kid == owner.sealing.key_id()).ok_or("not_mine")?;
    let dek = mine.open(&owner.sealing, &header.body.fid.0).map_err(|e| {
        log::warn!("cannot open my own envelope: {e}");
        "not_mine"
    })?;
    let wrapped = DekEnvelope::seal(&request.x25519_pub, &dek, grant_id).map_err(|_| "failed")?;
    let mut bytes = Vec::new();
    ciborium::into_writer(&wrapped, &mut bytes).map_err(|_| "failed")?;
    Ok(bytes)
}

/// Everything an answer needs from this machine.
pub struct Answering<'a> {
    /// The device's approval signer.
    pub signer: &'a dyn AuthProvider,
    /// Whether the owner chose OS confirmation for every approval on this device.
    pub device_setting: Confirmation,
    /// The owner's sealing keys, to re-wrap the file's key.
    pub owner: &'a OwnerKeys,
    /// The ledger, for the nonce.
    pub ledger: &'a Ledger,
    /// Which contract the signature is bound to.
    pub deployment: Deployment,
    /// The confirmation policy (T23).
    pub policy: &'a ConfirmationPolicy,
    /// Unix timestamps of this device's recent approvals, for the burst rule.
    pub recent: &'a [u64],
}

/// Answer one request: sign, re-wrap, send. Separate from the command so the whole path runs
/// in a test with a software signer and a real relay.
pub async fn answer(
    client: &RelayClient,
    pending: &PendingRequest,
    decision: DecisionArg,
    with: Answering<'_>,
) -> Result<Answered, &'static str> {
    let id = hex::encode(pending.request.nonce);
    let now = now();

    if decision == DecisionArg::Deny {
        let refusal = GrantMsg {
            request_nonce: pending.request.nonce,
            grant: None,
            owner_sig: None,
            envelope: None,
            tx_hash: None,
            decision: 0,
            ts: now,
        };
        client.send_grant(&refusal).await.map_err(|e| {
            log::warn!("cannot send the refusal: {e}");
            "relay_unreachable"
        })?;
        return Ok(Answered {
            id,
            decision: "deny",
            grant_id: None,
            expiry: None,
            confirmed_by_os: false,
            pending: vec![],
        });
    }

    let entry = pending.entry.as_ref().ok_or("unknown_file")?;
    if entry.header_hash != hex::encode(pending.request.header_hash) {
        return Err("version");
    }
    let permission = decision.permission();
    let grant_nonce = with.ledger.next_grant_nonce().map_err(|e| {
        log::warn!("cannot take a grant nonce: {e}");
        "failed"
    })?;
    let terms = terms_for(&pending.request, entry, permission, grant_nonce, now);
    let grant_id = terms.struct_hash();
    let digest = terms.digest(with.deployment.chain_id, &with.deployment.policy);

    // The OS prompt is the person's second look at an Edit or a burst of approvals (T23). It
    // is never weaker than what they chose at setup.
    let context = ApprovalContext { permission, file_id: terms.file_id };
    let confirmation = with.policy.required(&context, with.device_setting, with.recent, now);
    let assertion = with.signer.sign(&ApprovalChallenge { digest, context }, confirmation).map_err(|e| {
        log::warn!("approval signature failed: {e}");
        match e {
            zbacs_auth::AuthError::Cancelled => "cancelled",
            _ => "failed",
        }
    })?;
    let mut owner_sig = Vec::new();
    ciborium::into_writer(&assertion, &mut owner_sig).map_err(|_| "failed")?;

    let envelope = envelope_for(entry, &pending.request, with.owner, &grant_id)?;

    let grant = GrantMsg {
        request_nonce: pending.request.nonce,
        grant: Some(terms.to_cbor().map_err(|_| "failed")?),
        owner_sig: Some(owner_sig),
        envelope: Some(envelope),
        tx_hash: None,
        decision: permission as u8,
        ts: now,
    };
    client.send_grant(&grant).await.map_err(|e| {
        log::warn!("cannot send the approval: {e}");
        "relay_unreachable"
    })?;
    log::info!(
        "allowed: permission={permission:?} confirmed_by_os={} expires_in={}s",
        confirmation == Confirmation::OsUserVerification,
        terms.expiry.saturating_sub(now)
    );
    // Remembered so it can be listed and pulled back (Z-1.G.11). Sent first, recorded second:
    // an approval the other side never received is not one the owner needs to revoke.
    if let Err(e) = with.ledger.record_grant(&Grant {
        grant_id: hex::encode(grant_id),
        fid: entry.fid.clone(),
        file_name: entry.name.clone(),
        permission: decision.word().to_string(),
        expiry: terms.expiry,
        granted_at: now,
        revoked_at: None,
    }) {
        log::warn!("allowed, but could not record the approval for the list: {e}");
    }
    Ok(Answered {
        id,
        decision: decision.word(),
        grant_id: Some(hex::encode(grant_id)),
        expiry: Some(terms.expiry),
        confirmed_by_os: confirmation == Confirmation::OsUserVerification,
        pending: vec!["chain_grant"],
    })
}

/// What the "허락한 파일" screen shows for one approval.
#[derive(Debug, Clone, Serialize)]
pub struct Given {
    /// Grant id, hex — the handle a revoke names.
    pub grant_id: String,
    /// The file's name.
    pub file_name: String,
    /// `read_only` | `edit`.
    pub permission: String,
    /// Unix seconds it expires.
    pub expiry: u64,
    /// Unix seconds it was given.
    pub granted_at: u64,
    /// Whether it is still usable.
    pub active: bool,
    /// Whether the owner pulled it back.
    pub revoked: bool,
}

impl From<Grant> for Given {
    fn from(g: Grant) -> Self {
        let now = now();
        Self {
            active: g.is_active(now),
            revoked: g.revoked_at.is_some(),
            grant_id: g.grant_id,
            file_name: g.file_name,
            permission: g.permission,
            expiry: g.expiry,
            granted_at: g.granted_at,
        }
    }
}

/// Pull an approval back: tell the relay (which fans it out to every device that asked about
/// the file, T20) and mark it here. The chain revoke is Z-1.H.8. Separate from the command so
/// the two-machine test can drive it.
pub async fn revoke_now(
    client: &RelayClient,
    ledger: &Ledger,
    grant_id: &str,
) -> Result<Given, &'static str> {
    let grant = ledger.grant(grant_id).ok_or("unknown_grant")?;
    let mut id = [0u8; 32];
    hex::decode_to_slice(&grant.grant_id, &mut id).map_err(|_| "unknown_grant")?;
    let mut fid = [0u8; 32];
    hex::decode_to_slice(&grant.fid, &mut fid).map_err(|_| "unknown_grant")?;
    let now = now();
    client.send_revoke(&Revoke { grant_id: id, fid, ts: now }).await.map_err(|e| {
        log::warn!("cannot send the revoke: {e}");
        "relay_unreachable"
    })?;
    let marked = ledger.mark_revoked(grant_id, now).map_err(|_| "unknown_grant")?;
    log::info!("revoked an approval given {}s ago", now.saturating_sub(marked.granted_at));
    Ok(marked.into())
}

/// Read the owner inbox once and keep what is for this owner.
pub async fn next_requests(client: &RelayClient, owner: &[u8], ledger: &Ledger) -> Vec<PendingRequest> {
    let Ok(envelopes) = client.inbox_for_owner(owner).await else {
        return Vec::new();
    };
    let now = now();
    envelopes
        .iter()
        .filter_map(|e| accept_request(e, owner, now))
        .map(|request| {
            let entry = ledger.find(&request.fid);
            PendingRequest { request, entry }
        })
        .collect()
}

// ------------------------------------------------------------------ Agent state

/// Requests waiting for the person, and what the burst rule needs to remember.
#[derive(Default)]
pub struct Approvals {
    /// By request nonce, hex.
    pub pending: Mutex<HashMap<String, PendingRequest>>,
    /// Unix seconds of this device's recent allows.
    pub recent: Mutex<Vec<u64>>,
    /// Whether the inbox watcher is running.
    pub watching: AtomicBool,
}

fn client_for(app: &AppHandle) -> Result<(RelayClient, Vec<u8>), &'static str> {
    let profile = app
        .state::<Identity>()
        .0
        .lock()
        .expect("identity mutex")
        .as_ref()
        .map(|p| p.profile.clone())
        .ok_or("not_set_up")?;
    let keys = app.state::<SetupHost>().device_keys().map_err(|_| "not_set_up")?;
    let device = DeviceIdentity { keys: keys.envelope, signing: keys.signing };
    let client = RelayClient::new(relay_endpoints(), device).map_err(|_| "relay_unreachable")?;
    Ok((client, owner_account(&profile)))
}

/// Start reading the owner inbox, once. Called by the UI as soon as it knows the machine is
/// set up; harmless to call again.
#[tauri::command]
pub fn ensure_watching(app: AppHandle) -> Result<(), String> {
    let approvals = app.state::<Approvals>();
    if approvals.watching.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let (client, owner) = match client_for(&app) {
        Ok(v) => v,
        Err(e) => {
            approvals.watching.store(false, Ordering::SeqCst);
            return Err(e.to_string());
        }
    };
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        // The relay must know this device before it will take a grant from it; announcing
        // on every start also covers a relay that lost its registry.
        if let Err(e) = client.announce(None).await {
            log::warn!("cannot register with the relay yet: {e}");
        }
        loop {
            let ledger = handle.state::<Ledger>();
            let fresh = next_requests(&client, &owner, &ledger).await;
            if !fresh.is_empty() {
                let mut arrived = Vec::new();
                {
                    let approvals = handle.state::<Approvals>();
                    let mut pending = approvals.pending.lock().expect("approvals mutex");
                    for p in fresh {
                        let incoming = p.incoming();
                        if pending.insert(incoming.id.clone(), p).is_none() {
                            arrived.push(incoming);
                        }
                    }
                }
                for incoming in arrived {
                    log::info!(
                        "a request arrived: known={} can_allow={}",
                        incoming.known,
                        incoming.can_allow
                    );
                    if let Err(e) = handle.emit(APPROVAL_EVENT, &incoming) {
                        log::warn!("cannot show the request: {e}");
                    }
                }
                // The person has to see it: the Agent's whole job is to be there now (U-3).
                if let Some(window) = handle.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.unminimize();
                    let _ = window.set_focus();
                }
            }
            tokio::time::sleep(WATCH_INTERVAL).await;
        }
    });
    Ok(())
}

/// Requests waiting for the person, oldest first.
#[tauri::command]
pub fn pending_approvals(app: AppHandle) -> Vec<Incoming> {
    let approvals = app.state::<Approvals>();
    let pending = approvals.pending.lock().expect("approvals mutex");
    let mut list: Vec<Incoming> = pending.values().map(PendingRequest::incoming).collect();
    list.sort_by_key(|i| i.asked_at);
    list
}

/// Approvals this machine gave, newest first. Active ones first in the list the screen
/// shows; the rest stay visible for a while so "회수했어요" has something to point at.
#[tauri::command]
pub fn given_grants(app: AppHandle) -> Vec<Given> {
    let ledger = app.state::<Ledger>();
    ledger.grants(false, now()).into_iter().map(Given::from).collect()
}

/// The owner pulls an approval back.
#[tauri::command]
pub async fn revoke_grant(app: AppHandle, grant_id: String) -> Result<Given, String> {
    let (client, _owner) = client_for(&app).map_err(str::to_string)?;
    let ledger = app.state::<Ledger>();
    let given = revoke_now(&client, &ledger, &grant_id).await.map_err(str::to_string)?;
    if let Some(grant) = ledger.grant(&grant_id) {
        if let Ok(fid) = <[u8; 32]>::try_from(hex::decode(&grant.fid).unwrap_or_default()) {
            app.state::<crate::audit::AuditLog>().record(
                crate::audit::Kind::Revoked,
                crate::audit::Role::Owner,
                &fid,
                Some(&grant.file_name),
                None,
            );
        }
    }
    Ok(given)
}

/// The person answered. Off the UI thread: a real signer shows an OS prompt.
#[tauri::command]
pub async fn decide(app: AppHandle, id: String, decision: DecisionArg) -> Result<Answered, String> {
    let pending = {
        let approvals = app.state::<Approvals>();
        let map = approvals.pending.lock().expect("approvals mutex");
        map.get(&id).cloned().ok_or_else(|| "unknown_request".to_string())?
    };
    let (client, _owner) = client_for(&app).map_err(str::to_string)?;
    let (signer, device_setting) = {
        let identity = app.state::<Identity>();
        let held = identity.0.lock().expect("identity mutex");
        let prepared = held.as_ref().ok_or_else(|| "not_set_up".to_string())?;
        let setting = if prepared.profile.require_os_confirm {
            Confirmation::OsUserVerification
        } else {
            Confirmation::NotRequired
        };
        (prepared.signer.clone(), setting)
    };
    let owner = app.state::<SetupHost>().owner_keys().map_err(|_| "not_set_up".to_string())?;
    let recent: Vec<u64> = app.state::<Approvals>().recent.lock().expect("approvals mutex").clone();
    let policy = ConfirmationPolicy::default();

    let answered = {
        let ledger = app.state::<Ledger>();
        let with = Answering {
            signer: signer.as_ref(),
            device_setting,
            owner: &owner,
            ledger: &ledger,
            deployment: Deployment::DEV,
            policy: &policy,
            recent: &recent,
        };
        answer(&client, &pending, decision, with).await.map_err(str::to_string)?
    };

    let approvals = app.state::<Approvals>();
    approvals.pending.lock().expect("approvals mutex").remove(&id);
    if decision != DecisionArg::Deny {
        approvals.recent.lock().expect("approvals mutex").push(now());
    }
    app.state::<crate::audit::AuditLog>().record(
        if decision == DecisionArg::Deny { crate::audit::Kind::Denied } else { crate::audit::Kind::Granted },
        crate::audit::Role::Owner,
        &pending.request.fid,
        pending.entry.as_ref().map(|e| e.name.as_str()),
        Some(decision.word()),
    );
    Ok(answered)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(device: &DeviceIdentity, owner: &[u8], ts: u64) -> AccessRequest {
        AccessRequest {
            fid: [1; 32],
            header_hash: [2; 32],
            owner: owner.to_vec(),
            device_kid: device.kid(),
            x25519_pub: device.x25519_pub(),
            ed25519_pub: device.ed25519_pub(),
            requested: 1,
            nonce: [4; 16],
            hint: None,
            ts,
        }
    }

    fn queued(device: &DeviceIdentity, req: &AccessRequest) -> Envelope {
        let signed = Signed::sign(device, req, req.ts, [9; 16]).unwrap();
        Envelope { id: [1; 16], kind: Kind::Req, body: signed.to_bytes().unwrap(), queued_at: req.ts }
    }

    fn entry() -> Entry {
        Entry {
            fid: hex::encode([1; 32]),
            header_hash: hex::encode([2; 32]),
            name: "brief.docx".into(),
            path: "/nowhere/brief.docx.zbacs".into(),
            permission: "read_only".into(),
            ttl: 3600,
            max_opens: 3,
            sealed_at: 1_700_000_000,
        }
    }

    /// T05: the request must carry the key it was signed with, and be for this owner.
    #[test]
    fn t05_a_request_is_taken_only_from_its_own_signer_for_this_owner() {
        let bob = DeviceIdentity::generate().unwrap();
        let req = request(&bob, b"alice", 1_700_000_000);
        assert!(accept_request(&queued(&bob, &req), b"alice", 1_700_000_100).is_some());
        assert!(accept_request(&queued(&bob, &req), b"carol", 1_700_000_100).is_none(), "not this owner");

        let mut lying = req.clone();
        lying.ed25519_pub = DeviceIdentity::generate().unwrap().ed25519_pub();
        assert!(
            accept_request(&queued(&bob, &lying), b"alice", 1_700_000_100).is_none(),
            "key does not hash to kid"
        );

        let mallory = DeviceIdentity::generate().unwrap();
        assert!(
            accept_request(&queued(&mallory, &req), b"alice", 1_700_000_100).is_none(),
            "signed by someone else"
        );

        let mut wrong_kind = queued(&bob, &req);
        wrong_kind.kind = Kind::Grant;
        assert!(accept_request(&wrong_kind, b"alice", 1_700_000_100).is_none());
    }

    #[test]
    fn a_request_may_be_old_but_not_ancient_or_from_the_future() {
        let bob = DeviceIdentity::generate().unwrap();
        let hours_old = request(&bob, b"alice", 1_700_000_000);
        assert!(accept_request(&queued(&bob, &hours_old), b"alice", 1_700_000_000 + 6 * 3600).is_some());
        assert!(accept_request(&queued(&bob, &hours_old), b"alice", 1_700_000_000 + 25 * 3600).is_none());
        let future = request(&bob, b"alice", 1_700_010_000);
        assert!(accept_request(&queued(&bob, &future), b"alice", 1_700_000_000).is_none());
    }

    /// T06: what the screen shows comes from this machine's record.
    #[test]
    fn t06_the_screen_shows_the_record_not_the_request() {
        let bob = DeviceIdentity::generate().unwrap();
        let req = request(&bob, b"alice", 1_700_000_000);

        let known = PendingRequest { request: req.clone(), entry: Some(entry()) }.incoming();
        assert_eq!(known.file_name.as_deref(), Some("brief.docx"));
        assert!(known.known && known.same_version && known.can_allow);
        assert_eq!(known.requested, "read_only");
        assert_eq!(known.default_permission.as_deref(), Some("read_only"));

        let unknown = PendingRequest { request: req.clone(), entry: None }.incoming();
        assert!(unknown.file_name.is_none());
        assert!(!unknown.can_allow, "no record, no key, no allow");

        let mut older = entry();
        older.header_hash = hex::encode([7; 32]);
        let other_version = PendingRequest { request: req, entry: Some(older) }.incoming();
        assert!(other_version.known && !other_version.same_version && !other_version.can_allow);
    }

    #[test]
    fn the_terms_bind_file_version_device_and_the_owners_own_policy() {
        let bob = DeviceIdentity::generate().unwrap();
        let req = request(&bob, b"alice", 1_700_000_000);
        let t = terms_for(&req, &entry(), Permission::Edit, 5, 1_700_000_000);
        assert_eq!(t.file_id, req.fid);
        assert_eq!(t.header_hash, req.header_hash);
        assert_eq!(t.device_key_hash, device_key_hash(&bob.x25519_pub(), &bob.ed25519_pub()));
        assert_eq!(t.permission, 2);
        assert_eq!(t.not_before, 1_700_000_000 - NOT_BEFORE_SLACK_SECS);
        assert_eq!(t.expiry, 1_700_000_000 + 3600, "the ttl chosen at lock time");
        assert_eq!(t.max_opens, 3);
        assert_eq!(t.request_nonce, req.nonce);
        assert_eq!(t.grant_nonce, 5);
    }

    #[test]
    fn the_dev_deployment_is_the_anvil_policy_proxy() {
        assert_eq!(Deployment::DEV.chain_id, 31337);
        assert_eq!(hex::encode(Deployment::DEV.policy), "dc64a140aa3e981100a9beca4e685f962f0cf6c9");
    }
}
