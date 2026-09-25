//! The recipient's open step (Z-1.G.7, the first half of Z-1.G.8): from a held grant to a
//! plaintext file in a protected workspace, and back to nothing.
//!
//! What comes in is what Z-1.G.9 kept: the owner's terms and the DEK envelope wrapped for this
//! device, bound to the grant (`aad = grantId`). What goes out is a file in a workspace the
//! session state machine controls: read-only when the owner said 읽기만 (T07), wiped when the
//! session ends however it ends (T09).
//!
//! No viewer is launched here; that is [`zbacs_session::Viewer`]'s job and the UI's (S6). This
//! module is the part the E2E harness can run headless, and the Agent command will wrap.
//!
//! [`save`] is the other half of Z-1.G.8: an edited file becomes the next version, signed by
//! this device and with the DEK wrapped to the owner's public key from the header (spec §5),
//! and the owner is told through the relay so the version can be granted again (§4.6).

use std::path::{Path, PathBuf};

use zbacs_core::{DeviceKeys, Permission, SigningKeys};
use zbacs_proto::VersionMsg;
use zbacs_relay_client::RelayClient;
use zbacs_session::{Effect, Event, State, Workspace};

use crate::request::Held;

/// A file opened into a workspace.
#[derive(Debug)]
pub struct Materialised {
    /// The workspace holding the plaintext.
    pub workspace: Workspace,
    /// The plaintext file inside it.
    pub plain: PathBuf,
    /// The original file name, from the container.
    pub name: String,
    /// Effects the state machine asked for on open, already carried out here except
    /// `LaunchViewer` and `Audit`, which the caller owns.
    pub effects: Vec<Effect>,
}

/// Decrypt a granted file into a fresh workspace and move the session to `Open`.
///
/// Refuses anything the state machine refuses (an exhausted budget, a session that is not
/// `Granted`) and anything the envelope refuses (a grant for another device, another grant).
pub fn materialise(
    sealed: &Path,
    held: &mut Held,
    device: &DeviceKeys,
    base: &Path,
    session_id: &str,
) -> Result<Materialised, &'static str> {
    let terms = held.terms.as_ref().ok_or("not_granted")?;
    let envelope_bytes = held.envelope.as_ref().ok_or("not_granted")?;
    if held.session.state() != State::Granted {
        return Err("not_granted");
    }
    let grant_id = terms.struct_hash();
    let envelope: zbacs_core::Envelope =
        ciborium::from_reader(envelope_bytes.as_slice()).map_err(|_| "envelope")?;
    let dek = envelope.open(device, &grant_id).map_err(|e| {
        log::warn!("the grant's envelope does not open for this device: {e}");
        "envelope"
    })?;

    let (header, header_hash, rest) =
        zbacs_core::read_header(std::io::BufReader::new(std::fs::File::open(sealed).map_err(|_| "missing")?))
            .map_err(|_| "damaged")?;
    if header_hash.0 != terms.header_hash {
        // the file on disk is not the version the owner approved (T19)
        return Err("version");
    }

    // Ask the state machine first: it counts the open (T03) and may close instead.
    let now = now();
    let effects = held.session.apply(Event::Opened, now).map_err(|e| {
        log::warn!("open refused by the session: {e}");
        "not_granted"
    })?;
    if effects.contains(&Effect::WipeWorkspace) {
        return Err("opens_exhausted");
    }

    let workspace = Workspace::create(base, session_id).map_err(|e| {
        log::warn!("cannot create the workspace: {e}");
        "workspace"
    })?;
    let plain = workspace.file("opened.bin").map_err(|_| "workspace")?;
    let opened = {
        let out = std::fs::File::create(&plain).map_err(|_| "workspace")?;
        zbacs_core::open_with_dek(header, header_hash, rest, out, &dek).map_err(|e| {
            log::warn!("cannot open the file with the granted key: {e}");
            "damaged"
        })
    };
    let opened = match opened {
        Ok(o) => o,
        Err(e) => {
            let _ = workspace.wipe();
            return Err(e);
        }
    };
    // Keep the real name so the viewer picks the right application; the workspace file is
    // renamed inside the workspace only.
    let named = workspace.file(&opened.file_name).map_err(|_| "workspace")?;
    std::fs::rename(&plain, &named).map_err(|_| "workspace")?;
    if effects.contains(&Effect::MarkReadOnly) {
        workspace.mark_read_only(&opened.file_name).map_err(|_| "workspace")?;
    }
    log::info!(
        "opened into the workspace: permission={:?} opens={}",
        held.session.permission(),
        held.session.opens()
    );
    Ok(Materialised { workspace, plain: named, name: opened.file_name, effects })
}

/// The viewer went away (or the session was ended from outside): apply what the state machine
/// says and wipe. A ReadOnly workspace that was written to is discarded, not kept (T07).
pub fn close(mat: Materialised, held: &mut Held, event: Event) -> Result<Vec<Effect>, &'static str> {
    let effects = held.session.apply(event, now()).map_err(|_| "session")?;
    if mat.workspace.path().exists() {
        // a read-only file cannot be overwritten with zeros until it is writable again
        let _ = mat.workspace.clear_read_only(&mat.name);
        mat.workspace.wipe().map_err(|e| {
            log::warn!("wipe failed: {e}");
            "wipe"
        })?;
    }
    Ok(effects)
}

/// What [`save`] produced.
#[derive(Debug, Clone)]
pub struct Saved {
    /// The new version number.
    pub ver: u32,
    /// Header hash of the new version (what the owner must accept, T19).
    pub header_hash: [u8; 32],
    /// The notice sent to the owner.
    pub notice: VersionMsg,
}

/// The viewer saved an `Edit` session: reseal the edited plaintext over the container as the
/// next version and tell the owner (Z-1.G.8).
///
/// The session must be in `Resealing` (the caller applied `Event::Saved` and got `Reseal`).
/// The container is replaced atomically; the workspace file stays until the session ends.
pub async fn save(
    client: &RelayClient,
    sealed: &Path,
    mat: &Materialised,
    held: &mut Held,
    device: &DeviceKeys,
    signer: &SigningKeys,
) -> Result<Saved, &'static str> {
    if held.session.state() != State::Resealing {
        return Err("not_saving");
    }
    let terms = held.terms.as_ref().ok_or("not_granted")?;
    let envelope_bytes = held.envelope.as_ref().ok_or("not_granted")?;
    let grant_id = terms.struct_hash();
    let envelope: zbacs_core::Envelope =
        ciborium::from_reader(envelope_bytes.as_slice()).map_err(|_| "envelope")?;
    let dek = envelope.open(device, &grant_id).map_err(|_| "envelope")?;

    let (prev, prev_hash) =
        zbacs_core::inspect(std::io::BufReader::new(std::fs::File::open(sealed).map_err(|_| "missing")?))
            .map_err(|_| "damaged")?;
    if prev_hash.0 != terms.header_hash {
        return Err("version");
    }
    let policy = prev.body.pol.clone();
    let header =
        zbacs_core::reseal_as_recipient_to_path(&mat.plain, sealed, &dek, signer, policy).map_err(|e| {
            log::warn!("reseal failed: {e}");
            match e {
                zbacs_core::Error::NoOwnerKey => "no_owner_key",
                _ => "failed",
            }
        })?;
    let (_, new_hash) =
        zbacs_core::inspect(std::io::BufReader::new(std::fs::File::open(sealed).map_err(|_| "missing")?))
            .map_err(|_| "damaged")?;
    let mut owner_envelope = Vec::new();
    ciborium::into_writer(&header.body.env[0], &mut owner_envelope).map_err(|_| "failed")?;

    let notice = VersionMsg {
        fid: header.body.fid.0,
        owner: header.body.own.clone(),
        prev_header_hash: prev_hash.0,
        header_hash: new_hash.0,
        ver: header.body.ver,
        grant_id,
        owner_envelope,
        ed25519_pub: signer.verifying_key().to_bytes(),
        ts: now(),
    };
    client.send_version(&notice).await.map_err(|e| {
        log::warn!("the owner could not be told about the new version: {e}");
        "relay_unreachable"
    })?;
    let _ = held.session.apply(Event::Resealed { version: header.body.ver }, now());
    log::info!("resealed as version {} and told the owner", header.body.ver);
    Ok(Saved { ver: header.body.ver, header_hash: new_hash.0, notice })
}

/// Whether the owner allowed editing this session.
pub fn can_edit(held: &Held) -> bool {
    held.session.permission() == Some(Permission::Edit)
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
