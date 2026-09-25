//! The open session as the person sees it (ui_guideline S6/S7): [열기] → the file is in front
//! of them in the usual application → they save or close → it is locked again.
//!
//! This is the glue between the pieces that already exist: [`crate::open`] (decrypt into the
//! workspace, reseal on save), [`zbacs_session::Viewer`] (the application), the
//! [`zbacs_session::SaveWatcher`] (their save), and the grant watcher in [`crate::request`]
//! (the owner's revoke or the clock). One loop per open file, on a blocking thread, ends the
//! session on whichever comes first — the viewer quitting, "지금 잠그기", a revoke, expiry —
//! and always wipes (T09).
//!
//! What the screen gets is a phase, never a path or a key: `opened`, `saved`, `resealed`,
//! `discarded`, `closed`, `revoked`, `expired`, `problem`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use zbacs_core::{DeviceKeys, Permission, SigningKeys};
use zbacs_relay_client::RelayClient;
use zbacs_session::{Effect, Event, SaveEvent, SaveWatcher, State, Viewer, Workspace, DEFAULT_DEBOUNCE};

use crate::audit::{AuditLog, Kind, Role};
use crate::open::{close, materialise, save};
use crate::request::{relay_endpoints, Held, Requests};
use crate::setup::SetupHost;

/// Event the webview listens for while a file is open.
pub const SESSION_EVENT: &str = "zbacs://session";
/// Every machine value opening can hand the UI (Z-1.U.4), `open.rs`'s and this module's.
pub const OPEN_PROBLEMS: &[&str] = &[
    "not_granted",
    "envelope",
    "version",
    "opens_exhausted",
    "workspace",
    "damaged",
    "missing",
    "no_owner_key",
    "not_saving",
    "already_open",
    "no_viewer",
    "relay_unreachable",
    "not_set_up",
    "failed",
];
/// Developer override: `ZBACS_VIEWER="prog arg1 arg2"` starts that program with the file as
/// its last argument, tracked; unset, the OS's associated application opens it.
pub const VIEWER_ENV: &str = "ZBACS_VIEWER";
/// How long a viewer gets to close on its own after a revoke before it is stopped (T20).
pub const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// A progress report for the screen.
#[derive(Debug, Clone, Serialize)]
pub struct Update {
    /// Which file.
    pub path: String,
    /// `opened` | `saved` | `resealed` | `discarded` | `closed` | `revoked` | `expired` | `problem`.
    pub phase: &'static str,
    /// `read_only` | `edit`.
    pub permission: &'static str,
    /// Unix seconds the approval expires.
    pub expiry: u64,
    /// New container version after a reseal.
    pub version: Option<u32>,
    /// Machine value when `phase == problem`.
    pub problem: Option<&'static str>,
}

/// Which program shows the file.
#[derive(Debug, Clone, Default)]
pub struct ViewerSpec {
    /// A program and its leading arguments; the file goes last. `None` = OS default.
    pub program: Option<(String, Vec<String>)>,
}

impl ViewerSpec {
    /// From the environment (developer boxes and tests), else the OS default.
    pub fn from_env() -> Self {
        let Some(raw) = std::env::var(VIEWER_ENV).ok().filter(|s| !s.trim().is_empty()) else {
            return Self::default();
        };
        let mut parts = raw.split_whitespace().map(str::to_string);
        let program = parts.next().expect("non-empty");
        Self { program: Some((program, parts.collect())) }
    }

    fn launch(&self, file: &Path) -> Result<Viewer, &'static str> {
        let launched = match &self.program {
            Some((program, args)) => {
                let mut all: Vec<std::ffi::OsString> = args.iter().map(Into::into).collect();
                all.push(file.as_os_str().to_os_string());
                Viewer::launch_with(program, all, file)
            }
            None => Viewer::launch_default(file),
        };
        launched.map_err(|e| {
            log::warn!("cannot start the viewer: {e}");
            "no_viewer"
        })
    }
}

/// How a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// The viewer quit or the person chose 지금 잠그기.
    Closed,
    /// The owner pulled the approval back while it was open.
    Revoked,
    /// The approval's window closed while it was open.
    Expired,
    /// Something went wrong; the workspace was still wiped.
    Failed(&'static str),
}

/// Everything one session needs from the machine.
pub struct Running<'a> {
    /// The relay, for the version notice on save.
    pub client: &'a RelayClient,
    /// The sealed file on disk.
    pub sealed: &'a Path,
    /// The grant, in `Granted`.
    pub held: Held,
    /// This device's envelope key.
    pub device: &'a DeviceKeys,
    /// This device's signing key, for a recipient reseal.
    pub signer: &'a SigningKeys,
    /// Where workspaces go.
    pub base: &'a Path,
    /// Which program shows the file.
    pub viewer: ViewerSpec,
    /// "지금 잠그기" and revoke/expiry from outside.
    pub cancel: Arc<AtomicBool>,
    /// Tells whether the owner ended the grant meanwhile: `Some(Revoked | Closed)`.
    pub outside: Arc<dyn Fn() -> Option<State> + Send + Sync>,
    /// The record.
    pub audit: Option<&'a AuditLog>,
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn permission_word(p: Option<Permission>) -> &'static str {
    match p {
        Some(Permission::Edit) => "edit",
        _ => "read_only",
    }
}

/// Run one session to its end on the calling (blocking) thread. `on_update` gets every phase.
///
/// Separate from the command so a test can run it with a scripted viewer and no webview.
pub fn run_session(
    handle: tokio::runtime::Handle,
    mut running: Running<'_>,
    mut on_update: impl FnMut(Update),
) -> (End, Held) {
    let path = running.sealed.display().to_string();
    let expiry = running.held.terms.as_ref().map(|t| t.expiry).unwrap_or(0);
    let permission = permission_word(running.held.session.permission());
    let fid = running.held.terms.as_ref().map(|t| t.file_id).unwrap_or([0; 32]);
    let mut report = |phase: &'static str, version: Option<u32>, problem: Option<&'static str>| {
        on_update(Update { path: path.clone(), phase, permission, expiry, version, problem });
    };

    let session_id = format!("s{}-{}", now(), std::process::id());
    let mat = match materialise(running.sealed, &mut running.held, running.device, running.base, &session_id)
    {
        Ok(m) => m,
        Err(e) => {
            report("problem", None, Some(e));
            return (End::Failed(e), running.held);
        }
    };
    let mut viewer = match running.viewer.launch(&mat.plain) {
        Ok(v) => v,
        Err(e) => {
            let _ = close(mat, &mut running.held, Event::Failed("no_viewer"));
            report("problem", None, Some(e));
            return (End::Failed(e), running.held);
        }
    };
    let watcher = SaveWatcher::watch(&mat.plain, DEFAULT_DEBOUNCE).ok();
    if let Some(audit) = running.audit {
        audit.record(Kind::Opened, Role::Recipient, &fid, Some(&mat.name), Some(permission));
    }
    report("opened", None, None);

    let end = loop {
        if running.cancel.load(Ordering::Relaxed) {
            break End::Closed;
        }
        match (running.outside)() {
            Some(State::Revoked) => break End::Revoked,
            Some(State::Closed) => break End::Expired,
            _ => {}
        }
        if now() >= expiry {
            break End::Expired;
        }
        if viewer.is_running() == Some(false) {
            break End::Closed;
        }
        let event = watcher.as_ref().and_then(|w| w.next_event(Duration::from_millis(300)));
        if watcher.is_none() {
            std::thread::sleep(Duration::from_millis(300));
        }
        match event {
            Some(SaveEvent::Saved) => match running.held.session.apply(Event::Saved, now()) {
                Ok(effects) if effects.contains(&Effect::Reseal) => {
                    report("saved", None, None);
                    let saved = handle.block_on(save(
                        running.client,
                        running.sealed,
                        &mat,
                        &mut running.held,
                        running.device,
                        running.signer,
                    ));
                    match saved {
                        Ok(s) => {
                            if let Some(audit) = running.audit {
                                audit.record(
                                    Kind::Sealed,
                                    Role::Recipient,
                                    &fid,
                                    Some(&mat.name),
                                    Some("resealed"),
                                );
                            }
                            report("resealed", Some(s.ver), None);
                        }
                        Err(e) => {
                            // The plaintext is still in the workspace; the session goes on so
                            // the person can try saving again, and the wipe at the end stands.
                            log::warn!("save did not become a version: {e}");
                            report("problem", None, Some(e));
                            let _ = running.held.session.apply(Event::Failed(e), now());
                            break End::Failed(e);
                        }
                    }
                }
                Ok(_) => report("discarded", None, None),
                Err(e) => log::warn!("save ignored by the session: {e}"),
            },
            Some(SaveEvent::Vanished) => log::warn!("the workspace file vanished; waiting for the viewer"),
            None => {}
        }
    };

    // Ending: ask the viewer to close, give it a moment, then stop it; wipe either way.
    let _ = viewer.request_close();
    if !viewer.wait_timeout(CLOSE_GRACE) {
        let _ = viewer.kill();
    }
    let event = match end {
        End::Closed => Event::ViewerExited,
        End::Revoked => Event::Revoked,
        End::Expired => Event::Expired,
        End::Failed(reason) => Event::Failed(reason),
    };
    let _ = close(mat, &mut running.held, event);
    let (phase, kind) = match end {
        End::Closed => ("closed", None),
        End::Revoked => ("revoked", Some(Kind::Revoked)),
        End::Expired => ("expired", Some(Kind::Expired)),
        End::Failed(_) => ("problem", None),
    };
    if let (Some(audit), Some(kind)) = (running.audit, kind) {
        audit.record(kind, Role::Recipient, &fid, None, None);
    }
    match end {
        End::Failed(reason) => report(phase, None, Some(reason)),
        _ => report(phase, None, None),
    }
    (end, running.held)
}

// ------------------------------------------------------------------ Agent state

/// One open file.
pub struct Open {
    /// "지금 잠그기".
    pub cancel: Arc<AtomicBool>,
    /// The file's name, for the screen.
    pub name: String,
}

/// Files open right now, by sealed path.
#[derive(Default)]
pub struct Sessions(pub Mutex<HashMap<String, Open>>);

/// What the screen shows after [열기].
#[derive(Debug, Clone, Serialize)]
pub struct Opened {
    /// `read_only` | `edit`.
    pub permission: &'static str,
    /// Unix seconds the approval expires.
    pub expiry: u64,
}

/// Open a granted file: decrypt into the workspace, start the application, keep watch.
#[tauri::command]
pub async fn open_file(app: AppHandle, path: String) -> Result<Opened, String> {
    let held = {
        let requests = app.state::<Requests>();
        let map = requests.0.lock().expect("requests mutex");
        map.get(&path).and_then(|a| a.held.clone()).ok_or("not_granted")?
    };
    if held.session.state() != State::Granted {
        return Err("not_granted".into());
    }
    {
        let sessions = app.state::<Sessions>();
        if sessions.0.lock().expect("sessions mutex").contains_key(&path) {
            return Err("already_open".into());
        }
    }
    let keys = app.state::<SetupHost>().device_keys().map_err(|_| "not_set_up".to_string())?;
    let (device, signer) = (keys.envelope, keys.signing);
    let relay_keys = app.state::<SetupHost>().device_keys().map_err(|_| "not_set_up".to_string())?;
    let client = RelayClient::new(
        relay_endpoints(),
        zbacs_proto::DeviceIdentity { keys: relay_keys.envelope, signing: relay_keys.signing },
    )
    .map_err(|_| "relay_unreachable".to_string())?;

    let cancel = Arc::new(AtomicBool::new(false));
    let expiry = held.terms.as_ref().map(|t| t.expiry).unwrap_or(0);
    let permission = permission_word(held.session.permission());
    app.state::<Sessions>()
        .0
        .lock()
        .expect("sessions mutex")
        .insert(path.clone(), Open { cancel: cancel.clone(), name: String::new() });

    let handle = tauri::async_runtime::handle().inner().clone();
    let outside_app = app.clone();
    let outside_path = path.clone();
    let outside: Arc<dyn Fn() -> Option<State> + Send + Sync> = Arc::new(move || {
        let requests = outside_app.state::<Requests>();
        let map = requests.0.lock().expect("requests mutex");
        map.get(&outside_path).and_then(|a| a.held.as_ref()).map(|h| h.session.state())
    });
    let reporter = app.clone();
    let sealed = PathBuf::from(&path);
    let base = Workspace::default_base();
    let key = path.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let audit = reporter.state::<AuditLog>();
        let running = Running {
            client: &client,
            sealed: &sealed,
            held,
            device: &device,
            signer: &signer,
            base: &base,
            viewer: ViewerSpec::from_env(),
            cancel,
            outside,
            audit: Some(&audit),
        };
        let (end, held) = run_session(handle, running, |u| {
            if let Err(e) = reporter.emit(SESSION_EVENT, &u) {
                log::warn!("cannot report the session: {e}");
            }
        });
        log::info!("session ended: {end:?}");
        // the card shows what the session became: Granted again (more opens), Closed, Revoked…
        let requests = reporter.state::<Requests>();
        if let Some(active) = requests.0.lock().expect("requests mutex").get_mut(&key) {
            active.held = Some(held);
        }
        reporter.state::<Sessions>().0.lock().expect("sessions mutex").remove(&key);
    });
    Ok(Opened { permission, expiry })
}

/// "지금 잠그기": end the session now.
#[tauri::command]
pub fn lock_now(app: AppHandle, path: String) -> Result<(), String> {
    let sessions = app.state::<Sessions>();
    let map = sessions.0.lock().expect("sessions mutex");
    let open = map.get(&path).ok_or("not_granted")?;
    open.cancel.store(true, Ordering::Relaxed);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_viewer_override_is_a_program_and_leading_arguments() {
        let spec = ViewerSpec { program: Some(("sh".into(), vec!["-c".into(), "true".into()])) };
        assert_eq!(spec.program.as_ref().unwrap().1.len(), 2);
        assert!(ViewerSpec::default().program.is_none(), "no override = the OS default");
    }

    #[test]
    fn every_open_problem_is_a_known_word() {
        for id in OPEN_PROBLEMS {
            assert!(id.chars().all(|c| c.is_ascii_lowercase() || c == '_'), "{id}");
        }
    }
}
