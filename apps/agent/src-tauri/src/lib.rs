//! Z-1.G.1 — the Agent's shell: one instance, a tray, and a `.zbacs` double-click that lands
//! in the right window.
//!
//! This is the skeleton the rest of the G track fills in. What it does today:
//!
//! - **One instance.** A second double-click hands its path to the running Agent instead of
//!   starting a rival that would fight over the same workspace and session state.
//! - **A tray.** The Agent's job is to be there when a request arrives, so its normal state is
//!   a tray icon with the window closed, not a window the person has to keep open.
//! - **Reads a sealed file's header.** No keys are needed to see that a file is a Z-BACS
//!   container, which version it is and what the owner's default permission was — enough to
//!   show "this is locked, shall I ask the owner?" before any approval exists.
//!
//! Z-1.G.2 added the first run: two taps and the Agent has this machine's keys and the owner's
//! chosen approval style (see [`setup`]). Z-1.G.3 added locking (see [`seal`]) and Z-1.G.9
//! asking the owner and waiting for the answer (see [`request`]). Opening the file after an
//! approval is still ahead, and the UI says so rather than pretending.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::Serialize;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, RunEvent, State};

pub mod request;
pub mod seal;
pub mod setup;

/// Event the webview listens for when a file is handed to the Agent.
pub const OPENED_EVENT: &str = "zbacs://opened";

/// What the UI is told about a file the person double-clicked.
///
/// Note what is *not* here: the file name, which is encrypted, and the owner's identity, which
/// the container does not carry in a readable form. The UI shows the state, not the internals.
#[derive(Debug, Clone, Serialize)]
pub struct OpenedFile {
    /// Path on this machine.
    pub path: String,
    /// Whether this really is a Z-BACS container.
    pub sealed: bool,
    /// Version number of the sealed container.
    pub version: Option<u32>,
    /// Owner's default permission: "read-only" | "edit" | "deny".
    pub default_permission: Option<String>,
    /// Size of the sealed content in bytes.
    pub size: Option<u64>,
    /// Technical summary, for the developer panel only.
    pub detail: Option<String>,
    /// Why the file could not be read, in words a person can act on.
    pub problem: Option<String>,
}

/// Files pending because they arrived before the webview was listening.
#[derive(Default)]
pub struct Pending(pub Mutex<Vec<OpenedFile>>);

/// Paths handed to the process by the shell. Ignores flags and anything that is not `.zbacs`.
pub fn files_from_args<I: IntoIterator<Item = String>>(args: I) -> Vec<PathBuf> {
    args.into_iter()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .map(PathBuf::from)
        .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("zbacs")))
        .collect()
}

fn permission_word(p: zbacs_core::Permission) -> &'static str {
    match p {
        zbacs_core::Permission::Deny => "deny",
        zbacs_core::Permission::ReadOnly => "read-only",
        zbacs_core::Permission::Edit => "edit",
    }
}

/// Read what a sealed file will tell anyone, without a key.
pub fn inspect_file(path: &Path) -> OpenedFile {
    let mut out = OpenedFile {
        path: path.display().to_string(),
        sealed: false,
        version: None,
        default_permission: None,
        size: None,
        detail: None,
        problem: None,
    };
    let opened = File::open(path).map(BufReader::new).map_err(zbacs_core::Error::from);
    match opened.and_then(zbacs_core::inspect) {
        Ok((header, header_hash)) => {
            out.sealed = true;
            out.version = Some(header.body.ver);
            out.default_permission = Some(permission_word(header.body.pol.default).to_string());
            out.size = Some(header.body.plen);
            out.detail = Some(format!(
                "fid={} header={} ver={} chunk={} envelopes={}",
                header.body.fid,
                header_hash,
                header.body.ver,
                header.body.chunk,
                header.body.env.len()
            ));
        }
        Err(zbacs_core::Error::BadMagic) => {
            out.problem = Some("이 파일은 Z-BACS로 잠근 파일이 아닙니다.".into());
        }
        Err(zbacs_core::Error::UnsupportedVersion(major, _)) => {
            out.problem =
                Some(format!("더 새로운 방식(v{major})으로 잠긴 파일입니다. 앱을 업데이트해 주세요."));
        }
        Err(e) => {
            log::warn!("cannot read container: {e}");
            out.problem = Some("파일이 손상되었거나 읽을 수 없습니다.".into());
        }
    }
    out
}

/// Show the window and send it the files, remembering them if it is not listening yet.
pub fn deliver(app: &AppHandle, paths: &[PathBuf]) {
    if paths.is_empty() {
        return;
    }
    let files: Vec<OpenedFile> = paths.iter().map(|p| inspect_file(p)).collect();
    for file in &files {
        log::info!("handed a file: {} sealed={} version={:?}", file.path, file.sealed, file.version);
    }
    show_window(app);

    // Always remember, and always emit. A file handed over before the webview finished loading
    // would otherwise be lost, and one handed over after would sit unseen in the queue. The UI
    // keys on the path, so seeing the same file from both routes shows one card.
    if let Some(pending) = app.try_state::<Pending>() {
        pending.0.lock().expect("pending mutex").extend(files.clone());
    }
    if let Err(e) = app.emit(OPENED_EVENT, &files) {
        log::warn!("webview not listening yet, kept {} file(s) pending: {e}", files.len());
    }
}

fn show_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Files that arrived before the webview was ready. The UI calls this once on load.
#[tauri::command]
fn take_pending(pending: State<'_, Pending>) -> Vec<OpenedFile> {
    std::mem::take(&mut *pending.0.lock().expect("pending mutex"))
}

/// Inspect a path the UI already knows about (drag and drop, or a retry).
#[tauri::command]
fn inspect_path(path: String) -> OpenedFile {
    inspect_file(Path::new(&path))
}

/// The screen the person is now looking at.
///
/// Worth a log line for one reason: when a first run goes wrong on someone's machine, this is
/// the only trace of how far they got. It carries a screen name, never their content.
#[tauri::command]
fn ui_screen(name: String) {
    log::info!("screen: {name}");
}

/// Something went wrong before the UI could show anything.
#[tauri::command]
fn ui_problem(detail: String) {
    log::warn!("the first screen could not start: {detail}");
}

/// What the Agent can do so far, so the UI can be honest about the rest.
#[tauri::command]
fn capabilities() -> serde_json::Value {
    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "readSealedFiles": true,
        "onboarding": true,    // Z-1.G.2
        "sealing": true,       // Z-1.G.3
        "requestAccess": true, // Z-1.G.9
        "openFile": false      // Z-1.G.7/G.8
    })
}

/// Build and run the Agent.
pub fn run() {
    let launch_files = files_from_args(std::env::args());

    tauri::Builder::default()
        .plugin(
            tauri_plugin_log::Builder::new()
                .level(log::LevelFilter::Info)
                // clear first: `target` adds to the defaults, which would log every line twice
                .clear_targets()
                .target(tauri_plugin_log::Target::new(tauri_plugin_log::TargetKind::Stdout))
                .build(),
        )
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            // Another double-click while we are running: take its file, keep one Agent.
            log::info!("second instance handed over {} argument(s)", argv.len());
            deliver(app, &files_from_args(argv));
        }))
        .manage(Pending::default())
        .manage(setup::Identity::default())
        .manage(request::Requests::default())
        .invoke_handler(tauri::generate_handler![
            take_pending,
            inspect_path,
            capabilities,
            ui_screen,
            ui_problem,
            setup::setup_status,
            setup::complete_setup,
            seal::examine_path,
            seal::seal_file,
            seal::shred_original,
            request::request_access,
            request::cancel_request
        ])
        .setup(move |app| {
            let handle = app.handle().clone();
            let config_dir = handle.path().app_config_dir().unwrap_or_else(|e| {
                log::warn!("no app config directory ({e}); falling back to the working directory");
                std::path::PathBuf::from(".")
            });
            handle.manage(setup::SetupHost::new(config_dir));
            setup::restore(&handle);
            build_tray(&handle)?;
            if launch_files.is_empty() {
                // Started by the person rather than by a file: show the window so they see
                // something happened.
                show_window(&handle);
            } else {
                deliver(&handle, &launch_files);
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("build the Agent")
        .run(|app, event| {
            // macOS hands files over as an event rather than as arguments; the variant only
            // exists there, so the match is behind a cfg.
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            if let RunEvent::Opened { urls } = &event {
                let paths: Vec<PathBuf> = urls.iter().filter_map(|u| u.to_file_path().ok()).collect();
                deliver(app, &paths);
            }
            #[cfg(not(any(target_os = "macos", target_os = "ios")))]
            let _ = app;

            // Closing the window leaves the Agent in the tray: it has to be there when an
            // approval arrives, and quitting is an explicit choice in the tray menu.
            if let RunEvent::ExitRequested { api, .. } = event {
                api.prevent_exit();
            }
        });
}

fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "창 열기", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "종료", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &quit])?;

    TrayIconBuilder::with_id("zbacs")
        .icon(app.default_window_icon().expect("bundled icon").clone())
        .tooltip("Z-BACS")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_window(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let tauri::tray::TrayIconEvent::Click { button: tauri::tray::MouseButton::Left, .. } = event {
                show_window(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_zbacs_paths_are_taken_from_argv() {
        let argv = [
            "zbacs-agent".to_string(),
            "--flag".to_string(),
            "/tmp/a.zbacs".to_string(),
            "/tmp/b.txt".to_string(),
            "/tmp/C.ZBACS".to_string(),
        ];
        let files = files_from_args(argv);
        assert_eq!(files, vec![PathBuf::from("/tmp/a.zbacs"), PathBuf::from("/tmp/C.ZBACS")]);
        assert!(files_from_args(["zbacs-agent".to_string()]).is_empty());
    }

    #[test]
    fn a_file_that_is_not_a_container_is_explained_not_crashed() {
        let dir = std::env::temp_dir().join("zbacs-agent-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("not-sealed.zbacs");
        std::fs::write(&path, b"hello, not a container").unwrap();

        let out = inspect_file(&path);
        assert!(!out.sealed);
        assert!(out.problem.is_some(), "the person is told what is wrong");
        assert!(out.detail.is_none());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn a_missing_file_is_explained_too() {
        let out = inspect_file(Path::new("/nonexistent/nope.zbacs"));
        assert!(!out.sealed);
        assert!(out.problem.is_some());
    }

    #[test]
    fn a_real_container_reports_its_state_without_a_key() {
        let dir = std::env::temp_dir().join("zbacs-agent-test");
        std::fs::create_dir_all(&dir).unwrap();
        let plain = dir.join("plain.txt");
        let sealed = dir.join("sealed.zbacs");
        std::fs::write(&plain, b"contract text").unwrap();

        let owner = zbacs_core::OwnerKeys::generate().unwrap();
        let mut opts = zbacs_core::SealOptions::new(b"acct", "plain.txt");
        opts.policy = zbacs_core::Policy { default: zbacs_core::Permission::Edit, ..Default::default() };
        zbacs_core::seal_to_path(&plain, &sealed, &owner, &opts).unwrap();

        let out = inspect_file(&sealed);
        assert!(out.sealed);
        assert_eq!(out.version, Some(1));
        assert_eq!(out.default_permission.as_deref(), Some("edit"));
        assert_eq!(out.size, Some(13));
        assert!(out.problem.is_none());
        assert!(!out.detail.as_ref().unwrap().contains("plain.txt"), "the file name stays encrypted");

        std::fs::remove_file(plain).ok();
        std::fs::remove_file(sealed).ok();
    }
}
