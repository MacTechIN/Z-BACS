//! Z-0.G.1 spike: how a `.zbacs` double-click reaches the Agent on each OS.
//!
//! - Windows / Linux: the shell launches the exe with the file path as an argument.
//!   First launch → `std::env::args()`; while already running → `tauri-plugin-single-instance`
//!   callback receives the new process's argv and we forward it to the existing window.
//! - macOS: Launch Services sends `RunEvent::Opened { urls }` (also used for drag-onto-dock).
//!
//! Every path is inspected with `zbacs_core::container::inspect` (no keys needed) and the header
//! summary is emitted to the webview as `zbacs://opened`.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, RunEvent, State};

pub const OPENED_EVENT: &str = "zbacs://opened";

#[derive(Debug, Clone, Serialize)]
pub struct OpenedFile {
    pub path: String,
    pub ok: bool,
    pub fid: Option<String>,
    pub header_hash: Option<String>,
    pub version: Option<u32>,
    pub plen: Option<u64>,
    pub envelopes: Option<usize>,
    pub policy: Option<String>,
    pub error: Option<String>,
}

/// Paths handed to the process by the shell. Ignores flags and non-`.zbacs` arguments.
pub fn files_from_args<I: IntoIterator<Item = String>>(args: I) -> Vec<PathBuf> {
    args.into_iter()
        .skip(1)
        .filter(|a| !a.starts_with('-'))
        .map(PathBuf::from)
        .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("zbacs")))
        .collect()
}

pub fn inspect_file(path: &Path) -> OpenedFile {
    let mut out = OpenedFile {
        path: path.display().to_string(),
        ok: false,
        fid: None,
        header_hash: None,
        version: None,
        plen: None,
        envelopes: None,
        policy: None,
        error: None,
    };
    match File::open(path).map(BufReader::new).map_err(zbacs_core::Error::from).and_then(zbacs_core::container::inspect) {
        Ok((h, hh)) => {
            out.ok = true;
            out.fid = Some(hex::encode(&h.body.fid));
            out.header_hash = Some(hex::encode(hh));
            out.version = Some(h.body.ver);
            out.plen = Some(h.body.plen);
            out.envelopes = Some(h.body.env.len());
            out.policy = Some(format!("{:?}", h.body.pol.default));
        }
        Err(e) => out.error = Some(e.to_string()),
    }
    out
}

/// Files received before the webview asked for them.
pub struct PendingFiles(pub Mutex<Vec<OpenedFile>>);

fn handle_open(app: &AppHandle, paths: Vec<PathBuf>) {
    for p in paths {
        let info = inspect_file(&p);
        log::info!("opened: {}", serde_json::to_string(&info).unwrap_or_default());
        if let Err(e) = app.emit(OPENED_EVENT, &info) {
            log::warn!("emit failed: {e}");
        }
        if let Some(st) = app.try_state::<PendingFiles>() {
            st.0.lock().unwrap().push(info);
        }
    }
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// Webview calls this once on load to drain files that arrived before it was listening.
#[tauri::command]
fn take_pending(state: State<'_, PendingFiles>) -> Vec<OpenedFile> {
    std::mem::take(&mut *state.0.lock().unwrap())
}

#[tauri::command]
fn inspect_path(path: String) -> OpenedFile {
    inspect_file(Path::new(&path))
}

pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_log::Builder::new().level(log::LevelFilter::Info).build())
        .plugin(tauri_plugin_single_instance::init(|app, argv, cwd| {
            log::info!("second instance argv={argv:?} cwd={cwd}");
            handle_open(app, files_from_args(argv));
        }))
        .manage(PendingFiles(Mutex::new(Vec::new())))
        .invoke_handler(tauri::generate_handler![take_pending, inspect_path])
        .setup(|app| {
            let initial = files_from_args(std::env::args());
            log::info!("initial argv files: {initial:?}");
            handle_open(app.handle(), initial);
            // Headless smoke test hook (CI / no display): exit after N ms.
            if let Ok(ms) = std::env::var("ZBACS_SPIKE_AUTOEXIT_MS") {
                if let Ok(ms) = ms.parse::<u64>() {
                    let h = app.handle().clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(std::time::Duration::from_millis(ms));
                        log::info!("autoexit");
                        h.exit(0);
                    });
                }
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build tauri app");

    app.run(|app, event| {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        if let RunEvent::Opened { urls } = &event {
            let paths: Vec<PathBuf> = urls.iter().filter_map(|u| u.to_file_path().ok()).collect();
            log::info!("RunEvent::Opened {paths:?}");
            handle_open(app, paths);
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            let _ = (app, &event);
        }
        if let RunEvent::ExitRequested { .. } = event {
            log::info!("exit requested");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_filter_only_zbacs_paths() {
        let v = files_from_args(
            ["app.exe", "--flag", "C:\\Users\\bob\\report.docx.zbacs", "notes.txt", "/tmp/x.ZBACS"]
                .map(String::from),
        );
        assert_eq!(v, vec![PathBuf::from("C:\\Users\\bob\\report.docx.zbacs"), PathBuf::from("/tmp/x.ZBACS")]);
    }

    #[test]
    fn inspect_reports_error_for_non_container() {
        let dir = std::env::temp_dir().join("zbacs-spike-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("junk.zbacs");
        std::fs::write(&p, b"not a container").unwrap();
        let r = inspect_file(&p);
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("magic"));
    }
}
