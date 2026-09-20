//! Z-1.G.6 — viewer process tracking and save detection.
//!
//! The editors that matter (Word, Notepad, PDF readers) are a Windows manual check —
//! `docs/windows_checklist.md` §5. What runs here is the mechanism they exercise: a tracked
//! child process, and the filesystem patterns real editors produce.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use zbacs_session::{Launch, SaveEvent, SaveWatcher, Viewer, Workspace};

const DEBOUNCE: Duration = Duration::from_millis(200);
const PATIENCE: Duration = Duration::from_secs(5);

/// A process that stays up until it is told to stop, on either platform.
fn long_running() -> (&'static str, Vec<String>) {
    if cfg!(windows) {
        ("cmd", vec!["/C".into(), "timeout /T 30 /NOBREAK > NUL".into()])
    } else {
        ("sleep", vec!["30".into()])
    }
}

/// A process that exits at once, like a viewer the person closed immediately.
fn exits_at_once() -> (&'static str, Vec<String>) {
    if cfg!(windows) {
        ("cmd", vec!["/C".into(), "exit".into()])
    } else {
        ("true", vec![])
    }
}

fn workspace() -> (tempfile::TempDir, Workspace) {
    let base = tempfile::tempdir().unwrap();
    let ws = Workspace::create(base.path(), "viewer").unwrap();
    (base, ws)
}

/// Write the way a simple editor does: open, write, close.
fn write_in_place(path: &Path, content: &[u8]) {
    let mut f = fs::File::create(path).unwrap();
    f.write_all(content).unwrap();
    f.sync_all().unwrap();
}

/// Write the way Word does: temp file next to it, then rename over the original.
fn write_via_rename(path: &Path, content: &[u8]) {
    let tmp = path.with_extension("tmp~");
    write_in_place(&tmp, content);
    fs::rename(&tmp, path).unwrap();
}

// ------------------------------------------------------------------ save detection

#[test]
fn a_plain_write_is_one_save() {
    let (_base, ws) = workspace();
    let doc = ws.file("doc.txt").unwrap();
    write_in_place(&doc, b"v1");

    let watcher = SaveWatcher::watch(&doc, DEBOUNCE).unwrap();
    write_in_place(&doc, b"v2 edited");

    assert_eq!(watcher.next_event(PATIENCE), Some(SaveEvent::Saved));
    assert!(watcher.next_event(Duration::from_millis(600)).is_none(), "exactly one save");
    assert_eq!(fs::read(&doc).unwrap(), b"v2 edited");
}

/// The case that would be missed by watching the file instead of the directory.
#[test]
fn a_temp_and_rename_save_is_detected() {
    let (_base, ws) = workspace();
    let doc = ws.file("report.docx").unwrap();
    write_in_place(&doc, b"v1");

    let watcher = SaveWatcher::watch(&doc, DEBOUNCE).unwrap();
    write_via_rename(&doc, b"v2 from Word");

    assert_eq!(watcher.next_event(PATIENCE), Some(SaveEvent::Saved));
    assert_eq!(fs::read(&doc).unwrap(), b"v2 from Word");
}

/// A burst of writes must collapse into far fewer events than writes.
///
/// Debouncing is a time window, not a guarantee of exactly one event: on a loaded machine the
/// writes themselves can straddle the window and produce a second. That is harmless — an extra
/// event costs one extra reseal, never a missed save — so the test pins the property that
/// matters (a handful of writes is not a handful of saves) rather than an exact count.
#[test]
fn a_burst_of_writes_collapses_into_very_few_saves() {
    let (_base, ws) = workspace();
    let doc = ws.file("doc.txt").unwrap();
    write_in_place(&doc, b"v1");

    let watcher = SaveWatcher::watch(&doc, DEBOUNCE).unwrap();
    let writes = 8;
    for i in 0..writes {
        write_in_place(&doc, format!("chunk {i}").as_bytes());
        std::thread::sleep(Duration::from_millis(10));
    }

    assert_eq!(watcher.next_event(PATIENCE), Some(SaveEvent::Saved));
    std::thread::sleep(DEBOUNCE * 3);
    let events = watcher.drain().len() + 1;
    assert!(events * 2 <= writes, "{writes} writes produced {events} events");
}

/// An editor's own lock and swap files must not look like the person saving.
#[test]
fn other_files_in_the_workspace_are_ignored() {
    let (_base, ws) = workspace();
    let doc = ws.file("report.docx").unwrap();
    write_in_place(&doc, b"v1");

    let watcher = SaveWatcher::watch(&doc, DEBOUNCE).unwrap();
    write_in_place(&ws.file("~$report.docx").unwrap(), b"lock");
    write_in_place(&ws.file("report.docx.swp").unwrap(), b"swap");

    assert!(watcher.next_event(Duration::from_millis(800)).is_none(), "lock files are not saves");
}

#[test]
fn a_file_that_disappears_is_reported_as_vanished() {
    let (_base, ws) = workspace();
    let doc = ws.file("doc.txt").unwrap();
    write_in_place(&doc, b"v1");

    let watcher = SaveWatcher::watch(&doc, DEBOUNCE).unwrap();
    fs::remove_file(&doc).unwrap();

    assert_eq!(watcher.next_event(PATIENCE), Some(SaveEvent::Vanished));
}

#[test]
fn watching_requires_a_parent_directory() {
    assert!(SaveWatcher::watch(Path::new("/"), DEBOUNCE).is_err());
}

// ------------------------------------------------------------------ viewer process

#[test]
fn a_tracked_viewer_reports_its_pid_and_liveness() {
    let (_base, ws) = workspace();
    let doc = ws.file("doc.txt").unwrap();
    write_in_place(&doc, b"content");

    let (program, args) = long_running();
    let mut viewer = Viewer::launch_with(program, &args, &doc).unwrap();
    assert_eq!(viewer.launch(), Launch::Tracked);
    assert!(viewer.pid().is_some());
    assert_eq!(viewer.path(), doc.as_path());
    assert_eq!(viewer.is_running(), Some(true));

    viewer.kill().unwrap();
    assert_eq!(viewer.is_running(), Some(false));
}

#[test]
fn a_viewer_that_exits_on_its_own_is_noticed() {
    let (_base, ws) = workspace();
    let doc = ws.file("doc.txt").unwrap();
    write_in_place(&doc, b"content");

    let (program, args) = exits_at_once();
    let mut viewer = Viewer::launch_with(program, &args, &doc).unwrap();
    assert!(viewer.wait_timeout(PATIENCE), "should exit promptly");
    assert_eq!(viewer.is_running(), Some(false));
}

/// T20: a revoke has to be able to close the window, not just delete the file underneath it.
#[test]
fn t20_request_close_stops_a_viewer_without_forcing() {
    let (_base, ws) = workspace();
    let doc = ws.file("doc.txt").unwrap();
    write_in_place(&doc, b"content");

    let (program, args) = long_running();
    let mut viewer = Viewer::launch_with(program, &args, &doc).unwrap();
    assert_eq!(viewer.is_running(), Some(true));
    viewer.request_close().unwrap();
    assert!(viewer.wait_timeout(PATIENCE), "a close request should end it without /F or SIGKILL");
    assert_eq!(viewer.is_running(), Some(false));
}

#[test]
fn a_missing_program_fails_instead_of_pretending_to_run() {
    let (_base, ws) = workspace();
    let doc = ws.file("doc.txt").unwrap();
    write_in_place(&doc, b"content");
    assert!(Viewer::launch_file("zbacs-no-such-viewer", &doc).is_err());
}

/// Dropping the session must not leave the plaintext open in an editor.
#[cfg(unix)]
#[test]
fn dropping_a_viewer_kills_it() {
    let (_base, ws) = workspace();
    let doc = ws.file("doc.txt").unwrap();
    write_in_place(&doc, b"content");

    let pid = {
        let (program, args) = long_running();
        let mut viewer = Viewer::launch_with(program, &args, &doc).unwrap();
        let pid = viewer.pid().unwrap();
        assert_eq!(viewer.is_running(), Some(true));
        pid
    };

    // give the OS a moment to reap it
    let mut alive = true;
    for _ in 0..100 {
        alive = Path::new(&format!("/proc/{pid}")).exists();
        if !alive {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!alive, "viewer {pid} survived the session");
}

// ------------------------------------------------------------------ the whole edit loop

/// What an `Edit` session actually does: open, the person saves twice, the Agent sees two
/// saves, then the viewer closes and the workspace is wiped.
#[test]
fn an_edit_session_sees_each_save_then_the_close() {
    let (_base, ws) = workspace();
    let doc = ws.file("contract.docx").unwrap();
    write_in_place(&doc, b"v1 decrypted");

    let watcher = SaveWatcher::watch(&doc, DEBOUNCE).unwrap();
    let (program, args) = long_running();
    let mut viewer = Viewer::launch_with(program, &args, &doc).unwrap();

    write_via_rename(&doc, b"v2 edited");
    assert_eq!(watcher.next_event(PATIENCE), Some(SaveEvent::Saved));

    std::thread::sleep(Duration::from_millis(300));
    write_via_rename(&doc, b"v3 edited again");
    assert_eq!(watcher.next_event(PATIENCE), Some(SaveEvent::Saved));

    viewer.request_close().unwrap();
    assert!(viewer.wait_timeout(PATIENCE));

    drop(watcher);
    ws.wipe().unwrap();
    assert!(!doc.exists());
}
