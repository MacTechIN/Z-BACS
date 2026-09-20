//! Z-1.G.6 — run the viewer application and notice when it saves.
//!
//! The Agent decrypts into the workspace, hands the file to whatever application normally
//! opens it, and then has to answer two questions continuously:
//!
//! 1. *is the person still looking at it?* — [`Viewer::is_running`], so the session can close
//!    when they quit, and can be told to close when a revoke arrives (T20);
//! 2. *did they just save?* — [`SaveWatcher`], which is what turns an `Edit` grant into a new
//!    sealed version (Z-1.C.4).
//!
//! # Why watching is harder than it looks
//!
//! Word and most editors do not write in place. They create a lock file (`~$doc.docx`), write a
//! temporary file, then **rename it over the original**. Watching the file itself would miss
//! the save and could even see the file vanish. So the watcher watches the *directory*, treats
//! create/modify/rename-to-target all as the same event, and debounces: one save by a person is
//! one [`SaveEvent::Saved`], not the four filesystem events it really produced.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use notify::{Event, EventKind, RecursiveMode, Watcher};

use crate::error::{Result, SessionError};

/// How long the workspace must be quiet before a burst of filesystem events counts as one save.
pub const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(400);

/// What the watcher saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveEvent {
    /// The file was written (possibly via a temp-and-rename dance).
    Saved,
    /// The file disappeared and did not come back within the debounce window. An editor that
    /// crashes mid-save can do this; the Agent treats it as a failed save, not as a new version.
    Vanished,
}

/// Watches one file inside the workspace and reports saves.
///
/// Dropping it stops the watcher thread.
pub struct SaveWatcher {
    rx: Receiver<SaveEvent>,
    _stop: mpsc::Sender<()>,
}

impl SaveWatcher {
    /// Watch `target`, reporting a save once the directory has been quiet for `debounce`.
    pub fn watch(target: &Path, debounce: Duration) -> Result<Self> {
        let dir = target
            .parent()
            .ok_or(SessionError::Workspace("watch target has no parent directory".into()))?
            .to_path_buf();
        let target = target.to_path_buf();

        let (raw_tx, raw_rx) = mpsc::channel::<notify::Result<Event>>();
        let mut watcher = notify::recommended_watcher(raw_tx)
            .map_err(|e| SessionError::Workspace(format!("watcher: {e}")))?;
        watcher
            .watch(&dir, RecursiveMode::NonRecursive)
            .map_err(|e| SessionError::Workspace(format!("watch {}: {e}", dir.display())))?;

        let (out_tx, out_rx) = mpsc::channel::<SaveEvent>();
        let (stop_tx, stop_rx) = mpsc::channel::<()>();

        thread::spawn(move || {
            // `watcher` is moved in so it lives as long as the thread.
            let _watcher = watcher;
            let mut pending: Option<Instant> = None;
            loop {
                if stop_rx.try_recv().is_ok() {
                    return;
                }
                match raw_rx.recv_timeout(Duration::from_millis(50)) {
                    Ok(Ok(event)) => {
                        if touches(&event, &target) {
                            pending = Some(Instant::now());
                        }
                    }
                    Ok(Err(_)) => {} // a dropped inotify event is not worth failing a session over
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => return,
                }
                if let Some(since) = pending {
                    if since.elapsed() >= debounce {
                        pending = None;
                        let state = if target.exists() { SaveEvent::Saved } else { SaveEvent::Vanished };
                        if out_tx.send(state).is_err() {
                            return;
                        }
                    }
                }
            }
        });

        Ok(Self { rx: out_rx, _stop: stop_tx })
    }

    /// Wait for the next save, up to `timeout`.
    pub fn next_event(&self, timeout: Duration) -> Option<SaveEvent> {
        self.rx.recv_timeout(timeout).ok()
    }

    /// Take whatever has already been reported without waiting.
    pub fn drain(&self) -> Vec<SaveEvent> {
        self.rx.try_iter().collect()
    }
}

/// Does this event concern the file we care about?
///
/// A rename shows up with the temp file as source and the target as destination, so any path in
/// the event that matches counts. Editors' own lock files (`~$doc.docx`, `.doc.swp`) do not.
fn touches(event: &Event, target: &Path) -> bool {
    if matches!(event.kind, EventKind::Access(_)) {
        return false;
    }
    event.paths.iter().any(|p| p == target)
}

/// Where the viewer came from, which decides how much we can know about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Launch {
    /// A specific executable we started: we hold its process handle and can track it exactly.
    Tracked,
    /// The OS opened the file with whatever is associated. On Windows we still get the real
    /// process; elsewhere the helper exits immediately and the editor is someone else's child,
    /// so `is_running` cannot answer and the session relies on the watcher and the TTL.
    Delegated,
}

/// A running viewer.
pub struct Viewer {
    child: Option<Child>,
    pid: Option<u32>,
    launch: Launch,
    path: PathBuf,
}

impl Viewer {
    /// Start a named program (the Agent's preferred path: it knows what it started).
    ///
    /// `args` is the complete argument list — put the file where the program expects it, which
    /// for most viewers is last. `path` is recorded for bookkeeping and for the watcher; it is
    /// not appended, because some viewers take flags after the file name.
    pub fn launch_with<I, S>(program: &str, args: I, path: &Path) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let child = Command::new(program)
            .args(args)
            .spawn()
            .map_err(|e| SessionError::Workspace(format!("launch {program}: {e}")))?;
        Ok(Self {
            pid: Some(child.id()),
            child: Some(child),
            launch: Launch::Tracked,
            path: path.to_path_buf(),
        })
    }

    /// The common case: `program <file>`.
    pub fn launch_file(program: &str, path: &Path) -> Result<Self> {
        Self::launch_with(program, [path.as_os_str()], path)
    }

    /// Open the file with whatever the OS associates with it.
    pub fn launch_default(path: &Path) -> Result<Self> {
        #[cfg(windows)]
        {
            // `cmd /c start` returns immediately and the editor is not our child, so the PID is
            // unknown here. Z-1.G.9's UI covers the "we cannot tell if it is still open" case;
            // tracking the real process needs ShellExecuteEx and is part of the Tauri agent.
            let child = Command::new("cmd")
                .args(["/C", "start", "", ""])
                .arg(path)
                .spawn()
                .map_err(|e| SessionError::Workspace(format!("open: {e}")))?;
            Ok(Self { pid: None, child: Some(child), launch: Launch::Delegated, path: path.to_path_buf() })
        }
        #[cfg(target_os = "macos")]
        {
            let child = Command::new("open")
                .arg(path)
                .spawn()
                .map_err(|e| SessionError::Workspace(format!("open: {e}")))?;
            Ok(Self { pid: None, child: Some(child), launch: Launch::Delegated, path: path.to_path_buf() })
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            let child = Command::new("xdg-open")
                .arg(path)
                .spawn()
                .map_err(|e| SessionError::Workspace(format!("xdg-open: {e}")))?;
            Ok(Self { pid: None, child: Some(child), launch: Launch::Delegated, path: path.to_path_buf() })
        }
    }

    /// The process id, when we started the program ourselves.
    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// How this viewer was started.
    pub fn launch(&self) -> Launch {
        self.launch
    }

    /// The file it was pointed at.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Is it still running? `None` when we cannot tell ([`Launch::Delegated`]).
    pub fn is_running(&mut self) -> Option<bool> {
        if self.launch == Launch::Delegated {
            return None;
        }
        match self.child.as_mut()?.try_wait() {
            Ok(Some(_)) => Some(false),
            Ok(None) => Some(true),
            Err(_) => None,
        }
    }

    /// Ask it to close, the way a person clicking the X would.
    ///
    /// Windows: `taskkill` without `/F`, which posts `WM_CLOSE` and lets the editor offer to
    /// save. Unix: `SIGTERM`. Neither is forced — call [`Viewer::kill`] after a grace period if
    /// the session must end now (revoke, T20).
    pub fn request_close(&mut self) -> Result<()> {
        let Some(pid) = self.pid else {
            return Ok(()); // nothing we can address; the workspace wipe is the real stop
        };
        #[cfg(windows)]
        let result = Command::new("taskkill").args(["/PID", &pid.to_string()]).output();
        #[cfg(unix)]
        let result = Command::new("kill").args(["-TERM", &pid.to_string()]).output();
        result.map_err(|e| SessionError::Workspace(format!("request close: {e}")))?;
        Ok(())
    }

    /// Stop it now.
    pub fn kill(&mut self) -> Result<()> {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        Ok(())
    }

    /// Wait until it exits (or return immediately if we cannot tell).
    pub fn wait(&mut self) -> Result<()> {
        if let Some(child) = self.child.as_mut() {
            child.wait().map_err(|e| SessionError::Workspace(format!("wait: {e}")))?;
        }
        Ok(())
    }

    /// Wait for it to exit, up to `timeout`. Returns false on timeout.
    pub fn wait_timeout(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            match self.is_running() {
                Some(false) => return true,
                None => return false,
                Some(true) => thread::sleep(Duration::from_millis(20)),
            }
        }
        false
    }
}

impl Drop for Viewer {
    fn drop(&mut self) {
        // A session that ends must not leave a viewer holding the plaintext open.
        if self.is_running() == Some(true) {
            let _ = self.kill();
        }
    }
}
