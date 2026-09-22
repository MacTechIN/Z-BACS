//! Z-1.G.12 — the record: what happened to my files, in order (ui_guideline S10).
//!
//! Every step the Agent takes on this machine is appended here as it happens: a file locked,
//! a request sent or received, an allow or refusal given or received, an approval pulled back.
//! The screen shows it newest first with a chip filter, in sentences, with the file's name
//! from this machine's own record (never from a message — T06 applies to history too).
//!
//! This is the *local* half of the audit trail. The chain half — `AuditLog.Logged`,
//! `AccessPolicy.Granted/Revoked` — exists (Z-1.H.3/H.7) but nothing on this machine writes
//! to the chain yet (Z-1.H.8), so there is nothing there to read back. [`Source`] marks each
//! entry so the two can be merged when that lands, and the developer panel says `chain_events`
//! is pending rather than the screen pretending the public record is being shown.
//!
//! One append-only JSON-lines file beside the profile. It carries file ids and names, never
//! keys, never content, never the other party's identity beyond "someone".

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

/// File name beside the profile.
pub const AUDIT_FILE: &str = "audit.jsonl";
/// How many entries the screen asks for at most.
pub const DEFAULT_LIMIT: usize = 200;

/// What happened. Mirrors `AuditLog.Kind` + `AccessPolicy` events on chain, plus the two
/// outcomes only this machine can know about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A file was locked here.
    Sealed,
    /// Access was asked for (sent by this machine, or received by it).
    Requested,
    /// An approval was given (owner) or received (recipient).
    Granted,
    /// A refusal was given or received.
    Denied,
    /// An approval was pulled back, by this owner or by the file's owner.
    Revoked,
    /// A file was opened here.
    Opened,
    /// An approval's window closed.
    Expired,
    /// Something went wrong; `detail` says what.
    Failed,
}

/// Which side of the exchange this machine was on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// This machine's person owns the file.
    Owner,
    /// This machine's person received the file.
    Recipient,
}

/// Where an entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Written by this Agent as it acted.
    Local,
    /// Read back from the chain (Z-1.H.8 — not produced yet).
    Chain,
}

/// One line of the record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Unix seconds.
    pub at: u64,
    /// What happened.
    pub kind: Kind,
    /// This machine's side.
    pub role: Role,
    /// Where it came from.
    pub source: Source,
    /// Container file id, hex.
    pub fid: String,
    /// The file's name, when this machine knows it.
    pub file_name: Option<String>,
    /// `read_only` | `edit` for grants; a machine value for failures.
    pub detail: Option<String>,
}

/// The record, with the lock that keeps appends whole.
pub struct AuditLog {
    path: PathBuf,
    lock: Mutex<()>,
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl AuditLog {
    /// The record in this config directory.
    pub fn new(config_dir: &Path) -> Self {
        Self { path: config_dir.join(AUDIT_FILE), lock: Mutex::new(()) }
    }

    /// Append one entry, timestamped now.
    pub fn record(
        &self,
        kind: Kind,
        role: Role,
        fid: &[u8; 32],
        file_name: Option<&str>,
        detail: Option<&str>,
    ) {
        let entry = Entry {
            at: now(),
            kind,
            role,
            source: Source::Local,
            fid: hex::encode(fid),
            file_name: file_name.map(str::to_string),
            detail: detail.map(str::to_string),
        };
        if let Err(e) = self.append(&entry) {
            // The action already happened; a record that could not be written is a warning for
            // us, not a failure for the person.
            log::warn!("cannot write the record: {e}");
        }
    }

    fn append(&self, entry: &Entry) -> Result<(), String> {
        let _held = self.lock.lock().expect("audit mutex");
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| e.to_string())?;
        // A crash mid-write can leave a line without its newline; starting on a fresh line
        // keeps that one torn line from swallowing this entry too.
        let torn = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0) > 0 && {
            let mut tail = [0u8; 1];
            use std::io::{Read, Seek, SeekFrom};
            std::fs::File::open(&self.path)
                .and_then(|mut f| f.seek(SeekFrom::End(-1)).and_then(|_| f.read_exact(&mut tail)))
                .map(|_| tail[0] != b'\n')
                .unwrap_or(false)
        };
        let mut line = if torn { vec![b'\n'] } else { Vec::new() };
        serde_json::to_writer(&mut line, entry).map_err(|e| e.to_string())?;
        line.push(b'\n');
        file.write_all(&line).map_err(|e| e.to_string())
    }

    /// The last `limit` entries, newest first. A damaged line is skipped, not fatal: the
    /// record must still open after a crash mid-write.
    pub fn read(&self, limit: usize) -> Vec<Entry> {
        let _held = self.lock.lock().expect("audit mutex");
        let Ok(file) = std::fs::File::open(&self.path) else {
            return Vec::new();
        };
        let mut entries: Vec<Entry> = std::io::BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .filter_map(|line| serde_json::from_str(&line).ok())
            .collect();
        entries.reverse();
        entries.truncate(limit);
        entries
    }
}

/// The record, newest first.
#[tauri::command]
pub fn audit_entries(app: AppHandle, limit: Option<usize>) -> Vec<Entry> {
    app.state::<AuditLog>().read(limit.unwrap_or(DEFAULT_LIMIT))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zbacs-audit-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn entries_come_back_newest_first_and_limited() {
        let dir = temp("order");
        let log = AuditLog::new(&dir);
        assert!(log.read(10).is_empty());
        log.record(Kind::Sealed, Role::Owner, &[1; 32], Some("a.docx"), None);
        log.record(Kind::Requested, Role::Recipient, &[2; 32], None, None);
        log.record(Kind::Granted, Role::Owner, &[1; 32], Some("a.docx"), Some("read_only"));

        let all = log.read(10);
        assert_eq!(
            all.iter().map(|e| e.kind).collect::<Vec<_>>(),
            [Kind::Granted, Kind::Requested, Kind::Sealed]
        );
        assert_eq!(all[0].detail.as_deref(), Some("read_only"));
        assert_eq!(all[0].source, Source::Local);
        assert_eq!(log.read(2).len(), 2);
        assert_eq!(AuditLog::new(&dir).read(10).len(), 3, "it is the disk that remembers");
        std::fs::remove_dir_all(dir).ok();
    }

    /// The five kinds the screen must show (dev_plan Z-1.G.12 DoD), round-tripped by name.
    #[test]
    fn the_five_kinds_have_stable_names() {
        for (kind, name) in [
            (Kind::Sealed, "\"sealed\""),
            (Kind::Requested, "\"requested\""),
            (Kind::Granted, "\"granted\""),
            (Kind::Denied, "\"denied\""),
            (Kind::Revoked, "\"revoked\""),
        ] {
            assert_eq!(serde_json::to_string(&kind).unwrap(), name);
        }
    }

    #[test]
    fn a_torn_line_does_not_take_the_record_down() {
        let dir = temp("torn");
        let log = AuditLog::new(&dir);
        log.record(Kind::Sealed, Role::Owner, &[1; 32], Some("a.docx"), None);
        std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join(AUDIT_FILE))
            .unwrap()
            .write_all(b"{\"at\": 1, \"kind\": \"seal")
            .unwrap();
        log.record(Kind::Denied, Role::Owner, &[1; 32], Some("a.docx"), None);
        let all = log.read(10);
        assert_eq!(all.len(), 2, "the torn line is skipped, the rest is read");
        assert_eq!(all[0].kind, Kind::Denied);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn nothing_secret_is_written() {
        let dir = temp("secrets");
        let log = AuditLog::new(&dir);
        log.record(Kind::Granted, Role::Owner, &[7; 32], Some("brief.docx"), Some("edit"));
        let raw = std::fs::read_to_string(dir.join(AUDIT_FILE)).unwrap();
        // ids, names, kinds and permissions only; no keys, no envelopes, no signatures
        for field in ["at", "kind", "role", "source", "fid", "file_name", "detail"] {
            assert!(raw.contains(&format!("\"{field}\"")), "{field} missing");
        }
        assert!(!raw.contains("envelope") && !raw.contains("sig") && !raw.contains("dek"));
        std::fs::remove_dir_all(dir).ok();
    }
}
