//! The local record of files locked on this machine (Z-1.G.10, T06).
//!
//! When a request arrives, the approval screen shows the file's name and the policy the owner
//! chose — from *here*, never from the request. A request can name any file id it likes; only
//! this record says what that id is, and a request for an id that is not here cannot be
//! allowed at all, because the key to open the file is in that file's own envelope and this
//! machine does not have the file.
//!
//! One JSON file beside the device profile. Small, rewritten whole, never read by the webview.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::seal::{SealRequest, SealResult};

/// File name beside the profile.
pub const LEDGER_FILE: &str = "sealed.json";

/// One locked file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Container file id, hex.
    pub fid: String,
    /// Header hash of the version this machine wrote, hex.
    pub header_hash: String,
    /// Original file name, for the approval screen.
    pub name: String,
    /// Where the locked file is on this machine.
    pub path: String,
    /// `"read_only"` or `"edit"`: the permission the owner pre-approved.
    pub permission: String,
    /// How long an approval lasts, seconds.
    pub ttl: u64,
    /// How many opens an approval allows; 0 = unlimited.
    pub max_opens: u16,
    /// Unix seconds.
    pub sealed_at: u64,
}

impl Entry {
    /// The record for a file just locked.
    pub fn from_seal(result: &SealResult, request: &SealRequest) -> Self {
        let policy = request.policy();
        let name = Path::new(&result.original)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Self {
            fid: result.fid.clone(),
            header_hash: result.header_hash.clone(),
            name,
            path: result.output.clone(),
            permission: match policy.default {
                zbacs_core::Permission::Edit => "edit".into(),
                _ => "read_only".into(),
            },
            ttl: u64::from(policy.ttl),
            max_opens: policy.max,
            sealed_at: now(),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct File {
    /// Owner's sequential approval nonce (EIP-712 `grantNonce`). Local until Z-1.H.8 reads it
    /// from the chain; the contract rejects a reused one either way (T03).
    grant_nonce: u64,
    /// By file id.
    files: BTreeMap<String, Entry>,
}

/// The ledger, with the lock that serialises its read-modify-write.
pub struct Ledger {
    path: PathBuf,
    lock: Mutex<()>,
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Ledger {
    /// The ledger in this config directory.
    pub fn new(config_dir: &Path) -> Self {
        Self { path: config_dir.join(LEDGER_FILE), lock: Mutex::new(()) }
    }

    fn load(&self) -> Result<File, String> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("ledger is not readable: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(File::default()),
            Err(e) => Err(format!("cannot read the ledger: {e}")),
        }
    }

    fn store(&self, file: &File) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("cannot create the config dir: {e}"))?;
        }
        let bytes = serde_json::to_vec_pretty(file).map_err(|e| e.to_string())?;
        // beside, then rename: a crash mid-write must not leave half a ledger
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes).map_err(|e| format!("cannot write the ledger: {e}"))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| format!("cannot replace the ledger: {e}"))
    }

    /// Remember a locked file. A later lock of the same id (a reseal) replaces the entry.
    pub fn record(&self, entry: &Entry) -> Result<(), String> {
        let _held = self.lock.lock().expect("ledger mutex");
        let mut file = self.load()?;
        file.files.insert(entry.fid.clone(), entry.clone());
        self.store(&file)
    }

    /// The record for a file id, if this machine locked it.
    pub fn find(&self, fid: &[u8; 32]) -> Option<Entry> {
        let _held = self.lock.lock().expect("ledger mutex");
        self.load().ok()?.files.get(&hex::encode(fid)).cloned()
    }

    /// Everything this machine has locked, newest first.
    pub fn entries(&self) -> Vec<Entry> {
        let _held = self.lock.lock().expect("ledger mutex");
        let mut all: Vec<Entry> = self.load().map(|f| f.files.into_values().collect()).unwrap_or_default();
        all.sort_by_key(|e| std::cmp::Reverse(e.sealed_at));
        all
    }

    /// Take the next approval nonce. Persisted before it is returned, so a crash after signing
    /// cannot hand the same nonce out twice.
    pub fn next_grant_nonce(&self) -> Result<u64, String> {
        let _held = self.lock.lock().expect("ledger mutex");
        let mut file = self.load()?;
        let n = file.grant_nonce;
        file.grant_nonce += 1;
        self.store(&file)?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(fid: u8, at: u64) -> Entry {
        Entry {
            fid: hex::encode([fid; 32]),
            header_hash: hex::encode([fid + 1; 32]),
            name: format!("file-{fid}.docx"),
            path: format!("/tmp/file-{fid}.docx.zbacs"),
            permission: "read_only".into(),
            ttl: 3600,
            max_opens: 1,
            sealed_at: at,
        }
    }

    #[test]
    fn records_are_found_by_id_and_listed_newest_first() {
        let dir = std::env::temp_dir().join(format!("zbacs-ledger-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ledger = Ledger::new(&dir);
        assert!(ledger.find(&[1; 32]).is_none());
        assert!(ledger.entries().is_empty());

        ledger.record(&entry(1, 10)).unwrap();
        ledger.record(&entry(2, 20)).unwrap();
        assert_eq!(ledger.find(&[1; 32]).unwrap().name, "file-1.docx");
        assert_eq!(
            ledger.entries().iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            ["file-2.docx", "file-1.docx"]
        );

        // a reseal replaces the record for that id
        let mut newer = entry(1, 30);
        newer.header_hash = hex::encode([9; 32]);
        ledger.record(&newer).unwrap();
        assert_eq!(ledger.find(&[1; 32]).unwrap().header_hash, hex::encode([9; 32]));
        assert_eq!(ledger.entries().len(), 2);

        // a second Ledger on the same path sees the same file: it is the disk that remembers
        assert_eq!(Ledger::new(&dir).entries().len(), 2);
        std::fs::remove_dir_all(dir).ok();
    }

    /// T03: nonces are handed out once, and survive a restart.
    #[test]
    fn t03_grant_nonces_never_repeat() {
        let dir = std::env::temp_dir().join(format!("zbacs-ledger-nonce-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ledger = Ledger::new(&dir);
        assert_eq!(ledger.next_grant_nonce().unwrap(), 0);
        assert_eq!(ledger.next_grant_nonce().unwrap(), 1);
        assert_eq!(Ledger::new(&dir).next_grant_nonce().unwrap(), 2, "a restart continues the sequence");
        std::fs::remove_dir_all(dir).ok();
    }
}
