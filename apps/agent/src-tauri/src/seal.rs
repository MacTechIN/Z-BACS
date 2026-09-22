//! Z-1.G.3 / Z-1.U.3 — locking a file.
//!
//! The screen is one drop area, two buttons and "잠그기". Everything else is folded away:
//! how long a permission lasts and how many times it may be used are presets behind "고급",
//! never a number someone has to type (ux_principles rule 4, U-6).
//!
//! Two things this module is careful about.
//!
//! - **It never overwrites.** If a locked copy of that name already exists, it stops and says
//!   so. Silently replacing it would destroy the version chain of a file someone already sent.
//! - **It tells the truth about the original.** Locking makes a second file; the original is
//!   still sitting there in plain form. A person who is not told that believes they are
//!   protected when they are not (T09), so the result screen says it and offers to erase it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use zbacs_auth::setup::DeviceProfile;
use zbacs_core::{Permission, Policy, SealOptions};

use crate::setup::{Identity, SetupHost};

/// Extension of a locked file.
pub const SEALED_EXT: &str = "zbacs";

/// What the person chose on the lock screen.
#[derive(Debug, Clone, Deserialize)]
pub struct SealRequest {
    /// The file to lock.
    pub path: String,
    /// `"read_only"` or `"edit"` — the two buttons (Z-1.U.3).
    pub permission: PermissionArg,
    /// How long an approval lasts, from the presets.
    pub ttl: TtlArg,
    /// How many times an approval may be used, from the presets.
    pub opens: OpensArg,
}

/// The permission the owner pre-approves. `Deny` is not offered here: a file nobody may open
/// is a file there is no reason to send.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PermissionArg {
    /// 읽기만
    ReadOnly,
    /// 편집 허용
    Edit,
}

/// Preset lifetimes. Numbers live here, not in a text field.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TtlArg {
    /// 1시간 (기본)
    Hour,
    /// 하루
    Day,
    /// 1주
    Week,
}

/// Preset open counts.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpensArg {
    /// 한 번 (기본)
    Once,
    /// 세 번
    Thrice,
    /// 제한 없음
    Unlimited,
}

impl SealRequest {
    /// The header policy this choice means.
    pub fn policy(&self) -> Policy {
        Policy {
            default: match self.permission {
                PermissionArg::ReadOnly => Permission::ReadOnly,
                PermissionArg::Edit => Permission::Edit,
            },
            ttl: match self.ttl {
                TtlArg::Hour => 3600,
                TtlArg::Day => 86_400,
                TtlArg::Week => 604_800,
            },
            max: match self.opens {
                OpensArg::Once => 1,
                OpensArg::Thrice => 3,
                OpensArg::Unlimited => 0,
            },
            // Bind the approval to the asking device, and do not make the recipient wait for
            // the chain. Both are "고급" settings the person never sees (ux_principles 9).
            pin: true,
            strict: false,
        }
    }
}

/// What the person is shown after a file is locked.
#[derive(Debug, Clone, Serialize)]
pub struct SealResult {
    /// Where the locked file is.
    pub output: String,
    /// Its name, for the screen.
    pub output_name: String,
    /// The original, which is still there in plain form.
    pub original: String,
    /// Size of the locked file.
    pub size: u64,
    /// Machine values for what is still outstanding.
    pub pending: Vec<&'static str>,
    /// Container file id, hex. Developer panel and the local ledger (Z-1.G.10).
    pub fid: String,
    /// Header hash of the version just written, hex.
    pub header_hash: String,
}

/// A file the person dropped or picked, checked before anything is offered.
#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    /// The path as given.
    pub path: String,
    /// Its name, for the screen.
    pub name: String,
    /// Size in bytes.
    pub size: Option<u64>,
    /// Whether it can be locked.
    pub ok: bool,
    /// Why not, as a machine value the UI turns into a sentence.
    pub problem: Option<&'static str>,
}

/// Check a dropped path without locking anything, so the screen can refuse early and say why.
pub fn examine(path: &Path) -> Candidate {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut out = Candidate {
        path: path.display().to_string(),
        name,
        size: None,
        ok: false,
        problem: Some("unreadable"),
    };
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_dir() => out.problem = Some("is_folder"),
        Ok(meta) => {
            out.size = Some(meta.len());
            if path.extension().is_some_and(|e| e.eq_ignore_ascii_case(SEALED_EXT)) {
                out.problem = Some("already_locked");
            } else if meta.len() == 0 {
                out.problem = Some("empty");
            } else if sealed_path(path).exists() {
                out.problem = Some("output_exists");
            } else {
                out.ok = true;
                out.problem = None;
            }
        }
        Err(e) => {
            log::warn!("cannot read a dropped path: {e}");
            out.problem =
                Some(if e.kind() == std::io::ErrorKind::NotFound { "missing" } else { "unreadable" });
        }
    }
    out
}

/// `report.docx` → `report.docx.zbacs`. The original name is kept so the person recognises it;
/// inside the container the name is encrypted.
pub fn sealed_path(source: &Path) -> PathBuf {
    let mut name = source.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(SEALED_EXT);
    source.with_file_name(name)
}

/// The identifier committed with the file. Once the owner has a smart account on chain
/// (Z-1.H.8) that address is it; until then the owner's own signing key, which is stable and
/// already identifies them. Resealing carries the old value forward, so a file's versions never
/// disagree.
pub fn owner_account(profile: &DeviceProfile) -> Vec<u8> {
    match profile.account {
        Some(address) => address.to_vec(),
        None => profile.owner_signing_pub.to_vec(),
    }
}

/// Lock a file, given the owner's keys and this device's profile.
///
/// Separate from the command so the whole path — policy, container, naming — can be tested
/// without a webview, which is where the only real proof lives: the file it writes must open
/// again with the owner's own key.
pub fn seal_now(
    owner: &zbacs_core::OwnerKeys,
    profile: &DeviceProfile,
    request: &SealRequest,
) -> Result<SealResult, &'static str> {
    let source = PathBuf::from(&request.path);
    let checked = examine(&source);
    if !checked.ok {
        return Err(checked.problem.unwrap_or("unreadable"));
    }

    let output = sealed_path(&source);
    let account = owner_account(profile);
    let name = source.file_name().unwrap_or_default().to_string_lossy().into_owned();
    let mut opts = SealOptions::new(&account, &name);
    opts.policy = request.policy();

    zbacs_core::seal_to_path(&source, &output, owner, &opts).map_err(|e| {
        // The message carries no key material, but it is ours to read, not the person's.
        log::warn!("seal failed: {e}");
        "failed"
    })?;

    let size = std::fs::metadata(&output).map(|m| m.len()).unwrap_or_default();
    let (header, header_hash) = std::fs::File::open(&output)
        .map_err(zbacs_core::Error::from)
        .and_then(zbacs_core::inspect)
        .map_err(|e| {
            log::warn!("the file just written does not read back: {e}");
            "failed"
        })?;
    log::info!(
        "sealed a file: {} bytes, permission={:?}, ttl={}s, opens={}",
        size,
        opts.policy.default,
        opts.policy.ttl,
        opts.policy.max
    );

    Ok(SealResult {
        output: output.display().to_string(),
        output_name: output.file_name().unwrap_or_default().to_string_lossy().into_owned(),
        original: source.display().to_string(),
        size,
        // Registering the file on chain is Z-1.H.4/H.8; the file is complete without it, and
        // the UI does not pretend otherwise.
        pending: vec!["chain_registration"],
        fid: hex::encode(header.body.fid.0),
        header_hash: hex::encode(header_hash.0),
    })
}

/// Lock a file. Off the UI thread: a large file takes real time.
#[tauri::command]
pub async fn seal_file(app: AppHandle, request: SealRequest) -> Result<SealResult, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let identity = app.state::<Identity>();
        let profile = identity
            .0
            .lock()
            .expect("identity mutex")
            .as_ref()
            .map(|p| p.profile.clone())
            .ok_or_else(|| "not_set_up".to_string())?;

        let owner = app.state::<SetupHost>().owner_keys().map_err(|e| {
            log::warn!("cannot load the owner keys: {e}");
            "not_set_up".to_string()
        })?;

        let result = seal_now(&owner, &profile, &request).map_err(|e| e.to_string())?;
        // Remember it: an approval request names the file by id, and the approval screen must
        // show the name and policy from *this* machine's record, never from the request (T06).
        let entry = crate::ledger::Entry::from_seal(&result, &request);
        if let Err(e) = app.state::<crate::ledger::Ledger>().record(&entry) {
            log::warn!("locked, but could not record it for later approvals: {e}");
        }
        if let Ok(fid) = <[u8; 32]>::try_from(hex::decode(&result.fid).unwrap_or_default()) {
            app.state::<crate::audit::AuditLog>().record(
                crate::audit::Kind::Sealed,
                crate::audit::Role::Owner,
                &fid,
                Some(&entry.name),
                Some(&entry.permission),
            );
        }
        Ok(result)
    })
    .await
    .map_err(|e| format!("join: {e}"))?
}

/// Check a path the person dropped or picked.
#[tauri::command]
pub fn examine_path(path: String) -> Candidate {
    examine(Path::new(&path))
}

/// Erase the original, overwriting it first (T09).
///
/// Only ever reached by an explicit tap on the result screen, and only for the file that was
/// just locked — the UI passes back the path the seal returned, and this refuses anything that
/// does not have a locked copy sitting next to it.
#[tauri::command]
pub fn shred_original(path: String) -> Result<(), String> {
    let source = PathBuf::from(&path);
    if !sealed_path(&source).exists() {
        log::warn!("refusing to erase a file that has no locked copy: {}", source.display());
        return Err("no_locked_copy".to_string());
    }
    zbacs_session::secure_delete(&source).map_err(|e| {
        log::warn!("cannot erase the original: {e}");
        "failed".to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zbacs-seal-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn request(path: &Path) -> SealRequest {
        SealRequest {
            path: path.display().to_string(),
            permission: PermissionArg::ReadOnly,
            ttl: TtlArg::Hour,
            opens: OpensArg::Once,
        }
    }

    #[test]
    fn the_locked_file_sits_next_to_the_original_and_keeps_its_name() {
        assert_eq!(sealed_path(Path::new("/tmp/report.docx")), PathBuf::from("/tmp/report.docx.zbacs"));
        assert_eq!(sealed_path(Path::new("/tmp/no-extension")), PathBuf::from("/tmp/no-extension.zbacs"));
    }

    /// Every preset maps to a policy, and the defaults are the quiet ones (spec §2.2).
    #[test]
    fn the_presets_map_to_a_policy_and_the_default_is_the_careful_one() {
        let dir = temp("policy");
        let file = dir.join("a.txt");
        let mut r = request(&file);
        let policy = r.policy();
        assert_eq!(policy.default, Permission::ReadOnly);
        assert_eq!(policy.ttl, 3600);
        assert_eq!(policy.max, 1);
        assert!(policy.pin, "an approval is bound to the device that asked");

        r.permission = PermissionArg::Edit;
        r.ttl = TtlArg::Week;
        r.opens = OpensArg::Unlimited;
        let policy = r.policy();
        assert_eq!(policy.default, Permission::Edit);
        assert_eq!(policy.ttl, 604_800);
        assert_eq!(policy.max, 0, "0 means unlimited in the header");

        r.ttl = TtlArg::Day;
        r.opens = OpensArg::Thrice;
        assert_eq!(r.policy().ttl, 86_400);
        assert_eq!(r.policy().max, 3);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_path_that_cannot_be_locked_is_refused_with_a_reason() {
        let dir = temp("examine");
        assert_eq!(examine(&dir).problem, Some("is_folder"));
        assert_eq!(examine(&dir.join("nope.txt")).problem, Some("missing"));

        let empty = dir.join("empty.txt");
        std::fs::write(&empty, b"").unwrap();
        assert_eq!(examine(&empty).problem, Some("empty"));

        let sealed = dir.join("already.zbacs");
        std::fs::write(&sealed, b"x").unwrap();
        assert_eq!(examine(&sealed).problem, Some("already_locked"));

        let good = dir.join("report.docx");
        std::fs::write(&good, b"hello").unwrap();
        let ok = examine(&good);
        assert!(ok.ok, "{ok:?}");
        assert_eq!(ok.name, "report.docx");
        assert_eq!(ok.size, Some(5));

        // ...and once a locked copy exists, locking again would overwrite it, so it is refused
        std::fs::write(sealed_path(&good), b"pretend").unwrap();
        assert_eq!(examine(&good).problem, Some("output_exists"));
        std::fs::remove_dir_all(dir).ok();
    }

    /// The original must never be erased on the strength of a path alone.
    #[test]
    fn t09_erasing_the_original_needs_a_locked_copy_to_exist() {
        let dir = temp("shred");
        let lonely = dir.join("lonely.txt");
        std::fs::write(&lonely, b"still needed").unwrap();

        assert_eq!(shred_original(lonely.display().to_string()), Err("no_locked_copy".into()));
        assert!(lonely.exists(), "a file with no locked copy is left alone");

        std::fs::write(sealed_path(&lonely), b"pretend this is the container").unwrap();
        shred_original(lonely.display().to_string()).unwrap();
        assert!(!lonely.exists(), "with a locked copy beside it, the original goes");
        std::fs::remove_dir_all(dir).ok();
    }
}
