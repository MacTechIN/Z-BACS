//! Z-1.G.5 / Z-1.G.7 / Z-1.G.8 — the protected workspace.
//!
//! Decrypted plaintext only ever exists here: one directory per session, reachable by this user
//! alone, excluded from search indexing, and wiped when the session ends.
//!
//! What this can and cannot promise:
//! - it stops *other users* and casual processes from reading the file (ACL / `0700`);
//! - it does not stop the person who was granted access from copying it — that is T07, and only
//!   the Phase 3 minifilter changes it;
//! - `secure_delete` overwrites before unlinking, which defeats undelete tools but not an SSD's
//!   remapped blocks or a copy-on-write snapshot (T09; the forensic check is Z-1.Q.2).

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{Result, SessionError};

/// One session's directory.
#[derive(Debug)]
pub struct Workspace {
    root: PathBuf,
}

impl Workspace {
    /// Create `<base>/<session_id>` with restrictive permissions.
    ///
    /// `base` is normally `%LOCALAPPDATA%\Z-BACS\sessions` on Windows and
    /// `$XDG_RUNTIME_DIR/zbacs` elsewhere; [`Workspace::default_base`] picks it.
    pub fn create(base: &Path, session_id: &str) -> Result<Self> {
        if session_id.is_empty() || session_id.contains(['/', '\\', '.']) {
            return Err(SessionError::BadSessionId);
        }
        let root = base.join(session_id);
        fs::create_dir_all(&root)?;
        restrict(&root)?;
        exclude_from_indexing(&root)?;
        Ok(Self { root })
    }

    /// Where the OS wants per-user session scratch space.
    pub fn default_base() -> PathBuf {
        #[cfg(windows)]
        {
            std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir)
                .join("Z-BACS")
                .join("sessions")
        }
        #[cfg(not(windows))]
        {
            std::env::var_os("XDG_RUNTIME_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir)
                .join("zbacs")
                .join("sessions")
        }
    }

    /// The directory.
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// Full path for a file inside the workspace. Rejects anything that would escape it.
    pub fn file(&self, name: &str) -> Result<PathBuf> {
        if name.is_empty() || name.contains(['/', '\\']) || name.starts_with("..") {
            return Err(SessionError::BadFileName);
        }
        Ok(self.root.join(name))
    }

    /// Mark a file read-only (`ReadOnly` grants, Z-1.G.7).
    pub fn mark_read_only(&self, name: &str) -> Result<()> {
        let path = self.file(name)?;
        let mut perms = fs::metadata(&path)?.permissions();
        perms.set_readonly(true);
        fs::set_permissions(&path, perms)?;
        Ok(())
    }

    /// Undo [`Workspace::mark_read_only`] so the file can be wiped and removed.
    pub fn clear_read_only(&self, name: &str) -> Result<()> {
        let path = self.file(name)?;
        let mut perms = fs::metadata(&path)?.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        fs::set_permissions(&path, perms)?;
        Ok(())
    }

    /// Overwrite every file with zeros, then delete the directory (Z-1.G.8).
    ///
    /// Errors are collected rather than returned early: a session must end even if one file is
    /// locked by a viewer that has not quit yet.
    pub fn wipe(self) -> Result<()> {
        let mut first_error = None;
        if let Ok(entries) = fs::read_dir(&self.root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Err(e) = secure_delete(&path) {
                        first_error.get_or_insert(e);
                    }
                }
            }
        }
        if let Err(e) = fs::remove_dir_all(&self.root) {
            if e.kind() != std::io::ErrorKind::NotFound {
                first_error.get_or_insert(SessionError::Io(e));
            }
        }
        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// Overwrite a file's bytes with zeros, flush to the device, then remove it.
pub fn secure_delete(path: &Path) -> Result<()> {
    let meta = fs::metadata(path)?;
    if meta.permissions().readonly() {
        let mut perms = meta.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        fs::set_permissions(path, perms)?;
    }
    let len = meta.len();
    {
        let mut f = fs::OpenOptions::new().write(true).open(path)?;
        f.seek(SeekFrom::Start(0))?;
        let zeros = vec![0u8; 64 * 1024];
        let mut left = len;
        while left > 0 {
            let n = left.min(zeros.len() as u64) as usize;
            f.write_all(&zeros[..n])?;
            left -= n as u64;
        }
        f.flush()?;
        f.sync_all()?;
    }
    fs::remove_file(path)?;
    Ok(())
}

/// Restrict the directory to the current user.
#[cfg(unix)]
fn restrict(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// On Windows a fresh directory under `%LOCALAPPDATA%` already inherits a user-only ACL; the
/// Agent tightens it further (removing inherited groups) in Z-1.G.5's installer step, which
/// needs the process to run as the user whose profile it is.
#[cfg(windows)]
fn restrict(path: &Path) -> Result<()> {
    let _ = path;
    Ok(())
}

/// Keep the plaintext out of the search index (and, on Windows, out of File History).
#[cfg(windows)]
fn exclude_from_indexing(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        GetFileAttributesW, SetFileAttributesW, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
        FILE_FLAGS_AND_ATTRIBUTES, INVALID_FILE_ATTRIBUTES,
    };

    // The workspace is a directory: `FILE_ATTRIBUTE_TEMPORARY` is a file-only attribute and
    // Windows answers it with ERROR_INVALID_PARAMETER (found by the first real Windows run in
    // CI). Not-content-indexed is what keeps the plaintext out of Search; it is OR-ed onto
    // whatever the directory already has, because SetFileAttributesW replaces the whole set.
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    unsafe {
        let current = GetFileAttributesW(PCWSTR(wide.as_ptr()));
        if current == INVALID_FILE_ATTRIBUTES {
            return Err(SessionError::Workspace("get attributes: not found".into()));
        }
        SetFileAttributesW(
            PCWSTR(wide.as_ptr()),
            FILE_FLAGS_AND_ATTRIBUTES(current) | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
        )
        .map_err(|e| SessionError::Workspace(format!("set attributes: {e}")))?;
    }
    Ok(())
}

/// Other platforms: nothing standard to set. macOS exclusion from Spotlight/Time Machine is
/// Z-2.G.1.
#[cfg(not(windows))]
fn exclude_from_indexing(path: &Path) -> Result<()> {
    let _ = path;
    Ok(())
}
