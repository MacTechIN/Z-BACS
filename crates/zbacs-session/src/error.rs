//! Session errors. No plaintext, no keys, no absolute paths of user files.

use thiserror::Error;

/// Something went wrong driving a session.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SessionError {
    /// Filesystem trouble.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Session id would escape the workspace root.
    #[error("session id must be a plain name")]
    BadSessionId,
    /// File name would escape the workspace.
    #[error("file name must not contain a path separator")]
    BadFileName,
    /// Platform call failed while protecting the workspace.
    #[error("workspace: {0}")]
    Workspace(String),
}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, SessionError>;
