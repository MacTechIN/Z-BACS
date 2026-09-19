//! Z-BACS session lifecycle.
//!
//! One approval, from the request to the moment the plaintext is gone:
//!
//! - [`Session`] — the state machine that decides what may happen (Z-1.G.4).
//! - [`Workspace`] — the only place plaintext lives, and how it is destroyed (Z-1.G.5/G.7/G.8).
//!
//! The Agent owns the I/O; this crate owns the rules, so they can be tested on their own.

#![warn(missing_docs)]

pub mod error;
pub mod state;
pub mod workspace;

pub use error::SessionError;
pub use state::{AuditKind, Effect, Event, Notice, Session, State, TransitionError};
pub use workspace::{secure_delete, Workspace};
