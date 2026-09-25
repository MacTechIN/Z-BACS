//! Z-1.H.7 — the Agent's view of the chain.
//!
//! Three jobs, and a rule about each:
//!
//! - **read** what the chain says about a file or a grant. Cheap and unauthenticated; anyone
//!   can do it, which is the point — a recipient checks the owner's decision themselves.
//! - **watch** for `Granted` / `Revoked` / `VersionBumped`, so a revoke closes a session even
//!   when the relay never delivers one (T20, T16: the chain is the fallback channel).
//! - **remember**, because the chain is not always reachable. [`Cache`] keeps the last answer
//!   with the time it was taken, and the caller decides what a stale answer is worth: a
//!   `strict_onchain` file must not open on one, an ordinary file may (spec §2.6).
//!
//! Writes exist here for the owner's own agent and for tests. In production most writes travel
//! as user operations through a bundler (Z-1.H.8) so the owner never needs gas; this crate is
//! the direct path a self-hosted deployment or a test uses.

#![warn(missing_docs)]

pub mod aa;
pub mod bundler;
pub mod cache;
pub mod calls;
pub mod client;
pub mod contracts;
pub mod error;
pub mod watcher;

pub use aa::{KernelAccount, PackedUserOperation, RootValidator, ENTRY_POINT_V07};
pub use bundler::{Bundler, JsonRpcBundler, RpcUserOperation, UserOpReceipt, UserOpSender};
pub use cache::{Cache, Cached, Freshness, VersionRecord};
pub use client::{ChainClient, Deployment};
pub use error::ChainError;
pub use watcher::{ChainEvent, EventWatcher};
