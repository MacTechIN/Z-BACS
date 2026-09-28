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
//! Writes go through one trait, [`ChainWriter`] (Z-1.H.8, ADR-0008): in production they travel
//! as user operations from the owner's smart account through a bundler so the owner never
//! needs gas ([`SmartAccountWriter`]); on Anvil or a self-hosted deployment a funded key sends
//! them as plain transactions ([`DirectWriter`]). The Agent does not care which.

#![warn(missing_docs)]

pub mod aa;
pub mod bundler;
pub mod cache;
pub mod calls;
pub mod client;
pub mod contracts;
pub mod error;
pub mod watcher;
pub mod writer;

pub use aa::{KernelAccount, PackedUserOperation, RootValidator, ENTRY_POINT_V07};
pub use bundler::{Bundler, JsonRpcBundler, RpcUserOperation, UserOpReceipt, UserOpSender};
pub use cache::{Cache, Cached, Freshness, VersionRecord};
pub use client::{ChainClient, Deployment};
pub use error::ChainError;
pub use watcher::{ChainEvent, EventWatcher};
pub use writer::{ChainWriter, DirectWriter, SmartAccountWriter, UserOpSigner, Write};
