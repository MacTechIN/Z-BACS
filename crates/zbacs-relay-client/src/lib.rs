//! Z-1.R.5 — the agent side of the relay protocol.
//!
//! An agent has to keep working when the relay is slow, restarting, unreachable, or quietly
//! dropping it (T16, T21). This client therefore does three things the protocol makes possible:
//!
//! - **fails over** between several relay endpoints, so one operator cannot silence an owner;
//! - **retries** with backoff, and only for failures that might succeed later (a signature
//!   error never gets a second attempt);
//! - **retries the exact same bytes**, which makes a retry safe: the envelope's nonce means a
//!   duplicate that did land is answered `replayed`, and the client reads that as
//!   *already delivered* rather than as a failure. Re-signing with a fresh nonce would instead
//!   queue the message twice, which the owner would see as two requests for one file.
//!
//! Spec: `docs/specs/relay_protocol.md`.

#![warn(missing_docs)]

pub mod client;
pub mod error;

pub use client::{Delivery, RelayClient, RetryPolicy};
pub use error::ClientError;
