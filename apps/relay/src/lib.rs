//! Z-1.R.2 — the Z-BACS relay.
//!
//! It moves signed blobs between two agents that cannot reach each other directly, and that is
//! all it is trusted to do. It verifies that a message really came from a registered device
//! (so it can refuse to be a free spam queue), refuses replays, and applies quotas. It cannot
//! read a request's contents in any meaningful sense, cannot forge a grant, and cannot decrypt
//! an envelope — those rest on the owner's signature and HPKE, which bypass it entirely
//! (spec `relay_protocol.md`, T04/T05/T16).
//!
//! Routing is deliberately dumb: a request goes to the owner's inbox named in the request, and
//! the answer goes back to whoever asked, which the relay remembers by request nonce. Nothing
//! else about the file or the people is needed.

#![warn(missing_docs)]

pub mod routes;
pub mod state;

pub use routes::router;
pub use state::{Device, Inbox, Refusal, Relay};
