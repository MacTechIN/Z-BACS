//! Watching for the events a session cares about.
//!
//! Polling `eth_getLogs` rather than a subscription: an agent behind a proxy often cannot hold
//! a WebSocket open, and the fallback has to be the thing that always works. The cost is a few
//! seconds of latency on a revoke, which the session's TTL already bounds (T20).

use std::time::Duration;

use alloy::primitives::{Address, B256};
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;

use crate::contracts::{AccessPolicy, FileRegistry};
use crate::error::{ChainError, Result};

/// Something happened on chain that a session must react to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainEvent {
    /// A grant was recorded.
    Granted {
        /// EIP-712 struct hash of the grant.
        grant_id: [u8; 32],
        /// File it is for.
        file_id: [u8; 32],
        /// 0 Deny, 1 ReadOnly, 2 Edit.
        permission: u8,
        /// Unix seconds it expires.
        expiry: u64,
    },
    /// The owner pulled access back. A session holding this grant must close now.
    Revoked {
        /// Grant that was revoked.
        grant_id: [u8; 32],
        /// File it was for.
        file_id: [u8; 32],
    },
    /// A file was resealed; older versions can no longer be granted.
    VersionBumped {
        /// File that moved forward.
        file_id: [u8; 32],
        /// New version number.
        version: u32,
        /// New header hash.
        header_hash: [u8; 32],
    },
}

/// Polls for [`ChainEvent`]s from a starting block.
pub struct EventWatcher {
    provider: DynProvider,
    policy: Address,
    registry: Address,
    next_block: u64,
}

impl EventWatcher {
    /// Watch from `from_block` onwards.
    pub fn new(provider: DynProvider, policy: Address, registry: Address, from_block: u64) -> Self {
        Self { provider, policy, registry, next_block: from_block }
    }

    /// The next block this watcher will read.
    pub fn next_block(&self) -> u64 {
        self.next_block
    }

    /// Fetch whatever happened since the last call.
    ///
    /// Returns an empty list when nothing did. Advancing only on success means a failed poll
    /// re-reads the same range rather than skipping it — a missed `Revoked` is the one thing
    /// this must never do.
    pub async fn poll(&mut self) -> Result<Vec<ChainEvent>> {
        let head =
            self.provider.get_block_number().await.map_err(|e| ChainError::Unreachable(e.to_string()))?;
        if head < self.next_block {
            return Ok(Vec::new());
        }

        let filter = Filter::new()
            .address(vec![self.policy, self.registry])
            .from_block(self.next_block)
            .to_block(head);
        let logs =
            self.provider.get_logs(&filter).await.map_err(|e| ChainError::Unreachable(e.to_string()))?;

        let mut events = Vec::new();
        for log in logs {
            let Some(topic) = log.topic0() else { continue };
            if *topic == AccessPolicy::Granted::SIGNATURE_HASH {
                if let Ok(decoded) = log.log_decode::<AccessPolicy::Granted>() {
                    let e = decoded.inner.data;
                    events.push(ChainEvent::Granted {
                        grant_id: e.grantId.0,
                        file_id: e.fileId.0,
                        permission: e.permission,
                        expiry: e.expiry,
                    });
                }
            } else if *topic == AccessPolicy::Revoked::SIGNATURE_HASH {
                if let Ok(decoded) = log.log_decode::<AccessPolicy::Revoked>() {
                    let e = decoded.inner.data;
                    events.push(ChainEvent::Revoked { grant_id: e.grantId.0, file_id: e.fileId.0 });
                }
            } else if *topic == FileRegistry::VersionBumped::SIGNATURE_HASH {
                if let Ok(decoded) = log.log_decode::<FileRegistry::VersionBumped>() {
                    let e = decoded.inner.data;
                    events.push(ChainEvent::VersionBumped {
                        file_id: e.fileId.0,
                        version: e.version,
                        header_hash: e.headerHash.0,
                    });
                }
            }
        }
        self.next_block = head + 1;
        Ok(events)
    }

    /// Poll forever, handing each event to `on_event`, until `should_stop` says otherwise.
    ///
    /// Keeps going through outages: the chain being unreachable is not a reason to stop
    /// listening for a revoke.
    pub async fn run<F>(&mut self, interval: Duration, mut on_event: F, should_stop: impl Fn() -> bool)
    where
        F: FnMut(ChainEvent),
    {
        while !should_stop() {
            match self.poll().await {
                Ok(events) => {
                    for event in events {
                        on_event(event);
                    }
                }
                Err(_) => { /* stay on this block range and try again */ }
            }
            tokio::time::sleep(interval).await;
        }
    }
}

/// Unused import guard for `B256` in doc examples.
#[allow(dead_code)]
type _B = B256;
