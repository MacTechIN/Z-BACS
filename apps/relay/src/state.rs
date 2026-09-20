//! Relay state: who is registered, what is queued, what has been seen.
//!
//! Everything here is in memory. A relay that loses its queue costs the sender a retry; it
//! cannot lose anything secret, because it never holds anything secret (spec §7). Persistence
//! is a deployment choice, not a security one — Z-1.R.4 adds it for restarts.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::{rngs::OsRng, RngCore};
use zbacs_proto::{Envelope, Kind, NONCE_MEMORY_SECS};

/// How long an undelivered message waits (spec §6).
pub const QUEUE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Per-device quota: requests per minute (spec §6).
pub const RATE_PER_MINUTE: u32 = 30;
/// Per-device quota: requests per hour.
pub const RATE_PER_HOUR: u32 = 300;

/// A queue key: whose inbox this is.
///
/// Owners are addressed by the account bytes a request carries; recipients by the device key id
/// the relay remembers from their request. Neither is a secret, and neither tells the relay
/// anything about the file.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Inbox {
    /// Owner account identifier, copied from `AccessRequest.owner`.
    Owner(Vec<u8>),
    /// A requesting device.
    Device([u8; 16]),
}

struct Queued {
    envelope: Envelope,
    queued_at: Instant,
}

/// One registered device.
#[derive(Clone, Debug)]
pub struct Device {
    /// Ed25519 key that signs this device's envelopes.
    pub ed25519_pub: [u8; 32],
    /// X25519 key that receives DEK envelopes.
    pub x25519_pub: [u8; 32],
    /// Label for the owner's "my devices" list.
    pub label: Option<String>,
}

/// Shared relay state.
#[derive(Clone)]
pub struct Relay {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    devices: HashMap<[u8; 16], Device>,
    queues: HashMap<Inbox, VecDeque<Queued>>,
    /// Envelope nonces already accepted, with when they were seen.
    nonces: HashMap<[u8; 16], Instant>,
    /// `AccessRequest.nonce` → the device that asked, so a `GrantMsg` can be routed back
    /// without the owner having to say who it is for.
    request_routes: HashMap<[u8; 16], ([u8; 16], Instant)>,
    /// Per-device call timestamps for the quota.
    calls: HashMap<[u8; 16], VecDeque<Instant>>,
}

/// Why a submission was refused by the state layer.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The signing key id is not registered.
    UnknownDevice,
    /// This envelope nonce was already used.
    Replayed,
    /// The device is over its quota.
    RateLimited,
    /// A grant or revoke referenced a request the relay does not know.
    UnknownRequest,
}

impl Default for Relay {
    fn default() -> Self {
        Self::new()
    }
}

impl Relay {
    /// Empty relay.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                devices: HashMap::new(),
                queues: HashMap::new(),
                nonces: HashMap::new(),
                request_routes: HashMap::new(),
                calls: HashMap::new(),
            })),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("relay state mutex")
    }

    /// Register or refresh a device.
    pub fn announce(&self, kid: [u8; 16], device: Device) {
        self.lock().devices.insert(kid, device);
    }

    /// Look up a registered device's signing key.
    pub fn device(&self, kid: &[u8; 16]) -> Option<Device> {
        self.lock().devices.get(kid).cloned()
    }

    /// How many devices are registered.
    pub fn device_count(&self) -> usize {
        self.lock().devices.len()
    }

    /// Check the quota and record the call.
    pub fn take_quota(&self, kid: &[u8; 16], now: Instant) -> Result<(), Refusal> {
        let mut inner = self.lock();
        let calls = inner.calls.entry(*kid).or_default();
        while calls.front().is_some_and(|t| now.duration_since(*t) > Duration::from_secs(3600)) {
            calls.pop_front();
        }
        let last_minute = calls.iter().filter(|t| now.duration_since(**t) <= Duration::from_secs(60)).count();
        if last_minute >= RATE_PER_MINUTE as usize || calls.len() >= RATE_PER_HOUR as usize {
            return Err(Refusal::RateLimited);
        }
        calls.push_back(now);
        Ok(())
    }

    /// Record an envelope nonce, refusing a repeat (spec §3).
    pub fn take_nonce(&self, nonce: [u8; 16], now: Instant) -> Result<(), Refusal> {
        let mut inner = self.lock();
        inner.nonces.retain(|_, seen| now.duration_since(*seen) < Duration::from_secs(NONCE_MEMORY_SECS));
        if inner.nonces.contains_key(&nonce) {
            return Err(Refusal::Replayed);
        }
        inner.nonces.insert(nonce, now);
        Ok(())
    }

    /// Remember which device asked, so the answer can be routed back.
    pub fn remember_request(&self, request_nonce: [u8; 16], from: [u8; 16], now: Instant) {
        self.lock().request_routes.insert(request_nonce, (from, now));
    }

    /// Who asked for this request nonce?
    pub fn route_for(&self, request_nonce: &[u8; 16]) -> Result<[u8; 16], Refusal> {
        let mut inner = self.lock();
        let now = Instant::now();
        inner.request_routes.retain(|_, (_, at)| now.duration_since(*at) < QUEUE_TTL);
        inner.request_routes.get(request_nonce).map(|(kid, _)| *kid).ok_or(Refusal::UnknownRequest)
    }

    /// Put a signed message in an inbox. Returns the queue id.
    pub fn enqueue(&self, inbox: Inbox, kind: Kind, body: Vec<u8>, queued_at_unix: u64) -> [u8; 16] {
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        let envelope = Envelope { id, kind, body, queued_at: queued_at_unix };
        let mut inner = self.lock();
        let now = Instant::now();
        let queue = inner.queues.entry(inbox).or_default();
        while queue.front().is_some_and(|q| now.duration_since(q.queued_at) > QUEUE_TTL) {
            queue.pop_front();
        }
        queue.push_back(Queued { envelope, queued_at: now });
        id
    }

    /// Take everything waiting in an inbox.
    pub fn drain(&self, inbox: &Inbox) -> Vec<Envelope> {
        let mut inner = self.lock();
        let now = Instant::now();
        match inner.queues.get_mut(inbox) {
            Some(queue) => queue
                .drain(..)
                .filter(|q| now.duration_since(q.queued_at) <= QUEUE_TTL)
                .map(|q| q.envelope)
                .collect(),
            None => Vec::new(),
        }
    }

    /// How many messages are waiting (diagnostics and tests).
    pub fn queued(&self, inbox: &Inbox) -> usize {
        self.lock().queues.get(inbox).map_or(0, |q| q.len())
    }
}
