//! The client itself.

use std::time::Duration;

use rand::{rngs::OsRng, RngCore};
use zbacs_proto::messages::Message;
use zbacs_proto::{
    AccessRequest, Ack, DeviceAnnounce, DeviceIdentity, Envelope, ErrorCode, GrantMsg, Revoke, Signed,
};

use crate::error::{retryable, ClientError, Result};

/// How hard to try before giving up on all endpoints.
#[derive(Clone, Copy, Debug)]
pub struct RetryPolicy {
    /// Attempts per endpoint before moving to the next one.
    pub attempts_per_endpoint: u32,
    /// Delay before the second attempt; doubles each time.
    pub initial_backoff: Duration,
    /// Upper bound on the delay.
    pub max_backoff: Duration,
    /// How long one HTTP call may take.
    pub request_timeout: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            attempts_per_endpoint: 3,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(10),
            request_timeout: Duration::from_secs(15),
        }
    }
}

impl RetryPolicy {
    /// Backoff before attempt `n` (0-based), with jitter so a fleet of agents coming back after
    /// an outage does not hit the relay in lockstep.
    fn backoff(&self, n: u32) -> Duration {
        let base = self.initial_backoff.saturating_mul(1u32 << n.min(16));
        let base = base.min(self.max_backoff);
        let jitter = (OsRng.next_u32() % 1000) as u64;
        base + Duration::from_millis(jitter % (base.as_millis() as u64 / 2 + 1))
    }
}

/// Install rustls' `ring` provider once per process.
///
/// rustls needs one process-wide provider. We pick `ring` over the default `aws-lc-rs` because
/// the latter needs a C toolchain, cmake and NASM to build — a cost every Windows developer of
/// the Agent would pay. If the host application already installed a provider, that one wins and
/// this is a no-op.
fn install_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// What happened to a submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// The relay accepted it and queued it under this id.
    Queued([u8; 16]),
    /// A retry found the relay had already accepted this exact envelope. Nothing was
    /// duplicated; treat it as success (see the crate docs).
    AlreadyDelivered,
}

/// Talks to one or more relays on behalf of one device.
pub struct RelayClient {
    endpoints: Vec<String>,
    http: reqwest::Client,
    device: DeviceIdentity,
    policy: RetryPolicy,
}

impl RelayClient {
    /// Build a client. `endpoints` are tried in order; list more than one so a single relay
    /// cannot censor this agent (T21).
    pub fn new(endpoints: Vec<String>, device: DeviceIdentity) -> Result<Self> {
        Self::with_policy(endpoints, device, RetryPolicy::default())
    }

    /// Build a client with a custom [`RetryPolicy`].
    pub fn with_policy(endpoints: Vec<String>, device: DeviceIdentity, policy: RetryPolicy) -> Result<Self> {
        if endpoints.is_empty() {
            return Err(ClientError::Unreachable("no relay endpoints configured".into()));
        }
        install_crypto_provider();
        let http = reqwest::Client::builder()
            .timeout(policy.request_timeout)
            .build()
            .map_err(|e| ClientError::Unreachable(e.to_string()))?;
        Ok(Self {
            endpoints: endpoints.into_iter().map(|e| e.trim_end_matches('/').to_string()).collect(),
            http,
            device,
            policy,
        })
    }

    /// The device this client speaks for.
    pub fn device(&self) -> &DeviceIdentity {
        &self.device
    }

    /// Endpoints in the order they are tried.
    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }

    fn now(&self) -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }

    fn sign<T: Message>(&self, payload: &T) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        Ok(Signed::sign(&self.device, payload, self.now(), nonce)?.to_bytes()?)
    }

    /// Register this device with every endpoint (each relay keeps its own registry).
    pub async fn announce(&self, label: Option<&str>) -> Result<Delivery> {
        let announce = DeviceAnnounce {
            x25519_pub: self.device.x25519_pub(),
            ed25519_pub: self.device.ed25519_pub(),
            label: label.map(str::to_string),
            ts: self.now(),
        };
        self.submit("/v1/devices", &self.sign(&announce)?).await
    }

    /// Ask an owner for access.
    pub async fn send_request(&self, request: &AccessRequest) -> Result<Delivery> {
        self.submit("/v1/requests", &self.sign(request)?).await
    }

    /// Answer a request.
    pub async fn send_grant(&self, grant: &GrantMsg) -> Result<Delivery> {
        self.submit("/v1/grants", &self.sign(grant)?).await
    }

    /// Pull access back.
    pub async fn send_revoke(&self, revoke: &Revoke) -> Result<Delivery> {
        self.submit("/v1/revocations", &self.sign(revoke)?).await
    }

    /// Read this device's inbox.
    pub async fn inbox_for_device(&self) -> Result<Vec<Envelope>> {
        let kid = hex::encode(self.device.kid());
        self.fetch_inbox(&format!("device={kid}")).await
    }

    /// Read an owner account's inbox.
    pub async fn inbox_for_owner(&self, owner: &[u8]) -> Result<Vec<Envelope>> {
        self.fetch_inbox(&format!("owner={}", hex::encode(owner))).await
    }

    /// Is any relay answering?
    pub async fn health(&self) -> bool {
        for endpoint in &self.endpoints {
            if let Ok(res) = self.http.get(format!("{endpoint}/v1/health")).send().await {
                if res.status().is_success() {
                    return true;
                }
            }
        }
        false
    }

    /// Submit the *same bytes* on every attempt (see the crate docs on idempotent retries).
    async fn submit(&self, path: &str, body: &[u8]) -> Result<Delivery> {
        let mut last = String::from("not attempted");
        for endpoint in &self.endpoints {
            for attempt in 0..self.policy.attempts_per_endpoint {
                if attempt > 0 {
                    tokio::time::sleep(self.policy.backoff(attempt - 1)).await;
                }
                match self.submit_once(endpoint, path, body).await {
                    Ok(delivery) => return Ok(delivery),
                    Err(ClientError::Refused(code)) if !retryable(code) => {
                        return Err(ClientError::Refused(code));
                    }
                    Err(ClientError::Refused(code)) => last = format!("{endpoint}: {code:?}"),
                    Err(e) => last = format!("{endpoint}: {e}"),
                }
            }
        }
        Err(ClientError::Unreachable(last))
    }

    async fn submit_once(&self, endpoint: &str, path: &str, body: &[u8]) -> Result<Delivery> {
        let res = self
            .http
            .post(format!("{endpoint}{path}"))
            .header("content-type", "application/cbor")
            .body(body.to_vec())
            .send()
            .await
            .map_err(|e| ClientError::Unreachable(e.to_string()))?;

        let status = res.status();
        let bytes = res.bytes().await.map_err(|e| ClientError::Unreachable(e.to_string()))?;
        let ack: Ack = ciborium::from_reader(bytes.as_ref())
            .map_err(|_| ClientError::BadResponse(format!("HTTP {status} with a non-CBOR body")))?;

        match (ack.ok, ack.error) {
            (true, _) => Ok(Delivery::Queued(ack.id.unwrap_or_default())),
            // The relay remembers this envelope, so a previous attempt reached it.
            (false, Some(ErrorCode::Replayed)) => Ok(Delivery::AlreadyDelivered),
            (false, Some(code)) => Err(ClientError::Refused(code)),
            (false, None) => Err(ClientError::BadResponse(format!("HTTP {status} with no error code"))),
        }
    }

    async fn fetch_inbox(&self, query: &str) -> Result<Vec<Envelope>> {
        let mut last = String::from("not attempted");
        for endpoint in &self.endpoints {
            for attempt in 0..self.policy.attempts_per_endpoint {
                if attempt > 0 {
                    tokio::time::sleep(self.policy.backoff(attempt - 1)).await;
                }
                match self.http.get(format!("{endpoint}/v1/inbox?{query}")).send().await {
                    Ok(res) if res.status().is_success() => {
                        let bytes = res.bytes().await.map_err(|e| ClientError::Unreachable(e.to_string()))?;
                        return ciborium::from_reader(bytes.as_ref())
                            .map_err(|e| ClientError::BadResponse(e.to_string()));
                    }
                    Ok(res) => last = format!("{endpoint}: HTTP {}", res.status()),
                    Err(e) => last = format!("{endpoint}: {e}"),
                }
            }
        }
        Err(ClientError::Unreachable(last))
    }

    /// Poll for messages until `should_stop` says otherwise, reconnecting through outages.
    ///
    /// This is the fallback transport from spec §2; the WebSocket stream is the Agent's job
    /// (Z-1.G.9) because it needs the UI's event loop. Polling keeps working when a proxy or
    /// firewall eats WebSocket upgrades, which is why the spec has both.
    pub async fn poll_device_inbox<F>(
        &self,
        interval: Duration,
        mut on_envelope: F,
        should_stop: impl Fn() -> bool,
    ) where
        F: FnMut(Envelope),
    {
        let mut failures: u32 = 0;
        while !should_stop() {
            match self.inbox_for_device().await {
                Ok(envelopes) => {
                    failures = 0;
                    for envelope in envelopes {
                        on_envelope(envelope);
                    }
                    tokio::time::sleep(interval).await;
                }
                Err(_) => {
                    // back off while the relay is down, then carry on without giving up: the
                    // owner may answer at any moment and the agent must still be listening.
                    tokio::time::sleep(self.policy.backoff(failures)).await;
                    failures = failures.saturating_add(1);
                }
            }
        }
    }
}
