//! Z-1.R.5 — the client against the real relay, over real HTTP.
//!
//! DoD: reconnect and retry. So these start and stop actual servers rather than mocking the
//! transport, which is where the interesting failures live.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;
use zbacs_proto::{AccessRequest, DeviceIdentity, GrantMsg, Kind, Revoke, Signed};
use zbacs_relay::{router, Relay};
use zbacs_relay_client::{ClientError, Delivery, RelayClient, RetryPolicy};

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn quick() -> RetryPolicy {
    RetryPolicy {
        attempts_per_endpoint: 3,
        initial_backoff: Duration::from_millis(20),
        max_backoff: Duration::from_millis(100),
        request_timeout: Duration::from_secs(5),
    }
}

/// Start a relay on a free port. Returns its URL and a handle that stops it when dropped.
async fn start_relay() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router(Relay::new())).await;
    });
    (format!("http://{addr}"), handle)
}

/// A free port with nothing listening on it.
async fn dead_endpoint() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{addr}")
}

fn request_for(device: &DeviceIdentity, owner: &[u8], nonce: [u8; 16]) -> AccessRequest {
    AccessRequest {
        fid: [1; 32],
        header_hash: [2; 32],
        owner: owner.to_vec(),
        device_kid: device.kid(),
        x25519_pub: device.x25519_pub(),
        ed25519_pub: device.ed25519_pub(),
        requested: 1,
        nonce,
        hint: None,
        ts: now(),
    }
}

// ------------------------------------------------------------------ the happy path, end to end

#[tokio::test]
async fn an_agent_pair_exchanges_a_request_and_a_grant_over_http() {
    let (url, server) = start_relay().await;
    let bob =
        RelayClient::with_policy(vec![url.clone()], DeviceIdentity::generate().unwrap(), quick()).unwrap();
    let alice = RelayClient::with_policy(vec![url], DeviceIdentity::generate().unwrap(), quick()).unwrap();

    assert!(bob.health().await);
    assert!(matches!(bob.announce(Some("업무용 노트북")).await.unwrap(), Delivery::Queued(_)));
    assert!(matches!(alice.announce(Some("내 PC")).await.unwrap(), Delivery::Queued(_)));

    let owner = b"eip155:8453:0xA11CE";
    let nonce = [9u8; 16];
    bob.send_request(&request_for(bob.device(), owner, nonce)).await.unwrap();

    // Alice picks it up and checks Bob's signature herself
    let waiting = alice.inbox_for_owner(owner).await.unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].kind, Kind::Req);
    let (request, _) = Signed::from_bytes(&waiting[0].body)
        .unwrap()
        .verify::<AccessRequest>(&bob.device().ed25519_pub(), now())
        .unwrap();
    assert_eq!(request.nonce, nonce);

    // Alice answers; Bob receives it without either side naming the other
    let grant = GrantMsg {
        request_nonce: nonce,
        grant: Some(vec![0xA1]),
        owner_sig: Some(vec![0xC3; 96]),
        envelope: Some(vec![0xD4; 120]),
        tx_hash: None,
        decision: 1,
        ts: now(),
    };
    alice.send_grant(&grant).await.unwrap();

    let back = bob.inbox_for_device().await.unwrap();
    assert_eq!(back.len(), 1);
    let (got, _) = Signed::from_bytes(&back[0].body)
        .unwrap()
        .verify::<GrantMsg>(&alice.device().ed25519_pub(), now())
        .unwrap();
    assert_eq!(got.decision, 1);
    assert_eq!(got.request_nonce, nonce);

    // and a revoke travels the same way
    alice.send_revoke(&Revoke { grant_id: [7; 32], fid: [1; 32], ts: now() }).await.unwrap();
    assert_eq!(alice.inbox_for_device().await.unwrap().len(), 1);

    server.abort();
}

// ------------------------------------------------------------------ failover and retry (the DoD)

/// T21: one relay being unreachable must not silence an agent.
#[tokio::test]
async fn t21_a_dead_endpoint_falls_over_to_a_live_one() {
    let dead = dead_endpoint().await;
    let (live, server) = start_relay().await;
    let client =
        RelayClient::with_policy(vec![dead, live], DeviceIdentity::generate().unwrap(), quick()).unwrap();

    assert!(client.health().await, "health must consider every endpoint");
    assert!(matches!(client.announce(None).await.unwrap(), Delivery::Queued(_)));
    assert!(client.send_request(&request_for(client.device(), b"owner", [1; 16])).await.is_ok());
    server.abort();
}

#[tokio::test]
async fn every_endpoint_down_reports_unreachable_not_silence() {
    let a = dead_endpoint().await;
    let b = dead_endpoint().await;
    let client = RelayClient::with_policy(vec![a, b], DeviceIdentity::generate().unwrap(), quick()).unwrap();

    assert!(!client.health().await);
    let err = client.announce(None).await.unwrap_err();
    assert!(matches!(err, ClientError::Unreachable(_)), "{err:?}");
    assert!(err.is_transient(), "the agent should keep trying later");
}

/// A relay that restarts mid-session: the agent reconnects without being told to.
#[tokio::test]
async fn the_client_recovers_when_a_relay_comes_back() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");
    drop(listener); // nothing listening yet

    let client =
        RelayClient::with_policy(vec![url.clone()], DeviceIdentity::generate().unwrap(), quick()).unwrap();
    assert!(client.announce(None).await.is_err(), "nothing is listening yet");

    // the relay comes up on the same address
    let listener = TcpListener::bind(addr).await.unwrap();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, router(Relay::new())).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert!(matches!(client.announce(None).await.unwrap(), Delivery::Queued(_)));
    server.abort();
}

/// The retry safety property: resending the same envelope cannot duplicate a queued message.
#[tokio::test]
async fn t03_a_retry_of_a_delivered_message_is_reported_as_already_delivered() {
    let (url, server) = start_relay().await;
    let client =
        RelayClient::with_policy(vec![url.clone()], DeviceIdentity::generate().unwrap(), quick()).unwrap();
    client.announce(None).await.unwrap();

    // Sign one envelope and submit its exact bytes twice, which is what a retry after a lost
    // response does.
    let request = request_for(client.device(), b"owner", [3; 16]);
    let body = Signed::sign(client.device(), &request, now(), [5; 16]).unwrap().to_bytes().unwrap();

    let http = reqwest::Client::new();
    let post = |body: Vec<u8>| {
        let http = http.clone();
        let url = url.clone();
        async move { http.post(format!("{url}/v1/requests")).body(body).send().await.unwrap().status() }
    };
    assert_eq!(post(body.clone()).await, StatusCode::OK);
    assert_eq!(post(body).await, StatusCode::CONFLICT, "the relay refuses the duplicate");

    // the owner sees one request, not two
    assert_eq!(client.inbox_for_owner(b"owner").await.unwrap().len(), 1);
    server.abort();
}

/// A permanent refusal must not be retried: an unregistered device will still be unregistered.
#[tokio::test]
async fn a_permanent_refusal_is_returned_immediately() {
    let attempts = Arc::new(AtomicU32::new(0));
    let counter = attempts.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route(
        "/v1/requests",
        post(move || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut body = Vec::new();
                ciborium::into_writer(
                    &zbacs_proto::Ack {
                        ok: false,
                        id: None,
                        error: Some(zbacs_proto::ErrorCode::UnknownDevice),
                    },
                    &mut body,
                )
                .unwrap();
                (StatusCode::UNAUTHORIZED, body)
            }
        }),
    );
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let client = RelayClient::with_policy(
        vec![format!("http://{addr}")],
        DeviceIdentity::generate().unwrap(),
        quick(),
    )
    .unwrap();
    let err = client.send_request(&request_for(client.device(), b"owner", [1; 16])).await.unwrap_err();
    assert!(matches!(err, ClientError::Refused(zbacs_proto::ErrorCode::UnknownDevice)), "{err:?}");
    assert_eq!(attempts.load(Ordering::SeqCst), 1, "a permanent refusal must not be retried");
    server.abort();
}

/// A transient refusal (the relay is overloaded) is retried, and succeeds when it clears.
#[tokio::test]
async fn a_rate_limited_submission_is_retried_until_it_clears() {
    let attempts = Arc::new(AtomicU32::new(0));
    let counter = attempts.clone();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route(
        "/v1/devices",
        post(move || {
            let counter = counter.clone();
            async move {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                let mut body = Vec::new();
                if n < 2 {
                    ciborium::into_writer(
                        &zbacs_proto::Ack {
                            ok: false,
                            id: None,
                            error: Some(zbacs_proto::ErrorCode::RateLimited),
                        },
                        &mut body,
                    )
                    .unwrap();
                    (StatusCode::TOO_MANY_REQUESTS, body)
                } else {
                    ciborium::into_writer(
                        &zbacs_proto::Ack { ok: true, id: Some([7; 16]), error: None },
                        &mut body,
                    )
                    .unwrap();
                    (StatusCode::OK, body)
                }
            }
        }),
    );
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let client = RelayClient::with_policy(
        vec![format!("http://{addr}")],
        DeviceIdentity::generate().unwrap(),
        quick(),
    )
    .unwrap();
    assert_eq!(client.announce(None).await.unwrap(), Delivery::Queued([7; 16]));
    assert_eq!(attempts.load(Ordering::SeqCst), 3, "two refusals then success");
    server.abort();
}

#[tokio::test]
async fn a_relay_answering_nonsense_is_reported_not_believed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/v1/devices", post(|| async { (StatusCode::OK, "definitely not cbor") }))
        .route("/v1/health", get(|| async { StatusCode::OK }));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let client = RelayClient::with_policy(
        vec![format!("http://{addr}")],
        DeviceIdentity::generate().unwrap(),
        quick(),
    )
    .unwrap();
    let err = client.announce(None).await.unwrap_err();
    assert!(matches!(err, ClientError::Unreachable(_) | ClientError::BadResponse(_)), "{err:?}");
    server.abort();
}

#[tokio::test]
async fn polling_keeps_running_through_an_outage() {
    let (url, server) = start_relay().await;
    let bob =
        RelayClient::with_policy(vec![url.clone()], DeviceIdentity::generate().unwrap(), quick()).unwrap();
    let alice = RelayClient::with_policy(vec![url], DeviceIdentity::generate().unwrap(), quick()).unwrap();
    bob.announce(None).await.unwrap();
    alice.announce(None).await.unwrap();

    let received = Arc::new(AtomicU32::new(0));
    let counter = received.clone();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_flag = stop.clone();

    let poller = tokio::spawn(async move {
        bob.poll_device_inbox(
            Duration::from_millis(20),
            |_| {
                counter.fetch_add(1, Ordering::SeqCst);
            },
            move || stop_flag.load(Ordering::SeqCst),
        )
        .await;
    });

    // a request so the grant has somewhere to go, then the grant itself
    let nonce = [4u8; 16];
    let request = request_for(&DeviceIdentity::generate().unwrap(), b"owner", nonce);
    let _ = request; // the grant below is routed by the relay's memory of Bob's own request
    let bob2 = RelayClient::with_policy(
        vec![alice.endpoints()[0].clone()],
        DeviceIdentity::generate().unwrap(),
        quick(),
    )
    .unwrap();
    bob2.announce(None).await.unwrap();
    bob2.send_request(&request_for(bob2.device(), b"owner", nonce)).await.unwrap();

    alice.send_revoke(&Revoke { grant_id: [1; 32], fid: [2; 32], ts: now() }).await.unwrap();

    // Alice's own revoke lands in her inbox; Bob's poller should see nothing but keep running
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(received.load(Ordering::SeqCst), 0);

    // now stop the relay and confirm the poller survives the outage
    server.abort();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!poller.is_finished(), "the poller must wait for the relay to return");

    stop.store(true, Ordering::SeqCst);
    let _ = tokio::time::timeout(Duration::from_secs(3), poller).await;
}

#[tokio::test]
async fn a_client_needs_at_least_one_endpoint() {
    match RelayClient::new(vec![], DeviceIdentity::generate().unwrap()) {
        Err(ClientError::Unreachable(_)) => {}
        Err(other) => panic!("wrong error: {other:?}"),
        Ok(_) => panic!("a client with no endpoints must not be built"),
    }
}
