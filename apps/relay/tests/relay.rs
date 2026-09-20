//! Z-1.R.2 — the relay's behaviour, including what it refuses.
//!
//! These drive the router in-process (`tower::ServiceExt::oneshot`), so they exercise the real
//! handlers, parsing and state without binding a port.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use zbacs_proto::{
    AccessRequest, Ack, DeviceAnnounce, DeviceIdentity, Envelope, ErrorCode, GrantMsg, Kind, Revoke, Signed,
};
use zbacs_relay::{router, Relay};

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn nonce(tag: u8) -> [u8; 16] {
    let mut n = [0u8; 16];
    n[0] = tag;
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut n[1..]);
    n
}

async fn post(app: &axum::Router, path: &str, body: Vec<u8>) -> (StatusCode, Ack) {
    let res = app
        .clone()
        .oneshot(
            Request::post(path).header("content-type", "application/cbor").body(Body::from(body)).unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let ack: Ack = ciborium::from_reader(bytes.as_ref()).expect("ack is CBOR");
    (status, ack)
}

async fn inbox(app: &axum::Router, query: &str) -> Vec<Envelope> {
    let res = app
        .clone()
        .oneshot(Request::get(format!("/v1/inbox?{query}")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    ciborium::from_reader(bytes.as_ref()).expect("envelope list is CBOR")
}

fn announce_bytes(device: &DeviceIdentity, label: Option<&str>) -> Vec<u8> {
    let announce = DeviceAnnounce {
        x25519_pub: device.x25519_pub(),
        ed25519_pub: device.ed25519_pub(),
        label: label.map(str::to_string),
        ts: now(),
    };
    Signed::sign(device, &announce, now(), nonce(1)).unwrap().to_bytes().unwrap()
}

fn request_bytes(device: &DeviceIdentity, owner: &[u8], request_nonce: [u8; 16]) -> Vec<u8> {
    let request = AccessRequest {
        fid: [1; 32],
        header_hash: [2; 32],
        owner: owner.to_vec(),
        device_kid: device.kid(),
        x25519_pub: device.x25519_pub(),
        requested: 1,
        nonce: request_nonce,
        hint: None,
        ts: now(),
    };
    Signed::sign(device, &request, now(), nonce(2)).unwrap().to_bytes().unwrap()
}

fn grant_bytes(owner_device: &DeviceIdentity, request_nonce: [u8; 16], decision: u8) -> Vec<u8> {
    let grant = GrantMsg {
        request_nonce,
        grant: Some(vec![0xA1]),
        owner_sig: Some(vec![0xC3; 96]),
        envelope: if decision == 0 { None } else { Some(vec![0xD4; 120]) },
        tx_hash: None,
        decision,
        ts: now(),
    };
    Signed::sign(owner_device, &grant, now(), nonce(3)).unwrap().to_bytes().unwrap()
}

// ------------------------------------------------------------------ the whole round trip

#[tokio::test]
async fn a_request_reaches_the_owner_and_the_answer_comes_back() {
    let app = router(Relay::new());
    let bob = DeviceIdentity::generate().unwrap();
    let alice = DeviceIdentity::generate().unwrap();
    let owner_account = b"eip155:8453:0xA11CE";

    // both devices announce themselves
    for (d, label) in [(&bob, "업무용 노트북"), (&alice, "내 PC")] {
        let (status, ack) = post(&app, "/v1/devices", announce_bytes(d, Some(label))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(ack.ok);
    }

    // Bob asks
    let req_nonce = nonce(9);
    let (status, ack) = post(&app, "/v1/requests", request_bytes(&bob, owner_account, req_nonce)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(ack.ok && ack.id.is_some());

    // Alice reads her inbox and verifies Bob's signature herself
    let queued = inbox(&app, &format!("owner={}", hex::encode(owner_account))).await;
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].kind, Kind::Req);
    let (request, _) = Signed::from_bytes(&queued[0].body)
        .unwrap()
        .verify::<AccessRequest>(&bob.ed25519_pub(), now())
        .expect("relay must not alter the signed bytes");
    assert_eq!(request.nonce, req_nonce);
    assert_eq!(request.device_kid, bob.kid());

    // reading empties the queue
    assert!(inbox(&app, &format!("owner={}", hex::encode(owner_account))).await.is_empty());

    // Alice answers; the relay routes it back to Bob without being told who he is
    let (status, _) = post(&app, "/v1/grants", grant_bytes(&alice, req_nonce, 1)).await;
    assert_eq!(status, StatusCode::OK);

    let back = inbox(&app, &format!("device={}", hex::encode(bob.kid()))).await;
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].kind, Kind::Grant);
    let (grant, _) =
        Signed::from_bytes(&back[0].body).unwrap().verify::<GrantMsg>(&alice.ed25519_pub(), now()).unwrap();
    assert_eq!(grant.request_nonce, req_nonce);
    assert_eq!(grant.decision, 1);
}

#[tokio::test]
async fn a_refusal_travels_the_same_way_without_an_envelope() {
    let app = router(Relay::new());
    let bob = DeviceIdentity::generate().unwrap();
    let alice = DeviceIdentity::generate().unwrap();
    post(&app, "/v1/devices", announce_bytes(&bob, None)).await;
    post(&app, "/v1/devices", announce_bytes(&alice, None)).await;

    let req_nonce = nonce(9);
    post(&app, "/v1/requests", request_bytes(&bob, b"owner", req_nonce)).await;
    post(&app, "/v1/grants", grant_bytes(&alice, req_nonce, 0)).await;

    let back = inbox(&app, &format!("device={}", hex::encode(bob.kid()))).await;
    let (grant, _) =
        Signed::from_bytes(&back[0].body).unwrap().verify::<GrantMsg>(&alice.ed25519_pub(), now()).unwrap();
    assert_eq!(grant.decision, 0);
    assert!(grant.envelope.is_none());
}

#[tokio::test]
async fn revocations_are_queued() {
    let app = router(Relay::new());
    let alice = DeviceIdentity::generate().unwrap();
    post(&app, "/v1/devices", announce_bytes(&alice, None)).await;

    let revoke = Revoke { grant_id: [7; 32], fid: [1; 32], ts: now() };
    let body = Signed::sign(&alice, &revoke, now(), nonce(4)).unwrap().to_bytes().unwrap();
    let (status, ack) = post(&app, "/v1/revocations", body).await;
    assert_eq!(status, StatusCode::OK);
    assert!(ack.ok);
    assert_eq!(inbox(&app, &format!("device={}", hex::encode(alice.kid()))).await.len(), 1);
}

// ------------------------------------------------------------------ what it refuses

#[tokio::test]
async fn an_unregistered_device_is_refused() {
    let app = router(Relay::new());
    let stranger = DeviceIdentity::generate().unwrap();
    let (status, ack) = post(&app, "/v1/requests", request_bytes(&stranger, b"owner", nonce(9))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(ack.error, Some(ErrorCode::UnknownDevice));
}

/// T05: a message signed by one device must not claim to be about another.
#[tokio::test]
async fn t05_a_request_about_another_device_is_refused() {
    let app = router(Relay::new());
    let bob = DeviceIdentity::generate().unwrap();
    let eve = DeviceIdentity::generate().unwrap();
    post(&app, "/v1/devices", announce_bytes(&eve, None)).await;

    // Eve signs, but names Bob's device as the requester
    let request = AccessRequest {
        fid: [1; 32],
        header_hash: [2; 32],
        owner: b"owner".to_vec(),
        device_kid: bob.kid(),
        x25519_pub: bob.x25519_pub(),
        requested: 1,
        nonce: nonce(9),
        hint: None,
        ts: now(),
    };
    let body = Signed::sign(&eve, &request, now(), nonce(2)).unwrap().to_bytes().unwrap();
    let (status, ack) = post(&app, "/v1/requests", body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(ack.error, Some(ErrorCode::Unauthenticated));
}

#[tokio::test]
async fn a_tampered_body_is_refused() {
    let app = router(Relay::new());
    let bob = DeviceIdentity::generate().unwrap();
    post(&app, "/v1/devices", announce_bytes(&bob, None)).await;

    let mut body = request_bytes(&bob, b"owner", nonce(9));
    let last = body.len() - 1;
    body[last] ^= 1;
    let (status, ack) = post(&app, "/v1/requests", body).await;
    assert!(status == StatusCode::UNAUTHORIZED || status == StatusCode::BAD_REQUEST, "{status}");
    assert!(matches!(ack.error, Some(ErrorCode::Unauthenticated) | Some(ErrorCode::Malformed)));
}

/// T03: the same signed envelope cannot be submitted twice.
#[tokio::test]
async fn t03_a_replayed_envelope_is_refused() {
    let app = router(Relay::new());
    let bob = DeviceIdentity::generate().unwrap();
    post(&app, "/v1/devices", announce_bytes(&bob, None)).await;

    let body = request_bytes(&bob, b"owner", nonce(9));
    let (status, _) = post(&app, "/v1/requests", body.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let (status, ack) = post(&app, "/v1/requests", body).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(ack.error, Some(ErrorCode::Replayed));
}

#[tokio::test]
async fn a_stale_envelope_is_refused() {
    let app = router(Relay::new());
    let bob = DeviceIdentity::generate().unwrap();
    post(&app, "/v1/devices", announce_bytes(&bob, None)).await;

    let request = AccessRequest {
        fid: [1; 32],
        header_hash: [2; 32],
        owner: b"owner".to_vec(),
        device_kid: bob.kid(),
        x25519_pub: bob.x25519_pub(),
        requested: 1,
        nonce: nonce(9),
        hint: None,
        ts: now(),
    };
    // signed with a timestamp well outside the accepted window
    let body = Signed::sign(&bob, &request, now() - 600, nonce(2)).unwrap().to_bytes().unwrap();
    let (status, ack) = post(&app, "/v1/requests", body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(ack.error, Some(ErrorCode::Stale));
}

#[tokio::test]
async fn an_oversized_body_is_refused() {
    let app = router(Relay::new());
    let (status, ack) = post(&app, "/v1/requests", vec![0u8; 64 * 1024 + 1]).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(ack.error, Some(ErrorCode::TooLarge));
}

#[tokio::test]
async fn garbage_is_refused_without_panicking() {
    let app = router(Relay::new());
    for body in [vec![], vec![0xff, 0xff, 0xff], b"not cbor at all".to_vec()] {
        let (status, ack) = post(&app, "/v1/requests", body).await;
        assert!(status.is_client_error(), "{status}");
        assert!(ack.error.is_some());
    }
}

/// T16: a device cannot flood the relay.
#[tokio::test]
async fn t16_quota_stops_a_flood() {
    let app = router(Relay::new());
    let bob = DeviceIdentity::generate().unwrap();
    post(&app, "/v1/devices", announce_bytes(&bob, None)).await;

    let mut limited = false;
    for _ in 0..40 {
        let (status, ack) = post(&app, "/v1/requests", request_bytes(&bob, b"owner", nonce(9))).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(ack.error, Some(ErrorCode::RateLimited));
            limited = true;
            break;
        }
    }
    assert!(limited, "30 requests a minute should have been enforced");

    // a different device is unaffected
    let carol = DeviceIdentity::generate().unwrap();
    post(&app, "/v1/devices", announce_bytes(&carol, None)).await;
    let (status, _) = post(&app, "/v1/requests", request_bytes(&carol, b"owner", nonce(9))).await;
    assert_eq!(status, StatusCode::OK, "one device's flood must not starve another");
}

#[tokio::test]
async fn a_grant_for_an_unknown_request_goes_nowhere() {
    let app = router(Relay::new());
    let alice = DeviceIdentity::generate().unwrap();
    post(&app, "/v1/devices", announce_bytes(&alice, None)).await;
    let (status, ack) = post(&app, "/v1/grants", grant_bytes(&alice, nonce(42), 1)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(ack.error, Some(ErrorCode::NotFound));
}

#[tokio::test]
async fn an_announcement_must_carry_the_key_that_signed_it() {
    let app = router(Relay::new());
    let bob = DeviceIdentity::generate().unwrap();
    let eve = DeviceIdentity::generate().unwrap();

    // Eve signs an announcement that claims Bob's keys
    let announce = DeviceAnnounce {
        x25519_pub: bob.x25519_pub(),
        ed25519_pub: bob.ed25519_pub(),
        label: None,
        ts: now(),
    };
    let body = Signed::sign(&eve, &announce, now(), nonce(1)).unwrap().to_bytes().unwrap();
    let (status, ack) = post(&app, "/v1/devices", body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(ack.error, Some(ErrorCode::Unauthenticated));
}

#[tokio::test]
async fn inbox_queries_must_name_exactly_one_target() {
    let app = router(Relay::new());
    for query in ["", "owner=00&device=00", "device=zz", "owner="] {
        let res = app
            .clone()
            .oneshot(Request::get(format!("/v1/inbox?{query}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(res.status().is_client_error(), "{query} -> {}", res.status());
    }
}

#[tokio::test]
async fn health_needs_no_signature() {
    let app = router(Relay::new());
    let res = app.oneshot(Request::get("/v1/health").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

// ------------------------------------------------------------------ DoD: throughput

/// DoD: 100 requests a second. Measured against the real handlers in-process, with the quota
/// spread over enough devices that the limiter is not what we are timing.
///
/// Release-only: a debug build spends its time inside `ed25519-dalek` (115/s here), which says
/// nothing about the relay. Run it with the rest of the perf gate:
/// `cargo test --workspace --release -- --include-ignored perf_`.
#[tokio::test]
#[ignore = "perf gate runs in release: cargo test --release -- --include-ignored perf_"]
async fn perf_throughput_is_well_over_100_requests_per_second() {
    let app = router(Relay::new());
    let devices: Vec<_> = (0..40).map(|_| DeviceIdentity::generate().unwrap()).collect();
    for d in &devices {
        post(&app, "/v1/devices", announce_bytes(d, None)).await;
    }

    let total = 400;
    let start = Instant::now();
    for i in 0..total {
        let d = &devices[i % devices.len()];
        let (status, _) = post(&app, "/v1/requests", request_bytes(d, b"owner", nonce(9))).await;
        assert_eq!(status, StatusCode::OK, "request {i}");
    }
    let elapsed = start.elapsed();
    let rate = total as f64 / elapsed.as_secs_f64();
    println!("relay handled {total} signed requests in {elapsed:?} ({rate:.0}/s)");
    assert!(rate >= 100.0, "only {rate:.0} requests/s");
}
