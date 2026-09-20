//! HTTP and WebSocket surface (spec §2).

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use zbacs_proto::{
    AccessRequest, Ack, DeviceAnnounce, ErrorCode, GrantMsg, Kind, Revoke, Signed, MAX_BODY_LEN,
};

use crate::state::{Device, Inbox, Refusal, Relay};

/// Build the relay router.
pub fn router(relay: Relay) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/devices", post(devices))
        .route("/v1/requests", post(requests))
        .route("/v1/grants", post(grants))
        .route("/v1/revocations", post(revocations))
        .route("/v1/inbox", get(inbox))
        .route("/v1/stream", get(stream))
        .with_state(relay)
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// CBOR response with the right content type.
fn cbor<T: serde::Serialize>(status: StatusCode, value: &T) -> Response {
    let mut body = Vec::new();
    if ciborium::into_writer(value, &mut body).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let mut res = (status, body).into_response();
    res.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/cbor"));
    res
}

fn refuse(code: ErrorCode) -> Response {
    let status = StatusCode::from_u16(code.http_status()).unwrap_or(StatusCode::BAD_REQUEST);
    cbor(status, &Ack { ok: false, id: None, error: Some(code) })
}

fn accept(id: [u8; 16]) -> Response {
    cbor(StatusCode::OK, &Ack { ok: true, id: Some(id), error: None })
}

fn refusal_code(r: Refusal) -> ErrorCode {
    match r {
        Refusal::UnknownDevice => ErrorCode::UnknownDevice,
        Refusal::Replayed => ErrorCode::Replayed,
        Refusal::RateLimited => ErrorCode::RateLimited,
        Refusal::UnknownRequest => ErrorCode::NotFound,
    }
}

/// Parse and authenticate a submission.
///
/// Order matters: shape, then size, then *who signed it*, then quota, then replay. A device
/// that is not registered never consumes another device's quota, and a bad signature never
/// burns a nonce.
fn authenticate<T: zbacs_proto::messages::Message>(
    relay: &Relay,
    body: &Bytes,
) -> Result<(Signed, T), ErrorCode> {
    if body.len() > MAX_BODY_LEN {
        return Err(ErrorCode::TooLarge);
    }
    let signed = Signed::from_bytes(body).map_err(|e| e.code())?;
    let device = relay.device(&signed.kid).ok_or(ErrorCode::UnknownDevice)?;
    let (payload, nonce) = signed.verify::<T>(&device.ed25519_pub, now_unix()).map_err(|e| e.code())?;

    let now = Instant::now();
    relay.take_quota(&signed.kid, now).map_err(refusal_code)?;
    relay.take_nonce(nonce, now).map_err(refusal_code)?;
    Ok((signed, payload))
}

async fn health() -> Response {
    cbor(StatusCode::OK, &Ack { ok: true, id: None, error: None })
}

/// Register a device. Self-signed on purpose: the announcement carries the very key that signs
/// it, so the relay learns "this key exists" and nothing more. Trust comes from the owner
/// enrolling the device on chain, not from the relay believing this message.
async fn devices(State(relay): State<Relay>, body: Bytes) -> Response {
    if body.len() > MAX_BODY_LEN {
        return refuse(ErrorCode::TooLarge);
    }
    let Ok(signed) = Signed::from_bytes(&body) else {
        return refuse(ErrorCode::Malformed);
    };
    // Peek at the payload to get the key it claims, then verify the envelope against it.
    let Ok(announce) = ciborium::from_reader::<DeviceAnnounce, _>(signed.payload.as_slice()) else {
        return refuse(ErrorCode::Malformed);
    };
    let Ok((announce, nonce)) = signed.verify::<DeviceAnnounce>(&announce.ed25519_pub, now_unix()) else {
        return refuse(ErrorCode::Unauthenticated);
    };
    if zbacs_proto::identity::kid_of(&announce.ed25519_pub) != signed.kid {
        return refuse(ErrorCode::Unauthenticated);
    }
    if announce.label.as_ref().is_some_and(|l| l.len() > 32) {
        return refuse(ErrorCode::Malformed);
    }
    let now = Instant::now();
    if let Err(r) = relay.take_quota(&signed.kid, now) {
        return refuse(refusal_code(r));
    }
    if let Err(r) = relay.take_nonce(nonce, now) {
        return refuse(refusal_code(r));
    }
    relay.announce(
        signed.kid,
        Device { ed25519_pub: announce.ed25519_pub, x25519_pub: announce.x25519_pub, label: announce.label },
    );
    accept(signed.kid)
}

/// A recipient asks the owner. Queued for the owner named in the request.
async fn requests(State(relay): State<Relay>, body: Bytes) -> Response {
    let (signed, request) = match authenticate::<AccessRequest>(&relay, &body) {
        Ok(v) => v,
        Err(code) => return refuse(code),
    };
    if request.device_kid != signed.kid {
        // the request must be about the device that signed it (T05)
        return refuse(ErrorCode::Unauthenticated);
    }
    if request.owner.is_empty() || request.owner.len() > 64 {
        return refuse(ErrorCode::Malformed);
    }
    relay.remember_request(request.nonce, signed.kid, Instant::now());
    let id = relay.enqueue(Inbox::Owner(request.owner.clone()), Kind::Req, body.to_vec(), now_unix());
    accept(id)
}

/// The owner answers. Routed back to whoever asked, by request nonce.
async fn grants(State(relay): State<Relay>, body: Bytes) -> Response {
    let (_signed, grant) = match authenticate::<GrantMsg>(&relay, &body) {
        Ok(v) => v,
        Err(code) => return refuse(code),
    };
    let to = match relay.route_for(&grant.request_nonce) {
        Ok(kid) => kid,
        Err(r) => return refuse(refusal_code(r)),
    };
    let id = relay.enqueue(Inbox::Device(to), Kind::Grant, body.to_vec(), now_unix());
    accept(id)
}

/// The owner pulls access back. Broadcast to the device that holds the grant.
async fn revocations(State(relay): State<Relay>, body: Bytes) -> Response {
    let (_signed, _revoke) = match authenticate::<Revoke>(&relay, &body) {
        Ok(v) => v,
        Err(code) => return refuse(code),
    };
    // A revoke names a grant, not a request, so it is delivered to every device that asked
    // about this file. Agents ignore revokes for grants they do not hold, and the chain event
    // is the authoritative copy anyway (T20).
    let id = relay.enqueue(Inbox::Device(_signed.kid), Kind::Revoke, body.to_vec(), now_unix());
    accept(id)
}

/// Which inbox to read. A device reads its own; an owner reads by account.
#[derive(Deserialize)]
struct InboxQuery {
    /// Hex-encoded owner account bytes.
    owner: Option<String>,
    /// Hex-encoded device key id.
    device: Option<String>,
}

async fn inbox(State(relay): State<Relay>, Query(q): Query<InboxQuery>) -> Response {
    let target = match (q.owner, q.device) {
        (Some(owner), None) => match hex::decode(owner) {
            Ok(bytes) if !bytes.is_empty() && bytes.len() <= 64 => Inbox::Owner(bytes),
            _ => return refuse(ErrorCode::Malformed),
        },
        (None, Some(device)) => match hex::decode(device) {
            Ok(bytes) => match <[u8; 16]>::try_from(bytes.as_slice()) {
                Ok(kid) => Inbox::Device(kid),
                Err(_) => return refuse(ErrorCode::Malformed),
            },
            Err(_) => return refuse(ErrorCode::Malformed),
        },
        _ => return refuse(ErrorCode::Malformed),
    };
    cbor(StatusCode::OK, &relay.drain(&target))
}

/// Live delivery. The first frame must be a signed `Subscribe`; after that the relay pushes
/// whatever lands in that inbox.
async fn stream(State(relay): State<Relay>, Query(q): Query<InboxQuery>, ws: WebSocketUpgrade) -> Response {
    let target = match (q.owner, q.device) {
        (Some(owner), None) => match hex::decode(owner) {
            Ok(bytes) if !bytes.is_empty() => Inbox::Owner(bytes),
            _ => return refuse(ErrorCode::Malformed),
        },
        (None, Some(device)) => match hex::decode(device).ok().and_then(|b| <[u8; 16]>::try_from(b).ok()) {
            Some(kid) => Inbox::Device(kid),
            None => return refuse(ErrorCode::Malformed),
        },
        _ => return refuse(ErrorCode::Malformed),
    };
    ws.on_upgrade(move |socket| pump(socket, relay, target))
}

async fn pump(mut socket: WebSocket, relay: Relay, target: Inbox) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(200));
    loop {
        ticker.tick().await;
        for envelope in relay.drain(&target) {
            let mut body = Vec::new();
            if ciborium::into_writer(&envelope, &mut body).is_err() {
                return;
            }
            if socket.send(Message::Binary(body.into())).await.is_err() {
                return; // client went away
            }
        }
        // a cheap liveness check so a dead socket is noticed even with an empty queue
        if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
            return;
        }
    }
}
