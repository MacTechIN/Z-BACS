//! Z-1.R.1 — the relay wire protocol as an executable schema (spec `relay_protocol.md`).
//! The relay is untrusted, so these tests are mostly about what a receiver refuses.

use zbacs_proto::{
    AccessRequest, Ack, DeviceAnnounce, DeviceIdentity, Envelope, ErrorCode, GrantMsg, Kind, ProtoError,
    Revoke, Signed, Subscribe, MAX_BODY_LEN, MAX_SKEW_SECS,
};

const NOW: u64 = 1_700_000_000;

fn request(device: &DeviceIdentity) -> AccessRequest {
    AccessRequest {
        fid: [1; 32],
        header_hash: [2; 32],
        owner: b"eip155:8453:0xA11CE".to_vec(),
        device_kid: device.kid(),
        x25519_pub: device.x25519_pub(),
        ed25519_pub: device.ed25519_pub(),
        requested: 1,
        nonce: [9; 16],
        hint: None,
        ts: NOW,
    }
}

#[test]
fn signed_envelope_roundtrips_through_cbor() {
    let bob = DeviceIdentity::generate().unwrap();
    let req = request(&bob);
    let signed = Signed::sign(&bob, &req, NOW, [3; 16]).unwrap();

    let wire = signed.to_bytes().unwrap();
    let parsed = Signed::from_bytes(&wire).unwrap();
    assert_eq!(parsed, signed);
    assert_eq!(parsed.kind, Kind::Req);
    assert_eq!(parsed.kid, bob.kid());

    let (back, nonce) = parsed.verify::<AccessRequest>(&bob.ed25519_pub(), NOW + 5).unwrap();
    assert_eq!(back, req);
    assert_eq!(nonce, [3; 16]);
}

#[test]
fn t05_signature_from_another_device_is_refused() {
    let bob = DeviceIdentity::generate().unwrap();
    let eve = DeviceIdentity::generate().unwrap();
    let signed = Signed::sign(&bob, &request(&bob), NOW, [3; 16]).unwrap();
    // Eve's key does not match the kid in the envelope, and would not verify anyway
    assert_eq!(
        signed.verify::<AccessRequest>(&eve.ed25519_pub(), NOW).unwrap_err(),
        ProtoError::BadSignature
    );
}

#[test]
fn t05_tampering_with_any_signed_field_is_detected() {
    let bob = DeviceIdentity::generate().unwrap();
    let signed = Signed::sign(&bob, &request(&bob), NOW, [3; 16]).unwrap();
    let pk = bob.ed25519_pub();

    let mut payload_changed = signed.clone();
    payload_changed.payload[10] ^= 1;
    assert_eq!(payload_changed.verify::<AccessRequest>(&pk, NOW).unwrap_err(), ProtoError::BadSignature);

    let mut nonce_changed = signed.clone();
    nonce_changed.nonce[0] ^= 1;
    assert_eq!(nonce_changed.verify::<AccessRequest>(&pk, NOW).unwrap_err(), ProtoError::BadSignature);

    let mut ts_changed = signed.clone();
    ts_changed.ts += 1;
    assert_eq!(ts_changed.verify::<AccessRequest>(&pk, NOW).unwrap_err(), ProtoError::BadSignature);

    let mut sig_changed = signed;
    sig_changed.sig[0] ^= 1;
    assert_eq!(sig_changed.verify::<AccessRequest>(&pk, NOW).unwrap_err(), ProtoError::BadSignature);
}

/// The kind is inside the signature, so a relay cannot re-label a request as a grant.
#[test]
fn t03_a_signature_cannot_be_reused_for_another_kind() {
    let alice = DeviceIdentity::generate().unwrap();
    let revoke = Revoke { grant_id: [7; 32], fid: [1; 32], ts: NOW };
    let mut signed = Signed::sign(&alice, &revoke, NOW, [3; 16]).unwrap();

    signed.kind = Kind::Grant;
    assert_eq!(
        signed.verify::<GrantMsg>(&alice.ed25519_pub(), NOW).unwrap_err(),
        ProtoError::BadSignature,
        "relabelled envelope must not verify"
    );
    // and asking for the wrong payload type is caught before any crypto
    signed.kind = Kind::Revoke;
    assert!(matches!(signed.verify::<GrantMsg>(&alice.ed25519_pub(), NOW), Err(ProtoError::Malformed(_))));
}

#[test]
fn stale_or_future_timestamps_are_refused() {
    let bob = DeviceIdentity::generate().unwrap();
    let signed = Signed::sign(&bob, &request(&bob), NOW, [3; 16]).unwrap();
    let pk = bob.ed25519_pub();

    assert!(signed.verify::<AccessRequest>(&pk, NOW + MAX_SKEW_SECS).is_ok());
    assert!(signed.verify::<AccessRequest>(&pk, NOW - MAX_SKEW_SECS).is_ok());
    assert!(matches!(
        signed.verify::<AccessRequest>(&pk, NOW + MAX_SKEW_SECS + 1),
        Err(ProtoError::Stale { .. })
    ));
    assert!(matches!(
        signed.verify::<AccessRequest>(&pk, NOW - MAX_SKEW_SECS - 1),
        Err(ProtoError::Stale { .. })
    ));
}

#[test]
fn oversized_bodies_are_refused_on_both_sides() {
    let bob = DeviceIdentity::generate().unwrap();
    let mut req = request(&bob);
    req.hint = Some(vec![0u8; MAX_BODY_LEN]);
    assert!(matches!(Signed::sign(&bob, &req, NOW, [3; 16]), Err(ProtoError::TooLarge(_))));
    assert!(matches!(Signed::from_bytes(&vec![0u8; MAX_BODY_LEN + 1]), Err(ProtoError::TooLarge(_))));
}

#[test]
fn garbage_bytes_do_not_panic() {
    assert!(matches!(Signed::from_bytes(b""), Err(ProtoError::Malformed(_))));
    assert!(matches!(Signed::from_bytes(b"\xff\xff\xff"), Err(ProtoError::Malformed(_))));
    for len in 0..64usize {
        let junk: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
        let _ = Signed::from_bytes(&junk);
    }
}

/// A relay hands the original signed bytes on; the receiver verifies them itself (spec §4.5).
#[test]
fn t04_relay_forwards_opaque_bytes_that_the_receiver_verifies() {
    let alice = DeviceIdentity::generate().unwrap();
    let grant = GrantMsg {
        request_nonce: [9; 16],
        grant: Some(vec![0xA1, 0xB2]),
        owner_sig: Some(vec![0xC3; 96]),
        envelope: Some(vec![0xD4; 120]),
        tx_hash: Some([5; 32]),
        decision: 1,
        ts: NOW,
    };
    let signed = Signed::sign(&alice, &grant, NOW, [4; 16]).unwrap();

    // what the relay stores and forwards
    let queued =
        Envelope { id: [1; 16], kind: Kind::Grant, body: signed.to_bytes().unwrap(), queued_at: NOW };
    let mut wire = Vec::new();
    ciborium::into_writer(&queued, &mut wire).unwrap();
    let delivered: Envelope = ciborium::from_reader(wire.as_slice()).unwrap();

    // Bob verifies the owner's device signature himself, not the relay's word
    let (back, _) = Signed::from_bytes(&delivered.body)
        .unwrap()
        .verify::<GrantMsg>(&alice.ed25519_pub(), NOW + 10)
        .unwrap();
    assert_eq!(back, grant);
    assert_eq!(back.decision, 1);
}

#[test]
fn deny_answers_carry_no_envelope() {
    let alice = DeviceIdentity::generate().unwrap();
    let deny = GrantMsg {
        request_nonce: [9; 16],
        grant: None,
        owner_sig: None,
        envelope: None,
        tx_hash: None,
        decision: 0,
        ts: NOW,
    };
    let signed = Signed::sign(&alice, &deny, NOW, [4; 16]).unwrap();
    let (back, _) = signed.verify::<GrantMsg>(&alice.ed25519_pub(), NOW).unwrap();
    assert_eq!(back.decision, 0);
    assert!(back.envelope.is_none() && back.grant.is_none());
}

#[test]
fn every_message_kind_signs_and_verifies() {
    let d = DeviceIdentity::generate().unwrap();
    let pk = d.ed25519_pub();

    let announce = DeviceAnnounce {
        x25519_pub: d.x25519_pub(),
        ed25519_pub: pk,
        label: Some("업무용 노트북".into()),
        ts: NOW,
    };
    let s = Signed::sign(&d, &announce, NOW, [1; 16]).unwrap();
    assert_eq!(s.verify::<DeviceAnnounce>(&pk, NOW).unwrap().0, announce);

    let sub = Subscribe { since: None, kinds: vec![Kind::Req, Kind::Revoke], ts: NOW };
    let s = Signed::sign(&d, &sub, NOW, [2; 16]).unwrap();
    assert_eq!(s.verify::<Subscribe>(&pk, NOW).unwrap().0, sub);

    let ack = Ack { ok: false, id: None, error: Some(ErrorCode::RateLimited) };
    let s = Signed::sign(&d, &ack, NOW, [3; 16]).unwrap();
    assert_eq!(s.verify::<Ack>(&pk, NOW).unwrap().0, ack);

    let rev = Revoke { grant_id: [7; 32], fid: [1; 32], ts: NOW };
    let s = Signed::sign(&d, &rev, NOW, [4; 16]).unwrap();
    assert_eq!(s.verify::<Revoke>(&pk, NOW).unwrap().0, rev);
}

#[test]
fn error_codes_map_to_the_documented_http_statuses() {
    assert_eq!(ErrorCode::Unauthenticated.http_status(), 401);
    assert_eq!(ErrorCode::UnknownDevice.http_status(), 401);
    assert_eq!(ErrorCode::Stale.http_status(), 400);
    assert_eq!(ErrorCode::Malformed.http_status(), 400);
    assert_eq!(ErrorCode::Replayed.http_status(), 409);
    assert_eq!(ErrorCode::TooLarge.http_status(), 413);
    assert_eq!(ErrorCode::RateLimited.http_status(), 429);
    assert_eq!(ErrorCode::NotFound.http_status(), 404);
    assert_eq!(ErrorCode::Internal.http_status(), 500);

    assert_eq!(ProtoError::BadSignature.code(), ErrorCode::Unauthenticated);
    assert_eq!(ProtoError::Stale { ts: 1, now: 2 }.code(), ErrorCode::Stale);
    assert_eq!(ProtoError::TooLarge(1).code(), ErrorCode::TooLarge);
    assert_eq!(ProtoError::Malformed("x").code(), ErrorCode::Malformed);
}

/// The relay only needs the outer fields; it never parses a payload (spec §3).
#[test]
fn a_relay_can_route_without_understanding_the_payload() {
    let bob = DeviceIdentity::generate().unwrap();
    let signed = Signed::sign(&bob, &request(&bob), NOW, [3; 16]).unwrap();
    let wire = signed.to_bytes().unwrap();

    let seen = Signed::from_bytes(&wire).unwrap();
    assert_eq!(seen.kind, Kind::Req);
    assert_eq!(seen.kid, bob.kid());
    assert!(seen.ts > 0);
    // routing key comes from the payload only for requests, and the relay may read just that
    let (req, _) = seen.verify::<AccessRequest>(&bob.ed25519_pub(), NOW).unwrap();
    assert_eq!(req.owner, b"eip155:8453:0xA11CE");
}

#[test]
fn device_kid_is_the_hash_of_the_signing_key_not_the_envelope_key() {
    let d = DeviceIdentity::generate().unwrap();
    assert_eq!(d.kid(), zbacs_proto::identity::kid_of(&d.ed25519_pub()));
    assert_ne!(d.kid().to_vec(), zbacs_core::key_id_of(&d.x25519_pub()).as_bytes().to_vec());
}

#[test]
fn identity_restores_from_stored_secrets() {
    let d = DeviceIdentity::generate().unwrap();
    let restored = DeviceIdentity::from_secrets(d.keys.secret_key(), &d.signing.secret_bytes()).unwrap();
    assert_eq!(restored.kid(), d.kid());
    assert_eq!(restored.x25519_pub(), d.x25519_pub());
    assert!(matches!(DeviceIdentity::from_secrets(&[0; 3], &[0; 32]), Err(ProtoError::KeyLength)));
}
