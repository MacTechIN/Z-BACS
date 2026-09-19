//! Z-1.A.1 — AuthProvider API, both signer paths, confirmation policy, cross-implementation
//! vector from the JavaScript spike. Threat IDs in test names per docs/threat_model.md.

use zbacs_auth::software::{SoftwareDeviceKey, SoftwarePasskey};
use zbacs_auth::webauthn::{client_data_challenge, webauthn_signed_digest, AuthenticatorData};
use zbacs_auth::{
    verify_assertion, ApprovalAssertion, ApprovalChallenge, ApprovalContext, AuthError, AuthProvider,
    Confirmation, ConfirmationPolicy, DeviceEnroll, DeviceRevoke, KeyId, P256PublicKey, SignerKind,
};
use zbacs_core::Permission;

const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc,
    0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

fn challenge(permission: Permission) -> ApprovalChallenge {
    ApprovalChallenge { digest: [0x42; 32], context: ApprovalContext { permission, file_id: [7; 32] } }
}

fn high_s(s: &[u8; 32]) -> [u8; 32] {
    // n - s, big-endian
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = P256_N[i] as i16 - s[i] as i16 - borrow;
        if d < 0 {
            out[i] = (d + 256) as u8;
            borrow = 1;
        } else {
            out[i] = d as u8;
            borrow = 0;
        }
    }
    out
}

// ------------------------------------------------------------------ path B: DeviceKey

#[test]
fn device_key_sign_verify_roundtrip() {
    let dev = SoftwareDeviceKey::generate(false);
    assert_eq!(dev.kind(), SignerKind::DeviceKey);
    let c = challenge(Permission::ReadOnly);
    let a = dev.sign(&c, Confirmation::NotRequired).unwrap();
    assert_eq!(a.kind(), SignerKind::DeviceKey);
    verify_assertion(&dev.public_key().unwrap(), &c.digest, &a).unwrap();
}

#[test]
fn device_key_without_os_confirmation_refuses_when_required() {
    let dev = SoftwareDeviceKey::generate(false);
    let err = dev.sign(&challenge(Permission::Edit), Confirmation::OsUserVerification).unwrap_err();
    assert!(matches!(err, AuthError::ConfirmationUnavailable(SignerKind::DeviceKey, _)));
    assert!(SoftwareDeviceKey::generate(true)
        .sign(&challenge(Permission::Edit), Confirmation::OsUserVerification)
        .is_ok());
}

#[test]
fn t14_device_key_wrong_key_rejected() {
    let dev = SoftwareDeviceKey::generate(false);
    let other = SoftwareDeviceKey::generate(false);
    let c = challenge(Permission::ReadOnly);
    let a = dev.sign(&c, Confirmation::NotRequired).unwrap();
    assert!(matches!(
        verify_assertion(&other.public_key().unwrap(), &c.digest, &a),
        Err(AuthError::InvalidSignature)
    ));
}

// ------------------------------------------------------------------ path A: PlatformPasskey

#[test]
fn passkey_sign_verify_roundtrip() {
    let pk = SoftwarePasskey::generate("zbacs.local", "https://zbacs.local", false);
    let c = challenge(Permission::ReadOnly);
    let a = pk.sign(&c, Confirmation::OsUserVerification).unwrap();
    verify_assertion(&pk.public_key().unwrap(), &c.digest, &a).unwrap();
    let ApprovalAssertion::WebAuthn { authenticator_data, client_data_json, .. } = &a else { panic!() };
    let ad = AuthenticatorData::parse(authenticator_data).unwrap();
    assert!(ad.flags.up() && ad.flags.uv() && !ad.flags.is_synced());
    assert_eq!(ad.sign_count, 1);
    assert_eq!(client_data_challenge(client_data_json).unwrap(), c.digest);
}

#[test]
fn t14_tampered_webauthn_assertion_rejected() {
    let pk = SoftwarePasskey::generate("zbacs.local", "https://zbacs.local", false);
    let c = challenge(Permission::ReadOnly);
    let key = pk.public_key().unwrap();
    let a = pk.sign(&c, Confirmation::OsUserVerification).unwrap();

    // flip a signature byte
    let ApprovalAssertion::WebAuthn { authenticator_data, client_data_json, r, mut s } = a.clone() else {
        panic!()
    };
    s[31] ^= 1;
    let bad = ApprovalAssertion::WebAuthn {
        authenticator_data: authenticator_data.clone(),
        client_data_json: client_data_json.clone(),
        r,
        s,
    };
    assert!(matches!(verify_assertion(&key, &c.digest, &bad), Err(AuthError::InvalidSignature)));

    // same signature presented for a different challenge
    assert!(matches!(verify_assertion(&key, &[0x43; 32], &a), Err(AuthError::ChallengeMismatch)));

    // UV flag cleared
    let mut ad = authenticator_data.clone();
    ad[32] &= !0x04;
    let no_uv = ApprovalAssertion::WebAuthn {
        authenticator_data: ad,
        client_data_json,
        r,
        s: {
            let ApprovalAssertion::WebAuthn { s, .. } = &a else { panic!() };
            *s
        },
    };
    assert!(matches!(verify_assertion(&key, &c.digest, &no_uv), Err(AuthError::UserVerificationMissing)));
}

#[test]
fn t03_t14_high_s_signature_rejected() {
    let dev = SoftwareDeviceKey::generate(false);
    let c = challenge(Permission::ReadOnly);
    let ApprovalAssertion::P256Raw { key_id, r, s } = dev.sign(&c, Confirmation::NotRequired).unwrap() else {
        panic!()
    };
    let malleated = ApprovalAssertion::P256Raw { key_id, r, s: high_s(&s) };
    // (r, n-s) is a valid ECDSA signature mathematically, but must be rejected (malleability).
    assert!(matches!(
        verify_assertion(&dev.public_key().unwrap(), &c.digest, &malleated),
        Err(AuthError::HighS)
    ));
}

#[test]
fn t22_synced_passkey_flags_detected() {
    let synced = SoftwarePasskey::generate("zbacs.local", "https://zbacs.local", true);
    let ApprovalAssertion::WebAuthn { authenticator_data, .. } =
        synced.sign(&challenge(Permission::ReadOnly), Confirmation::OsUserVerification).unwrap()
    else {
        panic!()
    };
    let ad = AuthenticatorData::parse(&authenticator_data).unwrap();
    assert!(ad.flags.be() && ad.flags.bs() && ad.flags.is_synced());
}

// ------------------------------------------------------------------ T23 confirmation policy

#[test]
fn t23_edit_requires_os_confirmation_even_on_trusted_device() {
    let p = ConfirmationPolicy::default();
    let ro = ApprovalContext { permission: Permission::ReadOnly, file_id: [0; 32] };
    let edit = ApprovalContext { permission: Permission::Edit, file_id: [0; 32] };
    assert_eq!(p.required(&ro, Confirmation::NotRequired, &[], 1_000), Confirmation::NotRequired);
    assert_eq!(p.required(&edit, Confirmation::NotRequired, &[], 1_000), Confirmation::OsUserVerification);
    // device set to always confirm is never weakened
    assert_eq!(
        p.required(&ro, Confirmation::OsUserVerification, &[], 1_000),
        Confirmation::OsUserVerification
    );
}

#[test]
fn t23_burst_of_approvals_requires_os_confirmation() {
    let p = ConfirmationPolicy::default();
    let ro = ApprovalContext { permission: Permission::ReadOnly, file_id: [0; 32] };
    let now = 10_000;
    let four_recent = [now - 10, now - 20, now - 30, now - 40];
    assert_eq!(p.required(&ro, Confirmation::NotRequired, &four_recent, now), Confirmation::NotRequired);
    let five_recent = [now - 10, now - 20, now - 30, now - 40, now - 50];
    assert_eq!(
        p.required(&ro, Confirmation::NotRequired, &five_recent, now),
        Confirmation::OsUserVerification
    );
    // approvals outside the window do not count
    let old = [now - 700, now - 800, now - 900, now - 1000, now - 1100];
    assert_eq!(p.required(&ro, Confirmation::NotRequired, &old, now), Confirmation::NotRequired);
}

// ------------------------------------------------------------------ enrol / revoke digests

#[test]
fn enroll_and_revoke_digests_are_domain_separated_and_deterministic() {
    let dev = SoftwareDeviceKey::generate(false);
    let enroll = DeviceEnroll {
        account: [0xAA; 20],
        public_key: dev.public_key().unwrap(),
        kind: SignerKind::DeviceKey,
        require_os_confirm: false,
        ts: 1_700_000_000,
    };
    let revoke = DeviceRevoke { account: [0xAA; 20], key_id: enroll.key_id(), ts: 1_700_000_001 };
    assert_eq!(enroll.digest().unwrap(), enroll.clone().digest().unwrap());
    assert_ne!(enroll.digest().unwrap(), revoke.digest().unwrap());
    assert_eq!(enroll.key_id(), dev.key_id());

    // a registered signer can sign the enrolment of another device
    let signer = SoftwarePasskey::generate("zbacs.local", "https://zbacs.local", false);
    let c = ApprovalChallenge {
        digest: enroll.digest().unwrap(),
        context: ApprovalContext { permission: Permission::Deny, file_id: [0; 32] },
    };
    let a = signer.sign(&c, Confirmation::OsUserVerification).unwrap();
    verify_assertion(&signer.public_key().unwrap(), &c.digest, &a).unwrap();
}

#[test]
fn key_id_is_keccak_of_xy_and_matches_js_spike() {
    // spikes/aa-passkey: authenticatorIdHash / keyId conventions use keccak256(x||y)
    let key = P256PublicKey { x: [1; 32], y: [2; 32] };
    let KeyId(id) = key.key_id();
    let mut h = <sha3::Keccak256 as sha3::Digest>::new();
    sha3::Digest::update(&mut h, [1u8; 32]);
    sha3::Digest::update(&mut h, [2u8; 32]);
    assert_eq!(id, <[u8; 32]>::from(sha3::Digest::finalize(h)));
}

// ------------------------------------------------------------------ cross-implementation vector

#[test]
fn cross_impl_webauthn_vector_from_js_spike_verifies() {
    let json: serde_json::Value =
        serde_json::from_str(include_str!("vectors/webauthn_spike.json")).expect("vector json");
    let w = &json["webauthn"];
    let hex32 = |k: &str| -> [u8; 32] {
        hex::decode(w[k].as_str().unwrap().trim_start_matches("0x")).unwrap().try_into().unwrap()
    };
    let key = P256PublicKey { x: hex32("x"), y: hex32("y") };
    let authenticator_data =
        hex::decode(w["authenticatorData"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let client_data_json = w["clientDataJSON"].as_str().unwrap().to_string();
    let challenge = hex32("challenge");

    assert_eq!(
        webauthn_signed_digest(&authenticator_data, &client_data_json),
        hex32("digest"),
        "digest differs from node"
    );
    let a =
        ApprovalAssertion::WebAuthn { authenticator_data, client_data_json, r: hex32("r"), s: hex32("s") };
    verify_assertion(&key, &challenge, &a).expect("JS-produced assertion must verify in Rust");
}
