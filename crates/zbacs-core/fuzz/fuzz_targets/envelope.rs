//! Z-1.C.3 target 4: HPKE envelope open with arbitrary enc/ct/aad/alg (T04).
#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use zbacs_core::{DeviceKeys, Envelope, KeyId};

#[derive(Arbitrary, Debug)]
struct Case {
    enc: Vec<u8>,
    ct: Vec<u8>,
    aad: Vec<u8>,
    alg_ok: bool,
    kid: [u8; 16],
}

fn keys() -> &'static DeviceKeys {
    static K: OnceLock<DeviceKeys> = OnceLock::new();
    K.get_or_init(|| DeviceKeys::generate().unwrap())
}

fuzz_target!(|c: Case| {
    let env = Envelope {
        kid: KeyId(c.kid),
        alg: if c.alg_ok { "hpke-x25519-chacha".into() } else { "x".into() },
        enc: c.enc,
        ct: c.ct,
    };
    let _ = env.open(keys(), &c.aad);
    let _ = Envelope::seal(&c.aad, &zbacs_core::Dek::generate(), b"aad");
});
