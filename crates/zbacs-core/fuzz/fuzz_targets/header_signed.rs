//! Z-1.C.3 target 2: arbitrary *signed* headers. The fuzzer shapes a HeaderBody, we sign it
//! with a fixed key and feed it through read_header, so the post-signature limits
//! (validate_header) and everything after them are exercised (T18, T19).
#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use std::sync::OnceLock;
use zbacs_core::{Envelope, FileId, HeaderBody, HeaderHash, KeyId, NoncePrefix, Permission, Policy, Salt, SigningKeys};

#[derive(Arbitrary, Debug)]
struct Body {
    fid: [u8; 32],
    salt: [u8; 16],
    ver: u32,
    prev: Option<[u8; 32]>,
    own: Vec<u8>,
    def: u8,
    ttl: u32,
    max: u16,
    pin: bool,
    strict: bool,
    cipher: u8,
    chunk: u32,
    plen: u64,
    np: [u8; 16],
    name: Vec<u8>,
    env: Vec<(Vec<u8>, Vec<u8>)>,
    minor: u8,
    tail: Vec<u8>,
}

fn keys() -> &'static SigningKeys {
    static K: OnceLock<SigningKeys> = OnceLock::new();
    K.get_or_init(SigningKeys::generate)
}

fuzz_target!(|b: Body| {
    let def = match b.def % 3 {
        0 => Permission::Deny,
        1 => Permission::ReadOnly,
        _ => Permission::Edit,
    };
    let body = HeaderBody {
        fid: FileId(b.fid),
        salt: Salt(b.salt),
        ver: b.ver,
        prev: b.prev.map(HeaderHash),
        own: b.own,
        pol: Policy { default: def, ttl: b.ttl, max: b.max, pin: b.pin, strict: b.strict },
        cipher: b.cipher,
        chunk: b.chunk,
        plen: b.plen,
        np: NoncePrefix(b.np),
        name: b.name,
        env: b
            .env
            .into_iter()
            .take(40)
            .map(|(enc, ct)| Envelope { kid: KeyId([0; 16]), alg: "hpke-x25519-chacha".into(), enc, ct })
            .collect(),
    };
    let Ok(hdr) = body.sign(keys()) else { return };
    let Ok(hb) = hdr.encode() else { return };
    let mut data = zbacs_core::MAGIC.to_vec();
    data.extend_from_slice(&[zbacs_core::VERSION_MAJOR, b.minor]);
    data.extend_from_slice(&(hb.len() as u32).to_le_bytes());
    data.extend_from_slice(&hb);
    data.extend_from_slice(&b.tail);
    let _ = zbacs_core::inspect(Cursor::new(&data));
    // and try to open it with a random DEK: must fail cleanly (NameAuth/Truncated), never panic
    if let Ok((h, hh, r)) = zbacs_core::read_header(Cursor::new(&data)) {
        let mut sink = Vec::new();
        let _ = zbacs_core::open_with_dek(h, hh, r, &mut sink, &zbacs_core::Dek::generate());
    }
});
