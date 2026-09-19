//! Z-1.C.2 — malicious / malformed container inputs (spec §2.2 limits, §4 open order).
//! Every case must fail with a typed error and never panic; nothing is written past the
//! point of failure that a later step would have to undo. T17/T18/T19.

use std::io::Cursor;
use zbacs_core::{
    inspect, open, Envelope, Error, Header, HeaderBody, OwnerKeys, SealOptions, DEFAULT_CHUNK,
    MAX_HEADER_LEN, VERSION_MAJOR, VERSION_MINOR,
};

struct Fixture {
    owner: OwnerKeys,
    bytes: Vec<u8>,
    header_len: usize,
}

impl Fixture {
    fn new(plain: &[u8], chunk: usize) -> Self {
        let owner = OwnerKeys::generate().unwrap();
        let mut opts = SealOptions::new(b"acct", "doc.txt");
        opts.chunk_size = chunk;
        let mut bytes = Vec::new();
        zbacs_core::seal(Cursor::new(plain), &mut bytes, &owner, &opts).unwrap();
        let header_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        Self { owner, bytes, header_len }
    }
    fn header(&self) -> Header {
        inspect(Cursor::new(&self.bytes)).unwrap().0
    }
    fn chunks_start(&self) -> usize {
        12 + self.header_len
    }
    fn trailer_start(&self) -> usize {
        self.bytes.len() - 72
    }
    /// Re-sign a modified body with the owner's key (a "malicious owner" or a stolen signing
    /// key) and splice it in front of the original chunk stream.
    fn with_body(&self, f: impl FnOnce(&mut HeaderBody)) -> Vec<u8> {
        let mut body = self.header().body;
        f(&mut body);
        let hb = body.sign(&self.owner.signing).unwrap().encode().unwrap();
        let mut out = self.bytes[..8].to_vec();
        out.extend_from_slice(&(hb.len() as u32).to_le_bytes());
        out.extend_from_slice(&hb);
        out.extend_from_slice(&self.bytes[self.chunks_start()..]);
        out
    }
    fn open_err(&self, bytes: &[u8]) -> Error {
        let mut out = Vec::new();
        open(Cursor::new(bytes), &mut out, &self.owner.sealing).unwrap_err()
    }
}

fn header_decode(e: &Error) -> bool {
    matches!(e, Error::HeaderDecode(_))
}

// ------------------------------------------------------------------ framing

#[test]
fn t17_01_empty_input_is_bad_magic() {
    let f = Fixture::new(b"x", 16);
    assert!(matches!(f.open_err(&[]), Error::BadMagic));
}

#[test]
fn t17_02_wrong_magic_byte() {
    let f = Fixture::new(b"x", 16);
    let mut b = f.bytes.clone();
    b[5] = b'!';
    assert!(matches!(f.open_err(&b), Error::BadMagic));
}

#[test]
fn t19_03_other_major_version_rejected() {
    let f = Fixture::new(b"x", 16);
    for major in [0u8, VERSION_MAJOR + 1, 0xff] {
        let mut b = f.bytes.clone();
        b[6] = major;
        assert!(matches!(f.open_err(&b), Error::UnsupportedVersion(m, _) if m == major));
    }
}

#[test]
fn t19_04_newer_minor_version_still_opens() {
    let f = Fixture::new(b"forward compatible", 16);
    let mut b = f.bytes.clone();
    b[7] = VERSION_MINOR + 1;
    let mut out = Vec::new();
    open(Cursor::new(&b), &mut out, &f.owner.sealing).unwrap();
    assert_eq!(out, b"forward compatible");
}

#[test]
fn t18_05_zero_header_length() {
    let f = Fixture::new(b"x", 16);
    let mut b = f.bytes[..8].to_vec();
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&f.bytes[12..]);
    assert!(header_decode(&f.open_err(&b)));
}

#[test]
fn t18_06_header_length_over_limit() {
    let f = Fixture::new(b"x", 16);
    let mut b = f.bytes[..8].to_vec();
    b.extend_from_slice(&((MAX_HEADER_LEN + 1) as u32).to_le_bytes());
    b.extend_from_slice(&f.bytes[12..]);
    assert!(matches!(f.open_err(&b), Error::HeaderTooLarge(_)));
    let mut b = f.bytes[..8].to_vec();
    b.extend_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(f.open_err(&b), Error::HeaderTooLarge(_)));
}

#[test]
fn t18_07_header_length_past_end_of_stream() {
    let f = Fixture::new(b"x", 16);
    let mut b = f.bytes[..8].to_vec();
    b.extend_from_slice(&((f.bytes.len() * 2) as u32).to_le_bytes());
    b.extend_from_slice(&f.bytes[12..]);
    assert!(matches!(f.open_err(&b), Error::Truncated));
}

#[test]
fn t18_08_header_cbor_garbage() {
    let f = Fixture::new(b"x", 16);
    let mut b = f.bytes.clone();
    b[12..12 + f.header_len].fill(0xff);
    assert!(header_decode(&f.open_err(&b)));
}

#[test]
fn t18_09_header_cbor_truncated_inside_length() {
    // length field says N but the CBOR ends early: decode error, not a panic
    let f = Fixture::new(b"x", 16);
    let mut b = f.bytes.clone();
    let cut = 12 + f.header_len / 2;
    b[cut..12 + f.header_len].fill(0);
    assert!(header_decode(&f.open_err(&b)) || matches!(f.open_err(&b), Error::HeaderSignature));
}

// ------------------------------------------------------------------ signature

#[test]
fn t02_10_every_signature_byte_is_load_bearing() {
    let f = Fixture::new(b"x", 16);
    let hdr = f.header();
    let enc = hdr.encode().unwrap();
    // find the 64-byte signature inside the encoded header and flip bytes across it
    let pos = enc.windows(64).position(|w| w == hdr.sig.as_slice()).unwrap();
    for off in [0usize, 31, 63] {
        let mut b = f.bytes.clone();
        b[12 + pos + off] ^= 0x80;
        assert!(matches!(f.open_err(&b), Error::HeaderSignature));
    }
}

#[test]
fn t02_11_signer_key_swapped_for_another_valid_key() {
    let f = Fixture::new(b"x", 16);
    let hdr = f.header();
    let enc = hdr.encode().unwrap();
    let pos = enc.windows(32).position(|w| w == hdr.sigk.as_slice()).unwrap();
    let other = zbacs_core::SigningKeys::generate().verifying_key().to_bytes();
    let mut b = f.bytes.clone();
    b[12 + pos..12 + pos + 32].copy_from_slice(&other);
    assert!(matches!(f.open_err(&b), Error::HeaderSignature));
}

#[test]
fn t02_12_body_field_edited_without_resigning() {
    let f = Fixture::new(b"x", 16);
    let hdr = f.header();
    let enc = hdr.encode().unwrap();
    let pos = enc.windows(4).position(|w| w == b"acct").unwrap();
    let mut b = f.bytes.clone();
    b[12 + pos] = b'B';
    assert!(matches!(f.open_err(&b), Error::HeaderSignature));
}

// ------------------------------------------------------------------ field limits (signed by a malicious owner)

#[test]
fn t18_13_fixed_length_fields_wrong_size_rejected_at_decode() {
    // Serialize a body whose `fid` is 31 bytes by hand: the typed field cannot even express
    // it in Rust, so build the CBOR from a serde_json-like generic value.
    let f = Fixture::new(b"x", 16);
    let hdr = f.header();
    let enc = hdr.encode().unwrap();
    let mut v: ciborium::Value = ciborium::from_reader(enc.as_slice()).unwrap();
    if let ciborium::Value::Map(m) = &mut v {
        for (k, val) in m.iter_mut() {
            if k == &ciborium::Value::Text("fid".into()) {
                *val = ciborium::Value::Bytes(vec![0; 31]);
            }
        }
    }
    let mut hb = Vec::new();
    ciborium::into_writer(&v, &mut hb).unwrap();
    let mut b = f.bytes[..8].to_vec();
    b.extend_from_slice(&(hb.len() as u32).to_le_bytes());
    b.extend_from_slice(&hb);
    b.extend_from_slice(&f.bytes[f.chunks_start()..]);
    assert!(header_decode(&f.open_err(&b)));
}

#[test]
fn t18_14_unsupported_cipher() {
    let f = Fixture::new(b"x", 16);
    let b = f.with_body(|h| h.cipher = 2);
    assert!(matches!(f.open_err(&b), Error::UnsupportedCipher(2)));
}

#[test]
fn t18_15_chunk_size_zero_and_oversized() {
    let f = Fixture::new(b"x", 16);
    assert!(matches!(f.open_err(&f.with_body(|h| h.chunk = 0)), Error::BadChunkSize(0)));
    let big = 16 * 1024 * 1024 + 1;
    assert!(matches!(f.open_err(&f.with_body(|h| h.chunk = big)), Error::BadChunkSize(_)));
}

#[test]
fn t19_16_version_chain_invariants() {
    let f = Fixture::new(b"x", 16);
    assert!(header_decode(&f.open_err(&f.with_body(|h| h.ver = 0))));
    assert!(header_decode(&f.open_err(&f.with_body(|h| h.prev = Some([7; 32].into())))));
    assert!(header_decode(&f.open_err(&f.with_body(|h| {
        h.ver = 2;
        h.prev = None;
    }))));
}

#[test]
fn t18_17_owner_account_length_bounds() {
    let f = Fixture::new(b"x", 16);
    assert!(header_decode(&f.open_err(&f.with_body(|h| h.own = vec![]))));
    assert!(header_decode(&f.open_err(&f.with_body(|h| h.own = vec![1; 65]))));
}

#[test]
fn t18_18_file_name_field_length_bounds() {
    // padded plaintext is a multiple of 64 (spec §2.2), so the ciphertext is 64k + 16 tag
    let f = Fixture::new(b"x", 16);
    assert!(header_decode(&f.open_err(&f.with_body(|h| h.name = vec![0; 1105]))), "too long");
    assert!(header_decode(&f.open_err(&f.with_body(|h| h.name = vec![0; 16]))), "too short");
    // right length but garbage: fails authentication, never reaches the chunks
    let e = f.open_err(&f.with_body(|h| h.name = vec![0; 80]));
    assert!(matches!(e, Error::NameAuth), "{e:?}");
}

#[test]
fn t18_19_envelope_count_and_field_bounds() {
    let f = Fixture::new(b"x", 16);
    assert!(header_decode(&f.open_err(&f.with_body(|h| h.env.clear()))));
    assert!(header_decode(&f.open_err(&f.with_body(|h| {
        let e = h.env[0].clone();
        h.env = vec![e; 33];
    }))));
    assert!(header_decode(&f.open_err(&f.with_body(|h| h.env[0].ct = vec![0; 1025]))));
    assert!(header_decode(&f.open_err(&f.with_body(|h| h.env[0].enc = vec![0; 1025]))));
}

#[test]
fn t04_20_envelope_tampered_or_unknown_suite() {
    let f = Fixture::new(b"x", 16);
    let b = f.with_body(|h| h.env[0].ct[0] ^= 1);
    assert!(matches!(f.open_err(&b), Error::EnvelopeOpen));
    let b = f.with_body(|h| h.env[0].alg = "hpke-unknown".into());
    assert!(matches!(f.open_err(&b), Error::EnvelopeOpen));
    // envelope for someone else only, under the owner's signature
    let eve = zbacs_core::DeviceKeys::generate().unwrap();
    let b = f.with_body(|h| {
        h.env = vec![Envelope::seal(eve.public_key(), &zbacs_core::Dek::generate(), b"ctx").unwrap()];
    });
    assert!(matches!(f.open_err(&b), Error::NoEnvelope));
}

#[test]
fn t19_21_plen_larger_than_stream() {
    let f = Fixture::new(b"0123456789", 4);
    let b = f.with_body(|h| h.plen = 1 << 40);
    let e = f.open_err(&b);
    assert!(matches!(e, Error::Truncated | Error::ChunkAuth(_)), "{e:?}");
}

#[test]
fn t19_22_plen_smaller_than_stream() {
    let f = Fixture::new(b"0123456789", 4);
    let b = f.with_body(|h| h.plen = 4);
    let e = f.open_err(&b);
    assert!(matches!(e, Error::Truncated | Error::ChunkAuth(_)), "{e:?}");
}

// ------------------------------------------------------------------ chunk stream + trailer

#[test]
fn t18_23_every_chunk_is_authenticated() {
    let f = Fixture::new(b"0123456789abcdef", 4); // 4 chunks
    for i in 0..4 {
        let mut b = f.bytes.clone();
        b[f.chunks_start() + i * (4 + 16) + 2] ^= 1;
        assert!(matches!(f.open_err(&b), Error::ChunkAuth(n) if n == i as u64), "chunk {i}");
    }
}

#[test]
fn t18_24_chunk_duplicated_in_place_of_next() {
    let f = Fixture::new(b"0123456789abcdef", 4);
    let s = f.chunks_start();
    let mut b = f.bytes.clone();
    let c0 = b[s..s + 20].to_vec();
    b[s + 20..s + 40].copy_from_slice(&c0);
    assert!(matches!(f.open_err(&b), Error::ChunkAuth(1)));
}

#[test]
fn t19_25_last_chunk_dropped_at_frame_boundary() {
    let f = Fixture::new(b"0123456789abcdef", 4);
    let s = f.chunks_start();
    let mut b = f.bytes[..s + 3 * 20].to_vec();
    b.extend_from_slice(&f.bytes[f.trailer_start()..]);
    let e = f.open_err(&b);
    assert!(matches!(e, Error::ChunkAuth(3) | Error::Truncated), "{e:?}");
}

#[test]
fn t19_26_first_chunk_dropped() {
    let f = Fixture::new(b"0123456789abcdef", 4);
    let s = f.chunks_start();
    let mut b = f.bytes[..s].to_vec();
    b.extend_from_slice(&f.bytes[s + 20..]);
    assert!(matches!(f.open_err(&b), Error::ChunkAuth(0)));
}

#[test]
fn t19_27_trailer_fields_each_checked() {
    let f = Fixture::new(b"0123456789abcdef", 4);
    let t = f.trailer_start();
    for off in [0usize, 31, 32, 39, 40, 71] {
        let mut b = f.bytes.clone();
        b[t + off] ^= 1;
        assert!(matches!(f.open_err(&b), Error::Truncated), "trailer byte {off}");
    }
}

#[test]
fn t19_28_trailer_missing_or_short() {
    let f = Fixture::new(b"0123456789abcdef", 4);
    let t = f.trailer_start();
    assert!(matches!(f.open_err(&f.bytes[..t]), Error::Truncated));
    assert!(matches!(f.open_err(&f.bytes[..t + 71]), Error::Truncated));
}

#[test]
fn t19_29_bytes_appended_after_trailer() {
    let f = Fixture::new(b"0123456789abcdef", 4);
    let mut b = f.bytes.clone();
    b.extend_from_slice(b"\0");
    assert!(matches!(f.open_err(&b), Error::Truncated));
    let mut b = f.bytes.clone();
    b.extend_from_slice(&f.bytes); // a second container glued on
    assert!(matches!(f.open_err(&b), Error::Truncated));
}

#[test]
fn t19_30_partial_output_is_bounded_by_authenticated_chunks() {
    // Truncation is detected, and only fully authenticated chunks were ever written.
    let f = Fixture::new(b"0123456789abcdef", 4);
    let s = f.chunks_start();
    let mut b = f.bytes[..s + 2 * 20].to_vec();
    b.extend_from_slice(&f.bytes[f.trailer_start()..]);
    let mut out = Vec::new();
    let e = open(Cursor::new(&b), &mut out, &f.owner.sealing).unwrap_err();
    assert!(matches!(e, Error::ChunkAuth(2) | Error::Truncated), "{e:?}");
    assert!(out.len() <= 8, "no unauthenticated plaintext");
    assert!(out.is_empty() || out == b"01234567");
}

// ------------------------------------------------------------------ random mutation sweep

#[test]
fn t18_31_random_byte_mutations_never_panic_and_never_yield_wrong_plaintext() {
    use rand::{Rng, SeedableRng};
    let plain = b"the quick brown fox jumps over the lazy dog".repeat(8);
    let f = Fixture::new(&plain, DEFAULT_CHUNK);
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x5eed);
    for _ in 0..500 {
        let mut b = f.bytes.clone();
        let n = rng.gen_range(1..=3);
        for _ in 0..n {
            let i = rng.gen_range(0..b.len());
            b[i] ^= 1 << rng.gen_range(0..8);
        }
        let mut out = Vec::new();
        if open(Cursor::new(&b), &mut out, &f.owner.sealing).is_ok() {
            assert_eq!(out, plain, "mutation accepted but plaintext differs");
        }
    }
    // random truncation at every prefix length
    for cut in 0..f.bytes.len() {
        let mut out = Vec::new();
        assert!(open(Cursor::new(&f.bytes[..cut]), &mut out, &f.owner.sealing).is_err());
    }
}
