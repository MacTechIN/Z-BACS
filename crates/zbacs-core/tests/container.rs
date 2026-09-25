//! Z-0.C.1 acceptance tests. Threat-model IDs from docs/threat_model.md in test names.

use std::io::Cursor;
use std::time::Instant;
use zbacs_core::container::{inspect, open, seal, SealOptions};
use zbacs_core::{DeviceKeys, Error, OwnerKeys, Permission, Policy};

fn sealed(plain: &[u8], chunk: usize) -> (OwnerKeys, Vec<u8>) {
    let owner = OwnerKeys::generate().unwrap();
    let mut opts = SealOptions::new(b"chain:8453:0xowner", "report.docx");
    opts.chunk_size = chunk;
    opts.policy = Policy { default: Permission::Edit, ttl: 600, max: 2, pin: true, strict: false };
    let mut out = Vec::new();
    seal(Cursor::new(plain), &mut out, &owner, &opts).unwrap();
    (owner, out)
}

#[test]
fn roundtrip_various_sizes() {
    for (len, chunk) in [
        (0usize, 1024usize),
        (1, 1024),
        (1023, 1024),
        (1024, 1024),
        (1025, 1024),
        (10_000, 1024),
        (65_536 * 3 + 7, 65_536),
    ] {
        let plain: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
        let (owner, ct) = sealed(&plain, chunk);
        let mut got = Vec::new();
        let opened = open(Cursor::new(&ct), &mut got, &owner.sealing).unwrap();
        assert_eq!(got, plain, "len={len} chunk={chunk}");
        assert_eq!(opened.file_name, "report.docx");
        assert_eq!(opened.header.body.plen, len as u64);
        assert_eq!(opened.header.body.ver, 1);
        assert_eq!(opened.header.body.pol.default, Permission::Edit);
    }
}

#[test]
fn inspect_needs_no_key_but_hides_name() {
    let (_, ct) = sealed(b"hello", 1024);
    let (hdr, _) = inspect(Cursor::new(&ct)).unwrap();
    assert_eq!(hdr.body.env.len(), 1);
    assert!(!hdr.body.name.windows(6).any(|w| w == b"report"));
}

#[test]
fn t04_wrong_key_cannot_open() {
    let (_, ct) = sealed(b"secret", 1024);
    let eve = DeviceKeys::generate().unwrap();
    let mut out = Vec::new();
    assert!(matches!(open(Cursor::new(&ct), &mut out, &eve), Err(Error::NoEnvelope)));
}

#[test]
fn t02_header_tamper_policy_is_detected() {
    let (owner, mut ct) = sealed(b"secret", 1024);
    // find the policy default byte by re-encoding: flip a byte inside the header region
    let hdr_len = u32::from_le_bytes(ct[8..12].try_into().unwrap()) as usize;
    let hdr = &mut ct[12..12 + hdr_len];
    // flip a byte in the middle of the header (inside signed body)
    let i = hdr_len / 3;
    hdr[i] ^= 0x01;
    let mut out = Vec::new();
    let err = open(Cursor::new(&ct), &mut out, &owner.sealing).unwrap_err();
    assert!(matches!(err, Error::HeaderSignature | Error::HeaderDecode(_)), "{err:?}");
}

#[test]
fn t18_chunk_tamper_is_detected() {
    let plain = vec![7u8; 5000];
    let (owner, mut ct) = sealed(&plain, 1024);
    let hdr_len = u32::from_le_bytes(ct[8..12].try_into().unwrap()) as usize;
    let chunk0 = 12 + hdr_len;
    ct[chunk0 + 10] ^= 0xFF;
    let mut out = Vec::new();
    assert!(matches!(open(Cursor::new(&ct), &mut out, &owner.sealing), Err(Error::ChunkAuth(0))));
}

#[test]
fn t18_chunk_reorder_is_detected() {
    let plain: Vec<u8> = (0..4096).map(|i| i as u8).collect();
    let (owner, mut ct) = sealed(&plain, 1024);
    let hdr_len = u32::from_le_bytes(ct[8..12].try_into().unwrap()) as usize;
    let c0 = 12 + hdr_len;
    let frame = 1024 + 16;
    let (a, b) = (c0, c0 + frame);
    let tmp: Vec<u8> = ct[a..a + frame].to_vec();
    ct.copy_within(b..b + frame, a);
    ct[b..b + frame].copy_from_slice(&tmp);
    let mut out = Vec::new();
    assert!(matches!(open(Cursor::new(&ct), &mut out, &owner.sealing), Err(Error::ChunkAuth(0))));
}

#[test]
fn t19_truncation_is_detected() {
    let plain = vec![1u8; 3000];
    let (owner, ct) = sealed(&plain, 1024);
    for cut in [ct.len() - 1, ct.len() - 72, ct.len() - 72 - 500, 20] {
        let mut out = Vec::new();
        let err = open(Cursor::new(&ct[..cut]), &mut out, &owner.sealing).unwrap_err();
        assert!(
            matches!(err, Error::Truncated | Error::ChunkAuth(_) | Error::HeaderDecode(_)),
            "cut={cut} {err:?}"
        );
    }
    // appended garbage
    let mut ext = ct.clone();
    ext.push(0);
    let mut out = Vec::new();
    assert!(matches!(open(Cursor::new(&ext), &mut out, &owner.sealing), Err(Error::Truncated)));
}

#[test]
fn bad_magic_and_version() {
    let (owner, mut ct) = sealed(b"x", 1024);
    let mut out = Vec::new();
    let mut bad = ct.clone();
    bad[0] = b'X';
    assert!(matches!(open(Cursor::new(&bad), &mut out, &owner.sealing), Err(Error::BadMagic)));
    ct[6] = 9;
    assert!(matches!(open(Cursor::new(&ct), &mut out, &owner.sealing), Err(Error::UnsupportedVersion(9, _))));
}

#[test]
fn extra_recipient_envelope_opens() {
    let owner = OwnerKeys::generate().unwrap();
    let bob = DeviceKeys::generate().unwrap();
    let bob_pk = bob.public_key().to_vec();
    let recips: [&[u8]; 1] = [&bob_pk];
    let mut opts = SealOptions::new(b"acct", "a.txt");
    opts.extra_recipients = &recips;
    let mut ct = Vec::new();
    seal(Cursor::new(b"shared"), &mut ct, &owner, &opts).unwrap();
    let mut out = Vec::new();
    open(Cursor::new(&ct), &mut out, &bob).unwrap();
    assert_eq!(out, b"shared");
}

/// DoD Z-0.C.1: 100 MB round trip ≤ 2 s (release). Debug builds are slower; only assert in release.
#[test]
#[cfg_attr(debug_assertions, ignore = "perf gate runs in release: cargo test --release -- perf_")]
fn perf_100mb_roundtrip() {
    let plain = vec![0xA5u8; 100 * 1024 * 1024];
    let owner = OwnerKeys::generate().unwrap();
    let opts = SealOptions::new(b"acct", "big.bin");
    let mut ct = Vec::with_capacity(plain.len() + (1 << 20));
    let t0 = Instant::now();
    seal(Cursor::new(&plain), &mut ct, &owner, &opts).unwrap();
    let t_seal = t0.elapsed();
    let mut out = Vec::with_capacity(plain.len());
    let t1 = Instant::now();
    open(Cursor::new(&ct), &mut out, &owner.sealing).unwrap();
    let t_open = t1.elapsed();
    assert_eq!(out.len(), plain.len());
    eprintln!("100MB seal={t_seal:?} open={t_open:?}");
    if !cfg!(debug_assertions) {
        assert!(t_seal + t_open <= std::time::Duration::from_secs(2), "seal={t_seal:?} open={t_open:?}");
    }
}

// ------------------------------------------------------------------ recipient reseal (spec §5, Z-1.G.8)

/// A recipient with the current DEK (from a grant) writes the next version; the owner opens it
/// with their own keys, and the chain from v1 checks out.
#[test]
fn a_recipient_reseals_and_the_owner_can_open_the_new_version() {
    let dir = std::env::temp_dir().join(format!("zbacs-recipient-reseal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let plain = dir.join("doc.txt");
    let sealed = dir.join("doc.txt.zbacs");
    std::fs::write(&plain, b"version one").unwrap();

    let owner = zbacs_core::OwnerKeys::generate().unwrap();
    let mut opts = zbacs_core::SealOptions::new(b"acct", "doc.txt");
    opts.policy = zbacs_core::Policy { default: zbacs_core::Permission::Edit, ..Default::default() };
    let v1 = zbacs_core::seal_to_path(&plain, &sealed, &owner, &opts).unwrap();
    let opub: [u8; 32] = owner.sealing.public_key().try_into().unwrap();
    assert_eq!(v1.body.opub, Some(opub), "v1.1 headers carry the owner's public key");
    let (_, v1_hash) = zbacs_core::inspect(std::fs::File::open(&sealed).unwrap()).unwrap();

    // the grant path: the owner hands the DEK out (here: opened from the owner envelope)
    let dek = v1.body.env[0].open(&owner.sealing, &v1.body.fid.0).unwrap();

    // Bob edits and reseals with his own signing key
    let bob = zbacs_core::SigningKeys::generate();
    let edited = dir.join("edited.txt");
    std::fs::write(&edited, b"version two, by Bob").unwrap();
    let v2 = zbacs_core::reseal_as_recipient_to_path(
        &edited,
        &sealed,
        &dek,
        &bob,
        zbacs_core::Policy { default: zbacs_core::Permission::Edit, ..Default::default() },
    )
    .unwrap();
    assert_eq!(v2.body.ver, 2);
    assert_eq!(v2.body.prev, Some(v1_hash));
    assert_eq!(v2.body.fid, v1.body.fid);
    assert_eq!(v2.body.own, v1.body.own, "the owner account never changes");
    assert_eq!(v2.body.opub, Some(opub));
    assert_eq!(v2.sigk, bob.verifying_key().to_bytes().to_vec(), "signed by the recipient's device key");

    // the owner opens v2 with nothing but their own keys
    let out = dir.join("v2.txt");
    let opened = zbacs_core::open(
        std::fs::File::open(&sealed).unwrap(),
        std::fs::File::create(&out).unwrap(),
        &owner.sealing,
    )
    .unwrap();
    assert_eq!(opened.file_name, "doc.txt", "the name survives the reseal");
    assert_eq!(std::fs::read(&out).unwrap(), b"version two, by Bob");

    // the old DEK no longer opens the file (T20)
    let (h2, hh2, rest) = zbacs_core::read_header(std::fs::File::open(&sealed).unwrap()).unwrap();
    assert!(zbacs_core::open_with_dek(h2.clone(), hh2, rest, std::io::sink(), &dek).is_err());

    // and the chain v1 -> v2 is well formed (T19)
    zbacs_core::verify_version_chain(&[(v1, v1_hash), (h2, hh2)]).unwrap();
    std::fs::remove_dir_all(dir).ok();
}

/// A v1.0 container (no owner public key) cannot be resealed by a recipient, and says so.
#[test]
fn a_recipient_cannot_reseal_a_container_without_the_owner_key() {
    let dir = std::env::temp_dir().join(format!("zbacs-recipient-old-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let old = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/v1.zbacs");
    let (hdr, _) = zbacs_core::inspect(std::fs::File::open(&old).unwrap()).unwrap();
    assert_eq!(hdr.body.opub, None, "the fixture predates opub");
    let container = dir.join("old.zbacs");
    std::fs::copy(&old, &container).unwrap();
    let edited = dir.join("edited.txt");
    std::fs::write(&edited, b"x").unwrap();
    let dek = zbacs_core::Dek::generate();
    let err = zbacs_core::reseal_as_recipient_to_path(
        &edited,
        &container,
        &dek,
        &zbacs_core::SigningKeys::generate(),
        zbacs_core::Policy::default(),
    )
    .unwrap_err();
    assert!(matches!(err, zbacs_core::Error::NoOwnerKey), "{err:?}");
    std::fs::remove_dir_all(dir).ok();
}
