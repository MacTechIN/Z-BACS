//! Z-1.C.1 — formal API: Sealer/Opener traits, out-of-band grant path, reseal chain,
//! malformed-input rejections. Threat IDs per docs/threat_model.md.

use std::io::Cursor;
use zbacs_core::{
    inspect, read_header, Dek, DeviceKeys, Envelope, Error, GrantedDek, HeaderHash, Opener, OwnerKeys,
    Permission, Policy, PrevVersion, SealOptions, Sealer, MAGIC, MAX_HEADER_LEN, VERSION_MAJOR,
    VERSION_MINOR,
};

fn seal_bytes(owner: &OwnerKeys, plain: &[u8], opts: &SealOptions) -> Vec<u8> {
    let mut out = Vec::new();
    owner.seal(&mut Cursor::new(plain), &mut out, opts).unwrap();
    out
}

#[test]
fn sealer_and_opener_traits_are_object_safe_and_roundtrip() {
    let owner = OwnerKeys::generate().unwrap();
    let sealer: &dyn Sealer = &owner;
    let mut sealed = Vec::new();
    let hdr = sealer
        .seal(&mut Cursor::new(b"hello traits"), &mut sealed, &SealOptions::new(b"acct", "t.txt"))
        .unwrap();
    assert_eq!(hdr.body.ver, 1);
    assert!(hdr.body.prev.is_none());

    let opener: Box<dyn Opener> = Box::new(DeviceKeys::from_secret(owner.sealing.secret_key()).unwrap());
    let mut plain = Vec::new();
    let opened = opener.open(&mut Cursor::new(&sealed), &mut plain).unwrap();
    assert_eq!(plain, b"hello traits");
    assert_eq!(opened.file_name, "t.txt");
    assert_eq!(opened.header_hash, hdr.header_hash().unwrap());
}

/// The recipient never has an embedded envelope: the DEK arrives in a grant (spec §1.3).
#[test]
fn t04_granted_dek_opens_and_relay_only_sees_ciphertext() {
    let owner = OwnerKeys::generate().unwrap();
    let bob = DeviceKeys::generate().unwrap();
    let sealed = seal_bytes(&owner, b"granted content", &SealOptions::new(b"acct", "g.txt"));

    // owner side: unwrap own envelope, re-wrap for Bob bound to the grant context
    let (hdr, _hh) = inspect(Cursor::new(&sealed)).unwrap();
    let dek = hdr.body.env[0].open(&owner.sealing, hdr.body.fid.as_bytes()).unwrap();
    let grant_ctx = b"grantId-bytes";
    let for_bob = Envelope::seal(bob.public_key(), &dek, grant_ctx).unwrap();
    assert_eq!(for_bob.kid, bob.key_id());

    // Bob has no embedded envelope
    let mut sink = Vec::new();
    assert!(matches!(bob.open(&mut Cursor::new(&sealed), &mut sink), Err(Error::NoEnvelope)));

    // ...but opens with the granted DEK
    let dek_for_bob = for_bob.open(&bob, grant_ctx).unwrap();
    let opener = GrantedDek::new(dek_for_bob);
    let mut plain = Vec::new();
    let opened = opener.open(&mut Cursor::new(&sealed), &mut plain).unwrap();
    assert_eq!(plain, b"granted content");
    assert_eq!(opened.file_name, "g.txt");

    // wrong DEK fails on the name (first thing decrypted), never leaks chunks
    let wrong = GrantedDek::new(Dek::generate());
    let mut sink = Vec::new();
    assert!(matches!(wrong.open(&mut Cursor::new(&sealed), &mut sink), Err(Error::NameAuth)));
    assert!(sink.is_empty());
}

#[test]
fn reseal_chain_links_versions_by_header_hash() {
    let owner = OwnerKeys::generate().unwrap();
    let v1 = seal_bytes(&owner, b"v1", &SealOptions::new(b"acct", "doc.txt"));
    let (h1, hh1) = inspect(Cursor::new(&v1)).unwrap();
    assert_eq!(h1.body.ver, 1);

    let mut opts = SealOptions::new(b"acct", "doc.txt");
    opts.prev = Some(PrevVersion::of(&h1, hh1));
    opts.policy = Policy { default: Permission::Edit, ..Policy::default() };
    let v2 = seal_bytes(&owner, b"v2 edited", &opts);
    let (h2, _) = inspect(Cursor::new(&v2)).unwrap();
    assert_eq!(h2.body.ver, 2);
    assert_eq!(h2.body.prev, Some(hh1));
    assert_eq!(h2.body.pol.default, Permission::Edit);
    // a new version gets a fresh nonce prefix, but keeps the file identity (spec §5)
    assert_ne!(h2.body.np, h1.body.np);
    assert_eq!(h2.body.fid, h1.body.fid);
    assert_eq!(h2.body.salt, h1.body.salt);
}

#[test]
fn seal_to_path_is_atomic_and_reopens() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("in.bin");
    let dst = dir.path().join("out.zbacs");
    std::fs::write(&src, vec![0xA5u8; 100_000]).unwrap();
    let owner = OwnerKeys::generate().unwrap();
    let hdr = zbacs_core::seal_to_path(&src, &dst, &owner, &SealOptions::new(b"acct", "in.bin")).unwrap();
    assert!(!dir.path().join("out.zbacs.tmp").exists(), "temp file must be renamed away");
    assert_eq!(hdr.body.plen, 100_000);
    let data = std::fs::read(&dst).unwrap();
    let mut plain = Vec::new();
    let opened = zbacs_core::open(Cursor::new(&data), &mut plain, &owner.sealing).unwrap();
    assert_eq!(plain.len(), 100_000);
    assert_eq!(opened.file_name, "in.bin");
}

#[test]
fn empty_file_seals_to_one_chunk_and_opens() {
    let owner = OwnerKeys::generate().unwrap();
    let sealed = seal_bytes(&owner, b"", &SealOptions::new(b"acct", "empty"));
    let mut plain = vec![1u8];
    plain.clear();
    zbacs_core::open(Cursor::new(&sealed), &mut plain, &owner.sealing).unwrap();
    assert!(plain.is_empty());
}

#[test]
fn t18_seal_rejects_bad_chunk_sizes() {
    let owner = OwnerKeys::generate().unwrap();
    for bad in [0usize, 16 * 1024 * 1024 + 1] {
        let mut opts = SealOptions::new(b"acct", "x");
        opts.chunk_size = bad;
        let mut out = Vec::new();
        assert!(matches!(owner.seal(&mut Cursor::new(b"x"), &mut out, &opts), Err(Error::BadChunkSize(_))));
    }
}

#[test]
fn t18_header_length_field_is_bounded() {
    let mut data = MAGIC.to_vec();
    data.extend_from_slice(&[VERSION_MAJOR, VERSION_MINOR]);
    data.extend_from_slice(&((MAX_HEADER_LEN as u32) + 1).to_le_bytes());
    assert!(matches!(inspect(Cursor::new(&data)), Err(Error::HeaderTooLarge(_))));

    // length field larger than the actual stream -> truncated, not a panic
    let mut data = MAGIC.to_vec();
    data.extend_from_slice(&[VERSION_MAJOR, VERSION_MINOR]);
    data.extend_from_slice(&1000u32.to_le_bytes());
    data.extend_from_slice(&[0u8; 10]);
    assert!(matches!(inspect(Cursor::new(&data)), Err(Error::Truncated)));
}

#[test]
fn t18_unsupported_cipher_and_zero_chunk_in_header_rejected() {
    let owner = OwnerKeys::generate().unwrap();
    let sealed = seal_bytes(&owner, b"abc", &SealOptions::new(b"acct", "c"));
    let (hdr, _) = inspect(Cursor::new(&sealed)).unwrap();

    let rewrap = |body: zbacs_core::HeaderBody| -> Vec<u8> {
        let h = body.sign(&owner.signing).unwrap();
        let hb = h.encode().unwrap();
        let mut d = MAGIC.to_vec();
        d.extend_from_slice(&[VERSION_MAJOR, VERSION_MINOR]);
        d.extend_from_slice(&(hb.len() as u32).to_le_bytes());
        d.extend_from_slice(&hb);
        d
    };
    let mut b = hdr.body.clone();
    b.cipher = 99;
    assert!(matches!(inspect(Cursor::new(rewrap(b))), Err(Error::UnsupportedCipher(99))));
    let mut b = hdr.body.clone();
    b.chunk = 0;
    assert!(matches!(inspect(Cursor::new(rewrap(b))), Err(Error::BadChunkSize(0))));
}

#[test]
fn t19_trailing_bytes_after_trailer_rejected() {
    let owner = OwnerKeys::generate().unwrap();
    let mut sealed = seal_bytes(&owner, b"tail", &SealOptions::new(b"acct", "t"));
    sealed.push(0);
    let mut sink = Vec::new();
    assert!(matches!(
        zbacs_core::open(Cursor::new(&sealed), &mut sink, &owner.sealing),
        Err(Error::Truncated)
    ));
}

#[test]
fn read_header_positions_reader_at_first_chunk() {
    let owner = OwnerKeys::generate().unwrap();
    let sealed = seal_bytes(&owner, b"pos", &SealOptions::new(b"acct", "p"));
    let (hdr, hh, r) = read_header(Cursor::new(&sealed)).unwrap();
    let consumed = r.position() as usize;
    assert_eq!(consumed, 8 + 4 + hdr.encode().unwrap().len());
    assert_eq!(HeaderHash::from_slice(&sealed[sealed.len() - 72..sealed.len() - 40]).unwrap(), hh);
}

#[test]
fn error_display_never_contains_key_material() {
    let e = Error::ChunkAuth(3);
    assert_eq!(e.to_string(), "chunk 3 failed authentication");
    let e = Error::UnsupportedVersion(2, 0);
    assert_eq!(e.to_string(), "unsupported container version 2.0");
}
