//! Z-1.C.5 — frozen test vectors. The `.zbacs` files in `tests/vectors/` are committed and
//! must keep opening with the committed key and matching `manifest.json`. Any change to the
//! container format, the header CBOR, the name padding or the hashes breaks this test — which
//! is the point: the format is a contract with files already sealed on people's disks.
//!
//! Regenerate deliberately (and review the diff!) with:
//!   cargo test -p zbacs-core --test vectors -- --ignored regenerate
//!
//! The key file is a throwaway generated for these vectors only.

use std::io::Cursor;
use std::path::{Path, PathBuf};
use zbacs_core::{
    inspect, open, verify_version_chain, DeviceKeys, Header, HeaderHash, OwnerKeys, Permission, Policy,
    PrevVersion, SealOptions, SigningKeys,
};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn json(name: &str) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(dir().join(name)).expect(name)).unwrap()
}

fn owner() -> OwnerKeys {
    let k = json("owner.json");
    let hex = |f: &str| hex::decode(k[f].as_str().unwrap()).unwrap();
    OwnerKeys {
        sealing: DeviceKeys::from_secret(&hex("x25519_sk")).unwrap(),
        signing: SigningKeys::from_secret(&hex("ed25519_sk")).unwrap(),
    }
}

fn expect_hex(v: &serde_json::Value, field: &str) -> String {
    v[field].as_str().unwrap().to_string()
}

#[test]
fn frozen_vectors_still_open_and_match_the_manifest() {
    let m = json("manifest.json");
    let owner = owner();

    let mut chain: Vec<(Header, HeaderHash)> = Vec::new();
    for entry in m["versions"].as_array().unwrap() {
        let file = entry["file"].as_str().unwrap();
        let bytes = std::fs::read(dir().join(file)).expect(file);

        // header is verifiable without any key
        let (hdr, hh) = inspect(Cursor::new(&bytes)).unwrap();
        assert_eq!(hh.to_string(), expect_hex(entry, "header_hash"), "{file}: header hash drifted");
        assert_eq!(hdr.body.fid.to_string(), expect_hex(&m, "file_id"), "{file}: file id drifted");
        assert_eq!(
            hdr.policy_hash().unwrap().to_string(),
            expect_hex(entry, "policy_hash"),
            "{file}: policy hash drifted"
        );
        assert_eq!(hdr.body.ver, entry["version"].as_u64().unwrap() as u32);
        assert_eq!(hdr.body.plen, entry["plen"].as_u64().unwrap());
        assert_eq!(hdr.body.chunk, entry["chunk"].as_u64().unwrap() as u32);
        assert_eq!(hdr.body.env.len(), 1);
        assert_eq!(hdr.body.env[0].kid.to_string(), expect_hex(&m, "owner_kid"));
        // the encrypted name is padded to a 64-byte multiple + 16-byte tag (T13)
        assert_eq!(hdr.body.name.len() % 64, 16, "{file}: name field is not padded");

        // and it still decrypts to exactly the recorded plaintext and name
        let mut plain = Vec::new();
        let opened = open(Cursor::new(&bytes), &mut plain, &owner.sealing).unwrap();
        assert_eq!(opened.file_name, m["file_name"].as_str().unwrap());
        assert_eq!(
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&plain)),
            expect_hex(entry, "plaintext_sha256"),
            "{file}: plaintext drifted"
        );
        chain.push((hdr, hh));
    }

    // v1 -> v2 is a valid reseal chain
    verify_version_chain(&chain).unwrap();
    assert_eq!(chain[1].0.body.prev, Some(chain[0].1));
}

#[test]
fn a_tampered_vector_is_rejected() {
    let m = json("manifest.json");
    let file = m["versions"][0]["file"].as_str().unwrap();
    let mut bytes = std::fs::read(dir().join(file)).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let mut sink = Vec::new();
    assert!(open(Cursor::new(&bytes), &mut sink, &owner().sealing).is_err());
}

/// `cargo test -p zbacs-core --test vectors -- --ignored regenerate`
#[test]
#[ignore = "regenerates the committed vectors; run deliberately and review the diff"]
fn regenerate() {
    let d = dir();
    std::fs::create_dir_all(&d).unwrap();
    let owner = OwnerKeys::generate().unwrap();
    std::fs::write(
        d.join("owner.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "comment": "throwaway key for frozen container vectors (Z-1.C.5). Never used elsewhere.",
            "x25519_sk": hex::encode(owner.sealing.secret_key()),
            "x25519_pk": hex::encode(owner.sealing.public_key()),
            "ed25519_sk": hex::encode(owner.signing.secret_bytes()),
            "ed25519_pk": hex::encode(owner.signing.verifying_key().to_bytes()),
        }))
        .unwrap(),
    )
    .unwrap();

    let file_name = "분기보고서.docx"; // non-ASCII on purpose: the name is UTF-8 and padded
    let v1_plain = b"Z-BACS frozen vector v1: sealed content.".to_vec();
    let v2_plain = b"Z-BACS frozen vector v2: the recipient edited this, and the owner resealed it.".to_vec();

    let mut opts = SealOptions::new(b"eip155:84532:0xA11CE", file_name);
    opts.chunk_size = 16;
    opts.policy = Policy { default: Permission::ReadOnly, ttl: 3600, max: 1, pin: true, strict: false };
    let mut v1 = Vec::new();
    let h1 = zbacs_core::seal(Cursor::new(&v1_plain), &mut v1, &owner, &opts).unwrap();
    std::fs::write(d.join("v1.zbacs"), &v1).unwrap();
    let (_, hh1) = inspect(Cursor::new(&v1)).unwrap();

    let mut opts2 = SealOptions::new(b"eip155:84532:0xA11CE", file_name);
    opts2.chunk_size = 16;
    opts2.policy = Policy { default: Permission::Edit, ttl: 600, max: 3, pin: true, strict: true };
    opts2.prev = Some(PrevVersion::of(&h1, hh1));
    let mut v2 = Vec::new();
    let h2 = zbacs_core::seal(Cursor::new(&v2_plain), &mut v2, &owner, &opts2).unwrap();
    std::fs::write(d.join("v2.zbacs"), &v2).unwrap();
    let (_, hh2) = inspect(Cursor::new(&v2)).unwrap();

    let sha = |b: &[u8]| hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b));
    let manifest = serde_json::json!({
        "spec": "docs/specs/container_format.md v1.2",
        "generated_by": "cargo test -p zbacs-core --test vectors -- --ignored regenerate",
        "file_id": h1.body.fid.to_string(),
        "salt": h1.body.salt.to_string(),
        "file_name": file_name,
        "owner_account": "eip155:84532:0xA11CE",
        "owner_kid": h1.body.env[0].kid.to_string(),
        "versions": [
            {
                "file": "v1.zbacs",
                "version": 1,
                "header_hash": hh1.to_string(),
                "policy_hash": h1.policy_hash().unwrap().to_string(),
                "policy": "ReadOnly ttl=3600 max=1 pin strict=false",
                "plen": h1.body.plen,
                "chunk": h1.body.chunk,
                "plaintext_sha256": sha(&v1_plain),
            },
            {
                "file": "v2.zbacs",
                "version": 2,
                "header_hash": hh2.to_string(),
                "policy_hash": h2.policy_hash().unwrap().to_string(),
                "policy": "Edit ttl=600 max=3 pin strict=true",
                "plen": h2.body.plen,
                "chunk": h2.body.chunk,
                "plaintext_sha256": sha(&v2_plain),
                "prev": hh1.to_string(),
            }
        ],
    });
    std::fs::write(d.join("manifest.json"), serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    println!("regenerated vectors in {}", d.display());
}
