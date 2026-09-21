//! Z-1.G.3 DoD — the lock screen really produces a `.zbacs` the owner can open again.
//!
//! The unit tests in `seal.rs` cover the refusals; this one covers the thing that actually
//! matters to a person: a file they locked on this machine opens again on this machine, with
//! the permission they chose, and its name is not sitting in the clear inside the container.

#![cfg(feature = "demo-signer")]

use std::path::PathBuf;
use std::sync::Arc;

use zbacs_agent_lib::seal::{seal_now, OpensArg, PermissionArg, SealRequest, TtlArg};
use zbacs_agent_lib::setup::SetupHost;
use zbacs_auth::setup::ApprovalStyle;
use zbacs_auth::store::{KeyStore, MemoryKeyStore};

fn temp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zbacs-seal-it-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_locked_file_opens_again_with_the_owners_own_key() {
    let dir = temp("roundtrip");
    let store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let host = SetupHost::with_store(dir.join("config"), store, true);

    // first run, then lock a file — the order a person does it in
    let prepared = host.complete(ApprovalStyle::ThisDevice, 1_758_000_000).expect("setup");
    let owner = host.owner_keys().expect("owner keys");

    let plain = dir.join("report.docx");
    let text = b"quarterly numbers, not for everyone".to_vec();
    std::fs::write(&plain, &text).unwrap();

    let request = SealRequest {
        path: plain.display().to_string(),
        permission: PermissionArg::Edit,
        ttl: TtlArg::Day,
        opens: OpensArg::Thrice,
    };
    let result = seal_now(&owner, &prepared.profile, &request).expect("seal");
    assert_eq!(result.output_name, "report.docx.zbacs");
    assert!(result.pending.contains(&"chain_registration"), "not on chain yet, and says so");

    // what anyone can see without a key: it is locked, version 1, editable by the owner's choice
    let sealed = std::fs::File::open(&result.output).unwrap();
    let (header, _) = zbacs_core::inspect(std::io::BufReader::new(sealed)).expect("a container");
    assert_eq!(header.body.ver, 1);
    assert_eq!(header.body.pol.default, zbacs_core::Permission::Edit);
    assert_eq!(header.body.pol.ttl, 86_400);
    assert_eq!(header.body.pol.max, 3);
    assert_eq!(header.body.own, prepared.profile.owner_signing_pub.to_vec(), "owner identity");

    // T13: the file name is not readable in the container
    let raw = std::fs::read(&result.output).unwrap();
    assert!(
        !raw.windows(11).any(|w| w == b"report.docx"),
        "the original name must not be readable in the sealed file"
    );

    // and it opens again with the owner's sealing key
    let mut out = Vec::new();
    let opened = zbacs_core::open(
        std::io::BufReader::new(std::fs::File::open(&result.output).unwrap()),
        &mut out,
        &owner.sealing,
    )
    .expect("open");
    assert_eq!(out, text, "the plaintext comes back byte for byte");
    assert_eq!(opened.file_name, "report.docx", "the name comes back for the person who may see it");

    // the original is still there: the result screen says so, and offers to erase it
    assert!(plain.exists());
    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn locking_the_same_file_twice_does_not_overwrite_the_first_one() {
    let dir = temp("twice");
    let store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let host = SetupHost::with_store(dir.join("config"), store, true);
    let prepared = host.complete(ApprovalStyle::ThisDevice, 1_758_000_000).expect("setup");
    let owner = host.owner_keys().unwrap();

    let plain = dir.join("a.txt");
    std::fs::write(&plain, b"first").unwrap();
    let request = SealRequest {
        path: plain.display().to_string(),
        permission: PermissionArg::ReadOnly,
        ttl: TtlArg::Hour,
        opens: OpensArg::Once,
    };
    let first = seal_now(&owner, &prepared.profile, &request).unwrap();
    let before = std::fs::read(&first.output).unwrap();

    // a second attempt is refused, and the file already sent to someone is untouched
    assert_eq!(seal_now(&owner, &prepared.profile, &request).unwrap_err(), "output_exists");
    assert_eq!(std::fs::read(&first.output).unwrap(), before);
    std::fs::remove_dir_all(dir).ok();
}
