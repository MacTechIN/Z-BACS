//! Z-1.A.4 — owner key backup and restore. DoD: a backup restores, and only with its code.

use std::io::Cursor;
use zbacs_core::backup::{export_backup_with_code, BACKUP_MAGIC, BACKUP_VERSION};
use zbacs_core::{export_backup, inspect, open, restore_backup, Error, OwnerKeys, RecoveryCode, SealOptions};

fn seal(owner: &OwnerKeys, plain: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    zbacs_core::seal(Cursor::new(plain), &mut out, owner, &SealOptions::new(b"acct", "doc.txt")).unwrap();
    out
}

/// The point of the whole feature: a machine died, and the owner can still open their files.
#[test]
fn a_restored_owner_opens_files_sealed_on_the_old_machine() {
    let owner = OwnerKeys::generate().unwrap();
    let sealed = seal(&owner, b"contract text");
    let (backup, code) = export_backup(&owner, b"").unwrap();

    // new machine: only the backup file and the written-down code
    let typed = RecoveryCode::parse(code.as_str()).unwrap();
    let (restored, extra) = restore_backup(&backup, &typed).unwrap();
    assert!(extra.is_empty());

    let mut plain = Vec::new();
    let opened = open(Cursor::new(&sealed), &mut plain, &restored.sealing).unwrap();
    assert_eq!(plain, b"contract text");
    assert_eq!(opened.file_name, "doc.txt");

    // and it still signs headers with the same identity
    assert_eq!(restored.signing.verifying_key(), owner.signing.verifying_key());
    assert_eq!(restored.sealing.key_id(), owner.sealing.key_id());

    // a container sealed by the restored keys is indistinguishable to the old ones
    let after = seal(&restored, b"new file");
    let (hdr, _) = inspect(Cursor::new(&after)).unwrap();
    assert_eq!(hdr.sigk, owner.signing.verifying_key().to_bytes().to_vec());
}

#[test]
fn extra_payload_round_trips() {
    // the Agent carries the OTAK seed (and anything else) in the same file
    let owner = OwnerKeys::generate().unwrap();
    let otak_seed = [0x5A_u8; 32];
    let (backup, code) = export_backup(&owner, &otak_seed).unwrap();
    let (_, extra) = restore_backup(&backup, &code).unwrap();
    assert_eq!(extra, otak_seed);
}

#[test]
fn a_wrong_code_does_not_restore_anything() {
    let owner = OwnerKeys::generate().unwrap();
    let (backup, _code) = export_backup(&owner, b"").unwrap();
    let wrong = RecoveryCode::generate();
    assert!(matches!(restore_backup(&backup, &wrong), Err(Error::BackupAuth)));
}

/// Wrong code and damaged file must be indistinguishable — the person is shown one message.
#[test]
fn a_tampered_backup_is_refused_everywhere_it_can_be_touched() {
    let owner = OwnerKeys::generate().unwrap();
    let code = RecoveryCode::generate();
    let backup = export_backup_with_code(&owner, b"", &code).unwrap();

    // ciphertext
    let mut t = backup.clone();
    let last = t.len() - 1;
    t[last] ^= 1;
    assert!(matches!(restore_backup(&t, &code), Err(Error::BackupAuth)));

    // header: salt/nonce are authenticated as associated data, so flipping one is caught
    let header_len = u32::from_le_bytes(backup[8..12].try_into().unwrap()) as usize;
    for offset in [14usize, 12 + header_len - 1] {
        let mut t = backup.clone();
        t[offset] ^= 1;
        let e = restore_backup(&t, &code).unwrap_err();
        assert!(
            matches!(e, Error::BackupAuth | Error::HeaderDecode(_) | Error::UnsupportedVersion(_, _)),
            "offset {offset}: {e:?}"
        );
    }

    // truncation
    assert!(matches!(restore_backup(&backup[..backup.len() - 1], &code), Err(Error::BackupAuth)));
    assert!(matches!(restore_backup(&backup[..20], &code), Err(Error::Truncated)));
}

#[test]
fn a_file_that_is_not_a_backup_is_rejected_by_shape() {
    let code = RecoveryCode::generate();
    assert!(matches!(restore_backup(b"", &code), Err(Error::BadMagic)));
    assert!(matches!(restore_backup(b"not a backup file at all", &code), Err(Error::BadMagic)));

    let mut bogus = BACKUP_MAGIC.to_vec();
    bogus.extend_from_slice(&0u32.to_le_bytes());
    assert!(matches!(restore_backup(&bogus, &code), Err(Error::Truncated)));
}

#[test]
fn an_unknown_backup_version_is_refused() {
    let owner = OwnerKeys::generate().unwrap();
    let code = RecoveryCode::generate();
    let backup = export_backup_with_code(&owner, b"", &code).unwrap();
    // the header is CBOR `{"version": 1, ...}`; find the encoded version byte and bump it
    let header_len = u32::from_le_bytes(backup[8..12].try_into().unwrap()) as usize;
    let header = &backup[12..12 + header_len];
    let pos = header.windows(1).position(|w| w == [BACKUP_VERSION]).unwrap();
    let mut t = backup.clone();
    t[12 + pos] = 9;
    let e = restore_backup(&t, &code).unwrap_err();
    assert!(
        matches!(e, Error::UnsupportedVersion(_, _) | Error::HeaderDecode(_) | Error::BackupAuth),
        "{e:?}"
    );
}

/// A hostile file must not be able to make us spend a minute and 64 GiB on a KDF.
#[test]
fn absurd_kdf_parameters_are_refused_before_stretching() {
    let owner = OwnerKeys::generate().unwrap();
    let code = RecoveryCode::generate();
    let backup = export_backup_with_code(&owner, b"", &code).unwrap();
    let header_len = u32::from_le_bytes(backup[8..12].try_into().unwrap()) as usize;
    let header = &backup[12..12 + header_len];

    // 64 MiB = 0x10000 appears in the header as a CBOR uint32
    let needle = 65536u32.to_be_bytes();
    let pos = header.windows(4).position(|w| w == needle).expect("mem_kib in header");
    let mut t = backup.clone();
    t[12 + pos..12 + pos + 4].copy_from_slice(&(64 * 1024 * 1024u32).to_be_bytes()); // 64 GiB

    let start = std::time::Instant::now();
    let e = restore_backup(&t, &code).unwrap_err();
    assert!(matches!(e, Error::HeaderDecode(_) | Error::BackupAuth), "{e:?}");
    assert!(start.elapsed().as_secs() < 5, "must refuse without attempting the derivation");
}

#[test]
fn the_same_keys_exported_twice_produce_different_files() {
    let owner = OwnerKeys::generate().unwrap();
    let code = RecoveryCode::generate();
    let a = export_backup_with_code(&owner, b"", &code).unwrap();
    let b = export_backup_with_code(&owner, b"", &code).unwrap();
    assert_ne!(a, b, "fresh salt and nonce every time");
    // both restore
    assert_eq!(
        restore_backup(&a, &code).unwrap().0.sealing.key_id(),
        restore_backup(&b, &code).unwrap().0.sealing.key_id()
    );
}

#[test]
fn backup_files_are_small_enough_to_print() {
    let owner = OwnerKeys::generate().unwrap();
    let (backup, _) = export_backup(&owner, &[0u8; 32]).unwrap();
    assert!(backup.len() < 512, "backup is {} bytes", backup.len());
}
