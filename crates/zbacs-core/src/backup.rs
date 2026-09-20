//! Z-1.A.4 — encrypted backup of the owner's long-lived keys.
//!
//! The owner's sealing key is the only thing that can reopen their own sealed files. It lives
//! in the OS keychain, which dies with the machine — so there has to be a way to carry it to a
//! new one. This module writes that as a single small file.
//!
//! # Why a recovery code and not a password
//!
//! `ux_principles` forbids asking the person to invent and remember anything. So the Agent
//! *generates* a [`RecoveryCode`] (128 bits, grouped for reading aloud), shows it once, and
//! stretches it with Argon2id into the file key. The person writes it down or prints it; they
//! never type a password, and a weak choice is impossible.
//!
//! # What the file protects against
//!
//! - Someone who finds the file without the code learns nothing (Argon2id + XChaCha20-Poly1305).
//! - A modified file is refused rather than partly restored (AEAD over the whole body, and the
//!   header is authenticated as associated data).
//!
//! It does **not** protect against someone who has both the file and the code — that pair is
//! the account. Phase 2 splits the code with Shamir (Z-2.A.1) so no single place holds it.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::keys::{DeviceKeys, OwnerKeys, SigningKeys};
use crate::types::serde_bytes_array;

/// File magic: `ZBACSBK\0`.
pub const BACKUP_MAGIC: &[u8; 8] = b"ZBACSBK\0";
/// Backup format version.
pub const BACKUP_VERSION: u8 = 1;
/// Argon2id parameters: 64 MiB, 3 passes, 1 lane. Chosen so a laptop takes ~0.2 s while a
/// GPU farm still has to spend real memory per guess.
pub const ARGON_MEM_KIB: u32 = 64 * 1024;
/// Argon2id time cost.
pub const ARGON_PASSES: u32 = 3;
/// Argon2id lanes.
pub const ARGON_LANES: u32 = 1;
/// Domain separation for the backup KDF.
pub const BACKUP_KDF_DOMAIN: &[u8] = b"ZBACS-BACKUP-v1";

/// Alphabet for recovery codes: Crockford base32 minus `I`, `L`, `O`, `U` so nothing is
/// mistaken for another character when read aloud or written by hand.
const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Groups × characters per group (5 × 5 = 25 chars ≈ 125 bits).
const GROUPS: usize = 5;
const PER_GROUP: usize = 5;

/// A generated recovery code, e.g. `K7M2Q-3XJ9T-...`.
///
/// Shown once at onboarding. Zeroized on drop, so the Agent must render it before dropping it.
pub struct RecoveryCode(Zeroizing<String>);

impl RecoveryCode {
    /// Generate a fresh code from the OS RNG.
    pub fn generate() -> Self {
        let mut out = String::with_capacity(GROUPS * (PER_GROUP + 1));
        let mut buf = [0u8; GROUPS * PER_GROUP];
        OsRng.fill_bytes(&mut buf);
        for (i, b) in buf.iter().enumerate() {
            if i > 0 && i % PER_GROUP == 0 {
                out.push('-');
            }
            out.push(ALPHABET[(*b as usize) % ALPHABET.len()] as char);
        }
        buf.zeroize();
        Self(Zeroizing::new(out))
    }

    /// Accept a code the person typed back, ignoring case, spaces and dashes.
    pub fn parse(input: &str) -> Result<Self> {
        let normalised: String = input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        if normalised.len() != GROUPS * PER_GROUP {
            return Err(Error::RecoveryCode);
        }
        if !normalised.bytes().all(|b| ALPHABET.contains(&b)) {
            return Err(Error::RecoveryCode);
        }
        let grouped: String = normalised
            .as_bytes()
            .chunks(PER_GROUP)
            .map(|c| std::str::from_utf8(c).expect("ascii"))
            .collect::<Vec<_>>()
            .join("-");
        Ok(Self(Zeroizing::new(grouped)))
    }

    /// The code as shown to the person (groups separated by `-`).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Bytes fed to the KDF: the code without separators.
    fn kdf_input(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.bytes().filter(|b| *b != b'-').collect())
    }
}

impl std::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryCode(REDACTED)")
    }
}

/// The secrets a backup carries.
#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
struct Secrets {
    #[serde(with = "serde_bytes")]
    sealing_sk: Vec<u8>,
    #[serde(with = "serde_bytes_array")]
    signing_sk: [u8; 32],
    /// Extra secrets the Agent wants carried along (e.g. the OTAK seed). Opaque here.
    #[serde(with = "serde_bytes")]
    extra: Vec<u8>,
}

/// Authenticated header, written in the clear so a reader can tell what the file is and how to
/// stretch the code before it has anything to decrypt.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct Header {
    version: u8,
    mem_kib: u32,
    passes: u32,
    lanes: u32,
    #[serde(with = "serde_bytes_array")]
    salt: [u8; 16],
    #[serde(with = "serde_bytes_array")]
    nonce: [u8; 24],
}

/// Encrypt the owner's keys under a freshly generated recovery code.
///
/// Returns the file bytes and the code — **show the code once and do not store it next to the
/// file.** `extra` is passed through untouched (the Agent uses it for the OTAK seed).
pub fn export_backup(owner: &OwnerKeys, extra: &[u8]) -> Result<(Vec<u8>, RecoveryCode)> {
    let code = RecoveryCode::generate();
    let bytes = export_backup_with_code(owner, extra, &code)?;
    Ok((bytes, code))
}

/// Same as [`export_backup`] but with a code the caller already has (re-exporting to a second
/// medium, or tests).
pub fn export_backup_with_code(owner: &OwnerKeys, extra: &[u8], code: &RecoveryCode) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let header = Header {
        version: BACKUP_VERSION,
        mem_kib: ARGON_MEM_KIB,
        passes: ARGON_PASSES,
        lanes: ARGON_LANES,
        salt,
        nonce,
    };
    let header_cbor = cbor(&header)?;

    let secrets = Secrets {
        sealing_sk: owner.sealing.secret_key().to_vec(),
        signing_sk: owner.signing.secret_bytes(),
        extra: extra.to_vec(),
    };
    let plaintext = Zeroizing::new(cbor(&secrets)?);

    let key = derive_key(code, &header)?;
    let aead = XChaCha20Poly1305::new((&*key).into());
    let ct = aead
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plaintext, aad: &header_cbor })
        .map_err(|_| Error::EnvelopeSeal)?;

    let mut out = Vec::with_capacity(8 + 4 + header_cbor.len() + ct.len());
    out.extend_from_slice(BACKUP_MAGIC);
    out.extend_from_slice(&(header_cbor.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_cbor);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Restore the owner's keys from a backup file.
///
/// A wrong code and a tampered file are both [`Error::BackupAuth`]: the AEAD cannot tell them
/// apart, and neither can the person, so the Agent shows one message ("코드가 맞지 않거나
/// 파일이 손상되었습니다").
pub fn restore_backup(bytes: &[u8], code: &RecoveryCode) -> Result<(OwnerKeys, Vec<u8>)> {
    if bytes.len() < 12 || &bytes[..8] != BACKUP_MAGIC {
        return Err(Error::BadMagic);
    }
    let header_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    if header_len == 0 || bytes.len() < 12 + header_len + 16 {
        return Err(Error::Truncated);
    }
    let header_cbor = &bytes[12..12 + header_len];
    let header: Header =
        ciborium::from_reader(header_cbor).map_err(|e| Error::HeaderDecode(e.to_string()))?;
    if header.version != BACKUP_VERSION {
        return Err(Error::UnsupportedVersion(header.version, 0));
    }
    // Bound the KDF cost a hostile file can ask for: 1 GiB / 10 passes is far above our own
    // parameters and still finishes, while a crafted 64 GiB request would not.
    if header.mem_kib > 1024 * 1024 || header.passes > 10 || header.lanes > 4 || header.lanes == 0 {
        return Err(Error::HeaderDecode("backup KDF parameters out of range".into()));
    }

    let key = derive_key(code, &header)?;
    let aead = XChaCha20Poly1305::new((&*key).into());
    let plaintext = Zeroizing::new(
        aead.decrypt(
            XNonce::from_slice(&header.nonce),
            Payload { msg: &bytes[12 + header_len..], aad: header_cbor },
        )
        .map_err(|_| Error::BackupAuth)?,
    );

    let secrets: Secrets =
        ciborium::from_reader(plaintext.as_slice()).map_err(|e| Error::HeaderDecode(e.to_string()))?;
    let owner = OwnerKeys {
        sealing: DeviceKeys::from_secret(&secrets.sealing_sk)?,
        signing: SigningKeys::from_secret(&secrets.signing_sk)?,
    };
    Ok((owner, secrets.extra.clone()))
}

fn derive_key(code: &RecoveryCode, header: &Header) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(header.mem_kib, header.passes, header.lanes, Some(32))
        .map_err(|_| Error::HeaderDecode("bad Argon2 parameters".into()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut salted = Vec::with_capacity(BACKUP_KDF_DOMAIN.len() + header.salt.len());
    salted.extend_from_slice(BACKUP_KDF_DOMAIN);
    salted.extend_from_slice(&header.salt);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(&code.kdf_input(), &salted, &mut *key)
        .map_err(|_| Error::HeaderDecode("key derivation failed".into()))?;
    Ok(key)
}

fn cbor<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(v, &mut out).map_err(|e| Error::HeaderEncode(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_code_shape_and_parsing() {
        let code = RecoveryCode::generate();
        let shown = code.as_str().to_string();
        assert_eq!(shown.len(), GROUPS * PER_GROUP + (GROUPS - 1));
        assert_eq!(shown.matches('-').count(), GROUPS - 1);
        assert!(shown.bytes().all(|b| b == b'-' || ALPHABET.contains(&b)));
        assert!(!shown.contains(['I', 'L', 'O', 'U']), "ambiguous letters are excluded");
        assert_eq!(format!("{code:?}"), "RecoveryCode(REDACTED)");

        // typed back sloppily
        let messy = shown.to_lowercase().replace('-', " ");
        assert_eq!(RecoveryCode::parse(&messy).unwrap().as_str(), shown);
        assert!(matches!(RecoveryCode::parse("too-short"), Err(Error::RecoveryCode)));
        assert!(matches!(RecoveryCode::parse(&"I".repeat(25)), Err(Error::RecoveryCode)));
    }

    #[test]
    fn two_codes_are_not_the_same() {
        let a = RecoveryCode::generate();
        let b = RecoveryCode::generate();
        assert_ne!(a.as_str(), b.as_str());
    }
}
