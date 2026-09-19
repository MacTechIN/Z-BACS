//! Z-1.A.7 — device-bound P-256 key in the Windows TPM (ADR-0006 signer path B).
//!
//! The key is created *inside* the Platform Crypto Provider, which is the TPM. It has no
//! export policy, so the private scalar never exists in process memory — not at creation, not
//! at signing. Approving a file request is then a raw P-256 signature over the user operation
//! hash, which `P256Validator` verifies on chain (T22: the key cannot be cloned to another
//! machine; T12: losing the machine means revoking that one key).
//!
//! `require_os_confirm` maps to CNG's UI policy: Windows puts its own consent/PIN dialog in
//! front of every use of the key, which is the OS-level half of the T23 policy that
//! [`crate::ConfirmationPolicy`] decides.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject,
    NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash, BCRYPT_ECCPUBLIC_BLOB,
    BCRYPT_ECDSA_PUBLIC_P256_MAGIC, CERT_KEY_SPEC, MS_KEY_STORAGE_PROVIDER, MS_PLATFORM_CRYPTO_PROVIDER,
    NCRYPT_ECDSA_P256_ALGORITHM, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE,
    NCRYPT_UI_POLICY_PROPERTY, NCRYPT_UI_PROTECT_KEY_FLAG,
};

use crate::error::{AuthError, Result};
use crate::provider::AuthProvider;
use crate::types::{ApprovalAssertion, ApprovalChallenge, Confirmation, KeyId, P256PublicKey, SignerKind};

/// CNG `NCRYPT_UI_POLICY` (the fields Windows reads for a consent prompt).
#[repr(C)]
struct NcryptUiPolicy {
    dw_version: u32,
    dw_flags: u32,
    psz_creation_title: PCWSTR,
    psz_friendly_name: PCWSTR,
    psz_description: PCWSTR,
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn cng_err(what: &str, e: windows::core::Error) -> AuthError {
    // 0x80090010 NTE_PERM, 0x80090011 NTE_NOT_FOUND, 0x8009000B NTE_BAD_KEY_STATE...
    AuthError::Hardware(format!("{what}: {} ({:#010x})", e.message(), e.code().0 as u32))
}

/// A P-256 key living in the machine's TPM (or, when explicitly allowed, the software KSP).
pub struct WindowsDeviceKey {
    provider: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
    public: P256PublicKey,
    require_os_confirm: bool,
    tpm_backed: bool,
    name: String,
}

// The CNG handles are owned by this struct and only used behind &self; CNG itself is thread-safe
// for key handles, and we never hand them out.
unsafe impl Send for WindowsDeviceKey {}
unsafe impl Sync for WindowsDeviceKey {}

impl WindowsDeviceKey {
    /// Open the named key, creating it on first run.
    ///
    /// `allow_software_fallback` lets a machine without a usable TPM still work, at the cost of
    /// the hardware guarantee — the Agent tells the person plainly and records it in the
    /// enrolment (`P256Validator` stores only the public key, so the chain cannot tell).
    pub fn open_or_create(
        name: &str,
        require_os_confirm: bool,
        allow_software_fallback: bool,
    ) -> Result<Self> {
        unsafe {
            let (provider, tpm_backed) = match open_provider(MS_PLATFORM_CRYPTO_PROVIDER) {
                Ok(p) => (p, true),
                Err(e) if allow_software_fallback => {
                    let _ = e;
                    (open_provider(MS_KEY_STORAGE_PROVIDER)?, false)
                }
                Err(e) => return Err(e),
            };

            let wname = wide(name);
            let mut key = NCRYPT_KEY_HANDLE::default();
            let existing =
                NCryptOpenKey(provider, &mut key, PCWSTR(wname.as_ptr()), CERT_KEY_SPEC(0), NCRYPT_FLAGS(0));

            if existing.is_err() {
                NCryptCreatePersistedKey(
                    provider,
                    &mut key,
                    NCRYPT_ECDSA_P256_ALGORITHM,
                    PCWSTR(wname.as_ptr()),
                    CERT_KEY_SPEC(0),
                    NCRYPT_FLAGS(0),
                )
                .map_err(|e| cng_err("create device key", e))?;

                if require_os_confirm {
                    let title = wide("Z-BACS");
                    let friendly = wide("Z-BACS 승인 키");
                    let description = wide("파일 접근 승인에 이 기기의 키를 사용합니다.");
                    let policy = NcryptUiPolicy {
                        dw_version: 1,
                        dw_flags: NCRYPT_UI_PROTECT_KEY_FLAG,
                        psz_creation_title: PCWSTR(title.as_ptr()),
                        psz_friendly_name: PCWSTR(friendly.as_ptr()),
                        psz_description: PCWSTR(description.as_ptr()),
                    };
                    let bytes = std::slice::from_raw_parts(
                        &policy as *const NcryptUiPolicy as *const u8,
                        std::mem::size_of::<NcryptUiPolicy>(),
                    );
                    NCryptSetProperty(key, NCRYPT_UI_POLICY_PROPERTY, bytes, NCRYPT_FLAGS(0))
                        .map_err(|e| cng_err("set ui policy", e))?;
                }
                // No export policy is set, so the key is non-exportable — the default for a
                // persisted CNG key and the whole point of path B.
                NCryptFinalizeKey(key, NCRYPT_FLAGS(0)).map_err(|e| cng_err("finalize device key", e))?;
            }

            let public = export_public(key)?;
            Ok(Self { provider, key, public, require_os_confirm, tpm_backed, name: name.to_string() })
        }
    }

    /// Whether the key really sits in the TPM (false = software fallback).
    pub fn tpm_backed(&self) -> bool {
        self.tpm_backed
    }

    /// CNG key name, for diagnostics.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Delete the key from the store — used when the owner retires this device.
    pub fn delete(self) -> Result<()> {
        unsafe { NCryptDeleteKey(self.key, 0).map_err(|e| cng_err("delete device key", e)) }
    }
}

impl Drop for WindowsDeviceKey {
    fn drop(&mut self) {
        unsafe {
            let _ = NCryptFreeObject(self.key);
            let _ = NCryptFreeObject(self.provider);
        }
    }
}

unsafe fn open_provider(name: PCWSTR) -> Result<NCRYPT_PROV_HANDLE> {
    let mut provider = NCRYPT_PROV_HANDLE::default();
    NCryptOpenStorageProvider(&mut provider, name, 0).map_err(|e| cng_err("open storage provider", e))?;
    Ok(provider)
}

/// `BCRYPT_ECCKEY_BLOB`: magic(4) | cbKey(4) | X(cbKey) | Y(cbKey).
unsafe fn export_public(key: NCRYPT_KEY_HANDLE) -> Result<P256PublicKey> {
    let mut len = 0u32;
    NCryptExportKey(
        key,
        NCRYPT_KEY_HANDLE::default(),
        BCRYPT_ECCPUBLIC_BLOB,
        None,
        None,
        &mut len,
        NCRYPT_FLAGS(0),
    )
    .map_err(|e| cng_err("size public key", e))?;
    let mut blob = vec![0u8; len as usize];
    NCryptExportKey(
        key,
        NCRYPT_KEY_HANDLE::default(),
        BCRYPT_ECCPUBLIC_BLOB,
        None,
        Some(&mut blob),
        &mut len,
        NCRYPT_FLAGS(0),
    )
    .map_err(|e| cng_err("export public key", e))?;

    if blob.len() < 8 + 64 {
        return Err(AuthError::Malformed("ECC public blob is too short"));
    }
    let magic = u32::from_le_bytes(blob[0..4].try_into().unwrap());
    let cb_key = u32::from_le_bytes(blob[4..8].try_into().unwrap()) as usize;
    if magic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || cb_key != 32 {
        return Err(AuthError::Malformed("key is not ECDSA P-256"));
    }
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&blob[8..40]);
    y.copy_from_slice(&blob[40..72]);
    Ok(P256PublicKey { x, y })
}

impl AuthProvider for WindowsDeviceKey {
    fn kind(&self) -> SignerKind {
        SignerKind::DeviceKey
    }

    fn key_id(&self) -> KeyId {
        self.public.key_id()
    }

    fn public_key(&self) -> Option<P256PublicKey> {
        Some(self.public)
    }

    fn supports_os_confirmation(&self) -> bool {
        self.require_os_confirm
    }

    fn sign(&self, challenge: &ApprovalChallenge, confirmation: Confirmation) -> Result<ApprovalAssertion> {
        if confirmation == Confirmation::OsUserVerification && !self.require_os_confirm {
            return Err(AuthError::ConfirmationUnavailable(SignerKind::DeviceKey, confirmation));
        }
        unsafe {
            // ECDSA: no padding info, and CNG returns r||s big-endian, 32 bytes each.
            let mut len = 0u32;
            NCryptSignHash(self.key, None, &challenge.digest, None, &mut len, NCRYPT_FLAGS(0))
                .map_err(|e| cng_err("size signature", e))?;
            let mut sig = vec![0u8; len as usize];
            NCryptSignHash(self.key, None, &challenge.digest, Some(&mut sig), &mut len, NCRYPT_FLAGS(0))
                .map_err(|e| match e.code().0 as u32 {
                    // NTE_USER_CANCELLED — the person dismissed the Windows prompt
                    0x8009_002E => AuthError::Cancelled,
                    _ => cng_err("sign", e),
                })?;
            if sig.len() != 64 {
                return Err(AuthError::Malformed("CNG returned a signature that is not 64 bytes"));
            }
            let mut r = [0u8; 32];
            let mut s = [0u8; 32];
            r.copy_from_slice(&sig[..32]);
            s.copy_from_slice(&sig[32..]);
            let (r, s) = crate::windows::normalize_low_s(r, s);
            Ok(ApprovalAssertion::P256Raw { key_id: self.key_id(), r, s })
        }
    }
}
