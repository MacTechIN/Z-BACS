//! Where a device's long-lived secrets live (Z-1.A.3).
//!
//! The Agent never asks the person to manage a key, so the secrets have to survive reboots on
//! their own: the OS keychain does that, protected by the user's login (Windows Credential
//! Manager → DPAPI, macOS Keychain, Linux Secret Service).
//!
//! Note what is *not* here: the owner's approval key. A platform passkey or a TPM device key
//! never leaves its hardware (ADR-0006), so there is nothing to store. This module holds the
//! X25519/Ed25519 device keys that receive DEK envelopes and sign relay messages, plus the
//! owner's sealing key.

use std::collections::HashMap;
use std::sync::Mutex;
use zeroize::Zeroizing;

use crate::error::{AuthError, Result};

/// Service name the OS keychain groups Z-BACS entries under.
pub const SERVICE: &str = "Z-BACS";

/// Entry names. Stable strings: changing one orphans the old secret in the keychain.
pub mod entry {
    /// X25519 secret that receives DEK envelopes for this device.
    pub const DEVICE_X25519: &str = "device-x25519";
    /// Ed25519 secret that signs relay envelopes from this device.
    pub const DEVICE_ED25519: &str = "device-ed25519";
    /// Owner's X25519 sealing secret (the self-envelope key).
    pub const OWNER_SEALING: &str = "owner-sealing";
    /// Owner's Ed25519 container header signing secret.
    pub const OWNER_SIGNING: &str = "owner-signing";
}

/// A place to keep secrets between runs.
///
/// Implementations must not return partial data: either the exact bytes that were stored, or
/// `None`. Errors carry no key material.
pub trait KeyStore: Send + Sync {
    /// Fetch a secret, or `None` when the entry does not exist.
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;
    /// Store (or replace) a secret.
    fn put(&self, name: &str, secret: &[u8]) -> Result<()>;
    /// Remove a secret. Removing a missing entry is not an error.
    fn delete(&self, name: &str) -> Result<()>;

    /// Return the stored secret, or create one with `make` and store it.
    ///
    /// This is how onboarding stays silent: first run generates and saves, every later run
    /// loads, and the person is never shown a key (ux_principles).
    fn get_or_create(
        &self,
        name: &str,
        make: impl FnOnce() -> Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if let Some(found) = self.get(name)? {
            return Ok(found);
        }
        let fresh = make();
        self.put(name, &fresh)?;
        Ok(fresh)
    }
}

/// The OS keychain (`keyring` crate).
///
/// - Windows: Credential Manager, encrypted with DPAPI under the logged-in user.
/// - macOS: Keychain.
/// - Linux: Secret Service (GNOME Keyring / KWallet). Headless boxes usually have no Secret
///   Service; [`OsKeyStore::available`] reports that so the caller can fall back rather than
///   fail at an awkward moment.
#[cfg(feature = "os-keystore")]
pub struct OsKeyStore {
    service: String,
}

#[cfg(feature = "os-keystore")]
impl OsKeyStore {
    /// Use the default [`SERVICE`] namespace.
    pub fn new() -> Self {
        Self { service: SERVICE.to_string() }
    }

    /// Use a custom namespace (tests, or several profiles on one machine).
    pub fn with_service(service: impl Into<String>) -> Self {
        Self { service: service.into() }
    }

    /// Whether this machine actually has a working keychain right now.
    pub fn available(&self) -> bool {
        keyring::Entry::new(&self.service, "zbacs-probe")
            .map(|e| !matches!(e.get_secret(), Err(keyring::Error::PlatformFailure(_))))
            .unwrap_or(false)
    }

    fn entry(&self, name: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.service, name).map_err(|e| AuthError::Hardware(format!("keychain: {e}")))
    }
}

#[cfg(feature = "os-keystore")]
impl Default for OsKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "os-keystore")]
impl KeyStore for OsKeyStore {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match self.entry(name)?.get_secret() {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(AuthError::Hardware(format!("keychain read: {e}"))),
        }
    }

    fn put(&self, name: &str, secret: &[u8]) -> Result<()> {
        self.entry(name)?.set_secret(secret).map_err(|e| AuthError::Hardware(format!("keychain write: {e}")))
    }

    fn delete(&self, name: &str) -> Result<()> {
        match self.entry(name)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(AuthError::Hardware(format!("keychain delete: {e}"))),
        }
    }
}

/// In-process store for tests, demos and headless CI. Never ship it as the only store: the
/// secrets die with the process, so the device would re-enrol on every run.
#[derive(Default)]
pub struct MemoryKeyStore {
    map: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
}

impl MemoryKeyStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyStore for MemoryKeyStore {
    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self.map.lock().expect("keystore mutex").get(name).cloned())
    }

    fn put(&self, name: &str, secret: &[u8]) -> Result<()> {
        self.map.lock().expect("keystore mutex").insert(name.to_string(), Zeroizing::new(secret.to_vec()));
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<()> {
        self.map.lock().expect("keystore mutex").remove(name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_or_create_is_stable_across_calls() {
        let store = MemoryKeyStore::new();
        let first = store.get_or_create(entry::DEVICE_X25519, || Zeroizing::new(vec![7; 32])).unwrap();
        let second = store.get_or_create(entry::DEVICE_X25519, || Zeroizing::new(vec![9; 32])).unwrap();
        assert_eq!(&*first, &vec![7; 32], "first call creates");
        assert_eq!(&*second, &*first, "second call must load, not regenerate");
    }

    #[test]
    fn missing_entries_and_deletes_behave() {
        let store = MemoryKeyStore::new();
        assert!(store.get("nope").unwrap().is_none());
        store.delete("nope").unwrap(); // deleting a missing entry is fine
        store.put("k", &[1, 2, 3]).unwrap();
        assert_eq!(&**store.get("k").unwrap().unwrap(), &[1, 2, 3]);
        store.put("k", &[4]).unwrap();
        assert_eq!(&**store.get("k").unwrap().unwrap(), &[4], "put replaces");
        store.delete("k").unwrap();
        assert!(store.get("k").unwrap().is_none());
    }
}
