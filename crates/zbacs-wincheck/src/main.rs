//! `zbacs-wincheck` — the Windows half of Phase 1 that a Linux CI cannot touch.
//!
//! One command exercises every piece that needs real hardware and prints a pass/fail report:
//!
//! ```text
//! cargo run -p zbacs-wincheck
//! ```
//!
//! Covers Z-1.A.2 (Windows Hello), Z-1.A.7 (TPM device key), Z-1.A.3 (credential store) and the
//! Windows half of Z-0.G.1 (`.zbacs` file association). See `docs/windows_checklist.md`.

#[cfg(not(windows))]
fn main() {
    eprintln!("zbacs-wincheck only runs on Windows; on other platforms the software signers in");
    eprintln!("zbacs-auth (feature `software-signer`) cover the same paths.");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() {
    windows_main::run();
}

#[cfg(windows)]
mod windows_main {
    use zbacs_auth::store::{entry, KeyStore, OsKeyStore};
    use zbacs_auth::types::{ApprovalChallenge, ApprovalContext, Confirmation};
    use zbacs_auth::windows::{api_version, foreground_window, WindowsDeviceKey, WindowsPasskey};
    use zbacs_auth::{verify_assertion, AuthError, AuthProvider};
    use zbacs_core::Permission;

    const KEY_NAME: &str = "Z-BACS wincheck device key";
    const RP_ID: &str = "zbacs.local";

    struct Report {
        passed: Vec<String>,
        failed: Vec<String>,
        skipped: Vec<String>,
    }

    impl Report {
        fn pass(&mut self, what: &str, detail: &str) {
            println!("  [PASS] {what}: {detail}");
            self.passed.push(what.into());
        }
        fn fail(&mut self, what: &str, detail: &str) {
            println!("  [FAIL] {what}: {detail}");
            self.failed.push(what.into());
        }
        fn skip(&mut self, what: &str, detail: &str) {
            println!("  [SKIP] {what}: {detail}");
            self.skipped.push(what.into());
        }
    }

    fn challenge(tag: &[u8]) -> ApprovalChallenge {
        let mut digest = [0u8; 32];
        for (i, b) in tag.iter().cycle().take(32).enumerate() {
            digest[i] = *b ^ (i as u8);
        }
        ApprovalChallenge {
            digest,
            context: ApprovalContext { permission: Permission::ReadOnly, file_id: [0; 32] },
        }
    }

    pub fn run() {
        println!("Z-BACS Windows self-test\n");
        let mut r = Report { passed: vec![], failed: vec![], skipped: vec![] };

        println!("[1] Z-1.A.3  credential store (Windows Credential Manager / DPAPI)");
        credential_store(&mut r);

        println!("\n[2] Z-1.A.7  device-bound key in the TPM (signer path B)");
        device_key(&mut r);

        println!("\n[3] Z-1.A.2  Windows Hello passkey (signer path A)");
        passkey(&mut r);

        println!("\n[4] Z-0.G.1  .zbacs file association");
        file_association(&mut r);

        println!("\n--- summary ---");
        println!("passed {}  failed {}  skipped {}", r.passed.len(), r.failed.len(), r.skipped.len());
        if !r.failed.is_empty() {
            println!("failed: {}", r.failed.join(", "));
            std::process::exit(1);
        }
        println!("\nNext, reboot and run this again: the store and the TPM key must still be there");
        println!("(that is the Z-1.A.3 / Z-1.A.7 'survives a reboot' requirement).");
    }

    fn credential_store(r: &mut Report) {
        let store = OsKeyStore::with_service("Z-BACS wincheck");
        if !store.available() {
            r.fail("keychain available", "Credential Manager did not answer");
            return;
        }
        let secret = [0x5A_u8; 32];
        if let Err(e) = store.put(entry::DEVICE_X25519, &secret) {
            r.fail("keychain write", &e.to_string());
            return;
        }
        match store.get(entry::DEVICE_X25519) {
            Ok(Some(got)) if *got == secret => {
                r.pass("keychain round-trip", "32 bytes written and read back");
                println!(
                    "         (left in place on purpose — re-run after a reboot to confirm it survives)"
                );
            }
            Ok(Some(_)) => r.fail("keychain round-trip", "read back different bytes"),
            Ok(None) => r.fail("keychain round-trip", "entry vanished immediately"),
            Err(e) => r.fail("keychain read", &e.to_string()),
        }
    }

    fn device_key(r: &mut Report) {
        // require_os_confirm = false so this runs unattended; the Agent uses true for Edit grants
        let key = match WindowsDeviceKey::open_or_create(KEY_NAME, false, true) {
            Ok(k) => k,
            Err(e) => {
                r.fail("TPM key create/open", &e.to_string());
                return;
            }
        };
        if key.tpm_backed() {
            r.pass("TPM key", "created in the Platform Crypto Provider (TPM)");
        } else {
            r.skip("TPM key", "no usable TPM — fell back to the software KSP (hardware guarantee lost)");
        }
        let public = key.public_key().expect("device key has a public key");
        println!("         keyId = {}", key.key_id());
        println!("         x     = 0x{}", hex::encode(public.x));
        println!("         y     = 0x{}", hex::encode(public.y));

        let c = challenge(b"zbacs-device-key");
        match key.sign(&c, Confirmation::NotRequired) {
            Ok(assertion) => match verify_assertion(&public, &c.digest, &assertion) {
                Ok(()) => {
                    r.pass("TPM key signature", "verifies against the exported public key (low-s enforced)")
                }
                Err(e) => r.fail("TPM key signature", &format!("did not verify: {e}")),
            },
            Err(AuthError::Cancelled) => r.skip("TPM key signature", "cancelled at the Windows prompt"),
            Err(e) => r.fail("TPM key signature", &e.to_string()),
        }
        println!("         (the key stays in the TPM under the name '{KEY_NAME}')");
    }

    fn passkey(r: &mut Report) {
        let version = api_version();
        if version == 0 {
            r.fail("webauthn.dll", "not available — Windows 10 1903 or newer is required");
            return;
        }
        r.pass("webauthn.dll", &format!("API version {version}"));

        println!("         Windows will now ask for your face / fingerprint / PIN (credential creation)");
        let hwnd = foreground_window();
        let user = std::env::var("USERNAME").unwrap_or_else(|_| "zbacs".into());
        let passkey = match WindowsPasskey::create(RP_ID, "Z-BACS", &user, hwnd) {
            Ok(p) => p,
            Err(AuthError::Cancelled) => {
                r.skip("Hello credential", "cancelled at the prompt");
                return;
            }
            Err(e) => {
                r.fail("Hello credential", &e.to_string());
                return;
            }
        };
        let public = passkey.public_key().expect("passkey has a public key");
        r.pass("Hello credential", &format!("created, credentialId {} bytes", passkey.credential_id().len()));
        println!("         keyId = {}", passkey.key_id());
        println!("         x     = 0x{}", hex::encode(public.x));

        println!("         Approve once more to test signing");
        let c = challenge(b"zbacs-passkey");
        match passkey.sign(&c, Confirmation::OsUserVerification) {
            Ok(assertion) => match verify_assertion(&public, &c.digest, &assertion) {
                Ok(()) => r.pass("Hello assertion", "verifies (UP+UV flags, challenge match, low-s)"),
                Err(e) => r.fail("Hello assertion", &format!("did not verify: {e}")),
            },
            Err(AuthError::Cancelled) => r.skip("Hello assertion", "cancelled at the prompt"),
            Err(e) => r.fail("Hello assertion", &e.to_string()),
        }
    }

    fn file_association(r: &mut Report) {
        use windows::core::w;
        use windows::Win32::System::Registry::{
            RegCloseKey, RegOpenKeyExW, HKEY, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, KEY_READ,
        };

        let probe = |root: HKEY, path: windows::core::PCWSTR| -> bool {
            let mut key = HKEY::default();
            let ok = unsafe { RegOpenKeyExW(root, path, 0, KEY_READ, &mut key).is_ok() };
            if ok {
                unsafe {
                    let _ = RegCloseKey(key);
                }
            }
            ok
        };

        let classes = probe(HKEY_CLASSES_ROOT, w!(".zbacs"));
        let user = probe(HKEY_CURRENT_USER, w!("Software\\Classes\\.zbacs"));
        if classes || user {
            r.pass(".zbacs association", "registered in the registry");
            println!(
                "         double-click a .zbacs file: the Agent must open with the path as its argument"
            );
        } else {
            r.skip(
                ".zbacs association",
                "not registered (install the Agent or the spike's NSIS bundle first)",
            );
        }
    }
}
