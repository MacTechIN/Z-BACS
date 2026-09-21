//! Windows hardware signers: the two ADR-0006 paths as the OS actually provides them.
//!
//! - [`passkey::WindowsPasskey`] — Windows Hello through `webauthn.dll` (Z-1.A.2).
//! - [`device_key::WindowsDeviceKey`] — a non-exportable P-256 key in the TPM via CNG (Z-1.A.7).
//!
//! Both produce the same [`crate::ApprovalAssertion`] the software stand-ins do, so everything
//! above them — the confirmation policy, the relay message, the on-chain validators — is
//! unchanged. Only this module knows it is running on Windows.
//!
//! These paths need real hardware, so they are exercised by `zbacs-wincheck` on a Windows
//! machine rather than in CI (see `docs/windows_checklist.md`).

pub mod device_key;
pub mod passkey;

pub use device_key::WindowsDeviceKey;
pub use passkey::{api_version, foreground_window, WindowsPasskey};

use crate::error::{AuthError, Result};

/// Curve order and its halfway point (secp256r1).
const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc,
    0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// Fold `s` into the lower half of the curve order.
///
/// Neither CNG nor a WebAuthn authenticator promises a low `s`, but both on-chain validators
/// reject a high one (OZ `P256.verify`), so the normalisation has to happen here — the same
/// rule `zbacs-auth`'s verifier enforces (T03/T14, and the Z-0.H.2 finding that the RIP-7212
/// precompile does *not* reject malleable signatures by itself).
pub fn normalize_low_s(r: [u8; 32], s: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    if !is_high_s(&s) {
        return (r, s);
    }
    // s' = n - s, big-endian
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = N[i] as i16 - s[i] as i16 - borrow;
        if d < 0 {
            out[i] = (d + 256) as u8;
            borrow = 1;
        } else {
            out[i] = d as u8;
            borrow = 0;
        }
    }
    (r, out)
}

fn is_high_s(s: &[u8; 32]) -> bool {
    // s > n/2  <=>  2s > n; compare against n/2 directly (n is odd, so n/2 rounds down)
    let half = half_n();
    for i in 0..32 {
        match s[i].cmp(&half[i]) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    false
}

fn half_n() -> [u8; 32] {
    let mut half = [0u8; 32];
    let mut carry = 0u8;
    for i in 0..32 {
        half[i] = (N[i] >> 1) | (carry << 7);
        carry = N[i] & 1;
    }
    half
}

/// Parse an ASN.1 DER ECDSA signature into low-s `(r, s)`.
///
/// WebAuthn authenticators return DER; the on-chain validator wants raw 32-byte scalars.
pub fn der_to_low_s(der: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let sig =
        p256::ecdsa::Signature::from_der(der).map_err(|_| AuthError::Malformed("signature is not DER"))?;
    let sig = sig.normalize_s().unwrap_or(sig);
    Ok((sig.r().to_bytes().into(), sig.s().to_bytes().into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn half_n_is_the_documented_constant() {
        // n/2 for secp256r1
        let expected =
            hex::decode("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8").unwrap();
        assert_eq!(half_n().to_vec(), expected);
    }

    #[test]
    fn normalize_low_s_folds_only_high_values() {
        let r = [1u8; 32];
        let low = half_n();
        assert_eq!(normalize_low_s(r, low), (r, low), "s == n/2 is already low");

        let mut high = N;
        high[31] -= 1; // n - 1, definitely high
        let (_, folded) = normalize_low_s(r, high);
        assert_eq!(folded[31], 1, "n - (n-1) == 1");
        assert!(!is_high_s(&folded));
        // folding twice returns to the original
        let (_, back) = normalize_low_s(r, folded);
        assert_eq!(back, folded, "already-low s is untouched");
    }
}

/// The CNG key name this device's approval key is created under. Stable: changing it would
/// orphan the TPM key and silently enrol a second one.
pub const DEVICE_KEY_NAME: &str = "Z-BACS approval key";

/// Windows' half of [`crate::setup::SignerFactory`]: Hello for the biometric style, a TPM key
/// for the "this device" style (ADR-0006).
///
/// Which one exists is a fact about the machine, not a preference, so `capabilities` asks
/// Windows rather than assuming: a desktop with no camera, no reader and no PIN has no OS
/// authenticator, and the choice screen must not offer one.
pub struct WindowsSignerFactory {
    rp_id: String,
    rp_name: String,
    user_name: String,
    // HWND is a raw pointer, so it is kept as an integer to stay Send + Sync; it is only ever
    // handed back to Windows as the parent window for its own prompt.
    hwnd: isize,
    allow_software_fallback: bool,
}

impl WindowsSignerFactory {
    /// `hwnd` is the Agent's own window, so Windows parents its prompt to it rather than to
    /// whatever happened to be in front.
    pub fn new(rp_id: &str, rp_name: &str, user_name: &str, hwnd: isize) -> Self {
        Self {
            rp_id: rp_id.to_string(),
            rp_name: rp_name.to_string(),
            user_name: user_name.to_string(),
            hwnd,
            allow_software_fallback: true,
        }
    }

    /// Refuse to fall back to the software key storage provider when there is no usable TPM.
    pub fn require_hardware(mut self) -> Self {
        self.allow_software_fallback = false;
        self
    }

    fn window(&self) -> windows::Win32::Foundation::HWND {
        windows::Win32::Foundation::HWND(self.hwnd as *mut core::ffi::c_void)
    }
}

impl crate::setup::SignerFactory for WindowsSignerFactory {
    fn capabilities(&self) -> crate::setup::DeviceCapabilities {
        crate::setup::DeviceCapabilities {
            // WebAuthn API present (Windows 10 1903+). Whether the person has enrolled a face,
            // a fingerprint or a PIN is only known once Hello is asked, and Hello asks them to
            // set one up, so the API's presence is the right gate for showing the option.
            os_authenticator: api_version() > 0,
            hardware_key: true,
            persistent_store: keychain_available(),
        }
    }

    fn create(
        &self,
        style: crate::setup::ApprovalStyle,
        require_os_confirm: bool,
    ) -> Result<crate::setup::CreatedSigner> {
        match style {
            crate::setup::ApprovalStyle::Biometric => {
                let key = WindowsPasskey::create(&self.rp_id, &self.rp_name, &self.user_name, self.window())?;
                let credential = key.credential_id().to_vec();
                Ok(crate::setup::CreatedSigner {
                    provider: std::sync::Arc::new(key),
                    credential: Some(credential),
                    hardware_backed: true,
                })
            }
            crate::setup::ApprovalStyle::ThisDevice => {
                let key = WindowsDeviceKey::open_or_create(
                    DEVICE_KEY_NAME,
                    require_os_confirm,
                    self.allow_software_fallback,
                )?;
                let hardware_backed = key.tpm_backed();
                Ok(crate::setup::CreatedSigner {
                    provider: std::sync::Arc::new(key),
                    credential: Some(DEVICE_KEY_NAME.as_bytes().to_vec()),
                    hardware_backed,
                })
            }
        }
    }

    fn reopen(
        &self,
        profile: &crate::setup::DeviceProfile,
    ) -> Result<std::sync::Arc<dyn crate::provider::AuthProvider>> {
        match profile.style {
            crate::setup::ApprovalStyle::Biometric => {
                let public =
                    profile.public_key.ok_or(AuthError::Malformed("profile has no approval public key"))?;
                Ok(std::sync::Arc::new(WindowsPasskey::from_stored(
                    &self.rp_id,
                    profile.credential.clone(),
                    public,
                    self.window(),
                )))
            }
            crate::setup::ApprovalStyle::ThisDevice => {
                let name = std::str::from_utf8(&profile.credential)
                    .map_err(|_| AuthError::Malformed("profile key name is not text"))?;
                let name = if name.is_empty() { DEVICE_KEY_NAME } else { name };
                Ok(std::sync::Arc::new(WindowsDeviceKey::open_or_create(
                    name,
                    profile.require_os_confirm,
                    self.allow_software_fallback,
                )?))
            }
        }
    }
}

#[cfg(feature = "os-keystore")]
fn keychain_available() -> bool {
    crate::store::OsKeyStore::new().available()
}

/// Without the keychain feature there is nowhere durable to put the device secrets, so setup
/// records [`crate::setup::Pending::VolatileKeyStore`] instead of claiming otherwise.
#[cfg(not(feature = "os-keystore"))]
fn keychain_available() -> bool {
    false
}
