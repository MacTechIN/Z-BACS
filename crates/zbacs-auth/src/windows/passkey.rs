//! Z-1.A.2 — Windows Hello passkey through `webauthn.dll` (ADR-0006 signer path A).
//!
//! Windows owns the whole ceremony: it shows the face/fingerprint/PIN prompt, talks to the TPM
//! and hands back an assertion. We only build the client data, ask for user verification, and
//! turn the DER signature into the `(r, s)` pair the on-chain WebAuthn validator expects.
//!
//! The credential is created once at onboarding (`create`) and used for every approval
//! (`WindowsPasskey::sign`). Its public key goes on chain as an account signer; the private key
//! never leaves the platform authenticator.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use base64::Engine;
use windows::core::PCWSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::Networking::WindowsWebServices::{
    WebAuthNAuthenticatorGetAssertion, WebAuthNAuthenticatorMakeCredential, WebAuthNFreeAssertion,
    WebAuthNGetApiVersionNumber, WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
    WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM, WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_1, WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_1, WEBAUTHN_CLIENT_DATA,
    WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER, WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION, WEBAUTHN_CREDENTIAL, WEBAUTHN_CREDENTIALS,
    WEBAUTHN_CREDENTIAL_CURRENT_VERSION, WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
    WEBAUTHN_HASH_ALGORITHM_SHA_256, WEBAUTHN_RP_ENTITY_INFORMATION,
    WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION, WEBAUTHN_USER_ENTITY_INFORMATION,
    WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION, WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
};
use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

use crate::error::{AuthError, Result};
use crate::provider::AuthProvider;
use crate::types::{ApprovalAssertion, ApprovalChallenge, Confirmation, KeyId, P256PublicKey, SignerKind};

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn hello_err(what: &str, e: windows::core::Error) -> AuthError {
    match e.code().0 as u32 {
        // NTE_USER_CANCELLED / ERROR_CANCELLED — the person closed the Hello prompt
        0x8009_002E | 0x8007_04C7 => AuthError::Cancelled,
        _ => AuthError::Hardware(format!("{what}: {} ({:#010x})", e.message(), e.code().0 as u32)),
    }
}

/// A Windows Hello credential bound to this machine's user.
pub struct WindowsPasskey {
    rp_id: String,
    origin: String,
    credential_id: Vec<u8>,
    public: P256PublicKey,
    hwnd: HWND,
}

unsafe impl Send for WindowsPasskey {}
unsafe impl Sync for WindowsPasskey {}

/// Whether this machine has the WebAuthn API at all (Windows 10 1903+).
pub fn api_version() -> u32 {
    unsafe { WebAuthNGetApiVersionNumber() }
}

/// The window Windows should parent its prompt to. The Agent passes its own HWND; this is the
/// fallback for console tools.
pub fn foreground_window() -> HWND {
    unsafe { GetForegroundWindow() }
}

impl WindowsPasskey {
    /// Create a credential (onboarding). Shows the Hello prompt once.
    ///
    /// `user_name` is what Windows shows in its own UI; Z-BACS never asks the person to type it
    /// (ux_principles: no text fields), so the Agent passes the OS account name.
    pub fn create(rp_id: &str, rp_name: &str, user_name: &str, hwnd: HWND) -> Result<Self> {
        let challenge = {
            // The credential ceremony's challenge is not used for anything on chain: the account
            // is created from the public key. A random one keeps the ceremony well-formed.
            let mut c = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut c);
            c
        };
        let client_data_json = client_data(&challenge, &origin_of(rp_id));
        let w_rp_id = wide(rp_id);
        let w_rp_name = wide(rp_name);
        let w_user = wide(user_name);
        let mut user_id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut user_id);
        let mut cd_bytes = client_data_json.clone().into_bytes();

        unsafe {
            let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
                dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
                pwszId: PCWSTR(w_rp_id.as_ptr()),
                pwszName: PCWSTR(w_rp_name.as_ptr()),
                pwszIcon: PCWSTR::null(),
            };
            let user = WEBAUTHN_USER_ENTITY_INFORMATION {
                dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
                cbId: user_id.len() as u32,
                pbId: user_id.as_mut_ptr(),
                pwszName: PCWSTR(w_user.as_ptr()),
                pwszIcon: PCWSTR::null(),
                pwszDisplayName: PCWSTR(w_user.as_ptr()),
            };
            let mut param = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
                dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
                pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
                lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
            };
            let params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
                cCredentialParameters: 1,
                pCredentialParameters: &mut param,
            };
            let client = WEBAUTHN_CLIENT_DATA {
                dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
                cbClientDataJSON: cd_bytes.len() as u32,
                pbClientDataJSON: cd_bytes.as_mut_ptr(),
                pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
            };
            let options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
                dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_1,
                dwTimeoutMilliseconds: 60_000,
                dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
                dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
                dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
                ..Default::default()
            };

            let attestation =
                WebAuthNAuthenticatorMakeCredential(hwnd, &rp, &user, &params, &client, Some(&options))
                    .map_err(|e| hello_err("create passkey", e))?;
            if attestation.is_null() {
                return Err(AuthError::Hardware("webauthn returned no attestation".into()));
            }
            let a = &*attestation;
            let credential_id =
                std::slice::from_raw_parts(a.pbCredentialId, a.cbCredentialId as usize).to_vec();
            let auth_data = std::slice::from_raw_parts(a.pbAuthenticatorData, a.cbAuthenticatorData as usize);
            let public = public_key_from_authenticator_data(auth_data)?;

            Ok(Self { rp_id: rp_id.to_string(), origin: origin_of(rp_id), credential_id, public, hwnd })
        }
    }

    /// Rebuild from a stored credential id and public key (every run after onboarding).
    pub fn from_stored(rp_id: &str, credential_id: Vec<u8>, public: P256PublicKey, hwnd: HWND) -> Self {
        Self { rp_id: rp_id.to_string(), origin: origin_of(rp_id), credential_id, public, hwnd }
    }

    /// The credential id to persist alongside the public key.
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }
}

fn origin_of(rp_id: &str) -> String {
    format!("https://{rp_id}")
}

fn client_data(challenge: &[u8; 32], origin: &str) -> String {
    format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
        origin
    )
}

/// Pull the COSE public key out of attested credential data (WebAuthn L3 §6.5.1):
/// `rpIdHash(32) | flags(1) | signCount(4) | aaguid(16) | credIdLen(2) | credId | COSE key`.
fn public_key_from_authenticator_data(auth_data: &[u8]) -> Result<P256PublicKey> {
    if auth_data.len() < 55 {
        return Err(AuthError::Malformed("authenticator data has no attested credential"));
    }
    let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let cose_start = 55 + cred_len;
    if auth_data.len() < cose_start {
        return Err(AuthError::Malformed("credential id runs past the buffer"));
    }
    cose_p256_public_key(&auth_data[cose_start..])
}

/// Minimal COSE_Key reader for `EC2 / P-256`: map with -2 => x, -3 => y (RFC 9052).
fn cose_p256_public_key(bytes: &[u8]) -> Result<P256PublicKey> {
    let value: ciborium::Value =
        ciborium::from_reader(bytes).map_err(|_| AuthError::Malformed("COSE key is not valid CBOR"))?;
    let map = value.as_map().ok_or(AuthError::Malformed("COSE key is not a map"))?;
    let mut x = None;
    let mut y = None;
    for (k, v) in map {
        let Some(label) = k.as_integer().and_then(|i| i64::try_from(i).ok()) else { continue };
        match label {
            -2 => x = v.as_bytes().cloned(),
            -3 => y = v.as_bytes().cloned(),
            _ => {}
        }
    }
    let (x, y) = (
        x.ok_or(AuthError::Malformed("COSE key has no x"))?,
        y.ok_or(AuthError::Malformed("COSE key has no y"))?,
    );
    if x.len() != 32 || y.len() != 32 {
        return Err(AuthError::Malformed("COSE key coordinates are not 32 bytes"));
    }
    let mut xa = [0u8; 32];
    let mut ya = [0u8; 32];
    xa.copy_from_slice(&x);
    ya.copy_from_slice(&y);
    Ok(P256PublicKey { x: xa, y: ya })
}

impl AuthProvider for WindowsPasskey {
    fn kind(&self) -> SignerKind {
        SignerKind::PlatformPasskey
    }

    fn key_id(&self) -> KeyId {
        self.public.key_id()
    }

    fn public_key(&self) -> Option<P256PublicKey> {
        Some(self.public)
    }

    fn supports_os_confirmation(&self) -> bool {
        true // Windows always verifies the user for a platform credential
    }

    fn sign(&self, challenge: &ApprovalChallenge, _confirmation: Confirmation) -> Result<ApprovalAssertion> {
        let client_data_json = client_data(&challenge.digest, &self.origin);
        let mut cd_bytes = client_data_json.clone().into_bytes();
        let w_rp_id = wide(&self.rp_id);
        let mut cred_id = self.credential_id.clone();

        unsafe {
            let mut credential = WEBAUTHN_CREDENTIAL {
                dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
                cbId: cred_id.len() as u32,
                pbId: cred_id.as_mut_ptr(),
                pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            };
            let client = WEBAUTHN_CLIENT_DATA {
                dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
                cbClientDataJSON: cd_bytes.len() as u32,
                pbClientDataJSON: cd_bytes.as_mut_ptr(),
                pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
            };
            let options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
                dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_1,
                dwTimeoutMilliseconds: 60_000,
                CredentialList: WEBAUTHN_CREDENTIALS { cCredentials: 1, pCredentials: &mut credential },
                dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
                dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
                ..Default::default()
            };

            let assertion = WebAuthNAuthenticatorGetAssertion(
                self.hwnd,
                PCWSTR(w_rp_id.as_ptr()),
                &client,
                Some(&options),
            )
            .map_err(|e| hello_err("approve with Windows Hello", e))?;
            if assertion.is_null() {
                return Err(AuthError::Hardware("webauthn returned no assertion".into()));
            }
            let a = &*assertion;
            let authenticator_data =
                std::slice::from_raw_parts(a.pbAuthenticatorData, a.cbAuthenticatorData as usize).to_vec();
            let der = std::slice::from_raw_parts(a.pbSignature, a.cbSignature as usize).to_vec();
            WebAuthNFreeAssertion(assertion);

            let (r, s) = crate::windows::der_to_low_s(&der)?;
            Ok(ApprovalAssertion::WebAuthn { authenticator_data, client_data_json, r, s })
        }
    }
}
