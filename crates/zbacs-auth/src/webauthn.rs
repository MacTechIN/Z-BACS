//! WebAuthn assertion parsing and P-256 verification (both signer paths).
//!
//! Verification here mirrors what the on-chain validators do, so the Agent can reject a bad
//! assertion locally before spending a UserOperation, and so tests can cross-check vectors
//! produced by the JavaScript spike (`spikes/aa-passkey`).

use base64::Engine;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::error::{AuthError, Result};
use crate::types::{ApprovalAssertion, P256PublicKey};

/// Flags byte of WebAuthn authenticator data (spec: WebAuthn L3 §6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatorFlags(pub u8);

impl AuthenticatorFlags {
    /// User present.
    pub fn up(self) -> bool {
        self.0 & 0x01 != 0
    }
    /// User verified (biometric / PIN).
    pub fn uv(self) -> bool {
        self.0 & 0x04 != 0
    }
    /// Backup eligible — the credential can be synced to other devices.
    pub fn be(self) -> bool {
        self.0 & 0x08 != 0
    }
    /// Backed up — the credential *is* synced (T22).
    pub fn bs(self) -> bool {
        self.0 & 0x10 != 0
    }
    /// True when the passkey lives in a cloud keychain rather than only in this device.
    pub fn is_synced(self) -> bool {
        self.be() || self.bs()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatorData {
    pub rp_id_hash: [u8; 32],
    pub flags: AuthenticatorFlags,
    pub sign_count: u32,
}

impl AuthenticatorData {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 37 {
            return Err(AuthError::Malformed("authenticator data shorter than 37 bytes"));
        }
        let mut rp_id_hash = [0u8; 32];
        rp_id_hash.copy_from_slice(&bytes[..32]);
        let sign_count = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);
        Ok(Self { rp_id_hash, flags: AuthenticatorFlags(bytes[32]), sign_count })
    }
}

/// `sha256(authenticator_data || sha256(client_data_json))` — what the authenticator signed.
pub fn webauthn_signed_digest(authenticator_data: &[u8], client_data_json: &str) -> [u8; 32] {
    let cd_hash = Sha256::digest(client_data_json.as_bytes());
    let mut h = Sha256::new();
    h.update(authenticator_data);
    h.update(cd_hash);
    h.finalize().into()
}

/// Extract and base64url-decode `challenge` from client data JSON.
pub fn client_data_challenge(client_data_json: &str) -> Result<Vec<u8>> {
    let v: serde_json::Value = serde_json::from_str(client_data_json)
        .map_err(|_| AuthError::Malformed("client data is not JSON"))?;
    if v.get("type").and_then(|t| t.as_str()) != Some("webauthn.get") {
        return Err(AuthError::Malformed("client data type is not webauthn.get"));
    }
    let c = v
        .get("challenge")
        .and_then(|c| c.as_str())
        .ok_or(AuthError::Malformed("client data has no challenge"))?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(c)
        .map_err(|_| AuthError::Malformed("challenge is not base64url"))
}

/// Verify an assertion against the registered key and the expected challenge digest.
///
/// Enforces low-s (`HighS`), user presence + verification for WebAuthn
/// (`UserVerificationMissing`), and that the WebAuthn client data carries `challenge`
/// (`ChallengeMismatch`). BSA/OTAK assertions are verified elsewhere and are rejected here.
pub fn verify_assertion(
    key: &P256PublicKey,
    challenge: &[u8; 32],
    assertion: &ApprovalAssertion,
) -> Result<()> {
    match assertion {
        ApprovalAssertion::WebAuthn { authenticator_data, client_data_json, r, s } => {
            let ad = AuthenticatorData::parse(authenticator_data)?;
            if !(ad.flags.up() && ad.flags.uv()) {
                return Err(AuthError::UserVerificationMissing);
            }
            if client_data_challenge(client_data_json)? != challenge {
                return Err(AuthError::ChallengeMismatch);
            }
            let digest = webauthn_signed_digest(authenticator_data, client_data_json);
            verify_p256(key, &digest, r, s)
        }
        ApprovalAssertion::P256Raw { key_id, r, s } => {
            if *key_id != key.key_id() {
                return Err(AuthError::InvalidSignature);
            }
            verify_p256(key, challenge, r, s)
        }
        ApprovalAssertion::Bsa { .. } | ApprovalAssertion::Otak { .. } => {
            Err(AuthError::Malformed("BSA/OTAK assertions are not P-256; verify through their provider"))
        }
    }
}

/// Raw ECDSA P-256 verification over a prehashed 32-byte digest, low-s enforced.
pub fn verify_p256(key: &P256PublicKey, digest: &[u8; 32], r: &[u8; 32], s: &[u8; 32]) -> Result<()> {
    let vk = VerifyingKey::from_sec1_bytes(&key.to_sec1())
        .map_err(|_| AuthError::Malformed("public key not on curve"))?;
    let sig = Signature::from_scalars(*r, *s).map_err(|_| AuthError::Malformed("r/s out of range"))?;
    if sig.normalize_s().is_some() {
        return Err(AuthError::HighS);
    }
    vk.verify_prehash(digest, &sig).map_err(|_| AuthError::InvalidSignature)
}
