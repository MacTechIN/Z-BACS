//! Data types shared by every signer path (spec `approval_protocol.md` §1.2, §1.5).

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::fmt;
use zbacs_core::Permission;

use crate::error::{AuthError, Result};

/// Which kind of signer produced (or will produce) an assertion. ADR-0003 + ADR-0006.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerKind {
    /// OS authenticator (Windows Hello / Touch ID / Android biometrics) — WebAuthn assertion.
    PlatformPasskey,
    /// Non-exportable P-256 key in the device's hardware store — raw P-256 signature.
    DeviceKey,
    /// BSA SDK adapter (ADR-0003). Verified through the BSA callback, not on chain.
    Bsa,
    /// X.1284-style one-time authentication key (fallback / demo).
    Otak,
}

/// Uncompressed P-256 public key coordinates.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct P256PublicKey {
    #[serde(with = "serde_bytes_array")]
    pub x: [u8; 32],
    #[serde(with = "serde_bytes_array")]
    pub y: [u8; 32],
}

impl P256PublicKey {
    /// `keyId = keccak256(x || y)` — the identifier the on-chain `P256Validator` and the
    /// Kernel WebAuthn validator both key their registrations on (spec §1.5).
    pub fn key_id(&self) -> KeyId {
        let mut h = Keccak256::new();
        h.update(self.x);
        h.update(self.y);
        KeyId(h.finalize().into())
    }

    /// SEC1 uncompressed encoding `0x04 || x || y`.
    pub fn to_sec1(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0] = 0x04;
        out[1..33].copy_from_slice(&self.x);
        out[33..].copy_from_slice(&self.y);
        out
    }

    pub fn from_sec1(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 65 || bytes[0] != 0x04 {
            return Err(AuthError::Malformed("public key is not SEC1 uncompressed"));
        }
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&bytes[1..33]);
        y.copy_from_slice(&bytes[33..]);
        Ok(Self { x, y })
    }
}

impl fmt::Debug for P256PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "P256PublicKey({})", self.key_id())
    }
}

/// 32-byte signer identifier (`keccak256(x || y)`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(#[serde(with = "serde_bytes_array")] pub [u8; 32]);

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({self})")
    }
}

/// What the owner is approving. Drives the confirmation policy (T23), never shown raw in UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalContext {
    pub permission: Permission,
    #[serde(with = "serde_bytes_array")]
    pub file_id: [u8; 32],
}

/// The 32-byte digest an owner signer must sign: the EIP-712 `AccessGrant` digest, or the
/// ERC-4337 UserOperation hash when the approval is submitted through the smart account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApprovalChallenge {
    pub digest: [u8; 32],
    pub context: ApprovalContext,
}

/// Whether the OS must verify the person before the key is used (spec §1.5 policy, T23).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confirmation {
    /// A tap in the Agent UI is enough (DeviceKey on a device the owner marked as trusted).
    NotRequired,
    /// Biometric / PIN prompt through the OS authenticator.
    OsUserVerification,
}

/// A signature over an [`ApprovalChallenge`], in the form the on-chain account verifies.
/// Mirrors `OwnerSig` in spec §1.5.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApprovalAssertion {
    /// WebAuthn assertion (PlatformPasskey). Signed digest =
    /// `sha256(authenticator_data || sha256(client_data_json))`.
    WebAuthn {
        #[serde(with = "serde_bytes")]
        authenticator_data: Vec<u8>,
        client_data_json: String,
        #[serde(with = "serde_bytes_array")]
        r: [u8; 32],
        #[serde(with = "serde_bytes_array")]
        s: [u8; 32],
    },
    /// Raw P-256 ECDSA over the challenge digest (DeviceKey).
    P256Raw {
        key_id: KeyId,
        #[serde(with = "serde_bytes_array")]
        r: [u8; 32],
        #[serde(with = "serde_bytes_array")]
        s: [u8; 32],
    },
    /// Opaque BSA SDK token; verified by the BSA callback path (Z-1.A.5).
    Bsa {
        #[serde(with = "serde_bytes")]
        token: Vec<u8>,
    },
    /// One-time authentication key MAC (Z-1.A.6).
    Otak {
        key_id: KeyId,
        #[serde(with = "serde_bytes_array")]
        mac: [u8; 32],
    },
}

impl ApprovalAssertion {
    pub fn kind(&self) -> SignerKind {
        match self {
            Self::WebAuthn { .. } => SignerKind::PlatformPasskey,
            Self::P256Raw { .. } => SignerKind::DeviceKey,
            Self::Bsa { .. } => SignerKind::Bsa,
            Self::Otak { .. } => SignerKind::Otak,
        }
    }
}

impl fmt::Debug for ApprovalAssertion {
    // Signatures are public data, but keep logs short and free of the client data blob.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WebAuthn { authenticator_data, .. } => {
                write!(f, "WebAuthn(authenticator_data={} bytes)", authenticator_data.len())
            }
            Self::P256Raw { key_id, .. } => write!(f, "P256Raw(key_id={key_id})"),
            Self::Bsa { token } => write!(f, "Bsa(token={} bytes)", token.len()),
            Self::Otak { key_id, .. } => write!(f, "Otak(key_id={key_id})"),
        }
    }
}

/// Registers a new signer on the owner's account. Signed by an already-registered signer;
/// the first device is enrolled during onboarding (spec §1.5, ADR-0006).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEnroll {
    #[serde(with = "serde_bytes_array")]
    pub account: [u8; 20],
    pub public_key: P256PublicKey,
    pub kind: SignerKind,
    pub require_os_confirm: bool,
    pub ts: u64,
}

/// Removes a signer. Signed by a *different* registered signer (T12, T22).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRevoke {
    #[serde(with = "serde_bytes_array")]
    pub account: [u8; 20],
    pub key_id: KeyId,
    pub ts: u64,
}

impl DeviceEnroll {
    pub fn key_id(&self) -> KeyId {
        self.public_key.key_id()
    }

    /// `keccak256(ENROLL_DOMAIN || CBOR(self))` — the digest an existing signer signs.
    pub fn digest(&self) -> Result<[u8; 32]> {
        domain_digest(crate::ENROLL_DOMAIN, self)
    }
}

impl DeviceRevoke {
    pub fn digest(&self) -> Result<[u8; 32]> {
        domain_digest(crate::REVOKE_DOMAIN, self)
    }
}

fn domain_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<[u8; 32]> {
    let mut cbor = Vec::new();
    ciborium::into_writer(value, &mut cbor).map_err(|e| AuthError::Encode(e.to_string()))?;
    let mut h = Keccak256::new();
    h.update(domain);
    h.update(&cbor);
    Ok(h.finalize().into())
}

/// serde helper: fixed-size byte arrays as CBOR byte strings (not integer arrays).
pub(crate) mod serde_bytes_array {
    use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(v).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(d: D) -> Result<[u8; N], D::Error> {
        let b = serde_bytes::ByteBuf::deserialize(d)?;
        <[u8; N]>::try_from(b.into_vec())
            .map_err(|v| D::Error::custom(format!("expected {N} bytes, got {}", v.len())))
    }
}
