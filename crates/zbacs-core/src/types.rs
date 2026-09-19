//! Fixed-size identifiers used throughout the container format. Each serializes as a CBOR
//! byte string, so the wire format is identical to the PoC's `Vec<u8>` fields, but lengths
//! are now enforced by the type system instead of ad-hoc checks (Z-1.C.1).

use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! fixed_bytes {
    ($(#[$doc:meta])* $name:ident, $len:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(#[serde(with = "serde_bytes_array")] pub [u8; $len]);

        impl $name {
            /// Byte length of this identifier.
            pub const LEN: usize = $len;

            /// Borrow the raw bytes.
            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// Parse from a slice; fails unless exactly [`Self::LEN`] bytes.
            pub fn from_slice(b: &[u8]) -> crate::Result<Self> {
                let arr: [u8; $len] = b.try_into().map_err(|_| crate::Error::KeyLength)?;
                Ok(Self(arr))
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(b: [u8; $len]) -> Self {
                Self(b)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for b in self.0 {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self)
            }
        }
    };
}

fixed_bytes!(
    /// `fid = SHA-256(SHA-256(plaintext) || salt)` — the file's on-chain commitment (spec §2.2,
    /// T13: the chain never sees the plaintext hash itself).
    FileId,
    32
);

fixed_bytes!(
    /// `SHA-256(encoded header)` — chunk AAD, trailer binding and the on-chain `headerHash`.
    HeaderHash,
    32
);

fixed_bytes!(
    /// 16-byte envelope recipient id: `SHA-256(x25519_pk)[..16]` (spec §2.2 `env.kid`).
    KeyId,
    16
);

fixed_bytes!(
    /// Random 16-byte salt mixed into `fid`.
    Salt,
    16
);

fixed_bytes!(
    /// Random 16-byte nonce prefix for this container version; chunk nonce = `np || index`.
    NoncePrefix,
    16
);

/// serde helper: fixed-size arrays as CBOR byte strings.
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

/// serde helper: `Option<[u8; N]>` as an optional CBOR byte string.
pub(crate) mod serde_opt_bytes_array {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer, T: AsRef<[u8]>>(v: &Option<T>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => serde_bytes::Bytes::new(b.as_ref()).serialize(s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T>(d: D) -> Result<Option<T>, D::Error>
    where
        T: for<'a> TryFrom<&'a [u8]>,
    {
        let b: Option<serde_bytes::ByteBuf> = Option::deserialize(d)?;
        match b {
            None => Ok(None),
            Some(b) => T::try_from(b.as_ref())
                .map(Some)
                .map_err(|_| serde::de::Error::custom("bad optional byte string length")),
        }
    }
}

impl TryFrom<&[u8]> for HeaderHash {
    type Error = crate::Error;
    fn try_from(b: &[u8]) -> crate::Result<Self> {
        Self::from_slice(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_debug_and_slice_parsing() {
        let id = FileId([0xab; 32]);
        assert_eq!(id.to_string(), "ab".repeat(32));
        assert_eq!(format!("{id:?}"), format!("FileId({})", "ab".repeat(32)));
        assert_eq!(FileId::from_slice(&[0xab; 32]).unwrap(), id);
        assert!(matches!(FileId::from_slice(&[0; 31]), Err(crate::Error::KeyLength)));
        assert_eq!(KeyId::LEN, 16);
        assert_eq!(id.as_ref(), &[0xab; 32][..]);
    }

    #[test]
    fn cbor_encoding_is_a_byte_string() {
        let mut out = Vec::new();
        ciborium::into_writer(&KeyId([1; 16]), &mut out).unwrap();
        assert_eq!(out[0], 0x50); // major type 2 (bytes), length 16
        let back: KeyId = ciborium::from_reader(out.as_slice()).unwrap();
        assert_eq!(back, KeyId([1; 16]));
        // wrong length is rejected at decode time
        let mut bad = Vec::new();
        ciborium::into_writer(&serde_bytes::Bytes::new(&[1; 15]), &mut bad).unwrap();
        assert!(ciborium::from_reader::<KeyId, _>(bad.as_slice()).is_err());
    }
}
