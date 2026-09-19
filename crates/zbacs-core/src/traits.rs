//! `Sealer` / `Opener` — the two capabilities the Agent composes (architecture §3.1).
//!
//! Both traits are object-safe so the Agent can hold `Box<dyn Opener>` chosen at runtime:
//! the owner opens through their self-envelope, a recipient through a granted DEK.

use std::io::{Read, Seek, Write};

use crate::container::{open, open_with_dek, read_header, seal, Opened, SealOptions};
use crate::error::Result;
use crate::header::Header;
use crate::keys::{Dek, DeviceKeys, OwnerKeys};

/// A readable, seekable input (sealing needs two passes over the plaintext).
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek + ?Sized> ReadSeek for T {}

/// Produces `.zbacs` containers.
pub trait Sealer {
    /// Seal `input` into `out` under `opts`. Returns the signed header.
    fn seal(&self, input: &mut dyn ReadSeek, out: &mut dyn Write, opts: &SealOptions) -> Result<Header>;
}

/// Decrypts `.zbacs` containers it holds a key for.
pub trait Opener {
    /// Decrypt `input` into `out`, verifying header, every chunk and the trailer.
    fn open(&self, input: &mut dyn Read, out: &mut dyn Write) -> Result<Opened>;
}

impl Sealer for OwnerKeys {
    fn seal(&self, input: &mut dyn ReadSeek, out: &mut dyn Write, opts: &SealOptions) -> Result<Header> {
        seal(input, out, self, opts)
    }
}

/// Opens through an envelope embedded in the container (the owner's self-envelope, or an
/// extra recipient listed at seal time).
impl Opener for DeviceKeys {
    fn open(&self, input: &mut dyn Read, out: &mut dyn Write) -> Result<Opened> {
        open(input, out, self)
    }
}

/// A DEK received out-of-band in a `GrantMsg` envelope (spec §1.3). Opens exactly one
/// container: the one whose `fid` the grant was issued for.
pub struct GrantedDek {
    dek: Dek,
}

impl GrantedDek {
    /// Wrap a DEK unwrapped from a grant envelope.
    pub fn new(dek: Dek) -> Self {
        Self { dek }
    }
}

impl Opener for GrantedDek {
    fn open(&self, input: &mut dyn Read, out: &mut dyn Write) -> Result<Opened> {
        let (hdr, hh, r) = read_header(input)?;
        open_with_dek(hdr, hh, r, out, &self.dek)
    }
}
