//! Seal / open of `.zbacs` containers (spec §2 layout, §3 seal, §4 open).
//!
//! ```text
//! magic(6) major(1) minor(1) | hdr_len u32 LE | header CBOR | chunk frames | trailer
//! trailer = header_hash(32) || total_chunks u64 LE || BLAKE3(all chunk frames)(32)
//! chunk nonce  = np(16) || index u64 LE            (XChaCha20 24-byte nonce)
//! chunk aad    = header_hash(32) || index u64 LE || is_last u8
//! name nonce   = np(16) || 0xFFFF_FFFF_FFFF_FFFF   (reserved; chunk index never reaches it)
//! ```

use crate::envelope::Envelope;
use crate::error::{Error, Result};
use crate::header::{
    Header, HeaderBody, Policy, CIPHER_XCHACHA20_POLY1305_CHUNKED, MAGIC, VERSION_MAJOR, VERSION_MINOR,
};
use crate::keys::{Dek, DeviceKeys, OwnerKeys};
use crate::types::{FileId, HeaderHash, NoncePrefix, Salt};
use crate::{DEFAULT_CHUNK, MAX_HEADER_LEN};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

const TAG_LEN: usize = 16;
const NAME_INDEX: u64 = u64::MAX;
const MAX_CHUNK: u32 = 16 * 1024 * 1024;

/// Parameters for [`seal`]. Build with [`SealOptions::new`] and adjust fields as needed.
pub struct SealOptions<'a> {
    /// Owner policy written into the header.
    pub policy: Policy,
    /// Owner account identifier committed on-chain (chainId || address); opaque here.
    pub owner_account: &'a [u8],
    /// Original file name (stored encrypted).
    pub file_name: &'a str,
    /// Plaintext chunk size; 1..=16 MiB.
    pub chunk_size: usize,
    /// Extra recipients whose envelopes are embedded (normally none: grants travel out-of-band).
    pub extra_recipients: &'a [&'a [u8]],
    /// For reseal: previous header hash and version number (the new version is `prev.1 + 1`).
    pub prev: Option<(HeaderHash, u32)>,
}

impl<'a> SealOptions<'a> {
    /// Defaults: [`Policy::default`], [`DEFAULT_CHUNK`], no extra recipients, version 1.
    pub fn new(owner_account: &'a [u8], file_name: &'a str) -> Self {
        Self {
            policy: Policy::default(),
            owner_account,
            file_name,
            chunk_size: DEFAULT_CHUNK,
            extra_recipients: &[],
            prev: None,
        }
    }
}

fn nonce(np: &[u8], index: u64) -> XNonce {
    let mut n = [0u8; 24];
    n[..16].copy_from_slice(np);
    n[16..].copy_from_slice(&index.to_le_bytes());
    XNonce::from(n)
}

fn chunk_aad(header_hash: &HeaderHash, index: u64, is_last: bool) -> [u8; 41] {
    let mut a = [0u8; 41];
    a[..32].copy_from_slice(header_hash.as_bytes());
    a[32..40].copy_from_slice(&index.to_le_bytes());
    a[40] = is_last as u8;
    a
}

fn chunk_count(plen: u64, chunk: u64) -> u64 {
    if plen == 0 {
        1
    } else {
        plen.div_ceil(chunk)
    }
}

/// Seal `input` (must be seekable: pass 1 hashes, pass 2 encrypts) into `out`.
/// Returns the signed header.
pub fn seal<R: Read + Seek, W: Write>(
    mut input: R,
    out: W,
    owner: &OwnerKeys,
    opts: &SealOptions,
) -> Result<Header> {
    if opts.chunk_size == 0 || opts.chunk_size as u64 > MAX_CHUNK as u64 {
        return Err(Error::BadChunkSize(opts.chunk_size as u32));
    }
    // pass 1: plaintext hash + length
    let mut hasher = Sha256::new();
    let mut plen: u64 = 0;
    let mut buf = vec![0u8; opts.chunk_size];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        plen += n as u64;
    }
    let plaintext_hash: [u8; 32] = hasher.finalize().into();
    input.seek(SeekFrom::Start(0))?;

    // keys, salt, fid
    let dek = Dek::generate();
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut np = [0u8; 16];
    OsRng.fill_bytes(&mut np);
    let fid = FileId(Sha256::new().chain_update(plaintext_hash).chain_update(salt).finalize().into());

    let aead = XChaCha20Poly1305::new(dek.as_bytes().into());
    let name_ct = aead
        .encrypt(&nonce(&np, NAME_INDEX), Payload { msg: opts.file_name.as_bytes(), aad: b"name" })
        .map_err(|_| Error::EnvelopeSeal)?;

    // envelopes: owner self-envelope first, AAD = fid
    let mut env = vec![Envelope::seal(owner.sealing.public_key(), &dek, fid.as_bytes())?];
    for pk in opts.extra_recipients {
        env.push(Envelope::seal(pk, &dek, fid.as_bytes())?);
    }

    let (prev, ver) = match opts.prev {
        Some((h, v)) => (Some(h), v + 1),
        None => (None, 1),
    };
    let header = HeaderBody {
        fid,
        salt: Salt(salt),
        ver,
        prev,
        own: opts.owner_account.to_vec(),
        pol: opts.policy.clone(),
        cipher: CIPHER_XCHACHA20_POLY1305_CHUNKED,
        chunk: opts.chunk_size as u32,
        plen,
        np: NoncePrefix(np),
        name: name_ct,
        env,
    }
    .sign(&owner.signing)?;
    let header_bytes = header.encode()?;
    let header_hash = HeaderHash(Sha256::digest(&header_bytes).into());

    // write
    let mut w = BufWriter::new(out);
    w.write_all(MAGIC)?;
    w.write_all(&[VERSION_MAJOR, VERSION_MINOR])?;
    w.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
    w.write_all(&header_bytes)?;

    let total = chunk_count(plen, opts.chunk_size as u64);
    let mut ct_hash = blake3::Hasher::new();
    let mut index: u64 = 0;
    let mut remaining = plen;
    loop {
        let want = remaining.min(opts.chunk_size as u64) as usize;
        input.read_exact(&mut buf[..want])?;
        let is_last = index + 1 == total;
        let frame = aead
            .encrypt(
                &nonce(&np, index),
                Payload { msg: &buf[..want], aad: &chunk_aad(&header_hash, index, is_last) },
            )
            .map_err(|_| Error::EnvelopeSeal)?;
        ct_hash.update(&frame);
        w.write_all(&frame)?;
        remaining -= want as u64;
        index += 1;
        if is_last {
            break;
        }
    }
    w.write_all(header_hash.as_bytes())?;
    w.write_all(&total.to_le_bytes())?;
    w.write_all(ct_hash.finalize().as_bytes())?;
    w.flush()?;
    Ok(header)
}

/// Seal a file to `out_path` atomically (temp + rename).
pub fn seal_to_path(
    in_path: &Path,
    out_path: &Path,
    owner: &OwnerKeys,
    opts: &SealOptions,
) -> Result<Header> {
    let input = BufReader::new(File::open(in_path)?);
    let tmp = out_path.with_extension("zbacs.tmp");
    let hdr = {
        let f = File::create(&tmp)?;
        let hdr = seal(input, &f, owner, opts)?;
        f.sync_all()?;
        hdr
    };
    std::fs::rename(&tmp, out_path)?;
    Ok(hdr)
}

/// Result of a successful open: the verified header and the decrypted file name.
#[derive(Debug)]
pub struct Opened {
    /// Verified header.
    pub header: Header,
    /// Hash of the header as read (matches the trailer and the on-chain anchor).
    pub header_hash: HeaderHash,
    /// Original file name.
    pub file_name: String,
}

/// Read magic + header only (no key needed). Returns header, hash, and reader positioned at chunk 0.
pub fn read_header<R: Read>(mut r: R) -> Result<(Header, HeaderHash, R)> {
    let mut magic = [0u8; 8];
    r.read_exact(&mut magic).map_err(|_| Error::BadMagic)?;
    if &magic[..6] != MAGIC {
        return Err(Error::BadMagic);
    }
    if magic[6] != VERSION_MAJOR {
        return Err(Error::UnsupportedVersion(magic[6], magic[7]));
    }
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_HEADER_LEN {
        return Err(Error::HeaderTooLarge(len));
    }
    let mut hb = vec![0u8; len];
    r.read_exact(&mut hb).map_err(|_| Error::Truncated)?;
    let (hdr, hh) = Header::decode_verified(&hb)?;
    if hdr.body.cipher != CIPHER_XCHACHA20_POLY1305_CHUNKED {
        return Err(Error::UnsupportedCipher(hdr.body.cipher));
    }
    if hdr.body.chunk == 0 || hdr.body.chunk > MAX_CHUNK {
        return Err(Error::BadChunkSize(hdr.body.chunk));
    }
    Ok((hdr, hh, r))
}

/// Open a container with a DEK obtained from an embedded envelope for `keys`.
/// (Out-of-band grants call [`open_with_dek`] instead.)
pub fn open<R: Read, W: Write>(input: R, out: W, keys: &DeviceKeys) -> Result<Opened> {
    let (hdr, hh, r) = read_header(input)?;
    let kid = keys.key_id();
    let env = hdr.body.env.iter().find(|e| e.kid == kid).ok_or(Error::NoEnvelope)?;
    let dek = env.open(keys, hdr.body.fid.as_bytes())?;
    open_with_dek(hdr, hh, r, out, &dek)
}

/// Decrypt the chunk stream that follows a header returned by [`read_header`], using a DEK
/// obtained out-of-band (grant envelope). Verifies every chunk and the trailer.
pub fn open_with_dek<R: Read, W: Write>(
    hdr: Header,
    header_hash: HeaderHash,
    mut r: R,
    out: W,
    dek: &Dek,
) -> Result<Opened> {
    let aead = XChaCha20Poly1305::new(dek.as_bytes().into());
    let np = hdr.body.np.as_bytes();
    let name = aead
        .decrypt(&nonce(np, NAME_INDEX), Payload { msg: &hdr.body.name, aad: b"name" })
        .map_err(|_| Error::NameAuth)?;
    let file_name = String::from_utf8(name).map_err(|_| Error::NameAuth)?;

    let chunk = hdr.body.chunk as u64;
    let total = chunk_count(hdr.body.plen, chunk);
    let mut w = BufWriter::new(out);
    let mut ct_hash = blake3::Hasher::new();
    let mut frame = vec![0u8; hdr.body.chunk as usize + TAG_LEN];
    let mut remaining = hdr.body.plen;
    for index in 0..total {
        let want = remaining.min(chunk) as usize + TAG_LEN;
        r.read_exact(&mut frame[..want]).map_err(|_| Error::Truncated)?;
        ct_hash.update(&frame[..want]);
        let is_last = index + 1 == total;
        let pt = aead
            .decrypt(
                &nonce(np, index),
                Payload { msg: &frame[..want], aad: &chunk_aad(&header_hash, index, is_last) },
            )
            .map_err(|_| Error::ChunkAuth(index))?;
        w.write_all(&pt)?;
        remaining -= (want - TAG_LEN) as u64;
    }
    // trailer
    let mut tr = [0u8; 72];
    r.read_exact(&mut tr).map_err(|_| Error::Truncated)?;
    let mut extra = [0u8; 1];
    if r.read(&mut extra)? != 0 {
        return Err(Error::Truncated);
    }
    if tr[..32] != header_hash.0
        || u64::from_le_bytes(tr[32..40].try_into().unwrap()) != total
        || tr[40..72] != *ct_hash.finalize().as_bytes()
    {
        return Err(Error::Truncated);
    }
    w.flush()?;
    Ok(Opened { header: hdr, header_hash, file_name })
}

/// Inspect a container without keys: verified header + its hash (file name stays encrypted).
pub fn inspect<R: Read>(input: R) -> Result<(Header, HeaderHash)> {
    let (h, hh, _) = read_header(input)?;
    Ok((h, hh))
}
