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
use crate::keys::{Dek, DeviceKeys, OwnerKeys, SigningKeys};
use crate::types::{FileId, HeaderHash, NoncePrefix, Salt};
use crate::{DEFAULT_CHUNK, MAX_HEADER_LEN};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

const TAG_LEN: usize = 16;
const NAME_INDEX: u64 = u64::MAX;
const MAX_CHUNK: u32 = 16 * 1024 * 1024;
/// Spec §2.2 field limits enforced before any key is used.
const MAX_OWNER_LEN: usize = 64;
/// Padded file-name plaintext is a multiple of this, hiding the name's length (T13).
const NAME_PAD_BLOCK: usize = 64;
const MAX_NAME_LEN: usize = 1024;
/// 2-byte length prefix + name, rounded up to a whole number of pad blocks, + AEAD tag.
const MAX_NAME_CT_LEN: usize = 1088 + TAG_LEN;
const MAX_ENVELOPES: usize = 32;
const MAX_ENVELOPE_FIELD_LEN: usize = 1024;

/// Identity carried from the previous container version when resealing (spec §5).
///
/// `file_id` and `salt` are **stable across versions**: `fid` is the file's identity and the
/// key of the on-chain `FileRegistry` record, so a reseal keeps it and only bumps the header
/// hash. Build one with [`PrevVersion::of`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrevVersion {
    /// `SHA-256` of the previous version's header.
    pub header_hash: HeaderHash,
    /// Previous version number; the new container gets `version + 1`.
    pub version: u32,
    /// File identity, unchanged since version 1.
    pub file_id: FileId,
    /// Salt that version 1 mixed into `file_id`, unchanged since.
    pub salt: Salt,
}

impl PrevVersion {
    /// Read the identity out of the container version being replaced.
    pub fn of(header: &Header, header_hash: HeaderHash) -> Self {
        Self { header_hash, version: header.body.ver, file_id: header.body.fid, salt: header.body.salt }
    }
}

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
    /// For reseal: the previous version's identity (see [`PrevVersion`]).
    pub prev: Option<PrevVersion>,
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

/// `u16 LE length || name || zero padding` rounded up to [`NAME_PAD_BLOCK`] (spec §2.2).
fn pad_name(name: &str) -> Result<Vec<u8>> {
    let bytes = name.as_bytes();
    if bytes.len() > MAX_NAME_LEN {
        return Err(Error::HeaderEncode("file name too long".into()));
    }
    let padded = (2 + bytes.len()).div_ceil(NAME_PAD_BLOCK) * NAME_PAD_BLOCK;
    let mut out = vec![0u8; padded.max(NAME_PAD_BLOCK)];
    out[..2].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
    out[2..2 + bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

/// Inverse of [`pad_name`]. Rejects a wrong length, a non-block size, or non-zero padding —
/// padding bytes are a covert channel otherwise.
fn unpad_name(buf: &[u8]) -> Result<String> {
    if buf.len() < NAME_PAD_BLOCK
        || !buf.len().is_multiple_of(NAME_PAD_BLOCK)
        || buf.len() > MAX_NAME_CT_LEN - TAG_LEN
    {
        return Err(Error::NameAuth);
    }
    let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    if len > MAX_NAME_LEN || 2 + len > buf.len() {
        return Err(Error::NameAuth);
    }
    if buf[2 + len..].iter().any(|&b| b != 0) {
        return Err(Error::NameAuth);
    }
    String::from_utf8(buf[2..2 + len].to_vec()).map_err(|_| Error::NameAuth)
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
    let opub: [u8; 32] = owner.sealing.public_key().try_into().map_err(|_| Error::EnvelopeSeal)?;
    seal_signed(&mut input, out, &opub, &owner.signing, opts)
}

/// The general form of [`seal`]: the owner envelope goes to `owner_pk`, the header is signed
/// by `signer`. The owner uses their own two keys; a recipient resealing (spec §5) uses the
/// owner's public key from the previous header and their own device signing key.
fn seal_signed<R: Read + Seek, W: Write>(
    mut input: R,
    out: W,
    owner_pk: &[u8; 32],
    signer: &SigningKeys,
    opts: &SealOptions,
) -> Result<Header> {
    if opts.chunk_size == 0 || opts.chunk_size as u64 > MAX_CHUNK as u64 {
        return Err(Error::BadChunkSize(opts.chunk_size as u32));
    }
    // pass 1: plaintext hash + length
    let mut hasher = Sha256::new();
    let mut plen: u64 = 0;
    // Staging buffer for plaintext; wiped when it goes out of scope (T11).
    let mut buf = Zeroizing::new(vec![0u8; opts.chunk_size]);
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

    // keys and identity: a fresh DEK and nonce prefix every version (spec §5), while `fid`
    // and `salt` are inherited by a reseal so the on-chain record keeps its key.
    let dek = Dek::generate();
    let mut np = [0u8; 16];
    OsRng.fill_bytes(&mut np);
    let (fid, salt) = match opts.prev {
        Some(p) => (p.file_id, p.salt),
        None => {
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            (
                FileId(Sha256::new().chain_update(plaintext_hash).chain_update(salt).finalize().into()),
                Salt(salt),
            )
        }
    };

    let aead = XChaCha20Poly1305::new(dek.as_bytes().into());
    let name_ct = aead
        .encrypt(&nonce(&np, NAME_INDEX), Payload { msg: &pad_name(opts.file_name)?, aad: b"name" })
        .map_err(|_| Error::EnvelopeSeal)?;

    // envelopes: owner envelope first, AAD = fid
    let mut env = vec![Envelope::seal(owner_pk, &dek, fid.as_bytes())?];
    for pk in opts.extra_recipients {
        env.push(Envelope::seal(pk, &dek, fid.as_bytes())?);
    }

    let (prev, ver) = match opts.prev {
        Some(p) => (
            Some(p.header_hash),
            p.version.checked_add(1).ok_or_else(|| Error::HeaderEncode("version overflow".into()))?,
        ),
        None => (None, 1),
    };
    let header = HeaderBody {
        fid,
        salt,
        ver,
        prev,
        own: opts.owner_account.to_vec(),
        opub: Some(*owner_pk),
        pol: opts.policy.clone(),
        cipher: CIPHER_XCHACHA20_POLY1305_CHUNKED,
        chunk: opts.chunk_size as u32,
        plen,
        np: NoncePrefix(np),
        name: name_ct,
        env,
    }
    .sign(signer)?;
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
    let opub: [u8; 32] = owner.sealing.public_key().try_into().map_err(|_| Error::EnvelopeSeal)?;
    seal_signed_to_path(in_path, out_path, &opub, &owner.signing, opts)
}

fn seal_signed_to_path(
    in_path: &Path,
    out_path: &Path,
    owner_pk: &[u8; 32],
    signer: &SigningKeys,
    opts: &SealOptions,
) -> Result<Header> {
    let input = BufReader::new(File::open(in_path)?);
    let tmp = out_path.with_extension("zbacs.tmp");
    let hdr = {
        let f = File::create(&tmp)?;
        let hdr = seal_signed(input, &f, owner_pk, signer, opts)?;
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
    validate_header(&hdr)?;
    Ok((hdr, hh, r))
}

/// Spec §2.2 field limits and §4 step 1 invariants. Runs after signature verification and
/// before any key material is touched (T18, T19).
fn validate_header(hdr: &Header) -> Result<()> {
    let b = &hdr.body;
    if b.cipher != CIPHER_XCHACHA20_POLY1305_CHUNKED {
        return Err(Error::UnsupportedCipher(b.cipher));
    }
    if b.chunk == 0 || b.chunk > MAX_CHUNK {
        return Err(Error::BadChunkSize(b.chunk));
    }
    let reject = |why: &str| Err(Error::HeaderDecode(why.into()));
    if b.ver == 0 {
        return reject("version must be >= 1");
    }
    if (b.ver == 1) != b.prev.is_none() {
        return reject("version/prev chain mismatch");
    }
    if b.own.is_empty() || b.own.len() > MAX_OWNER_LEN {
        return reject("owner account length");
    }
    if b.name.len() > MAX_NAME_CT_LEN || b.name.len() < NAME_PAD_BLOCK + TAG_LEN {
        return reject("file name field length");
    }
    if b.env.is_empty() || b.env.len() > MAX_ENVELOPES {
        return reject("envelope count");
    }
    if b.env.iter().any(|e| e.enc.len() > MAX_ENVELOPE_FIELD_LEN || e.ct.len() > MAX_ENVELOPE_FIELD_LEN) {
        return reject("envelope field length");
    }
    Ok(())
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
///
/// On error, whatever was already written to `out` must be discarded: chunks are
/// individually authentic, but the file as a whole is not (spec §4 step 5).
pub fn open_with_dek<R: Read, W: Write>(
    hdr: Header,
    header_hash: HeaderHash,
    mut r: R,
    out: W,
    dek: &Dek,
) -> Result<Opened> {
    let file_name = decrypt_name(&hdr, dek)?;
    let aead = XChaCha20Poly1305::new(dek.as_bytes().into());
    let np = hdr.body.np.as_bytes();

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
        let mut pt = aead
            .decrypt(
                &nonce(np, index),
                Payload { msg: &frame[..want], aad: &chunk_aad(&header_hash, index, is_last) },
            )
            .map_err(|_| Error::ChunkAuth(index))?;
        let write = w.write_all(&pt);
        pt.zeroize(); // decrypted plaintext must not linger in freed memory (T11)
        write?;
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

/// Reseal a plaintext as the next version of an existing container, replacing it atomically.
///
/// Spec §5: a fresh DEK and nonce prefix, `ver + 1`, `prev = SHA-256(previous header)`, and the
/// inherited `fid`/`salt`. Because the DEK is new, any DEK handed out with an earlier grant
/// stops working — this is what makes a revoke stick once the recipient saves (T20).
///
/// The new container is written to a temporary file in the same directory and renamed over
/// `container_path`, so a crash leaves the previous version intact.
pub fn reseal_to_path(
    plaintext_path: &Path,
    container_path: &Path,
    owner: &OwnerKeys,
    policy: Policy,
) -> Result<Header> {
    let (prev_header, prev_hash) = inspect(BufReader::new(File::open(container_path)?))?;
    let mut opts = SealOptions::new(&prev_header.body.own, "");
    opts.policy = policy;
    opts.chunk_size = prev_header.body.chunk as usize;
    opts.prev = Some(PrevVersion::of(&prev_header, prev_hash));

    // The file name lives encrypted in the old header; recover it with the owner's envelope so
    // the new version keeps it without the caller having to pass it in.
    let env =
        prev_header.body.env.iter().find(|e| e.kid == owner.sealing.key_id()).ok_or(Error::NoEnvelope)?;
    let prev_dek = env.open(&owner.sealing, prev_header.body.fid.as_bytes())?;
    let name = decrypt_name(&prev_header, &prev_dek)?;
    opts.file_name = &name;

    seal_to_path(plaintext_path, container_path, owner, &opts)
}

/// Reseal by a *recipient* (spec §5, Z-1.G.8): the holder of the current version's DEK — obtained
/// through a grant — writes an edited plaintext as the next version.
///
/// The new owner envelope is wrapped to the owner's public key carried in the previous header
/// (`opub`), so the owner can open the new version without ever seeing this device's keys; the
/// header is signed by `signer`, this device's Ed25519 key, whose public half ends up in
/// `sigk`. Whether the owner *accepts* the version is decided outside the container: the
/// version notice (relay_protocol §4.6) and, on chain, `bumpVersion` (Z-1.H.8).
///
/// Fails with [`Error::NoOwnerKey`] on a v1.0 container.
pub fn reseal_as_recipient_to_path(
    plaintext_path: &Path,
    container_path: &Path,
    prev_dek: &Dek,
    signer: &SigningKeys,
    policy: Policy,
) -> Result<Header> {
    let (prev_header, prev_hash) = inspect(BufReader::new(File::open(container_path)?))?;
    let opub = prev_header.body.opub.ok_or(Error::NoOwnerKey)?;
    let mut opts = SealOptions::new(&prev_header.body.own, "");
    opts.policy = policy;
    opts.chunk_size = prev_header.body.chunk as usize;
    opts.prev = Some(PrevVersion::of(&prev_header, prev_hash));
    let name = decrypt_name(&prev_header, prev_dek)?;
    opts.file_name = &name;
    seal_signed_to_path(plaintext_path, container_path, &opub, signer, &opts)
}

/// Check that `chain` is a well-formed version chain `v1 → v2 → …` (spec §5).
///
/// Each entry is a header and its hash, oldest first. Verifies that versions increase by one,
/// that every `prev` matches the previous header's hash, and that `fid`/`salt` never change —
/// the checks an Agent runs before trusting a container that claims to supersede another (T19).
pub fn verify_version_chain(chain: &[(Header, HeaderHash)]) -> Result<()> {
    let broken = |why: &str| Err(Error::BrokenChain(why.into()));
    let Some(((first, _), rest)) = chain.split_first() else {
        return broken("empty chain");
    };
    if first.body.ver != 1 || first.body.prev.is_some() {
        return broken("chain does not start at version 1");
    }
    let mut prev = first;
    let mut prev_hash = chain[0].1;
    for (hdr, hash) in rest {
        if hdr.body.ver != prev.body.ver + 1 {
            return broken("version numbers are not consecutive");
        }
        if hdr.body.prev != Some(prev_hash) {
            return broken("prev does not match the previous header hash");
        }
        if hdr.body.fid != prev.body.fid || hdr.body.salt != prev.body.salt {
            return broken("file identity changed between versions");
        }
        if hdr.header_hash()? != *hash {
            return broken("header hash does not match the header");
        }
        prev = hdr;
        prev_hash = *hash;
    }
    Ok(())
}

/// Decrypt the file name stored in a header, given its DEK.
pub fn decrypt_name(header: &Header, dek: &Dek) -> Result<String> {
    let aead = XChaCha20Poly1305::new(dek.as_bytes().into());
    let padded = aead
        .decrypt(
            &nonce(header.body.np.as_bytes(), NAME_INDEX),
            Payload { msg: &header.body.name, aad: b"name" },
        )
        .map_err(|_| Error::NameAuth)?;
    let name = unpad_name(&padded);
    let mut padded = padded;
    padded.zeroize();
    name
}

/// Inspect a container without keys: verified header + its hash (file name stays encrypted).
pub fn inspect<R: Read>(input: R) -> Result<(Header, HeaderHash)> {
    let (h, hh, _) = read_header(input)?;
    Ok((h, hh))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_padding_hides_length_and_roundtrips() {
        for name in ["a", "report.docx", &"x".repeat(61), &"x".repeat(62), &"x".repeat(1024)] {
            let padded = pad_name(name).unwrap();
            assert!(padded.len().is_multiple_of(NAME_PAD_BLOCK));
            assert_eq!(unpad_name(&padded).unwrap(), name);
        }
        // short names are indistinguishable by ciphertext length
        assert_eq!(pad_name("a").unwrap().len(), pad_name(&"x".repeat(61)).unwrap().len());
        assert!(pad_name(&"x".repeat(1025)).is_err());
    }

    #[test]
    fn unpad_rejects_malformed_padding() {
        let mut padded = pad_name("doc.txt").unwrap();
        padded[63] = 1; // non-zero padding is a covert channel
        assert!(matches!(unpad_name(&padded), Err(Error::NameAuth)));

        let mut padded = pad_name("doc.txt").unwrap();
        padded[0] = 0xff; // length beyond the buffer
        assert!(matches!(unpad_name(&padded), Err(Error::NameAuth)));

        assert!(matches!(unpad_name(&[0u8; 10]), Err(Error::NameAuth)));
        assert!(matches!(unpad_name(&[0u8; 65]), Err(Error::NameAuth)));

        let mut padded = pad_name("x").unwrap();
        padded[2] = 0xff; // invalid UTF-8
        assert!(matches!(unpad_name(&padded), Err(Error::NameAuth)));
    }
}
