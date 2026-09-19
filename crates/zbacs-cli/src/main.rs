//! `zbacs` — PoC CLI for the container format (Z-0.C.1). Not the shipping Agent.
//! Keys are stored as a plain JSON file for the PoC only; the Agent uses the OS keychain (Z-1.A.3).

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use zbacs_core::container::{inspect, open, reseal_to_path, seal_to_path, SealOptions};
use zbacs_core::{DeviceKeys, OwnerKeys, Permission, Policy, SigningKeys};

#[derive(Parser)]
#[command(name = "zbacs", version, about = "Z-BACS container PoC")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an owner key file (X25519 sealing + Ed25519 signing). PoC: plaintext JSON.
    Keygen {
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Seal a file into a .zbacs container.
    Seal {
        #[arg(short, long)]
        key: PathBuf,
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = "read-only", value_parser = ["deny", "read-only", "edit"])]
        perm: String,
        #[arg(long, default_value_t = 3600)]
        ttl: u32,
        #[arg(long, default_value_t = 1)]
        max_opens: u16,
        #[arg(long, default_value = "poc:owner")]
        account: String,
        /// Extra recipient X25519 public keys (hex) to embed envelopes for.
        #[arg(long)]
        recipient: Vec<String>,
    },
    /// Open a container using the sealing key in the key file.
    Open {
        #[arg(short, long)]
        key: PathBuf,
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Reseal an edited plaintext as the next version of an existing container (new DEK,
    /// ver + 1, atomic replace) — what the Agent does when an Edit session saves.
    Reseal {
        #[arg(short, long)]
        key: PathBuf,
        /// Edited plaintext to seal as the new version.
        #[arg(short, long)]
        input: PathBuf,
        /// Container to replace in place.
        #[arg(short, long)]
        container: PathBuf,
        #[arg(long, default_value = "read-only", value_parser = ["deny", "read-only", "edit"])]
        perm: String,
        #[arg(long, default_value_t = 3600)]
        ttl: u32,
        #[arg(long, default_value_t = 1)]
        max_opens: u16,
    },
    /// Print header metadata (no key needed).
    Inspect { input: PathBuf },
}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    x25519_sk: String,
    x25519_pk: String,
    ed25519_sk: String,
    ed25519_pk: String,
}

fn parse_perm(p: &str) -> Result<Permission> {
    Ok(match p {
        "deny" => Permission::Deny,
        "edit" => Permission::Edit,
        "read-only" => Permission::ReadOnly,
        other => bail!("unknown permission {other}"),
    })
}

fn load_owner(p: &Path) -> Result<OwnerKeys> {
    let kf: KeyFile = serde_json::from_slice(&fs::read(p).with_context(|| format!("read {}", p.display()))?)?;
    Ok(OwnerKeys {
        sealing: DeviceKeys::from_secret(&hex::decode(kf.x25519_sk)?)?,
        signing: SigningKeys::from_secret(&hex::decode(kf.ed25519_sk)?)?,
    })
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen { out } => {
            let k = OwnerKeys::generate()?;
            let kf = KeyFile {
                x25519_sk: hex::encode(k.sealing.secret_key()),
                x25519_pk: hex::encode(k.sealing.public_key()),
                ed25519_sk: hex::encode(k.signing.secret_bytes()),
                ed25519_pk: hex::encode(k.signing.verifying_key().to_bytes()),
            };
            fs::write(&out, serde_json::to_vec_pretty(&kf)?)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&out, fs::Permissions::from_mode(0o600))?;
            }
            println!("wrote {}\nx25519_pk={}\ned25519_pk={}", out.display(), kf.x25519_pk, kf.ed25519_pk);
        }
        Cmd::Seal { key, input, output, perm, ttl, max_opens, account, recipient } => {
            let owner = load_owner(&key)?;
            let name = input.file_name().and_then(|s| s.to_str()).context("input file name")?;
            let output = output.unwrap_or_else(|| PathBuf::from(format!("{}.zbacs", input.display())));
            let recips: Vec<Vec<u8>> =
                recipient.iter().map(hex::decode).collect::<std::result::Result<_, _>>()?;
            let recips_ref: Vec<&[u8]> = recips.iter().map(|v| v.as_slice()).collect();
            let mut opts = SealOptions::new(account.as_bytes(), name);
            opts.policy =
                Policy { default: parse_perm(&perm)?, ttl, max: max_opens, pin: true, strict: false };
            opts.extra_recipients = &recips_ref;
            let hdr = seal_to_path(&input, &output, &owner, &opts)?;
            println!(
                "sealed {} -> {}\nfid={}\nversion={} plen={} envelopes={}",
                input.display(),
                output.display(),
                hex::encode(hdr.body.fid),
                hdr.body.ver,
                hdr.body.plen,
                hdr.body.env.len()
            );
        }
        Cmd::Open { key, input, output } => {
            let owner = load_owner(&key)?;
            let data = fs::read(&input)?;
            let mut plain = Vec::new();
            let opened = open(Cursor::new(&data), &mut plain, &owner.sealing)?;
            let output = output.unwrap_or_else(|| input.with_file_name(&opened.file_name));
            if output.exists() {
                bail!("refusing to overwrite {}", output.display());
            }
            fs::write(&output, &plain)?;
            println!(
                "opened -> {} ({} bytes, policy={:?})",
                output.display(),
                plain.len(),
                opened.header.body.pol.default
            );
        }
        Cmd::Reseal { key, input, container, perm, ttl, max_opens } => {
            let owner = load_owner(&key)?;
            let policy =
                Policy { default: parse_perm(&perm)?, ttl, max: max_opens, pin: true, strict: false };
            let hdr = reseal_to_path(&input, &container, &owner, policy)?;
            println!(
                "resealed {} -> version {} (prev={}) fid={} plen={}",
                container.display(),
                hdr.body.ver,
                hdr.body.prev.map(|h| h.to_string()).unwrap_or_else(|| "-".into()),
                hdr.body.fid,
                hdr.body.plen
            );
        }
        Cmd::Inspect { input } => {
            let data = fs::read(&input)?;
            let (h, hh) = inspect(Cursor::new(&data))?;
            println!("header_hash={}\nfid={}\nversion={} prev={}\nowner_account={}\npolicy={:?}\nchunk={} plen={} envelopes={}\nsigner={}",
                hex::encode(hh), hex::encode(h.body.fid), h.body.ver,
                h.body.prev.as_ref().map(hex::encode).unwrap_or_else(|| "-".into()),
                String::from_utf8_lossy(&h.body.own), h.body.pol, h.body.chunk, h.body.plen, h.body.env.len(),
                hex::encode(&h.sigk));
            for e in &h.body.env {
                println!("  env kid={} alg={}", hex::encode(e.kid), e.alg);
            }
        }
    }
    Ok(())
}
