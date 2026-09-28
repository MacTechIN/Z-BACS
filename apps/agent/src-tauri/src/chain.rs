//! Z-1.H.8 b — the Agent's link to the chain.
//!
//! Everything the Agent writes to the chain goes through `zbacs_chain::ChainWriter`
//! (ADR-0008): `register` when a file is locked, `grant` when the owner allows, `bumpVersion`
//! when a recipient's version is accepted, `revoke`. Reads (`isValid`, `nonces`, events) go
//! through the plain client. Which writer this machine has is decided once, from the
//! environment the installer or a developer set — never by the person (ux_principles §2):
//!
//! | `ZBACS_CHAIN_RPC` | `ZBACS_CHAIN_KEY` | `ZBACS_BUNDLER_URL` | mode |
//! |---|---|---|---|
//! | unset | — | — | no chain: writes are skipped and reported as `chain_*` pending |
//! | set | set | — | **direct**: a funded key sends transactions (Anvil, self-hosted) |
//! | set | — | set | **smart account**: the owner's Kernel account, paid by a paymaster |
//! | set | — | — | read-only: verify grants and merge events, write nothing |
//!
//! The owner's address is fixed at first run and written into the device profile
//! ([`crate::setup`]); from then on every container carries it and the relay routes by it.
//!
//! The chain is also the second channel for the record (Z-1.G.12): [`ChainLink::merge_events`]
//! reads `Granted` / `Revoked` / `VersionBumped` for this machine's files and appends them as
//! [`crate::audit::Source::Chain`] entries, so the screen shows what the public record confirms
//! and not only what this machine believes it did.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tauri::{AppHandle, Manager};
use zbacs_auth::setup::DeviceProfile;
use zbacs_auth::{
    ApprovalAssertion, ApprovalChallenge, ApprovalContext, AuthProvider, Confirmation, ConfirmationPolicy,
    SignerKind,
};
use zbacs_chain::aa::{p256_raw_signature, webauthn_signature};
use zbacs_chain::Provider;
use zbacs_chain::{
    Address, ChainClient, ChainEvent, ChainWriter, Deployment, DirectWriter, EventWatcher, JsonRpcBundler,
    KernelAccount, RootValidator, SmartAccountWriter, UserOpSigner, Write,
};
use zbacs_core::Permission;

use crate::audit::{AuditLog, Kind, Role};
use crate::ledger::Ledger;

/// Node URL. Unset means "no chain on this machine".
pub const RPC_ENV: &str = "ZBACS_CHAIN_RPC";
/// Path to `deployments/<chainId>.json` (Z-1.H.4). Defaults to the Anvil file beside a checkout.
pub const DEPLOYMENT_ENV: &str = "ZBACS_CHAIN_DEPLOYMENT";
/// Developer path: a funded private key, hex. Never set on a person's machine.
pub const KEY_ENV: &str = "ZBACS_CHAIN_KEY";
/// Production path: the bundler (with paymaster) URL, Z-1.H.9.
pub const BUNDLER_ENV: &str = "ZBACS_BUNDLER_URL";
/// How often the record picks up chain events while the Agent runs.
pub const MERGE_INTERVAL: Duration = Duration::from_secs(15);

/// How this machine writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// A funded key sends transactions.
    Direct,
    /// The owner's smart account sends user operations.
    SmartAccount,
    /// Reads only.
    ReadOnly,
}

impl Mode {
    /// Machine value for the developer panel.
    pub fn word(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::SmartAccount => "smart_account",
            Self::ReadOnly => "read_only",
        }
    }
}

/// What the environment asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvConfig {
    /// Node URL.
    pub rpc: String,
    /// Deployment file.
    pub deployment_path: String,
    /// Developer key, hex.
    pub key: Option<String>,
    /// Bundler URL.
    pub bundler: Option<String>,
}

impl EnvConfig {
    /// Read the environment. `None` when no chain is configured.
    pub fn from_env() -> Option<Self> {
        let rpc = std::env::var(RPC_ENV).ok().filter(|s| !s.trim().is_empty())?;
        let deployment_path =
            std::env::var(DEPLOYMENT_ENV).ok().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| {
                concat!(env!("CARGO_MANIFEST_DIR"), "/../../../contracts/deployments/31337.json").into()
            });
        Some(Self {
            rpc: rpc.trim().to_string(),
            deployment_path,
            key: std::env::var(KEY_ENV).ok().filter(|s| !s.trim().is_empty()),
            bundler: std::env::var(BUNDLER_ENV).ok().filter(|s| !s.trim().is_empty()),
        })
    }
}

/// How the writer is built.
pub enum WriterSetup {
    /// Reads only.
    None,
    /// A funded key, hex.
    Key(String),
    /// The owner's smart account.
    Account {
        /// Bundler URL.
        bundler_url: String,
        /// The account's root validator (this device's approval key).
        root: RootValidator,
        /// Signs user operations with that key.
        signer: Arc<dyn UserOpSigner>,
    },
}

/// One connected chain.
pub struct ChainLink {
    reader: ChainClient,
    writer: Option<Arc<dyn ChainWriter>>,
    deployment: Deployment,
    chain_id: u64,
    mode: Mode,
}

impl ChainLink {
    /// Connect. The chain id comes from the node, so a signature can never be bound to the
    /// wrong chain by a stale constant (T03).
    pub async fn connect(rpc: &str, deployment: Deployment, setup: WriterSetup) -> Result<Self, String> {
        let reader = ChainClient::connect(rpc, deployment).await.map_err(|e| e.to_string())?;
        let chain_id = reader.provider().get_chain_id().await.map_err(|e| format!("chain id: {e}"))?;
        let (writer, mode): (Option<Arc<dyn ChainWriter>>, Mode) = match setup {
            WriterSetup::None => (None, Mode::ReadOnly),
            WriterSetup::Key(key) => {
                let direct = DirectWriter::connect(rpc, deployment, &key).await.map_err(|e| e.to_string())?;
                (Some(Arc::new(direct)), Mode::Direct)
            }
            WriterSetup::Account { bundler_url, root, signer } => {
                let bundler = JsonRpcBundler::new(&bundler_url, true).map_err(|e| e.to_string())?;
                let writer = SmartAccountWriter::new(
                    KernelAccount::new(root),
                    reader.provider().clone(),
                    Arc::new(bundler),
                    signer,
                    deployment,
                    chain_id,
                );
                (Some(Arc::new(writer)), Mode::SmartAccount)
            }
        };
        Ok(Self { reader, writer, deployment, chain_id, mode })
    }

    /// Reads.
    pub fn reader(&self) -> &ChainClient {
        &self.reader
    }

    /// Writes, when this machine can.
    pub fn writer(&self) -> Option<&dyn ChainWriter> {
        self.writer.as_deref()
    }

    /// How this machine writes.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The owner's address on chain, when this machine writes.
    pub fn owner(&self) -> Option<[u8; 20]> {
        self.writer.as_ref().map(|w| w.owner().into_array())
    }

    /// Contract addresses.
    pub fn deployment(&self) -> Deployment {
        self.deployment
    }

    /// EIP-155 chain id.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// What the approval digest is bound to (T03).
    pub fn approval_deployment(&self) -> crate::approve::Deployment {
        crate::approve::Deployment { chain_id: self.chain_id, policy: self.deployment.policy.into_array() }
    }

    /// Z-1.G.12: append what the chain says about this machine's files since the last look.
    /// Returns how many entries were added. The cursor lives in the ledger, so a restart
    /// neither repeats nor skips a block.
    pub async fn merge_events(&self, ledger: &Ledger, audit: &AuditLog) -> Result<usize, String> {
        let from = match ledger.chain_cursor() {
            Some(next) => next,
            // First look: from now on. Scanning a public chain from block 0 would take the
            // rest of the day; this machine's own writes all lie ahead of its first start.
            None => self.reader.block_number().await.map_err(|e| e.to_string())?,
        };
        let mut watcher = EventWatcher::new(
            self.reader.provider().clone(),
            self.deployment.policy,
            self.deployment.registry,
            from,
        );
        let events = watcher.poll().await.map_err(|e| e.to_string())?;
        let mut added = 0;
        for event in events {
            let (fid, kind, detail) = match event {
                ChainEvent::Granted { file_id, permission, .. } => (
                    file_id,
                    Kind::Granted,
                    Some(if permission == 2 { "edit" } else { "read_only" }.to_string()),
                ),
                ChainEvent::Revoked { file_id, .. } => (file_id, Kind::Revoked, None),
                ChainEvent::VersionBumped { file_id, version, .. } => {
                    (file_id, Kind::Sealed, Some(format!("v{version}")))
                }
            };
            // Only this machine's files: the contracts are shared by everyone, the record is
            // this person's.
            let Some(entry) = ledger.find(&fid) else { continue };
            audit.record_from_chain(kind, Role::Owner, &fid, Some(&entry.name), detail.as_deref());
            added += 1;
        }
        ledger.set_chain_cursor(watcher.next_block()).map_err(|e| e.to_string())?;
        Ok(added)
    }
}

/// The root validator of this owner's smart account, from the device profile: our
/// `P256Validator` for a device key, Kernel's WebAuthn validator for a platform passkey.
pub fn root_validator_for(profile: &DeviceProfile, p256_validator: Option<Address>) -> Option<RootValidator> {
    let key = profile.public_key.as_ref()?;
    match profile.signer {
        SignerKind::DeviceKey => Some(RootValidator::DeviceKey {
            validator: p256_validator?,
            x: key.x,
            y: key.y,
            require_os_confirm: profile.require_os_confirm,
        }),
        SignerKind::PlatformPasskey => {
            Some(RootValidator::WebAuthn { x: key.x, y: key.y, credential_id: profile.credential.clone() })
        }
        _ => None,
    }
}

/// Signs user operations with this device's approval key, applying the confirmation policy
/// to the one signature an approval now has (ADR-0008, T23).
pub struct DeviceUserOpSigner {
    /// The device's approval signer.
    pub signer: Arc<dyn AuthProvider>,
    /// What the owner chose at setup.
    pub device_setting: Confirmation,
    /// The T23 policy.
    pub policy: ConfirmationPolicy,
    /// Recent approvals, for the burst rule.
    pub recent: Mutex<Vec<u64>>,
}

impl DeviceUserOpSigner {
    /// Wrap a signer with the default policy.
    pub fn new(signer: Arc<dyn AuthProvider>, device_setting: Confirmation) -> Self {
        Self { signer, device_setting, policy: ConfirmationPolicy::default(), recent: Mutex::new(Vec::new()) }
    }

    fn encode(&self, assertion: ApprovalAssertion) -> Result<zbacs_chain::Bytes, zbacs_chain::ChainError> {
        match assertion {
            ApprovalAssertion::P256Raw { key_id, r, s } => Ok(p256_raw_signature(key_id.0, r, s)),
            ApprovalAssertion::WebAuthn { authenticator_data, client_data_json, r, s } => {
                Ok(webauthn_signature(&authenticator_data, &client_data_json, r, s, true))
            }
            other => Err(zbacs_chain::ChainError::Config(format!(
                "a {:?} assertion cannot authorise a user operation",
                other.kind()
            ))),
        }
    }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl UserOpSigner for DeviceUserOpSigner {
    fn sign_user_op(
        &self,
        hash: zbacs_chain::B256,
        about: Write,
    ) -> Result<zbacs_chain::Bytes, zbacs_chain::ChainError> {
        let now = now();
        let (permission, confirmation) = match about {
            // The approval itself: the person tapped, the policy decides whether the OS asks
            // them again (Edit, or a burst).
            Write::Grant { permission, .. } => {
                let permission = if permission == 2 { Permission::Edit } else { Permission::ReadOnly };
                let recent = self.recent.lock().expect("recent mutex").clone();
                let context = ApprovalContext { permission, file_id: about.file_id() };
                (permission, self.policy.required(&context, self.device_setting, &recent, now))
            }
            // Explicit taps too, never stronger than the device setting.
            Write::Register { .. } | Write::Revoke { .. } => (Permission::ReadOnly, self.device_setting),
            // Not a tap at all (a recipient saved): nothing may pop up (ADR-0008 §5).
            Write::BumpVersion { .. } => (Permission::ReadOnly, Confirmation::NotRequired),
        };
        let challenge = ApprovalChallenge {
            digest: hash.0,
            context: ApprovalContext { permission, file_id: about.file_id() },
        };
        let assertion = self
            .signer
            .sign(&challenge, confirmation)
            .map_err(|e| zbacs_chain::ChainError::Config(format!("approval signature: {e}")))?;
        if matches!(about, Write::Grant { .. }) {
            self.recent.lock().expect("recent mutex").push(now);
        }
        self.encode(assertion)
    }

    fn stub_signature(&self) -> zbacs_chain::Bytes {
        match self.signer.kind() {
            SignerKind::PlatformPasskey => webauthn_signature(
                &[0u8; 37],
                "{\"type\":\"webauthn.get\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"origin\":\"https://zbacs.local\"}",
                [1u8; 32],
                [1u8; 32],
                true,
            ),
            _ => p256_raw_signature([0xAA; 32], [0xAA; 32], [0xAA; 32]),
        }
    }
}

// ------------------------------------------------------------------ Agent state

/// The link, once connected.
#[derive(Default)]
pub struct Chain(pub Mutex<Option<Arc<ChainLink>>>);

/// The link this Agent has, if any.
pub fn current(app: &AppHandle) -> Option<Arc<ChainLink>> {
    app.try_state::<Chain>().and_then(|c| c.0.lock().expect("chain mutex").clone())
}

/// Connect from the environment, once. Called after setup is restored or completed, because
/// the smart-account path needs this device's approval key. Harmless to call again.
pub fn ensure(app: &AppHandle) {
    let Some(config) = EnvConfig::from_env() else {
        return;
    };
    if current(app).is_some() {
        return;
    }
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let deployment = match Deployment::from_file(&config.deployment_path) {
            Ok(d) => d,
            Err(e) => {
                log::warn!("chain configured but the deployment file is unusable: {e}");
                return;
            }
        };
        let setup = writer_setup(&handle, &config, deployment);
        let link = match ChainLink::connect(&config.rpc, deployment, setup).await {
            Ok(link) => Arc::new(link),
            Err(e) => {
                log::warn!("cannot reach the chain at {}: {e}", config.rpc);
                return;
            }
        };
        log::info!("chain linked: id={} mode={}", link.chain_id(), link.mode().word());
        if let Some(owner) = link.owner() {
            adopt_owner(&handle, owner);
        }
        *handle.state::<Chain>().0.lock().expect("chain mutex") = Some(link.clone());

        // Z-1.G.12: the public record flows into the screen's record while the Agent runs.
        loop {
            {
                let ledger = handle.state::<Ledger>();
                let audit = handle.state::<AuditLog>();
                match link.merge_events(&ledger, &audit).await {
                    Ok(n) if n > 0 => log::info!(
                        "record: {n} entr{} confirmed by the chain",
                        if n == 1 { "y" } else { "ies" }
                    ),
                    Ok(_) => {}
                    Err(e) => log::warn!("cannot read chain events now: {e}"),
                }
            }
            tokio::time::sleep(MERGE_INTERVAL).await;
        }
    });
}

fn writer_setup(app: &AppHandle, config: &EnvConfig, deployment: Deployment) -> WriterSetup {
    if let Some(key) = &config.key {
        return WriterSetup::Key(key.clone());
    }
    let Some(bundler_url) = &config.bundler else {
        return WriterSetup::None;
    };
    let identity = app.state::<crate::setup::Identity>();
    let held = identity.0.lock().expect("identity mutex");
    let Some(prepared) = held.as_ref() else {
        log::info!("bundler configured; the owner account waits for setup to finish");
        return WriterSetup::None;
    };
    match root_validator_for(&prepared.profile, deployment.p256_validator) {
        Some(root) => WriterSetup::Account {
            bundler_url: bundler_url.clone(),
            root,
            signer: Arc::new(DeviceUserOpSigner::new(
                prepared.signer.clone(),
                prepared.profile.style.device_confirmation(),
            )),
        },
        None => {
            log::warn!("this device's signer cannot be a smart-account validator; reads only");
            WriterSetup::None
        }
    }
}

/// Write the owner's address into the profile (ADR-0008 §4) and the in-memory identity.
fn adopt_owner(app: &AppHandle, owner: [u8; 20]) {
    let host = app.state::<crate::setup::SetupHost>();
    match host.adopt_account(owner) {
        Ok(pending) => {
            let identity = app.state::<crate::setup::Identity>();
            let mut held = identity.0.lock().expect("identity mutex");
            if let Some(prepared) = held.as_mut() {
                prepared.profile.account = Some(owner);
                prepared.pending = pending;
            }
        }
        Err(e) => log::warn!("cannot record the owner account on this device: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_have_stable_words() {
        assert_eq!(Mode::Direct.word(), "direct");
        assert_eq!(Mode::SmartAccount.word(), "smart_account");
        assert_eq!(Mode::ReadOnly.word(), "read_only");
    }

    /// The root validator follows the approval style: a device key needs our validator's
    /// address, a passkey uses Kernel's, anything else cannot own an account.
    #[test]
    fn the_root_validator_follows_the_signer_kind() {
        let key = zbacs_auth::P256PublicKey { x: [1; 32], y: [2; 32] };
        let mut profile = DeviceProfile {
            schema: zbacs_auth::setup::PROFILE_SCHEMA,
            style: zbacs_auth::setup::ApprovalStyle::ThisDevice,
            signer: SignerKind::DeviceKey,
            key_id: key.key_id(),
            public_key: Some(key),
            credential: vec![7, 7],
            require_os_confirm: false,
            hardware_backed: true,
            device_x25519_pub: [0; 32],
            device_ed25519_pub: [0; 32],
            owner_sealing_pub: [0; 32],
            owner_signing_pub: [0; 32],
            account: None,
            enrolled_on_chain: false,
            created_at: 0,
        };
        let validator = Address::repeat_byte(0x11);
        assert!(matches!(
            root_validator_for(&profile, Some(validator)),
            Some(RootValidator::DeviceKey { validator: v, x, .. }) if v == validator && x == [1; 32]
        ));
        assert!(root_validator_for(&profile, None).is_none(), "no validator deployed, no account");

        profile.signer = SignerKind::PlatformPasskey;
        assert!(matches!(
            root_validator_for(&profile, None),
            Some(RootValidator::WebAuthn { credential_id, .. }) if credential_id == vec![7, 7]
        ));

        profile.signer = SignerKind::Bsa;
        assert!(root_validator_for(&profile, None).is_none());
    }
}
