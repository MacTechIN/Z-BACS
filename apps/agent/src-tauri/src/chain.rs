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
//! A release build carries these values (Z-1.H.11: `ZBACS_BUILD_*` at build time, see
//! `build.rs`), together with the deployment file and the paymaster policy (Z-1.H.9); a runtime
//! variable still overrides an embedded one. The bundler may be a comma-separated list, tried in
//! order (T21).
//!
//! The owner's address is fixed at first run and written into the device profile
//! ([`crate::setup`]); from then on every container carries it and the relay routes by it.
//!
//! **Deferred writes** (ADR-0008 §5): a `bumpVersion` happens when a recipient saved — not a
//! tap. A device key signs it silently; a platform passkey would put a Hello prompt on the
//! screen out of nowhere, so on such a device it is queued in the ledger and batched into the
//! next user operation the person does authorise ([`ChainLink::write`]).
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
    Address, Call, ChainClient, ChainEvent, ChainWriter, Deployment, DirectWriter, EventWatcher, Failover,
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
/// Production path: the bundler (with paymaster) URL(s), comma-separated, Z-1.H.9.
pub const BUNDLER_ENV: &str = "ZBACS_BUNDLER_URL";
/// Pimlico sponsorship policy id, when the paymaster wants one (Z-1.H.9).
pub const PAYMASTER_POLICY_ENV: &str = "ZBACS_PAYMASTER_POLICY";

/// What the build embedded (Z-1.H.11), if anything.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Embedded {
    /// Node URL.
    pub rpc: Option<&'static str>,
    /// The deployment file's contents.
    pub deployment_json: Option<&'static str>,
    /// Bundler URL(s).
    pub bundler: Option<&'static str>,
    /// Paymaster policy id.
    pub paymaster_policy: Option<&'static str>,
}

impl Embedded {
    /// This binary's values.
    pub const BUILD: Embedded = Embedded {
        rpc: option_env!("ZBACS_EMBEDDED_CHAIN_RPC"),
        deployment_json: option_env!("ZBACS_EMBEDDED_DEPLOYMENT_JSON"),
        bundler: option_env!("ZBACS_EMBEDDED_BUNDLER_URL"),
        paymaster_policy: option_env!("ZBACS_EMBEDDED_PAYMASTER_POLICY"),
    };
}

/// Where the contract addresses come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeploymentSource {
    /// A `deployments/<chainId>.json` on disk.
    Path(String),
    /// The file's contents, embedded at build time.
    Json(String),
}

impl DeploymentSource {
    /// Parse.
    pub fn load(&self) -> Result<Deployment, String> {
        match self {
            Self::Path(p) => Deployment::from_file(p),
            Self::Json(j) => Deployment::from_json(j),
        }
        .map_err(|e| e.to_string())
    }
}
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

/// What the environment (and the build) asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvConfig {
    /// Node URL.
    pub rpc: String,
    /// Contract addresses.
    pub deployment: DeploymentSource,
    /// Developer key, hex.
    pub key: Option<String>,
    /// Bundler URL(s), comma-separated.
    pub bundler: Option<String>,
    /// Paymaster policy id.
    pub paymaster_policy: Option<String>,
}

impl EnvConfig {
    /// Read the environment over what the build embedded. `None` when no chain is configured.
    pub fn from_env() -> Option<Self> {
        Self::resolve(|name| std::env::var(name).ok(), Embedded::BUILD)
    }

    /// Runtime variables win, then the embedded values, then the checkout's Anvil deployment
    /// file. Separate from the environment so the precedence can be tested.
    pub fn resolve(env: impl Fn(&str) -> Option<String>, embedded: Embedded) -> Option<Self> {
        let get = |name: &str| env(name).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let rpc = get(RPC_ENV).or_else(|| embedded.rpc.map(str::to_string))?;
        let deployment = match get(DEPLOYMENT_ENV) {
            Some(path) => DeploymentSource::Path(path),
            None => match embedded.deployment_json {
                Some(json) => DeploymentSource::Json(json.to_string()),
                None => DeploymentSource::Path(
                    concat!(env!("CARGO_MANIFEST_DIR"), "/../../../contracts/deployments/31337.json").into(),
                ),
            },
        };
        Some(Self {
            rpc,
            deployment,
            // A funded key is never embedded: it would ship in every installer.
            key: get(KEY_ENV),
            bundler: get(BUNDLER_ENV).or_else(|| embedded.bundler.map(str::to_string)),
            paymaster_policy: get(PAYMASTER_POLICY_ENV)
                .or_else(|| embedded.paymaster_policy.map(str::to_string)),
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
        /// Bundler URL(s), comma-separated, tried in order (T21).
        bundler_urls: String,
        /// Paymaster sponsorship policy id, if the paymaster wants one.
        paymaster_policy: Option<String>,
        /// The account's root validator (this device's approval key).
        root: RootValidator,
        /// Signs user operations with that key.
        signer: Arc<dyn UserOpSigner>,
        /// Whether every signature shows the person a prompt (a platform passkey does), so
        /// silent writes must wait for the next tap (ADR-0008 §5).
        prompts_always: bool,
    },
}

/// One connected chain.
pub struct ChainLink {
    reader: ChainClient,
    writer: Option<Arc<dyn ChainWriter>>,
    deployment: Deployment,
    chain_id: u64,
    mode: Mode,
    defers_silent_writes: bool,
}

impl ChainLink {
    /// Connect. The chain id comes from the node, so a signature can never be bound to the
    /// wrong chain by a stale constant (T03).
    pub async fn connect(rpc: &str, deployment: Deployment, setup: WriterSetup) -> Result<Self, String> {
        let reader = ChainClient::connect(rpc, deployment).await.map_err(|e| e.to_string())?;
        let chain_id = reader.provider().get_chain_id().await.map_err(|e| format!("chain id: {e}"))?;
        let mut defers = false;
        let (writer, mode): (Option<Arc<dyn ChainWriter>>, Mode) = match setup {
            WriterSetup::None => (None, Mode::ReadOnly),
            WriterSetup::Key(key) => {
                let direct = DirectWriter::connect(rpc, deployment, &key).await.map_err(|e| e.to_string())?;
                (Some(Arc::new(direct)), Mode::Direct)
            }
            WriterSetup::Account { bundler_urls, paymaster_policy, root, signer, prompts_always } => {
                let context = paymaster_policy.map(|id| serde_json::json!({ "sponsorshipPolicyId": id }));
                let bundler = Failover::from_urls(&bundler_urls, true, context).map_err(|e| e.to_string())?;
                let writer = SmartAccountWriter::new(
                    KernelAccount::new(root),
                    reader.provider().clone(),
                    Arc::new(bundler),
                    signer,
                    deployment,
                    chain_id,
                );
                defers = prompts_always;
                (Some(Arc::new(writer)), Mode::SmartAccount)
            }
        };
        Ok(Self { reader, writer, deployment, chain_id, mode, defers_silent_writes: defers })
    }

    /// For tests: a link over any writer, reads against `rpc`.
    #[doc(hidden)]
    pub async fn with_writer(
        rpc: &str,
        deployment: Deployment,
        writer: Arc<dyn ChainWriter>,
        mode: Mode,
        defers_silent_writes: bool,
    ) -> Result<Self, String> {
        let reader = ChainClient::connect(rpc, deployment).await.map_err(|e| e.to_string())?;
        Ok(Self { reader, writer: Some(writer), deployment, chain_id: 0, mode, defers_silent_writes })
    }

    /// Whether background writes wait for the next tap on this device (ADR-0008 §5).
    pub fn defers_silent_writes(&self) -> bool {
        self.defers_silent_writes
    }

    /// A write the person asked for, with whatever was waiting for a tap in front of it:
    /// one user operation, one signature (ADR-0008 §5). Queued writes that land are cleared;
    /// if the batch fails they stay queued for the next tap.
    pub async fn write(
        &self,
        ledger: &Ledger,
        call: Call,
        about: Write,
    ) -> Result<[u8; 32], zbacs_chain::ChainError> {
        let writer =
            self.writer.as_ref().ok_or_else(|| zbacs_chain::ChainError::Config("no writer".into()))?;
        let waiting = ledger.deferred_bumps();
        let mut batch: Vec<Call> = waiting
            .iter()
            .filter_map(|(fid, header)| {
                let mut f = [0u8; 32];
                let mut h = [0u8; 32];
                (hex::decode_to_slice(fid, &mut f).is_ok() && hex::decode_to_slice(header, &mut h).is_ok())
                    .then_some(Call::BumpVersion { file_id: f, header_hash: h })
            })
            .collect();
        batch.push(call);
        let tx = writer.submit(&batch, about).await?;
        if !waiting.is_empty() {
            log::info!("{} queued version(s) went out with this tap", waiting.len());
            if let Err(e) = ledger.clear_deferred_bumps(&waiting) {
                log::warn!("cannot clear the queued versions: {e}");
            }
        }
        Ok(tx)
    }

    /// A recipient's accepted version: sent now when this device can do so silently, queued
    /// for the next tap when it cannot (ADR-0008 §5). `Ok(None)` means queued.
    pub async fn bump_version(
        &self,
        ledger: &Ledger,
        file_id: [u8; 32],
        header_hash: [u8; 32],
    ) -> Result<Option<[u8; 32]>, zbacs_chain::ChainError> {
        let writer =
            self.writer.as_ref().ok_or_else(|| zbacs_chain::ChainError::Config("no writer".into()))?;
        if self.defers_silent_writes {
            ledger
                .defer_bump(&hex::encode(file_id), &hex::encode(header_hash))
                .map_err(zbacs_chain::ChainError::Config)?;
            return Ok(None);
        }
        writer.bump_version(file_id, header_hash).await.map(Some)
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
        let deployment = match config.deployment.load() {
            Ok(d) => d,
            Err(e) => {
                log::warn!("chain configured but the deployment is unusable: {e}");
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
    let Some(bundler_urls) = &config.bundler else {
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
            bundler_urls: bundler_urls.clone(),
            paymaster_policy: config.paymaster_policy.clone(),
            root,
            signer: Arc::new(DeviceUserOpSigner::new(
                prepared.signer.clone(),
                prepared.profile.style.device_confirmation(),
            )),
            // A platform passkey always shows Windows Hello; a device key can sign silently.
            prompts_always: prepared.profile.signer == SignerKind::PlatformPasskey,
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

    /// Z-1.H.11: a release carries its values; a developer's variable still wins; the funded
    /// key is never embedded; nothing configured means no chain.
    #[test]
    fn runtime_variables_win_over_embedded_values_and_nothing_means_no_chain() {
        let none = |_: &str| None;
        assert_eq!(EnvConfig::resolve(none, Embedded::default()), None);

        let embedded = Embedded {
            rpc: Some("https://sepolia.base.org"),
            deployment_json: Some("{\"registry\":\"0x1\"}"),
            bundler: Some("https://a.example,https://b.example"),
            paymaster_policy: Some("sp_x"),
        };
        let release = EnvConfig::resolve(none, embedded).unwrap();
        assert_eq!(release.rpc, "https://sepolia.base.org");
        assert_eq!(release.deployment, DeploymentSource::Json("{\"registry\":\"0x1\"}".into()));
        assert_eq!(release.bundler.as_deref(), Some("https://a.example,https://b.example"));
        assert_eq!(release.paymaster_policy.as_deref(), Some("sp_x"));
        assert_eq!(release.key, None, "a funded key never comes from the build");

        let dev = |name: &str| match name {
            RPC_ENV => Some("http://127.0.0.1:8545".to_string()),
            KEY_ENV => Some("0xac09".to_string()),
            DEPLOYMENT_ENV => Some("/tmp/31337.json".to_string()),
            BUNDLER_ENV => Some("  ".to_string()),
            _ => None,
        };
        let local = EnvConfig::resolve(dev, embedded).unwrap();
        assert_eq!(local.rpc, "http://127.0.0.1:8545");
        assert_eq!(local.deployment, DeploymentSource::Path("/tmp/31337.json".into()));
        assert_eq!(local.key.as_deref(), Some("0xac09"));
        assert_eq!(
            local.bundler.as_deref(),
            Some("https://a.example,https://b.example"),
            "blank falls through"
        );

        let rpc_only = |name: &str| (name == RPC_ENV).then(|| "http://x".to_string());
        let plain = EnvConfig::resolve(rpc_only, Embedded::default()).unwrap();
        assert!(
            matches!(plain.deployment, DeploymentSource::Path(ref p) if p.ends_with("contracts/deployments/31337.json"))
        );
    }

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
