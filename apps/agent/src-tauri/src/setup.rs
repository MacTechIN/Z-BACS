//! Z-1.G.2 — first run, wired into the Agent.
//!
//! The whole of setup is two taps: "시작하기", then one of the two approval styles. Everything
//! else — the device's envelope key, the owner's sealing and signing keys, the approval signer
//! in this machine's hardware — happens behind the progress indicator and is never named.
//!
//! This module deliberately returns *machine values* to the webview (`"biometric"`,
//! `"account_on_chain"`), not sentences. Every word the person reads lives in `ui/`, where the
//! terminology lint (`tools/ux-lint.sh`) can see all of it at once.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};
use zbacs_auth::setup::{ApprovalStyle, DeviceCapabilities, Pending, Prepared, Setup, SignerFactory};
use zbacs_auth::store::{KeyStore, MemoryKeyStore};

/// Relying-party id for the platform passkey. A constant, because the person never types one.
pub const RP_ID: &str = "zbacs.local";
/// What Windows shows in its own Hello dialog.
pub const RP_NAME: &str = "Z-BACS";

/// The Agent's identity on this machine, once setup has run.
#[derive(Default)]
pub struct Identity(pub Mutex<Option<Prepared>>);

/// One button on the choice screen. The UI supplies the words for `id`.
#[derive(Debug, Clone, Serialize)]
pub struct Choice {
    /// `"biometric"` or `"this_device"`.
    pub id: &'static str,
    /// Whether this machine can actually do it.
    pub available: bool,
    /// Whether the key would live in this machine's hardware.
    pub hardware_backed: bool,
}

/// What the UI needs to decide which screen to show.
#[derive(Debug, Clone, Serialize)]
pub struct SetupStatus {
    /// Setup has already run on this machine.
    pub onboarded: bool,
    /// Setup can run at all (false on a build with no signer compiled in).
    pub can_set_up: bool,
    /// Why not, as a machine value the UI turns into a sentence.
    pub blocked: Option<&'static str>,
    /// The two styles and whether each is possible here.
    pub choices: Vec<Choice>,
    /// Which one the screen should preselect.
    pub recommended: Option<&'static str>,
    /// What is still outstanding after setup, as machine values.
    pub pending: Vec<&'static str>,
    /// Which style is in use, once setup has run.
    pub style: Option<&'static str>,
}

/// The style the webview picked, as a machine value.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StyleArg {
    /// "얼굴이나 지문으로 확인하고 승인"
    Biometric,
    /// "이 기기에서 바로 승인"
    ThisDevice,
}

impl From<StyleArg> for ApprovalStyle {
    fn from(a: StyleArg) -> Self {
        match a {
            StyleArg::Biometric => ApprovalStyle::Biometric,
            StyleArg::ThisDevice => ApprovalStyle::ThisDevice,
        }
    }
}

fn style_id(style: ApprovalStyle) -> &'static str {
    match style {
        ApprovalStyle::Biometric => "biometric",
        ApprovalStyle::ThisDevice => "this_device",
    }
}

fn pending_id(p: Pending) -> &'static str {
    match p {
        Pending::AccountOnChain => "account_on_chain",
        Pending::DeviceEnrolment => "device_enrolment",
        Pending::RecoveryCode => "recovery_code",
        Pending::VolatileKeyStore => "volatile_key_store",
        Pending::SoftwareSigner => "software_signer",
    }
}

/// Everything setup needs, assembled once at startup.
pub struct SetupHost {
    setup: Option<Setup>,
    /// Why there is no setup, when there is none.
    blocked: Option<&'static str>,
}

impl SetupHost {
    /// Build the host for this machine: the durable key store if there is one, and whichever
    /// signer factory this build actually has.
    pub fn new(config_dir: PathBuf) -> Self {
        let (store, persistent) = key_store();
        Self::with_store(config_dir, store, persistent)
    }

    /// Same, with the key store supplied — a test needs one store to outlive two hosts the way
    /// a real keychain outlives two runs.
    pub fn with_store(config_dir: PathBuf, store: Arc<dyn KeyStore>, persistent: bool) -> Self {
        match signer_factory(store.clone(), persistent) {
            Some(factory) => {
                let path = config_dir.join(zbacs_auth::setup::PROFILE_FILE);
                Self { setup: Some(Setup::new(store, factory, path)), blocked: None }
            }
            None => Self { setup: None, blocked: Some("no_signer") },
        }
    }

    /// The owner's sealing and signing keys, for locking a file (Z-1.G.3).
    pub fn owner_keys(&self) -> Result<zbacs_core::OwnerKeys, zbacs_auth::AuthError> {
        self.setup
            .as_ref()
            .ok_or_else(|| zbacs_auth::AuthError::Hardware("this build has no signer".into()))?
            .owner_keys()
    }

    /// Finish setup with the chosen style. For tests and for the command path.
    pub fn complete(&self, style: ApprovalStyle, now: u64) -> Result<Prepared, zbacs_auth::AuthError> {
        self.setup
            .as_ref()
            .ok_or_else(|| zbacs_auth::AuthError::Hardware("this build has no signer".into()))?
            .complete(style, now)
    }

    /// Resume an earlier setup, if this machine has one.
    pub fn resume(&self) -> Option<Prepared> {
        let setup = self.setup.as_ref()?;
        match setup.resume() {
            Ok(prepared) => prepared,
            Err(e) => {
                // Not fatal: the person can set up again. Saying nothing would be worse.
                log::warn!("cannot resume setup: {e}");
                None
            }
        }
    }

    fn status(&self, prepared: Option<&Prepared>) -> SetupStatus {
        let Some(setup) = self.setup.as_ref() else {
            return SetupStatus {
                onboarded: false,
                can_set_up: false,
                blocked: self.blocked,
                choices: Vec::new(),
                recommended: None,
                pending: Vec::new(),
                style: None,
            };
        };
        let caps = setup.capabilities();
        SetupStatus {
            onboarded: prepared.is_some(),
            can_set_up: true,
            blocked: None,
            choices: vec![
                Choice {
                    id: "biometric",
                    available: caps.offers(ApprovalStyle::Biometric),
                    hardware_backed: caps.os_authenticator,
                },
                Choice {
                    id: "this_device",
                    available: caps.offers(ApprovalStyle::ThisDevice),
                    hardware_backed: caps.hardware_key,
                },
            ],
            recommended: Some(style_id(caps.recommended())),
            pending: prepared.map(|p| p.pending.iter().map(|p| pending_id(*p)).collect()).unwrap_or_default(),
            style: prepared.map(|p| style_id(p.profile.style)),
        }
    }
}

/// The OS keychain when it works, and an in-memory store when it does not, so a headless box
/// still runs. The difference is reported, never hidden: see [`Pending::VolatileKeyStore`].
fn key_store() -> (Arc<dyn KeyStore>, bool) {
    #[cfg(feature = "os-keystore")]
    {
        let os = zbacs_auth::store::OsKeyStore::new();
        if os.available() {
            return (Arc::new(os), true);
        }
        log::warn!("no OS keychain on this machine; secrets will not survive a restart");
    }
    (Arc::new(MemoryKeyStore::new()), false)
}

#[cfg(windows)]
fn signer_factory(_store: Arc<dyn KeyStore>, persistent: bool) -> Option<Arc<dyn SignerFactory>> {
    let _ = persistent;
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "Z-BACS".to_string());
    // hwnd 0 lets Windows pick the foreground window; the approval UI (Z-1.G.10) passes the
    // Agent's own window so the prompt is parented correctly.
    Some(Arc::new(zbacs_auth::windows::WindowsSignerFactory::new(RP_ID, RP_NAME, &user, 0)))
}

#[cfg(all(not(windows), feature = "demo-signer"))]
fn signer_factory(store: Arc<dyn KeyStore>, persistent: bool) -> Option<Arc<dyn SignerFactory>> {
    // A developer box with no TPM. The keys are ordinary process memory, which setup reports as
    // `software_signer`, and the UI says so rather than implying hardware protection.
    let caps =
        DeviceCapabilities { os_authenticator: true, hardware_key: false, persistent_store: persistent };
    Some(Arc::new(zbacs_auth::software::SoftwareSignerFactory::new(store, RP_ID).with_capabilities(caps)))
}

#[cfg(all(not(windows), not(feature = "demo-signer")))]
fn signer_factory(_store: Arc<dyn KeyStore>, _persistent: bool) -> Option<Arc<dyn SignerFactory>> {
    let _ = DeviceCapabilities::default();
    None
}

// ------------------------------------------------------------------ commands

/// Which screen to show, and what the choice screen should offer.
#[tauri::command]
pub fn setup_status(host: State<'_, SetupHost>, identity: State<'_, Identity>) -> SetupStatus {
    let held = identity.0.lock().expect("identity mutex");
    host.status(held.as_ref())
}

/// Finish setup with the chosen style. Runs off the UI thread because a real signer shows an
/// OS prompt and blocks until the person answers it.
#[tauri::command]
pub async fn complete_setup(app: AppHandle, style: StyleArg) -> Result<SetupStatus, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let host = app.state::<SetupHost>();
        let setup = host.setup.as_ref().ok_or_else(|| "no_signer".to_string())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();

        let prepared = setup.complete(style.into(), now).map_err(|e| {
            log::warn!("setup failed: {e}");
            error_id(&e).to_string()
        })?;
        log::info!(
            "setup complete: style={} signer={:?} hardware={} pending={:?}",
            style_id(prepared.profile.style),
            prepared.profile.signer,
            prepared.profile.hardware_backed,
            prepared.pending
        );

        let status = host.status(Some(&prepared));
        *app.state::<Identity>().0.lock().expect("identity mutex") = Some(prepared);
        Ok(status)
    })
    .await
    .map_err(|e| format!("join: {e}"))?
}

/// Map a failure to a value the UI turns into a sentence with an action (ux_principles rule 6).
fn error_id(e: &zbacs_auth::AuthError) -> &'static str {
    match e {
        zbacs_auth::AuthError::Cancelled => "cancelled",
        zbacs_auth::AuthError::Unsupported(_) => "unsupported",
        zbacs_auth::AuthError::ConfirmationUnavailable(_, _) => "unsupported",
        _ => "failed",
    }
}

/// Load an existing setup at startup, so a returning person never sees the first-run screens.
pub fn restore(app: &AppHandle) {
    let host = app.state::<SetupHost>();
    if let Some(prepared) = host.resume() {
        log::info!(
            "resumed setup: style={} pending={:?}",
            style_id(prepared.profile.style),
            prepared.pending
        );
        *app.state::<Identity>().0.lock().expect("identity mutex") = Some(prepared);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zbacs-agent-setup-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_ui_is_told_which_screen_to_show() {
        let dir = temp_dir("status");
        let host = SetupHost::new(dir.clone());
        let status = host.status(None);

        if status.can_set_up {
            assert!(!status.onboarded, "a fresh machine has not been set up");
            assert_eq!(status.choices.len(), 2, "exactly the two ADR-0006 styles");
            assert!(status.recommended.is_some(), "one is preselected so the screen is one tap");
            assert!(status.choices.iter().any(|c| c.id == "this_device" && c.available));
        } else {
            assert_eq!(status.blocked, Some("no_signer"));
            assert!(status.choices.is_empty(), "no buttons that cannot work");
        }
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn style_and_pending_values_are_stable_strings() {
        // The UI keys its Korean sentences on these; renaming one silently blanks a screen.
        assert_eq!(style_id(ApprovalStyle::Biometric), "biometric");
        assert_eq!(style_id(ApprovalStyle::ThisDevice), "this_device");
        assert_eq!(pending_id(Pending::AccountOnChain), "account_on_chain");
        assert_eq!(pending_id(Pending::DeviceEnrolment), "device_enrolment");
        assert_eq!(pending_id(Pending::RecoveryCode), "recovery_code");
        assert_eq!(pending_id(Pending::VolatileKeyStore), "volatile_key_store");
        assert_eq!(pending_id(Pending::SoftwareSigner), "software_signer");
    }

    #[test]
    fn a_cancelled_prompt_is_not_reported_as_a_failure() {
        assert_eq!(error_id(&zbacs_auth::AuthError::Cancelled), "cancelled");
        assert_eq!(
            error_id(&zbacs_auth::AuthError::Unsupported(zbacs_auth::SignerKind::PlatformPasskey)),
            "unsupported"
        );
        assert_eq!(error_id(&zbacs_auth::AuthError::InvalidSignature), "failed");
    }

    #[cfg(feature = "demo-signer")]
    #[test]
    fn setup_runs_end_to_end_and_a_later_run_resumes_it() {
        let dir = temp_dir("e2e");
        // One store for both hosts: a real keychain outlives a restart, and that is the
        // property under test.
        let store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
        let host = SetupHost::with_store(dir.clone(), store.clone(), true);
        assert!(host.resume().is_none(), "nothing to resume yet");

        let setup = host.setup.as_ref().expect("demo signer is compiled in");
        let prepared = setup.complete(ApprovalStyle::ThisDevice, 1_758_000_000).unwrap();
        let status = host.status(Some(&prepared));
        assert!(status.onboarded);
        assert_eq!(status.style, Some("this_device"));
        assert!(status.pending.contains(&"account_on_chain"), "{:?}", status.pending);
        assert!(!status.pending.contains(&"volatile_key_store"), "this store persists");

        let again = SetupHost::with_store(dir.clone(), store, true).resume().expect("a later run finds it");
        assert_eq!(again.profile.key_id, prepared.profile.key_id);
        std::fs::remove_dir_all(dir).ok();
    }
}
