//! Z-1.G.2 / Z-1.U.1 / Z-1.U.7 — first run, from the person's side: one tap to start, one tap
//! to choose how approvals happen, and the Agent is ready.
//!
//! Everything the person would otherwise have to understand happens here instead: the device's
//! envelope and relay keys, the owner's sealing and header-signing keys, and the approval
//! signer that ADR-0006 lets them choose between. None of it is shown to them, and none of it
//! is typed in — `docs/ux_principles.md` rules 1 and 2.
//!
//! Two things this module refuses to do:
//!
//! - **Pretend.** What could not be finished comes back as [`Pending`], so the UI can say "이
//!   기기에서 바로 쓸 수 있어요" without implying an account exists on chain before Z-1.H.8
//!   puts one there.
//! - **Choose for the person in a way they cannot see.** [`DeviceCapabilities::recommended`]
//!   preselects, it does not decide; a device that cannot offer a style never shows it.
//!
//! Secrets live in the [`KeyStore`]. The [`DeviceProfile`] written next to the app's config is
//! public data only — public keys, a credential id, what was chosen and when.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use zbacs_core::{DeviceKeys, SigningKeys};
use zeroize::Zeroizing;

use crate::error::{AuthError, Result};
use crate::provider::AuthProvider;
use crate::store::{entry, KeyStore};
use crate::types::{Confirmation, KeyId, P256PublicKey, SignerKind};

/// Profile schema version. Bumped when a field changes meaning; an older file is refused
/// rather than misread.
pub const PROFILE_SCHEMA: u16 = 1;

/// File name of the device profile inside the app's config directory.
pub const PROFILE_FILE: &str = "device.cbor";

/// How the owner wants to approve, in the only two shapes ADR-0006 allows.
///
/// The labels the person sees ("얼굴이나 지문으로 확인하고 승인" / "이 기기에서 바로 승인")
/// live in the UI; this type carries no user-facing text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStyle {
    /// The OS authenticator verifies the person on every approval (Windows Hello, Touch ID).
    Biometric,
    /// A hardware key on this device signs; a tap in the Agent is enough for the ordinary case.
    ThisDevice,
}

impl ApprovalStyle {
    /// The signer path this style is built on.
    pub fn signer_kind(self) -> SignerKind {
        match self {
            Self::Biometric => SignerKind::PlatformPasskey,
            Self::ThisDevice => SignerKind::DeviceKey,
        }
    }

    /// The per-device confirmation setting [`crate::ConfirmationPolicy`] starts from.
    ///
    /// `ThisDevice` starts at [`Confirmation::NotRequired`], which is *not* the same as "never
    /// asks": the policy still escalates an `Edit` grant or a burst of approvals to an OS
    /// prompt (T23).
    pub fn device_confirmation(self) -> Confirmation {
        match self {
            Self::Biometric => Confirmation::OsUserVerification,
            Self::ThisDevice => Confirmation::NotRequired,
        }
    }
}

/// What this machine can actually offer. The choice screen shows only what is true here, so a
/// person can never pick a button that then fails.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCapabilities {
    /// An OS authenticator with biometrics or a PIN is present and usable.
    pub os_authenticator: bool,
    /// A hardware-backed key store (TPM, Secure Enclave, StrongBox) is present.
    pub hardware_key: bool,
    /// Secrets survive a reboot (an OS keychain is reachable).
    pub persistent_store: bool,
}

impl DeviceCapabilities {
    /// Whether the style can be offered on this device.
    pub fn offers(&self, style: ApprovalStyle) -> bool {
        match style {
            ApprovalStyle::Biometric => self.os_authenticator,
            // A device with no hardware store can still hold a key; the person is told it is
            // this machine's key either way, and [`Pending::SoftwareSigner`] records the
            // weaker guarantee.
            ApprovalStyle::ThisDevice => true,
        }
    }

    /// Which style the screen should preselect (ADR-0006: the OS authenticator when there is
    /// one, otherwise this device's own key).
    pub fn recommended(&self) -> ApprovalStyle {
        if self.os_authenticator {
            ApprovalStyle::Biometric
        } else {
            ApprovalStyle::ThisDevice
        }
    }
}

/// A signer that was just created, with the public material needed to reopen it next run.
pub struct CreatedSigner {
    /// The signer itself.
    pub provider: Arc<dyn AuthProvider>,
    /// Public handle the platform needs to find the key again (a WebAuthn credential id, or a
    /// CNG key name). Never a secret.
    pub credential: Option<Vec<u8>>,
    /// Whether the private key really is inside hardware on this device.
    pub hardware_backed: bool,
}

/// Where approval signers come from. The OS sits behind this trait (CLAUDE.md rule 6), so the
/// setup flow is the same on Windows, on a phone and in a test.
pub trait SignerFactory: Send + Sync {
    /// What this device can offer right now.
    fn capabilities(&self) -> DeviceCapabilities;

    /// Create the signer for a first run. May block on an OS prompt.
    fn create(&self, style: ApprovalStyle, require_os_confirm: bool) -> Result<CreatedSigner>;

    /// Reopen the signer an earlier run created, from the profile's public material.
    fn reopen(&self, profile: &DeviceProfile) -> Result<Arc<dyn AuthProvider>>;
}

/// What this device is, in public terms. Written to disk; contains no secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceProfile {
    /// [`PROFILE_SCHEMA`] at the time of writing.
    pub schema: u16,
    /// What the owner chose on the one setup screen.
    pub style: ApprovalStyle,
    /// The signer path that choice maps to.
    pub signer: SignerKind,
    /// `keccak256(x || y)` of the approval key.
    pub key_id: KeyId,
    /// Approval public key, for on-chain registration (Z-1.H.10).
    pub public_key: Option<P256PublicKey>,
    /// Platform handle for reopening the key (credential id / key name). Public data.
    #[serde(with = "serde_bytes")]
    pub credential: Vec<u8>,
    /// Whether the OS must verify the person before this device's key is used.
    pub require_os_confirm: bool,
    /// Whether the approval key lives in this device's hardware.
    pub hardware_backed: bool,
    /// X25519 public key that receives DEK envelopes for this device.
    #[serde(with = "crate::types::serde_bytes_array")]
    pub device_x25519_pub: [u8; 32],
    /// Ed25519 public key that signs this device's relay envelopes.
    #[serde(with = "crate::types::serde_bytes_array")]
    pub device_ed25519_pub: [u8; 32],
    /// Owner's X25519 sealing public key (the self-envelope recipient).
    #[serde(with = "crate::types::serde_bytes_array")]
    pub owner_sealing_pub: [u8; 32],
    /// Owner's Ed25519 header-signing public key.
    #[serde(with = "crate::types::serde_bytes_array")]
    pub owner_signing_pub: [u8; 32],
    /// The owner's smart account, once it exists on chain (Z-1.H.8).
    pub account: Option<[u8; 20]>,
    /// Whether this device's approval key is registered on that account (Z-1.H.10).
    pub enrolled_on_chain: bool,
    /// Unix seconds when setup finished.
    pub created_at: u64,
}

/// Something setup could not finish. The UI turns each one into a sentence with an action;
/// none of them stops the person from using the Agent on this machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pending {
    /// No smart account on chain yet (Z-1.H.8).
    AccountOnChain,
    /// This device's approval key is not registered on the account yet (Z-1.H.10).
    DeviceEnrolment,
    /// No recovery code saved yet (Z-1.A.4; offered later, never during setup).
    RecoveryCode,
    /// Secrets are in memory only — this device would have to set up again next run.
    VolatileKeyStore,
    /// The approval key is not hardware-backed on this device.
    SoftwareSigner,
}

/// The result of a finished (or resumed) setup.
pub struct Prepared {
    /// This device's public record.
    pub profile: DeviceProfile,
    /// The signer that will approve requests.
    pub signer: Arc<dyn AuthProvider>,
    /// What is still outstanding.
    pub pending: Vec<Pending>,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared")
            .field("profile", &self.profile)
            .field("signer", &self.signer.kind())
            .field("pending", &self.pending)
            .finish()
    }
}

/// First-run setup, and the resume path every later run takes.
pub struct Setup {
    store: Arc<dyn KeyStore>,
    factory: Arc<dyn SignerFactory>,
    profile_path: PathBuf,
}

impl Setup {
    /// `profile_path` is normally `<app config dir>/device.cbor`.
    pub fn new(store: Arc<dyn KeyStore>, factory: Arc<dyn SignerFactory>, profile_path: PathBuf) -> Self {
        Self { store, factory, profile_path }
    }

    /// What this device can offer, for the choice screen.
    pub fn capabilities(&self) -> DeviceCapabilities {
        self.factory.capabilities()
    }

    /// Whether setup has already run on this machine.
    pub fn is_set_up(&self) -> bool {
        self.profile_path.exists()
    }

    /// Read the stored profile, if there is one.
    ///
    /// A file written by a newer build is refused rather than half-understood: the caller shows
    /// "앱을 업데이트해 주세요" instead of behaving unpredictably.
    pub fn profile(&self) -> Result<Option<DeviceProfile>> {
        let bytes = match std::fs::read(&self.profile_path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(AuthError::Hardware(format!("read profile: {e}"))),
        };
        let profile: DeviceProfile =
            ciborium::from_reader(&bytes[..]).map_err(|e| AuthError::Encode(format!("profile: {e}")))?;
        if profile.schema != PROFILE_SCHEMA {
            return Err(AuthError::Encode(format!(
                "profile schema {} is not {PROFILE_SCHEMA}",
                profile.schema
            )));
        }
        Ok(Some(profile))
    }

    /// Reopen an earlier setup. `Ok(None)` when this machine has never been set up.
    pub fn resume(&self) -> Result<Option<Prepared>> {
        let Some(profile) = self.profile()? else { return Ok(None) };
        let signer = self.factory.reopen(&profile)?;
        if signer.key_id() != profile.key_id {
            // The platform handed back a different key than the one this profile was written
            // for — approvals signed with it would be refused on chain. Say so here.
            return Err(AuthError::Hardware("stored approval key no longer matches this device".into()));
        }
        let pending = self.pending_for(&profile);
        Ok(Some(Prepared { profile, signer, pending }))
    }

    /// Finish setup with the chosen style, or resume if this machine is already set up.
    ///
    /// Idempotent on purpose: a second call with the same style must not mint a second identity,
    /// because the person cannot tell that two runs happened.
    pub fn complete(&self, style: ApprovalStyle, now: u64) -> Result<Prepared> {
        if let Some(existing) = self.resume()? {
            return Ok(existing);
        }
        if !self.capabilities().offers(style) {
            return Err(AuthError::Unsupported(style.signer_kind()));
        }

        // Long-lived key material. `get_or_create` means a half-finished earlier attempt is
        // picked up rather than replaced: the envelope key must stay the same or files sealed
        // to it stop opening.
        let device_x = self.x25519(entry::DEVICE_X25519)?;
        let device_ed = self.ed25519(entry::DEVICE_ED25519)?;
        let owner_sealing = self.x25519(entry::OWNER_SEALING)?;
        let owner_signing = self.ed25519(entry::OWNER_SIGNING)?;

        let require_os_confirm = style.device_confirmation() == Confirmation::OsUserVerification;
        let created = self.factory.create(style, require_os_confirm)?;

        let profile = DeviceProfile {
            schema: PROFILE_SCHEMA,
            style,
            signer: created.provider.kind(),
            key_id: created.provider.key_id(),
            public_key: created.provider.public_key(),
            credential: created.credential.unwrap_or_default(),
            require_os_confirm,
            hardware_backed: created.hardware_backed,
            device_x25519_pub: fixed32(device_x.public_key())?,
            device_ed25519_pub: device_ed.verifying_key().to_bytes(),
            owner_sealing_pub: fixed32(owner_sealing.public_key())?,
            owner_signing_pub: owner_signing.verifying_key().to_bytes(),
            account: None,
            enrolled_on_chain: false,
            created_at: now,
        };
        self.write_profile(&profile)?;

        let pending = self.pending_for(&profile);
        Ok(Prepared { profile, signer: created.provider, pending })
    }

    /// Forget this device's setup: the profile and every stored secret.
    ///
    /// Used by "이 기기에서 지우기" and by tests. It does not revoke anything on chain — that
    /// is a separate, deliberate act from another device (Z-1.H.10), because a machine that has
    /// just been wiped is exactly the one that cannot be trusted to speak for the account.
    pub fn forget(&self) -> Result<()> {
        for name in [entry::DEVICE_X25519, entry::DEVICE_ED25519, entry::OWNER_SEALING, entry::OWNER_SIGNING]
        {
            self.store.delete(name)?;
        }
        match std::fs::remove_file(&self.profile_path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(AuthError::Hardware(format!("remove profile: {e}"))),
        }
    }

    /// Load the named X25519 secret, creating it on first run.
    fn x25519(&self, name: &str) -> Result<DeviceKeys> {
        let secret =
            self.secret(name, || DeviceKeys::generate().map(|k| Zeroizing::new(k.secret_key().to_vec())))?;
        DeviceKeys::from_secret(&secret).map_err(|e| key_err(name, e))
    }

    /// Load the named Ed25519 secret, creating it on first run.
    fn ed25519(&self, name: &str) -> Result<SigningKeys> {
        let secret =
            self.secret(name, || Ok(Zeroizing::new(SigningKeys::generate().secret_bytes().to_vec())))?;
        SigningKeys::from_secret(&secret).map_err(|e| key_err(name, e))
    }

    fn secret(
        &self,
        name: &str,
        make: impl FnOnce() -> zbacs_core::Result<Zeroizing<Vec<u8>>>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if let Some(found) = self.store.get(name)? {
            return Ok(found);
        }
        let fresh = make().map_err(|e| key_err(name, e))?;
        self.store.put(name, &fresh)?;
        Ok(fresh)
    }

    fn pending_for(&self, profile: &DeviceProfile) -> Vec<Pending> {
        let mut pending = Vec::new();
        if profile.account.is_none() {
            pending.push(Pending::AccountOnChain);
        }
        if !profile.enrolled_on_chain {
            pending.push(Pending::DeviceEnrolment);
        }
        if !profile.hardware_backed {
            pending.push(Pending::SoftwareSigner);
        }
        if !self.capabilities().persistent_store {
            pending.push(Pending::VolatileKeyStore);
        }
        pending.push(Pending::RecoveryCode);
        pending
    }

    fn write_profile(&self, profile: &DeviceProfile) -> Result<()> {
        if let Some(parent) = self.profile_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| AuthError::Hardware(format!("create config dir: {e}")))?;
        }
        let mut bytes = Vec::new();
        ciborium::into_writer(profile, &mut bytes).map_err(|e| AuthError::Encode(e.to_string()))?;

        // Write beside the target and rename: a crash mid-write must not leave a profile that
        // parses but describes half a setup.
        let tmp = self.profile_path.with_extension("cbor.tmp");
        std::fs::write(&tmp, &bytes).map_err(|e| AuthError::Hardware(format!("write profile: {e}")))?;
        restrict(&tmp)?;
        std::fs::rename(&tmp, &self.profile_path)
            .map_err(|e| AuthError::Hardware(format!("replace profile: {e}")))?;
        Ok(())
    }
}

/// Key material failures never carry the material itself, only which entry went wrong.
fn key_err(name: &str, e: zbacs_core::Error) -> AuthError {
    AuthError::Hardware(format!("key material {name}: {e}"))
}

fn fixed32(bytes: &[u8]) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(bytes).map_err(|_| AuthError::Malformed("public key is not 32 bytes"))
}

/// Keep the profile readable by this user only. It holds no secret, but it does say which
/// account this machine belongs to.
#[cfg(unix)]
fn restrict(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| AuthError::Hardware(format!("restrict profile: {e}")))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<()> {
    // Windows inherits the user's profile directory ACL, which is already user-only.
    Ok(())
}

#[cfg(all(test, feature = "software-signer"))]
mod tests {
    use super::*;
    use crate::software::SoftwareSignerFactory;
    use crate::store::{KeyStore, MemoryKeyStore};

    const NOW: u64 = 1_758_000_000;

    struct Fixture {
        dir: PathBuf,
        store: Arc<dyn KeyStore>,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("zbacs-setup-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self { dir, store: Arc::new(MemoryKeyStore::new()) }
        }

        fn setup(&self) -> Setup {
            self.setup_with(DeviceCapabilities {
                os_authenticator: true,
                hardware_key: false,
                persistent_store: true,
            })
        }

        fn setup_with(&self, caps: DeviceCapabilities) -> Setup {
            Setup::new(
                self.store.clone(),
                Arc::new(
                    SoftwareSignerFactory::new(self.store.clone(), "zbacs.local").with_capabilities(caps),
                ),
                self.dir.join(PROFILE_FILE),
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Z-1.G.2 DoD: the second run must find the first run's identity, not mint a new one —
    /// a new envelope key would make every file sealed yesterday unopenable today.
    #[test]
    fn a_second_run_resumes_the_first_identity_instead_of_creating_another() {
        let f = Fixture::new("resume");
        let first = f.setup().complete(ApprovalStyle::Biometric, NOW).unwrap();
        assert!(f.setup().is_set_up());

        let again = f.setup().complete(ApprovalStyle::Biometric, NOW + 10).unwrap();
        assert_eq!(again.profile.key_id, first.profile.key_id);
        assert_eq!(again.profile.device_x25519_pub, first.profile.device_x25519_pub);
        assert_eq!(again.profile.owner_sealing_pub, first.profile.owner_sealing_pub);
        assert_eq!(again.profile.created_at, NOW, "the identity keeps its original date");

        let resumed = f.setup().resume().unwrap().expect("a profile exists");
        assert_eq!(resumed.signer.key_id(), first.profile.key_id);
    }

    #[test]
    fn a_machine_that_has_never_been_set_up_has_nothing_to_resume() {
        let f = Fixture::new("fresh");
        assert!(!f.setup().is_set_up());
        assert!(f.setup().profile().unwrap().is_none());
        assert!(f.setup().resume().unwrap().is_none());
    }

    /// ADR-0006 + Z-1.U.7: a device with no OS authenticator must not be shown the biometric
    /// button, and must be refused if something asks for it anyway.
    #[test]
    fn a_device_without_an_authenticator_is_neither_offered_nor_given_the_biometric_style() {
        let caps = DeviceCapabilities { os_authenticator: false, hardware_key: true, persistent_store: true };
        assert!(!caps.offers(ApprovalStyle::Biometric));
        assert!(caps.offers(ApprovalStyle::ThisDevice));
        assert_eq!(caps.recommended(), ApprovalStyle::ThisDevice);

        let f = Fixture::new("no-hello");
        let err = f.setup_with(caps).complete(ApprovalStyle::Biometric, NOW).unwrap_err();
        assert!(matches!(err, AuthError::Unsupported(SignerKind::PlatformPasskey)), "{err}");
        assert!(!f.setup_with(caps).is_set_up(), "a refused setup leaves nothing behind");

        // ...and the style it can offer works.
        let ok = f.setup_with(caps).complete(ApprovalStyle::ThisDevice, NOW).unwrap();
        assert_eq!(ok.profile.signer, SignerKind::DeviceKey);
    }

    #[test]
    fn the_recommended_style_is_the_authenticator_when_there_is_one() {
        let caps = DeviceCapabilities { os_authenticator: true, hardware_key: true, persistent_store: true };
        assert_eq!(caps.recommended(), ApprovalStyle::Biometric);
    }

    #[test]
    fn each_style_maps_to_one_signer_and_one_confirmation_setting() {
        assert_eq!(ApprovalStyle::Biometric.signer_kind(), SignerKind::PlatformPasskey);
        assert_eq!(ApprovalStyle::Biometric.device_confirmation(), Confirmation::OsUserVerification);
        assert_eq!(ApprovalStyle::ThisDevice.signer_kind(), SignerKind::DeviceKey);
        assert_eq!(ApprovalStyle::ThisDevice.device_confirmation(), Confirmation::NotRequired);
    }

    /// The UI may say "준비 끝" only for what is actually done; everything else comes back here.
    #[test]
    fn setup_reports_what_it_could_not_finish() {
        let f = Fixture::new("pending");
        let prepared = f.setup().complete(ApprovalStyle::ThisDevice, NOW).unwrap();
        assert!(prepared.pending.contains(&Pending::AccountOnChain), "no account until Z-1.H.8");
        assert!(prepared.pending.contains(&Pending::DeviceEnrolment), "not registered until Z-1.H.10");
        assert!(prepared.pending.contains(&Pending::RecoveryCode));
        assert!(prepared.pending.contains(&Pending::SoftwareSigner), "the stand-in is not hardware");
        assert!(!prepared.pending.contains(&Pending::VolatileKeyStore), "this fixture persists");

        let volatile = f.setup_with(DeviceCapabilities::default());
        assert!(volatile.resume().unwrap().unwrap().pending.contains(&Pending::VolatileKeyStore));
    }

    /// T11 / CLAUDE.md rule 3: the file left on disk must not contain key material.
    #[test]
    fn t11_the_stored_profile_contains_no_secret() {
        let f = Fixture::new("nosecret");
        let prepared = f.setup().complete(ApprovalStyle::Biometric, NOW).unwrap();
        let bytes = std::fs::read(f.dir.join(PROFILE_FILE)).unwrap();

        for name in [
            entry::DEVICE_X25519,
            entry::DEVICE_ED25519,
            entry::OWNER_SEALING,
            entry::OWNER_SIGNING,
            entry::APPROVAL_SOFTWARE,
        ] {
            let secret = f.store.get(name).unwrap().expect("setup stored it");
            assert!(!bytes.windows(secret.len()).any(|w| w == &secret[..]), "{name} leaked into the profile");
        }
        // the public halves are there, which is the point of the file
        assert!(bytes.windows(32).any(|w| w == prepared.profile.device_x25519_pub));
        assert!(format!("{:?}", prepared).contains("Prepared"));
    }

    #[test]
    #[cfg(unix)]
    fn the_profile_is_readable_by_this_user_only() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new("perms");
        f.setup().complete(ApprovalStyle::ThisDevice, NOW).unwrap();
        let mode = std::fs::metadata(f.dir.join(PROFILE_FILE)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {mode:o}");
        assert!(!f.dir.join("device.cbor.tmp").exists(), "the temporary file is renamed away");
    }

    #[test]
    fn a_profile_from_a_newer_build_is_refused_rather_than_misread() {
        let f = Fixture::new("schema");
        f.setup().complete(ApprovalStyle::ThisDevice, NOW).unwrap();

        let mut profile = f.setup().profile().unwrap().unwrap();
        profile.schema = PROFILE_SCHEMA + 1;
        let mut bytes = Vec::new();
        ciborium::into_writer(&profile, &mut bytes).unwrap();
        std::fs::write(f.dir.join(PROFILE_FILE), bytes).unwrap();

        let err = f.setup().profile().unwrap_err();
        assert!(matches!(err, AuthError::Encode(_)), "{err}");

        std::fs::write(f.dir.join(PROFILE_FILE), b"not cbor at all").unwrap();
        assert!(matches!(f.setup().profile().unwrap_err(), AuthError::Encode(_)));
    }

    /// If the platform hands back a different key than the profile names, approvals signed with
    /// it would be refused on chain. Better to say so here than at approval time.
    #[test]
    fn resume_refuses_a_key_that_no_longer_matches_the_profile() {
        let f = Fixture::new("mismatch");
        f.setup().complete(ApprovalStyle::Biometric, NOW).unwrap();

        let other: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
        let stranger = Setup::new(
            f.store.clone(),
            Arc::new(SoftwareSignerFactory::new(other, "zbacs.local")),
            f.dir.join(PROFILE_FILE),
        );
        let err = stranger.resume().unwrap_err();
        assert!(matches!(err, AuthError::Hardware(_)), "{err}");
    }

    #[test]
    fn forget_removes_the_profile_and_every_stored_secret() {
        let f = Fixture::new("forget");
        f.setup().complete(ApprovalStyle::Biometric, NOW).unwrap();
        assert!(f.store.get(entry::OWNER_SEALING).unwrap().is_some());

        f.setup().forget().unwrap();
        assert!(!f.setup().is_set_up());
        assert!(f.store.get(entry::OWNER_SEALING).unwrap().is_none());
        assert!(f.store.get(entry::DEVICE_X25519).unwrap().is_none());
        f.setup().forget().unwrap(); // forgetting twice is not an error
    }

    /// The signer setup produced must actually be usable for an approval, not just stored.
    #[test]
    fn the_prepared_signer_can_approve() {
        use crate::types::{ApprovalChallenge, ApprovalContext};
        use zbacs_core::Permission;

        let f = Fixture::new("sign");
        let prepared = f.setup().complete(ApprovalStyle::Biometric, NOW).unwrap();
        let challenge = ApprovalChallenge {
            digest: [3u8; 32],
            context: ApprovalContext { permission: Permission::ReadOnly, file_id: [1u8; 32] },
        };
        let assertion = prepared.signer.sign(&challenge, Confirmation::OsUserVerification).unwrap();
        assert_eq!(assertion.kind(), SignerKind::PlatformPasskey);
        let public = prepared.profile.public_key.expect("a P-256 key");
        crate::verify_assertion(&public, &challenge.digest, &assertion).unwrap();
    }
}
