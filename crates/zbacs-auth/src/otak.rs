//! Z-1.A.6 — OTAK: one-time authentication keys, derived here, no issuer.
//!
//! This is the ITU-T X.1284 shape implemented with our own key material: an enrolled device
//! holds a long-term seed, and every approval uses a key **derived for that one request and
//! destroyed after use**. Nothing is issued by anyone; enrolment is two devices agreeing on a
//! seed the owner generated.
//!
//! Where it fits (ADR-0003, ADR-0006): the passkey and TPM paths are what an owner normally
//! uses, and they are verifiable on chain. OTAK is the path that needs no hardware and no
//! vendor — useful for a second device that has neither, for a self-hosted deployment, and as
//! the honest stand-in for BSA while no SDK is in hand.
//!
//! What it does *not* do: an OTAK assertion is a MAC, so only a party holding the same seed can
//! check it. It cannot be verified by a smart contract, and it must never be sent through the
//! relay to someone who should not hold the seed. The on-chain account therefore still needs a
//! P-256 signer; OTAK authenticates to *our own* components (owner's other device, self-hosted
//! relay), which is exactly the X.1284 use case.
//!
//! Replay (the task's DoD): a derived key is single-use on both sides. The signer refuses to
//! derive the same key twice and the verifier refuses to accept the same challenge twice, so a
//! captured assertion is worthless even before the grant's own nonce is considered (T03).

use std::collections::HashSet;
use std::sync::Mutex;

use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{AuthError, Result};
use crate::provider::AuthProvider;
use crate::types::{ApprovalAssertion, ApprovalChallenge, Confirmation, KeyId, P256PublicKey, SignerKind};

/// Domain separation for one-time key derivation.
pub const OTAK_DERIVE_DOMAIN: &[u8] = b"ZBACS-OTAK-v1/derive";
/// Domain separation for the identity commitment.
pub const OTAK_ID_DOMAIN: &[u8] = b"ZBACS-OTAK-v1/id";
/// Domain separation for the assertion MAC.
pub const OTAK_MAC_DOMAIN: &[u8] = b"ZBACS-OTAK-v1/mac";

type HmacSha256 = Hmac<Sha256>;

/// The long-term secret an enrolled OTAK device holds. Generated here; never transmitted after
/// enrolment.
pub struct OtakSeed(Zeroizing<[u8; 32]>);

impl OtakSeed {
    /// Fresh random seed (enrolment on the first device).
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let me = Self(Zeroizing::new(seed));
        seed.zeroize();
        me
    }

    /// Restore from the OS keychain (`zbacs-auth::store`).
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = b.try_into().map_err(|_| AuthError::Malformed("OTAK seed must be 32 bytes"))?;
        Ok(Self(Zeroizing::new(arr)))
    }

    /// Raw bytes, for storing in the keychain. Treat as a secret.
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// `SHA-256(OTAK_ID_DOMAIN || seed)` — a public identifier that does not reveal the seed,
    /// so both sides can say which enrolment they mean.
    pub fn identity(&self) -> KeyId {
        let mut mac = HmacSha256::new_from_slice(OTAK_ID_DOMAIN).expect("hmac key");
        mac.update(self.expose());
        KeyId(mac.finalize().into_bytes().into())
    }

    /// Derive the one-time key for one challenge digest.
    ///
    /// The digest is unique per approval (it commits to the request nonce, spec §1.2), so it
    /// doubles as the derivation label — there is no separate counter to keep in sync.
    fn one_time_key(&self, digest: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        let mut mac = HmacSha256::new_from_slice(OTAK_DERIVE_DOMAIN).expect("hmac key");
        mac.update(self.expose());
        mac.update(digest);
        Zeroizing::new(mac.finalize().into_bytes().into())
    }
}

impl std::fmt::Debug for OtakSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OtakSeed({}, secret=REDACTED)", self.identity())
    }
}

/// Remembers which one-time keys have been spent. In-process for now; the Agent persists it
/// alongside the session log so a restart cannot reopen the window (Z-1.G.4 resume).
#[derive(Default)]
pub struct SpentKeys(Mutex<HashSet<[u8; 32]>>);

impl SpentKeys {
    /// Empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a digest spent. Returns false when it was already spent.
    pub fn spend(&self, digest: &[u8; 32]) -> bool {
        self.0.lock().expect("spent-keys mutex").insert(*digest)
    }

    /// Whether this digest has been used.
    pub fn is_spent(&self, digest: &[u8; 32]) -> bool {
        self.0.lock().expect("spent-keys mutex").contains(digest)
    }

    /// How many are remembered (the Agent prunes with the grant's expiry).
    pub fn len(&self) -> usize {
        self.0.lock().expect("spent-keys mutex").len()
    }

    /// True when nothing has been spent.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Signs approvals with a one-time key derived per request (X.1284 flow).
pub struct OtakProvider {
    seed: OtakSeed,
    spent: SpentKeys,
}

impl OtakProvider {
    /// Enrol with a seed this device generated or restored.
    pub fn new(seed: OtakSeed) -> Self {
        Self { seed, spent: SpentKeys::new() }
    }

    /// Generate a fresh enrolment. Store [`OtakSeed::expose`] in the keychain and hand the same
    /// bytes to the counterpart device once, out of band.
    pub fn enrol() -> Self {
        Self::new(OtakSeed::generate())
    }

    /// The enrolment's public identifier.
    pub fn identity(&self) -> KeyId {
        self.seed.identity()
    }

    /// The seed, to persist. Treat as a secret.
    pub fn seed(&self) -> &OtakSeed {
        &self.seed
    }

    /// How many one-time keys this device has spent.
    pub fn spent_count(&self) -> usize {
        self.spent.len()
    }
}

/// Compute the assertion MAC for a challenge under a one-time key.
fn assertion_mac(one_time: &[u8; 32], digest: &[u8; 32]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(one_time).expect("hmac key");
    mac.update(OTAK_MAC_DOMAIN);
    mac.update(digest);
    mac.finalize().into_bytes().into()
}

impl AuthProvider for OtakProvider {
    fn kind(&self) -> SignerKind {
        SignerKind::Otak
    }

    fn key_id(&self) -> KeyId {
        self.identity()
    }

    fn public_key(&self) -> Option<P256PublicKey> {
        // OTAK is symmetric: there is no public key to register on chain. An account that uses
        // OTAK still needs a P-256 signer for on-chain operations (ADR-0006).
        None
    }

    fn supports_os_confirmation(&self) -> bool {
        // Nothing here asks the OS for anything; the Agent's own prompt is the confirmation.
        false
    }

    fn sign(&self, challenge: &ApprovalChallenge, confirmation: Confirmation) -> Result<ApprovalAssertion> {
        if confirmation == Confirmation::OsUserVerification {
            return Err(AuthError::ConfirmationUnavailable(SignerKind::Otak, confirmation));
        }
        // One-time: a key is derived once and never again (X.1284 "폐기").
        if !self.spent.spend(&challenge.digest) {
            return Err(AuthError::Malformed("this one-time key was already used"));
        }
        let one_time = self.seed.one_time_key(&challenge.digest);
        Ok(ApprovalAssertion::Otak {
            key_id: self.identity(),
            mac: assertion_mac(&one_time, &challenge.digest),
        })
    }
}

/// The counterpart that checks OTAK assertions: the owner's other device, or a self-hosted
/// relay the owner runs. Holds the same seed, and enforces one-time use independently.
pub struct OtakVerifier {
    seed: OtakSeed,
    spent: SpentKeys,
}

impl OtakVerifier {
    /// Enrol the verifier with the seed shared out of band.
    pub fn new(seed: OtakSeed) -> Self {
        Self { seed, spent: SpentKeys::new() }
    }

    /// Verify an assertion and burn the one-time key.
    ///
    /// Returns [`AuthError::InvalidSignature`] for a wrong MAC or a different enrolment, and
    /// refuses a digest it has already accepted (replay, T03).
    pub fn verify(&self, digest: &[u8; 32], assertion: &ApprovalAssertion) -> Result<()> {
        let ApprovalAssertion::Otak { key_id, mac } = assertion else {
            return Err(AuthError::Malformed("not an OTAK assertion"));
        };
        if *key_id != self.seed.identity() {
            return Err(AuthError::InvalidSignature);
        }
        let one_time = self.seed.one_time_key(digest);
        let expected = assertion_mac(&one_time, digest);
        // constant-time compare
        if !bool::from(subtle_eq(&expected, mac)) {
            return Err(AuthError::InvalidSignature);
        }
        if !self.spent.spend(digest) {
            return Err(AuthError::Malformed("this one-time key was already used"));
        }
        Ok(())
    }

    /// Whether a digest has already been accepted.
    pub fn is_spent(&self, digest: &[u8; 32]) -> bool {
        self.spent.is_spent(digest)
    }
}

/// Constant-time 32-byte comparison.
fn subtle_eq(a: &[u8; 32], b: &[u8; 32]) -> subtle::Choice {
    use subtle::ConstantTimeEq;
    a.ct_eq(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ApprovalContext;
    use zbacs_core::Permission;

    fn challenge(n: u8) -> ApprovalChallenge {
        ApprovalChallenge {
            digest: [n; 32],
            context: ApprovalContext { permission: Permission::ReadOnly, file_id: [0; 32] },
        }
    }

    fn pair() -> (OtakProvider, OtakVerifier) {
        let provider = OtakProvider::enrol();
        let verifier = OtakVerifier::new(OtakSeed::from_bytes(provider.seed().expose()).unwrap());
        (provider, verifier)
    }

    #[test]
    fn an_enrolled_pair_approves_and_verifies() {
        let (provider, verifier) = pair();
        assert_eq!(provider.kind(), SignerKind::Otak);
        assert!(provider.public_key().is_none(), "OTAK is symmetric; nothing to register on chain");

        let c = challenge(1);
        let assertion = provider.sign(&c, Confirmation::NotRequired).unwrap();
        verifier.verify(&c.digest, &assertion).unwrap();
        assert_eq!(provider.spent_count(), 1);
    }

    /// The task's DoD: a captured assertion cannot be used again, on either side.
    #[test]
    fn t03_replay_is_refused_by_signer_and_verifier() {
        let (provider, verifier) = pair();
        let c = challenge(1);
        let assertion = provider.sign(&c, Confirmation::NotRequired).unwrap();
        verifier.verify(&c.digest, &assertion).unwrap();

        // the verifier refuses the same assertion a second time
        assert!(matches!(verifier.verify(&c.digest, &assertion), Err(AuthError::Malformed(_))));
        assert!(verifier.is_spent(&c.digest));

        // and the signer will not re-derive the same one-time key
        assert!(matches!(provider.sign(&c, Confirmation::NotRequired), Err(AuthError::Malformed(_))));

        // a different approval still works
        let c2 = challenge(2);
        let a2 = provider.sign(&c2, Confirmation::NotRequired).unwrap();
        verifier.verify(&c2.digest, &a2).unwrap();
    }

    #[test]
    fn keys_are_per_request_and_do_not_leak_the_seed() {
        let provider = OtakProvider::enrol();
        let k1 = provider.seed().one_time_key(&[1; 32]);
        let k2 = provider.seed().one_time_key(&[2; 32]);
        assert_ne!(*k1, *k2, "each request gets its own key");
        assert_ne!(k1.as_slice(), provider.seed().expose().as_slice());
        // identity is derived, not the seed itself
        assert_ne!(provider.identity().0.as_slice(), provider.seed().expose().as_slice());
        assert!(format!("{:?}", provider.seed()).contains("REDACTED"));
    }

    #[test]
    fn t14_wrong_enrolment_or_tampered_mac_is_refused() {
        let (provider, verifier) = pair();
        let c = challenge(1);
        let assertion = provider.sign(&c, Confirmation::NotRequired).unwrap();

        // another enrolment cannot verify it
        let stranger = OtakVerifier::new(OtakSeed::generate());
        assert!(matches!(stranger.verify(&c.digest, &assertion), Err(AuthError::InvalidSignature)));

        // flipped MAC bit
        let ApprovalAssertion::Otak { key_id, mut mac } = assertion else { panic!() };
        mac[31] ^= 1;
        let tampered = ApprovalAssertion::Otak { key_id, mac };
        assert!(matches!(verifier.verify(&c.digest, &tampered), Err(AuthError::InvalidSignature)));
        assert!(!verifier.is_spent(&c.digest), "a failed check must not burn the key");

        // the assertion is bound to its digest
        let a2 = OtakProvider::enrol();
        let other = a2.sign(&challenge(9), Confirmation::NotRequired).unwrap();
        assert!(matches!(verifier.verify(&[9; 32], &other), Err(AuthError::InvalidSignature)));
    }

    #[test]
    fn os_confirmation_is_honestly_refused() {
        let provider = OtakProvider::enrol();
        assert!(!provider.supports_os_confirmation());
        assert!(matches!(
            provider.sign(&challenge(1), Confirmation::OsUserVerification),
            Err(AuthError::ConfirmationUnavailable(SignerKind::Otak, _))
        ));
    }

    #[test]
    fn seed_restores_from_storage_and_keeps_its_identity() {
        let provider = OtakProvider::enrol();
        let stored = *provider.seed().expose();
        let restored = OtakProvider::new(OtakSeed::from_bytes(&stored).unwrap());
        assert_eq!(restored.identity(), provider.identity());
        assert!(matches!(OtakSeed::from_bytes(&[0; 31]), Err(AuthError::Malformed(_))));
    }

    #[test]
    fn p256_verifier_refuses_to_judge_an_otak_assertion() {
        let provider = OtakProvider::enrol();
        let assertion = provider.sign(&challenge(1), Confirmation::NotRequired).unwrap();
        let key = P256PublicKey { x: [1; 32], y: [2; 32] };
        assert!(matches!(crate::verify_assertion(&key, &[1; 32], &assertion), Err(AuthError::Malformed(_))));
    }
}
