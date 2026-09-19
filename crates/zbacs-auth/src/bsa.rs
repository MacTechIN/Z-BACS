//! Z-1.A.5 — `BsaProvider` skeleton.
//!
//! The BSA SDK is commercial and not in hand yet (Z-0.A.3 / OR-1 — see
//! `docs/research/bsa_sdk_notes.md`), so this is a mock that pins the *interface*: an approval
//! goes out to a separate authenticator, comes back as an opaque token, and is verified by the
//! vendor's own check rather than on chain.
//!
//! Keeping it compiling and tested means the day the SDK arrives, only [`BsaClient`] gets a
//! real implementation — every caller, the confirmation policy and the relay message stay as
//! they are (ADR-0003's whole point).

use crate::error::{AuthError, Result};
use crate::provider::AuthProvider;
use crate::types::{ApprovalAssertion, ApprovalChallenge, Confirmation, KeyId, P256PublicKey, SignerKind};

/// What the BSA SDK will have to provide. One trait, so the vendor call and the mock are
/// interchangeable and the provider above never changes.
pub trait BsaClient: Send + Sync {
    /// Ask the registered authenticator to approve `digest`. Blocks until the person answers.
    ///
    /// Returns the vendor's opaque approval token.
    fn request_approval(&self, digest: &[u8; 32]) -> Result<Vec<u8>>;

    /// Check a token the vendor issued. Used by the receiving side, which cannot verify a BSA
    /// token on chain (there is no signature we can check ourselves).
    fn verify(&self, digest: &[u8; 32], token: &[u8]) -> Result<bool>;

    /// Stable identifier of the enrolled BSA identity, used as [`AuthProvider::key_id`].
    fn identity(&self) -> KeyId;
}

/// Signer that delegates to a [`BsaClient`].
pub struct BsaProvider<C: BsaClient> {
    client: C,
}

impl<C: BsaClient> BsaProvider<C> {
    /// Wrap a client (the SDK, or [`MockBsaClient`]).
    pub fn new(client: C) -> Self {
        Self { client }
    }

    /// Verify a token that arrived in a `GrantMsg` (spec §1.5 `OwnerSig`).
    pub fn verify_assertion(&self, digest: &[u8; 32], assertion: &ApprovalAssertion) -> Result<()> {
        let ApprovalAssertion::Bsa { token } = assertion else {
            return Err(AuthError::Malformed("not a BSA assertion"));
        };
        if self.client.verify(digest, token)? {
            Ok(())
        } else {
            Err(AuthError::InvalidSignature)
        }
    }
}

impl<C: BsaClient> AuthProvider for BsaProvider<C> {
    fn kind(&self) -> SignerKind {
        SignerKind::Bsa
    }

    fn key_id(&self) -> KeyId {
        self.client.identity()
    }

    fn public_key(&self) -> Option<P256PublicKey> {
        // A BSA identity is not a P-256 key we can register on chain; its approvals are checked
        // by the vendor. An account using BSA alone therefore needs a co-signer for on-chain
        // operations — decided when the SDK lands.
        None
    }

    fn supports_os_confirmation(&self) -> bool {
        true // the BSA authenticator app does its own user verification
    }

    fn sign(&self, challenge: &ApprovalChallenge, _confirmation: Confirmation) -> Result<ApprovalAssertion> {
        let token = self.client.request_approval(&challenge.digest)?;
        Ok(ApprovalAssertion::Bsa { token })
    }
}

/// Stand-in used until the SDK is available: "approves" by returning a keyed hash of the digest
/// and verifies it the same way. **Not** a security construction — it exists so the interface
/// and its tests stay honest.
pub struct MockBsaClient {
    secret: [u8; 32],
    identity: KeyId,
    /// When set, every approval is refused — the "user pressed 거부" path.
    pub refuse: bool,
}

impl MockBsaClient {
    /// New mock with a deterministic identity.
    pub fn new(secret: [u8; 32]) -> Self {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"mock-bsa-identity");
        h.update(secret);
        Self { secret, identity: KeyId(h.finalize().into()), refuse: false }
    }

    fn token_for(&self, digest: &[u8; 32]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"mock-bsa-token");
        h.update(self.secret);
        h.update(digest);
        h.finalize().to_vec()
    }
}

impl BsaClient for MockBsaClient {
    fn request_approval(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        if self.refuse {
            return Err(AuthError::Cancelled);
        }
        Ok(self.token_for(digest))
    }

    fn verify(&self, digest: &[u8; 32], token: &[u8]) -> Result<bool> {
        Ok(token == self.token_for(digest))
    }

    fn identity(&self) -> KeyId {
        self.identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ApprovalContext;
    use zbacs_core::Permission;

    fn challenge() -> ApprovalChallenge {
        ApprovalChallenge {
            digest: [0x11; 32],
            context: ApprovalContext { permission: Permission::ReadOnly, file_id: [0; 32] },
        }
    }

    #[test]
    fn mock_provider_satisfies_the_auth_provider_contract() {
        let provider = BsaProvider::new(MockBsaClient::new([7; 32]));
        assert_eq!(provider.kind(), SignerKind::Bsa);
        assert!(provider.public_key().is_none(), "BSA identities are not on-chain P-256 keys");
        assert!(provider.supports_os_confirmation());

        let c = challenge();
        let assertion = provider.sign(&c, Confirmation::OsUserVerification).unwrap();
        assert_eq!(assertion.kind(), SignerKind::Bsa);
        provider.verify_assertion(&c.digest, &assertion).unwrap();
    }

    #[test]
    fn a_token_is_bound_to_its_digest_and_identity() {
        let provider = BsaProvider::new(MockBsaClient::new([7; 32]));
        let c = challenge();
        let assertion = provider.sign(&c, Confirmation::OsUserVerification).unwrap();

        assert!(matches!(
            provider.verify_assertion(&[0x22; 32], &assertion),
            Err(AuthError::InvalidSignature)
        ));
        let other = BsaProvider::new(MockBsaClient::new([8; 32]));
        assert!(matches!(other.verify_assertion(&c.digest, &assertion), Err(AuthError::InvalidSignature)));
        assert_ne!(other.key_id(), provider.key_id());
    }

    #[test]
    fn refusal_surfaces_as_cancelled_not_as_an_error() {
        let mut client = MockBsaClient::new([7; 32]);
        client.refuse = true;
        let provider = BsaProvider::new(client);
        assert!(matches!(
            provider.sign(&challenge(), Confirmation::OsUserVerification),
            Err(AuthError::Cancelled)
        ));
    }

    #[test]
    fn p256_verifier_refuses_to_judge_a_bsa_assertion() {
        // the on-chain path must not silently accept something it cannot check
        let provider = BsaProvider::new(MockBsaClient::new([7; 32]));
        let assertion = provider.sign(&challenge(), Confirmation::OsUserVerification).unwrap();
        let key = P256PublicKey { x: [1; 32], y: [2; 32] };
        assert!(matches!(
            crate::verify_assertion(&key, &[0x11; 32], &assertion),
            Err(AuthError::Malformed(_))
        ));
    }
}
