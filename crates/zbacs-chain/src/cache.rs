//! Remembering what the chain said, and being honest about how old it is.
//!
//! The Agent has to keep working on a train. What it must never do is pretend a stale answer is
//! a fresh one: a file whose policy says `strict_onchain` may only open on a fresh answer, and
//! a revoke that arrived five minutes ago is still a revoke even if the node is now unreachable
//! (T20 — once we have seen a revocation we never un-see it).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How old an answer is, relative to the caller's tolerance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    /// Taken within the tolerance.
    Fresh,
    /// Older than the tolerance, but still remembered.
    Stale,
}

/// A file's on-chain state: header hash, version number, retired flag.
pub type VersionRecord = ([u8; 32], u32, bool);

/// A remembered answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cached<T> {
    /// The answer.
    pub value: T,
    /// How fresh it is.
    pub freshness: Freshness,
    /// How long ago it was taken.
    pub age: Duration,
}

impl<T> Cached<T> {
    /// The value, but only if it is fresh enough to act on.
    pub fn if_fresh(self) -> Option<T> {
        match self.freshness {
            Freshness::Fresh => Some(self.value),
            Freshness::Stale => None,
        }
    }
}

struct Entry<T> {
    value: T,
    at: Instant,
}

/// Last-known chain answers.
///
/// Deliberately small: grant validity and file records. Anything else the Agent needs it can
/// ask for when it is online.
#[derive(Default)]
pub struct Cache {
    grants: Mutex<HashMap<[u8; 32], Entry<bool>>>,
    versions: Mutex<HashMap<[u8; 32], Entry<VersionRecord>>>,
}

impl Cache {
    /// Empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `isValid(grant_id)`.
    ///
    /// A grant that has been seen invalid stays invalid: a later "valid" answer for the same id
    /// cannot happen on chain (revocation and expiry are one-way), so if we see one we keep the
    /// negative. That turns a confused or hostile node into a closed session, not an open one.
    pub fn put_grant(&self, grant_id: [u8; 32], valid: bool) {
        let mut grants = self.grants.lock().expect("cache mutex");
        match grants.get(&grant_id) {
            Some(existing) if !existing.value && valid => {} // never resurrect a dead grant
            _ => {
                grants.insert(grant_id, Entry { value: valid, at: Instant::now() });
            }
        }
    }

    /// Look up a remembered `isValid`, with its age.
    pub fn grant(&self, grant_id: &[u8; 32], tolerance: Duration) -> Option<Cached<bool>> {
        let grants = self.grants.lock().expect("cache mutex");
        grants.get(grant_id).map(|e| {
            let age = e.at.elapsed();
            Cached {
                value: e.value,
                age,
                freshness: if age <= tolerance { Freshness::Fresh } else { Freshness::Stale },
            }
        })
    }

    /// Record a file's current version.
    pub fn put_version(&self, file_id: [u8; 32], header_hash: [u8; 32], version: u32, retired: bool) {
        self.versions
            .lock()
            .expect("cache mutex")
            .insert(file_id, Entry { value: (header_hash, version, retired), at: Instant::now() });
    }

    /// Look up a remembered file version.
    pub fn version(&self, file_id: &[u8; 32], tolerance: Duration) -> Option<Cached<VersionRecord>> {
        let versions = self.versions.lock().expect("cache mutex");
        versions.get(file_id).map(|e| {
            let age = e.at.elapsed();
            Cached {
                value: e.value,
                age,
                freshness: if age <= tolerance { Freshness::Fresh } else { Freshness::Stale },
            }
        })
    }

    /// Forget everything (sign-out, or a deliberate refresh).
    pub fn clear(&self) {
        self.grants.lock().expect("cache mutex").clear();
        self.versions.lock().expect("cache mutex").clear();
    }

    /// How many answers are remembered.
    pub fn len(&self) -> usize {
        self.grants.lock().expect("cache mutex").len() + self.versions.lock().expect("cache mutex").len()
    }

    /// Whether nothing is remembered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_answer_is_usable_and_an_old_one_is_not() {
        let cache = Cache::new();
        cache.put_grant([1; 32], true);

        let hit = cache.grant(&[1; 32], Duration::from_secs(60)).unwrap();
        assert!(hit.value);
        assert_eq!(hit.freshness, Freshness::Fresh);
        assert_eq!(hit.if_fresh(), Some(true));

        // with a zero tolerance the same entry is already too old to act on
        let hit = cache.grant(&[1; 32], Duration::ZERO).unwrap();
        assert_eq!(hit.freshness, Freshness::Stale);
        assert_eq!(hit.if_fresh(), None, "a strict file must not open on a stale answer");
    }

    /// T20: once a grant is known dead, no later answer may bring it back.
    #[test]
    fn t20_a_revoked_grant_is_never_resurrected_by_the_cache() {
        let cache = Cache::new();
        cache.put_grant([2; 32], true);
        cache.put_grant([2; 32], false); // revoke observed
        cache.put_grant([2; 32], true); // a confused or hostile node says otherwise

        assert!(!cache.grant(&[2; 32], Duration::from_secs(60)).unwrap().value);
    }

    #[test]
    fn versions_and_clearing() {
        let cache = Cache::new();
        assert!(cache.is_empty());
        cache.put_version([3; 32], [9; 32], 2, false);
        let hit = cache.version(&[3; 32], Duration::from_secs(60)).unwrap();
        assert_eq!(hit.value, ([9; 32], 2, false));
        assert!(cache.version(&[4; 32], Duration::from_secs(60)).is_none());
        assert_eq!(cache.len(), 1);
        cache.clear();
        assert!(cache.is_empty());
    }
}
