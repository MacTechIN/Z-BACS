//! Z-1.C.4 — reseal: new DEK per version, version chain, atomic replacement (spec §5).

use std::io::Cursor;
use zbacs_core::{
    inspect, open, reseal_to_path, seal_to_path, verify_version_chain, Dek, DeviceKeys, Envelope, Error,
    Header, HeaderHash, OwnerKeys, Permission, Policy, PrevVersion, SealOptions,
};

struct Repo {
    dir: tempfile::TempDir,
    owner: OwnerKeys,
}

impl Repo {
    fn new() -> Self {
        Self { dir: tempfile::tempdir().unwrap(), owner: OwnerKeys::generate().unwrap() }
    }
    fn container(&self) -> std::path::PathBuf {
        self.dir.path().join("doc.zbacs")
    }
    fn plaintext(&self, name: &str, content: &[u8]) -> std::path::PathBuf {
        let p = self.dir.path().join(name);
        std::fs::write(&p, content).unwrap();
        p
    }
    fn seal_v1(&self, content: &[u8]) -> Header {
        let src = self.plaintext("original.txt", content);
        seal_to_path(&src, &self.container(), &self.owner, &SealOptions::new(b"acct", "report.docx")).unwrap()
    }
    fn reseal(&self, content: &[u8], policy: Policy) -> Header {
        let edited = self.plaintext("edited.bin", content);
        reseal_to_path(&edited, &self.container(), &self.owner, policy).unwrap()
    }
    fn read(&self) -> (Header, HeaderHash) {
        inspect(Cursor::new(std::fs::read(self.container()).unwrap())).unwrap()
    }
    fn open(&self) -> (Vec<u8>, String) {
        let data = std::fs::read(self.container()).unwrap();
        let mut plain = Vec::new();
        let opened = open(Cursor::new(&data), &mut plain, &self.owner.sealing).unwrap();
        (plain, opened.file_name)
    }
    fn dek(&self) -> Dek {
        let (hdr, _) = self.read();
        let env = hdr.body.env.iter().find(|e| e.kid == self.owner.sealing.key_id()).unwrap();
        env.open(&self.owner.sealing, hdr.body.fid.as_bytes()).unwrap()
    }
}

#[test]
fn reseal_chain_v1_v2_v3() {
    let repo = Repo::new();
    let h1 = repo.seal_v1(b"version one");
    let (_, hh1) = repo.read();
    let h2 = repo.reseal(b"version two, edited", Policy::default());
    let (_, hh2) = repo.read();
    let h3 = repo.reseal(b"version three", Policy { default: Permission::ReadOnly, ..Policy::default() });
    let (_, hh3) = repo.read();

    assert_eq!((h1.body.ver, h2.body.ver, h3.body.ver), (1, 2, 3));
    assert_eq!(h1.body.prev, None);
    assert_eq!(h2.body.prev, Some(hh1));
    assert_eq!(h3.body.prev, Some(hh2));

    // identity is stable; the on-chain record keeps its key across bumpVersion calls
    assert_eq!(h2.body.fid, h1.body.fid);
    assert_eq!(h3.body.fid, h1.body.fid);
    assert_eq!(h2.body.salt, h1.body.salt);
    assert_eq!(h3.body.salt, h1.body.salt);

    verify_version_chain(&[(h1, hh1), (h2, hh2), (h3.clone(), hh3)]).unwrap();

    // the container on disk is the newest version and still carries the original file name
    let (plain, name) = repo.open();
    assert_eq!(plain, b"version three");
    assert_eq!(name, "report.docx");
    assert_eq!(repo.read().0, h3);
}

/// T20: a DEK released under an earlier grant must not open the resealed file.
#[test]
fn t20_each_version_gets_a_fresh_dek_and_nonce_prefix() {
    let repo = Repo::new();
    let h1 = repo.seal_v1(b"secret v1");
    let dek_v1 = repo.dek();

    let h2 = repo.reseal(b"secret v2", Policy::default());
    let dek_v2 = repo.dek();

    assert_ne!(dek_v1.as_ref(), dek_v2.as_ref(), "reseal must mint a new DEK");
    assert_ne!(h2.body.np, h1.body.np, "and a new nonce prefix");
    assert_ne!(h2.body.env[0].ct, h1.body.env[0].ct);

    // the old DEK, e.g. one a recipient still holds from a previous grant, is useless now
    let data = std::fs::read(repo.container()).unwrap();
    let mut sink = Vec::new();
    let stale = zbacs_core::GrantedDek::new(Dek::from_bytes(dek_v1.as_ref()).unwrap());
    use zbacs_core::Opener;
    assert!(matches!(stale.open(&mut Cursor::new(&data), &mut sink), Err(Error::NameAuth)));
    assert!(sink.is_empty());
}

#[test]
fn reseal_keeps_recipients_out_and_policy_updatable() {
    let repo = Repo::new();
    let bob = DeviceKeys::generate().unwrap();

    // v1 was sealed with Bob as an extra recipient
    let src = repo.plaintext("original.txt", b"v1");
    let bob_pk = bob.public_key().to_vec();
    let recipients: [&[u8]; 1] = [&bob_pk];
    let mut opts = SealOptions::new(b"acct", "report.docx");
    opts.extra_recipients = &recipients;
    seal_to_path(&src, &repo.container(), &repo.owner, &opts).unwrap();
    assert_eq!(repo.read().0.body.env.len(), 2);
    let mut plain = Vec::new();
    open(Cursor::new(std::fs::read(repo.container()).unwrap()), &mut plain, &bob).unwrap();

    // after a reseal only the owner's self-envelope remains: the next open needs a new grant
    let h2 = repo.reseal(b"v2", Policy { default: Permission::Edit, ttl: 60, ..Policy::default() });
    assert_eq!(h2.body.env.len(), 1);
    assert_eq!(h2.body.env[0].kid, repo.owner.sealing.key_id());
    assert_eq!(h2.body.pol.default, Permission::Edit);
    assert_eq!(h2.body.pol.ttl, 60);
    let mut sink = Vec::new();
    assert!(matches!(
        open(Cursor::new(std::fs::read(repo.container()).unwrap()), &mut sink, &bob),
        Err(Error::NoEnvelope)
    ));
}

#[test]
fn reseal_is_atomic_and_leaves_no_temp_file() {
    let repo = Repo::new();
    repo.seal_v1(b"v1");
    repo.reseal(b"v2 is quite a bit longer than v1", Policy::default());
    let leftovers: Vec<_> = std::fs::read_dir(repo.dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("tmp"))
        .collect();
    assert!(leftovers.is_empty(), "temp files left behind: {leftovers:?}");
    assert_eq!(repo.open().0, b"v2 is quite a bit longer than v1");
}

#[test]
fn reseal_without_the_owner_envelope_fails_cleanly() {
    let repo = Repo::new();
    let bob = DeviceKeys::generate().unwrap();
    let src = repo.plaintext("original.txt", b"v1");
    // sealed by someone else: our owner has no self-envelope in it
    let other = OwnerKeys::generate().unwrap();
    let bob_pk = bob.public_key().to_vec();
    let recipients: [&[u8]; 1] = [&bob_pk];
    let mut opts = SealOptions::new(b"acct", "x.txt");
    opts.extra_recipients = &recipients;
    seal_to_path(&src, &repo.container(), &other, &opts).unwrap();

    let edited = repo.plaintext("edited.bin", b"v2");
    assert!(matches!(
        reseal_to_path(&edited, &repo.container(), &repo.owner, Policy::default()),
        Err(Error::NoEnvelope)
    ));
    // the previous version is untouched
    assert_eq!(repo.read().0.body.ver, 1);
}

// ------------------------------------------------------------------ chain verification (T19)

fn chain_of(repo: &Repo) -> Vec<(Header, HeaderHash)> {
    let h1 = repo.seal_v1(b"v1");
    let (_, hh1) = repo.read();
    let h2 = repo.reseal(b"v2", Policy::default());
    let (_, hh2) = repo.read();
    vec![(h1, hh1), (h2, hh2)]
}

#[test]
fn t19_chain_must_start_at_version_one() {
    let repo = Repo::new();
    let chain = chain_of(&repo);
    assert!(matches!(verify_version_chain(&chain[1..]), Err(Error::BrokenChain(_))));
    assert!(matches!(verify_version_chain(&[]), Err(Error::BrokenChain(_))));
}

#[test]
fn t19_broken_links_are_rejected() {
    let repo = Repo::new();
    let mut chain = chain_of(&repo);

    // prev pointing at something else
    let mut tampered = chain.clone();
    tampered[1].0.body.prev = Some(HeaderHash([0xAA; 32]));
    assert!(matches!(verify_version_chain(&tampered), Err(Error::BrokenChain(_))));

    // version jump
    let mut tampered = chain.clone();
    tampered[1].0.body.ver = 5;
    assert!(matches!(verify_version_chain(&tampered), Err(Error::BrokenChain(_))));

    // a different file spliced in as "the next version"
    let other = Repo::new();
    let o1 = other.seal_v1(b"someone else's file");
    let (_, ohh) = other.read();
    chain.push((o1, ohh));
    assert!(matches!(verify_version_chain(&chain), Err(Error::BrokenChain(_))));
}

#[test]
fn t19_hash_must_match_the_header_it_accompanies() {
    let repo = Repo::new();
    let mut chain = chain_of(&repo);
    chain[1].1 = HeaderHash([1; 32]);
    assert!(matches!(verify_version_chain(&chain), Err(Error::BrokenChain(_))));
}

#[test]
fn seal_options_prev_can_be_built_by_hand() {
    // the Agent may drive reseal itself (in-memory streams rather than paths)
    let repo = Repo::new();
    let h1 = repo.seal_v1(b"v1");
    let (_, hh1) = repo.read();
    let prev = PrevVersion::of(&h1, hh1);
    assert_eq!(prev.file_id, h1.body.fid);
    assert_eq!(prev.version, 1);

    let mut opts = SealOptions::new(b"acct", "report.docx");
    opts.prev = Some(prev);
    let mut out = Vec::new();
    let h2 = zbacs_core::seal(Cursor::new(b"v2"), &mut out, &repo.owner, &opts).unwrap();
    assert_eq!(h2.body.ver, 2);
    assert_eq!(h2.body.fid, h1.body.fid);
    let (_, hh2) = inspect(Cursor::new(&out)).unwrap();
    verify_version_chain(&[(h1, hh1), (h2, hh2)]).unwrap();
}

#[test]
fn envelope_helper_is_reexported_for_agents() {
    // grant flow: owner unwraps their own envelope, re-wraps the fresh DEK for the recipient
    let repo = Repo::new();
    repo.seal_v1(b"v1");
    let dek = repo.dek();
    let bob = DeviceKeys::generate().unwrap();
    let env = Envelope::seal(bob.public_key(), &dek, b"grant").unwrap();
    assert_eq!(env.open(&bob, b"grant").unwrap().as_ref(), dek.as_ref());
}
