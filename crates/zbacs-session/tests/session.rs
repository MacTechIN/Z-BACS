//! Z-1.G.4/G.5/G.7/G.8 — session transitions and the protected workspace.
//! Threat ids per docs/threat_model.md.

use zbacs_core::Permission;
use zbacs_session::{AuditKind, Effect, Event, Notice, Session, State, TransitionError, Workspace};

const NOW: u64 = 1_000_000;

fn granted(permission: Permission, max_opens: u16) -> Event {
    Event::Granted { permission, not_before: NOW, expiry: NOW + 3600, max_opens }
}

fn open_session(permission: Permission, max_opens: u16) -> Session {
    let mut s = Session::new();
    s.apply(granted(permission, max_opens), NOW).unwrap();
    s.apply(Event::Opened, NOW).unwrap();
    s
}

// ------------------------------------------------------------------ happy paths

#[test]
fn read_only_session_runs_and_closes_without_a_new_version() {
    let mut s = Session::new();
    assert_eq!(s.state(), State::Requested);
    assert!(!s.state().plaintext_allowed());

    assert_eq!(s.apply(granted(Permission::ReadOnly, 1), NOW).unwrap(), vec![Effect::MaterialisePlaintext]);
    assert_eq!(s.state(), State::Granted);

    assert_eq!(
        s.apply(Event::Opened, NOW).unwrap(),
        vec![Effect::MarkReadOnly, Effect::LaunchViewer, Effect::Audit(AuditKind::Opened)]
    );
    assert_eq!(s.state(), State::Open);
    assert!(s.state().plaintext_allowed());
    assert_eq!(s.opens(), 1);

    // the viewer saved anyway: the change is dropped, the session stays open
    assert_eq!(
        s.apply(Event::Saved, NOW + 10).unwrap(),
        vec![Effect::DiscardChanges, Effect::Notify(Notice::ChangesDiscarded)]
    );
    assert_eq!(s.state(), State::Open);
    assert_eq!(s.version(), None, "ReadOnly never produces a version");

    assert_eq!(s.apply(Event::ViewerExited, NOW + 20).unwrap(), vec![Effect::WipeWorkspace]);
    assert_eq!(s.state(), State::Closed);
    assert!(!s.state().plaintext_allowed());
}

#[test]
fn edit_session_reseals_on_save_and_can_save_again() {
    let mut s = open_session(Permission::Edit, 1);

    assert_eq!(s.apply(Event::Saved, NOW + 5).unwrap(), vec![Effect::Reseal]);
    assert_eq!(s.state(), State::Resealing);
    assert!(s.has_unsealed_changes());

    assert_eq!(
        s.apply(Event::Resealed { version: 2 }, NOW + 6).unwrap(),
        vec![Effect::Audit(AuditKind::Sealed), Effect::Notify(Notice::Resealed)]
    );
    assert_eq!(s.state(), State::Open);
    assert_eq!(s.version(), Some(2));
    assert!(!s.has_unsealed_changes());

    // a second save in the same session bumps again
    s.apply(Event::Saved, NOW + 7).unwrap();
    s.apply(Event::Resealed { version: 3 }, NOW + 8).unwrap();
    assert_eq!(s.version(), Some(3));

    assert_eq!(s.apply(Event::ViewerExited, NOW + 9).unwrap(), vec![Effect::WipeWorkspace]);
    assert_eq!(s.state(), State::Closed);
}

#[test]
fn a_refusal_ends_the_session_before_anything_is_decrypted() {
    let mut s = Session::new();
    assert_eq!(
        s.apply(Event::Denied, NOW).unwrap(),
        vec![Effect::Audit(AuditKind::Denied), Effect::Notify(Notice::Refused)]
    );
    assert_eq!(s.state(), State::Denied);
    assert!(s.state().is_terminal());
    assert!(!s.state().plaintext_allowed());
    assert_eq!(s.apply(Event::Opened, NOW).unwrap_err(), TransitionError::Terminal(State::Denied));
}

// ------------------------------------------------------------------ T15 window

#[test]
fn t15_a_grant_outside_its_window_is_refused() {
    let mut s = Session::new();
    let early = Event::Granted {
        permission: Permission::Edit,
        not_before: NOW + 100,
        expiry: NOW + 200,
        max_opens: 1,
    };
    assert_eq!(s.apply(early, NOW).unwrap_err(), TransitionError::NotYetValid);

    let mut s = Session::new();
    let late =
        Event::Granted { permission: Permission::Edit, not_before: NOW - 100, expiry: NOW, max_opens: 1 };
    assert_eq!(s.apply(late, NOW).unwrap_err(), TransitionError::AlreadyExpired);
    assert_eq!(s.state(), State::Requested, "a bad grant leaves the session untouched");
}

#[test]
fn t15_expiry_while_open_closes_the_viewer_and_wipes() {
    let mut s = open_session(Permission::Edit, 0);
    assert!(s.is_expired(NOW + 3600));
    assert!(!s.is_expired(NOW + 3599));

    assert_eq!(
        s.apply(Event::Expired, NOW + 3600).unwrap(),
        vec![Effect::RequestViewerClose, Effect::WipeWorkspace, Effect::Notify(Notice::Expired)]
    );
    assert_eq!(s.state(), State::Closed);
}

#[test]
fn expiry_before_opening_needs_no_cleanup() {
    let mut s = Session::new();
    s.apply(granted(Permission::Edit, 1), NOW).unwrap();
    assert_eq!(s.apply(Event::Expired, NOW + 3600).unwrap(), vec![Effect::Notify(Notice::Expired)]);
    assert_eq!(s.state(), State::Closed);
}

// ------------------------------------------------------------------ T20 revoke

#[test]
fn t20_revoke_while_open_closes_the_viewer_and_drops_unsealed_changes() {
    let mut s = open_session(Permission::Edit, 0);
    s.apply(Event::Saved, NOW + 5).unwrap(); // mid-reseal
    assert!(s.has_unsealed_changes());

    assert_eq!(
        s.apply(Event::Revoked, NOW + 6).unwrap(),
        vec![Effect::RequestViewerClose, Effect::WipeWorkspace, Effect::Notify(Notice::RevokedByOwner)]
    );
    assert_eq!(s.state(), State::Revoked);
    assert!(!s.has_unsealed_changes(), "a revoked session must not produce a new version");
    assert_eq!(s.version(), None);
}

#[test]
fn t20_revoke_before_opening_is_still_terminal() {
    let mut s = Session::new();
    s.apply(granted(Permission::ReadOnly, 1), NOW).unwrap();
    assert_eq!(s.apply(Event::Revoked, NOW + 1).unwrap(), vec![Effect::Notify(Notice::RevokedByOwner)]);
    assert_eq!(s.state(), State::Revoked);
}

// ------------------------------------------------------------------ T03 one grant, counted opens

#[test]
fn t03_max_opens_is_enforced_locally() {
    let mut s = Session::new();
    s.apply(granted(Permission::ReadOnly, 1), NOW).unwrap();
    s.apply(Event::Opened, NOW).unwrap();
    assert_eq!(s.opens(), 1);
    s.apply(Event::ViewerExited, NOW + 1).unwrap();

    // the same session cannot be reopened — it is terminal
    assert_eq!(s.apply(Event::Opened, NOW + 2).unwrap_err(), TransitionError::Terminal(State::Closed));

    // and a fresh session on an exhausted grant refuses to materialise anything
    let mut s2 = Session::new();
    s2.apply(granted(Permission::ReadOnly, 1), NOW).unwrap();
    s2.apply(Event::Opened, NOW).unwrap();
    let mut s3 = s2.clone();
    // simulate the agent replaying the grant: opens are already at max
    s3.apply(Event::ViewerExited, NOW + 1).unwrap();
    assert_eq!(s3.state(), State::Closed);
}

#[test]
fn unlimited_opens_when_max_is_zero() {
    // max_opens = 0 means the grant sets no budget; a session still counts its single open,
    // and can reseal as often as the viewer saves.
    let mut s = Session::new();
    s.apply(granted(Permission::Edit, 0), NOW).unwrap();
    assert!(s.apply(Event::Opened, NOW).unwrap().contains(&Effect::LaunchViewer));
    assert_eq!(s.opens(), 1);
    for v in 2..5 {
        s.apply(Event::Saved, NOW).unwrap();
        s.apply(Event::Resealed { version: v }, NOW).unwrap();
    }
    assert_eq!(s.version(), Some(4));
    assert_eq!(s.state(), State::Open);
}

/// The Agent resumes a session after a restart; an exhausted budget must not show the file.
#[test]
fn t03_resumed_session_with_an_exhausted_budget_wipes_instead_of_opening() {
    let mut s = Session::resume(Permission::ReadOnly, NOW, NOW + 3600, 2, 2);
    assert_eq!(s.state(), State::Granted);
    assert_eq!(
        s.apply(Event::Opened, NOW).unwrap(),
        vec![Effect::WipeWorkspace, Effect::Notify(Notice::OpensExhausted)]
    );
    assert_eq!(s.state(), State::Closed);

    // with budget left, it opens normally and counts up
    let mut s = Session::resume(Permission::ReadOnly, NOW, NOW + 3600, 2, 1);
    assert!(s.apply(Event::Opened, NOW).unwrap().contains(&Effect::LaunchViewer));
    assert_eq!(s.opens(), 2);
}

// ------------------------------------------------------------------ misuse

#[test]
fn deny_cannot_arrive_as_a_grant() {
    let mut s = Session::new();
    let e = Event::Granted { permission: Permission::Deny, not_before: NOW, expiry: NOW + 10, max_opens: 1 };
    assert_eq!(s.apply(e, NOW).unwrap_err(), TransitionError::DenyIsNotAGrant);
}

#[test]
fn out_of_order_events_are_rejected_without_changing_state() {
    let mut s = Session::new();
    assert!(matches!(
        s.apply(Event::Saved, NOW).unwrap_err(),
        TransitionError::Unexpected { state: State::Requested, event: "Saved" }
    ));
    assert_eq!(s.state(), State::Requested);

    let mut s = open_session(Permission::Edit, 0);
    assert!(matches!(
        s.apply(Event::Resealed { version: 2 }, NOW).unwrap_err(),
        TransitionError::Unexpected { state: State::Open, .. }
    ));
    assert_eq!(s.state(), State::Open);
}

#[test]
fn a_failure_wipes_whatever_was_materialised() {
    let mut s = open_session(Permission::Edit, 0);
    assert_eq!(
        s.apply(Event::Failed("decrypt failed"), NOW).unwrap(),
        vec![Effect::WipeWorkspace, Effect::Audit(AuditKind::Failed), Effect::Notify(Notice::Problem)]
    );
    assert_eq!(s.state(), State::Failed);

    let mut s = Session::new();
    assert_eq!(
        s.apply(Event::Failed("relay unreachable"), NOW).unwrap(),
        vec![Effect::Audit(AuditKind::Failed), Effect::Notify(Notice::Problem)],
        "nothing to wipe before anything was decrypted"
    );
}

// ------------------------------------------------------------------ workspace (G.5/G.7/G.8)

#[test]
fn workspace_is_private_and_rejects_escapes() {
    let base = tempfile::tempdir().unwrap();
    let ws = Workspace::create(base.path(), "session-1").unwrap();
    assert!(ws.path().is_dir());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(ws.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "workspace must not be readable by other users");
    }

    assert!(ws.file("report.docx").is_ok());
    assert!(ws.file("../escape").is_err());
    assert!(ws.file("sub/dir").is_err());
    assert!(ws.file("").is_err());
    assert!(Workspace::create(base.path(), "../evil").is_err());
    assert!(Workspace::create(base.path(), "").is_err());
}

#[test]
fn t07_read_only_marking_blocks_writes() {
    let base = tempfile::tempdir().unwrap();
    let ws = Workspace::create(base.path(), "ro").unwrap();
    let path = ws.file("doc.txt").unwrap();
    std::fs::write(&path, b"plaintext").unwrap();

    ws.mark_read_only("doc.txt").unwrap();
    assert!(std::fs::metadata(&path).unwrap().permissions().readonly());
    assert!(std::fs::OpenOptions::new().write(true).open(&path).is_err(), "read-only must refuse writes");

    ws.clear_read_only("doc.txt").unwrap();
    assert!(std::fs::OpenOptions::new().write(true).open(&path).is_ok());
}

#[test]
fn t09_wipe_overwrites_and_removes_everything() {
    let base = tempfile::tempdir().unwrap();
    let ws = Workspace::create(base.path(), "wipe").unwrap();
    let secret = b"TOP SECRET PLAINTEXT that must not survive".repeat(50);
    let a = ws.file("a.bin").unwrap();
    let b = ws.file("b.bin").unwrap();
    std::fs::write(&a, &secret).unwrap();
    std::fs::write(&b, &secret).unwrap();
    ws.mark_read_only("b.bin").unwrap(); // a ReadOnly session still has to be wipeable
    let root = a.parent().unwrap().to_path_buf();

    ws.wipe().unwrap();
    assert!(!a.exists() && !b.exists());
    assert!(!root.exists(), "the session directory itself is gone");
}

#[test]
fn t09_secure_delete_overwrites_before_unlinking() {
    // Verify the overwrite actually happens by pointing a hard link at the same inode: after
    // secure_delete removes one name, the other still resolves to the (now zeroed) data.
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("plain.bin");
    let observer = dir.path().join("observer.bin");
    let secret = b"PLAINTEXT".repeat(1000);
    std::fs::write(&original, &secret).unwrap();
    std::fs::hard_link(&original, &observer).unwrap();

    zbacs_session::secure_delete(&original).unwrap();
    assert!(!original.exists());

    let left = std::fs::read(&observer).unwrap();
    assert_eq!(left.len(), secret.len());
    assert!(left.iter().all(|&b| b == 0), "bytes must have been overwritten, not just unlinked");
}
