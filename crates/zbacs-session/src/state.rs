//! Z-1.G.4 — the session state machine.
//!
//! A session is the life of one approval: request → grant → open → save/close. Every rule that
//! decides whether plaintext may exist right now lives here, in one place that can be tested
//! without a filesystem, a viewer or a chain:
//!
//! - a grant is consumed once (T03) and only within its window (T15);
//! - `maxOpens` is counted locally, because the on-chain counter is advisory (Z-1.H.2);
//! - a revoke closes the session immediately, and so does expiry (T20);
//! - `ReadOnly` never produces a new version; `Edit` must reseal before it can close (T07).
//!
//! The Agent drives it: it feeds events in and does what the returned [`Effect`]s say.

use std::fmt;

use zbacs_core::Permission;

/// Where a session is right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Request sent to the owner; nothing is decrypted.
    Requested,
    /// Owner refused. Terminal.
    Denied,
    /// Grant in hand, DEK available, nothing written yet.
    Granted,
    /// Plaintext is in the workspace and a viewer may be running.
    Open,
    /// An `Edit` session saved; the container is being resealed.
    Resealing,
    /// Everything is cleaned up. Terminal.
    Closed,
    /// Ended early because the owner pulled access. Terminal.
    Revoked,
    /// Ended because something went wrong. Terminal.
    Failed,
}

impl State {
    /// Whether plaintext may exist on disk in this state.
    pub fn plaintext_allowed(self) -> bool {
        matches!(self, State::Open | State::Resealing)
    }

    /// No further events are accepted.
    pub fn is_terminal(self) -> bool {
        matches!(self, State::Denied | State::Closed | State::Revoked | State::Failed)
    }
}

/// What happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The owner approved: permission, window and open budget from the grant.
    Granted {
        /// Approved permission (`Deny` arrives as [`Event::Denied`] instead).
        permission: Permission,
        /// Unix seconds the grant becomes valid.
        not_before: u64,
        /// Unix seconds the grant expires.
        expiry: u64,
        /// 0 means unlimited.
        max_opens: u16,
    },
    /// The owner refused.
    Denied,
    /// The agent decrypted into the workspace and is about to show the file.
    Opened,
    /// The viewer wrote the file.
    Saved,
    /// Resealing finished; the container is now at this version.
    Resealed {
        /// New container version number.
        version: u32,
    },
    /// The viewer process exited.
    ViewerExited,
    /// A revoke arrived (relay push or a chain event).
    Revoked,
    /// The clock passed the grant's expiry.
    Expired,
    /// Something failed; the reason is shown to the person and logged.
    Failed(&'static str),
}

/// What the Agent must do as a result of a transition. Ordered: do them in sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Decrypt into the protected workspace.
    MaterialisePlaintext,
    /// Make the workspace file read-only (ReadOnly grants).
    MarkReadOnly,
    /// Start the viewer application.
    LaunchViewer,
    /// Ask the viewer to close (revoke / expiry while open).
    RequestViewerClose,
    /// Reseal the edited plaintext as a new container version.
    Reseal,
    /// Throw away what the viewer wrote (ReadOnly saved anyway).
    DiscardChanges,
    /// Securely delete the plaintext and remove the workspace.
    WipeWorkspace,
    /// Record an audit entry for the step just taken.
    Audit(AuditKind),
    /// Tell the person why the session ended.
    Notify(Notice),
}

/// Audit entries this machine asks for (mirrors `AuditLog.Kind` on chain).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditKind {
    /// Access was requested.
    Requested,
    /// The owner refused.
    Denied,
    /// The file was opened.
    Opened,
    /// A new version was sealed.
    Sealed,
    /// The session failed.
    Failed,
}

/// User-facing notices. The wording lives in the UI string table (Z-1.U.4); this is the code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice {
    /// "이 파일은 열 수 없습니다" — the owner refused.
    Refused,
    /// "읽기 전용이라 변경 내용은 저장되지 않았습니다".
    ChangesDiscarded,
    /// "소유자가 접근을 회수했습니다".
    RevokedByOwner,
    /// "허용된 시간이 끝났습니다".
    Expired,
    /// "열 수 있는 횟수를 모두 썼습니다".
    OpensExhausted,
    /// "저장한 내용을 다시 봉인했습니다".
    Resealed,
    /// Something went wrong; the Agent adds the reason.
    Problem,
}

/// Why an event could not be applied. These are programming or protocol errors, not user
/// mistakes — user-visible outcomes travel as [`Notice`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionError {
    /// The session already ended.
    Terminal(State),
    /// This event makes no sense in this state.
    Unexpected {
        /// State the session was in.
        state: State,
        /// Event that was offered.
        event: &'static str,
    },
    /// The grant's window has not opened yet.
    NotYetValid,
    /// The grant was already expired when it arrived.
    AlreadyExpired,
    /// `Deny` cannot be a `Granted` event.
    DenyIsNotAGrant,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Terminal(s) => write!(f, "session already ended in {s:?}"),
            Self::Unexpected { state, event } => write!(f, "{event} is not valid in {state:?}"),
            Self::NotYetValid => write!(f, "grant is not valid yet"),
            Self::AlreadyExpired => write!(f, "grant is already expired"),
            Self::DenyIsNotAGrant => write!(f, "a Deny decision is not a grant"),
        }
    }
}

/// One session.
#[derive(Clone, Debug)]
pub struct Session {
    state: State,
    permission: Option<Permission>,
    not_before: u64,
    expiry: u64,
    max_opens: u16,
    opens: u16,
    version: Option<u32>,
    dirty: bool,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    /// A session that has just sent its request.
    pub fn new() -> Self {
        Self {
            state: State::Requested,
            permission: None,
            not_before: 0,
            expiry: 0,
            max_opens: 0,
            opens: 0,
            version: None,
            dirty: false,
        }
    }

    /// Rebuild a granted session the Agent had already started, after a restart.
    ///
    /// The Agent persists the grant's terms and how many opens it has used; on restart it
    /// resumes here rather than re-asking the owner. An exhausted budget surfaces on the next
    /// [`Event::Opened`], which wipes instead of showing the file (T03).
    pub fn resume(permission: Permission, not_before: u64, expiry: u64, max_opens: u16, opens: u16) -> Self {
        Self {
            state: State::Granted,
            permission: Some(permission),
            not_before,
            expiry,
            max_opens,
            opens,
            version: None,
            dirty: false,
        }
    }

    /// Current state.
    pub fn state(&self) -> State {
        self.state
    }

    /// Approved permission, once granted.
    pub fn permission(&self) -> Option<Permission> {
        self.permission
    }

    /// How many opens this grant has used.
    pub fn opens(&self) -> u16 {
        self.opens
    }

    /// Container version after the last reseal.
    pub fn version(&self) -> Option<u32> {
        self.version
    }

    /// Whether the viewer wrote something that has not been resealed yet.
    pub fn has_unsealed_changes(&self) -> bool {
        self.dirty
    }

    /// True when `now` is past the grant's expiry. The caller decides which clock to trust:
    /// local time for a normal grant, chain time when the policy is `strict` (T15).
    pub fn is_expired(&self, now: u64) -> bool {
        self.permission.is_some() && now >= self.expiry
    }

    /// Feed an event in; get back the effects to perform, in order.
    pub fn apply(&mut self, event: Event, now: u64) -> Result<Vec<Effect>, TransitionError> {
        if self.state.is_terminal() {
            return Err(TransitionError::Terminal(self.state));
        }
        match (self.state, event) {
            // ------------------------------------------------ waiting for the owner
            (State::Requested, Event::Granted { permission, not_before, expiry, max_opens }) => {
                if permission == Permission::Deny {
                    return Err(TransitionError::DenyIsNotAGrant);
                }
                if now < not_before {
                    return Err(TransitionError::NotYetValid);
                }
                if now >= expiry {
                    return Err(TransitionError::AlreadyExpired);
                }
                self.permission = Some(permission);
                self.not_before = not_before;
                self.expiry = expiry;
                self.max_opens = max_opens;
                self.state = State::Granted;
                Ok(vec![Effect::MaterialisePlaintext])
            }
            (State::Requested, Event::Denied) => {
                self.state = State::Denied;
                Ok(vec![Effect::Audit(AuditKind::Denied), Effect::Notify(Notice::Refused)])
            }

            // ------------------------------------------------ opening
            (State::Granted, Event::Opened) => {
                if self.max_opens != 0 && self.opens >= self.max_opens {
                    self.state = State::Closed;
                    return Ok(vec![Effect::WipeWorkspace, Effect::Notify(Notice::OpensExhausted)]);
                }
                self.opens += 1;
                self.state = State::Open;
                let mut effects = Vec::new();
                if self.permission == Some(Permission::ReadOnly) {
                    effects.push(Effect::MarkReadOnly);
                }
                effects.push(Effect::LaunchViewer);
                effects.push(Effect::Audit(AuditKind::Opened));
                Ok(effects)
            }

            // ------------------------------------------------ while open
            (State::Open, Event::Saved) => match self.permission {
                Some(Permission::Edit) => {
                    self.dirty = true;
                    self.state = State::Resealing;
                    Ok(vec![Effect::Reseal])
                }
                // A ReadOnly workspace is read-only, but an application can still write a copy
                // next to it or defeat the attribute; throwing the change away keeps the
                // guarantee the owner was shown (T07).
                _ => Ok(vec![Effect::DiscardChanges, Effect::Notify(Notice::ChangesDiscarded)]),
            },
            (State::Resealing, Event::Resealed { version }) => {
                self.version = Some(version);
                self.dirty = false;
                self.state = State::Open;
                Ok(vec![Effect::Audit(AuditKind::Sealed), Effect::Notify(Notice::Resealed)])
            }
            (State::Open, Event::ViewerExited) => {
                self.state = State::Closed;
                Ok(vec![Effect::WipeWorkspace])
            }

            // ------------------------------------------------ ended from outside
            (_, Event::Revoked) => {
                let mut effects = Vec::new();
                if self.state.plaintext_allowed() {
                    effects.push(Effect::RequestViewerClose);
                    // Anything the viewer wrote but did not reseal is lost on purpose: the
                    // owner pulled access, so no new version may be produced.
                    effects.push(Effect::WipeWorkspace);
                }
                self.dirty = false;
                self.state = State::Revoked;
                effects.push(Effect::Notify(Notice::RevokedByOwner));
                Ok(effects)
            }
            (_, Event::Expired) => {
                let mut effects = Vec::new();
                if self.state.plaintext_allowed() {
                    effects.push(Effect::RequestViewerClose);
                    effects.push(Effect::WipeWorkspace);
                }
                self.dirty = false;
                self.state = State::Closed;
                effects.push(Effect::Notify(Notice::Expired));
                Ok(effects)
            }
            (_, Event::Failed(_)) => {
                let mut effects = Vec::new();
                if self.state.plaintext_allowed() {
                    effects.push(Effect::WipeWorkspace);
                }
                self.state = State::Failed;
                effects.push(Effect::Audit(AuditKind::Failed));
                effects.push(Effect::Notify(Notice::Problem));
                Ok(effects)
            }

            // ------------------------------------------------ anything else
            (state, event) => Err(TransitionError::Unexpected { state, event: event_name(&event) }),
        }
    }
}

fn event_name(e: &Event) -> &'static str {
    match e {
        Event::Granted { .. } => "Granted",
        Event::Denied => "Denied",
        Event::Opened => "Opened",
        Event::Saved => "Saved",
        Event::Resealed { .. } => "Resealed",
        Event::ViewerExited => "ViewerExited",
        Event::Revoked => "Revoked",
        Event::Expired => "Expired",
        Event::Failed(_) => "Failed",
    }
}
