//! Confirmation policy: when the OS must verify the person before a key is used (T23).
//!
//! Spec §1.5 default: an `Edit` approval, or more than `burst_limit` approvals inside
//! `burst_window_secs`, requires OS user verification regardless of signer kind.

use zbacs_core::Permission;

use crate::types::{ApprovalContext, Confirmation};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmationPolicy {
    /// `Edit` grants always go through the OS prompt.
    pub edit_requires_confirmation: bool,
    /// More than this many approvals inside the window triggers the OS prompt.
    pub burst_limit: u32,
    pub burst_window_secs: u64,
}

impl Default for ConfirmationPolicy {
    fn default() -> Self {
        Self { edit_requires_confirmation: true, burst_limit: 5, burst_window_secs: 600 }
    }
}

impl ConfirmationPolicy {
    /// Decide the confirmation for one approval.
    ///
    /// * `device_setting` — what the owner chose for this device ("이 기기에서 바로 승인" =
    ///   `NotRequired`, "얼굴/지문으로 확인하고 승인" = `OsUserVerification`).
    /// * `recent_approval_ts` — Unix timestamps of this device's earlier approvals.
    ///
    /// The result is never weaker than `device_setting`.
    pub fn required(
        &self,
        ctx: &ApprovalContext,
        device_setting: Confirmation,
        recent_approval_ts: &[u64],
        now: u64,
    ) -> Confirmation {
        if device_setting == Confirmation::OsUserVerification {
            return Confirmation::OsUserVerification;
        }
        if self.edit_requires_confirmation && ctx.permission == Permission::Edit {
            return Confirmation::OsUserVerification;
        }
        let window_start = now.saturating_sub(self.burst_window_secs);
        let recent = recent_approval_ts.iter().filter(|&&t| t >= window_start && t <= now).count();
        if recent as u32 >= self.burst_limit {
            return Confirmation::OsUserVerification;
        }
        Confirmation::NotRequired
    }
}
