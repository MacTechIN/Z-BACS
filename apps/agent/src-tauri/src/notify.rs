//! Z-1.U.5 — the approval notification, answerable from the notification itself (U-3: the
//! owner allows or refuses within ten seconds, without finding the window).
//!
//! On Windows the toast carries the same three buttons as the S5 screen (allow read-only,
//! allow edit, refuse), and pressing one runs the very same answer path the screen runs
//! ([`crate::approve`]'s command), OS confirmation and all: T23 is not weakened by the
//! shortcut. Elsewhere the notification has no buttons and says so: it brings the person to
//! the window.
//!
//! The notification never carries more than the S5 screen would (T06): the file's name comes
//! from this machine's record, the other party is "누군가", nothing technical. What is shown
//! is a [`Plan`], a plain value, so the wording and the buttons can be tested without an OS.

use std::sync::Arc;

use tauri::{AppHandle, Manager};

use crate::approve::{DecisionArg, Incoming};

/// Which Windows app the toast is attributed to. Tauri registers the bundle identifier as the
/// process AUMID; a Start Menu shortcut from the installer makes Windows show toasts for it.
/// A dev build with no shortcut can borrow PowerShell's id (`ZBACS_TOAST_POWERSHELL=1`).
pub const APP_ID: &str = "dev.zbacs.agent";

/// One button on the notification. `action` is what comes back when it is pressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Button {
    /// Words on the button.
    pub label: String,
    /// `decision:<request id>` or `open:<request id>`.
    pub action: String,
}

/// What the notification says and offers. Pure data: built by [`plan_for`], tested there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// First line.
    pub title: String,
    /// Second line.
    pub body: String,
    /// Buttons, in order. Empty when the platform cannot show any.
    pub buttons: Vec<Button>,
}

/// What a pressed button means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Answer the request with this decision.
    Decide {
        /// Request nonce, hex.
        id: String,
        /// The answer.
        decision: DecisionArg,
    },
    /// Bring the window forward on this request.
    Open {
        /// Request nonce, hex.
        id: String,
    },
}

/// The notification for a request that just arrived.
pub fn plan_for(incoming: &Incoming) -> Plan {
    let wants = if incoming.requested == "edit" {
        "편집도 하고 싶어 해요"
    } else {
        "읽기만 하고 싶어 해요"
    };
    let body = match &incoming.file_name {
        Some(name) if incoming.can_allow => format!("\"{name}\" 파일을 {wants}."),
        Some(name) => format!("\"{name}\" 파일 — 그 뒤로 바뀐 파일이라 앱에서 확인해 주세요."),
        None => "이 컴퓨터에서 잠근 기록이 없는 파일이에요. 앱에서 확인해 주세요.".to_string(),
    };
    let mut buttons = Vec::new();
    if incoming.can_allow {
        buttons
            .push(Button { label: "읽기만 허락".into(), action: format!("read_only:{}", incoming.id) });
        buttons.push(Button { label: "편집도 허락".into(), action: format!("edit:{}", incoming.id) });
    }
    buttons.push(Button { label: "거절".into(), action: format!("deny:{}", incoming.id) });
    buttons.push(Button { label: "앱에서 보기".into(), action: format!("open:{}", incoming.id) });
    Plan { title: "누군가 내 파일을 열려고 해요".into(), body, buttons }
}

/// The notification after the person answered from a toast, so they see it took.
pub fn plan_after(decision: DecisionArg, file_name: Option<&str>) -> Plan {
    let name = file_name.map(|n| format!("\"{n}\" 파일")).unwrap_or_else(|| "그 파일".into());
    let (title, body) = match decision {
        DecisionArg::Deny => ("거절했어요", format!("{name}은 열 수 없다고 알려 줬어요.")),
        DecisionArg::ReadOnly => ("허락했어요", format!("{name}을 읽기만 할 수 있어요.")),
        DecisionArg::Edit => ("허락했어요", format!("{name}을 편집까지 할 수 있어요.")),
    };
    Plan { title: title.into(), body, buttons: Vec::new() }
}

/// The notification when answering from the toast did not work; the window is the way on.
pub fn plan_problem() -> Plan {
    Plan {
        title: "답을 보내지 못했어요".into(),
        body: "앱을 열어 다시 시도해 주세요.".into(),
        buttons: Vec::new(),
    }
}

/// What a button's action string means. `None` for anything else (a click on the body).
pub fn parse_action(action: &str) -> Option<Action> {
    let (verb, id) = action.split_once(':')?;
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let id = id.to_string();
    match verb {
        "read_only" => Some(Action::Decide { id, decision: DecisionArg::ReadOnly }),
        "edit" => Some(Action::Decide { id, decision: DecisionArg::Edit }),
        "deny" => Some(Action::Decide { id, decision: DecisionArg::Deny }),
        "open" => Some(Action::Open { id }),
        _ => None,
    }
}

/// Shows notifications. Vendors behind an interface (CLAUDE.md rule 6): Windows toasts with
/// buttons, or the plain notification of other desktops.
pub trait Notifier: Send + Sync {
    /// Whether buttons on the notification actually work here.
    fn has_buttons(&self) -> bool;
    /// Show it; `on_action` is called with the pressed button's action string.
    fn show(&self, plan: &Plan, on_action: Arc<dyn Fn(String) + Send + Sync>);
}

/// Windows: a toast with buttons, answered in place.
#[cfg(windows)]
pub struct WindowsToast;

#[cfg(windows)]
impl Notifier for WindowsToast {
    fn has_buttons(&self) -> bool {
        true
    }

    fn show(&self, plan: &Plan, on_action: Arc<dyn Fn(String) + Send + Sync>) {
        use tauri_winrt_notification::{Duration, Scenario, Toast};
        let app_id = if std::env::var_os("ZBACS_TOAST_POWERSHELL").is_some() {
            Toast::POWERSHELL_APP_ID
        } else {
            APP_ID
        };
        let mut toast = Toast::new(app_id)
            .title(&plan.title)
            .text1(&plan.body)
            .duration(Duration::Long)
            .scenario(Scenario::Reminder);
        for b in &plan.buttons {
            toast = toast.add_button(&b.label, &b.action);
        }
        let toast = toast.on_activated(move |arg| {
            on_action(arg.unwrap_or_default());
            Ok(())
        });
        if let Err(e) = toast.show() {
            log::warn!("cannot show the toast: {e}");
        }
    }
}

/// Everywhere else: the desktop's plain notification. No buttons, so the body says to open the
/// app, and a click on it brings the window forward.
pub struct PlainNotification {
    app: AppHandle,
}

impl Notifier for PlainNotification {
    fn has_buttons(&self) -> bool {
        false
    }

    fn show(&self, plan: &Plan, _on_action: Arc<dyn Fn(String) + Send + Sync>) {
        use tauri_plugin_notification::NotificationExt;
        let body = if plan.buttons.is_empty() {
            plan.body.clone()
        } else {
            format!("{} 앱에서 답해 주세요.", plan.body)
        };
        if let Err(e) = self.app.notification().builder().title(&plan.title).body(&body).show() {
            log::warn!("cannot show the notification: {e}");
        }
    }
}

/// The notifier for this platform.
pub fn notifier(app: &AppHandle) -> Arc<dyn Notifier> {
    #[cfg(windows)]
    {
        let _ = app;
        Arc::new(WindowsToast)
    }
    #[cfg(not(windows))]
    {
        Arc::new(PlainNotification { app: app.clone() })
    }
}

/// A request arrived: notify, and wire the buttons to the same decision path as the screen.
pub fn announce(app: &AppHandle, incoming: &Incoming) {
    let plan = plan_for(incoming);
    let handle = app.clone();
    let file_name = incoming.file_name.clone();
    let on_action: Arc<dyn Fn(String) + Send + Sync> = Arc::new(move |action| {
        let handle = handle.clone();
        let file_name = file_name.clone();
        match parse_action(&action) {
            Some(Action::Decide { id, decision }) => {
                log::info!("answered from the notification: {}", decision.word());
                tauri::async_runtime::spawn(async move {
                    let plan = match crate::approve::decide(handle.clone(), id, decision).await {
                        Ok(_) => plan_after(decision, file_name.as_deref()),
                        Err(e) => {
                            log::warn!("the notification's answer did not go through: {e}");
                            show_window(&handle);
                            plan_problem()
                        }
                    };
                    notifier(&handle).show(&plan, Arc::new(|_| {}));
                });
            }
            Some(Action::Open { .. }) | None => show_window(&handle),
        }
    });
    notifier(app).show(&plan, on_action);
}

fn show_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn incoming(known: bool, same_version: bool, requested: &'static str) -> Incoming {
        Incoming {
            id: "0a0b".into(),
            file_name: known.then(|| "brief.docx".to_string()),
            known,
            same_version,
            requested,
            default_permission: known.then(|| "read_only".to_string()),
            asked_at: 1_700_000_000,
            can_allow: known && same_version,
        }
    }

    /// U-3: the three answers are on the notification, wired to the request they belong to.
    #[test]
    fn u3_a_request_this_machine_can_allow_gets_all_three_answers() {
        let plan = plan_for(&incoming(true, true, "edit"));
        assert_eq!(plan.title, "누군가 내 파일을 열려고 해요");
        assert!(plan.body.contains("\"brief.docx\"") && plan.body.contains("편집도"));
        let actions: Vec<_> = plan.buttons.iter().map(|b| b.action.as_str()).collect();
        assert_eq!(actions, ["read_only:0a0b", "edit:0a0b", "deny:0a0b", "open:0a0b"]);
        assert_eq!(
            parse_action(&plan.buttons[1].action),
            Some(Action::Decide { id: "0a0b".into(), decision: DecisionArg::Edit })
        );
    }

    /// T06: a file this machine did not lock cannot be allowed from the toast either.
    #[test]
    fn t06_an_unknown_file_offers_only_refusal_and_the_app() {
        let plan = plan_for(&incoming(false, false, "read_only"));
        assert!(plan.body.contains("잠근 기록이 없는"));
        let labels: Vec<_> = plan.buttons.iter().map(|b| b.label.as_str()).collect();
        assert_eq!(labels, ["거절", "앱에서 보기"]);

        let other_version = plan_for(&incoming(true, false, "read_only"));
        assert!(other_version.body.contains("바뀐 파일"));
        assert_eq!(other_version.buttons.len(), 2);
    }

    #[test]
    fn only_well_formed_actions_are_accepted() {
        assert_eq!(parse_action("open:ff"), Some(Action::Open { id: "ff".into() }));
        assert_eq!(
            parse_action("deny:ff"),
            Some(Action::Decide { id: "ff".into(), decision: DecisionArg::Deny })
        );
        assert_eq!(parse_action(""), None);
        assert_eq!(parse_action("read_only:"), None);
        assert_eq!(parse_action("read_only:not-hex"), None);
        assert_eq!(parse_action("delete:ff"), None);
    }

    #[test]
    fn the_follow_up_says_what_was_done() {
        assert_eq!(plan_after(DecisionArg::ReadOnly, Some("a.docx")).title, "허락했어요");
        assert!(plan_after(DecisionArg::ReadOnly, Some("a.docx")).body.contains("읽기만"));
        assert_eq!(plan_after(DecisionArg::Deny, None).title, "거절했어요");
        assert!(plan_after(DecisionArg::Edit, None).buttons.is_empty());
    }
}
