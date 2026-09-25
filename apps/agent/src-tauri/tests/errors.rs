//! Z-1.U.4 — every error the Agent can hand the screen has a sentence and a next step.
//!
//! The backend speaks in machine values (`relay_unreachable`, `not_sealed`); the sentences
//! live in `ui/app.js` and the catalogue in `docs/design/ui_strings.md` §7. A value that one
//! of the three does not know about is a person left looking at a blank line, so this test
//! reads the other two files and refuses the drift. `tools/ux-lint.sh` checks the UI against
//! the document the same way; this test adds the backend to the triangle.

use std::collections::BTreeSet;
use std::path::Path;

use zbacs_agent_lib::approve::{APPROVE_PROBLEMS, REVOKE_PROBLEMS};
use zbacs_agent_lib::request::REQUEST_PROBLEMS;
use zbacs_agent_lib::seal::SEAL_PROBLEMS;
use zbacs_agent_lib::session::OPEN_PROBLEMS;
use zbacs_agent_lib::setup::SETUP_PROBLEMS;
use zbacs_agent_lib::INSPECT_PROBLEMS;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn all_backend_ids() -> BTreeSet<&'static str> {
    [
        INSPECT_PROBLEMS,
        SETUP_PROBLEMS,
        SEAL_PROBLEMS,
        REQUEST_PROBLEMS,
        APPROVE_PROBLEMS,
        REVOKE_PROBLEMS,
        OPEN_PROBLEMS,
    ]
    .into_iter()
    .flatten()
    .copied()
    .collect()
}

/// Keys of every `*_PROBLEMS` table in app.js.
fn ui_ids() -> BTreeSet<String> {
    let js = std::fs::read_to_string(root().join("../ui/app.js")).expect("ui/app.js");
    let mut ids = BTreeSet::new();
    let mut inside = false;
    for line in js.lines() {
        let t = line.trim();
        if t.starts_with("const ") && t.contains("_PROBLEMS = {") {
            inside = true;
            continue;
        }
        if inside && t == "};" {
            inside = false;
            continue;
        }
        if inside {
            if let Some((key, _)) = t.split_once(':') {
                let key = key.trim();
                if !key.is_empty() && key.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
                    ids.insert(key.to_string());
                }
            }
        }
    }
    ids
}

/// First column of every row in the §7 catalogue table.
fn catalogue_ids() -> BTreeSet<String> {
    let doc =
        std::fs::read_to_string(root().join("../../../docs/design/ui_strings.md")).expect("ui_strings.md");
    let mut ids = BTreeSet::new();
    let mut inside = false;
    for line in doc.lines() {
        if line.contains("ux-lint:errors:start") {
            inside = true;
            continue;
        }
        if line.contains("ux-lint:errors:end") {
            break;
        }
        if inside && line.starts_with("| `") {
            if let Some(id) = line.trim_start_matches("| `").split('`').next() {
                ids.insert(id.to_string());
            }
        }
    }
    ids
}

#[test]
fn every_backend_error_has_a_sentence_in_the_ui() {
    let ui = ui_ids();
    let missing: Vec<_> = all_backend_ids().into_iter().filter(|id| !ui.contains(*id)).collect();
    assert!(missing.is_empty(), "ui/app.js has no sentence for: {missing:?}");
}

#[test]
fn every_backend_error_is_in_the_catalogue() {
    let cat = catalogue_ids();
    assert!(!cat.is_empty(), "docs/design/ui_strings.md has no error catalogue block");
    let missing: Vec<_> = all_backend_ids().into_iter().filter(|id| !cat.contains(*id)).collect();
    assert!(missing.is_empty(), "docs/design/ui_strings.md §7 does not list: {missing:?}");
}

#[test]
fn the_catalogue_has_no_orphans() {
    let backend = all_backend_ids();
    let orphans: Vec<_> = catalogue_ids().into_iter().filter(|id| !backend.contains(id.as_str())).collect();
    assert!(orphans.is_empty(), "catalogue lists values no code produces: {orphans:?}");
}
