//! `bodies`: the agent, skill, rule and command files Claude loads hold no
//! hidden characters, secrets, chat-template tokens, remote images, raw
//! HTML or shell run at load (OWASP AST01, AST04, AST08), whoever wrote
//! them. A file in the project fails; one in the user's or a plugin's
//! directory warns, since the repository can't fix it. Advisory: the scans
//! are patterns, so a person still reads every change.

use crate::inventory::{Coverage, Inventory, MAX_FILES, Source};
use crate::report::{Check, Findings, Kind};

const FIX_PROJECT: &str = "Remove it from the file (for a file mezha generates, from its body under mezha/, then run `mezha compile`), and read the file: scans are patterns.";
const FIX_ELSEWHERE: &str =
    "Remove or fix the file, or uninstall what put it there; it loads in every project.";

pub fn check(inventory: &Inventory, spec: &mezha_spec::Spec) -> Check {
    let fetch = spec.fetch_allow().ok().flatten();
    let check = Check::new(
        "bodies",
        "agent, skill, rule and command files are clean",
        Kind::Advisory,
    );
    let mut f = Findings::default();
    for item in &inventory.items {
        let found = || format!("{}: {}", item.path, item.findings.join(", "));
        match (item.scan, item.source) {
            (Coverage::Fail, Source::Project) => f.fail(found(), FIX_PROJECT),
            (Coverage::Fail, _) => f.warn(found(), Some(FIX_ELSEWHERE.into())),
            (Coverage::Incomplete, _) => f.warn(
                format!("{} (incomplete: the scan couldn't look inside)", found()),
                None,
            ),
            (Coverage::Pass, _) => {}
        }
        // A project file's links must stay inside fetch_allow (AST05).
        if let Some(allowed) = &fetch
            && item.source == Source::Project
        {
            let outside: Vec<&str> = item
                .links
                .iter()
                .map(String::as_str)
                .filter(|h| !allowed.iter().any(|a| a.matches(h)))
                .collect();
            if !outside.is_empty() {
                f.fail(
                    format!(
                        "{} links to {}, which policy.fetch_allow doesn't list",
                        item.path,
                        outside.join(", ")
                    ),
                    "Copy what Claude needs into the file, or list the host in policy.fetch_allow.",
                );
            }
        }
        if !item.phrases.is_empty() {
            f.warn(
                format!(
                    "{} reads like instructions to a model: {}",
                    item.path,
                    item.phrases.join(", ")
                ),
                Some("Read those lines; reword them if they aren't meant for Claude.".into()),
            );
        }
    }
    if inventory.truncated {
        f.warn(
            format!("stopped after {MAX_FILES} files or 8 directories deep: incomplete"),
            None,
        );
    }
    let ok = format!(
        "{} file(s) scanned: no hidden text, secrets, raw HTML or shell run at load",
        inventory.items.len()
    );
    f.into_check(check, &ok)
}
