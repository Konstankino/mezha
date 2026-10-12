//! `inventory`: every skill that loads in this project is one a person
//! reviewed, and none is shadowed (OWASP AST06, AST09). Claude Code prefers
//! a personal skill to a project skill with the same name, so a file in
//! `~/.claude/skills` can replace what the repository reviewed: that
//! fails. Skills from outside the repository that `policy.external_skills`
//! doesn't list warn, and so does an enabled plugin verify can't find. A
//! listed skill pinned to a fingerprint fails when any file in it changes
//! (AST01, AST07); one listed without a pin warns, with the pin to add.
//! Plugin skills are namespaced (`plugin:skill`), and a project agent beats
//! a personal one, so neither can shadow the project's.

use std::collections::BTreeMap;

use mezha_render::Rendered;
use mezha_render::state::fingerprint;
use mezha_spec::Spec;

use crate::inventory::{Inventory, ItemKind, Source};
use crate::report::{Check, Findings, Kind};

/// The latest skill eval of each skill, as (stamp, SKILL.md fingerprint).
pub type LastEvals = BTreeMap<String, (String, String)>;

/// Reads `skill-evals.jsonl`: for each skill, the newest row that records
/// the SKILL.md it measured.
pub fn last_evals(store: &std::path::Path) -> LastEvals {
    let mut last = LastEvals::new();
    let text = std::fs::read_to_string(store.join("skill-evals.jsonl")).unwrap_or_default();
    for row in text
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
    {
        let field = |k: &str| row.get(k).and_then(|v| v.as_str()).map(str::to_string);
        let (Some(skill), Some(stamp), Some(sha)) =
            (field("skill"), field("stamp"), field("skill_sha"))
        else {
            continue;
        };
        if last.get(&skill).is_none_or(|(s, _)| *s < stamp) {
            last.insert(skill, (stamp, sha));
        }
    }
    last
}

pub fn check(inventory: &Inventory, spec: &Spec, rendered: &Rendered, evals: &LastEvals) -> Check {
    let check = Check::new(
        "inventory",
        "every skill that loads is reviewed",
        Kind::Integrity,
    );
    let mut f = Findings::default();
    let skills = || inventory.items.iter().filter(|i| i.kind == ItemKind::Skill);
    let project: Vec<&str> = skills()
        .filter(|i| i.source == Source::Project)
        .map(|i| i.name.as_str())
        .collect();

    let mut unlisted = Vec::new();
    let mut unpinned = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for item in skills().filter(|i| i.source != Source::Project) {
        let name = match (&item.plugin, item.source) {
            (Some(id), Source::Plugin) => {
                format!("{}:{}", id.split('@').next().unwrap_or(id), item.name)
            }
            _ => item.name.clone(),
        };
        seen.push(name.clone());
        let digest = item.digest.as_deref().unwrap_or("-");
        let listed = spec.policy.external().find(|(n, _)| *n == name);
        if item.source == Source::User && project.contains(&item.name.as_str()) {
            f.fail(
                format!(
                    "{} shadows the project's skill `{}`: Claude Code loads the personal one instead",
                    item.path, item.name
                ),
                "Rename or remove the personal skill.",
            );
        } else if let Some((_, Some(pin))) = listed {
            if pin != digest {
                f.fail(
                    format!(
                        "skill `{name}` ({}) changed since it was reviewed: pinned {pin}, now {digest}",
                        item.path.trim_end_matches("/SKILL.md")
                    ),
                    "Read what changed; if it is fine, put the new fingerprint in policy.external_skills.",
                );
            }
        } else if listed.is_some() {
            unpinned.push(format!("{name}@{digest}"));
        } else if !spec.skill.contains_key(&name) {
            unlisted.push(format!("{name}@{digest}"));
        }
    }
    if !unlisted.is_empty() {
        unlisted.sort();
        unlisted.dedup();
        f.warn(
            format!(
                "skill(s) from outside the repository load here without review: {}",
                unlisted.join(", ")
            ),
            Some(
                "Read each one, then list it in policy.external_skills as shown (name@fingerprint), or remove or disable it."
                    .into(),
            ),
        );
    }
    if !unpinned.is_empty() {
        unpinned.sort();
        f.warn(
            format!(
                "external skill(s) listed without a fingerprint, so a change wouldn't be noticed: {}",
                unpinned.join(", ")
            ),
            Some("List them as shown in policy.external_skills.".into()),
        );
    }
    for (name, _) in spec.policy.external() {
        if inventory.outside && !seen.iter().any(|s| s == name) {
            f.warn(
                format!("policy.external_skills lists `{name}`, which doesn't load here"),
                Some("Remove it, or install the skill.".into()),
            );
        }
    }
    // An eval's results describe the text it ran (OWASP AST08).
    for (name, (stamp, sha)) in evals {
        let path = format!(".claude/skills/{name}/SKILL.md");
        if let Some(text) = rendered.files.get(&path)
            && fingerprint(text) != *sha
        {
            f.warn(
                format!("skill `{name}` changed since its last eval ({stamp}), so those results describe the old text"),
                Some(format!("Run `mezha skill eval {name}`.")),
            );
        }
    }
    for id in &inventory.missing_plugins {
        f.warn(
            format!("plugin {id} is enabled, but verify couldn't find it on disk to scan"),
            None,
        );
    }
    let count = |source| skills().filter(|i| i.source == source).count();
    f.into_check(
        check,
        &format!(
            "{} project, {} personal and {} plugin skill(s), all reviewed",
            count(Source::Project),
            count(Source::User),
            count(Source::Plugin)
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::last_evals;

    #[test]
    fn last_evals_keep_the_newest_complete_row() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("skill-evals.jsonl"),
            concat!(
                "{\"v\":1,\"skill\":\"fmt\",\"stamp\":\"20270102T000000Z\",\"skill_sha\":\"sha256:new\"}\n",
                "{\"v\":1,\"skill\":\"fmt\",\"stamp\":\"20270101T000000Z\",\"skill_sha\":\"sha256:old\"}\n",
                "{\"v\":1,\"skill\":\"fmt\",\"stamp\":\"20270103T000000Z\"}\n",
                "{\"v\":1,\"skill\":\"lint\",\"stamp\":\"20270101T000000Z\",\"skill_sha\":\"sha256:l\"}\n",
                "not json\n",
            ),
        )
        .unwrap();
        let last = last_evals(tmp.path());
        assert_eq!(
            last.get("fmt"),
            Some(&("20270102T000000Z".to_string(), "sha256:new".to_string())),
            "{last:?}"
        );
        assert_eq!(
            last.get("lint").map(|(stamp, _)| stamp.as_str()),
            Some("20270101T000000Z"),
            "{last:?}"
        );
        assert!(last_evals(&tmp.path().join("missing")).is_empty());
    }
}
