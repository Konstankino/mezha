//! `inventory`: every skill that loads in this project is one a person
//! reviewed, and none is shadowed (OWASP AST06, AST09). Claude Code prefers
//! a personal skill to a project skill with the same name, so a file in
//! `~/.claude/skills` can replace what the repository reviewed: that
//! fails. Skills from outside the repository that `policy.external_skills`
//! doesn't list warn, and so does an enabled plugin verify can't find.
//! Plugin skills are namespaced (`plugin:skill`), and a project agent beats
//! a personal one, so neither can shadow the project's.

use mezha_spec::Spec;

use crate::inventory::{Inventory, ItemKind, Source};
use crate::report::{Check, Findings, Kind};

pub fn check(inventory: &Inventory, spec: &Spec) -> Check {
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
    for item in skills().filter(|i| i.source != Source::Project) {
        let name = match (&item.plugin, item.source) {
            (Some(id), Source::Plugin) => {
                format!("{}:{}", id.split('@').next().unwrap_or(id), item.name)
            }
            _ => item.name.clone(),
        };
        if item.source == Source::User && project.contains(&item.name.as_str()) {
            f.fail(
                format!(
                    "{} shadows the project's skill `{}`: Claude Code loads the personal one instead",
                    item.path, item.name
                ),
                "Rename or remove the personal skill.",
            );
        } else if !spec.policy.external_skills.contains(&name) && !spec.skill.contains_key(&name) {
            unlisted.push(name);
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
                "Read each one, then list it in policy.external_skills, or remove or disable it."
                    .into(),
            ),
        );
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
