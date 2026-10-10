//! `settings-layers`: does any settings file switch mezha's hook off or
//! override its guard rails?

use serde_json::Value;

use mezha_render::settings::GIT_GUARD_ENV;

use crate::Options;
use crate::ctx::Ctx;
use crate::layers::{Layers, Scope};
use crate::report::{Check, Findings, Kind};

pub fn check(ctx: &Ctx, layers: &Layers, opts: &Options) -> Check {
    let check = Check::new(
        "settings-layers",
        "no settings file weakens the gate",
        Kind::Integrity,
    );
    let mut f = Findings::default();

    for problem in &layers.problems {
        f.warn(
            format!("{problem}; Claude Code may ignore it or refuse to start"),
            Some("Fix or remove the file.".into()),
        );
    }
    if let Some((Value::Bool(true), layer)) = layers.winner("/disableAllHooks")
        && layer.scope != Scope::Managed
    {
        f.fail(
            format!("disableAllHooks in {} turns mezha's gate off", layer.label),
            format!("Remove disableAllHooks from {}.", layer.label),
        );
    }
    for (v, layer) in layers.every("/disableAllHooks") {
        if layer.scope == Scope::Managed && v == &Value::Bool(true) {
            f.fail(
                format!("managed settings ({}) disable all hooks", layer.label),
                "Ask your administrator.",
            );
        }
    }
    for (v, layer) in layers.every("/allowManagedHooksOnly") {
        if layer.scope == Scope::Managed && v == &Value::Bool(true) {
            f.fail(
                format!(
                    "allowManagedHooksOnly in {} blocks project hooks, mezha's gate included",
                    layer.label
                ),
                "Ask your administrator to deliver the gate through managed settings, or to lift the lock.",
            );
        }
    }
    // A `false` above the project file lets skills and commands run shell
    // when they load again (OWASP AST04); a managed `true` can't be undone.
    let managed_on = layers
        .every("/disableSkillShellExecution")
        .any(|(v, l)| l.scope == Scope::Managed && v == &Value::Bool(true));
    if let Some((Value::Bool(false), layer)) = layers.winner("/disableSkillShellExecution")
        && !managed_on
    {
        f.fail(
            format!(
                "disableSkillShellExecution is false in {}, so skills and commands can run shell commands when they load",
                layer.label
            ),
            format!("Remove disableSkillShellExecution from {}.", layer.label),
        );
    }
    for (key, expected) in GIT_GUARD_ENV {
        if let Some((v, layer)) = layers.winner(&format!("/env/{key}"))
            && layer.scope != Scope::Project
            && v.as_str() != Some(expected)
        {
            f.warn(
                format!(
                    "{key} in {} overrides mezha's git guard rail (advisory)",
                    layer.label
                ),
                Some(format!("Remove {key} from {}.", layer.label)),
            );
        }
    }
    if !opts.project_only && ctx.var("GIT_CONFIG_COUNT").is_some() {
        f.warn(
            "GIT_CONFIG_COUNT is set in your environment; inside Claude Code mezha's guard rail replaces it, so its entries are lost",
            None,
        );
    }
    if let Some((Value::String(mode), layer)) = layers.winner("/permissions/defaultMode")
        && (mode == "bypassPermissions" || mode == "auto")
    {
        f.warn(
            format!(
                "defaultMode is {mode} in {}: ask rules (git push) still prompt, other rules are skipped",
                layer.label
            ),
            None,
        );
    }
    for source in &layers.unchecked {
        f.warn(format!("{source} exists, and verify can't read it"), None);
    }
    let read = layers.layers.len();
    f.into_check(
        check,
        &format!("nothing switches the gate off ({read} settings file(s) read)"),
    )
}
