//! Claude Code's settings files, read the way Claude Code combines them:
//! user < project < local < managed for single values, every scope's
//! entries together for lists.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::ctx::{Ctx, Platform};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    User,
    Project,
    Local,
    Managed,
}

impl Scope {
    /// Settings that live in the repository.
    pub fn is_repository(self) -> bool {
        matches!(self, Scope::Project | Scope::Local)
    }
}

#[derive(Debug, Clone)]
pub struct Layer {
    pub scope: Scope,
    /// Where the file is, for messages.
    pub label: String,
    pub value: Value,
}

#[derive(Debug, Clone, Default)]
pub struct Layers {
    /// Lowest precedence first.
    pub layers: Vec<Layer>,
    /// Files that exist but couldn't be read as a JSON object.
    pub problems: Vec<String>,
    /// Policy sources verify can't read.
    pub unchecked: Vec<String>,
}

pub const PROJECT_SETTINGS: &str = ".claude/settings.json";
pub const LOCAL_SETTINGS: &str = ".claude/settings.local.json";

impl Layers {
    /// Reads every settings file that applies to a session started in the
    /// project root. With `project_only`, only the committed project file.
    pub fn load(ctx: &Ctx, project_only: bool) -> Layers {
        let mut layers = Layers::default();
        let root = &ctx.root;
        if !project_only {
            let user_dir = ctx
                .var("CLAUDE_CONFIG_DIR")
                .map(PathBuf::from)
                .or_else(|| ctx.home.as_ref().map(|h| h.join(".claude")));
            if let Some(dir) = user_dir {
                layers.read(Scope::User, &dir.join("settings.json"), None);
            }
        }
        layers.read(
            Scope::Project,
            &root.join(PROJECT_SETTINGS),
            Some(PROJECT_SETTINGS),
        );
        if !project_only {
            // The local file lives at the git root (the main checkout for a
            // worktree); a copy an older Claude Code left in the start
            // directory still counts, below it.
            let git_root = mezha_broker::repo_root(root);
            let start = std::fs::canonicalize(root).unwrap_or_else(|_| root.clone());
            let start_copy = start.join(LOCAL_SETTINGS);
            let root_copy = git_root.join(LOCAL_SETTINGS);
            if ctx.platform != Platform::Windows && start_copy != root_copy {
                layers.read(Scope::Local, &start_copy, None);
                layers.read(Scope::Local, &root_copy, None);
            } else {
                layers.read(Scope::Local, &start_copy, Some(LOCAL_SETTINGS));
            }
            if let Some(dir) = &ctx.managed_dir {
                layers.read(Scope::Managed, &dir.join("managed-settings.json"), None);
                let mut drop_ins: Vec<PathBuf> = std::fs::read_dir(dir.join("managed-settings.d"))
                    .into_iter()
                    .flatten()
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| {
                        let name = p.file_name().map(|n| n.to_string_lossy().into_owned());
                        name.is_some_and(|n| !n.starts_with('.') && n.ends_with(".json"))
                    })
                    .collect();
                drop_ins.sort();
                for path in drop_ins {
                    layers.read(Scope::Managed, &path, None);
                }
            }
            match ctx.platform {
                Platform::MacOs => {
                    let plist =
                        Path::new("/Library/Managed Preferences/com.anthropic.claudecode.plist");
                    if plist.exists() {
                        layers
                            .unchecked
                            .push(format!("MDM policy {}", plist.display()));
                    }
                }
                Platform::Windows => layers
                    .unchecked
                    .push(r"registry policy HKLM\SOFTWARE\Policies\ClaudeCode".to_string()),
                _ => {}
            }
        }
        layers
    }

    fn read(&mut self, scope: Scope, path: &Path, label: Option<&str>) {
        let label = label.map_or_else(|| path.display().to_string(), str::to_string);
        let Ok(text) = std::fs::read_to_string(path) else {
            if path.exists() {
                self.problems.push(format!("{label} can't be read"));
            }
            return;
        };
        match serde_json::from_str::<Value>(&text) {
            Ok(value @ Value::Object(_)) => self.layers.push(Layer {
                scope,
                label,
                value,
            }),
            Ok(_) => self.problems.push(format!("{label} is not a JSON object")),
            Err(e) => self
                .problems
                .push(format!("{label} is not valid JSON ({e})")),
        }
    }

    /// The value Claude Code uses for a single setting: the most specific
    /// layer that sets it.
    pub fn winner(&self, pointer: &str) -> Option<(&Value, &Layer)> {
        self.layers
            .iter()
            .rev()
            .find_map(|l| l.value.pointer(pointer).map(|v| (v, l)))
    }

    /// Every layer's value for a setting, lowest precedence first.
    pub fn every<'a>(
        &'a self,
        pointer: &'a str,
    ) -> impl Iterator<Item = (&'a Value, &'a Layer)> + 'a {
        self.layers
            .iter()
            .filter_map(move |l| l.value.pointer(pointer).map(|v| (v, l)))
    }

    /// The string entries of a list setting, from every layer.
    pub fn strings<'a>(&'a self, pointer: &'a str) -> Vec<(&'a str, &'a Layer)> {
        self.every(pointer)
            .flat_map(|(v, l)| {
                v.as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(move |s| (s, l))
            })
            .collect()
    }

    /// Where an agent may write besides the project and `TMPDIR`:
    /// `sandbox.filesystem.allowWrite` and the `Edit(...)` allow rules
    /// (Claude Code adds those to the sandbox's writable paths too), from
    /// every scope. A glob is cut back to the text before its first
    /// wildcard.
    pub fn agent_writable(&self, ctx: &Ctx) -> Vec<PathBuf> {
        let cut = |p: &str| p.find(['*', '?', '[']).map_or(p, |i| &p[..i]).to_string();
        let mut paths: Vec<PathBuf> = self
            .strings("/sandbox/filesystem/allowWrite")
            .into_iter()
            .filter_map(|(p, _)| ctx.resolve(&cut(p)))
            .collect();
        for (rule, _) in self.strings("/permissions/allow") {
            let Some(p) = rule.strip_prefix("Edit(").and_then(|r| r.strip_suffix(')')) else {
                continue;
            };
            // In a rule, `/x` is relative to the project and `//x` absolute.
            let p = cut(p);
            let p = match p.strip_prefix('/') {
                Some(rest) if !rest.starts_with('/') => rest.to_string(),
                _ => p,
            };
            paths.extend(ctx.resolve(&p));
        }
        paths.sort();
        paths.dedup();
        paths
    }

    /// While managed settings forbid unsandboxed commands or lock the
    /// domains, Claude Code ignores repository settings that loosen the
    /// sandbox.
    pub fn admin_required(&self) -> bool {
        self.layers.iter().any(|l| {
            l.scope == Scope::Managed
                && (l.value.pointer("/sandbox/allowUnsandboxedCommands")
                    == Some(&Value::Bool(false))
                    || l.value.pointer("/sandbox/network/allowManagedDomainsOnly")
                        == Some(&Value::Bool(true)))
        })
    }

    /// Whether a loosening value from `layer` takes effect.
    pub fn loosens(&self, layer: &Layer) -> bool {
        !(layer.scope.is_repository() && self.admin_required())
    }

    /// Like [`Layers::winner`], ignoring repository layers whose value
    /// loosens the sandbox while it is admin-required.
    pub fn winner_for_loosening(
        &self,
        pointer: &str,
        loosening: &Value,
    ) -> Option<(&Value, &Layer)> {
        self.layers.iter().rev().find_map(|l| {
            let v = l.value.pointer(pointer)?;
            (v != loosening || self.loosens(l)).then_some((v, l))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn layer(scope: Scope, value: Value) -> Layer {
        Layer {
            scope,
            label: format!("{scope:?}"),
            value,
        }
    }

    #[test]
    fn the_most_specific_layer_wins_and_lists_combine() {
        let layers = Layers {
            layers: vec![
                layer(
                    Scope::User,
                    json!({"sandbox": {"enabled": false, "excludedCommands": ["docker"]}}),
                ),
                layer(Scope::Project, json!({"sandbox": {"enabled": true}})),
                layer(
                    Scope::Local,
                    json!({"sandbox": {"excludedCommands": ["git"]}}),
                ),
            ],
            ..Layers::default()
        };
        let (v, l) = layers.winner("/sandbox/enabled").unwrap();
        assert_eq!((v, l.scope), (&json!(true), Scope::Project));
        let excluded: Vec<&str> = layers
            .strings("/sandbox/excludedCommands")
            .into_iter()
            .map(|(s, _)| s)
            .collect();
        assert_eq!(excluded, ["docker", "git"]);
        assert!(!layers.admin_required());
    }

    #[test]
    fn an_admin_required_sandbox_ignores_repository_loosening() {
        let layers = Layers {
            layers: vec![
                layer(Scope::User, json!({"sandbox": {"enabled": true}})),
                layer(Scope::Local, json!({"sandbox": {"enabled": false}})),
                layer(
                    Scope::Managed,
                    json!({"sandbox": {"allowUnsandboxedCommands": false}}),
                ),
            ],
            ..Layers::default()
        };
        assert!(layers.admin_required());
        let (v, l) = layers
            .winner_for_loosening("/sandbox/enabled", &json!(false))
            .unwrap();
        assert_eq!((v, l.scope), (&json!(true), Scope::User));
    }

    #[test]
    fn agent_writable_paths() {
        let layers = Layers {
            layers: vec![
                layer(
                    Scope::User,
                    json!({"sandbox": {"filesystem": {"allowWrite": ["~/.cache/**", "/opt/out", "build"]}}}),
                ),
                layer(
                    Scope::Local,
                    json!({"permissions": {"allow": ["Edit(/docs/**)", "Edit(//srv/x/*.md)", "Read(/y)"]}}),
                ),
            ],
            ..Layers::default()
        };
        let ctx = Ctx {
            root: PathBuf::from("/w/repo"),
            vars: Default::default(),
            home: Some(PathBuf::from("/h")),
            platform: Platform::Linux,
            managed_dir: None,
            mezha_exe: None,
            agent_writable: Vec::new(),
        };
        let paths: Vec<String> = layers
            .agent_writable(&ctx)
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        assert_eq!(
            paths,
            [
                "/h/.cache/",
                "/opt/out",
                "/srv/x/",
                "/w/repo/build",
                "/w/repo/docs/"
            ]
        );
    }

    #[test]
    fn reads_files_and_reports_broken_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("repo");
        let home = tmp.path().join("home");
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(root.join(".claude")).unwrap();
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        let managed = tmp.path().join("managed");
        std::fs::create_dir_all(managed.join("managed-settings.d")).unwrap();
        std::fs::write(home.join(".claude/settings.json"), r#"{"a": 1}"#).unwrap();
        std::fs::write(root.join(PROJECT_SETTINGS), r#"{"a": 2}"#).unwrap();
        std::fs::write(root.join(LOCAL_SETTINGS), "not json").unwrap();
        std::fs::write(managed.join("managed-settings.json"), r#"{"a": 3}"#).unwrap();
        std::fs::write(managed.join("managed-settings.d/20-b.json"), r#"{"a": 5}"#).unwrap();
        std::fs::write(managed.join("managed-settings.d/10-a.json"), r#"{"a": 4}"#).unwrap();
        std::fs::write(
            managed.join("managed-settings.d/.hidden.json"),
            r#"{"a": 9}"#,
        )
        .unwrap();
        let ctx = Ctx {
            root: root.clone(),
            vars: Default::default(),
            home: Some(home),
            platform: Platform::Linux,
            managed_dir: Some(managed),
            mezha_exe: None,
            agent_writable: Vec::new(),
        };
        let layers = Layers::load(&ctx, false);
        let values: Vec<i64> = layers
            .every("/a")
            .map(|(v, _)| v.as_i64().unwrap())
            .collect();
        assert_eq!(values, [1, 2, 3, 4, 5]);
        assert_eq!(layers.problems.len(), 1, "{:?}", layers.problems);
        assert_eq!(layers.winner("/a").unwrap().0, &json!(5));

        let project_only = Layers::load(&ctx, true);
        let values: Vec<i64> = project_only
            .every("/a")
            .map(|(v, _)| v.as_i64().unwrap())
            .collect();
        assert_eq!(values, [2]);
    }
}
