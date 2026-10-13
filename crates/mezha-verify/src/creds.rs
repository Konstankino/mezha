//! Which credentials that can push to a forge are within reach of a
//! sandboxed command. Each source is withheld, reachable, or unknown; the
//! inventory never reads a secret, only whether one is there.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::ctx::{Ctx, Platform};
use crate::gitcfg::GitConfig;
use crate::hosts::Remote;
use crate::layers::Layers;

/// Token variables that push to a forge.
const FORGE_ENV: [&str; 9] = [
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "GITHUB_ENTERPRISE_TOKEN",
    "HOMEBREW_GITHUB_API_TOKEN",
    "GITLAB_TOKEN",
    "GL_TOKEN",
    "CI_JOB_TOKEN",
    "GITEA_TOKEN",
];

/// Variables that point at a socket or handle which hands out credentials.
const HANDLE_ENV: [&str; 5] = [
    "SSH_AUTH_SOCK",
    "VSCODE_GIT_IPC_HANDLE",
    "VSCODE_GIT_ASKPASS_MAIN",
    "VSCODE_GIT_ASKPASS_NODE",
    "WSL_INTEROP",
];

/// Credential files a push can use, relative to home.
const FORGE_FILES: [&str; 8] = [
    "~/.git-credentials",
    "~/.config/git/credentials",
    "~/.netrc",
    "~/.ssh",
    "~/.config/gh",
    "~/.config/glab-cli",
    "~/.config/hub",
    "~/.gcm",
];

#[derive(Debug, Clone, Default)]
pub struct Inventory {
    pub reachable: Vec<String>,
    pub unknown: Vec<String>,
    /// The kinds of source looked at, for a clean verdict's message.
    pub checked: Vec<&'static str>,
    /// `gh` is logged in, so GitHub's endpoints count as push targets.
    pub gh_logged_in: bool,
}

/// What the effective sandbox settings withhold.
#[derive(Debug, Clone, Default)]
pub struct Withheld {
    pub paths: Vec<PathBuf>,
    pub env: Vec<String>,
    /// Unix sockets are reachable (`allowAllUnixSockets` or an allowlist).
    pub sockets_open: bool,
}

impl Withheld {
    pub fn from_layers(ctx: &Ctx, layers: &Layers) -> Withheld {
        let mut w = Withheld::default();
        let disabled = layers
            .every("/sandbox/filesystem/disabled")
            .any(|(v, l)| v == &Value::Bool(true) && !l.scope.is_repository());
        let resolve = |p: &str| ctx.resolve(p);
        for (entry, _) in layers.every("/sandbox/credentials/files") {
            for item in entry.as_array().into_iter().flatten() {
                if item["mode"] == "deny"
                    && let Some(path) = item["path"].as_str().and_then(resolve)
                    && !disabled
                {
                    w.paths.push(path);
                }
            }
        }
        if !disabled {
            for (path, _) in layers.strings("/sandbox/filesystem/denyRead") {
                if let Some(path) = resolve(path) {
                    w.paths.push(path);
                }
            }
        }
        for (entry, _) in layers.every("/sandbox/credentials/envVars") {
            for item in entry.as_array().into_iter().flatten() {
                if item["mode"] == "deny"
                    && let Some(name) = item["name"].as_str()
                {
                    w.env.push(name.to_string());
                }
            }
        }
        let all_sockets = layers
            .every("/sandbox/network/allowAllUnixSockets")
            .any(|(v, l)| v == &Value::Bool(true) && layers.loosens(l));
        let some_sockets = layers
            .strings("/sandbox/network/allowUnixSockets")
            .iter()
            .any(|(_, l)| layers.loosens(l));
        w.sockets_open = all_sockets || some_sockets;
        w
    }

    pub fn covers(&self, path: &Path, fold_case: bool) -> bool {
        let norm = |p: &Path| {
            let s = p.to_string_lossy().replace('\\', "/");
            let s = s.trim_end_matches('/').to_string();
            if fold_case { s.to_lowercase() } else { s }
        };
        let target = norm(path);
        self.paths.iter().any(|d| {
            let d = norm(d);
            target == d || target.starts_with(&format!("{d}/"))
        })
    }

    pub fn covers_env(&self, name: &str) -> bool {
        self.env.iter().any(|n| n == name)
    }
}

/// Builds the inventory. `git` is `None` when git's configuration couldn't
/// be read; with `project_only`, nothing machine-specific is looked at.
pub fn inventory(
    ctx: &Ctx,
    withheld: &Withheld,
    git: Option<&GitConfig>,
    project_only: bool,
) -> Inventory {
    let mut inv = Inventory::default();
    if project_only {
        return inv;
    }
    let fold = ctx.platform.folds_case();

    inv.checked.push("environment");
    for (name, value) in &ctx.vars {
        if value.is_empty() || withheld.covers_env(name) {
            continue;
        }
        if FORGE_ENV.contains(&name.as_str()) || looks_like_forge_token(name) {
            inv.reachable.push(format!("environment variable {name}"));
        } else if HANDLE_ENV.contains(&name.as_str()) && withheld.sockets_open {
            inv.unknown
                .push(format!("{name} (unix sockets are allowed)"));
        }
    }

    inv.checked.push("credential files");
    let mut candidates: Vec<(PathBuf, String)> = FORGE_FILES
        .iter()
        .filter_map(|p| ctx.expand(p).map(|path| (path, (*p).to_string())))
        .collect();
    if let Some(dir) = ctx.var("GH_CONFIG_DIR") {
        candidates.push((PathBuf::from(dir), "GH_CONFIG_DIR".into()));
    }
    if let Some(xdg) = ctx.var("XDG_CONFIG_HOME") {
        for sub in ["gh", "git/credentials", "hub", "glab-cli"] {
            candidates.push((Path::new(xdg).join(sub), format!("XDG_CONFIG_HOME/{sub}")));
        }
    }
    // The Windows user profiles, where Windows git, gh and ssh keep theirs.
    // compile withholds the whole tree; these show when it doesn't apply.
    if matches!(ctx.platform, Platform::Wsl2 | Platform::Wsl1) {
        for user in std::fs::read_dir("/mnt/c/Users")
            .into_iter()
            .flatten()
            .flatten()
        {
            for sub in [
                ".ssh",
                ".git-credentials",
                "_netrc",
                "AppData/Roaming/GitHub CLI",
            ] {
                let path = user.path().join(sub);
                candidates.push((path.clone(), path.display().to_string()));
            }
        }
    }
    for (path, label) in &candidates {
        if path.exists() && !withheld.covers(path, fold) {
            inv.reachable
                .push(format!("{label} (not withheld from the sandbox)"));
        }
    }

    let gh_hosts = gh_hosts_file(ctx);
    if let Some(hosts) = &gh_hosts {
        inv.gh_logged_in = true;
        let in_file = std::fs::read_to_string(hosts)
            .map(|t| t.contains("oauth_token:"))
            .unwrap_or(false);
        if !in_file {
            match ctx.platform {
                Platform::MacOs => inv
                    .reachable
                    .push("gh's token in the macOS keychain, which the sandbox can't hide".into()),
                Platform::Linux | Platform::Wsl2 | Platform::Wsl1 => inv
                    .unknown
                    .push("gh's token in the system keyring (blocked only if the sandbox blocks unix sockets)".into()),
                _ => {}
            }
        }
    }

    inv.checked.push("git config");
    match git {
        None => inv
            .unknown
            .push("git's configuration couldn't be read".into()),
        Some(cfg) => {
            for url in cfg.push_urls().iter().chain(&cfg.rewrite_bases()) {
                if Remote::parse(url).has_secret {
                    inv.reachable
                        .push("a credential written into a remote URL in git config".into());
                    break;
                }
            }
            if cfg.extra_headers() > 0 {
                inv.reachable
                    .push("http.extraHeader in git config (often an auth header)".into());
            }
            if cfg.get("core.askpass").is_some_and(|v| !v.is_empty()) {
                inv.unknown.push("core.askPass in git config".into());
            }
            inv.checked.push("credential helpers");
            for helper in cfg.helpers() {
                match classify_helper(&helper, ctx, withheld, cfg, gh_hosts.is_some()) {
                    Reach::Withheld => {}
                    Reach::Reachable(why) => inv.reachable.push(why),
                    Reach::Unknown(why) => inv.unknown.push(why),
                }
            }
        }
    }
    inv.reachable.dedup();
    inv.unknown.dedup();
    inv
}

/// The forge token variables set in the context.
pub fn forge_token_vars(ctx: &Ctx) -> Vec<String> {
    ctx.vars
        .iter()
        .filter(|(name, value)| {
            !value.is_empty()
                && (FORGE_ENV.contains(&name.as_str()) || looks_like_forge_token(name))
        })
        .map(|(name, _)| name.clone())
        .collect()
}

/// The file a `store --file PATH` credential helper keeps, if it is one.
pub fn store_helper_file(helper: &str) -> Option<String> {
    let program = first_word(helper);
    let base = program.rsplit(['/', '\\']).next().unwrap_or(&program);
    matches!(base, "store" | "git-credential-store").then(|| store_file(helper))?
}

fn looks_like_forge_token(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let forge = ["GITHUB", "GH_", "GITLAB", "GITEA", "BITBUCKET", "FORGEJO"]
        .iter()
        .any(|f| upper.contains(f));
    let secret = ["TOKEN", "PASSWORD", "SECRET", "_PAT", "API_KEY"]
        .iter()
        .any(|s| upper.contains(s));
    forge && secret
}

pub(crate) fn gh_hosts_file(ctx: &Ctx) -> Option<PathBuf> {
    gh_hosts_path(ctx).filter(|hosts| hosts.exists())
}

/// Where gh keeps its hosts file, whether or not it is there.
pub(crate) fn gh_hosts_path(ctx: &Ctx) -> Option<PathBuf> {
    let dir = ctx
        .var("GH_CONFIG_DIR")
        .map(PathBuf::from)
        .or_else(|| ctx.var("XDG_CONFIG_HOME").map(|x| Path::new(x).join("gh")))
        .or_else(|| ctx.expand("~/.config/gh"))?;
    Some(dir.join("hosts.yml"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reach {
    Withheld,
    Reachable(String),
    Unknown(String),
}

/// What a sandboxed command could get out of one credential helper.
pub fn classify_helper(
    helper: &str,
    ctx: &Ctx,
    withheld: &Withheld,
    cfg: &GitConfig,
    gh_logged_in: bool,
) -> Reach {
    let helper = helper.trim();
    let platform = ctx.platform;
    let fold = platform.folds_case();
    let socket = |what: &str| {
        if platform == Platform::MacOs && !withheld.sockets_open {
            Reach::Withheld
        } else {
            Reach::Unknown(format!(
                "{what}: blocked only if the sandbox blocks unix sockets (on Linux that needs its seccomp filter)"
            ))
        }
    };
    if let Some(shell) = helper.strip_prefix('!') {
        if shell.contains("auth git-credential") {
            return gh_helper(platform, gh_logged_in);
        }
        return Reach::Unknown(format!(
            "a shell credential helper (`!{}`)",
            first_word(shell)
        ));
    }
    let program = first_word(helper);
    let base = program
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&program)
        .to_ascii_lowercase();
    let base = base.strip_suffix(".exe").unwrap_or(&base);
    let name = base.strip_prefix("git-credential-").unwrap_or(base);
    let via_windows = program.contains("/mnt/") || program.to_ascii_lowercase().ends_with(".exe");
    match name {
        "osxkeychain" if platform == Platform::MacOs => Reach::Reachable(
            "credential helper osxkeychain: the macOS keychain is reachable from the sandbox"
                .into(),
        ),
        "osxkeychain" => Reach::Withheld,
        "manager" | "manager-core" => match platform {
            Platform::MacOs => Reach::Reachable(
                "Git Credential Manager, which keeps tokens in the macOS keychain".into(),
            ),
            Platform::Wsl2 | Platform::Wsl1 if via_windows => {
                Reach::Unknown("Git Credential Manager through Windows interop".into())
            }
            Platform::Linux | Platform::Wsl2 | Platform::Wsl1 => {
                match cfg.get("credential.credentialstore") {
                    Some("secretservice" | "cache") => socket("Git Credential Manager"),
                    Some("gpg") => file_store(
                        ctx,
                        withheld,
                        "~/.password-store",
                        "Git Credential Manager (gpg store)",
                    ),
                    Some("plaintext") => file_store(
                        ctx,
                        withheld,
                        "~/.gcm",
                        "Git Credential Manager (plaintext store)",
                    ),
                    _ => Reach::Unknown(
                        "Git Credential Manager with an unknown credential store".into(),
                    ),
                }
            }
            _ => Reach::Withheld,
        },
        "store" => {
            let file = store_file(helper);
            let files: Vec<PathBuf> = match file {
                Some(f) => ctx.expand(&f).into_iter().collect(),
                None => ["~/.git-credentials", "~/.config/git/credentials"]
                    .iter()
                    .filter_map(|p| ctx.expand(p))
                    .collect(),
            };
            match files
                .iter()
                .find(|p| p.exists() && !withheld.covers(p, fold))
            {
                Some(p) => Reach::Reachable(format!(
                    "credential helper store: {} is not withheld from the sandbox",
                    p.display()
                )),
                None => Reach::Withheld,
            }
        }
        "cache" => socket("credential helper cache"),
        "libsecret" | "gnome-keyring" if platform != Platform::MacOs => {
            socket(&format!("credential helper {name}"))
        }
        "wincred" if matches!(platform, Platform::Wsl2 | Platform::Wsl1) => {
            Reach::Unknown("wincred through Windows interop".into())
        }
        "libsecret" | "gnome-keyring" | "wincred" => Reach::Withheld,
        "gh" => gh_helper(platform, gh_logged_in),
        other => Reach::Unknown(format!("credential helper `{other}`")),
    }
}

fn gh_helper(platform: Platform, gh_logged_in: bool) -> Reach {
    match platform {
        _ if !gh_logged_in => Reach::Withheld,
        Platform::MacOs => Reach::Reachable(
            "credential helper gh: its token sits in the macOS keychain, which the sandbox can't hide"
                .into(),
        ),
        _ => Reach::Unknown("credential helper gh (keyring or hosts file)".into()),
    }
}

fn file_store(ctx: &Ctx, withheld: &Withheld, path: &str, what: &str) -> Reach {
    match ctx.expand(path) {
        Some(p) if p.exists() && !withheld.covers(&p, ctx.platform.folds_case()) => {
            Reach::Reachable(format!("{what}: {} is not withheld", p.display()))
        }
        _ => Reach::Withheld,
    }
}

/// The first word of a helper command, honouring double quotes.
fn first_word(text: &str) -> String {
    let text = text.trim_start();
    if let Some(rest) = text.strip_prefix('"') {
        return rest.split('"').next().unwrap_or("").to_string();
    }
    text.split_whitespace().next().unwrap_or("").to_string()
}

/// `store --file=PATH` or `store --file PATH`.
fn store_file(helper: &str) -> Option<String> {
    let mut words = helper.split_whitespace();
    while let Some(w) = words.next() {
        if let Some(f) = w.strip_prefix("--file=") {
            return Some(f.to_string());
        }
        if w == "--file" {
            return words.next().map(str::to_string);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::{Layer, Layers, Scope};
    use serde_json::json;

    fn ctx(platform: Platform) -> Ctx {
        Ctx {
            root: PathBuf::from("/work/repo"),
            vars: Default::default(),
            home: Some(PathBuf::from("/nonexistent-home")),
            platform,
            managed_dir: None,
            mezha_exe: None,
            agent_writable: Vec::new(),
        }
    }

    /// A context whose home is a scratch directory, with `vars` on top.
    fn ctx_at(home: &Path, platform: Platform, vars: &[(&str, &str)]) -> Ctx {
        Ctx {
            home: Some(home.to_path_buf()),
            vars: vars
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..ctx(platform)
        }
    }

    fn cfg(entries: &[(&str, &str)]) -> GitConfig {
        let text: String = entries
            .iter()
            .map(|(k, v)| format!("global\0file:/h/.gitconfig\0{k}\n{v}\0"))
            .collect();
        GitConfig::parse(&text)
    }

    fn layers(scope: Scope, value: Value) -> Layers {
        Layers {
            layers: vec![Layer {
                scope,
                label: format!("{scope:?}"),
                value,
            }],
            ..Layers::default()
        }
    }

    /// Unix only, as the sandbox is: on Windows the paths join with `\`.
    #[cfg(unix)]
    #[test]
    fn deny_read_paths_count_unless_the_filesystem_sandbox_is_off() {
        let c = ctx(Platform::Linux);
        let settings = json!({
            "sandbox": {
                "filesystem": { "denyRead": ["~/private", "secrets", "//etc/keys"] },
                "credentials": {
                    "files": [{ "path": "~/.netrc", "mode": "deny" }, { "path": "~/x", "mode": "mask" }],
                    "envVars": [{ "name": "GH_TOKEN", "mode": "deny" }, { "name": "X", "mode": "mask" }]
                }
            }
        });
        let w = Withheld::from_layers(&c, &layers(Scope::User, settings.clone()));
        let paths: Vec<String> = w.paths.iter().map(|p| p.display().to_string()).collect();
        assert_eq!(
            paths,
            [
                "/nonexistent-home/.netrc",
                "/nonexistent-home/private",
                "/work/repo/secrets",
                "/etc/keys"
            ]
        );
        assert_eq!(w.env, ["GH_TOKEN"]);
        assert!(!w.sockets_open);

        // With the filesystem sandbox off in user settings, no path is withheld.
        let mut off = settings.clone();
        off["sandbox"]["filesystem"]["disabled"] = json!(true);
        let w = Withheld::from_layers(&c, &layers(Scope::User, off.clone()));
        assert!(w.paths.is_empty(), "{:?}", w.paths);
        assert_eq!(w.env, ["GH_TOKEN"]);
        // From the repository, Claude Code ignores it.
        let w = Withheld::from_layers(&c, &layers(Scope::Local, off));
        assert_eq!(w.paths.len(), 4, "{:?}", w.paths);
    }

    #[test]
    fn sockets_count_as_open_only_where_the_setting_takes_effect() {
        let c = ctx(Platform::Linux);
        let all = json!({ "sandbox": { "network": { "allowAllUnixSockets": true } } });
        assert!(Withheld::from_layers(&c, &layers(Scope::User, all.clone())).sockets_open);
        let some = json!({ "sandbox": { "network": { "allowUnixSockets": ["/run/x"] } } });
        assert!(Withheld::from_layers(&c, &layers(Scope::Local, some)).sockets_open);
        // A repository setting under an admin-required sandbox doesn't loosen.
        let locked = Layers {
            layers: vec![
                Layer {
                    scope: Scope::Local,
                    label: "local".into(),
                    value: all,
                },
                Layer {
                    scope: Scope::Managed,
                    label: "managed".into(),
                    value: json!({ "sandbox": { "allowUnsandboxedCommands": false } }),
                },
            ],
            ..Layers::default()
        };
        assert!(!Withheld::from_layers(&c, &locked).sockets_open);
    }

    #[test]
    fn the_inventory_reads_the_environment_and_home() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let ghcfg = tmp.path().join("ghcfg");
        let xdg = tmp.path().join("xdg");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&ghcfg).unwrap();
        std::fs::create_dir_all(xdg.join("hub")).unwrap();
        std::fs::write(home.join(".netrc"), "machine h login u password p\n").unwrap();
        std::fs::write(ghcfg.join("hosts.yml"), "github.com:\n    user: me\n").unwrap();
        let vars = [
            ("GH_TOKEN", "t"),
            ("GITHUB_TOKEN", "withheld"),
            ("MY_GITLAB_PASSWORD", "p"),
            ("EMPTY_GITHUB_TOKEN", ""),
            ("SSH_AUTH_SOCK", "/run/agent"),
            ("GH_CONFIG_DIR", ghcfg.to_str().unwrap()),
            ("XDG_CONFIG_HOME", xdg.to_str().unwrap()),
        ];
        let withheld = Withheld {
            env: vec!["GITHUB_TOKEN".into()],
            sockets_open: true,
            ..Withheld::default()
        };
        let inv = inventory(
            &ctx_at(&home, Platform::MacOs, &vars),
            &withheld,
            None,
            false,
        );
        assert_eq!(
            inv.reachable,
            [
                "environment variable GH_TOKEN",
                "environment variable MY_GITLAB_PASSWORD",
                "~/.netrc (not withheld from the sandbox)",
                "GH_CONFIG_DIR (not withheld from the sandbox)",
                "XDG_CONFIG_HOME/hub (not withheld from the sandbox)",
                "gh's token in the macOS keychain, which the sandbox can't hide",
            ]
        );
        assert_eq!(
            inv.unknown,
            [
                "SSH_AUTH_SOCK (unix sockets are allowed)",
                "git's configuration couldn't be read",
            ]
        );
        assert!(inv.gh_logged_in);
        assert_eq!(
            inv.checked,
            ["environment", "credential files", "git config"]
        );

        // On a platform without a keychain or keyring to speak of, a login
        // without a token in the file adds nothing.
        let inv = inventory(
            &ctx_at(&home, Platform::Windows, &vars[5..6]),
            &Withheld::default(),
            None,
            false,
        );
        assert!(inv.gh_logged_in);
        assert!(
            !inv.reachable.iter().any(|r| r.contains("gh's token")),
            "{:?}",
            inv.reachable
        );
        // A token in the hosts file itself is a file, not a keychain entry.
        std::fs::write(
            ghcfg.join("hosts.yml"),
            "github.com:\n    oauth_token: gho_x\n",
        )
        .unwrap();
        let inv = inventory(
            &ctx_at(&home, Platform::MacOs, &vars[5..6]),
            &Withheld::default(),
            None,
            false,
        );
        assert!(inv.gh_logged_in);
        assert!(
            !inv.reachable.iter().any(|r| r.contains("gh's token")),
            "{:?}",
            inv.reachable
        );
        // Withheld, the same file doesn't count.
        let withheld = Withheld {
            paths: vec![home.join(".netrc")],
            ..Withheld::default()
        };
        let inv = inventory(&ctx_at(&home, Platform::Linux, &[]), &withheld, None, false);
        assert!(inv.reachable.is_empty(), "{:?}", inv.reachable);
        assert!(
            inventory(&ctx(Platform::Linux), &withheld, None, true)
                .checked
                .is_empty()
        );
    }

    #[test]
    fn the_inventory_reads_git_config() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let git = cfg(&[
            ("remote.origin.url", "https://x:tok@github.com/o/r.git"),
            ("http.extraheader", "AUTHORIZATION: basic x"),
            ("core.askpass", "/usr/bin/ask"),
            ("credential.helper", "osxkeychain"),
            ("credential.helper", "mystery"),
        ]);
        let inv = inventory(
            &ctx_at(&home, Platform::Linux, &[]),
            &Withheld::default(),
            Some(&git),
            false,
        );
        assert_eq!(
            inv.reachable,
            [
                "a credential written into a remote URL in git config",
                "http.extraHeader in git config (often an auth header)",
            ]
        );
        assert_eq!(
            inv.unknown,
            ["core.askPass in git config", "credential helper `mystery`"]
        );
        assert_eq!(
            inv.checked,
            [
                "environment",
                "credential files",
                "git config",
                "credential helpers"
            ]
        );
    }

    #[test]
    fn store_helper_files() {
        assert_eq!(
            store_helper_file("store --file=/x/creds").as_deref(),
            Some("/x/creds")
        );
        assert_eq!(
            store_helper_file("git-credential-store --file /y").as_deref(),
            Some("/y")
        );
        assert_eq!(
            store_helper_file("/usr/libexec/git-core/git-credential-store --file=~/z").as_deref(),
            Some("~/z")
        );
        assert_eq!(store_helper_file("store"), None);
        assert_eq!(store_helper_file("cache --file=/x"), None);
        assert_eq!(store_helper_file("!f() { :; }; f --file=/x"), None);
    }

    #[test]
    fn manager_on_linux_depends_on_its_store() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir_all(home.join(".password-store")).unwrap();
        let c = ctx_at(&home, Platform::Linux, &[]);
        let with = |store: &str| {
            classify_helper(
                "manager",
                &c,
                &Withheld::default(),
                &cfg(&[("credential.credentialstore", store)]),
                false,
            )
        };
        assert!(matches!(with("secretservice"), Reach::Unknown(_)));
        assert!(matches!(with("cache"), Reach::Unknown(_)));
        let gpg = with("gpg");
        let Reach::Reachable(why) = &gpg else {
            panic!("{gpg:?}");
        };
        assert!(
            why.contains("gpg store") && why.contains(".password-store is not withheld"),
            "{why}"
        );
        // The plaintext store's file isn't there.
        assert_eq!(with("plaintext"), Reach::Withheld);
        std::fs::create_dir_all(home.join(".gcm")).unwrap();
        assert!(matches!(with("plaintext"), Reach::Reachable(_)));
        // Withheld by the settings, it has nothing to give.
        let withheld = Withheld {
            paths: vec![home.join(".gcm")],
            ..Withheld::default()
        };
        assert_eq!(
            classify_helper(
                "manager-core",
                &c,
                &withheld,
                &cfg(&[("credential.credentialstore", "plaintext")]),
                false
            ),
            Reach::Withheld
        );
        let unknown = with("something-else");
        assert!(
            matches!(&unknown, Reach::Unknown(why) if why.contains("unknown credential store")),
            "{unknown:?}"
        );
        // WSL without Windows interop reads like Linux.
        let wsl = ctx_at(&home, Platform::Wsl2, &[]);
        assert!(matches!(
            classify_helper(
                "manager",
                &wsl,
                &Withheld::default(),
                &GitConfig::default(),
                false
            ),
            Reach::Unknown(_)
        ));
        assert_eq!(classify("manager", Platform::Windows), Reach::Withheld);
    }

    #[test]
    fn store_with_a_file_and_the_remaining_helpers() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let creds = home.join("creds");
        std::fs::write(&creds, "https://x:t@h\n").unwrap();
        let c = ctx_at(&home, Platform::Linux, &[]);
        let helper = format!("store --file={}", creds.display());
        let reach = classify_helper(
            &helper,
            &c,
            &Withheld::default(),
            &GitConfig::default(),
            false,
        );
        let Reach::Reachable(why) = &reach else {
            panic!("{reach:?}");
        };
        assert_eq!(
            why,
            &format!(
                "credential helper store: {} is not withheld from the sandbox",
                creds.display()
            )
        );
        assert_eq!(
            classify_helper(
                "store --file ~/missing",
                &c,
                &Withheld::default(),
                &GitConfig::default(),
                false
            ),
            Reach::Withheld
        );
        assert!(matches!(
            classify("wincred", Platform::Wsl2),
            Reach::Unknown(_)
        ));
        assert_eq!(classify("wincred", Platform::Linux), Reach::Withheld);
        assert_eq!(classify("libsecret", Platform::MacOs), Reach::Withheld);
        assert_eq!(classify("gnome-keyring", Platform::MacOs), Reach::Withheld);
        assert!(matches!(
            classify("gnome-keyring", Platform::Windows),
            Reach::Unknown(_)
        ));
        // gh: nothing without a login; a keyring question elsewhere than macOS.
        assert_eq!(
            classify_helper("gh", &c, &Withheld::default(), &GitConfig::default(), false),
            Reach::Withheld
        );
        assert!(matches!(
            classify_helper("gh", &c, &Withheld::default(), &GitConfig::default(), true),
            Reach::Unknown(_)
        ));
        assert!(matches!(
            classify("!gh auth git-credential", Platform::Linux),
            Reach::Unknown(_)
        ));
    }

    fn classify(helper: &str, platform: Platform) -> Reach {
        classify_helper(
            helper,
            &ctx(platform),
            &Withheld::default(),
            &GitConfig::default(),
            true,
        )
    }

    #[test]
    fn helpers_by_platform() {
        assert!(matches!(
            classify("osxkeychain", Platform::MacOs),
            Reach::Reachable(_)
        ));
        assert_eq!(classify("osxkeychain", Platform::Linux), Reach::Withheld);
        assert!(matches!(
            classify("manager", Platform::MacOs),
            Reach::Reachable(_)
        ));
        assert!(matches!(
            classify(
                "/mnt/c/Program Files/Git/mingw64/bin/git-credential-manager.exe",
                Platform::Wsl2
            ),
            Reach::Unknown(_)
        ));
        assert!(matches!(
            classify(
                "\"/mnt/c/Program Files/Git/git-credential-manager.exe\"",
                Platform::Wsl2
            ),
            Reach::Unknown(_)
        ));
        assert_eq!(
            classify("cache --timeout=300", Platform::MacOs),
            Reach::Withheld
        );
        assert!(matches!(
            classify("cache", Platform::Linux),
            Reach::Unknown(_)
        ));
        assert!(matches!(
            classify("libsecret", Platform::Linux),
            Reach::Unknown(_)
        ));
        assert!(matches!(
            classify("!/opt/homebrew/bin/gh auth git-credential", Platform::MacOs),
            Reach::Reachable(_)
        ));
        assert!(matches!(
            classify("!f() { echo x; }; f", Platform::Linux),
            Reach::Unknown(_)
        ));
        assert!(matches!(
            classify("something-custom", Platform::Linux),
            Reach::Unknown(_)
        ));
        // store with no file on disk has nothing to give.
        assert_eq!(classify("store", Platform::Linux), Reach::Withheld);
    }

    #[test]
    fn store_file_option() {
        assert_eq!(
            store_file("store --file=/x/creds").as_deref(),
            Some("/x/creds")
        );
        assert_eq!(store_file("store --file /y").as_deref(), Some("/y"));
        assert_eq!(store_file("store"), None);
    }

    #[test]
    fn covers_paths_and_children() {
        let w = Withheld {
            paths: vec![PathBuf::from("/h/.ssh"), PathBuf::from("/h/.netrc")],
            ..Withheld::default()
        };
        assert!(w.covers(Path::new("/h/.ssh/id_ed25519"), false));
        assert!(w.covers(Path::new("/h/.netrc"), false));
        assert!(!w.covers(Path::new("/h/.sshx"), false));
        assert!(w.covers(Path::new("/H/.SSH"), true));
        assert!(!w.covers(Path::new("/H/.SSH"), false));
    }

    #[test]
    fn forge_token_names() {
        assert!(looks_like_forge_token("MY_GITHUB_PAT"));
        assert!(looks_like_forge_token("GITLAB_API_TOKEN"));
        assert!(!looks_like_forge_token("CLAUDE_CODE_OAUTH_TOKEN"));
        assert!(!looks_like_forge_token("GITHUB_REPOSITORY"));
    }
}
