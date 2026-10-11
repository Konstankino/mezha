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
