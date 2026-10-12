//! Everything verify reads from the machine, gathered in one place so tests
//! can replace it: the environment, the home directory, the platform and
//! where managed settings live.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    MacOs,
    Linux,
    Wsl2,
    Wsl1,
    Windows,
    Other,
}

impl Platform {
    pub fn detect() -> Self {
        if cfg!(target_os = "macos") {
            Platform::MacOs
        } else if cfg!(windows) {
            Platform::Windows
        } else if cfg!(target_os = "linux") {
            let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .unwrap_or_default()
                .to_lowercase();
            if release.contains("microsoft") {
                if release.contains("wsl2") || release.contains("microsoft-standard") {
                    Platform::Wsl2
                } else {
                    Platform::Wsl1
                }
            } else {
                Platform::Linux
            }
        } else {
            Platform::Other
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Platform::MacOs => "macos",
            Platform::Linux => "linux",
            Platform::Wsl2 => "wsl2",
            Platform::Wsl1 => "wsl1",
            Platform::Windows => "windows",
            Platform::Other => "other",
        }
    }

    /// Where Claude Code's sandbox exists at all.
    pub fn has_sandbox(self) -> bool {
        matches!(self, Platform::MacOs | Platform::Linux | Platform::Wsl2)
    }

    /// File systems that ignore case by default.
    pub fn folds_case(self) -> bool {
        matches!(self, Platform::MacOs | Platform::Windows)
    }
}

#[derive(Debug, Clone)]
pub struct Ctx {
    /// The project root: the directory holding `mezha.toml`.
    pub root: PathBuf,
    /// The environment verify reads and hands to the commands it runs.
    pub vars: BTreeMap<String, String>,
    pub home: Option<PathBuf>,
    pub platform: Platform,
    /// The directory holding `managed-settings.json`.
    pub managed_dir: Option<PathBuf>,
    /// The running binary, to compare with the `mezha` on PATH.
    pub mezha_exe: Option<PathBuf>,
    /// Directories sandboxed commands may write besides the project and
    /// `TMPDIR` (the effective `sandbox.filesystem.allowWrite`).
    pub agent_writable: Vec<PathBuf>,
}

impl Ctx {
    pub fn from_process(root: &Path) -> Self {
        let vars: BTreeMap<String, String> = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect();
        let home = mezha_broker::home_dir(|k| vars.get(k).cloned());
        let platform = Platform::detect();
        let managed_dir = default_managed_dir(platform, &vars);
        Ctx {
            root: root.to_path_buf(),
            vars,
            home,
            platform,
            managed_dir,
            mezha_exe: std::env::current_exe().ok(),
            agent_writable: Vec::new(),
        }
    }

    /// A variable's value; empty counts as unset.
    pub fn var(&self, key: &str) -> Option<&str> {
        self.vars
            .get(key)
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }

    /// `~/x` with the home directory filled in.
    pub fn expand(&self, path: &str) -> Option<PathBuf> {
        match path.strip_prefix("~/") {
            Some(rest) => self.home.as_ref().map(|h| h.join(rest)),
            None if path == "~" => self.home.clone(),
            None => Some(PathBuf::from(path)),
        }
    }

    /// A path from a sandbox setting: `~/` is home, `//` marks an absolute
    /// path, and a relative path is relative to the project.
    pub fn resolve(&self, path: &str) -> Option<PathBuf> {
        let path = match path.strip_prefix("//") {
            Some(rest) => PathBuf::from(format!("/{rest}")),
            None => self.expand(path)?,
        };
        Some(if path.is_relative() {
            self.root.join(path)
        } else {
            path
        })
    }

    /// The executable `name` on this context's PATH (with PATHEXT on
    /// Windows), skipping copies an agent could have put there: anything
    /// whose path or target is under the project, `TMPDIR` or a sandbox
    /// `allowWrite` path, or sits in a group- or world-writable directory.
    /// Every program verify runs is found this way.
    pub fn which_trusted(&self, name: &str) -> Found {
        let mut found = Found::default();
        for candidate in self.candidates(name) {
            match self.distrust(&candidate) {
                None => {
                    found.path = Some(candidate);
                    break;
                }
                Some(why) => found
                    .skipped
                    .push(format!("{} ({why})", candidate.display())),
            }
        }
        found
    }

    /// PATH without the directories [`Ctx::which_trusted`] distrusts, for
    /// programs that look their own helpers up on PATH (`srt` runs `node`).
    pub fn trusted_path(&self) -> String {
        let Some(path) = self.path_var() else {
            return String::new();
        };
        let dirs: Vec<PathBuf> = std::env::split_paths(path)
            .filter(|dir| self.distrust_dir(dir).is_none())
            .collect();
        std::env::join_paths(dirs)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    fn path_var(&self) -> Option<&String> {
        self.vars.get("PATH").or_else(|| self.vars.get("Path"))
    }

    /// Every executable called `name` on PATH, in order.
    fn candidates(&self, name: &str) -> Vec<PathBuf> {
        let Some(path) = self.path_var() else {
            return Vec::new();
        };
        let exts: Vec<String> = if self.platform == Platform::Windows && !name.contains('.') {
            self.var("PATHEXT")
                .unwrap_or(".COM;.EXE;.BAT;.CMD")
                .split(';')
                .filter(|e| !e.is_empty())
                .map(str::to_string)
                .collect()
        } else {
            vec![String::new()]
        };
        std::env::split_paths(path)
            .flat_map(|dir| {
                exts.iter()
                    .map(|ext| dir.join(format!("{name}{ext}")))
                    .filter(|candidate| is_executable(candidate))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Where an agent can write: the project, `TMPDIR` and the sandbox's
    /// `allowWrite` paths, each with the words used to report it.
    fn writable_bases(&self) -> Vec<(PathBuf, &'static str)> {
        let mut bases = vec![(self.root.clone(), "inside the project")];
        if let Some(tmp) = self.var("TMPDIR") {
            bases.push((PathBuf::from(tmp), "under TMPDIR"));
        }
        for dir in &self.agent_writable {
            bases.push((dir.clone(), "under a sandbox allowWrite path"));
        }
        bases
            .into_iter()
            .map(|(p, why)| (std::fs::canonicalize(&p).unwrap_or(p), why))
            .collect()
    }

    fn under_writable(&self, path: &Path) -> Option<&'static str> {
        let fold = self.platform.folds_case();
        self.writable_bases()
            .into_iter()
            .find(|(base, _)| is_under(path, base, fold))
            .map(|(_, why)| why)
    }

    /// Why a PATH directory can't be trusted, if it can't.
    fn distrust_dir(&self, dir: &Path) -> Option<&'static str> {
        if dir.is_relative() {
            return Some("a relative PATH entry");
        }
        let canonical = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
        if let Some(why) = self.under_writable(dir).or(self.under_writable(&canonical)) {
            return Some(why);
        }
        loosely_writable(&canonical, true).then_some("in a group- or world-writable directory")
    }

    /// Why a candidate program can't be trusted, if it can't. Both the PATH
    /// entry and the file it resolves to count.
    fn distrust(&self, path: &Path) -> Option<&'static str> {
        let dir = path.parent().unwrap_or(Path::new(""));
        if let Some(why) = self.distrust_dir(dir) {
            return Some(why);
        }
        let Ok(target) = std::fs::canonicalize(path) else {
            return Some("can't be resolved");
        };
        if let Some(why) = self.under_writable(&target) {
            return Some(why);
        }
        if let Some(target_dir) = target.parent()
            && loosely_writable(target_dir, true)
        {
            return Some("in a group- or world-writable directory");
        }
        loosely_writable(&target, false).then_some("group- or world-writable")
    }
}

/// A program found on PATH, and the candidates passed over on the way.
#[derive(Debug, Clone, Default)]
pub struct Found {
    pub path: Option<PathBuf>,
    /// Each skipped candidate with the reason.
    pub skipped: Vec<String>,
}

impl Found {
    /// A warning for the skipped candidates, if any.
    pub fn skipped_note(&self, name: &str) -> Option<String> {
        (!self.skipped.is_empty()).then(|| {
            format!(
                "ignored `{name}` at {}: an agent can put programs there",
                self.skipped.join(", ")
            )
        })
    }
}

fn is_under(path: &Path, base: &Path, fold: bool) -> bool {
    if fold {
        let lower = |p: &Path| PathBuf::from(p.to_string_lossy().to_lowercase());
        lower(path).starts_with(lower(base))
    } else {
        path.starts_with(base)
    }
}

/// Writable by the group or by everyone, which lets someone else replace
/// what is there. A sticky directory doesn't count, nor does a group whose
/// members could write there anyway (see [`group_is_trusted`]).
#[cfg(unix)]
fn loosely_writable(path: &Path, is_dir: bool) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let mode = meta.permissions().mode();
    if is_dir && mode & 0o1000 != 0 {
        return false;
    }
    let line = |file: &str, id: u32| -> Option<String> {
        std::fs::read_to_string(file)
            .ok()?
            .lines()
            .find(|l| l.split(':').nth(2).and_then(|f| f.parse::<u32>().ok()) == Some(id))
            .map(str::to_string)
    };
    mode & 0o002 != 0
        || (mode & 0o020 != 0
            && !group_is_trusted(
                line("/etc/group", meta.gid()).as_deref(),
                line("/etc/passwd", meta.uid()).as_deref(),
            ))
}

#[cfg(not(unix))]
fn loosely_writable(_path: &Path, _is_dir: bool) -> bool {
    false
}

/// Groups that already hold root (`admin` on macOS, which Homebrew uses;
/// `wheel` and `sudo`), and a user-private group: named after the owner
/// (from its `/etc/passwd` line) with no other members, as some Linux
/// distributions create under umask 002. A group missing from
/// `/etc/group` isn't trusted.
#[cfg_attr(not(unix), allow(dead_code))]
fn group_is_trusted(group_line: Option<&str>, owner_line: Option<&str>) -> bool {
    let Some(group) = group_line else {
        return false;
    };
    let mut fields = group.split(':');
    let name = fields.next().unwrap_or_default();
    let members = fields.nth(2).unwrap_or_default();
    if matches!(name, "root" | "wheel" | "admin" | "sudo") {
        return true;
    }
    let owner = owner_line.and_then(|l| l.split(':').next());
    owner == Some(name) && members.split(',').all(|m| m.is_empty() || m == name)
}

fn default_managed_dir(platform: Platform, vars: &BTreeMap<String, String>) -> Option<PathBuf> {
    match platform {
        Platform::MacOs => Some(PathBuf::from("/Library/Application Support/ClaudeCode")),
        Platform::Linux | Platform::Wsl2 | Platform::Wsl1 => {
            Some(PathBuf::from("/etc/claude-code"))
        }
        Platform::Windows => {
            let base = vars
                .get("ProgramFiles")
                .cloned()
                .unwrap_or_else(|| r"C:\Program Files".to_string());
            Some(PathBuf::from(base).join("ClaudeCode"))
        }
        Platform::Other => None,
    }
}

fn is_executable(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.is_file() && meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        meta.is_file()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tool(dir: &Path, name: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn ctx(root: &Path, path: &[&Path], writable: &[&Path]) -> Ctx {
        let path = std::env::join_paths(path).unwrap();
        Ctx {
            root: root.to_path_buf(),
            vars: [("PATH".to_string(), path.to_string_lossy().into_owned())].into(),
            home: None,
            platform: Platform::Linux,
            managed_dir: None,
            mezha_exe: None,
            agent_writable: writable.iter().map(|p| p.to_path_buf()).collect(),
        }
    }

    #[test]
    fn which_trusted_skips_places_an_agent_can_write() {
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let root = base.join("repo");
        let in_project = root.join("node_modules/.bin");
        let open = base.join("open");
        let allowed = base.join("allowed");
        let good = base.join("good");
        tool(&in_project, "git");
        tool(&open, "git");
        tool(&allowed, "git");
        let real = tool(&good, "git");
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();

        let c = ctx(&root, &[&in_project, &open, &allowed, &good], &[&allowed]);
        let found = c.which_trusted("git");
        assert_eq!(found.path.as_deref(), Some(real.as_path()));
        let skipped = found.skipped.join("\n");
        assert_eq!(found.skipped.len(), 3, "{skipped}");
        assert!(skipped.contains("inside the project"), "{skipped}");
        assert!(skipped.contains("world-writable"), "{skipped}");
        assert!(skipped.contains("allowWrite"), "{skipped}");
        assert!(found.skipped_note("git").unwrap().contains("node_modules"));

        // A trusted directory's symlink into the project is still the project's.
        std::os::unix::fs::symlink(in_project.join("git"), good.join("gh")).unwrap();
        tool(&in_project, "gh");
        assert_eq!(c.which_trusted("gh").path, None);

        // A sticky world-writable directory is fine; TMPDIR is not.
        let sticky = base.join("sticky");
        let sticky_git = tool(&sticky, "git");
        std::fs::set_permissions(&sticky, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let c = ctx(&root, &[&sticky], &[]);
        assert_eq!(c.which_trusted("git").path, Some(sticky_git));
        let mut c = ctx(&root, &[&good], &[]);
        c.vars.insert("TMPDIR".into(), base.display().to_string());
        let found = c.which_trusted("git");
        assert_eq!(found.path, None);
        assert!(found.skipped[0].contains("TMPDIR"));
    }

    #[test]
    fn platform_names_and_what_each_has() {
        let all = [
            Platform::MacOs,
            Platform::Linux,
            Platform::Wsl2,
            Platform::Wsl1,
            Platform::Windows,
            Platform::Other,
        ];
        let names: Vec<&str> = all.iter().map(|p| p.as_str()).collect();
        assert_eq!(
            names,
            ["macos", "linux", "wsl2", "wsl1", "windows", "other"]
        );
        let sandboxed: Vec<bool> = all.iter().map(|p| p.has_sandbox()).collect();
        assert_eq!(sandboxed, [true, true, true, false, false, false]);
        let folding: Vec<bool> = all.iter().map(|p| p.folds_case()).collect();
        assert_eq!(folding, [true, false, false, false, true, false]);
    }

    #[test]
    fn managed_settings_live_where_the_platform_puts_them() {
        let none = BTreeMap::new();
        let dir = |p: Platform, vars: &BTreeMap<String, String>| {
            default_managed_dir(p, vars).map(|d| d.display().to_string())
        };
        assert_eq!(
            dir(Platform::MacOs, &none).as_deref(),
            Some("/Library/Application Support/ClaudeCode")
        );
        for p in [Platform::Linux, Platform::Wsl2, Platform::Wsl1] {
            assert_eq!(dir(p, &none).as_deref(), Some("/etc/claude-code"), "{p:?}");
        }
        assert_eq!(dir(Platform::Other, &none), None);
        let windows = dir(Platform::Windows, &none).unwrap();
        assert!(
            windows.starts_with(r"C:\Program Files") && windows.ends_with("ClaudeCode"),
            "{windows}"
        );
        let vars: BTreeMap<String, String> =
            [("ProgramFiles".to_string(), r"D:\Apps".to_string())].into();
        let windows = dir(Platform::Windows, &vars).unwrap();
        assert!(windows.starts_with(r"D:\Apps"), "{windows}");
    }

    #[test]
    fn from_process_reads_this_process() {
        let c = Ctx::from_process(Path::new("/x/repo"));
        assert_eq!(c.root, PathBuf::from("/x/repo"));
        assert_eq!(c.platform, Platform::detect());
        assert_eq!(
            c.managed_dir,
            default_managed_dir(c.platform, &c.vars),
            "{:?}",
            c.managed_dir
        );
        assert_eq!(c.vars.get("PATH").cloned(), std::env::var("PATH").ok());
        assert!(c.agent_writable.is_empty());
    }

    #[test]
    fn without_a_path_nothing_is_found() {
        let tmp = tempfile::tempdir().unwrap();
        let mut c = ctx(tmp.path(), &[], &[]);
        c.vars.remove("PATH");
        assert_eq!(c.trusted_path(), "");
        let found = c.which_trusted("git");
        assert_eq!(
            (found.path.clone(), found.skipped.clone()),
            (None, Vec::new()),
            "{found:?}"
        );
        assert_eq!(found.skipped_note("git"), None);
    }

    #[test]
    fn a_symlink_into_a_world_writable_directory_is_distrusted() {
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let root = base.join("repo");
        let open = base.join("open");
        let good = base.join("good");
        std::fs::create_dir_all(&root).unwrap();
        tool(&open, "git");
        std::fs::create_dir_all(&good).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::os::unix::fs::symlink(open.join("git"), good.join("git")).unwrap();
        let c = ctx(&root, &[&good], &[]);
        let found = c.which_trusted("git");
        assert_eq!(found.path, None, "{found:?}");
        assert_eq!(found.skipped.len(), 1, "{:?}", found.skipped);
        assert!(
            found.skipped[0].contains("in a group- or world-writable directory"),
            "{}",
            found.skipped[0]
        );
    }

    /// A group-writable directory is judged by its group: trusted when the
    /// group already holds root or is the owner's private group, otherwise
    /// skipped. Which one depends on the machine's `/etc/group`, so both
    /// answers are accepted, and nothing else is.
    #[test]
    fn a_group_writable_directory_is_judged_by_its_group() {
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let root = base.join("repo");
        let shared = base.join("shared");
        let git = tool(&shared, "git");
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o775)).unwrap();
        let c = ctx(&root, &[&shared], &[]);
        let found = c.which_trusted("git");
        match (&found.path, found.skipped.as_slice()) {
            (Some(path), []) => assert_eq!(path, &git),
            (None, [why]) => assert!(
                why.contains("in a group- or world-writable directory"),
                "{why}"
            ),
            _ => panic!("{found:?}"),
        }
    }

    #[test]
    fn trusted_groups() {
        assert!(group_is_trusted(
            Some("admin:*:80:root"),
            Some("dev:*:501:20::")
        ));
        assert!(group_is_trusted(Some("wheel:x:10:"), None));
        assert!(group_is_trusted(
            Some("dev:x:1000:"),
            Some("dev:x:1000:1000::/home/dev:/bin/bash")
        ));
        assert!(!group_is_trusted(
            Some("dev:x:1000:eve"),
            Some("dev:x:1000:1000::")
        ));
        assert!(!group_is_trusted(
            Some("staff:*:20:root"),
            Some("dev:*:501:20::")
        ));
        assert!(!group_is_trusted(None, Some("dev:x:1000:1000::")));
    }

    #[test]
    fn trusted_path_drops_untrusted_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let root = base.join("repo");
        let venv = root.join(".venv/bin");
        let good = base.join("good");
        std::fs::create_dir_all(&venv).unwrap();
        std::fs::create_dir_all(&good).unwrap();
        let nowhere = base.join("nowhere");
        let mut c = ctx(&root, &[&venv, &good, &nowhere], &[]);
        let path = c.vars["PATH"].clone();
        c.vars.insert("PATH".into(), format!("relative/bin:{path}"));
        // A directory that doesn't exist can't be written by anyone either.
        assert_eq!(
            c.trusted_path(),
            format!("{}:{}", good.display(), nowhere.display())
        );
    }
}
