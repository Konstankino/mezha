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

    /// The executable `name` on this context's PATH (with PATHEXT on Windows).
    pub fn which(&self, name: &str) -> Option<PathBuf> {
        let path = self.vars.get("PATH").or_else(|| self.vars.get("Path"))?;
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
        std::env::split_paths(path).find_map(|dir| {
            exts.iter()
                .map(|ext| dir.join(format!("{name}{ext}")))
                .find(|candidate| is_executable(candidate))
        })
    }
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
