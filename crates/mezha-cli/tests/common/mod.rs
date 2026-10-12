//! Helpers shared by the CLI and end-to-end tests. Every process starts from
//! an empty environment: these tests often run inside Claude Code, whose
//! `CLAUDECODE` and `CLAUDE_PROJECT_DIR` must not leak in.

#![allow(dead_code)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

pub const BIN: &str = env!("CARGO_BIN_EXE_mezha");

pub struct Project {
    _tmp: tempfile::TempDir,
    pub base: PathBuf,
    pub home: PathBuf,
    pub root: PathBuf,
    /// `TMPDIR` for the mezha under test: its scratch directories land here,
    /// not in `/tmp` (which a sandbox may refuse), and not where the test
    /// keeps its stand-in programs, which mezha distrusts under `TMPDIR`.
    pub tmp: PathBuf,
}

impl Project {
    /// An empty project directory and a scratch home, canonicalized (macOS
    /// puts temp dirs behind the `/var` → `/private/var` symlink).
    pub fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let home = base.join("home");
        let root = base.join("repo");
        let scratch = base.join("tmp");
        for dir in [&home, &root, &scratch] {
            fs::create_dir_all(dir).unwrap();
        }
        Project {
            _tmp: tmp,
            base,
            home,
            root,
            tmp: scratch,
        }
    }

    pub fn write_spec(&self, text: &str) {
        fs::write(self.root.join("mezha.toml"), text).unwrap();
    }

    pub fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.root.join(rel)).unwrap()
    }

    /// `mezha <args>` in the project, with a clean environment.
    pub fn mezha(&self, args: &[&str]) -> Output {
        self.mezha_env(args, &[])
    }

    pub fn mezha_env(&self, args: &[&str], extra: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(BIN);
        cmd.args(args)
            .current_dir(&self.root)
            .env_clear()
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("TMPDIR", &self.tmp)
            .stdin(Stdio::null());
        pass_through(&mut cmd);
        for (k, v) in extra {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    }
}

/// What a process started from an empty environment still needs from this
/// one: `PATH` to find git and the stand-ins, `SYSTEMROOT` on Windows, and
/// `LLVM_PROFILE_FILE` so a coverage run records what the child executed.
pub fn pass_through(cmd: &mut Command) {
    for key in ["PATH", "SYSTEMROOT", "LLVM_PROFILE_FILE"] {
        if let Some(value) = std::env::var_os(key) {
            cmd.env(key, value);
        }
    }
}

pub fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Runs `cmd` (a command string) under bash with `input` on stdin.
pub fn bash(cmd: &str, cwd: &Path, env: &[(&str, &str)], input: &[u8]) -> Output {
    let mut bash = Command::new("bash");
    bash.arg("-c").arg(cmd).current_dir(cwd).env_clear();
    pass_through(&mut bash);
    let mut child = bash
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A hook may exit before reading everything; that is not a test failure.
    let _ = child.stdin.take().unwrap().write_all(input);
    child.wait_with_output().unwrap()
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
