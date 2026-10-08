//! Running a command with a deadline. Every subprocess verify starts goes
//! through here: a clean environment from the context, `LC_ALL=C` so output
//! can be classified, both pipes drained at once so a chatty child can't
//! stall, and the whole process group killed on timeout.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::ctx::Ctx;

/// Output beyond this is read and dropped.
const OUTPUT_CAP: usize = 1 << 20;

#[derive(Debug, Clone, Default)]
pub struct Output {
    /// `None` when the command was killed or ended by a signal.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

impl Output {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

pub struct Run<'a> {
    pub program: &'a Path,
    pub args: &'a [&'a str],
    pub cwd: &'a Path,
    /// Variables set on top of the context's environment.
    pub env: &'a [(&'a str, &'a str)],
    /// Variables removed from the context's environment.
    pub remove: &'a [&'a str],
    pub stdin: &'a [u8],
    pub timeout: Duration,
}

pub fn run(ctx: &Ctx, spec: &Run<'_>) -> std::io::Result<Output> {
    let mut cmd = Command::new(spec.program);
    cmd.args(spec.args)
        .current_dir(spec.cwd)
        .env_clear()
        .envs(
            ctx.vars
                .iter()
                .filter(|(k, _)| !spec.remove.contains(&k.as_str())),
        )
        .envs(spec.env.iter().copied())
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    let mut child = cmd.spawn()?;

    let input = spec.stdin.to_vec();
    let mut stdin = child.stdin.take().expect("piped stdin");
    thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let out_rx = drain(child.stdout.take().expect("piped stdout"));
    let err_rx = drain(child.stderr.take().expect("piped stderr"));

    let deadline = Instant::now() + spec.timeout;
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if Instant::now() >= deadline {
            timed_out = true;
            kill_tree(&mut child);
            break None;
        }
        thread::sleep(Duration::from_millis(10));
    };
    // A background grandchild may hold the pipes open; don't wait for it.
    let grace = Duration::from_secs(2);
    let stdout = out_rx.recv_timeout(grace).unwrap_or_default();
    let stderr = err_rx.recv_timeout(grace).unwrap_or_default();
    Ok(Output {
        code: status.and_then(|s| s.code()),
        stdout,
        stderr,
        timed_out,
    })
}

fn drain(mut pipe: impl Read + Send + 'static) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut kept = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let room = OUTPUT_CAP.saturating_sub(kept.len());
                    kept.extend_from_slice(&buf[..n.min(room)]);
                }
            }
        }
        let _ = tx.send(String::from_utf8_lossy(&kept).into_owned());
    });
    rx
}

fn kill_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        // The child leads its own process group; take the group down with it.
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{}", child.id())])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/T", "/F", "/PID", &child.id().to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn ctx() -> Ctx {
        Ctx {
            root: PathBuf::from("/"),
            vars: [("PATH".to_string(), "/usr/bin:/bin".to_string())].into(),
            home: None,
            platform: crate::ctx::Platform::detect(),
            managed_dir: None,
            mezha_exe: None,
            agent_writable: Vec::new(),
        }
    }

    fn sh(script: &str, timeout: Duration) -> Output {
        run(
            &ctx(),
            &Run {
                program: Path::new("/bin/sh"),
                args: &["-c", script],
                cwd: Path::new("/"),
                env: &[],
                remove: &[],
                stdin: b"",
                timeout,
            },
        )
        .unwrap()
    }

    #[test]
    fn captures_output_and_code() {
        let out = sh("echo out; echo err >&2; exit 3", Duration::from_secs(5));
        assert_eq!(out.code, Some(3));
        assert_eq!(out.stdout, "out\n");
        assert_eq!(out.stderr, "err\n");
        assert!(!out.timed_out);
    }

    #[test]
    fn large_output_does_not_stall() {
        let out = sh(
            "head -c 300000 /dev/zero | tr '\\0' x; head -c 300000 /dev/zero | tr '\\0' y >&2",
            Duration::from_secs(10),
        );
        assert!(out.success());
        assert_eq!(out.stdout.len(), 300_000);
        assert_eq!(out.stderr.len(), 300_000);
    }

    #[test]
    fn times_out_and_kills_the_group() {
        let started = Instant::now();
        let out = sh("sleep 30 & sleep 30", Duration::from_millis(300));
        assert!(out.timed_out);
        assert_eq!(out.code, None);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn the_environment_is_only_the_context() {
        let out = sh("echo \"[$HOME][$LC_ALL]\"", Duration::from_secs(5));
        assert_eq!(out.stdout, "[][C]\n");
    }
}
