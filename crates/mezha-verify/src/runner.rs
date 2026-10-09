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
    /// [`run_lines`]: the line callback asked to stop, and the process was
    /// killed.
    pub stopped: bool,
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
    let mut child = spawn(ctx, spec)?;
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
        stopped: false,
    })
}

/// What a line callback wants next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    Continue,
    Stop,
}

/// Stdout lines longer than this are dropped by [`run_lines`].
const LINE_CAP: usize = 8 << 20;

/// Like [`run`] for a long-running child that reports as it goes: each
/// stdout line goes to `on_line` as it arrives and none is kept.
/// [`Next::Stop`] kills the process group at once.
pub fn run_lines(
    ctx: &Ctx,
    spec: &Run<'_>,
    mut on_line: impl FnMut(&str) -> Next,
) -> std::io::Result<Output> {
    let mut child = spawn(ctx, spec)?;
    let (tx, lines) = mpsc::channel::<String>();
    let mut stdout = std::io::BufReader::new(child.stdout.take().expect("piped stdout"));
    thread::spawn(move || {
        use std::io::BufRead;
        let mut line = Vec::new();
        loop {
            line.clear();
            match (&mut stdout)
                .take(LINE_CAP as u64 + 1)
                .read_until(b'\n', &mut line)
            {
                Ok(0) | Err(_) => break,
                Ok(_) if line.len() > LINE_CAP => {
                    // Skip the rest of an overlong line.
                    let mut rest = Vec::new();
                    if stdout.read_until(b'\n', &mut rest).is_err() {
                        break;
                    }
                }
                Ok(_) => {
                    if tx
                        .send(String::from_utf8_lossy(&line).into_owned())
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });
    let err_rx = drain(child.stderr.take().expect("piped stderr"));

    let deadline = Instant::now() + spec.timeout;
    let (mut timed_out, mut stopped) = (false, false);
    let status = loop {
        match lines.recv_timeout(Duration::from_millis(10)) {
            Ok(line) => {
                if on_line(line.trim_end_matches(['\n', '\r'])) == Next::Stop {
                    stopped = true;
                    kill_tree(&mut child);
                    break None;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // Stdout closed: the child is done or about to be.
                if let Some(status) = child.try_wait()? {
                    break Some(status);
                }
            }
        }
        if let Some(status) = child.try_wait()? {
            // Lines still in the channel belong to the run.
            while let Ok(line) = lines.recv_timeout(Duration::from_millis(200)) {
                if on_line(line.trim_end_matches(['\n', '\r'])) == Next::Stop {
                    stopped = true;
                    break;
                }
            }
            break Some(status);
        }
        if Instant::now() >= deadline {
            timed_out = true;
            kill_tree(&mut child);
            break None;
        }
    };
    let stderr = err_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_default();
    Ok(Output {
        code: status.and_then(|s| s.code()),
        stdout: String::new(),
        stderr,
        timed_out,
        stopped,
    })
}

fn spawn(ctx: &Ctx, spec: &Run<'_>) -> std::io::Result<std::process::Child> {
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
    Ok(child)
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
        // By absolute path: PATH may hold a directory an agent can write.
        let kill = ["/bin/kill", "/usr/bin/kill"]
            .into_iter()
            .find(|p| Path::new(p).exists())
            .unwrap_or("/bin/kill");
        let _ = Command::new(kill)
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
    fn lines_arrive_as_they_come_and_stop_kills() {
        let spec = |script: &'static str| -> (Vec<String>, Output) {
            let mut seen = Vec::new();
            let out = run_lines(
                &ctx(),
                &Run {
                    program: Path::new("/bin/sh"),
                    args: &["-c", script],
                    cwd: Path::new("/"),
                    env: &[],
                    remove: &[],
                    stdin: b"in",
                    timeout: Duration::from_secs(10),
                },
                |line| {
                    seen.push(line.to_string());
                    if line == "stop" {
                        Next::Stop
                    } else {
                        Next::Continue
                    }
                },
            )
            .unwrap();
            (seen, out)
        };
        let (seen, out) = spec("echo a; cat; echo; echo b >&2; exit 4");
        assert_eq!(seen, ["a", "in"]);
        assert_eq!(
            (out.code, out.stderr.as_str(), out.stopped),
            (Some(4), "b\n", false)
        );
        let started = Instant::now();
        let (seen, out) = spec("echo stop; sleep 30; echo late");
        assert_eq!(seen, ["stop"]);
        assert!(out.stopped && out.code.is_none());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn the_environment_is_only_the_context() {
        let out = sh("echo \"[$HOME][$LC_ALL]\"", Duration::from_secs(5));
        assert_eq!(out.stdout, "[][C]\n");
    }
}
