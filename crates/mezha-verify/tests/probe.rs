//! The network and credential probes' scripts against real git, without
//! srt and without the network: a `file://` repository stands in for a
//! server that opens a push session, and small local listeners play a
//! proxy that refuses CONNECT and a server that wants a password. The
//! classifier must read the installed git's and curl's own wording.

#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;

use mezha_verify::creds::Withheld;
use mezha_verify::probe::{Outcome, TestHook, credentials_direct, network_direct};
use mezha_verify::{Ctx, Platform};

struct Machine {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    home: PathBuf,
}

impl Machine {
    fn new() -> Machine {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let home = base.join("home");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(base.join("repo")).unwrap();
        Machine {
            _tmp: tmp,
            base,
            home,
        }
    }

    /// A scratch home and only system directories on PATH, so neither the
    /// developer's `.netrc` nor their proxy settings leak in.
    fn ctx(&self, extra: &[(&str, &str)]) -> Ctx {
        let mut vars: std::collections::BTreeMap<String, String> = [
            ("PATH", "/usr/bin:/bin".to_string()),
            ("HOME", self.home.display().to_string()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        for (k, v) in extra {
            vars.insert(k.to_string(), v.to_string());
        }
        Ctx {
            root: self.base.join("repo"),
            vars,
            home: Some(self.home.clone()),
            platform: Platform::detect(),
            managed_dir: None,
            mezha_exe: None,
            agent_writable: Vec::new(),
        }
    }
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A bare repository with one branch, and its refs.
fn served_repo(base: &Path) -> (PathBuf, String) {
    let work = base.join("work");
    fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "-q", "-b", "main"]);
    fs::write(work.join("f"), "x").unwrap();
    git(&work, &["add", "f"]);
    git(&work, &["commit", "-qm", "x"]);
    let bare = base.join("served.git");
    git(base, &["clone", "-q", "--bare", "work", "served.git"]);
    let refs = git(&bare, &["for-each-ref"]);
    (bare, refs)
}

#[test]
fn a_push_session_shows_on_a_file_repository() {
    let m = Machine::new();
    let (bare, refs) = served_repo(&m.base);
    let url = format!("file://{}", bare.display());
    let hook = TestHook {
        allow_file: true,
        real_push: false,
    };
    let (outcome, printed) = network_direct(&m.ctx(&[]), &url, hook);
    assert_eq!(outcome, Outcome::PushSession, "{printed}");

    // Without --dry-run, deleting a missing ref still sends nothing.
    let hook = TestHook {
        allow_file: true,
        real_push: true,
    };
    let (outcome, printed) = network_direct(&m.ctx(&[]), &url, hook);
    assert_eq!(outcome, Outcome::PushSession, "{printed}");
    assert_eq!(git(&bare, &["for-each-ref"]), refs);
}

#[test]
fn file_urls_are_refused_without_the_test_hook() {
    let m = Machine::new();
    let (bare, _) = served_repo(&m.base);
    let url = format!("file://{}", bare.display());
    let (outcome, printed) = network_direct(&m.ctx(&[]), &url, TestHook::default());
    assert!(matches!(outcome, Outcome::Inconclusive(_)), "{printed}");
    assert!(
        printed.contains("transport 'file' not allowed"),
        "{printed}"
    );
}

/// Answers every connection with `response` after reading the request
/// head; returns the port and a log of the request heads.
fn listener(response: &'static str) -> (u16, std::sync::mpsc::Receiver<String>) {
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        for stream in server.incoming().take(8) {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut head = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                head.push_str(&line);
            }
            let _ = tx.send(head);
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (port, rx)
}

#[test]
fn a_proxy_refusing_connect_is_blocked() {
    let m = Machine::new();
    let (port, heads) =
        listener("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let proxy = format!("http://127.0.0.1:{port}");
    let ctx = m.ctx(&[
        ("https_proxy", &proxy),
        ("HTTPS_PROXY", &proxy),
        ("NO_PROXY", "*"),
    ]);
    let (outcome, printed) =
        network_direct(&ctx, "https://github.com/o/r.git", TestHook::default());
    assert_eq!(outcome, Outcome::Blocked, "{printed}");
    let head = heads.recv().unwrap();
    assert!(head.starts_with("CONNECT github.com:443 "), "{head}");
}

#[test]
fn a_proxy_asking_for_authentication_is_inconclusive() {
    let m = Machine::new();
    let (port, _) = listener(
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"p\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let proxy = format!("http://127.0.0.1:{port}");
    let ctx = m.ctx(&[("https_proxy", &proxy), ("HTTPS_PROXY", &proxy)]);
    let (outcome, printed) =
        network_direct(&ctx, "https://github.com/o/r.git", TestHook::default());
    assert_eq!(
        outcome,
        Outcome::Inconclusive("the proxy asked for authentication".into()),
        "{printed}"
    );
}

#[test]
fn a_server_asking_for_a_password_is_unauthenticated() {
    let m = Machine::new();
    let (port, heads) = listener(
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"git\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let url = format!("http://127.0.0.1:{port}/o/r.git");
    let (outcome, printed) = network_direct(&m.ctx(&[]), &url, TestHook::default());
    assert_eq!(outcome, Outcome::Unauthenticated, "{printed}");
    let head = heads.recv().unwrap();
    assert!(
        head.starts_with("GET /o/r.git/info/refs?service=git-receive-pack "),
        "{head}"
    );
    assert!(!head.contains("Authorization"), "{head}");
}

#[test]
fn the_credential_probe_reports_indices_for_what_it_can_read() {
    let m = Machine::new();
    let ssh = m.home.join(".ssh");
    fs::create_dir_all(&ssh).unwrap();
    fs::write(ssh.join("id_ed25519"), "key").unwrap();
    fs::write(ssh.join("id_ed25519.pub"), "public").unwrap();
    fs::write(m.home.join(".netrc"), "").unwrap();
    let elsewhere = m.base.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    fs::write(elsewhere.join("creds"), "https://x:t@h\n").unwrap();
    std::os::unix::fs::symlink(elsewhere.join("creds"), m.home.join(".git-credentials")).unwrap();

    let ctx = m.ctx(&[
        ("GH_TOKEN", "t"),
        ("MY_GITHUB_PAT", "p"),
        ("GITHUB_REPOSITORY", "o/r"),
    ]);
    let withheld = Withheld {
        paths: vec![ssh.clone()],
        env: vec!["GH_TOKEN".into()],
        ..Withheld::default()
    };
    let facts = credentials_direct(&ctx, None, &withheld);
    assert!(facts.creds_checked);
    // No sandbox here, so everything that exists and isn't empty is readable.
    assert_eq!(
        facts.proven,
        [
            "~/.ssh/id_ed25519",
            "~/.git-credentials",
            &elsewhere.join("creds").display().to_string(),
            "environment variable GH_TOKEN",
            "environment variable MY_GITHUB_PAT",
        ]
    );
    // What mezha says is withheld but the script could read disagrees.
    assert_eq!(facts.disagree.len(), 2, "{:?}", facts.disagree);
    assert!(facts.disagree[0].contains("~/.ssh/id_ed25519"));
    assert!(facts.disagree[1].contains("GH_TOKEN"));
}
