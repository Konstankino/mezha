//! `mezha verify --probe` and `--inside` against a real `srt` (Anthropic's
//! sandbox runtime). Ignored by default: they need srt 0.0.79 or later on
//! PATH (with Node for it), and some reach github.com. The scheduled srt
//! workflow runs them with `--ignored` and `MEZHA_REAL_SRT=1`, which turns
//! a missing srt into a failure instead of a skip:
//!
//! ```text
//! MEZHA_REAL_SRT=1 cargo test -p mezha --test real_srt -- --ignored
//! ```
//!
//! They check what the stand-ins in `mezha-verify/tests` can't: that srt
//! accepts the settings mezha writes, that its `credentials` deny entries
//! hide files and variables, and the exact wording of its refusals.

#![cfg(unix)]

mod common;

use std::fs;
use std::path::Path;
use std::process::Command;

use common::{BIN, Project, stdout};
use serde_json::{Value, json};

/// Whether a real srt is on PATH; without one the tests skip, unless
/// `MEZHA_REAL_SRT` asks for them.
fn srt_available() -> bool {
    let found = std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join("srt").is_file()));
    if !found && std::env::var_os("MEZHA_REAL_SRT").is_some() {
        panic!("MEZHA_REAL_SRT is set, but srt isn't on PATH");
    }
    if !found {
        eprintln!("skipped: srt isn't on PATH");
    }
    found
}

/// A compiled project with `remote`, no system or global git config, and
/// `extra` environment variables.
fn project(egress: &str, remote: &str) -> Project {
    let p = Project::new();
    git(&p.root, &["init", "-q"]);
    git(&p.root, &["remote", "add", "origin", remote]);
    p.write_spec(&format!(
        "[project]\nname = \"real-srt\"\n\n[policy]\negress_allow = [{egress}]\npermissions_ask = [\"git push\"]\n"
    ));
    let out = p.mezha(&["compile"]);
    assert!(out.status.success(), "{}", stdout(&out));
    p
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}");
}

fn verify_json(p: &Project, args: &[&str], extra: &[(&str, &str)]) -> Value {
    let mut env = vec![("GIT_CONFIG_NOSYSTEM", "1")];
    env.extend_from_slice(extra);
    let mut full = vec!["verify", "--json"];
    full.extend_from_slice(args);
    let out = p.mezha_env(&full, &env);
    let text = stdout(&out);
    assert!(
        matches!(out.status.code(), Some(0 | 1)),
        "exit {:?}: {text}{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_str(&text).unwrap()
}

fn check<'a>(report: &'a Value, id: &str) -> &'a Value {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap()
}

fn detail(report: &Value, id: &str) -> String {
    check(report, id)["detail"].as_str().unwrap().to_string()
}

#[test]
#[ignore]
fn srt_shows_a_closed_network() {
    if !srt_available() {
        return;
    }
    let p = project("", "https://github.com/anthropics/sandbox-runtime.git");
    let r = verify_json(&p, &["--probe"], &[]);
    assert!(r["probe"].as_str().unwrap().starts_with("srt "), "{r}");
    let push = check(&r, "push-boundary");
    assert_eq!(push["status"], "pass", "{push}");
    assert_eq!(push["evidence"], json!(["static", "probe"]));
    assert!(
        detail(&r, "push-boundary").contains("github.com:443 refused by the sandbox proxy"),
        "{}",
        detail(&r, "push-boundary")
    );
}

/// srt hides what the `credentials` deny entries name (`~/.netrc`,
/// `GH_TOKEN`) and nothing else (a `store` helper's file elsewhere, a
/// token variable mezha doesn't list). github.com is allowed here, so the
/// probe also reaches it.
#[test]
#[ignore]
fn srt_withholds_what_the_settings_deny() {
    if !srt_available() {
        return;
    }
    let p = project(
        "\"github.com\"",
        "https://github.com/anthropics/sandbox-runtime.git",
    );
    fs::write(
        p.home.join(".netrc"),
        "machine github.com login x password y\n",
    )
    .unwrap();
    let store = p.base.join("elsewhere-creds");
    fs::write(&store, "https://x:y@github.com\n").unwrap();
    git(
        &p.root,
        &[
            "config",
            "credential.helper",
            &format!("store --file={}", store.display()),
        ],
    );
    let r = verify_json(
        &p,
        &["--probe"],
        &[
            ("GH_TOKEN", "ghp_withheld"),
            ("MY_GITHUB_PAT", "not-withheld"),
        ],
    );
    let text = detail(&r, "push-boundary");
    assert_eq!(check(&r, "push-boundary")["status"], "fail", "{text}");
    let shown = text
        .split("shown readable in srt: ")
        .nth(1)
        .unwrap_or_else(|| panic!("nothing shown readable: {text}"));
    let shown = shown.split(';').next().unwrap();
    assert!(shown.contains("elsewhere-creds"), "{shown}");
    assert!(
        shown.contains("environment variable MY_GITHUB_PAT"),
        "{shown}"
    );
    assert!(!shown.contains(".netrc"), "{shown}");
    assert!(!shown.contains("GH_TOKEN"), "{shown}");
    assert!(!text.contains("differ"), "{text}");
    assert!(
        text.contains("github.com:443 reachable, the server asked for a credential"),
        "{text}"
    );
    let json = r.to_string();
    assert!(!json.contains("ghp_withheld") && !json.contains("not-withheld"));
}

#[cfg(target_os = "linux")]
#[test]
#[ignore]
fn srt_refuses_ssh_through_socat() {
    if !srt_available() {
        return;
    }
    let p = project("", "git@github.com:anthropics/sandbox-runtime.git");
    let r = verify_json(&p, &["--probe"], &[]);
    let text = detail(&r, "push-boundary");
    if !text.contains("github.com:22 refused by the sandbox proxy") {
        panic!("{text}\n\nssh inside srt, by hand:\n{}", ssh_inside_srt(&p));
    }
}

/// What ssh says inside srt when it reaches github.com, for a failure
/// message: the probe's report carries only its verdict. Then the same
/// with socat logging at notice level, and the proxy's own answer to
/// `CONNECT github.com:22`. Proxy credentials are masked.
#[cfg(target_os = "linux")]
fn ssh_inside_srt(p: &Project) -> String {
    const SCRIPT: &str = r#"printf 'GIT_SSH_COMMAND=%s\n' "${GIT_SSH_COMMAND-(unset)}" | sed "s/proxyauth=[^,' ]*/proxyauth=***/g"
socat -V 2>&1 | sed -n 2p
GIT_SSH_COMMAND="${GIT_SSH_COMMAND:-ssh} -o BatchMode=yes -o ConnectTimeout=10" git ls-remote git@github.com:anthropics/sandbox-runtime.git 2>&1
echo "exit $?"
echo "--- socat at notice level"
loud=$(printf '%s' "${GIT_SSH_COMMAND:-ssh}" | sed 's/socat -/socat -d -d -/')
GIT_SSH_COMMAND="$loud -o BatchMode=yes -o ConnectTimeout=10" git ls-remote git@github.com:anthropics/sandbox-runtime.git 2>&1 | sed "s/proxyauth=[^,' ]*/proxyauth=***/g; s/\(Proxy-Authorization:\).*/\1 ***/I"
echo "--- the proxy's answer to CONNECT github.com:22"
curl -sv -p -x "$HTTPS_PROXY" --max-time 10 telnet://github.com:22 </dev/null 2>&1 | grep -E '^(< |\* CONNECT|\* Recv|curl: )'"#;
    // srt points TMPDIR at /tmp/claude but doesn't create it.
    fs::create_dir_all("/tmp/claude").unwrap();
    let settings = p.base.join("srt-ssh-settings.json");
    fs::write(&settings, settings_from_project(p).to_string()).unwrap();
    let mut cmd = Command::new("srt");
    cmd.args(["--settings", &settings.display().to_string(), "-c", SCRIPT])
        .current_dir(&p.root)
        .env_clear()
        .env("HOME", &p.home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null");
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    match cmd.output() {
        Ok(out) => format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
        Err(e) => format!("srt didn't start: {e}"),
    }
}

/// srt settings close to what Claude Code builds from the project's
/// `.claude/settings.json`: its hosts, credentials and write denials.
fn settings_from_project(p: &Project) -> Value {
    let settings: Value =
        serde_json::from_str(&fs::read_to_string(p.root.join(".claude/settings.json")).unwrap())
            .unwrap();
    let sandbox = &settings["sandbox"];
    let home = p.home.display().to_string();
    let root = p.root.display().to_string();
    let resolve = |path: &str| {
        if let Some(rest) = path.strip_prefix("~/") {
            format!("{home}/{rest}")
        } else if let Some(rest) = path.strip_prefix("./") {
            format!("{root}/{rest}")
        } else {
            path.to_string()
        }
    };
    let files: Vec<Value> = sandbox["credentials"]["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| json!({ "path": resolve(f["path"].as_str().unwrap()), "mode": f["mode"] }))
        .collect();
    let deny_write: Vec<String> = sandbox["filesystem"]["denyWrite"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| resolve(p.as_str().unwrap()))
        .collect();
    json!({
        "network": {
            "allowedDomains": sandbox["network"]["allowedDomains"],
            "deniedDomains": sandbox["network"]["deniedDomains"],
        },
        "filesystem": { "denyRead": [], "allowWrite": [], "denyWrite": deny_write },
        "credentials": { "files": files, "envVars": sandbox["credentials"]["envVars"] },
    })
}

/// `--inside` run as Claude Code would run it: as a command inside srt.
#[test]
#[ignore]
fn inside_sees_a_real_sandbox() {
    if !srt_available() {
        return;
    }
    // srt points TMPDIR at /tmp/claude and lets commands write there, but
    // doesn't create it.
    fs::create_dir_all("/tmp/claude").unwrap();
    let p = project("", "https://github.com/anthropics/sandbox-runtime.git");
    fs::create_dir_all(p.home.join(".ssh")).unwrap();
    fs::write(p.home.join(".ssh/id_ed25519"), "key").unwrap();
    let settings = p.base.join("srt-settings.json");
    fs::write(&settings, settings_from_project(&p).to_string()).unwrap();

    let command = format!("CLAUDECODE=1 '{BIN}' verify --inside --json");
    let mut cmd = Command::new("srt");
    cmd.args([
        "--settings",
        &settings.display().to_string(),
        "-c",
        &command,
    ])
    .current_dir(&p.root)
    .env_clear()
    .env("HOME", &p.home)
    .env("GIT_CONFIG_NOSYSTEM", "1");
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("PATH", path);
    }
    let out = cmd.output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let r: Value = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{e}: {text}{}", String::from_utf8_lossy(&out.stderr)));
    assert_eq!(r["mode"], "inside");
    assert_eq!(check(&r, "inside-sandbox")["status"], "pass", "{r}");
    assert_eq!(check(&r, "inside-credentials")["status"], "pass", "{r}");
    // macOS refuses a withheld directory; Linux shows it as an empty tmpfs.
    if cfg!(target_os = "macos") {
        assert!(detail(&r, "inside-credentials").contains("~/.ssh"), "{r}");
    }
    let network = detail(&r, "inside-network");
    assert!(network.contains("srt's proxy is in front"), "{network}");
    assert!(
        network.contains("refused inside the sandbox: github.com:443"),
        "{network}"
    );
}
