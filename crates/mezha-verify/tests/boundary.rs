//! verify must fail when the boundary is broken and pass when it isn't
//! (`mezha-plan.md` phase 1 definition of done). Each scenario compiles a
//! real project, breaks one thing, and runs verify with a fake machine:
//! scratch home and managed directory, no system or global git config, and
//! stand-in `claude`, `bwrap`, `socat` and `gh` on PATH.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use mezha_verify::{Ctx, Options, Platform, Report, Status, verify};
use serde_json::{Value, json};

struct Fixture {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    home: PathBuf,
    root: PathBuf,
    managed: PathBuf,
    bin: PathBuf,
    gitconfig: PathBuf,
}

fn spec(egress: &str) -> String {
    format!(
        "[project]\nname = \"boundary\"\n\n[policy]\negress_allow = [{egress}]\npermissions_ask = [\"git push\"]\n"
    )
}

impl Fixture {
    fn new(egress: &str, remote: &str) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let home = base.join("home");
        let root = base.join("repo");
        let managed = base.join("managed");
        let bin = base.join("bin");
        for dir in [&home, &root, &managed, &bin] {
            fs::create_dir_all(dir).unwrap();
        }
        let gitconfig = base.join("gitconfig");
        fs::write(&gitconfig, "").unwrap();
        let f = Fixture {
            _tmp: tmp,
            base,
            home,
            root,
            managed,
            bin,
            gitconfig,
        };
        f.git(&["init", "-q"]);
        f.git(&["remote", "add", "origin", remote]);
        f.tool("claude", "echo '2.1.285 (Claude Code)'");
        f.tool("bwrap", "exit 0");
        f.tool("socat", "exit 0");
        f.tool(
            "gh",
            "echo 'To get started with GitHub CLI, please run:  gh auth login' >&2; exit 4",
        );
        f.compile(&spec(egress));
        f
    }

    fn tool(&self, name: &str, body: &str) {
        let path = self.bin.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A stand-in `gh` that logs each call's arguments, working directory
    /// and environment, and answers from a recorded case in
    /// `tests/fixtures/protection` (after `edit`); a missing file is a 404.
    /// Returns the log's path.
    fn fake_gh(&self, case: &str, edit: impl Fn(&str, String) -> String) -> PathBuf {
        let src = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/protection")
            .join(case);
        let dir = self.base.join(format!("gh-{case}"));
        fs::create_dir_all(&dir).unwrap();
        for entry in fs::read_dir(&src).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let text = edit(&name, fs::read_to_string(&path).unwrap());
            fs::write(dir.join(&name), text).unwrap();
        }
        let log = self.base.join("gh.log");
        self.tool(
            "gh",
            &format!(
                r#"{{ printf 'ARGS'; for a in "$@"; do printf ' [%s]' "$a"; done; echo; echo "PWD $(pwd)"; env | sed 's/^/ENV /'; }} >> '{log}'
args="$*"
case "$args" in
  *graphql*) file=graphql.json ;;
  */rules/branches/*) file=rules.json ;;
  */rulesets/*) file=ruleset-$(printf '%s' "$args" | sed -n 's|.*/rulesets/\([0-9]*\).*|\1|p').json ;;
  *codeowners/errors*) file=codeowners.json ;;
  *) echo "unexpected: $args" >&2; exit 2 ;;
esac
if [ -f '{dir}/'"$file" ]; then cat '{dir}/'"$file"; else echo '{{"message":"Not Found"}}'; echo 'gh: Not Found (HTTP 404)' >&2; exit 1; fi"#,
                log = log.display(),
                dir = dir.display(),
            ),
        );
        log
    }

    /// A stand-in `srt` that prints `version`, keeps a copy of the settings
    /// it is given (and their path) in `<base>/srt`, runs `before`, then
    /// runs the command with bash and no sandbox.
    fn fake_srt(&self, version: &str, before: &str) -> PathBuf {
        let log = self.base.join("srt");
        fs::create_dir_all(&log).unwrap();
        self.tool(
            "srt",
            &format!(
                r#"if [ "$1" = --version ]; then echo {version}; exit 0; fi
if [ "$1" != --settings ] || [ "$3" != -c ]; then echo "unexpected: $*" >&2; exit 2; fi
echo "$2" >> '{log}/paths'
cp "$2" '{log}/settings.json'
{before}
exec bash -c "$4""#,
                log = log.display(),
            ),
        );
        log
    }

    fn probe(&self) -> Result<Report, mezha_verify::CantRun> {
        verify(
            &self.ctx(Platform::Linux),
            &Options {
                probe: true,
                ..Options::default()
            },
        )
    }

    fn git(&self, args: &[&str]) {
        let out = Command::new("git")
            .args(args)
            .current_dir(&self.root)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", &self.gitconfig)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn compile(&self, text: &str) {
        fs::write(self.root.join("mezha.toml"), text).unwrap();
        let spec = mezha_spec::parse(text).unwrap();
        let rendered = mezha_render::render(&spec, text).unwrap();
        let plan = mezha_render::plan(&self.root, &rendered).unwrap();
        mezha_render::write(&self.root, &plan, mezha_render::Mode::Apply, "t").unwrap();
    }

    fn ctx(&self, platform: Platform) -> Ctx {
        Ctx {
            root: self.root.clone(),
            vars: [
                ("PATH", format!("{}:/usr/bin:/bin", self.bin.display())),
                ("HOME", self.home.display().to_string()),
                ("GIT_CONFIG_NOSYSTEM", "1".into()),
                ("GIT_CONFIG_GLOBAL", self.gitconfig.display().to_string()),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
            home: Some(self.home.clone()),
            platform,
            managed_dir: Some(self.managed.clone()),
            mezha_exe: None,
            agent_writable: Vec::new(),
        }
    }

    fn verify_on(&self, platform: Platform, opts: Options) -> Report {
        verify(&self.ctx(platform), &opts).unwrap()
    }

    fn verify(&self) -> Report {
        self.verify_on(Platform::Linux, Options::default())
    }

    fn write_json(&self, path: &Path, value: Value) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, value.to_string()).unwrap();
    }

    fn user_settings(&self, value: Value) {
        self.write_json(&self.home.join(".claude/settings.json"), value);
    }

    fn local_settings(&self, value: Value) {
        self.write_json(&self.root.join(".claude/settings.local.json"), value);
    }

    fn edit_settings(&self, edit: impl FnOnce(&mut Value)) {
        let path = self.root.join(".claude/settings.json");
        let mut v: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        edit(&mut v);
        fs::write(&path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    }
}

const GITHUB: &str = "https://github.com/o/r.git";

fn status(report: &Report, id: &str) -> Status {
    report.checks.iter().find(|c| c.id == id).unwrap().status
}

fn detail<'a>(report: &'a Report, id: &str) -> &'a str {
    &report.checks.iter().find(|c| c.id == id).unwrap().detail
}

#[test]
fn a_clean_project_passes() {
    let f = Fixture::new("", GITHUB);
    let r = f.verify();
    assert_eq!(r.exit_code(), 0, "{}", r.to_human("x"));
    assert_eq!(
        status(&r, "sandbox"),
        Status::Pass,
        "{}",
        detail(&r, "sandbox")
    );
    assert_eq!(status(&r, "push-boundary"), Status::Pass);
    assert!(detail(&r, "push-boundary").contains("can't reach"));
    assert_eq!(status(&r, "settings-layers"), Status::Pass);
    // No mezha on the fake PATH: warned, not failed.
    assert_eq!(status(&r, "settings-intact"), Status::Warn);
    assert!(detail(&r, "settings-intact").contains("not on PATH"));
}

#[test]
fn scenario_1_sandbox_off_in_local_settings() {
    let f = Fixture::new("", GITHUB);
    f.local_settings(json!({ "sandbox": { "enabled": false } }));
    let r = f.verify();
    assert_eq!(r.exit_code(), 1);
    assert_eq!(status(&r, "sandbox"), Status::Fail);
    assert!(detail(&r, "sandbox").contains("settings.local.json"));
    assert_eq!(status(&r, "push-boundary"), Status::Fail);
}

#[test]
fn scenario_2_hooks_disabled_in_user_settings() {
    let f = Fixture::new("", GITHUB);
    f.user_settings(json!({ "disableAllHooks": true }));
    let r = f.verify();
    assert_eq!(r.exit_code(), 1);
    assert_eq!(status(&r, "settings-layers"), Status::Fail);
    assert!(detail(&r, "settings-layers").contains("disableAllHooks"));
}

#[test]
fn scenario_3_hand_edited_hook_command() {
    let f = Fixture::new("", GITHUB);
    f.edit_settings(|v| {
        v["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = json!("exit 0");
    });
    let r = f.verify();
    assert_eq!(r.exit_code(), 1);
    assert_eq!(status(&r, "settings-intact"), Status::Fail);
    assert!(detail(&r, "settings-intact").contains("edited by hand"));
}

#[test]
fn scenario_4_token_in_the_remote_url_with_github_allowed() {
    let f = Fixture::new(
        "\"github.com\"",
        "https://x:ghp_testtoken@github.com/o/r.git",
    );
    let r = f.verify();
    assert_eq!(r.exit_code(), 1);
    assert_eq!(status(&r, "push-boundary"), Status::Fail);
    assert!(detail(&r, "push-boundary").contains("remote URL"));
    let json = r.to_json();
    assert!(!json.contains("ghp_testtoken"), "secret leaked: {json}");
    assert!(!r.to_human("x").contains("ghp_testtoken"));
}

#[test]
fn scenario_5_excluded_commands_in_user_settings() {
    let f = Fixture::new("", GITHUB);
    f.user_settings(json!({ "sandbox": { "excludedCommands": ["git"] } }));
    let r = f.verify();
    assert_eq!(r.exit_code(), 1);
    assert_eq!(status(&r, "sandbox"), Status::Fail);
    assert!(detail(&r, "sandbox").contains("`git` runs outside the sandbox"));
}

#[test]
fn scenario_6_credentials_block_removed() {
    let f = Fixture::new("\"github.com\"", GITHUB);
    fs::write(f.home.join(".git-credentials"), "https://x:t@github.com\n").unwrap();
    // Withheld, so the file alone doesn't break the boundary.
    assert_eq!(status(&f.verify(), "push-boundary"), Status::Pass);

    f.edit_settings(|v| {
        v["sandbox"].as_object_mut().unwrap().remove("credentials");
    });
    let r = f.verify();
    assert_eq!(r.exit_code(), 1);
    assert_eq!(status(&r, "settings-intact"), Status::Fail);
    assert_eq!(status(&r, "push-boundary"), Status::Fail);
    assert!(detail(&r, "push-boundary").contains(".git-credentials"));
}

#[cfg(target_os = "macos")]
#[test]
fn scenario_7_macos_keychain_with_github_allowed() {
    let f = Fixture::new("\"github.com\"", GITHUB);
    fs::write(&f.gitconfig, "[credential]\n\thelper = osxkeychain\n").unwrap();
    let r = f.verify_on(Platform::MacOs, Options::default());
    assert_eq!(
        status(&r, "push-boundary"),
        Status::Fail,
        "{}",
        detail(&r, "push-boundary")
    );
    assert!(detail(&r, "push-boundary").contains("osxkeychain"));

    // Closing the network restores the boundary even though the keychain is open.
    let closed = Fixture::new("", GITHUB);
    fs::write(&closed.gitconfig, "[credential]\n\thelper = osxkeychain\n").unwrap();
    let r = closed.verify_on(Platform::MacOs, Options::default());
    assert_eq!(
        status(&r, "push-boundary"),
        Status::Pass,
        "{}",
        detail(&r, "push-boundary")
    );
}

#[test]
fn a_webfetch_allow_rule_opens_the_network_too() {
    let f = Fixture::new("", "https://x:tok@github.com/o/r.git");
    assert_eq!(status(&f.verify(), "push-boundary"), Status::Pass);
    f.local_settings(json!({ "permissions": { "allow": ["WebFetch(domain:github.com)"] } }));
    let r = f.verify();
    assert_eq!(
        status(&r, "push-boundary"),
        Status::Fail,
        "{}",
        detail(&r, "push-boundary")
    );
}

#[test]
fn unknown_helpers_make_an_open_network_unverified() {
    let f = Fixture::new("\"github.com\"", GITHUB);
    fs::write(&f.gitconfig, "[credential]\n\thelper = mystery\n").unwrap();
    let r = f.verify();
    assert_eq!(status(&r, "push-boundary"), Status::Warn);
    assert!(detail(&r, "push-boundary").contains("unverified"));
}

#[test]
fn an_admin_required_sandbox_ignores_repository_loosening() {
    let f = Fixture::new("", GITHUB);
    f.local_settings(json!({ "sandbox": { "enabled": false, "excludedCommands": ["git"] } }));
    fs::write(
        f.managed.join("managed-settings.json"),
        json!({ "sandbox": { "allowUnsandboxedCommands": false } }).to_string(),
    )
    .unwrap();
    let r = f.verify();
    assert_eq!(
        status(&r, "sandbox"),
        Status::Pass,
        "{}",
        detail(&r, "sandbox")
    );
}

#[test]
fn project_only_ignores_the_machine() {
    let f = Fixture::new("\"github.com\"", GITHUB);
    f.user_settings(json!({ "disableAllHooks": true }));
    let r = f.verify_on(
        Platform::Linux,
        Options {
            project_only: true,
            ..Options::default()
        },
    );
    assert_eq!(r.mode, "project-only");
    assert_eq!(status(&r, "settings-layers"), Status::Pass);
    assert_eq!(status(&r, "push-boundary"), Status::Warn);
    assert!(detail(&r, "push-boundary").contains("each machine"));
}

#[test]
fn native_windows_and_wsl1_fail_the_sandbox() {
    let f = Fixture::new("", GITHUB);
    for platform in [Platform::Windows, Platform::Wsl1] {
        let r = f.verify_on(platform, Options::default());
        assert_eq!(status(&r, "sandbox"), Status::Fail, "{platform:?}");
        assert_eq!(status(&r, "push-boundary"), Status::Fail, "{platform:?}");
    }
}

#[test]
fn an_old_claude_code_fails() {
    let f = Fixture::new("", GITHUB);
    f.tool("claude", "echo '2.1.200 (Claude Code)'");
    let r = f.verify();
    assert_eq!(status(&r, "sandbox"), Status::Fail);
    assert!(detail(&r, "sandbox").contains("2.1.200"));
}

#[test]
fn a_broken_bwrap_fails_on_linux() {
    let f = Fixture::new("", GITHUB);
    f.tool("bwrap", "exit 1");
    let r = f.verify();
    assert_eq!(status(&r, "sandbox"), Status::Fail);
    assert!(detail(&r, "sandbox").contains("bubblewrap"));
}

#[test]
fn a_missing_spec_cannot_run() {
    let f = Fixture::new("", GITHUB);
    fs::remove_file(f.root.join("mezha.toml")).unwrap();
    let err = verify(&f.ctx(Platform::Linux), &Options::default()).unwrap_err();
    assert!(matches!(err, mezha_verify::CantRun::NoSpec(_)));
}

fn as_writer(_: &str, text: String) -> String {
    text.replace("\"READ\"", "\"WRITE\"")
}

fn check<'a>(report: &'a Report, id: &str) -> &'a mezha_verify::Check {
    report.checks.iter().find(|c| c.id == id).unwrap()
}

#[test]
fn branch_protection_asks_gh_read_only_and_safely() {
    let f = Fixture::new("", GITHUB);
    let log = f.fake_gh("cli-cli", as_writer);
    let mut ctx = f.ctx(Platform::Linux);
    ctx.vars.insert("GH_FORCE_TTY".into(), "1".into());
    ctx.vars.insert("GH_REPO".into(), "evil/repo".into());
    let r = verify(&ctx, &Options::default()).unwrap();
    let c = check(&r, "branch-protection");
    assert_eq!(c.status, Status::Pass, "{}", c.detail);
    assert_eq!(c.evidence, ["server"]);
    assert!(
        c.detail
            .contains("o/r: `trunk` can't be pushed to directly"),
        "{}",
        c.detail
    );

    let log = fs::read_to_string(log).unwrap();
    let calls: Vec<&str> = log.lines().filter(|l| l.starts_with("ARGS")).collect();
    assert_eq!(calls.len(), 3, "graphql, rules, codeowners: {calls:?}");
    for call in &calls {
        assert!(call.starts_with("ARGS [api] "), "{call}");
        assert!(call.ends_with(" [--hostname] [github.com]"), "{call}");
        assert!(!call.contains("[-F]"), "{call}");
    }
    assert!(
        calls[0].contains("[graphql] [-f] [query=query("),
        "{}",
        calls[0]
    );
    assert!(
        calls[0].contains("[-f] [owner=o] [-f] [name=r]"),
        "{}",
        calls[0]
    );
    for call in &calls[1..] {
        assert!(call.contains("[--method] [GET]"), "{call}");
    }
    assert!(
        calls[1].contains("[repos/o/r/rules/branches/trunk]"),
        "{}",
        calls[1]
    );
    assert!(log.contains("ENV GH_PROMPT_DISABLED=1"));
    assert!(log.contains("ENV GH_PAGER=cat"));
    assert!(!log.contains("GH_FORCE_TTY"));
    assert!(!log.contains("GH_REPO"));
    // gh ran in a scratch directory that is gone, not in the repository.
    let pwd = log.lines().find_map(|l| l.strip_prefix("PWD ")).unwrap();
    assert!(!Path::new(pwd).starts_with(&f.root), "{pwd}");
    assert!(!Path::new(pwd).exists(), "{pwd}");
}

#[test]
fn an_unprotected_branch_fails_only_when_an_agent_can_push() {
    let f = Fixture::new("", GITHUB);
    f.fake_gh("hello-world", as_writer);
    let r = f.verify();
    assert_eq!(status(&r, "branch-protection"), Status::Warn);
    assert!(detail(&r, "branch-protection").contains("nothing stops a direct push to `master`"));

    let open = Fixture::new("\"github.com\"", "https://x:tok@github.com/o/r.git");
    open.fake_gh("hello-world", as_writer);
    let r = open.verify();
    assert_eq!(status(&r, "push-boundary"), Status::Fail);
    assert_eq!(status(&r, "branch-protection"), Status::Fail);
    assert!(!r.to_json().contains("tok@"));
}

#[test]
fn protection_verdicts_end_to_end() {
    let f = Fixture::new("", GITHUB);
    f.fake_gh("sandbox-runtime", as_writer);
    let r = f.verify();
    assert_eq!(status(&r, "branch-protection"), Status::Warn);
    assert!(
        detail(&r, "branch-protection").contains("no CODEOWNERS file"),
        "{}",
        detail(&r, "branch-protection")
    );

    let f = Fixture::new("", GITHUB);
    f.fake_gh("sandbox-runtime", |file, text| {
        as_writer(file, text).replace("\"never\"", "\"always\"")
    });
    let r = f.verify();
    assert_eq!(status(&r, "branch-protection"), Status::Warn);
    assert!(detail(&r, "branch-protection").contains("could push to `main` directly"));

    let f = Fixture::new("", GITHUB);
    f.fake_gh("cli-cli", |_, text| text);
    assert_eq!(status(&f.verify(), "branch-protection"), Status::Skip);
}

#[test]
fn branch_protection_without_gh_login_is_a_warning() {
    let f = Fixture::new("", GITHUB);
    let r = f.verify();
    assert_eq!(status(&r, "branch-protection"), Status::Warn);
    assert!(
        detail(&r, "branch-protection").contains("isn't logged in"),
        "{}",
        detail(&r, "branch-protection")
    );
    assert_eq!(r.exit_code(), 0);

    let none = Fixture::new("", "/srv/git/r.git");
    assert_eq!(status(&none.verify(), "branch-protection"), Status::Skip);
    let r = f.verify_on(
        Platform::Linux,
        Options {
            project_only: true,
            ..Options::default()
        },
    );
    assert_eq!(status(&r, "branch-protection"), Status::Skip);
}

#[test]
fn enterprise_tokens_reach_only_hosts_the_user_set_up() {
    let f = Fixture::new("", GITHUB);
    f.git(&["remote", "add", "ent", "https://ghe.corp/team/app.git"]);
    f.git(&["remote", "add", "other", "https://ghe.evil/team/app.git"]);
    fs::create_dir_all(f.home.join(".config/gh")).unwrap();
    fs::write(
        f.home.join(".config/gh/hosts.yml"),
        "ghe.corp:\n    user: me\n",
    )
    .unwrap();
    let log = f.fake_gh("cli-cli", as_writer);
    let mut ctx = f.ctx(Platform::Linux);
    ctx.vars
        .insert("GH_ENTERPRISE_TOKEN".into(), "ent-secret".into());
    let r = verify(&ctx, &Options::default()).unwrap();
    let detail = &check(&r, "branch-protection").detail;
    assert!(detail.contains("ghe.corp/team/app"), "{detail}");
    assert!(
        detail.contains("not checked (not GitHub): ghe.evil"),
        "{detail}"
    );

    let log = fs::read_to_string(log).unwrap();
    let mut host = "";
    let mut seen = (0, 0);
    for line in log.lines() {
        if let Some(call) = line.strip_prefix("ARGS") {
            host = if call.ends_with("[ghe.corp]") {
                "ghe.corp"
            } else {
                "github.com"
            };
        }
        if line.starts_with("ENV GH_ENTERPRISE_TOKEN=") {
            assert_eq!(host, "ghe.corp", "enterprise token sent to {host}");
            seen.0 += 1;
        }
        if line.starts_with("ARGS") && host == "github.com" {
            seen.1 += 1;
        }
    }
    assert!(seen.0 > 0 && seen.1 > 0, "{seen:?}");
    assert!(!log.contains("ghe.evil"));
}

/// Answers each connection with what `answer` makes of the request head,
/// and sends every head it saw down the channel.
fn serve(answer: fn(&str) -> String) -> (u16, std::sync::mpsc::Receiver<String>) {
    use std::io::{BufRead, BufReader, Write};
    let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = server.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in server.incoming().take(16) {
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
            let _ = stream.write_all(answer(&head).as_bytes());
            let _ = tx.send(head);
        }
    });
    (port, rx)
}

/// Every CONNECT refused, the way srt's proxy refuses a host that isn't
/// allowed.
fn refusing_proxy() -> u16 {
    serve(|_| "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()).0
}

fn pkt(line: &str) -> String {
    format!("{:04x}{line}", line.len() + 4)
}

/// A git smart-HTTP server that wants Basic auth for x:ghp_testtoken and
/// then advertises an empty repository for receive-pack.
fn push_server(head: &str) -> String {
    if !head.contains("Authorization: Basic eDpnaHBfdGVzdHRva2Vu") {
        return "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"git\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into();
    }
    let body = format!(
        "{}0000{}0000",
        pkt("# service=git-receive-pack\n"),
        pkt(
            "0000000000000000000000000000000000000000 capabilities^{}\0report-status delete-refs\n"
        )
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-git-receive-pack-advertisement\r\nCache-Control: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[test]
fn probe_cannot_run_without_a_usable_srt() {
    let f = Fixture::new("", GITHUB);
    let err = f.probe().unwrap_err().to_string();
    assert!(
        err.contains("npm i -g @anthropic-ai/sandbox-runtime@0.0.79"),
        "{err}"
    );

    f.fake_srt("0.0.78", "");
    let err = f.probe().unwrap_err().to_string();
    assert!(err.contains("0.0.78 is too old"), "{err}");

    let log = f.fake_srt(
        "0.0.79",
        "echo 'Error: Sandbox dependencies not available: bubblewrap (bwrap) not found' >&2; exit 1",
    );
    let err = f.probe().unwrap_err().to_string();
    assert!(err.contains("Sandbox dependencies not available"), "{err}");
    // The settings it was given are gone even so.
    let path = fs::read_to_string(log.join("paths")).unwrap();
    let path = Path::new(path.lines().last().unwrap());
    assert!(
        !path.exists() && !path.parent().unwrap().exists(),
        "{}",
        path.display()
    );

    f.fake_srt("0.0.79", "");
    let mut ctx = f.ctx(Platform::Linux);
    ctx.vars.insert("SANDBOX_RUNTIME".into(), "1".into());
    let opts = Options {
        probe: true,
        ..Options::default()
    };
    let err = verify(&ctx, &opts).unwrap_err().to_string();
    assert!(err.contains("SANDBOX_RUNTIME"), "{err}");
}

#[test]
fn probe_scenario_4_a_push_session_in_srt_fails() {
    let (port, heads) = serve(push_server);
    let url = format!("http://x:ghp_testtoken@127.0.0.1:{port}/o/r.git");
    let f = Fixture::new("\"127.0.0.1\"", &url);
    let log = f.fake_srt("0.0.79", "");
    let r = f.probe().unwrap();
    let c = check(&r, "push-boundary");
    assert_eq!(c.status, Status::Fail, "{}", c.detail);
    assert_eq!(c.evidence, ["static", "probe"]);
    assert!(
        c.detail.contains(&format!(
            "shown in srt with the settings as mezha reads them: 127.0.0.1:{port}: reachable, and the server accepted a push session"
        )),
        "{}",
        c.detail
    );
    assert_eq!(r.probe.as_deref(), Some("srt 0.0.79"));
    // The token really went to the server, and nowhere into the report.
    let seen: Vec<String> = heads.try_iter().collect();
    assert!(
        seen.iter().any(|h| h.contains("Authorization: Basic")),
        "{seen:?}"
    );
    assert!(seen.iter().all(|h| !h.contains("mezha-probe")), "{seen:?}");
    assert!(!r.to_json().contains("ghp_testtoken"));
    assert!(!r.to_human("x").contains("ghp_testtoken"));

    // srt got the settings as mezha reads them, from a file that is gone.
    let settings: Value =
        serde_json::from_str(&fs::read_to_string(log.join("settings.json")).unwrap()).unwrap();
    assert_eq!(settings["network"]["allowedDomains"], json!(["127.0.0.1"]));
    assert_eq!(settings["filesystem"]["allowWrite"], json!([]));
    let files = settings["credentials"]["files"].as_array().unwrap();
    assert!(files.iter().all(|e| e["mode"] == "deny"));
    assert!(
        files
            .iter()
            .any(|e| e["path"] == f.home.join(".ssh").display().to_string())
    );
    for path in fs::read_to_string(log.join("paths")).unwrap().lines() {
        assert!(!Path::new(path).exists(), "{path}");
    }
}

#[test]
fn probe_shows_a_closed_network() {
    let f = Fixture::new("", GITHUB);
    let proxy = format!("http://127.0.0.1:{}", refusing_proxy());
    f.fake_srt(
        "0.0.79",
        &format!("export https_proxy={proxy} HTTPS_PROXY={proxy}"),
    );
    let r = f.probe().unwrap();
    let c = check(&r, "push-boundary");
    assert_eq!(c.status, Status::Pass, "{}", c.detail);
    assert!(
        c.detail.contains("(shown closed in srt: github.com:443)"),
        "{}",
        c.detail
    );
    assert!(
        c.detail
            .contains("srt: github.com:443 refused by the sandbox proxy"),
        "{}",
        c.detail
    );
    assert!(
        r.notes
            .iter()
            .any(|n| n.contains("without the settings' `env` block"))
    );
}

#[test]
fn probe_and_settings_disagreeing_is_a_warning() {
    // mezha reads 127.0.0.1 as closed; this srt lets everything through.
    let (port, _) = serve(|_| {
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"git\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
    });
    let f = Fixture::new("", &format!("http://127.0.0.1:{port}/o/r.git"));
    f.fake_srt("0.0.79", "");
    let r = f.probe().unwrap();
    let c = check(&r, "push-boundary");
    assert_eq!(c.status, Status::Warn, "{}", c.detail);
    assert!(
        c.detail.contains(&format!(
            "srt and mezha's reading of the settings differ: srt reached 127.0.0.1:{port}, which mezha's reading blocks"
        )),
        "{}",
        c.detail
    );
}

#[test]
fn probe_readable_credentials_are_proven() {
    // github.com is allowed, and this srt hides nothing: the ssh key that
    // mezha reads as withheld shows up as readable.
    let f = Fixture::new("\"github.com\"", GITHUB);
    fs::create_dir_all(f.home.join(".ssh")).unwrap();
    fs::write(f.home.join(".ssh/id_ed25519"), "key").unwrap();
    let proxy = format!("http://127.0.0.1:{}", refusing_proxy());
    f.fake_srt(
        "0.0.79",
        &format!("export https_proxy={proxy} HTTPS_PROXY={proxy}"),
    );
    let r = f.probe().unwrap();
    let c = check(&r, "push-boundary");
    assert_eq!(c.status, Status::Fail, "{}", c.detail);
    assert!(
        c.detail
            .contains("shown readable in srt: ~/.ssh/id_ed25519"),
        "{}",
        c.detail
    );
    assert!(
        c.detail
            .contains("srt refused github.com:443, which mezha's reading allows"),
        "{}",
        c.detail
    );
    assert!(
        c.detail
            .contains("~/.ssh/id_ed25519 is withheld by mezha's reading but readable in srt"),
        "{}",
        c.detail
    );
}
