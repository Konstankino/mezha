//! `--probe` and `--inside` on a fake machine with no network: a stand-in
//! `srt` that keeps the settings it is given and runs the probe scripts
//! under bash with no sandbox, a proxy nobody answers on, and credential
//! files and variables the stand-in hides or lets through on purpose.
//! Nothing here binds a port, so it runs inside a sandbox too; the
//! listener scenarios live in `boundary.rs` and `probe.rs`.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use mezha_verify::probe::{Outcome, TestHook, network_direct};
use mezha_verify::{CantRun, Check, Ctx, Options, Platform, Report, Status, verify};
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

const GITHUB: &str = "https://github.com/o/r.git";
const LOCAL: &str = "/srv/git/r.git";

/// A proxy on a port nobody listens on, so the network probe runs its
/// script and fails to connect instead of reaching anything real.
const CLOSED_PROXY: &str = "export https_proxy=http://127.0.0.1:1 HTTPS_PROXY=http://127.0.0.1:1 http_proxy=http://127.0.0.1:1";

fn spec(egress: &str) -> String {
    format!(
        "[project]\nname = \"core\"\n\n[policy]\negress_allow = [{egress}]\npermissions_ask = [\"git push\"]\n"
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
        f.tool("unshare", "exit 0");
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

    /// A stand-in `srt` that prints `version`, keeps a copy of the settings
    /// it is given (and their path) in `<base>/srt`, runs `before`, then
    /// runs the command with bash and no sandbox. `before` sees the probe
    /// script in `MEZHA_PROBE_SCRIPT`, so it can tell the legs apart.
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
        let rendered = mezha_render::render(&spec, text, &self.root).unwrap();
        let plan = mezha_render::plan(&self.root, &rendered).unwrap();
        mezha_render::write(&self.root, &plan, mezha_render::Mode::Apply, "t").unwrap();
    }

    fn ctx(&self) -> Ctx {
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
            platform: Platform::Linux,
            managed_dir: Some(self.managed.clone()),
            mezha_exe: None,
            agent_writable: Vec::new(),
        }
    }

    fn probe_with(&self, ctx: &Ctx) -> Result<Report, CantRun> {
        verify(
            ctx,
            &Options {
                probe: true,
                ..Options::default()
            },
        )
    }

    fn probe(&self) -> Result<Report, CantRun> {
        self.probe_with(&self.ctx())
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
}

fn check<'a>(report: &'a Report, id: &str) -> &'a Check {
    report.checks.iter().find(|c| c.id == id).unwrap()
}

fn notes(report: &Report) -> String {
    report.notes.join("\n")
}

#[test]
fn options_that_do_not_go_together_cannot_run() {
    let f = Fixture::new("", GITHUB);
    let with = |opts: Options| verify(&f.ctx(), &opts).unwrap_err().to_string();
    assert_eq!(
        with(Options {
            probe: true,
            project_only: true,
            inside: false,
        }),
        "--probe can't run: it doesn't go with --project-only"
    );
    let mut inside_claude = f.ctx();
    inside_claude.vars.insert("CLAUDECODE".into(), "1".into());
    for opts in [
        Options {
            inside: true,
            probe: true,
            project_only: false,
        },
        Options {
            inside: true,
            probe: false,
            project_only: true,
        },
    ] {
        let err = verify(&inside_claude, &opts).unwrap_err();
        assert!(matches!(err, CantRun::Inside(_)), "{err:?}");
        assert_eq!(
            err.to_string(),
            "--inside can't run: it doesn't go with --project-only or --probe"
        );
    }
}

#[test]
fn a_spec_with_errors_cannot_run() {
    let f = Fixture::new("", GITHUB);
    fs::write(
        f.root.join("mezha.toml"),
        "schema = 0\n\n[project]\nname = \"core\"\n",
    )
    .unwrap();
    let err = verify(&f.ctx(), &Options::default()).unwrap_err();
    let CantRun::Spec(why) = &err else {
        panic!("{err:?}");
    };
    assert!(why.starts_with("mezha.toml has errors:\n"), "{why}");
    assert!(why.contains("unknown schema 0"), "{why}");
    assert_eq!(err.to_string(), *why);

    fs::remove_file(f.root.join("mezha.toml")).unwrap();
    let err = verify(&f.ctx(), &Options::default()).unwrap_err();
    assert_eq!(
        err.to_string(),
        format!(
            "{} not found (run `mezha init`)",
            f.root.join("mezha.toml").display()
        )
    );
}

#[test]
fn probe_whose_srt_vanishes_after_its_start_check_cannot_start() {
    let f = Fixture::new("", GITHUB);
    // The stand-in removes itself once started: the probes find no srt.
    f.fake_srt("0.0.79", r#"rm -f "$0""#);
    let r = f.probe().unwrap();
    assert!(!f.bin.join("srt").exists());
    let c = check(&r, "push-boundary");
    assert_eq!(c.status, Status::Pass, "{}", c.detail);
    assert!(
        c.detail
            .contains("; srt: github.com:443 inconclusive (the probe couldn't start ("),
        "{}",
        c.detail
    );
    assert!(
        notes(&r).contains("the credential probe didn't finish"),
        "{}",
        notes(&r)
    );
}

#[test]
fn probe_cannot_run_with_an_srt_an_agent_could_have_put_there() {
    let f = Fixture::new("", GITHUB);
    // The only srt sits inside the project, where an agent can write.
    let planted = f.root.join("node_modules/.bin");
    fs::create_dir_all(&planted).unwrap();
    fs::write(planted.join("srt"), "#!/bin/sh\necho 0.0.79\n").unwrap();
    fs::set_permissions(planted.join("srt"), fs::Permissions::from_mode(0o755)).unwrap();
    let mut ctx = f.ctx();
    let path = ctx.vars["PATH"].clone();
    ctx.vars
        .insert("PATH".into(), format!("{}:{path}", planted.display()));
    let err = f.probe_with(&ctx).unwrap_err().to_string();
    assert!(err.contains("isn't installed"), "{err}");
    assert!(
        err.contains(&format!(
            "; ignored `srt` at {} (inside the project): an agent can put programs there",
            planted.join("srt").display()
        )),
        "{err}"
    );
}

#[test]
fn probe_cannot_run_when_srt_cannot_start_quietly() {
    let f = Fixture::new("", GITHUB);
    f.fake_srt("0.0.79", "exit 1");
    let err = f.probe().unwrap_err().to_string();
    assert_eq!(
        err,
        "--probe can't run: srt can't start a sandbox here: it printed nothing"
    );

    f.tool("srt", "echo 'sandbox-runtime (unversioned)'");
    let err = f.probe().unwrap_err().to_string();
    assert!(
        err.contains("can't read srt's version from `sandbox-runtime (unversioned)`"),
        "{err}"
    );
}

#[test]
fn probe_with_a_local_remote_runs_only_the_credential_leg() {
    let f = Fixture::new("", LOCAL);
    let log = f.fake_srt("0.0.79", "");
    let r = f.probe().unwrap();
    assert_eq!(r.probe.as_deref(), Some("srt 0.0.79"));
    let c = check(&r, "push-boundary");
    assert_eq!(c.status, Status::Pass, "{}", c.detail);
    assert_eq!(c.evidence, ["static", "probe"]);
    assert_eq!(c.detail, "no remote to push to and no gh login");
    assert!(
        notes(&r).contains(
            "the credential probe ran without the settings' `env` block, which Claude Code adds inside the sandbox"
        ),
        "{}",
        notes(&r)
    );
    assert!(!notes(&r).contains("not probed"), "{}", notes(&r));
    // srt was started once to check it runs, then once for the credential
    // leg, with settings that allow no writes; the file is gone now.
    let paths = fs::read_to_string(log.join("paths")).unwrap();
    assert_eq!(paths.lines().count(), 2, "{paths}");
    for path in paths.lines() {
        assert!(!Path::new(path).exists(), "{path}");
    }
    let settings: Value =
        serde_json::from_str(&fs::read_to_string(log.join("settings.json")).unwrap()).unwrap();
    assert_eq!(settings["filesystem"]["allowWrite"], json!([]));
    assert_eq!(settings["network"]["allowedDomains"], json!([]));
}

#[test]
fn probe_through_a_proxy_nobody_answers_is_inconclusive() {
    let f = Fixture::new("", GITHUB);
    // CA settings from the global config are handed to the probe's git.
    let ca = f.base.join("ca.pem");
    fs::write(&ca, "not a certificate\n").unwrap();
    fs::write(
        &f.gitconfig,
        format!(
            "[http]\n\tsslCAInfo = {}\n\tsslCAPath = {}\n",
            ca.display(),
            f.base.display()
        ),
    )
    .unwrap();
    f.fake_srt("0.0.79", CLOSED_PROXY);
    let r = f.probe().unwrap();
    let c = check(&r, "push-boundary");
    assert_eq!(c.status, Status::Pass, "{}", c.detail);
    assert_eq!(c.evidence, ["static", "probe"]);
    assert!(
        c.detail
            .starts_with("sandboxed commands can't reach api.github.com:443, github.com:443"),
        "{}",
        c.detail
    );
    assert!(
        c.detail
            .ends_with("; srt: github.com:443 inconclusive (the connection failed)"),
        "{}",
        c.detail
    );
    assert!(!c.detail.contains("shown closed"), "{}", c.detail);
}

#[test]
fn probe_cannot_make_a_scratch_repository_with_a_broken_git() {
    let f = Fixture::new("", GITHUB);
    // A git that refuses `init` and passes everything else on.
    f.tool(
        "git",
        r#"case "$*" in "init "*) echo 'fatal: no init here' >&2; exit 128 ;; esac
PATH=/usr/bin:/bin exec git "$@""#,
    );
    f.fake_srt("0.0.79", CLOSED_PROXY);
    let r = f.probe().unwrap();
    let c = check(&r, "push-boundary");
    assert_eq!(c.status, Status::Pass, "{}", c.detail);
    assert!(
        c.detail
            .ends_with("; srt: github.com:443 inconclusive (couldn't create a scratch repository)"),
        "{}",
        c.detail
    );
}

#[test]
fn probe_credentials_masked_in_the_settings_cannot_be_judged() {
    let f = Fixture::new("\"github.com\"", GITHUB);
    fs::create_dir_all(f.home.join(".ssh")).unwrap();
    fs::write(f.home.join(".ssh/id_ed25519"), "key").unwrap();
    // The project denies ~/.ssh; the user masks the key, which srt can't.
    f.user_settings(json!({
        "sandbox": { "credentials": { "files": [
            { "path": "~/.ssh/id_ed25519", "mode": "mask" }
        ] } }
    }));
    f.fake_srt("0.0.79", CLOSED_PROXY);
    let r = f.probe().unwrap();
    let c = check(&r, "push-boundary");
    assert_eq!(c.status, Status::Warn, "{}", c.detail);
    assert!(
        c.detail.contains(
            "unverified: sandboxed commands can reach github.com:443, and these credential sources can't be judged: ~/.ssh/id_ed25519 (masked in the settings; srt can't mask)"
        ),
        "{}",
        c.detail
    );
    assert!(!c.detail.contains("differ"), "{}", c.detail);
}

/// The stand-in keeps a file out and removes a variable that mezha's
/// reading of the settings doesn't withhold, and lets a masked variable
/// through: each is reported for what it is.
#[test]
fn probe_credentials_srt_keeps_out_or_removes_differ_from_the_settings() {
    let f = Fixture::new("", GITHUB);
    let creds = f.base.join("elsewhere/creds");
    fs::create_dir_all(creds.parent().unwrap()).unwrap();
    fs::write(&creds, "https://x:t@h\n").unwrap();
    fs::write(
        &f.gitconfig,
        format!(
            "[credential]\n\thelper = store --file={}\n",
            creds.display()
        ),
    )
    .unwrap();
    f.user_settings(json!({
        "sandbox": { "credentials": { "envVars": [
            { "name": "GITEA_API_TOKEN", "mode": "mask" }
        ] } }
    }));
    f.fake_srt(
        "0.0.79",
        &format!(
            r#"{CLOSED_PROXY}
case "$MEZHA_PROBE_SCRIPT" in *MEZHA_PROBE_DONE*) MEZHA_PROBE_FILES=; export MEZHA_PROBE_FILES; unset MY_GITHUB_PAT ;; esac"#
        ),
    );
    let mut ctx = f.ctx();
    ctx.vars.insert("MY_GITHUB_PAT".into(), "p".into());
    ctx.vars.insert("GITEA_API_TOKEN".into(), "t".into());
    let r = f.probe_with(&ctx).unwrap();
    let c = check(&r, "push-boundary");
    assert_eq!(c.status, Status::Warn, "{}", c.detail);
    assert!(
        c.detail.starts_with(&format!(
            "srt and mezha's reading of the settings differ: {} isn't withheld by mezha's reading but srt kept it out; MY_GITHUB_PAT isn't withheld by mezha's reading but srt removed it; sandboxed commands can't reach",
            creds.display()
        )),
        "{}",
        c.detail
    );
    assert!(
        c.fix
            .as_deref()
            .is_some_and(|fix| fix.contains("Report this as a mezha bug")),
        "{:?}",
        c.fix
    );
    let json = r.to_json();
    assert!(!json.contains("x:t@h"), "{json}");
}

#[test]
fn probe_credential_leg_that_does_not_finish_is_noted() {
    let f = Fixture::new("", LOCAL);
    f.fake_srt(
        "0.0.79",
        r#"case "$MEZHA_PROBE_SCRIPT" in *MEZHA_PROBE_DONE*) echo 'F0' ; exit 1 ;; esac"#,
    );
    let r = f.probe().unwrap();
    assert!(
        notes(&r).contains(
            "the credential probe didn't finish, so credentials were judged from the settings only"
        ),
        "{}",
        notes(&r)
    );
    let c = check(&r, "push-boundary");
    assert_eq!(c.status, Status::Pass, "{}", c.detail);
}

#[test]
fn probe_notes_say_when_it_ran_inside_claude_code_or_did_not_run() {
    let f = Fixture::new("", LOCAL);
    f.fake_srt("0.0.79", "");
    let mut ctx = f.ctx();
    ctx.vars.insert("CLAUDECODE".into(), "1".into());
    let r = f.probe_with(&ctx).unwrap();
    assert!(
        notes(&r).contains(
            "running inside Claude Code: this environment differs from your own terminal's"
        ),
        "{}",
        notes(&r)
    );
    assert!(
        notes(&r).contains("srt starts inside Claude Code only from an unsandboxed `!` command"),
        "{}",
        notes(&r)
    );

    // With the sandbox off, srt is still checked but the probes don't run.
    f.local_settings(json!({ "sandbox": { "enabled": false } }));
    let r = f.probe().unwrap();
    assert_eq!(r.probe.as_deref(), Some("srt 0.0.79"));
    assert!(
        notes(&r).contains("the probes didn't run, since the sandbox isn't in effect"),
        "{}",
        notes(&r)
    );
    assert!(!notes(&r).contains("credential probe"), "{}", notes(&r));
    let c = check(&r, "push-boundary");
    assert_eq!(c.status, Status::Fail, "{}", c.detail);
    assert_eq!(c.evidence, ["static"]);
}

#[test]
fn probe_leaves_out_urls_it_cannot_pass_safely() {
    let f = Fixture::new("", "https://github.com/o/$(id).git");
    f.fake_srt("0.0.79", CLOSED_PROXY);
    let r = f.probe().unwrap();
    assert!(
        notes(&r).contains("not probed: https://github.com/o/$(id).git"),
        "{}",
        notes(&r)
    );
    let c = check(&r, "push-boundary");
    assert_eq!(c.status, Status::Pass, "{}", c.detail);
    assert!(!c.detail.contains("srt:"), "{}", c.detail);
}

#[test]
fn network_direct_without_git_says_so() {
    let f = Fixture::new("", GITHUB);
    let mut ctx = f.ctx();
    ctx.vars.insert("PATH".into(), f.bin.display().to_string());
    let (outcome, printed) = network_direct(&ctx, GITHUB, TestHook::default());
    assert_eq!(outcome, Outcome::Inconclusive("no git".into()), "{printed}");
    assert_eq!(printed, "");
}
