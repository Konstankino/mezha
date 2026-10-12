//! The fake machine the `checks_*` tests run verify on, as `boundary.rs`
//! builds it: a compiled project, a scratch home and managed directory, no
//! system or global git config, and stand-in `claude`, `bwrap`, `socat`,
//! `unshare` and `gh` on PATH. The stand-ins here answer from scripts, so
//! no test binds a port.

#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use mezha_verify::{Ctx, Options, Platform, Report, Status, verify};
use serde_json::Value;

pub const GITHUB: &str = "https://github.com/o/r.git";

pub struct Fixture {
    _tmp: tempfile::TempDir,
    pub base: PathBuf,
    pub home: PathBuf,
    /// The git root.
    pub repo: PathBuf,
    /// The project root: where `mezha.toml` is, the git root unless the
    /// fixture is nested.
    pub root: PathBuf,
    pub managed: PathBuf,
    pub bin: PathBuf,
    pub gitconfig: PathBuf,
}

pub fn spec(egress: &str) -> String {
    format!(
        "[project]\nname = \"checks\"\n\n[policy]\negress_allow = [{egress}]\npermissions_ask = [\"git push\"]\n"
    )
}

/// Two agents with memory: `helper` in project scope, `medic` with PHI
/// (local scope).
pub const WITH_AGENTS: &str = r#"[project]
name = "checks"

[policy]
egress_allow = []
permissions_ask = ["git push"]

[agent.helper]
description = "Helps with the code."
tools = ["Read", "Grep"]
rule_of_two = []
memory = {}

[agent.medic]
description = "Works on the clinical module."
tools = ["Read"]
rule_of_two = ["private_data"]
memory = { class = "phi" }
"#;

/// One agent whose memory lives in the user's scope.
pub const USER_MEMORY: &str = r#"[project]
name = "checks"

[policy]
egress_allow = []
permissions_ask = ["git push"]

[agent.helper]
description = "Helps with the code."
tools = ["Read", "Grep"]
rule_of_two = []
memory = { scope = "user" }
"#;

/// One agent with a scoped Bash, which gets the `agent-bash` hook.
pub const WITH_BASH_AGENT: &str = r#"[project]
name = "checks"

[policy]
egress_allow = []
permissions_ask = ["git push"]

[agent.tester]
description = "Runs the tests."
tools = ["Read", "Bash(cargo test *)"]
rule_of_two = []
"#;

impl Fixture {
    pub fn new(egress: &str, remote: &str) -> Fixture {
        Fixture::build(egress, remote, false)
    }

    /// A project in a subdirectory of the git repository.
    pub fn nested(egress: &str, remote: &str) -> Fixture {
        Fixture::build(egress, remote, true)
    }

    fn build(egress: &str, remote: &str, nested: bool) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let home = base.join("home");
        let repo = base.join("repo");
        let root = if nested {
            repo.join("sub")
        } else {
            repo.clone()
        };
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
            repo,
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

    /// A stand-in shell script on the fake PATH.
    pub fn tool(&self, name: &str, body: &str) {
        self.tool_in(&self.bin, name, body);
    }

    /// A stand-in shell script in `dir`.
    pub fn tool_in(&self, dir: &Path, name: &str, body: &str) {
        fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// An executable on the fake PATH that can't be started: its
    /// interpreter doesn't exist, so spawning it fails (a file without a
    /// shebang would be run through `sh` instead).
    pub fn broken_tool(&self, name: &str) {
        let path = self.bin.join(name);
        fs::write(&path, "#!/nonexistent/interpreter\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A symlink on the fake PATH to the real `name` on this machine's
    /// PATH, for tests whose PATH holds only the fake bin.
    pub fn link_real(&self, name: &str) {
        let real = std::env::var_os("PATH")
            .and_then(|path| {
                std::env::split_paths(&path)
                    .map(|dir| dir.join(name))
                    .find(|p| p.is_file())
            })
            .unwrap_or_else(|| panic!("no `{name}` on this machine's PATH"));
        std::os::unix::fs::symlink(real, self.bin.join(name)).unwrap();
    }

    /// A stand-in `gh` that answers from a recorded case in
    /// `tests/fixtures/protection` (after `edit`); a missing file is a 404.
    pub fn fake_gh(&self, case: &str, edit: impl Fn(&str, String) -> String) {
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
        self.tool(
            "gh",
            &format!(
                r#"args="$*"
case "$args" in
  *branchProtectionRule*) file=admin.json ;;
  *requiresSignatures*) file=signatures.json ;;
  *userLogins*) file=teams.json ;;
  *graphql*) file=graphql.json ;;
  */rules/branches/*) file=rules.json ;;
  */rulesets/*) file=ruleset-$(printf '%s' "$args" | sed -n 's|.*/rulesets/\([0-9]*\).*|\1|p').json ;;
  *codeowners/errors*) file=codeowners.json ;;
  *" meta "*) file=meta.json ;;
  *) echo "unexpected: $args" >&2; exit 2 ;;
esac
missing='{dir}/'"${{file%.json}}.404.json"
if [ -f '{dir}/'"$file" ]; then cat '{dir}/'"$file"
elif [ -f "$missing" ]; then cat "$missing"; echo 'gh: Not Found (HTTP 404)' >&2; exit 1
else echo '{{"message":"Not Found","documentation_url":"https://docs.github.com/rest/x#y"}}'; echo 'gh: Not Found (HTTP 404)' >&2; exit 1; fi"#,
                dir = dir.display(),
            ),
        );
    }

    pub fn git(&self, args: &[&str]) {
        let out = Command::new("git")
            .args(args)
            .current_dir(&self.repo)
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

    pub fn commit_all(&self) {
        self.git(&["add", "-A"]);
        self.git(&[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "commit",
            "-q",
            "--no-verify",
            "-m",
            "x",
        ]);
    }

    pub fn compile(&self, text: &str) {
        fs::write(self.root.join("mezha.toml"), text).unwrap();
        let spec = mezha_spec::parse(text).unwrap();
        let rendered = mezha_render::render(&spec, text, &self.root).unwrap();
        let plan = mezha_render::plan(&self.root, &rendered).unwrap();
        mezha_render::write(&self.root, &plan, mezha_render::Mode::Apply, "t").unwrap();
    }

    /// Compiles `WITH_AGENTS`, writing its body files first.
    pub fn with_agents(&self) {
        self.body("helper", "Help.\n");
        self.body("medic", "Treat data with care.\n");
        self.compile(WITH_AGENTS);
    }

    /// An agent's body file under `mezha/agents/`.
    pub fn body(&self, agent: &str, text: &str) {
        let dir = self.root.join("mezha/agents");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(format!("{agent}.md")), text).unwrap();
    }

    /// A file in the project, with its parent directories.
    pub fn file(&self, rel: &str, text: &str) {
        let path = self.root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    pub fn path(&self) -> String {
        format!("{}:/usr/bin:/bin", self.bin.display())
    }

    pub fn ctx(&self, platform: Platform) -> Ctx {
        Ctx {
            root: self.root.clone(),
            vars: [
                ("PATH", self.path()),
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

    pub fn verify_on(&self, platform: Platform, opts: Options) -> Report {
        verify(&self.ctx(platform), &opts).unwrap()
    }

    pub fn verify(&self) -> Report {
        self.verify_on(Platform::Linux, Options::default())
    }

    /// verify with extra variables in the environment.
    pub fn verify_with(&self, vars: &[(&str, &str)]) -> Report {
        let mut ctx = self.ctx(Platform::Linux);
        for (k, v) in vars {
            ctx.vars.insert(k.to_string(), v.to_string());
        }
        verify(&ctx, &Options::default()).unwrap()
    }

    pub fn write_json(&self, path: &Path, value: Value) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, value.to_string()).unwrap();
    }

    pub fn user_settings(&self, value: Value) {
        self.write_json(&self.home.join(".claude/settings.json"), value);
    }

    pub fn local_settings(&self, value: Value) {
        self.write_json(&self.root.join(".claude/settings.local.json"), value);
    }

    pub fn managed_settings(&self, value: Value) {
        self.write_json(&self.managed.join("managed-settings.json"), value);
    }

    pub fn edit_settings(&self, edit: impl FnOnce(&mut Value)) {
        let path = self.root.join(".claude/settings.json");
        let mut v: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        edit(&mut v);
        fs::write(&path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    }
}

pub fn check<'a>(report: &'a Report, id: &str) -> &'a mezha_verify::Check {
    report
        .checks
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("no check `{id}` in {}", report.to_human("x")))
}

pub fn status(report: &Report, id: &str) -> Status {
    check(report, id).status
}

pub fn detail<'a>(report: &'a Report, id: &str) -> &'a str {
    &check(report, id).detail
}

/// Asserts a check's status, showing its detail when it isn't so.
pub fn expect(report: &Report, id: &str, want: Status) {
    let c = check(report, id);
    assert_eq!(c.status, want, "{id}: {}", c.detail);
}

/// Asserts a check's detail holds `text`, showing the detail when it
/// doesn't.
pub fn expect_detail(report: &Report, id: &str, text: &str) {
    let d = detail(report, id);
    assert!(d.contains(text), "{id}: {text:?} not in {d:?}");
}
