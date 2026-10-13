//! The approval gate in-process: events in, exit code and reason out.

use std::path::{Path, PathBuf};

use mezha_broker::approvals;
use mezha_hooks::{Env, Outcome, PROTOCOL, run};
use serde_json::{Value, json};

const NOW: u64 = 1_800_000_000;

struct Fixture {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    repo: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let home = base.join("home");
        let repo = base.join("repo");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        Fixture {
            _tmp: tmp,
            home,
            repo,
        }
    }

    fn env(&self) -> Env {
        Env::new(
            [
                ("HOME", self.home.to_str().unwrap()),
                ("CLAUDE_PROJECT_DIR", self.repo.to_str().unwrap()),
            ],
            NOW,
        )
    }

    fn fire(&self, event: Value) -> Outcome {
        self.fire_with(&self.env(), event)
    }

    fn fire_with(&self, env: &Env, event: Value) -> Outcome {
        let argv: Vec<String> = [
            "approval-gate",
            "--protocol",
            &PROTOCOL.to_string(),
            "--gate",
            "git push",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let out = run(&argv, event.to_string().as_bytes(), env);
        assert!(out.code == 0 || out.code == 2, "{out:?}");
        out
    }

    fn approve(&self, root: &Path) {
        approvals::grant(&self.home, root, 10, NOW).unwrap();
    }
}

fn bash(command: &str) -> Value {
    json!({
        "session_id": "s",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "cwd": "/somewhere/else",
    })
}

fn tool(name: &str, input: Value) -> Value {
    json!({ "hook_event_name": "PreToolUse", "tool_name": name, "tool_input": input })
}

#[test]
fn a_push_needs_an_approval() {
    let f = Fixture::new();
    let out = f.fire(bash("git push origin main"));
    assert!(out.is_block());
    assert!(out.stderr.contains("`git push` is gated"), "{}", out.stderr);
    assert!(out.stderr.contains("own terminal"));
    assert!(out.stderr.contains("mezha approve --minutes 30"));
    assert!(out.stderr.contains("advisory"));

    f.approve(&f.repo);
    assert_eq!(f.fire(bash("git push origin main")), Outcome::allow());
    // Allowing never means "allow": no output, so permission rules still ask.
    assert!(f.fire(bash("git push")).stderr.is_empty());
}

#[test]
fn ordinary_calls_pass() {
    let f = Fixture::new();
    assert_eq!(f.fire(bash("git status")), Outcome::allow());
    assert_eq!(
        f.fire(tool("Read", json!({ "file_path": "/etc/hosts" }))),
        Outcome::allow()
    );
    assert_eq!(
        f.fire(tool("TodoWrite", json!({ "todos": [] }))),
        Outcome::allow()
    );
}

#[test]
fn an_approval_for_another_repo_does_not_count() {
    let f = Fixture::new();
    f.approve(&f.repo.with_file_name("other"));
    assert!(f.fire(bash("git push")).is_block());
}

#[test]
fn an_approval_from_a_subdirectory_counts() {
    let f = Fixture::new();
    f.approve(&f.repo);
    let sub = f.repo.join("src");
    std::fs::create_dir_all(&sub).unwrap();
    let env = Env::new(
        [
            ("HOME", f.home.to_str().unwrap()),
            ("CLAUDE_PROJECT_DIR", sub.to_str().unwrap()),
        ],
        NOW,
    );
    assert_eq!(f.fire_with(&env, bash("git push")), Outcome::allow());
}

#[test]
fn without_claude_project_dir_the_event_cwd_is_used() {
    let f = Fixture::new();
    f.approve(&f.repo);
    let env = Env::new([("HOME", f.home.to_str().unwrap())], NOW);
    let mut event = bash("git push");
    event["cwd"] = json!(f.repo);
    assert_eq!(f.fire_with(&env, event), Outcome::allow());
    let mut event = bash("git push");
    event.as_object_mut().unwrap().remove("cwd");
    assert!(f.fire_with(&env, event).is_block());
}

#[test]
fn the_agent_cannot_approve_itself_even_when_approved() {
    let f = Fixture::new();
    f.approve(&f.repo);
    let out = f.fire(bash("mezha approve --minutes 600"));
    assert!(out.is_block());
    assert!(out.stderr.contains("must be run by a human"));
    assert_eq!(f.fire(bash("mezha approve --status")), Outcome::allow());
}

#[test]
fn no_tool_may_touch_the_store() {
    let f = Fixture::new();
    let store = approvals::store_dir(&f.home);
    let inside = store.join("x.json");
    for input in [
        json!({ "file_path": inside }),
        json!({ "file_path": "~/.mezha/approvals/x.json" }),
        json!({ "notebook_path": f.home.join(".mezha") }),
        json!({ "path": f.home.join("a/../.mezha/approvals") }),
        json!({ "file_path": "../home/.mezha/approvals/x.json" }),
    ] {
        for name in ["Edit", "Write", "NotebookEdit", "Grep"] {
            let out = f.fire(tool(name, input.clone()));
            assert!(out.is_block(), "{name} {input}: {out:?}");
        }
    }
    assert_eq!(
        f.fire(tool(
            "Edit",
            json!({ "file_path": f.home.join(".mezhafoo") })
        )),
        Outcome::allow()
    );
}

/// A symlink in the project to an approval that doesn't exist yet: writing
/// through it would create the approval.
#[cfg(unix)]
#[test]
fn dangling_symlinks_into_the_store_block() {
    let f = Fixture::new();
    let target = approvals::store_dir(&f.home).join("forged.json");
    let link = f.repo.join("innocent.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let out = f.fire(tool("Write", json!({ "file_path": link })));
    assert!(out.is_block(), "{out:?}");
}

#[cfg(any(target_os = "macos", windows))]
#[test]
fn store_check_ignores_case_where_the_file_system_does() {
    let f = Fixture::new();
    let shouty = f.home.join(".MEZHA/Approvals/x.json");
    assert!(
        f.fire(tool("Write", json!({ "file_path": shouty })))
            .is_block()
    );
}

#[test]
fn malformed_input_blocks() {
    let f = Fixture::new();
    let argv: Vec<String> = ["approval-gate", "--protocol", "1"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    for input in [&b""[..], b"not json", b"[1,2]", b"null", b"\xff\xfe"] {
        assert!(run(&argv, input, &f.env()).is_block(), "{input:?}");
    }
    let huge = vec![b' '; mezha_hooks::MAX_INPUT + 1];
    assert!(run(&argv, &huge, &f.env()).is_block());
}

#[test]
fn unexpected_events_and_shapes_block() {
    let f = Fixture::new();
    let mut post = bash("ls");
    post["hook_event_name"] = json!("PostToolUse");
    assert!(f.fire(post).is_block());
    let mut nameless = bash("ls");
    nameless.as_object_mut().unwrap().remove("tool_name");
    assert!(f.fire(nameless).is_block());
    for name in ["Bash", "PowerShell", "Monitor"] {
        assert!(
            f.fire(tool(name, json!({ "description": "x" }))).is_block(),
            "{name}"
        );
    }
    assert!(
        f.fire(tool("Bash", json!({ "command": ["git", "push"] })))
            .is_block()
    );
    assert!(f.fire(bash("git status\u{1b}[2K")).is_block());
}

#[test]
fn any_tool_with_a_command_is_gated() {
    let f = Fixture::new();
    for name in ["PowerShell", "Monitor", "mcp__shell__run"] {
        assert!(
            f.fire(tool(name, json!({ "command": "git push" })))
                .is_block(),
            "{name}"
        );
    }
}

#[test]
fn expired_and_implausible_approvals_block() {
    let f = Fixture::new();
    approvals::grant(&f.home, &f.repo, 1, NOW - 120).unwrap();
    assert!(f.fire(bash("git push")).is_block(), "expired");
    approvals::grant(&f.home, &f.repo, 1440, NOW + 86_400).unwrap();
    assert!(f.fire(bash("git push")).is_block(), "too far ahead");
}

/// The audit log's records for the fixture's repository, oldest first.
fn audit(f: &Fixture) -> Vec<Value> {
    let dir = mezha_hooks::audit::dir(&f.home, Some(&f.repo));
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    files
        .iter()
        .flat_map(|p| {
            std::fs::read_to_string(p)
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect::<Vec<Value>>()
        })
        .collect()
}

#[test]
fn every_decision_is_recorded_without_its_content() {
    let f = Fixture::new();
    let mut push = bash("git push origin main --token=s3cret");
    push["tool_use_id"] = json!("toolu_1");
    assert!(f.fire(push).is_block());
    let mut read = tool("Read", json!({ "file_path": "/etc/hosts" }));
    read["session_id"] = json!("s");
    read["tool_use_id"] = json!("toolu_2");
    read["agent_type"] = json!("explorer");
    assert_eq!(f.fire(read), Outcome::allow());

    let records = audit(&f);
    assert_eq!(records.len(), 2, "{records:#?}");
    let (block, pass) = (&records[0], &records[1]);
    assert_eq!(block["type"], "admission");
    assert_eq!(block["decision"], "block");
    assert!(block["reason"].as_str().unwrap().contains("is gated"));
    assert_eq!(block["tool_name"], "Bash");
    assert_eq!(block["ts_ms"], NOW * 1000);
    assert_eq!(block["preimage"], json!(["session_id", "tool_use_id"]));
    assert!(
        block["input_sha256"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert_eq!(pass["decision"], "pass");
    assert_eq!(pass["agent_type"], "explorer");
    assert!(pass.get("reason").is_none());
    // Digests only: no command text, no paths.
    let text = serde_json::to_string(&records).unwrap();
    assert!(
        !text.contains("s3cret") && !text.contains("/etc/hosts"),
        "{text}"
    );
    let dir = mezha_hooks::audit::dir(&f.home, Some(&f.repo));
    assert!(dir.starts_with(approvals::mezha_home(&f.home).join("audit")));

    // The outcome joins its admission by attempt_id.
    let done = json!({
        "session_id": "s",
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_use_id": "toolu_2",
        "tool_response": { "content": "secret file text" },
    });
    let argv: Vec<String> = ["audit-outcome", "--protocol", &PROTOCOL.to_string()]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        run(&argv, done.to_string().as_bytes(), &f.env()),
        Outcome::allow()
    );
    let records = audit(&f);
    assert_eq!(records[2]["type"], "outcome");
    assert_eq!(records[2]["terminal_state"], "committed");
    assert_eq!(records[2]["attempt_id"], records[1]["attempt_id"]);
    assert!(
        !serde_json::to_string(&records[2])
            .unwrap()
            .contains("secret file")
    );
    let mut failed = done.clone();
    failed["hook_event_name"] = json!("PostToolUseFailure");
    failed["is_interrupt"] = json!(true);
    run(&argv, failed.to_string().as_bytes(), &f.env());
    let last = audit(&f).pop().unwrap();
    assert_eq!(last["terminal_state"], "failed");
    assert_eq!(last["interrupted"], true);
}

#[cfg(unix)]
#[test]
fn a_call_that_cannot_be_recorded_is_blocked() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let store = approvals::mezha_home(&f.home);
    std::fs::create_dir_all(&store).unwrap();
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o500)).unwrap();
    let out = f.fire(bash("git status"));
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(out.is_block(), "{out:?}");
    assert!(
        out.stderr.contains("couldn't write the audit log"),
        "{}",
        out.stderr
    );
}

#[test]
fn webfetch_stays_inside_fetch_allow() {
    let f = Fixture::new();
    let argv = |fetch: &[&str]| -> Vec<String> {
        let mut a: Vec<String> = ["approval-gate", "--protocol", &PROTOCOL.to_string()]
            .iter()
            .map(|s| s.to_string())
            .collect();
        if !fetch.is_empty() {
            a.push("--fetch-only".into());
        }
        for host in fetch.iter().filter(|h| !h.is_empty()) {
            a.extend(["--fetch".to_string(), host.to_string()]);
        }
        a
    };
    let fetch = |args: &[String], url: &str| {
        let event = tool("WebFetch", json!({ "url": url, "prompt": "summarise" }));
        run(args, event.to_string().as_bytes(), &f.env())
    };
    let limited = argv(&["docs.rs", "*.python.org"]);
    assert_eq!(fetch(&limited, "https://docs.rs/serde"), Outcome::allow());
    assert_eq!(
        fetch(&limited, "https://docs.python.org/3/"),
        Outcome::allow()
    );
    for url in [
        "https://evil.example/?k=secret",
        "https://docs.rs.evil.example/",
        "https://evil.example\\@docs.rs/",
        "https://python.org/",
        "file:///etc/passwd",
        "not a url",
    ] {
        let out = fetch(&limited, url);
        assert!(out.is_block(), "{url}: {out:?}");
    }
    let out = fetch(&limited, "https://evil.example/");
    assert!(
        out.stderr
            .contains("policy.fetch_allow (docs.rs, *.python.org)"),
        "{}",
        out.stderr
    );
    // `fetch_allow = []`: nothing; no list: anything, as before.
    assert!(fetch(&argv(&[""]), "https://docs.rs/").is_block());
    assert_eq!(fetch(&argv(&[]), "https://evil.example/"), Outcome::allow());
    // A list without --fetch-only means the command was edited.
    let mut edited = argv(&[]);
    edited.extend(["--fetch".to_string(), "docs.rs".to_string()]);
    assert!(fetch(&edited, "https://docs.rs/").is_block());
}

#[test]
fn records_link_a_subagent_to_the_call_that_spawned_it() {
    let f = Fixture::new();
    let argv: Vec<String> = ["audit-outcome", "--protocol", &PROTOCOL.to_string()]
        .iter()
        .map(|s| s.to_string())
        .collect();
    // The main thread spawns a subagent...
    let mut spawn = tool(
        "Agent",
        json!({ "subagent_type": "explorer", "prompt": "look" }),
    );
    spawn["session_id"] = json!("s");
    spawn["prompt_id"] = json!("p1");
    spawn["tool_use_id"] = json!("toolu_a");
    assert_eq!(f.fire(spawn.clone()), Outcome::allow());
    // ...whose own call carries its agent_id...
    let mut inner = tool("Read", json!({ "file_path": "x" }));
    inner["session_id"] = json!("s");
    inner["prompt_id"] = json!("p1");
    inner["tool_use_id"] = json!("toolu_b");
    inner["agent_id"] = json!("a42");
    inner["agent_type"] = json!("explorer");
    assert_eq!(f.fire(inner), Outcome::allow());
    // ...and the Agent call's result names the run it started.
    let mut done = spawn;
    done["hook_event_name"] = json!("PostToolUse");
    done["tool_response"] =
        json!({ "status": "completed", "agentId": "a42", "content": "found it" });
    run(&argv, done.to_string().as_bytes(), &f.env());

    let records = audit(&f);
    let (parent, child, outcome) = (&records[0], &records[1], &records[2]);
    assert_eq!(parent["prompt_id"], "p1");
    assert_eq!(child["prompt_id"], "p1");
    assert_eq!(child["agent_id"], "a42");
    assert_eq!(outcome["attempt_id"], parent["attempt_id"]);
    assert_eq!(outcome["spawned_agent_id"], child["agent_id"]);
    assert!(!serde_json::to_string(outcome).unwrap().contains("found it"));
}

/// Claude Code lets a crashed hook's call through, so a panic inside the
/// hook is caught and answered with exit 2 like any other failure.
#[test]
fn a_crash_inside_the_hook_blocks() {
    let f = Fixture::new();
    f.approve(&f.repo);
    // A clock at the end of time overflows the approval arithmetic.
    let mut env = f.env();
    env.now = u64::MAX;
    let out = f.fire_with(&env, bash("git push"));
    assert!(out.is_block(), "{out:?}");
    if cfg!(debug_assertions) {
        assert!(out.stderr.contains("the hook crashed"), "{out:?}");
    }
}

#[test]
fn a_command_too_deep_to_read_is_blocked() {
    let f = Fixture::new();
    f.approve(&f.repo);
    let deep = "echo ".to_string() + &"$(".repeat(12) + "ls" + &")".repeat(12);
    let out = f.fire(bash(&deep));
    assert!(out.is_block(), "{out:?}");
    assert!(out.stderr.contains("nests too deeply"), "{out:?}");
}

#[test]
fn paths_are_read_against_home_and_the_project() {
    let f = Fixture::new();
    // `~` alone is the home directory, not the store inside it.
    assert_eq!(
        f.fire(tool("Read", json!({ "file_path": "~" }))),
        Outcome::allow()
    );
    // Without a project directory a relative path is taken as it is.
    let env = Env::new([("HOME", f.home.to_str().unwrap())], NOW);
    let relative = tool(
        "Read",
        json!({ "file_path": "./no-such-file-for-tests.md" }),
    );
    assert_eq!(f.fire_with(&env, relative), Outcome::allow());
    let store = approvals::store_dir(&f.home).join("x.json");
    let out = f.fire_with(&env, tool("Edit", json!({ "file_path": store })));
    assert!(out.is_block(), "{out:?}");
    // The record of that decision goes to the no-project log.
    let dir = mezha_hooks::audit::dir(&f.home, None);
    assert!(dir.ends_with("audit/no-project"), "{}", dir.display());
    assert!(dir.is_dir(), "{}", dir.display());
}

#[test]
fn outcomes_that_cannot_be_read_or_written_never_block() {
    let f = Fixture::new();
    let argv: Vec<String> = ["audit-outcome", "--protocol", &PROTOCOL.to_string()]
        .iter()
        .map(|s| s.to_string())
        .collect();
    // The tool has already run: garbage and other events pass unrecorded.
    assert_eq!(run(&argv, b"not json", &f.env()), Outcome::allow());
    let pre = bash("ls");
    assert_eq!(
        run(&argv, pre.to_string().as_bytes(), &f.env()),
        Outcome::allow()
    );
    assert!(!mezha_hooks::audit::dir(&f.home, Some(&f.repo)).exists());
    // A record that can't be written is reported on stderr, not blocked.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let store = approvals::mezha_home(&f.home);
        std::fs::create_dir_all(&store).unwrap();
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o500)).unwrap();
        let mut done = bash("ls");
        done["hook_event_name"] = json!("PostToolUse");
        let out = run(&argv, done.to_string().as_bytes(), &f.env());
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(out.code, 0, "{out:?}");
        assert!(
            out.stderr.contains("couldn't write the audit log"),
            "{out:?}"
        );
    }
}

#[test]
fn admissions_name_the_policy_the_project_was_compiled_with() {
    let f = Fixture::new();
    let state = f.repo.join(".claude/.mezha-state.json");
    std::fs::create_dir_all(state.parent().unwrap()).unwrap();
    let policy = |text: &str| {
        std::fs::write(&state, text).unwrap();
        assert_eq!(f.fire(bash("git status")), Outcome::allow());
        audit(&f).pop().unwrap()["policy"].clone()
    };
    assert_eq!(policy(r#"{"spec":"sha256:abc"}"#), json!("sha256:abc"));
    assert_eq!(policy(r#"{"spec":1}"#), Value::Null, "not a fingerprint");
    assert_eq!(policy("not json"), Value::Null);
    std::fs::remove_file(&state).unwrap();
    assert_eq!(f.fire(bash("git status")), Outcome::allow());
    assert_eq!(
        audit(&f).pop().unwrap()["policy"],
        Value::Null,
        "no state file"
    );
}

/// Every directory on the way to the log can refuse the record, and a
/// blocked call reports both reasons.
#[cfg(unix)]
#[test]
fn an_unwritable_audit_log_is_reported_at_every_level() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    let lock = |p: &Path, mode: u32| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    let dir = mezha_hooks::audit::dir(&f.home, Some(&f.repo));
    let audit_root = dir.parent().unwrap().to_path_buf();
    let fails_in = |locked: &Path| {
        lock(locked, 0o500);
        let out = f.fire(bash("git status"));
        lock(locked, 0o700);
        assert!(out.is_block(), "{}: {out:?}", locked.display());
        assert!(
            out.stderr.contains("couldn't write the audit log in"),
            "{}: {out:?}",
            locked.display()
        );
    };
    // The project's directory can't be created...
    std::fs::create_dir_all(&audit_root).unwrap();
    fails_in(&audit_root);
    // ...or the day's file inside it.
    std::fs::create_dir_all(&dir).unwrap();
    fails_in(&dir);
    lock(&dir, 0o500);
    let out = f.fire(bash("git push"));
    lock(&dir, 0o700);
    assert!(out.stderr.contains("`git push` is gated"), "{out:?}");
    assert!(
        out.stderr.contains("couldn't write the audit log either"),
        "{out:?}"
    );
}
