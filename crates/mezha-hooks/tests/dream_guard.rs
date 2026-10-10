//! The dream guard in-process: what the dreamer may read and write.

use std::path::PathBuf;

use mezha_hooks::{Env, PROTOCOL, dream_guard_command, run};
use serde_json::{Value, json};

struct Fixture {
    _tmp: tempfile::TempDir,
    wt: PathBuf,
    staged: PathBuf,
    outside: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let wt = base.join("wt");
        let staged = base.join("staged/implementer");
        let outside = base.join("outside");
        for dir in [&wt, &staged, &outside] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(staged.join("MEMORY.md"), "# m\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.join("target.md"), staged.join("link.md")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, staged.join("dirlink")).unwrap();
        Fixture {
            _tmp: tmp,
            wt,
            staged,
            outside,
        }
    }

    fn check(&self, tool: &str, input: Value) -> bool {
        let argv: Vec<String> = [
            "dream-guard",
            "--protocol",
            &PROTOCOL.to_string(),
            "--read",
            self.wt.to_str().unwrap(),
            "--write",
            self.staged.to_str().unwrap(),
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let event = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": input,
            "cwd": self.wt,
        });
        let out = run(&argv, event.to_string().as_bytes(), &Env::default());
        assert!(out.code == 0 || out.code == 2, "{out:?}");
        if out.code == 2 {
            assert!(
                out.stderr.contains("advisory") || out.stderr.contains("mezha"),
                "{out:?}"
            );
        }
        out.code == 0
    }
}

#[test]
fn reads() {
    let f = Fixture::new();
    let p = |base: &PathBuf, rel: &str| base.join(rel).to_string_lossy().into_owned();
    assert!(f.check("Read", json!({"file_path": p(&f.wt, "src/lib.rs")})));
    assert!(f.check("Read", json!({"file_path": p(&f.staged, "MEMORY.md")})));
    assert!(f.check("Read", json!({"file_path": "src/lib.rs"})));
    assert!(!f.check("Read", json!({"file_path": p(&f.outside, "secret")})));
    assert!(!f.check("Read", json!({"file_path": "/etc/hosts"})));
    assert!(!f.check(
        "Read",
        json!({"file_path": format!("{}/../outside/x", f.wt.display())})
    ));
    assert!(!f.check(
        "Read",
        json!({"file_path": format!("{}/./src", f.wt.display())})
    ));
    assert!(!f.check("Read", json!({})));
    // Grep and Glob: the path (default cwd) and the pattern.
    assert!(f.check("Grep", json!({"pattern": "fn main"})));
    assert!(f.check(
        "Grep",
        json!({"pattern": "x", "path": p(&f.wt, "src"), "glob": "*.rs"})
    ));
    assert!(!f.check("Grep", json!({"pattern": "x", "path": "/"})));
    assert!(!f.check("Grep", json!({"pattern": "x", "glob": "../outside/*"})));
    assert!(f.check("Glob", json!({"pattern": "**/*.md"})));
    assert!(!f.check("Glob", json!({"pattern": "/etc/*"})));
    assert!(!f.check("Glob", json!({"pattern": "../**"})));
    assert!(!f.check("Glob", json!({"pattern": "~/.ssh/*"})));
}

#[test]
fn writes() {
    let f = Fixture::new();
    let staged = |name: &str| f.staged.join(name).to_string_lossy().into_owned();
    assert!(f.check(
        "Write",
        json!({"file_path": staged("MEMORY.md"), "content": "x"})
    ));
    assert!(f.check("Edit", json!({"file_path": staged("testing.md")})));
    assert!(f.check(
        "MultiEdit",
        json!({"file_path": staged("db-migrations.md")})
    ));
    assert!(!f.check("Write", json!({"file_path": staged("CHANGELOG.md")})));
    assert!(!f.check("Write", json!({"file_path": staged("changelog.md")})));
    assert!(!f.check("Write", json!({"file_path": staged("notes.txt")})));
    assert!(!f.check("Write", json!({"file_path": staged(".hidden.md")})));
    assert!(!f.check("Write", json!({"file_path": staged("sub/x.md")})));
    assert!(!f.check("Write", json!({"file_path": f.wt.join("src/lib.rs")})));
    assert!(!f.check("Edit", json!({"file_path": f.wt.join("MEMORY.md")})));
    assert!(!f.check(
        "Write",
        json!({"file_path": format!("{}/../x.md", f.staged.display())})
    ));
    #[cfg(unix)]
    {
        // A symlink in the staged directory resolves outside it.
        assert!(!f.check("Write", json!({"file_path": staged("link.md")})));
        assert!(!f.check("Write", json!({"file_path": staged("dirlink/x.md")})));
        assert!(!f.check("Read", json!({"file_path": staged("dirlink/x.md")})));
    }
    let _ = &f.outside;
}

#[test]
fn other_tools_and_events_block() {
    let f = Fixture::new();
    for tool in [
        "Bash",
        "NotebookEdit",
        "WebFetch",
        "Agent",
        "mcp__github__push",
        "Monitor",
    ] {
        assert!(
            !f.check(
                tool,
                json!({"command": "ls", "file_path": f.staged.join("x.md")})
            ),
            "{tool}"
        );
    }
    let argv: Vec<String> = [
        "dream-guard",
        "--protocol",
        "1",
        "--write",
        f.staged.to_str().unwrap(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for event in [
        json!({"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_input": {}}),
        json!({"hook_event_name": "PreToolUse"}),
    ] {
        let out = run(&argv, event.to_string().as_bytes(), &Env::default());
        assert_eq!(out.code, 2, "{event}");
    }
    assert_eq!(run(&argv, b"not json", &Env::default()).code, 2);
}

#[test]
fn command_quotes_paths() {
    let cmd = dream_guard_command(
        std::path::Path::new("/opt/me/bin/mezha"),
        &[std::path::Path::new("/home/o'brien/wt")],
        std::path::Path::new("/home/o'brien/.mezha/dreams/k/s/staged/r"),
    )
    .unwrap();
    assert_eq!(
        cmd,
        "'/opt/me/bin/mezha' hook dream-guard --protocol 2 --read '/home/o'\\''brien/wt' --write '/home/o'\\''brien/.mezha/dreams/k/s/staged/r' || exit 2"
    );
    assert!(
        dream_guard_command(
            std::path::Path::new("/bin/mezha"),
            &[],
            std::path::Path::new("/a\nb")
        )
        .is_err()
    );
}
