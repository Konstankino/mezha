//! `mezha dream --schedule <kind>`: prints how to run `mezha dream
//! --scheduled` every night. It installs nothing.

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use mezha_memory::dreamer::is_provider_key;
use mezha_memory::schedule::{self, Kind, When};
use mezha_spec::DreamSchedule;
use mezha_verify::Ctx;
use serde_json::Value;

use crate::files::create_private_dir;

pub fn print(root: &Path, kind: &str) -> Result<ExitCode> {
    let Some(kind) = Kind::parse(kind) else {
        bail!("--schedule takes launchd, systemd or cron, not `{kind}`");
    };
    let Some((spec, _)) = super::load(root)? else {
        return Ok(ExitCode::FAILURE);
    };
    let memory = &spec.memory;
    let when = match memory.dream_schedule {
        DreamSchedule::Manual => bail!(
            "mezha.toml has dream_schedule = \"manual\"; set \"nightly\" (with dream_at) or \"cron\" (with dream_cron) first"
        ),
        DreamSchedule::Nightly => {
            let (hour, minute) = memory.dream_at();
            When::Daily { hour, minute }
        }
        DreamSchedule::Cron => When::Cron(
            memory
                .dream_cron
                .clone()
                .context("dream_schedule = \"cron\" needs dream_cron")?,
        ),
    };
    let mut ctx = Ctx::from_process(root);
    let layers = mezha_verify::layers::Layers::load(&ctx, false);
    ctx.agent_writable = layers.agent_writable(&ctx);
    let home = ctx.home.clone().context("can't find the home directory")?;

    // The schedule runs the mezha on PATH, as found where agents can't
    // have put it: anything else would hand an agent a nightly,
    // unsandboxed run.
    let found = ctx.which_trusted("mezha");
    let Some(exe) = found.path else {
        let mut why = "no mezha on PATH outside directories agents can write".to_string();
        if let Some(note) = found.skipped_note("mezha") {
            why.push_str(&format!(" ({note})"));
        }
        bail!(
            "{why}; install it with `cargo install --locked --force --path crates/mezha-cli`, which puts it in ~/.cargo/bin"
        );
    };
    let running = std::env::current_exe().and_then(std::fs::canonicalize).ok();
    if std::fs::canonicalize(&exe).ok() != running {
        eprintln!(
            "note: the schedule runs {}, not the mezha you ran now; check its version with `{} --version`",
            exe.display(),
            exe.display()
        );
    }

    let mut env = vec![("PATH".to_string(), ctx.trusted_path())];
    if let Some(dir) = ctx.var("CLAUDE_CONFIG_DIR") {
        env.push(("CLAUDE_CONFIG_DIR".into(), dir.to_string()));
    }
    let from_settings: Vec<String> = layers
        .layers
        .iter()
        .filter(|l| l.scope == mezha_verify::layers::Scope::User)
        .filter_map(|l| l.value.get("env").and_then(Value::as_object))
        .flat_map(|e| e.keys().cloned())
        .collect();
    let shell_only: Vec<&str> = ctx
        .vars
        .keys()
        .map(String::as_str)
        .filter(|k| is_provider_key(k) && !from_settings.iter().any(|s| s == k))
        .collect();
    if !shell_only.is_empty() {
        eprintln!(
            "warning: set only in your shell, not in ~/.claude/settings.json: {}. A scheduled dream won't have them and may use another provider; move them into the `env` of your user settings.",
            shell_only.join(", ")
        );
    }

    let dreams = mezha_memory::dreams_dir(&home, root);
    create_private_dir(&dreams)?;
    let key = mezha_broker::approvals::root_hash(&mezha_memory::project_key_root(root));
    let log = dreams.join("schedule.log");
    let snippet = schedule::snippet(
        kind,
        &schedule::Job {
            id: &key[..12],
            exe: &exe,
            root,
            env: &env,
            log: &log,
            when,
        },
    )
    .map_err(anyhow::Error::msg)?;

    for file in &snippet.files {
        println!("Save as ~/{}:\n\n{}", file.path, file.contents);
    }
    if let Some(line) = &snippet.line {
        println!("Add to your crontab:\n\n{line}\n");
    }
    println!("Install:");
    for cmd in &snippet.install {
        println!("  {cmd}");
    }
    println!("Remove:");
    for cmd in &snippet.remove {
        println!("  {cmd}");
    }
    println!(
        "\nIt runs `mezha dream --scheduled`: project memory only (local and user memory need you at a terminal), \
         one branch per night, nothing pushed. Output goes to {}; `mezha metrics` shows how the last run went.",
        log.display()
    );
    match kind {
        Kind::Launchd => println!(
            "launchd runs a missed dream once when the Mac wakes, and skips nights it was off. It runs in your login session, so it uses your keychain login."
        ),
        Kind::Systemd => println!(
            "Persistent=true catches up after a boot. To run while you're logged out: `loginctl enable-linger`. Claude Code reads its login from ~/.claude/.credentials.json."
        ),
        Kind::Cron => {
            if cfg!(target_os = "macos") {
                eprintln!(
                    "warning: on macOS cron may not reach your keychain login; prefer `--schedule launchd`."
                );
            }
            println!("cron doesn't run missed jobs.");
        }
    }
    println!(
        "On a machine nobody logs in to, `claude setup-token` makes a long-lived token; keep CLAUDE_CODE_OAUTH_TOKEN in your own secret store, never in a snippet or under ~/.mezha, which sessions can read."
    );
    Ok(ExitCode::SUCCESS)
}
