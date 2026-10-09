//! `mezha dream`: recent agent runs become reviewed memory (ADR-0004).
//!
//! It runs in your terminal. For each role with memory it collects digests
//! of the role's runs from Claude Code's transcripts, runs one locked-down
//! headless dreamer on them in a worktree of the project, and reviews what
//! the dreamer wrote to a staged copy of the role's memory. Project memory
//! becomes a commit on a new branch for you to push; local and user memory
//! is applied after you confirm the diff. Everything lives under
//! `~/.mezha/dreams/<repo>/<stamp>/`, where sandboxed commands can't write
//! and sessions may not read. Every git call runs with hooks off.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use mezha_memory::claude::{self, Outcome};
use mezha_memory::dreamer::{self, Forwarded, Init};
use mezha_memory::inbox::{self, RoleInbox};
use mezha_memory::review::{self, Change, Review, Snapshot};
use mezha_memory::scan::escape;
use mezha_memory::time::{format_iso, parse_since};
use mezha_memory::{changelog, cursor, transcripts};
use mezha_spec::{Scope, Spec};
use mezha_verify::Ctx;
use mezha_verify::runner::{self, Next, Run};
use serde_json::Value;

use crate::files::{create_private_dir, fresh_dir, replace_file, shell_word};
use crate::git::{Git, resolve_base};

/// How long one role's dreamer may run.
const DREAM_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Default `--since` without a cursor.
const DEFAULT_SINCE: &str = "7d";
/// Finished dreams kept under `~/.mezha/dreams/<repo>/`.
const KEEP_DREAMS: usize = 5;

/// `~/.mezha/dreams/<repo>/last-run.json`: how the last dream ended.
pub const LAST_RUN: &str = "last-run.json";
const LOCK: &str = "dream.lock";

pub struct Options {
    pub roles: Vec<String>,
    pub since: Option<String>,
    pub base: Option<String>,
    pub dry_run: bool,
    /// The mode a schedule runs: project roles only, nothing pending.
    pub scheduled: bool,
    /// Print a schedule snippet instead of dreaming.
    pub schedule: Option<String>,
}

/// What `last-run.json` records.
#[derive(Default)]
struct LastRun {
    dir: Option<PathBuf>,
    ok: bool,
    roles: Vec<String>,
    cost_usd: f64,
    error: Option<String>,
}

/// Why `dream` won't run here, if it won't.
pub fn refusal(var: impl Fn(&str) -> Option<String>) -> Option<&'static str> {
    if super::approve::inside_claude_code(&var) {
        return Some(
            "mezha dream refuses to run inside Claude Code: a dream reads transcripts and \
             writes memory, so a human starts it from their own terminal",
        );
    }
    if cfg!(windows) {
        return Some("mezha dream runs on macOS, Linux and WSL2 (native Windows comes in phase 4)");
    }
    None
}

/// One role to dream.
struct Role<'a> {
    name: &'a str,
    agent: &'a mezha_spec::Agent,
    scope: Scope,
    since: i64,
    inbox: RoleInbox,
}

pub fn run(root: &Path, opts: &Options) -> Result<ExitCode> {
    if let Some(why) = refusal(|k| std::env::var(k).ok()) {
        bail!("{why}");
    }
    let root = std::fs::canonicalize(root).with_context(|| root.display().to_string())?;
    if let Some(kind) = &opts.schedule {
        return crate::schedule::print(&root, kind);
    }
    let mut last = LastRun::default();
    let result = dream(&root, opts, &mut last);
    if let Some(dir) = &last.dir {
        let error = match &result {
            Err(e) => Some(format!("{e:#}")),
            Ok(_) if !last.ok => last.error.clone().or(Some("refused".into())),
            Ok(_) => None,
        };
        let record = serde_json::json!({
            "v": 1,
            "at": super::now(),
            "scheduled": opts.scheduled,
            "ok": error.is_none(),
            "roles": last.roles,
            "cost_usd": last.cost_usd,
            "error": error,
        });
        let _ =
            mezha_memory::write_private(&dir.join(LAST_RUN), format!("{record:#}\n").as_bytes());
    }
    result
}

fn dream(root: &Path, opts: &Options, last: &mut LastRun) -> Result<ExitCode> {
    let root = root.to_path_buf();
    let Some((spec, _)) = super::load(&root)? else {
        return Ok(ExitCode::FAILURE);
    };
    let mut ctx = Ctx::from_process(&root);
    let layers = mezha_verify::layers::Layers::load(&ctx, false);
    ctx.agent_writable = layers.agent_writable(&ctx);
    let home = ctx.home.clone().context("can't find the home directory")?;
    let now = super::now() as i64;

    let mut chosen = choose_roles(&spec, &opts.roles)?;
    let dreams = mezha_memory::dreams_dir(&home, &root);
    create_private_dir(&dreams)?;
    last.dir = Some(dreams.clone());
    let note = format!("pid {} since {}", std::process::id(), format_iso(now));
    let _lock = match mezha_memory::lock::try_lock(&dreams.join(LOCK), &note) {
        Ok(lock) => lock,
        Err(mezha_memory::lock::LockError::Busy(holder)) => {
            last.dir = None;
            bail!("another dream of this project is running ({holder}); try again when it ends");
        }
        Err(e) => bail!("can't lock {}: {e}", dreams.join(LOCK).display()),
    };
    let git = Git::new(&ctx)?;
    let kept = refused_dreams(&dreams);
    if opts.scheduled {
        // Nobody is at a terminal to confirm local or user memory, and a
        // refused dream waits for you before the next one.
        chosen.retain(|(name, scope)| {
            let keep = *scope == Scope::Project;
            if !keep {
                println!(
                    "Skipping {name}: its {} memory needs you at a terminal.",
                    scope.as_str()
                );
            }
            keep
        });
        if !kept.is_empty() {
            bail!(
                "a refused dream is waiting for you; read it, then remove its worktree with `git worktree remove --force <path>`: {}",
                kept.iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let project = crate::metrics::Project::open(&ctx, &root)?;
        let pending = pending_roles(&project.dreams(true)?);
        chosen.retain(|(name, _)| match pending.get(*name) {
            Some(branch) => {
                println!(
                    "Skipping {name}: its last dream on {branch} hasn't been merged or dropped yet."
                );
                false
            }
            None => true,
        });
        if chosen.is_empty() {
            last.ok = true;
            println!("Nothing to dream about tonight.");
            return Ok(ExitCode::SUCCESS);
        }
    } else if !kept.is_empty() {
        eprintln!(
            "note: refused dreams still have worktrees: {}",
            kept.iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let prefix = git
        .out(&root, &["rev-parse", "--show-prefix"])?
        .trim()
        .to_string();
    let (base, base_name) = resolve_base(&git, &root, opts.base.as_deref())?;
    let config = transcripts::config_dir(|k| ctx.var(k).map(str::to_string), &home);
    for (name, scope) in &chosen {
        refuse_symlinks(&git, &root, &base, &prefix, name, *scope, &config)?;
    }
    if !git
        .out(
            &root,
            &[
                "ls-tree",
                "-r",
                "-z",
                "--name-only",
                &base,
                "--",
                &format!("{prefix}.claude/agent-memory-local"),
            ],
        )?
        .is_empty()
    {
        bail!(
            "{base_name} tracks .claude/agent-memory-local/, which is local memory and may hold \
             PHI; remove it from git (`git rm -r --cached .claude/agent-memory-local`) and ignore it"
        );
    }

    // Collect.
    let cursor_file = dreams.join(cursor::FILE);
    let mut cursors = cursor::load(&cursor_file);
    let explicit = opts
        .since
        .as_deref()
        .map(|s| parse_since(s, now))
        .transpose()
        .map_err(anyhow::Error::msg)?;
    let fallback = parse_since(DEFAULT_SINCE, now).map_err(anyhow::Error::msg)?;
    let since_of = |role: &str| {
        explicit
            .or_else(|| cursors.get(role).copied())
            .unwrap_or(fallback)
    };
    let mut roots = vec![root.clone()];
    for worktree in git.worktrees(&root)? {
        if !worktree.starts_with(&dreams) {
            roots.push(worktree.join(&prefix));
        }
    }
    let dir_override = ctx
        .var("CLAUDE_CONFIG_DIR")
        .and(ctx.var("CLAUDE_CODE_PROJECT_DIR_NAME"))
        .filter(|n| {
            n.len() <= 64
                && n.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        });
    let earliest = chosen
        .iter()
        .map(|(n, _)| since_of(n))
        .min()
        .unwrap_or(fallback);
    let role_names = chosen.iter().map(|(n, _)| n.to_string()).collect();
    let collected = transcripts::collect(
        &config.join("projects"),
        &roots,
        &role_names,
        earliest,
        dir_override,
    );
    let phi = spec.has_phi();
    let mut roles: Vec<Role> = chosen
        .iter()
        .map(|(name, scope)| {
            let since = since_of(name);
            let runs: Vec<_> = collected
                .runs
                .iter()
                .filter(|r| r.role == *name && r.end > since)
                .collect();
            Role {
                name,
                agent: &spec.agent[*name],
                scope: *scope,
                since,
                inbox: inbox::role_inbox(&runs, phi),
            }
        })
        .collect();
    // Project memory first; the local and user confirmations come at the end.
    roles.sort_by_key(|r| (r.scope != Scope::Project, r.name));

    println!(
        "Read {} session(s) of this project from {}.",
        collected.sessions,
        config.join("projects").display()
    );
    if collected.skipped_files > 0 {
        eprintln!(
            "note: {} transcript(s) were too large to read",
            collected.skipped_files
        );
    }
    for role in &roles {
        let inbox = &role.inbox;
        if inbox.digests.is_empty() {
            println!(
                "  {:<14} {:<8} no runs since {}",
                role.name,
                role.scope.as_str(),
                format_iso(role.since)
            );
            continue;
        }
        let mut line = format!(
            "  {:<14} {:<8} {} run(s)",
            role.name,
            role.scope.as_str(),
            inbox.digests.len()
        );
        if inbox.redactions > 0 {
            line.push_str(&format!(", {} span(s) redacted", inbox.redactions));
        }
        if inbox.left > 0 {
            line.push_str(&format!(", {} left for the next dream", inbox.left));
        }
        println!("{line}");
    }
    for branch in git.unmerged_dreams(&root, &base)? {
        eprintln!("note: {branch} isn't merged into {base_name} yet; this dream doesn't see it");
    }
    if !git
        .out(
            &root,
            &[
                "status",
                "--porcelain",
                "-z",
                "--",
                &format!("{prefix}.claude/agent-memory"),
            ],
        )?
        .is_empty()
    {
        eprintln!(
            "note: .claude/agent-memory has uncommitted changes here; the dream starts from {base_name} without them"
        );
    }
    if !opts.dry_run
        && let Err(e) = crate::metrics::record_sessions(&ctx, &spec, &root)
    {
        eprintln!("note: couldn't record metrics: {e:#}");
    }
    roles.retain(|r| !r.inbox.digests.is_empty());
    if roles.is_empty() {
        last.ok = true;
        println!("Nothing new to dream about.");
        return Ok(ExitCode::SUCCESS);
    }

    // The workspace: inbox now, worktree and staging if this isn't a dry run.
    prune(&dreams);
    let stamp = mezha_render::utc_stamp(now as u64);
    let ws = fresh_dir(&dreams, &stamp)?;
    for role in &roles {
        let dir = ws.join("inbox").join(role.name);
        create_private_dir(&dir)?;
        for d in &role.inbox.digests {
            mezha_memory::write_private(&dir.join(&d.file), d.text.as_bytes())?;
        }
    }
    println!("Digests: {}", ws.join("inbox").display());

    let user_settings = layers
        .layers
        .iter()
        .find(|l| l.scope == mezha_verify::layers::Scope::User)
        .map(|l| l.value.clone())
        .unwrap_or(Value::Null);
    let mut forwarded = dreamer::forward(&user_settings);
    if opts.scheduled {
        // These may open a browser and wait for you.
        for key in ["awsAuthRefresh", "gcpAuthRefresh"] {
            if forwarded.settings.remove(key).is_some() {
                println!("Not using {key} unattended; the run relies on cached credentials.");
            }
        }
    }
    if !forwarded.env.is_empty() || !forwarded.settings.is_empty() {
        let mut names: Vec<&str> = forwarded.env.iter().map(|(k, _)| k.as_str()).collect();
        names.extend(forwarded.settings.keys().map(String::as_str));
        println!("From your user settings: {}", names.join(", "));
    }

    if opts.dry_run {
        let staged = ws.join("staged").join(roles[0].name);
        let settings = ws.join(format!("settings-{}.json", roles[0].name));
        let args = dreamer::argv(&dreamer::Invocation {
            system_prompt: "<dreamer prompt>",
            model: spec.memory.dream_model(),
            memory_dir: &staged,
            settings_file: &settings,
            max_turns: spec.memory.dream_max_turns(),
            budget_usd: spec.memory.dream_budget_usd(),
        });
        last.ok = true;
        println!(
            "Dry run: no dreamer ran. Each role would run, in a worktree of {base_name}:\n  claude {}",
            args.iter()
                .map(|a| shell_word(a))
                .collect::<Vec<_>>()
                .join(" ")
        );
        return Ok(ExitCode::SUCCESS);
    }

    let claude = ctx
        .which_trusted("claude")
        .path
        .context("claude is not on PATH (or only in a directory an agent could write)")?;
    let version = claude_version(&ctx, &claude)?;

    // The worktree.
    let branch = git.fresh_branch(&root, &format!("mezha/dream-{stamp}"))?;
    let wt = ws.join("wt");
    git.out(
        &root,
        &[
            "worktree",
            "add",
            "--quiet",
            "-b",
            &branch,
            &wt.to_string_lossy(),
            &base,
        ],
    )?;
    let wt = std::fs::canonicalize(&wt)?;
    let wt_project = wt.join(&prefix);
    println!("Worktree: {} on {branch} (from {base_name})", wt.display());

    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .context("can't find the mezha binary")?;
    let mut dream = Dream {
        ctx: &ctx,
        git: &git,
        spec: &spec,
        claude: &claude,
        version: &version,
        exe: &exe,
        ws: &ws,
        wt: &wt,
        wt_project: &wt_project,
        prefix: &prefix,
        forwarded: &forwarded,
        phi,
        now,
        stamp: stamp.clone(),
        branch: branch.clone(),
        store: mezha_metrics::store::Store::new(&mezha_memory::metrics_dir(&home, &root)),
        commits: Vec::new(),
        pending: Vec::new(),
        cost: 0.0,
    };
    let mut done = Vec::new();
    for role in &roles {
        match dream.role(role, &config, &root) {
            Ok(result) => {
                if let Some(through) = result.advance {
                    cursors.insert(role.name.to_string(), through);
                    cursor::store(&cursor_file, &cursors)?;
                }
                done.push(result);
            }
            Err(refused) => {
                last.cost_usd = dream.cost;
                last.roles = dream.commits.iter().map(|c| c.role.clone()).collect();
                last.error = Some(format!("{}: {}", role.name, refused.trim()));
                eprintln!("\nThe dream of {} was refused:\n{refused}", role.name);
                eprintln!(
                    "Nothing more was committed or applied. The workspace stays for you to read: {}",
                    ws.display()
                );
                if !dream.commits.is_empty() {
                    eprintln!(
                        "Roles committed before it are on {branch}: {}",
                        dream
                            .commits
                            .iter()
                            .map(|c| c.role.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
                return Ok(ExitCode::FAILURE);
            }
        }
    }

    // Local and user memory: your confirmation, one role at a time.
    let pending = std::mem::take(&mut dream.pending);
    for p in pending {
        match apply_local(&p, &ws) {
            Ok(true) => {
                cursors.insert(p.role.clone(), p.through);
                cursor::store(&cursor_file, &cursors)?;
                dream.record(&p.role, p.scope, None, p.runs, p.turns, p.cost_usd, true);
            }
            Ok(false) => {}
            Err(refused) => {
                last.error = Some(format!("{}: {}", p.role, refused.trim()));
                eprintln!("\n{}: {refused}", p.role);
                return Ok(ExitCode::FAILURE);
            }
        }
    }

    git.out(
        &root,
        &["worktree", "remove", "--force", &wt.to_string_lossy()],
    )?;
    println!("\nThe dream cost ${:.2}.", dream.cost);
    last.ok = true;
    last.cost_usd = dream.cost;
    last.roles = done.iter().map(|r| r.role.clone()).collect();
    if dream.commits.is_empty() {
        git.out(&root, &["branch", "-D", "--quiet", &branch])?;
        println!("No project memory changed, so there is nothing to push.");
        return Ok(ExitCode::SUCCESS);
    }
    let pr = ws.join("pr.md");
    mezha_memory::write_private(&pr, pr_body(&stamp, &dream.commits).as_bytes())?;
    let gh_base = match base_name.strip_prefix("origin/").unwrap_or(&base_name) {
        "HEAD" => String::new(),
        name => format!("--base {} ", shell_word(name)),
    };
    println!(
        "Project memory is on {branch} ({} commit(s)). Read it, then push it for review:\n  git log -p {}..{branch}\n  git push -u origin {branch}\n  gh pr create {gh_base}--head {branch} --title {} --body-file {}",
        dream.commits.len(),
        &base[..base.len().min(12)],
        shell_word(&format!("mezha dream {stamp}")),
        shell_word(&pr.to_string_lossy()),
    );
    Ok(ExitCode::SUCCESS)
}

/// The roles to dream: agents with memory, or the ones named.
fn choose_roles<'a>(spec: &'a Spec, wanted: &[String]) -> Result<Vec<(&'a str, Scope)>> {
    let with_memory: Vec<(&str, Scope)> = spec
        .agent
        .iter()
        .filter_map(|(n, a)| Some((n.as_str(), spec.memory_scope(a)?)))
        .collect();
    if with_memory.is_empty() {
        bail!("no agent in mezha.toml has memory; give one `memory = {{}}` first");
    }
    if wanted.is_empty() {
        return Ok(with_memory);
    }
    wanted
        .iter()
        .map(|w| {
            with_memory
                .iter()
                .find(|(n, _)| n == w)
                .copied()
                .with_context(|| match spec.agent.contains_key(w) {
                    true => format!("agent.{w} has no memory"),
                    false => format!("there is no agent.{w} in mezha.toml"),
                })
        })
        .collect()
}

/// Refuses memory reached through a symlink: at the base commit for project
/// memory (git records the link), on disk for local and user memory.
fn refuse_symlinks(
    git: &Git,
    root: &Path,
    base: &str,
    prefix: &str,
    role: &str,
    scope: Scope,
    config: &Path,
) -> Result<()> {
    match scope {
        Scope::Project => {
            let dir = format!("{prefix}.claude/agent-memory/{role}");
            for path in [
                format!("{prefix}.claude"),
                format!("{prefix}.claude/agent-memory"),
                dir.clone(),
            ] {
                let listed = git.out(root, &["ls-tree", "-z", base, "--", &path])?;
                if listed
                    .split('\0')
                    .any(|e| e.starts_with("120000 ") || e.starts_with("160000 "))
                {
                    bail!(
                        "{path} is a symlink or a submodule at {base}, so its memory can't be dreamed safely"
                    );
                }
            }
            let listed = git.out(
                root,
                &["ls-tree", "-r", "-z", base, "--", &format!("{dir}/")],
            )?;
            for entry in listed.split('\0').filter(|e| !e.is_empty()) {
                let (mode, path) = entry.split_once('\t').unwrap_or((entry, ""));
                let name = path.strip_prefix(&format!("{dir}/")).unwrap_or(path);
                if !mode.starts_with("100") || name.contains('/') {
                    bail!(
                        "{} at {base} isn't a plain file directly in the memory directory",
                        escape(path)
                    );
                }
            }
        }
        Scope::Local => {
            let mut path = root.to_path_buf();
            for part in [".claude", "agent-memory-local", role] {
                path.push(part);
                if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
                    bail!(
                        "{} is a symlink, so local memory can't be dreamed safely",
                        path.display()
                    );
                }
            }
        }
        Scope::User => {
            let path = config.join("agent-memory").join(role);
            if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
                bail!(
                    "{} is a symlink, so user memory can't be dreamed safely",
                    path.display()
                );
            }
        }
    }
    Ok(())
}

fn claude_version(ctx: &Ctx, claude: &Path) -> Result<String> {
    let out = runner::run(
        ctx,
        &Run {
            program: claude,
            args: &["--version"],
            cwd: &ctx.root,
            env: &[("DISABLE_AUTOUPDATER", "1")],
            remove: &["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"],
            stdin: b"",
            timeout: Duration::from_secs(30),
        },
    )?;
    let text = out.stdout.trim().to_string();
    let Some(version) = claude::parse_version(&text) else {
        bail!("`claude --version` said {:?}, not a version", escape(&text));
    };
    if version < claude::MIN_CLAUDE_CODE {
        let (a, b, c) = claude::MIN_CLAUDE_CODE;
        bail!("Claude Code {text} is older than {a}.{b}.{c}, which mezha dream needs; update it");
    }
    Ok(text.split_whitespace().next().unwrap_or("").to_string())
}

/// A finished role.
struct RoleResult {
    role: String,
    /// Where the cursor moves: after a commit or "no changes", not before a
    /// confirmation.
    advance: Option<i64>,
}

/// A committed role, for the PR body.
struct Commit {
    role: String,
    runs: usize,
    first: i64,
    last: i64,
    outcome: Outcome,
    phrases: Vec<String>,
}

/// A local or user role waiting for your confirmation.
struct Pending {
    role: String,
    scope: Scope,
    runs: usize,
    turns: u64,
    cost_usd: f64,
    dir: PathBuf,
    /// The real directory when it was staged.
    original: Snapshot,
    changes: Vec<Change>,
    changelog: String,
    through: i64,
}

struct Dream<'a> {
    ctx: &'a Ctx,
    git: &'a Git<'a>,
    spec: &'a Spec,
    claude: &'a Path,
    version: &'a str,
    exe: &'a Path,
    ws: &'a Path,
    wt: &'a Path,
    wt_project: &'a Path,
    prefix: &'a str,
    forwarded: &'a Forwarded,
    phi: bool,
    now: i64,
    stamp: String,
    branch: String,
    /// The metrics store, where each commit and apply is recorded.
    store: mezha_metrics::store::Store,
    commits: Vec<Commit>,
    pending: Vec<Pending>,
    cost: f64,
}

impl Dream<'_> {
    /// Records a commit (with the patch-id of its memory change) or an
    /// applied local role in the metrics store. Metrics are a side matter:
    /// a failure here is a note, not a refusal.
    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        role: &str,
        scope: Scope,
        commit: Option<(String, String, Option<String>)>,
        runs: usize,
        turns: u64,
        cost_usd: f64,
        applied: bool,
    ) {
        let (commit, dir, patch_id) = match commit {
            Some((c, d, p)) => (Some(c), Some(d), p),
            None => (None, None, None),
        };
        let row = mezha_metrics::dreams::DreamRow {
            v: mezha_metrics::store::VERSION,
            key: format!("{}/{role}", self.stamp),
            stamp: self.stamp.clone(),
            role: role.to_string(),
            scope: scope.as_str().to_string(),
            at: self.now,
            runs,
            turns,
            cost_usd,
            branch: (scope == Scope::Project).then(|| self.branch.clone()),
            commit,
            dir,
            patch_id,
            applied,
            outcome: None,
        };
        let stored = serde_json::to_value(&row)
            .map_err(std::io::Error::other)
            .and_then(|v| self.store.upsert(mezha_metrics::store::DREAMS, "key", &[v]));
        if let Err(e) = stored {
            eprintln!("note: couldn't record the dream in the metrics store: {e}");
        }
    }

    /// Runs one role's dreamer and reviews the result. `Err` is a refusal.
    fn role(&mut self, role: &Role, config: &Path, root: &Path) -> Result<RoleResult, String> {
        let source = match role.scope {
            Scope::Project => self.wt_project.join(".claude/agent-memory").join(role.name),
            Scope::Local => root.join(".claude/agent-memory-local").join(role.name),
            Scope::User => config.join("agent-memory").join(role.name),
        };
        let original = review::snapshot(&source)?;
        let staged = self.ws.join("staged").join(role.name);
        create_private_dir(&staged).map_err(|e| e.to_string())?;
        for (name, bytes) in &original {
            std::fs::write(staged.join(name), bytes).map_err(|e| format!("{name}: {e}"))?;
        }
        let staged = std::fs::canonicalize(&staged).map_err(|e| e.to_string())?;
        let before = review::snapshot(&staged)?;

        let guard = mezha_hooks::dream_guard_command(self.exe, &[self.wt], &staged)?;
        let settings_file = self.ws.join(format!("settings-{}.json", role.name));
        let settings = dreamer::settings_json(&guard, self.forwarded);
        mezha_memory::write_private(&settings_file, format!("{settings:#}\n").as_bytes())
            .map_err(|e| e.to_string())?;
        let policy = role
            .agent
            .memory
            .as_ref()
            .and_then(|m| m.dream_policy)
            .unwrap_or_default();
        let prompt_file = self.wt_project.join(role.agent.prompt_path(role.name));
        let task = dreamer::task_prompt(&dreamer::Task {
            role: role.name,
            policy,
            scope: role.scope,
            description: role.agent.description.as_deref().unwrap_or(""),
            prompt_file: prompt_file.is_file().then_some(prompt_file.as_path()),
            memory_dir: &staged,
            inbox: &role.inbox,
        });
        let system = dreamer::system_prompt(policy);
        let memory = &self.spec.memory;
        let args = dreamer::argv(&dreamer::Invocation {
            system_prompt: &system,
            model: memory.dream_model(),
            memory_dir: &staged,
            settings_file: &settings_file,
            max_turns: memory.dream_max_turns(),
            budget_usd: memory.dream_budget_usd(),
        });

        println!(
            "\nDreaming {} ({} run(s); {}, up to {} turns and ${:.2})",
            role.name,
            role.inbox.digests.len(),
            memory.dream_model(),
            memory.dream_max_turns(),
            memory.dream_budget_usd()
        );
        let (init, outcome) = self.run_claude(&args, &task)?;
        self.cost += outcome.cost_usd;
        println!(
            "  done: {} turns, ${:.2}{}",
            outcome.turns,
            outcome.cost_usd,
            if init.plugins.is_empty() {
                String::new()
            } else {
                format!("; plugins loaded: {}", init.plugins.join(", "))
            }
        );
        for denial in &outcome.denials {
            println!("  refused by Claude Code: {}", escape(denial));
        }

        let dirty = self
            .git
            .out(
                self.wt,
                &[
                    "status",
                    "--porcelain=v1",
                    "-z",
                    "--untracked-files=all",
                    "--ignored",
                ],
            )
            .map_err(|e| e.to_string())?;
        if !dirty.is_empty() {
            let paths: Vec<String> = dirty
                .split('\0')
                .filter(|p| !p.is_empty())
                .map(escape)
                .collect();
            return Err(format!(
                "the worktree changed during the dream, and only the staged memory may: {}",
                paths.join(", ")
            ));
        }
        let after = review::snapshot(&staged)?;
        let mut r = review::review(&before, &after, self.phi);
        review::review_text(&mut r, "the dreamer's summary", &outcome.summary, self.phi);
        print_review(&r);
        if !r.is_clean() {
            return Err(r
                .refusals
                .iter()
                .map(|x| format!("  {x}"))
                .collect::<Vec<_>>()
                .join("\n"));
        }
        let through = role.inbox.through().unwrap_or(self.now);
        if r.changes.is_empty() {
            println!("  no changes");
            return Ok(RoleResult {
                role: role.name.to_string(),
                advance: Some(through),
            });
        }
        let entry = changelog::Entry {
            when: self.now,
            runs: role.inbox.digests.len(),
            first: role.inbox.first().unwrap_or(through),
            last: through,
            model: init.model.clone(),
            turns: outcome.turns,
            cost_usd: outcome.cost_usd,
            claude_code: self.version.to_string(),
            summary: outcome.summary.clone(),
        };
        let old_log = before
            .get(review::CHANGELOG)
            .map(|b| String::from_utf8_lossy(b).into_owned());
        let log = changelog::append(old_log.as_deref(), role.name, &entry);
        if role.scope != Scope::Project {
            self.pending.push(Pending {
                role: role.name.to_string(),
                scope: role.scope,
                runs: entry.runs,
                turns: outcome.turns,
                cost_usd: outcome.cost_usd,
                dir: source,
                original,
                changes: r.changes,
                changelog: log,
                through,
            });
            return Ok(RoleResult {
                role: role.name.to_string(),
                advance: None,
            });
        }
        let dir = self.commit(role, &r.changes, &log, &entry)?;
        let patch_id = crate::metrics::memory_patch_id(self.git, self.wt, "HEAD^1", "HEAD", &dir)
            .unwrap_or_else(|e| {
                eprintln!("note: couldn't compute the patch-id for metrics: {e:#}");
                None
            });
        let head = self
            .git
            .run_ok(self.wt, &["rev-parse", "HEAD"], b"")
            .unwrap_or_default();
        self.record(
            role.name,
            role.scope,
            Some((head.trim().to_string(), dir, patch_id)),
            entry.runs,
            outcome.turns,
            outcome.cost_usd,
            false,
        );
        self.commits.push(Commit {
            role: role.name.to_string(),
            runs: entry.runs,
            first: entry.first,
            last: entry.last,
            outcome,
            phrases: r.phrases,
        });
        Ok(RoleResult {
            role: role.name.to_string(),
            advance: Some(through),
        })
    }

    /// Runs the dreamer, checking its `system/init` before it gets far.
    fn run_claude(&self, args: &[String], task: &str) -> Result<(Init, Outcome), String> {
        let path = self.ctx.trusted_path();
        let mut env: Vec<(&str, &str)> = vec![
            ("PATH", path.as_str()),
            ("CLAUDE_CODE_DISABLE_CLAUDE_MDS", "1"),
            ("CLAUDE_CODE_DISABLE_AUTO_MEMORY", "1"),
            ("CLAUDE_CODE_DISABLE_FILE_CHECKPOINTING", "1"),
            ("DISABLE_AUTOUPDATER", "1"),
        ];
        for (k, v) in &self.forwarded.env {
            if self.ctx.var(k).is_none() {
                env.push((k, v));
            }
        }
        let mut remove = vec!["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"];
        remove.extend(
            mezha_render::settings::CREDENTIAL_ENV
                .iter()
                .filter(|k| !dreamer::is_provider_key(k)),
        );
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let mut init: Option<Result<Init, String>> = None;
        let mut result: Option<Value> = None;
        let mut turns = 0usize;
        let out = runner::run_lines(
            self.ctx,
            &Run {
                program: self.claude,
                args: &argv,
                cwd: self.wt,
                env: &env,
                remove: &remove,
                stdin: task.as_bytes(),
                timeout: DREAM_TIMEOUT,
            },
            |line| {
                let Ok(event) = serde_json::from_str::<Value>(line) else {
                    return Next::Continue;
                };
                match (
                    event.get("type").and_then(Value::as_str),
                    event.get("subtype").and_then(Value::as_str),
                ) {
                    (Some("system"), Some("init")) => {
                        let checked = dreamer::check_init(&event);
                        let stop = checked.is_err();
                        init = Some(checked);
                        if stop {
                            return Next::Stop;
                        }
                    }
                    (Some("assistant"), _) => {
                        turns += 1;
                        if turns.is_multiple_of(10) {
                            println!("  … {turns} messages");
                        }
                    }
                    (Some("result"), _) => result = Some(event),
                    _ => {}
                }
                Next::Continue
            },
        )
        .map_err(|e| format!("couldn't run claude: {e}"))?;
        let init = match init {
            Some(Ok(init)) => init,
            Some(Err(why)) => return Err(format!("  {why}; the dreamer was stopped")),
            None => {
                return Err(format!(
                    "  claude didn't report how it started (exit {:?}): {}",
                    out.code,
                    escape(&inbox::cut(out.stderr.trim(), 600))
                ));
            }
        };
        if out.timed_out {
            return Err(format!(
                "  the dreamer ran longer than {} minutes",
                DREAM_TIMEOUT.as_secs() / 60
            ));
        }
        let Some(result) = result else {
            return Err(format!(
                "  claude ended without a result (exit {:?}): {}",
                out.code,
                escape(&inbox::cut(out.stderr.trim(), 600))
            ));
        };
        let outcome =
            claude::read_result(&result).map_err(|why| format!("  the dreamer failed: {why}"))?;
        Ok((init, outcome))
    }

    /// Commits exactly the reviewed bytes: blobs from mezha's memory, not
    /// the disk, and a check that the commit holds the tree mezha wrote.
    fn commit(
        &self,
        role: &Role,
        changes: &[Change],
        log: &str,
        entry: &changelog::Entry,
    ) -> Result<String, String> {
        let git = self.git;
        let dir = format!("{}.claude/agent-memory/{}", self.prefix, role.name);
        let put = |name: &str, content: Option<&str>| -> Result<(), String> {
            let path = format!("{dir}/{name}");
            match content {
                Some(text) => {
                    let oid = git
                        .run_ok(
                            self.wt,
                            &["hash-object", "-w", "--stdin", "--no-filters"],
                            text.as_bytes(),
                        )?
                        .trim()
                        .to_string();
                    git.run_ok(
                        self.wt,
                        &[
                            "update-index",
                            "--add",
                            "--cacheinfo",
                            &format!("100644,{oid},{path}"),
                        ],
                        b"",
                    )?;
                }
                None => {
                    git.run_ok(
                        self.wt,
                        &["update-index", "--force-remove", "--", &path],
                        b"",
                    )?;
                }
            }
            Ok(())
        };
        for change in changes {
            put(&change.name, change.new.as_deref())?;
        }
        put(review::CHANGELOG, Some(log))?;
        let tree = git
            .run_ok(self.wt, &["write-tree"], b"")?
            .trim()
            .to_string();
        let subject = format!("mezha dream: {} ({} runs)", role.name, entry.runs);
        let body = format!(
            "Runs ended from {} to {}.\nDreamer: {}, {} turns, ${:.2}, Claude Code {}.\n\nMezha-Dream: {}",
            format_iso(entry.first),
            format_iso(entry.last),
            entry.model,
            entry.turns,
            entry.cost_usd,
            entry.claude_code,
            mezha_render::utc_stamp(self.now as u64),
        );
        git.run_ok(
            self.wt,
            &[
                "commit",
                "--quiet",
                "--no-verify",
                "-m",
                &subject,
                "-m",
                &body,
            ],
            b"",
        )?;
        let committed = git.run_ok(self.wt, &["rev-parse", "HEAD^{tree}"], b"")?;
        if committed.trim() != tree {
            return Err("the commit doesn't hold the tree mezha reviewed".into());
        }
        // Bring the worktree's files in line with the commit, so the next
        // role starts from a clean tree.
        git.run_ok(self.wt, &["reset", "--quiet", "--hard", "HEAD"], b"")?;
        println!("  committed {} file(s)", changes.len() + 1);
        Ok(dir)
    }
}

fn print_review(r: &Review) {
    for phrase in &r.phrases {
        println!("  look at: {phrase}");
    }
    for warning in &r.warnings {
        eprintln!("  warning: {warning}");
    }
    for change in &r.changes {
        let what = match (&change.old, &change.new) {
            (None, Some(_)) => "add",
            (Some(_), None) => "remove",
            _ => "update",
        };
        println!("  {what:<7}{}", change.name);
    }
}

/// Shows a local or user role's diff and applies it on your `y`, after
/// checking the real directory didn't change during the dream. `Ok(false)`
/// means it wasn't applied.
fn apply_local(p: &Pending, ws: &Path) -> Result<bool, String> {
    let now = review::snapshot(&p.dir)?;
    if now != p.original {
        return Err(format!(
            "{} changed during the dream, so the reviewed diff no longer applies; dream again",
            p.dir.display()
        ));
    }
    let mut diff = String::new();
    let old_log = p
        .original
        .get(review::CHANGELOG)
        .map(|b| String::from_utf8_lossy(b).into_owned());
    let log_change = Change {
        name: review::CHANGELOG.into(),
        old: old_log,
        new: Some(p.changelog.clone()),
    };
    for change in p.changes.iter().chain([&log_change]) {
        diff.push_str(&unified(change));
    }
    println!(
        "\nThe dreamer's changes to the memory of {} in {}:\n{}",
        p.role,
        p.dir.display(),
        escape(&diff)
    );
    let apply = std::io::stdin().is_terminal()
        && super::confirm(&format!("Apply this to {}?", p.dir.display()))
            .map_err(|e| e.to_string())?;
    if !apply {
        let patch = ws.join(format!("{}.patch", p.role));
        mezha_memory::write_private(&patch, diff.as_bytes()).map_err(|e| e.to_string())?;
        println!(
            "Not applied. To apply it later, after reading it:\n  patch -p1 -E -d {} < {}",
            shell_word(&p.dir.to_string_lossy()),
            shell_word(&patch.to_string_lossy())
        );
        return Ok(false);
    }
    create_private_dir(&p.dir).map_err(|e| e.to_string())?;
    for change in p.changes.iter().chain([&log_change]) {
        let path = p.dir.join(&change.name);
        if std::fs::symlink_metadata(&path).is_ok_and(|m| !m.is_file()) {
            return Err(format!("{} is not a regular file", path.display()));
        }
        match &change.new {
            Some(text) => replace_file(&path, text.as_bytes())
                .map_err(|e| format!("{}: {e}", path.display()))?,
            None => std::fs::remove_file(&path).map_err(|e| format!("{}: {e}", path.display()))?,
        }
    }
    println!("Applied.");
    Ok(true)
}

fn unified(change: &Change) -> String {
    let old = change.old.as_deref().unwrap_or("");
    let new = change.new.as_deref().unwrap_or("");
    similar::TextDiff::from_lines(old, new)
        .unified_diff()
        .context_radius(3)
        .header(&format!("a/{}", change.name), &format!("b/{}", change.name))
        .to_string()
}

fn pr_body(stamp: &str, commits: &[Commit]) -> String {
    let roles: Vec<&str> = commits.iter().map(|c| c.role.as_str()).collect();
    let mut out = format!(
        "Memory changes from `mezha dream` ({stamp}) for: {}.\n\nReview them like code: agents \
         load this memory as instructions. Each commit holds the bytes mezha reviewed; the \
         dreamer's summaries below are its own words.\n",
        roles.join(", ")
    );
    for c in commits {
        out.push_str(&format!(
            "\n## {}\n\n- Runs: {}, ended from {} to {}\n- Dreamer: {} turns, ${:.2}\n",
            c.role,
            c.runs,
            format_iso(c.first),
            format_iso(c.last),
            c.outcome.turns,
            c.outcome.cost_usd
        ));
        if !c.phrases.is_empty() {
            out.push_str("- Phrases to look at:\n");
            for p in &c.phrases {
                out.push_str(&format!("  - {}\n", p.replace('`', "'")));
            }
        }
        out.push('\n');
        out.push_str(&inbox::fenced(c.outcome.summary.trim()));
    }
    // Kept by a squash merge that uses the PR description, so `mezha
    // metrics` can tell which dream landed.
    out.push('\n');
    for c in commits {
        out.push_str(&format!("mezha dream: {} ({} runs)\n", c.role, c.runs));
    }
    out.push_str(&format!("\nMezha-Dream: {stamp}\n"));
    out
}

/// Dreams whose worktree is still there: refused, waiting for you.
fn refused_dreams(dreams: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dreams)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            is_stamp_dir(&name) && p.join("wt").is_dir()
        })
        .map(|p| p.join("wt"))
        .collect();
    found.sort();
    found
}

/// Roles whose newest project dream is still pending, with its branch.
fn pending_roles(
    dreams: &[(
        mezha_metrics::dreams::DreamRow,
        Option<mezha_metrics::dreams::Status>,
    )],
) -> std::collections::BTreeMap<String, String> {
    let mut newest: std::collections::BTreeMap<
        String,
        &(
            mezha_metrics::dreams::DreamRow,
            Option<mezha_metrics::dreams::Status>,
        ),
    > = std::collections::BTreeMap::new();
    for entry in dreams.iter().filter(|(d, _)| d.scope == "project") {
        let slot = newest.entry(entry.0.role.clone()).or_insert(entry);
        if entry.0.at > slot.0.at {
            *slot = entry;
        }
    }
    newest
        .into_iter()
        .filter(|(_, (_, status))| *status == Some(mezha_metrics::dreams::Status::Pending))
        .map(|(role, (d, _))| (role, d.branch.clone().unwrap_or_default()))
        .collect()
}

/// Removes finished dreams beyond the newest few. A dream whose worktree is
/// still there was refused and stays until you remove it.
fn prune(dreams: &Path) {
    let mut finished: Vec<PathBuf> = std::fs::read_dir(dreams)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            is_stamp_dir(&name)
                && std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir())
                && !p.join("wt").exists()
        })
        .collect();
    finished.sort();
    let excess = finished.len().saturating_sub(KEEP_DREAMS);
    for old in finished.into_iter().take(excess) {
        let _ = std::fs::remove_dir_all(old);
    }
}

fn is_stamp_dir(name: &str) -> bool {
    let (stamp, suffix) = name.split_at(name.len().min(16));
    stamp.len() == 16
        && stamp.as_bytes()[8] == b'T'
        && stamp.ends_with('Z')
        && stamp
            .bytes()
            .enumerate()
            .all(|(i, b)| i == 8 || i == 15 || b.is_ascii_digit())
        && (suffix.is_empty()
            || suffix
                .strip_prefix('-')
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_inside_claude_code() {
        let var = |k: &str| (k == "CLAUDECODE").then(|| "1".to_string());
        assert!(refusal(var).is_some());
        if !cfg!(windows) {
            assert!(refusal(|_| None).is_none());
        }
    }

    #[test]
    fn stamp_dirs() {
        assert!(is_stamp_dir("20261009T041231Z"));
        assert!(is_stamp_dir("20261009T041231Z-2"));
        assert!(!is_stamp_dir("no-hooks"));
        assert!(!is_stamp_dir("cursor.json"));
        assert!(!is_stamp_dir("20261009T041231Z-"));
    }

    #[test]
    fn shell_words() {
        assert_eq!(shell_word("mezha/dream-1"), "mezha/dream-1");
        assert_eq!(shell_word("a b"), "'a b'");
        assert_eq!(shell_word("o'b"), "'o'\\''b'");
    }
}
