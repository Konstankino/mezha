//! `mezha metrics`: sessions, dreams and A/B runs for one project, from the
//! transcripts and the store under `~/.mezha/metrics/<repo>/`. Without
//! `--record` it only reads; `--record` (and every dream) keeps the
//! store's history going after Claude Code deletes old transcripts.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use mezha_memory::time::parse_since;
use mezha_memory::transcripts;
use mezha_metrics::ab::AbRow;
use mezha_metrics::dreams::{self, BaseChange, DreamRow, Status};
use mezha_metrics::sessions::{self, SessionRow};
use mezha_metrics::store::{self, Store};
use mezha_spec::Spec;
use mezha_verify::Ctx;
use serde_json::Value;

use crate::git::Git;

pub struct Options {
    pub since: Option<String>,
    pub json: bool,
    pub record: bool,
    pub ab: Option<PathBuf>,
    pub repeat: u32,
    pub yes: bool,
    pub unsandboxed_check: bool,
}

/// One project as metrics sees it.
pub struct Project<'a> {
    pub ctx: &'a Ctx,
    pub root: PathBuf,
    pub home: PathBuf,
    pub git: Option<Git<'a>>,
    /// The project and its worktrees, where its sessions ran.
    pub roots: Vec<PathBuf>,
    pub store: Store,
}

impl<'a> Project<'a> {
    pub fn open(ctx: &'a Ctx, root: &Path) -> Result<Project<'a>> {
        let home = ctx.home.clone().context("can't find the home directory")?;
        let git = Git::new(ctx).ok();
        let mut roots = vec![root.to_path_buf()];
        if let Some(git) = &git {
            let prefix = git
                .out(root, &["rev-parse", "--show-prefix"])
                .map(|p| p.trim().to_string())
                .unwrap_or_default();
            let dreams = mezha_memory::dreams_dir(&home, root);
            for wt in git.worktrees(root).unwrap_or_default() {
                // Dream and A/B worktrees run no sessions of yours.
                let tmp = std::env::temp_dir();
                let ab = wt.starts_with(&tmp)
                    && wt
                        .components()
                        .any(|c| c.as_os_str().to_string_lossy().starts_with("mezha-ab-"));
                if !wt.starts_with(&dreams) && !ab {
                    roots.push(wt.join(&prefix));
                }
            }
        }
        Ok(Project {
            ctx,
            store: Store::new(&mezha_memory::metrics_dir(&home, root)),
            root: root.to_path_buf(),
            home,
            git,
            roots,
        })
    }

    /// Every session the store knows, refreshed from the transcripts that
    /// are still there. With `write`, the store keeps the refreshed rows.
    pub fn sessions(&self, spec: &Spec, write: bool) -> Result<Vec<SessionRow>> {
        let config = transcripts::config_dir(|k| self.ctx.var(k).map(str::to_string), &self.home);
        let dir_override = self
            .ctx
            .var("CLAUDE_CONFIG_DIR")
            .and(self.ctx.var("CLAUDE_CODE_PROJECT_DIR_NAME"));
        let sources =
            transcripts::project_sources(&config.join("projects"), &self.roots, dir_override);
        let roles: BTreeSet<String> = spec.agent.keys().cloned().collect();
        let mut known: BTreeMap<String, SessionRow> = self
            .store
            .read(store::SESSIONS, "id")
            .into_iter()
            .filter_map(|v| serde_json::from_value::<SessionRow>(v).ok())
            .map(|r| (r.id.clone(), r))
            .collect();
        let mut fresh = Vec::new();
        for file in &sources.files {
            let id = file
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let (mtime, size) = sessions::source_stamp(file);
            if known
                .get(&id)
                .is_some_and(|r| r.source_mtime == mtime && r.source_size == size)
            {
                continue;
            }
            if let Some(row) = sessions::extract(file, &sources.roots, &roles) {
                fresh.push(row);
            }
        }
        if write {
            let rows: Vec<Value> = fresh
                .iter()
                .filter_map(|r| serde_json::to_value(r).ok())
                .collect();
            self.store.upsert(store::SESSIONS, "id", &rows)?;
        }
        for row in fresh {
            known.insert(row.id.clone(), row);
        }
        let mut all: Vec<SessionRow> = known.into_values().collect();
        all.sort_by_key(|r| r.start);
        Ok(all)
    }

    /// Every recorded dream with where it stands now. With `write`, newly
    /// decided outcomes are stored.
    pub fn dreams(&self, write: bool) -> Result<Vec<(DreamRow, Option<Status>)>> {
        let rows: Vec<DreamRow> = self
            .store
            .read(store::DREAMS, "key")
            .into_iter()
            .filter_map(|v| serde_json::from_value(v).ok())
            .collect();
        let Some(git) = &self.git else {
            return Ok(rows.into_iter().map(|r| (r, None)).collect());
        };
        let top = git.out(&self.root, &["rev-parse", "--show-toplevel"]).ok();
        let base = resolve_base_quiet(git, &self.root);
        let now = super::now() as i64;
        let mut out = Vec::new();
        let mut decided = Vec::new();
        for mut row in rows {
            if row.scope != "project" {
                out.push((row, None));
                continue;
            }
            let (Some(top), Some(base)) = (top.as_deref(), base.as_deref()) else {
                out.push((row, None));
                continue;
            };
            let top = Path::new(top.trim());
            let changes = base_changes(git, top, base, &row).unwrap_or_default();
            let alive = row
                .branch
                .as_deref()
                .is_some_and(|b| branch_alive(git, top, b));
            let status = dreams::status(&row, &changes, now, alive);
            if let (Status::Decided(outcome), None) = (status, row.outcome) {
                row.outcome = Some(outcome);
                decided.push(row.clone());
            }
            out.push((row, Some(status)));
        }
        if write {
            let values: Vec<Value> = decided
                .iter()
                .filter_map(|r| serde_json::to_value(r).ok())
                .collect();
            self.store.upsert(store::DREAMS, "key", &values)?;
        }
        Ok(out)
    }
}

pub fn run(root: &Path, opts: &Options) -> Result<ExitCode> {
    if let Some(tasks) = &opts.ab {
        return crate::ab::run(root, tasks, opts);
    }
    let root = std::fs::canonicalize(root).with_context(|| root.display().to_string())?;
    if opts.record && crate::approve::inside_claude_code(&|k: &str| std::env::var(k).ok()) {
        bail!(
            "mezha metrics --record refuses to run inside Claude Code: the store is under \
             ~/.mezha, which sessions may not write. Run it in your own terminal."
        );
    }
    let Some((spec, _)) = super::load(&root)? else {
        return Ok(ExitCode::FAILURE);
    };
    let ctx = Ctx::from_process(&root);
    let project = Project::open(&ctx, &root)?;
    let now = super::now() as i64;
    let since =
        parse_since(opts.since.as_deref().unwrap_or("30d"), now).map_err(anyhow::Error::msg)?;
    let sessions = project.sessions(&spec, opts.record)?;
    let dreams = project.dreams(opts.record)?;
    if opts.record {
        return Ok(ExitCode::SUCCESS);
    }
    let last = std::fs::read_to_string(
        mezha_memory::dreams_dir(&project.home, &root).join(crate::dream::LAST_RUN),
    )
    .ok()
    .and_then(|t| serde_json::from_str::<Value>(&t).ok());
    let ab_rows: Vec<AbRow> = project
        .store
        .read(store::AB, "id")
        .into_iter()
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect();
    let report = mezha_metrics::report::build(
        &spec.project.name,
        since,
        &sessions,
        &dreams,
        &ab_rows,
        last,
    );
    if opts.json {
        print!("{}", report.to_json());
    } else {
        print!("{}", report.to_human());
    }
    Ok(ExitCode::SUCCESS)
}

/// The base branch's commit, or `None` without one; no notes printed.
fn resolve_base_quiet(git: &Git, root: &Path) -> Option<String> {
    git.out(
        root,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            "refs/remotes/origin/HEAD^{commit}",
        ],
    )
    .or_else(|_| git.out(root, &["rev-parse", "--verify", "--quiet", "HEAD^{commit}"]))
    .ok()
    .map(|s| s.trim().to_string())
}

/// The base's first-parent commits since the dream that changed its
/// role's memory, oldest first, each with the patch-id of that change.
fn base_changes(git: &Git, top: &Path, base: &str, row: &DreamRow) -> Result<Vec<BaseChange>> {
    let Some(dir) = row.dir.as_deref() else {
        return Ok(Vec::new());
    };
    let since = format!("--since=@{}", row.at - 60);
    let log = git.out(
        top,
        &[
            "log",
            "--first-parent",
            "--format=%H%x1f%ct%x1f%B%x1e",
            &since,
            base,
            "--",
            dir,
        ],
    )?;
    let mut changes = Vec::new();
    for entry in log.split('\x1e').map(str::trim).filter(|e| !e.is_empty()) {
        let mut fields = entry.splitn(3, '\x1f');
        let (Some(commit), Some(time), message) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let parent = format!("{commit}^1");
        if git
            .out(top, &["rev-parse", "--verify", "--quiet", &parent])
            .is_err()
        {
            continue;
        }
        changes.push(BaseChange {
            commit: commit.to_string(),
            time: time.trim().parse().unwrap_or(0),
            message: message.unwrap_or("").to_string(),
            patch_id: memory_patch_id(git, top, &parent, commit, dir)?,
        });
    }
    changes.reverse();
    Ok(changes)
}

/// The patch-id of what `from..to` changed in `dir`, `CHANGELOG.md` left
/// out, without context lines (so a moved base doesn't change it). `None`
/// when nothing else changed.
pub fn memory_patch_id(
    git: &Git,
    top: &Path,
    from: &str,
    to: &str,
    dir: &str,
) -> Result<Option<String>> {
    let exclude = format!(":(exclude){dir}/CHANGELOG.md");
    let diff = git.out(
        top,
        &[
            "diff",
            "-U0",
            "--no-color",
            "--no-ext-diff",
            from,
            to,
            "--",
            dir,
            &exclude,
        ],
    )?;
    if diff.trim().is_empty() {
        return Ok(None);
    }
    let out = git
        .run_ok(top, &["patch-id", "--stable"], diff.as_bytes())
        .map_err(anyhow::Error::msg)?;
    Ok(out.split_whitespace().next().map(str::to_string))
}

fn branch_alive(git: &Git, top: &Path, branch: &str) -> bool {
    let local = format!("refs/heads/{branch}");
    let remote = format!("refs/remotes/*/{branch}");
    git.out(
        top,
        &["for-each-ref", "--format=%(refname)", &local, &remote],
    )
    .is_ok_and(|o| !o.trim().is_empty())
}

/// Used by `mezha dream`: records the project's sessions, quietly.
pub fn record_sessions(ctx: &Ctx, spec: &Spec, root: &Path) -> Result<()> {
    let project = Project::open(ctx, root)?;
    project.sessions(spec, true)?;
    project.dreams(true)?;
    Ok(())
}
