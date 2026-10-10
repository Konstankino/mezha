//! Turning rendered files into a plan, and a plan into files on disk.
//!
//! All or nothing: the plan is built from what is on disk before anything is
//! written. A file mezha didn't write, or that someone edited since, is a
//! conflict; `compile` stops on it, `apply` backs it up first.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::state::{STATE_PATH, STATE_VERSION, State, fingerprint, normalize};
use crate::{Rendered, is_generated};

/// `YYYYMMDDTHHMMSSZ` for Unix seconds.
pub use mezha_broker::utc_stamp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Already has the new content.
    Unchanged,
    Create,
    /// mezha's own earlier output; replaced.
    Update,
    /// Written by someone else, or edited since mezha wrote it.
    Conflict(String),
    /// No longer generated and untouched since: deleted.
    Remove,
    /// No longer generated but edited by hand: left alone.
    KeepRemoved(String),
}

#[derive(Debug, Clone)]
pub struct Change {
    pub path: String,
    pub action: Action,
    /// What is on disk now.
    pub old: Option<String>,
    /// What mezha would write.
    pub new: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub changes: Vec<Change>,
    pub state: State,
    /// The state file needs rewriting.
    pub state_changed: bool,
    /// Things worth telling the user that change nothing.
    pub notes: Vec<String>,
}

impl Plan {
    pub fn conflicts(&self) -> impl Iterator<Item = &Change> {
        self.changes
            .iter()
            .filter(|c| matches!(c.action, Action::Conflict(_)))
    }

    /// True when writing the plan would change nothing on disk.
    pub fn is_noop(&self) -> bool {
        !self.state_changed
            && self
                .changes
                .iter()
                .all(|c| matches!(c.action, Action::Unchanged | Action::KeepRemoved(_)))
    }
}

#[derive(Debug)]
pub enum WriteError {
    /// A path mezha won't write through: a symlink, a directory, a non-file.
    Refused {
        path: String,
        reason: String,
    },
    /// The state file is from a newer mezha.
    NewerState(u32),
    /// `compile` found conflicts; nothing was written.
    Conflicts,
    Io {
        path: String,
        error: io::Error,
    },
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WriteError::Refused { path, reason } => write!(f, "refusing to write {path}: {reason}"),
            WriteError::NewerState(v) => write!(
                f,
                "{STATE_PATH} has state_version {v}, newer than this mezha reads ({STATE_VERSION}); \
                 upgrade mezha"
            ),
            WriteError::Conflicts => write!(f, "conflicting files; nothing was written"),
            WriteError::Io { path, error } => write!(f, "{path}: {error}"),
        }
    }
}

impl std::error::Error for WriteError {}

fn io_err(path: &str) -> impl FnOnce(io::Error) -> WriteError + '_ {
    move |error| WriteError::Io {
        path: path.to_string(),
        error,
    }
}

/// Compares the rendered files with what is on disk.
pub fn plan(root: &Path, rendered: &Rendered) -> Result<Plan, WriteError> {
    let mut notes = Vec::new();
    fence(root, STATE_PATH)?;
    let old_state_text = read_text(root, STATE_PATH)?;
    let old_state = match &old_state_text {
        None => None,
        Some(text) => match serde_json::from_str::<State>(text) {
            Ok(state) if state.state_version > STATE_VERSION => {
                return Err(WriteError::NewerState(state.state_version));
            }
            Ok(mut state) => {
                // The state file is in the repository, so an agent can edit
                // it: only paths mezha generates are taken from it.
                state.files.retain(|path, _| {
                    let known = is_generated(path);
                    if !known {
                        notes.push(format!(
                            "ignoring `{path}` in {STATE_PATH}: mezha doesn't generate it"
                        ));
                    }
                    known
                });
                Some(state)
            }
            Err(e) => {
                notes.push(format!(
                    "{STATE_PATH} is unreadable ({e}); treating existing files as hand-written"
                ));
                None
            }
        },
    };
    let recorded = old_state.as_ref().map(|s| &s.files);

    let mut changes = Vec::new();
    let mut files = BTreeMap::new();
    for (path, content) in &rendered.files {
        fence(root, path)?;
        files.insert(path.clone(), fingerprint(content));
        let old = read_text(root, path)?;
        let action = match &old {
            None => Action::Create,
            Some(disk) if normalize(disk) == normalize(content) => Action::Unchanged,
            Some(disk) => match recorded.and_then(|r| r.get(path)) {
                Some(print) if *print == fingerprint(disk) => Action::Update,
                Some(_) => Action::Conflict("changed by hand since mezha wrote it".into()),
                None => Action::Conflict("not written by mezha".into()),
            },
        };
        changes.push(Change {
            path: path.clone(),
            action,
            old,
            new: Some(content.clone()),
        });
    }
    for (path, print) in recorded.into_iter().flatten() {
        if rendered.files.contains_key(path) {
            continue;
        }
        fence(root, path)?;
        let Some(disk) = read_text(root, path)? else {
            continue;
        };
        let action = if fingerprint(&disk) == *print {
            Action::Remove
        } else {
            Action::KeepRemoved("no longer generated, but changed by hand; left in place".into())
        };
        changes.push(Change {
            path: path.clone(),
            action,
            old: Some(disk),
            new: None,
        });
    }

    let state = State {
        state_version: STATE_VERSION,
        hook_protocol: mezha_hooks::PROTOCOL,
        spec: rendered.spec.clone(),
        files,
    };
    let state_changed = old_state_text.as_deref() != Some(state.to_json().as_str());
    Ok(Plan {
        changes,
        state,
        state_changed,
        notes,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Stop on any conflict without writing.
    Compile,
    /// Back up conflicting files, then overwrite them.
    Apply,
}

#[derive(Debug, Default)]
pub struct Report {
    pub written: Vec<String>,
    pub removed: Vec<String>,
    pub backup: Option<PathBuf>,
}

/// Carries out `plan`. `stamp` names the backup directory, such as
/// `20270115T080000Z`.
pub fn write(root: &Path, plan: &Plan, mode: Mode, stamp: &str) -> Result<Report, WriteError> {
    if mode == Mode::Compile && plan.conflicts().next().is_some() {
        return Err(WriteError::Conflicts);
    }
    let mut report = Report::default();
    // Conflicting files are about to be overwritten, and removed ones are
    // gone afterwards: keep a copy of both.
    let saved: Vec<&Change> = plan
        .changes
        .iter()
        .filter(|c| matches!(c.action, Action::Conflict(_) | Action::Remove))
        .collect();
    if !saved.is_empty() {
        let dir = backup_dir(root, stamp);
        for change in &saved {
            let target = dir.join(backup_path(&change.path));
            let display = target.display().to_string();
            fs::create_dir_all(target.parent().expect("backup has a parent"))
                .map_err(io_err(&display))?;
            fs::copy(root.join(&change.path), &target).map_err(io_err(&display))?;
        }
        let ignore = root.join(BACKUP_DIR).join(".gitignore");
        if !ignore.exists() {
            fs::write(&ignore, "*\n").map_err(io_err(BACKUP_DIR))?;
        }
        report.backup = Some(dir);
    }
    for change in &plan.changes {
        match &change.action {
            Action::Create | Action::Update | Action::Conflict(_) => {
                let content = change.new.as_deref().expect("written changes have content");
                write_atomic(root, &change.path, content)?;
                report.written.push(change.path.clone());
            }
            Action::Remove => {
                let path = root.join(&change.path);
                fs::remove_file(&path).map_err(io_err(&change.path))?;
                // A skill's directory goes too once it is empty; never a
                // non-empty one, and never through a symlink (fenced above).
                if change.path.starts_with(".claude/skills/")
                    && let Some(dir) = path.parent()
                {
                    let _ = fs::remove_dir(dir);
                }
                report.removed.push(change.path.clone());
            }
            Action::Unchanged | Action::KeepRemoved(_) => {}
        }
    }
    // Last, so an interrupted run leaves the old fingerprints in place.
    if plan.state_changed {
        write_atomic(root, STATE_PATH, &plan.state.to_json())?;
    }
    Ok(report)
}

pub const BACKUP_DIR: &str = ".mezha-backup";

/// Where a file goes inside a backup: `.claude` becomes `_claude`, so Claude
/// Code doesn't load backed-up agents and skills as if they were live.
fn backup_path(rel: &str) -> String {
    match rel.strip_prefix(".claude/") {
        Some(rest) => format!("_claude/{rest}"),
        None => rel.to_string(),
    }
}

/// `.mezha-backup/<stamp>`, or `<stamp>-2`, `-3`... if taken.
fn backup_dir(root: &Path, stamp: &str) -> PathBuf {
    let base = root.join(BACKUP_DIR);
    let mut dir = base.join(stamp);
    let mut n = 2;
    while dir.exists() {
        dir = base.join(format!("{stamp}-{n}"));
        n += 1;
    }
    dir
}

/// Refuses paths that aren't plain relative paths, and writing through
/// symlinks or over anything but a regular file.
pub(crate) fn fence(root: &Path, rel: &str) -> Result<(), WriteError> {
    let refused = |reason: &str| WriteError::Refused {
        path: rel.to_string(),
        reason: reason.to_string(),
    };
    let rel_path = Path::new(rel);
    if rel.is_empty()
        || rel.contains('\\')
        || !rel_path
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
    {
        return Err(refused("not a plain relative path"));
    }
    let mut current = root.to_path_buf();
    let parts: Vec<_> = rel_path.components().collect();
    for (i, part) in parts.iter().enumerate() {
        current.push(part);
        let Ok(meta) = fs::symlink_metadata(&current) else {
            return Ok(());
        };
        if meta.file_type().is_symlink() {
            return Err(refused(&format!("{} is a symlink", current.display())));
        }
        let last = i + 1 == parts.len();
        if last && !meta.is_file() {
            return Err(refused("not a regular file"));
        }
        if !last && !meta.is_dir() {
            return Err(refused(&format!(
                "{} is not a directory",
                current.display()
            )));
        }
    }
    Ok(())
}

fn read_text(root: &Path, rel: &str) -> Result<Option<String>, WriteError> {
    match fs::read(root.join(rel)) {
        Ok(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err(rel)(e)),
    }
}

fn write_atomic(root: &Path, rel: &str, content: &str) -> Result<(), WriteError> {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(io_err(rel))?;
    }
    let tmp = path.with_file_name(format!(
        ".{}.mezha-tmp",
        path.file_name().expect("file name").to_string_lossy()
    ));
    let result = fs::write(&tmp, content).and_then(|()| fs::rename(&tmp, &path));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map_err(io_err(rel))
}

/// A unified diff of one change, for `mezha diff`.
pub fn unified_diff(change: &Change) -> String {
    let old = change.old.as_deref().map(normalize).unwrap_or_default();
    let new = change.new.as_deref().map(normalize).unwrap_or_default();
    similar::TextDiff::from_lines(&old, &new)
        .unified_diff()
        .context_radius(3)
        .header(&format!("a/{}", change.path), &format!("b/{}", change.path))
        .to_string()
}
