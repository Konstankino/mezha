//! Paths as hooks compare them: `.` and `..` folded without touching the
//! disk, symlinks resolved in the part that exists, and case folded where
//! the file system ignores it.

use std::path::{Component, Path, PathBuf};

/// Symlinks followed before giving up on a path.
const MAX_LINKS: usize = 40;

/// Removes `.` and `..` without touching the disk, then resolves symlinks in
/// the longest prefix that exists. A dangling symlink is followed to where
/// it points: writing through it would create its target.
pub(crate) fn resolve(path: &Path) -> PathBuf {
    resolve_at(path, 0)
}

fn resolve_at(path: &Path, depth: usize) -> PathBuf {
    let mut lexical = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                lexical.pop();
            }
            other => lexical.push(other),
        }
    }
    let mut existing = lexical.as_path();
    let mut missing = Vec::new();
    loop {
        if let Ok(canonical) = std::fs::canonicalize(existing) {
            let mut full = canonical;
            full.extend(missing.iter().rev());
            return full;
        }
        if depth < MAX_LINKS
            && std::fs::symlink_metadata(existing).is_ok_and(|m| m.file_type().is_symlink())
            && let Ok(target) = std::fs::read_link(existing)
        {
            let target = match existing.parent() {
                Some(parent) if target.is_relative() => parent.join(target),
                _ => target,
            };
            let mut full = resolve_at(&target, depth + 1);
            full.extend(missing.iter().rev());
            return full;
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                missing.push(name.to_os_string());
                existing = parent;
            }
            _ => return lexical,
        }
    }
}

pub(crate) fn within(path: &Path, dir: &Path) -> bool {
    let norm = |p: &Path| {
        let s = p.to_string_lossy().replace('\\', "/");
        let s = s.strip_prefix("//?/").map(str::to_string).unwrap_or(s);
        if cfg!(any(target_os = "macos", windows)) {
            s.to_lowercase()
        } else {
            s
        }
    };
    let (path, dir) = (norm(path), norm(dir));
    let dir = dir.trim_end_matches('/');
    path == dir || path.starts_with(&format!("{dir}/"))
}
