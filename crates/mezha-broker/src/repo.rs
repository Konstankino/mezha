//! Finding the repository root without running git: the hook calls this on
//! every gated command, and a hook that spawns processes can time out, which
//! Claude Code treats as "let the call through".

use std::fs;
use std::path::{Path, PathBuf};

/// The root that approvals are keyed by. Every worktree of a repository maps
/// to the main checkout, so one approval covers them all; a submodule is its
/// own root. Outside any repository, the canonical `start` is the root.
pub fn repo_root(start: &Path) -> PathBuf {
    let start = canon(start);
    for dir in start.ancestors() {
        let dotgit = dir.join(".git");
        let Ok(meta) = fs::metadata(&dotgit) else {
            continue;
        };
        if meta.is_dir() {
            return dir.to_path_buf();
        }
        if meta.is_file() {
            return gitfile_root(dir, &dotgit).unwrap_or_else(|| dir.to_path_buf());
        }
    }
    start
}

/// A `.git` file says `gitdir: <path>`. A linked worktree's gitdir has a
/// `commondir` file pointing at the main repository's `.git`; a submodule's
/// gitdir doesn't, and the submodule is its own root.
fn gitfile_root(dir: &Path, dotgit: &Path) -> Option<PathBuf> {
    let text = fs::read_to_string(dotgit).ok()?;
    let gitdir = text.lines().next()?.strip_prefix("gitdir:")?.trim();
    let gitdir = canon(&dir.join(gitdir));
    let common = fs::read_to_string(gitdir.join("commondir")).ok()?;
    let common = canon(&gitdir.join(common.trim()));
    common.parent().map(Path::to_path_buf)
}

fn canon(path: &Path) -> PathBuf {
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    strip_verbatim(canonical)
}

/// Windows `canonicalize` returns `\\?\C:\...`; keep the ordinary form so the
/// same folder always gives the same key.
fn strip_verbatim(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_directory_holding_dot_git() {
        let tmp = tempfile::tempdir().unwrap();
        let root = canon(tmp.path());
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(root.join("src/deep")).unwrap();
        assert_eq!(repo_root(&root.join("src/deep")), root);
        assert_eq!(repo_root(&root), root);
    }

    #[test]
    fn a_worktree_maps_to_the_main_checkout() {
        let tmp = tempfile::tempdir().unwrap();
        let main = canon(tmp.path()).join("main");
        let gitdir = main.join(".git/worktrees/wt");
        fs::create_dir_all(&gitdir).unwrap();
        fs::write(gitdir.join("commondir"), "../..\n").unwrap();
        let wt = canon(tmp.path()).join("wt");
        fs::create_dir_all(wt.join("src")).unwrap();
        fs::write(wt.join(".git"), format!("gitdir: {}\n", gitdir.display())).unwrap();
        assert_eq!(repo_root(&wt.join("src")), main);
    }

    #[test]
    fn a_submodule_is_its_own_root() {
        let tmp = tempfile::tempdir().unwrap();
        let outer = canon(tmp.path());
        let modules = outer.join(".git/modules/sub");
        fs::create_dir_all(&modules).unwrap();
        let sub = outer.join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join(".git"), "gitdir: ../.git/modules/sub\n").unwrap();
        assert_eq!(repo_root(&sub), sub);
    }

    #[test]
    fn outside_a_repository_the_start_is_the_root() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = canon(tmp.path()).join("plain");
        fs::create_dir_all(&dir).unwrap();
        // The temp dir itself might sit inside a repository on some machines.
        let expected = repo_root(&dir);
        assert!(expected == dir || dir.starts_with(&expected));
    }
}
