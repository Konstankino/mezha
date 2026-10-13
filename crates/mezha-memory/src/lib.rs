//! The memory plane's pure parts (`mezha-plan.md` section 3.6): reading
//! Claude Code transcripts into an inbox, the dreamer's invocation, the
//! scans, and the review of what the dreamer wrote. `mezha dream` (in the
//! CLI) runs the processes; nothing here starts one.

pub mod changelog;
pub mod claude;
pub mod cursor;
pub mod dreamer;
pub mod inbox;
pub mod lock;
pub mod markdown;
pub mod review;
pub mod scan;
pub mod schedule;
pub mod time;
pub mod transcripts;

use std::io;
use std::path::{Path, PathBuf};

/// `~/.mezha/dreams/<repo>`: one project's dreams. Sandboxed commands can't
/// write under `~/.mezha`, and sessions may not read `dreams/`.
pub fn dreams_dir(home: &Path, root: &Path) -> PathBuf {
    mezha_broker::approvals::mezha_home(home)
        .join("dreams")
        .join(mezha_broker::approvals::root_hash(&project_key_root(root)))
}

/// `~/.mezha/metrics/<repo>`: one project's metrics store.
pub fn metrics_dir(home: &Path, root: &Path) -> PathBuf {
    mezha_broker::approvals::mezha_home(home)
        .join("metrics")
        .join(mezha_broker::approvals::root_hash(&project_key_root(root)))
}

/// The path a project is filed under in `~/.mezha`: its place in the main
/// checkout, so every linked worktree of a repository shares one dreams
/// directory and one metrics store.
pub fn project_key_root(root: &Path) -> PathBuf {
    let top = root.ancestors().find(|dir| dir.join(".git").exists());
    let prefix = top
        .and_then(|t| root.strip_prefix(t).ok())
        .map(Path::to_path_buf)
        .unwrap_or_default();
    mezha_broker::repo_root(root).join(prefix)
}

/// Writes a file only its owner can read (0600 on Unix), replacing it
/// atomically.
pub fn write_private(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.mezha-tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&tmp)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worktrees_share_a_key() {
        let tmp = tempfile::tempdir().unwrap();
        // The key comes from `mezha_broker::repo_root`, which drops the
        // `\\?\` that `canonicalize` puts in front on Windows.
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let base = match base.to_str().and_then(|p| p.strip_prefix(r"\\?\")) {
            Some(plain) => PathBuf::from(plain),
            None => base,
        };
        let main = base.join("main");
        let gitdir = main.join(".git/worktrees/wt");
        std::fs::create_dir_all(&gitdir).unwrap();
        std::fs::write(gitdir.join("commondir"), "../..\n").unwrap();
        let wt = base.join("wt");
        std::fs::create_dir_all(wt.join("sub")).unwrap();
        std::fs::write(wt.join(".git"), format!("gitdir: {}\n", gitdir.display())).unwrap();
        assert_eq!(project_key_root(&wt), main);
        assert_eq!(project_key_root(&wt.join("sub")), main.join("sub"));
        assert_eq!(project_key_root(&main), main);
        let home = base.join("home");
        assert_eq!(dreams_dir(&home, &wt), dreams_dir(&home, &main));
    }

    #[test]
    fn metrics_sit_next_to_dreams_under_the_same_key() {
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let root = base.join("proj");
        std::fs::create_dir_all(root.join(".git")).unwrap();
        let home = base.join("home");
        let metrics = metrics_dir(&home, &root);
        let dreams = dreams_dir(&home, &root);
        let key = dreams.file_name().unwrap();
        assert_eq!(
            metrics.strip_prefix(&home).unwrap(),
            Path::new(".mezha/metrics").join(key),
            "{}",
            metrics.display()
        );
        assert_eq!(
            dreams.strip_prefix(&home).unwrap(),
            Path::new(".mezha/dreams").join(key),
            "{}",
            dreams.display()
        );
    }

    #[test]
    fn private_files_replace_their_predecessor() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("cursor.json");
        write_private(&path, b"one").unwrap();
        write_private(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        let names: Vec<String> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["cursor.json"]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{mode:o}");
        }
    }
}
