//! Small file helpers for the dream and metrics commands.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// A word for a shell command line, quoted when needed.
pub fn shell_word(word: &str) -> String {
    if !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:,@+%^{}".contains(c))
    {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', r"'\''"))
    }
}

/// `<parent>/<name>`, or `<name>-2` and so on when it exists.
pub fn fresh_dir(parent: &Path, name: &str) -> Result<PathBuf> {
    for n in 1..100 {
        let dir = if n == 1 {
            parent.join(name)
        } else {
            parent.join(format!("{name}-{n}"))
        };
        match create_private_dir_exclusive(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(|| dir.display().to_string()),
        }
    }
    bail!("too many dreams named {name} in {}", parent.display())
}

pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

pub fn create_private_dir_exclusive(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(dir)
    }
    #[cfg(not(unix))]
    std::fs::create_dir(dir)
}

/// Writes `path` through a temporary file in the same directory.
pub fn replace_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.mezha-tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    {
        use std::io::Write;
        let mut file = options.open(&tmp)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_taken_name_gets_a_suffix() {
        let tmp = tempfile::tempdir().unwrap();
        let first = fresh_dir(tmp.path(), "20261009T041231Z").unwrap();
        assert_eq!(first, tmp.path().join("20261009T041231Z"));
        let second = fresh_dir(tmp.path(), "20261009T041231Z").unwrap();
        assert_eq!(second, tmp.path().join("20261009T041231Z-2"));
        assert!(second.is_dir(), "{} wasn't created", second.display());
    }

    #[test]
    fn fresh_dir_gives_up_after_too_many_and_reports_other_errors() {
        let tmp = tempfile::tempdir().unwrap();
        for _ in 0..99 {
            fresh_dir(tmp.path(), "s").unwrap();
        }
        let err = fresh_dir(tmp.path(), "s").unwrap_err().to_string();
        assert!(err.contains("too many dreams named s in"), "{err}");

        let file = tmp.path().join("file");
        std::fs::write(&file, "").unwrap();
        let err = format!("{:#}", fresh_dir(&file, "s").unwrap_err());
        assert!(
            err.starts_with(&file.join("s").display().to_string()),
            "{err}"
        );
    }

    #[test]
    fn replace_file_writes_through_a_temporary_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("MEMORY.md");
        replace_file(&path, b"one\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one\n");
        replace_file(&path, b"two\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "two\n");
        let left: Vec<String> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, ["MEMORY.md"], "{left:?}");
    }
}
