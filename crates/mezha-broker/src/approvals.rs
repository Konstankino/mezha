//! The approval store: `~/.mezha/approvals/<sha256(root)>.json`.
//!
//! The store lives outside every project, and the generated settings deny
//! sandboxed commands write access to `~/.mezha`, so an agent can't approve
//! itself while the sandbox is on. Anything unreadable, mismatched or
//! implausible counts as "no approval".

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The longest approval a human can grant in one go: a day.
pub const MAX_MINUTES: u32 = 1440;

/// Clock skew tolerated when reading an expiry, on top of [`MAX_MINUTES`].
const SKEW_SECS: u64 = 300;

/// `~/.mezha`: everything mezha keeps per user. Agents may not write here.
pub fn mezha_home(home: &Path) -> PathBuf {
    home.join(".mezha")
}

pub fn store_dir(home: &Path) -> PathBuf {
    mezha_home(home).join("approvals")
}

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    root: String,
    expires_at: u64,
}

/// One spelling per folder: forward slashes, and lowercase where the file
/// system ignores case.
fn root_key(root: &Path) -> String {
    let key = root.to_string_lossy().replace('\\', "/");
    if cfg!(any(target_os = "macos", windows)) {
        key.to_lowercase()
    } else {
        key
    }
}

/// The name mezha files a project under in `~/.mezha`: the SHA-256 of its
/// root, spelled one way per folder.
pub fn root_hash(root: &Path) -> String {
    crate::sha256_hex(root_key(root).as_bytes())
}

fn record_path(home: &Path, root: &Path) -> PathBuf {
    store_dir(home).join(format!("{}.json", root_hash(root)))
}

/// Grants an approval for `root` that ends `minutes` from `now` (Unix
/// seconds). Returns the expiry.
pub fn grant(home: &Path, root: &Path, minutes: u32, now: u64) -> io::Result<u64> {
    if !(1..=MAX_MINUTES).contains(&minutes) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("minutes must be between 1 and {MAX_MINUTES}"),
        ));
    }
    let expires_at = now + u64::from(minutes) * 60;
    let record = Record {
        root: root_key(root),
        expires_at,
    };
    let path = record_path(home, root);
    create_private_dir(path.parent().expect("record has a parent"))?;
    let json = serde_json::to_string(&record).map_err(io::Error::other)?;
    write_private_atomic(&path, json.as_bytes())?;
    Ok(expires_at)
}

/// Seconds left on the approval for `root`, or `None` when there is none.
pub fn remaining(home: &Path, root: &Path, now: u64) -> Option<u64> {
    let text = fs::read_to_string(record_path(home, root)).ok()?;
    let record: Record = serde_json::from_str(&text).ok()?;
    let latest = now + u64::from(MAX_MINUTES) * 60 + SKEW_SECS;
    if record.root != root_key(root) || record.expires_at <= now || record.expires_at > latest {
        return None;
    }
    Some(record.expires_at - now)
}

/// Ends the approval for `root`. Returns whether there was one to remove.
pub fn revoke(home: &Path, root: &Path) -> io::Result<bool> {
    match fs::remove_file(record_path(home, root)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

/// Writes through a temporary file and a rename, so a reader never sees a
/// half-written record.
fn write_private_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let result = options
        .open(&tmp)
        .and_then(|mut f| f.write_all(data).and_then(|()| f.sync_all()))
        .and_then(|()| fs::rename(&tmp, path));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn grant_then_remaining_then_revoke() {
        let home = tempfile::tempdir().unwrap();
        let root = Path::new("/work/repo");
        assert_eq!(remaining(home.path(), root, NOW), None);
        let expiry = grant(home.path(), root, 30, NOW).unwrap();
        assert_eq!(expiry, NOW + 1800);
        assert_eq!(remaining(home.path(), root, NOW), Some(1800));
        assert_eq!(remaining(home.path(), root, NOW + 1799), Some(1));
        assert_eq!(remaining(home.path(), root, NOW + 1800), None);
        assert_eq!(remaining(home.path(), Path::new("/work/other"), NOW), None);
        assert!(revoke(home.path(), root).unwrap());
        assert!(!revoke(home.path(), root).unwrap());
        assert_eq!(remaining(home.path(), root, NOW), None);
    }

    #[test]
    fn minutes_are_bounded() {
        let home = tempfile::tempdir().unwrap();
        let root = Path::new("/r");
        assert!(grant(home.path(), root, 0, NOW).is_err());
        assert!(grant(home.path(), root, MAX_MINUTES + 1, NOW).is_err());
        assert!(grant(home.path(), root, MAX_MINUTES, NOW).is_ok());
    }

    #[test]
    fn implausible_records_count_as_none() {
        let home = tempfile::tempdir().unwrap();
        let root = Path::new("/r");
        grant(home.path(), root, 5, NOW).unwrap();
        let path = record_path(home.path(), root);

        let far = serde_json::json!({ "root": root_key(root), "expires_at": NOW + 2 * 86_400 });
        fs::write(&path, far.to_string()).unwrap();
        assert_eq!(remaining(home.path(), root, NOW), None, "too far ahead");

        let wrong = serde_json::json!({ "root": "/elsewhere", "expires_at": NOW + 60 });
        fs::write(&path, wrong.to_string()).unwrap();
        assert_eq!(remaining(home.path(), root, NOW), None, "root mismatch");

        fs::write(&path, "garbage").unwrap();
        assert_eq!(remaining(home.path(), root, NOW), None, "not JSON");
    }

    #[cfg(unix)]
    #[test]
    fn the_store_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let root = Path::new("/r");
        grant(home.path(), root, 5, NOW).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&store_dir(home.path())), 0o700);
        assert_eq!(mode(&record_path(home.path(), root)), 0o600);
    }
}
