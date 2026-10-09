//! The memory plane's pure parts (`mezha-plan.md` section 3.6): reading
//! Claude Code transcripts into an inbox, the dreamer's invocation, the
//! scans, and the review of what the dreamer wrote. `mezha dream` (in the
//! CLI) runs the processes; nothing here starts one.

pub mod changelog;
pub mod cursor;
pub mod dreamer;
pub mod inbox;
pub mod review;
pub mod scan;
pub mod time;
pub mod transcripts;

use std::io;
use std::path::{Path, PathBuf};

/// `~/.mezha/dreams/<repo>`: one project's dreams. Sandboxed commands can't
/// write under `~/.mezha`, and sessions may not read `dreams/`.
pub fn dreams_dir(home: &Path, root: &Path) -> PathBuf {
    mezha_broker::approvals::mezha_home(home)
        .join("dreams")
        .join(mezha_broker::approvals::root_hash(root))
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
