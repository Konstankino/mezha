//! Private scratch directories: a fresh name from the OS's randomness,
//! created exclusively (0700 on Unix), and removed when dropped, whichever
//! way the code leaves, a timeout included.

use std::io;
use std::path::{Path, PathBuf};

pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    /// A new empty directory under the system temp directory.
    pub fn new(prefix: &str) -> io::Result<Scratch> {
        let base = std::env::temp_dir();
        let mut last = None;
        for _ in 0..8 {
            let path = base.join(format!("{prefix}-{}", nonce()?));
            match create_private_dir(&path) {
                Ok(()) => return Ok(Scratch { path }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("no free scratch name")))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Writes a file that must not exist yet (0600 on Unix).
    pub fn write_new(&self, name: &str, contents: &[u8]) -> io::Result<PathBuf> {
        use std::io::Write;
        let path = self.path.join(name);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options.open(&path)?.write_all(contents)?;
        Ok(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> io::Result<()> {
    std::fs::create_dir(path)
}

/// 128 random bits as hex: from `/dev/urandom` on Unix, elsewhere from
/// the randomly seeded keys of the standard library's hasher.
pub fn nonce() -> io::Result<String> {
    let bytes = random_bytes()?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(unix)]
fn random_bytes() -> io::Result<[u8; 16]> {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

#[cfg(not(unix))]
fn random_bytes() -> io::Result<[u8; 16]> {
    use std::hash::{BuildHasher, Hasher};
    let half = || {
        std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish()
    };
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&half().to_le_bytes());
    bytes[8..].copy_from_slice(&half().to_le_bytes());
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scratch_is_private_and_goes_away() {
        let scratch = Scratch::new("mezha-test").unwrap();
        let dir = scratch.path().to_path_buf();
        let file = scratch.write_new("f", b"x").unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"x");
        assert!(scratch.write_new("f", b"y").is_err(), "create_new");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir), 0o700);
            assert_eq!(mode(&file), 0o600);
        }
        drop(scratch);
        assert!(!dir.exists());
    }

    #[test]
    fn nonces_differ() {
        let a = nonce().unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a, nonce().unwrap());
    }
}
