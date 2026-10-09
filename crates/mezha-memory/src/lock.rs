//! Advisory locks on files in `~/.mezha`: one dream per project at a time,
//! and one writer per metrics store. They are `flock` locks, so the kernel
//! drops them when the holder dies: no stale lock files, no reused PIDs.
//! On Windows they lock nothing (`mezha dream` doesn't run there yet).

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

/// Held until dropped.
#[derive(Debug)]
pub struct Lock {
    _file: File,
}

#[derive(Debug)]
pub enum LockError {
    /// Someone else holds it; the file says who, if they wrote it.
    Busy(String),
    Io(io::Error),
}

impl std::fmt::Display for LockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockError::Busy(holder) if holder.is_empty() => write!(f, "it is held"),
            LockError::Busy(holder) => write!(f, "it is held ({holder})"),
            LockError::Io(e) => write!(f, "{e}"),
        }
    }
}

fn open(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// Takes the lock now or fails with [`LockError::Busy`]. `note` (such as
/// "pid 123 since 03:00") is written into the file for whoever finds it
/// held.
pub fn try_lock(path: &Path, note: &str) -> Result<Lock, LockError> {
    let mut file = open(path).map_err(LockError::Io)?;
    #[cfg(unix)]
    {
        use rustix::fs::{FlockOperation, flock};
        if let Err(e) = flock(&file, FlockOperation::NonBlockingLockExclusive) {
            if e == rustix::io::Errno::WOULDBLOCK || e == rustix::io::Errno::AGAIN {
                let holder = std::fs::read_to_string(path).unwrap_or_default();
                return Err(LockError::Busy(holder.trim().to_string()));
            }
            return Err(LockError::Io(e.into()));
        }
    }
    file.set_len(0).map_err(LockError::Io)?;
    file.write_all(note.as_bytes()).map_err(LockError::Io)?;
    Ok(Lock { _file: file })
}

/// Waits for the lock: for short critical sections such as a store rewrite.
pub fn lock(path: &Path) -> io::Result<Lock> {
    let file = open(path)?;
    #[cfg(unix)]
    {
        use rustix::fs::{FlockOperation, flock};
        flock(&file, FlockOperation::LockExclusive)?;
    }
    Ok(Lock { _file: file })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn one_holder_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dream.lock");
        let held = try_lock(&path, "pid 1").unwrap();
        match try_lock(&path, "pid 2") {
            Err(LockError::Busy(holder)) => assert_eq!(holder, "pid 1"),
            other => panic!("{other:?}"),
        }
        drop(held);
        let again = try_lock(&path, "pid 3").unwrap();
        drop(again);
        let _store = lock(&path).unwrap();
    }

    #[test]
    fn a_dead_holder_frees_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dream.lock");
        // A child takes the lock and is killed while holding it.
        let mut child = std::process::Command::new("/usr/bin/python3")
            .args([
                "-I",
                "-c",
                "import fcntl,sys,time; f=open(sys.argv[1],'a'); fcntl.flock(f, fcntl.LOCK_EX); print('held', flush=True); time.sleep(30)",
            ])
            .arg(&path)
            .stdout(std::process::Stdio::piped())
            .spawn();
        let Ok(child) = child.as_mut() else {
            eprintln!("no python3; skipping");
            return;
        };
        let mut line = String::new();
        std::io::BufRead::read_line(
            &mut std::io::BufReader::new(child.stdout.as_mut().unwrap()),
            &mut line,
        )
        .unwrap();
        assert_eq!(line.trim(), "held");
        assert!(matches!(try_lock(&path, "me"), Err(LockError::Busy(_))));
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(try_lock(&path, "me").is_ok());
    }
}
