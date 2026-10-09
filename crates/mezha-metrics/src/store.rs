//! The metrics store: JSON Lines files under `~/.mezha/metrics/<repo>/`,
//! one object per line with `"v": 1` and an id. Rewrites happen under a
//! `flock` and replace the file atomically; the last line for an id wins.
//! A line this mezha can't read is kept as it is, so an older or newer
//! mezha loses nothing. The store holds counts, ids, times, costs and
//! hashes, never transcript text.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value;

pub const VERSION: u64 = 1;
pub const SESSIONS: &str = "sessions.jsonl";
pub const DREAMS: &str = "dreams.jsonl";
pub const AB: &str = "ab.jsonl";
const LOCK: &str = "store.lock";

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: &Path) -> Store {
        Store {
            dir: dir.to_path_buf(),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The objects in `file` that carry `key`, last line per id winning.
    /// A missing file is empty.
    pub fn read(&self, file: &str, key: &str) -> Vec<Value> {
        let text = std::fs::read_to_string(self.dir.join(file)).unwrap_or_default();
        let mut rows: BTreeMap<String, Value> = BTreeMap::new();
        for line in text.lines() {
            if let Some((id, value)) = parse(line, key) {
                rows.insert(id, value);
            }
        }
        rows.into_values().collect()
    }

    /// Adds or replaces `rows` (by `key`) in `file`, keeping every other
    /// line, including ones this mezha can't read.
    pub fn upsert(&self, file: &str, key: &str, rows: &[Value]) -> io::Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        create_private_dir(&self.dir)?;
        let _lock = mezha_memory::lock::lock(&self.dir.join(LOCK))?;
        let path = self.dir.join(file);
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let mut fresh: BTreeMap<String, String> = BTreeMap::new();
        for row in rows {
            let id = row
                .get(key)
                .and_then(Value::as_str)
                .ok_or_else(|| io::Error::other(format!("a row without `{key}`")))?;
            fresh.insert(id.to_string(), row.to_string());
        }
        let mut out = String::new();
        let mut kept: BTreeMap<String, ()> = BTreeMap::new();
        for line in text.lines() {
            match parse(line, key) {
                Some((id, _)) if fresh.contains_key(&id) => {}
                Some((id, _)) => {
                    // Keep only the last line of an id seen twice.
                    if kept.insert(id, ()).is_none() {
                        out.push_str(line);
                        out.push('\n');
                    }
                }
                None if line.trim().is_empty() => {}
                None => {
                    out.push_str(line);
                    out.push('\n');
                }
            }
        }
        for line in fresh.values() {
            out.push_str(line);
            out.push('\n');
        }
        mezha_memory::write_private(&path, out.as_bytes())
    }
}

/// A line's id and object, when it is an object of a version this mezha
/// reads that carries `key`.
fn parse(line: &str, key: &str) -> Option<(String, Value)> {
    let value: Value = serde_json::from_str(line).ok()?;
    if value.get("v").and_then(Value::as_u64) != Some(VERSION) {
        return None;
    }
    let id = value.get(key)?.as_str()?.to_string();
    Some((id, value))
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn upserts_and_keeps_what_it_cannot_read() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(&dir.path().join("m"));
        assert!(store.read(SESSIONS, "id").is_empty());
        store
            .upsert(
                SESSIONS,
                "id",
                &[
                    json!({"v": 1, "id": "a", "n": 1}),
                    json!({"v": 1, "id": "b", "n": 1}),
                ],
            )
            .unwrap();
        // Lines from another mezha and a torn line survive a rewrite.
        let path = dir.path().join("m").join(SESSIONS);
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("{\"v\": 2, \"id\": \"future\"}\n{\"v\": 1, \"id\": \"tor\n");
        std::fs::write(&path, text).unwrap();
        store
            .upsert(SESSIONS, "id", &[json!({"v": 1, "id": "a", "n": 2})])
            .unwrap();
        let rows = store.read(SESSIONS, "id");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["n"], 2);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"future\""), "{text}");
        assert!(text.contains("\"tor"), "{text}");
        assert_eq!(text.matches("\"id\":\"a\"").count(), 1, "{text}");
    }

    #[test]
    fn concurrent_writers_lose_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m");
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let store = Store::new(&path);
                    for i in 0..10 {
                        let row = json!({"v": 1, "id": format!("{t}-{i}")});
                        store.upsert(AB, "id", &[row]).unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(Store::new(&path).read(AB, "id").len(), 80);
    }
}
