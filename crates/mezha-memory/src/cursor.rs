//! Where the last dream of each role stopped reading, per machine
//! (`~/.mezha/dreams/<repo>/cursor.json`): another clone dreams from its
//! own transcripts, so the cursor can't live in the repository.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use serde_json::{Value, json};

use crate::time::{format_iso, parse_iso};

pub const FILE: &str = "cursor.json";

/// Role to the end time of the newest run its last dream read. Anything
/// unreadable counts as no cursor.
pub fn load(path: &Path) -> BTreeMap<String, i64> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return BTreeMap::new();
    };
    value
        .get("roles")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(role, at)| Some((role.clone(), parse_iso(at.as_str()?)?)))
        .collect()
}

/// Writes the cursor (0600, replaced atomically).
pub fn store(path: &Path, cursor: &BTreeMap<String, i64>) -> io::Result<()> {
    let roles: serde_json::Map<String, Value> = cursor
        .iter()
        .map(|(role, at)| (role.clone(), Value::from(format_iso(*at))))
        .collect();
    let text = format!(
        "{}\n",
        serde_json::to_string_pretty(&json!({ "version": 1, "roles": roles }))
            .map_err(io::Error::other)?
    );
    crate::write_private(path, text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE);
        assert!(load(&path).is_empty());
        let cursor = BTreeMap::from([("implementer".to_string(), 1_800_000_000)]);
        store(&path, &cursor).unwrap();
        assert_eq!(load(&path), cursor);
        std::fs::write(&path, "not json").unwrap();
        assert!(load(&path).is_empty());
    }
}
