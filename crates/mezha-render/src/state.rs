//! `.claude/.mezha-state.json`: the fingerprints of the files mezha wrote, so
//! a later run can tell its own output from a hand edit.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const STATE_PATH: &str = ".claude/.mezha-state.json";

/// The newest state format this mezha reads.
pub const STATE_VERSION: u32 = 1;

/// Sorted keys and no timestamps or mezha version, so teammates running the
/// same spec produce the same file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub state_version: u32,
    pub hook_protocol: u32,
    /// Fingerprint of the spec text the files were rendered from.
    pub spec: String,
    /// Generated path → fingerprint of its content.
    pub files: BTreeMap<String, String>,
}

impl State {
    pub fn to_json(&self) -> String {
        let mut text = serde_json::to_string_pretty(self).expect("state serializes");
        text.push('\n');
        text
    }
}

/// `sha256:<hex>` of the content with CRLF turned into LF, so a checkout with
/// `core.autocrlf` doesn't look like a hand edit.
pub fn fingerprint(content: &str) -> String {
    format!(
        "sha256:{}",
        mezha_broker::sha256_hex(normalize(content).as_bytes())
    )
}

pub fn normalize(content: &str) -> String {
    content.replace("\r\n", "\n")
}
