//! Approval as a granted capability.
//!
//! Week 1 holds only the approval store: a human runs `mezha approve` in their
//! own terminal, which writes an expiry outside the project, where sandboxed
//! agent commands can't write. The loopback credential helper and short-lived
//! tokens arrive in phase 1 (`mezha-plan.md`, section 3.5).

pub mod approvals;
mod repo;

use std::path::PathBuf;

pub use repo::repo_root;

/// The user's home: `HOME`, then `USERPROFILE`, then the platform's answer.
/// `var` reads the environment, so tests can point it at a scratch dir.
pub fn home_dir(var: impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    ["HOME", "USERPROFILE"]
        .iter()
        .filter_map(|k| var(k))
        .find(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(dirs::home_dir)
}

/// SHA-256 as lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
