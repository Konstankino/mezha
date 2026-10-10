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

/// `YYYYMMDDTHHMMSSZ` for Unix seconds, without a date crate.
pub fn utc_stamp(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's days-to-civil algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::utc_stamp;

    #[test]
    fn stamps() {
        assert_eq!(utc_stamp(0), "19700101T000000Z");
        assert_eq!(utc_stamp(1_800_000_000), "20270115T080000Z");
        assert_eq!(utc_stamp(951_782_400), "20000229T000000Z");
        assert_eq!(utc_stamp(4_102_444_799), "20991231T235959Z");
    }
}
