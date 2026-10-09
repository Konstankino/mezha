//! Did a dream land without edits? `mezha dream` records each commit with
//! the patch-id of its memory change (`git diff -U0`, `CHANGELOG.md` left
//! out). Later, the first commit on the base branch's first-parent history
//! that changed the role's memory decides:
//!
//! - the same patch-id: merged **without edits** (a merge commit, a rebase
//!   onto a moved base, or a squash);
//! - the dream's stamp in its message (the trailer, the branch name in a
//!   merge message, or the `mezha dream <stamp>` PR title): merged **with
//!   edits**;
//! - neither yet: **pending**, and **stale** after 30 days.
//!
//! A decided outcome is stored and doesn't change: memory edited weeks
//! later says nothing about the dream.

use serde::{Deserialize, Serialize};

/// When a pending dream becomes stale.
pub const STALE_AFTER: i64 = 30 * 86_400;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DreamRow {
    pub v: u64,
    /// `<stamp>/<role>`.
    pub key: String,
    pub stamp: String,
    pub role: String,
    /// `project`, `local` or `user`.
    pub scope: String,
    /// When the dream committed or applied (Unix seconds).
    pub at: i64,
    pub runs: usize,
    pub turns: u64,
    pub cost_usd: f64,
    /// Project memory: the commit, the role's directory and the patch-id of
    /// its change.
    pub commit: Option<String>,
    pub dir: Option<String>,
    pub patch_id: Option<String>,
    /// The branch the dream committed to.
    #[serde(default)]
    pub branch: Option<String>,
    /// Local and user memory: applied after you confirmed it.
    #[serde(default)]
    pub applied: bool,
    pub outcome: Option<Outcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    WithoutEdits,
    WithEdits,
    Stale,
}

/// A first-parent commit of the base branch that changed a role's memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseChange {
    pub commit: String,
    /// Committer time (Unix seconds).
    pub time: i64,
    pub message: String,
    /// The patch-id of its memory change, `None` when only `CHANGELOG.md`
    /// changed.
    pub patch_id: Option<String>,
}

/// The outcome of a project dream, from the base's changes to its memory
/// in commit order, oldest first. `None` while it is pending.
pub fn classify(row: &DreamRow, changes: &[BaseChange], now: i64) -> Option<Outcome> {
    if let Some(done) = row.outcome {
        return Some(done);
    }
    // Clock skew between machines: allow a minute.
    for change in changes.iter().filter(|c| c.time >= row.at - 60) {
        if row.patch_id.is_some() && change.patch_id == row.patch_id {
            return Some(Outcome::WithoutEdits);
        }
        if change.message.contains(&row.stamp) {
            return Some(Outcome::WithEdits);
        }
    }
    (now - row.at > STALE_AFTER).then_some(Outcome::Stale)
}

/// Where a project dream stands now. Only [`Status::Decided`] is stored:
/// "dropped" can turn into "merged" once you fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Decided(Outcome),
    /// Its branch is still there and it hasn't landed.
    Pending,
    /// Its branch is gone and it hasn't landed (as of your last fetch).
    Dropped,
}

pub fn status(row: &DreamRow, changes: &[BaseChange], now: i64, branch_alive: bool) -> Status {
    match classify(row, changes, now) {
        Some(outcome) => Status::Decided(outcome),
        None if branch_alive => Status::Pending,
        None => Status::Dropped,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DreamTally {
    pub without_edits: usize,
    pub with_edits: usize,
    pub stale: usize,
    pub pending: usize,
    pub dropped: usize,
    /// Local and user dreams you applied.
    pub applied: usize,
}

impl DreamTally {
    /// Counts a dream; `status` is where a project dream stands now.
    pub fn add(&mut self, row: &DreamRow, status: Option<Status>) {
        if row.scope != "project" {
            self.applied += usize::from(row.applied);
            return;
        }
        match status.unwrap_or(match row.outcome {
            Some(o) => Status::Decided(o),
            None => Status::Pending,
        }) {
            Status::Decided(Outcome::WithoutEdits) => self.without_edits += 1,
            Status::Decided(Outcome::WithEdits) => self.with_edits += 1,
            Status::Decided(Outcome::Stale) => self.stale += 1,
            Status::Pending => self.pending += 1,
            Status::Dropped => self.dropped += 1,
        }
    }

    /// Without edits among the decided project dreams (merged either way).
    pub fn share_without_edits(&self) -> Option<f64> {
        let decided = self.without_edits + self.with_edits;
        (decided > 0).then(|| self.without_edits as f64 / decided as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(stamp: &str, patch: &str) -> DreamRow {
        DreamRow {
            v: 1,
            key: format!("{stamp}/implementer"),
            stamp: stamp.into(),
            role: "implementer".into(),
            scope: "project".into(),
            at: 1000,
            runs: 1,
            turns: 4,
            cost_usd: 0.1,
            commit: Some("d".into()),
            dir: Some(".claude/agent-memory/implementer".into()),
            patch_id: Some(patch.into()),
            branch: Some(format!("mezha/dream-{stamp}")),
            applied: false,
            outcome: None,
        }
    }

    fn change(time: i64, message: &str, patch: Option<&str>) -> BaseChange {
        BaseChange {
            commit: format!("c{time}"),
            time,
            message: message.into(),
            patch_id: patch.map(str::to_string),
        }
    }

    #[test]
    fn outcomes() {
        let r = row("20261009T030000Z", "p1");
        // Merged as is (merge commit, rebase or squash): same patch.
        assert_eq!(
            classify(
                &r,
                &[change(2000, "Merge pull request #4", Some("p1"))],
                3000
            ),
            Some(Outcome::WithoutEdits)
        );
        // Edited in the PR: another patch, but the stamp is in the message.
        assert_eq!(
            classify(
                &r,
                &[change(
                    2000,
                    "mezha dream 20261009T030000Z (#4)",
                    Some("p2")
                )],
                3000
            ),
            Some(Outcome::WithEdits)
        );
        // An unrelated memory change first, then the dream lands as is.
        assert_eq!(
            classify(
                &r,
                &[
                    change(1500, "hand edit", Some("x")),
                    change(2000, "squash", Some("p1"))
                ],
                3000
            ),
            Some(Outcome::WithoutEdits)
        );
        // Changes from before the dream don't count; pending, then stale.
        assert_eq!(classify(&r, &[change(10, "old", Some("p1"))], 3000), None);
        assert_eq!(
            classify(&r, &[], 1000 + STALE_AFTER + 1),
            Some(Outcome::Stale)
        );
        // A decided outcome stays put.
        let decided = DreamRow {
            outcome: Some(Outcome::WithoutEdits),
            ..r.clone()
        };
        assert_eq!(
            classify(&decided, &[change(5000, "edit", Some("z"))], 9000),
            Some(Outcome::WithoutEdits)
        );
    }

    #[test]
    fn tallies() {
        let mut t = DreamTally::default();
        let mut r = row("s", "p");
        r.outcome = Some(Outcome::WithoutEdits);
        t.add(&r, None);
        r.outcome = Some(Outcome::WithEdits);
        t.add(&r, None);
        r.outcome = None;
        t.add(&r, Some(status(&r, &[], 2000, true)));
        t.add(&r, Some(status(&r, &[], 2000, false)));
        let local = DreamRow {
            scope: "local".into(),
            applied: true,
            ..r.clone()
        };
        t.add(&local, None);
        assert_eq!(
            (
                t.without_edits,
                t.with_edits,
                t.pending,
                t.dropped,
                t.applied
            ),
            (1, 1, 1, 1, 1)
        );
        assert_eq!(t.share_without_edits(), Some(0.5));
    }
}
