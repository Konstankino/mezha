//! The metrics plane (`mezha-plan.md` sections 3.7 and 7): what sessions
//! cost, how often work came back, what agents left unresolved, whether
//! dreams landed without edits, the A/B runner's task file and report, and
//! skill evals' case file and report.
//! Pure logic over transcripts and git facts; the CLI runs the processes.

pub mod ab;
pub mod dreams;
pub mod report;
pub mod sessions;
pub mod skill_eval;
pub mod store;
