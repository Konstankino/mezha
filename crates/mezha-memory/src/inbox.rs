//! The inbox: one Markdown digest per agent run, for the dreamer (on its
//! stdin) and for you (saved next to the dream). Everything a run said is
//! untrusted, so it goes inside fences, after hard markers and secrets are
//! redacted, and PHI too when the spec has any.

use crate::markdown::heading_section;
use crate::scan::{self, Scan};
use crate::time::format_iso;
use crate::transcripts::{Run, RunKind};

/// What a digest keeps of each part, in bytes.
pub const MAX_TASK: usize = 4 * 1024;
pub const MAX_FINAL: usize = 8 * 1024;
pub const MAX_SECTION: usize = 4 * 1024;
pub const MAX_FOLLOWUP: usize = 2 * 1024;
pub const MAX_FAILURES: usize = 20;
pub const MAX_FAILURE: usize = 600;
pub const MAX_DIGEST: usize = 24 * 1024;
/// The digests of one role a dream reads, oldest first; the rest wait for
/// the next dream.
pub const MAX_ROLE: usize = 150 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digest {
    /// `<end stamp>-<id>.md`.
    pub file: String,
    pub text: String,
    /// When the run ended (Unix seconds).
    pub end: i64,
    /// Spans replaced by redaction.
    pub redactions: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoleInbox {
    pub digests: Vec<Digest>,
    /// Runs that didn't fit, left for the next dream.
    pub left: usize,
    pub redactions: usize,
}

impl RoleInbox {
    /// When the newest included run ended: the dream's cursor moves here.
    pub fn through(&self) -> Option<i64> {
        self.digests.iter().map(|d| d.end).max()
    }

    pub fn first(&self) -> Option<i64> {
        self.digests.iter().map(|d| d.end).min()
    }
}

/// The digests of `runs` (oldest first) that fit in [`MAX_ROLE`].
pub fn role_inbox(runs: &[&Run], phi: bool) -> RoleInbox {
    let mut inbox = RoleInbox::default();
    let mut total = 0;
    for (i, run) in runs.iter().enumerate() {
        let d = digest(run, phi);
        if total + d.text.len() > MAX_ROLE && !inbox.digests.is_empty() {
            inbox.left = runs.len() - i;
            break;
        }
        total += d.text.len();
        inbox.redactions += d.redactions;
        inbox.digests.push(d);
    }
    inbox
}

/// One run as Markdown.
pub fn digest(run: &Run, phi: bool) -> Digest {
    let scan = Scan {
        phrases: false,
        phi,
    };
    let mut redactions = 0;
    let mut clean = |text: &str, max: usize| -> String {
        let (text, found) = scan::redact(&cut(text, max), scan);
        redactions += found.len();
        text
    };
    let kind = match run.kind {
        RunKind::Subagent => "subagent",
        RunKind::Session => "session started as the agent",
    };
    let mut out = format!(
        "# Run of `{}`: {kind} {}\n\n- Session: `{}`\n- Ended: {} (started {})\n",
        run.role,
        word(&run.id),
        word(&run.session),
        format_iso(run.end),
        format_iso(run.start),
    );
    if let Some(branch) = &run.branch {
        out.push_str(&format!("- Branch: `{}`\n", word(&clean(branch, 200))));
    }
    out.push_str(&format!("- Failed tool calls: {}\n", run.failures.len()));

    push_section(&mut out, "Task", &clean(&run.task, MAX_TASK));
    if !run.failures.is_empty() {
        out.push_str("\n## Failed tool calls\n");
        for (i, f) in run.failures.iter().take(MAX_FAILURES).enumerate() {
            let body = format!(
                "input: {}\n\n{}",
                clean(&f.input, MAX_FAILURE),
                clean(&f.output, MAX_FAILURE)
            );
            out.push_str(&format!(
                "\n{}. `{}`\n\n{}",
                i + 1,
                word(&f.tool),
                fenced(&body)
            ));
        }
        if run.failures.len() > MAX_FAILURES {
            out.push_str(&format!(
                "\n[mezha: {} more failed calls not shown]\n",
                run.failures.len() - MAX_FAILURES
            ));
        }
    }
    push_section(
        &mut out,
        "Final message",
        &clean(&run.final_text, MAX_FINAL),
    );
    // From the whole message: a long one would lose its closing sections to
    // the cut above.
    for name in ["Lessons", "Unresolved"] {
        if let Some(body) = heading_section(&run.final_text, name) {
            let title = format!("{name} (from the final message)");
            push_section(&mut out, &title, &clean(&body, MAX_SECTION));
        }
    }
    for followup in &run.followups {
        push_section(
            &mut out,
            "Your next message",
            &clean(followup, MAX_FOLLOWUP),
        );
    }
    let text = cut(&out, MAX_DIGEST);
    Digest {
        file: format!("{}-{}.md", stamp(run.end), file_word(&run.id)),
        text,
        end: run.end,
        redactions,
    }
}

fn push_section(out: &mut String, title: &str, body: &str) {
    if body.trim().is_empty() {
        return;
    }
    out.push_str(&format!("\n## {title}\n\n{}", fenced(body)));
}

/// `text` in a fence longer than any backtick run inside it.
pub fn fenced(text: &str) -> String {
    let mut longest = 0;
    let mut run = 0;
    for c in text.chars() {
        run = if c == '`' { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    let fence = "`".repeat((longest + 1).max(3));
    let body = text.trim_end_matches('\n');
    format!("{fence}text\n{body}\n{fence}\n")
}

/// At most `max` bytes of `text`, cut at a character boundary.
pub fn cut(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n[mezha: cut {} bytes]", &text[..end], text.len() - end)
}

/// A single-line value safe inside backticks.
fn word(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() && *c != '`')
        .take(120)
        .collect()
}

fn file_word(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(40)
        .collect()
}

/// `YYYYMMDDTHHMMSSZ`.
pub fn stamp(secs: i64) -> String {
    format_iso(secs).replace(['-', ':'], "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fences_outgrow_backticks() {
        assert_eq!(fenced("a"), "```text\na\n```\n");
        assert_eq!(fenced("x ```` y"), "`````text\nx ```` y\n`````\n");
    }

    #[test]
    fn cuts_at_char_boundaries() {
        assert_eq!(cut("abc", 5), "abc");
        assert_eq!(cut("ab€d", 3), "ab\n[mezha: cut 4 bytes]");
    }

    #[test]
    fn stamps() {
        assert_eq!(stamp(1_800_000_000), "20270115T080000Z");
    }

    #[test]
    fn an_inbox_spans_its_runs() {
        let empty = RoleInbox::default();
        assert_eq!((empty.first(), empty.through()), (None, None));
        let digest = |end: i64| Digest {
            file: format!("{end}.md"),
            text: String::new(),
            end,
            redactions: 0,
        };
        let inbox = RoleInbox {
            digests: vec![digest(20), digest(10), digest(15)],
            left: 0,
            redactions: 0,
        };
        assert_eq!((inbox.first(), inbox.through()), (Some(10), Some(20)));
    }

    #[test]
    fn digests_cap_the_failed_calls_and_skip_empty_parts() {
        let run = Run {
            role: "implementer".into(),
            id: "a1".into(),
            session: "s1".into(),
            kind: RunKind::Subagent,
            start: 1_800_000_000,
            end: 1_800_000_060,
            branch: None,
            task: String::new(),
            final_text: "  \n".into(),
            failures: (1..=MAX_FAILURES + 3)
                .map(|i| crate::transcripts::Failure {
                    tool: "Bash".into(),
                    input: format!("cargo test {i}"),
                    output: format!("error {i}"),
                })
                .collect(),
            followups: Vec::new(),
        };
        let d = digest(&run, false);
        let text = &d.text;
        assert_eq!(d.file, "20270115T080100Z-a1.md");
        assert_eq!(d.end, run.end);
        assert_eq!(d.redactions, 0);
        assert!(
            text.contains(&format!("- Failed tool calls: {}\n", MAX_FAILURES + 3)),
            "{text}"
        );
        assert!(
            text.contains(&format!("\n{MAX_FAILURES}. `Bash`\n")),
            "{text}"
        );
        assert!(
            !text.contains(&format!("\n{}. `Bash`\n", MAX_FAILURES + 1)),
            "{text}"
        );
        assert!(
            text.contains("\n[mezha: 3 more failed calls not shown]\n"),
            "{text}"
        );
        for absent in [
            "- Branch:",
            "## Task",
            "## Final message",
            "## Your next message",
        ] {
            assert!(!text.contains(absent), "{absent} is in:\n{text}");
        }
    }
}
