//! The inbox: one Markdown digest per agent run, for the dreamer (on its
//! stdin) and for you (saved next to the dream). Everything a run said is
//! untrusted, so it goes inside fences, after hard markers and secrets are
//! redacted, and PHI too when the spec has any.

use crate::scan::{self, Scan};
use crate::time::format_iso;
use crate::transcripts::{Run, RunKind};

/// What a digest keeps of each part, in bytes.
pub const MAX_TASK: usize = 4 * 1024;
pub const MAX_FINAL: usize = 8 * 1024;
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

    section(&mut out, "Task", &clean(&run.task, MAX_TASK));
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
    let final_text = clean(&run.final_text, MAX_FINAL);
    section(&mut out, "Final message", &final_text);
    if let Some(lessons) = lessons(&final_text) {
        section(&mut out, "Lessons (from the final message)", &lessons);
    }
    for followup in &run.followups {
        section(
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

/// The `## Lessons` section of a final message: from that heading (any
/// level) to the next heading of the same or a higher level.
pub fn lessons(text: &str) -> Option<String> {
    let mut lines = text.lines();
    let mut level = 0;
    for line in lines.by_ref() {
        let hashes = line.chars().take_while(|c| *c == '#').count();
        if (1..=6).contains(&hashes)
            && line[hashes..]
                .trim()
                .trim_end_matches(':')
                .eq_ignore_ascii_case("lessons")
        {
            level = hashes;
            break;
        }
    }
    if level == 0 {
        return None;
    }
    let body: Vec<&str> = lines
        .take_while(|line| {
            let hashes = line.chars().take_while(|c| *c == '#').count();
            !((1..=level).contains(&hashes) && line[hashes..].starts_with(' '))
        })
        .collect();
    let body = body.join("\n").trim().to_string();
    (!body.is_empty()).then_some(body)
}

fn section(out: &mut String, title: &str, body: &str) {
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
    fn finds_lessons() {
        let text = "Done.\n\n## Lessons\n\n- run `cargo fmt` first\n\n## Next\nmore";
        assert_eq!(lessons(text).as_deref(), Some("- run `cargo fmt` first"));
        assert_eq!(
            lessons("### lessons:\n- a\n#### detail\n- b").as_deref(),
            Some("- a\n#### detail\n- b")
        );
        assert_eq!(lessons("no heading"), None);
        assert_eq!(lessons("## Lessons\n\n## Other"), None);
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
}
