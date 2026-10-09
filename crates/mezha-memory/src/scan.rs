//! Pattern scans over memory and transcript text. They are heuristics, so
//! *advisory*: a person reviews every dream diff, and for PHI the boundary
//! is local scope, not these patterns.
//!
//! - **Hard** markers have no business in agent memory: hidden or control
//!   characters, chat-template tokens, remote images and raw HTML, and
//!   secrets. They are redacted from digests, refuse a dream's commit and
//!   fail `mezha verify`. Each pattern aims at zero false positives.
//! - **Phrases** read like instructions to a model ("ignore previous
//!   instructions", `--no-verify`). Legitimate lessons quote them too ("avoid
//!   `--no-verify`"), so they are only highlighted for the reviewer.
//! - **PHI** patterns run only when the spec has PHI.

use std::sync::OnceLock;

use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Phrase,
    Phi,
    Hard,
}

/// Which levels to look for; hard markers are always on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Scan {
    pub phrases: bool,
    pub phi: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub level: Level,
    /// What was found, such as `GitHub token` or `bidi control`.
    pub what: &'static str,
    /// Byte range in the scanned text.
    pub start: usize,
    pub end: usize,
    /// 1-based line of `start`.
    pub line: usize,
}

impl Finding {
    /// The matched text, shortened and with control characters escaped, for
    /// a terminal or a Markdown report. Secrets and PHI show only a prefix.
    pub fn excerpt(&self, text: &str) -> String {
        let matched = text.get(self.start..self.end).unwrap_or("");
        let keep = match self.level {
            Level::Hard if self.what.ends_with("token") || self.what.ends_with("key") => 4,
            Level::Phi => 2,
            _ => 60,
        };
        let shown: String = matched.chars().take(keep).collect();
        let cut = if matched.chars().count() > keep {
            "…"
        } else {
            ""
        };
        format!("{}{cut}", escape(&shown))
    }
}

/// `text` with control, bidi and invisible characters shown as `\u{..}`,
/// safe to print in a terminal.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c == '\n' || c == '\t' || !(is_control(c) || is_hidden(c)) {
            out.push(c);
        } else {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        }
    }
    out
}

struct Pattern {
    level: Level,
    what: &'static str,
    regex: &'static str,
}

const PATTERNS: &[Pattern] = &[
    // Chat-template and role tokens.
    Pattern {
        level: Level::Hard,
        what: "chat-template token",
        regex: r"<\|[A-Za-z_]{2,20}\|>|\[/?INST\]|<</?SYS>>|</?system(?:-reminder)?>",
    },
    // Images load a URL when the Markdown is rendered.
    Pattern {
        level: Level::Hard,
        what: "remote image",
        regex: r"!\[[^\]\n]*\]\(\s*<?\s*(?:[A-Za-z][A-Za-z0-9+.-]*:|//)|!\[[^\]\n]*\]\[[^\]\n]*\]",
    },
    Pattern {
        level: Level::Hard,
        what: "raw HTML",
        regex: r"(?i)<!--|<(?:img|iframe|script|object|embed|link|meta|style|form|svg)\b",
    },
    // Secrets.
    Pattern {
        level: Level::Hard,
        what: "GitHub token",
        regex: r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})",
    },
    Pattern {
        level: Level::Hard,
        what: "Anthropic API token",
        regex: r"\bsk-ant-[A-Za-z0-9_-]{20,}",
    },
    Pattern {
        level: Level::Hard,
        what: "OpenAI API token",
        regex: r"\bsk-proj-[A-Za-z0-9_-]{20,}",
    },
    Pattern {
        level: Level::Hard,
        what: "AWS access key",
        regex: r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    },
    Pattern {
        level: Level::Hard,
        what: "Slack token",
        regex: r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
    },
    Pattern {
        level: Level::Hard,
        what: "GitLab token",
        regex: r"\bglpat-[A-Za-z0-9_-]{20,}",
    },
    Pattern {
        level: Level::Hard,
        what: "npm token",
        regex: r"\bnpm_[A-Za-z0-9]{36}\b",
    },
    Pattern {
        level: Level::Hard,
        what: "Google API key",
        regex: r"\bAIza[0-9A-Za-z_-]{35}\b",
    },
    Pattern {
        level: Level::Hard,
        what: "Stripe live key",
        regex: r"\b[rs]k_live_[0-9A-Za-z]{24,}\b",
    },
    Pattern {
        level: Level::Hard,
        what: "private key",
        regex: r"-----BEGIN [A-Z ]{0,20}PRIVATE KEY-----",
    },
    Pattern {
        level: Level::Hard,
        what: "JSON web token",
        regex: r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    },
    Pattern {
        level: Level::Hard,
        what: "assigned secret",
        // The value must mix letters and digits; checked in `findings`.
        regex: r#"(?i)\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)\b["']?\s*[:=]\s*["']?([A-Za-z0-9+/_.=-]{8,})"#,
    },
    // Instruction-like phrases.
    Pattern {
        level: Level::Phrase,
        what: "instruction override",
        regex: r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+|the\s+|your\s+)*(?:previous|prior|above|earlier|preceding|system)\s+(?:instructions|rules|messages|directions|prompts?)\b",
    },
    Pattern {
        level: Level::Phrase,
        what: "new instructions",
        regex: r"(?i)\b(?:new|updated|real)\s+(?:system\s+)?instructions\s*:|\byou\s+are\s+now\s+(?:a|an|the|in\s+\w+\s+mode)\b",
    },
    Pattern {
        level: Level::Phrase,
        what: "check bypass",
        regex: r"(?i)--no-verify\b|\bbypassPermissions\b|--dangerously-skip-permissions\b|\bdangerouslyDisableSandbox\b|\bmezha\s+approve\b",
    },
    Pattern {
        level: Level::Phrase,
        what: "download and run",
        regex: r"(?i)\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b",
    },
    Pattern {
        level: Level::Phrase,
        what: "hide from the user",
        regex: r"(?i)\b(?:do\s+not|don't|never)\s+(?:tell|inform|mention\s+(?:this\s+)?to|alert|show)\s+the\s+user\b",
    },
    Pattern {
        level: Level::Phrase,
        what: "encoded blob",
        regex: r"[A-Za-z0-9+/]{200,}={0,2}",
    },
    // PHI.
    Pattern {
        level: Level::Phi,
        what: "email address",
        regex: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b",
    },
    Pattern {
        level: Level::Phi,
        what: "phone number",
        regex: r"(?:\+\d{1,3}[\s.-]?)?\(?\b\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b|\+\d{2,3}[\s-]?\(?\d{2,3}\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}\b",
    },
    Pattern {
        level: Level::Phi,
        what: "SSN-like number",
        regex: r"\b\d{3}-\d{2}-\d{4}\b",
    },
    Pattern {
        level: Level::Phi,
        what: "medical record number",
        regex: r"(?i)\b(?:MRN|medical\s+record\s+(?:number|no\.?|#))\s*[:#]?\s*[A-Z0-9-]{4,}",
    },
    Pattern {
        level: Level::Phi,
        what: "date of birth",
        regex: r"(?i)\b(?:DOB|D\.O\.B\.|date\s+of\s+birth|born(?:\s+on)?)\s*[:-]?\s*(?:\d{4}-\d{2}-\d{2}|\d{1,2}[/.]\d{1,2}[/.]\d{2,4}|[A-Za-z]{3,9}\.?\s+\d{1,2},?\s+\d{4})",
    },
];

fn compiled() -> &'static [Regex] {
    static CELL: OnceLock<Vec<Regex>> = OnceLock::new();
    CELL.get_or_init(|| {
        PATTERNS
            .iter()
            .map(|p| Regex::new(p.regex).expect("scan patterns are valid"))
            .collect()
    })
}

/// Everything `scan` looks for in `text`, in order.
pub fn findings(text: &str, scan: Scan) -> Vec<Finding> {
    let mut out = Vec::new();
    let line_of = |at: usize| text[..at].matches('\n').count() + 1;
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    for (i, &(at, c)) in chars.iter().enumerate() {
        let what = if c == '\r' {
            // A carriage return that doesn't end a line can hide one.
            (chars.get(i + 1).map(|&(_, n)| n) != Some('\n')).then_some("carriage return")
        } else if c == '\u{200d}' {
            // A zero-width joiner between emoji is how emoji combine.
            let emoji = |j: Option<&(usize, char)>| j.is_some_and(|&(_, n)| is_emoji(n));
            (!(i > 0 && emoji(chars.get(i - 1)) && emoji(chars.get(i + 1))))
                .then_some("zero-width joiner")
        } else if is_hidden(c) {
            Some(
                if ('\u{202a}'..='\u{202e}').contains(&c) || ('\u{2066}'..='\u{2069}').contains(&c)
                {
                    "bidi control"
                } else if ('\u{e0000}'..='\u{e007f}').contains(&c) {
                    "tag character"
                } else {
                    "invisible character"
                },
            )
        } else if is_control(c) && c != '\n' && c != '\t' {
            Some("control character")
        } else {
            None
        };
        if let Some(what) = what {
            out.push(Finding {
                level: Level::Hard,
                what,
                start: at,
                end: at + c.len_utf8(),
                line: line_of(at),
            });
        }
    }
    for (pattern, regex) in PATTERNS.iter().zip(compiled()) {
        let wanted = match pattern.level {
            Level::Hard => true,
            Level::Phrase => scan.phrases,
            Level::Phi => scan.phi,
        };
        if !wanted {
            continue;
        }
        for caps in regex.captures_iter(text) {
            let Some(m) = caps.get(0) else { continue };
            if pattern.what == "email address" && is_service_address(text, m.start(), m.end()) {
                continue;
            }
            if let Some(value) = caps.get(1).map(|v| v.as_str())
                && pattern.what == "assigned secret"
                && !(value.bytes().any(|b| b.is_ascii_digit())
                    && value.bytes().any(|b| b.is_ascii_alphabetic()))
            {
                continue;
            }
            out.push(Finding {
                level: pattern.level,
                what: pattern.what,
                start: m.start(),
                end: m.end(),
                line: line_of(m.start()),
            });
        }
    }
    out.sort_by_key(|f| (f.start, std::cmp::Reverse(f.end)));
    out
}

/// `text` with every finding replaced by `[mezha: redacted <what>]`, and
/// the findings. Overlapping findings are replaced once.
pub fn redact(text: &str, scan: Scan) -> (String, Vec<Finding>) {
    let found = findings(text, scan);
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for f in &found {
        if f.start < at {
            continue;
        }
        out.push_str(&text[at..f.start]);
        out.push_str(&format!("[mezha: redacted {}]", f.what));
        at = f.end;
    }
    out.push_str(&text[at..]);
    (out, found)
}

/// Addresses that name a service, not a person: `git@host:` remotes and
/// `noreply` senders.
fn is_service_address(text: &str, start: usize, end: usize) -> bool {
    let matched = &text[start..end];
    let local = matched.split('@').next().unwrap_or("");
    local == "git" && text[end..].starts_with(':')
        || local.eq_ignore_ascii_case("noreply")
        || local.eq_ignore_ascii_case("no-reply")
}

fn is_control(c: char) -> bool {
    c.is_control()
}

/// Characters that render as nothing (or reorder text) and so can hide
/// words from a reviewer.
fn is_hidden(c: char) -> bool {
    matches!(c,
        '\u{00ad}' | '\u{061c}' | '\u{180e}'
        | '\u{200b}'..='\u{200f}'
        | '\u{2028}'..='\u{202e}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{2069}'
        | '\u{feff}'
        | '\u{e0000}'..='\u{e007f}')
}

fn is_emoji(c: char) -> bool {
    matches!(c, '\u{1f000}'..='\u{1faff}' | '\u{2600}'..='\u{27bf}' | '\u{fe0f}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_once_per_span() {
        let text = "key ghp_0123456789abcdefghijklmnopqrstuvwxyzAB and \u{202e}x";
        let (out, found) = redact(text, Scan::default());
        assert_eq!(
            out,
            "key [mezha: redacted GitHub token] and [mezha: redacted bidi control]x"
        );
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn escapes_for_terminals() {
        assert_eq!(escape("a\u{1b}[2Jb\u{202e}\n"), "a\\u{1b}[2Jb\\u{202e}\n");
    }

    #[test]
    fn excerpts_hide_secrets() {
        let text = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB";
        let f = &findings(text, Scan::default())[0];
        assert_eq!(f.excerpt(text), "ghp_…");
    }
}
