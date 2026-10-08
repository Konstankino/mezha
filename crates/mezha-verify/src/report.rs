//! Check results, their human and JSON forms, and the exit code.

use serde::Serialize;

/// Bumped whenever the JSON shape changes incompatibly (new fields aren't).
pub const JSON_VERSION: u32 = 1;

/// Kinds of evidence behind a check's status.
pub const STATIC: &str = "static";
/// Shown by running something inside `srt`.
pub const PROBE: &str = "probe";
/// Reported by the forge's API.
pub const SERVER: &str = "server";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Skip,
    Pass,
    Warn,
    Fail,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
            Status::Skip => "SKIP",
        }
    }
}

/// What a check is about, matching the README's boundary table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// Enforced by the OS or the server.
    Boundary,
    /// Keeps generated guard rails from quietly disappearing.
    Integrity,
    /// A guard rail that a determined agent can get around.
    Advisory,
    /// Repository housekeeping that affects the above.
    Hygiene,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub title: &'static str,
    pub kind: Kind,
    pub status: Status,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    /// What the status rests on: [`STATIC`], [`PROBE`], [`SERVER`].
    pub evidence: Vec<&'static str>,
}

impl Check {
    pub fn new(id: &'static str, title: &'static str, kind: Kind) -> Self {
        Check {
            id,
            title,
            kind,
            status: Status::Pass,
            detail: String::new(),
            fix: None,
            evidence: vec![STATIC],
        }
    }

    pub fn skip(id: &'static str, title: &'static str, kind: Kind, why: &str) -> Self {
        Check {
            status: Status::Skip,
            detail: why.to_string(),
            evidence: Vec::new(),
            ..Check::new(id, title, kind)
        }
    }
}

/// Collects findings for one check; the worst status wins.
#[derive(Debug, Default)]
pub struct Findings {
    status: Option<Status>,
    details: Vec<String>,
    fixes: Vec<String>,
}

impl Findings {
    pub fn add(&mut self, status: Status, detail: impl Into<String>, fix: Option<String>) {
        self.status = Some(self.status.map_or(status, |s| s.max(status)));
        self.details.push(detail.into());
        if let Some(fix) = fix
            && !self.fixes.contains(&fix)
        {
            self.fixes.push(fix);
        }
    }

    pub fn fail(&mut self, detail: impl Into<String>, fix: impl Into<String>) {
        self.add(Status::Fail, detail, Some(fix.into()));
    }

    pub fn warn(&mut self, detail: impl Into<String>, fix: Option<String>) {
        self.add(Status::Warn, detail, fix);
    }

    pub fn status(&self) -> Status {
        self.status.unwrap_or(Status::Pass)
    }

    /// The finished check; `ok` describes a clean result.
    pub fn into_check(self, mut check: Check, ok: &str) -> Check {
        check.status = self.status();
        check.detail = if self.details.is_empty() {
            ok.to_string()
        } else {
            self.details.join("; ")
        };
        check.fix = (!self.fixes.is_empty()).then(|| self.fixes.join(" "));
        check
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    pub pass: usize,
    pub warn: usize,
    pub fail: usize,
    pub skip: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub version: u32,
    pub mezha: &'static str,
    pub hook_protocol: u32,
    pub platform: &'static str,
    pub claude_code: Option<String>,
    pub mode: &'static str,
    /// The sandbox runtime `--probe` ran in, such as `srt 0.0.79`.
    pub probe: Option<String>,
    pub checks: Vec<Check>,
    pub summary: Summary,
    pub notes: Vec<String>,
}

impl Report {
    pub fn summarize(&mut self) {
        let mut s = Summary::default();
        for check in &self.checks {
            match check.status {
                Status::Pass => s.pass += 1,
                Status::Warn => s.warn += 1,
                Status::Fail => s.fail += 1,
                Status::Skip => s.skip += 1,
            }
        }
        self.summary = s;
    }

    /// 0 when nothing failed, 1 otherwise. (2, "couldn't run", is decided
    /// before a report exists.)
    pub fn exit_code(&self) -> i32 {
        if self.checks.iter().any(|c| c.status == Status::Fail) {
            1
        } else {
            0
        }
    }

    /// Strips credentials from every piece of text in the report.
    pub fn redact(&mut self) {
        for check in &mut self.checks {
            check.detail = redact(&check.detail);
            check.fix = check.fix.as_deref().map(redact);
        }
        for note in &mut self.notes {
            *note = redact(note);
        }
        self.probe = self.probe.as_deref().map(redact);
    }

    pub fn to_json(&self) -> String {
        let mut text = serde_json::to_string_pretty(self).expect("report serializes");
        text.push('\n');
        text
    }

    pub fn to_human(&self, root: &str) -> String {
        let mut out = format!(
            "mezha verify: {root} ({}, Claude Code {}{}{})\n",
            self.platform,
            self.claude_code.as_deref().unwrap_or("not found"),
            if self.mode == "project-only" {
                ", project files only"
            } else {
                ""
            },
            self.probe
                .as_deref()
                .map(|p| format!(", probed in {p}"))
                .unwrap_or_default()
        );
        let width = self.checks.iter().map(|c| c.id.len()).max().unwrap_or(0);
        for check in &self.checks {
            out.push_str(&format!(
                "  {}  {:width$}  {}\n",
                check.status.label(),
                check.id,
                check.detail
            ));
            if let Some(fix) = &check.fix {
                out.push_str(&format!("        {:width$}  fix: {fix}\n", ""));
            }
        }
        for note in &self.notes {
            out.push_str(&format!("note: {note}\n"));
        }
        let s = &self.summary;
        out.push_str(&format!(
            "{} failed, {} warning(s), {} passed, {} skipped.\n",
            s.fail, s.warn, s.pass, s.skip
        ));
        out
    }
}

/// Removes userinfo from URLs (`https://user:token@host` → `https://host`)
/// so no credential reaches the output. A password may hold a `/`
/// (`https://u:a/b@host`): when the text before the first `/` has a `:` and
/// no `@`, everything up to the URL's last `@` goes.
pub fn redact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("://") {
        let (head, tail) = rest.split_at(i + 3);
        out.push_str(head);
        let token_end = tail
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`'))
            .unwrap_or(tail.len());
        let token = &tail[..token_end];
        let authority = &token[..token.find('/').unwrap_or(token.len())];
        let skip = match authority.rfind('@') {
            Some(at) => at + 1,
            None if authority.contains(':') => token.rfind('@').map_or(0, |at| at + 1),
            None => 0,
        };
        rest = &tail[skip..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_userinfo() {
        assert_eq!(
            redact("push to https://x:ghp_secret@github.com/o/r.git now"),
            "push to https://github.com/o/r.git now"
        );
        assert_eq!(
            redact("https://tok@h/x and ssh://git@h:22/r"),
            "https://h/x and ssh://h:22/r"
        );
        assert_eq!(redact("no urls here"), "no urls here");
        assert_eq!(
            redact("url https://u:pa/ss@github.com/o/r.git, then"),
            "url https://github.com/o/r.git, then"
        );
        assert_eq!(
            redact("'https://u:a/b/c@h/x' and https://h:8443/x"),
            "'https://h/x' and https://h:8443/x"
        );
        assert_eq!(
            redact("see https://proxy/?to=https://u:p@h/x"),
            "see https://proxy/?to=https://h/x"
        );
    }

    #[test]
    fn report_redaction_covers_every_text() {
        let secret = "https://x:ghp_s/cret@github.com/o/r";
        let mut check = Check::new("x", "X", Kind::Boundary);
        check.detail = format!("detail {secret}");
        check.fix = Some(format!("fix {secret}"));
        let mut report = Report {
            version: JSON_VERSION,
            mezha: "0",
            hook_protocol: 1,
            platform: "linux",
            claude_code: None,
            mode: "full",
            probe: Some(format!("srt {secret}")),
            checks: vec![check],
            summary: Summary::default(),
            notes: vec![format!("note {secret}")],
        };
        report.redact();
        let json = report.to_json();
        assert!(!json.contains("ghp_s"), "{json}");
        assert!(!json.contains("cret"), "{json}");
        assert_eq!(report.checks[0].evidence, [STATIC]);
    }

    #[test]
    fn worst_status_wins() {
        let mut f = Findings::default();
        f.warn("a", None);
        f.fail("b", "fix b");
        f.warn("c", Some("fix c".into()));
        let check = f.into_check(Check::new("x", "X", Kind::Integrity), "fine");
        assert_eq!(check.status, Status::Fail);
        assert_eq!(check.detail, "a; b; c");
        assert_eq!(check.fix.as_deref(), Some("fix b fix c"));
        let clean = Findings::default().into_check(Check::new("x", "X", Kind::Integrity), "fine");
        assert_eq!(
            (clean.status, clean.detail.as_str()),
            (Status::Pass, "fine")
        );
    }
}
