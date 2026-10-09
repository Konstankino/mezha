//! The scope in an agent's `Bash(...)` tool, as the `agent-bash` hook
//! checks it: whole words, where `*` stands for one word in the middle, or
//! for any further words at the end (`cargo test *`, or the older
//! `cargo test:*`). Without a trailing `*` the command must match exactly.

/// A parsed `Bash(...)` scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BashPattern {
    words: Vec<String>,
    /// A trailing `*`: any further words.
    rest: bool,
}

/// Characters a pattern word may not hold: they would need quoting in the
/// hook command or mean something to the shell.
const SPECIAL: &[char] = &[
    '\'', '"', '\\', '`', '$', '(', ')', '{', '}', ';', '&', '|', '<', '>', '#', '!', '~', '?',
    '[', ']',
];

impl BashPattern {
    pub fn parse(scope: &str) -> Result<BashPattern, String> {
        let scope = scope.trim();
        let scope = scope
            .strip_suffix(":*")
            .map_or(scope.to_string(), |s| format!("{s} *"));
        let mut words: Vec<String> = scope.split_whitespace().map(str::to_string).collect();
        let rest = words.last().is_some_and(|w| w == "*");
        if rest {
            words.pop();
        }
        let Some(program) = words.first() else {
            return Err("names no command".into());
        };
        if program == "*" {
            return Err("starts with `*`, which would allow any program".into());
        }
        if program.contains('=') {
            return Err(format!(
                "`{program}` is an environment assignment, not a program"
            ));
        }
        for word in &words {
            if word != "*" && word.contains('*') {
                return Err(format!(
                    "`{word}`: `*` stands only for whole words, such as `cargo test *`"
                ));
            }
            if let Some(c) = word.chars().find(|c| SPECIAL.contains(c) || c.is_control()) {
                return Err(format!(
                    "`{word}` holds `{c}`, which the shell treats specially"
                ));
            }
        }
        Ok(BashPattern { words, rest })
    }

    /// Whether a simple command's words match: the program exactly as
    /// written (`./x.sh` is not `x.sh`), then each word, `*` for any one.
    pub fn matches(&self, command: &[&str]) -> bool {
        if command.len() < self.words.len() || (!self.rest && command.len() != self.words.len()) {
            return false;
        }
        self.words
            .iter()
            .zip(command)
            .all(|(want, got)| want == "*" || want == got)
    }
}

impl std::fmt::Display for BashPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.words.join(" "))?;
        if self.rest {
            write!(f, " *")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> BashPattern {
        BashPattern::parse(s).unwrap()
    }

    #[test]
    fn patterns() {
        assert_eq!(p("cargo test *").to_string(), "cargo test *");
        assert_eq!(p("cargo test:*"), p("cargo test *"));
        assert!(p("cargo test *").matches(&["cargo", "test"]));
        assert!(p("cargo test *").matches(&["cargo", "test", "--release"]));
        assert!(!p("cargo test *").matches(&["cargo", "build"]));
        assert!(!p("cargo test *").matches(&["/usr/bin/cargo", "test"]));
        assert!(p("cargo fmt --check").matches(&["cargo", "fmt", "--check"]));
        assert!(!p("cargo fmt --check").matches(&["cargo", "fmt", "--check", "-v"]));
        assert!(p("git * main").matches(&["git", "push", "main"]));
        assert!(!p("git * main").matches(&["git", "main"]));
        assert!(p("./scripts/check.sh *").matches(&["./scripts/check.sh", "a"]));
        assert!(!p("./scripts/check.sh *").matches(&["scripts/check.sh", "a"]));
        for bad in [
            "",
            "*",
            "* x",
            "cargo te*t",
            "FOO=1 cargo",
            "echo $HOME",
            "it's",
            "a;b",
        ] {
            assert!(BashPattern::parse(bad).is_err(), "{bad}");
        }
    }
}
