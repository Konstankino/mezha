//! A gated command prefix such as `git push`.
//!
//! The same grammar guards both ends: the spec validates `permissions_ask`,
//! and the hook re-validates every `--gate` argument, because these words end
//! up inside a shell command that runs on every tool call. Words are
//! `[a-z0-9][a-z0-9._-]*`, so they never need quoting beyond `'...'`.

const MAX_WORDS: usize = 8;
const MAX_LEN: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPrefix {
    words: Vec<String>,
}

impl CommandPrefix {
    pub fn parse(text: &str) -> Result<Self, String> {
        let bad = || {
            format!(
                "`{text}` is not a command prefix: use up to {MAX_WORDS} words of lowercase \
                 letters, digits, `.`, `_` and `-`, separated by single spaces (like `git push`)"
            )
        };
        if text.is_empty() || text.len() > MAX_LEN {
            return Err(bad());
        }
        let words: Vec<String> = text.split(' ').map(str::to_string).collect();
        if words.len() > MAX_WORDS || !words.iter().all(|w| valid_word(w)) {
            return Err(bad());
        }
        Ok(CommandPrefix { words })
    }

    /// The program, such as `git`.
    pub fn program(&self) -> &str {
        &self.words[0]
    }

    /// The words after the program, such as `["push"]`.
    pub fn rest(&self) -> &[String] {
        &self.words[1..]
    }
}

fn valid_word(word: &str) -> bool {
    let mut chars = word.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c))
}

impl std::fmt::Display for CommandPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.words.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::CommandPrefix;

    #[test]
    fn parses_prefixes() {
        let p = CommandPrefix::parse("git push").unwrap();
        assert_eq!(p.program(), "git");
        assert_eq!(p.rest(), ["push"]);
        assert_eq!(p.to_string(), "git push");
        assert!(CommandPrefix::parse("rm").unwrap().rest().is_empty());
        assert!(CommandPrefix::parse("docker image push").is_ok());
        assert!(CommandPrefix::parse("npm publish").is_ok());
    }

    #[test]
    fn rejects_anything_that_needs_quoting() {
        for bad in [
            "",
            " git push",
            "git  push",
            "git push ",
            "Git push",
            "git 'push'",
            "git push; rm -rf /",
            "git $(push)",
            "git\tpush",
            "git push\n",
            "-rf",
            "a b c d e f g h i",
        ] {
            assert!(CommandPrefix::parse(bad).is_err(), "{bad:?}");
        }
    }
}
