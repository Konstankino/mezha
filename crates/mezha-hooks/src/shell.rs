//! A small POSIX-shell reader: just enough to tell which words each simple
//! command has, so the matcher can find the programs a command line runs.
//!
//! It understands quotes, escapes, line continuations, separators,
//! comments, redirections, `$(...)`, backticks, process substitution and
//! heredocs. Command substitutions are read as nested command lines, and
//! their commands join the output. Words whose value is only known at run
//! time (`$VAR`, `$(...)`, globs) are marked `dynamic`. This is not a
//! security boundary: it only has to be right for the commands an agent
//! usually writes, and to fail loudly on the rest.

/// Nesting deeper than this is refused rather than read.
pub const MAX_DEPTH: usize = 8;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Word {
    /// The value with quotes and escapes removed; expansions add nothing.
    pub text: String,
    /// Part of the value is only known at run time.
    pub dynamic: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Heredoc {
    /// The delimiter was quoted, so the body is not expanded, or the text
    /// came from a here-string.
    pub quoted: bool,
    pub body: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Command {
    pub words: Vec<Word>,
    pub heredocs: Vec<Heredoc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// A quote, substitution or other construct never ends.
    Unterminated(&'static str),
    /// Nested beyond [`MAX_DEPTH`].
    TooDeep,
}

/// Reads `src` into its simple commands, including those inside command
/// substitutions. `depth` counts how far inside other command lines `src`
/// already is.
pub fn parse(src: &str, depth: usize) -> Result<Vec<Command>, ParseError> {
    let mut parser = Parser {
        chars: src.chars().collect(),
        pos: 0,
        out: Vec::new(),
        pending: Vec::new(),
    };
    parser.list(None, depth)?;
    Ok(parser.out)
}

/// A heredoc whose body starts after the next newline.
struct Pending {
    command: usize,
    doc: usize,
    delimiter: String,
    strip_tabs: bool,
}

#[derive(Default, PartialEq, Eq)]
enum Next {
    #[default]
    Word,
    /// The next word is a redirection target, not an argument.
    Drop,
    /// The next word is a here-string's text.
    HereString,
}

#[derive(Default)]
struct Building {
    word: Option<Word>,
    words: Vec<Word>,
    heredocs: Vec<Heredoc>,
    /// Heredocs of this command: (delimiter, strip_tabs, index in heredocs).
    pending: Vec<(String, bool, usize)>,
    next: Next,
}

impl Building {
    fn word(&mut self) -> &mut Word {
        self.word.get_or_insert_with(Word::default)
    }

    fn end_word(&mut self) {
        if let Some(word) = self.word.take() {
            match std::mem::take(&mut self.next) {
                Next::Word => self.words.push(word),
                Next::Drop => {}
                Next::HereString => self.heredocs.push(Heredoc {
                    quoted: true,
                    body: word.text,
                }),
            }
        }
    }
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
    out: Vec<Command>,
    pending: Vec<Pending>,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    /// A command list, up to the end of input or, inside `$(`, its `)`.
    fn list(&mut self, close: Option<char>, depth: usize) -> Result<(), ParseError> {
        if depth > MAX_DEPTH {
            return Err(ParseError::TooDeep);
        }
        let mut cmd = Building::default();
        let mut parens = 0usize;
        loop {
            let Some(c) = self.peek() else {
                if close.is_some() {
                    return Err(ParseError::Unterminated("$("));
                }
                self.end_command(&mut cmd);
                return Ok(());
            };
            match c {
                '\\' if self.peek_at(1) == Some('\n') => self.pos += 2,
                ' ' | '\t' | '\r' => {
                    self.pos += 1;
                    cmd.end_word();
                }
                '\n' => {
                    self.pos += 1;
                    self.end_command(&mut cmd);
                    self.heredoc_bodies();
                }
                '&' if self.peek_at(1) == Some('>') => {
                    self.pos += 1;
                    self.redirect(&mut cmd, depth)?;
                }
                ';' | '|' | '&' => {
                    self.pos += 1;
                    self.end_command(&mut cmd);
                }
                '(' => {
                    self.pos += 1;
                    self.end_command(&mut cmd);
                    parens += 1;
                }
                ')' => {
                    self.pos += 1;
                    self.end_command(&mut cmd);
                    if parens > 0 {
                        parens -= 1;
                    } else if close == Some(')') {
                        return Ok(());
                    }
                }
                '<' | '>' => self.redirect(&mut cmd, depth)?,
                '#' if cmd.word.is_none() => {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.pos += 1;
                    }
                }
                _ => self.word_part(&mut cmd, depth)?,
            }
        }
    }

    fn end_command(&mut self, cmd: &mut Building) {
        cmd.end_word();
        let built = std::mem::take(cmd);
        if built.words.is_empty() && built.heredocs.is_empty() {
            return;
        }
        let index = self.out.len();
        for (delimiter, strip_tabs, doc) in built.pending {
            self.pending.push(Pending {
                command: index,
                doc,
                delimiter,
                strip_tabs,
            });
        }
        self.out.push(Command {
            words: built.words,
            heredocs: built.heredocs,
        });
    }

    /// Reads the bodies of the heredocs started on the line just ended. A
    /// missing delimiter ends the body at the end of input, as bash does.
    fn heredoc_bodies(&mut self) {
        for p in std::mem::take(&mut self.pending) {
            let mut body = String::new();
            while self.peek().is_some() {
                let mut line = String::new();
                while let Some(c) = self.bump() {
                    if c == '\n' {
                        break;
                    }
                    line.push(c);
                }
                let line = if p.strip_tabs {
                    line.trim_start_matches('\t').to_string()
                } else {
                    line
                };
                if line == p.delimiter {
                    break;
                }
                body.push_str(&line);
                body.push('\n');
            }
            if let Some(doc) = self
                .out
                .get_mut(p.command)
                .and_then(|c| c.heredocs.get_mut(p.doc))
            {
                doc.body = body;
            }
        }
    }

    fn redirect(&mut self, cmd: &mut Building, depth: usize) -> Result<(), ParseError> {
        // `2>file`: the digits are a file descriptor, not an argument.
        if cmd.word.as_ref().is_some_and(|w| {
            !w.dynamic && !w.text.is_empty() && w.text.bytes().all(|b| b.is_ascii_digit())
        }) {
            cmd.word = None;
        }
        cmd.end_word();
        let op = self.bump();
        if op == Some('<') && self.peek() == Some('<') {
            self.pos += 1;
            if self.peek() == Some('<') {
                self.pos += 1;
                cmd.next = Next::HereString;
                return Ok(());
            }
            let strip_tabs = self.peek() == Some('-');
            if strip_tabs {
                self.pos += 1;
            }
            while matches!(self.peek(), Some(' ' | '\t')) {
                self.pos += 1;
            }
            let (delimiter, quoted) = self.heredoc_delimiter()?;
            cmd.heredocs.push(Heredoc {
                quoted,
                body: String::new(),
            });
            cmd.pending
                .push((delimiter, strip_tabs, cmd.heredocs.len() - 1));
            return Ok(());
        }
        if self.peek() == Some('(') {
            // Process substitution: `<(cmd)` or `>(cmd)` runs `cmd`.
            self.pos += 1;
            return self.list(Some(')'), depth + 1);
        }
        if matches!(self.peek(), Some('>' | '&' | '|')) {
            self.pos += 1;
        }
        cmd.next = Next::Drop;
        Ok(())
    }

    /// The word after `<<`: any quoting makes the heredoc literal.
    fn heredoc_delimiter(&mut self) -> Result<(String, bool), ParseError> {
        let mut delimiter = String::new();
        let mut quoted = false;
        while let Some(c) = self.peek() {
            if c.is_whitespace() || ";&|<>()".contains(c) {
                break;
            }
            self.pos += 1;
            match c {
                '\'' | '"' => {
                    quoted = true;
                    loop {
                        match self.bump() {
                            Some(q) if q == c => break,
                            Some(x) => delimiter.push(x),
                            None => return Err(ParseError::Unterminated("<<")),
                        }
                    }
                }
                '\\' => {
                    quoted = true;
                    if let Some(x) = self.bump() {
                        delimiter.push(x);
                    }
                }
                _ => delimiter.push(c),
            }
        }
        if delimiter.is_empty() {
            return Err(ParseError::Unterminated("<<"));
        }
        Ok((delimiter, quoted))
    }

    fn word_part(&mut self, cmd: &mut Building, depth: usize) -> Result<(), ParseError> {
        let Some(c) = self.bump() else {
            return Ok(());
        };
        match c {
            '\\' => {
                if let Some(x) = self.bump() {
                    cmd.word().text.push(x);
                }
            }
            '\'' => {
                let word = cmd.word();
                loop {
                    match self.bump() {
                        Some('\'') => break,
                        Some(x) => word.text.push(x),
                        None => return Err(ParseError::Unterminated("'")),
                    }
                }
            }
            '"' => self.double_quoted(cmd, depth)?,
            '$' => self.dollar(cmd, depth)?,
            '`' => self.backtick(cmd, depth)?,
            '*' | '?' | '[' => {
                let word = cmd.word();
                word.text.push(c);
                word.dynamic = true;
            }
            _ => cmd.word().text.push(c),
        }
        Ok(())
    }

    fn double_quoted(&mut self, cmd: &mut Building, depth: usize) -> Result<(), ParseError> {
        cmd.word();
        loop {
            match self.bump() {
                None => return Err(ParseError::Unterminated("\"")),
                Some('"') => return Ok(()),
                Some('\\') => match self.peek() {
                    Some(x @ ('$' | '`' | '"' | '\\')) => {
                        self.pos += 1;
                        cmd.word().text.push(x);
                    }
                    Some('\n') => self.pos += 1,
                    _ => cmd.word().text.push('\\'),
                },
                Some('$') => self.dollar(cmd, depth)?,
                Some('`') => self.backtick(cmd, depth)?,
                Some(x) => cmd.word().text.push(x),
            }
        }
    }

    /// After a `$`: a substitution, an expansion, or a plain dollar sign.
    fn dollar(&mut self, cmd: &mut Building, depth: usize) -> Result<(), ParseError> {
        match self.peek() {
            Some('(') if self.peek_at(1) == Some('(') => {
                self.pos += 2;
                let mut open = 2usize;
                while open > 0 {
                    match self.bump() {
                        Some('(') => open += 1,
                        Some(')') => open -= 1,
                        Some(_) => {}
                        None => return Err(ParseError::Unterminated("$((")),
                    }
                }
                cmd.word().dynamic = true;
            }
            Some('(') => {
                self.pos += 1;
                cmd.word().dynamic = true;
                self.list(Some(')'), depth + 1)?;
            }
            Some('{') => {
                self.pos += 1;
                let mut open = 1usize;
                while open > 0 {
                    match self.bump() {
                        Some('{') => open += 1,
                        Some('}') => open -= 1,
                        Some(_) => {}
                        None => return Err(ParseError::Unterminated("${")),
                    }
                }
                cmd.word().dynamic = true;
            }
            Some('\'') => {
                // ANSI-C quoting: escapes such as \x70 can spell anything.
                self.pos += 1;
                let word = cmd.word();
                word.dynamic = true;
                loop {
                    match self.bump() {
                        Some('\'') => break,
                        Some('\\') => {
                            if let Some(x) = self.bump() {
                                word.text.push(x);
                            }
                        }
                        Some(x) => word.text.push(x),
                        None => return Err(ParseError::Unterminated("$'")),
                    }
                }
            }
            Some('"') => {
                self.pos += 1;
                self.double_quoted(cmd, depth)?;
            }
            Some(c) if c.is_ascii_alphanumeric() || c == '_' => {
                while self
                    .peek()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    self.pos += 1;
                }
                cmd.word().dynamic = true;
            }
            Some('@' | '*' | '#' | '?' | '$' | '!' | '-') => {
                self.pos += 1;
                cmd.word().dynamic = true;
            }
            _ => cmd.word().text.push('$'),
        }
        Ok(())
    }

    fn backtick(&mut self, cmd: &mut Building, depth: usize) -> Result<(), ParseError> {
        let mut inner = String::new();
        loop {
            match self.bump() {
                None => return Err(ParseError::Unterminated("`")),
                Some('`') => break,
                Some('\\') => match self.peek() {
                    Some(x @ ('`' | '\\' | '$')) => {
                        self.pos += 1;
                        inner.push(x);
                    }
                    _ => inner.push('\\'),
                },
                Some(x) => inner.push(x),
            }
        }
        cmd.word().dynamic = true;
        let nested = parse(&inner, depth + 1)?;
        self.out.extend(nested);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(src: &str) -> Vec<Vec<String>> {
        parse(src, 0)
            .unwrap()
            .into_iter()
            .map(|c| c.words.into_iter().map(|w| w.text).collect())
            .collect()
    }

    #[test]
    fn splits_commands_and_words() {
        assert_eq!(
            words("cd x && git push origin main; echo 'a b' | wc"),
            [
                vec!["cd", "x"],
                vec!["git", "push", "origin", "main"],
                vec!["echo", "a b"],
                vec!["wc"]
            ]
        );
        assert_eq!(words("a\\\n b"), [vec!["a", "b"]]);
        assert_eq!(words("git \\\n  push"), [vec!["git", "push"]]);
        assert_eq!(
            words("echo \"x\\\"y\" z#q # comment"),
            [vec!["echo", "x\"y", "z#q"]]
        );
    }

    #[test]
    fn drops_redirection_targets() {
        assert_eq!(
            words("make 2>&1 >build.log < in.txt &>/dev/null"),
            [vec!["make"]]
        );
        assert_eq!(words("echo hi > push"), [vec!["echo", "hi"]]);
    }

    #[test]
    fn substitutions_are_read_as_commands() {
        let cmds = parse("echo \"$(git rev-parse HEAD)\" `date`", 0).unwrap();
        let firsts: Vec<_> = cmds.iter().map(|c| c.words[0].text.as_str()).collect();
        assert_eq!(firsts, ["git", "date", "echo"]);
        let echo = cmds.iter().find(|c| c.words[0].text == "echo").unwrap();
        assert!(echo.words[1].dynamic);
    }

    #[test]
    fn heredocs_are_kept_apart() {
        let src = "git commit -m \"$(cat <<'EOF'\nDon't push yet\nEOF\n)\"\n";
        let cmds = parse(src, 0).unwrap();
        let cat = cmds.iter().find(|c| c.words[0].text == "cat").unwrap();
        assert_eq!(
            cat.heredocs,
            [Heredoc {
                quoted: true,
                body: "Don't push yet\n".into()
            }]
        );
        let git = cmds.iter().find(|c| c.words[0].text == "git").unwrap();
        assert_eq!(git.words.len(), 4);

        let cmds = parse("cat <<-END | sh\n\tgit push\n\tEND\necho done", 0).unwrap();
        assert_eq!(cmds[0].heredocs[0].body, "git push\n");
        assert!(!cmds[0].heredocs[0].quoted);
        assert_eq!(cmds[2].words[0].text, "echo");
    }

    #[test]
    fn marks_dynamic_words() {
        let cmds = parse("$x push *.rs ${y} plain", 0).unwrap();
        let dynamic: Vec<bool> = cmds[0].words.iter().map(|w| w.dynamic).collect();
        assert_eq!(dynamic, [true, false, true, true, false]);
    }

    #[test]
    fn reports_unterminated_input() {
        assert_eq!(parse("echo 'x", 0), Err(ParseError::Unterminated("'")));
        assert_eq!(parse("echo \"x", 0), Err(ParseError::Unterminated("\"")));
        assert_eq!(parse("echo $(x", 0), Err(ParseError::Unterminated("$(")));
        assert_eq!(parse("echo `x", 0), Err(ParseError::Unterminated("`")));
    }

    #[test]
    fn refuses_deep_nesting() {
        let deep = "$(".repeat(MAX_DEPTH + 1) + "x" + &")".repeat(MAX_DEPTH + 1);
        assert_eq!(parse(&deep, 0), Err(ParseError::TooDeep));
        let ok = "$(".repeat(MAX_DEPTH) + "x" + &")".repeat(MAX_DEPTH);
        assert!(parse(&ok, 0).is_ok());
    }
}
