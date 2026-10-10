//! Agent tool entries (`Read`, `Bash(cargo test *)`, `Agent(explorer)`) and
//! the strings that end up in rendered frontmatter.

/// Claude Code's built-in tools, for a warning on names it wouldn't know.
/// MCP tools (`mcp__server__tool`) are always accepted.
pub const KNOWN_TOOLS: [&str; 26] = [
    "Agent",
    "AskUserQuestion",
    "Bash",
    "Edit",
    "EnterPlanMode",
    "ExitPlanMode",
    "Glob",
    "Grep",
    "LSP",
    "ListMcpResourcesTool",
    "Monitor",
    "MultiEdit",
    "NotebookEdit",
    "PowerShell",
    "Read",
    "ReadMcpResourceTool",
    "SendMessage",
    "Skill",
    "Task",
    "TodoWrite",
    "ToolSearch",
    "WebFetch",
    "WebSearch",
    "Workflow",
    "Write",
    "KillShell",
];

/// `Name` or `Name(specifier)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolEntry<'a> {
    pub name: &'a str,
    pub specifier: Option<&'a str>,
}

/// Splits a tool entry; `None` when the parentheses don't close.
pub fn parse_tool(entry: &str) -> Option<ToolEntry<'_>> {
    let entry = entry.trim();
    match entry.split_once('(') {
        None => Some(ToolEntry {
            name: entry,
            specifier: None,
        }),
        Some((name, rest)) => Some(ToolEntry {
            name: name.trim(),
            specifier: Some(rest.strip_suffix(')')?.trim()),
        }),
    }
}

/// Why `text` can't go into YAML frontmatter, if it can't. Claude Code ends
/// the frontmatter block at the first `---` anywhere, and YAML forbids some
/// characters that JSON escaping leaves raw (DEL, C1 controls, U+2028/2029,
/// U+FFFE/FFFF). Other control characters are escaped, but nothing in a
/// one-line field needs them. Hidden characters would let a description say
/// one thing to a reviewer and another to Claude (OWASP AST04).
pub fn frontmatter_problem(text: &str) -> Option<&'static str> {
    if text.contains("---") {
        return Some("contains `---`, which ends Claude Code's frontmatter early");
    }
    if text
        .chars()
        .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}' | '\u{fffe}' | '\u{ffff}'))
    {
        return Some("contains a control character or a line or paragraph separator");
    }
    if hidden_char(text).is_some() {
        return Some("contains a hidden character (zero-width, bidi control or tag character)");
    }
    None
}

/// Characters that render as nothing (or reorder text) and so can hide
/// words from a reviewer.
pub fn is_hidden(c: char) -> bool {
    matches!(c,
        '\u{00ad}' | '\u{061c}' | '\u{180e}'
        | '\u{200b}'..='\u{200f}'
        | '\u{2028}'..='\u{202e}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{2069}'
        | '\u{feff}'
        | '\u{e0000}'..='\u{e007f}')
}

/// Characters a zero-width joiner may legitimately join.
pub fn is_emoji(c: char) -> bool {
    matches!(c, '\u{1f000}'..='\u{1faff}' | '\u{2600}'..='\u{27bf}' | '\u{fe0f}')
}

/// The first hidden character in `text` and its byte offset. A zero-width
/// joiner between two emoji is how emoji combine, so it doesn't count.
pub fn hidden_char(text: &str) -> Option<(usize, char)> {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    chars.iter().enumerate().find_map(|(i, &(at, c))| {
        let joins_emoji = c == '\u{200d}'
            && i > 0
            && is_emoji(chars[i - 1].1)
            && chars.get(i + 1).is_some_and(|&(_, n)| is_emoji(n));
        (is_hidden(c) && !joins_emoji).then_some((at, c))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_entries() {
        assert_eq!(
            parse_tool(" Bash(cargo test *) "),
            Some(ToolEntry {
                name: "Bash",
                specifier: Some("cargo test *")
            })
        );
        assert_eq!(
            parse_tool("Read"),
            Some(ToolEntry {
                name: "Read",
                specifier: None
            })
        );
        assert_eq!(parse_tool("Bash(cargo"), None);
    }

    #[test]
    fn frontmatter_strings() {
        assert!(frontmatter_problem("Use when: writing # Rust, \"quoted\" & *star*").is_none());
        assert!(frontmatter_problem("a --- b").is_some());
        assert!(frontmatter_problem("line\nbreak").is_some());
        assert!(frontmatter_problem("del\u{7f}").is_some());
        assert!(frontmatter_problem("c1\u{85}").is_some());
        assert!(frontmatter_problem("sep\u{2028}").is_some());
        assert!(frontmatter_problem("українська мова ✓").is_none());
        assert!(frontmatter_problem("zero\u{200b}width").is_some());
        assert!(frontmatter_problem("bidi \u{202e}x").is_some());
        assert!(frontmatter_problem("tag \u{e0041}").is_some());
        assert!(frontmatter_problem("family 👨\u{200d}👩").is_none());
    }
}
