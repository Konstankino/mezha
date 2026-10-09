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
/// one-line field needs them.
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
    None
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
    }
}
