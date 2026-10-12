//! YAML frontmatter for agents, skills and rules, written without
//! hand-built quoting: every scalar is a JSON string, number or boolean
//! (JSON scalars are valid YAML), and collections are block style, the form
//! Claude Code's parser handles best.
//!
//! Claude Code ends the frontmatter at the first `---` anywhere, and a file
//! whose frontmatter doesn't parse loses it all, so [`write`] refuses text
//! that contains `---` or characters YAML forbids raw.

use serde_json::Value;

/// Frontmatter from ordered `(key, value)` pairs; `Null` values are left
/// out. Keys are mezha's own and must be plain.
pub fn write(fields: &[(&str, Value)]) -> Result<String, String> {
    let mut out = String::new();
    for (key, value) in fields {
        if !value.is_null() {
            entry(&mut out, 0, key, value)?;
        }
    }
    if out.contains("---") {
        return Err("a frontmatter value contains `---`".into());
    }
    if let Some(c) = out.chars().find(|c| {
        (c.is_control() && *c != '\n')
            || matches!(c, '\u{2028}' | '\u{2029}' | '\u{fffe}' | '\u{ffff}')
    }) {
        return Err(format!("a frontmatter value contains U+{:04X}", c as u32));
    }
    Ok(format!("---\n{out}---\n"))
}

fn plain_key(key: &str) -> Result<(), String> {
    if !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        Ok(())
    } else {
        Err(format!("`{key}` isn't a plain frontmatter key"))
    }
}

fn scalar(value: &Value) -> String {
    serde_json::to_string(value).expect("scalars serialize")
}

fn entry(out: &mut String, indent: usize, key: &str, value: &Value) -> Result<(), String> {
    plain_key(key)?;
    let pad = " ".repeat(indent);
    match value {
        Value::Array(items) if items.is_empty() => out.push_str(&format!("{pad}{key}: []\n")),
        Value::Object(map) if map.is_empty() => out.push_str(&format!("{pad}{key}: {{}}\n")),
        Value::Array(items) => {
            out.push_str(&format!("{pad}{key}:\n"));
            for item in items {
                sequence_item(out, indent + 2, item)?;
            }
        }
        Value::Object(map) => {
            out.push_str(&format!("{pad}{key}:\n"));
            for (k, v) in map {
                entry(out, indent + 2, k, v)?;
            }
        }
        _ => out.push_str(&format!("{pad}{key}: {}\n", scalar(value))),
    }
    Ok(())
}

fn sequence_item(out: &mut String, indent: usize, item: &Value) -> Result<(), String> {
    let pad = " ".repeat(indent);
    match item {
        Value::Object(map) if !map.is_empty() => {
            // The first key shares the line with the dash.
            let mut block = String::new();
            for (k, v) in map {
                entry(&mut block, indent + 2, k, v)?;
            }
            out.push_str(&pad);
            out.push_str("- ");
            out.push_str(&block[indent + 2..]);
        }
        Value::Array(_) | Value::Object(_) => {
            return Err("nested lists aren't used in frontmatter".into());
        }
        _ => out.push_str(&format!("{pad}- {}\n", scalar(item))),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn block_style_with_json_scalars() {
        let text = write(&[
            ("name", json!("probe")),
            ("description", json!("Use when: \"quoted\" # not a comment, *star*, & anchor")),
            ("tools", json!(["Read", "Bash"])),
            ("maxTurns", json!(6)),
            ("skills", json!([])),
            ("model", Value::Null),
            (
                "hooks",
                json!({"PreToolUse": [{"matcher": "Bash|Monitor", "hooks": [{"type": "command", "command": "mezha hook x || exit 2"}]}]}),
            ),
        ])
        .unwrap();
        assert_eq!(
            text,
            r#"---
name: "probe"
description: "Use when: \"quoted\" # not a comment, *star*, & anchor"
tools:
  - "Read"
  - "Bash"
maxTurns: 6
skills: []
hooks:
  PreToolUse:
    - hooks:
        - command: "mezha hook x || exit 2"
          type: "command"
      matcher: "Bash|Monitor"
---
"#
        );
    }

    #[test]
    fn refuses_collections_nested_in_a_list() {
        for nested in [json!([[1]]), json!([{}]), json!([{"a": [[1]]}])] {
            let err = write(&[("x", nested.clone())]).unwrap_err();
            assert_eq!(err, "nested lists aren't used in frontmatter", "{nested}");
        }
        assert_eq!(write(&[("x", json!({}))]).unwrap(), "---\nx: {}\n---\n");
    }

    #[test]
    fn refuses_what_would_break_the_block() {
        assert!(write(&[("description", json!("a --- b"))]).is_err());
        assert!(write(&[("description", json!("sep\u{2028}"))]).is_err());
        assert!(write(&[("description", json!("del\u{7f}"))]).is_err());
        assert!(write(&[("bad key", json!("x"))]).is_err());
        // Newlines and other C0 controls are escaped by JSON.
        let ok = write(&[("description", json!("two\nlines\ttab"))]).unwrap();
        assert!(ok.contains(r#""two\nlines\ttab""#), "{ok}");
    }
}
