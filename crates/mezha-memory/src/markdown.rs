//! The bits of Markdown mezha reads in agents' final messages: a section
//! under a given heading (`## Lessons`, `## Unresolved`) and its items.

/// The body of the **last** section titled `name` (any heading level, any
/// case, an optional trailing colon), up to the next heading of the same
/// or a higher level. Headings inside fenced code don't count.
pub fn heading_section(text: &str, name: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut fence: Option<String> = None;
    let mut headings: Vec<(usize, usize, bool)> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        let ticks = trimmed
            .chars()
            .take_while(|c| *c == '`' || *c == '~')
            .count();
        if ticks >= 3 {
            let marker: String = trimmed.chars().take(ticks).collect();
            match &fence {
                Some(open) if marker.starts_with(open.as_str()) => fence = None,
                Some(_) => {}
                None => fence = Some(marker),
            }
            continue;
        }
        if fence.is_some() {
            continue;
        }
        let level = line.chars().take_while(|c| *c == '#').count();
        if (1..=6).contains(&level) && line[level..].starts_with([' ', '\t']) {
            let title = line[level..].trim().trim_end_matches(':').trim();
            headings.push((i, level, title.eq_ignore_ascii_case(name)));
        }
    }
    let (start, level) = headings
        .iter()
        .rev()
        .find(|(_, _, wanted)| *wanted)
        .map(|&(i, level, _)| (i, level))?;
    let end = headings
        .iter()
        .find(|&&(i, l, _)| i > start && l <= level)
        .map_or(lines.len(), |&(i, _, _)| i);
    let body = lines[start + 1..end].join("\n").trim().to_string();
    (!body.is_empty()).then_some(body)
}

/// How many things a section lists: its list items, or 1 for plain text.
/// "None", "n/a" and the like count as nothing.
pub fn item_count(section: &str) -> usize {
    let none = |s: &str| {
        let s = s
            .trim()
            .trim_end_matches('.')
            .trim_matches(|c| c == '*' || c == '_')
            .to_ascii_lowercase();
        matches!(
            s.as_str(),
            "" | "none" | "n/a" | "na" | "nothing" | "-" | "no"
        )
    };
    let items: Vec<&str> = section
        .lines()
        .map(str::trim)
        .filter_map(|l| {
            l.strip_prefix("- ")
                .or_else(|| l.strip_prefix("* "))
                .or_else(|| l.strip_prefix("+ "))
                .or_else(|| {
                    let digits = l.chars().take_while(char::is_ascii_digit).count();
                    (digits > 0)
                        .then(|| {
                            l[digits..]
                                .strip_prefix(". ")
                                .or(l[digits..].strip_prefix(") "))
                        })
                        .flatten()
                })
        })
        .collect();
    if items.is_empty() {
        return usize::from(!none(section));
    }
    items.iter().filter(|i| !none(i)).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections() {
        let text = "Done.\n\n## Lessons\n\n- run `cargo fmt` first\n\n## Next\nmore";
        assert_eq!(
            heading_section(text, "lessons").as_deref(),
            Some("- run `cargo fmt` first")
        );
        assert_eq!(
            heading_section("### lessons:\n- a\n#### detail\n- b", "Lessons").as_deref(),
            Some("- a\n#### detail\n- b")
        );
        assert_eq!(heading_section("no heading", "Lessons"), None);
        assert_eq!(heading_section("## Lessons\n\n## Other", "Lessons"), None);
        // The last section wins; headings in code don't count.
        let text = "## Unresolved\n- old\n\n```md\n## Unresolved\n- in code\n```\n\n## Unresolved\n- new\n";
        assert_eq!(
            heading_section(text, "Unresolved").as_deref(),
            Some("- new")
        );
        assert_eq!(heading_section("#Unresolved\n- x", "Unresolved"), None);
    }

    #[test]
    fn a_fence_closes_only_with_its_own_marker() {
        // The `~~~` inside the backtick fence doesn't close it, so the first
        // heading is still code.
        let text = "```\n~~~\n## Lessons\n- inside\n```\n\n## Lessons\n- outside\n";
        assert_eq!(
            heading_section(text, "Lessons").as_deref(),
            Some("- outside")
        );
        assert_eq!(
            heading_section("~~~\n```\n## Lessons\n- in code\n", "Lessons"),
            None
        );
    }

    #[test]
    fn items() {
        assert_eq!(item_count("- a\n- b\n  more\n1. c"), 3);
        assert_eq!(item_count("None."), 0);
        assert_eq!(item_count("- None"), 0);
        assert_eq!(item_count("- n/a\n- real thing"), 1);
        assert_eq!(item_count("The migration test is flaky."), 1);
        assert_eq!(item_count("**Nothing**"), 0);
    }
}
