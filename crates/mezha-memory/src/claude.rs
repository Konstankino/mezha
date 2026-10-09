//! What mezha reads back from a headless `claude -p`: its version and the
//! `result` event, shared by the dreamer and the A/B runner.

use serde_json::Value;

/// The oldest Claude Code mezha's headless runs were checked against.
pub const MIN_CLAUDE_CODE: (u32, u32, u32) = (2, 1, 285);

/// Variables Claude Code sets for its own processes: a child `claude` must
/// not think it runs inside a session.
pub const ENV_REMOVE: [&str; 2] = ["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"];

/// The end of a run, from the `result` event. Cost and turns are kept even
/// when the run failed: a run that hit its budget still spent it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Outcome {
    pub summary: String,
    pub turns: u64,
    pub cost_usd: f64,
    pub denials: Vec<String>,
    pub subtype: String,
    /// Why the run didn't succeed, if it didn't.
    pub failure: Option<String>,
}

/// Reads a `result` event. A run that didn't succeed has a `failure`,
/// whatever the subtype says: Claude Code reports a failed login as
/// `success` with `is_error: true`.
pub fn read_outcome(event: &Value) -> Outcome {
    let subtype = event
        .get("subtype")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let is_error = event.get("is_error").and_then(Value::as_bool) != Some(false);
    let summary = event
        .get("result")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let failure = (subtype != "success" || is_error).then(|| {
        let mut why = match subtype.as_str() {
            "error_max_turns" => "it ran out of turns".to_string(),
            "error_max_budget_usd" => "it reached its budget".to_string(),
            "" => "it reported no result".to_string(),
            other => format!("it ended with {other}"),
        };
        if let Some(reason) = event.get("terminal_reason").and_then(Value::as_str) {
            why.push_str(&format!(" ({reason})"));
        }
        let errors: Vec<&str> = event
            .get("errors")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if !errors.is_empty() {
            why.push_str(&format!(": {}", crate::scan::escape(&errors.join("; "))));
        }
        if !summary.is_empty() {
            why.push_str(&format!(
                ": {}",
                crate::scan::escape(&crate::inbox::cut(&summary, 300))
            ));
        }
        why
    });
    let denials = event
        .get("permission_denials")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|d| {
            let tool = d.get("tool_name").and_then(Value::as_str).unwrap_or("?");
            let input = d
                .get("tool_input")
                .map(Value::to_string)
                .unwrap_or_default();
            format!("{tool} {}", crate::inbox::cut(&input, 200))
        })
        .collect();
    Outcome {
        summary,
        turns: event.get("num_turns").and_then(Value::as_u64).unwrap_or(0),
        cost_usd: event
            .get("total_cost_usd")
            .and_then(Value::as_f64)
            .unwrap_or(0.0),
        denials,
        subtype,
        failure,
    }
}

/// [`read_outcome`] for callers that stop on failure.
pub fn read_result(event: &Value) -> Result<Outcome, String> {
    let outcome = read_outcome(event);
    match &outcome.failure {
        Some(why) => Err(why.clone()),
        None => Ok(outcome),
    }
}

/// `2.1.285 (Claude Code)` as numbers.
pub fn parse_version(text: &str) -> Option<(u32, u32, u32)> {
    let word = text.split_whitespace().next()?;
    let mut parts = word.split('.').map(|p| p.parse::<u32>().ok());
    Some((parts.next()??, parts.next()??, parts.next()??))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn results() {
        let failed_login = json!({"type": "result", "subtype": "success", "is_error": true,
            "terminal_reason": "api_error", "result": "Failed to authenticate"});
        let e = read_result(&failed_login).unwrap_err();
        assert!(
            e.contains("api_error") && e.contains("Failed to authenticate"),
            "{e}"
        );
        // As Claude Code 2.1.285 reports a spent budget; the cost survives.
        let spent = json!({"subtype": "error_max_budget_usd", "is_error": true,
            "terminal_reason": "budget_exhausted", "errors": ["Reached maximum budget ($0.0001)"],
            "num_turns": 3, "total_cost_usd": 0.028});
        assert_eq!(
            read_result(&spent).unwrap_err(),
            "it reached its budget (budget_exhausted): Reached maximum budget ($0.0001)"
        );
        let outcome = read_outcome(&spent);
        assert_eq!((outcome.turns, outcome.cost_usd), (3, 0.028));
        assert_eq!(outcome.subtype, "error_max_budget_usd");
        let ok = read_result(
            &json!({"subtype": "success", "is_error": false, "result": "no changes",
            "num_turns": 3, "total_cost_usd": 0.12,
            "permission_denials": [{"tool_name": "Write", "tool_input": {"file_path": "/etc/x"}}]}),
        )
        .unwrap();
        assert_eq!(ok.turns, 3);
        assert_eq!(ok.denials, [r#"Write {"file_path":"/etc/x"}"#]);
    }

    #[test]
    fn versions() {
        assert_eq!(parse_version("2.1.285 (Claude Code)"), Some((2, 1, 285)));
        assert_eq!(parse_version("garbage"), None);
    }
}
