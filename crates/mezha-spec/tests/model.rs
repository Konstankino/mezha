//! The typed spec: the spelling each enum takes in generated files is the
//! spelling the user wrote in `mezha.toml`, and load errors name the file.

use mezha_spec::{Agent, Capability, DreamPolicy, Effort, LoadError, Scope, parse};

/// An agent with `line` added to its table. Parsing doesn't need
/// `rule_of_two`; validation does, and these tests don't validate.
fn agent_with(line: &str) -> Agent {
    let text = format!(
        "[project]\nname = \"p\"\n[agent.a]\ndescription = \"x\"\ntools = [\"Read\"]\n{line}\n"
    );
    parse(&text)
        .unwrap_or_else(|e| panic!("{line}: {e}"))
        .agent
        .remove("a")
        .unwrap()
}

#[test]
fn efforts_are_spelled_as_written() {
    for spelling in ["low", "medium", "high", "xhigh", "max"] {
        let agent = agent_with(&format!("effort = \"{spelling}\""));
        assert_eq!(agent.effort.map(Effort::as_str), Some(spelling));
    }
}

#[test]
fn memory_scopes_are_spelled_as_written() {
    for spelling in ["project", "local", "user"] {
        let agent = agent_with(&format!("memory = {{ scope = \"{spelling}\" }}"));
        let scope = agent.memory.as_ref().unwrap().scope;
        assert_eq!(scope.map(Scope::as_str), Some(spelling));
    }
}

#[test]
fn dream_policies_are_spelled_as_written() {
    for spelling in ["lessons", "verified-facts", "attack-patterns-only"] {
        let agent = agent_with(&format!("memory = {{ dream_policy = \"{spelling}\" }}"));
        let policy = agent.memory.as_ref().unwrap().dream_policy;
        assert_eq!(policy.map(DreamPolicy::as_str), Some(spelling));
    }
}

#[test]
fn rule_of_two_properties_are_spelled_as_written() {
    let agent =
        agent_with("rule_of_two = [\"untrusted_input\", \"private_data\", \"external_action\"]");
    let spelled: Vec<&str> = agent
        .rule_of_two
        .as_deref()
        .unwrap()
        .iter()
        .map(|c| c.as_str())
        .collect();
    assert_eq!(
        spelled,
        ["untrusted_input", "private_data", "external_action"]
    );
    let all: Vec<&str> = Capability::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(all, spelled, "ALL lists every property once, in order");
}

#[test]
fn load_errors_name_the_spec_file() {
    let newer = LoadError::NewerSchema { found: 2 }.to_string();
    assert_eq!(
        newer,
        "mezha.toml: schema 2 needs a newer mezha (this one reads schema 1)"
    );
    let syntax = LoadError::Syntax("expected `=`\n".into()).to_string();
    assert_eq!(syntax, "mezha.toml: expected `=`");
}
