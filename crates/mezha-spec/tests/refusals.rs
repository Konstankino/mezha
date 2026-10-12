//! The compiler rules from `mezha-plan.md` section 4: specs that must not
//! build, and the plan's own example, which must.

use mezha_spec::{Diagnostics, LoadError, Scope, Severity, Spec, parse, validate};

fn load(name: &str) -> Spec {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    parse(&text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn check(text: &str) -> Diagnostics {
    validate(&parse(text).unwrap_or_else(|e| panic!("{e}")))
}

/// The single error at `path`, failing if there are other errors.
fn only_error<'a>(d: &'a Diagnostics, path: &str) -> &'a mezha_spec::Diagnostic {
    let errors: Vec<_> = d.errors().collect();
    assert_eq!(errors.len(), 1, "expected one error, got {errors:#?}");
    assert_eq!(errors[0].path, path, "{:#?}", errors[0]);
    errors[0]
}

fn paths(d: &Diagnostics, severity: Severity) -> Vec<&str> {
    d.0.iter()
        .filter(|x| x.severity == severity)
        .map(|x| x.path.as_str())
        .collect()
}

const BASE: &str = r#"
[project]
name = "base"

[policy]
permissions_ask = ["git push"]
fetch_allow = []
"#;

/// What every test agent needs besides the property under test.
const AGENT: &str = "description = \"A test agent.\"\ntools = [\"Read\"]\n";

#[test]
fn plan_example_builds_cleanly() {
    let spec = load("plan-example.toml");
    let d = validate(&spec);
    assert!(d.0.is_empty(), "{:#?}", d.0);
}

#[test]
fn preloaded_skills_must_be_reviewed() {
    // OWASP AST09: an agent preloads only skills someone has looked at.
    let agent =
        format!("{BASE}\n[agent.a]\n{AGENT}rule_of_two = []\nskills = [\"db-migrations\"]\n");
    let d = check(&agent);
    let e = only_error(&d, "agent.a.skills");
    assert!(e.message.contains("db-migrations"), "{e:?}");
    assert!(
        e.hint
            .as_deref()
            .unwrap()
            .contains("policy.external_skills")
    );

    let listed = agent.replace(
        "permissions_ask = [\"git push\"]",
        "permissions_ask = [\"git push\"]\nexternal_skills = [\"db-migrations\", \"tools:lint\"]",
    );
    assert!(check(&listed).0.is_empty(), "{:#?}", check(&listed).0);

    let pin = format!("sha256:{}", "ab".repeat(32));
    let pinned = agent.replace(
        "permissions_ask = [\"git push\"]",
        &format!("permissions_ask = [\"git push\"]\nexternal_skills = [\"db-migrations@{pin}\"]"),
    );
    assert!(check(&pinned).0.is_empty(), "{:#?}", check(&pinned).0);

    let bad = agent.replace(
        "permissions_ask = [\"git push\"]",
        "permissions_ask = [\"git push\"]\nexternal_skills = [\"db migrations\", \"a:b:c\", \"x@md5:1\"]",
    );
    assert_eq!(
        paths(&check(&bad), Severity::Error),
        [
            "policy.external_skills[0]",
            "policy.external_skills[1]",
            "policy.external_skills[2]",
            "agent.a.skills"
        ]
    );
}

#[test]
fn refuses_all_three_rule_of_two_properties() {
    let d = validate(&load("refuse-rule-of-two.toml"));
    let e = only_error(&d, "agent.researcher.rule_of_two");
    assert!(e.message.contains("all three"));
    let hint = e.hint.as_deref().unwrap();
    assert!(hint.contains("drop external_action"), "{hint}");
    assert!(hint.contains("human_gate = \"advisory\""), "{hint}");
}

#[test]
fn advisory_human_gate_builds_and_says_so() {
    let mut text = std::fs::read_to_string(format!(
        "{}/tests/fixtures/refuse-rule-of-two.toml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    text.push_str("human_gate = \"advisory\"\n");
    let d = check(&text);
    assert!(!d.has_errors(), "{:#?}", d.0);
    let w = d
        .warnings()
        .find(|w| w.path == "agent.researcher.human_gate")
        .unwrap();
    assert!(w.message.contains("advisory, not a boundary"));
}

#[test]
fn refuses_unscoped_bash_in_a_skill() {
    let d = validate(&load("refuse-unscoped-bash.toml"));
    let e = only_error(&d, "skill.release.allowed_tools");
    assert!(e.message.contains("`Bash`"));
}

#[test]
fn refuses_phi_memory_in_project_scope() {
    let d = validate(&load("refuse-phi-project.toml"));
    let e = only_error(&d, "agent.implementer.memory.scope");
    assert!(e.message.contains("must be local"));
}

#[test]
fn phi_memory_without_a_scope_becomes_local() {
    let spec = parse(&format!(
        "{BASE}\n[agent.a]\n{AGENT}rule_of_two = []\nmemory = {{ class = \"phi\" }}\n"
    ))
    .unwrap();
    let d = validate(&spec);
    assert!(!d.has_errors());
    assert_eq!(paths(&d, Severity::Warning), ["agent.a.memory.scope"]);
    assert_eq!(spec.memory_scope(&spec.agent["a"]), Some(Scope::Local));
}

#[test]
fn a_phi_repo_makes_every_agent_phi() {
    let text = r#"
[project]
name = "Client-X-PHI"

[policy]
permissions_ask = ["git push"]

[memory]
phi_repos = ["client-x-phi"]

[agent.a]
description = "A test agent."
tools = ["Read"]
rule_of_two = []
memory = { scope = "user" }

[agent.b]
description = "A test agent."
tools = ["Read"]
rule_of_two = []
memory = {}
"#;
    let spec = parse(text).unwrap();
    let d = validate(&spec);
    let e = only_error(&d, "agent.a.memory.scope");
    assert!(e.message.contains("phi_repos"));
    assert_eq!(spec.memory_scope(&spec.agent["b"]), Some(Scope::Local));
}

#[test]
fn rule_of_two_is_required() {
    let d = check(&format!("{BASE}\n[agent.a]\n{AGENT}"));
    only_error(&d, "agent.a.rule_of_two");
}

#[test]
fn rule_of_two_rejects_duplicates_and_needless_gates() {
    let d = check(&format!(
        "{BASE}\n[agent.a]\n{AGENT}rule_of_two = [\"private_data\", \"private_data\"]\nhuman_gate = \"advisory\"\n"
    ));
    only_error(&d, "agent.a.rule_of_two");
    assert_eq!(paths(&d, Severity::Warning), ["agent.a.human_gate"]);
}

#[test]
fn a_tool_cannot_be_allowed_and_disallowed() {
    let d = check(&format!(
        "{BASE}\n[agent.a]\ndescription = \"A test agent.\"\nrule_of_two = []\ntools = [\"Read\", \"Bash(cargo test *)\"]\ndisallowed_tools = [\"Bash\"]\n"
    ));
    only_error(&d, "agent.a.tools");
}

#[test]
fn knowledge_skills_need_a_real_description() {
    let short = check(&format!(
        "{BASE}\n[skill.k]\npreset = \"knowledge\"\ndescription = \"Use when coding.\"\n"
    ));
    only_error(&short, "skill.k.description");

    let no_when = check(&format!(
        "{BASE}\n[skill.k]\npreset = \"knowledge\"\ndescription = \"Error handling and logging conventions for this workspace.\"\n"
    ));
    let e = only_error(&no_when, "skill.k.description");
    assert!(e.message.contains("Use when"));

    let ok = check(&format!(
        "{BASE}\n[skill.k]\npreset = \"knowledge\"\ndescription = \"Logging conventions. Use when writing Rust code.\"\n"
    ));
    assert!(!ok.has_errors(), "{:#?}", ok.0);
}

#[test]
fn skill_listing_is_capped() {
    let long = "x".repeat(1500);
    let d = check(&format!(
        "{BASE}\n[skill.c]\npreset = \"command\"\ndescription = \"{long}\"\nwhen_to_use = \"{}\"\n",
        "y".repeat(40)
    ));
    let e = only_error(&d, "skill.c.description");
    assert!(e.message.contains("1540"));
}

#[test]
fn command_skills_resolve_and_must_stay_invocable() {
    let spec = parse(&format!(
        "{BASE}\n[skill.c]\npreset = \"command\"\ndescription = \"Cut a release.\"\n"
    ))
    .unwrap();
    let c = &spec.skill["c"];
    assert!(c.disable_model_invocation());
    assert!(c.user_invocable());

    let d = check(&format!(
        "{BASE}\n[skill.c]\npreset = \"command\"\ndescription = \"Cut a release.\"\nuser_invocable = false\n"
    ));
    only_error(&d, "skill.c.user_invocable");

    let spec = parse(&format!(
        "{BASE}\n[skill.k]\npreset = \"knowledge\"\ndescription = \"Logging conventions. Use when writing Rust code.\"\n"
    ))
    .unwrap();
    assert!(!spec.skill["k"].user_invocable());
    assert!(!spec.skill["k"].disable_model_invocation());
}

#[test]
fn rules_without_paths_warn() {
    let d = check(&format!("{BASE}\n[rule.style]\nmax_lines = 30\n"));
    assert!(!d.has_errors());
    assert_eq!(paths(&d, Severity::Warning), ["rule.style.paths"]);
}

#[test]
fn names_must_be_file_and_mention_safe() {
    let d = check(&format!(
        "{BASE}\n[agent.Implementer]\n{AGENT}rule_of_two = []\n"
    ));
    only_error(&d, "agent.Implementer");
    let d = check(&format!("{BASE}\n[rule.\"con\"]\npaths = [\"x\"]\n"));
    only_error(&d, "rule.con");
}

#[test]
fn policy_strings_cannot_inject_rules() {
    let d = check(
        r#"
[project]
name = "p"

[policy]
permissions_ask = ["git push", "git push; rm -rf /"]
deny_reads = [".env", "x) Bash(*"]
egress_allow = ["https://github.com", "github.com"]
"#,
    );
    assert_eq!(
        paths(&d, Severity::Error),
        [
            "policy.permissions_ask[1]",
            "policy.deny_reads[1]",
            "policy.egress_allow[0]"
        ]
    );
}

#[test]
fn policy_warnings() {
    let d = check("[project]\nname = \"p\"\n[policy]\nsandbox = false\n");
    assert!(!d.has_errors());
    assert_eq!(
        paths(&d, Severity::Warning),
        [
            "policy.permissions_ask",
            "policy.fetch_allow",
            "policy.sandbox"
        ]
    );
    let spec = parse("[project]\nname = \"p\"\n").unwrap();
    assert!(spec.policy.sandbox, "the sandbox is on by default");
}

#[test]
fn unknown_keys_and_newer_schemas_fail_to_load() {
    let typo = parse("[project]\nname = \"p\"\n[agent.a]\nrule_of_tow = []\n");
    assert!(
        matches!(&typo, Err(LoadError::Syntax(m)) if m.contains("rule_of_tow")),
        "{typo:?}"
    );
    let newer = parse("schema = 2\n[project]\nname = \"p\"\nfuture = true\n");
    assert_eq!(newer.unwrap_err(), LoadError::NewerSchema { found: 2 });
    let d =
        check("schema = 0\n[project]\nname = \"p\"\n[policy]\npermissions_ask = [\"git push\"]\n");
    only_error(&d, "schema");
}

#[test]
fn agents_need_a_description_and_a_safe_body_path() {
    let d = check(&format!(
        "{BASE}\n[agent.a]\ntools = [\"Read\"]\nrule_of_two = []\n"
    ));
    let e = only_error(&d, "agent.a.description");
    assert!(e.message.contains("is missing"));
    for bad in [
        "../x.md",
        "/abs.md",
        "agents/a.md",
        "mezha/.claude/a.md",
        "mezha/.GIT/a.md",
        "mezha/a.txt",
        "mezha\\\\a.md",
        "mezha//a.md",
        "mezha/./a.md",
    ] {
        let d = check(&format!(
            "{BASE}\n[agent.a]\n{AGENT}rule_of_two = []\nprompt_file = \"{bad}\"\n"
        ));
        only_error(&d, "agent.a.prompt_file");
    }
    let ok = check(&format!(
        "{BASE}\n[agent.a]\n{AGENT}rule_of_two = []\nprompt_file = \"mezha/roles/a.md\"\n"
    ));
    assert!(!ok.has_errors(), "{:#?}", ok.0);
    let d = check(&format!(
        "{BASE}\n[skill.k]\npreset = \"command\"\ndescription = \"Do it.\"\nbody_file = \"docs/k.md\"\n[rule.r]\npaths = [\"x\"]\nbody_file = \"mezha/rules/r.txt\"\n"
    ));
    assert_eq!(
        paths(&d, Severity::Error),
        ["skill.k.body_file", "rule.r.body_file"]
    );
}

#[test]
fn frontmatter_strings_must_not_end_the_block() {
    let d = check(&format!(
        "{BASE}\n[agent.a]\ndescription = \"a --- b\"\ntools = [\"Read\"]\nrule_of_two = []\n"
    ));
    let e = only_error(&d, "agent.a.description");
    assert!(e.message.contains("---"));
    let d = check(&format!(
        "{BASE}\n[skill.k]\npreset = \"command\"\ndescription = \"Do it.\\u2028\"\npaths = [\"a---b\"]\n"
    ));
    assert_eq!(
        paths(&d, Severity::Error),
        ["skill.k.description", "skill.k.paths"]
    );
}

#[test]
fn frontmatter_strings_must_not_hide_text() {
    // A description that reads one way to a reviewer and another to Claude
    // (OWASP AST04, ASCII smuggling).
    let d = check(&format!(
        "{BASE}\n[skill.k]\npreset = \"command\"\ndescription = \"Formats code.\\u200b\\U000E0049\\U000E0047\"\n"
    ));
    let e = only_error(&d, "skill.k.description");
    assert!(e.message.contains("hidden character"), "{e:?}");
}

#[test]
fn agent_tools() {
    // No tools key: everything would be inherited (OWASP AST03: no
    // permission manifest, no build).
    let d = check(&format!(
        "{BASE}\n[agent.a]\ndescription = \"x\"\nrule_of_two = []\n"
    ));
    let e = only_error(&d, "agent.a.tools");
    assert!(e.message.contains("permission manifest"), "{e}");
    // tools = [] is fine: no tools at all.
    let d = check(&format!(
        "{BASE}\n[agent.a]\ndescription = \"x\"\ntools = []\nrule_of_two = []\n"
    ));
    assert!(d.0.is_empty(), "{:#?}", d.0);
    // Only Bash and Agent take a specifier.
    let d = check(&format!(
        "{BASE}\n[agent.a]\ndescription = \"x\"\ntools = [\"Read(src/**)\", \"Agent(explorer)\", \"Bash(cargo test *)\"]\nrule_of_two = []\n"
    ));
    let e = only_error(&d, "agent.a.tools");
    assert!(e.message.contains("Read(src/**)"), "{e}");
    // Unscoped Bash warns, unknown tools warn, disallowed takes bare names.
    let d = check(&format!(
        "{BASE}\n[agent.a]\ndescription = \"x\"\ntools = [\"Bash\", \"Telepathy\"]\ndisallowed_tools = [\"Edit(x)\"]\nrule_of_two = []\n"
    ));
    assert_eq!(paths(&d, Severity::Error), ["agent.a.disallowed_tools"]);
    assert_eq!(
        paths(&d, Severity::Warning),
        ["agent.a.tools", "agent.a.tools"]
    );
    // A scoped Bash can't be checked for PowerShell.
    let d = check(&format!(
        "{BASE}\n[agent.a]\ndescription = \"x\"\ntools = [\"Bash(cargo *)\", \"PowerShell\"]\nrule_of_two = []\n"
    ));
    only_error(&d, "agent.a.tools");
    let d = check(&format!(
        "{BASE}\n[agent.a]\n{AGENT}rule_of_two = []\nmax_turns = 0\n"
    ));
    only_error(&d, "agent.a.max_turns");
}

#[test]
fn dream_settings() {
    let spec = parse(&format!(
        "{BASE}\n[memory]\ndream_model = \"opus\"\ndream_budget_usd = 2\ndream_max_turns = 10\n"
    ))
    .unwrap();
    assert!(validate(&spec).0.is_empty());
    assert_eq!(spec.memory.dream_model(), "opus");
    assert_eq!(spec.memory.dream_budget_usd(), 2.0);
    assert_eq!(spec.memory.dream_max_turns(), 10);
    let defaults = parse(BASE).unwrap();
    assert_eq!(defaults.memory.dream_model(), "sonnet");
    assert_eq!(defaults.memory.dream_budget_usd(), 1.0);
    assert_eq!(defaults.memory.dream_max_turns(), 40);

    for (line, path) in [
        (
            "dream_model = \"--dangerously-skip-permissions\"",
            "memory.dream_model",
        ),
        ("dream_model = \"son net\"", "memory.dream_model"),
        ("dream_model = \"\"", "memory.dream_model"),
        ("dream_budget_usd = 0", "memory.dream_budget_usd"),
        ("dream_budget_usd = 51", "memory.dream_budget_usd"),
        ("dream_budget_usd = nan", "memory.dream_budget_usd"),
        ("dream_max_turns = 0", "memory.dream_max_turns"),
        ("dream_max_turns = 201", "memory.dream_max_turns"),
    ] {
        let d = check(&format!("{BASE}\n[memory]\n{line}\n"));
        only_error(&d, path);
    }
}

#[test]
fn dream_policies() {
    let spec = load("plan-example.toml");
    assert_eq!(
        spec.agent["adversary"]
            .memory
            .as_ref()
            .unwrap()
            .dream_policy,
        Some(mezha_spec::DreamPolicy::AttackPatternsOnly)
    );
    let text = format!(
        "{BASE}\n[agent.a]\n{AGENT}rule_of_two = []\nmemory = {{ dream_policy = \"forget-everything\" }}\n"
    );
    let e = parse(&text).unwrap_err().to_string();
    for policy in ["lessons", "verified-facts", "attack-patterns-only"] {
        assert!(e.contains(policy), "{e}");
    }
}

#[test]
fn has_phi() {
    assert!(!parse(BASE).unwrap().has_phi());
    let spec = parse(&format!(
        "{BASE}\n[agent.a]\n{AGENT}rule_of_two = []\nmemory = {{ class = \"phi\" }}\n"
    ))
    .unwrap();
    assert!(spec.has_phi());
}

#[test]
fn dream_schedules() {
    let spec = parse(&format!(
        "{BASE}\n[memory]\ndream_schedule = \"nightly\"\ndream_at = \"02:30\"\n"
    ))
    .unwrap();
    assert!(validate(&spec).0.is_empty(), "{:?}", validate(&spec).0);
    assert_eq!(spec.memory.dream_at(), (2, 30));
    assert_eq!(parse(BASE).unwrap().memory.dream_at(), (3, 0));
    let d = check(&format!(
        "{BASE}\n[memory]\ndream_schedule = \"cron\"\ndream_cron = \"15 2 * * 1-5\"\n"
    ));
    assert!(d.0.is_empty(), "{:?}", d.0);

    only_error(
        &check(&format!("{BASE}\n[memory]\ndream_schedule = \"cron\"\n")),
        "memory.dream_schedule",
    );
    only_error(
        &check(&format!(
            "{BASE}\n[memory]\ndream_schedule = \"cron\"\ndream_cron = \"@daily\"\n"
        )),
        "memory.dream_cron",
    );
    only_error(
        &check(&format!(
            "{BASE}\n[memory]\ndream_schedule = \"nightly\"\ndream_at = \"3am\"\n"
        )),
        "memory.dream_at",
    );
    let d = check(&format!("{BASE}\n[memory]\ndream_at = \"04:00\"\n"));
    assert!(!d.has_errors());
    assert_eq!(paths(&d, Severity::Warning), ["memory.dream_at"]);
}

#[test]
fn skills_that_reach_out_without_asking_warn() {
    let d = check(&format!(
        "{BASE}\n[skill.k]\npreset = \"command\"\ndescription = \"Do it.\"\nallowed_tools = [\"Read\", \"WebFetch\", \"mcp__tracker__create\", \"Bash(cargo test *)\"]\n"
    ));
    assert!(!d.has_errors(), "{:#?}", d.0);
    let reach: Vec<_> = d
        .warnings()
        .filter(|w| w.message.contains("outside the sandbox"))
        .map(|w| w.message.split('`').nth(1).unwrap())
        .collect();
    assert_eq!(reach, ["WebFetch", "mcp__tracker__create"]);
}

#[test]
fn fetch_allow() {
    // Absent: WebFetch reaches anything, which deserves a warning.
    let open = BASE.replace("fetch_allow = []\n", "");
    let d = check(&open);
    assert_eq!(paths(&d, Severity::Warning), ["policy.fetch_allow"]);
    assert!(d.0[0].message.contains("AST05"));
    let d = check(&BASE.replace("[]", "[\"docs.rs\", \"*.example.com\", \"*\"]"));
    assert!(d.0.is_empty(), "{:#?}", d.0);
    let d = check(&BASE.replace(
        "fetch_allow = []",
        "fetch_allow = [\"https://docs.rs\", \"x.com:443\"]",
    ));
    assert_eq!(
        paths(&d, Severity::Error),
        ["policy.fetch_allow[0]", "policy.fetch_allow[1]"]
    );
}

#[test]
fn diagnostics_print_their_place_and_hint() {
    let d = check(&format!("{BASE}\n[agent.a]\n{AGENT}"));
    let text = only_error(&d, "agent.a.rule_of_two").to_string();
    assert!(
        text.starts_with("error: agent.a.rule_of_two: is missing"),
        "{text}"
    );
    assert!(text.contains("\n  hint: list any of"), "{text}");
    let d = check("[project]\nname = \"p\"\n[policy]\nsandbox = false\n");
    let w = d.warnings().find(|w| w.path == "policy.sandbox").unwrap();
    let text = w.to_string();
    assert!(
        text.starts_with("warning: policy.sandbox: the sandbox is off"),
        "{text}"
    );
    assert!(!text.contains("hint"), "{text}");
}

#[test]
fn the_project_needs_a_plain_name() {
    for bad in ["\"\"", "\"  \"", "\"a\\u0007b\""] {
        let d = check(&format!(
            "[project]\nname = {bad}\n[policy]\npermissions_ask = [\"git push\"]\nfetch_allow = []\n"
        ));
        let e = only_error(&d, "project.name");
        assert!(e.message.contains("non-empty name"), "{bad}: {e:?}");
    }
}

#[test]
fn policy_strings_must_not_be_empty_or_spaced() {
    let d = check(&BASE.replace(
        "fetch_allow = []",
        "fetch_allow = []\ndeny_reads = [\"\"]\negress_allow = [\"git hub.com\"]",
    ));
    let errors: Vec<_> = d.errors().collect();
    assert_eq!(
        paths(&d, Severity::Error),
        ["policy.deny_reads[0]", "policy.egress_allow[0]"]
    );
    assert_eq!(errors[0].message, "must not be empty");
    assert!(
        errors[1].message.contains("contains whitespace"),
        "{:?}",
        errors[1]
    );
}

#[test]
fn listing_a_spec_skill_as_external_does_nothing() {
    let d = check(&format!(
        "{BASE}external_skills = [\"ship\"]\n[skill.ship]\npreset = \"command\"\ndescription = \"Ship it.\"\n"
    ));
    assert!(!d.has_errors(), "{:#?}", d.0);
    assert_eq!(paths(&d, Severity::Warning), ["policy.external_skills[0]"]);
    assert!(
        d.0[0].message.contains("`ship` is defined in this spec"),
        "{:?}",
        d.0[0]
    );
}

#[test]
fn a_cron_without_the_cron_schedule_warns() {
    let d = check(&format!("{BASE}\n[memory]\ndream_cron = \"0 3 * * *\"\n"));
    assert!(!d.has_errors(), "{:#?}", d.0);
    assert_eq!(paths(&d, Severity::Warning), ["memory.dream_cron"]);
    assert!(
        d.0[0].message.contains("dream_schedule = \"cron\""),
        "{:?}",
        d.0[0]
    );
}

#[test]
fn a_long_agent_description_warns() {
    let long = "x".repeat(1025);
    let d = check(&format!(
        "{BASE}\n[agent.a]\ndescription = \"{long}\"\ntools = [\"Read\"]\nrule_of_two = []\n"
    ));
    assert!(!d.has_errors(), "{:#?}", d.0);
    assert_eq!(paths(&d, Severity::Warning), ["agent.a.description"]);
    assert!(
        d.0[0].message.contains("is over 1024 characters"),
        "{:?}",
        d.0[0]
    );
}

#[test]
fn phi_memory_may_say_local_itself() {
    let d = check(&format!(
        "{BASE}\n[agent.a]\n{AGENT}rule_of_two = []\nmemory = {{ class = \"phi\", scope = \"local\" }}\n"
    ));
    assert!(d.0.is_empty(), "{:#?}", d.0);
}

#[test]
fn bash_scopes_must_parse() {
    let d = check(&format!(
        "{BASE}\n[agent.a]\ndescription = \"x\"\ntools = [\"Bash(cargo\", \"Bash(cargo te*t)\"]\nrule_of_two = []\n"
    ));
    assert_eq!(
        paths(&d, Severity::Error),
        ["agent.a.tools", "agent.a.tools"]
    );
    let errors: Vec<_> = d.errors().collect();
    assert_eq!(
        errors[0].message, "`Bash(cargo` has an unclosed parenthesis",
        "{:?}",
        errors[0]
    );
    assert!(
        errors[1]
            .message
            .starts_with("`Bash(cargo te*t)`: the scope `te*t`"),
        "{:?}",
        errors[1]
    );
    assert!(
        errors[1].hint.as_deref().unwrap().contains("plain words"),
        "{:?}",
        errors[1]
    );
}

#[test]
fn unknown_disallowed_tools_warn() {
    let d = check(&format!(
        "{BASE}\n[agent.a]\n{AGENT}rule_of_two = []\ndisallowed_tools = [\"Telepathy\"]\n"
    ));
    assert!(!d.has_errors(), "{:#?}", d.0);
    assert_eq!(paths(&d, Severity::Warning), ["agent.a.disallowed_tools"]);
    assert!(
        d.0[0]
            .message
            .contains("`Telepathy` is not a Claude Code tool"),
        "{:?}",
        d.0[0]
    );
}

#[test]
fn skill_names_descriptions_and_rule_limits_are_checked() {
    let d = check(&format!(
        "{BASE}\n[skill.Ship]\npreset = \"command\"\ndescription = \"Ship it.\"\n"
    ));
    only_error(&d, "skill.Ship");
    let d = check(&format!(
        "{BASE}\n[skill.ship]\npreset = \"command\"\ndescription = \" \"\n"
    ));
    let e = only_error(&d, "skill.ship.description");
    assert_eq!(e.message, "must not be empty", "{e:?}");
    let d = check(&format!(
        "{BASE}\n[rule.r]\npaths = [\"x\"]\nmax_lines = 0\n"
    ));
    let e = only_error(&d, "rule.r.max_lines");
    assert_eq!(e.message, "must be at least 1", "{e:?}");
}
