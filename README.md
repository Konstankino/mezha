# Mezha

> **A boundary, not a matcher.** Governance and memory plane for Claude Code projects.

*Mezha* (Ukrainian *межа*) is a boundary that neighbours respect. Two ideas
give the tool its name:

1. An agent's safety is a **boundary** (the OS sandbox, credentials, the
   server), not a command matcher.
2. An agent's knowledge is what survives **past the session's boundary**
   (skills, rules, memory a human has reviewed).

Status: **pre-alpha**, the first week of [`mezha-plan.md`](mezha-plan.md).
Nothing is published yet.

## What is a boundary and what is advisory

Every security feature is either a boundary or labelled advisory. Today:

| Feature | Kind | Why |
|---|---|---|
| Sandbox `filesystem.denyWrite` on `~/.mezha` | **Boundary** (sandbox on) | The OS stops sandboxed commands from writing the approval store, so an agent can't approve itself. |
| Approval store outside the repository | **Boundary** (sandbox on) | It isn't in the working tree an agent may edit. |
| `deny_reads` as `Read(...)` deny rules | **Boundary** for sandboxed commands | Claude Code merges them into the sandbox's read restrictions; for file tools they are permission rules. |
| `git push` approval gate (hook) | *Advisory* | It reads command text. Scripts, `python -c` and git aliases get past it; [the tests list the known gaps](crates/mezha-hooks/tests/matcher_table.rs). |
| `permissions.ask` rules | *Advisory* | Claude Code documents them as not a boundary around a program. |
| Fail-closed hook (`\|\| exit 2`) | Integrity | It keeps the advisory gate from silently vanishing when `mezha` is missing or crashes. |
| `mezha approve` refusing inside Claude Code | Speed bump | The boundary is the store's location, not this check. |
| Anything on native Windows | *Advisory* | No sandbox, and hooks may run in PowerShell 5.1, which can't fail closed. `compile` refuses `os_mode = "native-windows"` until phase 4; use WSL2. |

Not here yet (phase 1): withholding credentials from sandboxed commands,
branch protection checks, `mezha verify`, and the approval broker with
short-lived tokens. Until then **an agent's `git push` is stopped by an
advisory gate only**. The strongest setup today: the agent commits, a human
pushes.

## Install

From source, until releases exist:

```bash
cargo install --path crates/mezha-cli
```

`mezha` must be on `PATH` on every machine that runs Claude Code in a mezha
project, and in CI. The hook fails closed: without the binary, every tool
call is blocked.

## Quickstart

```bash
mezha init        # writes mezha.toml
mezha compile     # writes .claude/settings.json and .claude/.mezha-state.json
```

Edit `mezha.toml` between the two. Start a new Claude Code session afterwards,
since hooks load at startup. When the agent needs to push, run this in your
own terminal, not through Claude:

```bash
mezha approve --minutes 30
```

`mezha approve --status` shows what is left; `mezha approve --revoke` ends it.

## Commands

| Command | What it does |
|---|---|
| `mezha init` | Creates `mezha.toml` from a commented template. |
| `mezha compile` | Validates the spec and writes the generated files. Writes nothing if a generated file was written or edited by someone else. |
| `mezha diff` | Shows what `compile` or `apply` would change, as a unified diff. |
| `mezha apply [--yes]` | Like `compile`, but backs conflicting files up to `.mezha-backup/<UTC time>/` and overwrites them. |
| `mezha approve [--minutes N \| --status \| --revoke]` | Grants gated commands for 1 to 1440 minutes. Refuses inside Claude Code and without a terminal. |
| `mezha hook <name>` | Run by Claude Code; see `.claude/settings.json`. |

`-p/--path` points any command at another project root.

## What `compile` writes

- `.claude/settings.json`:
  - `permissions.ask`: the gated commands, edits to `mezha.toml` and the
    settings files, and `mezha compile/apply/init`, so an agent can't quietly
    remove a gate;
  - `permissions.deny`: `mezha approve`, edits under `~/.mezha`, and the
    `deny_reads` patterns;
  - `sandbox` (when `policy.sandbox = true`): enabled, no unsandboxed
    retries, no silent fallback when the sandbox can't start, `egress_allow`
    as the allowed hosts, and writes to `~/.mezha`, `mezha.toml` and the
    state file denied;
  - one `PreToolUse` hook on every tool: the approval gate.
- `.claude/.mezha-state.json`: SHA-256 fingerprints of the generated files.
  It tells mezha's own output from a hand edit; it is not a tamper check.

`.claude/settings.local.json` is never touched. Agents, skills and rules in
`mezha.toml` are validated now and rendered in phase 1.

## The spec

`mezha.toml` follows section 4 of the plan. Unknown keys are errors. The
compiler refuses, among other things:

- an agent with all three Rule of Two properties (`untrusted_input`,
  `private_data`, `external_action`), unless `human_gate = "advisory"`;
- an agent without a `rule_of_two` list (an empty list is fine);
- unscoped `Bash` in a skill's `allowed_tools`;
- PHI memory (`class = "phi"`, or a repository listed in `phi_repos`) with
  project or user scope;
- a knowledge skill whose description is under 40 characters or lacks
  "Use when".

Every error and warning names its place in the spec, such as
`agent.implementer.rule_of_two`, and most come with a hint.

## Development

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

The end-to-end tests (`crates/mezha-cli/tests/e2e_hooks.rs`, Unix only) run
the hook command from a generated `settings.json` verbatim under bash, with
and without `mezha` on `PATH`. Don't run `mezha compile` in this repository
itself: with a broken or missing binary, the fail-closed hook would block
your own session.

The workspace has eight crates: `mezha-spec`, `mezha-render`, `mezha-hooks`,
`mezha-broker` and `mezha` (the CLI) do the work; `mezha-verify`,
`mezha-memory` and `mezha-metrics` are placeholders for later phases.

## Documents

- [`mezha-plan.md`](mezha-plan.md): the implementation plan (Ukrainian).
- [ADR-0001](docs/adr/0001-governance-and-memory-not-a-generator.md):
  governance and memory, not a generator.
- [ADR-0002](docs/adr/0002-fail-closed-hook-command.md): the fail-closed hook
  command.
- [Porting inventory](docs/porting-inventory.md): what comes from ocgen, and
  what doesn't.
