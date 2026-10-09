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
| Credentials withheld from sandboxed commands (`sandbox.credentials`) | **Boundary** (sandbox on) | The OS hides the known credential files and token variables from the agent's shell commands. |
| Forge hosts kept out of `egress_allow` | **Boundary** (sandbox on) | The sandbox proxy refuses hosts that aren't allowed, so a push can't connect. On macOS this is the only push boundary: the sandbox can't hide the keychain. |
| Forge write hosts in `deniedDomains` | **Boundary** (sandbox on) | Claude Code refuses them for sandboxed commands in every permission mode, with no "allow" prompt: neither a click, nor `bypassPermissions`, nor auto mode's classifier opens them. Other hosts outside the allowlist stay closed only while a session asks you, and verify warns about them. |
| Sandbox `filesystem.denyWrite` on `~/.mezha` | **Boundary** (sandbox on) | The OS stops sandboxed commands from writing the approval store, so an agent can't approve itself. |
| `deny_reads` and credential paths as `Read(...)` deny rules | **Boundary** for sandboxed commands | Claude Code merges them into the sandbox's read restrictions; for the Read tool, which runs outside the sandbox, they are permission rules. |
| Branch protection on GitHub (`branch-protection` in verify) | **Boundary** (server) | GitHub refuses direct pushes to the default branch and asks code owners to review. verify reads it with your `gh` (queries only) and warns when your own token could bypass it. It limits what a push can break; it doesn't make a push impossible. |
| `mezha verify` | Proof | Fails when the sandbox is off or weakened in any settings file, when an agent could push, or when the gate was edited or switched off. With `--probe` it shows the network and credential parts inside `srt` instead of only reasoning about them; with `--inside`, Claude runs it inside the session's own sandbox. |
| Git guard rail in `env` (no credential helper, no askpass) | *Advisory* | It closes accidental helper use, but a command can name a helper itself (`git -c credential.helper=...`). |
| `git push` approval gate (hook) | *Advisory* | It reads command text. Scripts, `python -c` and git aliases get past it; [the tests list the known gaps](crates/mezha-hooks/tests/matcher_table.rs). |
| `permissions.ask` rules | *Advisory* | Claude Code documents them as not a boundary around a program. |
| Fail-closed hook (`\|\| exit 2`) | Integrity | It keeps the advisory gate from silently vanishing when `mezha` is missing or crashes. |
| Agent memory is read-only in sessions | **Boundary** (deny rule + sandbox) | A deny rule on all three memory scopes beats Claude Code's own "memory may be written" allowance, and the sandbox can't write there either. Only `mezha dream` changes memory, and a person reviews the diff ([ADR-0004](docs/adr/0004-memory-changes-only-through-dreams.md)). |
| An agent's `Bash(...)` scope (`agent-bash` hook) | *Advisory* | Claude Code can't scope an agent's tools by argument, so a frontmatter hook reads each command and blocks anything outside the scope. It reads command text, like the gate. |
| `mezha approve` refusing inside Claude Code | Speed bump | The boundary is the store's location, not this check. |
| Anything on native Windows | *Advisory* | No sandbox, and hooks may run in PowerShell 5.1, which can't fail closed. `compile` refuses `os_mode = "native-windows"` until phase 4; use WSL2. |

The sandbox wraps shell commands only. Claude's file tools, WebFetch, MCP
servers and hooks run outside it: an MCP server with a GitHub token can push
through the API whatever the sandbox says. Claude Code reads project settings
only from the directory it starts in, so start it in the project root.

Withholding credentials means the agent can't push, fetch from private
remotes, run `gh` or sign commits in the sandbox, even with an approval: a
human does those from their own terminal ([ADR-0003](docs/adr/0003-push-boundary.md)).
Not here yet: the approval broker with short-lived tokens.

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
since hooks load at startup. Then check that the boundary holds:

```bash
mezha verify
```

Pushes happen from your own terminal. To lift the gate for commands that
don't need credentials, run this yourself, not through Claude:

```bash
mezha approve --minutes 30
```

`mezha approve --status` shows what is left; `mezha approve --revoke` ends it.

## Probing the boundary

`mezha verify` reasons from the settings. `mezha verify --probe` also runs
probes inside Anthropic's sandbox runtime, `srt`, started with the sandbox
settings as mezha reads them:

- a `git push --dry-run` to each push remote that deletes a ref that doesn't
  exist, so nothing is ever sent, from a scratch repository outside the
  project;
- a check of which credential files a sandboxed command can read and which
  token variables it sees.

A credential that reaches a server fails `push-boundary` as "shown in srt".
The probe can't see the macOS keychain, how Claude Code itself merges the
settings, or ssh on macOS (which always fails inside srt);
[ADR-0003](docs/adr/0003-push-boundary.md) has the details.

It needs, on macOS and Linux only:

- Node 22.12 or later and `npm i -g @anthropic-ai/sandbox-runtime@0.0.79`;
- on Linux, also `bwrap`, `socat` and `rg`, and on Ubuntu 24.04 and later
  unprivileged user namespaces for bwrap
  (`kernel.apparmor_restrict_unprivileged_userns`).

Without a usable `srt`, verify exits 2 and says why. Run it from your own
terminal. Inside Claude Code it works only from a `!` command, which runs
unsandboxed.

A quick manual check:

1. With `egress_allow = []`, `mezha verify --probe` shows `push-boundary`
   passing with "shown closed in srt".
2. With `egress_allow = ["github.com"]` on macOS, `push-boundary` fails on
   the keychain finding (static), and the probe shows the network open.
3. The same on Linux passes, with "in srt no credential was readable".

4. In a Claude Code session on a mezha project, ask Claude to run
   `mezha verify --inside` and read the command's output. `inside-sandbox`
   passes, `github.com:443` is "refused inside the sandbox", and no "allow"
   prompt appears.

verify only runs `srt`, `gh`, `git` and the other tools it uses when they
sit outside places an agent can write: the project, `$TMPDIR`, the sandbox's
`allowWrite` paths, and directories the group or everyone can write.

### From inside a session

`mezha verify --inside` is for Claude to run with its Bash tool, so it looks
at the sandbox Claude Code really built: its own merge of every settings
file, the `env` block and its proxy. It checks:

- that the command is sandboxed. The kernel decides, not environment
  variables: a direct connection is refused, and `mezha.toml` can't be
  opened for writing;
- that srt's proxy is in front, and that forge hosts in `deniedDomains` are
  refused. It contacts nothing that could make Claude Code ask you about a
  host;
- that no credential file, token variable or ssh agent is readable.

The report reaches you through Claude, so treat it as a diagnostic: read
the command's own output in the tool result, not Claude's summary. Without
`CLAUDECODE` in the environment it exits 2; from your own terminal, use
`--probe`.

## Commands

| Command | What it does |
|---|---|
| `mezha init` | Creates `mezha.toml` from a commented template. |
| `mezha compile` | Validates the spec and writes the generated files. Writes nothing if a generated file was written or edited by someone else. |
| `mezha diff` | Shows what `compile` or `apply` would change, as a unified diff. |
| `mezha apply [--yes]` | Like `compile`, but backs conflicting files up to `.mezha-backup/<UTC time>/` and overwrites them. |
| `mezha verify [--json] [--project-only \| --probe \| --inside]` | Checks that the boundary holds: sandbox in effect, no push possible, gate intact and switched on, default branch protected. Exit 0 pass, 1 a check failed, 2 couldn't run. `--project-only` looks at committed files only (for CI). `--probe` also runs side-effect-free probes inside `srt`, and `--inside` is for Claude to run inside the session's sandbox ([Probing the boundary](#probing-the-boundary)). |
| `mezha approve [--minutes N \| --status \| --revoke]` | Grants gated commands for 1 to 1440 minutes. Refuses inside Claude Code and without a terminal. |
| `mezha hook <name>` | Run by Claude Code; see `.claude/settings.json`. |

`-p/--path` points any command at another project root.

## What `compile` writes

- `.claude/settings.json`:
  - `permissions.ask`: the gated commands, edits to `mezha.toml`, the
    settings files, the body sources under `mezha/` and the generated agents,
    skills and rules, and `mezha compile/apply/init`, so an agent can't
    quietly remove a gate or rewrite what an agent is told;
  - `permissions.deny`: `mezha approve`, edits under `~/.mezha`, edits to
    agent memory in every scope, the `deny_reads` patterns, and reads of
    known credential files;
  - `env`: git starts with no credential helper, no askpass and no terminal
    prompt (advisory);
  - `sandbox` (when `policy.sandbox = true`): enabled, no unsandboxed
    retries, no silent fallback when the sandbox can't start, `egress_allow`
    as the allowed hosts, the known forge write hosts it doesn't cover
    (github.com, api/uploads/ssh.github.com, gitlab.com, bitbucket.org,
    api.bitbucket.org) as denied hosts, writes to `~/.mezha`, `mezha.toml`,
    the state file, `mezha/`, `.claude/rules` and agent memory denied, and
    credential files and token variables withheld;
  - one `PreToolUse` hook on every tool: the approval gate.
- `.claude/agents/<name>.md`, `.claude/skills/<name>/SKILL.md` and
  `.claude/rules/<name>.md`: frontmatter from the spec, body from your
  Markdown file under `mezha/` (see [Writing agents](#writing-agents)).
- `.claude/.mezha-state.json`: SHA-256 fingerprints of the generated files.
  It tells mezha's own output from a hand edit; it is not a tamper check.

`.claude/settings.local.json` is never touched.

A trap: the sandbox may not write `mezha/`, `mezha.toml`, `.claude/rules` or
agent memory, so a sandboxed `git switch`, `rebase` or `stash` across commits
that change those paths stops part-way. Run such git commands in your own
terminal.

## Writing agents

An agent, skill or rule has two halves: its settings in `mezha.toml`, and its
body in a Markdown file you own. compile joins them:

```toml
[agent.explorer]
description = "Answers questions about the code with file:line evidence. Use before changing unfamiliar code."
model = "haiku"
tools = ["Read", "Grep", "Glob"]
rule_of_two = ["private_data"]
memory = { scope = "project" }
# prompt_file = "mezha/agents/explorer.md"   # the default
```

- The body file holds only the body: mezha writes the frontmatter, so a body
  that starts with `---` is an error. Bodies live under `mezha/` (an ask rule
  and the sandbox protect them) and may not be symlinks.
- `tools` takes tool names. Only `Bash(...)` and `Agent(...)` take a scope;
  `Bash(cargo test *)` gives the agent Bash plus the advisory `agent-bash`
  hook. Leaving `tools` out gives the agent every tool, which compile warns
  about; `tools = []` gives it none.
- An agent with `memory` reads `.claude/agent-memory/<name>/MEMORY.md` (or
  the local scope for PHI) but can't write it: mezha takes back the Write and
  Edit tools Claude Code would add, and denies the path. Local memory must
  be git-ignored; `verify` fails if it isn't.
- Nothing in a frontmatter value may contain `---`: Claude Code ends the
  frontmatter at the first one.
- Agent, skill, rule or command files under `.claude/` that mezha doesn't
  generate are reported by `verify`, since they skip mezha's checks.

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
  "Use when";
- an agent without a `description`, a body path outside `mezha/`, a tool
  scope other than on `Bash` or `Agent`, and frontmatter text containing
  `---` or control characters.

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
and without `mezha` on `PATH`. `crates/mezha-verify/tests/probe.rs` runs the
probe's scripts against real git with local listeners (no network, no srt);
`boundary.rs` drives verify with stand-in `gh` and `srt` that answer from
GitHub responses recorded in `tests/fixtures/protection`. Don't run `mezha compile` in this repository
itself: with a broken or missing binary, the fail-closed hook would block
your own session.

`crates/mezha-cli/tests/real_srt.rs` runs the probes and `--inside` against
a real srt. The tests are ignored by default; with srt 0.0.79 and Node 22 on
`PATH`:

```bash
MEZHA_REAL_SRT=1 cargo test -p mezha --test real_srt -- --ignored
```

The scheduled workflow `.github/workflows/srt.yml` runs them weekly on
Ubuntu 24.04 and macOS 15, with srt installed from the lockfile in
`ci/srt`. It needs the repository on GitHub to run.

The workspace has eight crates: `mezha-spec`, `mezha-render`, `mezha-hooks`,
`mezha-broker`, `mezha-verify` and `mezha` (the CLI) do the work;
`mezha-memory` and `mezha-metrics` are placeholders for later phases. The
boundary scenarios verify must fail on live in
`crates/mezha-verify/tests/boundary.rs`.

## Documents

- [`mezha-plan.md`](mezha-plan.md): the implementation plan (Ukrainian).
- [ADR-0001](docs/adr/0001-governance-and-memory-not-a-generator.md):
  governance and memory, not a generator.
- [ADR-0002](docs/adr/0002-fail-closed-hook-command.md): the fail-closed hook
  command.
- [ADR-0003](docs/adr/0003-push-boundary.md): the push boundary and what
  `mezha verify` checks.
- [ADR-0004](docs/adr/0004-memory-changes-only-through-dreams.md): agent
  memory changes only through reviewed dreams.
- [Porting inventory](docs/porting-inventory.md): what comes from ocgen, and
  what doesn't.
