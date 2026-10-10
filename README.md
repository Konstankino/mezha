# Mezha

> **A boundary, not a matcher.** Governance and memory plane for Claude Code projects.

*Mezha* (Ukrainian *межа*) is a boundary that neighbours respect. Two ideas
give the tool its name:

1. An agent's safety is a **boundary** (the OS sandbox, credentials, the
   server), not a command matcher.
2. An agent's knowledge is what survives **past the session's boundary**
   (skills, rules, memory a human has reviewed).

Status: **pre-alpha**, phase 3 of [`mezha-plan.md`](mezha-plan.md).
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
| Branch protection on GitHub (`branch-protection` in verify) | **Boundary** (server) | GitHub refuses direct pushes to the default branch and asks code owners to review. verify reads it with your `gh` (queries only) and warns when your own token could bypass it, and when commits to a protected branch don't have to be signed, which would tie each change to agents, skills and memory to a verified identity. It limits what a push can break; it doesn't make a push impossible. |
| `mezha verify` | Proof | Fails when the sandbox is off or weakened in any settings file, when an agent could push, or when the gate was edited or switched off. With `--probe` it shows the network and credential parts inside `srt` instead of only reasoning about them; with `--inside`, Claude runs it inside the session's own sandbox. |
| Git guard rail in `env` (no credential helper, no askpass) | *Advisory* | It closes accidental helper use, but a command can name a helper itself (`git -c credential.helper=...`). |
| `git push` approval gate (hook) | *Advisory* | It reads command text. Scripts, `python -c` and git aliases get past it; [the tests list the known gaps](crates/mezha-hooks/tests/matcher_table.rs). |
| `permissions.ask` rules | *Advisory* | Claude Code documents them as not a boundary around a program. |
| WebFetch allowlist (`policy.fetch_allow`) | Hook (fail-closed) | The gate reads the host from each WebFetch URL as a browser would and blocks any host the list doesn't name; a redirect to another host comes back as a new WebFetch call, which it checks too. With `fetch_allow = []` settings also tell Claude Code to leave WebFetch out. Links in bodies must stay inside the list. MCP tools that fetch and WebSearch aren't covered. Without the key WebFetch reaches anything, and compile warns. |
| Repository config that runs code (`project-config` in verify) | Integrity | Settings that run a command, install plugins or point Claude's traffic elsewhere, and MCP servers from `.mcp.json`, all run outside the sandbox when a session starts. verify fails on them in the shared settings file, on any approval of every `.mcp.json` server, and on a `.mcp.json` server on this machine that takes calls without authentication (a web page can reach localhost too), and warns about other servers and about such settings in your local file. |
| Reviewed skills only (`inventory` in verify) | Integrity | Claude Code prefers a personal skill to a project skill with the same name, so verify fails when one in `~/.claude/skills` shadows the project's. Personal and plugin skills not listed in `policy.external_skills` warn, and an agent may preload only skills the spec defines or lists. A listed skill pinned to its fingerprint (`notes@sha256:...`, as verify prints it) fails when any file in its directory changes. |
| Audit log under `~/.mezha/audit` | Evidence (boundary on `~/.mezha`) | The gate records every call it decides before it runs, and a second hook records how it ended. Sandboxed commands can't write there and the file tools are denied, so an agent can't rewrite its own record; your own processes can, so it is evidence against the agent, not against you. A call that can't be recorded is blocked. See [Audit log](#audit-log). |
| Fail-closed hook (`\|\| exit 2`) | Integrity | It keeps the advisory gate from silently vanishing when `mezha` is missing or crashes. |
| Agent memory is read-only in sessions | **Boundary** (deny rule + sandbox) | A deny rule on all three memory scopes beats Claude Code's own "memory may be written" allowance, and the sandbox can't write there either. Only `mezha dream` changes memory, and a person reviews the diff ([ADR-0004](docs/adr/0004-memory-changes-only-through-dreams.md)). |
| Auto memory is read-only in sessions (`memory.auto_memory`) | **Boundary** (deny rule) | Claude Code's auto memory loads into every session and worktree of the project, so a line written there acts like an instruction later. A deny rule on `~/.claude/projects` keeps sessions from writing it (and their transcripts, which dreams read) while it still loads. `auto_memory = "writable"` turns this off; verify warns when `autoMemoryDirectory` or `CLAUDE_CONFIG_DIR` moves it where the rule doesn't reach. |
| A dream writes only the role's staged memory | **Boundary** (Claude Code permissions) | The dreamer runs as `claude -p --restricted` with `dontAsk`, no prompts, five file tools and one allow rule; mezha stops it if Claude Code reports other tools, MCP servers or another mode. See [Dreams](#dreams). |
| mezha's review of a dream | Integrity | mezha, not the model, reads the staged memory once, refuses anything but flat Markdown files and a clean worktree, and commits exactly the bytes it read, with the repository's git hooks off. |
| Code owners review memory changes | **Boundary** (server) | With `/.claude/agent-memory/` in CODEOWNERS and code owner reviews required, a dream branch needs their approval to land. verify warns until it is set up. |
| Dream digests under `~/.mezha/dreams` | **Boundary** for sandboxed writes | The sandbox can't write `~/.mezha`, so a session can't plant digests; a deny rule keeps sessions from reading them. |
| PHI memory stays local | **Boundary** (local scope) | PHI memory is never committed: the spec forces local scope and verify fails if local memory isn't git-ignored. |
| The `dream-guard` hook | *Advisory* | It checks each of the dreamer's file paths, fail-closed, but a hook reads paths, so it backs up the permissions rather than replacing them. |
| Skill shell off (`disableSkillShellExecution`) | **Boundary** (Claude Code) | Claude Code doesn't run `` !`cmd` `` in skills and commands, from any source, and shows a placeholder instead. Bundled and managed skills aren't affected. verify fails when another settings file turns it back on. |
| Injection, secret and PHI scans | *Advisory* | Patterns. They redact digests, and refuse a dream or an agent, skill or rule body with hidden characters, secrets, remote images, raw HTML or, in a skill, shell run at load; `verify`'s `bodies` check scans every file that loads. Phrases are matched again with hidden characters removed and fullwidth, mathematical and enclosed letters, and Cyrillic or Greek lookalikes inside Latin words, made plain; base64 text is decoded two layers deep; shell in a body's code is read as the shell reads it, so `c''url ... \| s""h` is still a download piped into a shell. [The evasion tests](crates/mezha-memory/tests/evasion.rs) list what they catch and what still gets past. They can still miss things: read every dream diff and body change. |
| An agent's `Bash(...)` scope (`agent-bash` hook) | *Advisory* | Claude Code can't scope an agent's tools by argument, so a frontmatter hook reads each command and blocks anything outside the scope. It reads command text, like the gate. |
| `mezha approve` refusing inside Claude Code | Speed bump | The boundary is the store's location, not this check. |
| Anything on native Windows | *Advisory* | No sandbox, and hooks may run in PowerShell 5.1, which can't fail closed. `compile` refuses `os_mode = "native-windows"` until phase 4; use WSL2. |

How these map to the OWASP Agentic Skills Top 10, mitigation by mitigation,
including what mezha leaves to registries and Claude Code:
[docs/owasp-ast10.md](docs/owasp-ast10.md).

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
cargo install --locked --force --path crates/mezha-cli
```

`--force` matters when you update: without it, cargo keeps an installed
mezha of the same version.

`mezha` must be on `PATH` on every machine that runs Claude Code in a mezha
project, and in CI. The hook fails closed: without the binary, every tool
call is blocked. The hook command carries a protocol number. A newer mezha
still runs the commands an older one compiled, until the next `mezha
compile`. An older mezha refuses a newer one's commands and says to
install the mezha the project uses: update it before you compile.

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
- that no credential file or token variable is readable, and that unix
  sockets can't be opened, so no ssh or gpg agent, keyring or git
  credential-cache can answer. On Linux that is srt's seccomp filter, which
  is optional: when it's missing, sockets open and the check warns, or
  fails once an agent is listening where they usually do.

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
| `mezha verify [--json] [--project-only \| --probe \| --inside]` | Checks that the boundary holds: sandbox in effect, no push possible, gate intact and switched on, default branch protected, and the agent, skill, rule and command files clean. `--json` adds an inventory of those files with fingerprints and scan results. Exit 0 pass, 1 a check failed, 2 couldn't run. `--project-only` looks at committed files only (for CI). `--probe` also runs side-effect-free probes inside `srt`, and `--inside` is for Claude to run inside the session's sandbox ([Probing the boundary](#probing-the-boundary)). |
| `mezha dream [--role R] [--since 7d] [--base REV] [--dry-run \| --scheduled]` | Turns recent agent runs into reviewed memory: a commit on a new branch for project memory, a confirmed diff for local and user memory. Refuses inside Claude Code. See [Dreams](#dreams). |
| `mezha dream --schedule launchd\|systemd\|cron` | Prints a snippet that runs `mezha dream --scheduled` every night. Installs nothing. See [Scheduling dreams](#scheduling-dreams). |
| `mezha metrics [--since 30d] [--json] [--record]` | Session cost, rework proxies, unresolved items per week, and whether dreams landed without edits. See [Metrics](#metrics). |
| `mezha metrics --ab TASKS.toml [--repeat N] [--yes] [--unsandboxed-check]` | Runs each task with the agent's memory and with it emptied, and compares. Spends money; asks first. |
| `mezha skill eval NAME [--cases FILE] [--repeat N] [--only triggers\|tasks] [--base REV] [--yes] [--unsandboxed-check]` | Checks that Claude loads the skill when it should and only then, and compares tasks with it and without it. Spends money; asks first. See [Skill evals](#skill-evals). |
| `mezha approve [--minutes N \| --status \| --revoke]` | Grants gated commands for 1 to 1440 minutes. Refuses inside Claude Code and without a terminal. |
| `mezha hook <name>` | Run by Claude Code; see `.claude/settings.json`. |

`-p/--path` points any command at another project root.

## What `compile` writes

- `.claude/settings.json`:
  - `permissions.ask`: the gated commands, edits to `mezha.toml`, the
    settings files, the body sources under `mezha/`, the generated agents,
    skills and rules, every `CLAUDE.md`, `CLAUDE.local.md` and `AGENTS.md`
    (and `~/.claude/CLAUDE.md`), and `mezha compile/apply/init`, so an agent
    can't quietly remove a gate or rewrite what an agent is told;
  - `permissions.deny`: `mezha approve`, edits under `~/.mezha`, reads of
    dream digests under `~/.mezha/dreams`, edits to agent memory in every
    scope and (unless `memory.auto_memory = "writable"`) to auto memory and
    transcripts under `~/.claude/projects`, the `deny_reads` patterns, and
    reads of known credential files;
  - `env`: git starts with no credential helper, no askpass and no terminal
    prompt (advisory);
  - `sandbox` (when `policy.sandbox = true`): enabled, no unsandboxed
    retries, no silent fallback when the sandbox can't start, `egress_allow`
    as the allowed hosts, the known forge write hosts it doesn't cover
    (github.com, api/uploads/ssh.github.com, gitlab.com, bitbucket.org,
    api.bitbucket.org) as denied hosts, writes to `~/.mezha`, `mezha.toml`,
    the state file, `mezha/`, `.claude/rules` and agent memory denied, and
    credential files and token variables withheld;
  - `disableSkillShellExecution`: skills and commands can't run shell
    commands when they load;
  - `enableAllProjectMcpServers: false`: each server in `.mcp.json` waits
    for your approval;
  - one `PreToolUse` hook on every tool: the approval gate, which also
    keeps WebFetch inside `policy.fetch_allow` and writes the
    [audit log](#audit-log); with `fetch_allow = []`,
    `CLAUDE_CODE_DISABLE_WEB_FETCH` in `env` as well;
  - `PostToolUse` and `PostToolUseFailure` hooks on every tool, which record
    how each call ended.
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

## Audit log

Every tool call the gate decides on gets a line in
`~/.mezha/audit/<sha256 of the repository root>/<YYYYMMDD>.jsonl` before it
runs (OWASP Agentic Skills Top 10, AST09):

```json
{"v":1,"type":"admission","attempt_id":"sha256:…","preimage":["session_id","tool_use_id"],"session_id":"…","tool_use_id":"…","agent_type":"explorer","tool_name":"Read","ts_ms":1791648000000,"input_sha256":"sha256:…","decision":"pass","policy":"sha256:…"}
```

- `decision` is `pass` or `block` (with the `reason` Claude was given).
  `pass` means mezha didn't object; Claude Code's permission rules still
  apply after it.
- `policy` is the spec fingerprint `mezha compile` recorded, so a record
  says which rules were in force.
- After the call, a second line with the same `attempt_id` gives its
  `terminal_state`: `committed`, or `failed` (with `interrupted` when you
  stopped it). An admission without an outcome is a call that was denied
  later, or a gap in the log.
- `attempt_id` is the SHA-256 of the fields `preimage` names, joined by a
  NUL, so you can recompute it from the transcript.
- Calls link up as far as Claude Code lets hooks see: `prompt_id` names
  the user prompt every call came from, a subagent's calls carry its
  `agent_id`, and the outcome of the Agent call that started it carries the
  same id as `spawned_agent_id`. Hooks get no reference to the spawning call
  before a subagent's calls run, so the admission can't name its parent
  itself; the join goes through the outcome.
- No content: tool input becomes a digest, since it can hold secrets or
  PHI. The session transcript keeps the content.
- If a record can't be written, the gate blocks the call, like every other
  failure in the hook. Each record is a single append without a lock, so a
  slow disk can't stall the hook until Claude Code gives up and lets the
  call through.
- Nothing is deleted: remove old files yourself.

`mezha verify` runs the gate with a scratch home and fails if it didn't
write its records.

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
  hook. `tools` is the agent's permission manifest, so it is required:
  without it the agent would inherit every tool, MCP tools included.
  `tools = []` gives it none.
- Every agent body ends with a mezha paragraph asking the agent to list
  what it couldn't finish under `## Unresolved` (in English whatever the
  answer language); `mezha metrics` counts those per week.
- Claude Code turns agent memory off together with auto memory:
  `autoMemoryEnabled = false` or `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1` leaves
  agents without their memory, and verify warns about it.
- An agent with `memory` reads `.claude/agent-memory/<name>/MEMORY.md` (or
  the local scope for PHI) but can't write it: mezha takes back the Write and
  Edit tools Claude Code would add, and denies the path. Local memory must
  be git-ignored; `verify` fails if it isn't.
- Nothing in a frontmatter value may contain `---`: Claude Code ends the
  frontmatter at the first one. Nor control or hidden characters
  (zero-width, bidi controls, tag characters), which could make a
  description read one way to you and another to Claude.
- Claude reads a body as instructions, so compile scans it: hidden
  characters, secrets, chat-template tokens, remote images and raw HTML
  (comments included) outside code, and, in a skill, `` !`cmd` `` or a
  ```` ```! ```` fence refuse it. Phrases that read like instructions to
  a model are warnings. So are links to other hosts, whose content can
  change after you review the body; with `policy.fetch_allow` set, a link
  to a host it doesn't list refuses the body. Copy what Claude needs into
  the body instead of linking it.
- Agent, skill, rule or command files under `.claude/` that mezha doesn't
  generate are reported by `verify`, since they skip mezha's checks.

## Dreams

`mezha dream` is the only way agent memory changes
([ADR-0004](docs/adr/0004-memory-changes-only-through-dreams.md)). Run it in
your own terminal; it refuses inside Claude Code.

```bash
mezha dream --dry-run
```

```bash
mezha dream --role implementer --since 3d
```

For each agent with memory (or each `--role`), it:

1. **Collects the role's runs** from Claude Code's transcripts
   (`~/.claude/projects/`, or `$CLAUDE_CONFIG_DIR/projects/`): subagent runs
   and sessions started with `claude --agent <role>`, in this project and its
   worktrees, that ended after the role's last dream on this machine (or
   `--since`; 7 days the first time). Each run becomes a digest: the task,
   failed tool calls, the final message and its `## Lessons`, and your next
   message. Secrets and hidden or control characters are redacted; when the
   spec has PHI anywhere, email addresses, phone numbers, record numbers and
   dates of birth are too.
2. **Runs a dreamer**: `claude -p --restricted` with Read, Grep, Glob, Edit
   and Write only, no CLAUDE.md, no auto memory, no MCP servers, no settings
   files but managed ones, and one allow rule: a staged copy of the role's
   memory. It reads the project in a worktree of `origin/HEAD` (or `--base`)
   and its digests on stdin. mezha stops it if Claude Code reports other
   tools, MCP servers or another permission mode.
3. **Reviews the staged copy itself**: flat `*.md` files only, no
   `CHANGELOG.md`, no symlinks, the worktree untouched, and nothing hard in
   the added lines: hidden or control characters, secrets, remote images or
   HTML, chat-template tokens, and PHI when the spec has PHI. Any of these
   refuses the dream: nothing is committed or applied, and the workspace
   stays for you to read. Instruction-like phrases ("ignore previous
   instructions", `--no-verify`) are shown for you to judge, since real
   lessons quote them too.
4. **Delivers**:
   - project memory: a commit per role on a new branch `mezha/dream-<time>`,
     holding exactly the bytes mezha reviewed plus a `CHANGELOG.md` entry.
     mezha prints the `git log`, `git push` and `gh pr create` commands and
     pushes nothing;
   - local and user memory: the diff, applied when you type `y`. Without a
     terminal, mezha leaves a patch and applies nothing.

A dream's workspace is `~/.mezha/dreams/<repo>/<time>/`: the digests
(`inbox/`), the staged memory, the PR body, patches, and the worktree while
a dream runs or after a refusal. Sandboxed commands can't write there and
sessions may not read it. The five newest finished dreams are kept. The
repository's git hooks don't run during a dream.

Settings, in `[memory]`: `dream_model` (default `sonnet`),
`dream_budget_usd` per role (default 1.0) and `dream_max_turns` (default
40). Claude Code checks the budget between turns, so a dream can spend a
turn's worth past it. `dream_policy` in an agent's `memory` picks what the dreamer keeps:
`lessons` (the default: "avoid X because Y, seen N times"),
`verified-facts` (only facts it checked, with `file:line`) or
`attack-patterns-only` (patterns that found real bugs).

Agents load memory as instructions, so give it owners: add
`/.claude/agent-memory/ @your-team` to CODEOWNERS and require code owner
reviews on the default branch. `verify`'s `dreamer` check warns until
CODEOWNERS covers it, and fails on hidden characters, secrets or remote
images in memory.

The dreamer uses your Claude Code login. `--restricted` ignores your user
settings, so mezha carries over provider settings from their `env`
(`ANTHROPIC_*`, Bedrock, Vertex, proxies, CA certificates) and the
`apiKeyHelper`-style helpers, and lists what it carried. Unattended runs
(step 2c) will use `CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY`.
Installed Claude Code mods and plugins still load, and mezha lists them.

The scans are patterns: they reduce PHI and injection risk, they don't
remove it. Read every dream diff. For PHI, local scope is the boundary.

## Scheduling dreams

Set `dream_schedule = "nightly"` (with `dream_at = "03:00"`, local time) or
`"cron"` (with `dream_cron = "15 2 * * 1-5"`) in `[memory]`, then print a
snippet for your scheduler:

```bash
mezha dream --schedule launchd
```

- **launchd** (macOS): a LaunchAgent plist and the `launchctl` commands.
  It runs in your login session, so it uses your keychain login. A dream
  missed while the Mac slept runs once on wake; nights it was off are
  skipped.
- **systemd** (Linux, WSL2): a user service and timer with
  `Persistent=true`, which catches up after a boot. `loginctl
  enable-linger` lets it run while you're logged out. Claude Code reads its
  login from `~/.claude/.credentials.json`.
- **cron**: one crontab line. It doesn't run missed jobs, and on macOS it
  may not reach your keychain, so prefer launchd there.

launchd and systemd take `nightly` only; a cron expression needs the cron
kind. Windows Task Scheduler comes with native Windows in phase 4.

The snippet runs the `mezha` on your PATH directly, not through a shell,
and refuses one in a directory an agent can write: that would give an agent
a nightly unsandboxed run. It sets PATH (and `CLAUDE_CONFIG_DIR` if you use
it), and warns about provider variables set only in your shell, which a
scheduled run won't have. Move those into the `env` of your user settings.
For a machine nobody logs in to, `claude setup-token` makes a long-lived
token; keep `CLAUDE_CODE_OAUTH_TOKEN` in your own secret store, never in a
snippet or under `~/.mezha`, which sessions can read.

`mezha dream --scheduled`, the mode the snippet runs:

- dreams project memory only; local and user memory need you at a terminal;
- skips a role whose last dream is still pending (its branch exists and
  hasn't landed), so branches don't pile up and conflict;
- stops while a refused dream's worktree is still there, for you to read;
- doesn't use `awsAuthRefresh` or `gcpAuthRefresh`, which may wait for a
  browser;
- records metrics.

Only one dream of a project runs at a time (a `flock` on
`~/.mezha/dreams/<repo>/dream.lock`, released when the process ends however
it ends). Every dream writes `last-run.json` next to it. `mezha metrics`
shows it, and verify's `dreamer` check warns when the last scheduled dream
failed. Output goes to `schedule.log` in the same directory.

## Metrics

```bash
mezha metrics --since 30d
```

It reads the project's transcripts and the store under
`~/.mezha/metrics/<repo>/`, and changes nothing. `--record` (and every
dream) adds to the store, which keeps the history after Claude Code
deletes old transcripts (`cleanupPeriodDays`, 30 by default). The store is
JSON Lines, one object per line: counts, ids, times, costs and hashes,
never transcript text.

| Figure | What it is |
|---|---|
| Cost | Claude Code's own estimate per session (`cost-state`), minus what a resumed or forked session copied from its parent. A session still running has none yet and isn't averaged. Dreams' cost is separate. |
| Follow-up prompts per session | Your prompts after the first. A proxy for rework, per session, not per task. |
| Re-runs | Another run of the same agent in a session after one of your prompts that followed its last run. Parallel runs don't count. |
| Unresolved per week | Items in agents' last `## Unresolved` section ("None" counts nothing), by ISO week. |
| Dreams without edits | A dream's memory change (its patch-id, `CHANGELOG.md` left out) landing as is on the base branch's first-parent history: through a merge commit, a rebase or a squash. A landing commit that names the dream's stamp but carries another change is "with edits". A dream whose branch is gone and that hasn't landed is "dropped". The share counts merged dreams. It is as fresh as your last fetch. |

Not measured: returns from human review (it needs PR data; phase 5).

### A/B runs

```bash
mezha metrics --ab tasks.toml --repeat 3
```

```toml
[ab]
model = "sonnet"          # optional
budget_usd = 2.0          # per session
max_turns = 40
timeout_minutes = 20

[[task]]
name = "parser-test"
prompt = "Add a unit test for the parser's error path."
agent = "implementer"           # a spec agent with project memory, or local non-PHI memory
check = "cargo test -p parser"  # exit 0 = passed
```

Each task runs as its agent (`claude -p --agent`) twice per repeat, with the
order alternating: once in a worktree of the base with the agent memory as
committed (plus local memory), and once with `.claude/agent-memory`
removed. Both worktrees get the same neutral commit, sit under the system
temp directory with neutral names, and run with the project's own
settings, sandbox and hooks in `acceptEdits`. Sessions can read auto memory
but not write it: every worktree of a repository shares it, and turning it
off would turn agent memory off too. User memory, CLAUDE.md and the model
are the same in both.

The tasks file's path is from the current directory, not the project. The
base (`origin/HEAD`, else `HEAD`) must hold each task's agent file and,
for project memory, some committed memory; local memory must not be empty.
Without the agent file Claude Code doesn't know the agent, and without
memory both variants run the same, so mezha refuses before asking about
money: run `mezha compile`, commit `.claude/`, and merge a dream first.

A check runs code the agent just wrote, so it runs in srt with the
project's sandbox settings. `--unsandboxed-check` runs it in your own
process instead, and the run says so. mezha prints every check and the most
the run can cost, and asks first (`--yes` skips the question). Results,
capped diffs and `report.md` go to `~/.mezha/metrics/<repo>/ab-<time>/`.
Below `--repeat 3` the report claims no difference. The A/B compares memory
with emptied memory; it doesn't say what mezha costs against Claude Code
without it.

## Skill evals

```bash
mezha skill eval rust-conventions --repeat 3
```

It reads the skill's cases from `mezha/evals/<skill>.toml` (or `--cases
FILE`). `mezha/` is behind an ask rule and the sandbox, so an agent can't
quietly rewrite them.

```toml
[eval]
model = "sonnet"       # optional
budget_usd = 1.0       # per session
max_turns = 30         # per task session
trigger_turns = 4      # turns a trigger run gets to load the skill
timeout_minutes = 15

[[trigger]]
prompt = "Add a timeout variant to the parser's error type."
should_trigger = true

[[trigger]]
prompt = "Summarise the README."
should_trigger = false

[[task]]
name = "timeout-error"
prompt = "Add a Timeout error to src/error.rs, with a test."
check = "cargo test -q"        # exit 0 = passed
expect = ["(?i)timeout"]       # the final message matches each
reject = ['unwrap\(\)']        # and none of these
```

- **Triggers** run with the skill only. A run loaded the skill when, within
  `trigger_turns`, Claude called the Skill tool for it or read its
  `SKILL.md`, and the call succeeded. The report gives precision (loads
  that were wanted) and recall (wanted loads that happened), against the
  80% precision target in section 7 of the plan. List prompts of both kinds.
- **Tasks** run with the skill and without it, the order alternating, as
  in A/B runs. A task passes when its check passes and its patterns hold;
  with neither, when the session succeeds. The report says how often the
  skill really loaded in runs that had it: a run that didn't load it says
  nothing about its content.
- The skill comes from `mezha.toml` and its body file as they are now,
  without `mezha compile`; the rest of the project from `origin/HEAD`, else
  `HEAD`, or `--base`. Without the skill, its directory and body file are
  gone. In both, the case files are gone and the same neutral commit is on
  top.
- Every run is a fresh clone of the repository (`git clone --shared`, its
  remote removed), not a worktree: in a linked worktree Claude Code reads
  the project's skills from the main checkout, so a skill removed from the
  worktree still loads. The clone, and the directory Claude Code makes for
  it under `~/.claude/projects`, are removed after the run; its commits
  never reach your repository.
- Sessions run as in A/B runs: the project's settings, sandbox and hooks,
  acceptEdits, checks in srt unless `--unsandboxed-check`. Your own skills
  and plugins load in both variants and compete for the trigger, so a
  colleague's numbers may differ. The project's auto memory doesn't load:
  each clone has its own, empty one.
- Command skills are refused, since Claude never loads them on its own. If
  a skill with the same name loads in a run without the project's, the eval
  stops: a user or plugin skill shares its name.
- `--only triggers` or `--only tasks` runs one kind, for instance while you
  work on a description.
- **Manifest.** Once the skill has loaded, every tool Claude calls is
  checked against the skill's `allowed_tools`: a tool it doesn't list, or a
  Bash command none of its `Bash(...)` scopes matches. The report's
  Manifest section lists them and marks those that reach outside the
  sandbox (WebFetch, WebSearch, MCP tools).

mezha prints the most the eval can cost and asks first (`--yes` skips the
question). Rows go to `skill-evals.jsonl` in the metrics store (counts, a
hash of each prompt, never its text, and the fingerprint of the `SKILL.md`
measured, the model asked for and the tools used; `mezha verify` warns when
a skill has changed since its last eval); the report and each task's final
message and diff go to `~/.mezha/metrics/<repo>/skill-<skill>-<time>/`.
`mezha metrics` shows the latest eval of each skill. Below `--repeat 3` the
report claims no difference between the variants. See
[ADR-0006](docs/adr/0006-skill-eval-own-runner-in-clones.md).

## The spec

`mezha.toml` follows section 4 of the plan. Unknown keys are errors. The
compiler refuses, among other things:

- an agent with all three Rule of Two properties (`untrusted_input`,
  `private_data`, `external_action`), unless `human_gate = "advisory"`;
- an agent without a `rule_of_two` list (an empty list is fine);
- unscoped `Bash` in a skill's `allowed_tools` (and `WebFetch`,
  `WebSearch` or an MCP tool there is a warning: while the skill is active
  they reach outside the sandbox without asking);
- an agent's `skills` entry that is neither a skill in the spec nor listed
  in `policy.external_skills` (personal skills by name, plugin skills as
  `plugin:skill`, each optionally pinned as `name@sha256:...` to the
  fingerprint verify prints), so nothing preloads unreviewed;
- PHI memory (`class = "phi"`, or a repository listed in `phi_repos`) with
  project or user scope;
- a knowledge skill whose description is under 40 characters or lacks
  "Use when";
- an agent without `tools` (`tools = []` is fine);
- an agent without a `description`, a body path outside `mezha/`, a tool
  scope other than on `Bash` or `Agent`, and frontmatter text containing
  `---`, control characters or hidden characters.

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

`crates/mezha-cli/tests/dream.rs` runs `mezha dream` end to end with a
stand-in `claude` that checks its arguments and plays a dreamer, against
fixture transcripts in a scratch home. `crates/mezha-memory/tests/memory.rs`
compares digests with `tests/fixtures/inbox-implementer` (rewrite them with
`MEZHA_BLESS=1`), and `scan_table.rs` lists what the scans must and must not
find.

`crates/mezha-cli/tests/real_dream.rs` runs one real dream against haiku
(about $0.02) with your Claude Code login, and removes what it puts in your
home afterwards:

```bash
MEZHA_REAL_DREAM=1 cargo test -p mezha --test real_dream -- --ignored --nocapture
```

What the dreamer's invocation was checked against (Claude Code 2.1.285,
haiku, step 2b spike):

- `system/init` lists exactly Edit, Glob, Grep, Read and Write, no MCP
  servers, and `dontAsk`.
- Write and Edit work in the `--add-dir` staged directory under
  `~/.mezha/dreams` with `Edit(//<dir>/*.md)`. A `.txt` file there, a file
  in the worktree, and reads outside the working directories are refused.
- A PreToolUse hook from `--settings` fires under `--restricted`, before the
  permission check, and exit 2 blocks. The real `dream-guard` refused
  `CHANGELOG.md` and a `..` path.
- CLAUDE.md in the project and its parent, `.claude/rules` and auto memory
  reach a plain `claude -p`. Each of `--restricted` and
  `CLAUDE_CODE_DISABLE_CLAUDE_MDS=1` keeps all of them out on its own;
  `--system-prompt` doesn't. `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1` keeps auto
  memory out.
- `~/.claude/file-history` gains nothing.
- A tiny budget ends in `error_max_budget_usd` (`budget_exhausted`), and
  `--max-turns` in `error_max_turns`. A failed login ends in `success`
  with `is_error: true`, which is why mezha checks both.
- An `apiKeyHelper` in `--settings` runs under `--restricted` and takes
  precedence over the claude.ai login.
- A session started with `--agent X` records
  `{"type":"agent-setting","agentSetting":"X"}`, which the inbox reads.

`crates/mezha-cli/tests/dream.rs` also covers the printed schedules,
`--scheduled`, the lock, `last-run.json` and `metrics --record`;
`crates/mezha-cli/tests/ab.rs` runs the A/B runner with stand-in `claude`
and `srt`, where the check passes only with memory. `real_ab.rs` runs one
real A/B task against haiku (about $0.04): the agent's memory holds a
codename the task asks for.

```bash
MEZHA_REAL_AB=1 cargo test -p mezha --test real_ab -- --ignored --nocapture
```

`crates/mezha-cli/tests/skill_eval.rs` runs `mezha skill eval` with stand-in
`claude` and `srt`. The stand-in loads the skill only when its `SKILL.md` is
in the clone, and knows the codename only from it, so every trigger comes
out right and the task passes only with the skill. `real_skill_eval.rs` runs
one real eval against haiku (about $0.17): a skill holds a codename, two
prompts should load it and two shouldn't, and the task asks for the
codename.

```bash
MEZHA_REAL_SKILL_EVAL=1 cargo test -p mezha --test real_skill_eval -- --ignored --nocapture
```

Found in step 3a (Claude Code 2.1.285, haiku):

- In a linked git worktree, project skills load from the main checkout
  ("Base directory for this skill: <main checkout>/.claude/skills/..."),
  while agent memory loads from the worktree. Skill evals run in clones;
  the A/B runner's emptied memory is unaffected.
- The `skills` and `slash_commands` lists in `system/init` leave out skills
  with `user-invocable: false`, mezha's default for knowledge skills;
  Claude still loads them with the Skill tool. A skill with `paths` is
  listed (a `commands_changed` event) only after the session reads a
  matching file.
- Headless, in acceptEdits with `--permission-prompts none`, the Skill tool
  runs without a denial. A missing skill fails with `is_error: true`
  ("Unknown skill"), and so does a Read of a missing file.
- haiku sometimes reads a skill's `SKILL.md` with Read instead of calling
  the Skill tool.

Found in step 2c: run as `claude -p --agent X`, an agent gets its memory
only while auto memory is on. `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1` or
`autoMemoryEnabled: false` turn agent memory off too; a deny rule on
`Edit(~/.claude/projects/**)` keeps auto memory from being written while
agent memory still loads.

The workspace has eight crates: `mezha-spec`, `mezha-render`, `mezha-hooks`,
`mezha-broker`, `mezha-verify`, `mezha-memory`, `mezha-metrics` and `mezha`
(the CLI). The boundary scenarios
verify must fail on live in `crates/mezha-verify/tests/boundary.rs`.

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
- [ADR-0005](docs/adr/0005-metrics-ab-and-scheduled-dreams.md): metrics, A/B
  runs and scheduled dreams.
- [ADR-0006](docs/adr/0006-skill-eval-own-runner-in-clones.md): skill evals,
  a runner of mezha's own in clones of the project.
- [ADR-0007](docs/adr/0007-owasp-agentic-skills-top-10.md): conforming to
  the OWASP Agentic Skills Top 10.
- [OWASP Agentic Skills Top 10](docs/owasp-ast10.md): every mitigation in
  AST01–AST10, and what mezha does about it.
- [Porting inventory](docs/porting-inventory.md): what comes from ocgen, and
  what doesn't.
