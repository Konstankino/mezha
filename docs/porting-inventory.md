# Porting inventory: ocgen → mezha

Mezha is written from scratch ([ADR-0001](adr/0001-governance-and-memory-not-a-generator.md)).
ocgen (v0.9.1) is a reference for behaviour and
for the edge cases it already fixed; no module is copied. This file maps every
item from `mezha-plan.md` sections 5.1 and 10 to its place in mezha.

## Map

| ocgen item | Where in ocgen | Mezha | Phase | Approach |
|---|---|---|---|---|
| Rust hooks with a protocol number | `src/hooks.rs` (`PROTOCOL`, `run`, `Outcome`, `Guard`) | `mezha-hooks` | Week 1: approval gate. Rest: 1 | Rewritten. One process, `--protocol` argument, `\|\| exit 2`, exit 0 or 2 only, no sh twins ([ADR-0002](adr/0002-fail-closed-hook-command.md)). The worker/confidence, task, plan, risk, loop-guard, WebFetch and config-audit gates follow in phase 1. |
| Approval store | `src/approval.rs` | `mezha-broker::approvals` | Week 1 | Rewritten. SHA-256 key, JSON record with the root, repo root found without spawning git. |
| High-impact command patterns | `src/risk.rs` (20 regex alternatives) | `mezha-hooks::{shell, matcher}` | Week 1 | Replaced by a small shell reader plus a word scan; gates come from `policy.permissions_ask`. |
| `approve` command | `src/overview.rs` `run_approve` | `mezha approve` | Week 1 | Rewritten; refusal is a pure function of the environment and the TTY. |
| `doctor`: fingerprints, backups, per-file review | `src/render.rs` (`fingerprint`, `Fence`, `plan_changes`, `backup`), `src/wizard/mod.rs` `run_doctor` | `mezha-render` (`plan`, `write`), `mezha compile/diff/apply` | Week 1 engine; `doctor` in 1 | Rewritten: SHA-256, all-or-nothing plan, state paths checked against an allowlist. Interactive per-file review comes with `doctor`. |
| `verify` skeleton | `src/verify.rs` (`Layers`, `Probe`, `claude_validate`) | `mezha-verify` | 1 | Reference for settings layering, hook probes and `claude plugin validate`. New: `--json`, `git push --dry-run` auth failure from the sandbox, branch protection, dreamer checks. |
| `/inquire` with ledger and HTML viewer | `src/notes/*`, `templates/claude/commands/inquire.md.j2` | not ported | 2 | Step 2b's inbox reads Claude Code's transcripts directly, so no ledger feeds it. Revisit only with a memory reason. |
| `/intent`: ADR, approvers, CODEOWNERS, tone check | `src/intent.rs`, `src/render/codeowners.rs`, `templates/claude/intent/*` | `mezha-verify` (`dreamer` reads CODEOWNERS) | 2 | mezha doesn't write CODEOWNERS, which is the project's own file: verify warns until it owns `.claude/agent-memory/`. ADR drafting is re-evaluated. |
| Instructions vs answers language | `src/render.rs` (`response_language`, `response_section`) | `mezha-spec` (`project.languages`), `mezha-render` | 3 | Parsed; not rendered into agent bodies (a subagent answers the parent model, not the user). Belongs in the CLAUDE.md roster, which isn't rendered yet. |
| `install.sh`, `install.ps1`, Scoop manifest | repo root, `scoop/ocgen.json` | repo root | 1 | Rename `OCGEN_*` to `MEZHA_*`, drop the pre-v0.5 missing-checksum fallback, fix the substring `PATH` check in `install.ps1`. |
| Release workflow with `SHA256SUMS` | `.github/workflows/release.yml` | same path | 1 | Same shape: build per target, publish job alone has `contents: write`. |
| Override templates (simplified) | `src/templates.rs` | `mezha-render` | 1 | Gate templates stay non-overridable. |
| Plugin output | `templates/claude/plugin/*` | `mezha compile --plugin` | 1 | `plugin.json` and `marketplace.json` built with serde, not text templates. |

## Not ported

From plan section 10: the wizard, providers, the OpenCode target, the
five-agent default, sh twins of hooks, and the text gate presented as security.
Also left behind: the notes viewer and its Milkdown editor, `recap`,
archetypes and their TOML seeds.

## ocgen defects not to repeat

- **Hooks that fail open.** With both the binary and the sh twin missing the
  command exits 127, which Claude Code treats as non-blocking. Malformed stdin
  JSON was parsed as `Null`, so every field read empty and the approval gate
  allowed the call. Mezha: `|| exit 2`, and unparseable input exits 2.
- **Two processes per hook call** (`ocgen hook --check`, then the hook).
- **`verify` says "too old" for any protocol mismatch**, including a newer binary.
- **FNV-1a fingerprints.** Fine for "did someone edit this", useless as a
  tamper check. Mezha: SHA-256 over LF-normalized content.
- **YAML frontmatter written without escaping**: a description containing
  `": "` breaks strict parsers. Mezha (step 2a): block-style frontmatter
  whose every scalar is JSON-escaped by `serde_json`, a refusal of `---`
  (Claude Code ends the block at the first one) and of characters YAML
  forbids raw, and a round-trip test through a YAML parser.
- **JSON rendered from text templates**: a `"` in a display name broke
  `plugin.json`. Mezha: serde_json only.
- **Repo root from `git rev-parse --git-common-dir`.** Wrong for submodules,
  and it spawns git inside the hook, where a timeout fails open. Mezha: walk
  `.git` and `commondir` without spawning anything.
- **`approve` refused when any `CLAUDE_CODE_*` variable was set**, which
  locks out people who export `CLAUDE_CODE_USE_BEDROCK`. Mezha: only
  `CLAUDECODE` and `CLAUDE_CODE_ENTRYPOINT`.
- **Case-insensitive name uniqueness checked only in wizard prompts**, not when
  loading state. Mezha: names are lowercase-only, so TOML's duplicate-key
  check covers it.

## ocgen layers revisited in phase 1

See [ADR-0003](adr/0003-push-boundary.md).

- **Withholding credentials from sandboxed commands: kept.** ocgen wrote
  `sandbox.credentials` into project settings, and Claude Code honours those
  `deny` entries: it merges them from every scope it loads, and no scope can
  remove one. They are dropped only when the project source is excluded with
  `--setting-sources` (v2.1.246 and later). mezha renders the same block,
  plus matching `Read(...)` deny rules, because the Read tool runs outside
  the sandbox.
- **The keychain reset (`GIT_CONFIG_*` in settings `env`): kept, as
  advisory.** On macOS the sandbox can't hide the keychain (ocgen commit
  `1efb776`), and a command can still name a helper itself.
- **The git pre-push hook: dropped.** `git push --no-verify` and
  `git -c core.hooksPath=/dev/null push` skip it, so it is one more advisory
  layer, not part of the boundary.

## Still not rendered (after step 2a)

Step 2a renders `.claude/settings.json`, agents, skills and rules. These
items from `mezha-plan.md` §3.2 are still to come: `.gitattributes` (LF for
`.claude/**`), `.worktreeinclude`, the CLAUDE.md roster and protocol, an
output style, and the plugin output (`compile --plugin`). Plugin agents
ignore `hooks`, so the `agent-bash` hook will need another carrier there.
