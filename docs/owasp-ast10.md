# OWASP Agentic Skills Top 10: how mezha conforms

This maps every preventive mitigation in the
[OWASP Agentic Skills Top 10](https://github.com/OWASP/www-project-agentic-skills-top-10)
(AST01–AST10, August 2026 edition) to what mezha does about it. The
mitigations are paraphrased; read the whitepaper for the full text. The
decisions behind this mapping are in
[ADR-0007](adr/0007-owasp-agentic-skills-top-10.md).

mezha is a governance layer for Claude Code projects, not a registry or a
marketplace. It compiles a project's agents, skills and rules from
`mezha.toml`, proves the boundary with `mezha verify`, and lets agent memory
change only through reviewed dreams. Mitigations aimed at registries,
publishers and enterprise tooling are out of its scope. Where they have a
local equivalent, the row names it.

| Status | Meaning |
|---|---|
| **Boundary** | Enforced by the OS sandbox, Claude Code's permission system or the forge, whatever the agent says. |
| **Integrity** | `compile` refuses, or `verify` fails, when it is missing or changed. |
| *Advisory* | Patterns, prompts or text matching: they help, and they can be got around. |
| Evidence | A record for people to read afterwards. |
| Partial | Some of the mitigation, as the row says. |
| Hook | mezha's fail-closed hook decides on a structured field, such as a URL's host, not on command text. A tool it doesn't see gets around it. |
| Out of scope | Belongs to a registry, a publisher, Claude Code itself or enterprise tooling. |

## AST01 Malicious Skills

| Mitigation | Status | In mezha |
|---|---|---|
| Sign published skills, bound to a revocable publisher identity; reject unsigned ones | Out of scope | mezha publishes nothing. A project's skills come from its repository, so their provenance is git history, branch protection and CODEOWNERS. `branch-protection` warns when a protected default branch takes unsigned commits. |
| Merkle-root signing of registries | Out of scope | No registry. |
| Layered scanning for payloads, hidden or obfuscated instructions and natural-language manipulation | *Advisory* | `compile` scans every agent, skill and rule body (`mezha-memory/src/scan.rs`). `verify`'s `bodies` check scans every file that loads from the project, the user's directory and enabled plugins. |
| Run skills in a sandbox | **Boundary**, Partial | Shell commands run in Claude Code's sandbox, strict and on by default. File tools, WebFetch, MCP servers and hooks run outside it (README); the gate keeps WebFetch to `policy.fetch_allow` (AST05). |
| Audit skill actions through structured logging | Evidence | The approval gate records every tool call before it runs, and a second hook records how it ended (`~/.mezha/audit`, README "Audit log"). |
| Reputation systems | Out of scope | |
| Protect identity files (MEMORY.md and the like) | **Boundary**, *Advisory* | Agent memory: deny rules and sandbox `denyWrite` (ADR-0004). Auto memory: a deny rule (`memory.auto_memory`). `CLAUDE.md`, `CLAUDE.local.md` and `AGENTS.md`: ask rules (advisory). |
| Monitor for cognitive degradation at runtime | Partial | Dreams, A/B and eval runs have turn and budget limits; `mezha metrics` tracks rework proxies and unresolved items. There is no in-session monitor. |
| Quarantine memory writes and validate them before commit | **Boundary**, Integrity | Memory changes only through `mezha dream`: staged, scanned, reviewed by a person, and committed from the bytes mezha read. |
| Non-overridable trust boundaries; review before privileged actions | **Boundary**, *Advisory* | Sandbox, withheld credentials, `deniedDomains`, Rule of Two at compile time; the approval gate is advisory. |
| Hash-pin installed skills; alert on change | Integrity | Generated files must match a fresh render (`settings-intact`). An external skill listed in `policy.external_skills` is pinned to its directory's fingerprint (`name@sha256:...`), and verify fails when any file in it changes. |
| Never auto-run "prerequisites" | **Boundary** | Settings set `disableSkillShellExecution`, so skills can't run `` !`cmd` `` when they load, and `compile` refuses it in bodies. |
| Secure manifests that declare permissions | Integrity | An agent's `tools` is required; Bash scopes, `allowed_tools` and frontmatter text are checked. |

## AST02 Supply Chain Compromise

| Mitigation | Status | In mezha |
|---|---|---|
| Signing identity covering `SKILL.md` and every resource file | Partial | Commits carry the identity (`branch-protection` warns when unsigned commits are allowed). `verify` fingerprints every file in a skill's directory. |
| Transparency logs for registry operations | Out of scope | |
| Pin nested dependencies to hashes | Partial | mezha's own: `Cargo.lock` with `--locked`, srt from a lockfile with `npm audit signatures`, CI actions pinned to commit SHAs. Skills mezha generates carry no dependencies; plugins' dependencies aren't checked. |
| Treat repository configuration as executable code | Integrity | `project-config` fails on shared settings that run a command, install plugins or redirect Claude's traffic, and on any approval of every `.mcp.json` server. Settings set `enableAllProjectMcpServers: false`. |
| Scan recursive dependency trees | Partial | Every file in a skill's directory is scanned; package dependencies aren't resolved. |
| An internal allowlist of skills | Integrity | `policy.external_skills`: agents may preload only listed or defined skills, `inventory` warns about any other that loads, and a pinned one fails when it changes. |
| Revocation infrastructure | Out of scope | Locally: take a skill off `external_skills` and verify warns while it still loads. |

## AST03 Over-Privileged Skills

| Mitigation | Status | In mezha |
|---|---|---|
| Require a permission manifest | Integrity | `compile` refuses an agent without `tools`. |
| Per-skill scoped credentials | **Boundary** | Sandboxed commands get no credentials at all (ADR-0003). |
| Flag write access to identity files | **Boundary**, *Advisory* | As in AST01; deny rules win over a skill's `allowed_tools`. |
| Enforce permissions at runtime | **Boundary**, *Advisory* | Sandbox and deny rules; an agent's Bash scope is an advisory hook. |
| Bind authorization to the approved task | Partial | `mezha approve` lifts the gates for one repository for 1–1440 minutes, not per task. The broker with short-lived tokens is planned. |
| Domain allowlists, not network on/off | **Boundary**, Hook | `egress_allow` and `deniedDomains` for sandboxed commands; `policy.fetch_allow` for WebFetch, through the gate. |
| Check declared permissions against behaviour in a sandbox | Evidence | Skill evals run in clones with checks in srt and record every tool Claude called while the skill was loaded that its `allowed_tools` doesn't declare; the report's Manifest section lists them. |
| Instruction hierarchy; skill and tool output are data | Partial | Dream digests reach the dreamer fenced as data. Inside sessions this is Claude Code's job. |
| Each skill in a delegation chain checks the original caller | Out of scope | Subagent delegation is Claude Code's. Rule of Two limits what any one agent combines. |
| Explicit consent for persistent state changes | **Boundary**, *Advisory* | Memory through dreams only, auto memory denied; instruction files ask. |
| Confirm deletion and unlisted binaries | *Advisory* | `permissions_ask` gates; the sandbox limits where commands write. |

## AST04 Insecure Metadata

| Mitigation | Status | In mezha |
|---|---|---|
| Safe parsers and an allowlist of keys | Integrity | `mezha.toml` is TOML with `deny_unknown_fields`; frontmatter is written as JSON scalars, never from templates. |
| Validate against a schema before use | Integrity | `schema` is read first, then every compiler rule runs. |
| Static analysis for ASCII smuggling, base64 and zero-width text | Integrity, *Advisory* | Hidden characters in frontmatter text are a compile error; bodies are scanned, phrases matched again on a folded copy, base64 decoded two layers deep. |
| Check declared permissions against runtime behaviour | Evidence | As in AST03. |
| Parse skill files with least privilege | Out of scope | mezha parses only its own spec; verify reads other skills as text and runs nothing from them. |
| Brand protection and metadata provenance in registry UIs | Out of scope | |

## AST05 Untrusted External Instructions

| Mitigation | Status | In mezha |
|---|---|---|
| Pin referenced content by hash and re-verify on load | Integrity, Hook | WebFetch hands Claude a model's reading of a page, not its bytes, so no hash can be checked when it loads. Instead, with `policy.fetch_allow` set, a body may link only to listed hosts (`compile` and `bodies` fail otherwise), and the gate blocks WebFetch to any other host. |
| Verify immediately before the model reads it | Hook | The gate checks each WebFetch's host before the call runs. |
| Inline rather than fetch | *Advisory*, Integrity | `compile` says to copy what Claude needs into the body; with `fetch_allow` set, links elsewhere are refused. |
| Allowlist reference domains | Hook | `policy.fetch_allow`, the host read from the URL as a browser would. Without it, compile warns. |
| Audit references transitively | Hook | A redirect to another host comes back as a new WebFetch call, so every step of a chain must be on the list. |
| Fleet-wide visibility of referenced sources | Evidence | `verify --json` lists each file's linked hosts. |
| Rescan continuously | Integrity | `verify` rescans on every run. |
| Keep instructions and data apart | Partial | As in AST03. |

## AST06 Weak Isolation

| Mitigation | Status | In mezha |
|---|---|---|
| Isolation by default; host mode as an explicit, documented opt-in | **Boundary** | The sandbox is on by default, can't fall back to running unsandboxed, and refuses unsandboxed retries; `policy.sandbox = false` is the opt-in and warns. |
| Bind control interfaces to localhost, with authentication | Integrity | mezha runs no server; the broker's requirement is recorded in `mezha-broker` (ADR-0007). `project-config` fails on a `.mcp.json` server on this machine that takes calls without authentication. |
| seccomp or AppArmor profiles | Out of scope | Claude Code's sandbox (Seatbelt, bubblewrap). |
| One process per skill | Out of scope | A skill is a prompt to one agent process. |
| Restrict hot reload and workspace precedence | **Boundary**, Integrity | The sandbox can't write `.claude/skills`; edits ask; `inventory` fails when a personal skill shadows a project skill. |
| Authenticate and rate-limit WebSocket connections | Out of scope | |
| Separate writable state by agent | **Boundary**, Partial | Each agent's memory is its own and read-only in sessions; agents can read each other's memory (ADR-0004). |

## AST07 Update Drift

| Mitigation | Status | In mezha |
|---|---|---|
| Pin skills to content hashes | Integrity | As in AST01. |
| Verify signatures on every update | Partial | Signed commits, as in AST02. |
| Freeze mode, no hot reload in production | **Boundary** | Sandboxed commands can't change skills mid-session; edits ask. |
| Subscribe to advisories | Out of scope | `verify` requires a minimum Claude Code version. |
| A person approves each update | Integrity | `compile`/`diff`/`apply`, ask rules, CODEOWNERS. |
| Inventory with version, hash and last-verified time | Evidence | `verify --json`: `inventory` and `verified_at`. |
| Semantic check of changes, with people in the loop | *Advisory* | Body scans; dreams reviewed by a person. |

## AST08 Poor Scanning

| Mitigation | Status | In mezha |
|---|---|---|
| Behavioural scanners that judge intent with calibrated models | Out of scope | Deliberately none (ADR-0006, ADR-0007): scans stay advisory and deterministic. |
| Scan the code and language layers apart; parse shell as the shell does | *Advisory* | Prose is matched as text. Shell in code blocks and inline code is parsed with the hooks' shell reader, so quoting, empty expansions, variables and substitutions can't hide a download or a decode piped into an interpreter. |
| Score each progressive-disclosure tier on its own | Partial | Frontmatter text is checked by the compiler apart from the body. |
| Pipelines of several tools | Out of scope | |
| Scanner results are advisory, never the only gate | *Advisory* | Every scan is labelled advisory; the boundaries are elsewhere. |
| Re-scan continuously | Integrity | Every `verify` run. |
| Scan every file in the skill directory; record coverage as pass, fail or incomplete | Integrity | `bodies` and `inventory`: a binary, a symlink, a file over 1 MiB, or a limit reached is `incomplete`, never clean. |
| Match on a normalised view as well as raw bytes; decode embedded encodings within bounds | *Advisory* | Before phrases are matched again: hidden characters are stripped; fullwidth, mathematical and enclosed letters are made plain; Cyrillic and Greek lookalikes are folded inside words that mix them with Latin letters, and such words are flagged themselves. Base64 is decoded two layers deep, and deeper or oversized runs are flagged. |
| Suppression lists typed by direction | Out of scope | No suppression lists. |
| Treat the scanner's own model as injectable | Partial | No model scans. The dreamer is a model: it runs with five file tools, no MCP and a fixed mode, checked at start. |
| Report false positives against a benign corpus | Partial | `scan_table.rs` and `evasion.rs` hold benign text the scans must leave alone, Ukrainian and shell included; no published rates. |
| Treat URLs and credentials as context, not convictions | *Advisory* | Links are warnings; secrets are hard findings by design. |
| The model at each node is a security dependency | Partial | The dreamer's model is explicit (`memory.dream_model`); eval rows record the model asked for and Claude Code's version. |
| Tie each result to the skill digest, model and version | Evidence | Each eval row records the fingerprint of the `SKILL.md` it measured, the model and Claude Code's version; verify warns when a skill has changed since its last eval. |
| Agent Threat Rules | Out of scope | |
| Test against an adaptive adversary | Evidence | `tests/evasion.rs` runs published bypass techniques against the scan and lists the ones it misses; `matcher_table.rs` does the same for the gate. |

## AST09 No Governance

| Mitigation | Status | In mezha |
|---|---|---|
| A central inventory | Evidence | Per project: `mezha.toml` and `verify --json`. |
| Approval workflow for installs | Integrity | Generated files go through `compile`; external skills through `policy.external_skills`. |
| Restrict installation pathways | Partial | `project-config` fails on plugins and marketplaces in the shared settings; personal installs are listed. |
| Non-human identities with scoped credentials | Out of scope | Sandboxed commands get none. |
| Audit logging of skill actions | Evidence | The audit log, and the dream changelog and commits for memory. |
| Identity-first discovery of SaaS skills | Out of scope | |
| Permission drift as a signal | Integrity | `settings-layers` and `project-config` on every run. |
| CMDB, ITSM and CASB integration; offboarding | Out of scope | |
| Inter-agent hand-offs are trust boundaries | Partial | Rule of Two; dream digests are data. |
| Place the most injection-resistant model on acting nodes | Out of scope | |
| Bilateral receipts (admission and outcome, shared attempt id, policy version, denials recorded) | Evidence, Partial | All but signatures. Calls link through `prompt_id`, `agent_id` and the Agent call's `spawned_agent_id`; hooks see no parent before a call runs, so the link is in the outcome, not the admission. Signing with a key on the same machine would add nothing against its owner, and the boundary on `~/.mezha` already keeps the agent out. |

## AST10 Cross-Platform Reuse

| Mitigation | Status | In mezha |
|---|---|---|
| Adopt the Universal Skill Format | Out of scope | Still a proposal. `mezha.toml` is the manifest; see the mapping below. |
| Re-validate fully when porting | Out of scope | mezha generates for Claude Code only. Portable skills are phase 4. |
| Cross-registry threat intelligence | Out of scope | |
| Platform-independent content scanners | *Advisory* | `scan.rs` reads text, whatever the platform. |
| Normalise risk tier, permissions and signatures | Partial | The mapping below. |

### Universal Skill Format fields in mezha

| USF field | mezha |
|---|---|
| `name`, `description` | `[skill.<name>]`, `description` |
| `version`, `changelog` | The git history of `mezha.toml` and `mezha/skills/<name>.md` |
| `author.identity`, `author.signing_key`, `signature` | The commit's signature; `branch-protection` warns when it isn't required |
| `content_hash` | The fingerprint in `.claude/.mezha-state.json` and `verify --json`; for an external skill, its pin in `policy.external_skills` |
| `permissions.tools`, `permissions.shell` | `allowed_tools`, with Bash scopes; an agent's `tools` |
| `permissions.files` | Project-wide: `deny_reads` and the sandbox's `denyWrite` |
| `permissions.files.deny_write` for identity files | Agent memory and auto memory denied; instruction files ask |
| `permissions.network.allow` | Project-wide: `egress_allow` for commands, `fetch_allow` for WebFetch |
| `risk_tier` | Not declared by the author: Rule of Two is checked per agent |
| `scan_status` | `verify`'s `bodies` check and each inventory item's `scan` |
| `requires.binaries` | None |

## Known limits

Every mitigation above has a place, or a reason why not. What remains are
limits of the approach, not items waiting:

1. An instruction in plain prose gets past every scan; `evasion.rs` lists
   such cases. The boundary for them is the sandbox, the withheld
   credentials and a person reading each change.
2. `fetch_allow` covers WebFetch. WebSearch, and MCP tools that fetch, are
   outside it.
3. The gate is a hook: an installed Claude Code mod can override it unless
   managed settings deliver it (ADR-0002), and a hook that times out lets
   the call through.
4. Audit records aren't signed, and a subagent's link to its parent goes
   through the Agent call's outcome. Claude Code doesn't document that the
   `agentId` there is the `agent_id` hooks see.
5. The broker, and so its authenticated interface, isn't built yet.
6. The eval's Manifest section is a report, not a gate: knowledge skills
   rightly guide tools they don't grant.
