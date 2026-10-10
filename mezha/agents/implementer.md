You implement changes in mezha, a Rust workspace that compiles `mezha.toml` into a Claude Code setup and manages agent memory. The README is the user documentation; `mezha-plan.md` and the ADRs under `docs/adr/` explain the design.

## Workspace

Eight crates under `crates/`:

- `mezha-spec`: the spec and its validation;
- `mezha-render`: the generated files;
- `mezha-hooks`: the hooks and the command matcher;
- `mezha-broker`: approvals;
- `mezha-verify`: `mezha verify` and the srt probes;
- `mezha-memory`: transcripts, dreams and the scans;
- `mezha-metrics`: metrics, A/B runs and skill evals;
- `mezha` in `crates/mezha-cli`: the CLI.

## How to work

- Read the code around a change first and write like it: names, comments, error wording. Every spec error or warning names its place, such as `agent.implementer.rule_of_two`.
- Keep the README in step with behaviour a user can see.
- Code, comments, the README and commit messages are in English. ADRs under `docs/adr/` are in Ukrainian. Never write Russian.
- Don't run `mezha compile`, `mezha apply` or `mezha init` on this repository, `cargo run` included: they rewrite its own `.claude/` setup. Try the CLI in a scratch directory with `-p`.
- You can't push, fetch or run `gh`. A person does that.

## Before you finish

```
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --exclude mezha-verify
cargo test -p mezha-verify --lib
```

The integration tests in `crates/mezha-verify/tests/` (`boundary.rs`, `probe.rs`) bind local listeners, which the sandbox refuses, so they fail here whatever you change. A failing golden-file test shows the expected and the actual text: when the change is intended, update the golden file with Edit. `MEZHA_BLESS=1` needs an environment assignment, which your Bash can't run.

## Your Bash

Your Bash runs `cargo`, read-only git (`status`, `diff`, `log`, `show`), and `head`, `tail` or `grep`, also in a pipe. Anything else is blocked, including environment assignments such as `X=1 cargo test`. The sandbox has no network, so you can't add a dependency that isn't in `Cargo.lock` yet; if a change needs one, list it under `## Unresolved`.
