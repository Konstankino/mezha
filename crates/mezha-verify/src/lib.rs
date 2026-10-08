//! Boundary tests: checks that fail when the boundary is broken, not when a
//! matcher misses (`mezha-plan.md` section 3.4, ADR-0003).
//!
//! Step 1a reasons statically: from every settings scope, git's
//! configuration and what is known about the sandbox on each platform. It
//! never runs a credential helper, never touches the network, and never
//! runs a command found on disk.

mod checks;
pub mod creds;
pub mod ctx;
pub mod gitcfg;
pub mod hosts;
pub mod layers;
pub mod report;
pub mod runner;

use mezha_spec::SPEC_FILE;

pub use ctx::{Ctx, Platform};
pub use report::{Check, Kind, Report, Status};

#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Look only at committed project files (for CI): no user or managed
    /// settings, environment, global git config or platform tools.
    pub project_only: bool,
}

/// Why verify couldn't produce a report at all (exit code 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CantRun {
    NoSpec(String),
    Spec(String),
}

impl std::fmt::Display for CantRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CantRun::NoSpec(path) => write!(f, "{path} not found (run `mezha init`)"),
            CantRun::Spec(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for CantRun {}

pub fn verify(ctx: &Ctx, opts: &Options) -> Result<Report, CantRun> {
    let spec_path = ctx.root.join(SPEC_FILE);
    let text = std::fs::read_to_string(&spec_path)
        .map_err(|_| CantRun::NoSpec(spec_path.display().to_string()))?;
    let spec = mezha_spec::parse(&text).map_err(|e| CantRun::Spec(e.to_string()))?;
    let diagnostics = mezha_spec::validate(&spec);
    if diagnostics.has_errors() {
        let errors: Vec<String> = diagnostics.errors().map(ToString::to_string).collect();
        return Err(CantRun::Spec(format!(
            "{SPEC_FILE} has errors:\n{}",
            errors.join("\n")
        )));
    }
    let rendered = mezha_render::render(&spec, &text).map_err(|e| CantRun::Spec(e.to_string()))?;

    let layers = layers::Layers::load(ctx, opts.project_only);
    let claude = if opts.project_only {
        None
    } else {
        checks::sandbox::claude_version(ctx)
    };
    let sandbox = checks::sandbox::check(ctx, &layers, claude.as_deref(), opts);
    let git = gitcfg::GitConfig::read(ctx, opts.project_only).ok();
    let withheld = creds::Withheld::from_layers(ctx, &layers);
    let inventory = creds::inventory(ctx, &withheld, git.as_ref(), opts.project_only);
    let push = checks::push::check(&layers, git.as_ref(), &inventory, sandbox.in_effect, opts);

    let mut checks = vec![
        sandbox.check,
        push,
        checks::settings::check(ctx, &rendered, opts),
        checks::layers::check(ctx, &layers, opts),
        checks::hygiene::check(ctx),
        Check::skip(
            "branch-protection",
            "the default branch is protected",
            Kind::Boundary,
            "arrives in step 1b (needs gh)",
        ),
        Check::skip(
            "dreamer",
            "the dreamer can't run commands",
            Kind::Integrity,
            "arrives in phase 2",
        ),
        Check::skip(
            "plugin-validate",
            "claude plugin validate",
            Kind::Integrity,
            "no skills or agents are rendered yet",
        ),
    ];
    for check in &mut checks {
        check.detail = report::redact(&check.detail);
    }

    let mut notes = Vec::new();
    if ctx.var("CLAUDECODE").is_some() {
        notes.push(
            "running inside Claude Code: this environment differs from your own terminal's".into(),
        );
    }
    if opts.project_only {
        notes.push(
            "project files only: user and managed settings, the environment and credentials weren't checked"
                .into(),
        );
    }

    let mut report = Report {
        version: report::JSON_VERSION,
        mezha: env!("CARGO_PKG_VERSION"),
        hook_protocol: mezha_hooks::PROTOCOL,
        platform: ctx.platform.as_str(),
        claude_code: claude,
        mode: if opts.project_only {
            "project-only"
        } else {
            "full"
        },
        checks,
        summary: Default::default(),
        notes,
    };
    report.summarize();
    Ok(report)
}
