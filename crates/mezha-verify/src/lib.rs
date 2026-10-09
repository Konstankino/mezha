//! Boundary tests: checks that fail when the boundary is broken, not when a
//! matcher misses (`mezha-plan.md` section 3.4, ADR-0003).
//!
//! By default verify reasons statically: from every settings scope, git's
//! configuration and what is known about the sandbox on each platform. The
//! one thing it asks a server is branch protection, through the user's
//! `gh`, with queries only. `--probe` adds side-effect-free probes inside
//! `srt` ([`probe`]), and `--inside` looks from inside Claude Code's own
//! sandbox instead ([`inside`]). verify never runs a credential helper or a
//! program an agent could have put on PATH ([`Ctx::which_trusted`]).

mod checks;
pub mod creds;
pub mod ctx;
pub mod gitcfg;
pub mod hosts;
pub mod inside;
pub mod layers;
pub mod probe;
pub mod report;
pub mod runner;
pub mod scratch;

use mezha_spec::SPEC_FILE;

pub use ctx::{Ctx, Platform};
pub use report::{Check, Kind, Report, Status};

#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Look only at committed project files (for CI): no user or managed
    /// settings, environment, global git config or platform tools.
    pub project_only: bool,
    /// Also run side-effect-free probes inside `srt` (`--probe`).
    pub probe: bool,
    /// Look from inside Claude Code's sandbox instead (`--inside`).
    pub inside: bool,
}

/// Why verify couldn't produce a report at all (exit code 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CantRun {
    NoSpec(String),
    Spec(String),
    /// `--probe` was asked for and can't run.
    Probe(String),
    /// `--inside` can't run here.
    Inside(String),
}

impl std::fmt::Display for CantRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CantRun::NoSpec(path) => write!(f, "{path} not found (run `mezha init`)"),
            CantRun::Spec(why) => write!(f, "{why}"),
            CantRun::Probe(why) => write!(f, "--probe can't run: {why}"),
            CantRun::Inside(why) => write!(f, "--inside can't run: {why}"),
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
    let rendered =
        mezha_render::render(&spec, &text, &ctx.root).map_err(|e| CantRun::Spec(e.to_string()))?;
    if opts.inside {
        return verify_inside(ctx, opts);
    }

    let layers = layers::Layers::load(ctx, opts.project_only);
    let ctx = &Ctx {
        agent_writable: layers.agent_writable(ctx),
        ..ctx.clone()
    };
    // Dropping this removes srt's settings, whichever way verify ends.
    let prepared = if opts.probe {
        if !cfg!(unix) {
            return Err(CantRun::Probe("it runs on macOS and Linux only".into()));
        }
        if opts.project_only {
            return Err(CantRun::Probe("it doesn't go with --project-only".into()));
        }
        Some(probe::prepare(ctx, &layers).map_err(CantRun::Probe)?)
    } else {
        None
    };
    let claude = if opts.project_only {
        None
    } else {
        checks::sandbox::claude_version(ctx)
    };
    let sandbox = checks::sandbox::check(ctx, &layers, claude.as_deref(), opts);
    let git = gitcfg::GitConfig::read(ctx, opts.project_only).ok();
    let withheld = creds::Withheld::from_layers(ctx, &layers);
    let inventory = creds::inventory(ctx, &withheld, git.as_ref(), opts.project_only);
    let probed = match &prepared {
        Some(p) if sandbox.in_effect => Some(probe::run_all(ctx, p, git.as_ref(), &withheld)),
        _ => None,
    };
    let push = checks::push::check(
        &layers,
        git.as_ref(),
        &inventory,
        sandbox.in_effect,
        probed.as_ref(),
        opts,
    );
    let protection =
        checks::protection::check(ctx, git.as_ref(), push.status == Status::Fail, opts);

    let checks = vec![
        sandbox.check,
        push,
        checks::settings::check(ctx, &rendered, opts),
        checks::layers::check(ctx, &layers, opts),
        checks::hygiene::check(ctx, &spec, &rendered),
        protection,
        Check::skip(
            "dreamer",
            "the dreamer can't run commands",
            Kind::Integrity,
            "arrives in step 2b",
        ),
        checks::plugin::check(ctx, opts),
    ];
    let mut notes = Vec::new();
    if ctx.var("CLAUDECODE").is_some() {
        notes.push(
            "running inside Claude Code: this environment differs from your own terminal's".into(),
        );
    }
    if prepared.is_some() && ctx.var("CLAUDECODE").is_some() {
        notes.push("srt starts inside Claude Code only from an unsandboxed `!` command".into());
    }
    if prepared.is_some() && !sandbox.in_effect {
        notes.push("the probes didn't run, since the sandbox isn't in effect".into());
    }
    if let Some(p) = &probed {
        notes.extend(p.notes.iter().cloned());
        if !p.unprobed.is_empty() {
            notes.push(format!("not probed: {}", p.unprobed.join(", ")));
        }
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
        probe: prepared.as_ref().map(probe::Prepared::runtime),
        checks,
        summary: Default::default(),
        notes,
    };
    report.summarize();
    report.redact();
    Ok(report)
}

/// `--inside`: only what can be seen from inside the sandbox.
fn verify_inside(ctx: &Ctx, opts: &Options) -> Result<Report, CantRun> {
    if !cfg!(unix) {
        return Err(CantRun::Inside("it runs on macOS and Linux only".into()));
    }
    if opts.project_only || opts.probe {
        return Err(CantRun::Inside(
            "it doesn't go with --project-only or --probe".into(),
        ));
    }
    if ctx.var("CLAUDECODE").is_none() {
        return Err(CantRun::Inside(
            "it is for Claude to run with its Bash tool, inside the sandbox. Ask Claude to run `mezha verify --inside`; from your own terminal, use `mezha verify --probe`".into(),
        ));
    }
    let layers = layers::Layers::load(ctx, false);
    let ctx = &Ctx {
        agent_writable: layers.agent_writable(ctx),
        ..ctx.clone()
    };
    let git = gitcfg::GitConfig::read(ctx, false).ok();
    let (checks, notes) = inside::checks(ctx, &layers, git.as_ref());
    let mut report = Report {
        version: report::JSON_VERSION,
        mezha: env!("CARGO_PKG_VERSION"),
        hook_protocol: mezha_hooks::PROTOCOL,
        platform: ctx.platform.as_str(),
        claude_code: None,
        mode: "inside",
        probe: None,
        checks,
        summary: Default::default(),
        notes,
    };
    report.summarize();
    report.redact();
    Ok(report)
}
