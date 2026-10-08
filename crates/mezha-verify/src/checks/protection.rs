//! `branch-protection`: is the default branch of each GitHub remote
//! protected against direct pushes, with code-owner review? Asked of the
//! forge through the user's own `gh`, with queries only (GraphQL and GET):
//!
//! - GraphQL `refUpdateRule` shows classic protection, `viewerPermission`
//!   what the user's token may do;
//! - `rules/branches/{b}` shows the rules of active rulesets, and
//!   `rulesets/{id}` whether the user can bypass each;
//! - `codeowners/errors` shows whether a valid CODEOWNERS file exists.
//!
//! The verdict is a pure function of those facts ([`judge`]), so the table
//! in ADR-0003 is tested without a network.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use serde_json::Value;

use crate::Options;
use crate::creds;
use crate::ctx::Ctx;
use crate::gitcfg::GitConfig;
use crate::hosts::{Remote, Scheme};
use crate::report::{self, Check, Findings, Kind, Status};
use crate::runner::{Run, run};
use crate::scratch::Scratch;

/// At most this many repositories are asked about...
const MAX_REPOS: usize = 3;
/// ...and at most this many rulesets in each.
const MAX_RULESETS: usize = 10;
const TIMEOUT: Duration = Duration::from_secs(20);

const QUERY: &str = "query($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { viewerPermission defaultBranchRef { name refUpdateRule { requiredApprovingReviewCount requiresCodeOwnerReviews allowsForcePushes allowsDeletions viewerCanPush } } } }";

/// Ruleset rule types that stop a direct push to the branch.
const BLOCKING_RULES: [&str; 3] = ["pull_request", "update", "merge_queue"];

const OWNERS_FIX: &str = "Require review from code owners in the rule that protects the branch, and commit a valid CODEOWNERS file.";
const BYPASS_FIX: &str = "Take yourself off the ruleset's bypass list, or for classic protection turn on \"Do not allow bypassing the above settings\".";
const PROTECT_FIX: &str =
    "Add a branch ruleset (Settings → Rules) that requires a pull request with code-owner review.";

fn new_check() -> Check {
    Check {
        evidence: vec![report::SERVER],
        ..Check::new(
            "branch-protection",
            "the default branch is protected",
            Kind::Boundary,
        )
    }
}

pub fn check(ctx: &Ctx, git: Option<&GitConfig>, push_failed: bool, opts: &Options) -> Check {
    if opts.project_only {
        return Check::skip(
            "branch-protection",
            "the default branch is protected",
            Kind::Boundary,
            "needs gh, which --project-only doesn't run",
        );
    }
    let mut f = Findings::default();
    let Some(git) = git else {
        f.warn(
            "git's configuration couldn't be read, so the remotes are unknown",
            None,
        );
        return f.into_check(new_check(), "");
    };
    let file_hosts = gh_config_hosts(ctx);
    let mut github = vec!["github.com".to_string()];
    github.extend(file_hosts.iter().cloned());
    github.extend(ctx.var("GH_HOST").map(str::to_ascii_lowercase));

    let mut repos: Vec<Repo> = Vec::new();
    let mut others: Vec<String> = Vec::new();
    for url in git.push_urls() {
        match Repo::from_url(&url, &github) {
            Some(repo) if !repos.contains(&repo) => repos.push(repo),
            Some(_) => {}
            None => others.extend(Some(Remote::parse(&url).host).filter(|h| !h.is_empty())),
        }
    }
    others.sort();
    others.dedup();
    if repos.is_empty() {
        let why = if others.is_empty() {
            "no GitHub remote".to_string()
        } else {
            format!(
                "no GitHub remote (only GitHub is checked, not {})",
                others.join(", ")
            )
        };
        return Check::skip(
            "branch-protection",
            "the default branch is protected",
            Kind::Boundary,
            &why,
        );
    }
    let unchecked = repos.split_off(repos.len().min(MAX_REPOS));

    let found = ctx.which_trusted("gh");
    if let Some(note) = found.skipped_note("gh") {
        f.warn(note, None);
    }
    let Some(gh) = found.path else {
        f.warn(
            "gh isn't installed, so branch protection is unknown",
            Some("Install GitHub CLI (https://cli.github.com) and run `gh auth login`.".into()),
        );
        return f.into_check(new_check(), "");
    };
    let Ok(scratch) = Scratch::new("mezha-gh") else {
        f.warn("couldn't create a scratch directory to run gh in", None);
        return f.into_check(new_check(), "");
    };
    for repo in &repos {
        // Enterprise tokens go only to an enterprise host the user set up.
        let enterprise = repo.host != "github.com"
            && (file_hosts.contains(&repo.host) || ctx.var("GH_HOST") == Some(&repo.host));
        let mut call =
            |args: &[&str]| gh_api(ctx, &gh, scratch.path(), &repo.host, enterprise, args);
        let judgement = judge(&gather(repo, &mut call));
        add_verdict(&mut f, repo, &judgement, push_failed);
    }
    if !unchecked.is_empty() {
        let labels: Vec<String> = unchecked.iter().map(Repo::label).collect();
        f.add(
            Status::Skip,
            format!("not checked (only {MAX_REPOS} are): {}", labels.join(", ")),
            None,
        );
    }
    if !others.is_empty() {
        f.add(
            Status::Skip,
            format!("not checked (not GitHub): {}", others.join(", ")),
            None,
        );
    }
    f.into_check(new_check(), "")
}

fn add_verdict(f: &mut Findings, repo: &Repo, j: &Judgement, push_failed: bool) {
    let label = repo.label();
    let branch = j
        .branch
        .as_deref()
        .map_or_else(|| "the default branch".to_string(), |b| format!("`{b}`"));
    match &j.verdict {
        Verdict::Protected => f.add(
            Status::Pass,
            format!("{label}: {branch} can't be pushed to directly, and code owners must review"),
            None,
        ),
        Verdict::WithoutCodeOwners(why) => f.warn(
            format!("{label}: {branch} can't be pushed to directly, but {why}"),
            Some(OWNERS_FIX.into()),
        ),
        Verdict::Bypassable(why) => f.warn(
            format!(
                "{label}: {why}, so an agent holding your token could push to {branch} directly"
            ),
            Some(BYPASS_FIX.into()),
        ),
        Verdict::Unknown(why) => f.warn(
            format!("{label}: protection of {branch} is unknown: {why}"),
            None,
        ),
        Verdict::Unprotected => f.add(
            if push_failed {
                Status::Fail
            } else {
                Status::Warn
            },
            format!(
                "{label}: nothing stops a direct push to {branch}{}",
                if push_failed {
                    ", and an agent can push (see push-boundary)"
                } else {
                    ""
                }
            ),
            Some(PROTECT_FIX.into()),
        ),
        Verdict::ReadOnly => f.add(
            Status::Skip,
            format!("{label}: you have read-only access, so your token can't push there either"),
            None,
        ),
        Verdict::NoBranch => f.add(
            Status::Skip,
            format!("{label}: the repository has no default branch yet"),
            None,
        ),
        Verdict::NotLoggedIn => f.warn(
            format!(
                "{label}: gh isn't logged in to {}, so protection is unknown",
                repo.host
            ),
            Some(format!("Run `gh auth login --hostname {}`.", repo.host)),
        ),
    }
    for warning in &j.warnings {
        f.warn(format!("{label}: {warning}"), None);
    }
}

/// The hosts in gh's `hosts.yml` (its top-level keys).
fn gh_config_hosts(ctx: &Ctx) -> Vec<String> {
    let Some(text) = creds::gh_hosts_file(ctx).and_then(|p| std::fs::read_to_string(p).ok()) else {
        return Vec::new();
    };
    text.lines()
        .filter(|l| !l.starts_with([' ', '\t', '#', '-']))
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, _)| k.trim().to_ascii_lowercase())
        })
        .filter(|h| {
            !h.is_empty()
                && h.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    pub host: String,
    pub owner: String,
    pub name: String,
}

impl Repo {
    /// The GitHub repository a push URL names. A host counts as GitHub only
    /// if it is in `github` (github.com, gh's hosts, `GH_HOST`): the URL
    /// comes from git config an agent can write.
    pub fn from_url(url: &str, github: &[String]) -> Option<Repo> {
        let remote = Remote::parse(url);
        if !matches!(remote.scheme, Scheme::Https | Scheme::Http | Scheme::Ssh) {
            return None;
        }
        let host = match remote.host.as_str() {
            "ssh.github.com" => "github.com".to_string(),
            h => h.to_string(),
        };
        if !github.iter().any(|g| g.eq_ignore_ascii_case(&host)) {
            return None;
        }
        let url = url.trim();
        let path = match url.split_once("://") {
            Some((_, rest)) => rest.split_once('/')?.1,
            None => url.split_once(':')?.1,
        };
        let path = path.trim_matches('/');
        let path = path.strip_suffix(".git").unwrap_or(path);
        let (owner, name) = path.split_once('/')?;
        (valid_name(owner) && valid_name(name)).then(|| Repo {
            host,
            owner: owner.to_string(),
            name: name.to_string(),
        })
    }

    pub fn label(&self) -> String {
        if self.host == "github.com" {
            format!("{}/{}", self.owner, self.name)
        } else {
            format!("{}/{}/{}", self.host, self.owner, self.name)
        }
    }
}

/// `^[A-Za-z0-9._-]+$`, but not `.` or `..`.
fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Percent-encodes everything but unreserved characters, for a branch name
/// in a URL path.
fn encode(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// What one `gh api` call came back with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GhOut {
    Ok(String),
    NotFound,
    /// Exit 4: no login for the host.
    NotLoggedIn,
    /// Any other failure; GraphQL may still have printed partial data.
    Failed {
        stdout: String,
        why: String,
    },
}

impl GhOut {
    fn why(&self) -> String {
        match self {
            GhOut::Ok(_) => String::new(),
            GhOut::NotFound => "not found".into(),
            GhOut::NotLoggedIn => "gh isn't logged in".into(),
            GhOut::Failed { why, .. } => why.clone(),
        }
    }
}

/// Runs `gh api ARGS --hostname HOST` from a scratch directory, so no
/// repository's config or `GH_REPO` steers it, with prompts, pagers,
/// colour and debug output off.
fn gh_api(ctx: &Ctx, gh: &Path, cwd: &Path, host: &str, enterprise: bool, args: &[&str]) -> GhOut {
    let mut full = vec!["api"];
    full.extend_from_slice(args);
    full.extend(["--hostname", host]);
    let mut remove = vec![
        "GH_FORCE_TTY",
        "CLICOLOR_FORCE",
        "GH_DEBUG",
        "DEBUG",
        "GH_REPO",
        "GH_HOST",
    ];
    if !enterprise {
        remove.extend(["GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"]);
    }
    let out = run(
        ctx,
        &Run {
            program: gh,
            args: &full,
            cwd,
            env: &[
                ("GH_PROMPT_DISABLED", "1"),
                ("GH_NO_UPDATE_NOTIFIER", "1"),
                ("GH_NO_EXTENSION_UPDATE_NOTIFIER", "1"),
                ("NO_COLOR", "1"),
                ("GH_PAGER", "cat"),
                ("LC_ALL", "C"),
            ],
            remove: &remove,
            stdin: b"",
            timeout: TIMEOUT,
        },
    );
    match out {
        Err(e) => GhOut::Failed {
            stdout: String::new(),
            why: format!("gh couldn't run ({e})"),
        },
        Ok(o) if o.timed_out => GhOut::Failed {
            stdout: String::new(),
            why: "gh timed out".into(),
        },
        Ok(o) if o.code == Some(0) => GhOut::Ok(o.stdout),
        Ok(o) if o.code == Some(4) => GhOut::NotLoggedIn,
        Ok(o) if o.stderr.contains("(HTTP 404)") => GhOut::NotFound,
        Ok(o) => GhOut::Failed {
            why: first_line(&o.stderr),
            stdout: o.stdout,
        },
    }
}

fn first_line(text: &str) -> String {
    let line = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("gh failed");
    line.chars().take(200).collect()
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Classic {
    pub required_reviews: Option<u64>,
    pub code_owners: Option<bool>,
    pub force_pushes: Option<bool>,
    pub viewer_can_push: Option<bool>,
}

/// A rule from an active ruleset that applies to the branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub kind: String,
    pub ruleset: Option<u64>,
    /// A `pull_request` rule's `require_code_owner_review`.
    pub code_owners: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ruleset {
    pub name: String,
    pub active: bool,
    /// `current_user_can_bypass`: never, pull_requests_only, always, exempt.
    pub bypass: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CodeOwners {
    #[default]
    Unknown,
    Valid,
    Missing,
    Errors(usize),
}

/// What the forge says about one repository. `None` means unknown.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    /// `viewerPermission`: ADMIN, MAINTAIN, WRITE, TRIAGE or READ.
    pub permission: Option<String>,
    /// `Some(None)`: the repository has no default branch.
    pub branch: Option<Option<String>>,
    /// `Some(None)`: no classic rule applies.
    pub classic: Option<Option<Classic>>,
    pub rules: Option<Vec<Rule>>,
    /// The rulesets that could be read, by id.
    pub rulesets: BTreeMap<u64, Ruleset>,
    pub codeowners: CodeOwners,
    pub not_logged_in: bool,
    /// What went wrong on the way, for the message.
    pub problems: Vec<String>,
}

impl Facts {
    fn read_graphql(&mut self, text: &str) {
        let Ok(v) = serde_json::from_str::<Value>(text) else {
            return;
        };
        let errors = v["errors"].as_array().cloned().unwrap_or_default();
        let errored = |field: &str| {
            errors.iter().any(|e| {
                e["path"]
                    .as_array()
                    .is_some_and(|p| p.iter().any(|s| s == field))
            })
        };
        for e in &errors {
            if let Some(message) = e["message"].as_str() {
                self.problems.push(first_line(message));
            }
        }
        let repo = &v["data"]["repository"];
        if !repo.is_object() {
            return;
        }
        self.permission = repo["viewerPermission"].as_str().map(str::to_string);
        match repo.get("defaultBranchRef") {
            Some(Value::Null) if !errored("defaultBranchRef") => self.branch = Some(None),
            Some(branch @ Value::Object(_)) => {
                self.branch = branch["name"].as_str().map(|n| Some(n.to_string()));
                match branch.get("refUpdateRule") {
                    Some(Value::Null) if !errored("refUpdateRule") => self.classic = Some(None),
                    Some(rule @ Value::Object(_)) => {
                        self.classic = Some(Some(Classic {
                            required_reviews: rule["requiredApprovingReviewCount"].as_u64(),
                            code_owners: rule["requiresCodeOwnerReviews"].as_bool(),
                            force_pushes: rule["allowsForcePushes"].as_bool(),
                            viewer_can_push: rule["viewerCanPush"].as_bool(),
                        }))
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

/// `gh api --paginate` prints one JSON array per page.
fn parse_rules(text: &str) -> Option<Vec<Rule>> {
    let mut rules = Vec::new();
    for page in serde_json::Deserializer::from_str(text).into_iter::<Value>() {
        for rule in page.ok()?.as_array()? {
            rules.push(Rule {
                kind: rule["type"].as_str().unwrap_or_default().to_string(),
                ruleset: rule["ruleset_id"].as_u64(),
                code_owners: rule["parameters"]["require_code_owner_review"] == Value::Bool(true),
            });
        }
    }
    Some(rules)
}

fn parse_ruleset(text: &str) -> Option<Ruleset> {
    let v: Value = serde_json::from_str(text).ok()?;
    Some(Ruleset {
        name: v["name"].as_str().unwrap_or_default().to_string(),
        active: v["enforcement"] == "active",
        bypass: v["current_user_can_bypass"].as_str().map(str::to_string),
    })
}

/// Asks the forge about one repository through `gh`, which runs
/// `gh api ARGS` and reports how it went.
pub fn gather(repo: &Repo, gh: &mut dyn FnMut(&[&str]) -> GhOut) -> Facts {
    let mut facts = Facts::default();
    let query = format!("query={QUERY}");
    let owner = format!("owner={}", repo.owner);
    let name = format!("name={}", repo.name);
    match gh(&["graphql", "-f", &query, "-f", &owner, "-f", &name]) {
        GhOut::NotLoggedIn => {
            facts.not_logged_in = true;
            return facts;
        }
        GhOut::Ok(text) => facts.read_graphql(&text),
        GhOut::Failed { stdout, why } => {
            facts.read_graphql(&stdout);
            facts.problems.push(why);
        }
        GhOut::NotFound => facts.problems.push("the repository wasn't found".into()),
    }
    let Some(Some(branch)) = facts.branch.clone() else {
        return facts;
    };
    let base = format!("repos/{}/{}", repo.owner, repo.name);
    let rules = format!("{base}/rules/branches/{}", encode(&branch));
    match gh(&["--method", "GET", "--paginate", &rules]) {
        GhOut::Ok(text) => facts.rules = parse_rules(&text),
        other => facts.problems.push(format!("rulesets: {}", other.why())),
    }
    let mut ids: Vec<u64> = facts
        .rules
        .iter()
        .flatten()
        .filter(|r| BLOCKING_RULES.contains(&r.kind.as_str()))
        .filter_map(|r| r.ruleset)
        .collect();
    ids.sort_unstable();
    ids.dedup();
    for id in ids.into_iter().take(MAX_RULESETS) {
        if let GhOut::Ok(text) = gh(&["--method", "GET", &format!("{base}/rulesets/{id}")])
            && let Some(ruleset) = parse_ruleset(&text)
        {
            facts.rulesets.insert(id, ruleset);
        }
    }
    facts.codeowners = match gh(&["--method", "GET", &format!("{base}/codeowners/errors")]) {
        GhOut::Ok(text) => serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| v["errors"].as_array().map(Vec::len))
            .map_or(CodeOwners::Unknown, |n| match n {
                0 => CodeOwners::Valid,
                n => CodeOwners::Errors(n),
            }),
        GhOut::NotFound => CodeOwners::Missing,
        _ => CodeOwners::Unknown,
    };
    facts
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A rule you can't bypass blocks direct pushes and requires code-owner
    /// review, and CODEOWNERS is valid.
    Protected,
    WithoutCodeOwners(String),
    /// Every rule that would block a direct push lets you through.
    Bypassable(String),
    Unknown(String),
    Unprotected,
    ReadOnly,
    NoBranch,
    NotLoggedIn,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judgement {
    pub verdict: Verdict,
    pub branch: Option<String>,
    /// Extra warnings, such as force pushes being allowed.
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Bypass {
    No,
    Yes(String),
    Unknown(String),
}

struct Block {
    bypass: Bypass,
    code_owners: bool,
}

/// The verdict for one repository, following ADR-0003's table.
pub fn judge(facts: &Facts) -> Judgement {
    let mut j = Judgement {
        verdict: Verdict::Unprotected,
        branch: None,
        warnings: Vec::new(),
    };
    if facts.not_logged_in {
        j.verdict = Verdict::NotLoggedIn;
        return j;
    }
    let permission = facts.permission.as_deref();
    if matches!(permission, Some("READ" | "TRIAGE")) {
        j.verdict = Verdict::ReadOnly;
        return j;
    }
    let mut unknown: Vec<String> = Vec::new();
    match &facts.branch {
        Some(Some(branch)) => j.branch = Some(branch.clone()),
        Some(None) => {
            j.verdict = Verdict::NoBranch;
            return j;
        }
        None => {
            unknown.push("the default branch couldn't be read".into());
            j.verdict = Verdict::Unknown(with_problems(&unknown, facts));
            return j;
        }
    }
    let can_write = matches!(permission, Some("WRITE" | "MAINTAIN" | "ADMIN"));
    let mut blocks: Vec<Block> = Vec::new();

    match &facts.classic {
        None => unknown.push("classic protection couldn't be read".into()),
        Some(None) => {}
        Some(Some(c)) => {
            let reviews = c.required_reviews.is_some_and(|n| n >= 1);
            let owners = c.code_owners == Some(true);
            let held = can_write && c.viewer_can_push == Some(false);
            let free = can_write && c.viewer_can_push == Some(true);
            if reviews || owners || held {
                let bypass = if permission == Some("ADMIN") {
                    Bypass::Yes("you are an admin, and classic protection lets admins push unless it is enforced for them".into())
                } else if free {
                    Bypass::Yes("the classic rule lets you push".into())
                } else if permission.is_none() {
                    Bypass::Unknown("your permission on the repository is unknown".into())
                } else {
                    Bypass::No
                };
                blocks.push(Block {
                    bypass,
                    code_owners: owners,
                });
            } else if !free {
                unknown.push(
                    "a classic rule requires 0 approvals, so whether it requires a pull request is unknown"
                        .into(),
                );
            }
            if c.force_pushes == Some(true) {
                j.warnings
                    .push("the classic rule allows force pushes".into());
            }
        }
    }

    match &facts.rules {
        None => unknown.push("rulesets couldn't be read".into()),
        Some(rules) => {
            for rule in rules
                .iter()
                .filter(|r| BLOCKING_RULES.contains(&r.kind.as_str()))
            {
                let ruleset = rule.ruleset.and_then(|id| facts.rulesets.get(&id));
                let Some(ruleset) = ruleset else {
                    unknown.push(format!(
                        "ruleset {} is hidden from you",
                        rule.ruleset.map_or("?".to_string(), |id| id.to_string())
                    ));
                    continue;
                };
                if !ruleset.active {
                    continue;
                }
                let bypass = match ruleset.bypass.as_deref() {
                    Some("never" | "pull_requests_only") => Bypass::No,
                    Some(how @ ("always" | "exempt")) => Bypass::Yes(format!(
                        "you can bypass ruleset \"{}\" ({how})",
                        ruleset.name
                    )),
                    _ => Bypass::Unknown(format!(
                        "whether you can bypass ruleset \"{}\" is unknown",
                        ruleset.name
                    )),
                };
                blocks.push(Block {
                    bypass,
                    code_owners: rule.kind == "pull_request" && rule.code_owners,
                });
            }
        }
    }

    let firm: Vec<&Block> = blocks.iter().filter(|b| b.bypass == Bypass::No).collect();
    for block in &blocks {
        if let Bypass::Unknown(why) = &block.bypass {
            unknown.push(why.clone());
        }
    }
    unknown.dedup();
    j.verdict = if !firm.is_empty() {
        let owners = firm.iter().any(|b| b.code_owners);
        match (owners, facts.codeowners) {
            (true, CodeOwners::Valid) => Verdict::Protected,
            (false, _) => Verdict::WithoutCodeOwners(
                "no rule that binds you requires code-owner review".into(),
            ),
            (true, CodeOwners::Missing) => Verdict::WithoutCodeOwners(
                "code-owner review is required and there is no CODEOWNERS file".into(),
            ),
            (true, CodeOwners::Errors(n)) => {
                Verdict::WithoutCodeOwners(format!("CODEOWNERS has {n} error(s)"))
            }
            (true, CodeOwners::Unknown) => {
                Verdict::WithoutCodeOwners("CODEOWNERS couldn't be checked".into())
            }
        }
    } else if !unknown.is_empty() {
        Verdict::Unknown(with_problems(&unknown, facts))
    } else if !blocks.is_empty() {
        let why: Vec<String> = blocks
            .iter()
            .filter_map(|b| match &b.bypass {
                Bypass::Yes(why) => Some(why.clone()),
                _ => None,
            })
            .collect();
        Verdict::Bypassable(why.join("; "))
    } else {
        Verdict::Unprotected
    };
    j
}

fn with_problems(unknown: &[String], facts: &Facts) -> String {
    let mut text = unknown.join("; ");
    if !facts.problems.is_empty() {
        text.push_str(&format!(" ({})", facts.problems.join("; ")));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/protection");

    /// Serves recorded answers from `tests/fixtures/protection/<case>`,
    /// after `edit` has had its way with them; a missing file is a 404.
    fn facts_from(case: &str, edit: impl Fn(&str, String) -> String) -> Facts {
        let repo = Repo {
            host: "github.com".into(),
            owner: "o".into(),
            name: "r".into(),
        };
        let mut calls = Vec::new();
        let mut gh = |args: &[&str]| {
            calls.push(args.join(" "));
            let path = args.last().unwrap();
            let file = if args[0] == "graphql" {
                "graphql.json".to_string()
            } else if path.contains("/rules/branches/") {
                "rules.json".to_string()
            } else if let Some(id) = path.split("/rulesets/").nth(1) {
                format!("ruleset-{id}.json")
            } else {
                "codeowners.json".to_string()
            };
            match std::fs::read_to_string(format!("{FIXTURES}/{case}/{file}")) {
                Ok(text) => GhOut::Ok(edit(&file, text)),
                Err(_) => GhOut::NotFound,
            }
        };
        let facts = gather(&repo, &mut gh);
        assert!(calls[0].starts_with("graphql -f query=query("), "{calls:?}");
        assert!(
            calls.iter().skip(1).all(|c| c.starts_with("--method GET")),
            "{calls:?}"
        );
        facts
    }

    fn as_writer(_: &str, text: String) -> String {
        text.replace("\"READ\"", "\"WRITE\"")
    }

    fn verdict(case: &str, edit: impl Fn(&str, String) -> String) -> Judgement {
        judge(&facts_from(case, edit))
    }

    #[test]
    fn cli_cli_classic_with_code_owners_is_protected() {
        let j = verdict("cli-cli", as_writer);
        assert_eq!(j.verdict, Verdict::Protected);
        assert_eq!(j.branch.as_deref(), Some("trunk"));
        assert!(j.warnings.is_empty());
    }

    #[test]
    fn read_only_access_is_skipped() {
        assert_eq!(verdict("cli-cli", |_, t| t).verdict, Verdict::ReadOnly);
    }

    #[test]
    fn sandbox_runtime_rulesets_without_codeowners() {
        let j = verdict("sandbox-runtime", as_writer);
        assert_eq!(
            j.verdict,
            Verdict::WithoutCodeOwners(
                "code-owner review is required and there is no CODEOWNERS file".into()
            )
        );
    }

    #[test]
    fn a_ruleset_you_can_bypass_does_not_protect() {
        let j = verdict("sandbox-runtime", |file, text| {
            as_writer(file, text).replace("\"never\"", "\"always\"")
        });
        assert!(
            matches!(&j.verdict, Verdict::Bypassable(why) if why.contains("(always)")),
            "{j:?}"
        );
        let j = verdict("sandbox-runtime", |file, text| {
            as_writer(file, text).replace("\"never\"", "\"pull_requests_only\"")
        });
        assert!(matches!(j.verdict, Verdict::WithoutCodeOwners(_)), "{j:?}");
    }

    #[test]
    fn a_hidden_ruleset_is_unknown() {
        let j = verdict("sandbox-runtime", |file, text| {
            if file.starts_with("ruleset-") {
                "not json".into()
            } else {
                as_writer(file, text)
            }
        });
        assert!(
            matches!(&j.verdict, Verdict::Unknown(why) if why.contains("hidden")),
            "{j:?}"
        );
    }

    #[test]
    fn an_inactive_ruleset_does_not_count() {
        let j = verdict("sandbox-runtime", |file, text| {
            as_writer(file, text).replace("\"active\"", "\"evaluate\"")
        });
        assert_eq!(j.verdict, Verdict::Unprotected);
    }

    #[test]
    fn hello_world_is_unprotected() {
        assert_eq!(
            verdict("hello-world", as_writer).verdict,
            Verdict::Unprotected
        );
    }

    #[test]
    fn nodejs_classic_with_zero_approvals_is_unknown() {
        // The classic rule alone: 0 approvals, no code owners, and no
        // viewerCanPush to settle it.
        let j = verdict("nodejs", |file, text| match file {
            "rules.json" => "[]".into(),
            _ => {
                as_writer(file, text).replace("\"viewerCanPush\": false", "\"viewerCanPush\": null")
            }
        });
        assert!(
            matches!(&j.verdict, Verdict::Unknown(why) if why.contains("0 approvals")),
            "{j:?}"
        );
        assert_eq!(j.warnings, ["the classic rule allows force pushes"]);
        // viewerCanPush false at WRITE settles it; the ruleset adds no code owners.
        let j = verdict("nodejs", as_writer);
        assert_eq!(
            j.verdict,
            Verdict::WithoutCodeOwners("no rule that binds you requires code-owner review".into())
        );
    }

    #[test]
    fn an_admin_bypasses_classic_protection() {
        let j = verdict("cli-cli", |_, text| text.replace("\"READ\"", "\"ADMIN\""));
        assert!(
            matches!(&j.verdict, Verdict::Bypassable(why) if why.contains("admin")),
            "{j:?}"
        );
    }

    #[test]
    fn codeowners_errors_and_partial_graphql() {
        let j = verdict("cli-cli", |file, text| match file {
            "codeowners.json" => r#"{"errors":[{"line":1}]}"#.into(),
            _ => as_writer(file, text),
        });
        assert_eq!(
            j.verdict,
            Verdict::WithoutCodeOwners("CODEOWNERS has 1 error(s)".into())
        );
        let mut facts = Facts::default();
        facts.read_graphql(
            r#"{"data":{"repository":{"viewerPermission":"WRITE","defaultBranchRef":{"name":"main","refUpdateRule":null}}},
                "errors":[{"path":["repository","defaultBranchRef","refUpdateRule"],"message":"Resource not accessible"}]}"#,
        );
        assert_eq!(facts.classic, None, "an errored null is unknown");
        facts.rules = Some(Vec::new());
        assert!(
            matches!(judge(&facts).verdict, Verdict::Unknown(why) if why.contains("Resource not accessible"))
        );
        let mut empty = Facts::default();
        empty.read_graphql(
            r#"{"data":{"repository":{"viewerPermission":"WRITE","defaultBranchRef":null}}}"#,
        );
        assert_eq!(judge(&empty).verdict, Verdict::NoBranch);
    }

    #[test]
    fn repos_from_urls() {
        let github = ["github.com".to_string(), "ghe.corp".to_string()];
        let repo = |url: &str| Repo::from_url(url, &github).map(|r| r.label());
        assert_eq!(repo("https://github.com/o/r.git").as_deref(), Some("o/r"));
        assert_eq!(repo("git@github.com:o/r.git/").as_deref(), Some("o/r"));
        assert_eq!(
            repo("ssh://git@ssh.github.com:443/o/r").as_deref(),
            Some("o/r")
        );
        assert_eq!(
            repo("https://ghe.corp/team/app").as_deref(),
            Some("ghe.corp/team/app")
        );
        // Only the hosts gh knows count; the URL is agent-writable.
        assert_eq!(repo("https://evil.ghe.com/o/r"), None);
        assert_eq!(repo("https://github.com/o/r/extra"), None);
        assert_eq!(repo("https://github.com/../r"), None);
        assert_eq!(repo("https://github.com/o/$(id)"), None);
        assert_eq!(repo("ext::sh -c x"), None);
        assert_eq!(encode("feat/ü x"), "feat%2F%C3%BC%20x");
    }
}
