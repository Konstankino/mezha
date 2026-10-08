//! `push-boundary`: can a sandboxed command push? A push needs a forge
//! write endpoint the sandbox can reach and a credential it can reach; the
//! verdict follows the table in ADR-0003. With `--probe`, what srt showed
//! joins what the settings say: a credential that reached a server fails
//! outright, an endpoint either reading finds open counts as open, and the
//! two readings disagreeing is a warning.

use crate::Options;
use crate::creds::Inventory;
use crate::gitcfg::GitConfig;
use crate::hosts::{Endpoint, Pattern, Remote, github_endpoints};
use crate::layers::Layers;
use crate::probe::{self, NetResult};
use crate::report::{self, Check, Findings, Kind, Status};

/// The hosts sandboxed commands may reach: `allowedDomains` from every
/// scope plus `WebFetch(domain:...)` allow rules, minus `deniedDomains`.
pub struct Network {
    allowed: Vec<Pattern>,
    denied: Vec<Pattern>,
    /// Why reachability can't be judged from settings, if it can't.
    pub unknown: Option<String>,
}

impl Network {
    pub fn from_layers(layers: &Layers) -> Network {
        let mut allowed: Vec<Pattern> = layers
            .strings("/sandbox/network/allowedDomains")
            .into_iter()
            .filter(|(_, l)| layers.loosens(l))
            .filter_map(|(s, _)| Pattern::parse(s))
            .collect();
        allowed.extend(
            layers
                .strings("/permissions/allow")
                .into_iter()
                .filter(|(_, l)| layers.loosens(l))
                .filter_map(|(rule, _)| {
                    rule.strip_prefix("WebFetch(domain:")?
                        .strip_suffix(')')
                        .and_then(Pattern::parse)
                }),
        );
        let denied = layers
            .strings("/sandbox/network/deniedDomains")
            .into_iter()
            .filter_map(|(s, _)| Pattern::parse(s))
            .collect();
        let unknown = [
            "/sandbox/network/httpProxyPort",
            "/sandbox/network/socksProxyPort",
        ]
        .iter()
        .find_map(|key| {
            layers
                .winner(key)
                .filter(|(v, _)| !v.is_null())
                .map(|(_, l)| format!("a custom sandbox proxy is set in {}", l.label))
        });
        Network {
            allowed,
            denied,
            unknown,
        }
    }

    pub fn reaches(&self, endpoint: &Endpoint) -> bool {
        self.allowed.iter().any(|p| p.matches(endpoint))
            && !self.denied.iter().any(|p| p.matches(endpoint))
    }
}

pub fn check(
    layers: &Layers,
    git: Option<&GitConfig>,
    inventory: &Inventory,
    sandbox_in_effect: bool,
    probe: Option<&probe::Facts>,
    opts: &Options,
) -> Check {
    let mut check = Check::new("push-boundary", "an agent can't push", Kind::Boundary);
    if probe.is_some() {
        check.evidence.push(report::PROBE);
    }
    let mut f = Findings::default();
    if !sandbox_in_effect {
        f.fail(
            "the sandbox isn't in effect (see `sandbox`), so nothing below the advisory gate stops a push",
            "Fix the `sandbox` check first.",
        );
        return f.into_check(check, "");
    }

    let mut endpoints: Vec<Endpoint> = git
        .map(|g| g.push_urls())
        .unwrap_or_default()
        .iter()
        .flat_map(|url| Remote::parse(url).write_endpoints())
        .collect();
    if inventory.gh_logged_in {
        endpoints.extend(github_endpoints());
    }
    endpoints.sort();
    endpoints.dedup();
    if endpoints.is_empty() {
        return f.into_check(check, "no remote to push to and no gh login");
    }

    let network = Network::from_layers(layers);
    let close = "Remove these hosts from egress_allow in mezha.toml (and any WebFetch(domain:...) allow rule), or remove the credentials listed.";
    // With a custom proxy, srt's own proxy says nothing about the real one.
    let results: Vec<&NetResult> = match (probe, &network.unknown) {
        (Some(p), None) => p.network.iter().collect(),
        _ => Vec::new(),
    };
    let shown: Vec<String> = results
        .iter()
        .filter(|r| r.outcome.credential_shown())
        .map(|r| format!("{}: {}", r.target.endpoint, r.outcome.describe()))
        .collect();
    if !shown.is_empty() {
        f.fail(
            format!(
                "shown in srt with the settings as mezha reads them: {}",
                shown.join("; ")
            ),
            close,
        );
        return f.into_check(check, "");
    }

    let probed = |open: bool| -> Vec<Endpoint> {
        results
            .iter()
            .filter(|r| r.outcome.network_open() == Some(open))
            .map(|r| r.target.endpoint.clone())
            .collect()
    };
    let (probed_open, probed_closed) = (probed(true), probed(false));
    let mut differ: Vec<String> = Vec::new();
    for e in &probed_closed {
        if network.reaches(e) {
            differ.push(format!("srt refused {e}, which mezha's reading allows"));
        }
    }
    for e in &probed_open {
        if !network.reaches(e) {
            differ.push(format!("srt reached {e}, which mezha's reading blocks"));
        }
    }
    differ.extend(probe.iter().flat_map(|p| p.disagree.iter().cloned()));
    if !differ.is_empty() {
        f.warn(
            format!(
                "srt and mezha's reading of the settings differ: {}",
                differ.join("; ")
            ),
            Some("Report this as a mezha bug, with the settings involved.".into()),
        );
    }

    // Open by either reading counts as open.
    let mut open: Vec<Endpoint> = endpoints
        .iter()
        .filter(|e| network.reaches(e))
        .cloned()
        .chain(probed_open)
        .collect();
    open.sort();
    open.dedup();
    let open: Vec<String> = open.iter().map(ToString::to_string).collect();
    let hosts = |list: &[String]| list.join(", ");
    if open.is_empty() && network.unknown.is_none() {
        let all: Vec<String> = endpoints.iter().map(ToString::to_string).collect();
        let mut text = format!("sandboxed commands can't reach {}", hosts(&all));
        if !probed_closed.is_empty() {
            let shown: Vec<String> = probed_closed.iter().map(ToString::to_string).collect();
            text.push_str(&format!(" (shown closed in srt: {})", shown.join(", ")));
        }
        f.add(Status::Pass, text, None);
        add_probe_summary(&mut f, probe, &network);
        return f.into_check(check, "");
    }
    let reach = match (&network.unknown, open.is_empty()) {
        (Some(why), true) => format!("network reach is unknown ({why})"),
        (Some(why), false) => format!("sandboxed commands can reach {} ({why})", hosts(&open)),
        (None, _) => format!("sandboxed commands can reach {}", hosts(&open)),
    };
    let proven: &[String] = probe.map_or(&[], |p| &p.proven);
    let probe_unknown: &[String] = probe.map_or(&[], |p| &p.unknown);

    if opts.project_only {
        f.warn(
            format!("{reach}; whether a push gets through depends on each machine's credentials"),
            Some("Run `mezha verify` on each machine that runs Claude Code.".into()),
        );
    } else if !inventory.reachable.is_empty() || !proven.is_empty() {
        let mut found = inventory.reachable.clone();
        if !proven.is_empty() {
            found.push(format!("shown readable in srt: {}", proven.join(", ")));
        }
        f.fail(
            format!(
                "{reach}, and these credentials are reachable: {}",
                found.join("; ")
            ),
            close,
        );
    } else if !inventory.unknown.is_empty() || !probe_unknown.is_empty() {
        let unknown: Vec<String> = inventory
            .unknown
            .iter()
            .chain(probe_unknown)
            .cloned()
            .collect();
        f.add(
            Status::Warn,
            format!(
                "unverified: {reach}, and these credential sources can't be judged: {}",
                unknown.join("; ")
            ),
            Some(close.into()),
        );
    } else {
        let srt = if probe.is_some_and(|p| p.creds_checked) {
            "; in srt no credential was readable"
        } else {
            ""
        };
        f.add(
            Status::Pass,
            format!(
                "{reach}, but no credential is reachable (checked: {}{srt})",
                inventory.checked.join(", ")
            ),
            None,
        );
    }
    add_probe_summary(&mut f, probe, &network);
    f.into_check(check, "")
}

/// What each network probe came to, for the detail.
fn add_probe_summary(f: &mut Findings, probe: Option<&probe::Facts>, network: &Network) {
    let Some(probe) = probe else {
        return;
    };
    let text = match &network.unknown {
        Some(why) => format!("srt: the network probe is inconclusive ({why})"),
        None if probe.network.is_empty() => return,
        None => {
            let each: Vec<String> = probe
                .network
                .iter()
                .map(|r| format!("{} {}", r.target.endpoint, r.outcome.describe()))
                .collect();
            format!("srt: {}", each.join("; "))
        }
    };
    f.add(Status::Pass, text, None);
}
