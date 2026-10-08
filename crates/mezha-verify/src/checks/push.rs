//! `push-boundary`: can a sandboxed command push? A push needs a forge
//! write endpoint the sandbox can reach and a credential it can reach; the
//! verdict follows the table in ADR-0003.

use crate::Options;
use crate::creds::Inventory;
use crate::gitcfg::GitConfig;
use crate::hosts::{Endpoint, Pattern, Remote, github_endpoints};
use crate::layers::Layers;
use crate::report::{Check, Findings, Kind, Status};

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
    opts: &Options,
) -> Check {
    let check = Check::new("push-boundary", "an agent can't push", Kind::Boundary);
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
    let open: Vec<String> = endpoints
        .iter()
        .filter(|e| network.reaches(e))
        .map(ToString::to_string)
        .collect();
    let hosts = |list: &[String]| list.join(", ");
    if open.is_empty() && network.unknown.is_none() {
        let all: Vec<String> = endpoints.iter().map(ToString::to_string).collect();
        return f.into_check(
            check,
            &format!("sandboxed commands can't reach {}", hosts(&all)),
        );
    }
    let reach = match (&network.unknown, open.is_empty()) {
        (Some(why), true) => format!("network reach is unknown ({why})"),
        (Some(why), false) => format!("sandboxed commands can reach {} ({why})", hosts(&open)),
        (None, _) => format!("sandboxed commands can reach {}", hosts(&open)),
    };
    let close = "Remove these hosts from egress_allow in mezha.toml (and any WebFetch(domain:...) allow rule), or remove the credentials listed.";

    if opts.project_only {
        f.warn(
            format!("{reach}; whether a push gets through depends on each machine's credentials"),
            Some("Run `mezha verify` on each machine that runs Claude Code.".into()),
        );
    } else if !inventory.reachable.is_empty() {
        f.fail(
            format!(
                "{reach}, and these credentials are reachable: {}",
                inventory.reachable.join("; ")
            ),
            close,
        );
    } else if !inventory.unknown.is_empty() {
        f.add(
            Status::Warn,
            format!(
                "unverified: {reach}, and these credential sources can't be judged: {}",
                inventory.unknown.join("; ")
            ),
            Some(close.into()),
        );
    } else {
        f.add(
            Status::Pass,
            format!(
                "{reach}, but no credential is reachable (checked: {})",
                inventory.checked.join(", ")
            ),
            None,
        );
    }
    f.into_check(check, "")
}
