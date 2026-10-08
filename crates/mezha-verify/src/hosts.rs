//! Which hosts sandboxed commands can reach, and which hosts a credential
//! can write to.
//!
//! Domain patterns follow the sandbox proxy: `example.com` matches only
//! itself, `*.example.com` matches subdomains at any depth but not the apex,
//! `*` matches every host, and an optional `:port` limits the port (without
//! one, every port matches).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    host: String,
    port: Option<u16>,
}

impl Pattern {
    pub fn parse(text: &str) -> Option<Pattern> {
        let text = text.trim().to_ascii_lowercase();
        if text.is_empty() {
            return None;
        }
        let (host, port) = match text.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), Some(port.parse().ok()?)),
            None => (text, None),
        };
        Some(Pattern { host, port })
    }

    pub fn matches(&self, endpoint: &Endpoint) -> bool {
        if self.port.is_some_and(|p| p != endpoint.port) {
            return false;
        }
        let host = endpoint.host.as_str();
        match self.host.as_str() {
            "*" => true,
            pattern => match pattern.strip_prefix("*.") {
                Some(suffix) => {
                    host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}"))
                }
                None => host == pattern,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Https,
    Http,
    Ssh,
    /// A local path or `file://`: no network.
    Local,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    /// The URL carries a user name or password (HTTP(S) only; `git@` for
    /// SSH is a user name, not a credential).
    pub has_secret: bool,
}

impl Remote {
    /// Understands `https://[user[:pass]@]host[:port]/path`,
    /// `ssh://[user@]host[:port]/path`, scp-like `user@host:path`, and local
    /// paths.
    pub fn parse(url: &str) -> Remote {
        let local = Remote {
            scheme: Scheme::Local,
            host: String::new(),
            port: 0,
            has_secret: false,
        };
        let url = url.trim();
        if let Some((scheme, rest)) = url.split_once("://") {
            let scheme_kind = match scheme.to_ascii_lowercase().as_str() {
                "https" => Scheme::Https,
                "http" => Scheme::Http,
                "ssh" | "git+ssh" | "ssh+git" => Scheme::Ssh,
                "file" => return local,
                _ => Scheme::Other,
            };
            let authority = rest.split('/').next().unwrap_or("");
            let (userinfo, hostport) = match authority.rsplit_once('@') {
                Some((user, hp)) => (Some(user), hp),
                None => (None, authority),
            };
            let (host, port) = split_port(hostport);
            let default_port = match scheme_kind {
                Scheme::Https => 443,
                Scheme::Http => 80,
                Scheme::Ssh => 22,
                _ => 0,
            };
            let http = matches!(scheme_kind, Scheme::Https | Scheme::Http);
            return Remote {
                scheme: scheme_kind,
                host: host.to_ascii_lowercase(),
                port: port.unwrap_or(default_port),
                has_secret: http && userinfo.is_some_and(|u| !u.is_empty()),
            };
        }
        // scp-like: `[user@]host:path`, where the colon comes before any slash.
        if let Some(colon) = url.find(':') {
            let before = &url[..colon];
            // `C:\repo` is a Windows path, not a host called `C`.
            let drive_letter = before.len() == 1 && cfg!(windows);
            if !before.contains('/') && !before.is_empty() && !drive_letter {
                let host = before.rsplit('@').next().unwrap_or(before);
                return Remote {
                    scheme: Scheme::Ssh,
                    host: host.to_ascii_lowercase(),
                    port: 22,
                    has_secret: false,
                };
            }
        }
        local
    }

    /// The host:port pairs a credential for this remote can write through:
    /// the remote itself plus the forge's API and upload hosts.
    pub fn write_endpoints(&self) -> Vec<Endpoint> {
        if matches!(self.scheme, Scheme::Local) || self.host.is_empty() {
            return Vec::new();
        }
        let mut endpoints = vec![Endpoint {
            host: self.host.clone(),
            port: self.port,
        }];
        let https = |host: &str| Endpoint {
            host: host.to_string(),
            port: 443,
        };
        match self.host.as_str() {
            "github.com" => {
                endpoints.extend([
                    https("github.com"),
                    https("api.github.com"),
                    https("uploads.github.com"),
                ]);
            }
            "gitlab.com" => endpoints.push(https("gitlab.com")),
            "bitbucket.org" => {
                endpoints.extend([https("bitbucket.org"), https("api.bitbucket.org")])
            }
            other if self.scheme == Scheme::Ssh => endpoints.push(https(other)),
            _ => {}
        }
        endpoints.sort();
        endpoints.dedup();
        endpoints
    }
}

fn split_port(hostport: &str) -> (&str, Option<u16>) {
    if let Some(rest) = hostport.strip_prefix('[') {
        // [ipv6]:port
        if let Some((host, after)) = rest.split_once(']') {
            return (host, after.strip_prefix(':').and_then(|p| p.parse().ok()));
        }
    }
    match hostport.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => (host, port.parse().ok()),
        _ => (hostport, None),
    }
}

/// GitHub's write endpoints, for a `gh` login.
pub fn github_endpoints() -> Vec<Endpoint> {
    Remote::parse("https://github.com/").write_endpoints()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(host: &str, port: u16) -> Endpoint {
        Endpoint {
            host: host.into(),
            port,
        }
    }

    #[test]
    fn domain_patterns() {
        let p = |s| Pattern::parse(s).unwrap();
        assert!(p("github.com").matches(&ep("github.com", 443)));
        assert!(p("GitHub.com").matches(&ep("github.com", 22)));
        assert!(!p("github.com").matches(&ep("api.github.com", 443)));
        assert!(p("*.github.com").matches(&ep("api.github.com", 443)));
        assert!(p("*.github.com").matches(&ep("a.b.github.com", 443)));
        assert!(!p("*.github.com").matches(&ep("github.com", 443)));
        assert!(!p("*.github.com").matches(&ep("evilgithub.com", 443)));
        assert!(p("*").matches(&ep("anything.example", 1)));
        assert!(p("github.com:443").matches(&ep("github.com", 443)));
        assert!(!p("github.com:443").matches(&ep("github.com", 22)));
        assert!(p("*:22").matches(&ep("github.com", 22)));
        assert!(Pattern::parse("").is_none());
        assert!(Pattern::parse("host:notaport").is_none());
    }

    #[test]
    fn remotes() {
        let r = Remote::parse("https://x:ghp_t@github.com/o/r.git");
        assert_eq!(
            (r.scheme, r.host.as_str(), r.port, r.has_secret),
            (Scheme::Https, "github.com", 443, true)
        );
        let r = Remote::parse("git@github.com:o/r.git");
        assert_eq!(
            (r.scheme, r.host.as_str(), r.port, r.has_secret),
            (Scheme::Ssh, "github.com", 22, false)
        );
        let r = Remote::parse("ssh://git@git.example.com:2222/r");
        assert_eq!((r.host.as_str(), r.port), ("git.example.com", 2222));
        let r = Remote::parse("https://ghe.corp:8443/o/r");
        assert_eq!(
            (r.host.as_str(), r.port, r.has_secret),
            ("ghe.corp", 8443, false)
        );
        assert_eq!(Remote::parse("/srv/git/r.git").scheme, Scheme::Local);
        assert_eq!(Remote::parse("file:///srv/r").scheme, Scheme::Local);
        assert_eq!(Remote::parse("../r").scheme, Scheme::Local);
    }

    #[test]
    fn write_endpoints() {
        let hosts: Vec<String> = Remote::parse("git@github.com:o/r")
            .write_endpoints()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            hosts,
            [
                "api.github.com:443",
                "github.com:22",
                "github.com:443",
                "uploads.github.com:443"
            ]
        );
        assert!(Remote::parse("/local").write_endpoints().is_empty());
        let hosts: Vec<String> = Remote::parse("https://bitbucket.org/o/r")
            .write_endpoints()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(hosts, ["api.bitbucket.org:443", "bitbucket.org:443"]);
    }
}
