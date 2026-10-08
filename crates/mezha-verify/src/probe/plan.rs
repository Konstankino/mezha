//! Which push URLs the network probe tries.

use crate::hosts::{Endpoint, Remote, Scheme};

/// At most this many (scheme, host, port) groups are probed.
pub const MAX_TARGETS: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub scheme: Scheme,
    pub endpoint: Endpoint,
    pub url: String,
}

/// The push URLs worth probing: HTTPS, HTTP and SSH ones, one per
/// (scheme, host, port), at most [`MAX_TARGETS`]. A URL must be made only
/// of characters git and ssh take literally, since it comes from git
/// config an agent can write; the rest are returned as skipped.
pub fn targets(urls: &[String]) -> (Vec<Target>, Vec<String>) {
    let mut targets: Vec<Target> = Vec::new();
    let mut skipped = Vec::new();
    for url in urls {
        let remote = Remote::parse(url);
        if !matches!(remote.scheme, Scheme::Https | Scheme::Http | Scheme::Ssh) {
            if remote.scheme != Scheme::Local {
                skipped.push(url.clone());
            }
            continue;
        }
        if !literal(url) {
            skipped.push(url.clone());
            continue;
        }
        let endpoint = Endpoint {
            host: remote.host.clone(),
            port: remote.port,
        };
        if targets
            .iter()
            .any(|t| t.scheme == remote.scheme && t.endpoint == endpoint)
        {
            continue;
        }
        if targets.len() == MAX_TARGETS {
            skipped.push(url.clone());
            continue;
        }
        targets.push(Target {
            scheme: remote.scheme,
            endpoint,
            url: url.clone(),
        });
    }
    (targets, skipped)
}

/// Letters, digits and `._~:/@%+=,-`, not starting with `-`.
fn literal(url: &str) -> bool {
    !url.starts_with('-')
        && url.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '.' | '_' | '~' | ':' | '/' | '@' | '%' | '+' | '=' | ',' | '-'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(urls: &[&str]) -> (Vec<String>, Vec<String>) {
        let urls: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
        let (targets, skipped) = targets(&urls);
        (targets.into_iter().map(|t| t.url).collect(), skipped)
    }

    #[test]
    fn one_url_per_scheme_host_and_port() {
        let (urls, skipped) = plan(&[
            "https://github.com/o/a.git",
            "https://x:tok@github.com/o/b.git",
            "git@github.com:o/a.git",
            "ssh://git@github.com:22/o/b.git",
            "ssh://git@ssh.github.com:443/o/a.git",
            "/srv/local.git",
            "file:///srv/local.git",
        ]);
        assert_eq!(
            urls,
            [
                "https://github.com/o/a.git",
                "git@github.com:o/a.git",
                "ssh://git@ssh.github.com:443/o/a.git"
            ]
        );
        assert!(skipped.is_empty(), "{skipped:?}");
    }

    #[test]
    fn urls_that_could_run_something_are_skipped() {
        let (urls, skipped) = plan(&[
            "ext::sh -c touch% /tmp/x",
            "fd::3",
            "https://github.com/o/$(id).git",
            "$(id)@github.com:o/r.git",
            "https://github.com/o/r.git;id",
            "git://github.com/o/r.git",
            "https://github.com/o/r`id`.git",
        ]);
        assert!(urls.is_empty(), "{urls:?}");
        assert_eq!(skipped.len(), 7);
    }

    #[test]
    fn at_most_five_targets() {
        let urls: Vec<String> = (0..7).map(|i| format!("https://h{i}.example/r")).collect();
        let (targets, skipped) = targets(&urls);
        assert_eq!(targets.len(), MAX_TARGETS);
        assert_eq!(skipped.len(), 2);
    }
}
