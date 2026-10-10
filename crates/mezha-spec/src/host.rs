//! Host patterns, as `egress_allow` and `fetch_allow` take them:
//! `example.com` is that host only, `*.example.com` its subdomains at any
//! depth (not the apex), `*` every host. Only the host is compared, at
//! label boundaries, never as a substring.

/// A validated host pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPattern(String);

impl HostPattern {
    pub fn parse(text: &str) -> Result<HostPattern, String> {
        let lower = text.trim_end_matches('.').to_ascii_lowercase();
        let host = lower.strip_prefix("*.").unwrap_or(&lower);
        let label = |l: &str| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        };
        let valid = lower == "*" || (host.len() <= 253 && host.split('.').all(label));
        if valid {
            Ok(HostPattern(lower))
        } else {
            Err(format!(
                "`{}` is not a host: use a name such as docs.rs or *.example.com, without a scheme, port or path",
                text.escape_debug()
            ))
        }
    }

    pub fn matches(&self, host: &str) -> bool {
        host_matches(&self.0, host)
    }
}

impl std::fmt::Display for HostPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether `pattern` covers `host`, ignoring case and a trailing dot.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    match pattern.as_str() {
        "*" => true,
        p => match p.strip_prefix("*.") {
            Some(suffix) => host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}")),
            None => host == p,
        },
    }
}

/// The host of an http(s) URL, lowercased, as a browser would read it:
/// a backslash ends the authority like a slash, and userinfo and the port
/// are dropped. Anything unusual (percent-encoding, spaces, non-ASCII) is
/// refused rather than guessed at.
pub fn url_host(url: &str) -> Option<String> {
    let (scheme, rest) = url.trim().split_once("://")?;
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return None;
    }
    let authority = rest.split(['/', '\\', '?', '#']).next()?;
    let host_port = authority.rsplit('@').next()?;
    let host = match host_port.strip_prefix('[') {
        Some(v6) => v6.split(']').next()?,
        None => host_port.split(':').next()?,
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let plain = host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == ':');
    (!host.is_empty() && plain).then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns() {
        let p = |t: &str| HostPattern::parse(t).unwrap();
        assert!(p("docs.rs").matches("DOCS.rs."));
        assert!(!p("docs.rs").matches("x.docs.rs"));
        assert!(p("*.example.com").matches("a.b.example.com"));
        assert!(!p("*.example.com").matches("example.com"));
        assert!(!p("*.example.com").matches("evilexample.com"));
        assert!(!p("example.com").matches("example.com.evil.net"));
        assert!(p("*").matches("anything.example"));
        for bad in [
            "https://docs.rs",
            "docs.rs/x",
            "docs.rs:443",
            "*.*.x",
            "",
            "a b",
            "-x.com",
            "x'y",
        ] {
            assert!(HostPattern::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn hosts_of_urls() {
        let host = |u: &str| url_host(u);
        assert_eq!(host("https://Docs.RS/x?y#z").as_deref(), Some("docs.rs"));
        assert_eq!(
            host("http://user:pw@a.example.com:8080/").as_deref(),
            Some("a.example.com")
        );
        assert_eq!(host("https://[::1]:443/").as_deref(), Some("::1"));
        // A backslash ends the authority, as in a browser.
        assert_eq!(
            host("https://evil.example\\@docs.rs/").as_deref(),
            Some("evil.example")
        );
        assert_eq!(host("https://docs.rs.").as_deref(), Some("docs.rs"));
        for bad in [
            "ftp://docs.rs",
            "docs.rs",
            "https://",
            "https://ev%2Eil.com/",
            "https://dócs.rs",
            "https://a b.com",
        ] {
            assert_eq!(host(bad), None, "{bad}");
        }
    }
}
