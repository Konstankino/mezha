//! Reading what a network probe printed. Pure, so the table of git, curl,
//! ssh and socat messages runs on every platform.
//!
//! Lines a server sends arrive prefixed with `remote:` and never count as
//! local markers (a proxy refusal, the push session): a server can't fake
//! those. Without the script's closing `MEZHA_PROBE_EXIT=` line nothing is
//! concluded.

use crate::ctx::Platform;
use crate::hosts::Scheme;

pub const EXIT_MARKER: &str = "MEZHA_PROBE_EXIT=";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The sandbox's proxy refused the connection: shown closed.
    Blocked,
    /// The server answered and asked for a credential: the network is open.
    Unauthenticated,
    /// ssh reached the server but stopped before offering a credential
    /// (its known hosts are withheld): open, credentials not tested.
    ReachedNoAuth,
    /// The server turned a credential down: a credential source exists.
    CredentialRejected,
    /// A credential reached the server, which refused this push.
    AuthDenied,
    /// The server accepted a push session: a push would go through.
    PushSession,
    Inconclusive(String),
}

impl Outcome {
    /// A credential got as far as the server.
    pub fn credential_shown(&self) -> bool {
        matches!(
            self,
            Outcome::CredentialRejected | Outcome::AuthDenied | Outcome::PushSession
        )
    }

    /// `Some(true)` open, `Some(false)` shown closed, `None` unknown.
    pub fn network_open(&self) -> Option<bool> {
        match self {
            Outcome::Blocked => Some(false),
            Outcome::Inconclusive(_) => None,
            _ => Some(true),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Outcome::Blocked => "refused by the sandbox proxy".into(),
            Outcome::Unauthenticated => "reachable, the server asked for a credential".into(),
            Outcome::ReachedNoAuth => "reachable (ssh stopped before offering a credential)".into(),
            Outcome::CredentialRejected => {
                "reachable, and a credential was offered and rejected".into()
            }
            Outcome::AuthDenied => "reachable, and a credential reached the server".into(),
            Outcome::PushSession => "reachable, and the server accepted a push session".into(),
            Outcome::Inconclusive(why) => format!("inconclusive ({why})"),
        }
    }
}

/// Classifies a probe's combined output. `nonce` names the probe's ref;
/// `scheme` and `platform` decide what a refusal proves (on macOS, ssh
/// fails inside srt whether or not the host is allowed).
pub fn classify(output: &str, nonce: &str, scheme: Scheme, platform: Platform) -> Outcome {
    let all: Vec<&str> = output.lines().map(str::trim).collect();
    let local: Vec<&str> = all
        .iter()
        .copied()
        .filter(|l| !l.starts_with("remote:"))
        .collect();
    let has_local = |pattern: &str| local.iter().any(|l| l.contains(pattern));
    let has_any = |pattern: &str| all.iter().any(|l| l.contains(pattern));

    if !local.iter().any(|l| l.starts_with(EXIT_MARKER)) {
        return Outcome::Inconclusive("the probe didn't finish".into());
    }
    if !nonce.is_empty()
        && has_local(&format!(
            "unable to delete 'mezha-probe-{nonce}': remote ref does not exist"
        ))
    {
        return Outcome::PushSession;
    }
    if all
        .iter()
        .any(|l| l.contains("Permission to ") && l.contains(" denied to "))
        || has_any("Write access to repository not granted")
        || has_any("marked as read only")
        || has_any("not allowed to push")
    {
        return Outcome::AuthDenied;
    }
    if has_any("Authentication failed")
        || has_any("Invalid username or password")
        || has_any("Password authentication is not supported")
        || has_any("HTTP Basic: Access denied")
    {
        return Outcome::CredentialRejected;
    }
    let proxy_refused = match scheme {
        Scheme::Https | Scheme::Http => {
            has_local("CONNECT tunnel failed, response 403")
                || has_local("Received HTTP code 403 from proxy")
        }
        // socat logs `E <request>: <reason>`; when its request line keeps
        // ` HTTP/1.0\r\n`, the reason lands on the next line.
        Scheme::Ssh => local.iter().enumerate().any(|(i, l)| {
            l.contains("socat[")
                && l.contains(" E CONNECT ")
                && (l.ends_with(": Forbidden")
                    || local.get(i + 1).is_some_and(|next| *next == ": Forbidden"))
        }),
        _ => false,
    };
    if proxy_refused {
        return match (scheme, platform) {
            (Scheme::Ssh, Platform::MacOs) => Outcome::Inconclusive(
                "ssh fails inside srt on macOS whether or not the host is allowed".into(),
            ),
            _ => Outcome::Blocked,
        };
    }
    if has_local("response 407") || has_local("Received HTTP code 407") {
        return Outcome::Inconclusive("the proxy asked for authentication".into());
    }
    if (has_any("could not read Username") && has_any("terminal prompts disabled"))
        || has_local("Permission denied (publickey")
    {
        return Outcome::Unauthenticated;
    }
    if has_local("Host key verification failed") {
        return Outcome::ReachedNoAuth;
    }
    if scheme == Scheme::Ssh && platform == Platform::MacOs {
        return Outcome::Inconclusive(
            "ssh fails inside srt on macOS whether or not the host is allowed".into(),
        );
    }
    let why = if has_local("Could not resolve host") {
        "the host name didn't resolve, so the request skipped srt's proxy".to_string()
    } else if has_any("Repository not found") {
        "the repository wasn't found".to_string()
    } else if has_local("timed out") || has_local("Timeout") {
        "the connection timed out".to_string()
    } else if has_local("Failed to connect") || has_local("Connection refused") {
        "the connection failed".to_string()
    } else {
        local
            .iter()
            .find(|l| l.starts_with("fatal:") || l.starts_with("error:"))
            .map_or_else(
                || "no known message".to_string(),
                |l| l.chars().take(160).collect(),
            )
    };
    Outcome::Inconclusive(why)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &str = "0123abcd";

    fn out(lines: &[&str]) -> String {
        let mut text = lines.join("\n");
        text.push_str("\nMEZHA_PROBE_EXIT=128\n");
        text
    }

    fn https(lines: &[&str]) -> Outcome {
        classify(&out(lines), NONCE, Scheme::Https, Platform::Linux)
    }

    #[test]
    fn the_table() {
        use Outcome::*;
        let cases: [(&[&str], Outcome); 15] = [
            (
                &[
                    "fatal: unable to access 'https://github.com/o/r.git/': CONNECT tunnel failed, response 403",
                ],
                Blocked,
            ),
            (
                &[
                    "fatal: unable to access 'https://github.com/o/r.git/': Received HTTP code 403 from proxy after CONNECT",
                ],
                Blocked,
            ),
            (
                &[
                    "fatal: unable to access 'https://github.com/o/r.git/': CONNECT tunnel failed, response 407",
                ],
                Inconclusive("the proxy asked for authentication".into()),
            ),
            (
                &[
                    "fatal: could not read Username for 'https://github.com': terminal prompts disabled",
                ],
                Unauthenticated,
            ),
            (
                &[
                    "remote: Invalid username or password.",
                    "fatal: Authentication failed for 'https://github.com/o/r.git/'",
                ],
                CredentialRejected,
            ),
            (
                &[
                    "remote: Support for password authentication was removed.",
                    "remote: Password authentication is not supported for Git operations.",
                ],
                CredentialRejected,
            ),
            (&["remote: HTTP Basic: Access denied"], CredentialRejected),
            (
                &[
                    "remote: Permission to o/r.git denied to someone.",
                    "fatal: unable to access 'https://github.com/o/r.git/': The requested URL returned error: 403",
                ],
                AuthDenied,
            ),
            (
                &["remote: Write access to repository not granted."],
                AuthDenied,
            ),
            (
                &["remote: You are not allowed to push code to this project."],
                AuthDenied,
            ),
            (
                &[
                    "error: unable to delete 'mezha-probe-0123abcd': remote ref does not exist",
                    "error: failed to push some refs to 'https://github.com/o/r.git'",
                ],
                PushSession,
            ),
            (
                &[
                    "fatal: unable to access 'https://github.com/o/r.git/': Could not resolve host: github.com",
                ],
                Inconclusive(
                    "the host name didn't resolve, so the request skipped srt's proxy".into(),
                ),
            ),
            (
                &[
                    "remote: Repository not found.",
                    "fatal: repository 'https://github.com/o/r.git/' not found",
                ],
                Inconclusive("the repository wasn't found".into()),
            ),
            (
                &[
                    "fatal: unable to access 'https://h/': Failed to connect to h port 443 after 3 ms: Couldn't connect to server",
                ],
                Inconclusive("the connection failed".into()),
            ),
            (
                &["something else entirely"],
                Inconclusive("no known message".into()),
            ),
        ];
        for (lines, expected) in cases {
            assert_eq!(https(lines), expected, "{lines:?}");
        }
    }

    #[test]
    fn a_server_cannot_fake_local_markers() {
        assert_eq!(
            https(&[
                "remote: error: unable to delete 'mezha-probe-0123abcd': remote ref does not exist"
            ]),
            Outcome::Inconclusive("no known message".into())
        );
        assert_eq!(
            https(&["remote: CONNECT tunnel failed, response 403"]),
            Outcome::Inconclusive("no known message".into())
        );
        // Another probe's ref (or a guessed one) isn't this push session.
        assert!(matches!(
            https(&["error: unable to delete 'mezha-probe-ffff': remote ref does not exist"]),
            Outcome::Inconclusive(_)
        ));
    }

    #[test]
    fn without_the_exit_marker_nothing_is_concluded() {
        let text = "error: unable to delete 'mezha-probe-0123abcd': remote ref does not exist\n";
        assert_eq!(
            classify(text, NONCE, Scheme::Https, Platform::Linux),
            Outcome::Inconclusive("the probe didn't finish".into())
        );
        let remote_marker = "remote: MEZHA_PROBE_EXIT=0\nCONNECT tunnel failed, response 403\n";
        assert!(matches!(
            classify(remote_marker, NONCE, Scheme::Https, Platform::Linux),
            Outcome::Inconclusive(_)
        ));
    }

    #[test]
    fn ssh_depends_on_the_platform() {
        let refused = out(&[
            "2026/10/08 12:00:00 socat[4242] E CONNECT github.com:22: Forbidden",
            "kex_exchange_identification: Connection closed by remote host",
        ]);
        assert_eq!(
            classify(&refused, NONCE, Scheme::Ssh, Platform::Linux),
            Outcome::Blocked
        );
        assert!(matches!(
            classify(&refused, NONCE, Scheme::Ssh, Platform::MacOs),
            Outcome::Inconclusive(_)
        ));
        let auth = out(&["git@github.com: Permission denied (publickey)."]);
        assert_eq!(
            classify(&auth, NONCE, Scheme::Ssh, Platform::MacOs),
            Outcome::Unauthenticated
        );
        let hostkey = out(&[
            "Host key verification failed.",
            "fatal: Could not read from remote repository.",
        ]);
        assert_eq!(
            classify(&hostkey, NONCE, Scheme::Ssh, Platform::Linux),
            Outcome::ReachedNoAuth
        );
        let split = out(&[
            "2026/10/08 12:00:00 socat[4242] E CONNECT github.com:22 HTTP/1.0\r",
            ": Forbidden",
        ]);
        assert_eq!(
            classify(&split, NONCE, Scheme::Ssh, Platform::Linux),
            Outcome::Blocked
        );
        let proxy_auth =
            out(&["2026/10/08 socat[1] E CONNECT github.com:22: Proxy Authentication Required"]);
        assert!(matches!(
            classify(&proxy_auth, NONCE, Scheme::Ssh, Platform::Linux),
            Outcome::Inconclusive(_)
        ));
        let denied = out(&["ERROR: Permission to o/r.git denied to deploy-key."]);
        assert_eq!(
            classify(&denied, NONCE, Scheme::Ssh, Platform::MacOs),
            Outcome::AuthDenied
        );
        // With no marker at all, ssh on macOS says nothing either way.
        let nothing = out(&["ssh: something unexpected"]);
        assert_eq!(
            classify(&nothing, NONCE, Scheme::Ssh, Platform::MacOs),
            Outcome::Inconclusive(
                "ssh fails inside srt on macOS whether or not the host is allowed".into()
            )
        );
        assert_eq!(
            classify(&nothing, NONCE, Scheme::Ssh, Platform::Linux),
            Outcome::Inconclusive("no known message".into())
        );
    }

    #[test]
    fn a_timeout_is_inconclusive() {
        assert_eq!(
            https(&["fatal: unable to access 'https://h/': Connection timed out after 10001 ms"]),
            Outcome::Inconclusive("the connection timed out".into())
        );
        assert_eq!(
            https(&["ssh: connect to host h port 22: Timeout"]),
            Outcome::Inconclusive("the connection timed out".into())
        );
        // A `fatal:` line that matches nothing known is quoted, cut short.
        let long = format!("fatal: {}", "x".repeat(300));
        let outcome = https(&[&long]);
        let Outcome::Inconclusive(why) = &outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(why.chars().count(), 160, "{why}");
        assert!(why.starts_with("fatal: xxx"), "{why}");
    }

    #[test]
    fn what_each_outcome_proves() {
        use Outcome::*;
        let all = [
            Blocked,
            Unauthenticated,
            ReachedNoAuth,
            CredentialRejected,
            AuthDenied,
            PushSession,
            Inconclusive("why".into()),
        ];
        let shown: Vec<bool> = all.iter().map(Outcome::credential_shown).collect();
        assert_eq!(
            shown,
            [false, false, false, true, true, true, false],
            "{all:?}"
        );
        let open: Vec<Option<bool>> = all.iter().map(Outcome::network_open).collect();
        assert_eq!(
            open,
            [
                Some(false),
                Some(true),
                Some(true),
                Some(true),
                Some(true),
                Some(true),
                None
            ],
            "{all:?}"
        );
        let described: Vec<String> = all.iter().map(Outcome::describe).collect();
        assert_eq!(
            described,
            [
                "refused by the sandbox proxy",
                "reachable, the server asked for a credential",
                "reachable (ssh stopped before offering a credential)",
                "reachable, and a credential was offered and rejected",
                "reachable, and a credential reached the server",
                "reachable, and the server accepted a push session",
                "inconclusive (why)",
            ]
        );
    }
}
