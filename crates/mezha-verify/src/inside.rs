//! `mezha verify --inside`: run by Claude through its Bash tool, so it sees
//! the sandbox Claude Code built (its own merge of the settings, the `env`
//! block, its proxy) instead of mezha's reading of the settings.
//!
//! - Whether this command is sandboxed comes from the kernel, not the
//!   environment, which anyone can set: a direct connection is refused at
//!   once (EPERM on macOS; on Linux the sandbox has its own network
//!   namespace and user namespace), and mezha's own `denyWrite` on
//!   `mezha.toml` refuses an open for writing, which writes nothing.
//! - It contacts no host Claude Code might ask you about, or let through
//!   silently in bypassPermissions mode: only srt's proxy without its token
//!   (a 407 comes before any filtering), and forge hosts in
//!   `deniedDomains`, which are refused in every permission mode.
//! - The static checks don't run: inside the sandbox a withheld file looks
//!   absent, so they would misread it.
//!
//! The report reaches the user through the agent. It is a diagnostic, not
//! proof against an agent that wants to deceive: read the command's own
//! output in the tool result.

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use mezha_spec::SPEC_FILE;

use crate::checks::push::Network;
use crate::creds;
use crate::ctx::{Ctx, Platform};
use crate::gitcfg::GitConfig;
use crate::hosts::Scheme;
use crate::layers::Layers;
use crate::probe::{self, Outcome, plan};
use crate::report::{self, Check, Findings, Kind, Status};

/// TEST-NET-1: an address for documentation that no network routes.
const NOWHERE: ([u8; 4], u16) = ([192, 0, 2, 1], 443);
const PROXY_REQUEST: &[u8] =
    b"CONNECT mezha-probe.invalid:443 HTTP/1.1\r\nHost: mezha-probe.invalid:443\r\n\r\n";

/// What a direct connection to [`NOWHERE`] came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direct {
    /// Refused at once (EPERM): a sandbox profile.
    Refused,
    /// No route at all (ENETUNREACH): a network namespace with only
    /// loopback, or a machine that is offline.
    NoRoute,
    /// The packets left: a timeout, or an answer from the network.
    Left,
    Unknown,
}

pub fn classify_direct(kind: ErrorKind) -> Direct {
    match kind {
        ErrorKind::PermissionDenied => Direct::Refused,
        ErrorKind::NetworkUnreachable => Direct::NoRoute,
        ErrorKind::TimedOut
        | ErrorKind::ConnectionRefused
        | ErrorKind::ConnectionReset
        | ErrorKind::HostUnreachable => Direct::Left,
        _ => Direct::Unknown,
    }
}

fn direct_egress() -> Direct {
    let addr = SocketAddr::from(NOWHERE);
    match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
        Ok(_) => Direct::Left,
        Err(e) => classify_direct(e.kind()),
    }
}

/// `/proc/self/uid_map` in the user namespace srt's bubblewrap makes: one
/// line that maps a single id, not the whole range.
pub fn single_id_map(text: &str) -> bool {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    lines.len() == 1 && lines[0].split_whitespace().nth(2) == Some("1")
}

/// `NoNewPrivs: 1` in `/proc/self/status`.
pub fn no_new_privs(status: &str) -> bool {
    status
        .lines()
        .any(|l| l.starts_with("NoNewPrivs:") && l.split_whitespace().nth(1) == Some("1"))
}

/// `/proc/self/net/dev` lists only loopback.
pub fn loopback_only(net_dev: &str) -> bool {
    let names: Vec<&str> = net_dev
        .lines()
        .skip(2)
        .filter_map(|l| l.split_once(':').map(|(name, _)| name.trim()))
        .collect();
    !names.is_empty() && names.iter().all(|n| *n == "lo")
}

/// Whether mezha's `denyWrite` on `mezha.toml` is in force here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    Applied,
    NotApplied,
    Unknown(String),
}

pub fn classify_write(kind: ErrorKind) -> Policy {
    match kind {
        ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem => Policy::Applied,
        other => Policy::Unknown(format!(
            "opening mezha.toml for writing failed oddly ({other:?})"
        )),
    }
}

/// Opens `mezha.toml` for appending and closes it again without writing.
fn policy(root: &Path) -> Policy {
    let path = root.join(SPEC_FILE);
    let Ok(meta) = fs::metadata(&path) else {
        return Policy::Unknown("mezha.toml can't be read".into());
    };
    if meta.permissions().readonly() {
        return Policy::Unknown("mezha.toml is read-only, so a refused write shows nothing".into());
    }
    match fs::OpenOptions::new().append(true).open(&path) {
        Ok(_) => Policy::NotApplied,
        Err(e) => classify_write(e.kind()),
    }
}

/// Everything that says whether this command is sandboxed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signals {
    pub platform: Platform,
    pub direct: Direct,
    pub single_id_map: bool,
    pub no_new_privs: bool,
    pub loopback_only: bool,
    pub policy: Policy,
    /// `SANDBOX_RUNTIME` is set; anyone can set it, so it only informs.
    pub env_says_sandboxed: bool,
}

impl Signals {
    pub fn gather(ctx: &Ctx) -> Signals {
        let proc =
            |file: &str| fs::read_to_string(format!("/proc/self/{file}")).unwrap_or_default();
        Signals {
            platform: ctx.platform,
            direct: direct_egress(),
            single_id_map: single_id_map(&proc("uid_map")),
            no_new_privs: no_new_privs(&proc("status")),
            loopback_only: loopback_only(&proc("net/dev")),
            policy: policy(&ctx.root),
            env_says_sandboxed: ctx.var("SANDBOX_RUNTIME").is_some(),
        }
    }

    /// The kernel says so: macOS refuses the connection; on Linux there is
    /// no route out of a namespace with only loopback, in a user namespace
    /// or under no-new-privs.
    pub fn sandboxed(&self) -> bool {
        match self.platform {
            Platform::MacOs => self.direct == Direct::Refused,
            Platform::Linux | Platform::Wsl2 => {
                matches!(self.direct, Direct::Refused | Direct::NoRoute)
                    && self.loopback_only
                    && (self.single_id_map || self.no_new_privs)
            }
            _ => false,
        }
    }
}

fn new_check(id: &'static str, title: &'static str) -> Check {
    Check {
        evidence: vec![report::INSIDE],
        ..Check::new(id, title, Kind::Boundary)
    }
}

pub fn sandbox_check(signals: &Signals) -> Check {
    let check = new_check("inside-sandbox", "this command runs in the sandbox");
    let mut f = Findings::default();
    let env = if signals.env_says_sandboxed {
        "SANDBOX_RUNTIME is set"
    } else {
        "SANDBOX_RUNTIME isn't set"
    };
    match (signals.sandboxed(), &signals.policy) {
        (true, Policy::Applied) => f.add(
            Status::Pass,
            format!("the kernel refuses a direct connection and mezha.toml can't be written, so this project's sandbox is in force ({env})"),
            None,
        ),
        (true, Policy::NotApplied) => f.fail(
            "the sandbox runs, but without this project's settings: mezha.toml can be written",
            "Start Claude Code in the project root, without --setting-sources leaving out the project.",
        ),
        (false, Policy::NotApplied) => f.fail(
            format!("this command ran outside the sandbox: a direct connection wasn't refused and mezha.toml can be written ({env})"),
            "Ask Claude to run `mezha verify --inside` with the Bash tool, not as a `!` command, and decline any retry outside the sandbox. If it still fails, run `mezha verify`.",
        ),
        (false, Policy::Applied) => f.warn(
            format!("mezha.toml can't be written, but the kernel shows no sandbox ({env})"),
            None,
        ),
        (_, Policy::Unknown(why)) => f.warn(format!("can't tell whether the sandbox is in force: {why}"), None),
    }
    f.into_check(check, "")
}

/// What answers on the sandbox's proxy port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proxy {
    /// srt's proxy: a 407 asking for its own token.
    Srt,
    Other(String),
    Missing,
    Unreachable,
}

/// `http://user:token@localhost:3128` → `localhost:3128`.
pub fn proxy_addr(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split('/').next()?;
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    (!hostport.is_empty()).then(|| hostport.to_string())
}

/// Reads a proxy's answer to a CONNECT without credentials.
pub fn read_proxy_answer(head: &str) -> Proxy {
    let status = head.lines().next().unwrap_or("").trim();
    let srt = head.lines().any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("proxy-authenticate:") && l.contains("realm=\"srt\"")
    });
    if status.split_whitespace().nth(1) == Some("407") && srt {
        Proxy::Srt
    } else {
        Proxy::Other(status.chars().take(80).collect())
    }
}

/// Asks the proxy in `HTTPS_PROXY` for a tunnel without its token. srt
/// answers 407 before it looks at the host, so nobody is asked anything.
fn fingerprint(ctx: &Ctx) -> Proxy {
    let Some(addr) = ctx
        .var("HTTPS_PROXY")
        .or_else(|| ctx.var("https_proxy"))
        .and_then(proxy_addr)
    else {
        return Proxy::Missing;
    };
    let candidates: Vec<SocketAddr> = match addr.strip_prefix("localhost:").map(str::parse::<u16>) {
        Some(Ok(port)) => vec![
            SocketAddr::from(([127, 0, 0, 1], port)),
            SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 1], port)),
        ],
        _ => addr
            .to_socket_addrs()
            .map(Iterator::collect)
            .unwrap_or_default(),
    };
    for socket in candidates {
        let Ok(mut stream) = TcpStream::connect_timeout(&socket, Duration::from_secs(2)) else {
            continue;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
        if stream.write_all(PROXY_REQUEST).is_err() {
            continue;
        }
        let mut head = Vec::new();
        let mut buf = [0u8; 512];
        while head.len() < 4096 && !head.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => head.extend_from_slice(&buf[..n]),
            }
        }
        return read_proxy_answer(&String::from_utf8_lossy(&head));
    }
    Proxy::Unreachable
}

pub fn network_check(
    ctx: &Ctx,
    layers: &Layers,
    git: Option<&GitConfig>,
    signals: &Signals,
) -> Check {
    let check = new_check("inside-network", "the sandbox's network, from inside");
    if !signals.sandboxed() {
        return Check::skip(
            "inside-network",
            "the sandbox's network, from inside",
            Kind::Boundary,
            "the command ran outside the sandbox",
        );
    }
    let mut f = Findings::default();
    f.add(Status::Pass, "direct connections are refused", None);
    let proxy = fingerprint(ctx);
    match &proxy {
        Proxy::Srt => f.add(
            Status::Pass,
            "srt's proxy is in front (it asked for its token)",
            None,
        ),
        Proxy::Missing => f.warn("no HTTPS_PROXY here, so the sandbox's proxy wasn't found", None),
        Proxy::Unreachable => f.warn("the proxy in HTTPS_PROXY doesn't answer", None),
        Proxy::Other(status) => f.warn(
            format!("the proxy isn't srt's (it answered `{status}`), as with a custom proxy; forge hosts weren't contacted"),
            None,
        ),
    }
    if proxy != Proxy::Srt || signals.policy != Policy::Applied {
        if signals.policy != Policy::Applied {
            f.warn(
                "this project's settings aren't in force, so forge hosts weren't contacted",
                None,
            );
        }
        return f.into_check(check, "");
    }

    let network = Network::from_layers(layers);
    let urls = git.map(GitConfig::push_urls).unwrap_or_default();
    let (targets, _) = plan::targets(&urls);
    let (denied, other): (Vec<_>, Vec<_>) = targets
        .into_iter()
        .partition(|t| network.denied(&t.endpoint));
    if !other.is_empty() {
        let names: Vec<String> = other.iter().map(|t| t.endpoint.to_string()).collect();
        f.warn(
            format!(
                "not contacted, since Claude Code could ask you about them or let them through: {}",
                names.join(", ")
            ),
            Some("Run `mezha compile`, which denies the known forge hosts in every permission mode, and add other hosts to sandbox.network.deniedDomains in your user settings.".into()),
        );
    }
    // ssh can't use srt's proxy on macOS at all, so a probe there says
    // nothing; deniedDomains covers every protocol anyway.
    let (unprobed, denied): (Vec<_>, Vec<_>) = denied
        .into_iter()
        .partition(|t| t.scheme == Scheme::Ssh && ctx.platform == Platform::MacOs);
    if !unprobed.is_empty() {
        let names: Vec<String> = unprobed.iter().map(|t| t.endpoint.to_string()).collect();
        f.add(
            Status::Pass,
            format!(
                "not probed, since ssh can't use srt's proxy on macOS: {} (deniedDomains lists it)",
                names.join(", ")
            ),
            None,
        );
    }
    let mut refused = Vec::new();
    for result in probe::network_here(ctx, &denied, git) {
        let endpoint = result.target.endpoint.to_string();
        match &result.outcome {
            Outcome::Blocked => refused.push(endpoint),
            Outcome::Inconclusive(why) => {
                f.warn(format!("{endpoint}: inconclusive ({why})"), None)
            }
            outcome => f.fail(
                format!(
                    "Claude Code let {endpoint} through although deniedDomains lists it: {}",
                    outcome.describe()
                ),
                "Report this, with your Claude Code version, to Anthropic; until then keep pushes in your own terminal.",
            ),
        }
    }
    if !refused.is_empty() {
        f.add(
            Status::Pass,
            format!("refused inside the sandbox: {}", refused.join(", ")),
            None,
        );
    }
    f.into_check(check, "")
}

/// What looking at a credential path showed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Look {
    Error(ErrorKind),
    /// `/dev/null` bound over a withheld file (Linux).
    CharDevice,
    Dir,
    /// Bytes read (at most 1), or why reading failed.
    File(Result<usize, ErrorKind>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seen {
    Withheld,
    Absent,
    Empty,
    Readable,
}

pub fn judge_look(look: Look) -> Seen {
    match look {
        Look::Error(ErrorKind::NotFound) | Look::Dir => Seen::Absent,
        Look::Error(_) | Look::CharDevice | Look::File(Err(_)) => Seen::Withheld,
        Look::File(Ok(0)) => Seen::Empty,
        Look::File(Ok(_)) => Seen::Readable,
    }
}

fn look(path: &Path) -> Look {
    let meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) => return Look::Error(e.kind()),
    };
    #[cfg(unix)]
    if std::os::unix::fs::FileTypeExt::is_char_device(&meta.file_type()) {
        return Look::CharDevice;
    }
    if meta.is_dir() {
        return Look::Dir;
    }
    let mut byte = [0u8; 1];
    Look::File(
        fs::File::open(path)
            .and_then(|mut file| file.read(&mut byte))
            .map_err(|e| e.kind()),
    )
}

pub fn credentials_check(ctx: &Ctx, git: Option<&GitConfig>, signals: &Signals) -> Check {
    let check = new_check("inside-credentials", "credentials, from inside");
    if !signals.sandboxed() {
        return Check::skip(
            "inside-credentials",
            "credentials, from inside",
            Kind::Boundary,
            "the command ran outside the sandbox",
        );
    }
    let mut f = Findings::default();
    let mut reachable = Vec::new();
    let mut withheld = Vec::new();
    if let Some(ssh) = ctx.expand("~/.ssh")
        && fs::read_dir(&ssh).is_err_and(|e| e.kind() == ErrorKind::PermissionDenied)
    {
        withheld.push("~/.ssh".to_string());
    }
    let mut paths = probe::credential_paths(ctx, git);
    paths.dedup();
    for path in paths {
        let label = probe::label(ctx, &path);
        match judge_look(look(&path)) {
            Seen::Readable => reachable.push(label),
            Seen::Withheld => withheld.push(label),
            Seen::Absent | Seen::Empty => {}
        }
    }
    let mut masked = Vec::new();
    for name in creds::forge_token_vars(ctx) {
        match ctx.var(&name) {
            Some(value) if value.starts_with("fake_value_") => masked.push(name),
            Some(_) => reachable.push(format!("environment variable {name}")),
            None => {}
        }
    }
    #[cfg(unix)]
    if let Some(socket) = ctx.var("SSH_AUTH_SOCK") {
        match std::os::unix::net::UnixStream::connect(socket) {
            Ok(_) => reachable.push("the ssh agent (SSH_AUTH_SOCK)".into()),
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                withheld.push("the ssh agent (SSH_AUTH_SOCK)".into())
            }
            Err(_) => {}
        }
    }
    withheld.dedup();
    if !masked.is_empty() {
        f.add(
            Status::Pass,
            format!(
                "masked (the real value goes only to the hosts it's for): {}",
                masked.join(", ")
            ),
            None,
        );
    }
    if reachable.is_empty() {
        f.add(
            Status::Pass,
            if withheld.is_empty() {
                "no credential file or token variable is readable".to_string()
            } else {
                format!("nothing readable; withheld: {}", withheld.join(", "))
            },
            None,
        );
    } else {
        f.fail(
            format!("readable inside the sandbox: {}", reachable.join(", ")),
            "Run `mezha compile`, and withhold anything else in sandbox.credentials in your user settings.",
        );
    }
    f.into_check(check, "")
}

/// The three inside checks and the notes that go with them.
pub fn checks(ctx: &Ctx, layers: &Layers, git: Option<&GitConfig>) -> (Vec<Check>, Vec<String>) {
    let signals = Signals::gather(ctx);
    let checks = vec![
        sandbox_check(&signals),
        network_check(ctx, layers, git, &signals),
        credentials_check(ctx, git, &signals),
    ];
    let mut notes = vec![
        "this report comes from a command Claude ran: read the command's own output in the tool result, not Claude's summary of it".to_string(),
    ];
    if ctx.platform == Platform::MacOs {
        notes.push(
            "the macOS keychain is reachable from the sandbox by design (ADR-0003); --inside doesn't touch it".into(),
        );
    }
    (checks, notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_connections() {
        assert_eq!(
            classify_direct(ErrorKind::PermissionDenied),
            Direct::Refused
        );
        assert_eq!(
            classify_direct(ErrorKind::NetworkUnreachable),
            Direct::NoRoute
        );
        assert_eq!(classify_direct(ErrorKind::TimedOut), Direct::Left);
        assert_eq!(classify_direct(ErrorKind::HostUnreachable), Direct::Left);
        assert_eq!(classify_direct(ErrorKind::Other), Direct::Unknown);
    }

    #[test]
    fn linux_proc_files() {
        assert!(single_id_map("      1000       1000          1\n"));
        assert!(!single_id_map("         0          0 4294967295\n"));
        assert!(!single_id_map(""));
        assert!(no_new_privs("Name:\tbash\nNoNewPrivs:\t1\nSeccomp:\t2\n"));
        assert!(!no_new_privs("NoNewPrivs:\t0\n"));
        let header = "Inter-|   Receive\n face |bytes\n";
        assert!(loopback_only(&format!("{header}    lo: 0 0\n")));
        assert!(!loopback_only(&format!(
            "{header}    lo: 0 0\n  eth0: 1 2\n"
        )));
        assert!(!loopback_only(""));
    }

    fn signals(platform: Platform, direct: Direct, policy: Policy) -> Signals {
        Signals {
            platform,
            direct,
            single_id_map: true,
            no_new_privs: true,
            loopback_only: true,
            policy,
            env_says_sandboxed: false,
        }
    }

    #[test]
    fn the_sandbox_verdict() {
        let verdict = |s: Signals| {
            let c = sandbox_check(&s);
            (c.status, c.detail)
        };
        assert_eq!(
            verdict(signals(Platform::MacOs, Direct::Refused, Policy::Applied)).0,
            Status::Pass
        );
        assert_eq!(
            verdict(signals(Platform::Linux, Direct::NoRoute, Policy::Applied)).0,
            Status::Pass
        );
        let (status, detail) = verdict(signals(Platform::MacOs, Direct::Left, Policy::NotApplied));
        assert_eq!(status, Status::Fail);
        assert!(detail.contains("ran outside the sandbox"), "{detail}");
        let (status, detail) = verdict(signals(
            Platform::MacOs,
            Direct::Refused,
            Policy::NotApplied,
        ));
        assert_eq!(status, Status::Fail);
        assert!(
            detail.contains("without this project's settings"),
            "{detail}"
        );
        // An offline Linux machine has no route either, but real interfaces.
        let mut offline = signals(Platform::Linux, Direct::NoRoute, Policy::NotApplied);
        offline.loopback_only = false;
        assert!(!offline.sandboxed());
        // On macOS no route isn't the sandbox's answer.
        assert!(!signals(Platform::MacOs, Direct::NoRoute, Policy::Applied).sandboxed());
        assert_eq!(
            verdict(signals(Platform::MacOs, Direct::Left, Policy::Applied)).0,
            Status::Warn
        );
        assert_eq!(
            classify_write(ErrorKind::ReadOnlyFilesystem),
            Policy::Applied
        );
        assert_eq!(classify_write(ErrorKind::PermissionDenied), Policy::Applied);
    }

    #[test]
    fn proxies() {
        assert_eq!(
            proxy_addr("http://srt.abc:0123@localhost:3128").as_deref(),
            Some("localhost:3128")
        );
        assert_eq!(
            proxy_addr("http://127.0.0.1:8080/").as_deref(),
            Some("127.0.0.1:8080")
        );
        assert_eq!(proxy_addr("http://"), None);
        assert_eq!(
            read_proxy_answer(
                "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"srt\"\r\n\r\n"
            ),
            Proxy::Srt
        );
        assert_eq!(
            read_proxy_answer(
                "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"corp\"\r\n\r\n"
            ),
            Proxy::Other("HTTP/1.1 407 Proxy Authentication Required".into())
        );
        assert!(matches!(read_proxy_answer(""), Proxy::Other(_)));
    }

    #[test]
    fn credential_looks() {
        assert_eq!(
            judge_look(Look::Error(ErrorKind::PermissionDenied)),
            Seen::Withheld
        );
        assert_eq!(judge_look(Look::Error(ErrorKind::NotFound)), Seen::Absent);
        assert_eq!(judge_look(Look::CharDevice), Seen::Withheld);
        assert_eq!(judge_look(Look::File(Ok(1))), Seen::Readable);
        assert_eq!(judge_look(Look::File(Ok(0))), Seen::Empty);
        assert_eq!(
            judge_look(Look::File(Err(ErrorKind::PermissionDenied))),
            Seen::Withheld
        );
        assert_eq!(judge_look(Look::Dir), Seen::Absent);
    }
}
