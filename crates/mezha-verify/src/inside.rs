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
use std::path::{Path, PathBuf};
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

/// `Seccomp: 2` in `/proc/self/status`: a seccomp filter is applied. srt's
/// is one; so is Docker's default, so this only says which way sockets
/// that turn out open are open.
pub fn seccomp_filter(status: &str) -> bool {
    status
        .lines()
        .any(|l| l.starts_with("Seccomp:") && l.split_whitespace().nth(1) == Some("2"))
}

/// The real user id from `/proc/self/status`, as the sandbox maps it.
pub fn uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find(|l| l.starts_with("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// Whether a sandboxed command can open unix sockets: how an ssh or gpg
/// agent, a keyring and git's credential-cache hand out credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sockets {
    /// Refused (EPERM): srt's seccomp filter on Linux, its profile on
    /// macOS.
    Blocked,
    /// A connect got through the sandbox to the socket layer.
    Open,
    Unknown(String),
}

/// Linux: srt's filter refuses `socket()` itself, so a connect to a path
/// that doesn't exist tells. EPERM means sockets are blocked; ENOENT
/// means the socket was made and only the path was missing.
pub fn classify_linux(kind: ErrorKind) -> Sockets {
    match kind {
        ErrorKind::PermissionDenied => Sockets::Blocked,
        ErrorKind::NotFound | ErrorKind::ConnectionRefused => Sockets::Open,
        other => Sockets::Unknown(format!(
            "connecting to a unix socket failed oddly ({other:?})"
        )),
    }
}

/// macOS: the profile judges each connect by its path, after the path is
/// looked up, so only sockets that exist tell. One refused means the
/// profile denies by default (`allowUnixSockets` names paths, which the
/// static checks read); every one let through means `allowAllUnixSockets`
/// or an allowed path above them all.
pub fn classify_macos(outcomes: &[Result<(), ErrorKind>]) -> Sockets {
    if outcomes.contains(&Err(ErrorKind::PermissionDenied)) {
        Sockets::Blocked
    } else if outcomes.iter().any(|o| *o != Err(ErrorKind::NotFound)) {
        Sockets::Open
    } else {
        Sockets::Unknown("no system socket was there to try".into())
    }
}

/// System sockets every macOS has, which srt's profile doesn't allow on
/// its own. A connect that gets through does nothing to them.
#[cfg(unix)]
const MACOS_SOCKETS: [&str; 2] = ["/private/var/run/mDNSResponder", "/var/run/syslog"];

#[cfg(unix)]
fn probe_sockets(platform: Platform) -> Sockets {
    use std::os::unix::net::UnixStream;
    match platform {
        Platform::Linux | Platform::Wsl2 => {
            let path = std::env::temp_dir().join("mezha-inside-no-such-socket");
            match UnixStream::connect(&path) {
                Ok(_) => Sockets::Open,
                Err(e) => classify_linux(e.kind()),
            }
        }
        Platform::MacOs => {
            let outcomes: Vec<Result<(), ErrorKind>> = MACOS_SOCKETS
                .iter()
                .map(|path| UnixStream::connect(path).map(drop).map_err(|e| e.kind()))
                .collect();
            classify_macos(&outcomes)
        }
        _ => Sockets::Unknown("no sandbox on this platform".into()),
    }
}

#[cfg(not(unix))]
fn probe_sockets(_: Platform) -> Sockets {
    Sockets::Unknown("no unix sockets on this platform".into())
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
    pub sockets: Sockets,
    /// A seccomp filter is applied (Linux); informs the sockets verdict.
    pub seccomp_filter: bool,
    /// The user id, for the runtime directory agents listen in (Linux).
    pub uid: Option<u32>,
}

impl Signals {
    pub fn gather(ctx: &Ctx) -> Signals {
        let proc =
            |file: &str| fs::read_to_string(format!("/proc/self/{file}")).unwrap_or_default();
        let status = proc("status");
        Signals {
            platform: ctx.platform,
            direct: direct_egress(),
            single_id_map: single_id_map(&proc("uid_map")),
            no_new_privs: no_new_privs(&status),
            loopback_only: loopback_only(&proc("net/dev")),
            policy: policy(&ctx.root),
            env_says_sandboxed: ctx.var("SANDBOX_RUNTIME").is_some(),
            sockets: probe_sockets(ctx.platform),
            seccomp_filter: seccomp_filter(&status),
            uid: uid(&status),
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
    // Agents and keyrings answer on unix sockets. The sandbox removes
    // SSH_AUTH_SOCK, so the question is whether sockets can be opened at
    // all, and if they can, which agents listen where they usually do.
    let mut agents = Vec::new();
    match &signals.sockets {
        Sockets::Blocked => {
            withheld.push("unix sockets (agents, keyrings, git credential-cache)".into())
        }
        Sockets::Open => {
            for (label, path) in agent_sockets(ctx, signals) {
                if answers(&path) {
                    agents.push(label);
                }
            }
            if agents.is_empty() {
                f.warn(
                    format!(
                        "{}; an ssh or gpg agent, a keyring or git's credential-cache would answer from here, though none is listening where they usually do now",
                        open_sockets(signals)
                    ),
                    Some(sockets_fix(signals.platform).into()),
                );
            }
        }
        Sockets::Unknown(why) => f.warn(
            format!("can't tell whether unix sockets are blocked: {why}"),
            None,
        ),
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
    if reachable.is_empty() && agents.is_empty() {
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
        let mut what = Vec::new();
        let mut fix = Vec::new();
        if !reachable.is_empty() {
            what.push(format!(
                "readable inside the sandbox: {}",
                reachable.join(", ")
            ));
            fix.push("Run `mezha compile`, and withhold anything else in sandbox.credentials in your user settings.");
        }
        if !agents.is_empty() {
            what.push(format!(
                "answering inside the sandbox ({}): {}",
                open_sockets(signals),
                agents.join(", ")
            ));
            fix.push(sockets_fix(signals.platform));
        }
        f.fail(what.join("; "), fix.join(" "));
    }
    f.into_check(check, "")
}

/// Why unix sockets are open, as far as the signals say.
fn open_sockets(signals: &Signals) -> &'static str {
    match signals.platform {
        Platform::Linux | Platform::Wsl2 if !signals.seccomp_filter => {
            "unix sockets can be opened, and no seccomp filter is applied"
        }
        Platform::Linux | Platform::Wsl2 => {
            "unix sockets can be opened although a seccomp filter is applied: srt's isn't in force, or the settings allow unix sockets"
        }
        _ => {
            "unix sockets can be opened: the settings allow them (allowAllUnixSockets, or allowUnixSockets with a path above them all)"
        }
    }
}

fn sockets_fix(platform: Platform) -> &'static str {
    match platform {
        Platform::Linux | Platform::Wsl2 => {
            "Install srt's seccomp filter (`npm install -g @anthropic-ai/sandbox-runtime`; `/sandbox` in Claude Code lists it under Dependencies), remove allowAllUnixSockets and allowUnixSockets from your settings, and restart Claude Code."
        }
        _ => "Remove allowAllUnixSockets from your settings, and narrow allowUnixSockets.",
    }
}

/// Where agents and keyrings usually listen, since the sandbox removes
/// `SSH_AUTH_SOCK`: launchd's listeners on macOS, the user's runtime
/// directory on Linux, and git's credential-cache.
fn agent_sockets(ctx: &Ctx, signals: &Signals) -> Vec<(String, PathBuf)> {
    let mut list = Vec::new();
    if let Some(sock) = ctx.var("SSH_AUTH_SOCK") {
        list.push((
            "the ssh agent (SSH_AUTH_SOCK)".to_string(),
            PathBuf::from(sock),
        ));
    }
    if signals.platform == Platform::MacOs
        && let Ok(entries) = fs::read_dir("/private/tmp")
    {
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with("com.apple.launchd.")
            {
                let path = entry.path().join("Listeners");
                list.push((format!("the ssh agent at {}", path.display()), path));
            }
        }
    }
    let runtime = ctx.var("XDG_RUNTIME_DIR").map(PathBuf::from).or_else(|| {
        signals
            .uid
            .map(|uid| PathBuf::from(format!("/run/user/{uid}")))
    });
    if let Some(dir) = runtime {
        for (what, rel) in [
            ("the ssh agent", "keyring/ssh"),
            ("the ssh agent", "gcr/ssh"),
            ("the gpg agent", "gnupg/S.gpg-agent"),
            ("the session bus, where keyrings answer", "bus"),
        ] {
            let path = dir.join(rel);
            list.push((format!("{what} at {}", path.display()), path));
        }
    }
    if let Some(path) = ctx.expand("~/.cache/git/credential/socket") {
        list.push((format!("git credential-cache at {}", path.display()), path));
    }
    list
}

/// Something accepts a connection on this unix socket.
#[cfg(unix)]
fn answers(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

#[cfg(not(unix))]
fn answers(_: &Path) -> bool {
    false
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
        assert!(seccomp_filter(
            "NoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n"
        ));
        assert!(!seccomp_filter("Seccomp:\t0\n"));
        assert!(!seccomp_filter(""));
        assert_eq!(
            uid("Name:\tbash\nUid:\t1000\t1000\t1000\t1000\n"),
            Some(1000)
        );
        assert_eq!(uid(""), None);
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
            sockets: Sockets::Blocked,
            seccomp_filter: true,
            uid: Some(1000),
        }
    }

    #[test]
    fn unix_sockets() {
        assert_eq!(
            classify_linux(ErrorKind::PermissionDenied),
            Sockets::Blocked
        );
        assert_eq!(classify_linux(ErrorKind::NotFound), Sockets::Open);
        assert_eq!(classify_linux(ErrorKind::ConnectionRefused), Sockets::Open);
        assert!(matches!(
            classify_linux(ErrorKind::Other),
            Sockets::Unknown(_)
        ));
        // macOS: the profile answers only for sockets that exist. Seen
        // under Claude Code's own sandbox: ENOENT for a missing path,
        // EPERM for the system sockets.
        let denied = Err(ErrorKind::PermissionDenied);
        let missing = Err(ErrorKind::NotFound);
        assert_eq!(classify_macos(&[denied, denied]), Sockets::Blocked);
        assert_eq!(classify_macos(&[Ok(()), denied]), Sockets::Blocked);
        assert_eq!(classify_macos(&[missing, denied]), Sockets::Blocked);
        assert_eq!(classify_macos(&[Ok(()), missing]), Sockets::Open);
        // A stream connect let through to syslog's datagram socket.
        assert_eq!(
            classify_macos(&[Ok(()), Err(ErrorKind::Other)]),
            Sockets::Open
        );
        assert!(matches!(
            classify_macos(&[missing, missing]),
            Sockets::Unknown(_)
        ));
        assert!(matches!(classify_macos(&[]), Sockets::Unknown(_)));
        let mut s = signals(Platform::Linux, Direct::NoRoute, Policy::Applied);
        s.seccomp_filter = false;
        assert!(open_sockets(&s).contains("no seccomp filter"));
        s.seccomp_filter = true;
        assert!(open_sockets(&s).contains("srt's isn't in force"));
        assert!(
            open_sockets(&signals(Platform::MacOs, Direct::Refused, Policy::Applied))
                .contains("allowAllUnixSockets")
        );
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

    fn ctx(root: &Path, home: Option<&Path>, platform: Platform, vars: &[(&str, &str)]) -> Ctx {
        Ctx {
            root: root.to_path_buf(),
            vars: vars
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            home: home.map(Path::to_path_buf),
            platform,
            managed_dir: None,
            mezha_exe: None,
            agent_writable: Vec::new(),
        }
    }

    #[test]
    fn the_policy_probe_reads_mezha_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        assert_eq!(
            policy(root),
            Policy::Unknown("mezha.toml can't be read".into())
        );
        let spec = root.join(SPEC_FILE);
        fs::write(&spec, "[project]\nname = \"x\"\n").unwrap();
        assert_eq!(policy(root), Policy::NotApplied);
        let mut perms = fs::metadata(&spec).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&spec, perms).unwrap();
        assert_eq!(
            policy(root),
            Policy::Unknown("mezha.toml is read-only, so a refused write shows nothing".into())
        );
        // A directory can be looked at but not opened for appending.
        fs::remove_file(&spec).unwrap();
        fs::create_dir(&spec).unwrap();
        let odd = policy(root);
        let Policy::Unknown(why) = &odd else {
            panic!("{odd:?}");
        };
        assert!(
            why.starts_with("opening mezha.toml for writing failed oddly ("),
            "{why}"
        );
    }

    #[test]
    fn socket_probes_by_platform() {
        let other = probe_sockets(Platform::Other);
        assert_eq!(
            other,
            Sockets::Unknown("no sandbox on this platform".into())
        );
        // Linux asks about a socket that isn't there: a connect gets as
        // far as the missing path unless the sandbox refuses it first.
        let linux = probe_sockets(Platform::Linux);
        assert!(
            matches!(linux, Sockets::Open | Sockets::Blocked),
            "{linux:?}"
        );
        let mac = probe_sockets(Platform::MacOs);
        if cfg!(target_os = "macos") {
            assert!(matches!(mac, Sockets::Open | Sockets::Blocked), "{mac:?}");
        } else {
            assert!(matches!(mac, Sockets::Unknown(_)), "{mac:?}");
        }
    }

    #[test]
    fn the_proxy_fingerprint_without_a_proxy_to_ask() {
        let root = Path::new("/w/repo");
        let c = |vars: &[(&str, &str)]| ctx(root, None, Platform::Linux, vars);
        assert_eq!(fingerprint(&c(&[])), Proxy::Missing);
        assert_eq!(
            fingerprint(&c(&[("HTTPS_PROXY", "http://")])),
            Proxy::Missing
        );
        // Nothing listens on port 1, on either loopback address.
        assert_eq!(
            fingerprint(&c(&[("HTTPS_PROXY", "http://srt:tok@localhost:1")])),
            Proxy::Unreachable
        );
        assert_eq!(
            fingerprint(&c(&[("https_proxy", "http://127.0.0.1:1")])),
            Proxy::Unreachable
        );
    }

    #[test]
    fn the_sandbox_verdict_on_other_platforms_and_odd_signals() {
        for platform in [Platform::Windows, Platform::Wsl1, Platform::Other] {
            let s = signals(platform, Direct::Refused, Policy::NotApplied);
            assert!(!s.sandboxed(), "{platform:?}");
            let c = sandbox_check(&s);
            assert_eq!(c.status, Status::Fail, "{platform:?}: {}", c.detail);
            assert!(
                c.detail.contains("ran outside the sandbox"),
                "{platform:?}: {}",
                c.detail
            );
        }
        let mut s = signals(Platform::MacOs, Direct::Refused, Policy::Applied);
        s.env_says_sandboxed = true;
        let c = sandbox_check(&s);
        assert_eq!(c.status, Status::Pass, "{}", c.detail);
        assert!(
            c.detail.ends_with("(SANDBOX_RUNTIME is set)"),
            "{}",
            c.detail
        );
        let s = signals(
            Platform::MacOs,
            Direct::Refused,
            Policy::Unknown("mezha.toml can't be read".into()),
        );
        let c = sandbox_check(&s);
        assert_eq!(c.status, Status::Warn, "{}", c.detail);
        assert_eq!(
            c.detail,
            "can't tell whether the sandbox is in force: mezha.toml can't be read"
        );
        assert!(matches!(
            classify_write(ErrorKind::Other),
            Policy::Unknown(why) if why.contains("failed oddly")
        ));
    }

    #[test]
    fn looks_tell_devices_and_directories_apart() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(look(Path::new("/dev/null")), Look::CharDevice);
        assert_eq!(look(tmp.path()), Look::Dir);
        assert_eq!(
            look(&tmp.path().join("missing")),
            Look::Error(ErrorKind::NotFound)
        );
        let full = tmp.path().join("full");
        fs::write(&full, "x").unwrap();
        assert_eq!(look(&full), Look::File(Ok(1)));
        let empty = tmp.path().join("empty");
        fs::write(&empty, "").unwrap();
        assert_eq!(look(&empty), Look::File(Ok(0)));
    }

    /// A withheld file shows as unreadable, as a device bound over it, or
    /// as a directory that can't be listed; a directory where a file was
    /// expected is simply absent.
    #[cfg(unix)]
    #[test]
    fn credentials_withheld_in_different_ways() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let ssh = home.join(".ssh");
        fs::create_dir_all(&ssh).unwrap();
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o000)).unwrap();
        std::os::unix::fs::symlink("/dev/null", home.join(".netrc")).unwrap();
        fs::create_dir_all(home.join(".config/hub")).unwrap();
        let locked = home.join(".git-credentials");
        fs::write(&locked, "https://x:t@h\n").unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let c = ctx(tmp.path(), Some(&home), Platform::Linux, &[]);

        let s = signals(Platform::Linux, Direct::NoRoute, Policy::Applied);
        let check = credentials_check(&c, None, &s);
        assert_eq!(check.status, Status::Pass, "{}", check.detail);
        assert_eq!(
            check.detail,
            "nothing readable; withheld: ~/.ssh, ~/.git-credentials, ~/.netrc, /dev/null, unix sockets (agents, keyrings, git credential-cache)"
        );

        let mut s = s;
        s.sockets = Sockets::Unknown("the probe went oddly".into());
        let check = credentials_check(&c, None, &s);
        assert_eq!(check.status, Status::Warn, "{}", check.detail);
        assert!(
            check
                .detail
                .starts_with("can't tell whether unix sockets are blocked: the probe went oddly; "),
            "{}",
            check.detail
        );
        fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn agent_sockets_follow_the_environment() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let c = ctx(
            tmp.path(),
            Some(&home),
            Platform::Linux,
            &[("SSH_AUTH_SOCK", "/nonexistent/agent.sock")],
        );
        let mut s = signals(Platform::Linux, Direct::NoRoute, Policy::Applied);
        s.uid = Some(4_242_424);
        let labels: Vec<String> = agent_sockets(&c, &s).into_iter().map(|(l, _)| l).collect();
        assert_eq!(
            labels,
            [
                "the ssh agent (SSH_AUTH_SOCK)",
                "the ssh agent at /run/user/4242424/keyring/ssh",
                "the ssh agent at /run/user/4242424/gcr/ssh",
                "the gpg agent at /run/user/4242424/gnupg/S.gpg-agent",
                "the session bus, where keyrings answer at /run/user/4242424/bus",
                &format!(
                    "git credential-cache at {}",
                    home.join(".cache/git/credential/socket").display()
                ),
            ]
        );
        // Without a runtime directory or a known uid, only the rest.
        s.uid = None;
        let no_home = ctx(tmp.path(), None, Platform::Linux, &[]);
        assert!(agent_sockets(&no_home, &s).is_empty());
        // On macOS, launchd's listeners under /private/tmp are tried too.
        let mac = ctx(tmp.path(), None, Platform::MacOs, &[]);
        let s = signals(Platform::MacOs, Direct::Refused, Policy::Applied);
        let launchd: Vec<(String, PathBuf)> = agent_sockets(&mac, &s)
            .into_iter()
            .filter(|(_, p)| !p.starts_with("/run/user"))
            .collect();
        for (label, path) in &launchd {
            assert!(
                path.starts_with("/private/tmp/com.apple.launchd.") && path.ends_with("Listeners"),
                "{label}: {}",
                path.display()
            );
        }
    }

    /// With unix sockets open on macOS the fix names the settings, not
    /// srt's seccomp filter. Whether a real launchd ssh agent answers on
    /// this machine decides between a warning and a failure.
    #[test]
    fn open_sockets_on_macos_name_the_settings_fix() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let c = ctx(tmp.path(), Some(&home), Platform::MacOs, &[]);
        let mut s = signals(Platform::MacOs, Direct::Refused, Policy::Applied);
        s.sockets = Sockets::Open;
        let check = credentials_check(&c, None, &s);
        assert!(
            matches!(check.status, Status::Warn | Status::Fail),
            "{}",
            check.detail
        );
        assert!(
            check
                .detail
                .contains("unix sockets can be opened: the settings allow them"),
            "{}",
            check.detail
        );
        assert_eq!(
            check.fix.as_deref(),
            Some("Remove allowAllUnixSockets from your settings, and narrow allowUnixSockets."),
            "{}",
            check.detail
        );
    }

    #[test]
    fn the_network_check_without_srt_in_front() {
        let root = Path::new("/w/repo");
        let layers = Layers::default();
        let s = signals(Platform::Linux, Direct::NoRoute, Policy::Applied);
        let c = ctx(root, None, Platform::Linux, &[]);
        let check = network_check(&c, &layers, None, &s);
        assert_eq!(check.status, Status::Warn, "{}", check.detail);
        assert_eq!(
            check.detail,
            "direct connections are refused; no HTTPS_PROXY here, so the sandbox's proxy wasn't found"
        );
        assert_eq!(check.evidence, [report::INSIDE]);

        let c = ctx(
            root,
            None,
            Platform::Linux,
            &[("HTTPS_PROXY", "http://srt:tok@localhost:1")],
        );
        let check = network_check(&c, &layers, None, &s);
        assert_eq!(
            check.detail,
            "direct connections are refused; the proxy in HTTPS_PROXY doesn't answer"
        );

        let not_applied = signals(Platform::Linux, Direct::NoRoute, Policy::NotApplied);
        let check = network_check(&c, &layers, None, &not_applied);
        assert_eq!(check.status, Status::Warn, "{}", check.detail);
        assert!(
            check.detail.ends_with(
                "; this project's settings aren't in force, so forge hosts weren't contacted"
            ),
            "{}",
            check.detail
        );

        let outside = signals(Platform::Linux, Direct::Left, Policy::NotApplied);
        let check = network_check(&c, &layers, None, &outside);
        assert_eq!(check.status, Status::Skip);
        assert_eq!(check.detail, "the command ran outside the sandbox");
    }

    #[test]
    fn the_notes_mention_the_keychain_on_macos() {
        let tmp = tempfile::tempdir().unwrap();
        let mac = ctx(tmp.path(), None, Platform::MacOs, &[]);
        let (checks, notes) = checks(&mac, &Layers::default(), None);
        let ids: Vec<&str> = checks.iter().map(|c| c.id).collect();
        assert_eq!(
            ids,
            ["inside-sandbox", "inside-network", "inside-credentials"]
        );
        assert_eq!(notes.len(), 2, "{notes:?}");
        assert!(notes[1].contains("macOS keychain"), "{}", notes[1]);
        let linux = ctx(tmp.path(), None, Platform::Linux, &[]);
        let (_, notes) = self::checks(&linux, &Layers::default(), None);
        assert_eq!(notes.len(), 1, "{notes:?}");
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
