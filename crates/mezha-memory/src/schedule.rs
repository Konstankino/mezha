//! Snippets that run `mezha dream --scheduled` on a timer: a launchd agent
//! (macOS), a systemd user timer or a crontab line (Linux, WSL2). mezha
//! prints them; installing one is yours to do. The program runs directly,
//! without a shell in between, and every value is escaped for its format.

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Launchd,
    Systemd,
    Cron,
}

impl Kind {
    pub fn parse(text: &str) -> Option<Kind> {
        match text {
            "launchd" => Some(Kind::Launchd),
            "systemd" => Some(Kind::Systemd),
            "cron" => Some(Kind::Cron),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum When {
    /// Every day at this local time.
    Daily { hour: u8, minute: u8 },
    /// A five-field cron expression (the `cron` kind only).
    Cron(String),
}

pub struct Job<'a> {
    /// A short, stable id for the project (the start of its key).
    pub id: &'a str,
    pub exe: &'a Path,
    pub root: &'a Path,
    /// Environment for the run, such as PATH and CLAUDE_CONFIG_DIR.
    pub env: &'a [(String, String)],
    pub log: &'a Path,
    pub when: When,
}

/// A file to create (relative to your home) and its contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    pub path: String,
    pub contents: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snippet {
    pub files: Vec<File>,
    /// A crontab line, for the cron kind.
    pub line: Option<String>,
    /// Commands that install it, in order.
    pub install: Vec<String>,
    /// Commands that remove it again.
    pub remove: Vec<String>,
}

pub fn snippet(kind: Kind, job: &Job<'_>) -> Result<Snippet, String> {
    let text = |p: &Path| -> Result<String, String> {
        let t = p
            .to_str()
            .ok_or_else(|| format!("{} is not valid UTF-8", p.display()))?;
        plain(t)?;
        Ok(t.to_string())
    };
    let exe = text(job.exe)?;
    let root = text(job.root)?;
    let log = text(job.log)?;
    for (k, v) in job.env {
        plain(k)?;
        plain(v)?;
    }
    let args = [exe.as_str(), "-p", root.as_str(), "dream", "--scheduled"];
    match kind {
        Kind::Launchd => launchd(job, &args, &log),
        Kind::Systemd => systemd(job, &args, &root, &log),
        Kind::Cron => Ok(cron(job, &args, &log)),
    }
}

fn plain(text: &str) -> Result<(), String> {
    if text.contains(['\n', '\r', '\0']) {
        return Err(format!("`{}` contains a line break", text.escape_debug()));
    }
    Ok(())
}

fn daily(when: &When, kind: &str) -> Result<(u8, u8), String> {
    match when {
        When::Daily { hour, minute } => Ok((*hour, *minute)),
        When::Cron(_) => Err(format!(
            "{kind} takes dream_schedule = \"nightly\" (with dream_at); a cron expression needs `--schedule cron`"
        )),
    }
}

fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn launchd(job: &Job<'_>, args: &[&str], log: &str) -> Result<Snippet, String> {
    let (hour, minute) = daily(&job.when, "launchd")?;
    let label = format!("dev.mezha.dream.{}", job.id);
    let mut plist = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n",
    );
    plist.push_str(&format!(
        "  <key>Label</key>\n  <string>{}</string>\n  <key>ProgramArguments</key>\n  <array>\n",
        xml(&label)
    ));
    for arg in args {
        plist.push_str(&format!("    <string>{}</string>\n", xml(arg)));
    }
    plist.push_str("  </array>\n  <key>EnvironmentVariables</key>\n  <dict>\n");
    for (k, v) in job.env {
        plist.push_str(&format!(
            "    <key>{}</key>\n    <string>{}</string>\n",
            xml(k),
            xml(v)
        ));
    }
    plist.push_str(&format!(
        "  </dict>\n  <key>StartCalendarInterval</key>\n  <dict>\n    <key>Hour</key>\n    <integer>{hour}</integer>\n    <key>Minute</key>\n    <integer>{minute}</integer>\n  </dict>\n  <key>StandardOutPath</key>\n  <string>{log}</string>\n  <key>StandardErrorPath</key>\n  <string>{log}</string>\n</dict>\n</plist>\n",
        log = xml(log)
    ));
    let path = format!("Library/LaunchAgents/{label}.plist");
    Ok(Snippet {
        install: vec![format!(
            "launchctl bootout gui/$(id -u)/{label} 2>/dev/null; launchctl bootstrap gui/$(id -u) ~/{path}"
        )],
        remove: vec![format!(
            "launchctl bootout gui/$(id -u)/{label}; rm ~/{path}"
        )],
        files: vec![File {
            path,
            contents: plist,
        }],
        line: None,
    })
}

/// A value inside double quotes in a systemd unit.
fn unit_quote(text: &str) -> String {
    let escaped = text
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%")
        .replace('$', "$$");
    format!("\"{escaped}\"")
}

fn systemd(job: &Job<'_>, args: &[&str], root: &str, log: &str) -> Result<Snippet, String> {
    let (hour, minute) = daily(&job.when, "systemd")?;
    let name = format!("mezha-dream-{}", job.id);
    let mut service = format!(
        "[Unit]\nDescription=mezha dream for {}\n\n[Service]\nType=oneshot\n",
        root.replace('%', "%%")
    );
    for (k, v) in job.env {
        service.push_str(&format!(
            "Environment={}\n",
            unit_quote(&format!("{k}={v}"))
        ));
    }
    service.push_str(&format!(
        "ExecStart={}\nStandardOutput=append:{log}\nStandardError=append:{log}\n",
        args.iter()
            .map(|a| unit_quote(a))
            .collect::<Vec<_>>()
            .join(" "),
        log = log.replace('%', "%%")
    ));
    let timer = format!(
        "[Unit]\nDescription=Nightly mezha dream for {}\n\n[Timer]\nOnCalendar=*-*-* {hour:02}:{minute:02}:00\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n",
        root.replace('%', "%%")
    );
    let dir = ".config/systemd/user";
    Ok(Snippet {
        files: vec![
            File {
                path: format!("{dir}/{name}.service"),
                contents: service,
            },
            File {
                path: format!("{dir}/{name}.timer"),
                contents: timer,
            },
        ],
        line: None,
        install: vec![
            "systemctl --user daemon-reload".into(),
            format!("systemctl --user enable --now {name}.timer"),
        ],
        remove: vec![
            format!("systemctl --user disable --now {name}.timer"),
            format!("rm ~/{dir}/{name}.service ~/{dir}/{name}.timer"),
        ],
    })
}

/// A word for a crontab line: single quotes for the shell, and `%`
/// escaped, which cron would otherwise turn into a line break.
fn cron_word(text: &str) -> String {
    let quoted = if !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:,@+".contains(c))
    {
        text.to_string()
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    };
    quoted.replace('%', "\\%")
}

fn cron(job: &Job<'_>, args: &[&str], log: &str) -> Snippet {
    let when = match &job.when {
        When::Daily { hour, minute } => format!("{minute} {hour} * * *"),
        When::Cron(expr) => expr.split_whitespace().collect::<Vec<_>>().join(" "),
    };
    let mut line = format!("{when} env");
    for (k, v) in job.env {
        line.push(' ');
        line.push_str(&cron_word(&format!("{k}={v}")));
    }
    for arg in args {
        line.push(' ');
        line.push_str(&cron_word(arg));
    }
    line.push_str(&format!(" >> {} 2>&1", cron_word(log)));
    Snippet {
        files: Vec::new(),
        line: Some(line),
        install: vec!["crontab -e   # then add the line above".into()],
        remove: vec!["crontab -e   # then delete the line".into()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job<'a>(root: &'a Path, env: &'a [(String, String)], when: When) -> Job<'a> {
        Job {
            id: "abc123def456",
            exe: Path::new("/opt/homebrew/bin/mezha"),
            root,
            env,
            log: Path::new("/Users/me/.mezha/dreams/k/schedule.log"),
            when,
        }
    }

    fn env() -> Vec<(String, String)> {
        vec![("PATH".into(), "/opt/homebrew/bin:/usr/bin:/bin".into())]
    }

    #[test]
    fn launchd_plist() {
        let env = env();
        let s = snippet(
            Kind::Launchd,
            &job(
                Path::new("/Users/me/A & B <x>"),
                &env,
                When::Daily { hour: 3, minute: 5 },
            ),
        )
        .unwrap();
        let plist = &s.files[0].contents;
        assert_eq!(
            s.files[0].path,
            "Library/LaunchAgents/dev.mezha.dream.abc123def456.plist"
        );
        assert!(
            plist.contains("<string>/Users/me/A &amp; B &lt;x&gt;</string>"),
            "{plist}"
        );
        assert!(plist.contains("    <string>dream</string>\n    <string>--scheduled</string>\n"));
        assert!(plist.contains("<key>Hour</key>\n    <integer>3</integer>\n    <key>Minute</key>\n    <integer>5</integer>"));
        assert!(!plist.contains("/bin/sh"));
        assert!(s.install[0].contains("launchctl bootstrap gui/$(id -u)"));
    }

    #[test]
    fn systemd_units() {
        let env = env();
        let s = snippet(
            Kind::Systemd,
            &job(
                Path::new("/home/me/100% $HOME \"q\""),
                &env,
                When::Daily {
                    hour: 23,
                    minute: 0,
                },
            ),
        )
        .unwrap();
        let service = &s.files[0].contents;
        assert!(
            service.contains("ExecStart=\"/opt/homebrew/bin/mezha\" \"-p\" \"/home/me/100%% $$HOME \\\"q\\\"\" \"dream\" \"--scheduled\"\n"),
            "{service}"
        );
        assert!(service.contains("Environment=\"PATH=/opt/homebrew/bin:/usr/bin:/bin\"\n"));
        assert!(
            s.files[1]
                .contents
                .contains("OnCalendar=*-*-* 23:00:00\nPersistent=true")
        );
    }

    #[test]
    fn crontab_lines() {
        let env = env();
        let s = snippet(
            Kind::Cron,
            &job(
                Path::new("/home/me/it's 50%"),
                &env,
                When::Cron("15 2  * * 1-5".into()),
            ),
        )
        .unwrap();
        assert_eq!(
            s.line.unwrap(),
            "15 2 * * 1-5 env PATH=/opt/homebrew/bin:/usr/bin:/bin /opt/homebrew/bin/mezha -p '/home/me/it'\\''s 50\\%' dream --scheduled >> /Users/me/.mezha/dreams/k/schedule.log 2>&1"
        );
    }

    #[test]
    fn kinds_by_name() {
        assert_eq!(Kind::parse("launchd"), Some(Kind::Launchd));
        assert_eq!(Kind::parse("systemd"), Some(Kind::Systemd));
        assert_eq!(Kind::parse("cron"), Some(Kind::Cron));
        assert_eq!(Kind::parse("Cron"), None);
        assert_eq!(Kind::parse(""), None);
    }

    #[test]
    fn a_nightly_crontab_line() {
        let env = env();
        let s = snippet(
            Kind::Cron,
            &job(
                Path::new("/home/me/proj"),
                &env,
                When::Daily { hour: 3, minute: 7 },
            ),
        )
        .unwrap();
        let line = s.line.unwrap();
        assert!(
            line.starts_with("7 3 * * * env PATH=/opt/homebrew/bin:/usr/bin:/bin "),
            "{line}"
        );
        assert!(s.files.is_empty());
        assert_eq!(s.install, ["crontab -e   # then add the line above"]);
    }

    #[test]
    fn refusals() {
        let env = env();
        let cron = When::Cron("0 3 * * *".into());
        assert!(snippet(Kind::Launchd, &job(Path::new("/r"), &env, cron.clone())).is_err());
        assert!(snippet(Kind::Systemd, &job(Path::new("/r"), &env, cron)).is_err());
        let daily = When::Daily { hour: 3, minute: 0 };
        assert!(snippet(Kind::Cron, &job(Path::new("/a\nb"), &env, daily.clone())).is_err());
        let bad_env = vec![("PATH".to_string(), "/x\n/y".to_string())];
        assert!(snippet(Kind::Launchd, &job(Path::new("/r"), &bad_env, daily)).is_err());
    }
}
