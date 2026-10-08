//! What git's configuration says about pushing: remotes, credential
//! helpers, and credentials stored in the config itself. It is read with
//! `git config --list` only: verify never runs a helper or touches the
//! network, because the repository's config is agent-writable and would run
//! as the human.

use std::time::Duration;

use crate::ctx::Ctx;
use crate::runner::{Run, run};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub scope: String,
    pub origin: String,
    /// Lowercase section and variable; a subsection keeps its case.
    pub key: String,
    /// `None` for a bare boolean key.
    pub value: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct GitConfig {
    pub entries: Vec<Entry>,
}

#[derive(Debug, Clone)]
pub enum ReadError {
    NoGit,
    Failed(String),
}

/// Variables that would add config from the environment. verify wants what
/// the config files say, which is what an agent can always get back to.
const ENV_CONFIG: [&str; 5] = [
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_KEY_0",
    "GIT_CONFIG_VALUE_0",
    "GIT_DIR",
];

impl GitConfig {
    /// Reads every scope (`local_only` = only the repository's own file).
    pub fn read(ctx: &Ctx, local_only: bool) -> Result<GitConfig, ReadError> {
        let git = ctx.which("git").ok_or(ReadError::NoGit)?;
        let mut args = vec!["-c", "core.fsmonitor=false", "config", "-z", "--list"];
        if local_only {
            args.push("--local");
        }
        args.extend(["--show-scope", "--show-origin"]);
        let out = run(
            ctx,
            &Run {
                program: &git,
                args: &args,
                cwd: &ctx.root,
                env: &[("GIT_TERMINAL_PROMPT", "0")],
                remove: &ENV_CONFIG,
                stdin: b"",
                timeout: Duration::from_secs(10),
            },
        )
        .map_err(|e| ReadError::Failed(e.to_string()))?;
        if !out.success() {
            return Err(ReadError::Failed(out.stderr.trim().to_string()));
        }
        Ok(GitConfig::parse(&out.stdout))
    }

    /// Parses `git config -z --list --show-scope --show-origin`: records of
    /// `scope NUL origin NUL key [LF value] NUL`.
    pub fn parse(text: &str) -> GitConfig {
        let fields: Vec<&str> = text.split('\0').collect();
        let entries = fields
            .chunks(3)
            .filter(|c| c.len() == 3)
            .map(|c| {
                let (key, value) = match c[2].split_once('\n') {
                    Some((k, v)) => (k, Some(v.to_string())),
                    None => (c[2], None),
                };
                Entry {
                    scope: c[0].to_string(),
                    origin: c[1].to_string(),
                    key: key.to_string(),
                    value,
                }
            })
            .collect();
        GitConfig { entries }
    }

    fn values<'a>(
        &'a self,
        matches: impl Fn(&str) -> bool + 'a,
    ) -> impl Iterator<Item = &'a Entry> + 'a {
        self.entries.iter().filter(move |e| matches(&e.key))
    }

    /// The URLs pushes go to: each remote's `pushurl`, else its `url`,
    /// rewritten by `pushInsteadOf` / `insteadOf`.
    pub fn push_urls(&self) -> Vec<String> {
        let mut remotes: Vec<String> = Vec::new();
        for e in &self.entries {
            if let Some(name) =
                remote_name(&e.key, ".url").or_else(|| remote_name(&e.key, ".pushurl"))
                && !remotes.iter().any(|r| r == name)
            {
                remotes.push(name.to_string());
            }
        }
        let mut urls = Vec::new();
        for name in remotes {
            let pushurls: Vec<&str> = self
                .values(|k| k == format!("remote.{name}.pushurl"))
                .filter_map(|e| e.value.as_deref())
                .collect();
            if !pushurls.is_empty() {
                urls.extend(pushurls.iter().map(|u| u.to_string()));
                continue;
            }
            for url in self
                .values(|k| k == format!("remote.{name}.url"))
                .filter_map(|e| e.value.as_deref())
            {
                let rewritten = self
                    .rewrite(url, "pushinsteadof")
                    .or_else(|| self.rewrite(url, "insteadof"))
                    .unwrap_or_else(|| url.to_string());
                urls.push(rewritten);
            }
        }
        urls.sort();
        urls.dedup();
        urls
    }

    /// The longest `url.<base>.<kind>` prefix of `url`, replaced by `<base>`.
    fn rewrite(&self, url: &str, kind: &str) -> Option<String> {
        self.entries
            .iter()
            .filter_map(|e| {
                let base = e
                    .key
                    .strip_prefix("url.")?
                    .strip_suffix(&format!(".{kind}"))?;
                let prefix = e.value.as_deref()?;
                url.starts_with(prefix)
                    .then_some((prefix.len(), base, prefix))
            })
            .max_by_key(|(len, _, _)| *len)
            .map(|(_, base, prefix)| format!("{base}{}", &url[prefix.len()..]))
    }

    /// `url.<base>.insteadOf` targets, which may carry credentials too.
    pub fn rewrite_bases(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter_map(|e| {
                let rest = e.key.strip_prefix("url.")?;
                rest.strip_suffix(".insteadof")
                    .or_else(|| rest.strip_suffix(".pushinsteadof"))
                    .map(str::to_string)
            })
            .collect()
    }

    /// The credential helpers git would ask, in order, with empty values
    /// resetting the list as git does. URL scoping is ignored on purpose:
    /// a helper for any host counts.
    pub fn helpers(&self) -> Vec<String> {
        let mut helpers: Vec<String> = Vec::new();
        for e in &self.entries {
            if e.key == "credential.helper"
                || (e.key.starts_with("credential.") && e.key.ends_with(".helper"))
            {
                match e.value.as_deref() {
                    None | Some("") => helpers.clear(),
                    Some(h) => helpers.push(h.to_string()),
                }
            }
        }
        helpers
    }

    /// `http[.<url>].extraHeader` values left after resets.
    pub fn extra_headers(&self) -> usize {
        let mut count = 0;
        for e in &self.entries {
            if e.key == "http.extraheader"
                || (e.key.starts_with("http.") && e.key.ends_with(".extraheader"))
            {
                match e.value.as_deref() {
                    None | Some("") => count = 0,
                    Some(_) => count += 1,
                }
            }
        }
        count
    }

    /// The last value of a single-valued key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.key == key)
            .and_then(|e| e.value.as_deref())
    }
}

fn remote_name<'a>(key: &'a str, suffix: &str) -> Option<&'a str> {
    key.strip_prefix("remote.")?.strip_suffix(suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(entries: &[(&str, &str)]) -> GitConfig {
        let text: String = entries
            .iter()
            .map(|(k, v)| format!("local\0file:.git/config\0{k}\n{v}\0"))
            .collect();
        GitConfig::parse(&text)
    }

    #[test]
    fn parses_records_including_bare_keys() {
        let c = GitConfig::parse(
            "global\0file:/h/.gitconfig\0user.name\nMe\0local\0file:.git/config\0core.bare\0",
        );
        assert_eq!(c.entries.len(), 2);
        assert_eq!(c.entries[0].scope, "global");
        assert_eq!(c.entries[0].value.as_deref(), Some("Me"));
        assert_eq!(c.entries[1].value, None);
    }

    #[test]
    fn push_urls_follow_pushurl_and_rewrites() {
        let c = cfg(&[
            ("remote.origin.url", "gh:o/r"),
            ("url.https://github.com/.insteadof", "gh:"),
            ("remote.fork.url", "https://example.com/r"),
            ("remote.fork.pushurl", "git@github.com:me/r"),
            ("remote.mirror.url", "https://a.example/r"),
            (
                "url.ssh://push.example/.pushinsteadof",
                "https://a.example/",
            ),
        ]);
        assert_eq!(
            c.push_urls(),
            [
                "git@github.com:me/r",
                "https://github.com/o/r",
                "ssh://push.example/r"
            ]
        );
    }

    #[test]
    fn helpers_reset_like_git() {
        let c = cfg(&[
            ("credential.helper", "osxkeychain"),
            ("credential.https://github.com.helper", ""),
            (
                "credential.https://github.com.helper",
                "!gh auth git-credential",
            ),
        ]);
        assert_eq!(c.helpers(), ["!gh auth git-credential"]);
        assert_eq!(
            cfg(&[("credential.helper", "store"), ("credential.helper", "")]).helpers(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn extra_headers_count_after_resets() {
        assert_eq!(
            cfg(&[("http.extraheader", "AUTHORIZATION: x")]).extra_headers(),
            1
        );
        assert_eq!(
            cfg(&[
                ("http.https://github.com/.extraheader", "x"),
                ("http.extraheader", "")
            ])
            .extra_headers(),
            0
        );
    }
}
