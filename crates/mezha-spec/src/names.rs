//! Names of agents, skills and rules become file names and `@mentions`, so
//! one grammar covers all three: lowercase ASCII letters, digits and hyphens.
//! Lowercase-only also makes case-insensitive uniqueness automatic, since TOML
//! already rejects duplicate keys.

const MAX_LEN: usize = 64;

/// Device names Windows refuses as file names, whatever the extension.
const WINDOWS_RESERVED: [&str; 22] = [
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Checks `^[a-z][a-z0-9-]{0,63}$` and the Windows device names.
pub fn check_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let starts_with_letter = chars.next().is_some_and(|c| c.is_ascii_lowercase());
    let rest_ok = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !starts_with_letter || !rest_ok || name.len() > MAX_LEN {
        return Err(format!(
            "`{name}` is not a valid name: use 1-{MAX_LEN} lowercase letters, digits and hyphens, \
             starting with a letter (it becomes a file name and an @mention)"
        ));
    }
    if WINDOWS_RESERVED.contains(&name) {
        return Err(format!(
            "`{name}` is a reserved device name on Windows and can't be a file name"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::check_name;

    #[test]
    fn accepts_plain_names() {
        for ok in ["implementer", "rust-conventions", "a", "db-migrations-2"] {
            assert!(check_name(ok).is_ok(), "{ok}");
        }
        assert!(check_name(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn rejects_unsafe_names() {
        for bad in [
            "",
            "Implementer",
            "2fast",
            "-x",
            "a_b",
            "a.b",
            "a/b",
            "a b",
            "con",
            "lpt1",
        ] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
        assert!(check_name(&"a".repeat(65)).is_err());
    }
}
