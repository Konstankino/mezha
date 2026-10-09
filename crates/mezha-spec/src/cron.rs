//! The schedule fields of `[memory]`: a time of day for `nightly`, and a
//! five-field cron expression for `cron`.

/// `HH:MM`, 24-hour.
pub fn parse_time(text: &str) -> Result<(u8, u8), String> {
    let bad = || {
        format!(
            "`{}` is not a time of day: use HH:MM, such as 03:00",
            text.escape_debug()
        )
    };
    let (h, m) = text.trim().split_once(':').ok_or_else(bad)?;
    if h.len() != 2 || m.len() != 2 {
        return Err(bad());
    }
    let hour: u8 = h.parse().map_err(|_| bad())?;
    let minute: u8 = m.parse().map_err(|_| bad())?;
    if hour > 23 || minute > 59 {
        return Err(bad());
    }
    Ok((hour, minute))
}

/// Checks a five-field cron expression (minute, hour, day of month, month,
/// day of week): numbers, `*`, ranges `a-b`, steps `/n` and lists. Names
/// such as `mon` and macros such as `@daily` aren't accepted.
pub fn check_cron(text: &str) -> Result<(), String> {
    const FIELDS: [(&str, u32, u32); 5] = [
        ("minute", 0, 59),
        ("hour", 0, 23),
        ("day of month", 1, 31),
        ("month", 1, 12),
        ("day of week", 0, 7),
    ];
    let fields: Vec<&str> = text.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(format!(
            "`{}` has {} fields; cron takes five: minute hour day-of-month month day-of-week",
            text.escape_debug(),
            fields.len()
        ));
    }
    for (field, (what, lo, hi)) in fields.iter().zip(FIELDS) {
        for part in field.split(',') {
            let (range, step) = match part.split_once('/') {
                Some((r, s)) => (r, Some(s)),
                None => (part, None),
            };
            if let Some(step) = step
                && !step.parse::<u32>().is_ok_and(|n| n > 0 && n <= hi)
            {
                return Err(format!("the {what} field `{field}` has a bad step"));
            }
            let in_range = |n: &str| n.parse::<u32>().is_ok_and(|n| (lo..=hi).contains(&n));
            let ok = match range.split_once('-') {
                _ if range == "*" => true,
                Some((a, b)) => {
                    in_range(a) && in_range(b) && a.parse::<u32>().ok() <= b.parse::<u32>().ok()
                }
                None => in_range(range),
            };
            if !ok {
                return Err(format!(
                    "the {what} field `{field}` isn't a number from {lo} to {hi}, `*`, a range or a list"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        assert_eq!(parse_time("03:00"), Ok((3, 0)));
        assert_eq!(parse_time("23:59"), Ok((23, 59)));
        for bad in ["3:00", "24:00", "03:60", "0300", "", "aa:bb"] {
            assert!(parse_time(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn cron_expressions() {
        for ok in [
            "0 3 * * *",
            "15 2 * * 1-5",
            "*/15 * * * *",
            "0 0,12 1 1-6/2 0,6",
        ] {
            assert_eq!(check_cron(ok), Ok(()), "{ok}");
        }
        for bad in [
            "@daily",
            "0 3 * *",
            "60 3 * * *",
            "0 3 * * mon",
            "0 3 0 * *",
            "5-1 * * * *",
            "*/0 * * * *",
            "0 3 * * * *",
        ] {
            assert!(check_cron(bad).is_err(), "{bad}");
        }
    }
}
