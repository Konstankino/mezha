//! Times without a date crate: the ISO 8601 timestamps Claude Code writes,
//! and the `--since` forms `mezha dream` takes. Everything is Unix seconds,
//! UTC.

const DAY: i64 = 86_400;

/// Unix seconds of an ISO 8601 time: `2026-10-09T03:12:45.123Z`, with or
/// without fractions, `Z` or an offset (`+03:00`, `+0300`), a space instead
/// of the `T`, or a bare date (midnight UTC). No zone means UTC.
pub fn parse_iso(text: &str) -> Option<i64> {
    let text = text.trim();
    let (date, rest) = match text.find(['T', 't', ' ']) {
        Some(i) => (&text[..i], Some(&text[i + 1..])),
        None => (text, None),
    };
    let mut parts = date.split('-');
    let year: i64 = number(parts.next()?, 4)?;
    let month: i64 = number(parts.next()?, 2)?;
    let day: i64 = number(parts.next()?, 2)?;
    if parts.next().is_some() || !(1..=12).contains(&month) || day < 1 || day > days_in(year, month)
    {
        return None;
    }
    let mut secs = days_from_civil(year, month, day) * DAY;
    let Some(rest) = rest else {
        return Some(secs);
    };
    let (clock, offset) = split_zone(rest)?;
    let mut fields = clock.split(':');
    let hour: i64 = number(fields.next()?, 2)?;
    let minute: i64 = number(fields.next()?, 2)?;
    let second: i64 = match fields.next() {
        Some(s) => {
            let whole = s.split(['.', ',']).next()?;
            let frac = &s[whole.len()..];
            if !frac.is_empty() && !frac[1..].bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            number(whole, 2)?
        }
        None => 0,
    };
    if fields.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    secs += hour * 3600 + minute * 60 + second;
    Some(secs - offset)
}

/// `YYYY-MM-DDTHH:MM:SSZ`.
pub fn format_iso(secs: i64) -> String {
    let days = secs.div_euclid(DAY);
    let rem = secs.rem_euclid(DAY);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

/// `--since`: `7d`, `12h`, a date or an ISO time.
pub fn parse_since(text: &str, now: i64) -> Result<i64, String> {
    let text = text.trim();
    let relative = |suffix: char, unit: i64| -> Option<i64> {
        let n: i64 = text.strip_suffix(suffix)?.parse().ok()?;
        (n > 0 && n <= 3650 * DAY / unit).then(|| now - n * unit)
    };
    relative('d', DAY)
        .or_else(|| relative('h', 3600))
        .or_else(|| parse_iso(text))
        .ok_or_else(|| {
            format!("`{text}` is not a time: use 7d, 12h, 2026-10-01 or 2026-10-01T09:00:00Z")
        })
}

fn number(text: &str, width: usize) -> Option<i64> {
    (text.len() == width && text.bytes().all(|b| b.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

/// The clock part and the offset in seconds east of UTC.
fn split_zone(rest: &str) -> Option<(&str, i64)> {
    if let Some(clock) = rest.strip_suffix(['Z', 'z']) {
        return Some((clock, 0));
    }
    let Some(i) = rest.rfind(['+', '-']) else {
        return Some((rest, 0));
    };
    let (clock, zone) = (&rest[..i], &rest[i + 1..]);
    let sign = if rest[i..].starts_with('-') { -1 } else { 1 };
    let digits: String = zone.chars().filter(|c| *c != ':').collect();
    let (h, m) = match digits.len() {
        2 => (number(&digits, 2)?, 0),
        4 => (number(&digits[..2], 2)?, number(&digits[2..], 2)?),
        _ => return None,
    };
    if h > 23 || m > 59 {
        return None;
    }
    Some((clock, sign * (h * 3600 + m * 60)))
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Howard Hinnant's days-from-civil algorithm.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_times() {
        assert_eq!(parse_iso("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_iso("2027-01-15T08:00:00.000Z"), Some(1_800_000_000));
        assert_eq!(parse_iso("2027-01-15T11:00:00+03:00"), Some(1_800_000_000));
        assert_eq!(parse_iso("2027-01-15T03:00:00-0500"), Some(1_800_000_000));
        assert_eq!(parse_iso("2027-01-15 08:00"), Some(1_800_000_000));
        assert_eq!(parse_iso("2000-02-29"), Some(951_782_400));
        for bad in [
            "",
            "2026-13-01",
            "2026-02-30",
            "2026-1-01",
            "2026-01-01T25:00:00Z",
            "2026-01-01T10:00:00.x1Z",
            "2026-01-01T10:00:00+3",
            "yesterday",
        ] {
            assert_eq!(parse_iso(bad), None, "{bad}");
        }
    }

    #[test]
    fn zone_offsets_and_month_lengths() {
        assert_eq!(parse_iso("2027-01-15T11:00:00+03"), Some(1_800_000_000));
        assert_eq!(parse_iso("2027-01-15T05:00:00-03"), Some(1_800_000_000));
        for bad in [
            "2027-01-15T08:00:00+25:00",
            "2027-01-15T08:00:00+03:60",
            "2027-01-15T08:00:00+0x30",
            "2026-04-31",
            "2026-06-31",
            "2026-09-31",
            "2026-11-31",
        ] {
            assert_eq!(parse_iso(bad), None, "{bad}");
        }
        for (date, want) in [
            ("2026-04-30", "2026-04-30T00:00:00Z"),
            ("2026-06-30", "2026-06-30T00:00:00Z"),
            ("2026-12-31", "2026-12-31T00:00:00Z"),
            ("2100-02-28", "2100-02-28T00:00:00Z"),
        ] {
            assert_eq!(
                parse_iso(date).map(format_iso).as_deref(),
                Some(want),
                "{date}"
            );
        }
        assert_eq!(parse_iso("2100-02-29"), None);
    }

    #[test]
    fn round_trip() {
        for secs in [0, 951_782_400, 1_800_000_000, 4_102_444_799, -86_400] {
            assert_eq!(parse_iso(&format_iso(secs)), Some(secs), "{secs}");
        }
        assert_eq!(format_iso(1_800_000_000), "2027-01-15T08:00:00Z");
    }

    #[test]
    fn since() {
        let now = 1_800_000_000;
        assert_eq!(parse_since("7d", now), Ok(now - 7 * DAY));
        assert_eq!(parse_since("12h", now), Ok(now - 12 * 3600));
        assert_eq!(parse_since("2027-01-15", now), Ok(1_799_971_200));
        assert!(parse_since("0d", now).is_err());
        assert!(parse_since("-1d", now).is_err());
        assert!(parse_since("soon", now).is_err());
    }
}
