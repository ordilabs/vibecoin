pub const COIN: i64 = 100_000_000;
pub const CENT: i64 = 1_000_000;

/// Format a monetary amount in satoshis to a string with two decimal places
/// and comma separators.
///
/// Inspired by the implementation in `bitcoin-cpp`.
pub fn format_money(mut n: i64, plus: bool) -> String {
    n /= CENT;
    let sign = if n < 0 {
        "-"
    } else if plus && n > 0 {
        "+"
    } else {
        ""
    };
    let mut abs_n = if n >= 0 { n } else { -n };
    let frac = abs_n % 100;
    abs_n /= 100;
    let mut digits: Vec<char> = abs_n.to_string().chars().rev().collect();
    let mut grouped = String::new();
    for (i, ch) in digits.iter().enumerate() {
        if i > 0 && i % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(*ch);
    }
    let int_str: String = grouped.chars().rev().collect();
    format!("{}{}.{}", sign, int_str, format!("{:02}", frac))
}

/// Parse a string with optional commas and two decimal places into satoshis.
/// Returns `None` on parse failure.
pub fn parse_money(s: &str) -> Option<i64> {
    let trimmed = s.trim();
    if trimmed.is_empty() { return None; }
    if trimmed.starts_with('-') || trimmed.starts_with('+') { return None; }
    let mut parts = trimmed.split('.');
    let whole_part = parts.next().unwrap();
    let frac_part = parts.next();
    if parts.next().is_some() { return None; }
    let whole_clean: String = whole_part.chars().filter(|&c| c != ',').collect();
    if whole_clean.len() > 14 { return None; }
    if !whole_clean.chars().all(|c| c.is_ascii_digit()) { return None; }
    let mut cents: i64 = 0;
    if let Some(frac) = frac_part {
        if frac.len() > 2 || !frac.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        cents = frac.chars().fold(0i64, |acc, c| acc * 10 + c.to_digit(10).unwrap() as i64);
        if frac.len() == 1 { cents *= 10; }
    }
    if cents < 0 || cents > 99 { return None; }
    let whole: i64 = whole_clean.parse().ok()?;
    let pre_value = whole.checked_mul(100)?.checked_add(cents)?;
    let value = pre_value.checked_mul(CENT)?;
    if value / CENT != pre_value { return None; }
    if value / COIN != whole { return None; }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_basic_values() {
        assert_eq!(format_money(COIN, false), "1.00");
        assert_eq!(format_money(12 * COIN + 34 * CENT, false), "12.34");
        assert_eq!(format_money(123_456_789 * COIN, false), "123,456,789.00");
    }

    #[test]
    fn parse_basic_values() {
        assert_eq!(parse_money("1.00"), Some(COIN));
        assert_eq!(parse_money("12.34"), Some(12 * COIN + 34 * CENT));
        assert_eq!(parse_money("123,456,789.00"), Some(123_456_789 * COIN));
    }

    #[test]
    fn parse_invalid() {
        assert_eq!(parse_money("-1"), None);
        assert_eq!(parse_money("1.234"), None);
    }
}

