pub const COIN: i64 = 100_000_000;
pub const CENT: i64 = 1_000_000;

/// Format satoshi amounts into a human readable string with two decimal places
/// and comma separators. Negative amounts are supported. If `plus` is true,
/// positive values are prefixed with `+`.
pub fn format_money(mut n: i64, plus: bool) -> String {
    let negative = n < 0;
    if negative {
        n = -n;
    }
    n /= CENT;
    let mut s = format!("{}.{:02}", n / 100, n % 100);
    let mut i = 6usize;
    while i < s.len() {
        if s.as_bytes()[s.len() - i - 1].is_ascii_digit() {
            s.insert(s.len() - i, ',');
        }
        i += 4;
    }
    if negative {
        s.insert(0, '-');
    } else if plus && n > 0 {
        s.insert(0, '+');
    }
    s
}

/// Parse a decimal string into a satoshi amount. Commas are ignored and up to
/// two fractional digits are supported. Returns `None` on parse failure or
/// overflow.
pub fn parse_money(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let mut chars = s.chars().peekable();
    let mut negative = false;
    if let Some(&c) = chars.peek() {
        if c == '+' || c == '-' {
            negative = c == '-';
            chars.next();
        }
    }
    let mut whole = String::new();
    while let Some(&c) = chars.peek() {
        if c == ',' {
            chars.next();
            continue;
        }
        if c == '.' || c.is_whitespace() {
            break;
        }
        if !c.is_ascii_digit() {
            return None;
        }
        whole.push(c);
        chars.next();
    }
    let mut cents: i64 = 0;
    if let Some('.') = chars.peek() {
        chars.next();
        if let Some(c1) = chars.next() {
            if !c1.is_ascii_digit() {
                return None;
            }
            cents = 10 * (c1.to_digit(10).unwrap() as i64);
            if let Some(&c2) = chars.peek() {
                if c2.is_ascii_digit() {
                    cents += c2.to_digit(10).unwrap() as i64;
                    chars.next();
                }
            }
        }
    }
    while let Some(&c) = chars.peek() {
        if !c.is_whitespace() {
            return None;
        }
        chars.next();
    }
    if whole.len() > 14 {
        return None;
    }
    let n_whole: i64 = whole.parse().ok()?;
    let pre = n_whole.checked_mul(100)?.checked_add(cents)?;
    let value = pre.checked_mul(CENT)?;
    if value / CENT != pre {
        return None;
    }
    if value / COIN != n_whole {
        return None;
    }
    if negative {
        Some(-value)
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_money_simple() {
        assert_eq!(format_money(COIN, false), "1.00");
        assert_eq!(format_money(-COIN, false), "-1.00");
    }

    #[test]
    fn test_format_money_commas() {
        assert_eq!(format_money(123_456_789 * COIN, false), "123,456,789.00");
    }

    #[test]
    fn test_format_money_sub_cent_negative() {
        assert_eq!(format_money(-50, false), "-0.00");
    }

    #[test]
    fn test_parse_money() {
        assert_eq!(parse_money("1.00"), Some(COIN));
        assert_eq!(parse_money("+1.00"), Some(COIN));
        assert_eq!(parse_money("-1.00"), Some(-COIN));
        assert_eq!(parse_money("0.01"), Some(CENT));
        assert_eq!(parse_money("123,456,789.00"), Some(123_456_789 * COIN));
        assert_eq!(parse_money("bogus"), None);
    }

    #[test]
    fn test_parse_money_max_value() {
        assert_eq!(
            parse_money("92,233,720,368.54"),
            Some(9_223_372_036_854_000_000)
        );
    }

    #[test]
    fn test_parse_money_invalid_commas() {
        assert_eq!(parse_money("1,234.5,6"), None);
        assert_eq!(parse_money("1.2,3"), None);
    }

    #[test]
    fn test_parse_money_overflow() {
        assert_eq!(parse_money("92,233,720,368.55"), None);
        assert_eq!(parse_money("10,000,000,000,000.00"), None);
    }
}
