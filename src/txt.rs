//! TXT values. The API returns TXT content in zone-file form: one or more quoted strings with `\"`, `\\` and `\DDD`
//! escapes (bare text is accepted too). Export re-emits them as quoted strings of at most 255 bytes; verify compares
//! the concatenated bytes, so a value split differently by another server still matches.

/// The character-strings of a TXT value, unescaped.
pub fn parse(content: &str) -> Vec<Vec<u8>> {
    let text = content.trim();
    if !text.starts_with('"') {
        return vec![text.as_bytes().to_vec()];
    }
    let bytes = text.as_bytes();
    let mut parts = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        if bytes[i] != b'"' {
            // Text outside quotes after a quoted string: keep it verbatim rather than dropping it.
            parts.push(bytes[i..].to_vec());
            break;
        }
        i += 1;
        let mut current = Vec::new();
        let mut closed = false;
        while i < bytes.len() {
            match bytes[i] {
                b'\\' if i + 1 < bytes.len() => {
                    let digits = &bytes[i + 1..bytes.len().min(i + 4)];
                    if digits.len() == 3 && digits.iter().all(u8::is_ascii_digit) {
                        let value = digits
                            .iter()
                            .fold(0u32, |n, d| n * 10 + u32::from(d - b'0'));
                        if let Ok(byte) = u8::try_from(value) {
                            current.push(byte);
                            i += 4;
                            continue;
                        }
                    }
                    current.push(bytes[i + 1]);
                    i += 2;
                }
                b'"' => {
                    i += 1;
                    closed = true;
                    break;
                }
                byte => {
                    current.push(byte);
                    i += 1;
                }
            }
        }
        parts.push(current);
        if !closed {
            break;
        }
    }
    if parts.is_empty() {
        parts.push(Vec::new());
    }
    parts
}

/// The value as one byte string (what resolvers compare).
pub fn joined(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

/// Zone-file form: every part as quoted strings of at most 255 bytes (existing boundaries kept), space-separated.
pub fn emit(parts: &[Vec<u8>]) -> String {
    let mut strings = Vec::new();
    for part in parts {
        if part.is_empty() {
            strings.push(quote(&[]));
        } else {
            strings.extend(part.chunks(255).map(quote));
        }
    }
    strings.join(" ")
}

/// One quoted string: `\"`, `\\`, printable ASCII as is, every other byte as `\DDD`.
pub fn quote(bytes: &[u8]) -> String {
    format!("\"{}\"", escape(bytes))
}

/// The escaped form without quotes; injective, so it doubles as a comparison key.
pub fn escape(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from(b)),
            _ => out.push_str(&format!("\\{b:03}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quoted_and_bare_values() {
        assert_eq!(
            parse(r#""v=spf1 include:_spf.example.com ~all""#),
            vec![b"v=spf1 include:_spf.example.com ~all".to_vec()]
        );
        assert_eq!(parse("v=spf1 -all"), vec![b"v=spf1 -all".to_vec()]);
        assert_eq!(
            parse(r#""part one" "part two""#),
            vec![b"part one".to_vec(), b"part two".to_vec()]
        );
        assert_eq!(
            parse(r#""say \"hi\" \\ there""#),
            vec![br#"say "hi" \ there"#.to_vec()]
        );
        assert_eq!(
            parse(r#""caf\195\169""#),
            vec![vec![b'c', b'a', b'f', 195, 169]]
        );
        assert_eq!(parse(r#""""#), vec![Vec::<u8>::new()]);
    }

    #[test]
    fn emits_escaped_strings_of_at_most_255_bytes() {
        assert_eq!(emit(&[br#"a "b" \c"#.to_vec()]), r#""a \"b\" \\c""#);
        assert_eq!(emit(&["café".as_bytes().to_vec()]), r#""caf\195\169""#);
        let long = vec![b'x'; 300];
        let out = emit(std::slice::from_ref(&long));
        assert_eq!(
            out,
            format!("\"{}\" \"{}\"", "x".repeat(255), "x".repeat(45))
        );
        assert_eq!(joined(&parse(&out)), long);
    }

    #[test]
    fn round_trips_through_parse_and_emit() {
        for value in [
            r#""v=DMARC1; p=none""#,
            r#""a" "b""#,
            r#""q\"uote""#,
            r#""tab\009x""#,
        ] {
            let parts = parse(value);
            assert_eq!(parse(&emit(&parts)), parts, "{value}");
        }
    }
}
