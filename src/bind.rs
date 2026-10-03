//! BIND zone-file export. Relative owner names with `@` for the apex, an explicit TTL on every line, trailing dots on
//! target names, TXT re-emitted from IONOS's quoted form. Apex NS and SOA, and disabled records, become comments: the
//! new provider sets its own NS and SOA, and a disabled record does not resolve today. `cloudflare` marks A, AAAA and
//! CNAME as not proxied for Cloudflare's import and comments out `_domainconnect`, a name Cloudflare reserves.
use crate::model::{Record, norm_name};
use crate::txt;

pub const DEFAULT_TTL: u32 = 3600;

pub struct Options {
    pub cloudflare: bool,
}

pub fn render(zone: &str, records: &[Record], options: &Options) -> String {
    let zone = norm_name(zone);
    let mut lines = vec![
        format!(
            "; {zone}: exported by ionos-dns-api-cli {} from the IONOS hosting DNS API",
            env!("CARGO_PKG_VERSION")
        ),
        format!("$ORIGIN {zone}."),
        format!("$TTL {DEFAULT_TTL}"),
    ];
    let mut sorted: Vec<&Record> = records.iter().collect();
    sorted.sort_by_key(|r| {
        (
            owner(&zone, &r.name) != "@",
            owner(&zone, &r.name),
            type_rank(&r.kind),
            r.content.clone(),
        )
    });
    for record in sorted {
        lines.push(line(&zone, record, options));
    }
    lines.push(String::new());
    lines.join("\n")
}

fn type_rank(kind: &str) -> usize {
    const ORDER: [&str; 9] = ["SOA", "NS", "A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA"];
    ORDER
        .iter()
        .position(|k| k.eq_ignore_ascii_case(kind))
        .unwrap_or(ORDER.len())
}

/// `@` for the apex, the relative label for names inside the zone, an absolute name otherwise.
pub fn owner(zone: &str, name: &str) -> String {
    let name = norm_name(name);
    if name == zone {
        "@".to_owned()
    } else if let Some(label) = name.strip_suffix(&format!(".{zone}")) {
        label.to_owned()
    } else {
        format!("{name}.")
    }
}

fn fqdn(name: &str) -> String {
    let name = name.trim();
    if name.ends_with('.') {
        name.to_owned()
    } else {
        format!("{name}.")
    }
}

fn line(zone: &str, record: &Record, options: &Options) -> String {
    let kind = record.kind.to_ascii_uppercase();
    let owner = owner(zone, &record.name);
    let ttl = record.ttl.unwrap_or(DEFAULT_TTL);
    let (rdata, known) = rdata(&kind, record);
    let mut text = format!("{owner}\t{ttl}\tIN\t{kind}\t{rdata}");
    let mut comment = None;
    if kind == "SOA" {
        comment = Some("SOA: the new provider sets its own");
    } else if kind == "NS" && owner == "@" {
        comment = Some("apex NS: the new provider sets its own");
    } else if record.disabled {
        comment = Some("disabled at IONOS, does not resolve today");
    } else if options.cloudflare && owner.eq_ignore_ascii_case("_domainconnect") {
        comment = Some("_domainconnect is reserved by Cloudflare");
    } else if !known {
        comment = Some("type not recognised by ionos-dns, content copied verbatim");
    }
    if options.cloudflare && comment.is_none() && matches!(kind.as_str(), "A" | "AAAA" | "CNAME") {
        text.push_str(" ; cf_tags=cf-proxied:false");
    }
    match comment {
        Some(reason) if reason.starts_with("type not") => format!("{text} ; {reason}"),
        Some(reason) => format!("; {reason}\n; {text}"),
        None => text,
    }
}

/// The record data in zone-file form, and whether the type is one this tool formats.
fn rdata(kind: &str, record: &Record) -> (String, bool) {
    let content = record.content.trim();
    let prio = record.prio.unwrap_or(0);
    match kind {
        "A" | "AAAA" => (content.to_owned(), true),
        "CNAME" | "NS" => (fqdn(content), true),
        "MX" => {
            let tokens: Vec<&str> = content.split_whitespace().collect();
            match tokens.as_slice() {
                [pref, host] if pref.parse::<u16>().is_ok() => {
                    (format!("{pref} {}", fqdn(host)), true)
                }
                _ => (format!("{prio} {}", fqdn(content)), true),
            }
        }
        "SRV" => {
            let tokens: Vec<&str> = content.split_whitespace().collect();
            match tokens.as_slice() {
                [weight, port, target] => {
                    (format!("{prio} {weight} {port} {}", fqdn(target)), true)
                }
                [p, weight, port, target] => {
                    (format!("{p} {weight} {port} {}", fqdn(target)), true)
                }
                _ => (content.to_owned(), false),
            }
        }
        "TXT" => (txt::emit(&txt::parse(content)), true),
        "CAA" => match caa_fields(content) {
            Some((flags, tag, value)) => (
                format!(
                    "{flags} {} {}",
                    tag.to_ascii_lowercase(),
                    txt::quote(&value)
                ),
                true,
            ),
            None => (content.to_owned(), false),
        },
        "SOA" => (content.to_owned(), true),
        _ => (content.to_owned(), false),
    }
}

/// `flags tag value` with the value quoted or bare.
pub fn caa_fields(content: &str) -> Option<(u8, String, Vec<u8>)> {
    let mut parts = content.trim().splitn(3, char::is_whitespace);
    let flags = parts.next()?.parse::<u8>().ok()?;
    let tag = parts.next()?.to_owned();
    let value = parts.next()?.trim();
    let bytes = if value.starts_with('"') {
        txt::joined(&txt::parse(value))
    } else {
        value.as_bytes().to_vec()
    };
    Some((flags, tag, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(
        name: &str,
        kind: &str,
        content: &str,
        ttl: u32,
        prio: Option<u32>,
        disabled: bool,
    ) -> Record {
        Record {
            name: name.into(),
            kind: kind.into(),
            content: content.into(),
            ttl: Some(ttl),
            prio,
            disabled,
        }
    }

    fn sample() -> Vec<Record> {
        vec![
            rec("example.com", "NS", "ns1.example.net", 86400, None, false),
            rec("example.com", "A", "192.0.2.1", 3600, None, false),
            rec("example.com", "AAAA", "2001:db8::1", 3600, None, false),
            rec(
                "example.com",
                "MX",
                "mail.example.net",
                3600,
                Some(10),
                false,
            ),
            rec(
                "example.com",
                "MX",
                "mailsec.example.net",
                3600,
                Some(20),
                false,
            ),
            rec(
                "example.com",
                "TXT",
                r#""v=spf1 include:_spf.example.net ~all""#,
                3600,
                None,
                false,
            ),
            rec(
                "_dmarc.example.com",
                "TXT",
                r#""v=DMARC1; p=none""#,
                3600,
                None,
                false,
            ),
            rec(
                "sel1._domainkey.example.com",
                "CNAME",
                "sel1.domainkey.example.net",
                3600,
                None,
                false,
            ),
            rec(
                "_domainconnect.example.com",
                "CNAME",
                "_domainconnect.example.net",
                3600,
                None,
                false,
            ),
            rec(
                "_sip._tcp.example.com",
                "SRV",
                "5 5060 sip.example.net",
                3600,
                Some(10),
                false,
            ),
            rec(
                "example.com",
                "CAA",
                r#"0 issue "letsencrypt.org""#,
                3600,
                None,
                false,
            ),
            rec("old.example.com", "A", "192.0.2.9", 3600, None, true),
        ]
    }

    #[test]
    fn renders_a_zone_file() {
        let out = render("Example.com.", &sample(), &Options { cloudflare: false });
        let expected = [
            "; example.com: exported by ionos-dns-api-cli VERSION from the IONOS hosting DNS API",
            "$ORIGIN example.com.",
            "$TTL 3600",
            "; apex NS: the new provider sets its own",
            "; @\t86400\tIN\tNS\tns1.example.net.",
            "@\t3600\tIN\tA\t192.0.2.1",
            "@\t3600\tIN\tAAAA\t2001:db8::1",
            "@\t3600\tIN\tMX\t10 mail.example.net.",
            "@\t3600\tIN\tMX\t20 mailsec.example.net.",
            "@\t3600\tIN\tTXT\t\"v=spf1 include:_spf.example.net ~all\"",
            "@\t3600\tIN\tCAA\t0 issue \"letsencrypt.org\"",
            "_dmarc\t3600\tIN\tTXT\t\"v=DMARC1; p=none\"",
            "_domainconnect\t3600\tIN\tCNAME\t_domainconnect.example.net.",
            "_sip._tcp\t3600\tIN\tSRV\t10 5 5060 sip.example.net.",
            "; disabled at IONOS, does not resolve today",
            "; old\t3600\tIN\tA\t192.0.2.9",
            "sel1._domainkey\t3600\tIN\tCNAME\tsel1.domainkey.example.net.",
            "",
        ]
        .join("\n")
        .replace("VERSION", env!("CARGO_PKG_VERSION"));
        assert_eq!(out, expected);
    }

    #[test]
    fn cloudflare_mode_marks_unproxied_and_skips_domainconnect() {
        let out = render("example.com", &sample(), &Options { cloudflare: true });
        assert!(out.contains("@\t3600\tIN\tA\t192.0.2.1 ; cf_tags=cf-proxied:false"));
        assert!(out.contains("sel1._domainkey\t3600\tIN\tCNAME\tsel1.domainkey.example.net. ; cf_tags=cf-proxied:false"));
        assert!(out.contains(
            "; _domainconnect is reserved by Cloudflare\n; _domainconnect\t3600\tIN\tCNAME"
        ));
        assert!(
            !out.contains("MX\t10 mail.example.net. ; cf_tags"),
            "only A, AAAA and CNAME carry the proxy tag"
        );
    }

    #[test]
    fn owner_names_are_relative_inside_the_zone() {
        assert_eq!(owner("example.com", "EXAMPLE.com."), "@");
        assert_eq!(owner("example.com", "a.b.example.com"), "a.b");
        assert_eq!(owner("example.com", "other.org"), "other.org.");
        assert_eq!(owner("example.com", "notexample.com"), "notexample.com.");
    }

    #[test]
    fn long_txt_is_split_and_caa_is_quoted() {
        let long = format!("\"{}\"", "k".repeat(300));
        let out = render(
            "example.com",
            &[
                rec("example.com", "TXT", &long, 300, None, false),
                rec("example.com", "CAA", "128 ISSUEWILD ;", 300, None, false),
            ],
            &Options { cloudflare: false },
        );
        assert!(out.contains(&format!(
            "@\t300\tIN\tTXT\t\"{}\" \"{}\"",
            "k".repeat(255),
            "k".repeat(45)
        )));
        assert!(out.contains("@\t300\tIN\tCAA\t128 issuewild \";\""));
    }
}
