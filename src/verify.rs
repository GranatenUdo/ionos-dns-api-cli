//! `verify`: ask other nameservers for every enabled source record set and compare the answers with the source.
//!
//! Queries are non-recursive by default and must come back authoritative (AA), as an authoritative server answers
//! for its own zones; `--recursive` asks a resolver instead. EDNS0 with a 1232-byte buffer, TCP when truncated,
//! 2 s timeout and 3 tries. Values are normalised: lower-case names without trailing dots, TXT as the concatenated
//! bytes (never lower-cased), CAA as flags, lower-case tag and raw value, MX and SRV fields as numbers. TTLs are
//! reported, not compared. Limit: DNS cannot reveal records that exist only on the queried server.
use crate::bind::caa_fields;
use crate::error::{Exit, Result};
use crate::model::{Record, norm_name};
use crate::txt;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::str::FromStr;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(2);
const TRIES: usize = 3;
const EDNS_PAYLOAD: u16 = 1232;

/// One record set to compare: owner name (lower case, no trailing dot) and type.
pub type Key = (String, String);

#[derive(Debug, Default, Serialize)]
pub struct Plan {
    /// Expected values per record set.
    pub expected: BTreeMap<Key, Expected>,
    /// Delegated subdomains (NS below the apex): not compared.
    pub delegations: Vec<String>,
    /// Record sets below a delegation, invisible at the parent: not compared.
    pub hidden: Vec<Key>,
    /// Record sets left out by `--skip`, the apex NS and SOA, or disabled records.
    pub skipped: Vec<Key>,
}

#[derive(Debug, Default, Serialize)]
pub struct Expected {
    pub values: BTreeSet<String>,
    pub ttl: Option<u32>,
}

/// Builds the comparison plan from the source records.
pub fn plan(zone: &str, records: &[Record], skips: &[Key]) -> Result<Plan> {
    let zone = norm_name(zone);
    let mut plan = Plan::default();
    let delegations: BTreeSet<String> = records
        .iter()
        .filter(|r| r.kind.eq_ignore_ascii_case("NS") && norm_name(&r.name) != zone && !r.disabled)
        .map(|r| norm_name(&r.name))
        .collect();
    for record in records {
        let name = norm_name(&record.name);
        let kind = record.kind.to_ascii_uppercase();
        let key = (name.clone(), kind.clone());
        let apex_infra = name == zone && (kind == "NS" || kind == "SOA");
        if apex_infra || record.disabled || kind == "SOA" || skips.contains(&key) {
            push_unique(&mut plan.skipped, key);
            continue;
        }
        if kind == "NS" && delegations.contains(&name) {
            continue;
        }
        if delegations.iter().any(|d| name.ends_with(&format!(".{d}"))) {
            push_unique(&mut plan.hidden, key);
            continue;
        }
        let value = source_value(&kind, record).ok_or_else(|| {
            Exit::api(format!(
                "cannot read the {kind} record {name}: {:?}",
                record.content
            ))
        })?;
        let entry = plan.expected.entry(key).or_default();
        entry.values.insert(value);
        entry.ttl = record.ttl.or(entry.ttl);
    }
    plan.delegations = delegations.into_iter().collect();
    Ok(plan)
}

fn push_unique(list: &mut Vec<Key>, key: Key) {
    if !list.contains(&key) {
        list.push(key);
    }
}

/// `name:TYPE` (name relative to the zone, `@`, or absolute).
pub fn parse_skip(zone: &str, text: &str) -> Result<Key> {
    let (name, kind) = text.rsplit_once(':').ok_or_else(|| {
        Exit::usage(format!(
            "--skip {text}: expected NAME:TYPE, for example _domainconnect:CNAME"
        ))
    })?;
    let zone = norm_name(zone);
    let name = norm_name(name);
    let full = if name == "@" || name.is_empty() {
        zone
    } else if name == zone || name.ends_with(&format!(".{zone}")) {
        name
    } else {
        format!("{name}.{zone}")
    };
    Ok((full, kind.to_ascii_uppercase()))
}

/// The source record's value in the canonical comparison form.
pub fn source_value(kind: &str, record: &Record) -> Option<String> {
    let content = record.content.trim();
    let prio = record.prio.unwrap_or(0);
    match kind {
        "A" => content
            .parse::<std::net::Ipv4Addr>()
            .ok()
            .map(|ip| ip.to_string()),
        "AAAA" => content
            .parse::<std::net::Ipv6Addr>()
            .ok()
            .map(|ip| ip.to_string()),
        "CNAME" | "NS" => Some(norm_name(content)),
        "MX" => {
            let tokens: Vec<&str> = content.split_whitespace().collect();
            match tokens.as_slice() {
                [pref, host] => Some(format!("{} {}", pref.parse::<u16>().ok()?, norm_name(host))),
                [host] => Some(format!("{prio} {}", norm_name(host))),
                _ => None,
            }
        }
        "SRV" => {
            let tokens: Vec<&str> = content.split_whitespace().collect();
            let (p, w, port, target) = match tokens.as_slice() {
                [w, port, target] => (prio.to_string(), *w, *port, *target),
                [p, w, port, target] => ((*p).to_owned(), *w, *port, *target),
                _ => return None,
            };
            Some(format!(
                "{} {} {} {}",
                p.parse::<u16>().ok()?,
                w.parse::<u16>().ok()?,
                port.parse::<u16>().ok()?,
                norm_name(target)
            ))
        }
        "TXT" => Some(txt::escape(&txt::joined(&txt::parse(content)))),
        "CAA" => caa_fields(content).map(|(flags, tag, value)| caa_value(flags, &tag, &value)),
        _ => Some(content.to_owned()),
    }
}

fn caa_value(flags: u8, tag: &str, value: &[u8]) -> String {
    format!(
        "{flags} {} {}",
        tag.to_ascii_lowercase(),
        txt::escape(value)
    )
}

/// The answer record's value in the same canonical form.
pub fn answer_value(data: &RData) -> Option<String> {
    let name = |n: &Name| norm_name(&n.to_ascii());
    Some(match data {
        RData::A(a) => a.0.to_string(),
        RData::AAAA(a) => a.0.to_string(),
        RData::CNAME(n) => name(&n.0),
        RData::NS(n) => name(&n.0),
        RData::MX(mx) => format!("{} {}", mx.preference, name(&mx.exchange)),
        RData::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            name(&srv.target)
        ),
        RData::TXT(t) => txt::escape(&t.txt_data.concat()),
        RData::CAA(c) => {
            let flags = if c.issuer_critical { 0x80 } else { 0 } | c.reserved_flags;
            caa_value(flags, &c.tag, &c.value)
        }
        _ => return None,
    })
}

/// A nameserver as given on the command line: `ip`, `ip:port`, `[v6]:port`, `host` or `host:port` (port 53 default).
pub struct Server {
    pub label: String,
    pub addrs: Vec<SocketAddr>,
}

pub fn resolve_server(text: &str) -> Result<Server> {
    let label = text.to_owned();
    if let Ok(addr) = SocketAddr::from_str(text) {
        return Ok(Server {
            label,
            addrs: vec![addr],
        });
    }
    if let Ok(ip) = IpAddr::from_str(text.trim_start_matches('[').trim_end_matches(']')) {
        return Ok(Server {
            label,
            addrs: vec![SocketAddr::new(ip, 53)],
        });
    }
    let (host, port) = match text.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (
            host,
            port.parse::<u16>()
                .map_err(|_| Exit::usage(format!("--ns {text}: invalid port")))?,
        ),
        _ => (text, 53),
    };
    let mut addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| Exit::dns(format!("--ns {text}: cannot resolve {host}: {e}")))?
        .collect();
    addrs.sort_by_key(|a| a.is_ipv6());
    addrs.dedup();
    if addrs.is_empty() {
        return Err(Exit::dns(format!("--ns {text}: {host} has no address")));
    }
    Ok(Server { label, addrs })
}

/// The usable part of one answer.
pub struct Answer {
    pub values: BTreeSet<String>,
    pub ttl: Option<u32>,
    /// The name is a CNAME, so the server answered with it instead of the asked type.
    pub cname: Option<String>,
}

fn query_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static COUNTER: AtomicU16 = AtomicU16::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos as u16) ^ (std::process::id() as u16) ^ COUNTER.fetch_add(0x9e37, Ordering::Relaxed)
}

/// Asks `server` for `name`/`kind`. Errors are DNS failures (exit 5).
pub fn ask(
    server: &Server,
    name: &str,
    kind: &str,
    recursive: bool,
) -> std::result::Result<Answer, String> {
    let rtype =
        RecordType::from_str(kind).map_err(|_| format!("unsupported record type {kind}"))?;
    let qname =
        Name::from_ascii(format!("{name}.")).map_err(|e| format!("invalid name {name}: {e}"))?;
    let mut last_error = String::from("no answer");
    for _ in 0..TRIES {
        for addr in &server.addrs {
            match exchange(*addr, &qname, rtype, recursive) {
                Ok(response) => return interpret(&response, &qname, rtype, recursive),
                Err(e) => last_error = format!("{addr}: {e}"),
            }
        }
    }
    Err(format!("{name} {kind}: {last_error} ({TRIES} tries)"))
}

fn request(qname: &Name, rtype: RecordType, recursive: bool) -> Message {
    let mut message = Message::new(query_id(), MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = recursive;
    message.add_query(Query::query(qname.clone(), rtype));
    let mut edns = Edns::new();
    edns.set_max_payload(EDNS_PAYLOAD);
    message.set_edns(edns);
    message
}

fn exchange(
    addr: SocketAddr,
    qname: &Name,
    rtype: RecordType,
    recursive: bool,
) -> std::result::Result<Message, String> {
    let message = request(qname, rtype, recursive);
    let id = message.metadata.id;
    let wire = message.to_vec().map_err(|e| e.to_string())?;
    let bind: SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    socket.connect(addr).map_err(|e| e.to_string())?;
    socket.send(&wire).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 65535];
    let response = loop {
        let n = socket.recv(&mut buf).map_err(|e| e.to_string())?;
        if let Ok(response) = Message::from_vec(&buf[..n]) {
            if response.metadata.id == id && response.metadata.message_type == MessageType::Response
            {
                break response;
            }
        }
    };
    if response.metadata.truncation {
        exchange_tcp(addr, &wire, id)
    } else {
        Ok(response)
    }
}

fn exchange_tcp(addr: SocketAddr, wire: &[u8], id: u16) -> std::result::Result<Message, String> {
    let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT).map_err(|e| format!("tcp: {e}"))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    let len = u16::try_from(wire.len()).map_err(|_| "query too large".to_owned())?;
    stream
        .write_all(&len.to_be_bytes())
        .and_then(|_| stream.write_all(wire))
        .map_err(|e| format!("tcp: {e}"))?;
    let mut len = [0u8; 2];
    stream
        .read_exact(&mut len)
        .map_err(|e| format!("tcp: {e}"))?;
    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream
        .read_exact(&mut buf)
        .map_err(|e| format!("tcp: {e}"))?;
    let response = Message::from_vec(&buf).map_err(|e| format!("tcp: {e}"))?;
    if response.metadata.id != id {
        return Err("tcp: response id does not match".to_owned());
    }
    Ok(response)
}

fn interpret(
    response: &Message,
    qname: &Name,
    rtype: RecordType,
    recursive: bool,
) -> std::result::Result<Answer, String> {
    let code = response.metadata.response_code;
    if code != ResponseCode::NoError && code != ResponseCode::NXDomain {
        return Err(format!("{} {rtype}: {code}", qname.to_ascii()));
    }
    if !recursive && !response.metadata.authoritative {
        return Err(format!(
            "{} {rtype}: answer not authoritative (no AA flag); use --recursive for a resolver",
            qname.to_ascii()
        ));
    }
    let wanted = norm_name(&qname.to_ascii());
    let mut answer = Answer {
        values: BTreeSet::new(),
        ttl: None,
        cname: None,
    };
    for record in &response.answers {
        if norm_name(&record.name.to_ascii()) != wanted {
            continue;
        }
        let kind = record.record_type();
        if kind == rtype {
            if let Some(value) = answer_value(&record.data) {
                answer.values.insert(value);
                answer.ttl = Some(answer.ttl.map_or(record.ttl, |t| t.min(record.ttl)));
            }
        } else if kind == RecordType::CNAME {
            answer.cname = answer_value(&record.data);
        }
    }
    Ok(answer)
}

#[derive(Debug, Serialize)]
pub struct Mismatch {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub expected: Vec<String>,
    pub actual: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ServerReport {
    pub server: String,
    pub addresses: Vec<String>,
    pub compared: usize,
    pub matched: usize,
    pub mismatches: Vec<Mismatch>,
    /// TTL differences (reported, not counted as mismatches).
    pub ttl_differences: Vec<String>,
    pub failures: Vec<String>,
}

pub fn check(server: &Server, plan: &Plan, recursive: bool) -> ServerReport {
    let mut report = ServerReport {
        server: server.label.clone(),
        addresses: server.addrs.iter().map(ToString::to_string).collect(),
        compared: 0,
        matched: 0,
        mismatches: Vec::new(),
        ttl_differences: Vec::new(),
        failures: Vec::new(),
    };
    for ((name, kind), expected) in &plan.expected {
        report.compared += 1;
        match ask(server, name, kind, recursive) {
            Err(e) => report.failures.push(e),
            Ok(answer) => {
                if answer.values == expected.values {
                    report.matched += 1;
                    if let (Some(want), Some(got)) = (expected.ttl, answer.ttl) {
                        if want != got {
                            report
                                .ttl_differences
                                .push(format!("{name} {kind}: source {want}, server {got}"));
                        }
                    }
                } else {
                    report.mismatches.push(Mismatch {
                        name: name.clone(),
                        kind: kind.clone(),
                        expected: expected.values.iter().cloned().collect(),
                        actual: answer.values.iter().cloned().collect(),
                        note: answer.cname.map(|target| {
                            format!("the server has a CNAME to {target} at this name")
                        }),
                    });
                }
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(name: &str, kind: &str, content: &str, prio: Option<u32>, disabled: bool) -> Record {
        Record {
            name: name.into(),
            kind: kind.into(),
            content: content.into(),
            ttl: Some(3600),
            prio,
            disabled,
        }
    }

    #[test]
    fn the_plan_skips_apex_infrastructure_disabled_and_delegated_records() {
        let records = vec![
            rec("example.com", "NS", "ns1.example.net", None, false),
            rec(
                "example.com",
                "SOA",
                "ns1.example.net. hostmaster.example.com. 1 2 3 4 5",
                None,
                false,
            ),
            rec("example.com", "A", "192.0.2.1", None, false),
            rec("example.com", "MX", "mail.example.net", Some(10), false),
            rec("old.example.com", "A", "192.0.2.9", None, true),
            rec("sub.example.com", "NS", "ns.other.example", None, false),
            rec("www.sub.example.com", "A", "192.0.2.7", None, false),
            rec(
                "_domainconnect.example.com",
                "CNAME",
                "x.example.net",
                None,
                false,
            ),
        ];
        let skips = vec![parse_skip("example.com", "_domainconnect:cname").unwrap()];
        let plan = plan("example.com", &records, &skips).unwrap();
        let keys: Vec<&Key> = plan.expected.keys().collect();
        assert_eq!(
            keys,
            vec![
                &("example.com".to_owned(), "A".to_owned()),
                &("example.com".to_owned(), "MX".to_owned())
            ]
        );
        assert_eq!(plan.delegations, vec!["sub.example.com".to_owned()]);
        assert_eq!(
            plan.hidden,
            vec![("www.sub.example.com".to_owned(), "A".to_owned())]
        );
        assert!(
            plan.skipped
                .contains(&("_domainconnect.example.com".to_owned(), "CNAME".to_owned()))
        );
        assert!(
            plan.skipped
                .contains(&("old.example.com".to_owned(), "A".to_owned()))
        );
        assert_eq!(
            plan.expected[&("example.com".to_owned(), "MX".to_owned())]
                .values
                .iter()
                .next()
                .unwrap(),
            "10 mail.example.net"
        );
    }

    #[test]
    fn source_values_are_normalised() {
        let v = |kind: &str, content: &str, prio: Option<u32>| {
            source_value(kind, &rec("example.com", kind, content, prio, false)).unwrap()
        };
        assert_eq!(v("AAAA", "2001:0db8:0000::0001", None), "2001:db8::1");
        assert_eq!(
            v("CNAME", "Target.Example.NET.", None),
            "target.example.net"
        );
        assert_eq!(v("MX", "mail.example.net", Some(20)), "20 mail.example.net");
        assert_eq!(v("MX", "5 mail.example.net.", None), "5 mail.example.net");
        assert_eq!(
            v("SRV", "5 5060 sip.example.net", Some(10)),
            "10 5 5060 sip.example.net"
        );
        assert_eq!(v("TXT", r#""v=spf1" " -all""#, None), "v=spf1 -all");
        assert_eq!(v("TXT", r#""Case Kept""#, None), "Case Kept");
        assert_eq!(
            v("CAA", r#"0 ISSUE "ca.example""#, None),
            "0 issue ca.example"
        );
    }

    #[test]
    fn skip_names_resolve_relative_to_the_zone() {
        assert_eq!(
            parse_skip("example.com", "@:mx").unwrap(),
            ("example.com".into(), "MX".into())
        );
        assert_eq!(
            parse_skip("example.com", "www:A").unwrap(),
            ("www.example.com".into(), "A".into())
        );
        assert_eq!(
            parse_skip("example.com", "www.example.com.:A").unwrap(),
            ("www.example.com".into(), "A".into())
        );
        assert!(parse_skip("example.com", "nocolon").is_err());
    }

    #[test]
    fn servers_parse_with_and_without_ports() {
        assert_eq!(
            resolve_server("192.0.2.53").unwrap().addrs,
            vec!["192.0.2.53:53".parse().unwrap()]
        );
        assert_eq!(
            resolve_server("127.0.0.1:5353").unwrap().addrs,
            vec!["127.0.0.1:5353".parse().unwrap()]
        );
        assert_eq!(
            resolve_server("[::1]:5353").unwrap().addrs,
            vec!["[::1]:5353".parse().unwrap()]
        );
        assert_eq!(
            resolve_server("2001:db8::53").unwrap().addrs,
            vec!["[2001:db8::53]:53".parse().unwrap()]
        );
        assert_eq!(
            resolve_server("localhost:5353").unwrap().addrs[0].port(),
            5353
        );
    }
}
