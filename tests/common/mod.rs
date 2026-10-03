//! Test doubles for the integration tests: an HTTP stub that plays the IONOS API, a DNS stub (UDP and TCP on the same
//! port) that plays a nameserver, and helpers to run the built binary. Fixtures use example.com and documentation
//! addresses only.
#![allow(dead_code)]

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

// ---------- temporary files ----------

static COUNTER: AtomicUsize = AtomicUsize::new(0);

pub fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ionos-dns-test-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A key file with the given mode.
pub fn key_file(dir: &Path, key: &str, mode: u32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("api-key");
    std::fs::write(&path, format!("{key}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

pub const KEY: &str = "testprefix.TopSecretValue123";

// ---------- running the binary ----------

/// The binary with a clean environment: only HOME (and the optional API base) set from the test.
pub fn command(args: &[&str], base: Option<&str>, home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ionos-dns"));
    command
        .args(args)
        .env_remove("IONOS_API_KEY_FILE")
        .env_remove("IONOS_DNS_API_BASE")
        .env_remove("XDG_CONFIG_HOME")
        .env("HOME", home);
    if let Some(base) = base {
        command.env("IONOS_DNS_API_BASE", base);
    }
    command
}

pub fn run(args: &[&str], base: Option<&str>, home: &Path) -> Output {
    let output = command(args, base, home).output().unwrap();
    assert_no_leak(&output);
    output
}

/// Runs with `input` on standard input (a pipe, not a terminal).
pub fn run_input(command: &mut Command, input: &[u8]) -> Output {
    use std::process::Stdio;
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let _ = stdin.write_all(input);
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert_no_leak(&output);
    output
}

pub fn assert_no_leak(output: &Output) {
    let all = format!("{}{}", stdout(output), stderr(output));
    assert!(
        !all.contains("TopSecretValue123"),
        "the key leaked into the output:\n{all}"
    );
}

pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

// ---------- HTTP stub ----------

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

pub fn json(status: u16, body: &str) -> Reply {
    Reply {
        status,
        headers: Vec::new(),
        body: body.to_owned(),
    }
}

pub struct HttpStub {
    pub base: String,
    pub requests: Arc<Mutex<Vec<Request>>>,
}

pub fn http_stub(handler: impl Fn(&Request) -> Reply + Send + Sync + 'static) -> HttpStub {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&requests);
    let handler = Arc::new(handler);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let seen = Arc::clone(&seen);
            let handler = Arc::clone(&handler);
            thread::spawn(move || serve_http(stream, &seen, &*handler));
        }
    });
    HttpStub { base, requests }
}

fn serve_http(stream: TcpStream, seen: &Mutex<Vec<Request>>, handler: &dyn Fn(&Request) -> Reply) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();
    let mut headers = Vec::new();
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).unwrap_or(0) == 0 || header.trim().is_empty() {
            break;
        }
        if let Some((k, v)) = header.split_once(':') {
            headers.push((k.trim().to_owned(), v.trim().to_owned()));
        }
    }
    let request = Request {
        method,
        target,
        headers,
    };
    let reply = handler(&request);
    seen.lock().unwrap().push(request);
    let mut out = stream;
    let mut head = format!(
        "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        reply.status,
        reply.body.len()
    );
    for (k, v) in &reply.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    let _ = out.write_all(head.as_bytes());
    let _ = out.write_all(reply.body.as_bytes());
    let _ = out.flush();
}

/// The fixture zone in the API's shape (OpenAPI 1.0.1): TXT content quoted as IONOS returns it.
pub const ZONE_ID: &str = "11af3414-ebba-11e9-8df5-66fbe8a334b4";

pub fn zones_body() -> String {
    format!(
        r#"[{{"name":"example.com","id":"{ZONE_ID}","type":"NATIVE"}},{{"name":"example.org","id":"22bf3414-ebba-11e9-8df5-66fbe8a334b4","type":"NATIVE"}}]"#
    )
}

pub fn zone_body() -> String {
    let records = [
        ("example.com", "NS", "ns1.example.net", 86400, None, false),
        ("example.com", "A", "192.0.2.1", 3600, None, false),
        ("example.com", "AAAA", "2001:db8::1", 3600, None, false),
        (
            "example.com",
            "MX",
            "mail.example.net",
            3600,
            Some(10),
            false,
        ),
        (
            "example.com",
            "MX",
            "mailsec.example.net",
            3600,
            Some(20),
            false,
        ),
        (
            "example.com",
            "TXT",
            "\"v=spf1 include:_spf.example.net ~all\"",
            3600,
            None,
            false,
        ),
        (
            "example.com",
            "TXT",
            "\"example-verification=0123abcd\"",
            3600,
            None,
            false,
        ),
        (
            "_dmarc.example.com",
            "TXT",
            "\"v=DMARC1; p=none; rua=mailto:dmarc@example.com\"",
            3600,
            None,
            false,
        ),
        (
            "sel1._domainkey.example.com",
            "CNAME",
            "sel1.domainkey.example.net",
            3600,
            None,
            false,
        ),
        (
            "_domainconnect.example.com",
            "CNAME",
            "_domainconnect.example.net",
            3600,
            None,
            false,
        ),
        ("old.example.com", "A", "192.0.2.9", 3600, None, true),
    ];
    let records: Vec<String> = records
        .iter()
        .enumerate()
        .map(|(i, (name, kind, content, ttl, prio, disabled))| {
            let prio = prio.map(|p| format!(r#","prio":{p}"#)).unwrap_or_default();
            format!(
                r#"{{"name":"{name}","rootName":"example.com","type":"{kind}","content":{content},"changeDate":"2026-01-0{d}T00:00:00.000Z","ttl":{ttl}{prio},"disabled":{disabled},"id":"rec-{i}","extraField":"kept"}}"#,
                content = serde_json::to_string(content).unwrap(),
                d = (i % 9) + 1
            )
        })
        .collect();
    format!(
        r#"{{"id":"{ZONE_ID}","name":"example.com","type":"NATIVE","records":[{}]}}"#,
        records.join(",")
    )
}

/// An API stub serving the fixture zone.
pub fn api_stub() -> HttpStub {
    http_stub(|req| {
        let path = req.target.split('?').next().unwrap_or_default();
        match path {
            "/v1/zones" => json(200, &zones_body()),
            p if p == format!("/v1/zones/{ZONE_ID}") => json(200, &zone_body()),
            _ => json(404, r#"[{"code":"NOT_FOUND","message":"Zone not found."}]"#),
        }
    })
}

// ---------- DNS stub ----------

#[derive(Clone)]
pub struct DnsConfig {
    pub authoritative: bool,
    pub rcode: ResponseCode,
    /// Answer UDP queries with TC set and no records, so the client must retry over TCP.
    pub truncate_udp: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            authoritative: true,
            rcode: ResponseCode::NoError,
            truncate_udp: false,
        }
    }
}

pub type Zone = HashMap<(String, RecordType), Vec<Record>>;

pub struct DnsStub {
    pub addr: String,
    pub udp_queries: Arc<AtomicUsize>,
    pub tcp_queries: Arc<AtomicUsize>,
}

pub fn name(text: &str) -> Name {
    Name::from_ascii(format!("{}.", text.trim_end_matches('.'))).unwrap()
}

pub fn record(owner: &str, ttl: u32, data: RData) -> Record {
    Record::from_rdata(name(owner), ttl, data)
}

/// The fixture zone as an authoritative server would serve it (enabled records, apex NS included).
pub fn fixture_dns_zone() -> Zone {
    let mut zone: Zone = HashMap::new();
    let mut add = |owner: &str, ttl: u32, data: RData| {
        let rec = record(owner, ttl, data);
        zone.entry((owner.to_owned(), rec.record_type()))
            .or_default()
            .push(rec);
    };
    add(
        "example.com",
        86400,
        RData::NS(NS(name("ns1.cloudflare.example"))),
    );
    add(
        "example.com",
        3600,
        RData::A(A("192.0.2.1".parse().unwrap())),
    );
    add(
        "example.com",
        3600,
        RData::AAAA(AAAA("2001:db8::1".parse().unwrap())),
    );
    add(
        "example.com",
        3600,
        RData::MX(MX::new(10, name("mail.example.net"))),
    );
    add(
        "example.com",
        3600,
        RData::MX(MX::new(20, name("mailsec.example.net"))),
    );
    // The SPF value split into two strings: verify compares the joined bytes.
    add(
        "example.com",
        300,
        RData::TXT(TXT::new(vec![
            "v=spf1 include:_spf".into(),
            ".example.net ~all".into(),
        ])),
    );
    add(
        "example.com",
        3600,
        RData::TXT(TXT::new(vec!["example-verification=0123abcd".into()])),
    );
    add(
        "_dmarc.example.com",
        3600,
        RData::TXT(TXT::new(vec![
            "v=DMARC1; p=none; rua=mailto:dmarc@example.com".into(),
        ])),
    );
    add(
        "sel1._domainkey.example.com",
        3600,
        RData::CNAME(CNAME(name("sel1.domainkey.example.net"))),
    );
    add(
        "_domainconnect.example.com",
        3600,
        RData::TXT(TXT::new(vec!["provider-owned".into()])),
    );
    zone
}

pub fn dns_stub(zone: Zone, config: DnsConfig) -> DnsStub {
    let (udp, tcp) = loop {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = udp.local_addr().unwrap().port();
        if let Ok(tcp) = TcpListener::bind(("127.0.0.1", port)) {
            break (udp, tcp);
        }
    };
    let addr = udp.local_addr().unwrap().to_string();
    let zone = Arc::new(zone);
    let udp_queries = Arc::new(AtomicUsize::new(0));
    let tcp_queries = Arc::new(AtomicUsize::new(0));
    {
        let (zone, config, count) = (Arc::clone(&zone), config.clone(), Arc::clone(&udp_queries));
        thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, peer)) = udp.recv_from(&mut buf) {
                count.fetch_add(1, Ordering::Relaxed);
                if let Some(reply) = answer(&buf[..n], &zone, &config, config.truncate_udp) {
                    let _ = udp.send_to(&reply, peer);
                }
            }
        });
    }
    {
        let count = Arc::clone(&tcp_queries);
        thread::spawn(move || {
            for mut stream in tcp.incoming().flatten() {
                count.fetch_add(1, Ordering::Relaxed);
                let mut len = [0u8; 2];
                if stream.read_exact(&mut len).is_err() {
                    continue;
                }
                let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
                if stream.read_exact(&mut buf).is_err() {
                    continue;
                }
                if let Some(reply) = answer(&buf, &zone, &config, false) {
                    let len = (reply.len() as u16).to_be_bytes();
                    let _ = stream.write_all(&len);
                    let _ = stream.write_all(&reply);
                }
            }
        });
    }
    DnsStub {
        addr,
        udp_queries,
        tcp_queries,
    }
}

fn answer(query: &[u8], zone: &Zone, config: &DnsConfig, truncate: bool) -> Option<Vec<u8>> {
    let request = Message::from_vec(query).ok()?;
    let question = request.queries.first()?.clone();
    let mut response = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
    response.metadata.authoritative = config.authoritative;
    response.metadata.response_code = config.rcode;
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.add_query(question.clone());
    if truncate {
        response.metadata.truncation = true;
    } else if config.rcode == ResponseCode::NoError {
        let owner = question
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let kind = question.query_type();
        if let Some(records) = zone.get(&(owner.clone(), kind)) {
            response.answers.extend(records.iter().cloned());
        } else if let Some(records) = zone.get(&(owner, RecordType::CNAME)) {
            response.answers.extend(records.iter().cloned());
        }
    }
    response.to_vec().ok()
}
