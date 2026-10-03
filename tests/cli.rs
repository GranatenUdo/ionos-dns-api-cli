//! End-to-end tests of the `ionos-dns` binary against local stubs (example.com fixtures only).
mod common;

use common::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RData;
use hickory_proto::rr::rdata::A;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::Ordering;

fn setup() -> (std::path::PathBuf, String) {
    let dir = temp_dir();
    let key = key_file(&dir, KEY, 0o600);
    (dir, key.to_string_lossy().into_owned())
}

#[test]
fn zones_lists_the_account_and_sends_the_key_header() {
    let stub = api_stub();
    let (home, key) = setup();
    let out = run(&["--key-file", &key, "zones"], Some(&stub.base), &home);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.starts_with("NAME"), "{text}");
    assert!(text.contains("example.com  NATIVE"), "{text}");
    let requests = stub.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].target, "/v1/zones");
    assert_eq!(requests[0].header("X-API-Key"), Some(KEY));
    assert!(
        requests[0]
            .header("User-Agent")
            .unwrap()
            .starts_with("ionos-dns-api-cli/")
    );
}

#[test]
fn records_passes_the_filters_and_sorts() {
    let stub = api_stub();
    let (home, key) = setup();
    let out = run(
        &[
            "records",
            "Example.COM.",
            "--suffix",
            "example.com",
            "--name",
            "example.com",
            "--type",
            "txt,mx",
            "--key-file",
            &key,
        ],
        Some(&stub.base),
        &home,
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let requests = stub.requests.lock().unwrap();
    let target = &requests[1].target;
    assert!(
        target.starts_with(&format!("/v1/zones/{ZONE_ID}?")),
        "{target}"
    );
    for part in [
        "recordName=example.com",
        "suffix=example.com",
        "recordType=TXT%2CMX",
    ] {
        assert!(target.contains(part), "{part} missing in {target}");
    }
    let text = stdout(&out);
    let first_data = text.lines().nth(1).unwrap();
    assert!(first_data.starts_with("_dmarc.example.com"), "{text}");
    assert!(text.contains("disabled"), "{text}");
}

#[test]
fn export_bind_writes_the_zone_file() {
    let stub = api_stub();
    let (home, key) = setup();
    let file = home.join("zone.txt");
    let out = run(
        &[
            "--key-file",
            &key,
            "export",
            "example.com",
            "-o",
            file.to_str().unwrap(),
        ],
        Some(&stub.base),
        &home,
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "exports are private");
    let zone = std::fs::read_to_string(&file).unwrap();
    for line in [
        "$ORIGIN example.com.",
        "; @\t86400\tIN\tNS\tns1.example.net.",
        "@\t3600\tIN\tA\t192.0.2.1",
        "@\t3600\tIN\tMX\t10 mail.example.net.",
        "@\t3600\tIN\tTXT\t\"v=spf1 include:_spf.example.net ~all\"",
        "_dmarc\t3600\tIN\tTXT\t\"v=DMARC1; p=none; rua=mailto:dmarc@example.com\"",
        "sel1._domainkey\t3600\tIN\tCNAME\tsel1.domainkey.example.net.",
        "; old\t3600\tIN\tA\t192.0.2.9",
    ] {
        assert!(zone.contains(line), "missing {line:?} in\n{zone}");
    }
    assert!(
        !zone.contains("\"\\\""),
        "TXT must not be quoted twice:\n{zone}"
    );
}

#[test]
fn export_cloudflare_marks_records_and_refuses_json() {
    let stub = api_stub();
    let (home, key) = setup();
    let out = run(
        &["--key-file", &key, "export", "example.com", "--cloudflare"],
        Some(&stub.base),
        &home,
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let zone = stdout(&out);
    assert!(zone.contains(
        "sel1._domainkey\t3600\tIN\tCNAME\tsel1.domainkey.example.net. ; cf_tags=cf-proxied:false"
    ));
    assert!(zone.contains("; _domainconnect is reserved by Cloudflare"));
    let refused = run(
        &[
            "--key-file",
            &key,
            "export",
            "example.com",
            "--cloudflare",
            "--format",
            "json",
        ],
        Some(&stub.base),
        &home,
    );
    assert_eq!(code(&refused), 2);
}

#[test]
fn export_json_is_lossless_and_sorted() {
    let stub = api_stub();
    let (home, key) = setup();
    let out = run(
        &[
            "--key-file",
            &key,
            "export",
            "example.com",
            "--format",
            "json",
        ],
        Some(&stub.base),
        &home,
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let value: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let records = value["records"].as_array().unwrap();
    assert_eq!(records.len(), 11);
    assert!(
        records
            .iter()
            .all(|r| r["extraField"] == "kept" && r.get("changeDate").is_some())
    );
    assert_eq!(records[0]["name"], "_dmarc.example.com");
    assert_eq!(
        records
            .iter()
            .find(|r| r["type"] == "TXT" && r["name"] == "example.com")
            .unwrap()["content"]
            .as_str()
            .unwrap()
            .chars()
            .next(),
        Some('"'),
        "the raw content stays as the API returned it"
    );
}

#[test]
fn api_errors_exit_3_with_the_api_message() {
    let stub = http_stub(|_| {
        json(
            401,
            r#"[{"code":"UNAUTHORIZED","message":"The customer is not authorized to do this operation."}]"#,
        )
    });
    let (home, key) = setup();
    let out = run(&["--key-file", &key, "zones"], Some(&stub.base), &home);
    assert_eq!(code(&out), 3);
    assert!(
        stderr(&out).contains(
            "HTTP 401, the API key was rejected (UNAUTHORIZED: The customer is not authorized"
        ),
        "{}",
        stderr(&out)
    );
}

#[test]
fn redirects_are_refused_and_never_followed() {
    let elsewhere = http_stub(|_| json(200, "[]"));
    let target = format!("{}/v1/zones", elsewhere.base);
    let stub = http_stub(move |_| Reply {
        status: 302,
        headers: vec![("Location".into(), target.clone())],
        body: String::new(),
    });
    let (home, key) = setup();
    let out = run(&["--key-file", &key, "zones"], Some(&stub.base), &home);
    assert_eq!(code(&out), 3);
    assert!(
        stderr(&out).contains("redirect refused"),
        "{}",
        stderr(&out)
    );
    assert!(
        elsewhere.requests.lock().unwrap().is_empty(),
        "the redirect was followed"
    );
}

#[test]
fn the_base_override_must_be_loopback() {
    let (home, key) = setup();
    let out = run(
        &["--key-file", &key, "zones"],
        Some("https://example.com/dns"),
        &home,
    );
    assert_eq!(code(&out), 3);
    assert!(
        stderr(&out).contains("IONOS_DNS_API_BASE may only point at"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn key_files_must_be_private_and_present() {
    let stub = api_stub();
    let home = temp_dir();
    let open = key_file(&home, KEY, 0o644);
    let out = run(
        &["--key-file", open.to_str().unwrap(), "zones"],
        Some(&stub.base),
        &home,
    );
    assert_eq!(code(&out), 3);
    assert!(stderr(&out).contains("chmod 600"), "{}", stderr(&out));
    let missing = run(&["zones"], Some(&stub.base), &home);
    assert_eq!(code(&missing), 3);
    assert!(
        stderr(&missing).contains(".config/ionos-dns/api-key"),
        "{}",
        stderr(&missing)
    );
    assert!(
        stub.requests.lock().unwrap().is_empty(),
        "no request without a usable key"
    );
}

#[test]
fn an_unknown_zone_exits_3() {
    let stub = api_stub();
    let (home, key) = setup();
    let out = run(
        &["--key-file", &key, "records", "example.net"],
        Some(&stub.base),
        &home,
    );
    assert_eq!(code(&out), 3);
    assert!(
        stderr(&out).contains("no zone named example.net"),
        "{}",
        stderr(&out)
    );
}

// ---------- verify ----------

fn verify(
    args: &[&str],
    dns: &DnsStub,
    api: &HttpStub,
    home: &std::path::Path,
    key: &str,
) -> std::process::Output {
    let mut all = vec![
        "--key-file",
        key,
        "verify",
        "example.com",
        "--ns",
        &dns.addr,
    ];
    all.extend_from_slice(args);
    run(&all, Some(&api.base), home)
}

#[test]
fn verify_matches_an_identical_server() {
    let api = api_stub();
    let dns = dns_stub(fixture_dns_zone(), DnsConfig::default());
    let (home, key) = setup();
    let out = verify(&["--skip", "_domainconnect:CNAME"], &dns, &api, &home, &key);
    assert_eq!(code(&out), 0, "{}{}", stdout(&out), stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("6 of 6 record sets match"), "{text}");
    assert!(
        text.contains("ttl (not compared) example.com TXT: source 3600, server 300"),
        "{text}"
    );
    assert!(text.contains("skipped: example.com NS"), "{text}");
    assert!(text.contains("skipped: old.example.com A"), "{text}");
}

#[test]
fn verify_reports_mismatches_with_exit_1() {
    let api = api_stub();
    let mut zone = fixture_dns_zone();
    zone.insert(
        ("example.com".into(), hickory_proto::rr::RecordType::A),
        vec![record(
            "example.com",
            3600,
            RData::A(A("198.51.100.7".parse().unwrap())),
        )],
    );
    let dns = dns_stub(zone, DnsConfig::default());
    let (home, key) = setup();
    let out = verify(&["--json"], &dns, &api, &home, &key);
    assert_eq!(code(&out), 1, "{}{}", stdout(&out), stderr(&out));
    let report: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    let mismatches = report["servers"][0]["mismatches"].as_array().unwrap();
    let names: Vec<String> = mismatches
        .iter()
        .map(|m| {
            format!(
                "{} {}",
                m["name"].as_str().unwrap(),
                m["type"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(
        names,
        vec!["_domainconnect.example.com CNAME", "example.com A"]
    );
    assert_eq!(mismatches[1]["actual"][0], "198.51.100.7");
}

#[test]
fn verify_requires_authoritative_answers_unless_recursive() {
    let api = api_stub();
    let dns = dns_stub(
        fixture_dns_zone(),
        DnsConfig {
            authoritative: false,
            ..DnsConfig::default()
        },
    );
    let (home, key) = setup();
    let out = verify(&["--skip", "_domainconnect:CNAME"], &dns, &api, &home, &key);
    assert_eq!(code(&out), 5, "{}{}", stdout(&out), stderr(&out));
    assert!(
        stdout(&out).contains("not authoritative"),
        "{}",
        stdout(&out)
    );
    let recursive = verify(
        &["--skip", "_domainconnect:CNAME", "--recursive"],
        &dns,
        &api,
        &home,
        &key,
    );
    assert_eq!(
        code(&recursive),
        0,
        "{}{}",
        stdout(&recursive),
        stderr(&recursive)
    );
}

#[test]
fn verify_treats_refused_as_a_dns_failure() {
    let api = api_stub();
    let dns = dns_stub(
        fixture_dns_zone(),
        DnsConfig {
            rcode: ResponseCode::Refused,
            ..DnsConfig::default()
        },
    );
    let (home, key) = setup();
    let out = verify(&[], &dns, &api, &home, &key);
    assert_eq!(code(&out), 5);
    assert!(stdout(&out).contains("DNS FAILURE"), "{}", stdout(&out));
}

#[test]
fn verify_retries_over_tcp_when_truncated() {
    let api = api_stub();
    let dns = dns_stub(
        fixture_dns_zone(),
        DnsConfig {
            truncate_udp: true,
            ..DnsConfig::default()
        },
    );
    let (home, key) = setup();
    let out = verify(&["--skip", "_domainconnect:CNAME"], &dns, &api, &home, &key);
    assert_eq!(code(&out), 0, "{}{}", stdout(&out), stderr(&out));
    assert!(dns.tcp_queries.load(Ordering::Relaxed) >= 6);
}

#[test]
fn verify_from_an_export_needs_no_key() {
    let api = api_stub();
    let (home, key) = setup();
    let export = home.join("zone.json");
    let out = run(
        &[
            "--key-file",
            &key,
            "export",
            "example.com",
            "--format",
            "json",
            "-o",
            export.to_str().unwrap(),
        ],
        Some(&api.base),
        &home,
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let dns = dns_stub(fixture_dns_zone(), DnsConfig::default());
    let empty_home = temp_dir();
    let out = run(
        &[
            "verify",
            "example.com",
            "--ns",
            &dns.addr,
            "--from",
            export.to_str().unwrap(),
            "--skip",
            "_domainconnect:CNAME",
        ],
        None,
        &empty_home,
    );
    assert_eq!(code(&out), 0, "{}{}", stdout(&out), stderr(&out));
    let wrong_zone = run(
        &[
            "verify",
            "example.org",
            "--ns",
            &dns.addr,
            "--from",
            export.to_str().unwrap(),
        ],
        None,
        &empty_home,
    );
    assert_eq!(code(&wrong_zone), 2, "{}", stderr(&wrong_zone));
}
