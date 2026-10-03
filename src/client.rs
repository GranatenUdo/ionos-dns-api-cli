//! Read-only client for the IONOS hosting DNS API (`https://api.hosting.ionos.com/dns`, OpenAPI 1.0.1).
//! It sends GET requests only, follows no redirects (ureq forwards custom headers such as `X-API-Key` across them) and
//! reads error bodies instead of discarding them.
use crate::error::{Exit, Result};
use crate::key::ApiKey;
use serde_json::Value;
use std::time::Duration;

pub const DEFAULT_BASE: &str = "https://api.hosting.ionos.com/dns";
/// Test-only override of the base URL; it may only point at this machine.
pub const BASE_ENV: &str = "IONOS_DNS_API_BASE";

const MAX_BODY: u64 = 16 * 1024 * 1024;

pub fn base_url() -> Result<String> {
    match std::env::var(BASE_ENV) {
        Ok(value) if !value.is_empty() => {
            check_override(&value)?;
            Ok(value.trim_end_matches('/').to_owned())
        }
        _ => Ok(DEFAULT_BASE.to_owned()),
    }
}

/// The override exists for local test servers only, so the key can never be sent to another host:
/// `http://127.0.0.1:<port>`, `http://localhost:<port>` or `http://[::1]:<port>`, optionally with a path.
pub fn check_override(base: &str) -> Result<()> {
    let refuse = || {
        Exit::api(format!(
            "{BASE_ENV} may only point at http://127.0.0.1:<port>, http://localhost:<port> or http://[::1]:<port>"
        ))
    };
    let rest = base.strip_prefix("http://").ok_or_else(refuse)?;
    let authority = rest.split('/').next().unwrap_or_default();
    let port = ["127.0.0.1:", "localhost:", "[::1]:"]
        .iter()
        .find_map(|host| authority.strip_prefix(host))
        .ok_or_else(refuse)?;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(refuse());
    }
    Ok(())
}

pub struct Client {
    agent: ureq::Agent,
    base: String,
    key: ApiKey,
}

impl Client {
    pub fn new(key: ApiKey) -> Result<Self> {
        let config = ureq::Agent::config_builder()
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(30)))
            .user_agent(concat!("ionos-dns-api-cli/", env!("CARGO_PKG_VERSION")))
            .build();
        Ok(Self {
            agent: config.into(),
            base: base_url()?,
            key,
        })
    }

    /// `GET /v1/zones`: the zones of the account.
    pub fn zones(&self) -> Result<Value> {
        self.get("/v1/zones", &[])
    }

    /// `GET /v1/zones/{id}` with the optional `suffix`, `recordName` and `recordType` filters.
    pub fn zone(&self, id: &str, filters: &[(&str, String)]) -> Result<Value> {
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(Exit::api(format!(
                "unexpected zone id {id:?} in the API response"
            )));
        }
        self.get(&format!("/v1/zones/{id}"), filters)
    }

    fn get(&self, path: &str, query: &[(&str, String)]) -> Result<Value> {
        let url = format!("{}{path}", self.base);
        let mut retried = false;
        loop {
            let mut request = self
                .agent
                .get(&url)
                .header("X-API-Key", self.key.expose())
                .header("Accept", "application/json");
            for (name, value) in query {
                request = request.query(*name, value);
            }
            let mut response = request
                .call()
                .map_err(|e| Exit::api(format!("GET {path} failed: {e}")))?;
            let status = response.status().as_u16();
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok());
            let body = response
                .body_mut()
                .with_config()
                .limit(MAX_BODY)
                .read_to_string()
                .unwrap_or_default();
            match status {
                200..=299 => {
                    return serde_json::from_str(&body).map_err(|e| {
                        Exit::api(format!("GET {path}: the response is not valid JSON: {e}"))
                    });
                }
                429 | 500..=599 if !retried && retry_after.is_some_and(|s| s <= 60) => {
                    retried = true;
                    std::thread::sleep(Duration::from_secs(retry_after.unwrap_or(1).max(1)));
                }
                300..=399 => {
                    return Err(Exit::api(format!(
                        "GET {path}: HTTP {status} redirect refused (the key is never sent to another location)"
                    )));
                }
                401 | 403 => {
                    return Err(Exit::api(format!(
                        "GET {path}: HTTP {status}, the API key was rejected{}",
                        api_message(&body)
                    )));
                }
                _ => {
                    return Err(Exit::api(format!(
                        "GET {path}: HTTP {status}{}",
                        api_message(&body)
                    )));
                }
            }
        }
    }
}

/// The API's error bodies differ by endpoint (`[{code, message}]`, `{errors: [...]}`, `{code, message}`); read them
/// loosely and keep the message short. Never echoes request headers.
pub fn api_message(body: &str) -> String {
    fn entry(v: &Value) -> Option<String> {
        let code = v.get("code").and_then(Value::as_str).unwrap_or_default();
        let message = v.get("message").and_then(Value::as_str).unwrap_or_default();
        match (code.is_empty(), message.is_empty()) {
            (true, true) => None,
            (true, false) => Some(message.to_owned()),
            (false, true) => Some(code.to_owned()),
            (false, false) => Some(format!("{code}: {message}")),
        }
    }
    let parsed: Option<Vec<String>> = serde_json::from_str::<Value>(body).ok().map(|v| match &v {
        Value::Array(items) => items.iter().filter_map(entry).collect(),
        Value::Object(map) => match map.get("errors").and_then(Value::as_array) {
            Some(items) => items.iter().filter_map(entry).collect(),
            None => entry(&v).into_iter().collect(),
        },
        _ => Vec::new(),
    });
    let text = match parsed {
        Some(messages) if !messages.is_empty() => messages.join("; "),
        _ => body.chars().filter(|c| !c.is_control()).take(200).collect(),
    };
    if text.trim().is_empty() {
        String::new()
    } else {
        format!(" ({})", text.trim())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_base_override_accepts_loopback_only() {
        for ok in [
            "http://127.0.0.1:8080",
            "http://localhost:1/dns",
            "http://[::1]:53000/",
        ] {
            assert!(check_override(ok).is_ok(), "{ok}");
        }
        for bad in [
            "https://api.hosting.ionos.com/dns",
            "http://example.com:80",
            "http://localhost:80@evil.example/",
            "http://127.0.0.1.evil.example:80",
            "http://127.0.0.1:",
            "http://localhost",
            "ftp://127.0.0.1:21",
        ] {
            assert!(check_override(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn error_bodies_are_read_loosely() {
        assert_eq!(
            api_message(r#"[{"code":"UNAUTHORIZED","message":"The customer is not authorized"}]"#),
            " (UNAUTHORIZED: The customer is not authorized)"
        );
        assert_eq!(
            api_message(r#"{"errors":[{"code":"INVALID_RECORD","message":"Record is invalid."}]}"#),
            " (INVALID_RECORD: Record is invalid.)"
        );
        assert_eq!(api_message(r#"{"message":"gone"}"#), " (gone)");
        assert_eq!(api_message("plain\ntext"), " (plaintext)");
        assert_eq!(api_message(""), "");
    }
}
