//! Typed views of the API's zones and records for display, export and verify. The JSON export keeps the raw values.
use crate::error::{Exit, Result};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
pub struct Zone {
    pub id: String,
    pub name: String,
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Record {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub ttl: Option<u32>,
    #[serde(default)]
    pub prio: Option<u32>,
    #[serde(default)]
    pub disabled: bool,
}

/// Lower case, without a trailing dot.
pub fn norm_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub fn zones_from(value: &Value) -> Result<Vec<Zone>> {
    serde_json::from_value(value.clone())
        .map_err(|e| Exit::api(format!("unexpected zone list in the API response: {e}")))
}

/// The `records` of a zone object (the API response or an earlier JSON export). An array is accepted as well.
pub fn record_values(zone: &Value) -> Result<Vec<Value>> {
    match zone {
        Value::Array(items) => Ok(items.clone()),
        Value::Object(map) => Ok(map
            .get("records")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()),
        _ => Err(Exit::api("expected a zone object with records")),
    }
}

pub fn records_from(values: &[Value]) -> Result<Vec<Record>> {
    values
        .iter()
        .map(|v| {
            serde_json::from_value(v.clone())
                .map_err(|e| Exit::api(format!("unexpected record in the API response: {e}")))
        })
        .collect()
}

/// Records sorted by name, type and content, so exports and listings are stable.
pub fn sort_values(values: &mut [Value]) {
    let key = |v: &Value| {
        let field = |k: &str| {
            v.get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase()
        };
        (field("name"), field("type"), field("content"))
    };
    values.sort_by_key(key);
}

/// The zone of the given name (case-insensitive, trailing dot ignored).
pub fn find_zone(zones: &[Zone], name: &str) -> Result<Zone> {
    let wanted = norm_name(name);
    zones
        .iter()
        .find(|z| norm_name(&z.name) == wanted)
        .cloned()
        .ok_or_else(|| Exit::api(format!("no zone named {wanted} in this account")))
}
