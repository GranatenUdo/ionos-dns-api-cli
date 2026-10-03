//! `ionos-dns`: a small read-only CLI for the IONOS hosting DNS API. See README.md.
mod bind;
mod client;
mod error;
mod key;
mod model;
mod output;
mod txt;
mod verify;

use clap::{Parser, Subcommand, ValueEnum};
use error::{Exit, Result};
use serde_json::Value;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "ionos-dns",
    version,
    about = "Read-only CLI for the IONOS hosting DNS API: list, export, verify"
)]
struct Cli {
    /// File holding the API key <prefix>.<secret> (default: $IONOS_API_KEY_FILE, else $XDG_CONFIG_HOME/ionos-dns/api-key)
    #[arg(long, global = true, value_name = "PATH")]
    key_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List the zones of the account
    Zones {
        /// Print the API's JSON instead of a table
        #[arg(long)]
        json: bool,
    },
    /// List the records of a zone
    Records {
        /// Zone name, for example example.com
        zone: String,
        /// Only records with exactly this name (the API's recordName filter)
        #[arg(long)]
        name: Option<String>,
        /// Only records whose name ends with this suffix (the API's suffix filter)
        #[arg(long)]
        suffix: Option<String>,
        /// Only these record types (comma-separated, for example A,AAAA,TXT)
        #[arg(long = "type", value_delimiter = ',', value_name = "TYPE")]
        types: Vec<String>,
        /// Print the records as JSON (raw API fields, sorted)
        #[arg(long)]
        json: bool,
    },
    /// Export a zone as a BIND zone file or as lossless JSON
    Export {
        /// Zone name, for example example.com
        zone: String,
        #[arg(long, value_enum, default_value_t = Format::Bind)]
        format: Format,
        /// BIND only: mark A, AAAA and CNAME as not proxied and comment out _domainconnect, for Cloudflare's import
        #[arg(long)]
        cloudflare: bool,
        /// Write to this file (created with mode 0600) instead of standard output
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Ask other nameservers for every record set of the zone and compare their answers
    Verify {
        /// Zone name, for example example.com
        zone: String,
        /// Nameserver to ask: host, ip, host:port or [ipv6]:port (repeatable)
        #[arg(long = "ns", required = true, value_name = "SERVER")]
        servers: Vec<String>,
        /// Read the source records from an earlier `export --format json` instead of the API (no key needed)
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,
        /// Ask a recursive resolver (RD set, no AA required) instead of authoritative servers
        #[arg(long)]
        recursive: bool,
        /// Leave out a record set, NAME:TYPE (repeatable), for example _domainconnect:CNAME
        #[arg(long, value_name = "NAME:TYPE")]
        skip: Vec<String>,
        /// Print the report as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Bind,
    Json,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(failure) => {
            eprintln!("ionos-dns: {failure}");
            ExitCode::from(failure.code)
        }
    }
}

fn run(cli: Cli) -> Result<u8> {
    let key_file = cli.key_file.as_deref();
    match cli.command {
        Command::Zones { json } => {
            let value = connect(key_file)?.zones()?;
            if json {
                emit(None, &output::json(&value)?)?;
            } else {
                let zones = model::zones_from(&value)?;
                let rows: Vec<Vec<String>> = zones
                    .iter()
                    .map(|z| {
                        vec![
                            z.name.clone(),
                            z.kind.clone().unwrap_or_default(),
                            z.id.clone(),
                        ]
                    })
                    .collect();
                emit(None, &output::table(&["NAME", "TYPE", "ID"], &rows))?;
            }
            Ok(0)
        }
        Command::Records {
            zone,
            name,
            suffix,
            types,
            json,
        } => {
            let client = connect(key_file)?;
            let found = model::find_zone(&model::zones_from(&client.zones()?)?, &zone)?;
            let mut filters = Vec::new();
            if let Some(name) = name {
                filters.push(("recordName", name));
            }
            if let Some(suffix) = suffix {
                filters.push(("suffix", suffix));
            }
            if !types.is_empty() {
                filters.push((
                    "recordType",
                    types
                        .iter()
                        .map(|t| t.to_ascii_uppercase())
                        .collect::<Vec<_>>()
                        .join(","),
                ));
            }
            let mut values = model::record_values(&client.zone(&found.id, &filters)?)?;
            model::sort_values(&mut values);
            if json {
                emit(None, &output::json(&values)?)?;
            } else {
                let rows: Vec<Vec<String>> = model::records_from(&values)?
                    .iter()
                    .map(|r| {
                        vec![
                            r.name.clone(),
                            r.kind.clone(),
                            r.ttl.map(|t| t.to_string()).unwrap_or_default(),
                            r.prio.map(|p| p.to_string()).unwrap_or_default(),
                            if r.disabled {
                                "disabled".to_owned()
                            } else {
                                String::new()
                            },
                            r.content.clone(),
                        ]
                    })
                    .collect();
                emit(
                    None,
                    &output::table(&["NAME", "TYPE", "TTL", "PRIO", "STATE", "CONTENT"], &rows),
                )?;
            }
            Ok(0)
        }
        Command::Export {
            zone,
            format,
            cloudflare,
            output,
        } => {
            if cloudflare && matches!(format, Format::Json) {
                return Err(Exit::usage("--cloudflare applies to --format bind only"));
            }
            let client = connect(key_file)?;
            let found = model::find_zone(&model::zones_from(&client.zones()?)?, &zone)?;
            let mut value = client.zone(&found.id, &[])?;
            let mut records = model::record_values(&value)?;
            model::sort_values(&mut records);
            let text = match format {
                Format::Json => {
                    if let Value::Object(map) = &mut value {
                        map.insert("records".to_owned(), Value::Array(records));
                    }
                    output::json(&value)?
                }
                Format::Bind => bind::render(
                    &found.name,
                    &model::records_from(&records)?,
                    &bind::Options { cloudflare },
                ),
            };
            emit(output.as_deref(), &text)?;
            Ok(0)
        }
        Command::Verify {
            zone,
            servers,
            from,
            recursive,
            skip,
            json,
        } => {
            let source = match &from {
                Some(path) => read_export(path, &zone)?,
                None => {
                    let client = connect(key_file)?;
                    let found = model::find_zone(&model::zones_from(&client.zones()?)?, &zone)?;
                    client.zone(&found.id, &[])?
                }
            };
            let records = model::records_from(&model::record_values(&source)?)?;
            let skips = skip
                .iter()
                .map(|s| verify::parse_skip(&zone, s))
                .collect::<Result<Vec<_>>>()?;
            let plan = verify::plan(&zone, &records, &skips)?;
            let servers = servers
                .iter()
                .map(|s| verify::resolve_server(s))
                .collect::<Result<Vec<_>>>()?;
            let reports: Vec<verify::ServerReport> = servers
                .iter()
                .map(|s| verify::check(s, &plan, recursive))
                .collect();
            let failed = reports.iter().any(|r| !r.failures.is_empty());
            let differs = reports.iter().any(|r| !r.mismatches.is_empty());
            if json {
                let doc = serde_json::json!({
                    "zone": model::norm_name(&zone),
                    "delegations": plan.delegations,
                    "hidden": plan.hidden,
                    "skipped": plan.skipped,
                    "servers": reports,
                });
                emit(None, &output::json(&doc)?)?;
            } else {
                emit(None, &verify_text(&plan, &reports))?;
            }
            Ok(if failed {
                error::DNS
            } else if differs {
                error::MISMATCH
            } else {
                0
            })
        }
    }
}

fn connect(key_file: Option<&Path>) -> Result<client::Client> {
    let path = key::key_path(key_file)?;
    client::Client::new(key::load(&path)?)
}

/// An earlier `export --format json` (a zone object with records), checked to be the zone asked for.
fn read_export(path: &Path, zone: &str) -> Result<Value> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Exit::api(format!("cannot read {}: {e}", path.display())))?;
    let value: Value = serde_json::from_str(&text)
        .map_err(|e| Exit::usage(format!("{} is not a JSON export: {e}", path.display())))?;
    if let Some(name) = value.get("name").and_then(Value::as_str) {
        if model::norm_name(name) != model::norm_name(zone) {
            return Err(Exit::usage(format!(
                "{} holds the zone {name}, not {zone}",
                path.display()
            )));
        }
    }
    Ok(value)
}

fn verify_text(plan: &verify::Plan, reports: &[verify::ServerReport]) -> String {
    let mut out = String::new();
    for report in reports {
        out.push_str(&format!(
            "{} ({}): {} of {} record sets match\n",
            report.server,
            report.addresses.join(", "),
            report.matched,
            report.compared
        ));
        for m in &report.mismatches {
            out.push_str(&format!(
                "  MISMATCH {} {}\n    source: {}\n    server: {}\n",
                m.name,
                m.kind,
                m.expected.join(" | "),
                list_or_none(&m.actual)
            ));
            if let Some(note) = &m.note {
                out.push_str(&format!("    note: {note}\n"));
            }
        }
        for failure in &report.failures {
            out.push_str(&format!("  DNS FAILURE {failure}\n"));
        }
        for ttl in &report.ttl_differences {
            out.push_str(&format!("  ttl (not compared) {ttl}\n"));
        }
    }
    for d in &plan.delegations {
        out.push_str(&format!("delegation (not compared): {d}\n"));
    }
    for (name, kind) in &plan.hidden {
        out.push_str(&format!(
            "below a delegation (not compared): {name} {kind}\n"
        ));
    }
    for (name, kind) in &plan.skipped {
        out.push_str(&format!("skipped: {name} {kind}\n"));
    }
    out
}

fn list_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "(none)".to_owned()
    } else {
        values.join(" | ")
    }
}

/// Standard output, or a new file with mode 0600 (exports hold the whole zone).
fn emit(path: Option<&Path>, text: &str) -> Result<()> {
    match path {
        None => std::io::stdout()
            .lock()
            .write_all(text.as_bytes())
            .map_err(|e| Exit::api(format!("cannot write to standard output: {e}"))),
        Some(path) => {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options
                .open(path)
                .and_then(|mut file| file.write_all(text.as_bytes()))
                .map_err(|e| Exit::api(format!("cannot write {}: {e}", path.display())))
        }
    }
}
