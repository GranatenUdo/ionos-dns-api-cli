//! `ionos-dns`: a small CLI for the IONOS hosting DNS API that reads DNS only. See README.md.
#[cfg(not(unix))]
compile_error!("ionos-dns supports Unix-like systems (Linux, macOS) only");

mod bind;
mod client;
mod error;
mod key;
mod model;
mod output;
mod prompt;
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
    about = "CLI for the IONOS hosting DNS API: store a key, list, export, verify (reads DNS only)"
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
    /// Store an API key: hidden entry, format check, a read-only test call, then a private 0600 file
    Login {
        /// Read the key from standard input (for scripts; not on a terminal, where entry is hidden instead)
        #[arg(long)]
        stdin: bool,
        /// Replace a key that is already stored
        #[arg(long)]
        force: bool,
        /// Do not open the IONOS key page in a browser; just print its address
        #[arg(long)]
        no_browser: bool,
        /// Catches a key typed as an argument, which is rejected without repeating it.
        #[arg(hide = true, num_args = 0.., allow_hyphen_values = true)]
        stray: Vec<String>,
    },
    /// Remove the stored key file (the key stays valid until you delete it in the IONOS developer portal)
    Logout,
    /// Check the stored key: file, permissions, format and whether the API accepts it
    Status {
        /// Print the report as JSON
        #[arg(long)]
        json: bool,
    },
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

/// The IONOS developer portal's API-key page, where keys are created and deleted.
const PORTAL_URL: &str = "https://developer.hosting.ionos.de/keys";
const PORTAL_STEPS: &str = "click \"Create New Key\", copy the key, then paste it here";

fn main() -> ExitCode {
    // No core dumps: a dump during a request would contain the key.
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: a valid rlimit struct; lowering a limit cannot fail in a way that matters here.
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) };
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
        Command::Login {
            stdin,
            force,
            no_browser,
            stray,
        } => login(key_file, stdin, force, no_browser, &stray),
        Command::Logout => {
            let path = key::key_path(key_file)?;
            if key::remove(&path)? {
                println!(
                    "Removed the key file {}. The key itself stays valid until you delete it in the IONOS developer portal: {PORTAL_URL}",
                    path.display()
                );
            } else {
                println!("No key stored at {}.", path.display());
            }
            Ok(0)
        }
        Command::Status { json } => status(key_file, json),
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

fn login(
    key_file: Option<&Path>,
    from_stdin: bool,
    force: bool,
    no_browser: bool,
    stray: &[String],
) -> Result<u8> {
    if !stray.is_empty() {
        return Err(Exit::usage(
            "login takes no key as an argument: an argument is visible to other processes and stays in your shell \
             history. If you typed a key, delete it in the IONOS developer portal and create a new one, then run \
             `ionos-dns login` and enter it at the hidden prompt.",
        ));
    }
    let path = key::key_path(key_file)?;
    key::check_target(&path, force)?;
    let (entered, two_parts) = if from_stdin {
        if prompt::stdin_is_terminal() {
            return Err(Exit::usage(
                "standard input is a terminal, where --stdin would show the key: omit --stdin for hidden entry",
            ));
        }
        key_from_stdin()?
    } else {
        // Checked before a browser opens, so `login </dev/null` or `login &` never launches one.
        prompt::check_terminal()?;
        let mut opener = open_portal(no_browser);
        eprintln!("The key will be stored in {}.", path.display());
        // A first part with a dot is the whole key; without one it is the prefix and the encrypted part follows.
        let wants_second = |first: &key::Secret| -> Result<bool> {
            let cleaned = key::clean_part(first.as_slice(), "first input")?;
            if cleaned.as_slice().is_empty() {
                return Err(Exit::usage("nothing was entered"));
            }
            Ok(!cleaned.as_slice().contains(&b'.'))
        };
        let parts = prompt::read_hidden_parts(
            "Key prefix, or the whole key (input hidden): ",
            "Encrypted part of the key (input hidden): ",
            &wants_second,
        );
        if let Some(child) = opener.as_mut() {
            let _ = child.try_wait();
        }
        let parts = parts?;
        assemble_parts(&parts)?
    };
    let dir = key::prepare_dir(&path)?;
    let temp = key::TempKey::write(&dir, &entered)?;
    drop(entered);
    // The test call uses the key as every other command does: loaded from a private file.
    let stored = key::load(temp.path())?;
    let prefix = stored.prefix().to_owned();
    let zones = client::Client::new(stored)?
        .zones()
        .map_err(|mut e| {
            if two_parts && e.message.contains("HTTP 401") {
                e.message.push_str(
                    "; check that the key prefix came first and the encrypted part second",
                );
            }
            e
        })
        .and_then(|v| model::zones_from(&v))?;
    temp.commit(&path, force)?;
    println!(
        "Stored the key {prefix}.… in {}. The API accepted it and lists {} zone{}.",
        path.display(),
        zones.len(),
        if zones.len() == 1 { "" } else { "s" }
    );
    Ok(0)
}

/// The key from one or two cleaned parts; the flag says whether it was entered in two parts.
fn assemble_parts(raw: &[key::Secret]) -> Result<(key::ApiKey, bool)> {
    match raw {
        [whole] => Ok((
            key::assemble(&key::clean_part(whole.as_slice(), "key")?, None)?,
            false,
        )),
        [prefix, secret] => {
            let prefix = key::clean_part(prefix.as_slice(), "key prefix")?;
            let secret = key::clean_part(secret.as_slice(), "encrypted part")?;
            Ok((key::assemble(&prefix, Some(&secret))?, true))
        }
        _ => Err(Exit::usage(
            "expected the whole key, or the key prefix and the encrypted part",
        )),
    }
}

/// `--stdin`: the whole key on one line, or the prefix and the encrypted part on two lines (blank lines and
/// surrounding whitespace, CRLF included, are ignored).
fn key_from_stdin() -> Result<(key::ApiKey, bool)> {
    let input = prompt::read_stdin()?;
    let mut lines = Vec::new();
    for line in input.as_slice().split(|b| *b == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if lines.len() == 2 {
            return Err(Exit::usage(
                "standard input has more than two lines: expected the whole key, or the key prefix and the \
                 encrypted part on two lines",
            ));
        }
        let mut part = key::Secret::new();
        part.extend(line);
        lines.push(part);
    }
    if lines.is_empty() {
        return Err(Exit::usage("standard input is empty"));
    }
    assemble_parts(&lines)
}

/// Opens the key page in the default browser (`xdg-open`, `open` on macOS) in a session of its own, so the prompt's
/// Ctrl-C or Ctrl-Z never reaches it and it cannot open this terminal. Never a failure: without a graphical session,
/// over SSH, with `--no-browser` or when the opener cannot start, the address is printed instead.
fn open_portal(no_browser: bool) -> Option<std::process::Child> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    let set = |name: &str| std::env::var_os(name).is_some_and(|v| !v.is_empty());
    let skip = if no_browser {
        Some("--no-browser")
    } else if set("SSH_CONNECTION") || set("SSH_TTY") {
        Some("SSH session")
    } else if cfg!(not(target_os = "macos")) && !set("WAYLAND_DISPLAY") && !set("DISPLAY") {
        Some("no graphical session")
    } else {
        None
    };
    if let Some(reason) = skip {
        eprintln!("Open {PORTAL_URL} in a browser ({reason}): {PORTAL_STEPS}.");
        return None;
    }
    let program = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let mut command = Command::new(program);
    command
        .arg(PORTAL_URL)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: setsid is async-signal-safe and cannot fail in a freshly forked child (never a group leader).
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    match command.spawn() {
        Ok(child) => {
            eprintln!(
                "Opening {PORTAL_URL} in your browser: {PORTAL_STEPS}. If nothing opens, visit the address yourself."
            );
            Some(child)
        }
        Err(_) => {
            eprintln!("Could not start a browser ({program}); open {PORTAL_URL}: {PORTAL_STEPS}.");
            None
        }
    }
}

fn status(key_file: Option<&Path>, json: bool) -> Result<u8> {
    let path = key::key_path(key_file)?;
    let state = key::inspect(&path);
    // The API is asked only with a key that passes the same checks as every other command.
    let api = match key::load(&path) {
        Err(e) => {
            serde_json::json!({ "checked": false, "ok": false, "zones": null, "error": e.message })
        }
        Ok(loaded) => match client::Client::new(loaded)
            .and_then(|c| c.zones())
            .and_then(|v| model::zones_from(&v))
        {
            Ok(zones) => {
                serde_json::json!({ "checked": true, "ok": true, "zones": zones.len(), "error": null })
            }
            Err(e) => {
                serde_json::json!({ "checked": true, "ok": false, "zones": null, "error": e.message })
            }
        },
    };
    let ok = api["ok"].as_bool().unwrap_or(false);
    if json {
        let mut doc = serde_json::to_value(&state).map_err(|e| Exit::api(e.to_string()))?;
        doc["api"] = api;
        emit(None, &output::json(&doc)?)?;
    } else {
        let yes = |b: bool| if b { "yes" } else { "no" };
        let mut text = format!("key file:   {}\n", state.path);
        if !state.exists {
            text.push_str("exists:     no (store a key with `ionos-dns login`)\n");
        } else {
            text.push_str(&format!(
                "file:       regular {}, symlink {}, owned by you {}, mode {}\n",
                yes(state.regular),
                yes(state.symlink),
                yes(state.owner_ok),
                state.mode.as_deref().unwrap_or("?")
            ));
            text.push_str(&format!(
                "key:        {}\n",
                match &state.prefix {
                    Some(prefix) => format!("{prefix}.… (format ok)"),
                    None => "not of the form <prefix>.<secret>".to_owned(),
                }
            ));
        }
        if let Some(mode) = &state.dir_mode {
            text.push_str(&format!(
                "directory:  mode {mode}, owned by you or root {}\n",
                yes(state.dir_owner_ok.unwrap_or(false))
            ));
        }
        text.push_str(&match (api["checked"].as_bool(), ok) {
            (Some(true), true) => format!("api:        key accepted, {} zones\n", api["zones"]),
            (Some(true), false) => format!(
                "api:        failed: {}\n",
                api["error"].as_str().unwrap_or("?")
            ),
            _ => format!(
                "api:        not checked: {}\n",
                api["error"].as_str().unwrap_or("?")
            ),
        });
        emit(None, &text)?;
    }
    Ok(if ok { 0 } else { error::API })
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
