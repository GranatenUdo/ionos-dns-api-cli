//! The API key: read only from a private file, never from arguments or the environment, never printed.
use crate::error::{Exit, Result};
use std::fmt;
use std::path::{Path, PathBuf};

/// Environment variable naming the key file (not the key itself).
pub const KEY_FILE_ENV: &str = "IONOS_API_KEY_FILE";

/// An IONOS API key of the form `<prefix>.<secret>`. `Debug` and `Display` never show it.
pub struct ApiKey(String);

impl ApiKey {
    pub fn parse(raw: &str) -> Option<Self> {
        let key = raw.trim();
        let (prefix, secret) = key.split_once('.')?;
        let printable = key.bytes().all(|b| b.is_ascii_graphic());
        (printable && !prefix.is_empty() && !secret.is_empty()).then(|| Self(key.to_owned()))
    }

    /// The header value; the only place the key leaves this type.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiKey(<redacted>)")
    }
}

impl fmt::Display for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// `--key-file`, else `$IONOS_API_KEY_FILE`, else `$XDG_CONFIG_HOME/ionos-dns/api-key` (default `~/.config/...`).
pub fn key_path(cli: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = cli {
        return Ok(path.to_path_buf());
    }
    if let Some(path) = std::env::var_os(KEY_FILE_ENV).filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .map(|h| PathBuf::from(h).join(".config"))
        })
        .ok_or_else(|| {
            Exit::api(format!(
                "no key file: pass --key-file or set {KEY_FILE_ENV}"
            ))
        })?;
    Ok(config.join("ionos-dns").join("api-key"))
}

pub fn load(path: &Path) -> Result<ApiKey> {
    check_file(path)?;
    let raw = std::fs::read_to_string(path)
        .map_err(|e| Exit::api(format!("cannot read the key file {}: {e}", path.display())))?;
    ApiKey::parse(&raw).ok_or_else(|| {
        Exit::api(format!(
            "the key file {} does not hold a key of the form <prefix>.<secret>",
            path.display()
        ))
    })
}

/// A regular file owned by the current user and not accessible to group or others.
#[cfg(unix)]
fn check_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = std::fs::metadata(path)
        .map_err(|e| Exit::api(format!("key file {}: {e}", path.display())))?;
    if !meta.is_file() {
        return Err(Exit::api(format!(
            "key file {} is not a regular file",
            path.display()
        )));
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if meta.uid() != uid {
        return Err(Exit::api(format!(
            "key file {} is not owned by the current user",
            path.display()
        )));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Exit::api(format!(
            "key file {} is accessible to group or others (mode {mode:o}); run: chmod 600 {}",
            path.display(),
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_trims_a_key() {
        let key = ApiKey::parse("abc123.secretPart\n").expect("valid");
        assert_eq!(key.expose(), "abc123.secretPart");
    }

    #[test]
    fn rejects_malformed_keys() {
        for raw in [
            "",
            "nodot",
            ".secret",
            "prefix.",
            "pre fix.secret",
            "prefix.sec ret",
        ] {
            assert!(ApiKey::parse(raw).is_none(), "{raw:?} must be rejected");
        }
    }

    #[test]
    fn never_prints_the_key() {
        let key = ApiKey::parse("abc123.topsecret").expect("valid");
        assert!(!format!("{key:?} {key}").contains("topsecret"));
    }
}
