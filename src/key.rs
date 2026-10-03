//! The API key: read only from a private file, never from arguments or the environment, never printed. `login`
//! stores it atomically with mode 0600, `logout` removes it, `status` inspects it.
use crate::error::{Exit, Result};
use serde::Serialize;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Environment variable naming the key file (not the key itself).
pub const KEY_FILE_ENV: &str = "IONOS_API_KEY_FILE";
/// Upper bound for key input and key files; IONOS keys are far shorter.
pub const MAX_KEY_BYTES: usize = 4096;

/// An IONOS API key of the form `<prefix>.<secret>`. `Debug` and `Display` never show it; it is zeroed on drop.
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

    /// The public part before the dot, which identifies the key in the IONOS developer portal.
    pub fn prefix(&self) -> &str {
        self.0.split_once('.').map(|(p, _)| p).unwrap_or_default()
    }
}

impl Drop for ApiKey {
    fn drop(&mut self) {
        // SAFETY: zero bytes keep the string valid UTF-8.
        wipe(unsafe { self.0.as_bytes_mut() });
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

/// Overwrites a buffer that held key material.
pub fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
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

/// Reads the key from a regular file owned by the current user and not accessible to group or others.
pub fn load(path: &Path) -> Result<ApiKey> {
    check_file(path)?;
    let mut raw = fs::read_to_string(path)
        .map_err(|e| Exit::api(format!("cannot read the key file {}: {e}", path.display())))?;
    let key = ApiKey::parse(&raw);
    // SAFETY: zero bytes keep the string valid UTF-8.
    wipe(unsafe { raw.as_bytes_mut() });
    key.ok_or_else(|| {
        Exit::api(format!(
            "the key file {} does not hold a key of the form <prefix>.<secret>",
            path.display()
        ))
    })
}

fn check_file(path: &Path) -> Result<()> {
    let meta =
        fs::metadata(path).map_err(|e| Exit::api(format!("key file {}: {e}", path.display())))?;
    if !meta.is_file() {
        return Err(Exit::api(format!(
            "key file {} is not a regular file",
            path.display()
        )));
    }
    if meta.uid() != current_uid() {
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

/// What `status` reports about the key file, without stopping at the first problem.
#[derive(Debug, Default, Serialize)]
pub struct FileState {
    pub path: String,
    pub exists: bool,
    pub symlink: bool,
    pub regular: bool,
    pub owner_ok: bool,
    pub mode: Option<String>,
    pub dir_mode: Option<String>,
    pub dir_owner_ok: Option<bool>,
    pub format_ok: bool,
    pub prefix: Option<String>,
}

pub fn inspect(path: &Path) -> FileState {
    let mut state = FileState {
        path: path.display().to_string(),
        ..FileState::default()
    };
    if let Some(dir) = parent(path).and_then(|d| fs::metadata(d).ok()) {
        state.dir_mode = Some(format!("{:o}", dir.permissions().mode() & 0o7777));
        state.dir_owner_ok = Some(dir.uid() == current_uid() || dir.uid() == 0);
    }
    if let Ok(link) = fs::symlink_metadata(path) {
        state.symlink = link.file_type().is_symlink();
    }
    let Ok(meta) = fs::metadata(path) else {
        return state;
    };
    state.exists = true;
    state.regular = meta.is_file();
    state.owner_ok = meta.uid() == current_uid();
    state.mode = Some(format!("{:o}", meta.permissions().mode() & 0o777));
    if state.regular && meta.len() <= MAX_KEY_BYTES as u64 {
        if let Ok(mut raw) = fs::read_to_string(path) {
            if let Some(key) = ApiKey::parse(&raw) {
                state.format_ok = true;
                state.prefix = Some(key.prefix().to_owned());
            }
            // SAFETY: zero bytes keep the string valid UTF-8.
            wipe(unsafe { raw.as_bytes_mut() });
        }
    }
    state
}

fn parent(path: &Path) -> Option<&Path> {
    match path.parent() {
        Some(dir) if dir.as_os_str().is_empty() => Some(Path::new(".")),
        other => other,
    }
}

/// `login` refuses a symbolic link or a non-file at the target, and an existing key unless `force` is set.
pub fn check_target(path: &Path, force: bool) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Exit::api(format!("key file {}: {e}", path.display()))),
        Ok(meta) if meta.file_type().is_symlink() => Err(Exit::usage(format!(
            "{} is a symbolic link; remove it or choose another --key-file",
            path.display()
        ))),
        Ok(meta) if !meta.is_file() => Err(Exit::usage(format!(
            "{} is not a regular file",
            path.display()
        ))),
        Ok(_) if !force => Err(Exit::usage(format!(
            "a key is already stored at {}; use --force to replace it, or `ionos-dns logout` first",
            path.display()
        ))),
        Ok(_) => Ok(()),
    }
}

/// Creates the key directory (and missing parents) with mode 0700 and refuses a directory others could write to.
pub fn prepare_dir(path: &Path) -> Result<PathBuf> {
    let dir = parent(path).unwrap_or(Path::new(".")).to_path_buf();
    let missing: Vec<&Path> = dir
        .ancestors()
        .take_while(|d| !d.as_os_str().is_empty() && !d.exists())
        .collect();
    for created in missing.into_iter().rev() {
        match fs::DirBuilder::new().mode(0o700).create(created) {
            Ok(()) => {
                fs::set_permissions(created, fs::Permissions::from_mode(0o700)).map_err(|e| {
                    Exit::api(format!("cannot set the mode of {}: {e}", created.display()))
                })?
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(Exit::api(format!(
                    "cannot create {}: {e}",
                    created.display()
                )));
            }
        }
    }
    let meta = fs::metadata(&dir).map_err(|e| Exit::api(format!("{}: {e}", dir.display())))?;
    let mode = meta.permissions().mode();
    let open = mode & 0o022 != 0 && mode & 0o1000 == 0;
    if open || (meta.uid() != current_uid() && meta.uid() != 0) {
        return Err(Exit::api(format!(
            "the directory {} can be changed by other users (mode {:o}); choose a private directory",
            dir.display(),
            mode & 0o7777
        )));
    }
    Ok(dir)
}

/// The key written to a private temporary file next to the target. Removed on drop unless committed.
pub struct TempKey {
    path: PathBuf,
    dir: PathBuf,
    committed: bool,
}

impl TempKey {
    pub fn write(dir: &Path, key: &ApiKey) -> Result<Self> {
        for attempt in 0..16u32 {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let path = dir.join(format!(
                ".api-key.tmp-{}-{nanos}-{attempt}",
                std::process::id()
            ));
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path);
            let mut file = match file {
                Ok(file) => file,
                Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(Exit::api(format!(
                        "cannot create a file in {}: {e}",
                        dir.display()
                    )));
                }
            };
            let temp = Self {
                path: path.clone(),
                dir: dir.to_path_buf(),
                committed: false,
            };
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .and_then(|()| file.write_all(key.expose().as_bytes()))
                .and_then(|()| file.write_all(b"\n"))
                .and_then(|()| file.sync_all())
                .map_err(|e| Exit::api(format!("cannot write {}: {e}", path.display())))?;
            return Ok(temp);
        }
        Err(Exit::api(format!(
            "cannot create a temporary file in {}",
            dir.display()
        )))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Moves the key into place: atomically refuses an existing target without `force` (hard link), replaces it
    /// with `force` (rename), then syncs the directory.
    pub fn commit(mut self, target: &Path, force: bool) -> Result<()> {
        if force {
            fs::rename(&self.path, target).map_err(|e| {
                Exit::api(format!("cannot store the key at {}: {e}", target.display()))
            })?;
        } else {
            fs::hard_link(&self.path, target).map_err(|e| {
                if e.kind() == ErrorKind::AlreadyExists {
                    Exit::usage(format!(
                        "a key appeared at {} meanwhile; nothing was replaced",
                        target.display()
                    ))
                } else {
                    Exit::api(format!("cannot store the key at {}: {e}", target.display()))
                }
            })?;
            let _ = fs::remove_file(&self.path);
        }
        self.committed = true;
        sync_dir(&self.dir)
    }
}

impl Drop for TempKey {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| Exit::api(format!("cannot sync {}: {e}", dir.display())))
}

/// `logout`: removes the key file if it is a regular file owned by the current user that holds a key.
/// Returns false when there is nothing to remove.
pub fn remove(path: &Path) -> Result<bool> {
    let meta = match fs::symlink_metadata(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(Exit::api(format!("key file {}: {e}", path.display()))),
        Ok(meta) => meta,
    };
    let refuse = |why: &str| Err(Exit::api(format!("{} {why}; not removed", path.display())));
    if meta.file_type().is_symlink() {
        return refuse("is a symbolic link (the key file it points to would stay)");
    }
    if !meta.is_file() {
        return refuse("is not a regular file");
    }
    if meta.uid() != current_uid() {
        return refuse("is not owned by the current user");
    }
    if meta.len() > MAX_KEY_BYTES as u64 {
        return refuse("is too large to be a key file");
    }
    let mut raw = fs::read_to_string(path)
        .map_err(|e| Exit::api(format!("cannot read {}: {e}", path.display())))?;
    let is_key = ApiKey::parse(&raw).is_some();
    // SAFETY: zero bytes keep the string valid UTF-8.
    wipe(unsafe { raw.as_bytes_mut() });
    if !is_key {
        return refuse("does not hold a key of the form <prefix>.<secret>");
    }
    fs::remove_file(path)
        .map_err(|e| Exit::api(format!("cannot remove {}: {e}", path.display())))?;
    sync_dir(parent(path).unwrap_or(Path::new(".")))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_trims_a_key() {
        let key = ApiKey::parse("abc123.secretPart\n").expect("valid");
        assert_eq!(key.expose(), "abc123.secretPart");
        assert_eq!(key.prefix(), "abc123");
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

    #[test]
    fn wipe_zeroes_the_buffer() {
        let mut buffer = *b"abc.def";
        wipe(&mut buffer);
        assert_eq!(buffer, [0u8; 7]);
    }
}
