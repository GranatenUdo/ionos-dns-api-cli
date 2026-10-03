//! `login`, `logout` and `status` through piped standard input (the hidden terminal prompt is covered in
//! tests/login_pty.rs).
mod common;

use common::*;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::Path;

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

fn default_key(home: &Path) -> std::path::PathBuf {
    home.join(".config/ionos-dns/api-key")
}

fn temp_files(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with(".api-key.tmp"))
                .collect()
        })
        .unwrap_or_default()
}

fn api_requests(stub: &HttpStub) -> usize {
    stub.requests.lock().unwrap().len()
}

#[test]
fn login_stores_a_tested_key_privately() {
    let stub = api_stub();
    let home = temp_dir();
    let out = run_input(
        &mut command(&["login", "--stdin"], Some(&stub.base), &home),
        format!("  {KEY}\n").as_bytes(),
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stdout(&out).contains("Stored the key testprefix.…"),
        "{}",
        stdout(&out)
    );
    assert!(stdout(&out).contains("lists 2 zones"), "{}", stdout(&out));
    let key = default_key(&home);
    assert_eq!(std::fs::read_to_string(&key).unwrap(), format!("{KEY}\n"));
    assert_eq!(mode(&key), 0o600);
    assert_eq!(
        mode(key.parent().unwrap()),
        0o700,
        "created directories are private"
    );
    assert_eq!(
        mode(&home.join(".config")),
        0o700,
        "created intermediates are private too"
    );
    let requests = stub.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].target, "/v1/zones");
    assert_eq!(requests[0].header("X-API-Key"), Some(KEY));
    assert!(temp_files(key.parent().unwrap()).is_empty());
}

#[test]
fn login_honours_xdg_and_key_file_and_keeps_existing_directories() {
    let stub = api_stub();
    let home = temp_dir();
    let xdg = home.join("xdg");
    std::fs::create_dir_all(xdg.join("ionos-dns")).unwrap();
    std::fs::set_permissions(
        xdg.join("ionos-dns"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let mut cmd = command(&["login", "--stdin"], Some(&stub.base), &home);
    cmd.env("XDG_CONFIG_HOME", &xdg);
    let out = run_input(&mut cmd, KEY.as_bytes());
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(xdg.join("ionos-dns/api-key").is_file());
    assert_eq!(
        mode(&xdg.join("ionos-dns")),
        0o755,
        "an existing directory is left as it is"
    );

    let explicit = home.join("elsewhere/key");
    let out = run_input(
        &mut command(
            &["login", "--stdin", "--key-file", explicit.to_str().unwrap()],
            Some(&stub.base),
            &home,
        ),
        KEY.as_bytes(),
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(mode(&explicit), 0o600);
}

#[test]
fn login_keeps_0600_under_umask_0() {
    let stub = api_stub();
    let home = temp_dir();
    let mut cmd = command(&["login", "--stdin"], Some(&stub.base), &home);
    // SAFETY: umask is async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            libc::umask(0);
            Ok(())
        });
    }
    let out = run_input(&mut cmd, KEY.as_bytes());
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(mode(&default_key(&home)), 0o600);
    assert_eq!(mode(default_key(&home).parent().unwrap()), 0o700);
}

#[test]
fn a_rejected_key_writes_nothing() {
    let stub = http_stub(|_| json(401, r#"[{"code":"UNAUTHORIZED","message":"no"}]"#));
    let home = temp_dir();
    let out = run_input(
        &mut command(&["login", "--stdin"], Some(&stub.base), &home),
        KEY.as_bytes(),
    );
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains("HTTP 401"), "{}", stderr(&out));
    assert!(!default_key(&home).exists());
    assert!(
        temp_files(default_key(&home).parent().unwrap()).is_empty(),
        "the temporary file is removed"
    );
}

#[test]
fn malformed_or_oversized_input_is_refused_without_an_api_call() {
    let stub = api_stub();
    let home = temp_dir();
    for input in [b"nodot\n".to_vec(), vec![b'a'; 5000]] {
        let out = run_input(
            &mut command(&["login", "--stdin"], Some(&stub.base), &home),
            &input,
        );
        assert_eq!(code(&out), 2, "{}", stderr(&out));
    }
    assert_eq!(api_requests(&stub), 0);
    assert!(!default_key(&home).exists());
}

#[test]
fn an_existing_key_needs_force() {
    let stub = api_stub();
    let home = temp_dir();
    let first = run_input(
        &mut command(&["login", "--stdin"], Some(&stub.base), &home),
        KEY.as_bytes(),
    );
    assert_eq!(code(&first), 0, "{}", stderr(&first));
    let other = "otherprefix.TopSecretValue123Other";
    let again = run_input(
        &mut command(&["login", "--stdin"], Some(&stub.base), &home),
        other.as_bytes(),
    );
    assert_eq!(code(&again), 2, "{}", stderr(&again));
    assert!(stderr(&again).contains("--force"), "{}", stderr(&again));
    assert_eq!(api_requests(&stub), 1, "no API call without --force");
    assert_eq!(
        std::fs::read_to_string(default_key(&home)).unwrap(),
        format!("{KEY}\n")
    );
    let forced = run_input(
        &mut command(&["login", "--stdin", "--force"], Some(&stub.base), &home),
        other.as_bytes(),
    );
    assert_eq!(code(&forced), 0, "{}", stderr(&forced));
    assert_eq!(
        std::fs::read_to_string(default_key(&home)).unwrap(),
        format!("{other}\n")
    );
    assert_eq!(mode(&default_key(&home)), 0o600);
}

#[test]
fn a_symlink_target_is_refused_even_when_dangling() {
    let stub = api_stub();
    let home = temp_dir();
    let key = default_key(&home);
    std::fs::create_dir_all(key.parent().unwrap()).unwrap();
    symlink(home.join("nowhere"), &key).unwrap();
    for args in [
        &["login", "--stdin"][..],
        &["login", "--stdin", "--force"][..],
    ] {
        let out = run_input(&mut command(args, Some(&stub.base), &home), KEY.as_bytes());
        assert_eq!(code(&out), 2, "{}", stderr(&out));
        assert!(stderr(&out).contains("symbolic link"), "{}", stderr(&out));
    }
    assert!(!home.join("nowhere").exists());
    assert_eq!(api_requests(&stub), 0);
}

#[test]
fn a_stale_temporary_file_does_not_block_login() {
    let stub = api_stub();
    let home = temp_dir();
    let dir = default_key(&home).parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(dir.join(".api-key.tmp-1-2-0"), "stale").unwrap();
    let out = run_input(
        &mut command(&["login", "--stdin"], Some(&stub.base), &home),
        KEY.as_bytes(),
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
}

#[test]
fn a_directory_others_can_write_is_refused() {
    let stub = api_stub();
    let home = temp_dir();
    let dir = home.join("open");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let target = dir.join("key");
    let out = run_input(
        &mut command(
            &["login", "--stdin", "--key-file", target.to_str().unwrap()],
            Some(&stub.base),
            &home,
        ),
        KEY.as_bytes(),
    );
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(!target.exists());
    assert_eq!(api_requests(&stub), 0);
}

#[test]
fn login_needs_a_terminal_or_stdin_and_rejects_a_key_argument() {
    let stub = api_stub();
    let home = temp_dir();
    let no_tty = run(&["login"], Some(&stub.base), &home);
    assert_eq!(code(&no_tty), 2);
    assert!(stderr(&no_tty).contains("--stdin"), "{}", stderr(&no_tty));
    let typed = run(&["login", KEY], Some(&stub.base), &home);
    assert_eq!(code(&typed), 2);
    assert!(
        stderr(&typed).contains("shell history"),
        "{}",
        stderr(&typed)
    );
    assert_eq!(api_requests(&stub), 0);
}

#[test]
fn logout_removes_only_a_key_file() {
    let stub = api_stub();
    let home = temp_dir();
    let login = run_input(
        &mut command(&["login", "--stdin"], Some(&stub.base), &home),
        KEY.as_bytes(),
    );
    assert_eq!(code(&login), 0, "{}", stderr(&login));
    let out = run(&["logout"], None, &home);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stdout(&out).contains("developer portal"),
        "{}",
        stdout(&out)
    );
    assert!(!default_key(&home).exists());
    let again = run(&["logout"], None, &home);
    assert_eq!(code(&again), 0);
    assert!(
        stdout(&again).contains("No key stored"),
        "{}",
        stdout(&again)
    );

    let unrelated = home.join("notes.txt");
    std::fs::write(&unrelated, "remember the milk\n").unwrap();
    let refused = run(
        &["logout", "--key-file", unrelated.to_str().unwrap()],
        None,
        &home,
    );
    assert_eq!(code(&refused), 3, "{}", stderr(&refused));
    assert!(unrelated.exists());

    let target = home.join("real-key");
    std::fs::write(&target, format!("{KEY}\n")).unwrap();
    let link = home.join("link-key");
    symlink(&target, &link).unwrap();
    let refused = run(
        &["logout", "--key-file", link.to_str().unwrap()],
        None,
        &home,
    );
    assert_eq!(code(&refused), 3, "{}", stderr(&refused));
    assert!(target.exists() && link.exists());
}

#[test]
fn status_reports_and_checks_only_compliant_files() {
    let stub = api_stub();
    let home = temp_dir();
    let missing = run(&["status"], Some(&stub.base), &home);
    assert_eq!(code(&missing), 3);
    assert!(
        stdout(&missing).contains("exists:     no"),
        "{}",
        stdout(&missing)
    );

    let login = run_input(
        &mut command(&["login", "--stdin"], Some(&stub.base), &home),
        KEY.as_bytes(),
    );
    assert_eq!(code(&login), 0, "{}", stderr(&login));
    let ok = run(&["status", "--json"], Some(&stub.base), &home);
    assert_eq!(code(&ok), 0, "{}", stderr(&ok));
    let doc: serde_json::Value = serde_json::from_str(&stdout(&ok)).unwrap();
    assert_eq!(doc["mode"], "600");
    assert_eq!(doc["dir_mode"], "700");
    assert_eq!(doc["prefix"], "testprefix");
    assert_eq!(doc["format_ok"], true);
    assert_eq!(doc["owner_ok"], true);
    assert_eq!(doc["symlink"], false);
    assert_eq!(doc["api"]["checked"], true);
    assert_eq!(doc["api"]["zones"], 2);

    let before = api_requests(&stub);
    std::fs::set_permissions(default_key(&home), std::fs::Permissions::from_mode(0o644)).unwrap();
    let open = run(&["status"], Some(&stub.base), &home);
    assert_eq!(code(&open), 3);
    assert!(stdout(&open).contains("mode 644"), "{}", stdout(&open));
    assert!(stdout(&open).contains("not checked"), "{}", stdout(&open));
    assert_eq!(
        api_requests(&stub),
        before,
        "a non-compliant key file is never sent to the API"
    );
}
