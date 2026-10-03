//! The hidden prompt of `login` on a real pseudo-terminal: the key is never echoed, and the terminal's echo is
//! restored after success, malformed input and an interrupt.
mod common;

use common::*;
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::Duration;

struct Pty {
    master: std::fs::File,
    slave: OwnedFd,
}

fn open_pty() -> Pty {
    let (mut master, mut slave) = (0, 0);
    // SAFETY: openpty fills two descriptors; null name, termios and winsize are allowed.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(rc, 0, "openpty failed");
    // SAFETY: freshly opened descriptors owned from here on.
    unsafe {
        Pty {
            master: std::fs::File::from_raw_fd(master),
            slave: OwnedFd::from_raw_fd(slave),
        }
    }
}

fn echo_on(slave: &OwnedFd) -> bool {
    use std::os::fd::AsRawFd;
    // SAFETY: termios is plain data filled by tcgetattr.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut t) }, 0);
    t.c_lflag & libc::ECHO != 0
}

enum Action<'a> {
    Type(&'a [u8]),
    Interrupt,
}

struct Session {
    status: ExitStatus,
    prompts: usize,
    stderr: String,
    stdout: String,
    terminal_output: Vec<u8>,
    echo_restored: bool,
}

const PROMPT: &str = "(input hidden): ";

/// Runs `login` with the pty as its controlling terminal; step n waits for the n-th hidden prompt, then types or
/// interrupts.
fn session(home: &std::path::Path, base: &str, steps: &[Action]) -> Session {
    session_with(home, base, &[], &[], steps)
}

fn session_with(
    home: &std::path::Path,
    base: &str,
    extra_args: &[&str],
    envs: &[(&str, &str)],
    steps: &[Action],
) -> Session {
    let pty = open_pty();
    assert!(echo_on(&pty.slave), "a new pty starts with echo on");
    let child_stdin = pty.slave.try_clone().unwrap();
    let mut args = vec!["login"];
    args.extend_from_slice(extra_args);
    let mut cmd = command(&args, Some(base), home);
    for (name, value) in envs {
        cmd.env(name, value);
    }
    cmd.stdin(Stdio::from(child_stdin))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: setsid and ioctl are async-signal-safe; the pty on fd 0 becomes the controlling terminal.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();
    let mut stderr_pipe = child.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let reader = std::thread::spawn(move || {
        let mut all = Vec::new();
        let mut buf = [0u8; 256];
        while let Ok(n) = stderr_pipe.read(&mut buf) {
            if n == 0 {
                break;
            }
            all.extend_from_slice(&buf[..n]);
            let _ = tx.send(buf[..n].to_vec());
        }
        all
    });
    let mut seen = Vec::new();
    let mut master = pty.master;
    for (index, step) in steps.iter().enumerate() {
        while String::from_utf8_lossy(&seen).matches(PROMPT).count() <= index {
            let chunk = rx
                .recv_timeout(Duration::from_secs(10))
                .unwrap_or_else(|_| panic!("prompt {} did not appear", index + 1));
            seen.extend_from_slice(&chunk);
        }
        match step {
            Action::Type(text) => master.write_all(text).unwrap(),
            // SAFETY: signals the child process we spawned.
            Action::Interrupt => unsafe {
                libc::kill(child.id() as libc::pid_t, libc::SIGINT);
            },
        }
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("login did not finish");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    let stderr = String::from_utf8_lossy(&reader.join().unwrap()).into_owned();
    // Whatever the terminal echoed back is waiting on the master side; read it without blocking.
    use std::os::fd::AsRawFd;
    // SAFETY: switches the master descriptor to non-blocking mode.
    unsafe {
        let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    let mut terminal_output = Vec::new();
    let mut buf = [0u8; 1024];
    while let Ok(n) = master.read(&mut buf) {
        if n == 0 {
            break;
        }
        terminal_output.extend_from_slice(&buf[..n]);
    }
    Session {
        status,
        prompts: stderr.matches(PROMPT).count(),
        stderr,
        stdout,
        terminal_output,
        echo_restored: echo_on(&pty.slave),
    }
}

#[test]
fn the_key_is_entered_hidden_and_echo_comes_back() {
    let stub = api_stub();
    let home = temp_dir();
    let s = session(
        &home,
        &stub.base,
        &[Action::Type(format!("{KEY}\n").as_bytes())],
    );
    assert_eq!(s.status.code(), Some(0), "{}{}", s.stdout, s.stderr);
    assert!(
        !String::from_utf8_lossy(&s.terminal_output).contains("TopSecretValue123"),
        "the terminal echoed the key"
    );
    assert!(!format!("{}{}", s.stdout, s.stderr).contains("TopSecretValue123"));
    assert!(s.echo_restored, "echo stays off after login");
    assert!(
        s.stderr.contains("developer.hosting.ionos.de/keys"),
        "{}",
        s.stderr
    );
    assert_eq!(
        std::fs::read_to_string(home.join(".config/ionos-dns/api-key")).unwrap(),
        format!("{KEY}\n")
    );
}

#[test]
fn malformed_input_restores_echo() {
    let stub = api_stub();
    let home = temp_dir();
    let s = session(&home, &stub.base, &[Action::Type(b"not a key\n")]);
    assert_eq!(s.status.code(), Some(2), "{}", s.stderr);
    assert!(s.echo_restored);
    assert!(!String::from_utf8_lossy(&s.terminal_output).contains("not a key"));
    assert!(s.stderr.contains("contains a space"), "{}", s.stderr);
    assert!(!s.stderr.contains("not a key"), "the input is never shown");
    assert_eq!(
        s.prompts, 1,
        "a bad first part is refused before the second prompt"
    );
    assert!(stub.requests.lock().unwrap().is_empty());
}

#[test]
fn an_interrupt_restores_echo_and_stores_nothing() {
    let stub = api_stub();
    let home = temp_dir();
    let s = session(&home, &stub.base, &[Action::Interrupt]);
    assert_eq!(
        s.status.signal(),
        Some(libc::SIGINT),
        "login ends by the interrupt itself"
    );
    assert!(
        s.echo_restored,
        "the terminal is restored before the signal is re-raised"
    );
    assert!(!home.join(".config/ionos-dns/api-key").exists());
    assert!(stub.requests.lock().unwrap().is_empty());
}

const KEY_PAGE: &str = "https://developer.hosting.ionos.de/keys";

#[test]
fn login_opens_the_key_page_in_a_session_of_its_own() {
    let stub = api_stub();
    let home = temp_dir();
    let s = session_with(
        &home,
        &stub.base,
        &[],
        &[("DISPLAY", ":99")],
        &[Action::Type(format!("{KEY}\n").as_bytes())],
    );
    assert_eq!(s.status.code(), Some(0), "{}{}", s.stdout, s.stderr);
    let record = wait_for_record(&home, 10).expect("the opener was not called");
    assert!(record.contains(&format!("args:{KEY_PAGE}\n")), "{record}");
    for fd in ["fd0", "fd1", "fd2"] {
        assert!(record.contains(&format!("{fd}:/dev/null\n")), "{record}");
    }
    assert!(
        record.contains("no-ctty"),
        "the opener can reach the terminal:\n{record}"
    );
    let opening = s.stderr.find("Opening").expect("no Opening line");
    let prompt = s.stderr.find("(input hidden): ").expect("no prompt");
    assert!(
        opening < prompt,
        "the browser is opened before the prompt:\n{}",
        s.stderr
    );
}

/// Extra arguments, extra environment, and the reason login prints.
type Case<'a> = (&'a [&'a str], &'a [(&'a str, &'a str)], &'a str);

#[test]
fn no_browser_over_ssh_without_display_or_when_asked() {
    let stub = api_stub();
    let cases: [Case; 3] = [
        (&["--no-browser"], &[("DISPLAY", ":99")], "(--no-browser)"),
        (
            &[],
            &[
                ("DISPLAY", ":99"),
                ("SSH_CONNECTION", "192.0.2.1 22 192.0.2.2 22"),
            ],
            "(SSH session)",
        ),
        (&[], &[], "(no graphical session)"),
    ];
    for (args, envs, reason) in cases {
        let home = temp_dir();
        let s = session_with(
            &home,
            &stub.base,
            args,
            envs,
            &[Action::Type(format!("{KEY}\n").as_bytes())],
        );
        assert_eq!(s.status.code(), Some(0), "{}{}", s.stdout, s.stderr);
        assert!(
            s.stderr
                .contains(&format!("Open {KEY_PAGE} in a browser {reason}")),
            "{}",
            s.stderr
        );
        assert!(
            wait_for_record(&home, 1).is_none(),
            "the opener was called for {reason}"
        );
    }
}

#[test]
fn a_missing_opener_does_not_stop_login() {
    let stub = api_stub();
    let home = temp_dir();
    let empty = home.join("empty-bin");
    std::fs::create_dir_all(&empty).unwrap();
    let s = session_with(
        &home,
        &stub.base,
        &[],
        &[("DISPLAY", ":99"), ("PATH", empty.to_str().unwrap())],
        &[Action::Type(format!("{KEY}\n").as_bytes())],
    );
    assert_eq!(s.status.code(), Some(0), "{}{}", s.stdout, s.stderr);
    assert!(
        s.stderr.contains("Could not start a browser"),
        "{}",
        s.stderr
    );
    assert!(home.join(".config/ionos-dns/api-key").is_file());
}

fn stored_key(home: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(home.join(".config/ionos-dns/api-key")).ok()
}

#[test]
fn the_whole_key_takes_one_prompt() {
    let stub = api_stub();
    let home = temp_dir();
    let s = session(
        &home,
        &stub.base,
        &[Action::Type(format!("{KEY}\n").as_bytes())],
    );
    assert_eq!(s.status.code(), Some(0), "{}", s.stderr);
    assert_eq!(s.prompts, 1, "{}", s.stderr);
}

#[test]
fn prefix_and_encrypted_part_in_two_prompts() {
    let stub = api_stub();
    let home = temp_dir();
    let s = session(
        &home,
        &stub.base,
        &[
            Action::Type(b"testprefix\n"),
            Action::Type(b"TopSecretValue123\n"),
        ],
    );
    assert_eq!(s.status.code(), Some(0), "{}{}", s.stdout, s.stderr);
    assert_eq!(s.prompts, 2);
    assert!(
        s.stderr.contains("Encrypted part of the key"),
        "{}",
        s.stderr
    );
    assert_eq!(
        stored_key(&home).as_deref(),
        Some(format!("{KEY}\n").as_str())
    );
    assert_eq!(
        stub.requests.lock().unwrap()[0].header("X-API-Key"),
        Some(KEY)
    );
    let echoed = String::from_utf8_lossy(&s.terminal_output).into_owned();
    assert!(
        !echoed.contains("testprefix") && !echoed.contains("TopSecretValue123"),
        "echoed: {echoed}"
    );
    assert!(s.echo_restored);
}

#[test]
fn both_parts_typed_ahead_are_kept() {
    let stub = api_stub();
    let home = temp_dir();
    let s = session(
        &home,
        &stub.base,
        &[Action::Type(b"testprefix\nTopSecretValue123\n")],
    );
    assert_eq!(s.status.code(), Some(0), "{}{}", s.stdout, s.stderr);
    assert_eq!(s.prompts, 2);
    assert_eq!(
        stored_key(&home).as_deref(),
        Some(format!("{KEY}\n").as_str())
    );
}

#[test]
fn an_interrupt_at_the_second_prompt_stores_nothing() {
    let stub = api_stub();
    let home = temp_dir();
    let s = session(
        &home,
        &stub.base,
        &[Action::Type(b"testprefix\n"), Action::Interrupt],
    );
    assert_eq!(s.status.signal(), Some(libc::SIGINT));
    assert!(s.echo_restored);
    assert!(stored_key(&home).is_none());
    assert!(stub.requests.lock().unwrap().is_empty());
}

#[test]
fn bracketed_paste_markers_are_removed() {
    let stub = api_stub();
    let home = temp_dir();
    let s = session(
        &home,
        &stub.base,
        &[Action::Type(
            format!("\x1b[200~{KEY}\x1b[201~\n").as_bytes(),
        )],
    );
    assert_eq!(s.status.code(), Some(0), "{}{}", s.stdout, s.stderr);
    assert_eq!(s.prompts, 1);
    assert_eq!(
        stored_key(&home).as_deref(),
        Some(format!("{KEY}\n").as_str())
    );
}
