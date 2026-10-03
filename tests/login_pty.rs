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
    stderr: String,
    stdout: String,
    terminal_output: Vec<u8>,
    echo_restored: bool,
}

/// Runs `login` with the pty as its controlling terminal, waits for the prompt, then types or interrupts.
fn session(home: &std::path::Path, base: &str, action: Action) -> Session {
    let pty = open_pty();
    assert!(echo_on(&pty.slave), "a new pty starts with echo on");
    let child_stdin = pty.slave.try_clone().unwrap();
    let mut cmd = command(&["login"], Some(base), home);
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
    while !String::from_utf8_lossy(&seen).contains("(input hidden): ") {
        let chunk = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the prompt did not appear");
        seen.extend_from_slice(&chunk);
    }
    let mut master = pty.master;
    match action {
        Action::Type(text) => master.write_all(text).unwrap(),
        // SAFETY: signals the child process we spawned.
        Action::Interrupt => unsafe {
            libc::kill(child.id() as libc::pid_t, libc::SIGINT);
        },
    }
    let status = child.wait().unwrap();
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
        Action::Type(format!("{KEY}\n").as_bytes()),
    );
    assert_eq!(s.status.code(), Some(0), "{}{}", s.stdout, s.stderr);
    assert!(
        !String::from_utf8_lossy(&s.terminal_output).contains("TopSecretValue123"),
        "the terminal echoed the key"
    );
    assert!(!format!("{}{}", s.stdout, s.stderr).contains("TopSecretValue123"));
    assert!(s.echo_restored, "echo stays off after login");
    assert!(s.stderr.contains("developer portal"), "{}", s.stderr);
    assert_eq!(
        std::fs::read_to_string(home.join(".config/ionos-dns/api-key")).unwrap(),
        format!("{KEY}\n")
    );
}

#[test]
fn malformed_input_restores_echo() {
    let stub = api_stub();
    let home = temp_dir();
    let s = session(&home, &stub.base, Action::Type(b"not-a-key\n"));
    assert_eq!(s.status.code(), Some(2), "{}", s.stderr);
    assert!(s.echo_restored);
    assert!(!String::from_utf8_lossy(&s.terminal_output).contains("not-a-key"));
    assert!(stub.requests.lock().unwrap().is_empty());
}

#[test]
fn an_interrupt_restores_echo_and_stores_nothing() {
    let stub = api_stub();
    let home = temp_dir();
    let s = session(&home, &stub.base, Action::Interrupt);
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
