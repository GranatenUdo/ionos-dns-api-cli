//! Reading a key for `login`: hidden entry on the terminal, or standard input for scripts. Both read with
//! `libc::read` into bounded buffers that are zeroed afterwards (std's buffered stdin would keep a copy).
//!
//! The terminal path follows readpassphrase(3): echo is switched off (and checked) before the prompt appears, the
//! interrupt, quit, hang-up, terminate and job-control signals are caught without `SA_RESTART`, the terminal is
//! restored before the signal is re-raised, and after a stop (Ctrl-Z) the prompt starts again with echo off.
use crate::error::{Exit, Result};
use crate::key::{MAX_KEY_BYTES, wipe};
use libc::c_int;
use std::sync::atomic::{AtomicI32, Ordering};

static CAUGHT: AtomicI32 = AtomicI32::new(0);

extern "C" fn catch(signal: c_int) {
    CAUGHT.store(signal, Ordering::SeqCst);
}

const SIGNALS: [c_int; 7] = [
    libc::SIGINT,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGTERM,
    libc::SIGTSTP,
    libc::SIGTTIN,
    libc::SIGTTOU,
];

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

pub fn stdin_is_terminal() -> bool {
    // SAFETY: isatty only inspects the descriptor.
    unsafe { libc::isatty(0) == 1 }
}

fn write_stderr(text: &str) {
    let bytes = text.as_bytes();
    // SAFETY: a valid buffer of the given length.
    let _ = unsafe { libc::write(2, bytes.as_ptr().cast(), bytes.len()) };
}

/// Standard input up to `MAX_KEY_BYTES`; longer input is an error, not truncated.
pub fn read_stdin() -> Result<Vec<u8>> {
    let mut buffer = Vec::with_capacity(MAX_KEY_BYTES);
    let mut chunk = [0u8; 512];
    let result = loop {
        // SAFETY: reads into a stack buffer of the given length.
        let n = unsafe { libc::read(0, chunk.as_mut_ptr().cast(), chunk.len()) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            break Err(Exit::api("cannot read standard input"));
        }
        let n = n as usize;
        if n == 0 {
            break Ok(());
        }
        if buffer.len() + n > MAX_KEY_BYTES {
            break Err(Exit::usage(format!(
                "the input is longer than {MAX_KEY_BYTES} bytes; that is not an IONOS API key"
            )));
        }
        buffer.extend_from_slice(&chunk[..n]);
    };
    wipe(&mut chunk);
    match result {
        Ok(()) => Ok(buffer),
        Err(e) => {
            wipe(&mut buffer);
            Err(e)
        }
    }
}

/// One line from the terminal with echo off.
/// Standard input is this process's controlling terminal and we are in its foreground process group: the only
/// situation in which the hidden prompt can work. `login` checks this before it opens a browser.
pub fn check_terminal() -> Result<()> {
    if !stdin_is_terminal() {
        return Err(Exit::usage(
            "standard input is not a terminal; pipe the key with --stdin",
        ));
    }
    // SAFETY: plain queries on descriptor 0 and the calling process.
    let (foreground, group) = unsafe { (libc::tcgetpgrp(0), libc::getpgrp()) };
    if foreground == -1 || foreground != group {
        return Err(Exit::usage(
            "the terminal is not controlled by this process (background job or no controlling terminal); \
             run login in the foreground or use --stdin",
        ));
    }
    Ok(())
}

pub fn read_hidden(prompt: &str) -> Result<Vec<u8>> {
    loop {
        check_terminal()?;
        CAUGHT.store(0, Ordering::SeqCst);
        let saved = install_handlers();
        let outcome = hidden_line(prompt);
        restore_handlers(&saved);
        let signal = CAUGHT.swap(0, Ordering::SeqCst);
        if signal != 0 {
            if let Ok(mut line) = outcome {
                wipe(&mut line);
            }
            // SAFETY: re-raises the caught signal with the original disposition back in place.
            unsafe { libc::raise(signal) };
            if matches!(signal, libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU) {
                continue;
            }
            return Err(Exit::usage("interrupted"));
        }
        return outcome;
    }
}

fn install_handlers() -> Vec<(c_int, libc::sigaction)> {
    let mut saved = Vec::with_capacity(SIGNALS.len());
    for &signal in &SIGNALS {
        // SAFETY: sigaction structs are plain data; the handler only stores to an atomic.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = catch as extern "C" fn(c_int) as libc::sighandler_t;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = 0;
            let mut old: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(signal, &action, &mut old) == 0 {
                saved.push((signal, old));
            }
        }
    }
    saved
}

fn restore_handlers(saved: &[(c_int, libc::sigaction)]) {
    for (signal, old) in saved {
        // SAFETY: restores a disposition previously returned by sigaction.
        unsafe { libc::sigaction(*signal, old, std::ptr::null_mut()) };
    }
}

/// Restores the terminal settings when dropped.
struct Restore(libc::termios);

impl Drop for Restore {
    fn drop(&mut self) {
        // SAFETY: settings previously read from the same descriptor.
        unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &self.0) };
    }
}

fn hidden_line(prompt: &str) -> Result<Vec<u8>> {
    // SAFETY: termios is plain data filled by tcgetattr.
    let mut original: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(0, &mut original) } != 0 {
        return Err(Exit::api("cannot read the terminal settings"));
    }
    let mut quiet = original;
    quiet.c_lflag &= !(libc::ECHO | libc::ECHONL);
    quiet.c_iflag |= libc::ICRNL;
    // SAFETY: valid settings for descriptor 0.
    if unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &quiet) } != 0 {
        return Err(Exit::api("cannot switch off the terminal echo"));
    }
    let restore = Restore(original);
    // tcsetattr reports success if any change applied; confirm echo is really off before asking for the key.
    let mut applied: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(0, &mut applied) } != 0 || applied.c_lflag & libc::ECHO != 0 {
        drop(restore);
        return Err(Exit::api(
            "could not switch off the terminal echo; not reading the key",
        ));
    }
    write_stderr(prompt);
    let mut line = Vec::with_capacity(MAX_KEY_BYTES);
    let mut byte = [0u8; 1];
    let result = loop {
        // SAFETY: reads one byte into a stack buffer.
        let n = unsafe { libc::read(0, byte.as_mut_ptr().cast(), 1) };
        if n < 0 {
            if errno() == libc::EINTR {
                if CAUGHT.load(Ordering::SeqCst) != 0 {
                    break Err(Exit::usage("interrupted"));
                }
                continue;
            }
            break Err(Exit::api("cannot read the terminal"));
        }
        if n == 0 || byte[0] == b'\n' {
            break Ok(());
        }
        if line.len() >= MAX_KEY_BYTES {
            break Err(Exit::usage(format!(
                "the input is longer than {MAX_KEY_BYTES} bytes; that is not an IONOS API key"
            )));
        }
        line.push(byte[0]);
    };
    wipe(&mut byte);
    drop(restore);
    write_stderr("\n");
    match result {
        Ok(()) => Ok(line),
        Err(e) => {
            wipe(&mut line);
            Err(e)
        }
    }
}
