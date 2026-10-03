//! Reading a key for `login`: hidden entry on the terminal, or standard input for scripts. Both read with
//! `libc::read` into bounded `Secret` buffers that wipe themselves (std's buffered stdin would keep a copy).
//!
//! The terminal path follows readpassphrase(3): echo is switched off (and checked) before the first prompt appears,
//! the interrupt, quit, hang-up, terminate and job-control signals are caught without `SA_RESTART`, the terminal is
//! restored before the signal is re-raised, and after a stop (Ctrl-Z) only the part still missing is asked again.
//! Both parts of a two-part key are read in one echo-off session, so pasted or typed-ahead input is never discarded
//! and echo never comes back between the prompts.
use crate::error::{Exit, Result};
use crate::key::{MAX_KEY_BYTES, Secret, wipe};
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

fn too_long() -> Exit {
    Exit::usage(format!(
        "the input is longer than {MAX_KEY_BYTES} bytes; that is not an IONOS API key"
    ))
}

/// Standard input up to `MAX_KEY_BYTES`; longer input is an error, not truncated.
pub fn read_stdin() -> Result<Secret> {
    let mut buffer = Secret::new();
    let mut chunk = Secret::new();
    chunk.resize_zeroed(512);
    loop {
        let slice = chunk.as_mut_slice();
        // SAFETY: reads into a buffer of the given length.
        let n = unsafe { libc::read(0, slice.as_mut_ptr().cast(), slice.len()) };
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return Err(Exit::api("cannot read standard input"));
        }
        let n = n as usize;
        if n == 0 {
            return Ok(buffer);
        }
        if !buffer.extend(&chunk.as_slice()[..n]) {
            return Err(too_long());
        }
    }
}

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

/// Reads one or two hidden lines in a single echo-off session. After the first line, `wants_second` decides (and may
/// refuse the first part early) whether the second prompt follows. Returns the raw lines.
pub fn read_hidden_parts(
    first_prompt: &str,
    second_prompt: &str,
    wants_second: &dyn Fn(&Secret) -> Result<bool>,
) -> Result<Vec<Secret>> {
    let mut parts: Vec<Secret> = Vec::new();
    loop {
        check_terminal()?;
        CAUGHT.store(0, Ordering::SeqCst);
        let saved = install_handlers();
        let outcome = session(&mut parts, first_prompt, second_prompt, wants_second);
        restore_handlers(&saved);
        let signal = CAUGHT.swap(0, Ordering::SeqCst);
        if signal != 0 {
            // SAFETY: re-raises the caught signal with the original disposition back in place.
            unsafe { libc::raise(signal) };
            if matches!(signal, libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU) {
                continue; // resumed: ask again for the part still missing
            }
            return Err(Exit::usage("interrupted"));
        }
        return outcome.map(|()| parts);
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

/// One echo-off session: asks for the parts still missing in `parts`.
fn session(
    parts: &mut Vec<Secret>,
    first_prompt: &str,
    second_prompt: &str,
    wants_second: &dyn Fn(&Secret) -> Result<bool>,
) -> Result<()> {
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
    let result = (|| {
        if parts.is_empty() {
            write_stderr(first_prompt);
            let line = read_line()?;
            write_stderr("\n");
            parts.push(line);
        }
        if parts.len() == 1 && wants_second(&parts[0])? {
            write_stderr(second_prompt);
            let line = read_line()?;
            write_stderr("\n");
            parts.push(line);
        }
        Ok(())
    })();
    drop(restore);
    result
}

/// One line from descriptor 0, without the newline.
fn read_line() -> Result<Secret> {
    let mut line = Secret::new();
    let mut byte = [0u8; 1];
    loop {
        // SAFETY: reads one byte into a stack buffer.
        let n = unsafe { libc::read(0, byte.as_mut_ptr().cast(), 1) };
        if n < 0 {
            if errno() == libc::EINTR {
                if CAUGHT.load(Ordering::SeqCst) != 0 {
                    wipe(&mut byte);
                    return Err(Exit::usage("interrupted"));
                }
                continue;
            }
            return Err(Exit::api("cannot read the terminal"));
        }
        if n == 0 || byte[0] == b'\n' {
            wipe(&mut byte);
            return Ok(line);
        }
        if !line.extend(&byte) {
            wipe(&mut byte);
            return Err(too_long());
        }
    }
}
