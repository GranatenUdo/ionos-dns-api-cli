//! Failures with their documented exit codes (README "Exit codes"). `main` maps every failure explicitly; nothing falls
//! back to a generic exit status.
use std::fmt;

/// Verify found records that differ.
pub const MISMATCH: u8 = 1;
/// Invalid arguments (clap also exits with 2 on its own usage errors).
pub const USAGE: u8 = 2;
/// Authentication, API, key-file or local I/O failure.
pub const API: u8 = 3;
/// A nameserver did not answer usably: timeout, REFUSED, SERVFAIL or a missing AA flag.
pub const DNS: u8 = 5;

#[derive(Debug)]
pub struct Exit {
    pub code: u8,
    pub message: String,
}

impl Exit {
    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            code: USAGE,
            message: message.into(),
        }
    }

    pub fn api(message: impl Into<String>) -> Self {
        Self {
            code: API,
            message: message.into(),
        }
    }

    pub fn dns(message: impl Into<String>) -> Self {
        Self {
            code: DNS,
            message: message.into(),
        }
    }
}

impl fmt::Display for Exit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Exit {}

pub type Result<T> = std::result::Result<T, Exit>;
