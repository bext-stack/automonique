// SPDX-License-Identifier: Elastic-2.0

//! Exact Linux process identity for durable generation ownership.

use std::fs;
use std::path::PathBuf;

const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const MAX_PROC_STAT_BYTES: usize = 16 * 1024;

/// One process identity that cannot be confused by PID reuse or reboot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    pub boot_id: String,
    pub pid: u32,
    pub starttime: u64,
}

/// Process identity could not be measured safely.
#[derive(Debug)]
pub enum ProcessIdentityError {
    Io(std::io::Error),
    Malformed(&'static str),
}

impl ProcessIdentity {
    /// Measure this process from kernel-owned sources.
    pub fn current() -> Result<Self, ProcessIdentityError> {
        let pid = std::process::id();
        Ok(Self {
            boot_id: read_boot_id()?,
            pid,
            starttime: read_starttime(pid)?
                .ok_or(ProcessIdentityError::Malformed("self_stat_disappeared"))?,
        })
    }

    /// Whether the kernel still reports this exact process on this exact boot.
    pub fn is_live(&self) -> Result<bool, ProcessIdentityError> {
        if read_boot_id()? != self.boot_id {
            return Ok(false);
        }
        Ok(read_starttime(self.pid)? == Some(self.starttime))
    }
}

fn read_boot_id() -> Result<String, ProcessIdentityError> {
    let value = fs::read_to_string(BOOT_ID_PATH).map_err(ProcessIdentityError::Io)?;
    let value = value.trim();
    if value.len() != 36
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    {
        return Err(ProcessIdentityError::Malformed("boot_id"));
    }
    Ok(value.to_owned())
}

fn read_starttime(pid: u32) -> Result<Option<u64>, ProcessIdentityError> {
    if pid == 0 {
        return Ok(None);
    }
    let path = PathBuf::from("/proc").join(pid.to_string()).join("stat");
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(ProcessIdentityError::Io(error)),
    };
    if bytes.len() > MAX_PROC_STAT_BYTES {
        return Err(ProcessIdentityError::Malformed("proc_stat_too_large"));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ProcessIdentityError::Malformed("proc_stat_utf8"))?;
    parse_starttime(text).map(Some)
}

fn parse_starttime(stat: &str) -> Result<u64, ProcessIdentityError> {
    // `comm` is parenthesized and may itself contain spaces or `)`, so the
    // final close-parenthesis is the only safe boundary. The words after it
    // begin at field 3 (`state`); starttime is field 22, therefore index 19.
    let close = stat
        .rfind(')')
        .ok_or(ProcessIdentityError::Malformed("proc_stat_comm"))?;
    let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    fields
        .get(19)
        .ok_or(ProcessIdentityError::Malformed("proc_stat_fields"))?
        .parse::<u64>()
        .map_err(|_| ProcessIdentityError::Malformed("proc_stat_starttime"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_identity_is_live_and_nonzero() {
        let identity = ProcessIdentity::current().expect("identity");
        assert!(identity.pid > 0);
        assert!(identity.starttime > 0);
        assert!(identity.is_live().expect("liveness"));
    }

    #[test]
    fn stat_parser_uses_the_last_parenthesis_and_exact_field() {
        let mut fields = vec!["S"; 20];
        fields[19] = "4242";
        let stat = format!("7 (name with ) inside) {}", fields.join(" "));
        assert_eq!(parse_starttime(&stat).expect("starttime"), 4242);
        assert!(parse_starttime("7 malformed").is_err());
    }
}
