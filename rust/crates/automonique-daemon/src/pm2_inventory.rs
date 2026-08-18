// SPDX-License-Identifier: Elastic-2.0

//! Bounded, credential-free projection of the current user's PM2 registry.

use std::io::Read as _;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const PM2: &str = "/usr/bin/pm2";
const TIMEOUT: Duration = Duration::from_millis(1_500);
const POLL: Duration = Duration::from_millis(20);
const MAX_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROCESSES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pm2Process {
    pub id: i64,
    pub name: String,
    pub status: String,
    pub restarts: u64,
    pub mode: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pm2Inventory {
    pub processes: Vec<Pm2Process>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pm2Failure {
    Unavailable,
    Timeout,
    Oversized,
    Malformed,
}

impl Pm2Inventory {
    #[must_use]
    pub fn online(&self) -> usize {
        self.processes
            .iter()
            .filter(|process| process.status == "online")
            .count()
    }

    #[must_use]
    pub fn render(&self) -> String {
        let online = self.online();
        let stopped = self
            .processes
            .iter()
            .filter(|process| process.status == "stopped")
            .count();
        let mut rendered = format!(
            "source=PM2 jlist sanitized read model\nstatus=available\nprocess_count={}\nonline={}\nstopped={}\nother={}",
            self.processes.len(),
            online,
            stopped,
            self.processes.len().saturating_sub(online + stopped),
        );
        for process in &self.processes {
            rendered.push_str(&format!(
                "\nprocess id={} name={} status={} restarts={} mode={}",
                process.id, process.name, process.status, process.restarts, process.mode
            ));
        }
        rendered
    }
}

/// Read the current user's PM2 registry through a fixed executable and fixed
/// argument. Only the safe fields represented by [`Pm2Process`] survive.
pub fn current() -> Result<Pm2Inventory, Pm2Failure> {
    let mut child = Command::new(PM2)
        .arg("jlist")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Pm2Failure::Unavailable)?;
    let stdout = child.stdout.take().ok_or(Pm2Failure::Unavailable)?;
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut stdout = stdout;
        let mut chunk = [0_u8; 8 * 1024];
        loop {
            let read = stdout.read(&mut chunk)?;
            if read == 0 {
                return Ok::<_, std::io::Error>(bytes);
            }
            let retained = MAX_OUTPUT_BYTES
                .saturating_add(1)
                .saturating_sub(bytes.len())
                .min(read);
            bytes.extend_from_slice(&chunk[..retained]);
        }
    });
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let bytes = reader
                    .join()
                    .map_err(|_| Pm2Failure::Unavailable)?
                    .map_err(|_| Pm2Failure::Unavailable)?;
                if !status.success() {
                    return Err(Pm2Failure::Unavailable);
                }
                return decode(&bytes);
            }
            Ok(None) if started.elapsed() < TIMEOUT => thread::sleep(POLL),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(Pm2Failure::Timeout);
            }
            Err(_) => return Err(Pm2Failure::Unavailable),
        }
    }
}

fn decode(bytes: &[u8]) -> Result<Pm2Inventory, Pm2Failure> {
    if bytes.len() > MAX_OUTPUT_BYTES {
        return Err(Pm2Failure::Oversized);
    }
    let rows =
        serde_json::from_slice::<serde_json::Value>(bytes).map_err(|_| Pm2Failure::Malformed)?;
    let rows = rows.as_array().ok_or(Pm2Failure::Malformed)?;
    if rows.len() > MAX_PROCESSES {
        return Err(Pm2Failure::Oversized);
    }
    let mut processes = rows
        .iter()
        .map(|row| {
            let environment = row.get("pm2_env").and_then(serde_json::Value::as_object);
            Pm2Process {
                id: row
                    .get("pm_id")
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(-1),
                name: safe_field(
                    row.get("name")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unnamed"),
                    128,
                ),
                status: safe_field(
                    environment
                        .and_then(|value| value.get("status"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown"),
                    32,
                ),
                restarts: environment
                    .and_then(|value| value.get("restart_time"))
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0),
                mode: safe_field(
                    environment
                        .and_then(|value| value.get("exec_mode"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown"),
                    32,
                ),
            }
        })
        .collect::<Vec<_>>();
    processes.sort_by(|left, right| {
        (left.status != "online")
            .cmp(&(right.status != "online"))
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(Pm2Inventory { processes })
}

fn safe_field(value: &str, maximum: usize) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(maximum)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_retains_only_safe_process_fields() {
        let bytes = br#"[{"pid":22,"name":"alpha\nservice","pm_id":7,"pm2_env":{"status":"online","restart_time":3,"exec_mode":"cluster_mode","cwd":"/private","SECRET":"no"},"monit":{"memory":99}}]"#;
        let inventory = decode(bytes).expect("inventory");
        assert_eq!(inventory.online(), 1);
        assert_eq!(inventory.processes[0].name, "alpha service");
        assert_eq!(inventory.processes[0].restarts, 3);
        let rendered = inventory.render();
        assert!(!rendered.contains("private"));
        assert!(!rendered.contains("SECRET"));
        assert!(!rendered.contains("memory"));
    }

    #[test]
    fn decoder_rejects_non_array_and_oversized_input() {
        assert_eq!(decode(b"{}"), Err(Pm2Failure::Malformed));
        assert_eq!(
            decode(&vec![b' '; MAX_OUTPUT_BYTES + 1]),
            Err(Pm2Failure::Oversized)
        );
    }
}
