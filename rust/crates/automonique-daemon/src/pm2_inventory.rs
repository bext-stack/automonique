// SPDX-License-Identifier: Elastic-2.0

//! Bounded, read-only projection of the current user's PM2 registry.
//!
//! PM2 exposes its process list over a local Unix RPC socket. This module sends
//! one fixed `getMonitorData` request using PM2's AMP framing, then retains only
//! process identity and lifecycle fields. Environment, command, path, log,
//! monitoring, and credential fields are never rendered or returned.

use std::env;
use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

const RPC_METHOD: &str = "getMonitorData";
const RPC_ID: &str = "automonique:0";
const TIMEOUT: Duration = Duration::from_millis(1_200);
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
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
    Insecure,
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
            "source=PM2 local read-only RPC sanitized projection\nstatus=available\nprocess_count={}\nonline={}\nstopped={}\nother={}",
            self.processes.len(),
            online,
            stopped,
            self.processes.len().saturating_sub(online + stopped),
        );
        for process in &self.processes {
            rendered.push_str(&format!(
                "\nprocess pm_id={} name={} status={} restarts={} mode={}",
                process.id, process.name, process.status, process.restarts, process.mode
            ));
        }
        rendered
    }
}

/// Query the current user's already-running PM2 daemon through its local RPC
/// socket. This never launches Node or starts a PM2 daemon.
pub fn current() -> Result<Pm2Inventory, Pm2Failure> {
    let socket = rpc_socket()?;
    let mut stream = UnixStream::connect(socket).map_err(|_| Pm2Failure::Unavailable)?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|_| Pm2Failure::Unavailable)?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|_| Pm2Failure::Unavailable)?;
    stream
        .write_all(&request_frame())
        .map_err(|_| Pm2Failure::Unavailable)?;
    let arguments = read_frame(&mut stream)?;
    decode_response(arguments)
}

fn rpc_socket() -> Result<PathBuf, Pm2Failure> {
    let root = env::var_os("PM2_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".pm2")))
        .ok_or(Pm2Failure::Unavailable)?;
    if !root.is_absolute() {
        return Err(Pm2Failure::Insecure);
    }
    let root = fs::canonicalize(root).map_err(|_| Pm2Failure::Unavailable)?;
    let socket = root.join("rpc.sock");
    let metadata = fs::symlink_metadata(&socket).map_err(|_| Pm2Failure::Unavailable)?;
    if !metadata.file_type().is_socket() || metadata.uid() != nix::unistd::geteuid().as_raw() {
        return Err(Pm2Failure::Insecure);
    }
    Ok(socket)
}

fn request_frame() -> Vec<u8> {
    encode_frame(&[
        format!("j:{{\"type\":\"call\",\"method\":\"{RPC_METHOD}\",\"args\":[{{}}]}}").as_bytes(),
        format!("s:{RPC_ID}").as_bytes(),
    ])
}

fn encode_frame(arguments: &[&[u8]]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(
        1 + arguments
            .iter()
            .map(|argument| 4 + argument.len())
            .sum::<usize>(),
    );
    frame.push(0x10 | u8::try_from(arguments.len()).unwrap_or(0x0f));
    for argument in arguments {
        frame.extend_from_slice(
            &u32::try_from(argument.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        frame.extend_from_slice(argument);
    }
    frame
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<Vec<u8>>, Pm2Failure> {
    let mut meta = [0_u8; 1];
    stream
        .read_exact(&mut meta)
        .map_err(|_| Pm2Failure::Unavailable)?;
    if meta[0] >> 4 != 1 || meta[0] & 0x0f == 0 {
        return Err(Pm2Failure::Malformed);
    }
    let count = usize::from(meta[0] & 0x0f);
    let mut total = 1_usize;
    let mut arguments = Vec::with_capacity(count);
    for _ in 0..count {
        let mut length = [0_u8; 4];
        stream
            .read_exact(&mut length)
            .map_err(|_| Pm2Failure::Unavailable)?;
        let length =
            usize::try_from(u32::from_be_bytes(length)).map_err(|_| Pm2Failure::Oversized)?;
        total = total.saturating_add(4).saturating_add(length);
        if total > MAX_RESPONSE_BYTES {
            return Err(Pm2Failure::Oversized);
        }
        let mut argument = vec![0_u8; length];
        stream
            .read_exact(&mut argument)
            .map_err(|_| Pm2Failure::Unavailable)?;
        arguments.push(argument);
    }
    Ok(arguments)
}

fn decode_response(arguments: Vec<Vec<u8>>) -> Result<Pm2Inventory, Pm2Failure> {
    if arguments.len() != 2 || arguments[1].as_slice() != format!("s:{RPC_ID}").as_bytes() {
        return Err(Pm2Failure::Malformed);
    }
    let document = arguments[0]
        .strip_prefix(b"j:")
        .ok_or(Pm2Failure::Malformed)?;
    let message =
        serde_json::from_slice::<serde_json::Value>(document).map_err(|_| Pm2Failure::Malformed)?;
    let object = message.as_object().ok_or(Pm2Failure::Malformed)?;
    if object.len() != 1 {
        return Err(Pm2Failure::Malformed);
    }
    let arguments = object
        .get("args")
        .and_then(serde_json::Value::as_array)
        .filter(|arguments| arguments.len() == 1)
        .ok_or(Pm2Failure::Malformed)?;
    decode_processes(&arguments[0])
}

fn decode_processes(value: &serde_json::Value) -> Result<Pm2Inventory, Pm2Failure> {
    let rows = value.as_array().ok_or(Pm2Failure::Malformed)?;
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
        let document = br#"{"args":[[{"pid":22,"name":"alpha\nservice","pm_id":7,"pm2_env":{"status":"online","restart_time":3,"exec_mode":"cluster_mode","cwd":"/private","SECRET":"no"},"monit":{"memory":99}}]]}"#;
        let inventory = decode_response(vec![
            [b"j:".as_slice(), document].concat(),
            format!("s:{RPC_ID}").into_bytes(),
        ])
        .expect("inventory");
        assert_eq!(inventory.online(), 1);
        assert_eq!(inventory.processes[0].name, "alpha service");
        assert_eq!(inventory.processes[0].restarts, 3);
        let rendered = inventory.render();
        assert!(!rendered.contains("private"));
        assert!(!rendered.contains("SECRET"));
        assert!(!rendered.contains("memory"));
    }

    #[test]
    fn request_is_exact_amp_and_responses_are_closed() {
        let request = request_frame();
        assert_eq!(request[0], 0x12);
        assert!(
            request
                .windows(RPC_METHOD.len())
                .any(|part| part == RPC_METHOD.as_bytes())
        );
        assert_eq!(
            decode_response(vec![b"j:null".to_vec()]),
            Err(Pm2Failure::Malformed)
        );
        assert_eq!(
            decode_processes(&serde_json::json!({})),
            Err(Pm2Failure::Malformed)
        );
    }

    #[test]
    #[ignore = "operator-only live host diagnostic"]
    fn live_host_rpc_reads_current_pm2_registry() {
        let socket = rpc_socket().expect("socket");
        let mut stream = UnixStream::connect(socket).expect("connect");
        stream.write_all(&request_frame()).expect("request");
        let arguments = read_frame(&mut stream).expect("frame");
        let inventory = decode_response(arguments).expect("live inventory");
        assert!(!inventory.processes.is_empty(), "{}", inventory.render());
    }
}
