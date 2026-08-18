// SPDX-License-Identifier: Elastic-2.0

//! Native, bounded projection of live PM2-managed processes.
//!
//! The dashboard runs with `MemoryDenyWriteExecute`, so invoking PM2's Node
//! CLI would require weakening the service sandbox. PM2 injects `pm_id` and
//! `name` into each managed child. This reader scans only same-UID `/proc`
//! environments, retains only those two exact keys, and discards every other
//! byte. It reports live children, not stopped PM2 registrations.

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

const PROC: &str = "/proc";
const MAX_PROC_ENTRIES: usize = 65_536;
const MAX_ENVIRON_BYTES: u64 = 256 * 1024;
const MAX_PROCESSES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pm2Process {
    pub id: u64,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pm2Inventory {
    pub processes: Vec<Pm2Process>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Pm2Failure {
    Unavailable,
    TooManyEntries,
    TooManyProcesses,
}

impl Pm2Inventory {
    #[must_use]
    pub fn online(&self) -> usize {
        self.processes.len()
    }

    #[must_use]
    pub fn render(&self) -> String {
        let mut rendered = format!(
            "source=same-UID /proc PM2 child projection\nstatus=available\nscope=live PM2-managed child processes only; stopped registrations are not included\nprocess_count={}\nonline={}",
            self.processes.len(),
            self.online(),
        );
        for process in &self.processes {
            rendered.push_str(&format!(
                "\nprocess pm_id={} name={} status=online",
                process.id, process.name
            ));
        }
        rendered
    }
}

/// Read live same-user PM2 children without executing Node or opening PM2
/// logs, dumps, sockets, configuration, or command lines.
pub fn current() -> Result<Pm2Inventory, Pm2Failure> {
    current_from(Path::new(PROC), nix::unistd::geteuid().as_raw())
}

fn current_from(root: &Path, effective_uid: u32) -> Result<Pm2Inventory, Pm2Failure> {
    let mut seen = 0_usize;
    let mut processes = Vec::new();
    for entry in fs::read_dir(root).map_err(|_| Pm2Failure::Unavailable)? {
        seen = seen.saturating_add(1);
        if seen > MAX_PROC_ENTRIES {
            return Err(Pm2Failure::TooManyEntries);
        }
        let Ok(entry) = entry else {
            continue;
        };
        let Some(_pid) = entry.file_name().to_str().and_then(parse_pid) else {
            continue;
        };
        let environ_path = entry.path().join("environ");
        let Ok(metadata) = fs::metadata(&environ_path) else {
            continue;
        };
        if !metadata.is_file()
            || metadata.uid() != effective_uid
            || metadata.len() > MAX_ENVIRON_BYTES
        {
            continue;
        }
        let Ok(file) = fs::File::open(environ_path) else {
            continue;
        };
        let mut bytes = Vec::new();
        if file
            .take(MAX_ENVIRON_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() as u64 > MAX_ENVIRON_BYTES
        {
            continue;
        }
        let mut id = None;
        let mut name = None;
        for field in bytes.split(|byte| *byte == 0) {
            if let Some(value) = field.strip_prefix(b"pm_id=") {
                id = std::str::from_utf8(value)
                    .ok()
                    .and_then(|value| value.parse::<u64>().ok());
            } else if let Some(value) = field.strip_prefix(b"name=") {
                name = std::str::from_utf8(value)
                    .ok()
                    .map(|value| safe_field(value, 128))
                    .filter(|value| !value.is_empty());
            }
        }
        if let (Some(id), Some(name)) = (id, name) {
            processes.push(Pm2Process { id, name });
            if processes.len() > MAX_PROCESSES {
                return Err(Pm2Failure::TooManyProcesses);
            }
        }
    }
    processes.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.id.cmp(&right.id))
    });
    processes.dedup_by(|left, right| left.id == right.id && left.name == right.name);
    Ok(Pm2Inventory { processes })
}

fn parse_pid(value: &str) -> Option<u32> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
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
    fn projection_retains_only_exact_pm2_keys() {
        let fixture = tempfile::tempdir().expect("fixture");
        let process = fixture.path().join("1234");
        fs::create_dir(&process).expect("process");
        fs::write(
            process.join("environ"),
            b"SECRET=never\0pm_id=7\0name=alpha\nservice\0cwd=/private\0",
        )
        .expect("environment");
        let uid = fs::metadata(process.join("environ"))
            .expect("metadata")
            .uid();
        let inventory = current_from(fixture.path(), uid).expect("inventory");
        assert_eq!(
            inventory.processes,
            [Pm2Process {
                id: 7,
                name: String::from("alpha service")
            }]
        );
        let rendered = inventory.render();
        assert!(!rendered.contains("SECRET"));
        assert!(!rendered.contains("private"));
        assert!(!rendered.contains("cwd"));
    }

    #[test]
    fn projection_ignores_non_processes_and_non_pm2_processes() {
        let fixture = tempfile::tempdir().expect("fixture");
        fs::create_dir(fixture.path().join("self")).expect("non-pid");
        let process = fixture.path().join("222");
        fs::create_dir(&process).expect("process");
        fs::write(process.join("environ"), b"name=ordinary\0").expect("environment");
        let uid = fs::metadata(process.join("environ"))
            .expect("metadata")
            .uid();
        assert!(
            current_from(fixture.path(), uid)
                .expect("inventory")
                .processes
                .is_empty()
        );
    }
}
