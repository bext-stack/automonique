// SPDX-License-Identifier: Elastic-2.0

//! Disposable process that enforces a filesystem policy on itself and reports
//! what it can still reach.
//!
//! A Landlock domain is irreversible and inherited by every child, so a policy
//! cannot be exercised inside a test process without poisoning the rest of that
//! binary. This helper exists so the enforcement proofs run in a process whose
//! only job is to die afterwards. It is a test instrument, not product
//! execution authority: it grants nothing on its own and refuses loudly.
//!
//! ```text
//! automonique-landlock-fs-probe
//!     [--layers N] [--extra-thread]
//!     [--grant <read|rw|rx> <path>]...
//!     [--probe <kind> <path>]...
//! ```
//!
//! Exit codes: 0 enforced and probed, 2 usage error, 3 the policy was refused.

use automonique_runner::filesystem::{FilesystemPolicy, PathIntent};
use std::path::{Path, PathBuf};

/// The policy was refused; nothing was proven about reachability.
const EXIT_REFUSED: i32 = 3;
/// The arguments were not a policy this helper knows how to build.
const EXIT_USAGE: i32 = 2;

struct Probe {
    kind: String,
    path: PathBuf,
}

fn main() {
    let mut policy = FilesystemPolicy::deny_all();
    let mut probes: Vec<Probe> = Vec::new();
    let mut layers: u32 = 1;
    let mut extra_thread = false;

    let mut arguments = std::env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.to_str() {
            Some("--grant") => {
                let Some(intent) = arguments.next() else {
                    usage("--grant needs an intent and a path");
                };
                let Some(path) = arguments.next() else {
                    usage("--grant needs an intent and a path");
                };
                let intent = match intent.to_str() {
                    Some("read") => PathIntent::Read,
                    Some("rw") => PathIntent::ReadWrite,
                    Some("rx") => PathIntent::ReadExecute,
                    _ => usage("unknown grant intent"),
                };
                policy = match policy.grant(intent, PathBuf::from(path)) {
                    Ok(updated) => updated,
                    Err(error) => refuse(&error.to_string()),
                };
            }
            Some("--probe") => {
                let Some(kind) = arguments.next() else {
                    usage("--probe needs a kind and a path");
                };
                let Some(path) = arguments.next() else {
                    usage("--probe needs a kind and a path");
                };
                let Some(kind) = kind.to_str() else {
                    usage("probe kind is not UTF-8");
                };
                probes.push(Probe {
                    kind: kind.to_owned(),
                    path: PathBuf::from(path),
                });
            }
            Some("--layers") => {
                let Some(value) = arguments.next().and_then(|value| {
                    value
                        .to_str()
                        .and_then(|value| value.parse::<u32>().ok())
                        .filter(|value| *value >= 1)
                }) else {
                    usage("--layers needs a positive count");
                };
                layers = value;
            }
            Some("--extra-thread") => extra_thread = true,
            _ => usage("unknown argument"),
        }
    }

    if extra_thread {
        // Kept alive well past the enforcement attempt, so the process really
        // is multi-threaded at the moment the policy is applied.
        std::thread::spawn(|| std::thread::sleep(std::time::Duration::from_secs(120)));
    }

    let mut isolation = None;
    for _ in 0..layers {
        match policy.enforce_on_current_thread() {
            Ok(applied) => isolation = Some(applied),
            Err(error) => refuse(&error.to_string()),
        }
    }
    let Some(isolation) = isolation else {
        usage("no enforcement was attempted");
    };

    println!("kernel_abi={}", isolation.kernel_abi());
    println!("policy_abi={}", isolation.policy_abi());
    match isolation.kernel_abi_beyond_crate() {
        Some(abi) => println!("beyond_crate={abi}"),
        None => println!("beyond_crate=none"),
    }
    println!("layers={layers}");
    // Echo the allowlist that is actually in force, so a probe result is read
    // against the policy the kernel got rather than the one the caller meant.
    for grant in policy.grants() {
        println!(
            "grant {} {}",
            grant.intent().as_str(),
            grant.path().display()
        );
    }
    for probe in &probes {
        println!(
            "probe {} {} = {}",
            probe.kind,
            probe.path.display(),
            run_probe(&probe.kind, &probe.path)
        );
    }
}

fn run_probe(kind: &str, path: &Path) -> String {
    match kind {
        "read-file" => report(std::fs::read(path).map(|_| ())),
        "list-dir" => report(std::fs::read_dir(path).map(|entries| {
            for entry in entries {
                drop(entry);
            }
        })),
        "write-file" => report(
            std::fs::OpenOptions::new()
                .write(true)
                .open(path)
                .and_then(|mut file| std::io::Write::write_all(&mut file, b"probe")),
        ),
        "create-file" => report(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map(|_| ()),
        ),
        "truncate" => match nix::unistd::truncate(path, 0) {
            Ok(()) => "ALLOWED".to_owned(),
            Err(errno) => format!("DENIED {errno:?}"),
        },
        "exec" => match std::process::Command::new(path).status() {
            Ok(status) if status.success() => "ALLOWED".to_owned(),
            Ok(status) => format!("DENIED nonzero {status}"),
            Err(error) => format!("DENIED {:?}", error.kind()),
        },
        _ => usage("unknown probe kind"),
    }
}

fn report(outcome: std::io::Result<()>) -> String {
    match outcome {
        Ok(()) => "ALLOWED".to_owned(),
        Err(error) => format!("DENIED {:?}", error.kind()),
    }
}

fn refuse(message: &str) -> ! {
    println!("refused={message}");
    std::process::exit(EXIT_REFUSED)
}

fn usage(message: &str) -> ! {
    eprintln!("usage error: {message}");
    std::process::exit(EXIT_USAGE)
}
