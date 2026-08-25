// SPDX-License-Identifier: Elastic-2.0

//! Command-line front for the spike.
//!
//! ```text
//! automonique-tempfs-quota serve <mountpoint> <byte-ceiling> <object-ceiling>
//! automonique-tempfs-quota inspect <mountpoint>
//! automonique-tempfs-quota detach <mountpoint>
//! automonique-tempfs-quota probe-auto-unmount <mountpoint>
//! ```
//!
//! `serve` mounts, prints the kernel's readback, then serves until it receives
//! `SIGTERM`, `SIGINT` or `SIGHUP`, or until someone else unmounts it. Either
//! way it prints the typed outcome before exiting. `inspect` classifies what
//! is at a path; `detach` lazily removes a mount this crate left behind;
//! `probe-auto-unmount` measures whether `auto_unmount` cleans up a same-uid
//! mount on this host once its owner is gone.

use automonique_tempfs_quota_spike::{
    Ceilings, FS_SUBTYPE, FusePrerequisites, MountedTempfs, detach_stale, inspect,
    probe_auto_unmount,
};
use nix::sys::signal::{SigSet, Signal};
use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

const POLL_INTERVAL: Duration = Duration::from_millis(50);

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().collect();
    let result = match arguments.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        [_, "serve", mountpoint, bytes, objects] => serve(mountpoint, bytes, objects),
        [_, "inspect", mountpoint] => inspect_command(mountpoint),
        [_, "detach", mountpoint] => detach(mountpoint),
        [_, "probe-auto-unmount", mountpoint] => probe(mountpoint),
        _ => Err("usage: serve <mountpoint> <bytes> <objects> | inspect <mountpoint> | detach <mountpoint> | probe-auto-unmount <mountpoint>".to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("automonique-tempfs-quota: {message}");
            ExitCode::FAILURE
        }
    }
}

fn serve(mountpoint: &str, bytes: &str, objects: &str) -> Result<(), String> {
    let bytes: u64 = bytes
        .parse()
        .map_err(|_| "byte ceiling must be an integer")?;
    let objects: u64 = objects
        .parse()
        .map_err(|_| "object ceiling must be an integer")?;
    let ceilings = Ceilings::new(bytes, objects).map_err(|error| error.to_string())?;

    // Block the termination signals before any other thread exists, so the
    // server thread inherits the mask and exactly one thread — the waiter
    // below — ever receives them.
    let mut signals = SigSet::empty();
    signals.add(Signal::SIGTERM);
    signals.add(Signal::SIGINT);
    signals.add(Signal::SIGHUP);
    signals
        .thread_block()
        .map_err(|error| format!("cannot block signals: {error}"))?;

    let verified = FusePrerequisites::host_default()
        .verify()
        .map_err(|error| format!("prerequisite: {error}"))?;
    let mounted = MountedTempfs::mount(&verified, Path::new(mountpoint), ceilings)
        .map_err(|error| format!("mount: {error}"))?;

    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "mounted={}", mounted.mountpoint().display());
    let _ = writeln!(stdout, "mount.evidence={}", mounted.evidence());
    let _ = writeln!(stdout, "statfs.at_mount={}", mounted.statfs_at_mount());
    let _ = writeln!(stdout, "ready=yes");
    let _ = stdout.flush();
    drop(stdout);

    let stop = Arc::new(AtomicBool::new(false));
    let waiter_flag = Arc::clone(&stop);
    thread::spawn(move || {
        let _ = signals.wait();
        waiter_flag.store(true, Ordering::Release);
    });
    while !stop.load(Ordering::Acquire) && mounted.serving() {
        thread::sleep(POLL_INTERVAL);
    }

    let outcome = mounted
        .unmount()
        .map_err(|error| format!("unmount: {error}"))?;
    print!("{outcome}");
    Ok(())
}

fn inspect_command(mountpoint: &str) -> Result<(), String> {
    let status = inspect(Path::new(mountpoint), FS_SUBTYPE).map_err(|error| error.to_string())?;
    println!("{status}");
    Ok(())
}

fn detach(mountpoint: &str) -> Result<(), String> {
    let verified = FusePrerequisites::host_default()
        .verify()
        .map_err(|error| format!("prerequisite: {error}"))?;
    let status =
        detach_stale(&verified, Path::new(mountpoint)).map_err(|error| error.to_string())?;
    println!("{status}");
    Ok(())
}

fn probe(mountpoint: &str) -> Result<(), String> {
    let verified = FusePrerequisites::host_default()
        .verify()
        .map_err(|error| format!("prerequisite: {error}"))?;
    let probe = probe_auto_unmount(&verified, Path::new(mountpoint))
        .map_err(|error| format!("probe: {error}"))?;
    println!("{probe}");
    Ok(())
}
