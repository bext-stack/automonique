// SPDX-License-Identifier: Elastic-2.0

//! Closed synthetic workloads for build-broker containment tests.

use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::process::{self, Command, Stdio};
use std::thread;
use std::time::Duration;

use nix::sys::resource::{Resource, setrlimit};
use nix::sys::signal::{SigSet, SigmaskHow, Signal, pthread_sigmask};
use nix::unistd::{getpgrp, getppid};

fn main() {
    if let Err(error) = run() {
        eprintln!("fixture-error:{error}");
        process::exit(70);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let recipe = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or("one fixed recipe is required")?;
    if arguments.next().is_some() {
        return Err("unexpected fixture argument".into());
    }

    let cpu = bounded_env("AUTOMONIQUE_CPU_SECONDS")?;
    let file_bytes = bounded_env("AUTOMONIQUE_FILE_BYTES")?;
    let open_files = bounded_env("AUTOMONIQUE_OPEN_FILES")?;
    let wall_ms = bounded_env("AUTOMONIQUE_WALL_MS")?;
    let grace_ms = bounded_env("AUTOMONIQUE_TERM_GRACE_MS")?;
    if env::vars_os().any(|(name, _)| {
        !matches!(
            name.to_str(),
            Some(
                "AUTOMONIQUE_CPU_SECONDS"
                    | "AUTOMONIQUE_FILE_BYTES"
                    | "AUTOMONIQUE_OPEN_FILES"
                    | "AUTOMONIQUE_WALL_MS"
                    | "AUTOMONIQUE_TERM_GRACE_MS"
            )
        )
    }) {
        return Err("fixture environment was not scrubbed".into());
    }
    setrlimit(Resource::RLIMIT_CPU, cpu, cpu.saturating_add(1))?;
    setrlimit(Resource::RLIMIT_FSIZE, file_bytes, file_bytes)?;
    setrlimit(Resource::RLIMIT_NOFILE, open_files, open_files)?;
    let parent = getppid();
    if parent.as_raw() == 1 {
        return Err("fixture was orphaned before parent-death protection".into());
    }
    nix::sys::prctl::set_pdeathsig(Signal::SIGKILL)?;
    if getppid() != parent {
        return Err("fixture parent changed before death signal was armed".into());
    }
    let mut blocked_term = SigSet::empty();
    blocked_term.add(Signal::SIGTERM);
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&blocked_term), None)?;
    let self_deadline = wall_ms
        .checked_add(grace_ms)
        .and_then(|value| value.checked_add(250))
        .ok_or("fixture deadline overflow")?;
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(self_deadline));
        let _ = nix::sys::signal::killpg(getpgrp(), Signal::SIGKILL);
    });
    if recipe != "sleep" {
        pthread_sigmask(SigmaskHow::SIG_UNBLOCK, Some(&blocked_term), None)?;
    }

    match recipe.as_str() {
        "success" => {
            println!("synthetic-build-ok");
            eprintln!("synthetic-build-diagnostic");
        }
        "sleep" => term_resistant_sleep()?,
        "cpu_hog" => cpu_hog(),
        "output_flood" => output_flood()?,
        "disk_flood" => disk_flood()?,
        "pid_burst" => pid_burst()?,
        "descendant" => descendant()?,
        "cpu_worker" => cpu_hog(),
        "descendant_worker" => sleep_forever(),
        "open_files" => open_files_workload(file_bytes),
        _ => return Err("unknown fixed recipe".into()),
    }
    Ok(())
}

fn bounded_env(name: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let value = env::var(name).map_err(|_| "required limit environment is missing")?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("limit environment is not an unsigned integer".into());
    }
    Ok(value.parse()?)
}

fn sleep_forever() -> ! {
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

fn term_resistant_sleep() -> Result<(), Box<dyn std::error::Error>> {
    let mut blocked = SigSet::empty();
    blocked.add(Signal::SIGTERM);
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&blocked), None)?;
    sleep_forever()
}

fn cpu_hog() -> ! {
    let mut value = 1_u64;
    loop {
        value = std::hint::black_box(
            value
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1),
        );
    }
}

fn output_flood() -> io::Result<()> {
    let mut output = io::stdout().lock();
    let block = [b'x'; 8_192];
    loop {
        output.write_all(&block)?;
        output.flush()?;
    }
}

fn disk_flood() -> io::Result<()> {
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open("artifact.bin")?;
    let block = [b'd'; 8_192];
    loop {
        output.write_all(&block)?;
        output.flush()?;
    }
}

fn pid_burst() -> Result<(), Box<dyn std::error::Error>> {
    let executable = env::current_exe()?;
    for _ in 0..3 {
        Command::new(&executable)
            .arg("cpu_worker")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
    }
    cpu_hog()
}

fn descendant() -> Result<(), Box<dyn std::error::Error>> {
    let executable = env::current_exe()?;
    let mut pids = Vec::new();
    for _ in 0..2 {
        pids.push(
            Command::new(&executable)
                .arg("descendant_worker")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?
                .id(),
        );
    }
    println!("descendant-pids:{},{}", pids[0], pids[1]);
    io::stdout().flush()?;
    sleep_forever()
}

fn open_files_workload(bytes_per_file: u64) -> ! {
    let mut files: Vec<File> = Vec::new();
    for index in 0_u64..1_024 {
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(format!("open-{index}"))
        {
            Ok(mut file) => {
                let block = [b'f'; 64];
                let mut remaining = bytes_per_file;
                while remaining != 0 {
                    let write = remaining.min(block.len() as u64) as usize;
                    if file.write_all(&block[..write]).is_err() {
                        process::exit(74);
                    }
                    remaining -= write as u64;
                }
                files.push(file);
            }
            Err(error) if error.raw_os_error() == Some(nix::libc::EMFILE) => process::exit(75),
            Err(_) => process::exit(74),
        }
    }
    process::exit(73)
}
