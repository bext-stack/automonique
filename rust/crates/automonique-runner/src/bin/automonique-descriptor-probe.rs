// SPDX-License-Identifier: Elastic-2.0

//! Test fixture for descriptor closure. Not a product entry point.
//!
//! This binary exists because the property under test — that a descriptor
//! inherited across `fork`/`exec` is gone — is only observable from inside the
//! child that inherited it. It reports what it saw through a file it opens
//! *after* closure, so that a run which closes the standard streams can still
//! be observed. Nothing here grants execution authority: it closes its own
//! descriptors, reports, and exits without executing a workload.
//!
//! Usage:
//! `automonique-descriptor-probe --automonique-descriptor-probe-v1 <mode>
//! <result-path> <allowlist-csv> <marker-fd>`
//!
//! `<allowlist-csv>` is `-` for the empty allowlist. `<marker-fd>` is `-1`
//! unless the mode uses it. Modes are `close`, `retain` and `residual`.

use automonique_runner::descriptors::{
    DescriptorAllowlist, DescriptorError, close_all_except, open_descriptors,
    verify_only_allowlist_open,
};
use std::fmt::Write as _;
use std::os::fd::{AsRawFd as _, RawFd};

/// Refusal before any descriptor work, matching the crate's fixture helpers.
const REFUSED_EXIT: u8 = 64;
/// The descriptor work ran but its report could not be delivered.
const UNREPORTED_EXIT: u8 = 70;

fn main() -> std::process::ExitCode {
    let refused = std::process::ExitCode::from(REFUSED_EXIT);
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if arguments.len() != 6 || arguments[1] != "--automonique-descriptor-probe-v1" {
        return refused;
    }
    let Some(mode) = arguments[2].to_str() else {
        return refused;
    };
    let result_path = std::path::PathBuf::from(&arguments[3]);
    let Some(allowlist) = arguments[4].to_str().and_then(parse_allowlist) else {
        return refused;
    };
    let Some(marker_fd) = arguments[5]
        .to_str()
        .and_then(|raw| raw.parse::<RawFd>().ok())
    else {
        return refused;
    };

    let report = match mode {
        "close" => report_closure(&allowlist, None),
        "retain" => report_closure(&allowlist, Some(marker_fd)),
        "residual" => report_residual(&allowlist),
        _ => return refused,
    };

    // The report is opened only now: every descriptor it needed is already
    // accounted for, and this open is the first one after closure.
    match std::fs::write(&result_path, report) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => std::process::ExitCode::from(UNREPORTED_EXIT),
    }
}

fn report_closure(allowlist: &DescriptorAllowlist, marker_fd: Option<RawFd>) -> String {
    let mut report = String::new();
    let before = open_descriptors();
    let _ = writeln!(report, "before={}", render(&before));
    match close_all_except(allowlist) {
        Ok(closure) => {
            let _ = writeln!(report, "closed={}", csv(closure.closed()));
            let _ = writeln!(report, "retained={}", csv(closure.retained()));
            let _ = writeln!(report, "outcome=ok");
        }
        Err(error) => {
            let _ = writeln!(report, "closed=");
            let _ = writeln!(report, "retained=");
            let _ = writeln!(report, "outcome=refused:{error}");
        }
    }
    // Reported whatever the outcome, so a caller can see what a refusal did to
    // the descriptor table rather than take its word that it did nothing.
    let _ = writeln!(report, "after={}", render(&open_descriptors()));
    if let Some(fd) = marker_fd {
        // Reading proves the retained descriptor is still the working
        // descriptor it was, not merely a number that survived a listing.
        let mut buffer = [0u8; 64];
        match nix::unistd::read(fd, &mut buffer) {
            Ok(count) => {
                let _ = writeln!(
                    report,
                    "marker={}",
                    String::from_utf8_lossy(&buffer[..count])
                );
            }
            Err(errno) => {
                let _ = writeln!(report, "marker=refused:{errno}");
            }
        }
    }
    report
}

fn report_residual(allowlist: &DescriptorAllowlist) -> String {
    let mut report = String::new();
    match close_all_except(allowlist) {
        Ok(_) => {
            let _ = writeln!(report, "outcome=ok");
        }
        Err(error) => {
            let _ = writeln!(report, "outcome=refused:{error}");
            return report;
        }
    }
    // Open one descriptor that no allowlist named, then ask verification about
    // a state it did not itself produce.
    match std::fs::File::open("/dev/null") {
        Ok(opened) => {
            let _ = writeln!(report, "probe_fd={}", opened.as_raw_fd());
            let _ = writeln!(
                report,
                "verify={}",
                match verify_only_allowlist_open(allowlist) {
                    Ok(()) => "ok".to_owned(),
                    Err(DescriptorError::ResidualDescriptor(fd)) => format!("residual:{fd}"),
                    Err(error) => format!("refused:{error}"),
                }
            );
            drop(opened);
        }
        Err(error) => {
            let _ = writeln!(report, "probe_fd=refused:{error}");
        }
    }
    report
}

fn parse_allowlist(raw: &str) -> Option<DescriptorAllowlist> {
    if raw == "-" {
        return Some(DescriptorAllowlist::none());
    }
    let fds = raw
        .split(',')
        .map(|field| field.parse::<RawFd>().ok())
        .collect::<Option<Vec<RawFd>>>()?;
    DescriptorAllowlist::new(&fds).ok()
}

fn render(observed: &Result<Vec<RawFd>, DescriptorError>) -> String {
    match observed {
        Ok(fds) => csv(fds),
        Err(error) => format!("refused:{error}"),
    }
}

fn csv(fds: &[RawFd]) -> String {
    fds.iter()
        .map(RawFd::to_string)
        .collect::<Vec<String>>()
        .join(",")
}
