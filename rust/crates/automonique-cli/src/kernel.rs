// SPDX-License-Identifier: Elastic-2.0

//! Bounded, read-only Linux host-setting inspection.

use automonique_protocol::{CheckStatus, DoctorCheck, DoctorReason, FindingCode, FindingMessage};
use nix::errno::Errno;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::stat::{Mode, SFlag, fstat};
use nix::unistd::{close, read};
use std::path::Path;

const CGROUP_CONTROLLERS_LIMIT: usize = 4_096;
const USER_NAMESPACES_LIMIT: usize = 32;
const REQUIRED_CONTROLLERS: [&str; 4] = ["cpu", "io", "memory", "pids"];

/// Inspect a caller-selected cgroup-v2 controller file without following links.
#[must_use]
pub fn inspect_cgroup_v2_controllers(path: &Path) -> DoctorCheck {
    let bytes = match read_bounded_regular(path, CGROUP_CONTROLLERS_LIMIT) {
        Ok(bytes) => bytes,
        Err(ReadFailure::Missing) => {
            return non_healthy(
                "kernel.cgroup-v2.controllers",
                CheckStatus::Finding,
                "kernel.cgroup-v2.controllers-missing",
                "The cgroup v2 controller list is absent",
            );
        }
        Err(ReadFailure::Unavailable) => {
            return non_healthy(
                "kernel.cgroup-v2.controllers",
                CheckStatus::Unavailable,
                "kernel.cgroup-v2.controllers-unavailable",
                "The cgroup v2 controller list could not be read safely",
            );
        }
    };
    let Some(controllers) = parse_controllers(&bytes) else {
        return non_healthy(
            "kernel.cgroup-v2.controllers",
            CheckStatus::Unavailable,
            "kernel.cgroup-v2.controllers-malformed",
            "The cgroup v2 controller list is malformed",
        );
    };
    if REQUIRED_CONTROLLERS
        .iter()
        .all(|required| controllers.contains(required))
    {
        healthy("kernel.cgroup-v2.controllers")
    } else {
        non_healthy(
            "kernel.cgroup-v2.controllers",
            CheckStatus::Finding,
            "kernel.cgroup-v2.controllers-incomplete",
            "Required cgroup v2 controllers are absent",
        )
    }
}

/// Inspect a caller-selected `max_user_namespaces` file without following links.
#[must_use]
pub fn inspect_max_user_namespaces(path: &Path) -> DoctorCheck {
    let bytes = match read_bounded_regular(path, USER_NAMESPACES_LIMIT) {
        Ok(bytes) => bytes,
        Err(ReadFailure::Missing | ReadFailure::Unavailable) => {
            return non_healthy(
                "kernel.max-user-namespaces-setting",
                CheckStatus::Unavailable,
                "kernel.max-user-namespaces-setting-unavailable",
                "The maximum user namespace host setting could not be read safely",
            );
        }
    };
    let Some(value) = parse_unsigned(&bytes) else {
        return non_healthy(
            "kernel.max-user-namespaces-setting",
            CheckStatus::Unavailable,
            "kernel.max-user-namespaces-setting-malformed",
            "The maximum user namespace host setting is malformed",
        );
    };
    if value == 0 {
        non_healthy(
            "kernel.max-user-namespaces-setting",
            CheckStatus::Finding,
            "kernel.max-user-namespaces-setting-zero",
            "The configured maximum user namespace count is zero",
        )
    } else {
        healthy("kernel.max-user-namespaces-setting")
    }
}

fn parse_controllers(bytes: &[u8]) -> Option<Vec<&str>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut controllers = Vec::new();
    for token in text.split_ascii_whitespace() {
        if token.is_empty()
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            || controllers.contains(&token)
        {
            return None;
        }
        controllers.push(token);
    }
    Some(controllers)
}

fn parse_unsigned(bytes: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(bytes).ok()?.trim_ascii();
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

#[derive(Clone, Copy)]
enum ReadFailure {
    Missing,
    Unavailable,
}

fn read_bounded_regular(path: &Path, limit: usize) -> Result<Vec<u8>, ReadFailure> {
    let how = OpenHow::new()
        .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NOATIME)
        .mode(Mode::empty())
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS);
    let descriptor = openat2(nix::libc::AT_FDCWD, path, how).map_err(|error| {
        if error == Errno::ENOENT {
            ReadFailure::Missing
        } else {
            ReadFailure::Unavailable
        }
    })?;
    let result = read_open_descriptor(descriptor, limit);
    let close_result = close(descriptor);
    match (result, close_result) {
        (Ok(bytes), Ok(())) => Ok(bytes),
        (Err(error), _) => Err(error),
        (Ok(_), Err(_)) => Err(ReadFailure::Unavailable),
    }
}

fn read_open_descriptor(descriptor: i32, limit: usize) -> Result<Vec<u8>, ReadFailure> {
    let metadata = fstat(descriptor).map_err(|_| ReadFailure::Unavailable)?;
    if !SFlag::from_bits_truncate(metadata.st_mode).contains(SFlag::S_IFREG) {
        return Err(ReadFailure::Unavailable);
    }
    let mut bytes = vec![0; limit + 1];
    let mut length = 0usize;
    loop {
        match read(descriptor, &mut bytes[length..]) {
            Ok(0) => {
                bytes.truncate(length);
                return Ok(bytes);
            }
            Ok(count) => {
                length += count;
                if length > limit {
                    return Err(ReadFailure::Unavailable);
                }
            }
            Err(Errno::EINTR) => {}
            Err(_) => return Err(ReadFailure::Unavailable),
        }
    }
}

fn healthy(code: &str) -> DoctorCheck {
    DoctorCheck::new(
        FindingCode::new(code).expect("constant check code is valid"),
        CheckStatus::Healthy,
        None,
    )
    .expect("constant healthy check is coherent")
}

fn non_healthy(
    check_code: &str,
    status: CheckStatus,
    reason_code: &str,
    message: &str,
) -> DoctorCheck {
    DoctorCheck::new(
        FindingCode::new(check_code).expect("constant check code is valid"),
        status,
        Some(DoctorReason::new(
            FindingCode::new(reason_code).expect("constant reason code is valid"),
            FindingMessage::new(message).expect("constant reason message is valid"),
        )),
    )
    .expect("constant non-healthy check is coherent")
}
