// SPDX-License-Identifier: Elastic-2.0

//! Bounded, read-only inspection of a caller-selected release manifest.

use nix::errno::Errno;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::stat::{Mode, fstat};
use nix::unistd::{Uid, close, read};
use serde_json::{Map, Value};
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

pub const MAX_RELEASE_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_PATH_COMPONENTS: usize = 256;
const MAX_PUBLIC_VALUE_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseInspectionStatus {
    Structured,
    Finding,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseIssue {
    PathInvalid,
    Missing,
    MetadataUnavailable,
    SymlinkForbidden,
    NotRegular,
    WrongOwner,
    PermissiveMode,
    TooLarge,
    OpenUnavailable,
    ReadUnavailable,
    ChangedDuringRead,
    MalformedJson,
    NonObjectJson,
    RequiredFieldMissing,
    RequiredFieldInvalid,
}

impl ReleaseIssue {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PathInvalid => "release.path-invalid",
            Self::Missing => "release.missing",
            Self::MetadataUnavailable => "release.metadata-unavailable",
            Self::SymlinkForbidden => "release.symlink-forbidden",
            Self::NotRegular => "release.not-regular",
            Self::WrongOwner => "release.wrong-owner",
            Self::PermissiveMode => "release.permissive-mode",
            Self::TooLarge => "release.too-large",
            Self::OpenUnavailable => "release.open-unavailable",
            Self::ReadUnavailable => "release.read-unavailable",
            Self::ChangedDuringRead => "release.changed-during-read",
            Self::MalformedJson => "release.malformed-json",
            Self::NonObjectJson => "release.non-object-json",
            Self::RequiredFieldMissing => "release.required-field-missing",
            Self::RequiredFieldInvalid => "release.required-field-invalid",
        }
    }

    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::PathInvalid => "Release manifest path is invalid",
            Self::Missing => "Release manifest is unavailable",
            Self::MetadataUnavailable => "Release manifest metadata is unavailable",
            Self::SymlinkForbidden => "Release manifest path contains a symbolic link",
            Self::NotRegular => "Release manifest is not a regular file",
            Self::WrongOwner => "Release manifest has the wrong owner",
            Self::PermissiveMode => "Release manifest permissions are not private",
            Self::TooLarge => "Release manifest exceeds the size limit",
            Self::OpenUnavailable => "Release manifest could not be opened safely",
            Self::ReadUnavailable => "Release manifest could not be read safely",
            Self::ChangedDuringRead => "Release manifest changed during inspection",
            Self::MalformedJson => "Release manifest is not valid JSON",
            Self::NonObjectJson => "Release manifest is not a JSON object",
            Self::RequiredFieldMissing => "Release manifest is missing a required field",
            Self::RequiredFieldInvalid => "Release manifest has an invalid required field",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionRange {
    pub minimum: u64,
    pub maximum: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseManifest {
    pub application_version: String,
    pub git_revision: String,
    pub build_target: String,
    pub protocol_range: VersionRange,
    pub database_schema_range: VersionRange,
    pub minimum_kernel: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseInspection {
    Structured(ReleaseManifest),
    Finding(ReleaseIssue),
    Unavailable(ReleaseIssue),
}

impl ReleaseInspection {
    #[must_use]
    pub const fn status(&self) -> ReleaseInspectionStatus {
        match self {
            Self::Structured(_) => ReleaseInspectionStatus::Structured,
            Self::Finding(_) => ReleaseInspectionStatus::Finding,
            Self::Unavailable(_) => ReleaseInspectionStatus::Unavailable,
        }
    }

    #[must_use]
    pub const fn issue(&self) -> Option<ReleaseIssue> {
        match self {
            Self::Structured(_) => None,
            Self::Finding(issue) | Self::Unavailable(issue) => Some(*issue),
        }
    }
}

/// Inspect an explicit manifest's bounded structure without claiming compatibility.
#[must_use]
pub fn inspect_release_manifest_structure(path: &Path) -> ReleaseInspection {
    let before = match inspect_metadata(path) {
        Ok(metadata) => metadata,
        Err(outcome) => return outcome.into_inspection(),
    };
    if !before.is_file() {
        return ReleaseInspection::Finding(ReleaseIssue::NotRegular);
    }
    if before.uid() != Uid::effective().as_raw() {
        return ReleaseInspection::Finding(ReleaseIssue::WrongOwner);
    }
    if before.mode() & 0o077 != 0 {
        return ReleaseInspection::Finding(ReleaseIssue::PermissiveMode);
    }
    if before.len() > MAX_RELEASE_MANIFEST_BYTES as u64 {
        return ReleaseInspection::Finding(ReleaseIssue::TooLarge);
    }

    let descriptor = match open_without_links(path) {
        Ok(descriptor) => descriptor,
        Err(Errno::ELOOP) => {
            return ReleaseInspection::Finding(ReleaseIssue::SymlinkForbidden);
        }
        Err(Errno::ENOENT) => return ReleaseInspection::Unavailable(ReleaseIssue::Missing),
        Err(_) => return ReleaseInspection::Unavailable(ReleaseIssue::OpenUnavailable),
    };
    let opened = match fstat(descriptor.raw()) {
        Ok(stat) => stat,
        Err(_) => return ReleaseInspection::Unavailable(ReleaseIssue::MetadataUnavailable),
    };
    if opened.st_dev != before.dev()
        || opened.st_ino != before.ino()
        || opened.st_uid != before.uid()
        || opened.st_mode != before.mode()
        || opened.st_size != before.len() as i64
    {
        return ReleaseInspection::Unavailable(ReleaseIssue::ChangedDuringRead);
    }

    let bytes = match read_bounded(descriptor.raw()) {
        Ok(bytes) => bytes,
        Err(issue) => return ReleaseInspection::Unavailable(issue),
    };
    let after = match inspect_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return ReleaseInspection::Unavailable(ReleaseIssue::ChangedDuringRead),
    };
    if !same_snapshot(&before, &after) {
        return ReleaseInspection::Unavailable(ReleaseIssue::ChangedDuringRead);
    }

    parse_manifest(&bytes)
}

#[derive(Clone, Copy)]
enum MetadataOutcome {
    Finding(ReleaseIssue),
    Unavailable(ReleaseIssue),
}

impl MetadataOutcome {
    const fn into_inspection(self) -> ReleaseInspection {
        match self {
            Self::Finding(issue) => ReleaseInspection::Finding(issue),
            Self::Unavailable(issue) => ReleaseInspection::Unavailable(issue),
        }
    }
}

fn inspect_metadata(path: &Path) -> Result<std::fs::Metadata, MetadataOutcome> {
    if !path.is_absolute()
        || path.as_os_str().as_bytes().len() > MAX_PATH_BYTES
        || path == Path::new("/")
    {
        return Err(MetadataOutcome::Finding(ReleaseIssue::PathInvalid));
    }

    let mut current = PathBuf::new();
    let mut components = 0usize;
    let mut final_metadata = None;
    for component in path.components() {
        match component {
            Component::RootDir | Component::Normal(_) => {}
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(MetadataOutcome::Finding(ReleaseIssue::PathInvalid));
            }
        }
        components += 1;
        if components > MAX_PATH_COMPONENTS {
            return Err(MetadataOutcome::Finding(ReleaseIssue::PathInvalid));
        }
        current.push(component.as_os_str());
        let metadata = match std::fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(MetadataOutcome::Unavailable(ReleaseIssue::Missing));
            }
            Err(_) => {
                return Err(MetadataOutcome::Unavailable(
                    ReleaseIssue::MetadataUnavailable,
                ));
            }
        };
        if metadata.file_type().is_symlink() {
            return Err(MetadataOutcome::Finding(ReleaseIssue::SymlinkForbidden));
        }
        final_metadata = Some(metadata);
    }
    final_metadata.ok_or(MetadataOutcome::Finding(ReleaseIssue::PathInvalid))
}

fn open_without_links(path: &Path) -> Result<Descriptor, Errno> {
    let flags = OFlag::O_RDONLY
        | OFlag::O_CLOEXEC
        | OFlag::O_NONBLOCK
        | OFlag::O_NOFOLLOW
        | OFlag::O_NOATIME;
    let how = OpenHow::new()
        .flags(flags)
        .mode(Mode::empty())
        .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS);
    openat2(nix::libc::AT_FDCWD, path, how).map(Descriptor)
}

fn read_bounded(descriptor: RawFd) -> Result<Vec<u8>, ReleaseIssue> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = read(descriptor, &mut buffer).map_err(|_| ReleaseIssue::ReadUnavailable)?;
        if count == 0 {
            return Ok(bytes);
        }
        if bytes.len().saturating_add(count) > MAX_RELEASE_MANIFEST_BYTES {
            return Err(ReleaseIssue::TooLarge);
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
}

fn same_snapshot(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.uid() == after.uid()
        && before.mode() == after.mode()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
}

fn parse_manifest(bytes: &[u8]) -> ReleaseInspection {
    let document: Value = match serde_json::from_slice(bytes) {
        Ok(document) => document,
        Err(_) => return ReleaseInspection::Finding(ReleaseIssue::MalformedJson),
    };
    let Value::Object(object) = document else {
        return ReleaseInspection::Finding(ReleaseIssue::NonObjectJson);
    };
    match manifest_from_object(&object) {
        Ok(manifest) => ReleaseInspection::Structured(manifest),
        Err(issue) => ReleaseInspection::Finding(issue),
    }
}

fn manifest_from_object(object: &Map<String, Value>) -> Result<ReleaseManifest, ReleaseIssue> {
    Ok(ReleaseManifest {
        application_version: required_token(object, "application_version")?,
        git_revision: required_revision(object)?,
        build_target: required_token(object, "build_target")?,
        protocol_range: required_range(object, "protocol_range")?,
        database_schema_range: required_range(object, "database_schema_range")?,
        minimum_kernel: required_token(object, "minimum_kernel")?,
    })
}

fn required_token(object: &Map<String, Value>, name: &str) -> Result<String, ReleaseIssue> {
    let value = object
        .get(name)
        .ok_or(ReleaseIssue::RequiredFieldMissing)?
        .as_str()
        .ok_or(ReleaseIssue::RequiredFieldInvalid)?;
    if value.is_empty()
        || value.len() > MAX_PUBLIC_VALUE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
    {
        return Err(ReleaseIssue::RequiredFieldInvalid);
    }
    Ok(value.to_owned())
}

fn required_revision(object: &Map<String, Value>) -> Result<String, ReleaseIssue> {
    let revision = required_token(object, "git_revision")?;
    if !matches!(revision.len(), 40 | 64)
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ReleaseIssue::RequiredFieldInvalid);
    }
    Ok(revision)
}

fn required_range(object: &Map<String, Value>, name: &str) -> Result<VersionRange, ReleaseIssue> {
    let range = object
        .get(name)
        .ok_or(ReleaseIssue::RequiredFieldMissing)?
        .as_object()
        .ok_or(ReleaseIssue::RequiredFieldInvalid)?;
    let minimum = range
        .get("minimum")
        .and_then(Value::as_u64)
        .ok_or(ReleaseIssue::RequiredFieldInvalid)?;
    let maximum = range
        .get("maximum")
        .and_then(Value::as_u64)
        .ok_or(ReleaseIssue::RequiredFieldInvalid)?;
    if minimum > maximum {
        return Err(ReleaseIssue::RequiredFieldInvalid);
    }
    Ok(VersionRange { minimum, maximum })
}

struct Descriptor(RawFd);

impl Descriptor {
    const fn raw(&self) -> RawFd {
        self.0
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        let _ = close(self.0);
    }
}
