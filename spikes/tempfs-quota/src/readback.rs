// SPDX-License-Identifier: Elastic-2.0

//! What the kernel says about a mountpoint.
//!
//! Every claim the spike makes about a mount — that it exists, that it is a
//! FUSE mount of this crate's subtype owned by this uid, that it reports the
//! ceilings, that it is gone after unmount — is answered from here, by
//! reading `/proc/self/mountinfo` and calling `statvfs(2)`. The mount
//! request itself proves nothing; only the readback does.

use nix::errno::Errno;
use nix::sys::statvfs::statvfs;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Path, PathBuf};

/// The mount table this process sees.
pub const MOUNTINFO: &str = "/proc/self/mountinfo";

/// One `mountinfo` line's identity fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountEvidence {
    pub mountpoint: PathBuf,
    /// `fuse.<subtype>` for a FUSE mount that named a subtype.
    pub fstype: String,
    /// The `fsname=` the mount was created with.
    pub source: String,
    /// Per-mount options (`rw,nosuid,nodev,noexec,relatime`).
    pub mount_options: String,
    /// Superblock options, where FUSE records `user_id=` and `group_id=`.
    pub super_options: String,
}

impl MountEvidence {
    /// The uid the kernel recorded as the mount's owner, from `user_id=`.
    #[must_use]
    pub fn user_id(&self) -> Option<u32> {
        self.super_options
            .split(',')
            .find_map(|option| option.strip_prefix("user_id="))
            .and_then(|value| value.parse().ok())
    }

    /// Whether this is a FUSE mount carrying `subtype`.
    #[must_use]
    pub fn is_fuse_subtype(&self, subtype: &str) -> bool {
        self.fstype
            .strip_prefix("fuse.")
            .is_some_and(|actual| actual == subtype)
    }
}

impl fmt::Display for MountEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "fstype={} source={} options={} super_options={}",
            self.fstype, self.source, self.mount_options, self.super_options
        )
    }
}

/// Parse the mount table, tolerating lines this crate does not understand.
#[must_use]
pub fn parse_mountinfo(text: &str) -> Vec<MountEvidence> {
    text.lines().filter_map(parse_line).collect()
}

fn parse_line(line: &str) -> Option<MountEvidence> {
    // `ID PARENT MAJ:MIN ROOT MOUNTPOINT OPTIONS [optional...] - FSTYPE SOURCE SUPEROPTS`
    let (before, after) = line.split_once(" - ")?;
    let mut before = before.split(' ');
    let mountpoint = before.nth(4)?;
    let mount_options = before.next()?;
    let mut after = after.split(' ');
    let fstype = after.next()?;
    let source = after.next()?;
    let super_options = after.next()?;
    Some(MountEvidence {
        mountpoint: PathBuf::from(unescape(mountpoint)),
        fstype: fstype.to_owned(),
        source: unescape(source).into_string().unwrap_or_default(),
        mount_options: mount_options.to_owned(),
        super_options: super_options.to_owned(),
    })
}

/// Undo `mountinfo`'s octal escaping of space, tab, newline and backslash.
fn unescape(field: &str) -> OsString {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 < bytes.len() {
            let digits = &bytes[index + 1..index + 4];
            if digits.iter().all(|digit| (b'0'..=b'7').contains(digit)) {
                let value = digits
                    .iter()
                    .fold(0_u32, |acc, digit| acc * 8 + u32::from(digit - b'0'));
                if let Ok(byte) = u8::try_from(value) {
                    out.push(byte);
                    index += 4;
                    continue;
                }
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    OsString::from_vec(out)
}

/// The topmost mount at exactly `mountpoint`, if any.
pub fn mount_evidence(mountpoint: &Path) -> io::Result<Option<MountEvidence>> {
    let text = fs::read_to_string(MOUNTINFO)?;
    Ok(parse_mountinfo(&text)
        .into_iter()
        .rfind(|entry| entry.mountpoint == mountpoint))
}

/// `statvfs(2)` as the kernel answered it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatfsReadback {
    pub block_size: u64,
    pub fragment_size: u64,
    pub blocks: u64,
    pub blocks_free: u64,
    pub blocks_available: u64,
    pub files: u64,
    pub files_free: u64,
    pub name_max: u64,
}

impl StatfsReadback {
    /// Total capacity in bytes: for this filesystem, the byte ceiling.
    #[must_use]
    pub const fn ceiling_bytes(&self) -> u64 {
        self.blocks * self.fragment_size
    }

    /// Bytes in use, at block granularity.
    #[must_use]
    pub const fn used_bytes(&self) -> u64 {
        (self.blocks - self.blocks_free) * self.fragment_size
    }

    /// Objects in use.
    #[must_use]
    pub const fn used_objects(&self) -> u64 {
        self.files - self.files_free
    }
}

impl fmt::Display for StatfsReadback {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "bsize={} frsize={} blocks={} bfree={} bavail={} files={} ffree={} namelen={}",
            self.block_size,
            self.fragment_size,
            self.blocks,
            self.blocks_free,
            self.blocks_available,
            self.files,
            self.files_free,
            self.name_max
        )
    }
}

/// Ask the kernel for the filesystem statistics at `mountpoint`.
pub fn statfs_readback(mountpoint: &Path) -> Result<StatfsReadback, Errno> {
    let stat = statvfs(mountpoint)?;
    Ok(StatfsReadback {
        block_size: stat.block_size(),
        fragment_size: stat.fragment_size(),
        blocks: stat.blocks(),
        blocks_free: stat.blocks_free(),
        blocks_available: stat.blocks_available(),
        files: stat.files(),
        files_free: stat.files_free(),
        name_max: stat.name_max(),
    })
}

/// What is at a mountpoint right now.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MountStatus {
    /// No mount at the path.
    NotMounted,
    /// A FUSE mount of the expected subtype whose server answers `statfs`.
    Live {
        evidence: MountEvidence,
        statfs: StatfsReadback,
    },
    /// A FUSE mount of the expected subtype whose server is gone: the kernel
    /// answers `ENOTCONN` for it. This is the stale mount a crashed
    /// supervisor leaves behind.
    Disconnected {
        evidence: MountEvidence,
        errno: Errno,
    },
    /// Something other than this crate's filesystem is mounted here.
    Foreign { evidence: MountEvidence },
}

impl fmt::Display for MountStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotMounted => formatter.write_str("status=not-mounted"),
            Self::Live { evidence, statfs } => {
                write!(formatter, "status=live {evidence} statfs: {statfs}")
            }
            Self::Disconnected { evidence, errno } => write!(
                formatter,
                "status=disconnected errno={errno:?}({}) {evidence}",
                *errno as i32
            ),
            Self::Foreign { evidence } => write!(formatter, "status=foreign {evidence}"),
        }
    }
}

/// Classify the mount at `mountpoint` against this crate's `subtype`.
pub fn inspect(mountpoint: &Path, subtype: &str) -> io::Result<MountStatus> {
    let Some(evidence) = mount_evidence(mountpoint)? else {
        return Ok(MountStatus::NotMounted);
    };
    if !evidence.is_fuse_subtype(subtype) {
        return Ok(MountStatus::Foreign { evidence });
    }
    match statfs_readback(mountpoint) {
        Ok(statfs) => Ok(MountStatus::Live { evidence, statfs }),
        Err(errno) => Ok(MountStatus::Disconnected { evidence, errno }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mountinfo_lines_parse_including_escapes_and_optional_fields() {
        let text = "36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue\n\
                    1213 33 0:87 / /tmp/with\\040space rw,nosuid,nodev,noexec,relatime - \
                    fuse.tempfs-quota automonique-tempfs rw,user_id=1000,group_id=1000,default_permissions\n\
                    garbage line\n";
        let parsed = parse_mountinfo(text);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].mountpoint, Path::new("/mnt2"));
        assert_eq!(parsed[0].fstype, "ext3");
        assert_eq!(parsed[0].mount_options, "rw,noatime");
        assert_eq!(parsed[1].mountpoint, Path::new("/tmp/with space"));
        assert!(parsed[1].is_fuse_subtype("tempfs-quota"));
        assert!(!parsed[1].is_fuse_subtype("other"));
        assert_eq!(parsed[1].source, "automonique-tempfs");
        assert_eq!(parsed[1].user_id(), Some(1000));
        assert_eq!(parsed[0].user_id(), None);
    }

    #[test]
    fn the_root_filesystem_is_visible_and_foreign() {
        let status = inspect(Path::new("/"), "tempfs-quota").unwrap();
        assert!(matches!(status, MountStatus::Foreign { .. }), "{status}");
    }

    #[test]
    fn statfs_arithmetic_uses_the_fragment_size() {
        let readback = StatfsReadback {
            block_size: 4096,
            fragment_size: 4096,
            blocks: 256,
            blocks_free: 200,
            blocks_available: 200,
            files: 16,
            files_free: 10,
            name_max: 255,
        };
        assert_eq!(readback.ceiling_bytes(), 1_048_576);
        assert_eq!(readback.used_bytes(), 56 * 4096);
        assert_eq!(readback.used_objects(), 6);
    }
}
