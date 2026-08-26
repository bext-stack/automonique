// SPDX-License-Identifier: Elastic-2.0

//! What the kernel says about a temporary-storage mountpoint.
//!
//! Every claim the runner makes about a mount — that it exists, that it is a
//! FUSE mount of this crate's subtype owned by this uid, that it reports the
//! ceilings, that it is gone after unmount — is answered from here, by
//! reading `/proc/self/mountinfo` and calling `statvfs(2)`. The mount
//! request itself proves nothing; only the readback does.
//!
//! A `statvfs` against a FUSE mount is answered by the mount's own server, so
//! a server that stopped answering would block the caller forever. Every
//! readback the supervisor issues against its own mount therefore goes
//! through [`statfs_bounded`], and a deadline that expires is what triggers
//! [`abort_connection`]: the kernel lets the mount owner abort a FUSE
//! connection through `fusectl`, after which every pending and future request
//! fails with `ENOTCONN` instead of waiting.

use nix::errno::Errno;
use nix::sys::statvfs::statvfs;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::time::Duration;

/// The mount table this process sees.
pub const MOUNTINFO: &str = "/proc/self/mountinfo";

/// Where the kernel exposes one control directory per FUSE connection.
pub const FUSE_CONNECTIONS: &str = "/sys/fs/fuse/connections";

/// Upper bound on the mount table read in one observation.
const MAX_MOUNTINFO_BYTES: usize = 4 * 1024 * 1024;

/// One `mountinfo` line's identity fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountEvidence {
    pub mountpoint: PathBuf,
    /// The minor number of the mount's anonymous block device, which is also
    /// the name of its `fusectl` connection directory.
    pub device_minor: u32,
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

    /// The `fusectl` control directory of this mount's connection.
    #[must_use]
    pub fn connection_directory(&self) -> PathBuf {
        Path::new(FUSE_CONNECTIONS).join(self.device_minor.to_string())
    }
}

impl fmt::Display for MountEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "fstype={} source={} device_minor={} options={} super_options={}",
            self.fstype, self.source, self.device_minor, self.mount_options, self.super_options
        )
    }
}

/// Parse the mount table, tolerating lines this crate does not understand.
#[must_use]
pub fn parse_mountinfo(text: &str) -> Vec<MountEvidence> {
    text.lines().filter_map(parse_mountinfo_line).collect()
}

/// Parse one `mountinfo` line, or refuse it.
///
/// Public because a mount performed inside a workload's own mount namespace
/// never appears in the supervisor's table: the launch reads the line there
/// and reports it, and the supervisor parses it here rather than trusting a
/// summary of it.
#[must_use]
pub fn parse_mountinfo_line(line: &str) -> Option<MountEvidence> {
    // `ID PARENT MAJ:MIN ROOT MOUNTPOINT OPTIONS [optional...] - FSTYPE SOURCE SUPEROPTS`
    let (before, after) = line.split_once(" - ")?;
    let mut before = before.split(' ');
    let device = before.nth(2)?;
    let (_, minor) = device.split_once(':')?;
    let device_minor = minor.parse().ok()?;
    let mountpoint = before.nth(1)?;
    let mount_options = before.next()?;
    let mut after = after.split(' ');
    let fstype = after.next()?;
    let source = after.next()?;
    let super_options = after.next()?;
    Some(MountEvidence {
        mountpoint: PathBuf::from(unescape(mountpoint)),
        device_minor,
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

/// The whole mount table, bounded.
pub fn mount_table() -> io::Result<Vec<MountEvidence>> {
    let raw = fs::read(MOUNTINFO)?;
    if raw.len() > MAX_MOUNTINFO_BYTES {
        return Err(io::Error::other("mount table exceeds the readback bound"));
    }
    let text = String::from_utf8(raw)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mount table is not UTF-8"))?;
    Ok(parse_mountinfo(&text))
}

/// The topmost mount at exactly `mountpoint`, if any.
pub fn mount_evidence(mountpoint: &Path) -> io::Result<Option<MountEvidence>> {
    Ok(mount_table()?
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
        self.blocks.saturating_sub(self.blocks_free) * self.fragment_size
    }

    /// Objects in use.
    #[must_use]
    pub const fn used_objects(&self) -> u64 {
        self.files.saturating_sub(self.files_free)
    }

    /// Parse the exact spelling [`Display`](fmt::Display) writes.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        let mut fields = [None; 8];
        for token in value.split(' ') {
            let (key, number) = token.split_once('=')?;
            let number: u64 = number.parse().ok()?;
            let index = match key {
                "bsize" => 0,
                "frsize" => 1,
                "blocks" => 2,
                "bfree" => 3,
                "bavail" => 4,
                "files" => 5,
                "ffree" => 6,
                "namelen" => 7,
                _ => return None,
            };
            fields[index] = Some(number);
        }
        Some(Self {
            block_size: fields[0]?,
            fragment_size: fields[1]?,
            blocks: fields[2]?,
            blocks_free: fields[3]?,
            blocks_available: fields[4]?,
            files: fields[5]?,
            files_free: fields[6]?,
            name_max: fields[7]?,
        })
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

/// Ask the kernel for the filesystem statistics at `mountpoint`, unbounded.
///
/// Correct for a mount whose server is known to answer; the supervisor's own
/// readbacks use [`statfs_bounded`].
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

/// Why a bounded readback produced no statistics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadbackError {
    /// The kernel answered with an error; `ENOTCONN` is a disconnected or
    /// aborted mount.
    Errno(Errno),
    /// No answer within the deadline: the server is not answering.
    TimedOut,
    /// The readback thread could not be created.
    ThreadUnavailable,
}

impl fmt::Display for ReadbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Errno(errno) => write!(formatter, "statvfs failed: {errno}"),
            Self::TimedOut => formatter.write_str("statvfs did not answer within the deadline"),
            Self::ThreadUnavailable => formatter.write_str("no thread for the readback"),
        }
    }
}

impl std::error::Error for ReadbackError {}

/// `statvfs` under a deadline.
///
/// The call runs on its own thread; a thread still blocked when the deadline
/// passes is detached rather than joined, because there is no way to
/// interrupt a `statvfs` against a server that will not answer. The caller
/// then aborts the connection, which is what frees that thread.
pub fn statfs_bounded(
    mountpoint: &Path,
    deadline: Duration,
) -> Result<StatfsReadback, ReadbackError> {
    let (sender, receiver) = channel();
    let path = mountpoint.to_path_buf();
    std::thread::Builder::new()
        .name("automonique-tempfs-readback".to_owned())
        .spawn(move || {
            let _ = sender.send(statfs_readback(&path));
        })
        .map_err(|_| ReadbackError::ThreadUnavailable)?;
    match receiver.recv_timeout(deadline) {
        Ok(Ok(readback)) => Ok(readback),
        Ok(Err(errno)) => Err(ReadbackError::Errno(errno)),
        Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
            Err(ReadbackError::TimedOut)
        }
    }
}

/// Abort the FUSE connection behind `evidence` through `fusectl`.
///
/// The connection directory is owned by the uid that mounted, so the mount
/// owner can always do this without privilege. After the write every request
/// pending on the connection fails with `ENOTCONN`, the server's session loop
/// ends, and the mount can be detached lazily.
pub fn abort_connection(evidence: &MountEvidence) -> io::Result<()> {
    let path = evidence.connection_directory().join("abort");
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(b"1")
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
    /// A FUSE mount of the expected subtype whose server is gone or not
    /// answering: the kernel answers `ENOTCONN` for it, or nothing within the
    /// deadline. This is the stale mount a crashed supervisor leaves behind.
    Disconnected {
        evidence: MountEvidence,
        error: ReadbackError,
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
            Self::Disconnected { evidence, error } => {
                write!(formatter, "status=disconnected error={error} {evidence}")
            }
            Self::Foreign { evidence } => write!(formatter, "status=foreign {evidence}"),
        }
    }
}

/// Classify the mount at `mountpoint` against `subtype`, with a bounded
/// readback.
pub fn inspect(mountpoint: &Path, subtype: &str, deadline: Duration) -> io::Result<MountStatus> {
    let Some(evidence) = mount_evidence(mountpoint)? else {
        return Ok(MountStatus::NotMounted);
    };
    Ok(classify(evidence, subtype, deadline))
}

/// Classify one mount table entry, with a bounded readback.
pub(crate) fn classify(evidence: MountEvidence, subtype: &str, deadline: Duration) -> MountStatus {
    if !evidence.is_fuse_subtype(subtype) {
        return MountStatus::Foreign { evidence };
    }
    match statfs_bounded(&evidence.mountpoint, deadline) {
        Ok(statfs) => MountStatus::Live { evidence, statfs },
        Err(error) => MountStatus::Disconnected { evidence, error },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mountinfo_lines_parse_including_escapes_and_optional_fields() {
        let text = "36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue\n\
                    1213 33 0:87 / /tmp/with\\040space rw,nosuid,nodev,noexec,relatime - \
                    fuse.automonique-tempfs automonique-tempfs rw,user_id=1000,group_id=1000,default_permissions\n\
                    garbage line\n\
                    9 8 nodevice / /x rw - ext4 /dev/x rw\n";
        let parsed = parse_mountinfo(text);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].mountpoint, Path::new("/mnt2"));
        assert_eq!(parsed[0].device_minor, 0);
        assert_eq!(parsed[0].fstype, "ext3");
        assert_eq!(parsed[0].mount_options, "rw,noatime");
        assert_eq!(parsed[1].mountpoint, Path::new("/tmp/with space"));
        assert_eq!(parsed[1].device_minor, 87);
        assert!(parsed[1].is_fuse_subtype("automonique-tempfs"));
        assert!(!parsed[1].is_fuse_subtype("other"));
        assert_eq!(parsed[1].source, "automonique-tempfs");
        assert_eq!(parsed[1].user_id(), Some(1000));
        assert_eq!(
            parsed[1].connection_directory(),
            Path::new("/sys/fs/fuse/connections/87")
        );
        assert_eq!(parsed[0].user_id(), None);
    }

    #[test]
    fn the_root_filesystem_is_visible_and_foreign() {
        let status = inspect(Path::new("/"), "automonique-tempfs", Duration::from_secs(5)).unwrap();
        assert!(matches!(status, MountStatus::Foreign { .. }), "{status}");
    }

    #[test]
    fn statfs_arithmetic_uses_the_fragment_size_and_round_trips() {
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
        assert_eq!(
            StatfsReadback::from_spelling(&readback.to_string()),
            Some(readback)
        );
        assert_eq!(StatfsReadback::from_spelling("bsize=4096"), None);
        assert_eq!(StatfsReadback::from_spelling("bogus=1"), None);
    }

    #[test]
    fn a_bounded_readback_answers_for_a_live_filesystem() {
        let readback = statfs_bounded(Path::new("/"), Duration::from_secs(5)).unwrap();
        assert!(readback.blocks > 0);
    }
}
