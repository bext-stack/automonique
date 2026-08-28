// SPDX-License-Identifier: Elastic-2.0

//! Durable checkpoints of a temporary-storage ledger.
//!
//! The ledger lives in the supervisor's memory, so a supervisor that dies
//! takes it along — unless it has been written down. A [`Checkpoint`] is the
//! ledger at one instant, written atomically (temporary file, `fsync`,
//! rename) into the run's private directory, outside the mount and outside
//! every grant the workload holds. The reaper reads it back after a crash so
//! the consumed-budget record survives the supervisor that produced it.
//!
//! The format is one `key=value` per line between a schema header and an
//! `end=` trailer; a file without the trailer is a torn write and is refused.

use crate::tempfs_ledger::{
    Exceedance, LedgerSnapshot, MAX_RECORDED_EXCEEDANCES, Resource, TemporaryStorageBudget,
};
use crate::tempfs_readback::StatfsReadback;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// First line of every checkpoint.
pub const CHECKPOINT_HEADER: &str = "schema=automonique.tempfs-ledger/v1";
/// Last line of every complete checkpoint.
pub const CHECKPOINT_TRAILER: &str = "end=automonique.tempfs-ledger/v1";
/// Upper bound on one checkpoint file.
pub const MAX_CHECKPOINT_BYTES: u64 = 64 * 1024;

/// Which moment of the mount's life a checkpoint describes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// The mount was live when this was written; usage may have moved since.
    Live,
    /// Written at unmount: the ledger's last word, with the readbacks taken
    /// at the end.
    Final,
}

impl Phase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Final => "final",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "live" => Some(Self::Live),
            "final" => Some(Self::Final),
            _ => None,
        }
    }
}

/// The readbacks and confirmations recorded once at unmount.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalRecord {
    /// `statvfs` right before unmounting, when the server still answered.
    pub statfs_before_unmount: Option<StatfsReadback>,
    /// The mount table showed no entry after unmounting.
    pub unmount_confirmed: bool,
    /// The connection had to be aborted because the readback timed out.
    pub aborted: bool,
}

/// The ledger at one instant, as written to and read from disk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    /// Monotonic within one mount: a later checkpoint has a larger sequence.
    pub sequence: u64,
    /// Wall-clock time of the write, in Unix milliseconds.
    pub at_millis: u64,
    pub phase: Phase,
    pub snapshot: LedgerSnapshot,
    /// The mount table entry as observed at mount time.
    pub mount_evidence: String,
    /// `statvfs` right after mounting.
    pub statfs_at_mount: StatfsReadback,
    /// Present only for [`Phase::Final`].
    pub final_record: Option<FinalRecord>,
}

/// Why a checkpoint could not be read back.
#[derive(Debug)]
pub enum CheckpointError {
    Io(io::Error),
    /// The file is larger than [`MAX_CHECKPOINT_BYTES`].
    Oversized,
    /// Not owned by this uid, or readable by others.
    UnsafeFile,
    /// The header, a line, or the trailer is missing or malformed.
    Malformed(&'static str),
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "checkpoint unreadable: {error}"),
            Self::Oversized => formatter.write_str("checkpoint exceeds its size bound"),
            Self::UnsafeFile => formatter.write_str("checkpoint is not a private file of this uid"),
            Self::Malformed(what) => write!(formatter, "checkpoint is malformed: {what}"),
        }
    }
}

impl std::error::Error for CheckpointError {}

impl From<io::Error> for CheckpointError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Unix milliseconds now, or zero when the clock is before the epoch.
#[must_use]
pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

impl Checkpoint {
    /// Serialise to the on-disk text.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut text = String::new();
        text.push_str(CHECKPOINT_HEADER);
        text.push('\n');
        text.push_str(&format!("sequence={}\n", self.sequence));
        text.push_str(&format!("at_millis={}\n", self.at_millis));
        text.push_str(&format!("phase={}\n", self.phase.as_str()));
        let snapshot = &self.snapshot;
        text.push_str(&format!("ceiling_bytes={}\n", snapshot.budget.bytes()));
        text.push_str(&format!("ceiling_objects={}\n", snapshot.budget.objects()));
        text.push_str(&format!("used_bytes={}\n", snapshot.used_bytes));
        text.push_str(&format!("used_objects={}\n", snapshot.used_objects));
        text.push_str(&format!("peak_bytes={}\n", snapshot.peak_bytes));
        text.push_str(&format!("peak_objects={}\n", snapshot.peak_objects));
        text.push_str(&format!("refused_bytes={}\n", snapshot.refused_bytes));
        text.push_str(&format!("refused_objects={}\n", snapshot.refused_objects));
        for exceedance in snapshot.recorded.iter().take(MAX_RECORDED_EXCEEDANCES) {
            text.push_str(&format!(
                "exceedance={} {} {} {}\n",
                exceedance.resource.as_str(),
                exceedance.requested,
                exceedance.used,
                exceedance.ceiling
            ));
        }
        text.push_str(&format!(
            "mount_evidence={}\n",
            sanitized(&self.mount_evidence)
        ));
        text.push_str(&format!("statfs_at_mount={}\n", self.statfs_at_mount));
        if let Some(record) = &self.final_record {
            match &record.statfs_before_unmount {
                Some(statfs) => text.push_str(&format!("statfs_before_unmount={statfs}\n")),
                None => text.push_str("statfs_before_unmount=absent\n"),
            }
            text.push_str(&format!("unmount_confirmed={}\n", record.unmount_confirmed));
            text.push_str(&format!("aborted={}\n", record.aborted));
        }
        text.push_str(CHECKPOINT_TRAILER);
        text.push('\n');
        text
    }

    /// Parse the on-disk text.
    pub fn decode(text: &str) -> Result<Self, CheckpointError> {
        let malformed = CheckpointError::Malformed;
        let mut lines = text.lines();
        if lines.next() != Some(CHECKPOINT_HEADER) {
            return Err(malformed("header"));
        }
        let mut sequence = None;
        let mut at_millis = None;
        let mut phase = None;
        let mut ceiling_bytes = None;
        let mut ceiling_objects = None;
        let mut used_bytes = None;
        let mut used_objects = None;
        let mut peak_bytes = None;
        let mut peak_objects = None;
        let mut refused_bytes = None;
        let mut refused_objects = None;
        let mut recorded = Vec::new();
        let mut mount_evidence = None;
        let mut statfs_at_mount = None;
        let mut statfs_before_unmount = None;
        let mut unmount_confirmed = None;
        let mut aborted = None;
        let mut terminated = false;
        for line in lines {
            if line == CHECKPOINT_TRAILER {
                terminated = true;
                break;
            }
            let (key, value) = line.split_once('=').ok_or(malformed("line"))?;
            let number = || value.parse::<u64>().map_err(|_| malformed("number"));
            let flag = || match value {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(malformed("flag")),
            };
            match key {
                "sequence" => sequence = Some(number()?),
                "at_millis" => at_millis = Some(number()?),
                "phase" => phase = Some(Phase::parse(value).ok_or(malformed("phase"))?),
                "ceiling_bytes" => ceiling_bytes = Some(number()?),
                "ceiling_objects" => ceiling_objects = Some(number()?),
                "used_bytes" => used_bytes = Some(number()?),
                "used_objects" => used_objects = Some(number()?),
                "peak_bytes" => peak_bytes = Some(number()?),
                "peak_objects" => peak_objects = Some(number()?),
                "refused_bytes" => refused_bytes = Some(number()?),
                "refused_objects" => refused_objects = Some(number()?),
                "exceedance" => {
                    if recorded.len() >= MAX_RECORDED_EXCEEDANCES {
                        return Err(malformed("too many exceedances"));
                    }
                    let mut parts = value.split(' ');
                    let resource = parts
                        .next()
                        .and_then(Resource::from_spelling)
                        .ok_or(malformed("exceedance"))?;
                    let mut numbers = parts.map(|part| part.parse::<u64>().ok());
                    let requested = numbers.next().flatten().ok_or(malformed("exceedance"))?;
                    let used = numbers.next().flatten().ok_or(malformed("exceedance"))?;
                    let ceiling = numbers.next().flatten().ok_or(malformed("exceedance"))?;
                    if numbers.next().is_some() {
                        return Err(malformed("exceedance"));
                    }
                    recorded.push(Exceedance {
                        resource,
                        requested,
                        used,
                        ceiling,
                    });
                }
                "mount_evidence" => mount_evidence = Some(value.to_owned()),
                "statfs_at_mount" => {
                    statfs_at_mount =
                        Some(StatfsReadback::from_spelling(value).ok_or(malformed("statfs"))?);
                }
                "statfs_before_unmount" => {
                    statfs_before_unmount = Some(if value == "absent" {
                        None
                    } else {
                        Some(StatfsReadback::from_spelling(value).ok_or(malformed("statfs"))?)
                    });
                }
                "unmount_confirmed" => unmount_confirmed = Some(flag()?),
                "aborted" => aborted = Some(flag()?),
                _ => return Err(malformed("unknown key")),
            }
        }
        if !terminated {
            return Err(malformed("trailer"));
        }
        let budget = TemporaryStorageBudget::new(
            ceiling_bytes.ok_or(malformed("ceiling_bytes"))?,
            ceiling_objects.ok_or(malformed("ceiling_objects"))?,
        )
        .map_err(|_| malformed("budget"))?;
        let phase = phase.ok_or(malformed("phase"))?;
        let final_record = match phase {
            Phase::Live => None,
            Phase::Final => Some(FinalRecord {
                statfs_before_unmount: statfs_before_unmount
                    .ok_or(malformed("statfs_before_unmount"))?,
                unmount_confirmed: unmount_confirmed.ok_or(malformed("unmount_confirmed"))?,
                aborted: aborted.ok_or(malformed("aborted"))?,
            }),
        };
        let snapshot = LedgerSnapshot {
            budget,
            used_bytes: used_bytes.ok_or(malformed("used_bytes"))?,
            used_objects: used_objects.ok_or(malformed("used_objects"))?,
            peak_bytes: peak_bytes.ok_or(malformed("peak_bytes"))?,
            peak_objects: peak_objects.ok_or(malformed("peak_objects"))?,
            refused_bytes: refused_bytes.ok_or(malformed("refused_bytes"))?,
            refused_objects: refused_objects.ok_or(malformed("refused_objects"))?,
            recorded,
        };
        StatfsReadback::from_ledger(&snapshot).map_err(|_| malformed("ledger relations"))?;
        Ok(Self {
            sequence: sequence.ok_or(malformed("sequence"))?,
            at_millis: at_millis.ok_or(malformed("at_millis"))?,
            phase,
            snapshot,
            mount_evidence: mount_evidence.ok_or(malformed("mount_evidence"))?,
            statfs_at_mount: statfs_at_mount.ok_or(malformed("statfs_at_mount"))?,
            final_record,
        })
    }

    /// Write atomically to `path`: a private sibling temporary file, `fsync`,
    /// then rename over the destination.
    pub fn write(&self, path: &Path) -> io::Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("checkpoint path has no parent"))?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| io::Error::other("checkpoint path has no name"))?;
        let temporary = parent.join(format!(".{name}.tmp"));
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&temporary)?;
        file.write_all(self.encode().as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        // Best effort: the rename is durable once the directory is, and a
        // directory that cannot be synced is not a reason to lose the run.
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    }

    /// Read a checkpoint this uid wrote at `path`.
    pub fn read(path: &Path) -> Result<Self, CheckpointError> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != nix::unistd::Uid::current().as_raw()
            || metadata.mode() & 0o077 != 0
        {
            return Err(CheckpointError::UnsafeFile);
        }
        if metadata.len() > MAX_CHECKPOINT_BYTES {
            return Err(CheckpointError::Oversized);
        }
        let mut text = String::new();
        std::io::Read::by_ref(&mut file)
            .take(MAX_CHECKPOINT_BYTES)
            .read_to_string(&mut text)
            .map_err(|_| CheckpointError::Malformed("utf-8"))?;
        Self::decode(&text)
    }
}

/// One line, always: a newline inside the evidence would forge a key.
fn sanitized(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tempfs_ledger::{Ledger, STATFS_BLOCK_BYTES};

    fn sample(phase: Phase) -> Checkpoint {
        let mut ledger =
            Ledger::new(TemporaryStorageBudget::new(2 * STATFS_BLOCK_BYTES, 2).unwrap());
        ledger.reserve_object().unwrap();
        ledger.reserve_bytes(5).unwrap();
        ledger.reserve_bytes(2 * STATFS_BLOCK_BYTES).unwrap_err();
        let statfs = StatfsReadback {
            block_size: 4096,
            fragment_size: 4096,
            blocks: 2,
            blocks_free: 2,
            blocks_available: 2,
            files: 2,
            files_free: 2,
            name_max: 255,
        };
        Checkpoint {
            sequence: 7,
            at_millis: 1_700_000_000_000,
            phase,
            snapshot: ledger.snapshot(),
            mount_evidence: "fstype=fuse.automonique-tempfs source=automonique-tempfs\nforged=1"
                .to_owned(),
            statfs_at_mount: statfs,
            final_record: match phase {
                Phase::Live => None,
                Phase::Final => Some(FinalRecord {
                    statfs_before_unmount: Some(StatfsReadback {
                        blocks_free: 1,
                        blocks_available: 1,
                        files_free: 1,
                        ..statfs
                    }),
                    unmount_confirmed: true,
                    aborted: false,
                }),
            },
        }
    }

    #[test]
    fn checkpoints_round_trip_through_text_and_disk() {
        for phase in [Phase::Live, Phase::Final] {
            let checkpoint = sample(phase);
            let text = checkpoint.encode();
            assert!(text.starts_with(CHECKPOINT_HEADER));
            assert!(text.ends_with(&format!("{CHECKPOINT_TRAILER}\n")));
            // The evidence line was flattened rather than allowed to forge a key.
            assert!(!text.contains("\nforged=1"));
            let decoded = Checkpoint::decode(&text).unwrap();
            assert_eq!(decoded.sequence, 7);
            assert_eq!(decoded.phase, phase);
            assert_eq!(decoded.snapshot, checkpoint.snapshot);
            assert_eq!(decoded.statfs_at_mount, checkpoint.statfs_at_mount);
            assert_eq!(decoded.final_record, checkpoint.final_record);

            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("tempfs-ledger");
            checkpoint.write(&path).unwrap();
            let read = Checkpoint::read(&path).unwrap();
            assert_eq!(read.snapshot, checkpoint.snapshot);
            assert_eq!(read.final_record, checkpoint.final_record);
            assert!(!directory.path().join(".tempfs-ledger.tmp").exists());
        }
    }

    #[test]
    fn torn_and_foreign_checkpoints_are_refused() {
        let text = sample(Phase::Live).encode();
        let torn = text.trim_end_matches(&format!("{CHECKPOINT_TRAILER}\n"));
        assert!(matches!(
            Checkpoint::decode(torn),
            Err(CheckpointError::Malformed("trailer"))
        ));
        assert!(matches!(
            Checkpoint::decode("schema=other\n"),
            Err(CheckpointError::Malformed("header"))
        ));
        let unknown = text.replace("used_bytes=", "sued_bytes=");
        assert!(matches!(
            Checkpoint::decode(&unknown),
            Err(CheckpointError::Malformed("unknown key"))
        ));
        let impossible_usage = text.replace("used_bytes=5", "used_bytes=999999");
        assert!(matches!(
            Checkpoint::decode(&impossible_usage),
            Err(CheckpointError::Malformed("ledger relations"))
        ));
        let missing_refusal = text.replace("refused_bytes=1", "refused_bytes=0");
        assert!(matches!(
            Checkpoint::decode(&missing_refusal),
            Err(CheckpointError::Malformed("ledger relations"))
        ));
        // A final checkpoint without its record is incomplete.
        let final_without_record = text.replace("phase=live", "phase=final");
        assert!(matches!(
            Checkpoint::decode(&final_without_record),
            Err(CheckpointError::Malformed("statfs_before_unmount"))
        ));
    }

    #[test]
    fn a_world_readable_checkpoint_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tempfs-ledger");
        sample(Phase::Live).write(&path).unwrap();
        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
        assert!(matches!(
            Checkpoint::read(&path),
            Err(CheckpointError::UnsafeFile)
        ));
    }
}
