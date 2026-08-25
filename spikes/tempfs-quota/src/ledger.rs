// SPDX-License-Identifier: Elastic-2.0

//! Exact byte and object accounting, independent of FUSE.
//!
//! Every byte the filesystem stores and every object it creates is reserved
//! from a [`Ledger`] first. The ledger is the one place a ceiling is compared
//! against, so the filesystem cannot drift from the budget by forgetting a
//! path, and every refusal is recorded as a typed [`Exceedance`] the
//! supervisor reads back after the run — the filesystem's own record of what
//! it refused, independent of whatever the workload printed.

use std::fmt;

/// Block size reported through `statfs`.
///
/// Enforcement is exact in bytes; `statfs` is block-granular. Requiring the
/// byte ceiling to be a positive multiple of this size means the ceiling a
/// workload reads back through `statfs` is the ceiling itself, not a rounding
/// of it.
pub const STATFS_BLOCK_BYTES: u64 = 4096;

/// Longest file name accepted, and reported through `statfs` as `f_namelen`.
pub const MAX_NAME_BYTES: u32 = 255;

/// Exceedances kept verbatim; beyond this only the counts grow.
pub const MAX_RECORDED_EXCEEDANCES: usize = 64;

/// The two ceilings a temporary filesystem enforces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ceilings {
    bytes: u64,
    objects: u64,
}

/// Why a pair of ceilings is refused before anything is mounted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CeilingError {
    /// A zero byte ceiling admits no write at all. Mounting a filesystem
    /// nothing can use is a refusal to launch, not a launch under a ceiling.
    BytesZero,
    /// The byte ceiling is not a multiple of [`STATFS_BLOCK_BYTES`], so
    /// `statfs` could not report it exactly.
    BytesNotBlockAligned { bytes: u64 },
    /// A zero object ceiling admits no file at all.
    ObjectsZero,
}

impl fmt::Display for CeilingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BytesZero => formatter.write_str("byte ceiling must be positive"),
            Self::BytesNotBlockAligned { bytes } => write!(
                formatter,
                "byte ceiling {bytes} is not a multiple of {STATFS_BLOCK_BYTES}"
            ),
            Self::ObjectsZero => formatter.write_str("object ceiling must be positive"),
        }
    }
}

impl std::error::Error for CeilingError {}

impl Ceilings {
    /// Exact ceilings: `bytes` of file content and `objects` files,
    /// directories and symbolic links, the root directory excluded.
    pub const fn new(bytes: u64, objects: u64) -> Result<Self, CeilingError> {
        if bytes == 0 {
            return Err(CeilingError::BytesZero);
        }
        if !bytes.is_multiple_of(STATFS_BLOCK_BYTES) {
            return Err(CeilingError::BytesNotBlockAligned { bytes });
        }
        if objects == 0 {
            return Err(CeilingError::ObjectsZero);
        }
        Ok(Self { bytes, objects })
    }

    /// Byte ceiling over the sum of every file's and symlink target's length.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
    }

    /// Object ceiling over files, directories and symlinks beneath the root.
    #[must_use]
    pub const fn objects(self) -> u64 {
        self.objects
    }
}

/// Which ceiling a reservation was checked against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resource {
    Bytes,
    Objects,
}

impl Resource {
    /// The errno a workload observes when this ceiling refuses it.
    ///
    /// Bytes refuse with `ENOSPC`: to the workload the filesystem is full, and
    /// `statfs` agrees, because `f_bavail` reads zero at the same moment.
    /// Objects refuse with `EDQUOT`. The two are distinct on purpose: the
    /// exceedance observed from inside containment then already names the
    /// ceiling that tripped, without any help from the supervisor.
    #[must_use]
    pub const fn errno(self) -> i32 {
        match self {
            Self::Bytes => nix::errno::Errno::ENOSPC as i32,
            Self::Objects => nix::errno::Errno::EDQUOT as i32,
        }
    }

    /// Stable spelling for reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Objects => "objects",
        }
    }

    const fn errno_name(self) -> &'static str {
        match self {
            Self::Bytes => "ENOSPC",
            Self::Objects => "EDQUOT",
        }
    }
}

/// One refused reservation, exactly as the filesystem observed it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Exceedance {
    /// The ceiling that refused.
    pub resource: Resource,
    /// How much more the operation needed.
    pub requested: u64,
    /// How much was in use when it asked.
    pub used: u64,
    /// The ceiling it was checked against.
    pub ceiling: u64,
}

impl Exceedance {
    /// The errno returned for this refusal.
    #[must_use]
    pub const fn errno(&self) -> i32 {
        self.resource.errno()
    }
}

impl fmt::Display for Exceedance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} requested={} used={} ceiling={} errno={}({})",
            self.resource.as_str(),
            self.requested,
            self.used,
            self.ceiling,
            self.resource.errno_name(),
            self.errno()
        )
    }
}

/// Live accounting against a pair of [`Ceilings`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ledger {
    ceilings: Ceilings,
    used_bytes: u64,
    used_objects: u64,
    peak_bytes: u64,
    peak_objects: u64,
    refused_bytes: u64,
    refused_objects: u64,
    recorded: Vec<Exceedance>,
}

impl Ledger {
    /// An empty ledger under `ceilings`.
    #[must_use]
    pub const fn new(ceilings: Ceilings) -> Self {
        Self {
            ceilings,
            used_bytes: 0,
            used_objects: 0,
            peak_bytes: 0,
            peak_objects: 0,
            refused_bytes: 0,
            refused_objects: 0,
            recorded: Vec::new(),
        }
    }

    /// The ceilings this ledger enforces.
    #[must_use]
    pub const fn ceilings(&self) -> Ceilings {
        self.ceilings
    }

    /// Bytes currently stored.
    #[must_use]
    pub const fn used_bytes(&self) -> u64 {
        self.used_bytes
    }

    /// Objects currently existing beneath the root.
    #[must_use]
    pub const fn used_objects(&self) -> u64 {
        self.used_objects
    }

    /// Reserve `delta` more bytes, or refuse without changing anything.
    ///
    /// A reservation is all-or-nothing: a write that would cross the ceiling
    /// is refused whole rather than truncated, so the byte count a workload
    /// observes is exactly what the ledger holds.
    pub fn reserve_bytes(&mut self, delta: u64) -> Result<(), Exceedance> {
        let ceiling = self.ceilings.bytes;
        match self.used_bytes.checked_add(delta) {
            Some(next) if next <= ceiling => {
                self.used_bytes = next;
                self.peak_bytes = self.peak_bytes.max(next);
                Ok(())
            }
            _ => {
                let exceedance = Exceedance {
                    resource: Resource::Bytes,
                    requested: delta,
                    used: self.used_bytes,
                    ceiling,
                };
                self.refused_bytes += 1;
                self.record(exceedance);
                Err(exceedance)
            }
        }
    }

    /// Return `delta` bytes. Releasing more than is held is a filesystem
    /// bug; it saturates rather than wrapping so the ledger can never report
    /// a negative or enormous usage.
    pub fn release_bytes(&mut self, delta: u64) {
        self.used_bytes = self.used_bytes.saturating_sub(delta);
    }

    /// Reserve one object, or refuse without changing anything.
    pub fn reserve_object(&mut self) -> Result<(), Exceedance> {
        let ceiling = self.ceilings.objects;
        if self.used_objects < ceiling {
            self.used_objects += 1;
            self.peak_objects = self.peak_objects.max(self.used_objects);
            return Ok(());
        }
        let exceedance = Exceedance {
            resource: Resource::Objects,
            requested: 1,
            used: self.used_objects,
            ceiling,
        };
        self.refused_objects += 1;
        self.record(exceedance);
        Err(exceedance)
    }

    /// Return one object.
    pub fn release_object(&mut self) {
        self.used_objects = self.used_objects.saturating_sub(1);
    }

    fn record(&mut self, exceedance: Exceedance) {
        if self.recorded.len() < MAX_RECORDED_EXCEEDANCES {
            self.recorded.push(exceedance);
        }
    }

    /// What `statfs` reports: the ceilings and the current usage, in
    /// [`STATFS_BLOCK_BYTES`] blocks. `files` is the object ceiling itself;
    /// the root directory is not counted against it.
    #[must_use]
    pub fn statfs(&self) -> StatfsView {
        let blocks = self.ceilings.bytes / STATFS_BLOCK_BYTES;
        let free_bytes = self.ceilings.bytes - self.used_bytes;
        StatfsView {
            block_bytes: u32::try_from(STATFS_BLOCK_BYTES).expect("block size fits"),
            blocks,
            blocks_free: free_bytes / STATFS_BLOCK_BYTES,
            files: self.ceilings.objects,
            files_free: self.ceilings.objects - self.used_objects,
            name_max: MAX_NAME_BYTES,
        }
    }

    /// A copy of everything the ledger knows, for the supervisor's report.
    #[must_use]
    pub fn snapshot(&self) -> LedgerSnapshot {
        LedgerSnapshot {
            ceilings: self.ceilings,
            used_bytes: self.used_bytes,
            used_objects: self.used_objects,
            peak_bytes: self.peak_bytes,
            peak_objects: self.peak_objects,
            refused_bytes: self.refused_bytes,
            refused_objects: self.refused_objects,
            recorded: self.recorded.clone(),
        }
    }
}

/// The `statfs` fields the filesystem reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatfsView {
    pub block_bytes: u32,
    pub blocks: u64,
    pub blocks_free: u64,
    pub files: u64,
    pub files_free: u64,
    pub name_max: u32,
}

/// The ledger at one instant: ceilings, usage, peaks and refusals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerSnapshot {
    pub ceilings: Ceilings,
    pub used_bytes: u64,
    pub used_objects: u64,
    pub peak_bytes: u64,
    pub peak_objects: u64,
    /// Byte reservations refused, in total.
    pub refused_bytes: u64,
    /// Object reservations refused, in total.
    pub refused_objects: u64,
    /// The first [`MAX_RECORDED_EXCEEDANCES`] refusals, verbatim.
    pub recorded: Vec<Exceedance>,
}

impl LedgerSnapshot {
    /// Whether any ceiling refused anything during the ledger's life.
    #[must_use]
    pub const fn exceeded(&self) -> bool {
        self.refused_bytes > 0 || self.refused_objects > 0
    }
}

impl fmt::Display for LedgerSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "ledger.ceiling_bytes={}", self.ceilings.bytes)?;
        writeln!(
            formatter,
            "ledger.ceiling_objects={}",
            self.ceilings.objects
        )?;
        writeln!(formatter, "ledger.used_bytes={}", self.used_bytes)?;
        writeln!(formatter, "ledger.used_objects={}", self.used_objects)?;
        writeln!(formatter, "ledger.peak_bytes={}", self.peak_bytes)?;
        writeln!(formatter, "ledger.peak_objects={}", self.peak_objects)?;
        writeln!(formatter, "ledger.refused_bytes={}", self.refused_bytes)?;
        writeln!(formatter, "ledger.refused_objects={}", self.refused_objects)?;
        for (index, exceedance) in self.recorded.iter().enumerate() {
            writeln!(formatter, "ledger.exceedance.{index}={exceedance}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ceilings() -> Ceilings {
        Ceilings::new(2 * STATFS_BLOCK_BYTES, 2).unwrap()
    }

    #[test]
    fn ceilings_are_validated_where_they_are_written() {
        assert_eq!(Ceilings::new(0, 1), Err(CeilingError::BytesZero));
        assert_eq!(
            Ceilings::new(STATFS_BLOCK_BYTES + 1, 1),
            Err(CeilingError::BytesNotBlockAligned {
                bytes: STATFS_BLOCK_BYTES + 1
            })
        );
        assert_eq!(
            Ceilings::new(STATFS_BLOCK_BYTES, 0),
            Err(CeilingError::ObjectsZero)
        );
        let accepted = Ceilings::new(STATFS_BLOCK_BYTES, 1).unwrap();
        assert_eq!(accepted.bytes(), STATFS_BLOCK_BYTES);
        assert_eq!(accepted.objects(), 1);
    }

    #[test]
    fn the_byte_ceiling_is_exact_and_all_or_nothing() {
        let mut ledger = Ledger::new(ceilings());
        ledger.reserve_bytes(2 * STATFS_BLOCK_BYTES - 1).unwrap();
        ledger
            .reserve_bytes(1)
            .expect("exactly the ceiling is admitted");
        let refused = ledger.reserve_bytes(1).unwrap_err();
        assert_eq!(
            refused,
            Exceedance {
                resource: Resource::Bytes,
                requested: 1,
                used: 2 * STATFS_BLOCK_BYTES,
                ceiling: 2 * STATFS_BLOCK_BYTES,
            }
        );
        assert_eq!(refused.errno(), nix::errno::Errno::ENOSPC as i32);
        // Nothing moved on refusal.
        assert_eq!(ledger.used_bytes(), 2 * STATFS_BLOCK_BYTES);
        // A large request against a nearly full ledger is refused whole, not
        // partially admitted.
        ledger.release_bytes(1);
        assert!(ledger.reserve_bytes(2).is_err());
        assert_eq!(ledger.used_bytes(), 2 * STATFS_BLOCK_BYTES - 1);
        // Overflowing arithmetic is a refusal, never a wrap.
        assert!(ledger.reserve_bytes(u64::MAX).is_err());
        let snapshot = ledger.snapshot();
        assert_eq!(snapshot.refused_bytes, 3);
        assert_eq!(snapshot.peak_bytes, 2 * STATFS_BLOCK_BYTES);
        assert!(snapshot.exceeded());
    }

    #[test]
    fn the_object_ceiling_is_exact() {
        let mut ledger = Ledger::new(ceilings());
        ledger.reserve_object().unwrap();
        ledger.reserve_object().unwrap();
        let refused = ledger.reserve_object().unwrap_err();
        assert_eq!(refused.resource, Resource::Objects);
        assert_eq!(refused.errno(), nix::errno::Errno::EDQUOT as i32);
        assert_eq!(refused.used, 2);
        ledger.release_object();
        ledger
            .reserve_object()
            .expect("a released object is reusable");
        assert_eq!(ledger.snapshot().refused_objects, 1);
        assert_eq!(ledger.snapshot().peak_objects, 2);
    }

    #[test]
    fn releases_saturate_rather_than_wrap() {
        let mut ledger = Ledger::new(ceilings());
        ledger.release_bytes(1);
        ledger.release_object();
        assert_eq!(ledger.used_bytes(), 0);
        assert_eq!(ledger.used_objects(), 0);
    }

    #[test]
    fn statfs_reports_the_ceilings_and_the_usage_in_blocks() {
        let mut ledger = Ledger::new(ceilings());
        assert_eq!(
            ledger.statfs(),
            StatfsView {
                block_bytes: 4096,
                blocks: 2,
                blocks_free: 2,
                files: 2,
                files_free: 2,
                name_max: MAX_NAME_BYTES,
            }
        );
        ledger.reserve_bytes(1).unwrap();
        ledger.reserve_object().unwrap();
        // One byte in use costs one whole block of the readback: the ceiling
        // is exact, the report is block-granular, and that asymmetry is the
        // documented one.
        let view = ledger.statfs();
        assert_eq!(view.blocks_free, 1);
        assert_eq!(view.files_free, 1);
    }

    #[test]
    fn only_the_first_exceedances_are_kept_verbatim() {
        let mut ledger = Ledger::new(Ceilings::new(STATFS_BLOCK_BYTES, 1).unwrap());
        ledger.reserve_object().unwrap();
        for _ in 0..(MAX_RECORDED_EXCEEDANCES + 5) {
            assert!(ledger.reserve_object().is_err());
        }
        let snapshot = ledger.snapshot();
        assert_eq!(snapshot.recorded.len(), MAX_RECORDED_EXCEEDANCES);
        assert_eq!(
            snapshot.refused_objects as usize,
            MAX_RECORDED_EXCEEDANCES + 5
        );
    }
}
