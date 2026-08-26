// SPDX-License-Identifier: Elastic-2.0

//! Exact byte and object accounting for the temporary-storage budget,
//! independent of FUSE.
//!
//! Every byte the filesystem stores and every object it creates is reserved
//! from a [`Ledger`] first. The ledger is the one place a ceiling is compared
//! against, so the filesystem cannot drift from the budget by forgetting a
//! path, and every refusal is recorded as a typed [`Exceedance`] the
//! supervisor reads back — the filesystem's own record of what it refused,
//! independent of whatever the workload printed.

use std::fmt;

/// Block size reported through `statfs`.
///
/// Enforcement is exact in bytes; `statfs` is block-granular. Requiring the
/// byte ceiling to be a positive multiple of this size means the ceiling a
/// workload reads back through `statfs` is the ceiling itself, not a rounding
/// of it.
pub const STATFS_BLOCK_BYTES: u64 = 4096;

/// Largest byte ceiling admission accepts for one run.
///
/// The filesystem stores bytes in the supervisor's memory, so this — times
/// the number of runs a supervisor hosts at once — is the supervisor's
/// exposure. It is a charging-policy cap, documented in
/// `docs/operations/temporary-storage-budget.md`, not a kernel limit.
pub const MAX_TEMPORARY_STORAGE_BYTES: u64 = 128 * 1024 * 1024;

/// Longest file name accepted, and reported through `statfs` as `f_namelen`.
pub const MAX_NAME_BYTES: u32 = 255;

/// Exceedances kept verbatim; beyond this only the counts grow.
pub const MAX_RECORDED_EXCEEDANCES: usize = 64;

/// The two ceilings a temporary filesystem enforces: bytes of content and
/// objects (files, directories and symbolic links, the root excluded).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TemporaryStorageBudget {
    bytes: u64,
    objects: u64,
}

/// Why a budget is refused before anything is mounted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetError {
    /// A zero byte ceiling admits no write at all. Mounting a filesystem
    /// nothing can use is a refusal to launch, not a launch under a ceiling.
    BytesZero,
    /// The byte ceiling is not a multiple of [`STATFS_BLOCK_BYTES`], so
    /// `statfs` could not report it exactly.
    BytesNotBlockAligned { bytes: u64 },
    /// The byte ceiling is above [`MAX_TEMPORARY_STORAGE_BYTES`].
    BytesAboveCap { bytes: u64 },
    /// A zero object ceiling admits no file at all.
    ObjectsZero,
}

impl fmt::Display for BudgetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BytesZero => formatter.write_str("byte ceiling must be positive"),
            Self::BytesNotBlockAligned { bytes } => write!(
                formatter,
                "byte ceiling {bytes} is not a multiple of {STATFS_BLOCK_BYTES}"
            ),
            Self::BytesAboveCap { bytes } => write!(
                formatter,
                "byte ceiling {bytes} is above the {MAX_TEMPORARY_STORAGE_BYTES} byte cap"
            ),
            Self::ObjectsZero => formatter.write_str("object ceiling must be positive"),
        }
    }
}

impl std::error::Error for BudgetError {}

impl TemporaryStorageBudget {
    /// Exact ceilings: `bytes` of file content and `objects` files,
    /// directories and symbolic links, the root directory excluded.
    pub const fn new(bytes: u64, objects: u64) -> Result<Self, BudgetError> {
        if bytes == 0 {
            return Err(BudgetError::BytesZero);
        }
        if !bytes.is_multiple_of(STATFS_BLOCK_BYTES) {
            return Err(BudgetError::BytesNotBlockAligned { bytes });
        }
        if bytes > MAX_TEMPORARY_STORAGE_BYTES {
            return Err(BudgetError::BytesAboveCap { bytes });
        }
        if objects == 0 {
            return Err(BudgetError::ObjectsZero);
        }
        Ok(Self { bytes, objects })
    }

    /// The budget a document's `temporary_storage_bytes` maps onto.
    ///
    /// The object ceiling is derived, one object per [`STATFS_BLOCK_BYTES`]
    /// of the byte ceiling: the document carries no object count, and a byte
    /// budget of `n` blocks bounding at most `n` objects keeps the server's
    /// per-object metadata proportional to the bytes the document reserved.
    /// This is a documented interpretation pinned by tests, never silent.
    pub const fn from_bytes(bytes: u64) -> Result<Self, BudgetError> {
        Self::new(bytes, bytes / STATFS_BLOCK_BYTES)
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

impl fmt::Display for TemporaryStorageBudget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "bytes={} objects={}", self.bytes, self.objects)
    }
}

/// Which ceiling a reservation was checked against.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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

    /// Parse the stable spelling.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        match value {
            "bytes" => Some(Self::Bytes),
            "objects" => Some(Self::Objects),
            _ => None,
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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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

/// Live accounting against a [`TemporaryStorageBudget`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ledger {
    budget: TemporaryStorageBudget,
    used_bytes: u64,
    used_objects: u64,
    peak_bytes: u64,
    peak_objects: u64,
    refused_bytes: u64,
    refused_objects: u64,
    recorded: Vec<Exceedance>,
}

impl Ledger {
    /// An empty ledger under `budget`.
    #[must_use]
    pub const fn new(budget: TemporaryStorageBudget) -> Self {
        Self {
            budget,
            used_bytes: 0,
            used_objects: 0,
            peak_bytes: 0,
            peak_objects: 0,
            refused_bytes: 0,
            refused_objects: 0,
            recorded: Vec::new(),
        }
    }

    /// The budget this ledger enforces.
    #[must_use]
    pub const fn budget(&self) -> TemporaryStorageBudget {
        self.budget
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
        let ceiling = self.budget.bytes;
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
        let ceiling = self.budget.objects;
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
        let blocks = self.budget.bytes / STATFS_BLOCK_BYTES;
        let free_bytes = self.budget.bytes - self.used_bytes;
        StatfsView {
            block_bytes: u32::try_from(STATFS_BLOCK_BYTES).expect("block size fits"),
            blocks,
            blocks_free: free_bytes / STATFS_BLOCK_BYTES,
            files: self.budget.objects,
            files_free: self.budget.objects - self.used_objects,
            name_max: MAX_NAME_BYTES,
        }
    }

    /// A copy of everything the ledger knows, for the supervisor's report.
    #[must_use]
    pub fn snapshot(&self) -> LedgerSnapshot {
        LedgerSnapshot {
            budget: self.budget,
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

/// The ledger at one instant: budget, usage, peaks and refusals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerSnapshot {
    pub budget: TemporaryStorageBudget,
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

    /// The first refusal, when there was one.
    #[must_use]
    pub fn first_exceedance(&self) -> Option<Exceedance> {
        self.recorded.first().copied()
    }
}

impl fmt::Display for LedgerSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "ledger.ceiling_bytes={}", self.budget.bytes)?;
        writeln!(formatter, "ledger.ceiling_objects={}", self.budget.objects)?;
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

    fn budget() -> TemporaryStorageBudget {
        TemporaryStorageBudget::new(2 * STATFS_BLOCK_BYTES, 2).unwrap()
    }

    #[test]
    fn budgets_are_validated_where_they_are_written() {
        assert_eq!(
            TemporaryStorageBudget::new(0, 1),
            Err(BudgetError::BytesZero)
        );
        assert_eq!(
            TemporaryStorageBudget::new(STATFS_BLOCK_BYTES + 1, 1),
            Err(BudgetError::BytesNotBlockAligned {
                bytes: STATFS_BLOCK_BYTES + 1
            })
        );
        assert_eq!(
            TemporaryStorageBudget::new(STATFS_BLOCK_BYTES, 0),
            Err(BudgetError::ObjectsZero)
        );
        assert_eq!(
            TemporaryStorageBudget::new(MAX_TEMPORARY_STORAGE_BYTES + STATFS_BLOCK_BYTES, 1),
            Err(BudgetError::BytesAboveCap {
                bytes: MAX_TEMPORARY_STORAGE_BYTES + STATFS_BLOCK_BYTES
            })
        );
        let accepted = TemporaryStorageBudget::new(STATFS_BLOCK_BYTES, 1).unwrap();
        assert_eq!(accepted.bytes(), STATFS_BLOCK_BYTES);
        assert_eq!(accepted.objects(), 1);
    }

    #[test]
    fn the_object_ceiling_is_one_per_block_of_the_byte_ceiling() {
        let derived = TemporaryStorageBudget::from_bytes(1024 * 1024).unwrap();
        assert_eq!(derived.bytes(), 1024 * 1024);
        assert_eq!(derived.objects(), 256);
        assert_eq!(
            TemporaryStorageBudget::from_bytes(STATFS_BLOCK_BYTES)
                .unwrap()
                .objects(),
            1
        );
        assert_eq!(
            TemporaryStorageBudget::from_bytes(MAX_TEMPORARY_STORAGE_BYTES)
                .unwrap()
                .objects(),
            MAX_TEMPORARY_STORAGE_BYTES / STATFS_BLOCK_BYTES
        );
    }

    #[test]
    fn the_byte_ceiling_is_exact_and_all_or_nothing() {
        let mut ledger = Ledger::new(budget());
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
        assert_eq!(snapshot.first_exceedance(), Some(refused));
    }

    #[test]
    fn the_object_ceiling_is_exact() {
        let mut ledger = Ledger::new(budget());
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
        let mut ledger = Ledger::new(budget());
        ledger.release_bytes(1);
        ledger.release_object();
        assert_eq!(ledger.used_bytes(), 0);
        assert_eq!(ledger.used_objects(), 0);
    }

    #[test]
    fn statfs_reports_the_ceilings_and_the_usage_in_blocks() {
        let mut ledger = Ledger::new(budget());
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
        let mut ledger = Ledger::new(TemporaryStorageBudget::new(STATFS_BLOCK_BYTES, 1).unwrap());
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

    #[test]
    fn resources_round_trip_their_spelling() {
        for resource in [Resource::Bytes, Resource::Objects] {
            assert_eq!(Resource::from_spelling(resource.as_str()), Some(resource));
        }
        assert_eq!(Resource::from_spelling("inodes"), None);
    }
}
