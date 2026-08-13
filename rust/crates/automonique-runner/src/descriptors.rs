// SPDX-License-Identifier: Elastic-2.0

//! Descriptor closure: removing inherited authority before `execv`.
//!
//! An open file descriptor is authority the kernel already granted. It survives
//! `execv` unless it carries `FD_CLOEXEC`, and it is checked at `open` time, not
//! at `read`/`write` time: a workload that inherits a descriptor for a file
//! outside its filesystem restrictions can still read and write that file, and
//! no later Landlock ruleset, mount namespace, or seccomp filter takes that
//! authority back. One leaked descriptor therefore defeats the containment it
//! was inherited past. This module closes every descriptor the caller did not
//! explicitly name, and then proves it by re-reading the kernel's own view.
//!
//! The intended call site is a child process, single-threaded, immediately
//! before `execv` of an untrusted workload.
//!
//! What this module does **not** establish:
//!
//! - It is not a sandbox. It removes descriptors the workload would inherit; it
//!   places no restriction whatsoever on what the workload opens afterwards.
//! - It says nothing about descriptors created after it returns. It closes
//!   descriptors now rather than marking them `FD_CLOEXEC`, so anything opened
//!   between this call and `execv` is inherited. Call it last.
//! - It does not weaken a retained descriptor. An allowlisted descriptor enters
//!   the workload with its full authority, including the authority to receive
//!   further descriptors over `SCM_RIGHTS` if it is a unix socket, and the
//!   authority to reach directories through `openat` if it is a directory. What
//!   the caller keeps is the caller's risk.
//! - It does not check what a retained descriptor points at. Closure proves the
//!   surviving descriptor *numbers*, never their identity; a descriptor
//!   substituted before this call is retained as faithfully as the intended one.
//! - It does not revoke authority already extracted from a descriptor: an
//!   existing memory mapping stays mapped, and a descriptor duplicated into
//!   another process is beyond this process's reach.
//! - Verification is a snapshot. It proves what `/proc/self/fd` contained at the
//!   moment it was read. Only a caller that runs this single-threaded, with no
//!   descriptor-opening code between verification and `execv`, may read that
//!   snapshot as the state the workload starts with. Concurrent descriptor
//!   creation in another thread is detected as
//!   [`DescriptorError::EnumerationUnattributed`] when it disturbs the
//!   observation, but detection is not prevention.
//! - It requires `/proc` mounted for this process. Without it there is no
//!   authoritative descriptor list, and every operation here refuses rather than
//!   guessing a range to close.

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, fcntl};
use nix::unistd::close;
use std::fmt;
use std::fs;
use std::os::fd::RawFd;
use std::path::Path;

/// The kernel's authoritative list of this process's open descriptors.
const PROC_SELF_FD: &str = "/proc/self/fd";

/// Longest accepted allowlist. A pre-`execv` handover needs a handful of
/// descriptors; a request in the hundreds is a caller defect, and refusing it
/// is cheaper than closing almost nothing and calling that containment.
pub const MAX_ALLOWLIST_LEN: usize = 64;

/// Largest descriptor number a caller may ask to retain, matching the usual
/// `fs.nr_open` ceiling. This bounds only what may be *kept*: closure closes
/// every descriptor the kernel reports, whatever its number.
pub const MAX_ALLOWLIST_DESCRIPTOR: RawFd = 1_048_576;

/// Upper bound on descriptors observed in one enumeration. A process holding
/// more than this before handing off to a workload is not in a state this
/// module will certify.
pub const MAX_OPEN_DESCRIPTORS: usize = 65_536;

/// Why descriptor closure is refused or unproven.
///
/// Every variant is a refusal. There is no variant meaning "closed but
/// unverified": closure this module cannot confirm against `/proc/self/fd` did
/// not happen as far as any caller is concerned.
#[derive(Debug)]
pub enum DescriptorError {
    /// `/proc/self/fd` could not be listed, so the set of open descriptors is
    /// unknown. Closing a guessed range would report success without knowing
    /// what it closed, so this refuses instead.
    ProcUnavailable(std::io::Error),
    /// `/proc/self/fd` held an entry that is not a non-negative descriptor
    /// number, so the listing is not the kernel view this module requires.
    ProcEntryUnreadable,
    /// The process holds more open descriptors than one enumeration will
    /// certify.
    TooManyDescriptors { limit: usize },
    /// The caller asked to retain more descriptors than an `execv` handover is
    /// allowed to carry.
    AllowlistTooLarge { requested: usize, limit: usize },
    /// A descriptor number is negative or beyond [`MAX_ALLOWLIST_DESCRIPTOR`].
    DescriptorOutOfRange(RawFd),
    /// A descriptor the caller required to survive is not open. From
    /// [`close_all_except`] this is refused before anything is closed, so the
    /// descriptor table is untouched. From [`verify_only_allowlist_open`] it
    /// says only that the descriptor is missing now, not what removed it.
    AllowlistNotOpen(RawFd),
    /// A descriptor could not be tested for openness, so the enumeration cannot
    /// be trusted.
    ProbeFailed { fd: RawFd, errno: Errno },
    /// `close` reported a failure other than an interruption, so this
    /// descriptor's fate is unknown.
    CloseFailed { fd: RawFd, errno: Errno },
    /// A descriptor outside the allowlist was still open after closure. This is
    /// the leak the module exists to prevent.
    ResidualDescriptor(RawFd),
    /// Exactly one descriptor in a listing must be the transient handle used to
    /// read it. Any other count means descriptors changed underneath the
    /// observation, so the listing describes no single moment.
    EnumerationUnattributed { stale: usize },
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProcUnavailable(error) => {
                write!(formatter, "{PROC_SELF_FD} could not be listed: {error}")
            }
            Self::ProcEntryUnreadable => {
                write!(formatter, "{PROC_SELF_FD} held a non-descriptor entry")
            }
            Self::TooManyDescriptors { limit } => write!(
                formatter,
                "more than {limit} descriptors are open in this process"
            ),
            Self::AllowlistTooLarge { requested, limit } => write!(
                formatter,
                "allowlist of {requested} descriptors exceeds the limit of {limit}"
            ),
            Self::DescriptorOutOfRange(fd) => {
                write!(formatter, "descriptor {fd} is not a retainable descriptor")
            }
            Self::AllowlistNotOpen(fd) => write!(
                formatter,
                "descriptor {fd} was required to survive but is not open"
            ),
            Self::ProbeFailed { fd, errno } => {
                write!(formatter, "descriptor {fd} could not be probed: {errno}")
            }
            Self::CloseFailed { fd, errno } => {
                write!(formatter, "descriptor {fd} could not be closed: {errno}")
            }
            Self::ResidualDescriptor(fd) => write!(
                formatter,
                "descriptor {fd} is open and outside the allowlist"
            ),
            Self::EnumerationUnattributed { stale } => write!(
                formatter,
                "{stale} descriptors vanished during enumeration, expected exactly the enumerating handle"
            ),
        }
    }
}

impl std::error::Error for DescriptorError {}

/// The exact descriptors a caller requires to survive closure.
///
/// Construction validates shape only. Whether the named descriptors are
/// actually open is decided at closure time, because that is the only moment at
/// which the answer is still true.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DescriptorAllowlist {
    /// Ascending and deduplicated, so membership is a binary search and the
    /// retained set has one spelling.
    fds: Vec<RawFd>,
}

impl DescriptorAllowlist {
    /// Retain nothing. The workload starts with no inherited descriptor at all,
    /// including no standard streams.
    #[must_use]
    pub const fn none() -> Self {
        Self { fds: Vec::new() }
    }

    /// Retain exactly `fds`.
    ///
    /// The length bound is applied to the request as written, before
    /// deduplication, so a caller that built its list from a buggy loop is told
    /// the list is wrong rather than silently handed a shorter one.
    pub fn new(fds: &[RawFd]) -> Result<Self, DescriptorError> {
        if fds.len() > MAX_ALLOWLIST_LEN {
            return Err(DescriptorError::AllowlistTooLarge {
                requested: fds.len(),
                limit: MAX_ALLOWLIST_LEN,
            });
        }
        for fd in fds {
            if *fd < 0 || *fd > MAX_ALLOWLIST_DESCRIPTOR {
                return Err(DescriptorError::DescriptorOutOfRange(*fd));
            }
        }
        let mut fds = fds.to_vec();
        fds.sort_unstable();
        fds.dedup();
        Ok(Self { fds })
    }

    /// Retain descriptors 0, 1 and 2.
    ///
    /// Nothing about the standard stream numbers is exempt from closure. This
    /// constructor exists so that a caller who has *decided* to hand stdio to
    /// the workload can say so exactly, and so that a caller who has not
    /// decided cannot get them by accident.
    #[must_use]
    pub fn standard_streams() -> Self {
        Self { fds: vec![0, 1, 2] }
    }

    /// The retained descriptors, ascending.
    #[must_use]
    pub fn as_slice(&self) -> &[RawFd] {
        &self.fds
    }

    /// Whether `fd` is retained.
    #[must_use]
    pub fn contains(&self, fd: RawFd) -> bool {
        self.fds.binary_search(&fd).is_ok()
    }

    /// Number of distinct retained descriptors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fds.len()
    }

    /// Whether nothing is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fds.is_empty()
    }
}

/// Evidence that closure happened and was checked against the kernel.
///
/// This value cannot be constructed except by a [`close_all_except`] call whose
/// verification pass succeeded, so holding one means `/proc/self/fd` was read
/// *after* the closes and contained exactly the allowlist. It does not mean the
/// condition still holds: see the module note on snapshots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescriptorClosure {
    closed: Vec<RawFd>,
    retained: Vec<RawFd>,
}

impl DescriptorClosure {
    /// Descriptors this call closed, ascending.
    #[must_use]
    pub fn closed(&self) -> &[RawFd] {
        &self.closed
    }

    /// Descriptors confirmed still open after closure, ascending. Equal to the
    /// allowlist, by verification rather than by construction.
    #[must_use]
    pub fn retained(&self) -> &[RawFd] {
        &self.retained
    }
}

/// Descriptors currently open in this process, ascending.
///
/// Enumerating requires an open directory handle, which the kernel lists among
/// the results. That handle is closed before the listing is attributed, and is
/// identified by being the only entry that is no longer open — not by its
/// number, and not by what it points at, so a caller's own handle on
/// `/proc/self/fd` is reported like any other descriptor rather than being
/// mistaken for the enumerator's.
pub fn open_descriptors() -> Result<Vec<RawFd>, DescriptorError> {
    attribute_enumeration(snapshot_at(Path::new(PROC_SELF_FD))?)
}

/// Whether `fd` is an open descriptor in this process.
///
/// `F_GETFD` asks the kernel about the descriptor table entry itself, so it
/// answers for descriptors of any type without reading, writing, or seeking
/// them.
pub fn descriptor_is_open(fd: RawFd) -> Result<bool, DescriptorError> {
    match fcntl(fd, FcntlArg::F_GETFD) {
        Ok(_) => Ok(true),
        Err(Errno::EBADF) => Ok(false),
        Err(errno) => Err(DescriptorError::ProbeFailed { fd, errno }),
    }
}

/// Close every open descriptor except those in `allowlist`, then prove it.
///
/// The order is deliberate. The allowlist is checked against the open set
/// *before* anything is closed, so a caller that named a descriptor which is
/// not open gets a refusal with its descriptors intact rather than a
/// half-closed process it cannot recover. After the closes, `/proc/self/fd` is
/// read again and required to hold exactly the allowlist; a residual descriptor
/// is an error even though every individual `close` reported success.
pub fn close_all_except(
    allowlist: &DescriptorAllowlist,
) -> Result<DescriptorClosure, DescriptorError> {
    let open = open_descriptors()?;
    for fd in allowlist.as_slice() {
        if !open.contains(fd) {
            return Err(DescriptorError::AllowlistNotOpen(*fd));
        }
    }
    let mut closed = Vec::with_capacity(open.len());
    for fd in open {
        if allowlist.contains(fd) {
            continue;
        }
        match close(fd) {
            Ok(()) => closed.push(fd),
            // Linux releases the descriptor even when `close` reports an
            // interruption, so retrying would close an unrelated descriptor
            // that reused the number. The verification pass below is what
            // decides whether this descriptor is really gone.
            Err(Errno::EINTR) => closed.push(fd),
            Err(errno) => return Err(DescriptorError::CloseFailed { fd, errno }),
        }
    }
    verify_only_allowlist_open(allowlist)?;
    Ok(DescriptorClosure {
        closed,
        retained: allowlist.as_slice().to_vec(),
    })
}

/// Confirm from `/proc/self/fd` that the open descriptors are exactly
/// `allowlist`.
///
/// This is a fresh kernel observation, not a replay of what closure believed it
/// did, which is why it is capable of contradicting it. Both directions are
/// checked: an extra descriptor is [`DescriptorError::ResidualDescriptor`], and
/// a missing allowlisted one is [`DescriptorError::AllowlistNotOpen`] — a
/// caller that asked to keep a descriptor and lost it has not been given what
/// it asked for either.
pub fn verify_only_allowlist_open(allowlist: &DescriptorAllowlist) -> Result<(), DescriptorError> {
    let open = open_descriptors()?;
    if let Some(fd) = open.iter().copied().find(|fd| !allowlist.contains(*fd)) {
        return Err(DescriptorError::ResidualDescriptor(fd));
    }
    for fd in allowlist.as_slice() {
        if !open.contains(fd) {
            return Err(DescriptorError::AllowlistNotOpen(*fd));
        }
    }
    Ok(())
}

/// Read one descriptor listing, ascending and deduplicated.
///
/// The listing includes the directory handle that produced it; the handle is
/// closed as this returns.
fn snapshot_at(directory: &Path) -> Result<Vec<RawFd>, DescriptorError> {
    let entries = fs::read_dir(directory).map_err(DescriptorError::ProcUnavailable)?;
    let mut observed = Vec::new();
    // `entries` is consumed by this loop and dropped with it, so the enumerating
    // handle is closed before any caller descriptor is probed or closed.
    for entry in entries {
        let entry = entry.map_err(DescriptorError::ProcUnavailable)?;
        if observed.len() >= MAX_OPEN_DESCRIPTORS {
            return Err(DescriptorError::TooManyDescriptors {
                limit: MAX_OPEN_DESCRIPTORS,
            });
        }
        let name = entry.file_name();
        let fd = name
            .to_str()
            .and_then(|name| name.parse::<RawFd>().ok())
            .ok_or(DescriptorError::ProcEntryUnreadable)?;
        if fd < 0 {
            return Err(DescriptorError::ProcEntryUnreadable);
        }
        observed.push(fd);
    }
    observed.sort_unstable();
    observed.dedup();
    Ok(observed)
}

/// Remove the enumerating handle from a snapshot, or refuse the snapshot.
///
/// The handle is already closed by the time this runs, so it is exactly the one
/// entry that no longer answers `F_GETFD`. Requiring precisely one such entry
/// is what makes the result attributable: zero means the number was reused
/// underneath us, and more than one means descriptors were closed concurrently.
/// In either case the listing describes no single moment and is refused.
fn attribute_enumeration(snapshot: Vec<RawFd>) -> Result<Vec<RawFd>, DescriptorError> {
    let mut live = Vec::with_capacity(snapshot.len());
    let mut stale = 0usize;
    for fd in snapshot {
        if descriptor_is_open(fd)? {
            live.push(fd);
        } else {
            stale += 1;
        }
    }
    if stale != 1 {
        return Err(DescriptorError::EnumerationUnattributed { stale });
    }
    Ok(live)
}

#[cfg(test)]
mod tests {
    use super::{DescriptorError, snapshot_at};
    use std::path::Path;

    #[test]
    fn absent_proc_listing_is_a_refusal_not_an_empty_set() {
        let error = snapshot_at(Path::new("/proc/self/automonique-absent-fd-directory"))
            .expect_err("a missing descriptor listing must refuse");
        assert!(
            matches!(error, DescriptorError::ProcUnavailable(_)),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn non_descriptor_entries_are_a_refusal() {
        // `/proc/self` lists names such as `cgroup`, which are not descriptor
        // numbers. A listing that is not the descriptor table is never read as
        // one, however plausible its location.
        let error =
            snapshot_at(Path::new("/proc/self")).expect_err("a non-descriptor listing must refuse");
        assert!(
            matches!(error, DescriptorError::ProcEntryUnreadable),
            "unexpected error: {error}"
        );
    }
}
