// SPDX-License-Identifier: Elastic-2.0

//! Feasibility spike: an unprivileged FUSE filesystem with exact byte and
//! object ceilings, for the runner's `temporary_storage` budget.
//!
//! Not product code. `README.md` beside this crate records what the spike
//! proves on this host, what it does not, and the design questions it
//! answers. The crate is organised as the runner would be:
//!
//! - [`ledger`] is the accounting: every byte and object is reserved there
//!   before it exists, and every refusal is a typed [`Exceedance`].
//! - [`filesystem`] is the FUSE implementation over that ledger.
//! - [`mount`] is mount ownership: fail-closed prerequisites, the
//!   `fusermount3` handshake by explicit argument vector, and unmount.
//! - [`readback`] is what the kernel says about the mountpoint, which is the
//!   only evidence any claim above rests on.

pub mod filesystem;
pub mod ledger;
pub mod mount;
pub mod readback;

pub use ledger::{
    CeilingError, Ceilings, Exceedance, Ledger, LedgerSnapshot, MAX_NAME_BYTES,
    MAX_RECORDED_EXCEEDANCES, Resource, STATFS_BLOCK_BYTES, StatfsView,
};
pub use mount::{
    AutoUnmountProbe, DEFAULT_DEV_FUSE, DEFAULT_FUSERMOUNT3, FS_NAME, FS_SUBTYPE,
    FusePrerequisites, MountError, MountedTempfs, Outcome, PrerequisiteError, UnmountError,
    VerifiedFuse, detach_stale, probe_auto_unmount,
};
pub use readback::{
    MOUNTINFO, MountEvidence, MountStatus, StatfsReadback, inspect, mount_evidence,
    parse_mountinfo, statfs_readback,
};
