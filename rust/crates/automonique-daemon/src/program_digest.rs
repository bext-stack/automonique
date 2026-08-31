// SPDX-License-Identifier: Elastic-2.0

//! One observation of the bytes behind a pinned program path.
//!
//! A provider executable is hundreds of megabytes, and every launch has to know
//! which bytes are at the path the document pins. Doing that read and that
//! SHA-256 where the request arrives puts the whole cost on the daemon's accept
//! thread: [`crate::Daemon::serve`] calls `handle_stream` inline, so for as long
//! as one start is hashing, every other admin, Runs and Platform exchange sits
//! in the listener backlog. Measured on a 150 MiB program with a warm page
//! cache, that is 173 ms per read — and a start that also passes the approval
//! gate paid it twice, because the gate and the execution lane each read the
//! file for themselves.
//!
//! This module is where that work goes instead. It is one thread and one small
//! set of observations, and it changes *where* and *how often* the bytes are
//! read. It does not change what is compared, who compares it, or what happens
//! when the comparison fails.
//!
//! # What an observation is
//!
//! [`ProgramDigests::digest`] opens the path, reads the opened descriptor to the
//! end in fixed-size chunks, and returns `sha256:<hex>` over exactly those
//! bytes. Nothing is buffered whole: the previous path allocated a `Vec` the
//! size of the program before hashing it, and a 512 MiB ceiling on the accept
//! thread meant a 512 MiB allocation there too.
//!
//! # When a remembered observation is reused
//!
//! An observation is remembered against the identity of the file it was read
//! from — device, inode, length, and both the modification and change
//! timestamps to the nanosecond — read from the same descriptor the bytes came
//! from, before and after the read. It is reused only when a later open of the
//! same path presents all of them unchanged, and it is remembered at all only
//! for a file no group and no other user may write, which is the same condition
//! `automonique_runner`'s entry helper already requires of a program it will
//! execute.
//!
//! Rewriting a file's contents advances its change timestamp, and no userspace
//! call can set that timestamp; replacing the file gives a new inode, and a
//! recycled inode number arrives with a later change timestamp than the one
//! remembered. So reuse means the bytes have not moved.
//!
//! # What this is not, stated plainly
//!
//! **This is not the check that stands between the pinned path and the process,
//! and it never was.** That check is `staged_verified_program_descriptor` in
//! [`automonique_runner::launch`]: the entry helper opens the program *again*,
//! copies it to a staged file while hashing what it copies, and refuses on
//! `program digest mismatch` unless the copy hashes to the digest the launch
//! plan carries. The plan's digest is the observed digest, and
//! [`automonique_runner::admission::admit`] refuses unless the observed digest
//! equals the document's own pin. So the bytes lifted off the pinned path at
//! launch are hashed, at launch, against the pin — by a read this daemon does
//! not perform and this module does not affect.
//!
//! What an observation here buys is a *synchronous typed refusal*
//! (`ExecuteRefusal::ProviderBinaryUnverified`) for a program whose bytes do not
//! match the pin, instead of an accepted request whose attempt dies in the
//! helper. If a remembered observation were ever stale — bytes changed with the
//! device, inode, length, modification time and change time all identical, on a
//! file only its owner can write — the cost is exactly that: the mismatch is
//! **verified later**, in the helper, rather than at the request. No approval is
//! spent on bytes nobody checked, and no byte reaches a process without the
//! helper having hashed it.
//!
//! What the helper does with the staged copy *after* it has hashed it — it is a
//! named same-uid-writable inode under `/tmp` until
//! `automonique_runner::filesystem` removes its path — is that module's window
//! and neither this one's nor the daemon's. Nothing here is read by it, nothing
//! here narrows it, and nothing here would narrow it if it were closed: both of
//! this daemon's reads happen before the helper process exists.

use std::collections::VecDeque;
use std::fs::{File, Metadata};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use sha2::Digest as _;

use automonique_protocol::digest::ALGORITHM;

/// Observations kept at once.
///
/// A deployment runs one provider executable, and a document that pins another
/// is the exception rather than the fleet. This is a memory bound on a map of
/// paths to 64 hexadecimal characters, not a working-set estimate, and the cost
/// of missing it is one read that would otherwise have happened anyway.
const MAX_REMEMBERED_PROGRAMS: usize = 8;

/// Requests the prefetch queue holds before it starts refusing them.
///
/// [`ProgramDigests::prefetch`] never blocks: a full queue means the worker is
/// already behind, and the caller — a request thread — must not wait on it. A
/// dropped prefetch costs the later read that would have happened without this
/// module at all.
const MAX_PENDING_PREFETCHES: usize = 32;

/// Chunk the program is read and hashed in.
///
/// Large enough that the read syscall is not the cost, small enough that the
/// buffer is not an allocation worth thinking about.
const READ_CHUNK_BYTES: usize = 256 * 1024;

/// The identity of one opened file, as the kernel reports it.
///
/// Every field is read from the descriptor the bytes are read from, never from
/// a `stat` of the path, so it describes the file that was actually opened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileIdentity {
    fn of(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

/// One remembered observation.
#[derive(Debug)]
struct Observation {
    path: PathBuf,
    identity: FileIdentity,
    digest: String,
}

/// The observations this daemon is holding, oldest first.
#[derive(Debug, Default)]
struct Remembered {
    observations: VecDeque<Observation>,
}

impl Remembered {
    /// The digest observed for exactly this path at exactly this identity.
    fn digest(&self, path: &Path, identity: FileIdentity) -> Option<String> {
        self.observations
            .iter()
            .find(|observation| observation.path == path && observation.identity == identity)
            .map(|observation| observation.digest.clone())
    }

    /// Remember one observation, replacing any earlier one for the same path.
    fn remember(&mut self, path: &Path, identity: FileIdentity, digest: &str) {
        self.observations
            .retain(|observation| observation.path != path);
        if self.observations.len() >= MAX_REMEMBERED_PROGRAMS {
            self.observations.pop_front();
        }
        self.observations.push_back(Observation {
            path: path.to_path_buf(),
            identity,
            digest: digest.to_owned(),
        });
    }
}

/// Shared between the worker and every request thread.
#[derive(Debug, Default)]
struct Shared {
    remembered: Mutex<Remembered>,
    /// How many times bytes were actually read and hashed.
    ///
    /// The counter exists so a test can assert that a second observation of an
    /// unchanged file reads nothing, which is a claim no timing can make
    /// honestly.
    reads: AtomicUsize,
}

/// Provider-program digests, observed once and reused while the bytes hold
/// still.
///
/// Held by [`crate::Daemon`] and, by a cloned [`Arc`], by
/// [`crate::execute::ExecutionLane`], so the approval gate and the execution
/// lane observe one program once between them rather than once each.
#[derive(Debug)]
pub struct ProgramDigests {
    shared: Arc<Shared>,
    /// `None` only after [`Drop`] has taken it, which ends the worker.
    requests: Option<SyncSender<PathBuf>>,
    worker: Option<JoinHandle<()>>,
}

impl ProgramDigests {
    /// Start the observer thread and hand back the shared handle.
    ///
    /// The thread does nothing until something is prefetched, and it ends when
    /// the last handle is dropped.
    #[must_use]
    pub fn start() -> Arc<Self> {
        let shared = Arc::new(Shared::default());
        let (requests, incoming) = sync_channel(MAX_PENDING_PREFETCHES);
        let worker_shared = Arc::clone(&shared);
        let worker = std::thread::Builder::new()
            .name("automonique-program-digest".to_owned())
            .spawn(move || observe_requested(&worker_shared, &incoming))
            .ok();
        Arc::new(Self {
            shared,
            requests: Some(requests),
            worker,
        })
    }

    /// Ask the worker to observe `path` before anybody needs the answer.
    ///
    /// Never blocks and never reports: a request thread calling this is buying
    /// a later request's latency, not its own correctness. A path that is
    /// already observed costs the worker one open and one `fstat`.
    pub fn prefetch(&self, path: &Path) {
        if let Some(requests) = self.requests.as_ref() {
            let _ = requests.try_send(path.to_path_buf());
        }
    }

    /// The digest of the bytes at `path`, refusing above `limit` bytes.
    ///
    /// `None` for a path that is not a readable regular file, or one larger
    /// than the ceiling — the same answer, and the same ceiling, the caller
    /// would have reached reading the file itself.
    #[must_use]
    pub fn digest(&self, path: &Path, limit: u64) -> Option<String> {
        observe(&self.shared, path, limit)
    }

    /// How many times this daemon has read and hashed a program.
    #[must_use]
    pub fn reads(&self) -> usize {
        self.shared.reads.load(Ordering::Acquire)
    }
}

impl Drop for ProgramDigests {
    /// End the worker and join it.
    ///
    /// Dropping the sender is what ends the loop, so it is dropped explicitly
    /// before the join rather than left to field order. The join waits for at
    /// most one program's read, which is bounded by the caller's own ceiling.
    fn drop(&mut self) {
        drop(self.requests.take());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// The digest of one program file, remembering nothing.
///
/// The one place a caller belongs that has no observer to share — the run
/// lane's composer hashes the configured provider on its own worker thread,
/// and threading a handle from the daemon through
/// [`crate::compose::CompositionInputs`] to reach it would be a parameter on
/// thirteen call sites to save a read that is not on the accept thread. What
/// it does get from here is the streaming read: the composer buffered the
/// whole program before hashing it.
#[must_use]
pub fn digest_of_program(path: &Path, limit: u64) -> Option<String> {
    let (file, _) = open_program(path, limit)?;
    hash_bounded(&file, limit)
}

/// The worker loop: observe what is asked for, and end when nobody can ask.
fn observe_requested(shared: &Arc<Shared>, incoming: &Receiver<PathBuf>) {
    while let Ok(path) = incoming.recv() {
        let _ = observe(shared, &path, crate::execute::MAX_PROVIDER_BINARY_BYTES);
    }
}

/// Open one program file, refusing anything that is not a regular file within
/// `limit` bytes.
///
/// The length is taken from the opened descriptor's own metadata rather than
/// from a `stat` of the path, so the bound is applied to the file that was
/// actually opened.
fn open_program(path: &Path, limit: u64) -> Option<(File, Metadata)> {
    let file = File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || !crate::execute::is_within_byte_limit(metadata.len(), limit) {
        return None;
    }
    Some((file, metadata))
}

/// Observe one program, reusing a remembered observation of the same bytes.
///
/// The lock is held for the lookup and for the insertion, never across the
/// read: a request thread must not wait behind the worker hashing a different
/// program, and two threads observing the same program at once cost one
/// duplicate read rather than a queue.
fn observe(shared: &Arc<Shared>, path: &Path, limit: u64) -> Option<String> {
    let (file, metadata) = open_program(path, limit)?;
    let identity = FileIdentity::of(&metadata);
    if let Ok(remembered) = shared.remembered.lock()
        && let Some(digest) = remembered.digest(path, identity)
    {
        return Some(digest);
    }

    let digest = hash_bounded(&file, limit)?;
    shared.reads.fetch_add(1, Ordering::AcqRel);

    // Read from the same descriptor once the bytes are hashed. A file rewritten
    // while it was being read has a later change timestamp, and remembering an
    // observation of bytes that are already gone is the one thing this must not
    // do. A program any other user may write is never remembered at all, which
    // is the entry helper's own condition for executing one.
    let after = FileIdentity::of(&file.metadata().ok()?);
    if after == identity
        && metadata.permissions().mode() & 0o022 == 0
        && let Ok(mut remembered) = shared.remembered.lock()
    {
        remembered.remember(path, identity, &digest);
    }
    Some(digest)
}

/// Hash a whole open file in chunks, or nothing above `limit` bytes.
///
/// Bounded by one byte over the limit, so a file that grew between its metadata
/// and its read is refused rather than hashed part-way — the rule
/// `execute::read_bounded` applied when it buffered the file whole.
fn hash_bounded(file: &File, limit: u64) -> Option<String> {
    let mut reader = file.take(limit.saturating_add(1));
    let mut hasher = sha2::Sha256::new();
    let mut buffer = vec![0_u8; READ_CHUNK_BYTES];
    let mut read_bytes = 0_u64;
    loop {
        let read = reader.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        read_bytes = read_bytes.checked_add(u64::try_from(read).ok()?)?;
        hasher.update(&buffer[..read]);
    }
    if !crate::execute::is_within_byte_limit(read_bytes, limit) {
        return None;
    }
    Some(format!("{ALGORITHM}:{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::{MAX_REMEMBERED_PROGRAMS, ProgramDigests};
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    const LIMIT: u64 = 8 * 1024 * 1024;

    /// A program file with the mode the entry helper requires of one.
    fn program(directory: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = directory.join(name);
        let mut file = std::fs::File::create(&path).expect("create the program");
        file.write_all(bytes).expect("write the program");
        file.sync_all().expect("flush the program");
        drop(file);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("program mode");
        path
    }

    /// What the kernel reports as this file's change timestamp.
    fn changed_at(path: &Path) -> (i64, i64) {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = std::fs::metadata(path).expect("program metadata");
        (metadata.ctime(), metadata.ctime_nsec())
    }

    /// Rewrite a file in place, and wait until the kernel reports a different
    /// change timestamp than the one it had.
    ///
    /// A rewrite inside one timestamp tick would leave the identity unchanged,
    /// which is precisely the case a remembered digest is *allowed* to be
    /// reused in, so a test asserting the re-read has to establish that it is
    /// not that case.
    fn rewrite(path: &Path, bytes: &[u8]) {
        let before = changed_at(path);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            std::fs::write(path, bytes).expect("rewrite the program");
            if changed_at(path) != before {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the change timestamp never moved"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// The spelling is the canonical one, over the bytes in the file.
    ///
    /// `abc` is the SHA-256 test vector, so this fails against a hash of the
    /// path, of a length prefix, or of anything but the file's own bytes.
    #[test]
    fn a_digest_is_the_canonical_sha256_of_the_files_bytes() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = program(directory.path(), "abc", b"abc");
        let digests = ProgramDigests::start();

        assert_eq!(
            digests.digest(&path, LIMIT).as_deref(),
            Some("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        );
    }

    /// The second observation of an unchanged program reads nothing.
    ///
    /// This is the whole of what takes the read off the request thread: a start
    /// that passes the approval gate observes the program twice, and a lane that
    /// re-read it would pay for both.
    #[test]
    fn an_unchanged_program_is_read_once() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = program(directory.path(), "provider", b"the provider's bytes");
        let digests = ProgramDigests::start();

        let first = digests.digest(&path, LIMIT).expect("the first observation");
        let second = digests
            .digest(&path, LIMIT)
            .expect("the second observation");

        assert_eq!(first, second);
        assert_eq!(
            digests.reads(),
            1,
            "an unchanged program was read {} times",
            digests.reads()
        );
    }

    /// A program whose bytes moved is read again, and reports the new bytes.
    ///
    /// The anti-vacuity half of the case above: a cache that never expired
    /// would pass that one and fail this one.
    #[test]
    fn a_rewritten_program_is_read_again() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = program(directory.path(), "provider", b"the provider's bytes");
        let digests = ProgramDigests::start();

        let first = digests.digest(&path, LIMIT).expect("the first observation");
        rewrite(&path, b"somebody else's bytes");
        let second = digests
            .digest(&path, LIMIT)
            .expect("the second observation");

        assert_ne!(
            first, second,
            "a rewritten program reported the digest of bytes that are gone"
        );
        assert_eq!(digests.reads(), 2, "the rewritten program was not re-read");
    }

    /// A program another user may write is never remembered.
    ///
    /// The entry helper refuses to execute such a file at all, so nothing is
    /// lost by re-reading it — and reusing an observation of a file the world
    /// can rewrite would be reuse without the identity argument behind it.
    #[test]
    fn a_group_writable_program_is_read_every_time() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = program(directory.path(), "loose", b"anybody's bytes");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o775))
            .expect("group-writable mode");
        let digests = ProgramDigests::start();

        let first = digests.digest(&path, LIMIT).expect("the first observation");
        let second = digests
            .digest(&path, LIMIT)
            .expect("the second observation");

        assert_eq!(first, second);
        assert_eq!(
            digests.reads(),
            2,
            "a group-writable program was remembered"
        );
    }

    /// One path's observation is never answered for another path.
    #[test]
    fn an_observation_is_not_reused_for_another_path() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let first = program(directory.path(), "first", b"first bytes");
        let second = program(directory.path(), "second", b"second bytes");
        let digests = ProgramDigests::start();

        let first_digest = digests.digest(&first, LIMIT).expect("first observation");
        let second_digest = digests.digest(&second, LIMIT).expect("second observation");

        assert_ne!(first_digest, second_digest);
        assert_eq!(digests.reads(), 2);
    }

    /// A prefetched program is observed by the worker, so the request that
    /// needs it reads nothing.
    ///
    /// This is the property the accept thread is being freed by: the read
    /// happened on another thread, before the request that needed it arrived.
    #[test]
    fn a_prefetched_program_is_not_read_by_the_caller() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = program(directory.path(), "provider", b"the provider's bytes");
        let digests = ProgramDigests::start();

        digests.prefetch(&path);
        let deadline = Instant::now() + Duration::from_secs(5);
        while digests.reads() == 0 {
            assert!(Instant::now() < deadline, "the worker never observed it");
            std::thread::sleep(Duration::from_millis(1));
        }

        let digest = digests.digest(&path, LIMIT).expect("the observation");
        assert_eq!(
            digests.reads(),
            1,
            "the caller re-read a program the worker had already observed"
        );
        assert!(digest.starts_with("sha256:"));
    }

    /// Nothing above the ceiling is observed, and nothing below it is refused
    /// for being close to it.
    #[test]
    fn the_ceiling_refuses_a_larger_program_and_admits_an_exact_one() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let exact = program(directory.path(), "exact", &[7_u8; 64]);
        let larger = program(directory.path(), "larger", &[7_u8; 65]);
        let digests = ProgramDigests::start();

        assert!(digests.digest(&exact, 64).is_some());
        assert!(digests.digest(&larger, 64).is_none());
    }

    /// Remembering is bounded, and the bound evicts rather than refusing.
    #[test]
    fn the_remembered_set_is_bounded() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let digests = ProgramDigests::start();
        let paths: Vec<PathBuf> = (0..=MAX_REMEMBERED_PROGRAMS)
            .map(|index| {
                program(
                    directory.path(),
                    &format!("program-{index}"),
                    format!("bytes {index}").as_bytes(),
                )
            })
            .collect();

        for path in &paths {
            digests.digest(path, LIMIT).expect("observed");
        }
        assert_eq!(digests.reads(), paths.len());

        // The newest is still remembered; the oldest was evicted for it.
        digests
            .digest(&paths[paths.len() - 1], LIMIT)
            .expect("newest");
        assert_eq!(digests.reads(), paths.len(), "the newest was evicted");
        digests.digest(&paths[0], LIMIT).expect("oldest");
        assert_eq!(
            digests.reads(),
            paths.len() + 1,
            "the oldest survived a bound it should have been evicted by"
        );
    }

    /// A path that is not a readable regular file is no observation at all.
    #[test]
    fn a_directory_and_a_missing_path_are_not_observed() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let digests = ProgramDigests::start();

        assert!(digests.digest(directory.path(), LIMIT).is_none());
        assert!(
            digests
                .digest(&directory.path().join("absent"), LIMIT)
                .is_none()
        );
        assert_eq!(digests.reads(), 0);
    }
}
