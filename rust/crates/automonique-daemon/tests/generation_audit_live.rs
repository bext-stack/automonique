// SPDX-License-Identifier: Elastic-2.0

//! Generation hand-offs as a real daemon actually records them.
//!
//! Every assertion here is read out of the daemon's own audit database with a
//! second handle — `automonique_store`'s public reader, opened on the path the
//! daemon chose — rather than from anything the daemon returns about itself.
//! That is the whole point: a tenure row exists to be readable by the *next*
//! process, so a test that believed an in-process value would be testing the
//! wrong side of the file.
//!
//! The holder and the epoch every test compares against come from the running
//! daemon's own `Status` answer, so a row that names some other process, or the
//! same process at some other epoch, fails rather than passing as "a row was
//! written".

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use automonique_daemon::{Daemon, DaemonConfig, DaemonError};
use automonique_protocol::admin::{AdminCommand, AdminRequest, AdminResponse};
use automonique_protocol::codec::{FrameDecode, RequestId, decode_frame, encode_frame};
use automonique_store::generation_audit::{
    EndKind, GenerationAudit, GenerationHistory, MAX_HISTORY_PAGE, TenureOpening, TenureRecord,
};
use automonique_store::{LeaseRequest, Store};

/// The generation identifier the daemon takes, mirroring its private constant.
///
/// Spelled here because the daemon does not export it. It is not taken on
/// trust: [`a_crashed_predecessor_is_superseded_by_the_successors_own_opening`]
/// seeds an expired lease under exactly this identifier and then asserts the
/// daemon came up at epoch two, which it can only do by having taken over that
/// row. A daemon that leased some other generation would come up at epoch one
/// and fail there.
const GENERATION: &str = "foreground";

fn fixture() -> (tempfile::TempDir, DaemonConfig) {
    let root = tempfile::tempdir().expect("temporary root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private root");
    let runtime = root.path().join("runtime");
    let state = root.path().join("state");
    std::fs::create_dir(&runtime).expect("runtime root");
    std::fs::create_dir(&state).expect("state root");
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))
        .expect("private runtime");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))
        .expect("private state");
    (
        root,
        DaemonConfig {
            runtime_root: runtime,
            state_root: state,
        },
    )
}

/// Create the product state directory a test needs before the daemon does.
///
/// Only the pre-seeding tests call this. Every database the daemon opens
/// requires a private, owned parent, so a test that writes one of them first
/// has to establish the directory on exactly the terms the daemon would.
fn private_state_dir(config: &DaemonConfig) {
    std::fs::create_dir(config.state_dir()).expect("state directory");
    std::fs::set_permissions(config.state_dir(), std::fs::Permissions::from_mode(0o700))
        .expect("private state directory");
}

fn now_ms() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("time fits")
}

fn call(config: &DaemonConfig, command: AdminCommand) -> AdminResponse {
    let request = AdminRequest::new(
        RequestId::new("generation-audit-1").expect("request ID"),
        command,
    );
    let mut stream = UnixStream::connect(config.admin_socket()).expect("connect to daemon");
    let payload = request
        .to_message()
        .expect("encode request")
        .to_canonical_bytes();
    let mut frame = Vec::new();
    encode_frame(&payload, &mut frame).expect("frame request");
    stream.write_all(&frame).expect("write request");
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).expect("response prefix");
    let length = u32::from_be_bytes(prefix) as usize;
    let mut response = vec![0_u8; length + 4];
    response[..4].copy_from_slice(&prefix);
    stream
        .read_exact(&mut response[4..])
        .expect("response body");
    let FrameDecode::Frame { payload, .. } = decode_frame(&response).expect("response frame")
    else {
        panic!("complete response was incomplete")
    };
    AdminResponse::from_canonical_bytes(payload).expect("admitted response")
}

/// Wait for the daemon thread to publish its endpoint.
///
/// The deadline is generous on purpose. Binding a socket costs nothing, but
/// everything before it — four SQLite databases opened `synchronous = FULL`,
/// each fsyncing its own WAL — is disk-bound, and a machine running the rest of
/// this suite concurrently can push that well past a second. A short deadline
/// here does not measure the daemon; it measures the test host.
fn wait_for_socket(config: &DaemonConfig) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !config.admin_socket().exists() {
        assert!(Instant::now() < deadline, "daemon did not bind");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// One daemon's whole life: open, serve, report its identity, stop cleanly.
///
/// Returns the `(holder_id, lease_epoch)` the daemon reported over its own
/// socket while it was running, which is what every tenure row is compared
/// against. `inspect` runs while the daemon is still live and still holds the
/// audit open, so the "a tenure is open right now" assertions are made against
/// a database with a live writer rather than a quiesced file.
fn serve_once(config: &DaemonConfig, inspect: impl FnOnce(&str, u64)) -> (String, u64) {
    let daemon = Daemon::open(config).expect("daemon opens");
    let stop = Arc::new(AtomicBool::new(false));
    let serve_stop = Arc::clone(&stop);
    let thread = std::thread::spawn(move || daemon.serve(&serve_stop));
    wait_for_socket(config);

    let AdminResponse::Status { status, .. } = call(config, AdminCommand::Status) else {
        panic!("status response expected")
    };
    let holder = status.instance_id().as_str().to_owned();
    let epoch = status.generation();
    inspect(&holder, epoch);

    assert!(matches!(
        call(config, AdminCommand::Shutdown),
        AdminResponse::ShutdownAccepted { .. }
    ));
    thread.join().expect("daemon thread").expect("clean stop");
    (holder, epoch)
}

fn audit(config: &DaemonConfig) -> GenerationAudit {
    GenerationAudit::open(config.generation_audit_path()).expect("audit reopens for reading")
}

fn history(config: &DaemonConfig) -> GenerationHistory {
    audit(config)
        .history(GENERATION, 0, MAX_HISTORY_PAGE)
        .expect("recorded history")
}

fn tenure_at(config: &DaemonConfig, epoch: u64) -> TenureRecord {
    audit(config)
        .tenure(GENERATION, epoch)
        .expect("read tenure")
        .unwrap_or_else(|| panic!("no tenure recorded at epoch {epoch}"))
}

/// A closed tenure's own coherence, asserted once instead of at four sites.
fn assert_closed(tenure: &TenureRecord, holder: &str, epoch: u64, kind: EndKind) {
    assert_eq!(tenure.holder_id, holder, "tenure names another holder");
    assert_eq!(tenure.lease_epoch, epoch);
    assert_eq!(tenure.end_kind, Some(kind), "tenure ended the wrong way");
    let ended = tenure.ended_at_ms.expect("a terminal tenure has an end");
    assert!(
        ended >= tenure.started_at_ms,
        "tenure ended at {ended} before it started at {}",
        tenure.started_at_ms
    );
    // The audit performs exactly one update per row, so `2` is the terminal
    // revision and anything else means the row was written twice.
    assert_eq!(tenure.revision, 2);
}

#[test]
fn a_live_daemon_holds_one_open_tenure_and_releases_it_on_a_clean_stop() {
    let (_root, config) = fixture();

    let (holder, epoch) = serve_once(&config, |holder, epoch| {
        // The row must exist *while the daemon runs*, not merely by the time it
        // has finished. A daemon that wrote its tenure at shutdown would have
        // recorded nothing at all had it crashed, which is the only moment the
        // record matters.
        let live = audit(&config);
        let open = live
            .latest_open(GENERATION)
            .expect("read the live audit")
            .expect("a running daemon must have an open tenure");
        assert_eq!(open.holder_id, holder, "tenure names another process");
        assert_eq!(open.lease_epoch, epoch, "tenure names another epoch");
        assert_eq!(open.generation_id, GENERATION);
        assert_eq!(open.end_kind, None, "a live tenure has not ended");
        assert_eq!(open.ended_at_ms, None);
        assert_eq!(open.revision, 1, "an open tenure is at revision one");
    });

    // A clean stop closes the row, and closes it `released` — the one end kind
    // a process may claim for itself when it stood down under its own power.
    let audit = audit(&config);
    assert_eq!(
        audit.latest_open(GENERATION).expect("read"),
        None,
        "a clean shutdown must leave no open tenure"
    );
    assert_closed(
        &tenure_at(&config, epoch),
        &holder,
        epoch,
        EndKind::Released,
    );
    // One daemon, one tenure, and nothing to hand over to.
    assert_eq!(audit.tenure_count().expect("count"), 1);
    assert_eq!(
        audit.handoff_count().expect("count"),
        0,
        "the first tenure of a generation displaced nobody"
    );
}

#[test]
fn a_restart_records_a_second_tenure_and_links_it_to_the_first() {
    let (_root, config) = fixture();

    let (first_holder, first_epoch) = serve_once(&config, |_, _| {});
    let (second_holder, second_epoch) = serve_once(&config, |holder, epoch| {
        let live = audit(&config);
        let open = live
            .latest_open(GENERATION)
            .expect("read the live audit")
            .expect("the successor must have its own open tenure");
        assert_eq!(open.holder_id, holder);
        assert_eq!(open.lease_epoch, epoch);
    });

    assert_ne!(
        second_holder, first_holder,
        "a restarted daemon is a different holder"
    );
    assert!(
        second_epoch > first_epoch,
        "the successor's epoch {second_epoch} must be above {first_epoch}"
    );

    let history = history(&config);
    assert_eq!(history.tenures.len(), 2, "both tenures must be recorded");
    let [first, second] = history.tenures.as_slice() else {
        panic!("two tenures expected")
    };
    // Oldest first, and the predecessor's terminal state survives the
    // succession untouched: a closed row is never rewritten, not even by the
    // process that displaced it.
    assert_closed(first, &first_holder, first_epoch, EndKind::Released);
    assert_closed(second, &second_holder, second_epoch, EndKind::Released);

    // The successor owed the log an observation of what it displaced, and a
    // clean predecessor is still something to have displaced. Without this row
    // the history would be two unrelated tenures rather than a hand-off.
    assert_eq!(history.handoffs.len(), 1, "the restart is one hand-off");
    let handoff = &history.handoffs[0];
    assert_eq!(handoff.predecessor_epoch, first_epoch);
    assert_eq!(handoff.successor_epoch, second_epoch);
    assert_eq!(handoff.predecessor_tenure_id, first.tenure_id);
    assert_eq!(handoff.successor_tenure_id, second.tenure_id);
    assert_eq!(
        handoff.predecessor_end_kind,
        EndKind::Released,
        "the predecessor closed its own row, so the hand-off must say so"
    );
    assert!(handoff.observed_at_ms >= second.started_at_ms);
}

#[test]
fn a_crashed_predecessor_is_superseded_by_the_successors_own_opening() {
    let (_root, config) = fixture();
    private_state_dir(&config);
    let crashed_at = now_ms() - 60_000;

    // A predecessor that took the generation and died: its lease lapsed
    // without ever being released, and its tenure row is still open. Both
    // halves are seeded, because both are what a crash leaves behind — the
    // store fence and the audit are separate databases, and a real crash
    // leaves the pair in exactly this state.
    {
        let mut store = Store::open(config.database_path()).expect("seed the store");
        let lease = store
            .acquire_generation_lease(LeaseRequest {
                generation_id: GENERATION,
                holder_id: "crashed-holder",
                now_ms: crashed_at,
                ttl_ms: 1_000,
            })
            .expect("predecessor generation lease");
        assert_eq!(lease.epoch, 1);
        assert!(
            lease.expires_ms < now_ms(),
            "the seeded lease must already have lapsed, or the daemon would \
             be refused rather than take over"
        );
    }
    {
        let mut seeded = GenerationAudit::open(config.generation_audit_path())
            .expect("seed the generation audit");
        seeded
            .open_tenure(TenureOpening {
                generation_id: GENERATION,
                holder_id: "crashed-holder",
                lease_epoch: 1,
                started_at_ms: crashed_at,
            })
            .expect("predecessor tenure");
    }

    let (holder, epoch) = serve_once(&config, |holder, epoch| {
        // Taking over the *seeded* generation is what proves this daemon leases
        // the identifier these rows are keyed by: a daemon on some other
        // generation would have come up at epoch one.
        assert_eq!(epoch, 2, "the successor must take the next epoch");
        assert_ne!(holder, "crashed-holder");

        // The succession is one transaction, so by the time the daemon is
        // serving, both halves of it are durable: the predecessor is closed
        // and the successor is open. Neither can be observed without the
        // other.
        let live = audit(&config);
        let predecessor = live
            .tenure(GENERATION, 1)
            .expect("read")
            .expect("the seeded tenure must still be recorded");
        assert_closed(&predecessor, "crashed-holder", 1, EndKind::Superseded);
        let open = live
            .latest_open(GENERATION)
            .expect("read")
            .expect("the successor must have an open tenure");
        assert_eq!(open.holder_id, holder);
        assert_eq!(open.lease_epoch, epoch);
        // The predecessor's end is dated at the successor's start: the
        // acquisition is the first instant at which anything durably knew that
        // tenure was over.
        assert_eq!(predecessor.ended_at_ms, Some(open.started_at_ms));
    });

    let history = history(&config);
    assert_eq!(history.tenures.len(), 2);
    let [predecessor, successor] = history.tenures.as_slice() else {
        panic!("two tenures expected")
    };
    // `superseded` is the successor's word about the predecessor, and it stays
    // that way after the successor closes its own row `released`.
    assert_closed(predecessor, "crashed-holder", 1, EndKind::Superseded);
    assert_closed(successor, &holder, epoch, EndKind::Released);

    assert_eq!(history.handoffs.len(), 1);
    let handoff = &history.handoffs[0];
    assert_eq!(handoff.predecessor_tenure_id, predecessor.tenure_id);
    assert_eq!(handoff.successor_tenure_id, successor.tenure_id);
    assert_eq!(handoff.predecessor_epoch, 1);
    assert_eq!(handoff.successor_epoch, epoch);
    assert_eq!(
        handoff.predecessor_end_kind,
        EndKind::Superseded,
        "a predecessor that never closed its own row is superseded, not released"
    );
}

#[test]
fn an_unopenable_audit_refuses_startup_without_publishing_a_socket() {
    let (_root, config) = fixture();
    private_state_dir(&config);
    // A directory where the audit database must be. Nothing else the daemon
    // opens touches this path, so the refusal below is this guard and no other.
    std::fs::create_dir(config.generation_audit_path()).expect("invalid audit path");

    let error = Daemon::open(&config)
        .err()
        .expect("an unopenable generation audit must refuse startup");
    assert!(
        matches!(error, DaemonError::GenerationAuditFailed(_)),
        "expected GenerationAuditFailed, got {error:?}"
    );
    assert_eq!(error.category(), "insecure_path");
    assert!(
        !config.admin_socket().exists(),
        "a refused startup must not leave the admin socket bound"
    );
}

#[test]
fn an_audit_ahead_of_the_lease_store_refuses_startup_rather_than_reusing_an_epoch() {
    let (_root, config) = fixture();
    private_state_dir(&config);

    // The lease lives in one database and this log in another. A main database
    // that was restored, replaced or deleted out from under the audit hands the
    // daemon an epoch the log has already recorded, and writing a second tenure
    // there would call two different processes the same authority.
    {
        let mut seeded = GenerationAudit::open(config.generation_audit_path())
            .expect("seed the generation audit");
        seeded
            .open_tenure(TenureOpening {
                generation_id: GENERATION,
                holder_id: "holder-from-a-lost-database",
                lease_epoch: 5,
                started_at_ms: now_ms() - 60_000,
            })
            .expect("recorded tenure");
    }

    let error = Daemon::open(&config)
        .err()
        .expect("an audit ahead of the lease store must refuse startup");
    assert!(
        matches!(error, DaemonError::GenerationAuditFailed(_)),
        "expected GenerationAuditFailed, got {error:?}"
    );
    assert_eq!(error.category(), "epoch_regression");
    assert!(
        !config.admin_socket().exists(),
        "a refused startup must not leave the admin socket bound"
    );
    // Refused, and nothing written: the log still holds exactly what was seeded.
    let audit = audit(&config);
    assert_eq!(audit.tenure_count().expect("count"), 1);
    assert!(
        audit
            .latest_open(GENERATION)
            .expect("read")
            .is_some_and(|tenure| tenure.holder_id == "holder-from-a-lost-database"),
        "the refused daemon must not have closed or displaced the seeded tenure"
    );
}
