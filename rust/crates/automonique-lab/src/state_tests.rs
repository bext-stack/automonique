// SPDX-License-Identifier: Elastic-2.0

use std::time::Duration;

use crate::protocol::{OpaqueId, Sha256Digest};
use crate::state::{
    AcquirePaths, AppendRecord, AttemptState, ControllerRoot, EffectIntent, EffectResult,
    EffectStatus, JournalKind, RecordAuthority, ReleasePaths, StateError, StateStore,
    TransitionAttempt,
};
use crate::workspace_lease::{
    ActionId, AttemptId, BaseRevision, FenceEpoch, LeaseId, Mutation, RepoPath, Revision,
};
use rusqlite::Connection;
use tempfile::tempdir;

const BASE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn open_state(path: impl AsRef<std::path::Path>) -> Result<StateStore, StateError> {
    prepare_test_state_parent(path.as_ref());
    StateStore::open(&ControllerRoot { seal: () }, path)
}

fn open_state_timeout(
    path: impl AsRef<std::path::Path>,
    timeout: Duration,
) -> Result<StateStore, StateError> {
    prepare_test_state_parent(path.as_ref());
    StateStore::open_with_timeout(&ControllerRoot { seal: () }, path, timeout)
}

fn prepare_test_state_parent(path: &std::path::Path) {
    #[cfg(unix)]
    if let Some(parent) = path.parent()
        && let Ok(metadata) = std::fs::symlink_metadata(parent)
        && metadata.is_dir()
        && !metadata.file_type().is_symlink()
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .expect("test state parent becomes private");
    }
}

fn attempt(value: &str) -> AttemptId {
    AttemptId::parse(value).expect("test attempt ID is valid")
}

fn action(value: &str) -> ActionId {
    ActionId::parse(value).expect("test action ID is valid")
}

fn lease(value: &str) -> LeaseId {
    LeaseId::parse(value).expect("test lease ID is valid")
}

fn path(value: &str) -> RepoPath {
    RepoPath::parse(value).expect("test path is valid")
}

fn base() -> BaseRevision {
    BaseRevision::parse(BASE).expect("test base is valid")
}

fn objective(value: &str) -> OpaqueId {
    OpaqueId::new(value).expect("test objective ID is valid")
}

fn digest(byte: char) -> Sha256Digest {
    Sha256Digest::new(byte.to_string().repeat(64)).expect("test digest is valid")
}

#[test]
fn active_lease_proof_is_exact_instance_bound_and_revoked_on_release() {
    let directory = tempdir().expect("temporary directory");
    let mut first = open_state(directory.path().join("first.sqlite3")).expect("first store");
    let second = open_state(directory.path().join("second.sqlite3")).expect("second store");
    let authority = first.broker_authority();
    first
        .create_attempt(
            &authority,
            attempt("proof-attempt"),
            objective("proof-objective"),
            base(),
        )
        .expect("attempt created");
    let acquired = first
        .acquire_paths(
            &authority,
            AcquirePaths {
                action_id: action("proof-acquire"),
                lease_id: lease("proof-lease"),
                attempt_id: attempt("proof-attempt"),
                base_revision: base(),
                expected_revision: Revision::default(),
                paths: vec![path("leased")],
            },
        )
        .expect("lease acquired");
    let receipt = acquired.receipt().clone();
    first
        .verify_active_lease(
            &authority,
            &attempt("proof-attempt"),
            &lease("proof-lease"),
            receipt.epoch,
            &base(),
            vec![path("leased")],
        )
        .expect("exact active lease verified");

    let foreign_authority = second.broker_authority();
    assert!(matches!(
        first.verify_active_lease(
            &foreign_authority,
            &attempt("proof-attempt"),
            &lease("proof-lease"),
            receipt.epoch,
            &base(),
            vec![path("leased")],
        ),
        Err(StateError::AuthorityDenied)
    ));
    assert!(matches!(
        first.verify_active_lease(
            &authority,
            &attempt("proof-attempt"),
            &lease("proof-lease"),
            FenceEpoch::from_u64(receipt.epoch.get() + 1),
            &base(),
            vec![path("leased")],
        ),
        Err(StateError::Fenced { .. })
    ));

    first
        .transition(
            &authority,
            TransitionAttempt {
                action_id: action("proof-terminal"),
                attempt_id: attempt("proof-attempt"),
                base_revision: base(),
                expected_revision: receipt.revision,
                target: AttemptState::Cancelled,
                event_digest: digest('b'),
            },
        )
        .expect("terminal transition releases lease");
    assert!(matches!(
        first.verify_active_lease(
            &authority,
            &attempt("proof-attempt"),
            &lease("proof-lease"),
            receipt.epoch,
            &base(),
            vec![path("leased")],
        ),
        Err(StateError::LeaseInactive)
    ));
}

fn transition(
    store: &mut StateStore,
    attempt_id: &str,
    action_id: &str,
    expected_revision: u64,
    target: AttemptState,
) {
    let broker = store.broker_authority();
    let mutation = store
        .transition(
            &broker,
            TransitionAttempt {
                action_id: action(action_id),
                attempt_id: attempt(attempt_id),
                base_revision: base(),
                expected_revision: Revision::from_u64(expected_revision),
                target,
                event_digest: digest('a'),
            },
        )
        .expect("transition succeeds");
    assert!(matches!(mutation, Mutation::Applied(_)));
}

#[test]
fn restart_preserves_attempt_journal_effect_and_lease_state() {
    let directory = tempdir().expect("temporary directory");
    let database = directory.path().join("state.sqlite3");

    let mut store = open_state(&database).expect("state opens");
    let broker = store.broker_authority();
    assert_eq!(store.schema_version().expect("schema version"), 1);
    store
        .create_attempt(
            &broker,
            attempt("attempt-1"),
            objective("objective-1"),
            base(),
        )
        .expect("attempt created");
    transition(&mut store, "attempt-1", "start-1", 0, AttemptState::Running);

    let checkpoint = store
        .append_record(
            &broker,
            AppendRecord {
                attempt_id: attempt("attempt-1"),
                base_revision: base(),
                expected_revision: Revision::from_u64(1),
                record_id: action("checkpoint-1"),
                kind: JournalKind::Checkpoint,
                payload_digest: digest('b'),
            },
        )
        .expect("checkpoint committed");
    assert_eq!(checkpoint.receipt().sequence(), 2);
    let wrong_checkpoint_replay = store.append_record(
        &broker,
        AppendRecord {
            attempt_id: attempt("attempt-1"),
            base_revision: base(),
            expected_revision: Revision::default(),
            record_id: action("checkpoint-1"),
            kind: JournalKind::Checkpoint,
            payload_digest: digest('b'),
        },
    );
    assert!(matches!(
        wrong_checkpoint_replay,
        Err(StateError::RecordConflict)
    ));

    store
        .record_effect_intent(
            &broker,
            EffectIntent {
                attempt_id: attempt("attempt-1"),
                base_revision: base(),
                expected_revision: Revision::from_u64(2),
                idempotency_key: action("effect-1"),
                request_digest: digest('c'),
            },
        )
        .expect("effect intent committed");
    let grant = store
        .acquire_paths(
            &broker,
            AcquirePaths {
                action_id: action("acquire-1"),
                lease_id: lease("lease-1"),
                attempt_id: attempt("attempt-1"),
                base_revision: base(),
                expected_revision: Revision::from_u64(3),
                paths: vec![path("rust/crates/automonique-lab")],
            },
        )
        .expect("lease committed");
    assert_eq!(grant.receipt().epoch.get(), 1);
    drop(store);

    let mut reopened = open_state(&database).expect("state reopens");
    let reopened_broker = reopened.broker_authority();
    let snapshot = reopened
        .attempt(&attempt("attempt-1"))
        .expect("attempt query")
        .expect("attempt exists");
    assert_eq!(snapshot.state(), AttemptState::Running);
    assert_eq!(snapshot.revision(), Revision::from_u64(4));
    assert_eq!(snapshot.last_sequence(), 2);
    assert_eq!(
        reopened
            .journal(&attempt("attempt-1"))
            .expect("journal")
            .len(),
        2
    );
    assert_eq!(reopened.active_leases().expect("leases").len(), 1);
    assert_eq!(
        reopened
            .effect(&attempt("attempt-1"), &action("effect-1"))
            .expect("effect query")
            .expect("effect exists")
            .status(),
        EffectStatus::Pending
    );
    let replayed_intent = reopened
        .record_effect_intent(
            &reopened_broker,
            EffectIntent {
                attempt_id: attempt("attempt-1"),
                base_revision: base(),
                expected_revision: Revision::from_u64(2),
                idempotency_key: action("effect-1"),
                request_digest: digest('c'),
            },
        )
        .expect("effect intent replayed after restart");
    assert!(matches!(replayed_intent, Mutation::Replayed(_)));
    let wrong_intent_replay = reopened.record_effect_intent(
        &reopened_broker,
        EffectIntent {
            attempt_id: attempt("attempt-1"),
            base_revision: base(),
            expected_revision: Revision::from_u64(3),
            idempotency_key: action("effect-1"),
            request_digest: digest('c'),
        },
    );
    assert!(matches!(
        wrong_intent_replay,
        Err(StateError::EffectConflict)
    ));

    let result_request = EffectResult {
        attempt_id: attempt("attempt-1"),
        base_revision: base(),
        expected_revision: Revision::from_u64(4),
        idempotency_key: action("effect-1"),
        request_digest: digest('c'),
        status: EffectStatus::Applied,
        result_digest: digest('d'),
    };
    assert!(matches!(
        reopened
            .record_effect_result(&reopened_broker, result_request.clone())
            .expect("effect result committed"),
        Mutation::Applied(_)
    ));
    assert!(matches!(
        reopened
            .record_effect_result(&reopened_broker, result_request)
            .expect("effect result replayed"),
        Mutation::Replayed(_)
    ));
}

#[test]
fn overlapping_leases_and_bad_cas_leave_durable_state_unchanged() {
    let directory = tempdir().expect("temporary directory");
    let database = directory.path().join("state.sqlite3");
    let mut store = open_state(&database).expect("state opens");
    let broker = store.broker_authority();
    for number in [1, 2] {
        store
            .create_attempt(
                &broker,
                attempt(&format!("attempt-{number}")),
                objective(&format!("objective-{number}")),
                base(),
            )
            .expect("attempt created");
    }
    let first = store
        .acquire_paths(
            &broker,
            AcquirePaths {
                action_id: action("acquire-1"),
                lease_id: lease("lease-1"),
                attempt_id: attempt("attempt-1"),
                base_revision: base(),
                expected_revision: Revision::default(),
                paths: vec![path("rust/crates/automonique-lab")],
            },
        )
        .expect("first lease acquired");
    assert_eq!(first.receipt().revision, Revision::from_u64(1));
    let mut contender = open_state(&database).expect("second connection opens");
    let contender_broker = contender.broker_authority();

    for (action_id, candidate) in [
        ("conflict-exact", "rust/crates/automonique-lab"),
        ("conflict-ancestor", "rust/crates"),
        ("conflict-descendant", "rust/crates/automonique-lab/src"),
    ] {
        let denied = contender.acquire_paths(
            &contender_broker,
            AcquirePaths {
                action_id: action(action_id),
                lease_id: lease(action_id),
                attempt_id: attempt("attempt-2"),
                base_revision: base(),
                expected_revision: Revision::default(),
                paths: vec![path(candidate)],
            },
        );
        assert!(matches!(denied, Err(StateError::LeaseConflict { .. })));
        assert_eq!(
            contender
                .attempt(&attempt("attempt-2"))
                .expect("attempt query")
                .expect("attempt exists")
                .revision(),
            Revision::default()
        );
        assert_eq!(contender.active_leases().expect("leases").len(), 1);
    }

    let wrong_revision = store.append_record(
        &broker,
        AppendRecord {
            attempt_id: attempt("attempt-1"),
            base_revision: base(),
            expected_revision: Revision::from_u64(9),
            record_id: action("bad-cas"),
            kind: JournalKind::Checkpoint,
            payload_digest: digest('e'),
        },
    );
    assert!(matches!(
        wrong_revision,
        Err(StateError::RevisionConflict { .. })
    ));
    assert!(
        store
            .journal(&attempt("attempt-1"))
            .expect("journal")
            .is_empty()
    );
}

#[test]
fn terminal_transition_releases_leases_atomically_and_denies_mutation() {
    let directory = tempdir().expect("temporary directory");
    let database = directory.path().join("state.sqlite3");
    let mut store = open_state(&database).expect("state opens");
    let broker = store.broker_authority();
    store
        .create_attempt(
            &broker,
            attempt("attempt-1"),
            objective("objective-1"),
            base(),
        )
        .expect("attempt created");
    transition(&mut store, "attempt-1", "start-1", 0, AttemptState::Running);
    let acquire = AcquirePaths {
        action_id: action("acquire-1"),
        lease_id: lease("lease-1"),
        attempt_id: attempt("attempt-1"),
        base_revision: base(),
        expected_revision: Revision::from_u64(1),
        paths: vec![path("rust")],
    };
    let grant = store
        .acquire_paths(&broker, acquire.clone())
        .expect("lease acquired");
    assert!(matches!(
        store.release_paths(
            &broker,
            ReleasePaths {
                action_id: action("release-1"),
                lease_id: lease("lease-1"),
                attempt_id: attempt("attempt-1"),
                base_revision: base(),
                expected_revision: Revision::from_u64(2),
                epoch: grant.receipt().epoch,
            },
        ),
        Err(StateError::NonterminalReleaseDenied)
    ));
    assert_eq!(store.active_leases().expect("leases").len(), 1);

    let terminal = store
        .transition(
            &broker,
            TransitionAttempt {
                action_id: action("finish-1"),
                attempt_id: attempt("attempt-1"),
                base_revision: base(),
                expected_revision: Revision::from_u64(2),
                target: AttemptState::Succeeded,
                event_digest: digest('f'),
            },
        )
        .expect("terminal transition");
    assert_eq!(terminal.receipt().released_lease_count, 1);
    assert!(store.active_leases().expect("leases").is_empty());
    assert!(matches!(
        store.acquire_paths(&broker, acquire),
        Err(StateError::LeaseInactive)
    ));
    assert!(
        store
            .journal(&attempt("attempt-1"))
            .expect("journal")
            .iter()
            .all(|record| record.authority() == RecordAuthority::Harness)
    );

    let before = store
        .attempt(&attempt("attempt-1"))
        .expect("attempt query")
        .expect("attempt exists");
    let denied = store.append_record(
        &broker,
        AppendRecord {
            attempt_id: attempt("attempt-1"),
            base_revision: base(),
            expected_revision: before.revision(),
            record_id: action("late-checkpoint"),
            kind: JournalKind::Checkpoint,
            payload_digest: digest('1'),
        },
    );
    assert!(matches!(denied, Err(StateError::TerminalImmutable)));
    assert_eq!(
        store
            .attempt(&attempt("attempt-1"))
            .expect("attempt query")
            .expect("attempt exists"),
        before
    );
}

#[test]
fn immediate_transactions_fail_closed_under_two_connection_contention() {
    let directory = tempdir().expect("temporary directory");
    let database = directory.path().join("state.sqlite3");
    let _initializer = open_state(&database).expect("schema initialized");
    let mut contender = open_state_timeout(&database, Duration::from_millis(1))
        .expect("second state connection opens");
    let contender_broker = contender.broker_authority();
    let locker = Connection::open(&database).expect("locking connection opens");
    locker
        .execute_batch("BEGIN IMMEDIATE")
        .expect("write lock acquired");

    let denied = contender.create_attempt(
        &contender_broker,
        attempt("attempt-1"),
        objective("objective-1"),
        base(),
    );
    assert!(matches!(denied, Err(StateError::Busy)));
    assert!(
        contender
            .attempt(&attempt("attempt-1"))
            .expect("attempt query")
            .is_none()
    );

    locker.execute_batch("ROLLBACK").expect("lock released");
    contender
        .create_attempt(
            &contender_broker,
            attempt("attempt-1"),
            objective("objective-1"),
            base(),
        )
        .expect("write succeeds after unlock");
}

#[cfg(unix)]
#[test]
fn database_open_rejects_symlinked_path_components() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("temporary directory");
    let real = directory.path().join("real");
    std::fs::create_dir(&real).expect("real directory created");
    let linked = directory.path().join("linked");
    symlink(&real, &linked).expect("directory symlink created");

    let denied = open_state(linked.join("state.sqlite3"));
    assert!(matches!(denied, Err(StateError::UnsafePath(_))));
    assert!(!real.join("state.sqlite3").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn permissive_directory_is_refused_without_mode_mutation() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let directory = tempdir().expect("temporary directory");
    let private = directory.path().join("state");
    std::fs::create_dir(&private).expect("state directory created");
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o755))
        .expect("permissive test mode set");
    let database = private.join("state.sqlite3");
    assert!(matches!(
        StateStore::open(&ControllerRoot { seal: () }, &database),
        Err(StateError::UnsafePath(_))
    ));
    assert_eq!(
        std::fs::metadata(&private)
            .expect("directory metadata")
            .mode()
            & 0o7777,
        0o755
    );
    assert!(!database.exists());

    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))
        .expect("caller makes dedicated directory private");
    let mut store = open_state(&database).expect("private directory opens");
    let broker = store.broker_authority();
    store
        .create_attempt(
            &broker,
            attempt("attempt-1"),
            objective("objective-1"),
            base(),
        )
        .expect("write creates WAL sidecars");

    let database_metadata = std::fs::metadata(&database).expect("database metadata");
    assert_eq!(
        std::fs::metadata(&private)
            .expect("directory metadata")
            .mode()
            & 0o7777,
        0o700
    );
    assert_eq!(database_metadata.mode() & 0o7777, 0o600);
    for suffix in ["-wal", "-shm"] {
        let mut name = database.as_os_str().to_os_string();
        name.push(suffix);
        let metadata = std::fs::metadata(name).expect("sidecar exists");
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(metadata.uid(), database_metadata.uid());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn foreign_owned_state_directory_is_rejected_when_chown_is_available() {
    use std::os::unix::fs::{MetadataExt, chown};

    let directory = tempdir().expect("temporary directory");
    let private = directory.path().join("foreign-state");
    std::fs::create_dir(&private).expect("state directory created");
    let current_uid = std::fs::metadata(&private)
        .expect("directory metadata")
        .uid();
    if current_uid != 0 {
        return;
    }
    chown(&private, Some(1), None).expect("root test can assign foreign owner");
    let denied = open_state(private.join("state.sqlite3"));
    chown(&private, Some(current_uid), None).expect("test owner restored");
    assert!(matches!(denied, Err(StateError::UnsafePath(_))));
}

#[test]
fn broker_capability_is_store_bound_and_denial_is_immutable() {
    let directory = tempdir().expect("temporary directory");
    let first_path = directory.path().join("first.sqlite3");
    let mut first = open_state(&first_path).expect("first store opens");
    let second = open_state(&first_path).expect("same-path second store opens");
    let foreign = second.broker_authority();
    assert!(matches!(
        first.create_attempt(
            &foreign,
            attempt("attempt-1"),
            objective("objective-1"),
            base()
        ),
        Err(StateError::AuthorityDenied)
    ));
    assert!(
        first
            .attempt(&attempt("attempt-1"))
            .expect("attempt query")
            .is_none()
    );
}

#[test]
fn partial_or_bogus_active_rows_fail_receipt_reconstruction_closed() {
    for corruption in ["partial", "bogus"] {
        let directory = tempdir().expect("temporary directory");
        let database = directory.path().join("state.sqlite3");
        let mut store = open_state(&database).expect("state opens");
        let broker = store.broker_authority();
        store
            .create_attempt(
                &broker,
                attempt("attempt-1"),
                objective("objective-1"),
                base(),
            )
            .expect("attempt created");
        let acquire = AcquirePaths {
            action_id: action("acquire-1"),
            lease_id: lease("lease-1"),
            attempt_id: attempt("attempt-1"),
            base_revision: base(),
            expected_revision: Revision::default(),
            paths: vec![path("rust/a"), path("rust/b")],
        };
        store
            .acquire_paths(&broker, acquire.clone())
            .expect("lease acquired");
        let raw = Connection::open(&database).expect("raw connection opens");
        if corruption == "partial" {
            raw.execute("DELETE FROM path_leases WHERE path = 'rust/a'", [])
                .expect("active row deleted");
        } else {
            raw.execute("INSERT INTO path_leases(lease_id, attempt_id, path, epoch, acquired_revision) VALUES ('lease-1', 'attempt-1', 'rust/c', 1, 1)", [])
                .expect("bogus active row inserted");
        }
        drop(raw);
        assert!(matches!(
            store.acquire_paths(&broker, acquire),
            Err(StateError::Corrupt(_))
        ));
        drop(store);
        assert!(matches!(open_state(&database), Err(StateError::Corrupt(_))));
    }
}

#[test]
fn orphan_active_row_without_acquire_receipt_fails_reopen_closed() {
    let directory = tempdir().expect("temporary directory");
    let database = directory.path().join("state.sqlite3");
    let mut store = open_state(&database).expect("state opens");
    let broker = store.broker_authority();
    store
        .create_attempt(
            &broker,
            attempt("attempt-1"),
            objective("objective-1"),
            base(),
        )
        .expect("attempt created");
    store
        .acquire_paths(
            &broker,
            AcquirePaths {
                action_id: action("acquire-1"),
                lease_id: lease("lease-1"),
                attempt_id: attempt("attempt-1"),
                base_revision: base(),
                expected_revision: Revision::default(),
                paths: vec![path("rust")],
            },
        )
        .expect("legitimate lease acquired");
    drop(store);

    Connection::open(&database)
        .expect("raw connection opens")
        .execute("INSERT INTO path_leases(lease_id, attempt_id, path, epoch, acquired_revision) VALUES ('orphan-lease', 'attempt-1', 'docs', 1, 1)", [])
        .expect("orphan active row injected");
    assert!(matches!(open_state(&database), Err(StateError::Corrupt(_))));
}

#[test]
fn schema_and_semantic_corruption_fail_reopen_closed() {
    let directory = tempdir().expect("temporary directory");
    let schema_path = directory.path().join("schema.sqlite3");
    drop(open_state(&schema_path).expect("schema store opens"));
    Connection::open(&schema_path)
        .expect("raw schema connection")
        .execute("CREATE TABLE rogue(value INTEGER)", [])
        .expect("schema corruption injected");
    assert!(matches!(
        open_state(&schema_path),
        Err(StateError::Corrupt(_))
    ));

    let semantic_path = directory.path().join("semantic.sqlite3");
    let mut store = open_state(&semantic_path).expect("semantic store opens");
    let broker = store.broker_authority();
    store
        .create_attempt(
            &broker,
            attempt("attempt-1"),
            objective("objective-1"),
            base(),
        )
        .expect("attempt created");
    drop(store);
    Connection::open(&semantic_path)
        .expect("raw semantic connection")
        .execute(
            "UPDATE attempts SET revision = 9 WHERE attempt_id = 'attempt-1'",
            [],
        )
        .expect("semantic corruption injected");
    assert!(matches!(
        open_state(&semantic_path),
        Err(StateError::Corrupt(_))
    ));
}

#[test]
fn foreign_key_corruption_and_unsupported_schema_fail_closed() {
    let directory = tempdir().expect("temporary directory");
    let foreign_path = directory.path().join("foreign.sqlite3");
    drop(open_state(&foreign_path).expect("foreign-key store opens"));
    let raw = Connection::open(&foreign_path).expect("raw foreign-key connection");
    raw.execute_batch("PRAGMA foreign_keys=OFF; INSERT INTO path_leases(lease_id, attempt_id, path, epoch, acquired_revision) VALUES ('lease-1', 'missing-attempt', 'rust', 1, 1);")
        .expect("foreign-key corruption injected");
    drop(raw);
    assert!(matches!(
        open_state(&foreign_path),
        Err(StateError::Corrupt(_))
    ));

    let version_path = directory.path().join("version.sqlite3");
    drop(open_state(&version_path).expect("version store opens"));
    Connection::open(&version_path)
        .expect("raw version connection")
        .pragma_update(None, "user_version", 2)
        .expect("unsupported version injected");
    assert!(matches!(
        open_state(&version_path),
        Err(StateError::SchemaVersion { found: 2 })
    ));
}
