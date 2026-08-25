// SPDX-License-Identifier: Elastic-2.0

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use automonique_store::reload_audit::{
    AdvanceReload, BeginReload, ReloadAudit, ReloadAuditError, ReloadPhase,
};
use rusqlite::Connection;

struct PrivateAudit {
    _root: tempfile::TempDir,
    path: PathBuf,
}

impl PrivateAudit {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("temporary root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        let path = root.path().join("reload-audit.sqlite3");
        Self { _root: root, path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn begin<'a>(reload_id: &'a str, target: &'a str, digest: &'a str) -> BeginReload<'a> {
    BeginReload {
        reload_id,
        source_generation_id: "generation-7",
        source_lease_epoch: 9,
        target_generation_id: target,
        target_release_digest: digest,
        created_at_ms: 1_000,
    }
}

fn advance(audit: &mut ReloadAudit, reload_id: &str, revision: u64, phase: ReloadPhase, at: i64) {
    audit
        .advance(AdvanceReload {
            reload_id,
            expected_revision: revision,
            phase,
            failure_category: None,
            observed_at_ms: at,
        })
        .expect("valid transition");
}

#[test]
fn one_reload_records_the_complete_success_path_and_survives_reopen() {
    let private = PrivateAudit::new();
    let release = digest('a');
    let mut audit = ReloadAudit::open(private.path()).expect("open");
    let created = audit
        .begin(begin("reload-1", "generation-8", &release))
        .expect("begin");
    assert_eq!(created.phase, ReloadPhase::Created);
    assert_eq!(created.revision, 1);
    assert_eq!(audit.active().expect("active"), Some(created.clone()));

    for (revision, phase) in [
        ReloadPhase::CandidateStarted,
        ReloadPhase::Warm,
        ReloadPhase::Quiescing,
        ReloadPhase::Transferred,
        ReloadPhase::ActiveProven,
        ReloadPhase::Draining,
        ReloadPhase::Succeeded,
    ]
    .into_iter()
    .enumerate()
    {
        advance(
            &mut audit,
            "reload-1",
            u64::try_from(revision).expect("small") + 1,
            phase,
            1_001 + i64::try_from(revision).expect("small"),
        );
    }
    assert!(audit.active().expect("active").is_none());
    drop(audit);

    let audit = ReloadAudit::open(private.path()).expect("reopen");
    let history = audit.history("reload-1", 0, 32).expect("history");
    assert_eq!(history.record.phase, ReloadPhase::Succeeded);
    assert_eq!(history.record.revision, 8);
    assert_eq!(history.transitions.len(), 8);
    assert_eq!(history.transitions[0].phase, ReloadPhase::Created);
    assert_eq!(history.transitions[7].phase, ReloadPhase::Succeeded);
    assert_eq!(history.transitions[7].observed_at_ms, 1_007);
}

#[test]
fn begin_is_idempotent_by_exact_coordinates_and_serializes_active_reload() {
    let private = PrivateAudit::new();
    let release = digest('b');
    let mut audit = ReloadAudit::open(private.path()).expect("open");
    let first = audit
        .begin(begin("reload-1", "generation-8", &release))
        .expect("begin");
    assert_eq!(
        audit
            .begin(begin("reload-1", "generation-8", &release))
            .expect("replay"),
        first
    );
    assert!(matches!(
        audit
            .begin(begin("reload-1", "generation-9", &release))
            .expect_err("changed replay"),
        ReloadAuditError::Conflict
    ));
    let another = digest('c');
    assert!(matches!(
        audit
            .begin(begin("reload-2", "generation-9", &another))
            .expect_err("one active"),
        ReloadAuditError::AlreadyActive(id) if id == "reload-1"
    ));
}

#[test]
fn failures_before_transfer_and_rollback_after_transfer_are_distinct_terminal_records() {
    let private = PrivateAudit::new();
    let first_release = digest('d');
    let second_release = digest('e');
    let mut audit = ReloadAudit::open(private.path()).expect("open");
    audit
        .begin(begin("reload-failed", "generation-8", &first_release))
        .expect("begin");
    let failed = audit
        .advance(AdvanceReload {
            reload_id: "reload-failed",
            expected_revision: 1,
            phase: ReloadPhase::Failed,
            failure_category: Some("candidate_warmup_failed"),
            observed_at_ms: 1_010,
        })
        .expect("failed");
    assert_eq!(
        failed.failure_category.as_deref(),
        Some("candidate_warmup_failed")
    );

    audit
        .begin(begin("reload-rollback", "generation-9", &second_release))
        .expect("second begin");
    advance(
        &mut audit,
        "reload-rollback",
        1,
        ReloadPhase::CandidateStarted,
        1_020,
    );
    advance(&mut audit, "reload-rollback", 2, ReloadPhase::Warm, 1_021);
    advance(
        &mut audit,
        "reload-rollback",
        3,
        ReloadPhase::Quiescing,
        1_022,
    );
    advance(
        &mut audit,
        "reload-rollback",
        4,
        ReloadPhase::Transferred,
        1_023,
    );
    let rolled_back = audit
        .advance(AdvanceReload {
            reload_id: "reload-rollback",
            expected_revision: 5,
            phase: ReloadPhase::RolledBack,
            failure_category: Some("active_proof_failed"),
            observed_at_ms: 1_024,
        })
        .expect("rollback");
    assert_eq!(rolled_back.phase, ReloadPhase::RolledBack);
    assert_eq!(rolled_back.terminal_at_ms, Some(1_024));
}

#[test]
fn transitions_are_closed_revision_checked_and_time_monotonic() {
    let private = PrivateAudit::new();
    let release = digest('f');
    let mut audit = ReloadAudit::open(private.path()).expect("open");
    audit
        .begin(begin("reload-1", "generation-8", &release))
        .expect("begin");

    assert!(matches!(
        audit
            .advance(AdvanceReload {
                reload_id: "reload-1",
                expected_revision: 1,
                phase: ReloadPhase::Transferred,
                failure_category: None,
                observed_at_ms: 1_001,
            })
            .expect_err("skip"),
        ReloadAuditError::InvalidTransition {
            from: ReloadPhase::Created,
            to: ReloadPhase::Transferred
        }
    ));
    assert!(matches!(
        audit
            .advance(AdvanceReload {
                reload_id: "reload-1",
                expected_revision: 2,
                phase: ReloadPhase::CandidateStarted,
                failure_category: None,
                observed_at_ms: 1_001,
            })
            .expect_err("stale expectation"),
        ReloadAuditError::RevisionMismatch {
            expected: 2,
            durable: 1
        }
    ));
    assert!(matches!(
        audit
            .advance(AdvanceReload {
                reload_id: "reload-1",
                expected_revision: 1,
                phase: ReloadPhase::Failed,
                failure_category: None,
                observed_at_ms: 1_001,
            })
            .expect_err("missing category"),
        ReloadAuditError::InvalidField("failure_category")
    ));
    assert!(matches!(
        audit
            .advance(AdvanceReload {
                reload_id: "reload-1",
                expected_revision: 1,
                phase: ReloadPhase::CandidateStarted,
                failure_category: None,
                observed_at_ms: 999,
            })
            .expect_err("backward clock"),
        ReloadAuditError::InvalidField("observed_at_ms")
    ));
}

#[test]
fn capacity_refuses_a_new_epoch_without_blocking_reads() {
    let private = PrivateAudit::new();
    let first_release = digest('1');
    let second_release = digest('2');
    let mut audit = ReloadAudit::open_with_capacity(private.path(), 1).expect("open");
    audit
        .begin(begin("reload-1", "generation-8", &first_release))
        .expect("first");
    audit
        .advance(AdvanceReload {
            reload_id: "reload-1",
            expected_revision: 1,
            phase: ReloadPhase::Failed,
            failure_category: Some("verification_failed"),
            observed_at_ms: 1_001,
        })
        .expect("terminal");
    assert!(matches!(
        audit
            .begin(begin("reload-2", "generation-9", &second_release))
            .expect_err("full"),
        ReloadAuditError::AuditFull
    ));
    assert_eq!(
        audit.get("reload-1").expect("read").expect("present").phase,
        ReloadPhase::Failed
    );
}

#[test]
fn malformed_coordinates_foreign_schema_and_corruption_fail_closed() {
    let private = PrivateAudit::new();
    let release = digest('3');
    let mut audit = ReloadAudit::open(private.path()).expect("open");
    assert!(matches!(
        audit
            .begin(begin("", "generation-8", &release))
            .expect_err("empty id"),
        ReloadAuditError::InvalidField("reload_id")
    ));
    assert!(matches!(
        audit
            .begin(begin("reload-1", "generation-7", &release))
            .expect_err("same generation"),
        ReloadAuditError::InvalidField("target_generation_id")
    ));
    audit
        .begin(begin("reload-1", "generation-8", &release))
        .expect("begin");
    drop(audit);

    let connection = Connection::open(private.path()).expect("raw open");
    connection
        .execute(
            "UPDATE reloads SET target_release_digest = ?1 WHERE reload_id = 'reload-1'",
            ["sha256:UPPER"],
        )
        .expect("smuggle malformed digest");
    drop(connection);
    let audit = ReloadAudit::open(private.path()).expect("schema still opens");
    assert!(matches!(
        audit.get("reload-1").expect_err("corruption"),
        ReloadAuditError::Corrupt("target_release_digest")
    ));
    drop(audit);

    let connection = Connection::open(private.path()).expect("raw reopen");
    connection
        .pragma_update(None, "user_version", 99)
        .expect("foreign version");
    drop(connection);
    assert!(matches!(
        ReloadAudit::open(private.path()).expect_err("foreign schema"),
        ReloadAuditError::ForeignSchema(99)
    ));
}
