// SPDX-License-Identifier: Elastic-2.0

use std::os::unix::fs::PermissionsExt;

use automonique_daemon::reload::{ReloadExecution, ReloadHooks, ReloadRefusal, execute_reload};
use automonique_store::reload_audit::{ReloadAudit, ReloadPhase};

const RELEASE: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[derive(Default)]
struct RecordingHooks {
    calls: Vec<&'static str>,
    fail_at: Option<&'static str>,
    rollback_fails: bool,
}

impl RecordingHooks {
    fn operation(&mut self, name: &'static str) -> Result<(), ReloadRefusal> {
        self.calls.push(name);
        if self.fail_at == Some(name) {
            Err(ReloadRefusal::new(name))
        } else {
            Ok(())
        }
    }
}

impl ReloadHooks for RecordingHooks {
    fn verify_target(&mut self) -> Result<(), ReloadRefusal> {
        self.operation("target_verification_failed")
    }

    fn spawn_candidate(&mut self) -> Result<(), ReloadRefusal> {
        self.operation("candidate_spawn_failed")
    }

    fn warm_candidate(&mut self) -> Result<(), ReloadRefusal> {
        self.operation("candidate_warmup_failed")
    }

    fn quiesce_source(&mut self) -> Result<(), ReloadRefusal> {
        self.operation("source_quiescence_failed")
    }

    fn transfer_leases(&mut self) -> Result<(), ReloadRefusal> {
        self.operation("lease_transfer_failed")
    }

    fn activate_candidate(&mut self) -> Result<(), ReloadRefusal> {
        self.operation("candidate_activation_failed")
    }

    fn prove_active(&mut self) -> Result<(), ReloadRefusal> {
        self.operation("active_proof_failed")
    }

    fn drain_source(&mut self) -> Result<(), ReloadRefusal> {
        self.operation("source_drain_failed")
    }

    fn stop_candidate(&mut self) {
        self.calls.push("stop_candidate");
    }

    fn resume_source(&mut self) {
        self.calls.push("resume_source");
    }

    fn return_leases(&mut self) -> Result<(), ReloadRefusal> {
        self.calls.push("return_leases");
        if self.rollback_fails {
            Err(ReloadRefusal::new("lease_return_failed"))
        } else {
            Ok(())
        }
    }
}

struct Fixture {
    _root: tempfile::TempDir,
    audit: ReloadAudit,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("temporary root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        let audit = ReloadAudit::open(root.path().join("reload-audit.sqlite3")).expect("audit");
        Self { _root: root, audit }
    }

    fn execute(&mut self, hooks: &mut RecordingHooks) -> Result<ReloadPhase, String> {
        let mut now = 1_000;
        execute_reload(
            &mut self.audit,
            ReloadExecution {
                reload_id: "reload-1",
                source_generation_id: "generation-1",
                source_lease_epoch: 7,
                target_generation_id: "generation-2",
                target_release_digest: RELEASE,
            },
            hooks,
            || {
                now += 1;
                Ok(now)
            },
        )
        .map(|record| record.phase)
        .map_err(|error| error.category().to_owned())
    }
}

#[test]
fn successful_reload_records_every_committed_phase_in_order() {
    let mut fixture = Fixture::new();
    let mut hooks = RecordingHooks::default();

    assert_eq!(fixture.execute(&mut hooks), Ok(ReloadPhase::Succeeded));
    assert_eq!(
        hooks.calls,
        [
            "target_verification_failed",
            "candidate_spawn_failed",
            "candidate_warmup_failed",
            "source_quiescence_failed",
            "lease_transfer_failed",
            "candidate_activation_failed",
            "active_proof_failed",
            "source_drain_failed",
        ]
    );
    let history = fixture.audit.history("reload-1", 0, 32).expect("history");
    assert_eq!(
        history
            .transitions
            .iter()
            .map(|transition| transition.phase)
            .collect::<Vec<_>>(),
        [
            ReloadPhase::Created,
            ReloadPhase::CandidateStarted,
            ReloadPhase::Warm,
            ReloadPhase::Quiescing,
            ReloadPhase::Transferred,
            ReloadPhase::ActiveProven,
            ReloadPhase::Draining,
            ReloadPhase::Succeeded,
        ]
    );
}

#[test]
fn target_verification_failure_never_creates_an_epoch() {
    let mut fixture = Fixture::new();
    let mut hooks = RecordingHooks {
        fail_at: Some("target_verification_failed"),
        ..RecordingHooks::default()
    };

    assert_eq!(
        fixture.execute(&mut hooks).expect_err("refused"),
        "target_verification_failed"
    );
    assert!(fixture.audit.active().expect("active").is_none());
    assert!(fixture.audit.get("reload-1").expect("record").is_none());
    assert_eq!(hooks.calls, ["target_verification_failed"]);
}

#[test]
fn every_pre_transfer_failure_resumes_source_and_stops_candidate() {
    for category in [
        "candidate_spawn_failed",
        "candidate_warmup_failed",
        "source_quiescence_failed",
        "lease_transfer_failed",
    ] {
        let mut fixture = Fixture::new();
        let mut hooks = RecordingHooks {
            fail_at: Some(category),
            ..RecordingHooks::default()
        };

        assert_eq!(fixture.execute(&mut hooks).expect_err("refused"), category);
        assert_eq!(
            hooks.calls[hooks.calls.len() - 2..],
            ["resume_source", "stop_candidate"]
        );
        assert!(!hooks.calls.contains(&"return_leases"));
        let record = fixture
            .audit
            .get("reload-1")
            .expect("record")
            .expect("reload");
        assert_eq!(record.phase, ReloadPhase::Failed);
        assert_eq!(record.failure_category.as_deref(), Some(category));
    }
}

#[test]
fn every_post_transfer_failure_returns_authority_before_resuming_source() {
    for category in [
        "candidate_activation_failed",
        "active_proof_failed",
        "source_drain_failed",
    ] {
        let mut fixture = Fixture::new();
        let mut hooks = RecordingHooks {
            fail_at: Some(category),
            ..RecordingHooks::default()
        };

        assert_eq!(fixture.execute(&mut hooks).expect_err("refused"), category);
        assert_eq!(
            hooks.calls[hooks.calls.len() - 3..],
            ["return_leases", "resume_source", "stop_candidate"]
        );
        let record = fixture
            .audit
            .get("reload-1")
            .expect("record")
            .expect("reload");
        assert_eq!(record.phase, ReloadPhase::RolledBack);
        assert_eq!(record.failure_category.as_deref(), Some(category));
    }
}

#[test]
fn failed_lease_return_never_claims_that_the_source_resumed() {
    let mut fixture = Fixture::new();
    let mut hooks = RecordingHooks {
        fail_at: Some("active_proof_failed"),
        rollback_fails: true,
        ..RecordingHooks::default()
    };

    assert_eq!(
        fixture.execute(&mut hooks).expect_err("refused"),
        "reload_recovery_required"
    );
    assert_eq!(hooks.calls[hooks.calls.len() - 1], "return_leases");
    assert!(!hooks.calls.contains(&"resume_source"));
    assert!(!hooks.calls.contains(&"stop_candidate"));
    let record = fixture
        .audit
        .get("reload-1")
        .expect("record")
        .expect("reload");
    assert_eq!(record.phase, ReloadPhase::Failed);
    assert_eq!(
        record.failure_category.as_deref(),
        Some("reload_recovery_required")
    );
}

#[test]
fn exact_retry_of_a_terminal_reload_never_starts_another_candidate() {
    let mut fixture = Fixture::new();
    let mut hooks = RecordingHooks::default();
    assert_eq!(fixture.execute(&mut hooks), Ok(ReloadPhase::Succeeded));
    hooks.calls.clear();

    assert_eq!(fixture.execute(&mut hooks), Ok(ReloadPhase::Succeeded));
    assert_eq!(hooks.calls, ["target_verification_failed"]);
    assert_eq!(
        fixture
            .audit
            .history("reload-1", 0, 32)
            .expect("history")
            .transitions
            .len(),
        8
    );
}

#[test]
fn retry_resumes_an_in_progress_epoch_without_duplicate_transitions() {
    use automonique_store::reload_audit::{AdvanceReload, BeginReload};

    let mut fixture = Fixture::new();
    fixture
        .audit
        .begin(BeginReload {
            reload_id: "reload-1",
            source_generation_id: "generation-1",
            source_lease_epoch: 7,
            target_generation_id: "generation-2",
            target_release_digest: RELEASE,
            created_at_ms: 900,
        })
        .expect("begin");
    for (revision, phase) in [
        ReloadPhase::CandidateStarted,
        ReloadPhase::Warm,
        ReloadPhase::Quiescing,
        ReloadPhase::Transferred,
    ]
    .into_iter()
    .enumerate()
    {
        fixture
            .audit
            .advance(AdvanceReload {
                reload_id: "reload-1",
                expected_revision: u64::try_from(revision).expect("small") + 1,
                phase,
                failure_category: None,
                observed_at_ms: 901 + i64::try_from(revision).expect("small"),
            })
            .expect("advance");
    }

    let mut hooks = RecordingHooks::default();
    assert_eq!(fixture.execute(&mut hooks), Ok(ReloadPhase::Succeeded));
    let history = fixture.audit.history("reload-1", 0, 32).expect("history");
    assert_eq!(history.record.revision, 8);
    assert_eq!(history.transitions.len(), 8);
    assert_eq!(history.transitions[4].phase, ReloadPhase::Transferred);
    assert_eq!(history.transitions[5].phase, ReloadPhase::ActiveProven);
}
