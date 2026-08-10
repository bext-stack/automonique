// SPDX-License-Identifier: Elastic-2.0

use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

use automonique_lab::build::BuildBroker;
use automonique_lab::controller::{
    AccountingCapability, BuildUnavailable, ControllerFault, LabController, SyntheticBuildBroker,
    SyntheticBuildEvidence, SyntheticBuildRequest, UnavailableBuildBroker,
};
use automonique_lab::protocol::{
    ActionStatus, BudgetEnforcement, CancelReason, CancelRequest, Execution, GitSha1, LabBudget,
    LabBudgetValues, LabRequest, LabResponse, ObserveRequest, OpaqueId, ProviderPolicy,
    ResumeRequest, SelectRequest, SyntheticProviderPolicy, UnitState,
};
use automonique_lab::workspace_lease::RepoPath;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;

const BASE: &str = "3637390b5298744b1404b9f4d0655671c4013752";

struct RecordingBroker {
    inner: BuildBroker,
    calls: Arc<Mutex<Vec<String>>>,
    evidence: Arc<Mutex<Vec<SyntheticBuildEvidence>>>,
}

impl RecordingBroker {
    fn open(
        root: &std::path::Path,
        calls: Arc<Mutex<Vec<String>>>,
        evidence: Arc<Mutex<Vec<SyntheticBuildEvidence>>>,
    ) -> Self {
        Self {
            inner: BuildBroker::open(root).unwrap(),
            calls,
            evidence,
        }
    }
}

impl SyntheticBuildBroker for RecordingBroker {
    fn execute(
        &mut self,
        request: &SyntheticBuildRequest,
    ) -> Result<SyntheticBuildEvidence, BuildUnavailable> {
        self.calls
            .lock()
            .unwrap()
            .push(request.operation_id().as_str().to_owned());
        let value = <BuildBroker as SyntheticBuildBroker>::execute(&mut self.inner, request)?;
        self.evidence.lock().unwrap().push(value.clone());
        Ok(value)
    }
}

fn id(value: &str) -> OpaqueId {
    OpaqueId::new(value).unwrap()
}
fn base() -> GitSha1 {
    GitSha1::new(BASE).unwrap()
}
fn budget() -> LabBudget {
    LabBudget::new(LabBudgetValues {
        max_wall_ms: 1_000,
        max_cpu_ms: 1_000,
        max_disk_bytes: 16_384,
        max_output_bytes: 16_384,
        max_pids: 2,
        max_model_calls: 0,
        max_cost_microunits: 0,
        enforcement: BudgetEnforcement::SyntheticInProcess,
    })
    .unwrap()
}
fn paths() -> Vec<RepoPath> {
    vec![RepoPath::parse("rust/crates/automonique-lab").unwrap()]
}
fn privatize(directory: &tempfile::TempDir) {
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
}
fn select(request: &str) -> LabRequest {
    select_with_budget(request, "objective-1", budget())
}
fn select_with_budget(request: &str, objective: &str, budget: LabBudget) -> LabRequest {
    LabRequest::Select(
        SelectRequest::new(
            id(request),
            id(objective),
            base(),
            Execution::Synthetic,
            ProviderPolicy::Synthetic(SyntheticProviderPolicy),
            budget,
        )
        .unwrap(),
    )
}

#[test]
fn select_observe_restart_resume_replay_and_cancel_are_durable() {
    let directory = tempfile::tempdir().unwrap();
    privatize(&directory);
    let state = directory.path().join("state.sqlite3");
    let build = directory.path().join("build");
    let calls = Arc::new(Mutex::new(Vec::new()));
    let evidence = Arc::new(Mutex::new(Vec::new()));
    let mut controller = LabController::open(
        &state,
        base(),
        paths(),
        RecordingBroker::open(&build, calls.clone(), evidence.clone()),
    )
    .unwrap();
    let selected = controller.handle(select("select-1")).unwrap();
    let unit = match selected {
        LabResponse::Selected(value) => value.unit().clone(),
        _ => panic!(),
    };
    assert_eq!(unit.state(), UnitState::Paused);
    assert_eq!(calls.lock().unwrap().len(), 1);
    let recorded = evidence.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        recorded[0].wall_accounting(),
        AccountingCapability::Observed
    );
    assert_eq!(
        recorded[0].cpu_accounting(),
        AccountingCapability::Unavailable
    );
    assert_eq!(
        recorded[0].pid_accounting(),
        AccountingCapability::Unavailable
    );
    assert_eq!(
        recorded[0].written_bytes_accounting(),
        AccountingCapability::Unavailable
    );
    assert_eq!(
        recorded[0].tree_accounting(),
        AccountingCapability::Unavailable
    );
    assert!(!recorded[0].output_truncated());
    assert!(recorded[0].output_bytes() > 0);
    assert_ne!(recorded[0].digest(), recorded[0].request_digest());
    assert_ne!(recorded[0].digest(), recorded[0].output_digest());
    drop(recorded);

    let observed = controller
        .handle(LabRequest::Observe(
            ObserveRequest::new(id("observe-1"), id("objective-1"), id("objective-1"), 0, 16)
                .unwrap(),
        ))
        .unwrap();
    let observed = match observed {
        LabResponse::Observed(value) => value,
        _ => panic!(),
    };
    assert_eq!(observed.events().len(), 5);
    assert_eq!(observed.next_sequence().get(), 5);
    drop(controller);

    let mut controller = LabController::open(
        &state,
        base(),
        paths(),
        RecordingBroker::open(&build, calls.clone(), evidence),
    )
    .unwrap();
    let checkpoint = unit.checkpoint_id().unwrap().clone();
    let resume = LabRequest::Resume(
        ResumeRequest::new(
            id("resume-1"),
            id("objective-1"),
            id("objective-1"),
            checkpoint,
            unit.revision().get(),
            id("resume-key"),
        )
        .unwrap(),
    );
    let first = controller.handle(resume.clone()).unwrap();
    let replay = controller.handle(resume).unwrap();
    let first = match first {
        LabResponse::Action(value) => value,
        _ => panic!(),
    };
    let replay = match replay {
        LabResponse::Action(value) => value,
        _ => panic!(),
    };
    assert_eq!(first.receipt().status(), ActionStatus::Accepted);
    assert_eq!(replay.receipt().status(), ActionStatus::AlreadyApplied);
    assert_eq!(replay.unit().state(), UnitState::Running);

    let select_replay = controller.handle(select("select-1")).unwrap();
    assert_eq!(
        match select_replay {
            LabResponse::Selected(value) => value.unit().state(),
            _ => panic!(),
        },
        UnitState::Running
    );
    assert_eq!(calls.lock().unwrap().len(), 1);

    let revision = replay.unit().revision().get();
    let cancel = LabRequest::Cancel(
        CancelRequest::new(
            id("cancel-1"),
            id("objective-1"),
            id("objective-1"),
            revision,
            id("cancel-key"),
            CancelReason::OperatorRequest,
        )
        .unwrap(),
    );
    let cancelled = controller.handle(cancel.clone()).unwrap();
    let duplicate = controller.handle(cancel).unwrap();
    assert_eq!(
        match cancelled {
            LabResponse::Action(value) => value.unit().state(),
            _ => panic!(),
        },
        UnitState::Cancelled
    );
    assert_eq!(
        match duplicate {
            LabResponse::Action(value) => value.receipt().status(),
            _ => panic!(),
        },
        ActionStatus::AlreadyApplied
    );
}

#[test]
fn base_drift_is_denied_without_calling_broker() {
    let directory = tempfile::tempdir().unwrap();
    privatize(&directory);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let evidence = Arc::new(Mutex::new(Vec::new()));
    let mut controller = LabController::open(
        directory.path().join("state.sqlite3"),
        base(),
        paths(),
        RecordingBroker::open(&directory.path().join("build"), calls.clone(), evidence),
    )
    .unwrap();
    let request = LabRequest::Select(
        SelectRequest::new(
            id("select-drift"),
            id("objective-drift"),
            GitSha1::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            Execution::Synthetic,
            ProviderPolicy::Synthetic(SyntheticProviderPolicy),
            budget(),
        )
        .unwrap(),
    );
    assert!(matches!(
        controller.handle(request).unwrap(),
        LabResponse::Denied(_)
    ));
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn revision_conflict_is_explicit_and_does_not_mutate() {
    let directory = tempfile::tempdir().unwrap();
    privatize(&directory);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let evidence = Arc::new(Mutex::new(Vec::new()));
    let mut controller = LabController::open(
        directory.path().join("state.sqlite3"),
        base(),
        paths(),
        RecordingBroker::open(&directory.path().join("build"), calls, evidence),
    )
    .unwrap();
    let unit = match controller.handle(select("select-conflict")).unwrap() {
        LabResponse::Selected(value) => value.unit().clone(),
        _ => panic!(),
    };
    let response = controller
        .handle(LabRequest::Cancel(
            CancelRequest::new(
                id("cancel-conflict"),
                id("objective-1"),
                id("objective-1"),
                unit.revision().get() - 1,
                id("conflict-key"),
                CancelReason::OperatorRequest,
            )
            .unwrap(),
        ))
        .unwrap();
    let action = match response {
        LabResponse::Action(value) => value,
        _ => panic!(),
    };
    assert_eq!(action.receipt().status(), ActionStatus::Conflict);
    assert_eq!(action.unit().state(), UnitState::Paused);
    assert_eq!(action.unit().revision(), unit.revision());
}

#[test]
fn overlapping_active_units_are_denied_across_connections() {
    let directory = tempfile::tempdir().unwrap();
    privatize(&directory);
    let state = directory.path().join("state.sqlite3");
    let build_one = directory.path().join("build-one");
    let build_two = directory.path().join("build-two");
    let calls = Arc::new(Mutex::new(Vec::new()));
    let evidence = Arc::new(Mutex::new(Vec::new()));
    let mut first = LabController::open(
        &state,
        base(),
        paths(),
        RecordingBroker::open(&build_one, calls.clone(), evidence.clone()),
    )
    .unwrap();
    assert!(matches!(
        first.handle(select("select-first")).unwrap(),
        LabResponse::Selected(_)
    ));

    let mut second = LabController::open(
        &state,
        base(),
        paths(),
        RecordingBroker::open(&build_two, calls.clone(), evidence),
    )
    .unwrap();
    let other = LabRequest::Select(
        SelectRequest::new(
            id("select-second"),
            id("objective-2"),
            base(),
            Execution::Synthetic,
            ProviderPolicy::Synthetic(SyntheticProviderPolicy),
            budget(),
        )
        .unwrap(),
    );
    assert!(matches!(
        second.handle(other).unwrap(),
        LabResponse::Denied(_)
    ));
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[test]
fn changed_selection_retry_conflicts_before_a_second_build() {
    let directory = tempfile::tempdir().unwrap();
    privatize(&directory);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let evidence = Arc::new(Mutex::new(Vec::new()));
    let mut controller = LabController::open(
        directory.path().join("state.sqlite3"),
        base(),
        paths(),
        RecordingBroker::open(&directory.path().join("build"), calls.clone(), evidence),
    )
    .unwrap();
    assert!(matches!(
        controller.handle(select("bound-request")).unwrap(),
        LabResponse::Selected(_)
    ));
    let changed_budget = LabBudget::new(LabBudgetValues {
        max_wall_ms: 2_000,
        max_cpu_ms: 1_000,
        max_disk_bytes: 16_384,
        max_output_bytes: 16_384,
        max_pids: 2,
        max_model_calls: 0,
        max_cost_microunits: 0,
        enforcement: BudgetEnforcement::SyntheticInProcess,
    })
    .unwrap();
    assert!(matches!(
        controller
            .handle(select_with_budget(
                "bound-request",
                "objective-1",
                changed_budget,
            ))
            .unwrap(),
        LabResponse::Denied(_)
    ));
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[test]
fn exact_retry_recovers_after_lease_before_running_crash() {
    let directory = tempfile::tempdir().unwrap();
    privatize(&directory);
    let state = directory.path().join("state.sqlite3");
    let build = directory.path().join("build");
    let calls = Arc::new(Mutex::new(Vec::new()));
    let evidence = Arc::new(Mutex::new(Vec::new()));
    let mut controller = LabController::open(
        &state,
        base(),
        paths(),
        RecordingBroker::open(&build, calls.clone(), evidence.clone()),
    )
    .unwrap();
    assert!(matches!(
        controller.handle_with_fault(select("crash-request"), Some(ControllerFault::AfterLease)),
        Err(automonique_lab::controller::ControllerError::InjectedFault(
            ControllerFault::AfterLease
        ))
    ));
    assert!(calls.lock().unwrap().is_empty());
    drop(controller);

    let mut reopened = LabController::open(
        &state,
        base(),
        paths(),
        RecordingBroker::open(&build, calls.clone(), evidence),
    )
    .unwrap();
    let response = reopened.handle(select("crash-request")).unwrap();
    assert_eq!(
        match response {
            LabResponse::Selected(value) => value.unit().state(),
            _ => panic!(),
        },
        UnitState::Paused
    );
    assert_eq!(calls.lock().unwrap().len(), 1);
}

#[test]
fn admitted_packet_allocates_and_replays_after_controller_restart() {
    let directory = tempfile::tempdir().unwrap();
    privatize(&directory);
    let repository = directory.path().join("repository");
    std::fs::create_dir_all(repository.join(".automonique/dev/guides")).unwrap();
    std::fs::create_dir_all(repository.join("plan")).unwrap();
    std::fs::create_dir_all(repository.join("leased")).unwrap();
    std::fs::write(repository.join(".gitignore"), b".automonique/state/\n").unwrap();
    std::fs::write(repository.join("leased/file.txt"), b"leased\n").unwrap();
    std::fs::write(repository.join("plan/work-graph.toml"), b"[work]\n").unwrap();
    std::fs::write(
        repository.join(".automonique/dev/guides/manifest.json"),
        b"{}\n",
    )
    .unwrap();
    let graph = file_sha(&repository.join("plan/work-graph.toml"));
    let program = json!({"schema":"automonique.dev-program/v1","source":{"graph":"plan/work-graph.toml","graph_sha256":graph,"item_count":1},"items":[{"id":"WORK-001","epic":"WORK","track":"core","title":"Work","summary":null,"depends_on":[],"blocked_by_gates":[],"licence":"Elastic-2.0","allowed_paths":["leased"],"closes_gate":null,"status":"blocked","contract":"plan/contracts/WORK-001.md","runnable":true}]});
    let mut program_bytes = b"# SPDX-License-Identifier: Elastic-2.0\n".to_vec();
    program_bytes.extend(serde_json::to_vec_pretty(&program).unwrap());
    std::fs::write(
        repository.join(".automonique/dev/program.yaml"),
        program_bytes,
    )
    .unwrap();
    let objectives = json!({"schema":"automonique.dev-objectives/v1","objectives":[{"id":"objective:WORK-001","work_id":"WORK-001","objective":"Allocate.","metric":{"name":"checks","target":1,"anti_regression":"none"},"baseline":{"value":null,"reason":"base"},"budget":{"max_iterations":3,"max_wall_seconds":300,"max_worker_seconds":200,"max_unchanged_results":1,"max_failures":2},"tests":["test"],"stop_conditions":["stop"],"hill_climbability":90,"autonomous_eligible":true,"allowed_paths":["leased"],"licence":"Elastic-2.0","sources":["plan/contracts/WORK-001.md"]}]});
    std::fs::write(
        repository.join(".automonique/dev/objectives.json"),
        serde_json::to_vec_pretty(&objectives).unwrap(),
    )
    .unwrap();
    fixture_git(&repository, &["init", "-q"]);
    fixture_git(&repository, &["config", "user.name", "Fixture"]);
    fixture_git(
        &repository,
        &["config", "user.email", "fixture@automonique.invalid"],
    );
    fixture_git(&repository, &["add", "."]);
    fixture_git(&repository, &["commit", "-qm", "base"]);
    let base = fixture_git_text(&repository, &["rev-parse", "HEAD"]);
    let run = "session_admitted_001";
    let packet_path = repository.join(format!(".automonique/state/runs/{run}/packet.json"));
    std::fs::create_dir_all(packet_path.parent().unwrap()).unwrap();
    let program_sha = file_sha(&repository.join(".automonique/dev/program.yaml"));
    let objectives_sha = file_sha(&repository.join(".automonique/dev/objectives.json"));
    let guides_sha = file_sha(&repository.join(".automonique/dev/guides/manifest.json"));
    let packet = json!({"attempt_baseline":{"admission_safety_checks":"pass","git_head":base,"guides_sha256":guides_sha,"objectives_sha256":objectives_sha,"program_sha256":program_sha,"worktree_clean":true},"driver":"codex_session","guides_sha256":guides_sha,"immutable_base":base,"integration_ceiling":"proposal_only","iteration":1,"objective":objectives["objectives"][0],"objectives_sha256":objectives_sha,"prior_iteration":null,"program_sha256":program_sha,"run_id":run,"schema":"automonique.harness-objective-packet/v1","session_coordination":{"native_subagents":true},"work_item":program["items"][0]});
    std::fs::write(&packet_path, serde_json::to_vec_pretty(&packet).unwrap()).unwrap();
    let packet_sha = file_sha(&packet_path);
    let state = json!({"base":base,"branch":"master","deadline_at":"2099-01-01T00:00:00+00:00","driver":"codex_session","failures":0,"iteration":1,"packet":format!(".automonique/state/runs/{run}/packet.json"),"packet_sha256":packet_sha,"run_id":run,"schema":"automonique.harness-loop-state/v1","started_at":"2026-01-01T00:00:00+00:00","status":"claimed","stop_reason":null,"unchanged_results":0,"updated_at":"2026-01-01T00:00:00+00:00","work_id":"WORK-001"});
    std::fs::write(
        repository.join(".automonique/state/harness-loop.json"),
        serde_json::to_vec_pretty(&state).unwrap(),
    )
    .unwrap();
    let prior = std::env::current_dir().unwrap();
    std::env::set_current_dir(&repository).unwrap();
    let database = directory.path().join("controller.sqlite3");
    let worktrees = directory.path().join("worktrees");
    let expected = GitSha1::new(&base).unwrap();
    let mut drifted = LabController::open(
        directory.path().join("drifted.sqlite3"),
        expected.clone(),
        vec![RepoPath::parse("plan").unwrap()],
        UnavailableBuildBroker,
    )
    .unwrap();
    assert!(
        drifted
            .select_admitted_worktree(&repository, &worktrees)
            .is_err()
    );
    assert!(!worktrees.exists());
    let mut controller = LabController::open(
        &database,
        expected.clone(),
        vec![RepoPath::parse("leased").unwrap()],
        UnavailableBuildBroker,
    )
    .unwrap();
    let first = controller
        .select_admitted_worktree(&repository, &worktrees)
        .unwrap();
    assert_eq!(
        first.attempt().state(),
        automonique_lab::state::AttemptState::Paused
    );
    drop(controller);
    let mut reopened = LabController::open(
        &database,
        expected,
        vec![RepoPath::parse("leased").unwrap()],
        UnavailableBuildBroker,
    )
    .unwrap();
    let replay = reopened
        .select_admitted_worktree(&repository, &worktrees)
        .unwrap();
    assert_eq!(
        replay.worktree().reconciliation(),
        automonique_lab::worktree::Reconciliation::Replayed
    );
    let observed = reopened
        .handle(LabRequest::Observe(
            ObserveRequest::new(
                id("observe-admitted"),
                id("objective:WORK-001"),
                id("objective:WORK-001"),
                0,
                16,
            )
            .unwrap(),
        ))
        .unwrap();
    let unit = match observed {
        LabResponse::Observed(value) => value.unit().clone(),
        _ => panic!(),
    };
    let resumed = reopened
        .handle(LabRequest::Resume(
            ResumeRequest::new(
                id("resume-admitted"),
                id("objective:WORK-001"),
                id("objective:WORK-001"),
                unit.checkpoint_id().unwrap().clone(),
                unit.revision().get(),
                id("resume-admitted-key"),
            )
            .unwrap(),
        ))
        .unwrap();
    assert_eq!(
        match resumed {
            LabResponse::Action(value) => value.unit().state(),
            _ => panic!(),
        },
        UnitState::Running
    );
    std::env::set_current_dir(prior).unwrap();
}

fn file_sha(path: &Path) -> String {
    hex::encode(Sha256::digest(std::fs::read(path).unwrap()))
}
fn fixture_git(root: &Path, args: &[&str]) {
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success()
    );
}
fn fixture_git_text(root: &Path, args: &[&str]) -> String {
    String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned()
}
