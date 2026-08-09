// SPDX-License-Identifier: Elastic-2.0

use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

use automonique_lab::build::BuildBroker;
use automonique_lab::controller::{
    AccountingCapability, BuildUnavailable, ControllerFault, LabController, SyntheticBuildBroker,
    SyntheticBuildEvidence, SyntheticBuildRequest,
};
use automonique_lab::protocol::{
    ActionStatus, BudgetEnforcement, CancelReason, CancelRequest, Execution, GitSha1, LabBudget,
    LabBudgetValues, LabRequest, LabResponse, ObserveRequest, OpaqueId, ProviderPolicy,
    ResumeRequest, SelectRequest, SyntheticProviderPolicy, UnitState,
};
use automonique_lab::workspace_lease::RepoPath;

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
