// SPDX-License-Identifier: Elastic-2.0

use automonique_runner::{
    BoundaryRequirement, BoundarySubject, ExecutionBoundaryAssessment, LaunchBlocker,
};

fn subject() -> BoundarySubject {
    BoundarySubject::new(
        "runner-detection-test",
        "run-detection-test",
        "a".repeat(64),
        "b".repeat(64),
    )
    .expect("bounded subject")
}

#[cfg(target_os = "linux")]
#[test]
fn current_linux_host_observation_never_grants_launch_authority() {
    let assessment = ExecutionBoundaryAssessment::observe(subject()).expect("fixed Linux probe");
    let refusal = assessment.launch_refusal();
    assert_eq!(refusal.evidence_sha256(), assessment.evidence_sha256());
    assert_eq!(refusal.unenforced_requirements(), BoundaryRequirement::ALL);
    assert_eq!(
        refusal.blockers(),
        [LaunchBlocker::MissingDescriptorClosure]
    );
    assert_eq!(
        refusal.blockers()[0].category(),
        "missing_descriptor_closure"
    );
    for requirement in BoundaryRequirement::ALL {
        assert!(
            !assessment.status(requirement).is_enforced(),
            "primitive detection must not become enforcement for {requirement:?}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn fixed_path_observation_is_repeatable_for_the_same_subject() {
    let first = ExecutionBoundaryAssessment::observe(subject()).expect("first observation");
    let second = ExecutionBoundaryAssessment::observe(subject()).expect("second observation");
    assert_eq!(first.evidence_sha256(), second.evidence_sha256());
    assert_eq!(first.launch_refusal(), second.launch_refusal());
}
