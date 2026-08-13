// SPDX-License-Identifier: Elastic-2.0

use automonique_runner::capability::{
    LANDLOCK_ABI_FILESYSTEM, LANDLOCK_ABI_HIGHEST_KNOWN, LANDLOCK_ABI_TCP, LandlockFinding,
};
use automonique_runner::{
    BoundaryRequirement, BoundaryStatus, BoundarySubject, ExecutionBoundaryAssessment,
    LaunchBlocker, LinuxPrimitive,
};

/// The securityfs path this module used to treat as the Landlock signal. It is
/// read here only to prove the observation no longer depends on it.
const LANDLOCK_SECURITYFS_ENTRY: &str = "/sys/kernel/security/landlock";

/// Whether the assessment recorded Landlock support, read back through the
/// public surface: Landlock is a supporting primitive for filesystem isolation.
#[cfg(target_os = "linux")]
fn observed_landlock_support(assessment: &ExecutionBoundaryAssessment) -> bool {
    match assessment.status(BoundaryRequirement::FilesystemIsolation) {
        BoundaryStatus::PrimitiveObserved(primitives) => {
            primitives.contains(&LinuxPrimitive::LandlockSupport)
        }
        BoundaryStatus::Unavailable => false,
    }
}

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
        [LaunchBlocker::MissingReviewedHelperPin]
    );
    assert_eq!(
        refusal.blockers()[0].category(),
        "missing_reviewed_helper_pin"
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

/// The Landlock observation must track the kernel's own answer, on every host.
///
/// This is written as an equality against an independent probe rather than
/// against a constant, so it is equally correct on a host with no Landlock at
/// all. The clause that has teeth is the securityfs one: on a host where the
/// entry is absent and the kernel nevertheless supports Landlock — the
/// development host for this crate is exactly that — an observation derived
/// from the securityfs path reports no support and fails here.
#[cfg(target_os = "linux")]
#[test]
fn landlock_observation_follows_the_kernel_not_the_securityfs_entry() {
    let assessment = ExecutionBoundaryAssessment::observe(subject()).expect("fixed Linux probe");
    let observed = observed_landlock_support(&assessment);
    let kernel = LandlockFinding::probe();

    assert_eq!(
        observed,
        kernel.abi().is_some(),
        "the assessment and the kernel disagree about Landlock support"
    );

    let securityfs_entry = std::path::Path::new(LANDLOCK_SECURITYFS_ENTRY).exists();
    if kernel.abi().is_some() {
        assert!(
            observed,
            "the kernel supports Landlock but the assessment recorded none; securityfs entry present: {securityfs_entry}"
        );
    } else {
        assert!(
            !observed,
            "the assessment claimed Landlock support the kernel refuses; securityfs entry present: {securityfs_entry}"
        );
    }
}

/// A reported ABI floor must be one this build can name and must agree with the
/// accessors derived from it. The extra clause pins the concrete floor whenever
/// the host reaches ABI 4, which is what this crate's development host reports,
/// without asserting a host constant that would be wrong on an older kernel.
#[cfg(target_os = "linux")]
#[test]
fn a_reported_landlock_floor_is_nameable_and_self_consistent() {
    let LandlockFinding::Enforceable(measured) = LandlockFinding::probe() else {
        assert_eq!(
            LandlockFinding::probe().abi(),
            None,
            "unsupported Landlock must carry no ABI"
        );
        return;
    };
    assert!(
        (LANDLOCK_ABI_FILESYSTEM..=LANDLOCK_ABI_HIGHEST_KNOWN).contains(&measured.level()),
        "reported Landlock floor {measured} is outside the range this build can name"
    );
    assert!(measured.restricts_filesystem());
    assert_eq!(measured.denies_tcp(), measured.level() >= LANDLOCK_ABI_TCP);

    if measured.denies_tcp() {
        assert!(
            measured.level() >= LANDLOCK_ABI_TCP,
            "TCP denial was claimed below the ABI level that defines it"
        );
        let assessment =
            ExecutionBoundaryAssessment::observe(subject()).expect("fixed Linux probe");
        assert!(
            observed_landlock_support(&assessment),
            "a host measured at ABI {LANDLOCK_ABI_TCP} or above must record Landlock support"
        );
    }
}

/// Correcting what is observed must not upgrade what is claimed. Even with
/// Landlock support recorded, filesystem isolation stays unenforced and the
/// launch refusal stays complete.
#[cfg(target_os = "linux")]
#[test]
fn recorded_landlock_support_never_becomes_an_enforced_boundary() {
    let assessment = ExecutionBoundaryAssessment::observe(subject()).expect("fixed Linux probe");
    assert!(
        !assessment
            .status(BoundaryRequirement::FilesystemIsolation)
            .is_enforced()
    );
    assert_eq!(
        assessment.launch_refusal().unenforced_requirements(),
        BoundaryRequirement::ALL
    );
    assert_eq!(
        assessment.launch_refusal().blockers(),
        [LaunchBlocker::MissingReviewedHelperPin]
    );
}

/// Asking the kernel its Landlock version must not restrict the caller.
/// `Ruleset::create` and `restrict_self` are never reached, so the observation
/// is repeatable and the prober keeps its own filesystem view.
///
/// Read through `/proc/thread-self`, never `/proc/self`: `no_new_privs` and the
/// seccomp fields are per-thread while `/proc/self` reports the thread-group
/// leader, so a restriction applied on the worker thread this test runs on
/// would not appear there at all.
#[cfg(target_os = "linux")]
#[test]
fn observing_landlock_does_not_restrict_the_observing_process() {
    let before = std::fs::read_to_string("/proc/thread-self/status").expect("thread status");
    let first = ExecutionBoundaryAssessment::observe(subject()).expect("first observation");
    let second = ExecutionBoundaryAssessment::observe(subject()).expect("second observation");
    let after = std::fs::read_to_string("/proc/thread-self/status").expect("thread status");

    let field = |status: &str, name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name).map(|value| value.trim().to_owned()))
    };
    for name in ["NoNewPrivs:", "Seccomp:", "Seccomp_filters:"] {
        assert_eq!(
            field(&before, name),
            field(&after, name),
            "observing changed this process's {name} state"
        );
    }
    assert!(
        std::fs::read_dir("/").is_ok(),
        "observing restricted this process's filesystem view"
    );
    assert_eq!(first.evidence_sha256(), second.evidence_sha256());
}
