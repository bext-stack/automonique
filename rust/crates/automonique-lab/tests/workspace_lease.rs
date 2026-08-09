// SPDX-License-Identifier: Elastic-2.0

use automonique_lab::workspace_lease::{
    AcquireLease, ActionId, AttemptId, BaseRevision, FenceEpoch, LeaseDenial, LeaseId,
    LeaseRegistry, Mutation, ReleaseLease, RepoPath, RepoPathError, Revision,
};

const BASE_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BASE_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn base(value: &str) -> BaseRevision {
    BaseRevision::parse(value).expect("test base is valid")
}

fn action(value: &str) -> ActionId {
    ActionId::parse(value).expect("test action ID is valid")
}

fn attempt(value: &str) -> AttemptId {
    AttemptId::parse(value).expect("test attempt ID is valid")
}

fn lease(value: &str) -> LeaseId {
    LeaseId::parse(value).expect("test lease ID is valid")
}

fn path(value: &str) -> RepoPath {
    RepoPath::parse(value).expect("test path is valid")
}

fn acquire(
    registry: &LeaseRegistry,
    action_id: &str,
    lease_id: &str,
    attempt_id: &str,
    paths: &[&str],
) -> AcquireLease {
    AcquireLease {
        action_id: action(action_id),
        lease_id: lease(lease_id),
        attempt_id: attempt(attempt_id),
        base_revision: registry.base_revision().clone(),
        expected_revision: registry.revision(),
        paths: paths.iter().copied().map(path).collect(),
    }
}

fn release(
    registry: &LeaseRegistry,
    action_id: &str,
    lease_id: &str,
    attempt_id: &str,
    epoch: FenceEpoch,
) -> ReleaseLease {
    ReleaseLease {
        action_id: action(action_id),
        lease_id: lease(lease_id),
        attempt_id: attempt(attempt_id),
        base_revision: registry.base_revision().clone(),
        expected_revision: registry.revision(),
        epoch,
    }
}

#[test]
fn validates_and_canonicalizes_base_and_repo_paths() {
    let uppercase = BaseRevision::parse("ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD")
        .expect("uppercase hexadecimal is accepted");
    assert_eq!(
        uppercase.as_str(),
        "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
    );
    assert!(BaseRevision::parse("abc").is_err());
    assert!(BaseRevision::parse("gggggggggggggggggggggggggggggggggggggggg").is_err());

    let canonical = path("crates/automonique-lab/src/lib.rs");
    assert_eq!(canonical.as_str(), "crates/automonique-lab/src/lib.rs");
    for invalid in [
        "",
        "/absolute",
        "C:/windows",
        "a\\b",
        "a//b",
        "a/./b",
        "a/../b",
        "a/",
        "line\nbreak",
    ] {
        assert!(RepoPath::parse(invalid).is_err(), "accepted {invalid:?}");
    }
    assert_eq!(RepoPath::parse(""), Err(RepoPathError::Empty));
}

#[test]
fn reserved_git_segments_are_denied_at_any_depth_without_registry_mutation() {
    let registry = LeaseRegistry::new(base(BASE_A));
    let before = registry.clone();
    for (candidate, index) in [
        (".git", 0),
        (".git/config", 0),
        ("src/.git/config", 1),
        ("src/.GiT/hooks/pre-commit", 1),
        ("nested/path/.GIT", 2),
    ] {
        assert_eq!(
            RepoPath::parse(candidate),
            Err(RepoPathError::ReservedGitSegment { index }),
            "accepted reserved path {candidate:?}"
        );
        assert_eq!(registry, before, "path denial changed lease state");
    }
    assert!(RepoPath::parse(".github/workflows/check.yml").is_ok());
    assert!(RepoPath::parse("src/git/config.rs").is_ok());
}

#[test]
fn lease_identifiers_require_an_ascii_alphanumeric_first_byte() {
    for invalid in [".leading", "_leading", ":leading", "-leading"] {
        assert!(
            ActionId::parse(invalid).is_err(),
            "accepted action {invalid:?}"
        );
        assert!(
            AttemptId::parse(invalid).is_err(),
            "accepted attempt {invalid:?}"
        );
        assert!(
            LeaseId::parse(invalid).is_err(),
            "accepted lease {invalid:?}"
        );
    }
    for valid in ["a", "A._:-", "0-leading"] {
        assert!(ActionId::parse(valid).is_ok(), "denied action {valid:?}");
        assert!(AttemptId::parse(valid).is_ok(), "denied attempt {valid:?}");
        assert!(LeaseId::parse(valid).is_ok(), "denied lease {valid:?}");
    }
}

#[test]
fn disjoint_and_segment_prefix_paths_can_be_leased() {
    let mut registry = LeaseRegistry::new(base(BASE_A));
    let first = registry
        .acquire(acquire(
            &registry,
            "acquire-1",
            "lease-1",
            "attempt-1",
            &["src/a"],
        ))
        .expect("first lease");
    assert!(matches!(first, Mutation::Applied(_)));

    let second = registry
        .acquire(acquire(
            &registry,
            "acquire-2",
            "lease-2",
            "attempt-2",
            &["src/ab", "tests/a"],
        ))
        .expect("segment prefix is not ancestry");
    assert!(matches!(second, Mutation::Applied(_)));
    assert_eq!(registry.revision(), Revision::from_u64(2));
    assert_eq!(registry.active_grants().len(), 2);
}

#[test]
fn exact_ancestor_and_descendant_conflicts_are_denied_without_mutation() {
    for (held, requested) in [
        ("src/lib.rs", "src/lib.rs"),
        ("src", "src/lib.rs"),
        ("src/lib.rs", "src"),
    ] {
        let mut registry = LeaseRegistry::new(base(BASE_A));
        registry
            .acquire(acquire(
                &registry,
                "acquire-held",
                "held",
                "attempt-held",
                &[held],
            ))
            .expect("held lease");
        let before = registry.clone();
        let denial = registry.acquire(acquire(
            &registry,
            "acquire-requested",
            "requested",
            "attempt-requested",
            &[requested],
        ));
        assert!(matches!(denial, Err(LeaseDenial::PathConflict { .. })));
        assert_eq!(registry, before, "denial mutated {held} vs {requested}");
    }
}

#[test]
fn a_multi_path_acquire_is_atomic_when_one_path_conflicts() {
    let mut registry = LeaseRegistry::new(base(BASE_A));
    registry
        .acquire(acquire(
            &registry,
            "acquire-held",
            "held",
            "attempt-held",
            &["src/held"],
        ))
        .expect("held lease");
    let before = registry.clone();
    let denial = registry.acquire(acquire(
        &registry,
        "acquire-many",
        "many",
        "attempt-many",
        &["free/a", "src/held/child", "free/b"],
    ));
    assert!(matches!(denial, Err(LeaseDenial::PathConflict { .. })));
    assert_eq!(registry, before);
    assert!(registry.active_grant(&lease("many")).is_none());
}

#[test]
fn empty_duplicate_and_internally_overlapping_sets_are_immutable_denials() {
    for paths in [vec![], vec!["src", "src"], vec!["src", "src/lib.rs"]] {
        let mut registry = LeaseRegistry::new(base(BASE_A));
        let before = registry.clone();
        let denial = registry.acquire(acquire(&registry, "acquire", "lease", "attempt", &paths));
        assert!(matches!(
            denial,
            Err(LeaseDenial::EmptyPathSet | LeaseDenial::RequestedPathsOverlap { .. })
        ));
        assert_eq!(registry, before);
    }
}

#[test]
fn oversized_path_set_is_a_bounded_immutable_denial() {
    let mut registry = LeaseRegistry::new(base(BASE_A));
    let before = registry.clone();
    let paths = (0..1025)
        .map(|index| path(&format!("generated/{index}")))
        .collect();
    let denial = registry.acquire(AcquireLease {
        action_id: action("acquire-many"),
        lease_id: lease("lease-many"),
        attempt_id: attempt("attempt-many"),
        base_revision: base(BASE_A),
        expected_revision: Revision::default(),
        paths,
    });
    assert_eq!(
        denial,
        Err(LeaseDenial::TooManyPaths {
            count: 1025,
            maximum: 1024,
        })
    );
    assert_eq!(registry, before);
}

#[test]
fn base_and_revision_compare_and_swap_denials_do_not_mutate_state() {
    let mut registry = LeaseRegistry::new(base(BASE_A));
    let mut wrong_base = acquire(&registry, "wrong-base", "lease-1", "attempt-1", &["src/a"]);
    wrong_base.base_revision = base(BASE_B);
    let before = registry.clone();
    assert!(matches!(
        registry.acquire(wrong_base),
        Err(LeaseDenial::BaseRevisionMismatch { .. })
    ));
    assert_eq!(registry, before);

    let mut wrong_revision = acquire(
        &registry,
        "wrong-revision",
        "lease-1",
        "attempt-1",
        &["src/a"],
    );
    wrong_revision.expected_revision = Revision::from_u64(7);
    let before = registry.clone();
    assert!(matches!(
        registry.acquire(wrong_revision),
        Err(LeaseDenial::RevisionConflict { .. })
    ));
    assert_eq!(registry, before);
}

#[test]
fn exact_acquire_retry_replays_original_receipt_after_state_advances() {
    let mut registry = LeaseRegistry::new(base(BASE_A));
    let request = acquire(&registry, "acquire-1", "lease-1", "attempt-1", &["z", "a"]);
    let original = registry
        .acquire(request.clone())
        .expect("first acquire")
        .receipt()
        .clone();
    registry
        .acquire(acquire(
            &registry,
            "acquire-2",
            "lease-2",
            "attempt-2",
            &["other"],
        ))
        .expect("advance state");
    let before = registry.clone();
    let replay = registry.acquire(request).expect("receipt replay");
    assert_eq!(replay, Mutation::Replayed(original));
    assert_eq!(registry, before);
}

#[test]
fn reused_action_with_changed_payload_or_operation_is_denied_immutably() {
    let mut registry = LeaseRegistry::new(base(BASE_A));
    let applied = registry
        .acquire(acquire(
            &registry,
            "same-action",
            "lease-1",
            "attempt-1",
            &["src/a"],
        ))
        .expect("initial acquire");
    let epoch = applied.receipt().grant.epoch;

    let before = registry.clone();
    let changed = registry.acquire(acquire(
        &registry,
        "same-action",
        "lease-1",
        "attempt-1",
        &["src/b"],
    ));
    assert!(matches!(
        changed,
        Err(LeaseDenial::IdempotencyConflict { .. })
    ));
    assert_eq!(registry, before);

    let malformed_reuse = registry.acquire(AcquireLease {
        action_id: action("same-action"),
        lease_id: lease("lease-1"),
        attempt_id: attempt("attempt-1"),
        base_revision: base(BASE_A),
        expected_revision: registry.revision(),
        paths: Vec::new(),
    });
    assert!(matches!(
        malformed_reuse,
        Err(LeaseDenial::IdempotencyConflict { .. })
    ));
    assert_eq!(registry, before);

    let cross_operation = registry.release(release(
        &registry,
        "same-action",
        "lease-1",
        "attempt-1",
        epoch,
    ));
    assert!(matches!(
        cross_operation,
        Err(LeaseDenial::IdempotencyConflict { .. })
    ));
    assert_eq!(registry, before);
}

#[test]
fn active_lease_id_owner_and_missing_release_denials_are_immutable() {
    let mut registry = LeaseRegistry::new(base(BASE_A));
    let receipt = registry
        .acquire(acquire(
            &registry,
            "acquire",
            "lease",
            "attempt",
            &["src/a"],
        ))
        .expect("acquire")
        .receipt()
        .clone();

    let before = registry.clone();
    assert!(matches!(
        registry.acquire(acquire(
            &registry,
            "duplicate-id",
            "lease",
            "attempt",
            &["other"],
        )),
        Err(LeaseDenial::LeaseAlreadyActive { .. })
    ));
    assert_eq!(registry, before);

    assert!(matches!(
        registry.release(release(
            &registry,
            "wrong-owner",
            "lease",
            "another-attempt",
            receipt.grant.epoch,
        )),
        Err(LeaseDenial::LeaseOwnerMismatch { .. })
    ));
    assert_eq!(registry, before);

    assert!(matches!(
        registry.release(release(
            &registry,
            "missing",
            "missing",
            "attempt",
            FenceEpoch::from_u64(1),
        )),
        Err(LeaseDenial::LeaseNotActive { .. })
    ));
    assert_eq!(registry, before);
}

#[test]
fn release_retry_and_stale_epoch_cannot_release_a_reacquired_lease() {
    let mut registry = LeaseRegistry::new(base(BASE_A));
    let first_epoch = registry
        .acquire(acquire(
            &registry,
            "acquire-1",
            "lease",
            "attempt",
            &["src/a"],
        ))
        .expect("first acquire")
        .receipt()
        .grant
        .epoch;
    let release_request = release(&registry, "release-1", "lease", "attempt", first_epoch);
    let original_release = registry
        .release(release_request.clone())
        .expect("first release")
        .receipt()
        .clone();
    let second_epoch = registry
        .acquire(acquire(
            &registry,
            "acquire-2",
            "lease",
            "attempt",
            &["src/a"],
        ))
        .expect("reacquire")
        .receipt()
        .grant
        .epoch;
    assert!(second_epoch > first_epoch);

    let before = registry.clone();
    let replay = registry
        .release(release_request)
        .expect("original receipt remains replayable");
    assert_eq!(replay, Mutation::Replayed(original_release));
    assert_eq!(registry, before);

    let stale = registry.release(release(
        &registry,
        "release-stale",
        "lease",
        "attempt",
        first_epoch,
    ));
    assert!(matches!(stale, Err(LeaseDenial::Fenced { .. })));
    assert_eq!(registry, before);
    assert_eq!(
        registry
            .active_grant(&lease("lease"))
            .map(|grant| grant.epoch),
        Some(second_epoch)
    );
}

#[test]
fn release_base_and_revision_denials_leave_the_grant_active() {
    let mut registry = LeaseRegistry::new(base(BASE_A));
    let epoch = registry
        .acquire(acquire(
            &registry,
            "acquire",
            "lease",
            "attempt",
            &["src/a"],
        ))
        .expect("acquire")
        .receipt()
        .grant
        .epoch;

    let mut wrong_base = release(&registry, "release-base", "lease", "attempt", epoch);
    wrong_base.base_revision = base(BASE_B);
    let before = registry.clone();
    assert!(matches!(
        registry.release(wrong_base),
        Err(LeaseDenial::BaseRevisionMismatch { .. })
    ));
    assert_eq!(registry, before);

    let mut wrong_revision = release(&registry, "release-revision", "lease", "attempt", epoch);
    wrong_revision.expected_revision = Revision::from_u64(99);
    assert!(matches!(
        registry.release(wrong_revision),
        Err(LeaseDenial::RevisionConflict { .. })
    ));
    assert_eq!(registry, before);
}
