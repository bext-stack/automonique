// SPDX-License-Identifier: Elastic-2.0

//! R1-15 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `docs/product-plan/requirements/models-media-and-execution.md`.

use automonique_protocol::host::{
    AttemptId, AttemptLog, ClaimRegistry, ExecutionHost, HostBoundary, HostError, HostId,
    HostLifetime, HostState, IdleDeadline, RestartClassification, RestartEvidence, RunPlacement,
    WorkId, classify_restart,
};
use automonique_protocol::primitives::EpochMillis;

fn host_id(value: &str) -> HostId {
    HostId::new(value).expect("valid host id")
}

fn attempt_id(value: &str) -> AttemptId {
    AttemptId::new(value).expect("valid attempt id")
}

fn work_id(value: &str) -> WorkId {
    WorkId::new(value).expect("valid work id")
}

fn boundary() -> HostBoundary {
    HostBoundary::new("acme", "account-1", "ws-hash-1", "boot-1").expect("valid boundary")
}

fn at(millis: i64) -> EpochMillis {
    EpochMillis::from_millis(millis)
}

fn host() -> ExecutionHost {
    ExecutionHost::new(host_id("h-1"), HostLifetime::Session, boundary())
}

mod identity_distinctness {
    use super::*;

    #[test]
    fn the_identities_are_separate_values() {
        // The same spelling in three domains stays three distinct values; the
        // compile-fail proof lives in the library doc tests.
        assert_eq!(work_id("x-1").as_str(), "x-1");
        assert_eq!(attempt_id("x-1").as_str(), "x-1");
        assert_eq!(host_id("x-1").as_str(), "x-1");
    }
}

mod retry_appends {
    use super::*;

    #[test]
    fn a_retry_adds_an_attempt_without_replacing_the_previous_one() {
        let log = AttemptLog::new(work_id("w-1"), attempt_id("a-1"));
        assert_eq!(log.attempts().len(), 1);
        assert_eq!(log.latest().number(), 1);
        assert!(log.latest().retry_of().is_none());

        let retried = log.retry(attempt_id("a-2"));
        assert_eq!(retried.attempts().len(), 2);
        assert_eq!(retried.latest().number(), 2);
        assert_eq!(
            retried
                .latest()
                .retry_of()
                .expect("links to its predecessor")
                .as_str(),
            "a-1"
        );

        // The first attempt is still addressable, in both logs.
        assert_eq!(retried.attempts()[0].id().as_str(), "a-1");
        assert_eq!(log.attempts().len(), 1, "the original log is unchanged");
    }

    #[test]
    fn attempt_numbers_increase_by_one_across_a_chain() {
        let mut log = AttemptLog::new(work_id("w-1"), attempt_id("a-1"));
        for index in 2..=5_u32 {
            log = log.retry(attempt_id(&format!("a-{index}")));
            assert_eq!(log.latest().number(), index);
        }
        let numbers: Vec<u32> = log.attempts().iter().map(|a| a.number()).collect();
        assert_eq!(numbers, vec![1, 2, 3, 4, 5]);
        assert_eq!(log.latest().work().as_str(), "w-1");
    }
}

mod lifetime_immutability {
    use super::*;

    #[test]
    fn a_lifetime_change_is_refused() {
        let session_host = host();
        assert_eq!(
            session_host
                .set_lifetime(HostLifetime::Attempt)
                .expect_err("immutable"),
            HostError::LifetimeIsImmutable {
                lifetime: HostLifetime::Session,
            }
        );
        assert_eq!(session_host.lifetime(), HostLifetime::Session);
    }

    #[test]
    fn both_lifetimes_are_constructible_and_stay_put() {
        let attempt_host = ExecutionHost::new(host_id("h-2"), HostLifetime::Attempt, boundary());
        assert_eq!(attempt_host.lifetime(), HostLifetime::Attempt);
        assert!(attempt_host.set_lifetime(HostLifetime::Session).is_err());
    }
}

mod boundary_bound_attach {
    use super::*;

    #[test]
    fn an_identical_boundary_attaches() {
        host().attach_within(&boundary()).expect("same boundary");
    }

    #[test]
    fn a_differing_component_is_named() {
        let cases = [
            (
                "tenant",
                HostBoundary::new("globex", "account-1", "ws-hash-1", "boot-1"),
            ),
            (
                "provider_account",
                HostBoundary::new("acme", "account-2", "ws-hash-1", "boot-1"),
            ),
            (
                "workspace_context",
                HostBoundary::new("acme", "account-1", "ws-hash-2", "boot-1"),
            ),
            (
                "boot_id",
                HostBoundary::new("acme", "account-1", "ws-hash-1", "boot-2"),
            ),
        ];
        for (component, other) in cases {
            let other = other.expect("valid boundary");
            assert_eq!(
                host().attach_within(&other).expect_err("differs"),
                HostError::BoundaryMismatch { component },
                "expected a mismatch in {component}"
            );
        }
    }
}

mod transition_legality {
    use super::*;

    #[test]
    fn terminal_states_have_no_successors() {
        for state in HostState::ALL
            .into_iter()
            .filter(|state| state.is_terminal())
        {
            assert!(
                state.legal_successors().is_empty(),
                "{} has outgoing transitions",
                state.as_str()
            );
            for target in HostState::ALL {
                assert!(
                    state.transition_to(target).is_err(),
                    "{} escaped to {}",
                    state.as_str(),
                    target.as_str()
                );
            }
        }
    }

    #[test]
    fn every_declared_transition_is_accepted_and_the_rest_are_refused() {
        for from in HostState::ALL {
            for to in HostState::ALL {
                let declared = from.legal_successors().contains(&to);
                let result = from.transition_to(to);
                assert_eq!(
                    result.is_ok(),
                    declared,
                    "{} -> {} disagreed with the table",
                    from.as_str(),
                    to.as_str()
                );
                if !declared {
                    assert_eq!(
                        result.expect_err("refused"),
                        HostError::IllegalTransition { from, to }
                    );
                }
            }
        }
    }

    #[test]
    fn a_representative_lifecycle_runs_end_to_end() {
        let started = host();
        assert_eq!(started.state(), HostState::Starting);
        let ready = started.transition_to(HostState::Ready).expect("ready");
        let busy = ready.transition_to(HostState::Busy).expect("busy");
        let idle = busy.transition_to(HostState::Idle).expect("idle");
        let hibernated = idle
            .transition_to(HostState::Hibernated)
            .expect("hibernated");
        let woken = hibernated.transition_to(HostState::Ready).expect("woken");
        let stopping = woken.transition_to(HostState::Stopping).expect("stopping");
        let stopped = stopping.transition_to(HostState::Stopped).expect("stopped");
        assert!(stopped.state().is_terminal());
    }

    #[test]
    fn state_spellings_are_distinct() {
        let mut spellings: Vec<&str> = HostState::ALL.iter().map(|s| s.as_str()).collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total);
    }
}

mod host_assignment_atomicity {
    use super::*;

    #[test]
    fn a_running_placement_always_carries_a_host() {
        let running = RunPlacement::start_on(host_id("h-1"));
        assert_eq!(
            running.host().expect("running carries a host").as_str(),
            "h-1"
        );
    }

    #[test]
    fn only_pre_launch_placements_lack_a_host() {
        for placement in [
            RunPlacement::Pending,
            RunPlacement::AdmissionBlocked,
            RunPlacement::PreLaunchCancelled,
        ] {
            assert!(
                placement.host().is_none(),
                "a pre-launch placement must not carry a host"
            );
        }
    }
}

mod expiry_purity {
    use super::*;

    #[test]
    fn expiry_is_a_pure_function_of_the_supplied_instants() {
        let deadline = IdleDeadline::new(at(1_000), 500);
        assert!(!deadline.is_expired_at(at(1_499)));
        assert!(deadline.is_expired_at(at(1_500)), "the ttl is inclusive");
        assert!(deadline.is_expired_at(at(9_999)));

        // Repeated evaluation with the same instant never differs, and no
        // clock is consulted to decide.
        for _ in 0..8 {
            assert!(!deadline.is_expired_at(at(1_000)));
        }
    }

    #[test]
    fn a_clock_that_runs_backwards_does_not_expire_a_window() {
        let deadline = IdleDeadline::new(at(5_000), 500);
        assert!(
            !deadline.is_expired_at(at(0)),
            "a saturating difference must not wrap into an expiry"
        );
    }
}

mod restart_classification {
    use super::*;

    #[test]
    fn absent_evidence_requires_reconciliation() {
        assert_eq!(
            classify_restart(RestartEvidence {
                recorded_state: None,
                provider_reports_resumable: None,
            }),
            RestartClassification::ReconciliationRequired
        );
        assert_eq!(
            classify_restart(RestartEvidence {
                recorded_state: None,
                provider_reports_resumable: Some(true),
            }),
            RestartClassification::ReconciliationRequired,
            "a provider claim without a recorded state is not enough"
        );
    }

    #[test]
    fn an_ambiguous_provider_answer_requires_reconciliation() {
        assert_eq!(
            classify_restart(RestartEvidence {
                recorded_state: Some(HostState::Busy),
                provider_reports_resumable: None,
            }),
            RestartClassification::ReconciliationRequired
        );
    }

    #[test]
    fn resumable_requires_an_authoritative_provider_answer() {
        assert_eq!(
            classify_restart(RestartEvidence {
                recorded_state: Some(HostState::Busy),
                provider_reports_resumable: Some(true),
            }),
            RestartClassification::Resumable
        );
        assert_eq!(
            classify_restart(RestartEvidence {
                recorded_state: Some(HostState::Hibernated),
                provider_reports_resumable: Some(true),
            }),
            RestartClassification::Hibernated
        );
        assert_eq!(
            classify_restart(RestartEvidence {
                recorded_state: Some(HostState::Busy),
                provider_reports_resumable: Some(false),
            }),
            RestartClassification::TerminallyInterrupted
        );
    }

    #[test]
    fn a_terminal_recorded_state_is_terminal_whatever_the_provider_says() {
        for state in HostState::ALL
            .into_iter()
            .filter(|state| state.is_terminal())
        {
            for reported in [None, Some(true), Some(false)] {
                assert_eq!(
                    classify_restart(RestartEvidence {
                        recorded_state: Some(state),
                        provider_reports_resumable: reported,
                    }),
                    RestartClassification::TerminallyInterrupted,
                    "{} with provider answer {reported:?}",
                    state.as_str()
                );
            }
        }
    }

    #[test]
    fn classification_is_total_and_never_invents_a_running_host() {
        // Drive every combination the evidence can take. No input yields a
        // "running" answer, because process presence is not an input at all.
        let states: Vec<Option<HostState>> = std::iter::once(None)
            .chain(HostState::ALL.into_iter().map(Some))
            .collect();
        for recorded_state in states {
            for provider_reports_resumable in [None, Some(true), Some(false)] {
                let classification = classify_restart(RestartEvidence {
                    recorded_state,
                    provider_reports_resumable,
                });
                assert!(!classification.as_str().is_empty());
                if recorded_state.is_none() {
                    assert_eq!(
                        classification,
                        RestartClassification::ReconciliationRequired,
                        "absent evidence must never resolve to anything else"
                    );
                }
            }
        }
    }
}

mod claim_lifecycle {
    use super::*;

    #[test]
    fn a_claim_cannot_be_released_while_its_work_is_active() {
        let mut claims = ClaimRegistry::new();
        claims.claim("scope-1", "w-1").expect("claimed");
        assert_eq!(
            claims.release("scope-1").expect_err("still active"),
            HostError::ClaimStillActive {
                work: "w-1".to_owned(),
            }
        );
        assert_eq!(claims.holder_of("scope-1"), Some("w-1"));
    }

    #[test]
    fn a_terminal_or_verified_loss_permits_release() {
        let mut claims = ClaimRegistry::new();
        claims.claim("scope-1", "w-1").expect("claimed");
        claims.mark_releasable("scope-1");
        claims.release("scope-1").expect("released");
        assert_eq!(claims.holder_of("scope-1"), None);
        claims.claim("scope-1", "w-2").expect("now available");
    }

    #[test]
    fn a_second_work_item_cannot_take_a_held_claim() {
        let mut claims = ClaimRegistry::new();
        claims.claim("scope-1", "w-1").expect("claimed");
        assert_eq!(
            claims.claim("scope-1", "w-2").expect_err("held"),
            HostError::ClaimStillActive {
                work: "w-1".to_owned(),
            }
        );
    }

    #[test]
    fn a_reload_transfers_ownership_without_deleting_the_claim() {
        let mut claims = ClaimRegistry::new();
        claims.claim("scope-1", "w-1").expect("claimed");
        claims.transfer_ownership("gen-2");

        let holder = claims.holder_of("scope-1").expect("still held");
        assert!(
            holder.contains("gen-2"),
            "ownership moved to the new generation"
        );
        // The key is still not free, so a paused old generation cannot act by
        // finding it available.
        assert!(claims.claim("scope-1", "w-9").is_err());
    }
}
