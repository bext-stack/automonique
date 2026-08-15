// SPDX-License-Identifier: Elastic-2.0

//! Tighten-only approval composition, proved by enumeration.
//!
//! The lattice is three-valued and the source count is three, so every claim
//! this module makes about composition is checked over all twenty-seven
//! triples rather than over a sample. The gate claims are checked over all
//! twenty-seven triples times three evidence values times all eight surface
//! combinations — 648 cases — which is small enough that a property generator
//! would only add a dependency and a seed.

use automonique_policy::approval::{
    ApprovalEvidence, ApprovalGate, ApprovalPolicyRefusal, ApprovalRequirement, ApprovalSources,
    OperatorSurfaces, decide,
};
use automonique_policy::peer::{PeerCredential, PeerPolicy};

const OWNER: u32 = 1000;

/// Every ordered triple of requirements. Twenty-seven, by construction.
fn triples() -> Vec<(
    ApprovalRequirement,
    ApprovalRequirement,
    ApprovalRequirement,
)> {
    let mut triples = Vec::new();
    for config in ApprovalRequirement::ALL {
        for host in ApprovalRequirement::ALL {
            for per_call in ApprovalRequirement::ALL {
                triples.push((config, host, per_call));
            }
        }
    }
    triples
}

/// Every combination of live surfaces. Eight, by construction.
fn surface_sets() -> Vec<OperatorSurfaces> {
    let mut sets = Vec::new();
    for telegram in [false, true] {
        for slack in [false, true] {
            for peer in [false, true] {
                let mut surfaces = OperatorSurfaces::none();
                if telegram {
                    surfaces = surfaces.with_telegram_poller();
                }
                if slack {
                    surfaces = surfaces.with_slack_approvals();
                }
                if peer {
                    surfaces = surfaces.with_admitted_peer(admission());
                }
                sets.push(surfaces);
            }
        }
    }
    sets
}

/// An admission that only the peer policy can have produced.
fn admission() -> automonique_policy::peer::Admission {
    PeerPolicy::new(&[OWNER])
        .expect("non-empty admitted set")
        .evaluate(Some(PeerCredential::new(OWNER, OWNER, 4242)))
        .expect("admitted peer")
}

mod lattice {
    use super::*;

    #[test]
    fn the_declaration_order_is_the_strictness_order() {
        assert!(ApprovalRequirement::Allowed < ApprovalRequirement::ApprovalRequired);
        assert!(ApprovalRequirement::ApprovalRequired < ApprovalRequirement::Forbidden);
        for (index, requirement) in ApprovalRequirement::ALL.into_iter().enumerate() {
            assert_eq!(
                u8::try_from(index).expect("three variants fit a byte"),
                requirement.rank(),
                "rank must agree with the declared order for {requirement}"
            );
        }
    }

    #[test]
    fn spellings_round_trip_and_an_unknown_one_is_refused() {
        for requirement in ApprovalRequirement::ALL {
            assert_eq!(
                ApprovalRequirement::from_spelling(requirement.as_str()),
                Some(requirement)
            );
        }
        assert_eq!(ApprovalRequirement::from_spelling("Allowed"), None);
        assert_eq!(ApprovalRequirement::from_spelling(""), None);
        assert_eq!(ApprovalRequirement::from_spelling("permitted"), None);
    }

    #[test]
    fn tighten_is_the_maximum_of_the_total_order() {
        for left in ApprovalRequirement::ALL {
            for right in ApprovalRequirement::ALL {
                let joined = left.tighten(right);
                assert_eq!(joined.rank(), left.rank().max(right.rank()));
                assert_eq!(joined, left.max(right));
            }
        }
    }

    #[test]
    fn tighten_is_commutative_associative_and_idempotent() {
        for (first, second, third) in triples() {
            assert_eq!(first.tighten(second), second.tighten(first));
            assert_eq!(
                first.tighten(second).tighten(third),
                first.tighten(second.tighten(third))
            );
            assert_eq!(first.tighten(first), first);
        }
    }

    #[test]
    fn composition_is_never_looser_than_any_one_source() {
        for (config, host, per_call) in triples() {
            let composed = ApprovalSources::new(config, host, per_call).compose();
            for source in [config, host, per_call] {
                assert!(
                    composed.rank() >= source.rank(),
                    "composing {config}/{host}/{per_call} produced {composed}, \
                     which is looser than {source}"
                );
            }
        }
    }

    #[test]
    fn composition_is_the_strictest_source_and_is_order_independent() {
        for (config, host, per_call) in triples() {
            let composed = ApprovalSources::new(config, host, per_call).compose();
            let strictest = [config, host, per_call]
                .into_iter()
                .max()
                .expect("three sources");
            assert_eq!(composed, strictest);

            // Every permutation of the same three values composes identically,
            // which is what makes "the order the daemon folds them in" not a
            // security-relevant decision.
            for permutation in [
                (config, per_call, host),
                (host, config, per_call),
                (host, per_call, config),
                (per_call, config, host),
                (per_call, host, config),
            ] {
                assert_eq!(
                    ApprovalSources::new(permutation.0, permutation.1, permutation.2).compose(),
                    composed
                );
            }
        }
    }

    #[test]
    fn sources_report_back_exactly_what_they_were_given() {
        for (config, host, per_call) in triples() {
            let sources = ApprovalSources::new(config, host, per_call);
            assert_eq!(sources.config(), config);
            assert_eq!(sources.host(), host);
            assert_eq!(sources.per_call(), per_call);
        }
    }

    #[test]
    fn an_unenforceable_host_forbids_and_an_enforceable_one_imposes_nothing() {
        assert_eq!(
            ApprovalRequirement::for_measured_host(false),
            ApprovalRequirement::Forbidden
        );
        assert_eq!(
            ApprovalRequirement::for_measured_host(true),
            ApprovalRequirement::Allowed
        );
    }
}

mod surfaces {
    use super::*;

    #[test]
    fn only_the_empty_surface_set_is_unreachable() {
        for surfaces in surface_sets() {
            let live = surfaces.telegram_poller() || surfaces.slack_approvals();
            assert_eq!(
                surfaces.any_reachable(),
                live || surfaces.admitted_peer(),
                "reachability must be the disjunction of the live surfaces"
            );
        }
        assert!(!OperatorSurfaces::none().any_reachable());
        assert_eq!(
            surface_sets()
                .into_iter()
                .filter(|surfaces| !surfaces.any_reachable())
                .count(),
            1,
            "exactly one of the eight combinations is unreachable"
        );
    }

    #[test]
    fn each_constructor_lights_exactly_one_surface() {
        let telegram = OperatorSurfaces::none().with_telegram_poller();
        assert!(telegram.telegram_poller());
        assert!(!telegram.slack_approvals());
        assert!(!telegram.admitted_peer());

        let slack = OperatorSurfaces::none().with_slack_approvals();
        assert!(slack.slack_approvals());
        assert!(!slack.telegram_poller());
        assert!(!slack.admitted_peer());

        let peer = OperatorSurfaces::none().with_admitted_peer(admission());
        assert!(peer.admitted_peer());
        assert!(!peer.telegram_poller());
        assert!(!peer.slack_approvals());
    }

    #[test]
    fn a_refused_peer_yields_no_admission_and_therefore_no_surface() {
        // The difference between a configured surface and a live one, stated as
        // a type: there is no way to reach `with_admitted_peer` from here.
        let refusal = PeerPolicy::new(&[OWNER])
            .expect("non-empty admitted set")
            .evaluate(Some(PeerCredential::new(OWNER + 1, OWNER, 4242)))
            .expect_err("a foreign uid is refused");
        assert_eq!(refusal.category(), "uid_not_admitted");
    }
}

mod gate {
    use super::*;

    #[test]
    fn forbidden_refuses_whatever_the_evidence_and_the_surfaces_say() {
        for (config, host, per_call) in triples() {
            let sources = ApprovalSources::new(config, host, per_call);
            if sources.compose() != ApprovalRequirement::Forbidden {
                continue;
            }
            for surfaces in surface_sets() {
                for evidence in ApprovalEvidence::ALL {
                    assert_eq!(
                        decide(sources, surfaces, evidence),
                        ApprovalGate::Refuse(ApprovalPolicyRefusal::Forbidden),
                        "a granted decision must not reach a forbidden action"
                    );
                }
            }
        }
    }

    #[test]
    fn allowed_proceeds_without_consulting_evidence_or_surfaces() {
        let sources = ApprovalSources::new(
            ApprovalRequirement::Allowed,
            ApprovalRequirement::Allowed,
            ApprovalRequirement::Allowed,
        );
        for surfaces in surface_sets() {
            for evidence in ApprovalEvidence::ALL {
                assert_eq!(decide(sources, surfaces, evidence), ApprovalGate::Proceed);
            }
        }
    }

    #[test]
    fn a_required_decision_with_no_live_surface_refuses_rather_than_waits() {
        let sources = ApprovalSources::new(
            ApprovalRequirement::ApprovalRequired,
            ApprovalRequirement::Allowed,
            ApprovalRequirement::Allowed,
        );
        assert_eq!(
            decide(
                sources,
                OperatorSurfaces::none(),
                ApprovalEvidence::Undecided
            ),
            ApprovalGate::Refuse(ApprovalPolicyRefusal::ApprovalUnreachable)
        );
        // A decision that already exists needs no surface to carry it back.
        assert_eq!(
            decide(sources, OperatorSurfaces::none(), ApprovalEvidence::Granted),
            ApprovalGate::Proceed
        );
        assert_eq!(
            decide(sources, OperatorSurfaces::none(), ApprovalEvidence::Denied),
            ApprovalGate::Refuse(ApprovalPolicyRefusal::ApprovalDenied)
        );
    }

    #[test]
    fn every_case_answers_exactly_one_way_and_evidence_only_ever_loosens_within_its_lane() {
        for (config, host, per_call) in triples() {
            let sources = ApprovalSources::new(config, host, per_call);
            let composed = sources.compose();
            for surfaces in surface_sets() {
                let undecided = decide(sources, surfaces, ApprovalEvidence::Undecided);
                for evidence in ApprovalEvidence::ALL {
                    let gate = decide(sources, surfaces, evidence);
                    match composed {
                        ApprovalRequirement::Forbidden => {
                            assert_eq!(
                                gate,
                                ApprovalGate::Refuse(ApprovalPolicyRefusal::Forbidden)
                            );
                            assert!(!gate.proceeds());
                        }
                        ApprovalRequirement::Allowed => {
                            assert_eq!(gate, ApprovalGate::Proceed);
                        }
                        ApprovalRequirement::ApprovalRequired => match evidence {
                            ApprovalEvidence::Granted => assert_eq!(gate, ApprovalGate::Proceed),
                            ApprovalEvidence::Denied => assert_eq!(
                                gate,
                                ApprovalGate::Refuse(ApprovalPolicyRefusal::ApprovalDenied)
                            ),
                            ApprovalEvidence::Undecided => assert_eq!(
                                gate,
                                if surfaces.any_reachable() {
                                    ApprovalGate::Propose
                                } else {
                                    ApprovalGate::Refuse(ApprovalPolicyRefusal::ApprovalUnreachable)
                                }
                            ),
                        },
                    }
                    // A granted decision never turns a refusal into a proposal
                    // or a proposal into anything but a start: evidence has one
                    // reachable effect and it is inside `ApprovalRequired`.
                    if evidence == ApprovalEvidence::Granted && gate != undecided {
                        assert_eq!(composed, ApprovalRequirement::ApprovalRequired);
                        assert_eq!(gate, ApprovalGate::Proceed);
                    }
                }
            }
        }
    }

    #[test]
    fn tightening_any_one_source_never_loosens_the_answer() {
        for (config, host, per_call) in triples() {
            for surfaces in surface_sets() {
                for evidence in ApprovalEvidence::ALL {
                    let base = ApprovalSources::new(config, host, per_call);
                    for stricter in ApprovalRequirement::ALL {
                        for tightened in [
                            ApprovalSources::new(config.tighten(stricter), host, per_call),
                            ApprovalSources::new(config, host.tighten(stricter), per_call),
                            ApprovalSources::new(config, host, per_call.tighten(stricter)),
                        ] {
                            assert!(
                                tightened.compose().rank() >= base.compose().rank(),
                                "tightening one source lowered the composed requirement"
                            );
                            if !decide(base, surfaces, evidence).proceeds() {
                                assert!(
                                    !decide(tightened, surfaces, evidence).proceeds(),
                                    "tightening a source turned a refusal into a start"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn refusal_categories_are_distinct_and_stable() {
        let categories: Vec<&str> = ApprovalPolicyRefusal::ALL
            .into_iter()
            .map(ApprovalPolicyRefusal::category)
            .collect();
        assert_eq!(
            categories,
            vec!["forbidden", "approval_denied", "approval_unreachable"]
        );
        let mut sorted = categories.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), categories.len());
    }

    #[test]
    fn evidence_spellings_are_stable() {
        let spellings: Vec<&str> = ApprovalEvidence::ALL
            .into_iter()
            .map(ApprovalEvidence::as_str)
            .collect();
        assert_eq!(spellings, vec!["undecided", "granted", "denied"]);
    }
}
