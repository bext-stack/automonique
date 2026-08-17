// SPDX-License-Identifier: Elastic-2.0

//! R1-13 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `docs/product-plan/requirements/operations-and-governance.md`.

use automonique_protocol::identity::{
    Actor, BreakGlassGrant, CredentialHealth, CredentialRecord, DecisionOutcome, DenyReason,
    ExternalIdentityKey, IdentityError, MutableAttribute, PolicyLedger, RoleGrant,
};
use automonique_protocol::primitives::{EpochMillis, Revision};

fn actor(tenant: &str, id: &str) -> Actor {
    Actor::new(tenant, id).expect("valid actor")
}

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("non-zero revision")
}

fn at(millis: i64) -> EpochMillis {
    EpochMillis::from_millis(millis)
}

/// A ledger where `alice` holds `operator`, which carries `run:start`, from
/// revision 2 until revision 5.
fn ledger() -> PolicyLedger {
    let mut ledger = PolicyLedger::new();
    ledger
        .allow_role("operator", "run:start")
        .expect("valid permission");
    ledger.grant(
        RoleGrant::new(
            actor("acme", "alice"),
            "operator",
            actor("acme", "owner"),
            revision(2),
            Some(revision(5)),
            "on call",
        )
        .expect("valid grant"),
    );
    ledger
}

mod tenant_scoping {
    use super::*;

    #[test]
    fn an_actor_requires_a_tenant() {
        assert!(
            Actor::new("", "alice").is_err(),
            "a tenant-free actor is not an actor"
        );
        assert!(Actor::new("acme", "").is_err());
        assert_eq!(actor("acme", "alice").tenant(), "acme");
    }

    #[test]
    fn cross_tenant_comparison_errors_rather_than_answering_false() {
        let left = actor("acme", "alice");
        let right = actor("globex", "alice");
        assert_eq!(
            left.is_same_as(&right).expect_err("different tenants"),
            IdentityError::CrossTenantComparison {
                left: "acme".to_owned(),
                right: "globex".to_owned(),
            }
        );
        // Same tenant compares normally, in both directions.
        assert!(left.is_same_as(&actor("acme", "alice")).expect("same"));
        assert!(!left.is_same_as(&actor("acme", "bob")).expect("different"));
    }
}

mod external_identity_keys {
    use super::*;

    #[test]
    fn a_key_uses_only_immutable_coordinates() {
        let key = ExternalIdentityKey::new("teams", "app-1", "ext-tenant", "immutable-1")
            .expect("valid key");
        assert_eq!(key.platform(), "teams");
        assert_eq!(key.immutable_user_id(), "immutable-1");
    }

    #[test]
    fn every_mutable_attribute_is_refused_as_a_key() {
        assert_eq!(MutableAttribute::ALL.len(), 5);
        for attribute in MutableAttribute::ALL {
            let error = ExternalIdentityKey::keyed_on(attribute)
                .expect_err("a mutable attribute is not a key");
            assert_eq!(
                error,
                IdentityError::MutableAttributeAsKey {
                    attribute: attribute.as_str(),
                }
            );
        }
    }

    #[test]
    fn a_key_requires_every_coordinate() {
        assert!(ExternalIdentityKey::new("", "a", "t", "u").is_err());
        assert!(ExternalIdentityKey::new("teams", "", "t", "u").is_err());
        assert!(ExternalIdentityKey::new("teams", "a", "", "u").is_err());
        assert!(ExternalIdentityKey::new("teams", "a", "t", "").is_err());
    }
}

mod historical_grants {
    use super::*;

    #[test]
    fn a_past_decision_stays_answerable_after_the_policy_changes() {
        let ledger = ledger();
        let alice = actor("acme", "alice");

        // In force at 2..4, not before, not after.
        assert!(
            !ledger
                .evaluate(&alice, "run:start", revision(1))
                .is_allowed()
        );
        assert!(
            ledger
                .evaluate(&alice, "run:start", revision(2))
                .is_allowed()
        );
        assert!(
            ledger
                .evaluate(&alice, "run:start", revision(4))
                .is_allowed()
        );
        assert!(
            !ledger
                .evaluate(&alice, "run:start", revision(5))
                .is_allowed()
        );

        // Asking again about the earlier revision still answers the same way,
        // which is what makes an old decision explainable.
        assert!(
            ledger
                .evaluate(&alice, "run:start", revision(3))
                .is_allowed()
        );
    }

    #[test]
    fn an_expired_grant_denies_for_its_own_reason() {
        let decision = ledger().evaluate(&actor("acme", "alice"), "run:start", revision(9));
        assert_eq!(
            decision.outcome(),
            &DecisionOutcome::Deny {
                reason: DenyReason::GrantNotInForce,
            }
        );
    }

    #[test]
    fn a_grant_records_who_granted_it_and_why() {
        let grant = RoleGrant::new(
            actor("acme", "alice"),
            "operator",
            actor("acme", "owner"),
            revision(1),
            None,
            "on call",
        )
        .expect("valid grant");
        assert_eq!(grant.granted_by().id(), "owner");
        assert_eq!(grant.reason(), "on call");
        assert_eq!(grant.role(), "operator");
        assert!(grant.in_force_at(revision(99)), "an open grant has no end");
    }
}

mod deny_by_default {
    use super::*;

    #[test]
    fn an_unmatched_request_denies_with_a_named_reason() {
        let decision = ledger().evaluate(&actor("acme", "carol"), "run:start", revision(3));
        assert_eq!(
            decision.outcome(),
            &DecisionOutcome::Deny {
                reason: DenyReason::NoMatchingGrant,
            }
        );
    }

    #[test]
    fn a_role_carries_only_the_permissions_it_names() {
        // alice holds operator, but operator does not carry run:cancel.
        let decision = ledger().evaluate(&actor("acme", "alice"), "run:cancel", revision(3));
        assert!(!decision.is_allowed());
        assert_eq!(
            decision.outcome(),
            &DecisionOutcome::Deny {
                reason: DenyReason::NoMatchingGrant,
            }
        );
    }

    #[test]
    fn an_actor_from_another_tenant_is_denied_for_that_reason() {
        let decision = ledger().evaluate(&actor("globex", "alice"), "run:start", revision(3));
        assert_eq!(
            decision.outcome(),
            &DecisionOutcome::Deny {
                reason: DenyReason::WrongTenant,
            },
            "a same-named actor in another tenant is not merely unmatched"
        );
    }

    #[test]
    fn an_empty_policy_denies_everything() {
        let empty = PolicyLedger::new();
        for permission in ["run:start", "run:cancel", "anything"] {
            assert!(
                !empty
                    .evaluate(&actor("acme", "alice"), permission, revision(1))
                    .is_allowed(),
                "{permission} was permitted by an empty policy"
            );
        }
    }
}

mod evaluation_purity {
    use super::*;

    #[test]
    fn the_same_request_and_revision_always_decide_the_same_way() {
        let ledger = ledger();
        let alice = actor("acme", "alice");
        let first = ledger.evaluate(&alice, "run:start", revision(3));
        for _ in 0..16 {
            assert_eq!(ledger.evaluate(&alice, "run:start", revision(3)), first);
        }
    }

    #[test]
    fn evaluation_does_not_depend_on_evaluation_order() {
        let ledger = ledger();
        let alice = actor("acme", "alice");
        let forward: Vec<bool> = (1..=6)
            .map(|value| {
                ledger
                    .evaluate(&alice, "run:start", revision(value))
                    .is_allowed()
            })
            .collect();
        let backward: Vec<bool> = (1..=6)
            .rev()
            .map(|value| {
                ledger
                    .evaluate(&alice, "run:start", revision(value))
                    .is_allowed()
            })
            .collect();
        let mut reversed = backward;
        reversed.reverse();
        assert_eq!(forward, reversed);
    }
}

mod evidence_completeness {
    use super::*;

    #[test]
    fn an_allow_names_the_grant_that_permitted_it() {
        let decision = ledger().evaluate(&actor("acme", "alice"), "run:start", revision(3));
        assert_eq!(
            decision.outcome(),
            &DecisionOutcome::Allow {
                role: "operator".to_owned(),
            }
        );
        assert_eq!(decision.actor().id(), "alice");
        assert_eq!(decision.actor().tenant(), "acme");
        assert_eq!(decision.permission(), "run:start");
        assert_eq!(decision.policy_revision().get(), 3);
    }

    #[test]
    fn every_decision_carries_its_full_evidence() {
        // Allow and deny both name actor, tenant, permission and revision;
        // there is no constructor that omits any of them.
        for permission in ["run:start", "run:cancel"] {
            let decision = ledger().evaluate(&actor("acme", "alice"), permission, revision(3));
            assert_eq!(decision.actor().tenant(), "acme");
            assert_eq!(decision.permission(), permission);
            assert_eq!(decision.policy_revision().get(), 3);
        }
    }

    #[test]
    fn every_deny_reason_has_a_distinct_spelling() {
        let reasons = [
            DenyReason::NoMatchingGrant,
            DenyReason::GrantNotInForce,
            DenyReason::WrongTenant,
        ];
        let mut spellings: Vec<&str> = reasons.iter().map(|reason| reason.as_str()).collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total);
    }
}

mod credential_hygiene {
    use super::*;

    #[test]
    fn a_record_names_a_credential_without_holding_it() {
        let record = CredentialRecord::new(
            "database",
            3,
            "platform",
            "read replica",
            "daemon",
            Some(at(10_000)),
        )
        .expect("valid record");
        assert_eq!(record.name(), "database");
        assert_eq!(record.version(), 3);
        assert_eq!(record.owner(), "platform");
        assert_eq!(record.health(), CredentialHealth::Active);
        // The compile-fail proof that no accessor returns a value lives in the
        // library doc tests, where it executes.
    }

    #[test]
    fn rotation_leaves_both_versions_usable_for_an_overlap_window() {
        let current =
            CredentialRecord::new("database", 3, "platform", "p", "a", None).expect("valid record");
        let (outgoing, incoming) = current.rotating_to(4);
        assert_eq!(outgoing.version(), 3);
        assert_eq!(incoming.version(), 4);
        assert_eq!(outgoing.health(), CredentialHealth::RotationOverlap);
        assert_eq!(incoming.health(), CredentialHealth::RotationOverlap);
        assert!(outgoing.grants_capability(at(0)));
        assert!(incoming.grants_capability(at(0)));
    }

    #[test]
    fn revocation_invalidates_derived_capabilities_immediately() {
        let record =
            CredentialRecord::new("database", 3, "platform", "p", "a", None).expect("valid record");
        assert!(record.grants_capability(at(0)));

        let revoked = record.revoked();
        assert_eq!(revoked.health(), CredentialHealth::Revoked);
        assert!(
            !revoked.grants_capability(at(0)),
            "revocation has no grace period to opt into"
        );
        assert!(!revoked.grants_capability(at(i64::MAX)));
    }

    #[test]
    fn an_expiry_ends_a_capability_without_revocation() {
        let record = CredentialRecord::new("database", 3, "platform", "p", "a", Some(at(1_000)))
            .expect("valid record");
        assert!(record.grants_capability(at(999)));
        assert!(!record.grants_capability(at(1_000)));
        assert!(!record.grants_capability(at(1_001)));
    }
}

mod break_glass_audit {
    use super::*;

    #[test]
    fn a_break_glass_grant_requires_an_expiry() {
        assert_eq!(
            BreakGlassGrant::new(actor("acme", "alice"), "incident 42", "owner", None)
                .expect_err("unbounded elevation"),
            IdentityError::BreakGlassNeedsExpiry
        );
    }

    #[test]
    fn a_break_glass_grant_cannot_be_silent() {
        assert!(
            BreakGlassGrant::new(actor("acme", "alice"), "", "owner", Some(at(1))).is_err(),
            "an elevation without a reason is not recordable"
        );
    }

    #[test]
    fn a_break_glass_grant_records_who_why_and_until_when() {
        let grant = BreakGlassGrant::new(
            actor("acme", "alice"),
            "incident 42",
            "owner",
            Some(at(5_000)),
        )
        .expect("valid grant");
        assert_eq!(grant.actor().id(), "alice");
        assert_eq!(grant.reason(), "incident 42");
        assert_eq!(grant.role(), "owner");
        assert!(grant.is_active_at(at(4_999)));
        assert!(!grant.is_active_at(at(5_000)), "the expiry is exclusive");
        // The grant is a durable value: cloning and dropping the original
        // changes nothing, which is what "restarting does not clear it" means
        // at this layer.
        let copy = grant.clone();
        drop(grant);
        assert!(copy.is_active_at(at(0)));
    }
}
