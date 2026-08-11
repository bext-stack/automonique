// SPDX-License-Identifier: Elastic-2.0

//! R1-23 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `plan/contracts/R1-23.md`.

use automonique_protocol::identity::Actor;
use automonique_protocol::journal::ActionLedger;
use automonique_protocol::primitives::Revision;
use automonique_protocol::protocols::{
    Admission, AliasRecord, ApprovalDecision, ApprovalTarget, CanonicalActionKind, CanonicalId,
    CanonicalKind, CanonicalWork, ClientBinding, ClientBindingParts, ExternalOperation,
    ExternalRef, ExternalRequest, HostApprovalDecision, IdentityMap, MappedApproval,
    ProjectedSemantic, Projection, ProtocolDialect, ProtocolError, ProtocolRange, ProtocolSemantic,
    ProtocolVersion, Quotas, RemoteAgentClaim, Scope, SemanticSupport, commit,
};

fn actor() -> Actor {
    Actor::new("acme", "svc-1").expect("valid actor")
}

fn quotas() -> Quotas {
    Quotas {
        concurrent_runs: 4,
        requests_per_minute: 120,
        tokens_per_day: 250_000,
    }
}

fn range(min: u32, max: u32) -> ProtocolRange {
    ProtocolRange::new(ProtocolVersion::new(min), ProtocolVersion::new(max))
        .expect("valid protocol range")
}

fn binding_with(dialect: ProtocolDialect, scopes: &[Scope]) -> ClientBinding {
    ClientBinding::bind(ClientBindingParts {
        dialect,
        client_id: "zed-1",
        actor: actor(),
        scopes,
        quotas: quotas(),
        credential_revision: Revision::new(7).expect("non-zero revision"),
        supported_range: range(1, 2),
    })
    .expect("valid binding")
}

/// A fully scoped binding for a named tenant and client.
fn binding_for(tenant: &str, client_id: &str) -> ClientBinding {
    ClientBinding::bind(ClientBindingParts {
        dialect: ProtocolDialect::Acp,
        client_id,
        actor: Actor::new(tenant, client_id).expect("valid actor"),
        scopes: &Scope::ALL,
        quotas: quotas(),
        credential_revision: Revision::new(7).expect("non-zero revision"),
        supported_range: range(1, 2),
    })
    .expect("valid binding")
}

fn full_binding(dialect: ProtocolDialect) -> ClientBinding {
    binding_with(dialect, &Scope::ALL)
}

fn canonical(kind: CanonicalKind, id: &str) -> CanonicalId {
    CanonicalId::new(kind, id).expect("valid canonical identity")
}

fn work_at(id: &str, title: &str, revision: Revision) -> CanonicalWork {
    CanonicalWork::new(canonical(CanonicalKind::Work, id), title, revision).expect("valid work")
}

fn work(id: &str) -> CanonicalWork {
    work_at(id, "ship the adapter", Revision::FIRST)
}

fn external(dialect: ProtocolDialect, client_id: &str, external_id: &str) -> ExternalRef {
    ExternalRef::new(dialect, client_id, external_id).expect("valid external reference")
}

fn request<'a>(
    operation: ExternalOperation,
    target: CanonicalId,
    idempotency_key: &'a str,
) -> ExternalRequest<'a> {
    ExternalRequest {
        operation,
        target,
        idempotency_key,
        expected_revision: Revision::new(3).expect("non-zero revision"),
        claim: None,
    }
}

mod binding_completeness {
    use super::*;

    #[test]
    fn every_binding_carries_dialect_actor_scopes_quotas_and_credential_revision() {
        let binding = binding_with(
            ProtocolDialect::Acp,
            &[Scope::ReadCanonicalState, Scope::WriteTurn],
        );
        assert_eq!(binding.dialect(), ProtocolDialect::Acp);
        assert_eq!(binding.client_id(), "zed-1");
        assert_eq!(binding.actor().tenant(), "acme");
        assert_eq!(binding.actor().id(), "svc-1");
        assert_eq!(
            binding.scopes(),
            [Scope::ReadCanonicalState, Scope::WriteTurn]
        );
        assert_eq!(binding.quotas().concurrent_runs, 4);
        assert_eq!(binding.quotas().requests_per_minute, 120);
        assert_eq!(binding.quotas().tokens_per_day, 250_000);
        assert_eq!(
            binding.credential_revision(),
            Revision::new(7).expect("non-zero revision")
        );
        assert_eq!(binding.supported_range(), range(1, 2));
    }

    #[test]
    fn every_dialect_reaches_the_domain_as_an_ordinary_scoped_actor() {
        for dialect in ProtocolDialect::ALL {
            let binding = full_binding(dialect);
            assert_eq!(
                binding.actor().tenant(),
                "acme",
                "{} bound without a tenant",
                dialect.as_str()
            );
            assert!(!binding.scopes().is_empty());
        }
    }

    #[test]
    fn a_binding_without_scopes_is_refused() {
        let attempt = ClientBinding::bind(ClientBindingParts {
            dialect: ProtocolDialect::Relay,
            client_id: "relay-1",
            actor: actor(),
            scopes: &[],
            quotas: quotas(),
            credential_revision: Revision::FIRST,
            supported_range: range(1, 1),
        });
        assert_eq!(
            attempt.expect_err("no scope"),
            ProtocolError::EmptyScopeSet,
            "a caller with no scope is not an ordinary scoped actor"
        );
    }

    #[test]
    fn a_binding_without_a_client_identifier_is_refused() {
        let attempt = ClientBinding::bind(ClientBindingParts {
            dialect: ProtocolDialect::McpExport,
            client_id: "",
            actor: actor(),
            scopes: &[Scope::ReadCanonicalState],
            quotas: quotas(),
            credential_revision: Revision::FIRST,
            supported_range: range(1, 1),
        });
        assert_eq!(
            attempt.expect_err("empty client id").category(),
            "field_invalid"
        );
    }

    #[test]
    fn granted_scopes_are_deduplicated_so_a_scope_cannot_be_counted_twice() {
        let binding = binding_with(
            ProtocolDialect::A2a,
            &[
                Scope::WriteTurn,
                Scope::ReadCanonicalState,
                Scope::WriteTurn,
            ],
        );
        assert_eq!(
            binding.scopes(),
            [Scope::ReadCanonicalState, Scope::WriteTurn]
        );
        assert!(binding.grants(Scope::WriteTurn));
        assert!(!binding.grants(Scope::InvokeTool));
    }
}

mod mapping_injectivity {
    use super::*;

    #[test]
    fn one_external_identifier_never_resolves_to_two() {
        let mut map = IdentityMap::new();
        let session = external(ProtocolDialect::Acp, "zed-1", "session-a");
        let first = canonical(CanonicalKind::Work, "w-1");
        let second = canonical(CanonicalKind::Work, "w-2");
        map.bind(session.clone(), first.clone())
            .expect("first bind");

        let error = map
            .bind(session.clone(), second)
            .expect_err("a second canonical identity");
        assert_eq!(error.category(), "external_identity_already_mapped");
        assert_eq!(map.resolve(&session), Some(&first));
    }

    #[test]
    fn one_external_identifier_never_crosses_canonical_kinds() {
        let mut map = IdentityMap::new();
        let reference = external(ProtocolDialect::OpenAiCompatible, "librechat-1", "resp-1");
        map.bind(reference.clone(), canonical(CanonicalKind::Run, "r-1"))
            .expect("first bind");
        let error = map
            .bind(reference.clone(), canonical(CanonicalKind::Turn, "r-1"))
            .expect_err("run and turn are different identities");
        assert_eq!(error.category(), "external_identity_already_mapped");
        assert_eq!(
            map.resolve(&reference).map(CanonicalId::kind),
            Some(CanonicalKind::Run)
        );
    }

    #[test]
    fn two_external_identifiers_reach_one_identity_only_through_an_alias_record() {
        let mut map = IdentityMap::new();
        let primary = external(ProtocolDialect::Acp, "zed-1", "session-a");
        let alias = external(ProtocolDialect::Acp, "zed-1", "session-b");
        let target = canonical(CanonicalKind::Work, "w-1");
        map.bind(primary.clone(), target.clone())
            .expect("first bind");

        let error = map
            .bind(alias.clone(), target.clone())
            .expect_err("a second claimer");
        assert_eq!(error.category(), "canonical_identity_already_claimed");
        assert_eq!(map.resolve(&alias), None);

        let record = AliasRecord::new(
            primary.clone(),
            alias.clone(),
            actor(),
            "host reconnected with a new session id",
        )
        .expect("valid alias record");
        map.alias(record).expect("explicit aliasing record");

        assert_eq!(map.resolve(&alias), Some(&target));
        assert_eq!(map.resolve(&primary), Some(&target));
        assert_eq!(map.external_refs_for(&target).len(), 2);
        assert_eq!(map.alias_records().len(), 1);
        assert_eq!(
            map.alias_records()[0].reason(),
            "host reconnected with a new session id"
        );
        assert_eq!(map.alias_records()[0].recorded_by().tenant(), "acme");
    }

    #[test]
    fn injectivity_is_scoped_to_one_dialect_and_one_client() {
        let mut map = IdentityMap::new();
        let target = canonical(CanonicalKind::Work, "w-1");
        // The same spelling from another dialect is another identifier.
        map.bind(
            external(ProtocolDialect::Acp, "zed-1", "abc"),
            canonical(CanonicalKind::Work, "w-9"),
        )
        .expect("acp bind");
        map.bind(
            external(ProtocolDialect::Relay, "zed-1", "abc"),
            target.clone(),
        )
        .expect("relay bind");
        // And two clients of one dialect may both watch one canonical identity.
        map.bind(
            external(ProtocolDialect::Relay, "zed-2", "xyz"),
            target.clone(),
        )
        .expect("second client bind");

        assert_eq!(
            map.resolve(&external(ProtocolDialect::Acp, "zed-1", "abc")),
            Some(&canonical(CanonicalKind::Work, "w-9"))
        );
        assert_eq!(
            map.resolve(&external(ProtocolDialect::Relay, "zed-1", "abc")),
            Some(&target)
        );
        assert_eq!(map.external_refs_for(&target).len(), 2);
    }

    #[test]
    fn rebinding_one_pair_is_idempotent() {
        let mut map = IdentityMap::new();
        let reference = external(ProtocolDialect::A2a, "peer-1", "task-1");
        let target = canonical(CanonicalKind::Work, "w-1");
        map.bind(reference.clone(), target.clone())
            .expect("first bind");
        map.bind(reference.clone(), target.clone())
            .expect("the same pair again");
        assert_eq!(map.external_refs_for(&target).len(), 1);
    }

    #[test]
    fn an_alias_of_an_unmapped_primary_is_refused() {
        let mut map = IdentityMap::new();
        let record = AliasRecord::new(
            external(ProtocolDialect::Acp, "zed-1", "session-a"),
            external(ProtocolDialect::Acp, "zed-1", "session-b"),
            actor(),
            "reconnect",
        )
        .expect("valid alias record");
        assert_eq!(
            map.alias(record).expect_err("nothing to alias").category(),
            "alias_primary_unmapped"
        );
    }

    #[test]
    fn an_alias_cannot_retarget_an_identifier_that_is_already_mapped() {
        let mut map = IdentityMap::new();
        let primary = external(ProtocolDialect::Acp, "zed-1", "session-a");
        let alias = external(ProtocolDialect::Acp, "zed-1", "session-b");
        map.bind(primary.clone(), canonical(CanonicalKind::Work, "w-1"))
            .expect("primary bind");
        map.bind(alias.clone(), canonical(CanonicalKind::Work, "w-2"))
            .expect("alias already means something else");
        let record =
            AliasRecord::new(primary, alias, actor(), "reconnect").expect("valid alias record");
        assert_eq!(
            map.alias(record).expect_err("already mapped").category(),
            "external_identity_already_mapped"
        );
    }

    #[test]
    fn an_unmapped_identifier_refuses_rather_than_inventing_an_identity() {
        let map = IdentityMap::new();
        let reference = external(ProtocolDialect::McpExport, "mcp-1", "unknown");
        assert_eq!(map.resolve(&reference), None);
        let error = map
            .resolve_or_refuse(&reference)
            .expect_err("nothing to resolve to");
        assert_eq!(error.category(), "external_identifier_unmapped");
        assert!(error.to_string().contains("mcp_export/mcp-1/unknown"));
    }
}

mod no_alternate_state {
    use super::*;

    #[test]
    fn a_projection_reads_canonical_state_rather_than_a_copy_of_it() {
        let binding = full_binding(ProtocolDialect::Acp);
        let drafted = work_at("w-1", "draft", Revision::FIRST);
        let projection = Projection::of(&binding, &drafted).expect("read scope");
        assert_eq!(projection.work().title(), "draft");
        assert_eq!(projection.work().revision(), Revision::FIRST);
        // The dialect is read back out of the binding, not stored beside it.
        assert_eq!(projection.dialect(), binding.dialect());
        assert_eq!(projection.binding(), &binding);

        let revised = work_at("w-1", "revised", Revision::new(2).expect("non-zero"));
        let reprojected = Projection::of(&binding, &revised).expect("read scope");
        assert_eq!(reprojected.work().title(), "revised");
        assert_eq!(
            reprojected.work().revision(),
            Revision::new(2).expect("non-zero")
        );
    }

    #[test]
    fn two_projections_of_one_state_are_indistinguishable() {
        // A projection that minted a session, cursor or approval of its own
        // would differ from its twin. These do not.
        let binding = full_binding(ProtocolDialect::OpenAiCompatible);
        let work = work("w-1");
        let first = Projection::of(&binding, &work).expect("read scope");
        let second = Projection::of(&binding, &work).expect("read scope");
        assert_eq!(first, second);
        assert_eq!(
            first.project(ProtocolSemantic::FileDiff, "1 file changed"),
            second.project(ProtocolSemantic::FileDiff, "1 file changed")
        );
    }

    #[test]
    fn every_effect_a_projection_offers_is_a_canonical_action() {
        let binding = full_binding(ProtocolDialect::Acp);
        let work = work("w-1");
        let projection = Projection::of(&binding, &work).expect("read scope");
        let Admission::Mutating(authority) = projection.admit(ProtocolVersion::new(1)) else {
            panic!("version 1 is inside the declared range");
        };
        for operation in ExternalOperation::ALL {
            let plan = authority
                .plan(&request(
                    operation,
                    canonical(CanonicalKind::Work, "w-1"),
                    "key-1",
                ))
                .expect("a granted scope");
            assert!(
                CanonicalActionKind::ALL.contains(&plan.kind()),
                "{} produced something outside the canonical action set",
                operation.as_str()
            );
            assert_eq!(plan.actor(), binding.actor());
        }
    }

    #[test]
    fn there_is_no_alternate_authorization_policy_and_no_scope_grants_another() {
        let work = work("w-1");
        for operation in ExternalOperation::ALL {
            let kind = operation.canonical_action();
            let withheld = kind.required_scope();
            let scopes: Vec<Scope> = Scope::ALL
                .into_iter()
                .filter(|scope| *scope != withheld)
                .collect();
            let binding = binding_with(ProtocolDialect::Relay, &scopes);
            let projection = Projection::of(&binding, &work).expect("read scope retained");
            let Admission::Mutating(authority) = projection.admit(ProtocolVersion::new(1)) else {
                panic!("version 1 is inside the declared range");
            };
            let error = authority
                .plan(&request(
                    operation,
                    canonical(CanonicalKind::Work, "w-1"),
                    "key-1",
                ))
                .expect_err("every other scope is held");
            assert_eq!(
                error,
                ProtocolError::ScopeNotGranted {
                    action: kind.as_str(),
                    scope: withheld.as_str(),
                },
                "holding six of seven scopes served {}",
                operation.as_str()
            );
        }
    }

    #[test]
    fn a_binding_that_cannot_read_canonical_state_cannot_project_it() {
        let binding = binding_with(ProtocolDialect::McpExport, &[Scope::InvokeTool]);
        let work = work("w-1");
        assert_eq!(
            Projection::of(&binding, &work)
                .expect_err("no read scope")
                .category(),
            "scope_not_granted"
        );
    }
}

mod effect_equivalence {
    use super::*;

    #[test]
    fn every_operation_maps_to_exactly_one_canonical_action() {
        let mut reached: Vec<CanonicalActionKind> = Vec::new();
        for operation in ExternalOperation::ALL {
            let kind = operation.canonical_action();
            assert_eq!(
                kind,
                operation.canonical_action(),
                "{} did not map deterministically",
                operation.as_str()
            );
            reached.push(kind);
        }
        for kind in CanonicalActionKind::ALL {
            assert!(
                reached.contains(&kind),
                "{} is reachable from no protocol operation",
                kind.as_str()
            );
        }
        // Several operations may name one action; none names two.
        assert_eq!(
            ExternalOperation::CancelPrompt.canonical_action(),
            ExternalOperation::StopRun.canonical_action()
        );
    }

    #[test]
    fn a_plan_carries_its_idempotency_key_and_expected_revision() {
        let binding = full_binding(ProtocolDialect::OpenAiCompatible);
        let work = work("w-1");
        let projection = Projection::of(&binding, &work).expect("read scope");
        let Admission::Mutating(authority) = projection.admit(ProtocolVersion::new(2)) else {
            panic!("version 2 is inside the declared range");
        };
        let plan = authority
            .plan(&request(
                ExternalOperation::CreateRun,
                canonical(CanonicalKind::Run, "r-1"),
                "idem-42",
            ))
            .expect("start_run granted");
        assert_eq!(plan.kind(), CanonicalActionKind::StartRun);
        assert_eq!(plan.dialect(), ProtocolDialect::OpenAiCompatible);
        assert_eq!(plan.idempotency_key(), "idem-42");
        assert_eq!(
            plan.expected_revision(),
            Revision::new(3).expect("non-zero revision")
        );
        assert_eq!(plan.target(), &canonical(CanonicalKind::Run, "r-1"));
        assert_eq!(plan.action_id(), "openai_compatible/start_run");
    }

    #[test]
    fn a_plan_without_an_idempotency_key_is_refused() {
        let binding = full_binding(ProtocolDialect::Relay);
        let work = work("w-1");
        let projection = Projection::of(&binding, &work).expect("read scope");
        let Admission::Mutating(authority) = projection.admit(ProtocolVersion::new(1)) else {
            panic!("version 1 is inside the declared range");
        };
        let error = authority
            .plan(&request(
                ExternalOperation::SendPrompt,
                canonical(CanonicalKind::Turn, "t-1"),
                "",
            ))
            .expect_err("empty idempotency key");
        assert_eq!(error.category(), "field_invalid");
    }

    #[test]
    fn a_duplicate_external_request_yields_the_same_receipt() {
        let binding = full_binding(ProtocolDialect::Acp);
        let work = work("w-1");
        let projection = Projection::of(&binding, &work).expect("read scope");
        let Admission::Mutating(authority) = projection.admit(ProtocolVersion::new(1)) else {
            panic!("version 1 is inside the declared range");
        };
        let external_request = request(
            ExternalOperation::SendPrompt,
            canonical(CanonicalKind::Turn, "t-1"),
            "idem-7",
        );
        let plan = authority
            .plan(&external_request)
            .expect("write_turn granted");
        let replayed = authority
            .plan(&external_request)
            .expect("the same request again");
        assert_eq!(plan, replayed, "one request maps to one canonical action");

        let mut ledger = ActionLedger::new();
        let first = commit(&plan, &mut ledger).expect("recorded");
        let second = commit(&replayed, &mut ledger).expect("replayed");
        assert_eq!(first, second, "a duplicate request is not a second effect");
        // The ledger stores the scoped key, not the caller's raw one, so a
        // second tenant reusing "idem-7" cannot land on this receipt.
        let scoped = plan.scoped_idempotency_key();
        assert_eq!(ledger.find(&scoped), Some(&first));
        assert_eq!(ledger.find("idem-7"), None);
        assert!(scoped.contains("acme"));
        assert!(scoped.ends_with("idem-7"));
        assert_eq!(
            first.expected_revision(),
            Some(Revision::new(3).expect("non-zero revision"))
        );
        assert_eq!(first.idempotency_key(), scoped);
    }

    #[test]
    fn one_idempotency_key_cannot_be_reused_for_a_different_target() {
        let binding = full_binding(ProtocolDialect::Acp);
        let work = work("w-1");
        let projection = Projection::of(&binding, &work).expect("read scope");
        let Admission::Mutating(authority) = projection.admit(ProtocolVersion::new(1)) else {
            panic!("version 1 is inside the declared range");
        };
        let mut ledger = ActionLedger::new();
        let first = authority
            .plan(&request(
                ExternalOperation::SendPrompt,
                canonical(CanonicalKind::Turn, "t-1"),
                "idem-7",
            ))
            .expect("write_turn granted");
        commit(&first, &mut ledger).expect("recorded");

        let retargeted = authority
            .plan(&request(
                ExternalOperation::SendPrompt,
                canonical(CanonicalKind::Turn, "t-2"),
                "idem-7",
            ))
            .expect("write_turn granted");
        assert_eq!(
            commit(&retargeted, &mut ledger)
                .expect_err("a second effect under one key")
                .category(),
            "idempotency_conflict"
        );
    }
}

mod approval_fidelity {
    use super::*;

    #[test]
    fn each_host_answer_maps_to_one_distinct_typed_decision() {
        let revision = Revision::new(11).expect("non-zero revision");
        let mut decisions: Vec<ApprovalDecision> = Vec::new();
        for host in HostApprovalDecision::ALL {
            let mapped = MappedApproval::from_host(
                ProtocolDialect::Acp,
                host,
                ApprovalTarget::tool("format").expect("valid tool"),
                revision,
                actor(),
            );
            decisions.push(mapped.decision());
        }
        assert_eq!(
            decisions,
            [
                ApprovalDecision::AllowOnce,
                ApprovalDecision::AllowUntilRevoked,
                ApprovalDecision::Deny,
            ]
        );
        let mut spellings: Vec<&str> = decisions.iter().map(|decision| decision.as_str()).collect();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), 3, "two host answers collapsed into one");
    }

    #[test]
    fn the_exact_target_revision_survives_the_mapping() {
        for value in [1_u64, 2, 97, u64::MAX] {
            let revision = Revision::new(value).expect("non-zero revision");
            let mapped = MappedApproval::from_host(
                ProtocolDialect::OpenAiCompatible,
                HostApprovalDecision::AllowOnce,
                ApprovalTarget::provider("anthropic").expect("valid provider"),
                revision,
                actor(),
            );
            assert_eq!(
                mapped.target_revision(),
                revision,
                "the approval drifted off revision {value}"
            );
        }
    }

    #[test]
    fn an_approval_names_exactly_one_provider_or_one_tool() {
        let provider = MappedApproval::from_host(
            ProtocolDialect::Relay,
            HostApprovalDecision::Deny,
            ApprovalTarget::provider("anthropic").expect("valid provider"),
            Revision::FIRST,
            actor(),
        );
        assert_eq!(provider.target().kind(), "provider");
        assert_eq!(provider.target().name(), "anthropic");

        let tool = MappedApproval::from_host(
            ProtocolDialect::Relay,
            HostApprovalDecision::AllowAlways,
            ApprovalTarget::tool("shell").expect("valid tool"),
            Revision::FIRST,
            actor(),
        );
        assert_eq!(tool.target().kind(), "tool");
        assert_eq!(tool.target().name(), "shell");
        assert_ne!(provider.target(), tool.target());
        // An unnamed target is refused rather than standing for all of them.
        assert_eq!(
            ApprovalTarget::tool("")
                .expect_err("unnamed tool")
                .category(),
            "field_invalid"
        );
    }

    #[test]
    fn an_approval_is_decided_by_a_resolved_tenant_actor() {
        let mapped = MappedApproval::from_host(
            ProtocolDialect::A2a,
            HostApprovalDecision::AllowOnce,
            ApprovalTarget::tool("shell").expect("valid tool"),
            Revision::FIRST,
            actor(),
        );
        assert_eq!(mapped.decided_by().tenant(), "acme");
        assert_eq!(mapped.decided_by().id(), "svc-1");
        assert_eq!(mapped.dialect(), ProtocolDialect::A2a);
    }
}

mod honest_degradation {
    use super::*;

    #[test]
    fn every_dialect_declares_every_semantic_exactly_once() {
        for dialect in ProtocolDialect::ALL {
            let table = dialect.capability_table();
            assert_eq!(table.len(), ProtocolSemantic::ALL.len());
            for semantic in ProtocolSemantic::ALL {
                let rows: Vec<SemanticSupport> = table
                    .iter()
                    .filter(|(declared, _)| *declared == semantic)
                    .map(|(_, support)| *support)
                    .collect();
                assert_eq!(
                    rows.len(),
                    1,
                    "{} declares {} {} times",
                    dialect.as_str(),
                    semantic.as_str(),
                    rows.len()
                );
                assert_eq!(rows[0], dialect.support(semantic));
            }
        }
    }

    #[test]
    fn only_the_native_surface_represents_everything() {
        for dialect in ProtocolDialect::ALL {
            let complete = ProtocolSemantic::ALL
                .into_iter()
                .all(|semantic| dialect.support(semantic) == SemanticSupport::Native);
            assert_eq!(
                complete,
                dialect.is_native(),
                "{} claims a fidelity it does not have",
                dialect.as_str()
            );
        }
    }

    #[test]
    fn an_unsupported_semantic_returns_a_typed_error_rather_than_being_dropped() {
        let binding = full_binding(ProtocolDialect::McpExport);
        let work = work("w-1");
        let projection = Projection::of(&binding, &work).expect("read scope");
        let error = projection
            .project(ProtocolSemantic::ExactRevision, "revision 3")
            .expect_err("mcp cannot carry an exact revision");
        assert_eq!(
            error,
            ProtocolError::UnsupportedSemantic {
                dialect: "mcp_export",
                semantic: "exact_revision",
            }
        );
        assert!(error.to_string().contains("not dropped"));
    }

    #[test]
    fn a_degraded_semantic_carries_bounded_text_and_the_authoritative_link() {
        let binding = full_binding(ProtocolDialect::OpenAiCompatible);
        let work = work("w-1");
        let projection = Projection::of(&binding, &work).expect("read scope");
        let projected = projection
            .project(ProtocolSemantic::FileDiff, "3 files changed, 12 insertions")
            .expect("degradation is available");
        let ProjectedSemantic::Degraded(degradation) = projected else {
            panic!("openai compatibility cannot represent a structured diff");
        };
        assert_eq!(degradation.semantic(), ProtocolSemantic::FileDiff);
        assert_eq!(
            degradation.rendering().text(),
            "3 files changed, 12 insertions"
        );
        assert!(!degradation.rendering().truncated());
        assert_eq!(degradation.authoritative().path(), "/native/v1/work/w-1");
    }

    #[test]
    fn over_long_text_is_truncated_and_marked_rather_than_silently_shortened() {
        let binding = full_binding(ProtocolDialect::A2a);
        let work = work("w-1");
        let projection = Projection::of(&binding, &work).expect("read scope");
        let long = "é".repeat(400);
        let projected = projection
            .project(ProtocolSemantic::WorkGraph, &long)
            .expect("degradation is available");
        let ProjectedSemantic::Degraded(degradation) = projected else {
            panic!("a2a cannot represent a work graph");
        };
        let rendering = degradation.rendering();
        assert!(rendering.truncated(), "truncation was not reported");
        assert_eq!(rendering.source_bytes(), 800);
        assert!(rendering.text().len() <= 512);
        assert!(
            long.starts_with(rendering.text()),
            "the rendering is a prefix of the source, not a rewrite of it"
        );
    }

    #[test]
    fn an_unusable_rendering_is_refused_rather_than_emitted_empty() {
        let binding = full_binding(ProtocolDialect::A2a);
        let work = work("w-1");
        let projection = Projection::of(&binding, &work).expect("read scope");
        assert_eq!(
            projection
                .project(ProtocolSemantic::WorkGraph, "")
                .expect_err("empty rendering")
                .category(),
            "field_invalid"
        );
    }

    #[test]
    fn the_authoritative_record_stays_intact_across_degradation() {
        let binding = full_binding(ProtocolDialect::McpExport);
        let work = work("w-1");
        let before = work.clone();
        let projection = Projection::of(&binding, &work).expect("read scope");
        for semantic in ProtocolSemantic::ALL {
            let _ = projection.project(semantic, "a summary of what happened");
        }
        assert_eq!(work, before, "projecting altered the canonical record");
    }
}

mod native_escape_hatch {
    use super::*;

    #[test]
    fn every_dialect_can_express_a_native_resource_link() {
        let work = work("w-1");
        for dialect in ProtocolDialect::ALL {
            let binding = full_binding(dialect);
            let projection = Projection::of(&binding, &work).expect("read scope");
            let link = projection.native_link();
            assert_eq!(link.kind(), CanonicalKind::Work);
            assert_eq!(link.id(), "w-1");
            assert_eq!(
                link.path(),
                "/native/v1/work/w-1",
                "{} could not point at the canonical surface",
                dialect.as_str()
            );
        }
    }

    #[test]
    fn every_successful_projection_carries_the_link() {
        let work = work("w-1");
        for dialect in ProtocolDialect::ALL {
            let binding = full_binding(dialect);
            let projection = Projection::of(&binding, &work).expect("read scope");
            for semantic in ProtocolSemantic::ALL {
                match projection.project(semantic, "a summary of what happened") {
                    Ok(projected) => {
                        assert_eq!(projected.semantic(), semantic);
                        assert_eq!(
                            projected.authoritative(),
                            &projection.native_link(),
                            "{} lost the escape hatch for {}",
                            dialect.as_str(),
                            semantic.as_str()
                        );
                    }
                    Err(error) => assert_eq!(error.category(), "unsupported_semantic"),
                }
            }
        }
    }
}

mod remote_claims_carry_nothing {
    use super::*;

    #[test]
    fn a_remote_claim_never_resolves_to_an_actor() {
        let claim = RemoteAgentClaim::new("peer-1", "admin@acme", "write_work").expect("valid");
        assert_eq!(claim.peer(), "peer-1");
        assert_eq!(claim.asserted_actor(), "admin@acme");
        assert_eq!(claim.asserted_scope(), "write_work");
        let error = claim
            .resolve_actor()
            .expect_err("a claim is not a principal");
        assert_eq!(error.category(), "remote_claim_carries_no_authority");
    }

    #[test]
    fn a_claim_does_not_change_the_plan_it_travels_with() {
        let binding = full_binding(ProtocolDialect::A2a);
        let work = work("w-1");
        let projection = Projection::of(&binding, &work).expect("read scope");
        let Admission::Mutating(authority) = projection.admit(ProtocolVersion::new(1)) else {
            panic!("version 1 is inside the declared range");
        };
        let plain = request(
            ExternalOperation::SendPrompt,
            canonical(CanonicalKind::Turn, "t-1"),
            "idem-7",
        );
        let mut asserted = plain.clone();
        asserted.claim =
            Some(RemoteAgentClaim::new("peer-1", "root@globex", "invoke_tool").expect("valid"));

        let without = authority.plan(&plain).expect("write_turn granted");
        let with = authority.plan(&asserted).expect("write_turn granted");
        assert_eq!(without, with, "the assertion changed the canonical action");
        assert_eq!(with.actor(), binding.actor());
        assert_eq!(with.actor().tenant(), "acme");
    }

    #[test]
    fn a_claim_cannot_supply_a_scope_the_binding_lacks() {
        let binding = binding_with(
            ProtocolDialect::Relay,
            &[Scope::ReadCanonicalState, Scope::WriteTurn],
        );
        let work = work("w-1");
        let projection = Projection::of(&binding, &work).expect("read scope");
        let Admission::Mutating(authority) = projection.admit(ProtocolVersion::new(1)) else {
            panic!("version 1 is inside the declared range");
        };
        let mut asserted = request(
            ExternalOperation::CallTool,
            canonical(CanonicalKind::Run, "r-1"),
            "idem-7",
        );
        asserted.claim = Some(
            RemoteAgentClaim::new("peer-1", "root@globex", "invoke_tool").expect("valid claim"),
        );
        assert_eq!(
            authority.plan(&asserted).expect_err("no invoke_tool scope"),
            ProtocolError::ScopeNotGranted {
                action: "invoke_tool",
                scope: "invoke_tool",
            }
        );
    }
}

mod range_coexistence {
    use super::*;

    #[test]
    fn each_binding_declares_a_supported_range() {
        for dialect in ProtocolDialect::ALL {
            let binding = full_binding(dialect);
            let declared = binding.supported_range();
            assert_eq!(declared.min(), ProtocolVersion::new(1));
            assert_eq!(declared.max(), ProtocolVersion::new(2));
            assert!(declared.admits(ProtocolVersion::new(1)));
            assert!(declared.admits(ProtocolVersion::new(2)));
            assert!(!declared.admits(ProtocolVersion::new(3)));
        }
    }

    #[test]
    fn an_inverted_range_is_refused() {
        let error = ProtocolRange::new(ProtocolVersion::new(4), ProtocolVersion::new(2))
            .expect_err("inverted");
        assert_eq!(error.category(), "inverted_protocol_range");
    }

    #[test]
    fn an_in_range_client_may_mutate() {
        let binding = full_binding(ProtocolDialect::Acp);
        let work = work("w-1");
        let projection = Projection::of(&binding, &work).expect("read scope");
        let Admission::Mutating(authority) = projection.admit(ProtocolVersion::new(2)) else {
            panic!("version 2 is inside the declared range");
        };
        assert_eq!(authority.projection(), projection);
        authority
            .plan(&request(
                ExternalOperation::SendPrompt,
                canonical(CanonicalKind::Turn, "t-1"),
                "idem-7",
            ))
            .expect("write_turn granted");
    }

    #[test]
    fn an_incompatible_client_is_admitted_read_only_and_keeps_reading() {
        let binding = full_binding(ProtocolDialect::Acp);
        let work = work("w-1");
        let projection = Projection::of(&binding, &work).expect("read scope");
        let Admission::ReadOnly(client) = projection.admit(ProtocolVersion::new(9)) else {
            panic!("version 9 is outside the declared range");
        };
        assert_eq!(client.client(), ProtocolVersion::new(9));
        assert_eq!(client.declared(), range(1, 2));
        // Reading never needed an admission, so the client is not cut off.
        assert_eq!(projection.work().title(), "ship the adapter");
        projection
            .project(ProtocolSemantic::StreamingText, "hello")
            .expect("reads still project");
    }

    #[test]
    fn every_unsupported_mutation_fails_closed_naming_both_versions() {
        let binding = full_binding(ProtocolDialect::Acp);
        let work = work("w-1");
        let projection = Projection::of(&binding, &work).expect("read scope");
        let Admission::ReadOnly(client) = projection.admit(ProtocolVersion::new(0)) else {
            panic!("version 0 is outside the declared range");
        };
        for kind in CanonicalActionKind::ALL {
            let error = client
                .refuse_mutation(kind)
                .expect_err("an out-of-range client cannot mutate");
            assert_eq!(
                error,
                ProtocolError::MutationOutsideProtocolRange {
                    action: kind.as_str(),
                    declared_min: 1,
                    declared_max: 2,
                    client: 0,
                }
            );
            assert!(error.to_string().contains("read-only"));
        }
    }

    #[test]
    fn adjacent_releases_coexist_on_their_overlap() {
        let work = work("w-1");
        let previous = ClientBinding::bind(ClientBindingParts {
            dialect: ProtocolDialect::Acp,
            client_id: "zed-1",
            actor: actor(),
            scopes: &Scope::ALL,
            quotas: quotas(),
            credential_revision: Revision::FIRST,
            supported_range: range(1, 2),
        })
        .expect("valid binding");
        let next = ClientBinding::bind(ClientBindingParts {
            dialect: ProtocolDialect::Acp,
            client_id: "zed-1",
            actor: actor(),
            scopes: &Scope::ALL,
            quotas: quotas(),
            credential_revision: Revision::FIRST,
            supported_range: range(2, 3),
        })
        .expect("valid binding");

        for binding in [&previous, &next] {
            let projection = Projection::of(binding, &work).expect("read scope");
            assert!(matches!(
                projection.admit(ProtocolVersion::new(2)),
                Admission::Mutating(_)
            ));
        }
        let old_release = Projection::of(&previous, &work).expect("read scope");
        assert!(matches!(
            old_release.admit(ProtocolVersion::new(3)),
            Admission::ReadOnly(_)
        ));
        let new_release = Projection::of(&next, &work).expect("read scope");
        assert!(matches!(
            new_release.admit(ProtocolVersion::new(1)),
            Admission::ReadOnly(_)
        ));
    }
}

/// Regressions found by adversarial review of this module.
///
/// Both defects were live: the suite passed while two callers could collide on
/// one idempotency key. Each test here fails if its fix is reverted.
mod idempotency_scoping {
    use super::*;

    #[test]
    fn two_tenants_sharing_a_key_do_not_collide() {
        let mut ledger = ActionLedger::new();
        let external = request(
            ExternalOperation::CreateRun,
            canonical(CanonicalKind::Run, "r-1"),
            "shared-key",
        );
        let work = work("w-1");

        let acme_binding = binding_for("acme", "svc-1");
        let globex_binding = binding_for("globex", "svc-1");
        let acme_projection = Projection::of(&acme_binding, &work).expect("read scope");
        let globex_projection = Projection::of(&globex_binding, &work).expect("read scope");
        let Admission::Mutating(acme) = acme_projection.admit(ProtocolVersion::new(1)) else {
            panic!("version 1 is in range");
        };
        let Admission::Mutating(globex) = globex_projection.admit(ProtocolVersion::new(1)) else {
            panic!("version 1 is in range");
        };

        let acme_plan = acme.plan(&external).expect("start_run granted");
        let globex_plan = globex.plan(&external).expect("start_run granted");
        assert_ne!(
            acme_plan.scoped_idempotency_key(),
            globex_plan.scoped_idempotency_key(),
            "two tenants must not share one ledger key"
        );

        let first = commit(&acme_plan, &mut ledger).expect("acme recorded");
        let second = commit(&globex_plan, &mut ledger).expect("globex recorded");
        assert_ne!(
            first, second,
            "globex's request must not be answered with acme's receipt"
        );
    }

    #[test]
    fn two_canonical_actions_on_one_target_do_not_collapse() {
        let mut ledger = ActionLedger::new();
        let work = work("w-1");
        let binding = binding_for("acme", "svc-1");
        let projection = Projection::of(&binding, &work).expect("read scope");
        let Admission::Mutating(authority) = projection.admit(ProtocolVersion::new(1)) else {
            panic!("version 1 is in range");
        };
        let target = canonical(CanonicalKind::Run, "r-1");

        let start = authority
            .plan(&request(ExternalOperation::CreateRun, target.clone(), "k"))
            .expect("start_run granted");
        let stop = authority
            .plan(&request(ExternalOperation::CancelPrompt, target, "k"))
            .expect("cancel_run granted");
        assert_ne!(
            start.scoped_idempotency_key(),
            stop.scoped_idempotency_key(),
            "two canonical actions must not share one ledger key"
        );

        let started = commit(&start, &mut ledger).expect("recorded");
        let stopped = commit(&stop, &mut ledger).expect("recorded");
        assert_ne!(
            started, stopped,
            "a cancel sharing a key with a start must not be dropped as a replay"
        );
    }
}
