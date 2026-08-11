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
    MutationAuthority, ProjectedSemantic, Projection, ProtocolDialect, ProtocolError,
    ProtocolRange, ProtocolSemantic, ProtocolVersion, Quotas, RemoteAgentClaim, Scope,
    SemanticSupport, commit,
};

/// The operation-to-action mapping, written out rather than read back.
///
/// Surjectivity onto [`CanonicalActionKind::ALL`] survives any permutation of
/// the mapping, so a coverage check cannot see one. These rows can.
const DECLARED_ACTIONS: [(ExternalOperation, CanonicalActionKind); 7] = [
    (
        ExternalOperation::OpenSession,
        CanonicalActionKind::CreateWork,
    ),
    (
        ExternalOperation::SendPrompt,
        CanonicalActionKind::AppendTurn,
    ),
    (
        ExternalOperation::CancelPrompt,
        CanonicalActionKind::CancelRun,
    ),
    (
        ExternalOperation::RespondToPermission,
        CanonicalActionKind::RespondToApproval,
    ),
    (ExternalOperation::CallTool, CanonicalActionKind::InvokeTool),
    (ExternalOperation::CreateRun, CanonicalActionKind::StartRun),
    (ExternalOperation::StopRun, CanonicalActionKind::CancelRun),
];

/// The action-to-scope mapping, written out rather than read back.
///
/// A guard that derives the scope it withholds from `required_scope()` moves
/// both sides together and pins nothing. Every scope assertion below comes from
/// this table instead.
const DECLARED_SCOPES: [(CanonicalActionKind, Scope); 6] = [
    (CanonicalActionKind::CreateWork, Scope::WriteWork),
    (CanonicalActionKind::StartRun, Scope::StartRun),
    (CanonicalActionKind::AppendTurn, Scope::WriteTurn),
    (CanonicalActionKind::CancelRun, Scope::CancelRun),
    (
        CanonicalActionKind::RespondToApproval,
        Scope::RespondToApproval,
    ),
    (CanonicalActionKind::InvokeTool, Scope::InvokeTool),
];

/// Every declared capability cell: six dialects by ten semantics.
///
/// Spot-checking a handful of calls leaves the rest of the matrix free to move.
/// All sixty cells are named here, in dialect-then-semantic order.
const DECLARED_SUPPORT: [(ProtocolDialect, ProtocolSemantic, SemanticSupport); 60] = {
    use ProtocolDialect::{A2a, Acp, McpExport, NativeRuns, OpenAiCompatible, Relay};
    use ProtocolSemantic::{
        ApprovalPrompt, CursorResumption, ExactRevision, FileDiff, ModelSelection, StreamingText,
        TerminalEvent, ThoughtSummary, ToolActivity, WorkGraph,
    };
    use SemanticSupport::{BoundedText, Native, Unsupported};

    [
        // The editor host represents everything it streams, but cannot carry an
        // exact aggregate revision and renders the work graph as text.
        (Acp, StreamingText, Native),
        (Acp, ThoughtSummary, Native),
        (Acp, ToolActivity, Native),
        (Acp, FileDiff, Native),
        (Acp, TerminalEvent, Native),
        (Acp, ModelSelection, Native),
        (Acp, ApprovalPrompt, Native),
        (Acp, CursorResumption, Native),
        (Acp, ExactRevision, Unsupported),
        (Acp, WorkGraph, BoundedText),
        // The OpenAI-compatible surface has no diff, terminal or reasoning
        // shape, and no revision or graph at all.
        (OpenAiCompatible, StreamingText, Native),
        (OpenAiCompatible, ThoughtSummary, BoundedText),
        (OpenAiCompatible, ToolActivity, Native),
        (OpenAiCompatible, FileDiff, BoundedText),
        (OpenAiCompatible, TerminalEvent, BoundedText),
        (OpenAiCompatible, ModelSelection, Native),
        (OpenAiCompatible, ApprovalPrompt, Native),
        (OpenAiCompatible, CursorResumption, Native),
        (OpenAiCompatible, ExactRevision, Unsupported),
        (OpenAiCompatible, WorkGraph, Unsupported),
        // The native surface is the reference point: nothing degrades in it.
        (NativeRuns, StreamingText, Native),
        (NativeRuns, ThoughtSummary, Native),
        (NativeRuns, ToolActivity, Native),
        (NativeRuns, FileDiff, Native),
        (NativeRuns, TerminalEvent, Native),
        (NativeRuns, ModelSelection, Native),
        (NativeRuns, ApprovalPrompt, Native),
        (NativeRuns, CursorResumption, Native),
        (NativeRuns, ExactRevision, Native),
        (NativeRuns, WorkGraph, Native),
        // The MCP export is a tool surface: tool activity and approvals
        // directly, a few shapes as text, the rest not at all.
        (McpExport, StreamingText, BoundedText),
        (McpExport, ThoughtSummary, Unsupported),
        (McpExport, ToolActivity, Native),
        (McpExport, FileDiff, BoundedText),
        (McpExport, TerminalEvent, BoundedText),
        (McpExport, ModelSelection, Unsupported),
        (McpExport, ApprovalPrompt, Native),
        (McpExport, CursorResumption, Unsupported),
        (McpExport, ExactRevision, Unsupported),
        (McpExport, WorkGraph, Unsupported),
        // The A2a peer streams and resumes; it decides nothing.
        (A2a, StreamingText, Native),
        (A2a, ThoughtSummary, BoundedText),
        (A2a, ToolActivity, BoundedText),
        (A2a, FileDiff, BoundedText),
        (A2a, TerminalEvent, Unsupported),
        (A2a, ModelSelection, Unsupported),
        (A2a, ApprovalPrompt, Unsupported),
        (A2a, CursorResumption, Native),
        (A2a, ExactRevision, Unsupported),
        (A2a, WorkGraph, BoundedText),
        // The relay carries the native shapes bar reasoning and the graph.
        (Relay, StreamingText, Native),
        (Relay, ThoughtSummary, BoundedText),
        (Relay, ToolActivity, Native),
        (Relay, FileDiff, Native),
        (Relay, TerminalEvent, Native),
        (Relay, ModelSelection, Native),
        (Relay, ApprovalPrompt, Native),
        (Relay, CursorResumption, Native),
        (Relay, ExactRevision, Native),
        (Relay, WorkGraph, BoundedText),
    ]
};

/// The scope [`DECLARED_SCOPES`] names for an action.
fn declared_scope(kind: CanonicalActionKind) -> Scope {
    DECLARED_SCOPES
        .into_iter()
        .find(|(declared, _)| *declared == kind)
        .map(|(_, scope)| scope)
        .expect("every canonical action is declared exactly once")
}

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

/// A fully scoped binding for an actor named by the caller.
fn binding_for_actor(actor: Actor) -> ClientBinding {
    ClientBinding::bind(ClientBindingParts {
        dialect: ProtocolDialect::Acp,
        client_id: "zed-1",
        actor,
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

/// The mutation authority of an in-range client of this binding.
fn authority_for<'a>(binding: &'a ClientBinding, work: &'a CanonicalWork) -> MutationAuthority<'a> {
    let projection = Projection::of(binding, work).expect("read scope");
    let Admission::Mutating(authority) = projection.admit(ProtocolVersion::new(1)) else {
        panic!("version 1 is inside the declared range");
    };
    authority
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

    /// Every action requires the one scope the table names, and a different
    /// one.
    ///
    /// A body that answered `Scope::InvokeTool` for everything satisfies any
    /// check that asks `required_scope()` what to withhold. It does not satisfy
    /// this one, because the expected scope is written down.
    #[test]
    fn each_canonical_action_requires_the_scope_it_declares() {
        assert_eq!(DECLARED_SCOPES.len(), CanonicalActionKind::ALL.len());
        for (kind, expected) in DECLARED_SCOPES {
            assert_eq!(
                kind.required_scope(),
                expected,
                "{} requires {}, not the declared {}",
                kind.as_str(),
                kind.required_scope().as_str(),
                expected.as_str()
            );
        }
        for kind in CanonicalActionKind::ALL {
            assert_eq!(
                DECLARED_SCOPES
                    .into_iter()
                    .filter(|(declared, _)| *declared == kind)
                    .count(),
                1,
                "{} is not declared exactly once",
                kind.as_str()
            );
        }

        // No scope stands in for another: six actions, six distinct scopes.
        let mut required: Vec<Scope> = CanonicalActionKind::ALL
            .into_iter()
            .map(CanonicalActionKind::required_scope)
            .collect();
        required.sort_unstable();
        required.dedup();
        assert_eq!(
            required.len(),
            CanonicalActionKind::ALL.len(),
            "two canonical actions collapsed onto one scope"
        );
        // Reading is not what any mutation is authorized by.
        assert!(!required.contains(&Scope::ReadCanonicalState));
    }

    /// Withholding the declared scope is what refuses each operation, and
    /// holding it is what serves it.
    ///
    /// Both halves matter. The refusal half alone passes for a mapping that
    /// sent every action to one scope; the grant half fails immediately, since
    /// a binding holding only `WriteWork` would then be served nothing.
    #[test]
    fn every_operation_is_gated_by_the_scope_its_action_declares() {
        let work = work("w-1");
        for (operation, kind) in DECLARED_ACTIONS {
            let scope = declared_scope(kind);

            let minimal = binding_with(ProtocolDialect::Relay, &[Scope::ReadCanonicalState, scope]);
            let plan = authority_for(&minimal, &work)
                .plan(&request(
                    operation,
                    canonical(CanonicalKind::Work, "w-1"),
                    "key-1",
                ))
                .unwrap_or_else(|error| {
                    panic!(
                        "{} was refused while holding its declared scope {}: {error}",
                        operation.as_str(),
                        scope.as_str()
                    )
                });
            assert_eq!(
                plan.kind(),
                kind,
                "{} reached {} rather than its declared action",
                operation.as_str(),
                plan.kind().as_str()
            );

            let others: Vec<Scope> = Scope::ALL
                .into_iter()
                .filter(|held| *held != scope)
                .collect();
            let starved = binding_with(ProtocolDialect::Relay, &others);
            assert_eq!(
                authority_for(&starved, &work)
                    .plan(&request(
                        operation,
                        canonical(CanonicalKind::Work, "w-1"),
                        "key-1",
                    ))
                    .expect_err("every other scope is held"),
                ProtocolError::ScopeNotGranted {
                    action: kind.as_str(),
                    scope: scope.as_str(),
                },
                "{} was not gated by {}",
                operation.as_str(),
                scope.as_str()
            );
        }
    }

    /// A projection is its two shared borrows and nothing else.
    ///
    /// The `compile_fail` in the module documentation states the lifetime tie
    /// only. A projection that cached its dialect beside the binding would
    /// still compile, still borrow, and still answer `dialect()` — and would be
    /// a second store of something the canonical record already holds. The
    /// width of the type is what refuses it.
    #[test]
    fn a_projection_is_exactly_the_two_borrows_it_documents() {
        assert_eq!(
            size_of::<Projection<'static>>(),
            size_of::<&ClientBinding>() + size_of::<&CanonicalWork>(),
            "a projection grew a field beyond the two borrows it is documented to hold"
        );
        assert_eq!(
            size_of::<MutationAuthority<'static>>(),
            size_of::<Projection<'static>>(),
            "a mutation authority grew a field beyond the projection it borrows"
        );

        // And what it answers is the binding's, for every dialect.
        let work = work("w-1");
        for dialect in ProtocolDialect::ALL {
            let binding = full_binding(dialect);
            let projection = Projection::of(&binding, &work).expect("read scope");
            assert_eq!(projection.dialect(), dialect);
            assert_eq!(projection.dialect(), projection.binding().dialect());
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

    /// Each operation reaches the action the table names.
    ///
    /// The coverage check above is blind to a permutation: swapping two
    /// operations' actions leaves the mapping onto
    /// [`CanonicalActionKind::ALL`] surjective and every assertion there true.
    /// These rows name which action, not merely how many.
    #[test]
    fn each_operation_reaches_the_canonical_action_it_declares() {
        assert_eq!(DECLARED_ACTIONS.len(), ExternalOperation::ALL.len());
        for (operation, expected) in DECLARED_ACTIONS {
            assert_eq!(
                operation.canonical_action(),
                expected,
                "{} reaches {}, not the declared {}",
                operation.as_str(),
                operation.canonical_action().as_str(),
                expected.as_str()
            );
        }
        for operation in ExternalOperation::ALL {
            assert_eq!(
                DECLARED_ACTIONS
                    .into_iter()
                    .filter(|(declared, _)| *declared == operation)
                    .count(),
                1,
                "{} is not declared exactly once",
                operation.as_str()
            );
        }
        // Cancelling a prompt and stopping a run are the one effect they are
        // documented to be; nothing else doubles up.
        let mut reached: Vec<&str> = DECLARED_ACTIONS
            .into_iter()
            .map(|(_, kind)| kind.as_str())
            .collect();
        reached.sort_unstable();
        reached.dedup();
        assert_eq!(reached.len(), CanonicalActionKind::ALL.len());
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

    /// Every one of the sixty cells is the cell that was reviewed.
    ///
    /// Totality says each pair has an answer; it does not say which. A cell
    /// flipped in either direction — a dialect claiming a fidelity it lacks, or
    /// disclaiming one it has — changes what a client is told and what
    /// [`Projection::project`] returns, and only a written-down matrix sees it.
    #[test]
    fn every_declared_capability_cell_is_the_one_under_review() {
        assert_eq!(
            DECLARED_SUPPORT.len(),
            ProtocolDialect::ALL.len() * ProtocolSemantic::ALL.len(),
            "the matrix is not one row per dialect per semantic"
        );
        for (dialect, semantic, expected) in DECLARED_SUPPORT {
            assert_eq!(
                dialect.support(semantic),
                expected,
                "{} declares {} as {}, not the reviewed {}",
                dialect.as_str(),
                semantic.as_str(),
                dialect.support(semantic).as_str(),
                expected.as_str()
            );
        }
        // Every pair is named exactly once, so a dropped row cannot free a cell.
        for dialect in ProtocolDialect::ALL {
            for semantic in ProtocolSemantic::ALL {
                assert_eq!(
                    DECLARED_SUPPORT
                        .into_iter()
                        .filter(|(declared, named, _)| *declared == dialect && *named == semantic)
                        .count(),
                    1,
                    "{} declares {} other than exactly once",
                    dialect.as_str(),
                    semantic.as_str()
                );
            }
        }
    }

    /// A flipped cell changes what a client actually receives.
    ///
    /// The matrix above pins the declaration; this pins that the declaration is
    /// what `project` obeys, so the two cannot drift apart.
    #[test]
    fn the_declared_cell_is_the_outcome_the_client_receives() {
        let work = work("w-1");
        for (dialect, semantic, expected) in DECLARED_SUPPORT {
            let binding = full_binding(dialect);
            let projection = Projection::of(&binding, &work).expect("read scope");
            let outcome = projection.project(semantic, "a summary of what happened");
            match expected {
                SemanticSupport::Native => assert!(
                    matches!(outcome, Ok(ProjectedSemantic::Native { .. })),
                    "{} was declared native for {} and returned {outcome:?}",
                    dialect.as_str(),
                    semantic.as_str()
                ),
                SemanticSupport::BoundedText => assert!(
                    matches!(outcome, Ok(ProjectedSemantic::Degraded(_))),
                    "{} was declared bounded text for {} and returned {outcome:?}",
                    dialect.as_str(),
                    semantic.as_str()
                ),
                SemanticSupport::Unsupported => assert_eq!(
                    outcome.expect_err("an unsupported semantic is refused"),
                    ProtocolError::UnsupportedSemantic {
                        dialect: dialect.as_str(),
                        semantic: semantic.as_str(),
                    }
                ),
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

    /// A whole degradation sweep leaves the authoritative record readable and
    /// unchanged, and every outcome still points at it.
    ///
    /// Comparing the record with a clone of itself is nearly free: a
    /// [`CanonicalWork`] has no interior mutability, so no `project` call could
    /// have altered it. What the sweep is worth pinning is that it happened at
    /// all and that each outcome is the class the dialect declares — otherwise
    /// deleting the loop leaves the comparison passing over an untouched value.
    /// The outcomes are therefore collected and asserted, and the record is
    /// re-read through the projection after every step.
    #[test]
    fn the_authoritative_record_stays_intact_across_degradation() {
        let binding = full_binding(ProtocolDialect::McpExport);
        let work = work("w-1");
        let before = work.clone();
        let projection = Projection::of(&binding, &work).expect("read scope");

        let mut observed: Vec<(ProtocolSemantic, SemanticSupport)> = Vec::new();
        for semantic in ProtocolSemantic::ALL {
            let class = match projection.project(semantic, "a summary of what happened") {
                Ok(ProjectedSemantic::Native { authoritative, .. }) => {
                    assert_eq!(authoritative.path(), "/native/v1/work/w-1");
                    SemanticSupport::Native
                }
                Ok(ProjectedSemantic::Degraded(degradation)) => {
                    assert_eq!(degradation.authoritative().path(), "/native/v1/work/w-1");
                    assert_eq!(
                        degradation.rendering().text(),
                        "a summary of what happened",
                        "the degradation rewrote the summary it was given"
                    );
                    SemanticSupport::BoundedText
                }
                Err(ProtocolError::UnsupportedSemantic { .. }) => SemanticSupport::Unsupported,
                Err(other) => panic!("{} refused unexpectedly: {other}", semantic.as_str()),
            };
            assert_eq!(
                projection.work(),
                &before,
                "the record read back through the projection changed while projecting {}",
                semantic.as_str()
            );
            observed.push((semantic, class));
        }

        assert_eq!(
            observed.len(),
            ProtocolSemantic::ALL.len(),
            "the sweep did not project every semantic"
        );
        for (semantic, class) in observed {
            assert_eq!(
                class,
                ProtocolDialect::McpExport.support(semantic),
                "{} left by a route the dialect does not declare",
                semantic.as_str()
            );
        }
        assert_eq!(work, before, "projecting altered the canonical record");
        assert_eq!(work.title(), "ship the adapter");
        assert_eq!(work.revision(), Revision::FIRST);
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

    /// A separator inside a tenant cannot forge another tenant's ledger key.
    ///
    /// `Actor::new` accepts any bounded text, and bounded text may contain a
    /// `/`. So `("a", "b/c")` and `("a/b", "c")` are two actors in two
    /// different tenants whose components, joined raw, spell one key: the
    /// ledger then answers the second tenant's request with the first tenant's
    /// receipt and records no second effect. That is the collision the scoping
    /// exists to prevent, reached through the separator rather than through a
    /// shared key.
    #[test]
    fn a_separator_in_a_tenant_cannot_forge_another_tenants_ledger_key() {
        let work = work("w-1");
        let split_tenant = binding_for_actor(Actor::new("a", "b/c").expect("valid actor"));
        let split_actor = binding_for_actor(Actor::new("a/b", "c").expect("valid actor"));
        assert_ne!(
            split_tenant.actor().tenant(),
            split_actor.actor().tenant(),
            "the two bindings must belong to different tenants for this to mean anything"
        );

        let external = request(
            ExternalOperation::CreateRun,
            canonical(CanonicalKind::Run, "r-1"),
            "k",
        );
        let first_plan = authority_for(&split_tenant, &work)
            .plan(&external)
            .expect("start_run granted");
        let second_plan = authority_for(&split_actor, &work)
            .plan(&external)
            .expect("start_run granted");
        assert_ne!(
            first_plan.scoped_idempotency_key(),
            second_plan.scoped_idempotency_key(),
            "two tenants collapsed onto one ledger key"
        );

        let mut ledger = ActionLedger::new();
        let first = commit(&first_plan, &mut ledger).expect("the first tenant recorded");
        let second = commit(&second_plan, &mut ledger).expect("the second tenant recorded");
        assert_ne!(
            first, second,
            "the second tenant was answered with the first tenant's receipt"
        );
        assert_eq!(
            ledger.find(&first_plan.scoped_idempotency_key()),
            Some(&first)
        );
        assert_eq!(
            ledger.find(&second_plan.scoped_idempotency_key()),
            Some(&second)
        );
    }

    /// Nor can a separator inside the caller's own key.
    ///
    /// The actor `b` with the key `acp/start_run/k` and the actor
    /// `b/acp/start_run` with the key `k` are a different caller asking a
    /// different question. Joined raw they are one string.
    #[test]
    fn a_separator_in_a_key_cannot_forge_another_actors_ledger_key() {
        let work = work("w-1");
        let plain = binding_for_actor(Actor::new("a", "b").expect("valid actor"));
        let padded = binding_for_actor(Actor::new("a", "b/acp/start_run").expect("valid actor"));
        assert_ne!(plain.actor().id(), padded.actor().id());

        let target = canonical(CanonicalKind::Run, "r-1");
        let crafted = authority_for(&plain, &work)
            .plan(&request(
                ExternalOperation::CreateRun,
                target.clone(),
                "acp/start_run/k",
            ))
            .expect("start_run granted");
        let ordinary = authority_for(&padded, &work)
            .plan(&request(ExternalOperation::CreateRun, target, "k"))
            .expect("start_run granted");
        assert_ne!(
            crafted.scoped_idempotency_key(),
            ordinary.scoped_idempotency_key(),
            "two callers collapsed onto one ledger key"
        );

        let mut ledger = ActionLedger::new();
        let first = commit(&crafted, &mut ledger).expect("the crafted key recorded");
        let second = commit(&ordinary, &mut ledger).expect("the ordinary key recorded");
        assert_ne!(
            first, second,
            "one caller was answered with another caller's receipt"
        );
    }

    /// Escaping costs the ordinary key nothing.
    ///
    /// A component carrying no separator is spelled exactly as before, so the
    /// fix above is not a rename of every key in the ledger.
    #[test]
    fn a_key_with_no_separator_keeps_its_spelling() {
        let work = work("w-1");
        let binding = binding_for("acme", "svc-1");
        let plan = authority_for(&binding, &work)
            .plan(&request(
                ExternalOperation::SendPrompt,
                canonical(CanonicalKind::Turn, "t-1"),
                "idem-7",
            ))
            .expect("write_turn granted");
        assert_eq!(
            plan.scoped_idempotency_key(),
            "acme/svc-1/acp/append_turn/idem-7"
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
