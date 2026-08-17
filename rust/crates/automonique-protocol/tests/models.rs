// SPDX-License-Identifier: Elastic-2.0

//! R1-24 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `docs/product-plan/requirements/models-media-and-execution.md`. No test contacts a model, vendor or media
//! backend; every instant and observation below is supplied by the test.

use automonique_protocol::models::{
    AccountState, AccountUsage, AdmissionOutcome, Aggregator, AliasBinding, AliasProfile,
    ApprovalChannel, ApprovalEvidence, ApprovalPause, ApprovalSemantics, ArtifactDigest,
    ArtifactTransfer, AuthMethod, BrowserGrant, BrowserGrantParts, CacheConsequence, Cancellation,
    CapturePolicy, CatalogEntryParts, Cleanup, ConsideredCandidate, ContextConsequence,
    ContextItem, ContextSensitivity, CostAccounting, CredentialHandling, CredentialPoolParts,
    CredentialReference, DataPolicy, Elimination, EnvironmentState, EventCursor, EvidenceKind,
    ExecutorClass, ExecutorRegistration, ExecutorRegistrationParts, FallbackChain, FallbackClass,
    FallbackHop, FallbackRegistry, GeneratedMedia, HopSemantics, ImmutableSpecAcceptance,
    IsolationIdentity, LifecycleEvidence, MAX_MODEL_FIELD_BYTES, MediaAdapterDeclaration,
    MediaAdapterParts, MediaDeployment, MediaFamily, MediaProvenance, MediaRetention,
    MediaVisibility, MinimizedContext, Modality, ModelCatalogEntry, ModelError, ModelRef,
    NativeOsGrant, NativeOsGrantParts, PendingApproval, PersistentEnvironment, PlatformDerivative,
    PoolAccount, PoolAccountParts, Pricing, PricingUnit, PromptRetention, ProtectedOriginal,
    ProviderAccountId, Quota, ReasoningControl, ReferenceCall, ReferenceOutput, RemoteCoordinate,
    Rotation, RotationTrigger, RoutingConstraint, RoutingDecision, SandboxContainment,
    SessionBinding, SessionModel, SnapshotRef, SpokenConfirmation, StructuredOutputSupport,
    SwitchReason, SwitchRefusal, SwitchRequest, ToolSupport, TrainingUse, TurnContext, UsageClass,
    VendorSandboxLabel, WakeWordDetection, WorkspaceTransfer, admit_allocation,
    with_credential_pool,
};
use automonique_protocol::primitives::{EpochMillis, Revision, ValueError};
use automonique_protocol::sandbox::{
    CgroupId, CredentialDelivery, EgressPolicyDigest, EnforcementAttestation,
    EnforcementAttestationParts, ExecutionBackendId, KernelBootId, LandlockAbi,
    LandlockAttestation, LandlockRulesetDigest, NamespaceIdentity, NamespaceKind, NetworkAccess,
    ProcessGroupId, SandboxPath, SeccompDigest, SupervisorProperty,
};

fn model(provider: &str, name: &str) -> ModelRef {
    ModelRef::new(provider, name).expect("valid model reference")
}

fn account(id: &str) -> ProviderAccountId {
    ProviderAccountId::new(id).expect("valid account")
}

fn data_policy() -> DataPolicy {
    DataPolicy::new(TrainingUse::Prohibited, PromptRetention::NoneRetained, "eu")
        .expect("valid data policy")
}

fn pricing() -> Pricing {
    Pricing::new("EUR", PricingUnit::MillionTokens, 3_000_000, 15_000_000).expect("valid pricing")
}

/// A digest body carrying `label` verbatim, so distinct labels stay distinct.
fn labelled_digest(label: &str) -> String {
    let mut hex: String = label.bytes().map(|byte| format!("{byte:02x}")).collect();
    assert!(hex.len() <= 64, "label is too long to encode");
    while hex.len() < 64 {
        hex.push('0');
    }
    format!("sha256:{hex}")
}

fn attestation(seccomp: &str) -> EnforcementAttestation {
    EnforcementAttestation::record(EnforcementAttestationParts {
        resolved_paths: &[SandboxPath::new("/workspace/attempt-1").expect("valid path")],
        namespaces: &[
            NamespaceIdentity::new(NamespaceKind::Mount, 4_026_531_840).expect("valid namespace")
        ],
        process_group: ProcessGroupId::new(4242).expect("valid process group"),
        cgroup: CgroupId::new("/automonique.slice/run-1.scope").expect("valid cgroup"),
        backend: ExecutionBackendId::new("scope-1").expect("valid backend"),
        kernel_boot: KernelBootId::new("boot-1").expect("valid kernel boot"),
        supervisor_properties: &[SupervisorProperty::NoNewPrivileges],
        landlock: LandlockAttestation::new(
            LandlockAbi::new(3).expect("valid abi"),
            LandlockRulesetDigest::parse(&labelled_digest("landlock-1")).expect("valid digest"),
        ),
        seccomp_digest: SeccompDigest::parse(&labelled_digest(seccomp)).expect("valid digest"),
        egress_digest: EgressPolicyDigest::parse(&labelled_digest("egress-1"))
            .expect("valid digest"),
        credential_delivery: CredentialDelivery::SealedDescriptor,
        external_daemon: None,
    })
    .expect("valid attestation")
}

fn instant(millis: i64) -> EpochMillis {
    EpochMillis::from_millis(millis)
}

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("non-zero revision")
}

fn pool_account(id: &str, state: AccountState, quota: Quota) -> PoolAccount {
    PoolAccount::declare(PoolAccountParts {
        id: account(id),
        owner_organization: "acme",
        billing_tenant: "acme-eu",
        data_boundary: "eu",
        credential: CredentialReference::new("vault://acme/eu/key").expect("valid coordinate"),
        usage: AccountUsage::new(3, 900, 300, quota),
        state,
    })
    .expect("valid account")
}

fn pool_parts(id: &str, accounts: Vec<PoolAccount>) -> CredentialPoolParts<'_> {
    CredentialPoolParts {
        id,
        owner_organization: "acme",
        billing_tenant: "acme-eu",
        data_boundary: "eu",
        accounts,
    }
}

fn semantics(
    tools: &[&str],
    containment: SandboxContainment,
    zone: &str,
    approval: ApprovalSemantics,
) -> HopSemantics {
    HopSemantics::new(tools, containment, zone, approval).expect("valid semantics")
}

fn requested_semantics() -> HopSemantics {
    semantics(
        &["read_file", "run_tests"],
        SandboxContainment::IsolatedWorkspace,
        "eu",
        ApprovalSemantics::ReviewRequired,
    )
}

fn hop(id: &str, name: &str, semantics: HopSemantics) -> FallbackHop {
    FallbackHop::new(account(id), model("anthropic", name), semantics)
}

fn lifecycle(seccomp: &str) -> LifecycleEvidence {
    LifecycleEvidence::signed("builder-1", "sha256:sig", attestation(seccomp))
        .expect("valid evidence")
}

fn registration(
    id: &str,
    class: ExecutorClass,
    evidence: LifecycleEvidence,
) -> ExecutorRegistration {
    ExecutorRegistration::declare(ExecutorRegistrationParts {
        id,
        class,
        workspace_transfer: WorkspaceTransfer::ContentAddressedBundle,
        artifact_transfer: ArtifactTransfer::DigestVerifiedPull,
        spec_acceptance: ImmutableSpecAcceptance::new("sha256:spec").expect("valid spec digest"),
        lifecycle_evidence: evidence,
        credential_handling: CredentialHandling::CapabilityInjected,
        event_cursor: EventCursor::new("run-1", 42).expect("valid cursor"),
        approval_pause: ApprovalPause::new(600_000),
        cancellation: Cancellation::new(5_000),
        cleanup: Cleanup::WorkspaceAndCredentials,
        cost_accounting: CostAccounting::PerSecond,
    })
    .expect("valid registration")
}

mod catalog_completeness {
    use super::*;

    fn entry() -> ModelCatalogEntry {
        ModelCatalogEntry::declare(CatalogEntryParts {
            model: model("anthropic", "opus"),
            display_name: "Opus",
            modalities: &[Modality::Text, Modality::Image],
            context_limit_tokens: 200_000,
            max_output_tokens: 64_000,
            reasoning: ReasoningControl::CallerSelectedEffort,
            tools: ToolSupport::Parallel,
            structured_output: StructuredOutputSupport::SchemaConstrained,
            region: "eu-west-1",
            sovereignty_zone: "eu",
            data_policy: data_policy(),
            pricing: pricing(),
            auth: AuthMethod::ApiKey,
        })
        .expect("valid entry")
    }

    #[test]
    fn every_declared_field_is_present_on_a_declared_entry() {
        let entry = entry();
        assert_eq!(entry.model().provider(), "anthropic");
        assert_eq!(entry.display_name(), "Opus");
        assert_eq!(entry.modalities(), [Modality::Text, Modality::Image]);
        assert_eq!(entry.context_limit_tokens(), 200_000);
        assert_eq!(entry.max_output_tokens(), 64_000);
        assert_eq!(entry.reasoning(), ReasoningControl::CallerSelectedEffort);
        assert_eq!(entry.tools(), ToolSupport::Parallel);
        assert_eq!(
            entry.structured_output(),
            StructuredOutputSupport::SchemaConstrained
        );
        assert_eq!(entry.region(), "eu-west-1");
        assert_eq!(entry.sovereignty_zone(), "eu");
        assert_eq!(entry.data_policy().training(), TrainingUse::Prohibited);
        assert_eq!(entry.data_policy().boundary(), "eu");
        assert_eq!(entry.pricing().unit(), PricingUnit::MillionTokens);
        assert_eq!(entry.auth(), AuthMethod::ApiKey);
    }

    #[test]
    fn an_entry_is_not_declarable_with_a_missing_field() {
        // Every bounded field is checked, and the refusal names the field it
        // rejected: a check that fires under another field's name would leave
        // the entry as unexplained as no check at all.
        let overlong = "n".repeat(MAX_MODEL_FIELD_BYTES + 1);
        let cases: [(ModelError, CatalogEntryParts<'_>); 8] = [
            (
                ModelError::Field {
                    field: "display_name",
                    error: ValueError::Empty,
                },
                CatalogEntryParts {
                    display_name: "",
                    ..parts()
                },
            ),
            (
                ModelError::Field {
                    field: "display_name",
                    error: ValueError::TooLong {
                        max_bytes: MAX_MODEL_FIELD_BYTES,
                        actual_bytes: MAX_MODEL_FIELD_BYTES + 1,
                    },
                },
                CatalogEntryParts {
                    display_name: overlong.as_str(),
                    ..parts()
                },
            ),
            (
                ModelError::Field {
                    field: "region",
                    error: ValueError::Empty,
                },
                CatalogEntryParts {
                    region: "",
                    ..parts()
                },
            ),
            (
                ModelError::Field {
                    field: "sovereignty_zone",
                    error: ValueError::Empty,
                },
                CatalogEntryParts {
                    sovereignty_zone: "",
                    ..parts()
                },
            ),
            (
                ModelError::Field {
                    field: "sovereignty_zone",
                    error: ValueError::ControlCharacter,
                },
                CatalogEntryParts {
                    sovereignty_zone: "eu\u{7}",
                    ..parts()
                },
            ),
            (
                ModelError::LimitRequired {
                    field: "modalities",
                },
                CatalogEntryParts {
                    modalities: &[],
                    ..parts()
                },
            ),
            (
                ModelError::LimitRequired {
                    field: "context_limit_tokens",
                },
                CatalogEntryParts {
                    context_limit_tokens: 0,
                    ..parts()
                },
            ),
            (
                ModelError::LimitRequired {
                    field: "max_output_tokens",
                },
                CatalogEntryParts {
                    max_output_tokens: 0,
                    ..parts()
                },
            ),
        ];
        for (expected, case) in cases {
            let refused = ModelCatalogEntry::declare(case).expect_err("incomplete entry");
            assert_eq!(refused.category(), expected.category());
            assert_eq!(refused, expected, "the refusal names the rejected field");
        }
    }

    fn parts() -> CatalogEntryParts<'static> {
        CatalogEntryParts {
            model: model("anthropic", "opus"),
            display_name: "Opus",
            modalities: &[Modality::Text],
            context_limit_tokens: 200_000,
            max_output_tokens: 64_000,
            reasoning: ReasoningControl::CallerSelectedEffort,
            tools: ToolSupport::Parallel,
            structured_output: StructuredOutputSupport::SchemaConstrained,
            region: "eu-west-1",
            sovereignty_zone: "eu",
            data_policy: data_policy(),
            pricing: pricing(),
            auth: AuthMethod::ApiKey,
        }
    }

    #[test]
    fn alias_resolution_is_reproducible_at_a_recorded_revision() {
        let first = AliasProfile::new(
            revision(1),
            vec![AliasBinding::new("fast", model("anthropic", "haiku")).expect("valid binding")],
        )
        .expect("valid profile");
        let second = AliasProfile::new(
            revision(2),
            vec![AliasBinding::new("fast", model("anthropic", "haiku-next")).expect("valid")],
        )
        .expect("valid profile");

        let once = first.resolve("fast").expect("bound");
        let twice = first.resolve("fast").expect("bound");
        assert_eq!(once, twice, "resolution is reproducible");
        assert_eq!(once.revision(), revision(1));
        assert_eq!(once.target().model(), "haiku");

        // A newer profile revision is a separate value; it does not reach back
        // and change what revision 1 resolves to.
        let later = second.resolve("fast").expect("bound");
        assert_eq!(later.revision(), revision(2));
        assert_eq!(later.target().model(), "haiku-next");
        assert_eq!(first.resolve("fast").expect("bound"), once);
    }

    #[test]
    fn an_unbound_alias_and_a_duplicated_binding_are_refused() {
        let profile = AliasProfile::new(
            revision(1),
            vec![AliasBinding::new("fast", model("anthropic", "haiku")).expect("valid")],
        )
        .expect("valid profile");
        assert_eq!(
            profile.resolve("slow").expect_err("unbound").category(),
            "unknown_alias"
        );

        let duplicated = AliasProfile::new(
            revision(1),
            vec![
                AliasBinding::new("fast", model("anthropic", "haiku")).expect("valid"),
                AliasBinding::new("fast", model("openai", "mini")).expect("valid"),
            ],
        );
        assert_eq!(
            duplicated.expect_err("duplicate").category(),
            "duplicate_alias"
        );
    }
}

mod explainable_routing {
    use super::*;

    fn decision() -> RoutingDecision {
        RoutingDecision::record(
            revision(7),
            instant(1_700_000_000_000),
            vec![
                ConsideredCandidate::eliminated(
                    account("acct-us-1"),
                    model("anthropic", "opus"),
                    Elimination::new(RoutingConstraint::Region, "serves us-east-1")
                        .expect("valid elimination"),
                ),
                ConsideredCandidate::eliminated(
                    account("acct-eu-2"),
                    model("openai", "gpt"),
                    Elimination::new(RoutingConstraint::DataCollection, "retains prompts 30d")
                        .expect("valid elimination"),
                ),
                ConsideredCandidate::selected(account("acct-eu-1"), model("anthropic", "opus")),
            ],
        )
        .expect("valid decision")
    }

    #[test]
    fn a_decision_records_the_order_and_the_constraint_for_each_rejection() {
        let decision = decision();
        let order: Vec<&str> = decision
            .ordered_candidates()
            .iter()
            .map(|candidate| candidate.account().as_str())
            .collect();
        assert_eq!(order, ["acct-us-1", "acct-eu-2", "acct-eu-1"]);
        assert_eq!(decision.selected_account().as_str(), "acct-eu-1");
        assert_eq!(decision.policy_revision(), revision(7));
        assert_eq!(decision.decided_at(), instant(1_700_000_000_000));

        let rejections: Vec<(&str, RoutingConstraint)> = decision
            .rejections()
            .map(|(candidate, reason)| (candidate.account().as_str(), reason.constraint()))
            .collect();
        assert_eq!(
            rejections,
            [
                ("acct-us-1", RoutingConstraint::Region),
                ("acct-eu-2", RoutingConstraint::DataCollection),
            ],
            "every rejected candidate names the constraint that eliminated it"
        );

        // "Why did this run on that model" is answerable per candidate.
        assert_eq!(
            decision
                .why_not("acct-eu-2")
                .expect("rejected candidate")
                .detail(),
            "retains prompts 30d"
        );
        assert!(
            decision.why_not("acct-eu-1").is_none(),
            "the selected candidate has no elimination"
        );
    }

    #[test]
    fn a_decision_needs_candidates_and_exactly_one_selection() {
        assert_eq!(
            RoutingDecision::record(revision(1), instant(0), Vec::new())
                .expect_err("no candidates")
                .category(),
            "no_candidates"
        );

        let all_rejected = RoutingDecision::record(
            revision(1),
            instant(0),
            vec![ConsideredCandidate::eliminated(
                account("acct-1"),
                model("anthropic", "opus"),
                Elimination::new(RoutingConstraint::Health, "unreachable").expect("valid"),
            )],
        );
        assert_eq!(
            all_rejected.expect_err("nothing ran").category(),
            "no_selection"
        );

        let two_selected = RoutingDecision::record(
            revision(1),
            instant(0),
            vec![
                ConsideredCandidate::selected(account("acct-1"), model("anthropic", "opus")),
                ConsideredCandidate::selected(account("acct-2"), model("anthropic", "opus")),
            ],
        );
        assert_eq!(
            two_selected.expect_err("ambiguous").category(),
            "ambiguous_selection"
        );
    }

    #[test]
    fn every_constraint_is_expressible_with_a_distinct_spelling() {
        assert_eq!(RoutingConstraint::ALL.len(), 9);
        let mut spellings: Vec<&str> = Vec::new();
        for constraint in RoutingConstraint::ALL {
            let elimination = Elimination::new(constraint, "observed").expect("valid");
            assert_eq!(elimination.constraint(), constraint);
            spellings.push(constraint.as_str());
        }
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total);
    }
}

mod boundary_refusals {
    use super::*;

    fn session(binding: SessionBinding) -> SessionModel {
        SessionModel::new(
            account("acct-eu-1"),
            model("anthropic", "opus"),
            "eu",
            binding,
            revision(4),
        )
        .expect("valid session")
    }

    #[test]
    fn crossing_a_sovereignty_zone_is_a_typed_refusal() {
        let session = session(SessionBinding::Portable);
        let request = SwitchRequest::new(
            account("acct-eu-1"),
            model("anthropic", "opus"),
            "us",
            200_000,
            SwitchReason::ActorDirected,
        )
        .expect("valid request");
        let refusal = session.switch(&request, 1_000).expect_err("crosses zones");
        assert_eq!(refusal.category(), "sovereignty_boundary");
        assert_eq!(
            refusal,
            SwitchRefusal::SovereigntyBoundary {
                from: "eu".to_owned(),
                to: "us".to_owned(),
            }
        );
    }

    #[test]
    fn crossing_a_provider_account_is_a_typed_refusal() {
        let session = session(SessionBinding::Portable);
        let request = SwitchRequest::new(
            account("acct-eu-9"),
            model("anthropic", "opus"),
            "eu",
            200_000,
            SwitchReason::PolicyDirected,
        )
        .expect("valid request");
        let refusal = session
            .switch(&request, 1_000)
            .expect_err("crosses accounts");
        assert_eq!(refusal.category(), "provider_account_boundary");
    }

    #[test]
    fn a_session_bound_provider_does_not_migrate_and_health_alone_is_not_a_reason() {
        let session = session(SessionBinding::SessionBound);

        let other_provider = SwitchRequest::new(
            account("acct-eu-1"),
            model("openai", "gpt"),
            "eu",
            200_000,
            SwitchReason::ActorDirected,
        )
        .expect("valid request");
        assert_eq!(
            session
                .switch(&other_provider, 1_000)
                .expect_err("session-bound"),
            SwitchRefusal::SessionBoundMigration {
                provider: "anthropic".to_owned(),
            },
            "a bound session does not move even when the actor asks"
        );

        let healthier = SwitchRequest::new(
            account("acct-eu-1"),
            model("anthropic", "haiku"),
            "eu",
            200_000,
            SwitchReason::HealthOnly,
        )
        .expect("valid request");
        assert_eq!(
            session.switch(&healthier, 1_000).expect_err("health alone"),
            SwitchRefusal::HealthAloneInsufficient {
                provider: "anthropic".to_owned(),
            }
        );

        // The same switch for a reviewed reason is permitted, so the refusal is
        // about the reason rather than about the model being different.
        let directed = SwitchRequest::new(
            account("acct-eu-1"),
            model("anthropic", "haiku"),
            "eu",
            200_000,
            SwitchReason::ActorDirected,
        )
        .expect("valid request");
        session
            .switch(&directed, 1_000)
            .expect("same provider, reviewed reason");
    }

    #[test]
    fn a_permitted_switch_is_a_new_turn_revision_carrying_its_consequences() {
        let session = session(SessionBinding::Portable);
        let smaller = SwitchRequest::new(
            account("acct-eu-1"),
            model("anthropic", "haiku"),
            "eu",
            100_000,
            SwitchReason::ActorDirected,
        )
        .expect("valid request");

        let switched = session.switch(&smaller, 140_000).expect("permitted");
        assert_eq!(switched.turn_revision(), revision(5));
        assert_eq!(switched.model().model(), "haiku");
        assert_eq!(switched.cache(), CacheConsequence::Discarded);
        assert_eq!(
            switched.context(),
            ContextConsequence::RequiresCompaction {
                over_by_tokens: 40_000
            }
        );

        let same_model = SwitchRequest::new(
            account("acct-eu-1"),
            model("anthropic", "opus"),
            "eu",
            200_000,
            SwitchReason::PolicyDirected,
        )
        .expect("valid request");
        let unchanged = session.switch(&same_model, 1_000).expect("permitted");
        assert_eq!(unchanged.cache(), CacheConsequence::Preserved);
        assert_eq!(unchanged.context(), ContextConsequence::Retained);
    }

    fn session_at(turn_revision: Revision, binding: SessionBinding) -> SessionModel {
        SessionModel::new(
            account("acct-eu-1"),
            model("anthropic", "opus"),
            "eu",
            binding,
            turn_revision,
        )
        .expect("valid session")
    }

    fn request(account_id: &str, name: &str, zone: &str, reason: SwitchReason) -> SwitchRequest {
        SwitchRequest::new(
            account(account_id),
            model("anthropic", name),
            zone,
            200_000,
            reason,
        )
        .expect("valid request")
    }

    #[test]
    fn a_switch_with_no_successor_turn_revision_is_a_typed_refusal() {
        let permitted = request("acct-eu-1", "haiku", "eu", SwitchReason::ActorDirected);

        // One revision below the ceiling the switch still records itself.
        let last = session_at(revision(u64::MAX - 1), SessionBinding::Portable);
        assert_eq!(
            last.switch(&permitted, 1_000)
                .expect("one revision remains")
                .turn_revision(),
            revision(u64::MAX)
        );

        // At the ceiling there is no revision left to record the switch in, so
        // the switch does not happen rather than happening unrecorded.
        let exhausted = session_at(revision(u64::MAX), SessionBinding::Portable);
        let refusal = exhausted
            .switch(&permitted, 1_000)
            .expect_err("no successor revision");
        assert_eq!(refusal, SwitchRefusal::RevisionExhausted);
        assert_eq!(refusal.category(), "revision_exhausted");
        assert_eq!(
            exhausted.turn_revision(),
            revision(u64::MAX),
            "a refused switch leaves the session where it was"
        );
    }

    #[test]
    fn an_exhausted_revision_space_never_masks_a_boundary_crossing() {
        // Both conditions hold at once. A boundary crossing must still be
        // reported as the crossing it is: answering "out of revisions" would
        // hide which boundary the caller tried to cross.
        let portable = session_at(revision(u64::MAX), SessionBinding::Portable);
        assert_eq!(
            portable
                .switch(
                    &request("acct-eu-1", "opus", "us", SwitchReason::ActorDirected),
                    1_000
                )
                .expect_err("crosses zones"),
            SwitchRefusal::SovereigntyBoundary {
                from: "eu".to_owned(),
                to: "us".to_owned(),
            }
        );
        assert_eq!(
            portable
                .switch(
                    &request("acct-eu-9", "opus", "eu", SwitchReason::PolicyDirected),
                    1_000
                )
                .expect_err("crosses accounts"),
            SwitchRefusal::ProviderAccountBoundary {
                from: "acct-eu-1".to_owned(),
                to: "acct-eu-9".to_owned(),
            }
        );

        let bound = session_at(revision(u64::MAX), SessionBinding::SessionBound);
        assert_eq!(
            bound
                .switch(
                    &SwitchRequest::new(
                        account("acct-eu-1"),
                        model("openai", "gpt"),
                        "eu",
                        200_000,
                        SwitchReason::ActorDirected,
                    )
                    .expect("valid request"),
                    1_000
                )
                .expect_err("session-bound"),
            SwitchRefusal::SessionBoundMigration {
                provider: "anthropic".to_owned(),
            }
        );
        assert_eq!(
            bound
                .switch(
                    &request("acct-eu-1", "haiku", "eu", SwitchReason::HealthOnly),
                    1_000
                )
                .expect_err("health alone"),
            SwitchRefusal::HealthAloneInsufficient {
                provider: "anthropic".to_owned(),
            }
        );
    }
}

mod pool_containment {
    use super::*;

    #[test]
    fn rotation_inside_one_pool_names_both_accounts() {
        let planned = with_credential_pool(
            pool_parts(
                "pool-eu",
                vec![
                    pool_account("acct-eu-1", AccountState::RateLimited, Quota::Remaining(0)),
                    pool_account("acct-eu-2", AccountState::Available, Quota::Remaining(500)),
                ],
            ),
            |pool| {
                let source = pool.member("acct-eu-1").expect("in pool");
                let target = pool.member("acct-eu-2").expect("in pool");
                let rotation = Rotation::plan(source, target, RotationTrigger::RateLimited)
                    .expect("same pool");
                (
                    rotation.source().account().as_str().to_owned(),
                    rotation.target().account().as_str().to_owned(),
                    rotation.trigger(),
                )
            },
        )
        .expect("valid pool");
        assert_eq!(
            planned,
            (
                "acct-eu-1".to_owned(),
                "acct-eu-2".to_owned(),
                RotationTrigger::RateLimited
            )
        );
        // The compile-fail proof that a rotation cannot name two pools lives in
        // the library doc tests, where it executes.
    }

    #[test]
    fn a_rotation_to_self_or_to_an_unusable_target_is_refused() {
        let (refused, permitted) = with_credential_pool(
            pool_parts(
                "pool-eu",
                vec![
                    pool_account("acct-eu-1", AccountState::Available, Quota::Remaining(500)),
                    pool_account("acct-eu-2", AccountState::Exhausted, Quota::Remaining(0)),
                    pool_account("acct-eu-3", AccountState::Available, Quota::Remaining(0)),
                    pool_account(
                        "acct-eu-4",
                        AccountState::RateLimited,
                        Quota::Remaining(500),
                    ),
                    pool_account("acct-eu-5", AccountState::Available, Quota::Unmetered),
                ],
            ),
            |pool| {
                let member = |id: &str| pool.member(id).expect("in pool");
                let refused: Vec<ModelError> = vec![
                    Rotation::plan(
                        member("acct-eu-1"),
                        member("acct-eu-1"),
                        RotationTrigger::AuthFailure,
                    )
                    .expect_err("same account"),
                    Rotation::plan(
                        member("acct-eu-1"),
                        member("acct-eu-2"),
                        RotationTrigger::Exhausted,
                    )
                    .expect_err("target is out of quota and says so"),
                    Rotation::plan(
                        member("acct-eu-1"),
                        member("acct-eu-3"),
                        RotationTrigger::Exhausted,
                    )
                    .expect_err("target has no quota left"),
                    Rotation::plan(
                        member("acct-eu-1"),
                        member("acct-eu-4"),
                        RotationTrigger::RateLimited,
                    )
                    .expect_err("target cannot serve traffic"),
                ];
                let permitted = Rotation::plan(
                    member("acct-eu-1"),
                    member("acct-eu-5"),
                    RotationTrigger::ScheduledReview,
                )
                .expect("target is available and has quota")
                .target()
                .account()
                .as_str()
                .to_owned();
                (refused, permitted)
            },
        )
        .expect("valid pool");

        assert_eq!(
            refused,
            vec![
                ModelError::RotationToSelf {
                    account: "acct-eu-1".to_owned(),
                },
                ModelError::RotationTargetUnavailable {
                    account: "acct-eu-2".to_owned(),
                    state: "exhausted",
                },
                // Observed available, but out of quota: quota alone disqualifies
                // a target, and the refusal names what disqualified it rather
                // than repeating a state that would contradict the refusal.
                ModelError::RotationTargetUnavailable {
                    account: "acct-eu-3".to_owned(),
                    state: "exhausted",
                },
                // Metered quota remains, but the state alone disqualifies it.
                ModelError::RotationTargetUnavailable {
                    account: "acct-eu-4".to_owned(),
                    state: "rate_limited",
                },
            ],
            "each refusal names the target and the observation that refused it"
        );
        let categories: Vec<&str> = refused.iter().map(ModelError::category).collect();
        assert_eq!(
            categories,
            [
                "rotation_to_self",
                "rotation_target_unavailable",
                "rotation_target_unavailable",
                "rotation_target_unavailable",
            ]
        );
        assert_eq!(
            permitted, "acct-eu-5",
            "a target that is available and has quota is rotated to"
        );
    }

    #[test]
    fn usage_and_exhaustion_are_observable_with_only_a_credential_coordinate() {
        let observed = with_credential_pool(
            pool_parts(
                "pool-eu",
                vec![
                    pool_account("acct-eu-1", AccountState::Available, Quota::Remaining(500)),
                    pool_account("acct-eu-2", AccountState::Exhausted, Quota::Remaining(0)),
                    pool_account("acct-eu-3", AccountState::Available, Quota::Unmetered),
                    pool_account("acct-eu-4", AccountState::Available, Quota::Remaining(0)),
                    pool_account("acct-eu-5", AccountState::Exhausted, Quota::Remaining(500)),
                    pool_account("acct-eu-6", AccountState::RateLimited, Quota::Remaining(20)),
                ],
            ),
            |pool| {
                let exhausted: Vec<String> = pool
                    .exhausted()
                    .iter()
                    .map(|found| found.id().as_str().to_owned())
                    .collect();
                let members: Vec<(String, AccountState, bool)> = pool
                    .accounts()
                    .iter()
                    .map(|held| {
                        let member = pool.member(held.id().as_str()).expect("in pool");
                        (
                            member.account().as_str().to_owned(),
                            member.state(),
                            member.is_exhausted(),
                        )
                    })
                    .collect();
                let first = &pool.accounts()[0];
                let usage = first.usage();
                (
                    exhausted,
                    members,
                    (
                        first.id().as_str().to_owned(),
                        first.owner_organization().to_owned(),
                        first.billing_tenant().to_owned(),
                        first.data_boundary().to_owned(),
                        first.credential_reference().as_str().to_owned(),
                        first.state(),
                    ),
                    (
                        usage.requests(),
                        usage.input_tokens(),
                        usage.output_tokens(),
                        usage.quota(),
                    ),
                )
            },
        )
        .expect("valid pool");
        let (exhausted, members, identity, usage) = observed;

        assert_eq!(
            exhausted,
            ["acct-eu-2", "acct-eu-4", "acct-eu-5"],
            "an observed exhausted state and a spent quota each exhaust an \
             account on their own"
        );
        assert_eq!(
            members,
            vec![
                ("acct-eu-1".to_owned(), AccountState::Available, false),
                ("acct-eu-2".to_owned(), AccountState::Exhausted, true),
                ("acct-eu-3".to_owned(), AccountState::Available, false),
                ("acct-eu-4".to_owned(), AccountState::Available, true),
                ("acct-eu-5".to_owned(), AccountState::Exhausted, true),
                ("acct-eu-6".to_owned(), AccountState::RateLimited, false),
            ],
            "a pool handle carries the account's own observed state and \
             exhaustion, not a default"
        );
        assert_eq!(
            identity,
            (
                "acct-eu-1".to_owned(),
                "acme".to_owned(),
                "acme-eu".to_owned(),
                "eu".to_owned(),
                "vault://acme/eu/key".to_owned(),
                AccountState::Available,
            ),
            "the account holds a lookup coordinate, not a credential"
        );
        assert_eq!(usage, (3, 900, 300, Quota::Remaining(500)));
    }

    #[test]
    fn a_pool_carries_the_identity_and_policy_it_was_declared_with() {
        let declared = with_credential_pool(
            pool_parts(
                "pool-eu",
                vec![pool_account(
                    "acct-eu-1",
                    AccountState::Available,
                    Quota::Remaining(500),
                )],
            ),
            |pool| {
                (
                    pool.id().to_owned(),
                    pool.owner_organization().to_owned(),
                    pool.billing_tenant().to_owned(),
                    pool.data_boundary().to_owned(),
                    pool.accounts().len(),
                )
            },
        )
        .expect("valid pool");
        assert_eq!(
            declared,
            (
                "pool-eu".to_owned(),
                "acme".to_owned(),
                "acme-eu".to_owned(),
                "eu".to_owned(),
                1
            ),
            "the pool reports the policy every member was checked against"
        );
    }

    #[test]
    fn a_pools_own_fields_are_bounded_and_the_refusal_names_them() {
        let cases: [(&str, CredentialPoolParts<'_>); 4] = [
            (
                "pool_id",
                CredentialPoolParts {
                    id: "",
                    ..pool_parts("pool-eu", Vec::new())
                },
            ),
            (
                "owner_organization",
                CredentialPoolParts {
                    owner_organization: "",
                    ..pool_parts("pool-eu", Vec::new())
                },
            ),
            (
                "billing_tenant",
                CredentialPoolParts {
                    billing_tenant: "",
                    ..pool_parts("pool-eu", Vec::new())
                },
            ),
            (
                "data_boundary",
                CredentialPoolParts {
                    data_boundary: "",
                    ..pool_parts("pool-eu", Vec::new())
                },
            ),
        ];
        for (field, parts) in cases {
            let refused = with_credential_pool(parts, |pool| pool.id().to_owned())
                .expect_err("a pool field is missing");
            assert_eq!(
                refused,
                ModelError::Field {
                    field,
                    error: ValueError::Empty,
                },
                "a pool whose own policy is unnamed groups nothing"
            );
        }
    }

    #[test]
    fn a_pool_refuses_an_account_whose_policy_differs() {
        let foreign = |owner: &str, tenant: &str, boundary: &str| {
            PoolAccount::declare(PoolAccountParts {
                id: account("acct-us-1"),
                owner_organization: owner,
                billing_tenant: tenant,
                data_boundary: boundary,
                credential: CredentialReference::new("vault://acme/us/key").expect("valid"),
                usage: AccountUsage::new(0, 0, 0, Quota::Unmetered),
                state: AccountState::Available,
            })
            .expect("valid account")
        };
        let place = |held: PoolAccount| {
            with_credential_pool(pool_parts("pool-eu", vec![held]), |pool| {
                pool.accounts().len()
            })
        };

        // Each axis is enforced on its own: the pool's guarantee is that all
        // three agree, so any one of them differing must refuse the pool.
        for (axis, differing) in [
            ("owner_organization", foreign("globex", "acme-eu", "eu")),
            ("billing_tenant", foreign("acme", "acme-us", "eu")),
            ("data_boundary", foreign("acme", "acme-eu", "us")),
        ] {
            let refused = place(differing).expect_err("policy differs");
            assert_eq!(refused.category(), "pool_policy_mismatch");
            assert_eq!(
                refused,
                ModelError::PoolPolicyMismatch {
                    account: "acct-us-1".to_owned(),
                    axis,
                },
                "the refusal names the account and the axis that differs"
            );
        }

        let two_axes = place(foreign("acme", "acme-us", "us")).expect_err("policy differs");
        assert_eq!(
            two_axes,
            ModelError::PoolPolicyMismatch {
                account: "acct-us-1".to_owned(),
                axis: "billing_tenant",
            },
            "the first differing axis is named"
        );

        assert_eq!(
            place(foreign("acme", "acme-eu", "eu")).expect("policies agree"),
            1,
            "an account agreeing on every axis is grouped"
        );
    }

    #[test]
    fn an_account_outside_the_pool_has_no_handle() {
        let refused = with_credential_pool(
            pool_parts(
                "pool-eu",
                vec![pool_account(
                    "acct-eu-1",
                    AccountState::Available,
                    Quota::Unmetered,
                )],
            ),
            |pool| pool.member("acct-us-1").expect_err("not in pool"),
        )
        .expect("valid pool");
        assert_eq!(refused.category(), "unknown_account");
        assert_eq!(
            refused,
            ModelError::UnknownAccount {
                account: "acct-us-1".to_owned(),
            },
            "the refusal names the account that was asked for"
        );
    }
}

mod fallback_preservation {
    use super::*;

    #[test]
    fn a_chain_that_preserves_every_semantic_is_declarable() {
        let chain = FallbackChain::declare(
            FallbackClass::PrimaryTurn,
            vec![
                hop("acct-eu-1", "opus", requested_semantics()),
                hop("acct-eu-2", "sonnet", requested_semantics()),
                hop(
                    "acct-eu-3",
                    "haiku",
                    semantics(
                        &["read_file", "run_tests", "write_file"],
                        SandboxContainment::SealedOffline,
                        "eu",
                        ApprovalSemantics::DualControl,
                    ),
                ),
            ],
        )
        .expect("nothing weakens");
        assert_eq!(chain.class(), FallbackClass::PrimaryTurn);
        assert_eq!(chain.hops().len(), 3);
    }

    #[test]
    fn a_chain_whose_next_hop_weakens_a_semantic_is_refused_at_declaration() {
        let cases: [(&str, HopSemantics); 4] = [
            (
                "tools",
                semantics(
                    &["read_file"],
                    SandboxContainment::IsolatedWorkspace,
                    "eu",
                    ApprovalSemantics::ReviewRequired,
                ),
            ),
            (
                "sandbox",
                semantics(
                    &["read_file", "run_tests"],
                    SandboxContainment::HostDirect,
                    "eu",
                    ApprovalSemantics::ReviewRequired,
                ),
            ),
            (
                "residency",
                semantics(
                    &["read_file", "run_tests"],
                    SandboxContainment::IsolatedWorkspace,
                    "us",
                    ApprovalSemantics::ReviewRequired,
                ),
            ),
            (
                "approval",
                semantics(
                    &["read_file", "run_tests"],
                    SandboxContainment::IsolatedWorkspace,
                    "eu",
                    ApprovalSemantics::Automatic,
                ),
            ),
        ];

        for (axis, weakened) in cases {
            let refused = FallbackChain::declare(
                FallbackClass::PrimaryTurn,
                vec![
                    hop("acct-eu-1", "opus", requested_semantics()),
                    hop("acct-eu-2", "sonnet", weakened.clone()),
                ],
            )
            .expect_err("the chain weakens a requested semantic");
            assert_eq!(
                refused,
                ModelError::FallbackWeakens { axis, hop: 1 },
                "the refusal names the axis and the hop"
            );
            assert_eq!(refused.category(), "fallback_weakens");

            // The same weakening further down the chain reports its own
            // position: an index that is right only for the hop after the head
            // would send an operator to the wrong hop.
            let deeper = FallbackChain::declare(
                FallbackClass::PrimaryTurn,
                vec![
                    hop("acct-eu-1", "opus", requested_semantics()),
                    hop("acct-eu-2", "sonnet", requested_semantics()),
                    hop("acct-eu-3", "haiku", requested_semantics()),
                    hop("acct-eu-4", "micro", weakened),
                ],
            )
            .expect_err("the chain weakens a requested semantic");
            assert_eq!(
                deeper,
                ModelError::FallbackWeakens { axis, hop: 3 },
                "the refusal names the offending hop's own position"
            );
        }
    }

    #[test]
    fn the_first_hop_that_weakens_is_the_one_named() {
        let refused = FallbackChain::declare(
            FallbackClass::PrimaryTurn,
            vec![
                hop("acct-eu-1", "opus", requested_semantics()),
                hop("acct-eu-2", "sonnet", requested_semantics()),
                hop(
                    "acct-eu-3",
                    "haiku",
                    semantics(
                        &["read_file"],
                        SandboxContainment::IsolatedWorkspace,
                        "eu",
                        ApprovalSemantics::ReviewRequired,
                    ),
                ),
                hop(
                    "acct-eu-4",
                    "micro",
                    semantics(
                        &["read_file", "run_tests"],
                        SandboxContainment::HostDirect,
                        "eu",
                        ApprovalSemantics::ReviewRequired,
                    ),
                ),
            ],
        )
        .expect_err("two hops weaken");
        assert_eq!(
            refused,
            ModelError::FallbackWeakens {
                axis: "tools",
                hop: 2
            }
        );
    }

    #[test]
    fn every_hop_is_measured_against_the_head_rather_than_its_predecessor() {
        // Hop 1 strengthens containment; hop 2 returns to exactly what the head
        // requested. Nothing the head asked for is weakened, so the chain is
        // declarable — a chain compared pairwise would refuse this.
        let chain = FallbackChain::declare(
            FallbackClass::Vision,
            vec![
                hop("acct-eu-1", "opus", requested_semantics()),
                hop(
                    "acct-eu-2",
                    "sonnet",
                    semantics(
                        &["read_file", "run_tests"],
                        SandboxContainment::SealedOffline,
                        "eu",
                        ApprovalSemantics::DualControl,
                    ),
                ),
                hop("acct-eu-3", "haiku", requested_semantics()),
            ],
        )
        .expect("no hop weakens what the head requested");
        assert_eq!(chain.hops().len(), 3);
        assert_eq!(
            chain.hops()[2].semantics().containment(),
            SandboxContainment::IsolatedWorkspace
        );
        assert_eq!(chain.hops()[2].account().as_str(), "acct-eu-3");
        assert_eq!(chain.hops()[2].model().model(), "haiku");
        assert_eq!(
            chain.hops()[1].semantics().approval(),
            ApprovalSemantics::DualControl
        );
        assert_eq!(
            chain.hops()[0].semantics().tools(),
            ["read_file", "run_tests"]
        );
        assert_eq!(chain.hops()[0].semantics().residency_zone(), "eu");
    }

    #[test]
    fn a_chain_needs_at_least_one_hop() {
        assert_eq!(
            FallbackChain::declare(FallbackClass::Titling, Vec::new())
                .expect_err("empty")
                .category(),
            "empty_chain"
        );
    }

    #[test]
    fn each_class_declares_its_own_chain_independently() {
        assert_eq!(FallbackClass::ALL.len(), 8);
        let mut registry = FallbackRegistry::new();
        assert_eq!(registry.undeclared().len(), 8);

        registry
            .declare(
                FallbackChain::declare(
                    FallbackClass::Titling,
                    vec![hop("acct-eu-1", "haiku", requested_semantics())],
                )
                .expect("valid chain"),
            )
            .expect("first declaration");

        assert!(registry.chain_for(FallbackClass::Titling).is_some());
        assert!(
            registry.chain_for(FallbackClass::Vision).is_none(),
            "one class's chain never serves another"
        );
        assert_eq!(registry.undeclared().len(), 7);

        let duplicate = registry.declare(
            FallbackChain::declare(
                FallbackClass::Titling,
                vec![hop("acct-eu-2", "haiku", requested_semantics())],
            )
            .expect("valid chain"),
        );
        assert_eq!(
            duplicate.expect_err("already declared").category(),
            "duplicate_chain_class"
        );
    }
}

mod untrusted_advice {
    use super::*;

    fn turn_context() -> TurnContext {
        TurnContext::new(vec![
            ContextItem::new("task", ContextSensitivity::Shareable, 120).expect("valid"),
            ContextItem::new(
                "customer_record",
                ContextSensitivity::TenantConfidential,
                4_000,
            )
            .expect("valid"),
            ContextItem::new("tenant_policy", ContextSensitivity::Restricted, 900).expect("valid"),
        ])
    }

    fn reference_for(tenant: &str, id: &str, name: &str, advice: &str) -> ReferenceOutput {
        ReferenceCall::new(
            tenant,
            account(id),
            model("openai", name),
            MinimizedContext::minimize(&turn_context()),
        )
        .expect("valid call")
        .respond(advice, 100, 40)
        .expect("valid advice")
    }

    fn reference(id: &str, name: &str, advice: &str) -> ReferenceOutput {
        reference_for("acme", id, name, advice)
    }

    fn aggregator(tools: &[&str]) -> Aggregator {
        Aggregator::new(
            "acme",
            account("acct-eu-1"),
            model("anthropic", "opus"),
            tools,
        )
        .expect("valid aggregator")
    }

    #[test]
    fn a_reference_call_receives_a_minimized_context() {
        let minimized = MinimizedContext::minimize(&turn_context());
        assert_eq!(minimized.items().len(), 1);
        assert_eq!(minimized.items()[0].label(), "task");
        assert_eq!(
            minimized.withheld(),
            2,
            "anything above shareable is dropped"
        );
        assert_eq!(minimized.shared_bytes(), 120);

        let call = ReferenceCall::new(
            "acme",
            account("acct-ref-1"),
            model("openai", "reference"),
            minimized,
        )
        .expect("valid call");
        assert_eq!(call.context().withheld(), 2);
        // The call takes no toolset argument, so a reference model holding
        // tools is not expressible.
    }

    #[test]
    fn only_the_aggregator_produces_the_result_and_advice_stays_advice() {
        let aggregator = aggregator(&["read_file", "run_tests"]);
        assert_eq!(aggregator.tools(), ["read_file", "run_tests"]);
        assert_eq!(aggregator.model(), &model("anthropic", "opus"));

        let advice = reference("acct-ref-1", "reference", "prefer the cached plan");
        assert_eq!(
            advice.advice().expose_untrusted(),
            "prefer the cached plan",
            "advice is readable, and reading it is greppable"
        );

        let result = aggregator
            .conclude("apply the migration", vec![advice], 400, 120)
            .expect("valid result");
        assert_eq!(result.author(), &model("anthropic", "opus"));
        assert_eq!(result.text(), "apply the migration");
        assert_eq!(result.references().len(), 1);
        assert_eq!(
            result.references()[0].model(),
            &model("openai", "reference"),
            "the advice stays attributed to the model that gave it"
        );
        assert_eq!(
            result.references()[0].advice().expose_untrusted(),
            "prefer the cached plan",
            "the aggregator retains the advice it considered, still labelled"
        );
        assert_eq!(
            result.references()[0].usage().class(),
            UsageClass::Reference,
            "advice remains a reference record inside the authoritative one"
        );
        // The compile-fail proof that a reference output is not an
        // `AggregateResult` lives in the library doc tests, where it executes.
    }

    #[test]
    fn repeating_advice_verbatim_is_still_the_aggregators_own_record() {
        // What the types enforce is authorship, not wording. `expose_untrusted`
        // hands back a `&str`, and nothing stops a caller passing it straight
        // to `conclude` — so this pins what survives that: the result is
        // authored, classed and counted as the aggregator's, and the advice it
        // repeats is still carried as advice from the model that gave it.
        let aggregator = aggregator(&["read_file"]);
        let advice = reference("acct-ref-1", "reference", "prefer the cached plan");
        let repeated = advice.advice().expose_untrusted().to_owned();

        let result = aggregator
            .conclude(&repeated, vec![advice], 400, 120)
            .expect("valid result");
        assert_eq!(result.text(), "prefer the cached plan");
        assert_eq!(
            result.author(),
            &model("anthropic", "opus"),
            "authorship follows the acting model, never the wording"
        );
        assert_eq!(
            result.references()[0].model(),
            &model("openai", "reference")
        );
        let classes: Vec<UsageClass> = result
            .usage_records()
            .iter()
            .map(|record| record.class())
            .collect();
        assert_eq!(
            classes,
            [UsageClass::Reference, UsageClass::Aggregation],
            "repeating the words does not reclass the reference call"
        );
    }

    #[test]
    fn advice_and_result_text_are_bounded_before_they_are_recorded() {
        let call = || {
            ReferenceCall::new(
                "acme",
                account("acct-ref-1"),
                model("openai", "reference"),
                MinimizedContext::minimize(&turn_context()),
            )
            .expect("valid call")
        };
        assert_eq!(
            call().respond("", 10, 5).expect_err("empty advice"),
            ModelError::Field {
                field: "advice",
                error: ValueError::Empty,
            }
        );
        assert_eq!(
            call()
                .respond("prefer\u{7}the cache", 10, 5)
                .expect_err("control character"),
            ModelError::Field {
                field: "advice",
                error: ValueError::ControlCharacter,
            }
        );

        let aggregator = aggregator(&["read_file"]);
        assert_eq!(
            aggregator
                .conclude("", Vec::new(), 40, 20)
                .expect_err("empty result text"),
            ModelError::Field {
                field: "result_text",
                error: ValueError::Empty,
            }
        );
        let overlong = "p".repeat(MAX_MODEL_FIELD_BYTES + 1);
        assert_eq!(
            aggregator
                .conclude(&overlong, Vec::new(), 40, 20)
                .expect_err("over the ceiling"),
            ModelError::Field {
                field: "result_text",
                error: ValueError::TooLong {
                    max_bytes: MAX_MODEL_FIELD_BYTES,
                    actual_bytes: MAX_MODEL_FIELD_BYTES + 1,
                },
            }
        );
    }

    #[test]
    fn every_reference_call_is_a_counted_usage_record() {
        let aggregator = aggregator(&[]);
        let references = vec![
            reference("acct-ref-1", "reference-a", "one"),
            reference("acct-ref-2", "reference-b", "two"),
            // A reference call made for another tenant, so that "counted
            // against the tenant" is checked against a record that could have
            // named a different one.
            reference_for("acme-eu", "acct-ref-3", "reference-c", "three"),
        ];
        let result = aggregator
            .conclude("the plan", references, 400, 120)
            .expect("valid result");

        let records = result.usage_records();
        assert_eq!(records.len(), 4, "three references plus the aggregator");
        let tenants: Vec<&str> = records.iter().map(|record| record.tenant()).collect();
        assert_eq!(
            tenants,
            ["acme", "acme", "acme-eu", "acme"],
            "each record counts against the tenant of the call that made it"
        );
        let accounts: Vec<&str> = records
            .iter()
            .map(|record| record.account().as_str())
            .collect();
        assert_eq!(
            accounts,
            ["acct-ref-1", "acct-ref-2", "acct-ref-3", "acct-eu-1"],
            "each record names the account it bills"
        );
        let models: Vec<String> = records
            .iter()
            .map(|record| record.model().to_string())
            .collect();
        assert_eq!(
            models,
            [
                "openai/reference-a",
                "openai/reference-b",
                "openai/reference-c",
                "anthropic/opus"
            ],
            "each record names the model that was called"
        );
        let classes: Vec<UsageClass> = records.iter().map(|record| record.class()).collect();
        assert_eq!(
            classes,
            [
                UsageClass::Reference,
                UsageClass::Reference,
                UsageClass::Reference,
                UsageClass::Aggregation
            ]
        );
        let input: u64 = records.iter().map(|record| record.input_tokens()).sum();
        assert_eq!(input, 700);
        let output: u64 = records.iter().map(|record| record.output_tokens()).sum();
        assert_eq!(output, 240, "three references at 40 plus the aggregator");
    }
}

mod media_provenance {
    use super::*;

    fn adapter_parts() -> MediaAdapterParts<'static> {
        MediaAdapterParts {
            id: "tts-eu",
            family: MediaFamily::TextToSpeech,
            deployment: MediaDeployment::OrganizationHosted,
            formats: &["audio/ogg", "audio/mpeg"],
            max_input_bytes: 1_048_576,
            max_duration_ms: 120_000,
            model: model("elevenlabs", "voice"),
            model_version: "2026-01",
            pricing: pricing(),
            retention: MediaRetention::Discarded,
            data_policy: data_policy(),
            credential: CredentialReference::new("vault://acme/eu/tts").expect("valid"),
            egress: NetworkAccess::BrokeredNamed,
        }
    }

    #[test]
    fn an_adapter_declares_every_field() {
        assert_eq!(MediaFamily::ALL.len(), 8);
        let adapter = MediaAdapterDeclaration::declare(adapter_parts()).expect("valid adapter");
        assert_eq!(adapter.id(), "tts-eu");
        assert_eq!(adapter.family(), MediaFamily::TextToSpeech);
        assert_eq!(adapter.deployment(), MediaDeployment::OrganizationHosted);
        assert_eq!(adapter.formats(), ["audio/ogg", "audio/mpeg"]);
        assert_eq!(adapter.max_input_bytes(), 1_048_576);
        assert_eq!(adapter.max_duration_ms(), 120_000);
        assert_eq!(adapter.model().provider(), "elevenlabs");
        assert_eq!(adapter.model_version(), "2026-01");
        assert_eq!(adapter.pricing().currency(), "EUR");
        assert_eq!(adapter.retention(), MediaRetention::Discarded);
        assert_eq!(adapter.data_policy().boundary(), "eu");
        assert_eq!(
            adapter.credential_reference().as_str(),
            "vault://acme/eu/tts"
        );
        assert_eq!(adapter.egress(), NetworkAccess::BrokeredNamed);
    }

    #[test]
    fn an_adapter_is_not_declarable_with_a_missing_field() {
        let no_formats = MediaAdapterDeclaration::declare(MediaAdapterParts {
            formats: &[],
            ..adapter_parts()
        });
        assert_eq!(
            no_formats.expect_err("no formats").category(),
            "limit_required"
        );

        let no_ceiling = MediaAdapterDeclaration::declare(MediaAdapterParts {
            max_input_bytes: 0,
            ..adapter_parts()
        });
        assert_eq!(
            no_ceiling.expect_err("no ceiling").category(),
            "limit_required"
        );

        let no_version = MediaAdapterDeclaration::declare(MediaAdapterParts {
            model_version: "",
            ..adapter_parts()
        });
        assert_eq!(
            no_version.expect_err("no version").category(),
            "field_invalid"
        );
    }

    #[test]
    fn a_platform_derivative_is_a_distinct_artifact_carrying_provenance() {
        let original = ProtectedOriginal::new(
            ArtifactDigest::new("sha256:original").expect("valid"),
            "acme",
            MediaVisibility::TenantPrivate,
        )
        .expect("valid original");
        let provenance = MediaProvenance::new(
            ArtifactDigest::new("sha256:original").expect("valid"),
            "media-convert",
            model("local", "ffmpeg"),
            "6.1",
            instant(1_700_000_000_000),
        )
        .expect("valid provenance");

        let derivative = PlatformDerivative::derive(
            &original,
            ArtifactDigest::new("sha256:derivative").expect("valid"),
            "image/jpeg",
            provenance,
        )
        .expect("valid derivative");

        assert_ne!(derivative.digest(), original.digest());
        assert_eq!(derivative.provenance().source(), original.digest());
        assert_eq!(derivative.provenance().adapter(), "media-convert");
        assert_eq!(derivative.provenance().model_version(), "6.1");
        assert_eq!(derivative.format(), "image/jpeg");
        assert_eq!(
            original.visibility(),
            MediaVisibility::TenantPrivate,
            "the original is untouched by the derivation"
        );
    }

    #[test]
    fn a_derivative_that_reuses_the_digest_or_misnames_its_source_is_refused() {
        let original = ProtectedOriginal::new(
            ArtifactDigest::new("sha256:original").expect("valid"),
            "acme",
            MediaVisibility::ParticipantsOnly,
        )
        .expect("valid original");
        let honest = || {
            MediaProvenance::new(
                ArtifactDigest::new("sha256:original").expect("valid"),
                "media-convert",
                model("local", "ffmpeg"),
                "6.1",
                instant(1),
            )
            .expect("valid provenance")
        };

        let same_digest = PlatformDerivative::derive(
            &original,
            ArtifactDigest::new("sha256:original").expect("valid"),
            "image/jpeg",
            honest(),
        );
        assert_eq!(
            same_digest.expect_err("not distinct").category(),
            "derivative_not_distinct"
        );

        let wrong_source = PlatformDerivative::derive(
            &original,
            ArtifactDigest::new("sha256:derivative").expect("valid"),
            "image/jpeg",
            MediaProvenance::new(
                ArtifactDigest::new("sha256:somewhere-else").expect("valid"),
                "media-convert",
                model("local", "ffmpeg"),
                "6.1",
                instant(1),
            )
            .expect("valid provenance"),
        );
        assert_eq!(
            wrong_source.expect_err("wrong source").category(),
            "provenance_mismatch"
        );
    }

    #[test]
    fn generated_media_carries_provenance() {
        let provenance = || {
            MediaProvenance::new(
                ArtifactDigest::new("sha256:prompt").expect("valid"),
                "image-gen",
                model("openai", "images"),
                "2026-02",
                instant(5),
            )
            .expect("valid provenance")
        };
        let generated = GeneratedMedia::record(
            ArtifactDigest::new("sha256:generated").expect("valid"),
            provenance(),
        )
        .expect("valid generated media");
        assert_eq!(generated.provenance().source().as_str(), "sha256:prompt");
        assert_eq!(generated.provenance().adapter(), "image-gen");
        assert_eq!(generated.provenance().model(), &model("openai", "images"));
        assert_eq!(generated.provenance().model_version(), "2026-02");
        assert_eq!(generated.provenance().produced_at(), instant(5));
        assert_eq!(generated.digest().as_str(), "sha256:generated");
    }

    #[test]
    fn generated_media_that_names_itself_as_its_own_input_is_refused() {
        // A record whose output digest is its input digest claims a model
        // produced the artifact it was given, which is a provenance chain that
        // closes on itself rather than reaching a source.
        let refused = GeneratedMedia::record(
            ArtifactDigest::new("sha256:prompt").expect("valid"),
            MediaProvenance::new(
                ArtifactDigest::new("sha256:prompt").expect("valid"),
                "image-gen",
                model("openai", "images"),
                "2026-02",
                instant(5),
            )
            .expect("valid provenance"),
        )
        .expect_err("the generated digest is its own source");
        assert_eq!(refused, ModelError::DerivativeNotDistinct);
        assert_eq!(refused.category(), "derivative_not_distinct");

        // One byte of difference is enough to be a distinct artifact, so the
        // refusal is about identity rather than about similarity.
        GeneratedMedia::record(
            ArtifactDigest::new("sha256:prompt-2").expect("valid"),
            MediaProvenance::new(
                ArtifactDigest::new("sha256:prompt").expect("valid"),
                "image-gen",
                model("openai", "images"),
                "2026-02",
                instant(5),
            )
            .expect("valid provenance"),
        )
        .expect("a distinct digest records");
    }
}

mod voice_is_not_approval {
    use super::*;

    #[test]
    fn an_approval_is_satisfied_only_by_evidence_naming_the_same_action() {
        let pending = PendingApproval::new("deploy", "sha256:action").expect("valid");
        assert_eq!(pending.class(), "deploy");

        let other_action =
            ApprovalEvidence::new("ada", ApprovalChannel::ReviewedConsole, "sha256:other")
                .expect("valid evidence");
        assert!(!pending.is_satisfied_by(&other_action));
        assert_eq!(
            pending
                .clone()
                .resolve(&other_action)
                .expect_err("wrong action")
                .category(),
            "approval_mismatch"
        );

        let evidence = ApprovalEvidence::new(
            "ada",
            ApprovalChannel::PlatformIdentityChallenge,
            "sha256:action",
        )
        .expect("valid evidence");
        let approved = pending.resolve(&evidence).expect("same action");
        assert_eq!(approved.actor(), "ada");
        assert_eq!(approved.action_digest(), "sha256:action");
        assert_eq!(
            approved.channel(),
            ApprovalChannel::PlatformIdentityChallenge
        );
    }

    #[test]
    fn a_spoken_confirmation_becomes_content_rather_than_authority() {
        let spoken = SpokenConfirmation::new("yes, deploy it").expect("valid");
        assert_eq!(spoken.transcript(), "yes, deploy it");

        let item = spoken.into_context_item().expect("valid item");
        assert_eq!(item.label(), "voice_transcript");
        assert_eq!(
            item.sensitivity(),
            ContextSensitivity::TenantConfidential,
            "an utterance is context, and context is not authority"
        );
        assert_eq!(item.bytes(), 14);

        // The only channels an approval can arrive on are identity-bound ones,
        // and the compile-fail proof that a spoken confirmation cannot be
        // offered as evidence lives in the library doc tests.
        assert_eq!(ApprovalChannel::ALL.len(), 2);
        for channel in ApprovalChannel::ALL {
            let evidence =
                ApprovalEvidence::new("ada", channel, "sha256:action").expect("valid evidence");
            assert_eq!(evidence.channel(), channel);
        }
    }

    #[test]
    fn wake_word_detection_starts_capture_and_grants_nothing() {
        let detection = WakeWordDetection::new("hey automonique", instant(9_000), true)
            .expect("valid detection");
        assert_eq!(detection.phrase(), "hey automonique");
        assert!(detection.detected_locally());

        let capture = detection.begin_capture();
        assert_eq!(
            capture.started_at(),
            instant(9_000),
            "the whole effect of a wake word is that capture starts"
        );

        // Capture is not an approval: a pending action is still pending.
        let pending = PendingApproval::new("deploy", "sha256:action").expect("valid");
        assert_eq!(pending.action_digest(), "sha256:action");
    }
}

mod capability_separation {
    use super::*;

    fn browser() -> BrowserGrant {
        BrowserGrant::declare(BrowserGrantParts {
            origins: &["https://docs.example.test", "https://api.example.test"],
            capture: CapturePolicy::RedactedScreenshots,
            isolation: IsolationIdentity::new("acme", "run-1", "browser-profile")
                .expect("valid identity"),
            attestation: attestation("seccomp-browser"),
            reviewer: "ada",
            reviewed_at: instant(1_000),
        })
        .expect("valid grant")
    }

    #[test]
    fn a_browser_grant_is_bounded_by_its_reviewed_allowlist() {
        let grant = browser();
        assert_eq!(grant.origins().len(), 2);
        assert_eq!(grant.capture(), CapturePolicy::RedactedScreenshots);
        assert_eq!(grant.isolation().tenant(), "acme");
        assert_eq!(grant.isolation().run(), "run-1");
        assert_eq!(grant.reviewer(), "ada");
        assert_eq!(grant.reviewed_at(), instant(1_000));
        assert_eq!(grant.attestation(), &attestation("seccomp-browser"));
        assert!(grant.permits_origin("https://api.example.test"));
        assert!(!grant.permits_origin("https://evil.example.test"));

        let empty = BrowserGrant::declare(BrowserGrantParts {
            origins: &[],
            capture: CapturePolicy::NoCapture,
            isolation: IsolationIdentity::new("acme", "run-1", "browser-profile")
                .expect("valid identity"),
            attestation: attestation("seccomp-browser"),
            reviewer: "ada",
            reviewed_at: instant(1_000),
        });
        assert_eq!(
            empty.expect_err("no reviewed origins").category(),
            "limit_required"
        );
    }

    #[test]
    fn a_download_is_quarantined_and_released_only_against_its_own_digest() {
        let grant = browser();
        let refused = grant.download(
            "https://evil.example.test",
            "payload.zip",
            ArtifactDigest::new("sha256:download").expect("valid"),
        );
        assert_eq!(
            refused.expect_err("unreviewed origin").category(),
            "origin_not_allowlisted"
        );

        let quarantined = grant
            .download(
                "https://docs.example.test",
                "report.pdf",
                ArtifactDigest::new("sha256:download").expect("valid"),
            )
            .expect("allowlisted origin");
        assert_eq!(quarantined.name(), "report.pdf");
        assert_eq!(quarantined.origin(), "https://docs.example.test");

        let wrong = ApprovalEvidence::new("ada", ApprovalChannel::ReviewedConsole, "sha256:other")
            .expect("valid evidence");
        assert_eq!(
            quarantined
                .clone()
                .release(&wrong)
                .expect_err("approves another artifact")
                .category(),
            "approval_mismatch"
        );

        let evidence =
            ApprovalEvidence::new("ada", ApprovalChannel::ReviewedConsole, "sha256:download")
                .expect("valid evidence");
        let released = quarantined.release(&evidence).expect("same artifact");
        assert_eq!(released.name(), "report.pdf");
        assert_eq!(released.released_by(), "ada");
    }

    #[test]
    fn native_os_access_is_declared_on_its_own_reviewed_evidence() {
        let grant = browser();
        let native = NativeOsGrant::declare(NativeOsGrantParts {
            display: ":1",
            isolation: IsolationIdentity::new("acme", "run-1", "desktop-profile")
                .expect("valid identity"),
            capture: CapturePolicy::RedactedScreenshots,
            attestation: attestation("seccomp-desktop"),
            reviewer: "grace",
            reviewed_at: instant(2_000),
        })
        .expect("valid grant");

        // Every field of the native grant is the one it was declared with: the
        // desktop driver's authority is its own reviewed evidence rather than
        // anything carried across from the browser session.
        assert_eq!(native.display(), ":1");
        assert_eq!(native.isolation().tenant(), "acme");
        assert_eq!(native.isolation().run(), "run-1");
        assert_eq!(native.isolation().profile(), "desktop-profile");
        assert_eq!(native.capture(), CapturePolicy::RedactedScreenshots);
        assert_eq!(
            native.attestation(),
            &attestation("seccomp-desktop"),
            "the desktop driver attests to what it enforced"
        );
        assert_eq!(native.reviewer(), "grace");
        assert_eq!(native.reviewed_at(), instant(2_000));

        // The browser grant declared alongside it keeps its own reviewed
        // evidence, so neither record is derived from the other.
        assert_eq!(grant.attestation(), &attestation("seccomp-browser"));
        assert_eq!(grant.isolation().profile(), "browser-profile");
        assert_eq!(grant.reviewer(), "ada");
        assert_eq!(grant.reviewed_at(), instant(1_000));

        // A native grant is bounded like any other reviewed record: it names a
        // display and a reviewer, or it is not declarable.
        for (field, parts) in [
            (
                "display",
                NativeOsGrantParts {
                    display: "",
                    isolation: IsolationIdentity::new("acme", "run-1", "desktop-profile")
                        .expect("valid identity"),
                    capture: CapturePolicy::NoCapture,
                    attestation: attestation("seccomp-desktop"),
                    reviewer: "grace",
                    reviewed_at: instant(2_000),
                },
            ),
            (
                "reviewer",
                NativeOsGrantParts {
                    display: ":1",
                    isolation: IsolationIdentity::new("acme", "run-1", "desktop-profile")
                        .expect("valid identity"),
                    capture: CapturePolicy::NoCapture,
                    attestation: attestation("seccomp-desktop"),
                    reviewer: "",
                    reviewed_at: instant(2_000),
                },
            ),
        ] {
            assert_eq!(
                NativeOsGrant::declare(parts).expect_err("an unnamed grant"),
                ModelError::Field {
                    field,
                    error: ValueError::Empty,
                }
            );
        }
        // The compile-fail proof that a browser grant does not convert into a
        // native grant lives in the library doc tests, where it executes.
    }
}

mod executor_completeness {
    use super::*;

    #[test]
    fn every_declared_executor_field_is_present() {
        let registered = registration("exec-1", ExecutorClass::MicroVm, lifecycle("seccomp-1"));
        assert_eq!(registered.id(), "exec-1");
        assert_eq!(registered.class().as_str(), "micro_vm");
        assert!(registered.class().coordinate().is_none());
        assert_eq!(
            registered.workspace_transfer(),
            WorkspaceTransfer::ContentAddressedBundle
        );
        assert_eq!(
            registered.artifact_transfer(),
            ArtifactTransfer::DigestVerifiedPull
        );
        assert_eq!(registered.spec_acceptance().spec_digest(), "sha256:spec");
        assert_eq!(registered.lifecycle_evidence().kind(), EvidenceKind::Signed);
        assert_eq!(
            registered.credential_handling(),
            CredentialHandling::CapabilityInjected
        );
        assert_eq!(registered.event_cursor().stream(), "run-1");
        assert_eq!(registered.event_cursor().position(), 42);
        assert_eq!(registered.approval_pause().max_pause_ms(), 600_000);
        assert_eq!(registered.cancellation().grace_ms(), 5_000);
        assert_eq!(registered.cleanup(), Cleanup::WorkspaceAndCredentials);
        assert_eq!(registered.cost_accounting(), CostAccounting::PerSecond);

        let unnamed = ExecutorRegistration::declare(ExecutorRegistrationParts {
            id: "",
            class: ExecutorClass::Local,
            workspace_transfer: WorkspaceTransfer::SharedMount,
            artifact_transfer: ArtifactTransfer::DigestVerifiedPush,
            spec_acceptance: ImmutableSpecAcceptance::new("sha256:spec").expect("valid"),
            lifecycle_evidence: lifecycle("seccomp-1"),
            credential_handling: CredentialHandling::BrokerIssuedShortLived,
            event_cursor: EventCursor::new("run-1", 0).expect("valid"),
            approval_pause: ApprovalPause::new(1),
            cancellation: Cancellation::new(1),
            cleanup: Cleanup::WorkspaceCredentialsAndSnapshot,
            cost_accounting: CostAccounting::PerRequest,
        });
        assert_eq!(
            unnamed.expect_err("no identifier").category(),
            "field_invalid"
        );
    }

    #[test]
    fn lifecycle_evidence_is_signed_or_mutually_authenticated() {
        let signed = lifecycle("seccomp-1");
        assert_eq!(signed.kind(), EvidenceKind::Signed);
        assert_eq!(signed.local_identity(), "builder-1");
        assert_eq!(signed.digest(), "sha256:sig");
        assert_eq!(signed.enforcement(), &attestation("seccomp-1"));

        let mutual = LifecycleEvidence::mutually_authenticated(
            "control-plane",
            "worker-7",
            "sha256:channel",
            attestation("seccomp-2"),
        )
        .expect("valid evidence");
        assert_eq!(mutual.kind(), EvidenceKind::MutuallyAuthenticated);
        assert_eq!(mutual.remote_identity(), "worker-7");

        // A vendor's claim is recordable, and stays a claim: it has a vendor and
        // a label, and no path into evidence. The compile-fail proof lives in
        // the library doc tests.
        let label =
            VendorSandboxLabel::new("vendor", "runs in a secure sandbox").expect("valid label");
        assert_eq!(label.vendor(), "vendor");
        assert_eq!(label.label(), "runs in a secure sandbox");
    }

    #[test]
    fn a_remote_vendor_identifier_is_a_coordinate_and_carries_no_authority() {
        let coordinate = RemoteCoordinate::new("modal", "sandbox-abc123").expect("valid");
        assert_eq!(coordinate.vendor(), "modal");
        assert_eq!(coordinate.resource_id(), "sandbox-abc123");

        let first = registration(
            "exec-remote-1",
            ExecutorClass::Remote(coordinate.clone()),
            lifecycle("seccomp-1"),
        );
        let second = registration(
            "exec-remote-2",
            ExecutorClass::Remote(coordinate),
            lifecycle("seccomp-2"),
        );
        assert_eq!(
            first.class().coordinate().expect("remote").resource_id(),
            second.class().coordinate().expect("remote").resource_id(),
            "the two registrations name the same vendor resource"
        );

        assert_eq!(
            admit_allocation(&first, &lifecycle("seccomp-1")),
            AdmissionOutcome::Admitted
        );
        assert_eq!(
            admit_allocation(&first, second.lifecycle_evidence()),
            AdmissionOutcome::Refused,
            "sharing a vendor identifier admits nothing"
        );
    }

    #[test]
    fn scale_to_zero_is_a_distinct_state_from_running() {
        assert_eq!(EnvironmentState::ALL.len(), 4);
        assert_ne!(EnvironmentState::ScaledToZero, EnvironmentState::Running);
        assert!(EnvironmentState::Running.is_running());
        assert!(!EnvironmentState::ScaledToZero.is_running());
        assert!(!EnvironmentState::Hibernated.is_running());

        let coordinate = RemoteCoordinate::new("daytona", "env-1").expect("valid");
        let suspended = PersistentEnvironment::declare(
            "env-1",
            coordinate.clone(),
            None,
            EnvironmentState::ScaledToZero,
        )
        .expect("valid environment");
        assert_eq!(suspended.id(), "env-1");
        assert_eq!(suspended.coordinate().vendor(), "daytona");
        assert!(suspended.snapshot().is_none());

        let woken = suspended.wake().expect("suspended environments wake");
        assert_eq!(woken.state(), EnvironmentState::Running);
        assert_eq!(
            woken.wake().expect_err("already running").category(),
            "not_suspended"
        );

        let terminated =
            PersistentEnvironment::declare("env-2", coordinate, None, EnvironmentState::Terminated)
                .expect("valid environment");
        assert_eq!(
            terminated.wake().expect_err("gone").category(),
            "not_suspended"
        );
    }

    #[test]
    fn a_hibernated_environment_carries_the_snapshot_it_wakes_from() {
        let coordinate = RemoteCoordinate::new("daytona", "env-3").expect("valid");
        let snapshot =
            SnapshotRef::new("snap-1", "sha256:snapshot", instant(11)).expect("valid snapshot");

        let hibernated = PersistentEnvironment::declare(
            "env-3",
            coordinate.clone(),
            Some(snapshot),
            EnvironmentState::Hibernated,
        )
        .expect("valid environment");
        assert_eq!(hibernated.snapshot().expect("present").id(), "snap-1");
        assert_eq!(
            hibernated.snapshot().expect("present").taken_at(),
            instant(11)
        );
        assert_eq!(
            hibernated.wake().expect("wakes").state(),
            EnvironmentState::Running
        );

        let unsnapshotted =
            PersistentEnvironment::declare("env-4", coordinate, None, EnvironmentState::Hibernated);
        assert_eq!(
            unsnapshotted.expect_err("nothing to wake from").category(),
            "snapshot_required"
        );
    }
}

mod quality {
    use super::*;

    /// The toolchain half of this row — offline workspace tests, strict Clippy
    /// and formatting with no new allowance, dependency or lockfile change — is
    /// carried by the commands recorded in the item's evidence. What is
    /// checkable in-process is that the vocabulary those commands compile is
    /// itself honest: every refusal has a distinct, stable category and a
    /// message that names the refusal.
    #[test]
    fn every_refusal_has_a_distinct_stable_category_and_a_message() {
        let errors = [
            ModelError::Field {
                field: "region",
                error: ValueError::Empty,
            },
            ModelError::LimitRequired { field: "formats" },
            ModelError::DuplicateAlias {
                alias: "fast".to_owned(),
            },
            ModelError::UnknownAlias {
                alias: "slow".to_owned(),
            },
            ModelError::NoCandidates,
            ModelError::NoSelection,
            ModelError::AmbiguousSelection { count: 2 },
            ModelError::UnknownAccount {
                account: "acct-1".to_owned(),
            },
            ModelError::PoolPolicyMismatch {
                account: "acct-1".to_owned(),
                axis: "data_boundary",
            },
            ModelError::RotationToSelf {
                account: "acct-1".to_owned(),
            },
            ModelError::RotationTargetUnavailable {
                account: "acct-1".to_owned(),
                state: "exhausted",
            },
            ModelError::EmptyChain,
            ModelError::FallbackWeakens {
                axis: "sandbox",
                hop: 1,
            },
            ModelError::DuplicateChainClass { class: "titling" },
            ModelError::DerivativeNotDistinct,
            ModelError::ProvenanceMismatch,
            ModelError::OriginNotAllowlisted {
                origin: "https://evil.example.test".to_owned(),
            },
            ModelError::ApprovalMismatch,
            ModelError::NotSuspended { state: "running" },
            ModelError::SnapshotRequired,
        ];

        let mut categories: Vec<&str> = Vec::new();
        for error in &errors {
            assert!(!error.to_string().is_empty());
            categories.push(error.category());
        }
        let total = categories.len();
        categories.sort_unstable();
        categories.dedup();
        assert_eq!(categories.len(), total, "categories are distinct");

        let refusals = [
            SwitchRefusal::SovereigntyBoundary {
                from: "eu".to_owned(),
                to: "us".to_owned(),
            },
            SwitchRefusal::ProviderAccountBoundary {
                from: "acct-1".to_owned(),
                to: "acct-2".to_owned(),
            },
            SwitchRefusal::SessionBoundMigration {
                provider: "anthropic".to_owned(),
            },
            SwitchRefusal::HealthAloneInsufficient {
                provider: "anthropic".to_owned(),
            },
            SwitchRefusal::RevisionExhausted,
        ];
        let mut spellings: Vec<&str> = Vec::new();
        for refusal in &refusals {
            assert!(!refusal.to_string().is_empty());
            spellings.push(refusal.category());
        }
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total);
    }
}
