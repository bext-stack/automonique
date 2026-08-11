// SPDX-License-Identifier: Elastic-2.0

//! R1-20 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `plan/contracts/R1-20.md`.

use automonique_protocol::context::{
    AuthorizationState, CandidateMemory, ComponentCaps, ComponentClass, CompressionParts,
    CompressionRecord, Confidence, ContentForm, ContextFork, ContextLabel, ContextManifest,
    ContextReference, DeletionReason, EstimatedTokens, FolderDepth, FolderFilter, LearningProposal,
    LineRange, MAX_CONFIDENCE, MAX_FOLDER_DEPTH, MeasuredTokens, MemoryEntry, MemoryEntryParts,
    MemoryStore, PolicyComponent, ProposalKind, ProposalPayload, ProviderTokenCount,
    RedactionOutcome, ReferenceUse, ResolutionFacts, ResolvedReference, Retention, RuleFileFormat,
    SecretScan, Sensitivity, SuppliedClass, SuppliedComponent, TokenAccount, TokenBudget,
    TrustClass, UnavailableReason, Visibility, WorkspaceRuleReference,
};
use automonique_protocol::primitives::{EpochMillis, Revision};

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("non-zero revision")
}

fn caps() -> ComponentCaps {
    ComponentCaps::new(4_096, 512).expect("valid caps")
}

fn supplied(source: &str, trust: TrustClass) -> SuppliedComponent {
    SuppliedComponent::new(
        source,
        SuppliedClass::Attachments,
        trust,
        "sha256:c",
        caps(),
        RedactionOutcome::Redacted,
    )
    .expect("valid component")
}

fn policy(source: &str) -> PolicyComponent {
    PolicyComponent::new(
        source,
        revision(3),
        "sha256:p",
        caps(),
        RedactionOutcome::Clean,
    )
    .expect("valid component")
}

fn manifest() -> ContextManifest {
    ContextManifest::new(
        revision(7),
        TokenBudget::new(8_192),
        vec![policy("tenant-policy")],
        vec![
            supplied("AGENTS.md", TrustClass::ActorSupplied),
            supplied("retrieved", TrustClass::Untrusted),
        ],
    )
}

fn memory_parts<'a>(
    store: MemoryStore,
    tenant: &'a str,
    provenance: &'a str,
    retention: Retention,
) -> MemoryEntryParts<'a> {
    MemoryEntryParts {
        store,
        tenant,
        provenance,
        confidence: Confidence::new(80).expect("valid confidence"),
        sensitivity: Sensitivity::Confidential,
        visibility: Visibility::Team,
        retention,
    }
}

fn workspace_memory() -> MemoryEntry {
    MemoryEntry::record(memory_parts(
        MemoryStore::Workspace,
        "acme",
        "session-12",
        Retention::ReviewBy(EpochMillis::from_millis(9_000)),
    ))
    .expect("valid entry")
}

fn compression() -> CompressionRecord {
    CompressionRecord::record(CompressionParts {
        source_from: 10,
        source_to: 42,
        compressor_provider: "compressor-provider",
        compressor_model: "compressor-model",
        template_digest: "sha256:template",
        output_digest: "sha256:output",
        protected_facts: &["the deploy target is staging"],
        verification: automonique_protocol::context::VerificationStatus::Verified,
    })
    .expect("valid record")
}

fn clean_facts(provenance: &str) -> ResolutionFacts<'_> {
    ResolutionFacts {
        size_bytes: 2_048,
        provenance,
        form: ContentForm::Utf8Text,
        intended_use: ReferenceUse::InlineText,
        secrets: SecretScan::Clean,
        authorization: AuthorizationState::Unchanged,
    }
}

mod manifest_completeness {
    use super::*;

    #[test]
    fn a_manifest_carries_its_policy_revision_and_token_budget() {
        let manifest = manifest();
        assert_eq!(
            manifest.policy_revision(),
            revision(7),
            "the manifest says which policy revision it was assembled under"
        );
        assert_eq!(manifest.token_budget(), TokenBudget::new(8_192));
        assert_eq!(manifest.token_budget().total_tokens(), 8_192);
    }

    #[test]
    fn a_component_without_caps_or_digest_has_no_constructor() {
        assert_eq!(
            ComponentCaps::new(0, 512)
                .expect_err("no byte cap")
                .category(),
            "field_invalid"
        );
        assert_eq!(
            ComponentCaps::new(4_096, 0)
                .expect_err("no token cap")
                .category(),
            "field_invalid"
        );
        let no_digest = SuppliedComponent::new(
            "retrieved",
            SuppliedClass::Attachments,
            TrustClass::Untrusted,
            "",
            caps(),
            RedactionOutcome::Clean,
        );
        assert_eq!(
            no_digest.expect_err("no digest").category(),
            "field_invalid"
        );
        let policy_without_digest = PolicyComponent::new(
            "tenant-policy",
            revision(1),
            "",
            caps(),
            RedactionOutcome::Clean,
        );
        assert_eq!(
            policy_without_digest.expect_err("no digest").category(),
            "field_invalid"
        );
    }

    #[test]
    fn every_component_carries_source_trust_caps_digest_and_redaction() {
        let manifest = manifest();
        for component in manifest.policy() {
            assert!(!component.source().is_empty());
            assert!(!component.digest().is_empty());
            assert_eq!(component.trust(), TrustClass::Policy);
            assert!(component.caps().byte_cap() > 0);
            assert!(component.caps().token_cap() > 0);
            assert_eq!(component.redaction(), RedactionOutcome::Clean);
        }
        for component in manifest.supplied() {
            assert!(!component.source().is_empty());
            assert!(!component.digest().is_empty());
            assert!(component.trust() < TrustClass::Policy);
            assert!(component.caps().byte_cap() > 0);
            assert!(component.caps().token_cap() > 0);
            assert_eq!(component.redaction(), RedactionOutcome::Redacted);
        }
    }

    #[test]
    fn the_manifest_is_ordered_with_policy_ahead_of_supplied() {
        let manifest = manifest();
        assert_eq!(
            manifest.ordered_digests(),
            vec!["sha256:p", "sha256:c", "sha256:c"],
            "policy digests precede supplied digests in assembly order"
        );
    }

    #[test]
    fn declared_caps_are_measured_against_the_budget() {
        let manifest = manifest();
        assert_eq!(manifest.declared_token_total(), 3 * 512);
        assert!(manifest.within_budget());

        let tight = ContextManifest::new(
            revision(7),
            TokenBudget::new(100),
            vec![policy("tenant-policy")],
            vec![supplied("retrieved", TrustClass::Untrusted)],
        );
        assert!(
            !tight.within_budget(),
            "declared caps above the budget are visible, not silently accepted"
        );
    }
}

mod precedence_enforcement {
    use super::*;

    #[test]
    fn supplied_content_cannot_claim_policy_trust() {
        // Even when it asks for it.
        let retrieved = supplied("retrieved-document", TrustClass::Policy);
        assert_eq!(
            retrieved.trust(),
            TrustClass::ActorSupplied,
            "a supplied component that asks to be policy is lowered, not honoured"
        );
        assert!(retrieved.trust() < TrustClass::Policy);
    }

    #[test]
    fn every_supplied_trust_stays_below_policy() {
        for requested in TrustClass::ALL {
            assert!(supplied("s", requested).trust() < TrustClass::Policy);
        }
    }

    #[test]
    fn a_manifest_keeps_the_two_kinds_apart() {
        let manifest = manifest();
        assert_eq!(manifest.policy().len(), 1);
        assert_eq!(manifest.supplied().len(), 2);
        assert_eq!(manifest.policy()[0].trust(), TrustClass::Policy);
        assert!(
            manifest.highest_supplied_trust().expect("some supplied") < TrustClass::Policy,
            "no supplied component reached policy trust"
        );
    }

    #[test]
    fn supplied_content_cannot_be_classified_as_system_policy() {
        for class in SuppliedClass::ALL {
            assert_ne!(
                class.as_component_class(),
                ComponentClass::SystemPolicy,
                "{} is a supplied class and must not account as system policy",
                class.as_str()
            );
        }
        assert_eq!(
            policy("tenant-policy").class(),
            ComponentClass::SystemPolicy
        );
    }

    #[test]
    fn trust_classes_are_ordered_and_distinctly_spelled() {
        assert!(TrustClass::Untrusted < TrustClass::Compatibility);
        assert!(TrustClass::Compatibility < TrustClass::ActorSupplied);
        assert!(TrustClass::ActorSupplied < TrustClass::Policy);
        let mut spellings: Vec<&str> = TrustClass::ALL.iter().map(|class| class.as_str()).collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total);
    }
}

mod rule_discovery_bounds {
    use super::*;

    #[test]
    fn rule_discovery_is_bounded_to_the_registered_workspace() {
        for path in [
            "/etc/agents.md",
            "~/AGENTS.md",
            "../AGENTS.md",
            "../../etc/agents.md",
        ] {
            let error = WorkspaceRuleReference::discovered(path, RuleFileFormat::Shared)
                .expect_err("outside the workspace");
            assert_eq!(error.category(), "outside_workspace", "{path} was accepted");
        }
        let inside = WorkspaceRuleReference::discovered("docs/AGENTS.md", RuleFileFormat::Shared)
            .expect("inside the workspace");
        assert_eq!(inside.path().as_str(), "docs/AGENTS.md");
    }

    #[test]
    fn provider_specific_rule_files_carry_a_distinct_compatibility_class() {
        assert_eq!(RuleFileFormat::Shared.trust(), TrustClass::ActorSupplied);
        assert_eq!(
            RuleFileFormat::ProviderCompatibility.trust(),
            TrustClass::Compatibility
        );
        assert_ne!(
            RuleFileFormat::Shared.trust(),
            RuleFileFormat::ProviderCompatibility.trust(),
            "a provider-specific file is not the shared format"
        );
        for format in RuleFileFormat::ALL {
            assert!(
                format.trust() < TrustClass::Policy,
                "{} reached policy trust",
                format.as_str()
            );
        }
    }

    #[test]
    fn a_discovered_rule_file_becomes_supplied_content_not_policy() {
        for format in RuleFileFormat::ALL {
            let discovered = WorkspaceRuleReference::discovered("AGENTS.md", format)
                .expect("inside the workspace");
            let component = discovered
                .as_component("sha256:rules", caps(), RedactionOutcome::Clean)
                .expect("valid component");
            assert_eq!(component.trust(), format.trust());
            assert_eq!(component.class(), SuppliedClass::WorkspaceRules);
            assert!(component.trust() < TrustClass::Policy);
        }
    }
}

mod reference_typing {
    use super::*;

    fn one_of_every_kind() -> Vec<ContextReference> {
        vec![
            ContextReference::file("src/main.rs", "sha256:f").expect("valid"),
            ContextReference::folder(
                "src",
                FolderDepth::new(2).expect("valid"),
                FolderFilter::all(),
            )
            .expect("valid"),
            ContextReference::diff("HEAD~1").expect("valid"),
            ContextReference::staged(),
            ContextReference::commit("c0ffee").expect("valid"),
            ContextReference::branch("main").expect("valid"),
            ContextReference::url("https://example.com/doc").expect("valid"),
            ContextReference::session("session-12").expect("valid"),
            ContextReference::turn("session-12", "turn-3").expect("valid"),
            ContextReference::run("run-4").expect("valid"),
            ContextReference::ticket("TCK-5").expect("valid"),
            ContextReference::artifact("sha256:a").expect("valid"),
            ContextReference::workspace("ws-1").expect("valid"),
        ]
    }

    #[test]
    fn every_listed_reference_kind_round_trips() {
        let mut spellings: Vec<&str> = one_of_every_kind()
            .iter()
            .map(ContextReference::kind)
            .collect();
        let built = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), built, "two kinds share a spelling");
        assert_eq!(
            spellings,
            ContextReference::KINDS.to_vec(),
            "the built kinds are exactly the contract's list"
        );
    }

    #[test]
    fn a_file_reference_carries_a_line_range_and_a_digest() {
        let lines = LineRange::new(10, 42).expect("valid range");
        let reference =
            ContextReference::file_lines("src/main.rs", "sha256:f", lines).expect("valid");
        match reference {
            ContextReference::File {
                path,
                digest,
                lines,
            } => {
                assert_eq!(path.as_str(), "src/main.rs");
                assert_eq!(digest.as_str(), "sha256:f");
                let range = lines.expect("a line range");
                assert_eq!((range.first(), range.last()), (10, 42));
            }
            other => panic!("wrong variant: {}", other.kind()),
        }
    }

    #[test]
    fn an_inverted_or_zero_based_line_range_is_refused() {
        assert_eq!(
            LineRange::new(0, 10).expect_err("zero-based").category(),
            "invalid_range"
        );
        assert_eq!(
            LineRange::new(42, 10).expect_err("inverted").category(),
            "invalid_range"
        );
        LineRange::new(10, 10).expect("a single line is a range");
    }

    #[test]
    fn a_folder_reference_is_bounded_in_depth_and_filter() {
        assert_eq!(
            FolderDepth::new(0).expect_err("no depth").category(),
            "invalid_range"
        );
        assert_eq!(
            FolderDepth::new(MAX_FOLDER_DEPTH + 1)
                .expect_err("over the maximum")
                .category(),
            "invalid_range"
        );
        FolderDepth::new(MAX_FOLDER_DEPTH).expect("exactly at the maximum");

        assert_eq!(
            FolderFilter::matching("../*.rs")
                .expect_err("escapes the folder")
                .category(),
            "outside_workspace"
        );
        assert_eq!(
            FolderFilter::matching("/etc/*")
                .expect_err("escapes the folder")
                .category(),
            "outside_workspace"
        );
        let filter = FolderFilter::matching("*.rs").expect("valid filter");
        assert_eq!(filter.pattern(), Some("*.rs"));
        assert_eq!(FolderFilter::all().pattern(), None);
    }

    #[test]
    fn references_outside_the_workspace_are_refused() {
        for path in ["/etc/passwd", "~/secrets", "../../etc/passwd", "../outside"] {
            let error = ContextReference::file(path, "sha256:f").expect_err("outside");
            assert_eq!(error.category(), "outside_workspace", "{path} was accepted");
        }
        // A traversal that stays inside is fine.
        ContextReference::folder(
            "src/a/../b",
            FolderDepth::new(1).expect("valid"),
            FolderFilter::all(),
        )
        .expect("stays inside");
    }

    #[test]
    fn malformed_paths_are_refused_for_their_own_reason() {
        for path in [
            "src//main.rs",
            "src/./main.rs",
            "src/main.rs\0",
            "src\\main.rs",
        ] {
            let error = ContextReference::file(path, "sha256:f").expect_err("malformed");
            assert_eq!(error.category(), "reference_refused", "{path} was accepted");
        }
    }

    #[test]
    fn a_url_reference_is_a_reviewed_public_url() {
        ContextReference::url("https://example.com/doc").expect("valid");
        for url in [
            "file:///etc/passwd",
            "https://user:pw@example.com/",
            "https://example.com/#fragment",
        ] {
            let error = ContextReference::url(url).expect_err("refused");
            assert_eq!(error.category(), "url_invalid", "{url} was accepted");
        }
    }

    #[test]
    fn a_resolved_reference_carries_its_size_and_provenance() {
        let resolved = ResolvedReference::resolve(
            ContextReference::file("src/main.rs", "sha256:f").expect("valid"),
            clean_facts("workspace-scan"),
        )
        .expect("resolves");
        assert_eq!(resolved.size_bytes(), 2_048);
        assert_eq!(resolved.provenance(), "workspace-scan");
        assert_eq!(resolved.form(), ContentForm::Utf8Text);
        assert_eq!(resolved.intended_use(), ReferenceUse::InlineText);
        assert_eq!(resolved.reference().kind(), "file");
    }

    #[test]
    fn resolution_rejects_secrets_binary_confusion_and_authorization_changes() {
        let reference = ContextReference::file("src/main.rs", "sha256:f").expect("valid");

        let mut binary = clean_facts("workspace-scan");
        binary.form = ContentForm::Binary;
        assert_eq!(
            ResolvedReference::resolve(reference.clone(), binary)
                .expect_err("binary inlined as text")
                .category(),
            "binary_confusion"
        );

        let mut binary_handle = clean_facts("workspace-scan");
        binary_handle.form = ContentForm::Binary;
        binary_handle.intended_use = ReferenceUse::ArtifactHandle;
        ResolvedReference::resolve(reference.clone(), binary_handle)
            .expect("binary carried as an artifact handle is not confusion");

        let mut secret = clean_facts("workspace-scan");
        secret.secrets = SecretScan::SecretDetected;
        assert_eq!(
            ResolvedReference::resolve(reference.clone(), secret)
                .expect_err("secret detected")
                .category(),
            "secret_detected"
        );

        let mut reauthorized = clean_facts("workspace-scan");
        reauthorized.authorization = AuthorizationState::Changed;
        assert_eq!(
            ResolvedReference::resolve(reference.clone(), reauthorized)
                .expect_err("authorization changed")
                .category(),
            "authorization_changed"
        );

        let missing_provenance = clean_facts("");
        assert_eq!(
            ResolvedReference::resolve(reference, missing_provenance)
                .expect_err("no provenance")
                .category(),
            "classification_required"
        );
    }
}

mod compression_lineage {
    use super::*;

    #[test]
    fn a_compression_records_its_full_lineage() {
        let record = compression();
        assert_eq!(record.source_range(), (10, 42));
        assert_eq!(record.compressor_provider(), "compressor-provider");
        assert_eq!(record.compressor_model(), "compressor-model");
        assert_eq!(record.template_digest(), "sha256:template");
        assert_eq!(record.output_digest(), "sha256:output");
        assert_eq!(record.protected_facts().len(), 1);
        assert!(record.is_verified());
        assert_eq!(record.verification().as_str(), "verified");
    }

    #[test]
    fn an_unverified_compression_is_not_reported_as_verified() {
        for status in automonique_protocol::context::VerificationStatus::ALL {
            let record = CompressionRecord::record(CompressionParts {
                source_from: 0,
                source_to: 1,
                compressor_provider: "p",
                compressor_model: "m",
                template_digest: "sha256:t",
                output_digest: "sha256:o",
                protected_facts: &[],
                verification: status,
            })
            .expect("valid record");
            assert_eq!(
                record.is_verified(),
                status == automonique_protocol::context::VerificationStatus::Verified,
                "{} was reported wrongly",
                status.as_str()
            );
        }
    }

    #[test]
    fn a_compression_cannot_reach_the_authoritative_transcript() {
        // The record carries digests and a range. There is no field holding the
        // transcript, so compression produces a derived view and cannot mutate
        // or delete what it derived from; the range still addresses the
        // authoritative messages. The compile-fail proof that no accessor
        // returns one lives in the library doc tests, where it executes.
        let record = compression();
        assert_eq!(record.source_range(), (10, 42));
        assert_ne!(record.output_digest(), record.template_digest());
    }

    #[test]
    fn an_inverted_source_range_is_refused() {
        let inverted = CompressionRecord::record(CompressionParts {
            source_from: 42,
            source_to: 10,
            compressor_provider: "p",
            compressor_model: "m",
            template_digest: "sha256:t",
            output_digest: "sha256:o",
            protected_facts: &[],
            verification: automonique_protocol::context::VerificationStatus::Pending,
        });
        assert_eq!(
            inverted.expect_err("inverted range").category(),
            "invalid_range"
        );
    }

    #[test]
    fn forking_before_compression_is_expressible() {
        let record = compression();
        let fork = ContextFork::before_compression(&record, "session-12", "session-13", 10)
            .expect("a fork at the first compressed message is before it");
        assert_eq!(fork.source_session().as_str(), "session-12");
        assert_eq!(fork.fork_session().as_str(), "session-13");
        assert_eq!(fork.at_message(), 10);
        assert!(fork.precedes(&record));

        let earlier = ContextFork::before_compression(&record, "session-12", "session-14", 3)
            .expect("an earlier fork is also before it");
        assert!(earlier.precedes(&record));
    }

    #[test]
    fn a_fork_inside_the_compressed_range_is_not_a_fork_before_compression() {
        let record = compression();
        assert_eq!(
            ContextFork::before_compression(&record, "session-12", "session-13", 11)
                .expect_err("inside the compressed range")
                .category(),
            "invalid_range"
        );
        assert_eq!(
            ContextFork::before_compression(&record, "session-12", "session-12", 5)
                .expect_err("its own source")
                .category(),
            "reference_refused"
        );
    }
}

mod token_honesty {
    use super::*;

    #[test]
    fn an_estimate_cannot_be_read_as_a_measurement() {
        let reported = TokenAccount::new(
            ComponentClass::Conversation,
            EstimatedTokens::new(90),
            ProviderTokenCount::Reported(MeasuredTokens::new(100)),
        );
        assert_eq!(reported.measured(), Some(MeasuredTokens::new(100)));
        assert_eq!(reported.estimated(), EstimatedTokens::new(90));
        assert_eq!(reported.unavailable_reason(), None);

        let estimated_only = TokenAccount::new(
            ComponentClass::Conversation,
            EstimatedTokens::new(90),
            ProviderTokenCount::Unavailable(
                UnavailableReason::new("provider does not report usage").expect("valid reason"),
            ),
        );
        assert_eq!(
            estimated_only.measured(),
            None,
            "an estimate is never returned as a measurement"
        );
        assert_eq!(
            estimated_only.estimated(),
            EstimatedTokens::new(90),
            "the estimate is still readable, as an estimate"
        );
    }

    #[test]
    fn an_unavailable_count_is_absent_with_a_reason() {
        let account = TokenAccount::new(
            ComponentClass::Tools,
            EstimatedTokens::new(12),
            ProviderTokenCount::Unavailable(
                UnavailableReason::new("provider silent").expect("valid reason"),
            ),
        );
        assert_eq!(account.measured(), None);
        assert_eq!(account.unavailable_reason(), Some("provider silent"));
        assert_eq!(
            UnavailableReason::new("")
                .expect_err("an empty reason is not a reason")
                .category(),
            "field_invalid"
        );
    }

    #[test]
    fn every_component_class_is_accounted_separately() {
        assert_eq!(ComponentClass::ALL.len(), 8);
        let mut spellings: Vec<&str> = ComponentClass::ALL
            .iter()
            .map(|class| class.as_str())
            .collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total);

        for class in ComponentClass::ALL {
            let account = TokenAccount::new(
                class,
                EstimatedTokens::new(1),
                ProviderTokenCount::Reported(MeasuredTokens::new(2)),
            );
            assert_eq!(account.class(), class);
        }
    }
}

mod memory_typing {
    use super::*;

    #[test]
    fn every_store_is_representable_and_tenant_scoped() {
        assert_eq!(MemoryStore::ALL.len(), 6);
        let mut spellings: Vec<&str> = MemoryStore::ALL
            .iter()
            .map(|store| store.as_str())
            .collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total);

        for store in MemoryStore::ALL {
            let entry = MemoryEntry::record(memory_parts(
                store,
                "acme",
                "session-12",
                Retention::ExpiresAt(EpochMillis::from_millis(1_000)),
            ))
            .expect("valid entry");
            assert_eq!(entry.store(), store);
            assert_eq!(entry.tenant(), "acme");

            let untenanted = MemoryEntry::record(memory_parts(
                store,
                "",
                "session-12",
                Retention::UnderLegalHold,
            ));
            assert_eq!(
                untenanted.expect_err("no tenant").category(),
                "field_invalid",
                "{} accepted an entry with no tenant",
                store.as_str()
            );
        }
    }

    #[test]
    fn an_entry_carries_every_required_classification() {
        let entry = workspace_memory();
        assert_eq!(entry.provenance(), "session-12");
        assert_eq!(entry.confidence().get(), 80);
        assert_eq!(entry.sensitivity(), Sensitivity::Confidential);
        assert_eq!(entry.visibility(), Visibility::Team);
        assert_eq!(
            entry.retention(),
            Retention::ReviewBy(EpochMillis::from_millis(9_000))
        );
        assert_eq!(
            entry.retention().instant(),
            Some(EpochMillis::from_millis(9_000))
        );
    }

    #[test]
    fn a_memory_without_provenance_is_unrecordable() {
        let error = MemoryEntry::record(memory_parts(
            MemoryStore::Workspace,
            "acme",
            "",
            Retention::UnderLegalHold,
        ))
        .expect_err("no provenance");
        assert_eq!(error.category(), "classification_required");
    }

    #[test]
    fn confidence_is_bounded() {
        Confidence::new(MAX_CONFIDENCE).expect("exactly at the maximum");
        assert_eq!(
            Confidence::new(MAX_CONFIDENCE + 1)
                .expect_err("over the maximum")
                .category(),
            "confidence_out_of_range"
        );
    }

    #[test]
    fn retention_is_total_and_says_what_it_permits() {
        assert!(Retention::ExpiresAt(EpochMillis::EPOCH).permits_deletion());
        assert!(Retention::ReviewBy(EpochMillis::EPOCH).permits_deletion());
        assert!(
            !Retention::UnderLegalHold.permits_deletion(),
            "a legal hold forbids deletion"
        );
        assert_eq!(Retention::UnderLegalHold.instant(), None);
    }

    #[test]
    fn sensitivity_and_visibility_are_distinct_classifications() {
        let mut spellings: Vec<&str> = Sensitivity::ALL
            .iter()
            .map(|level| level.as_str())
            .chain(Visibility::ALL.iter().map(|level| level.as_str()))
            .collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total);
        assert!(Sensitivity::Public < Sensitivity::Restricted);
        assert!(Visibility::Private < Visibility::Tenant);
    }
}

mod supersession_and_deletion {
    use super::*;

    #[test]
    fn a_correction_supersedes_rather_than_mutating() {
        let original = workspace_memory();
        assert!(original.superseded_by().is_none());

        let corrected = original
            .supersede_with("mem-2")
            .expect("valid supersession");
        assert_eq!(corrected.superseded_by(), Some("mem-2"));
        assert!(
            original.superseded_by().is_none(),
            "the original entry is unchanged, so the audit trail survives"
        );
        assert_eq!(corrected.provenance(), original.provenance());
        assert_eq!(corrected.confidence(), original.confidence());
        assert_eq!(corrected.sensitivity(), original.sensitivity());
    }

    #[test]
    fn an_already_superseded_entry_cannot_be_repointed() {
        let superseded = workspace_memory()
            .supersede_with("mem-2")
            .expect("valid supersession");
        assert_eq!(
            superseded
                .supersede_with("mem-3")
                .expect_err("history is not rewritable")
                .category(),
            "already_superseded"
        );
    }

    #[test]
    fn deletion_leaves_a_tombstone_that_preserves_the_audit_trail() {
        let entry = workspace_memory();
        let tombstone = entry
            .delete(
                "mem-1",
                EpochMillis::from_millis(5_000),
                DeletionReason::ActorRequest,
            )
            .expect("retention permits deletion");
        assert_eq!(tombstone.entry_id(), "mem-1");
        assert_eq!(tombstone.store(), entry.store());
        assert_eq!(tombstone.tenant(), entry.tenant());
        assert_eq!(
            tombstone.provenance(),
            entry.provenance(),
            "the tombstone keeps where the deleted memory came from"
        );
        assert_eq!(tombstone.sensitivity(), entry.sensitivity());
        assert_eq!(tombstone.deleted_at(), EpochMillis::from_millis(5_000));
        assert_eq!(tombstone.reason(), DeletionReason::ActorRequest);
    }

    #[test]
    fn deletion_follows_the_retention_rule() {
        let held = MemoryEntry::record(memory_parts(
            MemoryStore::Team,
            "acme",
            "review-3",
            Retention::UnderLegalHold,
        ))
        .expect("valid entry");
        assert_eq!(
            held.delete(
                "mem-9",
                EpochMillis::from_millis(5_000),
                DeletionReason::RetentionExpired
            )
            .expect_err("legal hold")
            .category(),
            "retention_forbids_deletion"
        );
    }

    #[test]
    fn every_deletion_reason_has_a_distinct_spelling() {
        assert_eq!(DeletionReason::ALL.len(), 3);
        let mut spellings: Vec<&str> = DeletionReason::ALL
            .iter()
            .map(|reason| reason.as_str())
            .collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total);
    }
}

mod proposal_isolation {
    use super::*;

    fn payloads() -> Vec<ProposalPayload> {
        vec![
            ProposalPayload::Memory(
                CandidateMemory::propose(memory_parts(
                    MemoryStore::UserProfile,
                    "acme",
                    "session-12",
                    Retention::ReviewBy(EpochMillis::from_millis(9_000)),
                ))
                .expect("valid candidate"),
            ),
            ProposalPayload::SkillPatch {
                skill: ContextLabel::new("deploy").expect("valid"),
                patch_digest: ContextLabel::new("sha256:patch").expect("valid"),
            },
            ProposalPayload::NewSkill {
                skill: ContextLabel::new("release").expect("valid"),
                bundle_digest: ContextLabel::new("sha256:bundle").expect("valid"),
            },
        ]
    }

    #[test]
    fn a_proposal_always_carries_the_lowest_trust() {
        for payload in payloads() {
            let kind = payload.kind();
            let proposal = LearningProposal::new(payload, "three passing runs", revision(2))
                .expect("valid proposal");
            assert_eq!(
                proposal.trust(),
                TrustClass::Untrusted,
                "a model-originated proposal cannot raise its own trust"
            );
            assert_eq!(proposal.kind(), kind);
            assert_eq!(proposal.revision(), revision(2));
        }
    }

    #[test]
    fn an_executable_skill_can_never_auto_activate() {
        for payload in payloads() {
            let kind = payload.kind();
            let proposal =
                LearningProposal::new(payload, "evidence", revision(1)).expect("valid proposal");
            assert_eq!(
                proposal.may_auto_activate(),
                !kind.is_executable(),
                "{} was auto-activatable",
                kind.as_str()
            );
        }
        assert!(ProposalKind::SkillPatch.is_executable());
        assert!(ProposalKind::NewSkill.is_executable());
        assert!(!ProposalKind::Memory.is_executable());
    }

    #[test]
    fn a_proposal_requires_evidence() {
        let payload = ProposalPayload::SkillPatch {
            skill: ContextLabel::new("deploy").expect("valid"),
            patch_digest: ContextLabel::new("sha256:patch").expect("valid"),
        };
        assert_eq!(
            LearningProposal::new(payload, "", revision(1))
                .expect_err("no evidence")
                .category(),
            "field_invalid"
        );
    }

    #[test]
    fn a_candidate_memory_is_not_published_state() {
        // The candidate carries every classification a published entry does,
        // and no accessor returns a MemoryEntry. The compile-fail proof that a
        // candidate cannot be bound as one lives in the library doc tests,
        // where it executes.
        let candidate = CandidateMemory::propose(memory_parts(
            MemoryStore::UserProfile,
            "acme",
            "session-12",
            Retention::ReviewBy(EpochMillis::from_millis(9_000)),
        ))
        .expect("valid candidate");
        assert_eq!(candidate.store(), MemoryStore::UserProfile);
        assert_eq!(candidate.tenant(), "acme");
        assert_eq!(candidate.provenance(), "session-12");
        assert_eq!(candidate.confidence().get(), 80);
        assert_eq!(candidate.sensitivity(), Sensitivity::Confidential);
        assert_eq!(candidate.visibility(), Visibility::Team);
        assert_eq!(
            candidate.retention(),
            Retention::ReviewBy(EpochMillis::from_millis(9_000))
        );
    }
}
