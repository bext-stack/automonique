// SPDX-License-Identifier: Elastic-2.0

//! R1-20 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `plan/contracts/R1-20.md`.

use automonique_protocol::context::{
    CompressionRecord, ContextManifest, ContextReference, LearningProposal, MemoryEntry,
    MemoryStore, PolicyComponent, ProposalKind, SuppliedComponent, TokenCount, TrustClass,
};
use automonique_protocol::primitives::{EpochMillis, Revision};

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("non-zero revision")
}

fn supplied(source: &str, trust: TrustClass) -> SuppliedComponent {
    SuppliedComponent::new(source, trust, "sha256:c", 4_096, true).expect("valid component")
}

fn policy(source: &str) -> PolicyComponent {
    PolicyComponent::new(source, revision(3), "sha256:p").expect("valid component")
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
        for requested in [
            TrustClass::Untrusted,
            TrustClass::Compatibility,
            TrustClass::ActorSupplied,
            TrustClass::Policy,
        ] {
            assert!(supplied("s", requested).trust() < TrustClass::Policy);
        }
    }

    #[test]
    fn a_manifest_keeps_the_two_kinds_apart() {
        let manifest = ContextManifest::new(
            vec![policy("tenant-policy")],
            vec![
                supplied("AGENTS.md", TrustClass::ActorSupplied),
                supplied("retrieved", TrustClass::Untrusted),
            ],
        );
        assert_eq!(manifest.policy().len(), 1);
        assert_eq!(manifest.supplied().len(), 2);
        assert_eq!(manifest.policy()[0].trust(), TrustClass::Policy);
        assert!(
            manifest.highest_supplied_trust().expect("some supplied") < TrustClass::Policy,
            "no supplied component reached policy trust"
        );
    }

    #[test]
    fn trust_classes_are_ordered_and_distinctly_spelled() {
        assert!(TrustClass::Untrusted < TrustClass::Compatibility);
        assert!(TrustClass::Compatibility < TrustClass::ActorSupplied);
        assert!(TrustClass::ActorSupplied < TrustClass::Policy);
        let mut spellings = [
            TrustClass::Untrusted.as_str(),
            TrustClass::Compatibility.as_str(),
            TrustClass::ActorSupplied.as_str(),
            TrustClass::Policy.as_str(),
        ];
        spellings.sort_unstable();
        let total = spellings.len();
        let mut deduped = spellings.to_vec();
        deduped.dedup();
        assert_eq!(deduped.len(), total);
    }
}

mod reference_typing {
    use super::*;

    #[test]
    fn a_workspace_relative_reference_is_accepted() {
        let file = ContextReference::file("src/main.rs", "sha256:f").expect("valid");
        assert_eq!(file.kind(), "file");
        let folder = ContextReference::folder("src/nested", 2).expect("valid");
        assert_eq!(folder.kind(), "folder");
        // A traversal that stays inside is fine.
        ContextReference::folder("src/a/../b", 1).expect("stays inside");
    }

    #[test]
    fn references_outside_the_workspace_are_refused() {
        for path in ["/etc/passwd", "~/secrets", "../../etc/passwd", "../outside"] {
            let error = ContextReference::file(path, "sha256:f").expect_err("outside");
            assert_eq!(error.category(), "outside_workspace", "{path} was accepted");
        }
    }

    #[test]
    fn malformed_paths_are_refused_for_their_own_reason() {
        for path in ["src//main.rs", "src/./main.rs", "src/main.rs\0"] {
            let error = ContextReference::file(path, "sha256:f").expect_err("malformed");
            assert_eq!(error.category(), "reference_refused", "{path} was accepted");
        }
    }

    #[test]
    fn every_reference_kind_has_a_distinct_spelling() {
        let kinds = [
            ContextReference::file("a", "d").expect("valid").kind(),
            ContextReference::folder("b", 1).expect("valid").kind(),
            ContextReference::Diff {
                revision: "r".to_owned(),
            }
            .kind(),
            ContextReference::Url {
                url: "https://x".to_owned(),
            }
            .kind(),
            ContextReference::Session {
                session: "s".to_owned(),
            }
            .kind(),
            ContextReference::Artifact {
                digest: "d".to_owned(),
            }
            .kind(),
        ];
        let mut spellings = kinds.to_vec();
        spellings.sort_unstable();
        let total = spellings.len();
        spellings.dedup();
        assert_eq!(spellings.len(), total);
    }
}

mod token_honesty {
    use super::*;

    #[test]
    fn an_estimate_cannot_be_read_as_a_measurement() {
        assert_eq!(TokenCount::Measured { tokens: 100 }.measured(), Some(100));
        assert_eq!(TokenCount::Estimated { tokens: 100 }.measured(), None);
        assert_eq!(
            TokenCount::Unavailable {
                reason: "provider silent"
            }
            .measured(),
            None
        );
    }

    #[test]
    fn unavailability_carries_a_reason() {
        let unavailable = TokenCount::Unavailable {
            reason: "provider does not report usage",
        };
        match unavailable {
            TokenCount::Unavailable { reason } => assert!(!reason.is_empty()),
            _ => panic!("wrong variant"),
        }
    }
}

mod compression_lineage {
    use super::*;

    #[test]
    fn a_compression_records_its_full_lineage() {
        let record = CompressionRecord::new(
            10,
            42,
            "compressor-model",
            "sha256:template",
            "sha256:output",
            &["the deploy target is staging"],
            true,
        )
        .expect("valid record");

        assert_eq!(record.source_range(), (10, 42));
        assert_eq!(record.compressor_model(), "compressor-model");
        assert_eq!(record.protected_facts().len(), 1);
        assert!(record.is_verified());
    }

    #[test]
    fn a_compression_cannot_reach_the_authoritative_transcript() {
        // The record carries digests and a range. There is no field holding the
        // transcript, so compression produces a derived view and cannot mutate
        // or delete what it derived from.
        let record = CompressionRecord::new(0, 1, "m", "sha256:t", "sha256:o", &[], false)
            .expect("valid record");
        assert!(!record.is_verified());
        assert!(record.protected_facts().is_empty());
    }
}

mod memory_typing {
    use super::*;

    #[test]
    fn every_store_is_representable_with_a_distinct_spelling() {
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
            let entry = MemoryEntry::new(
                store,
                "acme",
                "session-12",
                80,
                TrustClass::ActorSupplied,
                Some(EpochMillis::from_millis(1_000)),
            )
            .expect("valid entry");
            assert_eq!(entry.store(), store);
        }
    }

    #[test]
    fn a_memory_without_provenance_is_unrecordable() {
        let error = MemoryEntry::new(
            MemoryStore::Workspace,
            "acme",
            "",
            50,
            TrustClass::ActorSupplied,
            None,
        )
        .expect_err("no provenance");
        assert_eq!(error.category(), "classification_required");
    }

    #[test]
    fn a_correction_supersedes_rather_than_mutating() {
        let original = MemoryEntry::new(
            MemoryStore::Workspace,
            "acme",
            "session-12",
            80,
            TrustClass::ActorSupplied,
            None,
        )
        .expect("valid entry");
        assert!(original.supersedes().is_none());

        let corrected = original.superseded_by("mem-2").expect("valid supersession");
        assert_eq!(corrected.supersedes(), Some("mem-2"));
        assert!(
            original.supersedes().is_none(),
            "the original entry is unchanged, so the audit trail survives"
        );
        assert_eq!(corrected.provenance(), original.provenance());
        assert_eq!(corrected.confidence(), original.confidence());
    }

    #[test]
    fn a_memory_carries_its_visibility_and_review_date() {
        let entry = MemoryEntry::new(
            MemoryStore::Team,
            "acme",
            "review-3",
            60,
            TrustClass::Compatibility,
            Some(EpochMillis::from_millis(9_000)),
        )
        .expect("valid entry");
        assert_eq!(entry.visibility(), TrustClass::Compatibility);
        assert_eq!(entry.review_by(), Some(EpochMillis::from_millis(9_000)));
    }
}

mod proposal_isolation {
    use super::*;

    #[test]
    fn a_proposal_always_carries_the_lowest_trust() {
        for kind in [
            ProposalKind::Memory,
            ProposalKind::SkillPatch,
            ProposalKind::NewSkill,
        ] {
            let proposal = LearningProposal::new(kind, "three passing runs").expect("valid");
            assert_eq!(
                proposal.trust(),
                TrustClass::Untrusted,
                "a model-originated proposal cannot raise its own trust"
            );
            assert_eq!(proposal.kind(), kind);
        }
    }

    #[test]
    fn an_executable_skill_can_never_auto_activate() {
        for kind in [ProposalKind::SkillPatch, ProposalKind::NewSkill] {
            let proposal = LearningProposal::new(kind, "evidence").expect("valid");
            assert!(
                !proposal.may_auto_activate(),
                "an agent-created executable skill is never silently activated"
            );
        }
        // Non-executable personal memory is the only auto-acceptable kind.
        let memory = LearningProposal::new(ProposalKind::Memory, "evidence").expect("valid");
        assert!(memory.may_auto_activate());
    }

    #[test]
    fn a_proposal_requires_evidence() {
        assert!(LearningProposal::new(ProposalKind::Memory, "").is_err());
    }
}
