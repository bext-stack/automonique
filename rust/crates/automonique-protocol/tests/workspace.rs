// SPDX-License-Identifier: Elastic-2.0

//! R1-14 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `plan/contracts/R1-14.md`.

use automonique_protocol::primitives::Revision;
use automonique_protocol::release::ArtifactDigest;
use automonique_protocol::workspace::{
    Artifact, ArtifactLink, DeletionState, IsolationKind, LinkRelation, LockRegistry,
    RetentionClass, StorageLocator, Visibility, WorkspaceError, WorkspaceRegistration,
    WorkspaceToken,
};

const HEX_A: &str = "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899";
const HEX_B: &str = "0011223344556677889900112233445566778899aabbccddeeff001122334455";

fn digest(hex: &str) -> ArtifactDigest {
    ArtifactDigest::new("sha-256", hex).expect("valid digest")
}

fn token(value: &str) -> WorkspaceToken {
    WorkspaceToken::new(value).expect("valid token")
}

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("non-zero revision")
}

fn registration() -> WorkspaceRegistration {
    WorkspaceRegistration::new(
        "acme",
        "git+ssh://example.invalid/repo",
        revision(7),
        "snap-1",
        IsolationKind::AttemptCopy,
        token("wt-1"),
    )
    .expect("valid registration")
}

fn artifact(hex: &str, retention: RetentionClass) -> Artifact {
    Artifact::new(
        digest(hex),
        1_024,
        "application/json",
        "acme",
        "actor-1",
        Visibility::Tenant,
        retention,
    )
    .expect("valid artifact")
}

mod path_unrepresentability {
    use super::*;

    #[test]
    fn a_path_shaped_token_is_refused() {
        for candidate in [
            "/srv/work",
            "srv/work",
            "..\\escape",
            "../escape",
            "C:tmp",
            "~/home",
        ] {
            assert_eq!(
                WorkspaceToken::new(candidate)
                    .expect_err("path-shaped")
                    .category(),
                "path_shaped_token",
                "{candidate} was accepted as an opaque token"
            );
        }
    }

    #[test]
    fn an_opaque_token_is_accepted_and_round_trips() {
        assert_eq!(token("wt-3f9a").as_str(), "wt-3f9a");
        assert_eq!(registration().token().as_str(), "wt-1");
    }
}

mod base_immutability {
    use super::*;

    #[test]
    fn an_in_place_base_change_is_refused() {
        let registered = registration();
        assert_eq!(
            registered
                .set_base_revision(revision(8))
                .expect_err("immutable"),
            WorkspaceError::BaseIsImmutable { revision: 7 }
        );
        assert_eq!(registered.base_revision().get(), 7);
        assert_eq!(registered.snapshot(), "snap-1");
    }

    #[test]
    fn a_changed_base_means_a_new_registration() {
        let original = registration();
        let moved = original
            .at_new_base(revision(8), "snap-2", token("wt-2"))
            .expect("new registration");

        assert_eq!(moved.base_revision().get(), 8);
        assert_eq!(moved.snapshot(), "snap-2");
        // The original is untouched, so evidence attached to it stays true.
        assert_eq!(original.base_revision().get(), 7);
        assert_eq!(original.snapshot(), "snap-1");
        assert_eq!(moved.tenant(), original.tenant());
        assert_eq!(moved.canonical_source(), original.canonical_source());
        assert_eq!(
            original.canonical_source(),
            "git+ssh://example.invalid/repo"
        );
        assert_eq!(moved.isolation(), IsolationKind::AttemptCopy);
    }
}

mod lock_exclusion {
    use super::*;

    #[test]
    fn a_held_lock_conflicts_naming_the_holder() {
        let mut locks = LockRegistry::new();
        locks.acquire("wt-1:/src", "run-1").expect("first acquire");
        assert_eq!(
            locks
                .acquire("wt-1:/src", "run-2")
                .expect_err("already held"),
            WorkspaceError::LockHeld {
                holder: "run-1".to_owned(),
            }
        );
        assert_eq!(locks.holder_of("wt-1:/src"), Some("run-1"));
    }

    #[test]
    fn a_reentrant_acquire_is_the_same_conflict() {
        let mut locks = LockRegistry::new();
        locks.acquire("wt-1:/src", "run-1").expect("first");
        assert_eq!(
            locks
                .acquire("wt-1:/src", "run-1")
                .expect_err("no silent reentrancy"),
            WorkspaceError::LockHeld {
                holder: "run-1".to_owned(),
            }
        );
    }

    #[test]
    fn release_requires_the_holders_identity() {
        let mut locks = LockRegistry::new();
        locks.acquire("wt-1:/src", "run-1").expect("acquire");
        assert_eq!(
            locks
                .release("wt-1:/src", "run-2")
                .expect_err("not the holder"),
            WorkspaceError::NotLockHolder {
                holder: "run-1".to_owned(),
                attempted_by: "run-2".to_owned(),
            }
        );
        assert_eq!(locks.holder_of("wt-1:/src"), Some("run-1"));

        locks
            .release("wt-1:/src", "run-1")
            .expect("holder releases");
        assert_eq!(locks.holder_of("wt-1:/src"), None);
        // And the key is now available to someone else.
        locks.acquire("wt-1:/src", "run-2").expect("reacquire");
    }

    #[test]
    fn releasing_an_unheld_key_does_not_silently_succeed() {
        let mut locks = LockRegistry::new();
        assert!(locks.release("wt-1:/src", "run-1").is_err());
    }
}

mod digest_addressing {
    use super::*;

    #[test]
    fn identity_is_the_digest_not_the_locator() {
        let one = artifact(HEX_A, RetentionClass::Standard)
            .with_locator(StorageLocator::new("local", "objects/aa").expect("valid"));
        let two = artifact(HEX_A, RetentionClass::Standard)
            .with_locator(StorageLocator::new("local", "objects/aa").expect("valid"))
            .with_locator(StorageLocator::new("remote", "shard-2").expect("valid"));

        assert!(
            one.is_same_content(&two),
            "the same bytes in two places are one artifact"
        );
        assert_eq!(one.locators().len(), 1);
        assert_eq!(two.locators().len(), 2);

        let other = artifact(HEX_B, RetentionClass::Standard);
        assert!(!one.is_same_content(&other));
    }

    #[test]
    fn weakened_digest_algorithms_are_refused_by_the_shared_rule() {
        // Enforced once, in `release::ArtifactDigest`, rather than restated.
        for algorithm in ["md5", "sha-1", "crc32"] {
            assert!(ArtifactDigest::new(algorithm, HEX_A).is_err());
        }
    }
}

mod required_classification {
    use super::*;

    #[test]
    fn visibility_and_retention_are_required_arguments() {
        // Both are positional and neither has a default; the only way to build
        // an artifact is to name them.
        let recorded = artifact(HEX_A, RetentionClass::Audit);
        assert_eq!(recorded.visibility(), Visibility::Tenant);
        assert_eq!(recorded.retention(), RetentionClass::Audit);
        assert_eq!(recorded.size_bytes(), 1_024);
    }

    #[test]
    fn the_vocabularies_are_closed_and_distinct() {
        let visibilities = [
            Visibility::Private,
            Visibility::Tenant,
            Visibility::Published,
        ];
        for (index, left) in visibilities.iter().enumerate() {
            for right in &visibilities[index + 1..] {
                assert_ne!(left, right);
            }
        }
        let retentions = [
            RetentionClass::Ephemeral,
            RetentionClass::Standard,
            RetentionClass::Audit,
            RetentionClass::LegalHold,
        ];
        for (index, left) in retentions.iter().enumerate() {
            for right in &retentions[index + 1..] {
                assert_ne!(left, right);
            }
        }
    }
}

mod locator_abstraction {
    use super::*;

    #[test]
    fn a_locator_cannot_embed_a_path_or_a_dereferenceable_url() {
        for key in [
            "/var/lib/objects/aa",
            "https://bucket.example.invalid/aa",
            "s3://bucket/aa",
            "user:secret@host/aa",
            "C:\\objects\\aa",
        ] {
            assert_eq!(
                StorageLocator::new("local", key)
                    .expect_err("not opaque")
                    .category(),
                "locator_not_opaque",
                "{key} was accepted as an opaque locator"
            );
        }
    }

    #[test]
    fn an_opaque_locator_names_a_backend_and_a_key() {
        let locator = StorageLocator::new("local", "objects.aa11").expect("valid");
        assert_eq!(locator.backend(), "local");
        assert_eq!(locator.key(), "objects.aa11");
    }
}

mod link_typing {
    use super::*;

    #[test]
    fn every_relation_is_representable_with_a_distinct_spelling() {
        assert_eq!(LinkRelation::ALL.len(), 6);
        let mut spellings: Vec<&str> = LinkRelation::ALL
            .iter()
            .map(|relation| relation.as_str())
            .collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total, "two relations share a spelling");

        for relation in LinkRelation::ALL {
            let link = ArtifactLink::new(relation, digest(HEX_A), "target-1").expect("valid link");
            assert_eq!(link.relation(), relation);
            assert_eq!(link.target(), "target-1");
        }
    }

    #[test]
    fn a_link_carries_the_artifact_digest_rather_than_a_locator() {
        let link = ArtifactLink::new(LinkRelation::Approval, digest(HEX_A), "approval-9")
            .expect("valid link");
        assert!(link.digest().matches(&digest(HEX_A)));
    }
}

mod deletion_order {
    use super::*;

    #[test]
    fn deletion_proceeds_access_then_tombstone_then_collection() {
        let live = artifact(HEX_A, RetentionClass::Standard);
        assert_eq!(live.deletion(), DeletionState::Live);

        let removed = live.remove_access().expect("first step");
        assert_eq!(removed.deletion(), DeletionState::AccessRemoved);

        let tombstoned = removed.tombstone().expect("second step");
        assert_eq!(tombstoned.deletion(), DeletionState::Tombstoned);

        let collectable = tombstoned.permit_collection().expect("third step");
        assert_eq!(collectable.deletion(), DeletionState::Collectable);
    }

    #[test]
    fn bytes_are_never_collectable_before_the_tombstone_is_durable() {
        let live = artifact(HEX_A, RetentionClass::Standard);
        assert!(
            live.permit_collection().is_err(),
            "collection before a tombstone would erase the record of removal"
        );
        let removed = live.remove_access().expect("access removed");
        assert!(removed.permit_collection().is_err());
    }

    #[test]
    fn steps_cannot_be_repeated_or_reordered() {
        let removed = artifact(HEX_A, RetentionClass::Standard)
            .remove_access()
            .expect("first");
        assert!(removed.remove_access().is_err(), "already removed");
        assert!(
            artifact(HEX_A, RetentionClass::Standard)
                .tombstone()
                .is_err(),
            "a tombstone requires access removal first"
        );
    }

    #[test]
    fn legal_hold_refuses_every_deletion_step() {
        let held = artifact(HEX_A, RetentionClass::LegalHold);
        assert!(held.remove_access().is_err());
        assert!(held.tombstone().is_err());
        assert!(held.permit_collection().is_err());
    }

    #[test]
    fn deduplication_does_not_block_a_logical_deletion() {
        // Two tenants holding identical bytes are separate artifacts, so
        // deleting one says nothing about the other and cannot be prevented by
        // the other's existence.
        let mine = artifact(HEX_A, RetentionClass::Standard);
        let theirs = Artifact::new(
            digest(HEX_A),
            1_024,
            "application/json",
            "globex",
            "actor-9",
            Visibility::Private,
            RetentionClass::Standard,
        )
        .expect("valid artifact");

        assert!(mine.is_same_content(&theirs), "the bytes are identical");
        let deleted = mine
            .remove_access()
            .expect("deletion is not blocked by another tenant's copy");
        assert_eq!(deleted.deletion(), DeletionState::AccessRemoved);
        assert_eq!(
            theirs.deletion(),
            DeletionState::Live,
            "and the other tenant's copy is unaffected"
        );
    }
}
