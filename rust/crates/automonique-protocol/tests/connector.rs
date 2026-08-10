// SPDX-License-Identifier: Elastic-2.0

//! R1-16 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `plan/contracts/R1-16.md`.

use std::path::PathBuf;

use automonique_protocol::connector::{
    Acknowledgement, ActionToken, ArtifactGrant, BusinessAcceptance, ConnectorError,
    ConversationCoordinates, GrantDirection, IdentityResolution, InstallationKey,
    InstallationRegistry, RenderIntent, SourceKey, SourceMessageEvent, TenantResolution,
};
use automonique_protocol::identity::Actor;
use automonique_protocol::primitives::{EpochMillis, Revision};
use automonique_protocol::release::ArtifactDigest;

const HEX: &str = "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899";

fn installation() -> InstallationKey {
    InstallationKey::new("teams", "app-1", "ext-tenant-1").expect("valid installation")
}

fn actor(id: &str) -> Actor {
    Actor::new("acme", id).expect("valid actor")
}

fn at(millis: i64) -> EpochMillis {
    EpochMillis::from_millis(millis)
}

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("non-zero revision")
}

fn digest() -> ArtifactDigest {
    ArtifactDigest::new("sha-256", HEX).expect("valid digest")
}

mod installation_resolution {
    use super::*;

    #[test]
    fn one_installation_resolves_to_one_tenant() {
        let mut registry = InstallationRegistry::new();
        registry.bind(installation(), "acme").expect("bound");
        assert_eq!(
            registry.resolve(&installation()),
            TenantResolution::Resolved {
                tenant: "acme".to_owned(),
            }
        );
    }

    #[test]
    fn an_unrecognized_installation_requires_installation() {
        let registry = InstallationRegistry::new();
        assert_eq!(
            registry.resolve(&installation()),
            TenantResolution::InstallationRequired,
            "there is no fallback tenant to land on"
        );

        // A different installation on a bound platform is still unknown.
        let mut bound = InstallationRegistry::new();
        bound.bind(installation(), "acme").expect("bound");
        let other = InstallationKey::new("teams", "app-1", "ext-tenant-2").expect("valid");
        assert_eq!(
            bound.resolve(&other),
            TenantResolution::InstallationRequired
        );
    }

    #[test]
    fn rebinding_replaces_rather_than_duplicating() {
        let mut registry = InstallationRegistry::new();
        registry.bind(installation(), "acme").expect("first");
        registry.bind(installation(), "globex").expect("rebound");
        assert_eq!(
            registry.resolve(&installation()),
            TenantResolution::Resolved {
                tenant: "globex".to_owned(),
            }
        );
    }
}

mod identity_resolution {
    use super::*;

    #[test]
    fn an_unlinked_identity_is_a_first_class_outcome() {
        let unlinked = IdentityResolution::Unlinked {
            link_prompt: "link your account".to_owned(),
        };
        match unlinked {
            IdentityResolution::Unlinked { link_prompt } => {
                assert_eq!(link_prompt, "link your account");
            }
            IdentityResolution::Linked { .. } => panic!("unlinked became an actor"),
        }
    }

    #[test]
    fn a_linked_identity_carries_a_tenant_scoped_actor() {
        let linked = IdentityResolution::Linked {
            actor: actor("alice"),
        };
        match linked {
            IdentityResolution::Linked { actor } => assert_eq!(actor.tenant(), "acme"),
            IdentityResolution::Unlinked { .. } => panic!("linked became unlinked"),
        }
    }
}

mod source_key_stability {
    use super::*;

    #[test]
    fn the_same_platform_event_yields_the_same_key() {
        let first = SourceKey::derive(&installation(), "evt-1").expect("derived");
        // A second connector instance, after a restart, derives it again from
        // the same inputs and must agree.
        let second = SourceKey::derive(&installation(), "evt-1").expect("derived");
        assert_eq!(first, second);
        for _ in 0..8 {
            assert_eq!(
                SourceKey::derive(&installation(), "evt-1").expect("derived"),
                first
            );
        }
    }

    #[test]
    fn different_events_and_installations_yield_different_keys() {
        let base = SourceKey::derive(&installation(), "evt-1").expect("derived");
        let other_event = SourceKey::derive(&installation(), "evt-2").expect("derived");
        assert_ne!(base, other_event);

        let other_install = InstallationKey::new("teams", "app-1", "ext-tenant-2").expect("valid");
        assert_ne!(
            base,
            SourceKey::derive(&other_install, "evt-1").expect("derived")
        );

        let other_platform =
            InstallationKey::new("discord", "app-1", "ext-tenant-1").expect("valid");
        assert_ne!(
            base,
            SourceKey::derive(&other_platform, "evt-1").expect("derived")
        );
    }

    #[test]
    fn a_key_takes_no_time_or_process_input() {
        // `derive` accepts an installation and a platform event id and nothing
        // else, so there is no argument through which a clock reading, a random
        // value or a process id could enter.
        let key = SourceKey::derive(&installation(), "evt-1").expect("derived");
        assert!(key.as_str().contains("teams"));
        assert!(key.as_str().ends_with("evt-1"));
    }
}

mod acknowledgement_split {
    use super::*;

    #[test]
    fn acknowledgement_and_acceptance_are_different_types() {
        let ack = Acknowledgement::deferred();
        assert!(ack.is_deferred());
        assert!(!Acknowledgement::immediate().is_deferred());

        // Acceptance exists only with a durable input identity.
        let accepted = BusinessAcceptance::for_input("input-1").expect("durable input");
        assert_eq!(accepted.input_id(), "input-1");
    }

    #[test]
    fn acceptance_requires_a_durable_input_identity() {
        assert!(
            BusinessAcceptance::for_input("").is_err(),
            "there is no acceptance without an input to point at"
        );
    }
}

mod render_intents {
    use super::*;

    #[test]
    fn every_intent_kind_is_structured_and_bounded() {
        let progress = RenderIntent::progress("building", 2, Some(5)).expect("valid");
        assert_eq!(progress.kind(), "progress");

        let terminal = RenderIntent::terminal("done", true).expect("valid");
        assert_eq!(terminal.kind(), "terminal");

        let clarification = RenderIntent::Clarification {
            question: "which branch?".to_owned(),
        };
        assert_eq!(clarification.kind(), "clarification");

        let approval = RenderIntent::Approval {
            summary: "deploy".to_owned(),
            target_revision: revision(3),
        };
        assert_eq!(approval.kind(), "approval");
    }

    #[test]
    fn intent_text_is_bounded() {
        assert!(RenderIntent::progress("", 0, None).is_err());
        assert!(RenderIntent::terminal(&"x".repeat(5_000), true).is_err());
        assert!(RenderIntent::terminal("ok", true).is_ok());
    }
}

mod action_token_binding {
    use super::*;

    fn token() -> ActionToken {
        ActionToken::mint(
            "opaque-secret-1",
            "approval-9",
            revision(3),
            actor("alice"),
            at(10_000),
        )
        .expect("valid token")
    }

    #[test]
    fn the_stored_form_is_not_the_token() {
        let minted = token();
        let stored = minted.stored_form();
        assert!(
            !stored.contains("opaque-secret-1"),
            "a store leak must not yield usable tokens"
        );
        assert!(stored.starts_with("h:"));
        // Deterministic, so a lookup by stored form works.
        assert_eq!(stored, token().stored_form());
    }

    #[test]
    fn a_valid_token_resolves() {
        token()
            .resolve(at(9_999), &actor("alice"), revision(3))
            .expect("valid at the bound revision");
    }

    #[test]
    fn a_changed_target_revision_conflicts_rather_than_retargeting() {
        assert_eq!(
            token()
                .resolve(at(1), &actor("alice"), revision(4))
                .expect_err("the target moved"),
            ConnectorError::TargetRevisionChanged {
                bound_to: 3,
                current: 4,
            }
        );
    }

    #[test]
    fn expiry_and_ineligibility_are_distinct_outcomes() {
        let expired = token()
            .resolve(at(10_000), &actor("alice"), revision(3))
            .expect_err("expired");
        let ineligible = token()
            .resolve(at(1), &actor("bob"), revision(3))
            .expect_err("not eligible");
        assert_eq!(expired, ConnectorError::TokenExpired);
        assert_eq!(ineligible, ConnectorError::ActorNotEligible);
        assert_ne!(expired.category(), ineligible.category());
    }

    #[test]
    fn an_actor_from_another_tenant_is_not_eligible() {
        let foreign = Actor::new("globex", "alice").expect("valid actor");
        assert_eq!(
            token()
                .resolve(at(1), &foreign, revision(3))
                .expect_err("cross-tenant"),
            ConnectorError::ActorNotEligible
        );
    }
}

mod artifact_grants {
    use super::*;

    #[test]
    fn a_grant_names_a_digest_and_a_ceiling() {
        let grant = ArtifactGrant::issue(GrantDirection::Upload, digest(), 1_024, at(5_000))
            .expect("valid grant");
        assert_eq!(grant.direction(), GrantDirection::Upload);
        assert_eq!(grant.max_bytes(), 1_024);
        assert!(grant.digest().matches(&digest()));
        assert!(grant.is_valid_at(at(4_999)));
        assert!(!grant.is_valid_at(at(5_000)));
    }

    #[test]
    fn a_grant_above_the_ceiling_is_refused() {
        assert_eq!(
            ArtifactGrant::issue(
                GrantDirection::Download,
                digest(),
                ArtifactGrant::MAX_GRANT_BYTES + 1,
                at(1),
            )
            .expect_err("too large")
            .category(),
            "grant_too_large"
        );
        assert!(
            ArtifactGrant::issue(
                GrantDirection::Download,
                digest(),
                ArtifactGrant::MAX_GRANT_BYTES,
                at(1),
            )
            .is_ok()
        );
    }
}

mod coordinate_preservation {
    use super::*;

    #[test]
    fn coordinates_round_trip() {
        let coordinates = ConversationCoordinates::new(
            installation(),
            "conv-1",
            Some("thread-1"),
            "msg-1",
            Some("en-GB"),
            true,
        )
        .expect("valid coordinates");
        assert_eq!(coordinates.conversation(), "conv-1");
        assert_eq!(coordinates.thread(), Some("thread-1"));
        assert_eq!(coordinates.message(), "msg-1");
        assert!(coordinates.was_mentioned());
    }

    #[test]
    fn a_platform_without_threads_is_representable() {
        let coordinates =
            ConversationCoordinates::new(installation(), "conv-1", None, "msg-1", None, false)
                .expect("valid coordinates");
        assert_eq!(coordinates.thread(), None);
        assert!(!coordinates.was_mentioned());
    }

    #[test]
    fn an_edit_revises_and_a_deletion_tombstones() {
        let revised = SourceMessageEvent::Revised {
            revision: revision(2),
        };
        let tombstoned = SourceMessageEvent::Tombstoned { at: at(1_000) };
        assert_ne!(revised, tombstoned);
        // Neither variant carries an approved action, so neither can rewrite
        // one.
        match revised {
            SourceMessageEvent::Revised { revision } => assert_eq!(revision.get(), 2),
            SourceMessageEvent::Tombstoned { .. } => panic!("wrong variant"),
        }
    }
}

mod platform_type_isolation {
    use super::*;

    /// The core protocol must not name a platform-specific type.
    ///
    /// A documented boundary is a boundary that leaks, so this reads the
    /// crate's own sources and fails on any declaration whose name belongs to a
    /// platform package.
    #[test]
    fn no_platform_specific_type_is_declared_in_the_core_protocol() {
        let source_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let forbidden = [
            "AdaptiveCard",
            "TeamsActivity",
            "Activity ",
            "DiscordInteraction",
            "InteractionResponse",
            "MessageComponent",
            "ActionRow",
            "SlashCommand",
            "EmbedBuilder",
            "BotFrameworkActivity",
        ];

        let mut scanned = 0_usize;
        let mut findings: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(&source_dir).expect("the crate has sources") {
            let path = entry.expect("directory entry").path();
            if path.extension().and_then(|value| value.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("readable source");
            scanned += 1;
            for name in forbidden {
                // Only declarations matter; prose in a doc comment explaining
                // what is excluded is exactly what should be allowed.
                for keyword in ["struct", "enum", "type", "trait"] {
                    let declaration = format!("{keyword} {}", name.trim());
                    if text.contains(&declaration) {
                        findings.push(format!("{}: {declaration}", path.display()));
                    }
                }
            }
        }
        assert!(scanned >= 10, "only {scanned} source files were scanned");
        assert!(
            findings.is_empty(),
            "platform-specific types reached the core protocol: {findings:?}"
        );
    }

    #[test]
    fn outbound_content_is_an_intent_rather_than_a_payload() {
        // Every `RenderIntent` variant is structured. A caller cannot hand the
        // protocol a pre-rendered body, because no variant accepts one.
        let intents = [
            RenderIntent::progress("building", 1, None).expect("valid"),
            RenderIntent::terminal("done", true).expect("valid"),
        ];
        for intent in intents {
            assert!(!intent.kind().is_empty());
        }
    }
}
