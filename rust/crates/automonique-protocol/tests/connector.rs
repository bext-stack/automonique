// SPDX-License-Identifier: Elastic-2.0

//! R1-16 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `docs/product-plan/requirements/connector-catalog.md`.

use std::path::PathBuf;

use automonique_protocol::connector::{
    Acknowledgement, ActionToken, ArtifactGrant, BusinessAcceptance, ConformanceObligation,
    ConnectorError, ConversationCoordinates, DurableEvent, EventOutcome, GrantDirection,
    IdentityResolution, InstallationKey, InstallationRegistry, IntentPhrase, RenderIntent,
    SourceKey, SourceMessageEvent, SourceMessageLog, TenantResolution,
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

fn phrase(wording: &str) -> IntentPhrase {
    IntentPhrase::parse(wording).expect("plain wording")
}

fn coordinates() -> ConversationCoordinates {
    ConversationCoordinates::new(
        installation(),
        "conv-1",
        Some("thread-1"),
        "msg-1",
        Some("en-GB"),
        true,
    )
    .expect("valid coordinates")
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

    fn event(outcome: EventOutcome) -> DurableEvent {
        DurableEvent::record("evt-1", revision(7), outcome).expect("durable event")
    }

    #[test]
    fn every_intent_kind_is_derived_from_a_durable_event() {
        let outcomes = [
            (
                EventOutcome::Progressed {
                    summary: phrase("building"),
                    completed: 2,
                    total: Some(5),
                },
                "progress",
            ),
            (
                EventOutcome::ClarificationRequested {
                    question: phrase("which branch?"),
                },
                "clarification",
            ),
            (
                EventOutcome::ApprovalRequired {
                    summary: phrase("deploy"),
                },
                "approval",
            ),
            (
                EventOutcome::Finished {
                    summary: phrase("done"),
                    succeeded: true,
                },
                "terminal",
            ),
        ];
        for (outcome, kind) in outcomes {
            let intent = RenderIntent::derived_from(&event(outcome.clone()));
            assert_eq!(intent.kind(), kind);
            // The intent names the event it came from, so it cannot describe a
            // state that was never recorded.
            assert_eq!(intent.source_event(), "evt-1");
            assert_eq!(intent.target_revision(), revision(7));
            assert_eq!(intent.outcome(), &outcome);
        }
    }

    #[test]
    fn pre_rendered_markup_is_not_a_representable_phrase() {
        for markup in [
            // The exact probe that measured this row as failing.
            "<AdaptiveCard><TextBlock>done</TextBlock></AdaptiveCard>",
            "{\"type\":\"AdaptiveCard\",\"version\":\"1.5\"}",
            "{\"type\":2,\"data\":{\"custom_id\":\"approve\"}}",
            "<b>done</b>",
            "&lt;script&gt;",
            "[approve](https://example.invalid/approve)",
            "`rm -rf`",
            "escaped\\u003c",
        ] {
            assert_eq!(
                IntentPhrase::parse(markup)
                    .expect_err("presentation is not wording")
                    .category(),
                "markup_rejected",
                "{markup} reached an intent"
            );
        }
        // Differing only in the markup, the same wording parses.
        assert_eq!(phrase("done").as_str(), "done");
    }

    #[test]
    fn intent_wording_is_bounded() {
        assert_eq!(
            IntentPhrase::parse("").expect_err("empty").category(),
            "field_invalid"
        );
        assert!(IntentPhrase::parse(&"x".repeat(5_000)).is_err());
        assert!(IntentPhrase::parse("ok").is_ok());
    }

    #[test]
    fn an_invalid_event_identity_is_refused() {
        assert_eq!(
            DurableEvent::record(
                "",
                revision(1),
                EventOutcome::Finished {
                    summary: phrase("done"),
                    succeeded: true,
                },
            )
            .expect_err("an intent needs an event to point at")
            .category(),
            "field_invalid"
        );
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
    fn every_named_coordinate_round_trips() {
        // Platform, installation, conversation, thread, message, locale and
        // mention context: all seven go in and all seven come back out. A
        // coordinate that cannot be read back was not preserved.
        let coordinates = coordinates();
        assert_eq!(coordinates.platform(), "teams");
        assert_eq!(coordinates.installation(), &installation());
        assert_eq!(coordinates.installation().application(), "app-1");
        assert_eq!(
            coordinates.installation().installation_owner(),
            "ext-tenant-1"
        );
        assert_eq!(coordinates.conversation(), "conv-1");
        assert_eq!(coordinates.thread(), Some("thread-1"));
        assert_eq!(coordinates.message(), "msg-1");
        assert_eq!(coordinates.locale(), Some("en-GB"));
        assert!(coordinates.was_mentioned());
    }

    #[test]
    fn a_platform_without_threads_or_a_locale_is_representable() {
        let coordinates =
            ConversationCoordinates::new(installation(), "conv-1", None, "msg-1", None, false)
                .expect("valid coordinates");
        assert_eq!(coordinates.thread(), None);
        assert_eq!(coordinates.locale(), None);
        assert!(!coordinates.was_mentioned());
        assert_eq!(coordinates.platform(), "teams");
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

    #[test]
    fn a_tombstone_is_recorded_beside_the_history_not_in_place_of_it() {
        let mut log = SourceMessageLog::opened(coordinates());
        log.record(SourceMessageEvent::Revised {
            revision: revision(2),
        });
        log.record(SourceMessageEvent::Revised {
            revision: revision(3),
        });
        log.record(SourceMessageEvent::Tombstoned { at: at(1_000) });

        assert!(log.is_tombstoned());
        assert_eq!(
            log.events(),
            [
                SourceMessageEvent::Revised {
                    revision: revision(2),
                },
                SourceMessageEvent::Revised {
                    revision: revision(3),
                },
                SourceMessageEvent::Tombstoned { at: at(1_000) },
            ],
            "a deletion must not erase what was already recorded"
        );
        // The coordinates survive the deletion too.
        assert_eq!(log.coordinates().message(), "msg-1");
        assert_eq!(log.coordinates().locale(), Some("en-GB"));
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

        // Walk the whole tree, not just its top level. A scan that reads only
        // src/*.rs is defeated by adding src/teams/mod.rs, which is exactly
        // the shape a platform package would arrive in.
        fn rust_sources(directory: &std::path::Path, found: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(directory).expect("readable directory") {
                let path = entry.expect("directory entry").path();
                if path.is_dir() {
                    rust_sources(&path, found);
                } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
                    found.push(path);
                }
            }
        }
        let mut sources = Vec::new();
        rust_sources(&source_dir, &mut sources);

        let mut scanned = 0_usize;
        let mut findings: Vec<String> = Vec::new();
        for path in sources {
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
        // Every field of an intent is a count, a flag, a revision, a bounded
        // event identity or parsed wording, and the only constructor takes a
        // durable event, so there is nowhere on the type to put a body.
        let event = DurableEvent::record(
            "evt-1",
            revision(1),
            EventOutcome::Finished {
                summary: phrase("done"),
                succeeded: true,
            },
        )
        .expect("durable event");
        let intent = RenderIntent::derived_from(&event);
        assert_eq!(intent.kind(), "terminal");
        assert_eq!(intent.source_event(), "evt-1");
        assert!(
            IntentPhrase::parse("<AdaptiveCard><TextBlock>done</TextBlock></AdaptiveCard>")
                .is_err(),
            "an Adaptive Card body is not wording"
        );
    }
}

mod conformance_obligations {
    use super::*;

    /// Not a row of the check table; the objective's last bullet.
    #[test]
    fn the_obligations_are_a_checkable_list_including_restart_resumption() {
        assert_eq!(ConformanceObligation::ALL.len(), 9);

        let mut spellings: Vec<&str> = ConformanceObligation::ALL
            .iter()
            .map(|obligation| obligation.as_str())
            .collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total, "two obligations share a spelling");

        for obligation in ConformanceObligation::ALL {
            assert!(
                !obligation.description().is_empty(),
                "{} is unjudgeable without a description",
                obligation.as_str()
            );
        }

        let resumption = ConformanceObligation::ResumeWithoutReplayingExternalEffects;
        assert!(ConformanceObligation::ALL.contains(&resumption));
        assert!(resumption.description().contains("restart"));
    }
}
