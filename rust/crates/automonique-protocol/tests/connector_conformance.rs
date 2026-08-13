// SPDX-License-Identifier: Elastic-2.0

//! R13-01 verification: the generic connector descriptor and conformance shape.
//!
//! The two real connectors live in `automonique-transports`, which
//! `automonique-protocol` cannot import. Every literal this suite pins is
//! reproduced from that crate and named where it is pinned, so a rename there
//! fails an assertion here rather than drifting into a second authority.

use automonique_protocol::connector::ConformanceObligation;
use automonique_protocol::connector_conformance::{
    AckDiscipline, AckDisciplineKind, ActorPolicy, CONNECTOR_CONFORMANCE_SCHEMA_V1, CaseInput,
    ConformanceCase, ConformanceError, ConnectorConformanceSuite, ConnectorDescriptor,
    ConnectorKind, DedupIdentity, DescriptorParts, DispositionDeclaration, DispositionOutcome,
    KEY_SEPARATOR, KeySegment, MAX_CONFORMANCE_CASES, MAX_CONFORMANCE_INPUT_BYTES,
    MAX_CONNECTOR_IDENTIFIER_BYTES, MAX_INGRESS_BATCH, MAX_KEY_SEGMENTS, MAX_PRINCIPAL_COORDINATES,
    MAX_PRINCIPALS_PER_CONNECTOR, MAX_REDELIVERY_ATTEMPTS, PLANNED_ACK_DISCIPLINES,
    PLANNED_CONNECTOR_KINDS, SafeName,
};
use automonique_protocol::primitives::Revision;

fn name(value: &str) -> SafeName {
    SafeName::parse(value, "test_name").expect("separator-safe name")
}

fn field(value: &str) -> KeySegment {
    KeySegment::field(value).expect("separator-safe field")
}

fn admitted() -> DispositionDeclaration {
    DispositionDeclaration::declare(DispositionOutcome::Admitted, true).expect("admitted")
}

fn denied() -> DispositionDeclaration {
    DispositionDeclaration::declare(DispositionOutcome::Denied, false).expect("denied")
}

fn allowlist() -> ActorPolicy {
    ActorPolicy::exact_allowlist([name("chat"), name("actor")], 8).expect("exact allowlist")
}

fn parts() -> DescriptorParts {
    DescriptorParts {
        kind: ConnectorKind::Telegram,
        ack: AckDiscipline::offset_cursor("update_id", 100).expect("offset cursor"),
        dedup: DedupIdentity::new([field("bot"), field("update_id")]).expect("dedup identity"),
        dispositions: vec![admitted(), denied()],
        actors: allowlist(),
    }
}

fn descriptor() -> ConnectorDescriptor {
    ConnectorDescriptor::declare(parts()).expect("valid descriptor")
}

fn carried(kind: ConnectorKind) -> ConnectorDescriptor {
    ConnectorDescriptor::carried_for(kind).expect("the carried descriptor is well-formed")
}

fn fixture(body: &str) -> CaseInput {
    CaseInput::fixture(body).expect("bounded fixture")
}

fn case(
    case_name: &str,
    obligation: ConformanceObligation,
    expected: DispositionOutcome,
) -> ConformanceCase {
    ConformanceCase::state(case_name, obligation, fixture("{\"ok\":true}"), expected)
        .expect("valid case")
}

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("non-zero revision")
}

mod connector_kinds {
    use super::*;

    #[test]
    fn the_vocabulary_is_closed_and_round_trips() {
        assert_eq!(ConnectorKind::ALL.len(), 2);
        assert_eq!(ConnectorKind::Slack.as_str(), "slack");
        assert_eq!(ConnectorKind::Telegram.as_str(), "telegram");
        let mut spellings: Vec<&str> = ConnectorKind::ALL
            .iter()
            .map(|kind| kind.as_str())
            .collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total, "two kinds share a spelling");
        for kind in ConnectorKind::ALL {
            assert_eq!(ConnectorKind::from_spelling(kind.as_str()), Some(kind));
            assert_eq!(ConnectorKind::resolve(kind.as_str()), Ok(kind));
            assert_eq!(kind.to_string(), kind.as_str());
        }
        assert_eq!(ConnectorKind::from_spelling("Slack"), None);
        assert_eq!(ConnectorKind::from_spelling(""), None);
    }

    /// The catalog names a long list of connectors. This build has two, and it
    /// says which of the rest are planned rather than never-heard-of.
    #[test]
    fn every_planned_kind_refuses_by_name_and_not_as_unknown() {
        assert_eq!(PLANNED_CONNECTOR_KINDS.len(), 21);
        for planned in PLANNED_CONNECTOR_KINDS {
            assert_eq!(ConnectorKind::from_spelling(planned), None);
            assert_eq!(
                ConnectorKind::resolve(planned),
                Err(ConformanceError::PlannedConnectorKind {
                    name: planned.to_owned(),
                }),
                "{planned} did not refuse as a planned kind"
            );
        }
        // The two refusals are different answers to different questions.
        let planned = ConnectorKind::resolve("teams").expect_err("planned");
        let unknown = ConnectorKind::resolve("pigeon-post").expect_err("unknown");
        assert_eq!(planned.category(), "planned_connector_kind");
        assert_eq!(unknown.category(), "unknown_connector_kind");
        assert_ne!(planned.category(), unknown.category());
        assert!(planned.to_string().contains("teams"));
    }

    #[test]
    fn the_planned_list_is_sorted_unique_and_disjoint_from_the_built_kinds() {
        let mut sorted = PLANNED_CONNECTOR_KINDS;
        sorted.sort_unstable();
        assert_eq!(
            sorted, PLANNED_CONNECTOR_KINDS,
            "a new planned kind must land in sorted order"
        );
        let mut unique = PLANNED_CONNECTOR_KINDS.to_vec();
        unique.dedup();
        assert_eq!(unique.len(), PLANNED_CONNECTOR_KINDS.len());
        for kind in ConnectorKind::ALL {
            assert!(
                !PLANNED_CONNECTOR_KINDS.contains(&kind.as_str()),
                "{kind} is both built and planned"
            );
        }
    }

    #[test]
    fn a_spelling_outside_the_grammar_is_refused_before_it_is_looked_up() {
        assert_eq!(
            ConnectorKind::resolve("").expect_err("empty").category(),
            "field_invalid"
        );
        assert_eq!(
            ConnectorKind::resolve("sla:ck")
                .expect_err("carries the separator")
                .category(),
            "not_separator_safe"
        );
    }
}

mod separator_safe_names {
    use super::*;

    /// `automonique_transports::slack`'s `identifier` rule, reproduced: without
    /// it two distinct triples collide into one deduplication key.
    #[test]
    fn the_key_separator_cannot_appear_in_a_name() {
        assert_eq!(KEY_SEPARATOR, ':');
        assert_eq!(
            SafeName::parse("team:channel", "coordinate").expect_err("separator"),
            ConformanceError::NotSeparatorSafe {
                field: "coordinate",
                character: ':',
            }
        );
    }

    #[test]
    fn a_name_outside_the_ascii_graphic_grammar_is_refused() {
        for (value, character) in [
            ("with space", ' '),
            ("with\ttab", '\t'),
            ("with\nnewline", '\n'),
            ("café", 'é'),
        ] {
            assert_eq!(
                SafeName::parse(value, "coordinate").expect_err("unsafe"),
                ConformanceError::NotSeparatorSafe {
                    field: "coordinate",
                    character,
                },
                "{value} was admitted"
            );
        }
    }

    #[test]
    fn a_name_is_bounded_and_non_empty() {
        assert_eq!(
            SafeName::parse("", "coordinate")
                .expect_err("empty")
                .category(),
            "field_invalid"
        );
        assert_eq!(MAX_CONNECTOR_IDENTIFIER_BYTES, 128);
        let at_bound = "x".repeat(MAX_CONNECTOR_IDENTIFIER_BYTES);
        assert!(SafeName::parse(&at_bound, "coordinate").is_ok());
        let over = "x".repeat(MAX_CONNECTOR_IDENTIFIER_BYTES + 1);
        assert_eq!(
            SafeName::parse(&over, "coordinate")
                .expect_err("too long")
                .category(),
            "field_invalid"
        );
        assert_eq!(name("ts").as_str(), "ts");
        assert_eq!(name("ts").to_string(), "ts");
    }
}

mod dedup_identity {
    use super::*;

    /// A key of fixed words alone is a constant, and a constant key folds every
    /// event of a connector onto one row.
    #[test]
    fn a_constant_dedup_identity_is_refused() {
        let fixed = KeySegment::fixed("update").expect("fixed word");
        assert_eq!(
            DedupIdentity::new([fixed.clone()]).expect_err("constant"),
            ConformanceError::DedupIdentityConstant
        );
        assert_eq!(
            DedupIdentity::new([fixed.clone(), KeySegment::fixed("event").expect("fixed")])
                .expect_err("still constant"),
            ConformanceError::DedupIdentityConstant
        );
        // One field is enough to make it an identity.
        assert!(DedupIdentity::new([fixed, field("update_id")]).is_ok());
    }

    #[test]
    fn an_empty_or_over_long_identity_is_refused() {
        assert_eq!(
            DedupIdentity::new([]).expect_err("empty").category(),
            "field_invalid"
        );
        let over: Vec<KeySegment> = (0..=MAX_KEY_SEGMENTS)
            .map(|index| field(&format!("f{index}")))
            .collect();
        assert_eq!(
            DedupIdentity::new(over).expect_err("too many").category(),
            "field_invalid"
        );
        let at_bound: Vec<KeySegment> = (0..MAX_KEY_SEGMENTS)
            .map(|index| field(&format!("f{index}")))
            .collect();
        assert!(DedupIdentity::new(at_bound).is_ok());
    }

    #[test]
    fn a_repeated_field_is_refused() {
        assert_eq!(
            DedupIdentity::new([field("team"), field("channel"), field("team")])
                .expect_err("repeated"),
            ConformanceError::DuplicateKeyField {
                name: "team".to_owned(),
            }
        );
    }

    #[test]
    fn a_non_separator_safe_field_never_reaches_an_identity() {
        assert_eq!(
            KeySegment::field("te:am")
                .expect_err("separator")
                .category(),
            "not_separator_safe"
        );
        assert_eq!(
            KeySegment::fixed("up date").expect_err("space").category(),
            "not_separator_safe"
        );
    }

    #[test]
    fn a_template_is_content_free_and_deterministic() {
        let identity = DedupIdentity::new([
            field("bot"),
            KeySegment::fixed("update").expect("fixed"),
            field("update_id"),
        ])
        .expect("identity");
        assert_eq!(
            identity.render_template(ConnectorKind::Telegram),
            "telegram:{bot}:update:{update_id}"
        );
        assert_eq!(
            identity.render_template(ConnectorKind::Telegram),
            identity.render_template(ConnectorKind::Telegram)
        );
        assert!(identity.names_field(&name("bot")));
        assert!(
            !identity.names_field(&name("update")),
            "a fixed word is not a field"
        );
        assert!(!identity.names_field(&name("envelope_id")));
        assert_eq!(identity.segments().len(), 3);
    }
}

mod ack_discipline {
    use super::*;

    #[test]
    fn the_discipline_vocabulary_is_closed() {
        assert_eq!(AckDisciplineKind::ALL.len(), 2);
        assert_eq!(AckDisciplineKind::OffsetCursor.as_str(), "offset_cursor");
        assert_eq!(AckDisciplineKind::PerEnvelope.as_str(), "per_envelope");
        for kind in AckDisciplineKind::ALL {
            assert_eq!(AckDisciplineKind::from_spelling(kind.as_str()), Some(kind));
            assert_eq!(AckDisciplineKind::resolve(kind.as_str()), Ok(kind));
        }
        assert_eq!(AckDisciplineKind::from_spelling("offset"), None);
    }

    /// The catalog's signed inbound webhook route is a third discipline nothing
    /// here implements, so it refuses by name rather than being approximated
    /// onto the per-envelope shape.
    #[test]
    fn a_planned_discipline_refuses_by_name_and_not_as_unknown() {
        assert_eq!(PLANNED_ACK_DISCIPLINES.len(), 1);
        for planned in PLANNED_ACK_DISCIPLINES {
            assert_eq!(
                AckDisciplineKind::resolve(planned),
                Err(ConformanceError::PlannedAckDiscipline {
                    name: planned.to_owned(),
                })
            );
        }
        assert_eq!(
            AckDisciplineKind::resolve("carrier_pigeon")
                .expect_err("unknown")
                .category(),
            "unknown_ack_discipline"
        );
        assert_ne!(
            AckDisciplineKind::resolve("signed_webhook")
                .expect_err("planned")
                .category(),
            AckDisciplineKind::resolve("carrier_pigeon")
                .expect_err("unknown")
                .category()
        );
    }

    #[test]
    fn a_batch_ceiling_is_neither_zero_nor_unbounded() {
        assert_eq!(
            AckDiscipline::offset_cursor("update_id", 0).expect_err("zero"),
            ConformanceError::ZeroCeiling { field: "max_batch" }
        );
        assert_eq!(
            AckDiscipline::offset_cursor("update_id", MAX_INGRESS_BATCH + 1)
                .expect_err("unbounded"),
            ConformanceError::UnboundedDeclaration {
                field: "max_batch",
                ceiling: u64::from(MAX_INGRESS_BATCH),
                declared: u64::from(MAX_INGRESS_BATCH + 1),
            }
        );
        assert!(AckDiscipline::offset_cursor("update_id", MAX_INGRESS_BATCH).is_ok());
        assert_eq!(
            AckDiscipline::offset_cursor("update_id", u32::MAX)
                .expect_err("unbounded")
                .category(),
            "unbounded_declaration"
        );
    }

    #[test]
    fn a_redelivery_ceiling_is_bounded_and_a_malformed_ack_key_is_refused() {
        assert_eq!(
            AckDiscipline::per_envelope("envelope_id", MAX_REDELIVERY_ATTEMPTS + 1)
                .expect_err("unbounded")
                .category(),
            "unbounded_declaration"
        );
        assert_eq!(
            AckDiscipline::per_envelope("envelope:id", 3)
                .expect_err("separator in the ack key")
                .category(),
            "not_separator_safe"
        );
        assert_eq!(
            AckDiscipline::per_envelope("", 3)
                .expect_err("empty ack key")
                .category(),
            "field_invalid"
        );
        assert_eq!(
            AckDiscipline::offset_cursor("update:id", 10)
                .expect_err("separator in the cursor")
                .category(),
            "not_separator_safe"
        );
    }

    #[test]
    fn only_a_per_envelope_discipline_has_an_acknowledgement_key() {
        let per_envelope = AckDiscipline::per_envelope("envelope_id", 16).expect("valid");
        assert_eq!(per_envelope.kind(), AckDisciplineKind::PerEnvelope);
        assert_eq!(
            per_envelope.ack_key().map(SafeName::as_str),
            Some("envelope_id")
        );
        let offset = AckDiscipline::offset_cursor("update_id", 100).expect("valid");
        assert_eq!(offset.kind(), AckDisciplineKind::OffsetCursor);
        assert_eq!(offset.ack_key(), None);
    }
}

mod disposition_vocabulary {
    use super::*;

    #[test]
    fn the_vocabulary_is_closed_and_round_trips() {
        assert_eq!(DispositionOutcome::ALL.len(), 5);
        let mut spellings: Vec<&str> = DispositionOutcome::ALL
            .iter()
            .map(|outcome| outcome.as_str())
            .collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total, "two outcomes share a spelling");
        for outcome in DispositionOutcome::ALL {
            assert_eq!(
                DispositionOutcome::from_spelling(outcome.as_str()),
                Some(outcome)
            );
            assert_eq!(DispositionOutcome::resolve(outcome.as_str()), Ok(outcome));
        }
        assert_eq!(
            DispositionOutcome::resolve("exploded").expect_err("outside"),
            ConformanceError::UnknownDisposition {
                name: "exploded".to_owned(),
            }
        );
    }

    /// Both real connectors set their content field only on an admitted
    /// disposition, so a denied or ignored record is evidence that something
    /// arrived rather than a copy of it.
    #[test]
    fn only_an_admitted_disposition_may_retain_content() {
        assert!(DispositionOutcome::Admitted.retains_content());
        for outcome in DispositionOutcome::ALL {
            if outcome == DispositionOutcome::Admitted {
                continue;
            }
            assert!(!outcome.retains_content(), "{outcome} retains content");
            assert_eq!(
                DispositionDeclaration::declare(outcome, true).expect_err("content-free"),
                ConformanceError::ContentOnNonAdmittedDisposition {
                    outcome: outcome.as_str(),
                },
                "{outcome} was allowed to retain content"
            );
            assert!(DispositionDeclaration::declare(outcome, false).is_ok());
        }
        let declared = admitted();
        assert!(declared.retains_content());
        assert_eq!(declared.outcome(), DispositionOutcome::Admitted);
    }

    /// Pinned against `automonique_transports::slack::SlackDisposition::
    /// category`, which spells these four exactly this way.
    #[test]
    fn the_qualified_categories_are_pinned_against_the_transports_crate() {
        assert_eq!(
            DispositionOutcome::Admitted.qualified_category(ConnectorKind::Slack),
            "slack_admitted"
        );
        assert_eq!(
            DispositionOutcome::Denied.qualified_category(ConnectorKind::Slack),
            "slack_denied"
        );
        assert_eq!(
            DispositionOutcome::IgnoredUnsupported.qualified_category(ConnectorKind::Slack),
            "slack_ignored_unsupported"
        );
        assert_eq!(
            DispositionOutcome::ConnectionControl.qualified_category(ConnectorKind::Slack),
            "slack_connection_control"
        );
        // The one deliberate divergence: the real connector delegates a refusal
        // to its per-reason category (`slack_invalid_field` and friends), so
        // this spelling names the class and is not a string it ever emits.
        assert_eq!(
            DispositionOutcome::Refused.qualified_category(ConnectorKind::Slack),
            "slack_refused"
        );
        assert_eq!(
            DispositionOutcome::Admitted.qualified_category(ConnectorKind::Telegram),
            "telegram_admitted"
        );
    }
}

mod descriptor_invariants {
    use super::*;

    #[test]
    fn a_connector_that_admits_must_be_able_to_deny() {
        let refused = ConnectorDescriptor::declare(DescriptorParts {
            dispositions: vec![admitted()],
            ..parts()
        });
        assert_eq!(
            refused.expect_err("default-open"),
            ConformanceError::AdmissionWithoutDenial
        );
        // A connector that can only deny or ignore is a coherent
        // notification-only bridge and is not refused.
        assert!(
            ConnectorDescriptor::declare(DescriptorParts {
                dispositions: vec![denied()],
                ..parts()
            })
            .is_ok()
        );
    }

    #[test]
    fn an_empty_or_repeated_disposition_vocabulary_is_refused() {
        assert_eq!(
            ConnectorDescriptor::declare(DescriptorParts {
                dispositions: Vec::new(),
                ..parts()
            })
            .expect_err("empty")
            .category(),
            "field_invalid"
        );
        assert_eq!(
            ConnectorDescriptor::declare(DescriptorParts {
                dispositions: vec![admitted(), denied(), denied()],
                ..parts()
            })
            .expect_err("repeated"),
            ConformanceError::DuplicateDisposition { outcome: "denied" }
        );
    }

    /// A per-delivery key is minted afresh for every redelivery of the same
    /// event, so a dedup identity naming it counts one event as many. An offset
    /// cursor is the platform's own per-event identity, and the real Telegram
    /// key is built from it — the asymmetry is the point.
    #[test]
    fn the_acknowledgement_key_cannot_be_the_event_identity() {
        let refused = ConnectorDescriptor::declare(DescriptorParts {
            kind: ConnectorKind::Slack,
            ack: AckDiscipline::per_envelope("envelope_id", 16).expect("ack"),
            dedup: DedupIdentity::new([field("team"), field("envelope_id")]).expect("identity"),
            ..parts()
        });
        assert_eq!(
            refused.expect_err("per-delivery key"),
            ConformanceError::AckKeyInDedupIdentity {
                field: "envelope_id".to_owned(),
            }
        );
        // The same field name under an offset cursor is admitted, because a
        // cursor is not minted per delivery.
        assert!(
            ConnectorDescriptor::declare(DescriptorParts {
                ack: AckDiscipline::offset_cursor("envelope_id", 100).expect("ack"),
                dedup: DedupIdentity::new([field("team"), field("envelope_id")]).expect("identity"),
                ..parts()
            })
            .is_ok()
        );
    }

    /// There is no constructor for an open policy, so the only refusals left
    /// are the bounds on the exact allowlist.
    #[test]
    fn an_actor_policy_is_an_exact_bounded_allowlist() {
        assert_eq!(
            ActorPolicy::exact_allowlist([], 8)
                .expect_err("no coordinates")
                .category(),
            "field_invalid"
        );
        assert_eq!(
            ActorPolicy::exact_allowlist([name("team"), name("team")], 8).expect_err("repeated"),
            ConformanceError::DuplicateKeyField {
                name: "team".to_owned(),
            }
        );
        assert_eq!(
            ActorPolicy::exact_allowlist([name("team")], 0).expect_err("admits nothing"),
            ConformanceError::ZeroCeiling {
                field: "max_principals",
            }
        );
        assert_eq!(
            ActorPolicy::exact_allowlist([name("team")], MAX_PRINCIPALS_PER_CONNECTOR + 1)
                .expect_err("unbounded")
                .category(),
            "unbounded_declaration"
        );
        let over: Vec<SafeName> = (0..=MAX_PRINCIPAL_COORDINATES)
            .map(|index| name(&format!("c{index}")))
            .collect();
        assert_eq!(
            ActorPolicy::exact_allowlist(over, 8)
                .expect_err("too many coordinates")
                .category(),
            "field_invalid"
        );
    }

    #[test]
    fn a_declared_descriptor_hands_back_everything_it_was_given() {
        let declared = descriptor();
        assert_eq!(declared.kind(), ConnectorKind::Telegram);
        assert_eq!(declared.ack().kind(), AckDisciplineKind::OffsetCursor);
        assert_eq!(declared.dispositions().len(), 2);
        assert!(declared.produces(DispositionOutcome::Admitted));
        assert!(!declared.produces(DispositionOutcome::ConnectionControl));
        assert_eq!(declared.actors().max_principals(), 8);
        assert_eq!(declared.actors().coordinates().len(), 2);
        assert_eq!(declared.source_key_template(), "telegram:{bot}:{update_id}");
        assert_eq!(declared.dedup().segments().len(), 2);
    }
}

mod carried_spellings {
    use super::*;

    /// `SlackIngress::source_key` is
    /// `format!("slack:{app_id}:{team}:{channel}:{ts}")` and
    /// `TelegramIngress::source_key` is
    /// `format!("telegram:{bot_id}:update:{update_id}")`. Both templates are
    /// reproduced here; a rename on either side fails this assertion.
    #[test]
    fn the_source_key_templates_match_the_real_connectors() {
        assert_eq!(
            carried(ConnectorKind::Slack).source_key_template(),
            "slack:{app}:{team}:{channel}:{ts}"
        );
        assert_eq!(
            carried(ConnectorKind::Telegram).source_key_template(),
            "telegram:{bot}:update:{update_id}"
        );
        for kind in ConnectorKind::ALL {
            assert!(
                carried(kind)
                    .source_key_template()
                    .starts_with(&format!("{kind}{KEY_SEPARATOR}")),
                "{kind} does not open its own key"
            );
        }
    }

    /// Telegram advances a monotonic `update_id` offset bounded by
    /// `MAX_TELEGRAM_UPDATES` (100); Slack acknowledges one `envelope_id` per
    /// delivery and documents redeliveries up to `MAX_SLACK_RETRY_ATTEMPT` (16).
    #[test]
    fn the_acknowledgement_disciplines_match_the_real_connectors() {
        match carried(ConnectorKind::Telegram).ack() {
            AckDiscipline::OffsetCursor { cursor, max_batch } => {
                assert_eq!(cursor.as_str(), "update_id");
                assert_eq!(*max_batch, 100, "MAX_TELEGRAM_UPDATES");
            }
            AckDiscipline::PerEnvelope { .. } => panic!("telegram is offset-based"),
        }
        match carried(ConnectorKind::Slack).ack() {
            AckDiscipline::PerEnvelope {
                ack_key,
                max_redelivery_attempts,
            } => {
                assert_eq!(ack_key.as_str(), "envelope_id");
                assert_eq!(*max_redelivery_attempts, 16, "MAX_SLACK_RETRY_ATTEMPT");
            }
            AckDiscipline::OffsetCursor { .. } => panic!("slack is envelope-based"),
        }
    }

    /// The real Slack module excludes `envelope_id` from its deduplication key
    /// because Slack mints a fresh one per delivery attempt.
    #[test]
    fn the_slack_acknowledgement_key_is_absent_from_its_dedup_identity() {
        let slack = carried(ConnectorKind::Slack);
        let ack_key = slack
            .ack()
            .ack_key()
            .expect("slack acknowledges per envelope")
            .clone();
        assert!(!slack.dedup().names_field(&ack_key));
    }

    /// A Slack principal is `(team, channel, user)` because channel and user
    /// IDs are unique only within a workspace; a Telegram principal is
    /// `(chat, actor)`. Both allowlists are bounded by `MAX_POLICY_ENTRIES`.
    #[test]
    fn the_principal_coordinates_match_the_real_connectors() {
        let slack_descriptor = carried(ConnectorKind::Slack);
        let slack: Vec<&str> = slack_descriptor
            .actors()
            .coordinates()
            .iter()
            .map(SafeName::as_str)
            .collect();
        assert_eq!(slack, ["team", "channel", "user"]);
        let telegram_descriptor = carried(ConnectorKind::Telegram);
        let telegram: Vec<&str> = telegram_descriptor
            .actors()
            .coordinates()
            .iter()
            .map(SafeName::as_str)
            .collect();
        assert_eq!(telegram, ["chat", "actor"]);
        assert_eq!(MAX_PRINCIPALS_PER_CONNECTOR, 1_024, "MAX_POLICY_ENTRIES");
        for kind in ConnectorKind::ALL {
            assert_eq!(
                carried(kind).actors().max_principals(),
                MAX_PRINCIPALS_PER_CONNECTOR
            );
        }
    }

    /// Slack refuses a frame while keeping its ack key and sees `hello` and
    /// `disconnect` control frames. A Telegram poll response has neither: a
    /// malformed member poisons the whole batch as a `TelegramError`, because
    /// the batch shares one commit point.
    #[test]
    fn the_disposition_vocabularies_match_the_real_connectors() {
        let slack = carried(ConnectorKind::Slack);
        for outcome in DispositionOutcome::ALL {
            assert!(slack.produces(outcome), "slack cannot reach {outcome}");
        }
        let telegram = carried(ConnectorKind::Telegram);
        assert!(telegram.produces(DispositionOutcome::Admitted));
        assert!(telegram.produces(DispositionOutcome::Denied));
        assert!(telegram.produces(DispositionOutcome::IgnoredUnsupported));
        assert!(
            !telegram.produces(DispositionOutcome::Refused),
            "a poisoned batch is an error, not a disposition"
        );
        assert!(!telegram.produces(DispositionOutcome::ConnectionControl));
        // Content on the admitted disposition only, in both.
        for kind in ConnectorKind::ALL {
            for declaration in carried(kind).dispositions() {
                assert_eq!(
                    declaration.retains_content(),
                    declaration.outcome() == DispositionOutcome::Admitted,
                    "{kind} {} retains the wrong thing",
                    declaration.outcome()
                );
            }
        }
    }

    #[test]
    fn the_carried_bounds_match_the_transports_constants() {
        assert_eq!(
            MAX_CONNECTOR_IDENTIFIER_BYTES, 128,
            "MAX_SLACK_IDENTIFIER_BYTES"
        );
        assert_eq!(KEY_SEPARATOR, ':', "the slack identifier exclusion");
        // Compile-time assertions: these compare a const against a literal, so
        // a runtime `assert!` would be a constant-value assertion. As
        // `const _` they fail the build if a carried ceiling ever stops
        // admitting the real transport maximum.
        const _: () = assert!(
            MAX_INGRESS_BATCH >= 100,
            "the ceiling must admit MAX_TELEGRAM_UPDATES"
        );
        const _: () = assert!(
            MAX_REDELIVERY_ATTEMPTS >= 16,
            "the ceiling must admit MAX_SLACK_RETRY_ATTEMPT"
        );
    }
}

mod conformance_suites {
    use super::*;

    fn suite(cases: Vec<ConformanceCase>) -> ConnectorConformanceSuite {
        ConnectorConformanceSuite::declare(carried(ConnectorKind::Telegram), revision(3), cases)
            .expect("valid suite")
    }

    fn three_cases() -> Vec<ConformanceCase> {
        vec![
            case(
                "admits_an_allowlisted_chat",
                ConformanceObligation::DeriveStableSourceKeys,
                DispositionOutcome::Admitted,
            ),
            case(
                "denies_an_unlisted_chat",
                ConformanceObligation::ReportUnlinkedIdentity,
                DispositionOutcome::Denied,
            ),
            case(
                "ignores_an_unsupported_update",
                ConformanceObligation::ResolveInstallationOrRequire,
                DispositionOutcome::IgnoredUnsupported,
            ),
        ]
    }

    /// The closed vocabulary makes an unspellable expectation impossible; what
    /// is left to refuse is an expectation this connector never declared.
    #[test]
    fn an_expectation_outside_the_declared_vocabulary_is_refused() {
        let refused = ConnectorConformanceSuite::declare(
            carried(ConnectorKind::Telegram),
            revision(1),
            [case(
                "expects_a_control_frame",
                ConformanceObligation::DeriveStableSourceKeys,
                DispositionOutcome::ConnectionControl,
            )],
        );
        assert_eq!(
            refused.expect_err("telegram has no control frames"),
            ConformanceError::ExpectationOutsideVocabulary {
                kind: "telegram",
                outcome: "connection_control",
            }
        );
        // The same case is inside the Slack vocabulary.
        assert!(
            ConnectorConformanceSuite::declare(
                carried(ConnectorKind::Slack),
                revision(1),
                [case(
                    "expects_a_control_frame",
                    ConformanceObligation::DeriveStableSourceKeys,
                    DispositionOutcome::ConnectionControl,
                )],
            )
            .is_ok()
        );
    }

    #[test]
    fn a_corpus_over_the_bound_is_refused() {
        let over: Vec<ConformanceCase> = (0..=MAX_CONFORMANCE_CASES)
            .map(|index| {
                case(
                    &format!("case_{index}"),
                    ConformanceObligation::DeriveStableSourceKeys,
                    DispositionOutcome::Admitted,
                )
            })
            .collect();
        assert_eq!(
            ConnectorConformanceSuite::declare(
                carried(ConnectorKind::Telegram),
                revision(1),
                over,
            )
            .expect_err("over the bound"),
            ConformanceError::CorpusTooLarge {
                max_cases: MAX_CONFORMANCE_CASES,
                actual_cases: MAX_CONFORMANCE_CASES + 1,
            }
        );
        let at_bound: Vec<ConformanceCase> = (0..MAX_CONFORMANCE_CASES)
            .map(|index| {
                case(
                    &format!("case_{index}"),
                    ConformanceObligation::DeriveStableSourceKeys,
                    DispositionOutcome::Admitted,
                )
            })
            .collect();
        assert_eq!(suite(at_bound).cases().len(), MAX_CONFORMANCE_CASES);
    }

    #[test]
    fn an_empty_corpus_and_a_repeated_case_name_are_refused() {
        assert_eq!(
            ConnectorConformanceSuite::declare(carried(ConnectorKind::Telegram), revision(1), [],)
                .expect_err("empty")
                .category(),
            "field_invalid"
        );
        assert_eq!(
            ConnectorConformanceSuite::declare(
                carried(ConnectorKind::Telegram),
                revision(1),
                [
                    case(
                        "same_name",
                        ConformanceObligation::DeriveStableSourceKeys,
                        DispositionOutcome::Admitted,
                    ),
                    case(
                        "same_name",
                        ConformanceObligation::ReportUnlinkedIdentity,
                        DispositionOutcome::Denied,
                    ),
                ],
            )
            .expect_err("repeated"),
            ConformanceError::DuplicateCaseName {
                name: "same_name".to_owned(),
            }
        );
    }

    #[test]
    fn a_case_carries_a_bounded_fixture_and_a_safe_name() {
        assert_eq!(
            CaseInput::fixture("").expect_err("empty").category(),
            "field_invalid"
        );
        assert_eq!(
            CaseInput::fixture(&"x".repeat(MAX_CONFORMANCE_INPUT_BYTES + 1))
                .expect_err("too long")
                .category(),
            "field_invalid"
        );
        assert!(CaseInput::fixture(&"x".repeat(MAX_CONFORMANCE_INPUT_BYTES)).is_ok());
        assert_eq!(
            CaseInput::fixture("a\u{0}b")
                .expect_err("control character")
                .category(),
            "field_invalid"
        );
        // A checked-in frame may be pretty-printed.
        assert_eq!(
            CaseInput::fixture("{\n\t\"ok\": true\n}")
                .expect("pretty-printed")
                .as_str(),
            "{\n\t\"ok\": true\n}"
        );
        assert_eq!(
            ConformanceCase::state(
                "bad:name",
                ConformanceObligation::DeriveStableSourceKeys,
                fixture("{}"),
                DispositionOutcome::Admitted,
            )
            .expect_err("unsafe name")
            .category(),
            "not_separator_safe"
        );
    }

    /// A partial run must not read as a pass, so the obligations no case
    /// exercises are named.
    #[test]
    fn the_obligations_no_case_exercises_are_named() {
        let declared = suite(three_cases());
        assert_eq!(declared.covered_obligations().len(), 3);
        let missing = declared.missing_obligations();
        assert_eq!(
            missing.len(),
            ConformanceObligation::ALL.len() - 3,
            "coverage and gaps must account for every obligation"
        );
        assert!(missing.contains(&ConformanceObligation::ResumeWithoutReplayingExternalEffects));
        assert!(!missing.contains(&ConformanceObligation::DeriveStableSourceKeys));
        assert!(!declared.is_complete());

        let every: Vec<ConformanceCase> = ConformanceObligation::ALL
            .into_iter()
            .enumerate()
            .map(|(index, obligation)| {
                case(
                    &format!("case_{index}"),
                    obligation,
                    DispositionOutcome::Admitted,
                )
            })
            .collect();
        let complete = suite(every);
        assert!(complete.is_complete());
        assert!(complete.missing_obligations().is_empty());
        assert_eq!(
            complete.covered_obligations().len(),
            ConformanceObligation::ALL.len()
        );
    }

    #[test]
    fn a_rendered_suite_is_deterministic_and_order_independent() {
        let forwards = suite(three_cases());
        let mut backwards_cases = three_cases();
        backwards_cases.reverse();
        let backwards = suite(backwards_cases);
        assert_eq!(forwards.render(), forwards.render());
        assert_eq!(
            forwards.render(),
            backwards.render(),
            "insertion order reached the rendering"
        );
        assert_eq!(forwards, backwards, "insertion order reached the value");
        assert_eq!(
            forwards.cases()[0].name().as_str(),
            "admits_an_allowlisted_chat"
        );
    }

    #[test]
    fn a_rendering_carries_the_shape_and_never_the_fixture() {
        let secret = "{\"message\":{\"text\":\"launch codes\"}}";
        let declared = ConnectorConformanceSuite::declare(
            carried(ConnectorKind::Telegram),
            revision(7),
            [ConformanceCase::state(
                "admits_an_allowlisted_chat",
                ConformanceObligation::DeriveStableSourceKeys,
                CaseInput::fixture(secret).expect("fixture"),
                DispositionOutcome::Admitted,
            )
            .expect("case")],
        )
        .expect("suite");

        let rendered = declared.render();
        assert!(
            !rendered.contains("launch codes"),
            "a fixture body reached the rendered suite"
        );
        assert!(rendered.starts_with(CONNECTOR_CONFORMANCE_SCHEMA_V1));
        assert_eq!(declared.schema(), "automonique.connector-conformance/v1");
        assert!(rendered.contains("connector\ttelegram\n"));
        assert!(rendered.contains("revision\t7\n"));
        assert!(rendered.contains("source_key\ttelegram:{bot}:update:{update_id}\n"));
        assert!(rendered.contains("ack\toffset_cursor\n"));
        assert!(rendered.contains("principal_coordinate\tchat\n"));
        assert!(rendered.contains("disposition\ttelegram_admitted\tretains_content\n"));
        assert!(rendered.contains("disposition\ttelegram_denied\tcontent_free\n"));
        assert!(!rendered.contains("telegram_connection_control"));
        assert!(
            rendered.contains(
                "case\tadmits_an_allowlisted_chat\tderive_stable_source_keys\tadmitted\n"
            )
        );
        assert!(
            rendered.contains("missing_obligation\tresume_without_replaying_external_effects\n")
        );
        assert_eq!(declared.revision(), revision(7));
        assert_eq!(declared.descriptor().kind(), ConnectorKind::Telegram);
        assert_eq!(declared.cases()[0].input().as_str(), secret);
        assert_eq!(
            declared.cases()[0].obligation(),
            ConformanceObligation::DeriveStableSourceKeys
        );
        assert_eq!(declared.cases()[0].expected(), DispositionOutcome::Admitted);
    }
}
