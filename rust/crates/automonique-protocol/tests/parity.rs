// SPDX-License-Identifier: Elastic-2.0

//! Intended-action envelopes, the comparison vocabulary, and the weighted score.
//!
//! Three properties matter more than the rest and are tested first: an envelope
//! round-trips through canonical bytes exactly, a document this build does not
//! serve is refused rather than best-effort parsed, and deliberate silence is a
//! difference rather than an agreement.
//!
//! The vocabulary tests read `tools/oracle/fields.json` and
//! `tools/oracle/vocabulary.py` off disk. That is deliberate: the point of
//! reusing the oracle's closed vocabulary is that a live-traffic verdict and a
//! future archive-differential verdict are the same shape, and a Rust enum that
//! merely *looked* like the registry when it was written would drift silently.

use std::path::{Path, PathBuf};

use automonique_protocol::parity::{
    ActionKind, BAND_BLOCK_MAX, BAND_CAUTION_MAX, BAND_SHADOW_READY_MAX, Band, Category,
    Classification, Comparison, ComparisonField, ComparisonVerdict, DeviationEntry,
    DeviationReason, DeviationRegistry, INTENDED_ACTION_SCHEMA_V1, IntendedAction,
    IntendedActionEnvelope, MASKED_PLACEHOLDER, MAX_ACTION_ID_BYTES, MAX_SCOPE_BYTES,
    MAX_SOURCE_KEY_BYTES, ParityEngine, ParityError, ParityScore, Relation, ScoredComparison,
    WEIGHT_SCALE, compare,
};

fn repository_root() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for _ in 0..3 {
        path = path
            .parent()
            .map(Path::to_path_buf)
            .expect("workspace ancestor");
    }
    path
}

fn thread_reply(text: &str) -> IntendedAction {
    IntendedAction::new(
        ActionKind::SlackThreadReply,
        vec![
            String::from("C0CHANNEL"),
            String::from("1700000000.000100"),
            text.to_owned(),
        ],
    )
    .expect("valid thread reply")
}

fn envelope(engine: ParityEngine, action: IntendedAction) -> IntendedActionEnvelope {
    IntendedActionEnvelope::new(
        "slack-ticket-routing",
        "slack:T0TEAM:event:Ev0000000001",
        engine,
        0,
        action,
        1_700_000_000_000,
    )
    .expect("valid envelope")
}

mod envelope_documents {
    use super::*;

    #[test]
    fn round_trips_through_canonical_bytes() {
        let original = envelope(ParityEngine::ShadowCandidate, thread_reply("hello there"));
        let bytes = original.to_canonical_bytes();
        let decoded = IntendedActionEnvelope::from_canonical_bytes(&bytes).expect("decodes");
        assert_eq!(decoded, original);
        assert_eq!(decoded.to_canonical_bytes(), bytes);
    }

    #[test]
    fn every_action_kind_round_trips() {
        for kind in ActionKind::ALL {
            let values: Vec<String> = kind
                .fields()
                .iter()
                .enumerate()
                .map(|(index, field)| format!("{}-{index}", field.name()))
                .collect();
            let action = IntendedAction::new(kind, values).expect("valid action");
            let original = envelope(ParityEngine::LegacyObserved, action);
            let bytes = original.to_canonical_bytes();
            assert_eq!(
                IntendedActionEnvelope::from_canonical_bytes(&bytes).expect("decodes"),
                original,
                "{} did not round-trip",
                kind.as_str()
            );
        }
    }

    #[test]
    fn content_digest_is_over_the_canonical_bytes() {
        let recorded = envelope(ParityEngine::ShadowCandidate, thread_reply("hello"));
        assert_eq!(
            recorded.content_digest(),
            automonique_protocol::digest::Sha256::digest(&recorded.to_canonical_bytes())
        );
    }

    #[test]
    fn digest_ignores_member_order_but_not_content() {
        let first = envelope(ParityEngine::ShadowCandidate, thread_reply("hello"));
        let second = envelope(ParityEngine::ShadowCandidate, thread_reply("hello"));
        assert_eq!(first.content_digest(), second.content_digest());
        let third = envelope(ParityEngine::ShadowCandidate, thread_reply("hello!"));
        assert_ne!(first.content_digest(), third.content_digest());
    }

    #[test]
    fn refuses_a_schema_this_build_does_not_serve() {
        let bytes = envelope(ParityEngine::ShadowCandidate, thread_reply("hello"))
            .to_canonical_bytes()
            .to_vec();
        let text = String::from_utf8(bytes).expect("utf-8");
        let foreign = text.replace(INTENDED_ACTION_SCHEMA_V1, "automonique.intended-action/v2");
        assert_eq!(
            IntendedActionEnvelope::from_canonical_bytes(foreign.as_bytes()),
            Err(ParityError::UnknownSchema)
        );
    }

    #[test]
    fn refuses_an_unknown_engine_rather_than_defaulting() {
        let bytes = envelope(ParityEngine::ShadowCandidate, thread_reply("hello"))
            .to_canonical_bytes()
            .to_vec();
        let text = String::from_utf8(bytes).expect("utf-8");
        let foreign = text.replace("shadow-candidate", "shadow-candidat");
        let error =
            IntendedActionEnvelope::from_canonical_bytes(foreign.as_bytes()).expect_err("refused");
        assert_eq!(error.category(), "codec");
    }

    #[test]
    fn refuses_an_unknown_action_kind_rather_than_defaulting() {
        let bytes = envelope(ParityEngine::ShadowCandidate, thread_reply("hello"))
            .to_canonical_bytes()
            .to_vec();
        let text = String::from_utf8(bytes).expect("utf-8");
        let foreign = text.replace("slack-thread-reply", "slack-thread-repl");
        let error =
            IntendedActionEnvelope::from_canonical_bytes(foreign.as_bytes()).expect_err("refused");
        assert_eq!(error.category(), "codec");
    }

    #[test]
    fn refuses_non_canonical_json() {
        let bytes = envelope(ParityEngine::ShadowCandidate, thread_reply("hello"))
            .to_canonical_bytes()
            .to_vec();
        let text = String::from_utf8(bytes).expect("utf-8");
        let spaced = text.replace("\":", "\" :");
        let error =
            IntendedActionEnvelope::from_canonical_bytes(spaced.as_bytes()).expect_err("refused");
        assert_eq!(error.category(), "codec");
    }

    #[test]
    fn refuses_an_extra_member() {
        let bytes = envelope(ParityEngine::ShadowCandidate, thread_reply("hello"))
            .to_canonical_bytes()
            .to_vec();
        let text = String::from_utf8(bytes).expect("utf-8");
        let widened = text.replacen('{', "{\"aaa\":1,", 1);
        assert_eq!(
            IntendedActionEnvelope::from_canonical_bytes(widened.as_bytes()),
            Err(ParityError::InvalidBody)
        );
    }

    #[test]
    fn refuses_a_missing_member() {
        let bytes = envelope(ParityEngine::ShadowCandidate, thread_reply("hello"))
            .to_canonical_bytes()
            .to_vec();
        let text = String::from_utf8(bytes).expect("utf-8");
        let narrowed = text.replace(",\"sequence\":0", "");
        let error =
            IntendedActionEnvelope::from_canonical_bytes(narrowed.as_bytes()).expect_err("refused");
        assert!(matches!(
            error,
            ParityError::InvalidBody | ParityError::Codec(_)
        ));
    }

    #[test]
    fn refuses_an_over_long_scope_and_source_key() {
        let long_scope = "s".repeat(MAX_SCOPE_BYTES + 1);
        assert!(matches!(
            IntendedActionEnvelope::new(
                &long_scope,
                "k",
                ParityEngine::ShadowCandidate,
                0,
                thread_reply("hello"),
                0
            ),
            Err(ParityError::Field { field: "scope", .. })
        ));
        let long_key = "k".repeat(MAX_SOURCE_KEY_BYTES + 1);
        assert!(matches!(
            IntendedActionEnvelope::new(
                "scope",
                &long_key,
                ParityEngine::ShadowCandidate,
                0,
                thread_reply("hello"),
                0
            ),
            Err(ParityError::Field {
                field: "source_key",
                ..
            })
        ));
    }

    #[test]
    fn accepts_a_maximal_source_key() {
        let maximal = "k".repeat(MAX_SOURCE_KEY_BYTES);
        assert!(
            IntendedActionEnvelope::new(
                "scope",
                &maximal,
                ParityEngine::ShadowCandidate,
                0,
                thread_reply("hello"),
                0
            )
            .is_ok()
        );
    }

    #[test]
    fn refuses_a_negative_observation_clock() {
        assert!(matches!(
            IntendedActionEnvelope::new(
                "scope",
                "key",
                ParityEngine::ShadowCandidate,
                0,
                thread_reply("hello"),
                -1
            ),
            Err(ParityError::Field {
                field: "observed_at_ms",
                ..
            })
        ));
    }

    #[test]
    fn refuses_an_action_whose_field_count_is_wrong() {
        assert_eq!(
            IntendedAction::new(ActionKind::SlackChannelPost, vec![String::from("C0")]),
            Err(ParityError::InvalidBody)
        );
    }

    #[test]
    fn identifier_fields_refuse_a_newline_and_text_fields_admit_one() {
        assert!(matches!(
            IntendedAction::new(
                ActionKind::SlackChannelPost,
                vec![String::from("C0\nX"), String::from("body")]
            ),
            Err(ParityError::Field {
                field: "channel",
                ..
            })
        ));
        assert!(
            IntendedAction::new(
                ActionKind::SlackChannelPost,
                vec![String::from("C0"), String::from("first\nsecond")]
            )
            .is_ok()
        );
    }

    #[test]
    fn refuses_an_over_long_identifier_field() {
        let long = "c".repeat(MAX_ACTION_ID_BYTES + 1);
        assert!(matches!(
            IntendedAction::new(
                ActionKind::SlackChannelPost,
                vec![long, String::from("body")]
            ),
            Err(ParityError::Field {
                field: "channel",
                ..
            })
        ));
    }

    #[test]
    fn looks_up_a_field_by_its_declared_name() {
        let action = thread_reply("hello");
        assert_eq!(action.value("channel"), Some("C0CHANNEL"));
        assert_eq!(action.value("nonexistent"), None);
    }
}

mod normalization {
    use super::*;

    #[test]
    fn collapses_whitespace_in_text_fields_only() {
        let action = thread_reply("hello   there\n\nfriend ");
        let normalized = action.normalized();
        assert_eq!(normalized.value("text"), Some("hello there friend"));
        assert_eq!(normalized.value("channel"), Some("C0CHANNEL"));
    }

    #[test]
    fn masks_the_fields_the_registry_approves_as_nondeterministic() {
        let normalized = thread_reply("hello").normalized();
        assert_eq!(normalized.value("parent"), Some(MASKED_PLACEHOLDER));
    }

    #[test]
    fn is_idempotent() {
        let once = thread_reply("hello   there").normalized();
        assert_eq!(once.normalized(), once);
    }

    #[test]
    fn masked_fields_never_produce_a_difference() {
        let shadow = envelope(ParityEngine::ShadowCandidate, thread_reply("hello"));
        let drifted = IntendedAction::new(
            ActionKind::SlackThreadReply,
            vec![
                String::from("C0CHANNEL"),
                String::from("1799999999.999999"),
                String::from("hello"),
            ],
        )
        .expect("valid");
        let legacy = envelope(ParityEngine::LegacyObserved, drifted);
        assert_eq!(
            compare(Some(&shadow), Some(&legacy)).verdict(),
            ComparisonVerdict::Match
        );
    }
}

mod comparison {
    use super::*;

    #[test]
    fn identical_actions_match_with_no_differences() {
        let shadow = envelope(ParityEngine::ShadowCandidate, thread_reply("hello"));
        let legacy = envelope(ParityEngine::LegacyObserved, thread_reply("hello"));
        let comparison = compare(Some(&shadow), Some(&legacy));
        assert_eq!(comparison.verdict(), ComparisonVerdict::Match);
        assert!(comparison.differences().is_empty());
    }

    #[test]
    fn differing_text_is_a_rendered_message_difference() {
        let shadow = envelope(ParityEngine::ShadowCandidate, thread_reply("hello"));
        let legacy = envelope(ParityEngine::LegacyObserved, thread_reply("goodbye"));
        let comparison = compare(Some(&shadow), Some(&legacy));
        assert_eq!(comparison.verdict(), ComparisonVerdict::Mismatch);
        assert_eq!(comparison.differences().len(), 1);
        assert_eq!(
            comparison.differences()[0].field(),
            ComparisonField::RenderedMessage
        );
        assert_eq!(
            comparison.differences()[0].relation(),
            Relation::ValueDiffers
        );
    }

    #[test]
    fn a_silent_shadow_is_a_difference_not_an_agreement() {
        let legacy = envelope(ParityEngine::LegacyObserved, thread_reply("hello"));
        let comparison = compare(None, Some(&legacy));
        assert_eq!(comparison.verdict(), ComparisonVerdict::LegacyOnly);
        assert_eq!(
            comparison.differences()[0].relation(),
            Relation::AbsentInCandidate
        );
    }

    #[test]
    fn a_silent_reference_engine_is_a_difference_too() {
        let shadow = envelope(ParityEngine::ShadowCandidate, thread_reply("hello"));
        let comparison = compare(Some(&shadow), None);
        assert_eq!(comparison.verdict(), ComparisonVerdict::ShadowOnly);
        assert_eq!(
            comparison.differences()[0].relation(),
            Relation::AbsentInReference
        );
    }

    #[test]
    fn an_explicit_no_action_on_both_sides_matches() {
        let reason = IntendedAction::no_action("not-a-configured-channel").expect("valid");
        let shadow = envelope(ParityEngine::ShadowCandidate, reason.clone());
        let legacy = envelope(ParityEngine::LegacyObserved, reason);
        assert_eq!(
            compare(Some(&shadow), Some(&legacy)).verdict(),
            ComparisonVerdict::Match
        );
    }

    #[test]
    fn an_explicit_no_action_against_a_post_is_a_mismatch() {
        let shadow = envelope(
            ParityEngine::ShadowCandidate,
            IntendedAction::no_action("not-a-configured-channel").expect("valid"),
        );
        let legacy = envelope(ParityEngine::LegacyObserved, thread_reply("hello"));
        let comparison = compare(Some(&shadow), Some(&legacy));
        assert_eq!(comparison.verdict(), ComparisonVerdict::Mismatch);
        assert_eq!(
            comparison.differences(),
            &[automonique_protocol::parity::FieldDifference::new(
                ComparisonField::ActionEffect,
                Relation::TypeDiffers
            )]
        );
    }

    #[test]
    fn differing_kinds_do_not_invent_a_field_correspondence() {
        let shadow = envelope(
            ParityEngine::ShadowCandidate,
            IntendedAction::new(
                ActionKind::SupportEmailSend,
                vec![
                    String::from("a1"),
                    String::from("someone@example.invalid"),
                    String::from("subject"),
                    String::from("body"),
                ],
            )
            .expect("valid"),
        );
        let legacy = envelope(ParityEngine::LegacyObserved, thread_reply("hello"));
        assert_eq!(compare(Some(&shadow), Some(&legacy)).differences().len(), 1);
    }

    #[test]
    fn two_absences_are_agreement() {
        assert_eq!(compare(None, None).verdict(), ComparisonVerdict::Match);
    }

    #[test]
    fn comparison_documents_round_trip_to_a_stable_digest() {
        let shadow = envelope(ParityEngine::ShadowCandidate, thread_reply("hello"));
        let legacy = envelope(ParityEngine::LegacyObserved, thread_reply("goodbye"));
        let first = compare(Some(&shadow), Some(&legacy));
        let second = compare(Some(&shadow), Some(&legacy));
        assert_eq!(first.content_digest(), second.content_digest());
        assert!(!first.to_canonical_bytes().is_empty());
    }
}

mod deviation_registry {
    use super::*;

    fn entry(id: &str, field: ComparisonField) -> DeviationEntry {
        DeviationEntry::new(
            id,
            "slack-ticket-routing",
            ActionKind::SlackThreadReply,
            field,
            Relation::ValueDiffers,
            DeviationReason::DeliberateImprovement,
        )
        .expect("valid entry")
    }

    fn mismatch() -> Comparison {
        let shadow = envelope(ParityEngine::ShadowCandidate, thread_reply("hello"));
        let legacy = envelope(ParityEngine::LegacyObserved, thread_reply("goodbye"));
        compare(Some(&shadow), Some(&legacy))
    }

    #[test]
    fn an_unregistered_mismatch_is_always_a_regression() {
        let registry = DeviationRegistry::empty();
        let (classification, ids) = registry.classify(
            "slack-ticket-routing",
            ActionKind::SlackThreadReply,
            &mismatch(),
        );
        assert_eq!(classification, Classification::Regression);
        assert!(ids.is_empty());
    }

    #[test]
    fn a_registered_mismatch_is_a_known_deviation_naming_its_entry() {
        let registry =
            DeviationRegistry::new(vec![entry("dev-0001", ComparisonField::RenderedMessage)])
                .expect("valid registry");
        let (classification, ids) = registry.classify(
            "slack-ticket-routing",
            ActionKind::SlackThreadReply,
            &mismatch(),
        );
        assert_eq!(classification, Classification::KnownDeviation);
        assert_eq!(ids, vec![String::from("dev-0001")]);
    }

    #[test]
    fn a_registration_for_another_scope_does_not_apply() {
        let registry = DeviationRegistry::new(vec![
            DeviationEntry::new(
                "dev-0001",
                "telegram-conversation",
                ActionKind::SlackThreadReply,
                ComparisonField::RenderedMessage,
                Relation::ValueDiffers,
                DeviationReason::BugFix,
            )
            .expect("valid"),
        ])
        .expect("valid registry");
        let (classification, _) = registry.classify(
            "slack-ticket-routing",
            ActionKind::SlackThreadReply,
            &mismatch(),
        );
        assert_eq!(classification, Classification::Regression);
    }

    #[test]
    fn a_partly_explained_mismatch_is_unexplained() {
        let shadow = envelope(ParityEngine::ShadowCandidate, thread_reply("hello"));
        let other = IntendedAction::new(
            ActionKind::SlackThreadReply,
            vec![
                String::from("C0OTHER"),
                String::from("1700000000.000100"),
                String::from("goodbye"),
            ],
        )
        .expect("valid");
        let legacy = envelope(ParityEngine::LegacyObserved, other);
        let comparison = compare(Some(&shadow), Some(&legacy));
        assert_eq!(comparison.differences().len(), 2);
        let registry =
            DeviationRegistry::new(vec![entry("dev-0001", ComparisonField::RenderedMessage)])
                .expect("valid registry");
        let (classification, _) = registry.classify(
            "slack-ticket-routing",
            ActionKind::SlackThreadReply,
            &comparison,
        );
        assert_eq!(classification, Classification::Regression);
    }

    #[test]
    fn an_agreement_classifies_parity_under_any_registry() {
        let shadow = envelope(ParityEngine::ShadowCandidate, thread_reply("hello"));
        let legacy = envelope(ParityEngine::LegacyObserved, thread_reply("hello"));
        let (classification, ids) = DeviationRegistry::empty().classify(
            "slack-ticket-routing",
            ActionKind::SlackThreadReply,
            &compare(Some(&shadow), Some(&legacy)),
        );
        assert_eq!(classification, Classification::Parity);
        assert!(ids.is_empty());
    }

    #[test]
    fn refuses_a_repeated_identifier() {
        let error = DeviationRegistry::new(vec![
            entry("dev-0001", ComparisonField::RenderedMessage),
            entry("dev-0001", ComparisonField::Receipt),
        ])
        .expect_err("refused");
        assert_eq!(error.category(), "duplicate_deviation");
    }

    #[test]
    fn digest_is_independent_of_declaration_order() {
        let first = DeviationRegistry::new(vec![
            entry("dev-0001", ComparisonField::RenderedMessage),
            entry("dev-0002", ComparisonField::Receipt),
        ])
        .expect("valid");
        let second = DeviationRegistry::new(vec![
            entry("dev-0002", ComparisonField::Receipt),
            entry("dev-0001", ComparisonField::RenderedMessage),
        ])
        .expect("valid");
        assert_eq!(first.digest(), second.digest());
    }

    #[test]
    fn an_edit_changes_the_digest_a_decision_pinned() {
        let before = DeviationRegistry::new(vec![entry("dev-0001", ComparisonField::Receipt)])
            .expect("valid");
        let after =
            DeviationRegistry::new(vec![entry("dev-0001", ComparisonField::RenderedMessage)])
                .expect("valid");
        assert_ne!(before.digest(), after.digest());
    }

    #[test]
    fn round_trips_through_canonical_bytes() {
        let registry = DeviationRegistry::new(vec![
            entry("dev-0001", ComparisonField::RenderedMessage),
            entry("dev-0002", ComparisonField::Receipt),
        ])
        .expect("valid");
        let bytes = registry.to_canonical_bytes();
        assert_eq!(
            DeviationRegistry::from_canonical_bytes(&bytes).expect("decodes"),
            registry
        );
    }

    #[test]
    fn refuses_a_registry_schema_this_build_does_not_serve() {
        let bytes = DeviationRegistry::empty().to_canonical_bytes();
        let text = String::from_utf8(bytes).expect("utf-8");
        let foreign = text.replace("parity-deviations/v1", "parity-deviations/v2");
        assert_eq!(
            DeviationRegistry::from_canonical_bytes(foreign.as_bytes()),
            Err(ParityError::UnknownSchema)
        );
    }
}

mod weights_and_bands {
    use super::*;

    #[test]
    fn weights_are_the_plans_weights_in_fixed_point() {
        assert_eq!(Category::Happy.weight(), WEIGHT_SCALE);
        assert_eq!(Category::Error.weight(), 2 * WEIGHT_SCALE);
        assert_eq!(Category::Edge.weight(), 2 * WEIGHT_SCALE);
        assert_eq!(Category::Variety.weight(), 3 * WEIGHT_SCALE / 2);
        assert_eq!(
            Category::ProductionRepresentative.weight(),
            3 * WEIGHT_SCALE
        );
    }

    #[test]
    fn the_one_and_a_half_weight_is_exact_in_integers() {
        assert_eq!(Category::Variety.weight() * 2, 3 * Category::Happy.weight());
    }

    #[test]
    fn band_boundaries_are_pinned_on_both_sides() {
        assert_eq!(Band::for_score(0), Ok(Band::Block));
        assert_eq!(Band::for_score(BAND_BLOCK_MAX), Ok(Band::Block));
        assert_eq!(Band::for_score(BAND_BLOCK_MAX + 1), Ok(Band::Caution));
        assert_eq!(Band::for_score(BAND_CAUTION_MAX), Ok(Band::Caution));
        assert_eq!(Band::for_score(BAND_CAUTION_MAX + 1), Ok(Band::ShadowReady));
        assert_eq!(
            Band::for_score(BAND_SHADOW_READY_MAX),
            Ok(Band::ShadowReady)
        );
        assert_eq!(
            Band::for_score(BAND_SHADOW_READY_MAX + 1),
            Ok(Band::CutoverReady)
        );
        assert_eq!(Band::for_score(100), Ok(Band::CutoverReady));
    }

    #[test]
    fn band_boundaries_are_the_documented_numbers() {
        assert_eq!(BAND_BLOCK_MAX, 30);
        assert_eq!(BAND_CAUTION_MAX, 60);
        assert_eq!(BAND_SHADOW_READY_MAX, 85);
    }

    #[test]
    fn refuses_a_score_above_one_hundred() {
        assert_eq!(Band::for_score(101), Err(ParityError::ScoreUnrepresentable));
    }
}

mod scoring {
    use super::*;

    fn scored(category: Category, classification: Classification) -> ScoredComparison {
        ScoredComparison {
            category,
            classification,
        }
    }

    #[test]
    fn an_empty_corpus_refuses_rather_than_scoring_zero() {
        assert_eq!(ParityScore::compute(&[]), Err(ParityError::EmptyCorpus));
    }

    #[test]
    fn a_wholly_accounted_corpus_scores_one_hundred() {
        let corpus: Vec<ScoredComparison> = Category::ALL
            .into_iter()
            .map(|category| scored(category, Classification::Parity))
            .collect();
        let score = ParityScore::compute(&corpus).expect("scored");
        assert_eq!(score.score(), 100);
        assert_eq!(score.band(), Band::CutoverReady);
    }

    #[test]
    fn a_wholly_unaccounted_corpus_scores_zero_and_blocks() {
        let corpus = vec![scored(Category::Happy, Classification::Regression)];
        let score = ParityScore::compute(&corpus).expect("scored");
        assert_eq!(score.score(), 0);
        assert_eq!(score.band(), Band::Block);
    }

    #[test]
    fn a_known_deviation_counts_towards_the_score() {
        let corpus = vec![scored(Category::Happy, Classification::KnownDeviation)];
        assert_eq!(ParityScore::compute(&corpus).expect("scored").score(), 100);
    }

    #[test]
    fn a_production_representative_regression_costs_three_times_a_happy_one() {
        let happy_regression = ParityScore::compute(&[
            scored(Category::Happy, Classification::Regression),
            scored(Category::Happy, Classification::Parity),
            scored(Category::Happy, Classification::Parity),
            scored(Category::Happy, Classification::Parity),
        ])
        .expect("scored");
        assert_eq!(happy_regression.score(), 75);

        let production_regression = ParityScore::compute(&[
            scored(
                Category::ProductionRepresentative,
                Classification::Regression,
            ),
            scored(Category::Happy, Classification::Parity),
            scored(Category::Happy, Classification::Parity),
            scored(Category::Happy, Classification::Parity),
        ])
        .expect("scored");
        assert_eq!(production_regression.score(), 50);
    }

    #[test]
    fn the_quotient_truncates_so_a_score_never_rounds_into_a_higher_band() {
        // Two of three happy comparisons account: 200/3 is 66.67, and the score
        // is 66 rather than 67. Both land in the same band here; the property
        // being pinned is the direction of the rounding.
        let corpus = vec![
            scored(Category::Happy, Classification::Parity),
            scored(Category::Happy, Classification::Parity),
            scored(Category::Happy, Classification::Regression),
        ];
        assert_eq!(ParityScore::compute(&corpus).expect("scored").score(), 66);
    }

    #[test]
    fn per_category_counts_are_reported() {
        let corpus = vec![
            scored(Category::Happy, Classification::Parity),
            scored(Category::Happy, Classification::Regression),
            scored(Category::Edge, Classification::KnownDeviation),
        ];
        let score = ParityScore::compute(&corpus).expect("scored");
        assert_eq!(score.count(Category::Happy).total, 2);
        assert_eq!(score.count(Category::Happy).accounted, 1);
        assert_eq!(score.count(Category::Edge).total, 1);
        assert_eq!(score.count(Category::Edge).accounted, 1);
        assert_eq!(score.count(Category::Variety).total, 0);
    }

    #[test]
    fn the_variety_weight_is_honoured_without_a_float() {
        // Two variety comparisons weigh three happy ones exactly.
        let corpus = vec![
            scored(Category::Variety, Classification::Parity),
            scored(Category::Variety, Classification::Parity),
            scored(Category::Happy, Classification::Regression),
            scored(Category::Happy, Classification::Regression),
            scored(Category::Happy, Classification::Regression),
        ];
        assert_eq!(ParityScore::compute(&corpus).expect("scored").score(), 50);
    }
}

mod oracle_vocabulary {
    use super::*;

    #[test]
    fn comparison_fields_match_the_registry_member_for_member() {
        let registry = std::fs::read_to_string(repository_root().join("tools/oracle/fields.json"))
            .expect("fields.json is readable");
        let registered: Vec<&str> = registry
            .lines()
            .filter_map(|line| line.trim().strip_prefix("\"id\": \""))
            .filter_map(|rest| rest.strip_suffix("\","))
            .collect();
        let ours: Vec<&str> = ComparisonField::ALL
            .iter()
            .map(|field| field.as_str())
            .collect();
        assert_eq!(
            registered, ours,
            "tools/oracle/fields.json and ComparisonField have drifted apart"
        );
    }

    #[test]
    fn masked_fields_are_the_ones_the_registry_marks_masked() {
        let registry = std::fs::read_to_string(repository_root().join("tools/oracle/fields.json"))
            .expect("fields.json is readable");
        for field in ComparisonField::ALL {
            let block = registry
                .split("\"id\": \"")
                .find(|chunk| chunk.starts_with(field.as_str()))
                .expect("field is registered");
            let registered_masked = block.contains("\"masked\": true");
            assert_eq!(
                registered_masked,
                field.masked(),
                "{} disagrees with the registry about masking",
                field.as_str()
            );
        }
    }

    #[test]
    fn relations_match_the_oracle_vocabulary_member_for_member() {
        let vocabulary =
            std::fs::read_to_string(repository_root().join("tools/oracle/vocabulary.py"))
                .expect("vocabulary.py is readable");
        for relation in Relation::ALL {
            assert!(
                vocabulary.contains(&format!("= \"{}\"", relation.as_str())),
                "{} is not in the oracle vocabulary",
                relation.as_str()
            );
        }
    }
}
