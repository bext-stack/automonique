// SPDX-License-Identifier: Elastic-2.0

//! Shared composer semantics checks.
//!
//! The checks below are derived from the product documents that describe the
//! composer —
//! `docs/product-plan/requirements/operator-tui.md` (the session input bar,
//! free-form intake, and `queue/edit/withdraw`),
//! `docs/product-plan/requirements/external-capability-ledger.md` (multiline
//! editor, history and slash autocomplete; typed authorized context
//! references), and `docs/product-plan/requirements/
//! client-experience-and-surfaces.md` (durable queued input).

use automonique_protocol::admin::MAX_ADMIN_CANONICAL_BYTES;
use automonique_protocol::command_registry::{CommandId, CommandRegistry, admin_command_registry};
use automonique_protocol::composer::{
    AttachmentName, AttachmentRef, BodyFit, BoundAuthority, BoundKind, COMPOSER_SCHEMA_V1,
    CommandMention, ComposerBody, ComposerError, ComposerHistory, ComposerReference, ComposerState,
    ComposerTarget, ComposerTransport, Draft, MAX_ATTACHMENT_NAME_BYTES, MAX_COMPOSER_BODY_BYTES,
    MAX_COMPOSER_HISTORY, MAX_DRAFT_REFERENCES, MentionResolution, SteerRefusal, TRANSPORT_BOUNDS,
    UnresolvedReason,
};
use automonique_protocol::context::{ContextReference, LineRange};
use automonique_protocol::interaction::{
    ContentDigest, MAX_INTERACTION_TEXT_BYTES, RequestRef, RequiredAuthority, SessionRef,
    SurfaceKind, TurnRef,
};
use automonique_protocol::primitives::ValueError;

// ---------------------------------------------------------------------------
// Shared fixtures.
// ---------------------------------------------------------------------------

fn session() -> SessionRef {
    SessionRef::new("s-1").expect("valid session")
}

fn turn() -> TurnRef {
    TurnRef::new("t-1").expect("valid turn")
}

fn request() -> RequestRef {
    RequestRef::new("r-1").expect("valid request")
}

fn body(value: &str) -> ComposerBody {
    ComposerBody::new(value).expect("valid body")
}

fn registry() -> CommandRegistry {
    admin_command_registry().expect("shipped registry")
}

fn attachment(digest: &str, name: &str) -> ComposerReference {
    ComposerReference::Attachment(AttachmentRef::new(
        ContentDigest::new(digest).expect("valid digest"),
        AttachmentName::new(name).expect("valid name"),
    ))
}

fn mention(name: &str) -> ComposerReference {
    ComposerReference::Command(CommandMention::unchecked(
        CommandId::new(name).expect("valid command id"),
    ))
}

fn resolved_mention(name: &str) -> ComposerReference {
    ComposerReference::Command(CommandMention::resolved_against(
        CommandId::new(name).expect("valid command id"),
        &registry(),
    ))
}

fn file_reference() -> ComposerReference {
    ComposerReference::Context(
        ContextReference::file("src/main.rs", "sha256:abc").expect("valid file reference"),
    )
}

fn follow_up() -> ComposerTarget {
    ComposerTarget::FollowUp { session: session() }
}

fn steer_target() -> ComposerTarget {
    ComposerTarget::Steer {
        session: session(),
        turn: turn(),
    }
}

fn draft_with(target: ComposerTarget, text: &str, references: Vec<ComposerReference>) -> Draft {
    Draft::new(SurfaceKind::Tui, target, body(text), references).expect("valid draft")
}

fn simple_draft() -> Draft {
    draft_with(follow_up(), "ship it", Vec::new())
}

fn drafting() -> ComposerState {
    ComposerState::Empty
        .begin(simple_draft())
        .expect("empty composer accepts begin")
}

/// The narrowest text bound in [`TRANSPORT_BOUNDS`], as the table declares it.
fn narrowest_text_bound() -> usize {
    TRANSPORT_BOUNDS
        .iter()
        .filter(|bound| bound.kind() == BoundKind::Text)
        .map(|bound| bound.max_bytes())
        .min()
        .expect("the table declares at least one text bound")
}

// ---------------------------------------------------------------------------
// Body bounds: both directions, with the at-limit case accepted.
// ---------------------------------------------------------------------------

mod body_bounds {
    use super::{ComposerBody, ComposerError, MAX_COMPOSER_BODY_BYTES, ValueError, body};

    #[test]
    fn empty_body_is_refused() {
        assert_eq!(
            ComposerBody::new(""),
            Err(ComposerError::Field {
                field: "body",
                error: ValueError::Empty,
            })
        );
    }

    #[test]
    fn body_at_the_limit_is_accepted() {
        let text = "a".repeat(MAX_COMPOSER_BODY_BYTES);
        let accepted = ComposerBody::new(text).expect("a body at the ceiling is admissible");
        assert_eq!(accepted.len_bytes(), MAX_COMPOSER_BODY_BYTES);
    }

    #[test]
    fn body_one_byte_over_the_limit_is_refused() {
        let text = "a".repeat(MAX_COMPOSER_BODY_BYTES + 1);
        assert_eq!(
            ComposerBody::new(text),
            Err(ComposerError::Field {
                field: "body",
                error: ValueError::TooLong {
                    max_bytes: MAX_COMPOSER_BODY_BYTES,
                    actual_bytes: MAX_COMPOSER_BODY_BYTES + 1,
                },
            })
        );
    }

    #[test]
    fn the_ceiling_counts_utf8_bytes_not_characters() {
        // Two bytes per character, so half as many characters reach the same
        // ceiling.
        let at_limit = "é".repeat(MAX_COMPOSER_BODY_BYTES / 2);
        assert_eq!(
            ComposerBody::new(at_limit)
                .expect("a two-byte-per-character body at the ceiling is admissible")
                .len_bytes(),
            MAX_COMPOSER_BODY_BYTES
        );

        let over = "é".repeat(MAX_COMPOSER_BODY_BYTES / 2 + 1);
        assert_eq!(
            ComposerBody::new(over),
            Err(ComposerError::Field {
                field: "body",
                error: ValueError::TooLong {
                    max_bytes: MAX_COMPOSER_BODY_BYTES,
                    actual_bytes: MAX_COMPOSER_BODY_BYTES + 2,
                },
            })
        );
    }

    #[test]
    fn a_carriage_return_is_refused_rather_than_normalized() {
        assert_eq!(
            ComposerBody::new("first\r\nsecond"),
            Err(ComposerError::CarriageReturn)
        );
        assert_eq!(
            ComposerBody::new("bare\rreturn"),
            Err(ComposerError::CarriageReturn)
        );
    }

    #[test]
    fn multiline_and_tabs_are_admitted() {
        let multiline = body("first\n\tindented\nlast");
        assert_eq!(multiline.line_count(), 3);
        assert!(!multiline.is_single_line());
        assert_eq!(body("one line").line_count(), 1);
        assert!(body("one line").is_single_line());
    }

    #[test]
    fn every_other_control_character_is_refused() {
        for control in ['\u{0}', '\u{1}', '\u{7}', '\u{1b}', '\u{7f}', '\u{85}'] {
            assert_eq!(
                ComposerBody::new(format!("text{control}more")),
                Err(ComposerError::Field {
                    field: "body",
                    error: ValueError::ControlCharacter,
                }),
                "control character {control:?} must be refused"
            );
        }
    }

    #[test]
    fn an_accepted_body_is_returned_exactly() {
        let text = "keep\tthe\nexact bytes ✓";
        assert_eq!(body(text).as_str(), text);
    }
}

// ---------------------------------------------------------------------------
// Reference grammars: each family validated by the grammar that owns it.
// ---------------------------------------------------------------------------

mod references {
    use super::{
        AttachmentName, ComposerError, ComposerReference, Draft, MAX_ATTACHMENT_NAME_BYTES,
        MAX_DRAFT_REFERENCES, MentionResolution, SurfaceKind, UnresolvedReason, attachment, body,
        file_reference, follow_up, mention, resolved_mention,
    };
    use automonique_protocol::command_registry::CommandId;

    #[test]
    fn a_mention_cannot_carry_a_name_the_command_grammar_refuses() {
        for refused in ["Status", "with space", "trailing.", "run-submit", ""] {
            assert!(
                CommandId::new(refused).is_err(),
                "{refused:?} must not be a command identifier"
            );
        }
        assert!(CommandId::new("submit_run").is_ok());
        assert!(CommandId::new("automonique.interaction.undo").is_ok());
    }

    #[test]
    fn an_unchecked_mention_says_no_registry_was_consulted() {
        let ComposerReference::Command(unchecked) = mention("status") else {
            panic!("expected a command mention");
        };
        assert_eq!(
            unchecked.resolution(),
            &MentionResolution::Unresolved {
                reason: UnresolvedReason::NoRegistryConsulted,
            }
        );
        assert!(!unchecked.resolution().is_resolved());
    }

    #[test]
    fn an_unknown_command_is_representable_and_marked_unresolved() {
        let ComposerReference::Command(checked) = resolved_mention("no_such_command") else {
            panic!("expected a command mention");
        };
        assert_eq!(checked.named().as_str(), "no_such_command");
        assert_eq!(
            checked.resolution(),
            &MentionResolution::Unresolved {
                reason: UnresolvedReason::NotInRegistry,
            }
        );
    }

    #[test]
    fn a_known_command_resolves_to_its_canonical_identifier() {
        let ComposerReference::Command(checked) = resolved_mention("submit_run") else {
            panic!("expected a command mention");
        };
        assert_eq!(
            checked.resolution(),
            &MentionResolution::Resolved {
                canonical: CommandId::new("submit_run").expect("valid identifier"),
            }
        );
    }

    #[test]
    fn an_alias_resolves_to_the_command_it_names_not_to_itself() {
        // `submit` is `submit_synthetic`'s alias in the shipped registry.
        let ComposerReference::Command(checked) = resolved_mention("submit") else {
            panic!("expected a command mention");
        };
        assert_eq!(checked.named().as_str(), "submit");
        assert_eq!(
            checked.resolution(),
            &MentionResolution::Resolved {
                canonical: CommandId::new("submit_synthetic").expect("valid identifier"),
            }
        );
    }

    #[test]
    fn context_and_attachment_references_are_resolved_by_construction() {
        assert!(file_reference().is_resolved());
        assert!(attachment("sha256:aa", "notes.txt").is_resolved());
        assert!(!mention("status").is_resolved());
    }

    #[test]
    fn every_reference_family_is_covered() {
        let kinds: Vec<&str> = vec![
            attachment("sha256:aa", "a.txt").kind(),
            mention("status").kind(),
            file_reference().kind(),
        ];
        let mut sorted = kinds.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, ComposerReference::KINDS.to_vec());
    }

    #[test]
    fn one_digest_under_two_names_is_one_attachment() {
        let error = Draft::new(
            SurfaceKind::Tui,
            follow_up(),
            body("look"),
            vec![
                attachment("sha256:aa", "first.txt"),
                attachment("sha256:aa", "second.txt"),
            ],
        )
        .expect_err("the same digest twice is a duplicate");
        assert_eq!(
            error,
            ComposerError::DuplicateReference {
                reference: "attachment sha256:aa".to_owned(),
            }
        );
    }

    #[test]
    fn a_command_named_twice_is_a_duplicate_however_it_was_checked() {
        let error = Draft::new(
            SurfaceKind::Tui,
            follow_up(),
            body("run it"),
            vec![mention("submit_run"), resolved_mention("submit_run")],
        )
        .expect_err("resolution state does not make a second mention a new reference");
        assert_eq!(
            error,
            ComposerError::DuplicateReference {
                reference: "command submit_run".to_owned(),
            }
        );
    }

    #[test]
    fn context_references_are_distinguished_by_their_whole_identity() {
        use automonique_protocol::context::{ContextReference, LineRange};

        let whole = ComposerReference::Context(
            ContextReference::file("src/main.rs", "sha256:abc").expect("valid reference"),
        );
        let ranged = ComposerReference::Context(
            ContextReference::file_lines(
                "src/main.rs",
                "sha256:abc",
                LineRange::new(1, 20).expect("valid range"),
            )
            .expect("valid reference"),
        );
        assert_ne!(whole.identity(), ranged.identity());
        Draft::new(
            SurfaceKind::Tui,
            follow_up(),
            body("look"),
            vec![whole.clone(), ranged],
        )
        .expect("a file and a line range within it are different references");

        let error = Draft::new(
            SurfaceKind::Tui,
            follow_up(),
            body("look"),
            vec![whole.clone(), whole],
        )
        .expect_err("the identical reference twice is a duplicate");
        assert_eq!(error.category(), "duplicate_reference");
    }

    #[test]
    fn references_at_the_limit_are_accepted_and_one_more_is_refused() {
        let at_limit: Vec<ComposerReference> = (0..MAX_DRAFT_REFERENCES)
            .map(|index| attachment(&format!("sha256:{index:04x}"), "a.txt"))
            .collect();
        let draft = Draft::new(
            SurfaceKind::Tui,
            follow_up(),
            body("look"),
            at_limit.clone(),
        )
        .expect("a draft at the reference ceiling is admissible");
        assert_eq!(draft.references().len(), MAX_DRAFT_REFERENCES);

        let mut over = at_limit;
        over.push(attachment("sha256:ffff", "a.txt"));
        assert_eq!(
            Draft::new(SurfaceKind::Tui, follow_up(), body("look"), over),
            Err(ComposerError::TooMany {
                field: "references",
                max: MAX_DRAFT_REFERENCES,
                actual: MAX_DRAFT_REFERENCES + 1,
            })
        );
    }

    #[test]
    fn an_attachment_name_is_bounded_and_never_an_identity() {
        assert!(AttachmentName::new("a".repeat(MAX_ATTACHMENT_NAME_BYTES)).is_ok());
        assert!(AttachmentName::new("a".repeat(MAX_ATTACHMENT_NAME_BYTES + 1)).is_err());
        assert!(AttachmentName::new("").is_err());
    }
}

// ---------------------------------------------------------------------------
// Targets: the explicit-operation rule.
// ---------------------------------------------------------------------------

mod targets {
    use super::{
        ComposerTarget, RequestRef, RequiredAuthority, SessionRef, TurnRef, request, session, turn,
    };

    fn every_target() -> Vec<ComposerTarget> {
        vec![
            ComposerTarget::NewRequest,
            ComposerTarget::FollowUp { session: session() },
            ComposerTarget::Queue { session: session() },
            ComposerTarget::Steer {
                session: session(),
                turn: turn(),
            },
            ComposerTarget::Answer {
                session: session(),
                request: request(),
            },
        ]
    }

    #[test]
    fn every_target_kind_is_covered_and_distinct() {
        let kinds: Vec<&str> = every_target().iter().map(ComposerTarget::kind).collect();
        assert_eq!(kinds, ComposerTarget::KINDS.to_vec());
        let mut sorted = kinds;
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ComposerTarget::KINDS.len());
    }

    #[test]
    fn only_a_new_request_lacks_a_session() {
        for target in every_target() {
            match target {
                ComposerTarget::NewRequest => assert!(target.session().is_none()),
                _ => assert_eq!(
                    target.session().map(SessionRef::as_str),
                    Some("s-1"),
                    "{} must name its session",
                    target.kind()
                ),
            }
        }
    }

    #[test]
    fn answering_a_provider_request_needs_approval_authority() {
        assert_eq!(
            ComposerTarget::Answer {
                session: session(),
                request: request(),
            }
            .authority(),
            RequiredAuthority::Approve
        );
        for target in every_target() {
            if matches!(target, ComposerTarget::Answer { .. }) {
                continue;
            }
            assert_eq!(
                target.authority(),
                RequiredAuthority::Compose,
                "{} composes text",
                target.kind()
            );
        }
    }

    #[test]
    fn a_target_line_names_every_coordinate_it_holds() {
        assert_eq!(ComposerTarget::NewRequest.line(), "target new_request");
        assert_eq!(
            ComposerTarget::FollowUp { session: session() }.line(),
            "target follow_up session=s-1"
        );
        assert_eq!(
            ComposerTarget::Queue { session: session() }.line(),
            "target queue session=s-1"
        );
        assert_eq!(
            ComposerTarget::Steer {
                session: session(),
                turn: turn(),
            }
            .line(),
            "target steer session=s-1 turn=t-1"
        );
        assert_eq!(
            ComposerTarget::Answer {
                session: session(),
                request: request(),
            }
            .line(),
            "target answer session=s-1 request=r-1"
        );
    }

    #[test]
    fn coordinates_are_typed_so_they_cannot_be_swapped() {
        // A turn identity and a session identity are different types; the
        // module's compile_fail examples cover the negative case, and this
        // pins that the accessors return what they claim.
        let target = ComposerTarget::Steer {
            session: session(),
            turn: turn(),
        };
        let ComposerTarget::Steer {
            session: bound_session,
            turn: bound_turn,
        } = &target
        else {
            panic!("expected a steer target");
        };
        let _: &SessionRef = bound_session;
        let _: &TurnRef = bound_turn;
        let _: RequestRef = request();
    }
}

// ---------------------------------------------------------------------------
// The transport-fit table.
// ---------------------------------------------------------------------------

mod transport_fit {
    use super::{
        BodyFit, BoundAuthority, BoundKind, ComposerBody, ComposerTransport, Draft,
        MAX_ADMIN_CANONICAL_BYTES, MAX_COMPOSER_BODY_BYTES, SurfaceKind, TRANSPORT_BOUNDS,
        follow_up, narrowest_text_bound,
    };

    fn draft_of_bytes(count: usize) -> Draft {
        Draft::new(
            SurfaceKind::Tui,
            follow_up(),
            ComposerBody::new("a".repeat(count)).expect("valid body"),
            Vec::new(),
        )
        .expect("valid draft")
    }

    #[test]
    fn the_table_is_declared_in_transport_order() {
        let transports: Vec<ComposerTransport> = TRANSPORT_BOUNDS
            .iter()
            .map(|bound| bound.transport())
            .collect();
        assert_eq!(transports, ComposerTransport::ALL.to_vec());
    }

    #[test]
    fn the_admin_bound_is_the_real_constant_and_is_checkable_here() {
        let bound = ComposerTransport::AdminSocket.bound();
        assert_eq!(bound.max_bytes(), MAX_ADMIN_CANONICAL_BYTES);
        assert_eq!(bound.kind(), BoundKind::Frame);
        assert!(bound.authority().is_checkable_here());
        assert_eq!(
            bound.authority(),
            BoundAuthority::Local {
                symbol: "automonique_protocol::admin::MAX_ADMIN_CANONICAL_BYTES",
            }
        );
    }

    #[test]
    fn the_messaging_bounds_are_carried_copies_that_name_their_owner() {
        let slack = ComposerTransport::Slack.bound();
        let telegram = ComposerTransport::Telegram.bound();

        for bound in [slack, telegram] {
            assert_eq!(bound.kind(), BoundKind::Text);
            assert_eq!(bound.max_bytes(), 16 * 1024);
            assert!(
                !bound.authority().is_checkable_here(),
                "a copied value must not claim to be verified here"
            );
            assert_eq!(bound.authority().as_str(), "foreign");
        }
        assert_eq!(
            slack.authority().symbol(),
            "automonique_transports::MAX_SLACK_TEXT_BYTES"
        );
        assert_eq!(
            telegram.authority().symbol(),
            "automonique_transports::MAX_TELEGRAM_INPUT_BYTES"
        );
    }

    #[test]
    fn the_composer_ceiling_is_half_the_admin_frame() {
        assert_eq!(MAX_COMPOSER_BODY_BYTES, MAX_ADMIN_CANONICAL_BYTES / 2);
        assert_eq!(MAX_COMPOSER_BODY_BYTES, 32 * 1024);
    }

    #[test]
    fn the_composer_ceiling_deliberately_exceeds_the_narrowest_transport() {
        assert_eq!(narrowest_text_bound(), 16 * 1024);
        assert!(
            MAX_COMPOSER_BODY_BYTES > narrowest_text_bound(),
            "a wider ceiling is what makes an oversize answer necessary"
        );
    }

    #[test]
    fn a_body_at_a_transport_limit_fits_with_no_headroom() {
        let draft = draft_of_bytes(narrowest_text_bound());
        for transport in [ComposerTransport::Slack, ComposerTransport::Telegram] {
            assert_eq!(
                draft.fit(transport),
                BodyFit::Fits {
                    transport,
                    headroom_bytes: 0,
                }
            );
        }
    }

    #[test]
    fn a_body_one_byte_over_a_transport_limit_is_refused_by_name() {
        let over = narrowest_text_bound() + 1;
        let draft = draft_of_bytes(over);
        for transport in [ComposerTransport::Slack, ComposerTransport::Telegram] {
            assert_eq!(
                draft.fit(transport),
                BodyFit::TooLarge {
                    transport,
                    limit_bytes: narrowest_text_bound(),
                    actual_bytes: over,
                }
            );
            assert!(!draft.fit(transport).fits());
            assert_eq!(draft.fit(transport).transport(), transport);
        }
    }

    #[test]
    fn the_widest_admissible_body_still_fits_one_admin_frame() {
        let draft = draft_of_bytes(MAX_COMPOSER_BODY_BYTES);
        assert_eq!(
            draft.fit(ComposerTransport::AdminSocket),
            BodyFit::Fits {
                transport: ComposerTransport::AdminSocket,
                headroom_bytes: MAX_ADMIN_CANONICAL_BYTES - MAX_COMPOSER_BODY_BYTES,
            }
        );
    }

    #[test]
    fn the_fit_table_answers_for_every_transport_in_order() {
        let draft = draft_of_bytes(narrowest_text_bound() + 1);
        let table = draft.fit_table();
        let answers: Vec<(&str, &str)> = table
            .iter()
            .map(|fit| (fit.transport().as_str(), fit.as_str()))
            .collect();
        assert_eq!(
            answers,
            vec![
                ("admin_socket", "fits"),
                ("slack", "too_large"),
                ("telegram", "too_large"),
            ]
        );
    }
}

// ---------------------------------------------------------------------------
// Composition state transitions.
// ---------------------------------------------------------------------------

mod state_machine {
    use super::{
        ComposerError, ComposerState, ComposerTarget, RequiredAuthority, draft_with, drafting,
        follow_up, mention, request, session, simple_draft,
    };

    fn submitted() -> ComposerState {
        drafting()
            .submit(request(), &[RequiredAuthority::Compose])
            .expect("a granted compose authority admits the submission")
    }

    #[test]
    fn the_legal_path_runs_empty_drafting_submitted_empty() {
        let empty = ComposerState::Empty;
        assert_eq!(empty.state(), "empty");

        let drafting = empty.begin(simple_draft()).expect("begin from empty");
        assert_eq!(drafting.state(), "drafting");
        assert!(drafting.draft().is_some());
        assert!(drafting.submission().is_none());

        let edited = drafting
            .edit(draft_with(follow_up(), "ship it twice", Vec::new()))
            .expect("edit from drafting");
        assert_eq!(
            edited.draft().expect("a draft").body().as_str(),
            "ship it twice"
        );

        let submitted = edited
            .submit(request(), &[RequiredAuthority::Compose])
            .expect("submit from drafting");
        assert_eq!(submitted.state(), "submitted");
        assert!(submitted.draft().is_none());

        let cleared = submitted.clear().expect("clear from submitted");
        assert_eq!(cleared, ComposerState::Empty);
    }

    #[test]
    fn a_transition_returns_a_new_value_and_leaves_the_old_one_alone() {
        let empty = ComposerState::Empty;
        let next = empty.begin(simple_draft()).expect("begin from empty");
        assert_eq!(empty, ComposerState::Empty);
        assert_eq!(next.state(), "drafting");

        let discarded = next.discard().expect("discard from drafting");
        assert_eq!(next.state(), "drafting");
        assert_eq!(discarded, ComposerState::Empty);
    }

    #[test]
    fn every_illegal_transition_is_refused_by_name() {
        let states = [
            ("empty", ComposerState::Empty),
            ("drafting", drafting()),
            ("submitted", submitted()),
        ];
        // Every (state, event) pair the diagram does not contain.
        let illegal = [
            ("drafting", "begin"),
            ("submitted", "begin"),
            ("empty", "edit"),
            ("submitted", "edit"),
            ("empty", "discard"),
            ("submitted", "discard"),
            ("empty", "submit"),
            ("submitted", "submit"),
            ("empty", "clear"),
            ("drafting", "clear"),
        ];

        for (from, event) in illegal {
            let state = states
                .iter()
                .find(|(name, _)| *name == from)
                .map(|(_, state)| state)
                .expect("a state under test");
            let outcome = match event {
                "begin" => state.begin(simple_draft()),
                "edit" => state.edit(simple_draft()),
                "discard" => state.discard(),
                "submit" => state.submit(request(), &RequiredAuthority::ALL),
                "clear" => state.clear(),
                other => panic!("unknown event {other}"),
            };
            assert_eq!(
                outcome,
                Err(ComposerError::IllegalTransition { from, event }),
                "{from} must refuse {event}"
            );
        }
    }

    #[test]
    fn the_legal_pairs_and_the_illegal_pairs_partition_the_matrix() {
        let legal = [
            ("empty", "begin"),
            ("drafting", "edit"),
            ("drafting", "discard"),
            ("drafting", "submit"),
            ("submitted", "clear"),
        ];
        assert_eq!(
            legal.len() + 10,
            ComposerState::STATES.len() * ComposerState::EVENTS.len()
        );
    }

    #[test]
    fn submission_refuses_an_unresolved_reference_by_naming_it() {
        let state = ComposerState::Empty
            .begin(draft_with(
                follow_up(),
                "run /no_such_command",
                vec![mention("no_such_command")],
            ))
            .expect("begin from empty");
        assert_eq!(
            state.submit(request(), &RequiredAuthority::ALL),
            Err(ComposerError::UnresolvedReference {
                reference: "command no_such_command".to_owned(),
            })
        );
    }

    #[test]
    fn submission_refuses_when_the_targets_authority_was_not_granted() {
        assert_eq!(
            drafting().submit(request(), &[]),
            Err(ComposerError::AuthorityRequired {
                authority: RequiredAuthority::Compose,
            })
        );
        assert_eq!(
            drafting().submit(request(), &[RequiredAuthority::Observe]),
            Err(ComposerError::AuthorityRequired {
                authority: RequiredAuthority::Compose,
            })
        );
    }

    #[test]
    fn an_answer_needs_approval_and_compose_alone_will_not_do() {
        let state = ComposerState::Empty
            .begin(draft_with(
                ComposerTarget::Answer {
                    session: session(),
                    request: request(),
                },
                "yes, allow it",
                Vec::new(),
            ))
            .expect("begin from empty");
        assert_eq!(
            state.submit(request(), &[RequiredAuthority::Compose]),
            Err(ComposerError::AuthorityRequired {
                authority: RequiredAuthority::Approve,
            })
        );
        let submitted = state
            .submit(request(), &[RequiredAuthority::Approve])
            .expect("approve authority admits the answer");
        assert_eq!(
            submitted.submission().expect("a submission").authority(),
            RequiredAuthority::Approve
        );
    }

    #[test]
    fn a_submission_records_the_draft_and_the_request_identity() {
        let submission = submitted();
        let recorded = submission.submission().expect("a submission");
        assert_eq!(recorded.request().as_str(), "r-1");
        assert_eq!(recorded.draft(), &simple_draft());
        assert_eq!(recorded.authority(), RequiredAuthority::Compose);
    }

    #[test]
    fn submitting_twice_under_one_composition_is_refused() {
        assert_eq!(
            submitted().submit(request(), &RequiredAuthority::ALL),
            Err(ComposerError::IllegalTransition {
                from: "submitted",
                event: "submit",
            })
        );
    }
}

// ---------------------------------------------------------------------------
// The one bridge into `interaction`, and what it refuses.
// ---------------------------------------------------------------------------

mod steer_bridge {
    use super::{
        ComposerError, MAX_INTERACTION_TEXT_BYTES, SteerRefusal, ValueError, draft_with, follow_up,
        steer_target,
    };

    #[test]
    fn a_draft_addressed_elsewhere_is_not_a_steer() {
        assert_eq!(
            draft_with(follow_up(), "go left", Vec::new()).steer_request(),
            Err(ComposerError::TargetMismatch {
                expected: "steer",
                actual: "follow_up",
            })
        );
    }

    #[test]
    fn a_single_line_body_within_the_steer_ceiling_converts() {
        let steer = draft_with(steer_target(), "prefer the smaller diff", Vec::new())
            .steer_request()
            .expect("a short single-line body is expressible");
        assert_eq!(steer.text().as_str(), "prefer the smaller diff");
    }

    #[test]
    fn a_body_at_the_steer_ceiling_converts_and_one_byte_more_does_not() {
        let at_limit = "a".repeat(MAX_INTERACTION_TEXT_BYTES);
        assert!(
            draft_with(steer_target(), &at_limit, Vec::new())
                .steer_request()
                .is_ok()
        );

        let over = "a".repeat(MAX_INTERACTION_TEXT_BYTES + 1);
        assert_eq!(
            draft_with(steer_target(), &over, Vec::new()).steer_request(),
            Err(ComposerError::NotExpressibleAsSteer {
                reason: SteerRefusal::TooLong {
                    max_bytes: MAX_INTERACTION_TEXT_BYTES,
                    actual_bytes: MAX_INTERACTION_TEXT_BYTES + 1,
                },
            })
        );
    }

    #[test]
    fn a_multiline_body_is_refused_rather_than_flattened() {
        assert_eq!(
            draft_with(steer_target(), "first\nsecond", Vec::new()).steer_request(),
            Err(ComposerError::NotExpressibleAsSteer {
                reason: SteerRefusal::Multiline,
            })
        );
    }

    #[test]
    fn a_tab_is_refused_because_steering_text_admits_no_control_character() {
        assert_eq!(
            draft_with(steer_target(), "indent\there", Vec::new()).steer_request(),
            Err(ComposerError::Field {
                field: "steer_text",
                error: ValueError::ControlCharacter,
            })
        );
    }

    #[test]
    fn the_composer_can_hold_a_body_no_steer_can_carry() {
        // The seam this module documents rather than papers over: a body the
        // composer accepts at its own ceiling has no steering expression.
        let widest = "a".repeat(super::MAX_COMPOSER_BODY_BYTES);
        assert_eq!(
            draft_with(steer_target(), &widest, Vec::new()).steer_request(),
            Err(ComposerError::NotExpressibleAsSteer {
                reason: SteerRefusal::TooLong {
                    max_bytes: MAX_INTERACTION_TEXT_BYTES,
                    actual_bytes: super::MAX_COMPOSER_BODY_BYTES,
                },
            })
        );
    }
}

// ---------------------------------------------------------------------------
// Determinism of the rendered form.
// ---------------------------------------------------------------------------

mod canonical_form {
    use super::{
        COMPOSER_SCHEMA_V1, ComposerTarget, attachment, draft_with, file_reference, follow_up,
        mention, resolved_mention, session, simple_draft, turn,
    };

    #[test]
    fn the_form_names_the_versioned_schema_first() {
        let rendered = simple_draft().canonical_form();
        assert_eq!(
            rendered.lines().next(),
            Some(COMPOSER_SCHEMA_V1),
            "the first line names the schema version"
        );
        assert_eq!(COMPOSER_SCHEMA_V1, "automonique.composer/v1");
    }

    #[test]
    fn two_equal_drafts_render_to_identical_bytes() {
        let left = draft_with(
            follow_up(),
            "look at this",
            vec![file_reference(), resolved_mention("submit_run")],
        );
        let right = draft_with(
            follow_up(),
            "look at this",
            vec![file_reference(), resolved_mention("submit_run")],
        );
        assert_eq!(left, right);
        assert_eq!(left.canonical_form(), right.canonical_form());
        assert_eq!(left.canonical_form(), left.clone().canonical_form());
        // Repeated rendering of one value is stable.
        assert_eq!(left.canonical_form(), left.canonical_form());
    }

    #[test]
    fn reference_order_is_carried_not_normalized() {
        let forward = draft_with(
            follow_up(),
            "look",
            vec![file_reference(), attachment("sha256:aa", "a.txt")],
        );
        let reversed = draft_with(
            follow_up(),
            "look",
            vec![attachment("sha256:aa", "a.txt"), file_reference()],
        );
        assert_ne!(forward, reversed);
        assert_ne!(forward.canonical_form(), reversed.canonical_form());
    }

    #[test]
    fn resolution_state_is_visible_in_the_rendered_reference() {
        let unchecked = draft_with(follow_up(), "run", vec![mention("submit_run")]);
        let checked = draft_with(follow_up(), "run", vec![resolved_mention("submit_run")]);
        assert!(
            unchecked
                .canonical_form()
                .contains("command submit_run unresolved=no_registry_consulted")
        );
        assert!(
            checked
                .canonical_form()
                .contains("command submit_run resolved=submit_run")
        );
    }

    #[test]
    fn the_body_is_length_prefixed_and_written_last() {
        // A body whose own text imitates a header cannot be mistaken for one.
        let draft = draft_with(follow_up(), "body 5\nreal", Vec::new());
        let rendered = draft.canonical_form();
        assert_eq!(
            rendered,
            format!(
                "{COMPOSER_SCHEMA_V1}\nsurface tui\ntarget follow_up session=s-1\nreferences 0\nbody 11\nbody 5\nreal\n"
            )
        );
    }

    #[test]
    fn different_target_coordinates_render_differently() {
        let follow = draft_with(follow_up(), "go", Vec::new());
        let steer = draft_with(
            ComposerTarget::Steer {
                session: session(),
                turn: turn(),
            },
            "go",
            Vec::new(),
        );
        let intake = draft_with(ComposerTarget::NewRequest, "go", Vec::new());
        assert_ne!(follow.canonical_form(), steer.canonical_form());
        assert_ne!(follow.canonical_form(), intake.canonical_form());
        assert_ne!(steer.canonical_form(), intake.canonical_form());
    }

    #[test]
    fn the_reference_count_matches_the_lines_that_follow_it() {
        let draft = draft_with(
            follow_up(),
            "look",
            vec![
                file_reference(),
                attachment("sha256:aa", "a.txt"),
                resolved_mention("status"),
            ],
        );
        let rendered = draft.canonical_form();
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines[3], "references 3");
        assert_eq!(lines[4], "context file src/main.rs sha256:abc whole");
        assert_eq!(lines[5], "attachment sha256:aa");
        assert_eq!(lines[6], "command status resolved=status");
        assert_eq!(lines[7], "body 4");
    }
}

// ---------------------------------------------------------------------------
// History: a bounded window that never drops silently.
// ---------------------------------------------------------------------------

mod history {
    use super::{
        ComposerError, ComposerHistory, MAX_COMPOSER_HISTORY, draft_with, follow_up, simple_draft,
    };

    fn numbered(index: usize) -> super::Draft {
        draft_with(follow_up(), &format!("draft {index}"), Vec::new())
    }

    #[test]
    fn an_empty_window_recalls_nothing() {
        let history = ComposerHistory::new();
        assert!(history.is_empty());
        assert_eq!(history.len(), 0);
        assert_eq!(
            history.recall(0),
            Err(ComposerError::HistoryOutOfRange {
                length: 0,
                requested: 0,
            })
        );
    }

    #[test]
    fn the_most_recent_draft_is_slot_zero() {
        let (history, evicted) = ComposerHistory::new().push(numbered(1));
        assert!(evicted.is_none());
        let (history, _) = history.push(numbered(2));
        assert_eq!(history.len(), 2);
        assert_eq!(
            history.recall(0).expect("slot 0").body().as_str(),
            "draft 2"
        );
        assert_eq!(
            history.recall(1).expect("slot 1").body().as_str(),
            "draft 1"
        );
    }

    #[test]
    fn a_push_returns_a_new_window_and_leaves_the_old_one_alone() {
        let first = ComposerHistory::new();
        let (second, _) = first.push(simple_draft());
        assert!(first.is_empty());
        assert_eq!(second.len(), 1);
    }

    #[test]
    fn the_window_fills_to_its_ceiling_without_evicting() {
        let mut history = ComposerHistory::new();
        for index in 0..MAX_COMPOSER_HISTORY {
            let (next, evicted) = history.push(numbered(index));
            assert!(
                evicted.is_none(),
                "nothing leaves before the window is full"
            );
            history = next;
        }
        assert_eq!(history.len(), MAX_COMPOSER_HISTORY);
    }

    #[test]
    fn eviction_hands_back_exactly_what_left() {
        let mut history = ComposerHistory::new();
        for index in 0..MAX_COMPOSER_HISTORY {
            let (next, _) = history.push(numbered(index));
            history = next;
        }
        let (full, evicted) = history.push(numbered(MAX_COMPOSER_HISTORY));
        assert_eq!(full.len(), MAX_COMPOSER_HISTORY);
        assert_eq!(
            evicted.expect("the oldest draft is returned, not dropped"),
            numbered(0)
        );
        assert_eq!(
            full.recall(0).expect("slot 0").body().as_str(),
            format!("draft {MAX_COMPOSER_HISTORY}")
        );
        assert_eq!(
            full.recall(MAX_COMPOSER_HISTORY - 1)
                .expect("the last slot")
                .body()
                .as_str(),
            "draft 1"
        );
    }

    #[test]
    fn a_recall_past_the_window_is_refused_rather_than_clamped() {
        let (history, _) = ComposerHistory::new().push(simple_draft());
        assert_eq!(
            history.recall(1),
            Err(ComposerError::HistoryOutOfRange {
                length: 1,
                requested: 1,
            })
        );
        assert_eq!(
            history.recall(usize::MAX),
            Err(ComposerError::HistoryOutOfRange {
                length: 1,
                requested: usize::MAX,
            })
        );
    }
}

// ---------------------------------------------------------------------------
// Every refusal has a stable category, and every category is reachable.
// ---------------------------------------------------------------------------

mod error_categories {
    use super::{
        ComposerBody, ComposerError, ComposerHistory, ComposerReference, ComposerState,
        MAX_DRAFT_REFERENCES, RequiredAuthority, SurfaceKind, attachment, body, draft_with,
        drafting, follow_up, mention, request, steer_target,
    };
    use automonique_protocol::composer::Draft;

    /// One real refusal per category, produced through the public API.
    fn every_refusal() -> Vec<ComposerError> {
        let over: Vec<ComposerReference> = (0..=MAX_DRAFT_REFERENCES)
            .map(|index| attachment(&format!("sha256:{index:04x}"), "a.txt"))
            .collect();
        let unresolved_state = ComposerState::Empty
            .begin(draft_with(
                follow_up(),
                "run it",
                vec![mention("no_such_command")],
            ))
            .expect("begin from empty");

        vec![
            ComposerBody::new("").expect_err("empty body"),
            ComposerBody::new("a\rb").expect_err("carriage return"),
            Draft::new(SurfaceKind::Tui, follow_up(), body("x"), over).expect_err("too many"),
            Draft::new(
                SurfaceKind::Tui,
                follow_up(),
                body("x"),
                vec![attachment("sha256:aa", "a"), attachment("sha256:aa", "b")],
            )
            .expect_err("duplicate"),
            unresolved_state
                .submit(request(), &RequiredAuthority::ALL)
                .expect_err("unresolved"),
            draft_with(follow_up(), "x", Vec::new())
                .steer_request()
                .expect_err("target mismatch"),
            ComposerState::Empty
                .submit(request(), &RequiredAuthority::ALL)
                .expect_err("illegal transition"),
            drafting().submit(request(), &[]).expect_err("authority"),
            draft_with(steer_target(), "a\nb", Vec::new())
                .steer_request()
                .expect_err("not expressible as steer"),
            ComposerHistory::new().recall(0).expect_err("out of range"),
        ]
    }

    #[test]
    fn every_declared_category_is_reachable_through_the_public_api() {
        let mut seen: Vec<&str> = every_refusal()
            .iter()
            .map(ComposerError::category)
            .collect();
        seen.sort_unstable();
        seen.dedup();

        let mut declared = ComposerError::CATEGORIES.to_vec();
        declared.sort_unstable();
        assert_eq!(seen, declared);
    }

    #[test]
    fn the_declared_categories_are_unique() {
        let mut declared = ComposerError::CATEGORIES.to_vec();
        let count = declared.len();
        declared.sort_unstable();
        declared.dedup();
        assert_eq!(declared.len(), count);
    }

    #[test]
    fn every_refusal_explains_itself_without_echoing_a_body() {
        for error in every_refusal() {
            let message = error.to_string();
            assert!(!message.is_empty());
            assert!(
                !message.contains("run it"),
                "a refusal must not echo composed text: {message}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The module composes existing vocabularies rather than forking them.
// ---------------------------------------------------------------------------

mod alignment {
    use super::{
        ComposerReference, ContextReference, Draft, LineRange, SurfaceKind, body, file_reference,
        follow_up,
    };

    #[test]
    fn a_draft_can_carry_every_context_reference_kind() {
        let references = vec![
            ContextReference::file("src/main.rs", "sha256:a").expect("file"),
            ContextReference::file_lines(
                "src/lib.rs",
                "sha256:b",
                LineRange::new(3, 9).expect("range"),
            )
            .expect("file lines"),
            ContextReference::folder(
                "docs",
                automonique_protocol::context::FolderDepth::new(2).expect("depth"),
                automonique_protocol::context::FolderFilter::all(),
            )
            .expect("folder"),
            ContextReference::diff("HEAD~1").expect("diff"),
            ContextReference::staged(),
            ContextReference::commit("abc123").expect("commit"),
            ContextReference::branch("main").expect("branch"),
            ContextReference::url("https://example.com/a").expect("url"),
            ContextReference::session("s-9").expect("session"),
            ContextReference::turn("s-9", "t-2").expect("turn"),
            ContextReference::run("run-1").expect("run"),
            ContextReference::ticket("TCK-1").expect("ticket"),
            ContextReference::artifact("sha256:c").expect("artifact"),
            ContextReference::workspace("w-1").expect("workspace"),
        ];
        assert_eq!(references.len(), ContextReference::KINDS.len() + 1);

        let composed: Vec<ComposerReference> = references
            .into_iter()
            .map(ComposerReference::Context)
            .collect();
        let draft = Draft::new(SurfaceKind::Tui, follow_up(), body("look"), composed)
            .expect("every context reference kind composes");

        let mut identities: Vec<String> = draft
            .references()
            .iter()
            .map(ComposerReference::identity)
            .collect();
        let count = identities.len();
        identities.sort();
        identities.dedup();
        assert_eq!(
            identities.len(),
            count,
            "each context reference has its own identity line"
        );
    }

    #[test]
    fn a_draft_is_composed_on_a_named_surface() {
        for surface in SurfaceKind::ALL {
            let draft = Draft::new(surface, follow_up(), body("hi"), vec![file_reference()])
                .expect("valid draft");
            assert_eq!(draft.surface(), surface);
            assert!(
                draft
                    .canonical_form()
                    .contains(&format!("surface {}", surface.as_str()))
            );
        }
    }

    #[test]
    fn an_unresolved_reference_is_reported_not_removed() {
        let draft = super::draft_with(
            follow_up(),
            "run /ghost and /submit_run",
            vec![
                super::mention("ghost"),
                super::resolved_mention("submit_run"),
            ],
        );
        assert_eq!(draft.references().len(), 2);
        assert_eq!(draft.unresolved().len(), 1);
        assert!(!draft.is_fully_resolved());
        assert_eq!(draft.unresolved()[0].identity(), "command ghost");
    }
}
