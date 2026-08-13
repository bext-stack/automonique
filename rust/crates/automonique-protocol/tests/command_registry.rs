// SPDX-License-Identifier: Elastic-2.0

//! R7 verification: the declarative command registry and its generated help.
//!
//! The registry is a description, so the question every test here asks is
//! whether the description is true of the thing described. The centre of the
//! file is `anti_drift`: it encodes a real [`AdminRequest`] per command and
//! compares the resulting canonical JSON keys with the declared field names,
//! so the registry cannot quietly describe a message the daemon stopped
//! sending.

use automonique_protocol::admin::{
    AdminCommand, AdminRequest, IntakePause, IntakeResume, OutboxReconciliation,
    OutboxReconciliationDecision, OutboxReconciliationParts, ReconciliationFailure,
    SubmittedRunSpec, SyntheticSubmission,
};
use automonique_protocol::codec::RequestId;
use automonique_protocol::command_registry::{
    ApprovalPolicy, AuthorizationRequirement, COMMAND_REGISTRY_SCHEMA_V1, CommandAlias, CommandId,
    CommandRegistry, CommandRegistryError, CommandSpec, CommandSpecParts, DryRun, DryRunNote,
    FieldDescriptor, FieldEnumValue, FieldName, FieldPresence, FieldType, HelpText,
    MAX_COMMAND_ALIASES, MAX_COMMAND_FIELDS, MAX_FIELD_ENUM_VALUES, MAX_REGISTRY_COMMANDS,
    MutationDiscipline, MutationKeys, admin_command_registry,
};
use automonique_protocol::wire::JsonValue;

// ---------------------------------------------------------------------------
// Shared builders.
// ---------------------------------------------------------------------------

fn request_id() -> RequestId {
    RequestId::new("req-command-registry-1").expect("a valid correlation identifier")
}

fn text(value: &str) -> HelpText {
    HelpText::new(value).expect("bounded single-line help")
}

fn name(value: &str) -> FieldName {
    FieldName::new(value).expect("a valid field name")
}

fn id(value: &str) -> CommandId {
    CommandId::new(value).expect("a valid command identifier")
}

fn alias(value: &str) -> CommandAlias {
    CommandAlias::new(value).expect("a valid command alias")
}

fn string_field(field: &str, presence: FieldPresence) -> FieldDescriptor {
    FieldDescriptor::new(
        name(field),
        FieldType::bounded_string(64).expect("a non-zero ceiling"),
        presence,
        text("bounded text"),
    )
}

fn integer_field(field: &str) -> FieldDescriptor {
    FieldDescriptor::new(
        name(field),
        FieldType::integer(1, i64::MAX).expect("an ordered range"),
        FieldPresence::Required,
        text("a positive coordinate"),
    )
}

/// A read-only spec with no fields, used where only the identity matters.
fn read_only(command: &str, aliases: &[&str]) -> Result<CommandSpec, CommandRegistryError> {
    CommandSpec::new(CommandSpecParts {
        id: id(command),
        aliases: aliases.iter().copied().map(alias).collect(),
        summary: text("a described command"),
        fields: Vec::new(),
        authorization: AuthorizationRequirement::LocalPeer,
        approval: ApprovalPolicy::None,
        dry_run: DryRun::Unsupported,
        mutation: MutationDiscipline::ReadOnly,
    })
}

fn spec_with(
    fields: Vec<FieldDescriptor>,
    mutation: MutationDiscipline,
) -> Result<CommandSpec, CommandRegistryError> {
    CommandSpec::new(CommandSpecParts {
        id: id("subject"),
        aliases: Vec::new(),
        summary: text("a described command"),
        fields,
        authorization: AuthorizationRequirement::LocalPeer,
        approval: ApprovalPolicy::None,
        dry_run: DryRun::Unsupported,
        mutation,
    })
}

// ---------------------------------------------------------------------------
// The closed admin command surface, restated once and proved complete.
// ---------------------------------------------------------------------------

/// How many commands the closed [`AdminCommand`] enum carries.
const ADMIN_COMMAND_COUNT: usize = 10;

/// Every admin command, in the order the enum declares them.
const EVERY_ADMIN_COMMAND: [AdminCommand; ADMIN_COMMAND_COUNT] = [
    AdminCommand::Status,
    AdminCommand::SubmitSynthetic,
    AdminCommand::SubmitRun,
    AdminCommand::InspectReconciliation,
    AdminCommand::FailReconciliation,
    AdminCommand::InspectOutbox,
    AdminCommand::ReconcileOutbox,
    AdminCommand::PauseIntake,
    AdminCommand::ResumeIntake,
    AdminCommand::Shutdown,
];

/// Each command's position in [`EVERY_ADMIN_COMMAND`].
///
/// The match is exhaustive and carries no wildcard, so a new `AdminCommand`
/// variant stops this file compiling rather than silently going undescribed.
/// `the_command_list_is_the_whole_closed_enum` then proves the list really
/// holds every position, so mapping a new variant to a position is not enough
/// on its own either.
fn position(command: AdminCommand) -> usize {
    match command {
        AdminCommand::Status => 0,
        AdminCommand::SubmitSynthetic => 1,
        AdminCommand::SubmitRun => 2,
        AdminCommand::InspectReconciliation => 3,
        AdminCommand::FailReconciliation => 4,
        AdminCommand::InspectOutbox => 5,
        AdminCommand::ReconcileOutbox => 6,
        AdminCommand::PauseIntake => 7,
        AdminCommand::ResumeIntake => 8,
        AdminCommand::Shutdown => 9,
    }
}

/// Every body shape one command can encode.
///
/// `reconcile_outbox` has two: the decision selects which of `receipt_key` and
/// `reason` the body carries, which is exactly why the registry marks those two
/// optional and why the cross-check compares a union and an intersection rather
/// than one key set.
fn representative_requests(command: AdminCommand) -> Vec<AdminRequest> {
    match command {
        AdminCommand::Status => vec![AdminRequest::new(request_id(), AdminCommand::Status)],
        AdminCommand::Shutdown => vec![AdminRequest::new(request_id(), AdminCommand::Shutdown)],
        AdminCommand::SubmitSynthetic => vec![AdminRequest::submit(
            request_id(),
            SyntheticSubmission::new("scope-1", "synthetic-key-1", "do the synthetic thing")
                .expect("a valid synthetic submission"),
        )],
        AdminCommand::SubmitRun => vec![AdminRequest::submit_run(
            request_id(),
            SubmittedRunSpec::sealed(b"canonical-run-spec-document".to_vec(), "run-key-1")
                .expect("a valid custody request"),
        )],
        AdminCommand::InspectReconciliation => {
            vec![AdminRequest::inspect_reconciliation(request_id(), 7).expect("a valid inspection")]
        }
        AdminCommand::FailReconciliation => vec![AdminRequest::fail_reconciliation(
            request_id(),
            ReconciliationFailure::new(7, "generation-old", 4, 9, "decision-key-1", "stale claim")
                .expect("valid coordinates"),
        )],
        AdminCommand::InspectOutbox => {
            vec![AdminRequest::inspect_outbox(request_id(), 11).expect("a valid inspection")]
        }
        AdminCommand::ReconcileOutbox => [
            OutboxReconciliationDecision::Delivered {
                receipt_key: "provider:11".to_owned(),
            },
            OutboxReconciliationDecision::DeadLetter {
                reason: "operator_refused".to_owned(),
            },
        ]
        .into_iter()
        .map(|decision| {
            AdminRequest::reconcile_outbox(
                request_id(),
                OutboxReconciliation::new(OutboxReconciliationParts {
                    outbox_id: 11,
                    expected_generation_id: "generation-old".to_owned(),
                    expected_lease_epoch: 4,
                    expected_lease_token: "lease:11".to_owned(),
                    expected_attempt: 2,
                    expected_revision: 9,
                    decision,
                })
                .expect("valid coordinates"),
            )
        })
        .collect(),
        AdminCommand::PauseIntake => vec![AdminRequest::pause_intake(
            request_id(),
            IntakePause::new("ops:on-call", "database maintenance").expect("a valid pause"),
        )],
        AdminCommand::ResumeIntake => vec![AdminRequest::resume_intake(
            request_id(),
            IntakeResume::new("ops:on-call").expect("a valid resume"),
        )],
    }
}

/// The message kind and sorted body keys the shipped encoder actually writes.
fn encoded(request: &AdminRequest) -> (String, Vec<String>) {
    let message = request.to_message().expect("the request encodes");
    let JsonValue::Object(entries) = message.body().clone() else {
        panic!("an admin command body is an object");
    };
    let mut keys: Vec<String> = entries.into_iter().map(|(key, _)| key).collect();
    keys.sort();
    (message.envelope().kind().as_str().to_owned(), keys)
}

fn declared_names(spec: &CommandSpec, presence: Option<FieldPresence>) -> Vec<String> {
    let mut names: Vec<String> = spec
        .fields()
        .iter()
        .filter(|field| presence.is_none_or(|wanted| field.presence() == wanted))
        .map(|field| field.name().as_str().to_owned())
        .collect();
    names.sort();
    names
}

// ---------------------------------------------------------------------------

mod closed_surface {
    use super::*;

    #[test]
    fn the_command_list_is_the_whole_closed_enum() {
        assert_eq!(EVERY_ADMIN_COMMAND.len(), ADMIN_COMMAND_COUNT);
        let mut occupied = [false; ADMIN_COMMAND_COUNT];
        for command in EVERY_ADMIN_COMMAND {
            let index = position(command);
            assert!(
                index < ADMIN_COMMAND_COUNT,
                "{command:?} claims position {index}, which is outside the list"
            );
            assert!(!occupied[index], "two commands claim position {index}");
            occupied[index] = true;
        }
        assert!(
            occupied.into_iter().all(|seen| seen),
            "a position in the list is unoccupied, so a variant is missing from it"
        );
    }
}

mod anti_drift {
    use super::*;

    /// The heart of R7: the seeded registry measured against the encoder that
    /// produces the wire, not against a list restated in this file.
    ///
    /// A field added to an admin body, removed from one, or made conditional
    /// turns this red on the next run.
    #[test]
    fn every_seeded_spec_declares_the_encoders_own_field_names() {
        let registry = admin_command_registry().expect("the shipped registry builds");
        assert_eq!(
            registry.commands().len(),
            ADMIN_COMMAND_COUNT,
            "the registry describes a different number of commands than the protocol admits"
        );

        for command in EVERY_ADMIN_COMMAND {
            let shapes: Vec<(String, Vec<String>)> = representative_requests(command)
                .iter()
                .map(encoded)
                .collect();
            assert!(!shapes.is_empty(), "{command:?} has no representative body");
            let kind = shapes[0].0.clone();
            assert!(
                shapes.iter().all(|(other, _)| other == &kind),
                "{command:?} encoded more than one message kind"
            );

            let spec = registry
                .lookup(&kind)
                .unwrap_or_else(|| panic!("the registry describes no command named {kind}"));
            assert_eq!(
                spec.id().as_str(),
                kind,
                "the registry resolved {kind} to a command with another identifier"
            );

            let mut union: Vec<String> = Vec::new();
            for (_, keys) in &shapes {
                for key in keys {
                    if !union.contains(key) {
                        union.push(key.clone());
                    }
                }
            }
            union.sort();
            let intersection: Vec<String> = union
                .iter()
                .filter(|key| shapes.iter().all(|(_, keys)| keys.contains(key)))
                .cloned()
                .collect();

            assert_eq!(
                declared_names(spec, None),
                union,
                "{kind}: the declared field names are not the keys the encoder writes"
            );
            assert_eq!(
                declared_names(spec, Some(FieldPresence::Required)),
                intersection,
                "{kind}: the required field names are not the keys every body carries"
            );
        }
    }

    /// A mutation coordinate is a field of the command it belongs to, and the
    /// encoder writes it. `CommandSpec::new` checks the first half; this checks
    /// that the field it names is one the daemon really receives.
    #[test]
    fn every_declared_mutation_coordinate_is_a_key_the_encoder_writes() {
        let registry = admin_command_registry().expect("the shipped registry builds");
        let mut checked = 0_usize;
        for command in EVERY_ADMIN_COMMAND {
            let (kind, keys) = encoded(&representative_requests(command)[0]);
            let spec = registry.lookup(&kind).expect("a described command");
            if let MutationDiscipline::Mutating(mutation_keys) = spec.mutation() {
                for field in [
                    mutation_keys.idempotency_key(),
                    mutation_keys.expected_revision(),
                ]
                .into_iter()
                .flatten()
                {
                    assert!(
                        keys.contains(&field.as_str().to_owned()),
                        "{kind} names mutation coordinate {field}, which its body does not carry"
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(
            checked, 5,
            "the mutating commands stopped declaring the coordinates they used to"
        );
    }

    /// The three disciplines partition the ten commands, and the partition is
    /// stated rather than derived, so reclassifying a command — describing a
    /// write as a read, or dropping a retry key — fails here.
    #[test]
    fn the_mutation_disciplines_partition_the_admin_surface() {
        let registry = admin_command_registry().expect("the shipped registry builds");
        let named = |wanted: fn(&MutationDiscipline) -> bool| -> Vec<&str> {
            registry
                .commands()
                .iter()
                .filter(|spec| wanted(spec.mutation()))
                .map(|spec| spec.id().as_str())
                .collect()
        };

        assert_eq!(
            named(|mutation| matches!(mutation, MutationDiscipline::ReadOnly)),
            ["inspect_outbox", "inspect_reconciliation", "status"],
            "the set of read-only admin commands changed"
        );
        assert_eq!(
            named(|mutation| matches!(mutation, MutationDiscipline::Mutating(_))),
            [
                "fail_reconciliation",
                "reconcile_outbox",
                "submit_run",
                "submit_synthetic"
            ],
            "the set of retry-keyed admin commands changed"
        );
        assert_eq!(
            named(|mutation| matches!(mutation, MutationDiscipline::Unkeyed { .. })),
            ["pause_intake", "resume_intake", "shutdown"],
            "the set of commands exempt from the retry discipline changed"
        );
        assert_eq!(
            registry
                .commands()
                .iter()
                .filter(|spec| spec.mutation().mutates())
                .count(),
            ADMIN_COMMAND_COUNT - 3,
            "a command belongs to no discipline"
        );
    }
}

mod seeded_registry {
    use super::*;

    #[test]
    fn the_shipped_registry_builds_and_carries_its_schema() {
        let registry = admin_command_registry().expect("the shipped registry builds");
        assert_eq!(registry.schema(), COMMAND_REGISTRY_SCHEMA_V1);
        assert_eq!(registry.schema(), "automonique.command-registry/v1");
    }

    #[test]
    fn commands_are_iterated_in_one_stable_order() {
        let registry = admin_command_registry().expect("the shipped registry builds");
        let ids: Vec<&str> = registry
            .commands()
            .iter()
            .map(|spec| spec.id().as_str())
            .collect();
        assert_eq!(
            ids,
            [
                "fail_reconciliation",
                "inspect_outbox",
                "inspect_reconciliation",
                "pause_intake",
                "reconcile_outbox",
                "resume_intake",
                "shutdown",
                "status",
                "submit_run",
                "submit_synthetic",
            ]
        );
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "iteration order is not identifier order");
    }

    /// The aliases a shipped client already spells, and nothing invented.
    #[test]
    fn the_declared_aliases_are_the_ones_a_client_already_uses() {
        let registry = admin_command_registry().expect("the shipped registry builds");
        let mut declared: Vec<(&str, &str)> = Vec::new();
        for spec in registry.commands() {
            for alias in spec.aliases() {
                declared.push((alias.as_str(), spec.id().as_str()));
            }
        }
        assert_eq!(
            declared,
            [
                ("reconcile-fail", "fail_reconciliation"),
                ("outbox-inspect", "inspect_outbox"),
                ("reconcile-inspect", "inspect_reconciliation"),
                ("outbox-reconcile", "reconcile_outbox"),
                ("run-submit", "submit_run"),
                ("submit", "submit_synthetic"),
            ]
        );
    }

    /// Nothing this build ships supports a dry run, and the registry says so
    /// rather than decorating the commands with a flag nothing honours.
    #[test]
    fn no_shipped_command_claims_a_dry_run() {
        let registry = admin_command_registry().expect("the shipped registry builds");
        for spec in registry.commands() {
            assert!(
                !spec.dry_run().supported(),
                "{} claims a dry run the admin protocol has no field for",
                spec.id()
            );
            assert!(spec.dry_run().note().is_none());
        }
    }

    /// Authorization is the peer check and nothing else, on every command.
    #[test]
    fn every_command_requires_exactly_the_authorization_the_daemon_enforces() {
        let registry = admin_command_registry().expect("the shipped registry builds");
        for spec in registry.commands() {
            assert_eq!(spec.authorization(), AuthorizationRequirement::LocalPeer);
        }
        assert_eq!(AuthorizationRequirement::ALL.len(), 1);
    }

    #[test]
    fn the_commands_that_ask_for_operator_confirmation_are_the_destructive_ones() {
        let registry = admin_command_registry().expect("the shipped registry builds");
        let confirmed: Vec<&str> = registry
            .commands()
            .iter()
            .filter(|spec| spec.approval() == ApprovalPolicy::OperatorConfirmation)
            .map(|spec| spec.id().as_str())
            .collect();
        assert_eq!(
            confirmed,
            [
                "fail_reconciliation",
                "pause_intake",
                "reconcile_outbox",
                "shutdown"
            ]
        );
    }

    /// Every alias resolves, which is the runtime half of the type-level fact
    /// that an alias cannot name a command that does not exist.
    #[test]
    fn no_alias_resolves_to_nothing() {
        let registry = admin_command_registry().expect("the shipped registry builds");
        let mut resolved = 0_usize;
        for spec in registry.commands() {
            for alias in spec.aliases() {
                let found = registry
                    .lookup(alias.as_str())
                    .unwrap_or_else(|| panic!("{alias} resolves to nothing"));
                assert_eq!(found.id(), spec.id());
                resolved += 1;
            }
        }
        assert_eq!(resolved, 6, "the alias population changed");
    }
}

mod lookup {
    use super::*;

    #[test]
    fn an_identifier_and_an_alias_resolve_to_the_same_description() {
        let registry = admin_command_registry().expect("the shipped registry builds");
        let by_id = registry
            .lookup("submit_run")
            .expect("the identifier resolves");
        let by_alias = registry.lookup("run-submit").expect("the alias resolves");
        assert_eq!(by_id, by_alias);
        assert_eq!(by_alias.id().as_str(), "submit_run");
    }

    #[test]
    fn an_unknown_name_resolves_to_nothing_rather_than_to_a_guess() {
        let registry = admin_command_registry().expect("the shipped registry builds");
        for unknown in [
            "",
            "submit_ru",
            "submit_runs",
            "SUBMIT_RUN",
            "run submit",
            "run_submit",
            "^submit_run$",
        ] {
            assert!(
                registry.lookup(unknown).is_none(),
                "{unknown} resolved to a command"
            );
        }
    }

    #[test]
    fn one_commands_alias_never_reaches_another_command() {
        let registry = admin_command_registry().expect("the shipped registry builds");
        for spec in registry.commands() {
            for alias in spec.aliases() {
                assert!(
                    registry
                        .commands()
                        .iter()
                        .filter(|other| other.answers_to(alias.as_str()))
                        .count()
                        == 1,
                    "{alias} is answered by more than one command"
                );
            }
        }
    }
}

mod construction_refusals {
    use super::*;

    #[test]
    fn a_duplicate_identifier_is_refused() {
        let error = CommandRegistry::new([
            read_only("probe", &[]).expect("a valid spec"),
            read_only("probe", &[]).expect("a valid spec"),
        ])
        .expect_err("two commands cannot share an identifier");
        assert_eq!(
            error,
            CommandRegistryError::DuplicateCommand {
                id: "probe".to_owned()
            }
        );
        assert_eq!(error.category(), "duplicate_command");
    }

    #[test]
    fn two_commands_claiming_one_alias_are_refused() {
        let error = CommandRegistry::new([
            read_only("probe", &["ping"]).expect("a valid spec"),
            read_only("sound", &["ping"]).expect("a valid spec"),
        ])
        .expect_err("one alias cannot name two commands");
        assert_eq!(
            error,
            CommandRegistryError::AliasCollision {
                alias: "ping".to_owned()
            }
        );
    }

    #[test]
    fn an_alias_that_is_another_commands_identifier_is_refused() {
        let error = CommandRegistry::new([
            read_only("probe", &["sound"]).expect("a valid spec"),
            read_only("sound", &[]).expect("a valid spec"),
        ])
        .expect_err("an alias cannot shadow an identifier");
        assert_eq!(
            error,
            CommandRegistryError::AliasShadowsCommand {
                alias: "sound".to_owned()
            }
        );
    }

    #[test]
    fn an_alias_equal_to_its_own_identifier_is_refused() {
        let error = read_only("probe", &["probe"]).expect_err("an identifier is not an alias");
        assert_eq!(
            error,
            CommandRegistryError::AliasIsOwnId {
                id: "probe".to_owned()
            }
        );
    }

    #[test]
    fn a_repeated_alias_on_one_command_is_refused() {
        let error = read_only("probe", &["ping", "ping"]).expect_err("an alias is declared once");
        assert_eq!(
            error,
            CommandRegistryError::AliasCollision {
                alias: "ping".to_owned()
            }
        );
    }

    #[test]
    fn a_registry_with_no_commands_is_refused() {
        assert_eq!(
            CommandRegistry::new([]).expect_err("a registry describes something"),
            CommandRegistryError::EmptyRegistry
        );
    }

    #[test]
    fn an_unbounded_command_count_is_refused() {
        let specs: Vec<CommandSpec> = (0..=MAX_REGISTRY_COMMANDS)
            .map(|index| read_only(&format!("c{index}"), &[]).expect("a valid spec"))
            .collect();
        assert_eq!(specs.len(), MAX_REGISTRY_COMMANDS + 1);
        assert_eq!(
            CommandRegistry::new(specs.clone()).expect_err("the ceiling holds"),
            CommandRegistryError::TooMany {
                field: "commands",
                max: MAX_REGISTRY_COMMANDS,
                actual: MAX_REGISTRY_COMMANDS + 1,
            }
        );
        assert!(
            CommandRegistry::new(specs[..MAX_REGISTRY_COMMANDS].to_vec()).is_ok(),
            "the ceiling itself is accepted"
        );
    }

    #[test]
    fn an_unbounded_field_count_is_refused() {
        let fields: Vec<FieldDescriptor> = (0..=MAX_COMMAND_FIELDS)
            .map(|index| string_field(&format!("f{index}"), FieldPresence::Required))
            .collect();
        assert_eq!(
            spec_with(fields, MutationDiscipline::ReadOnly).expect_err("the ceiling holds"),
            CommandRegistryError::TooMany {
                field: "fields",
                max: MAX_COMMAND_FIELDS,
                actual: MAX_COMMAND_FIELDS + 1,
            }
        );
    }

    #[test]
    fn an_unbounded_alias_count_is_refused() {
        let aliases: Vec<String> = (0..=MAX_COMMAND_ALIASES)
            .map(|index| format!("a{index}"))
            .collect();
        let borrowed: Vec<&str> = aliases.iter().map(String::as_str).collect();
        assert_eq!(
            read_only("probe", &borrowed).expect_err("the ceiling holds"),
            CommandRegistryError::TooMany {
                field: "aliases",
                max: MAX_COMMAND_ALIASES,
                actual: MAX_COMMAND_ALIASES + 1,
            }
        );
    }

    #[test]
    fn a_repeated_field_name_is_refused() {
        let error = spec_with(
            vec![
                string_field("actor", FieldPresence::Required),
                string_field("actor", FieldPresence::Optional),
            ],
            MutationDiscipline::ReadOnly,
        )
        .expect_err("one command declares a name once");
        assert_eq!(
            error,
            CommandRegistryError::DuplicateField {
                command: "subject".to_owned(),
                field: "actor".to_owned(),
            }
        );
    }

    #[test]
    fn dry_run_support_without_a_result_note_is_refused() {
        assert_eq!(
            DryRun::declare(true, None).expect_err("support says what it returns"),
            CommandRegistryError::DryRunWithoutNote
        );
        assert_eq!(
            DryRun::declare(
                false,
                Some(DryRunNote::new("the plan").expect("bounded note"))
            )
            .expect_err("a note without support describes nothing"),
            CommandRegistryError::DryRunNoteWithoutSupport
        );
        let supported = DryRun::declare(
            true,
            Some(DryRunNote::new("the effect that would be applied").expect("bounded note")),
        )
        .expect("support with a note");
        assert!(supported.supported());
        assert_eq!(
            supported.note().map(DryRunNote::as_str),
            Some("the effect that would be applied")
        );
    }

    #[test]
    fn a_mutation_with_no_retry_coordinate_is_refused() {
        assert_eq!(
            MutationKeys::new(None, None).expect_err("a mutation must be retryable"),
            CommandRegistryError::MutationWithoutRetryCoordinate
        );
        assert!(MutationKeys::new(Some(name("idempotency_key")), None).is_ok());
        assert!(MutationKeys::new(None, Some(name("expected_revision"))).is_ok());
    }

    #[test]
    fn a_mutation_coordinate_absent_from_the_field_list_is_refused() {
        let keys = MutationKeys::new(Some(name("idempotency_key")), None).expect("one coordinate");
        let error = spec_with(
            vec![string_field("scope", FieldPresence::Required)],
            MutationDiscipline::Mutating(keys),
        )
        .expect_err("a coordinate is a field of its own command");
        assert_eq!(
            error,
            CommandRegistryError::MutationFieldAbsent {
                command: "subject".to_owned(),
                field: "idempotency_key".to_owned(),
            }
        );
    }

    #[test]
    fn an_optional_mutation_coordinate_is_refused() {
        let keys =
            MutationKeys::new(None, Some(name("expected_revision"))).expect("one coordinate");
        let error = spec_with(
            vec![FieldDescriptor::new(
                name("expected_revision"),
                FieldType::integer(1, i64::MAX).expect("an ordered range"),
                FieldPresence::Optional,
                text("a coordinate a caller may omit"),
            )],
            MutationDiscipline::Mutating(keys),
        )
        .expect_err("a coordinate a caller may omit is not a coordinate");
        assert_eq!(
            error,
            CommandRegistryError::MutationFieldOptional {
                command: "subject".to_owned(),
                field: "expected_revision".to_owned(),
            }
        );
    }

    #[test]
    fn a_well_formed_mutation_is_accepted() {
        let keys = MutationKeys::new(
            Some(name("idempotency_key")),
            Some(name("expected_revision")),
        )
        .expect("both coordinates");
        let spec = spec_with(
            vec![
                string_field("idempotency_key", FieldPresence::Required),
                integer_field("expected_revision"),
            ],
            MutationDiscipline::Mutating(keys),
        )
        .expect("a retryable, fenced mutation");
        assert!(spec.mutation().mutates());
    }
}

mod typed_field_refusals {
    use super::*;

    #[test]
    fn a_zero_string_bound_is_refused() {
        assert_eq!(
            FieldType::bounded_string(0).expect_err("a field accepts something"),
            CommandRegistryError::ZeroStringBound
        );
    }

    #[test]
    fn an_inverted_integer_range_is_refused() {
        assert_eq!(
            FieldType::integer(9, 1).expect_err("a range is not inverted"),
            CommandRegistryError::InvertedIntegerRange { min: 9, max: 1 }
        );
        assert!(
            FieldType::integer(5, 5).is_ok(),
            "a single value is a range"
        );
    }

    #[test]
    fn an_empty_or_repeating_enumeration_is_refused() {
        assert_eq!(
            FieldType::enumerated([]).expect_err("an enumeration accepts something"),
            CommandRegistryError::EmptyEnumeration
        );
        assert_eq!(
            FieldType::enumerated([
                FieldEnumValue::new("delivered").expect("a value"),
                FieldEnumValue::new("delivered").expect("a value"),
            ])
            .expect_err("a value is declared once"),
            CommandRegistryError::DuplicateEnumValue {
                value: "delivered".to_owned()
            }
        );
        let many: Vec<FieldEnumValue> = (0..=MAX_FIELD_ENUM_VALUES)
            .map(|index| FieldEnumValue::new(format!("v{index}")).expect("a value"))
            .collect();
        assert_eq!(
            FieldType::enumerated(many).expect_err("the ceiling holds"),
            CommandRegistryError::TooMany {
                field: "enum_values",
                max: MAX_FIELD_ENUM_VALUES,
                actual: MAX_FIELD_ENUM_VALUES + 1,
            }
        );
    }

    #[test]
    fn an_enumeration_renders_in_sorted_order_whatever_order_it_was_declared_in() {
        let ascending = FieldType::enumerated([
            FieldEnumValue::new("dead_letter").expect("a value"),
            FieldEnumValue::new("delivered").expect("a value"),
        ])
        .expect("a valid enumeration");
        let descending = FieldType::enumerated([
            FieldEnumValue::new("delivered").expect("a value"),
            FieldEnumValue::new("dead_letter").expect("a value"),
        ])
        .expect("a valid enumeration");
        assert_eq!(ascending, descending);
        assert_eq!(ascending.describe(), "enum{dead_letter|delivered}");
    }

    #[test]
    fn each_type_has_one_stable_rendering() {
        assert_eq!(
            FieldType::bounded_string(256)
                .expect("a ceiling")
                .describe(),
            "string<=256"
        );
        assert_eq!(
            FieldType::integer(1, i64::MAX).expect("a range").describe(),
            "integer 1..=9223372036854775807"
        );
    }
}

mod grammar {
    use super::*;

    #[test]
    fn a_command_identifier_is_a_dotted_path_of_lowercase_segments() {
        for accepted in [
            "status",
            "submit_run",
            "automonique.admin.submit_run",
            "v2.status",
        ] {
            assert!(
                CommandId::new(accepted).is_ok(),
                "{accepted} was wrongly refused"
            );
        }
        for refused in [
            "",
            "Status",
            "SUBMIT_RUN",
            "submit run",
            "submit-run",
            "1status",
            ".status",
            "status.",
            "a..b",
            "status\n",
        ] {
            assert!(
                CommandId::new(refused).is_err(),
                "{refused:?} was wrongly accepted"
            );
        }
        let overlong = "a".repeat(CommandId::MAX_BYTES + 1);
        assert!(CommandId::new(overlong).is_err());
    }

    #[test]
    fn an_alias_additionally_admits_the_hyphen_a_client_already_spells() {
        assert!(CommandAlias::new("run-submit").is_ok());
        assert!(CommandAlias::new("outbox-reconcile").is_ok());
        assert!(
            CommandId::new("run-submit").is_err(),
            "an identifier is not an alias"
        );
        for refused in ["-run", "Run-Submit", "run submit", ""] {
            assert!(
                CommandAlias::new(refused).is_err(),
                "{refused:?} was wrongly accepted"
            );
        }
    }

    #[test]
    fn a_field_name_has_the_shape_an_admin_body_key_has() {
        for accepted in ["actor", "expected_lease_epoch", "outbox_id"] {
            assert!(FieldName::new(accepted).is_ok(), "{accepted} was refused");
        }
        for refused in ["", "Actor", "outbox-id", "outbox.id", "1st"] {
            assert!(
                FieldName::new(refused).is_err(),
                "{refused:?} was wrongly accepted"
            );
        }
    }

    #[test]
    fn a_named_authorization_scope_this_build_cannot_check_is_refused() {
        assert_eq!(
            AuthorizationRequirement::named("local_peer").expect("the only enforced requirement"),
            AuthorizationRequirement::LocalPeer
        );
        for invented in ["admin_role", "tenant_owner", "operator", "root", ""] {
            assert_eq!(
                AuthorizationRequirement::named(invented)
                    .expect_err("an unenforceable scope is refused"),
                CommandRegistryError::UnenforceableAuthorization {
                    name: invented.to_owned()
                }
            );
        }
    }

    #[test]
    fn a_named_approval_policy_this_build_cannot_represent_is_refused() {
        assert_eq!(
            ApprovalPolicy::named("none").expect("a represented policy"),
            ApprovalPolicy::None
        );
        assert_eq!(
            ApprovalPolicy::named("operator_confirmation").expect("a represented policy"),
            ApprovalPolicy::OperatorConfirmation
        );
        for invented in ["named_approver", "two_person_rule", ""] {
            assert_eq!(
                ApprovalPolicy::named(invented).expect_err("an unrepresented policy is refused"),
                CommandRegistryError::UnenforceableApproval {
                    name: invented.to_owned()
                }
            );
        }
    }

    #[test]
    fn every_refusal_has_its_own_stable_category() {
        let categories = [
            CommandRegistryError::EmptyRegistry.category(),
            CommandRegistryError::EmptyEnumeration.category(),
            CommandRegistryError::ZeroStringBound.category(),
            CommandRegistryError::MutationWithoutRetryCoordinate.category(),
            CommandRegistryError::DryRunWithoutNote.category(),
            CommandRegistryError::DryRunNoteWithoutSupport.category(),
        ];
        let mut distinct = categories.to_vec();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), categories.len());
        assert!(!CommandRegistryError::EmptyRegistry.to_string().is_empty());
    }
}

mod generated_help {
    use super::*;

    /// A registry small enough for its whole generated help to be a reviewable
    /// literal, built to reach every rendering the format has: a command with
    /// no fields and no aliases, one with all three field types and both
    /// presences, both approval policies, both dry-run states, and all three
    /// mutation disciplines.
    fn sample_registry() -> CommandRegistry {
        let probe = CommandSpec::new(CommandSpecParts {
            id: id("probe"),
            aliases: vec![alias("ping")],
            summary: text("Ask the daemon whether it is answering."),
            fields: Vec::new(),
            authorization: AuthorizationRequirement::LocalPeer,
            approval: ApprovalPolicy::None,
            dry_run: DryRun::Unsupported,
            mutation: MutationDiscipline::ReadOnly,
        })
        .expect("a valid read");

        let retire = CommandSpec::new(CommandSpecParts {
            id: id("retire_thing"),
            aliases: vec![alias("thing-retire")],
            summary: text("Retire one thing under the revision the caller expects."),
            fields: vec![
                FieldDescriptor::new(
                    name("expected_revision"),
                    FieldType::integer(1, i64::MAX).expect("a range"),
                    FieldPresence::Required,
                    text("The revision the caller believes it is acting on."),
                ),
                FieldDescriptor::new(
                    name("mode"),
                    FieldType::enumerated([
                        FieldEnumValue::new("hard").expect("a value"),
                        FieldEnumValue::new("soft").expect("a value"),
                    ])
                    .expect("an enumeration"),
                    FieldPresence::Optional,
                    text("Present only when the caller chooses a non-default retirement."),
                ),
                FieldDescriptor::new(
                    name("retire_key"),
                    FieldType::bounded_string(128).expect("a ceiling"),
                    FieldPresence::Required,
                    text("Stable caller-controlled retry key."),
                ),
            ],
            authorization: AuthorizationRequirement::LocalPeer,
            approval: ApprovalPolicy::OperatorConfirmation,
            dry_run: DryRun::declare(
                true,
                Some(
                    DryRunNote::new("the thing that would be retired, and nothing else")
                        .expect("a note"),
                ),
            )
            .expect("support with a note"),
            mutation: MutationDiscipline::Mutating(
                MutationKeys::new(Some(name("retire_key")), Some(name("expected_revision")))
                    .expect("both coordinates"),
            ),
        })
        .expect("a valid mutation");

        let seal = CommandSpec::new(CommandSpecParts {
            id: id("seal"),
            aliases: Vec::new(),
            summary: text("Close the thing for good."),
            fields: Vec::new(),
            authorization: AuthorizationRequirement::LocalPeer,
            approval: ApprovalPolicy::OperatorConfirmation,
            dry_run: DryRun::Unsupported,
            mutation: MutationDiscipline::Unkeyed {
                justification: text("Sealing a sealed thing is the same fact, not a second one."),
            },
        })
        .expect("a valid unkeyed mutation");

        CommandRegistry::new([seal, retire, probe]).expect("a valid registry")
    }

    /// Every byte the sample registry renders. Computed here rather than
    /// read from a fixture, so the expected output is reviewable in the same
    /// diff as the renderer that produces it.
    const SAMPLE_HELP: &str = r#"automonique.command-registry/v1
commands: 3

probe
  summary: Ask the daemon whether it is answering.
  aliases: ping
  authorization: local_peer
  approval: none
  dry run: unsupported
  mutation: read only
  fields: (none)

retire_thing
  summary: Retire one thing under the revision the caller expects.
  aliases: thing-retire
  authorization: local_peer
  approval: operator_confirmation
  dry run: supported; returns the thing that would be retired, and nothing else
  mutation: mutating; idempotency key retire_key; expected revision expected_revision
  fields:
    expected_revision (required, integer 1..=9223372036854775807): The revision the caller believes it is acting on.
    mode (optional, enum{hard|soft}): Present only when the caller chooses a non-default retirement.
    retire_key (required, string<=128): Stable caller-controlled retry key.

seal
  summary: Close the thing for good.
  aliases: (none)
  authorization: local_peer
  approval: operator_confirmation
  dry run: unsupported
  mutation: unkeyed; Sealing a sealed thing is the same fact, not a second one.
  fields: (none)
"#;

    #[test]
    fn the_generated_help_is_byte_exact() {
        assert_eq!(sample_registry().help_text(), SAMPLE_HELP);
    }

    #[test]
    fn the_same_registry_renders_the_same_bytes_twice() {
        let registry = admin_command_registry().expect("the shipped registry builds");
        let first = registry.help_text();
        let second = registry.help_text();
        assert_eq!(first, second);
        assert_eq!(
            first.as_bytes(),
            second.as_bytes(),
            "two renders of one registry disagree"
        );
    }

    /// Declaration order is not rendering order, so a reordered seed cannot
    /// change a byte of the output.
    #[test]
    fn declaration_order_does_not_reach_the_output() {
        let registry = admin_command_registry().expect("the shipped registry builds");
        let mut reversed: Vec<CommandSpec> = registry.commands().to_vec();
        reversed.reverse();
        let rebuilt =
            CommandRegistry::new(reversed).expect("the same commands, declared backwards");
        assert_eq!(rebuilt, registry);
        assert_eq!(rebuilt.help_text(), registry.help_text());
    }

    #[test]
    fn every_seeded_command_alias_and_field_appears_in_the_help() {
        let registry = admin_command_registry().expect("the shipped registry builds");
        let help = registry.help_text();
        assert!(help.starts_with(COMMAND_REGISTRY_SCHEMA_V1));
        assert!(help.contains(&format!("commands: {ADMIN_COMMAND_COUNT}")));
        for spec in registry.commands() {
            assert!(
                help.contains(&format!("\n{}\n", spec.id())),
                "{} has no block in the generated help",
                spec.id()
            );
            assert!(help.contains(spec.summary().as_str()));
            for alias in spec.aliases() {
                assert!(
                    help.contains(alias.as_str()),
                    "{alias} is missing from the generated help"
                );
            }
            for field in spec.fields() {
                assert!(
                    help.contains(&format!("    {} (", field.name())),
                    "{}.{} is missing from the generated help",
                    spec.id(),
                    field.name()
                );
            }
        }
    }

    /// One real command's block, byte for byte, so the format is pinned against
    /// the shipped content and not only against a sample built for the test.
    #[test]
    fn one_seeded_command_renders_exactly_this() {
        let registry = admin_command_registry().expect("the shipped registry builds");
        let help = registry.help_text();
        let block = help
            .split("\n\n")
            .find(|block| block.starts_with("fail_reconciliation\n"))
            .expect("the command has a block");
        assert_eq!(
            block,
            r#"fail_reconciliation
  summary: Explicitly fail one exact old run observation under the daemon's fence.
  aliases: reconcile-fail
  authorization: local_peer
  approval: operator_confirmation
  dry run: unsupported
  mutation: mutating; idempotency key decision_key; expected revision expected_revision
  fields:
    decision_key (required, string<=256): Stable key this fail-only decision is retried under.
    expected_generation_id (required, string<=256): The daemon generation the observation belongs to.
    expected_lease_epoch (required, integer 1..=9223372036854775807): The lease epoch the observation belongs to.
    expected_revision (required, integer 1..=9223372036854775807): The run revision the caller believes it is acting on.
    reason (required, string<=256): Bounded operator account of why the run is failed.
    run_id (required, integer 1..=9223372036854775807): The durable run being failed."#
        );
    }
}
