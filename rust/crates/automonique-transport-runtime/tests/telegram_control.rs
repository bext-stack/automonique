// SPDX-License-Identifier: Elastic-2.0

//! The command layer as a host sees it: a gate, a parser, and a manifest that
//! has to describe the same product the parser accepts.

use automonique_transport_runtime::{
    AllowedUsers, AllowlistError, ArgumentShape, COMMAND_COUNT, CommandKind, CommandRefusal,
    ControlCommand, ControlRef, MAX_ALLOWED_USERS, MAX_COMMAND_TEXT_BYTES, MAX_CONTROL_REF_BYTES,
    MAX_RUN_TASK_BYTES, RunTask, TelegramBotCommand, authorize_and_parse, command_manifest,
    parse_command,
};

fn allowlist() -> AllowedUsers {
    AllowedUsers::new([42, 7]).expect("allowlist")
}

#[test]
fn every_command_in_the_vocabulary_parses_to_its_typed_value() {
    assert_eq!(parse_command("/help"), Ok(ControlCommand::Help));
    assert_eq!(parse_command("/status"), Ok(ControlCommand::Status));
    assert_eq!(parse_command("/runs"), Ok(ControlCommand::Runs));
    assert_eq!(parse_command("/tickets"), Ok(ControlCommand::Tickets));
    assert_eq!(
        parse_command("/ticket SUP-1042"),
        Ok(ControlCommand::Ticket {
            ticket_ref: ControlRef::new("SUP-1042").expect("reference")
        })
    );
    assert_eq!(
        parse_command("/run build the release notes"),
        Ok(ControlCommand::Run {
            task: RunTask::new("build the release notes").expect("task")
        })
    );
    assert_eq!(
        parse_command("/cancel run-01H8"),
        Ok(ControlCommand::Cancel {
            run_ref: ControlRef::new("run-01H8").expect("reference")
        })
    );
    assert_eq!(
        parse_command("/approve approval:9"),
        Ok(ControlCommand::Approve {
            approval_ref: ControlRef::new("approval:9").expect("reference")
        })
    );
    assert_eq!(
        parse_command("/deny approval:9"),
        Ok(ControlCommand::Deny {
            approval_ref: ControlRef::new("approval:9").expect("reference")
        })
    );

    // Approve and deny are different commands over the same reference: a parser
    // that collapsed them would silently turn a refusal into an approval.
    assert_ne!(
        parse_command("/approve approval:9"),
        parse_command("/deny approval:9")
    );
}

#[test]
fn surface_forms_an_operator_actually_types_are_accepted() {
    assert_eq!(parse_command("  /status  "), Ok(ControlCommand::Status));
    assert_eq!(parse_command("/STATUS"), Ok(ControlCommand::Status));
    assert_eq!(
        parse_command("/status@automonique_bot"),
        Ok(ControlCommand::Status)
    );
    assert_eq!(
        parse_command("/run   spaced   out  "),
        Ok(ControlCommand::Run {
            task: RunTask::new("spaced   out").expect("task")
        })
    );
    assert_eq!(
        parse_command("/run@automonique_bot ship it"),
        Ok(ControlCommand::Run {
            task: RunTask::new("ship it").expect("task")
        })
    );
    assert_eq!(
        parse_command("/run line one\nline two"),
        Ok(ControlCommand::Run {
            task: RunTask::new("line one\nline two").expect("task")
        })
    );
}

#[test]
fn unknown_shapes_are_typed_refusals_and_never_a_command() {
    assert_eq!(parse_command(""), Err(CommandRefusal::Empty));
    assert_eq!(parse_command("   \t "), Err(CommandRefusal::Empty));
    assert_eq!(parse_command("status"), Err(CommandRefusal::NotACommand));
    assert_eq!(
        parse_command("hello there"),
        Err(CommandRefusal::NotACommand)
    );
    assert_eq!(parse_command("/"), Err(CommandRefusal::UnknownCommand));
    assert_eq!(
        parse_command("/statuses"),
        Err(CommandRefusal::UnknownCommand)
    );
    assert_eq!(
        parse_command("/shutdown"),
        Err(CommandRefusal::UnknownCommand)
    );
    assert_eq!(
        parse_command("/status@"),
        Err(CommandRefusal::UnknownCommand)
    );
    assert_eq!(
        parse_command("/status@bad!bot"),
        Err(CommandRefusal::UnknownCommand)
    );
    assert_eq!(
        parse_command(&format!("/status@{}", "b".repeat(33))),
        Err(CommandRefusal::UnknownCommand)
    );
    // A well-formed mention followed by text is a command with an argument it
    // does not take, not an unknown command.
    assert_eq!(
        parse_command("/status@automonique_bot now"),
        Err(CommandRefusal::UnexpectedArgument)
    );
    assert_eq!(
        parse_command(&format!("/{}", "n".repeat(64))),
        Err(CommandRefusal::UnknownCommand)
    );
}

#[test]
fn argument_bounds_are_exact_at_the_boundary() {
    assert_eq!(
        parse_command("/status now"),
        Err(CommandRefusal::UnexpectedArgument)
    );
    assert_eq!(
        parse_command("/help me"),
        Err(CommandRefusal::UnexpectedArgument)
    );
    assert_eq!(
        parse_command("/runs 5"),
        Err(CommandRefusal::UnexpectedArgument)
    );
    assert_eq!(
        parse_command("/tickets open"),
        Err(CommandRefusal::UnexpectedArgument)
    );
    assert_eq!(
        parse_command("/ticket"),
        Err(CommandRefusal::MissingArgument)
    );
    assert_eq!(
        parse_command("/ticket SUP-1 SUP-2"),
        Err(CommandRefusal::UnexpectedArgument)
    );
    assert_eq!(
        parse_command("/ticket bad*ref"),
        Err(CommandRefusal::ArgumentInvalid)
    );
    assert_eq!(parse_command("/run"), Err(CommandRefusal::MissingArgument));
    assert_eq!(
        parse_command("/cancel"),
        Err(CommandRefusal::MissingArgument)
    );
    assert_eq!(
        parse_command("/cancel run-1 run-2"),
        Err(CommandRefusal::UnexpectedArgument)
    );
    assert_eq!(
        parse_command("/cancel run 1"),
        Err(CommandRefusal::UnexpectedArgument)
    );
    assert_eq!(
        parse_command("/approve not a ref"),
        Err(CommandRefusal::UnexpectedArgument)
    );
    assert_eq!(
        parse_command("/deny bad*ref"),
        Err(CommandRefusal::ArgumentInvalid)
    );

    let at_task_limit = "t".repeat(MAX_RUN_TASK_BYTES);
    assert_eq!(
        parse_command(&format!("/run {at_task_limit}")),
        Ok(ControlCommand::Run {
            task: RunTask::new(&at_task_limit).expect("task")
        })
    );
    assert_eq!(
        parse_command(&format!("/run {at_task_limit}t")),
        Err(CommandRefusal::ArgumentTooLong)
    );

    let at_ref_limit = "r".repeat(MAX_CONTROL_REF_BYTES);
    assert!(parse_command(&format!("/cancel {at_ref_limit}")).is_ok());
    assert_eq!(
        parse_command(&format!("/cancel {at_ref_limit}r")),
        Err(CommandRefusal::ArgumentTooLong)
    );

    let at_message_limit = "t".repeat(MAX_COMMAND_TEXT_BYTES - "/run ".len());
    assert!(parse_command(&format!("/run {at_message_limit}")).is_err());
    assert_eq!(
        parse_command(&"x".repeat(MAX_COMMAND_TEXT_BYTES + 1)),
        Err(CommandRefusal::MessageTooLong)
    );
    // The message ceiling is checked before anything else, so an over-long
    // message is never scanned for a command name at all.
    assert_eq!(
        parse_command(&format!("/status{}", " ".repeat(MAX_COMMAND_TEXT_BYTES))),
        Err(CommandRefusal::MessageTooLong)
    );
}

#[test]
fn control_characters_never_survive_into_a_typed_command() {
    assert_eq!(
        parse_command("/run bell\u{7}"),
        Err(CommandRefusal::ArgumentInvalid)
    );
    assert_eq!(
        parse_command("/run nul\u{0}byte"),
        Err(CommandRefusal::ArgumentInvalid)
    );
    assert_eq!(
        ControlRef::new("has space").err(),
        Some(CommandRefusal::ArgumentInvalid)
    );
    assert_eq!(
        ControlRef::new("quote\"").err(),
        Some(CommandRefusal::ArgumentInvalid)
    );
    assert_eq!(
        ControlRef::new("").err(),
        Some(CommandRefusal::MissingArgument)
    );
    assert!(ControlRef::new("run-01H8.a:b_c9").is_ok());
}

#[test]
fn the_allowlist_gate_admits_only_configured_users() {
    let allowed = allowlist();
    assert!(allowed.authorize(42));
    assert!(allowed.authorize(7));
    assert!(!allowed.authorize(43));
    assert!(!allowed.authorize(0));
    assert!(!allowed.authorize(-42));
    assert!(!allowed.authorize(i64::MIN));
    assert_eq!(allowed.as_slice(), [7, 42]);
    assert_eq!(allowed.len(), 2);
    assert!(!allowed.is_empty());

    assert_eq!(
        AllowedUsers::new([42, 42, 7])
            .expect("deduplicated")
            .as_slice(),
        [7, 42]
    );
    assert_eq!(AllowedUsers::new([]).err(), Some(AllowlistError::Empty));
    assert_eq!(
        AllowedUsers::new([0]).err(),
        Some(AllowlistError::InvalidUserId)
    );
    assert_eq!(
        AllowedUsers::new([-1]).err(),
        Some(AllowlistError::InvalidUserId)
    );
    assert!(AllowedUsers::new(1..=(MAX_ALLOWED_USERS as i64)).is_ok());
    assert_eq!(
        AllowedUsers::new(1..=(MAX_ALLOWED_USERS as i64 + 1)).err(),
        Some(AllowlistError::TooMany)
    );
}

#[test]
fn authorization_is_decided_before_the_message_is_read() {
    let allowed = allowlist();
    assert_eq!(
        authorize_and_parse(&allowed, 42, "/status"),
        Ok(ControlCommand::Status)
    );

    // Each of these texts has its own distinctive refusal when parsed. From an
    // unauthorized sender every one of them must come back Unauthorized, which
    // is only possible if the gate ran first.
    for (text, parsed_refusal) in [
        ("/status", None),
        ("", Some(CommandRefusal::Empty)),
        ("not a command", Some(CommandRefusal::NotACommand)),
        ("/nonesuch", Some(CommandRefusal::UnknownCommand)),
        ("/run", Some(CommandRefusal::MissingArgument)),
        ("/cancel bad*ref", Some(CommandRefusal::ArgumentInvalid)),
        ("/tickets", None),
        ("/ticket SUP-1042", None),
        ("/ticket", Some(CommandRefusal::MissingArgument)),
    ] {
        if let Some(expected) = parsed_refusal {
            assert_eq!(parse_command(text), Err(expected), "{text:?}");
        }
        assert_eq!(
            authorize_and_parse(&allowed, 99, text),
            Err(CommandRefusal::Unauthorized),
            "{text:?}"
        );
    }

    // Including a message far past the parser's own ceiling: the gate does not
    // let an unauthorized sender reach even the length check.
    assert_eq!(
        authorize_and_parse(&allowed, 99, &"x".repeat(MAX_COMMAND_TEXT_BYTES * 4)),
        Err(CommandRefusal::Unauthorized)
    );
    assert_eq!(
        parse_command(&"x".repeat(MAX_COMMAND_TEXT_BYTES * 4)),
        Err(CommandRefusal::MessageTooLong)
    );
}

#[test]
fn the_manifest_is_exhaustive_over_the_registry_and_round_trips() {
    let manifest = command_manifest();
    assert_eq!(manifest.len(), COMMAND_COUNT);
    assert_eq!(COMMAND_COUNT, CommandKind::ALL.len());

    // Exhaustive: every kind appears exactly once.
    for kind in CommandKind::ALL {
        assert_eq!(
            manifest.iter().filter(|entry| entry.kind == kind).count(),
            1,
            "{kind:?} is not advertised exactly once"
        );
    }

    // The advertised names are the names the parser answers to, and they are
    // the ones an operator has been told to type.
    assert_eq!(
        manifest.map(|entry| entry.name),
        [
            "help", "status", "runs", "tickets", "ticket", "run", "cancel", "approve", "deny"
        ]
    );
    for entry in manifest {
        let typed = match entry.kind.argument() {
            ArgumentShape::None => format!("/{}", entry.name),
            ArgumentShape::Task => format!("/{} do the thing", entry.name),
            ArgumentShape::Reference => format!("/{} reference-1", entry.name),
        };
        assert_eq!(
            parse_command(&typed).as_ref().map(ControlCommand::kind),
            Ok(entry.kind),
            "{typed:?}"
        );
        assert_eq!(entry.name, entry.kind.name());
        assert_eq!(entry.description, entry.kind.description());
    }
}

#[test]
fn every_manifest_entry_is_a_valid_telegram_menu_entry() {
    // The command layer knows nothing about HTTP and the HTTP layer knows
    // nothing about the registry, so this is the seam where a description that
    // Telegram would reject, or a name outside its grammar, becomes visible.
    for entry in command_manifest() {
        assert!(
            TelegramBotCommand::new(entry.name, entry.description).is_ok(),
            "{} is not publishable",
            entry.name
        );
    }
}

#[test]
fn commands_and_refusals_carry_no_operator_content_in_debug() {
    let command = parse_command("/run deploy the secret-sounding thing").expect("command");
    assert!(!format!("{command:?}").contains("secret-sounding"));
    assert!(format!("{command:?}").contains("<redacted"));
    let ControlCommand::Run { task } = &command else {
        panic!("expected a run command");
    };
    assert_eq!(task.as_str(), "deploy the secret-sounding thing");

    for refusal in [
        CommandRefusal::Unauthorized,
        CommandRefusal::MessageTooLong,
        CommandRefusal::ArgumentInvalid,
    ] {
        assert!(!refusal.operator_reply().is_empty());
        assert!(refusal.to_string().contains(refusal.category()));
    }
    assert_eq!(
        CommandRefusal::Unauthorized.operator_reply(),
        "Not authorized."
    );
}
