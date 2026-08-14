// SPDX-License-Identifier: Elastic-2.0

//! The operator command vocabulary, as pure values.
//!
//! This module turns one Telegram message into either a typed
//! [`ControlCommand`] or a typed [`CommandRefusal`], and nothing else. It
//! performs no I/O, holds no state, names no daemon type, and cannot start,
//! cancel, approve or deny anything — the daemon dispatches the value this
//! module returns. That separation is the point: parsing untrusted text and
//! acting on it are different privileges, and only the first one lives here.
//!
//! # The registry is one table
//!
//! [`CommandKind`] is closed, and each kind carries its own [`CommandSpec`] —
//! name, description, argument shape — in a single `const fn`. [`parse_command`]
//! and [`command_manifest`] both read that table, so the menu Telegram
//! advertises and the grammar the parser accepts cannot describe different
//! products. Adding a variant to `CommandKind` fails to compile until the table,
//! `CommandKind::ALL` and the parser's dispatch all name it.
//!
//! # Authorization precedes parsing
//!
//! [`authorize_and_parse`] checks the [`AllowedUsers`] gate *before* it looks at
//! the text at all. A message from a user who is not on the list is refused as
//! [`CommandRefusal::Unauthorized`] whether it was well-formed, malformed, or
//! four kilobytes of noise — the refusal never reports which, because that
//! would answer a question an unauthorized sender is not entitled to ask.
//!
//! # Bounds
//!
//! Every field is bounded before it is stored: the whole message, the run task,
//! and each reference. Refusals are content-free — they name the field and the
//! reason, never the value — so a refusal can be logged or replied to without
//! reflecting a sender's text back at anyone.

use std::error::Error;
use std::fmt;

/// Longest inbound message this parser will look at.
///
/// Telegram's own message ceiling is 4096 UTF-16 units; a longer body did not
/// come from the client and is refused without being scanned.
pub const MAX_COMMAND_TEXT_BYTES: usize = 4096;
/// Longest command name this parser will look up.
pub const MAX_COMMAND_NAME_BYTES: usize = 32;
/// Longest `@bot` suffix accepted after a command name.
pub const MAX_BOT_SUFFIX_BYTES: usize = 32;
/// Longest task text a `/run` may carry.
pub const MAX_RUN_TASK_BYTES: usize = 1024;
/// Longest reference a `/cancel`, `/approve`, `/deny` or `/ticket` may name.
pub const MAX_CONTROL_REF_BYTES: usize = 128;
/// Most Telegram user ids one allowlist may hold.
pub const MAX_ALLOWED_USERS: usize = 256;
/// Number of commands in the closed registry.
pub const COMMAND_COUNT: usize = 9;

const _: () = assert!(COMMAND_COUNT == CommandKind::ALL.len());
const _: () = assert!(MAX_COMMAND_NAME_BYTES <= MAX_COMMAND_TEXT_BYTES);
const _: () = assert!(MAX_RUN_TASK_BYTES < MAX_COMMAND_TEXT_BYTES);
const _: () = assert!(MAX_CONTROL_REF_BYTES < MAX_RUN_TASK_BYTES);

/// What a command takes after its name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArgumentShape {
    /// Nothing. Trailing text is a refusal, not something to ignore.
    None,
    /// One free-text task, bounded by [`MAX_RUN_TASK_BYTES`].
    Task,
    /// Exactly one opaque reference token.
    Reference,
}

/// One row of the closed registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    /// The name an operator types, without its leading slash.
    pub name: &'static str,
    /// The one-line description Telegram advertises.
    pub description: &'static str,
    /// What the parser accepts after the name.
    pub argument: ArgumentShape,
}

/// The closed operator vocabulary.
///
/// Each kind names a capability the control plane already has: a status
/// snapshot, the Runs read surface, the tracked support tickets, run
/// submission, cancellation, and the approval lane's two decisions. Nothing
/// here is aspirational — a kind with no lane behind it would be a command that
/// refuses at dispatch, which is worse than one that does not exist.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CommandKind {
    /// Render the command menu.
    Help,
    /// One daemon status snapshot.
    Status,
    /// List recent runs.
    Runs,
    /// List recently tracked support tickets.
    Tickets,
    /// One tracked support ticket.
    Ticket,
    /// Submit one run.
    Run,
    /// Cancel one run.
    Cancel,
    /// Approve one pending decision.
    Approve,
    /// Deny one pending decision.
    Deny,
}

impl CommandKind {
    /// Every kind, in menu order. The manifest and every exhaustiveness proof
    /// iterate this.
    pub const ALL: [Self; COMMAND_COUNT] = [
        Self::Help,
        Self::Status,
        Self::Runs,
        Self::Tickets,
        Self::Ticket,
        Self::Run,
        Self::Cancel,
        Self::Approve,
        Self::Deny,
    ];

    /// This kind's registry row.
    #[must_use]
    pub const fn spec(self) -> CommandSpec {
        match self {
            Self::Help => CommandSpec {
                name: "help",
                description: "Show the commands this bot accepts",
                argument: ArgumentShape::None,
            },
            Self::Status => CommandSpec {
                name: "status",
                description: "Report the daemon status snapshot",
                argument: ArgumentShape::None,
            },
            Self::Runs => CommandSpec {
                name: "runs",
                description: "List the most recent runs",
                argument: ArgumentShape::None,
            },
            Self::Tickets => CommandSpec {
                name: "tickets",
                description: "List the most recently tracked support tickets",
                argument: ArgumentShape::None,
            },
            Self::Ticket => CommandSpec {
                name: "ticket",
                description: "Show the tracked support ticket with the given reference",
                argument: ArgumentShape::Reference,
            },
            Self::Run => CommandSpec {
                name: "run",
                description: "Submit a run with the given task text",
                argument: ArgumentShape::Task,
            },
            Self::Cancel => CommandSpec {
                name: "cancel",
                description: "Cancel the run with the given reference",
                argument: ArgumentShape::Reference,
            },
            Self::Approve => CommandSpec {
                name: "approve",
                description: "Approve the pending decision with the given reference",
                argument: ArgumentShape::Reference,
            },
            Self::Deny => CommandSpec {
                name: "deny",
                description: "Deny the pending decision with the given reference",
                argument: ArgumentShape::Reference,
            },
        }
    }

    /// The name an operator types, without its leading slash.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.spec().name
    }

    /// The one-line description Telegram advertises.
    #[must_use]
    pub const fn description(self) -> &'static str {
        self.spec().description
    }

    /// What this command accepts after its name.
    #[must_use]
    pub const fn argument(self) -> ArgumentShape {
        self.spec().argument
    }

    /// Look one name up in the closed registry.
    ///
    /// The match is ASCII-case-insensitive: an operator typing `/Status` from a
    /// phone keyboard means `/status`, and there is no second command whose
    /// identity depends on its case.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.name().eq_ignore_ascii_case(name))
    }
}

/// One entry of the advertised command menu.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandManifestEntry {
    /// The kind this entry advertises.
    pub kind: CommandKind,
    /// The name, without its leading slash, as `setMyCommands` wants it.
    pub name: &'static str,
    /// The description `setMyCommands` advertises.
    pub description: &'static str,
}

/// The exact menu to publish with `setMyCommands`.
///
/// Derived from [`CommandKind::ALL`], so it is exhaustive over the registry by
/// construction rather than by review.
#[must_use]
pub fn command_manifest() -> [CommandManifestEntry; COMMAND_COUNT] {
    CommandKind::ALL.map(|kind| CommandManifestEntry {
        kind,
        name: kind.name(),
        description: kind.description(),
    })
}

/// The operator-facing help body, rendered from the same registry.
#[must_use]
pub fn help_text() -> String {
    let mut text = String::from("Commands:");
    for entry in command_manifest() {
        let usage = match entry.kind.argument() {
            ArgumentShape::None => String::new(),
            ArgumentShape::Task => String::from(" <task>"),
            ArgumentShape::Reference => String::from(" <reference>"),
        };
        text.push_str(&format!(
            "\n/{}{} — {}",
            entry.name, usage, entry.description
        ));
    }
    text
}

/// Bounded free text for one submitted run.
///
/// The text is operator content, so `Debug` reports its size and not its bytes.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RunTask(String);

impl RunTask {
    /// Validate one task body.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRefusal::MissingArgument`] when empty,
    /// [`CommandRefusal::ArgumentTooLong`] beyond [`MAX_RUN_TASK_BYTES`], and
    /// [`CommandRefusal::ArgumentInvalid`] for a control character other than
    /// newline or tab.
    pub fn new(text: impl AsRef<str>) -> Result<Self, CommandRefusal> {
        let text = text.as_ref().trim();
        if text.is_empty() {
            return Err(CommandRefusal::MissingArgument);
        }
        if text.len() > MAX_RUN_TASK_BYTES {
            return Err(CommandRefusal::ArgumentTooLong);
        }
        if text
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
        {
            return Err(CommandRefusal::ArgumentInvalid);
        }
        Ok(Self(text.to_owned()))
    }

    /// The validated task text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RunTask {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "RunTask(<redacted:{} bytes>)", self.0.len())
    }
}

/// A bounded, opaque reference to something the daemon owns.
///
/// This module never parses it, derives nothing from it and gives it no
/// structure — it is a run identifier, an approval key or a fleet issue id on
/// its way to the lane that understands it. A reference this grammar admits may
/// still be one no lane recognizes, and answering that is the lane's job: the
/// support ticket store's own identifiers are shorter than this ceiling, so a
/// reference at the ceiling is a ticket nobody recorded rather than a refusal
/// here. The grammar is deliberately narrower than those lanes
/// accept: refusing whitespace, quoting and control characters here means a
/// reference cannot smuggle a second argument, and a legitimate identifier this
/// tight grammar rejects is a reference the operator can still pass through the
/// admin socket.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ControlRef(String);

impl ControlRef {
    /// Validate one reference token.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRefusal::MissingArgument`] when empty,
    /// [`CommandRefusal::ArgumentTooLong`] beyond [`MAX_CONTROL_REF_BYTES`],
    /// and [`CommandRefusal::ArgumentInvalid`] outside the accepted grammar of
    /// ASCII alphanumerics, `-`, `_`, `.` and `:`.
    pub fn new(value: impl AsRef<str>) -> Result<Self, CommandRefusal> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(CommandRefusal::MissingArgument);
        }
        if value.len() > MAX_CONTROL_REF_BYTES {
            return Err(CommandRefusal::ArgumentTooLong);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
        {
            return Err(CommandRefusal::ArgumentInvalid);
        }
        Ok(Self(value.to_owned()))
    }

    /// The validated reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ControlRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ControlRef({})", self.0)
    }
}

impl fmt::Display for ControlRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One typed, inert operator intent.
///
/// Holding this value has no effect. It says what an authorized operator asked
/// for, in a shape the daemon can dispatch; it does not say that the run
/// exists, that the decision is pending, or that the caller may have it — those
/// remain the owning lane's to answer.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ControlCommand {
    /// Render the command menu.
    Help,
    /// Report one daemon status snapshot.
    Status,
    /// List the most recent runs.
    Runs,
    /// List the most recently tracked support tickets.
    Tickets,
    /// Report the tracked support ticket this reference names.
    Ticket {
        /// The fleet issue being asked about.
        ticket_ref: ControlRef,
    },
    /// Submit one run carrying this task text.
    Run {
        /// The bounded task body.
        task: RunTask,
    },
    /// Cancel the run this reference names.
    Cancel {
        /// The run being cancelled.
        run_ref: ControlRef,
    },
    /// Approve the decision this reference names.
    Approve {
        /// The decision being approved.
        approval_ref: ControlRef,
    },
    /// Deny the decision this reference names.
    Deny {
        /// The decision being denied.
        approval_ref: ControlRef,
    },
}

impl ControlCommand {
    /// The registry kind this command belongs to.
    ///
    /// Exhaustive on purpose: a new variant cannot be added without being given
    /// a kind, and therefore a manifest entry and a parse rule.
    #[must_use]
    pub const fn kind(&self) -> CommandKind {
        match self {
            Self::Help => CommandKind::Help,
            Self::Status => CommandKind::Status,
            Self::Runs => CommandKind::Runs,
            Self::Tickets => CommandKind::Tickets,
            Self::Ticket { .. } => CommandKind::Ticket,
            Self::Run { .. } => CommandKind::Run,
            Self::Cancel { .. } => CommandKind::Cancel,
            Self::Approve { .. } => CommandKind::Approve,
            Self::Deny { .. } => CommandKind::Deny,
        }
    }
}

/// Closed refusals for one inbound message.
///
/// Content-free by construction: each names what was wrong, never the text that
/// was wrong, so a refusal is safe to reply with and safe to log.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CommandRefusal {
    /// The sender is not on the allowlist. Decided before the text is read.
    Unauthorized,
    /// The message is empty or only whitespace.
    Empty,
    /// The message is longer than [`MAX_COMMAND_TEXT_BYTES`].
    MessageTooLong,
    /// The message does not begin with `/`, so it is not addressed to us.
    NotACommand,
    /// The name is not in the closed registry.
    UnknownCommand,
    /// The command needs an argument and none was given.
    MissingArgument,
    /// The command was given more argument than its shape admits.
    UnexpectedArgument,
    /// The argument is over its field's ceiling.
    ArgumentTooLong,
    /// The argument is outside its field's accepted grammar.
    ArgumentInvalid,
}

impl CommandRefusal {
    /// Stable, content-free category for logging and metrics.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::Empty => "empty",
            Self::MessageTooLong => "message_too_long",
            Self::NotACommand => "not_a_command",
            Self::UnknownCommand => "unknown_command",
            Self::MissingArgument => "missing_argument",
            Self::UnexpectedArgument => "unexpected_argument",
            Self::ArgumentTooLong => "argument_too_long",
            Self::ArgumentInvalid => "argument_invalid",
        }
    }

    /// A fixed reply an operator surface may send back.
    ///
    /// Every string is a literal. Nothing from the message is echoed, so a
    /// reply cannot be used to make the bot repeat a sender's text into a chat.
    #[must_use]
    pub const fn operator_reply(&self) -> &'static str {
        match self {
            Self::Unauthorized => "Not authorized.",
            Self::Empty => "Send a command, for example /help.",
            Self::MessageTooLong => "That message is too long to read as a command.",
            Self::NotACommand => "Commands start with a slash. Try /help.",
            Self::UnknownCommand => "Unknown command. Try /help.",
            Self::MissingArgument => "That command needs an argument. Try /help.",
            Self::UnexpectedArgument => "That command takes no argument. Try /help.",
            Self::ArgumentTooLong => "That argument is too long.",
            Self::ArgumentInvalid => "That argument is not in an accepted form.",
        }
    }
}

impl fmt::Display for CommandRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Telegram command refused: {}", self.category())
    }
}

impl Error for CommandRefusal {}

/// Refusals from building an allowlist, which is configuration rather than
/// traffic and so cannot be answered with a reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllowlistError {
    /// No user ids were supplied.
    ///
    /// Refused rather than accepted as "nobody": a control surface reachable by
    /// no one is almost always a configuration mistake, and a host that really
    /// wants the bot inert should not construct the gate at all.
    Empty,
    /// More than [`MAX_ALLOWED_USERS`] ids were supplied.
    TooMany,
    /// An id is not a positive Telegram user id.
    InvalidUserId,
}

impl AllowlistError {
    /// Stable, content-free category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::TooMany => "too_many",
            Self::InvalidUserId => "invalid_user_id",
        }
    }
}

impl fmt::Display for AllowlistError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Telegram allowlist refused: {}", self.category())
    }
}

impl Error for AllowlistError {}

/// The closed set of Telegram user ids permitted to command this bot.
///
/// Membership is the whole authority model at this layer: it says a message may
/// be parsed, never that a particular command may run. Per-command authority —
/// which operators may approve, for instance — belongs to the lane that owns
/// the effect, which is the only place it can be enforced against the admin
/// socket as well as against Telegram.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowedUsers(Vec<i64>);

impl AllowedUsers {
    /// Build the gate from configured user ids.
    ///
    /// Ids are sorted and de-duplicated, so membership is a binary search and
    /// two spellings of the same configuration compare equal.
    ///
    /// # Errors
    ///
    /// Returns [`AllowlistError::Empty`], [`AllowlistError::TooMany`] beyond
    /// [`MAX_ALLOWED_USERS`], or [`AllowlistError::InvalidUserId`] for an id
    /// that is not positive.
    pub fn new(user_ids: impl IntoIterator<Item = i64>) -> Result<Self, AllowlistError> {
        let mut ids: Vec<i64> = user_ids.into_iter().collect();
        if ids.iter().any(|id| *id <= 0) {
            return Err(AllowlistError::InvalidUserId);
        }
        ids.sort_unstable();
        ids.dedup();
        if ids.is_empty() {
            return Err(AllowlistError::Empty);
        }
        if ids.len() > MAX_ALLOWED_USERS {
            return Err(AllowlistError::TooMany);
        }
        Ok(Self(ids))
    }

    /// Whether this user may command the bot.
    #[must_use]
    pub fn authorize(&self, user_id: i64) -> bool {
        user_id > 0 && self.0.binary_search(&user_id).is_ok()
    }

    /// The sorted, de-duplicated membership.
    #[must_use]
    pub fn as_slice(&self) -> &[i64] {
        &self.0
    }

    /// How many distinct users may command the bot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always false: an empty allowlist cannot be constructed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Gate one message on its sender, then parse it.
///
/// This is the entry point a host should call. The gate runs first and returns
/// [`CommandRefusal::Unauthorized`] without inspecting the text, so an
/// unauthorized sender learns nothing about the grammar, the registry, or the
/// bounds — and no bounded field is even allocated on their behalf.
///
/// # Errors
///
/// Returns [`CommandRefusal::Unauthorized`] for a sender outside `allowed`, and
/// otherwise whatever [`parse_command`] returns.
pub fn authorize_and_parse(
    allowed: &AllowedUsers,
    user_id: i64,
    text: &str,
) -> Result<ControlCommand, CommandRefusal> {
    if !allowed.authorize(user_id) {
        return Err(CommandRefusal::Unauthorized);
    }
    parse_command(text)
}

/// Parse one `/name args` message into a typed command.
///
/// Accepts Telegram's group addressing form (`/status@some_bot`) by dropping a
/// bounded, well-formed suffix. The suffix is not checked against this bot's
/// username, which this layer does not know; a host serving one bot receives
/// only its own mentions, and a host that wants the stricter check owns the
/// username and can apply it before calling.
///
/// # Errors
///
/// Returns the closed [`CommandRefusal`] vocabulary. It never panics and never
/// unwraps external input.
pub fn parse_command(text: &str) -> Result<ControlCommand, CommandRefusal> {
    if text.len() > MAX_COMMAND_TEXT_BYTES {
        return Err(CommandRefusal::MessageTooLong);
    }
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(CommandRefusal::Empty);
    }
    let body = trimmed
        .strip_prefix('/')
        .ok_or(CommandRefusal::NotACommand)?;
    let (head, rest) = match body.find(char::is_whitespace) {
        Some(boundary) => body.split_at(boundary),
        None => (body, ""),
    };
    let rest = rest.trim();
    let name = strip_bot_suffix(head)?;
    if name.is_empty() || name.len() > MAX_COMMAND_NAME_BYTES {
        return Err(CommandRefusal::UnknownCommand);
    }
    let kind = CommandKind::from_name(name).ok_or(CommandRefusal::UnknownCommand)?;
    match kind {
        CommandKind::Help => no_argument(rest).map(|()| ControlCommand::Help),
        CommandKind::Status => no_argument(rest).map(|()| ControlCommand::Status),
        CommandKind::Runs => no_argument(rest).map(|()| ControlCommand::Runs),
        CommandKind::Tickets => no_argument(rest).map(|()| ControlCommand::Tickets),
        CommandKind::Ticket => {
            one_reference(rest).map(|ticket_ref| ControlCommand::Ticket { ticket_ref })
        }
        CommandKind::Run => RunTask::new(rest).map(|task| ControlCommand::Run { task }),
        CommandKind::Cancel => {
            one_reference(rest).map(|run_ref| ControlCommand::Cancel { run_ref })
        }
        CommandKind::Approve => {
            one_reference(rest).map(|approval_ref| ControlCommand::Approve { approval_ref })
        }
        CommandKind::Deny => {
            one_reference(rest).map(|approval_ref| ControlCommand::Deny { approval_ref })
        }
    }
}

/// Drop a bounded `@bot` suffix, refusing a malformed one.
///
/// A malformed suffix is [`CommandRefusal::UnknownCommand`] rather than an
/// argument refusal: `/status@` names no command in the registry, and saying so
/// reveals less than confirming that `status` was recognized.
fn strip_bot_suffix(head: &str) -> Result<&str, CommandRefusal> {
    let Some((name, suffix)) = head.split_once('@') else {
        return Ok(head);
    };
    if suffix.is_empty()
        || suffix.len() > MAX_BOT_SUFFIX_BYTES
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(CommandRefusal::UnknownCommand);
    }
    Ok(name)
}

fn no_argument(rest: &str) -> Result<(), CommandRefusal> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(CommandRefusal::UnexpectedArgument)
    }
}

/// Accept exactly one reference token and refuse a second.
fn one_reference(rest: &str) -> Result<ControlRef, CommandRefusal> {
    let mut tokens = rest.split_whitespace();
    let first = tokens.next().ok_or(CommandRefusal::MissingArgument)?;
    if tokens.next().is_some() {
        return Err(CommandRefusal::UnexpectedArgument);
    }
    ControlRef::new(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_is_a_closed_lowercase_set_with_distinct_names() {
        let manifest = command_manifest();
        assert_eq!(manifest.len(), COMMAND_COUNT);
        for (index, entry) in manifest.iter().enumerate() {
            assert!(
                entry
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
                "{} is outside Telegram's command grammar",
                entry.name
            );
            assert!(!entry.description.is_empty());
            assert!(
                manifest[..index]
                    .iter()
                    .all(|earlier| earlier.name != entry.name),
                "{} is advertised twice",
                entry.name
            );
        }
    }

    #[test]
    fn help_text_names_every_command_and_its_argument_shape() {
        let text = help_text();
        for entry in command_manifest() {
            assert!(text.contains(&format!("/{}", entry.name)), "{}", entry.name);
            assert!(text.contains(entry.description), "{}", entry.name);
        }
        assert!(text.contains("/run <task>"));
        assert!(text.contains("/cancel <reference>"));
        assert!(text.contains("/ticket <reference>"));
        assert!(!text.contains("/status <"));
        // The two ticket commands differ by one character and by their argument
        // shape, so the help an operator reads has to keep them apart.
        assert!(text.contains("/tickets — "));
    }

    #[test]
    fn the_two_ticket_commands_are_distinct_names_with_distinct_shapes() {
        assert_eq!(parse_command("/tickets"), Ok(ControlCommand::Tickets));
        assert_eq!(
            parse_command("/ticket SUP-1042"),
            Ok(ControlCommand::Ticket {
                ticket_ref: ControlRef::new("SUP-1042").expect("reference")
            })
        );
        // Neither name may be reached by the other's spelling: a plural that
        // parsed as a lookup, or a lookup that parsed as a listing, would answer
        // a question the operator did not ask.
        assert_eq!(
            parse_command("/tickets SUP-1042"),
            Err(CommandRefusal::UnexpectedArgument)
        );
        assert_eq!(
            parse_command("/ticket"),
            Err(CommandRefusal::MissingArgument)
        );
        assert_eq!(
            CommandKind::from_name("tickets"),
            Some(CommandKind::Tickets)
        );
        assert_eq!(CommandKind::from_name("ticket"), Some(CommandKind::Ticket));
        assert_eq!(CommandKind::from_name("ticketss"), None);
    }

    #[test]
    fn every_declared_argument_shape_matches_what_the_parser_accepts() {
        for entry in command_manifest() {
            let bare = parse_command(&format!("/{}", entry.name));
            let with_argument = parse_command(&format!("/{} fixture-ref", entry.name));
            match entry.kind.argument() {
                ArgumentShape::None => {
                    assert_eq!(
                        bare.as_ref().map(ControlCommand::kind),
                        Ok(entry.kind),
                        "{}",
                        entry.name
                    );
                    assert_eq!(
                        with_argument,
                        Err(CommandRefusal::UnexpectedArgument),
                        "{}",
                        entry.name
                    );
                }
                ArgumentShape::Task | ArgumentShape::Reference => {
                    assert_eq!(bare, Err(CommandRefusal::MissingArgument), "{}", entry.name);
                    assert_eq!(
                        with_argument.as_ref().map(ControlCommand::kind),
                        Ok(entry.kind),
                        "{}",
                        entry.name
                    );
                }
            }
        }
    }

    #[test]
    fn refusal_and_allowlist_vocabularies_are_distinct_and_content_free() {
        let categories: Vec<&str> = [
            CommandRefusal::Unauthorized,
            CommandRefusal::Empty,
            CommandRefusal::MessageTooLong,
            CommandRefusal::NotACommand,
            CommandRefusal::UnknownCommand,
            CommandRefusal::MissingArgument,
            CommandRefusal::UnexpectedArgument,
            CommandRefusal::ArgumentTooLong,
            CommandRefusal::ArgumentInvalid,
        ]
        .iter()
        .map(CommandRefusal::category)
        .collect();
        let mut sorted = categories.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), categories.len());
        assert_eq!(
            AllowlistError::InvalidUserId.to_string(),
            "Telegram allowlist refused: invalid_user_id"
        );
    }
}
