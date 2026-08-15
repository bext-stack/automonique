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
//! # Two tiers, one table
//!
//! Being allowed to command the bot and being allowed to command *this* is not
//! the same permission. Every registry row carries a [`CommandTier`], and
//! [`OperatorAuthority`] says which tier a sender carries:
//!
//! - [`CommandTier::Allowed`] — the reads. Anyone the host admits may ask what
//!   this daemon holds.
//! - [`CommandTier::Admin`] — the effects, and user management. A run costs a
//!   provider call, a `/work` writes durable state, and `/admin` decides who
//!   else may be here at all.
//!
//! [`authorize_and_parse_tiered`] resolves the command *name* and then checks
//! the tier, before it parses a single argument. The order matters: a member who
//! types an admin command is told [`CommandRefusal::NotPermitted`] no matter how
//! their arguments were spelled, so the refusal cannot be turned into an oracle
//! for the argument grammar of a command they may not run. The refusal is
//! deliberately distinct from [`CommandRefusal::Unauthorized`]: a member is a
//! known operator being told "not that one", not a stranger being told nothing.
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
/// Longest reference a `/cancel`, `/approve`, `/deny`, `/ticket` or `/work` may
/// name.
pub const MAX_CONTROL_REF_BYTES: usize = 128;
/// Longest configured channel name a `/slack` or `/say` may address.
///
/// A Slack channel name is at most 80 characters, and the name an operator
/// types here is not Slack's anyway — it is the friendly label a host wrote
/// down in its own configuration. The bound is the same so a label can always
/// be spelled the same as the channel it points at.
pub const MAX_CHANNEL_NAME_BYTES: usize = 80;
/// Longest message body one `/say` may carry.
///
/// Far below Slack's own 40,000-character ceiling and below
/// [`MAX_RUN_TASK_BYTES`], because this is text an operator types into a chat
/// on a phone to put in front of other humans, not a task for a model. A longer
/// message is refused rather than truncated: silently posting half of what
/// somebody wrote, to a channel other people read, is the worst available
/// answer.
pub const MAX_SAY_TEXT_BYTES: usize = 900;
/// Longest configured GitHub repository alias accepted by `/github_create`.
pub const MAX_GITHUB_REPO_ALIAS_BYTES: usize = 32;
/// Longest canonical GitHub issue URL accepted by an issue action command.
pub const MAX_GITHUB_ISSUE_URL_BYTES: usize = 512;
/// Longest natural-language request carried by a GitHub create or reply command.
pub const MAX_GITHUB_REQUEST_BYTES: usize = 3_000;
/// Longest checklist item text carried by a GitHub check or uncheck command.
pub const MAX_GITHUB_CHECKLIST_ITEM_BYTES: usize = 1_024;
/// Most Telegram user ids one allowlist may hold.
pub const MAX_ALLOWED_USERS: usize = 256;
/// Longest user id one `/admin` directive may name, in bytes.
///
/// A Telegram user id is a positive `i64`, so nothing legitimate is longer than
/// its decimal spelling. The bound is here so a directive is refused while it is
/// being read rather than after an allocation.
pub const MAX_USER_ID_BYTES: usize = 20;
/// Number of commands in the closed registry.
pub const COMMAND_COUNT: usize = 26;

const _: () = assert!(COMMAND_COUNT == CommandKind::ALL.len());
const _: () = assert!(MAX_COMMAND_NAME_BYTES <= MAX_COMMAND_TEXT_BYTES);
const _: () = assert!(MAX_RUN_TASK_BYTES < MAX_COMMAND_TEXT_BYTES);
const _: () = assert!(MAX_CONTROL_REF_BYTES < MAX_RUN_TASK_BYTES);
const _: () = assert!(MAX_USER_ID_BYTES < MAX_CONTROL_REF_BYTES);
const _: () = assert!(MAX_CHANNEL_NAME_BYTES < MAX_CONTROL_REF_BYTES);
const _: () = assert!(MAX_GITHUB_REPO_ALIAS_BYTES < MAX_GITHUB_ISSUE_URL_BYTES);
const _: () = assert!(MAX_GITHUB_ISSUE_URL_BYTES < MAX_GITHUB_REQUEST_BYTES);
const _: () = assert!(MAX_GITHUB_CHECKLIST_ITEM_BYTES < MAX_GITHUB_REQUEST_BYTES);
// A `/say` is one Telegram message carrying one channel name and one body, so
// the two together have to fit inside the message this parser will look at.
const _: () = assert!(MAX_SAY_TEXT_BYTES + MAX_CHANNEL_NAME_BYTES < MAX_COMMAND_TEXT_BYTES);

/// What a command takes after its name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArgumentShape {
    /// Nothing. Trailing text is a refusal, not something to ignore.
    None,
    /// One free-text task, bounded by [`MAX_RUN_TASK_BYTES`].
    Task,
    /// Exactly one opaque reference token.
    Reference,
    /// One [`AdminDirective`]: a subcommand and, for two of the three, a user
    /// id.
    ///
    /// The one shape whose grammar is closed on both tokens. `/admin` manages
    /// who may command this bot, so admitting a free-form argument there and
    /// letting a dispatcher work out what it meant is exactly the wrong shape
    /// for the one command that changes the allowlist.
    Directive,
    /// One [`ChannelName`], and nothing after it.
    ///
    /// Distinct from [`Self::Reference`] because a channel name is not an
    /// opaque token this layer passes through: it is a label the *host's own*
    /// configuration has to carry, and its grammar is what stops a Slack
    /// conversation id — or anything else with a `C0…` shape — being typed
    /// straight at the connector from a chat.
    Channel,
    /// One [`ChannelName`] and then one bounded [`SayText`] body.
    ///
    /// The only shape with two fields, and the only one whose second field is
    /// free text an operator wrote to be read by people outside this system.
    ChannelMessage,
    /// A closed memory subcommand with an optional bounded query.
    MemoryDirective,
    /// One configured GitHub repository alias and a bounded free-text request.
    GitHubRepositoryRequest,
    /// One exact GitHub issue URL and a bounded reply or checklist item.
    GitHubIssueRequest,
}

/// Which tier of operator a command belongs to.
///
/// Ordered, and the order is the rule: a sender may run a command when the tier
/// they carry is at least the tier the command declares. There is no third
/// value, and adding one would mean deciding what it can do to durable state
/// before it is written down here.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CommandTier {
    /// Any user the host admits at all. Every one of these is a read.
    Allowed,
    /// An administrator. Effects, spend, and user management.
    Admin,
}

impl CommandTier {
    /// Stable, content-free spelling for logs and help.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Admin => "admin",
        }
    }
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
    /// The lowest operator tier that may run it.
    pub tier: CommandTier,
}

/// The closed operator vocabulary.
///
/// Each kind names a capability the control plane already has: a status
/// snapshot, the Runs read surface, the tracked support tickets, working one of
/// them into a draft, run submission, cancellation, and the approval lane's two
/// decisions. Nothing here is aspirational — a kind with no lane behind it would
/// be a command that refuses at dispatch, which is worse than one that does not
/// exist.
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
    /// Work one tracked support ticket into a draft answer.
    Work,
    /// Submit one run.
    Run,
    /// Cancel one run.
    Cancel,
    /// Approve one pending decision.
    Approve,
    /// Deny one pending decision.
    Deny,
    /// Manage the non-admin members who may command this bot.
    Admin,
    /// Read one configured Slack channel's recent messages.
    Slack,
    /// Post one message to a configured Slack channel.
    Say,
    /// Inspect, search and review durable memories.
    Memory,
    /// Record one actor-supplied durable memory.
    Remember,
    /// Tombstone one durable memory by reference.
    Forget,
    /// Start a fresh conversation while preserving long-term memory.
    New,
    /// Create one GitHub issue in a configured repository.
    GitHubCreate,
    /// Reply to one exact GitHub issue.
    GitHubReply,
    /// Check one checklist item on an exact GitHub issue.
    GitHubCheck,
    /// Uncheck one checklist item on an exact GitHub issue.
    GitHubUncheck,
    /// Manage issue and pull-request metadata without entering `/ticket`.
    GitHubIssue,
    /// Manage repository label definitions or assignments.
    GitHubLabel,
    /// Manage repository milestone definitions or assignments.
    GitHubMilestone,
    /// Manage native parent, sub-issue, and dependency relationships.
    GitHubEpic,
    /// Manage GitHub Projects, fields, views, and items.
    GitHubProject,
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
        Self::Slack,
        Self::Memory,
        Self::Remember,
        Self::Forget,
        Self::New,
        Self::GitHubCreate,
        Self::GitHubReply,
        Self::GitHubCheck,
        Self::GitHubUncheck,
        Self::GitHubIssue,
        Self::GitHubLabel,
        Self::GitHubMilestone,
        Self::GitHubEpic,
        Self::GitHubProject,
        Self::Work,
        Self::Run,
        Self::Say,
        Self::Cancel,
        Self::Approve,
        Self::Deny,
        Self::Admin,
    ];

    /// This kind's registry row.
    ///
    /// The `tier` column is the whole authority model of this surface, so it is
    /// worth reading as a table rather than as ten separate decisions:
    ///
    /// | command | tier | why |
    /// |---|---|---|
    /// | `/help` | allowed | the vocabulary itself |
    /// | `/status` | allowed | a read of durable state |
    /// | `/runs` | allowed | a read of the run index |
    /// | `/tickets` | allowed | a read of the ticket store |
    /// | `/ticket` | allowed | a read of one ticket |
    /// | `/slack` | allowed | a read of a channel the host already configured |
    /// | `/work` | admin | spends a provider call and writes a draft |
    /// | `/run` | admin | spends a provider call |
    /// | `/say` | admin | puts text in front of everyone in a Slack channel |
    /// | `/cancel` | admin | ends somebody else's run |
    /// | `/approve` | admin | a decision with an effect behind it |
    /// | `/deny` | admin | the same decision, the other way |
    /// | `/admin` | admin | decides who may be here at all |
    ///
    /// The line between the two is *spend and effect*, not sensitivity: a member
    /// can already read everything the reads report, and the thing an owner
    /// cannot un-spend is a provider call.
    ///
    /// `/say` is the clearest case on the admin side and the one that says what
    /// the line is really about. It spends nothing and writes nothing durable
    /// here — and it is still admin-only, because it is the only command whose
    /// effect is visible to people who are not operators of this system at all.
    /// An unsend does not exist.
    #[must_use]
    pub const fn spec(self) -> CommandSpec {
        match self {
            Self::Help => CommandSpec {
                name: "help",
                description: "Show the commands this bot accepts",
                argument: ArgumentShape::None,
                tier: CommandTier::Allowed,
            },
            Self::Status => CommandSpec {
                name: "status",
                description: "Report the daemon status snapshot",
                argument: ArgumentShape::None,
                tier: CommandTier::Allowed,
            },
            Self::Runs => CommandSpec {
                name: "runs",
                description: "List the most recent runs",
                argument: ArgumentShape::None,
                tier: CommandTier::Allowed,
            },
            Self::Tickets => CommandSpec {
                name: "tickets",
                description: "List the most recently tracked support tickets",
                argument: ArgumentShape::None,
                tier: CommandTier::Allowed,
            },
            Self::Ticket => CommandSpec {
                name: "ticket",
                description: "Show the tracked support ticket with the given reference",
                argument: ArgumentShape::Reference,
                tier: CommandTier::Allowed,
            },
            Self::Slack => CommandSpec {
                name: "slack",
                description: "Read a Slack channel or list configured channels",
                argument: ArgumentShape::Channel,
                tier: CommandTier::Allowed,
            },
            Self::Say => CommandSpec {
                name: "say",
                description: "Post a message to the named Slack channel",
                argument: ArgumentShape::ChannelMessage,
                tier: CommandTier::Admin,
            },
            Self::Memory => CommandSpec {
                name: "memory",
                description: "Inspect, search or review durable memories",
                argument: ArgumentShape::MemoryDirective,
                tier: CommandTier::Admin,
            },
            Self::Remember => CommandSpec {
                name: "remember",
                description: "Record one explicit personal memory",
                argument: ArgumentShape::Task,
                tier: CommandTier::Admin,
            },
            Self::Forget => CommandSpec {
                name: "forget",
                description: "Forget the memory with the given reference",
                argument: ArgumentShape::Reference,
                tier: CommandTier::Admin,
            },
            Self::New => CommandSpec {
                name: "new",
                description: "Start a new conversation",
                argument: ArgumentShape::None,
                tier: CommandTier::Admin,
            },
            Self::GitHubCreate => CommandSpec {
                name: "github_create",
                description: "Create an issue in a configured GitHub repository",
                argument: ArgumentShape::GitHubRepositoryRequest,
                tier: CommandTier::Admin,
            },
            Self::GitHubReply => CommandSpec {
                name: "github_reply",
                description: "Reply to an exact GitHub issue URL",
                argument: ArgumentShape::GitHubIssueRequest,
                tier: CommandTier::Admin,
            },
            Self::GitHubCheck => CommandSpec {
                name: "github_check",
                description: "Check one item on an exact GitHub issue",
                argument: ArgumentShape::GitHubIssueRequest,
                tier: CommandTier::Admin,
            },
            Self::GitHubUncheck => CommandSpec {
                name: "github_uncheck",
                description: "Uncheck one item on an exact GitHub issue",
                argument: ArgumentShape::GitHubIssueRequest,
                tier: CommandTier::Admin,
            },
            Self::GitHubIssue => {
                github_management_spec("github_issue", "Manage GitHub issues or pull requests")
            }
            Self::GitHubLabel => github_management_spec("github_label", "Manage GitHub labels"),
            Self::GitHubMilestone => {
                github_management_spec("github_milestone", "Manage GitHub milestones")
            }
            Self::GitHubEpic => {
                github_management_spec("github_epic", "Manage GitHub native epics and dependencies")
            }
            Self::GitHubProject => {
                github_management_spec("github_project", "Manage GitHub Projects")
            }
            Self::Work => CommandSpec {
                name: "work",
                description: "Draft an answer to the support ticket with the given reference",
                argument: ArgumentShape::Reference,
                tier: CommandTier::Admin,
            },
            Self::Run => CommandSpec {
                name: "run",
                description: "Submit a run with the given task text",
                argument: ArgumentShape::Task,
                tier: CommandTier::Admin,
            },
            Self::Cancel => CommandSpec {
                name: "cancel",
                description: "Cancel the run with the given reference",
                argument: ArgumentShape::Reference,
                tier: CommandTier::Admin,
            },
            Self::Approve => CommandSpec {
                name: "approve",
                description: "Approve the pending decision with the given reference",
                argument: ArgumentShape::Reference,
                tier: CommandTier::Admin,
            },
            Self::Deny => CommandSpec {
                name: "deny",
                description: "Deny the pending decision with the given reference",
                argument: ArgumentShape::Reference,
                tier: CommandTier::Admin,
            },
            Self::Admin => CommandSpec {
                name: "admin",
                description: "Manage members: add <user_id>, remove <user_id>, or list",
                argument: ArgumentShape::Directive,
                tier: CommandTier::Admin,
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

    /// The lowest operator tier that may run this command.
    #[must_use]
    pub const fn tier(self) -> CommandTier {
        self.spec().tier
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

const fn github_management_spec(name: &'static str, description: &'static str) -> CommandSpec {
    CommandSpec {
        name,
        description,
        argument: ArgumentShape::Task,
        tier: CommandTier::Admin,
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
    /// The lowest tier that may run it.
    ///
    /// Advertised rather than hidden. Telegram publishes one menu per bot and
    /// this build does not scope it per user, so a member would see the admin
    /// commands in their client whatever this field said; carrying the tier
    /// means the help text can say which ones will refuse them, instead of
    /// letting them find out by being refused.
    pub tier: CommandTier,
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
        tier: kind.tier(),
    })
}

/// What the help marks an admin-only command with.
pub const ADMIN_HELP_MARK: &str = " [admin]";

/// The operator-facing help body, rendered from the same registry.
///
/// One body for both tiers. A member reading it sees the whole vocabulary with
/// the admin-only half marked, which is the honest rendering of a menu Telegram
/// publishes to everyone anyway — and it is how a member learns that the thing
/// to do about `/run` is to ask an administrator, rather than that the bot is
/// broken.
#[must_use]
pub fn help_text() -> String {
    let mut text = String::from("Commands:");
    for entry in command_manifest() {
        let usage = match entry.kind.argument() {
            ArgumentShape::None => String::new(),
            ArgumentShape::Task => String::from(" <task>"),
            ArgumentShape::Reference => String::from(" <reference>"),
            ArgumentShape::Directive => String::from(" <add|remove|list> [user_id]"),
            ArgumentShape::Channel if entry.kind == CommandKind::Slack => {
                String::from(" <channel|list>")
            }
            ArgumentShape::Channel => String::from(" <channel>"),
            ArgumentShape::ChannelMessage => String::from(" <channel> <message>"),
            ArgumentShape::MemoryDirective => String::from(
                " [search <query>|show <id>|proposals|approve <id>|deny <id>|sources <id>|link]",
            ),
            ArgumentShape::GitHubRepositoryRequest => String::from(" <repository> <request>"),
            ArgumentShape::GitHubIssueRequest => match entry.kind {
                CommandKind::GitHubReply => String::from(" <issue-url> <reply>"),
                CommandKind::GitHubCheck | CommandKind::GitHubUncheck => {
                    String::from(" <issue-url> <item>")
                }
                _ => String::from(" <issue-url> <request>"),
            },
        };
        let mark = match entry.tier {
            CommandTier::Allowed => "",
            CommandTier::Admin => ADMIN_HELP_MARK,
        };
        text.push_str(&format!(
            "\n/{}{} — {}{}",
            entry.name, usage, entry.description, mark
        ));
    }
    text.push_str(
        "\n\nAdministrators can also ask read-only questions in ordinary language. Answers use the daemon's current ticket and status snapshot; actions still require an explicit command.",
    );
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

/// One closed `/memory` operation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MemoryDirective {
    Summary,
    Search { query: RunTask },
    Show { memory_ref: ControlRef },
    Proposals,
    Approve { memory_ref: ControlRef },
    Deny { memory_ref: ControlRef },
    Sources { memory_ref: ControlRef },
    Link,
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

/// The friendly name of one Slack channel, as a host wrote it down.
///
/// **Not a Slack channel id, and deliberately unable to be one.** The grammar
/// is ASCII lowercase letters, digits, `-` and `_`, which is Slack's own
/// channel-name grammar and excludes nothing an operator would type — but the
/// name never reaches Slack either way. It is a key into a map the host's
/// configuration owns, and only the id that map yields is ever addressed. So a
/// sender who types a conversation id, a URL, or a name the host never
/// configured addresses nothing: there is no code path from this value to a
/// request except through the configured map.
///
/// A leading `#` is dropped, because that is how everybody writes a channel and
/// refusing it would be pedantry. The name is lowercased, which is what Slack
/// does to its own channel names, so `#Ops` and `ops` are the same key.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChannelName(String);

impl ChannelName {
    /// Validate one channel name.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRefusal::MissingArgument`] when empty,
    /// [`CommandRefusal::ArgumentTooLong`] beyond [`MAX_CHANNEL_NAME_BYTES`],
    /// and [`CommandRefusal::ArgumentInvalid`] outside the accepted grammar.
    pub fn new(value: impl AsRef<str>) -> Result<Self, CommandRefusal> {
        let value = value.as_ref().strip_prefix('#').unwrap_or(value.as_ref());
        if value.is_empty() {
            return Err(CommandRefusal::MissingArgument);
        }
        if value.len() > MAX_CHANNEL_NAME_BYTES {
            return Err(CommandRefusal::ArgumentTooLong);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(CommandRefusal::ArgumentInvalid);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// The validated, lowercased name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ChannelName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ChannelName({})", self.0)
    }
}

impl fmt::Display for ChannelName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Bounded text one `/say` would post to a Slack channel.
///
/// The one field on this surface whose content leaves the system, so it is the
/// one with the tightest reason to be bounded and checked here rather than at
/// the connector: a refusal at this layer is a reply in the chat the operator
/// is already looking at, while a refusal at the connector is a failed call
/// they have to interpret.
///
/// Newline and tab are admitted because a posted message is multi-line; every
/// other control character is refused. The text is *not* trimmed of its
/// interior and is never reformatted — what an operator typed is what would be
/// posted. Like [`RunTask`], `Debug` reports its size and not its bytes.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SayText(String);

impl SayText {
    /// Validate one message body.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRefusal::MissingArgument`] when empty,
    /// [`CommandRefusal::ArgumentTooLong`] beyond [`MAX_SAY_TEXT_BYTES`], and
    /// [`CommandRefusal::ArgumentInvalid`] for a control character other than
    /// newline or tab.
    pub fn new(text: impl AsRef<str>) -> Result<Self, CommandRefusal> {
        let text = text.as_ref().trim();
        if text.is_empty() {
            return Err(CommandRefusal::MissingArgument);
        }
        if text.len() > MAX_SAY_TEXT_BYTES {
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

    /// The validated message text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SayText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SayText(<redacted:{} bytes>)", self.0.len())
    }
}

/// A bounded friendly alias for one repository configured by the host.
///
/// This is deliberately not an `owner/repo` pair. The daemon must resolve the
/// alias through owner-managed configuration before an action can address a
/// repository, keeping raw chat input away from repository selection.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GitHubRepoAlias(String);

impl GitHubRepoAlias {
    /// Validate and normalize one configured repository alias.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRefusal::MissingArgument`] when empty,
    /// [`CommandRefusal::ArgumentTooLong`] beyond
    /// [`MAX_GITHUB_REPO_ALIAS_BYTES`], and
    /// [`CommandRefusal::ArgumentInvalid`] outside ASCII letters, digits,
    /// hyphen and underscore.
    pub fn new(value: impl AsRef<str>) -> Result<Self, CommandRefusal> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(CommandRefusal::MissingArgument);
        }
        if value.len() > MAX_GITHUB_REPO_ALIAS_BYTES {
            return Err(CommandRefusal::ArgumentTooLong);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(CommandRefusal::ArgumentInvalid);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    /// The normalized alias to resolve in host configuration.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GitHubRepoAlias {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GitHubRepoAlias({})", self.0)
    }
}

impl fmt::Display for GitHubRepoAlias {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One bounded canonical URL naming exactly one GitHub issue.
///
/// The accepted path is exactly
/// `https://github.com/<owner>/<repo>/issues/<positive-number>`. Query strings,
/// fragments, trailing slashes and alternate hosts are refused here. Repository
/// authorization and full repository-name parsing remain the daemon's job.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GitHubIssueUrl(String);

impl GitHubIssueUrl {
    /// Validate one exact public GitHub issue URL.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRefusal::MissingArgument`] when empty,
    /// [`CommandRefusal::ArgumentTooLong`] beyond
    /// [`MAX_GITHUB_ISSUE_URL_BYTES`], and
    /// [`CommandRefusal::ArgumentInvalid`] for any other URL shape.
    pub fn new(value: impl AsRef<str>) -> Result<Self, CommandRefusal> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(CommandRefusal::MissingArgument);
        }
        if value.len() > MAX_GITHUB_ISSUE_URL_BYTES {
            return Err(CommandRefusal::ArgumentTooLong);
        }
        let Some(path) = value.strip_prefix("https://github.com/") else {
            return Err(CommandRefusal::ArgumentInvalid);
        };
        let mut segments = path.split('/');
        let (Some(owner), Some(repo), Some("issues"), Some(issue_number), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return Err(CommandRefusal::ArgumentInvalid);
        };
        if !valid_github_path_segment(owner)
            || !valid_github_path_segment(repo)
            || issue_number.is_empty()
            || !issue_number.bytes().all(|byte| byte.is_ascii_digit())
            || issue_number
                .parse::<u64>()
                .ok()
                .filter(|number| *number > 0)
                .is_none()
        {
            return Err(CommandRefusal::ArgumentInvalid);
        }
        Ok(Self(value.to_owned()))
    }

    /// The exact validated issue URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_github_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

impl fmt::Debug for GitHubIssueUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "GitHubIssueUrl(<redacted:{} bytes>)",
            self.0.len()
        )
    }
}

impl fmt::Display for GitHubIssueUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Bounded natural-language instructions for creating or replying to an issue.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GitHubRequest(String);

impl GitHubRequest {
    /// Validate one request body.
    ///
    /// # Errors
    ///
    /// Returns the same content-free refusals as [`RunTask::new`], using
    /// [`MAX_GITHUB_REQUEST_BYTES`] as the length ceiling.
    pub fn new(text: impl AsRef<str>) -> Result<Self, CommandRefusal> {
        bounded_github_text(text.as_ref(), MAX_GITHUB_REQUEST_BYTES).map(Self)
    }

    /// The validated request text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GitHubRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "GitHubRequest(<redacted:{} bytes>)",
            self.0.len()
        )
    }
}

/// Bounded text identifying one checklist item in an issue or comment.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GitHubChecklistItem(String);

impl GitHubChecklistItem {
    /// Validate one checklist item label.
    ///
    /// # Errors
    ///
    /// Returns the same content-free refusals as [`RunTask::new`], using
    /// [`MAX_GITHUB_CHECKLIST_ITEM_BYTES`] as the length ceiling.
    pub fn new(text: impl AsRef<str>) -> Result<Self, CommandRefusal> {
        bounded_github_text(text.as_ref(), MAX_GITHUB_CHECKLIST_ITEM_BYTES).map(Self)
    }

    /// The exact validated checklist label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GitHubChecklistItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "GitHubChecklistItem(<redacted:{} bytes>)",
            self.0.len()
        )
    }
}

fn bounded_github_text(text: &str, max_bytes: usize) -> Result<String, CommandRefusal> {
    let text = text.trim();
    if text.is_empty() {
        return Err(CommandRefusal::MissingArgument);
    }
    if text.len() > max_bytes {
        return Err(CommandRefusal::ArgumentTooLong);
    }
    if text
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err(CommandRefusal::ArgumentInvalid);
    }
    Ok(text.to_owned())
}

/// One validated Telegram user id, named in an `/admin` directive.
///
/// A newtype rather than a bare `i64` because it crosses a boundary where the
/// difference matters: everything downstream of this value treats it as
/// somebody who may be given or refused access to a control surface, and an
/// unvalidated integer that reached that far could name user zero, a negative
/// id, or a chat.
///
/// Validating it here does not mean the id names anybody. Telegram has no
/// lookup this parser could perform and none it *should* — a directive naming a
/// user who does not exist adds a row nobody will ever match, which is inert.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperatorUserId(i64);

impl OperatorUserId {
    /// Validate one user id.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRefusal::ArgumentInvalid`] for anything that is not a
    /// positive `i64`, which is what a Telegram user id is.
    pub const fn new(user_id: i64) -> Result<Self, CommandRefusal> {
        if user_id <= 0 {
            return Err(CommandRefusal::ArgumentInvalid);
        }
        Ok(Self(user_id))
    }

    /// Parse one decimal user id token.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRefusal::MissingArgument`] when empty,
    /// [`CommandRefusal::ArgumentTooLong`] beyond [`MAX_USER_ID_BYTES`], and
    /// [`CommandRefusal::ArgumentInvalid`] for anything that is not a positive
    /// decimal integer. A leading `+` or `-`, whitespace and separators are all
    /// refused: there is exactly one spelling of an id.
    pub fn parse(token: &str) -> Result<Self, CommandRefusal> {
        if token.is_empty() {
            return Err(CommandRefusal::MissingArgument);
        }
        if token.len() > MAX_USER_ID_BYTES {
            return Err(CommandRefusal::ArgumentTooLong);
        }
        if !token.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(CommandRefusal::ArgumentInvalid);
        }
        let parsed = token
            .parse::<i64>()
            .map_err(|_| CommandRefusal::ArgumentInvalid)?;
        Self::new(parsed)
    }

    /// The validated id.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl fmt::Display for OperatorUserId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// What one `/admin` asked for.
///
/// Closed, and closed at three: adding a member, revoking one, and reading the
/// roster. There is deliberately no directive that grants administrator — the
/// admin tier is the configuration file's alone, so a chat cannot promote
/// anybody, and the absence of the verb is the enforcement.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AdminDirective {
    /// Add one non-admin member.
    Add {
        /// The user being added.
        user_id: OperatorUserId,
    },
    /// Revoke one non-admin member.
    Remove {
        /// The user being revoked.
        user_id: OperatorUserId,
    },
    /// Report the administrators and members this host currently admits.
    List,
}

impl AdminDirective {
    /// The subcommand word an operator types.
    #[must_use]
    pub const fn verb(self) -> &'static str {
        match self {
            Self::Add { .. } => "add",
            Self::Remove { .. } => "remove",
            Self::List => "list",
        }
    }

    /// The user this directive names, when it names one.
    #[must_use]
    pub const fn user_id(self) -> Option<OperatorUserId> {
        match self {
            Self::Add { user_id } | Self::Remove { user_id } => Some(user_id),
            Self::List => None,
        }
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
    /// Report the recent messages in the Slack channel this name resolves to.
    Slack {
        /// The configured channel being read.
        channel: ChannelName,
    },
    /// List the configured Slack channel labels without contacting Slack.
    SlackList,
    /// Inspect or review the current actor's durable memory.
    Memory { directive: MemoryDirective },
    /// Record one explicit actor-supplied fact.
    Remember { fact: RunTask },
    /// Tombstone one memory.
    Forget { memory_ref: ControlRef },
    /// Reset the active conversation projection, not long-term memory.
    New,
    /// Create one issue in the configured repository this alias resolves to.
    GitHubCreate {
        /// The owner-configured repository alias.
        repo_alias: GitHubRepoAlias,
        /// Natural-language instructions for the new issue.
        request: GitHubRequest,
    },
    /// Publish one reply on the exact GitHub issue URL.
    GitHubReply {
        /// The exact GitHub issue being replied to.
        issue_url: GitHubIssueUrl,
        /// Natural-language instructions for the reply.
        request: GitHubRequest,
    },
    /// Check one uniquely matching checklist item on a GitHub issue.
    GitHubCheck {
        /// The exact GitHub issue containing the item.
        issue_url: GitHubIssueUrl,
        /// The exact checklist item text to match.
        item: GitHubChecklistItem,
    },
    /// Uncheck one uniquely matching checklist item on a GitHub issue.
    GitHubUncheck {
        /// The exact GitHub issue containing the item.
        issue_url: GitHubIssueUrl,
        /// The exact checklist item text to match.
        item: GitHubChecklistItem,
    },
    /// Apply one issue or pull-request management instruction.
    GitHubIssue { request: GitHubRequest },
    /// Apply one label management instruction.
    GitHubLabel { request: GitHubRequest },
    /// Apply one milestone management instruction.
    GitHubMilestone { request: GitHubRequest },
    /// Apply one native hierarchy/dependency instruction.
    GitHubEpic { request: GitHubRequest },
    /// Apply one Projects management instruction.
    GitHubProject { request: GitHubRequest },
    /// Post one message to the Slack channel this name resolves to.
    ///
    /// The only command in this vocabulary whose effect is visible outside the
    /// system: holding this value still does nothing, but dispatching it puts
    /// `text` in front of every human in that channel, and nothing takes it
    /// back.
    Say {
        /// The configured channel being posted to.
        channel: ChannelName,
        /// The exact body to post.
        text: SayText,
    },
    /// Work the tracked support ticket this reference names into a draft answer.
    ///
    /// The reference is the whole of the operator's input. Everything the work
    /// is composed *from* is the ticket the daemon already recorded, so this
    /// value carries no task text that could reach a provider unread.
    Work {
        /// The fleet issue to work.
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
    /// Manage the non-admin members of this control surface.
    Admin {
        /// What was asked for.
        directive: AdminDirective,
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
            Self::Slack { .. } | Self::SlackList => CommandKind::Slack,
            Self::Memory { .. } => CommandKind::Memory,
            Self::Remember { .. } => CommandKind::Remember,
            Self::Forget { .. } => CommandKind::Forget,
            Self::New => CommandKind::New,
            Self::GitHubCreate { .. } => CommandKind::GitHubCreate,
            Self::GitHubReply { .. } => CommandKind::GitHubReply,
            Self::GitHubCheck { .. } => CommandKind::GitHubCheck,
            Self::GitHubUncheck { .. } => CommandKind::GitHubUncheck,
            Self::GitHubIssue { .. } => CommandKind::GitHubIssue,
            Self::GitHubLabel { .. } => CommandKind::GitHubLabel,
            Self::GitHubMilestone { .. } => CommandKind::GitHubMilestone,
            Self::GitHubEpic { .. } => CommandKind::GitHubEpic,
            Self::GitHubProject { .. } => CommandKind::GitHubProject,
            Self::Say { .. } => CommandKind::Say,
            Self::Work { .. } => CommandKind::Work,
            Self::Run { .. } => CommandKind::Run,
            Self::Cancel { .. } => CommandKind::Cancel,
            Self::Approve { .. } => CommandKind::Approve,
            Self::Deny { .. } => CommandKind::Deny,
            Self::Admin { .. } => CommandKind::Admin,
        }
    }

    /// The lowest operator tier that may run this command.
    ///
    /// Read from the same registry row the parser and the menu read, so a
    /// dispatcher cannot form a second opinion about who may run what.
    #[must_use]
    pub const fn tier(&self) -> CommandTier {
        self.kind().tier()
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
    /// The sender may command this bot, but not this command.
    ///
    /// Decided as soon as the name resolves and before any argument is parsed,
    /// so it cannot be used to probe the grammar of a command the sender may
    /// not run. Distinct from [`Self::Unauthorized`] on purpose: this sender is
    /// a known operator and telling them "not authorized" flat would send them
    /// looking for a fault in their own access.
    NotPermitted,
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
            Self::NotPermitted => "not_permitted",
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
            Self::NotPermitted => "Not authorized for that. Ask an administrator.",
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

/// Render a refusal in the context of the command the operator typed.
///
/// Authorization refusals return before the text is inspected, preserving the
/// tier gate's non-oracle property. For an admitted operator whose command name
/// resolved, the reply names the missing or extra field and includes the exact
/// usage instead of sending them to the whole help page.
#[must_use]
pub fn command_refusal_text(text: &str, refusal: CommandRefusal) -> String {
    if matches!(
        refusal,
        CommandRefusal::Unauthorized | CommandRefusal::NotPermitted
    ) {
        return refusal.operator_reply().to_owned();
    }
    let Ok((kind, rest)) = split_command(text) else {
        return refusal.operator_reply().to_owned();
    };
    match refusal {
        CommandRefusal::MissingArgument => match kind {
            CommandKind::Say => String::from(
                "Missing the message to post. Usage: /say <channel> <message>. Example: /say jean yo",
            ),
            CommandKind::Slack => {
                String::from("Missing the channel label. Usage: /slack <channel|list>.")
            }
            CommandKind::Run => String::from("Missing the task. Usage: /run <task>."),
            CommandKind::Admin => {
                String::from("Missing the admin action. Usage: /admin <add|remove|list> [user_id].")
            }
            CommandKind::Remember => String::from("Missing the fact. Usage: /remember <fact>."),
            CommandKind::Forget => String::from("Missing the memory id. Usage: /forget <id>."),
            CommandKind::GitHubCreate => String::from(
                "Missing the repository alias or request. Usage: /github_create <repository> <request>.",
            ),
            CommandKind::GitHubReply => String::from(
                "Missing the issue URL or reply. Usage: /github_reply <issue-url> <reply>.",
            ),
            CommandKind::GitHubCheck => String::from(
                "Missing the issue URL or checklist item. Usage: /github_check <issue-url> <item>.",
            ),
            CommandKind::GitHubUncheck => String::from(
                "Missing the issue URL or checklist item. Usage: /github_uncheck <issue-url> <item>.",
            ),
            CommandKind::GitHubIssue
            | CommandKind::GitHubLabel
            | CommandKind::GitHubMilestone
            | CommandKind::GitHubEpic
            | CommandKind::GitHubProject => format!(
                "Missing the GitHub management request. Usage: {}.",
                command_usage(kind)
            ),
            _ => format!("Missing the reference. Usage: {}.", command_usage(kind)),
        },
        CommandRefusal::UnexpectedArgument => match kind {
            CommandKind::Slack => String::from(
                "/slack reads one channel and accepts only its label (or list). Read: /slack <channel>. Post: /say <channel> <message>. Do not type the < > placeholders.",
            ),
            CommandKind::Help
            | CommandKind::Status
            | CommandKind::Runs
            | CommandKind::Tickets
            | CommandKind::New => {
                format!(
                    "/{} takes no arguments. Usage: {}.",
                    kind.name(),
                    command_usage(kind)
                )
            }
            _ => format!(
                "/{} received too many fields. Usage: {}.",
                kind.name(),
                command_usage(kind)
            ),
        },
        CommandRefusal::ArgumentInvalid => {
            if matches!(kind, CommandKind::Slack | CommandKind::Say)
                && say_channel_is_invalid(kind, rest)
            {
                format!(
                    "Invalid channel label. Use letters, numbers, - or _, without < > or quotes. Usage: {}.",
                    command_usage(kind)
                )
            } else {
                format!(
                    "Invalid argument for /{}. Usage: {}.",
                    kind.name(),
                    command_usage(kind)
                )
            }
        }
        CommandRefusal::ArgumentTooLong => format!(
            "An argument for /{} is too long. Usage: {}.",
            kind.name(),
            command_usage(kind)
        ),
        _ => refusal.operator_reply().to_owned(),
    }
}

const fn command_usage(kind: CommandKind) -> &'static str {
    match kind {
        CommandKind::Help => "/help",
        CommandKind::Status => "/status",
        CommandKind::Runs => "/runs",
        CommandKind::Tickets => "/tickets",
        CommandKind::Ticket => "/ticket <reference>",
        CommandKind::Slack => "/slack <channel|list>",
        CommandKind::Memory => {
            "/memory [search <query>|show <id>|proposals|approve <id>|deny <id>|sources <id>|link]"
        }
        CommandKind::Remember => "/remember <fact>",
        CommandKind::Forget => "/forget <id>",
        CommandKind::New => "/new",
        CommandKind::GitHubCreate => "/github_create <repository> <request>",
        CommandKind::GitHubReply => "/github_reply <issue-url> <reply>",
        CommandKind::GitHubCheck => "/github_check <issue-url> <item>",
        CommandKind::GitHubUncheck => "/github_uncheck <issue-url> <item>",
        CommandKind::GitHubIssue => "/github_issue <request>",
        CommandKind::GitHubLabel => "/github_label <request>",
        CommandKind::GitHubMilestone => "/github_milestone <request>",
        CommandKind::GitHubEpic => "/github_epic <request>",
        CommandKind::GitHubProject => "/github_project <request>",
        CommandKind::Work => "/work <reference>",
        CommandKind::Run => "/run <task>",
        CommandKind::Say => "/say <channel> <message>",
        CommandKind::Cancel => "/cancel <reference>",
        CommandKind::Approve => "/approve <reference>",
        CommandKind::Deny => "/deny <reference>",
        CommandKind::Admin => "/admin <add|remove|list> [user_id]",
    }
}

fn say_channel_is_invalid(kind: CommandKind, rest: &str) -> bool {
    if kind == CommandKind::Slack {
        return true;
    }
    rest.split_whitespace()
        .next()
        .is_none_or(|channel| ChannelName::new(channel).is_err())
}

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
    /// An administrator was named who is not in the allowed set.
    ///
    /// Refused rather than repaired by widening the allowed set: the two lists
    /// come from different places — configuration and configuration plus a
    /// durable roster — and a composition that silently admitted an
    /// administrator the allowed set never named would mean the two disagreed
    /// about who the operators are.
    AdminNotAllowed,
}

impl AllowlistError {
    /// Stable, content-free category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::TooMany => "too_many",
            Self::InvalidUserId => "invalid_user_id",
            Self::AdminNotAllowed => "admin_not_allowed",
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

/// Who may command this bot, and which of them may command all of it.
///
/// Two nested sets and one invariant: **every administrator is allowed**, so a
/// composition where they are not is refused rather than reconciled. That is
/// the property the whole tier model rests on — an administrator who was not in
/// the allowed set would be refused at the outer gate and never reach the tier
/// check at all, which reads as "the owner locked themselves out" and would be
/// impossible to diagnose from a chat.
///
/// The two sets come from different places and change at different rates. The
/// admin set is written down by the owner in a file the daemon reads at startup
/// and nothing at runtime can widen. The allowed set is that same file *plus* a
/// durable roster an administrator edits from a chat, so it is recomposed
/// whenever the roster moves. Holding them in one value is what keeps a
/// recomposition from updating one and forgetting the other.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorAuthority {
    allowed: AllowedUsers,
    admins: AllowedUsers,
}

impl OperatorAuthority {
    /// Compose the two sets.
    ///
    /// # Errors
    ///
    /// Returns [`AllowlistError::AdminNotAllowed`] when an administrator is not
    /// in the allowed set.
    pub fn new(allowed: AllowedUsers, admins: AllowedUsers) -> Result<Self, AllowlistError> {
        if admins
            .as_slice()
            .iter()
            .any(|admin| !allowed.authorize(*admin))
        {
            return Err(AllowlistError::AdminNotAllowed);
        }
        Ok(Self { allowed, admins })
    }

    /// The single-tier composition: everyone allowed is an administrator.
    ///
    /// This is what a deployment that never wrote down a second tier means, and
    /// naming it here is what lets a host express "no tiers configured" without
    /// building the two lists itself. See the daemon's bot configuration for why
    /// that is the back-compatible reading of an absent `admin=` line.
    #[must_use]
    pub fn single_tier(allowed: AllowedUsers) -> Self {
        Self {
            admins: allowed.clone(),
            allowed,
        }
    }

    /// Everyone who may command this bot at all.
    #[must_use]
    pub const fn allowed(&self) -> &AllowedUsers {
        &self.allowed
    }

    /// The administrators.
    #[must_use]
    pub const fn admins(&self) -> &AllowedUsers {
        &self.admins
    }

    /// Whether this user may command the bot at all.
    #[must_use]
    pub fn authorize(&self, user_id: i64) -> bool {
        self.allowed.authorize(user_id)
    }

    /// Whether this user is an administrator.
    #[must_use]
    pub fn is_admin(&self, user_id: i64) -> bool {
        self.admins.authorize(user_id)
    }

    /// The tier this user carries, or `None` for a user this host does not
    /// admit at all.
    #[must_use]
    pub fn tier_of(&self, user_id: i64) -> Option<CommandTier> {
        if self.is_admin(user_id) {
            return Some(CommandTier::Admin);
        }
        self.authorize(user_id).then_some(CommandTier::Allowed)
    }

    /// Whether this user may run this command.
    ///
    /// The whole rule, in one comparison: the tier they carry must be at least
    /// the tier the registry row declares.
    #[must_use]
    pub fn may(&self, user_id: i64, kind: CommandKind) -> bool {
        self.tier_of(user_id)
            .is_some_and(|tier| tier >= kind.tier())
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

/// Gate one message on its sender's *tier*, then parse it.
///
/// This is the entry point a two-tier host should call, and the order of the
/// three checks is the design:
///
/// 1. **Allowed at all?** A sender outside the allowed set is
///    [`CommandRefusal::Unauthorized`] without a byte of their text being
///    inspected, exactly as in [`authorize_and_parse`].
/// 2. **Which command?** The name is resolved against the closed registry.
/// 3. **May they run it?** The tier is checked against the registry row, before
///    any argument is parsed. A member typing `/run` with a perfect task and a
///    member typing `/run` with a four-kilobyte one receive the same
///    [`CommandRefusal::NotPermitted`], so the refusal says nothing about the
///    grammar of a command that is not theirs.
///
/// # Errors
///
/// Returns [`CommandRefusal::Unauthorized`] for a sender the host does not
/// admit, [`CommandRefusal::NotPermitted`] for one whose tier is below the
/// command's, and otherwise whatever the argument grammar refuses.
pub fn authorize_and_parse_tiered(
    authority: &OperatorAuthority,
    user_id: i64,
    text: &str,
) -> Result<ControlCommand, CommandRefusal> {
    let Some(tier) = authority.tier_of(user_id) else {
        return Err(CommandRefusal::Unauthorized);
    };
    let (kind, rest) = split_command(text)?;
    if tier < kind.tier() {
        return Err(CommandRefusal::NotPermitted);
    }
    parse_arguments(kind, rest)
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
    let (kind, rest) = split_command(text)?;
    parse_arguments(kind, rest)
}

/// Resolve one message's command name, returning it and its untouched
/// remainder.
///
/// Split out of [`parse_command`] so a tier check can happen between resolving
/// the name and parsing what follows it. Nothing here looks at the argument, so
/// a caller that refuses at the tier has refused before any field of an
/// untrusted message was validated, bounded or allocated.
fn split_command(text: &str) -> Result<(CommandKind, &str), CommandRefusal> {
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
    Ok((kind, rest))
}

/// Parse what follows one resolved command name.
///
/// Exhaustive over [`CommandKind`], which is what makes the registry's declared
/// [`ArgumentShape`] and the grammar the parser actually accepts one thing
/// rather than two that agree today.
fn parse_arguments(kind: CommandKind, rest: &str) -> Result<ControlCommand, CommandRefusal> {
    match kind {
        CommandKind::Help => no_argument(rest).map(|()| ControlCommand::Help),
        CommandKind::Status => no_argument(rest).map(|()| ControlCommand::Status),
        CommandKind::Runs => no_argument(rest).map(|()| ControlCommand::Runs),
        CommandKind::Tickets => no_argument(rest).map(|()| ControlCommand::Tickets),
        CommandKind::Ticket => {
            one_reference(rest).map(|ticket_ref| ControlCommand::Ticket { ticket_ref })
        }
        CommandKind::Slack => one_channel(rest).map(|channel| {
            if channel.as_str() == "list" {
                ControlCommand::SlackList
            } else {
                ControlCommand::Slack { channel }
            }
        }),
        CommandKind::Memory => {
            one_memory_directive(rest).map(|directive| ControlCommand::Memory { directive })
        }
        CommandKind::Remember => RunTask::new(rest).map(|fact| ControlCommand::Remember { fact }),
        CommandKind::Forget => {
            one_reference(rest).map(|memory_ref| ControlCommand::Forget { memory_ref })
        }
        CommandKind::New => no_argument(rest).map(|()| ControlCommand::New),
        CommandKind::GitHubCreate => {
            one_github_repository_request(rest).map(|(repo_alias, request)| {
                ControlCommand::GitHubCreate {
                    repo_alias,
                    request,
                }
            })
        }
        CommandKind::GitHubReply => {
            let (issue_url, request) = one_github_issue_and_text(rest)?;
            GitHubRequest::new(request)
                .map(|request| ControlCommand::GitHubReply { issue_url, request })
        }
        CommandKind::GitHubCheck => {
            let (issue_url, item) = one_github_issue_and_text(rest)?;
            GitHubChecklistItem::new(item)
                .map(|item| ControlCommand::GitHubCheck { issue_url, item })
        }
        CommandKind::GitHubUncheck => {
            let (issue_url, item) = one_github_issue_and_text(rest)?;
            GitHubChecklistItem::new(item)
                .map(|item| ControlCommand::GitHubUncheck { issue_url, item })
        }
        CommandKind::GitHubIssue => {
            GitHubRequest::new(rest).map(|request| ControlCommand::GitHubIssue { request })
        }
        CommandKind::GitHubLabel => {
            GitHubRequest::new(rest).map(|request| ControlCommand::GitHubLabel { request })
        }
        CommandKind::GitHubMilestone => {
            GitHubRequest::new(rest).map(|request| ControlCommand::GitHubMilestone { request })
        }
        CommandKind::GitHubEpic => {
            GitHubRequest::new(rest).map(|request| ControlCommand::GitHubEpic { request })
        }
        CommandKind::GitHubProject => {
            GitHubRequest::new(rest).map(|request| ControlCommand::GitHubProject { request })
        }
        CommandKind::Say => {
            one_channel_message(rest).map(|(channel, text)| ControlCommand::Say { channel, text })
        }
        CommandKind::Work => {
            one_reference(rest).map(|ticket_ref| ControlCommand::Work { ticket_ref })
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
        CommandKind::Admin => {
            one_directive(rest).map(|directive| ControlCommand::Admin { directive })
        }
    }
}

fn one_memory_directive(rest: &str) -> Result<MemoryDirective, CommandRefusal> {
    let rest = rest.trim();
    if rest.is_empty() || rest.eq_ignore_ascii_case("summary") || rest.eq_ignore_ascii_case("list")
    {
        return Ok(MemoryDirective::Summary);
    }
    if rest.eq_ignore_ascii_case("proposals") {
        return Ok(MemoryDirective::Proposals);
    }
    if rest.eq_ignore_ascii_case("link") {
        return Ok(MemoryDirective::Link);
    }
    let (verb, argument) = rest
        .split_once(char::is_whitespace)
        .ok_or(CommandRefusal::ArgumentInvalid)?;
    let argument = argument.trim();
    if verb.eq_ignore_ascii_case("search") {
        return RunTask::new(argument).map(|query| MemoryDirective::Search { query });
    }
    let memory_ref = one_reference(argument)?;
    if verb.eq_ignore_ascii_case("show") {
        Ok(MemoryDirective::Show { memory_ref })
    } else if verb.eq_ignore_ascii_case("approve") {
        Ok(MemoryDirective::Approve { memory_ref })
    } else if verb.eq_ignore_ascii_case("deny") {
        Ok(MemoryDirective::Deny { memory_ref })
    } else if verb.eq_ignore_ascii_case("sources") {
        Ok(MemoryDirective::Sources { memory_ref })
    } else {
        Err(CommandRefusal::ArgumentInvalid)
    }
}

fn split_github_target_and_text(rest: &str) -> Result<(&str, &str), CommandRefusal> {
    let rest = rest.trim_start();
    if rest.is_empty() {
        return Err(CommandRefusal::MissingArgument);
    }
    let Some(boundary) = rest.find(char::is_whitespace) else {
        return Err(CommandRefusal::MissingArgument);
    };
    let (target, text) = rest.split_at(boundary);
    if text.trim().is_empty() {
        return Err(CommandRefusal::MissingArgument);
    }
    Ok((target, text))
}

fn one_github_repository_request(
    rest: &str,
) -> Result<(GitHubRepoAlias, GitHubRequest), CommandRefusal> {
    let (alias, request) = split_github_target_and_text(rest)?;
    let alias = GitHubRepoAlias::new(alias)?;
    GitHubRequest::new(request).map(|request| (alias, request))
}

fn one_github_issue_and_text(rest: &str) -> Result<(GitHubIssueUrl, &str), CommandRefusal> {
    let (url, text) = split_github_target_and_text(rest)?;
    let url = GitHubIssueUrl::new(url)?;
    Ok((url, text))
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

/// Accept exactly one channel name and refuse a second.
fn one_channel(rest: &str) -> Result<ChannelName, CommandRefusal> {
    let mut tokens = rest.split_whitespace();
    let first = tokens.next().ok_or(CommandRefusal::MissingArgument)?;
    if tokens.next().is_some() {
        return Err(CommandRefusal::UnexpectedArgument);
    }
    ChannelName::new(first)
}

/// Accept one channel name followed by the rest of the message as its body.
///
/// The split is on the *first* run of whitespace and nothing further: everything
/// after the channel is the message, whitespace and all, because a message is
/// free text and a parser that tokenized it would be deciding what somebody
/// meant to say. The channel is validated first, so a `/say` naming a channel
/// this grammar refuses never allocates the body it would have posted.
fn one_channel_message(rest: &str) -> Result<(ChannelName, SayText), CommandRefusal> {
    let rest = rest.trim_start();
    if rest.is_empty() {
        return Err(CommandRefusal::MissingArgument);
    }
    let (head, body) = match rest.find(char::is_whitespace) {
        Some(boundary) => rest.split_at(boundary),
        None => (rest, ""),
    };
    let channel = ChannelName::new(head)?;
    Ok((channel, SayText::new(body)?))
}

/// Accept exactly one `/admin` directive.
///
/// The grammar is closed on both tokens and admits no third: `add <user_id>`,
/// `remove <user_id>`, `list`. An unrecognized verb is
/// [`CommandRefusal::ArgumentInvalid`] rather than [`CommandRefusal::UnknownCommand`],
/// because the *command* was recognized — an administrator who typed
/// `/admin delete 7` should be told their argument is not in an accepted form,
/// not that `/admin` does not exist.
///
/// The verb is matched case-insensitively for the reason command names are: an
/// operator typing from a phone keyboard that capitalized the first word means
/// the same thing.
fn one_directive(rest: &str) -> Result<AdminDirective, CommandRefusal> {
    let mut tokens = rest.split_whitespace();
    let verb = tokens.next().ok_or(CommandRefusal::MissingArgument)?;
    let argument = tokens.next();
    if tokens.next().is_some() {
        return Err(CommandRefusal::UnexpectedArgument);
    }
    if verb.len() > MAX_COMMAND_NAME_BYTES {
        return Err(CommandRefusal::ArgumentTooLong);
    }
    match (verb.to_ascii_lowercase().as_str(), argument) {
        ("list", None) => Ok(AdminDirective::List),
        ("list", Some(_)) => Err(CommandRefusal::UnexpectedArgument),
        ("add", Some(token)) => {
            OperatorUserId::parse(token).map(|user_id| AdminDirective::Add { user_id })
        }
        ("remove", Some(token)) => {
            OperatorUserId::parse(token).map(|user_id| AdminDirective::Remove { user_id })
        }
        ("add" | "remove", None) => Err(CommandRefusal::MissingArgument),
        _ => Err(CommandRefusal::ArgumentInvalid),
    }
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
        assert!(text.contains("/slack <channel|list>"));
        assert!(text.contains("/say <channel> <message>"));
        assert!(text.contains("/cancel <reference>"));
        assert!(text.contains("/ticket <reference>"));
        assert!(text.contains("/github_create <repository> <request>"));
        assert!(text.contains("/github_reply <issue-url> <reply>"));
        assert!(text.contains("/github_check <issue-url> <item>"));
        assert!(text.contains("/github_uncheck <issue-url> <item>"));
        assert!(!text.contains("/status <"));
        // The two ticket commands differ by one character and by their argument
        // shape, so the help an operator reads has to keep them apart.
        assert!(text.contains("/tickets — "));
        assert!(text.contains("ask read-only questions in ordinary language"));
        assert!(text.contains("actions still require an explicit command"));
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
    fn memory_commands_have_a_closed_reviewable_grammar() {
        assert_eq!(
            parse_command("/memory"),
            Ok(ControlCommand::Memory {
                directive: MemoryDirective::Summary
            })
        );
        assert_eq!(
            parse_command("/memory search concise french replies"),
            Ok(ControlCommand::Memory {
                directive: MemoryDirective::Search {
                    query: RunTask::new("concise french replies").expect("query")
                }
            })
        );
        for (verb, directive) in [
            (
                "show",
                MemoryDirective::Show {
                    memory_ref: ControlRef::new("M-42").expect("reference"),
                },
            ),
            (
                "approve",
                MemoryDirective::Approve {
                    memory_ref: ControlRef::new("M-42").expect("reference"),
                },
            ),
            (
                "deny",
                MemoryDirective::Deny {
                    memory_ref: ControlRef::new("M-42").expect("reference"),
                },
            ),
            (
                "sources",
                MemoryDirective::Sources {
                    memory_ref: ControlRef::new("M-42").expect("reference"),
                },
            ),
        ] {
            assert_eq!(
                parse_command(&format!("/memory {verb} M-42")),
                Ok(ControlCommand::Memory { directive })
            );
        }
        assert_eq!(
            parse_command("/remember replies should be concise"),
            Ok(ControlCommand::Remember {
                fact: RunTask::new("replies should be concise").expect("fact")
            })
        );
        assert_eq!(
            parse_command("/forget M-42"),
            Ok(ControlCommand::Forget {
                memory_ref: ControlRef::new("M-42").expect("reference")
            })
        );
        assert_eq!(parse_command("/new"), Ok(ControlCommand::New));
        assert_eq!(
            parse_command("/memory erase M-42"),
            Err(CommandRefusal::ArgumentInvalid)
        );
        assert_eq!(
            parse_command("/new now"),
            Err(CommandRefusal::UnexpectedArgument)
        );
        assert_eq!(CommandKind::Memory.tier(), CommandTier::Admin);
        assert_eq!(CommandKind::Remember.tier(), CommandTier::Admin);
        assert_eq!(CommandKind::Forget.tier(), CommandTier::Admin);
        assert_eq!(CommandKind::New.tier(), CommandTier::Admin);
    }

    #[test]
    fn github_commands_are_typed_bounded_and_distinct_from_support_tickets() {
        let issue_url =
            GitHubIssueUrl::new("https://github.com/acme/widgets/issues/42").expect("issue URL");
        assert_eq!(
            parse_command("/github_create Automonique corriger le menu mobile"),
            Ok(ControlCommand::GitHubCreate {
                repo_alias: GitHubRepoAlias::new("automonique").expect("alias"),
                request: GitHubRequest::new("corriger le menu mobile").expect("request"),
            })
        );
        assert_eq!(
            parse_command("/github_reply https://github.com/acme/widgets/issues/42 réponse prête"),
            Ok(ControlCommand::GitHubReply {
                issue_url: issue_url.clone(),
                request: GitHubRequest::new("réponse prête").expect("request"),
            })
        );
        assert_eq!(
            parse_command("/github_check https://github.com/acme/widgets/issues/42 tests validés"),
            Ok(ControlCommand::GitHubCheck {
                issue_url: issue_url.clone(),
                item: GitHubChecklistItem::new("tests validés").expect("item"),
            })
        );
        assert_eq!(
            parse_command(
                "/github_uncheck https://github.com/acme/widgets/issues/42 tests validés"
            ),
            Ok(ControlCommand::GitHubUncheck {
                issue_url,
                item: GitHubChecklistItem::new("tests validés").expect("item"),
            })
        );

        for command in [
            "/github_create",
            "/github_create automonique",
            "/github_reply",
            "/github_reply https://github.com/acme/widgets/issues/42",
            "/github_check https://github.com/acme/widgets/issues/42",
            "/github_uncheck https://github.com/acme/widgets/issues/42",
        ] {
            assert_eq!(
                parse_command(command),
                Err(CommandRefusal::MissingArgument),
                "{command}"
            );
        }
        assert_eq!(
            parse_command("/ticket https://github.com/acme/widgets/issues/42"),
            Err(CommandRefusal::ArgumentInvalid),
            "a GitHub URL must not become an internal support-ticket reference"
        );
        assert_ne!(
            parse_command("/github_check https://github.com/acme/widgets/issues/42 tests validés"),
            parse_command(
                "/github_uncheck https://github.com/acme/widgets/issues/42 tests validés"
            )
        );

        for (command, kind) in [
            (
                "/github_issue ferme https://github.com/acme/widgets/issues/42",
                CommandKind::GitHubIssue,
            ),
            (
                "/github_label crée le label bug dans widgets",
                CommandKind::GitHubLabel,
            ),
            (
                "/github_milestone crée le jalon v2 dans widgets",
                CommandKind::GitHubMilestone,
            ),
            (
                "/github_epic ajoute 42 comme sous-ticket de 10",
                CommandKind::GitHubEpic,
            ),
            (
                "/github_project crée un projet privé roadmap",
                CommandKind::GitHubProject,
            ),
        ] {
            assert_eq!(
                parse_command(command).as_ref().map(ControlCommand::kind),
                Ok(kind)
            );
            assert_ne!(kind, CommandKind::Ticket);
            assert_eq!(kind.tier(), CommandTier::Admin);
        }
    }

    #[test]
    fn github_issue_urls_and_action_text_have_closed_bounds() {
        for invalid in [
            "http://github.com/acme/widgets/issues/42",
            "https://www.github.com/acme/widgets/issues/42",
            "https://github.com/acme/widgets/pull/42",
            "https://github.com/acme/widgets/issues/0",
            "https://github.com/acme/widgets/issues/not-a-number",
            "https://github.com/acme/widgets/issues/42/",
            "https://github.com/acme/widgets/issues/42?view=1",
            "https://github.com/acme/widgets/issues/42#comment",
        ] {
            assert_eq!(
                GitHubIssueUrl::new(invalid),
                Err(CommandRefusal::ArgumentInvalid),
                "{invalid}"
            );
            assert_eq!(
                parse_command(&format!("/github_reply {invalid} reply")),
                Err(CommandRefusal::ArgumentInvalid),
                "{invalid}"
            );
        }
        assert_eq!(
            GitHubRepoAlias::new("bad/alias"),
            Err(CommandRefusal::ArgumentInvalid)
        );
        assert_eq!(
            GitHubRepoAlias::new("a".repeat(MAX_GITHUB_REPO_ALIAS_BYTES + 1)),
            Err(CommandRefusal::ArgumentTooLong)
        );
        assert_eq!(
            parse_command(&format!(
                "/github_reply https://github.com/acme/widgets/issues/42 {}",
                "r".repeat(MAX_GITHUB_REQUEST_BYTES + 1)
            )),
            Err(CommandRefusal::ArgumentTooLong)
        );
        assert_eq!(
            parse_command(&format!(
                "/github_check https://github.com/acme/widgets/issues/42 {}",
                "i".repeat(MAX_GITHUB_CHECKLIST_ITEM_BYTES + 1)
            )),
            Err(CommandRefusal::ArgumentTooLong)
        );
        assert_eq!(
            parse_command("/github_create automonique bell\u{7}"),
            Err(CommandRefusal::ArgumentInvalid)
        );
    }

    /// `/work` reads a ticket and `/ticket` reads a ticket, and they are not the
    /// same command: one of them is an effect. They take the same argument
    /// shape, so nothing but the name keeps them apart, and this is where that
    /// is watched.
    #[test]
    fn working_a_ticket_is_a_different_command_from_reading_one() {
        let ticket_ref = ControlRef::new("SUP-1042").expect("reference");
        assert_eq!(
            parse_command("/work SUP-1042"),
            Ok(ControlCommand::Work {
                ticket_ref: ticket_ref.clone()
            })
        );
        assert_ne!(
            parse_command("/work SUP-1042"),
            parse_command("/ticket SUP-1042"),
            "a read and an effect must not parse to the same value"
        );
        assert_eq!(parse_command("/work"), Err(CommandRefusal::MissingArgument));
        assert_eq!(
            parse_command("/work SUP-1042 and also this one"),
            Err(CommandRefusal::UnexpectedArgument),
            "one reference, so a second cannot be smuggled in"
        );
        // The reference grammar is the gate on what a `/work` can name: nothing
        // with whitespace, quoting or a control character reaches the daemon.
        assert_eq!(
            parse_command("/work SUP-1042;rm"),
            Err(CommandRefusal::ArgumentInvalid)
        );
        assert_eq!(CommandKind::from_name("work"), Some(CommandKind::Work));
        assert_eq!(CommandKind::Work.argument(), ArgumentShape::Reference);
    }

    /// The read and the post are different commands over the same channel
    /// vocabulary, and the difference is the whole safety story: one of them is
    /// visible to people outside this system.
    #[test]
    fn reading_a_channel_is_a_different_command_from_posting_to_one() {
        let channel = ChannelName::new("ops").expect("channel");
        assert_eq!(
            parse_command("/slack ops"),
            Ok(ControlCommand::Slack {
                channel: channel.clone()
            })
        );
        assert_eq!(parse_command("/slack list"), Ok(ControlCommand::SlackList));
        assert_eq!(
            parse_command("/say ops bonjour"),
            Ok(ControlCommand::Say {
                channel: channel.clone(),
                text: SayText::new("bonjour").expect("text"),
            })
        );
        assert_ne!(
            parse_command("/slack ops"),
            parse_command("/say ops bonjour"),
            "a read and an outward effect must not parse to the same value"
        );
        assert_eq!(CommandKind::Slack.tier(), CommandTier::Allowed);
        assert_eq!(CommandKind::Say.tier(), CommandTier::Admin);

        // The `#` everybody writes is dropped, and the case Slack ignores is
        // ignored here too, so all three spellings are one key.
        for spelling in ["#ops", "OPS", "#OPS"] {
            assert_eq!(
                parse_command(&format!("/slack {spelling}")),
                Ok(ControlCommand::Slack {
                    channel: channel.clone()
                }),
                "{spelling}"
            );
        }
        assert_eq!(channel.as_str(), "ops");
        assert_eq!(channel.to_string(), "ops");

        // One channel and no second one: a `/slack` cannot be talked into
        // naming two, and the extra token is not silently dropped.
        assert_eq!(
            parse_command("/slack"),
            Err(CommandRefusal::MissingArgument)
        );
        assert_eq!(
            parse_command("/slack ops incidents"),
            Err(CommandRefusal::UnexpectedArgument)
        );

        // Nothing that is not a configured channel *name* is a channel name.
        // A conversation id survives the grammar as a name — and that is fine,
        // because a name is only ever a key into the host's own map, and no
        // host configures one under that label.
        for token in ["ops/incidents", "ops!", "ops.eu", "C0RESERVED:1"] {
            assert_eq!(
                parse_command(&format!("/slack {token}")),
                Err(CommandRefusal::ArgumentInvalid),
                "{token}"
            );
        }
        // A bare `#` names nothing once the sigil is dropped, which is a
        // missing argument rather than a malformed one.
        assert_eq!(
            parse_command("/slack #"),
            Err(CommandRefusal::MissingArgument)
        );
        assert_eq!(
            parse_command(&format!(
                "/slack {}",
                "c".repeat(MAX_CHANNEL_NAME_BYTES + 1)
            )),
            Err(CommandRefusal::ArgumentTooLong)
        );

        // A `/say` needs both fields, and the body is everything after the
        // channel — spaces, punctuation and newlines included, unreformatted.
        assert_eq!(parse_command("/say"), Err(CommandRefusal::MissingArgument));
        assert_eq!(
            parse_command("/say ops"),
            Err(CommandRefusal::MissingArgument)
        );
        assert_eq!(
            parse_command("/say ops   deux mots\nligne deux"),
            Ok(ControlCommand::Say {
                channel: channel.clone(),
                text: SayText::new("deux mots\nligne deux").expect("text"),
            })
        );
        assert_eq!(
            parse_command(&format!("/say ops {}", "x".repeat(MAX_SAY_TEXT_BYTES + 1))),
            Err(CommandRefusal::ArgumentTooLong)
        );
        assert_eq!(
            parse_command("/say ops bell\u{7}"),
            Err(CommandRefusal::ArgumentInvalid)
        );
        // The channel is validated before the body, so a `/say` at a channel
        // this grammar refuses is refused for the channel it named.
        assert_eq!(
            parse_command("/say #ops/eu bonjour"),
            Err(CommandRefusal::ArgumentInvalid)
        );

        // Neither the name nor the body is rendered by `Debug` in a form that
        // could put a message body in a log.
        let posted = SayText::new("secret-body-never-printed").expect("text");
        let rendered = format!("{posted:?}");
        assert!(!rendered.contains("secret-body"), "rendered: {rendered}");
        assert!(rendered.contains("<redacted:"));
        assert_eq!(posted.as_str(), "secret-body-never-printed");
        assert_eq!(format!("{channel:?}"), "ChannelName(ops)");
    }

    #[test]
    fn refusal_text_explains_the_specific_command_shape() {
        assert_eq!(
            command_refusal_text("/say jean", CommandRefusal::MissingArgument),
            "Missing the message to post. Usage: /say <channel> <message>. Example: /say jean yo"
        );
        assert_eq!(
            command_refusal_text("/slack <jean> \"yo\"", CommandRefusal::UnexpectedArgument),
            "/slack reads one channel and accepts only its label (or list). Read: /slack <channel>. Post: /say <channel> <message>. Do not type the < > placeholders."
        );
        assert_eq!(
            command_refusal_text("/status now", CommandRefusal::UnexpectedArgument),
            "/status takes no arguments. Usage: /status."
        );
        assert_eq!(
            command_refusal_text(
                "/say jean secret-looking text",
                CommandRefusal::NotPermitted
            ),
            CommandRefusal::NotPermitted.operator_reply(),
            "authorization refusals remain independent of command contents"
        );
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
                ArgumentShape::Channel => {
                    assert_eq!(bare, Err(CommandRefusal::MissingArgument), "{}", entry.name);
                    assert_eq!(
                        with_argument.as_ref().map(ControlCommand::kind),
                        Ok(entry.kind),
                        "{}",
                        entry.name
                    );
                    // A channel name's grammar is narrower than a reference's,
                    // and this is the part of it that matters: nothing shaped
                    // like a Slack conversation id survives the lowercasing
                    // into something the configured map would answer to.
                    assert_eq!(
                        parse_command(&format!("/{} ops.eu:1", entry.name)),
                        Err(CommandRefusal::ArgumentInvalid),
                        "{}",
                        entry.name
                    );
                }
                ArgumentShape::ChannelMessage => {
                    assert_eq!(bare, Err(CommandRefusal::MissingArgument), "{}", entry.name);
                    // A channel with no message is not a message: the second
                    // field is required, and the first alone cannot stand in.
                    assert_eq!(
                        parse_command(&format!("/{} ops", entry.name)),
                        Err(CommandRefusal::MissingArgument),
                        "{}",
                        entry.name
                    );
                    assert_eq!(
                        parse_command(&format!("/{} ops bonjour", entry.name))
                            .as_ref()
                            .map(ControlCommand::kind),
                        Ok(entry.kind),
                        "{}",
                        entry.name
                    );
                }
                ArgumentShape::Directive => {
                    assert_eq!(bare, Err(CommandRefusal::MissingArgument), "{}", entry.name);
                    // A directive's grammar is closed on the verb too, so the
                    // token every other shape accepts is refused here.
                    assert_eq!(
                        with_argument,
                        Err(CommandRefusal::ArgumentInvalid),
                        "{}",
                        entry.name
                    );
                    assert_eq!(
                        parse_command(&format!("/{} list", entry.name))
                            .as_ref()
                            .map(ControlCommand::kind),
                        Ok(entry.kind),
                        "{}",
                        entry.name
                    );
                }
                ArgumentShape::MemoryDirective => {
                    assert_eq!(
                        bare.as_ref().map(ControlCommand::kind),
                        Ok(entry.kind),
                        "{}",
                        entry.name
                    );
                    assert_eq!(
                        with_argument,
                        Err(CommandRefusal::ArgumentInvalid),
                        "{}",
                        entry.name
                    );
                    assert_eq!(
                        parse_command(&format!("/{} proposals", entry.name))
                            .as_ref()
                            .map(ControlCommand::kind),
                        Ok(entry.kind),
                        "{}",
                        entry.name
                    );
                }
                ArgumentShape::GitHubRepositoryRequest => {
                    assert_eq!(bare, Err(CommandRefusal::MissingArgument), "{}", entry.name);
                    assert_eq!(
                        with_argument,
                        Err(CommandRefusal::MissingArgument),
                        "{}",
                        entry.name
                    );
                    assert_eq!(
                        parse_command(&format!(
                            "/{} automonique create a concise issue",
                            entry.name
                        ))
                        .as_ref()
                        .map(ControlCommand::kind),
                        Ok(entry.kind),
                        "{}",
                        entry.name
                    );
                }
                ArgumentShape::GitHubIssueRequest => {
                    assert_eq!(bare, Err(CommandRefusal::MissingArgument), "{}", entry.name);
                    assert_eq!(
                        with_argument,
                        Err(CommandRefusal::MissingArgument),
                        "{}",
                        entry.name
                    );
                    assert_eq!(
                        parse_command(&format!(
                            "/{} https://github.com/acme/widgets/issues/42 do the thing",
                            entry.name
                        ))
                        .as_ref()
                        .map(ControlCommand::kind),
                        Ok(entry.kind),
                        "{}",
                        entry.name
                    );
                }
            }
        }
    }

    /// The tier column is the authority model, so it is asserted as a table
    /// rather than trusted to whatever the registry happens to say today. A
    /// command moved from one tier to the other fails here.
    #[test]
    fn the_tier_of_every_command_is_the_documented_one() {
        let expected = [
            (CommandKind::Help, CommandTier::Allowed),
            (CommandKind::Status, CommandTier::Allowed),
            (CommandKind::Runs, CommandTier::Allowed),
            (CommandKind::Tickets, CommandTier::Allowed),
            (CommandKind::Ticket, CommandTier::Allowed),
            (CommandKind::Slack, CommandTier::Allowed),
            (CommandKind::Memory, CommandTier::Admin),
            (CommandKind::Remember, CommandTier::Admin),
            (CommandKind::Forget, CommandTier::Admin),
            (CommandKind::New, CommandTier::Admin),
            (CommandKind::GitHubCreate, CommandTier::Admin),
            (CommandKind::GitHubReply, CommandTier::Admin),
            (CommandKind::GitHubCheck, CommandTier::Admin),
            (CommandKind::GitHubUncheck, CommandTier::Admin),
            (CommandKind::GitHubIssue, CommandTier::Admin),
            (CommandKind::GitHubLabel, CommandTier::Admin),
            (CommandKind::GitHubMilestone, CommandTier::Admin),
            (CommandKind::GitHubEpic, CommandTier::Admin),
            (CommandKind::GitHubProject, CommandTier::Admin),
            (CommandKind::Work, CommandTier::Admin),
            (CommandKind::Run, CommandTier::Admin),
            (CommandKind::Say, CommandTier::Admin),
            (CommandKind::Cancel, CommandTier::Admin),
            (CommandKind::Approve, CommandTier::Admin),
            (CommandKind::Deny, CommandTier::Admin),
            (CommandKind::Admin, CommandTier::Admin),
        ];
        assert_eq!(expected.len(), COMMAND_COUNT, "a kind is unaccounted for");
        for (kind, tier) in expected {
            assert_eq!(kind.tier(), tier, "/{}", kind.name());
        }
        // Every spend or effect is admin-only, and the reads are not. This is
        // the property the table exists to hold, stated independently of it.
        for kind in CommandKind::ALL {
            let effectful = matches!(
                kind,
                CommandKind::Run
                    | CommandKind::Memory
                    | CommandKind::Remember
                    | CommandKind::Forget
                    | CommandKind::New
                    | CommandKind::GitHubCreate
                    | CommandKind::GitHubReply
                    | CommandKind::GitHubCheck
                    | CommandKind::GitHubUncheck
                    | CommandKind::GitHubIssue
                    | CommandKind::GitHubLabel
                    | CommandKind::GitHubMilestone
                    | CommandKind::GitHubEpic
                    | CommandKind::GitHubProject
                    | CommandKind::Work
                    | CommandKind::Say
                    | CommandKind::Cancel
                    | CommandKind::Approve
                    | CommandKind::Deny
                    | CommandKind::Admin
            );
            assert_eq!(
                kind.tier() == CommandTier::Admin,
                effectful,
                "/{} is on the wrong side of the spend/read line",
                kind.name()
            );
        }
        assert!(CommandTier::Allowed < CommandTier::Admin);
    }

    /// The `/admin` grammar, in full. Three verbs, one optional id, nothing
    /// else — and no verb that grants administrator, because the admin tier is
    /// the configuration file's alone.
    #[test]
    fn the_admin_directive_grammar_is_closed_on_three_verbs() {
        assert_eq!(
            parse_command("/admin list"),
            Ok(ControlCommand::Admin {
                directive: AdminDirective::List
            })
        );
        assert_eq!(
            parse_command("/admin add 7654321"),
            Ok(ControlCommand::Admin {
                directive: AdminDirective::Add {
                    user_id: OperatorUserId::new(7_654_321).expect("user id")
                }
            })
        );
        assert_eq!(
            parse_command("/Admin REMOVE 7654321"),
            Ok(ControlCommand::Admin {
                directive: AdminDirective::Remove {
                    user_id: OperatorUserId::new(7_654_321).expect("user id")
                }
            }),
            "a phone keyboard that capitalized the words meant the same thing"
        );

        assert_eq!(
            parse_command("/admin"),
            Err(CommandRefusal::MissingArgument)
        );
        assert_eq!(
            parse_command("/admin add"),
            Err(CommandRefusal::MissingArgument)
        );
        assert_eq!(
            parse_command("/admin list 7"),
            Err(CommandRefusal::UnexpectedArgument)
        );
        assert_eq!(
            parse_command("/admin add 7 8"),
            Err(CommandRefusal::UnexpectedArgument)
        );
        // No verb promotes anybody, and an unrecognized one is an argument
        // refusal rather than a claim that /admin does not exist.
        for text in [
            "/admin promote 7",
            "/admin grant 7",
            "/admin delete 7",
            "/admin ADDD 7",
        ] {
            assert_eq!(
                parse_command(text),
                Err(CommandRefusal::ArgumentInvalid),
                "{text}"
            );
        }
        // One spelling of an id. Nothing signed, padded, separated or negative.
        for token in ["0", "-7", "+7", "7.0", "7_000", "seven", "0x7"] {
            assert_eq!(
                parse_command(&format!("/admin add {token}")),
                Err(CommandRefusal::ArgumentInvalid),
                "add {token}"
            );
        }
        assert_eq!(
            parse_command(&format!("/admin add {}", "9".repeat(MAX_USER_ID_BYTES + 1))),
            Err(CommandRefusal::ArgumentTooLong)
        );
        // An id that is all digits, is inside the byte bound, and still
        // overflows `i64` is not a user id either — the length bound is not
        // doing the range check for us.
        assert_eq!(
            parse_command("/admin add 99999999999999999999"),
            Err(CommandRefusal::ArgumentInvalid)
        );
        assert_eq!(
            parse_command("/admin add 9223372036854775808"),
            Err(CommandRefusal::ArgumentInvalid)
        );

        assert_eq!(AdminDirective::List.verb(), "list");
        assert_eq!(AdminDirective::List.user_id(), None);
        assert_eq!(
            AdminDirective::Add {
                user_id: OperatorUserId::new(9).expect("user id")
            }
            .user_id()
            .map(OperatorUserId::get),
            Some(9)
        );
    }

    /// The tier gate, from both sides. A member is refused the admin half and
    /// keeps the read half; an administrator keeps everything.
    #[test]
    fn a_member_is_refused_admin_commands_and_an_administrator_is_not() {
        const ADMIN: i64 = 111;
        const MEMBER: i64 = 222;
        const OUTSIDER: i64 = 333;
        let authority = OperatorAuthority::new(
            AllowedUsers::new([ADMIN, MEMBER]).expect("allowlist"),
            AllowedUsers::new([ADMIN]).expect("admins"),
        )
        .expect("authority");

        assert_eq!(authority.tier_of(ADMIN), Some(CommandTier::Admin));
        assert_eq!(authority.tier_of(MEMBER), Some(CommandTier::Allowed));
        assert_eq!(authority.tier_of(OUTSIDER), None);

        for kind in CommandKind::ALL {
            let text = match kind.argument() {
                ArgumentShape::None => format!("/{}", kind.name()),
                ArgumentShape::Task => format!("/{} do the thing", kind.name()),
                ArgumentShape::Reference => format!("/{} SUP-1042", kind.name()),
                ArgumentShape::Directive => format!("/{} list", kind.name()),
                ArgumentShape::MemoryDirective => format!("/{} proposals", kind.name()),
                ArgumentShape::Channel => format!("/{} ops", kind.name()),
                ArgumentShape::ChannelMessage => format!("/{} ops bonjour", kind.name()),
                ArgumentShape::GitHubRepositoryRequest => {
                    format!("/{} automonique create a concise issue", kind.name())
                }
                ArgumentShape::GitHubIssueRequest => format!(
                    "/{} https://github.com/acme/widgets/issues/42 do the thing",
                    kind.name()
                ),
            };
            // The administrator's parse is exactly the untiered one.
            assert_eq!(
                authorize_and_parse_tiered(&authority, ADMIN, &text),
                parse_command(&text),
                "an administrator must reach {text}"
            );
            let member = authorize_and_parse_tiered(&authority, MEMBER, &text);
            match kind.tier() {
                CommandTier::Allowed => {
                    assert_eq!(member, parse_command(&text), "a member must reach {text}")
                }
                CommandTier::Admin => assert_eq!(
                    member,
                    Err(CommandRefusal::NotPermitted),
                    "a member must be refused {text}"
                ),
            }
            // A stranger learns nothing about any of it, whatever the tier.
            assert_eq!(
                authorize_and_parse_tiered(&authority, OUTSIDER, &text),
                Err(CommandRefusal::Unauthorized),
                "{text}"
            );
        }
    }

    /// The refusal a member gets must not depend on how they spelled the
    /// argument, or it becomes an oracle for a grammar that is not theirs.
    #[test]
    fn a_members_refusal_is_the_same_however_the_argument_was_spelled() {
        let authority = OperatorAuthority::new(
            AllowedUsers::new([111, 222]).expect("allowlist"),
            AllowedUsers::new([111]).expect("admins"),
        )
        .expect("authority");
        for text in [
            "/run",
            "/run a task",
            &format!("/run {}", "x".repeat(MAX_RUN_TASK_BYTES + 1)),
            "/work",
            "/work SUP-1042;rm",
            "/say",
            "/say ops",
            "/say ops bonjour tout le monde",
            "/say NOT A CHANNEL bonjour",
            &format!("/say ops {}", "x".repeat(MAX_SAY_TEXT_BYTES + 1)),
            "/admin",
            "/admin add 7654321",
            "/admin nonsense",
        ] {
            assert_eq!(
                authorize_and_parse_tiered(&authority, 222, text),
                Err(CommandRefusal::NotPermitted),
                "{text}"
            );
        }
        // The one thing a member does learn is that the command exists, which
        // the published menu already tells them. An unknown name still reads as
        // unknown rather than as forbidden.
        assert_eq!(
            authorize_and_parse_tiered(&authority, 222, "/runx"),
            Err(CommandRefusal::UnknownCommand)
        );
        // And a message that is not a command at all is refused before any tier
        // is considered.
        assert_eq!(
            authorize_and_parse_tiered(&authority, 222, "hello"),
            Err(CommandRefusal::NotACommand)
        );
    }

    /// The invariant the tier model rests on: an administrator who is not
    /// allowed cannot be composed, because they would be refused at the outer
    /// gate and never reach the tier check.
    #[test]
    fn an_administrator_outside_the_allowed_set_is_refused_at_composition() {
        let refusal = OperatorAuthority::new(
            AllowedUsers::new([222]).expect("allowlist"),
            AllowedUsers::new([111]).expect("admins"),
        )
        .expect_err("an administrator must be allowed");
        assert_eq!(refusal, AllowlistError::AdminNotAllowed);
        assert_eq!(refusal.category(), "admin_not_allowed");

        // The single-tier composition is the one a deployment that never wrote
        // a second tier means, and it cannot violate the invariant.
        let single = OperatorAuthority::single_tier(AllowedUsers::new([1, 2, 3]).expect("allowed"));
        for user_id in [1, 2, 3] {
            assert_eq!(single.tier_of(user_id), Some(CommandTier::Admin));
            assert!(single.may(user_id, CommandKind::Run));
            assert!(single.may(user_id, CommandKind::Admin));
        }
        assert_eq!(single.tier_of(4), None);
        assert!(!single.may(4, CommandKind::Help));
        assert_eq!(single.allowed().as_slice(), single.admins().as_slice());
    }

    #[test]
    fn the_help_marks_exactly_the_admin_commands() {
        let text = help_text();
        for entry in command_manifest() {
            let line = text
                .lines()
                .find(|line| {
                    line.starts_with(&format!("/{} ", entry.name))
                        || line.starts_with(&format!("/{}\u{a0}", entry.name))
                        || *line == format!("/{}", entry.name)
                })
                .unwrap_or_else(|| panic!("/{} is missing from the help", entry.name));
            assert_eq!(
                line.ends_with(ADMIN_HELP_MARK),
                entry.tier == CommandTier::Admin,
                "/{} is marked wrong: {line}",
                entry.name
            );
        }
        assert!(text.contains("/admin <add|remove|list> [user_id]"));
    }

    #[test]
    fn refusal_and_allowlist_vocabularies_are_distinct_and_content_free() {
        let categories: Vec<&str> = [
            CommandRefusal::Unauthorized,
            CommandRefusal::NotPermitted,
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
