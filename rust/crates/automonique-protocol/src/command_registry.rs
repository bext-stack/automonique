// SPDX-License-Identifier: Elastic-2.0

//! The declarative command registry: what a command *is*, not how it runs.
//!
//! One typed description per command — a stable identifier, its aliases, its
//! typed fields, the authorization it requires, its approval policy, whether it
//! supports a dry run, and the retry/concurrency discipline a mutation carries.
//! Every client reads the same description, so no surface needs a
//! command-routing regular expression of its own, and there is none to copy:
//!
//! ```
//! use automonique_protocol::command_registry::admin_command_registry;
//! let registry = admin_command_registry().unwrap();
//! let spec = registry.lookup("run-submit").unwrap();
//! assert_eq!(spec.id().as_str(), "submit_run");
//! ```
//!
//! ```compile_fail
//! use automonique_protocol::command_registry::CommandRegistry;
//! // There is no pattern surface to reach.
//! let spec = CommandRegistry::route("^run[- ]submit$");
//! ```
//!
//! # What this module is not
//!
//! It **describes** commands. It does not route, authorize, execute, or decode
//! one. A [`CommandSpec`] is a value; nothing here dispatches on it, no
//! constructor consults a daemon, and no method turns a description into an
//! effect. The admin protocol in [`crate::admin`] remains the only thing that
//! encodes a request, and the daemon remains the only thing that performs one.
//!
//! # The authorization vocabulary is the one the daemon enforces
//!
//! [`AuthorizationRequirement`] has exactly one value today —
//! [`AuthorizationRequirement::LocalPeer`] — because the local admin transport
//! authenticates the Unix peer before it decodes a frame and checks nothing
//! else. There is no role, scope, or tenant check to describe, so the registry
//! describes none. A named scope this build cannot check is refused rather than
//! recorded:
//!
//! ```
//! use automonique_protocol::command_registry::AuthorizationRequirement;
//! assert!(AuthorizationRequirement::named("local_peer").is_ok());
//! assert!(AuthorizationRequirement::named("admin_role").is_err());
//! ```
//!
//! A registry that advertised a scope nothing enforces would be worse than one
//! that admits it has only the peer check: a client would gate its own UI on a
//! promise the daemon never made. [`ApprovalPolicy`] carries the same
//! discipline, and its [`ApprovalPolicy::OperatorConfirmation`] is explicitly a
//! *client-side* obligation — the daemon sees an authenticated local peer and
//! cannot tell whether a human confirmed anything.
//!
//! # Where the seeded registry comes from
//!
//! [`admin_command_registry`] describes the thirteen commands
//! [`crate::admin::AdminCommand`] actually admits, with the field names those
//! bodies actually encode and the byte bounds `crate::admin` actually enforces
//! — imported from that module rather than restated here, so a widened bound
//! cannot drift out of the description. `tests/command_registry.rs` encodes a
//! real request per command and compares the resulting JSON keys with the
//! declared field names, so a field added to an admin body fails there rather
//! than shipping a registry that describes a message no longer sent.
//!
//! The aliases are the hyphen-joined operation spellings `automonique-cli`
//! writes in `crates/automonique-cli/src/admin_client.rs` (`run-submit`,
//! `reconcile-fail`, and so on). This crate has no dependency on the CLI and
//! therefore does not verify that correspondence; the aliases are declared here
//! because a shipped client already spells them, not because anything here
//! checks that it still does.

use std::error::Error;
use std::fmt;

use crate::admin::{
    MAX_INTAKE_ACTOR_BYTES, MAX_INTAKE_REASON_BYTES, MAX_RECONCILIATION_FIELD_BYTES,
    MAX_RELOAD_ID_BYTES, MAX_RUN_SUBMISSION_KEY_BYTES, MAX_SUBMITTED_RUN_SPEC_BYTES,
    MAX_SYNTHETIC_KEY_BYTES, MAX_SYNTHETIC_SCOPE_BYTES, MAX_SYNTHETIC_TASK_BYTES,
};
use crate::digest::{ALGORITHM, DIGEST_BYTES};
use crate::primitives::{BoundedString, ValueError};

/// Stable schema identifier for the registry described by this module.
pub const COMMAND_REGISTRY_SCHEMA_V1: &str = "automonique.command-registry/v1";

/// Maximum UTF-8 byte length of a stable command identifier.
pub const MAX_COMMAND_ID_BYTES: usize = 64;

/// Maximum UTF-8 byte length of a command alias.
pub const MAX_COMMAND_ALIAS_BYTES: usize = 64;

/// Maximum UTF-8 byte length of a field name.
pub const MAX_FIELD_NAME_BYTES: usize = 64;

/// Maximum UTF-8 byte length of one enumerated field value.
pub const MAX_FIELD_ENUM_VALUE_BYTES: usize = 64;

/// Maximum UTF-8 byte length of one line of help text.
pub const MAX_HELP_TEXT_BYTES: usize = 256;

/// Maximum UTF-8 byte length of a dry-run note.
pub const MAX_DRY_RUN_NOTE_BYTES: usize = 256;

/// Maximum number of fields one command may declare.
pub const MAX_COMMAND_FIELDS: usize = 32;

/// Maximum number of aliases one command may declare.
pub const MAX_COMMAND_ALIASES: usize = 8;

/// Maximum number of values one enumerated field may declare.
pub const MAX_FIELD_ENUM_VALUES: usize = 16;

/// Maximum number of commands one registry may describe.
pub const MAX_REGISTRY_COMMANDS: usize = 128;

/// Bounded, single-line, human-readable help.
pub type HelpText = BoundedString<MAX_HELP_TEXT_BYTES>;

/// Bounded, single-line description of what a dry run returns.
pub type DryRunNote = BoundedString<MAX_DRY_RUN_NOTE_BYTES>;

/// UTF-8 bytes in the canonical spelling of a SHA-256 digest.
///
/// Derived from [`crate::digest`] rather than written as a number, so the
/// registry cannot describe a digest field the digest type no longer produces.
const DIGEST_SPELLING_BYTES: usize = ALGORITHM.len() + 1 + 2 * DIGEST_BYTES;

/// Why a registry value was refused.
///
/// Every variant names what was rejected and why. Identifiers are carried
/// because a registry is assembled from declarations a developer controls, not
/// from peer-supplied bytes; nothing here echoes a message payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandRegistryError {
    /// A bounded field violated the shared value rules.
    Field {
        /// Field that was rejected.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
    /// A bounded field violated its own grammar.
    Grammar {
        /// Field that was rejected.
        field: &'static str,
    },
    /// A bounded collection exceeded its ceiling.
    TooMany {
        /// Collection that was rejected.
        field: &'static str,
        /// Maximum accepted count.
        max: usize,
        /// Supplied count.
        actual: usize,
    },
    /// A registry was built with no commands, so it describes nothing.
    EmptyRegistry,
    /// An enumerated field declared no values, so nothing satisfies it.
    EmptyEnumeration,
    /// An enumerated field declared one value twice.
    DuplicateEnumValue {
        /// The repeated value.
        value: String,
    },
    /// An integer field was declared with its maximum below its minimum.
    InvertedIntegerRange {
        /// Supplied minimum.
        min: i64,
        /// Supplied maximum.
        max: i64,
    },
    /// A string field was declared with a zero byte ceiling, which accepts
    /// nothing.
    ZeroStringBound,
    /// A stable command identifier occurred more than once.
    DuplicateCommand {
        /// The repeated identifier.
        id: String,
    },
    /// One command declared the same field name twice.
    DuplicateField {
        /// The command that declared it.
        command: String,
        /// The repeated field name.
        field: String,
    },
    /// A command declared its own identifier as an alias of itself.
    AliasIsOwnId {
        /// The identifier that was also spelled as an alias.
        id: String,
    },
    /// Two commands claimed the same alias.
    AliasCollision {
        /// The contested alias.
        alias: String,
    },
    /// An alias of one command is the stable identifier of another.
    AliasShadowsCommand {
        /// The alias that shadows an identifier.
        alias: String,
    },
    /// A mutating command declared neither a retry key nor an expected
    /// revision, so nothing makes a repeat safe.
    MutationWithoutRetryCoordinate,
    /// A mutation named a field the command does not declare.
    MutationFieldAbsent {
        /// The command that named it.
        command: String,
        /// The absent field name.
        field: String,
    },
    /// A mutation named an optional field, so the coordinate may be omitted.
    MutationFieldOptional {
        /// The command that named it.
        command: String,
        /// The optional field name.
        field: String,
    },
    /// Dry-run support was declared without saying what a dry run returns.
    DryRunWithoutNote,
    /// A dry-run note was declared by a command that does not support one.
    DryRunNoteWithoutSupport,
    /// A named authorization requirement is not one this build enforces.
    UnenforceableAuthorization {
        /// The refused spelling.
        name: String,
    },
    /// A named approval policy is not one this build represents.
    UnenforceableApproval {
        /// The refused spelling.
        name: String,
    },
}

impl CommandRegistryError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Field { .. } => "field_invalid",
            Self::Grammar { .. } => "field_grammar",
            Self::TooMany { .. } => "too_many",
            Self::EmptyRegistry => "empty_registry",
            Self::EmptyEnumeration => "empty_enumeration",
            Self::DuplicateEnumValue { .. } => "duplicate_enum_value",
            Self::InvertedIntegerRange { .. } => "inverted_integer_range",
            Self::ZeroStringBound => "zero_string_bound",
            Self::DuplicateCommand { .. } => "duplicate_command",
            Self::DuplicateField { .. } => "duplicate_field",
            Self::AliasIsOwnId { .. } => "alias_is_own_id",
            Self::AliasCollision { .. } => "alias_collision",
            Self::AliasShadowsCommand { .. } => "alias_shadows_command",
            Self::MutationWithoutRetryCoordinate => "mutation_without_retry_coordinate",
            Self::MutationFieldAbsent { .. } => "mutation_field_absent",
            Self::MutationFieldOptional { .. } => "mutation_field_optional",
            Self::DryRunWithoutNote => "dry_run_without_note",
            Self::DryRunNoteWithoutSupport => "dry_run_note_without_support",
            Self::UnenforceableAuthorization { .. } => "unenforceable_authorization",
            Self::UnenforceableApproval { .. } => "unenforceable_approval",
        }
    }
}

impl fmt::Display for CommandRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
            Self::Grammar { field } => write!(formatter, "field {field} violates its grammar"),
            Self::TooMany { field, max, actual } => {
                write!(
                    formatter,
                    "{field} holds {actual} entries; maximum is {max}"
                )
            }
            Self::EmptyRegistry => formatter.write_str("registry describes no command"),
            Self::EmptyEnumeration => {
                formatter.write_str("enumerated field declares no accepted value")
            }
            Self::DuplicateEnumValue { value } => {
                write!(formatter, "enumerated value {value} is declared twice")
            }
            Self::InvertedIntegerRange { min, max } => {
                write!(formatter, "integer range {min}..={max} is inverted")
            }
            Self::ZeroStringBound => formatter.write_str("string field accepts zero bytes"),
            Self::DuplicateCommand { id } => {
                write!(formatter, "duplicate command identifier: {id}")
            }
            Self::DuplicateField { command, field } => {
                write!(formatter, "command {command} declares field {field} twice")
            }
            Self::AliasIsOwnId { id } => {
                write!(
                    formatter,
                    "command {id} declares its own identifier as an alias"
                )
            }
            Self::AliasCollision { alias } => {
                write!(formatter, "alias {alias} is claimed by two commands")
            }
            Self::AliasShadowsCommand { alias } => {
                write!(formatter, "alias {alias} is another command's identifier")
            }
            Self::MutationWithoutRetryCoordinate => formatter.write_str(
                "a mutating command must declare an idempotency key, an expected revision, or both",
            ),
            Self::MutationFieldAbsent { command, field } => write!(
                formatter,
                "command {command} names mutation field {field}, which it does not declare"
            ),
            Self::MutationFieldOptional { command, field } => write!(
                formatter,
                "command {command} names optional field {field} as a mutation coordinate"
            ),
            Self::DryRunWithoutNote => {
                formatter.write_str("dry-run support declares no result note")
            }
            Self::DryRunNoteWithoutSupport => {
                formatter.write_str("dry-run result note declared without dry-run support")
            }
            Self::UnenforceableAuthorization { name } => write!(
                formatter,
                "authorization requirement {name} is not one this build enforces"
            ),
            Self::UnenforceableApproval { name } => write!(
                formatter,
                "approval policy {name} is not one this build represents"
            ),
        }
    }
}

impl Error for CommandRegistryError {}

macro_rules! bounded_name {
    ($name:ident, $max:expr, $field:literal, $doc:literal, $grammar:expr) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Maximum accepted UTF-8 byte length.
            pub const MAX_BYTES: usize = $max;

            /// Validate and construct the value.
            ///
            /// # Errors
            ///
            /// Returns [`CommandRegistryError::Field`] when the shared bounded
            /// value rules are violated and [`CommandRegistryError::Grammar`]
            /// when the value's own grammar is.
            pub fn new(value: impl Into<String>) -> Result<Self, CommandRegistryError> {
                let value = value.into();
                validate_bounded(&value, $max, $field)?;
                #[allow(clippy::redundant_closure_call)]
                if !($grammar)(value.as_str()) {
                    return Err(CommandRegistryError::Grammar { field: $field });
                }
                Ok(Self(value))
            }

            /// Return the validated spelling.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

bounded_name!(
    CommandId,
    MAX_COMMAND_ID_BYTES,
    "command_id",
    "Stable command identifier: a dotted path of lowercase segments.\n\n\
     The grammar is [`crate::codec::ProtocolName`]'s dotted discipline widened \
     by the underscore [`crate::codec::MessageKind`] already admits, because \
     the identifiers this product ships are its admin message kinds — \
     `submit_run`, `pause_intake` — and a single-segment path is a path.",
    is_dotted_path
);

bounded_name!(
    CommandAlias,
    MAX_COMMAND_ALIAS_BYTES,
    "command_alias",
    "An alternative spelling that resolves to exactly one command.\n\n\
     The grammar additionally admits `-`, because the spellings shipped clients \
     already use are hyphen-joined (`run-submit`, `outbox-reconcile`).",
    is_dotted_alias_path
);

bounded_name!(
    FieldName,
    MAX_FIELD_NAME_BYTES,
    "field_name",
    "The name of one typed field, as it appears in the command's body.",
    is_body_name
);

bounded_name!(
    FieldEnumValue,
    MAX_FIELD_ENUM_VALUE_BYTES,
    "field_enum_value",
    "One accepted spelling of an enumerated field.",
    is_body_name
);

/// Whether every dot-separated segment is a lowercase body name.
fn is_dotted_path(value: &str) -> bool {
    value.split('.').all(is_body_name)
}

/// The same, with `-` admitted inside a segment.
fn is_dotted_alias_path(value: &str) -> bool {
    value.split('.').all(|segment| {
        segment
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
            && segment.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
    })
}

/// A lowercase name that starts with a letter and otherwise carries digits and
/// underscores, which is the shape every admin body key has.
fn is_body_name(value: &str) -> bool {
    value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn validate_bounded(
    value: &str,
    max_bytes: usize,
    field: &'static str,
) -> Result<(), CommandRegistryError> {
    let error = if max_bytes == 0 {
        Some(ValueError::ZeroBound)
    } else if value.is_empty() {
        Some(ValueError::Empty)
    } else if value.len() > max_bytes {
        Some(ValueError::TooLong {
            max_bytes,
            actual_bytes: value.len(),
        })
    } else if value.chars().any(char::is_control) {
        Some(ValueError::ControlCharacter)
    } else {
        None
    };
    match error {
        Some(error) => Err(CommandRegistryError::Field { field, error }),
        None => Ok(()),
    }
}

/// The byte ceiling of one bounded string field.
///
/// Zero is unrepresentable: a field that accepts nothing is not a field.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StringBound(usize);

impl StringBound {
    /// Declare a non-zero byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRegistryError::ZeroStringBound`] for a zero ceiling.
    pub const fn new(max_bytes: usize) -> Result<Self, CommandRegistryError> {
        if max_bytes == 0 {
            return Err(CommandRegistryError::ZeroStringBound);
        }
        Ok(Self(max_bytes))
    }

    /// Maximum accepted UTF-8 byte length.
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        self.0
    }
}

/// The inclusive range of one integer field.
///
/// An empty range is unrepresentable: both bounds are inclusive and the
/// maximum may not fall below the minimum.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IntegerRange {
    min: i64,
    max: i64,
}

impl IntegerRange {
    /// Declare an inclusive range.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRegistryError::InvertedIntegerRange`] when `max` is
    /// below `min`.
    pub const fn new(min: i64, max: i64) -> Result<Self, CommandRegistryError> {
        if max < min {
            return Err(CommandRegistryError::InvertedIntegerRange { min, max });
        }
        Ok(Self { min, max })
    }

    /// Lowest accepted value.
    ///
    /// Named `minimum` rather than `min` because `Ord` already gives every
    /// reference to this type a `min`, and a reader should not have to know
    /// which one an expression selected.
    #[must_use]
    pub const fn minimum(self) -> i64 {
        self.min
    }

    /// Highest accepted value.
    #[must_use]
    pub const fn maximum(self) -> i64 {
        self.max
    }
}

/// The closed set of spellings one enumerated field accepts.
///
/// Values are sorted at construction, so two declarations of the same set are
/// the same value and render identically.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EnumValues(Vec<FieldEnumValue>);

impl EnumValues {
    /// Declare a non-empty, duplicate-free set.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRegistryError::EmptyEnumeration`] for an empty set,
    /// [`CommandRegistryError::DuplicateEnumValue`] for a repeat, and
    /// [`CommandRegistryError::TooMany`] above [`MAX_FIELD_ENUM_VALUES`].
    pub fn new(
        values: impl IntoIterator<Item = FieldEnumValue>,
    ) -> Result<Self, CommandRegistryError> {
        let mut ordered: Vec<FieldEnumValue> = Vec::new();
        for value in values {
            if ordered.len() == MAX_FIELD_ENUM_VALUES {
                return Err(CommandRegistryError::TooMany {
                    field: "enum_values",
                    max: MAX_FIELD_ENUM_VALUES,
                    actual: MAX_FIELD_ENUM_VALUES + 1,
                });
            }
            ordered.push(value);
        }
        if ordered.is_empty() {
            return Err(CommandRegistryError::EmptyEnumeration);
        }
        ordered.sort();
        if let Some(pair) = ordered.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(CommandRegistryError::DuplicateEnumValue {
                value: pair[0].as_str().to_owned(),
            });
        }
        Ok(Self(ordered))
    }

    /// Accepted spellings in sorted order.
    #[must_use]
    pub fn values(&self) -> &[FieldEnumValue] {
        &self.0
    }
}

/// The closed set of field shapes this product's commands actually use.
///
/// # Why the vocabulary is this short
///
/// Every field of every admin body is a bounded string, a positive integer
/// coordinate, or a closed enumeration; there is no boolean and no unbounded
/// string to describe. A variant for a shape no command has would be a promise
/// about a message this product does not send.
///
/// Two admin fields carry a further grammar this type does not restate:
/// `submit_run.document_hex` is hexadecimal and `submit_run.spec_digest` is a
/// `sha256:`-prefixed digest. Both are described here as the bounded strings
/// they are on the wire, because a second copy of a grammar is a second place
/// for it to be wrong, and `crate::admin` is where those two are enforced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FieldType {
    /// A bounded, control-free UTF-8 string.
    BoundedString(StringBound),
    /// An integer inside an inclusive range.
    Integer(IntegerRange),
    /// One of a closed set of lowercase spellings.
    Enumerated(EnumValues),
}

impl FieldType {
    /// Declare a bounded string field.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRegistryError::ZeroStringBound`] for a zero ceiling.
    pub fn bounded_string(max_bytes: usize) -> Result<Self, CommandRegistryError> {
        StringBound::new(max_bytes).map(Self::BoundedString)
    }

    /// Declare an integer field.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRegistryError::InvertedIntegerRange`] when `max` is
    /// below `min`.
    pub fn integer(min: i64, max: i64) -> Result<Self, CommandRegistryError> {
        IntegerRange::new(min, max).map(Self::Integer)
    }

    /// Declare an enumerated field.
    ///
    /// # Errors
    ///
    /// Returns the refusal [`EnumValues::new`] produces.
    pub fn enumerated(
        values: impl IntoIterator<Item = FieldEnumValue>,
    ) -> Result<Self, CommandRegistryError> {
        EnumValues::new(values).map(Self::Enumerated)
    }

    /// Stable rendering used by generated help.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::BoundedString(bound) => format!("string<={}", bound.max_bytes()),
            Self::Integer(range) => {
                format!("integer {}..={}", range.minimum(), range.maximum())
            }
            Self::Enumerated(values) => {
                let spellings: Vec<&str> =
                    values.values().iter().map(FieldEnumValue::as_str).collect();
                format!("enum{{{}}}", spellings.join("|"))
            }
        }
    }
}

/// Whether a field must be present in every body of its command.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FieldPresence {
    /// The field is present in every body of this command.
    Required,
    /// The field is present in some bodies of this command and absent in
    /// others; the field's help says exactly when.
    Optional,
}

impl FieldPresence {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Optional => "optional",
        }
    }
}

/// One typed field of one command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldDescriptor {
    name: FieldName,
    field_type: FieldType,
    presence: FieldPresence,
    help: HelpText,
}

impl FieldDescriptor {
    /// Describe a field.
    #[must_use]
    pub const fn new(
        name: FieldName,
        field_type: FieldType,
        presence: FieldPresence,
        help: HelpText,
    ) -> Self {
        Self {
            name,
            field_type,
            presence,
            help,
        }
    }

    /// The field's name on the wire.
    #[must_use]
    pub const fn name(&self) -> &FieldName {
        &self.name
    }

    /// The field's type.
    #[must_use]
    pub const fn field_type(&self) -> &FieldType {
        &self.field_type
    }

    /// Whether the field is present in every body of its command.
    #[must_use]
    pub const fn presence(&self) -> FieldPresence {
        self.presence
    }

    /// One line of help.
    #[must_use]
    pub const fn help(&self) -> &HelpText {
        &self.help
    }
}

/// What a caller must have established before the daemon will act.
///
/// See the module documentation: this vocabulary is deliberately the size of
/// what the daemon enforces.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AuthorizationRequirement {
    /// The authenticated local Unix peer.
    ///
    /// The admin transport establishes that the peer is this user before it
    /// decodes a frame, and checks nothing further. Every command this product
    /// ships requires exactly this and nothing more.
    LocalPeer,
}

impl AuthorizationRequirement {
    /// Every requirement this build can express.
    pub const ALL: [Self; 1] = [Self::LocalPeer];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalPeer => "local_peer",
        }
    }

    /// Resolve a named requirement, refusing one this build cannot check.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRegistryError::UnenforceableAuthorization`] for every
    /// spelling outside [`Self::ALL`]. The refusal is the point: a registry may
    /// grow a scope only when something can check it.
    pub fn named(name: &str) -> Result<Self, CommandRegistryError> {
        Self::ALL
            .into_iter()
            .find(|requirement| requirement.as_str() == name)
            .ok_or_else(|| CommandRegistryError::UnenforceableAuthorization {
                name: name.to_owned(),
            })
    }
}

/// Whether a client must obtain a human decision before sending the command.
///
/// This is a *client* obligation. The daemon authenticates a local peer and
/// cannot observe whether a human confirmed anything, so nothing here is
/// enforced server-side and this type does not pretend otherwise. A
/// named-approver policy — a second, identified party recorded durably — is not
/// represented, because there is no approver identity in this product to name.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ApprovalPolicy {
    /// The client may send the command without a separate confirmation.
    None,
    /// The client must obtain the operator's explicit confirmation first.
    OperatorConfirmation,
}

impl ApprovalPolicy {
    /// Every policy this build can express.
    pub const ALL: [Self; 2] = [Self::None, Self::OperatorConfirmation];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::OperatorConfirmation => "operator_confirmation",
        }
    }

    /// Resolve a named policy, refusing one this build cannot represent.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRegistryError::UnenforceableApproval`] for every
    /// spelling outside [`Self::ALL`].
    pub fn named(name: &str) -> Result<Self, CommandRegistryError> {
        Self::ALL
            .into_iter()
            .find(|policy| policy.as_str() == name)
            .ok_or_else(|| CommandRegistryError::UnenforceableApproval {
                name: name.to_owned(),
            })
    }
}

/// Whether a command supports a dry run, and what one returns.
///
/// Support and result travel together, so the flag cannot be decorative: there
/// is no value of this type that claims support without saying what a caller
/// gets back.
///
/// ```
/// use automonique_protocol::command_registry::DryRun;
/// assert!(DryRun::declare(true, None).is_err());
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DryRun {
    /// The command has no dry run. Sending it performs it.
    Unsupported,
    /// The command supports a dry run, which returns the described result.
    Supported {
        /// What a dry run returns instead of performing the command.
        note: DryRunNote,
    },
}

impl DryRun {
    /// Assemble from a flag and an optional note, as a decoder holds them.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRegistryError::DryRunWithoutNote`] for support with no
    /// note and [`CommandRegistryError::DryRunNoteWithoutSupport`] for a note
    /// with no support.
    pub fn declare(
        supported: bool,
        note: Option<DryRunNote>,
    ) -> Result<Self, CommandRegistryError> {
        match (supported, note) {
            (true, Some(note)) => Ok(Self::Supported { note }),
            (false, None) => Ok(Self::Unsupported),
            (true, None) => Err(CommandRegistryError::DryRunWithoutNote),
            (false, Some(_)) => Err(CommandRegistryError::DryRunNoteWithoutSupport),
        }
    }

    /// Whether a dry run exists.
    #[must_use]
    pub const fn supported(&self) -> bool {
        matches!(self, Self::Supported { .. })
    }

    /// What a dry run returns, when there is one.
    #[must_use]
    pub const fn note(&self) -> Option<&DryRunNote> {
        match self {
            Self::Supported { note } => Some(note),
            Self::Unsupported => None,
        }
    }

    /// Stable rendering used by generated help.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Unsupported => "unsupported".to_owned(),
            Self::Supported { note } => format!("supported; returns {note}"),
        }
    }
}

/// The fields a mutating command uses to make a repeat safe.
///
/// At least one coordinate is required. A caller-supplied idempotency key makes
/// a resend the same request; an expected revision makes a resend a
/// `conflict` rather than a second effect. A mutation with neither is a
/// mutation a disconnected client cannot retry, and is refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationKeys {
    idempotency_key: Option<FieldName>,
    expected_revision: Option<FieldName>,
}

impl MutationKeys {
    /// Declare the coordinates of one mutation.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRegistryError::MutationWithoutRetryCoordinate`] when
    /// both are absent.
    pub fn new(
        idempotency_key: Option<FieldName>,
        expected_revision: Option<FieldName>,
    ) -> Result<Self, CommandRegistryError> {
        if idempotency_key.is_none() && expected_revision.is_none() {
            return Err(CommandRegistryError::MutationWithoutRetryCoordinate);
        }
        Ok(Self {
            idempotency_key,
            expected_revision,
        })
    }

    /// The field carrying the caller-supplied retry key.
    #[must_use]
    pub const fn idempotency_key(&self) -> Option<&FieldName> {
        self.idempotency_key.as_ref()
    }

    /// The field carrying the revision the caller believes it is acting on.
    #[must_use]
    pub const fn expected_revision(&self) -> Option<&FieldName> {
        self.expected_revision.as_ref()
    }
}

/// What a command does to durable state, and what makes a repeat safe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MutationDiscipline {
    /// The command changes no durable state, so it declares no coordinates.
    ReadOnly,
    /// The command changes durable state and names the fields a repeat needs.
    Mutating(MutationKeys),
    /// The command changes durable state without a caller-supplied coordinate,
    /// because a repeat states the same fact rather than adding a second one.
    ///
    /// The justification is required: an unexplained exemption from the retry
    /// discipline is the one that turns out to have been an oversight.
    Unkeyed {
        /// Why a repeat of this command is not a second effect.
        justification: HelpText,
    },
}

impl MutationDiscipline {
    /// Whether the command changes durable state.
    #[must_use]
    pub const fn mutates(&self) -> bool {
        !matches!(self, Self::ReadOnly)
    }

    /// Stable rendering used by generated help.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::ReadOnly => "read only".to_owned(),
            Self::Mutating(keys) => {
                let mut rendered = String::from("mutating");
                if let Some(field) = keys.idempotency_key() {
                    rendered.push_str("; idempotency key ");
                    rendered.push_str(field.as_str());
                }
                if let Some(field) = keys.expected_revision() {
                    rendered.push_str("; expected revision ");
                    rendered.push_str(field.as_str());
                }
                rendered
            }
            Self::Unkeyed { justification } => format!("unkeyed; {justification}"),
        }
    }
}

/// Fields used to describe one command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpecParts {
    /// Stable identifier clients name the command by.
    pub id: CommandId,
    /// Alternative spellings that resolve to this command.
    pub aliases: Vec<CommandAlias>,
    /// One line saying what the command does.
    pub summary: HelpText,
    /// The command's typed fields.
    pub fields: Vec<FieldDescriptor>,
    /// What the caller must have established.
    pub authorization: AuthorizationRequirement,
    /// Whether a client must obtain a human decision first.
    pub approval: ApprovalPolicy,
    /// Whether a dry run exists, and what it returns.
    pub dry_run: DryRun,
    /// What the command does to durable state.
    pub mutation: MutationDiscipline,
}

/// One command's complete description.
///
/// Aliases and fields are sorted at construction, so a description built in any
/// order is the same value and renders the same bytes. Field order matches the
/// canonical JSON key order of the command's body for the same reason: both are
/// byte order over the name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    id: CommandId,
    aliases: Vec<CommandAlias>,
    summary: HelpText,
    fields: Vec<FieldDescriptor>,
    authorization: AuthorizationRequirement,
    approval: ApprovalPolicy,
    dry_run: DryRun,
    mutation: MutationDiscipline,
}

impl CommandSpec {
    /// Validate and construct a description.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRegistryError::TooMany`] above
    /// [`MAX_COMMAND_FIELDS`] or [`MAX_COMMAND_ALIASES`],
    /// [`CommandRegistryError::DuplicateField`] for a repeated field name,
    /// [`CommandRegistryError::AliasCollision`] for a repeated alias,
    /// [`CommandRegistryError::AliasIsOwnId`] for an alias equal to the
    /// command's own identifier, and
    /// [`CommandRegistryError::MutationFieldAbsent`] or
    /// [`CommandRegistryError::MutationFieldOptional`] when a mutation names a
    /// field the command does not declare, or declares as optional.
    pub fn new(parts: CommandSpecParts) -> Result<Self, CommandRegistryError> {
        let CommandSpecParts {
            id,
            mut aliases,
            summary,
            mut fields,
            authorization,
            approval,
            dry_run,
            mutation,
        } = parts;

        if fields.len() > MAX_COMMAND_FIELDS {
            return Err(CommandRegistryError::TooMany {
                field: "fields",
                max: MAX_COMMAND_FIELDS,
                actual: fields.len(),
            });
        }
        if aliases.len() > MAX_COMMAND_ALIASES {
            return Err(CommandRegistryError::TooMany {
                field: "aliases",
                max: MAX_COMMAND_ALIASES,
                actual: aliases.len(),
            });
        }

        fields.sort_by(|left, right| left.name.cmp(&right.name));
        if let Some(pair) = fields.windows(2).find(|pair| pair[0].name == pair[1].name) {
            return Err(CommandRegistryError::DuplicateField {
                command: id.as_str().to_owned(),
                field: pair[0].name.as_str().to_owned(),
            });
        }

        aliases.sort();
        if let Some(pair) = aliases.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(CommandRegistryError::AliasCollision {
                alias: pair[0].as_str().to_owned(),
            });
        }
        if aliases.iter().any(|alias| alias.as_str() == id.as_str()) {
            return Err(CommandRegistryError::AliasIsOwnId {
                id: id.as_str().to_owned(),
            });
        }

        if let MutationDiscipline::Mutating(keys) = &mutation {
            for named in [keys.idempotency_key(), keys.expected_revision()]
                .into_iter()
                .flatten()
            {
                let Some(field) = fields.iter().find(|field| &field.name == named) else {
                    return Err(CommandRegistryError::MutationFieldAbsent {
                        command: id.as_str().to_owned(),
                        field: named.as_str().to_owned(),
                    });
                };
                if field.presence() == FieldPresence::Optional {
                    return Err(CommandRegistryError::MutationFieldOptional {
                        command: id.as_str().to_owned(),
                        field: named.as_str().to_owned(),
                    });
                }
            }
        }

        Ok(Self {
            id,
            aliases,
            summary,
            fields,
            authorization,
            approval,
            dry_run,
            mutation,
        })
    }

    /// Stable identifier.
    #[must_use]
    pub const fn id(&self) -> &CommandId {
        &self.id
    }

    /// Aliases in sorted order.
    #[must_use]
    pub fn aliases(&self) -> &[CommandAlias] {
        &self.aliases
    }

    /// One line saying what the command does.
    #[must_use]
    pub const fn summary(&self) -> &HelpText {
        &self.summary
    }

    /// Typed fields in canonical name order.
    #[must_use]
    pub fn fields(&self) -> &[FieldDescriptor] {
        &self.fields
    }

    /// What the caller must have established.
    #[must_use]
    pub const fn authorization(&self) -> AuthorizationRequirement {
        self.authorization
    }

    /// Whether a client must obtain a human decision first.
    #[must_use]
    pub const fn approval(&self) -> ApprovalPolicy {
        self.approval
    }

    /// Whether a dry run exists, and what it returns.
    #[must_use]
    pub const fn dry_run(&self) -> &DryRun {
        &self.dry_run
    }

    /// What the command does to durable state.
    #[must_use]
    pub const fn mutation(&self) -> &MutationDiscipline {
        &self.mutation
    }

    /// Whether `name` is this command's identifier or one of its aliases.
    #[must_use]
    pub fn answers_to(&self, name: &str) -> bool {
        self.id.as_str() == name || self.aliases.iter().any(|alias| alias.as_str() == name)
    }

    /// Append this command's generated help block to `out`.
    fn render_help(&self, out: &mut String) {
        out.push_str(self.id.as_str());
        out.push('\n');
        out.push_str("  summary: ");
        out.push_str(self.summary.as_str());
        out.push('\n');
        out.push_str("  aliases: ");
        if self.aliases.is_empty() {
            out.push_str("(none)");
        } else {
            let spellings: Vec<&str> = self.aliases.iter().map(CommandAlias::as_str).collect();
            out.push_str(&spellings.join(", "));
        }
        out.push('\n');
        out.push_str("  authorization: ");
        out.push_str(self.authorization.as_str());
        out.push('\n');
        out.push_str("  approval: ");
        out.push_str(self.approval.as_str());
        out.push('\n');
        out.push_str("  dry run: ");
        out.push_str(&self.dry_run.describe());
        out.push('\n');
        out.push_str("  mutation: ");
        out.push_str(&self.mutation.describe());
        out.push('\n');
        if self.fields.is_empty() {
            out.push_str("  fields: (none)\n");
            return;
        }
        out.push_str("  fields:\n");
        for field in &self.fields {
            out.push_str("    ");
            out.push_str(field.name().as_str());
            out.push_str(" (");
            out.push_str(field.presence().as_str());
            out.push_str(", ");
            out.push_str(&field.field_type().describe());
            out.push_str("): ");
            out.push_str(field.help().as_str());
            out.push('\n');
        }
    }
}

/// A bounded set of command descriptions with unique identifiers and aliases.
///
/// An alias that resolves to nothing is unrepresentable: an alias lives inside
/// the [`CommandSpec`] it names, and the registry owns no method that binds one
/// to an identifier separately.
///
/// ```compile_fail
/// use automonique_protocol::command_registry::{CommandAlias, admin_command_registry};
/// let registry = admin_command_registry().unwrap();
/// registry.bind_alias(CommandAlias::new("ghost").unwrap(), "no_such_command");
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandRegistry {
    commands: Vec<CommandSpec>,
}

impl CommandRegistry {
    /// Validate and construct a registry.
    ///
    /// Commands are sorted by identifier, so iteration and generated help are
    /// stable regardless of declaration order.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRegistryError::EmptyRegistry`] for no commands,
    /// [`CommandRegistryError::TooMany`] above [`MAX_REGISTRY_COMMANDS`],
    /// [`CommandRegistryError::DuplicateCommand`] for a repeated identifier,
    /// [`CommandRegistryError::AliasCollision`] when two commands claim one
    /// alias, and [`CommandRegistryError::AliasShadowsCommand`] when an alias
    /// is another command's identifier.
    pub fn new(
        commands: impl IntoIterator<Item = CommandSpec>,
    ) -> Result<Self, CommandRegistryError> {
        let mut ordered: Vec<CommandSpec> = Vec::new();
        for command in commands {
            if ordered.len() == MAX_REGISTRY_COMMANDS {
                return Err(CommandRegistryError::TooMany {
                    field: "commands",
                    max: MAX_REGISTRY_COMMANDS,
                    actual: MAX_REGISTRY_COMMANDS + 1,
                });
            }
            ordered.push(command);
        }
        if ordered.is_empty() {
            return Err(CommandRegistryError::EmptyRegistry);
        }
        ordered.sort_by(|left, right| left.id.cmp(&right.id));
        if let Some(pair) = ordered.windows(2).find(|pair| pair[0].id == pair[1].id) {
            return Err(CommandRegistryError::DuplicateCommand {
                id: pair[0].id.as_str().to_owned(),
            });
        }

        let mut claimed: Vec<&str> = Vec::new();
        for command in &ordered {
            for alias in &command.aliases {
                if ordered
                    .iter()
                    .any(|other| other.id.as_str() == alias.as_str())
                {
                    return Err(CommandRegistryError::AliasShadowsCommand {
                        alias: alias.as_str().to_owned(),
                    });
                }
                if claimed.contains(&alias.as_str()) {
                    return Err(CommandRegistryError::AliasCollision {
                        alias: alias.as_str().to_owned(),
                    });
                }
                claimed.push(alias.as_str());
            }
        }

        Ok(Self { commands: ordered })
    }

    /// Stable schema identifier for this registry shape.
    #[must_use]
    pub const fn schema(&self) -> &'static str {
        COMMAND_REGISTRY_SCHEMA_V1
    }

    /// Every command, in stable identifier order.
    #[must_use]
    pub fn commands(&self) -> &[CommandSpec] {
        &self.commands
    }

    /// Resolve an identifier or an alias.
    ///
    /// One name resolves to at most one command; an unknown name resolves to
    /// nothing rather than to a guess.
    #[must_use]
    pub fn lookup(&self, name: &str) -> Option<&CommandSpec> {
        self.commands
            .iter()
            .find(|command| command.answers_to(name))
    }

    /// Render deterministic generated help for the whole registry.
    ///
    /// The output is a pure function of the registry's values: no clock, no
    /// locale, no hash iteration order, and no terminal width. Two calls on one
    /// registry produce identical bytes, and two registries built from the same
    /// declarations in different orders do too.
    #[must_use]
    pub fn help_text(&self) -> String {
        let mut out = String::new();
        out.push_str(COMMAND_REGISTRY_SCHEMA_V1);
        out.push('\n');
        out.push_str(&format!("commands: {}\n", self.commands.len()));
        for command in &self.commands {
            out.push('\n');
            command.render_help(&mut out);
        }
        out
    }
}

/// The registry describing the local administration commands this build ships.
///
/// Thirteen commands, matching [`crate::admin::AdminCommand`]'s variants, with
/// the field names and byte bounds `crate::admin` actually encodes and
/// enforces.
///
/// No shipped command supports a dry run: the admin protocol carries no
/// dry-run field, and declaring one here would describe a message this build
/// does not send. [`DryRun::Supported`] exists so that the first command that
/// gains a dry run must say what it returns.
///
/// # Errors
///
/// Returns a [`CommandRegistryError`] only if a compile-time literal in this
/// function no longer satisfies its own grammar or bound.
pub fn admin_command_registry() -> Result<CommandRegistry, CommandRegistryError> {
    CommandRegistry::new([
        status_spec()?,
        metrics_spec()?,
        generations_spec()?,
        reload_status_spec()?,
        submit_synthetic_spec()?,
        submit_run_spec()?,
        inspect_reconciliation_spec()?,
        fail_reconciliation_spec()?,
        inspect_outbox_spec()?,
        reconcile_outbox_spec()?,
        pause_intake_spec()?,
        resume_intake_spec()?,
        shutdown_spec()?,
    ])
}

fn help(value: &str) -> Result<HelpText, CommandRegistryError> {
    HelpText::new(value).map_err(|error| CommandRegistryError::Field {
        field: "help",
        error,
    })
}

fn required(
    name: &str,
    field_type: FieldType,
    text: &str,
) -> Result<FieldDescriptor, CommandRegistryError> {
    Ok(FieldDescriptor::new(
        FieldName::new(name)?,
        field_type,
        FieldPresence::Required,
        help(text)?,
    ))
}

fn optional(
    name: &str,
    field_type: FieldType,
    text: &str,
) -> Result<FieldDescriptor, CommandRegistryError> {
    Ok(FieldDescriptor::new(
        FieldName::new(name)?,
        field_type,
        FieldPresence::Optional,
        help(text)?,
    ))
}

/// The shape every durable coordinate in an admin body has: a positive integer
/// the encoder writes as canonical JSON, so its ceiling is the wire's.
fn coordinate() -> Result<FieldType, CommandRegistryError> {
    FieldType::integer(1, i64::MAX)
}

fn keyed(
    idempotency_key: Option<&str>,
    expected_revision: Option<&str>,
) -> Result<MutationDiscipline, CommandRegistryError> {
    let idempotency_key = idempotency_key.map(FieldName::new).transpose()?;
    let expected_revision = expected_revision.map(FieldName::new).transpose()?;
    Ok(MutationDiscipline::Mutating(MutationKeys::new(
        idempotency_key,
        expected_revision,
    )?))
}

fn unkeyed(justification: &str) -> Result<MutationDiscipline, CommandRegistryError> {
    Ok(MutationDiscipline::Unkeyed {
        justification: help(justification)?,
    })
}

fn status_spec() -> Result<CommandSpec, CommandRegistryError> {
    CommandSpec::new(CommandSpecParts {
        id: CommandId::new("status")?,
        aliases: Vec::new(),
        summary: help("Read a consistent daemon status snapshot.")?,
        fields: Vec::new(),
        authorization: AuthorizationRequirement::LocalPeer,
        approval: ApprovalPolicy::None,
        dry_run: DryRun::Unsupported,
        mutation: MutationDiscipline::ReadOnly,
    })
}

fn metrics_spec() -> Result<CommandSpec, CommandRegistryError> {
    CommandSpec::new(CommandSpecParts {
        id: CommandId::new("metrics")?,
        aliases: Vec::new(),
        summary: help("Read a Prometheus metrics snapshot.")?,
        fields: Vec::new(),
        authorization: AuthorizationRequirement::LocalPeer,
        approval: ApprovalPolicy::None,
        dry_run: DryRun::Unsupported,
        mutation: MutationDiscipline::ReadOnly,
    })
}

fn generations_spec() -> Result<CommandSpec, CommandRegistryError> {
    CommandSpec::new(CommandSpecParts {
        id: CommandId::new("generations")?,
        aliases: Vec::new(),
        summary: help("Read recent generation tenure and handoff history.")?,
        fields: Vec::new(),
        authorization: AuthorizationRequirement::LocalPeer,
        approval: ApprovalPolicy::None,
        dry_run: DryRun::Unsupported,
        mutation: MutationDiscipline::ReadOnly,
    })
}

fn reload_status_spec() -> Result<CommandSpec, CommandRegistryError> {
    CommandSpec::new(CommandSpecParts {
        id: CommandId::new("reload_status")?,
        aliases: vec![CommandAlias::new("reload-status")?],
        summary: help("Read one reload epoch and its append-only transitions.")?,
        fields: vec![required(
            "reload_id",
            FieldType::bounded_string(MAX_RELOAD_ID_BYTES)?,
            "The durable reload epoch to inspect.",
        )?],
        authorization: AuthorizationRequirement::LocalPeer,
        approval: ApprovalPolicy::None,
        dry_run: DryRun::Unsupported,
        mutation: MutationDiscipline::ReadOnly,
    })
}

fn submit_synthetic_spec() -> Result<CommandSpec, CommandRegistryError> {
    CommandSpec::new(CommandSpecParts {
        id: CommandId::new("submit_synthetic")?,
        aliases: vec![CommandAlias::new("submit")?],
        summary: help("Durably enqueue a no-effect synthetic work item.")?,
        fields: vec![
            required(
                "idempotency_key",
                FieldType::bounded_string(MAX_SYNTHETIC_KEY_BYTES)?,
                "Stable caller-controlled retry key for this item.",
            )?,
            required(
                "scope",
                FieldType::bounded_string(MAX_SYNTHETIC_SCOPE_BYTES)?,
                "Serialization scope the durable scheduler orders this item within.",
            )?,
            required(
                "task",
                FieldType::bounded_string(MAX_SYNTHETIC_TASK_BYTES)?,
                "Synthetic task text; it grants no provider or external-effect authority.",
            )?,
        ],
        authorization: AuthorizationRequirement::LocalPeer,
        approval: ApprovalPolicy::None,
        dry_run: DryRun::Unsupported,
        mutation: keyed(Some("idempotency_key"), None)?,
    })
}

fn submit_run_spec() -> Result<CommandSpec, CommandRegistryError> {
    CommandSpec::new(CommandSpecParts {
        id: CommandId::new("submit_run")?,
        aliases: vec![CommandAlias::new("run-submit")?],
        summary: help(
            "Take durable custody of one canonical RunSpec document; custody is not execution.",
        )?,
        fields: vec![
            required(
                "document_hex",
                FieldType::bounded_string(2 * MAX_SUBMITTED_RUN_SPEC_BYTES)?,
                "The canonical RunSpec document, hex-encoded and carried uninterpreted.",
            )?,
            required(
                "idempotency_key",
                FieldType::bounded_string(MAX_RUN_SUBMISSION_KEY_BYTES)?,
                "Stable caller-controlled retry key for this custody request.",
            )?,
            required(
                "spec_digest",
                FieldType::bounded_string(DIGEST_SPELLING_BYTES)?,
                "The digest the submitter declares for the document; the daemon verifies it.",
            )?,
        ],
        authorization: AuthorizationRequirement::LocalPeer,
        approval: ApprovalPolicy::None,
        dry_run: DryRun::Unsupported,
        mutation: keyed(Some("idempotency_key"), None)?,
    })
}

fn inspect_reconciliation_spec() -> Result<CommandSpec, CommandRegistryError> {
    CommandSpec::new(CommandSpecParts {
        id: CommandId::new("inspect_reconciliation")?,
        aliases: vec![CommandAlias::new("reconcile-inspect")?],
        summary: help("Inspect the durable evidence for one ambiguously claimed run.")?,
        fields: vec![required(
            "run_id",
            coordinate()?,
            "The durable run whose reconciliation evidence is read.",
        )?],
        authorization: AuthorizationRequirement::LocalPeer,
        approval: ApprovalPolicy::None,
        dry_run: DryRun::Unsupported,
        mutation: MutationDiscipline::ReadOnly,
    })
}

fn fail_reconciliation_spec() -> Result<CommandSpec, CommandRegistryError> {
    CommandSpec::new(CommandSpecParts {
        id: CommandId::new("fail_reconciliation")?,
        aliases: vec![CommandAlias::new("reconcile-fail")?],
        summary: help("Explicitly fail one exact old run observation under the daemon's fence.")?,
        fields: vec![
            required(
                "decision_key",
                FieldType::bounded_string(MAX_RECONCILIATION_FIELD_BYTES)?,
                "Stable key this fail-only decision is retried under.",
            )?,
            required(
                "expected_generation_id",
                FieldType::bounded_string(MAX_RECONCILIATION_FIELD_BYTES)?,
                "The daemon generation the observation belongs to.",
            )?,
            required(
                "expected_lease_epoch",
                coordinate()?,
                "The lease epoch the observation belongs to.",
            )?,
            required(
                "expected_revision",
                coordinate()?,
                "The run revision the caller believes it is acting on.",
            )?,
            required(
                "reason",
                FieldType::bounded_string(MAX_RECONCILIATION_FIELD_BYTES)?,
                "Bounded operator account of why the run is failed.",
            )?,
            required("run_id", coordinate()?, "The durable run being failed.")?,
        ],
        authorization: AuthorizationRequirement::LocalPeer,
        approval: ApprovalPolicy::OperatorConfirmation,
        dry_run: DryRun::Unsupported,
        mutation: keyed(Some("decision_key"), Some("expected_revision"))?,
    })
}

fn inspect_outbox_spec() -> Result<CommandSpec, CommandRegistryError> {
    CommandSpec::new(CommandSpecParts {
        id: CommandId::new("inspect_outbox")?,
        aliases: vec![CommandAlias::new("outbox-inspect")?],
        summary: help("Inspect redacted durable evidence for one outbox effect.")?,
        fields: vec![required(
            "outbox_id",
            coordinate()?,
            "The durable outbox effect whose redacted evidence is read.",
        )?],
        authorization: AuthorizationRequirement::LocalPeer,
        approval: ApprovalPolicy::None,
        dry_run: DryRun::Unsupported,
        mutation: MutationDiscipline::ReadOnly,
    })
}

fn reconcile_outbox_spec() -> Result<CommandSpec, CommandRegistryError> {
    CommandSpec::new(CommandSpecParts {
        id: CommandId::new("reconcile_outbox")?,
        aliases: vec![CommandAlias::new("outbox-reconcile")?],
        summary: help("Close one exact expired outbox observation as delivered or dead-lettered.")?,
        fields: vec![
            required(
                "decision",
                FieldType::enumerated([
                    FieldEnumValue::new("dead_letter")?,
                    FieldEnumValue::new("delivered")?,
                ])?,
                "Whether delivery was independently confirmed, or the effect is closed without it.",
            )?,
            required(
                "expected_attempt",
                coordinate()?,
                "The delivery attempt the observation belongs to.",
            )?,
            required(
                "expected_generation_id",
                FieldType::bounded_string(MAX_RECONCILIATION_FIELD_BYTES)?,
                "The daemon generation the observation belongs to.",
            )?,
            required(
                "expected_lease_epoch",
                coordinate()?,
                "The lease epoch the observation belongs to.",
            )?,
            required(
                "expected_lease_token",
                FieldType::bounded_string(MAX_RECONCILIATION_FIELD_BYTES)?,
                "The lease token the observation belongs to.",
            )?,
            required(
                "expected_revision",
                coordinate()?,
                "The outbox revision the caller believes it is acting on.",
            )?,
            required(
                "outbox_id",
                coordinate()?,
                "The durable outbox effect being closed.",
            )?,
            optional(
                "reason",
                FieldType::bounded_string(MAX_RECONCILIATION_FIELD_BYTES)?,
                "Present exactly when the decision is dead_letter: why delivery is abandoned.",
            )?,
            optional(
                "receipt_key",
                FieldType::bounded_string(MAX_RECONCILIATION_FIELD_BYTES)?,
                "Present exactly when the decision is delivered: the confirmed receipt key.",
            )?,
        ],
        authorization: AuthorizationRequirement::LocalPeer,
        approval: ApprovalPolicy::OperatorConfirmation,
        dry_run: DryRun::Unsupported,
        mutation: keyed(None, Some("expected_revision"))?,
    })
}

fn pause_intake_spec() -> Result<CommandSpec, CommandRegistryError> {
    CommandSpec::new(CommandSpecParts {
        id: CommandId::new("pause_intake")?,
        aliases: Vec::new(),
        summary: help("Durably close intake for this generation, naming the deciding operator.")?,
        fields: vec![
            required(
                "actor",
                FieldType::bounded_string(MAX_INTAKE_ACTOR_BYTES)?,
                "The operator's own account of who closed intake; not an authentication claim.",
            )?,
            required(
                "reason",
                FieldType::bounded_string(MAX_INTAKE_REASON_BYTES)?,
                "Why intake is closed; a pause with no stated cause cannot be safely resumed.",
            )?,
        ],
        authorization: AuthorizationRequirement::LocalPeer,
        approval: ApprovalPolicy::OperatorConfirmation,
        dry_run: DryRun::Unsupported,
        mutation: unkeyed(
            "The durable pause is set rather than appended, so a second pause is the same fact.",
        )?,
    })
}

fn resume_intake_spec() -> Result<CommandSpec, CommandRegistryError> {
    CommandSpec::new(CommandSpecParts {
        id: CommandId::new("resume_intake")?,
        aliases: Vec::new(),
        summary: help("Reopen intake, naming the operator who decided to.")?,
        fields: vec![required(
            "actor",
            FieldType::bounded_string(MAX_INTAKE_ACTOR_BYTES)?,
            "The operator's own account of who reopened intake; not an authentication claim.",
        )?],
        authorization: AuthorizationRequirement::LocalPeer,
        approval: ApprovalPolicy::None,
        dry_run: DryRun::Unsupported,
        mutation: unkeyed(
            "The durable pause is cleared rather than appended, so a second resume is the same fact.",
        )?,
    })
}

fn shutdown_spec() -> Result<CommandSpec, CommandRegistryError> {
    CommandSpec::new(CommandSpecParts {
        id: CommandId::new("shutdown")?,
        aliases: Vec::new(),
        summary: help("Stop intake and request an orderly shutdown.")?,
        fields: Vec::new(),
        authorization: AuthorizationRequirement::LocalPeer,
        approval: ApprovalPolicy::OperatorConfirmation,
        dry_run: DryRun::Unsupported,
        mutation: unkeyed(
            "A second shutdown request of one process is the same request; nothing is appended.",
        )?,
    })
}
