// SPDX-License-Identifier: Elastic-2.0

//! The operator modifier vocabulary, as pure values.
//!
//! A modifier says *how* to handle a message; a command in
//! [`crate::telegram_control`] says *what to do*. The two grammars compose and
//! neither replaces the other: `!fast what is the status?` is a question with a
//! routing hint, and `!new /status` is still a `/status`. Nothing here parses a
//! command name, and nothing in the slash registry parses a modifier.
//!
//! # Leading tokens only
//!
//! Modifiers are read from the *leading* run of whitespace-separated tokens and
//! nowhere else. The scan stops at the first token that is not a modifier, and
//! everything from that token on is returned untouched, byte for byte.
//!
//! That rule is the answer to the collision this grammar would otherwise have
//! with content. An operator pastes shell, a stack trace, a code fence, a
//! sentence ending in an exclamation — all of it contains `!words`, and none of
//! it is addressed to the parser. A mid-text scan would have to decide which
//! `!token` was meant, and every heuristic for that is wrong on somebody's
//! message. A leading scan needs no heuristic: a modifier is something you type
//! at the front, deliberately, before you say anything.
//!
//! It also bounds the refusal. A leading `!nope` is a typed
//! [`CommandRefusal::ArgumentInvalid`], because somebody plainly tried to
//! modify this message and misspelled it. The same token in the middle of a
//! paragraph is prose, and refusing a whole message over it would make this
//! bot unable to discuss its own syntax.
//!
//! # Closed on both halves
//!
//! [`ModifierKind`] is the registry and [`ALL_MODIFIERS`] is all of it.
//! [`ModelAlias`] is closed too: `!model` names a deployment the *host*
//! configured, never a model string, so no chat message can select a model
//! nobody reviewed. Resolving an alias to an actual deployment is the daemon's
//! job — an alias this grammar admits may still be one the host never
//! configured, and refusing that is dispatch's answer to give.

use std::fmt;

use crate::telegram_control::CommandRefusal;

/// The sigil that introduces a modifier.
pub const MODIFIER_SIGIL: char = '!';
/// Number of modifiers in the closed registry.
pub const MODIFIER_COUNT: usize = 5;
/// Longest modifier token this parser will look at, sigil included.
pub const MAX_MODIFIER_TOKEN_BYTES: usize = 16;
/// Longest model alias token this parser will look at.
pub const MAX_MODEL_ALIAS_BYTES: usize = 16;

const _: () = assert!(MODIFIER_COUNT == ALL_MODIFIERS.len());
const _: () = assert!(MAX_MODEL_ALIAS_BYTES <= MAX_MODIFIER_TOKEN_BYTES);

/// One row of the closed modifier registry.
///
/// Split from [`MessageModifier`] the way [`crate::CommandKind`]
/// is split from [`crate::ControlCommand`]: the kind is the
/// vocabulary and can be enumerated, the value carries what was parsed.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ModifierKind {
    /// Start a fresh conversation before handling this message.
    New,
    /// Route this message to the latency-oriented profile.
    Fast,
    /// Route this message to the bounded operational-lookup profile.
    Ask,
    /// Route this message to the full-strength reasoning profile.
    Think,
    /// Route this message to a named configured deployment.
    Model,
}

/// Every modifier, in the order the help renders them.
pub const ALL_MODIFIERS: [ModifierKind; MODIFIER_COUNT] = [
    ModifierKind::New,
    ModifierKind::Fast,
    ModifierKind::Ask,
    ModifierKind::Think,
    ModifierKind::Model,
];

impl ModifierKind {
    /// The word an operator types after the sigil.
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Fast => "fast",
            Self::Ask => "ask",
            Self::Think => "think",
            Self::Model => "model",
        }
    }

    /// Whether this modifier consumes the token after it.
    #[must_use]
    pub const fn takes_alias(self) -> bool {
        matches!(self, Self::Model)
    }

    /// Whether this modifier selects a reasoning profile.
    ///
    /// The three that do are mutually exclusive — a message cannot be routed
    /// two ways — and that exclusion is enforced at parse time rather than left
    /// for a dispatcher to notice.
    #[must_use]
    pub const fn selects_profile(self) -> bool {
        matches!(self, Self::Fast | Self::Ask | Self::Think)
    }

    /// Look one keyword up in the closed registry.
    ///
    /// Exact, lowercase, and deliberately *not* case-insensitive — unlike a
    /// command name. A command is a word an operator types and a phone keyboard
    /// may capitalize; a modifier is a sigil-prefixed switch, and admitting
    /// `!Fast` would mean admitting that a capitalized first word of a sentence
    /// beginning `!Fast forward the...` was a routing instruction.
    #[must_use]
    pub fn from_keyword(keyword: &str) -> Option<Self> {
        ALL_MODIFIERS
            .into_iter()
            .find(|kind| kind.keyword() == keyword)
    }
}

impl fmt::Display for ModifierKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{MODIFIER_SIGIL}{}", self.keyword())
    }
}

/// The closed set of deployments `!model` may name.
///
/// A key into the host's own configuration, exactly like
/// [`crate::ChannelName`], and closed for the same reason: a
/// free string here would let a chat message select a model, a reasoning
/// budget and a spend nobody reviewed. There is no code path from this value to
/// a provider except through the map the owner wrote.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ModelAlias {
    /// The configured harness deployment that runs tools in a sandbox.
    Codex,
    /// The configured direct chat-completion deployment.
    Flash,
}

impl ModelAlias {
    /// Every alias this grammar admits.
    pub const ALL: [Self; 2] = [Self::Codex, Self::Flash];

    /// The token an operator types.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Flash => "flash",
        }
    }

    /// Resolve one alias token.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRefusal::MissingArgument`] when empty,
    /// [`CommandRefusal::ArgumentTooLong`] beyond [`MAX_MODEL_ALIAS_BYTES`],
    /// and [`CommandRefusal::ArgumentInvalid`] for anything outside the closed
    /// set — including a real model identifier, which is the case this refusal
    /// exists for.
    pub fn parse(token: &str) -> Result<Self, CommandRefusal> {
        if token.is_empty() {
            return Err(CommandRefusal::MissingArgument);
        }
        if token.len() > MAX_MODEL_ALIAS_BYTES {
            return Err(CommandRefusal::ArgumentTooLong);
        }
        Self::ALL
            .into_iter()
            .find(|alias| alias.as_str() == token)
            .ok_or(CommandRefusal::ArgumentInvalid)
    }
}

impl fmt::Display for ModelAlias {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One parsed modifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MessageModifier {
    /// `!new` — rotate the conversation head before handling this message.
    New,
    /// `!fast` — the latency-oriented profile.
    Fast,
    /// `!ask` — the bounded operational-lookup profile.
    Ask,
    /// `!think` — the full-strength reasoning profile.
    Think,
    /// `!model <alias>` — a configured deployment, by alias.
    Model {
        /// The deployment the host configuration must resolve.
        alias: ModelAlias,
    },
}

impl MessageModifier {
    /// The registry row this value belongs to.
    ///
    /// Exhaustive on purpose: a modifier cannot be added to the value without
    /// being given a kind, and therefore a keyword and a parse rule.
    #[must_use]
    pub const fn kind(self) -> ModifierKind {
        match self {
            Self::New => ModifierKind::New,
            Self::Fast => ModifierKind::Fast,
            Self::Ask => ModifierKind::Ask,
            Self::Think => ModifierKind::Think,
            Self::Model { .. } => ModifierKind::Model,
        }
    }
}

impl fmt::Display for MessageModifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model { alias } => write!(formatter, "{MODIFIER_SIGIL}model {alias}"),
            other => write!(formatter, "{}", other.kind()),
        }
    }
}

/// The bounded set of modifiers one message carried.
///
/// At most one of each kind, and at most one of the three that select a
/// profile, so the set can never say two contradictory things about how to
/// handle a message.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MessageModifiers(Vec<MessageModifier>);

impl MessageModifiers {
    /// The modifiers, in the order they were typed.
    #[must_use]
    pub fn as_slice(&self) -> &[MessageModifier] {
        &self.0
    }

    /// Whether the message carried no modifier at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many modifiers the message carried.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this message asked for a fresh conversation first.
    #[must_use]
    pub fn rotates_conversation(&self) -> bool {
        self.0.contains(&MessageModifier::New)
    }

    /// The profile this message selected, if it selected one.
    #[must_use]
    pub fn profile(&self) -> Option<ModifierKind> {
        self.0
            .iter()
            .map(|modifier| modifier.kind())
            .find(|kind| kind.selects_profile())
    }

    /// The deployment alias this message named, if it named one.
    #[must_use]
    pub fn model(&self) -> Option<ModelAlias> {
        self.0.iter().find_map(|modifier| match modifier {
            MessageModifier::Model { alias } => Some(*alias),
            _ => None,
        })
    }

    fn push(&mut self, modifier: MessageModifier) -> Result<(), CommandRefusal> {
        if self
            .0
            .iter()
            .any(|existing| existing.kind() == modifier.kind())
        {
            return Err(CommandRefusal::UnexpectedArgument);
        }
        if modifier.kind().selects_profile() && self.profile().is_some() {
            return Err(CommandRefusal::ArgumentInvalid);
        }
        self.0.push(modifier);
        Ok(())
    }
}

/// Read the leading modifiers off one message.
///
/// Returns the modifiers and the residual text: everything from the first
/// non-modifier token onward, byte for byte, with no trimming, reflowing or
/// re-quoting of the operator's own content. A message that is nothing but
/// modifiers yields an empty residual, which the caller must treat as a message
/// with no body rather than as a body that happened to be blank.
///
/// # Errors
///
/// - [`CommandRefusal::MessageTooLong`] beyond
///   [`crate::MAX_COMMAND_TEXT_BYTES`], checked before a byte
///   is scanned.
/// - [`CommandRefusal::ArgumentInvalid`] for a leading `!token` outside
///   [`ALL_MODIFIERS`], for a second profile modifier, and for a `!model` alias
///   outside [`ModelAlias::ALL`].
/// - [`CommandRefusal::UnexpectedArgument`] for the same modifier twice.
/// - [`CommandRefusal::ArgumentTooLong`] for a `!token` longer than
///   [`MAX_MODIFIER_TOKEN_BYTES`], refused while it is read rather than after
///   it is looked up.
/// - [`CommandRefusal::MissingArgument`] for a trailing `!model` with no alias.
pub fn parse_modifiers(text: &str) -> Result<(MessageModifiers, String), CommandRefusal> {
    if text.len() > crate::telegram_control::MAX_COMMAND_TEXT_BYTES {
        return Err(CommandRefusal::MessageTooLong);
    }
    let mut modifiers = MessageModifiers::default();
    // The offset of the first byte that is not part of a consumed modifier.
    let mut residual_at = leading_space(text, 0);
    loop {
        let rest = &text[residual_at..];
        let token = rest
            .split_ascii_whitespace()
            .next()
            .filter(|token| token.starts_with(MODIFIER_SIGIL));
        let Some(token) = token else {
            break;
        };
        if token.len() > MAX_MODIFIER_TOKEN_BYTES {
            return Err(CommandRefusal::ArgumentTooLong);
        }
        let keyword = &token[MODIFIER_SIGIL.len_utf8()..];
        let kind = ModifierKind::from_keyword(keyword).ok_or(CommandRefusal::ArgumentInvalid)?;
        let mut cursor = leading_space(text, residual_at) + token.len();
        let modifier = if kind.takes_alias() {
            let alias_at = leading_space(text, cursor);
            let alias = text[alias_at..]
                .split_ascii_whitespace()
                .next()
                .ok_or(CommandRefusal::MissingArgument)?;
            cursor = alias_at + alias.len();
            MessageModifier::Model {
                alias: ModelAlias::parse(alias)?,
            }
        } else {
            match kind {
                ModifierKind::New => MessageModifier::New,
                ModifierKind::Fast => MessageModifier::Fast,
                ModifierKind::Ask => MessageModifier::Ask,
                ModifierKind::Think => MessageModifier::Think,
                ModifierKind::Model => return Err(CommandRefusal::ArgumentInvalid),
            }
        };
        modifiers.push(modifier)?;
        residual_at = leading_space(text, cursor);
    }
    Ok((modifiers, text[residual_at..].to_owned()))
}

/// The offset of the first non-space byte at or after `from`.
///
/// ASCII whitespace only, and only between tokens: the residual keeps whatever
/// its own interior whitespace was, because that is the operator's text and not
/// this parser's to normalize.
fn leading_space(text: &str, from: usize) -> usize {
    text[from..]
        .find(|character: char| !character.is_ascii_whitespace())
        .map_or(text.len(), |offset| from + offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telegram_control::MAX_COMMAND_TEXT_BYTES;

    /// Every member of the closed set parses, and the registry is exactly as
    /// long as it claims.
    #[test]
    fn every_modifier_in_the_closed_set_parses_from_its_own_keyword() {
        assert_eq!(ALL_MODIFIERS.len(), MODIFIER_COUNT);
        for kind in ALL_MODIFIERS {
            assert_eq!(ModifierKind::from_keyword(kind.keyword()), Some(kind));
            assert_eq!(kind.to_string(), format!("!{}", kind.keyword()));
            let text = if kind.takes_alias() {
                format!("!{} codex body", kind.keyword())
            } else {
                format!("!{} body", kind.keyword())
            };
            let (modifiers, residual) = parse_modifiers(&text).expect("parses");
            assert_eq!(modifiers.len(), 1, "{text}");
            assert_eq!(
                modifiers.as_slice()[0].kind(),
                kind,
                "{text} parsed as another kind"
            );
            assert_eq!(residual, "body", "{text}");
        }
        // Every keyword is distinct, or two modifiers would answer to one word.
        let mut keywords: Vec<&str> = ALL_MODIFIERS.iter().map(|kind| kind.keyword()).collect();
        let count = keywords.len();
        keywords.sort_unstable();
        keywords.dedup();
        assert_eq!(keywords.len(), count);
    }

    #[test]
    fn the_model_alias_set_is_closed_against_real_model_identifiers() {
        for alias in ModelAlias::ALL {
            assert_eq!(ModelAlias::parse(alias.as_str()), Ok(alias));
            assert_eq!(
                parse_modifiers(&format!("!model {alias} go")),
                Ok((
                    MessageModifiers(vec![MessageModifier::Model { alias }]),
                    String::from("go")
                ))
            );
        }
        // The alias is a key into configuration, so nothing that is a model
        // identifier — or a path, or a version — reaches a provider from a chat.
        for token in ["gpt-5.6-luna", "Codex", "CODEX", "codex-", "../codex"] {
            assert_eq!(
                ModelAlias::parse(token),
                Err(CommandRefusal::ArgumentInvalid),
                "{token}"
            );
            assert_eq!(
                parse_modifiers(&format!("!model {token} go")),
                Err(CommandRefusal::ArgumentInvalid),
                "{token}"
            );
        }
        // A model identifier long enough to exceed the alias bound is refused
        // while it is read rather than after it is looked up. Refused either
        // way, and this is the pair that shows the bound is doing work.
        assert_eq!(
            ModelAlias::parse("deepseek-v4-flash"),
            Err(CommandRefusal::ArgumentTooLong)
        );
        assert_eq!(
            parse_modifiers("!model deepseek-v4-flash go"),
            Err(CommandRefusal::ArgumentTooLong)
        );
        assert_eq!(
            ModelAlias::parse(&"a".repeat(MAX_MODEL_ALIAS_BYTES + 1)),
            Err(CommandRefusal::ArgumentTooLong)
        );
        // A `!model` with nothing after it names no deployment.
        assert_eq!(
            parse_modifiers("!model"),
            Err(CommandRefusal::MissingArgument)
        );
        assert_eq!(
            parse_modifiers("!model   "),
            Err(CommandRefusal::MissingArgument)
        );
    }

    /// The refusal, in full. A leading `!token` that is not in the set is a
    /// typed refusal naming nothing of the sender's text.
    #[test]
    fn an_unknown_or_miscased_leading_modifier_is_a_typed_refusal() {
        for text in [
            "!nope body",
            "!nope",
            "!ne w body",
            "! fast body",
            "!fastt body",
            "!fast- body",
        ] {
            assert_eq!(
                parse_modifiers(text),
                Err(CommandRefusal::ArgumentInvalid),
                "{text}"
            );
        }
        // Case-variants are refused rather than folded, so a capitalized first
        // word of a sentence cannot become a routing instruction by accident.
        for text in ["!Fast body", "!FAST body", "!New body", "!Model codex body"] {
            assert_eq!(
                parse_modifiers(text),
                Err(CommandRefusal::ArgumentInvalid),
                "{text}"
            );
        }
        // The refusal carries no sender text at all.
        assert_eq!(
            CommandRefusal::ArgumentInvalid.operator_reply(),
            "That argument is not in an accepted form."
        );
        // A token nobody could have meant is refused while it is read.
        assert_eq!(
            parse_modifiers(&format!("!{}", "x".repeat(MAX_MODIFIER_TOKEN_BYTES))),
            Err(CommandRefusal::ArgumentTooLong)
        );
        assert_eq!(
            parse_modifiers(&"x".repeat(MAX_COMMAND_TEXT_BYTES + 1)),
            Err(CommandRefusal::MessageTooLong)
        );
    }

    /// The whole-token rule. A `!word` that is not a standalone leading token
    /// is content, and content is returned untouched.
    #[test]
    fn a_modifier_is_never_read_out_of_the_middle_of_a_message() {
        for text in [
            "explain what !fast does",
            "the flag is a!fast thing",
            "deploy --force!new now",
            "wow!",
            "hello !nope world",
            "«!fast»",
        ] {
            let (modifiers, residual) = parse_modifiers(text).expect("content is not a grammar");
            assert!(modifiers.is_empty(), "{text}");
            assert_eq!(residual, text, "{text} was not returned byte for byte");
        }
    }

    /// The code-fence choice, pinned. A fenced block is content like any other,
    /// and the leading-token rule is what makes that true without this parser
    /// having to understand Markdown at all.
    #[test]
    fn a_code_fence_is_content_and_its_interior_is_never_scanned() {
        let fenced = "```sh\n!fast --now\n!nope\n```";
        let (modifiers, residual) = parse_modifiers(fenced).expect("a fence is content");
        assert!(modifiers.is_empty());
        assert_eq!(residual, fenced);

        // A modifier in front of a fence is still a modifier, and the fence
        // that follows it survives byte for byte — including its newlines,
        // which nothing here trims.
        let (modifiers, residual) =
            parse_modifiers("!fast ```sh\n!nope\n```").expect("a leading modifier");
        assert_eq!(modifiers.as_slice(), [MessageModifier::Fast]);
        assert_eq!(residual, "```sh\n!nope\n```");
    }

    /// The residual is the operator's text, not this parser's rendering of it.
    #[test]
    fn the_residual_keeps_every_byte_the_operator_typed_after_the_modifiers() {
        let (modifiers, residual) =
            parse_modifiers("!new   !think    deux mots\nligne deux  ").expect("parses");
        assert_eq!(
            modifiers.as_slice(),
            [MessageModifier::New, MessageModifier::Think]
        );
        assert_eq!(residual, "deux mots\nligne deux  ");

        // Newline is whitespace between tokens, so a modifier on its own line
        // is a modifier — and the body keeps its own interior shape.
        let (modifiers, residual) =
            parse_modifiers("!ask\n\nquelle est la question ?\n\nvoilà").expect("parses");
        assert_eq!(modifiers.as_slice(), [MessageModifier::Ask]);
        assert_eq!(residual, "quelle est la question ?\n\nvoilà");

        // A message that is only modifiers has no body at all.
        assert_eq!(
            parse_modifiers("!new !fast"),
            Ok((
                MessageModifiers(vec![MessageModifier::New, MessageModifier::Fast]),
                String::new()
            ))
        );
        // Non-ASCII bodies are not sliced through: the offsets this parser
        // computes are token boundaries, never byte guesses.
        let (modifiers, residual) = parse_modifiers("!new « déjà vu »").expect("parses");
        assert_eq!(modifiers.as_slice(), [MessageModifier::New]);
        assert_eq!(residual, "« déjà vu »");
        // And a message with nothing in it is a message with nothing in it.
        assert_eq!(
            parse_modifiers(""),
            Ok((MessageModifiers::default(), String::new()))
        );
        assert_eq!(
            parse_modifiers("   "),
            Ok((MessageModifiers::default(), String::new()))
        );
    }

    /// A set that says two contradictory things about one message is refused
    /// rather than resolved by an order nobody wrote down.
    #[test]
    fn a_message_cannot_carry_two_profiles_or_the_same_modifier_twice() {
        for text in [
            "!fast !think body",
            "!think !ask body",
            "!ask !fast body",
            "!fast !fast body",
        ] {
            assert!(parse_modifiers(text).is_err(), "{text}");
        }
        assert_eq!(
            parse_modifiers("!new !new body"),
            Err(CommandRefusal::UnexpectedArgument)
        );
        assert_eq!(
            parse_modifiers("!fast !think body"),
            Err(CommandRefusal::ArgumentInvalid)
        );
        assert_eq!(
            parse_modifiers("!model codex !model flash body"),
            Err(CommandRefusal::UnexpectedArgument)
        );
    }

    /// The accessors a dispatcher reads, so it never re-derives what the parser
    /// already decided.
    #[test]
    fn the_parsed_set_reports_the_routing_seams_it_selected() {
        let (modifiers, residual) =
            parse_modifiers("!new !think !model flash rends compte").expect("parses");
        assert_eq!(residual, "rends compte");
        assert!(modifiers.rotates_conversation());
        assert_eq!(modifiers.profile(), Some(ModifierKind::Think));
        assert_eq!(modifiers.model(), Some(ModelAlias::Flash));
        assert_eq!(modifiers.len(), 3);
        assert!(!modifiers.is_empty());
        assert_eq!(
            modifiers.as_slice()[2].to_string(),
            "!model flash",
            "a modifier renders as what an operator would type"
        );

        let (empty, _) = parse_modifiers("plain question").expect("parses");
        assert!(!empty.rotates_conversation());
        assert_eq!(empty.profile(), None);
        assert_eq!(empty.model(), None);
        assert!(empty.is_empty());

        // Exactly the three profile modifiers select a profile.
        for kind in ALL_MODIFIERS {
            assert_eq!(
                kind.selects_profile(),
                matches!(
                    kind,
                    ModifierKind::Fast | ModifierKind::Ask | ModifierKind::Think
                ),
                "{kind}"
            );
            assert_eq!(kind.takes_alias(), kind == ModifierKind::Model, "{kind}");
        }
    }

    /// The two grammars compose. A modifier in front of a slash command leaves
    /// a command the slash registry parses exactly as it always did.
    #[test]
    fn modifiers_compose_with_the_slash_registry_rather_than_replacing_it() {
        use crate::telegram_control::{ControlCommand, parse_command};

        let (modifiers, residual) = parse_modifiers("!new /status").expect("parses");
        assert_eq!(modifiers.as_slice(), [MessageModifier::New]);
        assert_eq!(residual, "/status");
        assert_eq!(parse_command(&residual), Ok(ControlCommand::Status));

        // And a bare command is untouched by this grammar.
        let (modifiers, residual) = parse_modifiers("/say ops bonjour !fast").expect("parses");
        assert!(modifiers.is_empty());
        assert_eq!(residual, "/say ops bonjour !fast");
    }
}
