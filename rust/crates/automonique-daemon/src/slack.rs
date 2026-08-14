// SPDX-License-Identifier: Elastic-2.0

//! The Slack enablement gate, the configured channel map, and the two
//! operations an operator can ask for from a chat.
//!
//! `automonique-slack-connector` can read one channel's recent messages and post
//! one message. This module is the enablement and naming layer between that
//! client and [`crate::telegram_bridge`], and nothing else: it decides whether
//! this daemon may talk to Slack at all, it turns a name an operator typed into
//! an id the connector will accept, and it renders what came back as one bounded
//! reply.
//!
//! ```text
//! /slack ops  ->  ChannelMap("ops") -> ChannelId  ->  conversations.history
//! /say   ops  ->  ChannelMap("ops") -> ChannelId  ->  chat.postMessage
//! ```
//!
//! # The enablement gate
//!
//! Exactly the shape [`crate::ticket_intake`] and [`crate::telegram`] use, for
//! the same reason. An absent `<state>/automonique/slack/slack.conf` means Slack
//! is deliberately not configured: no credential is read, no client is
//! constructed, and both commands answer [`SLACK_NOT_CONFIGURED`]. A
//! present-but-invalid or present-but-insecure file refuses daemon startup
//! rather than being ignored, because ignoring it would hide an operator error
//! behind an honest-looking disabled state.
//!
//! # Why an operator types a name and never an id
//!
//! [`ChannelId`] admits `C…`, `G…` and `D…` — every conversation the token can
//! see, including a direct message with any person in the workspace. A surface
//! that let a chat message carry one would mean the set of things `/say` can
//! post to is *whatever a sender can spell*, which is the whole workspace.
//!
//! So no id reaches the connector from a chat. The command layer's
//! [`ChannelName`] is a lowercase label, [`ChannelMap`] is the only thing that
//! turns one into an id, and the map is written down by hand in the same private
//! file as the credential. The reachable set is therefore exactly the channels
//! the owner named, and widening it takes editing that file — which is the same
//! cost as adding an operator.
//!
//! # The origin is not configurable
//!
//! There is no `base=` key. [`SlackBase::production`] is the only origin this
//! host addresses, so a configuration file cannot redirect the credential
//! somewhere else. The hermetic tests reach an injected [`SlackApi`] instead of
//! a loopback server, which is a stronger seam than a configurable origin and
//! costs the configuration nothing.
//!
//! # There is no `default_channel`
//!
//! Both commands name their channel. A default would mean a `/say` whose target
//! is decided by a file the operator is not looking at while they type, and the
//! one command in this product that is visible to people outside it should not
//! have an implicit destination.
//!
//! # `/say` is live, and that is the point
//!
//! Nothing here is a dry run. A `/say` from an administrator posts to the real
//! channel, immediately, and there is no second confirmation: the tier gate in
//! [`automonique_transport_runtime`] *is* the authorization, and an
//! administrator typing the command is the deliberate act. What this module owes
//! them in return is honesty about the outcome — see [`SlackWorkspace::post`] on
//! why a transport failure is reported as "unknown" and never as "not posted".

use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use automonique_slack_connector::{
    ChannelId, ConversationsHistoryRequest, MAX_PAGE_LIMIT, MessagePage, MessageText,
    PostMessageRequest, SlackBase, SlackClient, SlackErrorKind, SlackFailure, SlackMessage,
    SlackOutcome, SlackRejection, SlackToken, SlackUser, UserId, UsersInfoRequest,
};
use automonique_transport_runtime::ChannelName;

use crate::telegram_bridge::SlackSurface;

/// Configuration path beneath the daemon's private state directory.
const CONFIG_RELATIVE: &str = "slack/slack.conf";
/// Exact first line of a Slack configuration.
const CONFIG_HEADER: &str = "schema=automonique.slack/v1";
/// Exact final line of a complete Slack configuration.
const CONFIG_TERMINATOR: &str = "end=automonique.slack/v1";
/// Upper bound on the configuration file.
const MAX_CONFIG_BYTES: u64 = 4_096;

/// Most channels one configuration may name.
///
/// The reachable set is meant to be small and reviewable: a host that has named
/// thirty-two channels has told a chat it may post to thirty-two rooms, and a
/// number an owner can hold in their head is the point of the bound.
pub const MAX_CONFIGURED_CHANNELS: usize = 32;

/// How many messages one `/slack` reads.
///
/// A chat reply, not a transcript. Ten is what fits in one Telegram message
/// beside its authors, and a reader who needs more is reading Slack.
pub const SLACK_HISTORY_LIMIT: u16 = 10;

/// Most `users.info` calls one `/slack` will make.
///
/// One page is at most [`SLACK_HISTORY_LIMIT`] messages, so this is a bound on a
/// bound: distinct authors only, and no lookup is repeated inside one reply. It
/// exists so a page of ten messages by ten people cannot become an unbounded
/// fan-out if the history limit is ever raised.
pub const MAX_AUTHOR_LOOKUPS: usize = 10;

/// Longest message preview one listed row carries, in bytes.
pub const MAX_PREVIEW_BYTES: usize = 160;

/// Longest author label one listed row carries, in bytes.
pub const MAX_AUTHOR_BYTES: usize = 32;

/// The whole answer to a Slack command on a host with no `slack.conf`.
///
/// Not a refusal, and deliberately the same sentence for the read and the post:
/// nothing failed, this daemon was simply never given a workspace. An operator
/// told "unavailable" would go looking for a fault that does not exist.
pub const SLACK_NOT_CONFIGURED: &str = "Slack is not configured on this daemon.";

const _: () = assert!(SLACK_HISTORY_LIMIT <= MAX_PAGE_LIMIT);
const _: () = assert!(MAX_AUTHOR_LOOKUPS >= SLACK_HISTORY_LIMIT as usize);

/// The Slack calls this host makes, as one injectable seam.
///
/// [`SlackClient`] is the production implementation and the only one that opens
/// a socket; a test supplies canned answers and this module cannot tell the
/// difference, which is what keeps every test in this crate free of the network
/// and free of a live workspace.
///
/// Three methods, not the connector's six. `auth.test` and `conversations.list`
/// are real capabilities with no command behind them, and a seam that offered
/// them would be a surface this build cannot exercise.
pub trait SlackApi: Send {
    /// Read one page of one conversation's recent messages.
    ///
    /// # Errors
    ///
    /// Returns the connector's closed [`SlackFailure`] vocabulary for a
    /// transport problem or a response that is not the method's contract.
    /// Slack's *own* refusal is an `Ok` outcome, not an error, because it is a
    /// parsed answer.
    fn conversations_history(
        &self,
        channel: &ChannelId,
        limit: u16,
    ) -> Result<SlackOutcome<MessagePage>, SlackFailure>;

    /// Resolve one user, so an author id can be shown as a name.
    ///
    /// # Errors
    ///
    /// As [`SlackApi::conversations_history`], for this method's contract.
    fn users_info(&self, user: &UserId) -> Result<SlackOutcome<SlackUser>, SlackFailure>;

    /// Post one message to a conversation. The one externally visible effect.
    ///
    /// # Errors
    ///
    /// As [`SlackApi::conversations_history`], for this method's contract — and
    /// with one difference in meaning that matters: an error here is *unknown*,
    /// not *not sent*, because a budget can elapse after Slack accepted the
    /// message.
    fn post_message(
        &self,
        channel: &ChannelId,
        text: &MessageText,
    ) -> Result<SlackOutcome<PostedTs>, SlackFailure>;
}

/// The identity of a message that was posted.
///
/// The connector answers a whole `PostedMessage`; this seam carries only the
/// timestamp, because that is the entire part a reply uses and the rest is the
/// message we just sent. A narrower seam is a narrower thing for a fake to have
/// to be right about.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostedTs(pub String);

impl SlackApi for SlackClient {
    fn conversations_history(
        &self,
        channel: &ChannelId,
        limit: u16,
    ) -> Result<SlackOutcome<MessagePage>, SlackFailure> {
        // A limit outside the connector's own bound is this module's mistake,
        // not Slack's, and there is nothing to ask about it: report it as the
        // contract break it would have been.
        let request = ConversationsHistoryRequest::new(channel.clone(), limit)
            .map_err(|_| SlackFailure::InvalidResponse)?;
        Self::conversations_history(self, &request)
    }

    fn users_info(&self, user: &UserId) -> Result<SlackOutcome<SlackUser>, SlackFailure> {
        Self::users_info(self, &UsersInfoRequest::new(user.clone()))
    }

    fn post_message(
        &self,
        channel: &ChannelId,
        text: &MessageText,
    ) -> Result<SlackOutcome<PostedTs>, SlackFailure> {
        let request = PostMessageRequest::new(channel.clone(), text.clone());
        Ok(match Self::post_message(self, &request)? {
            SlackOutcome::Accepted(posted) => {
                SlackOutcome::Accepted(PostedTs(posted.ts.as_str().to_owned()))
            }
            SlackOutcome::Rejected(rejection) => SlackOutcome::Rejected(rejection),
        })
    }
}

/// Why a present Slack configuration was refused.
///
/// Every variant is a startup refusal. An absent file is not an error and is
/// represented by `Ok(None)` from [`SlackConfig::load`].
#[derive(Debug)]
pub enum SlackConfigError {
    /// The file exists but is not a private regular file owned by this user.
    Insecure,
    /// The file could not be read.
    Unreadable,
    /// The frame is malformed: bad header, missing terminator, unknown or
    /// duplicate keys, or trailing content.
    Malformed,
    /// `token` is absent, empty, over-long, outside the credential charset, or
    /// is not an `xoxb-` bot token.
    TokenInvalid,
    /// A `channel` entry is not `name:id`, names a label or an id outside its
    /// grammar, repeats a label, or there are more than
    /// [`MAX_CONFIGURED_CHANNELS`] of them — or there are none at all, which
    /// would be a configured workspace with nothing reachable in it.
    ChannelInvalid,
}

impl fmt::Display for SlackConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Insecure => {
                formatter.write_str("slack configuration is not a private owner-only regular file")
            }
            Self::Unreadable => formatter.write_str("slack configuration is unreadable"),
            Self::Malformed => {
                formatter.write_str("slack configuration frame is malformed or truncated")
            }
            Self::TokenInvalid => formatter.write_str("slack configuration token is invalid"),
            Self::ChannelInvalid => {
                formatter.write_str("slack configuration channel map is invalid or empty")
            }
        }
    }
}

impl std::error::Error for SlackConfigError {}

impl SlackConfigError {
    /// Stable machine-readable category for the daemon's error surface.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::Insecure => "slack_config_insecure",
            Self::Unreadable => "slack_config_unreadable",
            Self::Malformed => "slack_config_malformed",
            Self::TokenInvalid => "slack_config_token",
            Self::ChannelInvalid => "slack_config_channel",
        }
    }
}

/// The channels this host may address, and the labels it addresses them by.
///
/// A sorted list rather than a map: it is at most [`MAX_CONFIGURED_CHANNELS`]
/// long, the order is what a "configured channels" reply prints, and a
/// deterministic order means that reply is the same on every host that wrote the
/// same file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelMap(Vec<(ChannelName, ChannelId)>);

impl ChannelMap {
    /// The id this label names, when the configuration named one.
    #[must_use]
    pub fn resolve(&self, name: &ChannelName) -> Option<&ChannelId> {
        self.0
            .iter()
            .find(|(label, _)| label == name)
            .map(|(_, id)| id)
    }

    /// The configured labels, in configuration order.
    #[must_use]
    pub fn labels(&self) -> Vec<&str> {
        self.0.iter().map(|(label, _)| label.as_str()).collect()
    }

    /// How many channels are reachable at all.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always false: an empty map cannot be constructed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A validated Slack configuration.
///
/// Holding one means the operator authorized this daemon to read and post as
/// their bot. It carries the credential, so it is `Debug`-redacted the way
/// [`SlackToken`] is, and it is consumed into a [`SlackClient`] rather than kept
/// around.
pub struct SlackConfig {
    token: SlackToken,
    channels: ChannelMap,
}

impl fmt::Debug for SlackConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SlackConfig")
            .field("token", &"<redacted>")
            .field("channels", &self.channels.labels())
            .finish()
    }
}

impl SlackConfig {
    /// Configuration file location beneath `state_dir`.
    #[must_use]
    pub fn path(state_dir: &Path) -> PathBuf {
        state_dir.join(CONFIG_RELATIVE)
    }

    /// The channels this configuration makes reachable.
    #[must_use]
    pub const fn channels(&self) -> &ChannelMap {
        &self.channels
    }

    /// Load the configuration, distinguishing "deliberately not configured"
    /// (`Ok(None)`) from "configured but wrong" (`Err`).
    ///
    /// # Errors
    ///
    /// Returns [`SlackConfigError`] naming which part of a present file was
    /// refused. An absent file is never an error.
    pub fn load(state_dir: &Path) -> Result<Option<Self>, SlackConfigError> {
        let path = Self::path(state_dir);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(SlackConfigError::Unreadable),
        };
        if !metadata.is_file()
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.len() > MAX_CONFIG_BYTES
        {
            return Err(SlackConfigError::Insecure);
        }
        let raw = fs::read(&path).map_err(|_| SlackConfigError::Unreadable)?;
        let text = std::str::from_utf8(&raw).map_err(|_| SlackConfigError::Malformed)?;
        Self::parse(text)
    }

    /// Parse one configuration frame. Exposed to this crate's tests so the gate
    /// is provable without a filesystem.
    pub(crate) fn parse(text: &str) -> Result<Option<Self>, SlackConfigError> {
        let mut lines = text.lines();
        if lines.next() != Some(CONFIG_HEADER) {
            return Err(SlackConfigError::Malformed);
        }
        let mut token: Option<SlackToken> = None;
        let mut channels: Vec<(ChannelName, ChannelId)> = Vec::new();
        let mut terminated = false;
        for line in lines {
            if terminated {
                return Err(SlackConfigError::Malformed);
            }
            if line == CONFIG_TERMINATOR {
                terminated = true;
                continue;
            }
            let (key, value) = line.split_once('=').ok_or(SlackConfigError::Malformed)?;
            match key {
                "token" if token.is_none() => {
                    token = Some(
                        SlackToken::new(value.as_bytes().to_vec())
                            .map_err(|_| SlackConfigError::TokenInvalid)?,
                    );
                }
                // Repeatable, so a second one is another channel rather than a
                // duplicate key. A repeated *label* is still refused below: two
                // ids under one name is an ambiguity nobody can resolve later.
                "channel" => channels.push(parse_channel_entry(value)?),
                _ => return Err(SlackConfigError::Malformed),
            }
        }
        if !terminated {
            return Err(SlackConfigError::Malformed);
        }
        if channels.is_empty() || channels.len() > MAX_CONFIGURED_CHANNELS {
            return Err(SlackConfigError::ChannelInvalid);
        }
        for (index, (label, _)) in channels.iter().enumerate() {
            if channels[..index].iter().any(|(seen, _)| seen == label) {
                return Err(SlackConfigError::ChannelInvalid);
            }
        }
        Ok(Some(Self {
            token: token.ok_or(SlackConfigError::TokenInvalid)?,
            channels: ChannelMap(channels),
        }))
    }

    /// Build the live client this configuration authorizes.
    ///
    /// Constructing a client dials nothing, and the origin is
    /// [`SlackBase::production`] rather than anything the file could name.
    #[must_use]
    fn into_workspace(self) -> SlackWorkspace<SlackClient> {
        SlackWorkspace {
            api: SlackClient::new(SlackBase::production(), self.token),
            channels: self.channels,
        }
    }
}

/// Parse one `channel=<label>:<id>` entry.
///
/// The label is validated by the *command layer's* [`ChannelName`], not by a
/// second grammar written here: a label this file admits and the parser refuses
/// would be a channel an operator could configure and never reach.
fn parse_channel_entry(value: &str) -> Result<(ChannelName, ChannelId), SlackConfigError> {
    let (label, id) = value
        .split_once(':')
        .ok_or(SlackConfigError::ChannelInvalid)?;
    Ok((
        ChannelName::new(label).map_err(|_| SlackConfigError::ChannelInvalid)?,
        ChannelId::new(id).map_err(|_| SlackConfigError::ChannelInvalid)?,
    ))
}

/// Slack capability state.
///
/// The same two-state shape [`crate::ticket_intake`] has: a configuration file
/// is itself the authorization, and there is no third state where a credential
/// is held but nobody may use it — who may use it is the Telegram surface's
/// tier model, decided per command.
pub enum SlackHost {
    /// No configuration file exists. Nothing was constructed and no credential
    /// was read; this daemon cannot reach Slack.
    Disabled,
    /// A configuration exists, so a client and the channel map are composed.
    Configured(Box<SlackWorkspace<SlackClient>>),
}

/// The host holds a credential inside its composed client, so `Debug` renders
/// the gate's state and the reachable labels and nothing that could carry one
/// out.
impl fmt::Debug for SlackHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("SlackHost::Disabled"),
            Self::Configured(workspace) => formatter
                .debug_struct("SlackHost::Configured")
                .field("channels", &workspace.channels.labels())
                .field("client", &"<redacted>")
                .finish(),
        }
    }
}

impl SlackHost {
    /// Load the configuration and, when one exists, compose the client.
    ///
    /// Nothing is dialled here: a composed client has issued no request, and a
    /// daemon that is opened and never served never issues one.
    ///
    /// # Errors
    ///
    /// Returns [`SlackConfigError`] for a present-but-refused configuration. An
    /// absent configuration is [`Self::Disabled`], not an error.
    pub fn open(state_dir: &Path) -> Result<Self, SlackConfigError> {
        Ok(match SlackConfig::load(state_dir)? {
            None => Self::Disabled,
            Some(config) => Self::Configured(Box::new(config.into_workspace())),
        })
    }

    /// Whether this host can reach Slack at all.
    #[must_use]
    pub const fn is_configured(&self) -> bool {
        matches!(self, Self::Configured(_))
    }

    /// The surface the control bridge dispatches through, or `None` when Slack
    /// is not configured.
    ///
    /// `None` is what makes the bridge answer [`SLACK_NOT_CONFIGURED`]: the
    /// not-configured reply lives at the one seam rather than inside a workspace
    /// that would have to exist in order to say it does not.
    #[must_use]
    pub fn into_surface(self) -> Option<Box<dyn SlackSurface + Send>> {
        match self {
            Self::Disabled => None,
            Self::Configured(workspace) => Some(workspace),
        }
    }
}

/// One Slack workspace, as this daemon may use it.
///
/// Two operations over one client and one channel map. Every reply it renders is
/// bounded, and no reply carries a byte the *sender* chose: the channel label
/// comes from the configuration, and the message content comes from Slack.
pub struct SlackWorkspace<A: SlackApi> {
    api: A,
    channels: ChannelMap,
}

impl<A: SlackApi> fmt::Debug for SlackWorkspace<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SlackWorkspace")
            .field("channels", &self.channels.labels())
            .field("client", &"<redacted>")
            .finish()
    }
}

impl<A: SlackApi> SlackWorkspace<A> {
    /// Compose one workspace over an injected client.
    ///
    /// The production path goes through [`SlackConfig::into_workspace`]; this is
    /// what a test uses to compose the same rendering over canned answers.
    #[must_use]
    pub const fn new(api: A, channels: ChannelMap) -> Self {
        Self { api, channels }
    }

    /// The channels this workspace can reach.
    #[must_use]
    pub const fn channels(&self) -> &ChannelMap {
        &self.channels
    }

    /// Resolve one label, or render the whole answer for one nobody configured.
    ///
    /// The refusal lists the labels that *are* configured, which is
    /// configuration this host wrote down rather than anything a sender typed —
    /// so the reply cannot be used to make the bot repeat a sender's text, and
    /// an operator who mistyped a channel is told what they could have typed.
    fn channel_for(&self, name: &ChannelName) -> Result<&ChannelId, String> {
        self.channels.resolve(name).ok_or_else(|| {
            format!(
                "No such channel is configured on this daemon. Configured: {}.",
                self.channels.labels().join(", ")
            )
        })
    }

    /// Read one channel's recent messages and render them as one reply.
    ///
    /// # Errors
    ///
    /// Returns the operator-facing sentence for a read that produced nothing:
    /// an unconfigured label, Slack's own refusal, or a call that did not reach
    /// a contract answer. Nothing was read in any of them.
    pub fn read_recent(&mut self, name: &ChannelName) -> Result<String, String> {
        let channel = self.channel_for(name)?;
        let page = match self.api.conversations_history(channel, SLACK_HISTORY_LIMIT) {
            Ok(SlackOutcome::Accepted(page)) => page,
            Ok(SlackOutcome::Rejected(rejection)) => {
                return Err(read_rejection_reply(&rejection, name));
            }
            Err(failure) => {
                return Err(format!(
                    "Slack could not be reached ({}), so nothing was read.",
                    failure.category()
                ));
            }
        };
        if page.messages.is_empty() {
            return Ok(format!("#{name} has no recent messages."));
        }
        let authors = self.author_labels(&page);
        let mut text = format!("#{name}, {} most recent:", page.messages.len());
        for message in &page.messages {
            text.push('\n');
            text.push_str(&message_line(message, &authors));
        }
        Ok(text)
    }

    /// Post one message to one channel.
    ///
    /// **This posts, for real, to the real channel.** The tier gate is the whole
    /// authorization and there is no second confirmation here; what this owes
    /// the administrator who typed it is an honest outcome.
    ///
    /// # Errors
    ///
    /// Returns the operator-facing sentence for a post that did not certainly
    /// land. Two of those cases are different and are told apart on purpose: a
    /// [`SlackOutcome::Rejected`] is Slack saying it did *not* post, while a
    /// [`SlackFailure`] is this host not knowing — a request budget can elapse
    /// after Slack accepted the message, so the reply says "may or may not" and
    /// tells the operator to look before sending it again. Reporting that as
    /// "nothing was posted" would be the one lie that gets a channel posted to
    /// twice.
    pub fn post(&mut self, name: &ChannelName, text: &str) -> Result<String, String> {
        let channel = self.channel_for(name)?;
        // The command layer's own bounds are tighter than Slack's, so this
        // refusal is unreachable from `/say` today. It is an arm rather than an
        // unwrap because the two grammars are in different crates and only one
        // of them is Slack's.
        let body = MessageText::new(text).map_err(|_| {
            String::from("That message is not in a form Slack accepts, so nothing was posted.")
        })?;
        match self.api.post_message(channel, &body) {
            Ok(SlackOutcome::Accepted(posted)) => {
                Ok(format!("Posted to #{name} (ts {}).", posted.0))
            }
            Ok(SlackOutcome::Rejected(rejection)) => Err(post_rejection_reply(&rejection, name)),
            Err(failure) => Err(format!(
                "Slack did not confirm the post ({}). It may or may not have been posted — \
                 check #{name} before sending it again.",
                failure.category()
            )),
        }
    }

    /// Resolve the distinct authors of one page, bounded.
    ///
    /// A lookup that fails or that Slack refuses leaves the author unresolved,
    /// and the caller then prints the *id* as an id. It does not record the id
    /// as if it were a name: that is the exact lossy repair the connector's own
    /// documentation refuses, and doing it here would put a `U0…` string where a
    /// reader expects a person.
    fn author_labels(&mut self, page: &MessagePage) -> Vec<(UserId, String)> {
        let mut labels: Vec<(UserId, String)> = Vec::new();
        for message in &page.messages {
            let Some(user) = message.user.as_ref() else {
                continue;
            };
            if labels.len() >= MAX_AUTHOR_LOOKUPS {
                break;
            }
            if labels.iter().any(|(seen, _)| seen == user) {
                continue;
            }
            if let Ok(SlackOutcome::Accepted(profile)) = self.api.users_info(user) {
                labels.push((user.clone(), profile.display_label().to_owned()));
            }
        }
        labels
    }
}

impl<A: SlackApi> SlackSurface for SlackWorkspace<A> {
    fn recent_messages(&mut self, channel: &ChannelName) -> Result<String, String> {
        self.read_recent(channel)
    }

    fn post_message(&mut self, channel: &ChannelName, text: &str) -> Result<String, String> {
        self.post(channel, text)
    }
}

/// One message's line in a `/slack` reply.
///
/// The instant is the seconds half of Slack's `ts`, printed as the Unix seconds
/// it is. Rendering it as a date would need a calendar this crate does not
/// carry, and inventing a format for a number an operator can already correlate
/// against Slack's own view would be a second opinion about a value with one.
fn message_line(message: &SlackMessage, authors: &[(UserId, String)]) -> String {
    format!(
        "{} {}: {}",
        short_ts(message),
        author_label(message, authors),
        preview(&message.text),
    )
}

/// The seconds half of a message timestamp.
fn short_ts(message: &SlackMessage) -> &str {
    let ts = message.ts.as_str();
    ts.split_once('.').map_or(ts, |(seconds, _)| seconds)
}

/// Who a reader should understand wrote this message.
///
/// Four cases, and none of them invents a person: a member whose profile
/// resolved is their display label, a member whose profile did not is their id
/// *marked as an id*, an integration is the name it posted under, and a message
/// with neither is a dash.
fn author_label(message: &SlackMessage, authors: &[(UserId, String)]) -> String {
    if let Some(user) = message.user.as_ref() {
        let label = authors
            .iter()
            .find(|(seen, _)| seen == user)
            .map_or_else(|| format!("user {user}"), |(_, label)| label.clone());
        return bounded_field(&label, MAX_AUTHOR_BYTES);
    }
    if let Some(username) = message.username.as_ref() {
        return bounded_field(username, MAX_AUTHOR_BYTES);
    }
    if message.bot_id.is_some() {
        return String::from("app");
    }
    String::from("-")
}

/// One message's text, on one line and bounded.
///
/// Newlines and tabs become spaces because a listing is one row per message and
/// a multi-line message would otherwise silently become several rows. The
/// connector already refuses every other control character on the way in.
fn preview(text: &str) -> String {
    if text.is_empty() {
        return String::from("(no text)");
    }
    let flattened: String = text
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    bounded_field(flattened.trim(), MAX_PREVIEW_BYTES)
}

/// One listed field, cut at a character boundary and marked when it was cut.
fn bounded_field(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut cut = max_bytes;
    while cut > 0 && !value.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &value[..cut])
}

/// What Slack's refusal of a *read* means, and what to do about it.
fn read_rejection_reply(rejection: &SlackRejection, name: &ChannelName) -> String {
    format!(
        "{} Nothing was read. ({})",
        repair(rejection, name),
        rejection.code()
    )
}

/// What Slack's refusal of a *post* means, and what to do about it.
///
/// A rejection is Slack saying it did not accept the message, so this one is
/// allowed to state that nothing was posted. A [`SlackFailure`] is not, and does
/// not come through here.
fn post_rejection_reply(rejection: &SlackRejection, name: &ChannelName) -> String {
    format!(
        "{} Nothing was posted. ({})",
        repair(rejection, name),
        rejection.code()
    )
}

/// The repair one classified refusal calls for, in a sentence.
///
/// The classification is the connector's; this is only the wording. Each
/// sentence names a different action, which is the entire reason
/// [`SlackErrorKind`] exists rather than a boolean.
fn repair(rejection: &SlackRejection, name: &ChannelName) -> String {
    match rejection.kind() {
        SlackErrorKind::NotInChannel => {
            format!("Slack refused: this bot is not in #{name}. Invite it to the channel.")
        }
        SlackErrorKind::ChannelNotFound => format!(
            "Slack refused: it has no channel with the id configured for #{name}. \
             Check that entry in slack.conf."
        ),
        SlackErrorKind::MissingScope => String::from(
            "Slack refused: this bot token does not carry the scope for that. \
             Reinstall the app with the scope it needs.",
        ),
        SlackErrorKind::InvalidAuth => {
            String::from("Slack refused the credential. Replace the token in slack.conf.")
        }
        SlackErrorKind::RateLimited => match rejection.retry_after_seconds() {
            Some(seconds) => format!("Slack is rate-limiting this app; it asked for {seconds}s."),
            None => String::from("Slack is rate-limiting this app."),
        },
        SlackErrorKind::UserNotFound => String::from("Slack refused: it knows no such user."),
        SlackErrorKind::Invalid => String::from("Slack refused the request as malformed."),
        SlackErrorKind::Other => String::from("Slack refused the request."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use automonique_slack_connector::{MessageTs, SlackErrorCode};

    const SECRET: &str = "xoxb-0000000000-fixture-secret-never-print";

    fn config(lines: &[&str]) -> String {
        let mut text = vec![String::from(CONFIG_HEADER)];
        text.extend(lines.iter().map(|line| (*line).to_owned()));
        text.push(String::from(CONFIG_TERMINATOR));
        text.push(String::new());
        text.join("\n")
    }

    fn complete() -> Vec<String> {
        vec![
            format!("token={SECRET}"),
            String::from("channel=ops:C0RESERVED01"),
            String::from("channel=incidents:C0RESERVED02"),
        ]
    }

    fn borrowed(lines: &[String]) -> Vec<&str> {
        lines.iter().map(String::as_str).collect()
    }

    fn parsed() -> SlackConfig {
        SlackConfig::parse(&config(&borrowed(&complete())))
            .expect("valid configuration")
            .expect("present configuration")
    }

    fn name(value: &str) -> ChannelName {
        ChannelName::new(value).expect("channel name")
    }

    /// THE GATE, CLOSED. No configuration means nothing to parse and nothing to
    /// construct.
    #[test]
    fn an_absent_configuration_is_not_an_error() {
        let directory = tempfile::tempdir().expect("temporary directory");
        assert!(
            SlackConfig::load(directory.path())
                .expect("an absent file is deliberate")
                .is_none()
        );
        let host = SlackHost::open(directory.path()).expect("host opens");
        assert!(!host.is_configured());
        assert!(matches!(host, SlackHost::Disabled));
        assert_eq!(format!("{host:?}"), "SlackHost::Disabled");
        // And no surface, which is what makes both commands answer that Slack
        // is not configured.
        assert!(host.into_surface().is_none());
    }

    /// The other side of the gate: a complete file authorizes live calls.
    #[test]
    fn a_complete_configuration_carries_the_credential_and_the_channel_map() {
        let parsed = parsed();
        assert_eq!(parsed.channels().len(), 2);
        assert!(!parsed.channels().is_empty());
        assert_eq!(parsed.channels().labels(), vec!["ops", "incidents"]);
        assert_eq!(
            parsed
                .channels()
                .resolve(&name("ops"))
                .map(ChannelId::as_str),
            Some("C0RESERVED01")
        );
        // The name an operator types is the lowercase key, however they typed
        // it, and a label nobody configured resolves to nothing at all.
        assert_eq!(
            parsed
                .channels()
                .resolve(&name("#Incidents"))
                .map(ChannelId::as_str),
            Some("C0RESERVED02")
        );
        assert!(parsed.channels().resolve(&name("random")).is_none());
    }

    #[test]
    fn the_credential_never_reaches_a_rendering_of_the_configuration() {
        let parsed = parsed();
        let rendered = format!("{parsed:?}");
        assert!(!rendered.contains(SECRET), "rendered: {rendered}");
        assert!(!rendered.contains("xoxb-"), "rendered: {rendered}");
        assert!(rendered.contains("<redacted>"));
        // The composed host and workspace are the two other things that hold it.
        let workspace = parsed.into_workspace();
        let rendered = format!("{workspace:?}");
        assert!(!rendered.contains("xoxb-"), "rendered: {rendered}");
        assert!(rendered.contains("<redacted>"));
        let host = SlackHost::Configured(Box::new(workspace));
        let rendered = format!("{host:?}");
        assert!(!rendered.contains("xoxb-"), "rendered: {rendered}");
        assert!(rendered.contains("<redacted>"));
        assert!(host.is_configured());
    }

    #[test]
    fn every_incomplete_or_malformed_frame_is_refused() {
        // A missing required key names itself.
        for (dropped, expected) in [
            ("token=", "slack_config_token"),
            ("channel=", "slack_config_channel"),
        ] {
            let lines = complete();
            let kept: Vec<&str> = borrowed(&lines)
                .into_iter()
                .filter(|line| !line.starts_with(dropped))
                .collect();
            let error = SlackConfig::parse(&config(&kept)).expect_err("incomplete frame");
            assert_eq!(error.category(), expected);
        }

        // A malformed value names the field it was for.
        for (line, expected) in [
            ("token=", "slack_config_token"),
            ("token=not-a-slack-token", "slack_config_token"),
            // A user token acts as a person; only a bot token is admitted.
            ("token=xoxp-0000000000-user-token", "slack_config_token"),
            ("channel=ops", "slack_config_channel"),
            ("channel=ops:", "slack_config_channel"),
            ("channel=:C0RESERVED01", "slack_config_channel"),
            ("channel=ops:not-an-id", "slack_config_channel"),
            // The id position is Slack's grammar, so a lowercase one — which is
            // what an operator gets by pasting a name where an id goes — is
            // refused rather than sent.
            ("channel=ops:c0reserved01", "slack_config_channel"),
            ("channel=ops eu:C0RESERVED01", "slack_config_channel"),
        ] {
            let lines = complete();
            let mut kept: Vec<&str> = borrowed(&lines)
                .into_iter()
                .filter(|existing| {
                    !existing.starts_with(line.split_once('=').expect("key").0)
                        || line.starts_with("channel")
                })
                .collect();
            kept.push(line);
            let error = SlackConfig::parse(&config(&kept)).expect_err("malformed value");
            assert_eq!(error.category(), expected, "{line}");
        }

        // A label that *looks* like a conversation id is not refused, and does
        // not need to be: a label is only ever a key into this map, so the
        // worst it can do is name a channel under a confusing word. What would
        // be dangerous is the reverse — a sender's text reaching the id
        // position — and there is no path for that at all.
        let lines = complete();
        let mut labelled = borrowed(&lines);
        labelled.push("channel=C0RESERVED01:C0RESERVED09");
        let parsed = SlackConfig::parse(&config(&labelled))
            .expect("a label may be spelled anything the grammar admits")
            .expect("present configuration");
        assert_eq!(
            parsed
                .channels()
                .resolve(&name("c0reserved01"))
                .map(ChannelId::as_str),
            Some("C0RESERVED09"),
        );

        // Two ids under one label is an ambiguity nobody could resolve later.
        let lines = complete();
        let mut duplicated = borrowed(&lines);
        duplicated.push("channel=ops:C0RESERVED09");
        assert_eq!(
            SlackConfig::parse(&config(&duplicated))
                .expect_err("duplicate label")
                .category(),
            "slack_config_channel"
        );

        // A configuration naming more channels than the bound is refused while
        // it is being read.
        let mut many: Vec<String> = vec![format!("token={SECRET}")];
        for index in 0..=MAX_CONFIGURED_CHANNELS {
            many.push(format!("channel=room-{index}:C0RESERVED{index:02}"));
        }
        assert_eq!(
            SlackConfig::parse(&config(&borrowed(&many)))
                .expect_err("too many channels")
                .category(),
            "slack_config_channel"
        );

        // Frame damage is refused before any field is believed.
        let lines = complete();
        let complete_frame = config(&borrowed(&lines));
        for (what, text) in [
            (
                "a missing header",
                complete_frame.replacen(CONFIG_HEADER, "", 1),
            ),
            (
                "a missing terminator",
                complete_frame.replacen(CONFIG_TERMINATOR, "", 1),
            ),
            (
                "content after the terminator",
                format!("{complete_frame}channel=other:C0RESERVED03\n"),
            ),
            (
                "a duplicate token",
                complete_frame.replacen(
                    CONFIG_TERMINATOR,
                    &format!("token={SECRET}\n{CONFIG_TERMINATOR}"),
                    1,
                ),
            ),
            (
                "an unknown key",
                complete_frame.replacen(
                    CONFIG_TERMINATOR,
                    &format!("base=https://slack.example.com\n{CONFIG_TERMINATOR}"),
                    1,
                ),
            ),
            (
                "a keyless line",
                complete_frame.replacen(
                    CONFIG_TERMINATOR,
                    &format!("nonsense\n{CONFIG_TERMINATOR}"),
                    1,
                ),
            ),
        ] {
            assert_eq!(
                SlackConfig::parse(&text).expect_err(what).category(),
                "slack_config_malformed",
                "{what} must be refused"
            );
        }
    }

    /// THE GATE, AS THE FILESYSTEM SEES IT. A world-readable configuration is a
    /// startup refusal, not a warning: the file holds a credential.
    #[test]
    fn a_configuration_anybody_can_read_is_refused() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = SlackConfig::path(directory.path());
        fs::create_dir_all(path.parent().expect("parent")).expect("configuration directory");
        let lines = complete();
        fs::write(&path, config(&borrowed(&lines))).expect("configuration written");

        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .expect("private");
        assert!(
            SlackConfig::load(directory.path())
                .expect("a private file is admitted")
                .is_some()
        );

        for mode in [0o644, 0o604, 0o660] {
            fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(mode))
                .expect("permissions");
            assert_eq!(
                SlackConfig::load(directory.path())
                    .expect_err("a readable credential is refused")
                    .category(),
                "slack_config_insecure",
                "mode {mode:o}"
            );
        }
    }

    // ------------------------------------------------------------- the fake

    /// A Slack that answers from a script and never opens a socket.
    #[derive(Default)]
    struct FakeSlack {
        history: Option<Result<SlackOutcome<MessagePage>, SlackFailure>>,
        post: Option<Result<SlackOutcome<PostedTs>, SlackFailure>>,
        users: Vec<(String, &'static str)>,
        posted: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
    }

    impl FakeSlack {
        fn with_history(mut self, messages: Vec<SlackMessage>) -> Self {
            self.history = Some(Ok(SlackOutcome::Accepted(MessagePage {
                messages,
                has_more: false,
                next_cursor: None,
            })));
            self
        }

        fn with_user(mut self, id: &str, label: &'static str) -> Self {
            self.users.push((id.to_owned(), label));
            self
        }

        fn rejecting(mut self, code: &str) -> Self {
            let rejection = SlackRejection::new(SlackErrorCode::sanitized(code), None);
            self.history = Some(Ok(SlackOutcome::Rejected(rejection.clone())));
            self.post = Some(Ok(SlackOutcome::Rejected(rejection)));
            self
        }

        fn failing(mut self, failure: SlackFailure) -> Self {
            self.history = Some(Err(failure));
            self.post = Some(Err(failure));
            self
        }

        fn accepting_posts(mut self, ts: &str) -> Self {
            self.post = Some(Ok(SlackOutcome::Accepted(PostedTs(ts.to_owned()))));
            self
        }
    }

    impl SlackApi for FakeSlack {
        fn conversations_history(
            &self,
            _channel: &ChannelId,
            limit: u16,
        ) -> Result<SlackOutcome<MessagePage>, SlackFailure> {
            assert_eq!(limit, SLACK_HISTORY_LIMIT, "one page, of the bounded size");
            match &self.history {
                Some(Ok(outcome)) => Ok(outcome.clone()),
                Some(Err(failure)) => Err(*failure),
                None => Err(SlackFailure::Unavailable),
            }
        }

        fn users_info(&self, user: &UserId) -> Result<SlackOutcome<SlackUser>, SlackFailure> {
            let Some((_, label)) = self
                .users
                .iter()
                .find(|(id, _)| id.as_str() == user.as_str())
            else {
                return Ok(SlackOutcome::Rejected(SlackRejection::new(
                    SlackErrorCode::sanitized("user_not_found"),
                    None,
                )));
            };
            Ok(SlackOutcome::Accepted(SlackUser {
                id: user.clone(),
                name: (*label).to_owned(),
                real_name: None,
                display_name: Some((*label).to_owned()),
                is_bot: Some(false),
                deleted: Some(false),
            }))
        }

        fn post_message(
            &self,
            channel: &ChannelId,
            text: &MessageText,
        ) -> Result<SlackOutcome<PostedTs>, SlackFailure> {
            self.posted
                .lock()
                .expect("posted")
                .push((channel.as_str().to_owned(), text.as_str().to_owned()));
            match &self.post {
                Some(Ok(outcome)) => Ok(outcome.clone()),
                Some(Err(failure)) => Err(*failure),
                None => Err(SlackFailure::Unavailable),
            }
        }
    }

    fn message(user: Option<&str>, ts: &str, text: &str) -> SlackMessage {
        SlackMessage {
            kind: String::from("message"),
            user: user.map(|id| UserId::new(id).expect("user id")),
            bot_id: None,
            username: None,
            subtype: None,
            text: text.to_owned(),
            ts: MessageTs::new(ts).expect("ts"),
            thread_ts: None,
            reply_count: None,
        }
    }

    fn workspace(api: FakeSlack) -> SlackWorkspace<FakeSlack> {
        SlackWorkspace::new(api, parsed().channels)
    }

    #[test]
    fn a_read_lists_the_page_with_its_authors_resolved() {
        let api = FakeSlack::default()
            .with_history(vec![
                message(Some("U0RESERVED1"), "1723542000.000100", "premier message"),
                message(Some("U0RESERVED2"), "1723541000.000200", "deuxieme\nligne"),
                // The same author twice: one lookup, not two.
                message(Some("U0RESERVED1"), "1723540000.000300", ""),
            ])
            .with_user("U0RESERVED1", "amelie")
            .with_user("U0RESERVED2", "camille");
        let mut workspace = workspace(api);

        let reply = workspace
            .read_recent(&name("ops"))
            .expect("the page renders");
        assert!(reply.starts_with("#ops, 3 most recent:"), "{reply}");
        assert!(
            reply.contains("1723542000 amelie: premier message"),
            "{reply}"
        );
        // A multi-line message stays one row.
        assert!(
            reply.contains("1723541000 camille: deuxieme ligne"),
            "{reply}"
        );
        // A message with no text says so rather than rendering an empty row.
        assert!(reply.contains("1723540000 amelie: (no text)"), "{reply}");
        assert_eq!(reply.lines().count(), 4, "one header and three rows");
    }

    /// An author Slack will not resolve is printed as the id it is, and never
    /// as if the id were somebody's name.
    #[test]
    fn an_unresolvable_author_is_printed_as_an_id() {
        let api = FakeSlack::default().with_history(vec![message(
            Some("U0RESERVED9"),
            "1723542000.000100",
            "bonjour",
        )]);
        let reply = workspace(api)
            .read_recent(&name("ops"))
            .expect("the page renders");
        assert!(reply.contains("user U0RESERVED9: bonjour"), "{reply}");
    }

    #[test]
    fn an_empty_channel_reads_as_empty_rather_than_as_a_failure() {
        let reply = workspace(FakeSlack::default().with_history(Vec::new()))
            .read_recent(&name("ops"))
            .expect("an empty channel is an answer");
        assert_eq!(reply, "#ops has no recent messages.");
    }

    /// A label nobody configured reaches no id, so no call is made at all.
    #[test]
    fn an_unconfigured_channel_addresses_nothing() {
        let api = FakeSlack::default().accepting_posts("1723542000.000100");
        let posted = std::sync::Arc::clone(&api.posted);
        let mut workspace = workspace(api);
        let refusal = workspace
            .read_recent(&name("random"))
            .expect_err("no such channel");
        assert!(
            refusal.starts_with("No such channel is configured"),
            "{refusal}"
        );
        assert!(refusal.contains("ops, incidents"), "{refusal}");
        let refusal = workspace
            .post(&name("random"), "bonjour")
            .expect_err("no such channel");
        assert!(
            refusal.starts_with("No such channel is configured"),
            "{refusal}"
        );
        assert!(
            posted.lock().expect("posted").is_empty(),
            "an unresolvable name must not reach chat.postMessage"
        );
    }

    #[test]
    fn a_post_goes_to_the_configured_id_and_confirms_with_its_timestamp() {
        let api = FakeSlack::default().accepting_posts("1723542000.000100");
        let posted = std::sync::Arc::clone(&api.posted);
        let reply = workspace(api)
            .post(&name("incidents"), "la base est de retour")
            .expect("the post is confirmed");
        assert_eq!(reply, "Posted to #incidents (ts 1723542000.000100).");
        assert_eq!(
            posted.lock().expect("posted").as_slice(),
            [(
                String::from("C0RESERVED02"),
                String::from("la base est de retour")
            )],
            "the id the map named, and the exact text"
        );
    }

    /// Slack's own refusals are told apart, because each names a different
    /// repair — and a refusal of a post may say nothing was posted.
    #[test]
    fn each_slack_refusal_is_rendered_as_the_repair_it_calls_for() {
        for (code, expected) in [
            ("not_in_channel", "this bot is not in #ops"),
            ("channel_not_found", "no channel with the id configured"),
            ("missing_scope", "does not carry the scope"),
            ("invalid_auth", "Replace the token in slack.conf"),
            ("ratelimited", "rate-limiting this app"),
            ("is_archived", "Slack refused the request."),
        ] {
            let api = FakeSlack::default().rejecting(code);
            let posted = std::sync::Arc::clone(&api.posted);
            let mut workspace = workspace(api);
            let read = workspace
                .read_recent(&name("ops"))
                .expect_err("a refusal is not a page");
            assert!(read.contains(expected), "{code}: {read}");
            assert!(read.contains("Nothing was read."), "{code}: {read}");
            // The exact code survives, so an operator can look it up.
            assert!(read.contains(code), "{code}: {read}");

            let post = workspace
                .post(&name("ops"), "bonjour")
                .expect_err("a refusal is not a post");
            assert!(post.contains(expected), "{code}: {post}");
            assert!(post.contains("Nothing was posted."), "{code}: {post}");
            // The call was made and Slack refused it — this is not the
            // unresolvable-channel path, which never reaches the client.
            assert_eq!(posted.lock().expect("posted").len(), 1, "{code}");
        }
    }

    /// The one asymmetry that matters: a *transport* failure on a post is
    /// unknown, not "nothing happened".
    #[test]
    fn a_failed_post_is_reported_as_unknown_and_a_failed_read_as_nothing_read() {
        let mut workspace = workspace(FakeSlack::default().failing(SlackFailure::TimedOut));
        let read = workspace
            .read_recent(&name("ops"))
            .expect_err("a failure is not a page");
        assert_eq!(
            read,
            "Slack could not be reached (timed_out), so nothing was read."
        );

        let post = workspace
            .post(&name("ops"), "bonjour")
            .expect_err("a failure is not a confirmation");
        assert!(post.contains("may or may not have been posted"), "{post}");
        assert!(post.contains("timed_out"), "{post}");
        assert!(
            !post.contains("Nothing was posted"),
            "a timeout must never claim the message was not sent: {post}"
        );
    }

    /// A long message and a long author cannot make one row unbounded.
    #[test]
    fn listed_fields_are_bounded_and_marked_when_they_are_cut() {
        let long = "e\u{301}".repeat(MAX_PREVIEW_BYTES);
        let api = FakeSlack::default()
            .with_history(vec![message(
                Some("U0RESERVED1"),
                "1723542000.000100",
                &long,
            )])
            .with_user("U0RESERVED1", "amelie");
        let reply = workspace(api)
            .read_recent(&name("ops"))
            .expect("the page renders");
        let row = reply.lines().nth(1).expect("one row");
        assert!(row.ends_with('…'), "{row}");
        assert!(row.len() < long.len(), "{row}");
    }
}
