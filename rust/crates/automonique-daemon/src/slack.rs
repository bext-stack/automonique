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
//! Ticket intake additionally needs an `app_token=xapp-…` Socket Mode token and
//! one or more repeated `admin=U…` Slack user ids. Each configured `channel=` is
//! an intake allowlist entry. The app token and administrator list must either
//! both be present or both be absent, so a half-configured approval surface
//! cannot silently start.
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

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use automonique_github_connector::IssueLocator;
use automonique_protocol::event::EventKind;
use automonique_protocol::progress_api::ProgressFrame;
use automonique_slack_connector::{
    AppendStreamRequest, AppsConnectionsOpenClient, ChannelId, ConversationsHistoryRequest,
    HomeView, MAX_PAGE_LIMIT, MessageBlocks, MessagePage, MessageText, MessageTs, ModalView,
    OpenViewRequest, PostMessageRequest, PublishViewRequest, SlackAppToken, SlackBase, SlackClient,
    SlackErrorKind, SlackFailure, SlackMessage, SlackOutcome, SlackRejection,
    SlackSocketModeConnector, SlackToken, SlackUser, SocketModeFailure, StartStreamRequest,
    StopStreamRequest, StreamChunks, StreamMessage, StreamText, TriggerId, UpdateMessageRequest,
    UserId, UsersInfoRequest,
};
use automonique_store::agent_memory::{
    AgentMemoryStore, ConversationScope, ExternalIdentity, MessageInput, redact_content,
};
use automonique_store::approval_requests::{ApprovalRequests, ApprovalState};
use automonique_store::slack_interactions::{
    SlackInteractionAction, SlackInteractionInput, SlackInteractionRecord, SlackInteractionState,
    SlackInteractionStore,
};
use automonique_support_connector::{
    TicketDecision, TicketDecisionOutcome, TicketJobStatus, TicketStatus,
};
use automonique_transport_runtime::{
    CallPriority, ChannelName, GitHubChecklistItem, GitHubIssueUrl, GitHubRepoAlias, GitHubRequest,
    SlackBudgetedMethod, SlackCallBudget,
};
use automonique_transports::{
    SlackAccessPolicy, SlackAppId, SlackDisposition, SlackInputKind, SlackPrincipal,
    parse_slack_envelope,
};
use sha2::{Digest as _, Sha256};

use crate::github::{GitHubSurface, IssueFactDetail};
use crate::github_actions::{
    GitHubActionEngine, GitHubActionRequest, GitHubIssueRequestIntent, GitHubManagementDomain,
    is_github_capability_question, natural_issue_request,
};
use crate::manage_config::ManageUrl;
use crate::mcp_client::{McpCallResult, McpRegistry};
use crate::progress_hub::ProgressHub;
use crate::run_lane::{SlackProgressSink, SlackProgressTarget, SocketRunLane};
use crate::telegram_bridge::{
    ApprovalDecisionAnswer, ApprovalDecisionFailure, ControlSurface as _, HostFacts,
    QuestionProfile, RunLane as _, SlackSurface, StoreControlSurface,
    TransportConversationIdentity, TransportLiveSeams, TransportToolPlan,
    accepted_mcp_input_responses, answer_read_only_transport_question,
    answer_typed_github_issue_question, mcp_approval_preview, mcp_result_prompt,
    run_question_to_completion,
};
use crate::ticket_presentation::ticket_heading;

/// Configuration path beneath the daemon's private state directory.
const CONFIG_RELATIVE: &str = "slack/slack.conf";
/// Exact first line of a Slack configuration.
const CONFIG_HEADER: &str = "schema=automonique.slack/v1";
/// Exact final line of a complete Slack configuration.
const CONFIG_TERMINATOR: &str = "end=automonique.slack/v1";
const CONFIG_HEADER_V2: &str = "schema=automonique.slack/v2";
const CONFIG_TERMINATOR_V2: &str = "end=automonique.slack/v2";
/// Upper bound on the configuration file.
const MAX_CONFIG_BYTES: u64 = 4_096;

/// Most channels one configuration may name.
///
/// The reachable set is meant to be small and reviewable: a host that has named
/// thirty-two channels has told a chat it may post to thirty-two rooms, and a
/// number an owner can hold in their head is the point of the bound.
pub const MAX_CONFIGURED_CHANNELS: usize = 32;
/// Most Slack identities that may confirm a ticket gate.
pub const MAX_CONFIGURED_ADMINS: usize = 32;
/// Most Slack identities admitted to read-only Monique conversations.
pub const MAX_CONFIGURED_MEMBERS: usize = 256;
/// Most conversational tool approvals retained by one Slack worker.
const MAX_PENDING_SLACK_TOOL_APPROVALS: usize = 64;
/// Maximum channel-history pages one in-thread ticket audit may inspect.
///
/// This keeps a natural-language read bounded even when a configured channel
/// has years of history. Slack currently caps a page at `MAX_PAGE_LIMIT`, so
/// the total is at most 4,000 messages.
const MAX_CHANNEL_TICKET_AUDIT_PAGES: usize = 20;
/// Cadence for the bounded Slack terminal-job monitor.
const SLACK_TICKET_STATUS_POLL: Duration = Duration::from_secs(3);
/// Most outstanding ticket jobs one Socket Mode cadence may inspect.
const MAX_SLACK_TICKET_STATUS_POLLS: usize = 8;

/// Independently staged Slack product capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlackFeature {
    Approvals,
    Conversation,
    Commands,
    Files,
    AppHome,
}

impl SlackFeature {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "approvals" => Some(Self::Approvals),
            "conversation" => Some(Self::Conversation),
            "commands" => Some(Self::Commands),
            "files" => Some(Self::Files),
            "app_home" => Some(Self::AppHome),
            _ => None,
        }
    }
}

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

/// Largest number of `users.info` calls one roster resolution may make.
///
/// The member allowlist is already bounded by configuration, but that bound
/// belongs to another concern; this one keeps a single resolution from being
/// an unbounded burst against Slack's rate limit however that list grows.
const MAX_ROSTER_LOOKUPS: usize = 24;

/// Resolve the configured member allowlist into a verified tag roster.
///
/// Each entry pairs a member's exact `<@USERID>` token with their display
/// label, so the conversational router can turn "notify bruno" into a real
/// Slack tag instead of an unverified plain-text `@bruno`. Bots, deactivated
/// accounts and failed lookups are skipped rather than failing the roster:
/// a partial roster still tags the people it names, and an absent member
/// degrades to today's addressed-by-name reply.
fn slack_member_roster(api: &dyn SlackApi, members: &[UserId]) -> Option<String> {
    let mut entries = Vec::new();
    for member in members.iter().take(MAX_ROSTER_LOOKUPS) {
        let Ok(SlackOutcome::Accepted(user)) = api.users_info(member) else {
            continue;
        };
        if user.is_bot == Some(true) || user.deleted == Some(true) {
            continue;
        }
        let label = user
            .display_label()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if label.is_empty() {
            continue;
        }
        entries.push(format!("<@{}> is {label}", member.as_str()));
    }
    (!entries.is_empty()).then(|| entries.join("; "))
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
    /// Socket Mode was enabled without a non-empty, unique administrator set,
    /// or administrators were named without a Socket Mode credential.
    AdminInvalid,
    /// A member allowlist entry is invalid, duplicated, or over capacity.
    MemberInvalid,
    /// A v2 feature is unknown or repeated.
    FeatureInvalid,
    /// File exchange was enabled without a tenant artifact policy.
    ArtifactPolicyRequired,
    /// Socket Mode ticket intake was enabled without Manage's typed ticket
    /// action capability.
    TicketActionsUnavailable,
    /// GitHub actions were configured but their provider lane could not open.
    GitHubActionsUnavailable,
    /// Read-only Slack conversation could not open its typed source or lane.
    QuestionSurfaceUnavailable,
    /// A present Manage configuration was refused.
    ManageConfig(crate::manage_config::ManageConfigError),
    /// A present memory configuration was refused.
    MemoryConfig(crate::memory_config::MemoryConfigError),
    /// A present shadow configuration was refused.
    ShadowConfig(crate::shadow_config::ShadowConfigError),
    /// An identity to observe was configured and its recorder could not open.
    ///
    /// Refused rather than quietly disabled: an operator who named a comparison
    /// target believes a comparison is being recorded, and a harness that
    /// silently records nothing produces a gate decision over no evidence.
    ShadowRecorderUnavailable,
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
            Self::AdminInvalid => {
                formatter.write_str("slack ticket intake administrator configuration is invalid")
            }
            Self::MemberInvalid => {
                formatter.write_str("slack member allowlist configuration is invalid")
            }
            Self::FeatureInvalid => formatter.write_str("slack feature configuration is invalid"),
            Self::ArtifactPolicyRequired => {
                formatter.write_str("slack files require an explicit tenant artifact policy")
            }
            Self::TicketActionsUnavailable => {
                formatter.write_str("slack ticket intake requires configured Manage actions")
            }
            Self::GitHubActionsUnavailable => {
                formatter.write_str("slack GitHub actions require an available provider lane")
            }
            Self::QuestionSurfaceUnavailable => formatter
                .write_str("slack conversation requires an available read-only question surface"),
            Self::ManageConfig(error) => write!(formatter, "{error}"),
            Self::MemoryConfig(error) => write!(formatter, "{error}"),
            Self::ShadowConfig(error) => write!(formatter, "{error}"),
            Self::ShadowRecorderUnavailable => formatter
                .write_str("shadow observation is configured but its recorder is unavailable"),
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
            Self::AdminInvalid => "slack_config_admin",
            Self::MemberInvalid => "slack_config_member",
            Self::FeatureInvalid => "slack_config_feature",
            Self::ArtifactPolicyRequired => "slack_artifact_policy_required",
            Self::TicketActionsUnavailable => "slack_ticket_actions_unavailable",
            Self::GitHubActionsUnavailable => "slack_github_actions_unavailable",
            Self::QuestionSurfaceUnavailable => "slack_question_surface_unavailable",
            Self::ManageConfig(error) => error.category(),
            Self::MemoryConfig(error) => error.category(),
            Self::ShadowConfig(error) => error.category(),
            Self::ShadowRecorderUnavailable => "shadow_recorder_unavailable",
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
    app_token: Option<SlackAppToken>,
    channels: ChannelMap,
    admins: Vec<UserId>,
    members: Vec<UserId>,
    features: Vec<SlackFeature>,
    interactive_decisions: bool,
}

impl fmt::Debug for SlackConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SlackConfig")
            .field("token", &"<redacted>")
            .field(
                "socket_mode",
                &self.app_token.as_ref().map_or("disabled", |_| "enabled"),
            )
            .field("channels", &self.channels.labels())
            .field("admin_count", &self.admins.len())
            .field("member_count", &self.members.len())
            .field("features", &self.features)
            .field("interactive_decisions", &self.interactive_decisions)
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
        let v2 = match lines.next() {
            Some(CONFIG_HEADER) => false,
            Some(CONFIG_HEADER_V2) => true,
            _ => return Err(SlackConfigError::Malformed),
        };
        let terminator = if v2 {
            CONFIG_TERMINATOR_V2
        } else {
            CONFIG_TERMINATOR
        };
        let mut token: Option<SlackToken> = None;
        let mut app_token: Option<SlackAppToken> = None;
        let mut channels: Vec<(ChannelName, ChannelId)> = Vec::new();
        let mut admins: Vec<UserId> = Vec::new();
        let mut members: Vec<UserId> = Vec::new();
        let mut features: Vec<SlackFeature> = Vec::new();
        let mut terminated = false;
        for line in lines {
            if terminated {
                return Err(SlackConfigError::Malformed);
            }
            if line == terminator {
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
                "app_token" if app_token.is_none() => {
                    app_token = Some(
                        SlackAppToken::new(value.as_bytes().to_vec())
                            .map_err(|_| SlackConfigError::TokenInvalid)?,
                    );
                }
                // Repeatable, so a second one is another channel rather than a
                // duplicate key. A repeated *label* is still refused below: two
                // ids under one name is an ambiguity nobody can resolve later.
                "channel" => channels.push(parse_channel_entry(value)?),
                "admin" => {
                    admins.push(UserId::new(value).map_err(|_| SlackConfigError::AdminInvalid)?)
                }
                "member" if v2 => {
                    members.push(UserId::new(value).map_err(|_| SlackConfigError::MemberInvalid)?)
                }
                "feature" if v2 => features
                    .push(SlackFeature::parse(value).ok_or(SlackConfigError::FeatureInvalid)?),
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
        if admins.len() > MAX_CONFIGURED_ADMINS
            || admins
                .iter()
                .enumerate()
                .any(|(index, admin)| admins[..index].contains(admin))
            || app_token.is_some() == admins.is_empty()
        {
            return Err(SlackConfigError::AdminInvalid);
        }
        if !v2 {
            members.clone_from(&admins);
            features.extend([
                SlackFeature::Approvals,
                SlackFeature::Conversation,
                SlackFeature::Commands,
            ]);
        }
        if members.len() > MAX_CONFIGURED_MEMBERS
            || members
                .iter()
                .enumerate()
                .any(|(index, member)| members[..index].contains(member))
        {
            return Err(SlackConfigError::MemberInvalid);
        }
        for admin in &admins {
            if !members.contains(admin) {
                if members.len() == MAX_CONFIGURED_MEMBERS {
                    return Err(SlackConfigError::MemberInvalid);
                }
                members.push(admin.clone());
            }
        }
        if features
            .iter()
            .enumerate()
            .any(|(index, feature)| features[..index].contains(feature))
        {
            return Err(SlackConfigError::FeatureInvalid);
        }
        if features.contains(&SlackFeature::Files) {
            return Err(SlackConfigError::ArtifactPolicyRequired);
        }
        // V1 already requires a Socket Mode app token and an explicit
        // administrator list. Those are the same authority gates the V2
        // interactive flag represents, so legacy live configurations can
        // render contextual approval buttons instead of dead-end text.
        let interactive_decisions = v2 || app_token.is_some();
        Ok(Some(Self {
            token: token.ok_or(SlackConfigError::TokenInvalid)?,
            app_token,
            channels: ChannelMap(channels),
            admins,
            members,
            features,
            interactive_decisions,
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
    fn channel_labels(&self) -> Vec<String> {
        self.channels
            .labels()
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    fn recent_messages(&mut self, channel: &ChannelName) -> Result<String, String> {
        self.read_recent(channel)
    }

    fn post_message(&mut self, channel: &ChannelName, text: &str) -> Result<String, String> {
        self.post(channel, text)
    }
}

/// A bounded Slack message event relevant to configured-channel ticket intake.
#[derive(Clone, Debug, Eq, PartialEq)]
struct SlackTicketEvent {
    team_id: String,
    channel: ChannelId,
    user: UserId,
    text: String,
    parent: MessageTs,
    source_key: String,
    app_mention: bool,
    in_thread: bool,
    continues_conversation: bool,
    /// This bot's own user id, from the envelope's `authorizations`.
    ///
    /// `None` when Slack omitted the field: mention stripping then falls back
    /// to removing the first mention token, the pre-authorization behavior.
    bot_user: Option<UserId>,
}

/// Extract the acknowledgement key independently from the event payload.
///
/// Socket Mode is acknowledged before any Manage or Web API call. A malformed
/// event can therefore be dropped without Slack retrying it forever, while a
/// malformed outer envelope is left unacknowledged and forces reconnect.
fn socket_envelope_id(text: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()?
        .get("envelope_id")?
        .as_str()
        .map(str::to_owned)
}

/// Slack opens every Socket Mode connection with a control frame that has no
/// acknowledgement key. It is connection metadata, not a malformed event.
fn socket_hello(text: &str) -> bool {
    let Ok(frame) = serde_json::from_str::<serde_json::Value>(text) else {
        return false;
    };
    frame.get("type").and_then(serde_json::Value::as_str) == Some("hello")
        && frame.get("envelope_id").is_none()
}

fn slack_ticket_event(text: &str) -> Option<SlackTicketEvent> {
    let outer: serde_json::Value = serde_json::from_str(text).ok()?;
    if outer.get("type")?.as_str()? != "events_api" {
        return None;
    }
    let payload = outer.get("payload")?.as_object()?;
    let event_id = payload.get("event_id")?.as_str()?;
    let team_id = payload.get("team_id")?.as_str()?;
    let event = payload.get("event")?.as_object()?;
    let event_type = event.get("type")?.as_str()?;
    if !matches!(event_type, "message" | "app_mention")
        || event.get("subtype").is_some_and(|value| !value.is_null())
        || event.get("bot_id").is_some_and(|value| !value.is_null())
    {
        return None;
    }
    let channel = ChannelId::new(event.get("channel")?.as_str()?).ok()?;
    let user = UserId::new(event.get("user")?.as_str()?).ok()?;
    let text = event.get("text")?.as_str()?;
    if text.is_empty() || text.len() > 16 * 1024 || text.chars().any(|c| c == '\0') {
        return None;
    }
    let ts = event.get("ts")?.as_str()?;
    let thread_ts = event.get("thread_ts").and_then(serde_json::Value::as_str);
    let parent = thread_ts.unwrap_or(ts);
    let parent = MessageTs::new(parent).ok()?;
    if !team_id.bytes().all(|byte| byte.is_ascii_alphanumeric())
        || !event_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return None;
    }
    let source_key = format!("slack:{team_id}:event:{event_id}");
    if source_key.len() > automonique_support_connector::MAX_TICKET_SOURCE_KEY_BYTES {
        return None;
    }
    let bot_user = payload
        .get("authorizations")
        .and_then(serde_json::Value::as_array)
        .and_then(|authorizations| authorizations.first())
        .and_then(|authorization| authorization.get("user_id"))
        .and_then(serde_json::Value::as_str)
        .and_then(|user_id| UserId::new(user_id).ok());
    Some(SlackTicketEvent {
        team_id: team_id.to_owned(),
        channel,
        user,
        text: text.to_owned(),
        parent,
        source_key,
        app_mention: event_type == "app_mention",
        in_thread: thread_ts.is_some(),
        continues_conversation: false,
        bot_user,
    })
}

/// Whether `event` is the general `message` copy of a post whose dedicated
/// `app_mention` copy also arrives.
///
/// With the bot's own id known from the envelope, exactly a mention of the
/// bot qualifies: "it's <@U0BRUNO>" in a thread is one post with one copy and
/// must still be read and remembered. Without the id, any mention is treated
/// as the bot's, which is the only safe reading of an unauthorized envelope.
fn slack_plain_copy_of_bot_mention(event: &SlackTicketEvent) -> bool {
    if event.app_mention {
        return false;
    }
    match event.bot_user.as_ref() {
        Some(bot_user) => mention_token_range(&event.text, Some(bot_user.as_str())).is_some(),
        None => event.text.contains("<@"),
    }
}

/// Remove the bot mention that made Slack classify this as `app_mention`.
///
/// Slack keeps the mention as `<@U…>` inside `text`, sometimes with sentence
/// punctuation immediately after it. The conversational router should see the
/// prose the person wrote, while any other user mentions remain intact — they
/// are how a reply can tag the person the message is about. When the bot's own
/// id is known from the envelope, exactly its tokens are removed, wherever
/// they sit; without it the first token is removed, which mistakes "@Bruno
/// @Monique look" for a message about Monique, so the id-directed path is the
/// one every authorized envelope takes.
fn slack_app_mention_text(text: &str, bot_user: Option<&str>) -> String {
    let mut prose = text.to_owned();
    let mut removed_bot_mention = false;
    if let Some(bot_user) = bot_user {
        while let Some(range) = mention_token_range(&prose, Some(bot_user)) {
            prose.replace_range(range, "");
            removed_bot_mention = true;
        }
    }
    if !removed_bot_mention && let Some(range) = mention_token_range(&prose, None) {
        prose.replace_range(range, "");
    }
    prose
        .trim()
        .trim_matches(|character: char| matches!(character, '?' | '!' | '.' | ','))
        .trim()
        .to_owned()
}

/// Byte range of the first `<@…>` mention token, or with `user`, of the first
/// token whose id — before any legacy `|label` suffix — is exactly that user.
fn mention_token_range(text: &str, user: Option<&str>) -> Option<std::ops::RangeInclusive<usize>> {
    let mut search_start = 0;
    loop {
        let start = search_start + text.get(search_start..)?.find("<@")?;
        let relative_end = text[start + 2..].find('>')?;
        let end = start + 2 + relative_end;
        let inner = &text[start + 2..end];
        let id = inner.split('|').next().unwrap_or(inner);
        match user {
            Some(user) if id != user => search_start = end + 1,
            _ => return Some(start..=end),
        }
    }
}

/// Parse one message the configured reference bot published.
///
/// Deliberately the mirror image of [`slack_ticket_event`]'s filter: that
/// function drops every message carrying a `bot_id`, which would drop the one
/// engine the parity harness exists to compare against, *before* an observer
/// could see it. So the tap is here, upstream of routing, and it is as narrow as
/// the problem allows — a message is admitted only when it carries a `bot_id`
/// **and** its author is the exact configured identity. Nothing this returns
/// reaches the router; it reaches [`crate::shadow::LegacyObserver`], which
/// records and does not act.
fn slack_legacy_bot_message(
    text: &str,
    legacy_bot_user: &str,
) -> Option<crate::shadow::LegacyMessage> {
    let outer: serde_json::Value = serde_json::from_str(text).ok()?;
    if outer.get("type")?.as_str()? != "events_api" {
        return None;
    }
    let event = outer.get("payload")?.get("event")?.as_object()?;
    if event.get("type")?.as_str()? != "message" {
        return None;
    }
    // The bot_id is what makes this message one the router already discards.
    if event.get("bot_id").is_none_or(serde_json::Value::is_null) {
        return None;
    }
    if event.get("user").and_then(serde_json::Value::as_str)? != legacy_bot_user {
        return None;
    }
    let channel = ChannelId::new(event.get("channel")?.as_str()?).ok()?;
    let body = event.get("text")?.as_str()?;
    if body.is_empty() || body.len() > 16 * 1024 || body.chars().any(|c| c == '\0') {
        return None;
    }
    let ts = event.get("ts")?.as_str()?;
    let thread = event.get("thread_ts").and_then(serde_json::Value::as_str);
    let in_thread = thread.is_some();
    let thread_ts = MessageTs::new(thread.unwrap_or(ts)).ok()?;
    Some(crate::shadow::LegacyMessage {
        channel: channel.to_string(),
        thread_ts: thread_ts.to_string(),
        in_thread,
        text: body.to_owned(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SlackGitHubCommand {
    team_id: String,
    channel: ChannelId,
    user: UserId,
    source_key: String,
    request: GitHubActionRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SlackMoniqueCommand {
    team_id: String,
    channel: ChannelId,
    user: UserId,
    source_key: String,
    text: String,
}

fn slack_monique_command(
    text: &str,
    channels: &ChannelMap,
) -> Result<Option<SlackMoniqueCommand>, ()> {
    let frame: serde_json::Value = serde_json::from_str(text).map_err(|_| ())?;
    if frame.get("type").and_then(serde_json::Value::as_str) != Some("slash_commands") {
        return Ok(None);
    }
    let payload = frame
        .get("payload")
        .and_then(serde_json::Value::as_object)
        .ok_or(())?;
    if payload.get("command").and_then(serde_json::Value::as_str) != Some("/monique") {
        return Ok(None);
    }
    let team = payload
        .get("team_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(())?;
    let channel = ChannelId::new(
        payload
            .get("channel_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(())?,
    )
    .map_err(|_| ())?;
    if !channels
        .0
        .iter()
        .any(|(_, configured)| configured == &channel)
    {
        return Ok(None);
    }
    let user = UserId::new(
        payload
            .get("user_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(())?,
    )
    .map_err(|_| ())?;
    let trigger = payload
        .get("trigger_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(())?;
    let content = payload
        .get("text")
        .and_then(serde_json::Value::as_str)
        .ok_or(())?;
    if content.len() > automonique_transports::MAX_SLACK_TEXT_BYTES || content.contains('\0') {
        return Err(());
    }
    let source_key = format!(
        "slack:automonique-slack:{team}:{}:command:{trigger}",
        channel.as_str()
    );
    if source_key.len() > automonique_support_connector::MAX_TICKET_SOURCE_KEY_BYTES {
        return Err(());
    }
    Ok(Some(SlackMoniqueCommand {
        team_id: team.to_owned(),
        channel,
        user,
        source_key,
        text: content.trim().to_owned(),
    }))
}

fn slack_github_command(
    text: &str,
    channels: &ChannelMap,
    admins: &[UserId],
) -> Result<Option<SlackGitHubCommand>, ()> {
    let frame: serde_json::Value = serde_json::from_str(text).map_err(|_| ())?;
    if frame.get("type").and_then(serde_json::Value::as_str) != Some("slash_commands") {
        return Ok(None);
    }
    let payload = frame
        .get("payload")
        .and_then(serde_json::Value::as_object)
        .ok_or(())?;
    if !matches!(
        payload.get("command").and_then(serde_json::Value::as_str),
        Some(
            "/github_create"
                | "/github_reply"
                | "/github_check"
                | "/github_uncheck"
                | "/github_issue"
                | "/github_label"
                | "/github_milestone"
                | "/github_epic"
                | "/github_project"
        )
    ) {
        return Ok(None);
    }
    let team = payload
        .get("team_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(())?;
    let app_id = SlackAppId::new("automonique-slack").map_err(|_| ())?;
    let principals = channels.0.iter().flat_map(|(_, channel)| {
        admins
            .iter()
            .filter_map(|user| SlackPrincipal::new(team, channel.as_str(), user.as_str()).ok())
    });
    let policy = SlackAccessPolicy::new(app_id, principals).map_err(|_| ())?;
    let envelope = parse_slack_envelope(text.as_bytes(), &policy).map_err(|_| ())?;
    if envelope.disposition() != SlackDisposition::Admitted {
        return Ok(None);
    }
    let ingress = envelope.ingress().ok_or(())?;
    let content = ingress.content().ok_or(())?;
    let principal = ingress.principal();
    let channel = ChannelId::new(principal.channel()).map_err(|_| ())?;
    let user = UserId::new(principal.user()).map_err(|_| ())?;
    let request = github_slash_request(ingress.kind(), content)?;
    Ok(Some(SlackGitHubCommand {
        team_id: principal.team().to_owned(),
        channel,
        user,
        source_key: ingress.source_key().to_owned(),
        request,
    }))
}

fn github_slash_request(kind: SlackInputKind, content: &str) -> Result<GitHubActionRequest, ()> {
    let management_domain = match kind {
        SlackInputKind::GitHubIssue => Some(GitHubManagementDomain::Issue),
        SlackInputKind::GitHubLabel => Some(GitHubManagementDomain::Label),
        SlackInputKind::GitHubMilestone => Some(GitHubManagementDomain::Milestone),
        SlackInputKind::GitHubEpic => Some(GitHubManagementDomain::Epic),
        SlackInputKind::GitHubProject => Some(GitHubManagementDomain::Project),
        _ => None,
    };
    if let Some(domain) = management_domain {
        return Ok(GitHubActionRequest::Manage {
            domain,
            instruction: GitHubRequest::new(content)
                .map_err(|_| ())?
                .as_str()
                .to_owned(),
        });
    }
    let (coordinate, instruction) = content.trim().split_once(char::is_whitespace).ok_or(())?;
    let instruction = instruction.trim();
    match kind {
        SlackInputKind::GitHubCreate => Ok(GitHubActionRequest::Create {
            alias: GitHubRepoAlias::new(coordinate)
                .map_err(|_| ())?
                .as_str()
                .to_owned(),
            instruction: GitHubRequest::new(instruction)
                .map_err(|_| ())?
                .as_str()
                .to_owned(),
        }),
        SlackInputKind::GitHubReply => Ok(GitHubActionRequest::Reply {
            issue_url: GitHubIssueUrl::new(coordinate)
                .map_err(|_| ())?
                .as_str()
                .to_owned(),
            instruction: GitHubRequest::new(instruction)
                .map_err(|_| ())?
                .as_str()
                .to_owned(),
        }),
        SlackInputKind::GitHubCheck | SlackInputKind::GitHubUncheck => {
            Ok(GitHubActionRequest::Check {
                issue_url: GitHubIssueUrl::new(coordinate)
                    .map_err(|_| ())?
                    .as_str()
                    .to_owned(),
                instruction: instruction.to_owned(),
                checked: kind == SlackInputKind::GitHubCheck,
                exact_item: Some(
                    GitHubChecklistItem::new(instruction)
                        .map_err(|_| ())?
                        .as_str()
                        .to_owned(),
                ),
            })
        }
        SlackInputKind::Message
        | SlackInputKind::AppMention
        | SlackInputKind::GitHubIssue
        | SlackInputKind::GitHubLabel
        | SlackInputKind::GitHubMilestone
        | SlackInputKind::GitHubEpic
        | SlackInputKind::GitHubProject
        | SlackInputKind::Monique
        | SlackInputKind::Unsupported => Err(()),
    }
}

fn one_issue_url(text: &str) -> Result<Option<String>, ()> {
    let mut issue: Option<String> = None;
    for token in text.split_whitespace() {
        let token = token.trim_matches(|character: char| {
            matches!(
                character,
                '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '"' | '\'' | '!'
            )
        });
        // Slack renders named links as `<url|label>` in event text. Only the
        // exact URL half is relevant; the label is presentation, not an action
        // coordinate.
        let token = token.split_once('|').map_or(token, |(url, _)| url);
        let token = token.strip_suffix('.').unwrap_or(token);
        let Some(locator) = automonique_github_connector::IssueLocator::parse(token) else {
            continue;
        };
        let canonical = format!(
            "https://github.com/{}/issues/{}",
            locator.target(),
            locator.number().get()
        );
        if issue.as_ref().is_some_and(|seen| seen != &canonical) {
            return Err(());
        }
        issue = Some(canonical);
    }
    Ok(issue)
}

/// Return the canonical coordinate only when the message carries no request
/// beyond one Slack-rendered GitHub issue link.
///
/// A bare link is context, not permission to release work. Slack rewrites it
/// as `<url|label>`, so compare the URL half after removing presentation
/// punctuation. Explicit verbs such as `run`, `review`, or `status` continue
/// through their typed routes.
fn bare_issue_url(text: &str) -> Option<String> {
    let issue_url = one_issue_url(text).ok().flatten()?;
    let token = text.trim().trim_matches(|character: char| {
        matches!(
            character,
            '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '"' | '\'' | '!'
        )
    });
    let token = token.split_once('|').map_or(token, |(url, _)| url);
    let token = token.strip_suffix('.').unwrap_or(token);
    (token == issue_url).then_some(issue_url)
}

#[derive(Clone, Debug)]
enum SlackTicketInteractionKind {
    Approve,
    RejectOpen { trigger_id: String },
    RejectSubmit { reason: String },
}

#[derive(Clone, Debug)]
struct SlackTicketInteraction {
    interaction_key: String,
    team_id: String,
    channel: ChannelId,
    message_ts: MessageTs,
    user: UserId,
    job_id: String,
    kind: SlackTicketInteractionKind,
}

/// One pressed approval button, before any authorization is applied.
///
/// Deliberately not a [`SlackTicketInteraction`]: that one is bound to a live
/// ticket gate and journalled against Slack message coordinates, and this one
/// is bound to a durable proposal whose exactly-once guarantee is the daemon's
/// fence. Folding them together would mean widening the ticket journal's
/// `CHECK` constraints to hold rows it was not designed for.
#[derive(Clone, Debug)]
struct SlackApprovalInteraction {
    team_id: String,
    channel: ChannelId,
    message_ts: MessageTs,
    user: UserId,
    request_key: String,
    granted: bool,
}

/// The `action_id` an approve button carries.
const SLACK_APPROVAL_GRANT_ACTION: &str = "automonique_approval_grant";
/// The `action_id` a deny button carries.
const SLACK_APPROVAL_DENY_ACTION: &str = "automonique_approval_deny";
const SLACK_TOOL_GRANT_ACTION: &str = "automonique_tool_grant";
const SLACK_TOOL_DENY_ACTION: &str = "automonique_tool_deny";

struct SlackToolInteraction {
    channel: ChannelId,
    message_ts: MessageTs,
    user: UserId,
    key: String,
    granted: bool,
}

fn slack_tool_interaction(text: &str) -> Result<Option<SlackToolInteraction>, ()> {
    let frame: serde_json::Value = serde_json::from_str(text).map_err(|_| ())?;
    if frame.get("type").and_then(serde_json::Value::as_str) != Some("interactive") {
        return Ok(None);
    }
    let payload = frame
        .get("payload")
        .and_then(serde_json::Value::as_object)
        .ok_or(())?;
    if payload.get("type").and_then(serde_json::Value::as_str) != Some("block_actions") {
        return Ok(None);
    }
    let actions = payload
        .get("actions")
        .and_then(serde_json::Value::as_array)
        .ok_or(())?;
    let [action] = actions.as_slice() else {
        return Err(());
    };
    let granted = match action
        .get("action_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(())?
    {
        SLACK_TOOL_GRANT_ACTION => true,
        SLACK_TOOL_DENY_ACTION => false,
        _ => return Ok(None),
    };
    let key = action
        .get("value")
        .and_then(serde_json::Value::as_str)
        .ok_or(())?;
    if key.len() != 37
        || !key.starts_with("tool-")
        || !key[5..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(());
    }
    let user = payload
        .get("user")
        .and_then(|value| value.get("id"))
        .and_then(serde_json::Value::as_str)
        .ok_or(())?;
    let channel = payload
        .get("channel")
        .and_then(|value| value.get("id"))
        .and_then(serde_json::Value::as_str)
        .ok_or(())?;
    let message_ts = payload
        .get("container")
        .and_then(|value| value.get("message_ts"))
        .and_then(serde_json::Value::as_str)
        .ok_or(())?;
    Ok(Some(SlackToolInteraction {
        channel: ChannelId::new(channel).map_err(|_| ())?,
        message_ts: MessageTs::new(message_ts).map_err(|_| ())?,
        user: UserId::new(user).map_err(|_| ())?,
        key: key.to_owned(),
        granted,
    }))
}

/// Read one pressed approval button, or nothing.
///
/// The button's `value` is the opaque reference and nothing else. It is checked
/// against the `apr-` grammar here rather than trusted, because a `value` is
/// whatever the message that rendered it said — and this build renders those
/// messages, so anything else is a payload from somewhere it should not be.
fn slack_approval_interaction(text: &str) -> Result<Option<SlackApprovalInteraction>, ()> {
    let frame: serde_json::Value = serde_json::from_str(text).map_err(|_| ())?;
    if frame.get("type").and_then(serde_json::Value::as_str) != Some("interactive") {
        return Ok(None);
    }
    let payload = frame
        .get("payload")
        .and_then(serde_json::Value::as_object)
        .ok_or(())?;
    if payload.get("type").and_then(serde_json::Value::as_str) != Some("block_actions") {
        return Ok(None);
    }
    let actions = payload
        .get("actions")
        .and_then(serde_json::Value::as_array)
        .ok_or(())?;
    // Exactly one action per payload, as the ticket lane requires and for the
    // same reason: two presses in one envelope is not a shape this product
    // renders, so admitting it would be admitting somebody else's.
    let [action] = actions.as_slice() else {
        return Err(());
    };
    let granted = match action
        .get("action_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(())?
    {
        SLACK_APPROVAL_GRANT_ACTION => true,
        SLACK_APPROVAL_DENY_ACTION => false,
        _ => return Ok(None),
    };
    let request_key = action
        .get("value")
        .and_then(serde_json::Value::as_str)
        .ok_or(())?;
    if !request_key.starts_with(APPROVAL_REFERENCE_PREFIX) {
        return Err(());
    }
    let team_id = payload
        .get("team")
        .and_then(|value| value.get("id"))
        .and_then(serde_json::Value::as_str)
        .ok_or(())?;
    let user = payload
        .get("user")
        .and_then(|value| value.get("id"))
        .and_then(serde_json::Value::as_str)
        .ok_or(())?;
    let channel = payload
        .get("channel")
        .and_then(|value| value.get("id"))
        .and_then(serde_json::Value::as_str)
        .ok_or(())?;
    let message_ts = payload
        .get("container")
        .and_then(|value| value.get("message_ts"))
        .and_then(serde_json::Value::as_str)
        .ok_or(())?;
    Ok(Some(SlackApprovalInteraction {
        team_id: team_id.to_owned(),
        channel: ChannelId::new(channel).map_err(|_| ())?,
        message_ts: MessageTs::new(message_ts).map_err(|_| ())?,
        user: UserId::new(user).map_err(|_| ())?,
        request_key: request_key.to_owned(),
        granted,
    }))
}

fn slack_ticket_interaction(text: &str) -> Result<Option<SlackTicketInteraction>, ()> {
    let frame: serde_json::Value = serde_json::from_str(text).map_err(|_| ())?;
    if frame.get("type").and_then(serde_json::Value::as_str) != Some("interactive") {
        return Ok(None);
    }
    let payload = frame
        .get("payload")
        .and_then(serde_json::Value::as_object)
        .ok_or(())?;
    let team_id = payload
        .get("team")
        .and_then(|value| value.get("id"))
        .and_then(serde_json::Value::as_str)
        .ok_or(())?;
    let user = payload
        .get("user")
        .and_then(|value| value.get("id"))
        .and_then(serde_json::Value::as_str)
        .ok_or(())?;
    let user = UserId::new(user).map_err(|_| ())?;
    match payload.get("type").and_then(serde_json::Value::as_str) {
        Some("block_actions") => {
            let channel = payload
                .get("channel")
                .and_then(|value| value.get("id"))
                .and_then(serde_json::Value::as_str)
                .ok_or(())?;
            let message_ts = payload
                .get("container")
                .and_then(|value| value.get("message_ts"))
                .and_then(serde_json::Value::as_str)
                .ok_or(())?;
            let actions = payload
                .get("actions")
                .and_then(serde_json::Value::as_array)
                .ok_or(())?;
            let [action] = actions.as_slice() else {
                return Err(());
            };
            let action_id = action
                .get("action_id")
                .and_then(serde_json::Value::as_str)
                .ok_or(())?;
            let action_ts = action
                .get("action_ts")
                .and_then(serde_json::Value::as_str)
                .ok_or(())?;
            let job_id = action
                .get("value")
                .and_then(serde_json::Value::as_str)
                .ok_or(())?;
            let kind = match action_id {
                "monique_ticket_approve" => SlackTicketInteractionKind::Approve,
                "monique_ticket_reject" => SlackTicketInteractionKind::RejectOpen {
                    trigger_id: payload
                        .get("trigger_id")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(())?
                        .to_owned(),
                },
                _ => return Ok(None),
            };
            Ok(Some(SlackTicketInteraction {
                interaction_key: format!(
                    "slack-action:{team_id}:{channel}:{message_ts}:{}:{action_ts}:{action_id}",
                    user.as_str()
                ),
                team_id: team_id.to_owned(),
                channel: ChannelId::new(channel).map_err(|_| ())?,
                message_ts: MessageTs::new(message_ts).map_err(|_| ())?,
                user,
                job_id: job_id.to_owned(),
                kind,
            }))
        }
        Some("view_submission") => {
            let view = payload
                .get("view")
                .and_then(serde_json::Value::as_object)
                .ok_or(())?;
            if view.get("callback_id").and_then(serde_json::Value::as_str)
                != Some("monique_ticket_reject_submit")
            {
                return Ok(None);
            }
            let metadata: serde_json::Value = serde_json::from_str(
                view.get("private_metadata")
                    .and_then(serde_json::Value::as_str)
                    .ok_or(())?,
            )
            .map_err(|_| ())?;
            let channel = metadata
                .get("channel_id")
                .and_then(serde_json::Value::as_str)
                .ok_or(())?;
            let message_ts = metadata
                .get("message_ts")
                .and_then(serde_json::Value::as_str)
                .ok_or(())?;
            let job_id = metadata
                .get("job_id")
                .and_then(serde_json::Value::as_str)
                .ok_or(())?;
            let reason = view
                .get("state")
                .and_then(|value| value.get("values"))
                .and_then(|value| value.get("reason"))
                .and_then(|value| value.get("value"))
                .and_then(|value| value.get("value"))
                .and_then(serde_json::Value::as_str)
                .ok_or(())?
                .trim();
            TicketDecision::reject(reason).map_err(|_| ())?;
            let view_id = view
                .get("id")
                .and_then(serde_json::Value::as_str)
                .ok_or(())?;
            let hash = view
                .get("hash")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("nohash");
            Ok(Some(SlackTicketInteraction {
                interaction_key: format!(
                    "slack-view:{team_id}:{view_id}:{hash}:{}:reject",
                    user.as_str()
                ),
                team_id: team_id.to_owned(),
                channel: ChannelId::new(channel).map_err(|_| ())?,
                message_ts: MessageTs::new(message_ts).map_err(|_| ())?,
                user,
                job_id: job_id.to_owned(),
                kind: SlackTicketInteractionKind::RejectSubmit {
                    reason: reason.to_owned(),
                },
            }))
        }
        _ => Ok(None),
    }
}

fn slack_app_home_user(text: &str) -> Result<Option<UserId>, ()> {
    let frame: serde_json::Value = serde_json::from_str(text).map_err(|_| ())?;
    if frame.get("type").and_then(serde_json::Value::as_str) != Some("events_api") {
        return Ok(None);
    }
    let payload = frame
        .get("payload")
        .and_then(serde_json::Value::as_object)
        .ok_or(())?;
    let event = payload
        .get("event")
        .and_then(serde_json::Value::as_object)
        .ok_or(())?;
    if event.get("type").and_then(serde_json::Value::as_str) != Some("app_home_opened")
        || event.get("tab").and_then(serde_json::Value::as_str) != Some("home")
    {
        return Ok(None);
    }
    UserId::new(
        event
            .get("user")
            .and_then(serde_json::Value::as_str)
            .ok_or(())?,
    )
    .map(Some)
    .map_err(|_| ())
}

struct PreparedSlackTicketInteraction {
    interaction: SlackTicketInteraction,
    gate: crate::telegram_bridge::PendingTicketGate,
    record: SlackInteractionRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SlackEffectOutcome {
    Accepted,
    Rejected,
    Ambiguous,
}

/// The Slack effect seam.
///
/// `pub(crate)` rather than private so [`crate::shadow`] can decorate it from a
/// sibling module. Nothing outside this crate can name it, and
/// [`SlackTicketRouter`] is already generic over it, so the decoration costs the
/// router no change.
pub(crate) trait SlackTicketPoster {
    /// Note which inbound event the decisions that follow belong to.
    ///
    /// A no-op unless the implementation needs delivery correlation. The live
    /// poster uses it to remember only Slack-accepted replies; the recording
    /// decorator uses it because an intended-action envelope is keyed by the
    /// source event it was decided for, and the posting methods below carry no
    /// such key.
    fn begin_source(&mut self, _source_key: &str) {}

    /// Return a thread reply only after Slack accepted it.
    ///
    /// Recording posters leave this empty.  The live poster uses it to make
    /// Monique's own visible replies part of the durable conversation without
    /// ever remembering a delivery that Slack rejected or whose outcome is
    /// unknown.
    fn take_confirmed_thread_reply(&mut self) -> Option<ConfirmedSlackThreadReply> {
        None
    }

    fn post_thread(
        &mut self,
        channel: &ChannelId,
        parent: &MessageTs,
        text: &str,
    ) -> Result<(), ()>;

    fn post_channel(&mut self, channel: &ChannelId, text: &str) -> Result<(), ()>;

    /// Publish one fenced terminal ticket notification.
    ///
    /// Unlike the conversational helpers, this preserves Slack's distinction
    /// between an explicit rejection and an unknown transport result. The
    /// durable notification registry may retry only the former.
    fn post_ticket_notification(
        &mut self,
        channel: &ChannelId,
        parent: &MessageTs,
        text: &str,
    ) -> SlackEffectOutcome {
        match self.post_thread(channel, parent, text) {
            Ok(()) => SlackEffectOutcome::Accepted,
            Err(()) => SlackEffectOutcome::Ambiguous,
        }
    }

    fn post_approval_card(
        &mut self,
        channel: &ChannelId,
        parent: &MessageTs,
        receipt: &automonique_support_connector::TicketDispatchReceipt,
        _manage_url: Option<&ManageUrl>,
    ) -> Result<(), ()> {
        let short = receipt.job_id.get(..12).unwrap_or(&receipt.job_id);
        self.post_thread(
            channel,
            parent,
            &format!(
                "🔐 Confirmation required for `{}`\n{}\nMonique job `{short}` is pending approval. A configured Slack admin can reply `confirm {short}`; the same request can also be confirmed in Telegram or Manage. No work starts before confirmation.",
                receipt.issue_title, receipt.issue_url
            ),
        )
    }

    fn open_reject_modal(
        &mut self,
        _trigger_id: &str,
        _job_id: &str,
        _channel: &ChannelId,
        _message_ts: &MessageTs,
    ) -> Result<(), ()> {
        Err(())
    }

    /// Post one durable approval proposal as a card an administrator can
    /// decide from.
    ///
    /// The buttons carry the opaque reference as their `value` and nothing
    /// else: a `value` travels back verbatim, so anything descriptive in it
    /// would be a fact this product asserted about itself and then believed.
    ///
    /// Defaulted like every other effect on this trait, so the shadow poster
    /// and the test fakes stay source-compatible and post nothing.
    fn post_approval_request(
        &mut self,
        _channel: &ChannelId,
        _request_key: &str,
        _expires_at_ms: i64,
    ) -> Result<(), ()> {
        Err(())
    }

    fn post_tool_approval_card(
        &mut self,
        channel: &ChannelId,
        parent: &MessageTs,
        _key: &str,
        preview: &str,
    ) -> Result<(), ()> {
        self.post_thread(channel, parent, preview)
    }

    fn update_decision(
        &mut self,
        _channel: &ChannelId,
        _message_ts: &MessageTs,
        _text: &str,
    ) -> Result<(), ()> {
        Err(())
    }

    fn publish_home(
        &mut self,
        _user: &UserId,
        _is_admin: bool,
        _pending_count: usize,
    ) -> Result<(), ()> {
        Err(())
    }
}

pub(crate) struct ConfirmedSlackThreadReply {
    source_key: String,
    channel: ChannelId,
    parent: MessageTs,
    text: String,
}

struct LiveSlackTicketPoster {
    client: Arc<SlackClient>,
    source_key: Option<String>,
    confirmed_thread_replies: VecDeque<ConfirmedSlackThreadReply>,
}

impl LiveSlackTicketPoster {
    fn new(client: Arc<SlackClient>) -> Self {
        Self {
            client,
            source_key: None,
            confirmed_thread_replies: VecDeque::new(),
        }
    }

    fn client(&self) -> Arc<SlackClient> {
        Arc::clone(&self.client)
    }

    fn remember_thread_reply(&mut self, channel: &ChannelId, parent: &MessageTs, text: &str) {
        let Some(source_key) = self.source_key.clone() else {
            return;
        };
        self.confirmed_thread_replies
            .push_back(ConfirmedSlackThreadReply {
                source_key,
                channel: channel.clone(),
                parent: parent.clone(),
                text: text.to_owned(),
            });
    }
}

impl SlackTicketPoster for LiveSlackTicketPoster {
    fn begin_source(&mut self, source_key: &str) {
        self.source_key = Some(source_key.to_owned());
    }

    fn take_confirmed_thread_reply(&mut self) -> Option<ConfirmedSlackThreadReply> {
        self.confirmed_thread_replies.pop_front()
    }

    fn post_thread(
        &mut self,
        channel: &ChannelId,
        parent: &MessageTs,
        text: &str,
    ) -> Result<(), ()> {
        <Arc<SlackClient> as SlackTicketPoster>::post_thread(
            &mut self.client,
            channel,
            parent,
            text,
        )?;
        self.remember_thread_reply(channel, parent, text);
        Ok(())
    }

    fn post_channel(&mut self, channel: &ChannelId, text: &str) -> Result<(), ()> {
        <Arc<SlackClient> as SlackTicketPoster>::post_channel(&mut self.client, channel, text)
    }

    fn post_ticket_notification(
        &mut self,
        channel: &ChannelId,
        parent: &MessageTs,
        text: &str,
    ) -> SlackEffectOutcome {
        <Arc<SlackClient> as SlackTicketPoster>::post_ticket_notification(
            &mut self.client,
            channel,
            parent,
            text,
        )
    }

    fn post_approval_card(
        &mut self,
        channel: &ChannelId,
        parent: &MessageTs,
        receipt: &automonique_support_connector::TicketDispatchReceipt,
        manage_url: Option<&ManageUrl>,
    ) -> Result<(), ()> {
        <Arc<SlackClient> as SlackTicketPoster>::post_approval_card(
            &mut self.client,
            channel,
            parent,
            receipt,
            manage_url,
        )?;
        let short = receipt.job_id.get(..12).unwrap_or(&receipt.job_id);
        self.remember_thread_reply(
            channel,
            parent,
            &format!(
                "Confirmation required for {} ({}) — Monique job {short}",
                receipt.issue_title, receipt.issue_url
            ),
        );
        Ok(())
    }

    fn open_reject_modal(
        &mut self,
        trigger_id: &str,
        job_id: &str,
        channel: &ChannelId,
        message_ts: &MessageTs,
    ) -> Result<(), ()> {
        <Arc<SlackClient> as SlackTicketPoster>::open_reject_modal(
            &mut self.client,
            trigger_id,
            job_id,
            channel,
            message_ts,
        )
    }

    fn post_approval_request(
        &mut self,
        channel: &ChannelId,
        request_key: &str,
        expires_at_ms: i64,
    ) -> Result<(), ()> {
        <Arc<SlackClient> as SlackTicketPoster>::post_approval_request(
            &mut self.client,
            channel,
            request_key,
            expires_at_ms,
        )
    }

    fn post_tool_approval_card(
        &mut self,
        channel: &ChannelId,
        parent: &MessageTs,
        key: &str,
        preview: &str,
    ) -> Result<(), ()> {
        <Arc<SlackClient> as SlackTicketPoster>::post_tool_approval_card(
            &mut self.client,
            channel,
            parent,
            key,
            preview,
        )?;
        self.remember_thread_reply(channel, parent, preview);
        Ok(())
    }

    fn update_decision(
        &mut self,
        channel: &ChannelId,
        message_ts: &MessageTs,
        text: &str,
    ) -> Result<(), ()> {
        <Arc<SlackClient> as SlackTicketPoster>::update_decision(
            &mut self.client,
            channel,
            message_ts,
            text,
        )
    }

    fn publish_home(
        &mut self,
        user: &UserId,
        is_admin: bool,
        pending_count: usize,
    ) -> Result<(), ()> {
        <Arc<SlackClient> as SlackTicketPoster>::publish_home(
            &mut self.client,
            user,
            is_admin,
            pending_count,
        )
    }
}

impl SlackTicketPoster for Arc<SlackClient> {
    fn post_thread(
        &mut self,
        channel: &ChannelId,
        parent: &MessageTs,
        text: &str,
    ) -> Result<(), ()> {
        let text = MessageText::new(text).map_err(|_| ())?;
        let request = PostMessageRequest::new(channel.clone(), text).in_thread(parent.clone());
        match SlackClient::post_message(self.as_ref(), &request).map_err(|_| ())? {
            SlackOutcome::Accepted(_) => Ok(()),
            SlackOutcome::Rejected(_) => Err(()),
        }
    }

    fn post_channel(&mut self, channel: &ChannelId, text: &str) -> Result<(), ()> {
        let text = MessageText::new(text).map_err(|_| ())?;
        let request = PostMessageRequest::new(channel.clone(), text);
        match SlackClient::post_message(self.as_ref(), &request).map_err(|_| ())? {
            SlackOutcome::Accepted(_) => Ok(()),
            SlackOutcome::Rejected(_) => Err(()),
        }
    }

    fn post_ticket_notification(
        &mut self,
        channel: &ChannelId,
        parent: &MessageTs,
        text: &str,
    ) -> SlackEffectOutcome {
        let Ok(text) = MessageText::new(text) else {
            return SlackEffectOutcome::Rejected;
        };
        let request = PostMessageRequest::new(channel.clone(), text).in_thread(parent.clone());
        match SlackClient::post_message(self.as_ref(), &request) {
            Ok(SlackOutcome::Accepted(_)) => SlackEffectOutcome::Accepted,
            Ok(SlackOutcome::Rejected(_)) => SlackEffectOutcome::Rejected,
            Err(_) => SlackEffectOutcome::Ambiguous,
        }
    }

    fn post_approval_card(
        &mut self,
        channel: &ChannelId,
        parent: &MessageTs,
        receipt: &automonique_support_connector::TicketDispatchReceipt,
        manage_url: Option<&ManageUrl>,
    ) -> Result<(), ()> {
        let short = receipt.job_id.get(..12).unwrap_or(&receipt.job_id);
        let fallback = format!(
            "Confirmation required for {} ({}) — Monique job {short}",
            receipt.issue_title, receipt.issue_url
        );
        // The console address is one deployment's, so the button exists only
        // where one is configured. Omitting it costs the card nothing: both
        // decisions are on the card itself, and a link to a host this
        // installation does not have would be worse than no link.
        let mut elements = vec![
            serde_json::json!({"type":"button","action_id":"monique_ticket_approve","text":{"type":"plain_text","text":"Confirm"},"style":"primary","value":receipt.job_id,"confirm":{"title":{"type":"plain_text","text":"Confirm ticket?"},"text":{"type":"mrkdwn","text":"This releases the ticket for work."},"confirm":{"type":"plain_text","text":"Confirm"},"deny":{"type":"plain_text","text":"Cancel"}}}),
            serde_json::json!({"type":"button","action_id":"monique_ticket_reject","text":{"type":"plain_text","text":"Reject"},"style":"danger","value":receipt.job_id}),
        ];
        if let Some(url) = manage_url {
            elements.push(serde_json::json!({"type":"button","action_id":"monique_ticket_manage","text":{"type":"plain_text","text":"Open Manage"},"url":url.as_str()}));
        }
        let blocks = serde_json::json!([
            {"type":"header","text":{"type":"plain_text","text":"Confirmation required"}},
            {"type":"section","text":{"type":"mrkdwn","text":format!("*{}*\n<{}|Open GitHub issue>\nJob `{}` is pending approval. No work starts before confirmation.", receipt.issue_title, receipt.issue_url, short)}},
            {"type":"actions","elements":elements}
        ]);
        let blocks = MessageBlocks::new(&blocks.to_string()).map_err(|_| ())?;
        let request = PostMessageRequest::new(
            channel.clone(),
            MessageText::new(&fallback).map_err(|_| ())?,
        )
        .in_thread(parent.clone())
        .with_blocks(blocks);
        match SlackClient::post_message(self.as_ref(), &request).map_err(|_| ())? {
            SlackOutcome::Accepted(_) => Ok(()),
            SlackOutcome::Rejected(_) => Err(()),
        }
    }

    fn open_reject_modal(
        &mut self,
        trigger_id: &str,
        job_id: &str,
        channel: &ChannelId,
        message_ts: &MessageTs,
    ) -> Result<(), ()> {
        let metadata = serde_json::json!({
            "job_id": job_id,
            "channel_id": channel.as_str(),
            "message_ts": message_ts.as_str(),
        });
        let view = serde_json::json!({
            "type":"modal",
            "callback_id":"monique_ticket_reject_submit",
            "private_metadata":metadata.to_string(),
            "title":{"type":"plain_text","text":"Reject ticket"},
            "submit":{"type":"plain_text","text":"Reject"},
            "close":{"type":"plain_text","text":"Cancel"},
            "blocks":[{"type":"input","block_id":"reason","label":{"type":"plain_text","text":"Reason"},"element":{"type":"plain_text_input","action_id":"value","multiline":true,"min_length":1,"max_length":500}}]
        });
        let request = OpenViewRequest::new(
            TriggerId::new(trigger_id).map_err(|_| ())?,
            ModalView::new(&view.to_string()).map_err(|_| ())?,
        );
        match SlackClient::open_view(self.as_ref(), &request).map_err(|_| ())? {
            SlackOutcome::Accepted(()) => Ok(()),
            SlackOutcome::Rejected(_) => Err(()),
        }
    }

    fn post_approval_request(
        &mut self,
        channel: &ChannelId,
        request_key: &str,
        expires_at_ms: i64,
    ) -> Result<(), ()> {
        let fallback = format!("Approval waiting: {request_key}");
        let blocks = serde_json::json!([
            {"type":"header","text":{"type":"plain_text","text":"Approval required"}},
            {"type":"section","text":{"type":"mrkdwn","text":format!("Reference `{request_key}`. No run starts under it before a decision, and it stops being answerable at {expires_at_ms}.")}},
            {"type":"actions","elements":[
                {"type":"button","action_id":SLACK_APPROVAL_GRANT_ACTION,"text":{"type":"plain_text","text":"Approve"},"style":"primary","value":request_key,"confirm":{"title":{"type":"plain_text","text":"Approve this run?"},"text":{"type":"mrkdwn","text":"This permits the run to start. Starting it is a separate command."},"confirm":{"type":"plain_text","text":"Approve"},"deny":{"type":"plain_text","text":"Cancel"}}},
                {"type":"button","action_id":SLACK_APPROVAL_DENY_ACTION,"text":{"type":"plain_text","text":"Deny"},"style":"danger","value":request_key}
            ]}
        ]);
        let blocks = MessageBlocks::new(&blocks.to_string()).map_err(|_| ())?;
        let request = PostMessageRequest::new(
            channel.clone(),
            MessageText::new(&fallback).map_err(|_| ())?,
        )
        .with_blocks(blocks);
        match SlackClient::post_message(self.as_ref(), &request).map_err(|_| ())? {
            SlackOutcome::Accepted(_) => Ok(()),
            SlackOutcome::Rejected(_) => Err(()),
        }
    }

    fn post_tool_approval_card(
        &mut self,
        channel: &ChannelId,
        parent: &MessageTs,
        key: &str,
        preview: &str,
    ) -> Result<(), ()> {
        let blocks = serde_json::json!([
            {"type":"header","text":{"type":"plain_text","text":"Tool approval required"}},
            {"type":"section","text":{"type":"mrkdwn","text":preview}},
            {"type":"actions","elements":[
                {"type":"button","action_id":SLACK_TOOL_GRANT_ACTION,"text":{"type":"plain_text","text":"Approve"},"style":"primary","value":key,"confirm":{"title":{"type":"plain_text","text":"Run this tool?"},"text":{"type":"mrkdwn","text":"This performs the exact operation previewed above once."},"confirm":{"type":"plain_text","text":"Approve"},"deny":{"type":"plain_text","text":"Cancel"}}},
                {"type":"button","action_id":SLACK_TOOL_DENY_ACTION,"text":{"type":"plain_text","text":"Deny"},"style":"danger","value":key}
            ]}
        ]);
        let blocks = MessageBlocks::new(&blocks.to_string()).map_err(|_| ())?;
        let request =
            PostMessageRequest::new(channel.clone(), MessageText::new(preview).map_err(|_| ())?)
                .in_thread(parent.clone())
                .with_blocks(blocks);
        match SlackClient::post_message(self.as_ref(), &request).map_err(|_| ())? {
            SlackOutcome::Accepted(_) => Ok(()),
            SlackOutcome::Rejected(_) => Err(()),
        }
    }

    fn update_decision(
        &mut self,
        channel: &ChannelId,
        message_ts: &MessageTs,
        text: &str,
    ) -> Result<(), ()> {
        let blocks = MessageBlocks::new(
            &serde_json::json!([{"type":"section","text":{"type":"mrkdwn","text":text}}])
                .to_string(),
        )
        .map_err(|_| ())?;
        let request = automonique_slack_connector::UpdateMessageRequest::new(
            channel.clone(),
            message_ts.clone(),
            MessageText::new(text).map_err(|_| ())?,
        )
        .with_blocks(blocks);
        match SlackClient::update_message(self.as_ref(), &request).map_err(|_| ())? {
            SlackOutcome::Accepted(()) => Ok(()),
            SlackOutcome::Rejected(_) => Err(()),
        }
    }

    fn publish_home(
        &mut self,
        user: &UserId,
        is_admin: bool,
        pending_count: usize,
    ) -> Result<(), ()> {
        let mut blocks = vec![
            serde_json::json!({"type":"header","text":{"type":"plain_text","text":"Monique"}}),
            serde_json::json!({"type":"section","text":{"type":"mrkdwn","text":"Ask me a read-only question in a DM or mention me in a configured channel. Post one GitHub issue URL in the intake channel to request work."}}),
        ];
        if is_admin {
            blocks.push(serde_json::json!({"type":"section","text":{"type":"mrkdwn","text":format!("*Administrator health*\nPending confirmation gates: *{pending_count}*\nSlack Socket Mode: connected")}}));
        } else {
            blocks.push(serde_json::json!({"type":"context","elements":[{"type":"mrkdwn","text":"Your ticket status remains in the originating Slack thread."}]}));
        }
        let view = HomeView::new(&serde_json::json!({"type":"home","blocks":blocks}).to_string())
            .map_err(|_| ())?;
        let request = PublishViewRequest::new(user.clone(), view);
        match SlackClient::publish_view(self.as_ref(), &request).map_err(|_| ())? {
            SlackOutcome::Accepted(()) => Ok(()),
            SlackOutcome::Rejected(_) => Err(()),
        }
    }
}

struct SlackTicketRouter<P> {
    poster: P,
    manage: Box<dyn crate::telegram_bridge::TicketActionSurface + Send>,
    manage_url: Option<ManageUrl>,
    memory_tenant: String,
    channels: ChannelMap,
    admins: Vec<UserId>,
    members: Vec<UserId>,
    features: Vec<SlackFeature>,
    interactive_decisions: bool,
    gates: Arc<std::sync::Mutex<crate::telegram_bridge::TicketGateRegistry>>,
    github_actions: Option<GitHubActionEngine<SocketRunLane>>,
    /// A read-only view of the durable proposals this workspace can decide.
    ///
    /// Its own connection rather than the daemon's: this router runs on the
    /// Socket Mode thread, and a handle borrowed from the serve loop would
    /// either need a lock around every request or would race one. `None` when
    /// the table would not open, which makes the listing verb refuse rather
    /// than answer emptily.
    approvals: Option<ApprovalRequests>,
    /// The lane one durable approval decision travels down.
    ///
    /// Its own handle rather than the GitHub engine's, because the two are
    /// enabled independently: a workspace that approves runs and configures no
    /// GitHub host still has to be able to decide. `None` only when this
    /// daemon's own run index would not open, which is the same condition
    /// every other socket lane refuses on.
    approval_lane: Option<SocketRunLane>,
    /// The read-only conversational surface used only after action-shaped
    /// Slack routes have been excluded.
    question_answerer: Option<Box<dyn SlackQuestionAnswerer>>,
}

enum SlackQuestionReply {
    Text(String),
    Approval { key: String, preview: String },
    GitHubAction(GitHubActionRequest),
}

enum PendingSlackTool {
    SlackPost(crate::telegram_bridge::QuestionSlackPostPlan),
    McpCall {
        plan: crate::telegram_bridge::QuestionMcpCallPlan,
        requests: serde_json::Value,
    },
    /// The deeper lane for one question the chat lane could not answer.
    Escalate(crate::telegram_bridge::QuestionEscalation),
}

struct PendingSlackToolEntry {
    channel: ChannelId,
    tool: PendingSlackTool,
}

trait SlackQuestionAnswerer: Send {
    fn answer(
        &mut self,
        question: &str,
        context: &str,
        source_key: &str,
        actor: &UserId,
        channel: &ChannelId,
        approvals_enabled: bool,
    ) -> SlackQuestionReply;

    fn decide_tool(&mut self, _key: &str, _granted: bool, _channel: &ChannelId) -> String {
        String::from("That tool approval is no longer pending. Nothing was changed.")
    }

    fn provider_stats(&mut self) -> String {
        String::from("Monique's provider instance statistics are unavailable right now.")
    }

    fn channel_ticket_audit(&mut self, _channel: &ChannelId) -> String {
        String::from("Monique's Slack ticket auditor is unavailable right now.")
    }

    fn issue_status(&mut self, _issue_url: &str) -> String {
        String::from("Monique's GitHub issue reader is unavailable right now.")
    }

    fn issue_review(
        &mut self,
        _issue_url: &str,
        _question: &str,
        _context: &str,
        _deep: bool,
    ) -> String {
        String::from("Monique's GitHub issue reader is unavailable right now.")
    }
}

struct LiveSlackQuestionAnswerer {
    surface: StoreControlSurface,
    lane: SocketRunLane,
    github: Option<Box<dyn GitHubSurface + Send>>,
    /// The workspace as a read seam, so a router read plan naming a channel
    /// is honoured here as it is on Telegram.
    slack_reader: Option<Box<dyn SlackSurface + Send>>,
    administrators: Vec<i64>,
    configured: Vec<i64>,
    api: Arc<SlackClient>,
    channels: ChannelMap,
    members: Vec<UserId>,
    mcp: McpRegistry,
    github_action_aliases: Vec<String>,
    pending_tools: BTreeMap<String, PendingSlackToolEntry>,
    /// The member roster, resolved on the first conversational question and
    /// kept for the worker's lifetime.
    ///
    /// Once, not per question: the allowlist is startup configuration, and a
    /// per-question resolution would spend a `users.info` burst on every
    /// mention. The cost of the cache is that a member renamed mid-run keeps
    /// the old label until the daemon restarts, which a display label can
    /// tolerate.
    roster: Option<Option<String>>,
}

impl LiveSlackQuestionAnswerer {
    fn prepare_tool_approval(
        &mut self,
        selected: TransportToolPlan,
        question: &str,
        source_key: &str,
        channel: &ChannelId,
        approvals_enabled: bool,
    ) -> SlackQuestionReply {
        match selected {
            TransportToolPlan::McpCall(plan) => {
                match self
                    .mcp
                    .call(&plan.server, &plan.tool, plan.arguments.clone(), None)
                {
                    Ok(McpCallResult::Complete { value, is_error }) => {
                        let Some(prompt) = mcp_result_prompt(question, &plan, &value, is_error)
                        else {
                            return SlackQuestionReply::Text(String::from(
                                "The MCP result did not fit safely, so it was not sent to the answer model.",
                            ));
                        };
                        SlackQuestionReply::Text(
                            run_question_to_completion(
                                &mut self.lane,
                                &prompt,
                                QuestionProfile::OperationalLookup,
                            )
                                .unwrap_or_else(|_| {
                                    String::from(
                                        "The MCP read completed, but the answer model is unavailable right now.",
                                    )
                                }),
                        )
                    }
                    Ok(McpCallResult::InputRequired { requests }) => {
                        if !approvals_enabled {
                            return SlackQuestionReply::Text(String::from(
                                "This MCP operation requires approval, but interactive approvals are not enabled in this Slack workspace. Nothing was changed.",
                            ));
                        }
                        let preview = mcp_approval_preview(&plan, &requests);
                        self.stage_tool(
                            source_key,
                            channel,
                            PendingSlackTool::McpCall { plan, requests },
                            preview,
                        )
                    }
                    Err(_) => SlackQuestionReply::Text(String::from(
                        "The selected MCP capability is unavailable right now; nothing was changed.",
                    )),
                }
            }
            TransportToolPlan::SlackPost(plan) => {
                if !approvals_enabled {
                    return SlackQuestionReply::Text(String::from(
                        "Posting to another Slack channel requires approval, but interactive approvals are not enabled in this workspace. Nothing was posted.",
                    ));
                }
                let preview = format!(
                    "Slack post awaiting approval\nChannel: #{}\n\n{}\n\nApprove posts it once. Deny posts nothing.",
                    plan.channel, plan.text
                );
                self.stage_tool(
                    source_key,
                    channel,
                    PendingSlackTool::SlackPost(plan),
                    preview,
                )
            }
            TransportToolPlan::GitHubAction(request) => {
                if approvals_enabled {
                    SlackQuestionReply::GitHubAction(request)
                } else {
                    SlackQuestionReply::Text(String::from(
                        "GitHub writes require an administrator in an approval-enabled Slack conversation. Nothing was changed.",
                    ))
                }
            }
            TransportToolPlan::Escalate(escalation) => {
                if !approvals_enabled {
                    // No buttons on this workspace: say what was found and
                    // what the deeper lane would do, without running it.
                    let mut text = escalation.plan.preview();
                    text.push_str(
                        "\n\nInteractive approvals are not enabled in this workspace, so ask an administrator here or on Telegram to run it.",
                    );
                    return SlackQuestionReply::Text(text);
                }
                let preview = escalation.plan.preview();
                self.stage_tool(
                    source_key,
                    channel,
                    PendingSlackTool::Escalate(escalation),
                    preview,
                )
            }
        }
    }

    fn stage_tool(
        &mut self,
        source_key: &str,
        channel: &ChannelId,
        tool: PendingSlackTool,
        preview: String,
    ) -> SlackQuestionReply {
        if self.pending_tools.len() >= MAX_PENDING_SLACK_TOOL_APPROVALS {
            return SlackQuestionReply::Text(String::from(
                "Too many Slack tool approvals are pending; nothing was staged.",
            ));
        }
        let binding = format!("slack-tool-approval-v1\0{source_key}\0{}", channel.as_str());
        let digest = Sha256::digest(binding.as_bytes());
        let suffix = digest[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let key = format!("tool-{suffix}");
        self.pending_tools.insert(
            key.clone(),
            PendingSlackToolEntry {
                channel: channel.clone(),
                tool,
            },
        );
        SlackQuestionReply::Approval { key, preview }
    }

    fn decide_pending_tool(&mut self, key: &str, granted: bool, channel: &ChannelId) -> String {
        if self
            .pending_tools
            .get(key)
            .is_some_and(|pending| &pending.channel != channel)
        {
            return String::from(
                "That tool approval belongs to another Slack conversation. Nothing was changed.",
            );
        }
        let Some(pending) = self.pending_tools.remove(key) else {
            return String::from("That tool approval is no longer pending. Nothing was changed.");
        };
        if !granted {
            return String::from("Denied. The proposed tool was not run.");
        }
        match pending.tool {
            PendingSlackTool::SlackPost(plan) => {
                let label = self
                    .channels
                    .labels()
                    .into_iter()
                    .find(|label| label.eq_ignore_ascii_case(&plan.channel));
                let Some(label) = label else {
                    return String::from(
                        "That Slack channel is no longer configured, so nothing was posted.",
                    );
                };
                let Ok(name) = ChannelName::new(label) else {
                    return String::from(
                        "That configured Slack channel is invalid, so nothing was posted.",
                    );
                };
                let Some(target) = self.channels.resolve(&name).cloned() else {
                    return String::from(
                        "That Slack channel is no longer configured, so nothing was posted.",
                    );
                };
                let Ok(text) = MessageText::new(&plan.text) else {
                    return String::from(
                        "The approved Slack message is invalid; nothing was posted.",
                    );
                };
                match SlackClient::post_message(
                    self.api.as_ref(),
                    &PostMessageRequest::new(target, text),
                ) {
                    Ok(SlackOutcome::Accepted(_)) => {
                        format!("✅ Approved and posted once to #{}.", plan.channel)
                    }
                    Ok(SlackOutcome::Rejected(_)) => {
                        String::from("Slack rejected the approved post, so nothing was posted.")
                    }
                    Err(_) => String::from(
                        "Slack did not confirm the approved post. Its outcome is unknown and Monique did not retry it.",
                    ),
                }
            }
            PendingSlackTool::Escalate(escalation) => {
                crate::telegram_bridge::answer_approved_escalation(
                    &mut self.surface,
                    &mut self.lane,
                    self.github
                        .as_deref_mut()
                        .map(|github| github as &mut dyn GitHubSurface),
                    &escalation,
                    &self.administrators,
                    &self.configured,
                    "slack_question_worker",
                )
            }
            PendingSlackTool::McpCall { plan, requests } => {
                let Some(responses) = accepted_mcp_input_responses(&requests) else {
                    return String::from(
                        "The MCP approval request was malformed, so nothing was changed.",
                    );
                };
                match self
                    .mcp
                    .call(&plan.server, &plan.tool, plan.arguments, Some(responses))
                {
                    Ok(McpCallResult::Complete {
                        value,
                        is_error: false,
                    }) => bounded_slack_tool_reply(&format!(
                        "✅ Approved and completed {}.\n\n{}",
                        plan.tool, value
                    )),
                    Ok(McpCallResult::Complete {
                        value,
                        is_error: true,
                    }) => bounded_slack_tool_reply(&format!(
                        "The approved MCP operation returned an error.\n\n{value}"
                    )),
                    Ok(McpCallResult::InputRequired { .. }) => String::from(
                        "The MCP server requested another approval step; nothing further was executed.",
                    ),
                    Err(_) => String::from(
                        "The approved MCP operation could not be completed. Retry from the original request.",
                    ),
                }
            }
        }
    }
}

fn bounded_slack_tool_reply(value: &str) -> String {
    const MAX_BYTES: usize = 12 * 1024;
    if value.len() <= MAX_BYTES {
        return value.to_owned();
    }
    let mut end = MAX_BYTES;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n[…truncated]", &value[..end])
}

impl SlackQuestionAnswerer for LiveSlackQuestionAnswerer {
    fn answer(
        &mut self,
        question: &str,
        context: &str,
        source_key: &str,
        actor: &UserId,
        channel: &ChannelId,
        approvals_enabled: bool,
    ) -> SlackQuestionReply {
        if let Some(answer) = slack_reply_location_answer(question, context) {
            return SlackQuestionReply::Text(answer);
        }
        if self.roster.is_none() {
            self.roster = Some(slack_member_roster(self.api.as_ref(), &self.members));
        }
        let roster = self.roster.clone().flatten();
        let slack_channels = self
            .channels
            .labels()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mcp_tools = self.mcp.discover().unwrap_or_default();
        let github_configured = self.github.is_some();
        let mut selected_tool = None;
        let answer = answer_read_only_transport_question(
            &mut self.surface,
            &mut self.lane,
            TransportLiveSeams {
                slack: self
                    .slack_reader
                    .as_deref_mut()
                    .map(|slack| slack as &mut dyn SlackSurface),
                github: self
                    .github
                    .as_deref_mut()
                    .map(|github| github as &mut dyn GitHubSurface),
            },
            question,
            context,
            TransportConversationIdentity {
                lane_key: channel.as_str(),
                actor_key: actor.as_str(),
                source_key,
            },
            &self.administrators,
            &self.configured,
            roster.as_deref(),
            &slack_channels,
            github_configured,
            &mcp_tools,
            &self.github_action_aliases,
            &mut selected_tool,
            "slack_question_worker",
        );
        let Some(selected_tool) = selected_tool else {
            return SlackQuestionReply::Text(answer);
        };
        self.prepare_tool_approval(
            selected_tool,
            question,
            source_key,
            channel,
            approvals_enabled,
        )
    }

    fn decide_tool(&mut self, key: &str, granted: bool, channel: &ChannelId) -> String {
        self.decide_pending_tool(key, granted, channel)
    }

    fn provider_stats(&mut self) -> String {
        self.surface.agents_text().unwrap_or_else(|_| {
            String::from("Monique could not read provider instance statistics right now.")
        })
    }

    fn channel_ticket_audit(&mut self, channel: &ChannelId) -> String {
        let identity = match self.api.auth_test() {
            Ok(SlackOutcome::Accepted(identity)) => identity,
            Ok(SlackOutcome::Rejected(_)) | Err(_) => {
                return String::from(
                    "Monique could not identify its Slack account, so the ticket audit was not run.",
                );
            }
        };
        let mut messages = Vec::new();
        let mut cursor = None;
        let mut complete = false;
        for _ in 0..MAX_CHANNEL_TICKET_AUDIT_PAGES {
            let mut request =
                match ConversationsHistoryRequest::new(channel.clone(), MAX_PAGE_LIMIT) {
                    Ok(request) => request,
                    Err(_) => {
                        return String::from(
                            "Monique could not construct the bounded Slack history audit.",
                        );
                    }
                };
            if let Some(next) = cursor.take() {
                request = request.from_cursor(next);
            }
            let page = match self.api.conversations_history(&request) {
                Ok(SlackOutcome::Accepted(page)) => page,
                Ok(SlackOutcome::Rejected(_)) | Err(_) => {
                    return String::from(
                        "Slack did not provide a complete channel-history page, so Monique did not claim an audit result.",
                    );
                }
            };
            messages.extend(page.messages);
            cursor = page.next_cursor;
            if cursor.is_none() {
                complete = true;
                break;
            }
        }
        channel_ticket_audit_text(&messages, &identity.user_id, complete)
    }

    fn issue_status(&mut self, issue_url: &str) -> String {
        let Some(locator) = IssueLocator::parse(issue_url) else {
            return String::from("That is not a canonical GitHub issue URL.");
        };
        let Some(github) = self.github.as_deref_mut() else {
            return String::from("Monique's GitHub issue reader is not configured.");
        };
        match github.issue_facts(&locator, IssueFactDetail::Summary) {
            Ok(facts) => github_issue_status_answer(&locator, &facts),
            Err(error) if error.contains("repository_not_configured") => String::from(
                "That GitHub repository is not in Monique's configured read allowlist.",
            ),
            Err(_) => String::from("Monique could not read that GitHub issue right now."),
        }
    }

    fn issue_review(
        &mut self,
        issue_url: &str,
        question: &str,
        context: &str,
        deep: bool,
    ) -> String {
        let Some(locator) = IssueLocator::parse(issue_url) else {
            return String::from("That is not a canonical GitHub issue URL.");
        };
        let Some(github) = self.github.as_deref_mut() else {
            return String::from("Monique's GitHub issue reader is not configured.");
        };
        let facts = match github.issue_facts(&locator, IssueFactDetail::Full) {
            Ok(facts) => facts,
            Err(error) if error.contains("repository_not_configured") => {
                return String::from(
                    "That GitHub repository is not in Monique's configured read allowlist.",
                );
            }
            Err(_) => return String::from("Monique could not read that GitHub issue right now."),
        };
        let context =
            format!("{context}\n\n[live_github_issues]\nissue=\n{facts}\n[/live_github_issues]");
        answer_typed_github_issue_question(
            &mut self.lane,
            question,
            &context,
            deep,
            "slack_question_worker",
        )
    }
}

fn slack_reply_location_answer(question: &str, context: &str) -> Option<String> {
    let normalized = question
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let asks_where = [
        "tu as répondu ou",
        "tu as repondu ou",
        "où as-tu répondu",
        "ou as-tu repondu",
        "où est-ce que tu as répondu",
        "ou est ce que tu as repondu",
        "where did you reply",
        "where did you answer",
    ]
    .iter()
    .any(|phrase| normalized.contains(phrase));
    if !asks_where || !context.lines().any(|line| line.starts_with("assistant: ")) {
        return None;
    }
    Some(String::from(
        "Ma réponse précédente a été publiée dans ce thread Slack. Je n’ai envoyé ni message privé ni second message ailleurs.",
    ))
}

fn is_provider_stats_question(text: &str) -> bool {
    let normalized = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    normalized == "agents"
        || [
            "agent stats",
            "agents stats",
            "provider stats",
            "provider instances",
            "running codex",
            "running claude",
            "instances codex",
            "instances claude",
            "statut des agents",
            "stats des agents",
        ]
        .iter()
        .any(|phrase| normalized.contains(phrase))
}

fn github_issue_status_answer(locator: &IssueLocator, facts: &str) -> String {
    let value = |key: &str| {
        facts
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .unwrap_or_default()
    };
    let state = value("state=");
    let updated = value("updated=");
    let summary = match state {
        "closed" => "Yes — GitHub marks this issue as closed.",
        "open" => "No — GitHub still marks this issue as open.",
        _ => "GitHub returned the issue, but its state was not recognizable.",
    };
    format!(
        "{summary}\n{}#{}\nLast updated: {updated}",
        locator.target(),
        locator.number()
    )
}

fn is_github_issue_status_question(text: &str) -> bool {
    let normalized = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    [
        "is this done",
        "is it done",
        "is this complete",
        "is this completed",
        "is this closed",
        "is this resolved",
        "has this been done",
        "has this been completed",
        "what is the status",
        "what's the status",
        "status of this",
        "est-ce terminé",
        "est ce termine",
        "est-ce fini",
        "est ce fini",
        "est-ce fait",
        "est ce fait",
        "il est fait",
        "il est terminé",
        "il est termine",
        "est-il fait",
        "est il fait",
        "c'est fait",
        "c’est fait",
        "ça a été fait",
        "ca a ete fait",
    ]
    .iter()
    .any(|phrase| normalized.contains(phrase))
}

/// Recognize a question about the dispatched Manage job, not the GitHub
/// issue's open/closed state. These phrases are intentionally work-shaped so
/// an ordinary "how's it going?" still reaches conversation.
fn is_ticket_job_progress_question(text: &str) -> bool {
    let normalized = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    normalized.contains("progressing")
        || normalized.contains("job progress")
        || normalized.contains("job status")
        || normalized.contains("run status")
        || normalized.contains("work progress")
        || normalized.contains("work status")
        || normalized.contains("how is the work")
        || normalized.contains("how's the work")
        || normalized.contains("avancement du travail")
        || normalized.contains("avancement du job")
        || normalized.contains("statut du job")
        || normalized.contains("où en est le travail")
        || normalized.contains("ou en est le travail")
        || normalized.contains("où en est le job")
        || normalized.contains("ou en est le job")
}

/// Recognize a read-only request to audit ticket posts and their follow-ups in
/// the current Slack channel. In particular, `check` and `comments` here are
/// audit nouns: they must not be reinterpreted as checklist and reply writes.
fn is_channel_ticket_audit_question(text: &str) -> bool {
    let normalized = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let names_tickets = ["ticket", "tickets", "issue", "issues"]
        .iter()
        .any(|term| normalized.contains(term));
    let names_channel = normalized.contains("channel") || normalized.contains("slack");
    let asks_audit = [
        "check", "audit", "review", "inspect", "verify", "vérifie", "verifie",
    ]
    .iter()
    .any(|term| normalized.contains(term));
    let names_gap = [
        "missed",
        "unhandled",
        "not handled",
        "follow up",
        "follow-up",
        "comment",
        "oublié",
        "oublie",
        "non traité",
        "non traite",
    ]
    .iter()
    .any(|term| normalized.contains(term));
    names_tickets && names_channel && asks_audit && names_gap
}

fn channel_ticket_audit_text(
    messages: &[SlackMessage],
    bot_user: &UserId,
    complete_history: bool,
) -> String {
    let mut ticket_posts = 0usize;
    let mut unique_issues = BTreeMap::<String, usize>::new();
    let mut missing = BTreeMap::<String, usize>::new();
    let mut bot_only_threads = 0usize;
    let mut mixed_threads = 0usize;
    let mut uncertain_threads = 0usize;

    for message in messages {
        if !message.is_from_member() || !message.is_top_level() {
            continue;
        }
        let Ok(Some(issue_url)) = one_issue_url(&message.text) else {
            continue;
        };
        ticket_posts += 1;
        *unique_issues.entry(issue_url.clone()).or_default() += 1;
        if message.reply_count.unwrap_or_default() == 0 {
            *missing.entry(issue_url).or_default() += 1;
            continue;
        }
        let Some(reply_users) = message.reply_users.as_ref() else {
            uncertain_threads += 1;
            continue;
        };
        let summary_complete = message
            .reply_users_count
            .is_some_and(|count| usize::try_from(count).ok() == Some(reply_users.len()));
        if !summary_complete {
            uncertain_threads += 1;
            continue;
        }
        if !reply_users.contains(bot_user) {
            *missing.entry(issue_url).or_default() += 1;
        } else if reply_users.iter().any(|user| user != bot_user) {
            mixed_threads += 1;
        } else {
            bot_only_threads += 1;
        }
    }

    let history_scope = if complete_history {
        "all history Slack made available"
    } else {
        "the first 4,000 available channel messages"
    };
    let mut answer = format!(
        "Channel ticket audit: scanned {} messages and {ticket_posts} GitHub ticket posts ({} unique issues) across {history_scope}.",
        messages.len(),
        unique_issues.len()
    );
    if missing.is_empty() {
        answer.push_str("\n\nNo ticket post is confirmed as missing a Monique reply.");
    } else {
        let missed_posts: usize = missing.values().sum();
        answer.push_str(&format!(
            "\n\n{missed_posts} ticket post(s) have no confirmed Monique reply:"
        ));
        for (index, (issue_url, count)) in missing.iter().enumerate() {
            if index == 20 {
                answer.push_str(&format!(
                    "\n- … and {} more issue(s)",
                    missing.len().saturating_sub(index)
                ));
                break;
            }
            answer.push_str("\n- ");
            answer.push_str(issue_url);
            if *count > 1 {
                answer.push_str(&format!(" ({count} separate posts)"));
            }
        }
    }
    answer.push_str(&format!(
        "\n\nFollow-ups: {bot_only_threads} replied threads have only Monique in Slack's complete participant summary. {mixed_threads} thread(s) contain both Monique and human replies; channel history does not expose their reply order, so they still require exact per-thread checking."
    ));
    if uncertain_threads > 0 {
        answer.push_str(&format!(
            " Slack supplied an incomplete participant summary for {uncertain_threads} additional thread(s), so Monique does not claim those are clear."
        ));
    }
    answer
}

fn slack_ticket_status_text(status: &automonique_support_connector::TicketStatus) -> String {
    let short = status.job_id.get(..12).unwrap_or(&status.job_id);
    let mut text = format!(
        "{}\nMonique job `{short}` is {}.\nLast updated: {}",
        ticket_heading(status.job_status),
        status.job_status.as_str(),
        status.updated_at
    );
    if !status.result.trim().is_empty() {
        text.push('\n');
        text.push_str(status.result.trim());
    }
    text
}

fn completion_comment_permalink(result: &str, issue_url: &str) -> Option<String> {
    let prefix = format!("{issue_url}#issuecomment-");
    let start = result.find(&prefix)?;
    let suffix = &result[start + prefix.len()..];
    let digits = suffix.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    Some(format!("{prefix}{}", &suffix[..digits]))
}

fn slack_ticket_terminal_text(
    notification: &crate::telegram_bridge::SlackTicketNotification,
    status: &TicketStatus,
) -> Option<String> {
    if notification.job_id != status.job_id || notification.issue_url != status.issue_url {
        return None;
    }
    let short = status.job_id.get(..12).unwrap_or(&status.job_id);
    let requester = &notification.requester_user;
    match status.job_status {
        TicketJobStatus::Done => {
            let destination = completion_comment_permalink(&status.result, &status.issue_url)
                .map_or_else(
                    || {
                        format!(
                            "<{}|Open the GitHub issue> — the job receipt did not include the completion-comment permalink.",
                            status.issue_url
                        )
                    },
                    |url| format!("<{url}|View the completion summary on GitHub>"),
                );
            Some(format!(
                "{}\n<@{requester}> Monique completed the ticket work.\n{destination}\nMonique job `{short}` is done.",
                ticket_heading(status.job_status)
            ))
        }
        TicketJobStatus::Failed => Some(format!(
            "{}\n<@{requester}> Monique's ticket work failed.\n<{}|Open the GitHub issue>\nMonique job `{short}` is failed.",
            ticket_heading(status.job_status),
            status.issue_url
        )),
        TicketJobStatus::Cancelled => Some(format!(
            "{}\n<@{requester}> Monique's ticket work was cancelled.\n<{}|Open the GitHub issue>\nMonique job `{short}` is cancelled.",
            ticket_heading(status.job_status),
            status.issue_url
        )),
        TicketJobStatus::PendingApproval
        | TicketJobStatus::Pending
        | TicketJobStatus::Claimed
        | TicketJobStatus::Running => None,
    }
}

/// Resolve a read-only issue follow-up against the current Slack thread.
///
/// The first turn commonly carries the canonical URL while a human follow-up
/// says only "fais un récap de la demande".  The durable conversation context
/// is already scoped to that exact thread, so reusing its sole issue URL is a
/// safe typed read.  Ambiguous contexts deliberately fall through to ordinary
/// conversation rather than choosing a target for the user.
fn contextual_github_issue_review(text: &str, context: &str) -> Option<String> {
    if one_issue_url(text).ok().flatten().is_some() {
        return None;
    }
    let normalized = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let terms: std::collections::BTreeSet<&str> = normalized
        .split(|character: char| !character.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .collect();
    let asks_for_issue_detail = [
        "récap",
        "recap",
        "résumé",
        "resume",
        "summary",
        "summarize",
        "summarise",
        "détail",
        "detail",
        "contenu",
        "content",
        "demande",
        "requirement",
        "requirements",
        "checklist",
    ]
    .iter()
    .any(|term| terms.contains(term))
        || [
            "what does it ask",
            "what was requested",
            "what is requested",
            "de quoi s'agit-il",
            "de quoi il s'agit",
            "qu'est-ce qui est demandé",
            "qu est ce qui est demandé",
        ]
        .iter()
        .any(|phrase| normalized.contains(phrase));
    asks_for_issue_detail
        .then(|| one_issue_url(context).ok().flatten())
        .flatten()
}

/// Resolve a short execution follow-up against the sole GitHub issue in the
/// current Slack thread. The URL comes only from durable thread context; the
/// user's short phrase can authorize opening a gate, but can never select a
/// different target.
fn contextual_github_issue_work(text: &str, context: &str) -> Option<String> {
    if one_issue_url(text).ok().flatten().is_some() {
        return None;
    }
    let normalized = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_matches(|character: char| !character.is_alphanumeric())
        .to_lowercase();
    let requests_work = matches!(
        normalized.as_str(),
        "do it"
            | "go ahead"
            | "run it"
            | "execute it"
            | "handle it"
            | "fix it"
            | "implement it"
            | "fais le"
            | "fais-le"
            | "fait le"
            | "fait-le"
            | "vas y"
            | "vas-y"
            | "lance le"
            | "lance-le"
            | "execute le"
            | "exécute le"
    );
    requests_work
        .then(|| one_issue_url(context).ok().flatten())
        .flatten()
}

fn ticket_approval_failure(reason: &str) -> String {
    match reason {
        "executor_unavailable" => String::from(
            "Manage has no live code-execution worker for this ticket. The gate remains pending and no work was released.",
        ),
        "source_mismatch" => String::from(
            "Manage linked this confirmation to a different pending request. The gate remains pending and no work was released.",
        ),
        "manage_unavailable" | "decision_unavailable" => String::from(
            "Manage's decision endpoint was unavailable or timed out. The gate remains pending and no work was released.",
        ),
        "approval_expired" | "expired" => String::from(
            "This confirmation expired before Manage accepted it. Post the issue URL again to create a fresh gate; no work was released.",
        ),
        "already_decided" | "approval_already_decided" => String::from(
            "Manage reports that this gate was already decided. Check the job's current status before creating another request.",
        ),
        "decision_receipt_mismatch" => String::from(
            "Manage returned a decision receipt for different coordinates. The gate remains pending and no work was released.",
        ),
        _ if !reason.is_empty()
            && reason.len() <= 80
            && reason
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_') =>
        {
            format!(
                "Manage refused the approval with reason `{reason}`. The gate remains pending and no work was released."
            )
        }
        _ => String::from(
            "Manage did not accept that approval. The gate remains pending and no work was released.",
        ),
    }
}

impl<P: SlackTicketPoster> SlackTicketRouter<P> {
    fn poll_ticket_notifications(&mut self) {
        let notifications = self.gates.lock().map_or_else(
            |_| Vec::new(),
            |gates| gates.pending_slack_notifications(MAX_SLACK_TICKET_STATUS_POLLS),
        );
        for notification in notifications {
            let Ok(status) = self.manage.ticket_status(&notification.job_id) else {
                continue;
            };
            let Some(text) = slack_ticket_terminal_text(&notification, &status) else {
                continue;
            };
            let claimed = self
                .gates
                .lock()
                .ok()
                .and_then(|mut gates| gates.claim_slack_notification(&notification.job_id).ok())
                .unwrap_or(false);
            if !claimed {
                continue;
            }
            let Ok(channel) = ChannelId::new(&notification.channel) else {
                continue;
            };
            let Ok(parent) = MessageTs::new(&notification.thread_ts) else {
                continue;
            };
            match self
                .poster
                .post_ticket_notification(&channel, &parent, &text)
            {
                SlackEffectOutcome::Accepted => {
                    let _ = self
                        .gates
                        .lock()
                        .map(|mut gates| gates.complete_slack_notification(&notification.job_id));
                }
                SlackEffectOutcome::Rejected => {
                    let _ = self
                        .gates
                        .lock()
                        .map(|mut gates| gates.retry_slack_notification(&notification.job_id));
                }
                SlackEffectOutcome::Ambiguous => {}
            }
        }
    }

    fn open_ticket_gate(
        &mut self,
        event: &SlackTicketEvent,
        issue_url: String,
        thread_context: &str,
    ) {
        if !self.features.contains(&SlackFeature::Approvals) {
            return;
        }
        match self.manage.dispatch_ticket(&issue_url, &event.source_key) {
            Ok(receipt) if !receipt.approved => {
                let (registered, tracked) =
                    self.gates.lock().ok().map_or((false, false), |mut gates| {
                        let registered = gates
                            .register(crate::telegram_bridge::PendingTicketGate {
                                job_id: receipt.job_id.clone(),
                                issue_url: issue_url.clone(),
                                source_key: receipt.source_key.clone(),
                            })
                            .is_ok();
                        let tracked = gates
                            .register_slack_job(
                                &event.team_id,
                                event.channel.as_str(),
                                event.parent.as_str(),
                                event.user.as_str(),
                                &receipt.job_id,
                                &issue_url,
                            )
                            .is_ok();
                        // The thread that asked is the one context the
                        // approved job cannot get from GitHub. Best effort:
                        // the gate opens whether or not this sidecar wrote.
                        if tracked && let Some(state_dir) = gates.state_dir() {
                            let _ = crate::work_brief::record_ticket_thread_context(
                                &state_dir,
                                &receipt.job_id,
                                &issue_url,
                                thread_context,
                            );
                        }
                        (registered, tracked)
                    });
                if !registered {
                    let _ = self.poster.post_thread(
                        &event.channel,
                        &event.parent,
                        "The ticket is pending in Manage, but Monique could not retain its cross-channel confirmation coordinates. Confirm it in Manage; no work has been released.",
                    );
                    return;
                }
                if !tracked {
                    let _ = self.poster.post_thread(
                        &event.channel,
                        &event.parent,
                        "The ticket is pending in Manage, but Monique could not retain this thread's progress binding. Use `/monique status <job-id>` for status after confirmation.",
                    );
                }
                if self.interactive_decisions {
                    let _ = self.poster.post_approval_card(
                        &event.channel,
                        &event.parent,
                        &receipt,
                        self.manage_url.as_ref(),
                    );
                } else {
                    let short = receipt.job_id.get(..12).unwrap_or(&receipt.job_id);
                    let _ = self.poster.post_thread(
                        &event.channel,
                        &event.parent,
                        &format!(
                            "🔐 Confirmation required for `{}`\n{}\nMonique job `{short}` is pending approval. A configured Slack admin can reply `confirm {short}`; the same request can also be confirmed in Telegram or Manage. No work starts before confirmation.",
                            receipt.issue_title, receipt.issue_url
                        ),
                    );
                }
            }
            Ok(_) => {
                let _ = self.poster.post_thread(
                    &event.channel,
                    &event.parent,
                    "Manage returned an already-approved job to an unconfirmed Slack intake. The gate contract was violated; check Manage immediately.",
                );
            }
            Err(_) => {
                let _ = self.poster.post_thread(
                    &event.channel,
                    &event.parent,
                    "Manage could not create the pending ticket confirmation, so no work was released.",
                );
            }
        }
    }

    fn handle_monique_command(&mut self, command: SlackMoniqueCommand, context: &str) {
        self.poster.begin_source(&command.source_key);
        if !self.features.contains(&SlackFeature::Commands) {
            return;
        }
        let text = command.text.trim();
        match natural_issue_request(text) {
            Ok(Some(GitHubIssueRequestIntent::Read { issue_url, deep })) => {
                let answer = self.question_answerer.as_mut().map_or_else(
                    || String::from("Monique's GitHub issue reader is unavailable right now."),
                    |answerer| answerer.issue_review(&issue_url, text, context, deep),
                );
                let _ = self.poster.post_channel(&command.channel, &answer);
                return;
            }
            Ok(Some(GitHubIssueRequestIntent::Work { .. }) | None) => {}
            Err(answer) => {
                let _ = self.poster.post_channel(&command.channel, &answer);
                return;
            }
        }
        let ticket_text = text.strip_prefix("ticket ").unwrap_or(text);
        if let Ok(Some(issue_url)) = one_issue_url(ticket_text) {
            match self.manage.dispatch_ticket(&issue_url, &command.source_key) {
                Ok(receipt) if !receipt.approved => {
                    let registered = self.gates.lock().ok().is_some_and(|mut gates| {
                        gates
                            .register(crate::telegram_bridge::PendingTicketGate {
                                job_id: receipt.job_id.clone(),
                                issue_url: issue_url.clone(),
                                source_key: receipt.source_key.clone(),
                            })
                            .is_ok()
                    });
                    let reply = if registered {
                        format!(
                            "🔐 Confirmation required for {}\n{}\nMonique job `{}` is pending approval. Use `/monique approve {}` or `/monique reject {} <reason>`, or decide in Manage.",
                            receipt.issue_title,
                            receipt.issue_url,
                            receipt.job_id.get(..12).unwrap_or(&receipt.job_id),
                            receipt.job_id.get(..12).unwrap_or(&receipt.job_id),
                            receipt.job_id.get(..12).unwrap_or(&receipt.job_id),
                        )
                    } else {
                        String::from(
                            "Manage created the pending gate, but Monique could not retain its coordinates. Decide it in Manage; no work was released.",
                        )
                    };
                    let _ = self.poster.post_channel(&command.channel, &reply);
                }
                Ok(_) => {
                    let _ = self.poster.post_channel(
                        &command.channel,
                        "Manage returned an already-approved job to unconfirmed Slack intake; no new action was taken.",
                    );
                }
                Err(_) => {
                    let _ = self.poster.post_channel(
                        &command.channel,
                        "Manage could not create a pending confirmation, so no work was released.",
                    );
                }
            }
            return;
        }
        if !self.members.contains(&command.user) {
            let _ = self.poster.post_channel(
                &command.channel,
                "Only a configured Monique member can use this command. Posting one GitHub issue URL in the intake channel remains available to channel members.",
            );
            return;
        }
        if text.is_empty() || text == "help" {
            let _ = self.poster.post_channel(
                &command.channel,
                "Monique commands: `ticket <GitHub issue URL>`, `agents`, `help`. Admins can also use `approvals` to list what is waiting, `approve <reference>`, `reject <job> <reason>`, `status <job>`, and natural-language GitHub actions. Legacy `/github_*` commands remain available during migration.",
            );
            return;
        }
        if text == "agents" {
            let answer = self.question_answerer.as_mut().map_or_else(
                || {
                    String::from(
                        "Monique's provider instance statistics are unavailable right now.",
                    )
                },
                |answerer| answerer.provider_stats(),
            );
            let _ = self.poster.post_channel(&command.channel, &answer);
            return;
        }
        let is_admin = self.admins.contains(&command.user);
        if text == "approvals" {
            if !is_admin {
                let _ = self.poster.post_channel(
                    &command.channel,
                    "Only a configured Slack administrator can list approvals.",
                );
                return;
            }
            self.post_pending_approvals(&command);
            return;
        }
        // An `apr-` reference is a durable approval proposal on this daemon's
        // own lane, and it is answered before the ticket ladder below: that
        // ladder resolves references by *prefix* against a live gate registry,
        // so a reference from the other lane fed to it could match a ticket
        // nobody meant. The grammar is what keeps the two apart.
        for (prefix, granted) in [("approve ", true), ("reject ", false)] {
            let Some(rest) = text.strip_prefix(prefix) else {
                continue;
            };
            let reference = rest.split_whitespace().next().unwrap_or_default();
            if !reference.starts_with(APPROVAL_REFERENCE_PREFIX) {
                continue;
            }
            if !is_admin {
                let _ = self.poster.post_channel(
                    &command.channel,
                    "Only a configured Slack administrator can decide an approval.",
                );
                return;
            }
            self.decide_approval(&command, reference, granted);
            return;
        }
        if let Some(reference) = text.strip_prefix("approve ") {
            if !is_admin {
                let _ = self.poster.post_channel(
                    &command.channel,
                    "Only a configured Slack administrator can approve tickets.",
                );
                return;
            }
            let matches = self
                .gates
                .lock()
                .map(|gates| gates.matching(reference.trim()))
                .unwrap_or_default();
            let [pending] = matches.as_slice() else {
                let _ = self.poster.post_channel(
                    &command.channel,
                    "No unique pending ticket matches that job reference.",
                );
                return;
            };
            let result = crate::telegram_bridge::confirm_bound_ticket(
                self.manage.as_mut(),
                &pending.job_id,
                &pending.issue_url,
                &pending.source_key,
            );
            let reply = match result {
                Ok(receipt) if receipt.approved => {
                    let _ = self
                        .gates
                        .lock()
                        .map(|mut gates| gates.resolve(&pending.job_id));
                    format!(
                        "✅ Confirmed by <@{}>. Monique job `{}` is {}.",
                        command.user,
                        receipt.job_id.get(..12).unwrap_or(&receipt.job_id),
                        receipt.job_status.as_str()
                    )
                }
                Err(reason) => ticket_approval_failure(&reason),
                Ok(_) => String::from("Manage kept that ticket pending, so no work was released."),
            };
            let _ = self.poster.post_channel(&command.channel, &reply);
            return;
        }
        if let Some(rest) = text.strip_prefix("reject ") {
            if !is_admin {
                let _ = self.poster.post_channel(
                    &command.channel,
                    "Only a configured Slack administrator can reject tickets.",
                );
                return;
            }
            let Some((reference, reason)) = rest.trim().split_once(char::is_whitespace) else {
                let _ = self.poster.post_channel(
                    &command.channel,
                    "A rejection reason is required: `/monique reject <job> <reason>`.",
                );
                return;
            };
            let Ok(decision) = TicketDecision::reject(reason) else {
                let _ = self.poster.post_channel(
                    &command.channel,
                    "The rejection reason is empty or too long.",
                );
                return;
            };
            let matches = self
                .gates
                .lock()
                .map(|gates| gates.matching(reference))
                .unwrap_or_default();
            let [pending] = matches.as_slice() else {
                let _ = self.poster.post_channel(
                    &command.channel,
                    "No unique pending ticket matches that job reference.",
                );
                return;
            };
            let actor_key = format!("slack:{}:{}", command.team_id, command.user);
            let result = crate::telegram_bridge::decide_bound_ticket(
                self.manage.as_mut(),
                &pending.job_id,
                &pending.issue_url,
                &pending.source_key,
                &command.source_key,
                &actor_key,
                decision,
            );
            let reply = match result {
                Ok(receipt) if receipt.decision == TicketDecisionOutcome::Rejected => {
                    let _ = self
                        .gates
                        .lock()
                        .map(|mut gates| gates.resolve(&pending.job_id));
                    format!(
                        "⛔ Rejected by <@{}>. Monique job `{}` was cancelled.",
                        command.user,
                        receipt.job_id.get(..12).unwrap_or(&receipt.job_id)
                    )
                }
                _ => {
                    String::from("Manage did not accept that rejection; the gate remains pending.")
                }
            };
            let _ = self.poster.post_channel(&command.channel, &reply);
            return;
        }
        if let Some(reference) = text.strip_prefix("status ") {
            if !is_admin {
                let _ = self.poster.post_channel(
                    &command.channel,
                    "Ticket status for members remains in the originating thread.",
                );
                return;
            }
            let matches = self
                .gates
                .lock()
                .map(|gates| gates.matching(reference.trim()))
                .unwrap_or_default();
            let job_id = matches
                .first()
                .map_or(reference.trim(), |gate| gate.job_id.as_str());
            let reply = self.manage.ticket_status(job_id).map_or_else(
                |_| String::from("Manage could not read that job status."),
                |status| {
                    format!(
                        "Monique job `{}` is {}.\n{}",
                        status.job_id.get(..12).unwrap_or(&status.job_id),
                        status.job_status.as_str(),
                        status.result.trim()
                    )
                },
            );
            let _ = self.poster.post_channel(&command.channel, &reply);
            return;
        }
        if is_admin && let Some(actions) = self.github_actions.as_ref() {
            match actions.natural_request(text) {
                Ok(Some(request)) => {
                    let result = self.github_actions.as_mut().expect("checked").execute(
                        &command.source_key,
                        request,
                        context,
                    );
                    let _ = self.poster.post_channel(&command.channel, &result.text);
                    return;
                }
                Ok(None) => {}
                Err(reply) => {
                    let _ = self.poster.post_channel(&command.channel, &reply);
                    return;
                }
            }
        }
        let _ = self.poster.post_channel(&command.channel, "I could not map that `/monique` request to an enabled Slack capability. Use `/monique help`." );
    }

    /// Answer one pressed approval button.
    ///
    /// # Idempotency is the daemon's fence, not a Slack journal
    ///
    /// The ticket lane journals every interaction before acknowledging, because
    /// Socket Mode redelivers and a second `decide_ticket` would be a second
    /// call to another service. This lane needs no journal: a redelivered press
    /// makes the same `Daemon::record_decision` call, and that call is
    /// exactly-once by a fenced `UPDATE` over a write-once ledger. The second
    /// press finds the decision and is told so. Widening the ticket journal's
    /// `CHECK` constraints to hold rows for a lane that does not need them
    /// would be schema churn buying nothing.
    ///
    /// # A press by somebody who may not decide
    ///
    /// Ignored, exactly as the ticket lane ignores one: `prepare_interaction`
    /// answers `Ok(None)` and nothing is posted. This connector has no
    /// ephemeral method, and adding one to tell an unauthorized presser that
    /// they are unauthorized would be a new outbound effect for a message the
    /// four-way gate already makes harmless.
    fn handle_approval_interaction(&mut self, interaction: SlackApprovalInteraction) {
        if !self.may_decide(&interaction.user, &interaction.channel) {
            return;
        }
        let decider = format!("slack:{}:{}", interaction.team_id, interaction.user);
        let Some(lane) = self.approval_lane.as_mut() else {
            return;
        };
        let decided = lane.decide_approval(&interaction.request_key, interaction.granted, &decider);
        // The card is rewritten whatever the answer was. A press that found the
        // proposal already decided, or expired, is a press whose buttons are
        // stale, and a live-looking control that does nothing is worse than a
        // wrong one.
        let text = match decided {
            Ok(answer) => {
                let verb = match (answer, interaction.granted) {
                    (ApprovalDecisionAnswer::Recorded, true) => "✅ Approved",
                    (ApprovalDecisionAnswer::Recorded, false) => "⛔ Denied",
                    (ApprovalDecisionAnswer::AlreadyRecorded, true) => "✅ Already approved",
                    (ApprovalDecisionAnswer::AlreadyRecorded, false) => "⛔ Already denied",
                };
                format!(
                    "{verb} by <@{}>. Reference `{}`.",
                    interaction.user, interaction.request_key
                )
            }
            Err(failure) => failure.operator_reply().to_owned(),
        };
        // A failed rewrite does not roll anything back: the decision is durable
        // and the card is a view of it.
        let _ = self
            .poster
            .update_decision(&interaction.channel, &interaction.message_ts, &text);
    }

    fn handle_tool_interaction(&mut self, interaction: SlackToolInteraction) {
        if !self.may_decide(&interaction.user, &interaction.channel) {
            return;
        }
        // An approved deep lookup runs for minutes; the card says so at once
        // so the buttons do not look ignored, and is rewritten with the
        // result when it lands.
        if interaction.granted {
            let _ = self.poster.update_decision(
                &interaction.channel,
                &interaction.message_ts,
                "✅ Approved. Running now; the result replaces this card.",
            );
        }
        let text = self.question_answerer.as_mut().map_or_else(
            || String::from("Monique's conversational tool surface is unavailable right now."),
            |answerer| {
                answerer.decide_tool(&interaction.key, interaction.granted, &interaction.channel)
            },
        );
        let _ = self
            .poster
            .update_decision(&interaction.channel, &interaction.message_ts, &text);
    }

    /// Whether one presser may decide an approval in one channel.
    ///
    /// The same four gates `prepare_interaction` applies, in the same order,
    /// because a button is not a different authority from a modal: the
    /// workspace enables interactive decisions, the approvals capability is
    /// present, the presser is on the configured admin list, and the press came
    /// from a channel this deployment configured. Any one of them failing is
    /// the same answer, and it is a silent one.
    fn may_decide(&self, user: &UserId, channel: &ChannelId) -> bool {
        self.interactive_decisions
            && self.features.contains(&SlackFeature::Approvals)
            && self.admins.contains(user)
            && self.channels.0.iter().any(|(_, known)| known == channel)
    }

    /// Post one card per proposal an administrator could decide right now.
    ///
    /// Read straight off the durable table rather than from anything this
    /// worker remembers, so a card is a view of what is actually pending and a
    /// restart loses nothing.
    fn post_pending_approvals(&mut self, command: &SlackMoniqueCommand) {
        let Some(approvals) = self.approvals.as_ref() else {
            let _ = self.poster.post_channel(
                &command.channel,
                "The approval table would not answer, so nothing is listed.",
            );
            return;
        };
        let pending = approvals.pending(MAX_LISTED_APPROVALS).unwrap_or_default();
        if pending.is_empty() {
            let _ = self
                .poster
                .post_channel(&command.channel, "No approval is waiting.");
            return;
        }
        for record in pending {
            debug_assert_eq!(record.state, ApprovalState::Pending);
            if self
                .poster
                .post_approval_request(&command.channel, &record.request_key, record.expires_at_ms)
                .is_err()
            {
                let _ = self.poster.post_channel(
                    &command.channel,
                    "Slack refused an approval card, so the list is incomplete.",
                );
                return;
            }
        }
    }

    /// Record one Slack administrator's decision on one durable proposal.
    ///
    /// Dials this daemon's own socket, exactly as the Telegram bridge does, so
    /// both surfaces reach the one `Daemon::record_decision` rather than two
    /// implementations that agree today. The decider is the admin-allowlisted
    /// actor this router admitted; nothing is read from the command text but
    /// the reference itself.
    fn decide_approval(&mut self, command: &SlackMoniqueCommand, reference: &str, granted: bool) {
        let decider = format!("slack:{}:{}", command.team_id, command.user);
        let Some(lane) = self.approval_lane.as_mut() else {
            let _ = self.poster.post_channel(
                &command.channel,
                ApprovalDecisionFailure::Unavailable.operator_reply(),
            );
            return;
        };
        let reply = match lane.decide_approval(reference, granted, &decider) {
            Ok(answer) => {
                let verb = match (answer, granted) {
                    (ApprovalDecisionAnswer::Recorded, true) => "✅ Approved",
                    (ApprovalDecisionAnswer::Recorded, false) => "⛔ Denied",
                    (ApprovalDecisionAnswer::AlreadyRecorded, true) => "✅ Already approved",
                    (ApprovalDecisionAnswer::AlreadyRecorded, false) => "⛔ Already denied",
                };
                format!("{verb} by <@{}>. Reference `{reference}`.", command.user)
            }
            Err(failure) => failure.operator_reply().to_owned(),
        };
        let _ = self.poster.post_channel(&command.channel, &reply);
    }

    fn handle_app_home(&mut self, user: &UserId) {
        if !self.features.contains(&SlackFeature::AppHome) || !self.members.contains(user) {
            return;
        }
        let pending_count = self
            .gates
            .lock()
            .map(|gates| gates.len())
            .unwrap_or_default();
        let _ = self
            .poster
            .publish_home(user, self.admins.contains(user), pending_count);
    }

    fn prepare_interaction(
        &self,
        interaction: SlackTicketInteraction,
        store: &mut SlackInteractionStore,
    ) -> Result<Option<PreparedSlackTicketInteraction>, ()> {
        if !self.interactive_decisions
            || !self.features.contains(&SlackFeature::Approvals)
            || !self.admins.contains(&interaction.user)
            || !self
                .channels
                .0
                .iter()
                .any(|(_, channel)| channel == &interaction.channel)
        {
            return Ok(None);
        }
        let gate = self
            .gates
            .lock()
            .map_err(|_| ())?
            .matching(&interaction.job_id)
            .into_iter()
            .find(|gate| gate.job_id == interaction.job_id)
            .ok_or(())?;
        let actor_key = format!("slack:{}:{}", interaction.team_id, interaction.user);
        let action = match interaction.kind {
            SlackTicketInteractionKind::Approve => SlackInteractionAction::Approve,
            SlackTicketInteractionKind::RejectOpen { .. }
            | SlackTicketInteractionKind::RejectSubmit { .. } => SlackInteractionAction::Reject,
        };
        let (record, _) = store
            .record(&SlackInteractionInput {
                interaction_key: &interaction.interaction_key,
                job_id: &gate.job_id,
                ticket_source_key: &gate.source_key,
                actor_key: &actor_key,
                action,
                channel_id: interaction.channel.as_str(),
                message_ts: interaction.message_ts.as_str(),
                recorded_at_ms: crate::unix_millis().unwrap_or_default(),
            })
            .map_err(|_| ())?;
        Ok(Some(PreparedSlackTicketInteraction {
            interaction,
            gate,
            record,
        }))
    }

    fn handle_interaction(
        &mut self,
        prepared: PreparedSlackTicketInteraction,
        store: &mut SlackInteractionStore,
    ) {
        let PreparedSlackTicketInteraction {
            interaction,
            gate,
            record,
        } = prepared;
        if record.state != SlackInteractionState::Recorded {
            return;
        }
        let now = crate::unix_millis().unwrap_or_default();
        if let SlackTicketInteractionKind::RejectOpen { trigger_id } = &interaction.kind {
            let state = if self
                .poster
                .open_reject_modal(
                    trigger_id,
                    &gate.job_id,
                    &interaction.channel,
                    &interaction.message_ts,
                )
                .is_ok()
            {
                SlackInteractionState::Applied
            } else {
                SlackInteractionState::Failed
            };
            let _ = store.resolve(&record.interaction_key, record.revision, state, now);
            return;
        }
        let decision = match &interaction.kind {
            SlackTicketInteractionKind::Approve => TicketDecision::Approve,
            SlackTicketInteractionKind::RejectSubmit { reason } => {
                let Ok(decision) = TicketDecision::reject(reason) else {
                    return;
                };
                decision
            }
            SlackTicketInteractionKind::RejectOpen { .. } => return,
        };
        let expected = match &decision {
            TicketDecision::Approve => TicketDecisionOutcome::Approved,
            TicketDecision::Reject { .. } => TicketDecisionOutcome::Rejected,
        };
        let actor_key = format!("slack:{}:{}", interaction.team_id, interaction.user);
        let decision_result = crate::telegram_bridge::decide_bound_ticket(
            self.manage.as_mut(),
            &gate.job_id,
            &gate.issue_url,
            &gate.source_key,
            &interaction.interaction_key,
            &actor_key,
            decision,
        );
        let (accepted, failure_reason) = match decision_result {
            Ok(receipt) if receipt.job_id == gate.job_id && receipt.decision == expected => {
                (Some(receipt), None)
            }
            Ok(_) => (None, Some(String::from("decision_receipt_mismatch"))),
            Err(reason) => (None, Some(reason)),
        };
        let state = if let Some(receipt) = accepted {
            let _ = self
                .gates
                .lock()
                .map(|mut gates| gates.resolve(&gate.job_id));
            let text = match receipt.decision {
                TicketDecisionOutcome::Approved => format!(
                    "✅ Confirmed by <@{}>. Monique job `{}` is {}.",
                    interaction.user,
                    receipt.job_id.get(..12).unwrap_or(&receipt.job_id),
                    receipt.job_status.as_str()
                ),
                TicketDecisionOutcome::Rejected => format!(
                    "⛔ Rejected by <@{}>. Monique job `{}` was cancelled.",
                    interaction.user,
                    receipt.job_id.get(..12).unwrap_or(&receipt.job_id)
                ),
            };
            let _ =
                self.poster
                    .update_decision(&interaction.channel, &interaction.message_ts, &text);
            SlackInteractionState::Applied
        } else {
            let short = gate.job_id.get(..12).unwrap_or(&gate.job_id);
            let reason = failure_reason.as_deref().unwrap_or("decision_not_applied");
            let text = format!(
                "⚠️ Approval failed. {}\nMonique job `{short}` remains pending. Retry with `/monique approve {short}` after the reported blocker is fixed.",
                ticket_approval_failure(reason)
            );
            let _ =
                self.poster
                    .update_decision(&interaction.channel, &interaction.message_ts, &text);
            SlackInteractionState::Failed
        };
        let _ = store.resolve(&record.interaction_key, record.revision, state, now);
    }

    fn capture_memory(
        &self,
        memory: &mut AgentMemoryStore,
        event: &SlackTicketEvent,
    ) -> Result<(), ()> {
        if !self.members.contains(&event.user)
            || !self
                .channels
                .0
                .iter()
                .any(|(_, channel)| channel == &event.channel)
            // The mention copy of the same post is the one that is stored;
            // storing both made every Slack question appear twice in the
            // transcript the router reads.
            || slack_plain_copy_of_bot_mention(event)
        {
            return Ok(());
        }
        let identity = memory
            .resolve_identity(
                "slack",
                "automonique-slack",
                &event.team_id,
                event.user.as_str(),
            )
            .map_err(|_| ())?;
        let (tenant, actor) = identity.unwrap_or_else(|| {
            (
                self.memory_tenant.clone(),
                format!("slack:{}:{}", event.team_id, event.user),
            )
        });
        memory
            .bind_identity(
                &tenant,
                &actor,
                ExternalIdentity {
                    platform: "slack",
                    application: "automonique-slack",
                    external_tenant: &event.team_id,
                    external_user: event.user.as_str(),
                },
                crate::unix_millis().unwrap_or_default(),
            )
            .map_err(|_| ())?;
        // Derived rather than formatted here: this is byte-identical to the
        // scope this bridge has always written, and going through the store's
        // versioned producer is what keeps it that way as the grammar grows.
        let external_scope =
            ConversationScope::slack(event.channel.as_str(), Some(event.parent.as_str()))
                .map_err(|_| ())?;
        let external_scope = external_scope.as_str();
        let conversation_id = memory
            .current_conversation(&tenant, &actor, "slack", external_scope)
            .map_err(|_| ())?
            .unwrap_or_else(|| slack_event_conversation_id(event, event.app_mention));
        let content = redact_content(&event.text);
        memory
            .record_message(&MessageInput {
                tenant: &tenant,
                actor: &actor,
                conversation_id: &conversation_id,
                transport: "slack",
                external_scope,
                transport_key: &event.source_key,
                role: "user",
                content: &content,
                created_at_ms: crate::unix_millis().unwrap_or_default(),
            })
            .map(|_| ())
            .map_err(|_| ())
    }

    fn capture_confirmed_reply(
        &self,
        memory: &mut AgentMemoryStore,
        event: &SlackTicketEvent,
        reply: &ConfirmedSlackThreadReply,
    ) -> Result<(), ()> {
        if reply.source_key != event.source_key
            || reply.channel != event.channel
            || reply.parent != event.parent
            || !self.members.contains(&event.user)
        {
            return Ok(());
        }
        let identity = memory
            .resolve_identity(
                "slack",
                "automonique-slack",
                &event.team_id,
                event.user.as_str(),
            )
            .map_err(|_| ())?;
        let (tenant, actor) = identity.unwrap_or_else(|| {
            (
                self.memory_tenant.clone(),
                format!("slack:{}:{}", event.team_id, event.user),
            )
        });
        memory
            .bind_identity(
                &tenant,
                &actor,
                ExternalIdentity {
                    platform: "slack",
                    application: "automonique-slack",
                    external_tenant: &event.team_id,
                    external_user: event.user.as_str(),
                },
                crate::unix_millis().unwrap_or_default(),
            )
            .map_err(|_| ())?;
        let scope = ConversationScope::slack(reply.channel.as_str(), Some(reply.parent.as_str()))
            .map_err(|_| ())?;
        let conversation_id = memory
            .current_conversation(&tenant, &actor, "slack", scope.as_str())
            .map_err(|_| ())?
            .unwrap_or_else(|| slack_event_conversation_id(event, event.app_mention));
        let content = redact_content(&reply.text);
        memory
            .record_message(&MessageInput {
                tenant: &tenant,
                actor: &actor,
                conversation_id: &conversation_id,
                transport: "slack-assistant",
                external_scope: scope.as_str(),
                transport_key: &reply.source_key,
                role: "assistant",
                content: &content,
                created_at_ms: crate::unix_millis().unwrap_or_default(),
            })
            .map(|_| ())
            .map_err(|_| ())
    }

    /// Decide whether an unmentioned thread reply belongs to a conversation
    /// Monique already opened. New conversations carry an explicit durable
    /// identifier. The content check recognizes conversations opened by the
    /// immediately preceding release, which stored app mentions under the old
    /// neutral identifier.
    fn conversation_follow_up(
        &self,
        memory: &AgentMemoryStore,
        event: &SlackTicketEvent,
    ) -> Result<bool, ()> {
        if !event.in_thread
            || !self.members.contains(&event.user)
            || !self
                .channels
                .0
                .iter()
                .any(|(_, channel)| channel == &event.channel)
        {
            return Ok(false);
        }
        let identity = memory
            .resolve_identity(
                "slack",
                "automonique-slack",
                &event.team_id,
                event.user.as_str(),
            )
            .map_err(|_| ())?;
        let (tenant, actor) = identity.unwrap_or_else(|| {
            (
                self.memory_tenant.clone(),
                format!("slack:{}:{}", event.team_id, event.user),
            )
        });
        let scope = ConversationScope::slack(event.channel.as_str(), Some(event.parent.as_str()))
            .map_err(|_| ())?;
        let Some(conversation_id) = memory
            .current_conversation(&tenant, &actor, "slack", scope.as_str())
            .map_err(|_| ())?
        else {
            return Ok(false);
        };
        if conversation_id.starts_with("slack-monique:") {
            return Ok(true);
        }
        let prior_messages = memory
            .recent_messages(
                &tenant,
                &actor,
                &conversation_id,
                crate::unix_millis().unwrap_or_default(),
                20,
            )
            .map_err(|_| ())?;
        Ok(prior_messages
            .iter()
            .any(|message| message.content.contains("<@")))
    }

    fn capture_command_memory(
        &self,
        memory: &mut AgentMemoryStore,
        command: &SlackGitHubCommand,
    ) -> Result<(), ()> {
        let identity = memory
            .resolve_identity(
                "slack",
                "automonique-slack",
                &command.team_id,
                command.user.as_str(),
            )
            .map_err(|_| ())?;
        let (tenant, actor) = identity.unwrap_or_else(|| {
            (
                self.memory_tenant.clone(),
                format!("slack:{}:{}", command.team_id, command.user),
            )
        });
        memory
            .bind_identity(
                &tenant,
                &actor,
                ExternalIdentity {
                    platform: "slack",
                    application: "automonique-slack",
                    external_tenant: &command.team_id,
                    external_user: command.user.as_str(),
                },
                crate::unix_millis().unwrap_or_default(),
            )
            .map_err(|_| ())?;
        let content = match &command.request {
            GitHubActionRequest::Create { instruction, .. }
            | GitHubActionRequest::Reply { instruction, .. }
            | GitHubActionRequest::Check { instruction, .. }
            | GitHubActionRequest::Manage { instruction, .. } => redact_content(instruction),
        };
        // A slash command is not a thread: it belongs to the channel's own
        // session, which is the unthreaded scope. The literal suffix stays
        // because it is a distinct session, not a thread coordinate.
        let channel_scope =
            ConversationScope::slack(command.channel.as_str(), None).map_err(|_| ())?;
        let external_scope = format!("{channel_scope}:github-command");
        let conversation_id = format!(
            "slack:{}:{}:github-command:{}",
            command.team_id, command.channel, command.user
        );
        memory
            .record_message(&MessageInput {
                tenant: &tenant,
                actor: &actor,
                conversation_id: &conversation_id,
                transport: "slack",
                external_scope: &external_scope,
                transport_key: &command.source_key,
                role: "user",
                content: &content,
                created_at_ms: crate::unix_millis().unwrap_or_default(),
            })
            .map(|_| ())
            .map_err(|_| ())
    }

    fn handle_github_command(&mut self, command: SlackGitHubCommand, context: &str) {
        self.poster.begin_source(&command.source_key);
        let result = self.github_actions.as_mut().map_or_else(
            || crate::github_actions::GitHubActionResult {
                text: String::from(
                    "GitHub actions are not configured on this daemon, so nothing changed.",
                ),
                successful: false,
            },
            |actions| actions.execute(&command.source_key, command.request, context),
        );
        let _ = self.poster.post_channel(&command.channel, &result.text);
    }

    fn execute_github_thread_action(
        &mut self,
        event: &SlackTicketEvent,
        request: GitHubActionRequest,
        context: &str,
    ) {
        let Some(actions) = self.github_actions.as_ref() else {
            let _ = self.poster.post_thread(
                &event.channel,
                &event.parent,
                "GitHub actions are not configured on this daemon, so nothing changed.",
            );
            return;
        };
        actions.set_slack_progress_target(Some(crate::run_lane::SlackProgressTarget {
            channel: event.channel.clone(),
            thread_ts: event.parent.clone(),
        }));
        let result = self
            .github_actions
            .as_mut()
            .expect("GitHub action surface checked above")
            .execute(&event.source_key, request, context);
        let blocks = slack_result_blocks(&result.text);
        let streamed = self
            .github_actions
            .as_ref()
            .expect("GitHub action surface checked above")
            .finish_slack_progress(&result.text, blocks);
        self.github_actions
            .as_ref()
            .expect("GitHub action surface checked above")
            .set_slack_progress_target(None);
        if !streamed {
            let _ = self
                .poster
                .post_thread(&event.channel, &event.parent, &result.text);
        }
    }

    fn handle_with_context(&mut self, event: SlackTicketEvent, context: &str) {
        // Every decision below belongs to this event. Establishing the
        // correlation here rather than in the socket loop means a recording
        // poster is correctly keyed however the router is driven — including
        // from the golden-trace replay, which has no socket loop.
        self.poster.begin_source(&event.source_key);
        if !self
            .channels
            .0
            .iter()
            .any(|(_, channel)| channel == &event.channel)
        {
            return;
        }
        // With both `message.channels` and `app_mention` enabled Slack emits a
        // general message copy and a dedicated mention copy for the same post.
        // Only the dedicated copy may route a message that mentions the bot;
        // otherwise one human post can dispatch or answer twice.
        if slack_plain_copy_of_bot_mention(&event) {
            return;
        }
        let mention_text = event.app_mention.then(|| {
            slack_app_mention_text(&event.text, event.bot_user.as_ref().map(UserId::as_str))
        });
        let trimmed = mention_text.as_deref().unwrap_or_else(|| event.text.trim());
        // A read-only issue review is safe in every admitted configured-channel
        // message shape, not only app mentions and existing conversations. In
        // particular, it must be intercepted before the plain ticket-intake
        // lane could mistake "review <issue>" for authorization to work it.
        if self.members.contains(&event.user) {
            if let Some(issue_url) = bare_issue_url(trimmed) {
                let answer = self.question_answerer.as_mut().map_or_else(
                    || String::from("Monique's GitHub issue reader is unavailable right now."),
                    |answerer| {
                        answerer.issue_review(
                            &issue_url,
                            "Summarize this GitHub issue briefly in the language of its content and report its current state. Do not ask what to do next: a separate Slack confirmation card follows. Do not claim work has started before that card is approved.",
                            context,
                            true,
                        )
                    },
                );
                let _ = self
                    .poster
                    .post_thread(&event.channel, &event.parent, &answer);
                // A bare link is also the intake gesture on Slack: prepare the
                // durable gate and render its native confirmation controls.
                // The gate remains pending, so the summary itself never starts
                // work and the user needs no follow-up just to request tools.
                self.open_ticket_gate(&event, issue_url, context);
                return;
            }
            if is_github_issue_status_question(trimmed)
                && let Ok(Some(issue_url)) = one_issue_url(trimmed)
            {
                let answer = self.question_answerer.as_mut().map_or_else(
                    || String::from("Monique's GitHub issue reader is unavailable right now."),
                    |answerer| answerer.issue_status(&issue_url),
                );
                let _ = self
                    .poster
                    .post_thread(&event.channel, &event.parent, &answer);
                return;
            }
            match natural_issue_request(trimmed) {
                Ok(Some(GitHubIssueRequestIntent::Read { issue_url, deep })) => {
                    let answer = self.question_answerer.as_mut().map_or_else(
                        || String::from("Monique's GitHub issue reader is unavailable right now."),
                        |answerer| answerer.issue_review(&issue_url, trimmed, context, deep),
                    );
                    let _ = self
                        .poster
                        .post_thread(&event.channel, &event.parent, &answer);
                    return;
                }
                Ok(Some(GitHubIssueRequestIntent::Work { .. }) | None) => {}
                Err(text) => {
                    let _ = self
                        .poster
                        .post_thread(&event.channel, &event.parent, &text);
                    return;
                }
            }
        }
        let conversational = self.features.contains(&SlackFeature::Conversation)
            && self.members.contains(&event.user)
            && (event.app_mention
                || event.continues_conversation
                || event.channel.as_str().starts_with('D'));
        let mut contextual_work_url = None;
        if conversational {
            if is_github_capability_question(trimmed) {
                let text = if self.github_actions.is_some() {
                    "Yes. I can create GitHub issues, reply to them, and check or uncheck checklist items in configured repositories."
                } else {
                    "GitHub actions are not configured on this daemon, so I can only read configured issues here."
                };
                let _ = self.poster.post_thread(&event.channel, &event.parent, text);
                return;
            }
            if is_provider_stats_question(trimmed) {
                let answer = self.question_answerer.as_mut().map_or_else(
                    || {
                        String::from(
                            "Monique's provider instance statistics are unavailable right now.",
                        )
                    },
                    |answerer| answerer.provider_stats(),
                );
                let _ = self
                    .poster
                    .post_thread(&event.channel, &event.parent, &answer);
                return;
            }
            if is_channel_ticket_audit_question(trimmed) {
                let answer = self.question_answerer.as_mut().map_or_else(
                    || String::from("Monique's Slack ticket auditor is unavailable right now."),
                    |answerer| answerer.channel_ticket_audit(&event.channel),
                );
                let _ = self
                    .poster
                    .post_thread(&event.channel, &event.parent, &answer);
                return;
            }
            if is_ticket_job_progress_question(trimmed) {
                let issue_url = one_issue_url(trimmed).ok().flatten();
                let matches = self.gates.lock().map_or_else(
                    |_| Vec::new(),
                    |gates| {
                        gates.matching_slack_jobs(
                            &event.team_id,
                            event.channel.as_str(),
                            event.parent.as_str(),
                            issue_url.as_deref(),
                        )
                    },
                );
                let answer = match matches.as_slice() {
                    [binding] => self.manage.ticket_status(&binding.job_id).map_or_else(
                        |_| {
                            String::from(
                                "Manage could not read that Monique job's status right now.",
                            )
                        },
                        |status| slack_ticket_status_text(&status),
                    ),
                    [] => String::from(
                        "No Monique job is bound to this Slack thread. Use `/monique status <job-id>` if the job was created before thread tracking was enabled.",
                    ),
                    _ => String::from(
                        "More than one Monique job is bound to this thread. Include the exact GitHub issue URL or use `/monique status <job-id>`.",
                    ),
                };
                let _ = self
                    .poster
                    .post_thread(&event.channel, &event.parent, &answer);
                return;
            }
            if let Some(issue_url) = contextual_github_issue_review(trimmed, context) {
                let answer = self.question_answerer.as_mut().map_or_else(
                    || String::from("Monique's GitHub issue reader is unavailable right now."),
                    |answerer| answerer.issue_review(&issue_url, trimmed, context, true),
                );
                let _ = self
                    .poster
                    .post_thread(&event.channel, &event.parent, &answer);
                return;
            }
            contextual_work_url = contextual_github_issue_work(trimmed, context);
            if is_github_issue_status_question(trimmed)
                && let Ok(Some(issue_url)) = one_issue_url(trimmed)
            {
                let answer = self.question_answerer.as_mut().map_or_else(
                    || String::from("Monique's GitHub issue reader is unavailable right now."),
                    |answerer| answerer.issue_status(&issue_url),
                );
                let _ = self
                    .poster
                    .post_thread(&event.channel, &event.parent, &answer);
                return;
            }
            let issue_request = match natural_issue_request(trimmed) {
                Ok(intent) => intent,
                Err(text) => {
                    let _ = self
                        .poster
                        .post_thread(&event.channel, &event.parent, &text);
                    return;
                }
            };
            if let Some(GitHubIssueRequestIntent::Read { issue_url, deep }) = &issue_request {
                let answer = self.question_answerer.as_mut().map_or_else(
                    || String::from("Monique's GitHub issue reader is unavailable right now."),
                    |answerer| answerer.issue_review(issue_url, trimmed, context, *deep),
                );
                let _ = self
                    .poster
                    .post_thread(&event.channel, &event.parent, &answer);
                return;
            }
            let ticket_work_requested =
                matches!(issue_request, Some(GitHubIssueRequestIntent::Work { .. }));
            if !ticket_work_requested
                && self.admins.contains(&event.user)
                && let Some(actions) = self.github_actions.as_ref()
            {
                match actions.natural_request(trimmed) {
                    Ok(Some(request)) => {
                        self.execute_github_thread_action(&event, request, context);
                        return;
                    }
                    Ok(None) => {}
                    Err(text) => {
                        let _ = self
                            .poster
                            .post_thread(&event.channel, &event.parent, &text);
                        return;
                    }
                }
            }
        }
        if let Some(reference) = trimmed
            .strip_prefix("confirm ")
            .or_else(|| trimmed.strip_prefix("approve "))
        {
            if !self.features.contains(&SlackFeature::Approvals) {
                return;
            }
            self.confirm(&event, reference.trim());
            return;
        }
        let issue_url = match one_issue_url(trimmed) {
            Ok(Some(issue_url)) => issue_url,
            Ok(None) if contextual_work_url.is_some() => {
                contextual_work_url.expect("checked contextual work target")
            }
            Ok(None) => {
                if conversational {
                    let answer = self.question_answerer.as_mut().map_or_else(
                        || {
                            SlackQuestionReply::Text(String::from(
                                "Monique's conversational tool surface is unavailable right now.",
                            ))
                        },
                        |answerer| {
                            answerer.answer(
                                trimmed,
                                context,
                                &event.source_key,
                                &event.user,
                                &event.channel,
                                self.interactive_decisions
                                    && self.features.contains(&SlackFeature::Approvals)
                                    && self.admins.contains(&event.user),
                            )
                        },
                    );
                    match answer {
                        SlackQuestionReply::Text(answer) => {
                            let _ = self
                                .poster
                                .post_thread(&event.channel, &event.parent, &answer);
                        }
                        SlackQuestionReply::Approval { key, preview } => {
                            if self
                                .poster
                                .post_tool_approval_card(
                                    &event.channel,
                                    &event.parent,
                                    &key,
                                    &preview,
                                )
                                .is_err()
                            {
                                let _ = self.poster.post_thread(
                                    &event.channel,
                                    &event.parent,
                                    "Slack refused the tool approval controls, so nothing was executed.",
                                );
                            }
                        }
                        SlackQuestionReply::GitHubAction(request) => {
                            self.execute_github_thread_action(&event, request, context);
                        }
                    }
                }
                return;
            }
            Err(()) => {
                let _ = self.poster.post_thread(
                    &event.channel,
                    &event.parent,
                    "Monique found more than one GitHub issue URL. Post one ticket per message so each confirmation is exact.",
                );
                return;
            }
        };
        self.open_ticket_gate(&event, issue_url, context);
    }

    fn confirm(&mut self, event: &SlackTicketEvent, reference: &str) {
        if !self.admins.contains(&event.user) {
            let _ = self.poster.post_thread(
                &event.channel,
                &event.parent,
                "Only a configured Slack administrator can confirm this ticket.",
            );
            return;
        }
        let matches = self
            .gates
            .lock()
            .map(|gates| gates.matching(reference))
            .unwrap_or_default();
        let [pending] = matches.as_slice() else {
            let reply = if matches.is_empty() {
                "No pending ticket confirmation matches that reference."
            } else {
                "That reference is ambiguous; reply with the full Monique job id."
            };
            let _ = self
                .poster
                .post_thread(&event.channel, &event.parent, reply);
            return;
        };
        let result = crate::telegram_bridge::confirm_bound_ticket(
            self.manage.as_mut(),
            &pending.job_id,
            &pending.issue_url,
            &pending.source_key,
        );
        match result {
            Ok(receipt) if receipt.approved => {
                let _ = self
                    .gates
                    .lock()
                    .map(|mut gates| gates.resolve(&pending.job_id));
                let short = receipt.job_id.get(..12).unwrap_or(&receipt.job_id);
                let _ = self.poster.post_thread(
                    &event.channel,
                    &event.parent,
                    &format!(
                        "✅ Confirmed by <@{}>. Monique job `{short}` is {}.",
                        event.user,
                        receipt.job_status.as_str()
                    ),
                );
            }
            Ok(_) => {
                let _ = self.poster.post_thread(
                    &event.channel,
                    &event.parent,
                    "Manage kept the ticket pending, so no work was released.",
                );
            }
            Err(reason) => {
                let _ = self.poster.post_thread(
                    &event.channel,
                    &event.parent,
                    &ticket_approval_failure(&reason),
                );
            }
        }
    }
}

fn slack_result_blocks(text: &str) -> Option<MessageBlocks> {
    let value = serde_json::json!([{
        "type": "section",
        "text": {"type": "mrkdwn", "text": text}
    }]);
    MessageBlocks::new(&value.to_string()).ok()
}

/// Replay one Slack golden trace against the real router.
///
/// Builds the production [`SlackTicketRouter`] — not a stand-in for it — with
/// the shadow surfaces from [`crate::shadow`] and the workspace the trace
/// carries, feeds it the trace's inbound events, and answers with the envelope
/// stream it decided. Nothing here opens a socket, a database or a clock.
///
/// The GitHub action engine is deliberately absent: the router holds it over a
/// concrete lane type, so it cannot be replaced with the deterministic replay
/// lane. A trace that declares provider interactions for this scope is therefore
/// refused rather than replayed with those interactions silently ignored.
pub(crate) fn replay_slack_trace(
    trace: &crate::parity_trace::Trace,
) -> Result<
    Vec<automonique_protocol::parity::IntendedActionEnvelope>,
    crate::parity_trace::TraceError,
> {
    use crate::parity_trace::TraceError;

    let header = trace.header();
    if header.scope != SLACK_PARITY_SCOPE {
        return Err(TraceError::UnknownScope);
    }
    if !trace.provider_interactions().is_empty() {
        return Err(TraceError::ProviderInteractionUnconsumed);
    }
    let workspace = &header.workspace;
    let channel =
        ChannelId::new(&workspace.channel).map_err(|_| TraceError::Field("workspace.channel"))?;
    let identities = |values: &[String], field: &'static str| {
        values
            .iter()
            .map(|value| UserId::new(value).map_err(|_| TraceError::Field(field)))
            .collect::<Result<Vec<UserId>, TraceError>>()
    };
    let recorder = crate::parity_trace::replay_recorder(&header.scope);
    let mut router = SlackTicketRouter {
        poster: crate::shadow::ShadowPoster::new(recorder.clone()),
        manage: Box::new(crate::shadow::ShadowTicketSurface::new(recorder.clone())),
        manage_url: None,
        memory_tenant: String::from("replay"),
        channels: ChannelMap(vec![(
            ChannelName::new("replay").map_err(|_| TraceError::Field("workspace.channel"))?,
            channel.clone(),
        )]),
        admins: identities(&workspace.admins, "workspace.admins")?,
        members: identities(&workspace.members, "workspace.members")?,
        features: vec![
            SlackFeature::Approvals,
            SlackFeature::Conversation,
            SlackFeature::Commands,
        ],
        interactive_decisions: false,
        gates: Arc::new(std::sync::Mutex::new(
            crate::telegram_bridge::TicketGateRegistry::default(),
        )),
        github_actions: None,
        approvals: None,
        // The replay router reaches no daemon by construction: a parity replay
        // must not be able to decide anything.
        approval_lane: None,
        question_answerer: None,
    };
    for event in trace.events() {
        let source_key = format!("slack:{}:event:{}", workspace.team, event.event_id);
        if source_key.len() > automonique_support_connector::MAX_TICKET_SOURCE_KEY_BYTES {
            return Err(TraceError::Field("event_id"));
        }
        router.handle_with_context(
            SlackTicketEvent {
                team_id: workspace.team.clone(),
                channel: ChannelId::new(&event.channel)
                    .map_err(|_| TraceError::Field("event.channel"))?,
                user: UserId::new(&event.user).map_err(|_| TraceError::Field("event.user"))?,
                text: event.text.clone(),
                parent: MessageTs::new(&event.thread_ts)
                    .map_err(|_| TraceError::Field("event.thread_ts"))?,
                source_key,
                app_mention: event.app_mention,
                in_thread: true,
                continues_conversation: false,
                // Recorded traces carry no authorization envelope, so replay
                // takes the first-token fallback the recording behavior had.
                bot_user: None,
            },
            "",
        );
    }
    Ok(recorder.envelopes())
}

pub(crate) struct SlackTicketWorker {
    app: AppsConnectionsOpenClient,
    connector: SlackSocketModeConnector,
    router: SlackTicketRouter<LiveSlackTicketPoster>,
    memory: AgentMemoryStore,
    interactions: SlackInteractionStore,
    generation_canary: Option<SlackGenerationCanary>,
    last_ticket_status_poll: Option<Instant>,
    /// The reference engine's half of the parity comparison.
    ///
    /// `None` unless an installation configures an identity to observe. It
    /// records and never acts, so its presence cannot change what this worker
    /// does with an event.
    legacy: Option<LegacyObservation>,
}

/// The configured reference identity and the recorder that files its messages.
struct LegacyObservation {
    bot_user: String,
    observer: crate::shadow::LegacyObserver<crate::shadow::DurableSink>,
}

/// The parity scope this worker's decisions and observations are filed under.
const SLACK_PARITY_SCOPE: &str = "slack-ticket-routing";

/// Configured label for generation-health announcements.
const GENERATION_CANARY_CHANNEL: &str = "deploiements";

#[derive(Clone, Debug, Eq, PartialEq)]
struct SlackGenerationCanary {
    channel: ChannelId,
    generation: u64,
    queues_clean: bool,
}

/// Build the reference-engine observer, when an installation configures one.
///
/// Three outcomes, and they are deliberately distinct: no shadow configuration
/// at all is `Ok(None)`; a configuration that names no identity to observe is
/// also `Ok(None)`, because suppressing a scope and having something to compare
/// it against are independent choices; and a configuration that names one whose
/// recorder cannot open is a refusal.
fn legacy_observation(state_dir: &Path) -> Result<Option<LegacyObservation>, SlackConfigError> {
    let Some(config) = crate::shadow_config::ShadowConfig::load(state_dir)
        .map_err(SlackConfigError::ShadowConfig)?
    else {
        return Ok(None);
    };
    let Some(bot_user) = config.legacy_bot_user() else {
        return Ok(None);
    };
    let store = automonique_store::shadow_comparisons::ShadowComparisonStore::open(
        crate::shadow_config::ShadowConfig::database_path(state_dir),
    )
    .map_err(|_| SlackConfigError::ShadowRecorderUnavailable)?;
    Ok(Some(LegacyObservation {
        bot_user: bot_user.to_owned(),
        observer: crate::shadow::LegacyObserver::new(
            SLACK_PARITY_SCOPE,
            crate::shadow::ShadowClock::Host,
            crate::shadow::DurableSink::new(store),
        ),
    }))
}

/// Prefix that tells a durable approval reference from a ticket reference.
///
/// Pinned by literal from `automonique_store::approval_requests::REQUEST_KEY_PREFIX`,
/// for the reason the Telegram surface pins it: a transport recognizing one
/// string is not a reason to depend on another crate's grammar.
const APPROVAL_REFERENCE_PREFIX: &str = "apr-";

/// Largest number of proposals one listing renders as cards.
///
/// Each card is a separate `chat.postMessage`, so an unbounded listing would
/// be an unbounded burst against somebody else's rate limit.
const MAX_LISTED_APPROVALS: usize = 8;

pub(crate) struct SlackTicketHostParams<'a> {
    pub state_dir: &'a Path,
    pub database_path: &'a Path,
    pub admin_socket: &'a Path,
    pub run_index_path: &'a Path,
    pub support_tickets_path: &'a Path,
    pub operator_members_path: &'a Path,
    pub host_facts: HostFacts,
    pub question_administrators: Vec<i64>,
    pub question_configured: Vec<i64>,
    pub generation_queues_clean: bool,
}

/// Socket Mode ticket-intake lifecycle, separate from Telegram's Slack read and
/// post surface so Slack works even when Telegram is disabled.
pub(crate) enum SlackTicketHost {
    Disabled,
    Configured {
        prepared: Option<Box<SlackTicketWorker>>,
        stop: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
        /// Whether this configuration can carry an approval decision at all.
        ///
        /// Captured here at open because the router moves onto the worker
        /// thread at `start`, and the approval policy has to be able to ask
        /// this question from the serve loop. It is the same conjunction
        /// `prepare_interaction` gates on — interactive decisions enabled *and*
        /// the approvals capability present — so the two cannot disagree about
        /// whether a button would be honoured.
        approvals_enabled: bool,
    },
}

impl SlackTicketHost {
    pub fn open(
        params: &SlackTicketHostParams<'_>,
        gates: Arc<std::sync::Mutex<crate::telegram_bridge::TicketGateRegistry>>,
    ) -> Result<Self, SlackConfigError> {
        let SlackTicketHostParams {
            state_dir,
            database_path,
            admin_socket,
            run_index_path,
            support_tickets_path,
            operator_members_path,
            host_facts,
            question_administrators,
            question_configured,
            generation_queues_clean,
        } = params;
        let Some(config) = SlackConfig::load(state_dir)? else {
            return Ok(Self::Disabled);
        };
        let SlackConfig {
            token,
            app_token,
            channels,
            admins,
            members,
            features,
            interactive_decisions,
        } = config;
        let Some(app_token) = app_token else {
            return Ok(Self::Disabled);
        };
        let approvals_enabled =
            interactive_decisions && features.contains(&SlackFeature::Approvals);
        let generation_canary = ChannelName::new(GENERATION_CANARY_CHANNEL)
            .ok()
            .and_then(|name| channels.resolve(&name).cloned())
            .map(|channel| SlackGenerationCanary {
                channel,
                generation: host_facts.lease_epoch,
                queues_clean: *generation_queues_clean,
            });
        let manage = crate::ticket_intake::FleetConfig::load(state_dir)
            .map_err(|_| SlackConfigError::TicketActionsUnavailable)?
            .ok_or(SlackConfigError::TicketActionsUnavailable)?
            .into_action_client();
        let manage_config = crate::manage_config::ManageConfig::load(state_dir)
            .map_err(SlackConfigError::ManageConfig)?;
        let manage_url = manage_config
            .as_ref()
            .and_then(|config| config.url().cloned());
        let memory_tenant = crate::memory_config::MemoryConfig::tenant_or_default(state_dir)
            .map_err(SlackConfigError::MemoryConfig)?;
        let github_reader = crate::github::GitHubHost::load(state_dir)
            .map_err(|_| SlackConfigError::GitHubActionsUnavailable)?
            .into_surface();
        let github_actions = match crate::github::GitHubHost::load(state_dir)
            .map_err(|_| SlackConfigError::GitHubActionsUnavailable)?
            .into_action_surface()
        {
            Some(surface) => {
                let lane = SocketRunLane::open(state_dir, admin_socket, run_index_path)
                    .map_err(|_| SlackConfigError::GitHubActionsUnavailable)?;
                Some(GitHubActionEngine::new(
                    Arc::new(std::sync::Mutex::new(lane)),
                    surface,
                ))
            }
            None => None,
        };
        let github_action_aliases = github_actions
            .as_ref()
            .map(GitHubActionEngine::repository_aliases)
            .unwrap_or_default();
        let client = Arc::new(SlackClient::new(SlackBase::production(), token));
        let question_answerer = if features.contains(&SlackFeature::Conversation) {
            let surface = StoreControlSurface::open_with_lease_time_source(
                database_path,
                run_index_path,
                host_facts.clone(),
                Arc::new(crate::lease_time::BootTimeSource),
            )
            .map_err(|_| SlackConfigError::QuestionSurfaceUnavailable)?
            .with_support_tickets(support_tickets_path)
            .with_operator_members(operator_members_path)
            .with_prism_sites(Path::new(crate::site_inventory::NGINX_SITES_ENABLED))
            .with_local_knowledge(&crate::local_knowledge::catalog_path(state_dir))
            .with_provider_state(state_dir);
            let surface = match manage_config
                .as_ref()
                .and_then(crate::manage_config::ManageConfig::profile_app)
            {
                Some(profile) => surface.with_manage_profiles(profile.clone()),
                None => surface,
            };
            let lane = SocketRunLane::open(state_dir, admin_socket, run_index_path)
                .map_err(|_| SlackConfigError::QuestionSurfaceUnavailable)?;
            Some(Box::new(LiveSlackQuestionAnswerer {
                surface,
                lane,
                github: github_reader,
                slack_reader: SlackHost::open(state_dir)
                    .map_err(|_| SlackConfigError::QuestionSurfaceUnavailable)?
                    .into_surface(),
                administrators: question_administrators.clone(),
                configured: question_configured.clone(),
                api: Arc::clone(&client),
                channels: channels.clone(),
                members: members.clone(),
                mcp: McpRegistry::load(state_dir)
                    .map_err(|_| SlackConfigError::QuestionSurfaceUnavailable)?,
                github_action_aliases,
                pending_tools: BTreeMap::new(),
                roster: None,
            }) as Box<dyn SlackQuestionAnswerer>)
        } else {
            None
        };
        let legacy = legacy_observation(state_dir)?;
        Ok(Self::Configured {
            prepared: Some(Box::new(SlackTicketWorker {
                legacy,
                app: AppsConnectionsOpenClient::new(app_token),
                connector: SlackSocketModeConnector::new(),
                memory: AgentMemoryStore::open(state_dir.join("agent-memory.sqlite3"))
                    .map_err(|_| SlackConfigError::TicketActionsUnavailable)?,
                interactions: SlackInteractionStore::open(
                    state_dir.join("slack-ticket-interactions.sqlite3"),
                )
                .map_err(|_| SlackConfigError::TicketActionsUnavailable)?,
                generation_canary,
                last_ticket_status_poll: None,
                router: SlackTicketRouter {
                    poster: LiveSlackTicketPoster::new(client),
                    manage: Box::new(manage),
                    manage_url,
                    memory_tenant,
                    channels,
                    admins,
                    members,
                    features,
                    interactive_decisions,
                    gates,
                    github_actions,
                    approvals: ApprovalRequests::open(
                        state_dir.join(crate::APPROVAL_REQUESTS_NAME),
                    )
                    .ok(),
                    approval_lane: SocketRunLane::open(state_dir, admin_socket, run_index_path)
                        .ok(),
                    question_answerer,
                },
            })),
            stop: Arc::new(AtomicBool::new(false)),
            worker: None,
            approvals_enabled,
        })
    }

    /// Attach the execution lane's live progress before Socket Mode starts.
    pub(crate) fn attach_progress(&mut self, hub: Arc<ProgressHub>) {
        let Self::Configured { prepared, .. } = self else {
            return;
        };
        let Some(worker) = prepared.as_mut() else {
            return;
        };
        let Some(actions) = worker.router.github_actions.as_ref() else {
            return;
        };
        let now_ms = crate::unix_millis().unwrap_or_default();
        let budget = Arc::new(Mutex::new(SlackCallBudget::new(now_ms)));
        let sink = SlackStreamSink::new(worker.router.poster.client(), budget);
        actions.attach_slack_progress(hub, Box::new(sink));
    }

    /// Whether a Slack operator could decide an approval right now.
    ///
    /// Three things must hold together, and the answer is evidence rather than
    /// configuration: the workspace enables interactive decisions, the
    /// approvals capability is present, and the Socket Mode worker is actually
    /// running. A worker that ended took the connection with it, so a finished
    /// handle reports the surface as gone rather than as configured.
    pub(crate) fn approvals_live(&self) -> bool {
        match self {
            Self::Disabled => false,
            Self::Configured {
                worker,
                approvals_enabled,
                ..
            } => *approvals_enabled && worker.as_ref().is_some_and(|handle| !handle.is_finished()),
        }
    }

    pub fn start(&mut self) -> Result<(), SlackConfigError> {
        let Self::Configured {
            prepared,
            stop,
            worker,
            ..
        } = self
        else {
            return Ok(());
        };
        let Some(mut prepared) = prepared.take() else {
            return Ok(());
        };
        let stop = Arc::clone(stop);
        *worker = Some(
            std::thread::Builder::new()
                .name(String::from("automonique-slack-tickets"))
                .spawn(move || run_slack_ticket_worker(&mut prepared, &stop))
                .map_err(|_| SlackConfigError::TicketActionsUnavailable)?,
        );
        Ok(())
    }

    pub fn shutdown(&mut self) {
        let Self::Configured { stop, worker, .. } = self else {
            return;
        };
        stop.store(true, Ordering::Release);
        if let Some(worker) = worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for SlackTicketHost {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn run_slack_ticket_worker(worker: &mut SlackTicketWorker, stop: &AtomicBool) {
    while !stop.load(Ordering::Acquire) {
        let url = match worker.app.open() {
            Ok(SlackOutcome::Accepted(url)) => url,
            Ok(SlackOutcome::Rejected(_)) | Err(_) => {
                slack_backoff(stop);
                continue;
            }
        };
        let Ok(mut connection) = worker.connector.connect(&url) else {
            slack_backoff(stop);
            continue;
        };
        while !stop.load(Ordering::Acquire) {
            let envelope = match slack_receive_disposition(connection.receive_envelope()) {
                SlackReceiveDisposition::Envelope(envelope) => envelope,
                // The connector's bounded read timeout is also the worker's
                // shutdown cadence. Silence is not a failed Socket Mode
                // connection: keep the established websocket and check the
                // stop flag again instead of churning apps.connections.open.
                SlackReceiveDisposition::Idle => {
                    poll_slack_ticket_notifications(worker);
                    continue;
                }
                SlackReceiveDisposition::Reconnect => break,
            };
            let envelope_id = match socket_envelope_id(envelope.as_str()) {
                Some(envelope_id) => envelope_id,
                None if socket_hello(envelope.as_str()) => {
                    post_generation_canary(worker);
                    continue;
                }
                None => break,
            };
            let mut event = slack_ticket_event(envelope.as_str());
            let app_home_user = match slack_app_home_user(envelope.as_str()) {
                Ok(user) => user,
                Err(()) => break,
            };
            let interaction = match slack_ticket_interaction(envelope.as_str()) {
                Ok(interaction) => interaction,
                Err(()) => break,
            };
            let prepared_interaction = match interaction {
                Some(interaction) => match worker
                    .router
                    .prepare_interaction(interaction, &mut worker.interactions)
                {
                    Ok(prepared) => prepared,
                    Err(()) => break,
                },
                None => None,
            };
            // Parsed before the acknowledgement, like every other admitted
            // shape on this envelope, so a payload this build cannot read
            // breaks the connection rather than being acknowledged and
            // dropped.
            let approval = match slack_approval_interaction(envelope.as_str()) {
                Ok(approval) => approval,
                Err(()) => break,
            };
            let tool_interaction = match slack_tool_interaction(envelope.as_str()) {
                Ok(interaction) => interaction,
                Err(()) => break,
            };
            let command = match slack_github_command(
                envelope.as_str(),
                &worker.router.channels,
                &worker.router.admins,
            ) {
                Ok(command) => command,
                Err(()) => break,
            };
            let command = if worker.router.features.contains(&SlackFeature::Commands) {
                command
            } else {
                None
            };
            let monique_command =
                match slack_monique_command(envelope.as_str(), &worker.router.channels) {
                    Ok(command) => command,
                    Err(()) => break,
                };
            if event.as_mut().is_some_and(|event| {
                let Ok(continues) = worker.router.conversation_follow_up(&worker.memory, event)
                else {
                    return true;
                };
                event.continues_conversation = continues;
                worker
                    .router
                    .capture_memory(&mut worker.memory, event)
                    .is_err()
            }) {
                break;
            }
            if command.as_ref().is_some_and(|command| {
                worker
                    .router
                    .capture_command_memory(&mut worker.memory, command)
                    .is_err()
            }) {
                break;
            }
            if connection.acknowledge(&envelope_id).is_err() {
                break;
            }
            // The parity tap, upstream of the router and of the bot_id filter
            // that would otherwise have dropped the reference engine's own
            // messages. It records; it cannot route, reply or mutate anything.
            if let Some(legacy) = worker.legacy.as_mut() {
                if let Some(event) = event.as_ref() {
                    legacy.observer.correlate(
                        &event.channel.to_string(),
                        &event.parent.to_string(),
                        &event.source_key,
                    );
                }
                if let Some(message) = slack_legacy_bot_message(envelope.as_str(), &legacy.bot_user)
                {
                    legacy.observer.observe(&message);
                }
            }
            if let Some(event) = event {
                let context =
                    slack_event_context(&worker.memory, &worker.router.memory_tenant, &event);
                worker.router.handle_with_context(event.clone(), &context);
                while let Some(reply) = worker.router.poster.take_confirmed_thread_reply() {
                    if worker
                        .router
                        .capture_confirmed_reply(&mut worker.memory, &event, &reply)
                        .is_err()
                    {
                        break;
                    }
                }
            }
            if let Some(command) = command {
                let context =
                    slack_command_context(&worker.memory, &worker.router.memory_tenant, &command);
                worker.router.handle_github_command(command, &context);
            }
            if let Some(interaction) = prepared_interaction {
                worker
                    .router
                    .handle_interaction(interaction, &mut worker.interactions);
            }
            if let Some(approval) = approval {
                worker.router.handle_approval_interaction(approval);
            }
            if let Some(interaction) = tool_interaction {
                worker.router.handle_tool_interaction(interaction);
            }
            if let Some(user) = app_home_user {
                worker.router.handle_app_home(&user);
            }
            if let Some(command) = monique_command {
                worker.router.handle_monique_command(command, "");
            }
            poll_slack_ticket_notifications(worker);
        }
    }
}

fn poll_slack_ticket_notifications(worker: &mut SlackTicketWorker) {
    let now = Instant::now();
    if worker
        .last_ticket_status_poll
        .is_some_and(|last| now.duration_since(last) < SLACK_TICKET_STATUS_POLL)
    {
        return;
    }
    worker.last_ticket_status_poll = Some(now);
    worker.router.poll_ticket_notifications();
}

fn generation_canary_message(
    canary: &mut Option<SlackGenerationCanary>,
) -> Option<(ChannelId, String)> {
    let canary = canary.take()?;
    let (marker, queue_state) = if canary.queues_clean {
        (":white_check_mark:", "queues clean")
    } else {
        (":warning:", "queues not clean")
    };
    Some((
        canary.channel,
        format!(
            "{marker} Monique generation {} canary: Slack connected; {queue_state}.",
            canary.generation
        ),
    ))
}

fn post_generation_canary(worker: &mut SlackTicketWorker) {
    let Some((channel, text)) = generation_canary_message(&mut worker.generation_canary) else {
        return;
    };
    // Consume the canary before the network call. A lost response is
    // ambiguous, so retrying on this process's next Socket Mode hello could
    // duplicate an announcement that Slack already accepted.
    let _ = worker.router.poster.post_channel(&channel, &text);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlackReceiveDisposition<T> {
    Envelope(T),
    Idle,
    Reconnect,
}

fn slack_receive_disposition<T>(
    result: Result<T, SocketModeFailure>,
) -> SlackReceiveDisposition<T> {
    match result {
        Ok(envelope) => SlackReceiveDisposition::Envelope(envelope),
        Err(SocketModeFailure::TimedOut) => SlackReceiveDisposition::Idle,
        Err(_) => SlackReceiveDisposition::Reconnect,
    }
}

fn slack_event_context(
    memory: &AgentMemoryStore,
    default_tenant: &str,
    event: &SlackTicketEvent,
) -> String {
    let (tenant, actor) = memory
        .resolve_identity(
            "slack",
            "automonique-slack",
            &event.team_id,
            event.user.as_str(),
        )
        .ok()
        .flatten()
        .unwrap_or_else(|| {
            (
                String::from(default_tenant),
                format!("slack:{}:{}", event.team_id, event.user),
            )
        });
    let scope = ConversationScope::slack(event.channel.as_str(), Some(event.parent.as_str())).ok();
    let conversation_id = scope
        .as_ref()
        .and_then(|scope| {
            memory
                .current_conversation(&tenant, &actor, "slack", scope.as_str())
                .ok()
                .flatten()
        })
        .unwrap_or_else(|| slack_event_conversation_id(event, event.app_mention));
    recent_slack_context(memory, &tenant, &actor, &conversation_id)
}

fn slack_event_conversation_id(event: &SlackTicketEvent, monique: bool) -> String {
    let prefix = if monique { "slack-monique" } else { "slack" };
    format!(
        "{prefix}:{}:{}:{}:{}",
        event.team_id, event.channel, event.parent, event.user
    )
}

fn slack_command_context(
    memory: &AgentMemoryStore,
    default_tenant: &str,
    command: &SlackGitHubCommand,
) -> String {
    let (tenant, actor) = memory
        .resolve_identity(
            "slack",
            "automonique-slack",
            &command.team_id,
            command.user.as_str(),
        )
        .ok()
        .flatten()
        .unwrap_or_else(|| {
            (
                String::from(default_tenant),
                format!("slack:{}:{}", command.team_id, command.user),
            )
        });
    let conversation_id = format!(
        "slack:{}:{}:github-command:{}",
        command.team_id, command.channel, command.user
    );
    recent_slack_context(memory, &tenant, &actor, &conversation_id)
}

fn recent_slack_context(
    memory: &AgentMemoryStore,
    tenant: &str,
    actor: &str,
    conversation_id: &str,
) -> String {
    let memories = memory
        .active_for_actor(tenant, actor, crate::unix_millis().unwrap_or_default())
        .unwrap_or_default()
        .into_iter()
        .map(|memory| format!("{}: {}", memory.kind.as_str(), memory.content))
        .collect::<Vec<_>>()
        .join("\n");
    let Ok(messages) = memory.recent_messages(
        tenant,
        actor,
        conversation_id,
        crate::unix_millis().unwrap_or_default(),
        20,
    ) else {
        return String::new();
    };
    let messages = messages
        .into_iter()
        .map(|message| format!("{}: {}", message.role, message.content))
        .collect::<Vec<_>>()
        .join("\n");
    let context = if memories.is_empty() {
        messages
    } else if messages.is_empty() {
        format!("[reviewed memory]\n{memories}")
    } else {
        format!("[reviewed memory]\n{memories}\n\n[recent conversation]\n{messages}")
    };
    if context.len() <= 8 * 1024 {
        return context;
    }
    let mut start = context.len() - 8 * 1024;
    while !context.is_char_boundary(start) {
        start += 1;
    }
    format!("[…truncated]\n{}", &context[start..])
}

fn slack_backoff(stop: &AtomicBool) {
    for _ in 0..10 {
        if stop.load(Ordering::Acquire) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
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

/// Markdown lines one appended task-card chunk may carry.
///
/// Slack's own limit is on the message, not on an append; this bound is on how
/// much one drain turns into, so a burst of frames becomes one readable chunk
/// rather than a wall.
pub const MAX_TASK_CARD_LINES: usize = 16;

/// One native Slack stream chunk rendered from normalized progress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskCardChunk {
    Markdown(String),
    Task {
        id: String,
        title: String,
        status: &'static str,
    },
}

/// One Slack thread's view of a run in progress, folded from the same frames.
///
/// # Why this is a different fold from Telegram's
///
/// Because the two surfaces mean different things by an update. A Telegram
/// draft is *replaced*, so its renderer keeps the latest snapshot; a Slack
/// stream is *appended to*, so this one emits the lines that are new since the
/// last drain and never repeats one. Sharing a fold between them would have
/// forced one of the two to redraw what its reader had already seen.
///
#[derive(Clone, Debug, Default)]
pub struct RunTaskCard {
    cursor: u64,
    /// The last assistant text emitted, so an unchanged snapshot is not
    /// appended a second time.
    last_text: Option<String>,
    task_ids: BTreeMap<String, String>,
}

impl RunTaskCard {
    /// Start a card that has seen nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The highest frame sequence this card has folded in.
    #[must_use]
    pub const fn cursor(&self) -> u64 {
        self.cursor
    }

    /// Fold frames in and answer with the markdown lines that are new.
    ///
    /// Empty means there is nothing a reader has not already seen, which is a
    /// reason to append nothing rather than to append an empty chunk.
    pub fn absorb(&mut self, frames: &[ProgressFrame]) -> Vec<String> {
        self.absorb_chunks(frames)
            .into_iter()
            .map(|chunk| match chunk {
                TaskCardChunk::Markdown(text) => text,
                TaskCardChunk::Task { title, status, .. } => {
                    let display = if status == "complete" {
                        "completed"
                    } else {
                        status
                    };
                    format!("• {title} _{display}_")
                }
            })
            .collect()
    }

    /// Fold frames into Slack's typed markdown and task-update chunks.
    pub fn absorb_chunks(&mut self, frames: &[ProgressFrame]) -> Vec<TaskCardChunk> {
        let mut chunks = Vec::new();
        for frame in frames {
            if frame.sequence() <= self.cursor {
                continue;
            }
            self.cursor = frame.sequence();
            if let Some(chunk) = self.chunk_for(frame) {
                chunks.push(chunk);
            }
        }
        // Oldest first, and the newest kept: a chunk that had to be cut is
        // better cut at the end a reader has already scrolled past.
        while chunks.len() > MAX_TASK_CARD_LINES {
            chunks.remove(0);
        }
        chunks
    }

    /// Fold whatever a live hub has retained past this card's cursor.
    pub fn poll(&mut self, hub: &ProgressHub, run_id: &str) -> Vec<String> {
        let frames = hub.frames_after(run_id, self.cursor);
        self.absorb(&frames)
    }

    fn chunk_for(&mut self, frame: &ProgressFrame) -> Option<TaskCardChunk> {
        let text = frame.body().text().map(|text| text.as_str().to_owned());
        match frame.kind() {
            EventKind::AssistantMessageDelta | EventKind::AssistantMessageCompleted => {
                let text = text?;
                // A coalesced preview carries the message *so far*, so two in a
                // row differ by a suffix; appending the whole thing twice would
                // show the reader the same sentence again.
                if self.last_text.as_deref() == Some(text.as_str()) {
                    return None;
                }
                self.last_text = Some(text.clone());
                Some(TaskCardChunk::Markdown(text))
            }
            EventKind::ProviderWarning | EventKind::ProviderFault => {
                Some(TaskCardChunk::Markdown(format!(
                    ":warning: {}",
                    text.unwrap_or_else(|| frame.kind().as_str().to_owned())
                )))
            }
            // The thinking step, drawn from the status the frame carries rather
            // than from which kind arrived.
            kind => {
                let status = frame.body().step()?;
                let label = text.unwrap_or_else(|| kind.as_str().to_owned());
                let label = if label.len() > 256 {
                    bounded_field(&label, 253)
                } else {
                    label
                };
                let id = self
                    .task_ids
                    .entry(label.clone())
                    .or_insert_with(|| format!("task-{}", frame.sequence()))
                    .clone();
                let status = match status.as_str() {
                    "completed" => "complete",
                    other => other,
                };
                Some(TaskCardChunk::Task {
                    id,
                    title: label,
                    status,
                })
            }
        }
    }
}

enum ActiveSlackProgress {
    None,
    Native { channel: ChannelId, ts: MessageTs },
    Fallback { channel: ChannelId, ts: MessageTs },
}

trait SlackStreamApi: Send + Sync {
    fn start(
        &self,
        request: &StartStreamRequest,
    ) -> Result<SlackOutcome<StreamMessage>, SlackFailure>;
    fn append(
        &self,
        request: &AppendStreamRequest,
    ) -> Result<SlackOutcome<StreamMessage>, SlackFailure>;
    fn stop(
        &self,
        request: &StopStreamRequest,
    ) -> Result<SlackOutcome<StreamMessage>, SlackFailure>;
    fn post(
        &self,
        request: &PostMessageRequest,
    ) -> Result<SlackOutcome<StreamMessage>, SlackFailure>;
    fn update(&self, request: &UpdateMessageRequest) -> Result<SlackOutcome<()>, SlackFailure>;
}

impl SlackStreamApi for SlackClient {
    fn start(
        &self,
        request: &StartStreamRequest,
    ) -> Result<SlackOutcome<StreamMessage>, SlackFailure> {
        self.start_stream(request)
    }

    fn append(
        &self,
        request: &AppendStreamRequest,
    ) -> Result<SlackOutcome<StreamMessage>, SlackFailure> {
        self.append_stream(request)
    }

    fn stop(
        &self,
        request: &StopStreamRequest,
    ) -> Result<SlackOutcome<StreamMessage>, SlackFailure> {
        self.stop_stream(request)
    }

    fn post(
        &self,
        request: &PostMessageRequest,
    ) -> Result<SlackOutcome<StreamMessage>, SlackFailure> {
        Ok(match self.post_message(request)? {
            SlackOutcome::Accepted(message) => SlackOutcome::Accepted(StreamMessage {
                channel: message.channel,
                ts: message.ts,
            }),
            SlackOutcome::Rejected(rejection) => SlackOutcome::Rejected(rejection),
        })
    }

    fn update(&self, request: &UpdateMessageRequest) -> Result<SlackOutcome<()>, SlackFailure> {
        self.update_message(request)
    }
}

/// Native Slack streaming with one process-lifetime fallback latch.
pub struct SlackStreamSink {
    client: Arc<dyn SlackStreamApi>,
    budget: Arc<Mutex<SlackCallBudget>>,
    unsupported: bool,
    active: ActiveSlackProgress,
    card: RunTaskCard,
    fallback_text: String,
    last_fallback_edit_ms: Option<i64>,
}

impl SlackStreamSink {
    #[must_use]
    pub fn new(client: Arc<SlackClient>, budget: Arc<Mutex<SlackCallBudget>>) -> Self {
        Self::with_api(client, budget)
    }

    fn with_api(client: Arc<dyn SlackStreamApi>, budget: Arc<Mutex<SlackCallBudget>>) -> Self {
        Self {
            client,
            budget,
            unsupported: false,
            active: ActiveSlackProgress::None,
            card: RunTaskCard::new(),
            fallback_text: String::new(),
            last_fallback_edit_ms: None,
        }
    }

    #[must_use]
    pub const fn streaming_unsupported(&self) -> bool {
        self.unsupported
    }

    fn claim(
        &self,
        method: SlackBudgetedMethod,
        channel: &ChannelId,
        priority: CallPriority,
        now_ms: i64,
    ) -> bool {
        self.budget.lock().ok().is_some_and(|mut budget| {
            budget
                .claim(method, Some(channel.as_str()), priority, now_ms)
                .is_ok()
        })
    }

    fn note_rejection(&self, method: SlackBudgetedMethod, rejection: &SlackRejection, now_ms: i64) {
        if rejection.kind() != SlackErrorKind::RateLimited {
            return;
        }
        let retry_ms = u64::from(rejection.retry_after_seconds().unwrap_or(1)) * 1_000;
        if let Ok(mut budget) = self.budget.lock() {
            budget.note_rate_limited(method, retry_ms, now_ms);
        }
    }

    fn fallback_begin(&mut self, target: &SlackProgressTarget, now_ms: i64) -> bool {
        if !self.claim(
            SlackBudgetedMethod::ChatPostMessage,
            &target.channel,
            CallPriority::Ephemeral,
            now_ms,
        ) {
            return false;
        }
        let Ok(text) = MessageText::new("Thinking…") else {
            return false;
        };
        let request = PostMessageRequest::new(target.channel.clone(), text)
            .in_thread(target.thread_ts.clone());
        match self.client.post(&request) {
            Ok(SlackOutcome::Accepted(message)) => {
                self.active = ActiveSlackProgress::Fallback {
                    channel: message.channel,
                    ts: message.ts,
                };
                self.fallback_text = String::from("Thinking…");
                self.last_fallback_edit_ms = Some(now_ms);
                true
            }
            Ok(SlackOutcome::Rejected(rejection)) => {
                self.note_rejection(SlackBudgetedMethod::ChatPostMessage, &rejection, now_ms);
                false
            }
            Err(_) => false,
        }
    }

    fn append_native(&mut self, chunks: Vec<TaskCardChunk>, now_ms: i64) {
        let ActiveSlackProgress::Native { channel, ts } = &self.active else {
            return;
        };
        let mut retained = chunks;
        let (markdown, chunks) = loop {
            let markdown = retained
                .iter()
                .map(|chunk| match chunk {
                    TaskCardChunk::Markdown(text) => text.clone(),
                    TaskCardChunk::Task { title, status, .. } => {
                        format!("• {title} _{status}_")
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            let values: Vec<serde_json::Value> = retained
                .iter()
                .map(|chunk| match chunk {
                    TaskCardChunk::Markdown(text) => {
                        serde_json::json!({"type":"markdown_text","text":text})
                    }
                    TaskCardChunk::Task { id, title, status } => serde_json::json!({
                        "type":"task_update", "id":id, "title":title, "status":status
                    }),
                })
                .collect();
            if let (Ok(markdown), Ok(chunks)) = (
                StreamText::new(&markdown),
                StreamChunks::new(&serde_json::Value::Array(values).to_string()),
            ) {
                break (markdown, chunks);
            }
            if retained.len() <= 1 {
                return;
            }
            retained.remove(0);
        };
        let channel = channel.clone();
        let ts = ts.clone();
        if !self.claim(
            SlackBudgetedMethod::ChatAppendStream,
            &channel,
            CallPriority::Ephemeral,
            now_ms,
        ) {
            return;
        }
        let request = AppendStreamRequest::new(channel, ts, markdown).with_chunks(chunks);
        if let Ok(SlackOutcome::Rejected(rejection)) = self.client.append(&request) {
            self.note_rejection(SlackBudgetedMethod::ChatAppendStream, &rejection, now_ms);
        }
    }

    fn append_fallback(&mut self, chunks: Vec<TaskCardChunk>, now_ms: i64) {
        let ActiveSlackProgress::Fallback { channel, ts } = &self.active else {
            return;
        };
        for chunk in chunks {
            let line = match chunk {
                TaskCardChunk::Markdown(text) => text,
                TaskCardChunk::Task { title, status, .. } => format!("• {title} _{status}_"),
            };
            if self.fallback_text.len() + line.len()
                < automonique_slack_connector::MAX_MESSAGE_TEXT_BYTES
            {
                self.fallback_text.push('\n');
                self.fallback_text.push_str(&line);
            }
        }
        if self.last_fallback_edit_ms.is_some_and(|last| {
            now_ms.saturating_sub(last) < crate::run_lane::FALLBACK_EDIT_INTERVAL_MS
        }) {
            return;
        }
        let channel = channel.clone();
        let ts = ts.clone();
        if !self.claim(
            SlackBudgetedMethod::ChatUpdate,
            &channel,
            CallPriority::Ephemeral,
            now_ms,
        ) {
            return;
        }
        let Ok(text) = MessageText::new(&self.fallback_text) else {
            return;
        };
        let request = UpdateMessageRequest::new(channel, ts, text);
        match self.client.update(&request) {
            Ok(SlackOutcome::Accepted(())) => self.last_fallback_edit_ms = Some(now_ms),
            Ok(SlackOutcome::Rejected(rejection)) => {
                self.note_rejection(SlackBudgetedMethod::ChatUpdate, &rejection, now_ms);
            }
            Err(_) => {}
        }
    }
}

impl SlackProgressSink for SlackStreamSink {
    fn begin(&mut self, target: &SlackProgressTarget, now_ms: i64) -> bool {
        self.active = ActiveSlackProgress::None;
        self.card = RunTaskCard::new();
        self.fallback_text.clear();
        self.last_fallback_edit_ms = None;
        if self.unsupported {
            return self.fallback_begin(target, now_ms);
        }
        if !self.claim(
            SlackBudgetedMethod::ChatStartStream,
            &target.channel,
            CallPriority::Ephemeral,
            now_ms,
        ) {
            return false;
        }
        let request = StartStreamRequest::new(target.channel.clone(), target.thread_ts.clone())
            .with_markdown(StreamText::new("Thinking…").expect("fixed stream text"));
        match self.client.start(&request) {
            Ok(SlackOutcome::Accepted(message)) => {
                self.active = ActiveSlackProgress::Native {
                    channel: message.channel,
                    ts: message.ts,
                };
                true
            }
            Ok(SlackOutcome::Rejected(rejection)) => {
                self.note_rejection(SlackBudgetedMethod::ChatStartStream, &rejection, now_ms);
                if streaming_is_unsupported(&rejection) {
                    self.unsupported = true;
                    self.fallback_begin(target, now_ms)
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }

    fn progress(&mut self, _target: &SlackProgressTarget, frames: &[ProgressFrame], now_ms: i64) {
        let chunks = self.card.absorb_chunks(frames);
        if chunks.is_empty() {
            return;
        }
        match self.active {
            ActiveSlackProgress::Native { .. } => self.append_native(chunks, now_ms),
            ActiveSlackProgress::Fallback { .. } => self.append_fallback(chunks, now_ms),
            ActiveSlackProgress::None => {}
        }
    }

    fn finish(
        &mut self,
        _target: &SlackProgressTarget,
        text: &str,
        blocks: Option<MessageBlocks>,
        now_ms: i64,
    ) -> bool {
        match &self.active {
            ActiveSlackProgress::Native { channel, ts } => {
                let (channel, ts) = (channel.clone(), ts.clone());
                if !self.claim(
                    SlackBudgetedMethod::ChatStopStream,
                    &channel,
                    CallPriority::Durable,
                    now_ms,
                ) {
                    return false;
                }
                let Ok(markdown) = StreamText::new(text) else {
                    return false;
                };
                let mut request = StopStreamRequest::new(channel, ts, markdown);
                if let Some(blocks) = blocks {
                    request = request.with_blocks(blocks);
                }
                match self.client.stop(&request) {
                    Ok(SlackOutcome::Accepted(_)) => true,
                    Ok(SlackOutcome::Rejected(rejection)) => {
                        self.note_rejection(
                            SlackBudgetedMethod::ChatStopStream,
                            &rejection,
                            now_ms,
                        );
                        false
                    }
                    Err(_) => false,
                }
            }
            ActiveSlackProgress::Fallback { channel, ts } => {
                let (channel, ts) = (channel.clone(), ts.clone());
                if !self.claim(
                    SlackBudgetedMethod::ChatUpdate,
                    &channel,
                    CallPriority::Durable,
                    now_ms,
                ) {
                    return false;
                }
                let Ok(message) = MessageText::new(text) else {
                    return false;
                };
                let mut request = UpdateMessageRequest::new(channel, ts, message);
                if let Some(blocks) = blocks {
                    request = request.with_blocks(blocks);
                }
                match self.client.update(&request) {
                    Ok(SlackOutcome::Accepted(())) => true,
                    Ok(SlackOutcome::Rejected(rejection)) => {
                        self.note_rejection(SlackBudgetedMethod::ChatUpdate, &rejection, now_ms);
                        false
                    }
                    Err(_) => false,
                }
            }
            ActiveSlackProgress::None => false,
        }
    }
}

fn streaming_is_unsupported(rejection: &SlackRejection) -> bool {
    matches!(
        rejection.code().as_str(),
        "unknown_method"
            | "method_not_supported"
            | "feature_not_enabled"
            | "deprecated_endpoint"
            | "method_deprecated"
            | "not_allowed_token_type"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use automonique_slack_connector::{MessageTs, SlackErrorCode};

    const SECRET: &str = "xoxb-0000000000-fixture-secret-never-print";

    struct FakeStreamApi {
        calls: Mutex<Vec<&'static str>>,
        reject_start: bool,
    }

    impl FakeStreamApi {
        fn position() -> StreamMessage {
            StreamMessage {
                channel: ChannelId::new("C0RESERVED01").expect("channel"),
                ts: MessageTs::new("1723542300.000400").expect("ts"),
            }
        }
    }

    impl SlackStreamApi for FakeStreamApi {
        fn start(
            &self,
            _request: &StartStreamRequest,
        ) -> Result<SlackOutcome<StreamMessage>, SlackFailure> {
            self.calls.lock().expect("calls").push("start");
            if self.reject_start {
                Ok(SlackOutcome::Rejected(SlackRejection::new(
                    SlackErrorCode::sanitized("unknown_method"),
                    None,
                )))
            } else {
                Ok(SlackOutcome::Accepted(Self::position()))
            }
        }

        fn append(
            &self,
            request: &AppendStreamRequest,
        ) -> Result<SlackOutcome<StreamMessage>, SlackFailure> {
            self.calls
                .lock()
                .expect("calls")
                .push(if request.chunks().is_some() {
                    "append_chunks"
                } else {
                    "append"
                });
            Ok(SlackOutcome::Accepted(Self::position()))
        }

        fn stop(
            &self,
            request: &StopStreamRequest,
        ) -> Result<SlackOutcome<StreamMessage>, SlackFailure> {
            self.calls
                .lock()
                .expect("calls")
                .push(if request.blocks().is_some() {
                    "stop_blocks"
                } else {
                    "stop"
                });
            Ok(SlackOutcome::Accepted(Self::position()))
        }

        fn post(
            &self,
            _request: &PostMessageRequest,
        ) -> Result<SlackOutcome<StreamMessage>, SlackFailure> {
            self.calls.lock().expect("calls").push("post");
            Ok(SlackOutcome::Accepted(Self::position()))
        }

        fn update(
            &self,
            _request: &UpdateMessageRequest,
        ) -> Result<SlackOutcome<()>, SlackFailure> {
            self.calls.lock().expect("calls").push("update");
            Ok(SlackOutcome::Accepted(()))
        }
    }

    #[test]
    fn rejected_native_stream_latches_the_message_edit_fallback() {
        let api = Arc::new(FakeStreamApi {
            calls: Mutex::new(Vec::new()),
            reject_start: true,
        });
        let mut sink = SlackStreamSink::with_api(
            api.clone(),
            Arc::new(Mutex::new(SlackCallBudget::new(1_700_000_000_000))),
        );
        let target = SlackProgressTarget {
            channel: ChannelId::new("C0RESERVED01").expect("channel"),
            thread_ts: MessageTs::new("1723542000.000100").expect("thread"),
        };
        assert!(sink.begin(&target, 1_700_000_000_000));
        assert!(sink.streaming_unsupported());
        // A second run goes straight to postMessage; startStream is not probed
        // again after the process-lifetime latch has been set.
        assert!(sink.begin(&target, 1_700_000_000_001));
        assert!(sink.finish(
            &target,
            "Done",
            slack_result_blocks("Done"),
            1_700_000_000_002
        ));
        assert_eq!(
            *api.calls.lock().expect("calls"),
            vec!["start", "post", "post", "update"]
        );
    }

    #[test]
    fn native_stream_orders_task_chunks_before_final_blocks() {
        let api = Arc::new(FakeStreamApi {
            calls: Mutex::new(Vec::new()),
            reject_start: false,
        });
        let mut sink = SlackStreamSink::with_api(
            api.clone(),
            Arc::new(Mutex::new(SlackCallBudget::new(1_700_000_000_000))),
        );
        let target = SlackProgressTarget {
            channel: ChannelId::new("C0RESERVED01").expect("channel"),
            thread_ts: MessageTs::new("1723542000.000100").expect("thread"),
        };
        assert!(sink.begin(&target, 1_700_000_000_000));
        sink.append_native(
            vec![TaskCardChunk::Task {
                id: String::from("task-1"),
                title: String::from("read_file"),
                status: "in_progress",
            }],
            1_700_000_000_001,
        );
        assert!(sink.finish(
            &target,
            "Done",
            slack_result_blocks("Done"),
            1_700_000_000_002,
        ));
        assert_eq!(
            *api.calls.lock().expect("calls"),
            vec!["start", "append_chunks", "stop_blocks"]
        );
    }

    #[test]
    fn fallback_updates_wait_at_least_three_seconds() {
        const NOW: i64 = 1_700_000_000_000;
        let api = Arc::new(FakeStreamApi {
            calls: Mutex::new(Vec::new()),
            reject_start: true,
        });
        let mut sink =
            SlackStreamSink::with_api(api.clone(), Arc::new(Mutex::new(SlackCallBudget::new(NOW))));
        let target = SlackProgressTarget {
            channel: ChannelId::new("C0RESERVED01").expect("channel"),
            thread_ts: MessageTs::new("1723542000.000100").expect("thread"),
        };
        assert!(sink.begin(&target, NOW));
        let chunk = || vec![TaskCardChunk::Markdown(String::from("progress"))];
        sink.append_fallback(
            chunk(),
            NOW + crate::run_lane::FALLBACK_EDIT_INTERVAL_MS - 1,
        );
        assert_eq!(*api.calls.lock().expect("calls"), vec!["start", "post"]);
        sink.append_fallback(chunk(), NOW + crate::run_lane::FALLBACK_EDIT_INTERVAL_MS);
        assert_eq!(
            *api.calls.lock().expect("calls"),
            vec!["start", "post", "update"]
        );
    }

    fn config(lines: &[&str]) -> String {
        let mut text = vec![String::from(CONFIG_HEADER)];
        text.extend(lines.iter().map(|line| (*line).to_owned()));
        text.push(String::from(CONFIG_TERMINATOR));
        text.push(String::new());
        text.join("\n")
    }

    fn config_v2(lines: &[&str]) -> String {
        let mut text = vec![String::from(CONFIG_HEADER_V2)];
        text.extend(lines.iter().map(|line| (*line).to_owned()));
        text.push(String::from(CONFIG_TERMINATOR_V2));
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
            reply_users: None,
            reply_users_count: None,
            latest_reply: None,
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

    #[test]
    fn socket_mode_requires_an_explicit_admin_set_and_redacts_both_tokens() {
        let mut lines = complete();
        lines.push(String::from("app_token=xapp-fixture-secret"));
        assert_eq!(
            SlackConfig::parse(&config(&borrowed(&lines)))
                .expect_err("socket mode without admins")
                .category(),
            "slack_config_admin"
        );
        lines.push(String::from("admin=U0RESERVED1"));
        let parsed = SlackConfig::parse(&config(&borrowed(&lines)))
            .expect("ticket intake config")
            .expect("present");
        let rendered = format!("{parsed:?}");
        assert!(rendered.contains("enabled"));
        assert!(rendered.contains("admin_count: 1"));
        assert!(!rendered.contains("fixture-secret"));
    }

    #[test]
    fn v2_members_features_and_admin_implication_are_closed() {
        let parsed = SlackConfig::parse(&config_v2(&[
            &format!("token={SECRET}"),
            "app_token=xapp-fixture-secret",
            "channel=ops:C0RESERVED01",
            "member=U0MEMBER001",
            "admin=U0ADMIN001",
            "feature=approvals",
            "feature=conversation",
        ]))
        .expect("v2 config")
        .expect("present");
        assert_eq!(parsed.members.len(), 2);
        assert!(parsed.members.contains(&UserId::new("U0ADMIN001").unwrap()));
        assert_eq!(
            parsed.features,
            vec![SlackFeature::Approvals, SlackFeature::Conversation]
        );

        for bad in ["feature=future", "feature=approvals\nfeature=approvals"] {
            let frame = config_v2(&[&format!("token={SECRET}"), "channel=ops:C0RESERVED01", bad]);
            assert_eq!(
                SlackConfig::parse(&frame)
                    .expect_err("closed feature")
                    .category(),
                "slack_config_feature"
            );
        }
        let files = config_v2(&[
            &format!("token={SECRET}"),
            "channel=ops:C0RESERVED01",
            "feature=files",
        ]);
        assert_eq!(
            SlackConfig::parse(&files)
                .expect_err("artifact policy is mandatory")
                .category(),
            "slack_artifact_policy_required"
        );
    }

    /// One pressed approval button, as Slack's Socket Mode delivers it.
    fn approval_press(action_id: &str, value: &str) -> String {
        serde_json::json!({
            "type": "interactive",
            "payload": {
                "type": "block_actions",
                "team": {"id": "T0RESERVED01"},
                "user": {"id": "U0ADMIN001"},
                "channel": {"id": "C0RESERVED01"},
                "container": {"message_ts": "1723542000.000100"},
                "actions": [{"action_id": action_id, "value": value, "action_ts": "1723542001.1"}]
            }
        })
        .to_string()
    }

    #[test]
    fn an_approval_press_carries_only_an_opaque_reference() {
        let key = "apr-000102030405060708090a0b0c0d0e0f";
        let granted = slack_approval_interaction(&approval_press(SLACK_APPROVAL_GRANT_ACTION, key))
            .expect("a readable press")
            .expect("an approval press");
        assert_eq!(granted.request_key, key);
        assert!(granted.granted);
        assert_eq!(granted.user.as_str(), "U0ADMIN001");

        let denied = slack_approval_interaction(&approval_press(SLACK_APPROVAL_DENY_ACTION, key))
            .expect("a readable press")
            .expect("an approval press");
        assert!(!denied.granted);

        // A button from another lane is not this lane's to read.
        assert!(
            slack_approval_interaction(&approval_press("monique_ticket_approve", "job-1"))
                .expect("a readable press")
                .is_none()
        );
        // A value outside the `apr-` grammar on *this* lane's action is a
        // payload from somewhere it should not be, and it breaks the
        // connection rather than being ignored.
        assert!(
            slack_approval_interaction(&approval_press(SLACK_APPROVAL_GRANT_ACTION, "job-1"))
                .is_err()
        );
        // Two presses in one envelope is not a shape this product renders.
        let doubled = serde_json::json!({
            "type": "interactive",
            "payload": {
                "type": "block_actions",
                "team": {"id": "T0RESERVED01"},
                "user": {"id": "U0ADMIN001"},
                "channel": {"id": "C0RESERVED01"},
                "container": {"message_ts": "1723542000.000100"},
                "actions": [
                    {"action_id": SLACK_APPROVAL_GRANT_ACTION, "value": key},
                    {"action_id": SLACK_APPROVAL_DENY_ACTION, "value": key}
                ]
            }
        })
        .to_string();
        assert!(slack_approval_interaction(&doubled).is_err());
    }

    #[derive(Clone, Default)]
    struct FakeTicketPoster {
        messages: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl SlackTicketPoster for FakeTicketPoster {
        fn post_thread(
            &mut self,
            _channel: &ChannelId,
            _parent: &MessageTs,
            text: &str,
        ) -> Result<(), ()> {
            self.messages
                .lock()
                .expect("messages")
                .push(text.to_owned());
            Ok(())
        }

        fn post_channel(&mut self, _channel: &ChannelId, text: &str) -> Result<(), ()> {
            self.messages
                .lock()
                .expect("messages")
                .push(text.to_owned());
            Ok(())
        }

        fn update_decision(
            &mut self,
            _channel: &ChannelId,
            _message_ts: &MessageTs,
            text: &str,
        ) -> Result<(), ()> {
            self.messages
                .lock()
                .expect("messages")
                .push(text.to_owned());
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeManage {
        opened: Arc<std::sync::Mutex<Vec<(String, String)>>>,
        confirmed: Arc<std::sync::Mutex<Vec<(String, String)>>>,
        status_reads: Arc<std::sync::Mutex<Vec<String>>>,
        status: Option<automonique_support_connector::TicketStatus>,
        canonical_source: Option<String>,
    }

    struct FakeQuestionAnswerer {
        seen: Arc<std::sync::Mutex<Vec<(String, String, String)>>>,
    }

    struct DeferredRunLane {
        answers: std::collections::VecDeque<String>,
        profiles: Vec<QuestionProfile>,
    }

    impl DeferredRunLane {
        fn new(answers: &[&str]) -> Self {
            Self {
                answers: answers.iter().map(|answer| (*answer).to_owned()).collect(),
                profiles: Vec::new(),
            }
        }
    }

    impl crate::telegram_bridge::RunLane for DeferredRunLane {
        fn run(&mut self, _task: &str) -> Result<String, crate::telegram_bridge::RunFailure> {
            self.answers
                .pop_front()
                .ok_or(crate::telegram_bridge::RunFailure::Failed)
        }

        fn run_question(
            &mut self,
            _task: &str,
            profile: QuestionProfile,
        ) -> Result<String, crate::telegram_bridge::RunFailure> {
            self.profiles.push(profile);
            self.answers
                .pop_front()
                .ok_or(crate::telegram_bridge::RunFailure::Failed)
        }
    }

    #[test]
    fn slack_wait_placeholders_run_the_shared_completion_pass() {
        let mut lane = DeferredRunLane::new(&[
            "I'll search for that and get back to you.",
            "The Slack reply now contains the completed result.",
        ]);
        let answer = run_question_to_completion(
            &mut lane,
            "bounded Slack prompt",
            QuestionProfile::Conversation,
        )
        .expect("completion pass");
        assert_eq!(answer, "The Slack reply now contains the completed result.");
        assert_eq!(
            lane.profiles,
            [QuestionProfile::Conversation, QuestionProfile::Operational]
        );
    }

    impl SlackQuestionAnswerer for FakeQuestionAnswerer {
        fn answer(
            &mut self,
            question: &str,
            context: &str,
            _source_key: &str,
            actor: &UserId,
            _channel: &ChannelId,
            _approvals_enabled: bool,
        ) -> SlackQuestionReply {
            self.seen.lock().expect("questions").push((
                question.to_owned(),
                context.to_owned(),
                actor.as_str().to_owned(),
            ));
            SlackQuestionReply::Text(String::from("Monique intelligent answer"))
        }
    }

    struct FakeIssueStatusAnswerer {
        seen: Arc<std::sync::Mutex<Vec<String>>>,
    }

    struct FakeProviderStatsAnswerer;

    impl SlackQuestionAnswerer for FakeProviderStatsAnswerer {
        fn answer(
            &mut self,
            _question: &str,
            _context: &str,
            _source_key: &str,
            _actor: &UserId,
            _channel: &ChannelId,
            _approvals_enabled: bool,
        ) -> SlackQuestionReply {
            panic!("provider statistics must use the typed provider journal read")
        }

        fn provider_stats(&mut self) -> String {
            String::from("Automonique provider instances\ncodex: live 2 | recorded 5")
        }
    }

    impl SlackQuestionAnswerer for FakeIssueStatusAnswerer {
        fn answer(
            &mut self,
            _question: &str,
            _context: &str,
            _source_key: &str,
            _actor: &UserId,
            _channel: &ChannelId,
            _approvals_enabled: bool,
        ) -> SlackQuestionReply {
            panic!("status questions must use the typed GitHub issue reader")
        }

        fn issue_status(&mut self, issue_url: &str) -> String {
            self.seen
                .lock()
                .expect("issue reads")
                .push(issue_url.to_owned());
            String::from("No — GitHub still marks this issue as open.")
        }
    }

    struct FakeIssueReviewAnswerer {
        seen: Arc<std::sync::Mutex<Vec<(String, String, bool)>>>,
    }

    impl SlackQuestionAnswerer for FakeIssueReviewAnswerer {
        fn answer(
            &mut self,
            _question: &str,
            _context: &str,
            _source_key: &str,
            _actor: &UserId,
            _channel: &ChannelId,
            _approvals_enabled: bool,
        ) -> SlackQuestionReply {
            panic!("issue reviews must use the typed GitHub issue reader")
        }

        fn issue_review(
            &mut self,
            issue_url: &str,
            question: &str,
            _context: &str,
            deep: bool,
        ) -> String {
            self.seen.lock().expect("issue reviews").push((
                issue_url.to_owned(),
                question.to_owned(),
                deep,
            ));
            String::from("Typed GitHub issue review")
        }
    }

    struct FakeToolAnswerer {
        decisions: Arc<std::sync::Mutex<Vec<(String, bool, String)>>>,
    }

    impl SlackQuestionAnswerer for FakeToolAnswerer {
        fn answer(
            &mut self,
            _question: &str,
            _context: &str,
            _source_key: &str,
            _actor: &UserId,
            _channel: &ChannelId,
            approvals_enabled: bool,
        ) -> SlackQuestionReply {
            assert!(approvals_enabled);
            SlackQuestionReply::Approval {
                key: String::from("tool-0123456789abcdef0123456789abcdef"),
                preview: String::from("MCP action awaiting approval"),
            }
        }

        fn decide_tool(&mut self, key: &str, granted: bool, channel: &ChannelId) -> String {
            self.decisions.lock().expect("decisions").push((
                key.to_owned(),
                granted,
                channel.as_str().to_owned(),
            ));
            String::from("Approved and completed the tool.")
        }
    }

    fn ticket_receipt(approved: bool) -> automonique_support_connector::TicketDispatchReceipt {
        automonique_support_connector::TicketDispatchReceipt {
            issue_id: String::from("issue-fixture"),
            issue_url: String::from("https://github.com/example/project/issues/42"),
            issue_title: String::from("Repair the form"),
            project_label: String::from("Example"),
            site_label: None,
            workspace: automonique_support_connector::TicketWorkspace::InstanceDefault,
            job_id: String::from("job-fixture-123456"),
            source_key: String::from("slack:T0RESERVED:event:EvFixture"),
            job_status: if approved {
                automonique_support_connector::TicketJobStatus::Pending
            } else {
                automonique_support_connector::TicketJobStatus::PendingApproval
            },
            duplicate: false,
            approved,
        }
    }

    fn running_ticket_status() -> automonique_support_connector::TicketStatus {
        automonique_support_connector::TicketStatus {
            issue_id: String::from("issue-fixture"),
            issue_url: String::from("https://github.com/example/project/issues/42"),
            issue_title: String::from("Repair the form"),
            job_id: String::from("job-fixture-123456"),
            job_status: automonique_support_connector::TicketJobStatus::Running,
            result: String::from("Implementing the requested change."),
            created_at: String::from("2026-08-17T20:42:00Z"),
            updated_at: String::from("2026-08-17T20:54:00Z"),
        }
    }

    fn done_ticket_status() -> automonique_support_connector::TicketStatus {
        automonique_support_connector::TicketStatus {
            issue_id: String::from("issue-fixture"),
            issue_url: String::from("https://github.com/example/project/issues/42"),
            issue_title: String::from("Repair the form"),
            job_id: String::from("job-fixture-123456"),
            job_status: automonique_support_connector::TicketJobStatus::Done,
            result: String::from(
                "Implemented and verified. Completion summary: https://github.com/example/project/issues/42#issuecomment-9001",
            ),
            created_at: String::from("2026-08-17T20:42:00Z"),
            updated_at: String::from("2026-08-17T21:02:00Z"),
        }
    }

    impl crate::telegram_bridge::TicketActionSurface for FakeManage {
        fn dispatch_ticket(
            &mut self,
            issue_url: &str,
            source_key: &str,
        ) -> Result<automonique_support_connector::TicketDispatchReceipt, String> {
            self.opened
                .lock()
                .expect("opened")
                .push((issue_url.to_owned(), source_key.to_owned()));
            let mut receipt = ticket_receipt(false);
            receipt.source_key = self
                .canonical_source
                .clone()
                .unwrap_or_else(|| source_key.to_owned());
            Ok(receipt)
        }

        fn confirm_ticket(
            &mut self,
            issue_url: &str,
            source_key: &str,
        ) -> Result<automonique_support_connector::TicketDispatchReceipt, String> {
            self.confirmed
                .lock()
                .expect("confirmed")
                .push((issue_url.to_owned(), source_key.to_owned()));
            let mut receipt = ticket_receipt(true);
            receipt.source_key = source_key.to_owned();
            Ok(receipt)
        }

        fn ticket_status(
            &mut self,
            job_id: &str,
        ) -> Result<automonique_support_connector::TicketStatus, String> {
            self.status_reads
                .lock()
                .expect("status reads")
                .push(job_id.to_owned());
            self.status.clone().ok_or_else(|| String::from("not used"))
        }
    }

    fn ticket_event(user: &str, text: &str, event_id: &str) -> SlackTicketEvent {
        SlackTicketEvent {
            team_id: String::from("T0RESERVED"),
            channel: ChannelId::new("C0RESERVED01").expect("channel"),
            user: UserId::new(user).expect("user"),
            text: text.to_owned(),
            parent: MessageTs::new("1723542000.000100").expect("timestamp"),
            source_key: format!("slack:T0RESERVED:event:{event_id}"),
            app_mention: false,
            in_thread: false,
            continues_conversation: false,
            bot_user: Some(UserId::new("U0MONIQUE9").expect("bot user")),
        }
    }

    /// A router whose only variable is the four-way decide gate.
    fn decide_gate_router(
        interactive_decisions: bool,
        features: Vec<SlackFeature>,
        admins: Vec<&str>,
    ) -> SlackTicketRouter<FakeTicketPoster> {
        SlackTicketRouter {
            poster: FakeTicketPoster::default(),
            manage: Box::new(FakeManage::default()),
            manage_url: None,
            memory_tenant: String::from("primary"),
            channels: ChannelMap(vec![(
                name("ops"),
                ChannelId::new("C0RESERVED01").expect("channel"),
            )]),
            admins: admins
                .into_iter()
                .map(|admin| UserId::new(admin).expect("admin"))
                .collect(),
            members: Vec::new(),
            features,
            interactive_decisions,
            gates: Arc::new(std::sync::Mutex::new(
                crate::telegram_bridge::TicketGateRegistry::default(),
            )),
            github_actions: None,
            approvals: None,
            approval_lane: None,
            question_answerer: None,
        }
    }

    /// Every one of the four gates refuses a press on its own.
    ///
    /// A button is not a different authority from a modal, so this is the same
    /// conjunction `prepare_interaction` applies — and it is asserted one gate
    /// at a time, because a test that only checked the all-pass case would pass
    /// against a build that had dropped three of them.
    #[test]
    fn every_gate_refuses_an_approval_press_on_its_own() {
        let admin = UserId::new("U0ADMIN001").expect("admin");
        let channel = ChannelId::new("C0RESERVED01").expect("channel");
        let approvals = vec![SlackFeature::Approvals, SlackFeature::Conversation];

        let permitted = decide_gate_router(true, approvals.clone(), vec!["U0ADMIN001"]);
        assert!(permitted.may_decide(&admin, &channel));

        // Interactive decisions explicitly disabled decides nothing.
        assert!(
            !decide_gate_router(false, approvals.clone(), vec!["U0ADMIN001"])
                .may_decide(&admin, &channel)
        );
        // The approvals capability absent: a half-configured surface renders
        // buttons nobody can act on, and this is where that is refused.
        assert!(
            !decide_gate_router(true, vec![SlackFeature::Conversation], vec!["U0ADMIN001"])
                .may_decide(&admin, &channel)
        );
        // Not on the admin allowlist.
        assert!(!permitted.may_decide(&UserId::new("U0MEMBER01").expect("member"), &channel));
        // A channel this deployment did not configure.
        assert!(!permitted.may_decide(&admin, &ChannelId::new("C0ELSEWHERE").expect("channel")));
    }

    #[test]
    fn conversational_tool_plans_use_slack_buttons_and_the_same_admin_gate() {
        let poster = FakeTicketPoster::default();
        let messages = Arc::clone(&poster.messages);
        let decisions = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut router = SlackTicketRouter {
            poster,
            manage: Box::new(FakeManage::default()),
            manage_url: None,
            memory_tenant: String::from("primary"),
            channels: ChannelMap(vec![(
                name("ops"),
                ChannelId::new("C0RESERVED01").expect("channel"),
            )]),
            admins: vec![UserId::new("U0ADMIN001").expect("admin")],
            members: vec![UserId::new("U0ADMIN001").expect("member")],
            features: vec![SlackFeature::Approvals, SlackFeature::Conversation],
            interactive_decisions: true,
            gates: Arc::new(std::sync::Mutex::new(
                crate::telegram_bridge::TicketGateRegistry::default(),
            )),
            github_actions: None,
            approvals: None,
            approval_lane: None,
            question_answerer: Some(Box::new(FakeToolAnswerer {
                decisions: Arc::clone(&decisions),
            })),
        };
        let mut event = ticket_event("U0ADMIN001", "<@B0APP> utilise l'outil", "EvTool");
        event.app_mention = true;
        router.handle_with_context(event, "");
        assert_eq!(
            messages.lock().expect("messages").as_slice(),
            [String::from("MCP action awaiting approval")]
        );

        router.handle_tool_interaction(SlackToolInteraction {
            channel: ChannelId::new("C0RESERVED01").expect("channel"),
            message_ts: MessageTs::new("1723542001.000200").expect("message"),
            user: UserId::new("U0ADMIN001").expect("admin"),
            key: String::from("tool-0123456789abcdef0123456789abcdef"),
            granted: true,
        });
        assert_eq!(
            decisions.lock().expect("decisions").as_slice(),
            [(
                String::from("tool-0123456789abcdef0123456789abcdef"),
                true,
                String::from("C0RESERVED01"),
            )]
        );
    }

    #[test]
    fn slack_tool_button_payload_carries_only_an_opaque_plan_key() {
        let frame = r#"{"type":"interactive","payload":{"type":"block_actions","user":{"id":"U0ADMIN001"},"channel":{"id":"C0RESERVED01"},"container":{"message_ts":"1723542001.000200"},"actions":[{"action_id":"automonique_tool_grant","value":"tool-0123456789abcdef0123456789abcdef"}]}}"#;
        let interaction = slack_tool_interaction(frame)
            .expect("payload")
            .expect("tool interaction");
        assert!(interaction.granted);
        assert_eq!(interaction.key, "tool-0123456789abcdef0123456789abcdef");
        assert_eq!(interaction.channel.as_str(), "C0RESERVED01");
    }

    #[test]
    fn configured_channel_ticket_waits_for_a_configured_slack_admin() {
        let poster = FakeTicketPoster::default();
        let messages = Arc::clone(&poster.messages);
        let manage = FakeManage::default();
        let opened = Arc::clone(&manage.opened);
        let confirmed = Arc::clone(&manage.confirmed);
        let mut router = SlackTicketRouter {
            poster,
            manage: Box::new(manage),
            manage_url: None,
            memory_tenant: String::from("primary"),
            channels: ChannelMap(vec![(
                name("ops"),
                ChannelId::new("C0RESERVED01").expect("channel"),
            )]),
            admins: vec![UserId::new("U0ADMIN001").expect("admin")],
            members: vec![UserId::new("U0ADMIN001").expect("member")],
            features: vec![SlackFeature::Approvals, SlackFeature::Conversation],
            interactive_decisions: false,
            gates: Arc::new(std::sync::Mutex::new(
                crate::telegram_bridge::TicketGateRegistry::default(),
            )),
            github_actions: None,
            approvals: None,
            approval_lane: None,
            question_answerer: None,
        };

        router.handle_with_context(
            ticket_event(
                "U0REQUEST01",
                "please handle https://github.com/example/project/issues/42",
                "Ev1",
            ),
            "",
        );
        assert_eq!(opened.lock().expect("opened").len(), 1);
        assert!(confirmed.lock().expect("confirmed").is_empty());
        assert!(messages.lock().expect("messages")[0].contains("Confirmation required"));

        router.handle_with_context(
            ticket_event("U0REQUEST01", "confirm job-fixture", "Ev2"),
            "",
        );
        assert!(confirmed.lock().expect("confirmed").is_empty());
        assert!(
            messages
                .lock()
                .expect("messages")
                .iter()
                .any(|message| message.contains("Only a configured Slack administrator"))
        );

        router.handle_with_context(ticket_event("U0ADMIN001", "confirm job-fixture", "Ev3"), "");
        assert_eq!(confirmed.lock().expect("confirmed").len(), 1);
        assert!(
            messages
                .lock()
                .expect("messages")
                .iter()
                .any(|message| message.contains("Confirmed by <@U0ADMIN001>"))
        );
    }

    /// The zero-effect property, which is what the whole parity milestone rests
    /// on.
    ///
    /// A shadow harness whose shadow half can still post converts a *missing*
    /// gate into a *false* one, so the assertion is not "the envelopes look
    /// right" — it is "the production seams received nothing". Both halves are
    /// checked against the same scenario: the spying surfaces record what the
    /// primary engine does, the shadow surfaces are given the identical events,
    /// and the spies are then re-read to prove they did not move.
    mod shadow_zero_effect {
        use super::*;
        use crate::shadow::{
            MemorySink, ShadowClock, ShadowPoster, ShadowTicketSurface, SharedRecorder,
        };
        use automonique_protocol::parity::{ActionKind, ParityEngine};

        const ISSUE: &str = "please handle https://github.com/example/project/issues/42";

        fn router<P: SlackTicketPoster>(
            poster: P,
            manage: Box<dyn crate::telegram_bridge::TicketActionSurface + Send>,
        ) -> SlackTicketRouter<P> {
            SlackTicketRouter {
                poster,
                manage,
                manage_url: None,
                memory_tenant: String::from("primary"),
                channels: ChannelMap(vec![(
                    name("ops"),
                    ChannelId::new("C0RESERVED01").expect("channel"),
                )]),
                admins: vec![UserId::new("U0ADMIN001").expect("admin")],
                members: vec![UserId::new("U0ADMIN001").expect("member")],
                features: vec![SlackFeature::Approvals, SlackFeature::Conversation],
                interactive_decisions: false,
                gates: Arc::new(std::sync::Mutex::new(
                    crate::telegram_bridge::TicketGateRegistry::default(),
                )),
                github_actions: None,
                approvals: None,
                approval_lane: None,
                question_answerer: None,
            }
        }

        /// The same two events for both engines: one intake that opens a gate,
        /// one confirmation attempt by somebody who may not confirm.
        fn drive<P: SlackTicketPoster>(router: &mut SlackTicketRouter<P>) {
            router.handle_with_context(ticket_event("U0REQUEST01", ISSUE, "Ev1"), "");
            router.handle_with_context(
                ticket_event("U0REQUEST01", "confirm job-fixture", "Ev2"),
                "",
            );
        }

        /// One recorder for both decorators: the poster and the ticket surface
        /// are two halves of one engine's decision stream, so they share a
        /// sequence rather than each keeping their own.
        fn recorder() -> SharedRecorder<MemorySink> {
            SharedRecorder::opened(
                "slack-ticket-routing",
                ParityEngine::ShadowCandidate,
                ShadowClock::Fixed(1_700_000_000_000),
                MemorySink::new(),
            )
        }

        fn shadow_router(
            recorder: &SharedRecorder<MemorySink>,
        ) -> SlackTicketRouter<ShadowPoster<MemorySink>> {
            router(
                ShadowPoster::new(recorder.clone()),
                Box::new(ShadowTicketSurface::new(recorder.clone())),
            )
        }

        #[test]
        fn the_shadow_router_reaches_no_production_seam() {
            let spy_poster = FakeTicketPoster::default();
            let posted = Arc::clone(&spy_poster.messages);
            let spy_manage = FakeManage::default();
            let opened = Arc::clone(&spy_manage.opened);
            let confirmed = Arc::clone(&spy_manage.confirmed);

            // The scenario really does produce effects when the production
            // seams are in place. Without this half, "zero calls" would be
            // satisfied by a scenario that never asked for anything.
            let mut primary = router(spy_poster, Box::new(spy_manage));
            drive(&mut primary);
            let posts_by_primary = posted.lock().expect("messages").len();
            let dispatches_by_primary = opened.lock().expect("opened").len();
            assert!(posts_by_primary > 0);
            assert_eq!(dispatches_by_primary, 1);

            let recorder = recorder();
            let mut shadow = shadow_router(&recorder);
            drive(&mut shadow);

            assert_eq!(
                posted.lock().expect("messages").len(),
                posts_by_primary,
                "a shadow poster must not reach Slack"
            );
            assert_eq!(
                opened.lock().expect("opened").len(),
                dispatches_by_primary,
                "a shadow ticket surface must not reach the support backend"
            );
            assert!(confirmed.lock().expect("confirmed").is_empty());
        }

        #[test]
        fn the_shadow_router_records_the_decisions_it_suppressed() {
            let recorder = recorder();
            let mut shadow = shadow_router(&recorder);
            drive(&mut shadow);
            let envelopes = recorder.envelopes();
            let kinds: Vec<ActionKind> = envelopes
                .iter()
                .map(|envelope| envelope.action().kind())
                .collect();
            assert_eq!(
                kinds,
                vec![
                    ActionKind::TicketDispatch,
                    ActionKind::SlackThreadReply,
                    ActionKind::SlackThreadReply
                ],
                "one stream, in the order the engine decided: dispatch, then the \
                 card it provoked, then the refusal of the unauthorized confirm"
            );
            assert!(
                envelopes[1]
                    .action()
                    .value("text")
                    .expect("text")
                    .contains("Confirmation required")
            );
            assert!(
                envelopes[2]
                    .action()
                    .value("text")
                    .expect("text")
                    .contains("Only a configured Slack administrator")
            );
        }

        #[test]
        fn each_event_opens_its_own_envelope_sequence() {
            let recorder = recorder();
            let mut shadow = shadow_router(&recorder);
            drive(&mut shadow);
            let envelopes = recorder.envelopes();
            assert_eq!(envelopes[0].sequence(), 0);
            assert_eq!(envelopes[1].sequence(), 1);
            assert_eq!(envelopes[0].source_key(), envelopes[1].source_key());
            // The second event restarts the sequence, so position n always
            // means "the nth decision for this event" and two engines' streams
            // can be paired position by position.
            assert_eq!(envelopes[2].sequence(), 0);
            assert_ne!(envelopes[1].source_key(), envelopes[2].source_key());
        }

        #[test]
        fn a_shadow_run_is_byte_identical_under_a_fixed_clock() {
            let bytes = |()| {
                let recorder = recorder();
                let mut shadow = shadow_router(&recorder);
                drive(&mut shadow);
                recorder
                    .envelopes()
                    .iter()
                    .map(automonique_protocol::parity::IntendedActionEnvelope::to_canonical_bytes)
                    .collect::<Vec<_>>()
            };
            assert_eq!(bytes(()), bytes(()));
        }
    }

    #[test]
    fn a_reference_bot_message_is_seen_upstream_of_the_filter_that_drops_it() {
        let envelope = |body: &str| {
            format!(
                "{{\"type\":\"events_api\",\"payload\":{{\"event_id\":\"Ev1\",\"team_id\":\"T0RESERVED\",\"event\":{{{body}}}}}}}"
            )
        };
        let bot = envelope(
            "\"type\":\"message\",\"bot_id\":\"B0OTHER0001\",\"user\":\"U0REFERENCE\",\"channel\":\"C0RESERVED01\",\"text\":\"on it\",\"ts\":\"1723542000.000100\",\"thread_ts\":\"1723542000.000100\"",
        );
        // The router's own parser drops it, which is exactly why the observer
        // taps upstream.
        assert!(slack_ticket_event(&bot).is_none());
        let observed = slack_legacy_bot_message(&bot, "U0REFERENCE").expect("observed");
        assert_eq!(observed.channel, "C0RESERVED01");
        assert!(observed.in_thread);
        assert_eq!(observed.text, "on it");

        // Only the configured identity is admitted; every other bot stays
        // dropped, so the allowance is one bot rather than all of them.
        assert!(slack_legacy_bot_message(&bot, "U0SOMEONEELSE").is_none());

        // A human message carries no bot_id and is the router's business, not
        // the observer's.
        let human = envelope(
            "\"type\":\"message\",\"user\":\"U0REFERENCE\",\"channel\":\"C0RESERVED01\",\"text\":\"hello\",\"ts\":\"1723542000.000100\"",
        );
        assert!(slack_legacy_bot_message(&human, "U0REFERENCE").is_none());

        // A top-level post is distinguishable from a threaded reply.
        let top_level = envelope(
            "\"type\":\"message\",\"bot_id\":\"B0OTHER0001\",\"user\":\"U0REFERENCE\",\"channel\":\"C0RESERVED01\",\"text\":\"notice\",\"ts\":\"1723542000.000100\"",
        );
        let observed = slack_legacy_bot_message(&top_level, "U0REFERENCE").expect("observed");
        assert!(!observed.in_thread);
    }

    #[test]
    fn configured_admin_slack_memory_keeps_user_and_confirmed_assistant_turns() {
        let root = tempfile::tempdir().expect("memory root");
        std::fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("private memory root");
        let mut memory =
            AgentMemoryStore::open(root.path().join("agent-memory.sqlite3")).expect("memory store");
        let router = SlackTicketRouter {
            poster: FakeTicketPoster::default(),
            manage: Box::new(FakeManage::default()),
            manage_url: None,
            memory_tenant: String::from("primary"),
            channels: ChannelMap(vec![(
                name("ops"),
                ChannelId::new("C0RESERVED01").expect("channel"),
            )]),
            admins: vec![UserId::new("U0ADMIN001").expect("admin")],
            members: vec![UserId::new("U0ADMIN001").expect("member")],
            features: vec![SlackFeature::Approvals, SlackFeature::Conversation],
            interactive_decisions: false,
            gates: Arc::new(std::sync::Mutex::new(
                crate::telegram_bridge::TicketGateRegistry::default(),
            )),
            github_actions: None,
            approvals: None,
            approval_lane: None,
            question_answerer: None,
        };
        let event = ticket_event(
            "U0ADMIN001",
            "remember token sk-123456789012345678901234",
            "Memory1",
        );
        router
            .capture_memory(&mut memory, &event)
            .expect("first capture");
        router
            .capture_memory(&mut memory, &event)
            .expect("replay capture");
        let reply = ConfirmedSlackThreadReply {
            source_key: event.source_key.clone(),
            channel: event.channel.clone(),
            parent: event.parent.clone(),
            text: String::from("Je réponds dans ce thread; token sk-123456789012345678901234"),
        };
        router
            .capture_confirmed_reply(&mut memory, &event, &reply)
            .expect("confirmed reply capture");
        router
            .capture_confirmed_reply(&mut memory, &event, &reply)
            .expect("confirmed reply replay capture");
        let actor = "slack:T0RESERVED:U0ADMIN001";
        assert_eq!(
            memory
                .resolve_identity("slack", "automonique-slack", "T0RESERVED", "U0ADMIN001")
                .expect("binding"),
            Some((String::from("primary"), String::from(actor)))
        );
        assert_eq!(
            memory.counts("primary", actor).expect("counts").messages,
            2,
            "Slack event and accepted reply each become one durable message"
        );
        let messages = memory
            .recent_messages(
                "primary",
                actor,
                "slack:T0RESERVED:C0RESERVED01:1723542000.000100:U0ADMIN001",
                crate::unix_millis().expect("clock"),
                5,
            )
            .expect("history");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].role, "user");
        assert_eq!(messages[1].role, "assistant");
        assert!(messages[0].content.contains("[REDACTED]"));
        assert!(!messages[0].content.contains("sk-123456789012345678901234"));
        assert!(messages[1].content.contains("[REDACTED]"));
        assert!(!messages[1].content.contains("sk-123456789012345678901234"));
        let context = slack_event_context(&memory, "primary", &event);
        assert!(context.contains("user: remember token [REDACTED]"));
        assert!(context.contains("assistant: Je réponds dans ce thread; token [REDACTED]"));

        router
            .capture_memory(
                &mut memory,
                &ticket_event("U0REQUEST01", "private request", "Memory2"),
            )
            .expect("non-admin ignored");
        assert_eq!(
            memory
                .resolve_identity("slack", "automonique-slack", "T0RESERVED", "U0REQUEST01")
                .expect("no binding"),
            None
        );
    }

    #[test]
    fn slack_reply_location_is_grounded_in_confirmed_conversation_history() {
        assert_eq!(
            slack_reply_location_answer(
                "tu as répondu ou à Bruno ?",
                "user: explique à Bruno\nassistant: Bruno, Ben teste le truc.\nuser: tu as répondu ou à Bruno ?",
            )
            .as_deref(),
            Some(
                "Ma réponse précédente a été publiée dans ce thread Slack. Je n’ai envoyé ni message privé ni second message ailleurs."
            )
        );
        assert!(
            slack_reply_location_answer(
                "tu as répondu ou à Bruno ?",
                "user: tu as répondu ou à Bruno ?",
            )
            .is_none(),
            "without a confirmed assistant turn the helper must not invent delivery"
        );
    }

    /// Two threads of one Slack channel are two sessions, and the scope this
    /// bridge writes is byte-identical to the one it wrote before the
    /// derivation was versioned — so no existing head is orphaned.
    #[test]
    fn slack_threads_are_separate_sessions_under_the_scope_this_bridge_already_wrote() {
        let root = tempfile::tempdir().expect("memory root");
        std::fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("private memory root");
        let mut memory =
            AgentMemoryStore::open(root.path().join("agent-memory.sqlite3")).expect("memory store");
        let router = SlackTicketRouter {
            poster: FakeTicketPoster::default(),
            manage: Box::new(FakeManage::default()),
            manage_url: None,
            memory_tenant: String::from("primary"),
            channels: ChannelMap(vec![(
                name("ops"),
                ChannelId::new("C0RESERVED01").expect("channel"),
            )]),
            admins: vec![UserId::new("U0ADMIN001").expect("admin")],
            members: vec![UserId::new("U0ADMIN001").expect("member")],
            features: vec![SlackFeature::Approvals, SlackFeature::Conversation],
            interactive_decisions: false,
            gates: Arc::new(std::sync::Mutex::new(
                crate::telegram_bridge::TicketGateRegistry::default(),
            )),
            github_actions: None,
            approvals: None,
            approval_lane: None,
            question_answerer: None,
        };
        let mut in_thread = |thread_ts: &str, event_id: &str| {
            let mut event = ticket_event("U0ADMIN001", "bonjour", event_id);
            event.parent = MessageTs::new(thread_ts).expect("timestamp");
            router
                .capture_memory(&mut memory, &event)
                .expect("captured");
        };
        in_thread("1723542000.000100", "Thread1");
        in_thread("1723542900.000200", "Thread2");

        let actor = "slack:T0RESERVED:U0ADMIN001";
        // The exact string this bridge has always written, spelled out here so
        // a change to the derivation cannot pass silently.
        let first = memory
            .current_conversation(
                "primary",
                actor,
                "slack",
                "channel:C0RESERVED01:thread:1723542000.000100",
            )
            .expect("first head")
            .expect("the first thread has its own session");
        let second = memory
            .current_conversation(
                "primary",
                actor,
                "slack",
                "channel:C0RESERVED01:thread:1723542900.000200",
            )
            .expect("second head")
            .expect("the second thread has its own session");
        assert_ne!(first, second);
        // And the channel's own unthreaded scope is not either of them.
        assert_eq!(
            memory
                .current_conversation("primary", actor, "slack", "channel:C0RESERVED01")
                .expect("channel head"),
            None
        );
        assert_eq!(
            ConversationScope::slack("C0RESERVED01", Some("1723542000.000100"))
                .expect("derived")
                .as_str(),
            "channel:C0RESERVED01:thread:1723542000.000100"
        );
    }

    #[test]
    fn slack_admin_can_confirm_a_gate_created_by_another_transport() {
        let poster = FakeTicketPoster::default();
        let messages = Arc::clone(&poster.messages);
        let manage = FakeManage::default();
        let confirmed = Arc::clone(&manage.confirmed);
        let gates = Arc::new(std::sync::Mutex::new(
            crate::telegram_bridge::TicketGateRegistry::default(),
        ));
        gates
            .lock()
            .expect("gates")
            .register(crate::telegram_bridge::PendingTicketGate {
                job_id: String::from("job-fixture-123456"),
                issue_url: String::from("https://github.com/example/project/issues/42"),
                source_key: String::from("telegram:123:update:9"),
            })
            .expect("gate registered");
        let mut router = SlackTicketRouter {
            poster,
            manage: Box::new(manage),
            manage_url: None,
            memory_tenant: String::from("primary"),
            channels: ChannelMap(vec![(
                name("ops"),
                ChannelId::new("C0RESERVED01").expect("channel"),
            )]),
            admins: vec![UserId::new("U0ADMIN001").expect("admin")],
            members: vec![UserId::new("U0ADMIN001").expect("member")],
            features: vec![SlackFeature::Approvals, SlackFeature::Conversation],
            interactive_decisions: false,
            gates,
            github_actions: None,
            approvals: None,
            approval_lane: None,
            question_answerer: None,
        };
        router.handle_with_context(ticket_event("U0ADMIN001", "confirm job-fixture", "Ev4"), "");
        assert_eq!(
            confirmed.lock().expect("confirmed").as_slice(),
            [(
                String::from("https://github.com/example/project/issues/42"),
                String::from("telegram:123:update:9")
            )]
        );
        assert!(
            messages
                .lock()
                .expect("messages")
                .iter()
                .any(|message| message.contains("Confirmed by <@U0ADMIN001>"))
        );
    }

    #[test]
    fn socket_event_is_acknowledgeable_and_excludes_bot_messages() {
        let event = r#"{"envelope_id":"E1","type":"events_api","payload":{"event_id":"Ev1","team_id":"T0RESERVED","event":{"type":"message","channel":"C0RESERVED01","user":"U0REQUEST01","text":"https://github.com/example/project/issues/42","ts":"1723542000.000100"}}}"#;
        assert_eq!(socket_envelope_id(event).as_deref(), Some("E1"));
        assert_eq!(
            slack_ticket_event(event).expect("event").source_key,
            "slack:T0RESERVED:event:Ev1"
        );
        let bot = event.replace(
            "\"type\":\"message\"",
            "\"type\":\"message\",\"bot_id\":\"B0BOT00001\"",
        );
        assert!(slack_ticket_event(&bot).is_none());
    }

    #[test]
    fn socket_hello_is_connection_control_not_a_failed_envelope() {
        let hello = r#"{"type":"hello","num_connections":1,"debug_info":{"host":"example"}}"#;
        assert!(socket_hello(hello));
        assert!(socket_envelope_id(hello).is_none());
        assert!(!socket_hello(
            r#"{"type":"disconnect","reason":"refresh_requested"}"#
        ));
        assert!(!socket_hello(
            r#"{"type":"hello","envelope_id":"unexpected"}"#
        ));
        assert!(!socket_hello("not json"));
    }

    #[test]
    fn generation_canary_is_exact_and_consumed_once() {
        let mut canary = Some(SlackGenerationCanary {
            channel: ChannelId::new("C0DEPLOY001").expect("channel"),
            generation: 108,
            queues_clean: true,
        });
        let (_, message) = generation_canary_message(&mut canary).expect("first hello");
        assert_eq!(
            message,
            ":white_check_mark: Monique generation 108 canary: Slack connected; queues clean."
        );
        assert!(generation_canary_message(&mut canary).is_none());
    }

    #[test]
    fn generation_canary_does_not_claim_dirty_queues_are_clean() {
        let mut canary = Some(SlackGenerationCanary {
            channel: ChannelId::new("C0DEPLOY001").expect("channel"),
            generation: 109,
            queues_clean: false,
        });
        let (_, message) = generation_canary_message(&mut canary).expect("hello");
        assert_eq!(
            message,
            ":warning: Monique generation 109 canary: Slack connected; queues not clean."
        );
    }

    #[test]
    fn idle_socket_timeout_keeps_the_connection_and_other_failures_reconnect() {
        assert_eq!(
            slack_receive_disposition::<()>(Err(SocketModeFailure::TimedOut)),
            SlackReceiveDisposition::Idle
        );
        assert_eq!(
            slack_receive_disposition(Ok("event")),
            SlackReceiveDisposition::Envelope("event")
        );
        for failure in [
            SocketModeFailure::UrlRejected,
            SocketModeFailure::Redirected,
            SocketModeFailure::Unavailable,
            SocketModeFailure::BinaryFrame,
            SocketModeFailure::EnvelopeTooLarge,
            SocketModeFailure::InvalidText,
            SocketModeFailure::MalformedControl,
            SocketModeFailure::Closed,
            SocketModeFailure::InvalidAcknowledgement,
        ] {
            assert_eq!(
                slack_receive_disposition::<()>(Err(failure)),
                SlackReceiveDisposition::Reconnect,
                "{failure:?}"
            );
        }
    }

    #[test]
    fn channel_ticket_audit_is_read_only_and_reports_its_follow_up_boundary() {
        let request = "check if we missed handling any of the tickets or follow up comments of tickets posted in the channel";
        assert!(is_channel_ticket_audit_question(request));
        assert!(!is_channel_ticket_audit_question(
            "check the deployment item on https://github.com/example/project/issues/42"
        ));

        let bot = UserId::new("U0MONIQUE9").expect("bot user");
        let human = UserId::new("U0RESERVED").expect("human user");
        let mut missed = message(
            Some("U0RESERVED"),
            "1723542000.000100",
            "https://github.com/example/project/issues/42",
        );
        missed.reply_count = Some(0);
        let mut handled = message(
            Some("U0RESERVED"),
            "1723542100.000200",
            "https://github.com/example/project/issues/43",
        );
        handled.reply_count = Some(1);
        handled.reply_users = Some(vec![bot.clone()]);
        handled.reply_users_count = Some(1);
        let mut follow_up = message(
            Some("U0RESERVED"),
            "1723542200.000300",
            "https://github.com/example/project/issues/44",
        );
        follow_up.reply_count = Some(3);
        follow_up.reply_users = Some(vec![bot.clone(), human]);
        follow_up.reply_users_count = Some(2);

        let answer = channel_ticket_audit_text(&[missed, handled, follow_up], &bot, true);
        assert!(answer.contains("3 GitHub ticket posts (3 unique issues)"));
        assert!(answer.contains("1 ticket post(s) have no confirmed Monique reply"));
        assert!(answer.contains("https://github.com/example/project/issues/42"));
        assert!(answer.contains("1 replied threads have only Monique"));
        assert!(answer.contains("1 thread(s) contain both Monique and human replies"));
        assert!(!answer.contains("issues/43\n-"));
    }

    #[test]
    fn only_the_plain_copy_of_a_bot_mention_is_a_duplicate() {
        let plain = ticket_event("U0ADMIN001", "<@U0MONIQUE9> what is open?", "Ev10");
        assert!(slack_plain_copy_of_bot_mention(&plain));
        let mut mention = plain.clone();
        mention.app_mention = true;
        assert!(!slack_plain_copy_of_bot_mention(&mention));
        let other_human = ticket_event("U0ADMIN001", "it's <@U0BRUNO001>", "Ev11");
        assert!(!slack_plain_copy_of_bot_mention(&other_human));
        let mut unauthorized = other_human.clone();
        unauthorized.bot_user = None;
        assert!(slack_plain_copy_of_bot_mention(&unauthorized));
        let no_mention = ticket_event("U0ADMIN001", "tag him that's fine", "Ev12");
        assert!(!slack_plain_copy_of_bot_mention(&no_mention));
    }

    #[test]
    fn app_mentions_are_distinct_from_plain_ticket_messages() {
        let mention = r#"{"envelope_id":"E2","type":"events_api","payload":{"event_id":"Ev2","team_id":"T0RESERVED","event":{"type":"app_mention","channel":"C0RESERVED01","user":"U0ADMIN001","text":"<@B0APP> reply https://github.com/example/project/issues/42 with the verification","ts":"1723542000.000200"}}}"#;
        let parsed = slack_ticket_event(mention).expect("app mention");
        assert!(parsed.app_mention);
        assert_eq!(parsed.source_key, "slack:T0RESERVED:event:Ev2");

        let plain = mention.replace("app_mention", "message");
        assert!(
            !slack_ticket_event(&plain)
                .expect("plain message")
                .app_mention
        );
    }

    #[test]
    fn envelope_authorizations_identify_the_bot_being_mentioned() {
        let without = r#"{"envelope_id":"E3","type":"events_api","payload":{"event_id":"Ev3","team_id":"T0RESERVED","event":{"type":"app_mention","channel":"C0RESERVED01","user":"U0ADMIN001","text":"<@U0MONIQUE9> hello","ts":"1723542000.000300"}}}"#;
        assert_eq!(
            slack_ticket_event(without).expect("event").bot_user,
            None,
            "an envelope without authorizations still parses"
        );

        let with = r#"{"envelope_id":"E4","type":"events_api","payload":{"event_id":"Ev4","team_id":"T0RESERVED","authorizations":[{"team_id":"T0RESERVED","user_id":"U0MONIQUE9","is_bot":true}],"event":{"type":"app_mention","channel":"C0RESERVED01","user":"U0ADMIN001","text":"<@U0MONIQUE9> hello","ts":"1723542000.000400"}}}"#;
        assert_eq!(
            slack_ticket_event(with).expect("event").bot_user,
            Some(UserId::new("U0MONIQUE9").expect("bot user")),
        );
    }

    #[test]
    fn mention_stripping_removes_exactly_the_bot_and_keeps_other_tags() {
        // The bot first, another person mentioned after: only the bot goes.
        assert_eq!(
            slack_app_mention_text("<@U0MONIQUE9> notify <@U0BRUNO001> plz", Some("U0MONIQUE9")),
            "notify <@U0BRUNO001> plz"
        );
        // The bot mentioned second: the other person's tag must survive, which
        // the first-token fallback would have destroyed.
        assert_eq!(
            slack_app_mention_text(
                "hey <@U0BRUNO001> regarde <@U0MONIQUE9>",
                Some("U0MONIQUE9")
            ),
            "hey <@U0BRUNO001> regarde"
        );
        // Legacy tokens carry a `|label` suffix after the id.
        assert_eq!(
            slack_app_mention_text("<@U0MONIQUE9|monique> bonjour", Some("U0MONIQUE9")),
            "bonjour"
        );
        // A person who mentions the bot twice still asked one thing.
        assert_eq!(
            slack_app_mention_text("<@U0MONIQUE9> ping <@U0MONIQUE9>", Some("U0MONIQUE9")),
            "ping"
        );
        // Without an authorized id, the pre-authorization behavior holds: the
        // first token is the one Slack classified on.
        assert_eq!(
            slack_app_mention_text("<@U0BRUNO001> et <@U0MONIQUE9>", None),
            "et <@U0MONIQUE9>"
        );
        // An authorized id that matches no token also falls back, so a
        // mismatched envelope never yields prose with the trigger left in.
        assert_eq!(
            slack_app_mention_text("<@U0OTHERBOT> status", Some("U0MONIQUE9")),
            "status"
        );
    }

    #[test]
    fn member_roster_pairs_exact_tokens_with_display_labels() {
        struct RosterFake;
        impl SlackApi for RosterFake {
            fn conversations_history(
                &self,
                _channel: &ChannelId,
                _limit: u16,
            ) -> Result<SlackOutcome<MessagePage>, SlackFailure> {
                Err(SlackFailure::Unavailable)
            }

            fn users_info(&self, user: &UserId) -> Result<SlackOutcome<SlackUser>, SlackFailure> {
                let profile = |name: &str, is_bot, deleted| {
                    Ok(SlackOutcome::Accepted(SlackUser {
                        id: user.clone(),
                        name: name.to_owned(),
                        real_name: None,
                        display_name: Some(name.to_owned()),
                        is_bot: Some(is_bot),
                        deleted: Some(deleted),
                    }))
                };
                match user.as_str() {
                    "U0BEN000001" => profile("ben", false, false),
                    "U0BRUNO001" => profile("bruno", false, false),
                    "U0MONIQUE9" => profile("monique", true, false),
                    "U0GONE0001" => profile("gone", false, true),
                    _ => Err(SlackFailure::Unavailable),
                }
            }

            fn post_message(
                &self,
                _channel: &ChannelId,
                _text: &MessageText,
            ) -> Result<SlackOutcome<PostedTs>, SlackFailure> {
                Err(SlackFailure::Unavailable)
            }
        }

        let members = [
            "U0BEN000001",
            "U0MONIQUE9",
            "U0GONE0001",
            "U0MISSING01",
            "U0BRUNO001",
        ]
        .map(|id| UserId::new(id).expect("member"));
        assert_eq!(
            slack_member_roster(&RosterFake, &members).as_deref(),
            Some("<@U0BEN000001> is ben; <@U0BRUNO001> is bruno"),
            "bots, deactivated accounts and failed lookups are skipped"
        );
        assert_eq!(
            slack_member_roster(&RosterFake, &[]),
            None,
            "an empty allowlist resolves to no roster rather than an empty one"
        );
    }

    #[test]
    fn admitted_app_mentions_reach_monique_question_routing() {
        let poster = FakeTicketPoster::default();
        let messages = Arc::clone(&poster.messages);
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut router = SlackTicketRouter {
            poster,
            manage: Box::new(FakeManage::default()),
            manage_url: None,
            memory_tenant: String::from("primary"),
            channels: ChannelMap(vec![(
                name("ops"),
                ChannelId::new("C0RESERVED01").expect("channel"),
            )]),
            admins: vec![UserId::new("U0ADMIN001").expect("admin")],
            members: vec![
                UserId::new("U0ADMIN001").expect("member"),
                UserId::new("U0MEMBER002").expect("member"),
            ],
            features: vec![SlackFeature::Approvals, SlackFeature::Conversation],
            interactive_decisions: false,
            gates: Arc::new(std::sync::Mutex::new(
                crate::telegram_bridge::TicketGateRegistry::default(),
            )),
            github_actions: None,
            approvals: None,
            approval_lane: None,
            question_answerer: Some(Box::new(FakeQuestionAnswerer {
                seen: Arc::clone(&seen),
            })),
        };
        let mut event = ticket_event(
            "U0ADMIN001",
            "<@B0APP> what do you know about webdesign29 and activ?",
            "EvQuestion",
        );
        event.app_mention = true;
        router.handle_with_context(event, "remembered context");
        let mut second = ticket_event(
            "U0MEMBER002",
            "<@B0APP> what do you know about activ?",
            "EvSecondActor",
        );
        second.app_mention = true;
        router.handle_with_context(second, "second remembered context");

        assert_eq!(
            seen.lock().expect("questions").as_slice(),
            [
                (
                    String::from("what do you know about webdesign29 and activ"),
                    String::from("remembered context"),
                    String::from("U0ADMIN001"),
                ),
                (
                    String::from("what do you know about activ"),
                    String::from("second remembered context"),
                    String::from("U0MEMBER002"),
                ),
            ]
        );
        assert_eq!(
            messages.lock().expect("messages").as_slice(),
            [
                String::from("Monique intelligent answer"),
                String::from("Monique intelligent answer"),
            ]
        );
    }

    #[test]
    fn slack_can_read_provider_instance_stats_by_question_or_command() {
        let poster = FakeTicketPoster::default();
        let messages = Arc::clone(&poster.messages);
        let mut router = SlackTicketRouter {
            poster,
            manage: Box::new(FakeManage::default()),
            manage_url: None,
            memory_tenant: String::from("primary"),
            channels: ChannelMap(vec![(
                name("ops"),
                ChannelId::new("C0RESERVED01").expect("channel"),
            )]),
            admins: vec![UserId::new("U0ADMIN001").expect("admin")],
            members: vec![UserId::new("U0ADMIN001").expect("member")],
            features: vec![
                SlackFeature::Approvals,
                SlackFeature::Conversation,
                SlackFeature::Commands,
            ],
            interactive_decisions: false,
            gates: Arc::new(std::sync::Mutex::new(
                crate::telegram_bridge::TicketGateRegistry::default(),
            )),
            github_actions: None,
            approvals: None,
            approval_lane: None,
            question_answerer: Some(Box::new(FakeProviderStatsAnswerer)),
        };
        let mut mention = ticket_event(
            "U0ADMIN001",
            "<@B0APP> montre les running Codex instances",
            "EvAgents",
        );
        mention.app_mention = true;
        router.handle_with_context(mention, "");
        router.handle_monique_command(
            SlackMoniqueCommand {
                team_id: String::from("T0RESERVED"),
                channel: ChannelId::new("C0RESERVED01").expect("channel"),
                user: UserId::new("U0ADMIN001").expect("admin"),
                source_key: String::from("slack:command:agents"),
                text: String::from("agents"),
            },
            "",
        );
        assert_eq!(messages.lock().expect("messages").len(), 2);
        assert!(
            messages
                .lock()
                .expect("messages")
                .iter()
                .all(|message| message.contains("codex: live 2 | recorded 5"))
        );
    }

    #[test]
    fn github_status_mentions_read_once_and_never_enter_ticket_intake() {
        let poster = FakeTicketPoster::default();
        let messages = Arc::clone(&poster.messages);
        let manage = FakeManage::default();
        let opened = Arc::clone(&manage.opened);
        let issue_reads = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut router = SlackTicketRouter {
            poster,
            manage: Box::new(manage),
            manage_url: None,
            memory_tenant: String::from("primary"),
            channels: ChannelMap(vec![(
                name("ops"),
                ChannelId::new("C0RESERVED01").expect("channel"),
            )]),
            admins: vec![UserId::new("U0ADMIN001").expect("admin")],
            members: vec![UserId::new("U0ADMIN001").expect("member")],
            features: vec![SlackFeature::Approvals, SlackFeature::Conversation],
            interactive_decisions: false,
            gates: Arc::new(std::sync::Mutex::new(
                crate::telegram_bridge::TicketGateRegistry::default(),
            )),
            github_actions: None,
            approvals: None,
            approval_lane: None,
            question_answerer: Some(Box::new(FakeIssueStatusAnswerer {
                seen: Arc::clone(&issue_reads),
            })),
        };
        let text =
            "<@U0MONIQUE9> https://github.com/example/project/issues/42 il est fait celui là ?";

        // Slack's broad message subscription copy carries the same mention of
        // the bot (the envelope's authorized user) but is not the event that
        // owns conversational routing.
        router.handle_with_context(ticket_event("U0ADMIN001", text, "EvMessageCopy"), "");
        assert!(messages.lock().expect("messages").is_empty());
        assert!(opened.lock().expect("opened").is_empty());

        let mut mention = ticket_event("U0ADMIN001", text, "EvMentionCopy");
        mention.app_mention = true;
        router.handle_with_context(mention, "");

        assert_eq!(
            issue_reads.lock().expect("issue reads").as_slice(),
            [String::from("https://github.com/example/project/issues/42")]
        );
        assert_eq!(
            messages.lock().expect("messages").as_slice(),
            [String::from("No — GitHub still marks this issue as open.")]
        );
        assert!(opened.lock().expect("opened").is_empty());
    }

    #[test]
    fn github_comment_permalink_completion_question_reads_delivery_detail() {
        let poster = FakeTicketPoster::default();
        let messages = Arc::clone(&poster.messages);
        let manage = FakeManage::default();
        let opened = Arc::clone(&manage.opened);
        let issue_reads = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut router = SlackTicketRouter {
            poster,
            manage: Box::new(manage),
            manage_url: None,
            memory_tenant: String::from("primary"),
            channels: ChannelMap(vec![(
                name("ops"),
                ChannelId::new("C0RESERVED01").expect("channel"),
            )]),
            admins: vec![UserId::new("U0ADMIN001").expect("admin")],
            members: vec![UserId::new("U0ADMIN001").expect("member")],
            features: vec![SlackFeature::Approvals, SlackFeature::Conversation],
            interactive_decisions: false,
            gates: Arc::new(std::sync::Mutex::new(
                crate::telegram_bridge::TicketGateRegistry::default(),
            )),
            github_actions: None,
            approvals: None,
            approval_lane: None,
            question_answerer: Some(Box::new(FakeIssueReviewAnswerer {
                seen: Arc::clone(&issue_reads),
            })),
        };
        let mut mention = ticket_event(
            "U0ADMIN001",
            "<@B0APP> did you do https://github.com/example/project/issues/42#issuecomment-5325231229 ?",
            "EvCommentStatus",
        );
        mention.app_mention = true;
        router.handle_with_context(mention, "");

        assert_eq!(
            issue_reads.lock().expect("issue reads").as_slice(),
            [(
                String::from("https://github.com/example/project/issues/42"),
                String::from(
                    "did you do https://github.com/example/project/issues/42#issuecomment-5325231229"
                ),
                true,
            )]
        );
        assert_eq!(
            messages.lock().expect("messages").as_slice(),
            [String::from("Typed GitHub issue review")]
        );
        assert!(opened.lock().expect("opened").is_empty());
    }

    #[test]
    fn progress_follow_up_reads_the_manage_job_bound_to_the_slack_thread() {
        let poster = FakeTicketPoster::default();
        let messages = Arc::clone(&poster.messages);
        let manage = FakeManage {
            status: Some(running_ticket_status()),
            ..FakeManage::default()
        };
        let status_reads = Arc::clone(&manage.status_reads);
        let mut router = SlackTicketRouter {
            poster,
            manage: Box::new(manage),
            manage_url: None,
            memory_tenant: String::from("primary"),
            channels: ChannelMap(vec![(
                name("ops"),
                ChannelId::new("C0RESERVED01").expect("channel"),
            )]),
            admins: vec![UserId::new("U0ADMIN001").expect("admin")],
            members: vec![UserId::new("U0ADMIN001").expect("member")],
            features: vec![SlackFeature::Approvals, SlackFeature::Conversation],
            interactive_decisions: false,
            gates: Arc::new(std::sync::Mutex::new(
                crate::telegram_bridge::TicketGateRegistry::default(),
            )),
            github_actions: None,
            approvals: None,
            approval_lane: None,
            question_answerer: Some(Box::new(FakeIssueReviewAnswerer {
                seen: Arc::new(std::sync::Mutex::new(Vec::new())),
            })),
        };

        router.handle_with_context(
            ticket_event(
                "U0ADMIN001",
                "https://github.com/example/project/issues/42",
                "EvOpen",
            ),
            "",
        );
        router.handle_with_context(
            ticket_event("U0ADMIN001", "confirm job-fixture", "EvConfirm"),
            "",
        );
        let mut follow_up = ticket_event(
            "U0ADMIN001",
            "<@U0MONIQUE9> how's it progressing ?",
            "EvProgress",
        );
        follow_up.app_mention = true;
        router.handle_with_context(follow_up, "thread context");

        assert_eq!(
            status_reads.lock().expect("status reads").as_slice(),
            [String::from("job-fixture-123456")]
        );
        let messages = messages.lock().expect("messages");
        let progress = messages.last().expect("progress reply");
        assert!(progress.starts_with("🔄 Running\n"));
        assert!(progress.contains("Monique job `job-fixture-` is running."));
        assert!(progress.contains("Last updated: 2026-08-17T20:54:00Z"));
        assert!(progress.contains("Implementing the requested change."));
        assert!(!progress.contains("GitHub still marks this issue as open"));
    }

    #[test]
    fn terminal_ticket_status_mentions_the_requester_and_links_the_completion_comment_once() {
        let poster = FakeTicketPoster::default();
        let messages = Arc::clone(&poster.messages);
        let manage = FakeManage {
            status: Some(done_ticket_status()),
            ..FakeManage::default()
        };
        let status_reads = Arc::clone(&manage.status_reads);
        let mut router = SlackTicketRouter {
            poster,
            manage: Box::new(manage),
            manage_url: None,
            memory_tenant: String::from("primary"),
            channels: ChannelMap(vec![(
                name("ops"),
                ChannelId::new("C0RESERVED01").expect("channel"),
            )]),
            admins: vec![UserId::new("U0ADMIN001").expect("admin")],
            members: vec![UserId::new("U0REQUEST01").expect("member")],
            features: vec![SlackFeature::Approvals, SlackFeature::Conversation],
            interactive_decisions: false,
            gates: Arc::new(std::sync::Mutex::new(
                crate::telegram_bridge::TicketGateRegistry::default(),
            )),
            github_actions: None,
            approvals: None,
            approval_lane: None,
            question_answerer: None,
        };

        router.handle_with_context(
            ticket_event(
                "U0REQUEST01",
                "https://github.com/example/project/issues/42",
                "EvCompletion",
            ),
            "",
        );
        router.poll_ticket_notifications();
        router.poll_ticket_notifications();

        assert_eq!(
            status_reads.lock().expect("status reads").as_slice(),
            [String::from("job-fixture-123456")]
        );
        let messages = messages.lock().expect("messages");
        let completions: Vec<_> = messages
            .iter()
            .filter(|message| message.contains("Monique completed the ticket work"))
            .collect();
        assert_eq!(completions.len(), 1, "one completion reply: {messages:?}");
        let completion = completions[0];
        assert!(completion.starts_with("✅ Completed\n"));
        assert!(completion.contains("<@U0REQUEST01>"));
        assert!(completion.contains(
            "<https://github.com/example/project/issues/42#issuecomment-9001|View the completion summary on GitHub>"
        ));
        assert!(completion.contains("Monique job `job-fixture-` is done."));
    }

    #[test]
    fn typed_github_issue_facts_render_done_from_state() {
        let locator =
            IssueLocator::parse("https://github.com/example/project/issues/42").expect("locator");
        let answer = github_issue_status_answer(
            &locator,
            "status=available\nstate=closed\ntitle_untrusted=Delivered change\nupdated=2026-08-16T22:00:00Z",
        );
        assert!(answer.starts_with("Yes — GitHub marks this issue as closed."));
        assert!(answer.contains("example/project#42"));
        assert!(!answer.contains("Delivered change"));
    }

    #[test]
    fn issue_review_is_read_only_while_run_opens_a_confirmation_gate() {
        let poster = FakeTicketPoster::default();
        let messages = Arc::clone(&poster.messages);
        let manage = FakeManage::default();
        let opened = Arc::clone(&manage.opened);
        let reviews = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut router = SlackTicketRouter {
            poster,
            manage: Box::new(manage),
            manage_url: None,
            memory_tenant: String::from("primary"),
            channels: ChannelMap(vec![(
                name("ops"),
                ChannelId::new("C0RESERVED01").expect("channel"),
            )]),
            admins: vec![UserId::new("U0ADMIN001").expect("admin")],
            members: vec![UserId::new("U0ADMIN001").expect("member")],
            features: vec![SlackFeature::Approvals, SlackFeature::Conversation],
            interactive_decisions: false,
            gates: Arc::new(std::sync::Mutex::new(
                crate::telegram_bridge::TicketGateRegistry::default(),
            )),
            github_actions: None,
            approvals: None,
            approval_lane: None,
            question_answerer: Some(Box::new(FakeIssueReviewAnswerer {
                seen: Arc::clone(&reviews),
            })),
        };
        const ISSUE: &str = "https://github.com/example/company-manager/issues/1212";

        router.handle_with_context(
            ticket_event("U0ADMIN001", &format!("review {ISSUE}"), "EvReview"),
            "thread context",
        );
        router.handle_with_context(
            ticket_event("U0ADMIN001", &format!("check {ISSUE}"), "EvCheck"),
            "thread context",
        );
        assert!(opened.lock().expect("opened").is_empty());
        assert_eq!(reviews.lock().expect("reviews").len(), 2);
        assert!(
            messages
                .lock()
                .expect("messages")
                .iter()
                .all(|message| message == "Typed GitHub issue review")
        );

        router.handle_with_context(
            ticket_event("U0ADMIN001", &format!("run {ISSUE}"), "EvRun"),
            "thread context",
        );
        assert_eq!(opened.lock().expect("opened").len(), 1);
        assert!(
            messages
                .lock()
                .expect("messages")
                .iter()
                .any(|message| message.contains("Confirmation required"))
        );
    }

    #[test]
    fn issue_recap_follow_up_reuses_the_threads_single_github_url() {
        let poster = FakeTicketPoster::default();
        let messages = Arc::clone(&poster.messages);
        let manage = FakeManage::default();
        let opened = Arc::clone(&manage.opened);
        let reviews = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut router = SlackTicketRouter {
            poster,
            manage: Box::new(manage),
            manage_url: None,
            memory_tenant: String::from("primary"),
            channels: ChannelMap(vec![(
                name("ops"),
                ChannelId::new("C0RESERVED01").expect("channel"),
            )]),
            admins: vec![UserId::new("U0ADMIN001").expect("admin")],
            members: vec![UserId::new("U0ADMIN001").expect("member")],
            features: vec![SlackFeature::Conversation],
            interactive_decisions: false,
            gates: Arc::new(std::sync::Mutex::new(
                crate::telegram_bridge::TicketGateRegistry::default(),
            )),
            github_actions: None,
            approvals: None,
            approval_lane: None,
            question_answerer: Some(Box::new(FakeIssueReviewAnswerer {
                seen: Arc::clone(&reviews),
            })),
        };
        let mut follow_up = ticket_event(
            "U0ADMIN001",
            "<@B0APP> peux tu faire un récap de la demande ?",
            "EvRecap",
        );
        follow_up.app_mention = true;

        router.handle_with_context(
            follow_up,
            "user: <@B0APP> https://github.com/webdesign29/activ-erepas/issues/3027 il est fait celui là ?\nassistant: GitHub marks it closed.",
        );

        assert!(opened.lock().expect("opened").is_empty());
        assert_eq!(
            reviews.lock().expect("reviews").as_slice(),
            [(
                String::from("https://github.com/webdesign29/activ-erepas/issues/3027"),
                String::from("peux tu faire un récap de la demande"),
                true,
            )]
        );
        assert_eq!(
            messages.lock().expect("messages").as_slice(),
            [String::from("Typed GitHub issue review")]
        );
    }

    #[test]
    fn issue_recap_follow_up_does_not_guess_between_thread_urls() {
        let context = "user: compare https://github.com/example/one/issues/1 and https://github.com/example/two/issues/2";
        assert_eq!(
            contextual_github_issue_review("fais un récap de la demande", context),
            None
        );
    }

    #[test]
    fn unmentioned_thread_replies_continue_a_durable_monique_conversation() {
        let root = tempfile::tempdir().expect("memory root");
        std::fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("private memory root");
        let mut memory =
            AgentMemoryStore::open(root.path().join("agent-memory.sqlite3")).expect("memory store");
        let poster = FakeTicketPoster::default();
        let messages = Arc::clone(&poster.messages);
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut router = SlackTicketRouter {
            poster,
            manage: Box::new(FakeManage::default()),
            manage_url: None,
            memory_tenant: String::from("primary"),
            channels: ChannelMap(vec![(
                name("ops"),
                ChannelId::new("C0RESERVED01").expect("channel"),
            )]),
            admins: vec![UserId::new("U0ADMIN001").expect("admin")],
            members: vec![UserId::new("U0ADMIN001").expect("member")],
            features: vec![SlackFeature::Conversation],
            interactive_decisions: false,
            gates: Arc::new(std::sync::Mutex::new(
                crate::telegram_bridge::TicketGateRegistry::default(),
            )),
            github_actions: None,
            approvals: None,
            approval_lane: None,
            question_answerer: Some(Box::new(FakeQuestionAnswerer {
                seen: Arc::clone(&seen),
            })),
        };
        let mut mention = ticket_event("U0ADMIN001", "<@B0APP> tell me about activ", "EvRoot");
        mention.app_mention = true;
        router
            .capture_memory(&mut memory, &mention)
            .expect("mention captured");

        let actor = "slack:T0RESERVED:U0ADMIN001";
        let head = memory
            .current_conversation(
                "primary",
                actor,
                "slack",
                "channel:C0RESERVED01:thread:1723542000.000100",
            )
            .expect("head lookup")
            .expect("conversation head");
        assert!(head.starts_with("slack-monique:"));

        let mut follow_up = ticket_event("U0ADMIN001", "and webdesign29?", "EvFollowUp");
        follow_up.in_thread = true;
        follow_up.continues_conversation = router
            .conversation_follow_up(&memory, &follow_up)
            .expect("follow-up classification");
        assert!(follow_up.continues_conversation);
        router
            .capture_memory(&mut memory, &follow_up)
            .expect("follow-up captured");
        let context = slack_event_context(&memory, "primary", &follow_up);
        router.handle_with_context(follow_up, &context);

        let seen = seen.lock().expect("questions");
        assert_eq!(seen[0].0, "and webdesign29?");
        assert!(seen[0].1.contains("tell me about activ"));
        assert!(seen[0].1.contains("and webdesign29?"));
        assert_eq!(seen[0].2, "U0ADMIN001");
        assert_eq!(
            messages.lock().expect("messages").as_slice(),
            [String::from("Monique intelligent answer")]
        );
    }

    #[test]
    fn old_app_mention_threads_are_recognized_without_admitting_unrelated_threads() {
        let root = tempfile::tempdir().expect("memory root");
        std::fs::set_permissions(
            root.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("private memory root");
        let mut memory =
            AgentMemoryStore::open(root.path().join("agent-memory.sqlite3")).expect("memory store");
        let router = SlackTicketRouter {
            poster: FakeTicketPoster::default(),
            manage: Box::new(FakeManage::default()),
            manage_url: None,
            memory_tenant: String::from("primary"),
            channels: ChannelMap(vec![(
                name("ops"),
                ChannelId::new("C0RESERVED01").expect("channel"),
            )]),
            admins: vec![UserId::new("U0ADMIN001").expect("admin")],
            members: vec![UserId::new("U0ADMIN001").expect("member")],
            features: vec![SlackFeature::Conversation],
            interactive_decisions: false,
            gates: Arc::new(std::sync::Mutex::new(
                crate::telegram_bridge::TicketGateRegistry::default(),
            )),
            github_actions: None,
            approvals: None,
            approval_lane: None,
            question_answerer: None,
        };

        // Reproduce the identifier written by the release that received the
        // user's already-open thread, before app mentions were marked.
        let old_mention = ticket_event("U0ADMIN001", "hello <@B0APP>?", "EvOldRoot");
        router
            .capture_memory(&mut memory, &old_mention)
            .expect("old mention captured");
        let mut old_follow_up = ticket_event("U0ADMIN001", "are you there?", "EvOldReply");
        old_follow_up.in_thread = true;
        assert!(
            router
                .conversation_follow_up(&memory, &old_follow_up)
                .expect("old follow-up classification")
        );

        let mut unrelated_root = ticket_event("U0ADMIN001", "team status", "EvOtherRoot");
        unrelated_root.parent = MessageTs::new("1723542999.000900").expect("timestamp");
        router
            .capture_memory(&mut memory, &unrelated_root)
            .expect("unrelated root captured");
        let mut unrelated_reply = ticket_event("U0ADMIN001", "looks good", "EvOtherReply");
        unrelated_reply.parent = unrelated_root.parent;
        unrelated_reply.in_thread = true;
        assert!(
            !router
                .conversation_follow_up(&memory, &unrelated_reply)
                .expect("unrelated classification")
        );
    }

    #[test]
    fn slack_greetings_do_not_bypass_the_conversation_surface() {
        let poster = FakeTicketPoster::default();
        let messages = Arc::clone(&poster.messages);
        let mut router = SlackTicketRouter {
            poster,
            manage: Box::new(FakeManage::default()),
            manage_url: None,
            memory_tenant: String::from("primary"),
            channels: ChannelMap(vec![(
                name("ops"),
                ChannelId::new("C0RESERVED01").expect("channel"),
            )]),
            admins: vec![UserId::new("U0ADMIN001").expect("admin")],
            members: vec![UserId::new("U0ADMIN001").expect("member")],
            features: vec![SlackFeature::Conversation],
            interactive_decisions: false,
            gates: Arc::new(std::sync::Mutex::new(
                crate::telegram_bridge::TicketGateRegistry::default(),
            )),
            github_actions: None,
            approvals: None,
            approval_lane: None,
            question_answerer: None,
        };
        let mut event = ticket_event("U0ADMIN001", "hello <@B0APP>?", "EvHello");
        event.app_mention = true;
        router.handle_with_context(event, "");

        let messages = messages.lock().expect("messages");
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("conversational tool surface is unavailable"));
    }

    #[test]
    fn approval_buttons_and_required_reason_submissions_are_typed() {
        let approve = r#"{"type":"interactive","payload":{"type":"block_actions","team":{"id":"T0RESERVED"},"user":{"id":"U0ADMIN001"},"channel":{"id":"C0RESERVED01"},"container":{"message_ts":"1723542000.000100"},"trigger_id":"1337.abc","actions":[{"action_id":"monique_ticket_approve","action_ts":"1723542001.000200","value":"job-fixture-123456"}]}}"#;
        let parsed = slack_ticket_interaction(approve)
            .expect("valid action")
            .expect("interaction");
        assert_eq!(parsed.job_id, "job-fixture-123456");
        assert!(matches!(parsed.kind, SlackTicketInteractionKind::Approve));

        let reject = r#"{"type":"interactive","payload":{"type":"view_submission","team":{"id":"T0RESERVED"},"user":{"id":"U0ADMIN001"},"view":{"id":"V01","hash":"h01","callback_id":"monique_ticket_reject_submit","private_metadata":"{\"job_id\":\"job-fixture-123456\",\"channel_id\":\"C0RESERVED01\",\"message_ts\":\"1723542000.000100\"}","state":{"values":{"reason":{"value":{"type":"plain_text_input","value":"Not approved for release"}}}}}}}"#;
        let parsed = slack_ticket_interaction(reject)
            .expect("valid submission")
            .expect("interaction");
        assert!(matches!(
            parsed.kind,
            SlackTicketInteractionKind::RejectSubmit { ref reason }
                if reason == "Not approved for release"
        ));

        let missing_reason = reject.replace("Not approved for release", "");
        assert!(slack_ticket_interaction(&missing_reason).is_err());
    }

    #[test]
    fn app_home_open_is_scoped_to_the_home_tab_user() {
        let frame = r#"{"type":"events_api","payload":{"type":"event_callback","team_id":"T0RESERVED","event":{"type":"app_home_opened","user":"U0ADMIN001","tab":"home"}}}"#;
        assert_eq!(
            slack_app_home_user(frame)
                .expect("event")
                .map(|user| user.as_str().to_owned()),
            Some(String::from("U0ADMIN001"))
        );
        assert!(
            slack_app_home_user(&frame.replace("\"home\"", "\"messages\""))
                .expect("messages tab")
                .is_none()
        );
    }

    #[test]
    fn github_slash_commands_are_typed_without_using_ticket_intake_grammar() {
        let channels = ChannelMap(vec![(
            name("ops"),
            ChannelId::new("C0RESERVED01").expect("channel"),
        )]);
        let admins = vec![UserId::new("U0ADMIN001").expect("admin")];
        let frame = r#"{"accepts_response_payload":true,"envelope_id":"E3","payload":{"channel_id":"C0RESERVED01","command":"/github_reply","team_id":"T0RESERVED","text":"https://github.com/example/project/issues/42 post the verification result","trigger_id":"13345224609.abc123","user_id":"U0ADMIN001"},"type":"slash_commands"}"#;
        let command = slack_github_command(frame, &channels, &admins)
            .expect("valid frame")
            .expect("admitted command");
        assert_eq!(
            command.request,
            GitHubActionRequest::Reply {
                issue_url: String::from("https://github.com/example/project/issues/42"),
                instruction: String::from("post the verification result"),
            }
        );
        assert!(command.source_key.contains(":command:"));

        let denied = frame.replace("U0ADMIN001", "U0REQUEST01");
        assert!(
            slack_github_command(&denied, &channels, &admins)
                .expect("content-free denial")
                .is_none()
        );
    }

    #[test]
    fn unified_monique_command_is_channel_scoped_and_keeps_a_stable_source_key() {
        let channels = ChannelMap(vec![(
            name("ops"),
            ChannelId::new("C0RESERVED01").expect("channel"),
        )]);
        let frame = r#"{"accepts_response_payload":true,"envelope_id":"E4","payload":{"channel_id":"C0RESERVED01","command":"/monique","team_id":"T0RESERVED","text":"help","trigger_id":"13345224609.abc124","user_id":"U0MEMBER001"},"type":"slash_commands"}"#;
        let command = slack_monique_command(frame, &channels)
            .expect("frame")
            .expect("command");
        assert_eq!(command.text, "help");
        assert_eq!(command.user.as_str(), "U0MEMBER001");
        assert_eq!(
            command.source_key,
            "slack:automonique-slack:T0RESERVED:C0RESERVED01:command:13345224609.abc124"
        );
        assert!(
            slack_monique_command(&frame.replace("C0RESERVED01", "C0OTHER00001"), &channels)
                .expect("outside channel")
                .is_none()
        );
    }

    #[test]
    fn a_plain_admin_issue_url_is_summarized_and_opens_a_confirmation_gate() {
        let poster = FakeTicketPoster::default();
        let messages = Arc::clone(&poster.messages);
        let manage = FakeManage {
            canonical_source: Some(String::from("slack:T0RESERVED:event:EvFixture")),
            ..FakeManage::default()
        };
        let opened = Arc::clone(&manage.opened);
        let reviews = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut router = SlackTicketRouter {
            poster,
            manage: Box::new(manage),
            manage_url: None,
            memory_tenant: String::from("primary"),
            channels: ChannelMap(vec![(
                name("ops"),
                ChannelId::new("C0RESERVED01").expect("channel"),
            )]),
            admins: vec![UserId::new("U0ADMIN001").expect("admin")],
            members: vec![UserId::new("U0ADMIN001").expect("member")],
            features: vec![SlackFeature::Approvals, SlackFeature::Conversation],
            interactive_decisions: false,
            gates: Arc::new(std::sync::Mutex::new(
                crate::telegram_bridge::TicketGateRegistry::default(),
            )),
            github_actions: None,
            approvals: None,
            approval_lane: None,
            question_answerer: Some(Box::new(FakeIssueReviewAnswerer {
                seen: Arc::clone(&reviews),
            })),
        };
        router.handle_with_context(
            ticket_event(
                "U0ADMIN001",
                "https://github.com/example/project/issues/42",
                "EvPlain",
            ),
            "",
        );
        assert_eq!(opened.lock().expect("opened").len(), 1);
        let gates = router.gates.lock().expect("gates");
        let pending = gates.matching("job-fixture");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].source_key, "slack:T0RESERVED:event:EvFixture");
        drop(gates);
        let reviews = reviews.lock().expect("reviews");
        assert_eq!(reviews.len(), 1);
        assert_eq!(reviews[0].0, "https://github.com/example/project/issues/42");
        assert!(reviews[0].1.contains("confirmation card follows"));
        assert!(reviews[0].1.contains("Do not ask what to do next"));
        assert!(reviews[0].2);
        let messages = messages.lock().expect("messages");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0], "Typed GitHub issue review");
        assert!(messages[1].contains("Confirmation required"));
        assert!(messages[1].contains("No work starts before confirmation"));
    }

    #[test]
    fn a_short_work_follow_up_uses_the_threads_exact_issue_target() {
        let poster = FakeTicketPoster::default();
        let messages = Arc::clone(&poster.messages);
        let manage = FakeManage::default();
        let opened = Arc::clone(&manage.opened);
        let mut router = SlackTicketRouter {
            poster,
            manage: Box::new(manage),
            manage_url: None,
            memory_tenant: String::from("primary"),
            channels: ChannelMap(vec![(
                name("ops"),
                ChannelId::new("C0RESERVED01").expect("channel"),
            )]),
            admins: vec![UserId::new("U0ADMIN001").expect("admin")],
            members: vec![UserId::new("U0ADMIN001").expect("member")],
            features: vec![SlackFeature::Approvals, SlackFeature::Conversation],
            interactive_decisions: false,
            gates: Arc::new(std::sync::Mutex::new(
                crate::telegram_bridge::TicketGateRegistry::default(),
            )),
            github_actions: None,
            approvals: None,
            approval_lane: None,
            question_answerer: None,
        };
        let mut follow_up = ticket_event("U0ADMIN001", "do it", "EvDoIt");
        follow_up.in_thread = true;
        follow_up.continues_conversation = true;
        router.handle_with_context(
            follow_up,
            "user: https://github.com/example/project/issues/42\nassistant: issue summary",
        );

        assert_eq!(
            opened.lock().expect("opened").as_slice(),
            [(
                String::from("https://github.com/example/project/issues/42"),
                String::from("slack:T0RESERVED:event:EvDoIt"),
            )]
        );
        let messages = messages.lock().expect("messages");
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("Confirmation required"));
    }

    #[test]
    fn an_unavailable_executor_is_reported_without_claiming_release() {
        assert_eq!(
            ticket_approval_failure("executor_unavailable"),
            "Manage has no live code-execution worker for this ticket. The gate remains pending and no work was released."
        );
        assert_eq!(
            ticket_approval_failure("source_mismatch"),
            "Manage linked this confirmation to a different pending request. The gate remains pending and no work was released."
        );
        assert_eq!(
            ticket_approval_failure("manage_unavailable"),
            "Manage's decision endpoint was unavailable or timed out. The gate remains pending and no work was released."
        );
        assert_eq!(
            ticket_approval_failure("approval_expired"),
            "This confirmation expired before Manage accepted it. Post the issue URL again to create a fresh gate; no work was released."
        );
        assert_eq!(
            ticket_approval_failure("job_not_pending"),
            "Manage refused the approval with reason `job_not_pending`. The gate remains pending and no work was released."
        );
    }

    #[test]
    fn a_failed_button_decision_replaces_the_card_with_an_actionable_error() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("temporary directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure temporary directory");
        let mut store = SlackInteractionStore::open(directory.path().join("interactions.sqlite3"))
            .expect("interaction store");
        let mut router =
            decide_gate_router(true, vec![SlackFeature::Approvals], vec!["U0ADMIN001"]);
        router
            .gates
            .lock()
            .expect("gates")
            .register(crate::telegram_bridge::PendingTicketGate {
                job_id: String::from("job-fixture-123456"),
                issue_url: String::from("https://github.com/example/project/issues/42"),
                source_key: String::from("slack:T0RESERVED:event:EvFixture"),
            })
            .expect("registered gate");
        let prepared = router
            .prepare_interaction(
                SlackTicketInteraction {
                    interaction_key: String::from(
                        "slack-action:T0RESERVED:C0RESERVED01:1723542000.000100:U0ADMIN001:approve",
                    ),
                    team_id: String::from("T0RESERVED"),
                    channel: ChannelId::new("C0RESERVED01").expect("channel"),
                    message_ts: MessageTs::new("1723542000.000100").expect("timestamp"),
                    user: UserId::new("U0ADMIN001").expect("user"),
                    job_id: String::from("job-fixture-123456"),
                    kind: SlackTicketInteractionKind::Approve,
                },
                &mut store,
            )
            .expect("prepared interaction")
            .expect("accepted interaction");

        router.handle_interaction(prepared, &mut store);

        let messages = router.poster.messages.lock().expect("messages");
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("Approval failed"));
        assert!(messages[0].contains("ticket_decisions_unavailable"));
        assert!(messages[0].contains("remains pending"));
        assert!(messages[0].contains("/monique approve job-fixture"));
    }
}
