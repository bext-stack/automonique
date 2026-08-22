// SPDX-License-Identifier: Elastic-2.0

//! `automonique ask`: the conversational question path, from a terminal.
//!
//! The same router, baseline brief, read plans and answer lanes the Telegram
//! and Slack surfaces use, driven against this host's live state and the
//! running daemon's run lane, with no transport attached: nothing is sent to
//! Telegram or Slack, nothing is remembered, and a tool the router selects is
//! reported rather than staged. It exists so an operator can see what Monique
//! would say to a question before anyone types it into a chat, and so a
//! change to the router can be checked against real facts and the real model
//! instead of against a fixture.
//!
//! Escalations are the one plan that may be followed: `approve_escalation`
//! runs the deeper lane exactly as an approved card would, because its only
//! effect is a read on this host.

use std::path::Path;
use std::sync::Arc;

use crate::run_lane::SocketRunLane;
use crate::telegram_bridge::{
    HostFacts, QuestionEscalation, SlackSurface, StoreControlSurface,
    TransportConversationIdentity, TransportLiveSeams, TransportToolPlan,
    answer_approved_escalation, answer_read_only_transport_question,
};

/// What one question produced.
#[derive(Debug)]
pub struct AskOutcome {
    /// The reply the chat surface would have posted.
    pub answer: String,
    /// The tool or escalation the router selected, described for a terminal,
    /// when it selected one. Nothing in it ran.
    pub selected: Option<String>,
}

/// Everything `ask` needs from the host, opened once.
pub struct AskHost {
    surface: StoreControlSurface,
    lane: SocketRunLane,
    github: Option<Box<dyn crate::github::GitHubSurface + Send>>,
    github_configured: bool,
    slack: Option<Box<dyn SlackSurface + Send>>,
    mcp: crate::mcp_client::McpRegistry,
    administrators: Vec<i64>,
    configured: Vec<i64>,
    /// Configured Slack channel labels, so the router may select a Slack
    /// read exactly as it can from a chat; nothing is posted from here.
    slack_channels: Vec<String>,
    /// The escalation the last question asked permission for, if any.
    pending: Option<QuestionEscalation>,
}

impl AskHost {
    /// Open the question path over `config`'s state directory and the running
    /// daemon's admin socket.
    ///
    /// Every integration is optional in the same way it is for the chat
    /// surfaces: an absent GitHub or MCP configuration narrows what the router
    /// may select, it does not refuse the question.
    pub fn open(config: &crate::DaemonConfig) -> Result<Self, &'static str> {
        let state_dir = config.state_dir();
        let run_index_path = config.run_index_path();
        let (administrators, configured) = crate::telegram::TelegramBotConfig::load(&state_dir)
            .map_err(|_| "telegram_config_refused")?
            .map(|bot| bot.question_operator_ids())
            .unwrap_or_default();
        let bot_id = crate::telegram::TelegramBotConfig::load(&state_dir)
            .ok()
            .flatten()
            .map_or(0, |bot| bot.bot_id());
        let surface = StoreControlSurface::open_with_lease_time_source(
            &config.database_path(),
            &run_index_path,
            HostFacts {
                generation_id: crate::GENERATION_ID.to_owned(),
                holder_id: String::from("ask-cli"),
                lease_epoch: 0,
                bot_id,
                execution_state:
                    automonique_protocol::admin::ExecutionState::SandboxUnavailableLaneWired,
            },
            Arc::new(crate::lease_time::BootTimeSource),
        )
        .map_err(|_| "control_surface_unavailable")?
        .with_support_tickets(&config.support_tickets_path())
        .with_operator_members(&config.operator_members_path())
        .with_prism_sites(Path::new(crate::site_inventory::NGINX_SITES_ENABLED))
        .with_local_knowledge(&crate::local_knowledge::catalog_path(&state_dir))
        .with_provider_state(&state_dir);
        let surface = match crate::manage_config::ManageConfig::load(&state_dir)
            .ok()
            .flatten()
            .and_then(|manage| manage.profile_app().cloned())
        {
            Some(profile) => surface.with_manage_profiles(profile),
            None => surface,
        };
        let lane = SocketRunLane::open(&state_dir, &config.admin_socket(), &run_index_path)
            .map_err(|_| "run_lane_unavailable")?;
        let github = crate::github::GitHubHost::load(&state_dir)
            .map_err(|_| "github_config_refused")?
            .into_surface();
        let github_configured = github.is_some();
        let slack = crate::slack::SlackHost::open(&state_dir)
            .map_err(|_| "slack_config_refused")?
            .into_surface();
        let slack_channels = crate::slack::SlackConfig::load(&state_dir)
            .ok()
            .flatten()
            .map(|slack| {
                slack
                    .channels()
                    .labels()
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mcp =
            crate::mcp_client::McpRegistry::load(&state_dir).map_err(|_| "mcp_config_refused")?;
        Ok(Self {
            surface,
            lane,
            github,
            github_configured,
            slack,
            mcp,
            administrators,
            configured,
            slack_channels,
            pending: None,
        })
    }

    /// Exercise the run lane once with a trivial fast-lane task and report the
    /// lane's own failure category, for diagnosing a host where every answer
    /// comes back as "could not start".
    pub fn probe_lane(&mut self) -> Result<String, String> {
        use crate::telegram_bridge::{QuestionProfile, RunLane as _};
        self.lane
            .run_question(
                "Reply with the single word: pong",
                QuestionProfile::Conversation,
            )
            .map_err(|failure| format!("{failure:?}"))
    }

    /// Answer one question as the chat surfaces would, with `memory_context`
    /// standing in for the recent conversation (empty for a cold question).
    pub fn ask(&mut self, question: &str, memory_context: &str) -> AskOutcome {
        let mcp_tools = self.mcp.discover().unwrap_or_default();
        let mut selected_tool = None;
        let answer = answer_read_only_transport_question(
            &mut self.surface,
            &mut self.lane,
            TransportLiveSeams {
                slack: self
                    .slack
                    .as_deref_mut()
                    .map(|slack| slack as &mut dyn SlackSurface),
                github: self
                    .github
                    .as_deref_mut()
                    .map(|github| github as &mut dyn crate::github::GitHubSurface),
            },
            question,
            memory_context,
            TransportConversationIdentity {
                lane_key: "cli:ask",
                actor_key: "cli:operator",
                source_key: "cli:ask:current",
            },
            &self.administrators,
            &self.configured,
            None,
            &self.slack_channels,
            self.github_configured,
            &mcp_tools,
            &[],
            &mut selected_tool,
            "cli_ask",
        );
        self.pending = None;
        let selected = match selected_tool {
            None => None,
            Some(TransportToolPlan::SlackPost(post)) => Some(format!(
                "slack_post channel={} text={}",
                post.channel, post.text
            )),
            Some(TransportToolPlan::McpCall(call)) => Some(format!(
                "mcp_call server={} tool={} arguments={}",
                call.server, call.tool, call.arguments
            )),
            Some(TransportToolPlan::GitHubAction(request)) => {
                Some(format!("github_action {request:?}"))
            }
            Some(TransportToolPlan::Escalate(escalation)) => {
                let preview = escalation.plan.preview();
                self.pending = Some(escalation);
                Some(format!("escalate {preview}"))
            }
        };
        AskOutcome { answer, selected }
    }
}

/// [`AskHost`] with the last escalation the router asked permission for.
impl AskHost {
    /// Run the deeper lane for the escalation the last [`AskHost::ask`]
    /// produced, as an approved card would. `None` when there is none.
    pub fn approve_escalation(&mut self) -> Option<String> {
        let escalation = self.pending.take()?;
        Some(answer_approved_escalation(
            &mut self.surface,
            &mut self.lane,
            self.github
                .as_deref_mut()
                .map(|github| github as &mut dyn crate::github::GitHubSurface),
            &escalation,
            &self.administrators,
            &self.configured,
            "cli_ask",
        ))
    }
}
