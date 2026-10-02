// SPDX-License-Identifier: Elastic-2.0

//! The ticket work ledger, and the one place Slack ticket status reactions
//! are decided.
//!
//! The team channel reads two reactions on a message that posted a GitHub
//! ticket:
//!
//! - 👀 (`eyes`) — somebody has started on it: a Monique job reached
//!   `claimed` or `running`, or a local Claude Code session claimed it through
//!   `automonique ticket claim`.
//! - ✅ (`white_check_mark`) — it is verifiably finished: the Monique job
//!   reached `done` (the worker already validated its completion receipt), or
//!   GitHub itself says so (see [`delivery_finished`]). Never because a turn or
//!   a run ended.
//!
//! Before this module two writers reacted with the same bot: the daemon's
//! worker and a separate session hook. They disagreed, and the hook marked
//! unfinished tickets done. The daemon is now the single owner: sessions *ask*
//! through the local admin socket and the reactions follow from this ledger.
//!
//! # State, not events
//!
//! Reactions are derived, not emitted. [`TicketWorkLedger::pending_reactions`]
//! compares what the ledger says each recorded post should carry with what the
//! bot has already applied, and the reactor converges the difference a few
//! effects at a time. An intake path or a status poll therefore only records a
//! fact; it never has to remember to react, and a reaction lost to a transport
//! error is simply still pending on the next pass. `already_reacted` is
//! success, so a retry can never double-react.
//!
//! Only the bot's own reactions are ever touched, and only by adding: nothing
//! here removes a reaction, so a human's 👀 or ✅ is never disturbed.
//!
//! # The ledger file
//!
//! `ticket-work.v1.json` beside the other ticket registries in the daemon's
//! private state directory: owner-only, written atomically (temporary file,
//! `fsync`, rename, directory `fsync`), and bounded — at most
//! [`MAX_TICKETS`] tickets, [`MAX_POSTS_PER_TICKET`] posts and
//! [`MAX_CLAIMS_PER_TICKET`] claims each, and [`MAX_LEDGER_BYTES`] on disk.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use automonique_github_connector::{IssueLocator, IssueNumber, RepoTarget};
use automonique_slack_connector::{
    ChannelId, ConversationsHistoryRequest, MessageTs, ReactionChange, ReactionName,
    ReactionRequest, SlackClient, SlackOutcome,
};
use automonique_support_connector::TicketJobStatus;
use serde::{Deserialize, Serialize};

/// File name of the ledger inside the daemon's private state directory.
pub(crate) const TICKET_WORK_FILE: &str = "ticket-work.v1.json";
/// Exact schema marker of the ledger document.
const SCHEMA: &str = "automonique.ticket-work/v1";
/// Most tickets the ledger retains.
pub(crate) const MAX_TICKETS: usize = 256;
/// Most Slack posts recorded for one ticket.
pub(crate) const MAX_POSTS_PER_TICKET: usize = 16;
/// Most claims recorded for one ticket.
pub(crate) const MAX_CLAIMS_PER_TICKET: usize = 8;
/// Largest ledger document read or written.
pub(crate) const MAX_LEDGER_BYTES: usize = 1024 * 1024;
/// How often a released, unfinished ticket is checked against GitHub again.
pub(crate) const VERIFY_INTERVAL_MS: i64 = 10 * 60 * 1000;
/// How long a released, unfinished ticket stays queued before it is dropped.
pub(crate) const VERIFY_MAX_AGE_MS: i64 = 21 * 24 * 60 * 60 * 1000;
/// Most queued tickets one verification pass checks.
pub(crate) const VERIFY_PER_PASS: usize = 3;
/// How often a verification pass runs at all.
const VERIFY_PASS_INTERVAL_MS: i64 = 60 * 1000;
/// How often the reactor polls Manage for the jobs it is following.
const JOB_POLL_PASS_INTERVAL_MS: i64 = 15 * 1000;
/// The least time between two status reads of one job.
const JOB_POLL_MIN_INTERVAL_MS: i64 = 30 * 1000;
/// Most jobs one poll pass reads.
const JOBS_PER_PASS: usize = 4;
/// Consecutive unreadable statuses after which a job is no longer followed.
const MAX_JOB_READ_FAILURES: u8 = 60;
/// Most background reaction effects one reactor pass issues.
///
/// With [`REACTION_PASS_INTERVAL_MS`] this paces background reactions at 36
/// a minute, inside Slack's per-method budget for `reactions.add`, however
/// large a backlog a restart finds. A claim's own reactions are issued at once.
const REACTIONS_PER_PASS: usize = 3;
/// How often a background reaction pass runs.
const REACTION_PASS_INTERVAL_MS: i64 = 5 * 1000;
/// Slack refusals after which one reaction is no longer attempted.
const MAX_REACTION_ATTEMPTS: u8 = 3;
/// How long a Claude session's claim lasts without being renewed.
///
/// A session that dies without releasing must not hold a ticket forever: past
/// this the claim lapses and the ticket is queued for verification like any
/// other release.
pub(crate) const CLAUDE_CLAIM_TTL_MS: i64 = 12 * 60 * 60 * 1000;
/// Most configured channels one claim searches for an unrecorded post.
pub(crate) const MAX_CLAIM_SEARCH_CHANNELS: usize = 8;
/// Messages read from each searched channel.
pub(crate) const CLAIM_SEARCH_HISTORY: u16 = 100;
/// Most jobs one claim refreshes from Manage before reporting conflicts.
const MAX_CLAIM_JOB_REFRESH: usize = 4;
/// Longest Claude session coordinate a holder may carry.
pub(crate) const MAX_SESSION_BYTES: usize = 128;
/// Prefix of a Claude Code session holder.
pub(crate) const CLAUDE_HOLDER_PREFIX: &str = "claude:";
/// Prefix of a Monique job holder.
pub(crate) const MONIQUE_HOLDER_PREFIX: &str = "monique-job:";
/// Most claim requests queued for the reactor at once.
const MAX_QUEUED_CLAIMS: usize = 8;

/// Whether a ticket is an issue or a pull request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TicketKind {
    Issue,
    Pull,
}

impl TicketKind {
    const fn path_segment(self) -> &'static str {
        match self {
            Self::Issue => "issues",
            Self::Pull => "pull",
        }
    }
}

/// One GitHub ticket, independent of how a message spelled its URL.
///
/// Issues and pull requests share one number space per repository, so the
/// identity is `owner/repo#number`, compared case-insensitively the way GitHub
/// resolves it. The kind is a property recorded beside it rather than part of
/// the identity: Slack intake canonicalizes every link to `/issues/N`, and a
/// pull request reached that way must still be the same ticket a session
/// claimed by its `/pull/N` URL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TicketKey {
    target: RepoTarget,
    number: IssueNumber,
}

impl TicketKey {
    /// Parse one GitHub issue or pull-request URL.
    pub(crate) fn parse_url(url: &str) -> Option<(Self, TicketKind)> {
        let url = url.trim();
        if !url.to_ascii_lowercase().starts_with("https://github.com/") {
            return None;
        }
        let locator = IssueLocator::parse(url)?;
        let kind = if url
            .split('/')
            .nth(5)
            .is_some_and(|segment| segment.eq_ignore_ascii_case("pull"))
        {
            TicketKind::Pull
        } else {
            TicketKind::Issue
        };
        Some((Self::from_locator(&locator), kind))
    }

    pub(crate) fn from_locator(locator: &IssueLocator) -> Self {
        Self {
            target: locator.target().clone(),
            number: locator.number(),
        }
    }

    /// The case-folded identity the ledger compares on.
    pub(crate) fn identity(&self) -> String {
        format!("{}#{}", self.target, self.number.get()).to_ascii_lowercase()
    }

    pub(crate) fn locator(&self) -> IssueLocator {
        IssueLocator::new(self.target.clone(), self.number)
    }

    pub(crate) fn url(&self, kind: TicketKind) -> String {
        format!(
            "https://github.com/{}/{}/{}",
            self.target,
            kind.path_segment(),
            self.number.get()
        )
    }

    /// Whether one Slack message text names this ticket.
    ///
    /// Slack renders a link as `<url|label>` and may wrap it in punctuation;
    /// each token is trimmed the same way intake trims it before parsing.
    pub(crate) fn mentioned_in(&self, text: &str) -> bool {
        let identity = self.identity();
        text.split_whitespace().any(|token| {
            let token = token.trim_matches(|character: char| {
                matches!(
                    character,
                    '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '"' | '\'' | '!'
                )
            });
            let token = token.split_once('|').map_or(token, |(url, _)| url);
            let token = token.strip_suffix('.').unwrap_or(token);
            Self::parse_url(token).is_some_and(|(key, _)| key.identity() == identity)
        })
    }
}

/// Who holds a claim on a ticket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ClaimHolder {
    /// A Monique job Manage created for the ticket.
    MoniqueJob(String),
    /// A local Claude Code session that claimed the ticket.
    Claude(String),
}

impl ClaimHolder {
    pub(crate) fn as_string(&self) -> String {
        match self {
            Self::MoniqueJob(job) => format!("{MONIQUE_HOLDER_PREFIX}{job}"),
            Self::Claude(session) => format!("{CLAUDE_HOLDER_PREFIX}{session}"),
        }
    }

    /// Parse any holder spelling.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        if let Some(session) = value.strip_prefix(CLAUDE_HOLDER_PREFIX) {
            return valid_session(session).then(|| Self::Claude(session.to_owned()));
        }
        let job = value.strip_prefix(MONIQUE_HOLDER_PREFIX)?;
        valid_job_id(job).then(|| Self::MoniqueJob(job.to_owned()))
    }

    /// Parse a holder a local session may name: only `claude:<session>`.
    pub(crate) fn parse_claude(value: &str) -> Option<Self> {
        match Self::parse(value)? {
            claude @ Self::Claude(_) => Some(claude),
            Self::MoniqueJob(_) => None,
        }
    }
}

fn valid_session(session: &str) -> bool {
    !session.is_empty()
        && session.len() <= MAX_SESSION_BYTES
        && session
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn valid_job_id(job: &str) -> bool {
    !job.is_empty()
        && job.len() <= 128
        && job
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn job_status_word(status: TicketJobStatus) -> &'static str {
    status.as_str()
}

fn parse_job_status(value: &str) -> Option<TicketJobStatus> {
    [
        TicketJobStatus::PendingApproval,
        TicketJobStatus::Pending,
        TicketJobStatus::Claimed,
        TicketJobStatus::Running,
        TicketJobStatus::Done,
        TicketJobStatus::Failed,
        TicketJobStatus::Cancelled,
    ]
    .into_iter()
    .find(|status| status.as_str() == value)
}

/// Whether a job status means somebody is actively working the ticket.
const fn job_is_working(status: TicketJobStatus) -> bool {
    matches!(status, TicketJobStatus::Claimed | TicketJobStatus::Running)
}

/// Whether a job status competes with a new claim on the same ticket.
const fn job_conflicts(status: TicketJobStatus) -> bool {
    matches!(
        status,
        TicketJobStatus::PendingApproval
            | TicketJobStatus::Pending
            | TicketJobStatus::Claimed
            | TicketJobStatus::Running
    )
}

/// One Slack message that posted a ticket.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct TicketPost {
    pub(crate) channel: String,
    pub(crate) ts: String,
    recorded_ms: i64,
}

/// One claim on a ticket.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct StoredClaim {
    holder: String,
    since_ms: i64,
    /// The job's last observed status; `None` for a Claude claim, and for a
    /// job whose status has not been read yet.
    job_status: Option<String>,
    #[serde(default)]
    read_failures: u8,
    /// When the job's status was last read. Advanced in memory on every read
    /// and persisted with the next real change; a restart that reads a job a
    /// little early costs one status call.
    #[serde(default)]
    polled_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReactionState {
    Applied,
    Refused,
}

/// One reaction the bot applied, or tried to.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct StoredReaction {
    channel: String,
    ts: String,
    name: String,
    state: ReactionState,
    attempts: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Verification {
    first_queued_ms: i64,
    next_due_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct StoredTicket {
    /// The case-folded `owner/repo#number`.
    key: String,
    /// The URL the ticket is addressed by, in its recorded kind.
    url: String,
    kind: TicketKind,
    posts: Vec<TicketPost>,
    claims: Vec<StoredClaim>,
    reactions: Vec<StoredReaction>,
    finished_ms: Option<i64>,
    verification: Option<Verification>,
    updated_ms: i64,
}

impl StoredTicket {
    fn ticket_key(&self) -> Option<TicketKey> {
        TicketKey::parse_url(&self.url).map(|(key, _)| key)
    }

    fn holders(&self) -> impl Iterator<Item = (ClaimHolder, &StoredClaim)> {
        self.claims
            .iter()
            .filter_map(|claim| ClaimHolder::parse(&claim.holder).map(|holder| (holder, claim)))
    }

    /// Whether somebody is working the ticket right now.
    fn actively_claimed(&self) -> bool {
        self.holders().any(|(holder, claim)| match holder {
            ClaimHolder::Claude(_) => true,
            ClaimHolder::MoniqueJob(_) => claim
                .job_status
                .as_deref()
                .and_then(parse_job_status)
                .is_some_and(job_is_working),
        })
    }

    fn claude_holder(&self) -> Option<String> {
        self.holders()
            .find(|(holder, _)| matches!(holder, ClaimHolder::Claude(_)))
            .map(|(_, claim)| claim.holder.clone())
    }

    fn queue_verification(&mut self, now_ms: i64) {
        if self.finished_ms.is_some() {
            return;
        }
        let first_queued_ms = self
            .verification
            .map_or(now_ms, |verification| verification.first_queued_ms);
        self.verification = Some(Verification {
            first_queued_ms,
            next_due_ms: now_ms,
        });
    }

    /// Queue one check even though the ticket is recorded finished.
    fn requeue(&mut self, now_ms: i64) {
        let first_queued_ms = self
            .verification
            .map_or(now_ms, |verification| verification.first_queued_ms);
        self.verification = Some(Verification {
            first_queued_ms,
            next_due_ms: now_ms,
        });
    }

    fn finish(&mut self, now_ms: i64) {
        self.finished_ms = Some(now_ms);
        self.verification = None;
    }

    /// The reaction every recorded post should carry right now, if any.
    ///
    /// A finished ticket wants ✅ on the posts it was finished with; a post
    /// recorded after the finish gets nothing until the ticket is verified
    /// again, so a client re-posting a link as a reminder never receives 👀
    /// (or a stale ✅) for work that is not visibly under way.
    fn desired(&self, post: &TicketPost) -> Option<ReactionName> {
        match self.finished_ms {
            Some(finished_ms) if post.recorded_ms <= finished_ms => {
                Some(ReactionName::WhiteCheckMark)
            }
            Some(_) => None,
            None if self.actively_claimed() => Some(ReactionName::Eyes),
            None => None,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct LedgerDocument {
    schema: String,
    tickets: Vec<StoredTicket>,
}

/// One reaction the reactor still owes a post.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PendingReaction {
    pub(crate) ticket: String,
    pub(crate) channel: String,
    pub(crate) ts: String,
    pub(crate) name: ReactionName,
}

/// How one reaction effect ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReactionOutcome {
    /// The message now carries the bot's reaction (applied, or already there).
    Applied,
    /// Slack refused it (message gone, channel not joined, …).
    Refused,
    /// The transport did not say. Reactions are idempotent, so it is retried.
    Unknown,
}

/// One claim a conflict report names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimConflict {
    pub(crate) holder: String,
    pub(crate) status: String,
}

/// The ticket work ledger.
#[derive(Debug, Default)]
pub(crate) struct TicketWorkLedger {
    tickets: Vec<StoredTicket>,
    path: Option<PathBuf>,
}

impl TicketWorkLedger {
    /// A ledger that persists nowhere, for composition without a state dir.
    #[cfg(test)]
    pub(crate) fn in_memory() -> Self {
        Self::default()
    }

    /// Open the ledger file under one private directory.
    ///
    /// # Errors
    ///
    /// Refuses a directory or file that is not owner-only, an unreadable or
    /// oversized file, and a document that is not exactly this schema.
    pub(crate) fn open(path: PathBuf) -> Result<Self, ()> {
        use std::os::unix::fs::MetadataExt as _;
        let parent = path.parent().ok_or(())?;
        let parent_metadata = std::fs::symlink_metadata(parent).map_err(|_| ())?;
        let uid = nix::unistd::Uid::effective().as_raw();
        if !parent_metadata.is_dir()
            || parent_metadata.uid() != uid
            || parent_metadata.mode() & 0o077 != 0
        {
            return Err(());
        }
        let tickets = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.uid() != uid
                    || metadata.mode() & 0o077 != 0
                    || metadata.len() > MAX_LEDGER_BYTES as u64
                {
                    return Err(());
                }
                decode_ledger(&std::fs::read(&path).map_err(|_| ())?)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(_) => return Err(()),
        };
        Ok(Self {
            tickets,
            path: Some(path),
        })
    }

    fn find(&self, key: &TicketKey) -> Option<&StoredTicket> {
        let identity = key.identity();
        self.tickets.iter().find(|ticket| ticket.key == identity)
    }

    /// Apply one change to a copy, persist it, and only then adopt it, so a
    /// failed write leaves memory and disk agreeing.
    fn commit(&mut self, change: impl FnOnce(&mut Vec<StoredTicket>) -> bool) -> Result<bool, ()> {
        let mut tickets = self.tickets.clone();
        if !change(&mut tickets) {
            return Ok(false);
        }
        self.persist(&tickets)?;
        self.tickets = tickets;
        Ok(true)
    }

    /// The ticket's entry, created when absent and the ledger has room.
    fn entry<'a>(
        tickets: &'a mut Vec<StoredTicket>,
        key: &TicketKey,
        kind: TicketKind,
        now_ms: i64,
    ) -> Option<&'a mut StoredTicket> {
        let identity = key.identity();
        if let Some(index) = tickets.iter().position(|ticket| ticket.key == identity) {
            let ticket = &mut tickets[index];
            if kind == TicketKind::Pull && ticket.kind == TicketKind::Issue {
                ticket.kind = TicketKind::Pull;
                ticket.url = key.url(TicketKind::Pull);
            }
            return Some(ticket);
        }
        if tickets.len() >= MAX_TICKETS {
            // Evict the least recently touched ticket nobody is working and
            // nothing is waiting to verify; a full ledger of live work refuses
            // the new ticket rather than forgetting one in progress.
            let evictable = tickets
                .iter()
                .enumerate()
                .filter(|(_, ticket)| ticket.claims.is_empty() && ticket.verification.is_none())
                .min_by_key(|(_, ticket)| ticket.updated_ms)
                .map(|(index, _)| index)?;
            tickets.remove(evictable);
        }
        tickets.push(StoredTicket {
            key: identity,
            url: key.url(kind),
            kind,
            posts: Vec::new(),
            claims: Vec::new(),
            reactions: Vec::new(),
            finished_ms: None,
            verification: None,
            updated_ms: now_ms,
        });
        tickets.last_mut()
    }

    /// Record one Slack message that posted a ticket.
    ///
    /// A post that arrives after the ticket was verified finished queues one
    /// fresh verification instead of being reacted to: see
    /// [`StoredTicket::desired`].
    pub(crate) fn record_post(
        &mut self,
        key: &TicketKey,
        kind: TicketKind,
        channel: &str,
        ts: &str,
        now_ms: i64,
    ) -> Result<bool, ()> {
        if ChannelId::new(channel).is_err() || MessageTs::new(ts).is_err() {
            return Err(());
        }
        self.commit(|tickets| {
            let Some(ticket) = Self::entry(tickets, key, kind, now_ms) else {
                return false;
            };
            if ticket
                .posts
                .iter()
                .any(|post| post.channel == channel && post.ts == ts)
            {
                return false;
            }
            if ticket.posts.len() >= MAX_POSTS_PER_TICKET {
                ticket.posts.remove(0);
            }
            ticket.posts.push(TicketPost {
                channel: channel.to_owned(),
                ts: ts.to_owned(),
                recorded_ms: now_ms,
            });
            if ticket.finished_ms.is_some() {
                // Somebody posted a finished ticket again. Check it once more
                // rather than react: re-finished, the new post gets its ✅.
                ticket.requeue(now_ms);
            }
            ticket.updated_ms = now_ms;
            true
        })
    }

    /// Record a Monique job for a ticket, with its status when known.
    pub(crate) fn record_job(
        &mut self,
        key: &TicketKey,
        kind: TicketKind,
        job_id: &str,
        status: Option<TicketJobStatus>,
        now_ms: i64,
    ) -> Result<bool, ()> {
        if !valid_job_id(job_id) {
            return Err(());
        }
        let holder = ClaimHolder::MoniqueJob(job_id.to_owned()).as_string();
        let known = self
            .find(key)
            .is_some_and(|ticket| ticket.claims.iter().any(|claim| claim.holder == holder));
        if !known {
            let inserted = self.commit(|tickets| {
                let Some(ticket) = Self::entry(tickets, key, kind, now_ms) else {
                    return false;
                };
                if ticket.claims.len() >= MAX_CLAIMS_PER_TICKET {
                    return false;
                }
                ticket.claims.push(StoredClaim {
                    holder: holder.clone(),
                    since_ms: now_ms,
                    job_status: None,
                    read_failures: 0,
                    polled_ms: 0,
                });
                ticket.updated_ms = now_ms;
                true
            })?;
            if !inserted {
                return Ok(false);
            }
        }
        match status {
            Some(status) => self.observe_job_status(job_id, status, now_ms),
            None => Ok(!known),
        }
    }

    /// Apply one observed job status to every ticket following that job.
    pub(crate) fn observe_job_status(
        &mut self,
        job_id: &str,
        status: TicketJobStatus,
        now_ms: i64,
    ) -> Result<bool, ()> {
        let holder = ClaimHolder::MoniqueJob(job_id.to_owned()).as_string();
        let word = job_status_word(status);
        // The poll time is bookkeeping: advanced in place, persisted only
        // with a real change.
        for ticket in &mut self.tickets {
            for claim in ticket
                .claims
                .iter_mut()
                .filter(|claim| claim.holder == holder)
            {
                claim.polled_ms = now_ms;
                claim.read_failures = 0;
            }
        }
        self.commit(|tickets| {
            let mut changed = false;
            for ticket in tickets.iter_mut() {
                let Some(index) = ticket
                    .claims
                    .iter()
                    .position(|claim| claim.holder == holder)
                else {
                    continue;
                };
                if ticket.claims[index].job_status.as_deref() == Some(word) {
                    continue;
                }
                changed = true;
                ticket.updated_ms = now_ms;
                match status {
                    TicketJobStatus::Done => {
                        // The worker accepted a completion receipt for this
                        // job, which is this product's own proof of delivery.
                        ticket.claims[index].job_status = Some(word.to_owned());
                        ticket.finish(now_ms);
                    }
                    TicketJobStatus::Failed | TicketJobStatus::Cancelled => {
                        ticket.claims.remove(index);
                        if !ticket.actively_claimed() {
                            ticket.queue_verification(now_ms);
                        }
                    }
                    TicketJobStatus::PendingApproval
                    | TicketJobStatus::Pending
                    | TicketJobStatus::Claimed
                    | TicketJobStatus::Running => {
                        ticket.claims[index].job_status = Some(word.to_owned());
                    }
                }
            }
            changed
        })
    }

    /// Note that a job's status could not be read.
    ///
    /// After [`MAX_JOB_READ_FAILURES`] consecutive misses the job is no longer
    /// followed and its ticket is queued for verification instead.
    pub(crate) fn job_status_unavailable(&mut self, job_id: &str, now_ms: i64) -> Result<(), ()> {
        let holder = ClaimHolder::MoniqueJob(job_id.to_owned()).as_string();
        let mut exhausted = false;
        for ticket in &mut self.tickets {
            for claim in ticket
                .claims
                .iter_mut()
                .filter(|claim| claim.holder == holder)
            {
                claim.polled_ms = now_ms;
                claim.read_failures = claim.read_failures.saturating_add(1);
                exhausted |= claim.read_failures >= MAX_JOB_READ_FAILURES;
            }
        }
        if exhausted {
            self.commit(|tickets| {
                for ticket in tickets.iter_mut() {
                    let before = ticket.claims.len();
                    ticket.claims.retain(|claim| {
                        claim.holder != holder || claim.read_failures < MAX_JOB_READ_FAILURES
                    });
                    if ticket.claims.len() != before && !ticket.actively_claimed() {
                        ticket.queue_verification(now_ms);
                    }
                }
                true
            })?;
        }
        Ok(())
    }

    /// Jobs whose status is worth reading now, least recently read first.
    pub(crate) fn jobs_to_poll(&self, limit: usize, now_ms: i64) -> Vec<String> {
        let mut jobs: Vec<(i64, String)> = Vec::new();
        for ticket in &self.tickets {
            if ticket.finished_ms.is_some() {
                continue;
            }
            for (holder, claim) in ticket.holders() {
                let ClaimHolder::MoniqueJob(job) = holder else {
                    continue;
                };
                let terminal = claim
                    .job_status
                    .as_deref()
                    .and_then(parse_job_status)
                    .is_some_and(TicketJobStatus::is_terminal);
                if terminal
                    || claim.polled_ms.saturating_add(JOB_POLL_MIN_INTERVAL_MS) > now_ms
                    || jobs.iter().any(|(_, seen)| seen == &job)
                {
                    continue;
                }
                jobs.push((claim.polled_ms, job));
            }
        }
        jobs.sort();
        jobs.into_iter().take(limit).map(|(_, job)| job).collect()
    }

    /// Non-terminal jobs recorded for one ticket.
    pub(crate) fn ticket_jobs(&self, key: &TicketKey) -> Vec<String> {
        self.find(key).map_or_else(Vec::new, |ticket| {
            ticket
                .holders()
                .filter_map(|(holder, claim)| match holder {
                    ClaimHolder::MoniqueJob(job)
                        if !claim
                            .job_status
                            .as_deref()
                            .and_then(parse_job_status)
                            .is_some_and(TicketJobStatus::is_terminal) =>
                    {
                        Some(job)
                    }
                    _ => None,
                })
                .collect()
        })
    }

    /// Record or renew one Claude session's claim.
    pub(crate) fn claim(
        &mut self,
        key: &TicketKey,
        kind: TicketKind,
        holder: &ClaimHolder,
        now_ms: i64,
    ) -> Result<(), ()> {
        let holder = holder.as_string();
        let accepted = self.commit(|tickets| {
            let Some(ticket) = Self::entry(tickets, key, kind, now_ms) else {
                return false;
            };
            if let Some(claim) = ticket
                .claims
                .iter_mut()
                .find(|claim| claim.holder == holder)
            {
                claim.since_ms = now_ms;
            } else {
                if ticket.claims.len() >= MAX_CLAIMS_PER_TICKET {
                    return false;
                }
                ticket.claims.push(StoredClaim {
                    holder: holder.clone(),
                    since_ms: now_ms,
                    job_status: None,
                    read_failures: 0,
                    polled_ms: 0,
                });
            }
            // A session at work is not a ticket waiting to be checked.
            ticket.verification = None;
            ticket.updated_ms = now_ms;
            true
        })?;
        if accepted { Ok(()) } else { Err(()) }
    }

    /// Release one claim and queue the ticket for verification.
    ///
    /// Releasing a claim that is not held is not an error: the caller still
    /// wants to know whether the ticket is finished.
    pub(crate) fn release(
        &mut self,
        key: &TicketKey,
        kind: TicketKind,
        holder: &ClaimHolder,
        now_ms: i64,
    ) -> Result<(), ()> {
        let holder = holder.as_string();
        self.commit(|tickets| {
            let Some(ticket) = Self::entry(tickets, key, kind, now_ms) else {
                return false;
            };
            ticket.claims.retain(|claim| claim.holder != holder);
            if !ticket.actively_claimed() {
                ticket.queue_verification(now_ms);
            }
            ticket.updated_ms = now_ms;
            true
        })?;
        Ok(())
    }

    /// Let Claude claims older than [`CLAUDE_CLAIM_TTL_MS`] lapse.
    pub(crate) fn expire_claude_claims(&mut self, now_ms: i64) -> Result<bool, ()> {
        let stale = |claim: &StoredClaim| {
            claim.holder.starts_with(CLAUDE_HOLDER_PREFIX)
                && claim.since_ms.saturating_add(CLAUDE_CLAIM_TTL_MS) <= now_ms
        };
        if !self
            .tickets
            .iter()
            .any(|ticket| ticket.claims.iter().any(stale))
        {
            return Ok(false);
        }
        self.commit(|tickets| {
            for ticket in tickets.iter_mut() {
                let before = ticket.claims.len();
                ticket.claims.retain(|claim| !stale(claim));
                if ticket.claims.len() != before {
                    ticket.updated_ms = now_ms;
                    if !ticket.actively_claimed() {
                        ticket.queue_verification(now_ms);
                    }
                }
            }
            true
        })
    }

    /// The Claude session holding the ticket, when one does.
    pub(crate) fn claude_holder(&self, key: &TicketKey) -> Option<String> {
        self.find(key).and_then(StoredTicket::claude_holder)
    }

    #[cfg(test)]
    pub(crate) fn has_claude_claim(&self, key: &TicketKey) -> bool {
        self.claude_holder(key).is_some()
    }

    /// Whether somebody is working the ticket right now.
    pub(crate) fn actively_claimed(&self, key: &TicketKey) -> bool {
        self.find(key).is_some_and(StoredTicket::actively_claimed)
    }

    /// Whether the ticket is verified finished.
    #[cfg(test)]
    pub(crate) fn is_finished(&self, key: &TicketKey) -> bool {
        self.find(key)
            .is_some_and(|ticket| ticket.finished_ms.is_some())
    }

    /// The posts recorded for one ticket.
    pub(crate) fn posts(&self, key: &TicketKey) -> Vec<TicketPost> {
        self.find(key)
            .map_or_else(Vec::new, |ticket| ticket.posts.clone())
    }

    /// Every other claim that competes with `holder` on this ticket.
    pub(crate) fn conflicts(&self, key: &TicketKey, holder: &ClaimHolder) -> Vec<ClaimConflict> {
        let own = holder.as_string();
        self.find(key).map_or_else(Vec::new, |ticket| {
            ticket
                .holders()
                .filter(|(_, claim)| claim.holder != own)
                .filter_map(|(holder, claim)| match holder {
                    ClaimHolder::Claude(_) => Some(ClaimConflict {
                        holder: claim.holder.clone(),
                        status: String::from("claimed"),
                    }),
                    ClaimHolder::MoniqueJob(_) => {
                        let status = claim.job_status.as_deref().and_then(parse_job_status)?;
                        job_conflicts(status).then(|| ClaimConflict {
                            holder: claim.holder.clone(),
                            status: status.as_str().to_owned(),
                        })
                    }
                })
                .collect()
        })
    }

    /// Mark one ticket verified finished.
    pub(crate) fn mark_finished(&mut self, key: &TicketKey, now_ms: i64) -> Result<bool, ()> {
        let identity = key.identity();
        self.commit(|tickets| {
            let Some(ticket) = tickets.iter_mut().find(|ticket| ticket.key == identity) else {
                return false;
            };
            ticket.finish(now_ms);
            ticket.updated_ms = now_ms;
            true
        })
    }

    /// Reschedule one queued ticket whose check did not find it finished.
    ///
    /// `observed_unfinished` is true when GitHub answered and showed the
    /// ticket open; that also withdraws an earlier finish (a client reopened
    /// the conversation). A check that could not read GitHub only reschedules.
    pub(crate) fn verified_unfinished(
        &mut self,
        key: &TicketKey,
        observed_unfinished: bool,
        now_ms: i64,
    ) -> Result<(), ()> {
        let identity = key.identity();
        self.commit(|tickets| {
            let Some(ticket) = tickets.iter_mut().find(|ticket| ticket.key == identity) else {
                return false;
            };
            if observed_unfinished {
                ticket.finished_ms = None;
            }
            let Some(verification) = ticket.verification.as_mut() else {
                return observed_unfinished;
            };
            verification.next_due_ms = now_ms.saturating_add(VERIFY_INTERVAL_MS);
            true
        })?;
        Ok(())
    }

    /// Up to `limit` queued tickets due a check, dropping any queued longer
    /// than [`VERIFY_MAX_AGE_MS`].
    ///
    /// A ticket somebody is working is skipped: its own claim's end will
    /// queue it again.
    pub(crate) fn due_verifications(
        &mut self,
        limit: usize,
        now_ms: i64,
    ) -> Result<Vec<(TicketKey, TicketKind)>, ()> {
        let expired = |ticket: &StoredTicket| {
            ticket.verification.is_some_and(|verification| {
                verification
                    .first_queued_ms
                    .saturating_add(VERIFY_MAX_AGE_MS)
                    <= now_ms
            })
        };
        if self.tickets.iter().any(expired) {
            self.commit(|tickets| {
                for ticket in tickets.iter_mut().filter(|ticket| expired(ticket)) {
                    ticket.verification = None;
                }
                true
            })?;
        }
        let mut due: Vec<(i64, TicketKey, TicketKind)> = self
            .tickets
            .iter()
            .filter(|ticket| !ticket.actively_claimed())
            .filter_map(|ticket| {
                let verification = ticket.verification?;
                (verification.next_due_ms <= now_ms)
                    .then(|| ticket.ticket_key())
                    .flatten()
                    .map(|key| (verification.next_due_ms, key, ticket.kind))
            })
            .collect();
        due.sort_by_key(|(due_ms, _, _)| *due_ms);
        Ok(due
            .into_iter()
            .take(limit)
            .map(|(_, key, kind)| (key, kind))
            .collect())
    }

    /// Whether a ticket is queued for verification.
    pub(crate) fn is_queued(&self, key: &TicketKey) -> bool {
        self.find(key)
            .is_some_and(|ticket| ticket.verification.is_some())
    }

    /// Reactions the ledger owes, at most `limit`, optionally for one ticket.
    pub(crate) fn pending_reactions(
        &self,
        only: Option<&TicketKey>,
        limit: usize,
    ) -> Vec<PendingReaction> {
        let only = only.map(TicketKey::identity);
        let mut pending = Vec::new();
        for ticket in &self.tickets {
            if only
                .as_ref()
                .is_some_and(|identity| identity != &ticket.key)
            {
                continue;
            }
            for post in &ticket.posts {
                let Some(name) = ticket.desired(post) else {
                    continue;
                };
                let settled = ticket.reactions.iter().any(|reaction| {
                    reaction.channel == post.channel
                        && reaction.ts == post.ts
                        && reaction.name == name.as_wire()
                        && (reaction.state == ReactionState::Applied
                            || reaction.attempts >= MAX_REACTION_ATTEMPTS)
                });
                if settled {
                    continue;
                }
                pending.push(PendingReaction {
                    ticket: ticket.key.clone(),
                    channel: post.channel.clone(),
                    ts: post.ts.clone(),
                    name,
                });
                if pending.len() >= limit {
                    return pending;
                }
            }
        }
        pending
    }

    /// Record how one reaction effect ended.
    pub(crate) fn record_reaction(
        &mut self,
        reaction: &PendingReaction,
        outcome: ReactionOutcome,
    ) -> Result<(), ()> {
        if outcome == ReactionOutcome::Unknown {
            return Ok(());
        }
        self.commit(|tickets| {
            let Some(ticket) = tickets
                .iter_mut()
                .find(|ticket| ticket.key == reaction.ticket)
            else {
                return false;
            };
            let name = reaction.name.as_wire();
            let state = match outcome {
                ReactionOutcome::Applied => ReactionState::Applied,
                ReactionOutcome::Refused | ReactionOutcome::Unknown => ReactionState::Refused,
            };
            if let Some(existing) = ticket.reactions.iter_mut().find(|existing| {
                existing.channel == reaction.channel
                    && existing.ts == reaction.ts
                    && existing.name == name
            }) {
                existing.state = state;
                existing.attempts = existing.attempts.saturating_add(1);
            } else {
                if ticket.reactions.len() >= 2 * MAX_POSTS_PER_TICKET {
                    ticket.reactions.remove(0);
                }
                ticket.reactions.push(StoredReaction {
                    channel: reaction.channel.clone(),
                    ts: reaction.ts.clone(),
                    name: name.to_owned(),
                    state,
                    attempts: 1,
                });
            }
            true
        })?;
        Ok(())
    }

    /// Seed the ledger from the thread-to-job bindings older releases kept.
    ///
    /// Each binding names a ticket, the thread it was requested in and the
    /// job Manage created. Idempotent: a post or job already recorded is left
    /// as it is, so this runs on every open.
    pub(crate) fn backfill<'a>(
        &mut self,
        bindings: impl IntoIterator<Item = (&'a str, &'a str, &'a str, &'a str)>,
        now_ms: i64,
    ) -> Result<(), ()> {
        let bindings: Vec<_> = bindings.into_iter().collect();
        self.commit(|tickets| {
            let mut changed = false;
            for (channel, thread_ts, job_id, issue_url) in bindings {
                let Some((key, kind)) = TicketKey::parse_url(issue_url) else {
                    continue;
                };
                if ChannelId::new(channel).is_err()
                    || MessageTs::new(thread_ts).is_err()
                    || !valid_job_id(job_id)
                {
                    continue;
                }
                let Some(ticket) = Self::entry(tickets, &key, kind, now_ms) else {
                    continue;
                };
                if !ticket
                    .posts
                    .iter()
                    .any(|post| post.channel == channel && post.ts == thread_ts)
                    && ticket.posts.len() < MAX_POSTS_PER_TICKET
                {
                    ticket.posts.push(TicketPost {
                        channel: channel.to_owned(),
                        ts: thread_ts.to_owned(),
                        recorded_ms: now_ms,
                    });
                    changed = true;
                }
                let holder = ClaimHolder::MoniqueJob(job_id.to_owned()).as_string();
                if !ticket.claims.iter().any(|claim| claim.holder == holder)
                    && ticket.claims.len() < MAX_CLAIMS_PER_TICKET
                {
                    ticket.claims.push(StoredClaim {
                        holder,
                        since_ms: now_ms,
                        job_status: None,
                        read_failures: 0,
                        polled_ms: 0,
                    });
                    changed = true;
                }
            }
            changed
        })?;
        Ok(())
    }

    fn persist(&self, tickets: &[StoredTicket]) -> Result<(), ()> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };
        let document = LedgerDocument {
            schema: SCHEMA.to_owned(),
            tickets: tickets.to_vec(),
        };
        let bytes = serde_json::to_vec(&document).map_err(|_| ())?;
        if bytes.len() > MAX_LEDGER_BYTES {
            return Err(());
        }
        let temporary = path.with_extension("v1.tmp");
        use std::io::Write as _;
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
        if let Ok(metadata) = std::fs::symlink_metadata(&temporary) {
            if !metadata.is_file()
                || metadata.uid() != nix::unistd::Uid::effective().as_raw()
                || metadata.mode() & 0o077 != 0
            {
                return Err(());
            }
            std::fs::remove_file(&temporary).map_err(|_| ())?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| ())?;
        file.write_all(&bytes).map_err(|_| ())?;
        file.sync_all().map_err(|_| ())?;
        std::fs::rename(&temporary, path).map_err(|_| ())?;
        std::fs::File::open(path.parent().ok_or(())?)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ())
    }
}

fn decode_ledger(bytes: &[u8]) -> Result<Vec<StoredTicket>, ()> {
    if bytes.len() > MAX_LEDGER_BYTES {
        return Err(());
    }
    let document: LedgerDocument = serde_json::from_slice(bytes).map_err(|_| ())?;
    if document.schema != SCHEMA || document.tickets.len() > MAX_TICKETS {
        return Err(());
    }
    let mut seen = BTreeSet::new();
    for ticket in &document.tickets {
        let Some((key, _)) = TicketKey::parse_url(&ticket.url) else {
            return Err(());
        };
        if key.identity() != ticket.key
            || !seen.insert(ticket.key.clone())
            || ticket.posts.len() > MAX_POSTS_PER_TICKET
            || ticket.claims.len() > MAX_CLAIMS_PER_TICKET
            || ticket.reactions.len() > 2 * MAX_POSTS_PER_TICKET
            || ticket.posts.iter().any(|post| {
                ChannelId::new(&post.channel).is_err() || MessageTs::new(&post.ts).is_err()
            })
            || ticket.claims.iter().any(|claim| {
                ClaimHolder::parse(&claim.holder).is_none()
                    || claim
                        .job_status
                        .as_deref()
                        .is_some_and(|status| parse_job_status(status).is_none())
            })
            || ticket
                .reactions
                .iter()
                .any(|reaction| ReactionName::parse(&reaction.name).is_none())
        {
            return Err(());
        }
    }
    Ok(document.tickets)
}

/// What the Slack intake worker records into the ledger.
///
/// The intake side only states facts — a post that cited a ticket, a job
/// Manage created for it, a status a poll observed — and asks one question:
/// is a Claude session holding this ticket. It never reacts; the
/// [`TicketReactor`] does. Disabled (no ledger) everything is a no-op, which
/// is how routers composed for replay and tests stay effect-free.
#[derive(Clone, Debug, Default)]
pub(crate) struct TicketWorkRecorder {
    ledger: Option<Arc<Mutex<TicketWorkLedger>>>,
    /// Slack users whose ticket posts are confirmed without an approval card.
    auto_confirm: Vec<automonique_slack_connector::UserId>,
}

impl TicketWorkRecorder {
    pub(crate) fn new(
        ledger: Arc<Mutex<TicketWorkLedger>>,
        auto_confirm: Vec<automonique_slack_connector::UserId>,
    ) -> Self {
        Self {
            ledger: Some(ledger),
            auto_confirm,
        }
    }

    /// A recorder that records nothing.
    pub(crate) fn disabled() -> Self {
        Self::default()
    }

    /// A recorder over an in-memory ledger, for router tests.
    #[cfg(test)]
    pub(crate) fn in_memory(auto_confirm: Vec<automonique_slack_connector::UserId>) -> Self {
        Self::new(
            Arc::new(Mutex::new(TicketWorkLedger::in_memory())),
            auto_confirm,
        )
    }

    #[cfg(test)]
    pub(crate) fn ledger(&self) -> Option<Arc<Mutex<TicketWorkLedger>>> {
        self.ledger.clone()
    }

    fn with<T>(&self, operation: impl FnOnce(&mut TicketWorkLedger) -> T) -> Option<T> {
        self.ledger
            .as_ref()
            .and_then(|ledger| ledger.lock().ok())
            .map(|mut ledger| operation(&mut ledger))
    }

    /// Whether this Slack user's ticket posts skip the approval card.
    pub(crate) fn auto_confirms(&self, user: &automonique_slack_connector::UserId) -> bool {
        self.auto_confirm.contains(user)
    }

    /// Record the message that posted a ticket.
    pub(crate) fn record_post(&self, issue_url: &str, channel: &str, ts: &str) {
        let Some((key, kind)) = TicketKey::parse_url(issue_url) else {
            return;
        };
        let now_ms = crate::unix_millis().unwrap_or(0);
        let _ = self.with(|ledger| ledger.record_post(&key, kind, channel, ts, now_ms));
    }

    /// Record a job Manage created for a ticket.
    pub(crate) fn record_job(&self, issue_url: &str, job_id: &str, status: TicketJobStatus) {
        let Some((key, kind)) = TicketKey::parse_url(issue_url) else {
            return;
        };
        let now_ms = crate::unix_millis().unwrap_or(0);
        let _ = self.with(|ledger| ledger.record_job(&key, kind, job_id, Some(status), now_ms));
    }

    /// Share one status read another poll already made.
    pub(crate) fn observe_job_status(&self, job_id: &str, status: TicketJobStatus) {
        let now_ms = crate::unix_millis().unwrap_or(0);
        let _ = self.with(|ledger| ledger.observe_job_status(job_id, status, now_ms));
    }

    /// The Claude session holding a ticket, when one does.
    pub(crate) fn claude_holder(&self, issue_url: &str) -> Option<String> {
        let (key, _) = TicketKey::parse_url(issue_url)?;
        self.with(|ledger| ledger.claude_holder(&key)).flatten()
    }
}

// ---------------------------------------------------------------------------
// Verification against GitHub.
// ---------------------------------------------------------------------------

/// What GitHub says about one ticket, as far as delivery goes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TicketFacts {
    Issue {
        closed: bool,
        state_reason: Option<String>,
        /// The latest comment's author login and body, when there is one.
        latest_comment: Option<(String, String)>,
    },
    Pull {
        merged: bool,
    },
}

/// Phrases a team reply uses when it reports a delivery.
const DELIVERY_PHRASES: [&str; 12] = [
    "en ligne",
    "en production",
    "déploi",
    "deploi",
    "déploy",
    "deploy",
    "corrigé",
    "corrige",
    "maintenant",
    "is live",
    "deployed",
    "fixed",
];

/// Whether one comment body reports a delivery, case-insensitively.
pub(crate) fn reports_delivery(body: &str) -> bool {
    let body = body.to_lowercase();
    DELIVERY_PHRASES.iter().any(|phrase| body.contains(phrase))
}

/// Whether GitHub shows the ticket finished.
///
/// A ticket is finished when:
///
/// 1. it is a pull request and it is merged; or
/// 2. it is an issue closed as `completed` (or with no recorded reason, which
///    is how GitHub reports issues closed before reasons existed); or
/// 3. the issue's **latest** comment was written by a configured team login
///    and reports a delivery ([`reports_delivery`]).
///
/// The third rule reads only the latest comment, so a client reply after the
/// team's makes the ticket unfinished again, and it never compares against a
/// Slack timestamp: teams close tickets with plain replies, and clients re-post
/// links as reminders after them.
pub(crate) fn delivery_finished(facts: &TicketFacts, team_logins: &[String]) -> bool {
    match facts {
        TicketFacts::Pull { merged } => *merged,
        TicketFacts::Issue {
            closed: true,
            state_reason,
            ..
        } => matches!(state_reason.as_deref(), None | Some("completed")),
        TicketFacts::Issue {
            closed: false,
            latest_comment: Some((author, body)),
            ..
        } => {
            team_logins
                .iter()
                .any(|login| login.eq_ignore_ascii_case(author))
                && reports_delivery(body)
        }
        TicketFacts::Issue { .. } => false,
    }
}

// ---------------------------------------------------------------------------
// The reactor: the one place reactions are issued.
// ---------------------------------------------------------------------------

/// The Slack calls the reactor makes.
pub(crate) trait TicketSlack: Send {
    /// Add one closed reaction to one exact message.
    fn add_reaction(
        &mut self,
        channel: &ChannelId,
        ts: &MessageTs,
        name: ReactionName,
    ) -> ReactionOutcome;

    /// Read one page of a channel's recent top-level messages as `(ts, text)`.
    fn recent_messages(
        &mut self,
        channel: &ChannelId,
        limit: u16,
    ) -> Result<Vec<(String, String)>, ()>;
}

impl TicketSlack for Arc<SlackClient> {
    fn add_reaction(
        &mut self,
        channel: &ChannelId,
        ts: &MessageTs,
        name: ReactionName,
    ) -> ReactionOutcome {
        let request = ReactionRequest::new(channel.clone(), ts.clone(), name);
        match SlackClient::add_reaction(self.as_ref(), &request) {
            Ok(SlackOutcome::Accepted(
                ReactionChange::Applied | ReactionChange::AlreadyInPlace,
            )) => ReactionOutcome::Applied,
            // A rate limit is Slack saying "later", not "never": it must not
            // spend one of the bounded attempts.
            Ok(SlackOutcome::Rejected(rejection))
                if rejection.kind() == automonique_slack_connector::SlackErrorKind::RateLimited =>
            {
                ReactionOutcome::Unknown
            }
            Ok(SlackOutcome::Rejected(_)) => ReactionOutcome::Refused,
            Err(_) => ReactionOutcome::Unknown,
        }
    }

    fn recent_messages(
        &mut self,
        channel: &ChannelId,
        limit: u16,
    ) -> Result<Vec<(String, String)>, ()> {
        let request = ConversationsHistoryRequest::new(channel.clone(), limit).map_err(|_| ())?;
        match SlackClient::conversations_history(self.as_ref(), &request) {
            Ok(SlackOutcome::Accepted(page)) => Ok(page
                .messages
                .into_iter()
                .map(|message| (message.ts.as_str().to_owned(), message.text))
                .collect()),
            Ok(SlackOutcome::Rejected(_)) | Err(_) => Err(()),
        }
    }
}

/// The GitHub read the reactor verifies delivery with.
pub(crate) trait TicketDeliveryReader: Send {
    fn delivery(&mut self, key: &TicketKey, kind: TicketKind) -> Result<TicketFacts, ()>;
}

/// The Manage read the reactor follows jobs with.
pub(crate) trait TicketJobReader: Send {
    fn job_status(&mut self, job_id: &str) -> Result<TicketJobStatus, ()>;
}

impl<T: crate::telegram_bridge::TicketActionSurface + Send + ?Sized> TicketJobReader for Box<T> {
    fn job_status(&mut self, job_id: &str) -> Result<TicketJobStatus, ()> {
        self.ticket_status(job_id)
            .map(|status| status.job_status)
            .map_err(|_| ())
    }
}

/// One claim or release asked for over the local admin socket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TicketClaimRequest {
    pub issue_url: String,
    pub holder: String,
    pub release: bool,
}

/// What a claim or release found and did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TicketClaimOutcome {
    /// Slack posts the daemon knows for the ticket.
    pub posts_found: u32,
    /// Posts this call reacted to (👀 for a claim, ✅ for a verified release).
    pub reacted: u32,
    /// Every other active claim on the ticket, as `(holder, status)`.
    pub conflicts: Vec<(String, String)>,
}

type ClaimReply = SyncSender<Result<TicketClaimOutcome, String>>;

/// The daemon's handle onto the reactor's claim queue.
#[derive(Clone, Debug)]
pub struct TicketClaimHandle {
    sender: SyncSender<(TicketClaimRequest, ClaimReply)>,
}

impl TicketClaimHandle {
    /// Queue one request and return where its answer will arrive.
    ///
    /// # Errors
    ///
    /// `ticket_claims_busy` when [`MAX_QUEUED_CLAIMS`] are already waiting,
    /// `ticket_claims_unavailable` when the reactor has stopped.
    pub fn submit(
        &self,
        request: TicketClaimRequest,
    ) -> Result<Receiver<Result<TicketClaimOutcome, String>>, &'static str> {
        let (reply, answer) = std::sync::mpsc::sync_channel(1);
        match self.sender.try_send((request, reply)) {
            Ok(()) => Ok(answer),
            Err(TrySendError::Full(_)) => Err("ticket_claims_busy"),
            Err(TrySendError::Disconnected(_)) => Err("ticket_claims_unavailable"),
        }
    }
}

/// A claim queue: the handle the daemon keeps, the receiver the reactor drains.
pub(crate) fn claim_queue() -> (
    TicketClaimHandle,
    Receiver<(TicketClaimRequest, ClaimReply)>,
) {
    let (sender, receiver) = std::sync::mpsc::sync_channel(MAX_QUEUED_CLAIMS);
    (TicketClaimHandle { sender }, receiver)
}

/// The single owner of ticket status reactions.
pub(crate) struct TicketReactor {
    pub(crate) ledger: Arc<Mutex<TicketWorkLedger>>,
    pub(crate) slack: Box<dyn TicketSlack>,
    pub(crate) jobs: Option<Box<dyn TicketJobReader>>,
    pub(crate) github: Option<Box<dyn TicketDeliveryReader>>,
    pub(crate) team_logins: Vec<String>,
    pub(crate) channels: Vec<ChannelId>,
    pub(crate) requests: Receiver<(TicketClaimRequest, ClaimReply)>,
    pub(crate) last_job_poll_ms: i64,
    pub(crate) last_verify_pass_ms: i64,
    pub(crate) last_reaction_pass_ms: i64,
}

impl TicketReactor {
    /// Serve claims and converge reactions until `stop` rises.
    pub(crate) fn run(&mut self, stop: &AtomicBool) {
        while !stop.load(Ordering::Acquire) {
            match self.requests.recv_timeout(Duration::from_secs(1)) {
                Ok((request, reply)) => {
                    let answer = self.handle_claim(&request, crate::unix_millis().unwrap_or(0));
                    let _ = reply.try_send(answer);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            if stop.load(Ordering::Acquire) {
                break;
            }
            if let Ok(now_ms) = crate::unix_millis() {
                self.tick(now_ms);
            }
        }
    }

    fn with_ledger<T>(&self, operation: impl FnOnce(&mut TicketWorkLedger) -> T) -> Option<T> {
        self.ledger
            .lock()
            .ok()
            .map(|mut ledger| operation(&mut ledger))
    }

    /// One bounded pass: lapse stale claims, follow jobs, verify queued
    /// tickets, and issue a few owed reactions.
    pub(crate) fn tick(&mut self, now_ms: i64) {
        let _ = self.with_ledger(|ledger| ledger.expire_claude_claims(now_ms));
        if now_ms.saturating_sub(self.last_job_poll_ms) >= JOB_POLL_PASS_INTERVAL_MS {
            self.last_job_poll_ms = now_ms;
            self.poll_jobs(now_ms);
        }
        if now_ms.saturating_sub(self.last_verify_pass_ms) >= VERIFY_PASS_INTERVAL_MS {
            self.last_verify_pass_ms = now_ms;
            let due = self
                .with_ledger(|ledger| ledger.due_verifications(VERIFY_PER_PASS, now_ms))
                .and_then(Result::ok)
                .unwrap_or_default();
            for (key, kind) in due {
                self.verify(&key, kind, now_ms);
            }
        }
        if now_ms.saturating_sub(self.last_reaction_pass_ms) >= REACTION_PASS_INTERVAL_MS {
            self.last_reaction_pass_ms = now_ms;
            self.apply_reactions(None, REACTIONS_PER_PASS);
        }
    }

    fn poll_jobs(&mut self, now_ms: i64) {
        let Some(jobs) = self.jobs.as_mut() else {
            return;
        };
        let due = self
            .ledger
            .lock()
            .map(|ledger| ledger.jobs_to_poll(JOBS_PER_PASS, now_ms))
            .unwrap_or_default();
        for job in due {
            let status = jobs.job_status(&job);
            if let Ok(mut ledger) = self.ledger.lock() {
                let _ = match status {
                    Ok(status) => ledger.observe_job_status(&job, status, now_ms).map(|_| ()),
                    Err(()) => ledger.job_status_unavailable(&job, now_ms),
                };
            }
        }
    }

    /// Check one ticket against GitHub now. Returns whether it is finished.
    fn verify(&mut self, key: &TicketKey, kind: TicketKind, now_ms: i64) -> bool {
        let facts = self
            .github
            .as_mut()
            .and_then(|github| github.delivery(key, kind).ok());
        let finished = facts
            .as_ref()
            .is_some_and(|facts| delivery_finished(facts, &self.team_logins));
        let _ = self.with_ledger(|ledger| {
            if finished {
                ledger.mark_finished(key, now_ms).map(|_| ())
            } else {
                ledger.verified_unfinished(key, facts.is_some(), now_ms)
            }
        });
        finished
    }

    /// Issue up to `limit` owed reactions; returns how many now stand.
    fn apply_reactions(&mut self, only: Option<&TicketKey>, limit: usize) -> u32 {
        let pending = self
            .ledger
            .lock()
            .map(|ledger| ledger.pending_reactions(only, limit))
            .unwrap_or_default();
        let mut applied = 0;
        for reaction in pending {
            let (Ok(channel), Ok(ts)) = (
                ChannelId::new(&reaction.channel),
                MessageTs::new(&reaction.ts),
            ) else {
                continue;
            };
            let outcome = self.slack.add_reaction(&channel, &ts, reaction.name);
            if outcome == ReactionOutcome::Applied {
                applied += 1;
            }
            let _ = self.with_ledger(|ledger| ledger.record_reaction(&reaction, outcome));
        }
        applied
    }

    /// Find the posts of a ticket the ledger has never seen.
    fn search_posts(&mut self, key: &TicketKey, kind: TicketKind, now_ms: i64) {
        for channel in self.channels.clone().iter().take(MAX_CLAIM_SEARCH_CHANNELS) {
            let Ok(messages) = self.slack.recent_messages(channel, CLAIM_SEARCH_HISTORY) else {
                continue;
            };
            for (ts, text) in messages {
                if key.mentioned_in(&text) {
                    let _ = self.with_ledger(|ledger| {
                        ledger.record_post(key, kind, channel.as_str(), &ts, now_ms)
                    });
                }
            }
        }
    }

    /// Serve one claim or release.
    pub(crate) fn handle_claim(
        &mut self,
        request: &TicketClaimRequest,
        now_ms: i64,
    ) -> Result<TicketClaimOutcome, String> {
        let (key, kind) = TicketKey::parse_url(&request.issue_url)
            .ok_or_else(|| String::from("ticket_url_invalid"))?;
        let holder = ClaimHolder::parse_claude(&request.holder)
            .ok_or_else(|| String::from("ticket_holder_invalid"))?;
        let known_posts = self
            .with_ledger(|ledger| ledger.posts(&key).len())
            .ok_or_else(|| String::from("ticket_ledger_unavailable"))?;
        if known_posts == 0 {
            self.search_posts(&key, kind, now_ms);
        }
        // Conflicts are reported from fresh job statuses where Manage answers,
        // so a session is not told a finished job still holds the ticket.
        let jobs = self
            .with_ledger(|ledger| ledger.ticket_jobs(&key))
            .unwrap_or_default();
        if let Some(reader) = self.jobs.as_mut() {
            for job in jobs.into_iter().take(MAX_CLAIM_JOB_REFRESH) {
                let status = reader.job_status(&job);
                if let Ok(mut ledger) = self.ledger.lock() {
                    let _ = match status {
                        Ok(status) => ledger.observe_job_status(&job, status, now_ms).map(|_| ()),
                        Err(()) => ledger.job_status_unavailable(&job, now_ms),
                    };
                }
            }
        }
        let recorded = self
            .with_ledger(|ledger| {
                if request.release {
                    ledger.release(&key, kind, &holder, now_ms)
                } else {
                    ledger.claim(&key, kind, &holder, now_ms)
                }
            })
            .ok_or_else(|| String::from("ticket_ledger_unavailable"))?;
        if recorded.is_err() {
            return Err(String::from("ticket_ledger_full"));
        }
        if request.release {
            let verify = self
                .with_ledger(|ledger| ledger.is_queued(&key) && !ledger.actively_claimed(&key))
                .unwrap_or(false);
            if verify {
                self.verify(&key, kind, now_ms);
            }
        }
        let reacted = self.apply_reactions(Some(&key), MAX_POSTS_PER_TICKET);
        let (posts_found, conflicts) = self
            .with_ledger(|ledger| (ledger.posts(&key).len(), ledger.conflicts(&key, &holder)))
            .ok_or_else(|| String::from("ticket_ledger_unavailable"))?;
        Ok(TicketClaimOutcome {
            posts_found: u32::try_from(posts_found).unwrap_or(u32::MAX),
            reacted,
            conflicts: conflicts
                .into_iter()
                .map(|conflict| (conflict.holder, conflict.status))
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt as _;

    const URL: &str = "https://github.com/example/project/issues/42";
    const CHANNEL: &str = "C0RESERVED01";
    const OTHER_CHANNEL: &str = "C0RESERVED02";
    const POST: &str = "1723542000.000100";
    const SECOND_POST: &str = "1723542999.000200";
    const NOW: i64 = 1_800_000_000_000;

    fn key() -> (TicketKey, TicketKind) {
        TicketKey::parse_url(URL).expect("ticket")
    }

    fn claude(session: &str) -> ClaimHolder {
        ClaimHolder::parse_claude(&format!("claude:{session}")).expect("holder")
    }

    #[derive(Default)]
    struct FakeSlack {
        reactions: Arc<Mutex<Vec<(String, String, ReactionName)>>>,
        history: BTreeMap<String, Vec<(String, String)>>,
        searched: Arc<Mutex<Vec<String>>>,
        refuse: bool,
    }

    impl TicketSlack for FakeSlack {
        fn add_reaction(
            &mut self,
            channel: &ChannelId,
            ts: &MessageTs,
            name: ReactionName,
        ) -> ReactionOutcome {
            if self.refuse {
                return ReactionOutcome::Refused;
            }
            self.reactions.lock().expect("reactions").push((
                channel.as_str().to_owned(),
                ts.as_str().to_owned(),
                name,
            ));
            ReactionOutcome::Applied
        }

        fn recent_messages(
            &mut self,
            channel: &ChannelId,
            _limit: u16,
        ) -> Result<Vec<(String, String)>, ()> {
            self.searched
                .lock()
                .expect("searched")
                .push(channel.as_str().to_owned());
            Ok(self
                .history
                .get(channel.as_str())
                .cloned()
                .unwrap_or_default())
        }
    }

    struct FakeJobs(Arc<Mutex<BTreeMap<String, TicketJobStatus>>>);

    impl TicketJobReader for FakeJobs {
        fn job_status(&mut self, job_id: &str) -> Result<TicketJobStatus, ()> {
            self.0.lock().expect("jobs").get(job_id).copied().ok_or(())
        }
    }

    struct FakeGitHub(Arc<Mutex<Option<TicketFacts>>>);

    impl TicketDeliveryReader for FakeGitHub {
        fn delivery(&mut self, _key: &TicketKey, _kind: TicketKind) -> Result<TicketFacts, ()> {
            self.0.lock().expect("facts").clone().ok_or(())
        }
    }

    struct Harness {
        reactor: TicketReactor,
        reactions: Arc<Mutex<Vec<(String, String, ReactionName)>>>,
        searched: Arc<Mutex<Vec<String>>>,
        jobs: Arc<Mutex<BTreeMap<String, TicketJobStatus>>>,
        facts: Arc<Mutex<Option<TicketFacts>>>,
        _handle: TicketClaimHandle,
    }

    fn harness(history: BTreeMap<String, Vec<(String, String)>>) -> Harness {
        let slack = FakeSlack {
            history,
            ..FakeSlack::default()
        };
        let reactions = Arc::clone(&slack.reactions);
        let searched = Arc::clone(&slack.searched);
        let jobs = Arc::new(Mutex::new(BTreeMap::new()));
        let facts = Arc::new(Mutex::new(None));
        let (handle, requests) = claim_queue();
        Harness {
            reactor: TicketReactor {
                ledger: Arc::new(Mutex::new(TicketWorkLedger::in_memory())),
                slack: Box::new(slack),
                jobs: Some(Box::new(FakeJobs(Arc::clone(&jobs)))),
                github: Some(Box::new(FakeGitHub(Arc::clone(&facts)))),
                team_logins: vec![String::from("team-member")],
                channels: vec![
                    ChannelId::new(CHANNEL).expect("channel"),
                    ChannelId::new(OTHER_CHANNEL).expect("channel"),
                ],
                requests,
                last_job_poll_ms: 0,
                last_verify_pass_ms: 0,
                last_reaction_pass_ms: 0,
            },
            reactions,
            searched,
            jobs,
            facts,
            _handle: handle,
        }
    }

    fn claim_request(session: &str, release: bool) -> TicketClaimRequest {
        TicketClaimRequest {
            issue_url: String::from(URL),
            holder: format!("claude:{session}"),
            release,
        }
    }

    fn open_issue_with_comment(author: &str, body: &str) -> TicketFacts {
        TicketFacts::Issue {
            closed: false,
            state_reason: None,
            latest_comment: Some((author.to_owned(), body.to_owned())),
        }
    }

    #[test]
    fn a_ticket_key_ignores_case_kind_and_presentation() {
        let (issue, issue_kind) = key();
        let (pull, pull_kind) =
            TicketKey::parse_url("https://github.com/Example/Project/pull/42").expect("pull");
        assert_eq!(issue.identity(), pull.identity());
        assert_eq!(issue_kind, TicketKind::Issue);
        assert_eq!(pull_kind, TicketKind::Pull);
        assert_eq!(
            pull.url(pull_kind),
            "https://github.com/Example/Project/pull/42"
        );
        assert!(TicketKey::parse_url("example/project#42").is_none());
        assert!(TicketKey::parse_url("https://example.invalid/a/b/issues/1").is_none());
        assert!(issue.mentioned_in(
            "<https://github.com/example/project/issues/42|example/project#42> please"
        ));
        assert!(issue.mentioned_in("(see https://github.com/example/project/issues/42)."));
        assert!(!issue.mentioned_in("https://github.com/example/project/issues/421"));
    }

    #[test]
    fn holders_are_closed_and_a_session_may_only_name_itself_as_claude() {
        assert_eq!(
            ClaimHolder::parse("claude:session-1")
                .expect("claude")
                .as_string(),
            "claude:session-1"
        );
        assert_eq!(
            ClaimHolder::parse("monique-job:job_123")
                .expect("job")
                .as_string(),
            "monique-job:job_123"
        );
        assert!(ClaimHolder::parse_claude("monique-job:job_123").is_none());
        for refused in ["", "claude:", "claude:a b", "someone:x", "claude:é"] {
            assert!(ClaimHolder::parse(refused).is_none(), "{refused:?}");
        }
        assert!(ClaimHolder::parse(&format!("claude:{}", "a".repeat(129))).is_none());
    }

    #[test]
    fn the_delivery_rule_reads_merges_closures_and_only_the_latest_team_comment() {
        let team = vec![String::from("Team-Member")];
        assert!(delivery_finished(
            &TicketFacts::Pull { merged: true },
            &team
        ));
        assert!(!delivery_finished(
            &TicketFacts::Pull { merged: false },
            &team
        ));
        for (reason, finished) in [
            (None, true),
            (Some("completed"), true),
            (Some("not_planned"), false),
            (Some("duplicate"), false),
        ] {
            let facts = TicketFacts::Issue {
                closed: true,
                state_reason: reason.map(str::to_owned),
                latest_comment: None,
            };
            assert_eq!(delivery_finished(&facts, &team), finished, "{reason:?}");
        }
        for body in [
            "C'est en ligne",
            "Déployé en production",
            "Corrigé, merci",
            "DEPLOYED to staging and live",
            "fixed",
            "Le correctif est maintenant disponible",
            "Demande 1 … Déploiement : ok",
        ] {
            assert!(
                delivery_finished(&open_issue_with_comment("team-member", body), &team),
                "{body}"
            );
        }
        // The same words from someone outside the team, or a team reply that
        // reports no delivery, do not finish the ticket.
        assert!(!delivery_finished(
            &open_issue_with_comment("client-login", "c'est corrigé ?"),
            &team
        ));
        assert!(!delivery_finished(
            &open_issue_with_comment("team-member", "Je regarde ça demain"),
            &team
        ));
        assert!(!delivery_finished(
            &TicketFacts::Issue {
                closed: false,
                state_reason: None,
                latest_comment: None,
            },
            &team
        ));
        assert!(!delivery_finished(
            &open_issue_with_comment("team-member", "fixed"),
            &[]
        ));
    }

    #[test]
    fn a_claude_claim_searches_history_once_reacts_eyes_and_reports_no_conflict() {
        let mut history = BTreeMap::new();
        history.insert(
            CHANNEL.to_owned(),
            vec![
                (POST.to_owned(), format!("<{URL}|ticket>")),
                ("1723542001.000100".to_owned(), String::from("unrelated")),
            ],
        );
        let mut harness = harness(history);
        let outcome = harness
            .reactor
            .handle_claim(&claim_request("one", false), NOW)
            .expect("claim");
        assert_eq!(outcome.posts_found, 1);
        assert_eq!(outcome.reacted, 1);
        assert!(outcome.conflicts.is_empty());
        assert_eq!(
            *harness.reactions.lock().expect("reactions"),
            vec![(CHANNEL.to_owned(), POST.to_owned(), ReactionName::Eyes)]
        );
        assert_eq!(harness.searched.lock().expect("searched").len(), 2);

        // A second session's claim knows the post: no search, no second 👀,
        // and the first session is reported as a conflict.
        let outcome = harness
            .reactor
            .handle_claim(&claim_request("two", false), NOW + 1)
            .expect("claim");
        assert_eq!(outcome.posts_found, 1);
        assert_eq!(outcome.reacted, 0);
        assert_eq!(
            outcome.conflicts,
            vec![(String::from("claude:one"), String::from("claimed"))]
        );
        assert_eq!(harness.searched.lock().expect("searched").len(), 2);
        assert_eq!(harness.reactions.lock().expect("reactions").len(), 1);
    }

    #[test]
    fn a_claim_reports_an_active_monique_job_from_its_fresh_status() {
        let mut harness = harness(BTreeMap::new());
        let (ticket, kind) = key();
        {
            let mut ledger = harness.reactor.ledger.lock().expect("ledger");
            ledger
                .record_post(&ticket, kind, CHANNEL, POST, NOW)
                .expect("post");
            ledger
                .record_job(&ticket, kind, "job-1", Some(TicketJobStatus::Pending), NOW)
                .expect("job");
            ledger
                .record_job(
                    &ticket,
                    kind,
                    "job-old",
                    Some(TicketJobStatus::PendingApproval),
                    NOW,
                )
                .expect("job");
        }
        harness
            .jobs
            .lock()
            .expect("jobs")
            .insert(String::from("job-1"), TicketJobStatus::Running);
        harness
            .jobs
            .lock()
            .expect("jobs")
            .insert(String::from("job-old"), TicketJobStatus::Cancelled);
        let outcome = harness
            .reactor
            .handle_claim(&claim_request("one", false), NOW + 10)
            .expect("claim");
        assert_eq!(
            outcome.conflicts,
            vec![(String::from("monique-job:job-1"), String::from("running"))]
        );
        assert_eq!(outcome.reacted, 1);
        assert!(harness.searched.lock().expect("searched").is_empty());
    }

    #[test]
    fn a_release_that_github_shows_finished_reacts_check_mark() {
        let mut harness = harness(BTreeMap::new());
        let (ticket, kind) = key();
        harness
            .reactor
            .ledger
            .lock()
            .expect("ledger")
            .record_post(&ticket, kind, CHANNEL, POST, NOW)
            .expect("post");
        harness
            .reactor
            .handle_claim(&claim_request("one", false), NOW)
            .expect("claim");
        *harness.facts.lock().expect("facts") = Some(open_issue_with_comment(
            "team-member",
            "Corrigé et déployé en production.",
        ));
        let outcome = harness
            .reactor
            .handle_claim(&claim_request("one", true), NOW + 5)
            .expect("release");
        assert_eq!(outcome.reacted, 1);
        assert!(outcome.conflicts.is_empty());
        assert_eq!(
            *harness.reactions.lock().expect("reactions"),
            vec![
                (CHANNEL.to_owned(), POST.to_owned(), ReactionName::Eyes),
                (
                    CHANNEL.to_owned(),
                    POST.to_owned(),
                    ReactionName::WhiteCheckMark
                ),
            ]
        );
        let ledger = harness.reactor.ledger.lock().expect("ledger");
        assert!(ledger.is_finished(&ticket));
        assert!(!ledger.is_queued(&ticket));
    }

    #[test]
    fn an_unfinished_release_stays_queued_and_is_rechecked_at_the_cadence_until_it_expires() {
        let mut harness = harness(BTreeMap::new());
        let (ticket, kind) = key();
        harness
            .reactor
            .ledger
            .lock()
            .expect("ledger")
            .record_post(&ticket, kind, CHANNEL, POST, NOW)
            .expect("post");
        harness
            .reactor
            .handle_claim(&claim_request("one", false), NOW)
            .expect("claim");
        // The latest comment is the client's: the earlier team reply no
        // longer counts.
        *harness.facts.lock().expect("facts") =
            Some(open_issue_with_comment("client-login", "toujours cassé"));
        let outcome = harness
            .reactor
            .handle_claim(&claim_request("one", true), NOW + 1)
            .expect("release");
        assert_eq!(outcome.reacted, 0);
        assert!(
            harness
                .reactor
                .ledger
                .lock()
                .expect("ledger")
                .is_queued(&ticket)
        );

        // Not due again before the cadence…
        assert!(
            harness
                .reactor
                .ledger
                .lock()
                .expect("ledger")
                .due_verifications(VERIFY_PER_PASS, NOW + VERIFY_INTERVAL_MS - 1)
                .expect("due")
                .is_empty()
        );
        // …and verified on the pass after it, once the team replies.
        *harness.facts.lock().expect("facts") =
            Some(open_issue_with_comment("team-member", "C'est en ligne."));
        harness.reactor.last_verify_pass_ms = 0;
        harness.reactor.tick(NOW + 1 + VERIFY_INTERVAL_MS);
        assert!(
            harness
                .reactor
                .ledger
                .lock()
                .expect("ledger")
                .is_finished(&ticket)
        );
        assert!(harness.reactions.lock().expect("reactions").contains(&(
            CHANNEL.to_owned(),
            POST.to_owned(),
            ReactionName::WhiteCheckMark
        )));

        // A second ticket that never finishes is dropped after 21 days.
        let (other, other_kind) =
            TicketKey::parse_url("https://github.com/example/project/issues/43").expect("other");
        let mut ledger = harness.reactor.ledger.lock().expect("ledger");
        ledger
            .release(&other, other_kind, &claude("x"), NOW)
            .expect("release");
        assert!(ledger.is_queued(&other));
        assert!(
            ledger
                .due_verifications(VERIFY_PER_PASS, NOW + VERIFY_MAX_AGE_MS)
                .expect("due")
                .is_empty()
        );
        assert!(!ledger.is_queued(&other));
    }

    #[test]
    fn monique_job_status_drives_eyes_then_check_mark_without_github() {
        let mut harness = harness(BTreeMap::new());
        let (ticket, kind) = key();
        {
            let mut ledger = harness.reactor.ledger.lock().expect("ledger");
            ledger
                .record_post(&ticket, kind, CHANNEL, POST, NOW)
                .expect("post");
            ledger
                .record_job(
                    &ticket,
                    kind,
                    "job-1",
                    Some(TicketJobStatus::PendingApproval),
                    NOW,
                )
                .expect("job");
        }
        harness.reactor.tick(NOW);
        assert!(harness.reactions.lock().expect("reactions").is_empty());

        harness
            .jobs
            .lock()
            .expect("jobs")
            .insert(String::from("job-1"), TicketJobStatus::Running);
        harness.reactor.tick(NOW + JOB_POLL_MIN_INTERVAL_MS);
        assert_eq!(
            *harness.reactions.lock().expect("reactions"),
            vec![(CHANNEL.to_owned(), POST.to_owned(), ReactionName::Eyes)]
        );

        harness
            .jobs
            .lock()
            .expect("jobs")
            .insert(String::from("job-1"), TicketJobStatus::Done);
        harness.reactor.tick(NOW + 2 * JOB_POLL_MIN_INTERVAL_MS);
        assert_eq!(
            harness.reactions.lock().expect("reactions").last(),
            Some(&(
                CHANNEL.to_owned(),
                POST.to_owned(),
                ReactionName::WhiteCheckMark
            ))
        );
        assert!(
            harness
                .reactor
                .ledger
                .lock()
                .expect("ledger")
                .is_finished(&ticket)
        );
    }

    #[test]
    fn a_failed_job_releases_the_ticket_into_verification_and_never_marks_it_done() {
        let mut ledger = TicketWorkLedger::in_memory();
        let (ticket, kind) = key();
        ledger
            .record_job(&ticket, kind, "job-1", Some(TicketJobStatus::Running), NOW)
            .expect("job");
        assert!(ledger.actively_claimed(&ticket));
        ledger
            .observe_job_status("job-1", TicketJobStatus::Failed, NOW + 1)
            .expect("failed");
        assert!(!ledger.actively_claimed(&ticket));
        assert!(!ledger.is_finished(&ticket));
        assert!(ledger.is_queued(&ticket));
    }

    #[test]
    fn a_new_post_for_a_finished_ticket_gets_no_eyes_and_is_verified_again() {
        let harness = harness(BTreeMap::new());
        let (ticket, kind) = key();
        {
            let mut ledger = harness.reactor.ledger.lock().expect("ledger");
            ledger
                .record_post(&ticket, kind, CHANNEL, POST, NOW)
                .expect("post");
            ledger
                .claim(&ticket, kind, &claude("one"), NOW)
                .expect("claim");
            ledger
                .release(&ticket, kind, &claude("one"), NOW)
                .expect("release");
            ledger.mark_finished(&ticket, NOW + 1).expect("finished");
            // Another session claims while the ticket is finished: still no
            // 👀 is owed on anything.
            ledger
                .claim(&ticket, kind, &claude("two"), NOW + 2)
                .expect("claim");
            ledger
                .record_post(&ticket, kind, OTHER_CHANNEL, SECOND_POST, NOW + 3)
                .expect("reminder post");
        }
        let pending = harness
            .reactor
            .ledger
            .lock()
            .expect("ledger")
            .pending_reactions(None, 16);
        assert!(
            pending
                .iter()
                .all(|reaction| reaction.name != ReactionName::Eyes
                    || reaction.channel != OTHER_CHANNEL),
            "{pending:?}"
        );
        // The reminder post owes nothing yet, the original keeps its ✅, and
        // the ticket waits for one more check.
        assert!(
            pending
                .iter()
                .all(|reaction| reaction.channel != OTHER_CHANNEL)
        );
        let ledger = harness.reactor.ledger.lock().expect("ledger");
        assert!(ledger.is_queued(&ticket));
        assert!(ledger.is_finished(&ticket));
    }

    #[test]
    fn a_refused_reaction_is_retried_a_bounded_number_of_times() {
        let mut ledger = TicketWorkLedger::in_memory();
        let (ticket, kind) = key();
        ledger
            .record_post(&ticket, kind, CHANNEL, POST, NOW)
            .expect("post");
        ledger
            .claim(&ticket, kind, &claude("one"), NOW)
            .expect("claim");
        for _ in 0..MAX_REACTION_ATTEMPTS {
            let pending = ledger.pending_reactions(None, 8);
            assert_eq!(pending.len(), 1);
            ledger
                .record_reaction(&pending[0], ReactionOutcome::Refused)
                .expect("record");
        }
        assert!(ledger.pending_reactions(None, 8).is_empty());
        // An unknown transport result is not counted: it is simply retried.
        ledger
            .record_post(&ticket, kind, CHANNEL, SECOND_POST, NOW)
            .expect("post");
        let pending = ledger.pending_reactions(None, 8);
        ledger
            .record_reaction(&pending[0], ReactionOutcome::Unknown)
            .expect("record");
        assert_eq!(ledger.pending_reactions(None, 8).len(), 1);
    }

    #[test]
    fn a_stale_claude_claim_lapses_into_verification() {
        let mut ledger = TicketWorkLedger::in_memory();
        let (ticket, kind) = key();
        ledger
            .claim(&ticket, kind, &claude("one"), NOW)
            .expect("claim");
        assert!(ledger.has_claude_claim(&ticket));
        assert!(!ledger.expire_claude_claims(NOW + 1).expect("expire"));
        assert!(
            ledger
                .expire_claude_claims(NOW + CLAUDE_CLAIM_TTL_MS)
                .expect("expire")
        );
        assert!(!ledger.has_claude_claim(&ticket));
        assert!(ledger.is_queued(&ticket));
    }

    #[test]
    fn the_ledger_survives_a_reopen_and_refuses_a_foreign_document() {
        let directory = tempfile::tempdir().expect("directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private");
        let path = directory.path().join(TICKET_WORK_FILE);
        let (ticket, kind) = key();
        {
            let mut ledger = TicketWorkLedger::open(path.clone()).expect("open");
            ledger
                .record_post(&ticket, kind, CHANNEL, POST, NOW)
                .expect("post");
            ledger
                .record_job(&ticket, kind, "job-1", Some(TicketJobStatus::Claimed), NOW)
                .expect("job");
            ledger
                .claim(&ticket, kind, &claude("one"), NOW)
                .expect("claim");
        }
        let mode = std::fs::metadata(&path).expect("file").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let reopened = TicketWorkLedger::open(path.clone()).expect("reopen");
        assert_eq!(reopened.posts(&ticket).len(), 1);
        assert!(reopened.has_claude_claim(&ticket));
        assert_eq!(
            reopened.conflicts(&ticket, &claude("two")),
            vec![
                ClaimConflict {
                    holder: String::from("monique-job:job-1"),
                    status: String::from("claimed"),
                },
                ClaimConflict {
                    holder: String::from("claude:one"),
                    status: String::from("claimed"),
                },
            ]
        );
        std::fs::write(&path, br#"{"schema":"other","tickets":[]}"#).expect("write");
        assert!(TicketWorkLedger::open(path).is_err());
    }

    #[test]
    fn backfill_seeds_posts_and_jobs_once_from_thread_bindings() {
        let mut ledger = TicketWorkLedger::in_memory();
        let bindings = [(CHANNEL, POST, "job-1", URL), (CHANNEL, POST, "job-1", URL)];
        ledger.backfill(bindings, NOW).expect("backfill");
        ledger.backfill(bindings, NOW + 1).expect("backfill again");
        let (ticket, _) = key();
        assert_eq!(ledger.posts(&ticket).len(), 1);
        assert_eq!(ledger.ticket_jobs(&ticket), vec![String::from("job-1")]);
        // A job of unknown status is polled, but not counted as work.
        assert!(!ledger.actively_claimed(&ticket));
        assert_eq!(ledger.jobs_to_poll(4, NOW), vec![String::from("job-1")]);
    }

    #[test]
    fn the_ledger_stays_bounded_and_keeps_live_work() {
        let mut ledger = TicketWorkLedger::in_memory();
        for number in 1..=MAX_TICKETS as u32 {
            let (ticket, kind) = TicketKey::parse_url(&format!(
                "https://github.com/example/project/issues/{number}"
            ))
            .expect("ticket");
            ledger
                .record_post(&ticket, kind, CHANNEL, POST, NOW + i64::from(number))
                .expect("post");
        }
        let (first, kind) =
            TicketKey::parse_url("https://github.com/example/project/issues/1").expect("ticket");
        ledger
            .claim(&first, kind, &claude("one"), NOW)
            .expect("claim");
        let (newest, kind) =
            TicketKey::parse_url("https://github.com/example/project/issues/9999").expect("new");
        ledger
            .record_post(&newest, kind, CHANNEL, POST, NOW + 10_000)
            .expect("post");
        assert_eq!(ledger.tickets.len(), MAX_TICKETS);
        assert!(ledger.has_claude_claim(&first), "claimed ticket kept");
        let (evicted, _) =
            TicketKey::parse_url("https://github.com/example/project/issues/2").expect("ticket");
        assert!(
            ledger.posts(&evicted).is_empty(),
            "oldest idle ticket evicted"
        );
    }

    #[test]
    fn a_claim_handle_reports_busy_and_unavailable_rather_than_blocking() {
        let (handle, requests) = claim_queue();
        let mut answers = Vec::new();
        for _ in 0..MAX_QUEUED_CLAIMS {
            answers.push(handle.submit(claim_request("one", false)).expect("queued"));
        }
        assert_eq!(
            handle.submit(claim_request("one", false)).err(),
            Some("ticket_claims_busy")
        );
        drop(requests);
        assert_eq!(
            handle.submit(claim_request("one", false)).err(),
            Some("ticket_claims_unavailable")
        );
    }

    #[test]
    fn invalid_claims_are_refused_before_anything_is_recorded() {
        let mut harness = harness(BTreeMap::new());
        let bad_url = TicketClaimRequest {
            issue_url: String::from("https://example.invalid/issues/1"),
            holder: String::from("claude:one"),
            release: false,
        };
        assert_eq!(
            harness.reactor.handle_claim(&bad_url, NOW).err().as_deref(),
            Some("ticket_url_invalid")
        );
        let bad_holder = TicketClaimRequest {
            issue_url: String::from(URL),
            holder: String::from("monique-job:job-1"),
            release: false,
        };
        assert_eq!(
            harness
                .reactor
                .handle_claim(&bad_holder, NOW)
                .err()
                .as_deref(),
            Some("ticket_holder_invalid")
        );
        assert!(harness.searched.lock().expect("searched").is_empty());
    }
}
