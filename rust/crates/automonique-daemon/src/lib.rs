// SPDX-License-Identifier: Elastic-2.0

//! Foreground Automonique control-plane process.
//!
//! This daemon owns a private runtime directory, a durable SQLite store, one
//! fenced process generation, and a peer-authenticated Unix admin socket.
//!
//! It performs real external effects. Every one of them is gated on an
//! operator-written configuration file under the state directory, so a host
//! with no configuration still has none of them; a host that has one has all
//! of that surface, not a subset. The effects, and the file that enables each:
//!
//! * **Telegram** (`telegram`, `telegram_bridge`) — long-polls, publishes a
//!   command menu, and replies. Enabled by `telegram/bot.conf`; without an
//!   `allow=` line the token is dropped and no client is built.
//! * **Slack** (`slack`) — a Socket Mode worker that reads channels, posts
//!   messages, opens modals, and publishes an App Home view. Enabled by
//!   `slack/slack.conf`.
//! * **GitHub** (`github`, `github_actions`) — creates issues, comments,
//!   edits checklists, and runs typed work-management mutations, each
//!   individually enabled by an `action=` line in `github/github.conf` and
//!   each carrying an idempotency marker that is searched for before a create
//!   and re-searched after an ambiguous transport failure.
//! * **Support backend** (`ticket_intake`, `ticket_work`) — polls the ticket
//!   board into a durable store and drafts replies. Enabled by
//!   `support/fleet.conf`. Intake itself sends nothing; sending an email or
//!   dispatching a job happens only on an explicit operator intent.
//! * **Provider execution** (`execute`, `compose`, `run_lane`) — a real
//!   supervised process launch through the composed sandbox boundary, with
//!   brokered egress (`egress`) restricted to the destinations named in the
//!   `egress-destinations` file. Enabled by the `provider` file; absent, every
//!   compose refuses `ComposeRefusal::NotConfigured`.
//! * **Self-improvement** (`improvement_worker`, `improvement_publish`,
//!   `improvement_github`, `release_activation`) — pushes a tested candidate,
//!   opens and merges pull requests, repoints a release symlink, and restarts
//!   a systemd user unit. Enabled by `improvement-lab.json`, and gated behind
//!   two separate administrator approvals bound by an HMAC challenge.
//!
//! What it still does not do, in the words of the sites that say so: it runs
//! no scheduler, so the automation store decides nothing; it acts on nobody's
//! behalf, so the approval ledger permits nothing; it has no executor, so the
//! batch registry throttles nothing. It establishes no release trust —
//! nothing in this crate calls `release_trust_root`, so a provider binary is
//! admitted by pinned digest and workspace identity, never by an attested
//! signature. Its structured-log surface is limited to bounded, content-free
//! readiness and shutdown-drain records, and it cannot acknowledge a Telegram
//! callback query.

use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use automonique_observability::{
    GenAiUsageObservation, MetricName, MetricValue, RuntimeObservation, StoreProjection,
    render_exposition,
};
use automonique_policy::approval::{
    ApprovalEvidence, ApprovalGate, ApprovalPolicyRefusal, ApprovalRequirement, ApprovalSources,
    OperatorSurfaces,
};
use automonique_policy::peer::{Admission, PeerCredential, PeerPolicy};
use automonique_protocol::admin::{
    AdminInstanceId, AdminOutboxEvidence, AdminOutboxEvidenceParts, AdminReconciliationEvidence,
    AdminRefusalCategory, AdminRequest, AdminResponse, DaemonState, DaemonStatus,
    DurableStateCounts, DurableStateCountsParts, GenerationHandoffView, GenerationTenureView,
    GenerationsView, LocalRequest, MAX_ADMIN_CANONICAL_BYTES, MAX_GENERATION_HISTORY_ENTRIES,
    MAX_RELOAD_TRANSITIONS, OperationalMetric, OperationalStatus, OperationalStatusParts,
    OutboxReconciliationDecision, ReloadStatusView, ReloadTransitionView,
};
use automonique_protocol::approval_api::{
    ApprovalContinuation, ApprovalCursor, ApprovalDecision, ApprovalDisposition, ApprovalKey,
    ApprovalListPage, ApprovalReceiptView, ApprovalRecordParts, ApprovalRecordView,
    ApprovalRefusal, ApprovalRequest, ApprovalResponse, ApprovalSubject, ApprovalsBySubject,
    DecideRequest, Decider, ListApprovals, RecordApproval, RecordedApproval,
};
use automonique_protocol::audit::{AuditCategory, AuditEvent, AuditOutcome, AuditRecord};
use automonique_protocol::automation::{AutomationActor, EnablementState};
use automonique_protocol::automation_api::{
    AutomationContinuation, AutomationCursor, AutomationId, AutomationListPage,
    AutomationReceiptView, AutomationRecordParts, AutomationRecordView, AutomationRefusal,
    AutomationRequest, AutomationResponse, ListAutomations, PauseReason, RegisterAutomation,
    SetEnablement,
};
use automonique_protocol::batch_api::{
    AdvanceMember, BatchApiError, BatchContinuation, BatchCursor, BatchDetailResult, BatchListPage,
    BatchReceiptView, BatchRecordView, BatchRefusal, BatchRequest, BatchResponse, ListBatches,
    MemberReceiptParts, MemberReceiptView, MemberView, RegisterBatch,
};
use automonique_protocol::batch_runner::{
    BatchId, BatchLabel, BatchMemberKey, ConcurrencyPolicy, MemberProgress,
};
use automonique_protocol::codec::{LENGTH_PREFIX_BYTES, RequestId, decode_frame, encode_frame};
use automonique_protocol::digest::{ALGORITHM, Sha256, Sha256Digest};
use automonique_protocol::execute_api::ApprovalContextField;
use automonique_protocol::execute_api::{
    CancelRunOutcome, ExecuteRefusal, ExecuteRequest, ExecuteResponse,
};
use automonique_protocol::journal::{CursorResume, RetainedRange};
use automonique_protocol::platform::{
    Capabilities as PlatformCapabilities, Freshness, FreshnessState, PlatformAction,
    PlatformMethod, PlatformRequest, PlatformResponse, PlatformText, PlatformTransport,
    ReceiptOutcome, ResourceAuthority, ResourceCoordinate, ResourceId, ResourceKind,
    ResourceRecord, SessionList, SessionRecord, Snapshot,
};
use automonique_protocol::platform_api::{
    MAX_PLATFORM_REQUEST_CANONICAL_BYTES, PlatformRequestMessage, PlatformResponseMessage,
};
use automonique_protocol::primitives::Revision;
use automonique_protocol::provenance::{CausationId, CorrelationId, Provenance, TraceId};
use automonique_protocol::runs_api::{
    Continuation, LifecycleCoverage, ListRuns, MAX_LIFECYCLE_EVENTS, RunCursor, RunDetailView,
    RunLifecycleEvent, RunListPage, RunState, RunSummary, RunsRefusal, RunsRequest, RunsResponse,
    SpoolEventKind, SubmissionState,
};
use automonique_protocol::tools::RunId;
use automonique_runner::dispatch::DispatchOutcome;
use automonique_runner::{RunSpec, RunSpecDecodeError, Spool};
use automonique_store::approval_ledger::{
    ApprovalDecision as StoreApprovalDecision, ApprovalDecisionRecord,
    ApprovalDisposition as StoreApprovalDisposition, ApprovalEntry, ApprovalLedger,
    ApprovalLedgerError,
};
use automonique_store::approval_requests::{
    ApprovalContext, ApprovalOutcome, ApprovalProposal, ApprovalRequestError,
    ApprovalRequestRecord, ApprovalRequests, ApprovalState, MAX_APPROVAL_REQUEST_PAGE,
    StoredApprovalContext,
};
use automonique_store::audit_chain::{AuditAppend, AuditChain, GENESIS_PREV_HASH};
use automonique_store::automation_store::{
    AutomationRecord, AutomationRegistration, AutomationStore, AutomationStoreError,
    EnablementState as StoreEnablementState, EnablementTransition,
};
use automonique_store::batch_registry::{
    BatchRecord, BatchRegistration, BatchRegistry, BatchRegistryError,
    ConcurrencyPolicy as StoreConcurrencyPolicy, MemberAdvance, MemberProgress as StoreProgress,
    MemberRecord,
};
use automonique_store::generation_audit::{
    GenerationAudit, GenerationAuditError, SelfEndKind, Succession, TenureEnding, TenureOpening,
    TenureRecord,
};
use automonique_store::platform_store::{ActionAdmission, PlatformStore, PlatformStoreError};
use automonique_store::provider_journal::ProviderJournal;
use automonique_store::reload_audit::{ReloadAudit, ReloadAuditError};
use automonique_store::run_index::{
    RunIndex, RunIndexEntry, RunIndexError, RunIndexRecord, RunSpoolState,
};
use automonique_store::run_submissions::{
    RunSubmission, RunSubmissionError, RunSubmissionLog, RunSubmissionState,
};
use automonique_store::{
    GenerationLease, InboxSubmission, IntakePauseRequest, IntakeResumeRequest, LeaseExpiryRequest,
    LeaseOwnerIdentity, LeaseRenewal, LeaseRequest,
    OutboxReconciliationDecision as StoreOutboxDecision, OutboxReconciliationRequest,
    ReconciliationDecision, ReconciliationRequest, StatusSnapshot, Store, StoreError,
};
use nix::sys::signal::{SigSet, SigmaskHow, Signal, pthread_sigmask};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::socket::{getsockopt, sockopt};
use nix::unistd::geteuid;

mod agent_activity;
pub mod agent_followup;
pub mod agent_harness;
pub mod agent_lane_journal;
pub mod agent_profile;
pub mod agent_runtime;
pub mod agent_tool_broker;
pub mod approval_policy;
pub mod ask;
pub mod attempt_adoption;
pub mod attempt_host;
pub mod cancel_custody;
pub mod candidate;
pub mod codex_usage;
pub mod compose;
mod control_lock;
pub mod deepseek_balance;
pub mod egress;
pub mod execute;
pub mod github;
pub mod github_actions;
pub mod improvement_github;
pub mod improvement_publish;
pub mod improvement_worker;
pub mod improvements;
pub mod jcode_session_host;
mod lease_identity;
mod lease_time;
pub mod local_knowledge;
pub mod manage_config;
pub mod managed_sessions;
mod managed_tui;
pub mod mcp_client;
pub mod memory_config;
pub mod model_inventory;
pub mod parity_trace;
pub mod pm2_inventory;
pub mod progress;
pub mod progress_hub;
pub mod provider_health;
pub mod provider_session_host;
pub mod release_activation;
pub mod release_builder;
pub mod reload;
pub mod run_lane;
pub mod shadow;
pub mod shadow_config;
pub mod shot;
pub mod site_inventory;
pub mod skill_runtime;
pub mod slack;
mod structured_log;
mod synthetic;
mod systemd;
mod telegram;
pub mod telegram_bridge;
pub mod ticket_intake;
mod ticket_presentation;
pub mod ticket_work;
pub mod work_brief;
pub mod work_method;

use attempt_host::DaemonAttemptHost;

/// Socket filename inside the private product runtime directory.
pub const ADMIN_SOCKET_NAME: &str = concat!("admin", ".sock");

/// Minimum interval between live provider model-catalog reads.
///
/// Snapshot and subscription clients can poll much faster than the provider
/// catalog changes. Keeping the observation in the durable platform store and
/// refreshing it at this bounded cadence avoids spawning an App Server for
/// every UI tick while a daemon restart still forces an immediate read.
const PLATFORM_MODEL_REFRESH_MILLIS: i64 = 30_000;

/// Mutations implemented by this local authority. They are projected as
/// ordinary v1 resources so strict existing clients remain wire-compatible
/// while newer clients can build action surfaces without guessing from the
/// generic `execute` method.
const PLATFORM_LOCAL_ACTIONS: [PlatformAction; 6] = [
    PlatformAction::StartRun,
    PlatformAction::StopRun,
    PlatformAction::DecideApproval,
    PlatformAction::SubmitRequest,
    PlatformAction::FollowUp,
    PlatformAction::Steer,
];

/// Database filename inside the private product state directory.
pub const DATABASE_NAME: &str = concat!("automonique", ".sqlite3");

/// Process-exclusion lock beside, never on, the SQLite files.
pub const CONTROL_LOCK_NAME: &str = concat!("daemon", ".lock");

/// Durable provider process/session/turn journal and GenAI usage source.
pub const PROVIDER_JOURNAL_NAME: &str = concat!("provider-journal", ".sqlite3");

/// Run submission custody database, a sibling of [`DATABASE_NAME`].
///
/// Separate, like every other sibling log in `automonique-store`: its schema
/// versions independently of the scheduler's, and a submission is not scheduler
/// state. What the separation costs is stated in that module's documentation.
pub const RUN_SUBMISSIONS_NAME: &str = concat!("run-submissions", ".sqlite3");

/// Durable run index, a sibling of [`DATABASE_NAME`].
///
/// The derived read model behind the Runs API listing: one row per accepted
/// submission, binding it to its run and to the last state a writer reported.
/// Separate from [`RUN_SUBMISSIONS_NAME`] for the reason every sibling log is
/// separate — its schema versions independently — and because custody and a
/// read model are different things: the first is the source of truth, the
/// second is rebuildable from it.
pub const RUN_INDEX_NAME: &str = concat!("run-index", ".sqlite3");

/// Durable idempotency receipts, projections, cursors, and controller leases
/// for the platform-v1 endpoint.
pub const PLATFORM_STORE_NAME: &str = concat!("platform-v1", ".sqlite3");

/// Durable normalized provider-session to Automonique-run bindings.
pub const MANAGED_SESSIONS_NAME: &str = concat!("managed-sessions", ".sqlite3");

/// Durable automation enablement registry, a sibling of [`DATABASE_NAME`].
///
/// One row per automation, recording whether an operator has it in service and
/// who withdrew it. Separate for the reason every sibling log is separate — its
/// schema versions independently — and because an enablement decision is not
/// scheduler state.
///
/// WHAT THIS FILE DOES NOT DO. It holds no schedule, no trigger and no action,
/// and nothing in this build reads it to decide whether to run anything: there
/// is no scheduler and no executor. A `paused` row therefore suppresses nothing
/// today. It is written now so that the scheduler, when it lands, reads its
/// enablement out of a durable record rather than inventing one.
pub const AUTOMATION_REGISTRY_NAME: &str = concat!("automations", ".sqlite3");

/// Durable write-once approval decision ledger, a sibling of [`DATABASE_NAME`].
///
/// One row per decision, recording what was approved or refused, by whom, and
/// when. Separate for the reason every sibling log is separate — its schema
/// versions independently — and because a decision record is not scheduler
/// state.
///
/// WHAT THIS FILE NOW DOES. A `granted` row under an `apr-` key **admits a
/// launch**: [`Daemon::start_run`] reads this ledger through
/// [`APPROVAL_REQUESTS_NAME`] before any attempt starts, and a `denied` row
/// refuses one. That is new — every earlier release of this comment said the
/// opposite, truthfully, because nothing consulted the file.
///
/// WHAT IT STILL DOES NOT DO. It holds no pending state, by design: a decision
/// that was never made has no row here, and the question it answers lives in
/// [`APPROVAL_REQUESTS_NAME`]. It records a decider without verifying one — the
/// tier check happens at the surface that accepted the decision — and it is not
/// the per-session binding, which is `automonique_store::provider_journal`'s
/// `provider_approvals` table, keyed on `(session_id, approval_key)`. No
/// transaction spans this file and either of those two.
pub const APPROVAL_LEDGER_NAME: &str = concat!("approvals", ".sqlite3");

/// Durable approval proposals, a sibling of [`DATABASE_NAME`].
///
/// One row per thing awaiting an operator decision, keyed by an opaque `apr-`
/// reference and bound to the exact launch context it was raised for. Separate
/// from [`APPROVAL_LEDGER_NAME`] for the reason every sibling log is separate —
/// its schema versions independently — and for one more: that file is
/// write-once and has no pending state, which is the right shape for an answer
/// and the wrong shape for a question.
///
/// A decision touches both files and no transaction spans them. The ledger row
/// is written first and this row is transitioned second, so a crash in between
/// leaves a durable decision whose proposal still reads `pending` — a gap that
/// heals on the next read, because both halves are idempotent. The other order
/// would leave a proposal claiming an authority no ledger backs.
pub const APPROVAL_REQUESTS_NAME: &str = concat!("approval-requests", ".sqlite3");

/// Durable batch registry, a sibling of [`DATABASE_NAME`].
///
/// One row per batch recording the membership it declared, and one row per
/// member recording the progress a writer last reported for it. Separate for the
/// reason every sibling log is separate — its schema versions independently —
/// and because a declared membership is not scheduler state.
///
/// WHAT THIS FILE DOES NOT DO. It submits nothing: registering a batch writes no
/// row to [`RUN_SUBMISSIONS_NAME`], reserves no run identity and takes custody of
/// nothing, so a registered batch causes no run to exist. It schedules nothing
/// and throttles nothing — the concurrency policy is stored because the batch
/// declared it, and no executor in this build reads it, because there is no
/// executor. And a member's progress is a *writer's claim*: [`RUN_INDEX_NAME`]
/// is the true binding from a submission to the state its run reached, this file
/// never joins it, and no transaction spans the two. A `completed` member here
/// means somebody said so.
pub const BATCH_REGISTRY_NAME: &str = concat!("batches", ".sqlite3");

/// Durable host-wide cancellation ledger, a sibling of [`DATABASE_NAME`].
///
/// Separate for the same reason every sibling log is: its schema versions
/// independently, and a cancellation request is not scheduler state. Being a
/// sibling *of this state directory* is also what makes the daemon's
/// single-dispatcher argument work — one state directory admits one daemon, so
/// one ledger file has one owner. See [`attempt_host`].
pub const RUN_CANCEL_LEDGER_NAME: &str = concat!("run-cancel-ledger", ".sqlite3");

/// Durable hash-chained audit records, a sibling of [`DATABASE_NAME`].
///
/// Separate for the reason every sibling is, plus one specific to this file: it
/// is append-only and never pruned, so its growth is unlike any other store's
/// and an operator who wants to archive it should be moving one file rather
/// than a table out of a shared one.
///
/// `automonique audit verify` and the `doctor` report both locate it by joining
/// this name onto the product state directory, and `automonique-cli` pins the
/// spelling by literal because it does not depend on this crate.
pub const AUDIT_CHAIN_NAME: &str = concat!("audit-chain", ".sqlite3");

/// Durable support ticket record, a sibling of [`DATABASE_NAME`].
///
/// One row per fleet support issue this host has seen on the board, carrying the
/// fleet's own fields verbatim beside two instants and one lifecycle this host
/// owns. Separate for the reason every sibling log is separate — its schema
/// versions independently — and because a support ticket is not scheduler state.
///
/// WHAT THIS FILE DOES NOT DO. It answers nobody: no reply, no note and no email
/// is sent on account of a row in it, because [`ticket_intake`] reads the board
/// and writes here and does nothing else. It also does not exist on a daemon
/// with no fleet configuration — the file is created when the intake host is
/// composed, and an unconfigured host composes nothing.
pub const SUPPORT_TICKETS_NAME: &str = concat!("support-tickets", ".sqlite3");

/// Durable roster of operator members, a sibling of [`DATABASE_NAME`].
///
/// One row per non-admin operator an administrator added from the Telegram
/// control surface. Separate from the bot configuration for the reason every
/// runtime record is separate from the file that configures it: the
/// configuration is the owner's, edited by hand and read at startup, while this
/// is the daemon's, written while it runs.
///
/// WHAT THIS FILE DOES NOT DO. It grants no administrative authority and cannot
/// be made to. Administrators are named in `telegram/bot.conf` and nowhere else,
/// so a row here can widen who may *read* this daemon's state and can never
/// widen who may spend a provider call or manage users. It also does not exist
/// on a host whose administrators never added anybody — the first `/admin add`
/// creates it, and nothing else does.
pub const OPERATOR_MEMBERS_NAME: &str = concat!("operator-members", ".sqlite3");

/// Durable append-only record of this generation's hand-offs, a sibling of
/// [`DATABASE_NAME`].
///
/// The `generations` row in the main database is overwritten in place on every
/// takeover, so it answers only "who may act right now". This file is the
/// history that row destroys: one tenure per `(generation_id, lease_epoch)`,
/// closed exactly once, and one handoff row per successor recording what it
/// found open when it arrived.
///
/// WHAT THIS FILE DOES NOT DO. It carries no authority. Nothing in this daemon
/// reads it to decide whether it may act — that decision is the generation
/// lease's alone, and is taken before this file is opened at all. A tenure row
/// proves only that a claim was recorded.
pub const GENERATION_AUDIT_NAME: &str = concat!("generation-audit", ".sqlite3");

/// Durable reload epochs and phase transitions, kept separate from generation
/// tenure history so an adjacent rollback release can continue reading its v1
/// generation-audit database unchanged.
pub const RELOAD_AUDIT_NAME: &str = concat!("reload-audit", ".sqlite3");

/// This deployment's brokered-egress destination policy, a sibling of
/// [`DATABASE_NAME`].
///
/// A text file, not a database, because it is the one input here that an
/// operator writes and a reviewer reads. It exists because the sandbox spec has
/// no destination list: a document can declare `brokered_named` egress and
/// cannot say where to, so the deployment answers. See [`egress`] for the format
/// and for what this arrangement does and does not buy. An absent file permits
/// no brokered egress at all.
pub const EGRESS_DESTINATIONS_NAME: &str = "egress-destinations";

/// Maximum administration payload accepted by the daemon.
pub const MAX_ADMIN_PAYLOAD_BYTES: usize =
    if MAX_PLATFORM_REQUEST_CANONICAL_BYTES > MAX_ADMIN_CANONICAL_BYTES {
        MAX_PLATFORM_REQUEST_CANONICAL_BYTES
    } else {
        MAX_ADMIN_CANONICAL_BYTES
    };

/// Ceiling this daemon re-opens a finished run's spool under, to read its
/// lifecycle.
///
/// Deliberately above any single document's own spool budget rather than equal
/// to it. [`Spool::open`] refuses a file larger than the ceiling it is given, so
/// a reader that re-used the writer's budget would be unable to read exactly the
/// spool that had filled it — the one a reader most wants to see. Reading more
/// than a document budgeted for costs this process memory it has already
/// bounded; refusing to read it would cost the record.
const MAX_READ_SPOOL_BYTES: u64 = 64 * 1024 * 1024;

const GENERATION_ID: &str = "foreground";
const LEASE_TTL_MS: i64 = 30_000;
const LEASE_RENEW_INTERVAL_MS: i64 = 10_000;
/// Bot-lease TTL, strictly inside the generation TTL: the store refuses a bot
/// lease that would outlive its generation authority, and the bot lease is
/// always acquired or renewed moments after the generation lease.
const TELEGRAM_LEASE_TTL_MS: i64 = 20_000;
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const ACCEPT_POLL: Duration = Duration::from_millis(25);
const SHUTDOWN_WORKER_DIAGNOSTIC_BUDGET: Duration = Duration::from_secs(20);
const STARTUP_TIMEOUT_EXTENSION: Duration = Duration::from_secs(5 * 60);

/// Refusal category both intake lanes answer with while an operator pause is
/// live.
///
/// Distinct from `reconciliation_required` on purpose: a submitter that retries
/// on a degraded generation is waiting for a repair, while one that retries
/// through a pause is waiting for a person.
const INTAKE_PAUSED_CATEGORY: &str = "intake_paused";

/// Configuration for one foreground daemon instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonConfig {
    /// Existing private per-user runtime root, normally `$XDG_RUNTIME_DIR`.
    pub runtime_root: PathBuf,
    /// Existing or creatable private per-user state root.
    pub state_root: PathBuf,
}

impl DaemonConfig {
    /// Resolve the standard XDG locations without falling back to a home path.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::EnvironmentMissing`] if either required location
    /// is absent or not valid UTF-8 filesystem data.
    pub fn from_environment() -> Result<Self, DaemonError> {
        let runtime_root = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .ok_or(DaemonError::EnvironmentMissing("XDG_RUNTIME_DIR"))?;
        let state_root = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .ok_or(DaemonError::EnvironmentMissing("XDG_STATE_HOME"))?;
        Ok(Self {
            runtime_root,
            state_root,
        })
    }

    /// Product-owned runtime directory.
    #[must_use]
    pub fn runtime_dir(&self) -> PathBuf {
        self.runtime_root.join("automonique")
    }

    /// Product-owned state directory.
    #[must_use]
    pub fn state_dir(&self) -> PathBuf {
        self.state_root.join("automonique")
    }

    /// Local administration endpoint.
    #[must_use]
    pub fn admin_socket(&self) -> PathBuf {
        self.runtime_dir().join(ADMIN_SOCKET_NAME)
    }

    /// Live progress endpoint, a sibling of [`DaemonConfig::admin_socket`].
    ///
    /// A second socket rather than another request/response protocol on the first, and the
    /// reason is the admin socket's framing: one request, one response, one
    /// connection, served on the serve thread. A subscription is the opposite
    /// shape — one request and an unbounded stream of answers — and folding it
    /// into that loop would mean the serve thread could be held by a client
    /// watching a run. See [`crate::progress_hub`].
    #[must_use]
    pub fn progress_socket(&self) -> PathBuf {
        self.runtime_dir().join(progress_hub::PROGRESS_SOCKET_NAME)
    }

    /// Durable database path.
    #[must_use]
    pub fn database_path(&self) -> PathBuf {
        self.state_dir().join(DATABASE_NAME)
    }

    /// Process-exclusion lock for the complete product state root.
    #[must_use]
    pub fn control_lock_path(&self) -> PathBuf {
        self.state_dir().join(CONTROL_LOCK_NAME)
    }

    /// Durable provider journal and GenAI usage path.
    #[must_use]
    pub fn provider_journal_path(&self) -> PathBuf {
        self.state_dir().join(PROVIDER_JOURNAL_NAME)
    }

    /// Durable run submission custody path.
    #[must_use]
    pub fn run_submissions_path(&self) -> PathBuf {
        self.state_dir().join(RUN_SUBMISSIONS_NAME)
    }

    /// Durable host-wide cancellation ledger path.
    #[must_use]
    pub fn run_cancel_ledger_path(&self) -> PathBuf {
        self.state_dir().join(RUN_CANCEL_LEDGER_NAME)
    }

    /// Durable hash-chained audit record path.
    #[must_use]
    pub fn audit_chain_path(&self) -> PathBuf {
        self.state_dir().join(AUDIT_CHAIN_NAME)
    }

    /// Durable run index path.
    #[must_use]
    pub fn run_index_path(&self) -> PathBuf {
        self.state_dir().join(RUN_INDEX_NAME)
    }

    /// Durable platform-v1 kernel path.
    #[must_use]
    pub fn platform_store_path(&self) -> PathBuf {
        self.state_dir().join(PLATFORM_STORE_NAME)
    }

    /// Durable normalized provider-session bindings.
    #[must_use]
    pub fn managed_sessions_path(&self) -> PathBuf {
        self.state_dir().join(MANAGED_SESSIONS_NAME)
    }

    /// Durable automation enablement registry path.
    #[must_use]
    pub fn automation_registry_path(&self) -> PathBuf {
        self.state_dir().join(AUTOMATION_REGISTRY_NAME)
    }

    /// Durable approval decision ledger path.
    #[must_use]
    pub fn approval_ledger_path(&self) -> PathBuf {
        self.state_dir().join(APPROVAL_LEDGER_NAME)
    }

    /// Durable approval proposal path.
    #[must_use]
    pub fn approval_requests_path(&self) -> PathBuf {
        self.state_dir().join(APPROVAL_REQUESTS_NAME)
    }

    /// Durable batch registry path.
    #[must_use]
    pub fn batch_registry_path(&self) -> PathBuf {
        self.state_dir().join(BATCH_REGISTRY_NAME)
    }

    /// Durable generation hand-off audit path.
    #[must_use]
    pub fn generation_audit_path(&self) -> PathBuf {
        self.state_dir().join(GENERATION_AUDIT_NAME)
    }

    /// Durable reload epoch and transition audit path.
    #[must_use]
    pub fn reload_audit_path(&self) -> PathBuf {
        self.state_dir().join(RELOAD_AUDIT_NAME)
    }

    /// Durable support ticket record path.
    #[must_use]
    pub fn support_tickets_path(&self) -> PathBuf {
        self.state_dir().join(SUPPORT_TICKETS_NAME)
    }

    /// Durable operator member roster path.
    #[must_use]
    pub fn operator_members_path(&self) -> PathBuf {
        self.state_dir().join(OPERATOR_MEMBERS_NAME)
    }

    /// This deployment's brokered-egress destination policy path.
    #[must_use]
    pub fn egress_destinations_path(&self) -> PathBuf {
        self.state_dir().join(EGRESS_DESTINATIONS_NAME)
    }
}

/// How often the approval sweep runs.
///
/// Expiry is a deadline rather than an event, so somebody has to look. Thirty
/// seconds bounds how long a proposal reads `pending` after its deadline
/// passed; it does not bound when a *decision* on such a proposal is refused,
/// because [`Daemon::record_decision`] compares the deadline itself and does
/// not wait for the sweep to notice.
const APPROVAL_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Largest number of proposals one sweep transitions or reminds about.
///
/// The sweep runs on the accept loop, so it must not be able to hold the socket
/// for an unbounded stretch. A backlog past this simply takes the next tick.
const APPROVAL_SWEEP_BATCH: usize = 64;

/// Who this daemon records as the actor on a sweep's own audit records.
///
/// Not an operator, and named so a reader cannot mistake it for one: the sweep
/// is the clock noticing, and an expiry is a thing that happened to a proposal
/// rather than a thing a person did to it.
pub const APPROVAL_SWEEPER: &str = "system:ttl";

/// The operator-facing text of one reminder rung.
///
/// The reference is the whole of the content. A notice that quoted the run, the
/// program or the prompt would put a document's contents into a chat message
/// this daemon did not compose and cannot bound, and the operator already has a
/// verb that reads the proposal in full.
fn approval_notice_text(rung: &str, request_key: &str) -> String {
    let opening = if rung == "escalation" {
        "An approval is close to expiring"
    } else {
        "An approval is still waiting"
    };
    format!("{opening}: `/approve {request_key}` or `/deny {request_key}`.")
}

/// Who this daemon records as the proposer of a launch approval.
///
/// The execute lane carries no actor — the request is a run identifier over a
/// peer-authenticated socket — so the proposer is the lane, named once here
/// rather than invented at each call site.
pub const APPROVAL_PROPOSER: &str = "automonique.execute";

/// Bound on how many stale proposals one open repairs.
///
/// A generation dies mid-decision at most as often as it dies, so the real
/// number is small; the bound is here so a corrupted table cannot make startup
/// unbounded.
const APPROVAL_RECONCILE_LIMIT: usize = 256;

/// Mint the opaque reference one proposal is addressed by.
///
/// A domain-separated digest over the coordinates that make this proposal *this
/// one*: the subject, the run, the document, the instant, and how many
/// proposals the subject already has. The last component is what makes a
/// re-proposal after an expiry a genuinely new key rather than the same one
/// recomputed — which is what makes reviving a terminal row impossible rather
/// than merely forbidden.
///
/// It is a digest rather than a counter because the reference travels through
/// chat messages and inline-button payloads, and a counter would let a reader
/// tell how many approvals this deployment has ever raised.
fn mint_request_key(
    subject: &str,
    run_id: &str,
    spec_digest: &str,
    requested_at_ms: i64,
    prior_proposals: usize,
) -> String {
    let mut material = Vec::from(APPROVAL_KEY_DOMAIN);
    for component in [
        subject,
        run_id,
        spec_digest,
        &requested_at_ms.to_string(),
        &prior_proposals.to_string(),
    ] {
        material.extend_from_slice(component.as_bytes());
        material.push(0);
    }
    let digest = Sha256::digest(&material).to_hex();
    format!(
        "{}{}",
        automonique_store::approval_requests::REQUEST_KEY_PREFIX,
        &digest[..automonique_store::approval_requests::REQUEST_KEY_HEX_BYTES]
    )
}

/// Domain separator for [`mint_request_key`].
///
/// Without it the reference would be a plain re-hash of values that appear
/// elsewhere, and a reader holding one digest could not tell which of them it
/// had.
const APPROVAL_KEY_DOMAIN: &[u8] = b"automonique.approval-request/v1/key\0";

/// The first bound field of an approved context that no longer matches.
///
/// A pure total function over two contexts: no file is read here and no clock
/// is consulted, so the whole comparison is enumerable by test. The order is
/// [`ApprovalContextField::ALL`]'s, so a refusal names the first real
/// difference rather than whichever one a hash map happened to yield.
///
/// The five arms are the five fields, one each. A field added to
/// [`ApprovalContext`] without an arm here fails to compile, which is the point
/// of listing them rather than looping: a binding that silently stopped
/// covering a field would weaken the approval without changing a test.
fn approved_context_drift(
    approved: &StoredApprovalContext,
    observed: ApprovalContext<'_>,
) -> Option<ApprovalContextField> {
    let ApprovalContext {
        spec_digest,
        program_path,
        program_sha256,
        prompt_sha256,
        cwd_token,
    } = observed;
    ApprovalContextField::ALL
        .into_iter()
        .find(|field| match field {
            ApprovalContextField::SpecDigest => approved.spec_digest != spec_digest,
            ApprovalContextField::ProgramPath => approved.program_path != program_path,
            ApprovalContextField::ProgramSha256 => approved.program_sha256 != program_sha256,
            ApprovalContextField::PromptSha256 => approved.prompt_sha256 != prompt_sha256,
            ApprovalContextField::CwdToken => approved.cwd_token != cwd_token,
        })
}

/// What one subject's proposal history says about it.
///
/// The newest *terminal decision* wins, and an expiry is deliberately not one:
/// a proposal that timed out leaves the subject undecided, which is what makes
/// a re-proposal the right next step rather than a second denial.
fn evidence_of(history: &[ApprovalRequestRecord]) -> ApprovalEvidence {
    history
        .iter()
        .rev()
        .find_map(|record| match record.state {
            ApprovalState::Granted => Some(ApprovalEvidence::Granted),
            ApprovalState::Denied => Some(ApprovalEvidence::Denied),
            ApprovalState::Pending | ApprovalState::Expired => None,
        })
        .unwrap_or(ApprovalEvidence::Undecided)
}

/// Complete decisions that reached the ledger but not their proposal.
///
/// The repair half of the two-database seam this lane documents. A pending row
/// whose key already has a ledger entry was decided by a generation that died
/// between the two writes; the entry says what was decided and when, so the
/// transition is replayed from it rather than guessed.
///
/// A pending row with no ledger entry is left alone: it is a question nobody
/// answered, which is exactly what it should look like.
fn reconcile_approval_requests(
    requests: &mut ApprovalRequests,
    ledger: &ApprovalLedger,
) -> Result<(), DaemonError> {
    let page = requests
        .page(0, APPROVAL_RECONCILE_LIMIT)
        .map_err(|error| DaemonError::ApprovalRequestsFailed(error.category()))?;
    for record in page.records {
        if !record.state.is_pending() {
            continue;
        }
        let Some(entry) = ledger
            .entry(&record.request_key)
            .map_err(|error| DaemonError::ApprovalLedgerFailed(error.category()))?
        else {
            continue;
        };
        let outcome = if entry.decision.grants() {
            ApprovalOutcome::Granted
        } else {
            ApprovalOutcome::Denied
        };
        match requests.decide(
            &record.request_key,
            record.revision,
            outcome,
            &record.request_key,
            entry.decided_at_ms,
        ) {
            // A row another writer repaired first is repaired; that is the
            // point of the fence, and it is not this daemon's failure.
            Ok(_) | Err(ApprovalRequestError::StaleRevision) => {}
            Err(error) => return Err(DaemonError::ApprovalRequestsFailed(error.category())),
        }
    }
    Ok(())
}

/// Whether one decision was newly recorded or found already recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDecisionDisposition {
    /// This call wrote the decision.
    Recorded,
    /// The exact decision was already durable. Nothing changed.
    AlreadyRecorded,
}

impl ApprovalDecisionDisposition {
    /// Stable machine-oriented spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::AlreadyRecorded => "already_recorded",
        }
    }
}

/// What one recorded decision established.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalDecisionReceipt {
    /// Row identity of the durable decision in the ledger.
    pub entry_id: i64,
    /// Opaque reference the proposal was addressed by.
    pub request_key: String,
    /// What was decided about.
    pub subject: String,
    /// Run the proposal was raised for.
    pub run_id: String,
    /// What was decided.
    pub outcome: ApprovalOutcome,
    /// Who decided, as the deciding surface's tier-checked actor.
    ///
    /// Empty on an [`ApprovalDecisionDisposition::AlreadyRecorded`] answer read
    /// back from the proposal row rather than the ledger: that row records the
    /// decision, not the decider, and reporting this call's own actor as the
    /// earlier decider would be a lie about who answered.
    pub decider: String,
    /// The instant the durable decision records. On a replay this is the
    /// *first* decision's instant.
    pub decided_at_ms: i64,
    /// Whether this call wrote the decision or found it.
    pub disposition: ApprovalDecisionDisposition,
}

/// Why one decision was refused. Exactly one reason per answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalDecisionRefusal {
    /// The reference is not an approval reference at all.
    ///
    /// Distinct from [`ApprovalDecisionRefusal::UnknownRequest`] so a surface
    /// can tell "that is not one of ours" from "we have never seen it", which
    /// is what lets one verb serve two reference grammars.
    MalformedKey,
    /// No proposal is recorded under that reference.
    UnknownRequest,
    /// The proposal already carries a different decision. Nothing was written.
    AlreadyDecided {
        /// What the durable decision says.
        outcome: ApprovalOutcome,
        /// Who it records, when this answer came from the ledger.
        decider: String,
    },
    /// The deadline passed before this decision arrived.
    ///
    /// Not folded into [`ApprovalDecisionRefusal::AlreadyDecided`]: a question
    /// that closed unanswered and one that was answered are different facts,
    /// and only the first is worth re-proposing.
    RequestExpired,
    /// The decision ledger holds its full capacity.
    LedgerFull,
    /// This daemon's own durable state would not answer.
    DecisionUnavailable,
}

impl ApprovalDecisionRefusal {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::MalformedKey => "malformed_key",
            Self::UnknownRequest => "unknown_request",
            Self::AlreadyDecided { .. } => "already_decided",
            Self::RequestExpired => "request_expired",
            Self::LedgerFull => "ledger_full",
            Self::DecisionUnavailable => "decision_unavailable",
        }
    }
}

impl fmt::Display for ApprovalDecisionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedKey => formatter.write_str("that is not an approval reference"),
            Self::UnknownRequest => formatter.write_str("no approval is recorded under that key"),
            Self::AlreadyDecided { outcome, .. } => {
                write!(formatter, "that approval is already {outcome}")
            }
            Self::RequestExpired => formatter.write_str("that approval expired unanswered"),
            Self::LedgerFull => formatter.write_str("the approval ledger is full"),
            Self::DecisionUnavailable => {
                formatter.write_str("this daemon's approval state would not answer")
            }
        }
    }
}

impl Error for ApprovalDecisionRefusal {}

/// A daemon lifecycle or local-control refusal.
#[derive(Debug)]
pub enum DaemonError {
    /// A required environment variable was absent.
    EnvironmentMissing(&'static str),
    /// A configured filesystem path is not absolute, private, owned, or safe.
    InsecurePath(&'static str),
    /// Another daemon is accepting connections at the configured endpoint.
    AlreadyRunning,
    /// systemd advertised an inherited listener that did not match the one
    /// exact admin-socket contract this daemon accepts.
    SocketActivationRefused,
    /// The connecting Unix peer is not the daemon's effective user.
    PeerDenied,
    /// The admin frame was incomplete, too large, or not admitted.
    ProtocolRefused(&'static str),
    /// Filesystem or local socket operation failed.
    Io(std::io::Error),
    /// Durable state operation failed.
    Store(StoreError),
    /// A previously claimed synthetic run has no durable terminal outcome.
    ReconciliationRequired,
    /// Host signal setup failed.
    Signal(nix::Error),
    /// The Telegram configuration or bot-lease lifecycle was refused. The
    /// payload is the stable category from the telegram module.
    TelegramRefused(&'static str),
    /// The durable run submission log failed in a way no client caused. The
    /// payload is the stable category from that module.
    RunSubmissionFailed(&'static str),
    /// The durable run index failed in a way no client caused. The payload is
    /// the stable category from that module, or one of this crate's own for a
    /// disagreement between the index and the custody it derives from.
    ///
    /// A submission is durable before its index row is written, so this never
    /// reports a lost document: it reports a read model that could not be
    /// extended or could not be believed.
    RunIndexFailed(&'static str),
    /// The platform-v1 durable kernel could not be opened or updated.
    PlatformStoreFailed(&'static str),
    /// The durable audit chain could not be opened. The payload is the stable
    /// category from `automonique_store::audit_chain`.
    ///
    /// Fail-closed at startup rather than on the first record: a daemon that
    /// cannot write down what it was asked to do must not publish an endpoint
    /// that accepts requests.
    AuditChainFailed(&'static str),
    /// The host-wide cancellation host could not be opened or could not be
    /// disposed cleanly. The payload is the stable category from
    /// [`attempt_host`].
    AttemptHostFailed(&'static str),
    /// The private cross-generation attempt route could not be bound or
    /// started. The payload is the stable category from [`attempt_adoption`].
    AttemptAdoptionFailed(&'static str),
    /// The durable automation registry failed in a way no client caused. The
    /// payload is the stable category from that module.
    ///
    /// Deliberately separate from the refusals an operator earns: a malformed
    /// field, an illegal transition and a stale revision are answered to the
    /// client, while corruption, a schema mismatch and storage failure say the
    /// daemon's own durable state is unsound and must not be presented as an
    /// operator error. [`automation_refusal`] is where the line is drawn.
    AutomationStoreFailed(&'static str),
    /// The durable approval ledger failed in a way no client caused. The
    /// payload is the stable category from that module.
    ///
    /// The same line [`AutomationStoreFailed`](Self::AutomationStoreFailed)
    /// draws: a malformed field, a lost cursor and a full ledger are the
    /// operator's to fix and are answered to the client in one closed word,
    /// while corruption, a schema mismatch, an unsafe path and storage failure
    /// say the daemon's own durable state is unsound and must not be presented
    /// as an operator error. [`refuse_approval`] is where the line is drawn. No
    /// variant of this error echoes any part of the payload that met it.
    ApprovalLedgerFailed(&'static str),
    /// The durable batch registry failed in a way no client caused. The payload
    /// is the stable category from that module.
    ///
    /// The same line [`ApprovalLedgerFailed`](Self::ApprovalLedgerFailed) draws:
    /// a malformed field, a duplicate identity, an illegal member transition, an
    /// incoherent sequence, a lost cursor and a full registry are the operator's
    /// to fix and are answered to the client in one closed word, while
    /// corruption, a schema mismatch, an unsafe path and storage failure say the
    /// daemon's own durable state is unsound and must not be presented as an
    /// operator error. [`refuse_batch`] is where the line is drawn. No variant of
    /// this error echoes any part of the payload that met it.
    BatchRegistryFailed(&'static str),
    /// The durable generation hand-off audit could not be opened, could not
    /// record this daemon's tenure, or could not close it. The payload is the
    /// stable category from that module.
    ///
    /// No client can cause this and no client is told about it: the audit is
    /// never on a request path.
    GenerationAuditFailed(&'static str),
    /// The durable reload state machine could not be opened or validated.
    ReloadAuditFailed(&'static str),
    /// The support fleet configuration, the ticket store, or the intake worker
    /// thread was refused. The payload is the stable category from
    /// [`ticket_intake`].
    ///
    /// Only a daemon whose state directory carries a fleet configuration can
    /// produce this: an absent one is the disabled state and is never an error.
    /// Like the Telegram gate, a present-but-wrong configuration refuses startup
    /// rather than being ignored, because ignoring it would hide an operator
    /// error behind an honest-looking disabled state.
    TicketIntakeRefused(&'static str),
    /// The Slack configuration was present and refused. The payload is the
    /// stable category from [`slack`].
    ///
    /// The same gate the support fleet and Telegram have, and refused at
    /// startup for the same reason — with one extra: this file is the only
    /// thing that decides which channels `/say` can post to, and a host that
    /// ignored a malformed channel map would be a host whose reachable set is
    /// not the one the owner wrote down.
    SlackRefused(&'static str),
    /// The durable approval proposal table failed in a way no client caused.
    /// The payload is the stable category from
    /// `automonique_store::approval_requests`.
    ///
    /// The same line [`ApprovalLedgerFailed`](Self::ApprovalLedgerFailed)
    /// draws: a malformed field, a conflicting key and a stale fence are
    /// answered to the caller, while corruption, a schema mismatch and storage
    /// failure say this daemon's own durable state is unsound.
    ApprovalRequestsFailed(&'static str),
    /// The standing approval configuration is present and unusable. The payload
    /// is the stable category from [`approval_policy`].
    ///
    /// Refused at startup for the reason the credential gates are, and one
    /// more: this file is one of the three inputs to the requirement every
    /// launch is composed against, and a daemon that ignored a malformed one
    /// would compose against a policy nobody wrote.
    ApprovalPolicyRefused(&'static str),
    /// The live progress endpoint could not be bound or started. The payload is
    /// the stable category from [`progress_hub`].
    ///
    /// Fatal at startup for the reason a refused admin socket is: the two are
    /// one endpoint as far as a client is concerned, and a daemon that answered
    /// status while nothing could watch a run would be reporting a capability
    /// it does not have.
    ProgressEndpointFailed(&'static str),
    /// The service manager's readiness/watchdog notification channel failed.
    ServiceManagerFailed(&'static str),
    /// The control lock path was unsafe or another live daemon holds it.
    ControlLockFailed(&'static str),
    /// Boot-inclusive lease time could not be sampled safely.
    LeaseClockFailed(&'static str),
    /// A suspend/resume boundary invalidated every lease held by this process.
    LeaseSuspended,
}

impl DaemonError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::EnvironmentMissing(_) => "environment_missing",
            Self::InsecurePath(_) => "insecure_path",
            Self::AlreadyRunning => "already_running",
            Self::SocketActivationRefused => "socket_activation_refused",
            Self::PeerDenied => "peer_denied",
            Self::ProtocolRefused(_) => "protocol_refused",
            Self::Io(_) => "io",
            Self::Store(error) => error.category(),
            Self::ReconciliationRequired => "reconciliation_required",
            Self::Signal(_) => "signal",
            Self::TelegramRefused(category) => category,
            Self::RunSubmissionFailed(category) => category,
            Self::RunIndexFailed(category) => category,
            Self::PlatformStoreFailed(category) => category,
            Self::AuditChainFailed(category) => category,
            Self::AttemptHostFailed(category) => category,
            Self::AttemptAdoptionFailed(category) => category,
            Self::AutomationStoreFailed(category) => category,
            Self::ApprovalLedgerFailed(category) => category,
            Self::BatchRegistryFailed(category) => category,
            Self::GenerationAuditFailed(category) => category,
            Self::ReloadAuditFailed(category) => category,
            Self::TicketIntakeRefused(category) => category,
            Self::SlackRefused(category) => category,
            Self::ApprovalRequestsFailed(category) => category,
            Self::ApprovalPolicyRefused(category) => category,
            Self::ProgressEndpointFailed(category) => category,
            Self::ServiceManagerFailed(category) => category,
            Self::ControlLockFailed(category) => category,
            Self::LeaseClockFailed(_) => "lease_clock",
            Self::LeaseSuspended => "lease_suspended",
        }
    }
}

impl fmt::Display for DaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvironmentMissing(name) => {
                write!(formatter, "required environment {name} is absent")
            }
            Self::InsecurePath(kind) => write!(formatter, "{kind} path is not private and owned"),
            Self::AlreadyRunning => formatter.write_str("another Automonique daemon is running"),
            Self::SocketActivationRefused => {
                formatter.write_str("the inherited admin listener was refused")
            }
            Self::PeerDenied => formatter.write_str("local administration peer was denied"),
            Self::ProtocolRefused(category) => {
                write!(
                    formatter,
                    "local administration protocol refused: {category}"
                )
            }
            Self::Io(error) => write!(formatter, "daemon I/O failed: {error}"),
            Self::Store(error) => write!(formatter, "daemon store failed: {error}"),
            Self::ReconciliationRequired => {
                formatter.write_str("synthetic scheduler requires reconciliation")
            }
            Self::Signal(error) => write!(formatter, "daemon signal setup failed: {error}"),
            Self::TelegramRefused(category) => {
                write!(formatter, "telegram host refused: {category}")
            }
            Self::RunSubmissionFailed(category) => {
                write!(formatter, "run submission log failed: {category}")
            }
            Self::RunIndexFailed(category) => {
                write!(formatter, "run index failed: {category}")
            }
            Self::PlatformStoreFailed(category) => {
                write!(formatter, "platform store failed: {category}")
            }
            Self::AuditChainFailed(category) => {
                write!(formatter, "audit chain failed: {category}")
            }
            Self::AttemptHostFailed(category) => {
                write!(formatter, "attempt host refused: {category}")
            }
            Self::AttemptAdoptionFailed(category) => {
                write!(formatter, "attempt adoption endpoint refused: {category}")
            }
            Self::AutomationStoreFailed(category) => {
                write!(formatter, "automation registry failed: {category}")
            }
            Self::ApprovalLedgerFailed(category) => {
                write!(formatter, "approval ledger failed: {category}")
            }
            Self::BatchRegistryFailed(category) => {
                write!(formatter, "batch registry failed: {category}")
            }
            Self::GenerationAuditFailed(category) => {
                write!(formatter, "generation audit failed: {category}")
            }
            Self::ReloadAuditFailed(category) => {
                write!(formatter, "reload audit failed: {category}")
            }
            Self::TicketIntakeRefused(category) => {
                write!(formatter, "support ticket intake refused: {category}")
            }
            Self::SlackRefused(category) => {
                write!(formatter, "slack configuration refused: {category}")
            }
            Self::ApprovalRequestsFailed(category) => {
                write!(formatter, "approval requests failed: {category}")
            }
            Self::ApprovalPolicyRefused(category) => {
                write!(formatter, "approval configuration refused: {category}")
            }
            Self::ProgressEndpointFailed(category) => {
                write!(formatter, "progress endpoint failed: {category}")
            }
            Self::ServiceManagerFailed(category) => {
                write!(formatter, "service manager notification failed: {category}")
            }
            Self::ControlLockFailed(category) => {
                write!(formatter, "daemon control lock refused: {category}")
            }
            Self::LeaseClockFailed(category) => write!(formatter, "lease clock failed: {category}"),
            Self::LeaseSuspended => formatter.write_str("lease authority was lost across suspend"),
        }
    }
}

impl Error for DaemonError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Signal(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for DaemonError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<StoreError> for DaemonError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

/// An opened daemon whose runtime and store are ready.
pub struct Daemon {
    listener: UnixListener,
    socket_path: PathBuf,
    store: Store,
    instance_id: AdminInstanceId,
    lease_epoch: u64,
    lease_expires_ms: i64,
    lease_time: lease_time::SuspendFence,
    socket_identity: (u64, u64),
    remove_socket_on_drop: bool,
    controller: automonique_core::Controller,
    reconciliation_run_id: Option<i64>,
    telegram: telegram::TelegramHost,
    /// Configured-channel Slack ticket intake and confirmation lifecycle.
    slack_tickets: slack::SlackTicketHost,
    run_submissions: RunSubmissionLog,
    /// The listing read model derived from `run_submissions`.
    ///
    /// A plain field rather than an `Option`, because unlike
    /// [`Daemon::attempt_host`] this handle owns no dispatcher and needs no
    /// ordered disposal: it is a database, and dropping it closes it. It is
    /// opened beneath the same fence and before the socket guard is disarmed,
    /// for the reason custody storage is — a daemon that cannot record what it
    /// accepted must not publish an endpoint that accepts.
    run_index: RunIndex,
    /// Durable platform-v1 action, cursor, attachment, and control state.
    platform: PlatformStore,
    /// Durable normalized provider-session to latest-run bindings.
    managed_sessions: managed_sessions::ManagedSessionStore,
    /// Wall-clock instant of the last provider model-catalog projection.
    /// `None` forces the first platform read after every daemon start to
    /// reconcile the durable projection with the live provider authority.
    platform_models_observed_ms: Option<i64>,
    /// The hash-chained audit record of what this daemon was asked to do.
    ///
    /// A plain field for the reason [`Daemon::run_index`] is one: it owns no
    /// dispatcher and needs no ordered disposal, because it is a database and
    /// dropping it closes it.
    ///
    /// Append-only and never read on the request path. A record is written
    /// *after* the thing it describes has already happened, so a failure to
    /// append never blocks or reverses an action — see
    /// [`Daemon::record_cancellation_audit`], which states what that trade
    /// buys.
    audit_chain: AuditChain,
    /// The durable record of which automations an operator has in service.
    ///
    /// A plain field for the same reason [`Daemon::run_index`] is: it owns no
    /// dispatcher and needs no ordered disposal. Nothing in this daemon *reads*
    /// it to decide anything — no scheduler consults it, because there is no
    /// scheduler — so its whole role in this build is to answer the automation
    /// control lane truthfully across restarts.
    automations: AutomationStore,
    /// The durable record of which approval decisions were made, and by whom.
    ///
    /// A plain field for the reason [`Daemon::run_index`] is: it owns no
    /// dispatcher and needs no ordered disposal. Nothing in this daemon *reads*
    /// it to decide anything — no handler consults a decision before acting,
    /// because no handler in this build acts on anybody's behalf — so its whole
    /// role here is to answer the approval lane truthfully across restarts.
    approvals: ApprovalLedger,
    /// The durable record of what is waiting for an operator decision.
    ///
    /// A plain field for the reason [`Daemon::run_index`] is: it owns no
    /// dispatcher and dropping it closes a database. Unlike its siblings this
    /// one *is* read on the request path — [`Daemon::start_run`] consults it
    /// before any attempt starts — which is what turns
    /// [`Daemon::approvals`] from a record into a gate.
    approval_requests: ApprovalRequests,
    /// This daemon's private state directory.
    ///
    /// Held because the approval lane hashes a prompt slot out of it when it
    /// raises a proposal, and re-deriving it from a config this struct no
    /// longer owns would be a second answer to a question with one.
    state_dir: PathBuf,
    /// The durable record of which submissions each batch declared, and where
    /// each of them was last reported to have got to.
    ///
    /// A plain field for the reason [`Daemon::run_index`] is: it owns no
    /// dispatcher and needs no ordered disposal. Nothing in this daemon *reads*
    /// it to decide anything — no executor consults a batch's concurrency
    /// ceiling, because there is no executor — so its whole role here is to
    /// answer the batch control lane truthfully across restarts.
    batches: BatchRegistry,
    /// This host's one cancellation dispatcher over its one durable ledger.
    ///
    /// `Option` only so [`Daemon::serve`] can dispose of it explicitly while
    /// the generation fence is still held — this type has a `Drop` impl, so a
    /// field cannot otherwise be moved out. It is `Some` for the whole life of
    /// a daemon a caller can observe.
    ///
    /// Held behind an [`Arc`] because [`execute`] lends it to every worker
    /// thread that has an attempt registered on it. That is the *only* sharing
    /// of this value, and it does not weaken the composition
    /// [`attempt_host`](crate::attempt_host) establishes: an `Arc` is one
    /// dispatcher over one ledger reached from several threads, not two
    /// dispatchers. [`Daemon::serve`] joins every worker before it unwraps the
    /// `Arc` to dispose of it, so disposal still happens exactly once and only
    /// when nothing can still register.
    attempt_host: Option<Arc<DaemonAttemptHost>>,
    /// Holder- and epoch-bound route a successor uses for source-owned
    /// attempts during generation overlap.
    attempt_adoption: Option<attempt_adoption::AttemptAdoptionEndpoint>,
    /// The durable history of who has held this generation.
    ///
    /// A plain field, like [`Daemon::run_index`]: it owns no dispatcher, and
    /// dropping it closes a database. Unlike that field it has one ordered
    /// duty at shutdown — closing this daemon's own tenure row while the
    /// generation lease that authorized it is still held — which
    /// [`Daemon::serve`] performs explicitly rather than leaving to `Drop`.
    generation_audit: GenerationAudit,
    /// Durable reload epochs and their append-only transition history.
    reload_audit: ReloadAudit,
    /// Durable revision of this daemon's own open tenure row.
    ///
    /// Recorded from what the audit returned rather than assumed to be one:
    /// closing is compare-and-set on it, and a constant here would be this
    /// crate asserting a fact about another crate's schema.
    tenure_revision: u64,
    execution_state: automonique_protocol::admin::ExecutionState,
    /// The one settable input to the approval requirement every launch is
    /// composed against.
    ///
    /// Read once at open, like the other configuration gates, because it is a
    /// property of the installation rather than of a request. The other two
    /// inputs are not settable: the host's is measured, and the call's arrives
    /// with the call.
    configured_approval_requirement: ApprovalRequirement,
    /// How long a proposal stays answerable, and when it is reminded about.
    ///
    /// Read once at open beside the requirement it belongs to, so one file
    /// answers both questions and a proposal cannot be raised under a lifetime
    /// from one generation and reminded under a ladder from another.
    approval_lifetime: approval_policy::ApprovalLifetime,
    /// The lane that starts contained attempts for custodied documents.
    ///
    /// Opened on every host, including one that can never execute anything:
    /// what a host cannot do is answered as a typed refusal on the wire, not by
    /// a daemon that declines to start. See [`execute::ExecutionLane`].
    ///
    /// `Option` for the reason [`Daemon::attempt_host`] is, and it is the same
    /// reason twice over: this type has a `Drop` impl, so a field cannot be
    /// moved out of it, and [`Daemon::serve`] must *consume* the lane while the
    /// generation fence is still held — joining its workers and releasing its
    /// reference to the attempt host are both ordered operations, not disposal
    /// a drop could perform. It is `Some` for the whole life of a daemon a
    /// caller can observe.
    execution: Option<execute::ExecutionLane>,
    /// The support-board intake worker, and the gate that decides whether it
    /// exists at all.
    ///
    /// A plain field: it owns its own disposal, and its `Drop` stops and joins
    /// whatever thread it started. [`Daemon::serve`] still shuts it down
    /// explicitly, for the reason it joins the execution lane and the Telegram
    /// poller — the thread writes to durable state this generation owns, so it
    /// must end while the generation is still held rather than whenever a field
    /// happens to drop.
    ///
    /// On a daemon with no `support/fleet.conf` this is
    /// [`ticket_intake::TicketIntakeHost::Disabled`]: no credential was read, no
    /// client was constructed and no ticket store file was created.
    ticket_intake: ticket_intake::TicketIntakeHost,
    /// Durable managed-client intake and platform-receipt worker.
    managed_tui: managed_tui::ManagedTuiHost,
    /// The live progress endpoint, bound beside the admin socket.
    ///
    /// `Option` for the reason [`Daemon::execution`] is one: it owns threads
    /// that must be joined *while the generation is still held*, and joining is
    /// an ordered operation rather than disposal a drop can perform. Binding it
    /// happens in [`Daemon::open`] and starting its accept thread happens in
    /// [`Daemon::serve`], which is the same split every other worker here has:
    /// a process that opened a daemon and never served has answered nobody.
    progress_endpoint: Option<progress_hub::ProgressEndpoint>,
    /// Recovery mode never composes an external transport and refuses starts.
    disconnected_recovery: bool,
    /// Held until every database and worker field above it has been dropped.
    _control_lock: control_lock::ControlLock,
}

struct SocketCleanup {
    path: PathBuf,
    identity: (u64, u64),
    armed: bool,
}

enum StartupAuthority {
    Acquire,
    Transferred {
        resources: candidate::AdoptedCandidateResources,
        lease: GenerationLease,
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum LeaseDisposition {
    Release,
    Retain,
}

impl SocketCleanup {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        if self.armed {
            remove_socket_if_identity(&self.path, self.identity);
        }
    }
}

impl Daemon {
    /// Establish private directories, durable state, the fenced generation,
    /// and the local administration endpoint.
    ///
    /// # Errors
    ///
    /// Refuses unsafe paths, an active endpoint, or store initialization failure.
    pub fn open(config: &DaemonConfig) -> Result<Self, DaemonError> {
        Self::open_with_mode(config, false)
    }

    fn open_with_mode(
        config: &DaemonConfig,
        disconnected_recovery: bool,
    ) -> Result<Self, DaemonError> {
        Self::open_with_authority(config, disconnected_recovery, StartupAuthority::Acquire)
    }

    fn open_transferred(
        config: &DaemonConfig,
        resources: candidate::AdoptedCandidateResources,
        lease: GenerationLease,
    ) -> Result<Self, DaemonError> {
        Self::open_with_authority(
            config,
            false,
            StartupAuthority::Transferred { resources, lease },
        )
    }

    fn open_with_authority(
        config: &DaemonConfig,
        disconnected_recovery: bool,
        authority: StartupAuthority,
    ) -> Result<Self, DaemonError> {
        validate_root(&config.runtime_root, "runtime root")?;
        ensure_private_dir(&config.state_root, "state root")?;
        let runtime_dir = config.runtime_dir();
        let state_dir = config.state_dir();
        ensure_private_dir(&runtime_dir, "runtime directory")?;
        ensure_private_dir(&state_dir, "state directory")?;
        let process_identity =
            lease_identity::ProcessIdentity::current().map_err(|error| match error {
                lease_identity::ProcessIdentityError::Io(error) => DaemonError::Io(error),
                lease_identity::ProcessIdentityError::Malformed(category) => {
                    DaemonError::ControlLockFailed(category)
                }
            })?;
        let mut lease_time =
            lease_time::SuspendFence::system().map_err(DaemonError::LeaseClockFailed)?;
        let lease_now_ms = lease_time
            .require_authority()
            .map_err(map_lease_authority_error)?;
        let mut store = Store::open_with_lease_time_source(
            config.database_path(),
            Arc::new(lease_time::BootTimeSource),
        )?;

        let now_ms = unix_millis()?;
        let socket_path = config.admin_socket();
        let (
            listener,
            transferred_progress_listener,
            control_lock,
            instance_id,
            lease,
            socket_identity,
            remove_socket_on_drop,
        ) = match authority {
            StartupAuthority::Acquire => {
                let control_lock = control_lock::ControlLock::acquire(config.control_lock_path())
                    .map_err(|error| match error {
                    control_lock::ControlLockError::Held => DaemonError::AlreadyRunning,
                    control_lock::ControlLockError::InsecurePath => {
                        DaemonError::ControlLockFailed("insecure_path")
                    }
                    control_lock::ControlLockError::Io(error) => DaemonError::Io(error),
                })?;
                let (listener, remove_socket_on_drop) = open_admin_listener(&socket_path)?;
                let socket_identity = validate_admin_listener(&listener, &socket_path)?;
                let mut socket_cleanup = SocketCleanup {
                    path: socket_path.clone(),
                    identity: socket_identity,
                    armed: remove_socket_on_drop,
                };

                // Establish endpoint exclusion before changing durable ownership. A
                // failed competing bind cannot leave a phantom generation lease.
                if let Some(previous) = store
                    .status_snapshot_at(GENERATION_ID, now_ms)?
                    .generation()
                    && previous.lease_expires_ms() > lease_now_ms
                {
                    let previous_identity = lease_identity::ProcessIdentity {
                        boot_id: previous.boot_id().to_owned(),
                        pid: previous.holder_pid(),
                        starttime: previous.holder_starttime(),
                    };
                    let previous_live =
                        previous_identity.is_live().map_err(|error| match error {
                            lease_identity::ProcessIdentityError::Io(error) => {
                                DaemonError::Io(error)
                            }
                            lease_identity::ProcessIdentityError::Malformed(category) => {
                                DaemonError::ControlLockFailed(category)
                            }
                        })?;
                    if previous_live {
                        return Err(DaemonError::AlreadyRunning);
                    }
                    store.expire_generation_lease_owner(LeaseExpiryRequest {
                        generation_id: previous.generation_id(),
                        holder_id: previous.holder_id(),
                        epoch: previous.lease_epoch(),
                        owner: LeaseOwnerIdentity {
                            boot_id: previous.boot_id(),
                            pid: previous.holder_pid(),
                            starttime: previous.holder_starttime(),
                        },
                        now_ms,
                    })?;
                }
                let instance = format!("daemon-{}-{now_ms}", std::process::id());
                let instance_id = AdminInstanceId::new(instance)
                    .map_err(|error| DaemonError::ProtocolRefused(error.category()))?;
                let lease = store.acquire_generation_lease_owned(
                    LeaseRequest {
                        generation_id: GENERATION_ID,
                        holder_id: instance_id.as_str(),
                        now_ms,
                        ttl_ms: LEASE_TTL_MS,
                    },
                    LeaseOwnerIdentity {
                        boot_id: &process_identity.boot_id,
                        pid: process_identity.pid,
                        starttime: process_identity.starttime,
                    },
                )?;
                socket_cleanup.disarm();
                (
                    listener,
                    None,
                    control_lock,
                    instance_id,
                    lease,
                    socket_identity,
                    remove_socket_on_drop,
                )
            }
            StartupAuthority::Transferred { resources, lease } => {
                let (listener, progress_listener, control_lock) = resources.into_parts();
                let socket_identity = validate_admin_listener(&listener, &socket_path)?;
                if lease.generation_id != GENERATION_ID
                    || lease.expires_ms <= lease_now_ms
                    || lease.boot_id != process_identity.boot_id
                    || lease.holder_pid != process_identity.pid
                    || lease.holder_starttime != process_identity.starttime
                {
                    return Err(DaemonError::Store(StoreError::StaleEpoch));
                }
                let durable = store.status_snapshot_at(GENERATION_ID, now_ms)?;
                let Some(current) = durable.generation() else {
                    return Err(DaemonError::Store(StoreError::StaleEpoch));
                };
                if current.holder_id() != lease.holder_id
                    || current.lease_epoch() != lease.epoch
                    || current.lease_expires_ms() != lease.expires_ms
                    || current.boot_id() != lease.boot_id
                    || current.holder_pid() != lease.holder_pid
                    || current.holder_starttime() != lease.holder_starttime
                {
                    return Err(DaemonError::Store(StoreError::StaleEpoch));
                }
                let instance_id = AdminInstanceId::new(lease.holder_id.clone())
                    .map_err(|error| DaemonError::ProtocolRefused(error.category()))?;
                (
                    listener,
                    Some(progress_listener),
                    control_lock,
                    instance_id,
                    lease,
                    socket_identity,
                    false,
                )
            }
        };
        let mut socket_cleanup = SocketCleanup {
            path: socket_path.clone(),
            identity: socket_identity,
            armed: remove_socket_on_drop,
        };

        // THE TENURE IS RECORDED SECOND, AND IMMEDIATELY.
        //
        // `generation_audit` states the ordering duty this code is the caller
        // for: acquire the lease first, record second. Recording first would
        // leave a row for a tenure that never had authority. Recording *late*
        // — after the four sibling databases below — would widen the window in
        // which this process holds the generation with nothing written down,
        // so the audit opens here rather than beside them.
        //
        // WHY AN UNRECORDABLE TENURE IS FATAL. A tenure row is derived audit
        // and holds custody of nothing, so refusing startup over it costs a
        // control plane that would otherwise have run. It is still the right
        // trade, for a reason that is not "consistency with the other opens":
        // an unrecorded tenure is not merely absent from the history, it
        // *corrupts* the next daemon's reading of it. The successor supersedes
        // whatever tenure it finds open, so a generation this process really
        // held and never wrote down makes the successor link its handoff row
        // to some older predecessor and claim adjacency that never existed.
        // The log would be wrong rather than short. A daemon whose own
        // hand-off story is unprovable also has no reload story, and this
        // build's entire claim about reload is that it is auditable.
        let mut generation_audit = GenerationAudit::open(config.generation_audit_path())
            .map_err(generation_audit_failed)?;
        // A failure anywhere below this point returns with the tenure open and
        // the generation lease held, and both are left that way deliberately:
        // this process did hold the generation, and it dies without releasing
        // it. Closing the row while abandoning the lease would manufacture
        // that module's crash window 4 — a log saying the tenure ended while
        // the main database still fences writes to it — on every refused
        // startup. Letting both lapse together is the honest pairing, and the
        // successor closes the row `superseded` when the lease expires.
        let tenure = record_tenure(
            &mut generation_audit,
            instance_id.as_str(),
            lease.epoch,
            now_ms,
        )?;
        let reload_audit = ReloadAudit::open(config.reload_audit_path())
            .map_err(|error| DaemonError::ReloadAuditFailed(error.category()))?;
        let generation_queues_clean =
            startup_queues_clean(&store.status_snapshot_at(GENERATION_ID, now_ms)?);

        // The execution measurement is taken here rather than beside the lane
        // below, because the Telegram host reports it in a status reply and a
        // second probe would be a second answer to a question with one.
        let execution_state = if disconnected_recovery {
            automonique_protocol::admin::ExecutionState::SandboxUnavailableLaneWired
        } else {
            Self::measure_execution_state()
        };

        // The Telegram host loads its explicit configuration and, when one
        // exists, acquires the durable bot lease beneath the generation fence
        // established above. An absent configuration is the disabled state; a
        // present-but-refused one fails startup rather than being ignored.
        //
        // A configuration that also names authorized users *composes* a live
        // control bridge here and dials nothing: `TelegramHost::start` is what
        // puts it on a thread, and only `serve` calls that.
        //
        // THE SLACK GATE, loaded first because it is the Telegram bridge's
        // sixth seam and because its refusal is its own. An absent
        // `slack/slack.conf` is the disabled state: no credential is read, no
        // client is constructed, and the two Slack commands answer that Slack
        // is not configured. A present-but-refused one fails startup here even
        // on a host with no Telegram at all, which is the point of loading it
        // outside the Telegram host: an operator who wrote a bad `slack.conf`
        // is told so whether or not anything is composed to use it.
        let ticket_gates = Arc::new(Mutex::new(
            telegram_bridge::TicketGateRegistry::open(
                state_dir.join("ticket-confirmations.v1.json"),
            )
            .map_err(|_| DaemonError::SlackRefused("ticket_gate_store_unavailable"))?,
        ));
        let telegram_question_configuration = if disconnected_recovery {
            None
        } else {
            telegram::TelegramBotConfig::load(&state_dir).map_err(|error| {
                DaemonError::TelegramRefused(telegram::TelegramHostError::Config(error).category())
            })?
        };
        let telegram_bot_id = telegram_question_configuration
            .as_ref()
            .map_or(0, telegram::TelegramBotConfig::bot_id);
        let (question_administrators, question_configured) =
            telegram_question_configuration.as_ref().map_or_else(
                || (Vec::new(), Vec::new()),
                telegram::TelegramBotConfig::question_operator_ids,
            );
        drop(telegram_question_configuration);
        let (mut slack_tickets, slack) = if disconnected_recovery {
            (slack::SlackTicketHost::Disabled, slack::SlackHost::Disabled)
        } else {
            (
                slack::SlackTicketHost::open(
                    &slack::SlackTicketHostParams {
                        state_dir: &state_dir,
                        database_path: &config.database_path(),
                        admin_socket: &config.admin_socket(),
                        run_index_path: &config.run_index_path(),
                        support_tickets_path: &config.support_tickets_path(),
                        operator_members_path: &config.operator_members_path(),
                        host_facts: telegram_bridge::HostFacts {
                            generation_id: GENERATION_ID.to_owned(),
                            holder_id: instance_id.as_str().to_owned(),
                            lease_epoch: lease.epoch,
                            bot_id: telegram_bot_id,
                            execution_state,
                        },
                        question_administrators,
                        question_configured,
                        generation_queues_clean,
                    },
                    Arc::clone(&ticket_gates),
                )
                .map_err(|error| DaemonError::SlackRefused(error.category()))?,
                slack::SlackHost::open(&state_dir)
                    .map_err(|error| DaemonError::SlackRefused(error.category()))?,
            )
        };
        let mut telegram = if disconnected_recovery {
            telegram::TelegramHost::Disabled
        } else {
            telegram::TelegramHost::open_with_ticket_gates(
                &telegram::TelegramHostParams {
                    state_dir: &state_dir,
                    database_path: &config.database_path(),
                    lease_time_source: Arc::new(lease_time::BootTimeSource),
                    run_index_path: &config.run_index_path(),
                    support_tickets_path: &config.support_tickets_path(),
                    operator_members_path: &config.operator_members_path(),
                    admin_socket: &config.admin_socket(),
                    generation_id: GENERATION_ID,
                    holder_id: instance_id.as_str(),
                    authority_lease_epoch: lease.epoch,
                    ttl_ms: TELEGRAM_LEASE_TTL_MS,
                    execution_state,
                },
                slack,
                ticket_gates,
            )
            .map_err(|error| DaemonError::TelegramRefused(error.category()))?
        };

        // Custody storage opens beneath the same fence and before the socket
        // guard is disarmed: a daemon that cannot hold documents must not
        // publish an endpoint that accepts them.
        let run_submissions = RunSubmissionLog::open(config.run_submissions_path())
            .map_err(|error| DaemonError::RunSubmissionFailed(error.category()))?;

        // The listing read model opens beside custody and under the same
        // fence. It is opened even though nothing has to read it: an index
        // that only appears once someone lists would be an index whose first
        // write races its first read, and a submission accepted while it was
        // absent would never be listed at all.
        let run_index = RunIndex::open(config.run_index_path())
            .map_err(|error| DaemonError::RunIndexFailed(error.category()))?;

        let platform = PlatformStore::open(config.platform_store_path())
            .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?;
        let managed_sessions =
            managed_sessions::ManagedSessionStore::open(config.managed_sessions_path())
                .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?;

        // The audit chain opens under the same fence and before the socket
        // guard is disarmed, for the reason every durable sibling does: a
        // daemon that cannot record what it was asked to do must not publish
        // an endpoint that accepts requests. Opening it lazily on the first
        // record would put the one failure mode that matters — a chain that
        // cannot be written — at the exact moment there is already something
        // to write, which is the worst time to discover it.
        let audit_chain = AuditChain::open(config.audit_chain_path())
            .map_err(|error| DaemonError::AuditChainFailed(error.category()))?;

        // The automation registry opens under the same fence and before the
        // socket guard is disarmed, for the reason custody storage does: a
        // daemon that cannot durably record an operator's decision to pause an
        // automation must not publish an endpoint that accepts one. An
        // in-memory pause that a restart forgets is exactly the failure this
        // registry exists to remove, and serving the lane from a registry that
        // failed to open would reintroduce it silently.
        let automations = AutomationStore::open(config.automation_registry_path())
            .map_err(|error| DaemonError::AutomationStoreFailed(error.category()))?;

        // The approval ledger opens beside the registry, under the same fence
        // and before the socket guard is disarmed, for the same reason: a
        // daemon that cannot durably record that somebody approved something
        // must not publish an endpoint that accepts the recording. An approval
        // held in memory and forgotten by a restart is exactly the failure this
        // ledger exists to remove — `command_registry` says plainly that its
        // operator-confirmation policy leaves no durable trace — and serving
        // the lane from a ledger that failed to open would reintroduce it
        // silently.
        let approvals = ApprovalLedger::open(config.approval_ledger_path())
            .map_err(|error| DaemonError::ApprovalLedgerFailed(error.category()))?;

        // The proposal table opens beside the ledger it links to, and the two
        // are reconciled once before this daemon answers anything: a decision
        // that reached the ledger while a previous generation was dying leaves
        // its proposal reading `pending`, and repairing it here is cheaper than
        // teaching every reader to notice.
        let mut approval_requests = ApprovalRequests::open(config.approval_requests_path())
            .map_err(|error| DaemonError::ApprovalRequestsFailed(error.category()))?;
        reconcile_approval_requests(&mut approval_requests, &approvals)?;

        // The batch registry opens beside the ledger, under the same fence and
        // before the socket guard is disarmed, for the same reason: a daemon
        // that cannot durably record which submissions a batch declared must not
        // publish an endpoint that accepts the declaration. A membership held in
        // memory and forgotten by a restart is exactly the failure the registry
        // exists to remove — `batch_runner` says plainly that a plan in memory
        // makes "resume by stable record identity" impossible — and serving the
        // lane from a registry that failed to open would reintroduce it
        // silently.
        let batches = BatchRegistry::open(config.batch_registry_path())
            .map_err(|error| DaemonError::BatchRegistryFailed(error.category()))?;

        // The host's one cancellation dispatcher and its durable custody open
        // beneath the same fence and before the socket guard is disarmed, for
        // the same reason custody storage does: a daemon that cannot remember
        // which cancellations it delivered must not publish an endpoint at all.
        // This is also the moment the dispatcher's single-instance requirement
        // is satisfied — one bound endpoint and one generation lease per state
        // directory means one dispatcher per ledger file, with no new lock.
        let attempt_host = Arc::new(
            DaemonAttemptHost::open(config.run_cancel_ledger_path())
                .map_err(|error| DaemonError::AttemptHostFailed(error.category()))?,
        );
        let attempt_adoption_path =
            attempt_adoption::socket_path(&runtime_dir, instance_id.as_str())
                .map_err(|error| DaemonError::AttemptAdoptionFailed(error.category()))?;
        let attempt_adoption = attempt_adoption::AttemptAdoptionEndpoint::bind(
            attempt_adoption_path,
            instance_id.as_str(),
            lease.epoch,
            Arc::clone(&attempt_host),
        )
        .map_err(|error| DaemonError::AttemptAdoptionFailed(error.category()))?;

        // The execution lane opens last, beneath the same fence, and probes
        // nothing: it reads one environment variable and remembers the
        // measurement above. Discovering and preparing a cgroup domain is
        // deferred to the first request, because preparing one moves this
        // process into a supervisor leaf, and a daemon nobody asks to execute
        // anything must not have its own placement changed.
        let execution = execute::ExecutionLane::open(
            Arc::clone(&attempt_host),
            state_dir.clone(),
            config.run_index_path(),
            matches!(
                execution_state,
                automonique_protocol::admin::ExecutionState::SandboxEnforceableLaneWired
            ),
        );

        let database_path = config.database_path();
        let platform_store_path = config.platform_store_path();
        let managed_sessions_path = config.managed_sessions_path();
        let admin_socket = config.admin_socket();
        let run_index_path = config.run_index_path();
        let managed_tui = managed_tui::ManagedTuiHost::open(&managed_tui::ManagedTuiParams {
            database_path: &database_path,
            platform_store_path: &platform_store_path,
            managed_sessions_path: &managed_sessions_path,
            state_dir: &state_dir,
            admin_socket: &admin_socket,
            run_index_path: &run_index_path,
            generation_id: GENERATION_ID,
            holder_id: instance_id.as_str(),
            lease_epoch: lease.epoch,
            lease_time_source: Arc::new(lease_time::BootTimeSource),
        })
        .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?;

        // THE STREAM REACHES THE CHAT HERE, AND ONLY HERE. The Telegram host is
        // composed above, before the lane that owns the progress hub exists, so
        // the hub is handed over once the lane does — still inside `open`, and
        // long before `serve` starts the poller thread, so no iteration can
        // observe a half-attached lane. A host with no bridge ignores it.
        telegram.attach_progress(execution.progress());
        slack_tickets.attach_progress(execution.progress());

        // THE SUPPORT INTAKE GATE. An absent `support/fleet.conf` is the
        // disabled state: no credential is read, no fleet client is
        // constructed, no ticket store file is created and no thread can start,
        // so this daemon cannot reach the support API at all. A present file
        // composes the worker here and dials nothing —
        // `TicketIntakeHost::start` is what puts it on a thread, and only
        // `serve` calls that — while a present-but-refused one fails startup for
        // the reason the Telegram gate does.
        let ticket_intake = if disconnected_recovery {
            ticket_intake::TicketIntakeHost::Disabled
        } else {
            ticket_intake::TicketIntakeHost::open(&ticket_intake::TicketIntakeParams {
                state_dir: &state_dir,
                ticket_store_path: &config.support_tickets_path(),
            })
            .map_err(|error| DaemonError::TicketIntakeRefused(error.category()))?
        };
        // The standing approval requirement is the one configured input to the
        // gate every launch takes. It is read here, beside the other startup
        // gates, so a malformed file refuses a daemon rather than the first
        // launch that reaches the gate.
        let (configured_approval_requirement, approval_lifetime) =
            approval_policy::ApprovalPolicyConfig::values_or_default(&state_dir)
                .map_err(|error| DaemonError::ApprovalPolicyRefused(error.category()))?;
        // THE PROGRESS ENDPOINT BINDS LAST, AND STARTS NO THREAD.
        //
        // Last because it serves the execution lane's hub, which has to exist
        // first; and beneath the same fence as everything above, so a host that
        // cannot bind it refuses startup rather than publishing an admin socket
        // beside a progress socket that silently is not there. It is bound
        // before the admin socket guard is disarmed for that reason.
        //
        // A failure to bind is fatal, and deliberately: the two sockets are one
        // endpoint from a client's point of view, and a daemon that answered
        // status but could not be watched would be a daemon whose capability
        // integer is a lie.
        let progress_endpoint = transferred_progress_listener
            .map_or_else(
                || {
                    progress_hub::ProgressEndpoint::bind(
                        config.progress_socket(),
                        execution.progress(),
                    )
                },
                |listener| {
                    progress_hub::ProgressEndpoint::adopt(
                        config.progress_socket(),
                        listener,
                        execution.progress(),
                    )
                },
            )
            .map_err(|error| DaemonError::ProgressEndpointFailed(error.category()))?;
        socket_cleanup.disarm();

        Ok(Self {
            listener,
            socket_path,
            store,
            instance_id,
            lease_epoch: lease.epoch,
            lease_expires_ms: lease.expires_ms,
            lease_time,
            socket_identity,
            remove_socket_on_drop,
            controller: automonique_core::Controller::new(),
            reconciliation_run_id: None,
            telegram,
            slack_tickets,
            run_submissions,
            run_index,
            platform,
            managed_sessions,
            platform_models_observed_ms: None,
            audit_chain,
            automations,
            approvals,
            approval_requests,
            state_dir,
            batches,
            attempt_host: Some(attempt_host),
            attempt_adoption: Some(attempt_adoption),
            generation_audit,
            reload_audit,
            tenure_revision: tenure.revision,
            execution_state,
            configured_approval_requirement,
            approval_lifetime,
            execution: Some(execution),
            ticket_intake,
            managed_tui,
            progress_endpoint: Some(progress_endpoint),
            disconnected_recovery,
            _control_lock: control_lock,
        })
    }

    /// Bound local endpoint.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// This daemon's single host-wide cancellation dispatcher.
    ///
    /// Lent by reference and never by value: a second owner over the same
    /// ledger file is exactly the composition
    /// [`attempt_host`](crate::attempt_host) exists to prevent. `None` only
    /// after [`Daemon::serve`] disposed of it, which no caller can observe
    /// because `serve` consumes the daemon.
    ///
    /// [`execute::ExecutionLane`] registers every attempt it starts against
    /// this host, so a daemon with a live attempt has a non-empty registry and
    /// a cancellation delivered here reaches that attempt's process tree. A
    /// daemon that has been asked to run nothing has an empty one.
    ///
    /// The Execute lane's `cancel_run` verb routes here through
    /// [`Daemon::cancel_run`], which is the only caller that delivers. This
    /// accessor is for composition proofs, not for a second delivery path:
    /// cancelling through it directly skips the fence and the run-to-attempt
    /// resolution that make the operator surfaces equal in authority.
    #[must_use]
    pub fn attempt_host(&self) -> Option<&DaemonAttemptHost> {
        self.attempt_host.as_deref()
    }

    /// Holder- and epoch-bound route to attempts this process still hosts.
    ///
    /// A candidate records this route during warm-up and must reject any reply
    /// whose identity differs. `None` is reachable only after ordered shutdown,
    /// which consumes the daemon and is not externally observable.
    #[must_use]
    pub fn attempt_adoption_route(&self) -> Option<attempt_adoption::AttemptHostRoute> {
        self.attempt_adoption
            .as_ref()
            .map(attempt_adoption::AttemptAdoptionEndpoint::route)
    }

    /// Start only the holder-bound attempt route needed by candidate warm-up.
    ///
    /// The ordinary serving path starts this endpoint with every other worker.
    /// Handoff coordinators may start it earlier so an exact candidate can
    /// prove the source inventory before any listener or lease transfer.
    pub fn start_candidate_warmup_route(&mut self) -> Result<(), DaemonError> {
        self.attempt_adoption
            .as_mut()
            .ok_or(DaemonError::AttemptAdoptionFailed(
                "attempt_adoption_unavailable",
            ))?
            .start()
            .map_err(|error| DaemonError::AttemptAdoptionFailed(error.category()))
    }

    /// Duplicate the exact listener and locked open-file description for a
    /// warmed child. Possessing these descriptors grants no durable lease;
    /// candidate activation must still validate and transfer that authority.
    pub fn candidate_transfer_descriptors(
        &self,
    ) -> Result<candidate::CandidateTransferDescriptors, DaemonError> {
        let listener = self.listener.try_clone()?;
        let progress_listener = self
            .progress_endpoint
            .as_ref()
            .ok_or(DaemonError::ProgressEndpointFailed(
                "progress_endpoint_unavailable",
            ))?
            .duplicate_listener()
            .map_err(|error| DaemonError::ProgressEndpointFailed(error.category()))?;
        let control_lock = self
            ._control_lock
            .duplicate()
            .map_err(|error| match error {
                control_lock::ControlLockError::Io(error) => DaemonError::Io(error),
                control_lock::ControlLockError::Held => DaemonError::AlreadyRunning,
                control_lock::ControlLockError::InsecurePath => {
                    DaemonError::ControlLockFailed("insecure_path")
                }
            })?;
        Ok(candidate::CandidateTransferDescriptors::new(
            listener,
            progress_listener,
            control_lock,
        ))
    }

    /// This daemon's live progress replay, when it has an execution lane.
    ///
    /// The seam a renderer holds. Shared rather than lent: a chat bridge polls
    /// it from its own thread while an attempt's supervisor publishes into it
    /// from another, and the alternative — handing out a reference bound to the
    /// daemon's own lifetime — would make the two lifetimes one.
    ///
    /// `None` on a daemon with no lane, which is a host that can run nothing
    /// and therefore has nothing to show. Reading from it is never a substitute
    /// for the durable record: see [`crate::progress_hub`] for the two tiers
    /// and which of them a decision may rest on.
    #[must_use]
    pub fn progress(&self) -> Option<Arc<progress_hub::ProgressHub>> {
        self.execution
            .as_ref()
            .map(execute::ExecutionLane::progress)
    }

    /// Serve until the supplied stop flag is set or an authenticated shutdown
    /// request is accepted.
    ///
    /// # Errors
    ///
    /// Returns an I/O or durable-state failure. Individual hostile clients are
    /// closed and do not stop the daemon.
    pub fn serve(self, stop: &AtomicBool) -> Result<(), DaemonError> {
        let service_manager = systemd::Notifier::from_environment()
            .map_err(|error| DaemonError::ServiceManagerFailed(error.category()))?;
        let reload = AtomicBool::new(false);
        let (_, result) = self.serve_with_control(
            stop,
            &reload,
            service_manager,
            LeaseDisposition::Release,
            None,
        );
        result
    }

    fn serve_retaining_authority(
        self,
        stop: &AtomicBool,
        ready: std::sync::mpsc::SyncSender<()>,
    ) -> (Self, Result<(), DaemonError>) {
        let reload = AtomicBool::new(false);
        self.serve_with_control(stop, &reload, None, LeaseDisposition::Retain, Some(ready))
    }

    fn serve_with_control(
        mut self,
        stop: &AtomicBool,
        reload: &AtomicBool,
        mut service_manager: Option<systemd::Notifier>,
        lease_disposition: LeaseDisposition,
        mut ready: Option<std::sync::mpsc::SyncSender<()>>,
    ) -> (Self, Result<(), DaemonError>) {
        let initial_lease = self
            .lease_time
            .require_authority()
            .map_err(map_lease_authority_error);
        let mut self_end_kind = if initial_lease.is_ok() {
            SelfEndKind::Released
        } else {
            SelfEndKind::Expired
        };
        let mut next_renewal_boottime_ms = initial_lease
            .as_ref()
            .map_or(0, |now_boottime_ms| *now_boottime_ms)
            .saturating_add(LEASE_RENEW_INTERVAL_MS);
        // The first sweep runs immediately: a daemon that just took over a
        // generation is exactly the one most likely to be holding proposals
        // that expired while nobody was serving.
        let mut next_approval_sweep = std::time::Instant::now();
        // LIVE TELEGRAM POLLING BEGINS HERE, AND NOWHERE ELSE.
        //
        // Opening a daemon composes the bridge; serving it is what puts the
        // bridge on a thread. That split is why a process that opened a daemon
        // and never served — a refused startup, or a caller that only wanted the
        // socket path — has issued no request to anybody. A host with no
        // configured allowlist has nothing to start and this is a no-op.
        //
        // A failure here still falls through to the shutdown block below rather
        // than returning: this process already holds the generation and has an
        // open tenure row, and both have to be closed under it.
        //
        // LIVE SUPPORT POLLING BEGINS IN THE SAME PLACE, AND UNDER THE SAME
        // RULE. A daemon with no `support/fleet.conf` has nothing to start and
        // this is a no-op; one with a configuration puts its worker on a thread
        // here and nowhere else, so a process that opened a daemon and never
        // served has issued no request to the fleet either.
        let started = initial_lease
            .and_then(|_| {
                self.slack_tickets
                    .start()
                    .map_err(|error| DaemonError::SlackRefused(error.category()))
            })
            .and_then(|()| {
                self.telegram
                    .start()
                    .map_err(|error| DaemonError::TelegramRefused(error.category()))
            })
            .and_then(|()| {
                self.ticket_intake
                    .start()
                    .map_err(|error| DaemonError::TicketIntakeRefused(error.category()))
            })
            .and_then(|()| {
                self.managed_tui
                    .start()
                    .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))
            })
            // LIVE PROGRESS FAN-OUT BEGINS HERE, AND NOWHERE ELSE. The endpoint
            // was bound in `open`; this is what puts its accept loop on a
            // thread, so a process that opened a daemon and never served has
            // accepted no subscriber.
            .and_then(|()| {
                self.progress_endpoint.as_mut().map_or(Ok(()), |endpoint| {
                    endpoint
                        .start()
                        .map_err(|error| DaemonError::ProgressEndpointFailed(error.category()))
                })
            })
            .and_then(|()| {
                self.attempt_adoption.as_mut().map_or(Ok(()), |endpoint| {
                    endpoint
                        .start()
                        .map_err(|error| DaemonError::AttemptAdoptionFailed(error.category()))
                })
            });
        let result = match started {
            Err(error) => Err(error),
            Ok(()) => 'serving: {
                let _ = structured_log::emit_readiness(GENERATION_ID, self.lease_epoch);
                if let Some(notifier) = service_manager.as_mut()
                    && let Err(error) = notifier.ready()
                {
                    break 'serving Err(DaemonError::ServiceManagerFailed(error.category()));
                }
                if let Some(sender) = ready.take() {
                    let _ = sender.send(());
                }
                loop {
                    let lease_now_ms = match self.lease_time.require_authority() {
                        Ok(now_ms) => now_ms,
                        Err(lease_time::LeaseAuthorityError::Suspended) => {
                            self_end_kind = SelfEndKind::Expired;
                            break 'serving Err(DaemonError::LeaseSuspended);
                        }
                        Err(lease_time::LeaseAuthorityError::Clock(category)) => {
                            self_end_kind = SelfEndKind::Expired;
                            break 'serving Err(DaemonError::LeaseClockFailed(category));
                        }
                    };
                    if let Some(notifier) = service_manager.as_mut()
                        && let Err(error) = notifier.watchdog_if_due()
                    {
                        break 'serving Err(DaemonError::ServiceManagerFailed(error.category()));
                    }
                    if stop.load(Ordering::Acquire) {
                        break 'serving Ok(());
                    }
                    if reload.swap(false, Ordering::AcqRel) {
                        if let Some(notifier) = service_manager.as_ref()
                            && let Err(error) = notifier.reloading()
                        {
                            break 'serving Err(DaemonError::ServiceManagerFailed(
                                error.category(),
                            ));
                        }
                        match self.reload_configuration() {
                            Ok(()) => {
                                if let Some(notifier) = service_manager.as_ref()
                                    && let Err(error) = notifier.ready()
                                {
                                    break 'serving Err(DaemonError::ServiceManagerFailed(
                                        error.category(),
                                    ));
                                }
                            }
                            Err(DaemonError::ApprovalPolicyRefused(category)) => {
                                if let Some(notifier) = service_manager.as_ref()
                                    && let Err(error) = notifier.reload_refused(category)
                                {
                                    break 'serving Err(DaemonError::ServiceManagerFailed(
                                        error.category(),
                                    ));
                                }
                            }
                            Err(error) => break 'serving Err(error),
                        }
                    }
                    if lease_now_ms >= next_renewal_boottime_ms {
                        if let Err(error) = self.renew_lease() {
                            break 'serving Err(error);
                        }
                        // The bot lease renews on the same cadence and beneath the
                        // just-renewed generation authority; losing it is fencing
                        // evidence, not a condition to poll through. A live host
                        // republishes the renewed lease to its poller here, which is
                        // what keeps the next long poll inside its own expiry.
                        if let Err(error) = self.telegram.renew() {
                            break 'serving Err(DaemonError::TelegramRefused(error.category()));
                        }
                        next_renewal_boottime_ms =
                            lease_now_ms.saturating_add(LEASE_RENEW_INTERVAL_MS);
                    }
                    if !self.disconnected_recovery
                        && self.reconciliation_run_id.is_none()
                        && let Err(error) = self.tick_synthetic(lease_now_ms)
                    {
                        break 'serving Err(error);
                    }
                    // The approval sweep runs on its own cadence rather than on
                    // every accept poll: it reads two databases, and a deadline
                    // measured in minutes does not need to be checked at the rate a
                    // socket is polled.
                    if !self.disconnected_recovery
                        && std::time::Instant::now() >= next_approval_sweep
                    {
                        match unix_millis().and_then(|now_ms| self.tick_approvals(now_ms)) {
                            Ok(()) => {}
                            Err(error) => break 'serving Err(error),
                        }
                        next_approval_sweep = std::time::Instant::now() + APPROVAL_SWEEP_INTERVAL;
                    }
                    match self.listener.accept() {
                        Ok((mut stream, _)) => {
                            // The timed renewal and each store mutation validate the
                            // durable epoch. Read-only status additionally compares
                            // a consistent lease snapshot, so client polling must not
                            // turn into an fsync/lease-write storm.
                            match self.handle_stream(&mut stream, stop) {
                                Ok(()) => {}
                                Err(DaemonError::Store(store_error)) => {
                                    if fatal_store_error(&store_error) {
                                        break Err(DaemonError::Store(store_error));
                                    }
                                }
                                Err(_) => {
                                    // A hostile or incomplete peer is isolated to
                                    // this connection. Refusal details never contain
                                    // bytes.
                                }
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(ACCEPT_POLL);
                        }
                        Err(error) => break 'serving Err(DaemonError::Io(error)),
                    }
                }
            }
        };
        let service_stopping = service_manager.as_ref().map_or(Ok(()), |notifier| {
            notifier
                .stopping()
                .map_err(|error| DaemonError::ServiceManagerFailed(error.category()))
        });
        // LIVE ATTEMPTS END FIRST, AND THEY END BY FINISHING.
        //
        // Every worker holds a registration on the attempt host and writes to
        // the read model this generation owns, so both have to outlive it.
        // Joining also means this daemon never returns while a contained
        // process tree is still running under a supervisor that has stopped
        // answering for it. The lane is moved out and consumed rather than
        // borrowed, because ending it also releases its own reference to the
        // attempt host, which is what makes the unwrap below possible.
        // SUBSCRIBERS ARE DISCONNECTED FIRST, AND DISCONNECTING THEM CANCELS
        // NOTHING.
        //
        // Before the execution lane, because a writer thread holds a subscriber
        // slot on the lane's hub and this daemon must not join the lane while a
        // thread is still reaching into something it owns. Every attempt that
        // was running is still running when this returns: a transport
        // disconnect is not a cancellation, here or anywhere else — see
        // [`progress_hub`] — and cancellation remains the explicit dispatcher
        // path through [`Daemon::cancel_run`].
        let mut shutdown_workers = Vec::new();
        if let Some(attempt_adoption) = self.attempt_adoption.take() {
            shutdown_workers.extend(named_shutdown_workers(
                "attempt_adoption",
                attempt_adoption.begin_shutdown(),
            ));
        }
        shutdown_workers.extend(named_shutdown_workers(
            "managed_tui",
            self.managed_tui.begin_shutdown(),
        ));
        if let Some(progress_endpoint) = self.progress_endpoint.take() {
            shutdown_workers.extend(named_shutdown_workers(
                "progress_endpoint",
                progress_endpoint.begin_shutdown(),
            ));
        }
        if let Some(execution) = self.execution.take() {
            shutdown_workers.extend(named_shutdown_workers(
                "execution",
                execution.begin_shutdown(),
            ));
        }
        shutdown_workers.extend(named_shutdown_workers(
            "slack_tickets",
            self.slack_tickets.begin_shutdown(),
        ));
        // Support intake ends beside them, and for the same reason: its worker
        // writes to a durable sibling database this generation owns, so it must
        // stop and be joined while the generation is still held. It has no
        // durable lease of its own to release — it owns no cursor, so there is
        // nothing a second poller could double-advance — which is why this is a
        // join and not a lifecycle. See [`ticket_intake`].
        shutdown_workers.extend(named_shutdown_workers(
            "ticket_intake",
            self.ticket_intake.begin_shutdown(),
        ));
        shutdown_workers.extend(named_shutdown_workers(
            "telegram",
            self.telegram.begin_shutdown(),
        ));
        // Every worker above may be blocked in a bounded transport operation,
        // and live attempts deliberately drain to their own document deadline.
        // Starting every drain before joining makes the independent deadlines
        // overlap. More importantly, the serve thread remains the generation
        // and bot-lease coordinator while it waits: neither lease may expire
        // underneath a worker that still writes durable state.
        let shutdown_renewal = drain_shutdown_workers(
            shutdown_workers,
            Duration::from_millis(
                u64::try_from(LEASE_RENEW_INTERVAL_MS)
                    .expect("renewal interval is a positive constant"),
            ),
            SHUTDOWN_WORKER_DIAGNOSTIC_BUDGET,
            || {
                if self_end_kind == SelfEndKind::Expired {
                    return Ok(());
                }
                self.renew_lease().and_then(|()| {
                    self.telegram
                        .renew()
                        .map_err(|error| DaemonError::TelegramRefused(error.category()))
                })
            },
            |observation| {
                let _ = structured_log::emit_shutdown_worker_drain(
                    observation.worker_group,
                    observation.worker_ordinal,
                    observation.phase.as_str(),
                    observation.elapsed_ms,
                    observation.budget_ms,
                );
            },
        );
        // Cancellation dispatch ends next, beneath the still-held generation
        // fence. A reload successor may route cancellation back to this source
        // while its old attempts drain, but the adoption endpoint has now
        // stopped and all source workers have joined. This process can therefore
        // stop owning its dispatcher without stranding a live source sink.
        // Disposal reports exactly one state — a host a panicking sink poisoned,
        // whose last delivery is unknown — and reporting it is why shutdown does
        // not simply drop the field.
        //
        // Unwrapping the `Arc` is the proof that the join above did its job: a
        // surviving clone means a worker is still live, which is a state this
        // daemon cannot dispose from and will not pretend it did.
        let attempt_host_disposal = self.attempt_host.take().map_or(Ok(()), |host| {
            Arc::try_unwrap(host).map_or(
                Err(DaemonError::AttemptHostFailed("attempt_host_still_shared")),
                |host| {
                    host.dispose()
                        .map_err(|error| DaemonError::AttemptHostFailed(error.category()))
                },
            )
        });
        // The bot lease releases before the generation lease so its release
        // still runs under a live generation authority; both results defer to
        // any primary serve failure. A live host stops and joins its poller
        // first, for the reason the execution lane is joined above: that thread
        // commits to durable state this generation owns, and it holds the very
        // lease being released.
        let telegram_release = self
            .telegram
            .release()
            .map_err(|error| DaemonError::TelegramRefused(error.category()));
        // The tenure closes last before the lease, and beneath it. Closing
        // beneath the still-held generation is what makes `released` a true
        // statement — a row closed after the lease was gone would be this
        // process writing history for a generation somebody else may already
        // own — and closing immediately before the release narrows that
        // module's crash window 4, where the log says a tenure ended while the
        // main database still fences writes to it, to the gap between these
        // two statements.
        //
        // A clean stop writes `released`. Suspend detection writes `expired`:
        // the process is still alive to report why it self-fenced, but it no
        // longer claims continuous lease authority. A process that dies before
        // this point writes nothing; its successor closes the open row as
        // `superseded` when it observes the abandoned tenure.
        let tenure_close = if lease_disposition == LeaseDisposition::Release {
            unix_millis().and_then(|now_ms| {
                self.generation_audit
                    .end_tenure(TenureEnding {
                        generation_id: GENERATION_ID,
                        holder_id: self.instance_id.as_str(),
                        lease_epoch: self.lease_epoch,
                        expected_revision: self.tenure_revision,
                        ended_at_ms: now_ms,
                        end_kind: self_end_kind,
                    })
                    .map(|_| ())
                    .map_err(generation_audit_failed)
            })
        } else {
            Ok(())
        };
        let release = if lease_disposition == LeaseDisposition::Release {
            unix_millis().and_then(|now_ms| {
                self.store
                    .release_generation_lease(
                        GENERATION_ID,
                        self.instance_id.as_str(),
                        self.lease_epoch,
                        now_ms,
                    )
                    .map_err(DaemonError::Store)
            })
        } else {
            Ok(())
        };
        let outcome = match result {
            Err(primary) => {
                let _ = attempt_host_disposal;
                let _ = telegram_release;
                let _ = tenure_close;
                let _ = release;
                Err(primary)
            }
            Ok(()) => attempt_host_disposal
                .and(shutdown_renewal)
                .and(telegram_release)
                .and(tenure_close)
                .and(release)
                .and(service_stopping),
        };
        (self, outcome)
    }

    /// Replace the reloadable policy as one coherent value.
    ///
    /// All parsing finishes before either live field changes, so a refused
    /// replacement leaves the running generation's policy intact.
    fn reload_configuration(&mut self) -> Result<(), DaemonError> {
        let (requirement, lifetime) =
            approval_policy::ApprovalPolicyConfig::values_or_default(&self.state_dir)
                .map_err(|error| DaemonError::ApprovalPolicyRefused(error.category()))?;
        self.configured_approval_requirement = requirement;
        self.approval_lifetime = lifetime;
        Ok(())
    }

    /// Which operator decision surfaces are live on this host right now.
    ///
    /// Evidence, not configuration, and that distinction is the whole point: a
    /// configured Telegram bot whose poller is not running cannot carry a
    /// decision back, and a Slack workspace without interactive decisions
    /// renders buttons nobody can act on. Each surface is asked whether it is
    /// *running*.
    ///
    /// # Why the connected peer is not one of them
    ///
    /// `automonique_policy::approval::OperatorSurfaces` can carry an admitted
    /// administrative peer, and this daemon deliberately never gives it one.
    /// Every request that reaches this gate arrives over the admin socket, so a
    /// peer is always admitted while it runs — including the peer that asked
    /// for the launch. Counting it would mean the requirement was satisfied by
    /// the requester's own connection, which is exactly what an approval gate
    /// exists to prevent, and it would make "no operator surface is reachable"
    /// unreachable rather than rare.
    ///
    /// An operator at a terminal is of course able to decide: they run the
    /// approval verb, which is a *second* request from a person who read the
    /// refusal. This daemon cannot know whether anyone will make it, so it must
    /// not hold a proposal open on the hope that somebody does.
    fn operator_surfaces(&self) -> OperatorSurfaces {
        let mut surfaces = OperatorSurfaces::none();
        if self.telegram.poller_live() {
            surfaces = surfaces.with_telegram_poller();
        }
        if self.slack_tickets.approvals_live() {
            surfaces = surfaces.with_slack_approvals();
        }
        surfaces
    }

    /// The three requirement sources for one call, before composition.
    ///
    /// The host source is the startup measurement rather than a second probe:
    /// delegation is a property of this process's own cgroup placement, which
    /// does not change while it lives, and re-probing per request would let two
    /// launches in one daemon disagree about the same kernel.
    fn approval_sources(&self, per_call: ApprovalRequirement) -> ApprovalSources {
        ApprovalSources::new(
            self.configured_approval_requirement,
            ApprovalRequirement::for_measured_host(matches!(
                self.execution_state,
                automonique_protocol::admin::ExecutionState::SandboxEnforceableLaneWired
            )),
            per_call,
        )
    }

    /// Measure whether this host could enforce the composed sandbox.
    ///
    /// The measurement is the capability module's read-only probe asking for
    /// exactly the properties the composed launch path enforces: containment,
    /// filesystem restriction, TCP denial, and syscall restriction. It runs
    /// once at startup: delegation is a property of the daemon's own cgroup
    /// placement, which does not change while the process lives.
    ///
    /// The answer is about the host, not about work: it says what the kernel
    /// would enforce for a launch, never that a particular run was admitted.
    /// A refusal is the expected truthful state on an undelegated host, and on
    /// such a host [`execute::ExecutionLane`] is still opened and still
    /// refuses every start, so the measurement and the lane agree.
    fn measure_execution_state() -> automonique_protocol::admin::ExecutionState {
        use automonique_protocol::admin::ExecutionState;
        use automonique_runner::capability::HostCapabilities;

        // The property set is [`execute::ENFORCED_PROPERTIES`] rather than a
        // list written here, so the measurement this status reports and the
        // host features the execution lane offers cannot disagree about which
        // properties this build enforces.
        let selection = HostCapabilities::probe().select_mode(&execute::ENFORCED_PROPERTIES);
        match selection {
            Ok(_) => ExecutionState::SandboxEnforceableLaneWired,
            Err(_) => ExecutionState::SandboxUnavailableLaneWired,
        }
    }

    fn provider_available(&self) -> bool {
        matches!(
            self.execution_state,
            automonique_protocol::admin::ExecutionState::SandboxEnforceableLaneWired
        ) && compose::ProviderConfig::load(&self.state_dir.join(compose::PROVIDER_CONFIG_NAME))
            .ok()
            .flatten()
            .is_some()
    }

    fn gen_ai_usage(&self) -> Option<GenAiUsageObservation> {
        let path = self.state_dir.join(PROVIDER_JOURNAL_NAME);
        if !path.exists() {
            return None;
        }
        let journal = ProviderJournal::open(path).ok()?;
        let totals = journal.usage_totals().ok()?;
        Some(GenAiUsageObservation {
            requests: totals.requests,
            input_tokens: totals.input_tokens,
            output_tokens: totals.output_tokens,
        })
    }

    fn renew_lease(&mut self) -> Result<(), DaemonError> {
        let now_ms = unix_millis()?;
        let lease = self.store.renew_generation_lease(LeaseRenewal {
            generation_id: GENERATION_ID,
            holder_id: self.instance_id.as_str(),
            epoch: self.lease_epoch,
            now_ms,
            ttl_ms: LEASE_TTL_MS,
        })?;
        self.lease_expires_ms = lease.expires_ms;
        Ok(())
    }

    fn tick_synthetic(&mut self, lease_now_ms: i64) -> Result<(), DaemonError> {
        use automonique_core::{SchedulerFence, TickOutcome};

        let now_ms = unix_millis()?;
        let fence = SchedulerFence::new(GENERATION_ID, self.instance_id.as_str(), self.lease_epoch)
            .map_err(|_| DaemonError::ProtocolRefused("scheduler_fence"))?;
        let mut durable = synthetic::StoreScheduler::new(
            &mut self.store,
            now_ms,
            lease_now_ms,
            LEASE_TTL_MS,
            &mut self.lease_expires_ms,
        );
        match self
            .controller
            .tick(&mut durable, &fence)
            .map_err(|_| DaemonError::ProtocolRefused("scheduler_invariant"))?
        {
            TickOutcome::FenceRejected { .. } => Err(DaemonError::Store(StoreError::StaleEpoch)),
            TickOutcome::Idle
            | TickOutcome::Completed(_)
            | TickOutcome::Replayed(_)
            | TickOutcome::RetryRequired { .. } => Ok(()),
            TickOutcome::ReconciliationRequired(reconciliation) => {
                let run_id = reconciliation
                    .work_id()
                    .parse::<i64>()
                    .map_err(|_| DaemonError::ProtocolRefused("reconciliation_run_id"))?;
                self.reconciliation_run_id = Some(run_id);
                Ok(())
            }
        }
    }

    /// Authenticate the peer, read one bounded frame, and hand it to the lane
    /// its envelope names.
    ///
    /// The socket serves seven protocols. Which one a frame belongs to is read
    /// off its declared protocol name by
    /// [`LocalRequest::from_canonical_bytes`], never guessed and never tried in
    /// sequence, so an administration client, a Runs client, an Automation
    /// client, an Approval client, a Batch client and an Execute client receive
    /// their own lane's refusals rather than each other's.
    fn handle_stream(
        &mut self,
        stream: &mut UnixStream,
        stop: &AtomicBool,
    ) -> Result<(), DaemonError> {
        authenticate_peer(stream)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let payload = read_payload(stream)?;
        match LocalRequest::from_canonical_bytes(&payload)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?
        {
            LocalRequest::Admin(request) => self.handle_admin(stream, &request, stop),
            LocalRequest::Runs(request) => self.handle_runs(stream, &request),
            LocalRequest::Automation(request) => self.handle_automation(stream, &request),
            LocalRequest::Approval(request) => self.handle_approval(stream, &request),
            LocalRequest::Batch(request) => self.handle_batch(stream, &request),
            LocalRequest::Execute(request) => self.handle_execute(stream, &request),
            LocalRequest::Platform(request) => self.handle_platform(stream, &request),
        }
    }

    /// Count what this daemon durably holds, without letting a store that will
    /// not answer take the status down with it.
    ///
    /// Every count is a real read of the store that owns it. None of them is
    /// derived from another, cached, or defaulted: a store that refuses reports
    /// [`OperationalMetric::Unavailable`], and the status is still answered.
    /// That trade is the point of the metric type — an operator asking what a
    /// daemon is holding is better served by five counts and one honest gap
    /// than by a connection error — and it is safe here precisely because
    /// nothing in this build *decides* anything from these numbers.
    ///
    /// The generation audit is read once for a question the other three do not
    /// have: which tenure is open, and at which epoch. A row read without a
    /// usable epoch is reported as no reading at all rather than as a tenure
    /// whose identity is missing.
    fn durable_state_counts(&self) -> Result<DurableStateCounts, DaemonError> {
        let (open_tenures, open_tenure_epoch) = match self
            .generation_audit
            .latest_open(GENERATION_ID)
            .map(|tenure| tenure.map(|tenure| tenure.lease_epoch))
        {
            Ok(Some(epoch)) => match OperationalMetric::measured(epoch) {
                Ok(measured @ OperationalMetric::Measured(1..)) => {
                    (OperationalMetric::Measured(1), measured)
                }
                // An epoch of zero or one the wire cannot carry is not an epoch
                // this daemon can report, and a tenure without one is not
                // evidence of anything.
                _ => (
                    OperationalMetric::Unavailable,
                    OperationalMetric::Unavailable,
                ),
            },
            // No open row is a reading, and zero is what it counted.
            Ok(None) => (
                OperationalMetric::Measured(0),
                OperationalMetric::Unavailable,
            ),
            Err(_) => (
                OperationalMetric::Unavailable,
                OperationalMetric::Unavailable,
            ),
        };
        DurableStateCounts::new(DurableStateCountsParts {
            approvals_recorded: durable_count(self.approvals.decision_count()),
            automations_registered: durable_count(self.automations.automation_count()),
            open_tenure_epoch,
            open_tenures,
            runs_registered: durable_count(self.run_index.entry_count()),
            tenures_recorded: durable_count(self.generation_audit.tenure_count()),
        })
        .map_err(|error| DaemonError::ProtocolRefused(error.category()))
    }

    fn handle_admin(
        &mut self,
        stream: &mut UnixStream,
        request: &AdminRequest,
        stop: &AtomicBool,
    ) -> Result<(), DaemonError> {
        let response = match request.command() {
            automonique_protocol::admin::AdminCommand::Status => {
                let now_ms = unix_millis()?;
                let snapshot = self.store.status_snapshot_at(GENERATION_ID, now_ms)?;
                let generation = snapshot.generation().ok_or(StoreError::StaleEpoch)?;
                if generation.holder_id() != self.instance_id.as_str()
                    || generation.lease_epoch() != self.lease_epoch
                    || generation.lease_expires_ms() != self.lease_expires_ms
                    || generation.lease_expires_ms() <= snapshot.lease_observed_boottime_ms()
                {
                    return Err(DaemonError::Store(StoreError::StaleEpoch));
                }
                let degraded = self.reconciliation_run_id.is_some()
                    || snapshot_requires_reconciliation(&snapshot);
                // Read at the snapshot's own instant. A pause and a degraded
                // generation are different reasons for the same closed intake,
                // and the status reports both so an operator can tell which
                // one they are looking at.
                let paused = self.disconnected_recovery
                    || self.store.intake_paused(GENERATION_ID, now_ms)?.is_some();
                // The live fan-out is in this process's memory rather than in
                // the database, so it is measured here and attached rather than
                // projected from the snapshot. A daemon with no execution lane
                // attaches nothing, and the four samples stay `unavailable` —
                // which is the truthful answer for a host that cannot run
                // anything, and is why they are not defaulted to zero.
                let projection = StoreProjection::from_status(&snapshot)
                    .map_err(|_| DaemonError::ProtocolRefused("operational_projection"))?;
                let projection = match self.progress() {
                    Some(hub) => projection
                        .with_progress(hub.observation())
                        .map_err(|_| DaemonError::ProtocolRefused("operational_projection"))?,
                    None => projection,
                };
                let projection = projection
                    .with_runtime(RuntimeObservation {
                        daemon_ready: !degraded,
                        intake_enabled: !degraded && !paused,
                        provider_available: Some(
                            !self.disconnected_recovery && self.provider_available(),
                        ),
                        sandbox_launch_refusals: None,
                    })
                    .map_err(|_| DaemonError::ProtocolRefused("operational_projection"))?;
                let operational = operational_status(&projection)?;
                // Counted here, beside the projection, and not in it: these are
                // reads of four other databases, and this daemon opens no
                // transaction spanning them.
                let durable_state = self.durable_state_counts()?;
                let (telegram_state, telegram_poller_epoch) = self.telegram.status();
                let status = DaemonStatus::new(
                    self.instance_id.clone(),
                    if degraded {
                        DaemonState::Failed
                    } else {
                        DaemonState::Ready
                    },
                    self.lease_epoch,
                    snapshot.event_cursor(),
                    snapshot.inbox_pending(),
                    snapshot.outbox_pending(),
                    snapshot.runs_running(),
                    !degraded && !paused,
                )
                .and_then(|status| status.with_intake_pause(paused))
                .and_then(|status| status.with_telegram(telegram_state, telegram_poller_epoch))
                .map(|status| status.with_execution(self.execution_state))
                .and_then(|status| status.with_operational(operational))
                .and_then(|status| status.with_durable_state(durable_state))
                .map_err(|error| DaemonError::ProtocolRefused(error.category()))?;
                AdminResponse::Status {
                    request_id: request.request_id().clone(),
                    status,
                }
            }
            automonique_protocol::admin::AdminCommand::Metrics => {
                let now_ms = unix_millis()?;
                let snapshot = self.store.status_snapshot_at(GENERATION_ID, now_ms)?;
                let generation = snapshot.generation().ok_or(StoreError::StaleEpoch)?;
                if generation.holder_id() != self.instance_id.as_str()
                    || generation.lease_epoch() != self.lease_epoch
                    || generation.lease_expires_ms() != self.lease_expires_ms
                    || generation.lease_expires_ms() <= snapshot.lease_observed_boottime_ms()
                {
                    return Err(DaemonError::Store(StoreError::StaleEpoch));
                }
                let degraded = self.reconciliation_run_id.is_some()
                    || snapshot_requires_reconciliation(&snapshot);
                let paused = self.disconnected_recovery
                    || self.store.intake_paused(GENERATION_ID, now_ms)?.is_some();
                let projection = StoreProjection::from_status(&snapshot)
                    .map_err(|_| DaemonError::ProtocolRefused("operational_projection"))?;
                let projection = match self.progress() {
                    Some(hub) => projection
                        .with_progress(hub.observation())
                        .map_err(|_| DaemonError::ProtocolRefused("operational_projection"))?,
                    None => projection,
                };
                let projection = projection
                    .with_runtime(RuntimeObservation {
                        daemon_ready: !degraded,
                        intake_enabled: !degraded && !paused,
                        provider_available: Some(
                            !self.disconnected_recovery && self.provider_available(),
                        ),
                        sandbox_launch_refusals: None,
                    })
                    .map_err(|_| DaemonError::ProtocolRefused("operational_projection"))?;
                let projection = match self.gen_ai_usage() {
                    Some(observation) => projection
                        .with_gen_ai_usage(observation)
                        .map_err(|_| DaemonError::ProtocolRefused("operational_projection"))?,
                    None => projection,
                };
                AdminResponse::Metrics {
                    request_id: request.request_id().clone(),
                    exposition: render_exposition(projection.metrics(), env!("CARGO_PKG_VERSION")),
                }
            }
            automonique_protocol::admin::AdminCommand::Generations => {
                let since_epoch = self
                    .lease_epoch
                    .saturating_sub(MAX_GENERATION_HISTORY_ENTRIES as u64);
                let history = self
                    .generation_audit
                    .history(GENERATION_ID, since_epoch, MAX_GENERATION_HISTORY_ENTRIES)
                    .map_err(generation_audit_failed)?;
                let tenures = history
                    .tenures
                    .into_iter()
                    .map(|tenure| {
                        Ok(GenerationTenureView {
                            holder_id: tenure.holder_id,
                            lease_epoch: tenure.lease_epoch,
                            started_at_ms: wire_millis(tenure.started_at_ms)?,
                            ended_at_ms: tenure.ended_at_ms.map(wire_millis).transpose()?,
                            end_kind: tenure.end_kind.map(|kind| kind.as_str().to_owned()),
                        })
                    })
                    .collect::<Result<Vec<_>, DaemonError>>()?;
                let handoffs = history
                    .handoffs
                    .into_iter()
                    .map(|handoff| {
                        Ok(GenerationHandoffView {
                            predecessor_epoch: handoff.predecessor_epoch,
                            successor_epoch: handoff.successor_epoch,
                            predecessor_end_kind: handoff.predecessor_end_kind.as_str().to_owned(),
                            observed_at_ms: wire_millis(handoff.observed_at_ms)?,
                        })
                    })
                    .collect::<Result<Vec<_>, DaemonError>>()?;
                AdminResponse::Generations {
                    request_id: request.request_id().clone(),
                    generations: GenerationsView {
                        generation_id: GENERATION_ID.to_owned(),
                        tenures,
                        handoffs,
                    },
                }
            }
            automonique_protocol::admin::AdminCommand::ReloadStatus => {
                let reload_id = request
                    .reload_id()
                    .ok_or(DaemonError::ProtocolRefused("admin_invalid_body"))?;
                let history = match self
                    .reload_audit
                    .history(reload_id, 0, MAX_RELOAD_TRANSITIONS)
                {
                    Ok(history) => history,
                    Err(ReloadAuditError::NotFound) => {
                        return self.write_refusal(
                            stream,
                            request.request_id(),
                            "reload_not_found",
                        );
                    }
                    Err(error) => {
                        return Err(DaemonError::ReloadAuditFailed(error.category()));
                    }
                };
                let record = history.record;
                let transitions = history
                    .transitions
                    .into_iter()
                    .map(|transition| {
                        Ok(ReloadTransitionView {
                            revision: transition.revision,
                            phase: transition.phase.as_str().to_owned(),
                            observed_at_ms: wire_millis(transition.observed_at_ms)?,
                            failure_category: transition.failure_category,
                        })
                    })
                    .collect::<Result<Vec<_>, DaemonError>>()?;
                AdminResponse::ReloadStatus {
                    request_id: request.request_id().clone(),
                    reload: ReloadStatusView {
                        reload_id: record.reload_id,
                        source_generation_id: record.source_generation_id,
                        source_lease_epoch: record.source_lease_epoch,
                        target_generation_id: record.target_generation_id,
                        target_release_digest: record.target_release_digest,
                        phase: record.phase.as_str().to_owned(),
                        failure_category: record.failure_category,
                        created_at_ms: wire_millis(record.created_at_ms)?,
                        updated_at_ms: wire_millis(record.updated_at_ms)?,
                        terminal_at_ms: record.terminal_at_ms.map(wire_millis).transpose()?,
                        revision: record.revision,
                        transitions,
                    },
                }
            }
            automonique_protocol::admin::AdminCommand::SubmitSynthetic => {
                if self.disconnected_recovery {
                    return self.write_refusal(
                        stream,
                        request.request_id(),
                        "disconnected_recovery",
                    );
                }
                let now_ms = unix_millis()?;
                let snapshot = self.store.status_snapshot_at(GENERATION_ID, now_ms)?;
                if self.reconciliation_run_id.is_some()
                    || snapshot_requires_reconciliation(&snapshot)
                {
                    return self.write_refusal(
                        stream,
                        request.request_id(),
                        DaemonError::ReconciliationRequired.category(),
                    );
                }
                // An operator pause closes this lane with its own category, so
                // a client can tell "an operator stopped intake" from "this
                // generation is damaged" without reading the status.
                if self.store.intake_paused(GENERATION_ID, now_ms)?.is_some() {
                    return self.write_refusal(
                        stream,
                        request.request_id(),
                        INTAKE_PAUSED_CATEGORY,
                    );
                }
                let submission = request
                    .submission()
                    .ok_or(DaemonError::ProtocolRefused("admin_invalid_body"))?;
                let receipt = self.store.submit_inbox(InboxSubmission {
                    transport: "local.synthetic",
                    transport_key: submission.idempotency_key(),
                    scope: submission.scope(),
                    payload: submission.task().as_bytes(),
                    received_ms: unix_millis()?,
                })?;
                AdminResponse::SyntheticAccepted {
                    request_id: request.request_id().clone(),
                    inbox_id: u64::try_from(receipt.inbox_id)
                        .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                    duplicate: receipt.duplicate,
                }
            }
            automonique_protocol::admin::AdminCommand::SubmitRun => {
                if self.disconnected_recovery {
                    return self.write_refusal(
                        stream,
                        request.request_id(),
                        "disconnected_recovery",
                    );
                }
                // THIS ARM STOPS AT CUSTODY.
                //
                // What follows verifies a document and writes it down. It does
                // not admit the run, build a launch plan, reserve a workspace,
                // compose a sandbox, or start a supervisor — and it must not
                // acquire the habit of doing so quietly. Since the execution
                // lane was wired, starting a submitted document is a second,
                // separately authenticated request (`AdminCommand::Execute`,
                // handled by `handle_execute`), which is what keeps "we hold
                // this" and "we are running this" two decisions rather than
                // one. Accepting a document therefore establishes custody of
                // it and no authority over anything: the lane still refuses
                // fail-closed on a host whose sandbox is unenforceable, still
                // establishes no release trust for the binary the document
                // names, and still admits only the daemon's own workspace
                // registry and backend.
                let now_ms = unix_millis()?;
                let snapshot = self.store.status_snapshot_at(GENERATION_ID, now_ms)?;
                if self.reconciliation_run_id.is_some()
                    || snapshot_requires_reconciliation(&snapshot)
                {
                    // A degraded generation is not accepting intake, and a
                    // submission is intake even though it schedules nothing.
                    // The reported `accepting_intake` must keep meaning what
                    // the arms actually do.
                    return self.write_refusal(
                        stream,
                        request.request_id(),
                        DaemonError::ReconciliationRequired.category(),
                    );
                }
                // A pause closes intake, and custody of a document is intake
                // even though it schedules nothing — the same reasoning that
                // makes a degraded generation refuse here. Gating both lanes is
                // what keeps `accepting_intake == false` a true statement
                // rather than a description of one of the two arms.
                if self.store.intake_paused(GENERATION_ID, now_ms)?.is_some() {
                    return self.write_refusal(
                        stream,
                        request.request_id(),
                        INTAKE_PAUSED_CATEGORY,
                    );
                }
                // The fence is checked here and the row lands in a different
                // database, so this is a check-then-write across two files
                // rather than one transaction. `automonique_store`'s
                // run_submissions module states that race and the specific
                // ground on which a custody row may accept it.
                let generation = snapshot.generation().ok_or(StoreError::StaleEpoch)?;
                if generation.holder_id() != self.instance_id.as_str()
                    || generation.lease_epoch() != self.lease_epoch
                    || generation.lease_expires_ms() != self.lease_expires_ms
                    || generation.lease_expires_ms() <= snapshot.lease_observed_boottime_ms()
                {
                    return Err(DaemonError::Store(StoreError::StaleEpoch));
                }
                let submission = request
                    .run_submission()
                    .ok_or(DaemonError::ProtocolRefused("admin_invalid_body"))?;

                // 1. The declared digest must name the bytes as received. This
                //    runs before anything parses them, so a document whose
                //    name and contents disagree is refused without ever being
                //    interpreted.
                let spec_digest = Sha256::digest(submission.document());
                if &spec_digest != submission.spec_digest() {
                    return self.write_refusal(
                        stream,
                        request.request_id(),
                        "run_spec_digest_mismatch",
                    );
                }
                // 2. Strict decode by the runner's own decoder. The refusal
                //    carries its class and never a byte of the document.
                let spec = match RunSpec::from_canonical_bytes(submission.document()) {
                    Ok(spec) => spec,
                    Err(error) => {
                        return self.write_refusal(
                            stream,
                            request.request_id(),
                            run_spec_decode_category(error),
                        );
                    }
                };
                // 3. Re-encode what the decoder read and require the same
                //    digest, so the digest about to be stored is bound to the
                //    typed value the decoder actually produced.
                //
                //    Stated plainly: while the runner's decoder keeps its own
                //    `NonCanonicalRoundTrip` guard, this cannot fail, and no
                //    test here can distinguish a build with it from one
                //    without. It is kept because that guard is another crate's
                //    private decode step rather than a contract this lane can
                //    hold anyone to, and because the cost is one hash of at
                //    most a few tens of kilobytes. The `not_encodable` arm is
                //    unreachable for the same reason: a document that decoded
                //    from an admin frame cannot re-encode past the runner's
                //    8 MiB ceiling. Both are fail-closed, and neither is
                //    presented here as evidence of anything.
                let reencoded = match spec.to_canonical_bytes() {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return self.write_refusal(
                            stream,
                            request.request_id(),
                            "run_spec_not_encodable",
                        );
                    }
                };
                if Sha256::digest(&reencoded) != spec_digest {
                    return self.write_refusal(
                        stream,
                        request.request_id(),
                        "run_spec_not_canonical",
                    );
                }
                let digest_hex = spec_digest.to_hex();
                let receipt = match self.run_submissions.record(RunSubmission {
                    idempotency_key: submission.idempotency_key(),
                    run_id: spec.run_id().as_str(),
                    spec_digest: &digest_hex,
                    document: submission.document(),
                    accepted_at_ms: now_ms,
                }) {
                    Ok(receipt) => receipt,
                    Err(error) if run_submission_refusal(&error) => {
                        return self.write_refusal(stream, request.request_id(), error.category());
                    }
                    Err(error) => return Err(DaemonError::RunSubmissionFailed(error.category())),
                };
                // CUSTODY FIRST, READ MODEL SECOND — and the order is the
                // whole of the guarantee.
                //
                // The document is durable above. The index row below is a
                // derived read model of it: it holds nothing the submission
                // log does not, and a rebuild from custody could reconstruct
                // every row it contains. Writing it second means a crash
                // between the two loses a listing entry and never a document.
                // The reverse order would let an index name a submission
                // nobody accepted, which `automonique_store::run_index`
                // describes as a broken listing — the failure this ordering
                // buys, in exchange for never presenting a lost document as an
                // absent one.
                //
                // There is no transaction across the two databases and there
                // cannot be one; they are separate files. So a failed
                // registration is a typed daemon error rather than a client
                // refusal: the submitter's document is held, their receipt
                // would be true, and the thing that failed is ours.
                //
                // A replay registers nothing. The store would refuse it with
                // `AlreadyRegistered` anyway — the refusal is tolerated below
                // rather than relied upon — but the deeper reason is ordering:
                // rows are registered in submission order, which is what makes
                // a page ordered by `index_id` also ordered by
                // `submission_id`, and that is the order `RunListPage`
                // requires. Back-filling a submission whose registration
                // failed would insert a row whose submission identity is below
                // its predecessors', and every later listing would be refused
                // as out of order. Such a submission stays unlisted, and a
                // reconcile that rebuilds the read model in order is where it
                // would come back.
                if !receipt.disposition.is_replay() {
                    match self.run_index.register(RunIndexEntry {
                        submission_id: receipt.submission_id,
                        run_id: spec.run_id().as_str(),
                        registered_at_ms: now_ms,
                    }) {
                        Ok(_) | Err(RunIndexError::AlreadyRegistered { .. }) => {}
                        Err(error) => return Err(DaemonError::RunIndexFailed(error.category())),
                    }
                }
                AdminResponse::RunAccepted {
                    request_id: request.request_id().clone(),
                    run_id: spec.run_id().clone(),
                    spec_digest,
                    submission_id: u64::try_from(receipt.submission_id)
                        .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                    replay: receipt.disposition.is_replay(),
                }
            }
            automonique_protocol::admin::AdminCommand::InspectReconciliation => {
                let run_id = request
                    .reconciliation_run_id()
                    .and_then(|value| i64::try_from(value).ok())
                    .ok_or(DaemonError::ProtocolRefused("admin_invalid_body"))?;
                let evidence = match self.store.inspect_reconciliation(run_id) {
                    Ok(evidence) => evidence,
                    Err(error) if reconciliation_command_refusal(&error) => {
                        return self.write_refusal(stream, request.request_id(), error.category());
                    }
                    Err(error) => return Err(DaemonError::Store(error)),
                };
                let provenance = evidence.provenance.clone();
                let mut admin_evidence = AdminReconciliationEvidence::new(
                    u64::try_from(evidence.run_id)
                        .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                    evidence.scope,
                    evidence.generation_id,
                    evidence.lease_epoch,
                    evidence.run_revision,
                    evidence.terminal_payload_present,
                    evidence.outbox_count,
                )
                .map_err(|error| DaemonError::ProtocolRefused(error.category()))?;
                if let Some(provenance) = provenance {
                    admin_evidence = admin_evidence
                        .with_provenance(
                            provenance.trace_id,
                            provenance.correlation_id,
                            provenance.causation_id,
                        )
                        .map_err(|error| DaemonError::ProtocolRefused(error.category()))?;
                }
                AdminResponse::ReconciliationInspected {
                    request_id: request.request_id().clone(),
                    evidence: admin_evidence,
                }
            }
            automonique_protocol::admin::AdminCommand::FailReconciliation => {
                let failure = request
                    .reconciliation_failure()
                    .ok_or(DaemonError::ProtocolRefused("admin_invalid_body"))?;
                let run_id = i64::try_from(failure.run_id())
                    .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?;
                let receipt = match self.store.reconcile_run(ReconciliationRequest {
                    run_id,
                    authority_generation_id: GENERATION_ID,
                    authority_holder_id: self.instance_id.as_str(),
                    authority_lease_epoch: self.lease_epoch,
                    expected_generation_id: failure.expected_generation_id(),
                    expected_lease_epoch: failure.expected_lease_epoch(),
                    expected_revision: failure.expected_revision(),
                    decision_key: failure.decision_key(),
                    now_ms: unix_millis()?,
                    decision: ReconciliationDecision::Fail {
                        reason: failure.reason(),
                    },
                }) {
                    Ok(receipt) => receipt,
                    Err(error) if reconciliation_command_refusal(&error) => {
                        return self.write_refusal(stream, request.request_id(), error.category());
                    }
                    Err(error) => return Err(DaemonError::Store(error)),
                };
                if self.reconciliation_run_id == Some(run_id) {
                    self.reconciliation_run_id = None;
                }
                AdminResponse::ReconciliationFailed {
                    request_id: request.request_id().clone(),
                    run_event_id: u64::try_from(receipt.run_event_id)
                        .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                    inbox_event_id: u64::try_from(receipt.inbox_event_id)
                        .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                    outbox_id: u64::try_from(receipt.outbox_id)
                        .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                    duplicate: receipt.duplicate,
                }
            }
            automonique_protocol::admin::AdminCommand::InspectOutbox => {
                let outbox_id = request
                    .outbox_id()
                    .and_then(|value| i64::try_from(value).ok())
                    .ok_or(DaemonError::ProtocolRefused("admin_invalid_body"))?;
                let evidence = match self.store.inspect_outbox_reconciliation(outbox_id) {
                    Ok(evidence) => evidence,
                    Err(error) if reconciliation_command_refusal(&error) => {
                        return self.write_refusal(stream, request.request_id(), error.category());
                    }
                    Err(error) => return Err(DaemonError::Store(error)),
                };
                let provenance = evidence.provenance.clone();
                AdminResponse::OutboxInspected {
                    request_id: request.request_id().clone(),
                    evidence: AdminOutboxEvidence::new(AdminOutboxEvidenceParts {
                        outbox_id: u64::try_from(evidence.outbox_id)
                            .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                        intent_key: evidence.intent_key,
                        transport: evidence.transport,
                        kind: evidence.kind,
                        state: evidence.state,
                        revision: evidence.revision,
                        attempt: evidence.attempt,
                        lease_token: evidence.lease_token,
                        lease_generation_id: evidence.lease_generation_id,
                        lease_holder: evidence.lease_holder,
                        lease_epoch: evidence.lease_epoch,
                        lease_expires_ms: evidence
                            .lease_expires_ms
                            .map(u64::try_from)
                            .transpose()
                            .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                        delivery_receipt_key: evidence.delivery_receipt_key,
                        trace_id: provenance.as_ref().map(|value| value.trace_id.clone()),
                        correlation_id: provenance
                            .as_ref()
                            .map(|value| value.correlation_id.clone()),
                        causation_id: provenance.as_ref().map(|value| value.causation_id.clone()),
                    })
                    .map_err(|error| DaemonError::ProtocolRefused(error.category()))?,
                }
            }
            automonique_protocol::admin::AdminCommand::ReconcileOutbox => {
                let reconciliation = request
                    .outbox_reconciliation()
                    .ok_or(DaemonError::ProtocolRefused("admin_invalid_body"))?;
                let outbox_id = i64::try_from(reconciliation.outbox_id())
                    .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?;
                let decision = match reconciliation.decision() {
                    OutboxReconciliationDecision::Delivered { receipt_key } => {
                        StoreOutboxDecision::Delivered { receipt_key }
                    }
                    OutboxReconciliationDecision::DeadLetter { reason } => {
                        StoreOutboxDecision::DeadLetter { reason }
                    }
                };
                let receipt = match self.store.reconcile_outbox(OutboxReconciliationRequest {
                    outbox_id,
                    authority_generation_id: GENERATION_ID,
                    authority_holder_id: self.instance_id.as_str(),
                    authority_lease_epoch: self.lease_epoch,
                    expected_generation_id: reconciliation.expected_generation_id(),
                    expected_lease_epoch: reconciliation.expected_lease_epoch(),
                    expected_lease_token: reconciliation.expected_lease_token(),
                    expected_attempt: reconciliation.expected_attempt(),
                    expected_revision: reconciliation.expected_revision(),
                    now_ms: unix_millis()?,
                    decision,
                }) {
                    Ok(receipt) => receipt,
                    Err(error) if reconciliation_command_refusal(&error) => {
                        return self.write_refusal(stream, request.request_id(), error.category());
                    }
                    Err(error) => return Err(DaemonError::Store(error)),
                };
                AdminResponse::OutboxReconciled {
                    request_id: request.request_id().clone(),
                    outbox_id: u64::try_from(receipt.outbox_id)
                        .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                    state: receipt.state,
                    revision: receipt.revision,
                    duplicate: receipt.duplicate,
                }
            }
            automonique_protocol::admin::AdminCommand::PauseIntake => {
                // WHAT A PAUSE IS SCOPED TO, AND WHAT THAT COSTS.
                //
                // The durable row names `GENERATION_ID` — the identifier, not
                // the lease epoch that wrote it. Two consequences follow, and
                // only one of them is obvious:
                //
                // - A restart keeps the pause. This daemon always takes the
                //   same named generation, so a successor process reads the
                //   same row and comes back with intake closed. That is the
                //   point: an operator who paused before a crash should not
                //   have their decision quietly undone by the recovery.
                // - A *different* generation does not see it. Its intake is
                //   open on the first tick, and its operator must pause it
                //   themselves. Nothing here warns them.
                //
                // A global pause — one row gating every generation — is the
                // other reasonable policy, and it is a policy choice rather
                // than a correctness fix. It is deliberately not implemented:
                // it would let one operator close intake for a control plane
                // they may not own, which is a decision for whoever owns this
                // product to make, not for this handler to assume.
                let pause = request
                    .intake_pause()
                    .ok_or(DaemonError::ProtocolRefused("admin_invalid_body"))?;
                let receipt = match self.store.pause_intake(IntakePauseRequest {
                    generation_id: GENERATION_ID,
                    holder_id: self.instance_id.as_str(),
                    authority_lease_epoch: self.lease_epoch,
                    actor: pause.actor(),
                    reason: pause.reason(),
                    now_ms: unix_millis()?,
                }) {
                    Ok(receipt) => receipt,
                    Err(error) if intake_pause_refusal(&error) => {
                        return self.write_refusal(stream, request.request_id(), error.category());
                    }
                    Err(error) => return Err(DaemonError::Store(error)),
                };
                AdminResponse::IntakePaused {
                    request_id: request.request_id().clone(),
                    pause_id: u64::try_from(receipt.pause_id)
                        .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                    revision: receipt.revision,
                }
            }
            automonique_protocol::admin::AdminCommand::ResumeIntake => {
                let resume = request
                    .intake_resume()
                    .ok_or(DaemonError::ProtocolRefused("admin_invalid_body"))?;
                let now_ms = unix_millis()?;
                // The revision the resume presents is read here rather than
                // supplied by the client: a resume closes whichever pause is
                // live, and asking an operator to quote a revision they cannot
                // see would make the command unusable. The store still
                // compare-and-sets on it inside its own transaction, so a
                // concurrent writer between this read and that write is
                // refused rather than overwritten.
                let Some(live) = self.store.intake_paused(GENERATION_ID, now_ms)? else {
                    return self.write_refusal(
                        stream,
                        request.request_id(),
                        StoreError::NotPaused.category(),
                    );
                };
                let receipt = match self.store.resume_intake(IntakeResumeRequest {
                    generation_id: GENERATION_ID,
                    holder_id: self.instance_id.as_str(),
                    authority_lease_epoch: self.lease_epoch,
                    actor: resume.actor(),
                    expected_revision: live.revision,
                    now_ms,
                }) {
                    Ok(receipt) => receipt,
                    Err(error) if intake_pause_refusal(&error) => {
                        return self.write_refusal(stream, request.request_id(), error.category());
                    }
                    Err(error) => return Err(DaemonError::Store(error)),
                };
                AdminResponse::IntakeResumed {
                    request_id: request.request_id().clone(),
                    pause_id: u64::try_from(receipt.pause_id)
                        .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?,
                    revision: receipt.revision,
                }
            }
            automonique_protocol::admin::AdminCommand::Shutdown => {
                AdminResponse::ShutdownAccepted {
                    request_id: request.request_id().clone(),
                }
            }
        };
        let response = response
            .to_message()
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?
            .to_canonical_bytes();
        let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + response.len());
        encode_frame(&response, &mut frame)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?;
        stream.write_all(&frame)?;
        stream.flush()?;
        if matches!(
            request.command(),
            automonique_protocol::admin::AdminCommand::Shutdown
        ) {
            stop.store(true, Ordering::Release);
        }
        Ok(())
    }

    /// Serve the transport-independent platform-v1 contract on the local
    /// authenticated socket.
    fn handle_platform(
        &mut self,
        stream: &mut UnixStream,
        message: &PlatformRequestMessage,
    ) -> Result<(), DaemonError> {
        let now_ms = unix_millis()?;
        let snapshot = self.store.status_snapshot_at(GENERATION_ID, now_ms)?;
        let generation = snapshot.generation().ok_or(StoreError::StaleEpoch)?;
        if generation.holder_id() != self.instance_id.as_str()
            || generation.lease_epoch() != self.lease_epoch
            || generation.lease_expires_ms() != self.lease_expires_ms
            || generation.lease_expires_ms() <= snapshot.lease_observed_boottime_ms()
        {
            return Err(DaemonError::Store(StoreError::StaleEpoch));
        }

        let response = match message.request() {
            PlatformRequest::Capabilities => PlatformResponse::Capabilities(PlatformCapabilities {
                protocol: automonique_protocol::platform::PLATFORM_PROTOCOL,
                schema: automonique_protocol::platform::PLATFORM_SCHEMA_V1,
                methods: PlatformMethod::ALL.to_vec(),
                transports: vec![PlatformTransport::LocalUnix],
            }),
            PlatformRequest::Snapshot(request) => {
                self.refresh_platform_resources(&request.resources, now_ms)?;
                match self.platform.snapshot(&request.resources, "resources") {
                    Ok((resources, cursor)) => PlatformResponse::Snapshot(
                        Snapshot::new(resources, cursor)
                            .map_err(|_| DaemonError::ProtocolRefused("platform_snapshot"))?,
                    ),
                    Err(error) => platform_store_response(&error),
                }
            }
            PlatformRequest::Subscribe(request) => {
                let topic = request
                    .cursor
                    .as_ref()
                    .map_or("resources", |cursor| cursor.topic.as_str());
                if topic == "sessions" {
                    self.refresh_platform_sessions(now_ms)?;
                } else {
                    self.refresh_platform_resources(&[], now_ms)?;
                }
                match self.platform.subscribe(request.cursor.as_ref(), topic) {
                    Ok(subscription) => PlatformResponse::Subscription(subscription),
                    Err(error) => platform_store_response(&error),
                }
            }
            PlatformRequest::Execute(request) => {
                self.platform_execute(request, &snapshot, now_ms)?
            }
            PlatformRequest::GetReceipt(request) => match self
                .platform
                .receipt(request.id.as_ref(), request.idempotency_key.as_ref())
            {
                Ok(receipt) => PlatformResponse::Receipt(receipt),
                Err(error) => platform_store_response(&error),
            },
            PlatformRequest::ListSessions(request) => {
                if request.authority != ResourceAuthority::Automonique {
                    platform_refusal(ReceiptOutcome::Rejected, "authority_not_local")?
                } else {
                    self.refresh_platform_sessions(now_ms)?;
                    if let Some(cursor) = request.cursor.as_ref()
                        && let Err(error) = self.platform.subscribe(Some(cursor), "sessions")
                    {
                        platform_store_response(&error)
                    } else {
                        let (resources, cursor) = self
                            .platform
                            .snapshot(&[], "sessions")
                            .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?;
                        let mut sessions = Vec::new();
                        for session in resources
                            .into_iter()
                            .filter(|record| record.resource.kind == ResourceKind::Session)
                        {
                            let run = self.platform_run_for_session(&session.resource)?;
                            sessions.push(SessionRecord {
                                attachable: session.summary.as_str() == "open",
                                controllable: session.summary.as_str() == "open",
                                run,
                                session,
                            });
                        }
                        PlatformResponse::Sessions(
                            SessionList::new(sessions, cursor)
                                .map_err(|_| DaemonError::ProtocolRefused("platform_sessions"))?,
                        )
                    }
                }
            }
            PlatformRequest::Attach(request) => {
                self.refresh_platform_sessions(now_ms)?;
                if !self.platform_session_is_open(&request.session)? {
                    platform_refusal(ReceiptOutcome::Rejected, "session_not_attachable")?
                } else {
                    match self.platform.attach(
                        &request.session,
                        &request.client,
                        now_ms,
                        "sessions",
                    ) {
                        Ok(attachment) => PlatformResponse::Attached(attachment),
                        Err(error) => platform_store_response(&error),
                    }
                }
            }
            PlatformRequest::Detach(request) => {
                match self.platform.detach(&request.session, &request.client) {
                    Ok(()) => PlatformResponse::Detached {
                        session: request.session.clone(),
                        client: request.client.clone(),
                    },
                    Err(error) => platform_store_response(&error),
                }
            }
            PlatformRequest::ClaimControl(request) => {
                self.refresh_platform_sessions(now_ms)?;
                if !self.platform_session_is_open(&request.session)? {
                    platform_refusal(ReceiptOutcome::Rejected, "session_not_controllable")?
                } else {
                    match self.platform.claim_control(
                        &request.session,
                        &request.client,
                        &request.idempotency_key,
                        now_ms,
                    ) {
                        Ok(
                            automonique_store::platform_store::ControlAdmission::New(lease)
                            | automonique_store::platform_store::ControlAdmission::Replay(lease),
                        ) => PlatformResponse::ControlClaimed(lease),
                        Err(error) => platform_store_response(&error),
                    }
                }
            }
            PlatformRequest::ReleaseControl(request) => match self.platform.release_control(
                &request.session,
                &request.client,
                &request.lease,
                &request.idempotency_key,
                now_ms,
            ) {
                Ok(()) => PlatformResponse::ControlReleased {
                    session: request.session.clone(),
                    client: request.client.clone(),
                    lease: request.lease.clone(),
                },
                Err(error) => platform_store_response(&error),
            },
        };

        let payload = PlatformResponseMessage::new(message.request_id().clone(), response)
            .to_message()
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?
            .to_canonical_bytes();
        let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
        encode_frame(&payload, &mut frame)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?;
        stream.write_all(&frame)?;
        stream.flush()?;
        Ok(())
    }

    fn refresh_platform_sessions(&mut self, now_ms: i64) -> Result<(), DaemonError> {
        let path = self.state_dir.join(PROVIDER_JOURNAL_NAME);
        if path.exists() {
            let journal = ProviderJournal::open(path)
                .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?;
            let sessions = journal
                .sessions(automonique_protocol::platform::MAX_SNAPSHOT_RESOURCES)
                .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?;
            for session in sessions {
                let (freshness, summary) = match session.state {
                    automonique_store::provider_journal::SessionState::Open => {
                        (FreshnessState::Fresh, "open")
                    }
                    automonique_store::provider_journal::SessionState::Closed => {
                        (FreshnessState::Stale, "closed")
                    }
                    automonique_store::provider_journal::SessionState::Lost => {
                        (FreshnessState::Unknown, "lost")
                    }
                };
                let record = ResourceRecord {
                    resource: ResourceCoordinate::new(
                        ResourceAuthority::Automonique,
                        ResourceKind::Session,
                        ResourceId::new(session.provider_session_key)
                            .map_err(|_| DaemonError::PlatformStoreFailed("session_id_invalid"))?,
                    ),
                    freshness: Freshness {
                        state: freshness,
                        observed_at: automonique_protocol::primitives::EpochMillis::from_millis(
                            session.closed_ms.unwrap_or(now_ms),
                        ),
                        revision: Revision::new(session.revision)
                            .map_err(|_| DaemonError::PlatformStoreFailed("revision_invalid"))?,
                    },
                    summary: PlatformText::new(summary)
                        .map_err(|_| DaemonError::PlatformStoreFailed("session_state_invalid"))?,
                };
                self.platform
                    .upsert_resource("sessions", &record)
                    .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?;
            }
        }
        // A retained managed binding is the authority on resumability after
        // the attempt-scoped provider host closes. Apply it last so a normal
        // JCode host teardown does not make a resumable session look closed.
        for session in self
            .managed_sessions
            .list()
            .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?
        {
            let record = ResourceRecord {
                resource: ResourceCoordinate::new(
                    ResourceAuthority::Automonique,
                    ResourceKind::Session,
                    ResourceId::new(session.provider_session_id)
                        .map_err(|_| DaemonError::PlatformStoreFailed("session_id_invalid"))?,
                ),
                freshness: Freshness {
                    state: if session.open {
                        FreshnessState::Fresh
                    } else {
                        FreshnessState::Unknown
                    },
                    observed_at: automonique_protocol::primitives::EpochMillis::from_millis(
                        session.updated_ms,
                    ),
                    revision: Revision::new(session.revision)
                        .map_err(|_| DaemonError::PlatformStoreFailed("revision_invalid"))?,
                },
                summary: PlatformText::new(if session.open { "open" } else { "lost" })
                    .map_err(|_| DaemonError::PlatformStoreFailed("session_state_invalid"))?,
            };
            self.platform
                .upsert_resource("sessions", &record)
                .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?;
        }
        Ok(())
    }

    fn platform_session_is_open(&self, session: &ResourceCoordinate) -> Result<bool, DaemonError> {
        if session.authority != ResourceAuthority::Automonique
            || session.kind != ResourceKind::Session
        {
            return Ok(false);
        }
        self.platform
            .resource(session)
            .map(|record| record.is_some_and(|record| record.summary.as_str() == "open"))
            .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))
    }

    fn platform_run_for_session(
        &self,
        session: &ResourceCoordinate,
    ) -> Result<Option<ResourceCoordinate>, DaemonError> {
        if session.authority != ResourceAuthority::Automonique
            || session.kind != ResourceKind::Session
        {
            return Ok(None);
        }
        if let Some(binding) = self
            .managed_sessions
            .by_id(session.id.as_str())
            .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?
        {
            let id = ResourceId::new(binding.run_id)
                .map_err(|_| DaemonError::PlatformStoreFailed("run_id_invalid"))?;
            return Ok(Some(ResourceCoordinate::new(
                ResourceAuthority::Automonique,
                ResourceKind::Run,
                id,
            )));
        }
        let records = self
            .run_index
            .by_run_id(session.id.as_str())
            .map_err(index_failed)?;
        let Some(record) = records.last() else {
            return Ok(None);
        };
        let id = ResourceId::new(record.run_id.clone())
            .map_err(|_| DaemonError::PlatformStoreFailed("run_id_invalid"))?;
        Ok(Some(ResourceCoordinate::new(
            ResourceAuthority::Automonique,
            ResourceKind::Run,
            id,
        )))
    }

    fn refresh_platform_resources(
        &mut self,
        requested: &[ResourceCoordinate],
        now_ms: i64,
    ) -> Result<(), DaemonError> {
        let wants_all = requested.is_empty();
        let wants_actions = wants_all
            || requested.iter().any(|resource| {
                resource.authority == ResourceAuthority::Automonique
                    && resource.kind == ResourceKind::Client
                    && resource.id.as_str().starts_with("platform-action-")
            });
        if wants_actions {
            self.refresh_platform_actions(now_ms)?;
        }
        let wants_models = wants_all
            || requested.iter().any(|resource| {
                resource.authority == ResourceAuthority::Provider
                    && resource.kind == ResourceKind::Model
            });
        if wants_models {
            self.refresh_platform_models(now_ms)?;
        }
        let wants_node = wants_all
            || requested.iter().any(|resource| {
                resource.authority == ResourceAuthority::Automonique
                    && resource.kind == ResourceKind::Node
                    && resource.id.as_str() == self.instance_id.as_str()
            });
        if wants_node {
            let (existing_nodes, _) = self
                .platform
                .snapshot(&[], "resources")
                .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?;
            let active_node = self.instance_id.as_str().to_owned();
            for retired in existing_nodes.into_iter().filter(|record| {
                record.resource.authority == ResourceAuthority::Automonique
                    && record.resource.kind == ResourceKind::Node
                    && record.resource.id.as_str() != active_node
            }) {
                self.upsert_platform_observation(
                    retired.resource,
                    FreshnessState::Stale,
                    "daemon retired",
                    now_ms,
                )?;
            }
            let node = ResourceRecord {
                resource: ResourceCoordinate::new(
                    ResourceAuthority::Automonique,
                    ResourceKind::Node,
                    ResourceId::new(self.instance_id.as_str())
                        .map_err(|_| DaemonError::ProtocolRefused("platform_node_id"))?,
                ),
                freshness: Freshness {
                    state: FreshnessState::Fresh,
                    observed_at: automonique_protocol::primitives::EpochMillis::from_millis(now_ms),
                    revision: Revision::new(self.lease_epoch.max(1))
                        .map_err(|_| DaemonError::ProtocolRefused("platform_revision"))?,
                },
                summary: PlatformText::new("daemon ready")
                    .map_err(|_| DaemonError::ProtocolRefused("platform_summary"))?,
            };
            self.platform
                .upsert_resource("resources", &node)
                .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?;
        }

        let wants_approvals = wants_all
            || requested.iter().any(|resource| {
                resource.authority == ResourceAuthority::Automonique
                    && resource.kind == ResourceKind::Approval
            });
        if wants_approvals {
            self.refresh_platform_approvals(now_ms)?;
        }

        let records = if wants_all {
            self.run_index
                .page(0, automonique_protocol::platform::MAX_SNAPSHOT_RESOURCES)
                .map_err(index_failed)?
                .entries
        } else {
            let mut records = Vec::new();
            for resource in requested.iter().filter(|resource| {
                resource.authority == ResourceAuthority::Automonique
                    && resource.kind == ResourceKind::Run
            }) {
                if let Some(record) = self
                    .run_index
                    .by_run_id(resource.id.as_str())
                    .map_err(index_failed)?
                    .into_iter()
                    .last()
                {
                    records.push(record);
                }
            }
            records
        };
        for record in records {
            let resource = platform_run_resource(&record)?;
            self.platform
                .upsert_resource("resources", &resource)
                .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?;
        }
        Ok(())
    }

    fn refresh_platform_actions(&mut self, now_ms: i64) -> Result<(), DaemonError> {
        for action in PLATFORM_LOCAL_ACTIONS {
            let (target, parameter, confirmation) = match action {
                PlatformAction::StartRun => ("run", "none", "required"),
                PlatformAction::StopRun => ("run", "none", "required"),
                PlatformAction::DecideApproval => ("approval", "enum:grant|deny", "required"),
                PlatformAction::SubmitRequest => ("node", "text", "required"),
                PlatformAction::FollowUp => ("session", "text", "required"),
                PlatformAction::Steer => ("control_lease", "text", "required"),
                PlatformAction::SubmitJob
                | PlatformAction::ApproveRelease
                | PlatformAction::RegisterNode => continue,
            };
            let coordinate = ResourceCoordinate::new(
                ResourceAuthority::Automonique,
                ResourceKind::Client,
                ResourceId::new(format!("platform-action-{}", action.as_str()))
                    .map_err(|_| DaemonError::PlatformStoreFailed("action_id_invalid"))?,
            );
            self.upsert_platform_observation(
                coordinate,
                FreshnessState::Fresh,
                &format!(
                    "registry=platform-v1;action={};target={target};parameter={parameter};confirmation={confirmation}",
                    action.as_str()
                ),
                now_ms,
            )?;
        }
        Ok(())
    }

    fn refresh_platform_approvals(&mut self, now_ms: i64) -> Result<(), DaemonError> {
        let pending = self
            .approval_requests
            .pending(MAX_APPROVAL_REQUEST_PAGE)
            .map_err(|error| DaemonError::ApprovalRequestsFailed(error.category()))?;
        let pending_ids = pending
            .iter()
            .map(|record| record.request_key.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let (resources, _) = self
            .platform
            .snapshot(&[], "resources")
            .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?;
        let existing = resources
            .into_iter()
            .filter(|record| {
                record.resource.authority == ResourceAuthority::Automonique
                    && record.resource.kind == ResourceKind::Approval
            })
            .collect::<Vec<_>>();

        for record in &pending {
            let coordinate = ResourceCoordinate::new(
                ResourceAuthority::Automonique,
                ResourceKind::Approval,
                ResourceId::new(record.request_key.clone())
                    .map_err(|_| DaemonError::PlatformStoreFailed("approval_id_invalid"))?,
            );
            self.upsert_platform_observation(
                coordinate,
                FreshnessState::Fresh,
                &format!("state=pending;expires_at={}", record.expires_at_ms),
                now_ms,
            )?;
        }
        for resource in existing
            .into_iter()
            .filter(|resource| !pending_ids.contains(resource.resource.id.as_str()))
        {
            let state = self
                .approval_requests
                .entry(resource.resource.id.as_str())
                .map_err(|error| DaemonError::ApprovalRequestsFailed(error.category()))?
                .map_or("unknown", |record| record.state.as_str());
            self.upsert_platform_observation(
                resource.resource,
                FreshnessState::Stale,
                &format!("state={state}"),
                now_ms,
            )?;
        }
        Ok(())
    }

    /// Reconcile the credential-free provider model inventory into platform
    /// resources. Model IDs come only from the bounded `model/list` decoder;
    /// credentials and provider response bodies never enter the projection.
    fn refresh_platform_models(&mut self, now_ms: i64) -> Result<(), DaemonError> {
        if self.platform_models_observed_ms.is_some_and(|observed_ms| {
            now_ms >= observed_ms
                && now_ms.saturating_sub(observed_ms) < PLATFORM_MODEL_REFRESH_MILLIS
        }) {
            return Ok(());
        }

        let (resources, _) = self
            .platform
            .snapshot(&[], "resources")
            .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?;
        let existing: Vec<ResourceRecord> = resources
            .into_iter()
            .filter(|record| {
                record.resource.authority == ResourceAuthority::Provider
                    && record.resource.kind == ResourceKind::Model
            })
            .collect();

        match model_inventory::configured_provider_catalog(&self.state_dir) {
            model_inventory::ModelCatalogRead::Available(catalog) => {
                let source = catalog.source.as_str();
                let routes = model_inventory::configured_model_routes(&self.state_dir);
                let configured_routes = [
                    routes.conversation_primary.as_str(),
                    routes.conversation_fallback.as_str(),
                    routes.operational_primary.as_str(),
                ];
                let available: std::collections::BTreeSet<&str> = catalog
                    .models
                    .iter()
                    .map(|model| model.id.as_str())
                    .collect();
                for model in &catalog.models {
                    let coordinate = ResourceCoordinate::new(
                        ResourceAuthority::Provider,
                        ResourceKind::Model,
                        ResourceId::new(&model.id)
                            .map_err(|_| DaemonError::PlatformStoreFailed("model_id_invalid"))?,
                    );
                    let configured = configured_routes.contains(&model.id.as_str());
                    let summary = format!(
                        "source={source}; scope=configured_account; available=true; default={}; configured_route={configured}",
                        model.is_default
                    );
                    self.upsert_platform_observation(
                        coordinate,
                        FreshnessState::Fresh,
                        &summary,
                        now_ms,
                    )?;
                }
                for record in existing
                    .iter()
                    .filter(|record| !available.contains(record.resource.id.as_str()))
                {
                    self.upsert_platform_observation(
                        record.resource.clone(),
                        FreshnessState::Stale,
                        &format!("source={source}; scope=configured_account; available=false"),
                        now_ms,
                    )?;
                }
            }
            model_inventory::ModelCatalogRead::Unavailable(_) => {
                for record in existing {
                    self.upsert_platform_observation(
                        record.resource,
                        FreshnessState::Unknown,
                        "source=codex_model_list; scope=configured_account; available=unknown",
                        now_ms,
                    )?;
                }
            }
        }
        self.platform_models_observed_ms = Some(now_ms);
        Ok(())
    }

    /// Upsert one observation with a revision that advances only when its
    /// semantic state changes. Observation time alone does not create a
    /// subscription event, matching `PlatformStore::upsert_resource`.
    fn upsert_platform_observation(
        &mut self,
        coordinate: ResourceCoordinate,
        state: FreshnessState,
        summary: &str,
        now_ms: i64,
    ) -> Result<(), DaemonError> {
        let summary = PlatformText::new(summary)
            .map_err(|_| DaemonError::PlatformStoreFailed("platform_summary_invalid"))?;
        let current = self
            .platform
            .resource(&coordinate)
            .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?;
        let revision = match current.as_ref() {
            Some(record) if record.freshness.state == state && record.summary == summary => {
                record.freshness.revision
            }
            Some(record) => record
                .freshness
                .revision
                .checked_next()
                .map_err(|_| DaemonError::PlatformStoreFailed("revision_exhausted"))?,
            None => Revision::FIRST,
        };
        let record = ResourceRecord {
            resource: coordinate,
            freshness: Freshness {
                state,
                observed_at: automonique_protocol::primitives::EpochMillis::from_millis(now_ms),
                revision,
            },
            summary,
        };
        self.platform
            .upsert_resource("resources", &record)
            .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?;
        Ok(())
    }

    fn platform_execute(
        &mut self,
        request: &automonique_protocol::platform::ExecuteRequest,
        status: &StatusSnapshot,
        now_ms: i64,
    ) -> Result<PlatformResponse, DaemonError> {
        if request.target.authority != ResourceAuthority::Automonique {
            return platform_refusal(ReceiptOutcome::Rejected, "authority_not_local");
        }
        let mut steer_session_id = None;
        let authoritative_revision = match request.action {
            PlatformAction::StartRun | PlatformAction::StopRun => {
                if request.target.kind != ResourceKind::Run {
                    return platform_refusal(ReceiptOutcome::Rejected, "target_kind_invalid");
                }
                let records = self
                    .run_index
                    .by_run_id(request.target.id.as_str())
                    .map_err(index_failed)?;
                let Some(record) = records.last() else {
                    return platform_refusal(ReceiptOutcome::Rejected, "unknown_run");
                };
                Revision::new(record.revision)
                    .map_err(|_| DaemonError::RunIndexFailed("revision_invalid"))?
            }
            PlatformAction::DecideApproval => {
                if request.target.kind != ResourceKind::Approval {
                    return platform_refusal(ReceiptOutcome::Rejected, "target_kind_invalid");
                }
                let Some(record) = self
                    .approval_requests
                    .entry(request.target.id.as_str())
                    .map_err(|error| DaemonError::ApprovalRequestsFailed(error.category()))?
                else {
                    return platform_refusal(ReceiptOutcome::Rejected, "unknown_approval");
                };
                Revision::new(record.revision)
                    .map_err(|_| DaemonError::PlatformStoreFailed("revision_invalid"))?
            }
            PlatformAction::SubmitRequest => {
                if request.target.kind != ResourceKind::Node {
                    return platform_refusal(ReceiptOutcome::Rejected, "target_kind_invalid");
                }
                if request.target.id.as_str() != self.instance_id.as_str() {
                    return platform_refusal(ReceiptOutcome::Rejected, "target_not_active_node");
                }
                let Some(record) = self
                    .platform
                    .resource(&request.target)
                    .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?
                else {
                    return platform_refusal(ReceiptOutcome::Rejected, "unknown_node");
                };
                record.freshness.revision
            }
            PlatformAction::FollowUp => {
                if request.target.kind != ResourceKind::Session {
                    return platform_refusal(ReceiptOutcome::Rejected, "target_kind_invalid");
                }
                if !self.platform_session_is_open(&request.target)? {
                    return platform_refusal(ReceiptOutcome::Rejected, "session_not_controllable");
                }
                if !self
                    .managed_sessions
                    .by_id(request.target.id.as_str())
                    .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?
                    .is_some_and(|session| session.open)
                {
                    return platform_refusal(ReceiptOutcome::Rejected, "session_not_resumable");
                }
                let Some(record) = self
                    .platform
                    .resource(&request.target)
                    .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?
                else {
                    return platform_refusal(ReceiptOutcome::Rejected, "unknown_session");
                };
                record.freshness.revision
            }
            PlatformAction::Steer => {
                if request.target.kind != ResourceKind::ControlLease {
                    return platform_refusal(ReceiptOutcome::Rejected, "target_kind_invalid");
                }
                let lease =
                    automonique_protocol::platform::ControlLeaseId::new(request.target.id.as_str())
                        .map_err(|_| DaemonError::ProtocolRefused("platform_control_lease_id"))?;
                let Some(control) = self
                    .platform
                    .active_control(&lease, now_ms)
                    .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?
                else {
                    return platform_refusal(ReceiptOutcome::Rejected, "control_lease_not_active");
                };
                steer_session_id = Some(control.session.id.as_str().to_owned());
                control.revision
            }
            PlatformAction::SubmitJob
            | PlatformAction::ApproveRelease
            | PlatformAction::RegisterNode => {
                return platform_refusal(ReceiptOutcome::Rejected, "authority_not_local");
            }
        };
        let admission = match self
            .platform
            .prepare_execute(request, authoritative_revision, now_ms)
        {
            Ok(admission) => admission,
            Err(error) => return Ok(platform_store_response(&error)),
        };
        let accepted = match admission {
            ActionAdmission::New(receipt) => receipt,
            ActionAdmission::Replay(receipt) => return Ok(PlatformResponse::Receipt(receipt)),
        };

        let action_result = match request.action {
            PlatformAction::StartRun => {
                let run_id = RunId::new(request.target.id.as_str())
                    .map_err(|_| DaemonError::ProtocolRefused("platform_run_id"))?;
                let degraded = self.reconciliation_run_id.is_some()
                    || snapshot_requires_reconciliation(status);
                let paused = self.store.intake_paused(GENERATION_ID, now_ms)?.is_some();
                self.start_run(&run_id, degraded, paused, now_ms)
                    .map(|_| ReceiptOutcome::Accepted)
                    .map_err(ExecuteRefusal::as_str)
            }
            PlatformAction::StopRun => {
                let run_id = RunId::new(request.target.id.as_str())
                    .map_err(|_| DaemonError::ProtocolRefused("platform_run_id"))?;
                let records = self
                    .run_index
                    .by_run_id(run_id.as_str())
                    .map_err(index_failed)?;
                let observed = records.last().map_or(0, |record| record.last_sequence);
                self.cancel_run(&run_id, request.idempotency_key.as_str(), observed, now_ms)
                    .map(|_| ReceiptOutcome::Completed)
                    .map_err(ExecuteRefusal::as_str)
            }
            PlatformAction::DecideApproval => {
                let decision = match request
                    .parameter
                    .as_ref()
                    .map(|parameter| parameter.as_str())
                {
                    Some("grant") => ApprovalOutcome::Granted,
                    Some("deny") => ApprovalOutcome::Denied,
                    _ => {
                        return self.finalize_platform_rejection(
                            request,
                            "approval_decision_invalid",
                            now_ms,
                        );
                    }
                };
                self.record_decision(request.target.id.as_str(), decision, "platform-v1", now_ms)
                    .map(|_| ReceiptOutcome::Completed)
                    .map_err(|error| error.category())
            }
            PlatformAction::SubmitRequest | PlatformAction::FollowUp => {
                if self.disconnected_recovery {
                    Err("disconnected_recovery")
                } else if self.reconciliation_run_id.is_some()
                    || snapshot_requires_reconciliation(status)
                {
                    Err(DaemonError::ReconciliationRequired.category())
                } else if self.store.intake_paused(GENERATION_ID, now_ms)?.is_some() {
                    Err(INTAKE_PAUSED_CATEGORY)
                } else {
                    let Some(parameter) = request.parameter.as_ref() else {
                        return self.finalize_platform_rejection(
                            request,
                            "request_text_required",
                            now_ms,
                        );
                    };
                    let transport = if request.action == PlatformAction::SubmitRequest {
                        managed_tui::NEW_REQUEST_TRANSPORT
                    } else {
                        managed_tui::FOLLOW_UP_TRANSPORT
                    };
                    self.store
                        .submit_inbox(InboxSubmission {
                            transport,
                            transport_key: request.idempotency_key.as_str(),
                            scope: request.target.id.as_str(),
                            payload: parameter.as_str().as_bytes(),
                            received_ms: now_ms,
                        })
                        .map(|_| ReceiptOutcome::Accepted)
                        .map_err(|error| error.category())
                }
            }
            PlatformAction::Steer => {
                let Some(parameter) = request.parameter.as_ref() else {
                    return self.finalize_platform_rejection(
                        request,
                        "request_text_required",
                        now_ms,
                    );
                };
                let Some(session_id) = steer_session_id.as_deref() else {
                    return self.finalize_platform_rejection(
                        request,
                        "control_lease_not_active",
                        now_ms,
                    );
                };
                self.execution
                    .as_ref()
                    .ok_or(crate::execute::SteerRefusal::Unavailable)
                    .and_then(|execution| execution.steer_session(session_id, parameter.as_str()))
                    .map(|()| ReceiptOutcome::Completed)
                    .map_err(crate::execute::SteerRefusal::as_str)
            }
            PlatformAction::SubmitJob
            | PlatformAction::ApproveRelease
            | PlatformAction::RegisterNode => {
                return self.finalize_platform_rejection(request, "authority_not_local", now_ms);
            }
        };

        match action_result {
            Ok(ReceiptOutcome::Accepted) => Ok(PlatformResponse::Receipt(accepted)),
            Ok(outcome) => {
                let receipt = self
                    .platform
                    .finalize_execute(&request.idempotency_key, outcome, None, now_ms)
                    .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?;
                Ok(PlatformResponse::Receipt(receipt))
            }
            Err(category) => self.finalize_platform_rejection(request, category, now_ms),
        }
    }

    fn finalize_platform_rejection(
        &mut self,
        request: &automonique_protocol::platform::ExecuteRequest,
        category: &str,
        now_ms: i64,
    ) -> Result<PlatformResponse, DaemonError> {
        let receipt = self
            .platform
            .finalize_execute(
                &request.idempotency_key,
                ReceiptOutcome::Rejected,
                Some(category),
                now_ms,
            )
            .map_err(|error| DaemonError::PlatformStoreFailed(error.category()))?;
        Ok(PlatformResponse::Receipt(receipt))
    }

    /// Answer one read on the native Runs API.
    ///
    /// Fenced like every other arm: a daemon that has lost its generation
    /// answers nothing, because a read served from a database another
    /// generation now owns is a read of somebody else's state.
    ///
    /// Unlike the intake arms, this is *not* closed by a pause or by a
    /// degraded generation. A pause stops the daemon taking custody of new
    /// work; it does not make what is already held unreadable, and an operator
    /// diagnosing a degraded generation is precisely the person who needs to
    /// list what it holds.
    fn handle_runs(
        &mut self,
        stream: &mut UnixStream,
        request: &RunsRequest,
    ) -> Result<(), DaemonError> {
        let now_ms = unix_millis()?;
        let snapshot = self.store.status_snapshot_at(GENERATION_ID, now_ms)?;
        let generation = snapshot.generation().ok_or(StoreError::StaleEpoch)?;
        if generation.holder_id() != self.instance_id.as_str()
            || generation.lease_epoch() != self.lease_epoch
            || generation.lease_expires_ms() != self.lease_expires_ms
            || generation.lease_expires_ms() <= snapshot.lease_observed_boottime_ms()
        {
            return Err(DaemonError::Store(StoreError::StaleEpoch));
        }
        let response = match request {
            RunsRequest::ListRuns { request_id, query } => self.list_runs(request_id, query)?,
            RunsRequest::RunDetail { request_id, run_id } => self.run_detail(request_id, run_id)?,
        };
        let response = response
            .to_message()
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?
            .to_canonical_bytes();
        let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + response.len());
        encode_frame(&response, &mut frame)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?;
        stream.write_all(&frame)?;
        stream.flush()?;
        Ok(())
    }

    /// One bounded page of runs, or the resync a lost cursor earns.
    ///
    /// Every answer is built by [`RunsResponse::listing`] from the decision
    /// [`ListRuns::resume_within`] made, so a page that contradicts its own
    /// retention decision is refused here rather than served. This handler
    /// supplies the two things that module deliberately does not have — the
    /// real retained window and the rows — and nothing else.
    fn list_runs(
        &self,
        request_id: &RequestId,
        query: &ListRuns,
    ) -> Result<RunsResponse, DaemonError> {
        let Some(retained) = self.retained_runs()? else {
            // AN EMPTY INDEX RETAINS NOTHING AND HAS LOST NOTHING.
            //
            // There is no window to judge a cursor against, and inventing one
            // would mean answering `resync_required` — "positions you wanted
            // are gone" — about a log from which nothing has ever been
            // removed. Nothing here deletes, so a cursor ahead of an empty
            // index is caught up rather than lost, and the truthful answer is
            // an empty page that says it is complete.
            let from = query.since().map_or(1, RunCursor::position);
            let page =
                RunListPage::new(Vec::new(), Continuation::Complete).map_err(runs_refused)?;
            return RunsResponse::listing(
                request_id.clone(),
                query,
                CursorResume::Live { from },
                Some(page),
            )
            .map_err(runs_refused);
        };
        let decision = query.resume_within(retained.window);
        let CursorResume::Live { from } = decision else {
            return RunsResponse::listing(request_id.clone(), query, decision, None)
                .map_err(runs_refused);
        };
        let cursor = self.index_cursor_below(from, &retained)?;
        let limit = query.page_size().get();
        let page = match query.states().states() {
            // The filter is translated variant by variant, so a state this
            // build cannot name is a compile failure rather than a row the
            // listing silently drops.
            Some(states) => {
                let states: Vec<RunSpoolState> = states.iter().copied().map(spool_state).collect();
                self.run_index.page_in_states(cursor, limit, &states)
            }
            None => self.run_index.page(cursor, limit),
        }
        .map_err(index_failed)?;
        let mut runs = Vec::with_capacity(page.entries.len());
        for record in &page.entries {
            runs.push(self.summary(record)?);
        }
        // `next_cursor` is set only when the store saw a further *matching*
        // row, so a page shortened by the state filter still reports itself
        // complete only when nothing matching remains. The cursor is one past
        // the last submission served, which is the next identity a caller
        // receives — the coordinate a `RunCursor` names.
        let continuation = match (page.next_cursor, runs.last()) {
            (Some(_), Some(last)) => Continuation::More(RunCursor::new(
                last.submission_id()
                    .checked_add(1)
                    .ok_or(DaemonError::ProtocolRefused("counter_out_of_range"))?,
            )),
            _ => Continuation::Complete,
        };
        let page = RunListPage::new(runs, continuation).map_err(runs_refused)?;
        RunsResponse::listing(request_id.clone(), query, decision, Some(page)).map_err(runs_refused)
    }

    /// One run in full, or [`RunsRefusal::UnknownRun`].
    ///
    /// A run identity is not unique — `run_submissions` admits two submissions
    /// naming one run, and so does the index — so this answers with the most
    /// recently registered of them. The summary carries the exact
    /// `submission_id` it was built from, so the answer says which one it is
    /// rather than leaving a caller to assume there was only ever one.
    fn run_detail(
        &self,
        request_id: &RequestId,
        run_id: &RunId,
    ) -> Result<RunsResponse, DaemonError> {
        let records = self
            .run_index
            .by_run_id(run_id.as_str())
            .map_err(index_failed)?;
        let Some(record) = records.last() else {
            return Ok(RunsResponse::Refused {
                request_id: request_id.clone(),
                refusal: RunsRefusal::UnknownRun,
            });
        };
        // THE LIFECYCLE COMES FROM THE RUN'S OWN DURABLE SPOOL.
        //
        // The index holds a state and a last sequence; it does not hold the
        // events. Those live in the runner's hash-chained spool, one directory
        // per run, written by the execution lane's worker.
        //
        // A row still at `ready` and sequence zero has no spool to read, and
        // `LifecycleCoverage` makes that a statement rather than an omission:
        // `complete` with an empty lifecycle is only coherent for exactly that
        // row, which is what a run whose events do not exist is.
        if record.spool_state == RunSpoolState::Ready && record.last_sequence == 0 {
            let view = RunDetailView::new(
                self.summary(record)?,
                record.last_sequence,
                Vec::new(),
                LifecycleCoverage::Complete,
            )
            .map_err(runs_refused)?
            .with_provenance(run_detail_provenance(record)?);
            return Ok(RunsResponse::RunDetail {
                request_id: request_id.clone(),
                view,
            });
        }
        // THE SPOOL IS THE AUTHORITY FOR A ROW THAT HAS MOVED.
        //
        // The index row is a *writer's last report*; the spool is what the run
        // wrote. They can disagree in exactly one direction — a worker that
        // reached a terminal event and then failed to advance the row — and a
        // view that carried the spool's events beside the row's state would be
        // refused by `RunDetailView` for contradicting itself. So the state,
        // the last sequence and the events all come from the one place, and the
        // summary is rebuilt on it.
        let (lifecycle, state) = self.lifecycle(&record.run_id)?;
        let last_sequence = lifecycle.last().map_or(0, |event| event.sequence());
        let (carried, coverage) = if lifecycle.len() > MAX_LIFECYCLE_EVENTS {
            // A truncated view carries a *prefix*, not a tail: `resume_cursor`
            // is exclusive and a subscriber resumes from it, so the events this
            // view omits must be the ones after the last carried sequence.
            (
                lifecycle[..MAX_LIFECYCLE_EVENTS].to_vec(),
                LifecycleCoverage::Truncated,
            )
        } else {
            (lifecycle, LifecycleCoverage::Complete)
        };
        let view = RunDetailView::new(
            self.summary_in_state(record, state)?,
            last_sequence,
            carried,
            coverage,
        )
        .map_err(runs_refused)?
        .with_provenance(run_detail_provenance(record)?);
        Ok(RunsResponse::RunDetail {
            request_id: request_id.clone(),
            view,
        })
    }

    /// Read one run's durable lifecycle skeleton out of its spool.
    ///
    /// # Why this can refuse a live run
    ///
    /// [`Spool::open`] takes an **exclusive** `flock` for as long as the handle
    /// exists, and the execution lane's backend holds exactly that lock for the
    /// whole of an attempt. So a detail read of a run that is running right now
    /// cannot open its spool, and this refuses rather than answering.
    ///
    /// That is a real gap and it is named rather than papered over. The two
    /// alternatives were both worse: parsing the event file behind the lock
    /// would be a second reader of a record whose writer is mid-append, and
    /// synthesising a placeholder event would put a lifecycle in the answer
    /// that no run ever wrote. Closing it properly needs a read-only spool
    /// opener in the runner, which this lane may not add. Until then a live
    /// run is listed by [`Daemon::list_runs`] — which never touches a spool —
    /// and read in full once it has ended.
    /// Re-opening also re-verifies the spool's hash chain, so an answer built
    /// here is an answer built from a record that was intact when it was read.
    fn lifecycle(&self, run_id: &str) -> Result<(Vec<RunLifecycleEvent>, RunState), DaemonError> {
        let unavailable = || DaemonError::ProtocolRefused("run_lifecycle_unavailable");
        // The lane owns the directory layout, so the read asks it rather than
        // rebuilding the path. A daemon whose lane has been consumed is one
        // that is shutting down, and it answers no reads.
        let root = self
            .execution
            .as_ref()
            .ok_or_else(unavailable)?
            .spool_root(run_id);
        let spool = Spool::open(&root, run_id, MAX_READ_SPOOL_BYTES).map_err(|_| unavailable())?;
        let events = spool.events_after(0).map_err(|_| unavailable())?;
        let mut lifecycle = Vec::with_capacity(events.len());
        for event in &events {
            let at = i64::try_from(event.at_millis())
                .map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))?;
            lifecycle.push(
                RunLifecycleEvent::new(
                    event.sequence(),
                    automonique_protocol::primitives::EpochMillis::from_millis(at),
                    lifecycle_kind(event.kind()),
                    lifecycle_authority(event.authority()),
                )
                .map_err(runs_refused)?,
            );
        }
        Ok((lifecycle, spool_run_state(spool.status().state())))
    }

    /// Join one index row against the custody it derives from.
    ///
    /// The index knows the run's state; the submission log knows the digest
    /// the daemon verified and the instant it accepted. A summary is the pair,
    /// and this is the join `runs_api` names as the seam it left open.
    ///
    /// An index row whose submission is absent is refused rather than skipped.
    /// Skipping would shorten a page without saying so, which is the silent
    /// drop the whole retention rule exists to prevent; refusing makes a
    /// broken read model visible on the first read instead of on none.
    fn summary(&self, record: &RunIndexRecord) -> Result<RunSummary, DaemonError> {
        self.summary_in_state(record, run_state(record.spool_state))
    }

    /// [`Daemon::summary`], with the run state supplied rather than read off the
    /// index row.
    ///
    /// The one caller that supplies it is [`Daemon::run_detail`], which has just
    /// read the run's own spool and must not present a view whose summary
    /// contradicts the events beside it. Every other field still comes from the
    /// row and the custody it derives from.
    fn summary_in_state(
        &self,
        record: &RunIndexRecord,
        state: RunState,
    ) -> Result<RunSummary, DaemonError> {
        let entry = self
            .run_submissions
            .run_submissions(&record.run_id)
            .map_err(|error| DaemonError::RunSubmissionFailed(error.category()))?
            .into_iter()
            .find(|entry| entry.submission_id == record.submission_id)
            .ok_or(DaemonError::RunIndexFailed("run_index_dangling_row"))?;
        // The digest is the column the daemon wrote after verifying it against
        // the document bytes at acceptance. It is re-parsed, not re-computed:
        // re-hashing every stored document on every page would make a listing
        // a custody audit, which is a different operation with a different
        // cost, and this read does not claim to have performed one.
        let spec_digest: Sha256Digest = format!("{ALGORITHM}:{}", entry.spec_digest)
            .parse()
            .map_err(|_| DaemonError::RunSubmissionFailed("corrupt"))?;
        RunSummary::new(
            RunId::new(&record.run_id)
                .map_err(|_| DaemonError::RunIndexFailed("run_index_run_id_ungrammatical"))?,
            checked_row_id(record.submission_id)?,
            spec_digest,
            state,
            submission_state(entry.state),
            automonique_protocol::primitives::EpochMillis::from_millis(entry.accepted_at_ms),
        )
        .map_err(runs_refused)
    }

    /// The window of submission identities the index still holds, and the
    /// highest index position it holds them at.
    ///
    /// Both bounds are read from the index rather than assumed: nothing
    /// deletes today, so the floor is the first row ever registered, but a
    /// later retention policy would move it and this keeps saying something
    /// true when it does.
    ///
    /// `None` when the index is empty, which is a different answer than a
    /// window and is treated as one by the caller.
    fn retained_runs(&self) -> Result<Option<RetainedRuns>, DaemonError> {
        let Some(window) = self.run_index.retained_range().map_err(index_failed)? else {
            return Ok(None);
        };
        let first = self.submission_after(window.first.saturating_sub(1))?;
        let last = self.submission_after(window.last.saturating_sub(1))?;
        Ok(Some(RetainedRuns {
            window: RetainedRange::new(first, last)
                .map_err(|_| DaemonError::RunIndexFailed("run_index_inverted_window"))?,
            last_index: window.last,
        }))
    }

    /// The submission identity of the first row above an exclusive index
    /// cursor.
    fn submission_after(&self, cursor: u64) -> Result<u64, DaemonError> {
        let page = self.run_index.page(cursor, 1).map_err(index_failed)?;
        let record = page
            .entries
            .first()
            .ok_or(DaemonError::RunIndexFailed("run_index_row_missing"))?;
        checked_row_id(record.submission_id)
    }

    /// The exclusive index cursor a page beginning at submission `from` starts
    /// after.
    ///
    /// The listing's cursor is a *submission* identity, because that is what a
    /// `RunCursor` names and what `RunListPage` orders by. The store pages by
    /// `index_id`. The two agree in order — rows are registered in submission
    /// order, and nothing back-fills — but they are not the same number, so
    /// one has to be translated into the other.
    ///
    /// The translation is a binary search over index positions, which costs at
    /// most sixteen single-row reads against a full 65 536-row index and none
    /// at all in the common case of a listing that starts at the floor. A scan
    /// would also be correct and would cost the whole table; a
    /// submission-keyed page query in the store would cost nothing and is
    /// where this belongs when that store grows one.
    fn index_cursor_below(&self, from: u64, retained: &RetainedRuns) -> Result<u64, DaemonError> {
        if from <= retained.window.first() {
            return Ok(0);
        }
        // Invariant: every row at or below `low` carries a submission below
        // `from`, and the row above `high` — if any — carries one at or above
        // it. `high` starts at the last index position, where the invariant
        // holds because there is no row above it.
        let mut low = 0;
        let mut high = retained.last_index;
        while low < high {
            let middle = low + (high - low) / 2;
            if self.submission_after(middle)? >= from {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        Ok(low)
    }

    /// Start one run already in custody, or stop one that is running.
    ///
    /// # This is the lane that acts
    ///
    /// Every other handler on this socket ends at a durable row and says so.
    /// This one starts a contained process, so it is gated by everything the
    /// intake arms are gated by *and* by everything
    /// [`execute::ExecutionLane`] refuses on:
    ///
    /// - **Fenced**, like every arm: a daemon that has lost its generation must
    ///   not start work on state another generation now owns.
    /// - **Closed by a degraded generation and by an operator pause.** Unlike
    ///   the Runs read lane, and unlike the Automation and Approval control
    ///   lanes, this one takes the intake gates. Those lanes were left open
    ///   because reading what is held, and withdrawing something from service,
    ///   are what an operator repairing a generation needs to do. Starting a
    ///   process is the opposite: an operator who closed intake wants no new
    ///   work beginning, and a submission already in custody is still new work
    ///   the moment somebody asks for it to run.
    ///
    /// # Cancellation takes the fence and not the intake gates
    ///
    /// `cancel_run` is fenced identically — a daemon that lost its generation
    /// must not reach into another generation's work — but it is **not** gated
    /// on `paused` or `degraded`, and the reason is the same one that leaves
    /// the read and control lanes open. An operator who closed intake, or whose
    /// generation is awaiting reconciliation, still needs to stop what is
    /// already running; that is precisely the repair the pause was taken for.
    /// Refusing a cancel because intake is closed would make the pause a
    /// hazard.
    ///
    /// # What an accepted answer means
    ///
    /// One attempt was started. It is running when the answer is written, so
    /// the answer carries no outcome — [`Daemon::handle_runs`] is where one is
    /// observed, once the worker has advanced the read model. A refusal means
    /// nothing was started and nothing was written.
    ///
    /// A `cancel_result` means one cancellation request reached the durable
    /// ledger. It does not mean a process exited; see
    /// [`Daemon::cancel_run`].
    fn handle_execute(
        &mut self,
        stream: &mut UnixStream,
        request: &ExecuteRequest,
    ) -> Result<(), DaemonError> {
        let now_ms = unix_millis()?;
        let snapshot = self.store.status_snapshot_at(GENERATION_ID, now_ms)?;
        let generation = snapshot.generation().ok_or(StoreError::StaleEpoch)?;
        if generation.holder_id() != self.instance_id.as_str()
            || generation.lease_epoch() != self.lease_epoch
            || generation.lease_expires_ms() != self.lease_expires_ms
            || generation.lease_expires_ms() <= snapshot.lease_observed_boottime_ms()
        {
            return Err(DaemonError::Store(StoreError::StaleEpoch));
        }
        let degraded =
            self.reconciliation_run_id.is_some() || snapshot_requires_reconciliation(&snapshot);
        let paused = self.store.intake_paused(GENERATION_ID, now_ms)?.is_some();

        let response = match request {
            ExecuteRequest::ExecuteRun { request_id, run_id } => {
                let started = if self.disconnected_recovery {
                    Err(ExecuteRefusal::ExecutionUnavailable)
                } else {
                    self.start_run(run_id, degraded, paused, now_ms)
                };
                match started {
                    Ok(submission_id) => {
                        ExecuteResponse::accepted(request_id.clone(), run_id.clone(), submission_id)
                            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?
                    }
                    Err(refusal) => ExecuteResponse::Refused {
                        request_id: request_id.clone(),
                        refusal,
                    },
                }
            }
            ExecuteRequest::CancelRun {
                request_id,
                run_id,
                request_ref,
                observed_sequence,
            } => match self.cancel_run(run_id, request_ref.as_str(), *observed_sequence, now_ms) {
                Ok(outcome) => ExecuteResponse::Cancelled {
                    request_id: request_id.clone(),
                    run_id: run_id.clone(),
                    outcome,
                },
                Err(refusal) => ExecuteResponse::Refused {
                    request_id: request_id.clone(),
                    refusal,
                },
            },
        };
        let response = response
            .to_message()
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?
            .to_canonical_bytes();
        let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + response.len());
        encode_frame(&response, &mut frame)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?;
        stream.write_all(&frame)?;
        stream.flush()?;
        Ok(())
    }

    /// Resolve one run identity to the exact document and read-model row an
    /// attempt would run, and hand both to the lane.
    ///
    /// The join is the same one [`Daemon::summary`] performs, and it is
    /// performed for the same reason: the index says which submission is the
    /// run's most recent, and custody holds that submission's bytes. A lane
    /// handed a document from one row and a revision from another would advance
    /// the wrong row on terminal.
    ///
    /// # The approval gate lives here, and here only
    ///
    /// This is the one choke point every launch passes, so it is where the
    /// composed approval requirement is consulted — after the run resolves to
    /// the exact document that would run, because the thing being approved is
    /// that document and not the identifier that names it. Putting the check in
    /// the CLI or a chat bridge would make it advisory; putting it after the
    /// lane starts would make it a report.
    ///
    /// A granted approval is re-checked against the launch context it was
    /// bound to before it admits anything; see
    /// [`Daemon::verify_approved_context`] for which drift that closes and
    /// which it leaves open.
    ///
    /// # Errors
    ///
    /// Returns the [`ExecuteRefusal`] the caller is owed. A store failure is
    /// [`ExecuteRefusal::ExecutionUnavailable`] rather than a daemon error: the
    /// caller asked whether their run could start, and "this daemon's own state
    /// would not answer" is a truthful no rather than a dropped connection.
    fn start_run(
        &mut self,
        run_id: &RunId,
        degraded: bool,
        paused: bool,
        now_ms: i64,
    ) -> Result<u64, ExecuteRefusal> {
        if degraded {
            return Err(ExecuteRefusal::GenerationDegraded);
        }
        if paused {
            return Err(ExecuteRefusal::IntakePaused);
        }
        let records = self
            .run_index
            .by_run_id(run_id.as_str())
            .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?;
        let record = records.last().ok_or(ExecuteRefusal::UnknownRun)?;
        // A row that has already moved is not startable, and saying so is what
        // makes "one attempt per submission" enforceable across restarts rather
        // than only within one process's live set.
        if record.spool_state != RunSpoolState::Ready || record.last_sequence != 0 {
            return Err(ExecuteRefusal::RunNotReady);
        }
        let entry = self
            .run_submissions
            .run_submissions(&record.run_id)
            .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?
            .into_iter()
            .find(|entry| entry.submission_id == record.submission_id)
            .ok_or(ExecuteRefusal::ExecutionUnavailable)?;
        let submission_id =
            u64::try_from(entry.submission_id).map_err(|_| ExecuteRefusal::ExecutionUnavailable)?;
        self.admit_approval(&record.run_id, &entry.spec_digest, &entry.document, now_ms)?;
        self.execution
            .as_mut()
            .ok_or(ExecuteRefusal::ExecutionUnavailable)?
            .start(&entry.document, record.submission_id, record.revision)?;
        Ok(submission_id)
    }

    /// Expire what timed out, and remind about what has not.
    ///
    /// # An expiry is not a denial, and this is where that is enforced
    ///
    /// A proposal that reached its deadline unanswered moves to `expired` and
    /// the sweep appends an audit record whose outcome is `timeout`. It
    /// deliberately does **not** write a decision. A denial names a decider,
    /// and there was none: nobody answered. Forging one would put an operator's
    /// name on a silence, and every later reader — the audit chain, the ledger,
    /// the `by_subject` history — would show a refusal that no person made.
    /// The distinction survives in the vocabulary, which is why the audit
    /// outcome set has `timeout` at all.
    ///
    /// The launch this stopped is not left ambiguous by that choice: an expired
    /// proposal leaves its subject *undecided*, so the next request for the
    /// same document raises a fresh proposal rather than inheriting an answer.
    ///
    /// # Fenced, bounded, and idempotent
    ///
    /// Every transition is the store's single fenced `UPDATE`, so a proposal
    /// somebody decided a millisecond before the sweep reached it fails the
    /// fence and keeps their answer. A second sweep over the same row writes
    /// nothing for the same reason. The batch is bounded because this runs on
    /// the accept loop.
    ///
    /// # Reminders ride the durable outbox
    ///
    /// A notice is *staged*, never sent: the sweep enqueues it and the Telegram
    /// bridge's existing drain delivers it under the existing lease, retry and
    /// rate-limit budget. The outbox's own unique intent key is the ladder's
    /// memory — one row per proposal per rung, ever — so no column has to
    /// remember which notices went out and a sweep that runs every thirty
    /// seconds does not send a reminder every thirty seconds.
    ///
    /// A proposal decided between staging and delivery still delivers its
    /// notice. That race is real and it is the cheap side of the trade: a
    /// reminder about a just-answered question is noise, and the alternative —
    /// re-reading the proposal inside the delivery path — would put approval
    /// state on the poller thread to save an occasional message.
    fn tick_approvals(&mut self, now_ms: i64) -> Result<(), DaemonError> {
        let due = self
            .approval_requests
            .expiring_before(now_ms, APPROVAL_SWEEP_BATCH)
            .map_err(|error| DaemonError::ApprovalRequestsFailed(error.category()))?;
        for record in due {
            match self
                .approval_requests
                .expire(&record.request_key, record.revision, now_ms)
            {
                Ok(_) => self.append_approval_record(
                    &record.subject,
                    APPROVAL_SWEEPER,
                    "approval_expired",
                    AuditOutcome::Timeout,
                    now_ms,
                ),
                // Somebody answered between the read and the write. Their
                // answer stands and this sweep has nothing to record.
                Err(ApprovalRequestError::StaleRevision) => {}
                Err(error) => {
                    return Err(DaemonError::ApprovalRequestsFailed(error.category()));
                }
            }
        }
        self.stage_approval_notices(now_ms)
    }

    /// Stage the reminder and escalation notices that have come due.
    ///
    /// Silent when no operator surface can carry one: a notice staged for a bot
    /// with no poller is a row nothing will ever claim, and filling the outbox
    /// with them would turn a missing surface into a backlog.
    fn stage_approval_notices(&mut self, now_ms: i64) -> Result<(), DaemonError> {
        let Some((bot_id, audience)) = self.telegram.notice_targets() else {
            return Ok(());
        };
        if audience.is_empty() {
            return Ok(());
        }
        let audience: Vec<i64> = audience.to_vec();
        let pending = self
            .approval_requests
            .pending(APPROVAL_SWEEP_BATCH)
            .map_err(|error| DaemonError::ApprovalRequestsFailed(error.category()))?;
        for record in pending {
            let lifetime = self.approval_lifetime;
            for (rung, due_at) in [
                ("reminder", lifetime.reminder_at(record.requested_at_ms)),
                ("escalation", lifetime.escalation_at(record.requested_at_ms)),
            ] {
                if now_ms < due_at {
                    continue;
                }
                let text = approval_notice_text(rung, &record.request_key);
                let mut staged = false;
                for chat_id in &audience {
                    let intent_key = format!(
                        "telegram:{bot_id}:approval:{}:{rung}:{chat_id}",
                        record.request_key
                    );
                    // The notice carries its own buttons: an operator who is
                    // reminded should be able to answer where they were
                    // reminded, without retyping a reference they were shown.
                    let Some(payload) = telegram_bridge::telegram_notice_payload(
                        *chat_id,
                        &text,
                        Some(&record.request_key),
                    ) else {
                        continue;
                    };
                    let receipt = self
                        .store
                        .enqueue_outbox(automonique_store::OutboxEnqueue {
                            intent_key: &intent_key,
                            kind: telegram_bridge::TELEGRAM_SEND_KIND,
                            payload: &payload,
                            generation_id: GENERATION_ID,
                            holder_id: self.instance_id.as_str(),
                            lease_epoch: self.lease_epoch,
                            now_ms,
                        })?;
                    staged |= !receipt.duplicate;
                }
                // One record per rung per proposal, not one per recipient and
                // not one per sweep: the outbox's unique key already decided
                // whether this rung is new, and the audit chain records the
                // rung rather than the fan-out.
                if staged {
                    self.append_approval_record(
                        &record.subject,
                        APPROVAL_SWEEPER,
                        &format!("approval_{rung}"),
                        AuditOutcome::Escalated,
                        now_ms,
                    );
                }
            }
        }
        Ok(())
    }

    /// Consult the composed approval requirement for one custodied document.
    ///
    /// The subject an approval is about is the *document*, spelled
    /// `runspec:<spec_digest>`, not the run identifier: two runs of the same
    /// bytes are the same thing to approve, and one run resubmitted with
    /// different bytes is not.
    ///
    /// # What each answer costs
    ///
    /// A refusal writes nothing except an audit record, and the record is
    /// appended *after* the decision it describes, per the audit chain's own
    /// ordering rule. `Proceed` writes nothing at all: an action that never
    /// required approval must not acquire a durable footprint from the lane
    /// that would have gated it.
    ///
    /// # Errors
    ///
    /// The [`ExecuteRefusal`] the composed policy produced. A host that cannot
    /// enforce the sandbox is reported as [`ExecuteRefusal::SandboxUnenforceable`]
    /// rather than as an approval refusal, because that is the word the lane
    /// already uses for it and two spellings for one fact would be worse than
    /// the extra arm here.
    fn admit_approval(
        &mut self,
        run_id: &str,
        spec_digest: &str,
        document: &[u8],
        now_ms: i64,
    ) -> Result<(), ExecuteRefusal> {
        // No per-call source exists on the execute lane: the request carries a
        // run identifier and nothing else, so the call asks for no ceremony of
        // its own and the composition is over the other two.
        let sources = self.approval_sources(ApprovalRequirement::Allowed);
        let subject = format!("runspec:{spec_digest}");
        let history = self
            .approval_requests
            .by_subject(&subject)
            .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?;
        let refusal = match automonique_policy::approval::decide(
            sources,
            self.operator_surfaces(),
            evidence_of(&history),
        ) {
            ApprovalGate::Proceed => {
                // Only a launch that *needed* an approval has an approved
                // context to have drifted from. A composition that permits it
                // outright must not acquire a second admission gate from a lane
                // it does not belong to, so the re-check is inside the arm the
                // requirement reached rather than outside it.
                if sources.compose() != ApprovalRequirement::ApprovalRequired {
                    return Ok(());
                }
                match self.verify_approved_context(&history, spec_digest, document) {
                    Ok(()) => return Ok(()),
                    Err(refusal) => refusal,
                }
            }
            ApprovalGate::Refuse(ApprovalPolicyRefusal::Forbidden) => {
                if sources.host() == ApprovalRequirement::Forbidden {
                    ExecuteRefusal::SandboxUnenforceable
                } else {
                    ExecuteRefusal::ApprovalForbidden
                }
            }
            ApprovalGate::Refuse(ApprovalPolicyRefusal::ApprovalDenied) => {
                ExecuteRefusal::ApprovalDenied
            }
            ApprovalGate::Refuse(ApprovalPolicyRefusal::ApprovalUnreachable) => {
                ExecuteRefusal::ApprovalUnreachable
            }
            // A live surface exists and nobody has decided. Put the question in
            // front of them — or find the one already there — and refuse this
            // launch until it is answered.
            ApprovalGate::Propose => {
                self.propose_approval(run_id, &subject, spec_digest, document, &history, now_ms)?
            }
        };
        self.record_approval_audit(&subject, refusal, now_ms);
        Err(refusal)
    }

    /// Re-check that the launch context still matches the one approved.
    ///
    /// # The window this closes
    ///
    /// An operator approves a *document*, and between that moment and the
    /// launch every one of the five things the document resolves to can change:
    /// the bytes in custody, the path the program is pinned at, the bytes
    /// behind that path, the bytes in the prompt slot, and the working
    /// directory the run is placed in. Comparing all five against what was
    /// bound at proposal time closes **approval → admission** drift: an
    /// approval granted for one launch cannot be spent on a different one.
    ///
    /// The runner separately closes **admission → exec** drift: the launch
    /// frame carries the approved executable digest, and the entry helper
    /// copies, hashes, seals, and `execveat`s one descriptor without resolving
    /// the path again. A changed path is either a digest refusal or irrelevant
    /// to the immutable bytes executed.
    ///
    /// # Why this is not the provider-pin check
    ///
    /// The execution lane already hashes the pinned program and compares it to
    /// the document's own pin, refusing
    /// [`ExecuteRefusal::ProviderBinaryUnverified`]. That answers "this
    /// document does not describe this binary". This one answers "this binary
    /// is not the one that was approved", which is a different fact with a
    /// different remedy: the first is a bad document, and the second is a
    /// document whose world moved and needs a fresh decision. Two checks, two
    /// refusals, and neither is derivable from the other.
    ///
    /// # Errors
    ///
    /// [`ExecuteRefusal::ApprovalContextDrift`] naming the first bound field
    /// that differs, in the order [`ApprovalContextField::ALL`] declares.
    /// Nothing is started and nothing is written but the audit record its
    /// caller appends.
    fn verify_approved_context(
        &self,
        history: &[ApprovalRequestRecord],
        spec_digest: &str,
        document: &[u8],
    ) -> Result<(), ExecuteRefusal> {
        // The newest granted proposal is the one the policy admitted this
        // launch under, so it is the one whose binding has to still hold.
        let Some(approved) = history
            .iter()
            .rev()
            .find(|record| record.state == ApprovalState::Granted)
        else {
            return Ok(());
        };
        let spec = RunSpec::from_canonical_bytes(document)
            .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?;
        let program_path = spec
            .executable()
            .to_str()
            .ok_or(ExecuteRefusal::ProviderBinaryUnverified)?;
        // Observed now, by the same reads the proposal was bound with. A
        // program or prompt that cannot be observed at all is not "unchanged":
        // it is the lane's own refusal, and it is answered as one.
        let (program_sha256, prompt_sha256) =
            execute::approval_context_digests(&self.state_dir, &spec)
                .ok_or(ExecuteRefusal::ProviderBinaryUnverified)?;
        let observed = ApprovalContext {
            spec_digest,
            program_path,
            program_sha256: &program_sha256,
            prompt_sha256: &prompt_sha256,
            cwd_token: spec.cwd_token().as_str(),
        };
        match approved_context_drift(&approved.context, observed) {
            None => Ok(()),
            Some(field) => Err(ExecuteRefusal::ApprovalContextDrift { field }),
        }
    }

    /// Create the proposal this launch is waiting on, or report the open one.
    ///
    /// Create-or-report, never create-again: a run asked for twice while its
    /// proposal is open earns the same refusal twice and leaves one question in
    /// front of the operator. A row that expired without an answer is not
    /// reopened — it is terminal — so this mints a *fresh* key beside it, which
    /// is what makes re-proposal structurally distinct from revival.
    ///
    /// # Errors
    ///
    /// [`ExecuteRefusal::ApprovalRequired`] is the success path: it says the
    /// proposal is durable and the launch did not happen. A context that cannot
    /// be observed at all is [`ExecuteRefusal::ProviderBinaryUnverified`] or
    /// [`ExecuteRefusal::PromptUnresolvable`] rather than an empty binding, and
    /// a table that will not take the row is
    /// [`ExecuteRefusal::ExecutionUnavailable`].
    fn propose_approval(
        &mut self,
        run_id: &str,
        subject: &str,
        spec_digest: &str,
        document: &[u8],
        history: &[ApprovalRequestRecord],
        now_ms: i64,
    ) -> Result<ExecuteRefusal, ExecuteRefusal> {
        if history.iter().any(|record| record.is_answerable_at(now_ms)) {
            return Ok(ExecuteRefusal::ApprovalRequired);
        }
        let spec = RunSpec::from_canonical_bytes(document)
            .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?;
        let program_path = spec
            .executable()
            .to_str()
            .ok_or(ExecuteRefusal::ProviderBinaryUnverified)?
            .to_owned();
        let state_dir = self.state_dir.clone();
        let (program_sha256, prompt_sha256) = execute::approval_context_digests(&state_dir, &spec)
            .ok_or(ExecuteRefusal::ProviderBinaryUnverified)?;
        let request_key = mint_request_key(subject, run_id, spec_digest, now_ms, history.len());
        let expires_at_ms = self.approval_lifetime.expires_at(now_ms);
        self.approval_requests
            .propose(ApprovalProposal {
                request_key: &request_key,
                subject,
                run_id,
                context: ApprovalContext {
                    spec_digest,
                    program_path: &program_path,
                    program_sha256: &program_sha256,
                    prompt_sha256: &prompt_sha256,
                    cwd_token: spec.cwd_token().as_str(),
                },
                requested_by: APPROVAL_PROPOSER,
                requested_at_ms: now_ms,
                expires_at_ms,
            })
            .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?;
        Ok(ExecuteRefusal::ApprovalRequired)
    }

    /// Record one operator decision. **The only function that decides an
    /// approval**, and every surface routes through it.
    ///
    /// Telegram's `/approve` and `/deny`, Slack's slash verb and its buttons,
    /// and the CLI's approval verb all reach exactly this call — the bridges by
    /// dialling this daemon's own socket, which is the same shape cancellation
    /// uses and for the same reason. That is the whole of what makes the
    /// surfaces equal in authority: same fence, same ledger, same audit record,
    /// same answers, rather than four implementations that agree today.
    ///
    /// # The write order, and the failure it buys
    ///
    /// The ledger row is written **first** and the proposal transitioned
    /// **second**, across two databases no transaction spans. A crash between
    /// them leaves a durable decision whose proposal still reads `pending`;
    /// the next call under the same key finds the ledger row, is answered
    /// `AlreadyRecorded` — which writes nothing — and completes the transition,
    /// so the gap heals on replay. `Daemon::open` performs that same repair
    /// once for every pending row, so a generation that died mid-decision does
    /// not wait for somebody to press the button again.
    ///
    /// The other order would leave a proposal reading `granted` with no
    /// decision anywhere: a row claiming an authority no ledger backs, and
    /// nothing able to tell that it was never decided.
    ///
    /// # Authority
    ///
    /// This function records the decider it is given and does not verify one.
    /// The tier check belongs to the surface that accepted the decision — the
    /// Telegram bridge's admin tier, Slack's admin allowlist, the socket's peer
    /// admission — and each is asserted by its own test. A caller inside this
    /// process that skipped its gate would be recorded as faithfully as one
    /// that did not, which is why no surface is allowed to build one of these
    /// calls from a message body.
    ///
    /// # Errors
    ///
    /// [`ApprovalDecisionRefusal`], naming exactly one reason. Every refusal
    /// writes nothing to either database.
    pub fn record_decision(
        &mut self,
        request_key: &str,
        outcome: ApprovalOutcome,
        decider: &str,
        now_ms: i64,
    ) -> Result<ApprovalDecisionReceipt, ApprovalDecisionRefusal> {
        let record = self
            .approval_requests
            .entry(request_key)
            .map_err(|error| match error.category() {
                "invalid_field" => ApprovalDecisionRefusal::MalformedKey,
                _ => ApprovalDecisionRefusal::DecisionUnavailable,
            })?
            .ok_or(ApprovalDecisionRefusal::UnknownRequest)?;

        match record.state {
            // An expiry is the absence of an answer, so a late decision is not
            // accepted into it: the operator is told the question closed and
            // may raise a fresh one.
            ApprovalState::Expired => return Err(ApprovalDecisionRefusal::RequestExpired),
            ApprovalState::Granted | ApprovalState::Denied => {
                return self.already_decided(&record, outcome);
            }
            ApprovalState::Pending => {}
        }
        // A proposal past its deadline is answered as expired even before the
        // sweep reaches it, so the answer does not depend on sweep latency.
        if !record.is_answerable_at(now_ms) {
            return Err(ApprovalDecisionRefusal::RequestExpired);
        }

        let receipt = self
            .approvals
            .record(ApprovalDecisionRecord {
                approval_key: request_key,
                subject: &record.subject,
                decision: match outcome {
                    ApprovalOutcome::Granted => StoreApprovalDecision::Granted,
                    ApprovalOutcome::Denied => StoreApprovalDecision::Denied,
                },
                decider,
                decided_at_ms: now_ms,
            })
            .map_err(|error| match error {
                ApprovalLedgerError::Conflict {
                    recorded_decision,
                    recorded_decider,
                    ..
                } => ApprovalDecisionRefusal::AlreadyDecided {
                    outcome: if recorded_decision.grants() {
                        ApprovalOutcome::Granted
                    } else {
                        ApprovalOutcome::Denied
                    },
                    decider: recorded_decider,
                },
                ApprovalLedgerError::LedgerFull { .. } => ApprovalDecisionRefusal::LedgerFull,
                _ => ApprovalDecisionRefusal::DecisionUnavailable,
            })?;

        match self.approval_requests.decide(
            request_key,
            record.revision,
            outcome,
            request_key,
            now_ms,
        ) {
            Ok(_) => {}
            // Somebody else moved the row between the read and the write. The
            // ledger is write-once, so whatever they recorded is what happened;
            // re-read and report theirs rather than claiming this call's.
            Err(ApprovalRequestError::StaleRevision) => {
                let current = self
                    .approval_requests
                    .entry(request_key)
                    .map_err(|_| ApprovalDecisionRefusal::DecisionUnavailable)?
                    .ok_or(ApprovalDecisionRefusal::UnknownRequest)?;
                return self.already_decided(&current, outcome);
            }
            Err(_) => return Err(ApprovalDecisionRefusal::DecisionUnavailable),
        }

        self.record_decision_audit(&record.subject, outcome, decider, now_ms);
        Ok(ApprovalDecisionReceipt {
            entry_id: receipt.entry_id,
            request_key: request_key.to_owned(),
            subject: record.subject,
            run_id: record.run_id,
            outcome,
            decider: decider.to_owned(),
            decided_at_ms: receipt.decided_at_ms,
            disposition: match receipt.disposition {
                StoreApprovalDisposition::Recorded => ApprovalDecisionDisposition::Recorded,
                StoreApprovalDisposition::AlreadyRecorded => {
                    ApprovalDecisionDisposition::AlreadyRecorded
                }
            },
        })
    }

    /// Answer a caller whose proposal already carries a decision.
    ///
    /// An exact retry — same reference, same answer — is a *success* carrying
    /// the first decision's receipt, because that is what the caller asked for
    /// and it is already true. That is what makes a double-clicked button one
    /// decision and two acknowledgements. A different answer is a refusal
    /// naming what stands, so an operator who denied an already-granted
    /// proposal learns which answer won rather than seeing their own echoed
    /// back.
    ///
    /// The decider and the row identity come from the **ledger**, not from the
    /// proposal row: the proposal records that a decision happened, and the
    /// ledger records who made it. Reporting this call's own actor as the
    /// earlier decider would be a lie about who answered.
    fn already_decided(
        &self,
        record: &ApprovalRequestRecord,
        outcome: ApprovalOutcome,
    ) -> Result<ApprovalDecisionReceipt, ApprovalDecisionRefusal> {
        let recorded = match record.state {
            ApprovalState::Granted => ApprovalOutcome::Granted,
            ApprovalState::Denied => ApprovalOutcome::Denied,
            // Only the two decided states reach here: an expiry is refused
            // earlier and a pending row is not decided at all.
            ApprovalState::Pending | ApprovalState::Expired => {
                return Err(ApprovalDecisionRefusal::DecisionUnavailable);
            }
        };
        let entry = record
            .approval_key
            .as_deref()
            .and_then(|key| self.approvals.entry(key).ok().flatten())
            .ok_or(ApprovalDecisionRefusal::DecisionUnavailable)?;
        if recorded != outcome {
            return Err(ApprovalDecisionRefusal::AlreadyDecided {
                outcome: recorded,
                decider: entry.decider,
            });
        }
        Ok(ApprovalDecisionReceipt {
            entry_id: entry.entry_id,
            request_key: record.request_key.clone(),
            subject: record.subject.clone(),
            run_id: record.run_id.clone(),
            outcome: recorded,
            decider: entry.decider,
            decided_at_ms: entry.decided_at_ms,
            disposition: ApprovalDecisionDisposition::AlreadyRecorded,
        })
    }

    /// Append one `approval` record for a decision that was just recorded.
    ///
    /// Silent on failure for the reason [`Daemon::record_cancellation_audit`]
    /// gives, and written *after* the decision for the reason the audit chain's
    /// own header gives: a decision with no audit record is a detectable gap,
    /// and an audit record for a decision nobody made is a false claim nothing
    /// can detect.
    fn record_decision_audit(
        &mut self,
        subject: &str,
        outcome: ApprovalOutcome,
        decider: &str,
        now_ms: i64,
    ) {
        self.append_approval_record(
            subject,
            decider,
            "automonique.approval",
            match outcome {
                ApprovalOutcome::Granted => AuditOutcome::Success,
                ApprovalOutcome::Denied => AuditOutcome::Denied,
            },
            now_ms,
        );
    }

    /// Append one `approval` record for a launch the composed policy stopped.
    ///
    /// Silent on failure, for the reason
    /// [`Daemon::record_cancellation_audit`] gives: the refusal has already
    /// been decided and is about to be returned, and turning a failed append
    /// into a different answer would misreport what happened. A missing record
    /// beside a refusal is a detectable gap; a refusal turned into a start is
    /// not detectable at all.
    fn record_approval_audit(&mut self, subject: &str, refusal: ExecuteRefusal, now_ms: i64) {
        // The actor is the socket's peer, which this lane models as the local
        // operator and nothing finer: the execute lane carries no actor, so
        // claiming a name here would be inventing one.
        self.append_approval_record(
            subject,
            "local-peer",
            refusal.as_str(),
            // Every answer this records is a launch that did not happen.
            AuditOutcome::Denied,
            now_ms,
        );
    }

    /// Append one `approval` record to the hash-chained audit log.
    ///
    /// One builder for every approval-category record this daemon writes, so
    /// the refusal path and the decision path cannot drift into two shapes of
    /// the same claim. Failure is silent: the thing being recorded has already
    /// happened by the time this runs.
    fn append_approval_record(
        &mut self,
        subject: &str,
        actor: &str,
        surface: &str,
        outcome: AuditOutcome,
        now_ms: i64,
    ) {
        let (Ok(head), Some(recorded_at)) = (
            self.audit_chain.head(),
            telegram_bridge::utc_rfc3339_from_unix_millis(now_ms),
        ) else {
            return;
        };
        let (seq, prev_hash) = head.map_or_else(
            || (1, GENESIS_PREV_HASH.to_owned()),
            |head| (head.seq.saturating_add(1), head.record_hash),
        );
        let Ok(record) = AuditRecord::link(
            seq,
            &prev_hash,
            AuditEvent {
                recorded_at: &recorded_at,
                actor,
                surface,
                category: AuditCategory::Approval,
                subject,
                outcome,
            },
        ) else {
            return;
        };
        let record_id = record.record_id();
        let body = record.to_canonical_bytes();
        let record_hash = record.record_hash();
        let _ = self.audit_chain.append(AuditAppend {
            record_id: &record_id,
            recorded_at: record.recorded_at(),
            actor: record.actor(),
            surface: record.surface(),
            category: record.category().as_str(),
            subject: record.subject(),
            outcome: record.outcome().as_str(),
            body: &body,
            prev_hash: record.prev_hash(),
            record_hash: &record_hash,
        });
    }

    /// Deliver one cancellation request to the live attempt a run has.
    ///
    /// This is the *only* function that cancels a run, and every surface routes
    /// through it: the admin socket's `cancel_run`, the CLI's `cancel` verb, and
    /// the Telegram bridge's `/cancel`. That is the whole of what makes the
    /// three equal in authority — same fence, same resolution, same ledger,
    /// same answers — rather than three implementations that agree today.
    ///
    /// # Resolving a run to an attempt
    ///
    /// The dispatcher keys on `attempt_id` and an operator types a run
    /// reference, so the identity is resolved through the same walk
    /// [`Daemon::start_run`] performs — index row, custody row, then
    /// [`RunSpec::from_canonical_bytes`] for the document's own `attempt_id`.
    ///
    /// The document is **decoded**, never derived. This daemon's own composer
    /// mints an attempt identifier as a function of the run identifier, so
    /// deriving one would work for every run this daemon composed and silently
    /// cancel the wrong thing — or nothing — for a document submitted from
    /// outside. The identity an attempt was registered under is the one written
    /// in the document it was started from, and that is the one read here.
    ///
    /// # What the answer means
    ///
    /// [`CancelRunOutcome::Delivered`] says the request reached the registered
    /// sink exactly once and custody now holds it. It does **not** say the
    /// process exited, that its descendants were reaped, or that the run
    /// reached a terminal state — those are the Runs lane's to report, and the
    /// dispatcher's own documentation is explicit that a delivery is delivery
    /// evidence and not exit evidence.
    ///
    /// A run with no live attempt is [`ExecuteRefusal::NoLiveAttempt`] rather
    /// than a success. A cancellation that stopped nothing must never read as
    /// one that stopped something.
    ///
    /// # Errors
    ///
    /// Returns the [`ExecuteRefusal`] the caller is owed. `now_ms` is accepted
    /// and currently unused by the delivery itself; it is threaded through so
    /// the audit record this appends carries the same instant the rest of the
    /// request was judged against rather than a second reading of the clock.
    fn cancel_run(
        &mut self,
        run_id: &RunId,
        request_ref: &str,
        observed_sequence: u64,
        now_ms: i64,
    ) -> Result<CancelRunOutcome, ExecuteRefusal> {
        let attempt_id = self.attempt_id_for(run_id)?;
        let host = self
            .attempt_host
            .as_ref()
            .ok_or(ExecuteRefusal::ExecutionUnavailable)?;
        let outcome = match host.cancel(&attempt_id, request_ref, observed_sequence) {
            DispatchOutcome::Delivered => CancelRunOutcome::Delivered,
            DispatchOutcome::AlreadyDelivered => CancelRunOutcome::AlreadyDelivered,
            DispatchOutcome::Conflict => CancelRunOutcome::Conflict,
            // No registration holds this attempt: it finished, or never
            // started. Custody was not consulted and nothing was written.
            DispatchOutcome::UnknownAttempt => return Err(ExecuteRefusal::NoLiveAttempt),
            DispatchOutcome::SinkUnavailable => return Err(ExecuteRefusal::CancelNotDelivered),
            DispatchOutcome::CustodyFull => return Err(ExecuteRefusal::LaneSaturated),
            DispatchOutcome::CustodyUnavailable => {
                return Err(ExecuteRefusal::ExecutionUnavailable);
            }
            // The direct API is reachable by callers that never parsed a wire
            // line, so the dispatcher checks spelling itself. A frame that got
            // here was already admitted, so this is a caller inside this
            // process presenting something the protocol would have refused.
            DispatchOutcome::FieldInvalid => return Err(ExecuteRefusal::AdmissionRefused),
        };
        self.record_cancellation_audit(run_id, outcome, now_ms);
        Ok(outcome)
    }

    /// Append one `cancellation` record to the hash-chained audit log.
    ///
    /// # The write order, and the failure it buys
    ///
    /// The cancellation is delivered first and recorded second, which is the
    /// order `automonique_store::audit_chain`'s header requires and for the
    /// reason it gives: a crash between the two leaves a delivery with no audit
    /// record, which is a *detectable gap* — the chain is contiguous by `seq`,
    /// so reconciling the cancel ledger against it finds one. The other order
    /// would leave a record of a cancellation that never happened, and nothing
    /// can detect that, because a record of a thing that did not happen is
    /// exactly what a record of a thing that did looks like.
    ///
    /// # Why this returns nothing
    ///
    /// A failure to append is deliberately **not** propagated. The cancellation
    /// has already been delivered and durably recorded in the cancel ledger by
    /// the time this runs; turning an audit failure into a refusal would tell
    /// the caller their cancellation did not happen when it did, which is a
    /// worse lie than a missing audit record. The gap is detectable and this is
    /// not.
    ///
    /// The record is built against the chain's current head. A concurrent
    /// append would move that head, but this daemon holds the generation lease
    /// and is the single writer, so the read and the append cannot be
    /// interleaved by another writer — and if one somehow were, the chain
    /// refuses the stale link rather than forking.
    ///
    /// `request_ref` is deliberately not a field of the record. It is the
    /// cancel ledger's idempotency key and that ledger holds it; carrying it
    /// here would put one caller-chosen value in two databases no transaction
    /// spans, for no reader. The audit chain's subject is the run.
    fn record_cancellation_audit(
        &mut self,
        run_id: &RunId,
        outcome: CancelRunOutcome,
        now_ms: i64,
    ) {
        let (Ok(head), Some(recorded_at)) = (
            self.audit_chain.head(),
            telegram_bridge::utc_rfc3339_from_unix_millis(now_ms),
        ) else {
            return;
        };
        let (seq, prev_hash) = head.map_or_else(
            || (1, GENESIS_PREV_HASH.to_owned()),
            |head| (head.seq.saturating_add(1), head.record_hash),
        );
        // The actor is the socket's peer, which this lane models as the local
        // operator and nothing finer: no lane on this socket carries an actor,
        // so claiming a name here would be inventing one.
        let record = AuditRecord::link(
            seq,
            &prev_hash,
            AuditEvent {
                recorded_at: &recorded_at,
                actor: "local-peer",
                surface: "automonique.execute",
                category: AuditCategory::Cancellation,
                subject: run_id.as_str(),
                outcome: match outcome {
                    CancelRunOutcome::Delivered | CancelRunOutcome::AlreadyDelivered => {
                        AuditOutcome::Success
                    }
                    CancelRunOutcome::Conflict => AuditOutcome::Denied,
                },
            },
        );
        let Ok(record) = record else {
            return;
        };
        let record_id = record.record_id();
        let body = record.to_canonical_bytes();
        let record_hash = record.record_hash();
        let _ = self.audit_chain.append(AuditAppend {
            record_id: &record_id,
            recorded_at: record.recorded_at(),
            actor: record.actor(),
            surface: record.surface(),
            category: record.category().as_str(),
            subject: record.subject(),
            outcome: record.outcome().as_str(),
            body: &body,
            prev_hash: record.prev_hash(),
            record_hash: &record_hash,
        });
    }

    /// Read the attempt identifier the document one run is custodied under
    /// declares.
    ///
    /// # Errors
    ///
    /// [`ExecuteRefusal::UnknownRun`] when nothing is held under that identity,
    /// and [`ExecuteRefusal::ExecutionUnavailable`] when this daemon's own
    /// state would not answer — the same mapping [`Daemon::start_run`] uses,
    /// and for the same reason.
    fn attempt_id_for(&self, run_id: &RunId) -> Result<String, ExecuteRefusal> {
        let records = self
            .run_index
            .by_run_id(run_id.as_str())
            .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?;
        let record = records.last().ok_or(ExecuteRefusal::UnknownRun)?;
        let entry = self
            .run_submissions
            .run_submissions(&record.run_id)
            .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?
            .into_iter()
            .find(|entry| entry.submission_id == record.submission_id)
            .ok_or(ExecuteRefusal::ExecutionUnavailable)?;
        let spec = RunSpec::from_canonical_bytes(&entry.document)
            .map_err(|_| ExecuteRefusal::ExecutionUnavailable)?;
        Ok(spec.attempt_id().as_str().to_owned())
    }

    /// Answer one operation on the native Automation control API.
    ///
    /// # What an accepted write here does, and what it does not
    ///
    /// It commits one row to the durable registry saying that somebody
    /// claiming to be `actor` decided this automation is, or is no longer, in
    /// service. **Nothing else happens.** This daemon has no scheduler, no
    /// trigger evaluator and no executor, so:
    ///
    /// - registering an automation starts nothing;
    /// - pausing one suppresses nothing, because nothing was running; and
    /// - resuming one resumes nothing.
    ///
    /// That is why an accepted write answers `accepted` rather than
    /// `completed`: the row is committed, and the decision the row records has
    /// not taken effect anywhere, because there is nowhere for it to take
    /// effect yet.
    ///
    /// # Fencing
    ///
    /// Fenced exactly as [`Daemon::handle_runs`] is, and for a stronger reason:
    /// this lane *writes*. A daemon that has lost its generation must not
    /// record an operator's decision into a database another generation now
    /// owns, and must not serve one out of it either.
    ///
    /// Unlike the intake arms, this is *not* closed by an operator pause or by
    /// a degraded generation. An intake pause stops the daemon taking custody
    /// of new work; withdrawing an automation from service is the opposite of
    /// taking on work, and an operator repairing a degraded generation is
    /// precisely the person who needs to pause the automations on it.
    fn handle_automation(
        &mut self,
        stream: &mut UnixStream,
        request: &AutomationRequest,
    ) -> Result<(), DaemonError> {
        let now_ms = unix_millis()?;
        let snapshot = self.store.status_snapshot_at(GENERATION_ID, now_ms)?;
        let generation = snapshot.generation().ok_or(StoreError::StaleEpoch)?;
        if generation.holder_id() != self.instance_id.as_str()
            || generation.lease_epoch() != self.lease_epoch
            || generation.lease_expires_ms() != self.lease_expires_ms
            || generation.lease_expires_ms() <= snapshot.lease_observed_boottime_ms()
        {
            return Err(DaemonError::Store(StoreError::StaleEpoch));
        }
        let response = match request {
            AutomationRequest::RegisterAutomation {
                request_id,
                registration,
            } => self.register_automation(request_id, registration, now_ms)?,
            AutomationRequest::SetEnablement {
                request_id,
                transition,
            } => self.set_enablement(request_id, transition, now_ms)?,
            AutomationRequest::ListAutomations { request_id, query } => {
                self.list_automations(request_id, query)?
            }
            AutomationRequest::AutomationDetail {
                request_id,
                automation_id,
            } => self.automation_detail(request_id, automation_id)?,
        };
        let response = response
            .to_message()
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?
            .to_canonical_bytes();
        let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + response.len());
        encode_frame(&response, &mut frame)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?;
        stream.write_all(&frame)?;
        stream.flush()?;
        Ok(())
    }

    /// Record one new automation, enabled, at revision one.
    fn register_automation(
        &mut self,
        request_id: &RequestId,
        registration: &RegisterAutomation,
        now_ms: i64,
    ) -> Result<AutomationResponse, DaemonError> {
        let receipt = match self.automations.register(AutomationRegistration {
            automation_id: registration.automation_id().as_str(),
            actor: registration.actor().as_str(),
            now_ms,
        }) {
            Ok(receipt) => receipt,
            Err(error) => return refuse_automation(request_id, &error),
        };
        Ok(AutomationResponse::Accepted {
            request_id: request_id.clone(),
            receipt: AutomationReceiptView::new(
                checked_row_id(receipt.entry_id)?,
                registration.automation_id().clone(),
                enablement_state(receipt.enablement),
                receipt.revision,
                automonique_protocol::primitives::EpochMillis::from_millis(receipt.updated_at_ms),
            )
            .map_err(automation_refused)?,
        })
    }

    /// Move one automation along the enablement lattice.
    ///
    /// The cause coupling was already decided by the protocol's own decoder —
    /// a causeless pause never reaches this function — and the store decides it
    /// again. Neither check is redundant: the first refuses a malformed request
    /// before it touches durable state, and the second refuses a malformed row
    /// without trusting us.
    fn set_enablement(
        &mut self,
        request_id: &RequestId,
        transition: &SetEnablement,
        now_ms: i64,
    ) -> Result<AutomationResponse, DaemonError> {
        let receipt = match self.automations.transition(EnablementTransition {
            automation_id: transition.automation_id().as_str(),
            expected_revision: transition.expected_revision(),
            new_enablement: store_enablement_state(transition.target()),
            actor: transition.actor().as_str(),
            cause: transition.cause().map(PauseReason::as_str),
            now_ms,
        }) {
            Ok(receipt) => receipt,
            // A stale expected revision is a `conflict`, not a `rejected`: the
            // caller's request was well-formed and the row simply moved, and
            // the two are retried differently. The durable revision travels
            // with the answer so a retry does not need a second round trip.
            Err(AutomationStoreError::RevisionMismatch { expected, durable }) => {
                return AutomationResponse::conflict(request_id.clone(), expected, durable)
                    .map_err(automation_refused);
            }
            Err(error) => return refuse_automation(request_id, &error),
        };
        Ok(AutomationResponse::Accepted {
            request_id: request_id.clone(),
            receipt: AutomationReceiptView::new(
                checked_row_id(receipt.entry_id)?,
                transition.automation_id().clone(),
                enablement_state(receipt.enablement),
                receipt.revision,
                automonique_protocol::primitives::EpochMillis::from_millis(receipt.updated_at_ms),
            )
            .map_err(automation_refused)?,
        })
    }

    /// One bounded page of automations.
    ///
    /// The wire cursor is the store's own exclusive `entry_id` position, so
    /// nothing is translated between the two coordinate spaces and there is no
    /// off-by-one to re-derive — the failure the run listing had to work around
    /// because it pages by a different key than it is cursored on.
    fn list_automations(
        &self,
        request_id: &RequestId,
        query: &ListAutomations,
    ) -> Result<AutomationResponse, DaemonError> {
        let cursor = query.since().position();
        let limit = query.page_size().get();
        let page = match query.states().states() {
            // Translated variant by variant, so a state this build cannot name
            // is a compile failure rather than a row the listing silently
            // drops.
            Some(states) => {
                let states: Vec<StoreEnablementState> =
                    states.iter().copied().map(store_enablement_state).collect();
                self.automations.page_in_states(cursor, limit, &states)
            }
            None => self.automations.page(cursor, limit),
        };
        let page = match page {
            Ok(page) => page,
            Err(error) => return refuse_automation(request_id, &error),
        };
        let mut entries = Vec::with_capacity(page.entries.len());
        for record in &page.entries {
            entries.push(automation_record(record)?);
        }
        // `next_cursor` is set only when the store saw a further *matching*
        // row, so a page shortened by the state filter still reports itself
        // complete only when nothing matching remains.
        let continuation = match page.next_cursor {
            Some(next) => AutomationContinuation::More(AutomationCursor::new(next)),
            None => AutomationContinuation::Complete,
        };
        let page = AutomationListPage::new(entries, continuation).map_err(automation_refused)?;
        AutomationResponse::listing(request_id.clone(), query, page).map_err(automation_refused)
    }

    /// One automation in full, or [`AutomationRefusal::UnknownAutomation`].
    fn automation_detail(
        &self,
        request_id: &RequestId,
        automation_id: &AutomationId,
    ) -> Result<AutomationResponse, DaemonError> {
        let record = match self.automations.entry(automation_id.as_str()) {
            Ok(Some(record)) => record,
            Ok(None) => {
                return Ok(AutomationResponse::Refused {
                    request_id: request_id.clone(),
                    refusal: AutomationRefusal::UnknownAutomation,
                });
            }
            Err(error) => return refuse_automation(request_id, &error),
        };
        Ok(AutomationResponse::AutomationDetail {
            request_id: request_id.clone(),
            record: automation_record(&record)?,
        })
    }

    /// Answer one operation on the native Approval decision API.
    ///
    /// # What an accepted write here does, and what it does not
    ///
    /// There are two writes on this lane and they are not the same thing.
    ///
    /// [`ApprovalRequest::DecideRequest`] answers a durable proposal. **That
    /// one gates**: the decision it records is the one [`Daemon::start_run`]
    /// reads before any attempt starts, so a `granted` row under an `apr-`
    /// reference admits a launch and a `denied` row refuses it. It converges on
    /// [`Daemon::record_decision`] together with every chat surface, which is
    /// what makes the CLI and the bridges equal in authority rather than three
    /// implementations that agree today.
    ///
    /// [`ApprovalRequest::RecordApproval`] writes a free-form decision under a
    /// caller-chosen key. A key that names a live proposal is routed through the
    /// same one function; a key that names nothing still writes the row it
    /// always wrote, and **that row gates nothing** — there is no proposal for
    /// it to decide and no launch bound to it.
    ///
    /// In both cases:
    ///
    /// - **The decider is not authenticated.** [`authenticate_peer`] established
    ///   that the peer is this user; that string says which person or runbook
    ///   behind that user answered, and the daemon records it verbatim.
    /// - **The decision is bound to no provider session.** That binding is
    ///   `provider_journal`'s, in a different database, under a different key.
    ///
    /// A landed write answers `accepted` rather than `completed` because the
    /// row is committed and what it authorizes has not happened yet: an
    /// approved run still has to be started, and starting it is the Execute
    /// lane's answer, not this one's.
    ///
    /// # Fencing
    ///
    /// Fenced exactly as [`Daemon::handle_automation`] is, and for the same
    /// reason: this lane writes. A daemon that has lost its generation must not
    /// record a decision into a database another generation now owns, and must
    /// not serve one out of it either.
    ///
    /// Like the automation lane and unlike the intake arms, this is *not* closed
    /// by an operator pause or by a degraded generation. An intake pause stops
    /// the daemon taking custody of new work; writing down that somebody refused
    /// something is the opposite of taking on work, and an operator repairing a
    /// degraded generation is precisely the person whose decisions most need
    /// recording.
    fn handle_approval(
        &mut self,
        stream: &mut UnixStream,
        request: &ApprovalRequest,
    ) -> Result<(), DaemonError> {
        let now_ms = unix_millis()?;
        let snapshot = self.store.status_snapshot_at(GENERATION_ID, now_ms)?;
        let generation = snapshot.generation().ok_or(StoreError::StaleEpoch)?;
        if generation.holder_id() != self.instance_id.as_str()
            || generation.lease_epoch() != self.lease_epoch
            || generation.lease_expires_ms() != self.lease_expires_ms
            || generation.lease_expires_ms() <= snapshot.lease_observed_boottime_ms()
        {
            return Err(DaemonError::Store(StoreError::StaleEpoch));
        }
        let response = match request {
            ApprovalRequest::RecordApproval {
                request_id,
                decision,
            } => self.record_approval(request_id, decision, now_ms)?,
            ApprovalRequest::ListApprovals { request_id, query } => {
                self.list_approvals(request_id, *query)?
            }
            ApprovalRequest::ApprovalDetail {
                request_id,
                approval_key,
            } => self.approval_detail(request_id, approval_key)?,
            ApprovalRequest::ApprovalsBySubject { request_id, query } => {
                self.approvals_by_subject(request_id, query)?
            }
            ApprovalRequest::DecideRequest {
                request_id,
                decision,
            } => self.decide_request(request_id, decision, now_ms)?,
        };
        let response = response
            .to_message()
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?
            .to_canonical_bytes();
        let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + response.len());
        encode_frame(&response, &mut frame)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?;
        stream.write_all(&frame)?;
        stream.flush()?;
        Ok(())
    }

    /// Record one decision, write-once.
    ///
    /// The instant is the daemon's, not the caller's: the wire carries no
    /// timestamp, so a client cannot date a decision to whenever it likes.
    ///
    /// The three answers the ledger gives are the three this lane gives. An
    /// exact replay is a *success* carrying
    /// [`ApprovalDisposition::AlreadyRecorded`] and the first recording's
    /// instant — never a refusal, because a caller that lost the answer to its
    /// first attempt must get the first answer back. A key presented with a
    /// different subject, decision or decider is the conflict, which the
    /// protocol derives from both sides rather than trusting this function's
    /// claim about which field differed.
    fn record_approval(
        &mut self,
        request_id: &RequestId,
        decision: &RecordApproval,
        now_ms: i64,
    ) -> Result<ApprovalResponse, DaemonError> {
        // A key that names a live proposal is the same decision the chat
        // surfaces make, so it takes the same path: one function, one fence,
        // one audit record. A key that names nothing is the ledger's own
        // free-form lane and still writes the row it always wrote.
        if self
            .approval_requests
            .entry(decision.approval_key().as_str())
            .ok()
            .flatten()
            .is_some()
        {
            return self.decide_request(
                request_id,
                &DecideRequest::new(
                    decision.approval_key().clone(),
                    decision.decision(),
                    decision.decider().clone(),
                ),
                now_ms,
            );
        }
        let receipt = match self.approvals.record(ApprovalDecisionRecord {
            approval_key: decision.approval_key().as_str(),
            subject: decision.subject().as_str(),
            decision: store_approval_decision(decision.decision()),
            decider: decision.decider().as_str(),
            decided_at_ms: now_ms,
        }) {
            Ok(receipt) => receipt,
            Err(ApprovalLedgerError::Conflict {
                entry_id,
                recorded_subject,
                recorded_decision,
                recorded_decider,
                ..
            }) => {
                // The ledger's own `field` is deliberately dropped: the
                // protocol re-derives it from the two decisions in hand, so
                // this daemon cannot report a field the sides agree on.
                return ApprovalResponse::conflict(
                    request_id.clone(),
                    decision,
                    RecordedApproval {
                        entry_id: checked_row_id(entry_id)?,
                        subject: ApprovalSubject::new(&recorded_subject).map_err(|_| {
                            DaemonError::ApprovalLedgerFailed("subject_ungrammatical")
                        })?,
                        decision: approval_decision(recorded_decision),
                        decider: Decider::new(&recorded_decider).map_err(|_| {
                            DaemonError::ApprovalLedgerFailed("decider_ungrammatical")
                        })?,
                    },
                )
                .map_err(approval_refused);
            }
            Err(error) => return refuse_approval(request_id, &error),
        };
        Ok(ApprovalResponse::Recorded {
            request_id: request_id.clone(),
            receipt: ApprovalReceiptView::new(
                checked_row_id(receipt.entry_id)?,
                decision.approval_key().clone(),
                decision.decision(),
                approval_disposition(receipt.disposition),
                automonique_protocol::primitives::EpochMillis::from_millis(receipt.decided_at_ms),
            )
            .map_err(approval_refused)?,
        })
    }

    /// Decide one durable proposal over the wire.
    ///
    /// A thin projection onto [`Daemon::record_decision`], which is where the
    /// ordering, the fence and the audit record live. Nothing is decided here;
    /// this arm translates one typed refusal vocabulary into another and hands
    /// back the same receipt every other surface gets.
    fn decide_request(
        &mut self,
        request_id: &RequestId,
        decision: &DecideRequest,
        now_ms: i64,
    ) -> Result<ApprovalResponse, DaemonError> {
        let outcome = match decision.decision() {
            ApprovalDecision::Granted => ApprovalOutcome::Granted,
            ApprovalDecision::Denied => ApprovalOutcome::Denied,
        };
        match self.record_decision(
            decision.request_key().as_str(),
            outcome,
            decision.decider().as_str(),
            now_ms,
        ) {
            Ok(receipt) => Ok(ApprovalResponse::Recorded {
                request_id: request_id.clone(),
                receipt: ApprovalReceiptView::new(
                    checked_row_id(receipt.entry_id)?,
                    decision.request_key().clone(),
                    decision.decision(),
                    match receipt.disposition {
                        ApprovalDecisionDisposition::Recorded => ApprovalDisposition::Recorded,
                        ApprovalDecisionDisposition::AlreadyRecorded => {
                            ApprovalDisposition::AlreadyRecorded
                        }
                    },
                    automonique_protocol::primitives::EpochMillis::from_millis(
                        receipt.decided_at_ms,
                    ),
                )
                .map_err(approval_refused)?,
            }),
            Err(refusal) => Ok(ApprovalResponse::Refused {
                request_id: request_id.clone(),
                refusal: wire_approval_refusal(&refusal),
            }),
        }
    }

    /// One bounded page of every recorded decision.
    ///
    /// The wire cursor is the ledger's own exclusive `entry_id` position, so
    /// nothing is translated between two coordinate spaces and there is no
    /// off-by-one to re-derive.
    fn list_approvals(
        &self,
        request_id: &RequestId,
        query: ListApprovals,
    ) -> Result<ApprovalResponse, DaemonError> {
        let page = match self
            .approvals
            .page(query.since().position(), query.page_size().get())
        {
            Ok(page) => page,
            Err(error) => return refuse_approval(request_id, &error),
        };
        let page = approval_page(&page)?;
        ApprovalResponse::listing(request_id.clone(), query, page).map_err(approval_refused)
    }

    /// One bounded page of one subject's decisions, oldest first.
    fn approvals_by_subject(
        &self,
        request_id: &RequestId,
        query: &ApprovalsBySubject,
    ) -> Result<ApprovalResponse, DaemonError> {
        let page = match self.approvals.by_subject(
            query.subject().as_str(),
            query.since().position(),
            query.page_size().get(),
        ) {
            Ok(page) => page,
            Err(error) => return refuse_approval(request_id, &error),
        };
        let page = approval_page(&page)?;
        ApprovalResponse::subject_listing(request_id.clone(), query, page).map_err(approval_refused)
    }

    /// One decision in full, or [`ApprovalRefusal::UnknownApproval`].
    ///
    /// An absent row is "nothing was recorded under this key" and never "the
    /// subject behind it was refused"; those are different answers and this one
    /// makes the true one.
    fn approval_detail(
        &self,
        request_id: &RequestId,
        approval_key: &ApprovalKey,
    ) -> Result<ApprovalResponse, DaemonError> {
        let entry = match self.approvals.entry(approval_key.as_str()) {
            Ok(Some(entry)) => entry,
            Ok(None) => {
                return Ok(ApprovalResponse::Refused {
                    request_id: request_id.clone(),
                    refusal: ApprovalRefusal::UnknownApproval,
                });
            }
            Err(error) => return refuse_approval(request_id, &error),
        };
        Ok(ApprovalResponse::ApprovalDetail {
            request_id: request_id.clone(),
            record: approval_record(&entry)?,
        })
    }

    /// Answer one operation on the native Batch control API.
    ///
    /// # What an accepted write here does, and what it does not
    ///
    /// A registration commits one batch row and one row per member, every member
    /// at `unsubmitted`. An advance commits one member row at a new progress.
    /// **Nothing else happens.** In particular:
    ///
    /// - **Registering a batch submits nothing.** No RunSpec document is
    ///   accepted, no row is written to the run submission log, no run identity
    ///   is reserved. A member key names a submission the caller intends; this
    ///   daemon does not check that one exists and does not create one. A
    ///   registered batch therefore causes no run to exist, and
    ///   `tests/batch_live.rs` asserts that against the live Runs lane.
    /// - **Nothing is scheduled and nothing is throttled.** The concurrency
    ///   policy is stored because the batch declared it. No executor reads it,
    ///   because there is no executor.
    /// - **A member's progress is the caller's claim.** The run index is the true
    ///   binding from a submission to the state its run reached; this lane never
    ///   joins it and no transaction spans the two databases. What an accepted
    ///   advance establishes is that a writer *said* the member is at that
    ///   progress, at a sequence that did not go backwards, along a legal
    ///   lattice.
    ///
    /// That is why a landed write answers `accepted` rather than `completed`.
    ///
    /// # The rolled-up state
    ///
    /// [`Self::batch_detail`] serves the batch-level state the registry
    /// deliberately does not store. It is derived here, from the member slice
    /// being served, by [`BatchDetailResult::new`] — which is the one caller of
    /// `automonique_protocol::batch_runner::roll_up` on this path. This daemon
    /// never assembles that word itself, and could not smuggle one past its own
    /// wire format if it tried: the response decoder recomputes the rollup and
    /// refuses a body whose carried state contradicts its own members.
    ///
    /// # Fencing
    ///
    /// Fenced exactly as [`Daemon::handle_approval`] is, and for the same reason:
    /// this lane writes. A daemon that has lost its generation must not record a
    /// membership into a database another generation now owns, and must not serve
    /// one out of it either. Like the approval and automation lanes and unlike
    /// the intake arms, it is *not* closed by an operator pause: an intake pause
    /// stops the daemon taking custody of new work, and this lane takes custody
    /// of nothing.
    fn handle_batch(
        &mut self,
        stream: &mut UnixStream,
        request: &BatchRequest,
    ) -> Result<(), DaemonError> {
        let now_ms = unix_millis()?;
        let snapshot = self.store.status_snapshot_at(GENERATION_ID, now_ms)?;
        let generation = snapshot.generation().ok_or(StoreError::StaleEpoch)?;
        if generation.holder_id() != self.instance_id.as_str()
            || generation.lease_epoch() != self.lease_epoch
            || generation.lease_expires_ms() != self.lease_expires_ms
            || generation.lease_expires_ms() <= snapshot.lease_observed_boottime_ms()
        {
            return Err(DaemonError::Store(StoreError::StaleEpoch));
        }
        let response = match request {
            BatchRequest::RegisterBatch {
                request_id,
                registration,
            } => self.register_batch(request_id, registration, now_ms)?,
            BatchRequest::AdvanceMember {
                request_id,
                advance,
            } => self.advance_batch_member(request_id, advance, now_ms)?,
            BatchRequest::ListBatches { request_id, query } => {
                self.list_batches(request_id, *query)?
            }
            BatchRequest::BatchDetail {
                request_id,
                batch_id,
            } => self.batch_detail(request_id, batch_id)?,
        };
        let response = response
            .to_message()
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?
            .to_canonical_bytes();
        let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + response.len());
        encode_frame(&response, &mut frame)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?;
        stream.write_all(&frame)?;
        stream.flush()?;
        Ok(())
    }

    /// Record one batch and its whole declared membership.
    ///
    /// The instant is the daemon's, not the caller's: the wire carries no
    /// timestamp, so a client cannot date a registration to whenever it likes.
    ///
    /// The all-or-nothing is the registry's, not this function's — it writes the
    /// batch row and every member row in one immediate transaction, so a reader
    /// after a crash sees the whole membership or no batch at all. Nothing here
    /// compensates, retries or half-writes.
    ///
    /// Every refusal that is a property of the request alone was already made by
    /// the protocol's own decoder before this ran. The registry makes them again
    /// and this function maps them anyway, because the two checks are not
    /// redundant: the first refuses a malformed request before it touches durable
    /// state, and the second refuses a malformed row without trusting us.
    fn register_batch(
        &mut self,
        request_id: &RequestId,
        registration: &RegisterBatch,
        now_ms: i64,
    ) -> Result<BatchResponse, DaemonError> {
        let members: Vec<&str> = registration
            .members()
            .iter()
            .map(BatchMemberKey::as_str)
            .collect();
        let receipt = match self.batches.register(BatchRegistration {
            batch_id: registration.batch_id().as_str(),
            label: registration.label().map(BatchLabel::as_str),
            concurrency: store_concurrency(registration.concurrency()),
            members: &members,
            now_ms,
        }) {
            Ok(receipt) => receipt,
            Err(error) => return refuse_batch(request_id, &error),
        };
        Ok(BatchResponse::Registered {
            request_id: request_id.clone(),
            receipt: BatchReceiptView::new(
                checked_row_id(receipt.entry_id)?,
                registration.batch_id().clone(),
                receipt.member_count,
                receipt.revision,
                automonique_protocol::primitives::EpochMillis::from_millis(receipt.created_at_ms),
            )
            .map_err(batch_refused)?,
        })
    }

    /// Move one member along the progress lattice.
    ///
    /// The sequence coupling was already decided by the protocol's own decoder —
    /// a `ready` at a non-zero sequence never reaches this function — and the
    /// registry decides it again, for the reason [`Daemon::set_enablement`] gives
    /// for its cause coupling.
    ///
    /// A stale expected revision is a `conflict`, not a `rejected`: the caller's
    /// request was well-formed and the row simply moved, and the two are retried
    /// differently. The durable revision travels with the answer so a retry does
    /// not need a second round trip.
    fn advance_batch_member(
        &mut self,
        request_id: &RequestId,
        advance: &AdvanceMember,
        now_ms: i64,
    ) -> Result<BatchResponse, DaemonError> {
        let receipt = match self.batches.advance_member(MemberAdvance {
            batch_id: advance.batch_id().as_str(),
            member_key: advance.member_key().as_str(),
            expected_revision: advance.expected_revision(),
            new_progress: store_progress(advance.progress()),
            last_sequence: advance.last_sequence(),
            now_ms,
        }) {
            Ok(receipt) => receipt,
            Err(BatchRegistryError::RevisionMismatch { expected, durable }) => {
                return BatchResponse::conflict(request_id.clone(), expected, durable)
                    .map_err(batch_refused);
            }
            Err(error) => return refuse_batch(request_id, &error),
        };
        Ok(BatchResponse::MemberAdvanced {
            request_id: request_id.clone(),
            receipt: MemberReceiptView::new(MemberReceiptParts {
                batch_id: advance.batch_id().clone(),
                member_key: advance.member_key().clone(),
                ordinal: receipt.ordinal,
                progress: member_progress(receipt.progress),
                last_sequence: receipt.last_sequence,
                revision: receipt.revision,
                updated_at: automonique_protocol::primitives::EpochMillis::from_millis(
                    receipt.updated_at_ms,
                ),
            })
            .map_err(batch_refused)?,
        })
    }

    /// One bounded page of batches.
    ///
    /// The wire cursor is the registry's own exclusive `entry_id` position, so
    /// nothing is translated between two coordinate spaces and there is no
    /// off-by-one to re-derive. A page carries batch rows and not their
    /// memberships, exactly as the registry serves them: a maximal page of
    /// maximal batches would be a listing that had to be paged again.
    fn list_batches(
        &self,
        request_id: &RequestId,
        query: ListBatches,
    ) -> Result<BatchResponse, DaemonError> {
        let page = match self
            .batches
            .page(query.since().position(), query.page_size().get())
        {
            Ok(page) => page,
            Err(error) => return refuse_batch(request_id, &error),
        };
        let mut entries = Vec::with_capacity(page.entries.len());
        for record in &page.entries {
            entries.push(batch_record(record)?);
        }
        let continuation = match page.next_cursor {
            Some(next) => BatchContinuation::More(BatchCursor::new(next)),
            None => BatchContinuation::Complete,
        };
        let page = BatchListPage::new(entries, continuation).map_err(batch_refused)?;
        BatchResponse::listing(request_id.clone(), query, page).map_err(batch_refused)
    }

    /// One batch, its whole membership in ordinal order, and their rollup.
    ///
    /// An absent batch is [`BatchRefusal::UnknownBatch`] and never an empty
    /// membership: an unregistered batch and a batch whose members are all
    /// `unsubmitted` are different answers, and this one makes the true one.
    ///
    /// The rolled-up state is not read from anywhere. The registry has no such
    /// column, on purpose, and [`BatchDetailResult::new`] derives it from the
    /// very members being served — so the answer cannot drift from what it
    /// summarizes, and cannot be fabricated here.
    fn batch_detail(
        &self,
        request_id: &RequestId,
        batch_id: &BatchId,
    ) -> Result<BatchResponse, DaemonError> {
        let view = match self.batches.batch(batch_id.as_str()) {
            Ok(Some(view)) => view,
            Ok(None) => {
                return Ok(BatchResponse::Refused {
                    request_id: request_id.clone(),
                    refusal: BatchRefusal::UnknownBatch,
                });
            }
            Err(error) => return refuse_batch(request_id, &error),
        };
        let batch = batch_record(&view.batch)?;
        let mut members = Vec::with_capacity(view.members.len());
        for record in &view.members {
            members.push(member_view(record)?);
        }
        Ok(BatchResponse::BatchDetail {
            request_id: request_id.clone(),
            detail: BatchDetailResult::new(batch, members).map_err(batch_refused)?,
        })
    }

    fn write_refusal(
        &self,
        stream: &mut UnixStream,
        request_id: &automonique_protocol::codec::RequestId,
        category: &str,
    ) -> Result<(), DaemonError> {
        let response = AdminResponse::Refused {
            request_id: request_id.clone(),
            category: AdminRefusalCategory::new(category)
                .map_err(|error| DaemonError::ProtocolRefused(error.category()))?,
        }
        .to_message()
        .map_err(|error| DaemonError::ProtocolRefused(error.category()))?
        .to_canonical_bytes();
        let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + response.len());
        encode_frame(&response, &mut frame)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?;
        stream.write_all(&frame)?;
        stream.flush()?;
        Ok(())
    }
}

/// What the run index retains, in the two coordinate spaces a listing needs.
struct RetainedRuns {
    /// Submission identities still listable, which is what a cursor names.
    window: RetainedRange,
    /// Highest `index_id` recorded, which is what the store pages by.
    last_index: u64,
}

/// Translate the index's state vocabulary into the wire's.
///
/// Two closed six-word enums that mirror one another and one exhaustive match
/// between them. Deliberately not a spelling comparison: a variant added or
/// renamed on either side fails to compile here, where a lookup by word would
/// have failed at runtime on the first row that carried it.
const fn run_state(state: RunSpoolState) -> RunState {
    match state {
        RunSpoolState::Ready => RunState::Ready,
        RunSpoolState::Running => RunState::Running,
        RunSpoolState::Completed => RunState::Completed,
        RunSpoolState::Failed => RunState::Failed,
        RunSpoolState::Cancelled => RunState::Cancelled,
        RunSpoolState::TimedOut => RunState::TimedOut,
    }
}

/// Translate a wire state filter into the index's vocabulary.
const fn spool_state(state: RunState) -> RunSpoolState {
    match state {
        RunState::Ready => RunSpoolState::Ready,
        RunState::Running => RunSpoolState::Running,
        RunState::Completed => RunSpoolState::Completed,
        RunState::Failed => RunSpoolState::Failed,
        RunState::Cancelled => RunSpoolState::Cancelled,
        RunState::TimedOut => RunSpoolState::TimedOut,
    }
}

/// Translate the runner spool's own state vocabulary into the wire's.
///
/// A third translation beside [`run_state`] and [`spool_state`], and
/// deliberately not routed through either: this one crosses from the runner to
/// the wire without the store's vocabulary in the middle, so a read of a spool
/// never depends on a row agreeing with it. All three are exhaustive matches,
/// so a variant added anywhere fails to compile rather than silently mapping.
const fn spool_run_state(state: automonique_runner::RunState) -> RunState {
    match state {
        automonique_runner::RunState::Ready => RunState::Ready,
        automonique_runner::RunState::Running => RunState::Running,
        automonique_runner::RunState::Completed => RunState::Completed,
        automonique_runner::RunState::Failed => RunState::Failed,
        automonique_runner::RunState::Cancelled => RunState::Cancelled,
        automonique_runner::RunState::TimedOut => RunState::TimedOut,
    }
}

/// Translate one durable spool event kind onto the wire's.
///
/// `runs_api` carries [`SpoolEventKind`] precisely because
/// `automonique-protocol` cannot import the runner; this is the crossing that
/// pin exists for, made once, in an exhaustive match.
const fn lifecycle_kind(kind: automonique_runner::EventKind) -> SpoolEventKind {
    match kind {
        automonique_runner::EventKind::Started => SpoolEventKind::Started,
        automonique_runner::EventKind::AdapterEvent => SpoolEventKind::AdapterEvent,
        automonique_runner::EventKind::SimulationEvent => SpoolEventKind::SimulationEvent,
        automonique_runner::EventKind::CancelRequested => SpoolEventKind::CancelRequested,
        automonique_runner::EventKind::Terminal => SpoolEventKind::Terminal,
    }
}

/// Translate one durable spool authority onto the wire's.
const fn lifecycle_authority(
    authority: automonique_runner::Authority,
) -> automonique_protocol::event::Authority {
    match authority {
        automonique_runner::Authority::Synthetic => {
            automonique_protocol::event::Authority::Synthetic
        }
        automonique_runner::Authority::Authoritative => {
            automonique_protocol::event::Authority::Authoritative
        }
    }
}

/// Translate the custody vocabulary into the wire's.
///
/// One variant each, because the store's `CHECK (state IN ('accepted'))` admits
/// one value. The match grows when that constraint does, and not before.
const fn submission_state(state: RunSubmissionState) -> SubmissionState {
    match state {
        RunSubmissionState::Accepted => SubmissionState::Accepted,
    }
}

/// A durable row identity, refused rather than wrapped when it is not one.
///
/// SQLite rowids are signed and the protocol's are not. A negative identity is
/// a row this build could not have written, so it is refused here instead of
/// becoming an enormous unsigned coordinate further down.
fn checked_row_id(value: i64) -> Result<u64, DaemonError> {
    u64::try_from(value).map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))
}

fn runs_refused(error: automonique_protocol::runs_api::RunsApiError) -> DaemonError {
    DaemonError::ProtocolRefused(error.category())
}

fn run_detail_provenance(record: &RunIndexRecord) -> Result<Provenance, DaemonError> {
    let trace_id = TraceId::for_ingress("run", &record.run_id);
    Ok(Provenance::new(
        trace_id,
        CorrelationId::new(format!("run-submission:{}", record.submission_id))
            .map_err(|_| DaemonError::ProtocolRefused("run_provenance_invalid"))?,
        CausationId::new(format!("submission:{}", record.submission_id))
            .map_err(|_| DaemonError::ProtocolRefused("run_provenance_invalid"))?,
    ))
}

fn automation_refused(
    error: automonique_protocol::automation_api::AutomationApiError,
) -> DaemonError {
    DaemonError::ProtocolRefused(error.category())
}

/// Translate the registry's enablement vocabulary into the wire's.
///
/// Two closed three-word enums that mirror one another and one exhaustive match
/// between them. Deliberately not a spelling comparison: a variant added or
/// renamed on either side fails to compile here, where a lookup by word would
/// have failed at runtime on the first row that carried it.
const fn enablement_state(state: StoreEnablementState) -> EnablementState {
    match state {
        StoreEnablementState::Enabled => EnablementState::Enabled,
        StoreEnablementState::Paused => EnablementState::Paused,
        StoreEnablementState::Archived => EnablementState::Archived,
    }
}

/// Translate the wire's enablement vocabulary into the registry's.
const fn store_enablement_state(state: EnablementState) -> StoreEnablementState {
    match state {
        EnablementState::Enabled => StoreEnablementState::Enabled,
        EnablementState::Paused => StoreEnablementState::Paused,
        EnablementState::Archived => StoreEnablementState::Archived,
    }
}

/// Project one validated registry row onto the wire.
///
/// Every field is re-validated by the protocol's own constructor rather than
/// trusted through: the store validated it against its grammar, and this
/// validates it against the wire's, which is the one a client will decode
/// under. A row the wire cannot carry is a typed daemon failure rather than a
/// row silently omitted from a page — the same rule the run listing follows for
/// a dangling index row.
fn automation_record(record: &AutomationRecord) -> Result<AutomationRecordView, DaemonError> {
    use automonique_protocol::primitives::EpochMillis;

    AutomationRecordView::new(AutomationRecordParts {
        entry_id: checked_row_id(record.entry_id)?,
        automation_id: AutomationId::new(&record.automation_id)
            .map_err(|_| DaemonError::AutomationStoreFailed("automation_id_ungrammatical"))?,
        revision: record.revision,
        enablement: enablement_state(record.enablement),
        actor: AutomationActor::new(&record.actor)
            .map_err(|_| DaemonError::AutomationStoreFailed("actor_ungrammatical"))?,
        cause: record
            .cause
            .as_deref()
            .map(PauseReason::new)
            .transpose()
            .map_err(|_| DaemonError::AutomationStoreFailed("cause_ungrammatical"))?,
        created_at: EpochMillis::from_millis(record.created_at_ms),
        updated_at: EpochMillis::from_millis(record.updated_at_ms),
    })
    .map_err(automation_refused)
}

/// Answer one automation-registry failure to the client, or report it as ours.
///
/// The split is the same one the submission log gets: a malformed field, a
/// duplicate registration, an illegal move, an incoherent cause, a lost cursor
/// and a full registry are the operator's to fix and are answered with one
/// closed word carrying no echo of what they sent. Corruption, a schema
/// mismatch, an unsafe path and storage failure are *ours* — they say the
/// daemon's own durable state is unsound — and presenting them as a refusal
/// would blame an operator for our broken database.
///
/// [`AutomationStoreError::RevisionMismatch`] never reaches here: it is the
/// `conflict` answer, handled at the call site before this function is asked.
fn refuse_automation(
    request_id: &RequestId,
    error: &AutomationStoreError,
) -> Result<AutomationResponse, DaemonError> {
    let refusal = match error {
        AutomationStoreError::InvalidField(_) => AutomationRefusal::InvalidField,
        AutomationStoreError::AlreadyRegistered { .. } => AutomationRefusal::AlreadyRegistered,
        AutomationStoreError::NotFound(_) => AutomationRefusal::UnknownAutomation,
        AutomationStoreError::IllegalTransition { .. } => AutomationRefusal::IllegalTransition,
        AutomationStoreError::CauseRequired { .. } => AutomationRefusal::CauseRequired,
        AutomationStoreError::CauseForbidden { .. } => AutomationRefusal::CauseForbidden,
        AutomationStoreError::CursorOutOfRange { .. } => AutomationRefusal::CursorOutOfRange,
        AutomationStoreError::RegistryFull { .. } => AutomationRefusal::RegistryFull,
        AutomationStoreError::RevisionMismatch { .. }
        | AutomationStoreError::InsecurePath(_)
        | AutomationStoreError::SchemaVersion { .. }
        | AutomationStoreError::Corrupt(_)
        | AutomationStoreError::Io(_)
        | AutomationStoreError::Sqlite(_) => {
            return Err(DaemonError::AutomationStoreFailed(error.category()));
        }
    };
    Ok(AutomationResponse::Refused {
        request_id: request_id.clone(),
        refusal,
    })
}

/// Project one decision refusal onto the Approval protocol's vocabulary.
///
/// Two of this daemon's reasons have no wire spelling of their own and are
/// deliberately widened rather than invented: a malformed reference is the
/// protocol's `invalid_field`, because that is what a caller supplied, and an
/// unreadable durable state is `unknown_request`, because the honest thing to
/// tell a caller whose proposal this daemon cannot read is that it has no
/// answer for that reference — not that the proposal was decided.
const fn wire_approval_refusal(refusal: &ApprovalDecisionRefusal) -> ApprovalRefusal {
    match refusal {
        ApprovalDecisionRefusal::MalformedKey => ApprovalRefusal::InvalidField,
        ApprovalDecisionRefusal::UnknownRequest | ApprovalDecisionRefusal::DecisionUnavailable => {
            ApprovalRefusal::UnknownRequest
        }
        ApprovalDecisionRefusal::AlreadyDecided { .. } => ApprovalRefusal::AlreadyDecided,
        ApprovalDecisionRefusal::RequestExpired => ApprovalRefusal::RequestExpired,
        ApprovalDecisionRefusal::LedgerFull => ApprovalRefusal::LedgerFull,
    }
}

fn approval_refused(error: automonique_protocol::approval_api::ApprovalApiError) -> DaemonError {
    DaemonError::ProtocolRefused(error.category())
}

/// Translate the wire's decision vocabulary into the ledger's.
///
/// Two closed two-word enums that mirror one another and one exhaustive match
/// between them. Deliberately not a spelling comparison, and deliberately not a
/// shared type: this crate can see both, but neither crate depends on the other,
/// so the match is where a rename on either side becomes a compile failure
/// rather than a row nobody can read.
const fn store_approval_decision(decision: ApprovalDecision) -> StoreApprovalDecision {
    match decision {
        ApprovalDecision::Granted => StoreApprovalDecision::Granted,
        ApprovalDecision::Denied => StoreApprovalDecision::Denied,
    }
}

/// Translate the ledger's decision vocabulary into the wire's.
const fn approval_decision(decision: StoreApprovalDecision) -> ApprovalDecision {
    match decision {
        StoreApprovalDecision::Granted => ApprovalDecision::Granted,
        StoreApprovalDecision::Denied => ApprovalDecision::Denied,
    }
}

/// Translate the ledger's disposition vocabulary into the wire's.
const fn approval_disposition(disposition: StoreApprovalDisposition) -> ApprovalDisposition {
    match disposition {
        StoreApprovalDisposition::Recorded => ApprovalDisposition::Recorded,
        StoreApprovalDisposition::AlreadyRecorded => ApprovalDisposition::AlreadyRecorded,
    }
}

/// Project one validated ledger row onto the wire.
///
/// Every field is re-validated by the protocol's own constructor rather than
/// trusted through: the ledger validated it against its grammar, and this
/// validates it against the wire's, which is the one a client will decode under.
/// A row the wire cannot carry is a typed daemon failure rather than a row
/// silently omitted from a page.
fn approval_record(entry: &ApprovalEntry) -> Result<ApprovalRecordView, DaemonError> {
    use automonique_protocol::primitives::EpochMillis;

    ApprovalRecordView::new(ApprovalRecordParts {
        entry_id: checked_row_id(entry.entry_id)?,
        approval_key: ApprovalKey::new(&entry.approval_key)
            .map_err(|_| DaemonError::ApprovalLedgerFailed("approval_key_ungrammatical"))?,
        subject: ApprovalSubject::new(&entry.subject)
            .map_err(|_| DaemonError::ApprovalLedgerFailed("subject_ungrammatical"))?,
        decision: approval_decision(entry.decision),
        decider: Decider::new(&entry.decider)
            .map_err(|_| DaemonError::ApprovalLedgerFailed("decider_ungrammatical"))?,
        decided_at: EpochMillis::from_millis(entry.decided_at_ms),
        revision: entry.revision,
    })
    .map_err(approval_refused)
}

/// Project one bounded ledger page onto the wire.
///
/// `next_cursor` is set only when the ledger saw a further *matching* row, so a
/// page shortened by a subject filter still reports itself complete only when
/// nothing matching remains.
fn approval_page(
    page: &automonique_store::approval_ledger::ApprovalPage,
) -> Result<ApprovalListPage, DaemonError> {
    let mut entries = Vec::with_capacity(page.entries.len());
    for entry in &page.entries {
        entries.push(approval_record(entry)?);
    }
    let continuation = match page.next_cursor {
        Some(next) => ApprovalContinuation::More(ApprovalCursor::new(next)),
        None => ApprovalContinuation::Complete,
    };
    ApprovalListPage::new(entries, continuation).map_err(approval_refused)
}

/// Answer one approval-ledger failure to the client, or report it as ours.
///
/// The same split the automation registry gets: a malformed field, a lost cursor
/// and a full ledger are the operator's to fix and are answered with one closed
/// word carrying no echo of what they sent. Corruption, a schema mismatch, an
/// unsafe path and storage failure are *ours* — they say the daemon's own
/// durable state is unsound — and presenting them as a refusal would blame an
/// operator for our broken database.
///
/// [`ApprovalLedgerError::Conflict`] never reaches here: it is the `conflict`
/// answer, handled at the call site before this function is asked.
fn refuse_approval(
    request_id: &RequestId,
    error: &ApprovalLedgerError,
) -> Result<ApprovalResponse, DaemonError> {
    let refusal = match error {
        ApprovalLedgerError::InvalidField(_) => ApprovalRefusal::InvalidField,
        ApprovalLedgerError::CursorOutOfRange { .. } => ApprovalRefusal::CursorOutOfRange,
        ApprovalLedgerError::LedgerFull { .. } => ApprovalRefusal::LedgerFull,
        ApprovalLedgerError::Conflict { .. }
        | ApprovalLedgerError::InsecurePath(_)
        | ApprovalLedgerError::SchemaVersion { .. }
        | ApprovalLedgerError::Corrupt(_)
        | ApprovalLedgerError::Io(_)
        | ApprovalLedgerError::Sqlite(_) => {
            return Err(DaemonError::ApprovalLedgerFailed(error.category()));
        }
    };
    Ok(ApprovalResponse::Refused {
        request_id: request_id.clone(),
        refusal,
    })
}

fn batch_refused(error: BatchApiError) -> DaemonError {
    DaemonError::ProtocolRefused(error.category())
}

/// Translate the wire's concurrency vocabulary into the registry's.
///
/// Two mirrored enums and one exhaustive match between them. Deliberately not a
/// spelling comparison, and deliberately not a shared type: this crate can see
/// both, but neither crate depends on the other, so the match is where a rename
/// on either side becomes a compile failure rather than a row nobody can read.
const fn store_concurrency(policy: ConcurrencyPolicy) -> StoreConcurrencyPolicy {
    match policy {
        ConcurrencyPolicy::Sequential => StoreConcurrencyPolicy::Sequential,
        ConcurrencyPolicy::BoundedParallel { max_in_flight } => {
            StoreConcurrencyPolicy::BoundedParallel { max_in_flight }
        }
    }
}

/// Translate the registry's concurrency vocabulary into the wire's.
const fn concurrency_policy(policy: StoreConcurrencyPolicy) -> ConcurrencyPolicy {
    match policy {
        StoreConcurrencyPolicy::Sequential => ConcurrencyPolicy::Sequential,
        StoreConcurrencyPolicy::BoundedParallel { max_in_flight } => {
            ConcurrencyPolicy::BoundedParallel { max_in_flight }
        }
    }
}

/// Translate the wire's member progress into the registry's.
///
/// Six of the seven values are the run vocabulary, and they travel through the
/// same [`spool_state`] the run index lane uses, so a batch member and the index
/// row it mirrors cannot disagree about a word.
const fn store_progress(progress: MemberProgress) -> StoreProgress {
    match progress {
        MemberProgress::Unsubmitted => StoreProgress::Unsubmitted,
        MemberProgress::Run(state) => StoreProgress::Run(spool_state(state)),
    }
}

/// Translate the registry's member progress into the wire's.
const fn member_progress(progress: StoreProgress) -> MemberProgress {
    match progress {
        StoreProgress::Unsubmitted => MemberProgress::Unsubmitted,
        StoreProgress::Run(state) => MemberProgress::Run(run_state(state)),
    }
}

/// Project one validated batch row onto the wire.
///
/// Every field is re-validated by the protocol's own constructor rather than
/// trusted through: the registry validated it against its grammar, and this
/// validates it against the wire's, which is the one a client will decode under.
/// A row the wire cannot carry is a typed daemon failure rather than a row
/// silently omitted from a page.
fn batch_record(record: &BatchRecord) -> Result<BatchRecordView, DaemonError> {
    use automonique_protocol::primitives::EpochMillis;

    BatchRecordView::new(
        checked_row_id(record.entry_id)?,
        BatchId::new(&record.batch_id)
            .map_err(|_| DaemonError::BatchRegistryFailed("batch_id_ungrammatical"))?,
        record
            .label
            .as_deref()
            .map(BatchLabel::new)
            .transpose()
            .map_err(|_| DaemonError::BatchRegistryFailed("label_ungrammatical"))?,
        concurrency_policy(record.concurrency),
        EpochMillis::from_millis(record.created_at_ms),
        record.revision,
    )
    .map_err(batch_refused)
}

/// Project one validated member row onto the wire.
fn member_view(record: &MemberRecord) -> Result<MemberView, DaemonError> {
    use automonique_protocol::primitives::EpochMillis;

    MemberView::new(
        BatchMemberKey::new(&record.member_key)
            .map_err(|_| DaemonError::BatchRegistryFailed("member_key_ungrammatical"))?,
        record.ordinal,
        member_progress(record.progress),
        record.last_sequence,
        record.revision,
        EpochMillis::from_millis(record.updated_at_ms),
    )
    .map_err(batch_refused)
}

/// Answer one batch-registry failure to the client, or report it as ours.
///
/// The same split the approval ledger gets: a malformed field, a duplicate
/// identity, an empty or over-large membership, a repeated member, an incoherent
/// concurrency ceiling, an unknown batch or member, an illegal transition, an
/// incoherent or regressing sequence, a lost cursor and a full registry are the
/// operator's to fix and are answered with one closed word carrying no echo of
/// what they sent. Corruption, a schema mismatch, an unsafe path and storage
/// failure are *ours* — they say the daemon's own durable state is unsound — and
/// presenting them as a refusal would blame an operator for our broken database.
///
/// [`BatchRegistryError::RevisionMismatch`] never reaches here: it is the
/// `conflict` answer, handled at the call site before this function is asked.
///
/// [`BatchRegistryError::NotFound`] names the entity the registry failed to
/// find, and the registry looks the batch up first: anything that is not the
/// member is the batch.
fn refuse_batch(
    request_id: &RequestId,
    error: &BatchRegistryError,
) -> Result<BatchResponse, DaemonError> {
    let refusal = match error {
        BatchRegistryError::InvalidField(_) => BatchRefusal::InvalidField,
        BatchRegistryError::AlreadyRegistered { .. } => BatchRefusal::AlreadyRegistered,
        BatchRegistryError::EmptyBatch => BatchRefusal::EmptyBatch,
        BatchRegistryError::TooManyMembers { .. } => BatchRefusal::TooManyMembers,
        BatchRegistryError::DuplicateMember { .. } => BatchRefusal::DuplicateMember,
        BatchRegistryError::ConcurrencyCeilingZero
        | BatchRegistryError::ConcurrencyCeilingUnreachable { .. } => {
            BatchRefusal::ConcurrencyCeiling
        }
        BatchRegistryError::NotFound("batch member") => BatchRefusal::UnknownMember,
        BatchRegistryError::NotFound(_) => BatchRefusal::UnknownBatch,
        BatchRegistryError::IllegalTransition { .. } => BatchRefusal::IllegalTransition,
        BatchRegistryError::SequenceCoupling { .. } => BatchRefusal::SequenceCoupling,
        BatchRegistryError::SequenceRegression { .. } => BatchRefusal::SequenceRegression,
        BatchRegistryError::CursorOutOfRange { .. } => BatchRefusal::CursorOutOfRange,
        BatchRegistryError::RegistryFull { .. } => BatchRefusal::RegistryFull,
        BatchRegistryError::RevisionMismatch { .. }
        | BatchRegistryError::InsecurePath(_)
        | BatchRegistryError::SchemaVersion { .. }
        | BatchRegistryError::Corrupt(_)
        | BatchRegistryError::Io(_)
        | BatchRegistryError::Sqlite(_) => {
            return Err(DaemonError::BatchRegistryFailed(error.category()));
        }
    };
    Ok(BatchResponse::Refused {
        request_id: request_id.clone(),
        refusal,
    })
}

fn index_failed(error: RunIndexError) -> DaemonError {
    DaemonError::RunIndexFailed(error.category())
}

fn platform_run_resource(record: &RunIndexRecord) -> Result<ResourceRecord, DaemonError> {
    Ok(ResourceRecord {
        resource: ResourceCoordinate::new(
            ResourceAuthority::Automonique,
            ResourceKind::Run,
            ResourceId::new(&record.run_id)
                .map_err(|_| DaemonError::RunIndexFailed("run_id_ungrammatical"))?,
        ),
        freshness: Freshness {
            state: FreshnessState::Fresh,
            observed_at: automonique_protocol::primitives::EpochMillis::from_millis(
                record.updated_at_ms,
            ),
            revision: Revision::new(record.revision)
                .map_err(|_| DaemonError::RunIndexFailed("revision_invalid"))?,
        },
        summary: PlatformText::new(record.spool_state.as_str())
            .map_err(|_| DaemonError::RunIndexFailed("state_ungrammatical"))?,
    })
}

fn platform_refusal(
    outcome: ReceiptOutcome,
    category: &str,
) -> Result<PlatformResponse, DaemonError> {
    Ok(PlatformResponse::Refused {
        outcome,
        explanation: PlatformText::new(category)
            .map_err(|_| DaemonError::ProtocolRefused("platform_explanation"))?,
    })
}

fn platform_store_response(error: &PlatformStoreError) -> PlatformResponse {
    let outcome = match error {
        PlatformStoreError::StaleRevision | PlatformStoreError::Conflict(_) => {
            ReceiptOutcome::Conflict
        }
        PlatformStoreError::ResyncRequired => ReceiptOutcome::ResyncRequired,
        PlatformStoreError::NotFound
        | PlatformStoreError::InvalidField(_)
        | PlatformStoreError::InsecurePath(_)
        | PlatformStoreError::SchemaVersion { .. }
        | PlatformStoreError::Corrupt(_)
        | PlatformStoreError::Io(_)
        | PlatformStoreError::Sqlite(_) => ReceiptOutcome::Rejected,
    };
    PlatformResponse::Refused {
        outcome,
        explanation: PlatformText::new(error.category())
            .expect("closed platform-store categories fit the platform field bound"),
    }
}

fn generation_audit_failed(error: GenerationAuditError) -> DaemonError {
    DaemonError::GenerationAuditFailed(error.category())
}

fn map_lease_authority_error(error: lease_time::LeaseAuthorityError) -> DaemonError {
    match error {
        lease_time::LeaseAuthorityError::Clock(category) => DaemonError::LeaseClockFailed(category),
        lease_time::LeaseAuthorityError::Suspended => DaemonError::LeaseSuspended,
    }
}

/// Join already-signalled workers while periodically maintaining their fence.
///
/// Workers start draining before this function is called, so independent
/// transport deadlines overlap. The first renewal error is retained, but every
/// later renewal is still attempted until all workers have relinquished their
/// durable-state authority.
struct ShutdownWorker {
    worker_group: &'static str,
    worker_ordinal: usize,
    handle: std::thread::JoinHandle<()>,
    completion_reported: bool,
    over_budget_reported: bool,
}

fn named_shutdown_workers(
    worker_group: &'static str,
    workers: impl IntoIterator<Item = std::thread::JoinHandle<()>>,
) -> Vec<ShutdownWorker> {
    workers
        .into_iter()
        .enumerate()
        .map(|(worker_ordinal, handle)| ShutdownWorker {
            worker_group,
            worker_ordinal,
            handle,
            completion_reported: false,
            over_budget_reported: false,
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DrainPhase {
    Started,
    Completed,
    OverBudget,
}

impl DrainPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Completed => "completed",
            Self::OverBudget => "over_budget",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DrainObservation {
    worker_group: &'static str,
    worker_ordinal: usize,
    phase: DrainPhase,
    elapsed_ms: u64,
    budget_ms: u64,
}

fn duration_millis_bounded(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn drain_shutdown_workers<E>(
    mut workers: Vec<ShutdownWorker>,
    renewal_interval: Duration,
    diagnostic_budget: Duration,
    mut renew: impl FnMut() -> Result<(), E>,
    mut observe: impl FnMut(DrainObservation),
) -> Result<(), E> {
    let mut first_failure = None;
    let started_at = std::time::Instant::now();
    let mut next_renewal = started_at;
    let budget_ms = duration_millis_bounded(diagnostic_budget);
    for worker in &workers {
        observe(DrainObservation {
            worker_group: worker.worker_group,
            worker_ordinal: worker.worker_ordinal,
            phase: DrainPhase::Started,
            elapsed_ms: 0,
            budget_ms,
        });
    }
    while workers.iter().any(|worker| !worker.completion_reported) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(started_at);
        let elapsed_ms = duration_millis_bounded(elapsed);
        for worker in &mut workers {
            if !worker.completion_reported && worker.handle.is_finished() {
                worker.completion_reported = true;
                observe(DrainObservation {
                    worker_group: worker.worker_group,
                    worker_ordinal: worker.worker_ordinal,
                    phase: DrainPhase::Completed,
                    elapsed_ms,
                    budget_ms,
                });
            } else if !worker.completion_reported
                && !worker.over_budget_reported
                && elapsed >= diagnostic_budget
            {
                worker.over_budget_reported = true;
                observe(DrainObservation {
                    worker_group: worker.worker_group,
                    worker_ordinal: worker.worker_ordinal,
                    phase: DrainPhase::OverBudget,
                    elapsed_ms,
                    budget_ms,
                });
            }
        }
        if now >= next_renewal {
            if let Err(error) = renew()
                && first_failure.is_none()
            {
                first_failure = Some(error);
            }
            next_renewal = now + renewal_interval;
        }
        std::thread::sleep(ACCEPT_POLL);
    }
    for worker in workers {
        let _ = worker.handle.join();
    }
    first_failure.map_or(Ok(()), Err)
}

/// Record this daemon's tenure over the generation it has just leased.
///
/// # The decision is "has this generation any recorded history", not "is a tenure open"
///
/// It is tempting to read this as a crash check — supersede when a predecessor
/// left a row open, open plainly otherwise — and that reading is wrong in the
/// ordinary case. `open_tenure` refuses
/// [`GenerationAuditError::PredecessorRecorded`] for a generation whose tenures
/// are all *terminal*, which is precisely what a clean restart finds: the
/// previous daemon closed its row `released` on the way out. So the clean
/// restart, the most common startup this daemon will ever perform, takes the
/// succession path too, and its handoff row records the `released` it found.
///
/// That is the audit's design rather than a workaround. A successor owes the
/// log an observation of what it displaced, whether or not that predecessor
/// managed to close its own row, and `succeed_tenure` decides which end kind
/// the predecessor gets — this caller never names one. `open_tenure` is
/// therefore reachable exactly once per generation, on the first daemon ever to
/// hold it, which is the one startup with no predecessor to observe.
///
/// # What a refusal here means
///
/// [`GenerationAuditError::EpochRegression`] is the interesting one and it is
/// reachable: the lease lives in one database and this log in another, so an
/// audit carrying an epoch at or above the one just leased says the two files
/// disagree about how far this generation has got — a main database restored,
/// replaced or deleted out from under a log that remembers more. Refusing is
/// the only safe answer, because the alternative is writing a second tenure at
/// an epoch already recorded and calling two different processes the same
/// authority. It also covers, without a special case, the impossible-looking
/// state of finding *our own* `(holder, epoch)` already open: a second row at
/// our epoch is a regression whatever name is on it.
fn record_tenure(
    audit: &mut GenerationAudit,
    holder_id: &str,
    lease_epoch: u64,
    now_ms: i64,
) -> Result<TenureRecord, DaemonError> {
    let opening = TenureOpening {
        generation_id: GENERATION_ID,
        holder_id,
        lease_epoch,
        started_at_ms: now_ms,
    };
    // One row is enough: the question is whether this generation has ever been
    // recorded, not what its history says.
    let recorded = audit
        .history(GENERATION_ID, 0, 1)
        .map_err(generation_audit_failed)?;
    if recorded.tenures.is_empty() {
        return audit.open_tenure(opening).map_err(generation_audit_failed);
    }
    // `observed_at_ms` is the instant the lease was taken, not a fresh reading.
    // When the predecessor's row is still open this is also the `ended_at_ms`
    // written for it, and the acquisition is the first moment anything could
    // durably know that tenure was over — a later timestamp would be this
    // process dating the predecessor's end by how long its own startup took.
    audit
        .succeed_tenure(Succession {
            opening,
            observed_at_ms: now_ms,
        })
        .map(|succeeded| succeeded.tenure)
        .map_err(generation_audit_failed)
}

fn snapshot_requires_reconciliation(snapshot: &StatusSnapshot) -> bool {
    snapshot.runs_reconciliation_pending() > 0 || snapshot.outbox_in_flight_ambiguous() > 0
}

/// Whether a newly acquired generation found every active-work queue empty.
///
/// This fact is captured before the transport workers start, so the Slack
/// connection can report the generation's admission state without racing a
/// later status query against newly accepted work.
fn startup_queues_clean(snapshot: &StatusSnapshot) -> bool {
    snapshot.runs_running() == 0
        && snapshot.inbox_pending() == 0
        && snapshot.outbox_pending() == 0
        && snapshot.runs_reconciliation_pending() == 0
        && snapshot.outbox_in_flight_live() == 0
        && snapshot.outbox_in_flight_ambiguous() == 0
}

/// One durable count, or the honest absence of one.
///
/// Generic over the store error on purpose: the four stores this is used for
/// have four unrelated error types and exactly one thing to say between them —
/// that they did not answer. Naming each one here would invite a per-store
/// interpretation of a failure this code has no business interpreting.
///
/// A store that could not be counted is [`OperationalMetric::Unavailable`], and
/// never zero. Zero is a fact an operator acts on: nothing registered, nothing
/// to clean up, nothing to worry about. A read that failed supports none of
/// those conclusions, and substituting the friendlier of the two is how a
/// status report becomes a thing nobody can trust.
///
/// A count above the wire's signed ceiling is unavailable for the same reason:
/// this daemon cannot report the number it read, and reporting a different one
/// would be worse than reporting none.
fn durable_count<E>(read: Result<usize, E>) -> OperationalMetric {
    read.ok()
        .and_then(|count| u64::try_from(count).ok())
        .and_then(|count| OperationalMetric::measured(count).ok())
        .unwrap_or(OperationalMetric::Unavailable)
}

fn operational_status(projection: &StoreProjection) -> Result<OperationalStatus, DaemonError> {
    let metrics = projection.metrics();
    let measured = |name| match metrics.value(name) {
        MetricValue::Measured(value) => Ok(value),
        MetricValue::Unavailable(_) => Err(DaemonError::ProtocolRefused("operational_projection")),
    };
    let projected = |name| match metrics.value(name) {
        MetricValue::Measured(value) => OperationalMetric::measured(value),
        MetricValue::Unavailable(_) => Ok(OperationalMetric::Unavailable),
    };
    OperationalStatus::new(OperationalStatusParts {
        observed_ms: metrics.observed_ms(),
        reconciliation_pending: measured(MetricName::ReconciliationPending)?,
        outbox_pending_ready: measured(MetricName::OutboxPendingReady)?,
        outbox_pending_delayed: measured(MetricName::OutboxPendingDelayed)?,
        outbox_in_flight_live: measured(MetricName::OutboxInFlightLive)?,
        outbox_in_flight_ambiguous: measured(MetricName::OutboxInFlightAmbiguous)?,
        outbox_delivered: measured(MetricName::OutboxDelivered)?,
        outbox_dead_lettered: measured(MetricName::OutboxDeadLettered)?,
        outbox_oldest_ready_age_ms: measured(MetricName::OutboxOldestAgeMs)?,
        telegram_pollers_live: measured(MetricName::TelegramPollersLive)?,
        telegram_pollers_expired: measured(MetricName::TelegramPollersExpired)?,
        telegram_offset_lag: projected(MetricName::TelegramOffsetLag)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?,
        provider_available: projected(MetricName::ProviderAvailable)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?,
        sandbox_launch_refusals: projected(MetricName::SandboxLaunchRefusals)
            .map_err(|error| DaemonError::ProtocolRefused(error.category()))?,
    })
    .map_err(|error| DaemonError::ProtocolRefused(error.category()))
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if self.remove_socket_on_drop {
            remove_socket_if_identity(&self.socket_path, self.socket_identity);
        }
    }
}

fn remove_socket_if_identity(path: &Path, identity: (u64, u64)) {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.file_type().is_socket()
        && metadata.uid() == geteuid().as_raw()
        && (metadata.dev(), metadata.ino()) == identity
    {
        let _ = fs::remove_file(path);
    }
}

/// Run the daemon with SIGINT/SIGTERM translated into the same orderly stop
/// path as the local shutdown command and SIGHUP translated into a supervised
/// configuration reload.
///
/// # Errors
///
/// Returns setup, signal, store, or serving failures.
pub fn run_foreground(config: &DaemonConfig) -> Result<(), DaemonError> {
    run_with_mode(config, false)
}

/// Run the daemon with every external transport disabled and provider starts
/// refused. This is the only supported startup mode for a restored host before
/// reconciliation and credential revalidation.
pub fn run_disconnected_recovery(config: &DaemonConfig) -> Result<(), DaemonError> {
    run_with_mode(config, true)
}

fn run_with_mode(config: &DaemonConfig, disconnected_recovery: bool) -> Result<(), DaemonError> {
    let mut signals = SigSet::empty();
    signals.add(Signal::SIGINT);
    signals.add(Signal::SIGTERM);
    signals.add(Signal::SIGHUP);
    let mut old_signals = SigSet::empty();
    pthread_sigmask(
        SigmaskHow::SIG_BLOCK,
        Some(&signals),
        Some(&mut old_signals),
    )
    .map_err(DaemonError::Signal)?;
    let stop = Arc::new(AtomicBool::new(false));
    let signal_stop = Arc::clone(&stop);
    let reload = Arc::new(AtomicBool::new(false));
    let signal_reload = Arc::clone(&reload);
    let signal_fd = match SignalFd::with_flags(&signals, SfdFlags::SFD_NONBLOCK) {
        Ok(signal_fd) => signal_fd,
        Err(error) => {
            let _ = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&old_signals), None);
            return Err(DaemonError::Signal(error));
        }
    };
    let signal_thread = std::thread::spawn(move || {
        while !signal_stop.load(Ordering::Acquire) {
            match signal_fd.read_signal() {
                Ok(Some(info)) => {
                    let signal = i32::try_from(info.ssi_signo)
                        .ok()
                        .and_then(|number| Signal::try_from(number).ok());
                    match signal {
                        Some(Signal::SIGHUP) => signal_reload.store(true, Ordering::Release),
                        Some(Signal::SIGINT | Signal::SIGTERM) | None => {
                            signal_stop.store(true, Ordering::Release);
                        }
                        Some(_) => {}
                    }
                }
                Ok(None) => std::thread::sleep(ACCEPT_POLL),
                Err(_) => signal_stop.store(true, Ordering::Release),
            }
        }
    });
    let result = systemd::Notifier::from_environment()
        .map_err(|error| DaemonError::ServiceManagerFailed(error.category()))
        .and_then(|service_manager| {
            if let Some(notifier) = service_manager.as_ref() {
                notifier
                    .extend_timeout(STARTUP_TIMEOUT_EXTENSION)
                    .map_err(|error| DaemonError::ServiceManagerFailed(error.category()))?;
            }
            Daemon::open_with_mode(config, disconnected_recovery).and_then(|daemon| {
                let (_, result) = daemon.serve_with_control(
                    &stop,
                    &reload,
                    service_manager,
                    LeaseDisposition::Release,
                    None,
                );
                result
            })
        });
    if !stop.load(Ordering::Acquire) {
        stop.store(true, Ordering::Release);
    }
    let joined = signal_thread
        .join()
        .map_err(|_| DaemonError::Signal(nix::errno::Errno::EIO));
    let restored = pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&old_signals), None)
        .map_err(DaemonError::Signal);
    result.and(joined).and(restored)
}

fn read_payload(stream: &mut UnixStream) -> Result<Vec<u8>, DaemonError> {
    let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
    stream.read_exact(&mut prefix)?;
    let declared = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| DaemonError::ProtocolRefused("frame_too_large"))?;
    if declared == 0 || declared > MAX_ADMIN_PAYLOAD_BYTES {
        return Err(DaemonError::ProtocolRefused("frame_size"));
    }
    let mut framed = Vec::with_capacity(LENGTH_PREFIX_BYTES + declared);
    framed.extend_from_slice(&prefix);
    framed.resize(LENGTH_PREFIX_BYTES + declared, 0);
    stream.read_exact(&mut framed[LENGTH_PREFIX_BYTES..])?;
    match decode_frame(&framed).map_err(|error| DaemonError::ProtocolRefused(error.category()))? {
        automonique_protocol::codec::FrameDecode::Frame { payload, consumed }
            if consumed == framed.len() =>
        {
            Ok(payload.to_vec())
        }
        _ => Err(DaemonError::ProtocolRefused("incomplete_frame")),
    }
}

/// Decide whether a connected peer may reach the codec, and prove it.
///
/// The rule is unchanged — same effective user only — but it is no longer
/// spelled here. `automonique_policy::peer` owns the decision, this function
/// owns the `getsockopt`, and the two halves meet at [`PeerCredential`]. The
/// same policy backs the CLI's own check, so the client and the daemon can no
/// longer drift into two predicates that agree by inspection.
///
/// A `pid` of zero or less means the kernel gave no usable credential rather
/// than an unwelcome one, so it is presented as *absent* rather than as a
/// refused user: the policy's own documentation is explicit that no admission
/// rule may key on a PID, and it answers `CredentialsUnavailable` for `None`.
///
/// The returned [`Admission`] is the proof the caller must hold to proceed, and
/// [`Daemon::handle_stream`] holds it by construction: there is no path from a
/// refusal to a served frame. It is deliberately *not* carried onto the
/// approval lane's surface set — see [`Daemon::operator_surfaces`] for why a
/// peer that is making a request is not a surface for answering it.
///
/// # Errors
///
/// [`DaemonError::PeerDenied`] for every refusal. The policy's reason is
/// deliberately not widened onto the wire: a peer this socket will not talk to
/// learns that and nothing more.
fn authenticate_peer(stream: &UnixStream) -> Result<Admission, DaemonError> {
    let credential = getsockopt(stream, sockopt::PeerCredentials)
        .ok()
        .filter(|credentials| credentials.pid() > 0)
        .map(|credentials| {
            PeerCredential::new(credentials.uid(), credentials.gid(), credentials.pid())
        });
    local_peer_policy()?
        .evaluate(credential)
        .map_err(|_| DaemonError::PeerDenied)
}

/// The one peer policy this daemon serves under: its own effective user.
///
/// Built per connection rather than cached, because the set is one number and
/// the alternative is a second place where the admitted set could be stale.
///
/// # Errors
///
/// [`DaemonError::PeerDenied`] if the admitted set were ever empty, which this
/// construction cannot produce and which is refused rather than defaulted.
fn local_peer_policy() -> Result<PeerPolicy, DaemonError> {
    PeerPolicy::new(&[geteuid().as_raw()]).map_err(|_| DaemonError::PeerDenied)
}

const SYSTEMD_LISTEN_FD_START: i32 = 3;
const ADMIN_FD_NAME: &str = "admin";

/// Open the self-bound foreground listener or adopt systemd's one exact fd.
///
/// Activation is all-or-nothing. A matching `LISTEN_PID` must advertise one
/// descriptor, and an optional descriptor name must be `admin`; extra or
/// malformed descriptors are refused rather than silently ignored. The
/// activated pathname is compared with the configured endpoint and is never
/// unlinked by the daemon, because the socket unit owns its lifetime.
fn open_admin_listener(path: &Path) -> Result<(UnixListener, bool), DaemonError> {
    let listen_pid = std::env::var_os("LISTEN_PID");
    let listen_fds = std::env::var_os("LISTEN_FDS");
    let listen_fdnames = std::env::var_os("LISTEN_FDNAMES");
    let activated = activated_listener_fd(
        listen_pid.as_deref(),
        listen_fds.as_deref(),
        listen_fdnames.as_deref(),
        std::process::id(),
    )?;
    let Some(fd) = activated else {
        prepare_socket_path(path)?;
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        return Ok((listener, true));
    };

    let mut inherited = listenfd::ListenFd::from_env();
    if inherited.len() != 1 || fd != SYSTEMD_LISTEN_FD_START {
        return Err(DaemonError::SocketActivationRefused);
    }
    let listener = inherited
        .take_unix_listener(0)
        .map_err(|_| DaemonError::SocketActivationRefused)?
        .ok_or(DaemonError::SocketActivationRefused)?;
    let local = listener
        .local_addr()
        .map_err(|_| DaemonError::SocketActivationRefused)?;
    if local.as_pathname() != Some(path) {
        return Err(DaemonError::SocketActivationRefused);
    }
    listener.set_nonblocking(true)?;
    Ok((listener, false))
}

fn validate_admin_listener(
    listener: &UnixListener,
    path: &Path,
) -> Result<(u64, u64), DaemonError> {
    let local = listener.local_addr()?;
    if local.as_pathname() != Some(path) {
        return Err(DaemonError::InsecurePath("admin socket"));
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(DaemonError::InsecurePath("admin socket"));
    }
    listener.set_nonblocking(true)?;
    Ok((metadata.dev(), metadata.ino()))
}

fn activated_listener_fd(
    listen_pid: Option<&std::ffi::OsStr>,
    listen_fds: Option<&std::ffi::OsStr>,
    listen_fdnames: Option<&std::ffi::OsStr>,
    current_pid: u32,
) -> Result<Option<i32>, DaemonError> {
    let Some(listen_pid) = listen_pid else {
        return if listen_fds.is_none() && listen_fdnames.is_none() {
            Ok(None)
        } else {
            Err(DaemonError::SocketActivationRefused)
        };
    };
    let parsed_pid = listen_pid
        .to_str()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or(DaemonError::SocketActivationRefused)?;
    if parsed_pid != current_pid {
        return Ok(None);
    }
    if listen_fds.and_then(std::ffi::OsStr::to_str) != Some("1")
        || listen_fdnames
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| name != ADMIN_FD_NAME)
    {
        return Err(DaemonError::SocketActivationRefused);
    }
    Ok(Some(SYSTEMD_LISTEN_FD_START))
}

fn prepare_socket_path(path: &Path) -> Result<(), DaemonError> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if !metadata.file_type().is_socket() || metadata.uid() != geteuid().as_raw() {
        return Err(DaemonError::InsecurePath("admin socket"));
    }
    let identity = (metadata.dev(), metadata.ino());
    match UnixStream::connect(path) {
        Ok(_) => Err(DaemonError::AlreadyRunning),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            ) =>
        {
            let current = fs::symlink_metadata(path)?;
            if !current.file_type().is_socket()
                || current.uid() != geteuid().as_raw()
                || (current.dev(), current.ino()) != identity
            {
                return Err(DaemonError::InsecurePath("admin socket"));
            }
            fs::remove_file(path)?;
            Ok(())
        }
        Err(error) => Err(DaemonError::Io(error)),
    }
}

fn validate_root(path: &Path, kind: &'static str) -> Result<(), DaemonError> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(DaemonError::InsecurePath(kind));
    }
    validate_components(path, kind)?;
    let metadata = fs::symlink_metadata(path).map_err(DaemonError::Io)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(DaemonError::InsecurePath(kind));
    }
    Ok(())
}

fn validate_components(path: &Path, kind: &'static str) -> Result<(), DaemonError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(value) => {
                current.push(value);
                let metadata = fs::symlink_metadata(&current).map_err(DaemonError::Io)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(DaemonError::InsecurePath(kind));
                }
            }
            _ => return Err(DaemonError::InsecurePath(kind)),
        }
    }
    Ok(())
}

fn ensure_private_dir(path: &Path, kind: &'static str) -> Result<(), DaemonError> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(DaemonError::InsecurePath(kind));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => validate_root(path, kind),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or(DaemonError::InsecurePath(kind))?;
            validate_root(parent, kind)?;
            fs::create_dir(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            validate_root(path, kind)
        }
        Err(error) => Err(DaemonError::Io(error)),
    }
}

fn unix_millis() -> Result<i64, DaemonError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| DaemonError::ProtocolRefused("clock_before_epoch"))?;
    i64::try_from(duration.as_millis())
        .map_err(|_| DaemonError::ProtocolRefused("clock_out_of_range"))
}

fn wire_millis(value: i64) -> Result<u64, DaemonError> {
    u64::try_from(value).map_err(|_| DaemonError::ProtocolRefused("counter_out_of_range"))
}

fn fatal_store_error(error: &StoreError) -> bool {
    !matches!(
        error,
        StoreError::InvalidField(_)
            | StoreError::IdempotencyConflict(_)
            | StoreError::ScopeLocked
            | StoreError::AlreadyTerminal
            | StoreError::OutboxConflict
            | StoreError::NotFound(_)
    )
}

/// Stable, document-free class of one strict RunSpec decode refusal.
///
/// The decoder's own variants name a field or an object, which is our own
/// static vocabulary rather than submitter data. They are collapsed to a fixed
/// set here anyway: a refusal category is a metric label, and one that can take
/// a few dozen values is a worse label than one that takes six.
const fn run_spec_decode_category(error: RunSpecDecodeError) -> &'static str {
    match error {
        RunSpecDecodeError::DocumentTooLarge => "run_spec_document_too_large",
        RunSpecDecodeError::InvalidCanonicalJson => "run_spec_invalid_canonical_json",
        RunSpecDecodeError::ObjectShape(_) => "run_spec_object_shape",
        RunSpecDecodeError::Field(_) => "run_spec_field_invalid",
        RunSpecDecodeError::Domain(_) => "run_spec_domain_invariant",
        RunSpecDecodeError::NonCanonicalRoundTrip => "run_spec_non_canonical_round_trip",
    }
}

/// Whether a submission-log failure is the submitter's to fix.
///
/// A malformed field, a reused key and a full log are answered to the client.
/// Corruption, a schema mismatch and storage failure are not: they say the
/// daemon's own custody is unsound, and a correlated refusal would present that
/// as a client error.
const fn run_submission_refusal(error: &RunSubmissionError) -> bool {
    matches!(
        error,
        RunSubmissionError::InvalidField(_)
            | RunSubmissionError::Conflict { .. }
            | RunSubmissionError::LogFull { .. }
    )
}

/// Whether an intake pause or resume failure is the operator's to act on.
///
/// A lost fence, an idempotent repeat and a malformed field are answered to the
/// client. Storage failure is not: it says the daemon's own durable state is
/// unsound, and a correlated refusal would present that as an operator error.
fn intake_pause_refusal(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::InvalidField(_)
            | StoreError::IdempotencyConflict(_)
            | StoreError::StaleEpoch
            | StoreError::AlreadyPaused(_)
            | StoreError::NotPaused
    )
}

fn reconciliation_command_refusal(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::InvalidField(_)
            | StoreError::IdempotencyConflict(_)
            | StoreError::StaleEpoch
            | StoreError::LeaseHeld
            | StoreError::ScopeLocked
            | StoreError::AlreadyTerminal
            | StoreError::OutboxConflict
            | StoreError::NotFound(_)
    )
}

#[cfg(test)]
mod approval_context_tests {
    use super::{
        APPROVAL_KEY_DOMAIN, ApprovalContext, ApprovalContextField, StoredApprovalContext,
        approved_context_drift, mint_request_key,
    };

    const SPEC: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const PROGRAM: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const PROMPT: &str = "3333333333333333333333333333333333333333333333333333333333333333";
    const OTHER: &str = "4444444444444444444444444444444444444444444444444444444444444444";

    fn approved() -> StoredApprovalContext {
        StoredApprovalContext {
            spec_digest: String::from(SPEC),
            program_path: String::from("/usr/bin/example-provider"),
            program_sha256: String::from(PROGRAM),
            prompt_sha256: String::from(PROMPT),
            cwd_token: String::from("cwd-1"),
        }
    }

    fn observed() -> ApprovalContext<'static> {
        ApprovalContext {
            spec_digest: SPEC,
            program_path: "/usr/bin/example-provider",
            program_sha256: PROGRAM,
            prompt_sha256: PROMPT,
            cwd_token: "cwd-1",
        }
    }

    #[test]
    fn an_unchanged_context_names_no_drift() {
        assert_eq!(approved_context_drift(&approved(), observed()), None);
    }

    /// One assertion per bound component, each naming its own field.
    ///
    /// The list is the whole binding, so a component that stopped being
    /// compared would fail here rather than silently weaken every approval in
    /// the product. The count assertion is what makes that true of a *new*
    /// component too: adding one to `ApprovalContextField` without a case here
    /// fails this test rather than passing vacuously.
    #[test]
    fn every_bound_component_drifts_on_its_own_and_names_itself() {
        let mutations: [(ApprovalContextField, ApprovalContext<'static>); 5] = [
            (
                ApprovalContextField::SpecDigest,
                ApprovalContext {
                    spec_digest: OTHER,
                    ..observed()
                },
            ),
            (
                ApprovalContextField::ProgramPath,
                ApprovalContext {
                    program_path: "/usr/bin/other-provider",
                    ..observed()
                },
            ),
            (
                ApprovalContextField::ProgramSha256,
                ApprovalContext {
                    program_sha256: OTHER,
                    ..observed()
                },
            ),
            (
                ApprovalContextField::PromptSha256,
                ApprovalContext {
                    prompt_sha256: OTHER,
                    ..observed()
                },
            ),
            (
                ApprovalContextField::CwdToken,
                ApprovalContext {
                    cwd_token: "cwd-2",
                    ..observed()
                },
            ),
        ];
        assert_eq!(
            mutations.len(),
            ApprovalContextField::ALL.len(),
            "a bound component was added without a drift case"
        );
        for (expected, drifted) in mutations {
            assert_eq!(
                approved_context_drift(&approved(), drifted),
                Some(expected),
                "{expected} did not name itself"
            );
        }
    }

    #[test]
    fn the_first_field_in_declaration_order_wins_when_several_drift() {
        // A launch whose whole world moved is reported as one fact, and it is
        // the first one, so the answer does not depend on iteration order.
        let everything = ApprovalContext {
            spec_digest: OTHER,
            program_path: "/usr/bin/other-provider",
            program_sha256: OTHER,
            prompt_sha256: OTHER,
            cwd_token: "cwd-2",
        };
        assert_eq!(
            approved_context_drift(&approved(), everything),
            Some(ApprovalContextField::SpecDigest)
        );
        // And with the first one restored, the next one in order.
        let rest = ApprovalContext {
            spec_digest: SPEC,
            ..everything
        };
        assert_eq!(
            approved_context_drift(&approved(), rest),
            Some(ApprovalContextField::ProgramPath)
        );
    }

    #[test]
    fn a_re_proposal_mints_a_reference_the_first_one_did_not() {
        let first = mint_request_key("runspec:one", "run-1", SPEC, 1_000, 0);
        // Same coordinates, one prior proposal: a distinct reference, which is
        // what makes re-proposal structurally impossible to confuse with
        // reviving the row that expired.
        let second = mint_request_key("runspec:one", "run-1", SPEC, 1_000, 1);
        assert_ne!(first, second);
        // Deterministic, so a retry of the same proposal is a replay rather
        // than a second row.
        assert_eq!(
            first,
            mint_request_key("runspec:one", "run-1", SPEC, 1_000, 0)
        );
        // Every coordinate is part of the identity.
        assert_ne!(
            first,
            mint_request_key("runspec:two", "run-1", SPEC, 1_000, 0)
        );
        assert_ne!(
            first,
            mint_request_key("runspec:one", "run-2", SPEC, 1_000, 0)
        );
        assert_ne!(
            first,
            mint_request_key("runspec:one", "run-1", OTHER, 1_000, 0)
        );
        assert_ne!(
            first,
            mint_request_key("runspec:one", "run-1", SPEC, 2_000, 0)
        );

        assert_eq!(
            first.len(),
            automonique_store::approval_requests::REQUEST_KEY_BYTES
        );
        assert!(first.starts_with(automonique_store::approval_requests::REQUEST_KEY_PREFIX));
        assert!(
            first[4..].bytes().all(|byte| byte.is_ascii_hexdigit()),
            "the reference must be opaque hexadecimal"
        );
        // Domain separation, so the reference cannot collide with a plain
        // re-hash of values that appear elsewhere.
        assert!(APPROVAL_KEY_DOMAIN.ends_with(b"\0"));
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use automonique_policy::approval::ApprovalRequirement;

    use super::{
        Daemon, DaemonConfig, DrainPhase, OperationalMetric, activated_listener_fd,
        drain_shutdown_workers, durable_count, named_shutdown_workers,
    };

    #[test]
    fn socket_activation_environment_is_one_exact_named_descriptor() {
        use std::ffi::OsStr;

        assert_eq!(activated_listener_fd(None, None, None, 41).unwrap(), None);
        assert_eq!(
            activated_listener_fd(
                Some(OsStr::new("40")),
                Some(OsStr::new("99")),
                Some(OsStr::new("foreign")),
                41,
            )
            .unwrap(),
            None,
            "activation intended for another process is not ours to consume"
        );
        assert_eq!(
            activated_listener_fd(
                Some(OsStr::new("41")),
                Some(OsStr::new("1")),
                Some(OsStr::new("admin")),
                41,
            )
            .unwrap(),
            Some(3)
        );
        assert_eq!(
            activated_listener_fd(Some(OsStr::new("41")), Some(OsStr::new("1")), None, 41,)
                .unwrap(),
            Some(3),
            "LISTEN_FDNAMES is optional in the systemd protocol"
        );

        for refused in [
            activated_listener_fd(None, Some(OsStr::new("1")), None, 41),
            activated_listener_fd(
                Some(OsStr::new("not-a-pid")),
                Some(OsStr::new("1")),
                None,
                41,
            ),
            activated_listener_fd(Some(OsStr::new("41")), Some(OsStr::new("2")), None, 41),
            activated_listener_fd(
                Some(OsStr::new("41")),
                Some(OsStr::new("1")),
                Some(OsStr::new("other")),
                41,
            ),
        ] {
            assert_eq!(refused.unwrap_err().category(), "socket_activation_refused");
        }
    }

    #[test]
    fn configuration_reload_replaces_both_policy_fields_or_neither() {
        let root = tempfile::tempdir().expect("temporary root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        let runtime_root = root.path().join("runtime");
        let state_root = root.path().join("state");
        for path in [&runtime_root, &state_root] {
            std::fs::create_dir(path).expect("configuration root");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .expect("private configuration root");
        }
        let config = DaemonConfig {
            runtime_root,
            state_root,
        };
        let mut daemon = Daemon::open(&config).expect("daemon opens");
        assert_eq!(
            daemon.configured_approval_requirement,
            ApprovalRequirement::Allowed
        );
        let default_lifetime = daemon.approval_lifetime;

        let approval_dir = config.state_dir().join("approvals");
        std::fs::create_dir(&approval_dir).expect("approval configuration directory");
        std::fs::set_permissions(&approval_dir, std::fs::Permissions::from_mode(0o700))
            .expect("private approval configuration directory");
        let approval_path = approval_dir.join("approvals.conf");
        std::fs::write(
            &approval_path,
            "schema=automonique.approvals/v1\n\
             requirement=approval_required\n\
             ttl_ms=60000\n\
             reminder_percent=20\n\
             escalation_percent=70\n\
             end=automonique.approvals/v1\n",
        )
        .expect("approval configuration");
        std::fs::set_permissions(&approval_path, std::fs::Permissions::from_mode(0o600))
            .expect("private approval configuration");
        daemon.reload_configuration().expect("valid reload");
        assert_eq!(
            daemon.configured_approval_requirement,
            ApprovalRequirement::ApprovalRequired
        );
        assert_eq!(daemon.approval_lifetime.ttl_ms(), 60_000);

        std::fs::write(&approval_path, "not a configuration\n").expect("malformed replacement");
        let error = daemon
            .reload_configuration()
            .expect_err("malformed reload is refused");
        assert_eq!(error.category(), "approval_config_malformed");
        assert_eq!(
            daemon.configured_approval_requirement,
            ApprovalRequirement::ApprovalRequired
        );
        assert_eq!(daemon.approval_lifetime.ttl_ms(), 60_000);
        assert_ne!(daemon.approval_lifetime, default_lifetime);
    }

    #[test]
    fn shutdown_drain_renews_until_workers_finish_and_retains_the_first_failure() {
        let worker = std::thread::spawn(|| std::thread::sleep(Duration::from_millis(85)));
        let renewals = AtomicUsize::new(0);
        let mut observations = Vec::new();

        let result = drain_shutdown_workers(
            named_shutdown_workers("telegram", [worker]),
            Duration::from_millis(10),
            Duration::from_millis(30),
            || match renewals.fetch_add(1, Ordering::Relaxed) {
                0 => Err("first renewal failed"),
                _ => Ok(()),
            },
            |observation| observations.push(observation),
        );

        assert_eq!(result, Err("first renewal failed"));
        assert!(
            renewals.load(Ordering::Relaxed) >= 2,
            "a later renewal must still be attempted while the worker drains"
        );
        assert_eq!(observations.len(), 3);
        assert_eq!(observations[0].worker_group, "telegram");
        assert_eq!(observations[0].worker_ordinal, 0);
        assert_eq!(observations[0].phase, DrainPhase::Started);
        assert_eq!(observations[0].elapsed_ms, 0);
        assert_eq!(observations[0].budget_ms, 30);
        assert_eq!(observations[1].phase, DrainPhase::OverBudget);
        assert!(observations[1].elapsed_ms >= 30);
        assert_eq!(observations[2].phase, DrainPhase::Completed);
        assert!(observations[2].elapsed_ms >= observations[1].elapsed_ms);
    }

    /// The seam where a failed read becomes a reported value.
    ///
    /// This is the one place a fabricated zero could enter the status, and no
    /// integration test can reach it: the daemon holds its databases open for
    /// its whole life, so a test cannot make one of them stop answering from
    /// outside. So it is asserted here, on the conversion itself.
    #[test]
    fn an_unreadable_store_is_unavailable_and_an_empty_one_is_zero() {
        struct Unreadable;

        assert_eq!(
            durable_count::<Unreadable>(Err(Unreadable)),
            OperationalMetric::Unavailable,
            "a store that did not answer must not be reported as empty"
        );
        assert_eq!(
            durable_count::<Unreadable>(Ok(0)),
            OperationalMetric::Measured(0),
            "an empty store was counted, and zero is that count"
        );
        assert_eq!(
            durable_count::<Unreadable>(Ok(7)),
            OperationalMetric::Measured(7)
        );
        // A count the integer-only wire cannot carry is not reported as some
        // other count.
        assert_eq!(
            durable_count::<Unreadable>(Ok(usize::MAX)),
            OperationalMetric::Unavailable
        );
    }
}
