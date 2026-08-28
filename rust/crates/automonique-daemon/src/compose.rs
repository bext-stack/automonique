// SPDX-License-Identifier: Elastic-2.0

//! Turning one bounded task string into one RunSpec for a contained provider
//! completion.
//!
//! This is the first thing in the product that *writes* an admission document
//! rather than accepting one. Every other lane takes a RunSpec from a submitter
//! who wrote it; `/run` has a sentence of operator text and nothing else, so
//! something has to decide what the document says. This module is that
//! something, and it is deliberately the narrowest such thing that could work:
//! it composes exactly one shape of run — a **single contained provider
//! completion, over brokered egress, in a private empty attempt workspace,
//! whose answer is a file** — and it can compose nothing else.
//!
//! # What the operator supplies, and what the deployment supplies
//!
//! The operator supplies the task text. That is the whole of their input, and
//! it reaches the provider on stdin through the protected prompt slot; it never
//! becomes an argument, a path, a variable, or a destination.
//!
//! Everything that grants anything comes from the deployment, read from files
//! the owner writes in this daemon's private state directory:
//!
//! - [`PROVIDER_CONFIG_NAME`] — the provider binary and its isolated home;
//! - [`crate::EGRESS_DESTINATIONS_NAME`] — where a brokered run may reach.
//!
//! No machine-specific path appears in this file: the only absolute paths it
//! names are the system CA trust store, which is the same on every host this
//! runs on. A daemon whose owner has written neither file answers
//! [`ComposeRefusal::NotConfigured`], which is what `/run` replies with rather
//! than failing somewhere further in.
//!
//! # The answer is a file, because the lane records lifecycle and not output
//!
//! [`crate::execute`] records `Started` and exactly one terminal event. It never
//! reads a byte the workload wrote: `spawn_sandboxed` hands the workload the
//! supervisor's own stdout, and the backend says in as many words that it
//! captures no output. So an answer that has to come back to a chat cannot come
//! back through the spool.
//!
//! It comes back through the **attempt workspace**, which is the one durable place the
//! workload can write and this daemon can read. The composer names an absolute
//! answer path inside the run's own attempt workspace, the provider is told to
//! write its final message there, and [`Composition::answer_path`] is what a
//! reader opens afterwards.
//!
//! ## Why the composer can name that path at all
//!
//! A RunSpec's working directory is an opaque `cwd_token`; resolving it is the
//! attempt-workspace registry's job, and this daemon is the registry.
//! [`crate::execute`] publishes its resolution as
//! [`crate::execute::run_attempt_workspace`], a pure function of the state
//! directory and the run identity — both of which the composer chooses. So the
//! composer computes the *same* path the lane will resolve, through the same
//! function, and writes it into the document.
//!
//! That is worth stating as a choice, because the alternative was available and
//! is worse: the lane could have rewritten the argv at execute time, when the
//! path is certainly known. But the document in custody is what the run's
//! canonical digest identifies, and a lane that ran a modified argv would be
//! running something nobody can point at on disk. Naming the path in the
//! document keeps the document true: it says where the answer goes, its digest
//! covers that, and a reviewer reads it there.
//!
//! The path is **absolute** for a reason the launch surface forces: the launch
//! frame has no working-directory line, so the workload starts in whatever
//! directory the supervisor is in. A relative `answer.md` would be written
//! wherever the daemon happened to be. `-C <workspace>` tells the provider which
//! attempt workspace
//! to work; the absolute answer path is what makes the file land where this
//! daemon looks.
//!
//! # What this module does **not** establish
//!
//! - **It does not run anything.** It produces a document, a prompt, and two
//!   paths. Submitting it to custody and starting it is [`crate::run_lane`].
//! - **It is not release trust.** The provider binary is hashed here and the
//!   digest is pinned in the document; [`crate::execute`] hashes it again at
//!   execute time and refuses a mismatch. Who signed those bytes is
//!   [`automonique_protocol::release_trust_root`]'s question.
//! - **It does not know the provider's protocol.** The argv is
//!   [`DEFAULT_ARGV`] — the invocation the owner's live vehicle established,
//!   written down — or the one the owner configured; nothing here parses what
//!   the provider emits beyond reading the file it was told to write.
//! - **It is not a scheduler.** One task, one document, one run.

use std::ffi::OsString;
use std::fs;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use automonique_protocol::context::{ContextManifest, TokenBudget};
use automonique_protocol::digest::{ALGORITHM, Sha256};
use automonique_protocol::host::{AttemptId, HostId, HostLifetime, WorkId};
use automonique_protocol::identity::Actor;
use automonique_protocol::models::{ExecutorClass, ProviderAccountId};
use automonique_protocol::primitives::Revision;
use automonique_protocol::provider::BinaryProvenance;
use automonique_protocol::sandbox::{
    BudgetQuantities, Budgets, CredentialDescriptors, ExecutionAllowlists, ExecutionBackendId,
    FilesystemAccess, HostFeature, IsolationRequirement, NestedIsolation, NetworkAccess,
    PathAccess, PathGrant, PathGrants, PolicyDigest, ProhibitedCapabilities, ProviderControlEgress,
    RequiredFeature, RequiredFeatures, SandboxProfile, SandboxSpec, SandboxSpecParts,
    ToolWorkloadEgress, WorkspaceContextHash,
};
use automonique_protocol::tools::RunId;
use automonique_protocol::workspace::{
    AttemptWorkspaceRegistration, AttemptWorkspaceToken, IsolationKind,
};
use automonique_runner::{
    AdmissionFields, AdmissionFieldsParts, ArtifactGrantBindings, AttemptWorkspaceRegistryId,
    CwdToken, ExecutionPlanDigest, ExtensionSetDigest, FallbackEligibility, IntegrationMode,
    IoReservation, ModelRoutingDigest, PersonaDigest, PortabilityPolicy, ProfileDigest,
    PromptDeliveryPlan, ProtectedPromptReference, RemoteAttestationPolicy, RequiredCapabilities,
    RunCoordinates, RunOrigin, RunSpec, RunSpecParts, RunnerEventDialect, SchedulerDecisionDigest,
    SchedulerReservationBinding, SchedulerReservationId, SkillsetDigest, ToolsetDigest,
    WorkspaceReservation,
};

use crate::execute::{
    DAEMON_ATTEMPT_WORKSPACE_REGISTRY, DAEMON_BACKEND_ID, is_within_byte_limit,
    run_attempt_workspace,
};

/// The provider this deployment runs, a sibling of [`crate::DATABASE_NAME`].
///
/// A text file for the same reason the destination policy is one: it is an
/// input the owner writes and a reviewer reads, and it names host paths that
/// have no business inside any document. See [`ProviderConfig`] for the format.
pub const PROVIDER_CONFIG_NAME: &str = "provider";

/// Filename the provider is told to write its final message to.
///
/// Fixed rather than derived: the composer writes the absolute path into the
/// argv and [`Composition::answer_path`] carries the same value, so nothing
/// downstream reconstructs it. It lives in the run's own attempt workspace,
/// which is created empty for the run, so this file existing means this run
/// wrote it.
pub const ANSWER_LEAF: &str = "answer.md";

/// The two coordinates a composed argv may name, and the only substitution this
/// module performs.
///
/// Both are resolved at *compose* time, not at execute time, because both are
/// pure functions of the state directory and the run identity — see this
/// module's own note on why the document names the path rather than the lane
/// rewriting it. Every occurrence in every argument is replaced; an argument
/// that names neither is passed through byte for byte.
pub const ATTEMPT_WORKSPACE_PLACEHOLDER: &str = "{workspace}";
/// The run's answer file, absolute. See [`ATTEMPT_WORKSPACE_PLACEHOLDER`].
pub const ANSWER_PLACEHOLDER: &str = "{answer}";

/// The invocation this build reviewed, mirroring the owner's live vehicle.
///
/// `exec --json -` is a pure completion with the prompt on stdin and a
/// normalized JSONL progress stream on stdout; `-s read-only` and
/// `--ephemeral` keep it from writing outside its workspace or keeping state;
/// `--skip-git-repo-check` is needed because the workspace is an empty directory
/// rather than a repository; `--color never` keeps escape sequences out of a
/// file that becomes a chat message; `-o` names the file the final message is
/// written to.
///
/// `-C` is what points the provider at the workspace, and it is not optional:
/// the launch frame has no working-directory line, so the workload starts in
/// whatever directory the supervisor is in and a relative path would be written
/// somewhere else entirely.
pub const DEFAULT_ARGV: [&str; 13] = [
    "exec",
    "--json",
    "-",
    "-s",
    "read-only",
    "--skip-git-repo-check",
    "--color",
    "never",
    "--ephemeral",
    "-C",
    ATTEMPT_WORKSPACE_PLACEHOLDER,
    "-o",
    ANSWER_PLACEHOLDER,
];

/// Provider execution shape selected by a trusted caller.
///
/// This is deliberately typed rather than inferred from prompt text: an
/// administrator's `/run` task cannot lower its own execution profile by
/// imitating the internal Q&A prompt marker.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ProviderRunProfile {
    /// The configured invocation exactly as reviewed by the owner.
    #[default]
    Standard,
    /// Latency-oriented reasoning for bounded, read-only conversational Q&A.
    FastConversation,
    /// Full configured model for a complex but still read-only question.
    IntelligentQuestion,
    /// Explicitly authorized public-web research through Codex's native tool.
    WebResearch,
    /// Administrator-approved work in an empty writable scratchpad.
    ///
    /// Unlike conversational profiles, this profile may execute the bounded
    /// system runtimes declared by [`scratchpad_path_grants`]. It still has no
    /// repository, production path, ambient credential, or unrestricted
    /// network grant.
    AgenticScratchpad,
}

/// Provider-session behavior for a managed operator request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedSessionMode<'a> {
    /// Persist the provider session and expose its normalized identifier.
    New,
    /// Resume this exact normalized provider session.
    Resume(&'a str),
}

/// Codex's per-invocation override for latency-sensitive read-only Q&A.
pub const QUESTION_REASONING_CONFIG: &str = "model_reasoning_effort=\"none\"";

/// Current-family lightweight model selected by the trusted conversational
/// profile. The older GPT-5.4 nano API model was rejected by this Codex
/// harness, while operational work retains the configured Sol model.
pub const QUESTION_MODEL_CONFIG: &str = "model=\"gpt-5.6-luna\"";

/// Codex `-c` override that turns the native web search on for a research
/// run. Placed directly after `exec`, like [`QUESTION_MODEL_CONFIG`].
pub const WEB_SEARCH_MODE_CONFIG: &str = "web_search_mode=\"live\"";

/// Largest answer this daemon reads back out of a workspace.
///
/// A reply is bounded far below this by the chat transport; the bound here is
/// on what is read into memory at all, so a workload that filled its workspace
/// cannot be read whole by the process that is supposed to be reporting on it.
pub const MAX_ANSWER_BYTES: u64 = 64 * 1024;

/// Largest provider configuration file this daemon will read.
pub const MAX_PROVIDER_CONFIG_BYTES: u64 = 4 * 1024;

/// Most arguments one configured invocation may carry.
///
/// Deliberately the RunSpec's own argument ceiling: an invocation this file
/// accepted but the document could not carry would be a configuration that
/// composes nothing.
pub const MAX_ARGUMENTS: usize = automonique_runner::MAX_ARG_COUNT;

/// Largest provider binary the composer will hash to pin it.
///
/// Deliberately the execution lane's own ceiling: a program this composer
/// pinned but that lane would refuse to hash is a document that could never run.
pub const MAX_PROVIDER_BINARY_BYTES: u64 = crate::execute::MAX_PROVIDER_BINARY_BYTES;

/// Domain separator for the digests this composer declares about its own
/// composition.
pub const COMPOSE_DOMAIN: &str = "automonique.compose.v1";

/// The sandbox profile identity every composed run declares.
pub const COMPOSE_PROFILE_ID: &str = "automonique-run-completion";

/// Profile revision. Bumped when the composed shape changes what it grants.
pub const COMPOSE_PROFILE_VERSION: u32 = 1;

/// Tenant and actor a composed run is attributed to.
///
/// One tenant, because this daemon serves one owner: the whole product is a
/// single operator's control plane, and inventing a tenant per chat would be
/// identity this build does not have.
pub const COMPOSE_TENANT: &str = "automonique";
/// The actor a composed run records. It is the *surface*, not a person: a
/// Telegram sender is authorized by the control gate and is deliberately not
/// copied into a document that outlives the message.
pub const COMPOSE_ACTOR: &str = "telegram-control";

/// Memory ceiling one composed run's cgroup carries.
pub const COMPOSE_MEMORY_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Memory ceiling for conversational Q&A provider processes.
///
/// The measured live high-water mark is below 300 MiB. This leaves bounded
/// headroom while preventing a chat turn from reserving the 2 GiB allowed to
/// explicitly requested complex work.
pub const QUESTION_MEMORY_BYTES: u64 = 512 * 1024 * 1024;
/// Process ceiling one composed run's cgroup carries.
pub const COMPOSE_PROCESSES: u64 = 256;
/// Wall-clock budget one composed run gets, which is also the deadline the
/// backend kills it at.
pub const COMPOSE_TIMEOUT_MILLIS: u64 = 300_000;
/// Spool ceiling one composed run's lifecycle log carries.
pub const COMPOSE_SPOOL_BYTES: u64 = 1024 * 1024;

/// Where a composed run's provider looks for CA roots.
const CA_DIRECTORY: &str = "/etc/ssl/certs";
/// The bundle file inside [`CA_DIRECTORY`], named for providers that want a file.
const CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";
/// `PATH` a composed run gets. Ordinary profiles cannot execute entries on it;
/// the approved agentic scratchpad grants only the declared runtime roots.
const COMPOSE_PATH: &str = "/usr/bin:/bin";

/// Read/execute roots available only to an approved agentic scratchpad.
///
/// The workspace remains the only writable host path. `/usr/bin` supplies
/// shells and interpreters, while `/usr/lib` supplies their loaders, shared
/// libraries, and standard-library modules on merged-/usr Linux hosts. The
/// CA directory is already a read-only grant for every provider run.
const SCRATCHPAD_RUNTIME_BIN: &str = "/usr/bin";
const SCRATCHPAD_RUNTIME_LIB: &str = "/usr/lib";
const JCODE_NULL_DEVICE: &str = "/dev/null";
const SCRATCHPAD_RUNTIME_SHARE: &str = "/usr/share";

/// Why a task could not be composed into a document.
///
/// Every variant is a refusal that happened before any durable state existed.
/// None of them means "composed with less than was asked for".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComposeRefusal {
    /// This deployment has no provider configuration, no destination policy, or
    /// one that could not be read exactly. Nothing was composed.
    NotConfigured,
    /// The configured provider binary could not be read and hashed, so nothing
    /// could be pinned.
    ProviderUnreadable,
    /// This host offers no enforcement feature, so no document it composed
    /// could be admitted anywhere — including here.
    HostUnenforceable,
    /// The task text is empty or beyond what a prompt slot carries.
    TaskRejected,
    /// The run identity is not one this daemon can turn into a directory, a
    /// cgroup and a prompt slot.
    IdentityRejected,
    /// The composed document was refused by the RunSpec constructor. This is
    /// this module's own bug rather than the operator's, and it is a refusal
    /// rather than a panic because a control plane does not crash on a sentence.
    DocumentRejected,
    /// The run-execution provider selects the retired direct Codex engine.
    ///
    /// The direct Codex JSONL execution path was the temporary production
    /// fallback while the pinned JCode `api-stdio` engine was proven and
    /// live-verified (epic bext-stack/automonique#66; plan
    /// `docs/product-plan/unified-client-platform.md`). It is retired as a
    /// run-execution engine: [`ProviderConfig::load_execution`] refuses a
    /// provider that resolves to [`ProviderEngine::Codex`] so production selects
    /// the JCode engine or nothing. This says nothing about the conversational
    /// chat adapter, a separate provider role that still rides the Codex-style
    /// answer-file mechanism through the generic [`ProviderConfig::load`].
    CodexEngineRetired,
}

impl ComposeRefusal {
    /// Stable, content-free category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::NotConfigured => "run_not_configured",
            Self::ProviderUnreadable => "provider_unreadable",
            Self::HostUnenforceable => "host_unenforceable",
            Self::TaskRejected => "task_rejected",
            Self::IdentityRejected => "identity_rejected",
            Self::DocumentRejected => "document_rejected",
            Self::CodexEngineRetired => "codex_engine_retired",
        }
    }
}

impl core::fmt::Display for ComposeRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::NotConfigured => "this deployment has no provider or destination configuration",
            Self::ProviderUnreadable => "the configured provider binary could not be pinned",
            Self::HostUnenforceable => "this host enforces no sandbox property",
            Self::TaskRejected => "the task text is empty or too large",
            Self::IdentityRejected => "the run identity is unusable",
            Self::DocumentRejected => "the composed document was refused",
            Self::CodexEngineRetired => {
                "the direct Codex execution provider is retired; the run engine is JCode (set engine=jcode)"
            }
        })
    }
}

impl std::error::Error for ComposeRefusal {}

/// The provider one deployment runs, as its owner wrote it down.
///
/// # The format
///
/// One `key=value` per line; blank lines and `#` comments are ignored. Every
/// other line must parse completely — there is no key this reader skips.
///
/// ```text
/// # production provider protocol
/// engine=jcode
/// # the exact immutable JCode binary, absolute
/// binary=/opt/automonique/jcode/versions/COMMIT/jcode
/// # isolated JCODE_HOME/JCODE_RUNTIME_DIR
/// home=/var/lib/automonique/jcode-home
/// # for JCode, the exact hello_ok.server identity expected from these bytes
/// version=jcode/COMMIT
/// # fixed supervised protocol invocation; repeated arg keys preserve order
/// arg=--quiet
/// arg=--no-update
/// arg=--no-selfdev
/// arg=api-stdio
/// ```
///
/// `binary` and `home` are both required and both must be absolute. Neither is
/// opened here: [`ProviderConfig::load`] validates shape, and
/// [`compose`] is where the binary is hashed.
///
/// # The invocation
///
/// A repeated `arg=` key replaces [`DEFAULT_ARGV`] **entirely** — there is no
/// merging, because a partial override of an invocation has no single meaning.
/// Each line is one argument, taken literally, with [`ATTEMPT_WORKSPACE_PLACEHOLDER`]
/// and [`ANSWER_PLACEHOLDER`] substituted:
///
/// ```text
/// arg=exec
/// arg=-
/// arg=-C
/// arg={workspace}
/// arg=-o
/// arg={answer}
/// ```
///
/// A Codex compatibility override that never names [`ANSWER_PLACEHOLDER`] is
/// refused. A JCode invocation must name `api-stdio` and must not name the
/// answer placeholder: its typed terminal message is written by Automonique.
///
/// It exists for two stated reasons and no others. First, `-o` is the one flag
/// in [`DEFAULT_ARGV`] this build has never watched a provider release honour,
/// and an owner correcting a renamed flag should not need a rebuild of their
/// control plane. Second, the hermetic proof needs a provider it can run with no
/// network and no credential at all.
///
/// What it does **not** widen: an argument grants nothing. Paths, sockets and
/// variables come from the sandbox spec this module composes and from admission,
/// and no argv can add one. The furthest an override reaches is telling a
/// program the owner already chose to execute what to do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderConfig {
    engine: ProviderEngine,
    binary: PathBuf,
    home: PathBuf,
    version: String,
    argv: Vec<String>,
}

/// Protocol owner behind one configured executable. Omitted legacy configs
/// select the rollback-only Codex compatibility route during the production
/// canary; production configs explicitly select the supervised JCode protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderEngine {
    Codex,
    Jcode,
}

impl ProviderEngine {
    const fn integration_mode(self) -> &'static str {
        match self {
            Self::Codex => "codex-jsonl",
            Self::Jcode => "jcode-api-stdio-v1",
        }
    }
}

impl ProviderConfig {
    /// Read one provider configuration, or answer that there is none.
    ///
    /// An absent file is `Ok(None)`, which is the ordinary state of a
    /// deployment that has not been configured for `/run` and is answered as
    /// [`ComposeRefusal::NotConfigured`] by [`compose`]. A file that exists and
    /// cannot be read exactly is an error, so a misconfiguration is
    /// distinguishable from a deliberate absence.
    ///
    /// # Errors
    ///
    /// Returns [`ComposeRefusal::NotConfigured`] for a file that is not a
    /// bounded regular file, is not UTF-8, carries an unknown or duplicate key,
    /// omits a required key, or names a relative path.
    pub fn load(path: &Path) -> Result<Option<Self>, ComposeRefusal> {
        let Some(text) = read_bounded_text(path, MAX_PROVIDER_CONFIG_BYTES)? else {
            return Ok(None);
        };
        let rejected = || ComposeRefusal::NotConfigured;
        let mut binary: Option<PathBuf> = None;
        let mut home: Option<PathBuf> = None;
        let mut version: Option<String> = None;
        let mut engine: Option<ProviderEngine> = None;
        let mut argv: Vec<String> = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(rejected)?;
            let value = value.trim();
            if value.is_empty() {
                return Err(rejected());
            }
            let slot = match key.trim() {
                "engine" => {
                    let parsed = match value {
                        "codex" => ProviderEngine::Codex,
                        "jcode" => ProviderEngine::Jcode,
                        _ => return Err(rejected()),
                    };
                    if engine.replace(parsed).is_some() {
                        return Err(rejected());
                    }
                    continue;
                }
                "binary" => &mut binary,
                "home" => &mut home,
                "version" => {
                    if version.replace(value.to_owned()).is_some() {
                        return Err(rejected());
                    }
                    continue;
                }
                "arg" => {
                    if argv.len() >= MAX_ARGUMENTS {
                        return Err(rejected());
                    }
                    argv.push(value.to_owned());
                    continue;
                }
                _ => return Err(rejected()),
            };
            if slot.replace(PathBuf::from(value)).is_some() {
                return Err(rejected());
            }
        }
        let binary = binary.ok_or_else(rejected)?;
        let home = home.ok_or_else(rejected)?;
        let engine = engine.unwrap_or(ProviderEngine::Codex);
        let argv = if argv.is_empty() {
            if engine == ProviderEngine::Jcode {
                return Err(rejected());
            }
            DEFAULT_ARGV.iter().map(|arg| (*arg).to_owned()).collect()
        } else {
            // A run whose invocation never names the answer file can never
            // reply, so an override that omits it is a configuration error
            // rather than a provider that happens to say nothing.
            if engine == ProviderEngine::Codex
                && !argv.iter().any(|arg| arg.contains(ANSWER_PLACEHOLDER))
            {
                return Err(rejected());
            }
            if engine == ProviderEngine::Jcode
                && (!argv.iter().any(|arg| arg == "api-stdio")
                    || argv.iter().any(|arg| arg.contains(ANSWER_PLACEHOLDER)))
            {
                return Err(rejected());
            }
            argv
        };
        for path in [&binary, &home] {
            // A grant path must be absolute and canonical for the sandbox path
            // type as well as for the launch surface, and a relative provider
            // path would resolve against a working directory that says nothing
            // about which binary was meant.
            if automonique_protocol::sandbox::SandboxPath::new(path.to_str().ok_or_else(rejected)?)
                .is_err()
            {
                return Err(rejected());
            }
        }
        Ok(Some(Self {
            engine,
            binary,
            home,
            version: version.unwrap_or_else(|| String::from("provider")),
            argv,
        }))
    }

    /// Load the run-execution provider, refusing the retired direct `codex exec`
    /// engine.
    ///
    /// Run execution has one production engine: the pinned JCode `api-stdio`
    /// host. The direct Codex CLI JSONL path — `codex exec`, selected by a
    /// provider that resolves to [`ProviderEngine::Codex`] whose invocation is
    /// the Codex `exec` subcommand ([`DEFAULT_ARGV`], or any override that begins
    /// with `exec`) — was the temporary production fallback during the JCode
    /// canary and is retired (epic bext-stack/automonique#66; plan
    /// `docs/product-plan/unified-client-platform.md`, whose acceptance is
    /// "production provider configuration launches the pinned JCode engine
    /// rather than direct `codex exec`"). It is refused with
    /// [`ComposeRefusal::CodexEngineRetired`], so the run lane selects the JCode
    /// engine or reports no runnable provider rather than silently falling back
    /// to direct `codex exec`.
    ///
    /// The refusal is deliberately scoped to the direct Codex CLI, not to the
    /// shared answer-file mechanism [`ProviderEngine::Codex`] also expresses. The
    /// conversational chat adapter is a separate provider role that rides that
    /// mechanism with its own non-`exec` invocation and continues to load
    /// through the generic [`load`](Self::load) unchanged. An absent file remains
    /// `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Every error [`load`](Self::load) returns, plus
    /// [`ComposeRefusal::CodexEngineRetired`] for a provider that selects the
    /// retired direct `codex exec` engine.
    pub fn load_execution(path: &Path) -> Result<Option<Self>, ComposeRefusal> {
        match Self::load(path)? {
            Some(config) if config.is_direct_codex_cli() => Err(ComposeRefusal::CodexEngineRetired),
            other => Ok(other),
        }
    }

    /// Whether this provider is the retired direct Codex CLI: the Codex engine
    /// invoked through its `exec` subcommand.
    ///
    /// `codex exec` is the whole of the direct fallback the plan retires. A
    /// Codex-engine provider with a different invocation — the answer-file
    /// mechanism the conversational adapter and hermetic test providers ride —
    /// is not the Codex CLI and is not what this gate removes.
    #[must_use]
    fn is_direct_codex_cli(&self) -> bool {
        self.engine == ProviderEngine::Codex
            && self.argv.first().is_some_and(|argument| argument == "exec")
    }

    /// The provider binary this deployment runs.
    #[must_use]
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    #[must_use]
    pub const fn engine(&self) -> ProviderEngine {
        self.engine
    }

    /// The provider's isolated home directory, granted read-write.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// The recorded binary version; for JCode this is also the exact expected
    /// `hello_ok.server` identity used by the contained session host.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The invocation, before placeholder substitution.
    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }
}

/// One composed run: the document, its prompt, and the two paths a caller needs.
///
/// The prompt is carried beside the document rather than inside it, because a
/// RunSpec deliberately holds no prompt bytes: it holds a transport plan, and
/// the bytes live in the protected slot this names.
#[derive(Clone)]
pub struct Composition {
    run_id: String,
    prompt_slot: String,
    prompt: Vec<u8>,
    document: Vec<u8>,
    answer_path: PathBuf,
}

impl Composition {
    /// The run identity, which names the cgroup, the directory tree and the
    /// custody submission's idempotency key.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// The protected prompt slot the document routes its prompt through.
    #[must_use]
    pub fn prompt_slot(&self) -> &str {
        &self.prompt_slot
    }

    /// The prompt bytes, which a caller must place in the slot before the run
    /// is started.
    #[must_use]
    pub fn prompt(&self) -> &[u8] {
        &self.prompt
    }

    /// The canonical RunSpec bytes to submit to custody.
    #[must_use]
    pub fn document(&self) -> &[u8] {
        &self.document
    }

    /// Where the provider was told to write its final message.
    #[must_use]
    pub fn answer_path(&self) -> &Path {
        &self.answer_path
    }
}

/// Prompt bytes and a document are both protected content; neither is rendered.
impl core::fmt::Debug for Composition {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Composition")
            .field("run_id", &self.run_id)
            .field("prompt_slot", &self.prompt_slot)
            .field("prompt", &format_args!("<redacted:{}>", self.prompt.len()))
            .field("document", &format_args!("<{} bytes>", self.document.len()))
            .field("answer_path", &self.answer_path)
            .finish()
    }
}

/// Everything one composition needs that is not the task.
pub struct CompositionInputs<'a> {
    /// This daemon's private state directory. The workspace, the prompt slot
    /// and the answer file all resolve beneath it.
    pub state_dir: &'a Path,
    /// The run identity to compose for. The caller owns uniqueness; see
    /// [`compose`] for what this identifier has to satisfy.
    pub run_id: &'a str,
    /// The provider this deployment runs.
    pub provider: &'a ProviderConfig,
    /// What this host offers a document's enforcement negotiation, exactly as
    /// [`crate::execute::offered_host_features`] measured it.
    pub offered_features: &'a [HostFeature],
    /// Whether this deployment resolves any brokered destination at all.
    ///
    /// The destinations themselves are deliberately *not* an input: the
    /// document declares `brokered_named` and the admission context supplies
    /// the list, exactly as it does for a document written by anyone else. What
    /// this flag buys is a refusal the operator can read — "not configured" —
    /// instead of an `admission_refused` after a document was durably
    /// submitted.
    pub egress_configured: bool,
}

/// Compose one contained provider completion for `task`.
///
/// The document that comes out is the one shape this module can write:
///
/// - the configured provider binary, pinned to the digest this call observed;
/// - the invocation the owner's live vehicle established, plus
///   [`ANSWER_FLAG`] naming an absolute path in the run's own workspace;
/// - the task on the workload's stdin, routed through a protected prompt slot;
/// - `brokered_named` egress on both axes, so the run gets one loopback port
///   and no resolver, no UDP and no direct HTTPS;
/// - read-write on the provider's home and the workspace, read on the CA trust
///   store, and no other path at all.
///
/// # Errors
///
/// Returns [`ComposeRefusal::NotConfigured`] when the deployment resolves no
/// brokered destination, [`ComposeRefusal::HostUnenforceable`] when this host
/// offers no feature to negotiate against, [`ComposeRefusal::ProviderUnreadable`]
/// when the binary cannot be hashed, [`ComposeRefusal::TaskRejected`] for an
/// empty or oversized task, [`ComposeRefusal::IdentityRejected`] for a run
/// identity this daemon cannot turn into a path, and
/// [`ComposeRefusal::DocumentRejected`] when the composed parts are refused by
/// the RunSpec constructor.
pub fn compose(task: &str, inputs: &CompositionInputs<'_>) -> Result<Composition, ComposeRefusal> {
    compose_with_profile(task, inputs, ProviderRunProfile::Standard)
}

/// Compose one contained completion under an explicit trusted run profile.
///
/// Only the caller selects `profile`; task text is never inspected for it.
pub fn compose_with_profile(
    task: &str,
    inputs: &CompositionInputs<'_>,
    profile: ProviderRunProfile,
) -> Result<Composition, ComposeRefusal> {
    compose_inner(task, inputs, profile, None)
}

/// Compose a managed request whose normalized provider session remains
/// resumable by an exact later follow-up.
pub fn compose_managed(
    task: &str,
    inputs: &CompositionInputs<'_>,
    mode: ManagedSessionMode<'_>,
) -> Result<Composition, ComposeRefusal> {
    if let ManagedSessionMode::Resume(session_id) = mode {
        automonique_protocol::platform::ResourceId::new(session_id)
            .map_err(|_| ComposeRefusal::IdentityRejected)?;
    }
    compose_inner(task, inputs, ProviderRunProfile::Standard, Some(mode))
}

fn compose_inner(
    task: &str,
    inputs: &CompositionInputs<'_>,
    profile: ProviderRunProfile,
    managed_session: Option<ManagedSessionMode<'_>>,
) -> Result<Composition, ComposeRefusal> {
    if !inputs.egress_configured {
        return Err(ComposeRefusal::NotConfigured);
    }
    if inputs.offered_features.is_empty() {
        return Err(ComposeRefusal::HostUnenforceable);
    }
    let run_id = inputs.run_id;
    let prompt_slot = format!("{run_id}-prompt");
    // The run identity becomes a cgroup name, a directory name and a prompt
    // slot name. The slot is the longest of the three, so checking it covers
    // the others, and a composer that produced an identifier the lane refuses
    // would be writing a document that cannot run.
    if !is_safe_segment(run_id) || !is_safe_segment(&prompt_slot) {
        return Err(ComposeRefusal::IdentityRejected);
    }

    let prompt = task.trim().as_bytes().to_vec();
    if prompt.is_empty() || prompt.len() > crate::execute::MAX_PROMPT_BYTES {
        return Err(ComposeRefusal::TaskRejected);
    }

    let attempt_workspace_path = run_attempt_workspace(inputs.state_dir, run_id);
    let answer_path = attempt_workspace_path.join(ANSWER_LEAF);
    let (Some(attempt_workspace_text), Some(answer_text)) =
        (attempt_workspace_path.to_str(), answer_path.to_str())
    else {
        return Err(ComposeRefusal::IdentityRejected);
    };

    let provider_binary = observe_provider_binary(inputs.provider)?;
    let document = document(&DocumentParts {
        run_id,
        prompt_slot: &prompt_slot,
        provider: inputs.provider,
        provider_binary,
        offered_features: inputs.offered_features,
        attempt_workspace_path: attempt_workspace_text,
        answer: answer_text,
        profile,
        managed_session,
    })?;

    Ok(Composition {
        run_id: run_id.to_owned(),
        prompt_slot,
        prompt,
        document,
        answer_path,
    })
}

/// Read one composed run's answer back out of its attempt workspace.
///
/// This is the other half of the file the document named, and it is here rather
/// than at the caller so exactly one module knows what an answer is: `compose`
/// writes the path into the argv, this reads that path, and nothing in between
/// reconstructs either.
///
/// `None` means there is no answer to report — the file is absent, empty, not a
/// regular file, larger than [`MAX_ANSWER_BYTES`], or not text. Every one of
/// those is the same fact to a caller: the run reached a terminal state without
/// leaving an answer where it was told to.
#[must_use]
pub fn read_answer(path: &Path) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_ANSWER_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    // Bounded by one byte over the ceiling, so a file that grew between the
    // metadata read and the read is refused rather than read whole.
    file.take(MAX_ANSWER_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.is_empty() || u64::try_from(bytes.len()).ok()? > MAX_ANSWER_BYTES {
        return None;
    }
    let text = String::from_utf8(bytes).ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// Hash the configured binary and report it as the pin the document carries.
///
/// The schema digest is deliberately absent: this daemon speaks no provider
/// protocol, so it observes no schema, and [`crate::execute`] refuses a document
/// that pins one. The version travels from the configuration because
/// [`BinaryProvenance::matches`] compares digests and not versions.
fn observe_provider_binary(provider: &ProviderConfig) -> Result<BinaryProvenance, ComposeRefusal> {
    let file = fs::File::open(provider.binary()).map_err(|_| ComposeRefusal::ProviderUnreadable)?;
    let metadata = file
        .metadata()
        .map_err(|_| ComposeRefusal::ProviderUnreadable)?;
    if !metadata.is_file() || !is_within_byte_limit(metadata.len(), MAX_PROVIDER_BINARY_BYTES) {
        return Err(ComposeRefusal::ProviderUnreadable);
    }
    let mut bytes = Vec::new();
    file.take(MAX_PROVIDER_BINARY_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| ComposeRefusal::ProviderUnreadable)?;
    if !is_within_byte_limit(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        MAX_PROVIDER_BINARY_BYTES,
    ) {
        return Err(ComposeRefusal::ProviderUnreadable);
    }
    let observed = crate::execute::provider_binary_digest(&bytes);
    BinaryProvenance::new(provider.version(), &observed, None)
        .map_err(|_| ComposeRefusal::ProviderUnreadable)
}

/// Everything the document builder needs, already validated.
struct DocumentParts<'a> {
    run_id: &'a str,
    prompt_slot: &'a str,
    provider: &'a ProviderConfig,
    provider_binary: BinaryProvenance,
    offered_features: &'a [HostFeature],
    attempt_workspace_path: &'a str,
    answer: &'a str,
    profile: ProviderRunProfile,
    managed_session: Option<ManagedSessionMode<'a>>,
}

/// Every constructor in this module refuses the same way.
///
/// The document is composed from fixed values and validated inputs, so a
/// refusal from any of these constructors is this module's own bug rather than
/// a distinction a caller could act on. It is one word, and it is a refusal
/// rather than a panic because a control plane does not crash on a sentence.
fn rejected<E>(_error: E) -> ComposeRefusal {
    ComposeRefusal::DocumentRejected
}

/// Build and encode the one document shape this module writes.
fn document(parts: &DocumentParts<'_>) -> Result<Vec<u8>, ComposeRefusal> {
    let home = parts
        .provider
        .home()
        .to_str()
        .ok_or(ComposeRefusal::DocumentRejected)?;

    let spec = RunSpec::new(RunSpecParts {
        protocol_version: 1,
        coordinates: RunCoordinates::new(
            WorkId::new(format!("{}-work", parts.run_id)).map_err(rejected)?,
            RunId::new(parts.run_id).map_err(rejected)?,
            AttemptId::new(format!("{}-attempt", parts.run_id)).map_err(rejected)?,
            HostId::new(COMPOSE_PROFILE_ID).map_err(rejected)?,
            HostLifetime::Attempt,
            ExecutionBackendId::new(DAEMON_BACKEND_ID).map_err(rejected)?,
        ),
        executable: parts.provider.binary().to_path_buf(),
        arguments: argv(
            parts.provider.argv(),
            parts.attempt_workspace_path,
            parts.answer,
            parts.profile,
            parts.managed_session,
            parts.provider.engine(),
        ),
        // Opaque by construction: the resolution is the workspace registry's,
        // and this daemon is the registry. What it resolves to is
        // `run_attempt_workspace`, which is what the argv above already names.
        cwd_token: CwdToken::new(format!("{}-cwd", parts.run_id)).map_err(rejected)?,
        environment: environment(
            home,
            parts.attempt_workspace_path,
            parts.provider.engine(),
            parts.managed_session,
        ),
        // The transport, not the bytes. `execute` reads the slot and hands the
        // bytes to admission, which delivers them on the workload's stdin —
        // which is what `exec -` reads its prompt from.
        prompt: PromptDeliveryPlan::ProtectedReference(
            ProtectedPromptReference::new(parts.prompt_slot).map_err(rejected)?,
        ),
        attempt_workspace_registry_id: AttemptWorkspaceRegistryId::new(
            DAEMON_ATTEMPT_WORKSPACE_REGISTRY,
        )
        .map_err(rejected)?,
        attempt_workspace: AttemptWorkspaceRegistration::new(
            COMPOSE_TENANT,
            COMPOSE_PROFILE_ID,
            Revision::FIRST,
            &format!("{}-snapshot", parts.run_id),
            // Matches `FilesystemAccess::IsolatedWritable` below; the RunSpec
            // constructor cross-checks the pair and refuses a mismatch.
            IsolationKind::AttemptCopy,
            AttemptWorkspaceToken::new(&format!("{}-workspace", parts.run_id)).map_err(rejected)?,
        )
        .map_err(rejected)?,
        provider_binary: parts.provider_binary.clone(),
        sandbox: sandbox(parts, home)?,
        admission: admission_fields(parts.provider.engine()),
    })
    .map_err(rejected)?;
    spec.to_canonical_bytes().map_err(rejected)
}

/// The configured invocation, with the two coordinates resolved.
///
/// This is the whole of the substitution this module performs: every occurrence
/// of [`ATTEMPT_WORKSPACE_PLACEHOLDER`] and [`ANSWER_PLACEHOLDER`] becomes the absolute
/// path it names, and nothing else in an argument is touched. The task text is
/// deliberately not among the things that can be substituted — it reaches the
/// provider on stdin and never becomes an argument.
fn argv(
    configured: &[String],
    attempt_workspace: &str,
    answer: &str,
    profile: ProviderRunProfile,
    managed_session: Option<ManagedSessionMode<'_>>,
    engine: ProviderEngine,
) -> Vec<OsString> {
    let mut arguments: Vec<OsString> = configured
        .iter()
        .map(|argument| {
            OsString::from(
                argument
                    .replace(ATTEMPT_WORKSPACE_PLACEHOLDER, attempt_workspace)
                    .replace(ANSWER_PLACEHOLDER, answer),
            )
        })
        .collect();
    match (engine, managed_session) {
        (ProviderEngine::Codex, Some(ManagedSessionMode::New)) => {
            arguments.retain(|argument| argument != "--ephemeral");
            if !arguments.iter().any(|argument| argument == "--json") {
                arguments.push(OsString::from(crate::execute::PROVIDER_JSON_STREAM_ARG));
            }
        }
        (ProviderEngine::Codex, Some(ManagedSessionMode::Resume(session_id))) => {
            let sandbox = configured
                .windows(2)
                .find(|pair| pair[0] == "-s")
                .map_or("read-only", |pair| pair[1].as_str());
            let mut resumed = vec![
                OsString::from("-s"),
                OsString::from(sandbox),
                OsString::from("-C"),
                OsString::from(attempt_workspace),
                OsString::from("exec"),
                OsString::from("resume"),
            ];
            if configured
                .iter()
                .any(|argument| argument == "--skip-git-repo-check")
            {
                resumed.push(OsString::from("--skip-git-repo-check"));
            }
            resumed.extend([
                OsString::from("-o"),
                OsString::from(answer),
                OsString::from(crate::execute::PROVIDER_JSON_STREAM_ARG),
                OsString::from(session_id),
                OsString::from("-"),
            ]);
            arguments = resumed;
        }
        (ProviderEngine::Codex, None) | (ProviderEngine::Jcode, _) => {}
    }
    if arguments.first().is_some_and(|arg| arg == "exec")
        && profile == ProviderRunProfile::WebResearch
    {
        // The command itself is selected by trusted dispatch after an
        // explicit `/research` message. User text remains on stdin and can
        // never turn an ordinary question into a web-enabled run.
        //
        // Two spellings because the provider has two: the global `--search`
        // flag enables the native tool, and `web_search_mode="live"` is what
        // current releases actually consult before deciding whether to call
        // it. With the flag alone the model answered "web search is
        // unavailable in this session" and never searched.
        arguments.splice(
            1..1,
            [OsString::from("-c"), OsString::from(WEB_SEARCH_MODE_CONFIG)],
        );
        arguments.insert(0, OsString::from("--search"));
    }
    if profile == ProviderRunProfile::FastConversation
        && arguments.first().is_some_and(|arg| arg == "exec")
    {
        // `-c` is a Codex global option. Place it directly after the `exec`
        // subcommand so the prompt marker and all operator text remain stdin
        // data, never arguments capable of selecting this profile.
        arguments.splice(
            1..1,
            [
                OsString::from("-c"),
                OsString::from(QUESTION_MODEL_CONFIG),
                OsString::from("-c"),
                OsString::from(QUESTION_REASONING_CONFIG),
            ],
        );
    }
    if profile == ProviderRunProfile::AgenticScratchpad
        && arguments.first().is_some_and(|arg| arg == "exec")
    {
        // The execution profile is selected by trusted dispatch after an
        // authenticated administrator approves the frozen task. User text is
        // stdin data and cannot select or widen this profile. Replace only
        // Codex's reviewed `-s read-only` pair; an owner-configured provider
        // with a different argv retains its exact invocation and remains
        // bounded by the outer workspace and runtime grants below.
        for pair in arguments.windows(2).enumerate() {
            let (index, pair) = pair;
            if pair[0] == "-s" && pair[1] == "read-only" {
                arguments[index + 1] = OsString::from("workspace-write");
                break;
            }
        }
    }
    arguments
}

/// Every variable the workload gets, and nothing else: the launch inherits none.
///
/// `HTTPS_PROXY` and `HTTP_PROXY` are deliberately absent. They are bound by
/// [`automonique_runner::admission::AdmittedLaunch::with_broker`] to this run's
/// own broker, and a document that bound either itself would be refused a
/// broker outright — a plan refuses one name bound twice.
///
/// A JCode workload also gets `JCODE_NO_TELEMETRY=1`. The sandbox has no
/// telemetry egress, so the opt-out changes nothing the engine can reach; it
/// only stops the engine's opt-out notice from being written into every
/// contained run's journal.
fn environment(
    home: &str,
    attempt_workspace: &str,
    engine: ProviderEngine,
    managed_session: Option<ManagedSessionMode<'_>>,
) -> Vec<(OsString, OsString)> {
    let mut environment = vec![
        (
            OsString::from(match engine {
                ProviderEngine::Codex => "CODEX_HOME",
                ProviderEngine::Jcode => "JCODE_HOME",
            }),
            OsString::from(home),
        ),
        // Admission clears the ambient environment, including
        // XDG_RUNTIME_DIR. Keep JCode's shared server socket beneath the same
        // already-authorized private home instead of letting it fall back to
        // an ungranted host /tmp path.
        (OsString::from("JCODE_RUNTIME_DIR"), OsString::from(home)),
        (OsString::from("JCODE_NO_TELEMETRY"), OsString::from("1")),
        // Provider-neutral coordinate used by small contained adapters. The
        // credential remains a file below this already-granted home; no secret
        // is copied into the environment or the run document.
        (
            OsString::from("AUTOMONIQUE_PROVIDER_HOME"),
            OsString::from(home),
        ),
        // The provider's home directory, pointed at the run's own attempt workspace so
        // a provider that writes dotfiles writes them inside the boundary.
        (OsString::from("HOME"), OsString::from(attempt_workspace)),
        (OsString::from("PATH"), OsString::from(COMPOSE_PATH)),
        (OsString::from("TERM"), OsString::from("dumb")),
        (OsString::from("SSL_CERT_FILE"), OsString::from(CA_BUNDLE)),
        (OsString::from("SSL_CERT_DIR"), OsString::from(CA_DIRECTORY)),
    ];
    if engine == ProviderEngine::Codex {
        environment.retain(|(name, _)| name != "JCODE_RUNTIME_DIR" && name != "JCODE_NO_TELEMETRY");
    }
    if engine == ProviderEngine::Jcode
        && let Some(ManagedSessionMode::Resume(session_id)) = managed_session
    {
        environment.push((
            OsString::from("AUTOMONIQUE_JCODE_SESSION_ID"),
            OsString::from(session_id),
        ));
    }
    environment
}

/// The sandbox this composition declares.
fn sandbox(parts: &DocumentParts<'_>, home: &str) -> Result<SandboxSpec, ComposeRefusal> {
    // Both axes brokered, because this launch builds one boundary around one
    // process tree: admission refuses a document whose two egress axes
    // disagree, and would be right to.
    let egress = NetworkAccess::BrokeredNamed;
    SandboxSpec::compile(SandboxSpecParts {
        profile: SandboxProfile::new(
            COMPOSE_PROFILE_ID,
            COMPOSE_PROFILE_VERSION,
            FilesystemAccess::IsolatedWritable,
            ToolWorkloadEgress::brokered(egress),
        )
        .map_err(rejected)?,
        policy_digest: PolicyDigest::parse(&declared_digest("policy")).map_err(rejected)?,
        actor: Actor::new(COMPOSE_TENANT, COMPOSE_ACTOR).map_err(rejected)?,
        provider_account: ProviderAccountId::new(parts.provider.version()).map_err(rejected)?,
        workspace_context: WorkspaceContextHash::parse(&declared_digest("workspace-context"))
            .map_err(rejected)?,
        base_revision: Revision::FIRST,
        // The attempt workspace and the executable are granted by admission itself; a
        // document naming either again would collide, because two grants for
        // one path have no single meaning. What is left is the provider's own
        // home and the CA trust store.
        path_grants: scratchpad_path_grants(parts.profile, parts.provider.engine(), home)?,
        // Named execution allowlists remain empty because this launch has no
        // registry that maps those names. Exact executable authority is carried
        // by the provider path plus any explicit read_execute path grants.
        allowlists: ExecutionAllowlists::declare(&[]).map_err(rejected)?,
        provider_control_egress: ProviderControlEgress::brokered(egress),
        tool_workload_egress: ToolWorkloadEgress::brokered(egress),
        // No credential travels in the document. The provider's authorization is
        // a file inside its own home, reached by the read-write grant above and
        // never by a variable that would land in `/proc/<pid>/environ`.
        credentials: CredentialDescriptors::declare(&[]).map_err(rejected)?,
        budgets: Budgets::declare(BudgetQuantities {
            cgroup_memory_bytes: match parts.profile {
                ProviderRunProfile::Standard | ProviderRunProfile::AgenticScratchpad => {
                    COMPOSE_MEMORY_BYTES
                }
                ProviderRunProfile::FastConversation | ProviderRunProfile::IntelligentQuestion => {
                    QUESTION_MEMORY_BYTES
                }
                ProviderRunProfile::WebResearch => QUESTION_MEMORY_BYTES,
            },
            cgroup_cpu_millicores: 4_000,
            rlimit_processes: COMPOSE_PROCESSES,
            rlimit_descriptors: 1_024,
            timeout_millis: COMPOSE_TIMEOUT_MILLIS,
            temporary_storage_bytes: 64 * 1024 * 1024,
            spool_bytes: COMPOSE_SPOOL_BYTES,
            artifact_bytes: MAX_ANSWER_BYTES,
        })
        .map_err(rejected)?,
        // Require exactly what this host measured itself to enforce. A document
        // requiring nothing would admit on a host that enforces nothing, which
        // is why an empty set is refused and why an unmeasured host cannot
        // compose at all.
        required_features: features_requiring(parts.offered_features)?,
        nested_isolation: NestedIsolation::new(
            IsolationRequirement::HostBoundary,
            IsolationRequirement::HostBoundary,
        ),
        approval_revision: Revision::FIRST,
        prohibited_capabilities: ProhibitedCapabilities::declare(&[]).map_err(rejected)?,
    })
    .map_err(rejected)
}

/// Declare the profile's complete non-workspace filesystem authority.
///
/// The provider home and CA roots are common to all runs. Only the trusted
/// agentic profile adds executable system runtimes, and those roots remain
/// non-writable. The per-attempt workspace is supplied separately by
/// admission from the run's opaque workspace registration.
fn scratchpad_path_grants(
    profile: ProviderRunProfile,
    engine: ProviderEngine,
    home: &str,
) -> Result<PathGrants, ComposeRefusal> {
    let mut grants = vec![
        PathGrant::new(home, PathAccess::ReadWrite).map_err(rejected)?,
        PathGrant::new(CA_DIRECTORY, PathAccess::ReadOnly).map_err(rejected)?,
    ];
    // The installed JCode engine is dynamically linked and must start its
    // pinned server child after Landlock is active. Codex's current fallback
    // binary is self-contained, so this additional runtime grant belongs only
    // to the JCode execution mode.
    if engine == ProviderEngine::Jcode {
        grants.extend([
            PathGrant::new(SCRATCHPAD_RUNTIME_LIB, PathAccess::ReadExecute).map_err(rejected)?,
            // The contained client opens no ambient descriptors, but JCode's
            // supervised server child deliberately directs stdout to the null
            // device after Landlock is active.
            PathGrant::new(JCODE_NULL_DEVICE, PathAccess::ReadWrite).map_err(rejected)?,
        ]);
    }
    if profile == ProviderRunProfile::AgenticScratchpad {
        grants.push(
            PathGrant::new(SCRATCHPAD_RUNTIME_BIN, PathAccess::ReadExecute).map_err(rejected)?,
        );
        if engine != ProviderEngine::Jcode {
            grants.push(
                PathGrant::new(SCRATCHPAD_RUNTIME_LIB, PathAccess::ReadExecute)
                    .map_err(rejected)?,
            );
        }
        grants.push(
            PathGrant::new(SCRATCHPAD_RUNTIME_SHARE, PathAccess::ReadOnly).map_err(rejected)?,
        );
    }
    PathGrants::declare(&grants).map_err(rejected)
}

/// Require every feature this host offers, at the implementation it offers.
fn features_requiring(offered: &[HostFeature]) -> Result<RequiredFeatures, ComposeRefusal> {
    let mut required = Vec::with_capacity(offered.len());
    for feature in offered {
        required.push(
            RequiredFeature::new(
                feature.name(),
                std::slice::from_ref(feature.implementation()),
            )
            .map_err(|_| ComposeRefusal::DocumentRejected)?,
        );
    }
    RequiredFeatures::declare(&required).map_err(|_| ComposeRefusal::DocumentRejected)
}

/// The runner-owned admission fields, every one of which this launch either
/// leaves empty or sets to the single value admission will accept.
///
/// Nothing here is negotiable: `admission` refuses a session binding, a
/// fallback list, a required capability, an artifact grant, a credential
/// binding, an unpinned portability policy and a remote attestation
/// requirement, each because it names a subsystem this build does not have. A
/// composer that set any of them would be writing a document it knows will be
/// refused.
fn admission_fields(engine: ProviderEngine) -> AdmissionFields {
    let mode =
        IntegrationMode::new(engine.integration_mode()).expect("a fixed, bounded integration mode");
    AdmissionFields::new(AdmissionFieldsParts {
        io_reservation: IoReservation::new(1024, 1024).expect("a fixed, bounded reservation"),
        workspace_reservation: WorkspaceReservation::new(8_192).expect("a fixed reservation"),
        session_binding: None,
        fallback_eligibility: FallbackEligibility::declare(&mode, Vec::new())
            .expect("an empty fallback list"),
        integration_mode: mode,
        required_capabilities: RequiredCapabilities::declare(Vec::new())
            .expect("an empty capability list"),
        context_manifest: ContextManifest::new(
            Revision::FIRST,
            TokenBudget::new(0),
            Vec::new(),
            Vec::new(),
        ),
        profile_digest: parsed_digest::<ProfileDigest>("profile"),
        model_routing_digest: parsed_digest::<ModelRoutingDigest>("model-routing"),
        toolset_digest: parsed_digest::<ToolsetDigest>("toolset"),
        skillset_digest: parsed_digest::<SkillsetDigest>("skillset"),
        extension_set_digest: parsed_digest::<ExtensionSetDigest>("extension-set"),
        origin: RunOrigin::Interactive,
        executor_class: ExecutorClass::Local,
        portability_policy: PortabilityPolicy::Pinned,
        remote_attestation_policy: RemoteAttestationPolicy::NotRequired,
        persona_digest: parsed_digest::<PersonaDigest>("persona"),
        execution_plan_digest: parsed_digest::<ExecutionPlanDigest>("execution-plan"),
        scheduler_reservation: SchedulerReservationBinding::new(
            SchedulerReservationId::new(COMPOSE_PROFILE_ID).expect("a fixed reservation identity"),
            Revision::FIRST,
            parsed_digest::<SchedulerDecisionDigest>("scheduler-decision"),
        ),
        artifact_grants: ArtifactGrantBindings::declare(Vec::new()).expect("no artifact grants"),
        credential_bindings: Vec::new(),
        event_dialect: RunnerEventDialect::AutomoniqueRunnerV1,
    })
}

/// A digest over what this composer *declared*, rather than a placeholder.
///
/// Every one of these fields pins a subsystem that resolves inside a provider —
/// a persona, a toolset, a routing table — and this build resolves none of them,
/// so there is no artefact to hash. The alternative to a made-up constant is to
/// say plainly what is being pinned: the digest is the SHA-256 of
///
/// ```text
/// automonique.compose.v1
/// field=<field>
/// profile=<profile id>@<profile version>
/// ```
///
/// so it is a content identity of *this composition's declaration about that
/// field*, and it changes when the composed shape changes. It is not a digest of
/// a toolset, and nothing here pretends it is.
fn declared_digest(field: &str) -> String {
    let statement = format!(
        "{COMPOSE_DOMAIN}\nfield={field}\nprofile={COMPOSE_PROFILE_ID}@{COMPOSE_PROFILE_VERSION}\n"
    );
    format!(
        "{ALGORITHM}:{}",
        Sha256::digest(statement.as_bytes()).to_hex()
    )
}

/// [`declared_digest`], parsed into whichever tagged digest the field wants.
///
/// The parse cannot fail: the input is this crate's own hex of a SHA-256, and
/// every one of these types accepts exactly that spelling. It is spelled as an
/// expectation rather than threaded through a result because a failure here
/// would be a broken digest formatter, not an operator's mistake.
fn parsed_digest<D: DeclaredDigest>(field: &str) -> D {
    D::parse_declared(&declared_digest(field))
}

/// The tagged-digest types this composer declares, behind one parse.
trait DeclaredDigest: Sized {
    /// Parse this crate's own `sha256:<hex>` spelling.
    fn parse_declared(value: &str) -> Self;
}

macro_rules! declared_digest_for {
    ($($type:ty),+ $(,)?) => {
        $(impl DeclaredDigest for $type {
            fn parse_declared(value: &str) -> Self {
                Self::parse(value).expect("a composer-declared sha256 digest parses")
            }
        })+
    };
}

declared_digest_for!(
    ProfileDigest,
    ModelRoutingDigest,
    ToolsetDigest,
    SkillsetDigest,
    ExtensionSetDigest,
    PersonaDigest,
    ExecutionPlanDigest,
    SchedulerDecisionDigest,
);

/// Read a whole bounded regular file as text, or answer that there is none.
fn read_bounded_text(path: &Path, limit: u64) -> Result<Option<String>, ComposeRefusal> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ComposeRefusal::NotConfigured),
    };
    let metadata = file.metadata().map_err(|_| ComposeRefusal::NotConfigured)?;
    // The same private-file discipline every other owner-written input in this
    // state directory is held to: a world-readable provider configuration names
    // the directory a credential lives in.
    if !metadata.is_file() || metadata.len() > limit || metadata.permissions().mode() & 0o077 != 0 {
        return Err(ComposeRefusal::NotConfigured);
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| ComposeRefusal::NotConfigured)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(ComposeRefusal::NotConfigured);
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| ComposeRefusal::NotConfigured)
}

/// The bounded safe-name rule [`crate::execute`] applies to every identifier it
/// turns into a path, restated here so a composer never produces one that lane
/// would refuse.
fn is_safe_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[cfg(test)]
mod codex_retirement_tests {
    use super::{ComposeRefusal, ProviderConfig, ProviderEngine};
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    /// Write a private (0o600) provider configuration in a fresh temporary
    /// directory and return its path. The directory is leaked deliberately: a
    /// unit test process is short-lived and the file lives under the system
    /// temporary root, never the daemon state directory.
    fn private_provider(body: &str) -> PathBuf {
        let dir = tempfile::tempdir().expect("temporary directory");
        let path = dir.path().join("provider");
        let mut file = std::fs::File::create(&path).expect("provider file");
        file.write_all(body.as_bytes()).expect("provider body");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("private provider file");
        // Keep the directory alive for the lifetime of the test binary.
        std::mem::forget(dir);
        path
    }

    const JCODE: &str = "engine=jcode\nbinary=/bin/true\nhome=/tmp\narg=--quiet\narg=api-stdio\n";
    // The direct Codex CLI, explicit engine, with a `codex exec` invocation.
    const CODEX_EXEC_EXPLICIT: &str =
        "engine=codex\nbinary=/bin/true\nhome=/tmp\narg=exec\narg=--json\narg={answer}\n";
    // The historical production fallback: an omitted engine (Codex default) and
    // an omitted argv, which `load` fills with the `codex exec` DEFAULT_ARGV.
    const CODEX_EXEC_DEFAULT: &str = "binary=/bin/true\nhome=/tmp\n";
    // A Codex-engine provider that is NOT the Codex CLI: the answer-file
    // mechanism the conversational chat adapter rides (a non-`exec` invocation).
    const CODEX_ANSWER_FILE: &str = "binary=/bin/true\nhome=/tmp\narg=--output\narg={answer}\n";

    #[test]
    fn load_execution_refuses_an_explicit_direct_codex_exec_provider() {
        let path = private_provider(CODEX_EXEC_EXPLICIT);
        assert_eq!(
            ProviderConfig::load_execution(&path),
            Err(ComposeRefusal::CodexEngineRetired),
        );
    }

    #[test]
    fn load_execution_refuses_the_omitted_config_that_defaults_to_codex_exec() {
        let path = private_provider(CODEX_EXEC_DEFAULT);
        // load fills DEFAULT_ARGV, whose first argument is the `exec` subcommand.
        assert_eq!(
            ProviderConfig::load(&path)
                .expect("loads")
                .expect("present")
                .argv()
                .first()
                .map(String::as_str),
            Some("exec"),
        );
        assert_eq!(
            ProviderConfig::load_execution(&path),
            Err(ComposeRefusal::CodexEngineRetired),
        );
    }

    #[test]
    fn load_execution_accepts_the_pinned_jcode_run_engine() {
        let path = private_provider(JCODE);
        let provider = ProviderConfig::load_execution(&path)
            .expect("jcode run engine loads")
            .expect("provider present");
        assert_eq!(provider.engine(), ProviderEngine::Jcode);
    }

    #[test]
    fn load_execution_leaves_an_unconfigured_deployment_unconfigured() {
        let missing = Path::new("/nonexistent/automonique/provider");
        assert_eq!(ProviderConfig::load_execution(missing), Ok(None));
    }

    #[test]
    fn load_execution_accepts_the_non_cli_answer_file_mechanism() {
        // Retiring the direct `codex exec` engine must not remove the shared
        // answer-file mechanism a non-CLI Codex-engine provider (the
        // conversational adapter, hermetic test providers) rides. A Codex-engine
        // provider whose invocation is not `codex exec` still loads for
        // execution.
        let path = private_provider(CODEX_ANSWER_FILE);
        let provider = ProviderConfig::load_execution(&path)
            .expect("non-CLI codex-mechanism provider still loads for execution")
            .expect("provider present");
        assert_eq!(provider.engine(), ProviderEngine::Codex);
    }

    #[test]
    fn the_generic_loader_still_accepts_every_codex_style_provider() {
        // The conversational chat adapter loads through the generic loader, a
        // separate provider role from run execution. Retiring the direct Codex
        // *run* engine must not disturb it, so the generic loader still accepts
        // even a `codex exec` configuration.
        for body in [CODEX_EXEC_EXPLICIT, CODEX_EXEC_DEFAULT, CODEX_ANSWER_FILE] {
            let path = private_provider(body);
            let provider = ProviderConfig::load(&path)
                .expect("codex-style provider still loads")
                .expect("provider present");
            assert_eq!(provider.engine(), ProviderEngine::Codex);
        }
    }

    #[test]
    fn the_retirement_refusal_names_the_jcode_engine() {
        assert_eq!(
            ComposeRefusal::CodexEngineRetired.category(),
            "codex_engine_retired",
        );
        let message = ComposeRefusal::CodexEngineRetired.to_string();
        assert!(message.contains("JCode"), "{message}");
        assert!(message.contains("retired"), "{message}");
    }
}
