// SPDX-License-Identifier: Elastic-2.0

//! The typed bridge from an admitted [`RunSpec`] to one sandboxed launch.
//!
//! A [`RunSpec`] is a complete, immutable, declarative admission document. A
//! [`LaunchPlan`] plus [`ContainmentLimits`] is a complete, imperative
//! description of one attempt's enforcement. Neither can be derived from the
//! other alone: a RunSpec deliberately carries no host paths (its working
//! directory is an opaque [`CwdToken`](crate::CwdToken)), no prompt bytes (its
//! prompt is a transport plan), and no statement about what the host offers.
//! This module supplies the missing half as an explicit
//! [`AdmissionContext`] and produces either an [`AdmittedLaunch`] or a typed
//! [`AdmissionRefusal`].
//!
//! The mapping is pure. Nothing here opens, stats, reads, or writes anything;
//! grant paths are validated lexically by the launch surface and are opened
//! only at enforcement time, inside the entry helper.
//!
//! # Refuse, never drop
//!
//! Every RunSpec field either
//!
//! - **maps** onto the plan, the limits, or an [`AdmittedLaunch`] output field;
//! - **refuses** with [`AdmissionRefusal::UnmappableField`] naming it, because
//!   honouring it needs a subsystem that does not exist yet; or
//! - is on the closed, published [`INFORMATIONAL_FIELDS`] list of fields this
//!   bridge explicitly does not consult, each with a stated reason.
//!
//! There is no fourth case. A field that grants or restricts something is
//! never quietly ignored, and no refused field is silently replaced by a
//! default. The one place where a declaration is knowingly left unenforced —
//! budgets with no enforcement surface in this crate — requires the caller to
//! name each one in advance through [`AdmissionContext`], is refused when it
//! is not named, and is republished on the admitted value by
//! [`AdmittedLaunch::unenforced_budgets`].
//!
//! # What admission does **not** establish
//!
//! - **Admission is not authority.** An [`AdmittedLaunch`] is data. Nothing
//!   here starts a process, creates a cgroup, or installs a policy; the
//!   supervisor still has to, and [`Runner`](crate::Runner) is still
//!   fail-closed.
//! - **It is not a release trust chain.** The RunSpec pins the provider binary
//!   by digest, and this bridge only checks that pin against the provenance
//!   the caller says it observed. Hashing the file on disk, and trusting the
//!   party that signed it, are both outside this module and outside this crate.
//! - **There is no daemon lane.** A prompt routed through a provider session,
//!   a credential binding, an artifact grant, and a scheduler-arranged
//!   fallback each name a subsystem that has not been built; every one of them
//!   is a refusal here rather than a partial launch.
//! - **The plan cannot change its own working directory.** The launch frame
//!   has no `cwd` line, so the workload starts in whatever directory the
//!   supervisor is in. Admission resolves and publishes
//!   [`AdmittedLaunch::working_directory`] and proves it lies inside the
//!   resolved workspace root; it cannot prove the supervisor honours it.
//! - **Admission does not start a broker.** A spec asking for `brokered_named`
//!   egress is admitted with a [`BrokerRequirement`] naming the destinations
//!   and a plan that carries *no* network grant at all. The grants appear only
//!   when a supervisor that has actually started a broker attaches it with
//!   [`AdmittedLaunch::with_broker`], because the port it grants is that
//!   broker's own ephemeral port and does not exist until it is bound.
//! - **A capability is not a kernel boundary.** Provider capabilities,
//!   prohibited capabilities and execution allowlists are named subjects, not
//!   paths, and no registry maps a name to a path here, so a spec that carries
//!   any of them is refused rather than approximated.
//!
//! # Determinism
//!
//! One spec and one context produce one plan, byte for byte: every list is
//! walked in its declared order, the grant order is fixed
//! (executable, workspace root, then the sandbox's path grants in spec order),
//! and nothing is collected through an unordered container.

use crate::filesystem::PathIntent;
use crate::{
    ContainmentLimits, LaunchPlan, LaunchPlanError, MAX_RUN_ID_BYTES, PortabilityPolicy,
    PromptDeliveryPlan, ProtectedPromptReference, RemoteAttestationPolicy, RunSpec, RunSpecDigest,
    RunSpecEncodeError, WorkspaceRegistryId,
};
use automonique_protocol::models::ExecutorClass;
use automonique_protocol::provider::BinaryProvenance;
use automonique_protocol::sandbox::{
    Digest, DigestAlgorithm, ExecutionBackendId, FilesystemAccess, HostFeature,
    IsolationRequirement, NetworkAccess, PathAccess, SandboxError,
};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Upper bound on the host features one context may offer.
pub const MAX_OFFERED_FEATURES: usize = 64;

/// Upper bound on a context path, matching the launch surface's own ceiling.
pub const MAX_CONTEXT_PATH_BYTES: usize = crate::MAX_LAUNCH_ARG_BYTES;

/// Upper bound on the destinations one brokered launch may name.
///
/// Deliberately the egress broker's own `MAX_ALLOWLIST_ENTRIES`. A launch that
/// named more destinations than a broker will hold would be admitted against a
/// policy no broker could be started with, so the two ceilings are one number
/// written in two crates that do not depend on each other, and
/// [`BrokerRequirement`] is what a test pins them together through.
pub const MAX_BROKERED_DESTINATIONS: usize = 16;

/// Upper bound on a destination host, in bytes — the DNS name limit.
pub const MAX_DESTINATION_HOST_BYTES: usize = 253;

/// The two variables that point a brokered workload at its broker.
///
/// Both are bound to the same URL, which is the pair the egress broker
/// publishes: a provider's HTTPS and websocket transports tunnel through
/// `HTTPS_PROXY`, and `HTTP_PROXY` turns a plaintext request — which the broker
/// answers only with a refusal, since it speaks `CONNECT` alone — into a visible
/// refusal rather than a direct connection attempt.
pub const BROKER_PROXY_VARIABLES: [&str; 2] = ["HTTPS_PROXY", "HTTP_PROXY"];

/// Spec fields this bridge deliberately does not consult, and why.
///
/// This list is closed and asserted by the module's tests. A field is on it
/// only because reading it could not change the plan, the limits, or the
/// refusal: it identifies, audits, or accounts for the run rather than
/// granting or restricting anything the launch enforces.
///
/// - `work_id`, `attempt_id`, `host_id` — lifecycle identity. The run
///   identifier is consulted, because it names the containment cgroup.
/// - `host_lifetime` — how long the host this plan starts may serve later
///   turns, which is the supervisor's concern and not the plan's.
/// - `workspace.source`, `workspace.base_revision`, `workspace.snapshot`,
///   `workspace.token`, `workspace.tenant` — registry bookkeeping.
///   [`RunSpec::new`] has already cross-checked them against the sandbox spec,
///   and the runtime resolution arrives through the context.
/// - `provider_binary.version` — [`BinaryProvenance::matches`] compares the
///   binary and schema digests and is the authority on identity here.
/// - `sandbox.policy_digest`, `sandbox.workspace_context`,
///   `sandbox.approval_revision`, `sandbox.actor`, `sandbox.provider_account`,
///   `sandbox.base_revision` — review and identity provenance.
/// - `admission.io_reservation`, `admission.workspace_reservation`,
///   `admission.scheduler_reservation` — scheduler accounting. They record
///   what was promised to the run, not a ceiling any mechanism here applies.
/// - `admission.integration_mode` — how the provider is driven, which the
///   executable and argv already spell out concretely.
/// - `admission.context_manifest` — context composition, resolved before the
///   prompt reaches this bridge as bytes.
/// - `admission.profile_digest`, `admission.model_routing_digest`,
///   `admission.toolset_digest`, `admission.skillset_digest`,
///   `admission.extension_set_digest`, `admission.persona_digest`,
///   `admission.execution_plan_digest` — pins on subsystems that resolve
///   inside the provider, which this launch neither builds nor inspects.
/// - `admission.origin` — provenance of the request.
/// - `admission.event_dialect` — the spool's record format.
pub const INFORMATIONAL_FIELDS: [&str; 30] = [
    "work_id",
    "attempt_id",
    "host_id",
    "host_lifetime",
    "workspace.source",
    "workspace.base_revision",
    "workspace.snapshot",
    "workspace.token",
    "workspace.tenant",
    "provider_binary.version",
    "sandbox.policy_digest",
    "sandbox.workspace_context",
    "sandbox.approval_revision",
    "sandbox.actor",
    "sandbox.provider_account",
    "sandbox.base_revision",
    "admission.io_reservation",
    "admission.workspace_reservation",
    "admission.scheduler_reservation",
    "admission.integration_mode",
    "admission.context_manifest",
    "admission.origin",
    "admission.event_dialect",
    "admission.profile_digest",
    "admission.model_routing_digest",
    "admission.toolset_digest",
    "admission.skillset_digest",
    "admission.extension_set_digest",
    "admission.persona_digest",
    "admission.execution_plan_digest",
];

/// A budget the spec declares that this crate has no mechanism to enforce.
///
/// Each one is a real declaration, so admission refuses to proceed until the
/// caller has named it. Naming it is not a waiver of the budget: it is a
/// statement that the caller knows this launch does not apply it, and the
/// acknowledgement is carried on the admitted value so a supervisor can record
/// or re-check it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum UnenforcedBudget {
    /// `cgroup_cpu_millicores`. Nothing in [`ContainmentLimits`] writes
    /// `cpu.max`, and there is no other CPU ceiling in this crate.
    CgroupCpu,
    /// `rlimit_descriptors`. The launch closes every descriptor but the
    /// standard streams; it never sets `RLIMIT_NOFILE`, so a workload that
    /// opens more is bounded by the host, not by this budget.
    RlimitDescriptors,
    /// `temporary_storage_bytes`. No temporary filesystem is created or
    /// quota-bounded here.
    TemporaryStorage,
    /// `artifact_bytes`. Artifact collection is a separate, unbuilt subsystem.
    Artifact,
}

impl UnenforcedBudget {
    /// Every unenforced budget, in the order admission checks them.
    pub const ALL: [Self; 4] = [
        Self::CgroupCpu,
        Self::RlimitDescriptors,
        Self::TemporaryStorage,
        Self::Artifact,
    ];

    /// The exact spec field this budget names.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CgroupCpu => "sandbox.budgets.cgroup_cpu",
            Self::RlimitDescriptors => "sandbox.budgets.rlimit_descriptors",
            Self::TemporaryStorage => "sandbox.budgets.temporary_storage",
            Self::Artifact => "sandbox.budgets.artifact",
        }
    }
}

/// Where an allowlisted destination is expected to live.
///
/// A mirror of the egress broker's own `AddressScope`, kept in this crate so
/// admission can name a destination without depending on the broker. It carries
/// no policy of its own: the broker is what checks a resolved address against
/// it, and this is the word admission passes along.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BrokeredScope {
    /// A public internet endpoint.
    Public,
    /// An endpoint on this host.
    Loopback,
}

impl BrokeredScope {
    /// Every scope, for closed coverage.
    pub const ALL: [Self; 2] = [Self::Public, Self::Loopback];

    /// Stable spelling, matching the broker's own.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Loopback => "loopback",
        }
    }

    /// Parse the exact stable spelling.
    #[must_use]
    pub fn from_spelling(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|scope| scope.as_str() == value)
    }
}

impl fmt::Display for BrokeredScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One destination a brokered launch must be able to reach, and nothing else.
///
/// # This type bounds a host; it does not parse one
///
/// The egress broker's own `Destination` is the authority on what a destination
/// *is* — which spellings are a name, which are a literal, and which are
/// refused. This type exists so an admitted launch can carry the destinations it
/// was admitted for without this crate acquiring the broker as a dependency, and
/// it therefore checks only bounds and a byte set. A caller resolves a
/// destination through the broker's parser first and hands the result here; the
/// broker parses it again when the allowlist is built, and because both parses
/// are the same function the second cannot disagree with the first.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BrokeredDestination {
    host: String,
    port: u16,
    scope: BrokeredScope,
}

impl BrokeredDestination {
    /// Name one destination.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionRefusal::ContextRejected`] for an empty or over-long
    /// host, a host carrying a byte outside the letter/digit/hyphen/dot/colon/
    /// bracket set an allowlist entry can be written with, or port zero — which
    /// is not a port but a request for one.
    pub fn new(host: &str, port: u16, scope: BrokeredScope) -> Result<Self, AdmissionRefusal> {
        let rejected = || AdmissionRefusal::ContextRejected("brokered_destinations");
        if host.is_empty() || host.len() > MAX_DESTINATION_HOST_BYTES || port == 0 {
            return Err(rejected());
        }
        if !host.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b':' | b'[' | b']')
        }) {
            return Err(rejected());
        }
        Ok(Self {
            host: host.to_owned(),
            port,
            scope,
        })
    }

    /// The host as written.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The scope its resolved address must fall in.
    #[must_use]
    pub const fn scope(&self) -> BrokeredScope {
        self.scope
    }
}

impl fmt::Display for BrokeredDestination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.host, self.port)
    }
}

/// The destinations an admitted launch needs a broker to permit.
///
/// Its presence on an [`AdmittedLaunch`] is the "a broker is required" signal:
/// a supervisor that finds one must start a broker over exactly these
/// destinations and attach it with [`AdmittedLaunch::with_broker`] before the
/// plan is run, and a supervisor that finds none must start no broker at all.
/// The set is never empty — [`admit`] refuses a brokered spec whose destinations
/// were not resolved rather than admitting one with an allowlist that permits
/// nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerRequirement {
    destinations: Vec<BrokeredDestination>,
}

impl BrokerRequirement {
    /// The exact destinations, in the order the context named them.
    #[must_use]
    pub fn destinations(&self) -> &[BrokeredDestination] {
        &self.destinations
    }
}

/// Why one spec was not admitted, before any plan, cgroup or process exists.
///
/// Every variant is a refusal. None of them means "admitted with less than the
/// spec asked for".
#[derive(Debug)]
pub enum AdmissionRefusal {
    /// The document is not RunSpec v1.
    UnsupportedProtocol(u32),
    /// A context input is malformed; names the input.
    ContextRejected(&'static str),
    /// The resolved working directory is not the workspace root or beneath it.
    WorkingDirectoryOutsideWorkspace,
    /// The run identifier cannot name a containment cgroup.
    RunIdUnusable,
    /// A context input does not bind to the spec field it claims to resolve.
    ContextMismatch(&'static str),
    /// The spec needs a runtime resolution the context does not carry.
    ContextMissing(&'static str),
    /// The field grants or restricts something no built mechanism can honour.
    UnmappableField(&'static str),
    /// A quota's value cannot be applied as a ceiling.
    QuotaRejected(&'static str),
    /// A declared budget with no enforcement surface was not acknowledged.
    UnenforcedBudgetUnacknowledged(UnenforcedBudget),
    /// Supplied prompt bytes do not hash to the digest their resolution
    /// declared. No length or digest is quoted: both describe protected bytes.
    PromptDigestMismatch,
    /// A prompt resolution declared a digest in an algorithm this bridge does
    /// not compute.
    UnsupportedPromptDigest,
    /// The host does not offer a feature the sandbox spec requires, or offers
    /// it through a rejected implementation.
    HostFeatureRejected(SandboxError),
    /// A broker was offered to a launch that requires none. Attaching one would
    /// give a run whose spec denies egress a TCP socket and a connect port.
    BrokerNotRequired,
    /// A broker was offered to a launch that already has one. Two attachments
    /// would grant two connect ports and bind the proxy variables twice.
    BrokerAlreadyAttached,
    /// The offered broker endpoint is not a loopback address, or names port
    /// zero. A broker off this host is an open relay to the allowlist.
    BrokerEndpointRejected(SocketAddr),
    /// The launch surface refused the mapped plan; names the spec field whose
    /// mapping was refused.
    Plan {
        /// The spec field being mapped when the plan refused.
        field: &'static str,
        /// The launch surface's own refusal, unaltered.
        error: LaunchPlanError,
    },
    /// The spec's canonical digest could not be computed.
    Digest(RunSpecEncodeError),
}

impl fmt::Display for AdmissionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProtocol(version) => {
                write!(formatter, "unsupported runner protocol version {version}")
            }
            Self::ContextRejected(input) => {
                write!(formatter, "admission context input {input} is invalid")
            }
            Self::WorkingDirectoryOutsideWorkspace => formatter
                .write_str("the resolved working directory is outside the resolved workspace root"),
            Self::RunIdUnusable => {
                formatter.write_str("the run identifier cannot name a containment cgroup")
            }
            Self::ContextMismatch(field) => write!(
                formatter,
                "the admission context does not bind to spec field {field}"
            ),
            Self::ContextMissing(field) => write!(
                formatter,
                "spec field {field} needs a runtime resolution the context does not carry"
            ),
            Self::UnmappableField(field) => write!(
                formatter,
                "spec field {field} needs a mechanism this runner does not have"
            ),
            Self::QuotaRejected(field) => {
                write!(formatter, "spec field {field} is not a usable ceiling")
            }
            Self::UnenforcedBudgetUnacknowledged(budget) => write!(
                formatter,
                "spec field {} has no enforcement surface and was not acknowledged",
                budget.as_str()
            ),
            Self::PromptDigestMismatch => {
                formatter.write_str("resolved prompt bytes do not match their declared digest")
            }
            Self::UnsupportedPromptDigest => formatter.write_str("a prompt digest must be sha256"),
            Self::HostFeatureRejected(error) => {
                write!(formatter, "host enforcement negotiation failed: {error}")
            }
            Self::BrokerNotRequired => {
                formatter.write_str("this launch requires no broker, so none may be attached")
            }
            Self::BrokerAlreadyAttached => {
                formatter.write_str("this launch already carries a broker")
            }
            Self::BrokerEndpointRejected(endpoint) => write!(
                formatter,
                "broker endpoint {endpoint} is not a loopback address with a real port"
            ),
            Self::Plan { field, error } => {
                write!(formatter, "mapping spec field {field} was refused: {error}")
            }
            Self::Digest(error) => write!(formatter, "canonical spec digest unavailable: {error}"),
        }
    }
}

impl std::error::Error for AdmissionRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HostFeatureRejected(error) => Some(error),
            Self::Plan { error, .. } => Some(error),
            Self::Digest(error) => Some(error),
            _ => None,
        }
    }
}

/// Which spec-side prompt coordinate a resolution was made against.
///
/// The variant is compared with the spec's own [`PromptDeliveryPlan`], so
/// bytes resolved for one protected slot cannot be admitted for another, and
/// bytes resolved for a stdin delivery cannot stand in for a protected one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PromptSource {
    /// The spec delivers the prompt on the workload's stdin.
    Stdin,
    /// The spec names a protected slot the caller resolved.
    ProtectedReference(ProtectedPromptReference),
}

/// Prompt bytes a caller resolved, and the digest the resolution declared.
///
/// The bytes have no accessor: a prompt is resolved, admitted, and enforced,
/// and nothing downstream needs to read one back out. The declared digest is
/// what the resolving store asserted about those bytes; [`admit`] recomputes
/// it, so a store that hands back the wrong bytes is a refusal rather than a
/// launch.
///
/// A [`ProtectedPromptReference`] carries no digest of its own — it is an
/// opaque slot coordinate — so the binding admission checks is the pair
/// (source, digest) the caller supplies, not a pin inside the spec.
#[derive(Clone, Eq, PartialEq)]
pub struct ResolvedPrompt {
    source: PromptSource,
    bytes: Vec<u8>,
    declared: Digest,
}

impl ResolvedPrompt {
    /// Record resolved prompt bytes against the coordinate they came from.
    ///
    /// Construction validates only the digest's algorithm. Verifying the bytes
    /// deliberately happens in [`admit`], so dropping that check is a change to
    /// admission rather than a change to a constructor.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionRefusal::UnsupportedPromptDigest`] unless `declared`
    /// is a SHA-256 digest.
    pub fn new(
        source: PromptSource,
        bytes: Vec<u8>,
        declared: Digest,
    ) -> Result<Self, AdmissionRefusal> {
        if declared.algorithm() != DigestAlgorithm::Sha256 {
            return Err(AdmissionRefusal::UnsupportedPromptDigest);
        }
        Ok(Self {
            source,
            bytes,
            declared,
        })
    }

    /// The coordinate these bytes were resolved for.
    #[must_use]
    pub const fn source(&self) -> &PromptSource {
        &self.source
    }

    /// The digest the resolving store declared.
    #[must_use]
    pub const fn declared_digest(&self) -> &Digest {
        &self.declared
    }

    /// How many bytes were resolved.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the resolution is empty, which no launch accepts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Redacting: prompt bytes are exactly what a log must never hold.
impl fmt::Debug for ResolvedPrompt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedPrompt")
            .field("source", &self.source)
            .field("bytes", &format_args!("<redacted:{}>", self.bytes.len()))
            .field("declared", &format_args!("{}", self.declared))
            .finish()
    }
}

/// Every runtime-only fact one admission needs, named at the call site.
#[derive(Clone, Debug)]
pub struct AdmissionContextParts {
    /// The execution backend this caller actually is. It must be the backend
    /// the spec names, or the spec belongs to another runner.
    pub backend: ExecutionBackendId,
    /// The workspace registry record the resolved paths below came from.
    pub workspace_registry_id: WorkspaceRegistryId,
    /// The host path the registered workspace resolves to.
    pub workspace_root: PathBuf,
    /// The host path the spec's opaque `cwd_token` resolves to. It must be the
    /// workspace root or beneath it.
    pub working_directory: PathBuf,
    /// The provenance the caller observed for the program it is about to run.
    /// Hashing the file is the caller's job; this is the result.
    pub observed_provider_binary: BinaryProvenance,
    /// The enforcement features this host offers, for the sandbox spec's own
    /// negotiation.
    pub host_features: Vec<HostFeature>,
    /// Prompt bytes, when the spec's delivery plan needs them.
    pub prompt: Option<ResolvedPrompt>,
    /// Budgets the caller acknowledges this launch will not enforce.
    pub unenforced_budgets: Vec<UnenforcedBudget>,
    /// The destinations this deployment resolves `brokered_named` egress to.
    ///
    /// A standing host answer, like [`Self::host_features`] beside it: the same
    /// list is offered to every document, and only a document that asks for
    /// brokered egress consults it. See [`AdmissionContext`]'s own note for why
    /// this field exists at all.
    pub brokered_destinations: Vec<BrokeredDestination>,
}

/// The validated runtime half of one admission.
///
/// A context supplies resolutions, never grants: there is no field here that
/// can add a path, a socket, or a variable that the spec did not already
/// declare.
///
/// # The one field that is nearly an exception, and what bounds it
///
/// [`AdmissionContextParts::brokered_destinations`] is the exception's shape,
/// and it is here because of a gap in the protocol rather than a preference:
/// `NetworkAccess::BrokeredNamed` is documented as "named destinations through
/// the egress broker", and **the sandbox spec carries no list of those names**.
/// There is no destination field anywhere in
/// [`automonique_protocol::sandbox`] — the only egress-shaped values are the two
/// access enums and an `EgressPolicyDigest` in the attestation, which is a
/// digest of a policy no type in the protocol holds. So a document can say
/// *that* its egress is brokered and cannot say *where to*, and the deployment
/// running the broker is the only party that can supply the answer.
///
/// Three things keep that from being a hole the context can widen a spec
/// through, and they are the reason it is admissible at all:
///
/// - **The spec still decides whether there is any egress.** A document that
///   denies it is admitted with no [`BrokerRequirement`], no socket grant and no
///   proxy variable, whatever this list holds — and
///   [`AdmittedLaunch::with_broker`] then refuses to attach one. The list is a
///   standing host answer, like the offered host features beside it: every
///   document is shown the same one, and only a document that asks consults it.
/// - **A document that asks and gets no answer does not run.** A spec declaring
///   brokered egress against an empty list is a **refusal**. There is no
///   default, and an empty allowlist is never admitted as one.
/// - **What it buys the workload is one loopback port.** Reaching a destination
///   still requires a broker that holds this same list and is the only party
///   that resolves or dials anything.
///
/// What remains true, and is not papered over: the destinations a run reached
/// were chosen by the host that ran it, and no reviewer of the document can see
/// them in the document. Closing that needs a destination list in the sandbox
/// spec — a wire change, deliberately not made here.
#[derive(Clone, Debug)]
pub struct AdmissionContext {
    parts: AdmissionContextParts,
}

impl AdmissionContext {
    /// Validate one runtime context.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionRefusal::ContextRejected`] naming a malformed input
    /// and [`AdmissionRefusal::WorkingDirectoryOutsideWorkspace`] when the
    /// resolved working directory escapes the resolved workspace root.
    pub fn new(parts: AdmissionContextParts) -> Result<Self, AdmissionRefusal> {
        validate_context_path(&parts.workspace_root, "workspace_root")?;
        validate_context_path(&parts.working_directory, "working_directory")?;
        if !parts.working_directory.starts_with(&parts.workspace_root) {
            return Err(AdmissionRefusal::WorkingDirectoryOutsideWorkspace);
        }
        if parts.host_features.len() > MAX_OFFERED_FEATURES {
            return Err(AdmissionRefusal::ContextRejected("host_features"));
        }
        for (index, budget) in parts.unenforced_budgets.iter().enumerate() {
            if parts.unenforced_budgets[..index].contains(budget) {
                return Err(AdmissionRefusal::ContextRejected("unenforced_budgets"));
            }
        }
        if parts.brokered_destinations.len() > MAX_BROKERED_DESTINATIONS {
            return Err(AdmissionRefusal::ContextRejected("brokered_destinations"));
        }
        // A host and port named twice has no single meaning, and the broker's
        // own allowlist refuses the pair, so a launch is never admitted against
        // a destination set no broker could be started with.
        for (index, destination) in parts.brokered_destinations.iter().enumerate() {
            if parts.brokered_destinations[..index]
                .iter()
                .any(|held| held.host == destination.host && held.port == destination.port)
            {
                return Err(AdmissionRefusal::ContextRejected("brokered_destinations"));
            }
        }
        Ok(Self { parts })
    }

    /// The backend this context serves.
    #[must_use]
    pub const fn backend(&self) -> &ExecutionBackendId {
        &self.parts.backend
    }

    /// The workspace registry record the resolutions came from.
    #[must_use]
    pub const fn workspace_registry_id(&self) -> &WorkspaceRegistryId {
        &self.parts.workspace_registry_id
    }

    /// The resolved workspace root.
    #[must_use]
    pub fn workspace_root(&self) -> &Path {
        &self.parts.workspace_root
    }

    /// The resolved working directory.
    #[must_use]
    pub fn working_directory(&self) -> &Path {
        &self.parts.working_directory
    }

    /// The provenance the caller observed for the program.
    #[must_use]
    pub const fn observed_provider_binary(&self) -> &BinaryProvenance {
        &self.parts.observed_provider_binary
    }

    /// The enforcement features this host offers.
    #[must_use]
    pub fn host_features(&self) -> &[HostFeature] {
        &self.parts.host_features
    }

    /// The prompt resolution, when one was supplied.
    #[must_use]
    pub const fn prompt(&self) -> Option<&ResolvedPrompt> {
        self.parts.prompt.as_ref()
    }

    /// The budgets this caller acknowledges are not enforced.
    #[must_use]
    pub fn unenforced_budgets(&self) -> &[UnenforcedBudget] {
        &self.parts.unenforced_budgets
    }

    /// The destinations this deployment resolves brokered egress to.
    #[must_use]
    pub fn brokered_destinations(&self) -> &[BrokeredDestination] {
        &self.parts.brokered_destinations
    }
}

/// One spec, admitted: everything a supervisor needs for exactly one attempt.
///
/// The four fields a supervised attempt consumes — the plan, the ceilings, the
/// deadline and the spool budget — are all here, alongside the digest of the
/// document they were derived from, so a record of what ran can name it.
#[derive(Debug)]
pub struct AdmittedLaunch {
    plan: LaunchPlan,
    limits: ContainmentLimits,
    spec_digest: RunSpecDigest,
    run_id: String,
    working_directory: PathBuf,
    timeout: Duration,
    spool_budget_bytes: u64,
    unenforced_budgets: Vec<UnenforcedBudget>,
    broker: Option<BrokerRequirement>,
    broker_attached: bool,
}

impl AdmittedLaunch {
    /// The exact plan the entry helper must be handed.
    #[must_use]
    pub const fn plan(&self) -> &LaunchPlan {
        &self.plan
    }

    /// The exact ceilings the run cgroup must carry before the workload runs.
    #[must_use]
    pub const fn limits(&self) -> ContainmentLimits {
        self.limits
    }

    /// The canonical digest of the RunSpec this launch was derived from.
    #[must_use]
    pub const fn spec_digest(&self) -> &RunSpecDigest {
        &self.spec_digest
    }

    /// The run identifier, which names the containment cgroup.
    #[must_use]
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// The directory the supervisor must launch from.
    ///
    /// The launch frame has no working-directory line, so this is a
    /// requirement on the caller that admission publishes and cannot enforce.
    #[must_use]
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    /// The attempt's bounded runtime.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The attempt's spool ceiling.
    #[must_use]
    pub const fn spool_budget_bytes(&self) -> u64 {
        self.spool_budget_bytes
    }

    /// Budgets the spec declares that this launch does not enforce, exactly as
    /// the context acknowledged them.
    #[must_use]
    pub fn unenforced_budgets(&self) -> &[UnenforcedBudget] {
        &self.unenforced_budgets
    }

    /// The destinations this launch needs a broker for, when it needs one.
    ///
    /// `None` is the whole statement that no broker may be started: a run whose
    /// spec denies egress has no broker, no proxy variable and no socket grant,
    /// and [`Self::with_broker`] refuses to give it any.
    #[must_use]
    pub const fn broker_requirement(&self) -> Option<&BrokerRequirement> {
        self.broker.as_ref()
    }

    /// Whether a broker has already been attached to this launch.
    #[must_use]
    pub const fn has_broker(&self) -> bool {
        self.broker_attached
    }

    /// The closed list of spec fields admission did not consult.
    #[must_use]
    pub const fn informational_fields() -> &'static [&'static str] {
        &INFORMATIONAL_FIELDS
    }

    /// Point this launch at a running broker, and grant it nothing else.
    ///
    /// This is the *only* way network reach enters a plan, and it is written
    /// here rather than at the supervisor so the composition is one reviewed
    /// list in one place. What it adds, in full:
    ///
    /// - [`SocketGrant::Tcp`](crate::SocketGrant::Tcp) — the workload may create TCP sockets;
    /// - [`LaunchPlan::allow_connect_port`] for the broker's own port;
    /// - `HTTPS_PROXY` and `HTTP_PROXY`, both bound to `http://<endpoint>`.
    ///
    /// And what it deliberately does not add, each of which the pre-broker
    /// live-provider path had: no `SocketGrant::InetDatagram`, so the workload
    /// cannot create a UDP socket and cannot do DNS; no `connect` grant for 443
    /// or any other port a public service listens on; no `bind` port, so it
    /// cannot listen on the broker's port and impersonate it; and no resolver
    /// files in the filesystem allowlist, because there is no resolution left to
    /// do. The CA trust store, wherever the spec granted it, stays and must: the
    /// broker does not terminate TLS, so the workload validates the
    /// destination's real certificate itself.
    ///
    /// The honest residual, restated from the broker's own documentation: a
    /// Landlock network rule names a port and not an address, so the grant is
    /// "port `P`, anywhere" rather than "the broker". What narrows it is that
    /// `P` is a kernel-assigned ephemeral port on `127.0.0.1`, that the workload
    /// has no way to resolve a name, and that it may not bind.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionRefusal::BrokerNotRequired`] when this launch needs no
    /// broker, [`AdmissionRefusal::BrokerAlreadyAttached`] on a second
    /// attachment, [`AdmissionRefusal::BrokerEndpointRejected`] for an endpoint
    /// that is not loopback or names port zero, and
    /// [`AdmissionRefusal::Plan`] when the launch surface refuses the
    /// composition — which is what happens when the document bound a proxy
    /// variable itself, since a plan refuses one name bound twice.
    pub fn with_broker(mut self, endpoint: SocketAddr) -> Result<Self, AdmissionRefusal> {
        if self.broker.is_none() {
            return Err(AdmissionRefusal::BrokerNotRequired);
        }
        if self.broker_attached {
            return Err(AdmissionRefusal::BrokerAlreadyAttached);
        }
        if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
            return Err(AdmissionRefusal::BrokerEndpointRejected(endpoint));
        }
        let proxy = format!("http://{endpoint}");
        let refused = |error: LaunchPlanError| AdmissionRefusal::Plan {
            field: "sandbox.tool_workload_egress",
            error,
        };
        let mut plan = self
            .plan
            .clone()
            .socket_grant(crate::SocketGrant::Tcp)
            .map_err(refused)?
            .allow_connect_port(endpoint.port())
            .map_err(refused)?;
        for name in BROKER_PROXY_VARIABLES {
            plan = plan.environment(name, proxy.as_bytes()).map_err(refused)?;
        }
        self.plan = plan;
        self.broker_attached = true;
        Ok(self)
    }
}

/// Map one validated spec plus its runtime context onto one launch.
///
/// Checks run in a fixed order so a refusal is reproducible: document version,
/// run identity, backend and executor class, workspace and binary bindings,
/// host enforcement negotiation, unmappable admission fields, unmappable
/// sandbox fields, quotas, the prompt, and finally the plan itself.
///
/// # Errors
///
/// Returns the first [`AdmissionRefusal`] in that order. Nothing is admitted
/// partially: either the whole plan is produced or none of it is.
pub fn admit(
    spec: &RunSpec,
    context: &AdmissionContext,
) -> Result<AdmittedLaunch, AdmissionRefusal> {
    if spec.protocol_version() != 1 {
        return Err(AdmissionRefusal::UnsupportedProtocol(
            spec.protocol_version(),
        ));
    }
    let run_id = spec.run_id().as_str();
    if !is_containment_run_id(run_id) {
        return Err(AdmissionRefusal::RunIdUnusable);
    }
    if spec.backend_id().as_str() != context.backend().as_str() {
        return Err(AdmissionRefusal::ContextMismatch("backend_id"));
    }
    let admission = spec.admission();
    if !matches!(admission.executor_class(), ExecutorClass::Local) {
        return Err(AdmissionRefusal::UnmappableField(
            "admission.executor_class",
        ));
    }
    if spec.workspace_registry_id() != context.workspace_registry_id() {
        return Err(AdmissionRefusal::ContextMismatch("workspace_registry_id"));
    }
    if !spec
        .provider_binary()
        .matches(context.observed_provider_binary())
    {
        return Err(AdmissionRefusal::ContextMismatch("provider_binary"));
    }
    spec.sandbox()
        .admit_on(context.host_features())
        .map_err(AdmissionRefusal::HostFeatureRejected)?;

    check_admission_fields(spec)?;
    check_sandbox_fields(spec)?;
    let broker = check_egress(spec, context)?;
    let limits = map_quotas(spec, context)?;
    let prompt = resolve_prompt(spec, context)?;
    let plan = build_plan(spec, context, prompt)?;
    let spec_digest = spec.canonical_digest().map_err(AdmissionRefusal::Digest)?;

    Ok(AdmittedLaunch {
        plan,
        limits,
        spec_digest,
        run_id: run_id.to_owned(),
        working_directory: context.working_directory().to_path_buf(),
        timeout: spec.timeout(),
        spool_budget_bytes: spec.spool_budget_bytes(),
        unenforced_budgets: context.unenforced_budgets().to_vec(),
        broker,
        broker_attached: false,
    })
}

/// Refuse every runner-owned admission field that names an unbuilt subsystem.
fn check_admission_fields(spec: &RunSpec) -> Result<(), AdmissionRefusal> {
    let admission = spec.admission();
    if admission.session_binding().is_some() {
        // Binding a run to a provider session needs the daemon lane that keeps
        // the session; this launch starts one process and owns no session.
        return Err(AdmissionRefusal::UnmappableField(
            "admission.session_binding",
        ));
    }
    if !admission.fallback_eligibility().is_empty() {
        // Eligibility to fall back to another integration mode is an
        // instruction to a scheduler that would pick a different launch.
        return Err(AdmissionRefusal::UnmappableField(
            "admission.fallback_eligibility",
        ));
    }
    if !admission.required_capabilities().is_empty() {
        // Capabilities are named provider abilities. There is no provider
        // capability surface here to satisfy or deny them against.
        return Err(AdmissionRefusal::UnmappableField(
            "admission.required_capabilities",
        ));
    }
    if admission.portability_policy() != PortabilityPolicy::Pinned {
        return Err(AdmissionRefusal::UnmappableField(
            "admission.portability_policy",
        ));
    }
    if admission.remote_attestation_policy() != RemoteAttestationPolicy::NotRequired {
        return Err(AdmissionRefusal::UnmappableField(
            "admission.remote_attestation_policy",
        ));
    }
    if !admission.artifact_grants().is_empty() {
        return Err(AdmissionRefusal::UnmappableField(
            "admission.artifact_grants",
        ));
    }
    if !admission.credential_bindings().is_empty() {
        // A binding names a credential and its version; delivering one needs a
        // secret store, and putting a resolved secret in the plan's
        // environment would publish it to every same-uid reader of
        // /proc/<pid>/environ.
        return Err(AdmissionRefusal::UnmappableField(
            "admission.credential_bindings",
        ));
    }
    Ok(())
}

/// Refuse every sandbox-spec field this launch cannot enforce exactly.
fn check_sandbox_fields(spec: &RunSpec) -> Result<(), AdmissionRefusal> {
    let sandbox = spec.sandbox();
    if !sandbox.allowlists().as_slice().is_empty() {
        // An allowlist entry is a name, a Landlock grant is a path, and no
        // registry here maps one to the other. An empty allowlist is the only
        // one this plan enforces completely: it grants execute on exactly the
        // program the spec names and on nothing else.
        return Err(AdmissionRefusal::UnmappableField("sandbox.allowlists"));
    }
    if !sandbox.prohibited_capabilities().is_empty() {
        return Err(AdmissionRefusal::UnmappableField(
            "sandbox.prohibited_capabilities",
        ));
    }
    if !sandbox.credential_descriptors().is_empty() {
        return Err(AdmissionRefusal::UnmappableField("sandbox.credentials"));
    }
    let nested = sandbox.nested_isolation();
    if nested.nested_tools() != IsolationRequirement::HostBoundary {
        // This launch builds exactly one boundary, which every descendant
        // inherits. A stricter nested requirement needs a second mechanism.
        return Err(AdmissionRefusal::UnmappableField(
            "sandbox.nested_isolation.nested_tools",
        ));
    }
    if nested.extensions() != IsolationRequirement::HostBoundary {
        return Err(AdmissionRefusal::UnmappableField(
            "sandbox.nested_isolation.extensions",
        ));
    }
    if sandbox.profile().filesystem() == FilesystemAccess::None {
        // A workload that may read nothing cannot execute its own program.
        return Err(AdmissionRefusal::UnmappableField(
            "sandbox.profile.filesystem",
        ));
    }
    Ok(())
}

/// Decide whether this launch needs a broker, or refuse the egress it declares.
///
/// # One boundary, so one egress answer
///
/// The spec carries two egress policies — a trusted provider-control channel and
/// model-directed tool traffic — and they are distinct types precisely so tool
/// traffic cannot inherit control-plane reach. This launch builds **one**
/// boundary around **one** process tree, exactly as it does for nested
/// isolation, so the two policies land on the same seccomp filter and the same
/// Landlock ruleset and there is no mechanism here that could tell one kind of
/// traffic from the other.
///
/// A document whose two axes disagree therefore describes an enforcement this
/// build cannot perform, and it is refused rather than run under the wider of
/// the two while a record claims the narrower. The two admissible documents are
/// the two where the question does not arise: both axes denied, or both axes
/// `brokered_named`.
///
/// `brokered_any` is refused on either axis at any time. "Any destination the
/// broker permits" is a policy with no allowlist in it, and the broker this
/// composes has no such mode: its default configuration denies everything and
/// its entries are exact host-and-port pairs.
fn check_egress(
    spec: &RunSpec,
    context: &AdmissionContext,
) -> Result<Option<BrokerRequirement>, AdmissionRefusal> {
    let sandbox = spec.sandbox();
    let control = sandbox.provider_control_egress().access();
    let workload = sandbox.tool_workload_egress().access();
    for (access, field) in [
        (control, "sandbox.provider_control_egress"),
        (workload, "sandbox.tool_workload_egress"),
    ] {
        if access == NetworkAccess::BrokeredAny {
            return Err(AdmissionRefusal::UnmappableField(field));
        }
    }
    if control != workload {
        // Named on the control axis because that is the one a document raises
        // first when it wants a provider to reach its model endpoint, and the
        // refusal has to point at the field whose value the author must change.
        return Err(AdmissionRefusal::UnmappableField(
            "sandbox.provider_control_egress",
        ));
    }
    let destinations = context.brokered_destinations();
    match control {
        // The destination policy is a standing host answer, exactly like the
        // offered host features beside it: a document that asks nothing of it
        // is admitted without consulting it, and comes out with no broker
        // requirement, no socket grant and no proxy variable. The context
        // cannot make this document reach anything, whatever it carries.
        NetworkAccess::Denied => Ok(None),
        NetworkAccess::BrokeredNamed => {
            if destinations.is_empty() {
                // No default, and no empty allowlist admitted as one: a
                // deployment that cannot say where a run may reach cannot run it.
                return Err(AdmissionRefusal::ContextMissing(
                    "sandbox.tool_workload_egress",
                ));
            }
            Ok(Some(BrokerRequirement {
                destinations: destinations.to_vec(),
            }))
        }
        // Refused above, before anything read the context.
        NetworkAccess::BrokeredAny => Err(AdmissionRefusal::UnmappableField(
            "sandbox.tool_workload_egress",
        )),
    }
}

/// Map the cgroup quotas, and refuse every declared budget with no mechanism.
///
/// `cgroup_memory` becomes the subtree's `memory.max`. `rlimit_processes`
/// becomes the subtree's `pids.max`: a cgroup ceiling over the whole tree is
/// strictly stronger than a per-process `RLIMIT_NPROC`, so the mapping cannot
/// permit anything the budget denies, and no `RLIMIT_NPROC` is installed. Both
/// are documented interpretations, pinned by tests, never silent.
fn map_quotas(
    spec: &RunSpec,
    context: &AdmissionContext,
) -> Result<ContainmentLimits, AdmissionRefusal> {
    let budgets = spec.sandbox().budgets();
    let memory = budgets.cgroup_memory().quantity();
    if memory == 0 {
        // A zero ceiling admits no workload at all; that is a refusal to
        // launch, not a launch under a ceiling.
        return Err(AdmissionRefusal::QuotaRejected(
            "sandbox.budgets.cgroup_memory",
        ));
    }
    let processes = budgets.rlimit_processes().quantity();
    if processes == 0 {
        return Err(AdmissionRefusal::QuotaRejected(
            "sandbox.budgets.rlimit_processes",
        ));
    }
    for budget in UnenforcedBudget::ALL {
        if !context.unenforced_budgets().contains(&budget) {
            return Err(AdmissionRefusal::UnenforcedBudgetUnacknowledged(budget));
        }
    }
    Ok(ContainmentLimits::none()
        .with_memory_max_bytes(memory)
        .with_pids_max(processes))
}

/// Bind the spec's prompt transport to the caller's resolution, and verify it.
fn resolve_prompt<'context>(
    spec: &RunSpec,
    context: &'context AdmissionContext,
) -> Result<&'context ResolvedPrompt, AdmissionRefusal> {
    let expected = match spec.prompt_delivery() {
        PromptDeliveryPlan::Stdin => PromptSource::Stdin,
        PromptDeliveryPlan::ProtectedReference(reference) => {
            PromptSource::ProtectedReference(reference.clone())
        }
        PromptDeliveryPlan::BackendSession(_) => {
            // The daemon holds the session and delivers the prompt over it;
            // this crate has no session and no channel to one.
            return Err(AdmissionRefusal::UnmappableField(
                "prompt_delivery.backend_session",
            ));
        }
    };
    let Some(prompt) = context.prompt() else {
        return Err(AdmissionRefusal::ContextMissing("prompt_delivery"));
    };
    if prompt.source() != &expected {
        return Err(AdmissionRefusal::ContextMismatch("prompt_delivery"));
    }
    if sha256_hex(&prompt.bytes) != prompt.declared.hex() {
        return Err(AdmissionRefusal::PromptDigestMismatch);
    }
    Ok(prompt)
}

/// Assemble the plan in one fixed order, refusing wherever the plan refuses.
fn build_plan(
    spec: &RunSpec,
    context: &AdmissionContext,
    prompt: &ResolvedPrompt,
) -> Result<LaunchPlan, AdmissionRefusal> {
    let mut plan = LaunchPlan::new(spec.executable()).map_err(|error| AdmissionRefusal::Plan {
        field: "executable",
        error,
    })?;
    for argument in spec.arguments() {
        plan = plan
            .argument(argument.as_encoded_bytes())
            .map_err(|error| AdmissionRefusal::Plan {
                field: "argv",
                error,
            })?;
    }
    // Execute on exactly the program the spec names, and nothing else.
    plan = plan
        .filesystem_grant(PathIntent::ReadExecute, spec.executable())
        .map_err(|error| AdmissionRefusal::Plan {
            field: "executable",
            error,
        })?;
    // The workspace, at the intent its reviewed filesystem access permits.
    let workspace_intent = match spec.sandbox().profile().filesystem() {
        FilesystemAccess::ReadOnlySnapshot => PathIntent::Read,
        FilesystemAccess::IsolatedWritable | FilesystemAccess::WritableWithGrants => {
            PathIntent::ReadWrite
        }
        // Refused in check_sandbox_fields, before any plan exists.
        FilesystemAccess::None => {
            return Err(AdmissionRefusal::UnmappableField(
                "sandbox.profile.filesystem",
            ));
        }
    };
    plan = plan
        .filesystem_grant(workspace_intent, context.workspace_root())
        .map_err(|error| AdmissionRefusal::Plan {
            field: "workspace",
            error,
        })?;
    // The spec's own path grants, in declared order. A path the workspace or
    // the program already granted collides here rather than being merged: two
    // grants for one path have no single meaning.
    for grant in spec.sandbox().path_grants().as_slice() {
        let intent = match grant.access() {
            PathAccess::ReadOnly => PathIntent::Read,
            PathAccess::ReadWrite => PathIntent::ReadWrite,
        };
        plan = plan
            .filesystem_grant(intent, grant.path().as_str())
            .map_err(|error| AdmissionRefusal::Plan {
                field: "sandbox.path_grants",
                error,
            })?;
    }
    for (name, value) in spec.environment() {
        let Some(name) = name.to_str() else {
            return Err(AdmissionRefusal::UnmappableField("environment"));
        };
        plan = plan
            .environment(name, value.as_encoded_bytes())
            .map_err(|error| AdmissionRefusal::Plan {
                field: "environment",
                error,
            })?;
    }
    plan = plan
        .prompt(&prompt.bytes)
        .map_err(|error| AdmissionRefusal::Plan {
            field: "prompt_delivery",
            error,
        })?;
    Ok(plan)
}

/// The containment module's bounded cgroup-name rule, applied early.
///
/// [`crate::RunContainment`] remains the authority; refusing here means an
/// admitted launch cannot name a cgroup that could never be created.
fn is_containment_run_id(run_id: &str) -> bool {
    !run_id.is_empty()
        && run_id.len() <= MAX_RUN_ID_BYTES
        && run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// A context path must be absolute, bounded, and lexically canonical.
fn validate_context_path(path: &Path, input: &'static str) -> Result<(), AdmissionRefusal> {
    let bytes = path.as_os_str().as_encoded_bytes();
    let rejected = || AdmissionRefusal::ContextRejected(input);
    if !path.is_absolute() || bytes.len() < 2 || bytes.len() > MAX_CONTEXT_PATH_BYTES {
        return Err(rejected());
    }
    if bytes.contains(&0) || bytes.ends_with(b"/") {
        return Err(rejected());
    }
    for segment in bytes[1..].split(|byte| *byte == b'/') {
        if segment.is_empty() || segment == b"." || segment == b".." {
            return Err(rejected());
        }
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(char::from(DIGITS[usize::from(byte >> 4)]));
        hex.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    hex
}
