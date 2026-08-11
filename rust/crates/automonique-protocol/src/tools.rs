// SPDX-License-Identifier: Elastic-2.0

//! Tool descriptors, grant intersection, the bounded workflow capability, MCP
//! boundaries, extension manifests, hook classes and secret sources.
//!
//! Grants combine by intersection and nothing else. There is no union, no
//! override and no "grant wins", so a messaging surface cannot inherit the
//! breadth of a CLI profile:
//!
//! ```compile_fail
//! use automonique_protocol::tools::ToolsetGrant;
//! # fn grant() -> ToolsetGrant { unreachable!() }
//! // There is no union operation to reach for.
//! let combined = grant().union(&grant());
//! ```
//!
//! The same program with the only combining operation that exists compiles,
//! so the case above fails for the missing operation and not for its setup:
//!
//! ```no_run
//! use automonique_protocol::tools::ToolsetGrant;
//! # fn grant() -> ToolsetGrant { unreachable!() }
//! let combined = grant().intersect(&grant());
//! ```
//!
//! Nothing here executes a tool, starts an MCP server, installs an extension,
//! runs a hook or resolves a secret. Budgets are *accounted* against declared
//! costs; no clock is read and no resource is measured.

use core::fmt;
use std::error::Error;
use std::num::{NonZeroU32, NonZeroU64};

use crate::identity::Actor;
use crate::primitives::{OpaqueId, ValueError};
use crate::sandbox::{SandboxProfile, ToolWorkloadEgress};

/// Maximum UTF-8 byte length of a tool, extension, hook or secret field.
pub const MAX_TOOL_FIELD_BYTES: usize = 256;

/// Capability identities a workflow program may never name.
///
/// Recursion and self-invocation (the workflow tool itself), delegation,
/// arbitrary MCP access, approval decisions and privilege brokers all live
/// behind one of these identities, and [`WorkflowInvocable::eligible`] refuses
/// every one of them, so no [`WorkflowSpec`] value can contain one.
pub const RESERVED_CAPABILITIES: [&str; 5] = [
    "automonique.workflow.execute",
    "automonique.delegation.spawn",
    "automonique.mcp.raw",
    "automonique.approval.decide",
    "automonique.privilege.broker",
];

/// What a tool does to the world.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SideEffectClass {
    /// Reads only.
    ReadOnly,
    /// Writes inside the workspace.
    WorkspaceWrite,
    /// Reaches outside the host.
    ExternalEffect,
    /// Requests privileged action through a broker.
    PrivilegedRequest,
}

impl SideEffectClass {
    /// Every class, for coverage checks.
    pub const ALL: [Self; 4] = [
        Self::ReadOnly,
        Self::WorkspaceWrite,
        Self::ExternalEffect,
        Self::PrivilegedRequest,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::WorkspaceWrite => "workspace_write",
            Self::ExternalEffect => "external_effect",
            Self::PrivilegedRequest => "privileged_request",
        }
    }
}

/// Whether a tool needs an approval before running.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ApprovalRequirement {
    /// No approval needed.
    None,
    /// One approval per session.
    PerSession,
    /// An approval for every invocation.
    PerInvocation,
}

impl ApprovalRequirement {
    /// Every requirement, for coverage checks.
    pub const ALL: [Self; 3] = [Self::None, Self::PerSession, Self::PerInvocation];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::PerSession => "per_session",
            Self::PerInvocation => "per_invocation",
        }
    }
}

/// How much scrutiny a tool's implementation has had.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TrustClass {
    /// Built and reviewed in this repository.
    FirstParty,
    /// Signed by a reviewed publisher.
    ReviewedPublisher,
    /// Signed, but the publisher is not reviewed.
    UnreviewedThirdParty,
    /// Authored by a model during a run.
    ModelAuthored,
}

impl TrustClass {
    /// Every class, for coverage checks.
    pub const ALL: [Self; 4] = [
        Self::FirstParty,
        Self::ReviewedPublisher,
        Self::UnreviewedThirdParty,
        Self::ModelAuthored,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FirstParty => "first_party",
            Self::ReviewedPublisher => "reviewed_publisher",
            Self::UnreviewedThirdParty => "unreviewed_third_party",
            Self::ModelAuthored => "model_authored",
        }
    }
}

/// Why a tool or extension operation was refused.
///
/// No variant carries a tool identifier, so no error can name a tool the
/// caller may not reach.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolError {
    /// A secret source was given something other than a closed argument
    /// schema of shell-inert tokens.
    SecretSourceNeedsClosedArguments,
    /// A secret command bound a different number of values than its schema
    /// declares.
    SecretSourceArgumentCount {
        /// Named slots the schema declares.
        declared: usize,
        /// Values supplied.
        supplied: usize,
    },
    /// A workflow exceeded a declared budget.
    WorkflowBudgetExceeded {
        /// Which budget.
        budget: &'static str,
    },
    /// A tool is not reachable from a workflow capability.
    WorkflowToolNotEligible,
    /// A budget was declared as zero, which permits nothing.
    BudgetIsZero {
        /// Which budget.
        budget: &'static str,
    },
    /// A budget was declared above its ceiling.
    BudgetOutOfRange {
        /// Which budget.
        budget: &'static str,
        /// Maximum accepted quantity.
        max: u64,
        /// Quantity requested.
        requested: u64,
    },
    /// Server-initiated sampling was enabled without an approval requirement.
    SamplingNeedsApproval,
    /// Two hook bindings claimed the same position.
    HookOrderNotUnique {
        /// The contested position.
        order: u32,
    },
    /// A bounded field was rejected.
    Field {
        /// The rejected field.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
}

impl ToolError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::SecretSourceNeedsClosedArguments => "secret_source_open_arguments",
            Self::SecretSourceArgumentCount { .. } => "secret_source_argument_count",
            Self::WorkflowBudgetExceeded { .. } => "workflow_budget_exceeded",
            Self::WorkflowToolNotEligible => "workflow_tool_not_eligible",
            Self::BudgetIsZero { .. } => "budget_is_zero",
            Self::BudgetOutOfRange { .. } => "budget_out_of_range",
            Self::SamplingNeedsApproval => "sampling_needs_approval",
            Self::HookOrderNotUnique { .. } => "hook_order_not_unique",
            Self::Field { .. } => "field_invalid",
        }
    }
}

impl fmt::Display for ToolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecretSourceNeedsClosedArguments => formatter.write_str(
                "a secret source command needs a closed argument schema of shell-inert tokens",
            ),
            Self::SecretSourceArgumentCount { declared, supplied } => write!(
                formatter,
                "argument schema declares {declared} values; {supplied} were bound"
            ),
            Self::WorkflowBudgetExceeded { budget } => {
                write!(formatter, "workflow exceeded its {budget} budget")
            }
            Self::WorkflowToolNotEligible => {
                formatter.write_str("the tool is not reachable from this workflow capability")
            }
            Self::BudgetIsZero { budget } => {
                write!(
                    formatter,
                    "the {budget} budget is zero, which permits nothing"
                )
            }
            Self::BudgetOutOfRange {
                budget,
                max,
                requested,
            } => write!(
                formatter,
                "the {budget} budget of {requested} exceeds the maximum of {max}"
            ),
            Self::SamplingNeedsApproval => formatter
                .write_str("server-initiated sampling needs an approval requirement to be enabled"),
            Self::HookOrderNotUnique { order } => {
                write!(formatter, "two hook bindings claim position {order}")
            }
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
        }
    }
}

impl Error for ToolError {}

macro_rules! tool_domain {
    ($domain:ident, $alias:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $domain;

        impl crate::primitives::IdDomain for $domain {}

        #[doc = $doc]
        pub type $alias = OpaqueId<$domain, MAX_TOOL_FIELD_BYTES>;
    };
}

tool_domain!(RunDomain, RunId, "One run a nested call belongs to.");
tool_domain!(
    CausationDomain,
    CausationId,
    "The step a nested call was caused by."
);

/// A capability identity, independent of any one provider's tool name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CapabilityId(String);

impl CapabilityId {
    /// Name a capability.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid identifier.
    pub fn new(value: &str) -> Result<Self, ToolError> {
        bounded(value, "capability_id")?;
        Ok(Self(value.to_owned()))
    }

    /// The capability spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A content digest of the implementation a descriptor stands for.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProvenanceDigest(String);

impl ProvenanceDigest {
    /// Record a digest.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid digest.
    pub fn new(value: &str) -> Result<Self, ToolError> {
        bounded(value, "provenance_digest")?;
        Ok(Self(value.to_owned()))
    }

    /// The digest spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A schema identity paired with the digest of that schema's text.
///
/// Both halves are constructor arguments: an identifier without a digest names
/// a schema that may have changed underneath it.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchemaContract {
    id: String,
    digest: String,
}

impl SchemaContract {
    /// Pin a schema.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid component.
    pub fn new(id: &str, digest: &str) -> Result<Self, ToolError> {
        bounded(id, "schema_id")?;
        bounded(digest, "schema_digest")?;
        Ok(Self {
            id: id.to_owned(),
            digest: digest.to_owned(),
        })
    }

    /// The schema identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The digest of the schema text.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Credential audiences a tool may present.
///
/// There is no implicit audience: a descriptor either names the audiences it
/// may present or states that it presents none.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CredentialAudiences(Vec<String>);

impl CredentialAudiences {
    /// Declare that a tool presents no credential at all.
    #[must_use]
    pub const fn none() -> Self {
        Self(Vec::new())
    }

    /// Declare an exact audience list.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid audience.
    pub fn exactly(audiences: &[&str]) -> Result<Self, ToolError> {
        let mut owned = Vec::with_capacity(audiences.len());
        for audience in audiences {
            bounded(audience, "credential_audience")?;
            owned.push((*audience).to_owned());
        }
        owned.sort();
        owned.dedup();
        Ok(Self(owned))
    }

    /// The declared audiences.
    #[must_use]
    pub fn audiences(&self) -> &[String] {
        &self.0
    }

    /// Whether any credential may be presented.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A host platform a tool supports.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Platform {
    /// Linux hosts.
    Linux,
    /// macOS hosts.
    MacOs,
    /// Windows hosts.
    Windows,
}

impl Platform {
    /// Every platform, for coverage checks.
    pub const ALL: [Self; 3] = [Self::Linux, Self::MacOs, Self::Windows];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::MacOs => "macos",
            Self::Windows => "windows",
        }
    }
}

/// The platforms a tool declares support for.
///
/// Never empty: a tool that runs nowhere is not a tool, and an empty list read
/// as "everywhere" is exactly the widening this type exists to prevent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformSupport(Vec<Platform>);

impl PlatformSupport {
    /// Declare supported platforms.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] when the list is empty.
    pub fn new(platforms: &[Platform]) -> Result<Self, ToolError> {
        if platforms.is_empty() {
            return Err(ToolError::Field {
                field: "platform_support",
                error: ValueError::Empty,
            });
        }
        let mut owned = platforms.to_vec();
        owned.sort_unstable();
        owned.dedup();
        Ok(Self(owned))
    }

    /// The supported platforms.
    #[must_use]
    pub fn platforms(&self) -> &[Platform] {
        &self.0
    }

    /// Whether a platform is supported.
    #[must_use]
    pub fn supports(&self, platform: Platform) -> bool {
        self.0.contains(&platform)
    }
}

/// How long an artifact a tool produces is kept.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ArtifactRetention {
    /// Discarded at the end of the session.
    Session,
    /// Kept for the run that produced it.
    Run,
    /// Kept until an explicit retention decision removes it.
    Durable,
}

impl ArtifactRetention {
    /// Every retention, for coverage checks.
    pub const ALL: [Self; 3] = [Self::Session, Self::Run, Self::Durable];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Run => "run",
            Self::Durable => "durable",
        }
    }
}

/// What a tool hands back.
///
/// Both shapes pin a schema, and the artifact shape pins a retention, so an
/// unbounded or unretained result is not representable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutputContract {
    /// The result travels inline in the tool result.
    Inline {
        /// The schema the inline value satisfies.
        schema: SchemaContract,
    },
    /// The result is an artifact referenced by the tool result.
    Artifact {
        /// The schema the artifact reference satisfies.
        schema: SchemaContract,
        /// How long the artifact is kept.
        retention: ArtifactRetention,
    },
}

impl OutputContract {
    /// The schema either shape pins.
    #[must_use]
    pub const fn schema(&self) -> &SchemaContract {
        match self {
            Self::Inline { schema } | Self::Artifact { schema, .. } => schema,
        }
    }

    /// The retention of an artifact result, if the result is one.
    #[must_use]
    pub const fn retention(&self) -> Option<ArtifactRetention> {
        match self {
            Self::Inline { .. } => None,
            Self::Artifact { retention, .. } => Some(*retention),
        }
    }
}

macro_rules! quantity_budget {
    ($name:ident, $label:literal, $max:expr, $ctor:ident, $doc:literal) => {
        #[doc = $doc]
        ///
        /// Non-zero by construction, so an absent budget cannot be spelled as
        /// a permissive one.
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(NonZeroU64);

        impl $name {
            /// The declared ceiling for this budget.
            pub const MAX: u64 = $max;

            /// Stable spelling reported when this budget is exceeded.
            pub const LABEL: &'static str = $label;

            #[doc = concat!("Reserve the ", $label, " budget.")]
            ///
            /// # Errors
            ///
            /// Returns [`ToolError::BudgetIsZero`] for zero and
            /// [`ToolError::BudgetOutOfRange`] above [`Self::MAX`].
            pub const fn $ctor(quantity: u64) -> Result<Self, ToolError> {
                if quantity > Self::MAX {
                    return Err(ToolError::BudgetOutOfRange {
                        budget: Self::LABEL,
                        max: Self::MAX,
                        requested: quantity,
                    });
                }
                match NonZeroU64::new(quantity) {
                    Some(value) => Ok(Self(value)),
                    None => Err(ToolError::BudgetIsZero {
                        budget: Self::LABEL,
                    }),
                }
            }

            /// The reserved quantity.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0.get()
            }
        }
    };
}

quantity_budget!(
    WallClockBudget,
    "wall_clock",
    24 * 60 * 60 * 1_000,
    millis,
    "A wall-clock reservation in milliseconds."
);
quantity_budget!(
    CpuBudget,
    "cpu",
    24 * 60 * 60 * 1_000,
    millis,
    "A CPU-time reservation in milliseconds."
);
quantity_budget!(
    MemoryBudget,
    "memory",
    64 * 1024 * 1024 * 1024,
    bytes,
    "A peak resident-memory reservation in bytes."
);
quantity_budget!(
    OutputBudget,
    "output",
    1024 * 1024 * 1024,
    bytes,
    "A produced-output reservation in bytes."
);

/// A ceiling on how many nested calls a workflow may make.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CallBudget(NonZeroU32);

impl CallBudget {
    /// The declared ceiling.
    pub const MAX: u32 = 4_096;

    /// Stable spelling reported when this budget is exceeded.
    pub const LABEL: &'static str = "max_calls";

    /// Reserve a call count.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::BudgetIsZero`] for zero and
    /// [`ToolError::BudgetOutOfRange`] above [`Self::MAX`].
    pub const fn calls(quantity: u32) -> Result<Self, ToolError> {
        if quantity > Self::MAX {
            return Err(ToolError::BudgetOutOfRange {
                budget: Self::LABEL,
                max: Self::MAX as u64,
                requested: quantity as u64,
            });
        }
        match NonZeroU32::new(quantity) {
            Some(value) => Ok(Self(value)),
            None => Err(ToolError::BudgetIsZero {
                budget: Self::LABEL,
            }),
        }
    }

    /// The reserved call count.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// The four resource ceilings every bounded execution declares.
///
/// Each component is a distinct type, so a memory ceiling cannot be passed
/// where an output ceiling belongs:
///
/// ```compile_fail
/// use automonique_protocol::tools::{MemoryBudget, ResourceBudget};
/// # fn wall() -> automonique_protocol::tools::WallClockBudget { unreachable!() }
/// # fn cpu() -> automonique_protocol::tools::CpuBudget { unreachable!() }
/// let memory = MemoryBudget::bytes(1 << 28).unwrap();
/// // The fourth argument is an output ceiling, not a second memory one.
/// let budget = ResourceBudget::new(wall(), cpu(), memory, memory);
/// ```
///
/// The same program with the output ceiling in the output position compiles:
///
/// ```no_run
/// use automonique_protocol::tools::{MemoryBudget, OutputBudget, ResourceBudget};
/// # fn wall() -> automonique_protocol::tools::WallClockBudget { unreachable!() }
/// # fn cpu() -> automonique_protocol::tools::CpuBudget { unreachable!() }
/// let memory = MemoryBudget::bytes(1 << 28).unwrap();
/// let output = OutputBudget::bytes(1 << 20).unwrap();
/// let budget = ResourceBudget::new(wall(), cpu(), memory, output);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceBudget {
    wall_clock: WallClockBudget,
    cpu: CpuBudget,
    memory: MemoryBudget,
    output: OutputBudget,
}

impl ResourceBudget {
    /// Fix all four ceilings.
    #[must_use]
    pub const fn new(
        wall_clock: WallClockBudget,
        cpu: CpuBudget,
        memory: MemoryBudget,
        output: OutputBudget,
    ) -> Self {
        Self {
            wall_clock,
            cpu,
            memory,
            output,
        }
    }

    /// The wall-clock ceiling.
    #[must_use]
    pub const fn wall_clock(self) -> WallClockBudget {
        self.wall_clock
    }

    /// The CPU-time ceiling.
    #[must_use]
    pub const fn cpu(self) -> CpuBudget {
        self.cpu
    }

    /// The peak-memory ceiling.
    #[must_use]
    pub const fn memory(self) -> MemoryBudget {
        self.memory
    }

    /// The produced-output ceiling.
    #[must_use]
    pub const fn output(self) -> OutputBudget {
        self.output
    }
}

/// Every field a [`ToolDescriptor`] needs, named at the call site.
///
/// A struct rather than a positional argument list, for the reason
/// [`crate::sandbox::SandboxSpecParts`] is one: several components share a
/// type, and a transposed call would compile while describing the wrong tool.
/// Naming them removes that hazard without making any field optional, and the
/// type deliberately implements no `Default`, so `..Default::default()` cannot
/// fill a field the caller never considered.
///
/// A descriptor without a side-effect class does not compile:
///
/// ```compile_fail
/// use automonique_protocol::sandbox::{SandboxProfile, ToolWorkloadEgress};
/// use automonique_protocol::tools::{
///     ApprovalRequirement, CapabilityId, CredentialAudiences, OutputContract, PlatformSupport,
///     ProvenanceDigest, ResourceBudget, SchemaContract, SideEffectClass, ToolDescriptor,
///     ToolDescriptorParts, TrustClass,
/// };
/// # fn schema() -> SchemaContract { unreachable!() }
/// # fn capability() -> CapabilityId { unreachable!() }
/// # fn provenance() -> ProvenanceDigest { unreachable!() }
/// # fn profile() -> SandboxProfile { unreachable!() }
/// # fn audiences() -> CredentialAudiences { unreachable!() }
/// # fn resources() -> ResourceBudget { unreachable!() }
/// # fn platforms() -> PlatformSupport { unreachable!() }
/// # fn output() -> OutputContract { unreachable!() }
/// let declared = ToolDescriptor::declare(ToolDescriptorParts {
///     id: "fs.read",
///     capability: capability(),
///     input_schema: schema(),
///     output_schema: schema(),
///     provenance: provenance(),
///     trust: TrustClass::FirstParty,
///     approval: ApprovalRequirement::PerInvocation,
///     sandbox_profile: profile(),
///     credential_audiences: audiences(),
///     egress: ToolWorkloadEgress::denied(),
///     resources: resources(),
///     platforms: platforms(),
///     output_contract: output(),
/// });
/// ```
///
/// A descriptor without an approval requirement does not compile:
///
/// ```compile_fail
/// use automonique_protocol::sandbox::{SandboxProfile, ToolWorkloadEgress};
/// use automonique_protocol::tools::{
///     ApprovalRequirement, CapabilityId, CredentialAudiences, OutputContract, PlatformSupport,
///     ProvenanceDigest, ResourceBudget, SchemaContract, SideEffectClass, ToolDescriptor,
///     ToolDescriptorParts, TrustClass,
/// };
/// # fn schema() -> SchemaContract { unreachable!() }
/// # fn capability() -> CapabilityId { unreachable!() }
/// # fn provenance() -> ProvenanceDigest { unreachable!() }
/// # fn profile() -> SandboxProfile { unreachable!() }
/// # fn audiences() -> CredentialAudiences { unreachable!() }
/// # fn resources() -> ResourceBudget { unreachable!() }
/// # fn platforms() -> PlatformSupport { unreachable!() }
/// # fn output() -> OutputContract { unreachable!() }
/// let declared = ToolDescriptor::declare(ToolDescriptorParts {
///     id: "fs.read",
///     capability: capability(),
///     input_schema: schema(),
///     output_schema: schema(),
///     provenance: provenance(),
///     trust: TrustClass::FirstParty,
///     side_effect: SideEffectClass::ReadOnly,
///     sandbox_profile: profile(),
///     credential_audiences: audiences(),
///     egress: ToolWorkloadEgress::denied(),
///     resources: resources(),
///     platforms: platforms(),
///     output_contract: output(),
/// });
/// ```
///
/// The complete literal, which differs from each case above by exactly the
/// omitted line, compiles:
///
/// ```no_run
/// use automonique_protocol::sandbox::{SandboxProfile, ToolWorkloadEgress};
/// use automonique_protocol::tools::{
///     ApprovalRequirement, CapabilityId, CredentialAudiences, OutputContract, PlatformSupport,
///     ProvenanceDigest, ResourceBudget, SchemaContract, SideEffectClass, ToolDescriptor,
///     ToolDescriptorParts, TrustClass,
/// };
/// # fn schema() -> SchemaContract { unreachable!() }
/// # fn capability() -> CapabilityId { unreachable!() }
/// # fn provenance() -> ProvenanceDigest { unreachable!() }
/// # fn profile() -> SandboxProfile { unreachable!() }
/// # fn audiences() -> CredentialAudiences { unreachable!() }
/// # fn resources() -> ResourceBudget { unreachable!() }
/// # fn platforms() -> PlatformSupport { unreachable!() }
/// # fn output() -> OutputContract { unreachable!() }
/// let declared = ToolDescriptor::declare(ToolDescriptorParts {
///     id: "fs.read",
///     capability: capability(),
///     input_schema: schema(),
///     output_schema: schema(),
///     provenance: provenance(),
///     trust: TrustClass::FirstParty,
///     side_effect: SideEffectClass::ReadOnly,
///     approval: ApprovalRequirement::PerInvocation,
///     sandbox_profile: profile(),
///     credential_audiences: audiences(),
///     egress: ToolWorkloadEgress::denied(),
///     resources: resources(),
///     platforms: platforms(),
///     output_contract: output(),
/// });
/// ```
///
/// A tool's egress is model-directed traffic, so the provider-control policy
/// is not accepted in that position:
///
/// ```compile_fail
/// use automonique_protocol::sandbox::ProviderControlEgress;
/// use automonique_protocol::tools::ToolDescriptorParts;
/// # fn parts() -> ToolDescriptorParts<'static> { unreachable!() }
/// let mut parts = parts();
/// parts.egress = ProviderControlEgress::denied();
/// ```
///
/// while the tool-workload policy is:
///
/// ```no_run
/// use automonique_protocol::sandbox::ToolWorkloadEgress;
/// use automonique_protocol::tools::ToolDescriptorParts;
/// # fn parts() -> ToolDescriptorParts<'static> { unreachable!() }
/// let mut parts = parts();
/// parts.egress = ToolWorkloadEgress::denied();
/// ```
#[derive(Clone, Debug)]
pub struct ToolDescriptorParts<'a> {
    /// The registry-facing tool identifier.
    pub id: &'a str,
    /// The provider-independent capability this tool implements.
    pub capability: CapabilityId,
    /// The pinned input schema.
    pub input_schema: SchemaContract,
    /// The pinned output schema.
    pub output_schema: SchemaContract,
    /// The digest of the implementation.
    pub provenance: ProvenanceDigest,
    /// How much scrutiny the implementation has had.
    pub trust: TrustClass,
    /// What the tool does to the world.
    pub side_effect: SideEffectClass,
    /// Whether an approval is needed before running.
    pub approval: ApprovalRequirement,
    /// The sandbox profile the tool runs under.
    pub sandbox_profile: SandboxProfile,
    /// Credential audiences the tool may present.
    pub credential_audiences: CredentialAudiences,
    /// Egress policy for this model-directed workload.
    pub egress: ToolWorkloadEgress,
    /// Resource ceilings for one invocation.
    pub resources: ResourceBudget,
    /// Platforms the tool supports.
    pub platforms: PlatformSupport,
    /// What the tool hands back.
    pub output_contract: OutputContract,
}

/// A tool the registry knows about.
///
/// Every component is a constructor argument with no default, and there is no
/// setter, so a descriptor cannot be built incomplete or widened afterwards.
/// Side-effect class and approval requirement are called out in the contract
/// because those two are what a policy decides on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolDescriptor {
    id: String,
    capability: CapabilityId,
    input_schema: SchemaContract,
    output_schema: SchemaContract,
    provenance: ProvenanceDigest,
    trust: TrustClass,
    side_effect: SideEffectClass,
    approval: ApprovalRequirement,
    sandbox_profile: SandboxProfile,
    credential_audiences: CredentialAudiences,
    egress: ToolWorkloadEgress,
    resources: ResourceBudget,
    platforms: PlatformSupport,
    output_contract: OutputContract,
}

impl ToolDescriptor {
    /// Describe a tool.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid component.
    pub fn declare(parts: ToolDescriptorParts<'_>) -> Result<Self, ToolError> {
        bounded(parts.id, "tool_id")?;
        Ok(Self {
            id: parts.id.to_owned(),
            capability: parts.capability,
            input_schema: parts.input_schema,
            output_schema: parts.output_schema,
            provenance: parts.provenance,
            trust: parts.trust,
            side_effect: parts.side_effect,
            approval: parts.approval,
            sandbox_profile: parts.sandbox_profile,
            credential_audiences: parts.credential_audiences,
            egress: parts.egress,
            resources: parts.resources,
            platforms: parts.platforms,
            output_contract: parts.output_contract,
        })
    }

    /// The tool identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The capability it implements.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityId {
        &self.capability
    }

    /// The pinned input schema.
    #[must_use]
    pub const fn input_schema(&self) -> &SchemaContract {
        &self.input_schema
    }

    /// The pinned output schema.
    #[must_use]
    pub const fn output_schema(&self) -> &SchemaContract {
        &self.output_schema
    }

    /// The implementation digest.
    #[must_use]
    pub const fn provenance(&self) -> &ProvenanceDigest {
        &self.provenance
    }

    /// How much scrutiny the implementation has had.
    #[must_use]
    pub const fn trust(&self) -> TrustClass {
        self.trust
    }

    /// What it does to the world.
    #[must_use]
    pub const fn side_effect(&self) -> SideEffectClass {
        self.side_effect
    }

    /// Whether it needs an approval.
    #[must_use]
    pub const fn approval(&self) -> ApprovalRequirement {
        self.approval
    }

    /// The sandbox profile it runs under.
    #[must_use]
    pub const fn sandbox_profile(&self) -> &SandboxProfile {
        &self.sandbox_profile
    }

    /// Credential audiences it may present.
    #[must_use]
    pub const fn credential_audiences(&self) -> &CredentialAudiences {
        &self.credential_audiences
    }

    /// Its egress policy.
    #[must_use]
    pub const fn egress(&self) -> ToolWorkloadEgress {
        self.egress
    }

    /// Its resource ceilings.
    #[must_use]
    pub const fn resources(&self) -> ResourceBudget {
        self.resources
    }

    /// Platforms it supports.
    #[must_use]
    pub const fn platforms(&self) -> &PlatformSupport {
        &self.platforms
    }

    /// What it hands back.
    #[must_use]
    pub const fn output_contract(&self) -> &OutputContract {
        &self.output_contract
    }
}

/// A scope a toolset grant can be attached to.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GrantScope {
    /// The owning tenant.
    Tenant,
    /// The agent profile.
    Profile,
    /// The workspace.
    Workspace,
    /// The channel the session arrived on.
    Channel,
    /// The automation that started the run.
    Automation,
}

impl GrantScope {
    /// Every scope, for coverage checks.
    pub const ALL: [Self; 5] = [
        Self::Tenant,
        Self::Profile,
        Self::Workspace,
        Self::Channel,
        Self::Automation,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Profile => "profile",
            Self::Workspace => "workspace",
            Self::Channel => "channel",
            Self::Automation => "automation",
        }
    }
}

/// One scope's grant of tool identifiers.
///
/// The only combining operation is [`ToolsetGrant::intersect`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ToolsetGrant {
    allowed: Vec<String>,
}

impl ToolsetGrant {
    /// Grant an explicit set.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid identifier.
    pub fn new(allowed: &[&str]) -> Result<Self, ToolError> {
        for id in allowed {
            bounded(id, "tool_id")?;
        }
        let mut owned: Vec<String> = allowed.iter().map(|id| (*id).to_owned()).collect();
        owned.sort();
        owned.dedup();
        Ok(Self { allowed: owned })
    }

    /// The effective grant when both scopes apply.
    #[must_use]
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            allowed: self
                .allowed
                .iter()
                .filter(|id| other.allowed.contains(id))
                .cloned()
                .collect(),
        }
    }

    /// The granted identifiers.
    #[must_use]
    pub fn allowed(&self) -> &[String] {
        &self.allowed
    }

    /// Whether a tool is granted.
    #[must_use]
    pub fn permits(&self, id: &str) -> bool {
        self.allowed.iter().any(|allowed| allowed == id)
    }
}

/// A grant together with the scope it came from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopedGrant {
    scope: GrantScope,
    grant: ToolsetGrant,
}

impl ScopedGrant {
    /// Attach a grant to its scope.
    #[must_use]
    pub const fn new(scope: GrantScope, grant: ToolsetGrant) -> Self {
        Self { scope, grant }
    }

    /// The scope this grant came from.
    #[must_use]
    pub const fn scope(&self) -> GrantScope {
        self.scope
    }

    /// The granted set.
    #[must_use]
    pub const fn grant(&self) -> &ToolsetGrant {
        &self.grant
    }
}

/// The effective grant across every applicable scope.
///
/// Intersection is the only combining operation, so adding a scope can never
/// add a tool. With no applicable grant the result permits nothing: an absent
/// grant is not a permissive one.
#[must_use]
pub fn effective_grant(scoped: &[ScopedGrant]) -> ToolsetGrant {
    let mut remaining = scoped.iter();
    let Some(first) = remaining.next() else {
        return ToolsetGrant::default();
    };
    remaining.fold(first.grant.clone(), |effective, next| {
        effective.intersect(&next.grant)
    })
}

/// A durable change to a session's toolset.
///
/// Carrying a cause is what makes the change durable rather than incidental:
/// there is no constructor without one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolsetChange {
    grant: ToolsetGrant,
    cause: NestedCause,
}

impl ToolsetChange {
    /// Record a change and what caused it.
    #[must_use]
    pub const fn recorded(grant: ToolsetGrant, cause: NestedCause) -> Self {
        Self { grant, cause }
    }

    /// The grant the session moves to.
    #[must_use]
    pub const fn grant(&self) -> &ToolsetGrant {
        &self.grant
    }

    /// What caused the change.
    #[must_use]
    pub const fn cause(&self) -> &NestedCause {
        &self.cause
    }
}

/// The toolset a session is currently working under.
///
/// A search borrows it immutably and returns owned results, and the only
/// mutating operation takes a [`ToolsetChange`], so looking cannot change what
/// a session may reach:
///
/// ```compile_fail
/// use automonique_protocol::tools::{SessionToolset, ToolDescriptor, search_tools};
/// # fn registry() -> Vec<ToolDescriptor> { unreachable!() }
/// # fn toolset() -> SessionToolset { unreachable!() }
/// let registry = registry();
/// let mut toolset = toolset();
/// let results = search_tools(&registry, toolset.grant(), "fs");
/// // A search result is not a durable event.
/// toolset.apply(results);
/// ```
///
/// ```no_run
/// use automonique_protocol::tools::{
///     SessionToolset, ToolDescriptor, ToolsetChange, search_tools,
/// };
/// # fn registry() -> Vec<ToolDescriptor> { unreachable!() }
/// # fn toolset() -> SessionToolset { unreachable!() }
/// # fn change() -> ToolsetChange { unreachable!() }
/// let registry = registry();
/// let mut toolset = toolset();
/// let results = search_tools(&registry, toolset.grant(), "fs");
/// toolset.apply(change());
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionToolset {
    grant: ToolsetGrant,
    revision: u32,
}

impl SessionToolset {
    /// Open a session under a grant.
    #[must_use]
    pub const fn opened(grant: ToolsetGrant) -> Self {
        Self { grant, revision: 0 }
    }

    /// The grant in force.
    #[must_use]
    pub const fn grant(&self) -> &ToolsetGrant {
        &self.grant
    }

    /// How many durable changes have been applied.
    #[must_use]
    pub const fn revision(&self) -> u32 {
        self.revision
    }

    /// Apply a durable change.
    pub fn apply(&mut self, change: ToolsetChange) {
        self.grant = change.grant;
        self.revision = self.revision.saturating_add(1);
    }
}

/// The result of a deferred tool search.
///
/// Carries only tools the caller may reach. An unauthorized tool is absent
/// from the results and from any diagnostic, so search cannot enumerate the
/// registry.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SearchResults {
    matches: Vec<String>,
}

impl SearchResults {
    /// The authorized matches.
    #[must_use]
    pub fn matches(&self) -> &[String] {
        &self.matches
    }

    /// Whether anything matched.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }
}

/// Search the registry within a grant.
///
/// Takes the grant, so there is no call shape that searches without one, and
/// takes the registry by shared reference, so a search cannot alter it.
#[must_use]
pub fn search_tools(
    registry: &[ToolDescriptor],
    grant: &ToolsetGrant,
    query: &str,
) -> SearchResults {
    let mut matches: Vec<String> = registry
        .iter()
        .filter(|tool| grant.permits(&tool.id))
        .filter(|tool| tool.id.contains(query))
        .map(|tool| tool.id.clone())
        .collect();
    matches.sort();
    SearchResults { matches }
}

/// Load the exact schemas of one authorized tool.
///
/// Returns [`None`] for a tool the grant does not permit *and* for a tool that
/// does not exist, so the answer distinguishes neither case. There is no error
/// return, so no diagnostic can name a tool the caller may not reach.
#[must_use]
pub fn describe_tool<'a>(
    registry: &'a [ToolDescriptor],
    grant: &ToolsetGrant,
    id: &str,
) -> Option<&'a ToolDescriptor> {
    registry
        .iter()
        .find(|tool| tool.id == id && grant.permits(&tool.id))
}

/// Actor, run and causation identity carried by a nested call.
///
/// All three are constructor arguments, so a call that has lost one is not
/// representable. A child cause keeps the actor and run of its parent and
/// records the parent step, so a chain cannot be re-parented onto a different
/// principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NestedCause {
    actor: Actor,
    run: RunId,
    causation: CausationId,
    parent: Option<CausationId>,
}

impl NestedCause {
    /// Name the root cause of a run.
    #[must_use]
    pub const fn root(actor: Actor, run: RunId, causation: CausationId) -> Self {
        Self {
            actor,
            run,
            causation,
            parent: None,
        }
    }

    /// The principal the call acts for.
    #[must_use]
    pub const fn actor(&self) -> &Actor {
        &self.actor
    }

    /// The run the call belongs to.
    #[must_use]
    pub const fn run(&self) -> &RunId {
        &self.run
    }

    /// The step this call is.
    #[must_use]
    pub const fn causation(&self) -> &CausationId {
        &self.causation
    }

    /// The step that caused this one, if this is not the root.
    #[must_use]
    pub const fn parent(&self) -> Option<&CausationId> {
        self.parent.as_ref()
    }

    /// Derive the cause of a step this one causes.
    ///
    /// The actor and run are carried over rather than supplied, so a nested
    /// call cannot be attributed to a different principal or run.
    #[must_use]
    pub fn caused(&self, causation: CausationId) -> Self {
        Self {
            actor: self.actor.clone(),
            run: self.run.clone(),
            causation,
            parent: Some(self.causation.clone()),
        }
    }
}

/// A tool a workflow program is permitted to call.
///
/// Built only from a descriptor that is neither a privilege broker nor one of
/// the [`RESERVED_CAPABILITIES`], so no [`WorkflowSpec`] value can name the
/// workflow tool itself, delegation, raw MCP, an approval decision or a
/// broker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowInvocable {
    tool: String,
    capability: CapabilityId,
    approval: ApprovalRequirement,
}

impl WorkflowInvocable {
    /// Admit a descriptor to a workflow's eligible set.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::WorkflowToolNotEligible`] for a privileged-request
    /// tool or a reserved capability. The error names no tool.
    pub fn eligible(descriptor: &ToolDescriptor) -> Result<Self, ToolError> {
        if descriptor.side_effect() == SideEffectClass::PrivilegedRequest
            || RESERVED_CAPABILITIES.contains(&descriptor.capability().as_str())
        {
            return Err(ToolError::WorkflowToolNotEligible);
        }
        Ok(Self {
            tool: descriptor.id().to_owned(),
            capability: descriptor.capability().clone(),
            approval: descriptor.approval(),
        })
    }

    /// The tool identifier.
    #[must_use]
    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// The capability it implements.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityId {
        &self.capability
    }

    /// The approval it still requires.
    #[must_use]
    pub const fn approval(&self) -> ApprovalRequirement {
        self.approval
    }
}

/// Everything a workflow's authority is bounded by.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkflowBudget {
    calls: CallBudget,
    resources: ResourceBudget,
}

impl WorkflowBudget {
    /// Fix the call ceiling and the four resource ceilings.
    #[must_use]
    pub const fn new(calls: CallBudget, resources: ResourceBudget) -> Self {
        Self { calls, resources }
    }

    /// The call ceiling.
    #[must_use]
    pub const fn calls(self) -> CallBudget {
        self.calls
    }

    /// The resource ceilings.
    #[must_use]
    pub const fn resources(self) -> ResourceBudget {
        self.resources
    }
}

/// What one nested call declares it consumed.
///
/// This module measures nothing; a host reports the cost and the capability
/// accounts for it. Every component is a constructor argument and the type has
/// no `Default`, so a call cannot report a partial cost.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NestedCallCost {
    wall_clock_millis: u64,
    cpu_millis: u64,
    memory_bytes: u64,
    output_bytes: u64,
}

impl NestedCallCost {
    /// Report a call's cost.
    #[must_use]
    pub const fn new(
        wall_clock_millis: u64,
        cpu_millis: u64,
        memory_bytes: u64,
        output_bytes: u64,
    ) -> Self {
        Self {
            wall_clock_millis,
            cpu_millis,
            memory_bytes,
            output_bytes,
        }
    }

    /// Wall-clock milliseconds consumed.
    #[must_use]
    pub const fn wall_clock_millis(self) -> u64 {
        self.wall_clock_millis
    }

    /// CPU milliseconds consumed.
    #[must_use]
    pub const fn cpu_millis(self) -> u64 {
        self.cpu_millis
    }

    /// Peak resident bytes.
    #[must_use]
    pub const fn memory_bytes(self) -> u64 {
        self.memory_bytes
    }

    /// Output bytes produced.
    #[must_use]
    pub const fn output_bytes(self) -> u64 {
        self.output_bytes
    }
}

/// The immutable specification a workflow capability is issued from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowSpec {
    eligible: Vec<WorkflowInvocable>,
    budget: WorkflowBudget,
    cause: NestedCause,
}

impl WorkflowSpec {
    /// Fix the eligible set, the budgets and the cause of the workflow.
    #[must_use]
    pub const fn declare(
        eligible: Vec<WorkflowInvocable>,
        budget: WorkflowBudget,
        cause: NestedCause,
    ) -> Self {
        Self {
            eligible,
            budget,
            cause,
        }
    }

    /// The tools the workflow may call.
    #[must_use]
    pub fn eligible(&self) -> &[WorkflowInvocable] {
        &self.eligible
    }

    /// The budgets.
    #[must_use]
    pub const fn budget(&self) -> WorkflowBudget {
        self.budget
    }

    /// The cause every nested call descends from.
    #[must_use]
    pub const fn cause(&self) -> &NestedCause {
        &self.cause
    }
}

/// What a permitted nested call produced.
///
/// Carries identity and the approval the call still needs. It carries no
/// grant, no capability and no approval *decision*, so a call cannot be used
/// to bootstrap authority the workflow did not start with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NestedCallReceipt {
    tool: String,
    capability: CapabilityId,
    cause: NestedCause,
    approval: ApprovalRequirement,
}

impl NestedCallReceipt {
    /// The tool that was called.
    #[must_use]
    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// The capability it implements.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityId {
        &self.capability
    }

    /// Actor, run and causation identity of the call.
    #[must_use]
    pub const fn cause(&self) -> &NestedCause {
        &self.cause
    }

    /// The approval the call is still subject to.
    #[must_use]
    pub const fn approval_required(&self) -> ApprovalRequirement {
        self.approval
    }
}

/// The bounded authority a workflow program receives.
///
/// The type reaches nothing but [`WorkflowCapability::invoke`] over its own
/// eligible set. It has no operation that runs another workflow, so recursion
/// and self-invocation are unreachable:
///
/// ```compile_fail
/// use automonique_protocol::tools::WorkflowCapability;
/// # fn capability() -> WorkflowCapability { unreachable!() }
/// # fn cause() -> automonique_protocol::tools::CausationId { unreachable!() }
/// # fn cost() -> automonique_protocol::tools::NestedCallCost { unreachable!() }
/// let mut capability = capability();
/// let outcome = capability.invoke_workflow("fs.read", cause(), cost());
/// ```
///
/// ```no_run
/// use automonique_protocol::tools::WorkflowCapability;
/// # fn capability() -> WorkflowCapability { unreachable!() }
/// # fn cause() -> automonique_protocol::tools::CausationId { unreachable!() }
/// # fn cost() -> automonique_protocol::tools::NestedCallCost { unreachable!() }
/// let mut capability = capability();
/// let outcome = capability.invoke("fs.read", cause(), cost());
/// ```
///
/// no operation that delegates:
///
/// ```compile_fail
/// use automonique_protocol::tools::WorkflowCapability;
/// # fn capability() -> WorkflowCapability { unreachable!() }
/// # fn cause() -> automonique_protocol::tools::CausationId { unreachable!() }
/// # fn cost() -> automonique_protocol::tools::NestedCallCost { unreachable!() }
/// let mut capability = capability();
/// let outcome = capability.delegate("fs.read", cause(), cost());
/// ```
///
/// no operation that reaches an MCP server directly:
///
/// ```compile_fail
/// use automonique_protocol::tools::WorkflowCapability;
/// # fn capability() -> WorkflowCapability { unreachable!() }
/// # fn cause() -> automonique_protocol::tools::CausationId { unreachable!() }
/// # fn cost() -> automonique_protocol::tools::NestedCallCost { unreachable!() }
/// let mut capability = capability();
/// let outcome = capability.mcp_call("fs.read", cause(), cost());
/// ```
///
/// no operation that decides an approval:
///
/// ```compile_fail
/// use automonique_protocol::tools::WorkflowCapability;
/// # fn capability() -> WorkflowCapability { unreachable!() }
/// # fn cause() -> automonique_protocol::tools::CausationId { unreachable!() }
/// # fn cost() -> automonique_protocol::tools::NestedCallCost { unreachable!() }
/// let mut capability = capability();
/// let outcome = capability.approve("fs.read", cause(), cost());
/// ```
///
/// and no operation that reaches a privilege broker:
///
/// ```compile_fail
/// use automonique_protocol::tools::WorkflowCapability;
/// # fn capability() -> WorkflowCapability { unreachable!() }
/// # fn cause() -> automonique_protocol::tools::CausationId { unreachable!() }
/// # fn cost() -> automonique_protocol::tools::NestedCallCost { unreachable!() }
/// let mut capability = capability();
/// let outcome = capability.request_privilege("fs.read", cause(), cost());
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowCapability {
    spec: WorkflowSpec,
    calls_made: u32,
    spent_wall_clock_millis: u64,
    spent_cpu_millis: u64,
    peak_memory_bytes: u64,
    spent_output_bytes: u64,
}

impl WorkflowCapability {
    /// Issue a capability against a specification.
    #[must_use]
    pub const fn granted(spec: WorkflowSpec) -> Self {
        Self {
            spec,
            calls_made: 0,
            spent_wall_clock_millis: 0,
            spent_cpu_millis: 0,
            peak_memory_bytes: 0,
            spent_output_bytes: 0,
        }
    }

    /// The specification this capability was issued from.
    #[must_use]
    pub const fn spec(&self) -> &WorkflowSpec {
        &self.spec
    }

    /// Make one nested call.
    ///
    /// The receipt's identity is derived from the workflow's own cause, so the
    /// caller cannot supply an actor or run of its own choosing and cannot
    /// make a call that carries no causation. Nothing is charged when the call
    /// is refused.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::WorkflowToolNotEligible`] for a tool outside the
    /// eligible set and [`ToolError::WorkflowBudgetExceeded`] naming the first
    /// budget the call would exceed.
    pub fn invoke(
        &mut self,
        tool: &str,
        causation: CausationId,
        cost: NestedCallCost,
    ) -> Result<NestedCallReceipt, ToolError> {
        let Some(invocable) = self
            .spec
            .eligible
            .iter()
            .find(|candidate| candidate.tool == tool)
        else {
            return Err(ToolError::WorkflowToolNotEligible);
        };
        let budget = self.spec.budget;
        if self.calls_made >= budget.calls.get() {
            return Err(ToolError::WorkflowBudgetExceeded {
                budget: CallBudget::LABEL,
            });
        }
        let wall_clock = self
            .spent_wall_clock_millis
            .saturating_add(cost.wall_clock_millis);
        if wall_clock > budget.resources.wall_clock.get() {
            return Err(ToolError::WorkflowBudgetExceeded {
                budget: WallClockBudget::LABEL,
            });
        }
        let cpu = self.spent_cpu_millis.saturating_add(cost.cpu_millis);
        if cpu > budget.resources.cpu.get() {
            return Err(ToolError::WorkflowBudgetExceeded {
                budget: CpuBudget::LABEL,
            });
        }
        if cost.memory_bytes > budget.resources.memory.get() {
            return Err(ToolError::WorkflowBudgetExceeded {
                budget: MemoryBudget::LABEL,
            });
        }
        let output = self.spent_output_bytes.saturating_add(cost.output_bytes);
        if output > budget.resources.output.get() {
            return Err(ToolError::WorkflowBudgetExceeded {
                budget: OutputBudget::LABEL,
            });
        }
        let receipt = NestedCallReceipt {
            tool: invocable.tool.clone(),
            capability: invocable.capability.clone(),
            cause: self.spec.cause.caused(causation),
            approval: invocable.approval,
        };
        self.calls_made = self.calls_made.saturating_add(1);
        self.spent_wall_clock_millis = wall_clock;
        self.spent_cpu_millis = cpu;
        self.peak_memory_bytes = self.peak_memory_bytes.max(cost.memory_bytes);
        self.spent_output_bytes = output;
        Ok(receipt)
    }

    /// How many calls have been made.
    #[must_use]
    pub const fn calls_made(&self) -> u32 {
        self.calls_made
    }

    /// What has been charged so far, with memory as the observed peak.
    #[must_use]
    pub const fn spent(&self) -> NestedCallCost {
        NestedCallCost::new(
            self.spent_wall_clock_millis,
            self.spent_cpu_millis,
            self.peak_memory_bytes,
            self.spent_output_bytes,
        )
    }
}

/// How an MCP server is reached.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum McpTransport {
    /// A local child process over stdio.
    LocalStdio,
    /// A remote server over Streamable HTTP.
    RemoteStreamableHttp,
}

impl McpTransport {
    /// Every transport, for coverage checks.
    pub const ALL: [Self; 2] = [Self::LocalStdio, Self::RemoteStreamableHttp];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalStdio => "local_stdio",
            Self::RemoteStreamableHttp => "remote_streamable_http",
        }
    }
}

/// What stands between this host and an MCP server.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum McpTrustBoundary {
    /// The server runs in its own attested child sandbox.
    AttestedChildSandbox,
    /// The server is reached across a reviewed HTTPS identity.
    ReviewedHttpsIdentity,
}

impl McpTrustBoundary {
    /// Every boundary, for coverage checks.
    pub const ALL: [Self; 2] = [Self::AttestedChildSandbox, Self::ReviewedHttpsIdentity];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AttestedChildSandbox => "attested_child_sandbox",
            Self::ReviewedHttpsIdentity => "reviewed_https_identity",
        }
    }
}

/// How long discovery may take before the server is treated as unreachable.
///
/// Non-zero and bounded, so a client that waits forever is not representable.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DiscoveryTimeout(NonZeroU32);

impl DiscoveryTimeout {
    /// The declared ceiling in milliseconds.
    pub const MAX_MILLIS: u32 = 120_000;

    /// Set a discovery timeout.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::BudgetIsZero`] for zero and
    /// [`ToolError::BudgetOutOfRange`] above [`Self::MAX_MILLIS`].
    pub const fn millis(quantity: u32) -> Result<Self, ToolError> {
        if quantity > Self::MAX_MILLIS {
            return Err(ToolError::BudgetOutOfRange {
                budget: "discovery_timeout",
                max: Self::MAX_MILLIS as u64,
                requested: quantity as u64,
            });
        }
        match NonZeroU32::new(quantity) {
            Some(value) => Ok(Self(value)),
            None => Err(ToolError::BudgetIsZero {
                budget: "discovery_timeout",
            }),
        }
    }

    /// The timeout in milliseconds.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Which of a server's tools this host imports.
///
/// The only constructor is an explicit list, so importing whatever a server
/// happens to advertise is not representable.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct McpToolFilter(Vec<String>);

impl McpToolFilter {
    /// Import nothing.
    #[must_use]
    pub const fn none() -> Self {
        Self(Vec::new())
    }

    /// Import exactly these tools.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid identifier.
    pub fn exactly(tools: &[&str]) -> Result<Self, ToolError> {
        let mut owned = Vec::with_capacity(tools.len());
        for tool in tools {
            bounded(tool, "mcp_tool")?;
            owned.push((*tool).to_owned());
        }
        owned.sort();
        owned.dedup();
        Ok(Self(owned))
    }

    /// The imported tools.
    #[must_use]
    pub fn tools(&self) -> &[String] {
        &self.0
    }

    /// Whether a server tool is imported.
    #[must_use]
    pub fn imports(&self, tool: &str) -> bool {
        self.0.iter().any(|imported| imported == tool)
    }
}

/// Which credential audience is presented to a server, under which name.
///
/// A mapping is explicit in both halves: nothing is inherited from the host
/// environment.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct McpCredentialMapping(Vec<(String, String)>);

impl McpCredentialMapping {
    /// Present no credential.
    #[must_use]
    pub const fn none() -> Self {
        Self(Vec::new())
    }

    /// Map server-side variable names onto credential audiences.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid component.
    pub fn exactly(entries: &[(&str, &str)]) -> Result<Self, ToolError> {
        let mut owned = Vec::with_capacity(entries.len());
        for (name, audience) in entries {
            bounded(name, "mcp_credential_name")?;
            bounded(audience, "credential_audience")?;
            owned.push(((*name).to_owned(), (*audience).to_owned()));
        }
        owned.sort();
        owned.dedup();
        Ok(Self(owned))
    }

    /// The declared mappings.
    #[must_use]
    pub fn entries(&self) -> &[(String, String)] {
        &self.0
    }
}

/// A budgeted, policy-checked grant for server-initiated sampling.
///
/// Carries a budget and an approval requirement and nothing else: there is no
/// actor, credential or grant on this type, so an enabled sampling request
/// cannot inherit the user's authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SamplingGrant {
    budget: ResourceBudget,
    approval: ApprovalRequirement,
}

impl SamplingGrant {
    /// Grant sampling under a budget and an approval requirement.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::SamplingNeedsApproval`] when no approval is
    /// required, because an unapproved server-initiated model request is
    /// exactly the implicit authority this type exists to prevent.
    pub const fn new(
        budget: ResourceBudget,
        approval: ApprovalRequirement,
    ) -> Result<Self, ToolError> {
        match approval {
            ApprovalRequirement::None => Err(ToolError::SamplingNeedsApproval),
            ApprovalRequirement::PerSession | ApprovalRequirement::PerInvocation => {
                Ok(Self { budget, approval })
            }
        }
    }

    /// The budget the nested request runs under.
    #[must_use]
    pub const fn budget(self) -> ResourceBudget {
        self.budget
    }

    /// The approval the nested request is subject to.
    #[must_use]
    pub const fn approval(self) -> ApprovalRequirement {
        self.approval
    }
}

/// Whether a server may ask this host to run a model request.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum McpSampling {
    /// Off. This is what a declared client has until someone says otherwise.
    #[default]
    Disabled,
    /// On, under a budget and an approval requirement.
    Budgeted(SamplingGrant),
}

impl McpSampling {
    /// Whether sampling is enabled.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Budgeted(_))
    }

    /// The grant, when sampling is enabled.
    #[must_use]
    pub const fn grant(self) -> Option<SamplingGrant> {
        match self {
            Self::Disabled => None,
            Self::Budgeted(grant) => Some(grant),
        }
    }
}

/// Every field an [`McpClientDescriptor`] needs, named at the call site.
///
/// Sampling is deliberately absent: [`McpClientDescriptor::declare`] cannot
/// produce an enabled client, so enabling it is always a separate, greppable
/// act.
#[derive(Clone, Debug)]
pub struct McpClientParts<'a> {
    /// The server's local name.
    pub name: &'a str,
    /// How it is reached.
    pub transport: McpTransport,
    /// What stands between this host and it.
    pub trust_boundary: McpTrustBoundary,
    /// How long discovery may take.
    pub discovery_timeout: DiscoveryTimeout,
    /// Which of its tools are imported.
    pub tool_filter: McpToolFilter,
    /// Which credentials are presented, under which names.
    pub credential_mapping: McpCredentialMapping,
}

/// A configured MCP client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpClientDescriptor {
    name: String,
    transport: McpTransport,
    trust_boundary: McpTrustBoundary,
    discovery_timeout: DiscoveryTimeout,
    tool_filter: McpToolFilter,
    credential_mapping: McpCredentialMapping,
    sampling: McpSampling,
}

impl McpClientDescriptor {
    /// Declare a client. Sampling is [`McpSampling::Disabled`].
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid component.
    pub fn declare(parts: McpClientParts<'_>) -> Result<Self, ToolError> {
        bounded(parts.name, "mcp_server_name")?;
        Ok(Self {
            name: parts.name.to_owned(),
            transport: parts.transport,
            trust_boundary: parts.trust_boundary,
            discovery_timeout: parts.discovery_timeout,
            tool_filter: parts.tool_filter,
            credential_mapping: parts.credential_mapping,
            sampling: McpSampling::Disabled,
        })
    }

    /// Enable server-initiated sampling under a grant.
    ///
    /// Consumes and returns the descriptor rather than mutating one in place,
    /// so an enabled client is a value someone produced on purpose.
    #[must_use]
    pub fn with_sampling(mut self, grant: SamplingGrant) -> Self {
        self.sampling = McpSampling::Budgeted(grant);
        self
    }

    /// The server's local name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// How it is reached.
    #[must_use]
    pub const fn transport(&self) -> McpTransport {
        self.transport
    }

    /// What stands between this host and it.
    #[must_use]
    pub const fn trust_boundary(&self) -> McpTrustBoundary {
        self.trust_boundary
    }

    /// How long discovery may take.
    #[must_use]
    pub const fn discovery_timeout(&self) -> DiscoveryTimeout {
        self.discovery_timeout
    }

    /// Which of its tools are imported.
    #[must_use]
    pub const fn tool_filter(&self) -> &McpToolFilter {
        &self.tool_filter
    }

    /// Which credentials are presented.
    #[must_use]
    pub const fn credential_mapping(&self) -> &McpCredentialMapping {
        &self.credential_mapping
    }

    /// Whether the server may ask this host to run a model request.
    #[must_use]
    pub const fn sampling(&self) -> McpSampling {
        self.sampling
    }
}

/// A resource an MCP export may carry.
///
/// An exported resource names the capability that reaches it, an artifact class
/// and its retention. There is no shape for an unrestricted artifact, and none
/// for a store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceExport {
    capability: CapabilityId,
    artifact_class: String,
    retention: ArtifactRetention,
}

impl ResourceExport {
    /// Export one artifact class under a capability and a retention.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid class.
    pub fn new(
        capability: CapabilityId,
        artifact_class: &str,
        retention: ArtifactRetention,
    ) -> Result<Self, ToolError> {
        bounded(artifact_class, "artifact_class")?;
        Ok(Self {
            capability,
            artifact_class: artifact_class.to_owned(),
            retention,
        })
    }

    /// The capability that reaches it.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityId {
        &self.capability
    }

    /// The artifact class.
    #[must_use]
    pub fn artifact_class(&self) -> &str {
        &self.artifact_class
    }

    /// How long it is kept.
    #[must_use]
    pub const fn retention(&self) -> ArtifactRetention {
        self.retention
    }
}

/// A prompt an MCP export may carry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromptExport {
    capability: CapabilityId,
    name: String,
    schema: SchemaContract,
}

impl PromptExport {
    /// Export one prompt under a capability, against a pinned schema.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid name.
    pub fn new(
        capability: CapabilityId,
        name: &str,
        schema: SchemaContract,
    ) -> Result<Self, ToolError> {
        bounded(name, "prompt_name")?;
        Ok(Self {
            capability,
            name: name.to_owned(),
            schema,
        })
    }

    /// The capability that reaches it.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityId {
        &self.capability
    }

    /// The prompt name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The pinned schema.
    #[must_use]
    pub const fn schema(&self) -> &SchemaContract {
        &self.schema
    }
}

/// Something this host is willing to expose over its MCP server.
///
/// The three shapes here are the whole of what an export can be. There is no
/// variant for the raw store:
///
/// ```compile_fail
/// use automonique_protocol::tools::{CapabilityId, ExportItem};
/// # fn capability() -> CapabilityId { unreachable!() }
/// let item = ExportItem::RawStore(capability());
/// ```
///
/// none for hidden reasoning:
///
/// ```compile_fail
/// use automonique_protocol::tools::{CapabilityId, ExportItem};
/// # fn capability() -> CapabilityId { unreachable!() }
/// let item = ExportItem::HiddenReasoning(capability());
/// ```
///
/// none for credentials:
///
/// ```compile_fail
/// use automonique_protocol::tools::{CapabilityId, ExportItem};
/// # fn capability() -> CapabilityId { unreachable!() }
/// let item = ExportItem::Credential(capability());
/// ```
///
/// none for an unrestricted artifact:
///
/// ```compile_fail
/// use automonique_protocol::tools::{CapabilityId, ExportItem};
/// # fn capability() -> CapabilityId { unreachable!() }
/// let item = ExportItem::UnrestrictedArtifact(capability());
/// ```
///
/// and none for broker input:
///
/// ```compile_fail
/// use automonique_protocol::tools::{CapabilityId, ExportItem};
/// # fn capability() -> CapabilityId { unreachable!() }
/// let item = ExportItem::BrokerInput(capability());
/// ```
///
/// The only shape that takes a capability on its own is a tool, so each case
/// above fails for the missing variant and not for its argument:
///
/// ```no_run
/// use automonique_protocol::tools::{CapabilityId, ExportItem};
/// # fn capability() -> CapabilityId { unreachable!() }
/// let item = ExportItem::Tool(capability());
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExportItem {
    /// A capability-filtered tool.
    Tool(CapabilityId),
    /// A retained artifact class.
    Resource(ResourceExport),
    /// A prompt.
    Prompt(PromptExport),
}

impl ExportItem {
    /// The capability that reaches this item.
    ///
    /// Every shape has one, so every shape is filterable; there is no export
    /// that escapes the filter by having no capability to check.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityId {
        match self {
            Self::Tool(capability) => capability,
            Self::Resource(resource) => resource.capability(),
            Self::Prompt(prompt) => prompt.capability(),
        }
    }
}

/// What this host exposes to an authorized external MCP client.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct McpServerExport {
    items: Vec<ExportItem>,
}

impl McpServerExport {
    /// Keep only the items the caller's grant reaches.
    ///
    /// Tools, resources and prompts are all filtered by capability; an item
    /// outside the grant is absent from the export rather than present and
    /// refused later.
    #[must_use]
    pub fn capability_filtered(items: &[ExportItem], grant: &ToolsetGrant) -> Self {
        Self {
            items: items
                .iter()
                .filter(|item| grant.permits(item.capability().as_str()))
                .cloned()
                .collect(),
        }
    }

    /// The exported items.
    #[must_use]
    pub fn items(&self) -> &[ExportItem] {
        &self.items
    }
}

/// What a backend extension contributes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BackendExtensionKind {
    /// A tool.
    Tool,
    /// A lifecycle hook.
    Hook,
    /// A memory provider.
    MemoryProvider,
    /// A context engine.
    ContextEngine,
    /// A model or provider adapter.
    ModelProvider,
    /// A browser or media backend.
    MediaBackend,
    /// A secret source.
    SecretSource,
    /// A connector.
    Connector,
    /// A distribution package.
    Distribution,
}

impl BackendExtensionKind {
    /// Every kind, for coverage checks.
    pub const ALL: [Self; 9] = [
        Self::Tool,
        Self::Hook,
        Self::MemoryProvider,
        Self::ContextEngine,
        Self::ModelProvider,
        Self::MediaBackend,
        Self::SecretSource,
        Self::Connector,
        Self::Distribution,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tool => "tool",
            Self::Hook => "hook",
            Self::MemoryProvider => "memory_provider",
            Self::ContextEngine => "context_engine",
            Self::ModelProvider => "model_provider",
            Self::MediaBackend => "media_backend",
            Self::SecretSource => "secret_source",
            Self::Connector => "connector",
            Self::Distribution => "distribution",
        }
    }
}

/// Which surface a UI extension renders.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UiSurface {
    /// The web dashboard.
    Dashboard,
    /// The desktop client.
    Desktop,
    /// The terminal interface.
    Tui,
}

impl UiSurface {
    /// Every surface, for coverage checks.
    pub const ALL: [Self; 3] = [Self::Dashboard, Self::Desktop, Self::Tui];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dashboard => "dashboard",
            Self::Desktop => "desktop",
            Self::Tui => "tui",
        }
    }
}

/// What a backend extension runs and what authority it asks for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendContribution {
    kind: BackendExtensionKind,
    entry_point: String,
    capabilities: Vec<CapabilityId>,
}

impl BackendContribution {
    /// Declare a backend contribution.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid entry point.
    pub fn new(
        kind: BackendExtensionKind,
        entry_point: &str,
        capabilities: Vec<CapabilityId>,
    ) -> Result<Self, ToolError> {
        bounded(entry_point, "entry_point")?;
        Ok(Self {
            kind,
            entry_point: entry_point.to_owned(),
            capabilities,
        })
    }

    /// What it contributes.
    #[must_use]
    pub const fn kind(&self) -> BackendExtensionKind {
        self.kind
    }

    /// Where it starts.
    #[must_use]
    pub fn entry_point(&self) -> &str {
        &self.entry_point
    }

    /// The backend capabilities it declares.
    #[must_use]
    pub fn capabilities(&self) -> &[CapabilityId] {
        &self.capabilities
    }
}

/// What a UI extension renders and where its own state lives.
///
/// There is no capability field on this type, which is what makes a UI
/// extension declaring backend authority unrepresentable rather than rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SurfaceContribution {
    surface: UiSurface,
    entry_point: String,
    namespace: String,
}

impl SurfaceContribution {
    /// Declare a UI contribution.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid component.
    pub fn new(surface: UiSurface, entry_point: &str, namespace: &str) -> Result<Self, ToolError> {
        bounded(entry_point, "entry_point")?;
        bounded(namespace, "ui_namespace")?;
        Ok(Self {
            surface,
            entry_point: entry_point.to_owned(),
            namespace: namespace.to_owned(),
        })
    }

    /// Which surface it renders.
    #[must_use]
    pub const fn surface(&self) -> UiSurface {
        self.surface
    }

    /// Where it starts.
    #[must_use]
    pub fn entry_point(&self) -> &str {
        &self.entry_point
    }

    /// The namespace its own server API and storage live under.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}

/// What an extension contributes.
///
/// A manifest declares one of these. Backend authority lives on the backend
/// shape, and the UI shape has no field to hold it, so a UI extension with a
/// backend capability does not compile:
///
/// ```compile_fail
/// use automonique_protocol::tools::{
///     CapabilityId, ExtensionContribution, SurfaceContribution, UiSurface,
/// };
/// # fn capability() -> CapabilityId { unreachable!() }
/// let contribution = ExtensionContribution::UserInterface(
///     SurfaceContribution::new(UiSurface::Dashboard, "index.js", "acme.panel").unwrap(),
///     vec![capability()],
/// );
/// ```
///
/// while the same capability on the backend shape does:
///
/// ```no_run
/// use automonique_protocol::tools::{
///     BackendContribution, BackendExtensionKind, CapabilityId, ExtensionContribution,
/// };
/// # fn capability() -> CapabilityId { unreachable!() }
/// let contribution = ExtensionContribution::Backend(
///     BackendContribution::new(BackendExtensionKind::Tool, "main.js", vec![capability()])
///         .unwrap(),
/// );
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtensionContribution {
    /// Runs out of process and may hold backend capabilities.
    Backend(BackendContribution),
    /// Renders a surface and holds none.
    UserInterface(SurfaceContribution),
}

impl ExtensionContribution {
    /// Stable lowercase spelling of the extension type.
    #[must_use]
    pub const fn kind_str(&self) -> &'static str {
        match self {
            Self::Backend(backend) => backend.kind.as_str(),
            Self::UserInterface(_) => "user_interface",
        }
    }

    /// The entry point either shape declares.
    #[must_use]
    pub fn entry_point(&self) -> &str {
        match self {
            Self::Backend(backend) => backend.entry_point(),
            Self::UserInterface(surface) => surface.entry_point(),
        }
    }

    /// The backend capabilities declared.
    ///
    /// A UI contribution has none, and not because a check removed them: the
    /// shape has nowhere to put one.
    #[must_use]
    pub fn backend_capabilities(&self) -> &[CapabilityId] {
        match self {
            Self::Backend(backend) => backend.capabilities(),
            Self::UserInterface(_) => &[],
        }
    }
}

/// An inclusive range of supported versions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SupportedRange {
    minimum: u32,
    maximum: u32,
}

impl SupportedRange {
    /// Declare a range.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] when the maximum precedes the minimum.
    pub const fn new(minimum: u32, maximum: u32) -> Result<Self, ToolError> {
        if maximum < minimum {
            return Err(ToolError::Field {
                field: "supported_range",
                error: ValueError::Empty,
            });
        }
        Ok(Self { minimum, maximum })
    }

    /// The lowest supported version.
    #[must_use]
    pub const fn minimum(self) -> u32 {
        self.minimum
    }

    /// The highest supported version.
    #[must_use]
    pub const fn maximum(self) -> u32 {
        self.maximum
    }

    /// Whether a version is supported.
    #[must_use]
    pub const fn contains(self, version: u32) -> bool {
        self.minimum <= version && version <= self.maximum
    }
}

/// Which stream an installation follows.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UpdateChannel {
    /// Only reviewed stable releases.
    Stable,
    /// Pre-release builds.
    Beta,
    /// This exact content address and nothing else.
    Pinned,
}

impl UpdateChannel {
    /// Every channel, for coverage checks.
    pub const ALL: [Self; 3] = [Self::Stable, Self::Beta, Self::Pinned];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
            Self::Pinned => "pinned",
        }
    }
}

/// What an update does to state the previous version wrote.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MigrationBehavior {
    /// The extension keeps no state to migrate.
    NoState,
    /// State migrates forward automatically and cannot be reversed.
    AutomaticForward,
    /// State migrates only after a human decision.
    RequiresManualReview,
}

impl MigrationBehavior {
    /// Every behavior, for coverage checks.
    pub const ALL: [Self; 3] = [
        Self::NoState,
        Self::AutomaticForward,
        Self::RequiresManualReview,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoState => "no_state",
            Self::AutomaticForward => "automatic_forward",
            Self::RequiresManualReview => "requires_manual_review",
        }
    }
}

/// A publisher signature over a content address.
///
/// This module verifies nothing. The type records which key signed which
/// content address so that a manifest without either is not representable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionSignature {
    publisher_key: String,
    signature: String,
}

impl ExtensionSignature {
    /// Record a signature.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid component.
    pub fn new(publisher_key: &str, signature: &str) -> Result<Self, ToolError> {
        bounded(publisher_key, "publisher_key")?;
        bounded(signature, "signature")?;
        Ok(Self {
            publisher_key: publisher_key.to_owned(),
            signature: signature.to_owned(),
        })
    }

    /// The key that signed.
    #[must_use]
    pub fn publisher_key(&self) -> &str {
        &self.publisher_key
    }

    /// The signature itself.
    #[must_use]
    pub fn signature(&self) -> &str {
        &self.signature
    }
}

/// Every field an [`ExtensionManifest`] needs, named at the call site.
#[derive(Clone, Debug)]
pub struct ExtensionManifestParts<'a> {
    /// The package name.
    pub name: &'a str,
    /// The type, entry point and contributions.
    pub contribution: ExtensionContribution,
    /// Protocol versions the package supports.
    pub protocol_range: SupportedRange,
    /// Schema versions the package supports.
    pub schema_range: SupportedRange,
    /// The sandbox the package requires.
    pub required_sandbox: SandboxProfile,
    /// Files it needs.
    pub file_grants: &'a [&'a str],
    /// Network it needs.
    pub network: ToolWorkloadEgress,
    /// Credential audiences it needs.
    pub credential_audiences: CredentialAudiences,
    /// Resources it needs.
    pub resources: ResourceBudget,
    /// The licence it ships under.
    pub licence: &'a str,
    /// Who published it.
    pub publisher: &'a str,
    /// The build provenance digest.
    pub provenance: ProvenanceDigest,
    /// The address the package content hashes to.
    pub content_address: &'a str,
    /// The signature over that address.
    pub signature: ExtensionSignature,
    /// Which stream an installation follows.
    pub update_channel: UpdateChannel,
    /// The schema its configuration satisfies.
    pub configuration_schema: SchemaContract,
    /// What an update does to state.
    pub migration: MigrationBehavior,
}

/// A signed, content-addressed extension manifest.
///
/// Every declared field is a constructor argument with no default, and the
/// contribution is a sum type, so the UI-plus-backend combination has no
/// representation at all.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionManifest {
    name: String,
    contribution: ExtensionContribution,
    protocol_range: SupportedRange,
    schema_range: SupportedRange,
    required_sandbox: SandboxProfile,
    file_grants: Vec<String>,
    network: ToolWorkloadEgress,
    credential_audiences: CredentialAudiences,
    resources: ResourceBudget,
    licence: String,
    publisher: String,
    provenance: ProvenanceDigest,
    content_address: String,
    signature: ExtensionSignature,
    update_channel: UpdateChannel,
    configuration_schema: SchemaContract,
    migration: MigrationBehavior,
}

impl ExtensionManifest {
    /// Declare an extension.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid component.
    pub fn declare(parts: ExtensionManifestParts<'_>) -> Result<Self, ToolError> {
        bounded(parts.name, "extension_name")?;
        bounded(parts.licence, "licence")?;
        bounded(parts.publisher, "publisher")?;
        bounded(parts.content_address, "content_address")?;
        let mut file_grants = Vec::with_capacity(parts.file_grants.len());
        for grant in parts.file_grants {
            bounded(grant, "file_grant")?;
            file_grants.push((*grant).to_owned());
        }
        Ok(Self {
            name: parts.name.to_owned(),
            contribution: parts.contribution,
            protocol_range: parts.protocol_range,
            schema_range: parts.schema_range,
            required_sandbox: parts.required_sandbox,
            file_grants,
            network: parts.network,
            credential_audiences: parts.credential_audiences,
            resources: parts.resources,
            licence: parts.licence.to_owned(),
            publisher: parts.publisher.to_owned(),
            provenance: parts.provenance,
            content_address: parts.content_address.to_owned(),
            signature: parts.signature,
            update_channel: parts.update_channel,
            configuration_schema: parts.configuration_schema,
            migration: parts.migration,
        })
    }

    /// The package name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What it contributes.
    #[must_use]
    pub const fn contribution(&self) -> &ExtensionContribution {
        &self.contribution
    }

    /// Backend capabilities it declares, which is nothing for a UI extension.
    #[must_use]
    pub fn backend_capabilities(&self) -> &[CapabilityId] {
        self.contribution.backend_capabilities()
    }

    /// Protocol versions it supports.
    #[must_use]
    pub const fn protocol_range(&self) -> SupportedRange {
        self.protocol_range
    }

    /// Schema versions it supports.
    #[must_use]
    pub const fn schema_range(&self) -> SupportedRange {
        self.schema_range
    }

    /// The sandbox it requires.
    #[must_use]
    pub const fn required_sandbox(&self) -> &SandboxProfile {
        &self.required_sandbox
    }

    /// Files it needs.
    #[must_use]
    pub fn file_grants(&self) -> &[String] {
        &self.file_grants
    }

    /// Network it needs.
    #[must_use]
    pub const fn network(&self) -> ToolWorkloadEgress {
        self.network
    }

    /// Credential audiences it needs.
    #[must_use]
    pub const fn credential_audiences(&self) -> &CredentialAudiences {
        &self.credential_audiences
    }

    /// Resources it needs.
    #[must_use]
    pub const fn resources(&self) -> ResourceBudget {
        self.resources
    }

    /// The licence it ships under.
    #[must_use]
    pub fn licence(&self) -> &str {
        &self.licence
    }

    /// Who published it.
    #[must_use]
    pub fn publisher(&self) -> &str {
        &self.publisher
    }

    /// The build provenance digest.
    #[must_use]
    pub const fn provenance(&self) -> &ProvenanceDigest {
        &self.provenance
    }

    /// The address the content hashes to.
    #[must_use]
    pub fn content_address(&self) -> &str {
        &self.content_address
    }

    /// The signature over that address.
    #[must_use]
    pub const fn signature(&self) -> &ExtensionSignature {
        &self.signature
    }

    /// Which stream an installation follows.
    #[must_use]
    pub const fn update_channel(&self) -> UpdateChannel {
        self.update_channel
    }

    /// The schema its configuration satisfies.
    #[must_use]
    pub const fn configuration_schema(&self) -> &SchemaContract {
        &self.configuration_schema
    }

    /// What an update does to state.
    #[must_use]
    pub const fn migration(&self) -> MigrationBehavior {
        self.migration
    }
}

/// What a hook is permitted to do.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HookClass {
    /// Asynchronous; cannot change behaviour.
    Observer,
    /// May reject a bounded action with a typed reason.
    Filter,
    /// May return schema-validated bounded output.
    Transformer,
    /// May add labelled untrusted context within a budget.
    ContextProvider,
    /// Creates a durable input or action; never executes privilege inline.
    WorkflowTrigger,
}

/// Exactly one power per hook class.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HookPower {
    /// See what happened and change nothing.
    ObserveOnly,
    /// Refuse the action under review with a typed reason.
    RejectWithTypedReason,
    /// Replace the action's output with schema-validated bounded output.
    ReplaceWithValidatedOutput,
    /// Add labelled untrusted context within a budget.
    AddLabelledContext,
    /// Create a durable input or action for later, ordinary handling.
    EnqueueDurableAction,
}

/// What a power or a prohibited action would have to reach to take effect.
///
/// One enumeration for both, so "can this class do that" is an equality
/// between two computed surfaces rather than a hand-written `false`. The
/// mapping from [`HookPower`] is injective, so that equality is exactly
/// "these are the same power" and never an accident of two powers sharing a
/// surface.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Surface {
    /// Nothing at all.
    Nothing,
    /// Whether the action currently under review proceeds.
    ActionUnderReview,
    /// The output the action under review produced.
    ActionOutput,
    /// The context assembled for the next model turn.
    ContextWindow,
    /// A newly created durable input or action.
    NewDurableInput,
    /// The approval ledger.
    ApprovalLedger,
    /// The compiled sandbox specification.
    SandboxSpecification,
    /// Messages already recorded.
    RecordedHistory,
    /// Time without a bound.
    UnboundedTime,
}

impl Surface {
    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nothing => "nothing",
            Self::ActionUnderReview => "action_under_review",
            Self::ActionOutput => "action_output",
            Self::ContextWindow => "context_window",
            Self::NewDurableInput => "new_durable_input",
            Self::ApprovalLedger => "approval_ledger",
            Self::SandboxSpecification => "sandbox_specification",
            Self::RecordedHistory => "recorded_history",
            Self::UnboundedTime => "unbounded_time",
        }
    }
}

impl HookPower {
    /// Every power, for coverage checks.
    pub const ALL: [Self; 5] = [
        Self::ObserveOnly,
        Self::RejectWithTypedReason,
        Self::ReplaceWithValidatedOutput,
        Self::AddLabelledContext,
        Self::EnqueueDurableAction,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObserveOnly => "observe_only",
            Self::RejectWithTypedReason => "reject_with_typed_reason",
            Self::ReplaceWithValidatedOutput => "replace_with_validated_output",
            Self::AddLabelledContext => "add_labelled_context",
            Self::EnqueueDurableAction => "enqueue_durable_action",
        }
    }

    /// What this power reaches.
    ///
    /// One surface per power and no two alike, and no power reaches the
    /// approval ledger, the sandbox specification, recorded history or
    /// unbounded time.
    #[must_use]
    pub const fn surface(self) -> Surface {
        match self {
            Self::ObserveOnly => Surface::Nothing,
            Self::RejectWithTypedReason => Surface::ActionUnderReview,
            Self::ReplaceWithValidatedOutput => Surface::ActionOutput,
            Self::AddLabelledContext => Surface::ContextWindow,
            Self::EnqueueDurableAction => Surface::NewDurableInput,
        }
    }

    /// Whether exercising this power changes the action's outcome.
    #[must_use]
    pub const fn changes_outcome(self) -> bool {
        matches!(
            self,
            Self::RejectWithTypedReason | Self::ReplaceWithValidatedOutput
        )
    }
}

/// Something no hook class may do.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProhibitedHookAction {
    /// Decide an approval.
    Approve,
    /// Widen a sandbox.
    WidenSandbox,
    /// Rewrite a message already recorded.
    RewriteHistory,
    /// Block without a bound.
    BlockIndefinitely,
}

impl ProhibitedHookAction {
    /// Every prohibited action, for coverage checks.
    pub const ALL: [Self; 4] = [
        Self::Approve,
        Self::WidenSandbox,
        Self::RewriteHistory,
        Self::BlockIndefinitely,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::WidenSandbox => "widen_sandbox",
            Self::RewriteHistory => "rewrite_history",
            Self::BlockIndefinitely => "block_indefinitely",
        }
    }

    /// What this action would have to reach.
    ///
    /// One privileged surface per action and no two alike, so no prohibition
    /// rests on another's answer.
    #[must_use]
    pub const fn surface(self) -> Surface {
        match self {
            Self::Approve => Surface::ApprovalLedger,
            Self::WidenSandbox => Surface::SandboxSpecification,
            Self::RewriteHistory => Surface::RecordedHistory,
            Self::BlockIndefinitely => Surface::UnboundedTime,
        }
    }
}

/// Anything a hook might attempt: a power, or something no class may do.
///
/// The two live in one enumeration so [`HookClass::can_perform`] answers both
/// by the same comparison. That matters for what the answer *is*: a class can
/// perform its own power, so `true` is reachable, and a prohibited action is
/// refused because the surfaces differ rather than because a constant says so.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HookAction {
    /// Exercising one of the five hook powers.
    Exercise(HookPower),
    /// One of the four things no hook class may do.
    Prohibited(ProhibitedHookAction),
}

impl HookAction {
    /// Every action, permitted and prohibited, for coverage checks.
    pub const ALL: [Self; 9] = [
        Self::Exercise(HookPower::ObserveOnly),
        Self::Exercise(HookPower::RejectWithTypedReason),
        Self::Exercise(HookPower::ReplaceWithValidatedOutput),
        Self::Exercise(HookPower::AddLabelledContext),
        Self::Exercise(HookPower::EnqueueDurableAction),
        Self::Prohibited(ProhibitedHookAction::Approve),
        Self::Prohibited(ProhibitedHookAction::WidenSandbox),
        Self::Prohibited(ProhibitedHookAction::RewriteHistory),
        Self::Prohibited(ProhibitedHookAction::BlockIndefinitely),
    ];

    /// What the action would have to reach.
    #[must_use]
    pub const fn surface(self) -> Surface {
        match self {
            Self::Exercise(power) => power.surface(),
            Self::Prohibited(action) => action.surface(),
        }
    }

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exercise(power) => power.as_str(),
            Self::Prohibited(action) => action.as_str(),
        }
    }
}

impl HookClass {
    /// Every class, for coverage checks.
    pub const ALL: [Self; 5] = [
        Self::Observer,
        Self::Filter,
        Self::Transformer,
        Self::ContextProvider,
        Self::WorkflowTrigger,
    ];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observer => "observer",
            Self::Filter => "filter",
            Self::Transformer => "transformer",
            Self::ContextProvider => "context_provider",
            Self::WorkflowTrigger => "workflow_trigger",
        }
    }

    /// The one power this class has.
    #[must_use]
    pub const fn power(self) -> HookPower {
        match self {
            Self::Observer => HookPower::ObserveOnly,
            Self::Filter => HookPower::RejectWithTypedReason,
            Self::Transformer => HookPower::ReplaceWithValidatedOutput,
            Self::ContextProvider => HookPower::AddLabelledContext,
            Self::WorkflowTrigger => HookPower::EnqueueDurableAction,
        }
    }

    /// Whether this class may change the action's outcome.
    #[must_use]
    pub const fn may_change_outcome(self) -> bool {
        self.power().changes_outcome()
    }

    /// Whether this class could perform an action.
    ///
    /// Answered by comparing what the class's one power reaches against what
    /// the action would have to reach, so a power that acquired a privileged
    /// surface would turn a prohibited answer to `true` rather than pass
    /// silently. Both surfaces are injective in their source, so the answer is
    /// `true` exactly for the class's own power and `false` for every other
    /// power and every [`ProhibitedHookAction`].
    #[must_use]
    pub fn can_perform(self, action: HookAction) -> bool {
        self.power().surface() == action.surface()
    }

    /// Whether an outcome is one this class may return.
    #[must_use]
    pub fn admits(self, outcome: &HookOutcome) -> bool {
        self.power() == outcome.power()
    }
}

/// What a hook returned when it ran.
///
/// One shape per power. There is no shape carrying an approval decision, a
/// widened sandbox, a rewritten message or an unbounded wait, so a hook cannot
/// return one whatever its class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HookOutcome {
    /// The observer saw the action.
    Observed,
    /// The filter refused the action.
    Rejected {
        /// The typed reason.
        reason: String,
    },
    /// The transformer replaced the output.
    Replaced {
        /// The schema the replacement satisfies.
        schema: SchemaContract,
        /// The bounded replacement.
        output: String,
    },
    /// The context provider added labelled untrusted context.
    ContextAdded {
        /// The label the context is attributed to.
        label: String,
        /// The bounded context text.
        text: String,
    },
    /// The workflow trigger created a durable input or action.
    Enqueued {
        /// The durable input or action identifier.
        action: String,
    },
}

impl HookOutcome {
    /// Refuse the action with a typed reason.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid reason.
    pub fn rejected(reason: &str) -> Result<Self, ToolError> {
        bounded(reason, "rejection_reason")?;
        Ok(Self::Rejected {
            reason: reason.to_owned(),
        })
    }

    /// Replace the output with a bounded value, naming the schema it claims
    /// to satisfy.
    ///
    /// The replacement is screened for length and control characters and the
    /// schema is carried alongside it. Nothing here validates the one against
    /// the other: a [`SchemaContract`] is an identifier and a digest, and this
    /// module has no schema engine. It pins which schema a host must check.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid replacement.
    pub fn replaced(schema: SchemaContract, output: &str) -> Result<Self, ToolError> {
        bounded(output, "hook_output")?;
        Ok(Self::Replaced {
            schema,
            output: output.to_owned(),
        })
    }

    /// Add labelled untrusted context.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid label or text.
    pub fn context_added(label: &str, text: &str) -> Result<Self, ToolError> {
        bounded(label, "context_label")?;
        bounded(text, "context_text")?;
        Ok(Self::ContextAdded {
            label: label.to_owned(),
            text: text.to_owned(),
        })
    }

    /// Create a durable input or action.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid identifier.
    pub fn enqueued(action: &str) -> Result<Self, ToolError> {
        bounded(action, "durable_action")?;
        Ok(Self::Enqueued {
            action: action.to_owned(),
        })
    }

    /// The power this outcome exercises.
    #[must_use]
    pub const fn power(&self) -> HookPower {
        match self {
            Self::Observed => HookPower::ObserveOnly,
            Self::Rejected { .. } => HookPower::RejectWithTypedReason,
            Self::Replaced { .. } => HookPower::ReplaceWithValidatedOutput,
            Self::ContextAdded { .. } => HookPower::AddLabelledContext,
            Self::Enqueued { .. } => HookPower::EnqueueDurableAction,
        }
    }
}

/// How long a hook may run.
///
/// Non-zero, bounded and not optional, so a hook that blocks indefinitely is
/// not representable.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HookTimeout(NonZeroU32);

impl HookTimeout {
    /// The declared ceiling in milliseconds.
    pub const MAX_MILLIS: u32 = 30_000;

    /// Set a hook timeout.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::BudgetIsZero`] for zero and
    /// [`ToolError::BudgetOutOfRange`] above [`Self::MAX_MILLIS`].
    pub const fn millis(quantity: u32) -> Result<Self, ToolError> {
        if quantity > Self::MAX_MILLIS {
            return Err(ToolError::BudgetOutOfRange {
                budget: "hook_timeout",
                max: Self::MAX_MILLIS as u64,
                requested: quantity as u64,
            });
        }
        match NonZeroU32::new(quantity) {
            Some(value) => Ok(Self(value)),
            None => Err(ToolError::BudgetIsZero {
                budget: "hook_timeout",
            }),
        }
    }

    /// The timeout in milliseconds.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// What happens when a hook fails or times out.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HookFailurePolicy {
    /// The action the hook was attached to does not proceed.
    FailClosed,
    /// The failure is recorded and the action proceeds unchanged.
    RecordAndProceed,
}

impl HookFailurePolicy {
    /// Every policy, for coverage checks.
    pub const ALL: [Self; 2] = [Self::FailClosed, Self::RecordAndProceed];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FailClosed => "fail_closed",
            Self::RecordAndProceed => "record_and_proceed",
        }
    }
}

/// One hook attached at one position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HookBinding {
    id: String,
    class: HookClass,
    order: u32,
    timeout: HookTimeout,
    failure: HookFailurePolicy,
}

impl HookBinding {
    /// Bind a hook.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid identifier.
    pub fn new(
        id: &str,
        class: HookClass,
        order: u32,
        timeout: HookTimeout,
        failure: HookFailurePolicy,
    ) -> Result<Self, ToolError> {
        bounded(id, "hook_id")?;
        Ok(Self {
            id: id.to_owned(),
            class,
            order,
            timeout,
            failure,
        })
    }

    /// The hook identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Its class.
    #[must_use]
    pub const fn class(&self) -> HookClass {
        self.class
    }

    /// Its position in the chain.
    #[must_use]
    pub const fn order(&self) -> u32 {
        self.order
    }

    /// How long it may run.
    #[must_use]
    pub const fn timeout(&self) -> HookTimeout {
        self.timeout
    }

    /// What happens when it fails.
    #[must_use]
    pub const fn failure_policy(&self) -> HookFailurePolicy {
        self.failure
    }
}

/// The hooks attached at one point, in a deterministic order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HookChain {
    bindings: Vec<HookBinding>,
}

impl HookChain {
    /// Order a set of bindings.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::HookOrderNotUnique`] when two bindings claim the
    /// same position, because that would leave the order to chance.
    pub fn declare(bindings: Vec<HookBinding>) -> Result<Self, ToolError> {
        let mut ordered = bindings;
        ordered.sort_by(|left, right| left.order.cmp(&right.order));
        if let Some(pair) = ordered
            .windows(2)
            .find(|pair| pair[0].order == pair[1].order)
        {
            return Err(ToolError::HookOrderNotUnique {
                order: pair[0].order,
            });
        }
        Ok(Self { bindings: ordered })
    }

    /// The bindings, in the order they run.
    #[must_use]
    pub fn bindings(&self) -> &[HookBinding] {
        &self.bindings
    }
}

/// Where a secret comes from.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum VaultProvider {
    /// 1Password.
    OnePassword,
    /// Bitwarden.
    Bitwarden,
}

impl VaultProvider {
    /// Every provider, for coverage checks.
    pub const ALL: [Self; 2] = [Self::OnePassword, Self::Bitwarden];

    /// Stable lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OnePassword => "one_password",
            Self::Bitwarden => "bitwarden",
        }
    }
}

/// A pinned absolute path to a helper executable.
///
/// Absolute and free of whitespace and shell metacharacters, so a command line
/// cannot be smuggled through the executable position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedExecutable(String);

impl PinnedExecutable {
    /// Pin an executable.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::SecretSourceNeedsClosedArguments`] for a relative
    /// path or one carrying whitespace or a shell metacharacter, and
    /// [`ToolError::Field`] for an invalid string.
    pub fn new(path: &str) -> Result<Self, ToolError> {
        bounded(path, "executable")?;
        if !path.starts_with('/') {
            return Err(ToolError::SecretSourceNeedsClosedArguments);
        }
        inert_token(path)?;
        Ok(Self(path.to_owned()))
    }

    /// The pinned path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One position in a command helper's closed argument schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArgumentSlot {
    /// A token fixed by the schema itself.
    Fixed(String),
    /// A named position a caller binds one token to.
    Named(String),
}

impl ArgumentSlot {
    /// Fix a token.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::SecretSourceNeedsClosedArguments`] when the token
    /// carries whitespace or a shell metacharacter.
    pub fn fixed(token: &str) -> Result<Self, ToolError> {
        bounded(token, "argument")?;
        inert_token(token)?;
        Ok(Self::Fixed(token.to_owned()))
    }

    /// Declare a bindable position.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::SecretSourceNeedsClosedArguments`] when the name
    /// carries whitespace or a shell metacharacter.
    pub fn named(name: &str) -> Result<Self, ToolError> {
        bounded(name, "argument_name")?;
        inert_token(name)?;
        Ok(Self::Named(name.to_owned()))
    }
}

/// The closed argument schema of a command helper.
///
/// A schema is a fixed sequence of positions. There is no position accepting
/// free text, so a caller cannot append an argument the schema does not
/// declare.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ArgumentSchema {
    slots: Vec<ArgumentSlot>,
}

impl ArgumentSchema {
    /// Declare a schema.
    #[must_use]
    pub const fn new(slots: Vec<ArgumentSlot>) -> Self {
        Self { slots }
    }

    /// The declared positions.
    #[must_use]
    pub fn slots(&self) -> &[ArgumentSlot] {
        &self.slots
    }

    /// How many positions a caller must bind.
    #[must_use]
    pub fn named_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| matches!(slot, ArgumentSlot::Named(_)))
            .count()
    }
}

/// The environment a secret helper runs with.
///
/// A unit type with one inhabitant and no constructor taking a variable, so a
/// non-empty helper environment is not representable.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct EmptyEnvironment;

impl EmptyEnvironment {
    /// The variables the helper receives, which is none of them.
    #[must_use]
    pub const fn variables(self) -> &'static [(&'static str, &'static str)] {
        &[]
    }
}

/// A pinned command helper with a closed argument schema.
///
/// Every token, fixed or bound, is a single shell-inert word, and the schema
/// has no free-text position, so an arbitrary shell *string* — anything
/// carrying whitespace, a backslash or one of the twenty metacharacters — is
/// not representable in the executable position or in the argument vector, and
/// no argument the schema did not declare can be appended.
///
/// What this type does not do is judge what a pinned executable makes of its
/// arguments. `/bin/sh` with a fixed `-c` and a single bound word passes every
/// screen here, because one inert word is indistinguishable in shape from a
/// vault item name; the shape of a token is all this module can see. Which
/// executables a deployment allows a source to pin is a policy decision, made
/// where the source is admitted, not here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretCommand {
    executable: PinnedExecutable,
    schema: ArgumentSchema,
    bindings: Vec<String>,
    environment: EmptyEnvironment,
}

impl SecretCommand {
    /// Bind a schema's named positions and pin the command.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::SecretSourceArgumentCount`] when the number of
    /// values does not match the schema, and
    /// [`ToolError::SecretSourceNeedsClosedArguments`] when a value is not a
    /// single shell-inert token.
    pub fn bind(
        executable: PinnedExecutable,
        schema: ArgumentSchema,
        values: &[&str],
    ) -> Result<Self, ToolError> {
        let declared = schema.named_count();
        if declared != values.len() {
            return Err(ToolError::SecretSourceArgumentCount {
                declared,
                supplied: values.len(),
            });
        }
        let mut bindings = Vec::with_capacity(values.len());
        for value in values {
            bounded(value, "argument")?;
            inert_token(value)?;
            bindings.push((*value).to_owned());
        }
        Ok(Self {
            executable,
            schema,
            bindings,
            environment: EmptyEnvironment,
        })
    }

    /// The pinned executable.
    #[must_use]
    pub const fn executable(&self) -> &PinnedExecutable {
        &self.executable
    }

    /// The closed schema.
    #[must_use]
    pub const fn schema(&self) -> &ArgumentSchema {
        &self.schema
    }

    /// The environment, which is empty.
    #[must_use]
    pub const fn environment(&self) -> EmptyEnvironment {
        self.environment
    }

    /// The argument vector, fixed tokens and bound values in schema order.
    #[must_use]
    pub fn argv(&self) -> Vec<String> {
        let mut bound = self.bindings.iter();
        self.schema
            .slots
            .iter()
            .filter_map(|slot| match slot {
                ArgumentSlot::Fixed(token) => Some(token.clone()),
                ArgumentSlot::Named(_) => bound.next().cloned(),
            })
            .collect()
    }
}

/// How a secret is retrieved.
///
/// The command shape is the only one that names an executable, and it names a
/// [`SecretCommand`], so there is no shape carrying a shell string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecretRetrieval {
    /// A systemd credential passed to the unit.
    SystemdCredential {
        /// The credential name.
        name: String,
    },
    /// An entry in the encrypted local store.
    EncryptedLocalStore {
        /// The entry name.
        entry: String,
    },
    /// An item in a vault.
    Vault {
        /// Which vault.
        provider: VaultProvider,
        /// The item name.
        item: String,
    },
    /// A pinned command helper.
    CommandHelper(SecretCommand),
}

/// A secret a source can produce, with no material attached.
///
/// The type has no field, constructor or accessor carrying secret text, so a
/// plaintext secret is not representable here at all:
///
/// ```compile_fail
/// use automonique_protocol::tools::SealedSecret;
/// # fn sealed() -> SealedSecret { unreachable!() }
/// let value = sealed().expose_secret();
/// ```
///
/// ```no_run
/// use automonique_protocol::tools::SealedSecret;
/// # fn sealed() -> SealedSecret { unreachable!() }
/// let value = sealed().audience();
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedSecret {
    source: String,
    audience: String,
}

impl SealedSecret {
    /// Which source would produce it.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Which audience it is for.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }
}

/// Where a secret comes from and who it is for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretSource {
    id: String,
    audience: String,
    retrieval: SecretRetrieval,
}

impl SecretSource {
    /// Declare a source.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid component.
    pub fn new(id: &str, audience: &str, retrieval: SecretRetrieval) -> Result<Self, ToolError> {
        bounded(id, "secret_source_id")?;
        bounded(audience, "credential_audience")?;
        match &retrieval {
            SecretRetrieval::SystemdCredential { name } => bounded(name, "credential_name")?,
            SecretRetrieval::EncryptedLocalStore { entry } => bounded(entry, "store_entry")?,
            SecretRetrieval::Vault { item, .. } => bounded(item, "vault_item")?,
            SecretRetrieval::CommandHelper(_) => {}
        }
        Ok(Self {
            id: id.to_owned(),
            audience: audience.to_owned(),
            retrieval,
        })
    }

    /// The source identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Who the secret is for.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// How it is retrieved.
    #[must_use]
    pub const fn retrieval(&self) -> &SecretRetrieval {
        &self.retrieval
    }

    /// What this source yields.
    ///
    /// A descriptor, never material: this module resolves nothing, and the
    /// return type has nowhere to put a value if it did.
    #[must_use]
    pub fn sealed(&self) -> SealedSecret {
        SealedSecret {
            source: self.id.clone(),
            audience: self.audience.clone(),
        }
    }
}

/// Characters that give a token meaning to a shell.
const SHELL_METACHARACTERS: [char; 20] = [
    ';', '|', '&', '$', '>', '<', '`', '(', ')', '{', '}', '[', ']', '*', '?', '!', '~', '#', '\'',
    '"',
];

/// Accept a single word that a shell would not reinterpret.
fn inert_token(value: &str) -> Result<(), ToolError> {
    if value.chars().any(|character| {
        character.is_whitespace() || character == '\\' || SHELL_METACHARACTERS.contains(&character)
    }) {
        return Err(ToolError::SecretSourceNeedsClosedArguments);
    }
    Ok(())
}

fn bounded(value: &str, field: &'static str) -> Result<(), ToolError> {
    let error = if value.is_empty() {
        Some(ValueError::Empty)
    } else if value.len() > MAX_TOOL_FIELD_BYTES {
        Some(ValueError::TooLong {
            max_bytes: MAX_TOOL_FIELD_BYTES,
            actual_bytes: value.len(),
        })
    } else if value.chars().any(char::is_control) {
        Some(ValueError::ControlCharacter)
    } else {
        None
    };
    match error {
        Some(error) => Err(ToolError::Field { field, error }),
        None => Ok(()),
    }
}
