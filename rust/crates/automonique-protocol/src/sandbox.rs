// SPDX-License-Identifier: Elastic-2.0

//! Sandbox profiles, specs, attestation and violation dispositions.
//!
//! Two policies govern different traffic and must never substitute for one
//! another: a provider-control channel and a model-directed tool workload.
//! Collapsing them is what lets tool traffic inherit control-plane reach, so
//! they are distinct types:
//!
//! ```compile_fail
//! use automonique_protocol::sandbox::{ProviderControlEgress, ToolWorkloadEgress};
//! let control = ProviderControlEgress::denied();
//! // Tool traffic cannot be governed by the control-plane policy.
//! let workload: ToolWorkloadEgress = control;
//! ```
//!
//! An approval may not widen a spec. There is no accessor returning one, so
//! added authority produces a new reviewed plan rather than a mutation:
//!
//! ```compile_fail
//! use automonique_protocol::sandbox::ApprovalRequest;
//! let request = ApprovalRequest::new("command", "run tests").unwrap();
//! let widened = request.widened_spec();
//! ```
//!
//! This module defines the boundary. It does not enforce one: no namespace is
//! created, no seccomp filter loaded, no Landlock ruleset applied and no cgroup
//! allocated. Evidence must say that rather than implying a kernel property was
//! tested.

use core::fmt;
use std::error::Error;

use crate::primitives::ValueError;

/// Maximum UTF-8 byte length of a sandbox field.
pub const MAX_SANDBOX_FIELD_BYTES: usize = 256;

/// Why a sandbox operation was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SandboxError {
    /// A required enforcement feature is unavailable.
    ///
    /// Names the feature. There is no weaker profile to fall back to.
    RequiredEnforcementMissing {
        /// The absent feature.
        feature: String,
    },
    /// A budget was declared without a unit or above its ceiling.
    BudgetOutOfRange {
        /// The budget's unit.
        unit: &'static str,
        /// Maximum accepted quantity.
        max: u64,
        /// Quantity requested.
        requested: u64,
    },
    /// A bounded field was rejected.
    Field {
        /// The rejected field.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
}

impl SandboxError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::RequiredEnforcementMissing { .. } => "required_enforcement_missing",
            Self::BudgetOutOfRange { .. } => "budget_out_of_range",
            Self::Field { .. } => "field_invalid",
        }
    }
}

impl fmt::Display for SandboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequiredEnforcementMissing { feature } => write!(
                formatter,
                "required enforcement feature {feature} is unavailable; there is no weaker profile"
            ),
            Self::BudgetOutOfRange {
                unit,
                max,
                requested,
            } => write!(
                formatter,
                "budget of {requested} {unit} exceeds the maximum of {max}"
            ),
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
        }
    }
}

impl Error for SandboxError {}

/// How much of the filesystem a profile grants, ordered least to most.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FilesystemAccess {
    /// Nothing.
    None,
    /// A registered immutable snapshot, read-only.
    ReadOnlySnapshot,
    /// One isolated writable workspace.
    IsolatedWritable,
    /// A writable workspace plus declared artifact grants.
    WritableWithGrants,
}

/// How much network a profile grants a tool workload, ordered least to most.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum NetworkAccess {
    /// No network at all.
    Denied,
    /// Named destinations through the egress broker.
    BrokeredNamed,
    /// Any destination the broker permits.
    BrokeredAny,
}

/// Egress policy for the trusted provider-control channel.
///
/// Distinct from [`ToolWorkloadEgress`] by type, not by convention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderControlEgress(NetworkAccess);

impl ProviderControlEgress {
    /// Deny all control-plane egress.
    #[must_use]
    pub const fn denied() -> Self {
        Self(NetworkAccess::Denied)
    }

    /// Permit brokered control-plane egress.
    #[must_use]
    pub const fn brokered(access: NetworkAccess) -> Self {
        Self(access)
    }

    /// The granted access.
    #[must_use]
    pub const fn access(self) -> NetworkAccess {
        self.0
    }
}

/// Egress policy for model-directed tool traffic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ToolWorkloadEgress(NetworkAccess);

impl ToolWorkloadEgress {
    /// Deny all tool egress.
    #[must_use]
    pub const fn denied() -> Self {
        Self(NetworkAccess::Denied)
    }

    /// Permit brokered tool egress.
    #[must_use]
    pub const fn brokered(access: NetworkAccess) -> Self {
        Self(access)
    }

    /// The granted access.
    #[must_use]
    pub const fn access(self) -> NetworkAccess {
        self.0
    }
}

/// How two profiles relate.
///
/// A partial order, not a boolean: two profiles can each grant something the
/// other does not, and calling that "not narrower" would license a reuse that
/// widens one axis while narrowing another.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProfileOrdering {
    /// Grants strictly less on every axis it differs on.
    Narrower,
    /// Grants exactly the same.
    Identical,
    /// Grants strictly more on every axis it differs on.
    Wider,
    /// Grants more on one axis and less on another.
    Incomparable,
}

/// A versioned sandbox profile.
///
/// Profiles are minimum contracts: a deployment may narrow one, but adding a
/// capability needs a new plan revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxProfile {
    id: String,
    version: u32,
    filesystem: FilesystemAccess,
    tool_network: ToolWorkloadEgress,
}

impl SandboxProfile {
    /// Declare a profile.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::Field`] for an invalid identifier.
    pub fn new(
        id: &str,
        version: u32,
        filesystem: FilesystemAccess,
        tool_network: ToolWorkloadEgress,
    ) -> Result<Self, SandboxError> {
        bounded(id, "profile_id")?;
        Ok(Self {
            id: id.to_owned(),
            version,
            filesystem,
            tool_network,
        })
    }

    /// Profile identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Profile version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Compare against another profile.
    #[must_use]
    pub fn compare(&self, other: &Self) -> ProfileOrdering {
        let filesystem = self.filesystem.cmp(&other.filesystem);
        let network = self.tool_network.access().cmp(&other.tool_network.access());
        match (filesystem, network) {
            (core::cmp::Ordering::Equal, core::cmp::Ordering::Equal) => ProfileOrdering::Identical,
            (core::cmp::Ordering::Greater, core::cmp::Ordering::Less)
            | (core::cmp::Ordering::Less, core::cmp::Ordering::Greater) => {
                ProfileOrdering::Incomparable
            }
            (core::cmp::Ordering::Less | core::cmp::Ordering::Equal, _) => {
                ProfileOrdering::Narrower
            }
            (core::cmp::Ordering::Greater, _) => ProfileOrdering::Wider,
        }
    }
}

/// A budget's unit.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BudgetUnit {
    /// Wall-clock milliseconds.
    Milliseconds,
    /// Bytes of memory.
    MemoryBytes,
    /// Process identifiers.
    Processes,
    /// Bytes of temporary storage.
    TempBytes,
}

impl BudgetUnit {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Milliseconds => "milliseconds",
            Self::MemoryBytes => "memory_bytes",
            Self::Processes => "processes",
            Self::TempBytes => "temp_bytes",
        }
    }

    /// The declared ceiling for this unit.
    #[must_use]
    pub const fn ceiling(self) -> u64 {
        match self {
            Self::Milliseconds => 24 * 60 * 60 * 1_000,
            Self::MemoryBytes => 64 * 1024 * 1024 * 1024,
            Self::Processes => 4_096,
            Self::TempBytes => 512 * 1024 * 1024 * 1024,
        }
    }
}

/// A bounded resource reservation.
///
/// Carries its unit, so a unitless budget is unrepresentable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Budget {
    unit: BudgetUnit,
    quantity: u64,
}

impl Budget {
    /// Reserve a quantity in a unit.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::BudgetOutOfRange`] above the unit's ceiling.
    pub const fn new(unit: BudgetUnit, quantity: u64) -> Result<Self, SandboxError> {
        if quantity > unit.ceiling() {
            return Err(SandboxError::BudgetOutOfRange {
                unit: unit.as_str(),
                max: unit.ceiling(),
                requested: quantity,
            });
        }
        Ok(Self { unit, quantity })
    }

    /// The unit.
    #[must_use]
    pub const fn unit(self) -> BudgetUnit {
        self.unit
    }

    /// The reserved quantity.
    #[must_use]
    pub const fn quantity(self) -> u64 {
        self.quantity
    }
}

/// What went wrong inside a sandbox.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ViolationClass {
    /// The workload attempted something the policy forbids.
    PolicyViolation,
    /// A budget ran out.
    BudgetExhaustion,
    /// A kernel enforcement mechanism stopped working.
    EnforcementLoss,
    /// The recorded attestation no longer matches.
    AttestationMismatch,
}

impl ViolationClass {
    /// Every class, for coverage checks.
    pub const ALL: [Self; 4] = [
        Self::PolicyViolation,
        Self::BudgetExhaustion,
        Self::EnforcementLoss,
        Self::AttestationMismatch,
    ];

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyViolation => "policy_violation",
            Self::BudgetExhaustion => "budget_exhaustion",
            Self::EnforcementLoss => "enforcement_loss",
            Self::AttestationMismatch => "attestation_mismatch",
        }
    }

    /// What happens when this class occurs.
    ///
    /// Every class has one. None of them is "continue", because a boundary that
    /// keeps running after it was violated is not a boundary.
    #[must_use]
    pub const fn disposition(self) -> Disposition {
        match self {
            Self::PolicyViolation => Disposition::TerminateRun,
            Self::BudgetExhaustion => Disposition::TerminateRunAndRecord,
            Self::EnforcementLoss | Self::AttestationMismatch => Disposition::Quarantine,
        }
    }
}

/// What is done about a violation.
///
/// There is deliberately no `Continue` variant.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Disposition {
    /// Stop the run.
    TerminateRun,
    /// Stop the run and record the exhausted budget.
    TerminateRunAndRecord,
    /// Freeze the host; only observation, reconciliation or cancellation.
    Quarantine,
}

impl Disposition {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TerminateRun => "terminate_run",
            Self::TerminateRunAndRecord => "terminate_run_and_record",
            Self::Quarantine => "quarantine",
        }
    }
}

/// Every field a [`SandboxSpec`] needs, named at the call site.
///
/// A struct rather than a positional argument list: four of these are strings,
/// and a caller that transposes tenant and workspace context would compile
/// cleanly while compiling the wrong boundary. Naming them removes the hazard
/// without making any field optional.
#[derive(Clone, Debug)]
pub struct SandboxSpecParts<'a> {
    /// The profile this spec compiles from.
    pub profile: SandboxProfile,
    /// The complete policy digest.
    pub policy_digest: &'a str,
    /// The owning tenant.
    pub tenant: &'a str,
    /// The workspace security context.
    pub workspace_context: &'a str,
    /// Egress for the trusted provider-control channel.
    pub provider_control_egress: ProviderControlEgress,
    /// Egress for model-directed tool traffic.
    pub tool_workload_egress: ToolWorkloadEgress,
    /// Enforcement features the host must provide.
    pub required_features: &'a [&'a str],
    /// Declared resource reservations.
    pub budgets: Vec<Budget>,
    /// Capabilities that must not be present.
    pub prohibited_capabilities: &'a [&'a str],
}

/// An immutable compiled sandbox specification.
///
/// Every field is a constructor argument, so a spec cannot be built without
/// one, and there is no setter, so it cannot be changed after compilation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxSpec {
    profile: SandboxProfile,
    policy_digest: String,
    tenant: String,
    workspace_context: String,
    provider_control_egress: ProviderControlEgress,
    tool_workload_egress: ToolWorkloadEgress,
    required_features: Vec<String>,
    budgets: Vec<Budget>,
    prohibited_capabilities: Vec<String>,
}

impl SandboxSpec {
    /// Compile a specification.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::Field`] for an invalid component.
    pub fn compile(parts: SandboxSpecParts<'_>) -> Result<Self, SandboxError> {
        bounded(parts.policy_digest, "policy_digest")?;
        bounded(parts.tenant, "tenant")?;
        bounded(parts.workspace_context, "workspace_context")?;
        for feature in parts.required_features {
            bounded(feature, "required_feature")?;
        }
        for capability in parts.prohibited_capabilities {
            bounded(capability, "prohibited_capability")?;
        }
        Ok(Self {
            profile: parts.profile,
            policy_digest: parts.policy_digest.to_owned(),
            tenant: parts.tenant.to_owned(),
            workspace_context: parts.workspace_context.to_owned(),
            provider_control_egress: parts.provider_control_egress,
            tool_workload_egress: parts.tool_workload_egress,
            required_features: parts
                .required_features
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect(),
            budgets: parts.budgets,
            prohibited_capabilities: parts
                .prohibited_capabilities
                .iter()
                .map(|capability| (*capability).to_owned())
                .collect(),
        })
    }

    /// The profile this spec compiled from.
    #[must_use]
    pub const fn profile(&self) -> &SandboxProfile {
        &self.profile
    }

    /// The complete policy digest.
    #[must_use]
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    /// The owning tenant.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// The control-plane egress policy.
    #[must_use]
    pub const fn provider_control_egress(&self) -> ProviderControlEgress {
        self.provider_control_egress
    }

    /// The tool-workload egress policy.
    #[must_use]
    pub const fn tool_workload_egress(&self) -> ToolWorkloadEgress {
        self.tool_workload_egress
    }

    /// The features the host must provide.
    #[must_use]
    pub fn required_features(&self) -> &[String] {
        &self.required_features
    }

    /// The declared budgets.
    #[must_use]
    pub fn budgets(&self) -> &[Budget] {
        &self.budgets
    }

    /// Capabilities that must not be present.
    #[must_use]
    pub fn prohibited_capabilities(&self) -> &[String] {
        &self.prohibited_capabilities
    }

    /// Negotiate this spec against the features a host offers.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::RequiredEnforcementMissing`] naming the first
    /// absent feature. There is no return value representing a weaker profile,
    /// so there is no silent downgrade to reach.
    pub fn admit_on(&self, host_features: &[&str]) -> Result<(), SandboxError> {
        for feature in &self.required_features {
            if !host_features.contains(&feature.as_str()) {
                return Err(SandboxError::RequiredEnforcementMissing {
                    feature: feature.clone(),
                });
            }
        }
        Ok(())
    }
}

/// Whether an existing host may serve a new request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReuseOutcome {
    /// The request is identical or narrower; the host may be reused.
    Reuse,
    /// The request widens something; a new reviewed plan and host are needed.
    RequiresNewHost,
}

/// Decide whether a host running `existing` may serve `requested`.
///
/// Only identical or narrower requests reuse. Anything else — wider, or
/// incomparable — requires a new host, because an incomparable request widens
/// at least one axis.
#[must_use]
pub fn evaluate_reuse(existing: &SandboxSpec, requested: &SandboxSpec) -> ReuseOutcome {
    if existing.tenant != requested.tenant
        || existing.workspace_context != requested.workspace_context
        || requested.provider_control_egress.access() > existing.provider_control_egress.access()
    {
        return ReuseOutcome::RequiresNewHost;
    }
    match requested.profile.compare(&existing.profile) {
        ProfileOrdering::Narrower | ProfileOrdering::Identical => ReuseOutcome::Reuse,
        ProfileOrdering::Wider | ProfileOrdering::Incomparable => ReuseOutcome::RequiresNewHost,
    }
}

/// What a host recorded about its actual enforcement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnforcementAttestation {
    namespaces: String,
    cgroup: String,
    kernel_boot: String,
    landlock_digest: String,
    seccomp_digest: String,
    egress_digest: String,
}

impl EnforcementAttestation {
    /// Record what a host actually enforced.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::Field`] for an invalid component.
    pub fn new(
        namespaces: &str,
        cgroup: &str,
        kernel_boot: &str,
        landlock_digest: &str,
        seccomp_digest: &str,
        egress_digest: &str,
    ) -> Result<Self, SandboxError> {
        for (value, field) in [
            (namespaces, "namespaces"),
            (cgroup, "cgroup"),
            (kernel_boot, "kernel_boot"),
            (landlock_digest, "landlock_digest"),
            (seccomp_digest, "seccomp_digest"),
            (egress_digest, "egress_digest"),
        ] {
            bounded(value, field)?;
        }
        Ok(Self {
            namespaces: namespaces.to_owned(),
            cgroup: cgroup.to_owned(),
            kernel_boot: kernel_boot.to_owned(),
            landlock_digest: landlock_digest.to_owned(),
            seccomp_digest: seccomp_digest.to_owned(),
            egress_digest: egress_digest.to_owned(),
        })
    }
}

/// What a reload decided about an existing host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptionOutcome {
    /// The attestation matched; the host is adopted.
    Adopted,
    /// The attestation is absent or differs; the host is frozen.
    ///
    /// Only observation, reconciliation or cancellation are permitted.
    Quarantined,
}

/// Adopt a host across a control-plane reload.
///
/// The recorded attestation is *compared*, never reconstructed: a reload does
/// not rebuild a boundary around a live provider, it checks the one already
/// there.
#[must_use]
pub fn adopt_host(
    recorded: Option<&EnforcementAttestation>,
    observed: Option<&EnforcementAttestation>,
) -> AdoptionOutcome {
    match (recorded, observed) {
        (Some(recorded), Some(observed)) if recorded == observed => AdoptionOutcome::Adopted,
        _ => AdoptionOutcome::Quarantined,
    }
}

/// A provider's request for authority it does not have.
///
/// Carries a class and a description. There is no accessor returning a
/// [`SandboxSpec`], so an approval cannot widen one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalRequest {
    class: String,
    description: String,
}

impl ApprovalRequest {
    /// Record a request.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::Field`] for an invalid component.
    pub fn new(class: &str, description: &str) -> Result<Self, SandboxError> {
        bounded(class, "approval_class")?;
        bounded(description, "approval_description")?;
        Ok(Self {
            class: class.to_owned(),
            description: description.to_owned(),
        })
    }

    /// The class of authority sought.
    #[must_use]
    pub fn class(&self) -> &str {
        &self.class
    }

    /// What is being asked for.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }
}

fn bounded(value: &str, field: &'static str) -> Result<(), SandboxError> {
    let error = if value.is_empty() {
        Some(ValueError::Empty)
    } else if value.len() > MAX_SANDBOX_FIELD_BYTES {
        Some(ValueError::TooLong {
            max_bytes: MAX_SANDBOX_FIELD_BYTES,
            actual_bytes: value.len(),
        })
    } else if value.chars().any(char::is_control) {
        Some(ValueError::ControlCharacter)
    } else {
        None
    };
    match error {
        Some(error) => Err(SandboxError::Field { field, error }),
        None => Ok(()),
    }
}
