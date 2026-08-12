// SPDX-License-Identifier: Elastic-2.0

//! Provider capabilities, identities and integration-mode selection.
//!
//! Capabilities are observed at runtime and recorded with the binding they were
//! observed for. They are never inferred forever from a provider's name, so a
//! capability record that does not carry the binary it was observed against
//! cannot be constructed.
//!
//! Nothing here launches a provider, probes a binary or opens a socket. This is
//! the vocabulary a later adapter records into and selects from.
//!
//! The five provider identities are distinct types. Passing a turn where a
//! session is required is a compile error, not a runtime check:
//!
//! ```compile_fail
//! use automonique_protocol::provider::{ProviderSessionId, ProviderTurnId};
//! let turn = ProviderTurnId::new("t-1").unwrap();
//! // A turn identifier is not a session identifier.
//! let session: ProviderSessionId = turn;
//! ```
//!
//! ```compile_fail
//! use automonique_protocol::provider::{ProviderInstanceId, ProviderRequestId};
//! let instance = ProviderInstanceId::new("i-1").unwrap();
//! // Nor is an instance identifier a request correlation identifier.
//! let request: ProviderRequestId = instance;
//! ```
//!
//! ```compile_fail
//! use automonique_protocol::provider::{ModeDeclaration, Selection};
//! // A selection cannot be fabricated; only `ModeDeclaration::select` returns one.
//! let selection = Selection { mode: String::new(), degraded: Vec::new() };
//! ```

use core::fmt;
use core::marker::PhantomData;
use std::error::Error;

use crate::primitives::{OpaqueId, ValueError};
use crate::sandbox::{Digest, DigestAlgorithm, DigestError};

/// Maximum UTF-8 byte length of a provider coordinate.
pub const MAX_PROVIDER_ID_BYTES: usize = 128;

/// Maximum number of capabilities in one declaration.
pub const MAX_CAPABILITIES: usize = 128;

macro_rules! provider_domain {
    ($domain:ident, $alias:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $domain;

        impl crate::primitives::IdDomain for $domain {}

        #[doc = $doc]
        pub type $alias = OpaqueId<$domain, MAX_PROVIDER_ID_BYTES>;
    };
}

provider_domain!(
    ProviderInstanceDomain,
    ProviderInstanceId,
    "Daemon or server process identity."
);
provider_domain!(
    ProviderSessionDomain,
    ProviderSessionId,
    "Durable conversation identity."
);
provider_domain!(
    ProviderTurnDomain,
    ProviderTurnId,
    "One active user turn or request."
);
provider_domain!(
    ProviderItemDomain,
    ProviderItemId,
    "A tool, message or approval item."
);
provider_domain!(
    ProviderRequestDomain,
    ProviderRequestId,
    "Protocol request correlation."
);

/// A capability group, mirroring the requirement's structure.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CapabilityGroup {
    /// Session creation, resumption, forking and archival.
    Sessions,
    /// Turn start, queueing, steering, interruption and retry.
    Turns,
    /// Replay, authoritative messages and deltas.
    Events,
    /// Command, file, network, MCP and permission approvals.
    Approvals,
    /// Tool, MCP, skill and structured-output support.
    Tools,
    /// Model catalog, auth state, quota and usage reporting.
    Telemetry,
    /// Reconnect, reload and session survival guarantees.
    Lifecycle,
}

impl CapabilityGroup {
    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sessions => "sessions",
            Self::Turns => "turns",
            Self::Events => "events",
            Self::Approvals => "approvals",
            Self::Tools => "tools",
            Self::Telemetry => "telemetry",
            Self::Lifecycle => "lifecycle",
        }
    }
}

/// One named capability within a group.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Capability {
    group: CapabilityGroup,
    name: String,
}

impl Capability {
    /// Name a capability.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when the name is empty, over the ceiling, or
    /// contains a control character.
    pub fn new(group: CapabilityGroup, name: &str) -> Result<Self, ValueError> {
        if name.is_empty() {
            return Err(ValueError::Empty);
        }
        if name.len() > MAX_PROVIDER_ID_BYTES {
            return Err(ValueError::TooLong {
                max_bytes: MAX_PROVIDER_ID_BYTES,
                actual_bytes: name.len(),
            });
        }
        if name.chars().any(char::is_control) {
            return Err(ValueError::ControlCharacter);
        }
        Ok(Self {
            group,
            name: name.to_owned(),
        })
    }

    /// Owning group.
    #[must_use]
    pub const fn group(&self) -> CapabilityGroup {
        self.group
    }

    /// Capability name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// What is known about one capability for a given binding.
///
/// `Unprobed` and `Absent` are distinct: a capability nobody asked about is not
/// the same as one asked about and found missing.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CapabilityState {
    /// Observed and available.
    Present,
    /// Observed and unavailable.
    Absent,
    /// Never probed for this binding.
    Unprobed,
}

/// A capability an adapter reported that this build does not define.
///
/// Retained so a newer adapter's vocabulary survives a round trip, and never
/// counted as present.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UnknownCapability {
    name: String,
}

impl UnknownCapability {
    /// Retain an unrecognized capability name.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when the name violates the bounded value rules.
    pub fn new(name: &str) -> Result<Self, ValueError> {
        Capability::new(CapabilityGroup::Sessions, name)?;
        Ok(Self {
            name: name.to_owned(),
        })
    }

    /// The retained spelling.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Why a capability declaration or selection was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderError {
    /// A capability is both required and known-absent for the selected mode.
    RequiredCapabilityIsDegraded {
        /// The contradictory capability name.
        capability: String,
    },
    /// Selection refused because mandatory capabilities are missing.
    RequiredCapabilitiesMissing {
        /// Every missing mandatory capability, in declaration order.
        missing: Vec<String>,
    },
    /// A binding component differs from the one a session was created under.
    BindingMismatch {
        /// The differing component.
        component: &'static str,
    },
    /// A provider binary or protocol digest was malformed.
    Digest {
        /// Field that was rejected.
        field: &'static str,
        /// Structural digest violation.
        error: DigestError,
    },
    /// A well-formed digest used an algorithm other than SHA-256.
    DigestAlgorithm {
        /// Field that was rejected.
        field: &'static str,
    },
    /// A bounded provider value was rejected.
    Value {
        /// Field that was rejected.
        field: &'static str,
        /// Violation class.
        error: ValueError,
    },
    /// More capabilities were declared than may be recorded.
    TooManyCapabilities {
        /// Maximum accepted.
        max: usize,
    },
}

impl ProviderError {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(&self) -> &'static str {
        match self {
            Self::RequiredCapabilityIsDegraded { .. } => "required_capability_is_degraded",
            Self::RequiredCapabilitiesMissing { .. } => "required_capabilities_missing",
            Self::BindingMismatch { .. } => "binding_mismatch",
            Self::Digest { .. } => "digest_invalid",
            Self::DigestAlgorithm { .. } => "digest_algorithm_invalid",
            Self::Value { .. } => "value_invalid",
            Self::TooManyCapabilities { .. } => "too_many_capabilities",
        }
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequiredCapabilityIsDegraded { capability } => write!(
                formatter,
                "capability {capability} is both required and degraded for this mode"
            ),
            Self::RequiredCapabilitiesMissing { missing } => write!(
                formatter,
                "required capabilities are missing: {}",
                missing.join(", ")
            ),
            Self::BindingMismatch { component } => {
                write!(formatter, "session binding differs in {component}")
            }
            Self::Digest { field, error } => write!(formatter, "field {field}: {error}"),
            Self::DigestAlgorithm { field } => {
                write!(formatter, "field {field}: digest algorithm is not sha256")
            }
            Self::Value { field, error } => write!(formatter, "field {field}: {error}"),
            Self::TooManyCapabilities { max } => {
                write!(formatter, "more than {max} capabilities were declared")
            }
        }
    }
}

impl Error for ProviderError {}

/// The coordinates a provider binary was observed at.
///
/// A capability record is only meaningful with these, so it cannot be built
/// without them and a stale record is detectable by digest comparison alone.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BinaryProvenance {
    version: String,
    digest: String,
    schema_digest: Option<String>,
}

impl BinaryProvenance {
    /// Record the binary a capability set was observed against.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Value`] for an invalid version,
    /// [`ProviderError::Digest`] for malformed digest syntax, or
    /// [`ProviderError::DigestAlgorithm`] for any algorithm other than
    /// SHA-256.
    pub fn new(
        version: &str,
        digest: &str,
        schema_digest: Option<&str>,
    ) -> Result<Self, ProviderError> {
        bounded(version, "binary_version")?;
        canonical_sha256(digest, "binary_digest")?;
        if let Some(schema) = schema_digest {
            canonical_sha256(schema, "schema_digest")?;
        }
        Ok(Self {
            version: version.to_owned(),
            digest: digest.to_owned(),
            schema_digest: schema_digest.map(str::to_owned),
        })
    }

    /// Observed binary version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Observed binary digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Observed protocol schema digest, when the provider exposes one.
    #[must_use]
    pub fn schema_digest(&self) -> Option<&str> {
        self.schema_digest.as_deref()
    }

    /// Whether a later observation describes the same binary.
    #[must_use]
    pub fn matches(&self, observed: &Self) -> bool {
        self.digest == observed.digest && self.schema_digest == observed.schema_digest
    }
}

/// A structured session binding.
///
/// Every component participates in equality, so a resume cannot cross a tenant,
/// backend, provider account or namespace by accident. An unvalidated opaque
/// session value is not representable.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SessionBinding {
    tenant: String,
    backend: String,
    provider_account: String,
    provider_namespace: String,
    session: ProviderSessionId,
}

impl SessionBinding {
    /// Construct a fully qualified binding.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Value`] for an invalid component.
    pub fn new(
        tenant: &str,
        backend: &str,
        provider_account: &str,
        provider_namespace: &str,
        session: ProviderSessionId,
    ) -> Result<Self, ProviderError> {
        bounded(tenant, "tenant")?;
        bounded(backend, "backend")?;
        bounded(provider_account, "provider_account")?;
        bounded(provider_namespace, "provider_namespace")?;
        Ok(Self {
            tenant: tenant.to_owned(),
            backend: backend.to_owned(),
            provider_account: provider_account.to_owned(),
            provider_namespace: provider_namespace.to_owned(),
            session,
        })
    }

    /// Owning tenant.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// Execution backend name.
    #[must_use]
    pub fn backend(&self) -> &str {
        &self.backend
    }

    /// Provider-account coordinate.
    #[must_use]
    pub fn provider_account(&self) -> &str {
        &self.provider_account
    }

    /// Provider namespace within the account.
    #[must_use]
    pub fn provider_namespace(&self) -> &str {
        &self.provider_namespace
    }

    /// The durable session identity.
    #[must_use]
    pub const fn session(&self) -> &ProviderSessionId {
        &self.session
    }

    /// Confirm another binding is the same one, naming the first difference.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::BindingMismatch`] naming the differing
    /// component. A partial match is never an equality.
    pub fn confirm_same(&self, other: &Self) -> Result<(), ProviderError> {
        for (component, left, right) in [
            ("tenant", &self.tenant, &other.tenant),
            ("backend", &self.backend, &other.backend),
            (
                "provider_account",
                &self.provider_account,
                &other.provider_account,
            ),
            (
                "provider_namespace",
                &self.provider_namespace,
                &other.provider_namespace,
            ),
        ] {
            if left != right {
                return Err(ProviderError::BindingMismatch { component });
            }
        }
        if self.session != other.session {
            return Err(ProviderError::BindingMismatch {
                component: "session",
            });
        }
        Ok(())
    }
}

/// The capability sets an adapter declares for one integration mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModeDeclaration {
    mode: String,
    required: Vec<Capability>,
    native: Vec<Capability>,
    degraded: Vec<Capability>,
    unknown: Vec<UnknownCapability>,
    provenance: BinaryProvenance,
}

impl ModeDeclaration {
    /// Declare an integration mode.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::RequiredCapabilityIsDegraded`] when a mode
    /// names a capability as both mandatory and absent, which describes a mode
    /// that cannot exist, and [`ProviderError::TooManyCapabilities`] above the
    /// ceiling.
    pub fn new(
        mode: &str,
        required: Vec<Capability>,
        native: Vec<Capability>,
        degraded: Vec<Capability>,
        unknown: Vec<UnknownCapability>,
        provenance: BinaryProvenance,
    ) -> Result<Self, ProviderError> {
        bounded(mode, "mode")?;
        let total = required.len() + native.len() + degraded.len() + unknown.len();
        if total > MAX_CAPABILITIES {
            return Err(ProviderError::TooManyCapabilities {
                max: MAX_CAPABILITIES,
            });
        }
        if let Some(conflict) = required
            .iter()
            .find(|capability| degraded.contains(capability))
        {
            return Err(ProviderError::RequiredCapabilityIsDegraded {
                capability: conflict.name().to_owned(),
            });
        }
        Ok(Self {
            mode: mode.to_owned(),
            required,
            native,
            degraded,
            unknown,
            provenance,
        })
    }

    /// Mode name.
    #[must_use]
    pub fn mode(&self) -> &str {
        &self.mode
    }

    /// Capabilities without which this mode is unsafe.
    #[must_use]
    pub fn required(&self) -> &[Capability] {
        &self.required
    }

    /// Capabilities missing from this mode.
    #[must_use]
    pub fn degraded(&self) -> &[Capability] {
        &self.degraded
    }

    /// Capabilities this build does not define, retained and never present.
    #[must_use]
    pub fn unknown(&self) -> &[UnknownCapability] {
        &self.unknown
    }

    /// The binary these capabilities were observed against.
    #[must_use]
    pub const fn provenance(&self) -> &BinaryProvenance {
        &self.provenance
    }

    /// What is known about one capability for this mode.
    #[must_use]
    pub fn state(&self, capability: &Capability) -> CapabilityState {
        if self.native.contains(capability) {
            CapabilityState::Present
        } else if self.degraded.contains(capability) {
            CapabilityState::Absent
        } else {
            CapabilityState::Unprobed
        }
    }

    /// Select this mode for a job, failing closed on any missing requirement.
    ///
    /// There is no path on which a refusal becomes a downgrade. An
    /// approval-aware protocol is never silently replaced by auto-approval and
    /// a resumable session is never silently replaced by a fresh run, because
    /// both substitutions are expressible only as this refusal.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::RequiredCapabilitiesMissing`] naming every
    /// missing mandatory capability.
    pub fn select(&self) -> Result<Selection, ProviderError> {
        let missing: Vec<String> = self
            .required
            .iter()
            .filter(|capability| self.state(capability) != CapabilityState::Present)
            .map(|capability| capability.name().to_owned())
            .collect();
        if missing.is_empty() {
            Ok(Selection {
                mode: self.mode.clone(),
                degraded: self
                    .degraded
                    .iter()
                    .map(|capability| capability.name().to_owned())
                    .collect(),
                _private: PhantomData,
            })
        } else {
            Err(ProviderError::RequiredCapabilitiesMissing { missing })
        }
    }
}

/// Proof that an integration mode was admitted.
///
/// Obtainable only from [`ModeDeclaration::select`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Selection {
    mode: String,
    degraded: Vec<String>,
    _private: PhantomData<()>,
}

impl Selection {
    /// The admitted mode.
    #[must_use]
    pub fn mode(&self) -> &str {
        &self.mode
    }

    /// Capabilities absent in the admitted mode.
    ///
    /// Exposed so a client can display the degradation and a policy can refuse
    /// a job that needs one. This layer never decides that a degradation is
    /// acceptable.
    #[must_use]
    pub fn degraded(&self) -> &[String] {
        &self.degraded
    }
}

fn bounded(value: &str, field: &'static str) -> Result<(), ProviderError> {
    let error = if value.is_empty() {
        Some(ValueError::Empty)
    } else if value.len() > MAX_PROVIDER_ID_BYTES {
        Some(ValueError::TooLong {
            max_bytes: MAX_PROVIDER_ID_BYTES,
            actual_bytes: value.len(),
        })
    } else if value.chars().any(char::is_control) {
        Some(ValueError::ControlCharacter)
    } else {
        None
    };
    match error {
        Some(error) => Err(ProviderError::Value { field, error }),
        None => Ok(()),
    }
}

fn canonical_sha256(value: &str, field: &'static str) -> Result<(), ProviderError> {
    let digest = Digest::parse(value).map_err(|error| ProviderError::Digest { field, error })?;
    if digest.algorithm() != DigestAlgorithm::Sha256 {
        return Err(ProviderError::DigestAlgorithm { field });
    }
    Ok(())
}
