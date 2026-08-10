// SPDX-License-Identifier: Elastic-2.0

//! Tool descriptors, grant intersection, workflow capability and hook classes.
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
//! Nothing here executes a tool, starts an MCP server, installs an extension,
//! runs a hook or resolves a secret.

use core::fmt;
use std::error::Error;

use crate::primitives::ValueError;

/// Maximum UTF-8 byte length of a tool identifier.
pub const MAX_TOOL_FIELD_BYTES: usize = 256;

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

/// Why a tool or extension operation was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ToolError {
    /// A UI extension declared a backend capability.
    UiExtensionCannotHoldBackendCapability {
        /// The capability it asked for.
        capability: String,
    },
    /// A secret source was given an unbounded command.
    SecretSourceNeedsClosedArguments,
    /// A workflow exceeded a declared budget.
    WorkflowBudgetExceeded {
        /// Which budget.
        budget: &'static str,
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
            Self::UiExtensionCannotHoldBackendCapability { .. } => {
                "ui_extension_backend_capability"
            }
            Self::SecretSourceNeedsClosedArguments => "secret_source_open_arguments",
            Self::WorkflowBudgetExceeded { .. } => "workflow_budget_exceeded",
            Self::Field { .. } => "field_invalid",
        }
    }
}

impl fmt::Display for ToolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UiExtensionCannotHoldBackendCapability { capability } => write!(
                formatter,
                "a UI extension cannot declare the backend capability {capability}"
            ),
            Self::SecretSourceNeedsClosedArguments => formatter.write_str(
                "a secret source command needs a closed argument schema and empty environment",
            ),
            Self::WorkflowBudgetExceeded { budget } => {
                write!(formatter, "workflow exceeded its {budget} budget")
            }
            Self::Field { field, error } => write!(formatter, "field {field}: {error}"),
        }
    }
}

impl Error for ToolError {}

/// A tool the registry knows about.
///
/// Side-effect class and approval requirement are constructor arguments with no
/// defaults, because those two are what a policy decides on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolDescriptor {
    id: String,
    side_effect: SideEffectClass,
    approval: ApprovalRequirement,
    provenance_digest: String,
}

impl ToolDescriptor {
    /// Describe a tool.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::Field`] for an invalid component.
    pub fn new(
        id: &str,
        side_effect: SideEffectClass,
        approval: ApprovalRequirement,
        provenance_digest: &str,
    ) -> Result<Self, ToolError> {
        bounded(id, "tool_id")?;
        bounded(provenance_digest, "provenance_digest")?;
        Ok(Self {
            id: id.to_owned(),
            side_effect,
            approval,
            provenance_digest: provenance_digest.to_owned(),
        })
    }

    /// The tool identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
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

    /// The implementation digest.
    #[must_use]
    pub fn provenance_digest(&self) -> &str {
        &self.provenance_digest
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
}

/// Search the registry within a grant.
///
/// Takes the grant, so there is no call shape that searches without one.
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

/// The bounded authority a workflow program receives.
///
/// Recursion is not representable: there is no field naming the workflow tool
/// itself, and `eligible_tools` is fixed at construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowCapability {
    eligible_tools: ToolsetGrant,
    max_calls: u32,
    calls_made: u32,
}

impl WorkflowCapability {
    /// Grant a bounded capability.
    #[must_use]
    pub const fn new(eligible_tools: ToolsetGrant, max_calls: u32) -> Self {
        Self {
            eligible_tools,
            max_calls,
            calls_made: 0,
        }
    }

    /// Record one nested call.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::WorkflowBudgetExceeded`] at the ceiling, and
    /// [`ToolError::Field`] when the tool is outside the eligible set.
    pub fn invoke(&mut self, tool: &str) -> Result<(), ToolError> {
        if !self.eligible_tools.permits(tool) {
            return Err(ToolError::Field {
                field: "eligible_tool",
                error: ValueError::Empty,
            });
        }
        if self.calls_made >= self.max_calls {
            return Err(ToolError::WorkflowBudgetExceeded {
                budget: "max_calls",
            });
        }
        self.calls_made += 1;
        Ok(())
    }

    /// How many calls have been made.
    #[must_use]
    pub const fn calls_made(&self) -> u32 {
        self.calls_made
    }
}

/// What an extension contributes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExtensionKind {
    /// A backend tool.
    Tool,
    /// A lifecycle hook.
    Hook,
    /// A memory provider.
    MemoryProvider,
    /// A dashboard, desktop or TUI surface.
    UserInterface,
}

/// A signed extension manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionManifest {
    kind: ExtensionKind,
    publisher: String,
    provenance_digest: String,
    backend_capabilities: Vec<String>,
}

impl ExtensionManifest {
    /// Declare an extension.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::UiExtensionCannotHoldBackendCapability`] when a UI
    /// extension declares one, and [`ToolError::Field`] for an invalid
    /// component.
    pub fn new(
        kind: ExtensionKind,
        publisher: &str,
        provenance_digest: &str,
        backend_capabilities: &[&str],
    ) -> Result<Self, ToolError> {
        bounded(publisher, "publisher")?;
        bounded(provenance_digest, "provenance_digest")?;
        if kind == ExtensionKind::UserInterface
            && let Some(capability) = backend_capabilities.first()
        {
            return Err(ToolError::UiExtensionCannotHoldBackendCapability {
                capability: (*capability).to_owned(),
            });
        }
        for capability in backend_capabilities {
            bounded(capability, "backend_capability")?;
        }
        Ok(Self {
            kind,
            publisher: publisher.to_owned(),
            provenance_digest: provenance_digest.to_owned(),
            backend_capabilities: backend_capabilities
                .iter()
                .map(|c| (*c).to_owned())
                .collect(),
        })
    }

    /// What it contributes.
    #[must_use]
    pub const fn kind(&self) -> ExtensionKind {
        self.kind
    }

    /// Declared backend capabilities.
    #[must_use]
    pub fn backend_capabilities(&self) -> &[String] {
        &self.backend_capabilities
    }
}

/// What a hook is permitted to do.
///
/// Each class has exactly one power. None can approve, widen a sandbox or
/// rewrite history, because no class carries an operation that does.
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

    /// Whether this class may change the action's outcome.
    #[must_use]
    pub const fn may_change_outcome(self) -> bool {
        matches!(self, Self::Filter | Self::Transformer)
    }

    /// No hook class may approve.
    #[must_use]
    pub const fn may_approve(self) -> bool {
        false
    }

    /// No hook class may widen a sandbox.
    #[must_use]
    pub const fn may_widen_sandbox(self) -> bool {
        false
    }

    /// No hook class may rewrite a historical message.
    #[must_use]
    pub const fn may_rewrite_history(self) -> bool {
        false
    }
}

/// How a secret is fetched.
///
/// A command helper is a pinned executable with a closed argument list and an
/// empty environment. An arbitrary shell string is not representable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretSource {
    executable: String,
    arguments: Vec<String>,
}

impl SecretSource {
    /// Pin a command helper.
    ///
    /// # Errors
    ///
    /// Returns [`ToolError::SecretSourceNeedsClosedArguments`] when the
    /// executable looks like a shell invocation, and [`ToolError::Field`] for
    /// an invalid component.
    pub fn command(executable: &str, arguments: &[&str]) -> Result<Self, ToolError> {
        bounded(executable, "executable")?;
        if executable.contains(' ')
            || executable.contains(';')
            || executable.contains('|')
            || executable.contains('&')
        {
            return Err(ToolError::SecretSourceNeedsClosedArguments);
        }
        for argument in arguments {
            bounded(argument, "argument")?;
        }
        Ok(Self {
            executable: executable.to_owned(),
            arguments: arguments.iter().map(|a| (*a).to_owned()).collect(),
        })
    }

    /// The pinned executable.
    #[must_use]
    pub fn executable(&self) -> &str {
        &self.executable
    }

    /// The closed argument list.
    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }
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
