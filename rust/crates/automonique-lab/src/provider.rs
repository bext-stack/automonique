// SPDX-License-Identifier: Elastic-2.0

//! Trusted R0-06 inventory admission and fixed-adapter dispatch.
//!
//! This module has no executable discovery, argv construction, credential,
//! network, or process surface. It verifies the checked-in R0-06 inventory
//! snapshot and a digest-linked provider shard before it evaluates policy. A
//! successful evaluation mints the only value accepted by
//! [`ProviderBoundary::record_dispatch`]. Recording proves the launch gate;
//! it is deliberately not a provider-process effect.

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::protocol::{
    BoundedText, BudgetEnforcement, Capability, EvidenceLevel, LabBudget, OpaqueId, Sha256Digest,
    UntrustedInventoryPolicy,
};

pub const R0_06_INVENTORY_SHA256: &str =
    "3eebad2ee6a7c208861bb593b637d00b066b8084c420421fe71c79c0f187f521";
const INVENTORY_SCHEMA: &str = "automonique.provider-inventory/v1";
const SURFACE_SCHEMA: &str = "automonique.provider-surface/v1";
const CAPABILITIES: [(&str, Capability); 9] = [
    ("approval", Capability::Approval),
    ("cancel", Capability::Cancel),
    ("create", Capability::Create),
    ("model", Capability::Model),
    ("observe", Capability::Observe),
    ("reconnect", Capability::Reconnect),
    ("resume", Capability::Resume),
    ("steer", Capability::Steer),
    ("usage", Capability::Usage),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapabilitySupport {
    Advertised,
    Observed,
    Unknown,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InventoryMode {
    id: OpaqueId,
    safe_nonexperimental: bool,
    capabilities: HashMap<Capability, CapabilitySupport>,
    lost_guarantees: Vec<BoundedText>,
}

/// A selected R0-06 shard that can only be minted by the trusted loader.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedProviderInventory {
    provider: OpaqueId,
    inventory_digest: Sha256Digest,
    surface_digest: Sha256Digest,
    binary_digest: Option<Sha256Digest>,
    modes: Vec<InventoryMode>,
    fallback_order: Vec<OpaqueId>,
}

impl VerifiedProviderInventory {
    pub fn provider(&self) -> &OpaqueId {
        &self.provider
    }
    pub fn inventory_digest(&self) -> &Sha256Digest {
        &self.inventory_digest
    }
    pub fn surface_digest(&self) -> &Sha256Digest {
        &self.surface_digest
    }
    pub fn binary_digest(&self) -> Option<&Sha256Digest> {
        self.binary_digest.as_ref()
    }
}

/// Verifies bounded bytes against the pinned R0-06 inventory trust root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedInventoryLoader {
    max_artifact_bytes: usize,
}

impl TrustedInventoryLoader {
    pub fn new(max_artifact_bytes: usize) -> Result<Self, ProviderBoundaryError> {
        if !(1..=1_048_576).contains(&max_artifact_bytes) {
            return Err(ProviderBoundaryError::ArtifactLimit);
        }
        Ok(Self { max_artifact_bytes })
    }

    pub fn load(
        &self,
        inventory_bytes: &[u8],
        surface_bytes: &[u8],
    ) -> Result<VerifiedProviderInventory, ProviderBoundaryError> {
        self.check_size(inventory_bytes)?;
        self.check_size(surface_bytes)?;
        let trusted_inventory = digest(inventory_bytes)?;
        if trusted_inventory.as_str() != R0_06_INVENTORY_SHA256 {
            return Err(ProviderBoundaryError::InventoryTrustRootMismatch);
        }
        let inventory_value = self.parse(inventory_bytes, "inventory")?;
        let surface_value = self.parse(surface_bytes, "surface")?;
        let inventory = object(&inventory_value, "inventory")?;
        exact_fields(
            inventory,
            &[
                "capture_date",
                "deferred_questions",
                "deferred_to",
                "immutable_base",
                "licence",
                "providers",
                "raw_manifest",
                "schema",
            ],
        )?;
        if string(inventory, "schema")? != INVENTORY_SCHEMA
            || string(inventory, "licence")? != "Elastic-2.0"
        {
            return Err(ProviderBoundaryError::UnsupportedSchema);
        }

        let surface = object(&surface_value, "surface")?;
        if string(surface, "schema")? != SURFACE_SCHEMA {
            return Err(ProviderBoundaryError::UnsupportedSchema);
        }
        let provider = identifier(surface, "provider")?;
        let provider_entry = provider_entry(inventory, &provider)?;
        let expected_surface = Sha256Digest::new(string(provider_entry, "surface_sha256")?)
            .map_err(|_| ProviderBoundaryError::MalformedArtifact("surface_sha256"))?;
        let surface_digest = digest(surface_bytes)?;
        if surface_digest != expected_surface {
            return Err(ProviderBoundaryError::SurfaceDigestMismatch);
        }
        let expected_path = format!("spikes/provider-surfaces/providers/{provider}.json");
        if string(provider_entry, "surface_file")? != expected_path {
            return Err(ProviderBoundaryError::CoordinateMismatch);
        }
        let capability_fields = text_array(provider_entry, "capability_fields", 9)?;
        if capability_fields.len() != CAPABILITIES.len()
            || CAPABILITIES
                .iter()
                .any(|(name, _)| !capability_fields.iter().any(|field| field == name))
        {
            return Err(ProviderBoundaryError::MalformedArtifact(
                "capability_fields",
            ));
        }

        let mut modes = parse_modes(surface)?;
        let mode_count = provider_entry
            .get("mode_count")
            .and_then(Value::as_u64)
            .ok_or(ProviderBoundaryError::MalformedArtifact("mode_count"))?;
        if usize::try_from(mode_count).ok() != Some(modes.len()) {
            return Err(ProviderBoundaryError::CoordinateMismatch);
        }
        let fallback_order = parse_fallbacks(surface, &mut modes)?;
        let binary_digest = parse_binary_digest(surface)?;
        Ok(VerifiedProviderInventory {
            provider,
            inventory_digest: trusted_inventory,
            surface_digest,
            binary_digest,
            modes,
            fallback_order,
        })
    }

    fn parse(&self, bytes: &[u8], field: &'static str) -> Result<Value, ProviderBoundaryError> {
        serde_json::from_slice(bytes).map_err(|_| ProviderBoundaryError::MalformedArtifact(field))
    }

    fn check_size(&self, bytes: &[u8]) -> Result<(), ProviderBoundaryError> {
        if bytes.is_empty() || bytes.len() > self.max_artifact_bytes {
            return Err(ProviderBoundaryError::ArtifactLimit);
        }
        Ok(())
    }
}

fn provider_entry<'a>(
    inventory: &'a Map<String, Value>,
    provider: &OpaqueId,
) -> Result<&'a Map<String, Value>, ProviderBoundaryError> {
    let providers = array(inventory, "providers")?;
    if providers.is_empty() || providers.len() > 16 {
        return Err(ProviderBoundaryError::MalformedArtifact("providers"));
    }
    let mut found = None;
    let mut ids = HashSet::new();
    for value in providers {
        let entry = object(value, "provider entry")?;
        exact_fields(
            entry,
            &[
                "authentication_category",
                "capability_fields",
                "mode_count",
                "provider",
                "surface_file",
                "surface_sha256",
                "version",
            ],
        )?;
        let id = identifier(entry, "provider")?;
        if !ids.insert(id.clone()) {
            return Err(ProviderBoundaryError::DuplicateIdentifier);
        }
        if &id == provider {
            found = Some(entry);
        }
    }
    found.ok_or(ProviderBoundaryError::CoordinateMismatch)
}

fn parse_modes(surface: &Map<String, Value>) -> Result<Vec<InventoryMode>, ProviderBoundaryError> {
    let raw_modes = array(surface, "modes")?;
    if raw_modes.is_empty() || raw_modes.len() > 16 {
        return Err(ProviderBoundaryError::MalformedArtifact("modes"));
    }
    let mut ids = HashSet::new();
    raw_modes
        .iter()
        .map(|value| {
            let mode = object(value, "mode")?;
            let id = identifier(mode, "id")?;
            if !ids.insert(id.clone()) {
                return Err(ProviderBoundaryError::DuplicateIdentifier);
            }
            let stability = mode
                .get("stability")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let role = mode.get("role").and_then(Value::as_str).unwrap_or("");
            let evidence = mode
                .get("evidence_level")
                .and_then(Value::as_str)
                .unwrap_or("");
            let protocol = string(mode, "protocol")?.to_ascii_lowercase();
            let transport = string(mode, "transport")?.to_ascii_lowercase();
            let machine_runtime = !role.contains("operator")
                && !role.contains("diagnostic")
                && !role.contains("debug")
                && !role.contains("manual")
                && !protocol.contains("terminal")
                && !protocol.contains("debug")
                && !transport.contains("terminal")
                && !transport.contains("session_store")
                && !transport.contains("debug");
            let safe_nonexperimental = !matches!(stability, "experimental" | "debug_unsafe")
                && !matches!(evidence, "experimental")
                && machine_runtime;
            let raw_capabilities = mode
                .get("capabilities")
                .and_then(Value::as_object)
                .ok_or(ProviderBoundaryError::MalformedArtifact("capabilities"))?;
            exact_fields(raw_capabilities, &CAPABILITIES.map(|(name, _)| name))?;
            let capabilities = CAPABILITIES
                .iter()
                .map(|(name, capability)| {
                    let value = object(
                        raw_capabilities
                            .get(*name)
                            .ok_or(ProviderBoundaryError::MalformedArtifact("capability"))?,
                        "capability",
                    )?;
                    exact_fields(value, &["support", "reason"])?;
                    BoundedText::new(string(value, "reason")?.to_owned(), 1_024, "reason")
                        .map_err(|_| {
                            ProviderBoundaryError::MalformedArtifact("capability.reason")
                        })?;
                    let support = match string(value, "support")? {
                        "advertised" => CapabilitySupport::Advertised,
                        "observed" => CapabilitySupport::Observed,
                        "unknown" => CapabilitySupport::Unknown,
                        "unavailable" => CapabilitySupport::Unavailable,
                        _ => {
                            return Err(ProviderBoundaryError::MalformedArtifact(
                                "capability.support",
                            ));
                        }
                    };
                    Ok((*capability, support))
                })
                .collect::<Result<HashMap<_, _>, _>>()?;
            Ok(InventoryMode {
                id,
                safe_nonexperimental,
                capabilities,
                lost_guarantees: Vec::new(),
            })
        })
        .collect()
}

fn parse_fallbacks(
    surface: &Map<String, Value>,
    modes: &mut [InventoryMode],
) -> Result<Vec<OpaqueId>, ProviderBoundaryError> {
    let value = surface
        .get("fallbacks")
        .ok_or(ProviderBoundaryError::MalformedArtifact("fallbacks"))?;
    let entries = match value {
        Value::Array(entries) => entries,
        Value::Object(object) => array(object, "ordered")?,
        _ => return Err(ProviderBoundaryError::MalformedArtifact("fallbacks")),
    };
    if entries.is_empty() || entries.len() > 17 {
        return Err(ProviderBoundaryError::MalformedArtifact("fallbacks"));
    }
    let mut ranked = Vec::new();
    for entry in entries {
        let entry = object(entry, "fallback")?;
        let rank = entry
            .get("rank")
            .or_else(|| entry.get("order"))
            .and_then(Value::as_u64)
            .ok_or(ProviderBoundaryError::MalformedArtifact("fallback rank"))?;
        let mode = string(entry, "mode")?;
        if matches!(mode, "reject" | "unavailable") {
            continue;
        }
        let mode = OpaqueId::new(mode.to_owned())
            .map_err(|_| ProviderBoundaryError::MalformedArtifact("fallback mode"))?;
        if !modes.iter().any(|candidate| candidate.id == mode) {
            return Err(ProviderBoundaryError::FallbackOrder);
        }
        ranked.push((rank, mode));
    }
    ranked.sort_unstable_by_key(|(rank, _)| *rank);
    if ranked
        .iter()
        .enumerate()
        .any(|(index, (rank, _))| usize::try_from(*rank).ok() != Some(index + 1))
        || ranked
            .iter()
            .map(|(_, mode)| mode)
            .collect::<HashSet<_>>()
            .len()
            != ranked.len()
    {
        return Err(ProviderBoundaryError::FallbackOrder);
    }
    let order = ranked.into_iter().map(|(_, mode)| mode).collect::<Vec<_>>();
    populate_fallback_losses(value, modes, &order)?;
    Ok(order)
}

fn populate_fallback_losses(
    fallback_value: &Value,
    modes: &mut [InventoryMode],
    order: &[OpaqueId],
) -> Result<(), ProviderBoundaryError> {
    // Losses are validated during authorization. R0-06 uses two representations:
    // an array stores losses on each destination entry, while the older object
    // stores explicit from/to transition rows.
    let mut losses_by_mode: HashMap<OpaqueId, Vec<BoundedText>> = HashMap::new();
    match fallback_value {
        Value::Array(entries) => {
            for entry in entries {
                let entry = object(entry, "fallback")?;
                let Some(mode) = entry.get("mode").and_then(Value::as_str) else {
                    return Err(ProviderBoundaryError::MalformedArtifact("fallback mode"));
                };
                if matches!(mode, "reject" | "unavailable") {
                    continue;
                }
                let losses = bounded_text_array(entry, "lost_guarantees", 32)?;
                losses_by_mode.insert(
                    OpaqueId::new(mode.to_owned())
                        .map_err(|_| ProviderBoundaryError::MalformedArtifact("fallback mode"))?,
                    losses,
                );
            }
        }
        Value::Object(object) => {
            if let Some(Value::Array(transitions)) = object.get("lost_guarantees") {
                for transition in transitions {
                    let transition = object_ref(transition, "fallback transition")?;
                    let to = string(transition, "to")?;
                    if order.iter().any(|mode| mode.as_str() == to) {
                        losses_by_mode.insert(
                            OpaqueId::new(to.to_owned()).map_err(|_| {
                                ProviderBoundaryError::MalformedArtifact("fallback transition")
                            })?,
                            bounded_text_array(transition, "losses", 32)?,
                        );
                    }
                }
            }
        }
        _ => unreachable!("caller already established fallback representation"),
    }
    if losses_by_mode
        .keys()
        .any(|id| !modes.iter().any(|mode| &mode.id == id))
    {
        return Err(ProviderBoundaryError::FallbackOrder);
    }
    for mode in modes {
        if let Some(losses) = losses_by_mode.remove(&mode.id) {
            mode.lost_guarantees = losses;
        }
    }
    Ok(())
}

fn parse_binary_digest(
    surface: &Map<String, Value>,
) -> Result<Option<Sha256Digest>, ProviderBoundaryError> {
    let Some(Value::Object(binary)) = surface.get("binary") else {
        return Ok(None);
    };
    let candidate = binary.get("sha256").or_else(|| {
        binary
            .get("digest")
            .and_then(Value::as_object)?
            .get("value")
    });
    match candidate {
        Some(Value::String(value)) => Sha256Digest::new(value.clone())
            .map(Some)
            .map_err(|_| ProviderBoundaryError::MalformedArtifact("binary digest")),
        Some(Value::Null) | None => Ok(None),
        _ => Err(ProviderBoundaryError::MalformedArtifact("binary digest")),
    }
}

/// Absolute ceilings applied after wire-domain budget validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderBudgetCeilings {
    max_wall_ms: u64,
    max_cpu_ms: u64,
    max_disk_bytes: u64,
    max_output_bytes: u64,
    max_pids: u64,
    max_model_calls: u64,
    max_cost_microunits: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderBudgetCeilingValues {
    pub max_wall_ms: u64,
    pub max_cpu_ms: u64,
    pub max_disk_bytes: u64,
    pub max_output_bytes: u64,
    pub max_pids: u64,
    pub max_model_calls: u64,
    pub max_cost_microunits: u64,
}

impl ProviderBudgetCeilings {
    pub fn new(values: ProviderBudgetCeilingValues) -> Result<Self, ProviderBoundaryError> {
        if [
            values.max_wall_ms,
            values.max_cpu_ms,
            values.max_disk_bytes,
            values.max_output_bytes,
            values.max_pids,
        ]
        .contains(&0)
        {
            return Err(ProviderBoundaryError::UnboundedBudget);
        }
        Ok(Self {
            max_wall_ms: values.max_wall_ms,
            max_cpu_ms: values.max_cpu_ms,
            max_disk_bytes: values.max_disk_bytes,
            max_output_bytes: values.max_output_bytes,
            max_pids: values.max_pids,
            max_model_calls: values.max_model_calls,
            max_cost_microunits: values.max_cost_microunits,
        })
    }
}

impl Default for ProviderBudgetCeilings {
    fn default() -> Self {
        Self {
            max_wall_ms: 60_000,
            max_cpu_ms: 60_000,
            max_disk_bytes: 67_108_864,
            max_output_bytes: 4_194_304,
            max_pids: 4,
            max_model_calls: 1,
            max_cost_microunits: 1_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderStartBudget {
    pub max_wall_ms: u64,
    pub max_cpu_ms: u64,
    pub max_disk_bytes: u64,
    pub max_output_bytes: u64,
    pub max_pids: u64,
    pub max_model_calls: u64,
    pub max_cost_microunits: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderStartRequest {
    provider: OpaqueId,
    mode: OpaqueId,
    inventory_digest: Sha256Digest,
    surface_digest: Sha256Digest,
    binary_digest: Option<Sha256Digest>,
    budget: ProviderStartBudget,
}

impl ProviderStartRequest {
    pub fn provider(&self) -> &OpaqueId {
        &self.provider
    }
    pub fn mode(&self) -> &OpaqueId {
        &self.mode
    }
    pub fn inventory_digest(&self) -> &Sha256Digest {
        &self.inventory_digest
    }
    pub fn surface_digest(&self) -> &Sha256Digest {
        &self.surface_digest
    }
    pub fn binary_digest(&self) -> Option<&Sha256Digest> {
        self.binary_digest.as_ref()
    }
    pub const fn budget(&self) -> ProviderStartBudget {
        self.budget
    }
}

/// Unforgeable exact launch-gate token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedProviderSelection(ProviderStartRequest);

impl VerifiedProviderSelection {
    pub fn request(&self) -> &ProviderStartRequest {
        &self.0
    }
}

/// A fixed adapter injected by the composition root.
///
/// It receives no paths, argv, credentials, prompt, model, or network values.
pub trait ProviderDispatchRecorder {
    type Receipt;
    type Error: Error;

    fn provider_id(&self) -> &str;
    fn mode_id(&self) -> &str;
    fn record_dispatch(
        &mut self,
        request: &ProviderStartRequest,
    ) -> Result<Self::Receipt, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderBoundary {
    ceilings: ProviderBudgetCeilings,
}

impl ProviderBoundary {
    pub const fn new(ceilings: ProviderBudgetCeilings) -> Self {
        Self { ceilings }
    }

    pub fn authorize(
        &self,
        inventory: &VerifiedProviderInventory,
        coordinates: &UntrustedInventoryPolicy,
        budget: &LabBudget,
    ) -> Result<VerifiedProviderSelection, ProviderBoundaryError> {
        if inventory.provider != *coordinates.provider()
            || inventory.inventory_digest != *coordinates.inventory_digest()
            || inventory.surface_digest != *coordinates.surface_digest()
        {
            return Err(ProviderBoundaryError::CoordinateMismatch);
        }
        let start_budget = self.check_budget(budget)?;
        let selected = inventory
            .modes
            .iter()
            .find(|mode| &mode.id == coordinates.mode())
            .ok_or(ProviderBoundaryError::ModeMissing)?;
        check_mode(
            selected,
            coordinates.required_capabilities(),
            coordinates.minimum_evidence(),
            false,
        )?;
        let selected_index = inventory
            .fallback_order
            .iter()
            .position(|mode| mode == coordinates.mode())
            .ok_or(ProviderBoundaryError::FallbackOrder)?;
        let mut prior_index = selected_index;
        let mut seen = HashSet::new();
        for fallback in coordinates.explicit_fallbacks() {
            let index = inventory
                .fallback_order
                .iter()
                .position(|mode| mode == fallback.mode())
                .ok_or(ProviderBoundaryError::FallbackOrder)?;
            if index <= prior_index || !seen.insert(fallback.mode()) {
                return Err(ProviderBoundaryError::FallbackOrder);
            }
            let mode = inventory
                .modes
                .iter()
                .find(|mode| &mode.id == fallback.mode())
                .ok_or(ProviderBoundaryError::FallbackOrder)?;
            check_mode(
                mode,
                coordinates.required_capabilities(),
                coordinates.minimum_evidence(),
                true,
            )?;
            if mode.lost_guarantees != fallback.accepted_lost_guarantees() {
                return Err(ProviderBoundaryError::FallbackLosses);
            }
            prior_index = index;
        }
        Ok(VerifiedProviderSelection(ProviderStartRequest {
            provider: inventory.provider.clone(),
            mode: selected.id.clone(),
            inventory_digest: inventory.inventory_digest.clone(),
            surface_digest: inventory.surface_digest.clone(),
            binary_digest: inventory.binary_digest.clone(),
            budget: start_budget,
        }))
    }

    /// Dispatches only a previously authorized exact request.
    /// Record one authorized host-broker dispatch without starting a provider.
    ///
    /// Actual process lifecycle remains outside R0-06 evidence and is not an
    /// effect of this boundary.
    pub fn record_dispatch<S: ProviderDispatchRecorder>(
        &self,
        selection: &VerifiedProviderSelection,
        starter: &mut S,
    ) -> Result<S::Receipt, ProviderStartError<S::Error>> {
        let request = selection.request();
        if starter.provider_id() != request.provider.as_str()
            || starter.mode_id() != request.mode.as_str()
        {
            return Err(ProviderStartError::CoordinateMismatch);
        }
        if !self.within_ceilings(request.budget) {
            return Err(ProviderStartError::BudgetMismatch);
        }
        starter
            .record_dispatch(request)
            .map_err(ProviderStartError::Adapter)
    }

    fn check_budget(
        &self,
        budget: &LabBudget,
    ) -> Result<ProviderStartBudget, ProviderBoundaryError> {
        let values = ProviderStartBudget {
            max_wall_ms: budget.max_wall_ms().get(),
            max_cpu_ms: budget.max_cpu_ms().get(),
            max_disk_bytes: budget.max_disk_bytes().get(),
            max_output_bytes: budget.max_output_bytes().get(),
            max_pids: budget.max_pids().get(),
            max_model_calls: budget.max_model_calls().get(),
            max_cost_microunits: budget.max_cost_microunits().get(),
        };
        if budget.enforcement() != BudgetEnforcement::HostBrokerRequired
            || !self.within_ceilings(values)
        {
            return Err(ProviderBoundaryError::UnboundedBudget);
        }
        Ok(values)
    }

    fn within_ceilings(&self, values: ProviderStartBudget) -> bool {
        values.max_wall_ms <= self.ceilings.max_wall_ms
            && values.max_cpu_ms <= self.ceilings.max_cpu_ms
            && values.max_disk_bytes <= self.ceilings.max_disk_bytes
            && values.max_output_bytes <= self.ceilings.max_output_bytes
            && values.max_pids <= self.ceilings.max_pids
            && values.max_model_calls <= self.ceilings.max_model_calls
            && values.max_cost_microunits <= self.ceilings.max_cost_microunits
    }
}

fn check_mode(
    mode: &InventoryMode,
    required: &[Capability],
    minimum: EvidenceLevel,
    fallback: bool,
) -> Result<(), ProviderBoundaryError> {
    if !mode.safe_nonexperimental {
        return Err(if fallback {
            ProviderBoundaryError::UnsafeFallback
        } else {
            ProviderBoundaryError::UnsafeMode
        });
    }
    for capability in required {
        let support = mode
            .capabilities
            .get(capability)
            .ok_or(ProviderBoundaryError::CapabilityEvidence)?;
        let sufficient = *support == CapabilitySupport::Observed
            || (minimum == EvidenceLevel::Advertised && *support == CapabilitySupport::Advertised);
        if !sufficient {
            return Err(if fallback {
                ProviderBoundaryError::FallbackCapability
            } else {
                ProviderBoundaryError::CapabilityEvidence
            });
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderBoundaryError {
    ArtifactLimit,
    MalformedArtifact(&'static str),
    UnsupportedSchema,
    InventoryTrustRootMismatch,
    SurfaceDigestMismatch,
    CoordinateMismatch,
    DuplicateIdentifier,
    ModeMissing,
    UnsafeMode,
    CapabilityEvidence,
    FallbackOrder,
    UnsafeFallback,
    FallbackCapability,
    FallbackLosses,
    UnboundedBudget,
}

impl fmt::Display for ProviderBoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArtifactLimit => formatter.write_str("provider artifact exceeds its bound"),
            Self::MalformedArtifact(field) => {
                write!(formatter, "provider artifact field is malformed: {field}")
            }
            Self::UnsupportedSchema => {
                formatter.write_str("provider artifact schema is unsupported")
            }
            Self::InventoryTrustRootMismatch => {
                formatter.write_str("R0-06 inventory differs from the trusted snapshot")
            }
            Self::SurfaceDigestMismatch => {
                formatter.write_str("provider shard differs from the inventory digest")
            }
            Self::CoordinateMismatch => formatter.write_str("provider coordinates differ"),
            Self::DuplicateIdentifier => formatter.write_str("provider identifiers are duplicated"),
            Self::ModeMissing => formatter.write_str("provider mode is missing"),
            Self::UnsafeMode => formatter.write_str("provider mode is unsafe or experimental"),
            Self::CapabilityEvidence => {
                formatter.write_str("provider capability evidence is insufficient")
            }
            Self::FallbackOrder => formatter.write_str("provider fallback order is invalid"),
            Self::UnsafeFallback => {
                formatter.write_str("provider fallback is unsafe or experimental")
            }
            Self::FallbackCapability => {
                formatter.write_str("provider fallback capability evidence is insufficient")
            }
            Self::FallbackLosses => {
                formatter.write_str("provider fallback losses were not accepted exactly")
            }
            Self::UnboundedBudget => {
                formatter.write_str("provider budget is not bounded by host policy")
            }
        }
    }
}

impl Error for ProviderBoundaryError {}

#[derive(Debug)]
pub enum ProviderStartError<E> {
    CoordinateMismatch,
    BudgetMismatch,
    Adapter(E),
}

impl<E: fmt::Display> fmt::Display for ProviderStartError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CoordinateMismatch => {
                formatter.write_str("fixed provider adapter coordinates differ")
            }
            Self::BudgetMismatch => {
                formatter.write_str("provider start budget exceeds this boundary")
            }
            Self::Adapter(error) => write!(formatter, "fixed provider adapter failed: {error}"),
        }
    }
}

impl<E: Error + 'static> Error for ProviderStartError<E> {}

fn object<'a>(
    value: &'a Value,
    field: &'static str,
) -> Result<&'a Map<String, Value>, ProviderBoundaryError> {
    value
        .as_object()
        .ok_or(ProviderBoundaryError::MalformedArtifact(field))
}

fn object_ref<'a>(
    value: &'a Value,
    field: &'static str,
) -> Result<&'a Map<String, Value>, ProviderBoundaryError> {
    object(value, field)
}

fn array<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a Vec<Value>, ProviderBoundaryError> {
    object
        .get(field)
        .and_then(Value::as_array)
        .ok_or(ProviderBoundaryError::MalformedArtifact(field))
}

fn string<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, ProviderBoundaryError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ProviderBoundaryError::MalformedArtifact(field))
}

fn exact_fields(object: &Map<String, Value>, fields: &[&str]) -> Result<(), ProviderBoundaryError> {
    if object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err(ProviderBoundaryError::MalformedArtifact("unexpected field"));
    }
    Ok(())
}

fn identifier(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<OpaqueId, ProviderBoundaryError> {
    OpaqueId::new(string(object, field)?.to_owned())
        .map_err(|_| ProviderBoundaryError::MalformedArtifact(field))
}

fn text_array(
    object: &Map<String, Value>,
    field: &'static str,
    maximum: usize,
) -> Result<Vec<String>, ProviderBoundaryError> {
    let values = array(object, field)?;
    if values.len() > maximum {
        return Err(ProviderBoundaryError::MalformedArtifact(field));
    }
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or(ProviderBoundaryError::MalformedArtifact(field))
        })
        .collect()
}

fn bounded_text_array(
    object: &Map<String, Value>,
    field: &'static str,
    maximum: usize,
) -> Result<Vec<BoundedText>, ProviderBoundaryError> {
    text_array(object, field, maximum)?
        .into_iter()
        .map(|value| {
            BoundedText::new(value, 512, "fallback.loss")
                .map_err(|_| ProviderBoundaryError::MalformedArtifact(field))
        })
        .collect()
}

fn digest(bytes: &[u8]) -> Result<Sha256Digest, ProviderBoundaryError> {
    Sha256Digest::new(hex::encode(Sha256::digest(bytes)))
        .map_err(|_| ProviderBoundaryError::MalformedArtifact("digest"))
}
