// SPDX-License-Identifier: Elastic-2.0

use std::convert::Infallible;

use automonique_lab::protocol::{
    BudgetEnforcement, Capability, EvidenceLevel, ExplicitFallback, LabBudget, LabBudgetValues,
    OpaqueId, Sha256Digest, UntrustedInventoryPolicy,
};
use automonique_lab::provider::{
    ProviderBoundary, ProviderBoundaryError, ProviderDispatchRecorder, ProviderStartError,
    ProviderStartRequest, R0_06_INVENTORY_SHA256, TrustedInventoryLoader,
};

const INVENTORY: &[u8] = include_bytes!("../../../../spikes/provider-surfaces/inventory.json");
const CODEX_SURFACE: &[u8] =
    include_bytes!("../../../../spikes/provider-surfaces/providers/codex.json");
const CLAUDE_SURFACE: &[u8] =
    include_bytes!("../../../../spikes/provider-surfaces/providers/claude.json");
const JCODE_SURFACE: &[u8] =
    include_bytes!("../../../../spikes/provider-surfaces/providers/jcode.json");
const OPENCODE_SURFACE: &[u8] =
    include_bytes!("../../../../spikes/provider-surfaces/providers/opencode.json");
const CODEX_SURFACE_SHA256: &str =
    "abd7d9bcd2a12983ee76d97da9f28a229abea9f3e5d59702b776a7078448dfa8";
const CODEX_BINARY_SHA256: &str =
    "cb0a15567e9a60a5820d54b0f6ae86d504dc3805c1eab21a47f70e3eb7b73a40";

fn inventory() -> automonique_lab::provider::VerifiedProviderInventory {
    TrustedInventoryLoader::new(64 * 1_024)
        .expect("bounded loader")
        .load(INVENTORY, CODEX_SURFACE)
        .expect("checked-in R0-06 artifacts")
}

fn budget() -> LabBudget {
    LabBudget::new(LabBudgetValues {
        max_wall_ms: 1_000,
        max_cpu_ms: 500,
        max_disk_bytes: 16_384,
        max_output_bytes: 4_096,
        max_pids: 2,
        max_model_calls: 0,
        max_cost_microunits: 0,
        enforcement: BudgetEnforcement::HostBrokerRequired,
    })
    .expect("bounded budget")
}

fn policy(
    mode: &str,
    evidence: EvidenceLevel,
    fallbacks: Vec<ExplicitFallback>,
) -> UntrustedInventoryPolicy {
    UntrustedInventoryPolicy::new(
        OpaqueId::new("codex").expect("provider"),
        OpaqueId::new(mode).expect("mode"),
        Sha256Digest::new(R0_06_INVENTORY_SHA256).expect("inventory digest"),
        Sha256Digest::new(CODEX_SURFACE_SHA256).expect("surface digest"),
        vec![Capability::Create, Capability::Observe],
        evidence,
        fallbacks,
    )
    .expect("policy coordinates")
}

#[derive(Default)]
struct RecordingStarter {
    calls: usize,
    provider: &'static str,
    mode: &'static str,
    request: Option<ProviderStartRequest>,
}

impl RecordingStarter {
    fn codex_exec() -> Self {
        Self {
            provider: "codex",
            mode: "exec_jsonl",
            ..Self::default()
        }
    }
}

impl ProviderDispatchRecorder for RecordingStarter {
    type Receipt = &'static str;
    type Error = Infallible;

    fn provider_id(&self) -> &str {
        self.provider
    }

    fn mode_id(&self) -> &str {
        self.mode
    }

    fn record_dispatch(
        &mut self,
        request: &ProviderStartRequest,
    ) -> Result<Self::Receipt, Self::Error> {
        self.calls += 1;
        self.request = Some(request.clone());
        Ok("recorded")
    }
}

#[test]
fn checked_in_inventory_allows_only_an_advertised_recording_dispatch() {
    let inventory = inventory();
    assert_eq!(inventory.provider().as_str(), "codex");
    assert_eq!(
        inventory.inventory_digest().as_str(),
        R0_06_INVENTORY_SHA256
    );
    assert_eq!(inventory.surface_digest().as_str(), CODEX_SURFACE_SHA256);
    assert_eq!(
        inventory.binary_digest().map(Sha256Digest::as_str),
        Some(CODEX_BINARY_SHA256)
    );

    let boundary = ProviderBoundary::new(Default::default());
    let selection = boundary
        .authorize(
            &inventory,
            &policy("exec_jsonl", EvidenceLevel::Advertised, Vec::new()),
            &budget(),
        )
        .expect("advertised R0-06 launch gate");
    let mut starter = RecordingStarter::codex_exec();
    assert_eq!(
        boundary
            .record_dispatch(&selection, &mut starter)
            .expect("recording dispatch"),
        "recorded"
    );
    assert_eq!(starter.calls, 1);
    let request = starter.request.expect("exact request recorded");
    assert_eq!(request.provider().as_str(), "codex");
    assert_eq!(request.mode().as_str(), "exec_jsonl");
    assert_eq!(request.budget().max_model_calls, 0);
    assert_eq!(request.budget().max_cost_microunits, 0);
}

#[test]
fn actual_help_only_inventory_denies_observed_lifecycle_claim() {
    let boundary = ProviderBoundary::new(Default::default());
    let error = boundary
        .authorize(
            &inventory(),
            &policy("exec_jsonl", EvidenceLevel::Observed, Vec::new()),
            &budget(),
        )
        .expect_err("R0-06 advertised evidence is not observed runtime behavior");
    assert_eq!(error, ProviderBoundaryError::CapabilityEvidence);
}

#[test]
fn every_r0_06_mode_denies_an_observed_create_claim() {
    let cases = [
        (
            CLAUDE_SURFACE,
            &["stream_json", "one_shot_stream_json", "background_agents"][..],
        ),
        (
            CODEX_SURFACE,
            &[
                "interactive_cli",
                "exec_jsonl",
                "mcp_server",
                "app_server",
                "exec_server",
            ][..],
        ),
        (
            JCODE_SURFACE,
            &["acp", "api_bridge", "run_ndjson", "debug_socket"][..],
        ),
        (OPENCODE_SURFACE, &["http_server", "acp", "json_run"][..]),
    ];
    let loader = TrustedInventoryLoader::new(64 * 1_024).expect("loader");
    let boundary = ProviderBoundary::new(Default::default());
    let mut denied = 0;
    for (surface, modes) in cases {
        let inventory = loader.load(INVENTORY, surface).expect("R0-06 shard");
        for mode in modes {
            let coordinates = UntrustedInventoryPolicy::new(
                inventory.provider().clone(),
                OpaqueId::new(*mode).expect("mode"),
                inventory.inventory_digest().clone(),
                inventory.surface_digest().clone(),
                vec![Capability::Create],
                EvidenceLevel::Observed,
                Vec::new(),
            )
            .expect("coordinates");
            assert!(matches!(
                boundary.authorize(&inventory, &coordinates, &budget()),
                Err(ProviderBoundaryError::CapabilityEvidence | ProviderBoundaryError::UnsafeMode)
            ));
            denied += 1;
        }
    }
    assert_eq!(denied, 15);
}

#[test]
fn trust_root_and_inventory_link_reject_modified_artifacts() {
    assert_eq!(
        TrustedInventoryLoader::new(100)
            .expect("small loader")
            .load(INVENTORY, CODEX_SURFACE)
            .expect_err("size checked before trust parsing"),
        ProviderBoundaryError::ArtifactLimit
    );
    let loader = TrustedInventoryLoader::new(64 * 1_024).expect("loader");
    let mut changed_inventory = INVENTORY.to_vec();
    changed_inventory.push(b' ');
    assert_eq!(
        loader
            .load(&changed_inventory, CODEX_SURFACE)
            .expect_err("trust root"),
        ProviderBoundaryError::InventoryTrustRootMismatch
    );

    let mut changed_surface = CODEX_SURFACE.to_vec();
    changed_surface.push(b' ');
    assert_eq!(
        loader
            .load(INVENTORY, &changed_surface)
            .expect_err("surface link"),
        ProviderBoundaryError::SurfaceDigestMismatch
    );
}

#[test]
fn unsafe_or_experimental_mode_denies_before_dispatch() {
    let boundary = ProviderBoundary::new(Default::default());
    assert_eq!(
        boundary
            .authorize(
                &inventory(),
                &policy("app_server", EvidenceLevel::Advertised, Vec::new()),
                &budget(),
            )
            .expect_err("experimental mode"),
        ProviderBoundaryError::UnsafeMode
    );
}

#[test]
fn manual_interactive_mode_is_not_a_machine_runtime_dispatch() {
    let boundary = ProviderBoundary::new(Default::default());
    let inventory = inventory();
    let error = boundary
        .authorize(
            &inventory,
            &policy("interactive_cli", EvidenceLevel::Advertised, Vec::new()),
            &budget(),
        )
        .expect_err("terminal UI is not a fixed machine adapter");
    assert_eq!(error, ProviderBoundaryError::UnsafeMode);
    let starter = RecordingStarter::codex_exec();
    assert_eq!(starter.calls, 0);
}

#[test]
fn fallback_order_capabilities_and_losses_are_explicit() {
    let boundary = ProviderBoundary::new(Default::default());
    let weak_fallback = ExplicitFallback::new(
        OpaqueId::new("mcp_server").expect("mode"),
        vec![
            "No captured method schema".to_owned(),
            "No observed lifecycle semantics".to_owned(),
            "Stdio transport has no advertised reconnect mechanism".to_owned(),
        ],
    )
    .expect("fallback");
    assert_eq!(
        boundary
            .authorize(
                &inventory(),
                &policy("exec_jsonl", EvidenceLevel::Advertised, vec![weak_fallback],),
                &budget(),
            )
            .expect_err("fallback capabilities"),
        ProviderBoundaryError::FallbackCapability
    );

    let unaccepted_losses = ExplicitFallback::new(
        OpaqueId::new("one_shot_stream_json").expect("mode"),
        Vec::new(),
    )
    .expect("fallback");
    let claude = TrustedInventoryLoader::new(64 * 1_024)
        .expect("loader")
        .load(INVENTORY, CLAUDE_SURFACE)
        .expect("Claude inventory");
    let claude_policy = UntrustedInventoryPolicy::new(
        claude.provider().clone(),
        OpaqueId::new("stream_json").expect("mode"),
        claude.inventory_digest().clone(),
        claude.surface_digest().clone(),
        vec![Capability::Create, Capability::Observe],
        EvidenceLevel::Advertised,
        vec![unaccepted_losses],
    )
    .expect("policy");
    assert_eq!(
        boundary
            .authorize(&claude, &claude_policy, &budget())
            .expect_err("loss acceptance"),
        ProviderBoundaryError::FallbackLosses
    );
}

#[test]
fn budget_and_fixed_adapter_coordinates_fail_closed_without_call() {
    let inventory = inventory();
    let boundary = ProviderBoundary::new(Default::default());
    let oversized = LabBudget::new(LabBudgetValues {
        max_wall_ms: 60_001,
        max_cpu_ms: 500,
        max_disk_bytes: 16_384,
        max_output_bytes: 4_096,
        max_pids: 2,
        max_model_calls: 0,
        max_cost_microunits: 0,
        enforcement: BudgetEnforcement::HostBrokerRequired,
    })
    .expect("wire-valid budget");
    assert_eq!(
        boundary
            .authorize(
                &inventory,
                &policy("exec_jsonl", EvidenceLevel::Advertised, Vec::new()),
                &oversized,
            )
            .expect_err("host ceiling"),
        ProviderBoundaryError::UnboundedBudget
    );

    let selection = boundary
        .authorize(
            &inventory,
            &policy("exec_jsonl", EvidenceLevel::Advertised, Vec::new()),
            &budget(),
        )
        .expect("selection");
    let mut wrong = RecordingStarter {
        provider: "codex",
        mode: "interactive_cli",
        ..RecordingStarter::default()
    };
    assert!(matches!(
        boundary.record_dispatch(&selection, &mut wrong),
        Err(ProviderStartError::CoordinateMismatch)
    ));
    assert_eq!(wrong.calls, 0);
}
