// SPDX-License-Identifier: Elastic-2.0

use automonique_protocol::sandbox::{ImplementationDigest, WorkspaceContextHash};
use automonique_sandbox::{
    AdmissionAttestation, AdmissionError, AdmissionPolicy, AdoptionOutcome, CompileError,
    CompileRequest, EvidenceSource, HostCapability, HostProbeReport, PlanUse, ProbedFeature,
    ProviderEgressPolicy, QuarantineReason, ReuseDecision, RunnerAdmissionError,
    RunnerAdmissionSealer, RunnerBinding, StaticHostProbe, SupportedMode, ToolEgressPolicy, adopt,
    compile, evaluate_reuse,
};
#[cfg(target_os = "linux")]
use automonique_sandbox::{HostFeatureProbe, LinuxHostProbe};

fn digest(seed: u8) -> String {
    format!("sha256:{seed:02x}{}", "00".repeat(31))
}

fn implementation(capability: HostCapability) -> ImplementationDigest {
    let seed = HostCapability::ALL
        .iter()
        .position(|candidate| *candidate == capability)
        .expect("known capability") as u8
        + 1;
    ImplementationDigest::parse(&digest(seed)).expect("valid digest")
}

fn all_features() -> Vec<ProbedFeature> {
    HostCapability::ALL
        .into_iter()
        .map(|capability| ProbedFeature::new(capability, implementation(capability)))
        .collect()
}

fn policy() -> AdmissionPolicy {
    AdmissionPolicy::new(all_features()).expect("unique feature pins")
}

fn report_without(missing: Option<HostCapability>) -> HostProbeReport {
    HostProbeReport::new(
        all_features()
            .into_iter()
            .filter(|feature| Some(feature.capability()) != missing),
    )
    .expect("unique report")
}

fn request(mode: SupportedMode, provider_egress: ProviderEgressPolicy) -> CompileRequest {
    CompileRequest {
        mode,
        policy_digest: policy().digest().clone(),
        workspace_context: WorkspaceContextHash::parse(&digest(41)).expect("workspace digest"),
        provider_egress,
    }
}

fn plan(
    mode: SupportedMode,
    provider_egress: ProviderEgressPolicy,
) -> automonique_sandbox::AdmissionPlan {
    compile(
        request(mode, provider_egress),
        &policy(),
        &StaticHostProbe::new(report_without(None)),
    )
    .expect("admitted")
}

#[test]
fn every_required_observe_feature_is_fail_closed_when_missing() {
    for missing in [
        HostCapability::PrivateMountView,
        HostCapability::Landlock,
        HostCapability::ProcessBoundary,
        HostCapability::ResourceLimits,
        HostCapability::DescriptorIsolation,
        HostCapability::ToolNetworkDeny,
    ] {
        let error = compile(
            request(SupportedMode::Observe, ProviderEgressPolicy::Denied),
            &policy(),
            &StaticHostProbe::new(report_without(Some(missing))),
        )
        .expect_err("missing feature must refuse");
        assert_eq!(
            error,
            CompileError::Admission(AdmissionError::MissingHostFeature(missing))
        );
    }
}

#[test]
fn workspace_and_provider_separation_require_their_extra_features() {
    for (mode, provider, missing) in [
        (
            SupportedMode::WorkspaceOffline,
            ProviderEgressPolicy::Denied,
            HostCapability::IsolatedWritableWorkspace,
        ),
        (
            SupportedMode::Observe,
            ProviderEgressPolicy::BrokeredNamed,
            HostCapability::ProviderControlSeparation,
        ),
    ] {
        let error = compile(
            request(mode, provider),
            &policy(),
            &StaticHostProbe::new(report_without(Some(missing))),
        )
        .expect_err("missing feature must refuse");
        assert_eq!(
            error,
            CompileError::Admission(AdmissionError::MissingHostFeature(missing))
        );
    }
}

#[test]
fn rejected_implementation_never_downgrades_to_another_mode() {
    let mut features = all_features();
    let landlock = features
        .iter_mut()
        .find(|feature| feature.capability() == HostCapability::Landlock)
        .expect("landlock present");
    *landlock = ProbedFeature::new(
        HostCapability::Landlock,
        ImplementationDigest::parse(&digest(63)).expect("digest"),
    );
    let error = compile(
        request(
            SupportedMode::WorkspaceOffline,
            ProviderEgressPolicy::Denied,
        ),
        &policy(),
        &StaticHostProbe::new(HostProbeReport::new(features).expect("report")),
    )
    .expect_err("implementation drift refused");
    assert!(matches!(
        error,
        CompileError::Admission(AdmissionError::ImplementationRejected {
            capability: HostCapability::Landlock,
            ..
        })
    ));
}

#[test]
fn provider_and_tool_egress_are_separate_typed_decisions() {
    let admitted = plan(
        SupportedMode::WorkspaceOffline,
        ProviderEgressPolicy::BrokeredNamed,
    );
    assert_eq!(
        admitted.provider_egress(),
        ProviderEgressPolicy::BrokeredNamed
    );
    assert_eq!(admitted.tool_egress(), ToolEgressPolicy::Denied);
    assert_ne!(
        admitted.provider_control_egress().access(),
        admitted.tool_workload_egress().access()
    );
    assert_eq!(admitted.use_class(), PlanUse::ObservationOnly);

    let observe = plan(SupportedMode::Observe, ProviderEgressPolicy::Denied);
    assert_eq!(observe.use_class(), PlanUse::ObservationOnly);
}

#[test]
fn caller_fabricated_policy_and_report_never_admit_a_runner() {
    for mode in [SupportedMode::Observe, SupportedMode::WorkspaceOffline] {
        let supplied_policy = policy();
        let supplied_report = report_without(None);
        assert_eq!(supplied_policy.source(), EvidenceSource::CallerSupplied);
        assert_eq!(supplied_report.source(), EvidenceSource::CallerSupplied);
        let compiled = compile(
            CompileRequest {
                mode,
                policy_digest: supplied_policy.digest().clone(),
                workspace_context: WorkspaceContextHash::parse(&digest(41)).expect("digest"),
                provider_egress: ProviderEgressPolicy::BrokeredNamed,
            },
            &supplied_policy,
            &StaticHostProbe::new(supplied_report),
        )
        .expect("internally consistent fixture inputs compile");
        assert_eq!(compiled.use_class(), PlanUse::ObservationOnly);
    }
}

#[test]
fn request_policy_digest_is_bound_to_actual_pin_set() {
    let original_policy = policy();
    let mut changed_pins = all_features();
    let observe_unused_pin = changed_pins
        .iter_mut()
        .find(|feature| feature.capability() == HostCapability::ProviderControlSeparation)
        .expect("pin exists");
    *observe_unused_pin = ProbedFeature::new(
        HostCapability::ProviderControlSeparation,
        ImplementationDigest::parse(&digest(62)).expect("digest"),
    );
    let actual_policy = AdmissionPolicy::new(changed_pins).expect("changed policy");
    assert_ne!(original_policy.digest(), actual_policy.digest());
    let error = compile(
        CompileRequest {
            mode: SupportedMode::Observe,
            policy_digest: original_policy.digest().clone(),
            workspace_context: WorkspaceContextHash::parse(&digest(41)).expect("digest"),
            provider_egress: ProviderEgressPolicy::Denied,
        },
        &actual_policy,
        &StaticHostProbe::new(report_without(None)),
    )
    .expect_err("caller digest must not substitute for actual policy contents");
    assert_eq!(
        error,
        CompileError::Admission(AdmissionError::PolicyDigestMismatch {
            requested: original_policy.digest().to_string(),
            actual: actual_policy.digest().to_string(),
        })
    );
}

#[test]
fn wider_or_different_subject_reuse_requires_a_new_host() {
    let observe = plan(SupportedMode::Observe, ProviderEgressPolicy::Denied);
    let writable = plan(
        SupportedMode::WorkspaceOffline,
        ProviderEgressPolicy::Denied,
    );
    assert_eq!(
        evaluate_reuse(&observe, &writable),
        ReuseDecision::RequiresNewHost
    );
    assert_eq!(evaluate_reuse(&writable, &observe), ReuseDecision::Reuse);

    let provider_network = plan(
        SupportedMode::WorkspaceOffline,
        ProviderEgressPolicy::BrokeredNamed,
    );
    assert_eq!(
        evaluate_reuse(&writable, &provider_network),
        ReuseDecision::RequiresNewHost
    );

    let mut different = request(
        SupportedMode::WorkspaceOffline,
        ProviderEgressPolicy::Denied,
    );
    different.workspace_context = WorkspaceContextHash::parse(&digest(42)).expect("digest");
    let different = compile(
        different,
        &policy(),
        &StaticHostProbe::new(report_without(None)),
    )
    .expect("admitted");
    assert_eq!(
        evaluate_reuse(&writable, &different),
        ReuseDecision::RequiresNewHost
    );
}

#[test]
fn canonical_plan_digest_is_order_independent_and_input_sensitive() {
    let forward = report_without(None);
    let reverse = HostProbeReport::new(all_features().into_iter().rev()).expect("report");
    assert_eq!(forward.digest(), reverse.digest());
    let first = compile(
        request(
            SupportedMode::WorkspaceOffline,
            ProviderEgressPolicy::Denied,
        ),
        &policy(),
        &StaticHostProbe::new(forward),
    )
    .expect("admitted");
    let second = compile(
        request(
            SupportedMode::WorkspaceOffline,
            ProviderEgressPolicy::Denied,
        ),
        &policy(),
        &StaticHostProbe::new(reverse),
    )
    .expect("admitted");
    assert_eq!(first.digest(), second.digest());
    assert_ne!(
        first.digest(),
        plan(
            SupportedMode::WorkspaceOffline,
            ProviderEgressPolicy::BrokeredNamed
        )
        .digest()
    );
}

#[test]
fn reuse_refuses_changed_report_even_when_required_implementations_match() {
    let ordinary = plan(SupportedMode::Observe, ProviderEgressPolicy::Denied);
    let mut changed_features = all_features();
    let unused = changed_features
        .iter_mut()
        .find(|feature| feature.capability() == HostCapability::ProviderControlSeparation)
        .expect("unused feature exists");
    *unused = ProbedFeature::new(
        HostCapability::ProviderControlSeparation,
        ImplementationDigest::parse(&digest(62)).expect("digest"),
    );
    let changed = compile(
        request(SupportedMode::Observe, ProviderEgressPolicy::Denied),
        &policy(),
        &StaticHostProbe::new(HostProbeReport::new(changed_features).expect("report")),
    )
    .expect("changed unused evidence still compiles");
    assert_eq!(
        ordinary.required_features(),
        changed.required_features(),
        "negative control: required implementation list is unchanged"
    );
    assert_ne!(ordinary.host_report_digest(), changed.host_report_digest());
    assert_eq!(
        evaluate_reuse(&ordinary, &changed),
        ReuseDecision::RequiresNewHost
    );
}

#[test]
fn attestation_mismatch_quarantines_instead_of_adopting() {
    let original = plan(
        SupportedMode::WorkspaceOffline,
        ProviderEgressPolicy::Denied,
    );
    let changed = plan(
        SupportedMode::WorkspaceOffline,
        ProviderEgressPolicy::BrokeredNamed,
    );
    let recorded = AdmissionAttestation::record(&original);
    let observed = AdmissionAttestation::record(&changed);
    assert_eq!(
        adopt(Some(&recorded), Some(&recorded)),
        AdoptionOutcome::Adopted
    );
    let AdoptionOutcome::Quarantined(quarantine) = adopt(Some(&recorded), Some(&observed)) else {
        panic!("mismatch was adopted");
    };
    assert_eq!(quarantine.reason(), QuarantineReason::PlanDigestMismatch);
    assert_eq!(quarantine.permitted_operations().len(), 3);
    assert!(matches!(
        adopt(Some(&recorded), None),
        AdoptionOutcome::Quarantined(_)
    ));

    let mut changed_report = all_features();
    let unused = changed_report
        .iter_mut()
        .find(|feature| feature.capability() == HostCapability::ProviderControlSeparation)
        .expect("feature present");
    *unused = ProbedFeature::new(
        HostCapability::ProviderControlSeparation,
        ImplementationDigest::parse(&digest(62)).expect("digest"),
    );
    let changed_observation = compile(
        request(SupportedMode::Observe, ProviderEgressPolicy::Denied),
        &policy(),
        &StaticHostProbe::new(HostProbeReport::new(changed_report).expect("report")),
    )
    .expect("unrequired feature does not affect admission");
    let ordinary_observation = plan(SupportedMode::Observe, ProviderEgressPolicy::Denied);
    let recorded = AdmissionAttestation::record(&ordinary_observation);
    let observed = AdmissionAttestation::record(&changed_observation);
    let AdoptionOutcome::Quarantined(quarantine) = adopt(Some(&recorded), Some(&observed)) else {
        panic!("host report drift was adopted");
    };
    assert_eq!(quarantine.reason(), QuarantineReason::HostReportMismatch);
}

#[cfg(target_os = "linux")]
#[test]
fn fixed_linux_observation_is_independent_but_claims_no_enforcement_features() {
    let first = LinuxHostProbe::new().probe().expect("fixed Linux probe");
    let second = LinuxHostProbe::new()
        .probe()
        .expect("repeat fixed Linux probe");
    assert_eq!(first.source(), EvidenceSource::IndependentlyObservedLinux);
    assert_eq!(first.digest(), second.digest());
    assert!(
        HostCapability::ALL
            .into_iter()
            .all(|capability| first.implementation(capability).is_none()),
        "process observations must not be promoted to enforcement features"
    );

    let error = compile(
        request(
            SupportedMode::WorkspaceOffline,
            ProviderEgressPolicy::Denied,
        ),
        &policy(),
        &LinuxHostProbe::new(),
    )
    .expect_err("observing the process is not workspace enforcement");
    assert_eq!(
        error,
        CompileError::Admission(AdmissionError::MissingHostFeature(
            HostCapability::PrivateMountView
        ))
    );
}

#[cfg(target_os = "linux")]
#[test]
fn observed_sealer_cannot_promote_a_caller_compiled_plan() {
    let mut sealer = RunnerAdmissionSealer::observe().expect("observed sealer");
    let observation_only = plan(
        SupportedMode::WorkspaceOffline,
        ProviderEgressPolicy::Denied,
    );
    let binding = RunnerBinding::new(
        "runner-a",
        "run-a",
        implementation(HostCapability::IsolatedWritableWorkspace),
        implementation(HostCapability::ProcessBoundary),
    )
    .expect("runner binding");
    assert!(matches!(
        sealer.issue(&observation_only, binding),
        Err(RunnerAdmissionError::ObservationOnly)
    ));
}
