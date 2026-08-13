// SPDX-License-Identifier: Elastic-2.0

//! R14-01 verification contract — provider/model plugin catalog.
//!
//! Each module below covers one obligation: the closed provider vocabulary and
//! its cross-crate counterparts, the construction refusals, the alignment rules
//! against the surfaces this module reuses rather than restates, the separation
//! of registration from conformance, exact lookup, and the deterministic
//! rendered inventory.

use automonique_protocol::models::{
    AuthMethod, CatalogEntryParts, DataPolicy, Modality, ModelCatalogEntry, ModelRef, Pricing,
    PricingUnit, PromptRetention, ReasoningControl, StructuredOutputSupport, ToolSupport,
    TrainingUse,
};
use automonique_protocol::primitives::ValueError;
use automonique_protocol::provider::{
    BinaryProvenance, Capability, CapabilityGroup, CapabilityState, ModeDeclaration, ProviderError,
    UnknownCapability,
};
use automonique_protocol::provider_catalog::{
    CatalogError, ConformanceOutcome, ConformanceRecord, MAX_CATALOG_FIELD_BYTES,
    MAX_CONFORMANCE_RECORDS_PER_ENTRY, MAX_MODELS_PER_ENTRY, MAX_MODES_PER_ENTRY,
    PLANNED_PROVIDER_KINDS, PROVIDER_CATALOG_SCHEMA_V1, ProviderCatalog, ProviderCatalogEntry,
    ProviderEntryParts, ProviderKind, RunnerEventDialect,
};

const BINARY: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const SCHEMA: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const OTHER_BINARY: &str =
    "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const VERSION: &str = "0.146.0";
const ADAPTER: &str = "0.1.0";

fn provenance() -> BinaryProvenance {
    BinaryProvenance::new(VERSION, BINARY, Some(SCHEMA)).expect("valid provenance")
}

fn capability(group: CapabilityGroup, name: &str) -> Capability {
    Capability::new(group, name).expect("valid capability")
}

/// The mode this tree's Codex adapter would declare: approval-aware and
/// resumable, with cost telemetry observed absent and one capability spelling
/// this build does not define.
fn app_server() -> ModeDeclaration {
    ModeDeclaration::new(
        "app-server",
        vec![
            capability(CapabilityGroup::Approvals, "approval_response"),
            capability(CapabilityGroup::Sessions, "resume"),
        ],
        vec![
            capability(CapabilityGroup::Approvals, "approval_response"),
            capability(CapabilityGroup::Sessions, "resume"),
            capability(CapabilityGroup::Turns, "steer"),
        ],
        vec![capability(CapabilityGroup::Telemetry, "cost")],
        vec![UnknownCapability::new("future_capability").expect("valid")],
        provenance(),
    )
    .expect("consistent declaration")
}

fn named_mode(name: &str) -> ModeDeclaration {
    ModeDeclaration::new(
        name,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        provenance(),
    )
    .expect("consistent declaration")
}

fn model_named(provider: &str, model: &str) -> ModelCatalogEntry {
    ModelCatalogEntry::declare(CatalogEntryParts {
        model: ModelRef::new(provider, model).expect("valid model reference"),
        display_name: model,
        modalities: &[Modality::Image, Modality::Text],
        context_limit_tokens: 400_000,
        max_output_tokens: 128_000,
        reasoning: ReasoningControl::CallerSelectedEffort,
        tools: ToolSupport::Parallel,
        structured_output: StructuredOutputSupport::SchemaConstrained,
        region: "us-east-1",
        sovereignty_zone: "us",
        data_policy: DataPolicy::new(
            TrainingUse::Prohibited,
            PromptRetention::NoneRetained,
            "us-commercial",
        )
        .expect("valid data policy"),
        pricing: Pricing::new("usd", PricingUnit::MillionTokens, 1_250_000, 10_000_000)
            .expect("valid pricing"),
        auth: AuthMethod::SubscriptionSession,
    })
    .expect("complete catalog entry")
}

fn codex_model() -> ModelCatalogEntry {
    model_named("codex", "codex-mini")
}

fn record(mode: &str, adapter: &str, outcome: ConformanceOutcome) -> ConformanceRecord {
    ConformanceRecord::record(provenance(), mode, adapter, outcome).expect("valid record")
}

fn parts() -> ProviderEntryParts {
    ProviderEntryParts {
        kind: ProviderKind::Codex,
        executable: provenance(),
        dialect: RunnerEventDialect::AutomoniqueRunnerV1,
        modes: vec![app_server()],
        models: vec![codex_model()],
        conformance: vec![record("app-server", ADAPTER, ConformanceOutcome::Passed)],
    }
}

fn entry() -> ProviderCatalogEntry {
    ProviderCatalogEntry::register(parts()).expect("registerable provider")
}

fn catalog() -> ProviderCatalog {
    ProviderCatalog::register([entry()]).expect("assembled catalog")
}

/// The closed vocabulary, and the counterparts this crate cannot import.
mod vocabulary {
    use super::*;

    /// The spelling `automonique_agents::spawn_plan::ProviderKind::as_str`
    /// returns. `automonique-protocol` has no dependencies, so the agents crate
    /// is not visible here and this is an assertion rather than a cross-check —
    /// the same honest gap `compat.rs` records for its foreign matrix rows. A
    /// rename on either side fails one of the two suites.
    #[test]
    fn the_provider_kind_spellings_are_pinned_against_the_agents_crate() {
        assert_eq!(ProviderKind::ALL.len(), 1);
        assert_eq!(ProviderKind::Codex.as_str(), "codex");
        assert_eq!(ProviderKind::Codex.to_string(), "codex");
        for kind in ProviderKind::ALL {
            assert_eq!(ProviderKind::from_spelling(kind.as_str()), Some(kind));
        }
    }

    /// The spelling `automonique_runner::spec_fields::RunnerEventDialect`
    /// defines, pinned the same way.
    #[test]
    fn the_event_dialect_spelling_is_pinned_against_the_runner_crate() {
        assert_eq!(RunnerEventDialect::ALL.len(), 1);
        assert_eq!(
            RunnerEventDialect::AutomoniqueRunnerV1.as_str(),
            "automonique_runner_v1"
        );
        for dialect in RunnerEventDialect::ALL {
            assert_eq!(
                RunnerEventDialect::from_spelling(dialect.as_str()),
                Some(dialect)
            );
        }
        assert_eq!(
            RunnerEventDialect::from_spelling("automonique_runner"),
            None
        );
        assert_eq!(
            RunnerEventDialect::from_spelling("automonique_runner_v2"),
            None
        );
    }

    #[test]
    fn an_unregistered_spelling_is_a_typed_none() {
        assert_eq!(ProviderKind::from_spelling("claude"), None);
        assert_eq!(ProviderKind::from_spelling("Codex"), None);
        assert_eq!(ProviderKind::from_spelling(""), None);
    }

    /// The plan names four built-in providers. Three have no adapter, and the
    /// catalog says which three rather than treating them as never-heard-of.
    #[test]
    fn every_planned_but_unimplemented_kind_refuses_by_name() {
        assert_eq!(PLANNED_PROVIDER_KINDS.len(), 3);
        for planned in PLANNED_PROVIDER_KINDS {
            assert_eq!(ProviderKind::from_spelling(planned), None);
            assert_eq!(
                ProviderKind::resolve(planned),
                Err(CatalogError::PlannedProviderKind {
                    name: planned.to_owned()
                }),
                "{planned} did not refuse as a planned kind"
            );
        }
        assert!(!PLANNED_PROVIDER_KINDS.contains(&ProviderKind::Codex.as_str()));
    }

    #[test]
    fn an_undocumented_spelling_refuses_as_unknown_rather_than_planned() {
        assert_eq!(
            ProviderKind::resolve("acme-llm"),
            Err(CatalogError::UnknownProviderKind {
                name: "acme-llm".to_owned()
            })
        );
    }

    #[test]
    fn a_spelling_outside_the_bounded_grammar_refuses_before_it_is_classified() {
        assert_eq!(
            ProviderKind::resolve(""),
            Err(CatalogError::Value {
                field: "provider_kind",
                error: ValueError::Empty
            })
        );
        assert_eq!(
            ProviderKind::resolve("co\u{7}dex"),
            Err(CatalogError::Value {
                field: "provider_kind",
                error: ValueError::ControlCharacter
            })
        );
        let long = "c".repeat(MAX_CATALOG_FIELD_BYTES + 1);
        assert_eq!(
            ProviderKind::resolve(&long),
            Err(CatalogError::Value {
                field: "provider_kind",
                error: ValueError::TooLong {
                    max_bytes: MAX_CATALOG_FIELD_BYTES,
                    actual_bytes: MAX_CATALOG_FIELD_BYTES + 1,
                }
            })
        );
    }

    #[test]
    fn the_schema_name_is_a_versioned_dotted_automonique_name() {
        assert_eq!(
            PROVIDER_CATALOG_SCHEMA_V1,
            "automonique.provider-catalog/v1"
        );
        let (name, version) = PROVIDER_CATALOG_SCHEMA_V1
            .split_once("/v")
            .expect("a versioned name");
        assert!(name.starts_with("automonique."));
        assert!(version.chars().all(|digit| digit.is_ascii_digit()));
    }

    #[test]
    fn every_error_category_is_a_distinct_stable_spelling() {
        let categories = [
            CatalogError::UnknownProviderKind {
                name: String::from("x"),
            },
            CatalogError::PlannedProviderKind {
                name: String::from("x"),
            },
            CatalogError::ProviderAbsent {
                kind: ProviderKind::Codex,
            },
            CatalogError::ModelNotOffered {
                model: String::from("x"),
            },
            CatalogError::ModeNotRegistered {
                mode: String::from("x"),
            },
            CatalogError::DuplicateProviderKind {
                kind: ProviderKind::Codex,
            },
            CatalogError::DuplicateMode {
                mode: String::from("x"),
            },
            CatalogError::DuplicateModel {
                model: String::from("x"),
            },
            CatalogError::DuplicateConformance {
                mode: String::from("x"),
                adapter_version: String::from("y"),
            },
            CatalogError::Required { field: "x" },
            CatalogError::TooMany { field: "x", max: 1 },
            CatalogError::Value {
                field: "x",
                error: ValueError::Empty,
            },
            CatalogError::ModeProvenanceMismatch {
                mode: String::from("x"),
                field: "y",
            },
            CatalogError::ConformanceProvenanceMismatch {
                mode: String::from("x"),
                field: "y",
            },
            CatalogError::ModelProviderMismatch {
                model: String::from("x"),
                declared: String::from("y"),
                expected: "z",
            },
            CatalogError::Mode {
                error: ProviderError::TooManyCapabilities { max: 1 },
            },
            CatalogError::NotConformant {
                mode: String::from("x"),
                adapter_version: String::from("y"),
            },
            CatalogError::ConformanceFailed {
                mode: String::from("x"),
                adapter_version: String::from("y"),
            },
            CatalogError::DigestUnparsable { field: "x" },
        ];
        let mut spellings: Vec<&str> = categories
            .iter()
            .map(CatalogError::category)
            .collect::<Vec<&str>>();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total);
        for error in &categories {
            assert!(!error.to_string().is_empty());
        }
    }
}

/// Every bound and every alignment rule refuses at construction.
mod registration {
    use super::*;

    #[test]
    fn a_complete_registration_is_accepted() {
        let entry = entry();
        assert_eq!(entry.kind(), ProviderKind::Codex);
        assert_eq!(entry.dialect(), RunnerEventDialect::AutomoniqueRunnerV1);
        assert_eq!(entry.modes().len(), 1);
        assert_eq!(entry.models().len(), 1);
        assert_eq!(entry.conformance().len(), 1);
        assert_eq!(entry.executable().version(), VERSION);
    }

    /// Conformance is keyed by schema hash, so a binary whose protocol schema
    /// is unknown cannot be registered: every record filed against it would be
    /// unkeyable.
    #[test]
    fn a_binary_without_a_schema_digest_cannot_be_registered() {
        let unschemed = BinaryProvenance::new(VERSION, BINARY, None).expect("valid provenance");
        let modes = vec![
            ModeDeclaration::new(
                "app-server",
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                unschemed.clone(),
            )
            .expect("consistent declaration"),
        ];
        assert_eq!(
            ProviderCatalogEntry::register(ProviderEntryParts {
                executable: unschemed,
                modes,
                conformance: Vec::new(),
                ..parts()
            }),
            Err(CatalogError::Required {
                field: "schema_digest"
            })
        );
    }

    #[test]
    fn an_entry_declaring_no_mode_refuses() {
        assert_eq!(
            ProviderCatalogEntry::register(ProviderEntryParts {
                modes: Vec::new(),
                conformance: Vec::new(),
                ..parts()
            }),
            Err(CatalogError::Required { field: "modes" })
        );
    }

    #[test]
    fn more_modes_than_the_ceiling_refuse() {
        let modes: Vec<ModeDeclaration> = (0..=MAX_MODES_PER_ENTRY)
            .map(|index| named_mode(&format!("mode-{index}")))
            .collect();
        assert_eq!(modes.len(), MAX_MODES_PER_ENTRY + 1);
        assert_eq!(
            ProviderCatalogEntry::register(ProviderEntryParts {
                modes,
                conformance: Vec::new(),
                ..parts()
            }),
            Err(CatalogError::TooMany {
                field: "modes",
                max: MAX_MODES_PER_ENTRY
            })
        );
    }

    #[test]
    fn the_same_mode_declared_twice_refuses() {
        assert_eq!(
            ProviderCatalogEntry::register(ProviderEntryParts {
                modes: vec![app_server(), named_mode("app-server")],
                conformance: Vec::new(),
                ..parts()
            }),
            Err(CatalogError::DuplicateMode {
                mode: String::from("app-server")
            })
        );
    }

    /// A capability record observed against another binary cannot be filed
    /// under this entry. `BinaryProvenance::matches` is the comparison; the
    /// catalog is the place that insists on it.
    #[test]
    fn a_mode_observed_against_another_binary_refuses() {
        let elsewhere =
            BinaryProvenance::new(VERSION, OTHER_BINARY, Some(SCHEMA)).expect("valid provenance");
        let stale = ModeDeclaration::new(
            "app-server",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            elsewhere,
        )
        .expect("consistent declaration");
        assert_eq!(
            ProviderCatalogEntry::register(ProviderEntryParts {
                modes: vec![stale],
                conformance: Vec::new(),
                ..parts()
            }),
            Err(CatalogError::ModeProvenanceMismatch {
                mode: String::from("app-server"),
                field: "binary_digest"
            })
        );
    }

    #[test]
    fn a_mode_disagreeing_about_the_binary_version_refuses() {
        let renamed =
            BinaryProvenance::new("0.146.1", BINARY, Some(SCHEMA)).expect("valid provenance");
        let mismatched = ModeDeclaration::new(
            "app-server",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            renamed,
        )
        .expect("consistent declaration");
        assert_eq!(
            ProviderCatalogEntry::register(ProviderEntryParts {
                modes: vec![mismatched],
                conformance: Vec::new(),
                ..parts()
            }),
            Err(CatalogError::ModeProvenanceMismatch {
                mode: String::from("app-server"),
                field: "binary_version"
            })
        );
    }

    #[test]
    fn an_entry_offering_no_model_refuses() {
        assert_eq!(
            ProviderCatalogEntry::register(ProviderEntryParts {
                models: Vec::new(),
                ..parts()
            }),
            Err(CatalogError::Required { field: "models" })
        );
    }

    #[test]
    fn more_models_than_the_ceiling_refuse() {
        let models: Vec<ModelCatalogEntry> = (0..=MAX_MODELS_PER_ENTRY)
            .map(|index| model_named("codex", &format!("codex-{index}")))
            .collect();
        assert_eq!(models.len(), MAX_MODELS_PER_ENTRY + 1);
        assert_eq!(
            ProviderCatalogEntry::register(ProviderEntryParts { models, ..parts() }),
            Err(CatalogError::TooMany {
                field: "models",
                max: MAX_MODELS_PER_ENTRY
            })
        );
    }

    #[test]
    fn the_same_model_offered_twice_refuses() {
        assert_eq!(
            ProviderCatalogEntry::register(ProviderEntryParts {
                models: vec![codex_model(), codex_model()],
                ..parts()
            }),
            Err(CatalogError::DuplicateModel {
                model: String::from("codex/codex-mini")
            })
        );
    }

    /// `ModelRef` carries its provider as free text. This is the rule that
    /// closes it against the registered kind: an entry cannot smuggle another
    /// provider's model in under Codex's registration.
    #[test]
    fn a_model_naming_another_provider_refuses() {
        assert_eq!(
            ProviderCatalogEntry::register(ProviderEntryParts {
                models: vec![model_named("claude", "opus")],
                ..parts()
            }),
            Err(CatalogError::ModelProviderMismatch {
                model: String::from("claude/opus"),
                declared: String::from("claude"),
                expected: "codex"
            })
        );
    }

    #[test]
    fn more_conformance_records_than_the_ceiling_refuse() {
        let conformance: Vec<ConformanceRecord> = (0..=MAX_CONFORMANCE_RECORDS_PER_ENTRY)
            .map(|index| {
                record(
                    "app-server",
                    &format!("0.1.{index}"),
                    ConformanceOutcome::Passed,
                )
            })
            .collect();
        assert_eq!(conformance.len(), MAX_CONFORMANCE_RECORDS_PER_ENTRY + 1);
        assert_eq!(
            ProviderCatalogEntry::register(ProviderEntryParts {
                conformance,
                ..parts()
            }),
            Err(CatalogError::TooMany {
                field: "conformance",
                max: MAX_CONFORMANCE_RECORDS_PER_ENTRY
            })
        );
    }

    #[test]
    fn a_conformance_record_for_an_undeclared_mode_refuses() {
        assert_eq!(
            ProviderCatalogEntry::register(ProviderEntryParts {
                conformance: vec![record("exec-jsonl", ADAPTER, ConformanceOutcome::Passed)],
                ..parts()
            }),
            Err(CatalogError::ModeNotRegistered {
                mode: String::from("exec-jsonl")
            })
        );
    }

    #[test]
    fn a_conformance_record_against_another_binary_refuses() {
        let elsewhere =
            BinaryProvenance::new(VERSION, OTHER_BINARY, Some(SCHEMA)).expect("valid provenance");
        let stale =
            ConformanceRecord::record(elsewhere, "app-server", ADAPTER, ConformanceOutcome::Passed)
                .expect("valid record");
        assert_eq!(
            ProviderCatalogEntry::register(ProviderEntryParts {
                conformance: vec![stale],
                ..parts()
            }),
            Err(CatalogError::ConformanceProvenanceMismatch {
                mode: String::from("app-server"),
                field: "binary_digest"
            })
        );
    }

    #[test]
    fn a_conformance_record_disagreeing_about_the_version_refuses() {
        let renamed =
            BinaryProvenance::new("0.146.1", BINARY, Some(SCHEMA)).expect("valid provenance");
        let stale =
            ConformanceRecord::record(renamed, "app-server", ADAPTER, ConformanceOutcome::Passed)
                .expect("valid record");
        assert_eq!(
            ProviderCatalogEntry::register(ProviderEntryParts {
                conformance: vec![stale],
                ..parts()
            }),
            Err(CatalogError::ConformanceProvenanceMismatch {
                mode: String::from("app-server"),
                field: "binary_version"
            })
        );
    }

    #[test]
    fn two_records_for_one_mode_and_adapter_version_refuse() {
        assert_eq!(
            ProviderCatalogEntry::register(ProviderEntryParts {
                conformance: vec![
                    record("app-server", ADAPTER, ConformanceOutcome::Passed),
                    record("app-server", ADAPTER, ConformanceOutcome::Failed),
                ],
                ..parts()
            }),
            Err(CatalogError::DuplicateConformance {
                mode: String::from("app-server"),
                adapter_version: String::from(ADAPTER)
            })
        );
    }

    #[test]
    fn a_record_outside_the_bounded_grammar_refuses() {
        assert_eq!(
            ConformanceRecord::record(provenance(), "", ADAPTER, ConformanceOutcome::Passed),
            Err(CatalogError::Value {
                field: "conformance_mode",
                error: ValueError::Empty
            })
        );
        assert_eq!(
            ConformanceRecord::record(
                provenance(),
                "app-server",
                "0.1\u{7}.0",
                ConformanceOutcome::Passed
            ),
            Err(CatalogError::Value {
                field: "adapter_version",
                error: ValueError::ControlCharacter
            })
        );
        let long = "9".repeat(MAX_CATALOG_FIELD_BYTES + 1);
        assert_eq!(
            ConformanceRecord::record(
                provenance(),
                "app-server",
                &long,
                ConformanceOutcome::Passed
            ),
            Err(CatalogError::Value {
                field: "adapter_version",
                error: ValueError::TooLong {
                    max_bytes: MAX_CATALOG_FIELD_BYTES,
                    actual_bytes: MAX_CATALOG_FIELD_BYTES + 1,
                }
            })
        );
    }

    #[test]
    fn one_provider_kind_cannot_be_registered_twice() {
        assert_eq!(
            ProviderCatalog::register([entry(), entry()]),
            Err(CatalogError::DuplicateProviderKind {
                kind: ProviderKind::Codex
            })
        );
    }

    /// The catalog needs no count ceiling: its key is a closed enum and
    /// duplicates refuse, so its size is bounded by the vocabulary itself.
    #[test]
    fn the_catalog_is_bounded_by_the_provider_vocabulary() {
        let catalog = catalog();
        assert!(catalog.entries().len() <= ProviderKind::ALL.len());
        assert!(ProviderCatalog::register([entry(), entry()]).is_err());
    }

    /// A control plane with nothing registered is a real state, not a refusal.
    #[test]
    fn an_empty_catalog_is_permitted_and_looks_up_nothing() {
        let empty = ProviderCatalog::register(Vec::new()).expect("an empty catalog");
        assert!(empty.entries().is_empty());
        assert_eq!(empty.entry(ProviderKind::Codex), None);
        assert_eq!(empty.lookup(ProviderKind::Codex, "codex-mini"), None);
        assert_eq!(
            empty.admits_model(&ModelRef::new("codex", "codex-mini").expect("valid reference")),
            Err(CatalogError::ProviderAbsent {
                kind: ProviderKind::Codex
            })
        );
        assert_eq!(ProviderCatalog::default(), empty);
    }
}

/// The rules that bind this module to the surfaces it reuses.
mod alignment {
    use super::*;

    /// An entry cannot claim a capability spelling `provider.rs` refuses,
    /// because the only way into an entry is through the real `Capability`
    /// constructor, and it refuses first.
    #[test]
    fn a_capability_spelling_provider_rs_refuses_never_reaches_an_entry() {
        for (name, expected) in [
            ("", ValueError::Empty),
            ("approval\u{7}response", ValueError::ControlCharacter),
        ] {
            assert_eq!(
                Capability::new(CapabilityGroup::Approvals, name),
                Err(expected),
                "capability {name:?} was wrongly accepted"
            );
        }
        let long = "a".repeat(1024);
        assert!(Capability::new(CapabilityGroup::Approvals, &long).is_err());
        assert!(UnknownCapability::new("").is_err());
    }

    /// A mode naming a capability as both mandatory and absent describes a mode
    /// that cannot exist. `ModeDeclaration` refuses it, so no registration can
    /// carry one.
    #[test]
    fn a_mode_that_cannot_exist_refuses_before_registration() {
        let contradiction = ModeDeclaration::new(
            "app-server",
            vec![capability(CapabilityGroup::Sessions, "resume")],
            Vec::new(),
            vec![capability(CapabilityGroup::Sessions, "resume")],
            Vec::new(),
            provenance(),
        );
        assert_eq!(
            contradiction,
            Err(ProviderError::RequiredCapabilityIsDegraded {
                capability: String::from("resume")
            })
        );
    }

    /// A capability vocabulary this build does not define survives
    /// registration and is still never counted present.
    #[test]
    fn an_unknown_capability_is_retained_and_never_offered() {
        let entry = entry();
        let mode = entry.mode("app-server").expect("the declared mode");
        assert_eq!(mode.unknown().len(), 1);
        assert_eq!(mode.unknown()[0].name(), "future_capability");
        assert_eq!(
            mode.state(&capability(CapabilityGroup::Sessions, "future_capability")),
            CapabilityState::Unprobed
        );
        assert_eq!(
            mode.state(&capability(CapabilityGroup::Telemetry, "cost")),
            CapabilityState::Absent
        );
        assert_eq!(
            mode.state(&capability(CapabilityGroup::Turns, "steer")),
            CapabilityState::Present
        );
    }

    /// `BinaryProvenance` spells a digest `sha256:<hex>`; the agents crate's
    /// `ProviderExecutable::pinned` takes bare lowercase hex and refuses
    /// anything else. The bridge produces exactly what that constructor
    /// accepts.
    #[test]
    fn the_pinned_digest_is_offered_in_the_spelling_the_spawn_layer_accepts() {
        let entry = entry();
        let hex = entry.executable_sha256_hex();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        );
        assert_eq!(entry.executable().digest(), format!("sha256:{hex}"));
        assert!(!hex.contains(':'));
    }
}

/// Registration says a provider is known. Only conformance says it may serve.
mod conformance {
    use super::*;

    #[test]
    fn a_declared_conforming_mode_is_admitted_with_its_selection() {
        let entry = entry();
        let admitted = entry
            .admit_native("app-server", ADAPTER)
            .expect("an admitted native adapter");
        assert_eq!(admitted.kind(), ProviderKind::Codex);
        assert_eq!(admitted.mode(), "app-server");
        assert_eq!(admitted.adapter_version(), ADAPTER);
        assert_eq!(admitted.selection().mode(), "app-server");
        assert_eq!(admitted.selection().degraded(), ["cost"]);
    }

    #[test]
    fn an_undeclared_mode_is_never_admitted() {
        assert_eq!(
            entry().admit_native("exec-jsonl", ADAPTER),
            Err(CatalogError::ModeNotRegistered {
                mode: String::from("exec-jsonl")
            })
        );
    }

    /// The capability refusal is `provider.rs`'s, wrapped rather than
    /// re-derived, so a missing approval capability is still a refusal here and
    /// never a downgrade.
    #[test]
    fn a_mode_missing_a_mandatory_capability_is_never_admitted() {
        let unprobed = ModeDeclaration::new(
            "app-server",
            vec![capability(CapabilityGroup::Approvals, "approval_response")],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            provenance(),
        )
        .expect("consistent declaration");
        let entry = ProviderCatalogEntry::register(ProviderEntryParts {
            modes: vec![unprobed],
            ..parts()
        })
        .expect("registerable provider");
        assert_eq!(
            entry.admit_native("app-server", ADAPTER),
            Err(CatalogError::Mode {
                error: ProviderError::RequiredCapabilitiesMissing {
                    missing: vec![String::from("approval_response")]
                }
            })
        );
    }

    /// "A binary digest without a passing record cannot become the production
    /// native adapter automatically."
    #[test]
    fn a_registered_provider_without_a_record_is_not_a_native_adapter() {
        let entry = ProviderCatalogEntry::register(ProviderEntryParts {
            conformance: Vec::new(),
            ..parts()
        })
        .expect("registerable provider");
        assert_eq!(entry.conformance().len(), 0);
        assert_eq!(
            entry.admit_native("app-server", ADAPTER),
            Err(CatalogError::NotConformant {
                mode: String::from("app-server"),
                adapter_version: String::from(ADAPTER)
            })
        );
    }

    #[test]
    fn a_record_for_another_adapter_version_does_not_carry_over() {
        assert_eq!(
            entry().admit_native("app-server", "0.2.0"),
            Err(CatalogError::NotConformant {
                mode: String::from("app-server"),
                adapter_version: String::from("0.2.0")
            })
        );
    }

    #[test]
    fn a_failed_record_refuses_rather_than_being_absent() {
        let entry = ProviderCatalogEntry::register(ProviderEntryParts {
            conformance: vec![record("app-server", ADAPTER, ConformanceOutcome::Failed)],
            ..parts()
        })
        .expect("registerable provider");
        assert_eq!(
            entry.admit_native("app-server", ADAPTER),
            Err(CatalogError::ConformanceFailed {
                mode: String::from("app-server"),
                adapter_version: String::from(ADAPTER)
            })
        );
    }

    #[test]
    fn an_adapter_version_outside_the_grammar_refuses() {
        assert_eq!(
            entry().admit_native("app-server", ""),
            Err(CatalogError::Value {
                field: "adapter_version",
                error: ValueError::Empty
            })
        );
    }

    #[test]
    fn the_outcome_vocabulary_is_closed_and_stably_spelled() {
        assert_eq!(ConformanceOutcome::ALL.len(), 2);
        assert_eq!(ConformanceOutcome::Passed.as_str(), "passed");
        assert_eq!(ConformanceOutcome::Failed.as_str(), "failed");
    }
}

/// Exact lookup, and typed refusals for everything else.
mod lookup {
    use super::*;

    #[test]
    fn a_registered_model_is_found_by_kind_and_exact_identifier() {
        let catalog = catalog();
        let found = catalog
            .lookup(ProviderKind::Codex, "codex-mini")
            .expect("the offered model");
        assert_eq!(found.model().to_string(), "codex/codex-mini");
        assert_eq!(found.context_limit_tokens(), 400_000);
        assert_eq!(found.region(), "us-east-1");
    }

    #[test]
    fn an_unoffered_model_is_a_typed_none() {
        let catalog = catalog();
        assert_eq!(catalog.lookup(ProviderKind::Codex, "codex-maxi"), None);
        assert_eq!(
            catalog.lookup(ProviderKind::Codex, "codex/codex-mini"),
            None
        );
        assert_eq!(catalog.lookup(ProviderKind::Codex, ""), None);
        assert_eq!(
            catalog
                .entry(ProviderKind::Codex)
                .expect("the registered entry")
                .mode("exec-jsonl"),
            None
        );
    }

    /// The seam from `models.rs`'s free-text provider field — an alias target,
    /// a routing candidate — to the closed vocabulary.
    #[test]
    fn a_model_reference_resolves_through_the_registry() {
        let catalog = catalog();
        let target = ModelRef::new("codex", "codex-mini").expect("valid reference");
        assert_eq!(
            catalog.admits_model(&target).expect("an offered model"),
            catalog
                .lookup(ProviderKind::Codex, "codex-mini")
                .expect("the same model")
        );
    }

    #[test]
    fn a_reference_naming_a_planned_provider_refuses_by_name() {
        let catalog = catalog();
        let planned = ModelRef::new("claude", "opus").expect("valid reference");
        assert_eq!(
            catalog.admits_model(&planned),
            Err(CatalogError::PlannedProviderKind {
                name: String::from("claude")
            })
        );
        let unknown = ModelRef::new("acme-llm", "acme-1").expect("valid reference");
        assert_eq!(
            catalog.admits_model(&unknown),
            Err(CatalogError::UnknownProviderKind {
                name: String::from("acme-llm")
            })
        );
    }

    #[test]
    fn a_reference_to_an_unoffered_model_of_a_registered_provider_refuses() {
        let catalog = catalog();
        let absent = ModelRef::new("codex", "codex-maxi").expect("valid reference");
        assert_eq!(
            catalog.admits_model(&absent),
            Err(CatalogError::ModelNotOffered {
                model: String::from("codex/codex-maxi")
            })
        );
    }
}

/// The rendered inventory a later doctor or status surface reads.
mod inventory {
    use super::*;

    fn wide_entry() -> ProviderCatalogEntry {
        ProviderCatalogEntry::register(ProviderEntryParts {
            modes: vec![app_server(), named_mode("exec-jsonl")],
            models: vec![
                model_named("codex", "codex-mini"),
                model_named("codex", "codex-max"),
            ],
            conformance: vec![
                record("app-server", "0.2.0", ConformanceOutcome::Passed),
                record("app-server", ADAPTER, ConformanceOutcome::Failed),
                record("exec-jsonl", ADAPTER, ConformanceOutcome::Passed),
            ],
            ..parts()
        })
        .expect("registerable provider")
    }

    #[test]
    fn the_rendering_is_exactly_this_text() {
        let catalog = ProviderCatalog::register([wide_entry()]).expect("assembled catalog");
        let expected = format!(
            "automonique.provider-catalog/v1\n\
             provider codex version=0.146.0 binary={BINARY} schema={SCHEMA} \
             dialect=automonique_runner_v1\n\
             mode codex app-server required=2 degraded=1 unknown=1\n\
             mode codex exec-jsonl required=0 degraded=0 unknown=0\n\
             conformance codex app-server adapter=0.1.0 outcome=failed\n\
             conformance codex app-server adapter=0.2.0 outcome=passed\n\
             conformance codex exec-jsonl adapter=0.1.0 outcome=passed\n\
             model codex/codex-max modalities=text,image context=400000 output=128000 \
             region=us-east-1 zone=us\n\
             model codex/codex-mini modalities=text,image context=400000 output=128000 \
             region=us-east-1 zone=us\n"
        );
        assert_eq!(catalog.manifest(), expected);
    }

    #[test]
    fn the_header_names_the_versioned_schema() {
        assert_eq!(
            catalog().manifest().lines().next(),
            Some(PROVIDER_CATALOG_SCHEMA_V1)
        );
    }

    #[test]
    fn an_empty_catalog_renders_the_header_and_nothing_else() {
        let empty = ProviderCatalog::register(Vec::new()).expect("an empty catalog");
        assert_eq!(empty.manifest(), format!("{PROVIDER_CATALOG_SCHEMA_V1}\n"));
    }

    /// Reordering declarations changes nothing about what is registered, so it
    /// must change nothing about the rendering.
    #[test]
    fn reordering_declarations_does_not_change_the_rendering() {
        let forward = ProviderCatalog::register([wide_entry()]).expect("assembled catalog");
        let reversed = ProviderCatalogEntry::register(ProviderEntryParts {
            modes: vec![named_mode("exec-jsonl"), app_server()],
            models: vec![
                model_named("codex", "codex-max"),
                model_named("codex", "codex-mini"),
            ],
            conformance: vec![
                record("exec-jsonl", ADAPTER, ConformanceOutcome::Passed),
                record("app-server", ADAPTER, ConformanceOutcome::Failed),
                record("app-server", "0.2.0", ConformanceOutcome::Passed),
            ],
            ..parts()
        })
        .expect("registerable provider");
        let reversed = ProviderCatalog::register([reversed]).expect("assembled catalog");
        assert_eq!(forward.manifest(), reversed.manifest());
    }

    /// Modalities render in `Modality::ALL` order, so a declaration listing
    /// them differently renders identically.
    #[test]
    fn modality_declaration_order_does_not_change_the_rendering() {
        let one = ModelCatalogEntry::declare(CatalogEntryParts {
            model: ModelRef::new("codex", "codex-mini").expect("valid reference"),
            display_name: "codex-mini",
            modalities: &[Modality::Text, Modality::Image],
            context_limit_tokens: 400_000,
            max_output_tokens: 128_000,
            reasoning: ReasoningControl::CallerSelectedEffort,
            tools: ToolSupport::Parallel,
            structured_output: StructuredOutputSupport::SchemaConstrained,
            region: "us-east-1",
            sovereignty_zone: "us",
            data_policy: DataPolicy::new(
                TrainingUse::Prohibited,
                PromptRetention::NoneRetained,
                "us-commercial",
            )
            .expect("valid data policy"),
            pricing: Pricing::new("usd", PricingUnit::MillionTokens, 1_250_000, 10_000_000)
                .expect("valid pricing"),
            auth: AuthMethod::SubscriptionSession,
        })
        .expect("complete catalog entry");
        // `codex_model` declares the same two modalities image-first.
        let declared_image_first = ProviderCatalog::register([entry()]).expect("assembled catalog");
        let declared_text_first =
            ProviderCatalog::register([ProviderCatalogEntry::register(ProviderEntryParts {
                models: vec![one],
                ..parts()
            })
            .expect("registerable provider")])
            .expect("assembled catalog");
        assert_eq!(
            declared_image_first.manifest(),
            declared_text_first.manifest()
        );
        assert!(
            declared_image_first
                .manifest()
                .contains("modalities=text,image")
        );
    }

    #[test]
    fn the_rendering_is_stable_across_repeated_calls() {
        let assembled = catalog();
        assert_eq!(assembled.manifest(), assembled.manifest());
        assert_eq!(assembled.manifest(), catalog().manifest());
    }
}

/// What the catalog does not do, measured rather than asserted in prose.
mod honesty {
    use super::*;

    /// Registration reads nothing. The digests below name no file that exists,
    /// and the entry is accepted anyway — because verifying them is some other
    /// layer's job, and this module would be lying if it implied otherwise.
    #[test]
    fn registration_verifies_no_digest_and_touches_no_file() {
        let fictional = BinaryProvenance::new(
            "99.99.99",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            Some("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        )
        .expect("valid provenance");
        let entry = ProviderCatalogEntry::register(ProviderEntryParts {
            executable: fictional.clone(),
            modes: vec![
                ModeDeclaration::new(
                    "app-server",
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    fictional.clone(),
                )
                .expect("consistent declaration"),
            ],
            conformance: vec![
                ConformanceRecord::record(
                    fictional,
                    "app-server",
                    ADAPTER,
                    ConformanceOutcome::Passed,
                )
                .expect("valid record"),
            ],
            ..parts()
        })
        .expect("registerable provider");
        assert!(entry.admit_native("app-server", ADAPTER).is_ok());
    }

    /// An admission is data: reproducible from the same values, comparable, and
    /// carrying no handle to anything. Two independently derived admissions of
    /// the same registration are equal, which a capability token would not be.
    #[test]
    fn an_admission_is_a_description_and_not_a_handle() {
        let first = entry()
            .admit_native("app-server", ADAPTER)
            .expect("an admitted adapter");
        let second = entry()
            .admit_native("app-server", ADAPTER)
            .expect("an admitted adapter");
        assert_eq!(first, second);
        assert_eq!(first.clone(), first);
    }

    /// The three providers the plan names and this build cannot serve stay
    /// unregisterable. A later slice that adds one must add its argv contract
    /// and event vocabulary, which is what makes this assertion fail.
    #[test]
    fn no_planned_provider_became_registerable_by_accident() {
        assert_eq!(ProviderKind::ALL.len(), 1);
        for planned in PLANNED_PROVIDER_KINDS {
            assert!(
                ProviderKind::resolve(planned).is_err(),
                "{planned} became registerable without its adapter"
            );
        }
    }
}
