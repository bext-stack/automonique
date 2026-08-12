// SPDX-License-Identifier: Elastic-2.0

use automonique_protocol::sandbox::{BudgetQuantities, BudgetUnit, Budgets};
use automonique_runner::{
    MAX_ARG_BYTES, MAX_ARG_COUNT, MAX_ENV_COUNT, MAX_FIELD_BYTES, MAX_RESERVATION_BYTES,
    MAX_TOTAL_ARG_BYTES, MAX_TOTAL_ENV_BYTES, PromptDeliveryPlan, RunSpec, RunSpecDecodeError,
};

const GOLDEN: &[u8] = include_bytes!("fixtures/run_spec_v1_full.cjson");

fn replace_once(from: &str, to: &str) -> Vec<u8> {
    let source = std::str::from_utf8(GOLDEN).unwrap();
    assert_eq!(
        source.matches(from).count(),
        1,
        "mutation must be unique: {from}"
    );
    source.replacen(from, to, 1).into_bytes()
}

fn accepted(bytes: &[u8]) -> RunSpec {
    let spec = RunSpec::from_canonical_bytes(bytes).unwrap();
    assert_eq!(spec.to_canonical_bytes().unwrap(), bytes);
    spec
}

fn refused(bytes: &[u8], expected: RunSpecDecodeError) {
    assert_eq!(RunSpec::from_canonical_bytes(bytes).unwrap_err(), expected);
}

fn hex(byte: &str, bytes: usize) -> String {
    byte.repeat(bytes)
}

fn json_hex_array(items: impl IntoIterator<Item = String>) -> String {
    items
        .into_iter()
        .map(|item| format!("\"{item}\""))
        .collect::<Vec<_>>()
        .join(",")
}

#[test]
fn argument_item_count_and_aggregate_accept_exact_and_refuse_one_over() {
    let original = "\"argv_hex\":[\"61ff\",\"7365636f6e64\"]";

    let exact_item = replace_once(
        original,
        &format!("\"argv_hex\":[\"{}\"]", hex("61", MAX_ARG_BYTES)),
    );
    assert_eq!(accepted(&exact_item).arguments()[0].len(), MAX_ARG_BYTES);
    let over_item = replace_once(
        original,
        &format!("\"argv_hex\":[\"{}\"]", hex("61", MAX_ARG_BYTES + 1)),
    );
    refused(&over_item, RunSpecDecodeError::Field("argv_hex"));

    let exact_count = replace_once(
        original,
        &format!(
            "\"argv_hex\":[{}]",
            json_hex_array((0..MAX_ARG_COUNT).map(|_| "61".to_owned()))
        ),
    );
    assert_eq!(accepted(&exact_count).arguments().len(), MAX_ARG_COUNT);
    let over_count = replace_once(
        original,
        &format!(
            "\"argv_hex\":[{}]",
            json_hex_array((0..=MAX_ARG_COUNT).map(|_| "61".to_owned()))
        ),
    );
    refused(&over_count, RunSpecDecodeError::Field("argv_hex"));

    let full_items = MAX_TOTAL_ARG_BYTES / MAX_ARG_BYTES;
    let exact_aggregate = replace_once(
        original,
        &format!(
            "\"argv_hex\":[{}]",
            json_hex_array((0..full_items).map(|_| hex("61", MAX_ARG_BYTES)))
        ),
    );
    assert_eq!(
        accepted(&exact_aggregate)
            .arguments()
            .iter()
            .map(|item| item.len())
            .sum::<usize>(),
        MAX_TOTAL_ARG_BYTES
    );
    let over_aggregate = replace_once(
        original,
        &format!(
            "\"argv_hex\":[{},\"61\"]",
            json_hex_array((0..full_items).map(|_| hex("61", MAX_ARG_BYTES)))
        ),
    );
    refused(&over_aggregate, RunSpecDecodeError::Field("argv_hex"));
}

fn environment(entries: impl IntoIterator<Item = (String, String)>) -> String {
    entries
        .into_iter()
        .map(|(key, value)| format!("{{\"key_hex\":\"{key}\",\"value_hex\":\"{value}\"}}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn ascii_hex(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn environment_key_value_count_and_aggregate_accept_exact_and_refuse_one_over() {
    let original = "\"environment_hex\":[{\"key_hex\":\"414c504841\",\"value_hex\":\"ff78\"},{\"key_hex\":\"42455441\",\"value_hex\":\"76616c7565\"}]";

    let exact_key_text = format!("A{}", "1".repeat(MAX_FIELD_BYTES - 1));
    let exact_key = replace_once(
        original,
        &format!(
            "\"environment_hex\":[{}]",
            environment([(hex("41", exact_key_text.len()), "61".to_owned())])
        ),
    );
    assert_eq!(
        accepted(&exact_key).environment()[0].0.len(),
        MAX_FIELD_BYTES
    );
    let over_key = replace_once(
        original,
        &format!(
            "\"environment_hex\":[{}]",
            environment([(hex("41", MAX_FIELD_BYTES + 1), "61".to_owned())])
        ),
    );
    refused(&over_key, RunSpecDecodeError::Field("key_hex"));

    let exact_value = replace_once(
        original,
        &format!(
            "\"environment_hex\":[{}]",
            environment([("41".to_owned(), hex("61", MAX_ARG_BYTES))])
        ),
    );
    assert_eq!(
        accepted(&exact_value).environment()[0].1.len(),
        MAX_ARG_BYTES
    );
    let over_value = replace_once(
        original,
        &format!(
            "\"environment_hex\":[{}]",
            environment([("41".to_owned(), hex("61", MAX_ARG_BYTES + 1))])
        ),
    );
    refused(&over_value, RunSpecDecodeError::Field("value_hex"));

    let entries = |count: usize| {
        (0..count)
            .map(|index| (ascii_hex(&format!("K{index}")), "61".to_owned()))
            .collect::<Vec<_>>()
    };
    let exact_count = replace_once(
        original,
        &format!(
            "\"environment_hex\":[{}]",
            environment(entries(MAX_ENV_COUNT))
        ),
    );
    assert_eq!(accepted(&exact_count).environment().len(), MAX_ENV_COUNT);
    let over_count = replace_once(
        original,
        &format!(
            "\"environment_hex\":[{}]",
            environment(entries(MAX_ENV_COUNT + 1))
        ),
    );
    refused(&over_count, RunSpecDecodeError::Field("environment_hex"));

    let aggregate_entries = |over: bool| {
        (0..16)
            .map(|index| {
                let value_bytes = if over && index == 0 {
                    MAX_ARG_BYTES
                } else {
                    MAX_ARG_BYTES - 1
                };
                (
                    format!("{:02x}", b'A' + u8::try_from(index).unwrap()),
                    hex("61", value_bytes),
                )
            })
            .collect::<Vec<_>>()
    };
    let exact_aggregate = replace_once(
        original,
        &format!(
            "\"environment_hex\":[{}]",
            environment(aggregate_entries(false))
        ),
    );
    assert_eq!(
        accepted(&exact_aggregate)
            .environment()
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum::<usize>(),
        MAX_TOTAL_ENV_BYTES
    );
    let over_aggregate = replace_once(
        original,
        &format!(
            "\"environment_hex\":[{}]",
            environment(aggregate_entries(true))
        ),
    );
    refused(
        &over_aggregate,
        RunSpecDecodeError::Field("environment_hex"),
    );
}

#[test]
fn protected_reference_timeout_and_reservations_enforce_exact_boundaries() {
    let original_prompt = "\"prompt_delivery\":{\"backend_session\":\"session-1\",\"mode\":\"backend_session\",\"protected_reference\":null}";
    let prompt = |bytes: usize| {
        format!(
            "\"prompt_delivery\":{{\"backend_session\":null,\"mode\":\"protected_reference\",\"protected_reference\":\"{}\"}}",
            "p".repeat(bytes)
        )
    };
    let exact_reference = replace_once(original_prompt, &prompt(MAX_FIELD_BYTES));
    assert!(matches!(
        accepted(&exact_reference).prompt_delivery(),
        PromptDeliveryPlan::ProtectedReference(_)
    ));
    let over_reference = replace_once(original_prompt, &prompt(MAX_FIELD_BYTES + 1));
    refused(
        &over_reference,
        RunSpecDecodeError::Domain("protected_reference"),
    );

    let timeout = |value: u64| {
        replace_once(
            "\"timeout_millis\":\"10000\"",
            &format!("\"timeout_millis\":\"{value}\""),
        )
    };
    refused(&timeout(0), RunSpecDecodeError::Domain("run_spec"));
    assert_eq!(
        accepted(&timeout(24 * 60 * 60 * 1_000))
            .timeout()
            .as_millis(),
        24 * 60 * 60 * 1_000
    );
    refused(
        &timeout(24 * 60 * 60 * 1_000 + 1),
        RunSpecDecodeError::Domain("budgets"),
    );

    let read = |value: u64| {
        replace_once(
            "\"read_bytes\":\"2048\"",
            &format!("\"read_bytes\":\"{value}\""),
        )
    };
    assert_eq!(
        accepted(&read(MAX_RESERVATION_BYTES))
            .admission()
            .io_reservation()
            .read_bytes(),
        MAX_RESERVATION_BYTES
    );
    refused(
        &read(MAX_RESERVATION_BYTES + 1),
        RunSpecDecodeError::Domain("io_reservation"),
    );
    let write = |value: u64| {
        replace_once(
            "\"write_bytes\":\"4096\"",
            &format!("\"write_bytes\":\"{value}\""),
        )
    };
    assert_eq!(
        accepted(&write(MAX_RESERVATION_BYTES))
            .admission()
            .io_reservation()
            .write_bytes(),
        MAX_RESERVATION_BYTES
    );
    refused(
        &write(MAX_RESERVATION_BYTES + 1),
        RunSpecDecodeError::Domain("io_reservation"),
    );
    let workspace = |value: u64| {
        replace_once(
            "\"workspace_reservation\":\"8192\"",
            &format!("\"workspace_reservation\":\"{value}\""),
        )
    };
    assert_eq!(
        accepted(&workspace(MAX_RESERVATION_BYTES))
            .admission()
            .workspace_reservation()
            .bytes(),
        MAX_RESERVATION_BYTES
    );
    refused(
        &workspace(MAX_RESERVATION_BYTES + 1),
        RunSpecDecodeError::Domain("workspace_reservation"),
    );
}

#[derive(Clone, Copy)]
struct BudgetAxis {
    key: &'static str,
    fixture_value: u64,
    unit: BudgetUnit,
}

const BUDGET_AXES: [BudgetAxis; 8] = [
    BudgetAxis {
        key: "artifact_bytes",
        fixture_value: 4_194_304,
        unit: BudgetUnit::ArtifactBytes,
    },
    BudgetAxis {
        key: "cgroup_cpu_millicores",
        fixture_value: 2_000,
        unit: BudgetUnit::CpuMillicores,
    },
    BudgetAxis {
        key: "cgroup_memory_bytes",
        fixture_value: 268_435_456,
        unit: BudgetUnit::MemoryBytes,
    },
    BudgetAxis {
        key: "rlimit_descriptors",
        fixture_value: 512,
        unit: BudgetUnit::FileDescriptors,
    },
    BudgetAxis {
        key: "rlimit_processes",
        fixture_value: 128,
        unit: BudgetUnit::Processes,
    },
    BudgetAxis {
        key: "spool_bytes",
        fixture_value: 2_097_152,
        unit: BudgetUnit::SpoolBytes,
    },
    BudgetAxis {
        key: "temporary_storage_bytes",
        fixture_value: 2_097_152,
        unit: BudgetUnit::TempBytes,
    },
    BudgetAxis {
        key: "timeout_millis",
        fixture_value: 10_000,
        unit: BudgetUnit::Milliseconds,
    },
];

fn quantities_with(axis: BudgetUnit, quantity: u64) -> BudgetQuantities {
    let mut quantities = BudgetQuantities {
        cgroup_memory_bytes: 1,
        cgroup_cpu_millicores: 1,
        rlimit_processes: 1,
        rlimit_descriptors: 1,
        timeout_millis: 1,
        temporary_storage_bytes: 1,
        spool_bytes: 1,
        artifact_bytes: 1,
    };
    match axis {
        BudgetUnit::Milliseconds => quantities.timeout_millis = quantity,
        BudgetUnit::MemoryBytes => quantities.cgroup_memory_bytes = quantity,
        BudgetUnit::CpuMillicores => quantities.cgroup_cpu_millicores = quantity,
        BudgetUnit::Processes => quantities.rlimit_processes = quantity,
        BudgetUnit::FileDescriptors => quantities.rlimit_descriptors = quantity,
        BudgetUnit::TempBytes => quantities.temporary_storage_bytes = quantity,
        BudgetUnit::SpoolBytes => quantities.spool_bytes = quantity,
        BudgetUnit::ArtifactBytes => quantities.artifact_bytes = quantity,
    }
    quantities
}

fn budget_mutation(axis: BudgetAxis, quantity: u64) -> Vec<u8> {
    replace_once(
        &format!("\"{}\":\"{}\"", axis.key, axis.fixture_value),
        &format!("\"{}\":\"{quantity}\"", axis.key),
    )
}

#[test]
fn every_nested_budget_axis_maps_to_its_typed_ceiling_and_refuses_one_over() {
    assert_eq!(BudgetUnit::ALL.len(), BUDGET_AXES.len());
    for unit in BudgetUnit::ALL {
        assert_eq!(
            BUDGET_AXES.iter().filter(|axis| axis.unit == unit).count(),
            1,
            "unit {} must map to exactly one wire key",
            unit.as_str()
        );
    }

    for axis in BUDGET_AXES {
        let ceiling = axis.unit.ceiling();
        let budgets = Budgets::declare(quantities_with(axis.unit, ceiling))
            .expect("the exact protocol ceiling is representable");
        let declared = budgets
            .all()
            .into_iter()
            .find(|budget| budget.unit() == axis.unit)
            .expect("every named axis is present");
        assert_eq!(declared.quantity(), ceiling, "axis {}", axis.key);

        let error = Budgets::declare(quantities_with(axis.unit, ceiling + 1))
            .expect_err("one over a protocol ceiling must refuse");
        assert_eq!(error.category(), "budget_out_of_range", "axis {}", axis.key);
        assert!(
            error.to_string().contains(axis.unit.as_str()),
            "axis {}",
            axis.key
        );

        let over = budget_mutation(axis, ceiling + 1);
        refused(&over, RunSpecDecodeError::Domain("budgets"));

        let exact = budget_mutation(axis, ceiling);
        if axis.unit == BudgetUnit::SpoolBytes {
            refused(&exact, RunSpecDecodeError::Domain("run_spec"));
        } else {
            let spec = accepted(&exact);
            let decoded = spec
                .sandbox()
                .budgets()
                .all()
                .into_iter()
                .find(|budget| budget.unit() == axis.unit)
                .expect("decoded spec preserves every budget axis");
            assert_eq!(decoded.quantity(), ceiling, "axis {}", axis.key);
        }
    }

    let runner_spool_max = 1024 * 1024 * 1024;
    assert_eq!(
        accepted(&budget_mutation(BUDGET_AXES[5], runner_spool_max)).spool_budget_bytes(),
        runner_spool_max
    );
    refused(
        &budget_mutation(BUDGET_AXES[5], runner_spool_max + 1),
        RunSpecDecodeError::Domain("run_spec"),
    );
}
