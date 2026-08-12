// SPDX-License-Identifier: Elastic-2.0

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
