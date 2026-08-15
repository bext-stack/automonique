// SPDX-License-Identifier: Elastic-2.0

//! Audit record encoding, hashing and chain verification.
//!
//! Every refusal here is asserted by stable category or by the exact
//! [`ChainFault`], never by message text, so a mutation that reaches a
//! different guard fails the test instead of passing through a neighbouring
//! one. That matters more here than elsewhere: the faults are the whole
//! product of a verifier, and one reported as another is a wrong answer, not a
//! cosmetic difference.
//!
//! The canonicalization tests state their scope in their own names. This crate
//! does not implement RFC 8785 and no test here claims it does; what they prove
//! is the narrower and checkable claim the module documents — that over ASCII
//! keys, integers below 2^53 and strings, this encoder's bytes are what a JCS
//! encoder produces.

use automonique_protocol::audit::{
    AUDIT_RECORD_SCHEMA_V1, AuditCategory, AuditError, AuditEvent, AuditLink, AuditOutcome,
    AuditRecord, CANONICALIZATION_PROFILE, ChainFault, GENESIS_PREV_HASH, HASH_HEX_BYTES,
    MAX_AUDIT_FIELD_BYTES, MAX_AUDIT_SEQ, RECORD_ID_BYTES, RECORD_ID_PREFIX, derive_record_id,
    is_chain_hash, verify_chain,
};
use automonique_protocol::wire::JsonValue;

fn event() -> AuditEvent<'static> {
    AuditEvent {
        recorded_at: "2026-08-15T12:00:00Z",
        actor: "operator:ada",
        surface: "admin.socket",
        category: AuditCategory::Approval,
        subject: "run:alpha",
        outcome: AuditOutcome::Success,
    }
}

/// One record built at `seq` after `prev_hash`, with a distinguishable subject.
fn record(seq: u64, prev_hash: &str, subject: &str) -> AuditRecord {
    AuditRecord::link(seq, prev_hash, AuditEvent { subject, ..event() }).expect("record")
}

/// A chain of `count` records, each linked to the one before it.
fn chain(count: u64) -> Vec<AuditRecord> {
    let mut records = Vec::new();
    let mut prev = GENESIS_PREV_HASH.to_owned();
    for seq in 1..=count {
        let built = record(seq, &prev, &format!("run:{seq}"));
        prev = built.record_hash();
        records.push(built);
    }
    records
}

/// The stored columns each record would occupy.
fn stored(records: &[AuditRecord]) -> Vec<(u64, String, Vec<u8>, String, String)> {
    records
        .iter()
        .map(|record| {
            (
                record.seq(),
                record.record_id(),
                record.to_canonical_bytes(),
                record.prev_hash().to_owned(),
                record.record_hash(),
            )
        })
        .collect()
}

fn links(rows: &[(u64, String, Vec<u8>, String, String)]) -> Vec<AuditLink<'_>> {
    rows.iter()
        .map(|(seq, record_id, body, prev_hash, record_hash)| AuditLink {
            seq: *seq,
            record_id,
            body,
            prev_hash,
            record_hash,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The record and its identity
// ---------------------------------------------------------------------------

#[test]
fn a_genesis_record_links_to_sixty_four_zeros() {
    assert_eq!(GENESIS_PREV_HASH.len(), HASH_HEX_BYTES);
    assert!(GENESIS_PREV_HASH.bytes().all(|byte| byte == b'0'));
    assert!(is_chain_hash(GENESIS_PREV_HASH));

    let genesis = record(1, GENESIS_PREV_HASH, "run:alpha");
    assert_eq!(genesis.prev_hash(), GENESIS_PREV_HASH);
    assert!(is_chain_hash(&genesis.record_hash()));
}

#[test]
fn the_same_logical_record_hashes_the_same_twice() {
    // Guards against a map iteration order, a clock, or any other ambient
    // input sneaking into the encoding. A chain whose hashes depended on one
    // would verify in the process that wrote it and nowhere else.
    let first = record(7, GENESIS_PREV_HASH, "run:alpha");
    let second = record(7, GENESIS_PREV_HASH, "run:alpha");
    assert_eq!(first.to_canonical_bytes(), second.to_canonical_bytes());
    assert_eq!(first.record_hash(), second.record_hash());
    assert_eq!(first.record_id(), second.record_id());
}

#[test]
fn the_hash_covers_the_link_and_the_position_not_only_the_content() {
    // The whole reason `prev_hash` and `seq` are inside the body: two records
    // with identical content at different places in a chain are different
    // records, and a rewrite of history has to redo every one that follows.
    let base = record(1, GENESIS_PREV_HASH, "run:alpha");
    let moved = record(2, GENESIS_PREV_HASH, "run:alpha");
    let relinked = record(1, &base.record_hash(), "run:alpha");
    assert_ne!(base.record_hash(), moved.record_hash());
    assert_ne!(base.record_hash(), relinked.record_hash());
}

#[test]
fn the_record_id_is_derived_from_the_record_hash_and_is_not_a_prefix_of_it() {
    let built = record(1, GENESIS_PREV_HASH, "run:alpha");
    let hash = built.record_hash();
    let identifier = built.record_id();

    assert_eq!(identifier, derive_record_id(&hash));
    assert_eq!(identifier.len(), RECORD_ID_BYTES);
    assert!(identifier.starts_with(RECORD_ID_PREFIX));

    // Domain separation is the point: a reader holding one value must not be
    // able to mistake it for the other, so the identifier's digits are not the
    // hash's digits.
    let digits = &identifier[RECORD_ID_PREFIX.len()..];
    assert!(!hash.starts_with(digits), "{identifier} shadows {hash}");
    assert!(digits.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(digits.bytes().all(|byte| !byte.is_ascii_uppercase()));
}

#[test]
fn distinct_records_get_distinct_identifiers() {
    let mut seen = std::collections::BTreeSet::new();
    for record in chain(64) {
        assert!(
            seen.insert(record.record_id()),
            "two records shared an identifier"
        );
    }
    assert_eq!(seen.len(), 64);
}

#[test]
fn the_body_carries_its_schema_and_exactly_nine_keys() {
    let built = record(1, GENESIS_PREV_HASH, "run:alpha");
    let parsed = automonique_protocol::wire::parse_canonical(&built.to_canonical_bytes())
        .expect("the encoder writes canonical JSON");
    let JsonValue::Object(entries) = &parsed else {
        panic!("an audit body is an object")
    };
    let mut keys: Vec<&str> = entries.iter().map(|(key, _)| key.as_str()).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "actor",
            "category",
            "outcome",
            "prev_hash",
            "recorded_at",
            "schema",
            "seq",
            "subject",
            "surface"
        ]
    );
    assert_eq!(
        parsed.get("schema").and_then(JsonValue::as_str),
        Some(AUDIT_RECORD_SCHEMA_V1)
    );
    assert_eq!(parsed.get("seq").and_then(JsonValue::as_integer), Some(1));
}

// ---------------------------------------------------------------------------
// Field admission
// ---------------------------------------------------------------------------

#[test]
fn a_seq_of_zero_or_past_the_ceiling_is_refused() {
    for seq in [0, MAX_AUDIT_SEQ + 1, u64::MAX] {
        let refusal = AuditRecord::link(seq, GENESIS_PREV_HASH, event()).expect_err("seq refusal");
        assert_eq!(refusal, AuditError::SeqOutOfRange);
        assert_eq!(refusal.category(), "audit_seq_out_of_range");
    }
    assert!(AuditRecord::link(MAX_AUDIT_SEQ, GENESIS_PREV_HASH, event()).is_ok());
}

#[test]
fn a_prev_hash_that_is_not_sixty_four_lowercase_hex_digits_is_refused() {
    let uppercase = GENESIS_PREV_HASH.replace('0', "A");
    for candidate in [
        "",
        "abc",
        uppercase.as_str(),
        &GENESIS_PREV_HASH[..63],
        &format!("{GENESIS_PREV_HASH}0"),
        &"g".repeat(HASH_HEX_BYTES),
    ] {
        assert!(!is_chain_hash(candidate), "{candidate} is not a chain hash");
        let refusal = AuditRecord::link(1, candidate, event()).expect_err("hash refusal");
        assert_eq!(refusal, AuditError::InvalidHash("prev_hash"));
        assert_eq!(refusal.category(), "audit_invalid_hash");
    }
}

#[test]
fn an_empty_over_long_or_control_bearing_field_is_refused_by_name() {
    let long = "x".repeat(MAX_AUDIT_FIELD_BYTES + 1);
    let cases: [(&str, AuditEvent<'_>); 4] = [
        (
            "recorded_at",
            AuditEvent {
                recorded_at: "",
                ..event()
            },
        ),
        (
            "actor",
            AuditEvent {
                actor: long.as_str(),
                ..event()
            },
        ),
        (
            "surface",
            AuditEvent {
                surface: "admin\u{7}socket",
                ..event()
            },
        ),
        (
            "subject",
            AuditEvent {
                subject: "",
                ..event()
            },
        ),
    ];
    for (field, candidate) in cases {
        let refusal =
            AuditRecord::link(1, GENESIS_PREV_HASH, candidate).expect_err("field refusal");
        assert_eq!(refusal, AuditError::InvalidField(field));
        assert_eq!(refusal.category(), "audit_invalid_field");
    }
    // The boundary itself is admitted, so the ceiling is a ceiling and not an
    // off-by-one.
    assert!(
        AuditRecord::link(
            1,
            GENESIS_PREV_HASH,
            AuditEvent {
                actor: &"x".repeat(MAX_AUDIT_FIELD_BYTES),
                ..event()
            }
        )
        .is_ok()
    );
}

// ---------------------------------------------------------------------------
// The closed vocabularies
// ---------------------------------------------------------------------------

#[test]
fn every_category_and_outcome_round_trips_its_exact_spelling() {
    assert_eq!(AuditCategory::ALL.len(), 6);
    for category in AuditCategory::ALL {
        assert_eq!(
            AuditCategory::from_spelling(category.as_str()),
            Some(category)
        );
        assert_eq!(category.to_string(), category.as_str());
    }
    assert_eq!(AuditOutcome::ALL.len(), 5);
    for outcome in AuditOutcome::ALL {
        assert_eq!(AuditOutcome::from_spelling(outcome.as_str()), Some(outcome));
        assert_eq!(outcome.to_string(), outcome.as_str());
    }
}

#[test]
fn an_unknown_spelling_is_refused_rather_than_folded_into_a_neighbour() {
    for candidate in ["", "APPROVAL", "approvals", "approve", "maybe"] {
        assert_eq!(AuditCategory::from_spelling(candidate), None);
    }
    for candidate in ["", "SUCCESS", "ok", "succeeded", "refused"] {
        assert_eq!(AuditOutcome::from_spelling(candidate), None);
    }
}

#[test]
fn the_five_outcome_spellings_are_exactly_the_ones_the_store_column_admits() {
    // The store's CHECK constraint duplicates this vocabulary by literal,
    // because that crate's library modules take no protocol dependency. This
    // assertion is the seam between the two spellings.
    let spellings: Vec<&str> = AuditOutcome::ALL
        .into_iter()
        .map(AuditOutcome::as_str)
        .collect();
    assert_eq!(
        spellings,
        ["success", "failure", "timeout", "denied", "escalated"]
    );
    let categories: Vec<&str> = AuditCategory::ALL
        .into_iter()
        .map(AuditCategory::as_str)
        .collect();
    assert_eq!(
        categories,
        [
            "approval",
            "action",
            "override",
            "cancellation",
            "policy",
            "escalation"
        ]
    );
}

// ---------------------------------------------------------------------------
// Canonicalization, and the exact subset over which it is JCS
// ---------------------------------------------------------------------------

#[test]
fn the_profile_is_named_and_is_not_claimed_to_be_jcs() {
    // If this ever becomes "RFC 8785" the module's own documentation is wrong,
    // because the encoder sorts by UTF-8 bytes and admits no floats.
    assert_eq!(CANONICALIZATION_PROFILE, "automonique.wire/v1");
}

/// Over ASCII keys the encoder's byte order is RFC 8785 §3.2.3's order.
///
/// JCS sorts property names by UTF-16 code units and this encoder sorts by raw
/// UTF-8 bytes. Over U+0000..U+007F the two are the same order, because both
/// equal code-point order there, so for a key set this module controls — every
/// audit key is ASCII — the divergence is unreachable rather than merely
/// unlikely. This is the whole of the claim; nothing here tests a key outside
/// ASCII, and the encoder is not JCS for one.
#[test]
fn ascii_keys_sort_the_same_way_jcs_sorts_them() {
    let scrambled = JsonValue::Object(vec![
        ("~tilde".to_owned(), JsonValue::Integer(5)),
        ("Alpha".to_owned(), JsonValue::Integer(2)),
        ("_under".to_owned(), JsonValue::Integer(3)),
        ("0digit".to_owned(), JsonValue::Integer(1)),
        ("alpha".to_owned(), JsonValue::Integer(4)),
    ]);
    // 0x30 '0' < 0x41 'A' < 0x5f '_' < 0x61 'a' < 0x7e '~', which is both the
    // UTF-8 byte order and the UTF-16 code-unit order for these names.
    assert_eq!(
        scrambled.to_canonical_bytes(),
        br#"{"0digit":1,"Alpha":2,"_under":3,"alpha":4,"~tilde":5}"#
    );

    // And the same value built in sorted order encodes identically, which is
    // what makes the encoding a function of the value rather than of how it
    // was assembled.
    let ordered = JsonValue::Object(vec![
        ("0digit".to_owned(), JsonValue::Integer(1)),
        ("Alpha".to_owned(), JsonValue::Integer(2)),
        ("_under".to_owned(), JsonValue::Integer(3)),
        ("alpha".to_owned(), JsonValue::Integer(4)),
        ("~tilde".to_owned(), JsonValue::Integer(5)),
    ]);
    assert_eq!(ordered.to_canonical_bytes(), scrambled.to_canonical_bytes());
}

/// String escaping matches RFC 8785 §3.2.2.1, which is `JSON.stringify`'s.
///
/// Seven two-character escapes, lowercase `\u00xx` for the remaining C0
/// controls, and nothing else escaped. Applies to keys and values alike.
#[test]
fn string_escaping_matches_the_jcs_rule() {
    let value = JsonValue::Object(vec![(
        "k".to_owned(),
        JsonValue::String("\"\\\u{8}\u{c}\n\r\t\u{1}\u{1f}/é".to_owned()),
    )]);
    assert_eq!(
        value.to_canonical_bytes(),
        "{\"k\":\"\\\"\\\\\\b\\f\\n\\r\\t\\u0001\\u001f/é\"}".as_bytes(),
        "the seven short escapes, lowercase \\u00xx for other C0, \
         and no escaping of '/' or of non-ASCII"
    );
}

/// Integers below 2^53 serialize the way RFC 8785 §3.2.2.2 requires.
///
/// Shortest decimal, no exponent, no leading zeros, no `+`, a single `-` for
/// negatives, and `0` for zero. Above 2^53 the two encodings diverge — JCS
/// numbers are doubles and lose precision — which is why an audit record's only
/// integer is bounded at [`MAX_AUDIT_SEQ`].
#[test]
fn integers_below_two_to_the_fifty_three_serialize_the_jcs_way() {
    let cases: [(i64, &str); 7] = [
        (0, "0"),
        (1, "1"),
        (-1, "-1"),
        (10, "10"),
        (-1_000_000, "-1000000"),
        (9_007_199_254_740_991, "9007199254740991"),
        (-9_007_199_254_740_991, "-9007199254740991"),
    ];
    for (value, expected) in cases {
        let encoded = JsonValue::Integer(value).to_canonical_bytes();
        assert_eq!(
            String::from_utf8(encoded).expect("ascii"),
            expected,
            "integer {value} did not serialize as JCS does"
        );
    }
    // The bound that makes the claim above true rather than approximately
    // true: 2^53 - 1 is the largest integer a JCS number represents exactly.
    assert_eq!(MAX_AUDIT_SEQ, 9_007_199_254_740_991);
}

#[test]
fn one_whole_audit_record_encodes_to_exactly_these_bytes() {
    // A fixture rather than a property: it is what a second implementation in
    // another language has to reproduce, and a change to it is a wire change.
    let built = AuditRecord::link(1, GENESIS_PREV_HASH, event()).expect("record");
    let expected = format!(
        "{{\"actor\":\"operator:ada\",\"category\":\"approval\",\"outcome\":\"success\",\
         \"prev_hash\":\"{GENESIS_PREV_HASH}\",\"recorded_at\":\"2026-08-15T12:00:00Z\",\
         \"schema\":\"{AUDIT_RECORD_SCHEMA_V1}\",\"seq\":1,\"subject\":\"run:alpha\",\
         \"surface\":\"admin.socket\"}}"
    );
    assert_eq!(
        String::from_utf8(built.to_canonical_bytes()).expect("utf-8"),
        expected
    );
}

// ---------------------------------------------------------------------------
// Chain verification
// ---------------------------------------------------------------------------

#[test]
fn an_intact_chain_verifies_and_reports_its_length() {
    let rows = stored(&chain(32));
    assert_eq!(verify_chain(links(&rows)), Ok(32));
}

#[test]
fn an_empty_chain_verifies() {
    // A chain with no records makes no claim that could be false. Refusing it
    // would make "nothing has been recorded" indistinguishable from "the
    // records were tampered with".
    assert_eq!(verify_chain(Vec::new()), Ok(0));
}

#[test]
fn a_flipped_body_byte_breaks_at_that_exact_record() {
    // The byte is flipped *inside a string value*, so the body is still valid
    // canonical JSON afterwards and still decodes to a well-formed record. Only
    // the hash catches it, which is the whole point of storing one.
    let mut rows = stored(&chain(5));
    let target = rows.get_mut(2).expect("third record");
    let position = target
        .2
        .windows(3)
        .position(|window| window == b"ada")
        .expect("the actor's name is in the body");
    assert_ne!(target.2[position], b'a' ^ 0x01);
    target.2[position] ^= 0x01;
    assert!(
        automonique_protocol::wire::parse_canonical(&target.2).is_ok(),
        "the tampered body must still parse, or this proves the wrong thing"
    );

    let error = verify_chain(links(&rows)).expect_err("a tampered body must not verify");
    assert_eq!(error.seq, 3);
    assert_eq!(error.fault, ChainFault::RecordHashMismatch);
}

#[test]
fn a_body_edited_together_with_its_hash_column_still_breaks_the_link() {
    // The interesting attack: rewrite the body *and* recompute its hash, so
    // the record is internally consistent. The next record's `prev_hash` still
    // names the old hash, so the chain catches what the record alone cannot.
    let records = chain(4);
    let mut rows = stored(&records);
    let forged = record(2, records[0].record_hash().as_str(), "run:forged");
    let target = rows.get_mut(1).expect("second record");
    target.1 = forged.record_id();
    target.2 = forged.to_canonical_bytes();
    target.4 = forged.record_hash();

    let error = verify_chain(links(&rows)).expect_err("a forged record must not verify");
    assert_eq!(
        error.seq, 3,
        "the break surfaces at the record that follows"
    );
    assert_eq!(error.fault, ChainFault::PrevHashMismatch);
}

#[test]
fn two_swapped_rows_break_at_the_first_one_out_of_place() {
    let mut rows = stored(&chain(5));
    rows.swap(1, 2);

    let error = verify_chain(links(&rows)).expect_err("a reordered chain must not verify");
    assert_eq!(error.seq, 3, "the first row presented out of order");
    assert_eq!(error.fault, ChainFault::SeqNotContiguous);
}

#[test]
fn a_deleted_middle_record_breaks_at_the_gap() {
    let mut rows = stored(&chain(5));
    rows.remove(2);

    let error = verify_chain(links(&rows)).expect_err("a chain with a hole must not verify");
    assert_eq!(error.seq, 4, "the record that now sits where seq 3 belongs");
    assert_eq!(error.fault, ChainFault::SeqNotContiguous);
}

#[test]
fn a_genesis_that_does_not_link_to_zeros_is_named_as_such() {
    let records = chain(2);
    let mut rows = stored(&records);
    // Drop the first record, leaving a chain whose head claims seq 1.
    rows.remove(0);
    rows[0].0 = 1;

    let error = verify_chain(links(&rows)).expect_err("a false genesis must not verify");
    assert_eq!(error.seq, 1);
    assert_eq!(error.fault, ChainFault::GenesisNotZero);
}

#[test]
fn a_record_id_that_was_not_derived_from_the_hash_is_named() {
    let mut rows = stored(&chain(3));
    rows[1].1 = derive_record_id(&"a".repeat(HASH_HEX_BYTES));

    let error = verify_chain(links(&rows)).expect_err("a minted identifier must not verify");
    assert_eq!(error.seq, 2);
    assert_eq!(error.fault, ChainFault::RecordIdMismatch);
}

#[test]
fn a_body_that_is_not_canonical_json_is_named_as_malformed() {
    let mut rows = stored(&chain(2));
    rows[0].2 = b"{ \"actor\": \"operator:ada\" }".to_vec();

    let error = verify_chain(links(&rows)).expect_err("non-canonical bytes must not verify");
    assert_eq!(error.seq, 1);
    assert_eq!(error.fault, ChainFault::BodyMalformed);
}

#[test]
fn a_body_carrying_an_unknown_key_is_refused_rather_than_ignored() {
    let mut rows = stored(&chain(1));
    let built = record(1, GENESIS_PREV_HASH, "run:1");
    let JsonValue::Object(mut entries) =
        automonique_protocol::wire::parse_canonical(&built.to_canonical_bytes())
            .expect("canonical")
    else {
        panic!("an audit body is an object")
    };
    entries.push(("extra".to_owned(), JsonValue::Integer(1)));
    rows[0].2 = JsonValue::Object(entries).to_canonical_bytes();

    let error = verify_chain(links(&rows)).expect_err("an extra key must not verify");
    assert_eq!(error.seq, 1);
    assert_eq!(error.fault, ChainFault::BodyMalformed);
}

#[test]
fn every_fault_has_its_own_stable_spelling() {
    let faults = [
        ChainFault::SeqNotContiguous,
        ChainFault::BodyMalformed,
        ChainFault::BodyFieldInvalid,
        ChainFault::BodySeqMismatch,
        ChainFault::BodyPrevHashMismatch,
        ChainFault::GenesisNotZero,
        ChainFault::PrevHashMismatch,
        ChainFault::RecordHashMismatch,
        ChainFault::RecordIdMismatch,
    ];
    let mut spellings: Vec<&str> = faults.iter().map(|fault| fault.as_str()).collect();
    spellings.sort_unstable();
    let count = spellings.len();
    spellings.dedup();
    assert_eq!(spellings.len(), count, "two faults share a spelling");
    for fault in faults {
        assert_eq!(fault.to_string(), fault.as_str());
    }
}

#[test]
fn a_break_names_the_record_and_the_fault_in_its_message() {
    let mut rows = stored(&chain(3));
    rows.remove(1);
    let error = verify_chain(links(&rows)).expect_err("a hole must not verify");
    let rendered = error.to_string();
    assert!(rendered.contains("seq 3"), "{rendered}");
    assert!(rendered.contains("seq_not_contiguous"), "{rendered}");
}
