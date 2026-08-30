// SPDX-License-Identifier: Elastic-2.0

use automonique_protocol::platform::{
    Freshness, FreshnessState, MAX_SNAPSHOT_RESOURCES, PlatformText, ResourceAuthority,
    ResourceCoordinate, ResourceId, ResourceKind, ResourceRecord,
};
use automonique_protocol::platform_v2_inventory::*;
use automonique_protocol::platform_v2_inventory_api::*;
use automonique_protocol::primitives::{EpochMillis, Revision};

fn record(kind: ResourceKind, id: &str, revision: u64, summary: &str) -> ResourceRecord {
    ResourceRecord {
        resource: ResourceCoordinate::new(
            ResourceAuthority::Automonique,
            kind,
            ResourceId::new(id).unwrap(),
        ),
        freshness: Freshness {
            state: FreshnessState::Fresh,
            observed_at: EpochMillis::from_millis(1_700_000_000_000),
            revision: Revision::new(revision).unwrap(),
        },
        summary: PlatformText::new(summary).unwrap(),
    }
}

fn authorized(records: &[ResourceRecord]) -> Vec<AuthorizedResourceRecord> {
    records
        .iter()
        .cloned()
        .map(AuthorizedResourceRecord::new)
        .collect()
}

fn inventory(count: usize) -> Vec<ResourceRecord> {
    (0..count)
        .map(|index| {
            record(
                ResourceKind::Approval,
                &format!("approval-{index:04}"),
                1,
                "open",
            )
        })
        .collect()
}

fn query(limit: u16, after: Option<ResourceListingCursor>) -> ResourceListingQuery {
    ResourceListingQuery::new(Vec::new(), Vec::new(), after, limit).unwrap()
}

fn page(result: ResourceListingResult) -> ResourceListingPage {
    match result {
        ResourceListingResult::Page(page) => page,
        ResourceListingResult::Resync(value) => {
            panic!("expected a page, got a resync of {}", value.expired_after())
        }
    }
}

#[test]
fn an_untargeted_listing_pages_the_whole_inventory_instead_of_refusing_it() {
    // The v1 defect stated as a test: more resources than one v1 snapshot may
    // carry, listed without naming a single coordinate, and answered rather
    // than refused.
    let records = inventory(MAX_SNAPSHOT_RESOURCES + 7);
    let all = authorized(&records);
    let mut seen = Vec::new();
    let mut after = None;
    loop {
        let current = page(page_authorized_resources(&query(100, after), &all).unwrap());
        assert!(current.items().len() <= usize::from(current.granted_limit()));
        seen.extend(current.items().iter().map(|item| item.resource.clone()));
        match current.next_cursor() {
            Some(cursor) => after = Some(cursor.clone()),
            None => break,
        }
    }
    assert_eq!(seen.len(), records.len());
    let mut expected: Vec<ResourceCoordinate> =
        records.iter().map(|item| item.resource.clone()).collect();
    expected.sort();
    assert_eq!(seen, expected);
}

#[test]
fn a_page_larger_than_the_server_cap_is_clamped_and_never_refused() {
    let records = inventory(MAX_RESOURCE_LISTING_PAGE_ITEMS + 5);
    let requested = u16::try_from(MAX_RESOURCE_LISTING_PAGE_ITEMS).unwrap() + 900;
    let asked = query(requested, None);
    assert_eq!(asked.requested_limit(), requested);
    assert_eq!(
        usize::from(asked.granted_limit()),
        MAX_RESOURCE_LISTING_PAGE_ITEMS
    );
    let current = page(page_authorized_resources(&asked, &authorized(&records)).unwrap());
    assert_eq!(current.requested_limit(), requested);
    assert_eq!(
        current.items().len(),
        MAX_RESOURCE_LISTING_PAGE_ITEMS,
        "the caller gets the server's page, not its own"
    );
    assert!(current.has_more());
}

#[test]
fn a_page_that_claims_a_bound_the_server_never_applies_is_refused() {
    // The clamp is provable from the two numbers on the wire. A page claiming
    // it granted less than the server would have is a truncation nobody
    // performed, and a page claiming more is a bound nobody holds.
    let ceiling = u16::try_from(MAX_RESOURCE_LISTING_PAGE_ITEMS).unwrap();
    assert_eq!(
        ResourceListingPage::new(8, 4, None, None, false, Vec::new()),
        Err(ResourceListingError::PageLimitInvalid)
    );
    assert_eq!(
        ResourceListingPage::new(ceiling + 1, ceiling + 1, None, None, false, Vec::new()),
        Err(ResourceListingError::PageLimitInvalid)
    );
    assert!(ResourceListingPage::new(ceiling + 1, ceiling, None, None, false, Vec::new()).is_ok());
}

#[test]
fn a_zero_limit_is_refused_and_an_oversized_one_is_not() {
    assert_eq!(
        ResourceListingQuery::new(Vec::new(), Vec::new(), None, 0),
        Err(ResourceListingError::QueryLimitInvalid)
    );
    assert!(ResourceListingQuery::new(Vec::new(), Vec::new(), None, u16::MAX).is_ok());
}

#[test]
fn class_filters_must_be_ordered_and_free_of_repeats() {
    assert_eq!(
        ResourceListingQuery::new(
            vec![ResourceAuthority::GitHub, ResourceAuthority::AiOperations],
            Vec::new(),
            None,
            10,
        ),
        Err(ResourceListingError::QueryAuthoritiesInvalid)
    );
    assert_eq!(
        ResourceListingQuery::new(
            Vec::new(),
            vec![ResourceKind::Job, ResourceKind::Job],
            None,
            10,
        ),
        Err(ResourceListingError::QueryKindsInvalid)
    );
}

#[test]
fn a_hand_edited_cursor_never_becomes_a_valid_offset() {
    let records = inventory(10);
    let all = authorized(&records);
    let first = page(page_authorized_resources(&query(4, None), &all).unwrap());
    let cursor = first.next_cursor().unwrap().clone();
    let genuine = cursor.as_str().to_owned();
    let mut forged: Vec<String> = vec![
        genuine.replace("rl2.", "wc2."),
        format!("{genuine}9"),
        genuine.replacen('a', "b", 1),
        "rl2.deadbeef.deadbeef.0".to_owned(),
        "not-a-cursor".to_owned(),
    ];
    // The offset is inside the opaque value, so moving it past the end of the
    // caller's own list is also a forgery rather than a longer page.
    forged.push({
        let mut parts: Vec<&str> = genuine.split('.').collect();
        parts.pop();
        format!("{}.{}", parts.join("."), 9_999)
    });
    for candidate in forged {
        let cursor = ResourceListingCursor::new(candidate.clone()).unwrap();
        assert!(
            matches!(
                page_authorized_resources(&query(4, Some(cursor)), &all).unwrap(),
                ResourceListingResult::Resync(_)
            ),
            "a forged cursor was accepted: {candidate}"
        );
    }
}

#[test]
fn a_cursor_minted_against_another_authorized_set_expires() {
    // Two principals, two authorized sets. The cursor binds the set it was
    // minted against, so the narrower principal cannot resume the wider one's
    // listing and read past what it holds.
    let wide = inventory(10);
    let narrow: Vec<ResourceRecord> = wide.iter().take(5).cloned().collect();
    let cursor = page(page_authorized_resources(&query(4, None), &authorized(&wide)).unwrap())
        .next_cursor()
        .unwrap()
        .clone();
    assert!(matches!(
        page_authorized_resources(&query(4, Some(cursor)), &authorized(&narrow)).unwrap(),
        ResourceListingResult::Resync(_)
    ));
}

#[test]
fn a_cursor_bound_to_one_filter_does_not_resume_another() {
    let records = inventory(10);
    let all = authorized(&records);
    let scoped =
        ResourceListingQuery::new(Vec::new(), vec![ResourceKind::Approval], None, 4).unwrap();
    let cursor = page(page_authorized_resources(&scoped, &all).unwrap())
        .next_cursor()
        .unwrap()
        .clone();
    assert!(matches!(
        page_authorized_resources(&query(4, Some(cursor)), &all).unwrap(),
        ResourceListingResult::Resync(_)
    ));
}

#[test]
fn a_changed_inventory_is_fenced_rather_than_silently_resumed() {
    let records = inventory(10);
    let cursor = page(page_authorized_resources(&query(4, None), &authorized(&records)).unwrap())
        .next_cursor()
        .unwrap()
        .clone();
    for changed in [
        // A record added ahead of the cursor would shift every later offset.
        {
            let mut moved = records.clone();
            moved.insert(
                0,
                record(ResourceKind::Approval, "approval-0000a", 1, "open"),
            );
            moved
        },
        // A record removed would skip its successor.
        records[1..].to_vec(),
        // A revision moving is a change to what the offsets name.
        {
            let mut moved = records.clone();
            moved[0] = record(ResourceKind::Approval, "approval-0000", 2, "open");
            moved
        },
        // So is a summary moving.
        {
            let mut moved = records.clone();
            moved[0] = record(ResourceKind::Approval, "approval-0000", 1, "closed");
            moved
        },
    ] {
        assert!(matches!(
            page_authorized_resources(&query(4, Some(cursor.clone())), &authorized(&changed))
                .unwrap(),
            ResourceListingResult::Resync(_)
        ));
    }
}

#[test]
fn a_new_observation_time_alone_does_not_expire_a_cursor() {
    // The daemon rewrites the observation time on every refresh. If that
    // expired cursors, no caller could ever reach page two.
    let records = inventory(10);
    let cursor = page(page_authorized_resources(&query(4, None), &authorized(&records)).unwrap())
        .next_cursor()
        .unwrap()
        .clone();
    let observed_again: Vec<ResourceRecord> = records
        .iter()
        .map(|item| ResourceRecord {
            freshness: Freshness {
                observed_at: EpochMillis::from_millis(1_700_000_999_999),
                ..item.freshness
            },
            ..item.clone()
        })
        .collect();
    let second = page(
        page_authorized_resources(&query(4, Some(cursor)), &authorized(&observed_again)).unwrap(),
    );
    assert_eq!(second.items().len(), 4);
    assert_eq!(second.items()[0].resource.id.as_str(), "approval-0004");
}

#[test]
fn pages_neither_skip_nor_duplicate_across_a_complete_walk() {
    let records = inventory(23);
    let all = authorized(&records);
    let mut seen = Vec::new();
    let mut after = None;
    for _ in 0..10 {
        let current = page(page_authorized_resources(&query(5, after), &all).unwrap());
        seen.extend(current.items().iter().map(|item| item.resource.id.clone()));
        match current.next_cursor() {
            Some(cursor) => after = Some(cursor.clone()),
            None => break,
        }
    }
    assert_eq!(seen.len(), 23);
    let mut unique = seen.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 23);
}

#[test]
fn a_repeated_coordinate_in_the_authorized_set_is_refused() {
    let duplicated = vec![
        record(ResourceKind::Approval, "approval-1", 1, "open"),
        record(ResourceKind::Approval, "approval-1", 2, "closed"),
    ];
    assert_eq!(
        page_authorized_resources(&query(4, None), &authorized(&duplicated)),
        Err(ResourceListingError::InventoryInvalid)
    );
}

#[test]
fn class_filters_narrow_the_authorized_set_and_never_widen_it() {
    let records = vec![
        record(ResourceKind::Approval, "approval-1", 1, "open"),
        record(ResourceKind::Model, "model-1", 1, "available"),
    ];
    let only_models = ResourceListingQuery::new(
        vec![ResourceAuthority::Automonique],
        vec![ResourceKind::Model],
        None,
        10,
    )
    .unwrap();
    // Only the approval is authorized, so asking for models proves nothing
    // about whether a model exists.
    let listed = page(page_authorized_resources(&only_models, &authorized(&records[..1])).unwrap());
    assert!(listed.items().is_empty());
    assert!(!listed.has_more());
    let listed = page(page_authorized_resources(&only_models, &authorized(&records)).unwrap());
    assert_eq!(listed.items().len(), 1);
    assert_eq!(listed.items()[0].resource.kind, ResourceKind::Model);
}

#[test]
fn a_query_round_trips_through_its_canonical_document() {
    let asked = ResourceListingQuery::new(
        vec![ResourceAuthority::Automonique, ResourceAuthority::Provider],
        vec![ResourceKind::Approval, ResourceKind::Model],
        Some(
            ResourceListingCursor::new(format!("rl2.{}.{}.4", "a".repeat(64), "b".repeat(64)))
                .unwrap(),
        ),
        512,
    )
    .unwrap();
    let bytes = encode_resource_listing_query(&asked).unwrap();
    assert_eq!(decode_resource_listing_query(&bytes).unwrap(), asked);
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("\"schema\":\"automonique.platform/inventory/v1\""));
    assert!(text.contains("\"requested_limit\":512"));
}

#[test]
fn a_page_round_trips_through_its_canonical_document() {
    let listed =
        page(page_authorized_resources(&query(4, None), &authorized(&inventory(9))).unwrap());
    let bytes = encode_resource_listing_page(&listed).unwrap();
    assert_eq!(decode_resource_listing_page(&bytes).unwrap(), listed);
}

#[test]
fn a_resync_round_trips_through_its_canonical_document() {
    let resync = ResourceListingResync::new(
        ResourceListingCursor::new(format!("rl2.{}.{}.4", "a".repeat(64), "b".repeat(64))).unwrap(),
    );
    let bytes = encode_resource_listing_resync(&resync).unwrap();
    assert_eq!(decode_resource_listing_resync(&bytes).unwrap(), resync);
    assert!(
        String::from_utf8(bytes)
            .unwrap()
            .contains("\"outcome\":\"resync_required\"")
    );
}

#[test]
fn a_document_that_is_not_exactly_this_body_is_refused() {
    let asked = query(4, None);
    let bytes = encode_resource_listing_query(&asked).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    for hostile in [
        text.replace(
            "automonique.platform/inventory/v1",
            "automonique.platform/v2",
        ),
        text.replace("\"version\":2", "\"version\":1"),
        text.replacen('{', "{\"project\":\"project-1\",", 1),
        text.replace("\"requested_limit\":4,", ""),
    ] {
        assert!(
            decode_resource_listing_query(hostile.as_bytes()).is_err(),
            "a hostile query body was admitted: {hostile}"
        );
    }
}

#[test]
fn a_page_body_whose_two_limits_disagree_is_refused_by_the_decoder() {
    let listed =
        page(page_authorized_resources(&query(4, None), &authorized(&inventory(9))).unwrap());
    let text = String::from_utf8(encode_resource_listing_page(&listed).unwrap()).unwrap();
    let hostile = text.replace("\"granted_limit\":4", "\"granted_limit\":2");
    assert_ne!(hostile, text);
    assert!(decode_resource_listing_page(hostile.as_bytes()).is_err());
}
