// SPDX-License-Identifier: Elastic-2.0

//! Bounded, cursor-paginated resource listing for negotiated Platform v2.
//!
//! Platform v1 has no listing primitive. Its [`crate::platform::SnapshotRequest`]
//! carries only `resources: Vec<ResourceCoordinate>`, an empty list means *the
//! whole inventory*, and the answer is capped at
//! [`crate::platform::MAX_SNAPSHOT_RESOURCES`]. The untargeted snapshot was
//! therefore the listing primitive, and it does not scale: a caller that cannot
//! already name what it wants has to ask for everything and hope the inventory
//! fits under the ceiling. That surface is frozen — an installed peer decodes
//! `["resources"]` with an exact field set and would reject a body carrying a
//! cursor — so the listing belongs here, in the separately negotiated major.
//!
//! What this module owns is the *pagination contract*, not the inventory. The
//! caller of [`page_authorized_resources`] hands it records it has already
//! authorized one at a time; nothing here can widen that set. Three properties
//! are load-bearing and each is expressed in a type rather than in a comment:
//!
//! - **The cursor is opaque and self-validating.** It binds the class filter
//!   and a fingerprint of the exact authorized inventory generation it was
//!   minted against. A hand-edited or borrowed cursor does not match and the
//!   answer is [`ResourceListingResult::Resync`], never a page. A cursor
//!   therefore cannot be edited into reading anything: the offset it carries
//!   only ever indexes the presenting caller's own authorized, filtered list,
//!   and any disagreement about which list that is expires it.
//! - **The bound is the server's.** A query carries the limit its caller asked
//!   for, verbatim; [`granted_page_limit`] is the single place the server's cap
//!   is applied, and the page carries both numbers so a client can prove the
//!   clamp rather than trust it.
//! - **A changed inventory is fenced, not silently resumed.** Adding, removing
//!   or revising an authorized resource moves the inventory fingerprint and
//!   expires every outstanding cursor. That is the only answer that cannot skip
//!   or duplicate a record across pages, and [`ResourceListingResult`] makes a
//!   caller handle it: a resync is a distinct variant, not an empty page.

use core::fmt;

use crate::digest::Sha256;
use crate::platform::{ResourceAuthority, ResourceKind, ResourceRecord};
use crate::platform_v2::{
    decode_bound_cursor_parts, encode_bound_cursor_parts, strictly_increasing_or_empty,
};
use crate::primitives::{IdDomain, OpaqueId, ValueError};

/// Schema identifier for the v2 resource-listing documents.
pub const PLATFORM_INVENTORY_SCHEMA_V1: &str = "automonique.platform/inventory/v1";

/// The negotiated Platform major this sub-contract requires.
pub const PLATFORM_INVENTORY_REQUIRES_PLATFORM_MAJOR: u16 = 2;

/// The one transport method that answers with a bounded resource listing.
pub const INVENTORY_LIST_METHOD_V1: &str = "list_resources";

/// Maximum bytes in one opaque listing cursor.
pub const MAX_RESOURCE_LISTING_CURSOR_BYTES: usize = 256;

/// The server's page ceiling. A caller may ask for more and receives this.
pub const MAX_RESOURCE_LISTING_PAGE_ITEMS: usize = 128;

/// Cursor prefix. Distinct from every other v2 cursor grammar so a cursor
/// minted for another listing cannot be replayed here as a valid offset.
const RESOURCE_LISTING_CURSOR_PREFIX: &str = "rl2";

#[derive(Clone, Copy, Debug)]
pub struct ResourceListingCursorDomain;
impl IdDomain for ResourceListingCursorDomain {}

/// One opaque, server-minted continuation coordinate.
pub type ResourceListingCursor =
    OpaqueId<ResourceListingCursorDomain, MAX_RESOURCE_LISTING_CURSOR_BYTES>;

/// The server's page ceiling applied to one caller's request.
///
/// This is the *only* spelling of the clamp. The query reports it, the page
/// constructor proves the server used it, and the generated TypeScript decoder
/// re-derives it from the same two numbers on the wire. A caller asking for a
/// larger page is answered with the server's bound; it is never refused, and it
/// never receives the larger page.
#[must_use]
pub const fn granted_page_limit(requested_limit: u16) -> u16 {
    // The ceiling is a small constant, so this cast is exact.
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the page ceiling is a small constant chosen to fit u16"
    )]
    let ceiling = MAX_RESOURCE_LISTING_PAGE_ITEMS as u16;
    if requested_limit > ceiling {
        ceiling
    } else {
        requested_limit
    }
}

/// One bounded listing request over the v1 resource vocabulary.
///
/// An empty `authorities` or `kinds` list means *no filter on that axis*, which
/// is safe here in a way it was not in v1: the answer is a bounded page with a
/// cursor rather than the entire inventory in one frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceListingQuery {
    authorities: Vec<ResourceAuthority>,
    kinds: Vec<ResourceKind>,
    after: Option<ResourceListingCursor>,
    requested_limit: u16,
}

impl ResourceListingQuery {
    /// Build one listing query.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceListingError`] when a class filter repeats a value, is
    /// unordered, or overflows its closed vocabulary, or when the requested
    /// limit is zero. A requested limit above the server ceiling is *not* an
    /// error: see [`granted_page_limit`].
    pub fn new(
        authorities: Vec<ResourceAuthority>,
        kinds: Vec<ResourceKind>,
        after: Option<ResourceListingCursor>,
        requested_limit: u16,
    ) -> Result<Self, ResourceListingError> {
        if authorities.len() > ResourceAuthority::ALL.len()
            || !strictly_increasing_or_empty(&authorities)
        {
            return Err(ResourceListingError::QueryAuthoritiesInvalid);
        }
        if kinds.len() > ResourceKind::ALL.len() || !strictly_increasing_or_empty(&kinds) {
            return Err(ResourceListingError::QueryKindsInvalid);
        }
        if requested_limit == 0 {
            return Err(ResourceListingError::QueryLimitInvalid);
        }
        Ok(Self {
            authorities,
            kinds,
            after,
            requested_limit,
        })
    }

    #[must_use]
    pub fn authorities(&self) -> &[ResourceAuthority] {
        &self.authorities
    }

    #[must_use]
    pub fn kinds(&self) -> &[ResourceKind] {
        &self.kinds
    }

    #[must_use]
    pub const fn after(&self) -> Option<&ResourceListingCursor> {
        self.after.as_ref()
    }

    /// The limit the caller asked for, carried verbatim.
    #[must_use]
    pub const fn requested_limit(&self) -> u16 {
        self.requested_limit
    }

    /// The limit the server will actually apply.
    #[must_use]
    pub const fn granted_limit(&self) -> u16 {
        granted_page_limit(self.requested_limit)
    }

    /// Whether one record survives this query's class filters.
    #[must_use]
    pub fn admits(&self, record: &ResourceRecord) -> bool {
        (self.authorities.is_empty() || self.authorities.contains(&record.resource.authority))
            && (self.kinds.is_empty() || self.kinds.contains(&record.resource.kind))
    }
}

/// One bounded page of resource records.
///
/// Both limits are on the wire. `requested_limit` is what the caller asked for
/// and `granted_limit` is what the server applied; a decoder that finds them
/// inconsistent with [`granted_page_limit`] refuses the page rather than
/// reporting a truncation the server never performed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceListingPage {
    requested_limit: u16,
    granted_limit: u16,
    after: Option<ResourceListingCursor>,
    next_cursor: Option<ResourceListingCursor>,
    has_more: bool,
    items: Vec<ResourceRecord>,
}

impl ResourceListingPage {
    /// Build one page.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceListingError`] when the two limits disagree with the
    /// server's own clamp, the page carries more records than it granted, the
    /// continuation fields are incoherent, or the records repeat or are not in
    /// coordinate order.
    pub fn new(
        requested_limit: u16,
        granted_limit: u16,
        after: Option<ResourceListingCursor>,
        next_cursor: Option<ResourceListingCursor>,
        has_more: bool,
        items: Vec<ResourceRecord>,
    ) -> Result<Self, ResourceListingError> {
        if requested_limit == 0
            || granted_limit != granted_page_limit(requested_limit)
            || items.len() > usize::from(granted_limit)
        {
            return Err(ResourceListingError::PageLimitInvalid);
        }
        if has_more != next_cursor.is_some() || (has_more && items.is_empty()) {
            return Err(ResourceListingError::PageCursorInvalid);
        }
        if after.is_some() && after == next_cursor {
            return Err(ResourceListingError::PageCursorInvalid);
        }
        if !items
            .windows(2)
            .all(|pair| pair[0].resource < pair[1].resource)
        {
            return Err(ResourceListingError::PageOrderInvalid);
        }
        Ok(Self {
            requested_limit,
            granted_limit,
            after,
            next_cursor,
            has_more,
            items,
        })
    }

    #[must_use]
    pub const fn requested_limit(&self) -> u16 {
        self.requested_limit
    }

    #[must_use]
    pub const fn granted_limit(&self) -> u16 {
        self.granted_limit
    }

    #[must_use]
    pub const fn after(&self) -> Option<&ResourceListingCursor> {
        self.after.as_ref()
    }

    #[must_use]
    pub const fn next_cursor(&self) -> Option<&ResourceListingCursor> {
        self.next_cursor.as_ref()
    }

    #[must_use]
    pub const fn has_more(&self) -> bool {
        self.has_more
    }

    #[must_use]
    pub fn items(&self) -> &[ResourceRecord] {
        &self.items
    }

    #[must_use]
    pub fn into_items(self) -> Vec<ResourceRecord> {
        self.items
    }
}

/// The answer when a presented cursor no longer names a live listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceListingResync {
    expired_after: ResourceListingCursor,
}

impl ResourceListingResync {
    #[must_use]
    pub const fn new(expired_after: ResourceListingCursor) -> Self {
        Self { expired_after }
    }

    #[must_use]
    pub const fn expired_after(&self) -> &ResourceListingCursor {
        &self.expired_after
    }
}

/// The two answers a listing can have. A resync is a variant, not an empty
/// page, so a caller cannot mistake an expired continuation for the end of the
/// inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceListingResult {
    Page(ResourceListingPage),
    Resync(ResourceListingResync),
}

/// One resource record whose caller has already decided this principal may read
/// it.
///
/// This type is the whole of the authorization contract for a listing.
/// [`page_authorized_resources`] takes nothing else, so the pagination
/// primitive is structurally unable to see a record that failed a per-resource
/// check — a listing can never become a way to learn that a resource exists
/// that a targeted read would have refused. Deciding *which* records qualify is
/// the server's, and it must be a function of the record: a page-level shortcut
/// would defeat the point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedResourceRecord {
    record: ResourceRecord,
}

impl AuthorizedResourceRecord {
    #[must_use]
    pub const fn new(record: ResourceRecord) -> Self {
        Self { record }
    }

    #[must_use]
    pub const fn record(&self) -> &ResourceRecord {
        &self.record
    }
}

/// Page a deterministic set of records the caller has already authorized.
///
/// The cursor binds the class filter and a fingerprint of the authorized
/// inventory generation, so a changed filter, a changed authorization, or a
/// changed inventory answers [`ResourceListingResult::Resync`] rather than
/// resuming at an offset that now names a different record.
///
/// # Errors
///
/// Returns [`ResourceListingError::InventoryInvalid`] when the authorized set
/// repeats a coordinate, and propagates any refusal from constructing the page.
pub fn page_authorized_resources(
    query: &ResourceListingQuery,
    records: &[AuthorizedResourceRecord],
) -> Result<ResourceListingResult, ResourceListingError> {
    let mut ordered: Vec<&AuthorizedResourceRecord> = records.iter().collect();
    ordered.sort_by(|left, right| left.record().resource.cmp(&right.record().resource));
    if ordered
        .windows(2)
        .any(|pair| pair[0].record().resource == pair[1].record().resource)
    {
        return Err(ResourceListingError::InventoryInvalid);
    }
    let inventory = inventory_fingerprint(&ordered);
    let filter = query_filter_fingerprint(query);
    let start = match query.after() {
        None => 0,
        Some(after) => {
            match decode_bound_cursor_parts(after.as_str(), RESOURCE_LISTING_CURSOR_PREFIX) {
                Some((cursor_filter, cursor_inventory, offset))
                    if cursor_filter == filter && cursor_inventory == inventory =>
                {
                    offset
                }
                _ => {
                    return Ok(ResourceListingResult::Resync(ResourceListingResync::new(
                        after.clone(),
                    )));
                }
            }
        }
    };
    let filtered: Vec<&AuthorizedResourceRecord> = ordered
        .into_iter()
        .filter(|item| query.admits(item.record()))
        .collect();
    if start > filtered.len() {
        return Ok(ResourceListingResult::Resync(ResourceListingResync::new(
            query
                .after()
                .expect("a nonzero start comes from a cursor")
                .clone(),
        )));
    }
    let granted_limit = query.granted_limit();
    let end = start
        .saturating_add(usize::from(granted_limit))
        .min(filtered.len());
    let has_more = end < filtered.len();
    let next_cursor = has_more
        .then(|| encode_listing_cursor(&filter, &inventory, end))
        .transpose()?;
    Ok(ResourceListingResult::Page(ResourceListingPage::new(
        query.requested_limit(),
        granted_limit,
        query.after().cloned(),
        next_cursor,
        has_more,
        filtered[start..end]
            .iter()
            .map(|item| item.record().clone())
            .collect(),
    )?))
}

/// Fingerprint the authorized inventory generation a cursor is minted against.
///
/// The freshness *observation time* is deliberately absent. The daemon rewrites
/// `observed_at` on every refresh even when nothing about a resource changed —
/// that is exactly the predicate the durable platform store itself uses to
/// decide whether a resource moved — so including it would expire every cursor
/// on every poll and make paging impossible. What is included is what can make
/// a page skip or duplicate a record: the coordinate set, and each record's
/// revision, freshness state and summary.
fn inventory_fingerprint(records: &[&AuthorizedResourceRecord]) -> String {
    let mut bytes = Vec::new();
    for item in records {
        let record = item.record();
        bytes.extend_from_slice(coordinate_order_key(record).as_bytes());
        bytes.push(0xff);
        bytes.extend_from_slice(record.freshness.revision.get().to_string().as_bytes());
        bytes.push(0xfe);
        bytes.extend_from_slice(record.freshness.state.as_str().as_bytes());
        bytes.push(0xfd);
        bytes.extend_from_slice(record.summary.as_str().as_bytes());
        bytes.push(0xfc);
    }
    Sha256::digest(&bytes).to_hex()
}

fn query_filter_fingerprint(query: &ResourceListingQuery) -> String {
    let mut bytes = Vec::new();
    for authority in query.authorities() {
        bytes.extend_from_slice(authority.as_str().as_bytes());
        bytes.push(0xff);
    }
    bytes.push(0xfe);
    for kind in query.kinds() {
        bytes.extend_from_slice(kind.as_str().as_bytes());
        bytes.push(0xff);
    }
    Sha256::digest(&bytes).to_hex()
}

fn coordinate_order_key(record: &ResourceRecord) -> String {
    let mut key = record.resource.authority.as_str().to_owned();
    key.push('\0');
    key.push_str(record.resource.kind.as_str());
    key.push('\0');
    key.push_str(record.resource.id.as_str());
    key
}

fn encode_listing_cursor(
    filter: &str,
    inventory: &str,
    offset: usize,
) -> Result<ResourceListingCursor, ResourceListingError> {
    ResourceListingCursor::new(encode_bound_cursor_parts(
        RESOURCE_LISTING_CURSOR_PREFIX,
        filter,
        inventory,
        offset,
    ))
    .map_err(ResourceListingError::Field)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceListingError {
    Field(ValueError),
    QueryAuthoritiesInvalid,
    QueryKindsInvalid,
    QueryLimitInvalid,
    PageLimitInvalid,
    PageCursorInvalid,
    PageOrderInvalid,
    InventoryInvalid,
}

impl fmt::Display for ResourceListingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Field(error) => write!(formatter, "resource listing field is invalid: {error}"),
            Self::QueryAuthoritiesInvalid => {
                formatter.write_str("resource listing authorities are repeated or unordered")
            }
            Self::QueryKindsInvalid => {
                formatter.write_str("resource listing kinds are repeated or unordered")
            }
            Self::QueryLimitInvalid => formatter.write_str("resource listing limit is invalid"),
            Self::PageLimitInvalid => {
                formatter.write_str("resource listing page limits are inconsistent")
            }
            Self::PageCursorInvalid => {
                formatter.write_str("resource listing page cursor is incoherent")
            }
            Self::PageOrderInvalid => {
                formatter.write_str("resource listing page records are repeated or unordered")
            }
            Self::InventoryInvalid => {
                formatter.write_str("authorized resource inventory repeats a coordinate")
            }
        }
    }
}

impl std::error::Error for ResourceListingError {}

impl From<ValueError> for ResourceListingError {
    fn from(value: ValueError) -> Self {
        Self::Field(value)
    }
}
