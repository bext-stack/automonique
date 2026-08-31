// SPDX-License-Identifier: Apache-2.0

//! Capture one live Platform v2 attention read from a deployed web entry.
//!
//! `tools/run_attention_live_parity.py` needs the *bytes a deployment serves*,
//! not a fixture, and it needs them in a form three independent clients can
//! each decode with their own production decoder. Nothing in Python can produce
//! a canonical Platform v2 envelope without becoming a second implementation of
//! the codec, so this example does the reading with the real client — the same
//! `PlatformV2Client` a desktop or phone build links — and prints what came
//! back as canonical JSON.
//!
//! It performs three kinds of read, selected by the arguments:
//!
//! * with no `--source`, it negotiates and walks `query_work_contexts`, which
//!   is the authoritative record graph every client derives its attention
//!   source inventory from;
//! * with `--review-probe`, it additionally asks `get_review` for each named
//!   workspace, because whether a review source exists is a server fact and
//!   the inventory derivation needs it;
//! * with one or more `--source kind:id`, it reads exactly those attention
//!   source snapshots.
//!
//! Every outcome is recorded, including refusals and transport failures. A
//! refused lane is a live observation about the deployment, not an error to
//! retry away: it is exactly what the clients must then agree about.
//!
//! The credential is read from the environment variable *named* on the command
//! line and never printed, never echoed into the document, and never written
//! anywhere. The document names the variable, not its value.
//!
//! ```text
//! cargo run --example attention_live_capture -- \
//!   --endpoint https://host/api/platform/v2 \
//!   --credential-env AUTOMONIQUE_OPS_BASIC_AUTH
//! ```

use std::collections::BTreeSet;
use std::process::ExitCode;

use automonique_platform_client::platform_v2_client::{
    AttentionReadResult, NegotiationResult, PlatformV2Client, PlatformV2ClientError,
    ReviewReadResult, WorkContextQueryResult,
};
use automonique_platform_client::{BasicCredential, HttpsTransport};
use automonique_protocol::platform::{
    ResourceAuthority, ResourceCoordinate, ResourceId, ResourceKind,
};
use automonique_protocol::platform_v2::{
    AttemptWorkspaceId, CheckoutId, PlatformVersionOffer, ProjectId, UserWorkspaceId, V1SessionRef,
    WorkContextAttributes, WorkContextCursor, WorkContextIdentity, WorkContextKind,
    WorkContextLabel, WorkContextLifecycle, WorkContextPage, WorkContextQuery, WorkContextRecord,
    WorkContextRelation, WorkContextRelationKind, WorkSessionId,
};
use automonique_protocol::platform_v2_api::encode_work_context_page;
use automonique_protocol::platform_v2_attention::{
    AttentionItem, AttentionItemId, AttentionItemReason, AttentionItemState,
    AttentionSourceSnapshot,
};
use automonique_protocol::platform_v2_attention::{
    AttentionSource, AttentionSourceId, AttentionSourceKind,
};
use automonique_protocol::platform_v2_attention_api::encode_attention_source_snapshot;
use automonique_protocol::primitives::Revision;
use automonique_protocol::wire::JsonValue;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

/// The schema of the document this example prints. `run_attention_live_parity.py`
/// refuses anything else, so a build that changes the shape cannot be replayed
/// by a harness written against the old one.
const CAPTURE_SCHEMA: &str = "automonique.attention-live-capture/v1";

/// The same page size the hosted cockpit's `inventory()` walk asks for. Reading
/// the graph in a different number of pages than the surface under test would
/// make a cursor-boundary difference look like a client disagreement.
const WORK_CONTEXT_PAGE_LIMIT: u16 = 128;

/// The offer the hosted cockpit's bridge sends. Offering only `2` would make a
/// v1-only deployment look unreachable rather than downgraded.
const VERSION_OFFER: [u16; 2] = [1, 2];

/// A walk is bounded so a deployment that keeps handing out cursors cannot make
/// this example run forever.
const MAX_WORK_CONTEXT_PAGES: usize = 64;

fn object(entries: Vec<(&str, JsonValue)>) -> JsonValue {
    let mut entries: Vec<(String, JsonValue)> = entries
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    JsonValue::Object(entries)
}

fn text(value: impl Into<String>) -> JsonValue {
    JsonValue::String(value.into())
}

struct Arguments {
    endpoint: String,
    credential_env: String,
    projects: Vec<String>,
    workspaces: Vec<String>,
    sources: Vec<String>,
    review_probe: bool,
    control: bool,
    timeout_seconds: u64,
}

fn usage() -> String {
    concat!(
        "usage: attention_live_capture --endpoint <url> --credential-env <NAME>\n",
        "                             [--project <id>]... [--user-workspace <id>]...\n",
        "                             [--source <kind:id>]... [--review-probe]\n",
        "                             [--control]\n",
        "                             [--timeout-seconds <n>]\n",
    )
    .to_owned()
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut endpoint = None;
    let mut credential_env = None;
    let mut projects = Vec::new();
    let mut workspaces = Vec::new();
    let mut sources = Vec::new();
    let mut review_probe = false;
    let mut control = false;
    let mut timeout_seconds = 20;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let mut value = || {
            arguments
                .next()
                .ok_or_else(|| format!("{argument} needs a value"))
        };
        match argument.as_str() {
            "--endpoint" => endpoint = Some(value()?),
            "--credential-env" => credential_env = Some(value()?),
            "--project" => projects.push(value()?),
            "--user-workspace" => workspaces.push(value()?),
            "--source" => sources.push(value()?),
            "--review-probe" => review_probe = true,
            "--control" => control = true,
            "--timeout-seconds" => {
                timeout_seconds = value()?
                    .parse()
                    .map_err(|_| "--timeout-seconds is not a number".to_owned())?;
            }
            "--help" | "-h" => return Err(usage()),
            other => return Err(format!("unknown argument {other}\n{}", usage())),
        }
    }
    Ok(Arguments {
        endpoint: match (endpoint, control) {
            (Some(endpoint), _) => endpoint,
            // The control document is produced without touching the network.
            (None, true) => String::new(),
            (None, false) => return Err(format!("--endpoint is required\n{}", usage())),
        },
        credential_env: match (credential_env, control) {
            (Some(name), _) => name,
            (None, true) => String::new(),
            (None, false) => {
                return Err(format!("--credential-env is required\n{}", usage()));
            }
        },
        projects,
        workspaces,
        sources,
        review_probe,
        control,
        timeout_seconds,
    })
}

/// Split `user:password` without ever reproducing either half.
///
/// The value is taken from the environment by name and handed straight to
/// `BasicCredential`, which zeroizes it. Nothing here formats it, and the error
/// path says only that the variable was unusable.
fn credential(variable: &str) -> Result<BasicCredential, String> {
    let raw = std::env::var(variable)
        .map_err(|_| format!("environment variable {variable} is not set"))?;
    let (user, password) = raw
        .split_once(':')
        .ok_or_else(|| format!("environment variable {variable} is not `user:password`"))?;
    BasicCredential::new(user, password)
        .map_err(|_| format!("environment variable {variable} is not a usable Basic credential"))
}

fn parse_source(value: &str) -> Result<AttentionSource, String> {
    let (kind, id) = value
        .split_once(':')
        .ok_or_else(|| format!("--source {value} is not `kind:id`"))?;
    let kind = match kind {
        "review" => AttentionSourceKind::Review,
        "orchestration" => AttentionSourceKind::Orchestration,
        "provider_session" => AttentionSourceKind::ProviderSession,
        other => {
            return Err(format!(
                "--source kind {other} is not an attention source kind"
            ));
        }
    };
    let id = AttentionSourceId::new(id.to_owned())
        .map_err(|_| format!("--source id in {value} is not a source id"))?;
    Ok(AttentionSource::new(kind, id))
}

fn source_json(source: &AttentionSource) -> JsonValue {
    object(vec![
        ("kind", text(source.kind().as_str())),
        ("id", text(source.id().as_str())),
    ])
}

/// Record a transport failure as a fact about the read rather than aborting.
///
/// A deployment that cannot be reached, or that answers something this client
/// refuses, is a live observation the parity harness has to be able to state.
/// Turning it into a non-zero exit would lose which read failed and how.
fn client_error(error: PlatformV2ClientError) -> JsonValue {
    object(vec![
        ("state", text("error")),
        ("category", text(error.category())),
    ])
}

fn refusal(category: &str) -> JsonValue {
    object(vec![
        ("state", text("refused")),
        ("category", text(category)),
    ])
}

/// Carry canonical bytes through the document without re-serializing them.
///
/// Every client that replays this capture decodes it with its own production
/// decoder, and a decoder is only meaningful over the exact bytes the
/// deployment produced. Nesting the parsed value instead would make the
/// harness, not the deployment, the author of what the clients decode: the
/// re-serialization would have to reproduce canonical form byte for byte, and
/// any disagreement about escaping or key order would silently become a
/// disagreement about attention. Base64 has no such freedom.
fn canonical(bytes: &[u8]) -> JsonValue {
    text(BASE64.encode(bytes))
}

fn walk_work_contexts(
    client: &mut PlatformV2Client<HttpsTransport>,
    project: Option<ProjectId>,
) -> JsonValue {
    let mut pages = Vec::new();
    let mut after: Option<WorkContextCursor> = None;
    loop {
        let query = match WorkContextQuery::new(
            WorkContextKind::ALL.to_vec(),
            Vec::new(),
            project.clone(),
            None,
            after.clone(),
            WORK_CONTEXT_PAGE_LIMIT,
        ) {
            Ok(query) => query,
            Err(_) => return refusal("work_context_query_invalid"),
        };
        match client.query_work_contexts(query) {
            Ok(WorkContextQueryResult::Page(page)) => {
                let next = page.next_cursor().cloned();
                match encode_work_context_page(&page) {
                    Ok(bytes) => pages.push(canonical(&bytes)),
                    Err(_) => return refusal("work_context_page_not_encodable"),
                }
                match next {
                    Some(cursor) if pages.len() < MAX_WORK_CONTEXT_PAGES => after = Some(cursor),
                    // A walk that did not reach the end carries no records: a
                    // partial graph would derive a short source inventory, and
                    // a short inventory is exactly the partial board every
                    // client is supposed to refuse.
                    Some(_) => return refusal("work_context_walk_exceeds_bound"),
                    None => break,
                }
            }
            Ok(WorkContextQueryResult::Resync(_)) => {
                return refusal("work_context_resync_required");
            }
            Ok(WorkContextQueryResult::Refused(value)) => {
                return refusal(value.category().as_str());
            }
            Err(error) => return client_error(error),
        }
    }
    object(vec![
        ("state", text("available")),
        ("pages_canonical_base64", JsonValue::Array(pages)),
    ])
}

fn review_presence(
    client: &mut PlatformV2Client<HttpsTransport>,
    project: &ProjectId,
    workspace: &UserWorkspaceId,
) -> JsonValue {
    let identity = WorkContextIdentity::UserWorkspace(workspace.clone());
    match client.get_review(project.clone(), identity) {
        Ok(ReviewReadResult::Snapshot(_)) => object(vec![
            ("state", text("available")),
            ("presence", text("present")),
        ]),
        // The hosted cockpit reads exactly this distinction: the review source
        // exists when `get_review` answers, and is absent only on the typed
        // not-found refusal. Any other category leaves presence unknown, and an
        // unknown presence must not be guessed as `absent` — that would drop a
        // source from the inventory and hide items.
        Ok(ReviewReadResult::Refused(value)) => {
            let category = value.category().as_str().to_owned();
            if category.contains("not_found") {
                object(vec![
                    ("state", text("available")),
                    ("presence", text("absent")),
                ])
            } else {
                refusal(&category)
            }
        }
        Err(error) => client_error(error),
    }
}

fn read_sources(
    client: &mut PlatformV2Client<HttpsTransport>,
    arguments: &Arguments,
) -> Result<JsonValue, String> {
    if arguments.projects.len() != 1 || arguments.workspaces.len() != 1 {
        return Err(
            "--source needs exactly one --project and one --user-workspace to read against"
                .to_owned(),
        );
    }
    let project = ProjectId::new(arguments.projects[0].clone())
        .map_err(|_| "--project is not a project id".to_owned())?;
    let workspace = UserWorkspaceId::new(arguments.workspaces[0].clone())
        .map_err(|_| "--user-workspace is not a user workspace id".to_owned())?;
    let mut seen = BTreeSet::new();
    let mut reads = Vec::new();
    for raw in &arguments.sources {
        let source = parse_source(raw)?;
        if !seen.insert(source.clone()) {
            return Err(format!("--source {raw} was given twice"));
        }
        let read = match client.get_attention_source_snapshot(
            source.clone(),
            project.clone(),
            workspace.clone(),
        ) {
            Ok(AttentionReadResult::Snapshot(snapshot)) => {
                let bytes = encode_attention_source_snapshot(&snapshot)
                    .map_err(|_| "snapshot did not re-encode".to_owned())?;
                object(vec![
                    ("kind", text("snapshot")),
                    ("snapshot_canonical_base64", canonical(&bytes)),
                ])
            }
            Ok(AttentionReadResult::Refused(value)) => object(vec![
                ("kind", text("refusal")),
                ("category", text(value.category().as_str())),
            ]),
            // A transport failure is not a refusal: the server said nothing.
            // The clients' own vocabulary for that is `unavailable(transport)`,
            // and naming it as such here keeps the replay from inventing a
            // server category the server never sent.
            Err(error) => object(vec![
                ("kind", text("unavailable")),
                ("reason", text("transport")),
                ("client_error", text(error.category())),
            ]),
        };
        reads.push(object(vec![
            ("source", source_json(&source)),
            ("read", read),
        ]));
    }
    Ok(JsonValue::Array(reads))
}

// --- Positive control ------------------------------------------------------

/// The exact target the shared conformance corpus uses, so a reader comparing
/// this control against `platform-v2-attention-conformance-v1.json` sees the
/// same graph.
const CONTROL_PROJECT: &str = "project-conformance";
const CONTROL_WORKSPACE: &str = "workspace-conformance";
const CONTROL_ATTEMPT: &str = "attempt-conformance";
const CONTROL_SESSION: &str = "session-conformance";
const CONTROL_CHECKOUT: &str = "checkout-conformance";
const CONTROL_PLATFORM_SESSION: &str = "platform-session-conformance";

fn control_record(
    identity: WorkContextIdentity,
    lifecycle: WorkContextLifecycle,
    relations: Vec<(WorkContextRelationKind, WorkContextIdentity)>,
) -> Result<WorkContextRecord, String> {
    let relations = relations
        .into_iter()
        .map(|(kind, target)| WorkContextRelation::new(kind, target))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "control relation invalid".to_owned())?;
    WorkContextRecord::new(
        identity,
        Revision::FIRST,
        lifecycle,
        WorkContextLabel::new("control".to_owned())
            .map_err(|_| "control label invalid".to_owned())?,
        WorkContextAttributes::EMPTY,
        relations,
    )
    .map_err(|_| "control record invalid".to_owned())
}

fn control_item(id: &str, revision: u64, observed_at_ms: u64) -> Result<AttentionItem, String> {
    AttentionItem::new(
        AttentionItemId::new(id.to_owned()).map_err(|_| "control item id invalid".to_owned())?,
        Revision::new(revision).map_err(|_| "control item revision invalid".to_owned())?,
        observed_at_ms,
        AttentionItemState::NeedsYou,
        AttentionItemReason::ReviewRequested,
        true,
        Vec::new(),
        None,
    )
    .map_err(|_| "control item invalid".to_owned())
}

fn control_snapshot(
    source: &AttentionSource,
    revision: u64,
    previous: Option<u64>,
    items: Vec<AttentionItem>,
) -> Result<JsonValue, String> {
    let snapshot = AttentionSourceSnapshot::new(
        source.clone(),
        ProjectId::new(CONTROL_PROJECT.to_owned())
            .map_err(|_| "control project invalid".to_owned())?,
        UserWorkspaceId::new(CONTROL_WORKSPACE.to_owned())
            .map_err(|_| "control workspace invalid".to_owned())?,
        Revision::new(revision).map_err(|_| "control revision invalid".to_owned())?,
        previous
            .map(|value| Revision::new(value).map_err(|_| "control revision invalid".to_owned()))
            .transpose()?,
        1_000 * revision,
        items,
    )
    .map_err(|_| "control snapshot invalid".to_owned())?;
    let bytes = encode_attention_source_snapshot(&snapshot)
        .map_err(|_| "control snapshot did not encode".to_owned())?;
    Ok(object(vec![
        ("kind", text("snapshot")),
        ("snapshot_canonical_base64", canonical(&bytes)),
    ]))
}

/// Emit a replay input whose answer is known, using the same encoders a live
/// capture uses.
///
/// The live comparison has a failure mode that would look exactly like success:
/// three replay drivers that decode nothing, show nothing, and therefore agree.
/// This control is the fence against it. It carries a real record graph and a
/// real two-generation succession, so a driver that is not actually driving its
/// client's reducer cannot reproduce it, and the harness refuses to report a
/// live agreement until every driver has reproduced this one.
fn control_document() -> Result<JsonValue, String> {
    let project = ProjectId::new(CONTROL_PROJECT.to_owned())
        .map_err(|_| "control project invalid".to_owned())?;
    let workspace = UserWorkspaceId::new(CONTROL_WORKSPACE.to_owned())
        .map_err(|_| "control workspace invalid".to_owned())?;
    let attempt = AttemptWorkspaceId::new(CONTROL_ATTEMPT.to_owned())
        .map_err(|_| "control attempt invalid".to_owned())?;
    let session = WorkSessionId::new(CONTROL_SESSION.to_owned())
        .map_err(|_| "control session invalid".to_owned())?;
    let checkout = CheckoutId::new(CONTROL_CHECKOUT.to_owned())
        .map_err(|_| "control checkout invalid".to_owned())?;
    let platform_session = V1SessionRef::new(ResourceCoordinate::new(
        ResourceAuthority::Automonique,
        ResourceKind::Session,
        ResourceId::new(CONTROL_PLATFORM_SESSION.to_owned())
            .map_err(|_| "control platform session invalid".to_owned())?,
    ))
    .map_err(|_| "control platform session invalid".to_owned())?;

    let mut records = vec![
        control_record(
            WorkContextIdentity::UserWorkspace(workspace.clone()),
            WorkContextLifecycle::Active,
            vec![
                (
                    WorkContextRelationKind::UserWorkspaceProject,
                    WorkContextIdentity::Project(project),
                ),
                (
                    WorkContextRelationKind::UserWorkspaceCheckout,
                    WorkContextIdentity::Checkout(checkout),
                ),
            ],
        )?,
        control_record(
            WorkContextIdentity::AttemptWorkspace(attempt.clone()),
            WorkContextLifecycle::Running,
            vec![(
                WorkContextRelationKind::AttemptUserWorkspace,
                WorkContextIdentity::UserWorkspace(workspace),
            )],
        )?,
        control_record(
            WorkContextIdentity::Session(session),
            WorkContextLifecycle::Active,
            vec![
                (
                    WorkContextRelationKind::SessionAttemptWorkspace,
                    WorkContextIdentity::AttemptWorkspace(attempt),
                ),
                (
                    WorkContextRelationKind::SessionPlatformSession,
                    WorkContextIdentity::PlatformSession(platform_session),
                ),
            ],
        )?,
    ];
    records.sort_by(|left, right| left.identity().cmp(right.identity()));
    let page = WorkContextPage::new(WORK_CONTEXT_PAGE_LIMIT, None, None, false, records)
        .map_err(|_| "control page invalid".to_owned())?;
    let page =
        encode_work_context_page(&page).map_err(|_| "control page did not encode".to_owned())?;

    let source = AttentionSource::new(
        AttentionSourceKind::Review,
        AttentionSourceId::new(CONTROL_WORKSPACE.to_owned())
            .map_err(|_| "control source invalid".to_owned())?,
    );
    let first = control_snapshot(&source, 1, None, vec![control_item("item-a", 1, 1_000)?])?;
    let second = control_snapshot(
        &source,
        2,
        Some(1),
        vec![
            control_item("item-a", 2, 2_000)?,
            control_item("item-b", 2, 2_000)?,
        ],
    )?;
    let pass = |read: JsonValue| {
        object(vec![(
            "sources",
            JsonValue::Array(vec![object(vec![
                ("source", source_json(&source)),
                ("read", read),
            ])]),
        )])
    };
    Ok(object(vec![
        ("schema", text("automonique.attention-live-replay-input/v1")),
        (
            "target",
            object(vec![
                ("project", text(CONTROL_PROJECT)),
                ("user_workspace", text(CONTROL_WORKSPACE)),
            ]),
        ),
        ("review_presence", text("present")),
        (
            "work_context_pages_canonical_base64",
            JsonValue::Array(vec![canonical(&page)]),
        ),
        ("passes", JsonValue::Array(vec![pass(first), pass(second)])),
        (
            "control_expectation",
            object(vec![
                ("inventory_contains", text("review:workspace-conformance")),
                ("final_generation", text("2")),
                (
                    "final_visible_items",
                    JsonValue::Array(vec![text("item-a"), text("item-b")]),
                ),
            ]),
        ),
    ]))
}

fn capture(arguments: &Arguments) -> Result<JsonValue, String> {
    let transport = HttpsTransport::new_basic(
        arguments.endpoint.clone(),
        credential(&arguments.credential_env)?,
    )
    .map_err(|error| format!("endpoint refused by the client: {}", error.category()))?
    .with_timeout(std::time::Duration::from_secs(arguments.timeout_seconds));
    let mut client = PlatformV2Client::new_https(transport);

    let offer = PlatformVersionOffer::new(VERSION_OFFER.to_vec())
        .map_err(|_| "version offer invalid".to_owned())?;
    let lane = match client.negotiate(offer) {
        Ok(NegotiationResult::V2(value)) => object(vec![
            ("state", text("negotiated")),
            (
                "version",
                JsonValue::Integer(i64::from(value.version() as u16)),
            ),
        ]),
        Ok(NegotiationResult::Downgraded(value)) => object(vec![
            ("state", text("downgraded")),
            (
                "version",
                JsonValue::Integer(i64::from(value.version() as u16)),
            ),
        ]),
        Ok(NegotiationResult::Refused(value)) => refusal(value.category().as_str()),
        Err(error) => client_error(error),
    };
    let negotiated = lane.get("state").and_then(JsonValue::as_str) == Some("negotiated");

    let mut entries = vec![
        ("schema", text(CAPTURE_SCHEMA)),
        ("endpoint", text(arguments.endpoint.clone())),
        ("credential_env", text(arguments.credential_env.clone())),
        ("lane", lane),
    ];

    if !negotiated {
        // Everything below this line needs a negotiated v2 lane. Reporting the
        // reads as "not attempted" is the difference between "the deployment
        // served nothing" and "the deployment was never asked".
        entries.push(("reads_attempted", JsonValue::Bool(false)));
        return Ok(object(entries));
    }
    entries.push(("reads_attempted", JsonValue::Bool(true)));

    if arguments.sources.is_empty() {
        let project = match arguments.projects.first() {
            Some(value) => Some(
                ProjectId::new(value.clone())
                    .map_err(|_| "--project is not a project id".to_owned())?,
            ),
            None => None,
        };
        entries.push((
            "work_contexts",
            walk_work_contexts(&mut client, project.clone()),
        ));
        if arguments.review_probe {
            let project = project
                .ok_or_else(|| "--review-probe needs a --project to ask against".to_owned())?;
            let mut probes = Vec::new();
            for workspace in &arguments.workspaces {
                let workspace = UserWorkspaceId::new(workspace.clone())
                    .map_err(|_| "--user-workspace is not a user workspace id".to_owned())?;
                probes.push(object(vec![
                    ("user_workspace", text(workspace.as_str())),
                    ("review", review_presence(&mut client, &project, &workspace)),
                ]));
            }
            entries.push(("review_probes", JsonValue::Array(probes)));
        }
    } else {
        entries.push(("sources", read_sources(&mut client, arguments)?));
    }
    Ok(object(entries))
}

fn main() -> ExitCode {
    let arguments = match parse_arguments() {
        Ok(arguments) => arguments,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    let document = if arguments.control {
        control_document()
    } else {
        capture(&arguments)
    };
    match document {
        Ok(document) => {
            // The document is the only thing on stdout, so a caller can
            // redirect it into a file that parses.
            println!(
                "{}",
                String::from_utf8_lossy(&document.to_canonical_bytes())
            );
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}
