// SPDX-License-Identifier: Elastic-2.0

use automonique_protocol::platform::{
    ResourceAuthority, ResourceCoordinate, ResourceId, ResourceKind,
};
use automonique_protocol::platform_api::PlatformRequestMessage;
use automonique_protocol::platform_v2::*;
use automonique_protocol::platform_v2_api::*;
use automonique_protocol::primitives::Revision;
use automonique_protocol::wire::{JsonValue, parse_canonical};
use std::path::PathBuf;
use std::process::Command;

fn label(value: &str) -> WorkContextLabel {
    WorkContextLabel::new(value).unwrap()
}

fn relation(kind: WorkContextRelationKind, target: WorkContextIdentity) -> WorkContextRelation {
    WorkContextRelation::new(kind, target).unwrap()
}

fn project(index: usize) -> WorkContextRecord {
    WorkContextRecord::new(
        WorkContextIdentity::Project(ProjectId::new(format!("project-{index}")).unwrap()),
        Revision::FIRST,
        WorkContextLifecycle::Active,
        label("Project"),
        WorkContextAttributes::EMPTY,
        Vec::new(),
    )
    .unwrap()
}

fn corpus_project() -> WorkContextRecord {
    WorkContextRecord::new(
        WorkContextIdentity::Project(ProjectId::new("project-0000").unwrap()),
        Revision::FIRST,
        WorkContextLifecycle::Active,
        label("Project"),
        WorkContextAttributes::EMPTY,
        vec![
            relation(
                WorkContextRelationKind::ProjectRepository,
                repository("\u{e000}", ResourceAuthority::GitHub),
            ),
            relation(
                WorkContextRelationKind::ProjectRepository,
                repository("😀", ResourceAuthority::GitHub),
            ),
        ],
    )
    .unwrap()
}

fn repository(id: &str, authority: ResourceAuthority) -> WorkContextIdentity {
    WorkContextIdentity::Repository(
        V1RepositoryRef::new(ResourceCoordinate::new(
            authority,
            ResourceKind::Repository,
            ResourceId::new(id).unwrap(),
        ))
        .unwrap(),
    )
}

fn platform_session(id: &str, authority: ResourceAuthority) -> WorkContextIdentity {
    WorkContextIdentity::PlatformSession(
        V1SessionRef::new(ResourceCoordinate::new(
            authority,
            ResourceKind::Session,
            ResourceId::new(id).unwrap(),
        ))
        .unwrap(),
    )
}

#[test]
fn version_negotiation_prefers_v2_and_downgrades_truthfully() {
    let both = PlatformVersionOffer::new(vec![1, 2]).unwrap();
    let v1 = PlatformVersionOffer::new(vec![1]).unwrap();
    let v2 = PlatformVersionOffer::new(vec![2]).unwrap();
    let future = PlatformVersionOffer::new(vec![1, 2, 3]).unwrap();

    assert_eq!(
        negotiate_platform_version(&both, &both).unwrap(),
        NegotiatedPlatform::new(
            PlatformVersion::V2,
            PLATFORM_SCHEMA_V2,
            WorkContextAvailability::V2Structured,
        )
        .unwrap()
    );
    assert_eq!(
        negotiate_platform_version(&future, &future).unwrap(),
        NegotiatedPlatform::new(
            PlatformVersion::V2,
            PLATFORM_SCHEMA_V2,
            WorkContextAvailability::V2Structured,
        )
        .unwrap()
    );
    assert_eq!(
        negotiate_platform_version(&both, &v1).unwrap(),
        NegotiatedPlatform::new(
            PlatformVersion::V1,
            automonique_protocol::platform::PLATFORM_SCHEMA_V1,
            WorkContextAvailability::V1ExistingResourcesOnly,
        )
        .unwrap()
    );
    assert_eq!(
        negotiate_platform_version(&v1, &v2),
        Err(WorkContextError::VersionOverlapMissing)
    );

    let offer_bytes = encode_platform_version_offer(&future).unwrap();
    assert_eq!(decode_platform_version_offer(&offer_bytes).unwrap(), future);
    let negotiated = negotiate_platform_version(&both, &both).unwrap();
    let negotiated_bytes = encode_negotiated_platform(&negotiated).unwrap();
    assert_eq!(
        decode_negotiated_platform(&negotiated_bytes).unwrap(),
        negotiated
    );
    let incoherent =
        br#"{"schema":"automonique.platform/v2","version":1,"work_context":"v2_structured"}"#;
    assert_eq!(
        decode_negotiated_platform(incoherent),
        Err(WorkContextApiError::Context(
            WorkContextError::NegotiatedPlatformInvalid
        ))
    );
    let repeated = br#"{"schema":"automonique.platform/negotiation/v1","versions":[1,1]}"#;
    assert_eq!(
        decode_platform_version_offer(repeated),
        Err(WorkContextApiError::Context(
            WorkContextError::VersionOfferInvalid
        ))
    );
}

#[test]
fn installed_v1_adapter_fixture_negotiates_and_decodes_without_v2_projection() {
    let installed_client = PlatformVersionOffer::new(vec![1]).unwrap();
    let current_server = PlatformVersionOffer::new(vec![1, 2]).unwrap();
    let negotiated = negotiate_platform_version(&installed_client, &current_server).unwrap();
    assert_eq!(negotiated.version(), PlatformVersion::V1);
    assert_eq!(
        negotiated.schema(),
        automonique_protocol::platform::PLATFORM_SCHEMA_V1
    );
    assert_eq!(
        negotiated.work_context(),
        WorkContextAvailability::V1ExistingResourcesOnly
    );

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../adapters/ag-ui/test/fixtures/platform-requests.json"
    );
    let fixture = std::fs::read_to_string(path).expect("installed v1 fixture is checked in");
    let JsonValue::Object(entries) =
        parse_canonical(fixture.trim().as_bytes()).expect("installed fixture is canonical JSON")
    else {
        panic!("installed v1 fixture is an object of canonical request strings");
    };
    assert!(!entries.is_empty());
    for (label, value) in entries {
        let JsonValue::String(bytes) = value else {
            panic!("{label}: fixture entry must be a canonical request string");
        };
        let decoded = PlatformRequestMessage::from_canonical_bytes(bytes.as_bytes())
            .unwrap_or_else(|error| {
                panic!("{label}: installed v1 request no longer decodes: {error}")
            });
        assert_eq!(
            decoded.to_message().unwrap().to_canonical_bytes(),
            bytes.as_bytes(),
            "{label}: v1 decoding must retain the exact canonical wire shape"
        );
    }
}

#[test]
fn authoritative_identity_issuance_uses_only_random_nonce_bytes() {
    let sensitive_inputs = [
        "/home/operator/repository",
        "owner/repository",
        "builder.internal.example",
        "provider-session-token",
        "Developer tools",
    ];
    let mut issued = std::collections::BTreeSet::new();
    for (index, kind) in WorkContextKind::ALL.into_iter().enumerate() {
        let mut nonce = [0xa5; 16];
        nonce[0] = u8::try_from(index).unwrap();
        let identity = issue_work_context_identity_from_random_nonce(kind, nonce);
        assert_eq!(identity.kind(), WorkContextTargetKind::from(kind));
        assert!(identity.id().starts_with("wc2_"));
        assert!(
            sensitive_inputs
                .iter()
                .all(|sensitive| !identity.id().contains(sensitive))
        );
        assert!(issued.insert(identity.id().to_owned()));
    }
    assert_eq!(issued.len(), WorkContextKind::ALL.len());

    // Admission is intentionally not issuance: rejecting slash-shaped opaque
    // values here would break legitimate upstream/client-selected IDs without
    // proving that an authoritative issuer kept sensitive inputs out.
    assert!(
        WorkContextIdentity::parse_local(WorkContextTargetKind::Project, "owner/repository")
            .is_ok()
    );
}

#[test]
fn one_project_spans_repositories_hosts_and_both_authorized_workspace_kinds() {
    let project_id = ProjectId::new("project-1").unwrap();
    let project = WorkContextRecord::new(
        WorkContextIdentity::Project(project_id.clone()),
        Revision::FIRST,
        WorkContextLifecycle::Active,
        label("Developer tools"),
        WorkContextAttributes::EMPTY,
        vec![
            relation(
                WorkContextRelationKind::ProjectRepository,
                repository("repo-a", ResourceAuthority::GitHub),
            ),
            relation(
                WorkContextRelationKind::ProjectRepository,
                repository("repo-b", ResourceAuthority::Automonique),
            ),
        ],
    )
    .unwrap();
    let host = WorkContextRecord::new(
        WorkContextIdentity::HostSetup(HostSetupId::new("host-1").unwrap()),
        Revision::FIRST,
        WorkContextLifecycle::Active,
        label("Remote builder"),
        WorkContextAttributes::host_setup(HostSetupKind::Ssh),
        vec![relation(
            WorkContextRelationKind::HostSetupProject,
            WorkContextIdentity::Project(project_id.clone()),
        )],
    )
    .unwrap();
    let checkout = WorkContextRecord::new(
        WorkContextIdentity::Checkout(CheckoutId::new("checkout-1").unwrap()),
        Revision::FIRST,
        WorkContextLifecycle::Active,
        label("Issue 166 checkout"),
        WorkContextAttributes::checkout(CheckoutKind::GitWorktree),
        vec![
            relation(
                WorkContextRelationKind::CheckoutProject,
                WorkContextIdentity::Project(project_id.clone()),
            ),
            relation(
                WorkContextRelationKind::CheckoutHostSetup,
                host.identity().clone(),
            ),
            relation(
                WorkContextRelationKind::CheckoutRepository,
                repository("repo-a", ResourceAuthority::GitHub),
            ),
        ],
    )
    .unwrap();
    let local_host = WorkContextRecord::new(
        WorkContextIdentity::HostSetup(HostSetupId::new("host-local").unwrap()),
        Revision::FIRST,
        WorkContextLifecycle::Active,
        label("Local registry"),
        WorkContextAttributes::host_setup(HostSetupKind::Local),
        vec![relation(
            WorkContextRelationKind::HostSetupProject,
            WorkContextIdentity::Project(project_id.clone()),
        )],
    )
    .unwrap();
    let authorized_folder = WorkContextRecord::new(
        WorkContextIdentity::Checkout(CheckoutId::new("checkout-folder").unwrap()),
        Revision::FIRST,
        WorkContextLifecycle::Active,
        label("Authorized folder"),
        WorkContextAttributes::checkout(CheckoutKind::AuthorizedFolder),
        vec![
            relation(
                WorkContextRelationKind::CheckoutProject,
                WorkContextIdentity::Project(project_id.clone()),
            ),
            relation(
                WorkContextRelationKind::CheckoutHostSetup,
                local_host.identity().clone(),
            ),
            relation(
                WorkContextRelationKind::CheckoutRepository,
                repository("repo-b", ResourceAuthority::Automonique),
            ),
        ],
    )
    .unwrap();
    let user_workspace = WorkContextRecord::new(
        WorkContextIdentity::UserWorkspace(UserWorkspaceId::new("user-workspace-1").unwrap()),
        Revision::FIRST,
        WorkContextLifecycle::Active,
        label("Issue workspace"),
        WorkContextAttributes::EMPTY,
        vec![
            relation(
                WorkContextRelationKind::UserWorkspaceProject,
                WorkContextIdentity::Project(project_id.clone()),
            ),
            relation(
                WorkContextRelationKind::UserWorkspaceCheckout,
                checkout.identity().clone(),
            ),
        ],
    )
    .unwrap();
    let folder_user_workspace = WorkContextRecord::new(
        WorkContextIdentity::UserWorkspace(UserWorkspaceId::new("user-workspace-folder").unwrap()),
        Revision::FIRST,
        WorkContextLifecycle::Active,
        label("Authorized-folder workspace"),
        WorkContextAttributes::EMPTY,
        vec![
            relation(
                WorkContextRelationKind::UserWorkspaceProject,
                WorkContextIdentity::Project(project_id),
            ),
            relation(
                WorkContextRelationKind::UserWorkspaceCheckout,
                authorized_folder.identity().clone(),
            ),
        ],
    )
    .unwrap();
    let attempt = WorkContextRecord::new(
        WorkContextIdentity::AttemptWorkspace(
            AttemptWorkspaceId::new("attempt-workspace-1").unwrap(),
        ),
        Revision::FIRST,
        WorkContextLifecycle::Running,
        label("Attempt"),
        WorkContextAttributes::EMPTY,
        vec![relation(
            WorkContextRelationKind::AttemptUserWorkspace,
            user_workspace.identity().clone(),
        )],
    )
    .unwrap();
    let session = WorkContextRecord::new(
        WorkContextIdentity::Session(WorkSessionId::new("work-session-1").unwrap()),
        Revision::FIRST,
        WorkContextLifecycle::Active,
        label("Session"),
        WorkContextAttributes::EMPTY,
        vec![
            relation(
                WorkContextRelationKind::SessionAttemptWorkspace,
                attempt.identity().clone(),
            ),
            relation(
                WorkContextRelationKind::SessionPlatformSession,
                platform_session("platform-session-1", ResourceAuthority::Automonique),
            ),
        ],
    )
    .unwrap();
    let pane = WorkContextRecord::new(
        WorkContextIdentity::Pane(PaneId::new("pane-1").unwrap()),
        Revision::FIRST,
        WorkContextLifecycle::Active,
        label("Terminal"),
        WorkContextAttributes::EMPTY,
        vec![relation(
            WorkContextRelationKind::PaneSession,
            session.identity().clone(),
        )],
    )
    .unwrap();

    assert_eq!(project.relations().len(), 2);
    assert_eq!(
        host.attributes().host_setup_kind(),
        Some(HostSetupKind::Ssh)
    );
    assert_eq!(
        local_host.attributes().host_setup_kind(),
        Some(HostSetupKind::Local)
    );
    assert_eq!(
        checkout.attributes().checkout_kind(),
        Some(CheckoutKind::GitWorktree)
    );
    assert_eq!(
        authorized_folder.attributes().checkout_kind(),
        Some(CheckoutKind::AuthorizedFolder)
    );
    let mut records = vec![
        project,
        host,
        checkout,
        local_host,
        authorized_folder,
        user_workspace,
        folder_user_workspace,
        attempt,
        session,
        pane,
    ];
    records.sort_by(|left, right| left.identity().cmp(right.identity()));
    let encoded =
        encode_work_context_page(&WorkContextPage::new(10, None, None, false, records).unwrap())
            .unwrap();
    assert!(!encoded.windows(5).any(|bytes| bytes == b"/home"));
    let encoded = String::from_utf8(encoded).unwrap();
    assert!(
        encoded.contains(r#""resource":{"authority":"github","id":"repo-a","kind":"repository"}"#)
    );
    assert!(
        encoded.contains(
            r#""resource":{"authority":"automonique","id":"repo-b","kind":"repository"}"#
        )
    );
    assert!(encoded.contains(r#""id":"user-workspace-1","kind":"user_workspace""#));
    assert!(encoded.contains(r#""id":"user-workspace-folder","kind":"user_workspace""#));
    assert!(encoded.contains(
        r#""resource":{"authority":"automonique","id":"platform-session-1","kind":"session"}"#
    ));

    assert_eq!(
        V1RepositoryRef::new(ResourceCoordinate::new(
            ResourceAuthority::GitHub,
            ResourceKind::Session,
            ResourceId::new("wrong-kind").unwrap(),
        )),
        Err(WorkContextError::V1CoordinateKindInvalid)
    );
}

#[test]
fn attempt_workspace_and_user_workspace_cannot_be_confused() {
    let user = WorkContextIdentity::UserWorkspace(UserWorkspaceId::new("workspace-1").unwrap());
    let attempt = WorkContextRecord::new(
        WorkContextIdentity::AttemptWorkspace(
            AttemptWorkspaceId::new("attempt-workspace-1").unwrap(),
        ),
        Revision::FIRST,
        WorkContextLifecycle::Running,
        label("Attempt workspace"),
        WorkContextAttributes::EMPTY,
        vec![relation(
            WorkContextRelationKind::AttemptUserWorkspace,
            user,
        )],
    )
    .unwrap();

    assert_eq!(attempt.kind(), WorkContextKind::AttemptWorkspace);
    assert_eq!(
        WorkContextRecord::new(
            attempt.identity().clone(),
            Revision::FIRST,
            WorkContextLifecycle::Archived,
            label("invalid"),
            WorkContextAttributes::EMPTY,
            attempt.relations().to_vec(),
        ),
        Err(WorkContextError::LifecycleInvalid)
    );
}

#[test]
fn exact_query_and_page_codecs_refuse_shape_and_semantic_drift() {
    let query = WorkContextQuery::new(
        vec![WorkContextKind::Project, WorkContextKind::Session],
        vec![WorkContextLifecycle::Active],
        Some(ProjectId::new("project-1").unwrap()),
        None,
        Some(WorkContextCursor::new("cursor-1").unwrap()),
        64,
    )
    .unwrap();
    let query_bytes = encode_work_context_query(&query).unwrap();
    assert_eq!(decode_work_context_query(&query_bytes).unwrap(), query);

    let page = WorkContextPage::new(
        64,
        Some(WorkContextCursor::new("cursor-1").unwrap()),
        Some(WorkContextCursor::new("cursor-2").unwrap()),
        true,
        vec![corpus_project()],
    )
    .unwrap();
    let page_bytes = encode_work_context_page(&page).unwrap();
    assert_eq!(decode_work_context_page(&page_bytes).unwrap(), page);

    let with_extra = String::from_utf8(query_bytes)
        .expect("canonical JSON")
        .replace(
            "\"after\":\"cursor-1\",",
            "\"after\":\"cursor-1\",\"host_path\":\"/tmp\",",
        );
    assert_eq!(
        decode_work_context_query(with_extra.as_bytes()),
        Err(WorkContextApiError::InvalidBody)
    );
    let duplicate = String::from_utf8(encode_work_context_query(&query).unwrap())
        .unwrap()
        .replace(
            "\"kinds\":[\"project\",\"session\"]",
            "\"kinds\":[\"project\",\"project\"]",
        );
    assert_eq!(
        decode_work_context_query(duplicate.as_bytes()),
        Err(WorkContextApiError::Context(
            WorkContextError::QueryOrderInvalid
        ))
    );
    let unordered = String::from_utf8(encode_work_context_query(&query).unwrap())
        .unwrap()
        .replace(
            "\"kinds\":[\"project\",\"session\"]",
            "\"kinds\":[\"session\",\"project\"]",
        );
    assert_eq!(
        decode_work_context_query(unordered.as_bytes()),
        Err(WorkContextApiError::Context(
            WorkContextError::QueryOrderInvalid
        ))
    );
    assert_eq!(
        WorkContextPage::new(1, None, None, true, vec![project(2)]),
        Err(WorkContextError::PageCursorInvalid)
    );
    assert_eq!(
        WorkContextPage::new(2, None, None, false, vec![project(2), project(1)]),
        Err(WorkContextError::PageOrderInvalid)
    );
    assert_eq!(
        WorkContextPage::new(2, None, None, false, vec![project(1), project(1)]),
        Err(WorkContextError::PageOrderInvalid)
    );
}

#[test]
fn multi_kind_pager_uses_the_page_identity_order() {
    let project = project(7);
    let WorkContextIdentity::Project(project_id) = project.identity().clone() else {
        unreachable!("project helper always builds a project identity");
    };
    let project_identity = project.identity().clone();
    let host = WorkContextRecord::new(
        WorkContextIdentity::HostSetup(HostSetupId::new("host-mixed").unwrap()),
        Revision::FIRST,
        WorkContextLifecycle::Active,
        label("Mixed host"),
        WorkContextAttributes::host_setup(HostSetupKind::Local),
        vec![relation(
            WorkContextRelationKind::HostSetupProject,
            project_identity.clone(),
        )],
    )
    .unwrap();
    let inventory = vec![
        AuthorizedWorkContextRecord::new(host, project_id.clone(), vec![project_identity]).unwrap(),
        AuthorizedWorkContextRecord::new(project, project_id, Vec::new()).unwrap(),
    ];
    let query = WorkContextQuery::new(
        vec![WorkContextKind::Project, WorkContextKind::HostSetup],
        Vec::new(),
        None,
        None,
        None,
        2,
    )
    .unwrap();

    let WorkContextQueryResult::Page(page) =
        page_authorized_work_context(&query, &inventory).unwrap()
    else {
        panic!("a fresh mixed-kind query must return a page");
    };
    assert_eq!(
        page.items()
            .iter()
            .map(WorkContextRecord::kind)
            .collect::<Vec<_>>(),
        vec![WorkContextKind::Project, WorkContextKind::HostSetup]
    );
    assert_eq!(
        decode_work_context_page(&encode_work_context_page(&page).unwrap()).unwrap(),
        page
    );
}

#[test]
fn authorized_query_remains_functional_beyond_v1s_512_resource_ceiling() {
    let inventory: Vec<AuthorizedWorkContextRecord> = (0..640)
        .map(|index| {
            AuthorizedWorkContextRecord::new(
                project(index),
                ProjectId::new(format!("project-{index}")).unwrap(),
                Vec::new(),
            )
            .unwrap()
        })
        .collect();
    let mut decoded = Vec::new();
    let mut after = None;
    let mut pages = 0;
    let first_cursor = loop {
        let query = WorkContextQuery::new(
            vec![WorkContextKind::Project],
            Vec::new(),
            None,
            None,
            after.clone(),
            128,
        )
        .unwrap();
        assert_eq!(
            decode_work_context_query(&encode_work_context_query(&query).unwrap()).unwrap(),
            query
        );
        let WorkContextQueryResult::Page(page) =
            page_authorized_work_context(&query, &inventory).unwrap()
        else {
            panic!("unchanged authorized inventory must not expire its cursor");
        };
        pages += 1;
        let next = page.next_cursor().cloned();
        let has_more = page.has_more();
        let round_trip =
            decode_work_context_page(&encode_work_context_page(&page).unwrap()).unwrap();
        assert!(round_trip.items().len() <= MAX_WORK_CONTEXT_PAGE_ITEMS);
        decoded.extend(round_trip.into_items());
        if !has_more {
            break after.expect("a five-page inventory has a continuation");
        }
        after = next;
    };

    assert_eq!(pages, 5);
    assert_eq!(decoded.len(), 640);
    let unique: std::collections::BTreeSet<&str> = decoded
        .iter()
        .map(|record| record.identity().id())
        .collect();
    assert_eq!(unique.len(), 640);

    let mut changed_inventory = inventory;
    changed_inventory.push(
        AuthorizedWorkContextRecord::new(
            project(640),
            ProjectId::new("project-640").unwrap(),
            Vec::new(),
        )
        .unwrap(),
    );
    let resumed_query = WorkContextQuery::new(
        vec![WorkContextKind::Project],
        Vec::new(),
        None,
        None,
        Some(first_cursor.clone()),
        128,
    )
    .unwrap();
    let WorkContextQueryResult::Resync(resync) =
        page_authorized_work_context(&resumed_query, &changed_inventory).unwrap()
    else {
        panic!("a cursor bound to a changed inventory must require replacement");
    };
    assert_eq!(resync.expired_after(), &first_cursor);
    let encoded = encode_work_context_resync(&resync).unwrap();
    assert_eq!(decode_work_context_resync(&encoded).unwrap(), resync);
}

#[test]
fn rust_and_typescript_exchange_the_same_valid_corpus() {
    if !Command::new("bun")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
    {
        return;
    }
    let package =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../sdk/typescript/packages/protocol");
    let fixture = package.join("conformance/work-context-runtime.ts");
    let typescript = Command::new("bun")
        .arg(&fixture)
        .arg("encode-corpus")
        .current_dir(&package)
        .output()
        .expect("TypeScript work-context fixture starts");
    assert!(
        typescript.status.success(),
        "TypeScript corpus encode failed: {}",
        String::from_utf8_lossy(&typescript.stderr)
    );
    let documents: Vec<Vec<u8>> = String::from_utf8(typescript.stdout)
        .unwrap()
        .lines()
        .map(decode_hex)
        .collect();
    assert_eq!(documents.len(), 4);
    let offer = PlatformVersionOffer::new(vec![1, 2, 3]).unwrap();
    let negotiated = negotiate_platform_version(&offer, &offer).unwrap();
    let query = WorkContextQuery::new(
        vec![WorkContextKind::Project],
        vec![WorkContextLifecycle::Active],
        None,
        None,
        None,
        128,
    )
    .unwrap();
    let page = WorkContextPage::new(128, None, None, false, vec![corpus_project()]).unwrap();
    let expected_documents = vec![
        encode_platform_version_offer(&offer).unwrap(),
        encode_negotiated_platform(&negotiated).unwrap(),
        encode_work_context_query(&query).unwrap(),
        encode_work_context_page(&page).unwrap(),
    ];
    assert_eq!(documents, expected_documents);
    assert_eq!(decode_platform_version_offer(&documents[0]).unwrap(), offer);
    assert_eq!(
        decode_negotiated_platform(&documents[1]).unwrap(),
        negotiated
    );
    assert_eq!(decode_work_context_query(&documents[2]).unwrap(), query);
    assert_eq!(decode_work_context_page(&documents[3]).unwrap(), page);

    let decoded = Command::new("bun")
        .arg(&fixture)
        .arg("decode-corpus")
        .args(expected_documents.iter().map(|bytes| encode_hex(bytes)))
        .current_dir(package)
        .output()
        .expect("TypeScript work-context fixture starts");
    assert!(
        decoded.status.success(),
        "TypeScript corpus decode failed: {}",
        String::from_utf8_lossy(&decoded.stderr)
    );
    let expected_round_trip = expected_documents
        .iter()
        .map(|bytes| encode_hex(bytes))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    assert_eq!(
        String::from_utf8_lossy(&decoded.stdout),
        expected_round_trip
    );

    let valid_query = String::from_utf8(encode_work_context_query(&query).unwrap()).unwrap();
    let valid_page = String::from_utf8(encode_work_context_page(&page).unwrap()).unwrap();
    let items_start = valid_page.find("\"items\":[").unwrap() + "\"items\":[".len();
    let items_end = valid_page.find("],\"next_cursor\"").unwrap();
    let item = &valid_page[items_start..items_end];
    let duplicate_page = format!(
        "{}{item},{item}{}",
        &valid_page[..items_start],
        &valid_page[items_end..]
    );
    let replaced = |source: &str, from: &str, to: &str| {
        assert!(source.contains(from), "refusal mutation source is present");
        source.replacen(from, to, 1).into_bytes()
    };
    let refusals: Vec<(&str, Vec<u8>)> = vec![
        ("offer", br#"{"schema":"automonique.platform/negotiation/v1","versions":[1,1]}"#.to_vec()),
        ("negotiated", br#"{"schema":"automonique.platform/v2","version":1,"work_context":"v2_structured"}"#.to_vec()),
        ("query", br#"{"after":null,"kinds":["project","project"],"lifecycles":[],"limit":1,"parent":null,"project":null,"schema":"automonique.platform/v2"}"#.to_vec()),
        ("page", br#"{"after":null,"has_more":true,"items":[],"next_cursor":null,"requested_limit":1,"schema":"automonique.platform/v2"}"#.to_vec()),
        ("query", br#"{"after":null,"kinds":["project"],"lifecycles":[],"limit":129,"parent":null,"project":null,"schema":"automonique.platform/v2"}"#.to_vec()),
        ("page", br#"{"after":null,"has_more":false,"items":[{"attributes":{"checkout":null,"host_setup":null},"identity":{"id":"project-1","kind":"project"},"label":"Project","lifecycle":"active","relations":[{"kind":"project_repository","target":{"kind":"repository","resource":{"authority":"github","id":"repo-a","kind":"session"}}}],"revision":1}],"next_cursor":null,"requested_limit":1,"schema":"automonique.platform/v2"}"#.to_vec()),
        ("page", duplicate_page.into_bytes()),
        ("offer", br#"{"schema":"automonique.platform/negotiation/v9","versions":[1,2,3]}"#.to_vec()),
        ("offer", br#"{"schema":"automonique.platform/negotiation/v1","versions":[-1,2]}"#.to_vec()),
        ("offer", br#"{"schema":"automonique.platform/negotiation/v1","versions":[1,65536]}"#.to_vec()),
        ("offer", br#"{"schema":"automonique.platform/negotiation/v1","versions":[0,1]}"#.to_vec()),
        ("negotiated", br#"{"schema":"automonique.platform/v9","version":2,"work_context":"v2_structured"}"#.to_vec()),
        ("negotiated", br#"{"schema":"automonique.platform/v1","version":-1,"work_context":"v1_existing_resources_only"}"#.to_vec()),
        ("negotiated", br#"{"schema":"automonique.platform/v2","version":65536,"work_context":"v2_structured"}"#.to_vec()),
        ("negotiated", br#"{"schema":"automonique.platform/v3","version":3,"work_context":"v2_structured"}"#.to_vec()),
        ("query", replaced(&valid_query, "\"schema\":\"automonique.platform/v2\"", "\"schema\":\"automonique.platform/v9\"")),
        ("query", replaced(&valid_query, "\"limit\":128", "\"limit\":-1")),
        ("query", replaced(&valid_query, "\"limit\":128", "\"limit\":65536")),
        ("page", replaced(&valid_page, "\"schema\":\"automonique.platform/v2\"", "\"schema\":\"automonique.platform/v9\"")),
        ("page", replaced(&valid_page, "\"requested_limit\":128", "\"requested_limit\":-1")),
        ("page", replaced(&valid_page, "\"requested_limit\":128", "\"requested_limit\":65536")),
        ("page", replaced(&valid_page, "\"authority\":\"github\"", "\"authority\":\"future_authority\"")),
        ("page", replaced(&valid_page, "\"kind\":\"repository\"}", "\"kind\":\"future_kind\"}")),
        ("page", replaced(&valid_page, "\"revision\":1", "\"revision\":-1")),
        ("page", replaced(&valid_page, "\"revision\":1", "\"revision\":0")),
        ("page", replaced(&valid_page, "\"revision\":1", "\"revision\":9223372036854775808")),
    ];
    let categories: Vec<&str> = refusals
        .iter()
        .map(|(decoder, bytes)| work_context_refusal_category(decoder, bytes))
        .collect();
    let refused = Command::new("bun")
        .arg(&fixture)
        .arg("decode-refusal-corpus")
        .args(
            refusals
                .iter()
                .map(|(decoder, bytes)| format!("{decoder}:{}", encode_hex(bytes))),
        )
        .current_dir(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../../sdk/typescript/packages/protocol"),
        )
        .output()
        .expect("TypeScript work-context fixture starts");
    assert!(
        refused.status.success(),
        "TypeScript refusal corpus failed: {}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&refused.stdout),
        categories.join(",") + "\n"
    );

    let typescript_refusals = Command::new("bun")
        .arg(&fixture)
        .arg("encode-refusal-corpus")
        .current_dir(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../../sdk/typescript/packages/protocol"),
        )
        .output()
        .expect("TypeScript work-context refusal fixture starts");
    assert!(
        typescript_refusals.status.success(),
        "TypeScript refusal encode failed: {}",
        String::from_utf8_lossy(&typescript_refusals.stderr)
    );
    let mut typescript_refusal_count = 0;
    for line in String::from_utf8(typescript_refusals.stdout)
        .unwrap()
        .lines()
    {
        let mut fields = line.splitn(3, '\t');
        let decoder = fields.next().unwrap();
        let expected_category = fields.next().unwrap();
        let bytes = decode_hex(fields.next().unwrap());
        assert_eq!(
            work_context_refusal_category(decoder, &bytes),
            expected_category,
            "TypeScript-originated {decoder} refusal category drifted"
        );
        typescript_refusal_count += 1;
    }
    assert_eq!(typescript_refusal_count, 19);
}

fn work_context_refusal_category(decoder: &str, bytes: &[u8]) -> &'static str {
    match decoder {
        "offer" => decode_platform_version_offer(bytes).unwrap_err().category(),
        "negotiated" => decode_negotiated_platform(bytes).unwrap_err().category(),
        "query" => decode_work_context_query(bytes).unwrap_err().category(),
        "page" => decode_work_context_page(bytes).unwrap_err().category(),
        _ => panic!("unknown work-context refusal decoder {decoder}"),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("non-hex TypeScript corpus"),
            };
            digit(pair[0]) << 4 | digit(pair[1])
        })
        .collect()
}
