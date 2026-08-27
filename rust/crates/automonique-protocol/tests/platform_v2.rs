// SPDX-License-Identifier: Elastic-2.0

use automonique_protocol::platform_v2::*;
use automonique_protocol::platform_v2_api::*;
use automonique_protocol::primitives::Revision;

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

#[test]
fn version_negotiation_prefers_v2_and_downgrades_truthfully() {
    let both = PlatformVersionOffer::new(vec![PlatformVersion::V2, PlatformVersion::V1]).unwrap();
    let v1 = PlatformVersionOffer::new(vec![PlatformVersion::V1]).unwrap();
    let v2 = PlatformVersionOffer::new(vec![PlatformVersion::V2]).unwrap();

    assert_eq!(
        negotiate_platform_version(&both, &both).unwrap(),
        NegotiatedPlatform {
            version: PlatformVersion::V2,
            schema: PLATFORM_SCHEMA_V2,
            work_context: WorkContextAvailability::V2Structured,
        }
    );
    assert_eq!(
        negotiate_platform_version(&both, &v1).unwrap(),
        NegotiatedPlatform {
            version: PlatformVersion::V1,
            schema: automonique_protocol::platform::PLATFORM_SCHEMA_V1,
            work_context: WorkContextAvailability::V1ExistingResourcesOnly,
        }
    );
    assert_eq!(
        negotiate_platform_version(&v1, &v2),
        Err(WorkContextError::VersionOverlapMissing)
    );
}

#[test]
fn structured_relations_admit_multiple_repositories_without_summary_identity() {
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
                WorkContextIdentity::Repository(WorkContextRepositoryId::new("repo-a").unwrap()),
            ),
            relation(
                WorkContextRelationKind::ProjectRepository,
                WorkContextIdentity::Repository(WorkContextRepositoryId::new("repo-b").unwrap()),
            ),
        ],
    )
    .unwrap();
    let host = WorkContextRecord::new(
        WorkContextIdentity::HostSetup(HostSetupId::new("host-1").unwrap()),
        Revision::FIRST,
        WorkContextLifecycle::Active,
        label("Remote builder"),
        WorkContextAttributes {
            host_setup: Some(HostSetupKind::Ssh),
            checkout: None,
        },
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
        WorkContextAttributes {
            host_setup: None,
            checkout: Some(CheckoutKind::GitWorktree),
        },
        vec![
            relation(
                WorkContextRelationKind::CheckoutProject,
                WorkContextIdentity::Project(project_id.clone()),
            ),
            relation(
                WorkContextRelationKind::CheckoutHostSetup,
                host.identity.clone(),
            ),
            relation(
                WorkContextRelationKind::CheckoutRepository,
                WorkContextIdentity::Repository(WorkContextRepositoryId::new("repo-a").unwrap()),
            ),
        ],
    )
    .unwrap();
    let local_host = WorkContextRecord::new(
        WorkContextIdentity::HostSetup(HostSetupId::new("host-local").unwrap()),
        Revision::FIRST,
        WorkContextLifecycle::Active,
        label("Local registry"),
        WorkContextAttributes {
            host_setup: Some(HostSetupKind::Local),
            checkout: None,
        },
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
        WorkContextAttributes {
            host_setup: None,
            checkout: Some(CheckoutKind::AuthorizedFolder),
        },
        vec![
            relation(
                WorkContextRelationKind::CheckoutProject,
                WorkContextIdentity::Project(project_id.clone()),
            ),
            relation(
                WorkContextRelationKind::CheckoutHostSetup,
                local_host.identity.clone(),
            ),
            relation(
                WorkContextRelationKind::CheckoutRepository,
                WorkContextIdentity::Repository(WorkContextRepositoryId::new("repo-b").unwrap()),
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
                WorkContextIdentity::Project(project_id),
            ),
            relation(
                WorkContextRelationKind::UserWorkspaceCheckout,
                checkout.identity.clone(),
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
            user_workspace.identity.clone(),
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
                attempt.identity.clone(),
            ),
            relation(
                WorkContextRelationKind::SessionPlatformSession,
                WorkContextIdentity::PlatformSession(
                    PlatformSessionId::new("platform-session-1").unwrap(),
                ),
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
            session.identity.clone(),
        )],
    )
    .unwrap();

    assert_eq!(project.relations.len(), 2);
    assert_eq!(host.attributes.host_setup, Some(HostSetupKind::Ssh));
    assert_eq!(
        checkout.attributes.checkout,
        Some(CheckoutKind::GitWorktree)
    );
    assert_eq!(
        authorized_folder.attributes.checkout,
        Some(CheckoutKind::AuthorizedFolder)
    );
    assert!(
        !encode_work_context_page(
            &WorkContextPage::new(
                9,
                None,
                None,
                false,
                vec![
                    project,
                    host,
                    checkout,
                    local_host,
                    authorized_folder,
                    user_workspace,
                    attempt,
                    session,
                    pane,
                ],
            )
            .unwrap()
        )
        .unwrap()
        .windows(5)
        .any(|bytes| bytes == b"/home")
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
            attempt.identity,
            Revision::FIRST,
            WorkContextLifecycle::Archived,
            label("invalid"),
            WorkContextAttributes::EMPTY,
            attempt.relations,
        ),
        Err(WorkContextError::LifecycleInvalid)
    );
}

#[test]
fn exact_query_and_page_codecs_refuse_shape_and_semantic_drift() {
    let query = WorkContextQuery::new(
        vec![WorkContextKind::Session, WorkContextKind::Project],
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
        vec![project(1)],
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
    assert_eq!(
        WorkContextPage::new(1, None, None, true, vec![project(2)]),
        Err(WorkContextError::PageCursorInvalid)
    );
}

#[test]
fn inventory_above_512_remains_available_through_bounded_pages() {
    let inventory: Vec<WorkContextRecord> = (0..640).map(project).collect();
    let mut decoded = Vec::new();
    let mut after = None;
    for page_index in 0..5 {
        let has_more = page_index < 4;
        let next_cursor =
            has_more.then(|| WorkContextCursor::new(format!("page-{}", page_index + 1)).unwrap());
        let page = WorkContextPage::new(
            128,
            after.clone(),
            next_cursor.clone(),
            has_more,
            inventory[page_index * 128..(page_index + 1) * 128].to_vec(),
        )
        .unwrap();
        let round_trip =
            decode_work_context_page(&encode_work_context_page(&page).unwrap()).unwrap();
        assert!(round_trip.items.len() <= MAX_WORK_CONTEXT_PAGE_ITEMS);
        decoded.extend(round_trip.items);
        after = next_cursor;
    }

    assert_eq!(decoded.len(), 640);
    assert_eq!(decoded.first().unwrap().identity.id(), "project-0");
    assert_eq!(decoded.last().unwrap().identity.id(), "project-639");
}
