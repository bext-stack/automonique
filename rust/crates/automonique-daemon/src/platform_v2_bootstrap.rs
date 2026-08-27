// SPDX-License-Identifier: Elastic-2.0

//! Offline, operator-owned bootstrap for the Platform v2 authority graph.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

use automonique_protocol::digest::Sha256;
use automonique_protocol::platform::{
    ResourceAuthority, ResourceCoordinate, ResourceId, ResourceKind,
};
use automonique_protocol::platform_v2::{
    CheckoutId, CheckoutKind, HostSetupId, HostSetupKind, ProjectId, UserWorkspaceId,
    V1RepositoryRef, WorkContextAttributes, WorkContextIdentity, WorkContextLabel,
    WorkContextLifecycle, WorkContextRecord, WorkContextRelation, WorkContextRelationKind,
    WorkContextTargetKind,
};
use automonique_protocol::platform_v2_lifecycle::{ExpectedWorkContext, ExternalParentResolution};
use automonique_protocol::primitives::Revision;
use automonique_store::work_context_store::{
    WorkContextBootstrapExternal, WorkContextBootstrapState, WorkContextStore,
};
use nix::unistd::geteuid;
use serde::{Deserialize, Serialize};

use crate::{DaemonConfig, control_lock, ensure_private_dir, platform_v2_host};

const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_PROJECTS: usize = 128;
const MAX_GRAPH_RECORDS: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapMode {
    Plan,
    Apply,
    Verify,
}

#[derive(Debug, Serialize)]
pub struct BootstrapReport {
    pub mode: &'static str,
    pub state: &'static str,
    pub tenant: String,
    pub projects: usize,
    pub repositories: usize,
    pub records: usize,
    pub manifest_sha256: String,
    pub policy_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapDocument {
    version: u32,
    tenant: String,
    projects: Vec<ProjectDocument>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectDocument {
    id: String,
    label: String,
    repositories: Vec<RepositoryDocument>,
    host_setups: Vec<HostSetupDocument>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryDocument {
    authority: String,
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostSetupDocument {
    id: String,
    label: String,
    kind: String,
    checkouts: Vec<CheckoutDocument>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckoutDocument {
    id: String,
    label: String,
    kind: String,
    repository: RepositoryReferenceDocument,
    workspaces: Vec<UserWorkspaceDocument>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RepositoryReferenceDocument {
    authority: String,
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserWorkspaceDocument {
    id: String,
    label: String,
}

struct ValidatedBootstrap {
    tenant: String,
    projects: BTreeSet<ProjectId>,
    ownership: BTreeMap<WorkContextIdentity, ProjectId>,
    externals: Vec<WorkContextBootstrapExternal>,
    records: Vec<WorkContextRecord>,
}

pub fn run(
    config: &DaemonConfig,
    manifest_path: &Path,
    mode: BootstrapMode,
) -> Result<BootstrapReport, &'static str> {
    ensure_private_dir(&config.state_root, "state root")
        .map_err(|_| "platform_v2_bootstrap_state_insecure")?;
    ensure_private_dir(&config.state_dir(), "state directory")
        .map_err(|_| "platform_v2_bootstrap_state_insecure")?;
    let _lock = control_lock::ControlLock::acquire(config.control_lock_path()).map_err(
        |error| match error {
            control_lock::ControlLockError::Held => "platform_v2_bootstrap_daemon_running",
            control_lock::ControlLockError::InsecurePath => "platform_v2_bootstrap_lock_insecure",
            control_lock::ControlLockError::Io(_) => "platform_v2_bootstrap_lock_io",
        },
    )?;
    let bytes = read_manifest(manifest_path, geteuid().as_raw())?;
    let manifest_digest = Sha256::digest(&bytes).to_string();
    let document: BootstrapDocument =
        serde_json::from_slice(&bytes).map_err(|_| "platform_v2_bootstrap_manifest_invalid")?;
    let graph = validate_document(document)?;
    let policy_generation = platform_v2_host::verify_bootstrap_policy(
        &config.platform_v2_policy_path(),
        geteuid().as_raw(),
        &graph.tenant,
        &graph.projects,
        &graph.ownership,
    )?;
    let policy_digest = policy_generation.to_string();

    let store_path = config.platform_v2_work_context_path();
    let state = if store_path.exists() {
        let (store, compared) = match mode {
            BootstrapMode::Apply => {
                let mut store = WorkContextStore::open(&store_path)
                    .map_err(|_| "platform_v2_bootstrap_store_unavailable")?;
                let compared = store
                    .apply_bootstrap(&graph.tenant, &graph.externals, &graph.records)
                    .map_err(map_store_error)?;
                (store, compared)
            }
            BootstrapMode::Plan | BootstrapMode::Verify => {
                let store = WorkContextStore::open_read_only(&store_path)
                    .map_err(|_| "platform_v2_bootstrap_store_unavailable")?;
                let compared = store
                    .inspect_bootstrap(&graph.tenant, &graph.externals, &graph.records)
                    .map_err(map_store_error)?;
                (store, compared)
            }
        };
        if mode != BootstrapMode::Plan {
            if compared == WorkContextBootstrapState::Absent && mode == BootstrapMode::Verify {
                return Err("platform_v2_bootstrap_absent");
            }
            let verified_generation = platform_v2_host::verify_bootstrap_store(
                &config.platform_v2_policy_path(),
                geteuid().as_raw(),
                &store,
            )?;
            if verified_generation != policy_generation {
                return Err("platform_v2_bootstrap_policy_changed");
            }
        }
        compared
    } else {
        match mode {
            BootstrapMode::Plan => WorkContextBootstrapState::Absent,
            BootstrapMode::Verify => return Err("platform_v2_bootstrap_absent"),
            BootstrapMode::Apply => {
                let mut store = WorkContextStore::open(&store_path)
                    .map_err(|_| "platform_v2_bootstrap_store_unavailable")?;
                let state = store
                    .apply_bootstrap(&graph.tenant, &graph.externals, &graph.records)
                    .map_err(|_| "platform_v2_bootstrap_store_refused")?;
                let verified_generation = platform_v2_host::verify_bootstrap_store(
                    &config.platform_v2_policy_path(),
                    geteuid().as_raw(),
                    &store,
                )?;
                if verified_generation != policy_generation {
                    return Err("platform_v2_bootstrap_policy_changed");
                }
                state
            }
        }
    };
    Ok(BootstrapReport {
        mode: match mode {
            BootstrapMode::Plan => "plan",
            BootstrapMode::Apply => "apply",
            BootstrapMode::Verify => "verify",
        },
        state: match (mode, state) {
            (BootstrapMode::Apply, WorkContextBootstrapState::Absent) => "seeded",
            (_, WorkContextBootstrapState::Absent) => "absent",
            (_, WorkContextBootstrapState::Identical) => "identical",
        },
        tenant: graph.tenant,
        projects: graph.projects.len(),
        repositories: graph.externals.len(),
        records: graph.records.len(),
        manifest_sha256: manifest_digest,
        policy_sha256: policy_digest,
    })
}

fn map_store_error(
    error: automonique_store::work_context_store::WorkContextStoreError,
) -> &'static str {
    match error.category() {
        "bootstrap_partial" => "platform_v2_bootstrap_partial",
        "bootstrap_mismatch" => "platform_v2_bootstrap_mismatch",
        "bootstrap_downgrade" => "platform_v2_bootstrap_downgrade",
        _ => "platform_v2_bootstrap_store_refused",
    }
}

fn read_manifest(path: &Path, expected_uid: u32) -> Result<Vec<u8>, &'static str> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(nix::libc::ELOOP) {
                "platform_v2_bootstrap_manifest_insecure"
            } else {
                "platform_v2_bootstrap_manifest_io"
            }
        })?;
    let metadata = file
        .metadata()
        .map_err(|_| "platform_v2_bootstrap_manifest_io")?;
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > MAX_MANIFEST_BYTES
    {
        return Err("platform_v2_bootstrap_manifest_insecure");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "platform_v2_bootstrap_manifest_io")?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err("platform_v2_bootstrap_manifest_insecure");
    }
    Ok(bytes)
}

fn validate_document(document: BootstrapDocument) -> Result<ValidatedBootstrap, &'static str> {
    if document.version != 1
        || document.projects.is_empty()
        || document.projects.len() > MAX_PROJECTS
    {
        return Err("platform_v2_bootstrap_manifest_invalid");
    }
    automonique_protocol::identity::Actor::new(&document.tenant, "bootstrap-validator")
        .map_err(|_| "platform_v2_bootstrap_manifest_invalid")?;
    let revision = Revision::new(1).map_err(|_| "platform_v2_bootstrap_manifest_invalid")?;
    let mut projects = BTreeSet::new();
    let mut ownership = BTreeMap::new();
    let mut external_identities = BTreeSet::new();
    let mut externals = Vec::new();
    let mut records = Vec::new();
    for project_doc in document.projects {
        let project_id =
            ProjectId::new(project_doc.id).map_err(|_| "platform_v2_bootstrap_manifest_invalid")?;
        require_issued_id(WorkContextTargetKind::Project, project_id.as_str())?;
        if !projects.insert(project_id.clone())
            || project_doc.repositories.is_empty()
            || project_doc.host_setups.is_empty()
        {
            return Err("platform_v2_bootstrap_manifest_invalid");
        }
        let project_identity = WorkContextIdentity::Project(project_id.clone());
        if ownership
            .insert(project_identity.clone(), project_id.clone())
            .is_some()
        {
            return Err("platform_v2_bootstrap_manifest_invalid");
        }
        let mut repositories = BTreeMap::new();
        for repository_doc in project_doc.repositories {
            let repository = repository_identity(&repository_doc.authority, repository_doc.id)?;
            if !external_identities.insert(repository.clone()) {
                return Err("platform_v2_bootstrap_manifest_invalid");
            }
            repositories.insert(
                (repository_doc.authority, repository.id().to_owned()),
                repository.clone(),
            );
            externals.push(WorkContextBootstrapExternal {
                expected: ExpectedWorkContext::new(repository, revision),
                resolution: ExternalParentResolution::Available,
                owning_project: project_id.clone(),
            });
        }
        let project_relations = repositories
            .values()
            .cloned()
            .map(|repository| {
                WorkContextRelation::new(WorkContextRelationKind::ProjectRepository, repository)
                    .map_err(|_| "platform_v2_bootstrap_manifest_invalid")
            })
            .collect::<Result<Vec<_>, _>>()?;
        records.push(record(
            project_identity.clone(),
            revision,
            project_doc.label,
            WorkContextAttributes::EMPTY,
            project_relations,
        )?);
        for host_doc in project_doc.host_setups {
            let host_id = HostSetupId::new(host_doc.id)
                .map_err(|_| "platform_v2_bootstrap_manifest_invalid")?;
            require_issued_id(WorkContextTargetKind::HostSetup, host_id.as_str())?;
            let host_identity = WorkContextIdentity::HostSetup(host_id);
            if ownership
                .insert(host_identity.clone(), project_id.clone())
                .is_some()
                || host_doc.checkouts.is_empty()
            {
                return Err("platform_v2_bootstrap_manifest_invalid");
            }
            let host_kind = HostSetupKind::parse(&host_doc.kind)
                .map_err(|_| "platform_v2_bootstrap_manifest_invalid")?;
            records.push(record(
                host_identity.clone(),
                revision,
                host_doc.label,
                WorkContextAttributes::host_setup(host_kind),
                vec![relation(
                    WorkContextRelationKind::HostSetupProject,
                    project_identity.clone(),
                )?],
            )?);
            for checkout_doc in host_doc.checkouts {
                let checkout_id = CheckoutId::new(checkout_doc.id)
                    .map_err(|_| "platform_v2_bootstrap_manifest_invalid")?;
                require_issued_id(WorkContextTargetKind::Checkout, checkout_id.as_str())?;
                let checkout_identity = WorkContextIdentity::Checkout(checkout_id);
                if ownership
                    .insert(checkout_identity.clone(), project_id.clone())
                    .is_some()
                    || checkout_doc.workspaces.is_empty()
                {
                    return Err("platform_v2_bootstrap_manifest_invalid");
                }
                let repository = repositories
                    .get(&(
                        checkout_doc.repository.authority,
                        checkout_doc.repository.id,
                    ))
                    .cloned()
                    .ok_or("platform_v2_bootstrap_manifest_invalid")?;
                let checkout_kind = CheckoutKind::parse(&checkout_doc.kind)
                    .map_err(|_| "platform_v2_bootstrap_manifest_invalid")?;
                records.push(record(
                    checkout_identity.clone(),
                    revision,
                    checkout_doc.label,
                    WorkContextAttributes::checkout(checkout_kind),
                    vec![
                        relation(
                            WorkContextRelationKind::CheckoutProject,
                            project_identity.clone(),
                        )?,
                        relation(
                            WorkContextRelationKind::CheckoutHostSetup,
                            host_identity.clone(),
                        )?,
                        relation(WorkContextRelationKind::CheckoutRepository, repository)?,
                    ],
                )?);
                for workspace_doc in checkout_doc.workspaces {
                    let workspace_id = UserWorkspaceId::new(workspace_doc.id)
                        .map_err(|_| "platform_v2_bootstrap_manifest_invalid")?;
                    require_issued_id(WorkContextTargetKind::UserWorkspace, workspace_id.as_str())?;
                    let workspace_identity = WorkContextIdentity::UserWorkspace(workspace_id);
                    if ownership
                        .insert(workspace_identity.clone(), project_id.clone())
                        .is_some()
                    {
                        return Err("platform_v2_bootstrap_manifest_invalid");
                    }
                    records.push(record(
                        workspace_identity,
                        revision,
                        workspace_doc.label,
                        WorkContextAttributes::EMPTY,
                        vec![
                            relation(
                                WorkContextRelationKind::UserWorkspaceProject,
                                project_identity.clone(),
                            )?,
                            relation(
                                WorkContextRelationKind::UserWorkspaceCheckout,
                                checkout_identity.clone(),
                            )?,
                        ],
                    )?);
                }
            }
        }
    }
    if records.len() > MAX_GRAPH_RECORDS {
        return Err("platform_v2_bootstrap_manifest_invalid");
    }
    Ok(ValidatedBootstrap {
        tenant: document.tenant,
        projects,
        ownership,
        externals,
        records,
    })
}

fn repository_identity(authority: &str, id: String) -> Result<WorkContextIdentity, &'static str> {
    let authority = ResourceAuthority::parse(authority)
        .map_err(|_| "platform_v2_bootstrap_manifest_invalid")?;
    if authority != ResourceAuthority::GitHub {
        return Err("platform_v2_bootstrap_manifest_invalid");
    }
    let id = ResourceId::new(id).map_err(|_| "platform_v2_bootstrap_manifest_invalid")?;
    let repository = V1RepositoryRef::new(ResourceCoordinate::new(
        authority,
        ResourceKind::Repository,
        id,
    ))
    .map_err(|_| "platform_v2_bootstrap_manifest_invalid")?;
    Ok(WorkContextIdentity::Repository(repository))
}

fn require_issued_id(kind: WorkContextTargetKind, id: &str) -> Result<(), &'static str> {
    let prefix = format!("wc2_{}_", kind.as_str());
    let Some(nonce) = id.strip_prefix(&prefix) else {
        return Err("platform_v2_bootstrap_identity_not_server_issued");
    };
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("platform_v2_bootstrap_identity_not_server_issued");
    }
    Ok(())
}

fn record(
    identity: WorkContextIdentity,
    revision: Revision,
    label: String,
    attributes: WorkContextAttributes,
    relations: Vec<WorkContextRelation>,
) -> Result<WorkContextRecord, &'static str> {
    WorkContextRecord::new(
        identity,
        revision,
        WorkContextLifecycle::Active,
        WorkContextLabel::new(label).map_err(|_| "platform_v2_bootstrap_manifest_invalid")?,
        attributes,
        relations,
    )
    .map_err(|_| "platform_v2_bootstrap_manifest_invalid")
}

fn relation(
    kind: WorkContextRelationKind,
    target: WorkContextIdentity,
) -> Result<WorkContextRelation, &'static str> {
    WorkContextRelation::new(kind, target).map_err(|_| "platform_v2_bootstrap_manifest_invalid")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    const PROJECT: &str = "wc2_project_00000000000000000000000000000001";
    const HOST: &str = "wc2_host_setup_00000000000000000000000000000002";
    const CHECKOUT: &str = "wc2_checkout_00000000000000000000000000000003";
    const WORKSPACE: &str = "wc2_user_workspace_00000000000000000000000000000004";
    const PROJECT_TWO: &str = "wc2_project_00000000000000000000000000000005";
    const HOST_TWO: &str = "wc2_host_setup_00000000000000000000000000000006";
    const CHECKOUT_TWO: &str = "wc2_checkout_00000000000000000000000000000007";
    const WORKSPACE_TWO: &str = "wc2_user_workspace_00000000000000000000000000000008";

    fn manifest(label: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "tenant": "tenant-bootstrap",
            "projects": [{
                "id": PROJECT,
                "label": label,
                "repositories": [{"authority": "github", "id": "repository-1"}],
                "host_setups": [{
                    "id": HOST,
                    "label": "Local host",
                    "kind": "local",
                    "checkouts": [{
                        "id": CHECKOUT,
                        "label": "Main checkout",
                        "kind": "git_worktree",
                        "repository": {"authority": "github", "id": "repository-1"},
                        "workspaces": [{"id": WORKSPACE, "label": "Operator workspace"}]
                    }]
                }]
            }]
        }))
        .unwrap()
    }

    fn policy(uid: u32) -> Vec<u8> {
        let workspaces = [
            ("project", PROJECT),
            ("host_setup", HOST),
            ("checkout", CHECKOUT),
            ("user_workspace", WORKSPACE),
        ]
        .map(|(kind, id)| {
            serde_json::json!({
                "project": PROJECT,
                "kind": kind,
                "id": id,
                "inherited_authority": {
                    "filesystem": [], "credentials": [], "network": [],
                    "tools": [], "providers": [], "models": []
                }
            })
        });
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "principals": [{
                "uid": uid,
                "tenant": "tenant-bootstrap",
                "actor": "operator-bootstrap",
                "serving_authority": "automonique",
                "projects": [PROJECT],
                "workspaces": workspaces,
                "authority": {
                    "filesystem": [], "credentials": [], "network": [],
                    "tools": [], "providers": [], "models": []
                },
                "review_authorities": {}
            }]
        }))
        .unwrap()
    }

    fn two_project_manifest() -> Vec<u8> {
        let mut value: serde_json::Value =
            serde_json::from_slice(&manifest("Bootstrap project one")).unwrap();
        let mut project_two = value["projects"][0].clone();
        project_two["id"] = serde_json::json!(PROJECT_TWO);
        project_two["label"] = serde_json::json!("Bootstrap project two");
        project_two["repositories"][0]["id"] = serde_json::json!("repository-2");
        project_two["host_setups"][0]["id"] = serde_json::json!(HOST_TWO);
        project_two["host_setups"][0]["checkouts"][0]["id"] = serde_json::json!(CHECKOUT_TWO);
        project_two["host_setups"][0]["checkouts"][0]["repository"]["id"] =
            serde_json::json!("repository-2");
        project_two["host_setups"][0]["checkouts"][0]["workspaces"][0]["id"] =
            serde_json::json!(WORKSPACE_TWO);
        value["projects"].as_array_mut().unwrap().push(project_two);
        serde_json::to_vec(&value).unwrap()
    }

    fn two_project_policy_with_swapped_owners(uid: u32) -> Vec<u8> {
        let scope = |kind: &str, id: &str, project: &str| {
            serde_json::json!({
                "project": project,
                "kind": kind,
                "id": id,
                "inherited_authority": {
                    "filesystem": [], "credentials": [], "network": [],
                    "tools": [], "providers": [], "models": []
                }
            })
        };
        let workspaces = vec![
            scope("project", PROJECT, PROJECT),
            scope("host_setup", HOST, PROJECT_TWO),
            scope("checkout", CHECKOUT, PROJECT_TWO),
            scope("user_workspace", WORKSPACE, PROJECT_TWO),
            scope("project", PROJECT_TWO, PROJECT_TWO),
            scope("host_setup", HOST_TWO, PROJECT),
            scope("checkout", CHECKOUT_TWO, PROJECT),
            scope("user_workspace", WORKSPACE_TWO, PROJECT),
        ];
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "principals": [{
                "uid": uid,
                "tenant": "tenant-bootstrap",
                "actor": "operator-bootstrap",
                "serving_authority": "automonique",
                "projects": [PROJECT, PROJECT_TWO],
                "workspaces": workspaces,
                "authority": {
                    "filesystem": [], "credentials": [], "network": [],
                    "tools": [], "providers": [], "models": []
                },
                "review_authorities": {}
            }]
        }))
        .unwrap()
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn fixture() -> (tempfile::TempDir, DaemonConfig, std::path::PathBuf) {
        fixture_with_documents(&manifest("Bootstrap project"), &policy(geteuid().as_raw()))
    }

    fn fixture_with_documents(
        manifest_bytes: &[u8],
        policy_bytes: &[u8],
    ) -> (tempfile::TempDir, DaemonConfig, std::path::PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let state_root = temp.path().join("state");
        let state_dir = state_root.join("automonique");
        fs::create_dir(&state_root).unwrap();
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&state_dir).unwrap();
        fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let config = DaemonConfig {
            runtime_root: temp.path().join("runtime"),
            state_root,
        };
        write_private(&config.platform_v2_policy_path(), policy_bytes);
        let manifest_path = temp.path().join("bootstrap.json");
        write_private(&manifest_path, manifest_bytes);
        (temp, config, manifest_path)
    }

    #[test]
    fn plan_is_non_mutating_apply_is_atomic_and_replay_and_verify_are_identical() {
        let (_temp, config, manifest_path) = fixture();
        let plan = run(&config, &manifest_path, BootstrapMode::Plan).unwrap();
        assert_eq!(plan.state, "absent");
        assert!(!config.platform_v2_work_context_path().exists());

        let applied = run(&config, &manifest_path, BootstrapMode::Apply).unwrap();
        assert_eq!(applied.state, "seeded");
        let replay = run(&config, &manifest_path, BootstrapMode::Apply).unwrap();
        assert_eq!(replay.state, "identical");
        let verified = run(&config, &manifest_path, BootstrapMode::Verify).unwrap();
        assert_eq!(verified.state, "identical");
        assert_eq!(verified.records, 4);
        assert_eq!(verified.repositories, 1);
    }

    #[test]
    fn changed_graph_is_refused_without_overwriting_seeded_state() {
        let (temp, config, manifest_path) = fixture();
        run(&config, &manifest_path, BootstrapMode::Apply).unwrap();
        let changed = temp.path().join("changed.json");
        write_private(&changed, &manifest("Changed label"));
        assert_eq!(
            run(&config, &changed, BootstrapMode::Apply).unwrap_err(),
            "platform_v2_bootstrap_mismatch"
        );
        assert_eq!(
            run(&config, &manifest_path, BootstrapMode::Verify)
                .unwrap()
                .state,
            "identical"
        );

        let mut store = WorkContextStore::open(config.platform_v2_work_context_path()).unwrap();
        let extra = ExpectedWorkContext::new(
            repository_identity("github", "repository-extra".to_owned()).unwrap(),
            Revision::new(1).unwrap(),
        );
        store
            .put_external_snapshot(
                "tenant-bootstrap",
                &extra,
                ExternalParentResolution::Available,
                Some(&ProjectId::new(PROJECT).unwrap()),
            )
            .unwrap();
        drop(store);
        assert_eq!(
            run(&config, &manifest_path, BootstrapMode::Verify).unwrap_err(),
            "platform_v2_bootstrap_mismatch"
        );
    }

    #[test]
    fn manifest_requires_private_regular_owner_file_and_rejects_unknown_effect_fields() {
        let (temp, config, manifest_path) = fixture();
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            run(&config, &manifest_path, BootstrapMode::Plan).unwrap_err(),
            "platform_v2_bootstrap_manifest_insecure"
        );
        let target = temp.path().join("target.json");
        write_private(&target, &manifest("Project"));
        let link = temp.path().join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            run(&config, &link, BootstrapMode::Plan),
            Err("platform_v2_bootstrap_manifest_insecure")
                | Err("platform_v2_bootstrap_manifest_io")
        ));

        let mut unsafe_document: serde_json::Value =
            serde_json::from_slice(&manifest("Project")).unwrap();
        unsafe_document["projects"][0]["command"] = serde_json::json!("sh -c anything");
        let unsafe_path = temp.path().join("unsafe.json");
        write_private(&unsafe_path, &serde_json::to_vec(&unsafe_document).unwrap());
        assert_eq!(
            run(&config, &unsafe_path, BootstrapMode::Plan).unwrap_err(),
            "platform_v2_bootstrap_manifest_invalid"
        );
    }

    #[test]
    fn a_running_daemon_fence_refuses_even_plan() {
        let (_temp, config, manifest_path) = fixture();
        let lock = control_lock::ControlLock::acquire(config.control_lock_path()).unwrap();
        assert_eq!(
            run(&config, &manifest_path, BootstrapMode::Plan).unwrap_err(),
            "platform_v2_bootstrap_daemon_running"
        );
        drop(lock);
    }

    #[test]
    fn server_issued_ids_and_exact_policy_registry_are_mandatory() {
        let (_temp, config, manifest_path) = fixture();
        let bytes = fs::read(&manifest_path).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["projects"][0]["id"] = serde_json::json!("client-project");
        write_private(&manifest_path, &serde_json::to_vec(&value).unwrap());
        assert_eq!(
            run(&config, &manifest_path, BootstrapMode::Plan).unwrap_err(),
            "platform_v2_bootstrap_identity_not_server_issued"
        );

        let (_temp, config, manifest_path) = fixture();
        let policy_path = config.platform_v2_policy_path();
        let mut policy_value: serde_json::Value =
            serde_json::from_slice(&fs::read(&policy_path).unwrap()).unwrap();
        policy_value["principals"][0]["workspaces"]
            .as_array_mut()
            .unwrap()
            .pop();
        write_private(&policy_path, &serde_json::to_vec(&policy_value).unwrap());
        assert_eq!(
            run(&config, &manifest_path, BootstrapMode::Plan).unwrap_err(),
            "platform_v2_bootstrap_policy_mismatch"
        );
    }

    #[test]
    fn swapped_project_ownership_is_refused_before_plan_or_apply_can_write_the_graph() {
        let (_temp, config, manifest_path) = fixture_with_documents(
            &two_project_manifest(),
            &two_project_policy_with_swapped_owners(geteuid().as_raw()),
        );
        let store_path = config.platform_v2_work_context_path();

        assert_eq!(
            run(&config, &manifest_path, BootstrapMode::Plan).unwrap_err(),
            "platform_v2_bootstrap_policy_mismatch"
        );
        assert!(!store_path.exists());

        assert_eq!(
            run(&config, &manifest_path, BootstrapMode::Apply).unwrap_err(),
            "platform_v2_bootstrap_policy_mismatch"
        );
        assert!(!store_path.exists());
    }

    #[test]
    fn partial_mismatch_and_downgrade_are_distinct_atomic_refusals() {
        for (case, expected) in [
            ("partial", "platform_v2_bootstrap_partial"),
            ("mismatch", "platform_v2_bootstrap_mismatch"),
            ("downgrade", "platform_v2_bootstrap_downgrade"),
        ] {
            let (_temp, config, manifest_path) = fixture();
            let document: BootstrapDocument =
                serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
            let graph = validate_document(document).unwrap();
            let mut store = WorkContextStore::open(config.platform_v2_work_context_path()).unwrap();
            let external = &graph.externals[0];
            let owner = if case == "mismatch" {
                ProjectId::new("different-project").unwrap()
            } else {
                external.owning_project.clone()
            };
            store
                .put_external_snapshot(
                    &graph.tenant,
                    &external.expected,
                    ExternalParentResolution::Available,
                    Some(&owner),
                )
                .unwrap();
            if case == "downgrade" {
                store
                    .put_external_snapshot(
                        &graph.tenant,
                        &ExpectedWorkContext::new(
                            external.expected.identity().clone(),
                            Revision::new(2).unwrap(),
                        ),
                        ExternalParentResolution::Available,
                        Some(&owner),
                    )
                    .unwrap();
            }
            drop(store);
            assert_eq!(
                run(&config, &manifest_path, BootstrapMode::Apply).unwrap_err(),
                expected
            );
            let connection =
                rusqlite::Connection::open(config.platform_v2_work_context_path()).unwrap();
            let count: i64 = connection
                .query_row("SELECT count(*) FROM work_context_records", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "{case} refusal inserted no graph record");
        }
    }
}
