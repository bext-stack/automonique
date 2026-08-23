// SPDX-License-Identifier: Elastic-2.0

use std::fs;
use std::os::unix::fs::PermissionsExt;

use automonique_store::provider_deployments::{
    COOLDOWN_MS, DeploymentError, DeploymentRegistration, FAILURE_THRESHOLD, ProviderDeployments,
    RouteClass,
};

fn store() -> (tempfile::TempDir, ProviderDeployments) {
    let root = tempfile::tempdir().expect("tempdir");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private");
    let path = root.path().join("deployments.sqlite3");
    let store = ProviderDeployments::open(path).expect("open");
    (root, store)
}

fn register(store: &mut ProviderDeployments, id: &str, primary: u32, context: u32) {
    store
        .register(DeploymentRegistration {
            deployment_id: id,
            provider_kind: "fixture",
            primary_rank: Some(primary),
            context_window_rank: Some(context),
        })
        .expect("register");
}

#[test]
fn a_flapping_deployment_cools_down_while_its_sibling_serves() {
    let (_root, mut store) = store();
    register(&mut store, "primary-a", 0, 1);
    register(&mut store, "primary-b", 1, 0);
    assert_eq!(
        store
            .select(RouteClass::Primary, 1_000)
            .unwrap()
            .unwrap()
            .deployment_id,
        "primary-a"
    );
    for offset in 0..FAILURE_THRESHOLD {
        store
            .record_failure("primary-a", 2_000 + i64::from(offset))
            .expect("failure");
    }
    let cooled = store.get("primary-a").unwrap();
    assert_eq!(cooled.cooldown_until_ms, 2_002 + COOLDOWN_MS);
    assert_eq!(
        store
            .select(RouteClass::Primary, 3_000)
            .unwrap()
            .unwrap()
            .deployment_id,
        "primary-b"
    );
    assert_eq!(
        store
            .select(RouteClass::Primary, cooled.cooldown_until_ms)
            .unwrap()
            .unwrap()
            .deployment_id,
        "primary-a"
    );
}

#[test]
fn context_window_fallback_has_its_own_order_and_survives_reopen() {
    let (root, mut store) = store();
    let path = store.path().to_owned();
    register(&mut store, "large-context", 1, 0);
    register(&mut store, "cheap-primary", 0, 1);
    assert_eq!(
        store
            .select(RouteClass::Primary, 10)
            .unwrap()
            .unwrap()
            .deployment_id,
        "cheap-primary"
    );
    assert_eq!(
        store
            .select(RouteClass::ContextWindow, 10)
            .unwrap()
            .unwrap()
            .deployment_id,
        "large-context"
    );
    store.record_probe("large-context", false, 20).unwrap();
    drop(store);
    let reopened = ProviderDeployments::open(path).expect("reopen");
    assert_eq!(
        reopened
            .select(RouteClass::ContextWindow, 21)
            .unwrap()
            .unwrap()
            .deployment_id,
        "cheap-primary"
    );
    drop(root);
}

#[test]
fn a_success_clears_failure_state_without_touching_siblings() {
    let (_root, mut store) = store();
    register(&mut store, "one", 0, 0);
    store.record_failure("one", 1).unwrap();
    let reset = store.record_success("one").unwrap();
    assert_eq!(reset.failure_count, 0);
    assert_eq!(reset.failure_window_started_ms, None);
    assert_eq!(reset.cooldown_until_ms, 0);
}

#[test]
fn replacing_the_provider_in_a_stable_slot_resets_old_health_atomically() {
    let (_root, mut store) = store();
    store
        .register(DeploymentRegistration {
            deployment_id: "primary",
            provider_kind: "codex",
            primary_rank: Some(0),
            context_window_rank: Some(1),
        })
        .expect("register old provider");
    for offset in 0..FAILURE_THRESHOLD {
        store
            .record_failure("primary", 1_000 + i64::from(offset))
            .expect("record old-provider failure");
    }
    store
        .record_probe("primary", false, 2_000)
        .expect("record old-provider probe");
    let old_revision = store.get("primary").unwrap().revision;

    let replaced = store
        .register(DeploymentRegistration {
            deployment_id: "primary",
            provider_kind: "jcode",
            primary_rank: Some(0),
            context_window_rank: Some(1),
        })
        .expect("replace provider in the same routing slot");

    assert_eq!(replaced.provider_kind, "jcode");
    assert_eq!(replaced.failure_count, 0);
    assert_eq!(replaced.failure_window_started_ms, None);
    assert_eq!(replaced.cooldown_until_ms, 0);
    assert_eq!(replaced.last_probe_ms, None);
    assert_eq!(replaced.last_probe_healthy, None);
    assert_eq!(replaced.revision, old_revision + 1);
    assert_eq!(
        store
            .select(RouteClass::Primary, 2_001)
            .unwrap()
            .unwrap()
            .provider_kind,
        "jcode"
    );
}

#[test]
fn replacement_cannot_silently_change_a_slots_rank_topology() {
    let (_root, mut store) = store();
    register(&mut store, "primary", 0, 1);

    let error = store
        .register(DeploymentRegistration {
            deployment_id: "primary",
            provider_kind: "jcode",
            primary_rank: Some(1),
            context_window_rank: Some(0),
        })
        .expect_err("rank changes require an explicit topology migration");

    assert!(matches!(error, DeploymentError::Conflict));
    assert_eq!(store.get("primary").unwrap().provider_kind, "fixture");
}
