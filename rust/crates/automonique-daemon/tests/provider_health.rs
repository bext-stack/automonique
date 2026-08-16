// SPDX-License-Identifier: Elastic-2.0

use std::fs;
use std::os::unix::fs::PermissionsExt;

use automonique_daemon::provider_health::{ProviderProbe, probe_once};
use automonique_store::provider_deployments::{
    DeploymentRecord, DeploymentRegistration, ProviderDeployments, RouteClass,
};

struct Probe;

impl ProviderProbe for Probe {
    fn healthy(&self, deployment: &DeploymentRecord) -> bool {
        deployment.deployment_id != "down"
    }
}

#[test]
fn a_background_probe_evicts_only_the_unhealthy_deployment() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut store = ProviderDeployments::open(root.path().join("providers.sqlite3")).unwrap();
    for (id, rank) in [("down", 0), ("sibling", 1)] {
        store
            .register(DeploymentRegistration {
                deployment_id: id,
                provider_kind: "fixture",
                primary_rank: Some(rank),
                context_window_rank: None,
            })
            .unwrap();
    }
    assert_eq!(probe_once(&mut store, &Probe, 1_000).unwrap(), 2);
    assert_eq!(
        store
            .select(RouteClass::Primary, 1_001)
            .unwrap()
            .unwrap()
            .deployment_id,
        "sibling"
    );
    assert_eq!(store.get("down").unwrap().last_probe_healthy, Some(false));
    assert_eq!(store.get("sibling").unwrap().last_probe_healthy, Some(true));
}
