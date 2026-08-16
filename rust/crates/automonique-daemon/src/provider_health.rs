// SPDX-License-Identifier: Elastic-2.0

//! Bounded background health probes for provider deployments.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use automonique_store::provider_deployments::{
    DeploymentError, DeploymentRecord, ProviderDeployments,
};

pub const PROBE_POLL_SLICE: Duration = Duration::from_millis(100);

/// A cheap deployment handshake. Implementations must not submit a model turn.
pub trait ProviderProbe: Send + Sync + 'static {
    fn healthy(&self, deployment: &DeploymentRecord) -> bool;
}

/// Probe every registered deployment once and persist the observations.
pub fn probe_once(
    store: &mut ProviderDeployments,
    probe: &dyn ProviderProbe,
    now_ms: i64,
) -> Result<usize, DeploymentError> {
    let deployments = store.all()?;
    for deployment in &deployments {
        store.record_probe(&deployment.deployment_id, probe.healthy(deployment), now_ms)?;
    }
    Ok(deployments.len())
}

/// One worker thread, joined on explicit stop or drop.
pub struct ProviderHealthWorker {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl ProviderHealthWorker {
    pub fn spawn(
        database: PathBuf,
        probe: Arc<dyn ProviderProbe>,
        interval: Duration,
        now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let handle = thread::spawn(move || {
            while !worker_shutdown.load(Ordering::Acquire) {
                if let Ok(mut store) = ProviderDeployments::open(&database) {
                    let _ = probe_once(&mut store, probe.as_ref(), now_ms());
                }
                let mut waited = Duration::ZERO;
                while waited < interval && !worker_shutdown.load(Ordering::Acquire) {
                    let slice = PROBE_POLL_SLICE.min(interval.saturating_sub(waited));
                    thread::sleep(slice);
                    waited = waited.saturating_add(slice);
                }
            }
        });
        Self {
            shutdown,
            handle: Some(handle),
        }
    }

    pub fn stop(mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for ProviderHealthWorker {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
