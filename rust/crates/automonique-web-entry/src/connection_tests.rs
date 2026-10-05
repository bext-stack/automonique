// SPDX-License-Identifier: Elastic-2.0

use automonique_daemon::connection_checks::{CheckReport, Connector, test_connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Mutex, TryLockError};
use std::time::Instant;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TestRequest {
    pub connector: Connector,
}

#[derive(Serialize)]
pub(super) struct TestView {
    connector: Connector,
    checked_at_ms: u64,
    duration_ms: u64,
    #[serde(flatten)]
    report: CheckReport,
}

// A slow peer must not occupy every HTTP worker or queue duplicate probes.
#[derive(Default)]
pub(super) struct ConnectionTests {
    active: Mutex<()>,
}

impl ConnectionTests {
    pub fn run(&self, state_dir: &Path, connector: Connector) -> Result<TestView, &'static str> {
        self.with_check(connector, || test_connection(state_dir, connector))
    }

    fn with_check(
        &self,
        connector: Connector,
        check: impl FnOnce() -> CheckReport,
    ) -> Result<TestView, &'static str> {
        let _guard = match self.active.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Err("connection_test_busy"),
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
        };
        let started = Instant::now();
        let report = check();
        Ok(TestView {
            connector,
            checked_at_ms: super::now_ms(),
            duration_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            report,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_accepts_only_known_connectors_and_no_credentials_or_urls() {
        assert!(serde_json::from_str::<TestRequest>(r#"{"connector":"slack"}"#).is_ok());
        for body in [
            r#"{"connector":"unknown"}"#,
            r#"{"connector":"slack","url":"https://example.test"}"#,
            r#"{"connector":"slack","token":"private"}"#,
        ] {
            assert!(serde_json::from_str::<TestRequest>(body).is_err());
        }
    }
    #[test]
    fn concurrent_probe_is_refused_without_calling_provider_and_guard_is_released() {
        let checks = ConnectionTests::default();
        let state = tempfile::tempdir().unwrap();
        checks
            .with_check(Connector::Slack, || {
                assert_eq!(
                    checks
                        .with_check(Connector::Slack, || panic!("duplicate probe"))
                        .err(),
                    Some("connection_test_busy")
                );
                test_connection(state.path(), Connector::Slack)
            })
            .unwrap();
        let view = checks.run(state.path(), Connector::Slack).unwrap();
        assert!(view.checked_at_ms > 0);
        let json = serde_json::to_value(view).unwrap();
        assert_eq!(json["ok"], false);
        assert_eq!(json["reason"], "not_configured");
        assert_eq!(json.as_object().unwrap().len(), 5);
    }
}
