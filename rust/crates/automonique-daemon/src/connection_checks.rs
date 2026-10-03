// SPDX-License-Identifier: Elastic-2.0

//! Explicit, read-only diagnostics using the same validated configuration as
//! each connector. Reports contain closed categories, never upstream content.
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Connector {
    Slack,
    Telegram,
    Github,
    Support,
    Mcp,
}

pub(crate) type CheckResult = Result<&'static str, &'static str>;

#[derive(Debug, Serialize)]
pub struct CheckReport {
    pub ok: bool,
    pub reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub servers_passed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub servers_total: Option<usize>,
}

impl CheckReport {
    fn from_result(result: CheckResult) -> Self {
        Self {
            ok: result.is_ok(),
            reason: match result {
                Ok(reason) | Err(reason) => reason,
            },
            servers_passed: None,
            servers_total: None,
        }
    }
}

/// Contacts only operator-configured peers; callers must authenticate the user.
/// Native requests have eight-second deadlines. MCP discovery has an eight-second
/// admission budget plus at most one in-flight request (sixteen seconds total).
pub fn test_connection(state_dir: &Path, connector: Connector) -> CheckReport {
    let result = match connector {
        Connector::Slack => crate::slack::test_connection(state_dir),
        Connector::Telegram => crate::telegram::test_connection(state_dir),
        Connector::Github => crate::github::test_connection(state_dir),
        Connector::Support => crate::ticket_intake::test_connection(state_dir),
        Connector::Mcp => return test_mcp(state_dir),
    };
    CheckReport::from_result(result)
}

fn test_mcp(state_dir: &Path) -> CheckReport {
    let Ok(mut registry) = crate::mcp_client::McpRegistry::load(state_dir) else {
        return CheckReport::from_result(Err("invalid_configuration"));
    };
    let names = registry.configured_server_names();
    if names.is_empty() {
        return CheckReport::from_result(Err("not_configured"));
    }
    let started = Instant::now();
    let mut passed = 0;
    let mut checked = 0;
    for name in &names {
        if started.elapsed() >= Duration::from_secs(8) {
            break;
        }
        if registry.discover_server(name).is_ok() {
            passed += 1;
        }
        checked += 1;
    }
    mcp_report(passed, checked, names.len())
}

fn mcp_report(passed: usize, checked: usize, total: usize) -> CheckReport {
    CheckReport {
        ok: passed == total,
        reason: if passed == total {
            "tools_discovered"
        } else if checked < total {
            "discovery_timed_out"
        } else {
            "discovery_failed"
        },
        servers_passed: Some(passed),
        servers_total: Some(total),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_connectors_are_never_reported_healthy() {
        let state = tempfile::tempdir().unwrap();
        for connector in [
            Connector::Slack,
            Connector::Telegram,
            Connector::Github,
            Connector::Support,
            Connector::Mcp,
        ] {
            let report = test_connection(state.path(), connector);
            assert!(!report.ok);
            assert_eq!(report.reason, "not_configured");
        }
    }
    #[test]
    fn partial_or_unchecked_mcp_servers_do_not_pass() {
        assert!(mcp_report(2, 2, 2).ok);
        assert_eq!(mcp_report(1, 2, 2).reason, "discovery_failed");
        assert_eq!(mcp_report(1, 1, 2).reason, "discovery_timed_out");
        assert!(!mcp_report(1, 2, 2).ok);
        assert!(!mcp_report(1, 1, 2).ok);
    }
}
