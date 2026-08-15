// SPDX-License-Identifier: Elastic-2.0

//! Read-only DeepSeek account-balance projection.
//!
//! The configured conversation-provider executable remains the credential
//! owner. The daemon invokes its fixed `--balance` operation and accepts only a
//! small typed projection; it never opens the API-key file or receives account
//! identity or credential material.

use std::io::Read as _;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::compose::ProviderConfig;
use crate::run_lane::CONVERSATION_PROVIDER_CONFIG_NAME;

const READ_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_RESPONSE_BYTES: usize = 16 * 1024;
const PROVIDER_HOME_ENV: &str = "AUTOMONIQUE_PROVIDER_HOME";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct DeepSeekBalanceInfo {
    pub currency: String,
    pub total_balance: String,
    pub granted_balance: String,
    pub topped_up_balance: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct DeepSeekBalanceSnapshot {
    pub is_available: bool,
    pub balance_infos: Vec<DeepSeekBalanceInfo>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeepSeekBalanceUnavailable {
    NotConfigured,
    ConfigurationRefused,
    ProviderRefused,
    TimedOut,
    InvalidResponse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeepSeekBalanceRead {
    Available(DeepSeekBalanceSnapshot),
    Unavailable(DeepSeekBalanceUnavailable),
}

#[must_use]
pub fn configured_balance(state_dir: &std::path::Path) -> DeepSeekBalanceRead {
    let provider = match ProviderConfig::load(&state_dir.join(CONVERSATION_PROVIDER_CONFIG_NAME)) {
        Ok(Some(provider)) => provider,
        Ok(None) => {
            return DeepSeekBalanceRead::Unavailable(DeepSeekBalanceUnavailable::NotConfigured);
        }
        Err(_) => {
            return DeepSeekBalanceRead::Unavailable(
                DeepSeekBalanceUnavailable::ConfigurationRefused,
            );
        }
    };
    read_balance(&provider)
}

fn read_balance(provider: &ProviderConfig) -> DeepSeekBalanceRead {
    let mut child = match Command::new(provider.binary())
        .arg("--balance")
        .env(PROVIDER_HOME_ENV, provider.home())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => {
            return DeepSeekBalanceRead::Unavailable(DeepSeekBalanceUnavailable::ProviderRefused);
        }
    };

    let deadline = Instant::now() + READ_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(POLL_INTERVAL),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return DeepSeekBalanceRead::Unavailable(DeepSeekBalanceUnavailable::TimedOut);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return DeepSeekBalanceRead::Unavailable(
                    DeepSeekBalanceUnavailable::ProviderRefused,
                );
            }
        }
    };
    if !status.success() {
        return DeepSeekBalanceRead::Unavailable(DeepSeekBalanceUnavailable::ProviderRefused);
    }
    let Some(stdout) = child.stdout.take() else {
        return DeepSeekBalanceRead::Unavailable(DeepSeekBalanceUnavailable::ProviderRefused);
    };
    let mut bytes = Vec::new();
    if stdout
        .take((MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.is_empty()
        || bytes.len() > MAX_RESPONSE_BYTES
    {
        return DeepSeekBalanceRead::Unavailable(DeepSeekBalanceUnavailable::InvalidResponse);
    }
    decode_response(&bytes)
}

fn decode_response(bytes: &[u8]) -> DeepSeekBalanceRead {
    let Ok(snapshot) = serde_json::from_slice::<DeepSeekBalanceSnapshot>(bytes) else {
        return DeepSeekBalanceRead::Unavailable(DeepSeekBalanceUnavailable::InvalidResponse);
    };
    if snapshot.balance_infos.is_empty() || snapshot.balance_infos.len() > 2 {
        return DeepSeekBalanceRead::Unavailable(DeepSeekBalanceUnavailable::InvalidResponse);
    }
    let mut currencies = std::collections::BTreeSet::new();
    for balance in &snapshot.balance_infos {
        if !matches!(balance.currency.as_str(), "USD" | "CNY")
            || !currencies.insert(balance.currency.as_str())
            || !valid_decimal(&balance.total_balance)
            || !valid_decimal(&balance.granted_balance)
            || !valid_decimal(&balance.topped_up_balance)
        {
            return DeepSeekBalanceRead::Unavailable(DeepSeekBalanceUnavailable::InvalidResponse);
        }
    }
    DeepSeekBalanceRead::Available(snapshot)
}

fn valid_decimal(value: &str) -> bool {
    if value.is_empty() || value.len() > 32 {
        return false;
    }
    let (whole, fraction) = value
        .split_once('.')
        .map_or((value, None), |(whole, fraction)| (whole, Some(fraction)));
    !whole.is_empty()
        && whole.bytes().all(|byte| byte.is_ascii_digit())
        && fraction.is_none_or(|fraction| {
            !fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_balance_decodes_without_identity_or_credentials() {
        let DeepSeekBalanceRead::Available(snapshot) = decode_response(
            br#"{"is_available":true,"balance_infos":[{"currency":"USD","total_balance":"19.50","granted_balance":"4.50","topped_up_balance":"15.00"}]}"#,
        ) else {
            panic!("documented response must decode");
        };
        assert!(snapshot.is_available);
        assert_eq!(snapshot.balance_infos[0].total_balance, "19.50");
    }

    #[test]
    fn malformed_money_or_currency_is_refused() {
        for body in [
            br#"{"is_available":true,"balance_infos":[]}"#.as_slice(),
            br#"{"is_available":true,"balance_infos":[{"currency":"EUR","total_balance":"1","granted_balance":"0","topped_up_balance":"1"}]}"#,
            br#"{"is_available":true,"balance_infos":[{"currency":"USD","total_balance":"NaN","granted_balance":"0","topped_up_balance":"1"}]}"#,
        ] {
            assert_eq!(
                decode_response(body),
                DeepSeekBalanceRead::Unavailable(DeepSeekBalanceUnavailable::InvalidResponse)
            );
        }
    }
}
