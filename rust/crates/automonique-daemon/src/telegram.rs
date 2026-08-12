// SPDX-License-Identifier: Elastic-2.0

//! Telegram host capability state.
//!
//! There is deliberately no bot configuration, credential, HTTP client, or
//! network executor in the foreground daemon yet. The concrete lease lifecycle
//! is provided by `automonique_transport_runtime::TelegramLeaseCoordinator` for
//! a future explicitly configured host; this daemon therefore owns only the
//! truthful disabled state.

use automonique_protocol::admin::TelegramState;

pub(crate) struct TelegramHost;

impl TelegramHost {
    pub(crate) const fn disabled() -> Self {
        Self
    }

    pub(crate) const fn status(&self) -> (TelegramState, Option<u64>) {
        (TelegramState::DisabledNoClient, None)
    }
}
