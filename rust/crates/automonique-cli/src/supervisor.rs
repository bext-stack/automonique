// SPDX-License-Identifier: Elastic-2.0

//! Read-only supervisor adapter diagnostics.

use automonique_protocol::{CheckStatus, DoctorCheck, DoctorReason, FindingCode, FindingMessage};

const CHECK_CODE: &str = "supervisor.adapter";
const REASON_CODE: &str = "supervisor.configuration-unavailable";
const MESSAGE: &str = "Supervisor adapter configuration is unavailable in this release";

/// Report the supervisor adapter as unavailable until a release configuration
/// contract exists.
///
/// This diagnostic is intentionally independent of the host: it does not read
/// process, D-Bus, environment, or filesystem state and performs no mutation.
#[must_use]
pub fn inspect_supervisor_adapter() -> DoctorCheck {
    DoctorCheck::new(
        FindingCode::new(CHECK_CODE).expect("constant check code is valid"),
        CheckStatus::Unavailable,
        Some(DoctorReason::new(
            FindingCode::new(REASON_CODE).expect("constant reason code is valid"),
            FindingMessage::new(MESSAGE).expect("constant reason message is valid"),
        )),
    )
    .expect("constant unavailable check is coherent")
}
