// SPDX-License-Identifier: Elastic-2.0

//! Shared, transport-neutral headings for ticket lifecycle updates.

use automonique_support_connector::TicketJobStatus;

/// The compact first line Slack and Telegram show for one ticket state.
#[must_use]
pub(crate) const fn ticket_heading(status: TicketJobStatus) -> &'static str {
    match status {
        TicketJobStatus::PendingApproval => "🔐 Waiting for approval",
        TicketJobStatus::Pending | TicketJobStatus::Claimed => "⏳ Waiting to run",
        TicketJobStatus::Running => "🔄 Running",
        TicketJobStatus::Done => "✅ Completed",
        TicketJobStatus::Failed => "❌ Failed",
        TicketJobStatus::Cancelled => "⛔ Cancelled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_ticket_state_has_one_stable_heading() {
        let cases = [
            (TicketJobStatus::PendingApproval, "🔐 Waiting for approval"),
            (TicketJobStatus::Pending, "⏳ Waiting to run"),
            (TicketJobStatus::Claimed, "⏳ Waiting to run"),
            (TicketJobStatus::Running, "🔄 Running"),
            (TicketJobStatus::Done, "✅ Completed"),
            (TicketJobStatus::Failed, "❌ Failed"),
            (TicketJobStatus::Cancelled, "⛔ Cancelled"),
        ];
        for (status, expected) in cases {
            assert_eq!(expected, ticket_heading(status));
        }
    }
}
