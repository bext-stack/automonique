// SPDX-License-Identifier: Elastic-2.0

//! Turning one recorded support ticket into one work instruction, and one run's
//! answer into one storable draft.
//!
//! Two pure functions, no I/O, no clock, no store handle. They are the two ends
//! of `/work`: [`work_instruction`] is what goes *into* the run lane, and
//! [`storable_draft`] is what comes out of it on the way into the ticket store.
//! Both are here rather than inline in [`crate::telegram_bridge`] so that what a
//! ticket becomes is one readable page a reviewer can check against the ticket
//! store's own field list.
//!
//! # The instruction is an instruction, not a dump
//!
//! The composed text is a task: *draft an answer to this request, for a human to
//! review*. The ticket's fields appear in it because a draft written without the
//! subject line would be useless, and they appear as a short labelled header
//! rather than as a transcript.
//!
//! What is in it is exactly what `automonique_store::support_tickets` holds,
//! which is the fleet board's own summary of the request: an identifier, a
//! subject, a tenant, a site, a priority, a source, the fleet's status, a
//! comment count, and the fleet's display name for whoever filed it. That last
//! one is the only person-identifying field, and it is there because a draft
//! addressed to nobody is not a draft.
//!
//! What is **not** in it is the part that would make it a dump, and the reason
//! is worth stating plainly: the thread's messages are not in the store at all.
//! The connector reads a board summary, so this host has never held the
//! requester's own words, their address, their account, or anything they
//! attached. A composer here could not leak them if it tried, and the
//! instruction says so to the agent, so a draft written from a thin summary asks
//! for what it is missing instead of inventing it.
//!
//! Two host-owned facts are also left out — `first_seen_ms` and `last_synced_ms`
//! — because they say when *this daemon* looked at a board and have nothing to
//! do with answering the request.
//!
//! # The draft is normalized, not trusted
//!
//! A run's answer is provider output. The ticket store refuses a draft that is
//! empty, over its ceiling, or carrying a control character, and it is right to:
//! a draft is read in a chat and pasted into a support thread, and an escape
//! sequence in either is a rendering nobody asked for.
//!
//! [`storable_draft`] is the one place that difference is reconciled, and it
//! resolves it in the direction that keeps a completed run's work: a stray
//! control character becomes a space and an over-long answer is cut and *marked*,
//! rather than a finished run being thrown away over one byte. Nothing else is
//! reformatted — what the run wrote is what is stored.

use automonique_store::support_tickets::{MAX_DRAFT_ANSWER_BYTES, TicketRecord};

/// What a truncated draft ends with.
///
/// Marked rather than silent, for the same reason a truncated reply is: an
/// operator about to send a draft to a customer has to be able to tell "this is
/// the whole thing" from "this is the part that fit".
pub const DRAFT_TRUNCATION_MARK: &str = "\n[…truncated]";

/// Longest any one ticket field is copied into a work instruction, in bytes.
///
/// The store's own ceilings are already narrow — the widest is a 240-byte title
/// — so this bites on nothing the fleet legitimately sends. It exists so the
/// composed instruction has a bound that does not depend on reading another
/// module's constants and hoping they never move.
pub const MAX_INSTRUCTION_FIELD_BYTES: usize = 240;

/// What an absent optional field is printed as.
const NOT_STATED: &str = "not stated";

/// Compose the work instruction one recorded ticket becomes.
///
/// The whole of the operator's own input to a `/work` is the reference they
/// typed; every byte of the returned text comes from this host's durable record
/// of the ticket or from the fixed sentences below. That is deliberate — an
/// operator cannot append an instruction of their own to a ticket's work through
/// this path, so what a `/work` asks for is a property of this build rather than
/// of a chat message.
///
/// The result is bounded by construction: the fixed text is fixed, and every
/// field is cut at [`MAX_INSTRUCTION_FIELD_BYTES`]. It is far below the prompt
/// slot's own ceiling, which [`crate::compose`] enforces separately.
#[must_use]
pub fn work_instruction(record: &TicketRecord) -> String {
    let site = record.site_label.as_deref().unwrap_or(NOT_STATED);
    format!(
        "Draft a support answer for the Automonique operator to review.\n\
         \n\
         This is a work instruction, not a message to anybody. What you write is \
         stored as a draft on the operator's own host: nothing is sent to the \
         requester, to the support board, or anywhere else.\n\
         \n\
         Ticket: {}\n\
         Subject: {}\n\
         Tenant: {}\n\
         Site: {}\n\
         Priority: {} | Source: {} | Board status: {}\n\
         Requested by: {}\n\
         Comments on the thread: {}\n\
         \n\
         That header is the whole of what this host has recorded about the \
         request. The thread's own messages are not part of it, so if the \
         subject does not say enough to answer, say what you would need to read \
         instead of inventing it.\n\
         \n\
         Write the draft now: plain prose, addressed to the requester, under 250 \
         words, no headings and no markup. Do not state facts about the account, \
         the site or the history that the header does not give you.",
        field(&record.fleet_issue_id),
        field(&record.title),
        optional(&record.tenant_name),
        field(site),
        field(&record.priority),
        optional(&record.source),
        field(&record.fleet_status),
        optional(&record.requested_by),
        record.comment_count,
    )
}

/// Fit one run's answer into what the ticket store will hold, or answer that
/// there is nothing to store.
///
/// `None` means the run produced nothing storable: it was empty, or was nothing
/// but whitespace and control characters. Every other answer comes back as a
/// draft the store accepts — control characters other than newline and tab
/// replaced, the text trimmed, and anything past [`MAX_DRAFT_ANSWER_BYTES`] cut
/// at a character boundary and marked with [`DRAFT_TRUNCATION_MARK`].
#[must_use]
pub fn storable_draft(answer: &str) -> Option<String> {
    let ceiling = MAX_DRAFT_ANSWER_BYTES.saturating_sub(DRAFT_TRUNCATION_MARK.len());
    let mut text = String::with_capacity(answer.len().min(MAX_DRAFT_ANSWER_BYTES));
    let mut truncated = false;
    for character in answer.chars() {
        let character = if character.is_control() && !matches!(character, '\n' | '\t') {
            ' '
        } else {
            character
        };
        if text.len() + character.len_utf8() > ceiling {
            truncated = true;
            break;
        }
        text.push(character);
    }
    if truncated {
        // The trim happens before the mark so a cut that landed on trailing
        // whitespace does not push the mark past the ceiling.
        let mut kept = text.trim_end().to_owned();
        kept.push_str(DRAFT_TRUNCATION_MARK);
        return Some(kept);
    }
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// One ticket field, cut at a character boundary when it is over the bound.
fn field(value: &str) -> String {
    if value.len() <= MAX_INSTRUCTION_FIELD_BYTES {
        return value.to_owned();
    }
    let mut cut = MAX_INSTRUCTION_FIELD_BYTES;
    while cut > 0 && !value.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &value[..cut])
}

/// A field the fleet is allowed to leave empty.
///
/// An empty tenant or requester is a real state of a real ticket — the store
/// admits it because the connector does — and an empty value after a label reads
/// as a truncated instruction rather than as an absent fact.
fn optional(value: &str) -> String {
    if value.is_empty() {
        return String::from(NOT_STATED);
    }
    field(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record with every field set, so a test can assert what does and does
    /// not reach the instruction.
    fn record() -> TicketRecord {
        TicketRecord {
            ticket_id: 7,
            fleet_issue_id: String::from("SUP-1042"),
            title: String::from("Printer offline in the back room"),
            tenant_name: String::from("Boulangerie Milo"),
            site_label: Some(String::from("milo.invalid")),
            fleet_status: String::from("triaging"),
            priority: String::from("high"),
            source: String::from("email"),
            requested_by: String::from("Claire"),
            comment_count: 3,
            created_at: String::from("2026-08-10T09:12:00.000Z"),
            updated_at: String::from("2026-08-13T17:04:11.000Z"),
            first_seen_ms: 1_000,
            last_synced_ms: 2_000,
            lifecycle: automonique_store::support_tickets::TicketLifecycle::Working,
            revision: 2,
            draft_answer_bytes: None,
            draft_answer_at_ms: None,
        }
    }

    #[test]
    fn the_instruction_carries_the_summary_fields_and_asks_for_a_draft() {
        let instruction = work_instruction(&record());
        for expected in [
            "Ticket: SUP-1042",
            "Subject: Printer offline in the back room",
            "Tenant: Boulangerie Milo",
            "Site: milo.invalid",
            "Priority: high",
            "Source: email",
            "Board status: triaging",
            "Requested by: Claire",
            "Comments on the thread: 3",
        ] {
            assert!(instruction.contains(expected), "{expected}");
        }
        // It is an instruction: it says what to do, and it says the draft goes
        // nowhere.
        assert!(instruction.contains("Draft a support answer"));
        assert!(instruction.contains("nothing is sent to the requester"));
        assert!(instruction.contains("Write the draft now"));
    }

    /// The host's own bookkeeping is not the fleet's request, and none of it
    /// belongs in a prompt.
    #[test]
    fn the_instruction_carries_no_host_bookkeeping() {
        let instruction = work_instruction(&record());
        for absent in ["1000", "2000", "revision", "ticket_id", "lifecycle"] {
            assert!(
                !instruction.contains(absent),
                "{absent} must not reach the instruction: {instruction}"
            );
        }
    }

    #[test]
    fn an_empty_fleet_field_reads_as_absent_rather_than_as_nothing() {
        let mut record = record();
        record.tenant_name = String::new();
        record.requested_by = String::new();
        record.source = String::new();
        record.site_label = None;
        let instruction = work_instruction(&record);
        assert!(instruction.contains("Tenant: not stated"));
        assert!(instruction.contains("Requested by: not stated"));
        assert!(instruction.contains("Site: not stated"));
        assert!(!instruction.contains("Tenant: \n"));
    }

    #[test]
    fn an_over_wide_field_is_cut_and_marked() {
        let mut record = record();
        record.title = "T".repeat(MAX_INSTRUCTION_FIELD_BYTES + 40);
        let instruction = work_instruction(&record);
        assert!(instruction.contains(&format!(
            "Subject: {}…",
            "T".repeat(MAX_INSTRUCTION_FIELD_BYTES)
        )));
        assert!(!instruction.contains(&"T".repeat(MAX_INSTRUCTION_FIELD_BYTES + 1)));
    }

    #[test]
    fn a_plain_answer_is_stored_as_it_was_written() {
        assert_eq!(
            storable_draft("Bonjour Claire,\n\nnous avons identifié la panne.\n"),
            Some(String::from(
                "Bonjour Claire,\n\nnous avons identifié la panne."
            ))
        );
    }

    #[test]
    fn an_answer_with_nothing_in_it_is_not_a_draft() {
        for empty in ["", "   ", "\n\t \n", "\u{7}\u{1b}"] {
            assert_eq!(storable_draft(empty), None, "{empty:?}");
        }
    }

    #[test]
    fn control_characters_are_replaced_rather_than_refused() {
        let stored = storable_draft("one\u{7}two\u{1b}[31mthree\nfour\tfive").expect("a draft");
        assert_eq!(stored, "one two [31mthree\nfour\tfive");
        assert!(
            !stored
                .chars()
                .any(|character| character.is_control() && !matches!(character, '\n' | '\t')),
            "a stored draft must be one the ticket store accepts"
        );
    }

    #[test]
    fn an_over_long_answer_is_cut_at_the_store_ceiling_and_marked() {
        let stored = storable_draft(&"x".repeat(MAX_DRAFT_ANSWER_BYTES * 2)).expect("a draft");
        assert!(
            stored.len() <= MAX_DRAFT_ANSWER_BYTES,
            "{} is past the store's ceiling",
            stored.len()
        );
        assert!(stored.ends_with(DRAFT_TRUNCATION_MARK));

        // A multi-byte answer is cut on a character boundary, so the result is
        // still text.
        let stored = storable_draft(&"é".repeat(MAX_DRAFT_ANSWER_BYTES)).expect("a draft");
        assert!(stored.len() <= MAX_DRAFT_ANSWER_BYTES);
        assert!(stored.ends_with(DRAFT_TRUNCATION_MARK));
    }
}
