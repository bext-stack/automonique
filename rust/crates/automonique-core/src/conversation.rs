// SPDX-License-Identifier: Elastic-2.0

//! Pure conversational routing facts shared by every transport.
//!
//! This module performs no I/O and grants no authority. It only recognizes a
//! small closed set of intents and renders an already trusted Unix timestamp.
//! Telegram, Slack, and the web dashboard retain their own authentication,
//! delivery, read surfaces, and approval presentation.

use std::collections::BTreeSet;

/// Whether prose asks only for the trusted runtime clock.
///
/// Named-location conversions deliberately remain conversational because a
/// host clock does not establish the operator's timezone.
#[must_use]
pub fn is_current_time_question(text: &str) -> bool {
    matches!(
        text.trim()
            .trim_end_matches(['?', '!', '.'])
            .trim_end()
            .to_lowercase()
            .as_str(),
        "what time is it"
            | "what's the time"
            | "whats the time"
            | "what is the current time"
            | "current time"
            | "quelle heure est-il"
            | "quelle heure est il"
            | "il est quelle heure"
            | "quelle est l'heure actuelle"
    )
}

/// Whether a question asks for a bounded site/domain inventory.
#[must_use]
pub fn is_site_inventory_question(question: &str) -> bool {
    let normalized = question.to_lowercase();
    let terms: BTreeSet<&str> = normalized
        .split(|character: char| !character.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .collect();
    let names_inventory = terms.iter().any(|term| {
        matches!(
            *term,
            "sites" | "domains" | "domaines" | "hostnames" | "apps" | "applications"
        )
    });
    let inventory_cue = terms.iter().any(|term| {
        matches!(
            *term,
            "manage"
                | "managed"
                | "gère"
                | "gérons"
                | "gérer"
                | "gérés"
                | "host"
                | "hosted"
                | "hosting"
                | "héberge"
                | "hébergés"
                | "serve"
                | "served"
                | "server"
                | "serveur"
                | "webserver"
                | "webservers"
                | "inventory"
                | "inventaire"
                | "list"
                | "liste"
                | "prism"
        )
    });
    names_inventory && inventory_cue
}

/// Whether the enabled-vhost projection alone can answer a site question.
#[must_use]
pub fn is_enabled_site_inventory_question(question: &str) -> bool {
    if !is_site_inventory_question(question) {
        return false;
    }
    let normalized = question.to_lowercase();
    normalized
        .split(|character: char| !character.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .any(|term| {
            matches!(
                term,
                "host"
                    | "hosted"
                    | "hosting"
                    | "héberge"
                    | "hébergés"
                    | "server"
                    | "serveur"
                    | "webserver"
                    | "webservers"
                    | "inventory"
                    | "inventaire"
                    | "prism"
            )
        })
}

/// Render non-negative Unix milliseconds as an exact UTC RFC 3339 timestamp.
#[must_use]
pub fn utc_rfc3339_from_unix_millis(unix_ms: i64) -> Option<String> {
    let unix_ms = u64::try_from(unix_ms).ok()?;
    let unix_seconds = unix_ms / 1_000;
    let milliseconds = unix_ms % 1_000;
    let days = i64::try_from(unix_seconds / 86_400).ok()?;
    let seconds_in_day = unix_seconds % 86_400;
    let hour = seconds_in_day / 3_600;
    let minute = seconds_in_day % 3_600 / 60;
    let second = seconds_in_day % 60;

    // Howard Hinnant's civil-from-days transformation, with day zero at the
    // Unix epoch. Overflow means the clock cannot be rendered safely.
    let shifted = days.checked_add(719_468)?;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.checked_sub(era.checked_mul(146_097)?)?;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era.checked_add(era.checked_mul(400)?)?;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year = year.checked_add(1)?;
    }
    if !(0..=9_999).contains(&year) {
        return None;
    }
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{milliseconds:03}Z"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_intent_is_closed_and_timezone_safe() {
        assert!(is_current_time_question("what time is it ?"));
        assert!(is_current_time_question("Quelle heure est-il ?"));
        assert!(!is_current_time_question("what time is it in Paris?"));
    }

    #[test]
    fn site_inventory_requires_an_inventory_and_management_cue() {
        assert!(is_site_inventory_question("what sites do we manage?"));
        assert!(is_site_inventory_question("liste les domaines gérés"));
        assert!(!is_site_inventory_question("why is the client site down?"));
        assert!(is_enabled_site_inventory_question(
            "list sites hosted on this server"
        ));
        assert!(!is_enabled_site_inventory_question(
            "what sites do we manage?"
        ));
    }

    #[test]
    fn unix_milliseconds_render_as_utc() {
        assert_eq!(
            utc_rfc3339_from_unix_millis(0).as_deref(),
            Some("1970-01-01T00:00:00.000Z")
        );
        assert_eq!(utc_rfc3339_from_unix_millis(-1), None);
    }
}
