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

/// Whether the user is asking for the identity or description of one named
/// thing.
///
/// This is deliberately a high-recall read-only routing hint, not proof that
/// the named thing exists in any attached source. Callers may use it to attach
/// a bounded entity/profile index so the answering model can compare labels,
/// hostnames and business context semantically instead of requiring the user
/// to know an exact deployment spelling.
#[must_use]
pub fn is_named_entity_description_question(question: &str) -> bool {
    let normalized = question
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    [
        "tell me about ",
        "what do you know about ",
        "what is ",
        "who is ",
        "describe ",
        "parle-moi de ",
        "parle moi de ",
        "que sais-tu de ",
        "que sais tu de ",
        "qu'est-ce que ",
        "qu est ce que ",
    ]
    .iter()
    .any(|prefix| normalized.starts_with(prefix))
}

/// Whether a question should receive the bounded local site-profile source.
///
/// Inventory questions name the source explicitly. Named-entity description
/// questions receive the same read-only source at high recall so an AI answer
/// pass can perform semantic candidate matching. An unrelated profile remains
/// evidence to ignore, never a positive match.
#[must_use]
pub fn is_site_profile_question(question: &str) -> bool {
    is_site_inventory_question(question) || is_named_entity_description_question(question)
}

/// Whether a question asks for the host's current PM2 process projection.
///
/// This only routes a read. The process reader itself uses a fixed executable
/// and returns a deliberately narrow projection with no environment, command
/// line, working directory, or log data.
#[must_use]
pub fn is_pm2_process_question(question: &str) -> bool {
    let normalized = question.to_lowercase();
    let terms: BTreeSet<&str> = normalized
        .split(|character: char| !character.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .collect();
    terms.contains("pm2")
        || (terms.iter().any(|term| {
            matches!(
                *term,
                "process" | "processes" | "service" | "services" | "app" | "apps"
            )
        }) && terms.iter().any(|term| {
            matches!(
                *term,
                "running" | "online" | "stopped" | "runtime" | "server" | "serveur"
            )
        }))
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

/// Whether a provider returned a promise to answer later instead of the
/// complete one-shot answer every conversational transport requires.
///
/// The bound keeps this deliberately narrow: a long answer that happens to
/// discuss a future lookup is not rejected, while short acknowledgements such
/// as "I'll fetch that — one moment" cannot be mistaken for an asynchronous
/// job that the caller never scheduled.
#[must_use]
pub fn is_deferred_placeholder_answer(answer: &str) -> bool {
    let normalized = answer
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    if normalized.is_empty() || normalized.len() > 600 {
        return false;
    }
    [
        "i'll fetch",
        "i will fetch",
        "let me fetch",
        "i'll look into",
        "i will look into",
        "let me look into",
        "i'll check that",
        "i will check that",
        "i'll search",
        "i will search",
        "let me search",
        "i'll browse",
        "i will browse",
        "i'll research",
        "i will research",
        "i'll run that",
        "i will run that",
        "i'll do that",
        "i will do that",
        "i'll send",
        "i will send",
        "i'll post",
        "i will post",
        "i'll execute",
        "i will execute",
        "je vais chercher",
        "je vais rechercher",
        "je vais vérifier",
        "je vais verifier",
        "je vais consulter",
        "je vais le faire",
        "je vais exécuter",
        "je vais executer",
        "je vais envoyer",
        "je vais publier",
        "laisse-moi vérifier",
        "laisse moi verifier",
    ]
    .iter()
    .any(|promise| normalized.contains(promise))
        || ([
            "one moment",
            "please wait",
            "give me a moment",
            "un instant",
            "un moment",
            "patientez",
        ]
        .iter()
        .any(|wait| normalized.contains(wait))
            && [
                "fetch",
                "look into",
                "check",
                "search",
                "browse",
                "research",
                "run",
                "execute",
                "send",
                "post",
                "chercher",
                "rechercher",
                "consulter",
                "executer",
                "exécuter",
                "envoyer",
                "publier",
                "vérifier",
                "verifier",
            ]
            .iter()
            .any(|action| normalized.contains(action)))
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
    fn named_entities_attach_profiles_without_claiming_a_match() {
        assert!(is_named_entity_description_question(
            "what do you know about Amis de la ferme?"
        ));
        assert!(is_named_entity_description_question(
            "Parle-moi de la Ferme des Amis"
        ));
        assert!(is_site_profile_question(
            "what do you know about Amis de la ferme?"
        ));
        assert!(is_site_profile_question("what sites do we manage?"));
        assert!(!is_site_profile_question("why is the sky blue?"));
    }

    #[test]
    fn pm2_process_questions_are_recognized_without_catching_generic_prose() {
        assert!(is_pm2_process_question("which PM2 processes are running?"));
        assert!(is_pm2_process_question("running services on the server"));
        assert!(!is_pm2_process_question("what is a process?"));
    }

    #[test]
    fn deferred_one_shot_placeholders_are_detected_without_rejecting_answers() {
        assert!(is_deferred_placeholder_answer(
            "I can look into that issue for you — I'll fetch its details. One moment."
        ));
        assert!(is_deferred_placeholder_answer(
            "Je vais rechercher les détails, un instant."
        ));
        assert!(is_deferred_placeholder_answer(
            "I'll search the web and get back to you."
        ));
        assert!(is_deferred_placeholder_answer(
            "Je vais envoyer le message après vérification."
        ));
        assert!(!is_deferred_placeholder_answer(
            "The issue is open, but its latest delivery comment reports that production verification passed."
        ));
        assert!(!is_deferred_placeholder_answer(
            "I checked the issue and found that it is still open."
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
