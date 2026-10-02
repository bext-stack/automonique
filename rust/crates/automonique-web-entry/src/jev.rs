// SPDX-License-Identifier: Elastic-2.0

//! One TypeSafe System One ("Jev") call per dashboard chat turn that judges
//! which read-only live reads the turn needs and which language it is in.
//!
//! The router is optional and advisory: with no key file it is off, and any
//! failure (timeout, refusal, malformed answer) leaves the turn to the
//! existing keyword logic. The key never leaves this module except as the
//! request's bearer header, and nothing here logs it or the message.

use std::{
    fs,
    io::{ErrorKind, Read},
    path::Path,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use zeroize::Zeroizing;

/// The fixed System One endpoint.
const ENDPOINT: &str = "https://api.typesafe.ai/v1/systemone";
/// Model requested unless `typesafe.conf` names another.
const DEFAULT_MODEL: &str = "jev-latest";
/// Whole-request budget: the router must never hold a chat turn up for long.
const DEFAULT_TIMEOUT: Duration = Duration::from_millis(1_500);
/// Bounds accepted for a configured timeout.
const MIN_TIMEOUT_MS: u64 = 100;
const MAX_TIMEOUT_MS: u64 = 5_000;
/// Largest key file accepted.
const KEY_FILE_LIMIT: u64 = 4 * 1024;
/// Largest configuration file accepted.
const CONF_FILE_LIMIT: u64 = 4 * 1024;
/// Largest response body read.
const RESPONSE_LIMIT: u64 = 64 * 1024;
/// Earlier turns sent as context, and characters kept from each.
pub(crate) const RECENT_TURNS: usize = 4;
pub(crate) const RECENT_TURN_CHARS: usize = 300;
/// Characters of the current message sent.
const MESSAGE_CHARS: usize = 4_000;

/// Read when Jev's probability is at least this.
pub(crate) const READ_THRESHOLD: f64 = 0.5;
/// Refuse a Slack write when Jev's probability is at least this.
pub(crate) const SLACK_WRITE_THRESHOLD: f64 = 0.8;
/// Override the keyword reply language when Jev is at least this confident.
pub(crate) const LANGUAGE_CONFIDENCE: f64 = 0.7;

/// Question ids, in the order they are logged.
pub(crate) const QUESTION_IDS: [&str; 6] = [
    "read_slack",
    "slack_write",
    "issue_lookup",
    "agent_runs",
    "manage_data",
    "reply_language",
];

/// Where the router is configured and how it calls the service.
pub(crate) struct JevConfig {
    key: Zeroizing<String>,
    endpoint: String,
    model: String,
    timeout: Duration,
}

impl std::fmt::Debug for JevConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JevConfig")
            .field("endpoint", &self.endpoint)
            .field("model", &self.model)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl JevConfig {
    /// Load `<state_dir>/typesafe/api-key` (owner-only, mode 0600) and the
    /// optional `typesafe.conf` beside it. `Ok(None)` when no key file
    /// exists: the router is off. A key file that exists but is not private,
    /// or a malformed configuration, is refused with a category.
    pub(crate) fn load(
        state_dir: &Path,
        read_private: impl Fn(&Path, u64) -> Option<Vec<u8>>,
    ) -> Result<Option<Self>, &'static str> {
        let directory = state_dir.join("typesafe");
        let key_path = directory.join("api-key");
        match fs::symlink_metadata(&key_path) {
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("jev_key_unreadable"),
            Ok(_) => {}
        }
        let bytes =
            Zeroizing::new(read_private(&key_path, KEY_FILE_LIMIT).ok_or("jev_key_refused")?);
        let text = std::str::from_utf8(&bytes).map_err(|_| "jev_key_refused")?;
        let key = text.trim();
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
        {
            return Err("jev_key_refused");
        }
        let mut config = Self {
            key: Zeroizing::new(key.to_owned()),
            endpoint: String::from(ENDPOINT),
            model: String::from(DEFAULT_MODEL),
            timeout: DEFAULT_TIMEOUT,
        };
        let conf_path = directory.join("typesafe.conf");
        match fs::symlink_metadata(&conf_path) {
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err("jev_conf_unreadable"),
            Ok(metadata) => {
                if !metadata.file_type().is_file() || metadata.len() > CONF_FILE_LIMIT {
                    return Err("jev_conf_refused");
                }
                let conf = fs::read_to_string(&conf_path).map_err(|_| "jev_conf_unreadable")?;
                config.apply_conf(&conf)?;
            }
        }
        Ok(Some(config))
    }

    /// `model=<id>` and `timeout_ms=<n>` lines; `#` comments and blank
    /// lines are ignored. The endpoint is fixed and not configurable.
    fn apply_conf(&mut self, conf: &str) -> Result<(), &'static str> {
        for line in conf.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, value) = line.split_once('=').ok_or("jev_conf_refused")?;
            let value = value.trim();
            match name.trim() {
                "model" => {
                    if value.is_empty()
                        || value.len() > 64
                        || !value.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_')
                        })
                    {
                        return Err("jev_conf_refused");
                    }
                    value.clone_into(&mut self.model);
                }
                "timeout_ms" => {
                    let millis: u64 = value.parse().map_err(|_| "jev_conf_refused")?;
                    if !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&millis) {
                        return Err("jev_conf_refused");
                    }
                    self.timeout = Duration::from_millis(millis);
                }
                _ => return Err("jev_conf_refused"),
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn for_test(key: &str, endpoint: String, timeout: Duration) -> Self {
        Self {
            key: Zeroizing::new(key.to_owned()),
            endpoint,
            model: String::from(DEFAULT_MODEL),
            timeout,
        }
    }
}

/// What the router is told about one turn. No secrets, no retrieved data.
#[derive(Clone, Debug, Default)]
pub(crate) struct JevTurn {
    pub(crate) message: String,
    /// Earlier turns, oldest first, as `user: …` / `assistant: …`.
    pub(crate) recent_conversation: Vec<String>,
    pub(crate) sources: JevSources,
}

/// One description per configured source, built from labels and aliases.
#[derive(Clone, Debug, Default)]
pub(crate) struct JevSources {
    pub(crate) slack: String,
    pub(crate) github: String,
    pub(crate) manage: String,
}

impl JevSources {
    pub(crate) fn describe(
        slack_labels: Option<&[String]>,
        github_names: Option<&[String]>,
        manage_configured: bool,
    ) -> Self {
        let slack = match slack_labels {
            Some(labels) if !labels.is_empty() => format!(
                "Channels {}, where the team posts messages, requests and GitHub issue links",
                join_names(
                    &labels
                        .iter()
                        .map(|label| format!("#{label}"))
                        .collect::<Vec<_>>()
                )
            ),
            _ => String::from("Not configured"),
        };
        let github = match github_names {
            Some(names) if !names.is_empty() => {
                format!("Issues in the {} repositories", join_names(names))
            }
            Some(_) => String::from("Issues in the configured repositories"),
            None => String::from("Not configured"),
        };
        let manage = if manage_configured {
            String::from("Business data: sites, contacts, products, orders, bookings, users")
        } else {
            String::from("Not configured")
        };
        Self {
            slack,
            github,
            manage,
        }
    }
}

fn join_names(names: &[String]) -> String {
    match names {
        [] => String::new(),
        [only] => only.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// Jev's reply-language choice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JevLanguage {
    English,
    French,
    OtherOrUnclear,
}

impl JevLanguage {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::English => "english",
            Self::French => "french",
            Self::OtherOrUnclear => "other_or_unclear",
        }
    }
}

/// Typed answers. A question the service did not answer is `None`.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct JevAnswers {
    pub(crate) model: String,
    pub(crate) read_slack: Option<f64>,
    pub(crate) slack_write: Option<f64>,
    pub(crate) issue_lookup: Option<f64>,
    pub(crate) agent_runs: Option<f64>,
    pub(crate) manage_data: Option<f64>,
    pub(crate) reply_language: Option<(JevLanguage, f64)>,
}

impl JevAnswers {
    pub(crate) fn says_read(value: Option<f64>) -> bool {
        value.is_some_and(|probability| probability >= READ_THRESHOLD)
    }

    pub(crate) fn says_slack_write(&self) -> bool {
        self.slack_write
            .is_some_and(|probability| probability >= SLACK_WRITE_THRESHOLD)
    }

    /// The confident language choice, if any.
    pub(crate) fn confident_language(&self) -> Option<JevLanguage> {
        self.reply_language
            .filter(|(_, confidence)| *confidence >= LANGUAGE_CONFIDENCE)
            .map(|(language, _)| language)
    }

    /// `id:0.97,…` with two decimals, for the log line.
    pub(crate) fn rounded(&self) -> String {
        let mut parts = Vec::new();
        for (id, value) in [
            ("read_slack", self.read_slack),
            ("slack_write", self.slack_write),
            ("issue_lookup", self.issue_lookup),
            ("agent_runs", self.agent_runs),
            ("manage_data", self.manage_data),
        ] {
            parts.push(match value {
                Some(value) => format!("{id}:{value:.2}"),
                None => format!("{id}:-"),
            });
        }
        parts.push(match self.reply_language {
            Some((language, confidence)) => {
                format!("reply_language:{}@{confidence:.2}", language.as_str())
            }
            None => String::from("reply_language:-"),
        });
        parts.join(",")
    }
}

/// The JSON request body for one turn.
pub(crate) fn request_body(model: &str, turn: &JevTurn) -> Value {
    let message: String = turn.message.chars().take(MESSAGE_CHARS).collect();
    let recent: Vec<String> = turn
        .recent_conversation
        .iter()
        .rev()
        .take(RECENT_TURNS)
        .rev()
        .map(|line| line.chars().take(RECENT_TURN_CHARS).collect())
        .collect();
    json!({
        "model": model,
        "state": {
            "message": message,
            "recent_conversation": recent,
            "sources": {
                "slack": turn.sources.slack,
                "github": turn.sources.github,
                "manage": turn.sources.manage,
            },
        },
        "questions": questions(),
    })
}

fn questions() -> Value {
    json!({
        "read_slack": {
            "type": "noul",
            "instructions": {
                "question": "To answer `message`, does the assistant need to read the recent messages in the Slack channels listed in `sources.slack` (for example: what happened or was said there, what people asked or sent, messages from someone who posts there)?",
                "note": "Questions about GitHub issue comments, configuration, or Monique itself do not need a Slack read unless they also ask about Slack messages."
            },
            "criteria": {
                "true": "Answering requires the content of recent Slack messages",
                "false": "The answer does not depend on reading Slack messages"
            }
        },
        "slack_write": {
            "type": "noul",
            "instructions": "Does `message` ask the assistant to post, send, edit, or delete something in Slack?"
        },
        "issue_lookup": {
            "type": "noul",
            "instructions": "Does `message` ask about the state, progress, completion, or comments of GitHub issues, tickets, or work items, including ones named earlier in `recent_conversation`?"
        },
        "agent_runs": {
            "type": "noul",
            "instructions": "Does `message` ask about Monique's agent runs, jobs, the work queue, runs waiting for approval, or the agent worker?"
        },
        "manage_data": {
            "type": "noul",
            "instructions": "Does `message` ask about business data held in Manage (sites, contacts, products, orders, bookings, users, integrations)?"
        },
        "reply_language": {
            "type": "choice",
            "instructions": "In which language is `message` written?",
            "criteria": {
                "english": null,
                "french": null,
                "other_or_unclear": "Another language, a mix, or too short to tell (e.g. only an issue number or 'ping')"
            }
        }
    })
}

/// Parse a 200 response body into typed answers.
pub(crate) fn parse_answers(body: &[u8]) -> Result<JevAnswers, &'static str> {
    let value: Value = serde_json::from_slice(body).map_err(|_| "jev_malformed")?;
    let answers = value
        .get("answers")
        .and_then(Value::as_object)
        .ok_or("jev_malformed")?;
    let model = value
        .get("model")
        .and_then(Value::as_str)
        .filter(|model| {
            model.len() <= 64
                && model
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
        })
        .unwrap_or("unknown")
        .to_owned();
    let noul = |id: &str| -> Result<Option<f64>, &'static str> {
        let Some(answer) = answers.get(id) else {
            return Ok(None);
        };
        if answer.get("type").and_then(Value::as_str) != Some("noul") {
            return Err("jev_malformed");
        }
        let probability = answer
            .get("noul")
            .and_then(Value::as_f64)
            .filter(|value| (0.0..=1.0).contains(value))
            .ok_or("jev_malformed")?;
        Ok(Some(probability))
    };
    let reply_language = match answers.get("reply_language") {
        None => None,
        Some(answer) => {
            if answer.get("type").and_then(Value::as_str) != Some("choice") {
                return Err("jev_malformed");
            }
            let language = match answer.get("choice").and_then(Value::as_str) {
                Some("english") => JevLanguage::English,
                Some("french") => JevLanguage::French,
                Some("other_or_unclear") => JevLanguage::OtherOrUnclear,
                _ => return Err("jev_malformed"),
            };
            let confidence = answer
                .get("confidence")
                .and_then(Value::as_f64)
                .filter(|value| (0.0..=1.0).contains(value))
                .ok_or("jev_malformed")?;
            Some((language, confidence))
        }
    };
    let answers = JevAnswers {
        model,
        read_slack: noul("read_slack")?,
        slack_write: noul("slack_write")?,
        issue_lookup: noul("issue_lookup")?,
        agent_runs: noul("agent_runs")?,
        manage_data: noul("manage_data")?,
        reply_language,
    };
    if answers.read_slack.is_none()
        && answers.slack_write.is_none()
        && answers.issue_lookup.is_none()
        && answers.agent_runs.is_none()
        && answers.manage_data.is_none()
        && answers.reply_language.is_none()
    {
        return Err("jev_malformed");
    }
    Ok(answers)
}

/// Ask every question in one request. Never panics; every failure is a
/// short category safe to log.
pub(crate) fn ask(config: &JevConfig, turn: &JevTurn) -> Result<JevAnswers, &'static str> {
    let body = serde_json::to_vec(&request_body(&config.model, turn)).map_err(|_| "jev_request")?;
    let started = Instant::now();
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(config.timeout))
        .max_redirects(0)
        .proxy(None)
        .http_status_as_error(false)
        .build()
        .new_agent();
    let authorization = Zeroizing::new(format!("Bearer {}", config.key.as_str()));
    let response = agent
        .post(&config.endpoint)
        .header("authorization", authorization.as_str())
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .send(&body[..]);
    let mut response = match response {
        Ok(response) => response,
        Err(ureq::Error::Timeout(_)) => return Err("jev_timeout"),
        Err(_) if started.elapsed() >= config.timeout => return Err("jev_timeout"),
        Err(_) => return Err("jev_transport"),
    };
    match response.status().as_u16() {
        200 => {}
        401 | 403 => return Err("jev_unauthorized"),
        422 => return Err("jev_rejected"),
        429 => return Err("jev_rate_limited"),
        529 => return Err("jev_overloaded"),
        500..=599 => return Err("jev_server_error"),
        _ => return Err("jev_unexpected_status"),
    }
    let mut bytes = Vec::new();
    match response
        .body_mut()
        .with_config()
        .limit(RESPONSE_LIMIT)
        .reader()
        .read_to_end(&mut bytes)
    {
        Ok(_) => {}
        Err(_) if started.elapsed() >= config.timeout => return Err("jev_timeout"),
        Err(_) => return Err("jev_malformed"),
    }
    parse_answers(&bytes)
}

/// A one-shot local HTTP server standing in for the service.
#[cfg(test)]
pub(crate) mod fake {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
        time::Duration,
    };

    /// The captured request: header block (lowercased) and body.
    pub(crate) struct Captured {
        pub(crate) head: String,
        pub(crate) body: serde_json::Value,
    }

    /// Serve one request with `status` and `body` after `delay`; returns the
    /// endpoint URL and a receiver for what the client sent.
    pub(crate) fn serve(
        status: u16,
        body: &str,
        delay: Duration,
    ) -> (String, mpsc::Receiver<Captured>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let endpoint = format!(
            "http://{}/v1/systemone",
            listener.local_addr().expect("addr")
        );
        let body = body.to_owned();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut received = Vec::new();
            let mut chunk = [0_u8; 4096];
            let (head_end, length) = loop {
                let Ok(read) = stream.read(&mut chunk) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                received.extend_from_slice(&chunk[..read]);
                if let Some(end) = received.windows(4).position(|window| window == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&received[..end]).to_lowercase();
                    let length = head
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    break (end + 4, length);
                }
            };
            while received.len() < head_end + length {
                let Ok(read) = stream.read(&mut chunk) else {
                    return;
                };
                if read == 0 {
                    break;
                }
                received.extend_from_slice(&chunk[..read]);
            }
            let head = String::from_utf8_lossy(&received[..head_end]).to_lowercase();
            let request_body =
                serde_json::from_slice(&received[head_end..]).unwrap_or(serde_json::Value::Null);
            let _ = sender.send(Captured {
                head,
                body: request_body,
            });
            thread::sleep(delay);
            let _ = write!(
                stream,
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        });
        (endpoint, receiver)
    }

    /// A well-formed answer for every question.
    pub(crate) fn answer(
        read_slack: f64,
        slack_write: f64,
        issue_lookup: f64,
        agent_runs: f64,
        manage_data: f64,
        language: &str,
        confidence: f64,
    ) -> String {
        serde_json::json!({
            "model": "jev-1.13.0",
            "answers": {
                "read_slack": {"type": "noul", "noul": read_slack},
                "slack_write": {"type": "noul", "noul": slack_write},
                "issue_lookup": {"type": "noul", "noul": issue_lookup},
                "agent_runs": {"type": "noul", "noul": agent_runs},
                "manage_data": {"type": "noul", "noul": manage_data},
                "reply_language": {
                    "type": "choice",
                    "choice": language,
                    "probabilities": {language: confidence},
                    "confidence": confidence
                }
            },
            "usage": {"input_tokens": 420}
        })
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::PermissionsExt, time::Duration};

    use super::*;

    const KEY: &str = "ts-test-key-0123456789";

    fn turn() -> JevTurn {
        JevTurn {
            message: String::from("quoi de neuf sur Slack ?"),
            recent_conversation: (0..6)
                .map(|index| format!("user: turn {index} {}", "x".repeat(400)))
                .collect(),
            sources: JevSources::describe(
                Some(&[String::from("ops"), String::from("deploys")]),
                Some(&[String::from("activ"), String::from("gamma")]),
                true,
            ),
        }
    }

    #[test]
    fn one_request_carries_every_question_and_the_turn_state_but_no_secret() {
        let (endpoint, captured) = fake::serve(
            200,
            &fake::answer(0.97, 0.01, 0.1, 0.02, 0.03, "french", 0.96),
            Duration::ZERO,
        );
        let config = JevConfig::for_test(KEY, endpoint, Duration::from_millis(1_500));
        let answers = ask(&config, &turn()).expect("answers");
        let request = captured.recv().expect("request");
        assert!(request.head.starts_with("post /v1/systemone "));
        assert!(
            request
                .head
                .contains(&format!("authorization: bearer {}", KEY.to_lowercase()))
        );
        assert!(request.head.contains("content-type: application/json"));
        let body = &request.body;
        assert_eq!(body["model"], "jev-latest");
        let questions = body["questions"].as_object().expect("questions");
        let mut ids: Vec<&str> = questions.keys().map(String::as_str).collect();
        ids.sort_unstable();
        let mut expected = QUESTION_IDS.to_vec();
        expected.sort_unstable();
        assert_eq!(ids, expected);
        assert_eq!(questions["reply_language"]["type"], "choice");
        assert_eq!(
            questions["read_slack"]["criteria"]["true"],
            "Answering requires the content of recent Slack messages"
        );
        assert_eq!(body["state"]["message"], "quoi de neuf sur Slack ?");
        let recent = body["state"]["recent_conversation"]
            .as_array()
            .expect("recent");
        assert_eq!(recent.len(), RECENT_TURNS);
        assert!(
            recent[0]
                .as_str()
                .expect("turn")
                .starts_with("user: turn 2 ")
        );
        assert!(
            recent
                .iter()
                .all(|turn| turn.as_str().expect("turn").chars().count() <= RECENT_TURN_CHARS)
        );
        assert_eq!(
            body["state"]["sources"]["slack"],
            "Channels #ops and #deploys, where the team posts messages, requests and GitHub issue links"
        );
        assert_eq!(
            body["state"]["sources"]["github"],
            "Issues in the activ and gamma repositories"
        );
        assert!(
            body["state"]["sources"]["manage"]
                .as_str()
                .expect("manage")
                .starts_with("Business data")
        );
        assert!(!body.to_string().contains(KEY));

        assert_eq!(answers.model, "jev-1.13.0");
        assert_eq!(answers.read_slack, Some(0.97));
        assert!(JevAnswers::says_read(answers.read_slack));
        assert!(!answers.says_slack_write());
        assert_eq!(answers.confident_language(), Some(JevLanguage::French));
        assert_eq!(
            answers.rounded(),
            "read_slack:0.97,slack_write:0.01,issue_lookup:0.10,agent_runs:0.02,manage_data:0.03,reply_language:french@0.96"
        );
    }

    #[test]
    fn failures_map_to_categories() {
        for (status, body, expected) in [
            (500, String::from("{}"), "jev_server_error"),
            (529, String::from("{}"), "jev_overloaded"),
            (401, String::from("{}"), "jev_unauthorized"),
            (422, String::from("{}"), "jev_rejected"),
            (429, String::from("{}"), "jev_rate_limited"),
            (200, String::from("not json"), "jev_malformed"),
            (200, String::from("{\"answers\":{}}"), "jev_malformed"),
            (
                200,
                fake::answer(1.7, 0.0, 0.0, 0.0, 0.0, "english", 0.9),
                "jev_malformed",
            ),
            (
                200,
                fake::answer(0.1, 0.0, 0.0, 0.0, 0.0, "klingon", 0.9),
                "jev_malformed",
            ),
        ] {
            let (endpoint, _captured) = fake::serve(status, &body, Duration::ZERO);
            let config = JevConfig::for_test(KEY, endpoint, Duration::from_millis(1_500));
            assert_eq!(ask(&config, &turn()), Err(expected), "status {status}");
        }
    }

    #[test]
    fn a_slow_service_times_out_within_the_budget() {
        let (endpoint, _captured) = fake::serve(
            200,
            &fake::answer(0.9, 0.0, 0.0, 0.0, 0.0, "english", 0.9),
            Duration::from_secs(3),
        );
        let config = JevConfig::for_test(KEY, endpoint, Duration::from_millis(300));
        let started = Instant::now();
        assert_eq!(ask(&config, &turn()), Err("jev_timeout"));
        assert!(started.elapsed() < Duration::from_millis(1_500));
    }

    #[test]
    fn an_unreachable_service_is_a_transport_failure() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("listener");
        let endpoint = format!(
            "http://{}/v1/systemone",
            listener.local_addr().expect("addr")
        );
        drop(listener);
        let config = JevConfig::for_test(KEY, endpoint, Duration::from_millis(500));
        assert!(matches!(
            ask(&config, &turn()),
            Err("jev_transport" | "jev_timeout")
        ));
    }

    fn private_read(path: &Path, limit: u64) -> Option<Vec<u8>> {
        let metadata = fs::symlink_metadata(path).ok()?;
        (metadata.permissions().mode() & 0o777 == 0o600 && metadata.len() <= limit)
            .then(|| fs::read(path).ok())
            .flatten()
    }

    #[test]
    fn the_key_file_turns_the_router_on_and_its_absence_leaves_it_off() {
        let state = tempfile::tempdir().expect("state");
        assert!(matches!(
            JevConfig::load(state.path(), private_read),
            Ok(None)
        ));
        let directory = state.path().join("typesafe");
        fs::create_dir(&directory).expect("dir");
        let key = directory.join("api-key");
        fs::write(&key, format!("{KEY}\n")).expect("key");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).expect("mode");
        assert_eq!(
            JevConfig::load(state.path(), private_read).map(|config| config.is_some()),
            Err("jev_key_refused")
        );
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("mode");
        let config = JevConfig::load(state.path(), private_read)
            .expect("load")
            .expect("on");
        assert_eq!(config.key.as_str(), KEY);
        assert_eq!(config.model, DEFAULT_MODEL);
        assert_eq!(config.timeout, DEFAULT_TIMEOUT);
        assert_eq!(config.endpoint, ENDPOINT);
        assert!(!format!("{config:?}").contains(KEY));

        let conf = directory.join("typesafe.conf");
        fs::write(&conf, "# router\nmodel=jev-1.13.0\ntimeout_ms=900\n").expect("conf");
        let config = JevConfig::load(state.path(), private_read)
            .expect("load")
            .expect("on");
        assert_eq!(config.model, "jev-1.13.0");
        assert_eq!(config.timeout, Duration::from_millis(900));
        for bad in [
            "endpoint=https://elsewhere.example\n",
            "timeout_ms=60000\n",
            "model=jev latest\n",
        ] {
            fs::write(&conf, bad).expect("conf");
            assert_eq!(
                JevConfig::load(state.path(), private_read).map(|config| config.is_some()),
                Err("jev_conf_refused"),
                "{bad}"
            );
        }
    }
}
