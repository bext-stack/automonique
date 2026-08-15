// SPDX-License-Identifier: Elastic-2.0

//! The outbound seam as a host sees it: a typed plan, a canonical body, and a
//! credential only the HTTP boundary may spend.

use std::sync::{Arc, Mutex};

use automonique_transport_runtime::{
    CancellationToken, HttpFailure, HttpMethod, OpaqueBotToken, OutboundRefusal,
    SendMessageRequest, SetMyCommandsRequest, TelegramBotCommand, TelegramHttpResponse,
    TelegramOutbound, TelegramOutboundClient, TelegramOutboundPlan, command_manifest, help_text,
};

/// A host-side stand-in for the HTTPS client, recording exactly what a real one
/// would be asked to send.
#[derive(Clone, Default)]
struct FakeOutboundClient {
    sent: Arc<Mutex<Vec<ObservedOutbound>>>,
    failure: Option<HttpFailure>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedOutbound {
    method: HttpMethod,
    bot_id: i64,
    method_name: &'static str,
    body: String,
    had_authorization: bool,
    debug: String,
}

impl TelegramOutboundClient for FakeOutboundClient {
    fn send(
        &mut self,
        plan: &TelegramOutboundPlan<'_>,
        cancellation: &CancellationToken,
    ) -> Result<TelegramHttpResponse, HttpFailure> {
        if cancellation.is_cancelled() {
            return Err(HttpFailure::Cancelled);
        }
        self.sent.lock().expect("lock").push(ObservedOutbound {
            method: plan.method(),
            bot_id: plan.bot_id(),
            method_name: plan.request().method_name(),
            body: plan.canonical_body(),
            had_authorization: plan
                .authorization()
                .with_secret(|secret| secret == b"42:fixture-secret"),
            debug: format!("{plan:?}"),
        });
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        Ok(TelegramHttpResponse {
            status: 200,
            body: br#"{"ok":true,"result":{"message_id":9}}"#.to_vec(),
            completed_ms: 1_000,
        })
    }
}

fn token() -> OpaqueBotToken {
    OpaqueBotToken::new(b"42:fixture-secret".to_vec()).expect("token")
}

fn menu() -> TelegramOutbound {
    let commands = command_manifest()
        .into_iter()
        .map(|entry| TelegramBotCommand::new(entry.name, entry.description).expect("command"));
    TelegramOutbound::SetMyCommands(SetMyCommandsRequest::new(commands).expect("menu"))
}

#[test]
fn a_reply_round_trips_through_the_outbound_seam_unchanged() {
    let token = token();
    let request = TelegramOutbound::SendMessage(
        SendMessageRequest::new(-1_001_234, "run 7 finished: ok", Some(88)).expect("request"),
    );
    let plan = TelegramOutboundPlan::new(42, request, &token).expect("plan");
    let mut client = FakeOutboundClient::default();
    let response = client
        .send(&plan, &CancellationToken::new())
        .expect("delivered");
    assert_eq!(response.status, 200);

    let sent = client.sent.lock().expect("lock");
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].method, HttpMethod::Post);
    assert_eq!(sent[0].bot_id, 42);
    assert_eq!(sent[0].method_name, "sendMessage");
    assert_eq!(
        sent[0].body,
        r#"{"chat_id":-1001234,"text":"run 7 finished: ok","reply_to_message_id":88}"#
    );
    assert!(sent[0].had_authorization);
}

#[test]
fn command_output_is_preformatted_without_interpreting_its_text() {
    let token = token();
    let output = "line <tag> & `ticks` 😀";
    let request = TelegramOutbound::SendMessage(
        SendMessageRequest::new_preformatted(7, output, None).expect("request"),
    );
    let plan = TelegramOutboundPlan::new(42, request, &token).expect("plan");

    assert_eq!(plan.request().method_name(), "sendMessage");
    assert_eq!(
        plan.canonical_body(),
        r#"{"chat_id":7,"text":"line <tag> & `ticks` 😀","entities":[{"type":"pre","offset":0,"length":23}]}"#
    );
    assert!(
        !plan.canonical_body().contains("parse_mode"),
        "untrusted output must not become markup"
    );
}

#[test]
fn the_advertised_menu_is_the_command_registry_verbatim() {
    let token = token();
    let plan = TelegramOutboundPlan::new(42, menu(), &token).expect("plan");
    let mut client = FakeOutboundClient::default();
    client.send(&plan, &CancellationToken::new()).expect("sent");

    let sent = client.sent.lock().expect("lock");
    assert_eq!(sent[0].method_name, "setMyCommands");
    for entry in command_manifest() {
        assert!(
            sent[0]
                .body
                .contains(&format!(r#"{{"command":"{}","description":"#, entry.name)),
            "{} is missing from the published menu",
            entry.name
        );
        assert!(sent[0].body.contains(entry.description), "{}", entry.name);
    }
    // The menu is exactly the registry: no extra entries rode along.
    assert_eq!(
        sent[0].body.matches(r#"{"command":"#).count(),
        command_manifest().len()
    );
    // And the same registry is what /help renders, so the two cannot drift.
    let help = help_text();
    for entry in command_manifest() {
        assert!(help.contains(entry.description), "{}", entry.name);
    }
}

#[test]
fn the_token_is_reachable_only_through_the_credential_borrow() {
    let token = token();
    let request = TelegramOutbound::SendMessage(
        SendMessageRequest::new(7, "status: ready", None).expect("request"),
    );
    let plan = TelegramOutboundPlan::new(42, request, &token).expect("plan");
    assert!(plan.has_authorization());

    let mut client = FakeOutboundClient::default();
    client.send(&plan, &CancellationToken::new()).expect("sent");
    let sent = client.sent.lock().expect("lock");
    assert!(
        sent[0].had_authorization,
        "the boundary can spend the token"
    );

    let rendered = format!(
        "{}{}{:?}{:?}{:?}",
        sent[0].debug,
        sent[0].body,
        plan,
        token,
        plan.authorization()
    );
    assert!(!rendered.contains("fixture-secret"));
    assert!(!rendered.contains("api.telegram.org"));
    assert!(rendered.contains("<redacted>"));
}

#[test]
fn a_cancelled_or_failed_send_reports_the_closed_vocabulary() {
    let token = token();
    let request =
        TelegramOutbound::SendMessage(SendMessageRequest::new(7, "late", None).expect("request"));
    let plan = TelegramOutboundPlan::new(42, request, &token).expect("plan");

    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let mut client = FakeOutboundClient::default();
    assert_eq!(
        client.send(&plan, &cancellation),
        Err(HttpFailure::Cancelled)
    );
    assert!(
        client.sent.lock().expect("lock").is_empty(),
        "a cancelled send must not be issued"
    );

    let mut failing = FakeOutboundClient {
        sent: Arc::default(),
        failure: Some(HttpFailure::UnexpectedStatus),
    };
    assert_eq!(
        failing.send(&plan, &CancellationToken::new()),
        Err(HttpFailure::UnexpectedStatus)
    );
}

#[test]
fn outbound_refusals_are_decided_before_a_plan_exists() {
    let token = token();
    assert_eq!(
        SendMessageRequest::new(0, "hi", None).err(),
        Some(OutboundRefusal::ChatId)
    );
    assert_eq!(
        SendMessageRequest::new(7, "", None).err(),
        Some(OutboundRefusal::Text)
    );
    let request =
        TelegramOutbound::SendMessage(SendMessageRequest::new(7, "hi", None).expect("request"));
    assert_eq!(
        TelegramOutboundPlan::new(0, request, &token).err(),
        Some(OutboundRefusal::BotId)
    );
    assert_eq!(OutboundRefusal::ChatId.category(), "chat_id");
    assert_eq!(
        OutboundRefusal::ChatId.to_string(),
        "Telegram outbound refused: chat_id"
    );
}
