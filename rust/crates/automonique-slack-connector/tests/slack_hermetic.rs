// SPDX-License-Identifier: Elastic-2.0

//! End-to-end proofs for the Slack client, against a fake Web API on loopback.
//!
//! Nothing here touches an external network. Every destination is a
//! `TcpListener` this test owns and binds on `127.0.0.1:0`, so a run is
//! hermetic, no Slack credential is real, and a failure is the connector's
//! rather than the internet's. `slack.com` never appears as a base: every
//! client is built from the plaintext-loopback shape, and [`slack_client`]
//! asserts that before returning — as does
//! [`no_fixture_can_become_a_live_call`], which checks the whole fixture set.
//!
//! Every socket carries a five-second read and write deadline, and the client
//! under test is given a one-second budget, so a stuck peer fails an assertion
//! instead of hanging the suite.
//!
//! Every identifier in a fixture is reserved or synthetic: `C0RESERVED`,
//! `T0RESERVED`, `U0RESERVED`, `B0RESERVED` and `*.invalid` hosts. No real
//! workspace, channel, user or token appears anywhere in this file, so no
//! fixture can become a live call by accident.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use automonique_slack_connector::{
    ChannelId, ConversationTypes, ConversationsHistoryRequest, ConversationsInfoRequest,
    ConversationsListRequest, Cursor, MAX_SLACK_RESPONSE_BYTES, MessageText, MessageTs,
    PostMessageRequest, SLACK_ACCEPT, SLACK_CONTENT_TYPE, SLACK_USER_AGENT, SlackBase, SlackClient,
    SlackErrorKind, SlackFailure, SlackToken, UserId, UsersInfoRequest,
};

/// Bound on every server-side wait. A test that would otherwise hang fails here.
const SERVER_TIMEOUT: Duration = Duration::from_secs(5);
/// Budget the client under test is given, so a deadline assertion is quick.
const CLIENT_BUDGET: Duration = Duration::from_secs(1);
/// Largest request head the fake will buffer before giving up.
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// The fixture credential. It is not a real token and addresses nothing: the
/// only server that ever sees it is the one in this file.
const TOKEN: &str = "xoxb-0000000000-0000000000-fixture-never-print";
/// Reserved synthetic ids. None of these names anything in any workspace.
const CHANNEL: &str = "C0RESERVED";
const USER: &str = "U0RESERVED";
const TEAM: &str = "T0RESERVED";
const BOT: &str = "B0RESERVED";

/// One request the fake observed, recorded verbatim.
#[derive(Clone, Debug)]
struct Captured {
    request_line: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Captured {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// What the fake answers with.
#[derive(Clone)]
struct Canned {
    status: u16,
    content_type: &'static str,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
    /// Accept the connection and never answer, so the client's deadline is the
    /// only thing that can end the call.
    silent: bool,
}

impl Canned {
    fn json(body: &str) -> Self {
        Self::status(200, body)
    }

    fn status(status: u16, body: &str) -> Self {
        Self {
            status,
            content_type: "application/json; charset=utf-8",
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
            silent: false,
        }
    }

    fn with_content_type(mut self, content_type: &'static str) -> Self {
        self.content_type = content_type;
        self
    }

    fn with_header(mut self, name: &'static str, value: &str) -> Self {
        self.headers.push((name, value.to_owned()));
        self
    }

    fn silent() -> Self {
        Self {
            status: 200,
            content_type: "application/json",
            headers: Vec::new(),
            body: Vec::new(),
            silent: true,
        }
    }
}

/// A fake Slack Web API on loopback that records what it was asked.
struct FakeSlack {
    address: SocketAddr,
    captured: Arc<Mutex<Vec<Captured>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeSlack {
    /// Answer each successive request with the next canned response, reusing
    /// the last one once the script is exhausted.
    fn spawn(script: Vec<Canned>) -> Self {
        assert!(!script.is_empty(), "a fake needs at least one response");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake slack");
        let address = listener.local_addr().expect("fake slack address");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");

        let captured = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let captured = Arc::clone(&captured);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let mut served = 0_usize;
                let mut held = Vec::new();
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((socket, _)) => {
                            socket.set_nonblocking(false).expect("blocking socket");
                            socket
                                .set_read_timeout(Some(SERVER_TIMEOUT))
                                .expect("server read deadline");
                            socket
                                .set_write_timeout(Some(SERVER_TIMEOUT))
                                .expect("server write deadline");
                            let canned = script[served.min(script.len() - 1)].clone();
                            served += 1;
                            // A silent connection is held rather than dropped:
                            // dropping would close it, which is not what
                            // "silent" means.
                            if let Some(socket) = serve(socket, &canned, &captured) {
                                held.push(socket);
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        Self {
            address,
            captured,
            stop,
            thread: Some(thread),
        }
    }

    fn port(&self) -> u16 {
        self.address.port()
    }

    fn captured(&self) -> Vec<Captured> {
        self.captured.lock().expect("captured lock").clone()
    }

    /// The single request this fake was asked, failing the test if it saw a
    /// different number.
    fn only_request(&self) -> Captured {
        let captured = self.captured();
        assert_eq!(captured.len(), 1, "expected exactly one request");
        captured.into_iter().next().expect("one request")
    }
}

impl Drop for FakeSlack {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Read one request, record it, and write the canned answer.
fn serve(
    mut socket: TcpStream,
    canned: &Canned,
    captured: &Arc<Mutex<Vec<Captured>>>,
) -> Option<TcpStream> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match socket.read(&mut byte) {
            Ok(0) => return None,
            Ok(_) => head.push(byte[0]),
            Err(_) => return None,
        }
        if head.len() > MAX_HEAD_BYTES {
            return None;
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default().to_owned();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    let length: usize = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0_u8; length];
    if length > 0 && socket.read_exact(&mut body).is_err() {
        return None;
    }
    captured.lock().expect("captured lock").push(Captured {
        request_line,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    });

    if canned.silent {
        return Some(socket);
    }
    let mut response = format!(
        "HTTP/1.1 {} X\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n",
        canned.status,
        canned.content_type,
        canned.body.len()
    );
    for (name, value) in &canned.headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    let mut response = response.into_bytes();
    response.extend_from_slice(&canned.body);
    let _ = socket.write_all(&response);
    let _ = socket.flush();
    None
}

/// A client pointed at the fake, proven to be loopback-only before it is used.
fn slack_client(fake: &FakeSlack) -> SlackClient {
    let base = SlackBase::new(&format!("http://127.0.0.1:{}", fake.port())).expect("loopback base");
    assert!(
        base.is_plaintext_loopback(),
        "every hermetic client must be loopback-only"
    );
    SlackClient::with_request_timeout(
        base,
        SlackToken::new(TOKEN.as_bytes().to_vec()).expect("token"),
        CLIENT_BUDGET,
    )
}

fn channel() -> ChannelId {
    ChannelId::new(CHANNEL).expect("channel")
}

fn history(limit: u16) -> ConversationsHistoryRequest {
    ConversationsHistoryRequest::new(channel(), limit).expect("history")
}

/// One complete channel object, carrying every field the contract names.
fn channel_json() -> String {
    format!(
        "{{\"id\":\"{CHANNEL}\",\"name\":\"reserve-general\",\"is_channel\":true,\
         \"is_group\":false,\"is_im\":false,\"created\":1723542000,\"is_archived\":false,\
         \"is_general\":true,\"is_private\":false,\"is_member\":true}}"
    )
}

/// One complete message object, carrying every field the contract names.
fn message_json() -> String {
    format!(
        "{{\"type\":\"message\",\"user\":\"{USER}\",\"text\":\"le paiement echoue\",\
         \"ts\":\"1723542000.000100\",\"thread_ts\":\"1723542000.000100\",\"reply_count\":2}}"
    )
}

/// Every request must be one this connector is allowed to make.
fn assert_wire_shape(captured: &Captured, path: &str) {
    assert_eq!(
        captured.request_line,
        format!("POST {path} HTTP/1.1"),
        "the connector must address exactly the documented method path"
    );
    assert_eq!(
        captured.header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str()),
        "the bearer header must reach the wire exactly as configured"
    );
    assert_eq!(captured.header("content-type"), Some(SLACK_CONTENT_TYPE));
    assert_eq!(captured.header("accept"), Some(SLACK_ACCEPT));
    assert_eq!(captured.header("user-agent"), Some(SLACK_USER_AGENT));
}

#[test]
fn the_auth_test_method_sends_its_exact_request_and_parses_the_identity_back() {
    let fake = FakeSlack::spawn(vec![Canned::json(&format!(
        "{{\"ok\":true,\"url\":\"https://exemple-reserve.invalid/\",\"team\":\"Exemple\",\
         \"user\":\"monique\",\"team_id\":\"{TEAM}\",\"user_id\":\"{USER}\",\
         \"bot_id\":\"{BOT}\",\"is_enterprise_install\":false}}"
    ))]);
    let client = slack_client(&fake);

    let outcome = client.auth_test().expect("call");

    let captured = fake.only_request();
    assert_wire_shape(&captured, "/api/auth.test");
    assert_eq!(
        captured.body, "",
        "the one method with no argument sends an empty form body"
    );

    let identity = outcome.accepted().expect("accepted identity");
    assert_eq!(identity.url, "https://exemple-reserve.invalid/");
    assert_eq!(identity.team, "Exemple");
    assert_eq!(identity.user, "monique");
    assert_eq!(identity.team_id.as_str(), TEAM);
    assert_eq!(identity.user_id.as_str(), USER);
}

#[test]
fn the_conversations_list_method_sends_its_exact_request_and_parses_the_page_back() {
    let fake = FakeSlack::spawn(vec![Canned::json(&format!(
        "{{\"ok\":true,\"channels\":[{}],\
         \"response_metadata\":{{\"next_cursor\":\"dGVhbTpDMFJFU0VSVkVE\"}}}}",
        channel_json()
    ))]);
    let client = slack_client(&fake);

    let outcome = client
        .conversations_list(
            &ConversationsListRequest::new(ConversationTypes::all_channels(), 200).expect("list"),
        )
        .expect("call");

    let captured = fake.only_request();
    assert_wire_shape(&captured, "/api/conversations.list");
    assert_eq!(
        captured.body,
        "types=public_channel%2Cprivate_channel&limit=200"
    );

    let page = outcome.accepted().expect("accepted page");
    assert_eq!(page.channels.len(), 1);
    assert_eq!(page.channels[0].id.as_str(), CHANNEL);
    assert_eq!(page.channels[0].name, "reserve-general");
    assert!(page.channels[0].is_channel);
    assert!(!page.channels[0].is_private);
    assert!(!page.channels[0].is_archived);
    assert_eq!(page.channels[0].is_member, Some(true));
    assert_eq!(
        page.next_cursor.as_ref().map(Cursor::as_str),
        Some("dGVhbTpDMFJFU0VSVkVE")
    );
}

#[test]
fn the_conversations_info_method_sends_its_exact_request_and_parses_the_channel_back() {
    let fake = FakeSlack::spawn(vec![Canned::json(&format!(
        "{{\"ok\":true,\"channel\":{}}}",
        channel_json()
    ))]);
    let client = slack_client(&fake);

    let outcome = client
        .conversations_info(&ConversationsInfoRequest::new(channel()))
        .expect("call");

    let captured = fake.only_request();
    assert_wire_shape(&captured, "/api/conversations.info");
    assert_eq!(captured.body, "channel=C0RESERVED");

    let channel = outcome.accepted().expect("accepted channel");
    assert_eq!(channel.id.as_str(), CHANNEL);
    assert_eq!(
        channel.name, "reserve-general",
        "the legacy reader substitutes the empty string here; this one reads the name"
    );
}

#[test]
fn the_conversations_history_method_reads_a_channels_recent_messages() {
    let integration = format!(
        "{{\"type\":\"message\",\"subtype\":\"bot_message\",\"bot_id\":\"{BOT}\",\
         \"username\":\"Monique\",\"text\":\"ticket recu\",\"ts\":\"1723542100.000200\"}}"
    );
    let fake = FakeSlack::spawn(vec![Canned::json(&format!(
        "{{\"ok\":true,\"messages\":[{},{}],\"has_more\":true,\"pin_count\":0,\
         \"response_metadata\":{{\"next_cursor\":\"bmV4dF90czox\"}}}}",
        message_json(),
        integration
    ))]);
    let client = slack_client(&fake);

    let outcome = client
        .conversations_history(
            &history(40)
                .since(MessageTs::new("1723500000.000000").expect("ts"))
                .from_cursor(Cursor::new("cHJldjox").expect("cursor")),
        )
        .expect("call");

    let captured = fake.only_request();
    assert_wire_shape(&captured, "/api/conversations.history");
    assert_eq!(
        captured.body,
        "channel=C0RESERVED&limit=40&cursor=cHJldjox&oldest=1723500000.000000"
    );

    let page = outcome.accepted().expect("accepted page");
    assert!(page.has_more);
    assert_eq!(
        page.next_cursor.as_ref().map(Cursor::as_str),
        Some("bmV4dF90czox")
    );
    assert_eq!(page.messages.len(), 2);

    let human = &page.messages[0];
    assert_eq!(human.user.as_ref().map(UserId::as_str), Some(USER));
    assert_eq!(human.text, "le paiement echoue");
    assert_eq!(human.ts.as_str(), "1723542000.000100");
    assert_eq!(human.reply_count, Some(2));
    assert!(human.is_from_member());
    assert!(human.is_top_level());

    let app = &page.messages[1];
    assert_eq!(app.user, None);
    assert_eq!(app.bot_id.as_deref(), Some(BOT));
    assert_eq!(app.subtype.as_deref(), Some("bot_message"));
    assert!(!app.is_from_member());
}

#[test]
fn paging_a_history_returns_slacks_own_cursor_verbatim_on_the_next_request() {
    let second = format!(
        "{{\"type\":\"message\",\"user\":\"{USER}\",\"text\":\"suite\",\
         \"ts\":\"1723541000.000100\"}}"
    );
    let fake = FakeSlack::spawn(vec![
        Canned::json(&format!(
            "{{\"ok\":true,\"messages\":[{}],\"has_more\":true,\
             \"response_metadata\":{{\"next_cursor\":\"bmV4dF90czoxNzIzNTQxMDAw\"}}}}",
            message_json()
        )),
        Canned::json(&format!(
            "{{\"ok\":true,\"messages\":[{second}],\"has_more\":false,\
             \"response_metadata\":{{\"next_cursor\":\"\"}}}}"
        )),
    ]);
    let client = slack_client(&fake);

    let first = client
        .conversations_history(&history(1))
        .expect("call")
        .accepted()
        .expect("accepted page")
        .clone();
    let cursor = first.next_cursor.clone().expect("a cursor for page two");

    let last = client
        .conversations_history(&history(1).from_cursor(cursor))
        .expect("call")
        .accepted()
        .expect("accepted page")
        .clone();
    assert!(!last.has_more);
    assert_eq!(
        last.next_cursor, None,
        "Slack spells the last page as an empty cursor"
    );
    assert_eq!(last.messages[0].text, "suite");

    let captured = fake.captured();
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0].body, "channel=C0RESERVED&limit=1");
    assert_eq!(
        captured[1].body,
        "channel=C0RESERVED&limit=1&cursor=bmV4dF90czoxNzIzNTQxMDAw",
        "the cursor must go back exactly as Slack issued it"
    );
}

#[test]
fn the_users_info_method_resolves_an_author_to_a_display_name() {
    let fake = FakeSlack::spawn(vec![Canned::json(&format!(
        "{{\"ok\":true,\"user\":{{\"id\":\"{USER}\",\"team_id\":\"{TEAM}\",\"name\":\"claire\",\
         \"real_name\":\"Claire Martin\",\"deleted\":false,\"is_bot\":false,\
         \"profile\":{{\"display_name\":\"Claire\",\"real_name\":\"Claire Martin\"}}}}}}"
    ))]);
    let client = slack_client(&fake);

    let outcome = client
        .users_info(&UsersInfoRequest::new(UserId::new(USER).expect("user")))
        .expect("call");

    let captured = fake.only_request();
    assert_wire_shape(&captured, "/api/users.info");
    assert_eq!(captured.body, "user=U0RESERVED");

    let user = outcome.accepted().expect("accepted user");
    assert_eq!(user.id.as_str(), USER);
    assert_eq!(user.name, "claire");
    assert_eq!(user.display_label(), "Claire");
    assert_eq!(user.is_bot, Some(false));
    assert_eq!(user.deleted, Some(false));
}

#[test]
fn the_post_message_method_sends_its_exact_request_and_parses_the_receipt_back() {
    let fake = FakeSlack::spawn(vec![Canned::json(&format!(
        "{{\"ok\":true,\"channel\":\"{CHANNEL}\",\"ts\":\"1723542300.000400\",\
         \"message\":{{\"type\":\"message\",\"subtype\":\"bot_message\",\"bot_id\":\"{BOT}\",\
         \"text\":\"Bonjour,\\nc'est regle.\",\"ts\":\"1723542300.000400\",\
         \"thread_ts\":\"1723542000.000100\"}}}}"
    ))]);
    let client = slack_client(&fake);

    let outcome = client
        .post_message(
            &PostMessageRequest::new(
                channel(),
                MessageText::new("Bonjour,\nc'est regle.").expect("text"),
            )
            .in_thread(MessageTs::new("1723542000.000100").expect("ts")),
        )
        .expect("call");

    let captured = fake.only_request();
    assert_wire_shape(&captured, "/api/chat.postMessage");
    assert_eq!(
        captured.body,
        "channel=C0RESERVED&text=Bonjour%2C%0Ac%27est%20regle.&thread_ts=1723542000.000100"
    );

    let posted = outcome.accepted().expect("accepted receipt");
    assert_eq!(posted.channel.as_str(), CHANNEL);
    assert_eq!(posted.ts.as_str(), "1723542300.000400");
    assert_eq!(posted.message.text, "Bonjour,\nc'est regle.");
    assert_eq!(posted.message.ts, posted.ts);
}

#[test]
fn hostile_message_content_survives_one_round_trip_byte_exactly() {
    // Text full of JSON metacharacters must arrive at the fake as the same
    // text, not as a broken envelope.
    let hostile = "quote\" slash\\ brace} newline\nend";
    let fake = FakeSlack::spawn(vec![Canned::json(&format!(
        "{{\"ok\":true,\"channel\":\"{CHANNEL}\",\"ts\":\"1723542300.000400\",\
         \"message\":{{\"type\":\"message\",\"bot_id\":\"{BOT}\",\"text\":\"x\",\
         \"ts\":\"1723542300.000400\"}}}}"
    ))]);
    let client = slack_client(&fake);
    client
        .post_message(&PostMessageRequest::new(
            channel(),
            MessageText::new(hostile).expect("text"),
        ))
        .expect("call");

    let captured = fake.only_request();
    // Every JSON and form metacharacter in the text is percent-encoded, so the
    // text arrives as the value of `text` and cannot become body structure.
    assert_eq!(
        captured.body,
        "channel=C0RESERVED&text=quote%22%20slash%5C%20brace%7D%20newline%0Aend"
    );
}

#[test]
fn the_credential_reaches_the_wire_once_and_nothing_else() {
    let fake = FakeSlack::spawn(vec![Canned::json(&format!(
        "{{\"ok\":true,\"channel\":\"{CHANNEL}\",\"ts\":\"1723542300.000400\",\
         \"message\":{{\"type\":\"message\",\"bot_id\":\"{BOT}\",\"text\":\"bonjour\",\
         \"ts\":\"1723542300.000400\"}}}}"
    ))]);
    let client = slack_client(&fake);
    let request = PostMessageRequest::new(channel(), MessageText::new("bonjour").expect("text"));
    client.post_message(&request).expect("call");

    // Everything a host could observe or log about this client and its
    // credential.
    let token = SlackToken::new(TOKEN.as_bytes().to_vec()).expect("token");
    let operation = automonique_slack_connector::SlackOperation::ChatPostMessage(request);
    let rendered = format!(
        "{client:?}|{}|{}|{:?}|{}|{:?}|{token:?}|{:?}",
        client.endpoint(operation.method()),
        SlackClient::canonical_body(&operation),
        SlackFailure::Unavailable,
        SlackFailure::Unavailable,
        client.base(),
        token.authorization()
    );
    assert!(!rendered.contains(TOKEN), "rendered: {rendered}");
    assert!(!rendered.contains("xoxb-"), "rendered: {rendered}");
    assert!(rendered.contains("<redacted>"));

    // The one place it legitimately appears is the header the fake received,
    // and it appears there exactly once.
    let captured = fake.only_request();
    assert_eq!(
        captured.header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    assert!(
        !captured.body.contains(TOKEN),
        "the credential must never ride in a body"
    );
    assert!(
        !captured.body.contains("xoxb-"),
        "the credential must never ride in a body"
    );
    assert!(
        !captured.request_line.contains(TOKEN),
        "the credential must never ride in a path"
    );
    assert_eq!(
        captured
            .headers
            .iter()
            .filter(|(_, value)| value.contains(TOKEN))
            .count(),
        1,
        "exactly one header carries the credential"
    );
}

#[test]
fn a_slack_error_is_a_parsed_rejection_rather_than_a_transport_failure() {
    let cases: [(&str, SlackErrorKind); 5] = [
        ("not_in_channel", SlackErrorKind::NotInChannel),
        ("channel_not_found", SlackErrorKind::ChannelNotFound),
        ("invalid_auth", SlackErrorKind::InvalidAuth),
        ("missing_scope", SlackErrorKind::MissingScope),
        ("is_archived", SlackErrorKind::Other),
    ];
    for (code, kind) in cases {
        // Slack reports its own refusals as `200 {"ok":false}`.
        let fake = FakeSlack::spawn(vec![Canned::json(&format!(
            "{{\"ok\":false,\"error\":\"{code}\"}}"
        ))]);
        let client = slack_client(&fake);
        let outcome = client
            .conversations_history(&history(40))
            .expect("a slack refusal is a well-formed answer, not a failure");
        let rejection = outcome.rejected().expect("rejected");
        assert_eq!(rejection.code().as_str(), code);
        assert_eq!(rejection.kind(), kind, "code {code}");
        assert_eq!(rejection.retry_after_seconds(), None);
        assert!(outcome.accepted().is_none());
    }

    // The write path reads the same envelope: a bot that was never invited is
    // told exactly that, rather than being told the network failed.
    let fake = FakeSlack::spawn(vec![Canned::json(
        "{\"ok\":false,\"error\":\"not_in_channel\"}",
    )]);
    let client = slack_client(&fake);
    let outcome = client
        .post_message(&PostMessageRequest::new(
            channel(),
            MessageText::new("bonjour").expect("text"),
        ))
        .expect("call");
    assert_eq!(
        outcome.rejected().expect("rejected").kind(),
        SlackErrorKind::NotInChannel
    );
}

#[test]
fn a_rate_limited_call_surfaces_the_wait_slack_asked_for_without_taking_it() {
    let fake = FakeSlack::spawn(vec![
        Canned::status(429, "{\"ok\":false,\"error\":\"ratelimited\"}")
            .with_header("retry-after", "30"),
    ]);
    let client = slack_client(&fake);

    let started = Instant::now();
    let outcome = client
        .conversations_history(&history(200))
        .expect("a 429 is a well-formed answer, not a failure");
    let elapsed = started.elapsed();

    let rejection = outcome.rejected().expect("rejected");
    assert_eq!(rejection.kind(), SlackErrorKind::RateLimited);
    assert_eq!(rejection.retry_after_seconds(), Some(30));
    assert_eq!(rejection.code().as_str(), "ratelimited");
    assert!(
        elapsed < Duration::from_secs(5),
        "the wait is carried, never taken: took {elapsed:?}"
    );

    // Slack's rate-limit answer has historically been plain text, and the
    // status is the news either way.
    let fake = FakeSlack::spawn(vec![
        Canned::status(429, "Too many requests")
            .with_content_type("text/plain")
            .with_header("retry-after", "1"),
    ]);
    let client = slack_client(&fake);
    let outcome = client.auth_test().expect("call");
    let rejection = outcome.rejected().expect("rejected");
    assert_eq!(rejection.kind(), SlackErrorKind::RateLimited);
    assert_eq!(rejection.retry_after_seconds(), Some(1));
    assert_eq!(rejection.code().as_str(), "ratelimited");

    // A 429 with no header at all is still a rate-limited rejection, with no
    // wait invented for it.
    let fake = FakeSlack::spawn(vec![Canned::status(
        429,
        "{\"ok\":false,\"error\":\"ratelimited\"}",
    )]);
    let client = slack_client(&fake);
    let outcome = client.auth_test().expect("call");
    let rejection = outcome.rejected().expect("rejected");
    assert_eq!(rejection.kind(), SlackErrorKind::RateLimited);
    assert_eq!(rejection.retry_after_seconds(), None);
}

#[test]
fn a_malformed_response_is_a_typed_refusal_rather_than_a_panic() {
    let cases: [(&str, SlackFailure); 7] = [
        ("{\"ok\":true,", SlackFailure::InvalidResponse),
        ("<html>maintenance</html>", SlackFailure::InvalidResponse),
        ("[]", SlackFailure::InvalidResponse),
        // No `ok` at all is not the Slack envelope.
        ("{\"messages\":[]}", SlackFailure::InvalidResponse),
        ("{\"ok\":\"true\"}", SlackFailure::InvalidResponse),
        // Two `ok` fields would let a reader and this decoder disagree about
        // whether the call succeeded.
        (
            "{\"ok\":false,\"ok\":true,\"error\":\"x\"}",
            SlackFailure::InvalidResponse,
        ),
        ("{\"ok\":false}", SlackFailure::MissingField),
    ];
    for (body, expected) in cases {
        let fake = FakeSlack::spawn(vec![Canned::json(body)]);
        let client = slack_client(&fake);
        assert_eq!(
            client.conversations_history(&history(40)).err(),
            Some(expected),
            "body {body:?}"
        );
    }
}

#[test]
fn a_response_missing_a_contract_field_is_refused_rather_than_repaired() {
    for key in ["id", "name", "is_channel", "is_private", "is_archived"] {
        let mut row: serde_json::Value = serde_json::from_str(&channel_json()).expect("row");
        row.as_object_mut().expect("object").remove(key);

        let fake = FakeSlack::spawn(vec![Canned::json(&format!(
            "{{\"ok\":true,\"channel\":{row}}}"
        ))]);
        let client = slack_client(&fake);
        assert_eq!(
            client
                .conversations_info(&ConversationsInfoRequest::new(channel()))
                .err(),
            Some(SlackFailure::MissingField),
            "dropping {key} must be a refusal, never a plausible-looking channel"
        );
    }
    for key in ["type", "ts"] {
        let mut row: serde_json::Value = serde_json::from_str(&message_json()).expect("row");
        row.as_object_mut().expect("object").remove(key);

        let fake = FakeSlack::spawn(vec![Canned::json(&format!(
            "{{\"ok\":true,\"messages\":[{row}],\"has_more\":false}}"
        ))]);
        let client = slack_client(&fake);
        assert_eq!(
            client.conversations_history(&history(40)).err(),
            Some(SlackFailure::MissingField),
            "dropping {key} must be a refusal, never a plausible-looking message"
        );
    }
    // The page's own answer is required too: without `has_more` a caller
    // cannot tell "that is everything" from "there is more".
    let fake = FakeSlack::spawn(vec![Canned::json("{\"ok\":true,\"messages\":[]}")]);
    let client = slack_client(&fake);
    assert_eq!(
        client.conversations_history(&history(40)).err(),
        Some(SlackFailure::MissingField)
    );
}

#[test]
fn an_oversized_response_is_refused_rather_than_buffered() {
    let padding = "a".repeat(MAX_SLACK_RESPONSE_BYTES);
    let body = format!("{{\"ok\":true,\"messages\":[],\"has_more\":false,\"pad\":\"{padding}\"}}");
    assert!(body.len() > MAX_SLACK_RESPONSE_BYTES);

    let fake = FakeSlack::spawn(vec![Canned::json(&body)]);
    let client = slack_client(&fake);
    assert_eq!(
        client.conversations_history(&history(40)).err(),
        Some(SlackFailure::ResponseTooLarge)
    );
}

#[test]
fn a_page_longer_than_was_asked_for_is_refused() {
    let fake = FakeSlack::spawn(vec![Canned::json(&format!(
        "{{\"ok\":true,\"messages\":[{},{}],\"has_more\":false}}",
        message_json(),
        message_json()
    ))]);
    let client = slack_client(&fake);
    assert_eq!(
        client.conversations_history(&history(1)).err(),
        Some(SlackFailure::TooManyItems)
    );

    let fake = FakeSlack::spawn(vec![Canned::json(&format!(
        "{{\"ok\":true,\"channels\":[{},{}]}}",
        channel_json(),
        channel_json()
    ))]);
    let client = slack_client(&fake);
    assert_eq!(
        client
            .conversations_list(
                &ConversationsListRequest::new(ConversationTypes::all_channels(), 1).expect("list")
            )
            .err(),
        Some(SlackFailure::TooManyItems)
    );
}

#[test]
fn a_redirect_is_refused_rather_than_followed() {
    for status in [301_u16, 302, 307, 308] {
        let fake = FakeSlack::spawn(vec![
            Canned::status(status, "{}")
                .with_header("location", "https://evil.invalid/api/chat.postMessage"),
        ]);
        let client = slack_client(&fake);
        assert_eq!(
            client.auth_test().err(),
            Some(SlackFailure::Redirected),
            "status {status}: a redirect decides where the credential goes next"
        );
    }
}

#[test]
fn a_non_json_success_is_refused_before_it_is_parsed() {
    for content_type in [
        "text/html",
        "text/json",
        "text/plain",
        "application/json; charset=latin1",
    ] {
        let fake = FakeSlack::spawn(vec![
            Canned::json("{\"ok\":true,\"messages\":[],\"has_more\":false}")
                .with_content_type(content_type),
        ]);
        let client = slack_client(&fake);
        assert_eq!(
            client.conversations_history(&history(40)).err(),
            Some(SlackFailure::UnexpectedContentType),
            "content type {content_type}"
        );
    }
}

#[test]
fn a_status_slack_does_not_use_is_named_rather_than_parsed() {
    // Slack answers 200 for its own refusals, so anything else came from in
    // front of it.
    for (status, expected) in [
        (401_u16, SlackFailure::Unauthorized),
        (403, SlackFailure::Unauthorized),
        (500, SlackFailure::UnexpectedStatus),
        (503, SlackFailure::UnexpectedStatus),
    ] {
        let fake = FakeSlack::spawn(vec![
            Canned::status(status, "<html>proxy</html>").with_content_type("text/html"),
        ]);
        let client = slack_client(&fake);
        assert_eq!(client.auth_test().err(), Some(expected), "status {status}");
    }
}

#[test]
fn a_silent_server_ends_the_call_at_the_clients_deadline_rather_than_hanging() {
    let fake = FakeSlack::spawn(vec![Canned::silent()]);
    let client = slack_client(&fake);

    let started = Instant::now();
    let result = client.auth_test();
    let elapsed = started.elapsed();

    assert_eq!(result.err(), Some(SlackFailure::TimedOut));
    assert!(
        elapsed < Duration::from_secs(5),
        "the request budget must fire, not hang: took {elapsed:?}"
    );
    assert!(
        elapsed >= CLIENT_BUDGET,
        "the budget must actually be waited out: took {elapsed:?}"
    );
    assert_eq!(fake.captured().len(), 1);
}

#[test]
fn a_refused_connection_is_a_typed_failure_rather_than_a_panic() {
    // Bind and immediately drop, so the port is almost certainly closed.
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("address").port()
    };
    let client = SlackClient::with_request_timeout(
        SlackBase::new(&format!("http://127.0.0.1:{port}")).expect("base"),
        SlackToken::new(TOKEN.as_bytes().to_vec()).expect("token"),
        CLIENT_BUDGET,
    );
    assert!(matches!(
        client.auth_test().err(),
        Some(SlackFailure::Unavailable | SlackFailure::TimedOut)
    ));
}

#[test]
fn no_fixture_can_become_a_live_call() {
    // Every client this suite builds is loopback-only, and the production
    // origin is never one of them.
    let fake = FakeSlack::spawn(vec![Canned::json("{\"ok\":true}")]);
    let client = slack_client(&fake);
    assert!(client.base().is_plaintext_loopback());
    assert!(
        client.base().origin().starts_with("http://127.0.0.1:"),
        "origin: {}",
        client.base().origin()
    );
    assert!(!client.base().origin().contains("slack.com"));
    assert_ne!(client.base(), &SlackBase::production());

    // And every identifier a fixture names is reserved or synthetic.
    for fixture in [channel_json(), message_json()] {
        assert!(fixture.contains("RESERVED"), "fixture: {fixture}");
    }
    for id in [CHANNEL, USER, TEAM, BOT] {
        assert!(id.ends_with("0RESERVED"), "id: {id}");
    }
}
