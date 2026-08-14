// SPDX-License-Identifier: Elastic-2.0

//! End-to-end proofs for the GitHub client, against a fake API on loopback.
//!
//! Nothing here touches an external network. Every destination is a
//! `TcpListener` this test owns and binds on `127.0.0.1:0`, so a run is
//! hermetic, no GitHub credential is real, and a failure is the connector's
//! rather than the internet's. `api.github.com` never appears as a base: every
//! client is built from the plaintext-loopback shape, and [`github_client`]
//! asserts that before returning.
//!
//! Every socket carries a five-second read and write deadline, and the client
//! under test is given a one-second budget, so a stuck peer fails an assertion
//! instead of hanging the suite.
//!
//! Fixtures name `example-org/example-repo` and `*.invalid` hosts throughout:
//! reserved shapes that address nothing, so no fixture can become a live call
//! by accident.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use automonique_github_connector::{
    Attribution, ChecklistItem, CommentRequest, CreateIssueRequest, GITHUB_ACCEPT,
    GITHUB_API_VERSION, GITHUB_USER_AGENT, GetCommentsRequest, GetIssueRequest, GitHubBase,
    GitHubClient, GitHubFailure, GitHubOperation, GitHubToken, IssueBodyText, IssueFilter,
    IssueListState, IssueNumber, IssuePriority, IssueSource, IssueState, IssueStatus, IssueTitle,
    Label, ListIssuesRequest, MAX_GITHUB_RESPONSE_BYTES, Page, RejectionKind, ReplaceLabelsRequest,
    RepoMap, RepoRule, RepoTarget, SearchIssuesRequest, SetStateRequest, Since, SiteId, TenantId,
    TenantIssue, ThreadId, TicketDraft, TicketExchange, body_carries_marker, marker_thread_id,
    ticket_labels,
};

/// Bound on every server-side wait. A test that would otherwise hang fails here.
const SERVER_TIMEOUT: Duration = Duration::from_secs(5);
/// Budget the client under test is given, so a deadline assertion is quick.
const CLIENT_BUDGET: Duration = Duration::from_secs(1);
/// Largest request head the fake will buffer before giving up.
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// The fixture credential. It is not a real token and addresses nothing: the
/// only server that ever sees it is the one in this file.
const TOKEN: &str = "ghp_fixture-secret-never-print";
const OWNER: &str = "example-org";
const REPO: &str = "example-repo";
const THREAD: &str = "thr_2026-08-13.01";

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

/// A fake GitHub on loopback that records what it was asked.
struct FakeGitHub {
    address: SocketAddr,
    captured: Arc<Mutex<Vec<Captured>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeGitHub {
    /// Answer each successive request with the next canned response, reusing
    /// the last one once the script is exhausted.
    fn spawn(script: Vec<Canned>) -> Self {
        assert!(!script.is_empty(), "a fake needs at least one response");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake github");
        let address = listener.local_addr().expect("fake github address");
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

impl Drop for FakeGitHub {
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
fn github_client(fake: &FakeGitHub) -> GitHubClient {
    let base =
        GitHubBase::new(&format!("http://127.0.0.1:{}", fake.port())).expect("loopback base");
    assert!(
        base.is_plaintext_loopback(),
        "every hermetic client must be loopback-only"
    );
    GitHubClient::with_request_timeout(
        base,
        GitHubToken::new(TOKEN.as_bytes().to_vec()).expect("token"),
        CLIENT_BUDGET,
    )
}

fn target() -> RepoTarget {
    RepoTarget::parse(OWNER, REPO).expect("target")
}

fn number() -> IssueNumber {
    IssueNumber::new(42).expect("number")
}

/// One complete issue object, carrying every field the contract names.
fn issue_json() -> String {
    format!(
        "{{\"number\":42,\"title\":\"Panne de paiement\",\"state\":\"open\",\
         \"html_url\":\"https://github.com/{OWNER}/{REPO}/issues/42\",\
         \"labels\":[{{\"name\":\"tenant:Boulangerie Milo\"}},{{\"name\":\"prio:high\"}}],\
         \"user\":{{\"login\":\"octocat\"}},\"comments\":2,\
         \"created_at\":\"2026-08-10T09:12:00Z\",\"updated_at\":\"2026-08-13T17:04:11Z\",\
         \"closed_at\":null,\"body\":\"corps\"}}"
    )
}

/// Every request must be one this connector is allowed to make.
fn assert_wire_shape(captured: &Captured, method: &str, path: &str) {
    assert_eq!(
        captured.request_line,
        format!("{method} {path} HTTP/1.1"),
        "the connector must address exactly the documented method and path"
    );
    assert_eq!(
        captured.header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str()),
        "the bearer header must reach the wire exactly as configured"
    );
    assert_eq!(captured.header("accept"), Some(GITHUB_ACCEPT));
    assert_eq!(
        captured.header("x-github-api-version"),
        Some(GITHUB_API_VERSION)
    );
    assert_eq!(captured.header("user-agent"), Some(GITHUB_USER_AGENT));
}

#[test]
fn the_create_issue_operation_sends_its_exact_request_and_parses_the_issue_back() {
    let fake = FakeGitHub::spawn(vec![Canned::status(201, &issue_json())]);
    let client = github_client(&fake);

    let request = CreateIssueRequest::new(
        target(),
        IssueTitle::new("Panne de paiement").expect("title"),
        IssueBodyText::new("corps").expect("body"),
        vec![
            Label::new("tenant:Boulangerie Milo").expect("label"),
            Label::new("prio:high").expect("label"),
        ],
    )
    .expect("create");
    let reply = client.create_issue(&request).expect("call");

    let captured = fake.only_request();
    assert_wire_shape(&captured, "POST", "/repos/example-org/example-repo/issues");
    assert_eq!(captured.header("content-type"), Some("application/json"));
    assert_eq!(
        captured.body,
        "{\"title\":\"Panne de paiement\",\"body\":\"corps\",\
         \"labels\":[\"tenant:Boulangerie Milo\",\"prio:high\"]}"
    );

    let issue = reply.accepted().expect("accepted issue");
    assert_eq!(issue.number.get(), 42);
    assert_eq!(issue.title, "Panne de paiement");
    assert_eq!(issue.state, IssueState::Open);
    assert_eq!(issue.target.to_string(), "example-org/example-repo");
    assert_eq!(issue.labels, vec!["tenant:Boulangerie Milo", "prio:high"]);
    assert_eq!(issue.author, "octocat");
    assert_eq!(issue.comment_count, 2);
    assert_eq!(issue.created_at, "2026-08-10T09:12:00Z");
    assert_eq!(issue.updated_at, "2026-08-13T17:04:11Z");
    assert_eq!(issue.closed_at, None);
    assert_eq!(issue.body, "corps");
}

#[test]
fn the_comment_operation_sends_its_exact_request_and_parses_the_reference_back() {
    let fake = FakeGitHub::spawn(vec![Canned::status(
        201,
        "{\"id\":9001,\"html_url\":\
         \"https://github.com/example-org/example-repo/issues/42#issuecomment-9001\"}",
    )]);
    let client = github_client(&fake);

    let reply = client
        .comment(&CommentRequest::new(
            target(),
            number(),
            IssueBodyText::new("Bonjour,\nc'est regle.").expect("body"),
        ))
        .expect("call");

    let captured = fake.only_request();
    assert_wire_shape(
        &captured,
        "POST",
        "/repos/example-org/example-repo/issues/42/comments",
    );
    assert_eq!(captured.body, "{\"body\":\"Bonjour,\\nc'est regle.\"}");

    let reference = reply.accepted().expect("accepted comment");
    assert_eq!(reference.id, 9_001);
    assert!(reference.url.ends_with("#issuecomment-9001"));
}

#[test]
fn the_set_state_operation_patches_and_reports_the_resulting_state() {
    let closed = issue_json()
        .replace("\"state\":\"open\"", "\"state\":\"closed\"")
        .replace(
            "\"closed_at\":null",
            "\"closed_at\":\"2026-08-14T08:00:00Z\"",
        );
    let fake = FakeGitHub::spawn(vec![Canned::json(&closed)]);
    let client = github_client(&fake);

    let reply = client
        .set_state(&SetStateRequest::new(
            target(),
            number(),
            IssueState::Closed,
        ))
        .expect("call");

    let captured = fake.only_request();
    assert_wire_shape(
        &captured,
        "PATCH",
        "/repos/example-org/example-repo/issues/42",
    );
    assert_eq!(captured.body, "{\"state\":\"closed\"}");

    let issue = reply.accepted().expect("accepted issue");
    assert_eq!(issue.state, IssueState::Closed);
    assert_eq!(issue.closed_at.as_deref(), Some("2026-08-14T08:00:00Z"));
}

#[test]
fn the_replace_labels_operation_puts_the_complete_set_and_reads_it_back() {
    let fake = FakeGitHub::spawn(vec![Canned::json(
        "[{\"name\":\"prio:urgent\"},{\"name\":\"tenant:Milo\"}]",
    )]);
    let client = github_client(&fake);

    let reply = client
        .replace_labels(
            &ReplaceLabelsRequest::new(
                target(),
                number(),
                vec![
                    Label::new("prio:urgent").expect("label"),
                    Label::new("tenant:Milo").expect("label"),
                ],
            )
            .expect("labels"),
        )
        .expect("call");

    let captured = fake.only_request();
    assert_wire_shape(
        &captured,
        "PUT",
        "/repos/example-org/example-repo/issues/42/labels",
    );
    assert_eq!(
        captured.body, "{\"labels\":[\"prio:urgent\",\"tenant:Milo\"]}",
        "PUT is replace-all: the array is the issue's complete label set"
    );
    assert_eq!(
        reply.accepted().expect("accepted labels"),
        &vec!["prio:urgent".to_owned(), "tenant:Milo".to_owned()]
    );
}

#[test]
fn the_read_operations_send_no_body_and_carry_their_paging_in_the_query() {
    // One issue.
    let fake = FakeGitHub::spawn(vec![Canned::json(&issue_json())]);
    let client = github_client(&fake);
    client
        .get_issue(&GetIssueRequest::new(target(), number()))
        .expect("call");
    let captured = fake.only_request();
    assert_wire_shape(
        &captured,
        "GET",
        "/repos/example-org/example-repo/issues/42",
    );
    assert!(captured.body.is_empty(), "a read sends no body");
    assert_eq!(
        captured.header("content-type"),
        None,
        "a read declares no content type"
    );

    // One page of comments.
    let fake = FakeGitHub::spawn(vec![Canned::json(
        "[{\"id\":9001,\"user\":{\"login\":\"octocat\"},\"body\":\"merci\",\
          \"created_at\":\"2026-08-13T17:04:11Z\",\"updated_at\":\"2026-08-13T17:05:11Z\"}]",
    )]);
    let client = github_client(&fake);
    let reply = client
        .get_comments(&GetCommentsRequest::new(
            target(),
            number(),
            Page::new(2, 100).expect("page"),
        ))
        .expect("call");
    assert_wire_shape(
        &fake.only_request(),
        "GET",
        "/repos/example-org/example-repo/issues/42/comments?per_page=100&page=2",
    );
    let comments = reply.accepted().expect("accepted comments");
    assert_eq!(comments.len(), 1);
    assert_eq!(comments[0].id, 9_001);
    assert_eq!(comments[0].author, "octocat");
    assert_eq!(comments[0].body, "merci");

    // One page of a repository's issues, filtered.
    let fake = FakeGitHub::spawn(vec![Canned::json(&format!("[{}]", issue_json()))]);
    let client = github_client(&fake);
    let filter = IssueFilter::new(IssueListState::All)
        .with_since(Since::new("2026-08-01T00:00:00Z").expect("since"))
        .with_labels(vec![Label::new("prio:high").expect("label")])
        .expect("labels");
    let reply = client
        .list_issues(&ListIssuesRequest::new(
            target(),
            filter,
            Page::new(1, 50).expect("page"),
        ))
        .expect("call");
    assert_wire_shape(
        &fake.only_request(),
        "GET",
        "/repos/example-org/example-repo/issues\
         ?state=all&per_page=50&page=1&sort=created&direction=desc\
         &since=2026-08-01T00%3A00%3A00Z&labels=prio%3Ahigh",
    );
    let page = reply.accepted().expect("accepted page");
    assert_eq!(page.issues.len(), 1);
    assert_eq!(page.pull_requests_skipped, 0);
    assert!(!page.has_more);

    // The account behind the credential.
    let fake = FakeGitHub::spawn(vec![Canned::json("{\"login\":\"octocat\",\"id\":1}")]);
    let client = github_client(&fake);
    let reply = client.whoami().expect("call");
    assert_wire_shape(&fake.only_request(), "GET", "/user");
    assert_eq!(reply.accepted().expect("accepted viewer").login, "octocat");
}

#[test]
fn the_search_operation_appends_the_issue_qualifier_and_recovers_each_repository() {
    let fake = FakeGitHub::spawn(vec![Canned::json(&format!(
        "{{\"total_count\":7,\"incomplete_results\":false,\"items\":[{}]}}",
        issue_json()
    ))]);
    let client = github_client(&fake);

    let reply = client
        .search_issues(
            &SearchIssuesRequest::new(
                "repo:example-org/example-repo panne",
                Page::new(1, 30).expect("page"),
            )
            .expect("search"),
        )
        .expect("call");

    assert_wire_shape(
        &fake.only_request(),
        "GET",
        "/search/issues?q=repo%3Aexample-org%2Fexample-repo%20panne%20is%3Aissue\
         &per_page=30&page=1",
    );
    let page = reply.accepted().expect("accepted page");
    assert_eq!(page.total, 7);
    assert_eq!(page.issues.len(), 1);
    assert_eq!(
        page.issues[0].target.to_string(),
        "example-org/example-repo",
        "a search item names its repository only in its URL"
    );
}

#[test]
fn a_listing_drops_pull_requests_and_reports_how_many_it_dropped() {
    let pull = issue_json().replace(
        "\"closed_at\":null",
        "\"pull_request\":{\"url\":\"https://api.github.com/x\"},\"closed_at\":null",
    );
    let fake = FakeGitHub::spawn(vec![Canned::json(&format!("[{},{}]", issue_json(), pull))]);
    let client = github_client(&fake);
    let reply = client
        .list_issues(&ListIssuesRequest::new(
            target(),
            IssueFilter::default(),
            Page::new(1, 2).expect("page"),
        ))
        .expect("call");
    let page = reply.accepted().expect("accepted page");
    assert_eq!(page.issues.len(), 1);
    assert_eq!(page.pull_requests_skipped, 1);
    assert!(page.has_more, "a full page means there may be another");

    // Reading a pull request directly is named rather than decoded as an issue.
    let fake = FakeGitHub::spawn(vec![Canned::json(&pull)]);
    let client = github_client(&fake);
    assert_eq!(
        client
            .get_issue(&GetIssueRequest::new(target(), number()))
            .err(),
        Some(GitHubFailure::NotAnIssue)
    );
}

#[test]
fn the_credential_reaches_the_wire_once_and_nothing_else() {
    let fake = FakeGitHub::spawn(vec![Canned::status(201, &issue_json())]);
    let client = github_client(&fake);
    let request = CreateIssueRequest::new(
        target(),
        IssueTitle::new("Panne de paiement").expect("title"),
        IssueBodyText::new("corps").expect("body"),
        Vec::new(),
    )
    .expect("create");
    client.create_issue(&request).expect("call");

    // Everything a host could observe or log about this client.
    let operation = GitHubOperation::CreateIssue(request);
    let rendered = format!(
        "{client:?}|{}|{}|{:?}|{}|{:?}",
        client.endpoint(&operation),
        operation.body().unwrap_or_default(),
        GitHubFailure::Unavailable,
        GitHubFailure::Unavailable,
        client.base()
    );
    assert!(!rendered.contains(TOKEN), "rendered: {rendered}");
    assert!(!rendered.contains("ghp_"), "rendered: {rendered}");
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
fn a_github_error_is_a_parsed_rejection_rather_than_a_transport_failure() {
    let cases: [(u16, &str, RejectionKind); 4] = [
        (401, "Bad credentials", RejectionKind::Unauthorized),
        (404, "Not Found", RejectionKind::NotFound),
        (422, "Validation Failed", RejectionKind::Validation),
        (500, "Server Error", RejectionKind::Other),
    ];
    for (status, message, kind) in cases {
        let fake = FakeGitHub::spawn(vec![Canned::status(
            status,
            &format!(
                "{{\"message\":\"{message}\",\"documentation_url\":\"https://docs.invalid\"}}"
            ),
        )]);
        let client = github_client(&fake);
        let reply = client
            .get_issue(&GetIssueRequest::new(target(), number()))
            .expect("a github refusal is a well-formed answer, not a failure");
        let rejection = reply.rejected().expect("rejected");
        assert_eq!(rejection.status(), status);
        assert_eq!(rejection.kind(), kind, "status {status}");
        assert_eq!(rejection.message().as_str(), message);
        assert!(reply.accepted().is_none());
    }
}

#[test]
fn a_spent_rate_window_is_told_apart_from_a_missing_scope() {
    // 403 with the window spent: wait.
    let fake = FakeGitHub::spawn(vec![
        Canned::status(403, "{\"message\":\"API rate limit exceeded\"}")
            .with_header("x-ratelimit-remaining", "0")
            .with_header("x-ratelimit-limit", "5000")
            .with_header("x-ratelimit-reset", "1760000000")
            .with_header("retry-after", "45"),
    ]);
    let client = github_client(&fake);
    let reply = client.whoami().expect("call");
    let rejection = reply.rejected().expect("rejected");
    assert_eq!(rejection.kind(), RejectionKind::RateLimited);
    assert_eq!(rejection.retry_after_seconds(), Some(45));
    assert_eq!(reply.rate().remaining(), Some(0));
    assert_eq!(reply.rate().limit(), Some(5_000));
    assert_eq!(reply.rate().reset(), Some(1_760_000_000));
    assert!(reply.rate().is_exhausted());

    // 403 with the window intact: fix the token's scope.
    let fake = FakeGitHub::spawn(vec![
        Canned::status(403, "{\"message\":\"Resource not accessible\"}")
            .with_header("x-ratelimit-remaining", "4999"),
    ]);
    let client = github_client(&fake);
    let reply = client.whoami().expect("call");
    assert_eq!(
        reply.rejected().expect("rejected").kind(),
        RejectionKind::Forbidden
    );
    assert_eq!(
        reply.rejected().expect("rejected").retry_after_seconds(),
        None
    );
}

#[test]
fn the_rate_window_rides_back_on_an_accepted_call_too() {
    let fake = FakeGitHub::spawn(vec![
        Canned::json("{\"login\":\"octocat\"}")
            .with_header("x-ratelimit-remaining", "4998")
            .with_header("x-ratelimit-limit", "5000")
            .with_header("x-ratelimit-reset", "1760000000"),
    ]);
    let client = github_client(&fake);
    let reply = client.whoami().expect("call");
    assert_eq!(reply.accepted().expect("accepted").login, "octocat");
    assert_eq!(reply.rate().remaining(), Some(4_998));
    assert!(!reply.rate().is_exhausted());

    // Absent headers are absent, never zero: a client that read a missing
    // window as "no calls left" would stop working for no reason.
    let fake = FakeGitHub::spawn(vec![Canned::json("{\"login\":\"octocat\"}")]);
    let client = github_client(&fake);
    let reply = client.whoami().expect("call");
    assert_eq!(reply.rate().remaining(), None);
    assert!(!reply.rate().is_exhausted());
}

#[test]
fn a_malformed_response_is_a_typed_refusal_rather_than_a_panic() {
    let cases: [(&str, GitHubFailure); 6] = [
        ("{\"number\":42,", GitHubFailure::InvalidResponse),
        ("<html>maintenance</html>", GitHubFailure::InvalidResponse),
        ("[]", GitHubFailure::InvalidResponse),
        ("{\"title\":\"x\"}", GitHubFailure::MissingField),
        (
            "{\"number\":42,\"number\":43,\"title\":\"x\"}",
            GitHubFailure::InvalidResponse,
        ),
        (
            "{\"number\":42,\"title\":\"x\",\"state\":\"merged\",\
             \"html_url\":\"https://github.com/example-org/example-repo/issues/42\",\
             \"labels\":[],\"user\":{\"login\":\"o\"},\"comments\":0,\
             \"created_at\":\"a\",\"updated_at\":\"b\"}",
            GitHubFailure::FieldOutOfBounds,
        ),
    ];
    for (body, expected) in cases {
        let fake = FakeGitHub::spawn(vec![Canned::json(body)]);
        let client = github_client(&fake);
        assert_eq!(
            client
                .get_issue(&GetIssueRequest::new(target(), number()))
                .err(),
            Some(expected),
            "body {body:?}"
        );
    }
}

#[test]
fn a_response_missing_a_contract_field_is_refused_rather_than_repaired() {
    for key in [
        "number",
        "title",
        "state",
        "html_url",
        "labels",
        "user",
        "comments",
        "created_at",
        "updated_at",
    ] {
        let mut row: serde_json::Value = serde_json::from_str(&issue_json()).expect("row");
        row.as_object_mut().expect("object").remove(key);

        let fake = FakeGitHub::spawn(vec![Canned::json(&row.to_string())]);
        let client = github_client(&fake);
        assert_eq!(
            client
                .get_issue(&GetIssueRequest::new(target(), number()))
                .err(),
            Some(GitHubFailure::MissingField),
            "dropping {key} must be a refusal, never a plausible-looking issue"
        );
    }
}

#[test]
fn an_oversized_response_is_refused_rather_than_buffered() {
    let padding = "a".repeat(MAX_GITHUB_RESPONSE_BYTES);
    let body = format!("{{\"login\":\"octocat\",\"pad\":\"{padding}\"}}");
    assert!(body.len() > MAX_GITHUB_RESPONSE_BYTES);

    let fake = FakeGitHub::spawn(vec![Canned::json(&body)]);
    let client = github_client(&fake);
    assert_eq!(client.whoami().err(), Some(GitHubFailure::ResponseTooLarge));
}

#[test]
fn a_page_longer_than_was_asked_for_is_refused() {
    let fake = FakeGitHub::spawn(vec![Canned::json(&format!(
        "[{},{}]",
        issue_json(),
        issue_json()
    ))]);
    let client = github_client(&fake);
    assert_eq!(
        client
            .list_issues(&ListIssuesRequest::new(
                target(),
                IssueFilter::default(),
                Page::new(1, 1).expect("page"),
            ))
            .err(),
        Some(GitHubFailure::TooManyItems)
    );
}

#[test]
fn a_redirect_is_refused_rather_than_followed() {
    for status in [301_u16, 302, 307, 308] {
        let fake = FakeGitHub::spawn(vec![
            Canned::status(status, "{}")
                .with_header("location", "https://evil.invalid/repos/x/y/issues"),
        ]);
        let client = github_client(&fake);
        assert_eq!(
            client.whoami().err(),
            Some(GitHubFailure::Redirected),
            "status {status}: a redirect decides where the credential goes next"
        );
    }
}

#[test]
fn a_non_json_success_is_refused_before_it_is_parsed() {
    for content_type in ["text/html", "text/json", "application/json; charset=latin1"] {
        let fake = FakeGitHub::spawn(vec![
            Canned::json("{\"login\":\"octocat\"}").with_content_type(content_type),
        ]);
        let client = github_client(&fake);
        assert_eq!(
            client.whoami().err(),
            Some(GitHubFailure::UnexpectedContentType),
            "content type {content_type}"
        );
    }
    // A refusal, on the other hand, is classified whatever it is written in:
    // GitHub's own maintenance page is still a 503.
    let fake = FakeGitHub::spawn(vec![
        Canned::status(503, "<html>maintenance</html>").with_content_type("text/html"),
    ]);
    let client = github_client(&fake);
    let reply = client.whoami().expect("call");
    let rejection = reply.rejected().expect("rejected");
    assert_eq!(rejection.status(), 503);
    assert_eq!(rejection.message().as_str(), "github 503");
}

#[test]
fn a_silent_server_ends_the_call_at_the_clients_deadline_rather_than_hanging() {
    let fake = FakeGitHub::spawn(vec![Canned::silent()]);
    let client = github_client(&fake);

    let started = Instant::now();
    let result = client.whoami();
    let elapsed = started.elapsed();

    assert_eq!(result.err(), Some(GitHubFailure::TimedOut));
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
    let client = GitHubClient::with_request_timeout(
        GitHubBase::new(&format!("http://127.0.0.1:{port}")).expect("base"),
        GitHubToken::new(TOKEN.as_bytes().to_vec()).expect("token"),
        CLIENT_BUDGET,
    );
    assert!(matches!(
        client.whoami().err(),
        Some(GitHubFailure::Unavailable | GitHubFailure::TimedOut)
    ));
}

#[test]
fn the_repo_map_decides_which_repository_the_request_addresses() {
    let map = RepoMap::new(
        Some(RepoTarget::parse(OWNER, "fallback-repo").expect("target")),
        vec![
            RepoRule::new(
                TenantId::new("tenant-a").expect("tenant"),
                None,
                RepoTarget::parse(OWNER, "tenant-a-repo").expect("target"),
                None,
            )
            .expect("rule"),
            RepoRule::new(
                TenantId::new("tenant-a").expect("tenant"),
                Some(SiteId::new("site-1").expect("site")),
                RepoTarget::parse(OWNER, "site-1-repo").expect("target"),
                None,
            )
            .expect("rule"),
        ],
    )
    .expect("map");

    let tenant = TenantId::new("tenant-a").expect("tenant");
    let site = SiteId::new("site-1").expect("site");
    let other = SiteId::new("site-2").expect("site");
    let unknown = TenantId::new("tenant-z").expect("tenant");

    // Each resolution files into a different repository, and the path proves it.
    for (resolved, expected_repo) in [
        (map.resolve(&tenant, Some(&site)), "site-1-repo"),
        (map.resolve(&tenant, Some(&other)), "tenant-a-repo"),
        (map.resolve(&tenant, None), "tenant-a-repo"),
        (map.resolve(&unknown, Some(&site)), "fallback-repo"),
    ] {
        let resolved = resolved.expect("resolved").clone();
        let fake = FakeGitHub::spawn(vec![Canned::status(201, &issue_json())]);
        let client = github_client(&fake);
        client
            .create_issue(
                &CreateIssueRequest::new(
                    resolved,
                    IssueTitle::new("Panne").expect("title"),
                    IssueBodyText::new("corps").expect("body"),
                    Vec::new(),
                )
                .expect("create"),
            )
            .expect("call");
        assert_eq!(
            fake.only_request().request_line,
            format!("POST /repos/example-org/{expected_repo}/issues HTTP/1.1"),
            "the resolved repository is the one addressed"
        );
    }
}

#[test]
fn a_support_thread_marker_survives_the_round_trip_and_makes_a_retry_idempotent() {
    let thread = ThreadId::new(THREAD).expect("thread");
    let draft = TicketDraft::new(
        IssueTitle::new("Milo Paris · Panne de paiement").expect("title"),
        Attribution::new("email")
            .expect("channel")
            .with_site("Milo Paris", Some("https://milo.invalid/"))
            .expect("site")
            .with_requested_by("Claire Martin")
            .expect("requested by"),
        vec![ChecklistItem::new("- [ ] Corriger le paiement").expect("item")],
    )
    .expect("draft")
    .with_exchanges(vec![
        TicketExchange::new("Claire", "2026-08-13T09:12:00Z", "le paiement echoue")
            .expect("exchange"),
    ])
    .expect("exchanges")
    .with_thread(thread.clone());
    let body = draft.render_body().expect("body");
    assert!(body_carries_marker(body.as_str(), &thread));

    // The created issue comes back carrying the body it was filed with.
    let created = format!(
        "{{\"number\":42,\"title\":\"Milo Paris · Panne de paiement\",\"state\":\"open\",\
         \"html_url\":\"https://github.com/{OWNER}/{REPO}/issues/42\",\"labels\":[],\
         \"user\":{{\"login\":\"octocat\"}},\"comments\":0,\
         \"created_at\":\"2026-08-13T09:13:00Z\",\"updated_at\":\"2026-08-13T09:13:00Z\",\
         \"closed_at\":null,\"body\":{}}}",
        serde_json::Value::String(body.as_str().to_owned())
    );
    let fake = FakeGitHub::spawn(vec![Canned::status(201, &created)]);
    let client = github_client(&fake);
    let reply = client
        .create_issue(
            &CreateIssueRequest::new(target(), draft.title().clone(), body.clone(), Vec::new())
                .expect("create"),
        )
        .expect("call");

    // The marker reached the wire inside the body, exactly once.
    let captured = fake.only_request();
    let sent: serde_json::Value = serde_json::from_str(&captured.body).expect("body is JSON");
    let sent_body = sent["body"].as_str().expect("body string");
    assert_eq!(sent_body, body.as_str());
    assert_eq!(
        sent_body.matches(&thread.marker()).count(),
        1,
        "the idempotency marker is written exactly once"
    );
    assert!(sent_body.ends_with(&thread.marker()));

    // And it is readable off the issue GitHub returned, which is what makes a
    // retry find this ticket instead of opening a second one.
    let issue = reply.accepted().expect("accepted issue");
    assert_eq!(marker_thread_id(&issue.body).as_ref(), Some(&thread));
    assert!(body_carries_marker(&issue.body, &thread));
    assert!(!body_carries_marker(
        &issue.body,
        &ThreadId::new("thr_autre").expect("thread")
    ));
}

#[test]
fn a_ticket_becomes_the_labels_the_legacy_push_would_have_set() {
    let ticket = TenantIssue::new(
        "iss-1",
        TenantId::new("tenant-a").expect("tenant"),
        "Boulangerie Milo",
        IssueTitle::new("Panne de paiement").expect("title"),
        IssueBodyText::new("corps").expect("body"),
        IssueStatus::Triaging,
        IssuePriority::High,
        IssueSource::Support,
        "Claire",
    )
    .expect("ticket")
    .with_site(
        Some(SiteId::new("site-1").expect("site")),
        Some("Milo Paris"),
    )
    .expect("site");

    let fake = FakeGitHub::spawn(vec![Canned::status(201, &issue_json())]);
    let client = github_client(&fake);
    client
        .create_issue(
            &CreateIssueRequest::new(
                target(),
                ticket.title().clone(),
                ticket.body().clone(),
                ticket_labels(&ticket).expect("labels"),
            )
            .expect("create"),
        )
        .expect("call");

    let captured = fake.only_request();
    let sent: serde_json::Value = serde_json::from_str(&captured.body).expect("body is JSON");
    assert_eq!(
        sent["labels"],
        serde_json::json!(["tenant:Boulangerie Milo", "site:Milo Paris", "prio:high"]),
        "the legacy label set, in the legacy order"
    );
}

#[test]
fn hostile_ticket_content_survives_one_round_trip_byte_exactly() {
    // A body full of JSON metacharacters must arrive at the fake as the same
    // text, not as a broken envelope.
    let hostile = "quote\" slash\\ brace} newline\nend";
    let fake = FakeGitHub::spawn(vec![Canned::status(
        201,
        "{\"id\":9001,\"html_url\":\
         \"https://github.com/example-org/example-repo/issues/42#issuecomment-9001\"}",
    )]);
    let client = github_client(&fake);
    client
        .comment(&CommentRequest::new(
            target(),
            number(),
            IssueBodyText::new(hostile).expect("body"),
        ))
        .expect("call");

    let captured = fake.only_request();
    let body: serde_json::Value = serde_json::from_str(&captured.body).expect("body is JSON");
    assert_eq!(body["body"], hostile);
}
