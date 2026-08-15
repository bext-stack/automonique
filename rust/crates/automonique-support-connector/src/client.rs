// SPDX-License-Identifier: Elastic-2.0

//! The synchronous fleet client.
//!
//! One endpoint, one verb, five actions. The client is the composition of
//! [`FleetRequest::canonical_body`] and the `decode_*` functions around a single
//! bounded HTTP call — it adds no field to a request and repairs no field in a
//! response, so everything it can send or accept is already provable without a
//! socket.
//!
//! The ureq agent mirrors `TelegramHttpsClient`: pinned WebPKI roots, no
//! environment proxy, no redirects, a header-size ceiling, and statuses
//! surfaced as values rather than errors. `https_only` is relaxed only for a
//! [`FleetBase`] that proved itself the plaintext-loopback shape, which is how
//! the hermetic tests reach an in-process fake without a certificate.

use std::fmt;
use std::io::Read;
use std::time::Duration;

use ureq::tls::{RootCerts, TlsConfig};

use crate::response::{
    decode_support_delivery, decode_support_issues, decode_support_note, decode_support_thread,
    decode_ticket_decision, decode_ticket_dispatch, decode_ticket_status,
};
use crate::{
    FLEET_REQUEST_TIMEOUT_SECONDS, FleetBase, FleetFailure, FleetInstanceId, FleetOutcome,
    FleetRequest, FleetToken, MAX_FLEET_RESPONSE_BYTES, SupportDelivery, SupportEmailRequest,
    SupportIssues, SupportIssuesRequest, SupportReplyRequest, SupportThreadNoteRequest,
    SupportThreadRef, SupportThreadResolveRequest, TicketDecisionReceipt, TicketDecisionRequest,
    TicketDispatchReceipt, TicketDispatchRequest, TicketStatus, TicketStatusRequest,
};

/// The one request path this connector can address.
///
/// Private and constant: with the origin locked by [`FleetBase`] and the action
/// locked by the request enum, this is the last piece of the URL, and no caller
/// string reaches any of the three.
const FLEET_PATH: &str = "/api/manage/shelldeck/fleet";

const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;

/// The workspace caps the `log` facade at Debug because ureq redacts request
/// metadata at Debug and reveals more at Trace. Rebuilding with Trace enabled
/// is intentionally unsupported, and this assertion is what says so.
const _: () = assert!((log::STATIC_MAX_LEVEL as usize) <= (log::LevelFilter::Debug as usize));

/// A synchronous client for one fleet instance.
///
/// The credential is held here for the client's lifetime and lent to the
/// request boundary one call at a time.
pub struct FleetClient {
    agent: ureq::Agent,
    url: String,
    base: FleetBase,
    instance: FleetInstanceId,
    token: FleetToken,
    timeout: Duration,
}

impl FleetClient {
    /// Bind one origin, one instance identity and one credential.
    ///
    /// The URL is materialized once, here, from the validated origin and the
    /// private path constant. Nothing later can change it. The request budget
    /// is [`FLEET_REQUEST_TIMEOUT_SECONDS`].
    #[must_use]
    pub fn new(base: FleetBase, instance: FleetInstanceId, token: FleetToken) -> Self {
        Self::with_request_timeout(
            base,
            instance,
            token,
            Duration::from_secs(FLEET_REQUEST_TIMEOUT_SECONDS),
        )
    }

    /// Bind a client with a *tighter* request budget.
    ///
    /// The budget is clamped to [`FLEET_REQUEST_TIMEOUT_SECONDS`], so a caller
    /// may only shorten it, never extend it: a host that is talked into asking
    /// for an hour still gets fifteen seconds. A zero budget is read as "the
    /// ceiling" rather than "no wait at all", because a zero-length deadline is
    /// never what a caller means.
    #[must_use]
    pub fn with_request_timeout(
        base: FleetBase,
        instance: FleetInstanceId,
        token: FleetToken,
        timeout: Duration,
    ) -> Self {
        let ceiling = Duration::from_secs(FLEET_REQUEST_TIMEOUT_SECONDS);
        let timeout = if timeout.is_zero() {
            ceiling
        } else {
            timeout.min(ceiling)
        };
        let tls = TlsConfig::builder().root_certs(RootCerts::WebPki).build();
        let config = ureq::Agent::config_builder()
            .https_only(!base.is_plaintext_loopback())
            .proxy(None)
            .max_redirects(0)
            .http_status_as_error(false)
            .max_response_header_size(MAX_RESPONSE_HEADER_BYTES)
            .tls_config(tls)
            .build();
        let url = format!("{}{FLEET_PATH}", base.origin());
        Self {
            agent: config.new_agent(),
            url,
            base,
            instance,
            token,
            timeout,
        }
    }

    /// The exact endpoint this client will address, credential-free.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.url
    }

    /// The origin this client is locked to.
    #[must_use]
    pub const fn base(&self) -> &FleetBase {
        &self.base
    }

    /// The instance identity every envelope carries.
    #[must_use]
    pub const fn instance(&self) -> &FleetInstanceId {
        &self.instance
    }

    /// The whole-call budget this client issues requests with.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        self.timeout
    }

    /// The exact body a request would send, without sending it.
    #[must_use]
    pub fn canonical_body(&self, request: &FleetRequest) -> String {
        request.canonical_body(&self.instance)
    }

    /// Read one page of the support board.
    ///
    /// # Errors
    ///
    /// Returns the closed [`FleetFailure`] vocabulary for a transport problem
    /// or a response that is not this action's contract.
    pub fn support_issues(
        &self,
        request: &SupportIssuesRequest,
    ) -> Result<FleetOutcome<SupportIssues>, FleetFailure> {
        let body = self.send(&FleetRequest::SupportIssues(request.clone()))?;
        decode_support_issues(&body)
    }

    /// Resolve one mail message to its support thread.
    ///
    /// # Errors
    ///
    /// As [`FleetClient::support_issues`], for this action's contract.
    pub fn resolve_thread(
        &self,
        request: &SupportThreadResolveRequest,
    ) -> Result<FleetOutcome<SupportThreadRef>, FleetFailure> {
        let body = self.send(&FleetRequest::SupportThreadResolve(request.clone()))?;
        decode_support_thread(&body)
    }

    /// Add one internal note to a support thread.
    ///
    /// # Errors
    ///
    /// As [`FleetClient::support_issues`], for this action's contract.
    pub fn add_thread_note(
        &self,
        request: &SupportThreadNoteRequest,
    ) -> Result<FleetOutcome<()>, FleetFailure> {
        let body = self.send(&FleetRequest::SupportThreadNote(request.clone()))?;
        decode_support_note(&body)
    }

    /// Reply to the requester on a support thread.
    ///
    /// An externally visible effect: call it only from a confirmed-action path.
    ///
    /// # Errors
    ///
    /// As [`FleetClient::support_issues`], for this action's contract.
    pub fn reply_thread(
        &self,
        request: &SupportReplyRequest,
    ) -> Result<FleetOutcome<SupportDelivery>, FleetFailure> {
        let body = self.send(&FleetRequest::SupportThreadReply(request.clone()))?;
        // The reply contract's acceptance signal is `ok` alone.
        decode_support_delivery(&body, false)
    }

    /// Send one support email.
    ///
    /// An externally visible effect: call it only from a confirmed-action path.
    ///
    /// # Errors
    ///
    /// As [`FleetClient::support_issues`], for this action's contract.
    pub fn send_email(
        &self,
        request: &SupportEmailRequest,
    ) -> Result<FleetOutcome<SupportDelivery>, FleetFailure> {
        let body = self.send(&FleetRequest::SupportEmail(request.clone()))?;
        // The email contract demands `ok` and `queued` both.
        decode_support_delivery(&body, true)
    }

    /// Dispatch one exact GitHub issue through Manage's project/profile and
    /// approval machinery.
    pub fn dispatch_ticket(
        &self,
        request: &TicketDispatchRequest,
    ) -> Result<FleetOutcome<TicketDispatchReceipt>, FleetFailure> {
        let body = self.send(&FleetRequest::TicketDispatch(request.clone()))?;
        decode_ticket_dispatch(&body)
    }

    /// Approve or reject one exact pending job using a stable decision key.
    pub fn decide_ticket(
        &self,
        request: &TicketDecisionRequest,
    ) -> Result<FleetOutcome<TicketDecisionReceipt>, FleetFailure> {
        let body = self.send(&FleetRequest::TicketDecision(request.clone()))?;
        decode_ticket_decision(&body)
    }

    /// Read one exact job created for this configured fleet instance.
    pub fn ticket_status(
        &self,
        request: &TicketStatusRequest,
    ) -> Result<FleetOutcome<TicketStatus>, FleetFailure> {
        let body = self.send(&FleetRequest::TicketStatus(request.clone()))?;
        decode_ticket_status(&body)
    }

    /// Issue one request and return its bounded response body.
    ///
    /// The credential is rendered into an `Authorization` header inside the
    /// callback and dropped when it returns; it is never stored on the request
    /// builder beyond that, never logged, and never named in a failure.
    fn send(&self, request: &FleetRequest) -> Result<Vec<u8>, FleetFailure> {
        let body = request.canonical_body(&self.instance);
        let mut response = self
            .token
            .authorization()
            .with_header_value(|header| {
                self.agent
                    .post(&self.url)
                    .header("authorization", header)
                    .header("content-type", "application/json")
                    .header("accept", "application/json")
                    .config()
                    .timeout_global(Some(self.timeout))
                    .build()
                    .send(&body)
            })
            .map_err(map_ureq_error)?;

        let status = response.status().as_u16();
        if matches!(status, 401 | 403) {
            // Named apart from any other status because a revoked fleet token
            // is the failure mode that otherwise looks like a quiet outage.
            return Err(FleetFailure::Unauthorized);
        }
        if status != 200 {
            return Err(FleetFailure::UnexpectedStatus);
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok());
        if !content_type.is_some_and(is_json_content_type) {
            return Err(FleetFailure::UnexpectedContentType);
        }

        let reader = response
            .body_mut()
            .with_config()
            .limit((MAX_FLEET_RESPONSE_BYTES + 1) as u64)
            .reader();
        read_bounded_body(reader)
    }
}

/// No field of this client is safe to print except the endpoint, so `Debug`
/// prints that and says so about the rest.
impl fmt::Debug for FleetClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FleetClient")
            .field("endpoint", &self.url)
            .field("instance", &self.instance)
            .field("authorization", &"<redacted>")
            .finish()
    }
}

fn is_json_content_type(value: &str) -> bool {
    let mut fields = value.split(';');
    if !fields
        .next()
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
    {
        return false;
    }
    fields.all(|parameter| {
        let Some((name, value)) = parameter.trim().split_once('=') else {
            return false;
        };
        name.trim().eq_ignore_ascii_case("charset")
            && value.trim().trim_matches('"').eq_ignore_ascii_case("utf-8")
    })
}

fn read_bounded_body(mut reader: impl Read) -> Result<Vec<u8>, FleetFailure> {
    let mut body = Vec::new();
    reader
        .read_to_end(&mut body)
        .map_err(|error| map_ureq_error(ureq::Error::from(error)))?;
    if body.len() > MAX_FLEET_RESPONSE_BYTES {
        return Err(FleetFailure::ResponseTooLarge);
    }
    Ok(body)
}

/// Map a transport error onto the closed vocabulary, borrowing nothing from it.
///
/// ureq's own error rendering can name the URL it was dialling; none of it is
/// carried across this boundary.
fn map_ureq_error(error: ureq::Error) -> FleetFailure {
    match error {
        ureq::Error::Timeout(_) => FleetFailure::TimedOut,
        ureq::Error::BodyExceedsLimit(_) => FleetFailure::ResponseTooLarge,
        _ => FleetFailure::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(base: &str) -> FleetClient {
        FleetClient::new(
            FleetBase::new(base).expect("base"),
            FleetInstanceId::new("sd-instance-01").expect("instance"),
            FleetToken::new(b"sd_fixture-secret-never-print".to_vec()).expect("token"),
        )
    }

    #[test]
    fn the_endpoint_is_the_locked_origin_plus_the_one_fleet_path() {
        let client = client("https://manage.example.com");
        assert_eq!(
            client.endpoint(),
            "https://manage.example.com/api/manage/shelldeck/fleet"
        );
        assert_eq!(FLEET_PATH, "/api/manage/shelldeck/fleet");
    }

    #[test]
    fn a_tls_base_yields_a_direct_verified_non_redirecting_agent() {
        let client = client("https://manage.example.com");
        let config = client.agent.config();
        assert!(config.https_only());
        assert!(config.proxy().is_none());
        assert_eq!(config.max_redirects(), 0);
        assert!(!config.http_status_as_error());
        assert_eq!(config.max_response_header_size(), MAX_RESPONSE_HEADER_BYTES);
        assert!(matches!(
            config.tls_config().root_certs(),
            RootCerts::WebPki
        ));
        assert!(log::STATIC_MAX_LEVEL <= log::LevelFilter::Debug);
    }

    #[test]
    fn only_a_loopback_base_relaxes_https_only() {
        assert!(
            client("https://manage.example.com")
                .agent
                .config()
                .https_only()
        );
        assert!(!client("http://127.0.0.1:8080").agent.config().https_only());
    }

    #[test]
    fn the_credential_never_reaches_debug_the_endpoint_or_a_body() {
        const SECRET: &str = "sd_fixture-secret-never-print";
        let client = client("https://manage.example.com");
        let request = FleetRequest::SupportEmail(
            SupportEmailRequest::new("act-1", "claire@exemple.invalid", "Sujet", "Corps")
                .expect("email"),
        );
        let rendered = format!(
            "{client:?}|{}|{}|{:?}|{}",
            client.endpoint(),
            client.canonical_body(&request),
            FleetFailure::Unauthorized,
            FleetFailure::Unauthorized
        );
        assert!(!rendered.contains(SECRET), "rendered: {rendered}");
        assert!(!rendered.contains("sd_fixture"), "rendered: {rendered}");
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn the_request_budget_may_only_be_tightened_never_extended() {
        let ceiling = Duration::from_secs(FLEET_REQUEST_TIMEOUT_SECONDS);
        let tighten = |timeout| {
            FleetClient::with_request_timeout(
                FleetBase::new("https://manage.example.com").expect("base"),
                FleetInstanceId::new("sd-instance-01").expect("instance"),
                FleetToken::new(b"sd_fixture".to_vec()).expect("token"),
                timeout,
            )
            .request_timeout()
        };
        assert_eq!(
            client("https://manage.example.com").request_timeout(),
            ceiling
        );
        assert_eq!(tighten(Duration::from_secs(1)), Duration::from_secs(1));
        assert_eq!(tighten(Duration::from_secs(3600)), ceiling);
        assert_eq!(tighten(Duration::ZERO), ceiling);
    }

    #[test]
    fn the_response_content_type_is_closed() {
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("Application/Json; charset=UTF-8"));
        assert!(!is_json_content_type("text/json"));
        assert!(!is_json_content_type("application/json; profile=secret"));
        assert!(!is_json_content_type("application/json; charset=latin1"));
        assert!(!is_json_content_type("text/html"));
    }

    #[test]
    fn the_body_cap_accepts_the_boundary_and_refuses_one_over() {
        let at_limit = vec![b'a'; MAX_FLEET_RESPONSE_BYTES];
        assert_eq!(
            read_bounded_body(std::io::Cursor::new(&at_limit)).expect("at limit"),
            at_limit
        );
        assert_eq!(
            read_bounded_body(std::io::Cursor::new(vec![
                b'a';
                MAX_FLEET_RESPONSE_BYTES + 1
            ])),
            Err(FleetFailure::ResponseTooLarge)
        );
    }
}
