// SPDX-License-Identifier: Elastic-2.0

//! Typed `apps.connections.open` bootstrap for Slack Socket Mode.
//!
//! Slack's app-level token is rendered only inside the injected HTTP transport
//! call. Production always addresses one constant HTTPS endpoint with redirects
//! disabled; tests inject [`ConnectionsOpenTransport`] and therefore never need
//! a configurable origin or a real credential-bearing call.

use std::fmt;
use std::time::Duration;

use automonique_connector_substrate::http::{map_ureq_error, read_bounded_body};
use ureq::tls::{RootCerts, TlsConfig};

use crate::{
    MAX_SLACK_RESPONSE_BYTES, SLACK_ACCEPT, SLACK_CONTENT_TYPE, SLACK_REQUEST_TIMEOUT_SECONDS,
    SLACK_USER_AGENT, SlackAppToken, SlackFailure, SlackOutcome, SlackRejection, SlackSocketUrl,
    decode_apps_connections_open, decode_error_code,
};

/// The only endpoint an app-level credential may address.
pub const APPS_CONNECTIONS_OPEN_ENDPOINT: &str = "https://slack.com/api/apps.connections.open";

const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
const RATE_LIMITED: &str = "ratelimited";

/// One exact credential-bearing `apps.connections.open` request.
///
/// The body is empty and the token is carried only by `Authorization`, as Slack
/// requires. `Debug` never renders the header value.
pub struct ConnectionsOpenHttpRequest<'a> {
    authorization: &'a str,
}

impl<'a> ConnectionsOpenHttpRequest<'a> {
    #[must_use]
    pub const fn endpoint(&self) -> &'static str {
        APPS_CONNECTIONS_OPEN_ENDPOINT
    }

    #[must_use]
    pub const fn body(&self) -> &'static str {
        ""
    }

    #[must_use]
    pub const fn content_type(&self) -> &'static str {
        SLACK_CONTENT_TYPE
    }

    #[must_use]
    pub const fn accept(&self) -> &'static str {
        SLACK_ACCEPT
    }

    #[must_use]
    pub const fn user_agent(&self) -> &'static str {
        SLACK_USER_AGENT
    }

    /// Trusted HTTP adapter access to the short-lived header rendering.
    #[must_use]
    pub const fn authorization(&self) -> &'a str {
        self.authorization
    }
}

impl fmt::Debug for ConnectionsOpenHttpRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionsOpenHttpRequest")
            .field("endpoint", &APPS_CONNECTIONS_OPEN_ENDPOINT)
            .field("authorization", &"<redacted>")
            .field("body", &"")
            .finish()
    }
}

/// Raw bounded HTTP answer surfaced by an injected transport.
pub struct ConnectionsOpenHttpResponse {
    status: u16,
    content_type: Option<String>,
    retry_after_seconds: Option<u32>,
    body: Vec<u8>,
}

impl ConnectionsOpenHttpResponse {
    /// Construct a fake or adapter response for classification by the client.
    #[must_use]
    pub fn new(
        status: u16,
        content_type: Option<String>,
        retry_after_seconds: Option<u32>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            status,
            content_type,
            retry_after_seconds,
            body,
        }
    }
}

impl fmt::Debug for ConnectionsOpenHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionsOpenHttpResponse")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("retry_after_seconds", &self.retry_after_seconds)
            .field("body", &format_args!("<redacted:{}>", self.body.len()))
            .finish()
    }
}

/// Injected synchronous HTTP seam for the Socket Mode bootstrap call.
pub trait ConnectionsOpenTransport {
    fn send(
        &mut self,
        request: &ConnectionsOpenHttpRequest<'_>,
        timeout: Duration,
    ) -> Result<ConnectionsOpenHttpResponse, SlackFailure>;
}

/// Production HTTPS transport, constructible only with its fixed Slack origin.
pub struct SlackConnectionsOpenTransport {
    agent: ureq::Agent,
}

impl SlackConnectionsOpenTransport {
    #[must_use]
    fn production() -> Self {
        let tls = TlsConfig::builder().root_certs(RootCerts::WebPki).build();
        let config = ureq::Agent::config_builder()
            .https_only(true)
            .proxy(None)
            .max_redirects(0)
            .http_status_as_error(false)
            .max_response_header_size(MAX_RESPONSE_HEADER_BYTES)
            .user_agent(SLACK_USER_AGENT)
            .tls_config(tls)
            .build();
        Self {
            agent: config.new_agent(),
        }
    }
}

impl ConnectionsOpenTransport for SlackConnectionsOpenTransport {
    fn send(
        &mut self,
        request: &ConnectionsOpenHttpRequest<'_>,
        timeout: Duration,
    ) -> Result<ConnectionsOpenHttpResponse, SlackFailure> {
        let mut response = self
            .agent
            .post(request.endpoint())
            .header("authorization", request.authorization())
            .header("content-type", request.content_type())
            .header("accept", request.accept())
            .header("user-agent", request.user_agent())
            .config()
            .timeout_global(Some(timeout))
            .build()
            .send(request.body())
            .map_err(map_ureq_error)?;
        let status = response.status().as_u16();
        let headers = response.headers();
        let header = |name: &str| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let content_type = header("content-type");
        let retry_after_seconds = header("retry-after").and_then(|value| value.parse().ok());
        let reader = response
            .body_mut()
            .with_config()
            .limit((MAX_SLACK_RESPONSE_BYTES + 1) as u64)
            .reader();
        Ok(ConnectionsOpenHttpResponse::new(
            status,
            content_type,
            retry_after_seconds,
            read_bounded_body(reader, MAX_SLACK_RESPONSE_BYTES)?,
        ))
    }
}

impl fmt::Debug for SlackConnectionsOpenTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SlackConnectionsOpenTransport(https://slack.com)")
    }
}

/// Typed `apps.connections.open` client over one app-level token.
pub struct AppsConnectionsOpenClient<T = SlackConnectionsOpenTransport> {
    token: SlackAppToken,
    transport: T,
    timeout: Duration,
}

impl AppsConnectionsOpenClient<SlackConnectionsOpenTransport> {
    /// Construct the production-only HTTPS client. No request is issued here.
    #[must_use]
    pub fn new(token: SlackAppToken) -> Self {
        Self::with_transport(token, SlackConnectionsOpenTransport::production())
    }
}

impl<T> AppsConnectionsOpenClient<T>
where
    T: ConnectionsOpenTransport,
{
    /// Compose the same client over an injected transport.
    #[must_use]
    pub fn with_transport(token: SlackAppToken, transport: T) -> Self {
        Self::with_transport_timeout(
            token,
            transport,
            Duration::from_secs(SLACK_REQUEST_TIMEOUT_SECONDS),
        )
    }

    /// Compose with a tighter whole-request deadline.
    #[must_use]
    pub fn with_transport_timeout(token: SlackAppToken, transport: T, timeout: Duration) -> Self {
        let ceiling = Duration::from_secs(SLACK_REQUEST_TIMEOUT_SECONDS);
        let timeout = if timeout.is_zero() {
            ceiling
        } else {
            timeout.min(ceiling)
        };
        Self {
            token,
            transport,
            timeout,
        }
    }

    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        self.timeout
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    /// Obtain one temporary production Socket Mode websocket URL.
    ///
    /// Slack refusals are typed `Rejected` outcomes. Redirects, unexpected
    /// statuses/content types, oversized bodies, invalid JSON, and any URL that
    /// is not the locked production `wss` shape fail closed.
    pub fn open(&mut self) -> Result<SlackOutcome<SlackSocketUrl>, SlackFailure> {
        let transport = &mut self.transport;
        let timeout = self.timeout;
        let response = self
            .token
            .authorization()
            .with_header_value(|authorization| {
                transport.send(&ConnectionsOpenHttpRequest { authorization }, timeout)
            })?;
        classify(response)
    }
}

impl<T> fmt::Debug for AppsConnectionsOpenClient<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppsConnectionsOpenClient")
            .field("endpoint", &APPS_CONNECTIONS_OPEN_ENDPOINT)
            .field("authorization", &"<redacted>")
            .field("timeout", &self.timeout)
            .finish()
    }
}

fn classify(
    response: ConnectionsOpenHttpResponse,
) -> Result<SlackOutcome<SlackSocketUrl>, SlackFailure> {
    if response.body.len() > MAX_SLACK_RESPONSE_BYTES {
        return Err(SlackFailure::ResponseTooLarge);
    }
    if (300..400).contains(&response.status) {
        return Err(SlackFailure::Redirected);
    }
    if response.status == 429 {
        return Ok(SlackOutcome::Rejected(SlackRejection::rate_limited(
            decode_error_code(&response.body, RATE_LIMITED),
            response.retry_after_seconds,
        )));
    }
    if matches!(response.status, 401 | 403) {
        return Err(SlackFailure::Unauthorized);
    }
    if response.status != 200 {
        return Err(SlackFailure::UnexpectedStatus);
    }
    if !response.content_type.as_deref().is_some_and(is_slack_json) {
        return Err(SlackFailure::UnexpectedContentType);
    }
    decode_apps_connections_open(&response.body)
}

fn is_slack_json(value: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    const APP_SECRET: &str = "xapp-1-A0FIXTURE-fixture-never-print";
    const URL: &str = "wss://wss-primary.slack.com/link/?ticket=fixture-ticket&app_id=A1";

    struct FakeTransport {
        response: Option<Result<ConnectionsOpenHttpResponse, SlackFailure>>,
        observed: Vec<String>,
    }

    impl ConnectionsOpenTransport for FakeTransport {
        fn send(
            &mut self,
            request: &ConnectionsOpenHttpRequest<'_>,
            timeout: Duration,
        ) -> Result<ConnectionsOpenHttpResponse, SlackFailure> {
            self.observed.push(format!(
                "{}|{}|{}|{}|{}|{}|{:?}|{request:?}",
                request.endpoint(),
                request.body(),
                request.content_type(),
                request.accept(),
                request.user_agent(),
                request.authorization(),
                timeout,
            ));
            self.response
                .take()
                .unwrap_or(Err(SlackFailure::Unavailable))
        }
    }

    fn response(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> FakeTransport {
        FakeTransport {
            response: Some(Ok(ConnectionsOpenHttpResponse::new(
                status,
                Some(content_type.to_owned()),
                None,
                body.into(),
            ))),
            observed: Vec::new(),
        }
    }

    fn client(transport: FakeTransport) -> AppsConnectionsOpenClient<FakeTransport> {
        AppsConnectionsOpenClient::with_transport_timeout(
            SlackAppToken::new(APP_SECRET.as_bytes().to_vec()).expect("token"),
            transport,
            Duration::from_millis(300),
        )
    }

    #[test]
    fn the_injected_request_is_exact_and_the_ticket_never_reaches_debug() {
        let mut client = client(response(
            200,
            "application/json; charset=utf-8",
            format!(r#"{{"ok":true,"url":"{URL}"}}"#),
        ));
        let outcome = client.open().expect("open response");
        let SlackOutcome::Accepted(url) = outcome else {
            panic!("accepted URL")
        };
        url.with_url(|value| assert_eq!(value, URL));
        let client_rendered = format!("{client:?}");
        assert!(!client_rendered.contains(APP_SECRET));
        let transport = client.into_transport();
        assert_eq!(transport.observed.len(), 1);
        let observed = &transport.observed[0];
        assert!(observed.contains(APPS_CONNECTIONS_OPEN_ENDPOINT));
        assert!(observed.contains("application/x-www-form-urlencoded"));
        assert!(observed.contains("application/json"));
        assert!(observed.contains("automonique-slack-connector"));
        assert!(observed.contains(&format!("Bearer {APP_SECRET}")));
        assert!(observed.contains("300ms"));
        let debug_tail = observed.split('|').next_back().expect("debug request");
        assert!(!debug_tail.contains(APP_SECRET));
        assert!(debug_tail.contains("<redacted>"));
    }

    #[test]
    fn slack_refusal_redirect_wrong_content_and_hostile_url_are_distinct() {
        let mut rejected = client(response(
            200,
            "application/json",
            br#"{"ok":false,"error":"invalid_auth"}"#.to_vec(),
        ));
        let SlackOutcome::Rejected(rejection) = rejected.open().expect("Slack refusal") else {
            panic!("rejected")
        };
        assert_eq!(rejection.code().as_str(), "invalid_auth");

        let mut redirected = client(response(302, "application/json", Vec::new()));
        assert_eq!(redirected.open().err(), Some(SlackFailure::Redirected));

        let mut wrong_type = client(response(
            200,
            "text/plain",
            format!(r#"{{"ok":true,"url":"{URL}"}}"#),
        ));
        assert_eq!(
            wrong_type.open().err(),
            Some(SlackFailure::UnexpectedContentType)
        );

        let mut hostile = client(response(
            200,
            "application/json",
            br#"{"ok":true,"url":"wss://evil.invalid/link/?ticket=secret"}"#.to_vec(),
        ));
        assert_eq!(hostile.open().err(), Some(SlackFailure::FieldOutOfBounds));
    }

    #[test]
    fn timeout_and_oversized_response_fail_closed() {
        let mut timed_out = client(FakeTransport {
            response: Some(Err(SlackFailure::TimedOut)),
            observed: Vec::new(),
        });
        assert_eq!(timed_out.open().err(), Some(SlackFailure::TimedOut));

        let mut oversized = client(response(
            200,
            "application/json",
            vec![b'x'; MAX_SLACK_RESPONSE_BYTES + 1],
        ));
        assert_eq!(oversized.open().err(), Some(SlackFailure::ResponseTooLarge));
    }
}
