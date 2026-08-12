// SPDX-License-Identifier: Elastic-2.0

//! Exact, synchronous HTTPS transport for Telegram `getUpdates`.

use std::fmt;
use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ureq::tls::{RootCerts, TlsConfig};

use crate::{
    CancellationToken, HttpFailure, HttpMethod, MAX_TELEGRAM_RESPONSE_BYTES, TelegramHttpClient,
    TelegramHttpPlan, TelegramHttpResponse, TelegramTarget,
};

const TELEGRAM_ORIGIN: &str = "https://api.telegram.org";
const HTTP_TRANSPORT_ALLOWANCE_SECONDS: u64 = 3;
const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
const _: () = assert!((log::STATIC_MAX_LEVEL as usize) <= (log::LevelFilter::Debug as usize));

/// Production synchronous Telegram HTTPS client.
///
/// The client holds no credential. Each call materializes Telegram's required
/// token-bearing path only for the duration of the request. Redirects and
/// environment proxies are disabled so that path cannot be forwarded to a
/// different peer. The workspace statically caps the `log` facade at Debug
/// because ureq redacts request paths at Debug but reveals them at Trace;
/// rebuilding with Trace enabled is intentionally unsupported. Cancellation is
/// cooperative: a cancellation observed while blocked in DNS/TCP/TLS/HTTP is
/// returned after the bounded global timeout.
pub struct TelegramHttpsClient {
    agent: ureq::Agent,
}

impl TelegramHttpsClient {
    /// Build a client using rustls verification and ureq's pinned WebPKI roots.
    #[must_use]
    pub fn new() -> Self {
        let tls = TlsConfig::builder().root_certs(RootCerts::WebPki).build();
        let config = ureq::Agent::config_builder()
            .https_only(true)
            .proxy(None)
            .max_redirects(0)
            .http_status_as_error(false)
            .max_response_header_size(MAX_RESPONSE_HEADER_BYTES)
            .tls_config(tls)
            .build();
        Self {
            agent: config.new_agent(),
        }
    }
}

impl Default for TelegramHttpsClient {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for TelegramHttpsClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelegramHttpsClient")
            .field("origin", &TELEGRAM_ORIGIN)
            .field("authorization", &"<not retained>")
            .finish()
    }
}

impl TelegramHttpClient for TelegramHttpsClient {
    fn execute(
        &mut self,
        plan: &TelegramHttpPlan<'_>,
        cancellation: &CancellationToken,
    ) -> Result<TelegramHttpResponse, HttpFailure> {
        if cancellation.is_cancelled() {
            return Err(HttpFailure::Cancelled);
        }
        let prepared = PreparedRequest::from_plan(plan)?;
        let timeout = request_timeout(plan.body.timeout_seconds);

        let mut response = self
            .agent
            .post(&prepared.url)
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .config()
            .timeout_global(Some(timeout))
            .build()
            .send(&prepared.body)
            .map_err(map_ureq_error)?;

        if cancellation.is_cancelled() {
            return Err(HttpFailure::Cancelled);
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok());
        validate_response_metadata(response.status().as_u16(), content_type)?;

        let reader = response
            .body_mut()
            .with_config()
            .limit((MAX_TELEGRAM_RESPONSE_BYTES + 1) as u64)
            .reader();
        let body = read_bounded_body(reader)?;
        if cancellation.is_cancelled() {
            return Err(HttpFailure::Cancelled);
        }

        Ok(TelegramHttpResponse {
            status: 200,
            body,
            completed_ms: unix_millis()?,
        })
    }
}

struct PreparedRequest {
    url: String,
    body: String,
}

impl PreparedRequest {
    fn from_plan(plan: &TelegramHttpPlan<'_>) -> Result<Self, HttpFailure> {
        if plan.method != HttpMethod::Post
            || plan.target != TelegramTarget::GetUpdates
            || plan.bot_id <= 0
            || plan.body.limit == 0
            || plan.body.limit > 100
            || plan.body.timeout_seconds == 0
            || plan.body.timeout_seconds > 50
        {
            return Err(HttpFailure::Unavailable);
        }

        let url = plan.authorization().with_secret(|secret| {
            let token = std::str::from_utf8(secret).map_err(|_| HttpFailure::Unavailable)?;
            let (token_bot, token_secret) =
                token.split_once(':').ok_or(HttpFailure::Unavailable)?;
            if token_bot != plan.bot_id.to_string()
                || token_secret.is_empty()
                || !token_secret
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            {
                return Err(HttpFailure::Unavailable);
            }
            Ok(format!("{TELEGRAM_ORIGIN}/bot{token}/getUpdates"))
        })?;
        let body = format!(
            "{{\"offset\":{},\"limit\":{},\"timeout\":{}}}",
            plan.body.offset, plan.body.limit, plan.body.timeout_seconds
        );
        Ok(Self { url, body })
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

fn request_timeout(long_poll_seconds: u16) -> Duration {
    Duration::from_secs(u64::from(long_poll_seconds) + HTTP_TRANSPORT_ALLOWANCE_SECONDS)
}

fn validate_response_metadata(status: u16, content_type: Option<&str>) -> Result<(), HttpFailure> {
    if status != 200 {
        return Err(HttpFailure::UnexpectedStatus);
    }
    if !content_type.is_some_and(is_json_content_type) {
        return Err(HttpFailure::UnexpectedContentType);
    }
    Ok(())
}

fn read_bounded_body(mut reader: impl Read) -> Result<Vec<u8>, HttpFailure> {
    let mut body = Vec::new();
    reader
        .read_to_end(&mut body)
        .map_err(|error| map_ureq_error(ureq::Error::from(error)))?;
    if body.len() > MAX_TELEGRAM_RESPONSE_BYTES {
        return Err(HttpFailure::ResponseTooLarge);
    }
    Ok(body)
}

fn map_ureq_error(error: ureq::Error) -> HttpFailure {
    match error {
        ureq::Error::Timeout(_) => HttpFailure::TimedOut,
        ureq::Error::BodyExceedsLimit(_) => HttpFailure::ResponseTooLarge,
        _ => HttpFailure::Unavailable,
    }
}

fn unix_millis() -> Result<i64, HttpFailure> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HttpFailure::Unavailable)?
        .as_millis();
    i64::try_from(millis).map_err(|_| HttpFailure::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GetUpdatesBody, OpaqueBotToken};

    fn plan<'a>(token: &'a OpaqueBotToken) -> TelegramHttpPlan<'a> {
        TelegramHttpPlan {
            method: HttpMethod::Post,
            target: TelegramTarget::GetUpdates,
            bot_id: 42,
            body: GetUpdatesBody {
                offset: u64::MAX,
                limit: 100,
                timeout_seconds: 50,
            },
            authorization: token,
        }
    }

    #[test]
    fn client_configuration_is_https_direct_verified_and_non_redirecting() {
        let client = TelegramHttpsClient::new();
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
    fn prepared_request_is_exact_post_target_and_numeric_json() {
        let token = OpaqueBotToken::new(b"42:fixture-token".to_vec()).expect("token");
        let prepared = PreparedRequest::from_plan(&plan(&token)).expect("prepare");
        assert_eq!(
            prepared.url,
            "https://api.telegram.org/bot42:fixture-token/getUpdates"
        );
        assert_eq!(
            prepared.body,
            format!("{{\"offset\":{},\"limit\":100,\"timeout\":50}}", u64::MAX)
        );
    }

    #[test]
    fn authorization_never_appears_in_debug_or_closed_errors() {
        let token_text = "42:fixture-secret-never-print";
        let token = OpaqueBotToken::new(token_text.as_bytes().to_vec()).expect("token");
        let client = TelegramHttpsClient::new();
        let plan = plan(&token);
        assert!(!format!("{token:?}{plan:?}{client:?}").contains(token_text));
        assert!(!format!("{:?}", HttpFailure::Unavailable).contains(token_text));
    }

    #[test]
    fn mismatched_bot_and_malformed_token_are_refused_before_io() {
        let wrong_bot = OpaqueBotToken::new(b"41:fixture-token".to_vec()).expect("token");
        assert!(matches!(
            PreparedRequest::from_plan(&plan(&wrong_bot)),
            Err(HttpFailure::Unavailable)
        ));
        let malformed = OpaqueBotToken::new(b"42-no-separator".to_vec()).expect("token");
        assert!(matches!(
            PreparedRequest::from_plan(&plan(&malformed)),
            Err(HttpFailure::Unavailable)
        ));
        let alternate_bot = OpaqueBotToken::new(b"042:fixture-token".to_vec()).expect("token");
        assert!(matches!(
            PreparedRequest::from_plan(&plan(&alternate_bot)),
            Err(HttpFailure::Unavailable)
        ));
    }

    #[test]
    fn response_content_type_is_closed() {
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("Application/Json; charset=UTF-8"));
        assert!(!is_json_content_type("text/json"));
        assert!(!is_json_content_type("application/json; profile=secret"));
        assert!(!is_json_content_type("application/json; charset=latin1"));
        assert_eq!(
            validate_response_metadata(429, Some("application/json")),
            Err(HttpFailure::UnexpectedStatus)
        );
        assert_eq!(
            validate_response_metadata(200, None),
            Err(HttpFailure::UnexpectedContentType)
        );
    }

    #[test]
    fn response_body_cap_accepts_boundary_and_refuses_one_over() {
        let at_limit = vec![0_u8; MAX_TELEGRAM_RESPONSE_BYTES];
        assert_eq!(
            read_bounded_body(std::io::Cursor::new(&at_limit)).expect("at limit"),
            at_limit
        );
        let over_limit = vec![0_u8; MAX_TELEGRAM_RESPONSE_BYTES + 1];
        assert_eq!(
            read_bounded_body(std::io::Cursor::new(over_limit)),
            Err(HttpFailure::ResponseTooLarge)
        );
    }

    #[test]
    fn transport_timeout_stays_inside_lease_margin() {
        let timeout = request_timeout(50);
        assert_eq!(timeout, Duration::from_secs(53));
        assert!(timeout.as_millis() < crate::TELEGRAM_HTTP_LEASE_MARGIN_MS as u128 + 50_000);
    }

    #[test]
    fn cancellation_before_io_is_closed() {
        let token = OpaqueBotToken::new(b"42:fixture-token".to_vec()).expect("token");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut client = TelegramHttpsClient::new();
        assert_eq!(
            client.execute(&plan(&token), &cancellation),
            Err(HttpFailure::Cancelled)
        );
    }
}
