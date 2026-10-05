// SPDX-License-Identifier: Elastic-2.0

//! `automonique shot --login`: the capture of a screen behind a sign-in.
//!
//! A protected screen is proven by looking at it signed in, and the agent
//! holds no password. For a host the operator has configured, the verb
//! exchanges a service credential for one short-lived session cookie at the
//! application's own sign-in service, hands that cookie to the headless
//! browser before the navigation, and captures the page as the application's
//! verification account sees it.
//!
//! The configuration is one private frame per host, at
//! `shot/logins/<host>.conf` beneath the state directory:
//!
//! ```text
//! schema=automonique.shot-login/v1
//! endpoint=https://manage.example/api/v1/agent/session
//! token=<service credential>
//! end=automonique.shot-login/v1
//! ```
//!
//! `--login-site <id>` names the site whose space the session opens on, for
//! an application that keeps several; it travels as `site_id` in the request
//! and the service decides whether the account may enter it.
//!
//! The file is looked up by the host being captured and by nothing else, so
//! a session can only ever be presented to the host it was configured for.
//! The service answers `{"cookie":{"name","value","path","secure",
//! "http_only","same_site"},…}`; the cookie is scoped to the captured origin
//! here, whatever the service says about its domain. The credential and the
//! cookie value never appear in an output line or a debug rendering.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::worker_verb::{FrameRefusal, JsonPost, frame, header_safe_secret, read_private};

/// Whole-call budget for the sign-in request.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Largest sign-in answer accepted.
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024;

const CONFIG_DIRECTORY: &str = "shot/logins";
const CONFIG_HEADER: &str = "schema=automonique.shot-login/v1";
const CONFIG_TERMINATOR: &str = "end=automonique.shot-login/v1";
const MAX_ENDPOINT_BYTES: usize = 512;
const MAX_COOKIE_NAME_BYTES: usize = 128;
const MAX_COOKIE_VALUE_BYTES: usize = 8 * 1024;
const MAX_COOKIE_PATH_BYTES: usize = 256;
/// Longest site identifier accepted by `--login-site`.
pub const MAX_SITE_BYTES: usize = 64;

/// Whether `value` is an opaque site identifier: letters, digits and dashes.
#[must_use]
pub fn valid_site(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SITE_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// A session cookie to present to the captured origin.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionCookie {
    pub(crate) name: String,
    pub(crate) value: Zeroizing<String>,
    pub(crate) path: String,
    pub(crate) secure: bool,
    pub(crate) http_only: bool,
    pub(crate) same_site: Option<&'static str>,
}

impl fmt::Debug for SessionCookie {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionCookie")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .field("path", &self.path)
            .field("secure", &self.secure)
            .field("http_only", &self.http_only)
            .field("same_site", &self.same_site)
            .finish()
    }
}

struct LoginConfig {
    endpoint: String,
    token: Zeroizing<String>,
}

/// Configuration file location for `host` beneath `state_dir`.
#[must_use]
pub fn config_path(state_dir: &Path, host: &str) -> PathBuf {
    state_dir
        .join(CONFIG_DIRECTORY)
        .join(format!("{}.conf", host.to_ascii_lowercase()))
}

fn https_endpoint(value: &str) -> bool {
    value.len() <= MAX_ENDPOINT_BYTES
        && value
            .strip_prefix("https://")
            .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'))
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
}

fn parse_config(text: &str) -> Result<LoginConfig, FrameRefusal> {
    let mut endpoint = None;
    let mut token = None;
    for (key, value) in frame(text, CONFIG_HEADER, CONFIG_TERMINATOR)? {
        match key {
            "endpoint" if endpoint.is_none() && https_endpoint(value) => {
                endpoint = Some(value.to_owned());
            }
            "token" if token.is_none() && header_safe_secret(value) => {
                token = Some(Zeroizing::new(value.to_owned()));
            }
            _ => return Err(FrameRefusal::Malformed),
        }
    }
    Ok(LoginConfig {
        endpoint: endpoint.ok_or(FrameRefusal::Malformed)?,
        token: token.ok_or(FrameRefusal::Malformed)?,
    })
}

fn cookie_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_COOKIE_NAME_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn cookie_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_COOKIE_VALUE_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'"' | b';' | b',' | b'\\'))
}

fn cookie_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= MAX_COOKIE_PATH_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b';')
}

/// Read the sign-in answer against its contract. `None` for anything else.
fn parse_cookie(body: &[u8]) -> Option<SessionCookie> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let cookie = value.get("cookie")?;
    let name = cookie
        .get("name")?
        .as_str()
        .filter(|name| cookie_name(name))?;
    let secret = cookie
        .get("value")?
        .as_str()
        .filter(|value| cookie_value(value))?;
    let path = match cookie.get("path") {
        Some(path) => path.as_str().filter(|path| cookie_path(path))?,
        None => "/",
    };
    let same_site = match cookie.get("same_site").and_then(serde_json::Value::as_str) {
        Some(mode) if mode.eq_ignore_ascii_case("strict") => Some("Strict"),
        Some(mode) if mode.eq_ignore_ascii_case("lax") => Some("Lax"),
        Some(mode) if mode.eq_ignore_ascii_case("none") => Some("None"),
        Some(_) => return None,
        None => None,
    };
    Some(SessionCookie {
        name: name.to_owned(),
        value: Zeroizing::new(secret.to_owned()),
        path: path.to_owned(),
        secure: cookie.get("secure").and_then(serde_json::Value::as_bool) == Some(true),
        http_only: cookie.get("http_only").and_then(serde_json::Value::as_bool) != Some(false),
        same_site,
    })
}

/// Obtain a session cookie for `host` from its configured sign-in service.
///
/// # Errors
///
/// Returns one sentence naming what stopped the sign-in. It never carries
/// the credential, the endpoint or anything the service answered.
pub fn sign_in(
    state_dir: Option<&Path>,
    host: &str,
    site: Option<&str>,
    transport: &dyn JsonPost,
) -> Result<SessionCookie, String> {
    let state_dir = state_dir
        .ok_or_else(|| String::from("login needs the state directory, which is not set"))?;
    let config = match read_private(&config_path(state_dir, host)) {
        Ok(Some(text)) => parse_config(&text),
        Ok(None) => return Err(format!("login is not configured for {host}")),
        Err(refusal) => Err(refusal),
    }
    .map_err(|refusal| {
        format!(
            "login configuration for {host} {}",
            match refusal {
                FrameRefusal::Insecure => "is not a private owner-only regular file",
                FrameRefusal::Unreadable => "is unreadable",
                FrameRefusal::Malformed => "is malformed",
            }
        )
    })?;
    let body = match site {
        Some(site) if valid_site(site) => serde_json::json!({ "site_id": site }).to_string(),
        Some(_) => return Err(String::from("--login-site is not a site identifier")),
        None => String::from("{}"),
    };
    let authorization = Zeroizing::new(format!("Bearer {}", config.token.as_str()));
    let reply = transport
        .post_json(
            &config.endpoint,
            &[("authorization", authorization.as_str())],
            &body,
        )
        .map_err(|failure| format!("login for {host} failed: {}", failure.reason()))?;
    if !(200..300).contains(&reply.status) {
        return Err(format!(
            "login for {host} was refused by the sign-in service (HTTP {})",
            reply.status
        ));
    }
    parse_cookie(&reply.body)
        .ok_or_else(|| format!("login for {host} returned no usable session cookie"))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::worker_verb::PostFailure;
    use crate::worker_verb::testing::FakePost;

    const HOST: &str = "manage.example";
    const ENDPOINT: &str = "https://manage.example/api/v1/agent/session";
    const TOKEN: &str = "svc_0123456789abcdefghijklmnopqrstuvwxyz";
    const REPLY: &str = r#"{"cookie":{"name":"__Secure-authjs.session-token","value":"aaa.bbb.ccc","path":"/","secure":true,"http_only":true,"same_site":"Lax"},"expires_at":1}"#;

    fn conf(lines: &[&str]) -> String {
        format!(
            "{CONFIG_HEADER}\n{}\n{CONFIG_TERMINATOR}\n",
            lines.join("\n")
        )
    }

    fn state_with(host: &str, text: &str, mode: u32) -> tempfile::TempDir {
        let state = tempfile::tempdir().expect("state directory");
        let path = config_path(state.path(), host);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("directory");
        std::fs::write(&path, text).expect("configuration");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("mode");
        state
    }

    fn configured() -> tempfile::TempDir {
        let endpoint = format!("endpoint={ENDPOINT}");
        let token = format!("token={TOKEN}");
        state_with(HOST, &conf(&[&endpoint, &token]), 0o600)
    }

    #[test]
    fn a_sign_in_presents_the_credential_once_and_reads_the_cookie() {
        let state = configured();
        let transport = FakePost::answering(200, REPLY);
        let cookie = sign_in(Some(state.path()), HOST, None, &transport).expect("signs in");
        assert_eq!(cookie.name, "__Secure-authjs.session-token");
        assert_eq!(cookie.value.as_str(), "aaa.bbb.ccc");
        assert_eq!(cookie.path, "/");
        assert!(cookie.secure && cookie.http_only);
        assert_eq!(cookie.same_site, Some("Lax"));
        assert!(!format!("{cookie:?}").contains("aaa.bbb.ccc"));

        let sent = transport.sent.borrow();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].url, ENDPOINT);
        assert_eq!(
            sent[0].headers,
            vec![(String::from("authorization"), format!("Bearer {TOKEN}"))]
        );
    }

    #[test]
    fn a_site_travels_as_data_and_is_refused_when_it_is_not_an_identifier() {
        let state = configured();
        let transport = FakePost::answering(200, REPLY);
        let site = "019b03c2-ac41-74d3-8c53-5658f167b887";
        sign_in(Some(state.path()), HOST, Some(site), &transport).expect("signs in");
        sign_in(Some(state.path()), HOST, None, &transport).expect("signs in");
        let sent = transport.sent.borrow();
        assert_eq!(sent[0].body, format!(r#"{{"site_id":"{site}"}}"#));
        assert_eq!(sent[1].body, "{}");
        drop(sent);

        let refused = FakePost::answering(200, REPLY);
        for bad in ["", "a b", "x\",\"y", &"a".repeat(MAX_SITE_BYTES + 1)] {
            assert_eq!(
                sign_in(Some(state.path()), HOST, Some(bad), &refused).unwrap_err(),
                "--login-site is not a site identifier"
            );
        }
        assert_eq!(refused.calls(), 0);
    }

    #[test]
    fn the_configuration_is_found_by_host_only_and_must_be_private() {
        let state = configured();
        let transport = FakePost::answering(200, REPLY);
        assert_eq!(
            sign_in(Some(state.path()), "other.example", None, &transport).unwrap_err(),
            "login is not configured for other.example"
        );
        assert!(sign_in(Some(state.path()), "MANAGE.example", None, &transport).is_ok());
        assert_eq!(
            sign_in(None, HOST, None, &transport).unwrap_err(),
            "login needs the state directory, which is not set"
        );

        let endpoint = format!("endpoint={ENDPOINT}");
        let token = format!("token={TOKEN}");
        let readable = state_with(HOST, &conf(&[&endpoint, &token]), 0o640);
        let refused = FakePost::answering(200, REPLY);
        assert_eq!(
            sign_in(Some(readable.path()), HOST, None, &refused).unwrap_err(),
            "login configuration for manage.example is not a private owner-only regular file"
        );
        assert_eq!(refused.calls(), 0);
    }

    #[test]
    fn the_configuration_frame_is_strict() {
        let token = format!("token={TOKEN}");
        for lines in [
            vec!["endpoint=http://manage.example/session", token.as_str()],
            vec!["endpoint=https://", token.as_str()],
            vec![&format!("endpoint={ENDPOINT}") as &str],
            vec![&format!("endpoint={ENDPOINT}") as &str, "token="],
            vec![
                &format!("endpoint={ENDPOINT}") as &str,
                token.as_str(),
                "extra=1",
            ],
        ] {
            let state = state_with(HOST, &conf(&lines), 0o600);
            let transport = FakePost::answering(200, REPLY);
            assert_eq!(
                sign_in(Some(state.path()), HOST, None, &transport).unwrap_err(),
                "login configuration for manage.example is malformed",
                "{lines:?}"
            );
            assert_eq!(transport.calls(), 0);
        }
    }

    #[test]
    fn a_refusal_or_an_unusable_answer_is_one_sentence_without_secrets() {
        let state = configured();
        let refused = FakePost::answering(403, r#"{"error":{"code":"forbidden"}}"#);
        assert_eq!(
            sign_in(Some(state.path()), HOST, None, &refused).unwrap_err(),
            "login for manage.example was refused by the sign-in service (HTTP 403)"
        );
        let down = FakePost::failing(PostFailure::TimedOut);
        assert_eq!(
            sign_in(Some(state.path()), HOST, None, &down).unwrap_err(),
            "login for manage.example failed: the service did not answer in time"
        );
        for body in [
            "not json",
            r#"{"cookie":{"name":"a b","value":"x"}}"#,
            r#"{"cookie":{"name":"sid","value":"x;y"}}"#,
            r#"{"cookie":{"name":"sid","value":"x","path":"relative"}}"#,
            r#"{"cookie":{"name":"sid","value":"x","same_site":"sideways"}}"#,
            r#"{"cookie":{"name":"sid"}}"#,
        ] {
            let transport = FakePost::answering(200, body);
            assert_eq!(
                sign_in(Some(state.path()), HOST, None, &transport).unwrap_err(),
                "login for manage.example returned no usable session cookie",
                "{body}"
            );
        }
    }

    #[test]
    fn an_answer_may_leave_the_optional_cookie_attributes_out() {
        let cookie = parse_cookie(br#"{"cookie":{"name":"sid","value":"abc"}}"#).expect("cookie");
        assert_eq!(cookie.path, "/");
        assert!(!cookie.secure);
        assert!(cookie.http_only);
        assert_eq!(cookie.same_site, None);
    }
}
