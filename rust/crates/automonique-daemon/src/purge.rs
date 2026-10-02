// SPDX-License-Identifier: Elastic-2.0

//! `automonique purge`: invalidate one site's render cache.
//!
//! A change is not delivered until the site serves it, and a platform that
//! caches rendered pages keeps serving the old one until its cache for that
//! site is dropped. Agents used to find the right call by trial and error.
//! This verb is the one call: it asks the platform's local invalidate
//! endpoint to drop the caches of one site, by the site's name.
//!
//! ```text
//! automonique purge --site <name>
//! MONIQUE_PURGE_OK: <name>
//! status: synchronous
//! ```
//!
//! The endpoint addresses a site by name, not by public URL, so the verb
//! takes `--site` and refuses a URL rather than guess which site serves it.
//! The request is `POST <endpoint>` with the JSON body `{"site":"<name>"}`.
//!
//! # Configuration
//!
//! One private frame in the state directory, `purge/purge.conf`. An absent
//! file means the verb is not configured.
//!
//! ```text
//! schema=automonique.purge/v1
//! endpoint=http://127.0.0.1/<the platform's site invalidate path>
//! app_id=<optional: caller identity, sent as x-bext-app-id>
//! sdk_token=<optional: that identity's token, sent as x-bext-sdk-token>
//! token=<optional: sent as authorization: Bearer>
//! end=automonique.purge/v1
//! ```
//!
//! `endpoint` must be a plaintext loopback URL (`127.0.0.1`, `localhost` or
//! `[::1]`): the invalidate surface is local to the host that serves the
//! sites, and a configuration pointing anywhere else is refused rather than
//! followed. The credentials are optional because how a deployment
//! authenticates a local caller is the deployment's choice; whichever are
//! present are sent, none is ever printed, and all are redacted in `Debug`.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::worker_verb::{
    FrameRefusal, HttpReply, JsonPost, VerbOutcome, error_token, frame, header_safe_secret,
    read_private,
};

/// Success marker the agent looks for.
pub const OK_MARKER: &str = "MONIQUE_PURGE_OK:";
/// Failure marker the agent looks for.
pub const FAIL_MARKER: &str = "MONIQUE_PURGE_FAIL:";
/// Usage line printed when the arguments are refused.
pub const USAGE: &str = "usage: automonique purge --site <name>";

/// Whole-call budget for the invalidation.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Ceiling on the platform's answer, which is one small JSON object.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Configuration path beneath the state directory.
const CONFIG_RELATIVE: &str = "purge/purge.conf";
const CONFIG_HEADER: &str = "schema=automonique.purge/v1";
const CONFIG_TERMINATOR: &str = "end=automonique.purge/v1";
/// Longest endpoint URL admitted.
const MAX_ENDPOINT_BYTES: usize = 512;
/// Longest caller identity admitted.
const MAX_APP_ID_BYTES: usize = 128;
/// Longest site name admitted, first character included.
const MAX_SITE_BYTES: usize = 63;

/// Why a present purge configuration was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PurgeConfigError {
    /// The file is not a private owner-only regular file within its bound.
    Insecure,
    /// The file could not be read.
    Unreadable,
    /// Bad frame, or an unknown or duplicate key.
    Malformed,
    /// `endpoint` is absent or is not a plaintext loopback URL.
    EndpointInvalid,
    /// `app_id` is not an opaque identifier.
    AppIdInvalid,
    /// `token` or `sdk_token` is empty, over-long, or not visible ASCII.
    TokenInvalid,
}

impl fmt::Display for PurgeConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Insecure => "purge configuration is not a private owner-only regular file",
            Self::Unreadable => "purge configuration is unreadable",
            Self::Malformed => "purge configuration frame is malformed or truncated",
            Self::EndpointInvalid => "purge configuration endpoint is not a loopback http URL",
            Self::AppIdInvalid => "purge configuration app_id is invalid",
            Self::TokenInvalid => "purge configuration token is invalid",
        })
    }
}

impl std::error::Error for PurgeConfigError {}

impl From<FrameRefusal> for PurgeConfigError {
    fn from(refusal: FrameRefusal) -> Self {
        match refusal {
            FrameRefusal::Insecure => Self::Insecure,
            FrameRefusal::Unreadable => Self::Unreadable,
            FrameRefusal::Malformed => Self::Malformed,
        }
    }
}

/// A validated purge configuration.
pub struct PurgeConfig {
    endpoint: String,
    app_id: Option<String>,
    sdk_token: Option<Zeroizing<String>>,
    token: Option<Zeroizing<String>>,
}

impl fmt::Debug for PurgeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted = |present: bool| if present { "<redacted>" } else { "<none>" };
        formatter
            .debug_struct("PurgeConfig")
            .field("endpoint", &self.endpoint)
            .field("app_id", &self.app_id)
            .field("sdk_token", &redacted(self.sdk_token.is_some()))
            .field("token", &redacted(self.token.is_some()))
            .finish()
    }
}

impl PurgeConfig {
    /// Configuration file location beneath `state_dir`.
    #[must_use]
    pub fn path(state_dir: &Path) -> PathBuf {
        state_dir.join(CONFIG_RELATIVE)
    }

    /// Load the configuration, distinguishing "not configured" (`Ok(None)`)
    /// from "configured but wrong" (`Err`).
    ///
    /// # Errors
    ///
    /// Returns [`PurgeConfigError`] naming which part of a present file was
    /// refused.
    pub fn load(state_dir: &Path) -> Result<Option<Self>, PurgeConfigError> {
        match read_private(&Self::path(state_dir))? {
            Some(text) => Self::parse(&text).map(Some),
            None => Ok(None),
        }
    }

    pub(crate) fn parse(text: &str) -> Result<Self, PurgeConfigError> {
        let secret = |value: &str| {
            header_safe_secret(value)
                .then(|| Zeroizing::new(value.to_owned()))
                .ok_or(PurgeConfigError::TokenInvalid)
        };
        let mut endpoint = None;
        let mut app_id = None;
        let mut sdk_token = None;
        let mut token = None;
        for (key, value) in frame(text, CONFIG_HEADER, CONFIG_TERMINATOR)? {
            match key {
                "endpoint" if endpoint.is_none() => {
                    if !loopback_endpoint(value) {
                        return Err(PurgeConfigError::EndpointInvalid);
                    }
                    endpoint = Some(value.to_owned());
                }
                "app_id" if app_id.is_none() => {
                    if !valid_app_id(value) {
                        return Err(PurgeConfigError::AppIdInvalid);
                    }
                    app_id = Some(value.to_owned());
                }
                "sdk_token" if sdk_token.is_none() => sdk_token = Some(secret(value)?),
                "token" if token.is_none() => token = Some(secret(value)?),
                _ => return Err(PurgeConfigError::Malformed),
            }
        }
        Ok(Self {
            endpoint: endpoint.ok_or(PurgeConfigError::EndpointInvalid)?,
            app_id,
            sdk_token,
            token,
        })
    }
}

/// Whether `value` is `http://<loopback>[:port]/<path>` and nothing else.
///
/// The host is compared whole, so a name that merely starts with a loopback
/// address is refused, as are credentials, a query and a fragment.
fn loopback_endpoint(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("http://") else {
        return false;
    };
    if value.len() > MAX_ENDPOINT_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
        || value.contains(['@', '?', '#', '\\', '"'])
    {
        return false;
    }
    let Some((authority, _path)) = rest.split_once('/') else {
        return false;
    };
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        match bracketed.split_once(']') {
            Some((host, "")) => (host, None),
            Some((host, port)) => match port.strip_prefix(':') {
                Some(port) => (host, Some(port)),
                None => return false,
            },
            None => return false,
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let host_is_loopback = if authority.starts_with('[') {
        host == "::1"
    } else {
        matches!(host, "127.0.0.1" | "localhost")
    };
    let port_is_valid = port.is_none_or(|port| {
        !port.is_empty()
            && port.len() <= 5
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|number| number != 0)
    });
    host_is_loopback && port_is_valid
}

/// An opaque caller identity that can travel as one header value.
fn valid_app_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_APP_ID_BYTES
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// `^[a-z0-9][a-z0-9-]{0,62}$`.
fn valid_site(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_SITE_BYTES
        && bytes[0] != b'-'
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// One parsed invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PurgeRequest {
    /// The platform's name for the site whose caches are dropped.
    pub site: String,
}

/// Parse `purge --site <name>`.
///
/// # Errors
///
/// Returns one sentence naming the refused argument. A URL is refused with
/// the reason spelled out, because it is the natural thing to try.
pub fn parse(values: &[OsString]) -> Result<PurgeRequest, String> {
    let mut site = None;
    let mut values = values.iter();
    while let Some(value) = values.next() {
        let text = value
            .to_str()
            .ok_or_else(|| String::from("arguments must be UTF-8"))?;
        match text {
            "--site" if site.is_none() => {
                let name = values
                    .next()
                    .and_then(|value| value.to_str())
                    .ok_or_else(|| String::from("--site needs a site name"))?;
                if !valid_site(name) {
                    return Err(String::from(
                        "the site name must match ^[a-z0-9][a-z0-9-]{0,62}$",
                    ));
                }
                site = Some(name.to_owned());
            }
            other if other.starts_with("--") => return Err(format!("unknown option {other}")),
            other if other.contains("://") => {
                return Err(String::from(
                    "purge takes --site <name>, not a URL: the platform invalidates a site by its name",
                ));
            }
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    site.map(|site| PurgeRequest { site })
        .ok_or_else(|| String::from("--site <name> is required"))
}

/// What the platform said it did, from its closed status vocabulary.
fn invalidation_status(config_site: &str, reply: &HttpReply) -> Result<&'static str, String> {
    if reply.status != 200 {
        return Err(match error_token(&reply.body) {
            Some(token) => format!(
                "the platform refused the purge (HTTP {}: {token})",
                reply.status
            ),
            None => format!("the platform refused the purge (HTTP {})", reply.status),
        });
    }
    let unusable = || String::from("the platform answered with an unusable response");
    let value: serde_json::Value = serde_json::from_slice(&reply.body).map_err(|_| unusable())?;
    if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(unusable());
    }
    // The platform answers `ok` without a `site` when the name maps to no
    // site it serves: nothing was invalidated, and saying otherwise would
    // send the agent looking for a stale page somewhere else.
    if value
        .get("site")
        .and_then(serde_json::Value::as_str)
        .is_none()
    {
        return Err(format!("the platform serves no site named {config_site}"));
    }
    Ok(
        match value.get("status").and_then(serde_json::Value::as_str) {
            Some("synchronous") => "synchronous",
            Some("no_worker_running") => "no_worker_running",
            Some("fallback") => "fallback",
            _ => "unknown",
        },
    )
}

/// Ask the platform to drop one site's caches.
///
/// # Errors
///
/// Returns one sentence suitable for a failure marker. It never contains a
/// credential.
pub fn invalidate(
    config: &PurgeConfig,
    request: &PurgeRequest,
    transport: &dyn JsonPost,
) -> Result<&'static str, String> {
    let bearer = config
        .token
        .as_ref()
        .map(|token| Zeroizing::new(format!("Bearer {}", token.as_str())));
    let mut headers: Vec<(&'static str, &str)> = Vec::new();
    if let Some(app_id) = config.app_id.as_deref() {
        headers.push(("x-bext-app-id", app_id));
    }
    if let Some(sdk_token) = config.sdk_token.as_ref() {
        headers.push(("x-bext-sdk-token", sdk_token.as_str()));
    }
    if let Some(bearer) = bearer.as_ref() {
        headers.push(("authorization", bearer.as_str()));
    }
    let body = serde_json::json!({ "site": request.site }).to_string();
    let reply = transport
        .post_json(&config.endpoint, &headers, &body)
        .map_err(|failure| format!("purge failed: {}", failure.reason()))?;
    invalidation_status(&request.site, &reply)
}

/// The whole verb: arguments, configuration, invalidation, marker line.
#[must_use]
pub fn run(state_dir: Option<&Path>, values: &[OsString], transport: &dyn JsonPost) -> VerbOutcome {
    let request = match parse(values) {
        Ok(request) => request,
        Err(reason) => return VerbOutcome::usage(FAIL_MARKER, &reason, USAGE),
    };
    let Some(state_dir) = state_dir else {
        return VerbOutcome::failed(FAIL_MARKER, "purge is not configured on this host");
    };
    let config = match PurgeConfig::load(state_dir) {
        Ok(Some(config)) => config,
        Ok(None) => {
            return VerbOutcome::failed(FAIL_MARKER, "purge is not configured on this host");
        }
        Err(error) => return VerbOutcome::failed(FAIL_MARKER, &error.to_string()),
    };
    match invalidate(&config, &request, transport) {
        Ok(status) => VerbOutcome::ok(vec![
            format!("{OK_MARKER} {}", request.site),
            format!("status: {status}"),
        ]),
        Err(reason) => VerbOutcome::failed(FAIL_MARKER, &reason),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::worker_verb::PostFailure;
    use crate::worker_verb::testing::FakePost;

    const ENDPOINT: &str = "http://127.0.0.1/__platform/site/invalidate";
    const OK_REPLY: &str = r#"{"ok":true,"site":"shop","status":"synchronous","durationMs":4}"#;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn conf(lines: &[&str]) -> String {
        format!(
            "{CONFIG_HEADER}\n{}\n{CONFIG_TERMINATOR}\n",
            lines.join("\n")
        )
    }

    fn state_with(text: &str) -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("tempdir");
        let path = PurgeConfig::path(root.path());
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(&path, text).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        root
    }

    #[test]
    fn only_a_loopback_http_endpoint_is_admitted() {
        for good in [
            ENDPOINT,
            "http://127.0.0.1:8080/x",
            "http://localhost/x",
            "http://localhost:65535/x",
            "http://[::1]/x",
            "http://[::1]:8080/x",
        ] {
            assert!(loopback_endpoint(good), "{good}");
        }
        for bad in [
            "https://127.0.0.1/x",
            "http://127.0.0.1",
            "http://127.0.0.1.evil.example/x",
            "http://127.0.0.2/x",
            "http://10.0.0.5/x",
            "http://platform.example.test/x",
            "http://localhost.evil.example/x",
            "http://user@127.0.0.1/x",
            "http://127.0.0.1@evil.example/x",
            "http://127.0.0.1:0/x",
            "http://127.0.0.1:99999/x",
            "http://127.0.0.1:80a/x",
            "http://127.0.0.1:/x",
            "http://[::2]/x",
            "http://[::1]evil/x",
            "http://[::1/x",
            "http://::1/x",
            "http://127.0.0.1/x?redirect=1",
            "http://127.0.0.1/x#y",
            "http://127.0.0.1/a b",
            "127.0.0.1/x",
            "",
        ] {
            assert!(!loopback_endpoint(bad), "{bad}");
        }
    }

    #[test]
    fn the_configuration_frame_is_strict_and_credentials_are_optional() {
        let bare = PurgeConfig::parse(&conf(&[&format!("endpoint={ENDPOINT}")])).expect("valid");
        assert_eq!(bare.endpoint, ENDPOINT);
        assert!(bare.app_id.is_none() && bare.sdk_token.is_none() && bare.token.is_none());

        let refused = |lines: &[&str]| PurgeConfig::parse(&conf(lines)).expect_err("refused");
        assert_eq!(refused(&["token=t"]), PurgeConfigError::EndpointInvalid);
        assert_eq!(
            refused(&["endpoint=http://platform.example.test/x"]),
            PurgeConfigError::EndpointInvalid
        );
        assert_eq!(
            refused(&[&format!("endpoint={ENDPOINT}"), "token="]),
            PurgeConfigError::TokenInvalid
        );
        assert_eq!(
            refused(&[&format!("endpoint={ENDPOINT}"), "sdk_token=two words"]),
            PurgeConfigError::TokenInvalid
        );
        assert_eq!(
            refused(&[&format!("endpoint={ENDPOINT}"), "app_id=bad id"]),
            PurgeConfigError::AppIdInvalid
        );
        assert_eq!(
            refused(&[&format!("endpoint={ENDPOINT}"), "app_id=../x"]),
            PurgeConfigError::AppIdInvalid
        );
        assert_eq!(
            refused(&[
                &format!("endpoint={ENDPOINT}"),
                &format!("endpoint={ENDPOINT}")
            ]),
            PurgeConfigError::Malformed
        );
        assert_eq!(
            refused(&[&format!("endpoint={ENDPOINT}"), "extra=1"]),
            PurgeConfigError::Malformed
        );
        assert_eq!(
            PurgeConfig::parse(&format!("endpoint={ENDPOINT}\n")).expect_err("no frame"),
            PurgeConfigError::Malformed
        );
    }

    #[test]
    fn credentials_are_redacted_in_debug() {
        let config = PurgeConfig::parse(&conf(&[
            &format!("endpoint={ENDPOINT}"),
            "app_id=fixture-app",
            "sdk_token=fixture-sdk-token",
            "token=fixture-bearer",
        ]))
        .expect("valid");
        let rendered = format!("{config:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("fixture-sdk-token"));
        assert!(!rendered.contains("fixture-bearer"));
    }

    #[test]
    fn a_group_readable_configuration_is_refused_and_an_absent_one_is_not_configured() {
        let root = state_with(&conf(&[&format!("endpoint={ENDPOINT}")]));
        assert!(PurgeConfig::load(root.path()).expect("loads").is_some());
        fs::set_permissions(
            PurgeConfig::path(root.path()),
            fs::Permissions::from_mode(0o604),
        )
        .expect("chmod");
        assert_eq!(
            PurgeConfig::load(root.path()).expect_err("insecure"),
            PurgeConfigError::Insecure
        );
        let empty = tempfile::tempdir().expect("tempdir");
        assert!(PurgeConfig::load(empty.path()).expect("absent").is_none());
    }

    #[test]
    fn a_site_is_named_not_located() {
        assert_eq!(
            parse(&args(&["--site", "shop-2"])).expect("parses").site,
            "shop-2"
        );
        assert!(valid_site("a"));
        assert!(valid_site(&"a".repeat(63)));
        for bad in [
            "",
            "-shop",
            "Shop",
            "shop_1",
            "shop.example",
            "shop/../x",
            "shop one",
            &"a".repeat(64),
        ] {
            assert!(!valid_site(bad), "{bad}");
            assert!(parse(&args(&["--site", bad])).is_err(), "{bad}");
        }
        assert!(parse(&args(&[])).is_err());
        assert!(parse(&args(&["--site"])).is_err());
        assert!(parse(&args(&["--site", "a", "--site", "b"])).is_err());
        assert!(parse(&args(&["--site", "a", "--bogus"])).is_err());
        assert!(parse(&args(&["shop"])).is_err());
        let url = parse(&args(&["https://shop.example.test/produits"])).expect_err("a URL");
        assert!(url.contains("--site <name>, not a URL"));
    }

    #[test]
    fn a_purge_posts_the_site_name_and_prints_the_marker() {
        let state = state_with(&conf(&[
            &format!("endpoint={ENDPOINT}"),
            "app_id=fixture-app",
            "sdk_token=fixture-sdk-token",
            "token=fixture-bearer",
        ]));
        let transport = FakePost::answering(200, OK_REPLY);
        let outcome = run(Some(state.path()), &args(&["--site", "shop"]), &transport);
        assert_eq!(outcome.code, 0);
        assert_eq!(
            outcome.lines,
            vec![
                String::from("MONIQUE_PURGE_OK: shop"),
                String::from("status: synchronous")
            ]
        );
        let sent = transport.sent.borrow();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].url, ENDPOINT);
        assert_eq!(sent[0].body, r#"{"site":"shop"}"#);
        assert_eq!(
            sent[0].headers,
            vec![
                (String::from("x-bext-app-id"), String::from("fixture-app")),
                (
                    String::from("x-bext-sdk-token"),
                    String::from("fixture-sdk-token")
                ),
                (
                    String::from("authorization"),
                    String::from("Bearer fixture-bearer")
                ),
            ]
        );
        let printed = outcome.lines.join("\n");
        assert!(!printed.contains("fixture-sdk-token") && !printed.contains("fixture-bearer"));

        let bare = state_with(&conf(&[&format!("endpoint={ENDPOINT}")]));
        let transport = FakePost::answering(200, OK_REPLY);
        assert_eq!(
            run(Some(bare.path()), &args(&["--site", "shop"]), &transport).code,
            0
        );
        assert!(transport.sent.borrow()[0].headers.is_empty());
    }

    #[test]
    fn the_platform_answer_is_read_against_its_contract() {
        let answer = |status: u16, body: &str| {
            invalidation_status(
                "shop",
                &HttpReply {
                    status,
                    body: body.as_bytes().to_vec(),
                },
            )
        };
        assert_eq!(answer(200, OK_REPLY), Ok("synchronous"));
        assert_eq!(
            answer(200, r#"{"ok":true,"site":"shop","status":"fallback"}"#),
            Ok("fallback")
        );
        assert_eq!(
            answer(
                200,
                r#"{"ok":true,"site":"shop","status":"no_worker_running"}"#
            ),
            Ok("no_worker_running")
        );
        assert_eq!(
            answer(200, r#"{"ok":true,"site":"shop","status":"<script>"}"#),
            Ok("unknown")
        );
        assert_eq!(
            answer(200, r#"{"ok":true,"status":"no_worker_running"}"#),
            Err(String::from("the platform serves no site named shop"))
        );
        for body in ["not json", "{}", r#"{"ok":false,"site":"shop"}"#] {
            assert_eq!(
                answer(200, body),
                Err(String::from(
                    "the platform answered with an unusable response"
                )),
                "{body}"
            );
        }
        assert_eq!(
            answer(403, r#"{"error":"forbidden"}"#),
            Err(String::from(
                "the platform refused the purge (HTTP 403: forbidden)"
            ))
        );
        assert_eq!(
            answer(400, r#"{"error":"site or worktree required"}"#),
            Err(String::from("the platform refused the purge (HTTP 400)"))
        );
    }

    #[test]
    fn failures_are_one_marker_line_and_nothing_is_sent_without_configuration() {
        let transport = FakePost::answering(200, OK_REPLY);
        let unconfigured = tempfile::tempdir().expect("tempdir");
        for outcome in [
            run(
                Some(unconfigured.path()),
                &args(&["--site", "shop"]),
                &transport,
            ),
            run(None, &args(&["--site", "shop"]), &transport),
        ] {
            assert_eq!(outcome.code, 1);
            assert_eq!(
                outcome.lines,
                vec![String::from(
                    "MONIQUE_PURGE_FAIL: purge is not configured on this host"
                )]
            );
        }
        let remote = state_with(&conf(&["endpoint=http://platform.example.test/x"]));
        let outcome = run(Some(remote.path()), &args(&["--site", "shop"]), &transport);
        assert_eq!(outcome.code, 1);
        assert_eq!(
            outcome.lines,
            vec![String::from(
                "MONIQUE_PURGE_FAIL: purge configuration endpoint is not a loopback http URL"
            )]
        );
        let usage = run(
            Some(unconfigured.path()),
            &args(&["https://shop.example.test/"]),
            &transport,
        );
        assert_eq!(usage.code, 2);
        assert_eq!(usage.usage, Some(USAGE));
        assert!(usage.lines[0].starts_with("MONIQUE_PURGE_FAIL: "));
        assert_eq!(transport.calls(), 0);

        let state = state_with(&conf(&[
            &format!("endpoint={ENDPOINT}"),
            "token=fixture-bearer",
        ]));
        let down = FakePost::failing(PostFailure::Unavailable);
        let outcome = run(Some(state.path()), &args(&["--site", "shop"]), &down);
        assert_eq!(outcome.code, 1);
        assert_eq!(
            outcome.lines,
            vec![String::from(
                "MONIQUE_PURGE_FAIL: purge failed: the service is unreachable"
            )]
        );
    }
}
