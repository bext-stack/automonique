// SPDX-License-Identifier: Elastic-2.0

#![forbid(unsafe_code)]

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub const CANONICAL_HOST: &str = "monique.1clic.pro";
pub const LEGACY_HOST: &str = "jean.1clic.pro";
pub const MANAGE_URL: &str = "https://manage.inklura.fr/manage";

const DASHBOARD_HTML: &str = include_str!("../assets/dashboard.html");
const DASHBOARD_CSS: &str = include_str!("../assets/dashboard.css");
const DASHBOARD_JS: &str = include_str!("../assets/dashboard.js");
const FAVICON_SVG: &str = include_str!("../assets/favicon.svg");
const ROBOTS_TXT: &str = "User-agent: *\nDisallow: /\n";

const HEADER_LIMIT: usize = 16 * 1024;
const HEADER_COUNT_LIMIT: usize = 32;
const WORKERS: usize = 4;
const QUEUE_DEPTH: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(3);
const STATUS_REFRESH: Duration = Duration::from_secs(5);
const RATE_WINDOW: Duration = Duration::from_secs(60);
const RATE_LIMIT: u32 = 600;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    Get,
    Head,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    Dashboard,
    Styles,
    Script,
    Favicon,
    Robots,
    ApiStatus,
    Health,
    Legacy,
    NotFound,
    UnknownHost,
    RateLimited,
    MethodNotAllowed,
    BadRequest,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Request<'a> {
    pub method: Method,
    pub path: &'a str,
    pub host: &'a str,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DashboardStatus {
    pub schema: String,
    pub health: String,
    pub state: String,
    pub running: Option<u64>,
    pub inbox_pending: Option<u64>,
    pub outbox_pending: Option<u64>,
    pub reconciliation_pending: Option<u64>,
    pub outbox_ambiguous: Option<u64>,
    pub provider_available: Option<bool>,
    pub accepting_intake: Option<bool>,
    pub generation: Option<u64>,
    pub execution_state: Option<String>,
    pub telegram_state: Option<String>,
    pub observed_ms: Option<u64>,
    pub stale: bool,
}

impl DashboardStatus {
    fn unavailable() -> Self {
        Self {
            schema: String::from("automonique.dashboard.status/v1"),
            health: String::from("unavailable"),
            state: String::from("unavailable"),
            running: None,
            inbox_pending: None,
            outbox_pending: None,
            reconciliation_pending: None,
            outbox_ambiguous: None,
            provider_available: None,
            accepting_intake: None,
            generation: None,
            execution_state: None,
            telegram_state: None,
            observed_ms: None,
            stale: true,
        }
    }
}

#[derive(Deserialize)]
struct AdminStatus {
    state: String,
    running: u64,
    inbox_pending: u64,
    outbox_pending: u64,
    accepting_intake: bool,
    generation: u64,
    execution_state: String,
    telegram_state: String,
    operational: OperationalStatus,
}

#[derive(Deserialize)]
struct OperationalStatus {
    reconciliation_pending: u64,
    outbox_in_flight_ambiguous: u64,
    provider_available: OperationalMetric,
}

#[derive(Deserialize)]
struct OperationalMetric {
    value: Option<u64>,
}

struct RateWindow {
    started: Instant,
    requests: u32,
}

pub struct AppState {
    status: RwLock<DashboardStatus>,
    rate: Mutex<RateWindow>,
}

impl AppState {
    pub fn new(status: DashboardStatus) -> Self {
        Self {
            status: RwLock::new(status),
            rate: Mutex::new(RateWindow {
                started: Instant::now(),
                requests: 0,
            }),
        }
    }

    fn snapshot(&self) -> DashboardStatus {
        match self.status.read() {
            Ok(status) => status.clone(),
            Err(_) => DashboardStatus::unavailable(),
        }
    }

    fn admit(&self) -> bool {
        let Ok(mut window) = self.rate.lock() else {
            return false;
        };
        if window.started.elapsed() >= RATE_WINDOW {
            window.started = Instant::now();
            window.requests = 0;
        }
        if window.requests >= RATE_LIMIT {
            return false;
        }
        window.requests += 1;
        true
    }
}

pub fn parse_request(bytes: &[u8]) -> Result<Request<'_>, Route> {
    let mut headers = [httparse::EMPTY_HEADER; HEADER_COUNT_LIMIT];
    let mut parsed = httparse::Request::new(&mut headers);
    let status = parsed.parse(bytes).map_err(|_| Route::BadRequest)?;
    if !status.is_complete() || parsed.version != Some(1) {
        return Err(Route::BadRequest);
    }

    let method = match parsed.method {
        Some("GET") => Method::Get,
        Some("HEAD") => Method::Head,
        Some(_) => return Err(Route::MethodNotAllowed),
        None => return Err(Route::BadRequest),
    };
    let path = parsed.path.ok_or(Route::BadRequest)?;
    if !path.starts_with('/') || path.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(Route::BadRequest);
    }

    let mut host = None;
    for header in parsed.headers.iter() {
        if header.name.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return Err(Route::BadRequest);
            }
            host = Some(std::str::from_utf8(header.value).map_err(|_| Route::BadRequest)?);
        }
    }
    let host = host.ok_or(Route::BadRequest)?.trim();
    if normalize_host(host).is_none() {
        return Err(Route::BadRequest);
    }
    Ok(Request { method, path, host })
}

pub fn route(request: &Request<'_>) -> Route {
    match normalize_host(request.host) {
        Some(host) if host.eq_ignore_ascii_case(LEGACY_HOST) => Route::Legacy,
        Some(host)
            if host.eq_ignore_ascii_case(CANONICAL_HOST)
                || host.eq_ignore_ascii_case("localhost") =>
        {
            match request.path.split('?').next().unwrap_or_default() {
                "/" => Route::Dashboard,
                "/assets/dashboard.css" => Route::Styles,
                "/assets/dashboard.js" => Route::Script,
                "/favicon.svg" => Route::Favicon,
                "/robots.txt" => Route::Robots,
                "/api/status" => Route::ApiStatus,
                "/healthz" => Route::Health,
                _ => Route::NotFound,
            }
        }
        Some(_) => Route::UnknownHost,
        None => Route::BadRequest,
    }
}

pub fn normalize_host(value: &str) -> Option<&str> {
    if value.is_empty() || value.len() > 253 || !value.is_ascii() || value.ends_with('.') {
        return None;
    }
    let (host, port) = match value.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (value, None),
    };
    if host.is_empty()
        || host.contains([':', '@', '/', '\\', ' ', '\t'])
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return None;
    }
    if let Some(port) = port {
        let port = port.parse::<u16>().ok()?;
        if port == 0 {
            return None;
        }
    }
    Some(host)
}

pub fn dashboard_status(admin_json: &[u8], observed_ms: u64) -> Option<DashboardStatus> {
    let status: AdminStatus = serde_json::from_slice(admin_json).ok()?;
    let state = bounded_state(&status.state)?;
    let execution_state = bounded_state(&status.execution_state)?;
    let telegram_state = bounded_state(&status.telegram_state)?;
    let provider_available = status
        .operational
        .provider_available
        .value
        .map(|value| value > 0);
    let healthy = state == "ready"
        && status.accepting_intake
        && status.operational.reconciliation_pending == 0
        && status.operational.outbox_in_flight_ambiguous == 0
        && provider_available == Some(true);
    Some(DashboardStatus {
        schema: String::from("automonique.dashboard.status/v1"),
        health: String::from(if healthy { "operational" } else { "degraded" }),
        state,
        running: Some(status.running),
        inbox_pending: Some(status.inbox_pending),
        outbox_pending: Some(status.outbox_pending),
        reconciliation_pending: Some(status.operational.reconciliation_pending),
        outbox_ambiguous: Some(status.operational.outbox_in_flight_ambiguous),
        provider_available,
        accepting_intake: Some(status.accepting_intake),
        generation: Some(status.generation),
        execution_state: Some(execution_state),
        telegram_state: Some(telegram_state),
        observed_ms: Some(observed_ms),
        stale: false,
    })
}

fn bounded_state(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return None;
    }
    Some(value.to_owned())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn refresh_status(state: &AppState) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = automonique_cli::run(["status", "--json"], &mut stdout, &mut stderr);
    let next = if exit == 0 {
        dashboard_status(&stdout, now_ms())
    } else {
        None
    };
    let Ok(mut status) = state.status.write() else {
        return;
    };
    if let Some(next) = next {
        *status = next;
    } else {
        status.stale = true;
        status.health = String::from(if status.observed_ms.is_some() {
            "degraded"
        } else {
            "unavailable"
        });
    }
}

fn start_status_refresher(state: Arc<AppState>) -> io::Result<()> {
    thread::Builder::new()
        .name(String::from("dashboard-status"))
        .spawn(move || {
            loop {
                refresh_status(&state);
                thread::park_timeout(STATUS_REFRESH);
            }
        })?;
    Ok(())
}

struct Response {
    status: &'static str,
    content_type: Option<&'static str>,
    cache_control: &'static str,
    location: Option<&'static str>,
    retry_after: Option<&'static str>,
    body: Vec<u8>,
}

impl Response {
    fn static_asset(content_type: &'static str, body: &'static str) -> Self {
        Self {
            status: "200 OK",
            content_type: Some(content_type),
            cache_control: "public, max-age=3600",
            location: None,
            retry_after: None,
            body: body.as_bytes().to_vec(),
        }
    }
}

fn response_for(route: Route, state: &AppState) -> Response {
    match route {
        Route::Dashboard => Response {
            status: "200 OK",
            content_type: Some("text/html; charset=utf-8"),
            cache_control: "no-cache",
            location: None,
            retry_after: None,
            body: DASHBOARD_HTML.as_bytes().to_vec(),
        },
        Route::Styles => Response::static_asset("text/css; charset=utf-8", DASHBOARD_CSS),
        Route::Script => Response::static_asset("text/javascript; charset=utf-8", DASHBOARD_JS),
        Route::Favicon => Response::static_asset("image/svg+xml", FAVICON_SVG),
        Route::Robots => Response::static_asset("text/plain; charset=utf-8", ROBOTS_TXT),
        Route::ApiStatus => Response {
            status: "200 OK",
            content_type: Some("application/json; charset=utf-8"),
            cache_control: "no-store",
            location: None,
            retry_after: None,
            body: serde_json::to_vec(&state.snapshot()).unwrap_or_else(|_| b"{}".to_vec()),
        },
        Route::Health => Response {
            status: "200 OK",
            content_type: Some("text/plain; charset=utf-8"),
            cache_control: "no-store",
            location: None,
            retry_after: None,
            body: b"ok\n".to_vec(),
        },
        Route::Legacy => Response {
            status: "308 Permanent Redirect",
            content_type: None,
            cache_control: "no-store",
            location: Some("https://monique.1clic.pro/"),
            retry_after: None,
            body: Vec::new(),
        },
        Route::NotFound => empty_response("404 Not Found"),
        Route::UnknownHost => empty_response("421 Misdirected Request"),
        Route::RateLimited => Response {
            status: "429 Too Many Requests",
            content_type: None,
            cache_control: "no-store",
            location: None,
            retry_after: Some("60"),
            body: Vec::new(),
        },
        Route::MethodNotAllowed => Response {
            status: "405 Method Not Allowed",
            content_type: None,
            cache_control: "no-store",
            location: None,
            retry_after: None,
            body: Vec::new(),
        },
        Route::BadRequest => empty_response("400 Bad Request"),
    }
}

fn empty_response(status: &'static str) -> Response {
    Response {
        status,
        content_type: None,
        cache_control: "no-store",
        location: None,
        retry_after: None,
        body: Vec::new(),
    }
}

fn response_bytes(response: Response, head_only: bool) -> Vec<u8> {
    let content_security_policy = if response.content_type == Some("text/html; charset=utf-8") {
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
    } else {
        "default-src 'none'; frame-ancestors 'none'"
    };
    let mut headers = format!(
        "HTTP/1.1 {}\r\n\
         Cache-Control: {}\r\n\
         Content-Security-Policy: {}\r\n\
         Cross-Origin-Opener-Policy: same-origin\r\n\
         Cross-Origin-Resource-Policy: same-origin\r\n\
         Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()\r\n\
         Referrer-Policy: no-referrer\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         X-Robots-Tag: noindex, nofollow\r\n\
         Connection: close\r\n",
        response.status, response.cache_control, content_security_policy
    );
    if let Some(content_type) = response.content_type {
        headers.push_str(&format!("Content-Type: {content_type}\r\n"));
    }
    if let Some(location) = response.location {
        headers.push_str(&format!("Location: {location}\r\n"));
    }
    if let Some(retry_after) = response.retry_after {
        headers.push_str(&format!("Retry-After: {retry_after}\r\n"));
    }
    if response.status == "405 Method Not Allowed" {
        headers.push_str("Allow: GET, HEAD\r\n");
    }
    headers.push_str(&format!("Content-Length: {}\r\n\r\n", response.body.len()));
    let mut bytes = headers.into_bytes();
    if !head_only {
        bytes.extend_from_slice(&response.body);
    }
    bytes
}

fn handle(mut stream: TcpStream, state: &AppState) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut bytes = [0_u8; HEADER_LIMIT];
    let mut used = 0;
    let parsed = loop {
        if used == bytes.len() {
            break Err(Route::BadRequest);
        }
        let read = stream.read(&mut bytes[used..])?;
        if read == 0 {
            break Err(Route::BadRequest);
        }
        used += read;
        match parse_request(&bytes[..used]) {
            Ok(request) => {
                let route = if state.admit() {
                    route(&request)
                } else {
                    Route::RateLimited
                };
                break Ok((route, request.method == Method::Head));
            }
            Err(Route::BadRequest) if !bytes[..used].windows(4).any(|part| part == b"\r\n\r\n") => {
                continue;
            }
            Err(error) => break Err(error),
        }
    };
    let (route, head_only) = match parsed {
        Ok(value) => value,
        Err(route) => (route, false),
    };
    stream.write_all(&response_bytes(response_for(route, state), head_only))?;
    stream.flush()
}

pub fn serve(listener: TcpListener) -> io::Result<()> {
    let state = Arc::new(AppState::new(DashboardStatus::unavailable()));
    refresh_status(&state);
    start_status_refresher(Arc::clone(&state))?;

    let (sender, receiver) = mpsc::sync_channel::<TcpStream>(QUEUE_DEPTH);
    let receiver = Arc::new(Mutex::new(receiver));
    for index in 0..WORKERS {
        let receiver = Arc::clone(&receiver);
        let state = Arc::clone(&state);
        thread::Builder::new()
            .name(format!("web-entry-{index}"))
            .spawn(move || {
                loop {
                    let stream = match receiver.lock() {
                        Ok(receiver) => receiver.recv(),
                        Err(_) => return,
                    };
                    match stream {
                        Ok(stream) => {
                            let _ = handle(stream, &state);
                        }
                        Err(_) => return,
                    }
                }
            })?;
    }

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => match sender.try_send(stream) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(mut stream)) => {
                    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                    let _ = stream.write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                    );
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "web entry worker queue disconnected",
                    ));
                }
            },
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Shutdown;

    fn request(method: &str, path: &str, host: &str) -> Vec<u8> {
        format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
            .into_bytes()
    }

    fn fixture_status() -> DashboardStatus {
        dashboard_status(
            br#"{
              "state":"ready","running":2,"inbox_pending":1,"outbox_pending":0,
              "accepting_intake":true,"generation":42,
              "execution_state":"sandbox_enforceable_no_lane","telegram_state":"polling_live",
              "operational":{"reconciliation_pending":0,"outbox_in_flight_ambiguous":0,
                "provider_available":{"state":"measured","value":1}}
            }"#,
            1234,
        )
        .unwrap()
    }

    #[test]
    fn canonical_routes_are_dedicated_dashboard_assets() {
        let cases = [
            ("/", Route::Dashboard),
            ("/assets/dashboard.css", Route::Styles),
            ("/assets/dashboard.js", Route::Script),
            ("/api/status?fresh=1", Route::ApiStatus),
            ("/missing", Route::NotFound),
        ];
        for (path, expected) in cases {
            let bytes = request("GET", path, CANONICAL_HOST);
            assert_eq!(expected, route(&parse_request(&bytes).unwrap()));
        }
    }

    #[test]
    fn status_projection_is_bounded_and_operational() {
        let status = fixture_status();
        assert_eq!("automonique.dashboard.status/v1", status.schema);
        assert_eq!("operational", status.health);
        assert_eq!(Some(2), status.running);
        assert_eq!(Some(true), status.provider_available);
        assert_eq!(Some(1234), status.observed_ms);
        assert!(!status.stale);
    }

    #[test]
    fn status_projection_refuses_unbounded_labels() {
        let invalid = br#"{
          "state":"<script>","running":0,"inbox_pending":0,"outbox_pending":0,
          "accepting_intake":true,"generation":1,"execution_state":"ready",
          "telegram_state":"disabled_no_client","operational":{"reconciliation_pending":0,
          "outbox_in_flight_ambiguous":0,"provider_available":{"value":1}}
        }"#;
        assert!(dashboard_status(invalid, 1).is_none());
    }

    #[test]
    fn api_contains_no_instance_or_message_fields() {
        let state = AppState::new(fixture_status());
        let response = response_for(Route::ApiStatus, &state);
        let value: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        let object = value.as_object().unwrap();
        for forbidden in [
            "instance_id",
            "messages",
            "token",
            "runs",
            "outbox_delivered",
        ] {
            assert!(!object.contains_key(forbidden));
        }
    }

    #[test]
    fn dashboard_security_policy_allows_only_same_origin_assets() {
        let state = AppState::new(fixture_status());
        let response = String::from_utf8(response_bytes(
            response_for(Route::Dashboard, &state),
            false,
        ))
        .unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("script-src 'self'"));
        assert!(response.contains("connect-src 'self'"));
        assert!(response.contains("X-Frame-Options: DENY\r\n"));
        assert!(!response.contains("unsafe-inline"));
    }

    #[test]
    fn legacy_host_redirects_to_canonical_host() {
        let bytes = request("HEAD", "/old/path", LEGACY_HOST);
        let parsed = parse_request(&bytes).unwrap();
        assert_eq!(Method::Head, parsed.method);
        assert_eq!(Route::Legacy, route(&parsed));
        let state = AppState::new(fixture_status());
        let response = response_bytes(response_for(Route::Legacy, &state), true);
        assert!(
            response
                .windows(CANONICAL_HOST.len())
                .any(|part| part == CANONICAL_HOST.as_bytes())
        );
    }

    #[test]
    fn invalid_or_duplicate_host_is_rejected() {
        for host in ["", "attacker@monique.1clic.pro", "monique.1clic.pro:0"] {
            assert!(parse_request(&request("GET", "/", host)).is_err());
        }
        let duplicate =
            b"GET / HTTP/1.1\r\nHost: monique.1clic.pro\r\nHost: attacker.example\r\n\r\n";
        assert_eq!(Err(Route::BadRequest), parse_request(duplicate));
    }

    #[test]
    fn method_not_allowed_has_no_redirect() {
        let bytes = request("POST", "/", CANONICAL_HOST);
        let parsed = parse_request(&bytes);
        assert_eq!(Err(Route::MethodNotAllowed), parsed);
        let state = AppState::new(fixture_status());
        let response = response_bytes(response_for(Route::MethodNotAllowed, &state), false);
        assert!(!response.windows(9).any(|part| part == b"Location:"));
    }

    #[test]
    fn tcp_handler_returns_dashboard_html() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(AppState::new(fixture_status()));
        let server_state = Arc::clone(&state);
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle(stream, &server_state).unwrap();
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .write_all(&request("GET", "/", CANONICAL_HOST))
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut received = Vec::new();
        client.read_to_end(&mut received).unwrap();
        server.join().unwrap();
        assert!(received.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(
            received
                .windows(17)
                .any(|part| part == b"Monique dashboard")
        );
    }
}
