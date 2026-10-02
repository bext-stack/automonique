// SPDX-License-Identifier: Elastic-2.0

//! The interactive half of `automonique shot`.
//!
//! The browser's command-line screenshot mode captures a page as loaded and
//! nothing else. A state that needs an interaction first is reached here over
//! the DevTools protocol instead: the browser is started with a throwaway
//! profile and a debugging port it picks itself on the loopback interface,
//! and this module speaks JSON to it over one websocket.
//!
//! The vocabulary is closed. An action is one of four verbs plus a CSS
//! selector, and the selector is never spliced into a program: the page-side
//! code is the constant [`LOCATE_FUNCTION`], and the selector travels as a
//! `Runtime.callFunctionOn` argument, so a selector full of quotes is still
//! only a string the page hands to `querySelector`. Clicks and hovers are
//! real pointer events at the element's centre, refused while something else
//! covers that point, so a capture never claims an interaction the page did
//! not receive.
//!
//! Every wait is bounded twice: by the per-action timeout, which produces a
//! reason naming the action and its selector, and by the invocation's hard
//! deadline, after which the browser is killed.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde_json::{Value, json};
use tungstenite::protocol::{Message, WebSocket, WebSocketConfig};

use crate::shot::{
    ActionKind, DEFAULT_SETTLE_MS, MAX_DIMENSION, ShotAction, ShotOutcome, ShotRequest,
};

/// Largest protocol message accepted: a full-height PNG travels base64 in one.
const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
/// Largest decoded screenshot written to disk.
const MAX_PNG_BYTES: usize = 40 * 1024 * 1024;
/// How long the page's load event is awaited before the actions start anyway.
const LOAD_WAIT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
const STARTUP_POLL: Duration = Duration::from_millis(25);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const CLOSE_GRACE: Duration = Duration::from_secs(1);
const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

/// The only page-side program an action runs. It receives the selector and
/// the mode as arguments and reports where the element is; it never builds
/// code from either.
const LOCATE_FUNCTION: &str = r"function (selector, mode) {
  let element;
  try {
    element = document.querySelector(selector);
  } catch (error) {
    return { state: 'invalid' };
  }
  if (!element) return { state: 'missing' };
  const style = getComputedStyle(element);
  let box = element.getBoundingClientRect();
  if (!(box.width > 0 && box.height > 0) || style.visibility === 'hidden' || style.display === 'none') {
    return { state: 'hidden' };
  }
  if (mode !== 'wait') {
    element.scrollIntoView({ block: mode === 'start' ? 'start' : 'center', inline: 'nearest', behavior: 'instant' });
    box = element.getBoundingClientRect();
  }
  if (element.tagName === 'IMG' && !(element.complete && element.naturalWidth > 0)) {
    return { state: 'loading' };
  }
  const x = box.left + box.width / 2;
  const y = box.top + box.height / 2;
  if (mode === 'point') {
    if (x < 0 || y < 0 || x >= window.innerWidth || y >= window.innerHeight) {
      return { state: 'offscreen' };
    }
    const hit = document.elementFromPoint(x, y);
    if (hit && hit !== element && !element.contains(hit) && !hit.contains(element)) {
      let name = hit.tagName.toLowerCase();
      if (hit.id) name += '#' + hit.id;
      else if (hit.classList.length) name += '.' + hit.classList[0];
      return { state: 'covered', by: name.slice(0, 80) };
    }
  }
  return {
    state: 'visible',
    x: x,
    y: y,
    left: box.left + window.scrollX,
    top: box.top + window.scrollY,
    width: box.width,
    height: box.height,
  };
}";

/// Constant expression read once before the capture.
const PAGE_INFO_EXPRESSION: &str = "(() => { const body = document.body; \
const title = document.head && document.head.querySelector('title'); \
return { title: title ? document.title : null, \
empty: !body || (body.childElementCount === 0 && body.textContent.trim() === '') }; })()";

/// What the page-side locator does besides reporting the element's box.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    /// Report only.
    Wait,
    /// Scroll the element to the top of the viewport.
    Start,
    /// Scroll the element to the middle of the viewport.
    Center,
    /// Scroll to the middle and require the centre point to reach the element.
    Point,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::Wait => "wait",
            Self::Start => "start",
            Self::Center => "center",
            Self::Point => "point",
        }
    }
}

/// A visible element: its centre in viewport coordinates and its box in
/// document coordinates, in CSS pixels.
#[derive(Clone, Debug, PartialEq)]
struct Located {
    x: f64,
    y: f64,
    left: f64,
    top: f64,
    width: f64,
    height: f64,
}

/// One answer from the page-side locator.
#[derive(Clone, Debug, PartialEq)]
enum Probe {
    Visible(Located),
    Missing,
    Hidden,
    Loading,
    Offscreen,
    Covered(String),
    Invalid,
}

impl Probe {
    /// Why the wait is not over, as the failure reason spells it.
    fn reason(&self) -> String {
        match self {
            Self::Visible(_) => String::from("visible"),
            Self::Missing => String::from("not found"),
            Self::Hidden => String::from("not visible"),
            Self::Loading => String::from("image not loaded"),
            Self::Offscreen => String::from("outside the viewport"),
            Self::Covered(by) => format!("covered by <{by}>"),
            Self::Invalid => String::from("invalid selector"),
        }
    }
}

/// Why a protocol exchange did not produce a result.
#[derive(Debug)]
enum Fault {
    /// The invocation's hard deadline passed.
    Deadline,
    /// The browser answered with an error. During a wait this usually means a
    /// navigation replaced the document, so the wait tries again.
    Refused(String),
    /// The connection to the browser is unusable.
    Broken(String),
}

/// Capture `request` after applying its actions. `navigation` and
/// `resolver_rule` are the already-pinned URL and resolver mapping the plain
/// path would have used.
pub(crate) fn capture(
    request: &ShotRequest,
    browser: &Path,
    navigation: &str,
    resolver_rule: Option<&str>,
) -> Result<ShotOutcome, String> {
    let deadline = Instant::now() + request.deadline;
    // Declared first so it is removed last, after the browser has gone.
    let profile = Profile::create()?;
    let mut process = BrowserProcess::spawn(request, browser, &profile.0, resolver_rule)?;
    drive(request, navigation, &profile.0, &mut process, deadline)
}

fn drive(
    request: &ShotRequest,
    navigation: &str,
    profile: &Path,
    process: &mut BrowserProcess,
    deadline: Instant,
) -> Result<ShotOutcome, String> {
    let endpoint = process.endpoint(profile, deadline, request)?;
    let mut devtools = Devtools::connect(&endpoint, deadline)
        .map_err(|fault| explain(fault, request, "connecting to the browser"))?;
    let opening = |fault| explain(fault, request, "opening the page");

    let targets = devtools
        .call("Target.getTargets", json!({}))
        .map_err(opening)?;
    let existing = targets["targetInfos"]
        .as_array()
        .and_then(|infos| infos.iter().find(|info| info["type"] == "page"))
        .and_then(|info| info["targetId"].as_str())
        .map(str::to_owned);
    let target = match existing {
        Some(target) => target,
        None => devtools
            .call("Target.createTarget", json!({ "url": "about:blank" }))
            .map_err(opening)?["targetId"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| String::from("the browser opened no page"))?,
    };
    let attached = devtools
        .call(
            "Target.attachToTarget",
            json!({ "targetId": target, "flatten": true }),
        )
        .map_err(opening)?;
    devtools.session = Some(
        attached["sessionId"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| String::from("the browser attached no page session"))?,
    );
    devtools.call("Page.enable", json!({})).map_err(opening)?;
    devtools
        .call(
            "Emulation.setDeviceMetricsOverride",
            viewport_params(request.width, request.height),
        )
        .map_err(opening)?;
    devtools.load_fired = false;
    let navigated = devtools
        .call("Page.navigate", json!({ "url": navigation }))
        .map_err(opening)?;
    if let Some(error) = navigated["errorText"]
        .as_str()
        .filter(|text| !text.is_empty())
    {
        return Err(format!(
            "the page did not load ({}): check the URL, the vhost and that the site answers",
            one_line(error, 80)
        ));
    }
    devtools
        .wait_for_load(deadline.min(Instant::now() + LOAD_WAIT))
        .map_err(opening)?;

    for action in &request.actions {
        devtools.perform(action, request)?;
    }
    if let Some(selector) = request.selector.as_deref() {
        devtools.locate("selector", selector, Mode::Center, request)?;
    }
    let settle = request
        .settle
        .unwrap_or(Duration::from_millis(DEFAULT_SETTLE_MS));
    std::thread::sleep(settle.min(deadline.saturating_duration_since(Instant::now())));
    let clip = match request.selector.as_deref() {
        Some(selector) => Some(clip_params(&devtools.locate(
            "selector",
            selector,
            Mode::Wait,
            request,
        )?)),
        None => None,
    };

    let capturing = |fault| explain(fault, request, "capturing the page");
    let info = devtools
        .call(
            "Runtime.evaluate",
            json!({ "expression": PAGE_INFO_EXPRESSION, "returnByValue": true }),
        )
        .map_err(capturing)?;
    let page = &info["result"]["value"];
    if page["empty"] == true {
        return Err(String::from(
            "the page did not load (empty document): check the URL, the vhost and that the site answers",
        ));
    }
    let title = page_title(page["title"].as_str());
    let shot = devtools
        .call("Page.captureScreenshot", screenshot_params(clip))
        .map_err(capturing)?;
    let png = decode_png(shot["data"].as_str().unwrap_or_default())?;
    std::fs::write(&request.out, &png)
        .map_err(|error| format!("could not write {}: {error}", request.out.display()))?;

    devtools.session = None;
    if devtools.send("Browser.close", json!({})).is_ok() {
        process.closing = true;
    }
    Ok(ShotOutcome {
        png: std::fs::canonicalize(&request.out).unwrap_or_else(|_| request.out.clone()),
        title,
        bytes: png.len() as u64,
    })
}

/// A throwaway browser profile, private to this user and removed on drop.
/// The debugging port requires a profile directory of its own, and a fresh
/// one keeps cookies and caches of one capture out of the next.
struct Profile(PathBuf);

impl Profile {
    fn create() -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt as _;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        for attempt in 0..16_u32 {
            let path = std::env::temp_dir().join(format!(
                "monique-shot-profile-{}-{nanos}-{attempt}",
                std::process::id()
            ));
            // `create` refuses an existing path, so a directory someone else
            // prepared under this name is never adopted.
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!(
                        "could not create a browser profile directory: {error}"
                    ));
                }
            }
        }
        Err(String::from(
            "could not create a browser profile directory: every candidate name exists",
        ))
    }
}

impl Drop for Profile {
    fn drop(&mut self) {
        if std::fs::remove_dir_all(&self.0).is_err() {
            // A helper process of the browser may still be closing a file.
            std::thread::sleep(Duration::from_millis(200));
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

/// Where the browser's DevTools endpoint listens on loopback.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Endpoint {
    port: u16,
    path: String,
}

/// Read the `DevToolsActivePort` file the browser writes into its profile:
/// the port on the first line, the browser endpoint path on the second.
fn parse_active_port(text: &str) -> Option<Endpoint> {
    let mut lines = text.lines();
    let port: u16 = lines.next()?.trim().parse().ok()?;
    let path = lines.next()?.trim();
    let valid = port != 0
        && path.starts_with("/devtools/browser/")
        && path.len() <= 128
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'/' || byte == b'-');
    valid.then(|| Endpoint {
        port,
        path: path.to_owned(),
    })
}

/// The browser process, killed on drop.
struct BrowserProcess {
    child: Child,
    /// Set once the browser was asked to close, so drop gives it a moment.
    closing: bool,
}

impl BrowserProcess {
    fn spawn(
        request: &ShotRequest,
        browser: &Path,
        profile: &Path,
        resolver_rule: Option<&str>,
    ) -> Result<Self, String> {
        let mut command = Command::new(browser);
        command
            .arg("--headless=new")
            .arg("--no-sandbox")
            .arg("--disable-gpu")
            .arg("--disable-dev-shm-usage")
            .arg("--hide-scrollbars")
            .arg("--ignore-certificate-errors")
            .arg("--no-first-run")
            .arg("--disable-extensions")
            .arg("--disable-sync")
            .arg("--disable-background-networking")
            .arg(format!(
                "--window-size={},{}",
                request.width, request.height
            ))
            // Port 0 lets the browser pick a free port; it listens on the
            // loopback interface only and reports the port in its profile.
            .arg("--remote-debugging-address=127.0.0.1")
            .arg("--remote-debugging-port=0")
            .arg(format!("--user-data-dir={}", profile.display()));
        if let Some(rule) = resolver_rule {
            command.arg(format!("--host-resolver-rules={rule}"));
        }
        let child = command
            .arg("about:blank")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("could not start {}: {error}", browser.display()))?;
        Ok(Self {
            child,
            closing: false,
        })
    }

    /// Wait for the browser to publish its DevTools endpoint.
    fn endpoint(
        &mut self,
        profile: &Path,
        deadline: Instant,
        request: &ShotRequest,
    ) -> Result<Endpoint, String> {
        let file = profile.join("DevToolsActivePort");
        loop {
            if let Some(endpoint) = std::fs::read_to_string(&file)
                .ok()
                .as_deref()
                .and_then(parse_active_port)
            {
                return Ok(endpoint);
            }
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    return Err(format!(
                        "the browser exited before it could be driven (exit status {status})"
                    ));
                }
                Ok(None) => {}
                Err(error) => return Err(format!("waiting for the browser failed: {error}")),
            }
            if Instant::now() >= deadline {
                return Err(explain(Fault::Deadline, request, "starting the browser"));
            }
            std::thread::sleep(STARTUP_POLL);
        }
    }
}

impl Drop for BrowserProcess {
    fn drop(&mut self) {
        if self.closing {
            let until = Instant::now() + CLOSE_GRACE;
            while Instant::now() < until {
                if !matches!(self.child.try_wait(), Ok(None)) {
                    return;
                }
                std::thread::sleep(STARTUP_POLL);
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One DevTools connection, attached to at most one page session.
struct Devtools {
    socket: WebSocket<TcpStream>,
    next_id: u64,
    session: Option<String>,
    deadline: Instant,
    load_fired: bool,
}

impl Devtools {
    fn connect(endpoint: &Endpoint, deadline: Instant) -> Result<Self, Fault> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Fault::Deadline);
        }
        let broken = |error: std::io::Error| {
            Fault::Broken(format!("the browser's DevTools port is unusable: {error}"))
        };
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, endpoint.port));
        let stream =
            TcpStream::connect_timeout(&address, remaining.min(CONNECT_TIMEOUT)).map_err(broken)?;
        stream
            .set_read_timeout(Some(remaining.min(CONNECT_TIMEOUT)))
            .map_err(broken)?;
        stream
            .set_write_timeout(Some(WRITE_TIMEOUT))
            .map_err(broken)?;
        stream.set_nodelay(true).map_err(broken)?;
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE_BYTES))
            .max_frame_size(Some(MAX_MESSAGE_BYTES));
        let url = format!("ws://127.0.0.1:{}{}", endpoint.port, endpoint.path);
        let (socket, _) =
            tungstenite::client::client_with_config(url.as_str(), stream, Some(config)).map_err(
                |error| Fault::Broken(format!("the DevTools handshake failed: {error}")),
            )?;
        Ok(Self {
            socket,
            next_id: 1,
            session: None,
            deadline,
            load_fired: false,
        })
    }

    fn send(&mut self, method: &str, params: Value) -> Result<u64, Fault> {
        let id = self.next_id;
        self.next_id += 1;
        let text = command(id, self.session.as_deref(), method, params).to_string();
        self.socket
            .send(Message::text(text))
            .map_err(|error| Fault::Broken(format!("the browser connection failed: {error}")))?;
        Ok(id)
    }

    /// Send one command and wait for its reply, up to the hard deadline.
    fn call(&mut self, method: &str, params: Value) -> Result<Value, Fault> {
        let id = self.send(method, params)?;
        loop {
            let Some(mut message) = self.read(self.deadline)? else {
                return Err(Fault::Deadline);
            };
            if message["id"].as_u64() != Some(id) {
                continue;
            }
            if let Some(error) = message.get("error") {
                return Err(Fault::Refused(one_line(
                    error["message"].as_str().unwrap_or("protocol error"),
                    200,
                )));
            }
            return Ok(message["result"].take());
        }
    }

    /// Read one message, or `None` when `until` passes first. Events that
    /// matter are handled here whichever reply is being awaited.
    fn read(&mut self, until: Instant) -> Result<Option<Value>, Fault> {
        let remaining = until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        self.socket
            .get_ref()
            .set_read_timeout(Some(remaining))
            .map_err(|error| Fault::Broken(format!("the browser connection failed: {error}")))?;
        let message = match self.socket.read() {
            Ok(message) => message,
            Err(tungstenite::Error::Io(error))
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                return Ok(None);
            }
            Err(error) => {
                return Err(Fault::Broken(format!(
                    "the browser connection failed: {error}"
                )));
            }
        };
        let Message::Text(text) = message else {
            return Ok(Some(Value::Null));
        };
        let value: Value = serde_json::from_str(text.as_str()).unwrap_or(Value::Null);
        match value["method"].as_str() {
            Some("Page.loadEventFired") => self.load_fired = true,
            // A modal dialog would block every later evaluation; accept it so
            // the capture shows the page behind it.
            Some("Page.javascriptDialogOpening") => {
                self.send("Page.handleJavaScriptDialog", json!({ "accept": true }))?;
            }
            _ => {}
        }
        Ok(Some(value))
    }

    fn wait_for_load(&mut self, until: Instant) -> Result<(), Fault> {
        while !self.load_fired {
            if self.read(until)?.is_none() {
                break;
            }
        }
        Ok(())
    }

    /// Ask the page where `selector` is, once.
    fn probe(&mut self, selector: &str, mode: Mode) -> Result<Probe, Fault> {
        let document = self.call("Runtime.evaluate", json!({ "expression": "document" }))?;
        let object = document["result"]["objectId"]
            .as_str()
            .ok_or_else(|| Fault::Refused(String::from("the page has no document")))?
            .to_owned();
        let reply = self.call(
            "Runtime.callFunctionOn",
            locate_params(&object, selector, mode),
        )?;
        if !reply["exceptionDetails"].is_null() {
            return Err(Fault::Refused(String::from("the page raised an exception")));
        }
        Ok(parse_probe(&reply["result"]["value"]))
    }

    /// Wait until `selector` is visible (and, for `Mode::Point`, reachable),
    /// up to the request's per-action timeout.
    fn locate(
        &mut self,
        label: &str,
        selector: &str,
        mode: Mode,
        request: &ShotRequest,
    ) -> Result<Located, String> {
        let give_up = Instant::now() + request.action_timeout;
        let mut last = Probe::Missing;
        loop {
            match self.probe(selector, mode) {
                Ok(Probe::Visible(found)) => return Ok(found),
                Ok(Probe::Invalid) => {
                    return Err(format!("{label} {selector:?}: invalid selector"));
                }
                Ok(other) => last = other,
                // A navigation replaced the document under the probe.
                Err(Fault::Refused(_)) => {}
                Err(fault) => {
                    return Err(explain(fault, request, &format!("{label} {selector:?}")));
                }
            }
            let now = Instant::now();
            if now >= self.deadline {
                return Err(explain(
                    Fault::Deadline,
                    request,
                    &format!("{label} {selector:?}"),
                ));
            }
            if now >= give_up {
                return Err(wait_failure(label, selector, &last, request.action_timeout));
            }
            std::thread::sleep(
                POLL_INTERVAL
                    .min(give_up.saturating_duration_since(now))
                    .min(self.deadline.saturating_duration_since(now)),
            );
        }
    }

    fn perform(&mut self, action: &ShotAction, request: &ShotRequest) -> Result<(), String> {
        let label = action.kind.label();
        let mode = match action.kind {
            ActionKind::WaitFor => Mode::Wait,
            ActionKind::Click | ActionKind::Hover => Mode::Point,
            ActionKind::ScrollTo => Mode::Start,
        };
        let found = self.locate(label, &action.selector, mode, request)?;
        let events = match action.kind {
            ActionKind::Click => click_events(found.x, found.y).to_vec(),
            ActionKind::Hover => vec![mouse_event("mouseMoved", found.x, found.y, false)],
            ActionKind::WaitFor | ActionKind::ScrollTo => Vec::new(),
        };
        for event in events {
            self.call("Input.dispatchMouseEvent", event)
                .map_err(|fault| {
                    explain(fault, request, &format!("{label} {:?}", action.selector))
                })?;
        }
        Ok(())
    }
}

/// One protocol command. `method` is always a literal of this module.
fn command(id: u64, session: Option<&str>, method: &str, params: Value) -> Value {
    let mut message = json!({ "id": id, "method": method, "params": params });
    if let Some(session) = session {
        message["sessionId"] = Value::from(session);
    }
    message
}

/// `Runtime.callFunctionOn` parameters for the locator. The selector is the
/// first call argument: JSON data, whatever characters it holds.
fn locate_params(object: &str, selector: &str, mode: Mode) -> Value {
    json!({
        "objectId": object,
        "functionDeclaration": LOCATE_FUNCTION,
        "arguments": [{ "value": selector }, { "value": mode.name() }],
        "returnByValue": true,
    })
}

fn viewport_params(width: u32, height: u32) -> Value {
    json!({ "width": width, "height": height, "deviceScaleFactor": 1, "mobile": false })
}

fn mouse_event(kind: &str, x: f64, y: f64, pressed: bool) -> Value {
    if pressed {
        json!({ "type": kind, "x": x, "y": y, "button": "left", "clickCount": 1 })
    } else {
        json!({ "type": kind, "x": x, "y": y, "button": "none" })
    }
}

/// A click is the pointer arriving, then the primary button going down and up.
fn click_events(x: f64, y: f64) -> [Value; 3] {
    [
        mouse_event("mouseMoved", x, y, false),
        mouse_event("mousePressed", x, y, true),
        mouse_event("mouseReleased", x, y, true),
    ]
}

/// The screenshot clip for one element: whole pixels around its box, bounded
/// like every other dimension of this verb.
fn clip_params(found: &Located) -> Value {
    let max = f64::from(MAX_DIMENSION);
    let x = found.left.floor().max(0.0);
    let y = found.top.floor().max(0.0);
    let width = ((found.left + found.width).ceil() - x).clamp(1.0, max);
    let height = ((found.top + found.height).ceil() - y).clamp(1.0, max);
    json!({ "x": x, "y": y, "width": width, "height": height, "scale": 1 })
}

fn screenshot_params(clip: Option<Value>) -> Value {
    match clip {
        Some(clip) => json!({ "format": "png", "clip": clip, "captureBeyondViewport": true }),
        None => json!({ "format": "png" }),
    }
}

/// Decode the locator's answer. Anything unexpected reads as "not there yet".
fn parse_probe(value: &Value) -> Probe {
    match value["state"].as_str() {
        Some("visible") => {
            let number = |key: &str| value[key].as_f64().filter(|number| number.is_finite());
            match (
                number("x"),
                number("y"),
                number("left"),
                number("top"),
                number("width"),
                number("height"),
            ) {
                (Some(x), Some(y), Some(left), Some(top), Some(width), Some(height)) => {
                    Probe::Visible(Located {
                        x,
                        y,
                        left,
                        top,
                        width,
                        height,
                    })
                }
                _ => Probe::Missing,
            }
        }
        Some("hidden") => Probe::Hidden,
        Some("loading") => Probe::Loading,
        Some("offscreen") => Probe::Offscreen,
        Some("covered") => Probe::Covered(one_line(value["by"].as_str().unwrap_or("element"), 80)),
        Some("invalid") => Probe::Invalid,
        _ => Probe::Missing,
    }
}

/// The reason an action gave up, naming the action and its selector.
fn wait_failure(label: &str, selector: &str, last: &Probe, timeout: Duration) -> String {
    format!(
        "{label} {selector:?}: {} after {} ms",
        last.reason(),
        timeout.as_millis()
    )
}

fn explain(fault: Fault, request: &ShotRequest, step: &str) -> String {
    match fault {
        Fault::Deadline => format!(
            "hard timeout: the browser did not return within {}s ({step})",
            request.deadline.as_secs()
        ),
        Fault::Refused(message) => format!("{step}: the browser refused: {message}"),
        Fault::Broken(message) => format!("{step}: {message}"),
    }
}

/// Text that came from the page or the browser, made safe for a one-line
/// reason: control characters dropped, whitespace collapsed, length bounded.
fn one_line(text: &str, max: usize) -> String {
    let cleaned: String = text
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    cleaned
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(max)
        .collect()
}

/// The title line, in the words the plain path uses.
fn page_title(raw: Option<&str>) -> String {
    let Some(raw) = raw else {
        return String::from("(no title)");
    };
    let title = one_line(raw, 200);
    if title.is_empty() {
        return String::from("(empty title)");
    }
    title
}

fn decode_png(data: &str) -> Result<Vec<u8>, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|_| String::from("the browser returned an unreadable screenshot"))?;
    if !bytes.starts_with(PNG_SIGNATURE) {
        return Err(String::from("no screenshot was produced"));
    }
    if bytes.len() > MAX_PNG_BYTES {
        return Err(format!(
            "the screenshot is larger than {} MiB",
            MAX_PNG_BYTES / (1024 * 1024)
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    use super::*;
    use crate::shot::{find_browser, parse};

    const HOSTILE: &str = r#"a[title="x\"]'); document.body.remove(); //"#;

    #[test]
    fn a_selector_travels_as_a_call_argument_and_never_as_code() {
        let params = locate_params("object-1", HOSTILE, Mode::Point);
        assert_eq!(params["arguments"][0]["value"], HOSTILE);
        assert_eq!(params["arguments"][1]["value"], "point");
        assert_eq!(params["functionDeclaration"], LOCATE_FUNCTION);
        assert_eq!(params["objectId"], "object-1");
        assert!(!LOCATE_FUNCTION.contains("eval"));
        assert!(!LOCATE_FUNCTION.contains("Function("));

        // On the wire the selector is one JSON string: quotes and backslashes
        // are escaped by the encoder and come back unchanged.
        let wire = command(7, Some("session-1"), "Runtime.callFunctionOn", params).to_string();
        assert!(
            !wire.contains(HOSTILE),
            "the raw selector is not spliced in"
        );
        let decoded: Value = serde_json::from_str(&wire).expect("valid JSON");
        assert_eq!(decoded["id"], 7);
        assert_eq!(decoded["sessionId"], "session-1");
        assert_eq!(decoded["method"], "Runtime.callFunctionOn");
        assert_eq!(decoded["params"]["arguments"][0]["value"], HOSTILE);
        assert_eq!(
            decoded["params"]["functionDeclaration"], LOCATE_FUNCTION,
            "the page-side program is the same constant for every selector"
        );

        let browser_level = command(1, None, "Target.getTargets", json!({}));
        assert!(browser_level.get("sessionId").is_none());
    }

    #[test]
    fn each_action_kind_maps_to_its_protocol_messages() {
        let [moved, pressed, released] = click_events(12.5, 40.0);
        assert_eq!(
            moved,
            json!({ "type": "mouseMoved", "x": 12.5, "y": 40.0, "button": "none" })
        );
        assert_eq!(
            pressed,
            json!({ "type": "mousePressed", "x": 12.5, "y": 40.0, "button": "left", "clickCount": 1 })
        );
        assert_eq!(released["type"], "mouseReleased");
        assert_eq!(released["button"], "left");

        assert_eq!(
            viewport_params(390, 900),
            json!({ "width": 390, "height": 900, "deviceScaleFactor": 1, "mobile": false })
        );
        assert_eq!(screenshot_params(None), json!({ "format": "png" }));
        let clip = clip_params(&Located {
            x: 0.0,
            y: 0.0,
            left: 10.4,
            top: 1500.6,
            width: 240.2,
            height: 120.0,
        });
        assert_eq!(
            clip,
            json!({ "x": 10.0, "y": 1500.0, "width": 241.0, "height": 121.0, "scale": 1 })
        );
        assert_eq!(
            screenshot_params(Some(clip.clone())),
            json!({ "format": "png", "clip": clip, "captureBeyondViewport": true })
        );
        let huge = clip_params(&Located {
            x: 0.0,
            y: 0.0,
            left: -5.0,
            top: 0.0,
            width: 20_000.0,
            height: 0.2,
        });
        assert_eq!(huge["x"], 0.0);
        assert_eq!(huge["width"], f64::from(MAX_DIMENSION));
        assert_eq!(huge["height"], 1.0);
    }

    #[test]
    fn a_failed_wait_names_the_action_the_selector_and_the_cause() {
        let timeout = Duration::from_millis(10_000);
        assert_eq!(
            wait_failure("click", ".modal-open", &Probe::Missing, timeout),
            "click \".modal-open\": not found after 10000 ms"
        );
        assert_eq!(
            wait_failure("wait-for", "#panel", &Probe::Hidden, timeout),
            "wait-for \"#panel\": not visible after 10000 ms"
        );
        assert_eq!(
            wait_failure("scroll-to", "img.hero", &Probe::Loading, timeout),
            "scroll-to \"img.hero\": image not loaded after 10000 ms"
        );
        assert_eq!(
            wait_failure(
                "hover",
                "nav a",
                &Probe::Covered(String::from("div#cookies")),
                Duration::from_millis(1_500)
            ),
            "hover \"nav a\": covered by <div#cookies> after 1500 ms"
        );
        assert_eq!(
            wait_failure("click", "#far", &Probe::Offscreen, timeout),
            "click \"#far\": outside the viewport after 10000 ms"
        );
        // A selector with quotes or a line break still yields one line.
        let reason = wait_failure("selector", "a[href=\"/x\"]", &Probe::Missing, timeout);
        assert_eq!(
            reason,
            "selector \"a[href=\\\"/x\\\"]\": not found after 10000 ms"
        );
        assert!(!wait_failure("click", "a\nb", &Probe::Missing, timeout).contains('\n'));
    }

    #[test]
    fn the_locator_answer_is_decoded_defensively() {
        let visible = json!({
            "state": "visible", "x": 5.0, "y": 6.0, "left": 1.0, "top": 2.0, "width": 8.0, "height": 9.0
        });
        assert_eq!(
            parse_probe(&visible),
            Probe::Visible(Located {
                x: 5.0,
                y: 6.0,
                left: 1.0,
                top: 2.0,
                width: 8.0,
                height: 9.0
            })
        );
        assert_eq!(parse_probe(&json!({ "state": "missing" })), Probe::Missing);
        assert_eq!(parse_probe(&json!({ "state": "hidden" })), Probe::Hidden);
        assert_eq!(parse_probe(&json!({ "state": "loading" })), Probe::Loading);
        assert_eq!(parse_probe(&json!({ "state": "invalid" })), Probe::Invalid);
        assert_eq!(
            parse_probe(&json!({ "state": "offscreen" })),
            Probe::Offscreen
        );
        // The covering element's name comes from the page: one bounded line.
        let noisy = format!("div#a\nMONIQUE_SHOT_OK: {}", "x".repeat(200));
        let Probe::Covered(by) = parse_probe(&json!({ "state": "covered", "by": noisy })) else {
            panic!("covered");
        };
        assert!(by.starts_with("div#a MONIQUE_SHOT_OK:"));
        assert_eq!(by.chars().count(), 80);
        assert!(!by.contains('\n'));
        // A truncated or foreign answer is "not there yet", never a position.
        assert_eq!(
            parse_probe(&json!({ "state": "visible", "x": 1.0 })),
            Probe::Missing
        );
        assert_eq!(parse_probe(&Value::Null), Probe::Missing);
        assert_eq!(parse_probe(&json!("visible")), Probe::Missing);
    }

    #[test]
    fn the_devtools_endpoint_file_is_read_strictly() {
        assert_eq!(
            parse_active_port("41213\n/devtools/browser/0a1b-2c3d\n"),
            Some(Endpoint {
                port: 41213,
                path: String::from("/devtools/browser/0a1b-2c3d")
            })
        );
        assert_eq!(parse_active_port(""), None);
        assert_eq!(parse_active_port("41213\n"), None);
        assert_eq!(parse_active_port("0\n/devtools/browser/x\n"), None);
        assert_eq!(parse_active_port("99999\n/devtools/browser/x\n"), None);
        assert_eq!(parse_active_port("41213\n/other/x\n"), None);
        assert_eq!(
            parse_active_port("41213\n/devtools/browser/x y@evil.example/\n"),
            None
        );
    }

    #[test]
    fn titles_and_screenshots_are_bounded_and_checked() {
        assert_eq!(page_title(None), "(no title)");
        assert_eq!(page_title(Some("  \n ")), "(empty title)");
        assert_eq!(page_title(Some("  R&D —\n  page ")), "R&D — page");
        assert_eq!(page_title(Some(&"x".repeat(500))).len(), 200);

        let encoded = base64::engine::general_purpose::STANDARD.encode(b"\x89PNG\r\n\x1a\nrest");
        assert_eq!(
            decode_png(&encoded).expect("png"),
            b"\x89PNG\r\n\x1a\nrest".to_vec()
        );
        assert!(decode_png("").is_err());
        assert!(decode_png("not base64!").is_err());
        let text = base64::engine::general_purpose::STANDARD.encode(b"<html>");
        assert_eq!(
            decode_png(&text).expect_err("not a png"),
            "no screenshot was produced"
        );

        let request = parse(
            &[
                OsString::from("http://127.0.0.1:1/"),
                "--wait-ms".into(),
                "0".into(),
            ],
            PathBuf::from("/tmp/unused.png"),
        )
        .expect("parses");
        assert_eq!(
            explain(Fault::Deadline, &request, "click \"#x\""),
            "hard timeout: the browser did not return within 45s (click \"#x\")"
        );
    }

    const FIXTURE: &str = r#"<!doctype html>
<html><head><title>Shot  fixture</title>
<style>
  body { margin: 0; font: 16px sans-serif; }
  #panel { display: none; width: 240px; height: 120px; margin-top: 1500px; background: #b00020; }
  #menu { display: block; width: 100px; height: 30px; background: #222; }
  #tip { display: none; width: 200px; height: 50px; background: #0a7; }
  #menu:hover + #tip { display: block; }
</style></head>
<body>
<button data-role="open" onclick="setTimeout(() => { document.getElementById('panel').style.display = 'block'; }, 250)">Open</button>
<div id="panel"><span id="menu"></span><span id="tip"></span></div>
</body></html>"#;

    /// Serve `FIXTURE` on a loopback port for as long as the test runs.
    fn serve_fixture() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().expect("address").port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                    let mut buffer = [0_u8; 4096];
                    if stream.read(&mut buffer).unwrap_or(0) == 0 {
                        return;
                    }
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{FIXTURE}",
                        FIXTURE.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                });
            }
        });
        format!("http://127.0.0.1:{port}/")
    }

    fn png_dimensions(path: &Path) -> (u32, u32) {
        let bytes = std::fs::read(path).expect("png written");
        assert!(bytes.starts_with(PNG_SIGNATURE), "a PNG file");
        let field =
            |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().expect("four bytes"));
        (field(16), field(20))
    }

    fn shot(url: &str, out: &Path, options: &[&str]) -> Option<Result<ShotOutcome, String>> {
        let Some(browser) = find_browser() else {
            eprintln!("skipped: no headless browser on this machine");
            return None;
        };
        let mut values = vec![OsString::from(url), "--out".into(), out.into()];
        values.extend(options.iter().map(OsString::from));
        let request = parse(&values, out.to_path_buf()).expect("parses");
        assert!(request.interactive());
        Some(crate::shot::capture(&request, &browser))
    }

    #[test]
    fn a_real_browser_clicks_waits_and_captures_one_element() {
        let directory = tempfile::tempdir().expect("tempdir");
        let out = directory.path().join("panel.png");
        let url = serve_fixture();
        let Some(result) = shot(
            &url,
            &out,
            &[
                "--click",
                "button[data-role=\"open\"]",
                "--wait-for",
                "#panel",
                "--selector",
                "#panel",
            ],
        ) else {
            return;
        };
        let outcome = result.expect("captures the revealed panel");
        assert_eq!(outcome.title, "Shot fixture");
        assert!(outcome.bytes > 100, "a non-empty PNG");
        assert_eq!(png_dimensions(&out), (240, 120));
    }

    #[test]
    fn a_real_browser_scrolls_hovers_and_captures_the_viewport() {
        let directory = tempfile::tempdir().expect("tempdir");
        let out = directory.path().join("tip.png");
        let url = serve_fixture();
        // Without the hover the tooltip never shows.
        let Some(result) = shot(
            &url,
            &out,
            &[
                "--click",
                "[data-role=open]",
                "--scroll-to",
                "#panel",
                "--selector",
                "#tip",
                "--timeout-ms",
                "1500",
            ],
        ) else {
            return;
        };
        assert_eq!(
            result.expect_err("the tooltip is hidden until hovered"),
            "selector \"#tip\": not visible after 1500 ms"
        );
        assert!(!out.exists(), "a failed capture leaves no file");

        let result = shot(
            &url,
            &out,
            &[
                "--click",
                "[data-role=open]",
                "--scroll-to",
                "#panel",
                "--hover",
                "#menu",
                "--selector",
                "#tip",
            ],
        )
        .expect("browser present");
        result.expect("captures the hovered tooltip");
        assert_eq!(png_dimensions(&out), (200, 50));

        let viewport = directory.path().join("viewport.png");
        let result = shot(
            &url,
            &viewport,
            &["--width", "390", "--height", "700", "--wait-ms", "100"],
        )
        .expect("browser present");
        result.expect("captures the viewport");
        assert_eq!(png_dimensions(&viewport), (390, 700));
    }

    #[test]
    fn a_real_browser_reports_the_action_that_failed() {
        let directory = tempfile::tempdir().expect("tempdir");
        let out = directory.path().join("never.png");
        let url = serve_fixture();
        let Some(result) = shot(
            &url,
            &out,
            &[
                "--click",
                "[data-role=open]",
                "--click",
                ".modal-open",
                "--timeout-ms",
                "1000",
            ],
        ) else {
            return;
        };
        assert_eq!(
            result.expect_err("no such element"),
            "click \".modal-open\": not found after 1000 ms"
        );
        let result = shot(&url, &out, &["--wait-for", "div:nope("]).expect("browser present");
        assert_eq!(
            result.expect_err("bad selector"),
            "wait-for \"div:nope(\": invalid selector"
        );
        assert!(!out.exists());
    }
}
