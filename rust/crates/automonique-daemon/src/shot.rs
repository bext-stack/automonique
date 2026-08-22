//! `automonique shot`: visual proof for a rendered page.
//!
//! A change to a page, a component or a style is not delivered until someone
//! has looked at the page. This verb captures one URL with a headless
//! Chromium already present on the host (the browser that ships with a
//! Playwright cache, or a system Chromium), writes a PNG the agent can read
//! back, and reports the page title. It uses the browser's own command-line
//! screenshot mode, so it needs no driver, no Node, no Python.
//!
//! The contract is deliberately small and never hangs: success prints
//! `MONIQUE_SHOT_OK: <png>` then `title: <title>`; any failure prints one
//! `MONIQUE_SHOT_FAIL: <reason>` line and exits non-zero, with the browser
//! killed after the deadline. Visual verification is evidence for a report,
//! never a reason for a job to wedge.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Environment override naming the browser binary.
pub const BROWSER_ENV: &str = "AUTOMONIQUE_BROWSER";

/// Success marker the agent looks for.
pub const OK_MARKER: &str = "MONIQUE_SHOT_OK:";
/// Failure marker the agent looks for.
pub const FAIL_MARKER: &str = "MONIQUE_SHOT_FAIL:";

const DEFAULT_WIDTH: u32 = 1280;
const DEFAULT_HEIGHT: u32 = 900;
const FULL_PAGE_HEIGHT: u32 = 4_000;
const MAX_DIMENSION: u32 = 8_000;
const DEFAULT_DEADLINE_SECS: u64 = 45;
const MAX_DEADLINE_SECS: u64 = 180;
/// Virtual time the page gets to settle before the capture, in ms.
const SETTLE_BUDGET_MS: u32 = 5_000;

/// One parsed invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShotRequest {
    pub url: String,
    pub out: PathBuf,
    /// Render the URL's origin as this virtual host: the name is resolved to
    /// the URL's host and the navigation happens under the virtual host so
    /// both `Host` and SNI match the vhost while the socket stays local.
    pub host: Option<String>,
    pub width: u32,
    pub height: u32,
    pub deadline: Duration,
}

/// What a successful capture established.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShotOutcome {
    pub png: PathBuf,
    pub title: String,
    pub bytes: u64,
}

/// Parse `shot <url> [--out PATH] [--host H] [--width N] [--height N] [--full] [--timeout S]`.
pub fn parse(values: &[OsString], default_out: PathBuf) -> Result<ShotRequest, String> {
    let mut url = None;
    let mut out = default_out;
    let mut host = None;
    let mut width = DEFAULT_WIDTH;
    let mut height = DEFAULT_HEIGHT;
    let mut full = false;
    let mut deadline = Duration::from_secs(DEFAULT_DEADLINE_SECS);
    let mut values = values.iter();
    while let Some(value) = values.next() {
        let text = value
            .to_str()
            .ok_or_else(|| String::from("arguments must be UTF-8"))?;
        match text {
            "--out" => {
                out = values
                    .next()
                    .map(PathBuf::from)
                    .ok_or_else(|| String::from("--out needs a path"))?;
            }
            "--host" => {
                let name = values
                    .next()
                    .and_then(|value| value.to_str())
                    .ok_or_else(|| String::from("--host needs a host name"))?;
                if !valid_host(name) {
                    return Err(format!("invalid --host {name:?}"));
                }
                host = Some(name.to_owned());
            }
            "--width" => width = dimension(values.next(), "--width")?,
            "--height" => height = dimension(values.next(), "--height")?,
            "--full" => full = true,
            "--timeout" => {
                let seconds: u64 = values
                    .next()
                    .and_then(|value| value.to_str())
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(|| String::from("--timeout needs whole seconds"))?;
                if seconds == 0 || seconds > MAX_DEADLINE_SECS {
                    return Err(format!("--timeout must be 1..={MAX_DEADLINE_SECS}"));
                }
                deadline = Duration::from_secs(seconds);
            }
            other if other.starts_with("--") => return Err(format!("unknown option {other}")),
            other if url.is_none() => url = Some(other.to_owned()),
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    let url = url.ok_or_else(|| String::from("a URL is required"))?;
    if !(url.starts_with("https://") || url.starts_with("http://")) || url.len() > 2_048 {
        return Err(String::from(
            "the URL must be http(s) and at most 2048 bytes",
        ));
    }
    if url
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(String::from(
            "the URL must not contain whitespace or control characters",
        ));
    }
    if full {
        height = height.max(FULL_PAGE_HEIGHT);
    }
    Ok(ShotRequest {
        url,
        out,
        host,
        width,
        height,
        deadline,
    })
}

fn dimension(value: Option<&OsString>, flag: &str) -> Result<u32, String> {
    let parsed: u32 = value
        .and_then(|value| value.to_str())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| format!("{flag} needs a whole number of pixels"))?;
    if parsed == 0 || parsed > MAX_DIMENSION {
        return Err(format!("{flag} must be 1..={MAX_DIMENSION}"));
    }
    Ok(parsed)
}

fn valid_host(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// The host part of an http(s) URL, without port, or `None` when malformed.
fn url_host(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        stripped.split_once(']')?.0
    } else {
        authority.split(':').next()?
    };
    (!host.is_empty()).then_some(host)
}

/// Rewrite `url` so the browser navigates as `host` while still connecting to
/// the original address. Returns the navigation URL and the resolver rule.
fn pinned_navigation(url: &str, host: &str) -> Option<(String, String)> {
    let origin_host = url_host(url)?;
    let (scheme, rest) = url.split_once("://")?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let port = authority
        .rsplit_once(':')
        .filter(|(_, port)| port.bytes().all(|byte| byte.is_ascii_digit()) && !port.is_empty())
        .map(|(_, port)| format!(":{port}"))
        .unwrap_or_default();
    let navigation = format!("{scheme}://{host}{port}{}", &rest[authority_end..]);
    Some((navigation, format!("MAP {host} {origin_host}")))
}

/// Locate a headless-capable Chromium on this host.
///
/// In order: [`BROWSER_ENV`]; the Playwright-managed headless shell and full
/// Chromium under the user's cache (newest build wins); then a system
/// `chromium`, `chromium-browser`, `google-chrome` or `chrome` on `PATH`.
pub fn find_browser() -> Option<PathBuf> {
    if let Some(configured) = std::env::var_os(BROWSER_ENV) {
        let path = PathBuf::from(configured);
        return path.is_file().then_some(path);
    }
    if let Some(home) = std::env::var_os("HOME") {
        let cache = Path::new(&home).join(".cache").join("ms-playwright");
        for (prefix, leaf) in [
            (
                "chromium_headless_shell-",
                "chrome-headless-shell-linux64/chrome-headless-shell",
            ),
            ("chromium-", "chrome-linux64/chrome"),
            ("chromium-", "chrome-linux/chrome"),
        ] {
            if let Some(found) = newest_playwright_build(&cache, prefix, leaf) {
                return Some(found);
            }
        }
    }
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        for name in ["chromium", "chromium-browser", "google-chrome", "chrome"] {
            let candidate = directory.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn newest_playwright_build(cache: &Path, prefix: &str, leaf: &str) -> Option<PathBuf> {
    let mut builds: Vec<(u64, PathBuf)> = std::fs::read_dir(cache)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?;
            let build: u64 = name.strip_prefix(prefix)?.parse().ok()?;
            let binary = entry.path().join(leaf);
            binary.is_file().then_some((build, binary))
        })
        .collect();
    builds.sort_by(|left, right| right.0.cmp(&left.0));
    builds.into_iter().next().map(|(_, path)| path)
}

/// Capture the page. Never panics; every failure is a sentence.
pub fn capture(request: &ShotRequest, browser: &Path) -> Result<ShotOutcome, String> {
    let (navigation, resolver_rule) = match request.host.as_deref() {
        Some(host) => {
            let (navigation, rule) = pinned_navigation(&request.url, host)
                .ok_or_else(|| String::from("the URL has no host to pin"))?;
            (navigation, Some(rule))
        }
        None => (request.url.clone(), None),
    };
    if let Some(parent) = request.out.parent()
        && !parent.as_os_str().is_empty()
        && !parent.is_dir()
    {
        return Err(format!(
            "output directory {} does not exist",
            parent.display()
        ));
    }
    let _ = std::fs::remove_file(&request.out);
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
        .arg(format!("--virtual-time-budget={SETTLE_BUDGET_MS}"))
        .arg(format!("--screenshot={}", request.out.display()))
        .arg("--dump-dom");
    if let Some(rule) = resolver_rule {
        command.arg(format!("--host-resolver-rules={rule}"));
    }
    command
        .arg(&navigation)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let started = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start {}: {error}", browser.display()))?;
    let mut stdout = child.stdout.take();
    let reader = std::thread::spawn(move || {
        use std::io::Read as _;
        let mut bytes = Vec::new();
        if let Some(stdout) = stdout.as_mut() {
            let _ = stdout.take(4 * 1024 * 1024).read_to_end(&mut bytes);
        }
        bytes
    });
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() >= request.deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(error) => return Err(format!("waiting for the browser failed: {error}")),
        }
    };
    let dom = reader.join().unwrap_or_default();
    let Some(status) = status else {
        return Err(format!(
            "hard timeout: the browser did not return within {}s",
            request.deadline.as_secs()
        ));
    };
    let bytes = std::fs::metadata(&request.out)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    if bytes == 0 {
        return Err(format!(
            "no screenshot was written (browser exit status {status}); the page may not have loaded"
        ));
    }
    let dom = String::from_utf8_lossy(&dom);
    if document_is_empty(&dom) {
        let _ = std::fs::remove_file(&request.out);
        return Err(String::from(
            "the page did not load (empty document): check the URL, the vhost and that the site answers",
        ));
    }
    let title = dom_title(&dom);
    Ok(ShotOutcome {
        png: std::fs::canonicalize(&request.out).unwrap_or_else(|_| request.out.clone()),
        title,
        bytes,
    })
}

/// A navigation the browser could not complete dumps a bare skeleton; a
/// screenshot of that is a blank rectangle, not evidence.
fn document_is_empty(dom: &str) -> bool {
    let compact: String = dom.chars().filter(|c| !c.is_whitespace()).collect();
    compact.is_empty()
        || compact.eq_ignore_ascii_case("<html><head></head><body></body></html>")
        || compact.eq_ignore_ascii_case("<!DOCTYPEhtml><html><head></head><body></body></html>")
}

/// The first `<title>` text in a DOM dump, collapsed to one line and bounded.
fn dom_title(dom: &str) -> String {
    let lower = dom.to_ascii_lowercase();
    let Some(start) = lower.find("<title") else {
        return String::from("(no title)");
    };
    let Some(open_end) = lower[start..].find('>') else {
        return String::from("(no title)");
    };
    let content_start = start + open_end + 1;
    let Some(length) = lower[content_start..].find("</title>") else {
        return String::from("(no title)");
    };
    let raw = &dom[content_start..content_start + length];
    let text = raw
        .replace("&amp;", "&")
        .replace("&#39;", "'")
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">");
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return String::from("(empty title)");
    }
    collapsed.chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_the_documented_options_and_refuses_the_rest() {
        let request = parse(
            &args(&[
                "https://127.0.0.1/produits",
                "--host",
                "shop.platform.example",
                "--width",
                "390",
                "--full",
                "--out",
                "/tmp/x.png",
                "--timeout",
                "30",
            ]),
            PathBuf::from("/tmp/default.png"),
        )
        .expect("parses");
        assert_eq!(request.url, "https://127.0.0.1/produits");
        assert_eq!(request.host.as_deref(), Some("shop.platform.example"));
        assert_eq!(request.width, 390);
        assert_eq!(request.height, FULL_PAGE_HEIGHT);
        assert_eq!(request.out, PathBuf::from("/tmp/x.png"));
        assert_eq!(request.deadline, Duration::from_secs(30));

        let default = parse(
            &args(&["http://localhost:3000/"]),
            PathBuf::from("/tmp/d.png"),
        )
        .expect("parses");
        assert_eq!(default.out, PathBuf::from("/tmp/d.png"));
        assert_eq!(
            (default.width, default.height),
            (DEFAULT_WIDTH, DEFAULT_HEIGHT)
        );

        assert!(parse(&args(&[]), PathBuf::from("/tmp/d.png")).is_err());
        assert!(parse(&args(&["ftp://x/"]), PathBuf::from("/tmp/d.png")).is_err());
        assert!(parse(&args(&["https://x/ y"]), PathBuf::from("/tmp/d.png")).is_err());
        assert!(
            parse(
                &args(&["https://x/", "--host", "bad host"]),
                PathBuf::from("/tmp/d.png")
            )
            .is_err()
        );
        assert!(
            parse(
                &args(&["https://x/", "--width", "0"]),
                PathBuf::from("/tmp/d.png")
            )
            .is_err()
        );
        assert!(
            parse(
                &args(&["https://x/", "--timeout", "999"]),
                PathBuf::from("/tmp/d.png")
            )
            .is_err()
        );
        assert!(
            parse(
                &args(&["https://x/", "--bogus"]),
                PathBuf::from("/tmp/d.png")
            )
            .is_err()
        );
        assert!(
            parse(
                &args(&["https://x/", "https://y/"]),
                PathBuf::from("/tmp/d.png")
            )
            .is_err()
        );
    }

    #[test]
    fn a_virtual_host_pins_the_name_to_the_original_address() {
        let (navigation, rule) =
            pinned_navigation("https://127.0.0.1/produits?x=1", "shop.platform.example")
                .expect("pins");
        assert_eq!(navigation, "https://shop.platform.example/produits?x=1");
        assert_eq!(rule, "MAP shop.platform.example 127.0.0.1");
        let (navigation, rule) =
            pinned_navigation("http://10.0.0.5:8080/", "site.example").expect("pins");
        assert_eq!(navigation, "http://site.example:8080/");
        assert_eq!(rule, "MAP site.example 10.0.0.5");
        assert_eq!(
            url_host("https://user@host.example:443/p"),
            Some("host.example")
        );
        assert_eq!(url_host("https://[::1]:8443/p"), Some("::1"));
        assert!(pinned_navigation("https:///x", "h").is_none());
    }

    #[test]
    fn a_failed_navigation_is_recognized_by_its_empty_document() {
        assert!(document_is_empty(
            "<html><head></head><body></body></html>\n"
        ));
        assert!(document_is_empty(""));
        assert!(!document_is_empty(
            "<html><head></head><body><p>x</p></body></html>"
        ));
    }

    #[test]
    fn the_title_is_read_from_the_dom_dump_and_bounded() {
        assert_eq!(
            dom_title("<html><head><TITLE lang=\"fr\">  R&amp;D —\n  page </TITLE></head>"),
            "R&D — page"
        );
        assert_eq!(dom_title("<html></html>"), "(no title)");
        assert_eq!(dom_title("<title></title>"), "(empty title)");
        let long = format!("<title>{}</title>", "x".repeat(500));
        assert_eq!(dom_title(&long).len(), 200);
    }
}
