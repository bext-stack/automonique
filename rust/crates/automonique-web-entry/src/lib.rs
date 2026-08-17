// SPDX-License-Identifier: Elastic-2.0

#![forbid(unsafe_code)]

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

pub const CANONICAL_HOST: &str = "monique.1clic.pro";
pub const LEGACY_HOST: &str = "jean.1clic.pro";
pub const MANAGE_URL: &str = "https://manage.inklura.fr/manage";

const HEADER_LIMIT: usize = 16 * 1024;
const HEADER_COUNT_LIMIT: usize = 32;
const WORKERS: usize = 4;
const QUEUE_DEPTH: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    Get,
    Head,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    Health,
    Manage,
    Legacy,
    UnknownHost,
    MethodNotAllowed,
    BadRequest,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Request<'a> {
    pub method: Method,
    pub path: &'a str,
    pub host: &'a str,
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
        Some(host) if host.eq_ignore_ascii_case(CANONICAL_HOST) => {
            if request.path == "/healthz" {
                Route::Health
            } else {
                Route::Manage
            }
        }
        Some("localhost") if request.path == "/healthz" => Route::Health,
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

pub fn response(route: Route, head_only: bool) -> Vec<u8> {
    let (status, extra_headers, body): (&str, &str, &[u8]) = match route {
        Route::Health => (
            "200 OK",
            "Content-Type: text/plain; charset=utf-8\r\n",
            b"ok\n",
        ),
        Route::Manage => (
            "302 Found",
            "Location: https://manage.inklura.fr/manage\r\n",
            b"",
        ),
        Route::Legacy => (
            "308 Permanent Redirect",
            "Location: https://monique.1clic.pro/\r\n",
            b"",
        ),
        Route::UnknownHost => ("421 Misdirected Request", "", b""),
        Route::MethodNotAllowed => ("405 Method Not Allowed", "Allow: GET, HEAD\r\n", b""),
        Route::BadRequest => ("400 Bad Request", "", b""),
    };
    let length = body.len();
    let mut bytes = format!(
        "HTTP/1.1 {status}\r\n\
         Cache-Control: no-store\r\n\
         Content-Security-Policy: default-src 'none'\r\n\
         Referrer-Policy: no-referrer\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Connection: close\r\n\
         {extra_headers}\
         Content-Length: {length}\r\n\r\n"
    )
    .into_bytes();
    if !head_only {
        bytes.extend_from_slice(body);
    }
    bytes
}

fn handle(mut stream: TcpStream) -> io::Result<()> {
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
            Ok(request) => break Ok((route(&request), request.method == Method::Head)),
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
    stream.write_all(&response(route, head_only))?;
    stream.flush()
}

pub fn serve(listener: TcpListener) -> io::Result<()> {
    let (sender, receiver) = mpsc::sync_channel::<TcpStream>(QUEUE_DEPTH);
    let receiver = Arc::new(Mutex::new(receiver));
    for index in 0..WORKERS {
        let receiver = Arc::clone(&receiver);
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
                            let _ = handle(stream);
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

    #[test]
    fn canonical_host_enters_manage() {
        let bytes = request("GET", "/", CANONICAL_HOST);
        let parsed = parse_request(&bytes).unwrap();
        assert_eq!(Route::Manage, route(&parsed));
        let response = response(route(&parsed), false);
        assert!(response.starts_with(b"HTTP/1.1 302 Found\r\n"));
        assert!(
            response
                .windows(MANAGE_URL.len())
                .any(|part| part == MANAGE_URL.as_bytes())
        );
    }

    #[test]
    fn legacy_host_redirects_to_canonical_host() {
        let bytes = request("HEAD", "/old/path", LEGACY_HOST);
        let parsed = parse_request(&bytes).unwrap();
        assert_eq!(Method::Head, parsed.method);
        assert_eq!(Route::Legacy, route(&parsed));
        assert!(
            response(Route::Legacy, true)
                .windows(CANONICAL_HOST.len())
                .any(|part| part == CANONICAL_HOST.as_bytes())
        );
    }

    #[test]
    fn health_is_bounded_to_canonical_or_loopback_host() {
        for host in [CANONICAL_HOST, "localhost"] {
            let bytes = request("GET", "/healthz", host);
            assert_eq!(Route::Health, route(&parse_request(&bytes).unwrap()));
        }
        let bytes = request("GET", "/healthz", "attacker.example");
        assert_eq!(Route::UnknownHost, route(&parse_request(&bytes).unwrap()));
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
        let response = response(Route::MethodNotAllowed, false);
        assert!(!response.windows(9).any(|part| part == b"Location:"));
    }

    #[test]
    fn security_headers_apply_to_redirects() {
        let response = String::from_utf8(response(Route::Manage, false)).unwrap();
        assert!(response.contains("Cache-Control: no-store\r\n"));
        assert!(response.contains("Content-Security-Policy: default-src 'none'\r\n"));
        assert!(response.contains("X-Frame-Options: DENY\r\n"));
    }

    #[test]
    fn tcp_handler_returns_the_bounded_redirect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle(stream).unwrap();
        });
        let mut client = TcpStream::connect(address).unwrap();
        client
            .write_all(&request("GET", "/", CANONICAL_HOST))
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut received = Vec::new();
        client.read_to_end(&mut received).unwrap();
        server.join().unwrap();
        assert!(received.starts_with(b"HTTP/1.1 302 Found\r\n"));
        assert!(
            received
                .windows(MANAGE_URL.len())
                .any(|part| part == MANAGE_URL.as_bytes())
        );
    }
}
