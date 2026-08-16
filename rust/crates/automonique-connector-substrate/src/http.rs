// SPDX-License-Identifier: Elastic-2.0

//! Reading a bounded response body, and naming why a request failed.

use std::error::Error;
use std::fmt;
use std::io::Read;

/// Why a request or a response read failed, in the vocabulary every connector
/// already used.
///
/// Three variants because that is what the six copies this replaced all mapped
/// onto, independently. It is deliberately *not* the connectors' error type:
/// each of those carries service-specific refusals — `Unauthorized`,
/// `Redirected`, `RateLimited` — that a shared HTTP helper has no business
/// producing. Consumers convert with their own `From` impl, so a mapping stays
/// visible in the crate whose vocabulary it belongs to.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransportFailure {
    /// The request or the body read exceeded its deadline.
    TimedOut,
    /// The body was longer than the caller's ceiling.
    ResponseTooLarge,
    /// Anything else: connection, TLS, DNS, protocol.
    Unavailable,
}

impl fmt::Display for TransportFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TimedOut => "request timed out",
            Self::ResponseTooLarge => "response exceeded its ceiling",
            Self::Unavailable => "service was unavailable",
        })
    }
}

impl Error for TransportFailure {}

/// Map a transport error onto the closed vocabulary, borrowing nothing from it.
///
/// ureq's own error rendering can name the URL it was dialling; none of it is
/// carried across this boundary.
pub fn map_ureq_error(error: ureq::Error) -> TransportFailure {
    match error {
        ureq::Error::Timeout(_) => TransportFailure::TimedOut,
        ureq::Error::BodyExceedsLimit(_) => TransportFailure::ResponseTooLarge,
        _ => TransportFailure::Unavailable,
    }
}

/// Read a whole response body, refusing one longer than `max_bytes`.
///
/// The ceiling is an argument, not a constant, and must stay that way: a
/// GitHub page, a Slack page and a fleet page have different worst cases, and
/// a single shared number would be either too small for one service or too
/// generous for the others. The callers keep their own constants; this keeps
/// the mechanism.
///
/// # Errors
///
/// Returns [`TransportFailure::ResponseTooLarge`] above the ceiling, or
/// whatever [`map_ureq_error`] makes of an I/O failure during the read.
pub fn read_bounded_body(
    mut reader: impl Read,
    max_bytes: usize,
) -> Result<Vec<u8>, TransportFailure> {
    let mut body = Vec::new();
    reader
        .read_to_end(&mut body)
        .map_err(|error| map_ureq_error(ureq::Error::from(error)))?;
    if body.len() > max_bytes {
        return Err(TransportFailure::ResponseTooLarge);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    /// A reader that fails immediately, so the error path is reachable without
    /// a socket.
    struct Failing(io::ErrorKind);

    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(self.0, "fixture"))
        }
    }

    /// A reader whose failure is a ureq error smuggled inside an `io::Error`,
    /// which is how ureq reports a body-limit breach through `Read`.
    struct FailingWithUreq(fn() -> ureq::Error);

    impl Read for FailingWithUreq {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other((self.0)()))
        }
    }

    #[test]
    fn a_body_at_the_ceiling_is_accepted() {
        let body = vec![b'a'; 64];
        assert_eq!(read_bounded_body(body.as_slice(), 64), Ok(body));
    }

    /// The ceiling is inclusive, and one byte past it is refused rather than
    /// truncated — a truncated body would decode as a different message.
    #[test]
    fn one_byte_past_the_ceiling_is_refused() {
        let body = vec![b'a'; 65];
        assert_eq!(
            read_bounded_body(body.as_slice(), 64),
            Err(TransportFailure::ResponseTooLarge)
        );
    }

    #[test]
    fn an_empty_body_is_accepted() {
        assert_eq!(read_bounded_body(b"".as_slice(), 64), Ok(Vec::new()));
    }

    /// A zero ceiling accepts an empty body and nothing else, rather than
    /// meaning "no limit".
    #[test]
    fn a_zero_ceiling_admits_only_an_empty_body() {
        assert_eq!(read_bounded_body(b"".as_slice(), 0), Ok(Vec::new()));
        assert_eq!(
            read_bounded_body(b"a".as_slice(), 0),
            Err(TransportFailure::ResponseTooLarge)
        );
    }

    #[test]
    fn each_caller_s_ceiling_is_its_own() {
        let body = vec![b'a'; 100];
        assert!(read_bounded_body(body.as_slice(), 256).is_ok());
        assert_eq!(
            read_bounded_body(body.as_slice(), 99),
            Err(TransportFailure::ResponseTooLarge)
        );
    }

    /// A plain I/O failure is `Unavailable` whatever its kind — including
    /// `TimedOut`.
    ///
    /// This is the surprising one, and it is pre-existing behaviour rather than
    /// a choice made here. `ureq::Error::from` only recovers a *wrapped* ureq
    /// error out of an `io::Error`; anything else becomes `Error::Io`, which
    /// falls to the catch-all. So `io::ErrorKind::TimedOut` does not reach
    /// `TransportFailure::TimedOut`: only ureq's own `Error::Timeout`, raised
    /// by the deadline the agent was configured with, does.
    #[test]
    fn a_plain_read_failure_is_unavailable_whatever_its_kind() {
        for kind in [
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::TimedOut,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::UnexpectedEof,
        ] {
            assert_eq!(
                read_bounded_body(Failing(kind), 64),
                Err(TransportFailure::Unavailable),
                "{kind:?}"
            );
        }
    }

    /// A ureq error carried inside an `io::Error` keeps its own name.
    ///
    /// This is the path a body-limit breach actually takes: ureq sets a
    /// `.limit()` on the response reader, and the breach surfaces through
    /// `Read` as an `io::Error` boxing `Error::BodyExceedsLimit`. Recovering it
    /// is what makes an oversized body report as too large rather than as a
    /// generic connection fault.
    #[test]
    fn a_ureq_error_smuggled_through_io_keeps_its_name() {
        assert_eq!(
            read_bounded_body(FailingWithUreq(|| ureq::Error::BodyExceedsLimit(64)), 64),
            Err(TransportFailure::ResponseTooLarge)
        );
        assert_eq!(
            read_bounded_body(
                FailingWithUreq(|| ureq::Error::Timeout(ureq::Timeout::Global)),
                64
            ),
            Err(TransportFailure::TimedOut)
        );
    }

    #[test]
    fn a_timeout_is_named_as_one() {
        let timeout = ureq::Error::Timeout(ureq::Timeout::Global);
        assert_eq!(map_ureq_error(timeout), TransportFailure::TimedOut);
    }

    #[test]
    fn a_body_limit_breach_is_named_as_one() {
        assert_eq!(
            map_ureq_error(ureq::Error::BodyExceedsLimit(64)),
            TransportFailure::ResponseTooLarge
        );
    }

    /// Everything else collapses into one variant on purpose: a connector that
    /// distinguished DNS from TLS from refused-connection would be telling a
    /// caller about a network it cannot act on.
    #[test]
    fn every_other_transport_error_is_unavailable() {
        for error in [
            ureq::Error::HostNotFound,
            ureq::Error::TooManyRedirects,
            ureq::Error::RedirectFailed,
            ureq::Error::ConnectionFailed,
            ureq::Error::InvalidProxyUrl,
            ureq::Error::StatusCode(500),
            ureq::Error::BadUri("fixture".to_owned()),
            ureq::Error::Tls("fixture"),
        ] {
            assert_eq!(map_ureq_error(error), TransportFailure::Unavailable);
        }
    }

    /// The failure names itself without naming what it was dialling.
    #[test]
    fn a_rendered_failure_carries_no_request_detail() {
        for failure in [
            TransportFailure::TimedOut,
            TransportFailure::ResponseTooLarge,
            TransportFailure::Unavailable,
        ] {
            let rendered = failure.to_string();
            assert!(!rendered.is_empty());
            assert!(!rendered.contains("://"), "{rendered}");
        }
    }
}
