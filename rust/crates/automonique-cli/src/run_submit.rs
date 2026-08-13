// SPDX-License-Identifier: Elastic-2.0

//! Operator submission of one canonical RunSpec document into durable custody.
//!
//! This verb asks the daemon to hold one document. It is not a launch request,
//! and the answer it renders is custody evidence and nothing more: a document
//! that is accepted here may still never be admitted or executed.
//!
//! The discipline is the same one `submit` and `outbox reconcile` carry, for
//! the same reasons:
//!
//! - **The document arrives on stdin, never in argv.** A canonical RunSpec is
//!   arbitrary bytes — it is not required to be UTF-8, and it names process
//!   arguments and environment values. Argv is world-readable through
//!   `/proc`, so the bytes are read from a pipe and this client never renders
//!   them back.
//! - **The read is bounded before it is buffered.** Exactly
//!   [`MAX_SUBMITTED_RUN_SPEC_BYTES`] + 1 bytes are taken from stdin: one byte
//!   past the protocol ceiling is enough to know the input is too large, and
//!   is refused without allocating for the rest of it.
//! - **The digest is computed here, over the bytes that are sent.** The
//!   protocol lets a submitter declare any digest for any document, and the
//!   daemon verifies rather than trusts. This client uses
//!   [`SubmittedRunSpec::sealed`], so the digest is right by construction and
//!   there is no path through which a truncated or altered buffer travels
//!   under the digest of the bytes that were read.
//! - **The idempotency key is judged before the connection.** The key is the
//!   operator's retry identity; a malformed one is a mistake to report, not a
//!   frame to spend. Its grammar mirrors the server bound exactly.
//!
//! Nothing reaches stdout unless the daemon reported custody. A pipeline that
//! reads this command's output therefore never sees a partial or speculative
//! record.

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};

use automonique_protocol::admin::{
    AdminResponse, MAX_RUN_SUBMISSION_KEY_BYTES, MAX_SUBMITTED_RUN_SPEC_BYTES, SubmittedRunSpec,
};

use crate::admin_client;

/// Why one submission produced no output.
///
/// A client-decided category is a `'static` word of this crate's own. A
/// daemon-decided one is the stable category the daemon published, which its
/// own type bounds to 64 bytes of `[a-z0-9_]` — so it is rendered as it is,
/// exactly as the other admin verbs render theirs. No variant ever carries a
/// document byte or an idempotency key.
#[derive(Clone, Debug, Eq, PartialEq)]
enum SubmitError {
    /// An operator-supplied field is outside its bounded grammar. Nothing was
    /// read further, connected to or sent.
    Field(&'static str),
    /// Stdin could not be read to its bound.
    Input(&'static str),
    /// The daemon, its transport or its socket refused.
    Endpoint(String),
}

impl SubmitError {
    /// Stable category spelling written to stderr.
    fn category(&self) -> &str {
        match self {
            Self::Field(category) | Self::Input(category) => category,
            Self::Endpoint(category) => category,
        }
    }

    /// Usage-shaped failures exit 2 like the rest of this CLI; everything the
    /// transport or the daemon decided exits 1.
    const fn exit_code(&self) -> u8 {
        match self {
            Self::Field(_) => 2,
            Self::Input(_) | Self::Endpoint(_) => 1,
        }
    }
}

/// Submit the document on `input` under `idempotency_key`, rendering custody
/// evidence only on success.
pub(crate) fn run<R: Read, W: Write, E: Write>(
    runtime: Option<&OsStr>,
    idempotency_key: OsString,
    input: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    match submit(runtime, idempotency_key, input) {
        Ok(rendered) => {
            if stdout.write_all(rendered.as_bytes()).is_err() {
                return 1;
            }
            0
        }
        Err(error) => {
            let _ = writeln!(stderr, "automonique run refused: {}", error.category());
            error.exit_code()
        }
    }
}

fn submit<R: Read>(
    runtime: Option<&OsStr>,
    idempotency_key: OsString,
    input: &mut R,
) -> Result<String, SubmitError> {
    let idempotency_key = submission_key(idempotency_key)?;
    let document = bounded_document(input)?;
    // `sealed` hashes the buffer it is handed, so the digest on the wire is a
    // digest of the bytes on the wire. Its remaining refusals are already
    // excluded above; they are mapped rather than unwrapped so that a widened
    // constructor cannot become a panic here.
    let submission = SubmittedRunSpec::sealed(document, idempotency_key)
        .map_err(|_| SubmitError::Field("invalid_submission"))?;
    match admin_client::request(runtime, admin_client::Operation::SubmitRun(submission)) {
        Ok(AdminResponse::RunAccepted {
            run_id,
            spec_digest,
            submission_id,
            replay,
            ..
        }) => Ok(format!(
            "Automonique run accepted: run_id={} spec_digest={spec_digest} submission_id={submission_id} replay={replay}\n",
            run_id.as_str(),
        )),
        Ok(_) => Err(SubmitError::Endpoint("response_mismatch".to_owned())),
        Err(error) => Err(SubmitError::Endpoint(error.category().to_owned())),
    }
}

/// Validate the operator's retry key against the server's own bound.
///
/// The protocol collapses an invalid key and an empty document into one body
/// refusal. Checking the key here keeps the two distinguishable in the
/// operator's terminal, and keeps a malformed key from costing a connection.
fn submission_key(idempotency_key: OsString) -> Result<String, SubmitError> {
    let Ok(idempotency_key) = idempotency_key.into_string() else {
        return Err(SubmitError::Field("invalid_idempotency_key"));
    };
    if idempotency_key.is_empty()
        || idempotency_key.len() > MAX_RUN_SUBMISSION_KEY_BYTES
        || idempotency_key.chars().any(char::is_control)
    {
        return Err(SubmitError::Field("invalid_idempotency_key"));
    }
    Ok(idempotency_key)
}

/// Read at most one byte past the protocol ceiling, and refuse at the ceiling.
///
/// Reading the extra byte is what makes "too large" distinguishable from
/// "exactly maximal" without trusting the writer to report its own length.
fn bounded_document<R: Read>(input: &mut R) -> Result<Vec<u8>, SubmitError> {
    let limit =
        u64::try_from(MAX_SUBMITTED_RUN_SPEC_BYTES).expect("protocol document bound fits u64") + 1;
    let mut document = Vec::new();
    if input.take(limit).read_to_end(&mut document).is_err() {
        return Err(SubmitError::Input("stdin_io"));
    }
    if document.len() > MAX_SUBMITTED_RUN_SPEC_BYTES {
        return Err(SubmitError::Field("document_too_large"));
    }
    if document.is_empty() {
        return Err(SubmitError::Field("empty_document"));
    }
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    use automonique_protocol::admin::{AdminCommand, AdminRefusalCategory, AdminRequest};
    use automonique_protocol::codec::encode_frame;
    use automonique_protocol::digest::Sha256;
    use automonique_protocol::tools::RunId;

    /// A private runtime root holding a private `automonique/` directory, which
    /// is what the admin client insists on before it will connect.
    fn runtime_root() -> tempfile::TempDir {
        let runtime = tempfile::tempdir().expect("runtime");
        std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700))
            .expect("runtime mode");
        let product = runtime.path().join("automonique");
        std::fs::create_dir(&product).expect("product runtime");
        std::fs::set_permissions(&product, std::fs::Permissions::from_mode(0o700))
            .expect("product mode");
        runtime
    }

    fn listener(runtime: &tempfile::TempDir) -> UnixListener {
        let socket = runtime.path().join("automonique/admin.sock");
        let listener = UnixListener::bind(&socket).expect("listener");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .expect("socket mode");
        listener
    }

    /// What one fake-server turn observed about the request it was sent.
    struct Observed {
        command: AdminCommand,
        document: Vec<u8>,
        spec_digest: String,
        idempotency_key: String,
    }

    /// How long a fake server waits for the client before giving up.
    ///
    /// Every wait in this harness is deadlined. A client that is *supposed* to
    /// connect but does not must fail its test, not wedge the suite: an
    /// unbounded `accept` would turn that regression into a hang, which reports
    /// nothing and blocks everything behind it.
    const SERVER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

    /// Accept one connection within [`SERVER_DEADLINE`], or report that none
    /// arrived.
    fn accept_deadlined(listener: &UnixListener) -> Option<std::os::unix::net::UnixStream> {
        listener.set_nonblocking(true).expect("non-blocking");
        let deadline = std::time::Instant::now() + SERVER_DEADLINE;
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).expect("blocking stream");
                    stream
                        .set_read_timeout(Some(SERVER_DEADLINE))
                        .expect("read deadline");
                    stream
                        .set_write_timeout(Some(SERVER_DEADLINE))
                        .expect("write deadline");
                    return Some(stream);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) => panic!("accept: {error}"),
            }
        }
        None
    }

    /// Serve exactly one request with the real codec, answering with whatever
    /// `answer` builds from the decoded request.
    ///
    /// Returns `None` when no client arrived before the deadline, so a test
    /// that expected a connection fails on its own assertion.
    fn serve_once(
        listener: UnixListener,
        answer: impl FnOnce(&AdminRequest) -> AdminResponse + Send + 'static,
    ) -> std::thread::JoinHandle<Option<Observed>> {
        std::thread::spawn(move || {
            let mut stream = accept_deadlined(&listener)?;
            let mut prefix = [0_u8; 4];
            stream.read_exact(&mut prefix).expect("request prefix");
            let mut body = vec![0_u8; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut body).expect("request body");
            let request = AdminRequest::from_canonical_bytes(&body).expect("typed request");
            let submission = request.run_submission().expect("carried run submission");
            let observed = Observed {
                command: request.command(),
                document: submission.document().to_vec(),
                spec_digest: submission.spec_digest().to_string(),
                idempotency_key: submission.idempotency_key().to_owned(),
            };
            let response = answer(&request)
                .to_message()
                .expect("response")
                .to_canonical_bytes();
            let mut frame = Vec::new();
            encode_frame(&response, &mut frame).expect("frame");
            stream.write_all(&frame).expect("write");
            Some(observed)
        })
    }

    fn accepted(request: &AdminRequest, replay: bool) -> AdminResponse {
        AdminResponse::RunAccepted {
            request_id: request.request_id().clone(),
            run_id: RunId::new("run-alpha").expect("run identity"),
            spec_digest: *request
                .run_submission()
                .expect("carried run submission")
                .spec_digest(),
            submission_id: 7,
            replay,
        }
    }

    /// A listener that never accepted anything has nothing queued on it.
    fn assert_never_connected(listener: &UnixListener) {
        listener.set_nonblocking(true).expect("non-blocking");
        let pending = listener.accept();
        assert!(
            matches!(&pending, Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "the client connected to the daemon before it had judged its arguments",
        );
    }

    #[test]
    fn the_piped_document_travels_whole_under_its_own_digest() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| accepted(request, false));
        // Deliberately not UTF-8, and holding a NUL: a canonical RunSpec
        // document is arbitrary bytes, and this lane must not narrow that.
        let document = [b"canonical\0run\0spec".as_slice(), &[0xff, 0x00, 0xfe]].concat();

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run(
            Some(runtime.path().as_os_str()),
            OsString::from("operator:cli:1"),
            &mut document.as_slice(),
            &mut stdout,
            &mut stderr,
        );

        let observed = server
            .join()
            .expect("server")
            .expect("the client never connected");
        assert_eq!(observed.command, AdminCommand::SubmitRun);
        assert_eq!(observed.document, document);
        assert_eq!(observed.idempotency_key, "operator:cli:1");
        assert_eq!(
            observed.spec_digest,
            Sha256::digest(&document).to_string(),
            "the wire digest must be a digest of the bytes on the wire",
        );
        assert_eq!(exit, 0);
        assert!(stderr.is_empty());
        assert_eq!(
            String::from_utf8(stdout).expect("utf8 output"),
            format!(
                "Automonique run accepted: run_id=run-alpha spec_digest={} submission_id=7 replay=false\n",
                Sha256::digest(&document)
            )
        );
    }

    #[test]
    fn a_replayed_submission_renders_its_replay_flag() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| accepted(request, true));

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run(
            Some(runtime.path().as_os_str()),
            OsString::from("operator:cli:replay"),
            &mut b"document".as_slice(),
            &mut stdout,
            &mut stderr,
        );

        assert!(
            server.join().expect("server").is_some(),
            "the client never connected",
        );
        assert_eq!(exit, 0);
        assert!(stderr.is_empty());
        assert!(
            String::from_utf8(stdout)
                .expect("utf8 output")
                .ends_with(" submission_id=7 replay=true\n")
        );
    }

    #[test]
    fn a_maximal_document_is_carried_whole() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| accepted(request, false));
        let document = vec![b'd'; MAX_SUBMITTED_RUN_SPEC_BYTES];

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run(
            Some(runtime.path().as_os_str()),
            OsString::from("operator:cli:maximal"),
            &mut document.as_slice(),
            &mut stdout,
            &mut stderr,
        );

        let observed = server
            .join()
            .expect("server")
            .expect("the client never connected");
        assert_eq!(observed.document.len(), MAX_SUBMITTED_RUN_SPEC_BYTES);
        assert_eq!(observed.document, document);
        assert_eq!(observed.spec_digest, Sha256::digest(&document).to_string());
        assert_eq!(exit, 0);
        assert!(stderr.is_empty());
    }

    #[test]
    fn one_byte_past_the_ceiling_is_refused_without_a_connection() {
        let runtime = runtime_root();
        let listener = listener(&runtime);
        let document = vec![b'd'; MAX_SUBMITTED_RUN_SPEC_BYTES + 1];

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run(
            Some(runtime.path().as_os_str()),
            OsString::from("operator:cli:oversize"),
            &mut document.as_slice(),
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit, 2);
        assert!(stdout.is_empty());
        assert_eq!(stderr, b"automonique run refused: document_too_large\n");
        assert_never_connected(&listener);
    }

    #[test]
    fn an_empty_document_is_refused_without_a_connection() {
        let runtime = runtime_root();
        let listener = listener(&runtime);

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run(
            Some(runtime.path().as_os_str()),
            OsString::from("operator:cli:empty"),
            &mut b"".as_slice(),
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit, 2);
        assert!(stdout.is_empty());
        assert_eq!(stderr, b"automonique run refused: empty_document\n");
        assert_never_connected(&listener);
    }

    #[test]
    fn every_key_outside_the_grammar_is_refused_without_a_connection() {
        for key in [
            OsString::from(""),
            OsString::from("x".repeat(MAX_RUN_SUBMISSION_KEY_BYTES + 1)),
            OsString::from("operator:cli\n1"),
            OsString::from("operator:cli\u{0}1"),
        ] {
            let runtime = runtime_root();
            let listener = listener(&runtime);

            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let exit = run(
                Some(runtime.path().as_os_str()),
                key.clone(),
                &mut b"document".as_slice(),
                &mut stdout,
                &mut stderr,
            );

            assert_eq!(exit, 2, "key {key:?} was not refused");
            assert!(stdout.is_empty());
            assert_eq!(
                stderr,
                b"automonique run refused: invalid_idempotency_key\n"
            );
            assert_never_connected(&listener);
        }
    }

    #[test]
    fn a_key_at_the_ceiling_is_carried_rather_than_refused() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| accepted(request, false));
        let key = "k".repeat(MAX_RUN_SUBMISSION_KEY_BYTES);

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run(
            Some(runtime.path().as_os_str()),
            OsString::from(&key),
            &mut b"document".as_slice(),
            &mut stdout,
            &mut stderr,
        );

        let observed = server
            .join()
            .expect("server")
            .expect("the client never connected");
        assert_eq!(observed.idempotency_key, key);
        assert_eq!(exit, 0);
        assert!(stderr.is_empty());
    }

    #[test]
    fn a_daemon_refusal_reaches_stderr_and_never_stdout() {
        let runtime = runtime_root();
        let server = std::thread::spawn({
            let listener = listener(&runtime);
            move || {
                let mut stream = accept_deadlined(&listener).expect("the client never connected");
                let mut prefix = [0_u8; 4];
                stream.read_exact(&mut prefix).expect("request prefix");
                let mut body = vec![0_u8; u32::from_be_bytes(prefix) as usize];
                stream.read_exact(&mut body).expect("request body");
                let request = AdminRequest::from_canonical_bytes(&body).expect("typed request");
                let response = AdminResponse::Refused {
                    request_id: request.request_id().clone(),
                    category: AdminRefusalCategory::new("run_spec_undecodable").expect("category"),
                }
                .to_message()
                .expect("response")
                .to_canonical_bytes();
                let mut frame = Vec::new();
                encode_frame(&response, &mut frame).expect("frame");
                stream.write_all(&frame).expect("write");
            }
        });

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run(
            Some(runtime.path().as_os_str()),
            OsString::from("operator:cli:refused"),
            &mut b"not a run spec".as_slice(),
            &mut stdout,
            &mut stderr,
        );

        // This server panics inside its own deadline when nothing connects, so
        // joining it is already the assertion that the client arrived.
        server.join().expect("server");
        assert_eq!(exit, 1);
        assert!(stdout.is_empty(), "a refusal must not reach stdout");
        assert_eq!(stderr, b"automonique run refused: run_spec_undecodable\n");
    }

    #[test]
    fn an_answer_for_another_command_is_not_read_as_custody() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| {
            AdminResponse::SyntheticAccepted {
                request_id: request.request_id().clone(),
                inbox_id: 9,
                duplicate: false,
            }
        });

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run(
            Some(runtime.path().as_os_str()),
            OsString::from("operator:cli:mismatch"),
            &mut b"document".as_slice(),
            &mut stdout,
            &mut stderr,
        );

        server.join().expect("server");
        assert_eq!(exit, 1);
        assert!(stdout.is_empty());
        assert_eq!(stderr, b"automonique run refused: response_mismatch\n");
    }

    #[test]
    fn an_unavailable_runtime_is_reported_rather_than_guessed() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run(
            None,
            OsString::from("operator:cli:noruntime"),
            &mut b"document".as_slice(),
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit, 1);
        assert!(stdout.is_empty());
        assert_eq!(stderr, b"automonique run refused: runtime_unavailable\n");
    }
}
