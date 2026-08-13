// SPDX-License-Identifier: Elastic-2.0

//! Operator reads on the native Runs API.
//!
//! `runs list` and `runs detail` are reads and nothing else: they take no
//! custody, schedule nothing, and change no durable state. They travel under
//! the Runs protocol rather than as administration commands — the daemon places
//! a frame by the protocol its envelope declares — so nothing here widens the
//! admin lane's closed command set.
//!
//! The discipline mirrors the other verbs:
//!
//! - **Arguments are judged before the connection.** A misspelled state word or
//!   a page size outside the protocol's range is an operator mistake to report,
//!   not a frame to spend. Nothing is clamped into range: an operator who asked
//!   for a page of two hundred is told so rather than quietly served sixty-four,
//!   because a silently shortened page is indistinguishable from a short one.
//! - **Only a matching answer is rendered.** A listing answered with a detail
//!   view is a mismatch, not something to print. Stdout stays empty unless the
//!   daemon answered the question that was asked.
//! - **Every rendered byte came out of the protocol's own decoder**, which
//!   validated each identifier against its grammar and each state, coverage and
//!   refusal word against a closed vocabulary. No daemon-supplied byte is
//!   written through unchecked.
//!
//! A `resync_required` answer is reported on stderr with the window a fresh
//! listing must cover, and stdout stays empty. It is not a refusal — the daemon
//! answered exactly, and correctly — but it is not the page the operator asked
//! for either, and printing an empty page for it would say the log is empty.

use std::ffi::{OsStr, OsString};
use std::io::Write;

use automonique_protocol::runs_api::{
    ListRuns, PageSize, RunCursor, RunState, RunStateFilter, RunSummary, RunsRequest, RunsResponse,
};
use automonique_protocol::tools::RunId;

use crate::admin_client;

/// One read on the Runs API, as argv named it.
#[derive(Clone)]
pub(crate) enum Operation {
    /// One bounded page of runs, filtered and paged by the remaining words.
    List { flags: Vec<OsString> },
    /// One run in full.
    Detail { run_id: OsString },
}

/// Why one Runs read produced no output.
enum RunsError {
    /// An operator-supplied argument is outside its grammar. Nothing was
    /// connected to or sent.
    Field(&'static str),
    /// The daemon, its transport or its socket answered something other than
    /// the page that was asked for.
    Endpoint(String),
}

impl RunsError {
    fn category(&self) -> &str {
        match self {
            Self::Field(category) => category,
            Self::Endpoint(category) => category,
        }
    }

    /// Usage-shaped failures exit 2 like the rest of this CLI; everything the
    /// transport or the daemon decided exits 1.
    const fn exit_code(&self) -> u8 {
        match self {
            Self::Field(_) => 2,
            Self::Endpoint(_) => 1,
        }
    }
}

/// Answer one Runs read, writing rendered output only on success.
pub(crate) fn run<W: Write, E: Write>(
    operation: &Operation,
    runtime: Option<&OsStr>,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let request = match operation {
        Operation::List { flags } => list_request(flags),
        Operation::Detail { run_id } => detail_request(run_id),
    };
    let rendered = request.and_then(|request| {
        let response = admin_client::runs_request(runtime, &request)
            .map_err(|error| RunsError::Endpoint(error.category().to_owned()))?;
        render(&request, response)
    });
    match rendered {
        Ok(text) => {
            if stdout.write_all(text.as_bytes()).is_err() {
                return 1;
            }
            0
        }
        Err(error) => {
            let _ = writeln!(stderr, "automonique runs refused: {}", error.category());
            error.exit_code()
        }
    }
}

/// Render the answer to the question that was asked, and nothing else.
///
/// The pairing is exact: a listing answered with a detail view, or a detail
/// answered with a resync, is a mismatch rather than something to render.
fn render(request: &RunsRequest, response: RunsResponse) -> Result<String, RunsError> {
    match (request, response) {
        (RunsRequest::ListRuns { .. }, RunsResponse::RunList { page, .. }) => {
            let mut rendered = format!(
                "Automonique runs: count={} more={} next_cursor={}\n",
                page.runs().len(),
                page.continuation().has_more(),
                page.continuation()
                    .cursor()
                    .map_or_else(|| "-".to_owned(), |cursor| cursor.position().to_string()),
            );
            for summary in page.runs() {
                rendered.push_str(&render_summary(summary));
                rendered.push('\n');
            }
            Ok(rendered)
        }
        (RunsRequest::RunDetail { .. }, RunsResponse::RunDetail { view, .. }) => Ok(format!(
            "Automonique run: {} last_sequence={} coverage={} lifecycle_events={} resume_cursor={}\n",
            render_summary(view.summary()),
            view.last_sequence(),
            view.coverage(),
            view.lifecycle().len(),
            view.resume_cursor()
                .map_or_else(|| "-".to_owned(), |cursor| cursor.to_string()),
        )),
        (
            RunsRequest::ListRuns { .. },
            RunsResponse::Resync {
                snapshot_from,
                snapshot_to,
                ..
            },
        ) => Err(RunsError::Endpoint(format!(
            "resync_required snapshot_from={snapshot_from} snapshot_to={snapshot_to}"
        ))),
        _ => Err(RunsError::Endpoint("response_mismatch".to_owned())),
    }
}

fn render_summary(summary: &RunSummary) -> String {
    format!(
        "run_id={} submission_id={} state={} submission_state={} accepted_at_ms={} spec_digest={}",
        summary.run_id().as_str(),
        summary.submission_id(),
        summary.state(),
        summary.submission_state(),
        summary.accepted_at().as_millis(),
        summary.spec_digest(),
    )
}

/// Judge `runs list` arguments and build the request they name.
///
/// Every bound is the protocol's own: the state words are its closed
/// vocabulary, the page size is its `PageSize`, and a repeated state is its
/// refusal.
fn list_request(flags: &[OsString]) -> Result<RunsRequest, RunsError> {
    let mut states: Vec<RunState> = Vec::new();
    let mut cursor: Option<u64> = None;
    let mut page_size: Option<usize> = None;
    let mut flags = flags.iter();
    while let Some(flag) = flags.next() {
        match flag.to_str() {
            Some("--state") => {
                let spelling = flag_value(&mut flags).ok_or(RunsError::Field("invalid_state"))?;
                states.push(
                    RunState::from_spelling(spelling).ok_or(RunsError::Field("invalid_state"))?,
                );
            }
            Some("--cursor") => {
                if cursor.is_some() {
                    return Err(RunsError::Field("repeated_flag"));
                }
                cursor = Some(
                    flag_value(&mut flags)
                        .and_then(|value| value.parse::<u64>().ok())
                        .ok_or(RunsError::Field("invalid_cursor"))?,
                );
            }
            Some("--page") => {
                if page_size.is_some() {
                    return Err(RunsError::Field("repeated_flag"));
                }
                page_size = Some(
                    flag_value(&mut flags)
                        .and_then(|value| value.parse::<usize>().ok())
                        .ok_or(RunsError::Field("invalid_page"))?,
                );
            }
            _ => return Err(RunsError::Field("invalid_flag")),
        }
    }
    let states = if states.is_empty() {
        RunStateFilter::any()
    } else {
        RunStateFilter::only(states).map_err(|_| RunsError::Field("invalid_state_filter"))?
    };
    let page_size = match page_size {
        Some(size) => PageSize::new(size).map_err(|_| RunsError::Field("invalid_page"))?,
        None => PageSize::MAX,
    };
    Ok(RunsRequest::ListRuns {
        request_id: admin_client::correlation("runs-list")
            .map_err(|_| RunsError::Field("invalid_request_id"))?,
        query: ListRuns::new(states, cursor.map(RunCursor::new), page_size),
    })
}

/// The word after a flag, when there is one and it is text.
///
/// A flag whose value is missing or is not UTF-8 yields nothing, and every
/// caller turns that into a refusal naming the flag rather than reading the
/// next flag as its value.
fn flag_value<'a, I: Iterator<Item = &'a OsString>>(flags: &mut I) -> Option<&'a str> {
    flags.next().and_then(|value| value.to_str())
}

/// Judge a `runs detail` argument and build the request it names.
fn detail_request(run_id: &OsStr) -> Result<RunsRequest, RunsError> {
    let run_id = run_id.to_str().ok_or(RunsError::Field("invalid_run_id"))?;
    Ok(RunsRequest::RunDetail {
        request_id: admin_client::correlation("runs-detail")
            .map_err(|_| RunsError::Field("invalid_request_id"))?,
        run_id: RunId::new(run_id).map_err(|_| RunsError::Field("invalid_run_id"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Read;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};

    use automonique_protocol::codec::{RequestId, encode_frame};
    use automonique_protocol::digest::{Sha256, Sha256Digest};
    use automonique_protocol::journal::CursorResume;
    use automonique_protocol::primitives::EpochMillis;
    use automonique_protocol::runs_api::{
        Continuation, LifecycleCoverage, RunDetailView, RunListPage, RunsRefusal, SubmissionState,
    };
    use automonique_protocol::tools::MAX_TOOL_FIELD_BYTES;

    /// A private runtime root holding a private `automonique/` directory, which
    /// is what the client insists on before it will connect.
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

    /// How long a fake server waits for the client before giving up.
    ///
    /// Every wait here is deadlined: a client that is *supposed* to connect but
    /// does not must fail its test rather than wedge the suite.
    const SERVER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

    fn accept_deadlined(listener: &UnixListener) -> Option<UnixStream> {
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

    /// Serve exactly one Runs request with the real codec, answering with
    /// whatever `answer` builds from the decoded request.
    ///
    /// The request is decoded by the protocol's own decoder, so a client that
    /// sent an admin frame, an unframed payload or a body this protocol does
    /// not define fails here rather than being quietly accommodated.
    fn serve_once(
        listener: UnixListener,
        answer: impl FnOnce(&RunsRequest) -> RunsResponse + Send + 'static,
    ) -> std::thread::JoinHandle<Option<RunsRequest>> {
        std::thread::spawn(move || {
            let mut stream = accept_deadlined(&listener)?;
            let mut prefix = [0_u8; 4];
            stream.read_exact(&mut prefix).expect("request prefix");
            let mut body = vec![0_u8; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut body).expect("request body");
            let request = RunsRequest::from_canonical_bytes(&body).expect("typed runs request");
            let response = answer(&request)
                .to_message()
                .expect("response")
                .to_canonical_bytes();
            let mut frame = Vec::new();
            encode_frame(&response, &mut frame).expect("frame");
            stream.write_all(&frame).expect("write");
            Some(request)
        })
    }

    /// A listener that never accepted anything has nothing queued on it.
    fn assert_never_connected(listener: &UnixListener) {
        listener.set_nonblocking(true).expect("non-blocking");
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "the client connected to the daemon before it had judged its arguments",
        );
    }

    fn digest() -> Sha256Digest {
        Sha256::digest(b"a run specification document")
    }

    fn summary(run: &str, submission_id: u64, state: RunState) -> RunSummary {
        RunSummary::new(
            RunId::new(run).expect("run identity"),
            submission_id,
            digest(),
            state,
            SubmissionState::Accepted,
            EpochMillis::from_millis(1_700_000_000_000),
        )
        .expect("summary")
    }

    fn invoke(runtime: &tempfile::TempDir, operation: &Operation) -> (u8, String, String) {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run(
            operation,
            Some(runtime.path().as_os_str()),
            &mut stdout,
            &mut stderr,
        );
        (
            exit,
            String::from_utf8(stdout).expect("utf-8 stdout"),
            String::from_utf8(stderr).expect("utf-8 stderr"),
        )
    }

    fn list(flags: &[&str]) -> Operation {
        Operation::List {
            flags: flags.iter().map(OsString::from).collect(),
        }
    }

    #[test]
    fn a_listing_renders_every_summary_field_the_daemon_reported() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| RunsResponse::RunList {
            request_id: request.request_id().clone(),
            page: RunListPage::new(
                vec![
                    summary("run-1", 1, RunState::Ready),
                    summary("run-2", 2, RunState::Running),
                ],
                Continuation::More(RunCursor::new(3)),
            )
            .expect("page"),
        });

        let (exit, stdout, stderr) = invoke(&runtime, &list(&[]));
        assert_eq!(exit, 0, "stderr: {stderr}");
        assert!(stderr.is_empty());
        assert_eq!(
            stdout,
            format!(
                "Automonique runs: count=2 more=true next_cursor=3\n\
                 run_id=run-1 submission_id=1 state=ready submission_state=accepted accepted_at_ms=1700000000000 spec_digest={digest}\n\
                 run_id=run-2 submission_id=2 state=running submission_state=accepted accepted_at_ms=1700000000000 spec_digest={digest}\n",
                digest = digest(),
            ),
        );

        // The query the daemon received is the one argv named, defaulted where
        // argv said nothing.
        let RunsRequest::ListRuns { query, .. } = server.join().expect("server").expect("served")
        else {
            panic!("the client sent a detail request for a listing")
        };
        assert_eq!(query.states().states(), None);
        assert_eq!(query.since(), None);
        assert_eq!(query.page_size(), PageSize::MAX);
    }

    #[test]
    fn every_flag_reaches_the_query_the_daemon_receives() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| RunsResponse::RunList {
            request_id: request.request_id().clone(),
            page: RunListPage::new(Vec::new(), Continuation::Complete).expect("page"),
        });

        let (exit, stdout, _) = invoke(
            &runtime,
            &list(&[
                "--state", "failed", "--state", "ready", "--cursor", "9", "--page", "3",
            ]),
        );
        assert_eq!(exit, 0);
        assert_eq!(
            stdout,
            "Automonique runs: count=0 more=false next_cursor=-\n"
        );

        let RunsRequest::ListRuns { query, .. } = server.join().expect("server").expect("served")
        else {
            panic!("the client sent a detail request for a listing")
        };
        // Repeated `--state` accumulates, and the protocol sorts the set into
        // its own declaration order, so the wire form does not depend on the
        // order an operator typed.
        assert_eq!(
            query.states().states(),
            Some([RunState::Ready, RunState::Failed].as_slice()),
        );
        assert_eq!(query.since().map(RunCursor::position), Some(9));
        assert_eq!(query.page_size().get(), 3);
    }

    #[test]
    fn a_detail_view_renders_its_lifecycle_statement() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| RunsResponse::RunDetail {
            request_id: request.request_id().clone(),
            view: RunDetailView::new(
                summary("run-1", 4, RunState::Ready),
                0,
                Vec::new(),
                LifecycleCoverage::Complete,
            )
            .expect("view"),
        });

        let (exit, stdout, stderr) = invoke(
            &runtime,
            &Operation::Detail {
                run_id: OsString::from("run-1"),
            },
        );
        assert_eq!(exit, 0, "stderr: {stderr}");
        assert_eq!(
            stdout,
            format!(
                "Automonique run: run_id=run-1 submission_id=4 state=ready submission_state=accepted accepted_at_ms=1700000000000 spec_digest={} last_sequence=0 coverage=complete lifecycle_events=0 resume_cursor=-\n",
                digest(),
            ),
        );

        let RunsRequest::RunDetail { run_id, .. } = server.join().expect("server").expect("served")
        else {
            panic!("the client sent a listing for a detail request")
        };
        assert_eq!(run_id.as_str(), "run-1");
    }

    #[test]
    fn a_refusal_and_a_resync_both_keep_stdout_empty() {
        for (answer, expected) in [
            (
                Box::new(|request: &RunsRequest| RunsResponse::Refused {
                    request_id: request.request_id().clone(),
                    refusal: RunsRefusal::UnknownRun,
                }) as Box<dyn FnOnce(&RunsRequest) -> RunsResponse + Send>,
                "automonique runs refused: unknown_run\n",
            ),
            (
                Box::new(|request: &RunsRequest| {
                    RunsResponse::listing(
                        request.request_id().clone(),
                        match request {
                            RunsRequest::ListRuns { query, .. } => query,
                            RunsRequest::RunDetail { .. } => panic!("a listing was expected"),
                        },
                        CursorResume::ResyncRequired {
                            snapshot_from: 4,
                            snapshot_to: 9,
                        },
                        None,
                    )
                    .expect("resync")
                }),
                "automonique runs refused: resync_required snapshot_from=4 snapshot_to=9\n",
            ),
        ] {
            let runtime = runtime_root();
            let server = serve_once(listener(&runtime), answer);
            let (exit, stdout, stderr) = invoke(&runtime, &list(&["--cursor", "1"]));
            assert_eq!(exit, 1);
            assert!(stdout.is_empty(), "a failed read wrote {stdout:?}");
            assert_eq!(stderr, expected);
            server.join().expect("server").expect("served");
        }
    }

    #[test]
    fn an_answer_to_a_different_question_is_not_rendered() {
        // The daemon answers a listing with a detail view. Both are well-formed
        // Runs messages, so only the pairing can catch it — and it must, or a
        // pipeline would read a run it never asked about.
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| RunsResponse::RunDetail {
            request_id: request.request_id().clone(),
            view: RunDetailView::new(
                summary("run-1", 4, RunState::Ready),
                0,
                Vec::new(),
                LifecycleCoverage::Complete,
            )
            .expect("view"),
        });
        let (exit, stdout, stderr) = invoke(&runtime, &list(&[]));
        assert_eq!(exit, 1);
        assert!(stdout.is_empty());
        assert_eq!(stderr, "automonique runs refused: response_mismatch\n");
        server.join().expect("server").expect("served");
    }

    #[test]
    fn an_uncorrelated_answer_is_refused_rather_than_rendered() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |_| RunsResponse::RunList {
            request_id: RequestId::new("somebody-elses-question").expect("request ID"),
            page: RunListPage::new(
                vec![summary("run-1", 1, RunState::Ready)],
                Continuation::Complete,
            )
            .expect("page"),
        });
        let (exit, stdout, stderr) = invoke(&runtime, &list(&[]));
        assert_eq!(exit, 1);
        assert!(stdout.is_empty());
        assert_eq!(stderr, "automonique runs refused: request_id_mismatch\n");
        server.join().expect("server").expect("served");
    }

    #[test]
    fn arguments_outside_their_grammar_are_refused_before_any_connection() {
        for (operation, expected) in [
            (list(&["--state", "sleeping"]), "invalid_state"),
            (list(&["--state"]), "invalid_state"),
            (
                list(&["--state", "ready", "--state", "ready"]),
                "invalid_state_filter",
            ),
            (list(&["--cursor", "-1"]), "invalid_cursor"),
            (list(&["--cursor", "many"]), "invalid_cursor"),
            (list(&["--cursor", "1", "--cursor", "2"]), "repeated_flag"),
            (list(&["--page", "0"]), "invalid_page"),
            (list(&["--page", "65"]), "invalid_page"),
            (list(&["--page", "1", "--page", "2"]), "repeated_flag"),
            (list(&["--since", "1"]), "invalid_flag"),
            (list(&["ready"]), "invalid_flag"),
            (
                Operation::Detail {
                    run_id: OsString::new(),
                },
                "invalid_run_id",
            ),
            (
                Operation::Detail {
                    run_id: OsString::from("run\n1"),
                },
                "invalid_run_id",
            ),
            (
                Operation::Detail {
                    run_id: OsString::from("r".repeat(MAX_TOOL_FIELD_BYTES + 1)),
                },
                "invalid_run_id",
            ),
            (
                // Argv is bytes, not text. A run identity that is not UTF-8
                // cannot be a protocol identifier, and is refused rather than
                // lossily converted into one that is.
                Operation::Detail {
                    run_id: OsString::from_vec(vec![b'r', 0xff]),
                },
                "invalid_run_id",
            ),
        ] {
            let runtime = runtime_root();
            let listener = listener(&runtime);
            let (exit, stdout, stderr) = invoke(&runtime, &operation);
            assert_eq!(exit, 2, "{expected} did not exit 2");
            assert!(stdout.is_empty());
            assert_eq!(stderr, format!("automonique runs refused: {expected}\n"));
            assert_never_connected(&listener);
        }
    }

    #[test]
    fn a_page_size_is_reported_rather_than_clamped_into_range() {
        // `--page 200` is above the protocol ceiling. Serving sixty-four
        // instead would look identical to a log that held sixty-four runs.
        let runtime = runtime_root();
        let listener = listener(&runtime);
        let (exit, stdout, stderr) = invoke(&runtime, &list(&["--page", "200"]));
        assert_eq!(exit, 2);
        assert!(stdout.is_empty());
        assert_eq!(stderr, "automonique runs refused: invalid_page\n");
        assert_never_connected(&listener);

        // The ceiling itself is admitted, so the refusal above is a bound and
        // not an off-by-one.
        let server = serve_once(listener, |request| RunsResponse::RunList {
            request_id: request.request_id().clone(),
            page: RunListPage::new(Vec::new(), Continuation::Complete).expect("page"),
        });
        let (exit, _, _) = invoke(&runtime, &list(&["--page", "64"]));
        assert_eq!(exit, 0);
        server.join().expect("server").expect("served");
    }

    #[test]
    fn an_unavailable_runtime_is_reported_and_never_guessed_at() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run(&list(&[]), None, &mut stdout, &mut stderr);
        assert_eq!(exit, 1);
        assert!(stdout.is_empty());
        assert_eq!(stderr, b"automonique runs refused: runtime_unavailable\n");
    }
}
