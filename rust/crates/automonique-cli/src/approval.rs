// SPDX-License-Identifier: Elastic-2.0

//! Operator recording of approval decisions.
//!
//! `approval record` writes one durable row; `list`, `detail` and `by-subject`
//! read them back. They travel under the Approval protocol rather than as
//! administration commands — the daemon places a frame by the protocol its
//! envelope declares — so nothing here widens the admin lane's closed command
//! set.
//!
//! # What these verbs actually do
//!
//! **They write down that somebody answered an approval question, and nothing
//! else.** There is no gate in this build that reads the answer:
//!
//! - `record granted` permits nothing that was not already permitted;
//! - `record denied` blocks nothing, because nothing consults the row before
//!   acting; and
//! - the decider is a name the daemon records verbatim, never a credential it
//!   checks. The local socket's peer check is the authentication.
//!
//! An accepted write is reported as `accepted` rather than `done` for exactly
//! that reason: the row is committed and survives a restart, and the decision it
//! records has nowhere to take effect yet.
//!
//! # There is no `amend` and no `revoke`
//!
//! The ledger is write-once, so this verb set is too. Reversing a decision is a
//! `record` under a **new** key naming the same subject, and `by-subject` then
//! shows both in the order they were made. Which of them governs is not
//! something this CLI will tell you, because it is not something the ledger
//! knows.
//!
//! # The discipline, mirroring the other verbs
//!
//! - **Arguments are judged before the connection.** A misspelled decision word,
//!   a non-numeric cursor or a page size outside the protocol's range is an
//!   operator mistake to report, not a frame to spend. Nothing is clamped.
//! - **Only a matching answer is rendered.** A listing answered with a detail
//!   record is a mismatch, not something to print.
//! - **Every rendered byte came out of the protocol's own decoder**, which
//!   validated each identifier against its grammar and each decision,
//!   disposition and refusal word against a closed vocabulary.
//!
//! An `approval_conflict` answer is reported on stderr with the coordinates the
//! durable row records, and stdout stays empty. It is not a refusal — the
//! request was well-formed — but it is not the write the operator asked for
//! either, and unlike a revision conflict it must not be retried: the key is
//! spoken for permanently.

use std::ffi::{OsStr, OsString};
use std::io::Write;

use automonique_protocol::approval_api::{
    ApprovalCursor, ApprovalKey, ApprovalPageSize, ApprovalRecordView, ApprovalRequest,
    ApprovalResponse, ApprovalSubject, ApprovalsBySubject, Decider, ListApprovals, RecordApproval,
    decode_decision,
};

use crate::admin_client;

/// One approval operation, as argv named it.
#[derive(Clone)]
pub(crate) enum Operation {
    /// Record one decision, write-once.
    Record {
        /// The idempotency identity.
        approval_key: OsString,
        /// What was decided.
        subject: OsString,
        /// `granted` or `denied`.
        decision: OsString,
        /// Who answered.
        decider: OsString,
    },
    /// One bounded page of every decision, paged by the flags.
    List {
        /// The remaining argument words.
        flags: Vec<OsString>,
    },
    /// One decision in full.
    Detail {
        /// The idempotency identity.
        approval_key: OsString,
    },
    /// One bounded page of one subject's decisions, paged by the flags.
    BySubject {
        /// The subject.
        subject: OsString,
        /// The remaining argument words.
        flags: Vec<OsString>,
    },
}

/// Why one approval operation produced no output.
enum ApprovalCliError {
    /// An operator-supplied argument is outside its grammar. Nothing was
    /// connected to or sent.
    Field(&'static str),
    /// The daemon, its transport or its socket answered something other than
    /// the write or the page that was asked for.
    Endpoint(String),
}

impl ApprovalCliError {
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

/// Answer one approval operation, writing rendered output only on success.
pub(crate) fn run<W: Write, E: Write>(
    operation: &Operation,
    runtime: Option<&OsStr>,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let rendered = build(operation).and_then(|request| {
        let response = admin_client::approval_request(runtime, &request)
            .map_err(|error| ApprovalCliError::Endpoint(error.category().to_owned()))?;
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
            let _ = writeln!(stderr, "automonique approval refused: {}", error.category());
            error.exit_code()
        }
    }
}

/// Judge one operation's arguments and build the request they name.
fn build(operation: &Operation) -> Result<ApprovalRequest, ApprovalCliError> {
    match operation {
        Operation::Record {
            approval_key,
            subject,
            decision,
            decider,
        } => Ok(ApprovalRequest::RecordApproval {
            request_id: correlation("record")?,
            decision: RecordApproval::new(
                key(approval_key)?,
                about(subject)?,
                answer(decision)?,
                who(decider)?,
            ),
        }),
        Operation::List { flags } => {
            let (cursor, page_size) = paging(flags)?;
            Ok(ApprovalRequest::ListApprovals {
                request_id: correlation("list")?,
                query: ListApprovals::new(cursor, page_size),
            })
        }
        Operation::Detail { approval_key } => Ok(ApprovalRequest::ApprovalDetail {
            request_id: correlation("detail")?,
            approval_key: key(approval_key)?,
        }),
        Operation::BySubject { subject, flags } => {
            let subject = about(subject)?;
            let (cursor, page_size) = paging(flags)?;
            Ok(ApprovalRequest::ApprovalsBySubject {
                request_id: correlation("by-subject")?,
                query: ApprovalsBySubject::new(subject, cursor, page_size),
            })
        }
    }
}

/// Judge the paging flags both listings share.
///
/// One reader for both verbs, so `list` and `by-subject` cannot disagree about
/// what `--page 0` means.
fn paging(flags: &[OsString]) -> Result<(ApprovalCursor, ApprovalPageSize), ApprovalCliError> {
    let mut cursor: Option<u64> = None;
    let mut page_size: Option<usize> = None;
    let mut flags = flags.iter();
    while let Some(flag) = flags.next() {
        match flag.to_str() {
            Some("--cursor") => {
                if cursor.is_some() {
                    return Err(ApprovalCliError::Field("repeated_flag"));
                }
                cursor = Some(
                    flag_value(&mut flags)
                        .and_then(|value| value.parse::<u64>().ok())
                        .ok_or(ApprovalCliError::Field("invalid_cursor"))?,
                );
            }
            Some("--page") => {
                if page_size.is_some() {
                    return Err(ApprovalCliError::Field("repeated_flag"));
                }
                page_size = Some(
                    flag_value(&mut flags)
                        .and_then(|value| value.parse::<usize>().ok())
                        .ok_or(ApprovalCliError::Field("invalid_page"))?,
                );
            }
            _ => return Err(ApprovalCliError::Field("invalid_flag")),
        }
    }
    let page_size = match page_size {
        Some(size) => {
            ApprovalPageSize::new(size).map_err(|_| ApprovalCliError::Field("invalid_page"))?
        }
        None => ApprovalPageSize::MAX,
    };
    Ok((
        cursor.map_or(ApprovalCursor::START, ApprovalCursor::new),
        page_size,
    ))
}

/// Render the answer to the question that was asked, and nothing else.
///
/// The pairing is exact: a listing answered with a detail record, or a recording
/// answered with a page, is a mismatch rather than something to render.
fn render(
    request: &ApprovalRequest,
    response: ApprovalResponse,
) -> Result<String, ApprovalCliError> {
    match (request, response) {
        (ApprovalRequest::RecordApproval { .. }, ApprovalResponse::Recorded { receipt, .. }) => {
            Ok(format!(
                "Automonique approval accepted: approval_key={} entry_id={} decision={} disposition={} decided_at_ms={}\n",
                receipt.approval_key(),
                receipt.entry_id(),
                receipt.decision().as_str(),
                receipt.disposition().as_str(),
                receipt.decided_at().as_millis(),
            ))
        }
        (
            ApprovalRequest::ListApprovals { .. } | ApprovalRequest::ApprovalsBySubject { .. },
            ApprovalResponse::ApprovalList { page, .. },
        ) => {
            let mut rendered = format!(
                "Automonique approvals: count={} more={} next_cursor={}\n",
                page.entries().len(),
                page.continuation().has_more(),
                page.continuation()
                    .cursor()
                    .map_or_else(|| "-".to_owned(), |cursor| cursor.position().to_string()),
            );
            for record in page.entries() {
                rendered.push_str(&render_record(record));
                rendered.push('\n');
            }
            Ok(rendered)
        }
        (
            ApprovalRequest::ApprovalDetail { .. },
            ApprovalResponse::ApprovalDetail { record, .. },
        ) => Ok(format!(
            "Automonique approval: {}\n",
            render_record(&record)
        )),
        (
            ApprovalRequest::RecordApproval { .. },
            ApprovalResponse::Conflict {
                field, recorded, ..
            },
        ) => Err(ApprovalCliError::Endpoint(format!(
            "approval_conflict field={field} entry_id={} recorded_subject={} recorded_decision={} recorded_decider={}",
            recorded.entry_id, recorded.subject, recorded.decision, recorded.decider,
        ))),
        _ => Err(ApprovalCliError::Endpoint("response_mismatch".to_owned())),
    }
}

/// One record, every column the daemon reported.
///
/// `revision` is printed because it is the visible half of the write-once
/// promise: the protocol's decoder refuses anything but one, so a rendered `1`
/// is evidence that the row was never amended rather than a constant this
/// function typed out.
fn render_record(record: &ApprovalRecordView) -> String {
    format!(
        "approval_key={} entry_id={} subject={} decision={} decider={} decided_at_ms={} revision={}",
        record.approval_key(),
        record.entry_id(),
        record.subject(),
        record.decision().as_str(),
        record.decider(),
        record.decided_at().as_millis(),
        record.revision(),
    )
}

fn correlation(
    operation: &str,
) -> Result<automonique_protocol::codec::RequestId, ApprovalCliError> {
    admin_client::correlation(&format!("approval-{operation}"))
        .map_err(|_| ApprovalCliError::Field("invalid_request_id"))
}

fn key(value: &OsStr) -> Result<ApprovalKey, ApprovalCliError> {
    value
        .to_str()
        .and_then(|value| ApprovalKey::new(value).ok())
        .ok_or(ApprovalCliError::Field("invalid_approval_key"))
}

fn about(value: &OsStr) -> Result<ApprovalSubject, ApprovalCliError> {
    value
        .to_str()
        .and_then(|value| ApprovalSubject::new(value).ok())
        .ok_or(ApprovalCliError::Field("invalid_subject"))
}

fn who(value: &OsStr) -> Result<Decider, ApprovalCliError> {
    value
        .to_str()
        .and_then(|value| Decider::new(value).ok())
        .ok_or(ApprovalCliError::Field("invalid_decider"))
}

/// The decision word, judged by the protocol's own closed vocabulary.
///
/// Not a local match on two strings: `decode_decision` is the same fail-closed
/// decoder a frame is judged by, so an operator's word and a wire value cannot
/// be admitted by different rules.
fn answer(
    value: &OsStr,
) -> Result<automonique_protocol::approval_api::ApprovalDecision, ApprovalCliError> {
    value
        .to_str()
        .and_then(|value| decode_decision(value).ok())
        .ok_or(ApprovalCliError::Field("invalid_decision"))
}

/// The word after a flag, when there is one and it is text.
fn flag_value<'a, I: Iterator<Item = &'a OsString>>(flags: &mut I) -> Option<&'a str> {
    flags.next().and_then(|value| value.to_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Read;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};

    use automonique_protocol::approval_api::{
        ApprovalContinuation, ApprovalDecision, ApprovalDisposition, ApprovalListPage,
        ApprovalReceiptView, ApprovalRecordParts, ApprovalRefusal, MAX_APPROVAL_API_FIELD_BYTES,
        RecordedApproval,
    };
    use automonique_protocol::codec::{RequestId, encode_frame};
    use automonique_protocol::primitives::EpochMillis;

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

    /// Serve exactly one Approval request with the real codec.
    ///
    /// The request is decoded by the protocol's own decoder, so a client that
    /// sent an admin frame, an unframed payload or a body this protocol does not
    /// define fails here rather than being quietly accommodated.
    fn serve_once(
        listener: UnixListener,
        answer: impl FnOnce(&ApprovalRequest) -> ApprovalResponse + Send + 'static,
    ) -> std::thread::JoinHandle<Option<ApprovalRequest>> {
        std::thread::spawn(move || {
            let mut stream = accept_deadlined(&listener)?;
            let mut prefix = [0_u8; 4];
            stream.read_exact(&mut prefix).expect("request prefix");
            let mut body = vec![0_u8; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut body).expect("request body");
            let request =
                ApprovalRequest::from_canonical_bytes(&body).expect("typed approval request");
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

    fn recording(decision: &str) -> Operation {
        Operation::Record {
            approval_key: OsString::from("deploy-2026-08-13"),
            subject: OsString::from("command:shutdown"),
            decision: OsString::from(decision),
            decider: OsString::from("ben"),
        }
    }

    fn receipt(
        decision: ApprovalDecision,
        disposition: ApprovalDisposition,
    ) -> ApprovalReceiptView {
        ApprovalReceiptView::new(
            7,
            ApprovalKey::new("deploy-2026-08-13").expect("key"),
            decision,
            disposition,
            EpochMillis::from_millis(1_700_000_000_000),
        )
        .expect("receipt")
    }

    fn row(
        entry_id: u64,
        approval_key: &str,
        subject: &str,
        decision: ApprovalDecision,
        decider: &str,
    ) -> ApprovalRecordView {
        ApprovalRecordView::new(ApprovalRecordParts {
            entry_id,
            approval_key: ApprovalKey::new(approval_key).expect("key"),
            subject: ApprovalSubject::new(subject).expect("subject"),
            decision,
            decider: Decider::new(decider).expect("decider"),
            decided_at: EpochMillis::from_millis(1_700_000_001_000),
            revision: 1,
        })
        .expect("record")
    }

    #[test]
    fn a_recording_renders_the_receipt_the_daemon_returned() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| ApprovalResponse::Recorded {
            request_id: request.request_id().clone(),
            receipt: receipt(ApprovalDecision::Granted, ApprovalDisposition::Recorded),
        });

        let (exit, stdout, stderr) = invoke(&runtime, &recording("granted"));
        assert_eq!(exit, 0, "stderr: {stderr}");
        assert!(stderr.is_empty());
        assert_eq!(
            stdout,
            "Automonique approval accepted: approval_key=deploy-2026-08-13 entry_id=7 \
             decision=granted disposition=recorded decided_at_ms=1700000000000\n",
        );

        // The request the daemon received is the one argv named.
        let ApprovalRequest::RecordApproval { decision, .. } =
            server.join().expect("server").expect("served")
        else {
            panic!("the client sent something other than a recording")
        };
        assert_eq!(decision.approval_key().as_str(), "deploy-2026-08-13");
        assert_eq!(decision.subject().as_str(), "command:shutdown");
        assert_eq!(decision.decision(), ApprovalDecision::Granted);
        assert_eq!(decision.decider().as_str(), "ben");
    }

    #[test]
    fn a_replay_renders_its_disposition_rather_than_claiming_a_fresh_write() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| ApprovalResponse::Recorded {
            request_id: request.request_id().clone(),
            receipt: receipt(
                ApprovalDecision::Denied,
                ApprovalDisposition::AlreadyRecorded,
            ),
        });
        let (exit, stdout, stderr) = invoke(&runtime, &recording("denied"));
        assert_eq!(exit, 0, "stderr: {stderr}");
        assert!(
            stdout.contains("disposition=already_recorded"),
            "a replay was rendered as a fresh write: {stdout}",
        );
        assert!(stdout.contains("decision=denied"));
        server.join().expect("server").expect("served");
    }

    #[test]
    fn a_listing_renders_every_column_and_defaults_where_argv_said_nothing() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| {
            ApprovalResponse::ApprovalList {
                request_id: request.request_id().clone(),
                page: ApprovalListPage::new(
                    vec![
                        row(
                            1,
                            "deploy-1",
                            "command:shutdown",
                            ApprovalDecision::Granted,
                            "ben",
                        ),
                        row(
                            2,
                            "deploy-2",
                            "command:shutdown",
                            ApprovalDecision::Denied,
                            "dana",
                        ),
                    ],
                    ApprovalContinuation::More(ApprovalCursor::new(2)),
                )
                .expect("page"),
            }
        });

        let (exit, stdout, stderr) = invoke(&runtime, &list(&[]));
        assert_eq!(exit, 0, "stderr: {stderr}");
        assert_eq!(
            stdout,
            "Automonique approvals: count=2 more=true next_cursor=2\n\
             approval_key=deploy-1 entry_id=1 subject=command:shutdown decision=granted decider=ben decided_at_ms=1700000001000 revision=1\n\
             approval_key=deploy-2 entry_id=2 subject=command:shutdown decision=denied decider=dana decided_at_ms=1700000001000 revision=1\n",
        );

        let ApprovalRequest::ListApprovals { query, .. } =
            server.join().expect("server").expect("served")
        else {
            panic!("the client sent something other than a listing")
        };
        assert_eq!(query.since(), ApprovalCursor::START);
        assert_eq!(query.page_size(), ApprovalPageSize::MAX);
    }

    #[test]
    fn every_paging_flag_reaches_both_listings() {
        for build_operation in [
            (|flags: &[&str]| list(flags)) as fn(&[&str]) -> Operation,
            |flags: &[&str]| Operation::BySubject {
                subject: OsString::from("command:shutdown"),
                flags: flags.iter().map(OsString::from).collect(),
            },
        ] {
            let runtime = runtime_root();
            let server = serve_once(listener(&runtime), |request| {
                ApprovalResponse::ApprovalList {
                    request_id: request.request_id().clone(),
                    page: ApprovalListPage::new(Vec::new(), ApprovalContinuation::Complete)
                        .expect("page"),
                }
            });
            let (exit, stdout, stderr) = invoke(
                &runtime,
                &build_operation(&["--cursor", "9", "--page", "3"]),
            );
            assert_eq!(exit, 0, "stderr: {stderr}");
            assert_eq!(
                stdout,
                "Automonique approvals: count=0 more=false next_cursor=-\n"
            );
            let (since, page_size, subject) = match server.join().expect("server").expect("served")
            {
                ApprovalRequest::ListApprovals { query, .. } => {
                    (query.since(), query.page_size(), None)
                }
                ApprovalRequest::ApprovalsBySubject { query, .. } => (
                    query.since(),
                    query.page_size(),
                    Some(query.subject().as_str().to_owned()),
                ),
                other => panic!("the client sent {other:?}"),
            };
            assert_eq!(since, ApprovalCursor::new(9));
            assert_eq!(page_size.get(), 3);
            assert!(subject.is_none_or(|subject| subject == "command:shutdown"));
        }
    }

    #[test]
    fn a_detail_read_renders_the_record_it_asked_for() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| {
            ApprovalResponse::ApprovalDetail {
                request_id: request.request_id().clone(),
                record: row(
                    2,
                    "deploy-2",
                    "command:shutdown",
                    ApprovalDecision::Denied,
                    "dana",
                ),
            }
        });
        let (exit, stdout, stderr) = invoke(
            &runtime,
            &Operation::Detail {
                approval_key: OsString::from("deploy-2"),
            },
        );
        assert_eq!(exit, 0, "stderr: {stderr}");
        assert_eq!(
            stdout,
            "Automonique approval: approval_key=deploy-2 entry_id=2 subject=command:shutdown \
             decision=denied decider=dana decided_at_ms=1700000001000 revision=1\n",
        );
        let ApprovalRequest::ApprovalDetail { approval_key, .. } =
            server.join().expect("server").expect("served")
        else {
            panic!("the client sent something other than a detail read")
        };
        assert_eq!(approval_key.as_str(), "deploy-2");
    }

    #[test]
    fn a_refusal_and_a_conflict_both_keep_stdout_empty() {
        for (answer, expected) in [
            (
                Box::new(|request: &ApprovalRequest| ApprovalResponse::Refused {
                    request_id: request.request_id().clone(),
                    refusal: ApprovalRefusal::LedgerFull,
                }) as Box<dyn FnOnce(&ApprovalRequest) -> ApprovalResponse + Send>,
                "automonique approval refused: ledger_full\n",
            ),
            (
                Box::new(|request: &ApprovalRequest| {
                    let ApprovalRequest::RecordApproval { decision, .. } = request else {
                        panic!("the client sent something other than a recording")
                    };
                    ApprovalResponse::conflict(
                        request.request_id().clone(),
                        decision,
                        RecordedApproval {
                            entry_id: 4,
                            subject: ApprovalSubject::new("command:shutdown").expect("subject"),
                            decision: ApprovalDecision::Denied,
                            decider: Decider::new("dana").expect("decider"),
                        },
                    )
                    .expect("conflict")
                }),
                "automonique approval refused: approval_conflict field=decision entry_id=4 \
                 recorded_subject=command:shutdown recorded_decision=denied recorded_decider=dana\n",
            ),
        ] {
            let runtime = runtime_root();
            let server = serve_once(listener(&runtime), answer);
            let (exit, stdout, stderr) = invoke(&runtime, &recording("granted"));
            assert_eq!(exit, 1);
            assert!(stdout.is_empty(), "a failed write wrote {stdout:?}");
            assert_eq!(stderr, expected);
            server.join().expect("server").expect("served");
        }
    }

    #[test]
    fn an_answer_to_a_different_question_is_not_rendered() {
        // The daemon answers a listing with a detail record. Both are
        // well-formed Approval messages, so only the pairing can catch it.
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| {
            ApprovalResponse::ApprovalDetail {
                request_id: request.request_id().clone(),
                record: row(
                    1,
                    "deploy-1",
                    "command:shutdown",
                    ApprovalDecision::Granted,
                    "ben",
                ),
            }
        });
        let (exit, stdout, stderr) = invoke(&runtime, &list(&[]));
        assert_eq!(exit, 1);
        assert!(stdout.is_empty());
        assert_eq!(stderr, "automonique approval refused: response_mismatch\n");
        server.join().expect("server").expect("served");
    }

    #[test]
    fn an_uncorrelated_answer_is_refused_rather_than_rendered() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |_| ApprovalResponse::Recorded {
            request_id: RequestId::new("somebody-elses-question").expect("request ID"),
            receipt: receipt(ApprovalDecision::Granted, ApprovalDisposition::Recorded),
        });
        let (exit, stdout, stderr) = invoke(&runtime, &recording("granted"));
        assert_eq!(exit, 1);
        assert!(stdout.is_empty());
        assert_eq!(
            stderr,
            "automonique approval refused: request_id_mismatch\n"
        );
        server.join().expect("server").expect("served");
    }

    #[test]
    fn arguments_outside_their_grammar_are_refused_before_any_connection() {
        let over_long = "a".repeat(MAX_APPROVAL_API_FIELD_BYTES + 1);
        for (operation, expected) in [
            (
                Operation::Record {
                    approval_key: OsString::new(),
                    subject: OsString::from("command:shutdown"),
                    decision: OsString::from("granted"),
                    decider: OsString::from("ben"),
                },
                "invalid_approval_key",
            ),
            (
                Operation::Record {
                    approval_key: OsString::from("deploy\n1"),
                    subject: OsString::from("command:shutdown"),
                    decision: OsString::from("granted"),
                    decider: OsString::from("ben"),
                },
                "invalid_approval_key",
            ),
            (
                Operation::Record {
                    approval_key: OsString::from(over_long.clone()),
                    subject: OsString::from("command:shutdown"),
                    decision: OsString::from("granted"),
                    decider: OsString::from("ben"),
                },
                "invalid_approval_key",
            ),
            (
                // Argv is bytes, not text. A key that is not UTF-8 cannot be a
                // protocol identifier and is refused rather than lossily
                // converted into one that is.
                Operation::Record {
                    approval_key: OsString::from_vec(vec![b'a', 0xff]),
                    subject: OsString::from("command:shutdown"),
                    decision: OsString::from("granted"),
                    decider: OsString::from("ben"),
                },
                "invalid_approval_key",
            ),
            (
                Operation::Record {
                    approval_key: OsString::from("deploy-1"),
                    subject: OsString::new(),
                    decision: OsString::from("granted"),
                    decider: OsString::from("ben"),
                },
                "invalid_subject",
            ),
            (
                Operation::Record {
                    approval_key: OsString::from("deploy-1"),
                    subject: OsString::from("command:shutdown"),
                    decision: OsString::from("granted"),
                    decider: OsString::new(),
                },
                "invalid_decider",
            ),
            // The decision vocabulary is closed and two-valued. Neither a third
            // word, nor a case variant, nor an empty one is admitted.
            (recording("approved"), "invalid_decision"),
            (recording("GRANTED"), "invalid_decision"),
            (recording("pending"), "invalid_decision"),
            (recording(""), "invalid_decision"),
            (
                Operation::Detail {
                    approval_key: OsString::from(over_long.clone()),
                },
                "invalid_approval_key",
            ),
            (
                Operation::BySubject {
                    subject: OsString::from(over_long),
                    flags: Vec::new(),
                },
                "invalid_subject",
            ),
            (list(&["--nope"]), "invalid_flag"),
            (list(&["--cursor", "-1"]), "invalid_cursor"),
            (list(&["--cursor"]), "invalid_cursor"),
            (list(&["--cursor", "1", "--cursor", "2"]), "repeated_flag"),
            (list(&["--page", "0"]), "invalid_page"),
            (list(&["--page", "33"]), "invalid_page"),
        ] {
            let runtime = runtime_root();
            let listener = listener(&runtime);
            let (exit, stdout, stderr) = invoke(&runtime, &operation);
            assert_eq!(exit, 2, "{expected} did not exit 2");
            assert!(stdout.is_empty());
            assert_eq!(
                stderr,
                format!("automonique approval refused: {expected}\n")
            );
            assert_never_connected(&listener);
        }
    }

    #[test]
    fn a_page_size_is_reported_rather_than_clamped_into_range() {
        // `--page 200` is above the protocol ceiling. Serving thirty-two instead
        // would look identical to a ledger that held thirty-two.
        let runtime = runtime_root();
        let listener = listener(&runtime);
        let (exit, stdout, stderr) = invoke(&runtime, &list(&["--page", "200"]));
        assert_eq!(exit, 2);
        assert!(stdout.is_empty());
        assert_eq!(stderr, "automonique approval refused: invalid_page\n");
        assert_never_connected(&listener);

        // The ceiling itself is admitted, so the refusal above is a bound and
        // not an off-by-one.
        let server = serve_once(listener, |request| ApprovalResponse::ApprovalList {
            request_id: request.request_id().clone(),
            page: ApprovalListPage::new(Vec::new(), ApprovalContinuation::Complete).expect("page"),
        });
        let (exit, _, _) = invoke(&runtime, &list(&["--page", "32"]));
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
        assert_eq!(
            stderr,
            b"automonique approval refused: runtime_unavailable\n"
        );
    }
}
