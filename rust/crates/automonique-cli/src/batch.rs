// SPDX-License-Identifier: Elastic-2.0

//! Operator control of batches.
//!
//! `batch register` declares one batch and its whole membership; `batch advance`
//! reports where one member has got to; `list` and `detail` read them back. They
//! travel under the Batch control protocol rather than as administration
//! commands — the daemon places a frame by the protocol its envelope declares —
//! so nothing here widens the admin lane's closed command set.
//!
//! # What these verbs actually do
//!
//! **They write down which submissions a batch names and what somebody reported
//! about each of them, and nothing else.**
//!
//! - `register` **submits nothing**. It sends member *keys*, not RunSpec
//!   documents; no run is created, none is reserved, and `automonique runs list`
//!   is unchanged by it. A member sits at `unsubmitted` until somebody advances
//!   it, and `unsubmitted` means "nobody has told the registry a submission
//!   exists" — never "one does not".
//! - `--parallel N` **throttles nothing**. The ceiling is recorded because the
//!   batch declared it; no executor in this build reads it, because there is no
//!   executor.
//! - `advance` records a **claim**. The run index is the true binding from a
//!   submission to the state its run reached; this verb says what a writer
//!   observed after reading it, and the daemon checks that the claim follows the
//!   lattice and does not rewind — never that it is true.
//!
//! An accepted write is reported as `registered` or `advanced` rather than
//! `done` for exactly that reason.
//!
//! # `detail` prints a state nothing stores
//!
//! The batch-level state on a `detail` read is derived from the members printed
//! beside it by the batch model's own `roll_up`, and the registry deliberately
//! keeps no such column: a stored rollup is a second copy of an answer that can
//! drift from what it summarizes. The protocol's decoder recomputes it before
//! this file prints anything, so a daemon that fabricated `completed` over
//! members that say otherwise would fail to be decoded rather than be rendered.
//!
//! # Member keys travel in argv, and the reason is not "it was easier"
//!
//! `submit`, `outbox reconcile` and `run submit` read their payloads from stdin
//! because those payloads are *content* — task text, receipts, a RunSpec
//! document — and content in argv appears in every process listing on the host.
//! A member key is not content. It is a bounded, already-public idempotency
//! coordinate of exactly the kind `automation register` and `approval record`
//! already pass in argv, and it is the same string the operator must type to
//! submit the run it names. A maximal membership this lane accepts is 128 keys
//! of 128 bytes, which is 16 KiB of argv against a `ARG_MAX` two orders of
//! magnitude larger, so the bound is the protocol's rather than the shell's.
//!
//! # The discipline, mirroring the other verbs
//!
//! - **Arguments are judged before the connection.** An empty membership, a
//!   repeated member key, a concurrency ceiling of zero, a misspelled progress
//!   word or a page size outside the protocol's range is an operator mistake to
//!   report, not a frame to spend. Nothing is clamped.
//! - **Only a matching answer is rendered.** A listing answered with a detail
//!   view is a mismatch, not something to print.
//! - **Every rendered byte came out of the protocol's own decoder**, which
//!   validated each identifier against its grammar and each progress,
//!   concurrency and refusal word against a closed vocabulary.
//!
//! A `revision_conflict` answer to `advance` is reported on stderr with the
//! durable revision, and stdout stays empty. It is not a refusal — the request
//! was well-formed and the member row simply moved — and unlike a refusal it is
//! retried against the revision the answer carries.

use std::ffi::{OsStr, OsString};
use std::io::Write;

use automonique_protocol::batch_api::{
    AdvanceMember, BatchCursor, BatchDetailResult, BatchPageSize, BatchRecordView, BatchRequest,
    BatchResponse, ListBatches, MemberView, RegisterBatch,
};
use automonique_protocol::batch_runner::{
    BatchId, BatchLabel, BatchMemberKey, ConcurrencyPolicy, MemberProgress,
};
use automonique_protocol::codec::decode_security_enum;

use crate::admin_client;

/// One batch operation, as argv named it.
#[derive(Clone)]
pub(crate) enum Operation {
    /// Declare one batch and its whole membership.
    Register {
        /// The durable batch identity.
        batch_id: OsString,
        /// The remaining argument words: flags and member keys.
        words: Vec<OsString>,
    },
    /// Report that one member moved.
    Advance {
        /// The batch the member belongs to.
        batch_id: OsString,
        /// The member whose row is being advanced.
        member_key: OsString,
        /// Durable revision the caller believes it is advancing.
        revision: OsString,
        /// Progress the writer observed.
        state: OsString,
        /// Highest spool sequence the writer observed.
        last_sequence: OsString,
    },
    /// One bounded page of every batch, paged by the flags.
    List {
        /// The remaining argument words.
        flags: Vec<OsString>,
    },
    /// One batch, its members, and their rollup.
    Detail {
        /// The durable batch identity.
        batch_id: OsString,
    },
}

/// Why one batch operation produced no output.
enum BatchCliError {
    /// An operator-supplied argument is outside its grammar. Nothing was
    /// connected to or sent.
    Field(&'static str),
    /// The daemon, its transport or its socket answered something other than
    /// the write or the read that was asked for.
    Endpoint(String),
}

impl BatchCliError {
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

/// Answer one batch operation, writing rendered output only on success.
pub(crate) fn run<W: Write, E: Write>(
    operation: &Operation,
    runtime: Option<&OsStr>,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let rendered = build(operation).and_then(|request| {
        let response = admin_client::batch_request(runtime, &request)
            .map_err(|error| BatchCliError::Endpoint(error.category().to_owned()))?;
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
            let _ = writeln!(stderr, "automonique batch refused: {}", error.category());
            error.exit_code()
        }
    }
}

/// Judge one operation's arguments and build the request they name.
fn build(operation: &Operation) -> Result<BatchRequest, BatchCliError> {
    match operation {
        Operation::Register { batch_id, words } => {
            let (label, concurrency, members) = membership(words)?;
            Ok(BatchRequest::RegisterBatch {
                request_id: correlation("register")?,
                registration: RegisterBatch::new(identity(batch_id)?, label, concurrency, members)
                    .map_err(|_| BatchCliError::Field("invalid_membership"))?,
            })
        }
        Operation::Advance {
            batch_id,
            member_key,
            revision,
            state,
            last_sequence,
        } => Ok(BatchRequest::AdvanceMember {
            request_id: correlation("advance")?,
            advance: AdvanceMember::new(
                identity(batch_id)?,
                member(member_key)?,
                number(revision, "invalid_revision")?,
                progress(state)?,
                number(last_sequence, "invalid_last_sequence")?,
            )
            .map_err(|_| BatchCliError::Field("invalid_advance"))?,
        }),
        Operation::List { flags } => {
            let (cursor, page_size) = paging(flags)?;
            Ok(BatchRequest::ListBatches {
                request_id: correlation("list")?,
                query: ListBatches::new(cursor, page_size),
            })
        }
        Operation::Detail { batch_id } => Ok(BatchRequest::BatchDetail {
            request_id: correlation("detail")?,
            batch_id: identity(batch_id)?,
        }),
    }
}

/// Split `register`'s remaining words into its flags and its membership.
///
/// A recognized flag is consumed wherever it appears and every other word is a
/// member key, in the order argv gave — that order becomes the members'
/// ordinals, because a sequential policy names it. A member key spelled exactly
/// like one of the three flags is therefore not expressible here; that is the
/// price of not requiring a `--` separator, and it is stated rather than
/// discovered.
///
/// Neither concurrency flag defaults to `--sequential`: it declares the least
/// parallelism and fixes the order to the one argv gave, which is the only thing
/// a caller who said nothing can be presumed to want.
fn membership(
    words: &[OsString],
) -> Result<(Option<BatchLabel>, ConcurrencyPolicy, Vec<BatchMemberKey>), BatchCliError> {
    let mut label: Option<BatchLabel> = None;
    let mut concurrency: Option<ConcurrencyPolicy> = None;
    let mut members = Vec::new();
    let mut words = words.iter();
    while let Some(word) = words.next() {
        match word.to_str() {
            Some("--label") => {
                if label.is_some() {
                    return Err(BatchCliError::Field("repeated_flag"));
                }
                label = Some(
                    flag_value(&mut words)
                        .and_then(|value| BatchLabel::new(value).ok())
                        .ok_or(BatchCliError::Field("invalid_label"))?,
                );
            }
            Some("--sequential") => {
                if concurrency.is_some() {
                    return Err(BatchCliError::Field("repeated_flag"));
                }
                concurrency = Some(ConcurrencyPolicy::Sequential);
            }
            Some("--parallel") => {
                if concurrency.is_some() {
                    return Err(BatchCliError::Field("repeated_flag"));
                }
                concurrency = Some(
                    flag_value(&mut words)
                        .and_then(|value| value.parse::<u32>().ok())
                        .and_then(|ceiling| ConcurrencyPolicy::bounded_parallel(ceiling).ok())
                        .ok_or(BatchCliError::Field("invalid_parallel"))?,
                );
            }
            _ => members.push(member(word)?),
        }
    }
    Ok((
        label,
        concurrency.unwrap_or(ConcurrencyPolicy::Sequential),
        members,
    ))
}

/// Judge the paging flags the listing takes.
fn paging(flags: &[OsString]) -> Result<(BatchCursor, BatchPageSize), BatchCliError> {
    let mut cursor: Option<u64> = None;
    let mut page_size: Option<usize> = None;
    let mut flags = flags.iter();
    while let Some(flag) = flags.next() {
        match flag.to_str() {
            Some("--cursor") => {
                if cursor.is_some() {
                    return Err(BatchCliError::Field("repeated_flag"));
                }
                cursor = Some(
                    flag_value(&mut flags)
                        .and_then(|value| value.parse::<u64>().ok())
                        .ok_or(BatchCliError::Field("invalid_cursor"))?,
                );
            }
            Some("--page") => {
                if page_size.is_some() {
                    return Err(BatchCliError::Field("repeated_flag"));
                }
                page_size = Some(
                    flag_value(&mut flags)
                        .and_then(|value| value.parse::<usize>().ok())
                        .ok_or(BatchCliError::Field("invalid_page"))?,
                );
            }
            _ => return Err(BatchCliError::Field("invalid_flag")),
        }
    }
    let page_size = match page_size {
        Some(size) => BatchPageSize::new(size).map_err(|_| BatchCliError::Field("invalid_page"))?,
        None => BatchPageSize::MAX,
    };
    Ok((
        cursor.map_or(BatchCursor::START, BatchCursor::new),
        page_size,
    ))
}

/// Render the answer to the question that was asked, and nothing else.
///
/// The pairing is exact: a listing answered with a detail view, or a
/// registration answered with a page, is a mismatch rather than something to
/// render.
fn render(request: &BatchRequest, response: BatchResponse) -> Result<String, BatchCliError> {
    match (request, response) {
        (BatchRequest::RegisterBatch { .. }, BatchResponse::Registered { receipt, .. }) => {
            Ok(format!(
                "Automonique batch registered: batch_id={} entry_id={} members={} revision={} created_at_ms={}\n",
                receipt.batch_id(),
                receipt.entry_id(),
                receipt.member_count(),
                receipt.revision(),
                receipt.created_at().as_millis(),
            ))
        }
        (BatchRequest::AdvanceMember { .. }, BatchResponse::MemberAdvanced { receipt, .. }) => {
            Ok(format!(
                "Automonique batch member advanced: batch_id={} member_key={} ordinal={} state={} last_sequence={} revision={} updated_at_ms={}\n",
                receipt.batch_id(),
                receipt.member_key(),
                receipt.ordinal(),
                receipt.progress().as_str(),
                receipt.last_sequence(),
                receipt.revision(),
                receipt.updated_at().as_millis(),
            ))
        }
        (BatchRequest::ListBatches { .. }, BatchResponse::BatchList { page, .. }) => {
            let mut rendered = format!(
                "Automonique batches: count={} more={} next_cursor={}\n",
                page.entries().len(),
                page.continuation().has_more(),
                page.continuation()
                    .cursor()
                    .map_or_else(|| "-".to_owned(), |cursor| cursor.position().to_string()),
            );
            for record in page.entries() {
                rendered.push_str(&render_batch(record));
                rendered.push('\n');
            }
            Ok(rendered)
        }
        (BatchRequest::BatchDetail { .. }, BatchResponse::BatchDetail { detail, .. }) => {
            Ok(render_detail(&detail))
        }
        (
            BatchRequest::AdvanceMember { .. },
            BatchResponse::Conflict {
                expected_revision,
                durable_revision,
                ..
            },
        ) => Err(BatchCliError::Endpoint(format!(
            "revision_conflict expected={expected_revision} durable={durable_revision}"
        ))),
        _ => Err(BatchCliError::Endpoint("response_mismatch".to_owned())),
    }
}

/// One batch row, every column the daemon reported.
fn render_batch(record: &BatchRecordView) -> String {
    format!(
        "batch_id={} entry_id={} label={} concurrency={} created_at_ms={} revision={}",
        record.batch_id(),
        record.entry_id(),
        record
            .label()
            .map_or_else(|| "-".to_owned(), |label| label.as_str().to_owned()),
        render_concurrency(record.concurrency()),
        record.created_at().as_millis(),
        record.revision(),
    )
}

/// One batch, its rolled-up state, and every member in ordinal order.
///
/// `state` is printed on the batch line and not on any member's, because it is
/// the batch's and is derived from the member lines below it. See the module
/// note on why nothing stores it.
fn render_detail(detail: &BatchDetailResult) -> String {
    let mut rendered = format!(
        "Automonique batch: {} state={} members={}\n",
        render_batch(detail.batch()),
        detail.rolled_up_state().as_str(),
        detail.members().len(),
    );
    for member in detail.members() {
        rendered.push_str(&render_member(member));
        rendered.push('\n');
    }
    rendered
}

/// One member row, every column the daemon reported.
///
/// `revision` is printed because it is the value the next `advance` of this
/// member must present: an operator reads it here and fences with it there.
fn render_member(member: &MemberView) -> String {
    format!(
        "member_key={} ordinal={} state={} last_sequence={} revision={} updated_at_ms={}",
        member.key(),
        member.ordinal(),
        member.progress().as_str(),
        member.last_sequence(),
        member.revision(),
        member.updated_at().as_millis(),
    )
}

/// The concurrency policy, with its ceiling when it declares one.
///
/// `sequential` and `bounded_parallel(1)` render differently because they are
/// different policies: the first also fixes the order to the one the batch
/// declared, the second declares none.
fn render_concurrency(policy: ConcurrencyPolicy) -> String {
    match policy.declared_ceiling() {
        Some(ceiling) => format!("{}({ceiling})", policy.kind().as_str()),
        None => policy.kind().as_str().to_owned(),
    }
}

fn correlation(operation: &str) -> Result<automonique_protocol::codec::RequestId, BatchCliError> {
    admin_client::correlation(&format!("batch-{operation}"))
        .map_err(|_| BatchCliError::Field("invalid_request_id"))
}

fn identity(value: &OsStr) -> Result<BatchId, BatchCliError> {
    value
        .to_str()
        .and_then(|value| BatchId::new(value).ok())
        .ok_or(BatchCliError::Field("invalid_batch_id"))
}

fn member(value: &OsStr) -> Result<BatchMemberKey, BatchCliError> {
    value
        .to_str()
        .and_then(|value| BatchMemberKey::new(value).ok())
        .ok_or(BatchCliError::Field("invalid_member_key"))
}

/// The progress word, judged by the protocol's own closed vocabulary.
///
/// Not a local match on seven strings: `decode_security_enum` is the same
/// fail-closed decoder a frame is judged by, so an operator's word and a wire
/// value cannot be admitted by different rules.
fn progress(value: &OsStr) -> Result<MemberProgress, BatchCliError> {
    value
        .to_str()
        .and_then(|value| decode_security_enum::<MemberProgress>(value).ok())
        .ok_or(BatchCliError::Field("invalid_state"))
}

fn number(value: &OsStr, category: &'static str) -> Result<u64, BatchCliError> {
    value
        .to_str()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(BatchCliError::Field(category))
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

    use automonique_protocol::batch_api::{
        BatchContinuation, BatchListPage, BatchReceiptView, BatchRefusal, MemberReceiptParts,
        MemberReceiptView,
    };
    use automonique_protocol::batch_runner::MAX_BATCH_ID_BYTES;
    use automonique_protocol::codec::{RequestId, encode_frame};
    use automonique_protocol::primitives::EpochMillis;
    use automonique_protocol::runs_api::RunState;

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

    /// Serve exactly one Batch request with the real codec.
    ///
    /// The request is decoded by the protocol's own decoder, so a client that
    /// sent an admin frame, an unframed payload or a body this protocol does not
    /// define fails here rather than being quietly accommodated.
    fn serve_once(
        listener: UnixListener,
        answer: impl FnOnce(&BatchRequest) -> BatchResponse + Send + 'static,
    ) -> std::thread::JoinHandle<Option<BatchRequest>> {
        std::thread::spawn(move || {
            let mut stream = accept_deadlined(&listener)?;
            let mut prefix = [0_u8; 4];
            stream.read_exact(&mut prefix).expect("request prefix");
            let mut body = vec![0_u8; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut body).expect("request body");
            let request = BatchRequest::from_canonical_bytes(&body).expect("typed batch request");
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

    fn register(words: &[&str]) -> Operation {
        Operation::Register {
            batch_id: OsString::from("nightly-eval"),
            words: words.iter().map(OsString::from).collect(),
        }
    }

    fn list(flags: &[&str]) -> Operation {
        Operation::List {
            flags: flags.iter().map(OsString::from).collect(),
        }
    }

    fn advance(revision: &str, state: &str, last_sequence: &str) -> Operation {
        Operation::Advance {
            batch_id: OsString::from("nightly-eval"),
            member_key: OsString::from("record-1"),
            revision: OsString::from(revision),
            state: OsString::from(state),
            last_sequence: OsString::from(last_sequence),
        }
    }

    fn batch_row(entry_id: u64, batch_id: &str, concurrency: ConcurrencyPolicy) -> BatchRecordView {
        BatchRecordView::new(
            entry_id,
            BatchId::new(batch_id).expect("batch identity"),
            Some(BatchLabel::new("nightly").expect("label")),
            concurrency,
            EpochMillis::from_millis(1_700_000_000_000),
            1,
        )
        .expect("batch row")
    }

    fn member_row(key: &str, ordinal: u32, progress: MemberProgress, sequence: u64) -> MemberView {
        MemberView::new(
            BatchMemberKey::new(key).expect("member key"),
            ordinal,
            progress,
            sequence,
            if progress == MemberProgress::Unsubmitted {
                1
            } else {
                2
            },
            EpochMillis::from_millis(1_700_000_001_000),
        )
        .expect("member row")
    }

    #[test]
    fn a_registration_renders_the_receipt_the_daemon_returned() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| BatchResponse::Registered {
            request_id: request.request_id().clone(),
            receipt: BatchReceiptView::new(
                3,
                BatchId::new("nightly-eval").expect("batch identity"),
                2,
                1,
                EpochMillis::from_millis(1_700_000_000_000),
            )
            .expect("receipt"),
        });

        let (exit, stdout, stderr) = invoke(
            &runtime,
            &register(&[
                "--label",
                "nightly",
                "--parallel",
                "4",
                "record-1",
                "record-2",
            ]),
        );
        assert_eq!(exit, 0, "stderr: {stderr}");
        assert!(stderr.is_empty());
        assert_eq!(
            stdout,
            "Automonique batch registered: batch_id=nightly-eval entry_id=3 members=2 \
             revision=1 created_at_ms=1700000000000\n",
        );

        // The request the daemon received is the one argv named, membership in
        // the order argv gave: that order becomes the ordinals.
        let BatchRequest::RegisterBatch { registration, .. } =
            server.join().expect("server").expect("served")
        else {
            panic!("the client sent something other than a registration")
        };
        assert_eq!(registration.batch_id().as_str(), "nightly-eval");
        assert_eq!(
            registration.label().map(BatchLabel::as_str),
            Some("nightly")
        );
        assert_eq!(
            registration.concurrency(),
            ConcurrencyPolicy::BoundedParallel { max_in_flight: 4 }
        );
        assert_eq!(
            registration
                .members()
                .iter()
                .map(BatchMemberKey::as_str)
                .collect::<Vec<_>>(),
            vec!["record-1", "record-2"],
        );
    }

    #[test]
    fn a_registration_that_named_no_policy_declares_the_conservative_one() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| BatchResponse::Registered {
            request_id: request.request_id().clone(),
            receipt: BatchReceiptView::new(
                1,
                BatchId::new("nightly-eval").expect("batch identity"),
                1,
                1,
                EpochMillis::from_millis(1),
            )
            .expect("receipt"),
        });
        let (exit, _, stderr) = invoke(&runtime, &register(&["record-1"]));
        assert_eq!(exit, 0, "stderr: {stderr}");
        let BatchRequest::RegisterBatch { registration, .. } =
            server.join().expect("server").expect("served")
        else {
            panic!("the client sent something other than a registration")
        };
        assert_eq!(registration.concurrency(), ConcurrencyPolicy::Sequential);
        assert!(registration.label().is_none());
    }

    #[test]
    fn an_advance_renders_the_receipt_and_sends_what_argv_named() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| {
            BatchResponse::MemberAdvanced {
                request_id: request.request_id().clone(),
                receipt: MemberReceiptView::new(MemberReceiptParts {
                    batch_id: BatchId::new("nightly-eval").expect("batch identity"),
                    member_key: BatchMemberKey::new("record-1").expect("member key"),
                    ordinal: 0,
                    progress: MemberProgress::Run(RunState::Running),
                    last_sequence: 7,
                    revision: 3,
                    updated_at: EpochMillis::from_millis(1_700_000_002_000),
                })
                .expect("receipt"),
            }
        });
        let (exit, stdout, stderr) = invoke(&runtime, &advance("2", "running", "7"));
        assert_eq!(exit, 0, "stderr: {stderr}");
        assert_eq!(
            stdout,
            "Automonique batch member advanced: batch_id=nightly-eval member_key=record-1 \
             ordinal=0 state=running last_sequence=7 revision=3 updated_at_ms=1700000002000\n",
        );
        let BatchRequest::AdvanceMember { advance, .. } =
            server.join().expect("server").expect("served")
        else {
            panic!("the client sent something other than an advance")
        };
        assert_eq!(advance.batch_id().as_str(), "nightly-eval");
        assert_eq!(advance.member_key().as_str(), "record-1");
        assert_eq!(advance.expected_revision(), 2);
        assert_eq!(advance.progress(), MemberProgress::Run(RunState::Running));
        assert_eq!(advance.last_sequence(), 7);
    }

    #[test]
    fn a_listing_renders_every_column_and_defaults_where_argv_said_nothing() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| BatchResponse::BatchList {
            request_id: request.request_id().clone(),
            page: BatchListPage::new(
                vec![
                    batch_row(1, "nightly-eval", ConcurrencyPolicy::Sequential),
                    batch_row(
                        2,
                        "weekly-eval",
                        ConcurrencyPolicy::BoundedParallel { max_in_flight: 8 },
                    ),
                ],
                BatchContinuation::More(BatchCursor::new(2)),
            )
            .expect("page"),
        });

        let (exit, stdout, stderr) = invoke(&runtime, &list(&[]));
        assert_eq!(exit, 0, "stderr: {stderr}");
        assert_eq!(
            stdout,
            "Automonique batches: count=2 more=true next_cursor=2\n\
             batch_id=nightly-eval entry_id=1 label=nightly concurrency=sequential created_at_ms=1700000000000 revision=1\n\
             batch_id=weekly-eval entry_id=2 label=nightly concurrency=bounded_parallel(8) created_at_ms=1700000000000 revision=1\n",
        );
        let BatchRequest::ListBatches { query, .. } =
            server.join().expect("server").expect("served")
        else {
            panic!("the client sent something other than a listing")
        };
        assert_eq!(query.since(), BatchCursor::START);
        assert_eq!(query.page_size(), BatchPageSize::MAX);
    }

    #[test]
    fn every_paging_flag_reaches_the_listing() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| BatchResponse::BatchList {
            request_id: request.request_id().clone(),
            page: BatchListPage::new(Vec::new(), BatchContinuation::Complete).expect("page"),
        });
        let (exit, stdout, stderr) = invoke(&runtime, &list(&["--cursor", "9", "--page", "3"]));
        assert_eq!(exit, 0, "stderr: {stderr}");
        assert_eq!(
            stdout,
            "Automonique batches: count=0 more=false next_cursor=-\n"
        );
        let BatchRequest::ListBatches { query, .. } =
            server.join().expect("server").expect("served")
        else {
            panic!("the client sent something other than a listing")
        };
        assert_eq!(query.since(), BatchCursor::new(9));
        assert_eq!(query.page_size().get(), 3);
    }

    #[test]
    fn a_detail_read_renders_the_members_and_the_state_they_roll_up_to() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| BatchResponse::BatchDetail {
            request_id: request.request_id().clone(),
            detail: BatchDetailResult::new(
                batch_row(1, "nightly-eval", ConcurrencyPolicy::Sequential),
                vec![
                    member_row("record-1", 0, MemberProgress::Run(RunState::Completed), 4),
                    member_row("record-2", 1, MemberProgress::Run(RunState::Running), 2),
                ],
            )
            .expect("detail"),
        });
        let (exit, stdout, stderr) = invoke(
            &runtime,
            &Operation::Detail {
                batch_id: OsString::from("nightly-eval"),
            },
        );
        assert_eq!(exit, 0, "stderr: {stderr}");
        assert_eq!(
            stdout,
            "Automonique batch: batch_id=nightly-eval entry_id=1 label=nightly concurrency=sequential created_at_ms=1700000000000 revision=1 state=running members=2\n\
             member_key=record-1 ordinal=0 state=completed last_sequence=4 revision=2 updated_at_ms=1700000001000\n\
             member_key=record-2 ordinal=1 state=running last_sequence=2 revision=2 updated_at_ms=1700000001000\n",
        );
        let BatchRequest::BatchDetail { batch_id, .. } =
            server.join().expect("server").expect("served")
        else {
            panic!("the client sent something other than a detail read")
        };
        assert_eq!(batch_id.as_str(), "nightly-eval");
    }

    #[test]
    fn a_refusal_and_a_conflict_both_keep_stdout_empty() {
        for (operation, answer, expected) in [
            (
                register(&["record-1"]),
                Box::new(|request: &BatchRequest| BatchResponse::Refused {
                    request_id: request.request_id().clone(),
                    refusal: BatchRefusal::AlreadyRegistered,
                }) as Box<dyn FnOnce(&BatchRequest) -> BatchResponse + Send>,
                "automonique batch refused: already_registered\n",
            ),
            (
                advance("2", "running", "7"),
                Box::new(|request: &BatchRequest| {
                    BatchResponse::conflict(request.request_id().clone(), 2, 5).expect("conflict")
                }),
                "automonique batch refused: revision_conflict expected=2 durable=5\n",
            ),
        ] {
            let runtime = runtime_root();
            let server = serve_once(listener(&runtime), answer);
            let (exit, stdout, stderr) = invoke(&runtime, &operation);
            assert_eq!(exit, 1);
            assert!(stdout.is_empty(), "a failed write wrote {stdout:?}");
            assert_eq!(stderr, expected);
            server.join().expect("server").expect("served");
        }
    }

    #[test]
    fn an_answer_to_a_different_question_is_not_rendered() {
        // The daemon answers a listing with a registration receipt. Both are
        // well-formed Batch messages, so only the pairing can catch it.
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| BatchResponse::Registered {
            request_id: request.request_id().clone(),
            receipt: BatchReceiptView::new(
                1,
                BatchId::new("nightly-eval").expect("batch identity"),
                1,
                1,
                EpochMillis::from_millis(1),
            )
            .expect("receipt"),
        });
        let (exit, stdout, stderr) = invoke(&runtime, &list(&[]));
        assert_eq!(exit, 1);
        assert!(stdout.is_empty());
        assert_eq!(stderr, "automonique batch refused: response_mismatch\n");
        server.join().expect("server").expect("served");
    }

    #[test]
    fn an_uncorrelated_answer_is_refused_rather_than_rendered() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |_| BatchResponse::Registered {
            request_id: RequestId::new("somebody-elses-question").expect("request ID"),
            receipt: BatchReceiptView::new(
                1,
                BatchId::new("nightly-eval").expect("batch identity"),
                1,
                1,
                EpochMillis::from_millis(1),
            )
            .expect("receipt"),
        });
        let (exit, stdout, stderr) = invoke(&runtime, &register(&["record-1"]));
        assert_eq!(exit, 1);
        assert!(stdout.is_empty());
        assert_eq!(stderr, "automonique batch refused: request_id_mismatch\n");
        server.join().expect("server").expect("served");
    }

    #[test]
    fn arguments_outside_their_grammar_are_refused_before_any_connection() {
        let over_long = "a".repeat(MAX_BATCH_ID_BYTES + 1);
        for (operation, expected) in [
            (
                Operation::Register {
                    batch_id: OsString::new(),
                    words: vec![OsString::from("record-1")],
                },
                "invalid_batch_id",
            ),
            (
                Operation::Register {
                    batch_id: OsString::from(over_long.clone()),
                    words: vec![OsString::from("record-1")],
                },
                "invalid_batch_id",
            ),
            (
                // Argv is bytes, not text. A key that is not UTF-8 cannot be a
                // protocol identifier and is refused rather than lossily
                // converted into one that is.
                Operation::Register {
                    batch_id: OsString::from("nightly-eval"),
                    words: vec![OsString::from_vec(vec![b'a', 0xff])],
                },
                "invalid_member_key",
            ),
            // An empty membership is a unit with nothing in it, and a repeated
            // key is a caller that believes it asked for something it did not.
            (register(&[]), "invalid_membership"),
            (register(&["record-1", "record-1"]), "invalid_membership"),
            // A ceiling that admits nothing, and one no batch could reach.
            (
                register(&["--parallel", "0", "record-1"]),
                "invalid_parallel",
            ),
            (
                register(&["--parallel", "257", "record-1"]),
                "invalid_parallel",
            ),
            (
                register(&["--parallel", "many", "record-1"]),
                "invalid_parallel",
            ),
            (register(&["--parallel"]), "invalid_parallel"),
            (
                register(&["--parallel", "2", "--sequential", "record-1"]),
                "repeated_flag",
            ),
            (
                register(&["--label", "a", "--label", "b", "record-1"]),
                "repeated_flag",
            ),
            (register(&["--label", "", "record-1"]), "invalid_label"),
            // The progress vocabulary is closed and seven-valued. Neither an
            // eighth word nor a case variant is admitted.
            (advance("2", "finished", "1"), "invalid_state"),
            (advance("2", "RUNNING", "1"), "invalid_state"),
            (advance("2", "", "1"), "invalid_state"),
            (advance("nope", "running", "1"), "invalid_revision"),
            (advance("2", "running", "nope"), "invalid_last_sequence"),
            // Revision zero names a row no writer produced, and the sequence
            // coupling is a property of the request alone.
            (advance("0", "running", "1"), "invalid_advance"),
            (advance("2", "ready", "7"), "invalid_advance"),
            (advance("2", "running", "0"), "invalid_advance"),
            (
                Operation::Detail {
                    batch_id: OsString::from(over_long),
                },
                "invalid_batch_id",
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
            assert_eq!(stderr, format!("automonique batch refused: {expected}\n"));
            assert_never_connected(&listener);
        }
    }

    #[test]
    fn a_page_size_is_reported_rather_than_clamped_into_range() {
        // `--page 200` is above the protocol ceiling. Serving thirty-two instead
        // would look identical to a registry that held thirty-two.
        let runtime = runtime_root();
        let listener = listener(&runtime);
        let (exit, stdout, stderr) = invoke(&runtime, &list(&["--page", "200"]));
        assert_eq!(exit, 2);
        assert!(stdout.is_empty());
        assert_eq!(stderr, "automonique batch refused: invalid_page\n");
        assert_never_connected(&listener);

        // The ceiling itself is admitted, so the refusal above is a bound and
        // not an off-by-one.
        let server = serve_once(listener, |request| BatchResponse::BatchList {
            request_id: request.request_id().clone(),
            page: BatchListPage::new(Vec::new(), BatchContinuation::Complete).expect("page"),
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
        assert_eq!(stderr, b"automonique batch refused: runtime_unavailable\n");
    }
}
