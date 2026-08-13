// SPDX-License-Identifier: Elastic-2.0

//! Operator control of automation enablement.
//!
//! `automation register`, `pause`, `resume` and `archive` write one durable
//! row each; `list` and `detail` read them back. They travel under the
//! Automation protocol rather than as administration commands — the daemon
//! places a frame by the protocol its envelope declares — so nothing here
//! widens the admin lane's closed command set.
//!
//! # What these verbs actually do
//!
//! **They record an operator's decision about whether an automation is in
//! service, and nothing else.** There is no scheduler in this build and no
//! executor, so:
//!
//! - `register` starts nothing;
//! - `pause` suppresses nothing, because nothing was running to suppress; and
//! - `resume` resumes nothing.
//!
//! An accepted write is reported as `accepted` rather than `done` for exactly
//! that reason: the row is committed and survives a restart, and the decision
//! it records has nowhere to take effect yet.
//!
//! # The discipline, mirroring the other verbs
//!
//! - **Arguments are judged before the connection.** A misspelled state word, a
//!   non-numeric revision or a page size outside the protocol's range is an
//!   operator mistake to report, not a frame to spend. Nothing is clamped.
//! - **The cause coupling is judged before the connection too.** `pause` and
//!   `archive` require a reason and the protocol's own constructor refuses a
//!   causeless one, so an operator learns immediately rather than after a round
//!   trip. `resume` takes no reason and there is no argument position to give
//!   it one.
//! - **Only a matching answer is rendered.** A listing answered with a detail
//!   record is a mismatch, not something to print.
//! - **Every rendered byte came out of the protocol's own decoder**, which
//!   validated each identifier against its grammar and each enablement and
//!   refusal word against a closed vocabulary.
//!
//! A `revision_conflict` answer is reported on stderr with the durable revision
//! to retry against, and stdout stays empty. It is not a refusal — the request
//! was well-formed and the row simply moved — but it is not the write the
//! operator asked for either.

use std::ffi::{OsStr, OsString};
use std::io::Write;

use automonique_protocol::automation::{AutomationActor, EnablementState};
use automonique_protocol::automation_api::{
    AutomationCursor, AutomationId, AutomationPageSize, AutomationRecordView, AutomationRequest,
    AutomationResponse, AutomationStateFilter, ListAutomations, PauseReason, RegisterAutomation,
    SetEnablement, decode_enablement,
};

use crate::admin_client;

/// One automation control operation, as argv named it.
#[derive(Clone)]
pub(crate) enum Operation {
    /// Declare one automation, enabled, at revision one.
    Register {
        /// The identity, then the actor.
        automation_id: OsString,
        /// Who declared it.
        actor: OsString,
    },
    /// Withdraw one automation from service, resumably.
    Pause {
        /// The identity.
        automation_id: OsString,
        /// The durable revision being moved.
        revision: OsString,
        /// Who withdrew it.
        actor: OsString,
        /// Why.
        cause: OsString,
    },
    /// Put one automation back in service.
    Resume {
        /// The identity.
        automation_id: OsString,
        /// The durable revision being moved.
        revision: OsString,
        /// Who reopened it.
        actor: OsString,
    },
    /// Withdraw one automation permanently.
    Archive {
        /// The identity.
        automation_id: OsString,
        /// The durable revision being moved.
        revision: OsString,
        /// Who archived it.
        actor: OsString,
        /// Why.
        cause: OsString,
    },
    /// One bounded page of automations, filtered and paged by the flags.
    List {
        /// The remaining argument words.
        flags: Vec<OsString>,
    },
    /// One automation in full.
    Detail {
        /// The identity.
        automation_id: OsString,
    },
}

/// Why one automation operation produced no output.
enum AutomationCliError {
    /// An operator-supplied argument is outside its grammar. Nothing was
    /// connected to or sent.
    Field(&'static str),
    /// The daemon, its transport or its socket answered something other than
    /// the write or the page that was asked for.
    Endpoint(String),
}

impl AutomationCliError {
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

/// Answer one automation operation, writing rendered output only on success.
pub(crate) fn run<W: Write, E: Write>(
    operation: &Operation,
    runtime: Option<&OsStr>,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let rendered = build(operation).and_then(|request| {
        let response = admin_client::automation_request(runtime, &request)
            .map_err(|error| AutomationCliError::Endpoint(error.category().to_owned()))?;
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
            let _ = writeln!(
                stderr,
                "automonique automation refused: {}",
                error.category()
            );
            error.exit_code()
        }
    }
}

/// Judge one operation's arguments and build the request they name.
fn build(operation: &Operation) -> Result<AutomationRequest, AutomationCliError> {
    match operation {
        Operation::Register {
            automation_id,
            actor,
        } => Ok(AutomationRequest::RegisterAutomation {
            request_id: correlation("register")?,
            registration: RegisterAutomation::new(identity(automation_id)?, who(actor)?),
        }),
        Operation::Pause {
            automation_id,
            revision,
            actor,
            cause,
        } => transition(
            "pause",
            automation_id,
            revision,
            EnablementState::Paused,
            actor,
            Some(cause),
        ),
        Operation::Resume {
            automation_id,
            revision,
            actor,
        } => transition(
            "resume",
            automation_id,
            revision,
            EnablementState::Enabled,
            actor,
            None,
        ),
        Operation::Archive {
            automation_id,
            revision,
            actor,
            cause,
        } => transition(
            "archive",
            automation_id,
            revision,
            EnablementState::Archived,
            actor,
            Some(cause),
        ),
        Operation::List { flags } => list_request(flags),
        Operation::Detail { automation_id } => Ok(AutomationRequest::AutomationDetail {
            request_id: correlation("detail")?,
            automation_id: identity(automation_id)?,
        }),
    }
}

/// Build one lattice move from the words that named it.
///
/// The cause coupling is the protocol's, not this function's: `pause` and
/// `archive` hand it a reason and `resume` hands it none, and
/// [`SetEnablement::new`] is what refuses an incoherent pairing. Re-deciding it
/// here would create a second authority that could drift from the first.
fn transition(
    label: &'static str,
    automation_id: &OsStr,
    revision: &OsStr,
    target: EnablementState,
    actor: &OsStr,
    cause: Option<&OsString>,
) -> Result<AutomationRequest, AutomationCliError> {
    let cause = cause.map(|cause| reason(cause)).transpose()?;
    Ok(AutomationRequest::SetEnablement {
        request_id: correlation(label)?,
        transition: SetEnablement::new(
            identity(automation_id)?,
            expected_revision(revision)?,
            target,
            who(actor)?,
            cause,
        )
        .map_err(|_| AutomationCliError::Field("invalid_transition"))?,
    })
}

/// Judge `automation list` arguments and build the request they name.
fn list_request(flags: &[OsString]) -> Result<AutomationRequest, AutomationCliError> {
    let mut states: Vec<EnablementState> = Vec::new();
    let mut cursor: Option<u64> = None;
    let mut page_size: Option<usize> = None;
    let mut flags = flags.iter();
    while let Some(flag) = flags.next() {
        match flag.to_str() {
            Some("--state") => {
                let spelling =
                    flag_value(&mut flags).ok_or(AutomationCliError::Field("invalid_state"))?;
                states.push(
                    decode_enablement(spelling)
                        .map_err(|_| AutomationCliError::Field("invalid_state"))?,
                );
            }
            Some("--cursor") => {
                if cursor.is_some() {
                    return Err(AutomationCliError::Field("repeated_flag"));
                }
                cursor = Some(
                    flag_value(&mut flags)
                        .and_then(|value| value.parse::<u64>().ok())
                        .ok_or(AutomationCliError::Field("invalid_cursor"))?,
                );
            }
            Some("--page") => {
                if page_size.is_some() {
                    return Err(AutomationCliError::Field("repeated_flag"));
                }
                page_size = Some(
                    flag_value(&mut flags)
                        .and_then(|value| value.parse::<usize>().ok())
                        .ok_or(AutomationCliError::Field("invalid_page"))?,
                );
            }
            _ => return Err(AutomationCliError::Field("invalid_flag")),
        }
    }
    let states = if states.is_empty() {
        AutomationStateFilter::any()
    } else {
        AutomationStateFilter::only(states)
            .map_err(|_| AutomationCliError::Field("invalid_state_filter"))?
    };
    let page_size = match page_size {
        Some(size) => {
            AutomationPageSize::new(size).map_err(|_| AutomationCliError::Field("invalid_page"))?
        }
        None => AutomationPageSize::MAX,
    };
    Ok(AutomationRequest::ListAutomations {
        request_id: correlation("list")?,
        query: ListAutomations::new(
            states,
            cursor.map_or(AutomationCursor::START, AutomationCursor::new),
            page_size,
        ),
    })
}

/// Render the answer to the question that was asked, and nothing else.
///
/// The pairing is exact: a listing answered with a detail record, or a register
/// answered with a page, is a mismatch rather than something to render.
fn render(
    request: &AutomationRequest,
    response: AutomationResponse,
) -> Result<String, AutomationCliError> {
    match (request, response) {
        (
            AutomationRequest::RegisterAutomation { .. } | AutomationRequest::SetEnablement { .. },
            AutomationResponse::Accepted { receipt, .. },
        ) => Ok(format!(
            "Automonique automation accepted: automation_id={} entry_id={} enablement={} revision={} updated_at_ms={}\n",
            receipt.automation_id(),
            receipt.entry_id(),
            receipt.enablement().as_str(),
            receipt.revision(),
            receipt.updated_at().as_millis(),
        )),
        (
            AutomationRequest::ListAutomations { .. },
            AutomationResponse::AutomationList { page, .. },
        ) => {
            let mut rendered = format!(
                "Automonique automations: count={} more={} next_cursor={}\n",
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
            AutomationRequest::AutomationDetail { .. },
            AutomationResponse::AutomationDetail { record, .. },
        ) => Ok(format!(
            "Automonique automation: {}\n",
            render_record(&record)
        )),
        (
            AutomationRequest::RegisterAutomation { .. } | AutomationRequest::SetEnablement { .. },
            AutomationResponse::Conflict {
                expected_revision,
                durable_revision,
                ..
            },
        ) => Err(AutomationCliError::Endpoint(format!(
            "revision_conflict expected={expected_revision} durable={durable_revision}"
        ))),
        _ => Err(AutomationCliError::Endpoint("response_mismatch".to_owned())),
    }
}

/// One record, every column the daemon reported.
///
/// `resumed_by` is derived rather than stored, and it is printed because it is
/// the one question the flat columns do not answer at a glance: an `enabled`
/// row above revision one was put back by somebody, and a never-paused one was
/// not.
fn render_record(record: &AutomationRecordView) -> String {
    format!(
        "automation_id={} entry_id={} revision={} enablement={} actor={} cause={} resumed_by={} created_at_ms={} updated_at_ms={}",
        record.automation_id(),
        record.entry_id(),
        record.revision(),
        record.enablement().as_str(),
        record.actor().as_str(),
        record.cause().map_or(
            "-",
            automonique_protocol::automation_api::PauseReason::as_str
        ),
        record.resumed_by().map_or("-", AutomationActor::as_str),
        record.created_at().as_millis(),
        record.updated_at().as_millis(),
    )
}

fn correlation(
    operation: &str,
) -> Result<automonique_protocol::codec::RequestId, AutomationCliError> {
    admin_client::correlation(&format!("automation-{operation}"))
        .map_err(|_| AutomationCliError::Field("invalid_request_id"))
}

fn identity(value: &OsStr) -> Result<AutomationId, AutomationCliError> {
    value
        .to_str()
        .and_then(|value| AutomationId::new(value).ok())
        .ok_or(AutomationCliError::Field("invalid_automation_id"))
}

fn who(value: &OsStr) -> Result<AutomationActor, AutomationCliError> {
    value
        .to_str()
        .and_then(|value| AutomationActor::new(value).ok())
        .ok_or(AutomationCliError::Field("invalid_actor"))
}

fn reason(value: &OsStr) -> Result<PauseReason, AutomationCliError> {
    value
        .to_str()
        .and_then(|value| PauseReason::new(value).ok())
        .ok_or(AutomationCliError::Field("invalid_cause"))
}

fn expected_revision(value: &OsStr) -> Result<u64, AutomationCliError> {
    value
        .to_str()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|revision| *revision > 0)
        .ok_or(AutomationCliError::Field("invalid_revision"))
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

    use automonique_protocol::automation_api::{
        AutomationContinuation, AutomationListPage, AutomationReceiptView, AutomationRecordParts,
        AutomationRefusal, MAX_AUTOMATION_API_FIELD_BYTES,
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

    /// Serve exactly one Automation request with the real codec.
    ///
    /// The request is decoded by the protocol's own decoder, so a client that
    /// sent an admin frame, an unframed payload or a body this protocol does
    /// not define fails here rather than being quietly accommodated.
    fn serve_once(
        listener: UnixListener,
        answer: impl FnOnce(&AutomationRequest) -> AutomationResponse + Send + 'static,
    ) -> std::thread::JoinHandle<Option<AutomationRequest>> {
        std::thread::spawn(move || {
            let mut stream = accept_deadlined(&listener)?;
            let mut prefix = [0_u8; 4];
            stream.read_exact(&mut prefix).expect("request prefix");
            let mut body = vec![0_u8; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut body).expect("request body");
            let request =
                AutomationRequest::from_canonical_bytes(&body).expect("typed automation request");
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

    fn receipt(enablement: EnablementState, revision: u64) -> AutomationReceiptView {
        AutomationReceiptView::new(
            7,
            AutomationId::new("nightly-report").expect("identity"),
            enablement,
            revision,
            EpochMillis::from_millis(1_700_000_000_000),
        )
        .expect("receipt")
    }

    fn row(
        entry_id: u64,
        automation: &str,
        revision: u64,
        enablement: EnablementState,
        actor: &str,
        cause: Option<&str>,
    ) -> AutomationRecordView {
        AutomationRecordView::new(AutomationRecordParts {
            entry_id,
            automation_id: AutomationId::new(automation).expect("identity"),
            revision,
            enablement,
            actor: AutomationActor::new(actor).expect("actor"),
            cause: cause.map(|cause| PauseReason::new(cause).expect("cause")),
            created_at: EpochMillis::from_millis(1_700_000_000_000),
            updated_at: EpochMillis::from_millis(1_700_000_001_000),
        })
        .expect("record")
    }

    #[test]
    fn a_registration_renders_the_receipt_the_daemon_returned() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| AutomationResponse::Accepted {
            request_id: request.request_id().clone(),
            receipt: receipt(EnablementState::Enabled, 1),
        });

        let (exit, stdout, stderr) = invoke(
            &runtime,
            &Operation::Register {
                automation_id: OsString::from("nightly-report"),
                actor: OsString::from("ben"),
            },
        );
        assert_eq!(exit, 0, "stderr: {stderr}");
        assert!(stderr.is_empty());
        assert_eq!(
            stdout,
            "Automonique automation accepted: automation_id=nightly-report entry_id=7 \
             enablement=enabled revision=1 updated_at_ms=1700000000000\n",
        );

        // The request the daemon received is the one argv named.
        let AutomationRequest::RegisterAutomation { registration, .. } =
            server.join().expect("server").expect("served")
        else {
            panic!("the client sent something other than a registration")
        };
        assert_eq!(registration.automation_id().as_str(), "nightly-report");
        assert_eq!(registration.actor().as_str(), "ben");
    }

    #[test]
    fn a_pause_carries_its_cause_and_a_resume_carries_none() {
        for (operation, target, cause, revision) in [
            (
                Operation::Pause {
                    automation_id: OsString::from("nightly-report"),
                    revision: OsString::from("1"),
                    actor: OsString::from("ben"),
                    cause: OsString::from("provider outage"),
                },
                EnablementState::Paused,
                Some("provider outage"),
                1_u64,
            ),
            (
                Operation::Resume {
                    automation_id: OsString::from("nightly-report"),
                    revision: OsString::from("2"),
                    actor: OsString::from("dana"),
                },
                EnablementState::Enabled,
                None,
                2,
            ),
            (
                Operation::Archive {
                    automation_id: OsString::from("nightly-report"),
                    revision: OsString::from("3"),
                    actor: OsString::from("dana"),
                    cause: OsString::from("superseded"),
                },
                EnablementState::Archived,
                Some("superseded"),
                3,
            ),
        ] {
            let runtime = runtime_root();
            let server = serve_once(listener(&runtime), move |request| {
                AutomationResponse::Accepted {
                    request_id: request.request_id().clone(),
                    receipt: receipt(target, revision + 1),
                }
            });
            let (exit, stdout, stderr) = invoke(&runtime, &operation);
            assert_eq!(exit, 0, "stderr: {stderr}");
            assert!(stdout.contains(&format!("enablement={}", target.as_str())));

            let AutomationRequest::SetEnablement { transition, .. } =
                server.join().expect("server").expect("served")
            else {
                panic!("the client sent something other than a transition")
            };
            assert_eq!(transition.automation_id().as_str(), "nightly-report");
            assert_eq!(transition.expected_revision(), revision);
            assert_eq!(transition.target(), target);
            assert_eq!(transition.cause().map(PauseReason::as_str), cause);
        }
    }

    #[test]
    fn a_listing_renders_every_column_including_the_derived_resumed_by() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| {
            AutomationResponse::AutomationList {
                request_id: request.request_id().clone(),
                page: AutomationListPage::new(
                    vec![
                        row(1, "alpha", 1, EnablementState::Enabled, "ben", None),
                        row(
                            2,
                            "beta",
                            2,
                            EnablementState::Paused,
                            "dana",
                            Some("provider outage"),
                        ),
                        row(3, "gamma", 4, EnablementState::Enabled, "dana", None),
                    ],
                    AutomationContinuation::More(AutomationCursor::new(3)),
                )
                .expect("page"),
            }
        });

        let (exit, stdout, stderr) = invoke(&runtime, &list(&[]));
        assert_eq!(exit, 0, "stderr: {stderr}");
        assert_eq!(
            stdout,
            "Automonique automations: count=3 more=true next_cursor=3\n\
             automation_id=alpha entry_id=1 revision=1 enablement=enabled actor=ben cause=- resumed_by=- created_at_ms=1700000000000 updated_at_ms=1700000001000\n\
             automation_id=beta entry_id=2 revision=2 enablement=paused actor=dana cause=provider outage resumed_by=- created_at_ms=1700000000000 updated_at_ms=1700000001000\n\
             automation_id=gamma entry_id=3 revision=4 enablement=enabled actor=dana cause=- resumed_by=dana created_at_ms=1700000000000 updated_at_ms=1700000001000\n",
        );

        // Defaults, where argv said nothing.
        let AutomationRequest::ListAutomations { query, .. } =
            server.join().expect("server").expect("served")
        else {
            panic!("the client sent something other than a listing")
        };
        assert_eq!(query.states().states(), None);
        assert_eq!(query.since(), AutomationCursor::START);
        assert_eq!(query.page_size(), AutomationPageSize::MAX);
    }

    #[test]
    fn every_listing_flag_reaches_the_query_the_daemon_receives() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| {
            AutomationResponse::AutomationList {
                request_id: request.request_id().clone(),
                page: AutomationListPage::new(Vec::new(), AutomationContinuation::Complete)
                    .expect("page"),
            }
        });

        let (exit, stdout, _) = invoke(
            &runtime,
            &list(&[
                "--state", "archived", "--state", "paused", "--cursor", "9", "--page", "3",
            ]),
        );
        assert_eq!(exit, 0);
        assert_eq!(
            stdout,
            "Automonique automations: count=0 more=false next_cursor=-\n"
        );

        let AutomationRequest::ListAutomations { query, .. } =
            server.join().expect("server").expect("served")
        else {
            panic!("the client sent something other than a listing")
        };
        // Repeated `--state` accumulates, and the protocol sorts the set into
        // its own declaration order, so the wire form does not depend on the
        // order an operator typed.
        assert_eq!(
            query.states().states(),
            Some([EnablementState::Paused, EnablementState::Archived].as_slice()),
        );
        assert_eq!(query.since(), AutomationCursor::new(9));
        assert_eq!(query.page_size().get(), 3);
    }

    #[test]
    fn a_detail_read_renders_the_record_it_asked_for() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| {
            AutomationResponse::AutomationDetail {
                request_id: request.request_id().clone(),
                record: row(
                    2,
                    "beta",
                    2,
                    EnablementState::Paused,
                    "dana",
                    Some("provider outage"),
                ),
            }
        });
        let (exit, stdout, stderr) = invoke(
            &runtime,
            &Operation::Detail {
                automation_id: OsString::from("beta"),
            },
        );
        assert_eq!(exit, 0, "stderr: {stderr}");
        assert_eq!(
            stdout,
            "Automonique automation: automation_id=beta entry_id=2 revision=2 enablement=paused \
             actor=dana cause=provider outage resumed_by=- created_at_ms=1700000000000 \
             updated_at_ms=1700000001000\n",
        );
        let AutomationRequest::AutomationDetail { automation_id, .. } =
            server.join().expect("server").expect("served")
        else {
            panic!("the client sent something other than a detail read")
        };
        assert_eq!(automation_id.as_str(), "beta");
    }

    #[test]
    fn a_refusal_and_a_conflict_both_keep_stdout_empty() {
        for (answer, expected) in [
            (
                Box::new(|request: &AutomationRequest| AutomationResponse::Refused {
                    request_id: request.request_id().clone(),
                    refusal: AutomationRefusal::IllegalTransition,
                })
                    as Box<dyn FnOnce(&AutomationRequest) -> AutomationResponse + Send>,
                "automonique automation refused: illegal_transition\n",
            ),
            (
                Box::new(|request: &AutomationRequest| {
                    AutomationResponse::conflict(request.request_id().clone(), 1, 4)
                        .expect("conflict")
                }),
                "automonique automation refused: revision_conflict expected=1 durable=4\n",
            ),
        ] {
            let runtime = runtime_root();
            let server = serve_once(listener(&runtime), answer);
            let (exit, stdout, stderr) = invoke(
                &runtime,
                &Operation::Resume {
                    automation_id: OsString::from("nightly-report"),
                    revision: OsString::from("1"),
                    actor: OsString::from("dana"),
                },
            );
            assert_eq!(exit, 1);
            assert!(stdout.is_empty(), "a failed write wrote {stdout:?}");
            assert_eq!(stderr, expected);
            server.join().expect("server").expect("served");
        }
    }

    #[test]
    fn an_answer_to_a_different_question_is_not_rendered() {
        // The daemon answers a listing with a detail record. Both are
        // well-formed Automation messages, so only the pairing can catch it.
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |request| {
            AutomationResponse::AutomationDetail {
                request_id: request.request_id().clone(),
                record: row(1, "alpha", 1, EnablementState::Enabled, "ben", None),
            }
        });
        let (exit, stdout, stderr) = invoke(&runtime, &list(&[]));
        assert_eq!(exit, 1);
        assert!(stdout.is_empty());
        assert_eq!(
            stderr,
            "automonique automation refused: response_mismatch\n"
        );
        server.join().expect("server").expect("served");
    }

    #[test]
    fn an_uncorrelated_answer_is_refused_rather_than_rendered() {
        let runtime = runtime_root();
        let server = serve_once(listener(&runtime), |_| AutomationResponse::Accepted {
            request_id: RequestId::new("somebody-elses-question").expect("request ID"),
            receipt: receipt(EnablementState::Enabled, 1),
        });
        let (exit, stdout, stderr) = invoke(
            &runtime,
            &Operation::Register {
                automation_id: OsString::from("nightly-report"),
                actor: OsString::from("ben"),
            },
        );
        assert_eq!(exit, 1);
        assert!(stdout.is_empty());
        assert_eq!(
            stderr,
            "automonique automation refused: request_id_mismatch\n"
        );
        server.join().expect("server").expect("served");
    }

    #[test]
    fn arguments_outside_their_grammar_are_refused_before_any_connection() {
        let over_long = "a".repeat(MAX_AUTOMATION_API_FIELD_BYTES + 1);
        for (operation, expected) in [
            (
                Operation::Register {
                    automation_id: OsString::new(),
                    actor: OsString::from("ben"),
                },
                "invalid_automation_id",
            ),
            (
                Operation::Register {
                    automation_id: OsString::from("night\nly"),
                    actor: OsString::from("ben"),
                },
                "invalid_automation_id",
            ),
            (
                Operation::Register {
                    automation_id: OsString::from(over_long.clone()),
                    actor: OsString::from("ben"),
                },
                "invalid_automation_id",
            ),
            (
                // Argv is bytes, not text. An identity that is not UTF-8 cannot
                // be a protocol identifier and is refused rather than lossily
                // converted into one that is.
                Operation::Register {
                    automation_id: OsString::from_vec(vec![b'a', 0xff]),
                    actor: OsString::from("ben"),
                },
                "invalid_automation_id",
            ),
            (
                Operation::Register {
                    automation_id: OsString::from("nightly-report"),
                    actor: OsString::new(),
                },
                "invalid_actor",
            ),
            (
                Operation::Pause {
                    automation_id: OsString::from("nightly-report"),
                    revision: OsString::from("0"),
                    actor: OsString::from("ben"),
                    cause: OsString::from("outage"),
                },
                "invalid_revision",
            ),
            (
                Operation::Pause {
                    automation_id: OsString::from("nightly-report"),
                    revision: OsString::from("-1"),
                    actor: OsString::from("ben"),
                    cause: OsString::from("outage"),
                },
                "invalid_revision",
            ),
            (
                Operation::Pause {
                    automation_id: OsString::from("nightly-report"),
                    revision: OsString::from("many"),
                    actor: OsString::from("ben"),
                    cause: OsString::from("outage"),
                },
                "invalid_revision",
            ),
            (
                Operation::Pause {
                    automation_id: OsString::from("nightly-report"),
                    revision: OsString::from("1"),
                    actor: OsString::from("ben"),
                    cause: OsString::new(),
                },
                "invalid_cause",
            ),
            (
                Operation::Detail {
                    automation_id: OsString::from(over_long),
                },
                "invalid_automation_id",
            ),
            (list(&["--nope"]), "invalid_flag"),
            (list(&["--state", "sleeping"]), "invalid_state"),
            (list(&["--state"]), "invalid_state"),
            (
                list(&["--state", "paused", "--state", "paused"]),
                "invalid_state_filter",
            ),
            (list(&["--cursor", "-1"]), "invalid_cursor"),
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
                format!("automonique automation refused: {expected}\n")
            );
            assert_never_connected(&listener);
        }
    }

    #[test]
    fn a_page_size_is_reported_rather_than_clamped_into_range() {
        // `--page 200` is above the protocol ceiling. Serving thirty-two
        // instead would look identical to a registry that held thirty-two.
        let runtime = runtime_root();
        let listener = listener(&runtime);
        let (exit, stdout, stderr) = invoke(&runtime, &list(&["--page", "200"]));
        assert_eq!(exit, 2);
        assert!(stdout.is_empty());
        assert_eq!(stderr, "automonique automation refused: invalid_page\n");
        assert_never_connected(&listener);

        // The ceiling itself is admitted, so the refusal above is a bound and
        // not an off-by-one.
        let server = serve_once(listener, |request| AutomationResponse::AutomationList {
            request_id: request.request_id().clone(),
            page: AutomationListPage::new(Vec::new(), AutomationContinuation::Complete)
                .expect("page"),
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
            b"automonique automation refused: runtime_unavailable\n"
        );
    }
}
