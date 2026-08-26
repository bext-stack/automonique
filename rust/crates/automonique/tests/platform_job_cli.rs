// SPDX-License-Identifier: Elastic-2.0

//! `automonique platform-job` against a daemon whose inventory no longer fits
//! one snapshot response.
//!
//! The Manage fleet worker runs this command for every AI Operations
//! `submit_job` it is delivered, so it is the last hop of the federated
//! AI Operations -> node -> execution path. The serving daemon answers an
//! empty snapshot request, which asks for everything, with the typed
//! `snapshot_too_large` refusal as soon as its resource inventory exceeds one
//! frame; a command that discovered its node by reading the whole inventory
//! therefore failed before it could execute anything. The fake daemon here
//! refuses exactly like production and records what the command asked for.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;

use automonique_daemon::CURRENT_NODE_ALIAS;
use automonique_protocol::codec::{FrameDecode, decode_frame, encode_frame};
use automonique_protocol::platform::{
    ActionReceipt, CursorTopic, Freshness, FreshnessState, PlatformCursor, PlatformRequest,
    PlatformResponse, PlatformText, ReceiptId, ReceiptOutcome, ResourceAuthority,
    ResourceCoordinate, ResourceId, ResourceKind, ResourceRecord, Snapshot,
};
use automonique_protocol::platform_api::{PlatformRequestMessage, PlatformResponseMessage};
use automonique_protocol::primitives::{EpochMillis, Revision};

/// The serving generation's concrete node identity, as the alias resolves it.
const NODE_ID: &str = "daemon-4242-reload-0123456789abcdef";
const NODE_REVISION: u64 = 206;
const PROMPT: &str = "Reply with exactly PLATFORM-JOB-ALIAS-OK and nothing else.";

/// What the fake daemon was asked, in arrival order.
#[derive(Debug)]
enum Observed {
    Snapshot(Vec<ResourceCoordinate>),
    Execute {
        target: ResourceCoordinate,
        expected_revision: Option<Revision>,
        parameter: Option<String>,
    },
    GetReceipt,
}

fn read_frame(stream: &mut UnixStream) -> Option<Vec<u8>> {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix).ok()?;
    let length = usize::try_from(u32::from_be_bytes(prefix)).ok()?;
    let mut frame = vec![0_u8; 4 + length];
    frame[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut frame[4..]).ok()?;
    match decode_frame(&frame).ok()? {
        FrameDecode::Frame { payload, .. } => Some(payload.to_vec()),
        FrameDecode::NeedMore { .. } => None,
    }
}

fn write_frame(stream: &mut UnixStream, payload: &[u8]) {
    let mut frame = Vec::new();
    encode_frame(payload, &mut frame).expect("response frame");
    stream.write_all(&frame).expect("response written");
}

fn text(value: &str) -> PlatformText {
    PlatformText::new(value).expect("bounded text")
}

fn concrete_node() -> ResourceCoordinate {
    ResourceCoordinate::new(
        ResourceAuthority::Automonique,
        ResourceKind::Node,
        ResourceId::new(NODE_ID).expect("node id"),
    )
}

fn is_current_alias(resource: &ResourceCoordinate) -> bool {
    resource.authority == ResourceAuthority::Automonique
        && resource.kind == ResourceKind::Node
        && resource.id.as_str() == CURRENT_NODE_ALIAS
}

fn receipt(
    target: ResourceCoordinate,
    outcome: ReceiptOutcome,
    explanation: Option<&str>,
) -> ActionReceipt {
    ActionReceipt {
        id: ReceiptId::new("receipt-1").expect("receipt id"),
        action: automonique_protocol::platform::PlatformAction::SubmitRequest,
        target,
        outcome,
        revision: Revision::new(NODE_REVISION + 1).expect("revision"),
        recorded_at: EpochMillis::from_millis(1_787_768_400_000),
        explanation: explanation.map(text),
    }
}

/// A daemon that refuses the whole inventory, resolves `node/current`, accepts
/// the execute and completes it on the first receipt read. Returns once the
/// terminal receipt has been handed out.
fn serve(listener: UnixListener, observed: &mpsc::Sender<Observed>) {
    for stream in listener.incoming() {
        let mut stream = stream.expect("accepted connection");
        while let Some(payload) = read_frame(&mut stream) {
            let message =
                PlatformRequestMessage::from_canonical_bytes(&payload).expect("platform request");
            let mut terminal = false;
            let response = match message.request() {
                PlatformRequest::Snapshot(request) => {
                    observed
                        .send(Observed::Snapshot(request.resources.clone()))
                        .expect("observer");
                    if request.resources.is_empty() {
                        PlatformResponse::Refused {
                            outcome: ReceiptOutcome::Rejected,
                            explanation: text("snapshot_too_large"),
                        }
                    } else {
                        let resources = if request.resources.iter().any(is_current_alias) {
                            vec![ResourceRecord {
                                resource: concrete_node(),
                                freshness: Freshness {
                                    state: FreshnessState::Fresh,
                                    observed_at: EpochMillis::from_millis(1_787_768_383_652),
                                    revision: Revision::new(NODE_REVISION).expect("revision"),
                                },
                                summary: text("daemon ready"),
                            }]
                        } else {
                            Vec::new()
                        };
                        PlatformResponse::Snapshot(Snapshot {
                            resources,
                            cursor: PlatformCursor {
                                authority: ResourceAuthority::Automonique,
                                topic: CursorTopic::new("platform").expect("topic"),
                                sequence: Revision::new(727).expect("sequence"),
                            },
                        })
                    }
                }
                PlatformRequest::Execute(request) => {
                    observed
                        .send(Observed::Execute {
                            target: request.target.clone(),
                            expected_revision: request.expected_revision,
                            parameter: request
                                .parameter
                                .as_ref()
                                .map(|value| value.as_str().to_owned()),
                        })
                        .expect("observer");
                    PlatformResponse::Receipt(receipt(
                        request.target.clone(),
                        ReceiptOutcome::Accepted,
                        None,
                    ))
                }
                PlatformRequest::GetReceipt(_) => {
                    observed.send(Observed::GetReceipt).expect("observer");
                    terminal = true;
                    PlatformResponse::Receipt(receipt(
                        concrete_node(),
                        ReceiptOutcome::Completed,
                        Some("run=fixture-run;session=fixture-session"),
                    ))
                }
                _ => PlatformResponse::Refused {
                    outcome: ReceiptOutcome::Rejected,
                    explanation: text("unexpected request"),
                },
            };
            let bytes = PlatformResponseMessage::new(message.request_id().clone(), response)
                .to_message()
                .expect("platform response")
                .to_canonical_bytes();
            write_frame(&mut stream, &bytes);
            if terminal {
                return;
            }
        }
    }
}

#[test]
fn platform_job_discovers_its_node_through_the_current_alias_and_completes() {
    let runtime = tempfile::tempdir().expect("private runtime directory");
    std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private runtime directory");
    let socket = runtime.path().join("admin.sock");
    let listener = UnixListener::bind(&socket).expect("admin socket");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
        .expect("private admin socket");
    let (observer, observed) = mpsc::channel();
    // Not joined: a command that fails before its terminal receipt leaves the
    // fake daemon waiting in accept, and the observations below are complete
    // once the command has exited because every request was answered in line.
    let _daemon = thread::spawn(move || serve(listener, &observer));

    let mut child = Command::new(env!("CARGO_BIN_EXE_automonique"))
        .args([
            "platform-job",
            "--socket",
            socket.to_str().expect("socket path"),
            "--idempotency-key",
            "cmd_epic66-alias-regression",
            "--timeout-seconds",
            "30",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("automonique starts");
    child
        .stdin
        .take()
        .expect("prompt pipe")
        .write_all(format!("{PROMPT}\n").as_bytes())
        .expect("prompt delivered");
    let output = child.wait_with_output().expect("automonique exits");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "platform-job must complete against a daemon that refuses the whole inventory: {stderr}"
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    let report: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON report");
    assert_eq!(report["schema"], "automonique.platform-job/v1", "{stdout}");
    assert_eq!(report["outcome"], "completed", "{stdout}");
    assert_eq!(
        report["explanation"], "run=fixture-run;session=fixture-session",
        "{stdout}"
    );

    let observed: Vec<Observed> = observed.try_iter().collect();
    let snapshots: Vec<&Vec<ResourceCoordinate>> = observed
        .iter()
        .filter_map(|entry| match entry {
            Observed::Snapshot(resources) => Some(resources),
            _ => None,
        })
        .collect();
    assert!(
        !snapshots.is_empty(),
        "the command discovers its node through a snapshot: {observed:?}"
    );
    for resources in &snapshots {
        assert!(
            !resources.is_empty(),
            "a snapshot of everything is refused by the daemon and must never be asked for: {observed:?}"
        );
        assert!(
            resources.iter().all(is_current_alias),
            "the only resource the command needs is node/current: {observed:?}"
        );
    }
    let Some(Observed::Execute {
        target,
        expected_revision,
        parameter,
    }) = observed
        .iter()
        .find(|entry| matches!(entry, Observed::Execute { .. }))
    else {
        panic!("the command executes on the resolved node: {observed:?}");
    };
    assert_eq!(
        target,
        &concrete_node(),
        "the execute names the concrete identity the alias resolved to, never the alias"
    );
    assert_eq!(
        *expected_revision,
        Some(Revision::new(NODE_REVISION).expect("revision")),
        "the execute is bound to the revision the snapshot reported"
    );
    assert_eq!(parameter.as_deref(), Some(PROMPT));
    assert!(
        observed
            .iter()
            .any(|entry| matches!(entry, Observed::GetReceipt)),
        "the command waits for the durable terminal receipt: {observed:?}"
    );
}
