// SPDX-License-Identifier: Elastic-2.0

//! Claim or release one GitHub ticket for a local Claude Code session.
//!
//! ```text
//! automonique ticket claim <github-url> --holder claude:<session>
//! automonique ticket release <github-url> --holder claude:<session>
//! ```
//!
//! The daemon owns the Slack status reactions on the messages that posted a
//! ticket. A session therefore never reacts itself: it tells the daemon it has
//! started (`claim`) or stopped (`release`), and the daemon decides what the
//! channel sees — 👀 for work under way, ✅ only once the ticket is verifiably
//! finished.
//!
//! The answer is one JSON line on stdout:
//!
//! ```text
//! {"conflicts":[{"holder":"monique-job:…","status":"running"}],"posts_found":1,"reacted":1}
//! ```
//!
//! `posts_found` counts the Slack posts the daemon knows for the ticket,
//! `reacted` the posts this call reacted to, and `conflicts` every other claim
//! still competing for the ticket — a Monique job awaiting approval, queued or
//! running, or another session. A conflict is reported, not refused: the
//! caller decides whether to keep working.

use std::ffi::{OsStr, OsString};
use std::io::Write;

use automonique_protocol::admin::{AdminResponse, TicketClaim};

use crate::admin_client;

/// One claim or release as argv named it.
#[derive(Clone)]
pub(crate) struct Operation {
    pub release: bool,
    pub issue_url: OsString,
    pub holder: OsString,
}

/// Execute one ticket verb against the daemon's local admin socket.
pub(crate) fn run<W: Write, E: Write>(
    operation: &Operation,
    runtime: Option<&OsStr>,
    stdout: &mut W,
    stderr: &mut E,
) -> u8 {
    let verb = if operation.release {
        "release"
    } else {
        "claim"
    };
    let (Some(issue_url), Some(holder)) = (operation.issue_url.to_str(), operation.holder.to_str())
    else {
        let _ = writeln!(
            stderr,
            "automonique ticket {verb} refused: invalid_argument"
        );
        return 2;
    };
    let Ok(claim) = TicketClaim::new(issue_url, holder) else {
        let _ = writeln!(
            stderr,
            "automonique ticket {verb} refused: invalid_argument"
        );
        return 2;
    };
    match admin_client::request(
        runtime,
        admin_client::Operation::TicketClaim {
            claim,
            release: operation.release,
        },
    ) {
        Ok(AdminResponse::TicketClaimed {
            posts_found,
            reacted,
            conflicts,
            ..
        }) => {
            let rendered = serde_json::json!({
                "conflicts": conflicts
                    .iter()
                    .map(|conflict| serde_json::json!({
                        "holder": conflict.holder(),
                        "status": conflict.status(),
                    }))
                    .collect::<Vec<_>>(),
                "posts_found": posts_found,
                "reacted": reacted,
            });
            u8::from(writeln!(stdout, "{rendered}").is_err())
        }
        Ok(_) => {
            let _ = writeln!(
                stderr,
                "automonique ticket {verb} refused: response_mismatch"
            );
            1
        }
        Err(error) => {
            let _ = writeln!(
                stderr,
                "automonique ticket {verb} refused: {}",
                error.category()
            );
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;

    use automonique_protocol::admin::{AdminRequest, TicketClaimConflict};
    use automonique_protocol::codec::{FrameDecode, decode_frame, encode_frame};

    /// A one-shot daemon on a private runtime directory that answers the one
    /// request it receives with `answer`, and hands the request back.
    fn fake_daemon(
        answer: impl FnOnce(&AdminRequest) -> AdminResponse + Send + 'static,
    ) -> (tempfile::TempDir, std::thread::JoinHandle<AdminRequest>) {
        let runtime = tempfile::tempdir().expect("runtime");
        std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700))
            .expect("runtime mode");
        let product = runtime.path().join("automonique");
        std::fs::create_dir(&product).expect("product runtime");
        std::fs::set_permissions(&product, std::fs::Permissions::from_mode(0o700))
            .expect("product mode");
        let socket = product.join("admin.sock");
        let listener = UnixListener::bind(&socket).expect("listener");
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .expect("socket mode");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut prefix = [0_u8; 4];
            stream.read_exact(&mut prefix).expect("request prefix");
            let mut body = vec![0_u8; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut body).expect("request body");
            let mut framed = prefix.to_vec();
            framed.extend_from_slice(&body);
            let FrameDecode::Frame { payload, .. } = decode_frame(&framed).expect("frame") else {
                panic!("incomplete request frame");
            };
            let request = AdminRequest::from_canonical_bytes(payload).expect("request");
            let response = answer(&request)
                .to_message()
                .expect("response")
                .to_canonical_bytes();
            let mut frame = Vec::new();
            encode_frame(&response, &mut frame).expect("frame");
            std::io::Write::write_all(&mut stream, &frame).expect("write");
            request
        });
        (runtime, server)
    }

    fn operation(release: bool) -> Operation {
        Operation {
            release,
            issue_url: OsString::from("https://github.com/example/project/issues/42"),
            holder: OsString::from("claude:session-1"),
        }
    }

    #[test]
    fn a_claim_prints_the_daemons_answer_as_one_json_line() {
        let (runtime, server) = fake_daemon(|request| AdminResponse::TicketClaimed {
            request_id: request.request_id().clone(),
            posts_found: 2,
            reacted: 1,
            conflicts: vec![
                TicketClaimConflict::new("monique-job:job-1", "running").expect("conflict"),
            ],
        });
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(
            &operation(false),
            Some(runtime.path().as_os_str()),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&stderr));
        assert_eq!(
            String::from_utf8(stdout).expect("utf-8"),
            "{\"conflicts\":[{\"holder\":\"monique-job:job-1\",\"status\":\"running\"}],\"posts_found\":2,\"reacted\":1}\n"
        );
        let request = server.join().expect("server");
        assert_eq!(
            request.command(),
            automonique_protocol::admin::AdminCommand::TicketClaim
        );
        assert_eq!(
            request.ticket().map(TicketClaim::holder),
            Some("claude:session-1")
        );
    }

    #[test]
    fn a_release_carries_its_own_command_and_a_refusal_is_reported_by_category() {
        let (runtime, server) = fake_daemon(|request| AdminResponse::Refused {
            request_id: request.request_id().clone(),
            category: automonique_protocol::admin::AdminRefusalCategory::new(
                "slack_tickets_unavailable",
            )
            .expect("category"),
        });
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(
            &operation(true),
            Some(runtime.path().as_os_str()),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 1);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8(stderr).expect("utf-8"),
            "automonique ticket release refused: slack_tickets_unavailable\n"
        );
        assert_eq!(
            server.join().expect("server").command(),
            automonique_protocol::admin::AdminCommand::TicketRelease
        );
    }

    #[test]
    fn an_invalid_holder_is_refused_before_anything_is_sent() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run(
            &Operation {
                release: false,
                issue_url: OsString::from("https://github.com/example/project/issues/42"),
                holder: OsString::from("monique-job:job-1"),
            },
            None,
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 2);
        assert_eq!(
            String::from_utf8(stderr).expect("utf-8"),
            "automonique ticket claim refused: invalid_argument\n"
        );
    }
}
