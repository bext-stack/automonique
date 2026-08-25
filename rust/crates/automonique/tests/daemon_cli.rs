// SPDX-License-Identifier: Elastic-2.0

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use automonique_store::{
    InboxSubmission, LeaseRequest, OutboxClaimRequest, SchedulerClaim, Store, TerminalRun,
    TerminalState,
    reload_audit::{BeginReload, ReloadAudit},
};

fn roots() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let root = tempfile::tempdir().expect("temporary root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("private root");
    let runtime = root.path().join("runtime");
    let state = root.path().join("state");
    std::fs::create_dir(&runtime).expect("runtime root");
    std::fs::create_dir(&state).expect("state root");
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))
        .expect("private runtime");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))
        .expect("private state");
    (root, runtime, state)
}

fn command(runtime: &std::path::Path, state: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_automonique"));
    command
        .env("XDG_RUNTIME_DIR", runtime)
        .env("XDG_STATE_HOME", state)
        .env_remove("AUTOMONIQUE_CONFIG")
        .env_remove("AUTOMONIQUE_HOME");
    command
}

fn launch(runtime: &std::path::Path, state: &std::path::Path) -> Child {
    command(runtime, state)
        .args(["daemon", "--foreground"])
        .spawn()
        .expect("launch daemon")
}

fn run(runtime: &std::path::Path, state: &std::path::Path, args: &[&str]) -> Output {
    command(runtime, state)
        .args(args)
        .output()
        .expect("run client")
}

fn run_with_stdin(
    runtime: &std::path::Path,
    state: &std::path::Path,
    args: &[&str],
    input: &[u8],
) -> Output {
    let mut child = command(runtime, state)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run client");
    child
        .stdin
        .take()
        .expect("client stdin")
        .write_all(input)
        .expect("write client stdin");
    child.wait_with_output().expect("client output")
}

/// Wait for the spawned daemon to answer a status request.
///
/// The budget is generous on purpose. Every poll spawns a fresh client binary,
/// and the daemon it is waiting for opens a private SQLite database per durable
/// module under `synchronous = FULL` — which is the crate's storage discipline
/// and grows by one file whenever a module lands. On an unloaded host readiness
/// is well under a second; under a full parallel test run the same work has to
/// share the disk with everything else, and a budget tight enough to catch a
/// hang was also tight enough to fail on a busy machine. A daemon that is
/// genuinely stuck still fails here, a few seconds later.
fn wait_ready(runtime: &std::path::Path, state: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let output = run(runtime, state, &["status", "--json"]);
        if output.status.success() {
            return;
        }
        assert!(Instant::now() < deadline, "daemon did not become ready");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn cli_reads_generation_history_and_one_durable_reload_epoch() {
    let (_root, runtime, state) = roots();
    let mut daemon = launch(&runtime, &state);
    wait_ready(&runtime, &state);

    let generations = run(&runtime, &state, &["generations"]);
    assert!(
        generations.status.success(),
        "{}",
        String::from_utf8_lossy(&generations.stderr)
    );
    let generations = String::from_utf8(generations.stdout).expect("generation history");
    assert!(
        generations.contains("generation foreground\n"),
        "{generations}"
    );
    assert!(generations.contains("tenure epoch=1 "), "{generations}");
    assert!(generations.contains("ended_ms=- end=open"), "{generations}");

    let missing = run(&runtime, &state, &["reload-status", "reload-missing"]);
    assert!(!missing.status.success());
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("reload_not_found"),
        "{}",
        String::from_utf8_lossy(&missing.stderr)
    );

    let product = state.join("automonique");
    let mut audit = ReloadAudit::open(product.join("reload-audit.sqlite3"))
        .expect("open reload audit beside daemon");
    audit
        .begin(BeginReload {
            reload_id: "reload-operator-read",
            source_generation_id: "foreground",
            source_lease_epoch: 1,
            target_generation_id: "foreground-candidate",
            target_release_digest: concat!(
                "sha256:",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            created_at_ms: 123,
        })
        .expect("record reload epoch");

    let status = run(&runtime, &state, &["reload-status", "reload-operator-read"]);
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status = String::from_utf8(status.stdout).expect("reload status");
    assert!(
        status.contains("reload reload-operator-read phase=created revision=1 source=foreground@1 target=foreground-candidate"),
        "{status}"
    );
    assert!(
        status.contains("transition revision=1 phase=created observed_ms=123 failure=-"),
        "{status}"
    );

    assert!(run(&runtime, &state, &["shutdown"]).status.success());
    assert!(daemon.wait().expect("wait daemon").success());
}

fn seed_expired_outbox(state: &std::path::Path) -> (u64, String, u64, u64, u64) {
    let product = state.join("automonique");
    std::fs::create_dir(&product).expect("state directory");
    std::fs::set_permissions(&product, std::fs::Permissions::from_mode(0o700))
        .expect("private state");
    let mut store = Store::open(product.join("automonique.sqlite3")).expect("store");
    let generation = store
        .acquire_generation_lease(LeaseRequest {
            generation_id: "foreground",
            holder_id: "crashed-cli",
            now_ms: 1,
            ttl_ms: 100,
        })
        .expect("generation");
    store
        .submit_inbox(InboxSubmission {
            transport: "local.synthetic",
            transport_key: "cli:outbox",
            scope: "workspace:cli-outbox",
            payload: b"inbox-private",
            received_ms: 2,
        })
        .expect("inbox");
    let run = store
        .claim_next(SchedulerClaim {
            transport: "local.synthetic",
            generation_id: "foreground",
            holder_id: "crashed-cli",
            lease_epoch: generation.epoch,
            now_ms: 3,
        })
        .expect("claim")
        .expect("run");
    store
        .finish_run(TerminalRun {
            run_id: run.run_id,
            generation_id: "foreground",
            holder_id: "crashed-cli",
            lease_epoch: generation.epoch,
            expected_revision: 1,
            now_ms: 4,
            state: TerminalState::Succeeded,
            event_kind: "run.succeeded",
            event_payload: b"event",
            outbox_intent_key: "fake:cli-outbox",
            outbox_kind: "fake.receipt",
            outbox_payload: b"must-never-appear-in-cli",
        })
        .expect("outbox");
    let lease = store
        .claim_outbox(OutboxClaimRequest {
            transport: "fake",
            kind: "fake.receipt",
            generation_id: "foreground",
            holder_id: "crashed-cli",
            lease_epoch: generation.epoch,
            now_ms: 5,
            ttl_ms: 10,
        })
        .expect("claim outbox")
        .expect("outbox lease");
    (
        u64::try_from(lease.outbox_id).expect("id"),
        lease.lease_token,
        generation.epoch,
        lease.attempt,
        lease.revision,
    )
}

#[test]
fn cli_inspects_and_dead_letters_exact_expired_outbox_without_exposing_payload() {
    let (_root, runtime, state) = roots();
    let (outbox_id, token, epoch, attempt, revision) = seed_expired_outbox(&state);
    let mut daemon = launch(&runtime, &state);
    wait_ready(&runtime, &state);
    let degraded = run(&runtime, &state, &["status", "--json"]);
    assert!(degraded.status.success());
    let degraded: serde_json::Value =
        serde_json::from_slice(&degraded.stdout).expect("degraded JSON status");
    assert_eq!(degraded["state"], "failed");
    assert_eq!(degraded["accepting_intake"], false);
    assert_eq!(degraded["operational"]["reconciliation_pending"], 1);
    assert_eq!(degraded["operational"]["outbox_in_flight_ambiguous"], 1);
    assert_eq!(
        degraded["operational"]["provider_available"],
        serde_json::json!({"state": "measured", "value": 0})
    );
    let id = outbox_id.to_string();
    let inspect = run(&runtime, &state, &["outbox", "inspect", &id]);
    assert!(
        inspect.status.success(),
        "{}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let inspected = String::from_utf8(inspect.stdout).expect("inspection");
    assert!(inspected.contains("state=in_flight"), "{inspected}");
    assert!(
        inspected.contains("lease_token_present=true"),
        "{inspected}"
    );
    assert!(!inspected.contains(&token), "{inspected}");
    assert!(
        !inspected.contains("must-never-appear-in-cli"),
        "{inspected}"
    );

    let epoch = epoch.to_string();
    let attempt = attempt.to_string();
    let revision = revision.to_string();
    let private_input = "operator_refused\n";
    let wrong = run_with_stdin(
        &runtime,
        &state,
        &[
            "outbox",
            "reconcile",
            "dead-letter",
            &id,
            "wrong-generation",
            &epoch,
            &attempt,
            &revision,
        ],
        private_input.as_bytes(),
    );
    assert!(!wrong.status.success());
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("stale_evidence"));
    let unchanged = run(&runtime, &state, &["outbox", "inspect", &id]);
    assert!(String::from_utf8_lossy(&unchanged.stdout).contains("state=in_flight"));

    let exact_args = [
        "outbox",
        "reconcile",
        "dead-letter",
        &id,
        "foreground",
        &epoch,
        &attempt,
        &revision,
    ];
    let resolved = run_with_stdin(&runtime, &state, &exact_args, private_input.as_bytes());
    assert!(
        resolved.status.success(),
        "{}",
        String::from_utf8_lossy(&resolved.stderr)
    );
    assert!(String::from_utf8_lossy(&resolved.stdout).contains("state=dead_lettered"));
    assert!(String::from_utf8_lossy(&resolved.stdout).contains("duplicate=false"));
    let retry = run_with_stdin(&runtime, &state, &exact_args, private_input.as_bytes());
    assert!(
        retry.status.success(),
        "{}",
        String::from_utf8_lossy(&retry.stderr)
    );
    assert!(String::from_utf8_lossy(&retry.stdout).contains("duplicate=true"));

    assert!(run(&runtime, &state, &["shutdown"]).status.success());
    assert!(daemon.wait().expect("shutdown").success());
    daemon = launch(&runtime, &state);
    wait_ready(&runtime, &state);
    let reopened = run(&runtime, &state, &["outbox", "inspect", &id]);
    assert!(String::from_utf8_lossy(&reopened.stdout).contains("state=dead_lettered"));
    assert!(run(&runtime, &state, &["shutdown"]).status.success());
    assert!(daemon.wait().expect("restart shutdown").success());
}

#[test]
fn the_product_binary_serves_status_and_shutdown_end_to_end() {
    let (_root, runtime, state) = roots();
    let mut daemon = launch(&runtime, &state);
    wait_ready(&runtime, &state);

    let human = run(&runtime, &state, &["status"]);
    assert!(human.status.success());
    let human = String::from_utf8(human.stdout).expect("UTF-8 status");
    assert!(human.contains("Automonique daemon: ready"), "{human}");
    assert!(human.contains("accepting intake: true"), "{human}");
    assert!(human.contains("telegram: disabled_no_client"), "{human}");
    assert!(human.contains("telegram poller epoch: -"), "{human}");
    assert!(human.contains("reconciliation pending: 0\n"), "{human}");
    assert!(human.contains("outbox ambiguous: 0\n"), "{human}");
    assert!(
        human.contains("telegram offset lag: unavailable\n"),
        "{human}"
    );
    assert!(human.contains("provider available: measured\n"), "{human}");
    assert!(
        human.contains("sandbox launch refusals: unavailable\n"),
        "{human}"
    );
    // The durable-state block follows the operational metrics: a fresh daemon
    // under its first generation has one open tenure at epoch 1, no runs, and
    // its automation scheduler worker on its thread.
    assert!(human.contains("runs registered: 0\n"), "{human}");
    assert!(human.contains("open tenure epoch: 1\n"), "{human}");
    assert!(
        human.ends_with("automation scheduler workers: 1\n"),
        "{human}"
    );

    let json = run(&runtime, &state, &["status", "--json"]);
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).expect("JSON status");
    assert_eq!(value["state"], "ready");
    assert_eq!(value["accepting_intake"], true);
    assert_eq!(value["telegram_state"], "disabled_no_client");
    assert_eq!(value["telegram_poller_epoch"], serde_json::Value::Null);
    assert!(value["operational"]["observed_ms"].as_u64().is_some());
    assert_eq!(value["operational"]["reconciliation_pending"], 0);
    assert_eq!(value["operational"]["outbox_in_flight_ambiguous"], 0);
    assert_eq!(value["operational"]["telegram_pollers_live"], 0);
    assert_eq!(value["operational"]["telegram_pollers_expired"], 0);
    assert_eq!(
        value["operational"]["provider_available"],
        serde_json::json!({"state": "measured", "value": 0})
    );
    for unavailable in ["telegram_offset_lag", "sandbox_launch_refusals"] {
        assert_eq!(
            value["operational"][unavailable],
            serde_json::json!({"state": "unavailable", "value": null})
        );
    }
    assert!(
        value["event_cursor"]
            .as_u64()
            .is_some_and(|cursor| cursor >= 1)
    );
    assert_eq!(
        value["durable_state"]["automation_scheduler_workers"],
        serde_json::json!({"state": "measured", "value": 1})
    );

    // The `automation:` key namespace is the scheduler's; the product binary
    // refuses it by name before it dials, and nothing reaches the lane.
    let reserved = run_with_stdin(
        &runtime,
        &state,
        &["submit", "workspace:test", "automation:cli:1"],
        b"synthetic local task",
    );
    assert_eq!(reserved.status.code(), Some(2));
    assert_eq!(
        reserved.stderr,
        b"automonique submit refused: idempotency_key_reserved\n"
    );

    let accepted = run_with_stdin(
        &runtime,
        &state,
        &["submit", "workspace:test", "cli:test:1"],
        b"synthetic local task",
    );
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    assert_eq!(
        accepted.stdout,
        b"Automonique synthetic task accepted: inbox_id=1 duplicate=false\n"
    );

    let after_first = run(&runtime, &state, &["status", "--json"]);
    assert!(after_first.status.success());
    let after_first: serde_json::Value =
        serde_json::from_slice(&after_first.stdout).expect("status after first execution");
    assert_eq!(after_first["inbox_pending"], 0);
    assert_eq!(after_first["running"], 0);
    assert_eq!(after_first["outbox_pending"], 1);
    let terminal_cursor = after_first["event_cursor"]
        .as_u64()
        .expect("terminal event cursor");

    let duplicate = run_with_stdin(
        &runtime,
        &state,
        &["submit", "workspace:test", "cli:test:1"],
        b"synthetic local task",
    );
    assert!(
        duplicate.status.success(),
        "{}",
        String::from_utf8_lossy(&duplicate.stderr)
    );
    assert_eq!(
        duplicate.stdout,
        b"Automonique synthetic task accepted: inbox_id=1 duplicate=true\n"
    );

    let after_submit = run(&runtime, &state, &["status", "--json"]);
    assert!(after_submit.status.success());
    let value: serde_json::Value =
        serde_json::from_slice(&after_submit.stdout).expect("JSON status after submission");
    assert_eq!(value["inbox_pending"], 0);
    assert_eq!(value["running"], 0);
    assert_eq!(value["outbox_pending"], 1);
    assert_eq!(value["event_cursor"], terminal_cursor);

    let shutdown = run(&runtime, &state, &["shutdown"]);
    assert!(shutdown.status.success());
    assert_eq!(shutdown.stdout, b"Automonique daemon shutdown accepted\n");
    assert!(daemon.wait().expect("wait daemon").success());
    assert!(!runtime.join("automonique/admin.sock").exists());
    assert!(state.join("automonique/automonique.sqlite3").is_file());

    // A process restart observes the durable terminal and never creates a
    // second run or fake receipt for the completed input.
    daemon = launch(&runtime, &state);
    wait_ready(&runtime, &state);
    let restarted = run(&runtime, &state, &["status", "--json"]);
    assert!(restarted.status.success());
    let restarted: serde_json::Value =
        serde_json::from_slice(&restarted.stdout).expect("status after restart");
    assert_eq!(restarted["inbox_pending"], 0);
    assert_eq!(restarted["running"], 0);
    assert_eq!(restarted["outbox_pending"], 1);

    // Reusing a stable key with different input fails closed without stopping
    // the daemon or changing the one durable result.
    let conflict = run_with_stdin(
        &runtime,
        &state,
        &["submit", "workspace:test", "cli:test:1"],
        b"changed task",
    );
    assert!(!conflict.status.success());
    let after_conflict = run(&runtime, &state, &["status", "--json"]);
    assert!(after_conflict.status.success());
    let after_conflict: serde_json::Value =
        serde_json::from_slice(&after_conflict.stdout).expect("status after conflict");
    assert_eq!(after_conflict["outbox_pending"], 1);

    // Command-looking fixture text stays inert: the only effects are durable
    // SQLite records in the configured state root.
    let marker = state.join("must-not-exist");
    let command_like = format!("touch {}", marker.display());
    let inert = run_with_stdin(
        &runtime,
        &state,
        &["submit", "workspace:inert", "cli:test:2"],
        command_like.as_bytes(),
    );
    assert!(inert.status.success());
    let failed = run_with_stdin(
        &runtime,
        &state,
        &["submit", "workspace:failure", "cli:test:3"],
        b"fail",
    );
    assert!(failed.status.success());
    let final_status = run(&runtime, &state, &["status", "--json"]);
    assert!(final_status.status.success());
    let final_status: serde_json::Value =
        serde_json::from_slice(&final_status.stdout).expect("final status");
    assert_eq!(final_status["inbox_pending"], 0);
    assert_eq!(final_status["running"], 0);
    assert_eq!(final_status["outbox_pending"], 3);
    assert!(!marker.exists());

    assert!(run(&runtime, &state, &["shutdown"]).status.success());
    assert!(daemon.wait().expect("wait restarted daemon").success());
    let store = automonique_store::Store::open(state.join("automonique/automonique.sqlite3"))
        .expect("inspect durable state");
    assert_eq!(store.run_snapshot(1).expect("first run").state, "succeeded");
    assert_eq!(store.run_snapshot(2).expect("inert run").state, "succeeded");
    assert_eq!(store.run_snapshot(3).expect("failed run").state, "failed");
    for outbox_id in 1..=3 {
        let outbox = store.outbox_snapshot(outbox_id).expect("fake receipt");
        assert_eq!(outbox.kind, "fake.receipt");
        assert_eq!(outbox.state, "pending");
    }
}
