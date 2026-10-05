// SPDX-License-Identifier: Elastic-2.0

//! Executable tests of the Manage fleet worker script.
//!
//! The worker is a shell program whose behaviour is process handling: it
//! starts providers, bounds them in time, cleans up after them and reports to
//! Manage. Asserting on its text proves none of that, so these tests run the
//! real script against a local stand-in for the Manage platform endpoint and a
//! stand-in provider binary, and observe what it reports and which processes
//! are left.

use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const MANAGE_WORKER: &str = include_str!("../../../../tools/run_manage_fleet_worker.sh");
const NODE: &str = "worker-under-test";
const PATIENCE: Duration = Duration::from_secs(60);

/// Stand-in provider. It answers the auth probe, and on `run` picks its
/// behaviour from a `MODE:<name>` word in the prompt it reads on stdin.
const FAKE_PROVIDER: &str = r#"#!/usr/bin/env bash
if [[ "$*" == *"auth status"* ]]; then
    printf '%s\n' '{"any_available":true}'
    exit 0
fi
prompt=$(cat)
mode=$(grep -o 'MODE:[a-z]*' <<<"$prompt" | head -n 1)
mode=${mode#MODE:}
dir=${FAKE_PROVIDER_DIR:?}
printf '%s\n' "$$" >"$dir/$mode.pid"
printf '%s\n' "$*" >"$dir/$mode.args"
printf '%s\n' "${JCODE_OPENAI_REASONING_EFFORT:-}" >"$dir/$mode.effort"
printf '%s\n' "{\"type\":\"start\",\"model\":\"fake-model-1\",\"provider\":\"FakeAI\",\"session_id\":\"session_fake_$mode\"}"
printf '%s\n' '{"type":"tokens","input":100,"output":7,"cache_read_input":60,"cache_creation_input":null}'
printf '%s\n' '{"type":"tool_start","name":"bash","id":"call_1"}'
printf '%s\n' '{"type":"tokens","input":200,"output":11,"cache_read_input":150,"cache_creation_input":null}'
finish() {
    printf '%s\n' "{\"type\":\"done\",\"text\":\"Finished. https://github.com/example/repo/issues/1#issuecomment-5\",\"model\":\"fake-model-1\",\"provider\":\"FakeAI\",\"upstream_provider\":null,\"usage\":{\"input_tokens\":200,\"output_tokens\":11,\"cache_read_input_tokens\":150,\"cache_creation_input_tokens\":null},\"session_id\":\"session_fake_$mode\"}"
}
case "$mode" in
    done|limit)
        finish
        ;;
    fail)
        printf '%s' '{"type":"tok'
        exit 3
        ;;
    slow)
        sleep 3
        finish
        ;;
    leftover)
        sleep 300 >/dev/null 2>&1 &
        printf '%s\n' "$!" >"$dir/$mode.child.pid"
        finish
        ;;
    hang)
        # A child that ignores TERM, like a daemon that has to be killed.
        ( trap '' TERM; exec sleep 300 ) >/dev/null 2>&1 &
        printf '%s\n' "$!" >"$dir/$mode.child.pid"
        exec sleep 300
        ;;
esac
"#;

/// Stand-in for Claude Code, the second engine of a JCode worker. It is signed
/// in while `claude-signed-in` exists, answers the tool-less triage call from a
/// `ROUTE:<verdict>` word in the ticket, and otherwise runs the job.
const FAKE_CLAUDE: &str = r#"#!/usr/bin/env bash
dir=${FAKE_PROVIDER_DIR:?}
if [[ "$*" == "auth status --json" ]]; then
    if [[ -e "$dir/claude-signed-in" ]]; then
        printf '%s\n' '{"loggedIn":true,"authMethod":"claude.ai"}'
        exit 0
    fi
    printf '%s\n' '{"loggedIn":false,"authMethod":"none"}'
    exit 1
fi
prompt=$(cat)
if [[ "$*" == *"--tools"* ]]; then
    printf '%s\n' "$*" >>"$dir/claude-triage.args"
    case "$prompt" in
        *ROUTE:claude*) answer='Here it is: {\"engine\":\"claude\",\"reason\":\"new tool to build\"}' ;;
        *ROUTE:hard*) answer='{\"engine\":\"jcode\",\"effort\":\"high\",\"reason\":\"bug with unknown cause\"}' ;;
        *ROUTE:jcode*) answer='{\"engine\":\"jcode\",\"reason\":\"scoped fix\"}' ;;
        *ROUTE:other*) answer='{\"engine\":\"codex\",\"reason\":\"not an engine of this worker\"}' ;;
        *) answer='I cannot tell.' ;;
    esac
    printf '%s\n' "{\"type\":\"result\",\"is_error\":false,\"result\":\"$answer\"}"
    exit 0
fi
printf '%s\n' "$*" >>"$dir/claude-run.args"
if [[ "$prompt" == *MODE:limit* ]]; then
    printf '%s\n' '{"type":"system","subtype":"init","session_id":"claude_session_1","model":"fake-claude-1"}'
    printf '%s\n' '{"type":"result","subtype":"error","is_error":true,"session_id":"claude_session_1","result":"Claude usage limit reached. Your limit will reset at 9pm."}'
    exit 1
fi
printf '%s\n' "$CLAUDE_CONFIG_DIR" >"$dir/claude-run.home"
printf '%s\n' '{"type":"system","subtype":"init","session_id":"claude_session_1","model":"fake-claude-1"}'
printf '%s\n' '{"type":"result","subtype":"success","session_id":"claude_session_1","result":"Finished. https://github.com/example/repo/issues/1#issuecomment-5","total_cost_usd":0.25,"num_turns":4,"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":20,"cache_read_input_tokens":30,"cache_creation_input_tokens":40}}'
"#;

/// Stand-in for Codex, the third engine a job can ask for by name. It is signed
/// in while `codex-signed-in` exists.
const FAKE_CODEX: &str = r#"#!/usr/bin/env bash
dir=${FAKE_PROVIDER_DIR:?}
if [[ "$*" == "login status" ]]; then
    if [[ -e "$dir/codex-signed-in" ]]; then
        printf '%s\n' 'Logged in using ChatGPT'
        exit 0
    fi
    printf '%s\n' 'Not logged in'
    exit 1
fi
cat >/dev/null
printf '%s\n' "$*" >>"$dir/codex-run.args"
printf '%s\n' "$CODEX_HOME" >"$dir/codex-run.home"
printf '%s\n' '{"type":"thread.started","thread_id":"codex_thread_1"}'
printf '%s\n' '{"type":"item.completed","item":{"type":"agent_message","text":"Finished. https://github.com/example/repo/issues/1#issuecomment-5"}}'
printf '%s\n' '{"type":"turn.completed","usage":{"input_tokens":50,"cached_input_tokens":20,"output_tokens":9}}'
"#;
const CODEX_ACCOUNT: &str = "acct-89abcdef0123456789abcdef";

/// A Claude account and a Codex account, both selected.
fn install_both_accounts(root: &Path, codex_signed_in: bool) {
    install_claude_account(root, true);
    fs::create_dir_all(root.join("agent-auth/profiles").join(CODEX_ACCOUNT)).expect("profile");
    fs::write(
        root.join("agent-auth/accounts.json"),
        json!({
            "schema": "automonique.agent-accounts/v1",
            "worker_provider": "codex",
            "selected": {"claude": CLAUDE_ACCOUNT, "codex": CODEX_ACCOUNT},
            "accounts": [
                {"id": CLAUDE_ACCOUNT, "provider": "claude", "label": "Test Claude"},
                {"id": CODEX_ACCOUNT, "provider": "codex", "label": "Test Codex"},
            ],
        })
        .to_string(),
    )
    .expect("account registry");
    executable(&root.join("bin/codex"), FAKE_CODEX);
    if codex_signed_in {
        fs::write(root.join("pids/codex-signed-in"), "").expect("signed-in marker");
    }
}
const THIRD_ENGINE: &[(&str, &str)] = &[
    ("AUTOMONIQUE_AGENT_AUTH_DIR", "{root}/agent-auth"),
    ("AUTOMONIQUE_FLEET_CLAUDE_BINARY", "{root}/bin/claude"),
    ("AUTOMONIQUE_FLEET_CODEX_BINARY", "{root}/bin/codex"),
    ("AUTOMONIQUE_FLEET_CONCURRENCY", "1"),
];

/// The account directory the dashboard writes: one Claude account, selected.
const CLAUDE_ACCOUNT: &str = "acct-0123456789abcdef01234567";
const SECOND_ENGINE: &[(&str, &str)] = &[
    ("AUTOMONIQUE_AGENT_AUTH_DIR", "{root}/agent-auth"),
    ("AUTOMONIQUE_FLEET_CLAUDE_BINARY", "{root}/bin/claude"),
];

fn install_claude_account(root: &Path, signed_in: bool) {
    for directory in ["agent-auth/health", "agent-auth/profiles"] {
        fs::create_dir_all(root.join(directory)).expect("account layout");
    }
    fs::create_dir_all(root.join("agent-auth/profiles").join(CLAUDE_ACCOUNT)).expect("profile");
    fs::write(
        root.join("agent-auth/accounts.json"),
        json!({
            "schema": "automonique.agent-accounts/v1",
            "worker_provider": "codex",
            "selected": {"claude": CLAUDE_ACCOUNT},
            "accounts": [{"id": CLAUDE_ACCOUNT, "provider": "claude", "label": "Test Claude"}],
        })
        .to_string(),
    )
    .expect("account registry");
    executable(&root.join("bin/claude"), FAKE_CLAUDE);
    if signed_in {
        fs::write(root.join("pids/claude-signed-in"), "").expect("signed-in marker");
    }
}

/// Stand-in for the GitHub CLI: every completion comment follows the report
/// shape the worker requires.
const FAKE_GH: &str =
    "#!/usr/bin/env bash\nprintf '%s\\n' 'Demande 1 : done. Vérification. Preuve.'\n";

#[derive(Default)]
struct PlatformState {
    queue: VecDeque<Value>,
    commands: Vec<Value>,
    snapshot_jobs: Vec<Value>,
    requests: Vec<Value>,
    workdir: String,
}

/// A local HTTP listener that speaks the platform runtime protocol the worker
/// uses: one `PUT` per action, a JSON document back.
struct Platform {
    port: u16,
    state: Arc<Mutex<PlatformState>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Platform {
    fn start(workdir: &Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("platform listener");
        let port = listener.local_addr().expect("platform address").port();
        let state = Arc::new(Mutex::new(PlatformState {
            workdir: workdir.to_string_lossy().into_owned(),
            ..PlatformState::default()
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let state = Arc::clone(&state);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(stream) = stream {
                        serve(stream, &state);
                    }
                }
            })
        };
        Self {
            port,
            state,
            stop,
            thread: Some(thread),
        }
    }

    fn queue_job(&self, id: &str, mode: &str) {
        self.state.lock().unwrap().queue.push_back(json!({
            "id": id,
            "prompt": format!("Handle the ticket. MODE:{mode}"),
        }));
    }

    /// A job whose ticket carries a routing word for the triage stand-in and,
    /// when Manage resolved one, the engine its label or project asks for.
    fn queue_routed_job(&self, id: &str, mode: &str, route: &str, engine: Option<&str>) {
        let mut job = json!({
            "id": id,
            "prompt": format!("Handle the ticket. MODE:{mode} ROUTE:{route}"),
        });
        if let Some(engine) = engine {
            job["engine"] = json!(engine);
        }
        self.state.lock().unwrap().queue.push_back(job);
    }

    /// A job with the routing fields Manage resolved for it, as given.
    fn queue_job_with(&self, id: &str, mode: &str, route: &str, fields: Value) {
        let mut job = json!({
            "id": id,
            "prompt": format!("Handle the ticket. MODE:{mode} ROUTE:{route}"),
        });
        for (key, value) in fields.as_object().expect("an object") {
            job[key] = value.clone();
        }
        self.state.lock().unwrap().queue.push_back(job);
    }

    /// Every runtime document of one action received so far.
    fn runtime(&self, action: &str) -> Vec<Value> {
        self.state
            .lock()
            .unwrap()
            .requests
            .iter()
            .map(|request| request["runtime"].clone())
            .filter(|runtime| runtime["action"] == action)
            .collect()
    }

    /// The terminal (`done` or `failed`) report of one job, once it arrived.
    fn terminal_report(&self, job: &str) -> Option<Value> {
        self.runtime("job")
            .into_iter()
            .find(|report| report["jobId"] == job && report["status"] != "running")
    }

    fn receipts(&self) -> Vec<Value> {
        self.state
            .lock()
            .unwrap()
            .requests
            .iter()
            .flat_map(|request| request["receipts"].as_array().cloned().unwrap_or_default())
            .collect()
    }
}

impl Drop for Platform {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(mut stream: TcpStream, state: &Arc<Mutex<PlatformState>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 8192];
    let header_end = loop {
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    };
    let head = String::from_utf8_lossy(&buffer[..header_end]).to_ascii_lowercase();
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if head.contains("expect: 100-continue") {
        let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
    }
    while buffer.len() < header_end + length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
        }
    }
    let Ok(request) = serde_json::from_slice::<Value>(&buffer[header_end..header_end + length])
    else {
        return;
    };
    let answer = {
        let mut state = state.lock().unwrap();
        let runtime = match request["runtime"]["action"].as_str().unwrap_or_default() {
            "register" => json!({"ok": true, "instance": {"id": NODE}}),
            "snapshot" => json!({
                "ok": true,
                "instances": [{"id": NODE, "name": "Test worker", "status": "online", "workdir": state.workdir}],
                "jobs": state.snapshot_jobs,
            }),
            "claim" => json!({"ok": true, "job": state.queue.pop_front()}),
            "job" if request["runtime"]["interrupted"] == true => {
                json!({"ok": true, "requeued": true})
            }
            "job" => json!({"ok": true, "job": {}}),
            _ => json!({"ok": true}),
        };
        let commands = std::mem::take(&mut state.commands);
        state.requests.push(request);
        json!({"ok": true, "runtime": runtime, "commands": commands}).to_string()
    };
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        answer.len(),
        answer
    );
}

/// One worker process with its private state directory and stand-ins.
struct Worker {
    root: tempfile::TempDir,
    platform: Platform,
    child: Option<Child>,
}

impl Worker {
    /// Lay out the state directory and stand-ins, let `prepare` queue work on
    /// the platform or write fixture files, then start the script.
    ///
    /// `{root}` in an environment value stands for the private directory.
    fn start(environment: &[(&str, &str)], prepare: impl FnOnce(&Platform, &Path)) -> Self {
        let root = tempfile::tempdir().expect("temporary root");
        let path = root.path();
        for directory in ["state/support", "work", "home", "bin", "pids"] {
            fs::create_dir_all(path.join(directory)).expect("layout");
        }
        let platform = Platform::start(&path.join("work").canonicalize().expect("workdir"));
        executable(&path.join("bin/provider"), FAKE_PROVIDER);
        executable(&path.join("bin/gh"), FAKE_GH);
        executable(&path.join("worker.sh"), MANAGE_WORKER);
        fs::write(
            path.join("state/support/fleet.conf"),
            format!(
                "base=http://127.0.0.1:{}\ninstance={NODE}\ntoken=test-token\n",
                platform.port
            ),
        )
        .expect("fleet configuration");
        fs::write(
            path.join("state/provider"),
            format!(
                "binary={}\nhome={}\nengine=jcode\n",
                path.join("bin/provider").display(),
                path.join("home").display()
            ),
        )
        .expect("provider configuration");
        prepare(&platform, path);

        let mut command = Command::new("bash");
        command
            .arg(path.join("worker.sh"))
            .current_dir(path.join("work"))
            .env_clear()
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    path.join("bin").display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("HOME", path.join("home"))
            .env("AUTOMONIQUE_STATE_DIR", path.join("state"))
            .env("AUTOMONIQUE_PLATFORM_ENDPOINT", "http://127.0.0.1:9")
            .env("AUTOMONIQUE_FLEET_WORKDIR", path.join("work"))
            .env("AUTOMONIQUE_FLEET_POLL_SECONDS", "1")
            .env("AUTOMONIQUE_FLEET_HEARTBEAT_SECONDS", "5")
            // The host running the tests may itself be short of memory.
            .env("AUTOMONIQUE_FLEET_MIN_AVAILABLE_MB", "0")
            .env("AUTOMONIQUE_FLEET_MAX_MEMORY_PRESSURE", "0")
            .env("FAKE_PROVIDER_DIR", path.join("pids"))
            .stdin(Stdio::null())
            .stdout(fs::File::create(path.join("worker.out")).expect("stdout file"))
            .stderr(fs::File::create(path.join("worker.err")).expect("stderr file"))
            // Its own process group, so a test can signal the whole worker
            // the way an operator would and clean up without collateral.
            .process_group(0);
        for (key, value) in environment {
            command.env(key, value.replace("{root}", &path.to_string_lossy()));
        }
        let child = command.spawn().expect("start the worker");
        Self {
            root,
            platform,
            child: Some(child),
        }
    }

    fn pid(&self) -> u32 {
        self.child.as_ref().expect("worker is running").id()
    }

    fn journal(&self) -> String {
        fs::read_to_string(self.root.path().join("worker.err")).unwrap_or_default()
    }

    /// The pid a stand-in provider recorded, once it has.
    fn recorded_pid(&self, name: &str) -> u32 {
        let file = self.root.path().join("pids").join(name);
        self.until(&format!("{name} to be recorded"), || {
            fs::read_to_string(&file)
                .ok()
                .and_then(|text| text.trim().parse().ok())
        })
    }

    /// Wait for `probe` to produce a value, failing with the worker's own
    /// journal when it does not.
    fn until<T>(&self, what: &str, mut probe: impl FnMut() -> Option<T>) -> T {
        let deadline = Instant::now() + PATIENCE;
        loop {
            if let Some(value) = probe() {
                return value;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {what}\nworker journal:\n{}\nrequests:\n{:#?}",
                self.journal(),
                self.platform.runtime("job")
            );
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn terminal_report(&self, job: &str) -> Value {
        self.until(&format!("the terminal report of {job}"), || {
            self.platform.terminal_report(job)
        })
    }

    fn until_gone(&self, pid: u32, what: &str) {
        self.until(&format!("{what} (pid {pid}) to be gone"), || {
            (!alive(pid)).then_some(())
        });
    }

    /// Ask the worker shell alone to stop, as the service manager does, and
    /// return its exit status once it has drained.
    fn stop(&mut self) -> std::process::ExitStatus {
        signal("-TERM", &self.pid().to_string());
        self.wait()
    }

    fn wait(&mut self) -> std::process::ExitStatus {
        let mut child = self.child.take().expect("worker is running");
        let deadline = Instant::now() + PATIENCE;
        loop {
            if let Some(status) = child.try_wait().expect("worker status") {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "the worker did not stop\nworker journal:\n{}",
                self.journal()
            );
            thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            signal("-KILL", &format!("-{}", child.id()));
            let _ = child.wait();
        }
        // Providers run in their own sessions; anything a failed assertion
        // left behind is named in the pid files.
        if let Ok(entries) = fs::read_dir(self.root.path().join("pids")) {
            for entry in entries.flatten() {
                let recorded = fs::read_to_string(entry.path()).unwrap_or_default();
                if entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "pid")
                    && let Ok(pid) = recorded.trim().parse::<u32>()
                    && alive(pid)
                {
                    signal("-KILL", &pid.to_string());
                }
            }
        }
    }
}

fn executable(path: &Path, content: &str) {
    fs::write(path, content).expect("write stand-in");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("stand-in mode");
}

fn signal(name: &str, target: &str) {
    let _ = Command::new("kill")
        .args([name, "--", target])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Whether a process still runs. A zombie waiting to be reaped has stopped.
fn alive(pid: u32) -> bool {
    let stat = PathBuf::from(format!("/proc/{pid}/stat"));
    match fs::read_to_string(stat) {
        Ok(text) => text
            .rsplit_once(") ")
            .is_none_or(|(_, rest)| !rest.starts_with('Z')),
        Err(_) => false,
    }
}

fn job_id(number: u32) -> String {
    format!("00000000-0000-4000-8000-{number:012}")
}

fn assert_run_counters(report: &Value) {
    // Two turns of 100 and 200 input tokens, 60 and 150 of them cached:
    // input is what was not served from the cache.
    assert_eq!(2, report["num_turns"], "{report}");
    assert_eq!(90, report["input_tokens"], "{report}");
    assert_eq!(18, report["output_tokens"], "{report}");
    assert_eq!(210, report["cache_read_input_tokens"], "{report}");
    assert_eq!(
        "FakeAI/fake-model-1", report["upstream_provider"],
        "{report}"
    );
    assert!(report["duration_ms"].is_u64(), "{report}");
    // A flat subscription has no per-run cost, and the provider never
    // reported a cache write: neither is invented.
    assert!(report.get("cost_usd").is_none(), "{report}");
    assert!(
        report.get("cache_creation_input_tokens").is_none(),
        "{report}"
    );
}

#[test]
fn a_finished_run_and_a_failed_run_both_report_their_telemetry() {
    let done = job_id(1);
    let failed = job_id(2);
    let mut worker = Worker::start(&[], |platform, _| {
        platform.queue_job(&done, "done");
        platform.queue_job(&failed, "fail");
    });

    let report = worker.terminal_report(&done);
    assert_eq!("done", report["status"], "{report}");
    assert_eq!("session_fake_done", report["session_id"], "{report}");
    assert_run_counters(&report);
    assert!(report.get("timed_out").is_none(), "{report}");
    assert!(report.get("stop_reason").is_none(), "{report}");

    // The failed run stopped mid-line and never sent its final event: the
    // counters of the turns it completed and the session it opened survive.
    let report = worker.terminal_report(&failed);
    assert_eq!("failed", report["status"], "{report}");
    assert_eq!("jcode exited with status 3.", report["result"], "{report}");
    assert_eq!("session_fake_fail", report["session_id"], "{report}");
    assert_run_counters(&report);
    assert!(report.get("timed_out").is_none(), "{report}");

    let arguments = fs::read_to_string(worker.root.path().join("pids/done.args")).unwrap();
    assert!(arguments.contains("run --ndjson --disabled-tools browser,swarm,integration_tools -"));
    assert!(worker.stop().success());
    assert!(!worker.journal().contains("left processes behind"));
}

#[test]
fn a_ticket_that_asks_for_claude_runs_on_claude_and_reports_it() {
    let asked = job_id(20);
    let mut worker = Worker::start(SECOND_ENGINE, |platform, root| {
        install_claude_account(root, true);
        platform.queue_routed_job(&asked, "done", "jcode", Some("claude"));
    });

    let report = worker.terminal_report(&asked);
    assert_eq!("done", report["status"], "{report}");
    assert_eq!("claude", report["agent"], "{report}");
    assert_eq!(
        "asked for by the ticket or its project", report["engine_reason"],
        "{report}"
    );
    assert_eq!("claude_session_1", report["session_id"], "{report}");
    assert_eq!("fake-claude-1", report["model"], "{report}");
    assert_eq!(4, report["num_turns"], "{report}");
    assert_eq!(0.25, report["cost_usd"], "{report}");

    // Manage learns the engine when the run starts, not only when it ends.
    let running = worker
        .platform
        .runtime("job")
        .into_iter()
        .find(|report| report["jobId"] == asked.as_str() && report["status"] == "running")
        .expect("a running report");
    assert_eq!("claude", running["agent"], "{running}");

    let pids = worker.root.path().join("pids");
    // The request decided: nothing was triaged and JCode never started.
    assert!(!pids.join("claude-triage.args").exists());
    assert!(!pids.join("done.pid").exists());
    let home = fs::read_to_string(pids.join("claude-run.home")).unwrap();
    assert!(home.trim_end().ends_with(CLAUDE_ACCOUNT), "{home}");
    let arguments = fs::read_to_string(pids.join("claude-run.args")).unwrap();
    assert!(arguments.contains("--print --output-format stream-json --verbose"));

    // The second engine's health is its account's. The file that gates new
    // claims still describes the worker's own engine.
    let state = worker
        .root
        .path()
        .join("state/manage-fleet-worker/auth-health.json");
    let aggregate: Value = serde_json::from_str(&fs::read_to_string(state).unwrap()).unwrap();
    assert_eq!("jcode", aggregate["provider"], "{aggregate}");
    let account = worker
        .root
        .path()
        .join(format!("agent-auth/health/{CLAUDE_ACCOUNT}.json"));
    let account: Value = serde_json::from_str(&fs::read_to_string(account).unwrap()).unwrap();
    assert_eq!("claude", account["provider"], "{account}");
    assert_eq!("authenticated", account["status"], "{account}");
    assert!(last_heartbeat_detail(&worker.platform).contains("claude ready"));
    assert!(worker.stop().success());
}

#[test]
fn an_unmarked_ticket_is_triaged_and_a_ticket_that_names_jcode_is_not() {
    let open_ended = job_id(21);
    let scoped = job_id(22);
    let unclear = job_id(23);
    let foreign = job_id(24);
    let named = job_id(25);
    let mut worker = Worker::start(
        &[SECOND_ENGINE, &[("AUTOMONIQUE_FLEET_CONCURRENCY", "1")]].concat(),
        |platform, root| {
            install_claude_account(root, true);
            platform.queue_routed_job(&open_ended, "done", "claude", None);
            platform.queue_routed_job(&scoped, "done", "jcode", None);
            platform.queue_routed_job(&unclear, "done", "unsure", None);
            platform.queue_routed_job(&foreign, "done", "other", None);
            platform.queue_routed_job(&named, "done", "claude", Some("jcode"));
        },
    );

    let report = worker.terminal_report(&open_ended);
    assert_eq!("done", report["status"], "{report}");
    assert_eq!("claude", report["agent"], "{report}");
    assert_eq!(
        "triage: new tool to build", report["engine_reason"],
        "{report}"
    );

    let report = worker.terminal_report(&scoped);
    assert_eq!("jcode", report["agent"], "{report}");
    assert_eq!("triage: scoped fix", report["engine_reason"], "{report}");
    assert_eq!("fake-model-1", report["model"], "{report}");

    // No verdict, or a verdict naming an engine this worker does not host:
    // the ticket stays on the worker's own engine.
    for job in [&unclear, &foreign] {
        let report = worker.terminal_report(job);
        assert_eq!("done", report["status"], "{report}");
        assert_eq!("jcode", report["agent"], "{report}");
        assert_eq!(
            "triage gave no verdict", report["engine_reason"],
            "{report}"
        );
    }

    let report = worker.terminal_report(&named);
    assert_eq!("jcode", report["agent"], "{report}");
    assert_eq!(
        "asked for by the ticket or its project", report["engine_reason"],
        "{report}"
    );

    let pids = worker.root.path().join("pids");
    // Four tickets were triaged, each by a call that can use no tool.
    let triage = fs::read_to_string(pids.join("claude-triage.args")).unwrap();
    assert_eq!(4, triage.lines().count(), "{triage}");
    for call in triage.lines() {
        assert!(
            call.contains(
                "--tools  --no-session-persistence --strict-mcp-config --setting-sources"
            ),
            "{call}"
        );
    }
    assert_eq!(
        1,
        fs::read_to_string(pids.join("claude-run.args"))
            .unwrap()
            .lines()
            .count()
    );
    assert!(worker.stop().success());
}

#[test]
fn a_ticket_can_name_codex_its_model_and_its_effort() {
    let codex = job_id(30);
    let claude = job_id(31);
    let mut worker = Worker::start(THIRD_ENGINE, |platform, root| {
        install_both_accounts(root, true);
        platform.queue_job_with(
            &codex,
            "done",
            "claude",
            json!({"engine": "codex", "model": "gpt-test-9", "effort": "high", "prior_runs": 9}),
        );
        platform.queue_job_with(
            &claude,
            "done",
            "jcode",
            json!({"engine": "claude", "model": "opus-test[1m]", "effort": "xhigh"}),
        );
    });

    let report = worker.terminal_report(&codex);
    assert_eq!("done", report["status"], "{report}");
    assert_eq!("codex", report["agent"], "{report}");
    assert_eq!("high", report["effort"], "{report}");
    assert_eq!("gpt-test-9", report["model"], "{report}");
    assert_eq!("codex_thread_1", report["session_id"], "{report}");
    assert_eq!(
        "asked for by the ticket or its project", report["engine_reason"],
        "{report}"
    );
    let pids = worker.root.path().join("pids");
    let arguments = fs::read_to_string(pids.join("codex-run.args")).unwrap();
    assert!(arguments.contains("-m gpt-test-9"), "{arguments}");
    assert!(
        arguments.contains("-c model_reasoning_effort=\"high\""),
        "{arguments}"
    );
    let home = fs::read_to_string(pids.join("codex-run.home")).unwrap();
    assert!(home.trim_end().ends_with(CODEX_ACCOUNT), "{home}");

    let report = worker.terminal_report(&claude);
    assert_eq!("claude", report["agent"], "{report}");
    assert_eq!("xhigh", report["effort"], "{report}");
    let arguments = fs::read_to_string(pids.join("claude-run.args")).unwrap();
    assert!(
        arguments.contains("--model opus-test[1m] --effort xhigh"),
        "{arguments}"
    );
    // Neither request was triaged, and JCode never started.
    assert!(!pids.join("claude-triage.args").exists());
    assert!(!pids.join("done.pid").exists());
    assert!(worker.stop().success());
}

#[test]
fn a_signed_out_codex_account_fails_the_ticket_that_asks_for_it() {
    let asked = job_id(32);
    let mut worker = Worker::start(THIRD_ENGINE, |platform, root| {
        install_both_accounts(root, false);
        platform.queue_job_with(&asked, "done", "jcode", json!({"engine": "codex"}));
    });
    let report = worker.terminal_report(&asked);
    assert_eq!("failed", report["status"], "{report}");
    assert!(
        report["result"]
            .as_str()
            .unwrap()
            .starts_with("This ticket asks for Codex"),
        "{report}"
    );
    assert!(worker.stop().success());
}

#[test]
fn triage_names_the_effort_and_a_ticket_that_keeps_coming_back_is_escalated() {
    let hard = job_id(33);
    let third_run = job_id(34);
    let fifth_run = job_id(35);
    let pinned = job_id(36);
    let mut worker = Worker::start(THIRD_ENGINE, |platform, root| {
        install_both_accounts(root, true);
        platform.queue_job_with(&hard, "done", "hard", json!({}));
        platform.queue_job_with(&third_run, "slow", "jcode", json!({"prior_runs": 2}));
        platform.queue_job_with(&fifth_run, "leftover", "jcode", json!({"prior_runs": 4}));
        platform.queue_job_with(
            &pinned,
            "done",
            "claude",
            json!({"engine": "jcode", "effort": "low", "prior_runs": 9}),
        );
    });
    let pids = worker.root.path().join("pids");

    // The triage's effort reaches the engine it chose.
    let report = worker.terminal_report(&hard);
    assert_eq!("jcode", report["agent"], "{report}");
    assert_eq!("high", report["effort"], "{report}");
    assert_eq!(
        "triage: bug with unknown cause", report["engine_reason"],
        "{report}"
    );
    assert_eq!(
        "high",
        fs::read_to_string(pids.join("done.effort")).unwrap().trim()
    );

    // A third run on the same ticket thinks harder, on the same engine.
    let report = worker.terminal_report(&third_run);
    assert_eq!("jcode", report["agent"], "{report}");
    assert_eq!("high", report["effort"], "{report}");
    assert_eq!(
        "triage: scoped fix; effort raised: run 3 on this ticket", report["engine_reason"],
        "{report}"
    );
    assert_eq!(
        "high",
        fs::read_to_string(pids.join("slow.effort")).unwrap().trim()
    );

    // A fifth run moves to Claude at the highest effort.
    let report = worker.terminal_report(&fifth_run);
    assert_eq!("claude", report["agent"], "{report}");
    assert_eq!("xhigh", report["effort"], "{report}");
    assert_eq!(
        "escalated: run 5 on this ticket", report["engine_reason"],
        "{report}"
    );
    assert!(!pids.join("leftover.pid").exists());
    let arguments = fs::read_to_string(pids.join("claude-run.args")).unwrap();
    assert!(arguments.contains("--effort xhigh"), "{arguments}");

    // What the ticket or its project named is never escalated.
    let report = worker.terminal_report(&pinned);
    assert_eq!("jcode", report["agent"], "{report}");
    assert_eq!("low", report["effort"], "{report}");
    assert_eq!(
        "asked for by the ticket or its project", report["engine_reason"],
        "{report}"
    );
    assert_eq!(
        "low",
        fs::read_to_string(pids.join("done.effort")).unwrap().trim()
    );
    assert!(worker.stop().success());
}

#[test]
fn a_run_claude_cannot_serve_goes_back_to_jcode_unless_the_ticket_named_claude() {
    let routed = job_id(40);
    let named = job_id(41);
    let mut worker = Worker::start(THIRD_ENGINE, |platform, root| {
        install_both_accounts(root, true);
        platform.queue_job_with(&routed, "limit", "claude", json!({}));
        platform.queue_job_with(&named, "limit", "jcode", json!({"engine": "claude"}));
    });

    // The triage chose Claude, Claude was at its limit: the job still gets done.
    let report = worker.terminal_report(&routed);
    assert_eq!("done", report["status"], "{report}");
    assert_eq!("jcode", report["agent"], "{report}");
    assert_eq!(
        "fell back from claude: it could not serve the run", report["engine_reason"],
        "{report}"
    );
    assert_eq!("session_fake_limit", report["session_id"], "{report}");
    assert!(last_heartbeat_detail(&worker.platform).contains("codex ready"));

    // A ticket that asked for Claude by name fails rather than change engine.
    let report = worker.terminal_report(&named);
    assert_eq!("failed", report["status"], "{report}");
    assert_eq!("claude", report["agent"], "{report}");
    assert!(
        report["result"].as_str().unwrap().contains("usage limit"),
        "{report}"
    );
    assert!(worker.stop().success());
}

#[test]
fn a_signed_out_claude_account_fails_the_ticket_that_asks_for_it_and_no_other() {
    let asked = job_id(26);
    let unmarked = job_id(27);
    let mut worker = Worker::start(SECOND_ENGINE, |platform, root| {
        install_claude_account(root, false);
        platform.queue_routed_job(&asked, "done", "claude", Some("claude"));
        platform.queue_routed_job(&unmarked, "done", "claude", None);
    });

    let report = worker.terminal_report(&asked);
    assert_eq!("failed", report["status"], "{report}");
    assert!(
        report["result"]
            .as_str()
            .unwrap()
            .contains("no signed-in Claude account"),
        "{report}"
    );

    let report = worker.terminal_report(&unmarked);
    assert_eq!("done", report["status"], "{report}");
    assert_eq!("jcode", report["agent"], "{report}");
    assert_eq!(
        "not triaged: the Claude account is signed out", report["engine_reason"],
        "{report}"
    );

    let pids = worker.root.path().join("pids");
    assert!(!pids.join("claude-triage.args").exists());
    assert!(!pids.join("claude-run.args").exists());
    worker.until("a heartbeat that names the signed-out account", || {
        last_heartbeat_detail(&worker.platform)
            .contains("claude signed out")
            .then_some(())
    });
    assert!(worker.stop().success());
}

#[test]
fn a_worker_without_a_second_engine_fails_a_ticket_that_asks_for_claude() {
    let plain = job_id(28);
    let mut worker = Worker::start(&[], |platform, _| {
        platform.queue_routed_job(&plain, "done", "claude", Some("claude"));
    });

    // No account directory: asking for Claude cannot be served here.
    let report = worker.terminal_report(&plain);
    assert_eq!("failed", report["status"], "{report}");
    assert!(!last_heartbeat_detail(&worker.platform).contains("claude"));
    assert!(worker.stop().success());
}

#[test]
fn a_run_past_the_wall_clock_limit_is_stopped_with_its_children_and_reported_timed_out() {
    let hung = job_id(3);
    let next = job_id(4);
    let mut worker = Worker::start(
        &[
            ("AUTOMONIQUE_FLEET_TEST_JOB_TIMEOUT_SECONDS", "2"),
            ("AUTOMONIQUE_FLEET_TEST_KILL_GRACE_SECONDS", "1"),
        ],
        |platform, _| platform.queue_job(&hung, "hang"),
    );
    let provider = worker.recorded_pid("hang.pid");
    let child = worker.recorded_pid("hang.child.pid");
    assert!(alive(provider) && alive(child));

    let report = worker.terminal_report(&hung);
    assert_eq!("failed", report["status"], "{report}");
    assert_eq!(true, report["timed_out"], "{report}");
    assert_eq!("timeout", report["stop_reason"], "{report}");
    assert!(
        report["result"]
            .as_str()
            .unwrap()
            .starts_with("Timed out after 2 seconds"),
        "{report}"
    );
    // The session it opened is what lets Manage resume the run.
    assert_eq!("session_fake_hang", report["session_id"], "{report}");
    assert_run_counters(&report);
    // The provider went on TERM; its child ignored TERM and needed KILL.
    worker.until_gone(provider, "the timed-out provider");
    worker.until_gone(child, "the timed-out provider's child");

    // The worker itself is untouched and takes the next job.
    worker.platform.queue_job(&next, "done");
    let report = worker.terminal_report(&next);
    assert_eq!("done", report["status"], "{report}");
    assert!(report.get("timed_out").is_none(), "{report}");
    assert!(worker.stop().success());
}

#[test]
fn processes_a_finished_run_leaves_behind_are_stopped() {
    let job = job_id(5);
    let mut worker = Worker::start(&[], |platform, _| platform.queue_job(&job, "leftover"));
    let leftover = worker.recorded_pid("leftover.child.pid");

    let report = worker.terminal_report(&job);
    assert_eq!("done", report["status"], "{report}");
    assert!(report.get("timed_out").is_none(), "{report}");
    worker.until_gone(leftover, "the process the run left behind");
    assert!(worker.journal().contains("left processes behind"));
    assert!(worker.stop().success());
}

/// Replace a fixture file in one step, so the worker never reads it half
/// written.
fn replace_file(path: &Path, content: &str) {
    let staged = path.with_extension("staged");
    fs::write(&staged, content).expect("stage fixture");
    fs::rename(&staged, path).expect("publish fixture");
}

fn last_heartbeat_detail(platform: &Platform) -> String {
    platform
        .runtime("heartbeat")
        .last()
        .and_then(|heartbeat| heartbeat["detail"].as_str().map(str::to_owned))
        .unwrap_or_default()
}

#[test]
fn a_host_short_of_memory_claims_no_job_until_it_recovers() {
    const PLENTY: &str =
        "MemTotal:       65000000 kB\nMemFree:          100000 kB\nMemAvailable:   30000000 kB\n";
    // 3.1 GB available, below the 6144 MiB floor.
    const SHORT: &str =
        "MemTotal:       65000000 kB\nMemFree:          100000 kB\nMemAvailable:    3250586 kB\n";
    let first = job_id(6);
    let second = job_id(7);
    let mut worker = Worker::start(
        &[
            ("AUTOMONIQUE_FLEET_MIN_AVAILABLE_MB", "6144"),
            ("AUTOMONIQUE_FLEET_MAX_MEMORY_PRESSURE", "20"),
            ("AUTOMONIQUE_FLEET_TEST_MEMINFO_PATH", "{root}/meminfo"),
            // Absent at first: a host without pressure accounting is not under pressure.
            (
                "AUTOMONIQUE_FLEET_TEST_MEMORY_PRESSURE_PATH",
                "{root}/pressure",
            ),
        ],
        |platform, root| {
            replace_file(&root.join("meminfo"), SHORT);
            platform.queue_job(&first, "done");
            platform.state.lock().unwrap().commands.push(json!({
                "id": "cmd-approve-0001",
                "action": "approve_release",
            }));
        },
    );
    let meminfo = worker.root.path().join("meminfo");
    let pressure = worker.root.path().join("pressure");

    // Guarded: the console is told why, platform commands still run, and the
    // queued job is not even asked for.
    worker.until("a heartbeat that explains the wait", || {
        last_heartbeat_detail(&worker.platform)
            .contains("waiting for memory: 3.1 GB available")
            .then_some(())
    });
    worker.until("the platform command receipt", || {
        worker
            .platform
            .receipts()
            .iter()
            .any(|receipt| {
                receipt["command_id"] == "cmd-approve-0001" && receipt["outcome"] == "completed"
            })
            .then_some(())
    });
    thread::sleep(Duration::from_millis(2500));
    assert!(worker.platform.runtime("claim").is_empty());

    // Memory is back: the job runs and the heartbeat stops mentioning it.
    replace_file(&meminfo, PLENTY);
    let report = worker.terminal_report(&first);
    assert_eq!("done", report["status"], "{report}");
    assert!(!last_heartbeat_detail(&worker.platform).contains("waiting for memory"));

    // Enough memory on paper, but the host is stalling on it.
    replace_file(
        &pressure,
        "some avg10=35.50 avg60=12.00 avg300=3.00 total=123456\nfull avg10=1.00 avg60=0.50 avg300=0.10 total=2345\n",
    );
    worker.until("a heartbeat that reports the pressure", || {
        last_heartbeat_detail(&worker.platform)
            .contains("waiting for memory: pressure 35.50%")
            .then_some(())
    });
    let claims = worker.platform.runtime("claim").len();
    worker.platform.queue_job(&second, "done");
    thread::sleep(Duration::from_millis(2500));
    assert_eq!(claims, worker.platform.runtime("claim").len());
    assert!(worker.platform.terminal_report(&second).is_none());

    replace_file(
        &pressure,
        "some avg10=0.50 avg60=9.00 avg300=3.00 total=123999\nfull avg10=0.00 avg60=0.40 avg300=0.10 total=2345\n",
    );
    let report = worker.terminal_report(&second);
    assert_eq!("done", report["status"], "{report}");
    assert!(worker.stop().success());

    // One line when the guard engages and one when it lifts, not one a poll.
    let journal = worker.journal();
    assert_eq!(
        2,
        journal.matches("memory guard engaged").count(),
        "{journal}"
    );
    assert_eq!(
        2,
        journal.matches("memory guard lifted").count(),
        "{journal}"
    );
}

#[test]
fn stopping_the_worker_lets_a_running_job_finish_and_never_calls_it_timed_out() {
    let job = job_id(8);
    let mut worker = Worker::start(&[], |platform, _| platform.queue_job(&job, "slow"));
    worker.recorded_pid("slow.pid");
    assert!(worker.platform.terminal_report(&job).is_none());

    // The service manager signals the worker shell alone; it stops claiming
    // and waits for the run it accepted.
    assert!(worker.stop().success());
    let report = worker
        .platform
        .terminal_report(&job)
        .expect("the drained job's report");
    assert_eq!("done", report["status"], "{report}");
    assert!(report.get("timed_out").is_none(), "{report}");
    assert_run_counters(&report);
    assert!(
        worker
            .platform
            .runtime("heartbeat")
            .iter()
            .any(|heartbeat| heartbeat["status"] == "offline")
    );
}

#[test]
fn terminating_the_whole_worker_takes_the_run_down_without_a_timeout_report() {
    let job = job_id(9);
    let mut worker = Worker::start(
        &[("AUTOMONIQUE_FLEET_TEST_KILL_GRACE_SECONDS", "1")],
        |platform, _| platform.queue_job(&job, "hang"),
    );
    let provider = worker.recorded_pid("hang.pid");
    let child = worker.recorded_pid("hang.child.pid");

    // TERM to the worker's process group, the provider's session excluded by
    // construction: the job's own shell must carry the stop over to it.
    signal("-TERM", &format!("-{}", worker.pid()));
    worker.wait();
    worker.until_gone(provider, "the provider of the terminated worker");
    worker.until_gone(child, "the provider's child");

    // No terminal report: the next start hands the job back as interrupted.
    assert!(worker.platform.terminal_report(&job).is_none());
    assert!(!worker.journal().contains("wall-clock limit"));
}

#[test]
fn a_restarted_worker_hands_back_the_run_it_lost_as_interrupted() {
    let lost = job_id(10);
    let mut worker = Worker::start(&[], |platform, _| {
        platform.state.lock().unwrap().snapshot_jobs.push(json!({
            "id": lost,
            "status": "running",
            "instance_id": NODE,
            "updated_at": "2026-01-01T00:00:00.000Z",
        }));
    });
    let report = worker.terminal_report(&lost);
    assert_eq!("failed", report["status"], "{report}");
    assert_eq!(true, report["interrupted"], "{report}");
    assert!(report.get("timed_out").is_none(), "{report}");
    // The worker writes its journal line after Manage answered the report.
    worker.until("the requeue to be journalled", || {
        worker
            .journal()
            .contains("requeued interrupted job")
            .then_some(())
    });
    assert!(worker.stop().success());
}

#[test]
fn the_worker_script_is_valid_shell() {
    let root = tempfile::tempdir().expect("temporary root");
    let script = root.path().join("worker.sh");
    fs::write(&script, MANAGE_WORKER).expect("write the script");
    let checked = Command::new("bash")
        .arg("-n")
        .arg(&script)
        .output()
        .expect("bash -n");
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
}
