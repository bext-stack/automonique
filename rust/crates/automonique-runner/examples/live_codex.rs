// SPDX-License-Identifier: Elastic-2.0

//! Drive a **real** provider (the Codex CLI) through the enforced launch path,
//! and capture its one live model round-trip.
//!
//! This is the first time the runner holds a real provider process rather than
//! a busybox stand-in. It is a **manually-run example, never a `cargo test`**:
//! it makes a live, paid, networked call, which has no place in a hermetic gate.
//! Run it by hand under a delegated cgroup v2 scope (see the invocation at the
//! bottom of this comment).
//!
//! # The one deliberate deviation: network egress
//!
//! Every other boundary the runner enforces is applied here unchanged — the
//! workload runs inside a cgroup v2 domain with atomic descendant kill, with
//! every inherited descriptor closed to the three standard streams, under a
//! Landlock filesystem policy that grants exactly the paths named below and
//! denies the rest, and under the seccomp socket-family filter.
//!
//! The exception is **network egress**, and it is the whole reason this needs a
//! human to run it rather than living in the test suite. A live provider must
//! reach its model API, and there is no direct-egress variant in the sandbox
//! spec. So this example opens exactly two holes and no more:
//!
//! - [`SocketGrant::Tcp`] plus [`LaunchPlan::allow_connect_port`] for `443`, so
//!   the workload can open a TCP socket and `connect` to an HTTPS endpoint —
//!   and only to port 443, on any address, because Landlock's TCP rules are
//!   per-port, not per-host.
//! - [`SocketGrant::InetDatagram`], so the workload's own resolver can open the
//!   UDP sockets `getaddrinfo`/musl use for DNS. This is the wider of the two:
//!   nothing in this crate bounds where a UDP datagram is sent.
//!
//! That pair is the entire relaxation, and **it is now superseded**. The egress
//! broker exists, and the daemon's execution lane composes it: a document
//! declaring `brokered_named` egress is admitted to `SocketGrant::Tcp` plus a
//! `connect` to one loopback ephemeral port, with `HTTPS_PROXY`/`HTTP_PROXY`
//! naming the broker — no UDP grant, no port 443, and no resolver files. The
//! composition is one reviewed list in
//! [`admission::AdmittedLaunch::with_broker`](automonique_runner::admission::AdmittedLaunch::with_broker),
//! and `automonique-daemon`'s `execute_brokered` test drives it end to end with
//! a contained workload.
//!
//! This example is deliberately left as it was, because it is the *pre-broker*
//! measurement the broker is compared against, and because rewriting the
//! owner's live-provider vehicle is a change only a live run can verify. The
//! live provider round trip through the broker is that run.
//!
//! # It is a pure completion, not an agent
//!
//! Codex is invoked with `exec - -s read-only --ephemeral`, given a benign,
//! deterministic prompt on stdin, and asked for a fixed token. It is not asked
//! to use tools. Any subprocess it might still try to spawn (it probes the
//! environment with `lsb_release` and a shell) is denied by the filesystem
//! policy — only the codex binary itself carries an execute grant — and Codex
//! degrades past those probes, exactly as it does uncontained.
//!
//! # Configuration (no machine-specific paths in this file)
//!
//! Every path is read from the environment so nothing here is tied to one host:
//!
//! - `LIVE_CODEX_BIN` — absolute path to the codex executable.
//! - `LIVE_CODEX_HOME` — an **isolated** `CODEX_HOME` (a copy of `auth.json`
//!   and a minimal `config.toml`), so the run never touches the operator's real
//!   Codex state. Credentials travel as a read grant on this directory, never
//!   as an environment variable.
//! - `LIVE_CODEX_WORKSPACE` — a scratch working directory (not a real repo).
//! - `LIVE_CODEX_PROMPT` — optional; defaults to the fixed-token instruction.
//! - `LIVE_CODEX_EXPECT` — optional; if set, the run fails unless the captured
//!   stdout contains it.
//! - `AUTOMONIQUE_LAUNCH_HELPER` — optional; the `automonique-launch-enter`
//!   binary. Defaults to the sibling of this example under `target/`.
//!
//! # Running it
//!
//! ```text
//! cargo build -p automonique-runner --example live_codex \
//!   --bin automonique-launch-enter
//! systemd-run --user --scope -p Delegate=yes \
//!   --setenv=LIVE_CODEX_BIN=... --setenv=LIVE_CODEX_HOME=... \
//!   --setenv=LIVE_CODEX_WORKSPACE=... \
//!   env XDG_RUNTIME_DIR=/run/user/$(id -u) \
//!   ./target/debug/examples/live_codex
//! ```

use std::error::Error;
use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use automonique_runner::filesystem::PathIntent;
use automonique_runner::{
    CGROUP_DIR_ENV, ContainmentDomain, ContainmentLimits, LaunchPlan, RunContainment, SocketGrant,
};

/// The default benign prompt: a deterministic token, no tools.
const DEFAULT_PROMPT: &str = "Reply with exactly the text AUTOMONIQUE-LIVE-OK and \
     nothing else. Do not run any commands or use any tools.";

/// How long to wait for the whole round-trip (model latency included).
const RUN_DEADLINE: Duration = Duration::from_secs(180);

fn required(name: &str) -> Result<String, Box<dyn Error>> {
    std::env::var(name).map_err(|_| format!("{name} must be set (see the example's docs)").into())
}

/// Locate the entry helper: an explicit override, or the sibling of this
/// example binary (`target/<profile>/examples/live_codex` →
/// `target/<profile>/automonique-launch-enter`).
fn helper_path() -> Result<PathBuf, Box<dyn Error>> {
    if let Ok(explicit) = std::env::var("AUTOMONIQUE_LAUNCH_HELPER") {
        return Ok(PathBuf::from(explicit));
    }
    let here = std::env::current_exe()?;
    let target_dir = here
        .parent()
        .and_then(|examples| examples.parent())
        .ok_or("cannot locate target directory from current_exe")?;
    let helper = target_dir.join("automonique-launch-enter");
    if !helper.exists() {
        return Err(format!(
            "helper not found at {}; build it with \
             `cargo build -p automonique-runner --bin automonique-launch-enter`, \
             or set AUTOMONIQUE_LAUNCH_HELPER",
            helper.display()
        )
        .into());
    }
    Ok(helper)
}

/// Resolve a path to its real, non-symlink target. The launch surface refuses a
/// grant whose path is a symlink (a grant must name what it actually opens), and
/// `/etc/resolv.conf` is a symlink to the systemd-resolved stub on many hosts.
fn real(path: &str) -> Result<PathBuf, Box<dyn Error>> {
    std::fs::canonicalize(path).map_err(|error| format!("{path}: {error}").into())
}

/// Build the launch plan for one contained Codex completion.
fn build_plan(
    codex_bin: &str,
    codex_home: &str,
    workspace: &str,
    prompt: &str,
) -> Result<LaunchPlan, Box<dyn Error>> {
    // The files a musl resolver reads to find its nameservers, named by their
    // real targets so a symlinked resolv.conf is granted as its stub file.
    let resolv = real("/etc/resolv.conf")?;
    let hosts = real("/etc/hosts")?;
    let plan = LaunchPlan::new(codex_bin)?
        // codex exec -, prompt on stdin, a pure read-only completion.
        .argument("exec")?
        .argument("-")?
        .argument("-s")?
        .argument("read-only")?
        .argument("--skip-git-repo-check")?
        .argument("--color")?
        .argument("never")?
        .argument("--ephemeral")?
        .argument("-C")?
        .argument(workspace)?
        // Execute exactly the codex binary and nothing else.
        .filesystem_grant(PathIntent::ReadExecute, codex_bin)?
        // Its isolated CODEX_HOME (auth.json + config.toml) and scratch cwd.
        .filesystem_grant(PathIntent::ReadWrite, codex_home)?
        .filesystem_grant(PathIntent::ReadWrite, workspace)?
        .filesystem_grant(PathIntent::Read, resolv)?
        .filesystem_grant(PathIntent::Read, hosts)?
        // The system CA trust store: codex validates its endpoint against the
        // host's roots, not a bundled set. One read grant on the standard
        // directory covers the bundle file via Landlock's subtree rule.
        .filesystem_grant(PathIntent::Read, "/etc/ssl/certs")?
        // Nothing is inherited; name every variable the workload gets.
        .environment("CODEX_HOME", codex_home)?
        .environment("HOME", workspace)?
        .environment("PATH", "/usr/bin:/bin")?
        .environment("TERM", "dumb")?
        .environment("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt")?
        .environment("SSL_CERT_DIR", "/etc/ssl/certs")?
        // --- the deliberate, approved network deviation (see module docs) ---
        .socket_grant(SocketGrant::Tcp)?
        .socket_grant(SocketGrant::InetDatagram)?
        .allow_connect_port(443)?
        // -------------------------------------------------------------------
        // Not egress: the provider's async runtime (tokio) builds an AF_UNIX
        // socketpair as its signal self-pipe — both ends held by the workload,
        // no external peer, and any pathname socket is still bounded by the
        // filesystem policy above.
        .socket_grant(SocketGrant::Unix)?
        .prompt(prompt)?;
    Ok(plan)
}

/// Spawn the helper, stream the plan frame to its stdin, and capture the
/// workload's stdout/stderr on reader threads so a chatty provider cannot
/// deadlock against a full pipe.
fn run(plan: &LaunchPlan, containment: &RunContainment) -> Result<Captured, Box<dyn Error>> {
    let helper = helper_path()?;
    let frame = plan.encode()?;

    let mut child = Command::new(&helper)
        .env_clear()
        .env(CGROUP_DIR_ENV, containment.path())
        .current_dir(std::env::var("LIVE_CODEX_WORKSPACE").expect("workspace validated by caller"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    child.stdin.take().ok_or("child stdin")?.write_all(&frame)?;

    let mut out_pipe = child.stdout.take().ok_or("child stdout")?;
    let mut err_pipe = child.stderr.take().ok_or("child stderr")?;
    let out_reader = thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = out_pipe.read_to_end(&mut buffer);
        buffer
    });
    let err_reader = thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = err_pipe.read_to_end(&mut buffer);
        buffer
    });

    let deadline = Instant::now() + RUN_DEADLINE;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            None => {
                // The cgroup kill is atomic over the whole tree; the child is
                // then reaped so the reader threads see EOF.
                let _ = containment.kill();
                let _ = child.wait();
                break child.wait()?;
            }
        }
    };

    let stdout = out_reader.join().map_err(|_| "stdout reader panicked")?;
    let stderr = err_reader.join().map_err(|_| "stderr reader panicked")?;
    Ok(Captured {
        code: status.code().unwrap_or(-1),
        stdout,
        stderr,
    })
}

struct Captured {
    code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let codex_bin = required("LIVE_CODEX_BIN")?;
    let codex_home = required("LIVE_CODEX_HOME")?;
    let workspace = required("LIVE_CODEX_WORKSPACE")?;
    let prompt = std::env::var("LIVE_CODEX_PROMPT").unwrap_or_else(|_| DEFAULT_PROMPT.to_owned());

    let domain = match ContainmentDomain::discover() {
        Ok(domain) => domain,
        Err(error) => {
            return Err(format!(
                "no delegated cgroup v2 domain: {error}. Run under \
                 `systemd-run --user --scope -p Delegate=yes` with \
                 XDG_RUNTIME_DIR set."
            )
            .into());
        }
    };
    let run_id = format!("live-codex-{}", std::process::id());
    let containment = RunContainment::create(&domain, &run_id, ContainmentLimits::none())?;
    eprintln!("[live_codex] containment: {}", containment.path().display());

    let plan = build_plan(&codex_bin, &codex_home, &workspace, &prompt)?;
    let captured = run(&plan, &containment)?;
    // Dispose of the cgroup tree regardless of how the workload exited.
    let _ = containment.dispose(Duration::from_secs(5));

    eprintln!("[live_codex] exit code: {}", captured.code);
    eprintln!(
        "[live_codex] --- provider stderr ---\n{}",
        String::from_utf8_lossy(&captured.stderr)
    );
    let stdout = String::from_utf8_lossy(&captured.stdout);
    println!("--- provider stdout ---\n{stdout}");

    if let Ok(expected) = std::env::var("LIVE_CODEX_EXPECT") {
        if !stdout.contains(&expected) {
            return Err(format!(
                "expected {expected:?} in the provider's stdout, but it was absent — \
                 the contained live round-trip did not complete as expected"
            )
            .into());
        }
        eprintln!("[live_codex] OK: captured stdout contains {expected:?}");
    }
    Ok(())
}
