// SPDX-License-Identifier: Elastic-2.0

//! The temporary-storage owner answers when asked, not when it next wakes.
//!
//! Setting a run's private mount up is a three-round-trip handshake through
//! this socket and every checkpoint afterwards is another request, so the
//! endpoint's accept latency is paid several times per run and then repeatedly
//! for the run's whole life. A loop that napped between accepts charged most of
//! its interval to each of those legs.
//!
//! The request used here is deliberately one the owner refuses at its first
//! guard — a version it does not speak. Refusing is a complete round trip
//! through accept, receive and disposal without creating custody, touching a
//! cgroup or writing a checkpoint, so what is measured is the wait and nothing
//! else. A case that had to mount something to time the accept would be timing
//! the mount.

use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use std::{fs, thread};

/// How many sequential exchanges the measurement makes.
///
/// A serialized caller is the shape that suffers: it cannot send the next
/// request until the previous answer is in, so it reliably arrives just after
/// an idle loop went to sleep and pays the remainder, every time. One exchange
/// could not tell that apart from a scheduling hiccup; this many makes the
/// difference between the two implementations larger than any plausible noise.
const EXCHANGES: u32 = 30;

/// The interval `tempfs_owner::IDLE_TICK` bounds the wait at, mirrored here.
///
/// Mirrored rather than imported because it is private, and because a test that
/// read the constant would still pass if both it and the loop were changed
/// together — the number this case is defending is the one in the comment, not
/// whatever the module currently says.
const IDLE_TICK: Duration = Duration::from_millis(10);

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn private_directory(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

/// One complete refused exchange: connect, ask, read to the owner's hang-up.
///
/// Reading to end-of-file is what makes this a measurement of the *server*. The
/// connect returns as soon as the kernel queues it, whether or not anything has
/// accepted; the hang-up happens only after the owner accepted the connection
/// and disposed of the request.
fn refused_exchange(socket: &Path) {
    let mut stream = UnixStream::connect(socket).expect("owner endpoint accepts connections");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read deadline");
    stream
        .write_all(b"automonique.tempfs-owner/v0 unspoken\n")
        .expect("write the request");
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).expect("the owner hangs up");
}

/// A serialized caller does not pay the idle interval on every exchange.
///
/// With a nap between accepts this loop costs about `EXCHANGES * IDLE_TICK`,
/// because each request arrives while the owner is asleep. Waiting on the
/// listener instead costs the exchanges themselves. The ceiling is set at half
/// the sleeping cost so the two cannot be confused, while leaving a very wide
/// margin over what the exchanges actually take.
#[test]
fn a_serialized_caller_is_not_charged_the_idle_interval_per_request() {
    let temporary = tempfile::tempdir().unwrap();
    let state = temporary.path().join("state");
    let runtime = temporary.path().join("runtime");
    let socket_parent = runtime.join("automonique");
    for directory in [&state, &state.join("automonique/runs"), &socket_parent] {
        private_directory(directory);
    }
    let socket = socket_parent.join("tempfs-owner.sock");

    let owner = Command::new(env!("CARGO_BIN_EXE_automonique-launch-enter"))
        .arg(automonique_runner::tempfs_owner::OWNER_MODE_FLAG)
        .env("XDG_STATE_HOME", &state)
        .env("XDG_RUNTIME_DIR", &runtime)
        .env(automonique_runner::tempfs_owner::OWNER_SOCKET_ENV, &socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _owner = ChildGuard(owner);

    let deadline = Instant::now() + Duration::from_secs(5);
    while UnixStream::connect(&socket).is_err() {
        assert!(Instant::now() < deadline, "the owner did not become ready");
        thread::sleep(Duration::from_millis(10));
    }

    // One exchange before the clock starts, so the measurement is of a steady
    // state rather than of whatever the first connection had to fault in.
    refused_exchange(&socket);

    let started = Instant::now();
    for _ in 0..EXCHANGES {
        refused_exchange(&socket);
    }
    let elapsed = started.elapsed();

    let sleeping_cost = IDLE_TICK * EXCHANGES;
    assert!(
        elapsed < sleeping_cost / 2,
        "{EXCHANGES} sequential requests took {elapsed:?}. A loop that waits on its listener \
         serves them as they arrive; one that naps charges each of them most of {IDLE_TICK:?}, \
         which is the {sleeping_cost:?} this is within reach of"
    );
}
