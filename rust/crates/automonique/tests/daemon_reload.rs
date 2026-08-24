// SPDX-License-Identifier: Elastic-2.0

use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

#[test]
fn sighup_completes_the_notify_reload_protocol_without_changing_pid() {
    let root = tempfile::tempdir().expect("temporary root");
    private_directory(root.path());
    let runtime_root = root.path().join("runtime");
    let state_root = root.path().join("state");
    private_directory(&runtime_root);
    private_directory(&state_root);
    let notify_path = root.path().join("notify.sock");
    let notifications = UnixDatagram::bind(&notify_path).expect("notification socket");
    notifications
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("notification timeout");

    let child = Command::new(env!("CARGO_BIN_EXE_automonique"))
        .args(["daemon", "--foreground"])
        .env("XDG_RUNTIME_DIR", &runtime_root)
        .env("XDG_STATE_HOME", &state_root)
        .env("NOTIFY_SOCKET", &notify_path)
        .spawn()
        .expect("foreground daemon");
    let mut child = ChildGuard(Some(child));
    let pid = child.pid();

    assert_eq!(receive(&notifications), b"EXTEND_TIMEOUT_USEC=300000000");
    assert_eq!(receive(&notifications), b"READY=1\nSTATUS=Ready");

    kill(pid, Signal::SIGHUP).expect("request reload");
    let reloading = receive(&notifications);
    assert!(reloading.starts_with(b"RELOADING=1\nMONOTONIC_USEC="));
    assert_eq!(receive(&notifications), b"READY=1\nSTATUS=Ready");
    assert_eq!(child.pid(), pid, "reload must retain the main PID");
    assert!(
        child.try_wait().expect("daemon status").is_none(),
        "reload must leave the daemon running"
    );

    kill(pid, Signal::SIGTERM).expect("stop daemon");
    assert_eq!(receive(&notifications), b"STOPPING=1\nSTATUS=Stopping");
    let status = child.wait_deadlined(Duration::from_secs(20));
    assert!(status.success(), "daemon exited with {status}");
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn pid(&self) -> Pid {
        let raw = i32::try_from(self.0.as_ref().expect("live child").id()).expect("PID fits i32");
        Pid::from_raw(raw)
    }

    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.0.as_mut().expect("live child").try_wait()
    }

    fn wait_deadlined(&mut self, timeout: Duration) -> ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.try_wait().expect("daemon status") {
                self.0 = None;
                return status;
            }
            assert!(Instant::now() < deadline, "daemon did not stop on time");
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn receive(socket: &UnixDatagram) -> Vec<u8> {
    let mut buffer = [0_u8; 256];
    let size = socket.recv(&mut buffer).expect("service notification");
    buffer[..size].to_vec()
}

fn private_directory(path: &Path) {
    std::fs::create_dir_all(path).expect("private directory");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("private directory mode");
}
