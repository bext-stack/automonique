// SPDX-License-Identifier: Elastic-2.0

//! Minimal systemd readiness, reload, timeout, and watchdog notifications.

use std::ffi::OsStr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant};

use nix::sys::socket::{AddressFamily, MsgFlags, SockFlag, SockType, UnixAddr, sendto, socket};
use nix::sys::time::TimeValLike as _;
use nix::time::{ClockId, clock_gettime};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NotifyError {
    InvalidSocket,
    InvalidWatchdog,
    Clock,
    Socket,
    Send,
}

impl NotifyError {
    pub(crate) const fn category(self) -> &'static str {
        match self {
            Self::InvalidSocket => "notify_socket_invalid",
            Self::InvalidWatchdog => "watchdog_configuration_invalid",
            Self::Clock => "notify_clock_failed",
            Self::Socket => "notify_socket_unavailable",
            Self::Send => "notify_send_failed",
        }
    }
}

pub(crate) struct Notifier {
    socket: OwnedFd,
    address: UnixAddr,
    watchdog_interval: Option<Duration>,
    next_watchdog: Option<Instant>,
}

impl Notifier {
    pub(crate) fn from_environment() -> Result<Option<Self>, NotifyError> {
        let Some(address) = std::env::var_os("NOTIFY_SOCKET") else {
            return Ok(None);
        };
        let watchdog_usec = std::env::var_os("WATCHDOG_USEC");
        let watchdog_pid = std::env::var_os("WATCHDOG_PID");
        Self::new(&address, watchdog_usec.as_deref(), watchdog_pid.as_deref()).map(Some)
    }

    fn new(
        address: &OsStr,
        watchdog_usec: Option<&OsStr>,
        watchdog_pid: Option<&OsStr>,
    ) -> Result<Self, NotifyError> {
        let bytes = address.as_bytes();
        let address = match bytes {
            [b'@', rest @ ..] if !rest.is_empty() => {
                UnixAddr::new_abstract(rest).map_err(|_| NotifyError::InvalidSocket)?
            }
            [] => return Err(NotifyError::InvalidSocket),
            _ => UnixAddr::new(Path::new(address)).map_err(|_| NotifyError::InvalidSocket)?,
        };
        let socket = socket(
            AddressFamily::Unix,
            SockType::Datagram,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(|_| NotifyError::Socket)?;
        let watchdog_interval = watchdog_interval(watchdog_usec, watchdog_pid)?;
        let next_watchdog = watchdog_interval.map(|interval| Instant::now() + interval);
        Ok(Self {
            socket,
            address,
            watchdog_interval,
            next_watchdog,
        })
    }

    pub(crate) fn ready(&self) -> Result<(), NotifyError> {
        self.send(b"READY=1\nSTATUS=Ready")
    }

    pub(crate) fn extend_timeout(&self, extension: Duration) -> Result<(), NotifyError> {
        self.send(format!("EXTEND_TIMEOUT_USEC={}", extension.as_micros()).as_bytes())
    }

    pub(crate) fn reloading(&self) -> Result<(), NotifyError> {
        let monotonic_usec = clock_gettime(ClockId::CLOCK_MONOTONIC)
            .map_err(|_| NotifyError::Clock)?
            .num_microseconds();
        self.send(format!("RELOADING=1\nMONOTONIC_USEC={monotonic_usec}").as_bytes())
    }

    /// Hand the service's main process over to `pid`.
    ///
    /// Sent by the current main process (the only sender `NotifyAccess=main`
    /// admits) once a warmed reload candidate holds authority and before it
    /// starts serving. Without it the manager reads the source's exit as the
    /// unit stopping, kills the candidate at `TimeoutStopSec` and restarts
    /// the unit: a zero-downtime handoff turned into a delayed restart. After
    /// this message the candidate's own `READY=1` and `WATCHDOG=1` are the
    /// ones the manager counts.
    pub(crate) fn main_pid(&self, pid: u32) -> Result<(), NotifyError> {
        self.send(format!("MAINPID={pid}").as_bytes())
    }

    pub(crate) fn reload_refused(&self, category: &str) -> Result<(), NotifyError> {
        self.send(format!("READY=1\nSTATUS=Reload refused: {category}").as_bytes())
    }

    pub(crate) fn watchdog_if_due(&mut self) -> Result<(), NotifyError> {
        let now = Instant::now();
        if self.next_watchdog.is_some_and(|deadline| now >= deadline) {
            self.send(b"WATCHDOG=1")?;
            self.next_watchdog = self.watchdog_interval.map(|interval| now + interval);
        }
        Ok(())
    }

    pub(crate) fn stopping(&self) -> Result<(), NotifyError> {
        self.send(b"STOPPING=1\nSTATUS=Stopping")
    }

    fn send(&self, message: &[u8]) -> Result<(), NotifyError> {
        let sent = sendto(
            self.socket.as_raw_fd(),
            message,
            &self.address,
            MsgFlags::MSG_NOSIGNAL,
        )
        .map_err(|_| NotifyError::Send)?;
        if sent != message.len() {
            return Err(NotifyError::Send);
        }
        Ok(())
    }
}

fn watchdog_interval(
    usec: Option<&OsStr>,
    pid: Option<&OsStr>,
) -> Result<Option<Duration>, NotifyError> {
    if let Some(pid) = pid {
        let pid = pid
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or(NotifyError::InvalidWatchdog)?;
        if pid != std::process::id() {
            return Ok(None);
        }
    }
    let Some(usec) = usec else {
        return Ok(None);
    };
    let usec = usec
        .to_str()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or(NotifyError::InvalidWatchdog)?;
    Ok(Some(Duration::from_micros((usec / 2).max(1))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    #[test]
    fn readiness_watchdog_and_stopping_reach_the_declared_socket() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&path).expect("notification receiver");
        let pid = std::process::id().to_string();
        let mut notifier = Notifier::new(
            path.as_os_str(),
            Some(OsStr::new("2")),
            Some(OsStr::new(&pid)),
        )
        .expect("notifier");

        notifier.ready().expect("ready");
        assert_eq!(receive(&receiver), b"READY=1\nSTATUS=Ready");
        notifier
            .extend_timeout(Duration::from_secs(5))
            .expect("extend timeout");
        assert_eq!(receive(&receiver), b"EXTEND_TIMEOUT_USEC=5000000");
        notifier.reloading().expect("reloading");
        let reloading = receive(&receiver);
        assert!(reloading.starts_with(b"RELOADING=1\nMONOTONIC_USEC="));
        assert!(
            reloading[b"RELOADING=1\nMONOTONIC_USEC=".len()..]
                .iter()
                .all(u8::is_ascii_digit)
        );
        notifier
            .reload_refused("approval_config_malformed")
            .expect("reload refused");
        assert_eq!(
            receive(&receiver),
            b"READY=1\nSTATUS=Reload refused: approval_config_malformed"
        );
        notifier.next_watchdog = Some(Instant::now());
        notifier.watchdog_if_due().expect("watchdog");
        assert_eq!(receive(&receiver), b"WATCHDOG=1");
        notifier.main_pid(424_242).expect("main pid handover");
        assert_eq!(receive(&receiver), b"MAINPID=424242");
        notifier.stopping().expect("stopping");
        assert_eq!(receive(&receiver), b"STOPPING=1\nSTATUS=Stopping");
    }

    #[test]
    fn another_process_watchdog_is_not_ours_to_feed() {
        assert_eq!(
            watchdog_interval(Some(OsStr::new("1000")), Some(OsStr::new("4294967295"))),
            Ok(None)
        );
    }

    #[test]
    fn service_unit_matches_the_daemon_runtime_contract() {
        let unit = include_str!("../../../../packaging/systemd/automonique.service");
        for directive in [
            "Type=notify-reload",
            "NotifyAccess=main",
            "WatchdogSec=30s",
            "RuntimeDirectory=automonique",
            "StateDirectory=automonique",
            "Environment=XDG_RUNTIME_DIR=%t",
            "Environment=XDG_STATE_HOME=%S",
            "Delegate=yes",
            "Restart=on-failure",
            "ExecStart=%S/automonique/bin/automonique daemon --foreground",
        ] {
            assert!(
                unit.lines().any(|line| line == directive),
                "missing service contract directive: {directive}"
            );
        }
    }

    #[test]
    fn socket_unit_matches_the_inherited_admin_listener_contract() {
        let unit = include_str!("../../../../packaging/systemd/automonique.socket");
        for directive in [
            "ListenStream=%t/automonique/admin.sock",
            "SocketMode=0600",
            "DirectoryMode=0700",
            "FileDescriptorName=admin",
            "Service=automonique.service",
            "RemoveOnStop=yes",
        ] {
            assert!(
                unit.lines().any(|line| line == directive),
                "missing socket contract directive: {directive}"
            );
        }
    }

    #[test]
    fn disconnected_recovery_excludes_the_normal_socket_owner() {
        let unit = include_str!("../../../../packaging/systemd/automonique-recovery.service");
        assert!(
            unit.lines()
                .any(|line| line == "Conflicts=automonique.service automonique.socket")
        );
    }

    #[test]
    fn web_entry_restarts_after_an_unexpected_clean_exit() {
        let unit = include_str!("../../../../packaging/systemd/automonique-web-entry.service");
        for directive in ["Restart=always", "RestartSec=5s"] {
            assert!(
                unit.lines().any(|line| line == directive),
                "missing web-entry availability directive: {directive}"
            );
        }
    }

    fn receive(socket: &UnixDatagram) -> Vec<u8> {
        let mut buffer = [0_u8; 64];
        let size = socket.recv(&mut buffer).expect("notification");
        buffer[..size].to_vec()
    }
}
