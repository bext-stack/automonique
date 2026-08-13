// SPDX-License-Identifier: Elastic-2.0

#![cfg(target_os = "linux")]

//! Direct mechanism checks on descriptor closure. Every check that matters is
//! made against the kernel's own view or against a descriptor genuinely
//! inherited by a child process, because a closure test that only reads back
//! the library's own bookkeeping proves nothing about the workload.
//!
//! Tests that create, inherit or close descriptors hold a single process-wide
//! lock. The test harness runs tests on concurrent threads, and a descriptor
//! table is process-wide: without serialisation one test's leaked descriptor
//! would be inherited by another test's child, and one test's `close` would
//! disturb another test's enumeration.

use automonique_runner::descriptors::{
    DescriptorAllowlist, DescriptorError, MAX_ALLOWLIST_DESCRIPTOR, MAX_ALLOWLIST_LEN,
    descriptor_is_open, open_descriptors, verify_only_allowlist_open,
};
use nix::fcntl::{FcntlArg, fcntl};
use nix::unistd::close;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::os::fd::{AsRawFd as _, RawFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

/// Serialises every test that touches this process's descriptor table.
static DESCRIPTOR_TABLE: Mutex<()> = Mutex::new(());

/// Marker content read back through an inherited descriptor.
const MARKER: &str = "automonique-retained-marker";

fn exclusive() -> MutexGuard<'static, ()> {
    DESCRIPTOR_TABLE
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "automonique-descriptors-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("workspace");
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn probe() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_automonique-descriptor-probe"))
}

/// Duplicate `source` onto a descriptor at or above 300 with no `FD_CLOEXEC`.
///
/// `F_DUPFD` clears the close-on-exec flag on the new descriptor by
/// definition, so this is precisely the accident the module exists to undo: a
/// descriptor that survives `execv` into an untrusted workload. Choosing a
/// number the process is not already using keeps the leak from displacing a
/// descriptor the harness relies on.
fn leak_into_children(source: RawFd) -> RawFd {
    fcntl(source, FcntlArg::F_DUPFD(300)).expect("duplicate without close-on-exec")
}

fn run_probe(
    mode: &str,
    result: &Path,
    allowlist: &str,
    marker_fd: RawFd,
) -> BTreeMap<String, String> {
    let output = Command::new(probe())
        .args(["--automonique-descriptor-probe-v1", mode])
        .arg(result)
        .args([allowlist.to_owned(), marker_fd.to_string()])
        .env_clear()
        .output()
        .expect("execute descriptor probe");
    assert!(
        output.status.success(),
        "probe refused with {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = fs::read_to_string(result).expect("probe report");
    report
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

fn field<'report>(report: &'report BTreeMap<String, String>, key: &str) -> &'report str {
    report
        .get(key)
        .unwrap_or_else(|| panic!("report has no {key}: {report:?}"))
}

fn descriptors(value: &str) -> Vec<RawFd> {
    if value.is_empty() {
        return Vec::new();
    }
    value
        .split(',')
        .map(|entry| entry.parse::<RawFd>().expect("descriptor number"))
        .collect()
}

fn marker_file(workspace: &TempDir) -> File {
    let path = workspace.join("marker");
    fs::write(&path, MARKER).expect("write marker");
    File::open(&path).expect("open marker")
}

#[test]
fn closure_removes_a_descriptor_deliberately_leaked_into_a_child() {
    let _serial = exclusive();
    let workspace = TempDir::new();
    let result = workspace.join("report");
    let marker = marker_file(&workspace);
    let leaked = leak_into_children(marker.as_raw_fd());

    let report = run_probe("close", &result, "0,1,2", -1);
    close(leaked).expect("close the parent's leaked descriptor");

    let before = descriptors(field(&report, "before"));
    assert!(
        before.contains(&leaked),
        "the child did not inherit descriptor {leaked}, so this test proves nothing: {report:?}"
    );
    assert!(
        descriptors(field(&report, "closed")).contains(&leaked),
        "leaked descriptor was not closed: {report:?}"
    );
    assert_eq!(field(&report, "retained"), "0,1,2");
    assert_eq!(field(&report, "outcome"), "ok");
}

#[test]
fn an_allowlisted_descriptor_survives_and_still_works() {
    let _serial = exclusive();
    let workspace = TempDir::new();
    let result = workspace.join("report");
    let marker = marker_file(&workspace);
    let retained = leak_into_children(marker.as_raw_fd());

    let allowlist = format!("0,1,2,{retained}");
    let report = run_probe("retain", &result, &allowlist, retained);
    close(retained).expect("close the parent's leaked descriptor");

    assert_eq!(field(&report, "outcome"), "ok");
    assert!(
        descriptors(field(&report, "retained")).contains(&retained),
        "allowlisted descriptor was not retained: {report:?}"
    );
    assert!(
        !descriptors(field(&report, "closed")).contains(&retained),
        "allowlisted descriptor was closed: {report:?}"
    );
    // Surviving a listing is not the claim; the descriptor must still carry the
    // authority it was inherited with.
    assert_eq!(field(&report, "marker"), MARKER);
}

#[test]
fn standard_streams_are_not_exempt_from_closure() {
    let _serial = exclusive();
    let workspace = TempDir::new();
    let result = workspace.join("report");
    let marker = marker_file(&workspace);
    let leaked = leak_into_children(marker.as_raw_fd());

    // The report reaches this test from a child that closed its own stdout, so
    // it is delivered through a file the child opened after closure.
    let report = run_probe("close", &result, "-", -1);
    close(leaked).expect("close the parent's leaked descriptor");

    let before = descriptors(field(&report, "before"));
    for stream in [0, 1, 2, leaked] {
        assert!(
            before.contains(&stream),
            "descriptor {stream} was not open in the child: {report:?}"
        );
    }
    assert_eq!(
        descriptors(field(&report, "closed")),
        before,
        "an empty allowlist must close every descriptor: {report:?}"
    );
    assert_eq!(field(&report, "retained"), "");
    assert_eq!(field(&report, "outcome"), "ok");
}

#[test]
fn verification_detects_a_descriptor_opened_after_closure() {
    let _serial = exclusive();
    let workspace = TempDir::new();
    let result = workspace.join("report");

    let report = run_probe("residual", &result, "0,1,2", -1);

    assert_eq!(field(&report, "outcome"), "ok");
    let opened = field(&report, "probe_fd");
    assert_eq!(
        field(&report, "verify"),
        format!("residual:{opened}"),
        "verification accepted a descriptor outside the allowlist: {report:?}"
    );
}

#[test]
fn enumeration_reports_only_descriptors_that_are_open() {
    let _serial = exclusive();
    let workspace = TempDir::new();
    let observed = open_descriptors().expect("enumerate descriptors");
    for fd in &observed {
        assert!(
            descriptor_is_open(*fd).expect("probe descriptor"),
            "enumeration reported descriptor {fd}, which is not open"
        );
    }
    // The handle used to read /proc/self/fd is itself listed there. Reporting
    // it would make every enumeration disagree with the next.
    assert_eq!(
        observed,
        open_descriptors().expect("enumerate descriptors again"),
        "enumeration is not stable across calls"
    );

    let opened = marker_file(&workspace);
    let fd = opened.as_raw_fd();
    assert!(
        open_descriptors()
            .expect("enumerate with the file open")
            .contains(&fd),
        "enumeration missed an open descriptor {fd}"
    );
    drop(opened);
    assert!(
        !open_descriptors()
            .expect("enumerate with the file closed")
            .contains(&fd),
        "enumeration reported closed descriptor {fd}"
    );
}

#[test]
fn a_descriptor_required_to_survive_but_not_open_is_refused_before_anything_closes() {
    let _serial = exclusive();
    let workspace = TempDir::new();
    let result = workspace.join("report");
    let marker = marker_file(&workspace);
    let leaked = leak_into_children(marker.as_raw_fd());

    // Descriptor 900 is not open in the child, so the requested post-condition
    // cannot be established. The refusal is checked in a child rather than in
    // this process because a closure that started before checking would take
    // the test harness's own descriptors with it.
    let report = run_probe("retain", &result, "0,1,2,900", leaked);
    close(leaked).expect("close the parent's leaked descriptor");

    assert_eq!(
        field(&report, "outcome"),
        "refused:descriptor 900 was required to survive but is not open"
    );
    // The refusal must be total, not partial.
    assert_eq!(
        field(&report, "after"),
        field(&report, "before"),
        "a refusal changed the descriptor table: {report:?}"
    );
    // The descriptor the caller would have kept is not merely still listed; it
    // still reads.
    assert_eq!(field(&report, "marker"), MARKER);
}

#[test]
fn verification_refuses_when_a_required_descriptor_is_not_open() {
    let _serial = exclusive();
    let absent = (900..1000)
        .find(|fd| !descriptor_is_open(*fd).expect("probe descriptor"))
        .expect("an unused descriptor number");
    let mut required = open_descriptors().expect("enumerate descriptors");
    assert!(
        required.len() < MAX_ALLOWLIST_LEN,
        "this process holds too many descriptors for the test to name them all"
    );
    required.push(absent);

    let allowlist = DescriptorAllowlist::new(&required).expect("bounded allowlist");
    let error = verify_only_allowlist_open(&allowlist).expect_err("verification must refuse");
    assert!(
        matches!(error, DescriptorError::AllowlistNotOpen(fd) if fd == absent),
        "unexpected error: {error}"
    );
}

#[test]
fn verification_refuses_when_an_open_descriptor_is_outside_the_allowlist() {
    let _serial = exclusive();
    let workspace = TempDir::new();
    let keeper = marker_file(&workspace);
    let kept = keeper.as_raw_fd();

    let allowlist = DescriptorAllowlist::new(&[kept]).expect("bounded allowlist");
    let error = verify_only_allowlist_open(&allowlist).expect_err("verification must refuse");
    match error {
        DescriptorError::ResidualDescriptor(fd) => assert_ne!(fd, kept),
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn an_absurd_allowlist_is_refused() {
    let oversized = (0..=i32::try_from(MAX_ALLOWLIST_LEN).expect("bound fits a descriptor"))
        .collect::<Vec<RawFd>>();
    let error = DescriptorAllowlist::new(&oversized).expect_err("oversized allowlist");
    assert!(
        matches!(
            error,
            DescriptorError::AllowlistTooLarge { requested, limit }
                if requested == MAX_ALLOWLIST_LEN + 1 && limit == MAX_ALLOWLIST_LEN
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn descriptor_numbers_that_are_not_descriptors_are_refused() {
    for absurd in [-1, i32::MIN, MAX_ALLOWLIST_DESCRIPTOR + 1, i32::MAX] {
        let error = DescriptorAllowlist::new(&[absurd]).expect_err("invalid descriptor number");
        assert!(
            matches!(error, DescriptorError::DescriptorOutOfRange(fd) if fd == absurd),
            "unexpected error for {absurd}: {error}"
        );
    }
}

#[test]
fn an_allowlist_has_one_spelling() {
    let allowlist = DescriptorAllowlist::new(&[3, 1, 1, 2, 3]).expect("bounded allowlist");
    assert_eq!(allowlist.as_slice(), [1, 2, 3]);
    assert_eq!(allowlist.len(), 3);
    assert!(allowlist.contains(2));
    assert!(!allowlist.contains(0));
    assert!(DescriptorAllowlist::none().is_empty());
    assert_eq!(
        DescriptorAllowlist::standard_streams().as_slice(),
        [0, 1, 2]
    );
}
