// SPDX-License-Identifier: Elastic-2.0

#![cfg(target_os = "linux")]

//! Direct mechanism checks only. Running this fixed fixture does not create
//! product execution authority; the public boundary remains a typed refusal.

use nix::unistd::{close, dup2};
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "automonique-descriptor-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("workspace");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}

fn digest(path: &Path) -> String {
    let digest = Sha256::digest(fs::read(path).expect("read executable"));
    let mut result = String::with_capacity(64);
    for byte in digest {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

fn helper() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_automonique-fd-closure"))
}

#[test]
fn helper_closes_inherited_high_descriptor_before_fixed_fixture() {
    let workspace = TempDir::new();
    let metadata = fs::metadata(&workspace.0).expect("metadata");
    let helper_digest = digest(helper());
    let bwrap_digest = digest(Path::new("/usr/bin/bwrap"));
    let fixture_digest = digest(Path::new("/usr/bin/busybox"));
    let workspace_digest = "a".repeat(64);

    dup2(0, 314).expect("install inherited high descriptor");
    let output = Command::new(helper())
        .args([
            "--automonique-fd-closure-v1",
            "/usr/bin/bwrap",
            &bwrap_digest,
            "/usr/bin/busybox",
            &fixture_digest,
        ])
        .arg(&workspace.0)
        .args([
            metadata.dev().to_string(),
            metadata.ino().to_string(),
            helper_digest,
            "run-fixture".to_owned(),
            workspace_digest,
        ])
        .env_clear()
        .output()
        .expect("execute helper");
    close(314).expect("close test descriptor");
    assert!(
        output.status.success(),
        "helper refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let attestation = String::from_utf8(output.stdout).expect("utf8 attestation");
    assert!(
        attestation.contains("\nfds=0,1,2,3\n"),
        "unexpected attestation: {attestation:?}"
    );
    assert!(attestation.contains("\ncap_eff=0000000000000000\n"));
    assert!(attestation.contains("\nno_new_privs=1\n"));
    assert!(attestation.contains("\nroot_entries=busybox,dev,fixture,proc,workspace\n"));
}

#[test]
fn helper_rejects_widened_argv_before_execution() {
    let output = Command::new(helper())
        .args(["--automonique-fd-closure-v1", "unexpected"])
        .env_clear()
        .output()
        .expect("helper refusal");
    assert_eq!(output.status.code(), Some(64));
    assert!(output.stdout.is_empty());
}
