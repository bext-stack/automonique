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
fn helper_closes_inherited_high_descriptor_or_refuses_missing_fixed_dependency() {
    let workspace = TempDir::new();
    let metadata = fs::metadata(&workspace.0).expect("metadata");
    let helper_digest = digest(helper());
    let bwrap_path = Path::new("/usr/bin/bwrap");
    let fixture_path = Path::new("/usr/bin/busybox");
    let bwrap_available = fs::symlink_metadata(bwrap_path)
        .is_ok_and(|metadata| metadata.file_type().is_file());
    let fixture_available = fs::symlink_metadata(fixture_path)
        .is_ok_and(|metadata| metadata.file_type().is_file());
    let bwrap_digest = if bwrap_available {
        digest(bwrap_path)
    } else {
        "b".repeat(64)
    };
    let fixture_digest = if fixture_available {
        digest(fixture_path)
    } else {
        "c".repeat(64)
    };
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

    if !bwrap_available || !fixture_available {
        assert_eq!(output.status.code(), Some(64));
        assert!(output.stdout.is_empty());
        let expected_category = if bwrap_available {
            "fixture"
        } else {
            "bwrap"
        };
        assert_eq!(
            String::from_utf8(output.stderr).expect("utf8 refusal"),
            format!("automonique fixture helper refused: {expected_category}\n")
        );
        return;
    }

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
