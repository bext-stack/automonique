// SPDX-License-Identifier: Elastic-2.0

#![cfg(target_os = "linux")]

//! Exercised proof that the Landlock allowlist denies what it says it denies.
//!
//! These tests do not assert that a ruleset was accepted. They launch a
//! disposable helper process, have it enforce a real policy on itself, and then
//! require that reads outside the allowlist actually fail, that a read-only
//! grant actually refuses writes, and that an execute grant is a bit a read
//! grant does not carry.
//!
//! The enforcement proofs cannot run in this process. A Landlock domain is
//! irreversible and covers the calling thread and every child it later spawns,
//! so applying one here would silently restrict the rest of the test binary.
//! Everything that must be observed *after* enforcement therefore runs in
//! `automonique-landlock-fs-probe`, which exists only to be restricted and then
//! exit.
//!
//! Refusals that happen before any syscall — path shape, grant bounds, and the
//! enforcement decision table — are checked in-process, because those are pure
//! decisions and nothing is applied to reach them.

use automonique_runner::filesystem::{
    FilesystemPolicy, FilesystemPolicyError, KernelSupport, MAX_GRANT_PATH_BYTES, MAX_PATH_GRANTS,
    POLICY_LANDLOCK_ABI, PathIntent, RulesetEnforcement, assess_enforcement,
};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const HELPER: &str = env!("CARGO_BIN_EXE_automonique-landlock-fs-probe");
/// Landlock allows a bounded number of stacked domains; exceeding it must be a
/// typed refusal rather than a silently unrestricted process.
const OVER_LAYER_LIMIT: &str = "17";
/// A dynamically linked program present on any host with coreutils, used to
/// prove that execute is a distinct grant.
const EXECUTABLE_FIXTURE: &str = "/usr/bin/true";

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "automonique-filesystem-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create workspace");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("workspace mode");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn file(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, contents).expect("seed file");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ProbeRun {
    code: i32,
    stdout: String,
}

impl ProbeRun {
    /// The recorded outcome of one probe, or a panic naming what was printed.
    fn outcome(&self, kind: &str, path: &Path) -> &str {
        let prefix = format!("probe {kind} {} = ", path.display());
        self.stdout
            .lines()
            .find_map(|line| line.strip_prefix(prefix.as_str()))
            .unwrap_or_else(|| {
                panic!(
                    "no result for probe {kind} {} in helper output:\n{}",
                    path.display(),
                    self.stdout
                )
            })
    }

    fn assert_allowed(&self, kind: &str, path: &Path) {
        let outcome = self.outcome(kind, path);
        assert_eq!(
            outcome,
            "ALLOWED",
            "expected {kind} {} to be allowed, helper said {outcome}\n{}",
            path.display(),
            self.stdout
        );
    }

    fn assert_denied(&self, kind: &str, path: &Path) {
        let outcome = self.outcome(kind, path);
        assert!(
            outcome.starts_with("DENIED"),
            "expected {kind} {} to be denied, helper said {outcome}\n{}",
            path.display(),
            self.stdout
        );
    }

    fn field(&self, name: &str) -> &str {
        let prefix = format!("{name}=");
        self.stdout
            .lines()
            .find_map(|line| line.strip_prefix(prefix.as_str()))
            .unwrap_or_else(|| panic!("no {name} in helper output:\n{}", self.stdout))
    }

    /// Require that the helper enforced, and that the ABI it reported is at
    /// least the one the policy handles.
    fn assert_enforced(&self) {
        assert_eq!(
            self.code, 0,
            "helper did not enforce the policy:\n{}",
            self.stdout
        );
        let kernel_abi: u8 = self.field("kernel_abi").parse().expect("kernel abi");
        assert!(
            kernel_abi >= POLICY_LANDLOCK_ABI,
            "reported kernel ABI {kernel_abi} is below the policy ABI {POLICY_LANDLOCK_ABI}"
        );
        assert_eq!(
            self.field("policy_abi"),
            POLICY_LANDLOCK_ABI.to_string(),
            "helper reported a policy ABI this build does not handle"
        );
    }

    /// Require that the helper refused, naming `expected` in the refusal.
    fn assert_refused(&self, expected: &str) {
        assert_eq!(
            self.code, 3,
            "helper did not refuse; it exited {}:\n{}",
            self.code, self.stdout
        );
        let refusal = self.field("refused");
        assert!(
            refusal.contains(expected),
            "refusal {refusal:?} does not mention {expected:?}"
        );
    }
}

fn probe<S: AsRef<OsStr>>(arguments: &[S]) -> ProbeRun {
    let output = Command::new(HELPER)
        .args(arguments)
        .output()
        .expect("run landlock filesystem probe");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stdout.is_empty() || !stderr.is_empty(),
        "helper produced no output at all"
    );
    ProbeRun {
        code: output.status.code().unwrap_or(-1),
        stdout: format!("{stdout}{stderr}"),
    }
}

fn argument(value: &Path) -> String {
    value.to_str().expect("utf-8 test path").to_owned()
}

// ---------------------------------------------------------------------------
// Enforcement proofs. Every assertion below is about what a restricted process
// could still do.
// ---------------------------------------------------------------------------

#[test]
fn allowlisted_path_is_readable_and_everything_else_is_denied() {
    let workspace = TempDir::new("inside-outside");
    let inside = workspace.file("inside.txt", "granted");
    let outside = Path::new("/etc/hostname");

    let run = probe(&[
        "--grant",
        "read",
        &argument(workspace.path()),
        "--probe",
        "read-file",
        &argument(&inside),
        "--probe",
        "list-dir",
        &argument(workspace.path()),
        "--probe",
        "read-file",
        &argument(outside),
        "--probe",
        "list-dir",
        "/etc",
    ]);

    run.assert_enforced();
    run.assert_allowed("read-file", &inside);
    run.assert_allowed("list-dir", workspace.path());
    // The core proof: the allowlist is an allowlist.
    run.assert_denied("read-file", outside);
    run.assert_denied("list-dir", Path::new("/etc"));
}

#[test]
fn empty_policy_denies_the_whole_filesystem() {
    let workspace = TempDir::new("deny-all");
    let inside = workspace.file("inside.txt", "granted to nobody");

    let run = probe(&[
        "--probe",
        "read-file",
        &argument(&inside),
        "--probe",
        "list-dir",
        &argument(workspace.path()),
        "--probe",
        "read-file",
        "/etc/hostname",
    ]);

    run.assert_enforced();
    run.assert_denied("read-file", &inside);
    run.assert_denied("list-dir", workspace.path());
    run.assert_denied("read-file", Path::new("/etc/hostname"));
}

#[test]
fn read_only_grant_refuses_writes() {
    let workspace = TempDir::new("read-only");
    let inside = workspace.file("inside.txt", "read me");
    let fresh = workspace.path().join("fresh.txt");

    let run = probe(&[
        "--grant",
        "read",
        &argument(workspace.path()),
        "--probe",
        "read-file",
        &argument(&inside),
        "--probe",
        "write-file",
        &argument(&inside),
        "--probe",
        "create-file",
        &argument(&fresh),
        "--probe",
        "truncate",
        &argument(&inside),
    ]);

    run.assert_enforced();
    run.assert_allowed("read-file", &inside);
    run.assert_denied("write-file", &inside);
    run.assert_denied("create-file", &fresh);
    // Truncation is only restrictable from Landlock ABI 3. A denial here is the
    // behavioural cross-check that the reported ABI floor is real, rather than
    // a number the helper printed.
    run.assert_denied("truncate", &inside);

    assert_eq!(
        fs::read_to_string(&inside).expect("file survives"),
        "read me",
        "a denied write must not have reached the file"
    );
    assert!(!fresh.exists(), "a denied create must not leave a file");
}

#[test]
fn read_write_grant_allows_the_writes_a_read_grant_refuses() {
    let workspace = TempDir::new("read-write");
    let inside = workspace.file("inside.txt", "overwrite me");
    let fresh = workspace.path().join("fresh.txt");

    let run = probe(&[
        "--grant",
        "rw",
        &argument(workspace.path()),
        "--probe",
        "write-file",
        &argument(&inside),
        "--probe",
        "create-file",
        &argument(&fresh),
        "--probe",
        "truncate",
        &argument(&inside),
    ]);

    run.assert_enforced();
    run.assert_allowed("write-file", &inside);
    run.assert_allowed("create-file", &fresh);
    run.assert_allowed("truncate", &inside);
}

#[test]
fn execute_is_a_grant_a_read_grant_does_not_carry() {
    assert!(
        fs::metadata(EXECUTABLE_FIXTURE).is_ok_and(|metadata| metadata.is_file()),
        "{EXECUTABLE_FIXTURE} is required to prove the execute grant"
    );
    let workspace = TempDir::new("execute");
    let program = workspace.path().join("fixture");
    fs::copy(EXECUTABLE_FIXTURE, &program).expect("copy executable fixture");

    // Identical policies but for the workspace intent, so the only variable is
    // the execute right on the hierarchy holding the program.
    let readable = probe(&[
        "--grant",
        "read",
        &argument(workspace.path()),
        "--grant",
        "rx",
        "/usr",
        "--grant",
        "read",
        "/etc",
        "--probe",
        "read-file",
        &argument(&program),
        "--probe",
        "exec",
        &argument(&program),
    ]);
    readable.assert_enforced();
    readable.assert_allowed("read-file", &program);
    readable.assert_denied("exec", &program);

    let executable = probe(&[
        "--grant",
        "rx",
        &argument(workspace.path()),
        "--grant",
        "rx",
        "/usr",
        "--grant",
        "read",
        "/etc",
        "--probe",
        "exec",
        &argument(&program),
    ]);
    executable.assert_enforced();
    executable.assert_allowed("exec", &program);
}

#[test]
fn a_file_grant_covers_the_file_and_not_its_directory() {
    let workspace = TempDir::new("file-grant");
    let granted = workspace.file("granted.txt", "just this one");
    let sibling = workspace.file("sibling.txt", "not this one");

    let run = probe(&[
        "--grant",
        "read",
        &argument(&granted),
        "--probe",
        "read-file",
        &argument(&granted),
        "--probe",
        "read-file",
        &argument(&sibling),
        "--probe",
        "list-dir",
        &argument(workspace.path()),
    ]);

    run.assert_enforced();
    run.assert_allowed("read-file", &granted);
    run.assert_denied("read-file", &sibling);
    run.assert_denied("list-dir", workspace.path());
}

// ---------------------------------------------------------------------------
// Fail-closed proofs.
// ---------------------------------------------------------------------------

#[test]
fn a_multi_threaded_caller_is_refused_rather_than_half_restricted() {
    let workspace = TempDir::new("threads");

    let run = probe(&[
        "--extra-thread",
        "--grant",
        "read",
        &argument(workspace.path()),
        "--probe",
        "read-file",
        "/etc/hostname",
    ]);

    run.assert_refused("more than one thread");
}

#[test]
fn exhausting_the_kernel_layer_limit_is_a_typed_refusal() {
    let workspace = TempDir::new("layers");

    // `/proc` is granted because each further application re-confirms the
    // caller is single-threaded, which reads `/proc/self/status`.
    let run = probe(&[
        "--layers",
        OVER_LAYER_LIMIT,
        "--grant",
        "read",
        "/proc",
        "--grant",
        "read",
        &argument(workspace.path()),
    ]);

    run.assert_refused("landlock_restrict_self failed");
}

#[test]
fn a_symlinked_grant_path_is_refused_rather_than_silently_following() {
    let workspace = TempDir::new("symlink");
    let target = workspace.path().join("target");
    fs::create_dir(&target).expect("target directory");
    let link = workspace.path().join("link");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");

    let run = probe(&["--grant", "read", &argument(&link)]);

    run.assert_refused("symbolic link");
}

#[test]
fn a_missing_grant_path_is_refused_rather_than_dropped() {
    let workspace = TempDir::new("missing");
    let absent = workspace.path().join("absent");

    let run = probe(&["--grant", "read", &argument(&absent)]);

    run.assert_refused("does not exist");
}

#[test]
fn enforcement_is_refused_for_every_outcome_short_of_full() {
    let available = KernelSupport::Available {
        abi: POLICY_LANDLOCK_ABI,
        beyond_crate: None,
    };

    assert!(matches!(
        assess_enforcement(KernelSupport::Unavailable, RulesetEnforcement::Full, true),
        Err(FilesystemPolicyError::LandlockUnavailable)
    ));
    assert!(matches!(
        assess_enforcement(
            KernelSupport::Available {
                abi: POLICY_LANDLOCK_ABI - 1,
                beyond_crate: None,
            },
            RulesetEnforcement::Full,
            true,
        ),
        Err(FilesystemPolicyError::AbiTooOld {
            observed: Some(observed),
            required,
        }) if observed == POLICY_LANDLOCK_ABI - 1 && required == POLICY_LANDLOCK_ABI
    ));
    // A partially enforced ruleset is not the policy that was asked for, so it
    // is never reported as isolation.
    assert!(matches!(
        assess_enforcement(available, RulesetEnforcement::Partial, true),
        Err(FilesystemPolicyError::NotFullyEnforced)
    ));
    assert!(matches!(
        assess_enforcement(available, RulesetEnforcement::None, true),
        Err(FilesystemPolicyError::NotFullyEnforced)
    ));
    assert!(matches!(
        assess_enforcement(available, RulesetEnforcement::Full, false),
        Err(FilesystemPolicyError::NoNewPrivsNotSet)
    ));

    let isolation = assess_enforcement(
        KernelSupport::Available {
            abi: POLICY_LANDLOCK_ABI + 2,
            beyond_crate: Some(99),
        },
        RulesetEnforcement::Full,
        true,
    )
    .expect("a fully enforced ruleset on a supported ABI is isolation");
    assert_eq!(isolation.kernel_abi(), POLICY_LANDLOCK_ABI + 2);
    assert_eq!(isolation.policy_abi(), POLICY_LANDLOCK_ABI);
    // A kernel newer than the crate offers rights this policy does not handle;
    // that is reported, not hidden.
    assert_eq!(isolation.kernel_abi_beyond_crate(), Some(99));
}

#[test]
fn grant_paths_must_be_bounded_absolute_hierarchies() {
    for rejected in [
        "relative/path",
        "/has/../parent",
        "/has/./current",
        "/has//empty",
        "/has/trailing/",
        "/",
        "",
        "..",
    ] {
        let error = FilesystemPolicy::deny_all()
            .grant(PathIntent::Read, rejected)
            .err()
            .unwrap_or_else(|| panic!("{rejected:?} must be refused as a grant path"));
        assert!(
            matches!(error, FilesystemPolicyError::GrantPathRejected(_)),
            "{rejected:?} produced {error}"
        );
    }

    let oversized = format!("/{}", "a".repeat(MAX_GRANT_PATH_BYTES));
    assert!(matches!(
        FilesystemPolicy::deny_all().grant(PathIntent::Read, oversized),
        Err(FilesystemPolicyError::GrantPathRejected(_))
    ));

    let accepted = FilesystemPolicy::deny_all()
        .grant(PathIntent::ReadWrite, "/usr/lib")
        .expect("an absolute path below the root is a grant");
    assert_eq!(accepted.grants().len(), 1);
    assert_eq!(accepted.grants()[0].path(), Path::new("/usr/lib"));
    assert_eq!(accepted.grants()[0].intent(), PathIntent::ReadWrite);
}

#[test]
fn the_allowlist_is_bounded_and_unambiguous() {
    let mut policy = FilesystemPolicy::deny_all();
    for index in 0..MAX_PATH_GRANTS {
        policy = policy
            .grant(PathIntent::Read, format!("/grant-{index}"))
            .expect("grants within the bound are accepted");
    }
    assert_eq!(policy.grants().len(), MAX_PATH_GRANTS);
    assert!(matches!(
        policy.clone().grant(PathIntent::Read, "/one-too-many"),
        Err(FilesystemPolicyError::TooManyGrants)
    ));

    let duplicated = FilesystemPolicy::deny_all()
        .grant(PathIntent::Read, "/usr/lib")
        .expect("first grant")
        .grant(PathIntent::ReadWrite, "/usr/lib");
    assert!(matches!(
        duplicated,
        Err(FilesystemPolicyError::DuplicateGrantPath(_))
    ));
}
