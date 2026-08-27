// SPDX-License-Identifier: Elastic-2.0

//! TypeScript code generation checks.
//!
//! The generated SDK output and its compatibility behavior are checked here.
//!
//! Running this test regenerates `generated/spike.ts`. CI's zero-diff rule is
//! the reproducibility check: if regeneration changes the checked-in file, the
//! working tree is dirty.

use std::path::PathBuf;
use std::process::Command;

use automonique_protocol::admin::{
    AdminInstanceId, AdminResponse, DaemonState, DaemonStatus, DurableStateCounts,
    DurableStateCountsParts, MAX_ADMIN_CANONICAL_BYTES, MAX_INSTANCE_ID_BYTES, OperationalMetric,
    OperationalStatus, OperationalStatusParts,
};
use automonique_protocol::codec::RequestId;
use automonique_protocol::codegen::{SpikeSchema, emit_typescript, hostile_slice};
use automonique_protocol::wire::{JsonValue, Message};

mod platform_surface {
    use super::*;

    #[test]
    fn the_typescript_fixture_agrees_with_rust_and_fails_closed() {
        let runtime = javascript_runtime().unwrap_or_else(|| {
            record_js_gap("the platform cross-language fixture did not run");
            "bun"
        });
        if javascript_runtime().is_none() {
            return;
        }
        let output = Command::new(runtime)
            .arg(package_root().join("conformance/platform-runtime.ts"))
            .current_dir(package_root())
            .output()
            .expect("the TypeScript runtime starts");
        assert!(
            output.status.success(),
            "platform fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "{\"authority\":\"automonique\",\"id\":\"run-1\",\"kind\":\"run\"}\n\
             ValidationError\nValidationError\nValidationError\n"
        );
    }
}

mod platform_v2_transport_surface {
    use super::*;

    #[test]
    fn generated_typescript_matches_rust_transport_bytes_and_response_policy() {
        let runtime = javascript_runtime().unwrap_or_else(|| {
            record_js_gap("the Platform v2 transport cross-language fixture did not run");
            "bun"
        });
        if javascript_runtime().is_none() {
            return;
        }
        let output = Command::new(runtime)
            .arg(package_root().join("conformance/platform-v2-transport-runtime.ts"))
            .current_dir(package_root())
            .output()
            .expect("the TypeScript transport runtime starts");
        assert!(
            output.status.success(),
            "Platform v2 transport fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "{\"fixture_lines\":2,\"negotiation_bytes\":186,\"unoffered_refused\":true,\"v1_ceiling_preserved\":true,\"v2_bytes\":153}\n"
        );
    }
}

mod work_context_surface {
    use super::*;

    #[test]
    fn generated_typescript_keeps_distinct_identities_and_pages_past_512() {
        let runtime = javascript_runtime().unwrap_or_else(|| {
            record_js_gap("the work-context cross-language fixture did not run");
            "bun"
        });
        if javascript_runtime().is_none() {
            return;
        }
        let output = Command::new(runtime)
            .arg(package_root().join("conformance/work-context-runtime.ts"))
            .current_dir(package_root())
            .output()
            .expect("the TypeScript runtime starts");
        assert!(
            output.status.success(),
            "work-context fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "{\"identities\":9,\"items\":640,\"page_limit\":128,\"schema\":\"automonique.platform/v2\",\"refusals\":9,\"version\":2}\n"
        );
    }

    #[test]
    fn generated_typescript_consumes_the_shared_lineage_boundary_corpus() {
        let runtime = javascript_runtime().unwrap_or_else(|| {
            record_js_gap("the Platform v2 lineage fixture did not run");
            "bun"
        });
        if javascript_runtime().is_none() {
            return;
        }
        let output = Command::new(runtime)
            .arg(package_root().join("conformance/platform-v2-lineage-runtime.ts"))
            .current_dir(package_root())
            .output()
            .expect("the TypeScript lineage runtime starts");
        assert!(
            output.status.success(),
            "lineage fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "{\"cases\":9,\"codec_bytes\":578,\"providers\":4,\"question_links\":2,\"stale_heartbeats\":1}\n"
        );
    }
}

mod review_context_surface {
    use super::*;

    #[test]
    fn generated_typescript_preserves_review_fixture_and_authority_refusals() {
        let runtime = javascript_runtime().unwrap_or_else(|| {
            record_js_gap("the review-context cross-language fixture did not run");
            "bun"
        });
        if javascript_runtime().is_none() {
            return;
        }
        let output = Command::new(runtime)
            .arg(package_root().join("conformance/review-context-runtime.ts"))
            .current_dir(package_root())
            .output()
            .expect("the TypeScript runtime starts");
        assert!(
            output.status.success(),
            "review-context fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "{\"action\":\"rerun_check\",\"attention\":\"needs_you\",\"bytes\":1856,\"receipt\":\"poll_receipt\",\"refusals\":11,\"schema\":\"automonique.platform/review/v1\"}\n"
        );
    }
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn package_root() -> PathBuf {
    crate_root().join("../../../sdk/typescript/packages/protocol")
}

fn generated_path() -> PathBuf {
    package_root().join("generated/spike.ts")
}

/// A JavaScript runtime that can execute the `.ts` conformance scripts.
///
/// The capability rather than the name. Every caller hands this runtime a
/// TypeScript file, so a `node` too old to strip types answers `--version`
/// happily and then fails each caller with `ERR_UNKNOWN_FILE_EXTENSION` — a
/// loud failure that names the wrong thing. Probing what the callers need
/// turns that into an accurate report: a gap locally, and under
/// [`REQUIRE_JS_TOOLCHAIN_ENV`] a failure that says the runtime is missing.
///
/// bun is probed first because it is the runtime `generated/VERDICT.md`
/// measured under, and it is what CI pins.
fn javascript_runtime() -> Option<&'static str> {
    ["bun", "node"]
        .into_iter()
        .find(|candidate| runs_typescript(candidate))
}

/// Whether `candidate` can execute a TypeScript file.
fn runs_typescript(candidate: &str) -> bool {
    static PROBE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    // Unique per call: these tests run as threads of one process, so a fixed
    // name would let one probe delete the file another is about to run.
    let probe = std::env::temp_dir().join(format!(
        "automonique-runtime-probe-{}-{}.ts",
        std::process::id(),
        PROBE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    // The annotation is the point: a runtime that tolerates the extension but
    // does not erase types is no more use here than one that refuses it.
    if std::fs::write(&probe, "const ok: string = \"ok\";\nconsole.log(ok);\n").is_err() {
        return false;
    }
    let ran = Command::new(candidate)
        .arg(&probe)
        .output()
        .is_ok_and(|output| output.status.success());
    let _ = std::fs::remove_file(&probe);
    ran
}

/// Set to demand the JavaScript toolchain rather than tolerate its absence.
///
/// CI sets it, because on a runner a missing toolchain is a broken job
/// definition, not a fact about the environment. Locally it is unset, so a
/// contributor without bun installed still gets a green run.
const REQUIRE_JS_TOOLCHAIN_ENV: &str = "AUTOMONIQUE_REQUIRE_JS_TOOLCHAIN";

fn js_toolchain_required() -> bool {
    std::env::var(REQUIRE_JS_TOOLCHAIN_ENV).is_ok_and(|value| !value.is_empty() && value != "0")
}

/// Record a claim that needed the JavaScript toolchain to measure.
///
/// The single choke point every JavaScript gap in this file routes through, so
/// the policy is one decision rather than fifteen. Under
/// [`REQUIRE_JS_TOOLCHAIN_ENV`] it panics with the gap text: a runner that
/// never installed bun then fails the job instead of passing fifteen tests
/// that measured nothing, which is the failure this whole arrangement exists
/// to prevent — a skip and a pass are the same colour in a log.
///
/// Unset, it prints the gap as a `::warning::` annotation. Note that cargo
/// captures test output unless `--nocapture` is passed, so the annotation is a
/// belt-and-braces measure for the runs that do pass it; the env var is what
/// actually makes CI honest.
#[track_caller]
fn record_js_gap(note: &str) {
    assert!(
        !js_toolchain_required(),
        "GAP: {note}\n{REQUIRE_JS_TOOLCHAIN_ENV} is set, so an unmeasured claim is a \
         failure: install the JavaScript toolchain or stop asking CI to prove this."
    );
    eprintln!("::warning::GAP: {note}");
}

/// The exact `typescript` version `package.json` pins, as a bare version.
///
/// Read out of the manifest rather than written here, so the pin has one
/// spelling: bumping the dependency and forgetting this test is not a thing
/// that can happen. The extraction is deliberately literal — the crate has no
/// JSON dependency and this needs one field, not a parser.
fn pinned_typescript_version() -> String {
    let manifest_path = package_root().join("package.json");
    let manifest =
        std::fs::read_to_string(&manifest_path).expect("the package manifest is checked in");
    let key = "\"typescript\": \"";
    let start = manifest.find(key).unwrap_or_else(|| {
        panic!(
            "{} declares no typescript dependency",
            manifest_path.display()
        )
    }) + key.len();
    let rest = &manifest[start..];
    let end = rest.find('"').unwrap_or_else(|| {
        panic!(
            "{} has an unterminated typescript pin",
            manifest_path.display()
        )
    });
    let version = &rest[..end];
    assert!(
        version.starts_with(|character: char| character.is_ascii_digit()),
        "the typescript dependency is a range ({version:?}), not an exact pin; a range lets \
         the compiler that measures the negative cases change without a commit"
    );
    version.to_owned()
}

/// What `npx --offline tsc --version` prints, or `None` when it cannot run.
fn typescript_version() -> Option<String> {
    let output = Command::new("npx")
        .arg("--offline")
        .arg("tsc")
        .arg("--version")
        .current_dir(package_root())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Run `tsc` over one or more files, returning whether they typechecked.
fn typechecks(files: &[PathBuf]) -> Option<(bool, String)> {
    let mut command = Command::new("npx");
    command
        .arg("--offline")
        .arg("tsc")
        .arg("--noEmit")
        .arg("--strict")
        // Without this, tsc refuses with TS5112 whenever a tsconfig is present
        // and files are named on the command line. Every negative case would
        // then "fail" on a configuration error rather than the property it
        // guards, which is a vacuous pass.
        .arg("--ignoreConfig")
        .arg("--target")
        .arg("ES2023")
        .arg("--lib")
        .arg("ES2023,DOM")
        .arg("--module")
        .arg("ESNext")
        .arg("--moduleResolution")
        .arg("Bundler")
        .arg("--allowImportingTsExtensions")
        .args(files);
    let output = command.current_dir(package_root()).output().ok()?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Some((output.status.success(), combined))
}

/// One run of the runtime half of the spike.
struct RuntimeRun {
    /// The interpreter that ran it.
    runtime: &'static str,
    /// Whether it exited zero.
    success: bool,
    /// What it printed on standard output.
    stdout: String,
    /// What it printed on standard error.
    stderr: String,
}

/// Run `conformance/spike-runtime.ts`, or `None` when no runtime is installed.
///
/// The output is returned rather than asserted on so that two checks can share
/// one execution: one asserts the script passed, the other reads the
/// measurements it printed.
fn run_runtime_conformance() -> Option<RuntimeRun> {
    let runtime = javascript_runtime()?;
    let output = Command::new(runtime)
        .arg(package_root().join("conformance/spike-runtime.ts"))
        .current_dir(package_root())
        .output()
        .ok()?;
    Some(RuntimeRun {
        runtime,
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// Every refusal category one command surface's fields actually refuse with.
///
/// The two `match`es are the coverage gate rather than a convenience: a value
/// kind added to [`RequestValue`] or [`ResponseValue`] fails to compile here,
/// so a new way to refuse cannot reach the generated surface without a test
/// asking whether its category is declared. Both the Runs and the Automation
/// suites read it, so one arm covers both.
fn referenced_categories(surface: &automonique_protocol::codegen::CommandSurface) -> Vec<String> {
    use automonique_protocol::codegen::{RequestValidation, RequestValue, ResponseValue};

    let mut referenced = Vec::new();
    for field in surface.requests.iter().flat_map(|request| &request.fields) {
        match &field.value {
            RequestValue::Checked {
                refusal_category, ..
            }
            | RequestValue::NullableChecked {
                refusal_category, ..
            }
            | RequestValue::Integer {
                refusal_category, ..
            }
            | RequestValue::NullableInteger {
                refusal_category, ..
            } => referenced.push(refusal_category.clone()),
            RequestValue::RangedInteger {
                below_category,
                above_category,
                ..
            } => referenced.extend([below_category.clone(), above_category.clone()]),
            RequestValue::Enum {
                unknown_category, ..
            } => referenced.push(unknown_category.clone()),
            RequestValue::HexBytes {
                oversize_category, ..
            } => referenced.push(oversize_category.clone()),
            RequestValue::CheckedArray {
                refusal_category,
                oversize_category,
                empty_category,
                ..
            } => referenced.extend([
                refusal_category.clone(),
                oversize_category.clone(),
                empty_category.clone(),
            ]),
            // The categories a discriminated body refuses with belong to the
            // body rather than to the field that carries it, and are collected
            // from the surface's own list below.
            RequestValue::Discriminated { .. } => {}
            RequestValue::Object { .. } | RequestValue::NullableObject { .. } => {}
            RequestValue::ObjectArray {
                oversize_category, ..
            } => referenced.push(oversize_category.clone()),
            RequestValue::NullableEnumSet {
                empty_category,
                repeat_category,
                unknown_category,
                ..
            } => referenced.extend([
                empty_category.clone(),
                repeat_category.clone(),
                unknown_category.clone(),
            ]),
        }
    }
    // A coupling refuses under two categories of its own, and neither is any
    // one field's: they belong to the relation between two.
    for coupling in surface
        .requests
        .iter()
        .filter_map(|request| request.coupling.as_ref())
    {
        referenced.extend([
            coupling.required_category.clone(),
            coupling.forbidden_category.clone(),
        ]);
    }
    for (_, validation) in &surface.request_validations {
        referenced.push(match validation {
            RequestValidation::ExactlyOneNonNull {
                refusal_category, ..
            }
            | RequestValidation::ActionAuthority {
                refusal_category, ..
            }
            | RequestValidation::ExactCoordinate {
                refusal_category, ..
            } => refusal_category.clone(),
        });
    }
    for field in surface
        .responses
        .iter()
        .flat_map(|response| &response.fields)
        .chain(
            surface
                .body_objects
                .iter()
                .flat_map(|object| &object.fields),
        )
    {
        match &field.value {
            ResponseValue::Bool
            | ResponseValue::Object { .. }
            | ResponseValue::NullableObject { .. } => {}
            ResponseValue::Checked {
                refusal_category, ..
            }
            | ResponseValue::NullableChecked {
                refusal_category, ..
            }
            | ResponseValue::Integer {
                refusal_category, ..
            }
            | ResponseValue::NullableInteger {
                refusal_category, ..
            } => referenced.push(refusal_category.clone()),
            ResponseValue::Enum {
                unknown_category, ..
            } => referenced.push(unknown_category.clone()),
            ResponseValue::EnumArray {
                oversize_category,
                unknown_category,
                ..
            } => referenced.extend([oversize_category.clone(), unknown_category.clone()]),
            ResponseValue::CheckedArray {
                oversize_category,
                refusal_category,
                ..
            }
            | ResponseValue::IntegerArray {
                oversize_category,
                refusal_category,
                ..
            } => referenced.extend([oversize_category.clone(), refusal_category.clone()]),
            ResponseValue::ExactString {
                mismatch_category, ..
            } => referenced.push(mismatch_category.clone()),
            ResponseValue::RangedInteger {
                below_category,
                above_category,
                ..
            } => referenced.extend([below_category.clone(), above_category.clone()]),
            ResponseValue::ObjectArray {
                oversize_category, ..
            } => referenced.push(oversize_category.clone()),
        }
    }
    // A discriminated body refuses under four categories of its own: the two
    // ends of its payload's domain, the closed word it is discriminated on, and
    // the body shape its two keys can contradict.
    for body in &surface.discriminated_bodies {
        referenced.extend([
            body.unknown_tag_category.clone(),
            body.payload_below_category.clone(),
            body.payload_above_category.clone(),
            body.invalid_body_category.clone(),
        ]);
    }
    referenced
}

mod source_direction {
    use super::*;

    #[test]
    fn the_generated_file_is_written_from_the_rust_slice() {
        let generated = emit_typescript(&hostile_slice());
        std::fs::create_dir_all(package_root().join("generated")).expect("generated directory");
        // Write atomically. `reproducibility::the_checked_in_file_matches_regeneration`
        // reads this file in the same parallel run, and a plain write left it
        // momentarily zero-length — a flake that turns a workspace run red for
        // reasons unrelated to the code under test.
        let final_path = generated_path();
        let staging = final_path.with_extension("ts.staging");
        std::fs::write(&staging, &generated).expect("stage generated file");
        std::fs::rename(&staging, &final_path).expect("publish generated file");

        assert!(generated.contains("GENERATED by automonique_protocol::codegen"));
        assert!(generated.contains("Rust is the wire source of truth"));
        assert!(generated.contains("readonly field: string;"));
        assert!(generated.contains("this.field = field;"));
        assert!(generated.contains("this.violation = violation;"));
        assert!(
            !generated.contains("constructor(readonly"),
            "parameter properties require a TypeScript transform and fail in Node strip-only mode"
        );
        // Nothing hand-written may redefine a wire structure; the marker above
        // is what a reviewer greps for.
        assert!(!generated.contains("TODO"));
    }
}

mod slice_difficulty {
    use super::*;

    #[test]
    fn the_slice_contains_every_construct_the_contract_demands() {
        let slice = hostile_slice();
        assert!(
            slice.branded_ids.len() >= 2,
            "two branded domains are required to test cross-assignment"
        );
        assert!(
            !slice.bounded_strings.is_empty(),
            "a bounded string is required"
        );
        assert!(
            !slice.bounded_integers.is_empty(),
            "a bounded integer is required"
        );

        let union = slice.unions.first().expect("a union is required");
        assert!(
            union.variants.len() >= 3,
            "three or more variants are required"
        );
        assert!(
            union
                .variants
                .iter()
                .any(|variant| variant.payload.is_none()),
            "a payload-free variant is required"
        );

        let sensitivities: Vec<_> = slice
            .enums
            .iter()
            .map(|generated| generated.sensitivity)
            .collect();
        assert_eq!(
            sensitivities.len(),
            2,
            "both enum classes are required: {sensitivities:?}"
        );
        assert_ne!(
            sensitivities[0], sensitivities[1],
            "the two enums must differ in sensitivity"
        );

        let generated = emit_typescript(&slice);
        // Optional versus nullable, and an event kind the generator has not seen.
        assert!(generated.contains("readonly note?: string;"));
        assert!(generated.contains("readonly detail: string | null;"));
        assert!(generated.contains("MAX_UNKNOWN_EVENT_BYTES"));
    }
}

mod reproducibility {
    use super::*;

    #[test]
    fn regeneration_is_byte_identical() {
        let first = emit_typescript(&hostile_slice());
        for _ in 0..8 {
            assert_eq!(
                emit_typescript(&hostile_slice()),
                first,
                "generation is not deterministic"
            );
        }
    }

    #[test]
    fn construction_order_does_not_change_the_output() {
        let forward = hostile_slice();
        let mut reversed = SpikeSchema {
            branded_ids: forward.branded_ids.clone(),
            bounded_strings: forward.bounded_strings.clone(),
            bounded_integers: forward.bounded_integers.clone(),
            unions: forward.unions.clone(),
            enums: forward.enums.clone(),
        };
        reversed.branded_ids.reverse();
        reversed.enums.reverse();
        for union in &mut reversed.unions {
            union.variants.reverse();
        }
        assert_eq!(
            emit_typescript(&reversed),
            emit_typescript(&forward),
            "output depends on input ordering"
        );
    }

    #[test]
    fn the_output_embeds_nothing_time_or_host_dependent() {
        let generated = emit_typescript(&hostile_slice());
        for forbidden in ["20", "generated at", "timestamp", "/home/", "Z\n"] {
            if forbidden == "20" {
                // A bare year prefix would appear in an embedded date; the
                // slice itself contains no such literal.
                assert!(
                    !generated.contains("2026-") && !generated.contains("2025-"),
                    "an embedded date reached the output"
                );
                continue;
            }
            assert!(
                !generated.to_lowercase().contains(forbidden),
                "output contains {forbidden:?}"
            );
        }
    }

    #[test]
    fn the_checked_in_file_matches_regeneration() {
        // The file is written by `source_direction`; this asserts the checked-in
        // copy equals what the generator produces, which is the zero-diff rule
        // CI enforces on the working tree.
        let expected = emit_typescript(&hostile_slice());
        let actual = std::fs::read_to_string(generated_path())
            .expect("the generated file is checked in — run this test to create it");
        assert_eq!(actual, expected, "the checked-in file is stale");
    }
}

mod typescript_properties {
    use super::*;

    /// The compiler that runs the checks below is the one the package pins.
    ///
    /// Every negative case in this module asserts exact TypeScript diagnostic
    /// text, and a compiler major version can reword any of those sentences.
    /// Before the package declared `typescript` as a dependency,
    /// `npx --offline tsc` resolved whatever the ambient environment happened
    /// to supply — a global npm cache on one machine, a runner image on
    /// another — so a security-relevant conformance result could flip with no
    /// commit touching the repository. This test is what closes that: it reads
    /// the pin out of `package.json` and refuses a compiler that is not it.
    ///
    /// It is a test rather than a README line for the obvious reason — a
    /// README cannot fail.
    #[test]
    fn the_typescript_compiler_is_the_pinned_one() {
        let pinned = pinned_typescript_version();
        let Some(reported) = typescript_version() else {
            record_js_gap("tsc is unavailable; the pinned compiler version is unverified");
            return;
        };
        assert_eq!(
            reported.trim(),
            format!("Version {pinned}"),
            "npx resolved a TypeScript other than the pin in package.json.\n\
             The negative cases below assert exact compiler diagnostic text, so \
             a substituted compiler makes their result meaningless. Run \
             `bun install --frozen-lockfile` in {package}.",
            package = package_root().display()
        );
    }

    #[test]
    fn the_generated_file_typechecks() {
        let Some((ok, output)) = typechecks(&[generated_path()]) else {
            record_js_gap("tsc is unavailable; the codegen spike is unmeasured");
            return;
        };
        assert!(ok, "generated TypeScript does not typecheck:\n{output}");
    }

    /// The positive half of the negative cases.
    ///
    /// A file that fails to compile is evidence only when the same code
    /// compiles with the guarded property restored; otherwise a typo in an
    /// import path would look exactly like a preserved brand.
    /// `conformance/spike-runtime.ts` imports the same constructors from the
    /// same generated file and performs the same shape of assignment *within*
    /// one domain, so it must typecheck while `brand-crossing.ts` must not.
    /// Typechecking it also keeps the runtime measurements themselves under the
    /// compiler, which is where a stale cast would otherwise hide.
    #[test]
    fn the_runtime_conformance_script_typechecks() {
        let files = [
            package_root().join("conformance/spike-runtime.ts"),
            // The ambient `process` declaration the script relies on. The
            // package tsconfig picks it up by directory; a file list has to
            // name it.
            package_root().join("conformance/node-runtime.d.ts"),
        ];
        let Some((ok, output)) = typechecks(&files) else {
            record_js_gap("tsc is unavailable; the runtime conformance script is unmeasured");
            return;
        };
        assert!(
            ok,
            "conformance/spike-runtime.ts does not typecheck:\n{output}"
        );
    }

    /// Each negative case must fail to compile, and fail for the property it
    /// guards. A case that fails on a configuration or import error proves
    /// nothing, so the expected diagnostic is named per file.
    #[test]
    fn every_negative_case_fails_for_its_own_reason() {
        let expected: [(&str, &str); 4] = [
            ("bound-widening.ts", "is not assignable to type 'TurnId'"),
            (
                "brand-crossing.ts",
                "Type 'TurnId' is not assignable to type 'SessionId'",
            ),
            (
                "payload-free-variant.ts",
                "Property 'text' does not exist on type",
            ),
            (
                "union-nonexhaustive.ts",
                "is not assignable to parameter of type 'never'",
            ),
        ];
        let directory = package_root().join("conformance/negative");
        let present: Vec<String> = std::fs::read_dir(&directory)
            .expect("negative cases are checked in")
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                (path.extension()?.to_str()? == "ts")
                    .then(|| path.file_name()?.to_str().map(str::to_owned))?
            })
            .collect();
        assert_eq!(
            present.len(),
            expected.len(),
            "a negative case was added or removed without updating the expectations: {present:?}"
        );

        for (file, diagnostic) in expected {
            let path = directory.join(file);
            let Some((ok, output)) = typechecks(&[path]) else {
                record_js_gap("tsc is unavailable; negative cases are unmeasured");
                return;
            };
            assert!(!ok, "{file} compiled, so the property it guards was lost");
            assert!(
                output.contains(diagnostic),
                "{file} failed, but not for its own reason.\nexpected: {diagnostic}\nactual:\n{output}"
            );
        }
    }

    #[test]
    fn the_runtime_behaviour_matches_the_rust_bounds() {
        let Some(run) = run_runtime_conformance() else {
            record_js_gap("no JavaScript runtime; runtime behaviour is unmeasured");
            return;
        };
        assert!(
            run.success,
            "runtime property check failed under {}:\n{}{}",
            run.runtime, run.stdout, run.stderr
        );
        println!(
            "codegen runtime checks under {}: {}",
            run.runtime,
            run.stdout.trim()
        );
    }
}

mod verdict_quality {
    use super::*;

    /// The properties the contract's check table names, spelled as the verdict
    /// tabulates them.
    const PROPERTIES: [&str; 5] = [
        "Bound preservation",
        "Brand distinctness",
        "Union exhaustiveness",
        "Unknown-event tolerance",
        "Reproducibility",
    ];

    /// The results a property row may record. `null` is the contract's spelling
    /// for unmeasured; anything else is a word whose meaning nobody has fixed,
    /// and a reader would have to guess whether it counts as a pass.
    const RECOGNIZED_RESULTS: [&str; 4] = ["pass", "partial", "fail", "null"];

    fn verdict() -> String {
        std::fs::read_to_string(package_root().join("generated/VERDICT.md"))
            .expect("the spike verdict is checked in")
    }

    /// The whole table row the verdict records for one property.
    fn row<'a>(verdict: &'a str, property: &str) -> &'a str {
        let prefix = format!("| {property} |");
        verdict
            .lines()
            .find(|line| line.starts_with(&prefix))
            .unwrap_or_else(|| panic!("the verdict has no table row for {property}"))
    }

    /// The Result column of that row.
    fn result_cell(verdict: &str, property: &str) -> String {
        row(verdict, property)
            .split('|')
            .nth(2)
            .unwrap_or_else(|| panic!("the {property} row has no result column"))
            .trim()
            .to_owned()
    }

    /// The section listing what `R8B` is told it must plan for.
    fn constraints(verdict: &str) -> &str {
        let start = verdict
            .find("## Constraints")
            .expect("the verdict lists the constraints R8B must plan for");
        let rest = &verdict[start..];
        &rest[..rest.find("\n## ").unwrap_or(rest.len())]
    }

    /// Where a generated brand exists.
    #[derive(Debug, Eq, PartialEq)]
    enum BrandExistence {
        /// The type checker knows which domain a value came from; the value
        /// itself does not.
        CompileTimeOnly,
        /// The value carries its domain into the running program.
        Runtime,
    }

    /// Read the emitted constructor for `name` and decide where its brand
    /// exists.
    ///
    /// What the verdict must record is derived from the emitter here rather
    /// than hard-coded, so that changing the emitter changes the obligation
    /// instead of leaving a stale caveat behind. A constructor that returns its
    /// argument unchanged cannot carry a brand: the value that comes out is the
    /// value that went in.
    fn brand_existence(generated: &str, name: &str) -> BrandExistence {
        let signature = format!("export function {name}(value: string): {name} {{");
        let start = generated
            .find(&signature)
            .unwrap_or_else(|| panic!("{name} has no emitted constructor"));
        let body = &generated[start + signature.len()..];
        let end = body
            .find("\n}")
            .unwrap_or_else(|| panic!("{name}'s emitted constructor is unterminated"));
        if body[..end].contains(&format!("return value as {name};")) {
            BrandExistence::CompileTimeOnly
        } else {
            BrandExistence::Runtime
        }
    }

    /// The branded domains whose brand exists only in the type checker.
    fn erasing_brands(generated: &str, slice: &SpikeSchema) -> Vec<String> {
        // Without this, a slice that lost its branded domains would make every
        // question below vacuously true rather than loudly wrong.
        assert!(
            !slice.branded_ids.is_empty(),
            "the slice has no branded domain to judge"
        );
        slice
            .branded_ids
            .iter()
            .filter(|id| brand_existence(generated, &id.name) == BrandExistence::CompileTimeOnly)
            .map(|id| id.name.clone())
            .collect()
    }

    #[test]
    fn the_verdict_is_recorded_and_names_its_outcome() {
        let verdict = verdict();
        let recognized = ["recommended with named constraints", "not recommended"]
            .iter()
            .any(|outcome| verdict.contains(outcome))
            || verdict.contains("**Verdict:** recommended");
        assert!(
            recognized,
            "the verdict does not state a recognized outcome"
        );
        // Every property in the contract's table must be accounted for, and
        // accounted for as a result rather than as prose.
        for property in PROPERTIES {
            let cell = result_cell(&verdict, property);
            assert!(
                RECOGNIZED_RESULTS.contains(&cell.as_str()),
                "{property} records {cell:?}, which is not one of {RECOGNIZED_RESULTS:?}"
            );
            // A qualification recorded only in the table is a footnote a
            // planner reads past. Anything short of a clean pass must also
            // reach the list of what R8B has to plan for.
            if cell != "pass" {
                let key = property
                    .split_whitespace()
                    .next()
                    .expect("a property name is not empty")
                    .to_lowercase();
                assert!(
                    constraints(&verdict).to_lowercase().contains(&key),
                    "{property} is recorded as {cell:?}, but no constraint mentions {key:?}"
                );
            }
        }
        assert!(
            verdict.contains("R8B"),
            "the verdict does not state what a failure would cost R8B"
        );
    }

    /// The contract calls a brand that holds at compile time and erases at
    /// runtime a partial pass. This is what stops the verdict from recording it
    /// as a clean one.
    #[test]
    fn a_brand_that_erases_at_runtime_is_recorded_as_a_partial() {
        let slice = hostile_slice();
        let generated = emit_typescript(&slice);
        let erasing = erasing_brands(&generated, &slice);
        if erasing.is_empty() {
            // The emitter now carries brands into the value, so there is no
            // partial left to record. The obligation follows the emitter.
            return;
        }

        let verdict = verdict();
        let cell = result_cell(&verdict, "Brand distinctness");
        assert_eq!(
            cell, "partial",
            "the brands of {erasing:?} exist only in the type checker, which the contract records \
             as a partial pass, but the verdict records {cell:?}"
        );
        let recorded = row(&verdict, "Brand distinctness").to_lowercase();
        assert!(
            recorded.contains("runtime") && recorded.contains("eras"),
            "the brand distinctness row is marked partial without naming the runtime erasure that \
             makes it one: {recorded}"
        );
        let planned = constraints(&verdict).to_lowercase();
        assert!(
            planned.contains("brand") && planned.contains("runtime"),
            "no constraint tells R8B what the runtime erasure costs it"
        );
    }

    /// What the verdict records, what the emitter writes and what the generated
    /// code actually does must be the same claim. The first two are text; this
    /// compares them against the third by running it.
    #[test]
    fn what_the_runtime_measures_agrees_with_the_emitted_brand() {
        let slice = hostile_slice();
        let generated = emit_typescript(&slice);
        let emitted = if erasing_brands(&generated, &slice).len() == slice.branded_ids.len() {
            "erased"
        } else {
            "carried"
        };
        let Some(run) = run_runtime_conformance() else {
            record_js_gap("no JavaScript runtime; the brand's runtime existence is unmeasured");
            return;
        };
        let observed = run
            .stdout
            .lines()
            .find_map(|line| line.strip_prefix("brand-runtime-existence: "))
            .unwrap_or_else(|| {
                panic!(
                    "the runtime conformance script no longer reports whether the brand survives \
                     into the value:\n{}{}",
                    run.stdout, run.stderr
                )
            });
        assert_eq!(
            observed.trim(),
            emitted,
            "the emitted constructors say the brand is {emitted}, but running the generated code \
             under {} reports {observed}",
            run.runtime
        );
    }
}

/// A real encoded status message, built through the shipped constructors.
///
/// The projection is required and its counts have to agree with the aggregate,
/// so this is the smallest snapshot `to_message` will accept.
fn encoded_status() -> Message {
    let status = DaemonStatus::new(
        AdminInstanceId::new("codegen-status").expect("valid instance"),
        DaemonState::Ready,
        7,
        41,
        2,
        3,
        1,
        true,
    )
    .expect("base status")
    .with_operational(
        OperationalStatus::new(OperationalStatusParts {
            observed_ms: 100,
            reconciliation_pending: 0,
            outbox_pending_ready: 2,
            outbox_pending_delayed: 1,
            outbox_in_flight_live: 4,
            outbox_in_flight_ambiguous: 0,
            outbox_delivered: 5,
            outbox_dead_lettered: 6,
            outbox_oldest_ready_age_ms: 7,
            telegram_pollers_live: 0,
            telegram_pollers_expired: 0,
            telegram_offset_lag: OperationalMetric::Unavailable,
            provider_available: OperationalMetric::Unavailable,
            sandbox_launch_refusals: OperationalMetric::Unavailable,
        })
        .expect("valid projection"),
    )
    .expect("coherent snapshot")
    .with_durable_state(
        DurableStateCounts::new(DurableStateCountsParts {
            approvals_recorded: OperationalMetric::Measured(2),
            automation_scheduler_workers: OperationalMetric::Measured(1),
            automations_registered: OperationalMetric::Measured(1),
            // The epoch is this snapshot's own generation, which is what the
            // status carries above; any other number is refused.
            open_tenure_epoch: OperationalMetric::Measured(7),
            open_tenures: OperationalMetric::Measured(1),
            runs_registered: OperationalMetric::Measured(3),
            tenures_recorded: OperationalMetric::Unavailable,
        })
        .expect("coherent durable counts"),
    )
    .expect("coherent tenure observation");
    AdminResponse::Status {
        request_id: RequestId::new("req-codegen-1").expect("valid request ID"),
        status,
    }
    .to_message()
    .expect("a complete status encodes")
}

/// The maintained read surface: the doctor report and the admin status read.
///
/// These files differ from `generated/spike.ts` in one way that matters. The
/// spike file is rewritten by an ordinary test run, so the check that it
/// matches the generator can never fail — the same run that compares it wrote
/// it. These files are only rewritten when `REGENERATE_ENV` is set, so the
/// comparison is a real gate: a hand edit, a stale checkout or a generator
/// change without a regeneration all turn the suite red.
mod maintained_surface {
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;

    use automonique_protocol::codegen::{
        ADMIN_STATUS_MODULE, BARREL_MODULE, DOCTOR_MODULE, GENERATED_DIRECTORY, REGENERATE_COMMAND,
        REGENERATE_ENV, RUNTIME_MODULE, generated_files, generated_platform_v1_schema_digest,
        generated_schema_digest, maintained_modules, module_file_name,
    };
    use automonique_protocol::{
        MAX_DOCTOR_CHECKS, MAX_FINDING_CODE_BYTES, MAX_FINDING_MESSAGE_BYTES,
    };

    use super::*;

    fn generated_directory() -> PathBuf {
        package_root().join("generated")
    }

    fn files() -> BTreeMap<String, String> {
        generated_files().into_iter().collect()
    }

    /// The generated contents of one module, by stem.
    fn file(module: &str) -> String {
        let name = module_file_name(module);
        files()
            .remove(&name)
            .unwrap_or_else(|| panic!("{name} is not a generated file"))
    }

    /// Whether this run was asked to rewrite the checked-in files.
    fn regenerating() -> bool {
        std::env::var(REGENERATE_ENV).is_ok_and(|value| !value.is_empty() && value != "0")
    }

    /// The first place two texts diverge, named precisely enough to act on.
    fn first_difference(actual: &str, expected: &str) -> String {
        for (index, (left, right)) in actual.lines().zip(expected.lines()).enumerate() {
            if left != right {
                return format!("line {}: on disk {left:?}, generated {right:?}", index + 1);
            }
        }
        format!(
            "{} lines on disk, {} lines generated",
            actual.lines().count(),
            expected.lines().count()
        )
    }

    /// The field names one generated `_FIELDS` array carries, sorted.
    fn generated_fields(contents: &str, name: &str) -> Vec<String> {
        let marker = format!("export const {name}_FIELDS: readonly string[] = [\n");
        let start = contents
            .find(&marker)
            .unwrap_or_else(|| panic!("{name} has no generated field array"))
            + marker.len();
        let rest = &contents[start..];
        let end = rest
            .find("];")
            .unwrap_or_else(|| panic!("{name}'s generated field array is unterminated"));
        let mut names: Vec<String> = rest[..end]
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                Some(trimmed.strip_prefix('"')?.strip_suffix("\",")?.to_owned())
            })
            .collect();
        names.sort();
        names
    }

    /// The drift gate, and the regeneration that closes it.
    #[test]
    fn the_checked_in_files_match_regeneration() {
        let directory = generated_directory();
        let regenerating = regenerating();
        let mut stale = Vec::new();
        for (file_name, expected) in generated_files() {
            let path = directory.join(&file_name);
            if regenerating {
                std::fs::create_dir_all(&directory).expect("generated directory");
                // Publish atomically: the typecheck below reads these files in
                // the same parallel run, and a partial write would fail it for
                // a reason unrelated to the code under test.
                let staging = path.with_extension("ts.staging");
                std::fs::write(&staging, &expected).expect("stage generated file");
                std::fs::rename(&staging, &path).expect("publish generated file");
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(actual) if actual == expected => {}
                Ok(actual) => stale.push(format!(
                    "{file_name}: {}",
                    first_difference(&actual, &expected)
                )),
                Err(error) => stale.push(format!("{file_name}: cannot be read ({error})")),
            }
        }
        assert!(
            stale.is_empty(),
            "the checked-in TypeScript in {GENERATED_DIRECTORY} no longer matches the generator:\
             \n  {}\n\nRegenerate with: {REGENERATE_COMMAND}",
            stale.join("\n  ")
        );
    }

    /// A module deleted from the generator must not leave its output behind.
    ///
    /// Without this, dropping a schema would pass every other check while a
    /// stale file kept serving the surface it described.
    #[test]
    fn the_generated_directory_holds_nothing_the_generator_does_not_own() {
        if regenerating() {
            // A regeneration is publishing into this directory from a test
            // running beside this one, so its contents are legitimately in
            // flux. The ordinary run — the one CI makes — is the measurement.
            eprintln!("GAP: skipped during regeneration; rerun without {REGENERATE_ENV}");
            return;
        }
        let owned: BTreeSet<String> = generated_files()
            .into_iter()
            .map(|(name, _)| name)
            .chain(std::iter::once("spike.ts".to_owned()))
            .collect();
        let present: BTreeSet<String> = std::fs::read_dir(generated_directory())
            .expect("the generated directory is checked in")
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                // `.ts` only: this skips `VERDICT.md` and the `.ts.staging`
                // file a concurrent regeneration may be holding open.
                (path.extension()?.to_str()? == "ts")
                    .then(|| path.file_name()?.to_str().map(str::to_owned))?
            })
            .collect();
        assert_eq!(
            present, owned,
            "{GENERATED_DIRECTORY} does not hold exactly the files the generator owns; \
             regenerate with: {REGENERATE_COMMAND}"
        );
    }

    #[test]
    fn regeneration_is_byte_identical() {
        let first = generated_files();
        for _ in 0..8 {
            assert_eq!(
                generated_files(),
                first,
                "generation of the maintained surface is not deterministic"
            );
        }
    }

    #[test]
    fn the_output_embeds_nothing_time_or_host_dependent() {
        for (file_name, contents) in generated_files() {
            for forbidden in ["generated at", "timestamp", "/home/", "2026-", "2025-"] {
                assert!(
                    !contents.to_lowercase().contains(forbidden),
                    "{file_name} contains {forbidden:?}"
                );
            }
        }
    }

    /// Every bound in the output is the Rust constant, not a number retyped
    /// next to it.
    ///
    /// The expected text is built from the constant itself, so changing
    /// `MAX_FINDING_MESSAGE_BYTES` and forgetting to regenerate fails here as
    /// well as at the drift gate.
    #[test]
    fn the_generated_bounds_are_the_rust_constants() {
        let doctor = file(DOCTOR_MODULE);
        let admin = file(ADMIN_STATUS_MODULE);
        for (file_name, contents, declaration) in [
            (
                DOCTOR_MODULE,
                &doctor,
                format!("export const FindingCode_MAX_BYTES = {MAX_FINDING_CODE_BYTES};"),
            ),
            (
                DOCTOR_MODULE,
                &doctor,
                format!("export const FindingMessage_MAX_BYTES = {MAX_FINDING_MESSAGE_BYTES};"),
            ),
            (
                DOCTOR_MODULE,
                &doctor,
                format!("export const MAX_DOCTOR_CHECKS = {MAX_DOCTOR_CHECKS};"),
            ),
            (
                ADMIN_STATUS_MODULE,
                &admin,
                format!("export const AdminInstanceId_MAX_BYTES = {MAX_INSTANCE_ID_BYTES};"),
            ),
            (
                ADMIN_STATUS_MODULE,
                &admin,
                format!("export const MAX_ADMIN_CANONICAL_BYTES = {MAX_ADMIN_CANONICAL_BYTES};"),
            ),
            (
                ADMIN_STATUS_MODULE,
                &admin,
                format!("export const WireCounter_MAX = {}n;", i64::MAX),
            ),
        ] {
            assert!(
                contents.contains(&declaration),
                "{file_name} does not carry the Rust bound: {declaration}"
            );
        }

        // Declaring the bound is not using it. A generator that emitted the
        // right constant and then compared against a different literal would
        // pass everything above.
        for (file_name, contents, name, max_bytes) in [
            (
                DOCTOR_MODULE,
                &doctor,
                "FindingCode",
                MAX_FINDING_CODE_BYTES,
            ),
            (
                DOCTOR_MODULE,
                &doctor,
                "FindingMessage",
                MAX_FINDING_MESSAGE_BYTES,
            ),
            (
                ADMIN_STATUS_MODULE,
                &admin,
                "AdminInstanceId",
                MAX_INSTANCE_ID_BYTES,
            ),
        ] {
            let check = format!(
                "  if (byteLength(value) > {max_bytes}) throw new ValidationError(\"{name}\", \
                 \"too_long\");"
            );
            assert!(
                contents.contains(&check),
                "{file_name} declares {name}'s bound but does not check it: {check}"
            );
        }
    }

    /// The closed value sets, restated here rather than read back from the
    /// generator.
    ///
    /// A generator that dropped a variant would agree with itself perfectly;
    /// this is the second opinion that catches it.
    #[test]
    fn every_closed_enumeration_carries_all_of_its_variants() {
        let expected: [(&str, &str, &[&str]); 5] = [
            (
                DOCTOR_MODULE,
                "CheckStatus",
                &["finding", "healthy", "unavailable"],
            ),
            (
                DOCTOR_MODULE,
                "ReportStatus",
                &["degraded", "failed", "healthy"],
            ),
            (
                ADMIN_STATUS_MODULE,
                "DaemonState",
                &["draining", "failed", "ready", "starting", "stopped"],
            ),
            (
                ADMIN_STATUS_MODULE,
                "ExecutionState",
                &[
                    "sandbox_enforceable_lane_wired",
                    "sandbox_enforceable_no_lane",
                    "sandbox_unavailable_lane_wired",
                    "sandbox_unavailable_no_lane",
                ],
            ),
            (
                ADMIN_STATUS_MODULE,
                "TelegramState",
                &[
                    "disabled_no_client",
                    "lease_owned_no_client",
                    "polling_live",
                ],
            ),
        ];
        for (file_name, name, values) in expected {
            let contents = file(file_name);
            let literals: Vec<String> = values.iter().map(|value| format!("\"{value}\"")).collect();
            let declaration = format!("export type {name} = {};", literals.join(" | "));
            assert!(
                contents.contains(&declaration),
                "{file_name} lost a {name} variant.\nexpected: {declaration}"
            );
            let table = format!(
                "export const {name}_VALUES: readonly {name}[] = [{}];",
                literals.join(", ")
            );
            assert!(
                contents.contains(&table),
                "{file_name}'s {name} table does not match its type.\nexpected: {table}"
            );
            // Every one of these refuses an undefined spelling in Rust, so the
            // decoder must refuse it too rather than retain it.
            assert!(
                contents.contains(&format!(
                    "export function decode{name}(value: string): {name} {{"
                )),
                "{file_name} does not refuse an undefined {name}"
            );
        }
    }

    /// The unavailable arm is the one that must survive.
    ///
    /// `OperationalMetric` exists to stop a missing measurement from reading
    /// as a zero. A generated type that widened `value` to a plain counter
    /// would hand that mistake straight back to every client.
    #[test]
    fn the_operational_metric_union_keeps_its_unavailable_arm() {
        let admin = file(ADMIN_STATUS_MODULE);
        for arm in [
            "  | {readonly state: \"measured\"; readonly value: WireCounter}",
            "  | {readonly state: \"unavailable\"; readonly value: null}",
        ] {
            assert!(
                admin.contains(arm),
                "the OperationalMetric union lost an arm.\nexpected: {arm}"
            );
        }
        assert!(
            admin.contains("export function assertNeverOperationalMetric(value: never): never {"),
            "OperationalMetric has no exhaustiveness helper, so a dropped arm would go unnoticed \
             in TypeScript too"
        );
    }

    /// The generated field sets, measured against the encoder that produces the
    /// wire rather than against a list restated here.
    ///
    /// A list retyped in this file would only prove the generator agrees with
    /// my memory of `admin.rs`. Encoding a real [`DaemonStatus`] and reading
    /// the keys back compares the generated arrays with what the daemon
    /// actually sends, so a field added to the Rust body fails here on the
    /// next run instead of shipping a `_FIELDS` array the decoder would
    /// refuse.
    #[test]
    fn the_status_field_sets_are_the_encoders_own_field_sets() {
        let admin = file(ADMIN_STATUS_MODULE);
        let JsonValue::Object(body) = encoded_status().body().clone() else {
            panic!("a status message body is an object");
        };
        let keys = |entries: &[(String, JsonValue)]| -> Vec<String> {
            let mut names: Vec<String> = entries.iter().map(|(name, _)| name.clone()).collect();
            names.sort();
            names
        };

        assert_eq!(
            generated_fields(&admin, "DaemonStatus"),
            keys(&body),
            "the generated DaemonStatus field set is not what the admin encoder writes; \
             regenerate with: {REGENERATE_COMMAND}"
        );

        let Some(JsonValue::Object(operational)) = body
            .iter()
            .find(|(name, _)| name == "operational")
            .map(|(_, value)| value.clone())
        else {
            panic!("the status body carries an operational projection");
        };
        assert_eq!(
            generated_fields(&admin, "OperationalStatus"),
            keys(&operational),
            "the generated OperationalStatus field set is not what the admin encoder writes; \
             regenerate with: {REGENERATE_COMMAND}"
        );

        let Some(JsonValue::Object(durable_state)) = body
            .iter()
            .find(|(name, _)| name == "durable_state")
            .map(|(_, value)| value.clone())
        else {
            panic!("the status body carries the durable-state counts");
        };
        assert_eq!(
            generated_fields(&admin, "DurableStateCounts"),
            keys(&durable_state),
            "the generated DurableStateCounts field set is not what the admin encoder writes; \
             regenerate with: {REGENERATE_COMMAND}"
        );
    }

    /// Present-and-null is not the same fact as absent, and the status body
    /// carries exactly one field of the first kind.
    #[test]
    fn the_status_snapshot_keeps_nullable_apart_from_optional() {
        let admin = file(ADMIN_STATUS_MODULE);
        assert!(
            admin.contains("  readonly telegram_poller_epoch: WireCounter | null;"),
            "the nullable poller epoch lost its null"
        );
        assert!(
            admin.contains("  readonly operational: OperationalStatus;"),
            "the operational projection is required on the wire, not nullable"
        );
        assert!(
            admin.contains("  readonly durable_state: DurableStateCounts;"),
            "the durable-state counts are required on the wire, not nullable"
        );
        // A count that could not be read is `unavailable` inside the metric
        // union, never a missing or null field: the absence is carried by the
        // value, so a reader cannot mistake it for a store holding nothing.
        assert!(
            admin.contains("  readonly runs_registered: OperationalMetric;"),
            "a durable count must carry its own unavailability, not be omitted"
        );
        assert!(
            !admin.contains("?:"),
            "no field of the status body may be absent; every key is required"
        );
    }

    /// The doctor report's own shapes.
    #[test]
    fn the_doctor_report_carries_its_bounded_reason() {
        let doctor = file(DOCTOR_MODULE);
        for declaration in [
            "  readonly code: FindingCode;",
            "  readonly message: FindingMessage;",
            "  readonly reason: DoctorReason | null;",
            "  readonly status: CheckStatus;",
            "  readonly checks: readonly DoctorCheck[];",
            "  readonly schema: typeof DOCTOR_REPORT_SCHEMA_V1;",
        ] {
            assert!(
                doctor.contains(declaration),
                "the doctor surface lost a declaration.\nexpected: {declaration}"
            );
        }
        // The grammars, not only the lengths. A code is lowercase and starts
        // with a letter; a message carries no control character.
        assert!(doctor.contains("export const FindingCode_PATTERN = /^[a-z][a-z0-9._-]*$/u;"));
        assert!(doctor.contains("export const FindingMessage_PATTERN = /^[^\\p{Cc}]+$/u;"));
    }

    /// The barrel must re-export every maintained module and not the spike.
    ///
    /// A module added to the generator but left out of the barrel would be
    /// generated, typechecked and unreachable — the failure mode that makes
    /// codegen look like it is working when nothing consumes it.
    #[test]
    fn the_barrel_reaches_every_maintained_module() {
        let name = module_file_name(BARREL_MODULE);
        let barrel = file(BARREL_MODULE);
        for module in maintained_modules() {
            let specifier = module.file_name.trim_end_matches(".ts");
            let line = format!("export * from \"./{specifier}.js\";");
            assert!(
                barrel.contains(&line),
                "{name} does not re-export {}, so nothing importing the package can reach \
                 it.\nexpected: {line}",
                module.file_name
            );
        }
        assert!(
            !barrel.contains("spike"),
            "the barrel re-exports the spike, whose own ValidationError collides with the \
             runtime module's"
        );
        // The barrel is a list of re-exports plus the schema digest, and
        // nothing else; any other declaration here would be surface no schema
        // describes.
        for line in barrel.lines() {
            assert!(
                line.is_empty()
                    || line.starts_with("//")
                    || line.starts_with("export * from ")
                    || line.starts_with("export const SCHEMA_DIGEST")
                    || line.starts_with("export const PLATFORM_V1_SCHEMA_DIGEST"),
                "{name} carries something other than a re-export or the schema digest: {line:?}"
            );
        }
    }

    /// The digest checked into the barrel is the one the generator computes.
    ///
    /// This is what makes the digest evidence rather than decoration: a schema
    /// change that reaches the emitted surface moves the digest, and a barrel
    /// that was not regenerated alongside it fails here by name instead of
    /// somewhere downstream where the SDK is admitted against a surface it does
    /// not have.
    #[test]
    fn the_barrel_digest_is_the_digest_of_the_generated_surface() {
        if regenerating() {
            // The barrel is being rewritten by a test running beside this one,
            // so what is on disk is legitimately in flux. The ordinary run —
            // the one CI makes — is the measurement.
            eprintln!("GAP: skipped during regeneration; rerun without {REGENERATE_ENV}");
            return;
        }
        let (algorithm, hex) = generated_schema_digest();
        // Deliberately the checked-in file rather than `file(BARREL_MODULE)`:
        // comparing the generator against itself would pass whatever is on
        // disk. The claim is that the committed digest is current.
        let path = generated_directory().join(module_file_name(BARREL_MODULE));
        let barrel = std::fs::read_to_string(&path).expect("the barrel is checked in");
        assert!(
            barrel.contains(&format!(
                "export const SCHEMA_DIGEST_ALGORITHM = \"{algorithm}\";"
            )),
            "the barrel does not name the digest algorithm; regenerate with: {REGENERATE_COMMAND}"
        );
        assert!(
            barrel.contains(&format!("export const SCHEMA_DIGEST = \"{hex}\";")),
            "the barrel's schema digest is not the digest of the generated surface; \
             regenerate with: {REGENERATE_COMMAND}"
        );
        // The shape the release manifest will parse it back with.
        assert_eq!(algorithm, "sha256");
        assert_eq!(
            hex.len(),
            64,
            "a sha256 digest is 64 hexadecimal characters"
        );
        assert!(
            hex.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "the digest is not lowercase hexadecimal: {hex}"
        );

        let (_, platform_v1_hex) = generated_platform_v1_schema_digest();
        assert!(
            barrel.contains(&format!(
                "export const PLATFORM_V1_SCHEMA_DIGEST = \"{platform_v1_hex}\";"
            )),
            "the barrel's Platform v1 digest does not identify the exact v1 module; \
             regenerate with: {REGENERATE_COMMAND}"
        );
        assert_ne!(
            platform_v1_hex, hex,
            "the Platform v1 package pin must be distinct from the additive aggregate surface"
        );
    }

    /// A changed surface must move the digest.
    ///
    /// Without this, a digest computed over a constant — or over a subset of
    /// the surface that happens to be stable — would pass the equality test
    /// above forever while identifying nothing.
    #[test]
    fn the_digest_covers_the_surface_it_claims_to() {
        let (_, hex) = generated_schema_digest();
        let barrel_name = module_file_name(BARREL_MODULE);
        let mut inputs: Vec<(String, String)> = generated_files()
            .into_iter()
            .filter(|(name, _)| name != &barrel_name)
            .collect();
        assert!(
            inputs.len() > 1,
            "the digest is computed over fewer modules than the surface has"
        );
        for index in 0..inputs.len() {
            let mut mutated = inputs.clone();
            mutated[index].1.push_str("\n// a schema change\n");
            assert_ne!(
                digest_of(&mutated),
                hex,
                "changing {} does not move the schema digest",
                mutated[index].0
            );
        }
        // Renaming a module moves it too: the name is part of the surface.
        inputs[0].0.push_str(".renamed");
        assert_ne!(
            digest_of(&inputs),
            hex,
            "renaming a module does not move the schema digest"
        );
    }

    /// The generator's digest fold, restated so the test measures the value
    /// rather than calling the function it is checking.
    fn digest_of(modules: &[(String, String)]) -> String {
        use automonique_protocol::digest::Sha256;

        let mut hasher = Sha256::new();
        for (file_name, contents) in modules {
            hasher.update(file_name.as_bytes());
            hasher.update(b"\n");
            hasher.update(contents.len().to_string().as_bytes());
            hasher.update(b"\n");
            hasher.update(contents.as_bytes());
        }
        hasher.finish().to_hex()
    }

    /// A generated file must say how to rewrite itself, and the command it
    /// names must be the one that works.
    #[test]
    fn every_generated_file_names_the_command_that_rewrites_it() {
        assert!(
            REGENERATE_COMMAND.contains(REGENERATE_ENV),
            "the documented regeneration command does not set the variable that triggers it"
        );
        for (file_name, contents) in generated_files() {
            assert!(
                contents.starts_with("// SPDX-License-Identifier: Apache-2.0\n"),
                "{file_name} does not open with the Apache-2.0 identifier the SDK tree requires"
            );
            assert!(
                !contents.contains("Elastic-2.0"),
                "{file_name} carries an Elastic-2.0 marker into the Apache-2.0 tree"
            );
            assert!(
                contents.contains(&format!("// Regenerate with: {REGENERATE_COMMAND}")),
                "{file_name} does not name the command that rewrites it"
            );
            assert!(
                contents.contains("GENERATED by automonique_protocol::codegen"),
                "{file_name} does not say it is generated"
            );
            assert!(
                !contents.contains("constructor(readonly"),
                "{file_name} uses a parameter property, which Node's strip-only loader rejects"
            );
            assert!(!contents.contains("TODO"), "{file_name} ships a TODO");
        }
    }

    /// Only the shared runtime file is hand-written prose; everything else is
    /// a description of a wire shape.
    #[test]
    fn only_the_shared_runtime_module_is_verbatim_typescript() {
        let mut seen_runtime = false;
        for module in maintained_modules() {
            if module.file_name == module_file_name(RUNTIME_MODULE) {
                seen_runtime = true;
                assert!(
                    !module.preamble.is_empty(),
                    "the runtime module lost the helpers every other module imports"
                );
                continue;
            }
            assert!(
                module.preamble.is_empty(),
                "{} smuggles hand-written TypeScript past the schema description",
                module.file_name
            );
        }
        assert!(
            seen_runtime,
            "no module provides the shared runtime helpers"
        );
    }

    /// The package's own tsconfig, over the whole package, generated files
    /// included. This is stricter than the flag set the spike's negative cases
    /// use: it turns on `exactOptionalPropertyTypes` and
    /// `noUncheckedIndexedAccess` as the SDK actually ships them.
    #[test]
    fn the_package_typechecks_with_the_generated_files() {
        let output = Command::new("npx")
            .arg("--offline")
            .arg("tsc")
            .arg("-p")
            .arg("./tsconfig.json")
            .current_dir(package_root())
            .output();
        let Ok(output) = output else {
            record_js_gap("tsc is unavailable; the generated surface is untypechecked");
            return;
        };
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success(),
            "the protocol package does not typecheck with the generated files:\n{combined}"
        );
    }
}

/// The `automonique.admin` command surface, measured across two languages.
///
/// # Where the comparison runs, and what each side is trusted for
///
/// `fixtures/admin-command-v1.json` is *generated* from the shipped Rust
/// constructors, unlike the hand-written corpus in `fixtures/wire-v1.json`.
/// Nothing in it is a prediction: every canonical byte string was produced by
/// encoding a real request, every refusal category was read back from the error
/// the Rust constructor or decoder actually returned, and every decoded
/// spelling came out of `AdminResponse::from_canonical_bytes` rather than out
/// of the value this file constructed.
///
/// `conformance/admin-command.ts` then rebuilds each request from the recorded
/// parameters with the *generated* encoders and compares its canonical bytes
/// with the recorded ones, decodes each recorded response and compares the
/// decoded spellings, and asserts the same inputs are refused under the same
/// categories. It writes every payload it produced to a file, and
/// [`the_generated_typescript_agrees_with_rust_byte_for_byte`] compares those
/// bytes with Rust's own encoding and feeds them back through
/// `AdminRequest::from_canonical_bytes`.
///
/// So the byte comparison happens twice, in both languages, and the maximal
/// `submit_run` — 24 KiB of document, too large to review as a literal and
/// therefore built on both sides from a rule — is compared in Rust, where the
/// bytes it should have are available rather than recorded.
mod command_surface {
    use core::fmt::Write as _;
    use std::collections::{BTreeMap, BTreeSet};

    use automonique_protocol::admin::{
        ADMIN_PROTOCOL, AdminCommand, AdminError, AdminOutboxEvidence, AdminOutboxEvidenceParts,
        AdminReconciliationEvidence, AdminRefusalCategory, AdminRequest, GenerationHandoffView,
        GenerationTenureView, GenerationsView, IntakePause, IntakeResume, MAX_INTAKE_REASON_BYTES,
        MAX_RUN_SUBMISSION_KEY_BYTES, MAX_SUBMITTED_RUN_SPEC_BYTES, OutboxReconciliation,
        OutboxReconciliationDecision, OutboxReconciliationParts, ReconciliationFailure,
        ReloadStatusView, ReloadTransitionView, SubmittedRunSpec, SyntheticSubmission,
    };
    use automonique_protocol::codec::{
        Envelope, MAX_REQUEST_ID_BYTES, MajorVersion, MessageKind, ProtocolName,
    };
    use automonique_protocol::codegen::{
        ADMIN_COMMAND_MODULE, CommandSurface, ConstantValue, REGENERATE_COMMAND, REGENERATE_ENV,
        RequestValue, generated_files, maintained_modules, module_file_name,
    };
    use automonique_protocol::digest::Sha256;
    use automonique_protocol::tools::RunId;

    use super::*;

    fn corpus_path() -> PathBuf {
        crate_root().join("fixtures/admin-command-v1.json")
    }

    fn runner_path() -> PathBuf {
        package_root().join("conformance/admin-command.ts")
    }

    /// Whether this run was asked to rewrite the checked-in corpus.
    fn regenerating() -> bool {
        std::env::var(REGENERATE_ENV).is_ok_and(|value| !value.is_empty() && value != "0")
    }

    /// The command surface the generator describes.
    fn surface() -> CommandSurface {
        maintained_modules()
            .into_iter()
            .find(|module| module.file_name == module_file_name(ADMIN_COMMAND_MODULE))
            .and_then(|module| module.command_surface)
            .expect("the admin command module describes a command surface")
    }

    /// The generated TypeScript of the command module.
    fn generated_admin_command() -> String {
        generated_files()
            .into_iter()
            .find(|(name, _)| *name == module_file_name(ADMIN_COMMAND_MODULE))
            .map(|(_, contents)| contents)
            .expect("the command module is generated")
    }

    pub(crate) fn request_id(value: &str) -> RequestId {
        RequestId::new(value).expect("a valid correlation identifier")
    }

    // -----------------------------------------------------------------------
    // The document rule
    //
    // A 24 KiB literal is not reviewable, so the corpus carries a rule and each
    // implementation builds the bytes from it. That the two read the rule the
    // same way is measured before any verdict about the encoders is believed:
    // the TypeScript side reports the payload it built, and the comparison is
    // against the payload Rust built from the same rule.
    // -----------------------------------------------------------------------

    const DOCUMENT_SEED: u8 = 7;
    const DOCUMENT_STEP: u8 = 37;

    fn ruled_document(length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| {
                let index = u8::try_from(index % 256).expect("a value below 256 is a byte");
                DOCUMENT_SEED.wrapping_add(index.wrapping_mul(DOCUMENT_STEP))
            })
            .collect()
    }

    pub(crate) fn text(value: &str) -> JsonValue {
        JsonValue::String(value.to_owned())
    }

    pub(crate) fn count(value: usize) -> JsonValue {
        JsonValue::Integer(i64::try_from(value).expect("a corpus count is within the wire range"))
    }

    pub(crate) fn hex(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(encoded, "{byte:02x}");
        }
        encoded
    }

    pub(crate) fn unhex(value: &str) -> Vec<u8> {
        assert!(value.len().is_multiple_of(2), "hex has two digits per byte");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(
                    core::str::from_utf8(pair).expect("hex digits are ASCII"),
                    16,
                )
                .expect("a hex byte")
            })
            .collect()
    }

    /// Every escape the canonical writer defines that a bounded coordinate may
    /// carry, and the two multibyte classes a UTF-16 runtime is most likely to
    /// mishandle: a three-byte character and a surrogate pair.
    ///
    /// Control characters are absent because the Rust constructor refuses them,
    /// so `\n` and `\t` cannot appear in a reason at all; the escapes that
    /// remain reachable are the quote and the backslash, and the solidus that
    /// canonical JSON pointedly does *not* escape.
    fn escaping_reason() -> String {
        "held: \"maintenance\" \\ paused by ops/oncall — naïve 日本語 🚀".to_owned()
    }

    // -----------------------------------------------------------------------
    // Requests
    // -----------------------------------------------------------------------

    /// One request fixture: what Rust encodes, and the parameters the other
    /// implementation builds the same request from.
    struct RequestCase {
        id: &'static str,
        note: &'static str,
        request: AdminRequest,
        /// Builder parameters, in the shape the runner reads for this kind.
        params: JsonValue,
        /// Whether the canonical bytes are small enough to review as a literal.
        inline_hex: bool,
    }

    fn request_cases() -> Vec<RequestCase> {
        let small_document = br#"{"schema":"automonique.run-spec/v1"}"#.to_vec();
        let small_submission = SubmittedRunSpec::sealed(small_document.clone(), "submit-run-key-1")
            .expect("a small document is carried");
        // A key of quotes is the worst case the Rust bound arithmetic budgets
        // for: every character escapes to two bytes, so a maximal key costs
        // twice its length inside the canonical body.
        let maximal_key = "\"".repeat(MAX_RUN_SUBMISSION_KEY_BYTES);
        let maximal_document = ruled_document(MAX_SUBMITTED_RUN_SPEC_BYTES);
        let maximal_submission =
            SubmittedRunSpec::sealed(maximal_document, maximal_key.clone()).expect("at the bound");
        let maximal_request_id = format!("req-{}", "a".repeat(MAX_REQUEST_ID_BYTES - 4));

        vec![
            RequestCase {
                id: "status-minimal",
                note: "a command with no arguments carries an empty object, not an absent body",
                request: AdminRequest::new(request_id("req-status-1"), AdminCommand::Status),
                params: JsonValue::Object(Vec::new()),
                inline_hex: true,
            },
            RequestCase {
                id: "shutdown-minimal",
                note: "the other argument-free command, which differs only in its kind",
                request: AdminRequest::new(request_id("req-shutdown-1"), AdminCommand::Shutdown),
                params: JsonValue::Object(Vec::new()),
                inline_hex: true,
            },
            RequestCase {
                id: "pause-intake-escaping",
                note: "a reason carrying every escape a bounded coordinate can reach, a \
                       three-byte character and a surrogate pair",
                request: AdminRequest::pause_intake(
                    request_id("req-pause-1"),
                    IntakePause::new("ops:on-call", escaping_reason()).expect("a valid pause"),
                ),
                params: JsonValue::Object(vec![
                    ("actor".to_owned(), text("ops:on-call")),
                    ("reason".to_owned(), text(&escaping_reason())),
                ]),
                inline_hex: true,
            },
            RequestCase {
                id: "resume-intake-ascii",
                note: "the resume body carries no reason: the durable pause already has one",
                request: AdminRequest::resume_intake(
                    request_id("req-resume-1"),
                    IntakeResume::new("ops:on-call").expect("a valid resume"),
                ),
                params: JsonValue::Object(vec![("actor".to_owned(), text("ops:on-call"))]),
                inline_hex: true,
            },
            RequestCase {
                id: "submit-run-small",
                note: "a document small enough to review as a literal, under its own digest",
                params: JsonValue::Object(vec![
                    ("document_hex".to_owned(), text(&hex(&small_document))),
                    ("idempotency_key".to_owned(), text("submit-run-key-1")),
                    (
                        "spec_digest".to_owned(),
                        text(&small_submission.spec_digest().to_string()),
                    ),
                ]),
                request: AdminRequest::submit_run(request_id("req-submit-1"), small_submission),
                inline_hex: true,
            },
            RequestCase {
                id: "submit-run-maximal",
                note: "every bound at once: a document at MAX_SUBMITTED_RUN_SPEC_BYTES, a \
                       correlation identifier at MAX_REQUEST_ID_BYTES, and an idempotency key \
                       at its bound whose every character escapes to two bytes",
                params: JsonValue::Object(vec![
                    (
                        "document_length".to_owned(),
                        count(MAX_SUBMITTED_RUN_SPEC_BYTES),
                    ),
                    ("idempotency_key".to_owned(), text(&maximal_key)),
                    (
                        "spec_digest".to_owned(),
                        text(&maximal_submission.spec_digest().to_string()),
                    ),
                ]),
                request: AdminRequest::submit_run(
                    request_id(&maximal_request_id),
                    maximal_submission,
                ),
                // 49 KiB of hex is not a reviewable literal; the bytes are
                // compared in Rust instead, against what Rust encoded.
                inline_hex: false,
            },
        ]
    }

    fn request_entry(case: &RequestCase) -> JsonValue {
        let message = case.request.to_message().expect("the request encodes");
        let canonical = message.to_canonical_bytes();
        // What the corpus records is checked against the shipped decoder before
        // it is written: a fixture Rust would not itself admit proves nothing.
        assert_eq!(
            AdminRequest::from_canonical_bytes(&canonical).expect("Rust admits its own encoding"),
            case.request,
            "{}: the Rust decoder does not admit the Rust encoding",
            case.id
        );
        assert!(
            canonical.len() <= MAX_ADMIN_CANONICAL_BYTES,
            "{}: the encoding does not fit one admin frame",
            case.id
        );
        let mut entry = vec![
            ("canonical_bytes".to_owned(), count(canonical.len())),
            ("id".to_owned(), text(case.id)),
            ("kind".to_owned(), text(message.envelope().kind().as_str())),
            ("note".to_owned(), text(case.note)),
            ("params".to_owned(), case.params.clone()),
            (
                "request_id".to_owned(),
                text(message.envelope().request_id().as_str()),
            ),
        ];
        if case.inline_hex {
            entry.push(("canonical_hex".to_owned(), text(&hex(&canonical))));
        }
        JsonValue::Object(entry)
    }

    // -----------------------------------------------------------------------
    // Responses
    // -----------------------------------------------------------------------

    struct ResponseCase {
        id: &'static str,
        note: &'static str,
        response: AdminResponse,
    }

    fn response_cases() -> Vec<ResponseCase> {
        let digest = Sha256::digest(b"a canonical run specification document");
        vec![
            ResponseCase {
                id: "run-accepted-largest-submission",
                note: "a submission identity at the wire's ceiling, which a decoder carrying \
                       identities in a double would round to an even neighbour",
                response: AdminResponse::RunAccepted {
                    request_id: request_id("req-submit-1"),
                    run_id: RunId::new("run-01J8Z9Q").expect("a valid run identity"),
                    spec_digest: digest,
                    submission_id: u64::try_from(i64::MAX).expect("the wire ceiling is positive"),
                    replay: false,
                },
            },
            ResponseCase {
                id: "run-accepted-replay",
                note: "the exact retry of a submission already held; custody, not a second one",
                response: AdminResponse::RunAccepted {
                    request_id: request_id("req-submit-1"),
                    run_id: RunId::new("run-01J8Z9Q").expect("a valid run identity"),
                    spec_digest: digest,
                    submission_id: 1,
                    replay: true,
                },
            },
            ResponseCase {
                id: "intake-paused",
                note: "the fencing revision an exact resume must present",
                response: AdminResponse::IntakePaused {
                    request_id: request_id("req-pause-1"),
                    pause_id: 12,
                    revision: 3,
                },
            },
            ResponseCase {
                id: "intake-resumed",
                note: "the same body under a different kind: the pause row is retained",
                response: AdminResponse::IntakeResumed {
                    request_id: request_id("req-resume-1"),
                    pause_id: 12,
                    revision: 4,
                },
            },
            ResponseCase {
                id: "refused-while-paused",
                note: "the category both intake lanes answer with while an operator pause is live",
                response: AdminResponse::Refused {
                    request_id: request_id("req-submit-2"),
                    category: AdminRefusalCategory::new("intake_paused").expect("a valid category"),
                },
            },
            ResponseCase {
                id: "shutdown-accepted",
                note: "an empty body, which is not the same fact as an absent one",
                response: AdminResponse::ShutdownAccepted {
                    request_id: request_id("req-shutdown-1"),
                },
            },
        ]
    }

    /// How one decoded response is spelled in the corpus.
    ///
    /// Built from the value the *Rust decoder* recovered rather than from the
    /// value this file constructed, so an entry cannot record a field the
    /// decoder does not actually produce. Integers are decimal strings because
    /// the wire carries 64-bit values and a reader that used a double would
    /// round the largest of them without saying so.
    fn decoded_spelling(response: &AdminResponse) -> JsonValue {
        let number = |value: u64| JsonValue::String(value.to_string());
        let mut fields = vec![(
            "request_id".to_owned(),
            text(response.request_id().as_str()),
        )];
        match response {
            AdminResponse::RunAccepted {
                run_id,
                spec_digest,
                submission_id,
                replay,
                ..
            } => {
                fields.push(("replay".to_owned(), text(&replay.to_string())));
                fields.push(("run_id".to_owned(), text(run_id.as_str())));
                fields.push(("spec_digest".to_owned(), text(&spec_digest.to_string())));
                fields.push(("submission_id".to_owned(), number(*submission_id)));
            }
            AdminResponse::IntakePaused {
                pause_id, revision, ..
            }
            | AdminResponse::IntakeResumed {
                pause_id, revision, ..
            } => {
                fields.push(("pause_id".to_owned(), number(*pause_id)));
                fields.push(("revision".to_owned(), number(*revision)));
            }
            AdminResponse::Refused { category, .. } => {
                fields.push(("category".to_owned(), text(category.as_str())));
            }
            AdminResponse::ShutdownAccepted { .. } => {}
            other => panic!("the corpus has no spelling for {other:?}"),
        }
        JsonValue::Object(fields)
    }

    fn response_entry(case: &ResponseCase) -> JsonValue {
        let message = case.response.to_message().expect("the response encodes");
        let canonical = message.to_canonical_bytes();
        let decoded =
            AdminResponse::from_canonical_bytes(&canonical).expect("Rust admits its own encoding");
        assert_eq!(
            decoded, case.response,
            "{}: the Rust decoder does not recover what it encoded",
            case.id
        );
        JsonValue::Object(vec![
            ("canonical_hex".to_owned(), text(&hex(&canonical))),
            ("decoded".to_owned(), decoded_spelling(&decoded)),
            ("id".to_owned(), text(case.id)),
            ("kind".to_owned(), text(message.envelope().kind().as_str())),
            ("note".to_owned(), text(case.note)),
        ])
    }

    /// A response this protocol version defines and the generated surface does
    /// not decode.
    ///
    /// These are the evidence that the `undecoded` arm is reachable and honest:
    /// Rust admits every payload here, so a client told "undefined kind" about
    /// one of them would have been told something false.
    struct UndecodedCase {
        id: &'static str,
        note: &'static str,
        payload: Vec<u8>,
    }

    fn undecoded_cases() -> Vec<UndecodedCase> {
        vec![
            UndecodedCase {
                id: "status-result-undecoded",
                note: "the status snapshot: admin-status.ts carries its types, and no generated \
                       decoder builds them",
                payload: encoded_status().to_canonical_bytes(),
            },
            UndecodedCase {
                id: "synthetic-accepted-undecoded",
                note: "the synthetic intake receipt, whose command this surface does not build \
                       either",
                payload: AdminResponse::SyntheticAccepted {
                    request_id: request_id("req-synthetic-1"),
                    inbox_id: 9,
                    duplicate: true,
                }
                .to_message()
                .expect("the receipt encodes")
                .to_canonical_bytes(),
            },
        ]
    }

    fn undecoded_entry(case: &UndecodedCase) -> JsonValue {
        let message = Message::from_canonical_bytes(&case.payload).expect("a well-formed message");
        AdminResponse::from_canonical_bytes(&case.payload).unwrap_or_else(|error| {
            panic!(
                "{}: Rust does not define this kind, so it is unknown rather than undecoded: \
                 {error}",
                case.id
            )
        });
        JsonValue::Object(vec![
            ("id".to_owned(), text(case.id)),
            ("kind".to_owned(), text(message.envelope().kind().as_str())),
            ("note".to_owned(), text(case.note)),
            ("payload_hex".to_owned(), text(&hex(&case.payload))),
            (
                "request_id".to_owned(),
                text(message.envelope().request_id().as_str()),
            ),
        ])
    }

    // -----------------------------------------------------------------------
    // Refusals
    // -----------------------------------------------------------------------

    /// A payload both implementations must refuse.
    struct DecodeRefusal {
        id: &'static str,
        note: &'static str,
        payload: Vec<u8>,
    }

    /// Build one message with full control over the envelope, including the
    /// parts a valid request could not carry.
    pub(crate) fn raw_message(
        protocol: &str,
        version: u32,
        kind: &str,
        id: &str,
        body: JsonValue,
    ) -> Vec<u8> {
        Message::new(
            Envelope::new(
                ProtocolName::new(protocol).expect("a protocol name"),
                MajorVersion::new(version).expect("a major version"),
                request_id(id),
                MessageKind::new(kind).expect("a message kind"),
            ),
            body,
        )
        .to_canonical_bytes()
    }

    fn decode_refusals() -> Vec<DecodeRefusal> {
        let row = |name: &str, value: i64| (name.to_owned(), JsonValue::Integer(value));
        let paused_body = || JsonValue::Object(vec![row("pause_id", 12), row("revision", 3)]);
        vec![
            DecodeRefusal {
                id: "run-accepted-zero-submission",
                note: "a durable row identity starts at one; zero is an unwritten row reported \
                       as accepted",
                payload: raw_message(
                    ADMIN_PROTOCOL,
                    1,
                    "run_accepted",
                    "req-submit-1",
                    JsonValue::Object(vec![
                        ("replay".to_owned(), JsonValue::Bool(false)),
                        ("run_id".to_owned(), text("run-01J8Z9Q")),
                        (
                            "spec_digest".to_owned(),
                            text(&Sha256::digest(b"document").to_string()),
                        ),
                        row("submission_id", 0),
                    ]),
                ),
            },
            DecodeRefusal {
                id: "intake-paused-extra-field",
                note: "an unexpected key is refused rather than ignored",
                payload: raw_message(
                    ADMIN_PROTOCOL,
                    1,
                    "intake_paused",
                    "req-pause-1",
                    JsonValue::Object(vec![
                        row("pause_id", 12),
                        row("revision", 3),
                        ("surprise".to_owned(), JsonValue::Bool(true)),
                    ]),
                ),
            },
            DecodeRefusal {
                id: "intake-paused-missing-revision",
                note: "a missing key is refused rather than defaulted",
                payload: raw_message(
                    ADMIN_PROTOCOL,
                    1,
                    "intake_paused",
                    "req-pause-1",
                    JsonValue::Object(vec![row("pause_id", 12)]),
                ),
            },
            DecodeRefusal {
                id: "refused-uppercase-category",
                note: "a refusal category is lowercase; an uppercase spelling is not folded",
                payload: raw_message(
                    ADMIN_PROTOCOL,
                    1,
                    "refused",
                    "req-submit-2",
                    JsonValue::Object(vec![("category".to_owned(), text("Intake_Paused"))]),
                ),
            },
            DecodeRefusal {
                id: "unknown-kind",
                note: "a kind this protocol version does not define",
                payload: raw_message(
                    ADMIN_PROTOCOL,
                    1,
                    "intake_frozen",
                    "req-pause-1",
                    paused_body(),
                ),
            },
            DecodeRefusal {
                id: "unknown-protocol",
                note: "another protocol's message, refused on the name axis",
                payload: raw_message(
                    "automonique.runner",
                    1,
                    "intake_paused",
                    "req-pause-1",
                    paused_body(),
                ),
            },
            DecodeRefusal {
                id: "unsupported-version",
                note: "this protocol at a major version neither side implements",
                payload: raw_message(ADMIN_PROTOCOL, 2, "intake_paused", "req-pause-1", paused_body()),
            },
            DecodeRefusal {
                id: "non-canonical-key-order",
                note: "a payload that parses but is not canonical is refused, not normalized",
                payload: br#"{"kind":"intake_paused","body":{"pause_id":12,"revision":3},"protocol":"automonique.admin","request_id":"req-pause-1","version":1}"#.to_vec(),
            },
            DecodeRefusal {
                id: "duplicate-body-key",
                note: "one key, one value: a repeated key is refused rather than last-wins",
                payload: br#"{"body":{"pause_id":12,"pause_id":13,"revision":3},"kind":"intake_paused","protocol":"automonique.admin","request_id":"req-pause-1","version":1}"#.to_vec(),
            },
            DecodeRefusal {
                id: "empty-payload",
                note: "zero bytes is not an empty message",
                payload: Vec::new(),
            },
        ]
    }

    fn decode_refusal_entry(refusal: &DecodeRefusal) -> JsonValue {
        let category = AdminResponse::from_canonical_bytes(&refusal.payload)
            .err()
            .unwrap_or_else(|| panic!("{}: Rust accepted a payload it must refuse", refusal.id))
            .category()
            .to_owned();
        JsonValue::Object(vec![
            ("category".to_owned(), text(&category)),
            ("id".to_owned(), text(refusal.id)),
            ("note".to_owned(), text(refusal.note)),
            ("payload_hex".to_owned(), text(&hex(&refusal.payload))),
        ])
    }

    /// A request the other implementation must refuse while building it, under
    /// the category the Rust constructor answers for the same input.
    struct EncodeRefusal {
        id: &'static str,
        note: &'static str,
        kind: &'static str,
        request_id: String,
        params: JsonValue,
        category: String,
        /// The generated constructor that refuses the value, when one does, and
        /// the violation it names.
        constructor: Option<(&'static str, &'static str)>,
    }

    fn encode_refusals() -> Vec<EncodeRefusal> {
        let long_reason = "r".repeat(MAX_INTAKE_REASON_BYTES + 1);
        let long_key = "k".repeat(MAX_RUN_SUBMISSION_KEY_BYTES + 1);
        let long_request_id = "r".repeat(MAX_REQUEST_ID_BYTES + 1);
        let digest = Sha256::digest(b"document").to_string();
        let document = br#"{"schema":"automonique.run-spec/v1"}"#.to_vec();

        let reason_category = IntakePause::new("ops", &long_reason)
            .expect_err("an overlong reason is refused")
            .category()
            .to_owned();
        let actor_category = IntakePause::new("ops\u{7}", "why")
            .expect_err("a control character in an actor is refused")
            .category()
            .to_owned();
        let key_category = SubmittedRunSpec::sealed(document.clone(), &long_key)
            .expect_err("an overlong idempotency key is refused")
            .category()
            .to_owned();
        let oversize_category = SubmittedRunSpec::sealed(
            ruled_document(MAX_SUBMITTED_RUN_SPEC_BYTES + 1),
            "submit-run-key-1",
        )
        .expect_err("a document over the bound is refused")
        .category()
        .to_owned();
        let empty_category = SubmittedRunSpec::sealed(Vec::new(), "submit-run-key-1")
            .expect_err("an empty document is refused")
            .category()
            .to_owned();
        let long_id_category = AdminError::from(
            RequestId::new(&long_request_id).expect_err("an overlong request id is refused"),
        )
        .category()
        .to_owned();
        let bad_id_category = AdminError::from(
            RequestId::new("req 1").expect_err("a space is outside the request id grammar"),
        )
        .category()
        .to_owned();

        vec![
            EncodeRefusal {
                id: "pause-intake-reason-too-long",
                note: "one byte over the reason bound, measured in UTF-8 bytes",
                kind: "pause_intake",
                request_id: "req-pause-1".to_owned(),
                params: JsonValue::Object(vec![
                    ("actor".to_owned(), text("ops")),
                    ("reason".to_owned(), text(&long_reason)),
                ]),
                category: reason_category,
                constructor: Some(("IntakeReason", "too_long")),
            },
            EncodeRefusal {
                id: "pause-intake-actor-control-character",
                note: "a control character in an actor, which the wire never carries raw",
                kind: "pause_intake",
                request_id: "req-pause-1".to_owned(),
                params: JsonValue::Object(vec![
                    ("actor".to_owned(), text("ops\u{7}")),
                    ("reason".to_owned(), text("why")),
                ]),
                category: actor_category,
                constructor: Some(("IntakeActor", "invalid_character")),
            },
            EncodeRefusal {
                id: "submit-run-key-too-long",
                note: "one byte over the idempotency key bound",
                kind: "submit_run",
                request_id: "req-submit-1".to_owned(),
                params: JsonValue::Object(vec![
                    ("document_hex".to_owned(), text(&hex(&document))),
                    ("idempotency_key".to_owned(), text(&long_key)),
                    ("spec_digest".to_owned(), text(&digest)),
                ]),
                category: key_category,
                constructor: Some(("RunSubmissionKey", "too_long")),
            },
            EncodeRefusal {
                id: "submit-run-document-too-large",
                note: "one byte over the document bound, which is its own refusal rather than \
                       a generic invalid body",
                kind: "submit_run",
                request_id: "req-submit-1".to_owned(),
                params: JsonValue::Object(vec![
                    (
                        "document_length".to_owned(),
                        count(MAX_SUBMITTED_RUN_SPEC_BYTES + 1),
                    ),
                    ("idempotency_key".to_owned(), text("submit-run-key-1")),
                    ("spec_digest".to_owned(), text(&digest)),
                ]),
                category: oversize_category,
                constructor: None,
            },
            EncodeRefusal {
                id: "submit-run-empty-document",
                note: "an empty document is a different fault from an oversized one",
                kind: "submit_run",
                request_id: "req-submit-1".to_owned(),
                params: JsonValue::Object(vec![
                    ("document_hex".to_owned(), text("")),
                    ("idempotency_key".to_owned(), text("submit-run-key-1")),
                    ("spec_digest".to_owned(), text(&digest)),
                ]),
                category: empty_category,
                constructor: None,
            },
            EncodeRefusal {
                id: "request-id-too-long",
                note: "the envelope's fields are judged by the shared codec, whose refusal for \
                       a bound is not the one this protocol uses for a body",
                kind: "status",
                request_id: long_request_id,
                params: JsonValue::Object(Vec::new()),
                category: long_id_category,
                constructor: Some(("RequestId", "too_long")),
            },
            EncodeRefusal {
                id: "request-id-outside-grammar",
                note: "a grammar refusal is not a bounds refusal, and the categories differ",
                kind: "status",
                request_id: "req 1".to_owned(),
                params: JsonValue::Object(Vec::new()),
                category: bad_id_category,
                constructor: Some(("RequestId", "invalid_character")),
            },
        ]
    }

    fn encode_refusal_entry(refusal: &EncodeRefusal) -> JsonValue {
        let mut entry = vec![
            ("category".to_owned(), text(&refusal.category)),
            ("id".to_owned(), text(refusal.id)),
            ("kind".to_owned(), text(refusal.kind)),
            ("note".to_owned(), text(refusal.note)),
            ("params".to_owned(), refusal.params.clone()),
            ("request_id".to_owned(), text(&refusal.request_id)),
        ];
        if let Some((constructor, violation)) = refusal.constructor {
            // Named `refused_by` rather than `constructor`: a JSON object
            // parsed by a JavaScript reader inherits `constructor` from its
            // prototype, so a runner asking whether the key is present would be
            // told yes for every entry that omits it.
            entry.push(("refused_by".to_owned(), text(constructor)));
            entry.push(("violation".to_owned(), text(violation)));
        }
        JsonValue::Object(entry)
    }

    // -----------------------------------------------------------------------
    // The corpus file
    // -----------------------------------------------------------------------

    /// Write one JSON value as reviewable text: two-space indentation, keys in
    /// the wire's own order, scalars in the wire's own escaping.
    pub(crate) fn write_pretty(value: &JsonValue, indent: usize, out: &mut String) {
        let pad = |depth: usize| "  ".repeat(depth);
        match value {
            JsonValue::Object(entries) if !entries.is_empty() => {
                let mut ordered: Vec<&(String, JsonValue)> = entries.iter().collect();
                ordered.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
                out.push_str("{\n");
                for (index, (key, item)) in ordered.iter().enumerate() {
                    if index > 0 {
                        out.push_str(",\n");
                    }
                    out.push_str(&pad(indent + 1));
                    write_pretty(&JsonValue::String(key.clone()), indent + 1, out);
                    out.push_str(": ");
                    write_pretty(item, indent + 1, out);
                }
                out.push('\n');
                out.push_str(&pad(indent));
                out.push('}');
            }
            JsonValue::Array(items) if !items.is_empty() => {
                out.push_str("[\n");
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push_str(",\n");
                    }
                    out.push_str(&pad(indent + 1));
                    write_pretty(item, indent + 1, out);
                }
                out.push('\n');
                out.push_str(&pad(indent));
                out.push(']');
            }
            scalar => out.push_str(
                &String::from_utf8(scalar.to_canonical_bytes())
                    .expect("canonical JSON is UTF-8 text"),
            ),
        }
    }

    fn corpus() -> String {
        let document = JsonValue::Object(vec![
            (
                "document_rule".to_owned(),
                JsonValue::Object(vec![
                    (
                        "note".to_owned(),
                        text(
                            "byte i = (seed + (i mod 256) * step) mod 256; a document too large \
                             to review as a literal is built from this rule on both sides",
                        ),
                    ),
                    ("seed".to_owned(), count(usize::from(DOCUMENT_SEED))),
                    ("step".to_owned(), count(usize::from(DOCUMENT_STEP))),
                ]),
            ),
            (
                "decode_refusals".to_owned(),
                JsonValue::Array(decode_refusals().iter().map(decode_refusal_entry).collect()),
            ),
            (
                "encode_refusals".to_owned(),
                JsonValue::Array(encode_refusals().iter().map(encode_refusal_entry).collect()),
            ),
            (
                "generator".to_owned(),
                text("automonique-protocol tests/codegen.rs, module command_surface"),
            ),
            (
                "note".to_owned(),
                text(
                    "Generated from the shipped Rust constructors: every canonical byte string \
                     here was produced by encoding a real message, and every refusal category \
                     was read back from the error Rust returned for that exact input. Rust is \
                     the wire source of truth, so a disagreement is fixed in whichever \
                     implementation is wrong — never in this file.",
                ),
            ),
            ("protocol".to_owned(), text(ADMIN_PROTOCOL)),
            (
                "requests".to_owned(),
                JsonValue::Array(request_cases().iter().map(request_entry).collect()),
            ),
            (
                "responses".to_owned(),
                JsonValue::Array(response_cases().iter().map(response_entry).collect()),
            ),
            (
                "undecoded_responses".to_owned(),
                JsonValue::Array(undecoded_cases().iter().map(undecoded_entry).collect()),
            ),
            (
                "version".to_owned(),
                JsonValue::Integer(i64::from(MajorVersion::FIRST.get())),
            ),
        ]);
        let mut out = String::new();
        write_pretty(&document, 0, &mut out);
        out.push('\n');
        out
    }

    /// The drift gate over the corpus, and the regeneration that closes it.
    ///
    /// The corpus is generated, so it is held to the same rule as the generated
    /// TypeScript: an ordinary run compares, and only a run that asks for it
    /// rewrites. A constructor whose refusal category changed, a bound that
    /// moved, or an encoder that started spelling a body differently all turn
    /// this red rather than silently rewriting the evidence they are measured
    /// against.
    #[test]
    fn the_checked_in_corpus_matches_regeneration() {
        let expected = corpus();
        let path = corpus_path();
        if regenerating() {
            let staging = path.with_extension("json.staging");
            std::fs::write(&staging, &expected).expect("stage the corpus");
            std::fs::rename(&staging, &path).expect("publish the corpus");
            return;
        }
        let actual = std::fs::read_to_string(&path)
            .expect("the corpus is checked in — regenerate it to create it");
        if actual != expected {
            let difference = actual
                .lines()
                .zip(expected.lines())
                .enumerate()
                .find(|(_, (left, right))| left != right)
                .map_or_else(
                    || {
                        format!(
                            "{} lines on disk, {} lines generated",
                            actual.lines().count(),
                            expected.lines().count()
                        )
                    },
                    |(index, (left, right))| {
                        let shorten = |line: &str| line.chars().take(120).collect::<String>();
                        format!(
                            "line {}: on disk {:?}, generated {:?}",
                            index + 1,
                            shorten(left),
                            shorten(right)
                        )
                    },
                );
            panic!(
                "the checked-in command corpus no longer matches the Rust encoders: \
                 {difference}\n\nRegenerate with: {REGENERATE_COMMAND}"
            );
        }
    }

    /// Every command this protocol version defines is either built by the
    /// generated surface or named as one it does not build.
    ///
    /// The kinds come from encoding one request per [`AdminCommand`] variant,
    /// so a command added to the protocol appears here without anyone
    /// remembering to add it, and a generated surface that quietly did not
    /// cover it fails.
    #[test]
    fn every_command_kind_is_generated_or_named_as_absent() {
        let id = request_id("req-coverage-1");
        let requests = vec![
            AdminRequest::new(id.clone(), AdminCommand::Status),
            AdminRequest::new(id.clone(), AdminCommand::Metrics),
            AdminRequest::new(id.clone(), AdminCommand::Generations),
            AdminRequest::reload(
                id.clone(),
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .expect("a reload request"),
            AdminRequest::new(id.clone(), AdminCommand::Rollback),
            AdminRequest::reload_status(id.clone(), "reload-1").expect("a reload lookup"),
            AdminRequest::new(id.clone(), AdminCommand::Shutdown),
            AdminRequest::submit(
                id.clone(),
                SyntheticSubmission::new("scope", "key", "task").expect("a synthetic submission"),
            ),
            AdminRequest::submit_run(
                id.clone(),
                SubmittedRunSpec::sealed(b"document".to_vec(), "key").expect("a carried document"),
            ),
            AdminRequest::inspect_reconciliation(id.clone(), 1).expect("an inspection"),
            AdminRequest::fail_reconciliation(
                id.clone(),
                ReconciliationFailure::new(1, "generation", 1, 1, "decision", "reason")
                    .expect("a fail decision"),
            ),
            AdminRequest::inspect_outbox(id.clone(), 1).expect("an outbox inspection"),
            AdminRequest::reconcile_outbox(
                id.clone(),
                OutboxReconciliation::new(OutboxReconciliationParts {
                    outbox_id: 1,
                    expected_generation_id: "generation".to_owned(),
                    expected_lease_epoch: 1,
                    expected_lease_token: "token".to_owned(),
                    expected_attempt: 1,
                    expected_revision: 1,
                    decision: OutboxReconciliationDecision::Delivered {
                        receipt_key: "receipt".to_owned(),
                    },
                })
                .expect("an outbox decision"),
            ),
            AdminRequest::pause_intake(
                id.clone(),
                IntakePause::new("ops", "why").expect("a pause"),
            ),
            AdminRequest::resume_intake(id, IntakeResume::new("ops").expect("a resume")),
        ];
        // Every variant of the command enum is represented above. The match is
        // the point: a command added to `AdminCommand` fails to compile here.
        let mut declared: BTreeSet<String> = BTreeSet::new();
        for command in [
            AdminCommand::Status,
            AdminCommand::Metrics,
            AdminCommand::Generations,
            AdminCommand::Reload,
            AdminCommand::Rollback,
            AdminCommand::ReloadStatus,
            AdminCommand::SubmitSynthetic,
            AdminCommand::SubmitRun,
            AdminCommand::InspectReconciliation,
            AdminCommand::FailReconciliation,
            AdminCommand::InspectOutbox,
            AdminCommand::ReconcileOutbox,
            AdminCommand::PauseIntake,
            AdminCommand::ResumeIntake,
            AdminCommand::Shutdown,
        ] {
            match command {
                AdminCommand::Status
                | AdminCommand::Metrics
                | AdminCommand::Generations
                | AdminCommand::Reload
                | AdminCommand::Rollback
                | AdminCommand::ReloadStatus
                | AdminCommand::SubmitSynthetic
                | AdminCommand::SubmitRun
                | AdminCommand::InspectReconciliation
                | AdminCommand::FailReconciliation
                | AdminCommand::InspectOutbox
                | AdminCommand::ReconcileOutbox
                | AdminCommand::PauseIntake
                | AdminCommand::ResumeIntake
                | AdminCommand::Shutdown => {}
            }
            declared.insert(format!("{command:?}"));
        }
        let encoded: BTreeSet<String> = requests
            .iter()
            .map(|request| {
                request
                    .to_message()
                    .expect("each command encodes")
                    .envelope()
                    .kind()
                    .as_str()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            encoded.len(),
            declared.len(),
            "one request per command variant is required; {} were built for {} variants",
            encoded.len(),
            declared.len()
        );

        let surface = surface();
        let mut covered: BTreeSet<String> = surface
            .requests
            .iter()
            .map(|request| request.kind.clone())
            .collect();
        for kind in &surface.request_kinds_not_generated {
            assert!(
                covered.insert(kind.clone()),
                "{kind} is both generated and named as absent"
            );
        }
        assert_eq!(
            covered, encoded,
            "the generated command surface does not account for every kind the Rust encoders \
             produce; regenerate with: {REGENERATE_COMMAND}"
        );
    }

    /// Every response this protocol version defines is either decoded by the
    /// generated surface or named as one it does not decode.
    #[test]
    fn every_response_kind_is_decoded_or_named_as_undecoded() {
        let id = request_id("req-coverage-1");
        let digest = Sha256::digest(b"document");
        let responses = vec![
            AdminResponse::from_canonical_bytes(&encoded_status().to_canonical_bytes())
                .expect("a status response"),
            AdminResponse::Metrics {
                request_id: id.clone(),
                exposition: "automonique_ready 1\n".to_owned(),
            },
            AdminResponse::Generations {
                request_id: id.clone(),
                generations: GenerationsView {
                    generation_id: "foreground".to_owned(),
                    tenures: vec![GenerationTenureView {
                        holder_id: "holder-1".to_owned(),
                        lease_epoch: 1,
                        started_at_ms: 1,
                        ended_at_ms: None,
                        end_kind: None,
                    }],
                    handoffs: Vec::<GenerationHandoffView>::new(),
                },
            },
            AdminResponse::ReloadStatus {
                request_id: id.clone(),
                reload: ReloadStatusView {
                    reload_id: "reload-1".to_owned(),
                    source_generation_id: "foreground".to_owned(),
                    source_lease_epoch: 1,
                    target_generation_id: "foreground-next".to_owned(),
                    target_release_digest: format!("sha256:{}", "a".repeat(64)),
                    phase: "created".to_owned(),
                    failure_category: None,
                    created_at_ms: 1,
                    updated_at_ms: 1,
                    terminal_at_ms: None,
                    revision: 1,
                    transitions: vec![ReloadTransitionView {
                        revision: 1,
                        phase: "created".to_owned(),
                        observed_at_ms: 1,
                        failure_category: None,
                    }],
                },
            },
            AdminResponse::SyntheticAccepted {
                request_id: id.clone(),
                inbox_id: 1,
                duplicate: false,
            },
            AdminResponse::RunAccepted {
                request_id: id.clone(),
                run_id: RunId::new("run-1").expect("a run identity"),
                spec_digest: digest,
                submission_id: 1,
                replay: false,
            },
            AdminResponse::ReconciliationInspected {
                request_id: id.clone(),
                evidence: AdminReconciliationEvidence::new(
                    1,
                    "scope",
                    "generation",
                    1,
                    1,
                    false,
                    0,
                )
                .expect("reconciliation evidence"),
            },
            AdminResponse::ReconciliationFailed {
                request_id: id.clone(),
                run_event_id: 1,
                inbox_event_id: 2,
                outbox_id: 3,
                duplicate: false,
            },
            AdminResponse::OutboxInspected {
                request_id: id.clone(),
                evidence: AdminOutboxEvidence::new(AdminOutboxEvidenceParts {
                    outbox_id: 1,
                    intent_key: "intent".to_owned(),
                    transport: "telegram".to_owned(),
                    kind: "message".to_owned(),
                    state: "pending".to_owned(),
                    revision: 1,
                    attempt: 0,
                    lease_token: None,
                    lease_generation_id: None,
                    lease_holder: None,
                    lease_epoch: None,
                    lease_expires_ms: None,
                    delivery_receipt_key: None,
                    trace_id: None,
                    correlation_id: None,
                    causation_id: None,
                })
                .expect("outbox evidence"),
            },
            AdminResponse::OutboxReconciled {
                request_id: id.clone(),
                outbox_id: 1,
                state: "delivered".to_owned(),
                revision: 1,
                duplicate: false,
            },
            AdminResponse::IntakePaused {
                request_id: id.clone(),
                pause_id: 1,
                revision: 1,
            },
            AdminResponse::IntakeResumed {
                request_id: id.clone(),
                pause_id: 1,
                revision: 2,
            },
            AdminResponse::ReloadSucceeded {
                request_id: id.clone(),
                reload_id: "reload-1".to_owned(),
            },
            AdminResponse::ReloadAccepted {
                request_id: id.clone(),
                reload_id: "reload-accepted-1".to_owned(),
            },
            AdminResponse::RollbackSucceeded {
                request_id: id.clone(),
                reload_id: "reload-2".to_owned(),
            },
            AdminResponse::RollbackAccepted {
                request_id: id.clone(),
                reload_id: "rollback-accepted-1".to_owned(),
            },
            AdminResponse::Refused {
                request_id: id.clone(),
                category: AdminRefusalCategory::new("intake_paused").expect("a category"),
            },
            AdminResponse::ShutdownAccepted { request_id: id },
        ];
        // The match is the point: a variant added to `AdminResponse` fails to
        // compile here rather than slipping past a surface that ignores it.
        for response in &responses {
            match response {
                AdminResponse::Status { .. }
                | AdminResponse::Metrics { .. }
                | AdminResponse::Generations { .. }
                | AdminResponse::ReloadStatus { .. }
                | AdminResponse::ReloadSucceeded { .. }
                | AdminResponse::ReloadAccepted { .. }
                | AdminResponse::RollbackSucceeded { .. }
                | AdminResponse::RollbackAccepted { .. }
                | AdminResponse::SyntheticAccepted { .. }
                | AdminResponse::RunAccepted { .. }
                | AdminResponse::ReconciliationInspected { .. }
                | AdminResponse::ReconciliationFailed { .. }
                | AdminResponse::OutboxInspected { .. }
                | AdminResponse::OutboxReconciled { .. }
                | AdminResponse::IntakePaused { .. }
                | AdminResponse::IntakeResumed { .. }
                | AdminResponse::Refused { .. }
                | AdminResponse::ShutdownAccepted { .. } => {}
            }
        }
        let encoded: BTreeSet<String> = responses
            .iter()
            .map(|response| {
                response
                    .to_message()
                    .expect("each response encodes")
                    .envelope()
                    .kind()
                    .as_str()
                    .to_owned()
            })
            .collect();

        let surface = surface();
        let mut covered: BTreeSet<String> = surface
            .responses
            .iter()
            .map(|response| response.kind.clone())
            .collect();
        for kind in &surface.response_kinds_not_decoded {
            assert!(
                covered.insert(kind.clone()),
                "{kind} is both decoded and named as undecoded"
            );
        }
        assert_eq!(
            covered, encoded,
            "the generated response surface does not account for every kind the daemon can \
             answer with; regenerate with: {REGENERATE_COMMAND}"
        );
    }

    /// Every category the generated code refuses with is declared, and every
    /// declared category is a spelling Rust actually produces.
    #[test]
    fn every_refusal_category_is_declared_and_is_the_rust_spelling() {
        let surface = surface();
        let declared: BTreeMap<String, String> = surface
            .categories
            .iter()
            .map(|constant| {
                let ConstantValue::Text(value) = &constant.value else {
                    panic!("{} is a refusal category, which is text", constant.name)
                };
                (constant.name.clone(), value.clone())
            })
            .collect();

        let mut referenced = vec![
            surface.invalid_body_category.clone(),
            surface.unknown_kind_category.clone(),
            surface.oversize_category.clone(),
            surface.field_invalid_category.clone(),
            surface.field_grammar_category.clone(),
        ];
        for field in surface.requests.iter().flat_map(|request| &request.fields) {
            if let RequestValue::HexBytes {
                oversize_category, ..
            } = &field.value
            {
                referenced.push(oversize_category.clone());
            }
        }
        for name in &referenced {
            assert!(
                declared.contains_key(name),
                "the surface refuses with {name}, which it does not declare"
            );
        }

        // The spellings, against the errors themselves rather than against a
        // list retyped here. `frame_size` is the exception and says so: the
        // protocol crate has no constant for it, and the test names where it
        // does live.
        let generated = generated_admin_command();
        for (name, expected) in [
            (
                surface.invalid_body_category.as_str(),
                AdminError::InvalidBody.category(),
            ),
            (
                surface.unknown_kind_category.as_str(),
                AdminError::UnknownKind.category(),
            ),
            (
                surface.field_invalid_category.as_str(),
                AdminError::from(automonique_protocol::codec::CodecError::Field {
                    field: "request_id",
                    error: automonique_protocol::primitives::ValueError::Empty,
                })
                .category(),
            ),
            (
                surface.field_grammar_category.as_str(),
                AdminError::from(automonique_protocol::codec::CodecError::Grammar {
                    field: "request_id",
                })
                .category(),
            ),
        ] {
            assert_eq!(
                declared.get(name).map(String::as_str),
                Some(expected),
                "{name} is not the category Rust reports"
            );
            assert!(
                generated.contains(&format!("export const {name} = \"{expected}\";")),
                "the generated file does not carry {name} as {expected}"
            );
        }
        assert_eq!(
            declared.get(&surface.oversize_category).map(String::as_str),
            Some("frame_size"),
            "the oversize category is the spelling automonique-daemon and automonique-cli \
             report for a payload above MAX_ADMIN_PAYLOAD_BYTES"
        );
    }

    /// One name, one declaring module.
    ///
    /// The barrel re-exports every module with `export *`, so a name declared
    /// twice is ambiguous for every consumer — and the second declaration is
    /// exactly what a new module copying an existing constant would produce.
    #[test]
    fn no_two_generated_modules_export_the_same_name() {
        let mut owner: BTreeMap<String, String> = BTreeMap::new();
        for (file_name, contents) in generated_files() {
            for line in contents.lines() {
                let Some(rest) = line
                    .strip_prefix("export const ")
                    .or_else(|| line.strip_prefix("export function "))
                    .or_else(|| line.strip_prefix("export interface "))
                    .or_else(|| line.strip_prefix("export type "))
                else {
                    continue;
                };
                let name: String = rest
                    .chars()
                    .take_while(|character| character.is_alphanumeric() || *character == '_')
                    .collect();
                if name.is_empty() {
                    continue;
                }
                if let Some(first) = owner.get(&name) {
                    assert_eq!(
                        first, &file_name,
                        "{name} is declared in both {first} and {file_name}, which makes it \
                         ambiguous through the barrel"
                    );
                } else {
                    owner.insert(name, file_name.clone());
                }
            }
        }
        assert!(
            owner.contains_key("decodeAdminResponse"),
            "the command surface is not in the generated tree at all"
        );
    }

    /// The command module's bounds are the Rust constants, and its grammars are
    /// the Rust grammars.
    #[test]
    fn the_generated_command_bounds_are_the_rust_constants() {
        let generated = generated_admin_command();
        for declaration in [
            format!("export const MAX_SUBMITTED_RUN_SPEC_BYTES = {MAX_SUBMITTED_RUN_SPEC_BYTES};"),
            format!("export const IntakeReason_MAX_BYTES = {MAX_INTAKE_REASON_BYTES};"),
            format!("export const RunSubmissionKey_MAX_BYTES = {MAX_RUN_SUBMISSION_KEY_BYTES};"),
            format!("export const RequestId_MAX_BYTES = {MAX_REQUEST_ID_BYTES};"),
            format!("export const DurableRowId_MAX = {}n;", i64::MAX),
            "export const DurableRowId_MIN = 1n;".to_owned(),
            format!(
                "export const SpecDigest_PATTERN = /^{}:[0-9a-f]{{{}}}$/u;",
                automonique_protocol::digest::ALGORITHM,
                automonique_protocol::digest::DIGEST_BYTES * 2
            ),
        ] {
            assert!(
                generated.contains(&declaration),
                "the command surface does not carry the Rust bound: {declaration}"
            );
        }
        // Declaring a bound is not checking it.
        assert!(
            generated.contains(&format!(
                "  if (byteLength(value) > {MAX_INTAKE_REASON_BYTES}) throw new \
                 ValidationError(\"IntakeReason\", \"too_long\");"
            )),
            "IntakeReason declares its bound but does not check it"
        );
        assert!(
            generated.contains(
                "boundedBytes(body.document, MAX_SUBMITTED_RUN_SPEC_BYTES, \
                 ADMIN_DOCUMENT_TOO_LARGE, ADMIN_INVALID_BODY)"
            ),
            "the document bound is declared but not applied where the document is encoded"
        );
    }

    /// The SDK has no transport, and the generated file says so where a reader
    /// would otherwise have to guess whether these bytes are framed.
    #[test]
    fn the_generated_surface_says_the_framing_is_excluded() {
        let generated = generated_admin_command();
        for statement in [
            "The length-delimited framing this protocol travels under is not applied",
            "This package has no transport.",
            "The payload is the framed transport's payload, without its length prefix.",
        ] {
            assert!(
                generated.contains(statement),
                "the generated command surface does not state where framing lives: {statement}"
            );
        }
    }

    /// The heart of the wave: the generated TypeScript encodes the same bytes
    /// Rust does, decodes what Rust answers, and refuses what Rust refuses.
    #[test]
    fn the_generated_typescript_agrees_with_rust_byte_for_byte() {
        let Some(runtime) = javascript_runtime() else {
            record_js_gap(
                "no JavaScript runtime; the command surface is unmeasured across languages",
            );
            return;
        };
        let directory =
            std::env::temp_dir().join(format!("automonique-admin-command-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("scratch directory");
        let produced_path = directory.join("typescript-encodings.txt");

        let output = Command::new(runtime)
            .arg(runner_path())
            .arg(corpus_path())
            .arg(&produced_path)
            .current_dir(package_root())
            .output()
            .expect("the conformance runner starts");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success(),
            "the generated command surface disagrees with the Rust corpus under {runtime}:\n\
             {combined}"
        );

        // The second direction. The runner reports the bytes it produced, and
        // they are compared here against what Rust encodes — which is the only
        // comparison the maximal submit_run gets, because its 49 KiB of hex is
        // not a reviewable literal — and then fed to the shipped decoder.
        let reported = std::fs::read_to_string(&produced_path)
            .expect("the runner reports the payloads it produced");
        let mut produced: BTreeMap<String, Vec<u8>> = reported
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| {
                let (id, payload) = line
                    .split_once(' ')
                    .unwrap_or_else(|| panic!("a reported line is `<id> <hex>`: {line:?}"));
                (id.to_owned(), unhex(payload))
            })
            .collect();

        for case in request_cases() {
            let expected = case
                .request
                .to_message()
                .expect("the request encodes")
                .to_canonical_bytes();
            let actual = produced
                .remove(case.id)
                .unwrap_or_else(|| panic!("the runner did not report {}", case.id));
            assert_eq!(
                actual.len(),
                expected.len(),
                "{}: {runtime} produced {} canonical bytes, Rust produced {}",
                case.id,
                actual.len(),
                expected.len()
            );
            if let Some(index) = actual
                .iter()
                .zip(expected.iter())
                .position(|(left, right)| left != right)
            {
                let window = |bytes: &[u8]| {
                    String::from_utf8_lossy(
                        &bytes[index.saturating_sub(24)..(index + 24).min(bytes.len())],
                    )
                    .into_owned()
                };
                panic!(
                    "{}: the two encodings first differ at byte {index}\n  {runtime}: {}\n  \
                     rust: {}",
                    case.id,
                    window(&actual),
                    window(&expected)
                );
            }
            assert_eq!(
                AdminRequest::from_canonical_bytes(&actual).unwrap_or_else(|error| panic!(
                    "{}: Rust refuses what {runtime} produced: {error}",
                    case.id
                )),
                case.request,
                "{}: Rust decodes what {runtime} produced as a different request",
                case.id
            );
        }
        assert!(
            produced.is_empty(),
            "the runner reported payloads the corpus has no cases for: {:?}",
            produced.keys().collect::<Vec<_>>()
        );
        println!(
            "admin command surface under {runtime}: {}",
            String::from_utf8_lossy(&output.stdout).trim()
        );
    }
}

/// The `automonique.runs` read surface, measured across two languages.
///
/// The mechanism is the one [`command_surface`] established, applied to a
/// protocol with a richer shape: nested bodies, bounded arrays, a nullable
/// cursor, and a state filter whose canonical order is the Rust enum's
/// declaration order rather than anything a sort would produce.
///
/// `fixtures/runs-api-v1.json` is generated from the shipped Rust constructors.
/// Every canonical byte string in it was produced by encoding a real message and
/// re-read through `from_canonical_bytes` before it was written, every refusal
/// category was read back from the error Rust returned for that exact input, and
/// every decoded spelling came out of the Rust decoder rather than out of the
/// value this file constructed.
///
/// One section is unlike the others. `rust_only_refusals` records payloads the
/// Rust constructors refuse and the generated TypeScript *accepts*, because they
/// break rules that relate two fields — a continuation that rewinds, a coverage
/// that contradicts what it carries — and the generated surface holds each
/// field's own shape rather than the relations between them. The runner asserts
/// those payloads decode, so the gap is measured rather than described: teaching
/// the generator one of these rules turns this suite red until the entry moves
/// to `decode_refusals`, and losing one from the Rust side turns it red here.
mod runs_surface {
    use std::collections::{BTreeMap, BTreeSet};

    use automonique_protocol::codec::{MAX_REQUEST_ID_BYTES, MajorVersion};
    use automonique_protocol::codegen::{
        CommandSurface, ConstantValue, REGENERATE_COMMAND, RUNS_MODULE, generated_files,
        maintained_modules, module_file_name,
    };
    use automonique_protocol::digest::Sha256;
    use automonique_protocol::event::Authority;
    use automonique_protocol::journal::{CursorResume, RetainedRange};
    use automonique_protocol::primitives::{EpochMillis, ValueError};
    use automonique_protocol::runs_api::{
        Continuation, LifecycleCoverage, ListRuns, MAX_LIFECYCLE_EVENTS, MAX_RUN_PAGE_ITEMS,
        PageSize, RUNS_PROTOCOL, RunCursor, RunDetailView, RunLifecycleEvent, RunListPage,
        RunState, RunStateFilter, RunSummary, RunsApiError, RunsRefusal, RunsRequest, RunsResponse,
        SpoolEventKind, SubmissionState,
    };
    use automonique_protocol::tools::{MAX_TOOL_FIELD_BYTES, RunId};

    use super::command_surface::{count, hex, raw_message, request_id, text, unhex, write_pretty};
    use super::*;

    fn corpus_path() -> PathBuf {
        crate_root().join("fixtures/runs-api-v1.json")
    }

    fn runner_path() -> PathBuf {
        package_root().join("conformance/runs-api.ts")
    }

    fn regenerating() -> bool {
        std::env::var(automonique_protocol::codegen::REGENERATE_ENV)
            .is_ok_and(|value| !value.is_empty() && value != "0")
    }

    /// The command surface the generator describes for this protocol.
    fn surface() -> CommandSurface {
        maintained_modules()
            .into_iter()
            .find(|module| module.file_name == module_file_name(RUNS_MODULE))
            .and_then(|module| module.command_surface)
            .expect("the runs module describes a command surface")
    }

    /// The generated TypeScript of the runs module.
    fn generated_runs() -> String {
        generated_files()
            .into_iter()
            .find(|(name, _)| *name == module_file_name(RUNS_MODULE))
            .map(|(_, contents)| contents)
            .expect("the runs module is generated")
    }

    fn run_id(value: &str) -> RunId {
        RunId::new(value).expect("a valid run identity")
    }

    /// A decimal string, because the wire carries 64-bit values and a JSON
    /// reader that used a double would round the largest of them without saying
    /// so. Every counter in this corpus travels as text for that reason.
    fn number(value: u64) -> JsonValue {
        JsonValue::String(value.to_string())
    }

    fn page_size(items: usize) -> PageSize {
        PageSize::new(items).expect("a page size within the bound")
    }

    fn summary(id: &str, submission_id: u64, state: RunState, accepted_at_ms: i64) -> RunSummary {
        RunSummary::new(
            run_id(id),
            submission_id,
            Sha256::digest(id.as_bytes()),
            state,
            SubmissionState::Accepted,
            EpochMillis::from_millis(accepted_at_ms),
        )
        .expect("a well-formed summary")
    }

    fn event(
        sequence: u64,
        at_ms: i64,
        kind: SpoolEventKind,
        authority: Authority,
    ) -> RunLifecycleEvent {
        RunLifecycleEvent::new(sequence, EpochMillis::from_millis(at_ms), kind, authority)
            .expect("a well-formed lifecycle event")
    }

    /// The wire ceiling, which a decoder carrying counters in a double rounds.
    fn wire_ceiling() -> u64 {
        u64::try_from(i64::MAX).expect("the wire ceiling is positive")
    }

    /// A run identity carrying every escape a bounded identifier can reach, a
    /// three-byte character and a surrogate pair.
    ///
    /// Control characters are absent because `RunId::new` refuses them; what
    /// remains reachable is the quote, the backslash, and the solidus that
    /// canonical JSON pointedly does *not* escape.
    fn escaping_run_id() -> String {
        "run/\"01J8\" \\ naïve 日本語 🚀".to_owned()
    }

    // -----------------------------------------------------------------------
    // Requests
    // -----------------------------------------------------------------------

    struct RequestCase {
        id: &'static str,
        note: &'static str,
        request: RunsRequest,
        /// Builder parameters, in the shape the runner reads for this kind.
        ///
        /// `states` is recorded in an order that is *not* the wire's, so a
        /// TypeScript builder that forwarded the caller's order instead of
        /// canonicalizing it would produce different bytes and be caught.
        params: JsonValue,
    }

    fn request_cases() -> Vec<RequestCase> {
        let maximal_request_id = format!("req-{}", "a".repeat(MAX_REQUEST_ID_BYTES - 4));
        // Every character escapes to two bytes, which is the worst case the
        // protocol's own frame arithmetic budgets for.
        let maximal_run_id = "\"".repeat(MAX_TOOL_FIELD_BYTES);

        vec![
            RequestCase {
                id: "list-runs-maximal",
                note: "every bound at once: all six states, a cursor at the wire's integer \
                       ceiling, the largest page this protocol serves, and a correlation \
                       identifier at MAX_REQUEST_ID_BYTES. The states are recorded shuffled: \
                       the wire order is the enum's declaration order, not the caller's and not \
                       alphabetical",
                request: RunsRequest::ListRuns {
                    request_id: request_id(&maximal_request_id),
                    query: ListRuns::new(
                        RunStateFilter::only(RunState::ALL).expect("every state is a valid set"),
                        Some(RunCursor::new(wire_ceiling())),
                        page_size(MAX_RUN_PAGE_ITEMS),
                    ),
                },
                params: JsonValue::Object(vec![
                    ("page_size".to_owned(), number(MAX_RUN_PAGE_ITEMS as u64)),
                    ("since".to_owned(), number(wire_ceiling())),
                    (
                        "states".to_owned(),
                        JsonValue::Array(
                            [
                                "timed_out",
                                "ready",
                                "failed",
                                "completed",
                                "running",
                                "cancelled",
                            ]
                            .into_iter()
                            .map(text)
                            .collect(),
                        ),
                    ),
                ]),
            },
            RequestCase {
                id: "list-runs-unfiltered",
                note: "no filter and no cursor: two explicit nulls, which are different wire \
                       facts from an absent key and from a filter naming every state",
                request: RunsRequest::ListRuns {
                    request_id: request_id("req-list-1"),
                    query: ListRuns::new(RunStateFilter::any(), None, page_size(1)),
                },
                params: JsonValue::Object(vec![
                    ("page_size".to_owned(), number(1)),
                    ("since".to_owned(), JsonValue::Null),
                    ("states".to_owned(), JsonValue::Null),
                ]),
            },
            RequestCase {
                id: "list-runs-from-position-zero",
                note: "position zero is a cursor a listing may hold, and is not the absence of \
                       one",
                request: RunsRequest::ListRuns {
                    request_id: request_id("req-list-2"),
                    query: ListRuns::new(
                        RunStateFilter::only([RunState::Completed, RunState::Ready])
                            .expect("a two-state filter"),
                        Some(RunCursor::new(0)),
                        page_size(7),
                    ),
                },
                params: JsonValue::Object(vec![
                    ("page_size".to_owned(), number(7)),
                    ("since".to_owned(), number(0)),
                    (
                        "states".to_owned(),
                        JsonValue::Array(vec![text("completed"), text("ready")]),
                    ),
                ]),
            },
            RequestCase {
                id: "run-detail-escaping",
                note: "a run identity carrying every escape a bounded identifier can reach, a \
                       three-byte character and a surrogate pair",
                request: RunsRequest::RunDetail {
                    request_id: request_id("req-detail-1"),
                    run_id: run_id(&escaping_run_id()),
                },
                params: JsonValue::Object(vec![("run_id".to_owned(), text(&escaping_run_id()))]),
            },
            RequestCase {
                id: "run-detail-maximal-run-id",
                note: "a run identity at MAX_TOOL_FIELD_BYTES whose every character escapes to \
                       two bytes",
                request: RunsRequest::RunDetail {
                    request_id: request_id("req-detail-2"),
                    run_id: run_id(&maximal_run_id),
                },
                params: JsonValue::Object(vec![("run_id".to_owned(), text(&maximal_run_id))]),
            },
        ]
    }

    fn request_entry(case: &RequestCase) -> JsonValue {
        let message = case.request.to_message().expect("the request encodes");
        let canonical = message.to_canonical_bytes();
        // What the corpus records is checked against the shipped decoder before
        // it is written: a fixture Rust would not itself admit proves nothing.
        assert_eq!(
            RunsRequest::from_canonical_bytes(&canonical).expect("Rust admits its own encoding"),
            case.request,
            "{}: the Rust decoder does not admit the Rust encoding",
            case.id
        );
        assert!(
            canonical.len() <= automonique_protocol::runs_api::MAX_RUNS_CANONICAL_BYTES,
            "{}: the encoding does not fit one runs frame",
            case.id
        );
        JsonValue::Object(vec![
            ("canonical_bytes".to_owned(), count(canonical.len())),
            ("canonical_hex".to_owned(), text(&hex(&canonical))),
            ("id".to_owned(), text(case.id)),
            ("kind".to_owned(), text(message.envelope().kind().as_str())),
            ("note".to_owned(), text(case.note)),
            ("params".to_owned(), case.params.clone()),
            (
                "request_id".to_owned(),
                text(message.envelope().request_id().as_str()),
            ),
        ])
    }

    // -----------------------------------------------------------------------
    // Responses
    // -----------------------------------------------------------------------

    struct ResponseCase {
        id: &'static str,
        note: &'static str,
        response: RunsResponse,
    }

    /// A listing answer built through the enforcement path rather than around
    /// it.
    ///
    /// `RunsResponse::listing` is what refuses a page that contradicts the
    /// retention decision it was built from, so a corpus entry that constructed
    /// the variant directly would record bytes no daemon could have produced.
    fn listing(
        id: &str,
        query: &ListRuns,
        retained: RetainedRange,
        page: RunListPage,
    ) -> RunsResponse {
        let decision = query.resume_within(retained);
        assert!(
            matches!(decision, CursorResume::Live { .. }),
            "{id}: this fixture's cursor is inside retention"
        );
        RunsResponse::listing(request_id(id), query, decision, Some(page))
            .expect("the page satisfies the decision it answers")
    }

    fn response_cases() -> Vec<ResponseCase> {
        let unfiltered = ListRuns::new(RunStateFilter::any(), None, page_size(MAX_RUN_PAGE_ITEMS));
        let retained = RetainedRange::new(1, wire_ceiling()).expect("a retained window");

        vec![
            ResponseCase {
                id: "run-list-page-more",
                note: "a page whose last row and whose continuation cursor are both at the \
                       wire's ceiling, which a decoder carrying counters in a double would round \
                       to an even neighbour",
                response: listing(
                    "run-list-page-more",
                    &unfiltered,
                    retained,
                    RunListPage::new(
                        vec![
                            summary("run-first", 1, RunState::Running, 0),
                            summary(
                                "run-last",
                                wire_ceiling() - 1,
                                RunState::Completed,
                                i64::MAX,
                            ),
                        ],
                        Continuation::More(RunCursor::new(wire_ceiling())),
                    )
                    .expect("a well-formed page"),
                ),
            },
            ResponseCase {
                id: "run-list-page-empty-more",
                note: "an empty page that still reports more: a state filter can exclude every \
                       row in one scanned window while rows remain behind it, so a client that \
                       inferred `done` from a short page would stop early",
                response: listing(
                    "run-list-page-empty-more",
                    &unfiltered,
                    retained,
                    RunListPage::new(Vec::new(), Continuation::More(RunCursor::new(42)))
                        .expect("an empty page may continue"),
                ),
            },
            ResponseCase {
                id: "run-list-page-complete",
                note: "the end of the retained log: `more` false and an explicit null cursor",
                response: listing(
                    "run-list-page-complete",
                    &unfiltered,
                    retained,
                    RunListPage::new(
                        vec![summary(
                            "run-only",
                            9,
                            RunState::TimedOut,
                            1_700_000_000_000,
                        )],
                        Continuation::Complete,
                    )
                    .expect("a well-formed page"),
                ),
            },
            ResponseCase {
                id: "run-detail-truncated",
                note: "a bounded tail with a coverage that says so; the omitted events stay on \
                       the subscribe lane, resuming from the last carried sequence",
                response: RunsResponse::RunDetail {
                    request_id: request_id("req-detail-1"),
                    view: RunDetailView::new(
                        summary("run-busy", 4, RunState::Running, 1_700_000_000_000),
                        500,
                        vec![
                            event(
                                1,
                                1_700_000_000_001,
                                SpoolEventKind::Started,
                                Authority::Authoritative,
                            ),
                            event(
                                2,
                                1_700_000_000_002,
                                SpoolEventKind::AdapterEvent,
                                Authority::Synthetic,
                            ),
                        ],
                        LifecycleCoverage::Truncated,
                    )
                    .expect("a coherent truncated view"),
                },
            },
            ResponseCase {
                id: "run-detail-complete-terminal",
                note: "the whole log of an ended run: the final event is terminal exactly \
                       because the state is",
                response: RunsResponse::RunDetail {
                    request_id: request_id("req-detail-2"),
                    view: RunDetailView::new(
                        summary("run-done", 5, RunState::Completed, 1_700_000_000_000),
                        3,
                        vec![
                            event(
                                1,
                                1_700_000_000_001,
                                SpoolEventKind::Started,
                                Authority::Authoritative,
                            ),
                            event(
                                2,
                                1_700_000_000_002,
                                SpoolEventKind::CancelRequested,
                                Authority::Authoritative,
                            ),
                            event(
                                3,
                                1_700_000_000_003,
                                SpoolEventKind::Terminal,
                                Authority::Synthetic,
                            ),
                        ],
                        LifecycleCoverage::Complete,
                    )
                    .expect("a coherent complete view"),
                },
            },
            ResponseCase {
                id: "run-detail-complete-empty",
                note: "an accepted run with no events yet: an empty array and sequence zero, \
                       which is a complete log rather than a truncated one",
                response: RunsResponse::RunDetail {
                    request_id: request_id("req-detail-3"),
                    view: RunDetailView::new(
                        summary("run-ready", 6, RunState::Ready, 0),
                        0,
                        Vec::new(),
                        LifecycleCoverage::Complete,
                    )
                    .expect("a coherent empty view"),
                },
            },
            ResponseCase {
                id: "resync-required",
                note: "a cursor outside retention receives the window a bounded snapshot must \
                       cover, and never a partial page",
                response: RunsResponse::Resync {
                    request_id: request_id("req-list-3"),
                    snapshot_from: 10,
                    snapshot_to: 99,
                },
            },
            ResponseCase {
                id: "refused-unknown-run",
                note: "the only refusal this slice can decide; there is no not_authorized, \
                       because no actor is modelled",
                response: RunsResponse::Refused {
                    request_id: request_id("req-detail-4"),
                    refusal: RunsRefusal::UnknownRun,
                },
            },
        ]
    }

    /// How one decoded response is spelled in the corpus.
    ///
    /// Built from the value the *Rust decoder* recovered, and flattened with
    /// dotted keys so a nested page compares field by field rather than as one
    /// opaque blob: a runner that decoded the third summary's state wrongly says
    /// exactly that.
    fn decoded_spelling(response: &RunsResponse) -> JsonValue {
        let mut fields = vec![(
            "request_id".to_owned(),
            text(response.request_id().as_str()),
        )];
        let summary_fields = |prefix: &str, value: &RunSummary| -> Vec<(String, JsonValue)> {
            [
                (
                    "accepted_at_ms",
                    JsonValue::String(value.accepted_at().as_millis().to_string()),
                ),
                ("run_id", text(value.run_id().as_str())),
                ("spec_digest", text(&value.spec_digest().to_string())),
                ("state", text(value.state().as_str())),
                ("submission_id", number(value.submission_id())),
                ("submission_state", text(value.submission_state().as_str())),
            ]
            .into_iter()
            .map(|(name, spelled)| (format!("{prefix}{name}"), spelled))
            .collect()
        };
        match response {
            RunsResponse::RunList { page, .. } => {
                fields.push((
                    "more".to_owned(),
                    text(&page.continuation().has_more().to_string()),
                ));
                fields.push((
                    "next_cursor".to_owned(),
                    match page.continuation().cursor() {
                        Some(cursor) => number(cursor.position()),
                        None => text("null"),
                    },
                ));
                fields.push(("runs.len".to_owned(), number(page.runs().len() as u64)));
                for (index, run) in page.runs().iter().enumerate() {
                    fields.extend(summary_fields(&format!("runs.{index}."), run));
                }
            }
            RunsResponse::RunDetail { view, .. } => {
                fields.push(("coverage".to_owned(), text(view.coverage().as_str())));
                fields.push(("last_sequence".to_owned(), number(view.last_sequence())));
                fields.push((
                    "lifecycle.len".to_owned(),
                    number(view.lifecycle().len() as u64),
                ));
                for (index, carried) in view.lifecycle().iter().enumerate() {
                    for (name, spelled) in [
                        (
                            "at_ms",
                            JsonValue::String(carried.at().as_millis().to_string()),
                        ),
                        ("authority", text(carried.authority().as_str())),
                        ("kind", text(carried.kind().as_str())),
                        ("sequence", number(carried.sequence())),
                    ] {
                        fields.push((format!("lifecycle.{index}.{name}"), spelled));
                    }
                }
                fields.extend(summary_fields("summary.", view.summary()));
            }
            RunsResponse::Resync {
                snapshot_from,
                snapshot_to,
                ..
            } => {
                fields.push(("snapshot_from".to_owned(), number(*snapshot_from)));
                fields.push(("snapshot_to".to_owned(), number(*snapshot_to)));
            }
            RunsResponse::Refused { refusal, .. } => {
                fields.push(("refusal".to_owned(), text(refusal.as_str())));
            }
        }
        JsonValue::Object(fields)
    }

    fn response_entry(case: &ResponseCase) -> JsonValue {
        let message = case.response.to_message().expect("the response encodes");
        let canonical = message.to_canonical_bytes();
        let decoded =
            RunsResponse::from_canonical_bytes(&canonical).expect("Rust admits its own encoding");
        assert_eq!(
            decoded, case.response,
            "{}: the Rust decoder does not recover what it encoded",
            case.id
        );
        JsonValue::Object(vec![
            ("canonical_hex".to_owned(), text(&hex(&canonical))),
            ("decoded".to_owned(), decoded_spelling(&decoded)),
            ("id".to_owned(), text(case.id)),
            ("kind".to_owned(), text(message.envelope().kind().as_str())),
            ("note".to_owned(), text(case.note)),
            ("outcome".to_owned(), text(decoded.outcome().as_str())),
        ])
    }

    // -----------------------------------------------------------------------
    // Refusals
    // -----------------------------------------------------------------------

    /// A payload both implementations must refuse, under one category.
    struct DecodeRefusal {
        id: &'static str,
        note: &'static str,
        payload: Vec<u8>,
    }

    /// A well-formed summary body, as a starting point for one that is not.
    fn summary_body(overrides: &[(&str, JsonValue)]) -> JsonValue {
        let mut entries: Vec<(String, JsonValue)> = vec![
            (
                "accepted_at_ms".to_owned(),
                JsonValue::Integer(1_700_000_000_000),
            ),
            ("run_id".to_owned(), text("run-1")),
            (
                "spec_digest".to_owned(),
                text(&Sha256::digest(b"document").to_string()),
            ),
            ("state".to_owned(), text("running")),
            ("submission_id".to_owned(), JsonValue::Integer(1)),
            ("submission_state".to_owned(), text("accepted")),
        ];
        for (name, value) in overrides {
            let slot = entries
                .iter_mut()
                .find(|(existing, _)| existing == name)
                .unwrap_or_else(|| panic!("{name} is not a summary field"));
            slot.1 = value.clone();
        }
        JsonValue::Object(entries)
    }

    /// A well-formed lifecycle event body.
    fn event_body(overrides: &[(&str, JsonValue)]) -> JsonValue {
        let mut entries: Vec<(String, JsonValue)> = vec![
            ("at_ms".to_owned(), JsonValue::Integer(1_700_000_000_001)),
            ("authority".to_owned(), text("authoritative")),
            ("kind".to_owned(), text("started")),
            ("sequence".to_owned(), JsonValue::Integer(1)),
        ];
        for (name, value) in overrides {
            let slot = entries
                .iter_mut()
                .find(|(existing, _)| existing == name)
                .unwrap_or_else(|| panic!("{name} is not a lifecycle field"));
            slot.1 = value.clone();
        }
        JsonValue::Object(entries)
    }

    /// A page body carrying the given summaries and continuation.
    fn page_body(runs: Vec<JsonValue>, more: bool, next_cursor: JsonValue) -> JsonValue {
        JsonValue::Object(vec![
            ("more".to_owned(), JsonValue::Bool(more)),
            ("next_cursor".to_owned(), next_cursor),
            ("runs".to_owned(), JsonValue::Array(runs)),
        ])
    }

    /// A detail body carrying the given lifecycle, coverage and last sequence.
    fn view_body(
        summary: JsonValue,
        last_sequence: i64,
        lifecycle: Vec<JsonValue>,
        coverage: &str,
    ) -> JsonValue {
        JsonValue::Object(vec![
            ("causation_id".to_owned(), JsonValue::Null),
            ("correlation_id".to_owned(), JsonValue::Null),
            ("coverage".to_owned(), text(coverage)),
            (
                "last_sequence".to_owned(),
                JsonValue::Integer(last_sequence),
            ),
            ("lifecycle".to_owned(), JsonValue::Array(lifecycle)),
            ("summary".to_owned(), summary),
            ("trace_id".to_owned(), JsonValue::Null),
        ])
    }

    fn runs_message(kind: &str, id: &str, body: JsonValue) -> Vec<u8> {
        raw_message(RUNS_PROTOCOL, 1, kind, id, body)
    }

    fn decode_refusals() -> Vec<DecodeRefusal> {
        // Both array bounds are judged before any item is read, in Rust and in
        // the generated TypeScript alike, so the over-bound payloads carry
        // integers rather than bodies: what is wrong with them is their length.
        let filler = |count: usize| -> Vec<JsonValue> {
            (0..count)
                .map(|index| JsonValue::Integer(index as i64))
                .collect()
        };
        vec![
            DecodeRefusal {
                id: "state-undefined-spelling",
                note: "a run state this build does not define fails closed rather than \
                       decoding to a default a client would act on",
                payload: runs_message(
                    "run_list_result",
                    "req-list-1",
                    page_body(
                        vec![summary_body(&[("state", text("paused"))])],
                        false,
                        JsonValue::Null,
                    ),
                ),
            },
            DecodeRefusal {
                id: "submission-state-undefined-spelling",
                note: "the store's custody vocabulary is closed at one value in this release, \
                       and a second one is refused rather than retained",
                payload: runs_message(
                    "run_list_result",
                    "req-list-1",
                    page_body(
                        vec![summary_body(&[("submission_state", text("queued"))])],
                        false,
                        JsonValue::Null,
                    ),
                ),
            },
            DecodeRefusal {
                id: "spool-event-kind-undefined-spelling",
                note: "the runner's five durable kinds are not the normalized 23-kind event \
                       vocabulary; a kind from the other one is undefined here",
                payload: runs_message(
                    "run_detail_result",
                    "req-detail-1",
                    view_body(
                        summary_body(&[]),
                        1,
                        vec![event_body(&[("kind", text("tool_call"))])],
                        "complete",
                    ),
                ),
            },
            DecodeRefusal {
                id: "authority-undefined-spelling",
                note: "an authority outside the two words both crates carry",
                payload: runs_message(
                    "run_detail_result",
                    "req-detail-1",
                    view_body(
                        summary_body(&[]),
                        1,
                        vec![event_body(&[("authority", text("inferred"))])],
                        "complete",
                    ),
                ),
            },
            DecodeRefusal {
                id: "coverage-undefined-spelling",
                note: "a third coverage would be a partial log presented as something a client \
                       has no rule for",
                payload: runs_message(
                    "run_detail_result",
                    "req-detail-1",
                    view_body(summary_body(&[]), 0, Vec::new(), "partial"),
                ),
            },
            DecodeRefusal {
                id: "refusal-not-authorized",
                note: "this slice models no actor, so it names no authorization refusal; a peer \
                       claiming one is a peer this build does not understand",
                payload: runs_message(
                    "refused",
                    "req-detail-1",
                    JsonValue::Object(vec![("refusal".to_owned(), text("not_authorized"))]),
                ),
            },
            DecodeRefusal {
                id: "submission-id-zero",
                note: "a durable identity starts at one; zero names a row no writer produced",
                payload: runs_message(
                    "run_list_result",
                    "req-list-1",
                    page_body(
                        vec![summary_body(&[("submission_id", JsonValue::Integer(0))])],
                        false,
                        JsonValue::Null,
                    ),
                ),
            },
            DecodeRefusal {
                id: "submission-id-negative",
                note: "a negative identity is a malformed body rather than an unwritten row: \
                       the decoder converts before it judges the domain, and the two categories \
                       differ",
                payload: runs_message(
                    "run_list_result",
                    "req-list-1",
                    page_body(
                        vec![summary_body(&[("submission_id", JsonValue::Integer(-1))])],
                        false,
                        JsonValue::Null,
                    ),
                ),
            },
            DecodeRefusal {
                id: "accepted-at-before-epoch",
                note: "an acceptance instant the store's own constraint cannot hold",
                payload: runs_message(
                    "run_list_result",
                    "req-list-1",
                    page_body(
                        vec![summary_body(&[("accepted_at_ms", JsonValue::Integer(-1))])],
                        false,
                        JsonValue::Null,
                    ),
                ),
            },
            DecodeRefusal {
                id: "lifecycle-sequence-zero",
                note: "spool sequences begin at one; zero is what the status reports when there \
                       are no events at all",
                payload: runs_message(
                    "run_detail_result",
                    "req-detail-1",
                    view_body(
                        summary_body(&[]),
                        1,
                        vec![event_body(&[("sequence", JsonValue::Integer(0))])],
                        "complete",
                    ),
                ),
            },
            DecodeRefusal {
                id: "page-over-bound",
                note: "one row past MAX_RUN_PAGE_ITEMS. The length is judged before any item is \
                       read, so what these items are does not matter and the refusal names the \
                       length",
                payload: runs_message(
                    "run_list_result",
                    "req-list-1",
                    page_body(filler(MAX_RUN_PAGE_ITEMS + 1), false, JsonValue::Null),
                ),
            },
            DecodeRefusal {
                id: "lifecycle-over-bound",
                note: "one event past MAX_LIFECYCLE_EVENTS, judged the same way",
                payload: runs_message(
                    "run_detail_result",
                    "req-detail-1",
                    view_body(
                        summary_body(&[]),
                        1,
                        filler(MAX_LIFECYCLE_EVENTS + 1),
                        "complete",
                    ),
                ),
            },
            DecodeRefusal {
                id: "page-extra-field",
                note: "an unexpected key is refused rather than ignored",
                payload: runs_message(
                    "run_list_result",
                    "req-list-1",
                    JsonValue::Object(vec![
                        ("more".to_owned(), JsonValue::Bool(false)),
                        ("next_cursor".to_owned(), JsonValue::Null),
                        ("runs".to_owned(), JsonValue::Array(Vec::new())),
                        ("total".to_owned(), JsonValue::Integer(1)),
                    ]),
                ),
            },
            DecodeRefusal {
                id: "summary-missing-field",
                note: "a missing key is refused rather than defaulted, inside a nested body as \
                       much as at the top level",
                payload: runs_message(
                    "run_list_result",
                    "req-list-1",
                    page_body(
                        vec![JsonValue::Object(vec![
                            ("accepted_at_ms".to_owned(), JsonValue::Integer(0)),
                            ("run_id".to_owned(), text("run-1")),
                            ("state".to_owned(), text("running")),
                            ("submission_id".to_owned(), JsonValue::Integer(1)),
                            ("submission_state".to_owned(), text("accepted")),
                        ])],
                        false,
                        JsonValue::Null,
                    ),
                ),
            },
            DecodeRefusal {
                id: "unknown-kind",
                note: "a kind this protocol version does not define, which is a different \
                       answer from a kind it defines and this surface does not decode",
                payload: runs_message(
                    "run_events_result",
                    "req-list-1",
                    page_body(Vec::new(), false, JsonValue::Null),
                ),
            },
            DecodeRefusal {
                id: "admin-protocol-message",
                note: "the admin lane's name on this lane's decoder, refused on the name axis \
                       so the two protocols' closed kind sets stay closed",
                payload: raw_message(
                    "automonique.admin",
                    1,
                    "run_list_result",
                    "req-list-1",
                    page_body(Vec::new(), false, JsonValue::Null),
                ),
            },
            DecodeRefusal {
                id: "unsupported-version",
                note: "this protocol at a major version neither side implements",
                payload: raw_message(
                    RUNS_PROTOCOL,
                    2,
                    "run_list_result",
                    "req-list-1",
                    page_body(Vec::new(), false, JsonValue::Null),
                ),
            },
            DecodeRefusal {
                id: "non-canonical-key-order",
                note: "a payload that parses but is not canonical is refused, not normalized",
                payload: br#"{"kind":"refused","body":{"refusal":"unknown_run"},"protocol":"automonique.runs","request_id":"req-detail-1","version":1}"#.to_vec(),
            },
            DecodeRefusal {
                id: "empty-payload",
                note: "zero bytes is not an empty message",
                payload: Vec::new(),
            },
        ]
    }

    fn decode_refusal_entry(refusal: &DecodeRefusal) -> JsonValue {
        let category = RunsResponse::from_canonical_bytes(&refusal.payload)
            .err()
            .unwrap_or_else(|| panic!("{}: Rust accepted a payload it must refuse", refusal.id))
            .category()
            .to_owned();
        JsonValue::Object(vec![
            ("category".to_owned(), text(&category)),
            ("id".to_owned(), text(refusal.id)),
            ("note".to_owned(), text(refusal.note)),
            ("payload_hex".to_owned(), text(&hex(&refusal.payload))),
        ])
    }

    // -----------------------------------------------------------------------
    // The measured gap
    // -----------------------------------------------------------------------

    /// A payload the Rust constructors refuse and the generated TypeScript
    /// accepts.
    ///
    /// Every one of these breaks a rule that relates two fields, which the
    /// generated surface does not hold: it carries each field's own shape and
    /// bounds. Recording them as a corpus section rather than as a sentence
    /// makes the gap a measurement — the runner asserts these decode, so
    /// teaching the generator one of these rules turns this suite red until the
    /// entry moves up to [`decode_refusals`].
    struct RustOnlyRefusal {
        id: &'static str,
        note: &'static str,
        payload: Vec<u8>,
    }

    fn rust_only_refusals() -> Vec<RustOnlyRefusal> {
        vec![
            RustOnlyRefusal {
                id: "continuation-incoherent",
                note: "rows follow, with no cursor to resume from",
                payload: runs_message(
                    "run_list_result",
                    "req-list-1",
                    page_body(Vec::new(), true, JsonValue::Null),
                ),
            },
            RustOnlyRefusal {
                id: "continuation-rewinds",
                note: "a continuation cursor at or below the last row on the page, which would \
                       re-serve it",
                payload: runs_message(
                    "run_list_result",
                    "req-list-1",
                    page_body(
                        vec![summary_body(&[("submission_id", JsonValue::Integer(9))])],
                        true,
                        JsonValue::Integer(9),
                    ),
                ),
            },
            RustOnlyRefusal {
                id: "page-out-of-order",
                note: "summaries that do not strictly increase by submission identity, so the \
                       next page would re-serve or skip",
                payload: runs_message(
                    "run_list_result",
                    "req-list-1",
                    page_body(
                        vec![
                            summary_body(&[("submission_id", JsonValue::Integer(5))]),
                            summary_body(&[("submission_id", JsonValue::Integer(2))]),
                        ],
                        false,
                        JsonValue::Null,
                    ),
                ),
            },
            RustOnlyRefusal {
                id: "lifecycle-out-of-order",
                note: "lifecycle sequences that do not strictly increase",
                payload: runs_message(
                    "run_detail_result",
                    "req-detail-1",
                    view_body(
                        summary_body(&[]),
                        9,
                        vec![
                            event_body(&[("sequence", JsonValue::Integer(4))]),
                            event_body(&[("sequence", JsonValue::Integer(2))]),
                        ],
                        "truncated",
                    ),
                ),
            },
            RustOnlyRefusal {
                id: "lifecycle-above-last-sequence",
                note: "an event above the highest sequence the run's spool reports holding",
                payload: runs_message(
                    "run_detail_result",
                    "req-detail-1",
                    view_body(
                        summary_body(&[]),
                        1,
                        vec![event_body(&[("sequence", JsonValue::Integer(7))])],
                        "complete",
                    ),
                ),
            },
            RustOnlyRefusal {
                id: "terminal-event-not-last",
                note: "a run reaches exactly one terminal event and nothing follows it",
                payload: runs_message(
                    "run_detail_result",
                    "req-detail-1",
                    view_body(
                        summary_body(&[("state", text("completed"))]),
                        2,
                        vec![
                            event_body(&[
                                ("kind", text("terminal")),
                                ("sequence", JsonValue::Integer(1)),
                            ]),
                            event_body(&[
                                ("kind", text("adapter_event")),
                                ("sequence", JsonValue::Integer(2)),
                            ]),
                        ],
                        "complete",
                    ),
                ),
            },
            RustOnlyRefusal {
                id: "terminal-event-contradicts-state",
                note: "a terminal event carried for a run whose state says it has not ended",
                payload: runs_message(
                    "run_detail_result",
                    "req-detail-1",
                    view_body(
                        summary_body(&[("state", text("running"))]),
                        1,
                        vec![event_body(&[("kind", text("terminal"))])],
                        "complete",
                    ),
                ),
            },
            RustOnlyRefusal {
                id: "coverage-incoherent",
                note: "a log declared complete that stops below the last sequence the run holds",
                payload: runs_message(
                    "run_detail_result",
                    "req-detail-1",
                    view_body(
                        summary_body(&[]),
                        9,
                        vec![event_body(&[("sequence", JsonValue::Integer(1))])],
                        "complete",
                    ),
                ),
            },
            RustOnlyRefusal {
                id: "resync-inverted-window",
                note: "a snapshot window that ends before it starts",
                payload: runs_message(
                    "resync_required",
                    "req-list-1",
                    JsonValue::Object(vec![
                        ("snapshot_from".to_owned(), JsonValue::Integer(99)),
                        ("snapshot_to".to_owned(), JsonValue::Integer(10)),
                    ]),
                ),
            },
        ]
    }

    fn rust_only_entry(refusal: &RustOnlyRefusal) -> JsonValue {
        let category = RunsResponse::from_canonical_bytes(&refusal.payload)
            .err()
            .unwrap_or_else(|| {
                panic!(
                    "{}: Rust accepts this, so it is not a rule the generated surface is \
                     missing",
                    refusal.id
                )
            })
            .category()
            .to_owned();
        JsonValue::Object(vec![
            ("id".to_owned(), text(refusal.id)),
            ("note".to_owned(), text(refusal.note)),
            ("payload_hex".to_owned(), text(&hex(&refusal.payload))),
            ("rust_category".to_owned(), text(&category)),
        ])
    }

    // -----------------------------------------------------------------------
    // Encode refusals
    // -----------------------------------------------------------------------

    /// A request the other implementation must refuse while building it.
    struct EncodeRefusal {
        id: &'static str,
        note: &'static str,
        kind: &'static str,
        request_id: String,
        params: JsonValue,
        category: String,
        /// The generated constructor that refuses the value, and the violation
        /// it names.
        constructor: Option<(&'static str, &'static str)>,
    }

    /// The category Rust reports for a run identity this lane cannot carry.
    ///
    /// Taken from the constructor's own refusal rather than named here: the
    /// bounded-value error is `RunId`'s, and the category is the one this
    /// protocol reports when it meets that error on the wire.
    fn run_id_category(value: &str) -> String {
        RunsApiError::Field {
            field: "run_id",
            error: RunId::new(value).expect_err("this identity is refused"),
        }
        .category()
        .to_owned()
    }

    fn encode_refusals() -> Vec<EncodeRefusal> {
        let long_run_id = "r".repeat(MAX_TOOL_FIELD_BYTES + 1);
        let long_request_id = "r".repeat(MAX_REQUEST_ID_BYTES + 1);
        let unfiltered = || JsonValue::Null;

        let page_size_category = PageSize::new(0)
            .expect_err("a page that admits nothing is refused")
            .category()
            .to_owned();
        let cursor_category = RunsRequest::ListRuns {
            request_id: request_id("req-list-1"),
            query: ListRuns::new(
                RunStateFilter::any(),
                Some(RunCursor::new(wire_ceiling() + 1)),
                page_size(1),
            ),
        }
        .to_message()
        .expect_err("a cursor above the wire ceiling is refused")
        .category()
        .to_owned();
        let empty_filter_category = RunStateFilter::only([])
            .expect_err("an empty filter is refused")
            .category()
            .to_owned();
        let repeat_filter_category = RunStateFilter::only([RunState::Running, RunState::Running])
            .expect_err("a repeated state is refused")
            .category()
            .to_owned();
        let undefined_state_category =
            RunsApiError::Codec(automonique_protocol::codec::CodecError::UnknownEnumValue {
                field: "state",
            })
            .category()
            .to_owned();
        let long_id_category = RunsApiError::Codec(
            RequestId::new(&long_request_id).expect_err("an overlong request id is refused"),
        )
        .category()
        .to_owned();
        let bad_id_category = RunsApiError::Codec(
            RequestId::new("req 1").expect_err("a space is outside the request id grammar"),
        )
        .category()
        .to_owned();

        let list_params = |size: JsonValue, since: JsonValue, states: JsonValue| {
            JsonValue::Object(vec![
                ("page_size".to_owned(), size),
                ("since".to_owned(), since),
                ("states".to_owned(), states),
            ])
        };

        vec![
            EncodeRefusal {
                id: "list-runs-page-size-zero",
                note: "a page that admits nothing cannot make progress, so zero is refused \
                       rather than treated as a default",
                kind: "list_runs",
                request_id: "req-list-1".to_owned(),
                params: list_params(number(0), JsonValue::Null, unfiltered()),
                category: page_size_category.clone(),
                constructor: Some(("PageSize", "out_of_range")),
            },
            EncodeRefusal {
                id: "list-runs-page-size-above-bound",
                note: "one past MAX_RUN_PAGE_ITEMS",
                kind: "list_runs",
                request_id: "req-list-1".to_owned(),
                params: list_params(
                    number(MAX_RUN_PAGE_ITEMS as u64 + 1),
                    JsonValue::Null,
                    unfiltered(),
                ),
                category: page_size_category,
                constructor: Some(("PageSize", "out_of_range")),
            },
            EncodeRefusal {
                id: "list-runs-cursor-above-wire-ceiling",
                note: "a cursor one past the largest integer this wire carries, which is a \
                       counter refusal rather than a malformed body",
                kind: "list_runs",
                request_id: "req-list-1".to_owned(),
                params: list_params(number(1), number(wire_ceiling() + 1), unfiltered()),
                category: cursor_category,
                constructor: Some(("RunCursor", "out_of_range")),
            },
            EncodeRefusal {
                id: "list-runs-empty-state-filter",
                note: "an empty filter admits nothing, which no listing could ever answer; it \
                       is not the same request as no filter at all",
                kind: "list_runs",
                request_id: "req-list-1".to_owned(),
                params: list_params(number(1), JsonValue::Null, JsonValue::Array(Vec::new())),
                category: empty_filter_category,
                constructor: None,
            },
            EncodeRefusal {
                id: "list-runs-repeated-state",
                note: "a repeat means a caller believes it asked for something it did not",
                kind: "list_runs",
                request_id: "req-list-1".to_owned(),
                params: list_params(
                    number(1),
                    JsonValue::Null,
                    JsonValue::Array(vec![text("running"), text("running")]),
                ),
                category: repeat_filter_category,
                constructor: None,
            },
            EncodeRefusal {
                id: "list-runs-undefined-state",
                note: "a brand exists only in the type checker, so the builder is where an \
                       untyped caller's undefined state is stopped",
                kind: "list_runs",
                request_id: "req-list-1".to_owned(),
                params: list_params(
                    number(1),
                    JsonValue::Null,
                    JsonValue::Array(vec![text("paused")]),
                ),
                category: undefined_state_category,
                constructor: None,
            },
            EncodeRefusal {
                id: "run-detail-run-id-too-long",
                note: "one byte over the run identity bound, measured in UTF-8 bytes",
                kind: "run_detail",
                request_id: "req-detail-1".to_owned(),
                params: JsonValue::Object(vec![("run_id".to_owned(), text(&long_run_id))]),
                category: run_id_category(&long_run_id),
                constructor: Some(("RunId", "too_long")),
            },
            EncodeRefusal {
                id: "run-detail-run-id-control-character",
                note: "a control character in a run identity, which the wire never carries raw",
                kind: "run_detail",
                request_id: "req-detail-1".to_owned(),
                params: JsonValue::Object(vec![("run_id".to_owned(), text("run\u{7}1"))]),
                category: run_id_category("run\u{7}1"),
                constructor: Some(("RunId", "invalid_character")),
            },
            EncodeRefusal {
                id: "request-id-too-long",
                note: "the envelope's fields are judged by the shared codec, whose refusal for \
                       a bound is not the one this protocol uses for a body",
                kind: "list_runs",
                request_id: long_request_id,
                params: list_params(number(1), JsonValue::Null, unfiltered()),
                category: long_id_category,
                constructor: Some(("RequestId", "too_long")),
            },
            EncodeRefusal {
                id: "request-id-outside-grammar",
                note: "a grammar refusal is not a bounds refusal, and the categories differ",
                kind: "run_detail",
                request_id: "req 1".to_owned(),
                params: JsonValue::Object(vec![("run_id".to_owned(), text("run-1"))]),
                category: bad_id_category,
                constructor: Some(("RequestId", "invalid_character")),
            },
        ]
    }

    fn encode_refusal_entry(refusal: &EncodeRefusal) -> JsonValue {
        let mut entry = vec![
            ("category".to_owned(), text(&refusal.category)),
            ("id".to_owned(), text(refusal.id)),
            ("kind".to_owned(), text(refusal.kind)),
            ("note".to_owned(), text(refusal.note)),
            ("params".to_owned(), refusal.params.clone()),
            ("request_id".to_owned(), text(&refusal.request_id)),
        ];
        if let Some((constructor, violation)) = refusal.constructor {
            // Named `refused_by` rather than `constructor`: a JSON object parsed
            // by a JavaScript reader inherits `constructor` from its prototype.
            entry.push(("refused_by".to_owned(), text(constructor)));
            entry.push(("violation".to_owned(), text(violation)));
        }
        JsonValue::Object(entry)
    }

    // -----------------------------------------------------------------------
    // The corpus file
    // -----------------------------------------------------------------------

    fn corpus() -> String {
        let document = JsonValue::Object(vec![
            (
                "decode_refusals".to_owned(),
                JsonValue::Array(decode_refusals().iter().map(decode_refusal_entry).collect()),
            ),
            (
                "encode_refusals".to_owned(),
                JsonValue::Array(encode_refusals().iter().map(encode_refusal_entry).collect()),
            ),
            (
                "generator".to_owned(),
                text("automonique-protocol tests/codegen.rs, module runs_surface"),
            ),
            (
                "note".to_owned(),
                text(
                    "Generated from the shipped Rust constructors: every canonical byte string \
                     here was produced by encoding a real message and re-read through \
                     from_canonical_bytes before it was written, and every refusal category was \
                     read back from the error Rust returned for that exact input. Counters \
                     travel as decimal strings because a JSON reader using a double would round \
                     the largest of them without saying so. Rust is the wire source of truth, so \
                     a disagreement is fixed in whichever implementation is wrong — never in \
                     this file.",
                ),
            ),
            ("protocol".to_owned(), text(RUNS_PROTOCOL)),
            (
                "requests".to_owned(),
                JsonValue::Array(request_cases().iter().map(request_entry).collect()),
            ),
            (
                "responses".to_owned(),
                JsonValue::Array(response_cases().iter().map(response_entry).collect()),
            ),
            (
                "rust_only_refusals".to_owned(),
                JsonValue::Array(rust_only_refusals().iter().map(rust_only_entry).collect()),
            ),
            (
                "rust_only_refusals_note".to_owned(),
                text(
                    "Payloads the Rust constructors refuse and the generated TypeScript accepts. \
                     Each breaks a rule that relates two fields, which the generated surface \
                     does not hold: it carries each field's own shape and bounds. The runner \
                     asserts these decode, so the gap is measured rather than described — \
                     teaching the generator one of these rules turns the suite red until the \
                     entry moves to decode_refusals.",
                ),
            ),
            (
                "version".to_owned(),
                JsonValue::Integer(i64::from(MajorVersion::FIRST.get())),
            ),
        ]);
        let mut out = String::new();
        write_pretty(&document, 0, &mut out);
        out.push('\n');
        out
    }

    /// The drift gate over the corpus, and the regeneration that closes it.
    #[test]
    fn the_checked_in_corpus_matches_regeneration() {
        let expected = corpus();
        let path = corpus_path();
        if regenerating() {
            let staging = path.with_extension("json.staging");
            std::fs::write(&staging, &expected).expect("stage the corpus");
            std::fs::rename(&staging, &path).expect("publish the corpus");
            return;
        }
        let actual = std::fs::read_to_string(&path)
            .expect("the corpus is checked in — regenerate it to create it");
        if actual != expected {
            let difference = actual
                .lines()
                .zip(expected.lines())
                .enumerate()
                .find(|(_, (left, right))| left != right)
                .map_or_else(
                    || {
                        format!(
                            "{} lines on disk, {} lines generated",
                            actual.lines().count(),
                            expected.lines().count()
                        )
                    },
                    |(index, (left, right))| {
                        let shorten = |line: &str| line.chars().take(120).collect::<String>();
                        format!(
                            "line {}: on disk {:?}, generated {:?}",
                            index + 1,
                            shorten(left),
                            shorten(right)
                        )
                    },
                );
            panic!(
                "the checked-in runs corpus no longer matches the Rust encoders: {difference}\n\n\
                 Regenerate with: {REGENERATE_COMMAND}"
            );
        }
    }

    /// Every request this protocol version defines is generated or named absent.
    ///
    /// The kinds come from encoding one request per [`RunsRequest`] variant, and
    /// the `match` below is exhaustive, so a request added to the protocol
    /// fails here rather than quietly falling outside the generated surface.
    #[test]
    fn every_request_kind_is_generated_or_named_as_absent() {
        let id = request_id("req-coverage-1");
        let requests = vec![
            RunsRequest::ListRuns {
                request_id: id.clone(),
                query: ListRuns::new(RunStateFilter::any(), None, page_size(1)),
            },
            RunsRequest::RunDetail {
                request_id: id,
                run_id: run_id("run-1"),
            },
        ];
        for request in &requests {
            match request {
                RunsRequest::ListRuns { .. } | RunsRequest::RunDetail { .. } => {}
            }
        }
        let encoded: BTreeSet<String> = requests
            .iter()
            .map(|request| {
                request
                    .to_message()
                    .expect("each request encodes")
                    .envelope()
                    .kind()
                    .as_str()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            encoded.len(),
            requests.len(),
            "one request per variant is required, each with its own kind"
        );

        let surface = surface();
        let mut covered: BTreeSet<String> = surface
            .requests
            .iter()
            .map(|request| request.kind.clone())
            .collect();
        for kind in &surface.request_kinds_not_generated {
            assert!(
                covered.insert(kind.clone()),
                "{kind} is both generated and named as absent"
            );
        }
        assert_eq!(
            covered, encoded,
            "the generated runs surface does not account for every request kind the Rust \
             encoders produce; regenerate with: {REGENERATE_COMMAND}"
        );
    }

    /// Every response this protocol version defines is decoded or named as
    /// undecoded.
    #[test]
    fn every_response_kind_is_decoded_or_named_as_undecoded() {
        let id = request_id("req-coverage-1");
        let responses = vec![
            RunsResponse::RunList {
                request_id: id.clone(),
                page: RunListPage::new(Vec::new(), Continuation::Complete).expect("a page"),
            },
            RunsResponse::RunDetail {
                request_id: id.clone(),
                view: RunDetailView::new(
                    summary("run-1", 1, RunState::Ready, 0),
                    0,
                    Vec::new(),
                    LifecycleCoverage::Complete,
                )
                .expect("a view"),
            },
            RunsResponse::Resync {
                request_id: id.clone(),
                snapshot_from: 1,
                snapshot_to: 2,
            },
            RunsResponse::Refused {
                request_id: id,
                refusal: RunsRefusal::UnknownRun,
            },
        ];
        // The match is the point: a variant added to `RunsResponse` fails to
        // compile here rather than slipping past a surface that ignores it.
        for response in &responses {
            match response {
                RunsResponse::RunList { .. }
                | RunsResponse::RunDetail { .. }
                | RunsResponse::Resync { .. }
                | RunsResponse::Refused { .. } => {}
            }
        }
        let encoded: BTreeSet<String> = responses
            .iter()
            .map(|response| {
                response
                    .to_message()
                    .expect("each response encodes")
                    .envelope()
                    .kind()
                    .as_str()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            encoded.len(),
            responses.len(),
            "one response per variant is required, each with its own kind"
        );

        let surface = surface();
        let mut covered: BTreeSet<String> = surface
            .responses
            .iter()
            .map(|response| response.kind.clone())
            .collect();
        for kind in &surface.response_kinds_not_decoded {
            assert!(
                covered.insert(kind.clone()),
                "{kind} is both decoded and named as undecoded"
            );
        }
        assert_eq!(
            covered, encoded,
            "the generated runs surface does not account for every answer the daemon can \
             produce; regenerate with: {REGENERATE_COMMAND}"
        );
    }

    /// The closed vocabularies, restated here rather than read back from the
    /// generator.
    ///
    /// A generator that dropped a variant would agree with itself perfectly.
    /// This is the second opinion, and the third is the wire order, which is
    /// checked against `RunState::ALL` rather than against a list: the sorted
    /// `_VALUES` table is not the order a state filter encodes in, and a
    /// generator that emitted the sorted one there would produce bytes Rust
    /// refuses to match.
    #[test]
    fn every_closed_vocabulary_carries_all_of_its_variants() {
        let generated = generated_runs();
        let expected: [(&str, &[&str]); 6] = [
            ("Authority", &["authoritative", "synthetic"]),
            ("LifecycleCoverage", &["complete", "truncated"]),
            (
                "RunState",
                &[
                    "cancelled",
                    "completed",
                    "failed",
                    "ready",
                    "running",
                    "timed_out",
                ],
            ),
            ("RunsRefusal", &["unknown_run"]),
            (
                "SpoolEventKind",
                &[
                    "adapter_event",
                    "cancel_requested",
                    "simulation_event",
                    "started",
                    "terminal",
                ],
            ),
            ("SubmissionState", &["accepted"]),
        ];
        for (name, values) in expected {
            let literals: Vec<String> = values.iter().map(|value| format!("\"{value}\"")).collect();
            let declaration = format!("export type {name} = {};", literals.join(" | "));
            assert!(
                generated.contains(&declaration),
                "the runs surface lost a {name} variant.\nexpected: {declaration}"
            );
            assert!(
                generated.contains(&format!(
                    "export const {name}_VALUES: readonly {name}[] = [{}];",
                    literals.join(", ")
                )),
                "the {name} table does not match its type"
            );
            // Every one of these is a `SecuritySensitiveEnum` in Rust, whose
            // decoder refuses an undefined spelling rather than retaining it.
            assert!(
                generated.contains(&format!(
                    "export function decode{name}(value: string): {name} {{"
                )),
                "the runs surface does not refuse an undefined {name}"
            );
        }

        let order: Vec<String> = RunState::ALL
            .iter()
            .map(|state| format!("\"{}\"", state.as_str()))
            .collect();
        assert!(
            generated.contains(&format!(
                "export const RunState_WIRE_ORDER: readonly RunState[] = [{}];",
                order.join(", ")
            )),
            "the generated wire order is not RunState::ALL, so a state filter would encode \
             bytes Rust does not produce"
        );
        assert_ne!(
            {
                let mut sorted = order.clone();
                sorted.sort();
                sorted
            },
            order,
            "this check is only worth making while the two orders differ"
        );
    }

    /// The bounds in the output are the Rust constants, and they are applied.
    #[test]
    fn the_generated_runs_bounds_are_the_rust_constants() {
        let generated = generated_runs();
        for declaration in [
            format!("export const MAX_RUN_PAGE_ITEMS = {MAX_RUN_PAGE_ITEMS};"),
            format!("export const MAX_LIFECYCLE_EVENTS = {MAX_LIFECYCLE_EVENTS};"),
            format!(
                "export const MAX_RUNS_CANONICAL_BYTES = {};",
                automonique_protocol::runs_api::MAX_RUNS_CANONICAL_BYTES
            ),
            format!("export const PageSize_MAX = {MAX_RUN_PAGE_ITEMS}n;"),
            "export const PageSize_MIN = 1n;".to_owned(),
            "export const SpoolSequence_MIN = 1n;".to_owned(),
            "export const EpochMillis_MIN = 0n;".to_owned(),
            format!("export const RunCursor_MAX = {}n;", i64::MAX),
            format!("export const RUNS_PROTOCOL = \"{RUNS_PROTOCOL}\";"),
        ] {
            assert!(
                generated.contains(&declaration),
                "the runs surface does not carry the Rust bound: {declaration}"
            );
        }
        // Declaring a bound is not applying it.
        for application in [
            format!(
                "  if (typeof value !== \"bigint\" || value < 1n || value > {MAX_RUN_PAGE_ITEMS}n) throw new \
                 ValidationError(\"PageSize\", \"out_of_range\");"
            ),
            "bodyArray(fields, \"runs\", RUNS_INVALID_BODY, MAX_RUN_PAGE_ITEMS, \
             RUNS_PAGE_TOO_LARGE)"
                .to_owned(),
            "bodyArray(fields, \"lifecycle\", RUNS_INVALID_BODY, MAX_LIFECYCLE_EVENTS, \
             RUNS_LIFECYCLE_TOO_LONG)"
                .to_owned(),
        ] {
            assert!(
                generated.contains(&application),
                "the runs surface declares a bound it does not apply: {application}"
            );
        }
    }

    /// Every category the generated code refuses with is declared, and every
    /// declared category is a spelling Rust actually produces.
    ///
    /// `frame_size` is the exception and says so: no shipped transport carries
    /// this protocol, so nothing pins it. The test names that rather than
    /// pretending otherwise.
    #[test]
    fn every_refusal_category_is_declared_and_is_the_rust_spelling() {
        let surface = surface();
        let declared: BTreeMap<String, String> = surface
            .categories
            .iter()
            .map(|constant| {
                let ConstantValue::Text(value) = &constant.value else {
                    panic!("{} is a refusal category, which is text", constant.name)
                };
                (constant.name.clone(), value.clone())
            })
            .collect();

        let mut referenced = vec![
            surface.invalid_body_category.clone(),
            surface.unknown_kind_category.clone(),
            surface.oversize_category.clone(),
            surface.field_invalid_category.clone(),
            surface.field_grammar_category.clone(),
        ];
        referenced.extend(referenced_categories(&surface));
        for name in &referenced {
            assert!(
                declared.contains_key(name),
                "the runs surface refuses with {name}, which it does not declare"
            );
        }

        let generated = generated_runs();
        for (name, expected) in [
            ("RUNS_INVALID_BODY", RunsApiError::InvalidBody.category()),
            ("RUNS_UNKNOWN_KIND", RunsApiError::UnknownKind.category()),
            (
                "RUNS_PAGE_TOO_LARGE",
                RunsApiError::PageTooLarge {
                    max_items: 0,
                    actual_items: 0,
                }
                .category(),
            ),
            (
                "RUNS_UNWRITTEN_ROW",
                RunsApiError::UnwrittenRow { field: "x" }.category(),
            ),
            (
                "RUNS_UNKNOWN_ENUM_VALUE",
                RunsApiError::Codec(automonique_protocol::codec::CodecError::UnknownEnumValue {
                    field: "state",
                })
                .category(),
            ),
            (
                "RUNS_FIELD_INVALID",
                RunsApiError::Codec(automonique_protocol::codec::CodecError::Field {
                    field: "request_id",
                    error: ValueError::Empty,
                })
                .category(),
            ),
        ] {
            assert_eq!(
                declared.get(name).map(String::as_str),
                Some(expected),
                "{name} is not the category Rust reports"
            );
            assert!(
                generated.contains(&format!("export const {name} = \"{expected}\";")),
                "the generated file does not carry {name} as {expected}"
            );
        }
        assert_eq!(
            declared.get(&surface.oversize_category).map(String::as_str),
            Some("frame_size"),
            "the oversize category is the spelling a transport would report; no shipped \
             transport carries this protocol yet, so nothing pins it"
        );
    }

    /// The SDK has no transport, and the generated file says so.
    #[test]
    fn the_generated_surface_says_the_framing_is_excluded() {
        let generated = generated_runs();
        for statement in [
            "The length-delimited framing this protocol travels under is not applied",
            "This package has no transport.",
            "The payload is the framed transport's payload, without its length prefix.",
        ] {
            assert!(
                generated.contains(statement),
                "the generated runs surface does not state where framing lives: {statement}"
            );
        }
    }

    /// The package typecheck actually reads the new files.
    ///
    /// `the_package_typechecks_with_the_generated_files` runs `tsc -p`, which
    /// takes its file set from `tsconfig.json`. A file outside the `include`
    /// globs would be generated, committed and never typechecked, and the suite
    /// would stay green. `--listFiles` is what turns "the package typechecks"
    /// into "the package typechecks *these files*".
    #[test]
    fn the_typecheck_reads_the_runs_surface_and_its_runner() {
        let output = Command::new("npx")
            .arg("--offline")
            .arg("tsc")
            .arg("-p")
            .arg("./tsconfig.json")
            .arg("--listFiles")
            .current_dir(package_root())
            .output();
        let Ok(output) = output else {
            record_js_gap("tsc is unavailable; the runs surface is untypechecked");
            return;
        };
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success(),
            "the protocol package does not typecheck with the runs surface:\n{combined}"
        );
        for expected in [
            "generated/runs.ts",
            "generated/runtime.ts",
            "conformance/runs-api.ts",
        ] {
            assert!(
                combined.lines().any(|line| line.trim().ends_with(expected)),
                "tsc did not read {expected}; it is outside the tsconfig include globs, so \
                 nothing typechecks it.\n{combined}"
            );
        }
    }

    /// The heart of the wave: the generated TypeScript encodes the same bytes
    /// Rust does, decodes what Rust answers, refuses what Rust refuses, and
    /// accepts exactly the cross-field payloads it is documented not to judge.
    #[test]
    fn the_generated_typescript_agrees_with_rust_byte_for_byte() {
        let Some(runtime) = javascript_runtime() else {
            record_js_gap("no JavaScript runtime; the runs surface is unmeasured across languages");
            return;
        };
        let directory =
            std::env::temp_dir().join(format!("automonique-runs-api-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("scratch directory");
        let produced_path = directory.join("typescript-encodings.txt");

        let output = Command::new(runtime)
            .arg(runner_path())
            .arg(corpus_path())
            .arg(&produced_path)
            .current_dir(package_root())
            .output()
            .expect("the conformance runner starts");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success(),
            "the generated runs surface disagrees with the Rust corpus under {runtime}:\n\
             {combined}"
        );

        // The second direction: the runner reports the bytes it produced, and
        // they are compared here against what Rust encodes and then fed to the
        // shipped decoder.
        let reported = std::fs::read_to_string(&produced_path)
            .expect("the runner reports the payloads it produced");
        let mut produced: BTreeMap<String, Vec<u8>> = reported
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| {
                let (id, payload) = line
                    .split_once(' ')
                    .unwrap_or_else(|| panic!("a reported line is `<id> <hex>`: {line:?}"));
                (id.to_owned(), unhex(payload))
            })
            .collect();

        for case in request_cases() {
            let expected = case
                .request
                .to_message()
                .expect("the request encodes")
                .to_canonical_bytes();
            let actual = produced
                .remove(case.id)
                .unwrap_or_else(|| panic!("the runner did not report {}", case.id));
            assert_eq!(
                actual.len(),
                expected.len(),
                "{}: {runtime} produced {} canonical bytes, Rust produced {}",
                case.id,
                actual.len(),
                expected.len()
            );
            if let Some(index) = actual
                .iter()
                .zip(expected.iter())
                .position(|(left, right)| left != right)
            {
                let window = |bytes: &[u8]| {
                    String::from_utf8_lossy(
                        &bytes[index.saturating_sub(24)..(index + 24).min(bytes.len())],
                    )
                    .into_owned()
                };
                panic!(
                    "{}: the two encodings first differ at byte {index}\n  {runtime}: {}\n  \
                     rust: {}",
                    case.id,
                    window(&actual),
                    window(&expected)
                );
            }
            assert_eq!(
                RunsRequest::from_canonical_bytes(&actual).unwrap_or_else(|error| panic!(
                    "{}: Rust refuses what {runtime} produced: {error}",
                    case.id
                )),
                case.request,
                "{}: Rust decodes what {runtime} produced as a different request",
                case.id
            );
        }
        assert!(
            produced.is_empty(),
            "the runner reported payloads the corpus has no cases for: {:?}",
            produced.keys().collect::<Vec<_>>()
        );
        println!(
            "runs api surface under {runtime}: {}",
            String::from_utf8_lossy(&output.stdout).trim()
        );
    }
}

/// The `automonique.automation` control surface, measured across two languages.
///
/// The same shape as [`runs_surface`], and for the same reason: a generated
/// encoder is worth what its bytes are worth beside the encoder that owns the
/// wire. `fixtures/automation-api-v1.json` is generated from the shipped Rust
/// constructors — every canonical byte string was produced by encoding a real
/// message and re-read through `from_canonical_bytes` before it was written,
/// every refusal category was read back from the error Rust returned for that
/// exact input, and every decoded spelling came out of
/// `AutomationResponse::from_canonical_bytes` rather than out of the value this
/// file constructed.
///
/// # What this lane adds to what the Runs lane already measured
///
/// The **enablement/cause coupling**, which is the first cross-field rule the
/// generator applies rather than records as a gap — and only on the way out.
/// `conformance/automation-api.ts` proves the generated builder refuses a
/// withdrawal with no cause and a resume with one, under the two categories
/// `SetEnablement::new` answers; and `rust_only_refusals` proves the *decoder*
/// still does not hold the same relation, so the gap that remains is measured
/// rather than described.
mod automation_surface {
    use std::collections::{BTreeMap, BTreeSet};

    use automonique_protocol::automation::{AutomationActor, EnablementState};
    use automonique_protocol::automation_api::{
        AUTOMATION_PROTOCOL, AutomationApiError, AutomationContinuation, AutomationCursor,
        AutomationId, AutomationListPage, AutomationPageSize, AutomationPrompt,
        AutomationReceiptView, AutomationRecordParts, AutomationRecordView, AutomationRefusal,
        AutomationRequest, AutomationResponse, AutomationSchedule, AutomationScope,
        AutomationStateFilter, ListAutomations, MAX_AUTOMATION_API_FIELD_BYTES,
        MAX_AUTOMATION_PAGE_ITEMS, MAX_AUTOMATION_PROMPT_BYTES, MAX_AUTOMATION_SCOPE_BYTES,
        MAX_SCHEDULED_AUTOMATION_ID_BYTES, PauseReason, RegisterAutomation, SetEnablement,
    };
    use automonique_protocol::codec::{MAX_REQUEST_ID_BYTES, MajorVersion};
    use automonique_protocol::codegen::{
        AUTOMATION_MODULE, CommandSurface, ConstantValue, REGENERATE_COMMAND, generated_files,
        maintained_modules, module_file_name,
    };
    use automonique_protocol::primitives::{EpochMillis, ValueError};

    use super::command_surface::{count, hex, raw_message, request_id, text, unhex, write_pretty};
    use super::*;

    fn corpus_path() -> PathBuf {
        crate_root().join("fixtures/automation-api-v1.json")
    }

    fn runner_path() -> PathBuf {
        package_root().join("conformance/automation-api.ts")
    }

    fn regenerating() -> bool {
        std::env::var(automonique_protocol::codegen::REGENERATE_ENV)
            .is_ok_and(|value| !value.is_empty() && value != "0")
    }

    /// The command surface the generator describes for this protocol.
    fn surface() -> CommandSurface {
        maintained_modules()
            .into_iter()
            .find(|module| module.file_name == module_file_name(AUTOMATION_MODULE))
            .and_then(|module| module.command_surface)
            .expect("the automation module describes a command surface")
    }

    /// The generated TypeScript of the automation module.
    fn generated_automation() -> String {
        generated_files()
            .into_iter()
            .find(|(name, _)| *name == module_file_name(AUTOMATION_MODULE))
            .map(|(_, contents)| contents)
            .expect("the automation module is generated")
    }

    fn automation_id(value: &str) -> AutomationId {
        AutomationId::new(value).expect("a valid automation identity")
    }

    fn actor(value: &str) -> AutomationActor {
        AutomationActor::new(value).expect("a valid actor")
    }

    fn reason(value: &str) -> PauseReason {
        PauseReason::new(value).expect("a valid cause")
    }

    fn page_size(items: usize) -> AutomationPageSize {
        AutomationPageSize::new(items).expect("a page size within the bound")
    }

    fn schedule(rendered: &str) -> AutomationSchedule {
        AutomationSchedule::from_rendering(rendered).expect("a canonical schedule")
    }

    fn scope(value: &str) -> AutomationScope {
        AutomationScope::new(value).expect("a valid scope")
    }

    fn prompt(value: &str) -> AutomationPrompt {
        AutomationPrompt::new(value).expect("a valid prompt")
    }

    /// A decimal string, because the wire carries 64-bit values and a JSON
    /// reader that used a double would round the largest of them without saying
    /// so. Every counter in this corpus travels as text for that reason.
    fn number(value: u64) -> JsonValue {
        JsonValue::String(value.to_string())
    }

    /// The wire ceiling, which a decoder carrying counters in a double rounds.
    fn wire_ceiling() -> u64 {
        u64::try_from(i64::MAX).expect("the wire ceiling is positive")
    }

    /// An automation identity carrying every escape a bounded identifier can
    /// reach, a three-byte character, a surrogate pair — and a space.
    ///
    /// The space is the point of the last one: [`AutomationId`] deliberately
    /// does *not* reuse `DurableId`, whose grammar additionally forbids
    /// whitespace, because the durable registry stores any bounded control-free
    /// identifier and a wire type stricter than the table would make a stored
    /// row unreadable. A TypeScript brand that copied the wrong grammar would
    /// refuse this fixture.
    fn escaping_automation_id() -> String {
        "auto/\"nightly digest\" \\ naïve 日本語 🚀".to_owned()
    }

    fn escaping_actor() -> String {
        "ops/\"oncall\" \\ naïve 日本語 🚀".to_owned()
    }

    fn escaping_cause() -> String {
        "held: \"maintenance\" \\ withdrawn by ops/oncall — naïve 日本語 🚀".to_owned()
    }

    fn escaping_scope() -> String {
        "workspace/\"reports\" \\ naïve 日本語 🚀".to_owned()
    }

    /// A prompt is prose: it carries a newline and a tab, which no identifier
    /// on this lane may, beside every escape the identifiers reach.
    fn escaping_prompt() -> String {
        "Summarize \"last night\":\n\t- naïve 日本語 🚀 \\ done".to_owned()
    }

    /// One row's eight columns, in the shape the fixtures name them.
    ///
    /// A parameter object for the same reason [`AutomationRecordParts`] is one:
    /// two `u64` revisions and two instants sit beside one another, and a
    /// transposed pair would type-check into a fixture that measured the wrong
    /// thing.
    struct Row<'a> {
        entry_id: u64,
        automation_id: &'a str,
        revision: u64,
        enablement: EnablementState,
        actor: &'a str,
        cause: Option<&'a str>,
        created_at_ms: i64,
        updated_at_ms: i64,
        schedule: Option<&'a str>,
        scope: Option<&'a str>,
        next_fire_at_ms: Option<i64>,
        last_fired_at_ms: Option<i64>,
    }

    fn record(row: Row<'_>) -> AutomationRecordView {
        AutomationRecordView::new(AutomationRecordParts {
            entry_id: row.entry_id,
            automation_id: automation_id(row.automation_id),
            revision: row.revision,
            enablement: row.enablement,
            actor: actor(row.actor),
            cause: row.cause.map(reason),
            created_at: EpochMillis::from_millis(row.created_at_ms),
            updated_at: EpochMillis::from_millis(row.updated_at_ms),
            schedule: row.schedule.map(schedule),
            scope: row.scope.map(scope),
            next_fire_at: row.next_fire_at_ms.map(EpochMillis::from_millis),
            last_fired_at: row.last_fired_at_ms.map(EpochMillis::from_millis),
        })
        .expect("a well-formed automation row")
    }

    // -----------------------------------------------------------------------
    // Requests
    // -----------------------------------------------------------------------

    struct RequestCase {
        id: &'static str,
        note: &'static str,
        request: AutomationRequest,
        /// Builder parameters, in the shape the runner reads for this kind.
        params: JsonValue,
    }

    fn request_cases() -> Vec<RequestCase> {
        let maximal_request_id = format!("req-{}", "a".repeat(MAX_REQUEST_ID_BYTES - 4));
        // Every character escapes to two bytes, which is the worst case the
        // protocol's own frame arithmetic budgets for. A registration's
        // identity is bounded by the occurrence key it derives, so its maximum
        // is the narrower one.
        let maximal_automation_id = "\"".repeat(MAX_SCHEDULED_AUTOMATION_ID_BYTES);
        let maximal_scope = "\"".repeat(MAX_AUTOMATION_SCOPE_BYTES);
        let maximal_prompt = "\"".repeat(MAX_AUTOMATION_PROMPT_BYTES);

        vec![
            RequestCase {
                id: "list-automations-maximal",
                note: "every bound at once: all three states, a cursor at the wire's integer \
                       ceiling, the largest page this protocol serves, and a correlation \
                       identifier at MAX_REQUEST_ID_BYTES. The states are recorded shuffled — \
                       the wire order is the enum's declaration order, which is neither the \
                       caller's nor alphabetical",
                request: AutomationRequest::ListAutomations {
                    request_id: request_id(&maximal_request_id),
                    query: ListAutomations::new(
                        AutomationStateFilter::only(EnablementState::ALL)
                            .expect("every state is a valid set"),
                        AutomationCursor::new(wire_ceiling()),
                        page_size(MAX_AUTOMATION_PAGE_ITEMS),
                    ),
                },
                params: JsonValue::Object(vec![
                    (
                        "page_size".to_owned(),
                        number(MAX_AUTOMATION_PAGE_ITEMS as u64),
                    ),
                    ("since".to_owned(), number(wire_ceiling())),
                    (
                        "states".to_owned(),
                        JsonValue::Array(
                            ["paused", "archived", "enabled"]
                                .into_iter()
                                .map(text)
                                .collect(),
                        ),
                    ),
                ]),
            },
            RequestCase {
                id: "list-automations-unfiltered",
                note: "no filter and the beginning of the listing: an explicit null, which is a \
                       different wire fact from a filter naming every state, and a cursor of \
                       zero, which is a position rather than the absence of one",
                request: AutomationRequest::ListAutomations {
                    request_id: request_id("req-list-1"),
                    query: ListAutomations::new(
                        AutomationStateFilter::any(),
                        AutomationCursor::START,
                        page_size(1),
                    ),
                },
                params: JsonValue::Object(vec![
                    ("page_size".to_owned(), number(1)),
                    ("since".to_owned(), number(0)),
                    ("states".to_owned(), JsonValue::Null),
                ]),
            },
            RequestCase {
                id: "list-automations-withdrawn-only",
                note: "a two-state filter naming exactly the two states that carry a cause",
                request: AutomationRequest::ListAutomations {
                    request_id: request_id("req-list-2"),
                    query: ListAutomations::new(
                        AutomationStateFilter::only([
                            EnablementState::Archived,
                            EnablementState::Paused,
                        ])
                        .expect("a two-state filter"),
                        AutomationCursor::new(7),
                        page_size(4),
                    ),
                },
                params: JsonValue::Object(vec![
                    ("page_size".to_owned(), number(4)),
                    ("since".to_owned(), number(7)),
                    (
                        "states".to_owned(),
                        JsonValue::Array(vec![text("archived"), text("paused")]),
                    ),
                ]),
            },
            RequestCase {
                id: "set-enablement-pause-escaping",
                note: "a withdrawal at the wire's ceiling revision, with an actor and a cause \
                       carrying every escape a bounded field can reach, a three-byte character \
                       and a surrogate pair; the automation identity carries a space, which this \
                       lane's grammar admits and DurableId's does not",
                request: AutomationRequest::SetEnablement {
                    request_id: request_id("req-set-1"),
                    transition: SetEnablement::new(
                        automation_id(&escaping_automation_id()),
                        wire_ceiling(),
                        EnablementState::Paused,
                        actor(&escaping_actor()),
                        Some(reason(&escaping_cause())),
                    )
                    .expect("a withdrawal that states its cause"),
                },
                params: JsonValue::Object(vec![
                    ("actor".to_owned(), text(&escaping_actor())),
                    ("automation_id".to_owned(), text(&escaping_automation_id())),
                    ("cause".to_owned(), text(&escaping_cause())),
                    ("expected_revision".to_owned(), number(wire_ceiling())),
                    ("target".to_owned(), text("paused")),
                ]),
            },
            RequestCase {
                id: "set-enablement-resume",
                note: "a resume states no cause, and the null is explicit: the absence of a \
                       reason is a fact this wire carries rather than a key it omits",
                request: AutomationRequest::SetEnablement {
                    request_id: request_id("req-set-2"),
                    transition: SetEnablement::new(
                        automation_id("auto-nightly"),
                        2,
                        EnablementState::Enabled,
                        actor("ops/oncall"),
                        None,
                    )
                    .expect("a resume admits no cause"),
                },
                params: JsonValue::Object(vec![
                    ("actor".to_owned(), text("ops/oncall")),
                    ("automation_id".to_owned(), text("auto-nightly")),
                    ("cause".to_owned(), JsonValue::Null),
                    ("expected_revision".to_owned(), number(2)),
                    ("target".to_owned(), text("enabled")),
                ]),
            },
            RequestCase {
                id: "set-enablement-archive",
                note: "the terminal state, which also owes a cause; nothing transitions out of it",
                request: AutomationRequest::SetEnablement {
                    request_id: request_id("req-set-3"),
                    transition: SetEnablement::new(
                        automation_id("auto-nightly"),
                        3,
                        EnablementState::Archived,
                        actor("ops/oncall"),
                        Some(reason("superseded by auto-nightly-v2")),
                    )
                    .expect("an archival that states its cause"),
                },
                params: JsonValue::Object(vec![
                    ("actor".to_owned(), text("ops/oncall")),
                    ("automation_id".to_owned(), text("auto-nightly")),
                    ("cause".to_owned(), text("superseded by auto-nightly-v2")),
                    ("expected_revision".to_owned(), number(3)),
                    ("target".to_owned(), text("archived")),
                ]),
            },
            RequestCase {
                id: "register-automation-maximal",
                note: "every job bound at once: an identity at \
                       MAX_SCHEDULED_AUTOMATION_ID_BYTES, a scope at MAX_AUTOMATION_SCOPE_BYTES \
                       and a prompt at MAX_AUTOMATION_PROMPT_BYTES, each character of each \
                       escaping to two bytes, under an interval at the wire's integer ceiling",
                request: AutomationRequest::RegisterAutomation {
                    request_id: request_id("req-register-1"),
                    registration: RegisterAutomation::new(
                        automation_id(&maximal_automation_id),
                        actor(&escaping_actor()),
                        schedule(&format!("every@{}", i64::MAX)),
                        scope(&maximal_scope),
                        prompt(&maximal_prompt),
                    )
                    .expect("a maximal registration"),
                },
                params: JsonValue::Object(vec![
                    ("actor".to_owned(), text(&escaping_actor())),
                    ("automation_id".to_owned(), text(&maximal_automation_id)),
                    ("prompt".to_owned(), text(&maximal_prompt)),
                    ("schedule".to_owned(), text(&format!("every@{}", i64::MAX))),
                    ("scope".to_owned(), text(&maximal_scope)),
                ]),
            },
            RequestCase {
                id: "register-automation-once-escaping",
                note: "a one-shot at the epoch itself — `once@0`, the one rendering whose \
                       instant is a single zero — with a prompt carrying a newline and a tab, \
                       which a prompt may and no identifier on this lane may",
                request: AutomationRequest::RegisterAutomation {
                    request_id: request_id("req-register-2"),
                    registration: RegisterAutomation::new(
                        automation_id(&escaping_automation_id()),
                        actor("ops/oncall"),
                        schedule("once@0"),
                        scope(&escaping_scope()),
                        prompt(&escaping_prompt()),
                    )
                    .expect("a one-shot registration"),
                },
                params: JsonValue::Object(vec![
                    ("actor".to_owned(), text("ops/oncall")),
                    ("automation_id".to_owned(), text(&escaping_automation_id())),
                    ("prompt".to_owned(), text(&escaping_prompt())),
                    ("schedule".to_owned(), text("once@0")),
                    ("scope".to_owned(), text(&escaping_scope())),
                ]),
            },
            RequestCase {
                id: "automation-detail-escaping",
                note: "one automation read by an identity carrying every reachable escape",
                request: AutomationRequest::AutomationDetail {
                    request_id: request_id("req-detail-1"),
                    automation_id: automation_id(&escaping_automation_id()),
                },
                params: JsonValue::Object(vec![(
                    "automation_id".to_owned(),
                    text(&escaping_automation_id()),
                )]),
            },
        ]
    }

    fn request_entry(case: &RequestCase) -> JsonValue {
        let message = case.request.to_message().expect("the request encodes");
        let canonical = message.to_canonical_bytes();
        // What the corpus records is checked against the shipped decoder before
        // it is written: a fixture Rust would not itself admit proves nothing.
        assert_eq!(
            AutomationRequest::from_canonical_bytes(&canonical)
                .expect("Rust admits its own encoding"),
            case.request,
            "{}: the Rust decoder does not admit the Rust encoding",
            case.id
        );
        assert!(
            canonical.len() <= automonique_protocol::automation_api::MAX_AUTOMATION_CANONICAL_BYTES,
            "{}: the encoding does not fit one automation frame",
            case.id
        );
        JsonValue::Object(vec![
            ("canonical_bytes".to_owned(), count(canonical.len())),
            ("canonical_hex".to_owned(), text(&hex(&canonical))),
            ("id".to_owned(), text(case.id)),
            ("kind".to_owned(), text(message.envelope().kind().as_str())),
            ("note".to_owned(), text(case.note)),
            ("params".to_owned(), case.params.clone()),
            (
                "request_id".to_owned(),
                text(message.envelope().request_id().as_str()),
            ),
        ])
    }

    // -----------------------------------------------------------------------
    // Responses
    // -----------------------------------------------------------------------

    struct ResponseCase {
        id: &'static str,
        note: &'static str,
        response: AutomationResponse,
    }

    /// A listing answer built through the enforcement path rather than around
    /// it.
    ///
    /// `AutomationResponse::listing` is what refuses a page longer than the
    /// query asked for or carrying a row its filter excludes, so a corpus entry
    /// that constructed the variant directly would record bytes no daemon could
    /// have produced.
    fn listing(id: &str, query: &ListAutomations, page: AutomationListPage) -> AutomationResponse {
        AutomationResponse::listing(request_id(id), query, page)
            .expect("the page answers the query it was built for")
    }

    fn response_cases() -> Vec<ResponseCase> {
        let unfiltered = ListAutomations::new(
            AutomationStateFilter::any(),
            AutomationCursor::START,
            page_size(MAX_AUTOMATION_PAGE_ITEMS),
        );

        vec![
            ResponseCase {
                id: "accepted-registration",
                note: "what a registration establishes: revision one, enabled, with no cause. \
                       `accepted` says the row is recorded, never that anything will run it",
                response: AutomationResponse::Accepted {
                    request_id: request_id("req-register-1"),
                    receipt: AutomationReceiptView::new(
                        1,
                        automation_id("auto-nightly"),
                        EnablementState::Enabled,
                        1,
                        EpochMillis::from_millis(1_700_000_000_000),
                    )
                    .expect("a well-formed receipt"),
                },
            },
            ResponseCase {
                id: "accepted-pause-at-ceiling",
                note: "a withdrawal landing at the wire's ceiling revision and instant, both of \
                       which a decoder carrying counters in a double would round to an even \
                       neighbour",
                response: AutomationResponse::Accepted {
                    request_id: request_id("req-set-1"),
                    receipt: AutomationReceiptView::new(
                        wire_ceiling() - 1,
                        automation_id(&escaping_automation_id()),
                        EnablementState::Paused,
                        wire_ceiling(),
                        EpochMillis::from_millis(i64::MAX),
                    )
                    .expect("a well-formed receipt"),
                },
            },
            ResponseCase {
                id: "automation-list-page-more",
                note: "a page whose last row and whose continuation cursor are both at the \
                       wire's ceiling, carrying a resumed automation beside a withdrawn one so \
                       that a null cause and a stated one travel in the same array — and a \
                       fixed interval with both executions beside a fired one-shot whose next \
                       instant is null and whose last is at the ceiling",
                response: listing(
                    "automation-list-page-more",
                    &unfiltered,
                    AutomationListPage::new(
                        vec![
                            record(Row {
                                entry_id: 1,
                                automation_id: "auto-first",
                                revision: 3,
                                enablement: EnablementState::Enabled,
                                actor: "ops/oncall",
                                cause: None,
                                created_at_ms: 1_700_000_000_000,
                                updated_at_ms: 1_700_000_000_500,
                                schedule: Some("every@60000"),
                                scope: Some("workspace/reports"),
                                next_fire_at_ms: Some(1_700_000_120_000),
                                last_fired_at_ms: Some(1_700_000_060_000),
                            }),
                            record(Row {
                                entry_id: wire_ceiling() - 1,
                                automation_id: &escaping_automation_id(),
                                revision: 2,
                                enablement: EnablementState::Archived,
                                actor: &escaping_actor(),
                                cause: Some(&escaping_cause()),
                                created_at_ms: 0,
                                updated_at_ms: i64::MAX,
                                schedule: Some("once@0"),
                                scope: Some(&escaping_scope()),
                                next_fire_at_ms: None,
                                last_fired_at_ms: Some(i64::MAX),
                            }),
                        ],
                        AutomationContinuation::More(AutomationCursor::new(wire_ceiling())),
                    )
                    .expect("a well-formed page"),
                ),
            },
            ResponseCase {
                id: "automation-list-page-empty-more",
                note: "an empty page that still reports more: an enablement filter can exclude \
                       every row in one scanned window while rows remain behind it, so a client \
                       that inferred `done` from a short page would stop early",
                response: listing(
                    "automation-list-page-empty-more",
                    &unfiltered,
                    AutomationListPage::new(
                        Vec::new(),
                        AutomationContinuation::More(AutomationCursor::new(42)),
                    )
                    .expect("an empty page may continue"),
                ),
            },
            ResponseCase {
                id: "automation-list-page-complete",
                note: "the end of the registry: `more` false and an explicit null cursor, \
                       carrying a row registered before jobs existed — every job column null \
                       together, which is the one shape the nulls may take",
                response: listing(
                    "automation-list-page-complete",
                    &unfiltered,
                    AutomationListPage::new(
                        vec![record(Row {
                            entry_id: 9,
                            automation_id: "auto-only",
                            revision: 2,
                            enablement: EnablementState::Paused,
                            actor: "ops/oncall",
                            cause: Some("held for the migration"),
                            created_at_ms: 1_700_000_000_000,
                            updated_at_ms: 1_700_000_009_000,
                            schedule: None,
                            scope: None,
                            next_fire_at_ms: None,
                            last_fired_at_ms: None,
                        })],
                        AutomationContinuation::Complete,
                    )
                    .expect("a well-formed page"),
                ),
            },
            ResponseCase {
                id: "automation-detail-paused",
                note: "one automation in full, withdrawn: the actor is whoever withdrew it and \
                       the cause is why, which is the whole of the history this registry keeps. \
                       The prompt travels here and only here, with every escape a prompt can \
                       carry",
                response: AutomationResponse::detail(
                    request_id("req-detail-1"),
                    record(Row {
                        entry_id: 4,
                        automation_id: &escaping_automation_id(),
                        revision: 2,
                        enablement: EnablementState::Paused,
                        actor: &escaping_actor(),
                        cause: Some(&escaping_cause()),
                        created_at_ms: 1_700_000_000_000,
                        updated_at_ms: 1_700_000_001_000,
                        schedule: Some("every@3600000"),
                        scope: Some(&escaping_scope()),
                        next_fire_at_ms: Some(1_700_000_000_000),
                        last_fired_at_ms: None,
                    }),
                    Some(prompt(&escaping_prompt())),
                )
                .expect("a coherent detail"),
            },
            ResponseCase {
                id: "automation-detail-never-paused",
                note: "a never-paused automation at revision one: the actor is the registrant \
                       rather than a resumer, and the cause is null. Registered before jobs \
                       existed, so the job columns and the prompt are null together",
                response: AutomationResponse::detail(
                    request_id("req-detail-2"),
                    record(Row {
                        entry_id: 5,
                        automation_id: "auto-fresh",
                        revision: 1,
                        enablement: EnablementState::Enabled,
                        actor: "ops/oncall",
                        cause: None,
                        created_at_ms: 1_700_000_000_000,
                        updated_at_ms: 1_700_000_000_000,
                        schedule: None,
                        scope: None,
                        next_fire_at_ms: None,
                        last_fired_at_ms: None,
                    }),
                    None,
                )
                .expect("a coherent detail"),
            },
            ResponseCase {
                id: "revision-conflict",
                note: "a stale fencing revision, which is not a rejection: the caller retries \
                       against the durable revision this carries",
                response: AutomationResponse::conflict(request_id("req-set-2"), 3, 7)
                    .expect("two revisions that disagree"),
            },
            ResponseCase {
                id: "refused-already-registered",
                note: "the identity is already registered, whatever state its row is in",
                response: AutomationResponse::Refused {
                    request_id: request_id("req-register-1"),
                    refusal: AutomationRefusal::AlreadyRegistered,
                },
            },
        ]
    }

    /// How one decoded response is spelled in the corpus.
    ///
    /// Built from the value the *Rust decoder* recovered, and flattened with
    /// dotted keys so a nested page compares field by field rather than as one
    /// opaque blob.
    fn decoded_spelling(response: &AutomationResponse) -> JsonValue {
        let mut fields = vec![(
            "request_id".to_owned(),
            text(response.request_id().as_str()),
        )];
        let record_fields =
            |prefix: &str, value: &AutomationRecordView| -> Vec<(String, JsonValue)> {
                [
                    ("actor", text(value.actor().as_str())),
                    ("automation_id", text(value.automation_id().as_str())),
                    (
                        "cause",
                        value
                            .cause()
                            .map_or_else(|| text("null"), |cause| text(cause.as_str())),
                    ),
                    (
                        "created_at_ms",
                        JsonValue::String(value.created_at().as_millis().to_string()),
                    ),
                    ("enablement", text(value.enablement().as_str())),
                    ("entry_id", number(value.entry_id())),
                    (
                        "last_fired_at_ms",
                        value.last_fired_at().map_or_else(
                            || text("null"),
                            |instant| JsonValue::String(instant.as_millis().to_string()),
                        ),
                    ),
                    (
                        "next_fire_at_ms",
                        value.next_fire_at().map_or_else(
                            || text("null"),
                            |instant| JsonValue::String(instant.as_millis().to_string()),
                        ),
                    ),
                    ("revision", number(value.revision())),
                    (
                        "schedule",
                        value
                            .schedule()
                            .map_or_else(|| text("null"), |schedule| text(&schedule.render())),
                    ),
                    (
                        "scope",
                        value
                            .scope()
                            .map_or_else(|| text("null"), |scope| text(scope.as_str())),
                    ),
                    (
                        "updated_at_ms",
                        JsonValue::String(value.updated_at().as_millis().to_string()),
                    ),
                ]
                .into_iter()
                .map(|(name, spelled)| (format!("{prefix}{name}"), spelled))
                .collect()
            };
        match response {
            AutomationResponse::Accepted { receipt, .. } => {
                fields.push((
                    "automation_id".to_owned(),
                    text(receipt.automation_id().as_str()),
                ));
                fields.push(("enablement".to_owned(), text(receipt.enablement().as_str())));
                fields.push(("entry_id".to_owned(), number(receipt.entry_id())));
                fields.push(("revision".to_owned(), number(receipt.revision())));
                fields.push((
                    "updated_at_ms".to_owned(),
                    JsonValue::String(receipt.updated_at().as_millis().to_string()),
                ));
            }
            AutomationResponse::AutomationList { page, .. } => {
                fields.push((
                    "automations.len".to_owned(),
                    number(page.entries().len() as u64),
                ));
                fields.push((
                    "more".to_owned(),
                    text(&page.continuation().has_more().to_string()),
                ));
                fields.push((
                    "next_cursor".to_owned(),
                    match page.continuation().cursor() {
                        Some(cursor) => number(cursor.position()),
                        None => text("null"),
                    },
                ));
                for (index, carried) in page.entries().iter().enumerate() {
                    fields.extend(record_fields(&format!("automations.{index}."), carried));
                }
            }
            AutomationResponse::AutomationDetail { record, prompt, .. } => {
                fields.extend(record_fields("", record));
                fields.push((
                    "prompt".to_owned(),
                    prompt
                        .as_ref()
                        .map_or_else(|| text("null"), |prompt| text(prompt.as_str())),
                ));
            }
            AutomationResponse::Conflict {
                expected_revision,
                durable_revision,
                ..
            } => {
                fields.push(("durable_revision".to_owned(), number(*durable_revision)));
                fields.push(("expected_revision".to_owned(), number(*expected_revision)));
            }
            AutomationResponse::Refused { refusal, .. } => {
                fields.push(("refusal".to_owned(), text(refusal.as_str())));
            }
        }
        JsonValue::Object(fields)
    }

    fn response_entry(case: &ResponseCase) -> JsonValue {
        let message = case.response.to_message().expect("the response encodes");
        let canonical = message.to_canonical_bytes();
        let decoded = AutomationResponse::from_canonical_bytes(&canonical)
            .expect("Rust admits its own encoding");
        assert_eq!(
            decoded, case.response,
            "{}: the Rust decoder does not recover what it encoded",
            case.id
        );
        JsonValue::Object(vec![
            ("canonical_hex".to_owned(), text(&hex(&canonical))),
            ("decoded".to_owned(), decoded_spelling(&decoded)),
            ("id".to_owned(), text(case.id)),
            ("kind".to_owned(), text(message.envelope().kind().as_str())),
            ("note".to_owned(), text(case.note)),
            ("outcome".to_owned(), text(decoded.outcome().as_str())),
        ])
    }

    // -----------------------------------------------------------------------
    // Bodies, for the payloads no constructor would produce
    // -----------------------------------------------------------------------

    /// A well-formed record body, as a starting point for one that is not.
    ///
    /// Scheduled, so that a job column can be overridden on its own to make a
    /// body incoherent, and so that the instants have a schedule to belong to.
    fn record_body(overrides: &[(&str, JsonValue)]) -> JsonValue {
        let mut entries: Vec<(String, JsonValue)> = vec![
            ("actor".to_owned(), text("ops/oncall")),
            ("automation_id".to_owned(), text("auto-nightly")),
            ("cause".to_owned(), JsonValue::Null),
            (
                "created_at_ms".to_owned(),
                JsonValue::Integer(1_700_000_000_000),
            ),
            ("enablement".to_owned(), text("enabled")),
            ("entry_id".to_owned(), JsonValue::Integer(1)),
            ("last_fired_at_ms".to_owned(), JsonValue::Null),
            (
                "next_fire_at_ms".to_owned(),
                JsonValue::Integer(1_700_000_060_000),
            ),
            ("revision".to_owned(), JsonValue::Integer(1)),
            ("schedule".to_owned(), text("every@60000")),
            ("scope".to_owned(), text("workspace/reports")),
            (
                "updated_at_ms".to_owned(),
                JsonValue::Integer(1_700_000_000_000),
            ),
        ];
        for (name, value) in overrides {
            let slot = entries
                .iter_mut()
                .find(|(existing, _)| existing == name)
                .unwrap_or_else(|| panic!("{name} is not a record field"));
            slot.1 = value.clone();
        }
        JsonValue::Object(entries)
    }

    /// A detail body: a record body with its prompt member spliced in.
    fn detail_body(overrides: &[(&str, JsonValue)], prompt: JsonValue) -> JsonValue {
        let JsonValue::Object(mut entries) = record_body(overrides) else {
            panic!("a record body is an object")
        };
        let position = entries
            .iter()
            .position(|(name, _)| name.as_str() > "prompt")
            .unwrap_or(entries.len());
        entries.insert(position, ("prompt".to_owned(), prompt));
        JsonValue::Object(entries)
    }

    /// A well-formed receipt body.
    fn receipt_body(overrides: &[(&str, JsonValue)]) -> JsonValue {
        let mut entries: Vec<(String, JsonValue)> = vec![
            ("automation_id".to_owned(), text("auto-nightly")),
            ("enablement".to_owned(), text("enabled")),
            ("entry_id".to_owned(), JsonValue::Integer(1)),
            ("revision".to_owned(), JsonValue::Integer(1)),
            (
                "updated_at_ms".to_owned(),
                JsonValue::Integer(1_700_000_000_000),
            ),
        ];
        for (name, value) in overrides {
            let slot = entries
                .iter_mut()
                .find(|(existing, _)| existing == name)
                .unwrap_or_else(|| panic!("{name} is not a receipt field"));
            slot.1 = value.clone();
        }
        JsonValue::Object(entries)
    }

    /// A page body carrying the given records and continuation.
    fn page_body(automations: Vec<JsonValue>, more: bool, next_cursor: JsonValue) -> JsonValue {
        JsonValue::Object(vec![
            ("automations".to_owned(), JsonValue::Array(automations)),
            ("more".to_owned(), JsonValue::Bool(more)),
            ("next_cursor".to_owned(), next_cursor),
        ])
    }

    fn conflict_body(expected: i64, durable: i64) -> JsonValue {
        JsonValue::Object(vec![
            ("durable_revision".to_owned(), JsonValue::Integer(durable)),
            ("expected_revision".to_owned(), JsonValue::Integer(expected)),
        ])
    }

    fn automation_message(kind: &str, id: &str, body: JsonValue) -> Vec<u8> {
        raw_message(AUTOMATION_PROTOCOL, 1, kind, id, body)
    }

    /// One record wrapped in the smallest page that can carry it.
    fn one_record_page(record: JsonValue) -> Vec<u8> {
        automation_message(
            "automation_list_result",
            "req-list-1",
            page_body(vec![record], false, JsonValue::Null),
        )
    }

    // -----------------------------------------------------------------------
    // Refusals both implementations make
    // -----------------------------------------------------------------------

    struct DecodeRefusal {
        id: &'static str,
        note: &'static str,
        payload: Vec<u8>,
    }

    fn decode_refusals() -> Vec<DecodeRefusal> {
        // The page bound is judged before any item is read, in Rust and in the
        // generated TypeScript alike, so the over-bound payload carries integers
        // rather than bodies: what is wrong with it is its length.
        let filler: Vec<JsonValue> = (0..=MAX_AUTOMATION_PAGE_ITEMS)
            .map(|index| JsonValue::Integer(index as i64))
            .collect();
        let long_identifier = "a".repeat(MAX_AUTOMATION_API_FIELD_BYTES + 1);

        vec![
            DecodeRefusal {
                id: "enablement-undefined-spelling",
                note: "an enablement this build does not define fails closed rather than \
                       decoding to a default a client would act on — and the safe-looking guess \
                       for an unnameable state is the wrong one",
                payload: one_record_page(record_body(&[("enablement", text("disabled"))])),
            },
            DecodeRefusal {
                id: "refusal-undefined-spelling",
                note: "a refusal word outside the eight this build carries; the vocabulary is \
                       closed on both sides of the wire",
                payload: automation_message(
                    "refused",
                    "req-register-1",
                    JsonValue::Object(vec![("refusal".to_owned(), text("not_authorized"))]),
                ),
            },
            DecodeRefusal {
                id: "entry-id-zero",
                note: "a durable identity starts at one; zero names a row no writer produced",
                payload: one_record_page(record_body(&[("entry_id", JsonValue::Integer(0))])),
            },
            DecodeRefusal {
                id: "entry-id-negative",
                note: "a negative identity is a malformed body rather than an unwritten row: the \
                       decoder converts before it judges the domain, and the two categories differ",
                payload: one_record_page(record_body(&[("entry_id", JsonValue::Integer(-1))])),
            },
            DecodeRefusal {
                id: "revision-zero",
                note: "registration writes revision one and every accepted transition writes one \
                       higher, so zero is a row no writer produced — a different statement from \
                       an unwritten row identity, under a different category",
                payload: one_record_page(record_body(&[("revision", JsonValue::Integer(0))])),
            },
            DecodeRefusal {
                id: "receipt-revision-zero",
                note: "the same rule on a receipt, which is the answer a write returns",
                payload: automation_message(
                    "automation_accepted",
                    "req-set-1",
                    receipt_body(&[("revision", JsonValue::Integer(0))]),
                ),
            },
            DecodeRefusal {
                id: "created-at-before-epoch",
                note: "a registration instant the store's own `created_at_ms >= 0` constraint \
                       cannot hold",
                payload: one_record_page(record_body(&[("created_at_ms", JsonValue::Integer(-1))])),
            },
            DecodeRefusal {
                id: "receipt-updated-at-before-epoch",
                note: "the same constraint on the instant a write reports",
                payload: automation_message(
                    "automation_accepted",
                    "req-set-1",
                    receipt_body(&[("updated_at_ms", JsonValue::Integer(-1))]),
                ),
            },
            DecodeRefusal {
                id: "cause-empty-string",
                note: "an empty cause is refused rather than read as `no reason given`: a \
                       withdrawal an operator cannot safely resume from is the one this product \
                       does not offer a spelling for. The absence of a cause is null",
                payload: one_record_page(record_body(&[
                    ("enablement", text("paused")),
                    ("revision", JsonValue::Integer(2)),
                    ("cause", text("")),
                ])),
            },
            DecodeRefusal {
                id: "cause-not-a-string",
                note: "the field is a string or a null and nothing else; a number is a malformed \
                       body rather than a cause",
                payload: one_record_page(record_body(&[("cause", JsonValue::Integer(5))])),
            },
            DecodeRefusal {
                id: "automation-id-over-bound",
                note: "one byte over the identity bound, measured in UTF-8 bytes rather than in \
                       the UTF-16 code units a JavaScript `length` counts",
                payload: one_record_page(record_body(&[("automation_id", text(&long_identifier))])),
            },
            DecodeRefusal {
                id: "actor-empty",
                note: "an empty actor names nobody, and this lane records who asked",
                payload: one_record_page(record_body(&[("actor", text(""))])),
            },
            DecodeRefusal {
                id: "schedule-not-canonical",
                note: "a schedule that is prose rather than a canonical rendering: the wire \
                       carries `once@<ms>` and `every@<ms>` and nothing an operator typed",
                payload: one_record_page(record_body(&[("schedule", text("daily"))])),
            },
            DecodeRefusal {
                id: "schedule-interval-zero",
                note: "`every@0` would fire without advancing; the interval is strictly positive \
                       on both sides of the wire",
                payload: one_record_page(record_body(&[("schedule", text("every@0"))])),
            },
            DecodeRefusal {
                id: "scope-empty",
                note: "an empty scope serializes under nothing; the absence of a scope is null, \
                       and only beside a null schedule",
                payload: one_record_page(record_body(&[("scope", text(""))])),
            },
            DecodeRefusal {
                id: "next-fire-at-before-epoch",
                note: "an instant the registry's `next_fire_at_ms >= 0` constraint cannot hold",
                payload: one_record_page(record_body(&[(
                    "next_fire_at_ms",
                    JsonValue::Integer(-1),
                )])),
            },
            DecodeRefusal {
                id: "last-fired-at-not-an-integer",
                note: "an execution instant is an integer or a null and nothing else",
                payload: one_record_page(record_body(&[("last_fired_at_ms", text("never"))])),
            },
            DecodeRefusal {
                id: "detail-prompt-empty",
                note: "an empty prompt is a job that submits nothing; the absence of a prompt is \
                       null, and only beside a null schedule",
                payload: automation_message(
                    "automation_detail_result",
                    "req-detail-1",
                    detail_body(&[], text("")),
                ),
            },
            DecodeRefusal {
                id: "detail-prompt-not-a-string",
                note: "the prompt member is a string or a null and nothing else",
                payload: automation_message(
                    "automation_detail_result",
                    "req-detail-1",
                    detail_body(&[], JsonValue::Integer(5)),
                ),
            },
            DecodeRefusal {
                id: "detail-without-prompt-member",
                note: "a detail body is a record plus its prompt; a record on its own is a body \
                       of the wrong shape, however well-formed the record",
                payload: automation_message(
                    "automation_detail_result",
                    "req-detail-1",
                    record_body(&[]),
                ),
            },
            DecodeRefusal {
                id: "page-over-bound",
                note: "one row past MAX_AUTOMATION_PAGE_ITEMS. The length is judged before any \
                       item is read, so what these items are does not matter and the refusal \
                       names the length",
                payload: automation_message(
                    "automation_list_result",
                    "req-list-1",
                    page_body(filler, false, JsonValue::Null),
                ),
            },
            DecodeRefusal {
                id: "next-cursor-negative",
                note: "a cursor below the beginning of the listing",
                payload: automation_message(
                    "automation_list_result",
                    "req-list-1",
                    page_body(Vec::new(), true, JsonValue::Integer(-1)),
                ),
            },
            DecodeRefusal {
                id: "more-not-a-boolean",
                note: "the wire carries true or false for a continuation and nothing else",
                payload: automation_message(
                    "automation_list_result",
                    "req-list-1",
                    JsonValue::Object(vec![
                        ("automations".to_owned(), JsonValue::Array(Vec::new())),
                        ("more".to_owned(), JsonValue::Integer(1)),
                        ("next_cursor".to_owned(), JsonValue::Null),
                    ]),
                ),
            },
            DecodeRefusal {
                id: "conflict-expected-revision-zero",
                note: "a conflict about a revision no writer produced tells a caller to retry \
                       against nothing",
                payload: automation_message("revision_conflict", "req-set-1", conflict_body(0, 5)),
            },
            DecodeRefusal {
                id: "page-extra-field",
                note: "an unexpected key is refused rather than ignored",
                payload: automation_message(
                    "automation_list_result",
                    "req-list-1",
                    JsonValue::Object(vec![
                        ("automations".to_owned(), JsonValue::Array(Vec::new())),
                        ("more".to_owned(), JsonValue::Bool(false)),
                        ("next_cursor".to_owned(), JsonValue::Null),
                        ("total".to_owned(), JsonValue::Integer(1)),
                    ]),
                ),
            },
            DecodeRefusal {
                id: "record-missing-field",
                note: "a missing key is refused rather than defaulted, inside a nested body as \
                       much as at the top level",
                payload: one_record_page(JsonValue::Object(vec![
                    ("actor".to_owned(), text("ops/oncall")),
                    ("automation_id".to_owned(), text("auto-nightly")),
                    ("cause".to_owned(), JsonValue::Null),
                    ("enablement".to_owned(), text("enabled")),
                    ("entry_id".to_owned(), JsonValue::Integer(1)),
                    ("last_fired_at_ms".to_owned(), JsonValue::Null),
                    ("next_fire_at_ms".to_owned(), JsonValue::Null),
                    ("revision".to_owned(), JsonValue::Integer(1)),
                    ("schedule".to_owned(), JsonValue::Null),
                    ("scope".to_owned(), JsonValue::Null),
                    (
                        "updated_at_ms".to_owned(),
                        JsonValue::Integer(1_700_000_000_000),
                    ),
                ])),
            },
            DecodeRefusal {
                id: "page-item-carries-a-prompt",
                note: "the prompt travels on a detail read and never in a listing; a page item \
                       carrying one is a record of the wrong shape",
                payload: one_record_page(detail_body(&[], text("summarize"))),
            },
            DecodeRefusal {
                id: "unknown-kind",
                note: "a kind this protocol version does not define, which is a different answer \
                       from a kind it defines and this surface does not decode",
                payload: automation_message(
                    "automation_history_result",
                    "req-list-1",
                    page_body(Vec::new(), false, JsonValue::Null),
                ),
            },
            DecodeRefusal {
                id: "runs-protocol-message",
                note: "the Runs lane's name on this lane's decoder, refused on the name axis so \
                       each protocol's closed kind set stays closed",
                payload: raw_message(
                    "automonique.runs",
                    1,
                    "automation_list_result",
                    "req-list-1",
                    page_body(Vec::new(), false, JsonValue::Null),
                ),
            },
            DecodeRefusal {
                id: "unsupported-version",
                note: "this protocol at a major version neither side implements",
                payload: raw_message(
                    AUTOMATION_PROTOCOL,
                    2,
                    "automation_list_result",
                    "req-list-1",
                    page_body(Vec::new(), false, JsonValue::Null),
                ),
            },
            DecodeRefusal {
                id: "non-canonical-key-order",
                note: "a payload that parses but is not canonical is refused, not normalized",
                payload: br#"{"kind":"refused","body":{"refusal":"registry_full"},"protocol":"automonique.automation","request_id":"req-register-1","version":1}"#.to_vec(),
            },
            DecodeRefusal {
                id: "empty-payload",
                note: "zero bytes is not an empty message",
                payload: Vec::new(),
            },
        ]
    }

    fn decode_refusal_entry(refusal: &DecodeRefusal) -> JsonValue {
        let category = AutomationResponse::from_canonical_bytes(&refusal.payload)
            .err()
            .unwrap_or_else(|| panic!("{}: Rust accepted a payload it must refuse", refusal.id))
            .category()
            .to_owned();
        JsonValue::Object(vec![
            ("category".to_owned(), text(&category)),
            ("id".to_owned(), text(refusal.id)),
            ("note".to_owned(), text(refusal.note)),
            ("payload_hex".to_owned(), text(&hex(&refusal.payload))),
        ])
    }

    // -----------------------------------------------------------------------
    // The measured gap
    // -----------------------------------------------------------------------

    /// A payload the Rust constructors refuse and the generated TypeScript
    /// accepts.
    ///
    /// Every one of these breaks a rule relating two fields of a *decoded*
    /// message. The request-side cause coupling is deliberately not among them:
    /// the generated builder does apply that one, and `encode_refusals` proves
    /// it. What a client cannot check is whether a peer's answer is internally
    /// coherent, and that is what stays here.
    struct RustOnlyRefusal {
        id: &'static str,
        note: &'static str,
        payload: Vec<u8>,
    }

    fn rust_only_refusals() -> Vec<RustOnlyRefusal> {
        vec![
            RustOnlyRefusal {
                id: "record-cause-required",
                note: "a withdrawn row with no stated cause: the same coupling the builder \
                       applies on the way out, met on the way in, where this surface does not \
                       hold it",
                payload: one_record_page(record_body(&[
                    ("enablement", text("paused")),
                    ("revision", JsonValue::Integer(2)),
                ])),
            },
            RustOnlyRefusal {
                id: "record-cause-forbidden",
                note: "an enabled row carrying a cause, which would say an automation in service \
                       was withdrawn",
                payload: one_record_page(record_body(&[("cause", text("held for maintenance"))])),
            },
            RustOnlyRefusal {
                id: "record-withdrawn-at-first-revision",
                note: "registration is the only writer of revision one and it always writes \
                       enabled, so a withdrawn row below revision two is a row no writer produced",
                payload: one_record_page(record_body(&[
                    ("enablement", text("archived")),
                    ("cause", text("superseded")),
                ])),
            },
            RustOnlyRefusal {
                id: "receipt-withdrawn-at-first-revision",
                note: "the same rule on a receipt",
                payload: automation_message(
                    "automation_accepted",
                    "req-set-1",
                    receipt_body(&[("enablement", text("paused"))]),
                ),
            },
            RustOnlyRefusal {
                id: "page-out-of-order",
                note: "records that do not strictly increase by durable row identity, so the \
                       next page would re-serve or skip",
                payload: automation_message(
                    "automation_list_result",
                    "req-list-1",
                    page_body(
                        vec![
                            record_body(&[("entry_id", JsonValue::Integer(5))]),
                            record_body(&[("entry_id", JsonValue::Integer(2))]),
                        ],
                        false,
                        JsonValue::Null,
                    ),
                ),
            },
            RustOnlyRefusal {
                id: "continuation-incoherent",
                note: "rows follow, with no cursor to resume from",
                payload: automation_message(
                    "automation_list_result",
                    "req-list-1",
                    page_body(Vec::new(), true, JsonValue::Null),
                ),
            },
            RustOnlyRefusal {
                id: "continuation-rewinds",
                note: "a continuation cursor below the last row on the page, which would re-serve \
                       it",
                payload: automation_message(
                    "automation_list_result",
                    "req-list-1",
                    page_body(
                        vec![record_body(&[("entry_id", JsonValue::Integer(9))])],
                        true,
                        JsonValue::Integer(4),
                    ),
                ),
            },
            RustOnlyRefusal {
                id: "conflict-without-disagreement",
                note: "a conflict naming the revision the caller expected, which is agreement — \
                       and would tell a caller to retry with the revision it already used",
                payload: automation_message("revision_conflict", "req-set-1", conflict_body(4, 4)),
            },
            RustOnlyRefusal {
                id: "record-scope-without-schedule",
                note: "a scope with no schedule to serialize under: the job columns are null \
                       together or present together, which relates two fields",
                payload: one_record_page(record_body(&[
                    ("schedule", JsonValue::Null),
                    ("next_fire_at_ms", JsonValue::Null),
                ])),
            },
            RustOnlyRefusal {
                id: "record-next-fire-without-schedule",
                note: "an instant something is due at, on a row with nothing scheduled",
                payload: one_record_page(record_body(&[
                    ("schedule", JsonValue::Null),
                    ("scope", JsonValue::Null),
                ])),
            },
            RustOnlyRefusal {
                id: "detail-prompt-without-job",
                note: "a prompt on a row registered before jobs existed, which is a task \
                       nothing will ever fire — the prompt and the job imply each other",
                payload: automation_message(
                    "automation_detail_result",
                    "req-detail-1",
                    detail_body(
                        &[
                            ("schedule", JsonValue::Null),
                            ("scope", JsonValue::Null),
                            ("next_fire_at_ms", JsonValue::Null),
                        ],
                        text("summarize"),
                    ),
                ),
            },
            RustOnlyRefusal {
                id: "detail-job-without-prompt",
                note: "a scheduled row whose detail carries no prompt: a job that would submit \
                       nothing, refused by the same coupling the other way round",
                payload: automation_message(
                    "automation_detail_result",
                    "req-detail-1",
                    detail_body(&[], JsonValue::Null),
                ),
            },
        ]
    }

    fn rust_only_entry(refusal: &RustOnlyRefusal) -> JsonValue {
        let category = AutomationResponse::from_canonical_bytes(&refusal.payload)
            .err()
            .unwrap_or_else(|| {
                panic!(
                    "{}: Rust accepts this, so it is not a rule the generated surface is missing",
                    refusal.id
                )
            })
            .category()
            .to_owned();
        JsonValue::Object(vec![
            ("id".to_owned(), text(refusal.id)),
            ("note".to_owned(), text(refusal.note)),
            ("payload_hex".to_owned(), text(&hex(&refusal.payload))),
            ("rust_category".to_owned(), text(&category)),
        ])
    }

    // -----------------------------------------------------------------------
    // Encode refusals
    // -----------------------------------------------------------------------

    /// A request the other implementation must refuse while building it.
    struct EncodeRefusal {
        id: &'static str,
        note: &'static str,
        kind: &'static str,
        request_id: String,
        params: JsonValue,
        category: String,
        /// The generated constructor that refuses the value on its own, the
        /// parameter it is applied to, and the violation it names.
        constructor: Option<(&'static str, &'static str, &'static str)>,
    }

    /// The category Rust reports for a request body carrying this exact value.
    ///
    /// Read back from the shipped decoder rather than constructed here. The
    /// bounded-field errors of `crate::automation` are translated into this
    /// lane's on the way in, and a category retyped beside the translation
    /// would be a claim about it rather than a reading of it.
    fn wire_category(kind: &str, body: JsonValue) -> String {
        AutomationRequest::from_canonical_bytes(&automation_message(kind, "req-1", body))
            .err()
            .unwrap_or_else(|| panic!("{kind}: Rust accepted a body it must refuse"))
            .category()
            .to_owned()
    }

    fn set_enablement_params(
        actor: &str,
        id: &str,
        cause: JsonValue,
        expected_revision: JsonValue,
        target: &str,
    ) -> JsonValue {
        JsonValue::Object(vec![
            ("actor".to_owned(), text(actor)),
            ("automation_id".to_owned(), text(id)),
            ("cause".to_owned(), cause),
            ("expected_revision".to_owned(), expected_revision),
            ("target".to_owned(), text(target)),
        ])
    }

    fn list_params(size: JsonValue, since: JsonValue, states: JsonValue) -> JsonValue {
        JsonValue::Object(vec![
            ("page_size".to_owned(), size),
            ("since".to_owned(), since),
            ("states".to_owned(), states),
        ])
    }

    fn register_params(
        actor: &str,
        id: &str,
        prompt: &str,
        schedule: &str,
        scope: &str,
    ) -> JsonValue {
        JsonValue::Object(vec![
            ("actor".to_owned(), text(actor)),
            ("automation_id".to_owned(), text(id)),
            ("prompt".to_owned(), text(prompt)),
            ("schedule".to_owned(), text(schedule)),
            ("scope".to_owned(), text(scope)),
        ])
    }

    fn encode_refusals() -> Vec<EncodeRefusal> {
        let long_identifier = "a".repeat(MAX_AUTOMATION_API_FIELD_BYTES + 1);
        let scheduled_identifier_over_bound = "a".repeat(MAX_SCHEDULED_AUTOMATION_ID_BYTES + 1);
        let long_prompt = "p".repeat(MAX_AUTOMATION_PROMPT_BYTES + 1);
        let long_request_id = "r".repeat(MAX_REQUEST_ID_BYTES + 1);

        let withdrawal_without_cause = |target: EnablementState| {
            SetEnablement::new(
                automation_id("auto-nightly"),
                2,
                target,
                actor("ops/oncall"),
                None,
            )
            .expect_err("a withdrawal with no stated cause is refused")
            .category()
            .to_owned()
        };
        let resume_with_cause = SetEnablement::new(
            automation_id("auto-nightly"),
            2,
            EnablementState::Enabled,
            actor("ops/oncall"),
            Some(reason("held")),
        )
        .expect_err("a resume that states a cause is refused")
        .category()
        .to_owned();
        let unwritten_revision = SetEnablement::new(
            automation_id("auto-nightly"),
            0,
            EnablementState::Enabled,
            actor("ops/oncall"),
            None,
        )
        .expect_err("revision zero is refused")
        .category()
        .to_owned();
        let revision_out_of_range = AutomationRequest::SetEnablement {
            request_id: request_id("req-set-1"),
            transition: SetEnablement::new(
                automation_id("auto-nightly"),
                wire_ceiling() + 1,
                EnablementState::Enabled,
                actor("ops/oncall"),
                None,
            )
            .expect("the constructor admits any nonzero revision"),
        }
        .to_message()
        .expect_err("a revision above the wire ceiling is refused")
        .category()
        .to_owned();
        let cursor_out_of_range = AutomationRequest::ListAutomations {
            request_id: request_id("req-list-1"),
            query: ListAutomations::new(
                AutomationStateFilter::any(),
                AutomationCursor::new(wire_ceiling() + 1),
                page_size(1),
            ),
        }
        .to_message()
        .expect_err("a cursor above the wire ceiling is refused")
        .category()
        .to_owned();
        let page_size_out_of_range = AutomationPageSize::new(0)
            .expect_err("a page that admits nothing is refused")
            .category()
            .to_owned();
        let empty_filter = AutomationStateFilter::only([])
            .expect_err("an empty filter is refused")
            .category()
            .to_owned();
        let repeated_state =
            AutomationStateFilter::only([EnablementState::Paused, EnablementState::Paused])
                .expect_err("a repeated state is refused")
                .category()
                .to_owned();
        let undefined_state =
            AutomationApiError::Codec(automonique_protocol::codec::CodecError::UnknownEnumValue {
                field: "target",
            })
            .category()
            .to_owned();
        let long_id_refusal = AutomationApiError::Codec(
            RequestId::new(&long_request_id).expect_err("an overlong request id is refused"),
        )
        .category()
        .to_owned();
        let bad_id_refusal = AutomationApiError::Codec(
            RequestId::new("req 1").expect_err("a space is outside the request id grammar"),
        )
        .category()
        .to_owned();

        vec![
            EncodeRefusal {
                id: "set-enablement-pause-without-cause",
                note: "the coupling, on the way out: a pause with no stated cause is refused \
                       before a frame is spent, because a withdrawal an operator cannot safely \
                       resume from is not a request this product has a shape for",
                kind: "set_enablement",
                request_id: "req-set-1".to_owned(),
                params: set_enablement_params(
                    "ops/oncall",
                    "auto-nightly",
                    JsonValue::Null,
                    number(2),
                    "paused",
                ),
                category: withdrawal_without_cause(EnablementState::Paused),
                constructor: None,
            },
            EncodeRefusal {
                id: "set-enablement-archive-without-cause",
                note: "the terminal state owes a cause as much as the resumable one does",
                kind: "set_enablement",
                request_id: "req-set-1".to_owned(),
                params: set_enablement_params(
                    "ops/oncall",
                    "auto-nightly",
                    JsonValue::Null,
                    number(2),
                    "archived",
                ),
                category: withdrawal_without_cause(EnablementState::Archived),
                constructor: None,
            },
            EncodeRefusal {
                id: "set-enablement-resume-with-cause",
                note: "the other half of the coupling: a resume that states a cause is refused \
                       rather than silently dropping the cause, which would leave the caller \
                       believing it recorded something",
                kind: "set_enablement",
                request_id: "req-set-1".to_owned(),
                params: set_enablement_params(
                    "ops/oncall",
                    "auto-nightly",
                    text("held for the migration"),
                    number(2),
                    "enabled",
                ),
                category: resume_with_cause,
                constructor: None,
            },
            EncodeRefusal {
                id: "set-enablement-revision-zero",
                note: "zero names a row no writer produced, which is a different fault from a \
                       counter the wire cannot carry — and the two categories differ",
                kind: "set_enablement",
                request_id: "req-set-1".to_owned(),
                params: set_enablement_params(
                    "ops/oncall",
                    "auto-nightly",
                    JsonValue::Null,
                    number(0),
                    "enabled",
                ),
                category: unwritten_revision,
                constructor: Some(("DurableRowId", "expected_revision", "out_of_range")),
            },
            EncodeRefusal {
                id: "set-enablement-revision-above-wire-ceiling",
                note: "one past the largest integer this wire carries: the same branded \
                       constructor refuses it, and the encoder reports the other end of the range",
                kind: "set_enablement",
                request_id: "req-set-1".to_owned(),
                params: set_enablement_params(
                    "ops/oncall",
                    "auto-nightly",
                    JsonValue::Null,
                    number(wire_ceiling() + 1),
                    "enabled",
                ),
                category: revision_out_of_range,
                constructor: Some(("DurableRowId", "expected_revision", "out_of_range")),
            },
            EncodeRefusal {
                id: "set-enablement-undefined-target",
                note: "a brand exists only in the type checker, so the builder is where an \
                       untyped caller's undefined state is stopped. The coupling passes first — \
                       an unknown target requires no cause and none is given — so what refuses \
                       this is the vocabulary rather than the relation",
                kind: "set_enablement",
                request_id: "req-set-1".to_owned(),
                params: set_enablement_params(
                    "ops/oncall",
                    "auto-nightly",
                    JsonValue::Null,
                    number(2),
                    "disabled",
                ),
                category: undefined_state,
                constructor: None,
            },
            EncodeRefusal {
                id: "set-enablement-cause-over-bound",
                note: "one byte over the cause bound, measured in UTF-8 bytes",
                kind: "set_enablement",
                request_id: "req-set-1".to_owned(),
                params: set_enablement_params(
                    "ops/oncall",
                    "auto-nightly",
                    text(&long_identifier),
                    number(2),
                    "paused",
                ),
                category: PauseReason::new(&long_identifier)
                    .expect_err("an overlong cause is refused")
                    .category()
                    .to_owned(),
                constructor: Some(("PauseReason", "cause", "too_long")),
            },
            EncodeRefusal {
                id: "register-automation-id-over-bound",
                note: "one byte over the identity bound, which the registry grammar itself \
                       refuses before the narrower scheduled bound is reached",
                kind: "register_automation",
                request_id: "req-register-1".to_owned(),
                params: register_params(
                    "ops/oncall",
                    &long_identifier,
                    "summarize",
                    "every@60000",
                    "workspace/reports",
                ),
                category: AutomationId::new(&long_identifier)
                    .expect_err("an overlong identity is refused")
                    .category()
                    .to_owned(),
                constructor: Some(("ScheduledAutomationId", "automation_id", "too_long")),
            },
            EncodeRefusal {
                id: "register-automation-id-over-scheduled-bound",
                note: "one byte over the scheduled identity bound: an identity the registry \
                       could hold but whose occurrence key could never fit the durable submit \
                       lane, refused before a frame is spent rather than registered and never \
                       fired",
                kind: "register_automation",
                request_id: "req-register-1".to_owned(),
                params: register_params(
                    "ops/oncall",
                    &scheduled_identifier_over_bound,
                    "summarize",
                    "every@60000",
                    "workspace/reports",
                ),
                category: RegisterAutomation::new(
                    automation_id(&scheduled_identifier_over_bound),
                    actor("ops/oncall"),
                    schedule("every@60000"),
                    scope("workspace/reports"),
                    prompt("summarize"),
                )
                .expect_err("an identity too long to derive a key from is refused")
                .category()
                .to_owned(),
                constructor: Some(("ScheduledAutomationId", "automation_id", "too_long")),
            },
            EncodeRefusal {
                id: "register-actor-control-character",
                note: "a control character in an actor, which the wire never carries raw",
                kind: "register_automation",
                request_id: "req-register-1".to_owned(),
                params: register_params(
                    "ops\u{7}oncall",
                    "auto-nightly",
                    "summarize",
                    "every@60000",
                    "workspace/reports",
                ),
                category: wire_category(
                    "register_automation",
                    register_params(
                        "ops\u{7}oncall",
                        "auto-nightly",
                        "summarize",
                        "every@60000",
                        "workspace/reports",
                    ),
                ),
                constructor: Some(("AutomationActor", "actor", "invalid_character")),
            },
            EncodeRefusal {
                id: "register-prompt-empty",
                note: "an empty prompt is a job that submits nothing",
                kind: "register_automation",
                request_id: "req-register-1".to_owned(),
                params: register_params(
                    "ops/oncall",
                    "auto-nightly",
                    "",
                    "every@60000",
                    "workspace/reports",
                ),
                category: AutomationPrompt::new("")
                    .expect_err("an empty prompt is refused")
                    .category()
                    .to_owned(),
                constructor: Some(("AutomationPrompt", "prompt", "empty")),
            },
            EncodeRefusal {
                id: "register-prompt-over-bound",
                note: "one byte over the prompt bound, which is the durable submit lane's task \
                       bound",
                kind: "register_automation",
                request_id: "req-register-1".to_owned(),
                params: register_params(
                    "ops/oncall",
                    "auto-nightly",
                    &long_prompt,
                    "every@60000",
                    "workspace/reports",
                ),
                category: AutomationPrompt::new(&long_prompt)
                    .expect_err("an overlong prompt is refused")
                    .category()
                    .to_owned(),
                constructor: Some(("AutomationPrompt", "prompt", "too_long")),
            },
            EncodeRefusal {
                id: "register-scope-control-character",
                note: "a scope is an identifier, not prose: the newline a prompt may carry is \
                       outside a scope's grammar",
                kind: "register_automation",
                request_id: "req-register-1".to_owned(),
                params: register_params(
                    "ops/oncall",
                    "auto-nightly",
                    "summarize",
                    "every@60000",
                    "workspace\nreports",
                ),
                category: AutomationScope::new("workspace\nreports")
                    .expect_err("a control-bearing scope is refused")
                    .category()
                    .to_owned(),
                constructor: Some(("AutomationScope", "scope", "invalid_character")),
            },
            EncodeRefusal {
                id: "register-schedule-prose",
                note: "a schedule that is prose rather than a canonical rendering, stopped where \
                       an untyped caller reaches the builder: what an operator typed is parsed \
                       into a rendering before it reaches the wire, never carried as typed",
                kind: "register_automation",
                request_id: "req-register-1".to_owned(),
                params: register_params(
                    "ops/oncall",
                    "auto-nightly",
                    "summarize",
                    "every day at nine",
                    "workspace/reports",
                ),
                category: wire_category(
                    "register_automation",
                    register_params(
                        "ops/oncall",
                        "auto-nightly",
                        "summarize",
                        "every day at nine",
                        "workspace/reports",
                    ),
                ),
                constructor: Some(("AutomationSchedule", "schedule", "invalid_character")),
            },
            EncodeRefusal {
                id: "automation-detail-id-empty",
                note: "an empty identity names nothing",
                kind: "automation_detail",
                request_id: "req-detail-1".to_owned(),
                params: JsonValue::Object(vec![("automation_id".to_owned(), text(""))]),
                category: AutomationId::new("")
                    .expect_err("an empty identity is refused")
                    .category()
                    .to_owned(),
                constructor: Some(("AutomationId", "automation_id", "empty")),
            },
            EncodeRefusal {
                id: "list-automations-page-size-zero",
                note: "a page that admits nothing cannot make progress, so zero is refused \
                       rather than treated as a default",
                kind: "list_automations",
                request_id: "req-list-1".to_owned(),
                params: list_params(number(0), number(0), JsonValue::Null),
                category: page_size_out_of_range.clone(),
                constructor: Some(("AutomationPageSize", "page_size", "out_of_range")),
            },
            EncodeRefusal {
                id: "list-automations-page-size-above-bound",
                note: "one past MAX_AUTOMATION_PAGE_ITEMS, which is twenty-four here and \
                       sixty-four on the Runs lane: a page bound follows the frame arithmetic of \
                       the rows it carries",
                kind: "list_automations",
                request_id: "req-list-1".to_owned(),
                params: list_params(
                    number(MAX_AUTOMATION_PAGE_ITEMS as u64 + 1),
                    number(0),
                    JsonValue::Null,
                ),
                category: page_size_out_of_range,
                constructor: Some(("AutomationPageSize", "page_size", "out_of_range")),
            },
            EncodeRefusal {
                id: "list-automations-cursor-above-wire-ceiling",
                note: "a cursor one past the largest integer this wire carries, which is a \
                       counter refusal rather than a malformed body",
                kind: "list_automations",
                request_id: "req-list-1".to_owned(),
                params: list_params(number(1), number(wire_ceiling() + 1), JsonValue::Null),
                category: cursor_out_of_range,
                constructor: Some(("AutomationCursor", "since", "out_of_range")),
            },
            EncodeRefusal {
                id: "list-automations-empty-state-filter",
                note: "an empty filter admits nothing, which no listing could ever answer; it is \
                       not the same request as no filter at all",
                kind: "list_automations",
                request_id: "req-list-1".to_owned(),
                params: list_params(number(1), number(0), JsonValue::Array(Vec::new())),
                category: empty_filter,
                constructor: None,
            },
            EncodeRefusal {
                id: "list-automations-repeated-state",
                note: "a repeat means a caller believes it asked for something it did not",
                kind: "list_automations",
                request_id: "req-list-1".to_owned(),
                params: list_params(
                    number(1),
                    number(0),
                    JsonValue::Array(vec![text("paused"), text("paused")]),
                ),
                category: repeated_state,
                constructor: None,
            },
            EncodeRefusal {
                id: "list-automations-undefined-state",
                note: "an undefined state in a filter, stopped where an untyped caller reaches \
                       the builder",
                kind: "list_automations",
                request_id: "req-list-1".to_owned(),
                params: list_params(
                    number(1),
                    number(0),
                    JsonValue::Array(vec![text("disabled")]),
                ),
                category: AutomationApiError::Codec(
                    automonique_protocol::codec::CodecError::UnknownEnumValue {
                        field: "enablement",
                    },
                )
                .category()
                .to_owned(),
                constructor: None,
            },
            EncodeRefusal {
                id: "request-id-too-long",
                note: "the envelope's fields are judged by the shared codec, whose refusal for a \
                       bound is not the one this protocol uses for a body",
                kind: "automation_detail",
                request_id: long_request_id,
                params: JsonValue::Object(vec![("automation_id".to_owned(), text("auto-nightly"))]),
                category: long_id_refusal,
                constructor: Some(("RequestId", "request_id", "too_long")),
            },
            EncodeRefusal {
                id: "request-id-outside-grammar",
                note: "a grammar refusal is not a bounds refusal, and the categories differ. A \
                       space is outside the correlation identifier's grammar and inside the \
                       automation identity's, which is the difference this lane's looser \
                       identifier makes",
                kind: "automation_detail",
                request_id: "req 1".to_owned(),
                params: JsonValue::Object(vec![("automation_id".to_owned(), text("auto nightly"))]),
                category: bad_id_refusal,
                constructor: Some(("RequestId", "request_id", "invalid_character")),
            },
        ]
    }

    fn encode_refusal_entry(refusal: &EncodeRefusal) -> JsonValue {
        let mut entry = vec![
            ("category".to_owned(), text(&refusal.category)),
            ("id".to_owned(), text(refusal.id)),
            ("kind".to_owned(), text(refusal.kind)),
            ("note".to_owned(), text(refusal.note)),
            ("params".to_owned(), refusal.params.clone()),
            ("request_id".to_owned(), text(&refusal.request_id)),
        ];
        if let Some((constructor, parameter, violation)) = refusal.constructor {
            // Named `refused_by` rather than `constructor`: a JSON object parsed
            // by a JavaScript reader inherits `constructor` from its prototype.
            entry.push(("refused_by".to_owned(), text(constructor)));
            entry.push(("refused_param".to_owned(), text(parameter)));
            entry.push(("violation".to_owned(), text(violation)));
        }
        JsonValue::Object(entry)
    }

    // -----------------------------------------------------------------------
    // The corpus file
    // -----------------------------------------------------------------------

    fn corpus() -> String {
        let document = JsonValue::Object(vec![
            (
                "decode_refusals".to_owned(),
                JsonValue::Array(decode_refusals().iter().map(decode_refusal_entry).collect()),
            ),
            (
                "encode_refusals".to_owned(),
                JsonValue::Array(encode_refusals().iter().map(encode_refusal_entry).collect()),
            ),
            (
                "generator".to_owned(),
                text("automonique-protocol tests/codegen.rs, module automation_surface"),
            ),
            (
                "note".to_owned(),
                text(
                    "Generated from the shipped Rust constructors: every canonical byte string \
                     here was produced by encoding a real message and re-read through \
                     from_canonical_bytes before it was written, and every refusal category was \
                     read back from the error Rust returned for that exact input. Counters \
                     travel as decimal strings because a JSON reader using a double would round \
                     the largest of them without saying so. Rust is the wire source of truth, so \
                     a disagreement is fixed in whichever implementation is wrong — never in \
                     this file.",
                ),
            ),
            ("protocol".to_owned(), text(AUTOMATION_PROTOCOL)),
            (
                "requests".to_owned(),
                JsonValue::Array(request_cases().iter().map(request_entry).collect()),
            ),
            (
                "responses".to_owned(),
                JsonValue::Array(response_cases().iter().map(response_entry).collect()),
            ),
            (
                "rust_only_refusals".to_owned(),
                JsonValue::Array(rust_only_refusals().iter().map(rust_only_entry).collect()),
            ),
            (
                "rust_only_refusals_note".to_owned(),
                text(
                    "Payloads the Rust constructors refuse and the generated TypeScript accepts. \
                     Each breaks a rule relating two fields of a decoded message, which the \
                     generated surface does not hold. The request-side enablement/cause coupling \
                     is deliberately absent from this list: the generated builder does apply it, \
                     and encode_refusals is where that is proved. The runner asserts these \
                     decode, so the remaining gap is measured rather than described — teaching \
                     the generator one of these rules turns the suite red until the entry moves \
                     to decode_refusals.",
                ),
            ),
            (
                "version".to_owned(),
                JsonValue::Integer(i64::from(MajorVersion::FIRST.get())),
            ),
        ]);
        let mut out = String::new();
        write_pretty(&document, 0, &mut out);
        out.push('\n');
        out
    }

    /// The drift gate over the corpus, and the regeneration that closes it.
    #[test]
    fn the_checked_in_corpus_matches_regeneration() {
        let expected = corpus();
        let path = corpus_path();
        if regenerating() {
            let staging = path.with_extension("json.staging");
            std::fs::write(&staging, &expected).expect("stage the corpus");
            std::fs::rename(&staging, &path).expect("publish the corpus");
            return;
        }
        let actual = std::fs::read_to_string(&path)
            .expect("the corpus is checked in — regenerate it to create it");
        if actual != expected {
            let difference = actual
                .lines()
                .zip(expected.lines())
                .enumerate()
                .find(|(_, (left, right))| left != right)
                .map_or_else(
                    || {
                        format!(
                            "{} lines on disk, {} lines generated",
                            actual.lines().count(),
                            expected.lines().count()
                        )
                    },
                    |(index, (left, right))| {
                        let shorten = |line: &str| line.chars().take(120).collect::<String>();
                        format!(
                            "line {}: on disk {:?}, generated {:?}",
                            index + 1,
                            shorten(left),
                            shorten(right)
                        )
                    },
                );
            panic!(
                "the checked-in automation corpus no longer matches the Rust encoders: \
                 {difference}\n\nRegenerate with: {REGENERATE_COMMAND}"
            );
        }
    }

    /// Every request this protocol version defines is generated or named absent.
    #[test]
    fn every_request_kind_is_generated_or_named_as_absent() {
        let id = request_id("req-coverage-1");
        let requests = vec![
            AutomationRequest::RegisterAutomation {
                request_id: id.clone(),
                registration: RegisterAutomation::new(
                    automation_id("auto-1"),
                    actor("ops/oncall"),
                    schedule("every@60000"),
                    scope("workspace/reports"),
                    prompt("summarize"),
                )
                .expect("a registration"),
            },
            AutomationRequest::SetEnablement {
                request_id: id.clone(),
                transition: SetEnablement::new(
                    automation_id("auto-1"),
                    1,
                    EnablementState::Enabled,
                    actor("ops/oncall"),
                    None,
                )
                .expect("a resume"),
            },
            AutomationRequest::ListAutomations {
                request_id: id.clone(),
                query: ListAutomations::new(
                    AutomationStateFilter::any(),
                    AutomationCursor::START,
                    page_size(1),
                ),
            },
            AutomationRequest::AutomationDetail {
                request_id: id,
                automation_id: automation_id("auto-1"),
            },
        ];
        // The match is the point: a request added to `AutomationRequest` fails
        // to compile here rather than quietly falling outside the generated
        // surface.
        for request in &requests {
            match request {
                AutomationRequest::RegisterAutomation { .. }
                | AutomationRequest::SetEnablement { .. }
                | AutomationRequest::ListAutomations { .. }
                | AutomationRequest::AutomationDetail { .. } => {}
            }
        }
        let encoded: BTreeSet<String> = requests
            .iter()
            .map(|request| {
                request
                    .to_message()
                    .expect("each request encodes")
                    .envelope()
                    .kind()
                    .as_str()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            encoded.len(),
            requests.len(),
            "one request per variant is required, each with its own kind"
        );

        let surface = surface();
        let mut covered: BTreeSet<String> = surface
            .requests
            .iter()
            .map(|request| request.kind.clone())
            .collect();
        for kind in &surface.request_kinds_not_generated {
            assert!(
                covered.insert(kind.clone()),
                "{kind} is both generated and named as absent"
            );
        }
        assert_eq!(
            covered, encoded,
            "the generated automation surface does not account for every request kind the Rust \
             encoders produce; regenerate with: {REGENERATE_COMMAND}"
        );
    }

    /// Every answer this protocol version defines is decoded or named undecoded.
    #[test]
    fn every_response_kind_is_decoded_or_named_as_undecoded() {
        let id = request_id("req-coverage-1");
        let responses = vec![
            AutomationResponse::Accepted {
                request_id: id.clone(),
                receipt: AutomationReceiptView::new(
                    1,
                    automation_id("auto-1"),
                    EnablementState::Enabled,
                    1,
                    EpochMillis::from_millis(0),
                )
                .expect("a receipt"),
            },
            AutomationResponse::AutomationList {
                request_id: id.clone(),
                page: AutomationListPage::new(Vec::new(), AutomationContinuation::Complete)
                    .expect("a page"),
            },
            AutomationResponse::AutomationDetail {
                request_id: id.clone(),
                record: record(Row {
                    entry_id: 1,
                    automation_id: "auto-1",
                    revision: 1,
                    enablement: EnablementState::Enabled,
                    actor: "ops/oncall",
                    cause: None,
                    created_at_ms: 0,
                    updated_at_ms: 0,
                    schedule: None,
                    scope: None,
                    next_fire_at_ms: None,
                    last_fired_at_ms: None,
                }),
                prompt: None,
            },
            AutomationResponse::conflict(id.clone(), 1, 2).expect("a conflict"),
            AutomationResponse::Refused {
                request_id: id,
                refusal: AutomationRefusal::UnknownAutomation,
            },
        ];
        // The match is the point: a variant added to `AutomationResponse` fails
        // to compile here rather than slipping past a surface that ignores it.
        for response in &responses {
            match response {
                AutomationResponse::Accepted { .. }
                | AutomationResponse::AutomationList { .. }
                | AutomationResponse::AutomationDetail { .. }
                | AutomationResponse::Conflict { .. }
                | AutomationResponse::Refused { .. } => {}
            }
        }
        let encoded: BTreeSet<String> = responses
            .iter()
            .map(|response| {
                response
                    .to_message()
                    .expect("each response encodes")
                    .envelope()
                    .kind()
                    .as_str()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            encoded.len(),
            responses.len(),
            "one response per variant is required, each with its own kind"
        );

        let surface = surface();
        let mut covered: BTreeSet<String> = surface
            .responses
            .iter()
            .map(|response| response.kind.clone())
            .collect();
        for kind in &surface.response_kinds_not_decoded {
            assert!(
                covered.insert(kind.clone()),
                "{kind} is both decoded and named as undecoded"
            );
        }
        assert_eq!(
            covered, encoded,
            "the generated automation surface does not account for every answer the daemon can \
             produce; regenerate with: {REGENERATE_COMMAND}"
        );
    }

    /// The closed vocabularies, restated here rather than read back from the
    /// generator.
    ///
    /// A generator that dropped a variant would agree with itself perfectly.
    /// This is the second opinion, and the third is the wire order, which is
    /// checked against `EnablementState::ALL` rather than against a list: the
    /// sorted `_VALUES` table is not the order a state filter encodes in, and a
    /// generator that emitted the sorted one there would produce bytes Rust
    /// refuses to match.
    #[test]
    fn every_closed_vocabulary_carries_all_of_its_variants() {
        let generated = generated_automation();
        let expected: [(&str, &[&str]); 2] = [
            (
                "AutomationRefusal",
                &[
                    "already_registered",
                    "cause_forbidden",
                    "cause_required",
                    "cursor_out_of_range",
                    "illegal_transition",
                    "invalid_field",
                    "registry_full",
                    "unknown_automation",
                ],
            ),
            ("EnablementState", &["archived", "enabled", "paused"]),
        ];
        for (name, values) in expected {
            let literals: Vec<String> = values.iter().map(|value| format!("\"{value}\"")).collect();
            let declaration = format!("export type {name} = {};", literals.join(" | "));
            assert!(
                generated.contains(&declaration),
                "the automation surface lost a {name} variant.\nexpected: {declaration}"
            );
            assert!(
                generated.contains(&format!(
                    "export const {name}_VALUES: readonly {name}[] = [{}];",
                    literals.join(", ")
                )),
                "the {name} table does not match its type"
            );
            assert!(
                generated.contains(&format!(
                    "export function decode{name}(value: string): {name} {{"
                )),
                "the automation surface does not refuse an undefined {name}"
            );
        }

        let order: Vec<String> = EnablementState::ALL
            .iter()
            .map(|state| format!("\"{}\"", state.as_str()))
            .collect();
        assert!(
            generated.contains(&format!(
                "export const EnablementState_WIRE_ORDER: readonly EnablementState[] = [{}];",
                order.join(", ")
            )),
            "the generated wire order is not EnablementState::ALL, so a state filter would \
             encode bytes Rust does not produce"
        );
        assert_ne!(
            {
                let mut sorted = order.clone();
                sorted.sort();
                sorted
            },
            order,
            "this check is only worth making while the two orders differ"
        );
    }

    /// The states that owe a cause are the ones `requires_cause` names.
    ///
    /// Not a list retyped beside the generator's: the expectation is built by
    /// asking the same function the daemon and the store agree with, and the
    /// assertion below is that the *wire order* is preserved rather than sorted,
    /// because a coupling that tested membership in a sorted list would still
    /// pass while the array said something the enum does not.
    #[test]
    fn the_cause_coupling_names_exactly_the_withdrawn_states() {
        let expected: Vec<&str> = EnablementState::ALL
            .iter()
            .filter(|state| automonique_protocol::automation_api::requires_cause(**state))
            .map(|state| state.as_str())
            .collect();
        assert_eq!(
            expected,
            vec!["paused", "archived"],
            "the withdrawn states are the two that carry a PauseCause"
        );
        let literals: Vec<String> = expected
            .iter()
            .map(|value| format!("\"{value}\""))
            .collect();
        let generated = generated_automation();
        assert!(
            generated.contains(&format!(
                "export const ENABLEMENT_STATES_REQUIRING_CAUSE: readonly string[] = [{}];",
                literals.join(", ")
            )),
            "the generated coupling does not name the states requires_cause names"
        );
        // Declaring the rule is not applying it.
        for application in [
            "const cause = coupledField(body.target, body.cause, {",
            "requiring: ENABLEMENT_STATES_REQUIRING_CAUSE,",
            "required: AUTOMATION_CAUSE_REQUIRED,",
            "forbidden: AUTOMATION_CAUSE_FORBIDDEN,",
        ] {
            assert!(
                generated.contains(application),
                "the automation surface declares the coupling but does not apply it: {application}"
            );
        }
        assert!(
            !generated.contains("cause: PauseReason;"),
            "a cause that cannot be null would make the coupling unreachable: a resume could not \
             be spelled at all"
        );
    }

    /// The bounds in the output are the Rust constants, and they are applied.
    #[test]
    fn the_generated_automation_bounds_are_the_rust_constants() {
        let generated = generated_automation();
        for declaration in [
            format!("export const MAX_AUTOMATION_PAGE_ITEMS = {MAX_AUTOMATION_PAGE_ITEMS};"),
            format!(
                "export const MAX_AUTOMATION_CANONICAL_BYTES = {};",
                automonique_protocol::automation_api::MAX_AUTOMATION_CANONICAL_BYTES
            ),
            format!("export const AutomationId_MAX_BYTES = {MAX_AUTOMATION_API_FIELD_BYTES};"),
            format!(
                "export const ScheduledAutomationId_MAX_BYTES = {MAX_SCHEDULED_AUTOMATION_ID_BYTES};"
            ),
            format!("export const AutomationActor_MAX_BYTES = {MAX_AUTOMATION_API_FIELD_BYTES};"),
            format!("export const PauseReason_MAX_BYTES = {MAX_AUTOMATION_API_FIELD_BYTES};"),
            format!("export const AutomationScope_MAX_BYTES = {MAX_AUTOMATION_SCOPE_BYTES};"),
            format!("export const AutomationPrompt_MAX_BYTES = {MAX_AUTOMATION_PROMPT_BYTES};"),
            format!(
                "export const AutomationSchedule_MAX_BYTES = {};",
                automonique_protocol::automation_api::MAX_AUTOMATION_SCHEDULE_BYTES
            ),
            format!("export const AutomationPageSize_MAX = {MAX_AUTOMATION_PAGE_ITEMS}n;"),
            "export const AutomationPageSize_MIN = 1n;".to_owned(),
            "export const AutomationCursor_MIN = 0n;".to_owned(),
            format!("export const AutomationCursor_MAX = {}n;", i64::MAX),
            format!("export const AUTOMATION_PROTOCOL = \"{AUTOMATION_PROTOCOL}\";"),
            format!(
                "export const AUTOMATION_API_SCHEMA_V1 = \"{}\";",
                automonique_protocol::automation_api::AUTOMATION_API_SCHEMA_V1
            ),
        ] {
            assert!(
                generated.contains(&declaration),
                "the automation surface does not carry the Rust bound: {declaration}"
            );
        }
        // Declaring a bound is not applying it.
        for application in [
            format!(
                "  if (byteLength(value) > {MAX_AUTOMATION_API_FIELD_BYTES}) throw new \
                 ValidationError(\"AutomationId\", \"too_long\");"
            ),
            format!(
                "  if (byteLength(value) > {MAX_AUTOMATION_API_FIELD_BYTES}) throw new \
                 ValidationError(\"PauseReason\", \"too_long\");"
            ),
            format!(
                "  if (typeof value !== \"bigint\" || value < 1n || value > {MAX_AUTOMATION_PAGE_ITEMS}n) throw new \
                 ValidationError(\"AutomationPageSize\", \"out_of_range\");"
            ),
            "bodyArray(fields, \"automations\", AUTOMATION_INVALID_BODY, \
             MAX_AUTOMATION_PAGE_ITEMS, AUTOMATION_PAGE_TOO_LARGE)"
                .to_owned(),
        ] {
            assert!(
                generated.contains(&application),
                "the automation surface declares a bound it does not apply: {application}"
            );
        }
        // The identity's grammar is the store's looser one, not `DurableId`'s.
        assert!(
            generated.contains("export const AutomationId_PATTERN = /^[^\\p{Cc}]+$/u;"),
            "the automation identity does not carry the control-free grammar the durable \
             registry stores under"
        );
        // A prompt is prose: only NUL is outside its grammar.
        assert!(
            generated.contains("export const AutomationPrompt_PATTERN = /^[^\\u0000]+$/u;"),
            "the prompt does not carry the durable submit lane's task grammar"
        );
        // The schedule grammar is the two canonical renderings and nothing else.
        assert!(
            generated.contains(
                "export const AutomationSchedule_PATTERN = \
                 /^(once@(0|[1-9][0-9]{0,18})|every@[1-9][0-9]{0,18})$/u;"
            ),
            "the schedule does not carry the canonical once@/every@ grammar"
        );
        // And the narrower registration identity is the scheduled bound, not
        // the registry one, so a builder cannot register what cannot fire.
        // This check is only worth making while the two bounds differ.
        const {
            assert!(MAX_SCHEDULED_AUTOMATION_ID_BYTES < MAX_AUTOMATION_API_FIELD_BYTES);
        }
        assert!(
            generated.contains(&format!(
                "  if (byteLength(value) > {MAX_SCHEDULED_AUTOMATION_ID_BYTES}) throw new \
                 ValidationError(\"ScheduledAutomationId\", \"too_long\");"
            )),
            "the scheduled identity bound is declared but not applied"
        );
    }

    /// Every category the generated code refuses with is declared, and every
    /// declared category is a spelling Rust actually produces.
    #[test]
    fn every_refusal_category_is_declared_and_is_the_rust_spelling() {
        let surface = surface();
        let declared: BTreeMap<String, String> = surface
            .categories
            .iter()
            .map(|constant| {
                let ConstantValue::Text(value) = &constant.value else {
                    panic!("{} is a refusal category, which is text", constant.name)
                };
                (constant.name.clone(), value.clone())
            })
            .collect();

        let mut referenced = vec![
            surface.invalid_body_category.clone(),
            surface.unknown_kind_category.clone(),
            surface.oversize_category.clone(),
            surface.field_invalid_category.clone(),
            surface.field_grammar_category.clone(),
        ];
        referenced.extend(referenced_categories(&surface));
        for name in &referenced {
            assert!(
                declared.contains_key(name),
                "the automation surface refuses with {name}, which it does not declare"
            );
        }

        let generated = generated_automation();
        for (name, expected) in [
            (
                "AUTOMATION_INVALID_BODY",
                AutomationApiError::InvalidBody.category(),
            ),
            (
                "AUTOMATION_UNKNOWN_KIND",
                AutomationApiError::UnknownKind.category(),
            ),
            (
                "AUTOMATION_CAUSE_REQUIRED",
                AutomationApiError::CauseRequired {
                    state: EnablementState::Paused,
                }
                .category(),
            ),
            (
                "AUTOMATION_CAUSE_FORBIDDEN",
                AutomationApiError::CauseForbidden {
                    state: EnablementState::Enabled,
                }
                .category(),
            ),
            (
                "AUTOMATION_UNWRITTEN_REVISION",
                AutomationApiError::UnwrittenRevision.category(),
            ),
            (
                "AUTOMATION_UNWRITTEN_ROW",
                AutomationApiError::UnwrittenRow { field: "entry_id" }.category(),
            ),
            (
                "AUTOMATION_PAGE_TOO_LARGE",
                AutomationApiError::PageTooLarge {
                    max_items: 0,
                    actual_items: 0,
                }
                .category(),
            ),
            (
                "AUTOMATION_TIME_BEFORE_EPOCH",
                AutomationApiError::TimeBeforeEpoch {
                    field: "updated_at_ms",
                }
                .category(),
            ),
            (
                "AUTOMATION_UNKNOWN_ENUM_VALUE",
                AutomationApiError::Codec(
                    automonique_protocol::codec::CodecError::UnknownEnumValue {
                        field: "enablement",
                    },
                )
                .category(),
            ),
            (
                "AUTOMATION_INVALID_FIELD",
                AutomationApiError::Field {
                    field: "automation_id",
                    error: ValueError::Empty,
                }
                .category(),
            ),
            (
                "AUTOMATION_INVALID_SCHEDULE",
                AutomationApiError::InvalidSchedule.category(),
            ),
        ] {
            assert_eq!(
                declared.get(name).map(String::as_str),
                Some(expected),
                "{name} is not the category Rust reports"
            );
            assert!(
                generated.contains(&format!("export const {name} = \"{expected}\";")),
                "the generated file does not carry {name} as {expected}"
            );
        }
        // The two ends of the revision range are different faults, and the
        // generated encoder reports each under the category Rust reports.
        assert_ne!(
            declared.get("AUTOMATION_UNWRITTEN_REVISION"),
            declared.get("AUTOMATION_COUNTER_OUT_OF_RANGE"),
            "a revision of zero and a revision above the wire ceiling are different faults"
        );
        assert_eq!(
            declared.get(&surface.oversize_category).map(String::as_str),
            Some("frame_size"),
            "the oversize category is the spelling a transport would report; no shipped \
             transport carries this protocol yet, so nothing pins it"
        );
    }

    /// The SDK has no transport, and the generated file says so.
    #[test]
    fn the_generated_surface_says_the_framing_is_excluded() {
        let generated = generated_automation();
        for statement in [
            "The length-delimited framing this protocol travels under is not applied",
            "This package has no transport.",
            "The payload is the framed transport's payload, without its length prefix.",
        ] {
            assert!(
                generated.contains(statement),
                "the generated automation surface does not state where framing lives: {statement}"
            );
        }
    }

    /// The package typecheck actually reads the new files.
    #[test]
    fn the_typecheck_reads_the_automation_surface_and_its_runner() {
        let output = Command::new("npx")
            .arg("--offline")
            .arg("tsc")
            .arg("-p")
            .arg("./tsconfig.json")
            .arg("--listFiles")
            .current_dir(package_root())
            .output();
        let Ok(output) = output else {
            record_js_gap("tsc is unavailable; the automation surface is untypechecked");
            return;
        };
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success(),
            "the protocol package does not typecheck with the automation surface:\n{combined}"
        );
        for expected in [
            "generated/automation.ts",
            "generated/runtime.ts",
            "conformance/automation-api.ts",
        ] {
            assert!(
                combined.lines().any(|line| line.trim().ends_with(expected)),
                "tsc did not read {expected}; it is outside the tsconfig include globs, so \
                 nothing typechecks it.\n{combined}"
            );
        }
    }

    /// The heart of the wave: the generated TypeScript encodes the same bytes
    /// Rust does, decodes what Rust answers, refuses what Rust refuses, and
    /// accepts exactly the cross-field payloads it is documented not to judge.
    #[test]
    fn the_generated_typescript_agrees_with_rust_byte_for_byte() {
        let Some(runtime) = javascript_runtime() else {
            record_js_gap(
                "no JavaScript runtime; the automation surface is unmeasured across languages",
            );
            return;
        };
        let directory =
            std::env::temp_dir().join(format!("automonique-automation-api-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("scratch directory");
        let produced_path = directory.join("typescript-encodings.txt");

        let output = Command::new(runtime)
            .arg(runner_path())
            .arg(corpus_path())
            .arg(&produced_path)
            .current_dir(package_root())
            .output()
            .expect("the conformance runner starts");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success(),
            "the generated automation surface disagrees with the Rust corpus under {runtime}:\n\
             {combined}"
        );

        // The second direction: the runner reports the bytes it produced, and
        // they are compared here against what Rust encodes and then fed to the
        // shipped decoder.
        let reported = std::fs::read_to_string(&produced_path)
            .expect("the runner reports the payloads it produced");
        let mut produced: BTreeMap<String, Vec<u8>> = reported
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| {
                let (id, payload) = line
                    .split_once(' ')
                    .unwrap_or_else(|| panic!("a reported line is `<id> <hex>`: {line:?}"));
                (id.to_owned(), unhex(payload))
            })
            .collect();

        for case in request_cases() {
            let expected = case
                .request
                .to_message()
                .expect("the request encodes")
                .to_canonical_bytes();
            let actual = produced
                .remove(case.id)
                .unwrap_or_else(|| panic!("the runner did not report {}", case.id));
            assert_eq!(
                actual.len(),
                expected.len(),
                "{}: {runtime} produced {} canonical bytes, Rust produced {}",
                case.id,
                actual.len(),
                expected.len()
            );
            if let Some(index) = actual
                .iter()
                .zip(expected.iter())
                .position(|(left, right)| left != right)
            {
                let window = |bytes: &[u8]| {
                    String::from_utf8_lossy(
                        &bytes[index.saturating_sub(24)..(index + 24).min(bytes.len())],
                    )
                    .into_owned()
                };
                panic!(
                    "{}: the two encodings first differ at byte {index}\n  {runtime}: {}\n  \
                     rust: {}",
                    case.id,
                    window(&actual),
                    window(&expected)
                );
            }
            assert_eq!(
                AutomationRequest::from_canonical_bytes(&actual).unwrap_or_else(|error| panic!(
                    "{}: Rust refuses what {runtime} produced: {error}",
                    case.id
                )),
                case.request,
                "{}: Rust decodes what {runtime} produced as a different request",
                case.id
            );
        }
        assert!(
            produced.is_empty(),
            "the runner reported payloads the corpus has no cases for: {:?}",
            produced.keys().collect::<Vec<_>>()
        );
        println!(
            "automation api surface under {runtime}: {}",
            String::from_utf8_lossy(&output.stdout).trim()
        );
    }
}

/// The `automonique.approval` decision surface, measured across two languages.
///
/// The mechanism is the one [`command_surface`] established and
/// [`automation_surface`] last applied: `fixtures/approval-api-v1.json` is
/// generated from the shipped Rust constructors — every canonical byte string
/// was produced by encoding a real message and re-read through
/// `from_canonical_bytes` before it was written, every refusal category was read
/// back from the error Rust returned for that exact input, and every decoded
/// spelling came out of `ApprovalResponse::from_canonical_bytes` rather than out
/// of the value this file constructed.
///
/// # What this lane adds to what the other three already measured
///
/// **The write-once revision**, which is the first *durable-row* invariant to
/// cross into the generated surface rather than be recorded as a gap. The
/// automation lane could not hand a client its revision rule, because "withdrawn
/// implies revision two or above" relates two fields; this lane's rule is
/// `revision == 1` and nothing else, which is a bound on one field's own value.
/// It is generated as a bounded integer of domain `1..=1` and refused under the
/// category `ApprovalRecordView::new` answers, so a client can see for itself
/// that the row it decoded was never amended — and `decode_refusals` carries
/// both a `0` and a `2` to prove it.
///
/// **Four fail-closed vocabularies at once**, where the automation lane carried
/// two: a decision, a disposition, a conflict field and a refusal. Every one of
/// them has an undefined-spelling entry in `decode_refusals`, because a reader
/// that retained an unnameable answer to an approval question has no safe guess
/// available — treating it as a grant invents permission, and treating it as a
/// denial invents a refusal nobody made.
///
/// `rust_only_refusals` is correspondingly shorter than either of the two lanes
/// before it, and the three refusals that are *not* on it are named in
/// [`the_rust_only_list_is_the_whole_of_the_gap`] rather than left to be assumed
/// absent by accident.
mod approval_surface {
    use std::collections::{BTreeMap, BTreeSet};

    use automonique_protocol::approval_api::{
        APPROVAL_PROTOCOL, ApprovalApiError, ApprovalContinuation, ApprovalCursor,
        ApprovalDecision, ApprovalDisposition, ApprovalKey, ApprovalListPage, ApprovalPageSize,
        ApprovalReceiptView, ApprovalRecordParts, ApprovalRecordView, ApprovalRefusal,
        ApprovalRequest, ApprovalResponse, ApprovalSubject, ApprovalsBySubject, ConflictField,
        DecideRequest, Decider, ListApprovals, MAX_APPROVAL_API_FIELD_BYTES,
        MAX_APPROVAL_PAGE_ITEMS, RecordApproval, RecordedApproval,
    };
    use automonique_protocol::codec::{MAX_REQUEST_ID_BYTES, MajorVersion};
    use automonique_protocol::codegen::{
        APPROVAL_MODULE, CommandSurface, ConstantValue, REGENERATE_COMMAND, generated_files,
        maintained_modules, module_file_name,
    };
    use automonique_protocol::primitives::{EpochMillis, ValueError};

    use super::command_surface::{count, hex, raw_message, request_id, text, unhex, write_pretty};
    use super::*;

    fn corpus_path() -> PathBuf {
        crate_root().join("fixtures/approval-api-v1.json")
    }

    fn runner_path() -> PathBuf {
        package_root().join("conformance/approval-api.ts")
    }

    fn regenerating() -> bool {
        std::env::var(automonique_protocol::codegen::REGENERATE_ENV)
            .is_ok_and(|value| !value.is_empty() && value != "0")
    }

    /// The command surface the generator describes for this protocol.
    fn surface() -> CommandSurface {
        maintained_modules()
            .into_iter()
            .find(|module| module.file_name == module_file_name(APPROVAL_MODULE))
            .and_then(|module| module.command_surface)
            .expect("the approval module describes a command surface")
    }

    /// The generated TypeScript of the approval module.
    fn generated_approval() -> String {
        generated_files()
            .into_iter()
            .find(|(name, _)| *name == module_file_name(APPROVAL_MODULE))
            .map(|(_, contents)| contents)
            .expect("the approval module is generated")
    }

    fn key(value: &str) -> ApprovalKey {
        ApprovalKey::new(value).expect("a valid approval key")
    }

    fn subject(value: &str) -> ApprovalSubject {
        ApprovalSubject::new(value).expect("a valid subject")
    }

    fn decider(value: &str) -> Decider {
        Decider::new(value).expect("a valid decider")
    }

    fn page_size(items: usize) -> ApprovalPageSize {
        ApprovalPageSize::new(items).expect("a page size within the bound")
    }

    /// A decimal string, because the wire carries 64-bit values and a JSON
    /// reader that used a double would round the largest of them without saying
    /// so. Every counter in this corpus travels as text for that reason.
    fn number(value: u64) -> JsonValue {
        JsonValue::String(value.to_string())
    }

    /// The wire ceiling, which a decoder carrying counters in a double rounds.
    fn wire_ceiling() -> u64 {
        u64::try_from(i64::MAX).expect("the wire ceiling is positive")
    }

    /// An approval key carrying every escape a bounded identifier can reach, a
    /// three-byte character, a surrogate pair — and a space.
    ///
    /// The key is opaque to this protocol: it parses nothing, derives nothing
    /// and gives it no structure, so its grammar is the ledger's own and admits
    /// whitespace. A TypeScript brand that copied `DurableId`'s stricter grammar
    /// would refuse this fixture.
    fn escaping_key() -> String {
        "approval/\"deploy prod\" \\ naïve 日本語 🚀".to_owned()
    }

    fn escaping_subject() -> String {
        "effect:\"publish artifact\" \\ sha256:naïve 日本語 🚀".to_owned()
    }

    fn escaping_decider() -> String {
        "ops/\"oncall\" \\ naïve 日本語 🚀".to_owned()
    }

    /// A value inside the UTF-16 code-unit bound and outside the UTF-8 one.
    ///
    /// One hundred and twenty-nine two-byte characters: `value.length` in
    /// JavaScript counts 129, well under the bound, while the UTF-8 length Rust
    /// measures is 258 and over it. A generated constructor that measured code
    /// units would accept a value the daemon refuses, which is the one direction
    /// that matters.
    fn over_bound_by_bytes_only() -> String {
        "é".repeat(MAX_APPROVAL_API_FIELD_BYTES / 2 + 1)
    }

    /// One row's seven columns, in the shape the fixtures name them.
    ///
    /// A parameter object for the same reason [`ApprovalRecordParts`] is one:
    /// three bounded strings sit beside one another, and a transposed pair would
    /// type-check into a fixture that measured the wrong thing.
    struct Row<'a> {
        entry_id: u64,
        approval_key: &'a str,
        subject: &'a str,
        decision: ApprovalDecision,
        decider: &'a str,
        decided_at_ms: i64,
    }

    fn record(row: Row<'_>) -> ApprovalRecordView {
        ApprovalRecordView::new(ApprovalRecordParts {
            entry_id: row.entry_id,
            approval_key: key(row.approval_key),
            subject: subject(row.subject),
            decision: row.decision,
            decider: decider(row.decider),
            decided_at: EpochMillis::from_millis(row.decided_at_ms),
            // The only revision a write-once row can carry. The constructor
            // refuses anything else, so this is not a choice the fixtures make.
            revision: 1,
        })
        .expect("a well-formed decision row")
    }

    // -----------------------------------------------------------------------
    // Requests
    // -----------------------------------------------------------------------

    struct RequestCase {
        id: &'static str,
        note: &'static str,
        request: ApprovalRequest,
        /// Builder parameters, in the shape the runner reads for this kind.
        params: JsonValue,
    }

    fn request_cases() -> Vec<RequestCase> {
        let maximal_request_id = format!("req-{}", "a".repeat(MAX_REQUEST_ID_BYTES - 4));
        // Every character escapes to two bytes, which is the worst case this
        // protocol's own frame arithmetic budgets for.
        let maximal_key = "\"".repeat(MAX_APPROVAL_API_FIELD_BYTES);

        vec![
            RequestCase {
                id: "list-approvals-maximal",
                note: "every bound at once: a cursor at the wire's integer ceiling, the largest \
                       page this protocol serves, and a correlation identifier at \
                       MAX_REQUEST_ID_BYTES. A reader carrying the cursor in a double would \
                       encode 9223372036854775808 here without a word of complaint",
                request: ApprovalRequest::ListApprovals {
                    request_id: request_id(&maximal_request_id),
                    query: ListApprovals::new(
                        ApprovalCursor::new(wire_ceiling()),
                        page_size(MAX_APPROVAL_PAGE_ITEMS),
                    ),
                },
                params: JsonValue::Object(vec![
                    (
                        "page_size".to_owned(),
                        number(MAX_APPROVAL_PAGE_ITEMS as u64),
                    ),
                    ("since".to_owned(), number(wire_ceiling())),
                ]),
            },
            RequestCase {
                id: "list-approvals-start",
                note: "the beginning of the ledger: a cursor of zero, which is a position rather \
                       than the absence of one, and the smallest page that can make progress",
                request: ApprovalRequest::ListApprovals {
                    request_id: request_id("req-list-1"),
                    query: ListApprovals::new(ApprovalCursor::START, page_size(1)),
                },
                params: JsonValue::Object(vec![
                    ("page_size".to_owned(), number(1)),
                    ("since".to_owned(), number(0)),
                ]),
            },
            RequestCase {
                id: "record-approval-granted-escaping",
                note: "a grant whose key, subject and decider each carry every escape a bounded \
                       field can reach, a three-byte character and a surrogate pair; the key \
                       carries a space, which this lane's grammar admits because the ledger \
                       stores any bounded control-free identifier",
                request: ApprovalRequest::RecordApproval {
                    request_id: request_id("req-record-1"),
                    decision: RecordApproval::new(
                        key(&escaping_key()),
                        subject(&escaping_subject()),
                        ApprovalDecision::Granted,
                        decider(&escaping_decider()),
                    ),
                },
                params: JsonValue::Object(vec![
                    ("approval_key".to_owned(), text(&escaping_key())),
                    ("decider".to_owned(), text(&escaping_decider())),
                    ("decision".to_owned(), text("granted")),
                    ("subject".to_owned(), text(&escaping_subject())),
                ]),
            },
            RequestCase {
                id: "record-approval-denied-maximal",
                note: "a denial under a key at MAX_APPROVAL_API_FIELD_BYTES whose every \
                       character escapes to two bytes, which is the worst case this protocol's \
                       frame arithmetic budgets for. `denied` is a recorded answer and not a \
                       refusal: an unrecorded decision and a denied one are different facts",
                request: ApprovalRequest::RecordApproval {
                    request_id: request_id("req-record-2"),
                    decision: RecordApproval::new(
                        key(&maximal_key),
                        subject(&escaping_subject()),
                        ApprovalDecision::Denied,
                        decider("runbook/nightly-release"),
                    ),
                },
                params: JsonValue::Object(vec![
                    ("approval_key".to_owned(), text(&maximal_key)),
                    ("decider".to_owned(), text("runbook/nightly-release")),
                    ("decision".to_owned(), text("denied")),
                    ("subject".to_owned(), text(&escaping_subject())),
                ]),
            },
            RequestCase {
                id: "approval-detail-escaping",
                note: "one decision read by a key carrying every reachable escape",
                request: ApprovalRequest::ApprovalDetail {
                    request_id: request_id("req-detail-1"),
                    approval_key: key(&escaping_key()),
                },
                params: JsonValue::Object(vec![("approval_key".to_owned(), text(&escaping_key()))]),
            },
            RequestCase {
                id: "approvals-by-subject-maximal",
                note: "one subject's whole decision history at the wire's ceiling cursor and the \
                       largest page: the cursor is a position in the whole listing rather than \
                       in the matching subset, exactly as the ledger judges it",
                request: ApprovalRequest::ApprovalsBySubject {
                    request_id: request_id("req-subject-1"),
                    query: ApprovalsBySubject::new(
                        subject(&escaping_subject()),
                        ApprovalCursor::new(wire_ceiling()),
                        page_size(MAX_APPROVAL_PAGE_ITEMS),
                    ),
                },
                params: JsonValue::Object(vec![
                    (
                        "page_size".to_owned(),
                        number(MAX_APPROVAL_PAGE_ITEMS as u64),
                    ),
                    ("since".to_owned(), number(wire_ceiling())),
                    ("subject".to_owned(), text(&escaping_subject())),
                ]),
            },
            RequestCase {
                id: "approvals-by-subject-start",
                note: "the same read from the beginning, with the smallest page",
                request: ApprovalRequest::ApprovalsBySubject {
                    request_id: request_id("req-subject-2"),
                    query: ApprovalsBySubject::new(
                        subject("effect:publish-artifact"),
                        ApprovalCursor::START,
                        page_size(2),
                    ),
                },
                params: JsonValue::Object(vec![
                    ("page_size".to_owned(), number(2)),
                    ("since".to_owned(), number(0)),
                    ("subject".to_owned(), text("effect:publish-artifact")),
                ]),
            },
        ]
    }

    fn request_entry(case: &RequestCase) -> JsonValue {
        let message = case.request.to_message().expect("the request encodes");
        let canonical = message.to_canonical_bytes();
        // What the corpus records is checked against the shipped decoder before
        // it is written: a fixture Rust would not itself admit proves nothing.
        assert_eq!(
            ApprovalRequest::from_canonical_bytes(&canonical)
                .expect("Rust admits its own encoding"),
            case.request,
            "{}: the Rust decoder does not admit the Rust encoding",
            case.id
        );
        assert!(
            canonical.len() <= automonique_protocol::approval_api::MAX_APPROVAL_CANONICAL_BYTES,
            "{}: the encoding does not fit one approval frame",
            case.id
        );
        JsonValue::Object(vec![
            ("canonical_bytes".to_owned(), count(canonical.len())),
            ("canonical_hex".to_owned(), text(&hex(&canonical))),
            ("id".to_owned(), text(case.id)),
            ("kind".to_owned(), text(message.envelope().kind().as_str())),
            ("note".to_owned(), text(case.note)),
            ("params".to_owned(), case.params.clone()),
            (
                "request_id".to_owned(),
                text(message.envelope().request_id().as_str()),
            ),
        ])
    }

    // -----------------------------------------------------------------------
    // Responses
    // -----------------------------------------------------------------------

    struct ResponseCase {
        id: &'static str,
        note: &'static str,
        response: ApprovalResponse,
    }

    /// A whole-ledger listing answer built through the enforcement path rather
    /// than around it.
    ///
    /// `ApprovalResponse::listing` is what refuses a page longer than the query
    /// asked for, so a corpus entry that constructed the variant directly would
    /// record bytes no daemon could have produced.
    fn listing(id: &str, query: ListApprovals, page: ApprovalListPage) -> ApprovalResponse {
        ApprovalResponse::listing(request_id(id), query, page)
            .expect("the page answers the query it was built for")
    }

    /// A subject listing built through the stricter of the two paths.
    ///
    /// `subject_listing` additionally refuses a page carrying a decision
    /// recorded against another subject, which is the enforcement that module
    /// exists for.
    fn subject_listing(
        id: &str,
        query: &ApprovalsBySubject,
        page: ApprovalListPage,
    ) -> ApprovalResponse {
        ApprovalResponse::subject_listing(request_id(id), query, page)
            .expect("the page answers the subject it was built for")
    }

    /// A conflict built through the deriving constructor.
    ///
    /// `ApprovalResponse::conflict` compares the presented and recorded
    /// decisions in the order the ledger compares them and reports the first
    /// difference, so a fixture cannot name a field the two agree on.
    fn conflict(
        id: &str,
        presented: &RecordApproval,
        recorded: RecordedApproval,
    ) -> ApprovalResponse {
        ApprovalResponse::conflict(request_id(id), presented, recorded)
            .expect("two decisions that disagree")
    }

    fn presented_grant() -> RecordApproval {
        RecordApproval::new(
            key("approval/deploy-prod-2026-08-13"),
            subject("effect:publish-artifact"),
            ApprovalDecision::Granted,
            decider("ops/oncall"),
        )
    }

    fn response_cases() -> Vec<ResponseCase> {
        let whole_ledger =
            ListApprovals::new(ApprovalCursor::START, page_size(MAX_APPROVAL_PAGE_ITEMS));
        let by_subject = ApprovalsBySubject::new(
            subject(&escaping_subject()),
            ApprovalCursor::START,
            page_size(MAX_APPROVAL_PAGE_ITEMS),
        );

        vec![
            ResponseCase {
                id: "recorded-new",
                note: "the key was new, so this call is what made the decision durable. \
                       `accepted` rather than `completed`: the row is committed, but what it \
                       records has not taken effect and cannot, because no executor in this \
                       build consults the ledger before acting",
                response: ApprovalResponse::Recorded {
                    request_id: request_id("req-record-1"),
                    receipt: ApprovalReceiptView::new(
                        1,
                        key(&escaping_key()),
                        ApprovalDecision::Granted,
                        ApprovalDisposition::Recorded,
                        EpochMillis::from_millis(1_700_000_000_000),
                    )
                    .expect("a well-formed receipt"),
                },
            },
            ResponseCase {
                id: "recorded-already-at-ceiling",
                note: "an exact replay writes nothing and must never degrade into a refusal: the \
                       disposition says `already_recorded` and the instant is the *first* \
                       recording's, not this call's. Both counters sit at the wire's ceiling, \
                       which a decoder carrying them in a double would round to an even neighbour",
                response: ApprovalResponse::Recorded {
                    request_id: request_id("req-record-2"),
                    receipt: ApprovalReceiptView::new(
                        wire_ceiling(),
                        key("approval/deploy-prod-2026-08-13"),
                        ApprovalDecision::Denied,
                        ApprovalDisposition::AlreadyRecorded,
                        EpochMillis::from_millis(i64::MAX),
                    )
                    .expect("a well-formed receipt"),
                },
            },
            ResponseCase {
                id: "approval-list-page-more",
                note: "a page whose last row and whose continuation cursor are both at the \
                       wire's ceiling, carrying a grant beside a denial so both decision \
                       spellings travel in the same array",
                response: listing(
                    "approval-list-page-more",
                    whole_ledger,
                    ApprovalListPage::new(
                        vec![
                            record(Row {
                                entry_id: 1,
                                approval_key: "approval/first",
                                subject: "effect:publish-artifact",
                                decision: ApprovalDecision::Granted,
                                decider: "ops/oncall",
                                decided_at_ms: 1_700_000_000_000,
                            }),
                            record(Row {
                                entry_id: wire_ceiling() - 1,
                                approval_key: &escaping_key(),
                                subject: &escaping_subject(),
                                decision: ApprovalDecision::Denied,
                                decider: &escaping_decider(),
                                decided_at_ms: i64::MAX,
                            }),
                        ],
                        ApprovalContinuation::More(ApprovalCursor::new(wire_ceiling())),
                    )
                    .expect("a well-formed page"),
                ),
            },
            ResponseCase {
                id: "approval-list-page-complete",
                note: "the end of the ledger: `more` false and an explicit null cursor. A \
                       decision recorded at the epoch, which the ledger's own \
                       `decided_at_ms >= 0` constraint admits and one millisecond earlier does not",
                response: listing(
                    "approval-list-page-complete",
                    whole_ledger,
                    ApprovalListPage::new(
                        vec![record(Row {
                            entry_id: 9,
                            approval_key: "approval/only",
                            subject: "command:automonique.run.submit",
                            decision: ApprovalDecision::Denied,
                            decider: "ops/oncall",
                            decided_at_ms: 0,
                        })],
                        ApprovalContinuation::Complete,
                    )
                    .expect("a well-formed page"),
                ),
            },
            ResponseCase {
                id: "approval-list-page-empty-more",
                note: "an empty page that still reports more: a subject filter can exclude every \
                       row in one scanned window while rows remain behind it, so a client that \
                       inferred `done` from a short page would stop early",
                response: listing(
                    "approval-list-page-empty-more",
                    whole_ledger,
                    ApprovalListPage::new(
                        Vec::new(),
                        ApprovalContinuation::More(ApprovalCursor::new(42)),
                    )
                    .expect("an empty page may continue"),
                ),
            },
            ResponseCase {
                id: "approvals-by-subject-page",
                note: "one subject's history: a grant and the later denial that reconsidered it, \
                       in the order they were recorded, under two different keys. Which of them \
                       governs is not this protocol's answer, and it does not pretend to give one",
                response: subject_listing(
                    "approvals-by-subject-page",
                    &by_subject,
                    ApprovalListPage::new(
                        vec![
                            record(Row {
                                entry_id: 4,
                                approval_key: "approval/publish-2026-08-12",
                                subject: &escaping_subject(),
                                decision: ApprovalDecision::Granted,
                                decider: "ops/oncall",
                                decided_at_ms: 1_700_000_000_000,
                            }),
                            record(Row {
                                entry_id: 11,
                                approval_key: &escaping_key(),
                                subject: &escaping_subject(),
                                decision: ApprovalDecision::Denied,
                                decider: &escaping_decider(),
                                decided_at_ms: 1_700_000_009_000,
                            }),
                        ],
                        ApprovalContinuation::Complete,
                    )
                    .expect("a well-formed page"),
                ),
            },
            ResponseCase {
                id: "approval-detail-granted",
                note: "one decision in full, including the revision a reader checks for itself: \
                       one, and this build has no way to write anything else",
                response: ApprovalResponse::ApprovalDetail {
                    request_id: request_id("req-detail-1"),
                    record: record(Row {
                        entry_id: 4,
                        approval_key: &escaping_key(),
                        subject: &escaping_subject(),
                        decision: ApprovalDecision::Granted,
                        decider: &escaping_decider(),
                        decided_at_ms: 1_700_000_001_000,
                    }),
                },
            },
            ResponseCase {
                id: "conflict-decision",
                note: "the key is recorded with the other answer. Not a rejection and not a \
                       replay: nothing was written, and nothing ever will be for this key, \
                       because the ledger has no update path and a genuinely changed decision is \
                       a new key",
                response: conflict(
                    "req-record-1",
                    &presented_grant(),
                    RecordedApproval {
                        entry_id: 12,
                        subject: subject("effect:publish-artifact"),
                        decision: ApprovalDecision::Denied,
                        decider: decider("ops/oncall"),
                    },
                ),
            },
            ResponseCase {
                id: "conflict-subject-escaping",
                note: "the key was recorded describing something else, which the ledger compares \
                       first and this therefore reports; the recorded coordinates travel at the \
                       wire's ceiling row and carry every reachable escape, so a caller learns \
                       what it collided with without a second read",
                response: conflict(
                    "req-record-2",
                    &presented_grant(),
                    RecordedApproval {
                        entry_id: wire_ceiling(),
                        subject: subject(&escaping_subject()),
                        decision: ApprovalDecision::Denied,
                        decider: decider(&escaping_decider()),
                    },
                ),
            },
            ResponseCase {
                id: "conflict-decider",
                note: "the subject and the answer agree and the person does not, which is the \
                       third and last field the ledger compares. All three spellings of the \
                       conflict vocabulary reach this corpus",
                response: conflict(
                    "req-record-3",
                    &presented_grant(),
                    RecordedApproval {
                        entry_id: 13,
                        subject: subject("effect:publish-artifact"),
                        decision: ApprovalDecision::Granted,
                        decider: decider(&escaping_decider()),
                    },
                ),
            },
            ResponseCase {
                id: "refused-unknown-approval",
                note: "no decision is recorded under that key. This is not `the subject behind \
                       the key was refused`: an unrecorded decision and a denied one are \
                       different answers, and this protocol only ever makes the true one",
                response: ApprovalResponse::Refused {
                    request_id: request_id("req-detail-1"),
                    refusal: ApprovalRefusal::UnknownApproval,
                },
            },
            ResponseCase {
                id: "refused-ledger-full",
                note: "capacity is a refusal and never an eviction: forgetting a denied row \
                       would let the denied thing be presented again as a fresh, undecided \
                       request",
                response: ApprovalResponse::Refused {
                    request_id: request_id("req-record-1"),
                    refusal: ApprovalRefusal::LedgerFull,
                },
            },
        ]
    }

    /// How one decoded response is spelled in the corpus.
    ///
    /// Built from the value the *Rust decoder* recovered, and flattened with
    /// dotted keys so a nested page compares field by field rather than as one
    /// opaque blob.
    fn decoded_spelling(response: &ApprovalResponse) -> JsonValue {
        let mut fields = vec![(
            "request_id".to_owned(),
            text(response.request_id().as_str()),
        )];
        let record_fields =
            |prefix: &str, value: &ApprovalRecordView| -> Vec<(String, JsonValue)> {
                [
                    ("approval_key", text(value.approval_key().as_str())),
                    (
                        "decided_at_ms",
                        JsonValue::String(value.decided_at().as_millis().to_string()),
                    ),
                    ("decider", text(value.decider().as_str())),
                    ("decision", text(value.decision().as_str())),
                    ("entry_id", number(value.entry_id())),
                    ("revision", number(value.revision())),
                    ("subject", text(value.subject().as_str())),
                ]
                .into_iter()
                .map(|(name, spelled)| (format!("{prefix}{name}"), spelled))
                .collect()
            };
        match response {
            ApprovalResponse::Recorded { receipt, .. } => {
                fields.push((
                    "approval_key".to_owned(),
                    text(receipt.approval_key().as_str()),
                ));
                fields.push((
                    "decided_at_ms".to_owned(),
                    JsonValue::String(receipt.decided_at().as_millis().to_string()),
                ));
                fields.push(("decision".to_owned(), text(receipt.decision().as_str())));
                fields.push((
                    "disposition".to_owned(),
                    text(receipt.disposition().as_str()),
                ));
                fields.push(("entry_id".to_owned(), number(receipt.entry_id())));
            }
            ApprovalResponse::ApprovalList { page, .. } => {
                fields.push((
                    "approvals.len".to_owned(),
                    number(page.entries().len() as u64),
                ));
                fields.push((
                    "more".to_owned(),
                    text(&page.continuation().has_more().to_string()),
                ));
                fields.push((
                    "next_cursor".to_owned(),
                    match page.continuation().cursor() {
                        Some(cursor) => number(cursor.position()),
                        None => text("null"),
                    },
                ));
                for (index, carried) in page.entries().iter().enumerate() {
                    fields.extend(record_fields(&format!("approvals.{index}."), carried));
                }
            }
            ApprovalResponse::ApprovalDetail { record, .. } => {
                fields.extend(record_fields("", record));
            }
            ApprovalResponse::Conflict {
                field, recorded, ..
            } => {
                fields.push(("entry_id".to_owned(), number(recorded.entry_id)));
                fields.push(("field".to_owned(), text(field.as_str())));
                fields.push((
                    "recorded_decider".to_owned(),
                    text(recorded.decider.as_str()),
                ));
                fields.push((
                    "recorded_decision".to_owned(),
                    text(recorded.decision.as_str()),
                ));
                fields.push((
                    "recorded_subject".to_owned(),
                    text(recorded.subject.as_str()),
                ));
            }
            ApprovalResponse::Refused { refusal, .. } => {
                fields.push(("refusal".to_owned(), text(refusal.as_str())));
            }
        }
        JsonValue::Object(fields)
    }

    fn response_entry(case: &ResponseCase) -> JsonValue {
        let message = case.response.to_message().expect("the response encodes");
        let canonical = message.to_canonical_bytes();
        let decoded = ApprovalResponse::from_canonical_bytes(&canonical)
            .expect("Rust admits its own encoding");
        assert_eq!(
            decoded, case.response,
            "{}: the Rust decoder does not recover what it encoded",
            case.id
        );
        JsonValue::Object(vec![
            ("canonical_hex".to_owned(), text(&hex(&canonical))),
            ("decoded".to_owned(), decoded_spelling(&decoded)),
            ("id".to_owned(), text(case.id)),
            ("kind".to_owned(), text(message.envelope().kind().as_str())),
            ("note".to_owned(), text(case.note)),
            ("outcome".to_owned(), text(decoded.outcome().as_str())),
        ])
    }

    // -----------------------------------------------------------------------
    // Bodies, for the payloads no constructor would produce
    // -----------------------------------------------------------------------

    /// A well-formed record body, as a starting point for one that is not.
    fn record_body(overrides: &[(&str, JsonValue)]) -> JsonValue {
        let mut entries: Vec<(String, JsonValue)> = vec![
            ("approval_key".to_owned(), text("approval/deploy-prod")),
            (
                "decided_at_ms".to_owned(),
                JsonValue::Integer(1_700_000_000_000),
            ),
            ("decider".to_owned(), text("ops/oncall")),
            ("decision".to_owned(), text("granted")),
            ("entry_id".to_owned(), JsonValue::Integer(1)),
            ("revision".to_owned(), JsonValue::Integer(1)),
            ("subject".to_owned(), text("effect:publish-artifact")),
        ];
        for (name, value) in overrides {
            let slot = entries
                .iter_mut()
                .find(|(existing, _)| existing == name)
                .unwrap_or_else(|| panic!("{name} is not a record field"));
            slot.1 = value.clone();
        }
        JsonValue::Object(entries)
    }

    /// A well-formed receipt body.
    fn receipt_body(overrides: &[(&str, JsonValue)]) -> JsonValue {
        let mut entries: Vec<(String, JsonValue)> = vec![
            ("approval_key".to_owned(), text("approval/deploy-prod")),
            (
                "decided_at_ms".to_owned(),
                JsonValue::Integer(1_700_000_000_000),
            ),
            ("decision".to_owned(), text("granted")),
            ("disposition".to_owned(), text("recorded")),
            ("entry_id".to_owned(), JsonValue::Integer(1)),
        ];
        for (name, value) in overrides {
            let slot = entries
                .iter_mut()
                .find(|(existing, _)| existing == name)
                .unwrap_or_else(|| panic!("{name} is not a receipt field"));
            slot.1 = value.clone();
        }
        JsonValue::Object(entries)
    }

    /// A well-formed conflict body.
    fn conflict_body(overrides: &[(&str, JsonValue)]) -> JsonValue {
        let mut entries: Vec<(String, JsonValue)> = vec![
            ("entry_id".to_owned(), JsonValue::Integer(12)),
            ("field".to_owned(), text("decision")),
            ("recorded_decider".to_owned(), text("ops/oncall")),
            ("recorded_decision".to_owned(), text("denied")),
            (
                "recorded_subject".to_owned(),
                text("effect:publish-artifact"),
            ),
        ];
        for (name, value) in overrides {
            let slot = entries
                .iter_mut()
                .find(|(existing, _)| existing == name)
                .unwrap_or_else(|| panic!("{name} is not a conflict field"));
            slot.1 = value.clone();
        }
        JsonValue::Object(entries)
    }

    /// A page body carrying the given records and continuation.
    fn page_body(approvals: Vec<JsonValue>, more: bool, next_cursor: JsonValue) -> JsonValue {
        JsonValue::Object(vec![
            ("approvals".to_owned(), JsonValue::Array(approvals)),
            ("more".to_owned(), JsonValue::Bool(more)),
            ("next_cursor".to_owned(), next_cursor),
        ])
    }

    fn approval_message(kind: &str, id: &str, body: JsonValue) -> Vec<u8> {
        raw_message(APPROVAL_PROTOCOL, 1, kind, id, body)
    }

    /// One record wrapped in the smallest page that can carry it.
    fn one_record_page(record: JsonValue) -> Vec<u8> {
        approval_message(
            "approval_list_result",
            "req-list-1",
            page_body(vec![record], false, JsonValue::Null),
        )
    }

    // -----------------------------------------------------------------------
    // Refusals both implementations make
    // -----------------------------------------------------------------------

    struct DecodeRefusal {
        id: &'static str,
        note: &'static str,
        payload: Vec<u8>,
    }

    fn decode_refusals() -> Vec<DecodeRefusal> {
        // The page bound is judged before any item is read, in Rust and in the
        // generated TypeScript alike, so the over-bound payload carries integers
        // rather than bodies: what is wrong with it is its length.
        let filler: Vec<JsonValue> = (0..=MAX_APPROVAL_PAGE_ITEMS)
            .map(|index| JsonValue::Integer(index as i64))
            .collect();

        vec![
            DecodeRefusal {
                id: "decision-undefined-spelling",
                note: "a decision this build does not define fails closed rather than decoding \
                       to a default a client would act on. There is no safe guess here: reading \
                       it as a grant invents permission, and reading it as a denial invents a \
                       refusal nobody made",
                payload: one_record_page(record_body(&[("decision", text("abstained"))])),
            },
            DecodeRefusal {
                id: "disposition-undefined-spelling",
                note: "a disposition outside the two this build carries, on the answer a write \
                       returns; the vocabulary is closed on both sides of the wire",
                payload: approval_message(
                    "approval_recorded",
                    "req-record-1",
                    receipt_body(&[("disposition", text("superseded"))]),
                ),
            },
            DecodeRefusal {
                id: "conflict-field-undefined-spelling",
                note: "a conflict naming a field outside the three the ledger compares. A \
                       decoder cannot re-derive which field disagrees — a conflict carries only \
                       the recorded side — so holding the spelling closed is exactly what it can \
                       hold",
                payload: approval_message(
                    "approval_conflict",
                    "req-record-1",
                    conflict_body(&[("field", text("decided_at"))]),
                ),
            },
            DecodeRefusal {
                id: "refusal-undefined-spelling",
                note: "a refusal word outside the four this build carries",
                payload: approval_message(
                    "refused",
                    "req-record-1",
                    JsonValue::Object(vec![("refusal".to_owned(), text("not_authorized"))]),
                ),
            },
            DecodeRefusal {
                id: "entry-id-zero",
                note: "a durable identity starts at one; zero names a row no writer produced",
                payload: one_record_page(record_body(&[("entry_id", JsonValue::Integer(0))])),
            },
            DecodeRefusal {
                id: "entry-id-negative",
                note: "a negative identity is a malformed body rather than an unwritten row: the \
                       decoder converts before it judges the domain, and the two categories differ",
                payload: one_record_page(record_body(&[("entry_id", JsonValue::Integer(-1))])),
            },
            DecodeRefusal {
                id: "revision-two",
                note: "the write-once pin, met from above: the ledger has no update path at all, \
                       so a second revision names a row a second writer produced. This is the \
                       durable-row rule the generated surface *does* hold, because `revision == \
                       1` is a bound on one field's own value rather than a relation between two",
                payload: one_record_page(record_body(&[("revision", JsonValue::Integer(2))])),
            },
            DecodeRefusal {
                id: "revision-zero",
                note: "the same pin met from below, and under the same category: a write-once \
                       row that claims revision zero is as impossible as one that claims two",
                payload: one_record_page(record_body(&[("revision", JsonValue::Integer(0))])),
            },
            DecodeRefusal {
                id: "decided-at-before-epoch",
                note: "an instant the ledger's own `decided_at_ms >= 0` constraint cannot hold",
                payload: one_record_page(record_body(&[("decided_at_ms", JsonValue::Integer(-1))])),
            },
            DecodeRefusal {
                id: "receipt-decided-at-before-epoch",
                note: "the same constraint on the instant a write reports",
                payload: approval_message(
                    "approval_recorded",
                    "req-record-1",
                    receipt_body(&[("decided_at_ms", JsonValue::Integer(-1))]),
                ),
            },
            DecodeRefusal {
                id: "subject-empty",
                note: "an empty subject would answer `was this decided` and never `what was \
                       decided`, which is the whole reason the ledger stores a subject beside \
                       the key",
                payload: one_record_page(record_body(&[("subject", text(""))])),
            },
            DecodeRefusal {
                id: "decider-empty",
                note: "an empty decider names nobody. This lane records who answered, and an \
                       unattributed decision is the one it does not offer a spelling for",
                payload: one_record_page(record_body(&[("decider", text(""))])),
            },
            DecodeRefusal {
                id: "approval-key-over-bound-in-bytes-only",
                note: "129 two-byte characters: 129 UTF-16 code units, which a JavaScript \
                       `length` check would wave through, and 258 UTF-8 bytes, which is over the \
                       bound Rust and the ledger both measure",
                payload: one_record_page(record_body(&[(
                    "approval_key",
                    text(&over_bound_by_bytes_only()),
                )])),
            },
            DecodeRefusal {
                id: "decider-control-character",
                note: "a control character in a decider, which the wire never carries raw",
                payload: one_record_page(record_body(&[("decider", text("ops\u{7}oncall"))])),
            },
            DecodeRefusal {
                id: "page-over-bound",
                note: "one row past MAX_APPROVAL_PAGE_ITEMS. The length is judged before any \
                       item is read, so what these items are does not matter and the refusal \
                       names the length",
                payload: approval_message(
                    "approval_list_result",
                    "req-list-1",
                    page_body(filler, false, JsonValue::Null),
                ),
            },
            DecodeRefusal {
                id: "next-cursor-negative",
                note: "a cursor below the beginning of the listing",
                payload: approval_message(
                    "approval_list_result",
                    "req-list-1",
                    page_body(Vec::new(), true, JsonValue::Integer(-1)),
                ),
            },
            DecodeRefusal {
                id: "more-not-a-boolean",
                note: "the wire carries true or false for a continuation and nothing else",
                payload: approval_message(
                    "approval_list_result",
                    "req-list-1",
                    JsonValue::Object(vec![
                        ("approvals".to_owned(), JsonValue::Array(Vec::new())),
                        ("more".to_owned(), JsonValue::Integer(1)),
                        ("next_cursor".to_owned(), JsonValue::Null),
                    ]),
                ),
            },
            DecodeRefusal {
                id: "conflict-entry-id-zero",
                note: "a conflict pointing at a row no writer produced tells a caller it \
                       collided with nothing",
                payload: approval_message(
                    "approval_conflict",
                    "req-record-1",
                    conflict_body(&[("entry_id", JsonValue::Integer(0))]),
                ),
            },
            DecodeRefusal {
                id: "conflict-recorded-subject-empty",
                note: "the recorded coordinates are held to the same grammar as the ones a \
                       record carries; a conflict is evidence and not an error string",
                payload: approval_message(
                    "approval_conflict",
                    "req-record-1",
                    conflict_body(&[("recorded_subject", text(""))]),
                ),
            },
            DecodeRefusal {
                id: "page-extra-field",
                note: "an unexpected key is refused rather than ignored",
                payload: approval_message(
                    "approval_list_result",
                    "req-list-1",
                    JsonValue::Object(vec![
                        ("approvals".to_owned(), JsonValue::Array(Vec::new())),
                        ("more".to_owned(), JsonValue::Bool(false)),
                        ("next_cursor".to_owned(), JsonValue::Null),
                        ("total".to_owned(), JsonValue::Integer(1)),
                    ]),
                ),
            },
            DecodeRefusal {
                id: "record-missing-revision",
                note: "a missing key is refused rather than defaulted, inside a nested body as \
                       much as at the top level — and defaulting this one to `1` is exactly the \
                       shortcut that would make the write-once claim unfalsifiable",
                payload: one_record_page(JsonValue::Object(vec![
                    ("approval_key".to_owned(), text("approval/deploy-prod")),
                    (
                        "decided_at_ms".to_owned(),
                        JsonValue::Integer(1_700_000_000_000),
                    ),
                    ("decider".to_owned(), text("ops/oncall")),
                    ("decision".to_owned(), text("granted")),
                    ("entry_id".to_owned(), JsonValue::Integer(1)),
                    ("subject".to_owned(), text("effect:publish-artifact")),
                ])),
            },
            DecodeRefusal {
                id: "unknown-kind",
                note: "a kind this protocol version does not define, which is a different answer \
                       from a kind it defines and this surface does not decode",
                payload: approval_message(
                    "approval_history_result",
                    "req-list-1",
                    page_body(Vec::new(), false, JsonValue::Null),
                ),
            },
            DecodeRefusal {
                id: "automation-protocol-message",
                note: "the Automation lane's name on this lane's decoder, refused on the name \
                       axis so each protocol's closed kind set stays closed",
                payload: raw_message(
                    "automonique.automation",
                    1,
                    "approval_list_result",
                    "req-list-1",
                    page_body(Vec::new(), false, JsonValue::Null),
                ),
            },
            DecodeRefusal {
                id: "unsupported-version",
                note: "this protocol at a major version neither side implements",
                payload: raw_message(
                    APPROVAL_PROTOCOL,
                    2,
                    "approval_list_result",
                    "req-list-1",
                    page_body(Vec::new(), false, JsonValue::Null),
                ),
            },
            DecodeRefusal {
                id: "non-canonical-key-order",
                note: "a payload that parses but is not canonical is refused, not normalized",
                payload: br#"{"kind":"refused","body":{"refusal":"ledger_full"},"protocol":"automonique.approval","request_id":"req-record-1","version":1}"#.to_vec(),
            },
            DecodeRefusal {
                id: "empty-payload",
                note: "zero bytes is not an empty message",
                payload: Vec::new(),
            },
        ]
    }

    fn decode_refusal_entry(refusal: &DecodeRefusal) -> JsonValue {
        let category = ApprovalResponse::from_canonical_bytes(&refusal.payload)
            .err()
            .unwrap_or_else(|| panic!("{}: Rust accepted a payload it must refuse", refusal.id))
            .category()
            .to_owned();
        JsonValue::Object(vec![
            ("category".to_owned(), text(&category)),
            ("id".to_owned(), text(refusal.id)),
            ("note".to_owned(), text(refusal.note)),
            ("payload_hex".to_owned(), text(&hex(&refusal.payload))),
        ])
    }

    // -----------------------------------------------------------------------
    // The measured gap
    // -----------------------------------------------------------------------

    /// A payload the Rust decoder refuses and the generated TypeScript accepts.
    ///
    /// Every one of these breaks a rule relating two fields of a *decoded*
    /// message. The list is shorter than either lane before it, and
    /// [`the_rust_only_list_is_the_whole_of_the_gap`] names the three refusals
    /// that are deliberately absent from it — because they are not decoder rules
    /// on the Rust side either, and a gap list that claimed them would describe
    /// a gap that does not exist.
    struct RustOnlyRefusal {
        id: &'static str,
        note: &'static str,
        payload: Vec<u8>,
    }

    fn rust_only_refusals() -> Vec<RustOnlyRefusal> {
        vec![
            RustOnlyRefusal {
                id: "page-out-of-order",
                note: "records that do not strictly increase by durable row identity, so the \
                       next page would re-serve or skip",
                payload: approval_message(
                    "approval_list_result",
                    "req-list-1",
                    page_body(
                        vec![
                            record_body(&[("entry_id", JsonValue::Integer(5))]),
                            record_body(&[("entry_id", JsonValue::Integer(2))]),
                        ],
                        false,
                        JsonValue::Null,
                    ),
                ),
            },
            RustOnlyRefusal {
                id: "continuation-incoherent",
                note: "rows follow, with no cursor to resume from",
                payload: approval_message(
                    "approval_list_result",
                    "req-list-1",
                    page_body(Vec::new(), true, JsonValue::Null),
                ),
            },
            RustOnlyRefusal {
                id: "continuation-rewinds",
                note: "a continuation cursor below the last row on the page, which would \
                       re-serve it",
                payload: approval_message(
                    "approval_list_result",
                    "req-list-1",
                    page_body(
                        vec![record_body(&[("entry_id", JsonValue::Integer(9))])],
                        true,
                        JsonValue::Integer(4),
                    ),
                ),
            },
        ]
    }

    fn rust_only_entry(refusal: &RustOnlyRefusal) -> JsonValue {
        let category = ApprovalResponse::from_canonical_bytes(&refusal.payload)
            .err()
            .unwrap_or_else(|| {
                panic!(
                    "{}: Rust accepts this, so it is not a rule the generated surface is missing",
                    refusal.id
                )
            })
            .category()
            .to_owned();
        JsonValue::Object(vec![
            ("id".to_owned(), text(refusal.id)),
            ("note".to_owned(), text(refusal.note)),
            ("payload_hex".to_owned(), text(&hex(&refusal.payload))),
            ("rust_category".to_owned(), text(&category)),
        ])
    }

    // -----------------------------------------------------------------------
    // Encode refusals
    // -----------------------------------------------------------------------

    /// A request the other implementation must refuse while building it.
    struct EncodeRefusal {
        id: &'static str,
        note: &'static str,
        kind: &'static str,
        request_id: String,
        params: JsonValue,
        category: String,
        /// The generated constructor that refuses the value on its own, the
        /// parameter it is applied to, and the violation it names.
        constructor: Option<(&'static str, &'static str, &'static str)>,
    }

    /// The category Rust reports for a request body carrying this exact value.
    ///
    /// Read back from the shipped decoder rather than constructed here.
    fn wire_category(kind: &str, body: JsonValue) -> String {
        ApprovalRequest::from_canonical_bytes(&approval_message(kind, "req-1", body))
            .err()
            .unwrap_or_else(|| panic!("{kind}: Rust accepted a body it must refuse"))
            .category()
            .to_owned()
    }

    fn record_params(
        approval_key: &str,
        decider_name: &str,
        decision: &str,
        subject_name: &str,
    ) -> JsonValue {
        JsonValue::Object(vec![
            ("approval_key".to_owned(), text(approval_key)),
            ("decider".to_owned(), text(decider_name)),
            ("decision".to_owned(), text(decision)),
            ("subject".to_owned(), text(subject_name)),
        ])
    }

    fn list_params(size: JsonValue, since: JsonValue) -> JsonValue {
        JsonValue::Object(vec![
            ("page_size".to_owned(), size),
            ("since".to_owned(), since),
        ])
    }

    fn subject_params(size: JsonValue, since: JsonValue, subject_name: &str) -> JsonValue {
        JsonValue::Object(vec![
            ("page_size".to_owned(), size),
            ("since".to_owned(), since),
            ("subject".to_owned(), text(subject_name)),
        ])
    }

    fn encode_refusals() -> Vec<EncodeRefusal> {
        let over_bound = over_bound_by_bytes_only();
        let long_request_id = "r".repeat(MAX_REQUEST_ID_BYTES + 1);

        let page_size_out_of_range = ApprovalPageSize::new(0)
            .expect_err("a page that admits nothing is refused")
            .category()
            .to_owned();
        let cursor_out_of_range = ApprovalRequest::ListApprovals {
            request_id: request_id("req-list-1"),
            query: ListApprovals::new(ApprovalCursor::new(wire_ceiling() + 1), page_size(1)),
        }
        .to_message()
        .expect_err("a cursor above the wire ceiling is refused")
        .category()
        .to_owned();
        let long_id_refusal = ApprovalApiError::Codec(
            RequestId::new(&long_request_id).expect_err("an overlong request id is refused"),
        )
        .category()
        .to_owned();
        let bad_id_refusal = ApprovalApiError::Codec(
            RequestId::new("req 1").expect_err("a space is outside the request id grammar"),
        )
        .category()
        .to_owned();

        vec![
            EncodeRefusal {
                id: "record-approval-undefined-decision",
                note: "a brand exists only in the type checker, so the builder is where an \
                       untyped caller's undefined decision is stopped rather than put on the \
                       wire. `abstained` is not a word this ledger can store",
                kind: "record_approval",
                request_id: "req-record-1".to_owned(),
                params: record_params(
                    "approval/deploy-prod",
                    "ops/oncall",
                    "abstained",
                    "effect:publish-artifact",
                ),
                category: wire_category(
                    "record_approval",
                    record_params(
                        "approval/deploy-prod",
                        "ops/oncall",
                        "abstained",
                        "effect:publish-artifact",
                    ),
                ),
                constructor: None,
            },
            EncodeRefusal {
                id: "record-approval-decision-title-case",
                note: "the spelling is exact and lowercase: `Granted` is not `granted`, and a \
                       vocabulary that case-folded would admit words the ledger's CHECK refuses",
                kind: "record_approval",
                request_id: "req-record-1".to_owned(),
                params: record_params(
                    "approval/deploy-prod",
                    "ops/oncall",
                    "Granted",
                    "effect:publish-artifact",
                ),
                category: wire_category(
                    "record_approval",
                    record_params(
                        "approval/deploy-prod",
                        "ops/oncall",
                        "Granted",
                        "effect:publish-artifact",
                    ),
                ),
                constructor: None,
            },
            EncodeRefusal {
                id: "record-approval-subject-over-bound",
                note: "129 two-byte characters: inside the UTF-16 code-unit bound and outside \
                       the UTF-8 one the ledger stores under",
                kind: "record_approval",
                request_id: "req-record-1".to_owned(),
                params: record_params("approval/deploy-prod", "ops/oncall", "granted", &over_bound),
                category: ApprovalSubject::new(&over_bound)
                    .expect_err("an overlong subject is refused")
                    .category()
                    .to_owned(),
                constructor: Some(("ApprovalSubject", "subject", "too_long")),
            },
            EncodeRefusal {
                id: "record-approval-decider-empty",
                note: "empty is refused rather than read as `nobody`: an unattributed decision \
                       is the one this product does not offer a spelling for",
                kind: "record_approval",
                request_id: "req-record-1".to_owned(),
                params: record_params(
                    "approval/deploy-prod",
                    "",
                    "granted",
                    "effect:publish-artifact",
                ),
                category: Decider::new("")
                    .expect_err("an empty decider is refused")
                    .category()
                    .to_owned(),
                constructor: Some(("Decider", "decider", "empty")),
            },
            EncodeRefusal {
                id: "record-approval-key-control-character",
                note: "a control character in a key, which the wire never carries raw. A space \
                       *is* admitted here, which is the difference between this lane's grammar \
                       and the correlation identifier's",
                kind: "record_approval",
                request_id: "req-record-1".to_owned(),
                params: record_params(
                    "approval\u{7}deploy",
                    "ops/oncall",
                    "granted",
                    "effect:publish-artifact",
                ),
                category: wire_category(
                    "record_approval",
                    record_params(
                        "approval\u{7}deploy",
                        "ops/oncall",
                        "granted",
                        "effect:publish-artifact",
                    ),
                ),
                constructor: Some(("ApprovalKey", "approval_key", "invalid_character")),
            },
            EncodeRefusal {
                id: "list-approvals-page-size-zero",
                note: "a page that admits nothing cannot make progress, so zero is refused \
                       rather than treated as a default",
                kind: "list_approvals",
                request_id: "req-list-1".to_owned(),
                params: list_params(number(0), number(0)),
                category: page_size_out_of_range.clone(),
                constructor: Some(("ApprovalPageSize", "page_size", "out_of_range")),
            },
            EncodeRefusal {
                id: "list-approvals-page-size-above-bound",
                note: "one past MAX_APPROVAL_PAGE_ITEMS, which is thirty-two here and \
                       sixty-four on the Runs lane: a page bound follows the frame arithmetic of \
                       the rows it carries, and a decision row carries three maximal identifiers \
                       where a run summary carries one",
                kind: "list_approvals",
                request_id: "req-list-1".to_owned(),
                params: list_params(number(MAX_APPROVAL_PAGE_ITEMS as u64 + 1), number(0)),
                category: page_size_out_of_range.clone(),
                constructor: Some(("ApprovalPageSize", "page_size", "out_of_range")),
            },
            EncodeRefusal {
                id: "list-approvals-cursor-above-wire-ceiling",
                note: "a cursor one past the largest integer this wire carries, which is a \
                       counter refusal rather than a malformed body",
                kind: "list_approvals",
                request_id: "req-list-1".to_owned(),
                params: list_params(number(1), number(wire_ceiling() + 1)),
                category: cursor_out_of_range,
                constructor: Some(("ApprovalCursor", "since", "out_of_range")),
            },
            EncodeRefusal {
                id: "approvals-by-subject-page-size-above-bound",
                note: "the second listing obeys the same page bound as the first; they share one \
                       decoder in Rust and one branded type here, so they cannot disagree",
                kind: "approvals_by_subject",
                request_id: "req-subject-1".to_owned(),
                params: subject_params(
                    number(MAX_APPROVAL_PAGE_ITEMS as u64 + 1),
                    number(0),
                    "effect:publish-artifact",
                ),
                category: page_size_out_of_range,
                constructor: Some(("ApprovalPageSize", "page_size", "out_of_range")),
            },
            EncodeRefusal {
                id: "approvals-by-subject-subject-empty",
                note: "an empty subject names nothing to read the history of",
                kind: "approvals_by_subject",
                request_id: "req-subject-1".to_owned(),
                params: subject_params(number(1), number(0), ""),
                category: ApprovalSubject::new("")
                    .expect_err("an empty subject is refused")
                    .category()
                    .to_owned(),
                constructor: Some(("ApprovalSubject", "subject", "empty")),
            },
            EncodeRefusal {
                id: "approval-detail-key-empty",
                note: "an empty key names no decision",
                kind: "approval_detail",
                request_id: "req-detail-1".to_owned(),
                params: JsonValue::Object(vec![("approval_key".to_owned(), text(""))]),
                category: ApprovalKey::new("")
                    .expect_err("an empty key is refused")
                    .category()
                    .to_owned(),
                constructor: Some(("ApprovalKey", "approval_key", "empty")),
            },
            EncodeRefusal {
                id: "request-id-too-long",
                note: "the envelope's fields are judged by the shared codec, whose refusal for a \
                       bound is not the one this protocol uses for a body",
                kind: "approval_detail",
                request_id: long_request_id,
                params: JsonValue::Object(vec![(
                    "approval_key".to_owned(),
                    text("approval/deploy-prod"),
                )]),
                category: long_id_refusal,
                constructor: Some(("RequestId", "request_id", "too_long")),
            },
            EncodeRefusal {
                id: "request-id-outside-grammar",
                note: "a grammar refusal is not a bounds refusal, and the categories differ. A \
                       space is outside the correlation identifier's grammar and inside the \
                       approval key's, which is the difference this lane's looser identifier makes",
                kind: "approval_detail",
                request_id: "req 1".to_owned(),
                params: JsonValue::Object(vec![(
                    "approval_key".to_owned(),
                    text("approval/deploy prod"),
                )]),
                category: bad_id_refusal,
                constructor: Some(("RequestId", "request_id", "invalid_character")),
            },
        ]
    }

    fn encode_refusal_entry(refusal: &EncodeRefusal) -> JsonValue {
        let mut entry = vec![
            ("category".to_owned(), text(&refusal.category)),
            ("id".to_owned(), text(refusal.id)),
            ("kind".to_owned(), text(refusal.kind)),
            ("note".to_owned(), text(refusal.note)),
            ("params".to_owned(), refusal.params.clone()),
            ("request_id".to_owned(), text(&refusal.request_id)),
        ];
        if let Some((constructor, parameter, violation)) = refusal.constructor {
            // Named `refused_by` rather than `constructor`: a JSON object parsed
            // by a JavaScript reader inherits `constructor` from its prototype.
            entry.push(("refused_by".to_owned(), text(constructor)));
            entry.push(("refused_param".to_owned(), text(parameter)));
            entry.push(("violation".to_owned(), text(violation)));
        }
        JsonValue::Object(entry)
    }

    // -----------------------------------------------------------------------
    // The corpus file
    // -----------------------------------------------------------------------

    fn corpus() -> String {
        let document = JsonValue::Object(vec![
            (
                "decode_refusals".to_owned(),
                JsonValue::Array(decode_refusals().iter().map(decode_refusal_entry).collect()),
            ),
            (
                "encode_refusals".to_owned(),
                JsonValue::Array(encode_refusals().iter().map(encode_refusal_entry).collect()),
            ),
            (
                "generator".to_owned(),
                text("automonique-protocol tests/codegen.rs, module approval_surface"),
            ),
            (
                "note".to_owned(),
                text(
                    "Generated from the shipped Rust constructors: every canonical byte string \
                     here was produced by encoding a real message and re-read through \
                     from_canonical_bytes before it was written, and every refusal category was \
                     read back from the error Rust returned for that exact input. Counters \
                     travel as decimal strings because a JSON reader using a double would round \
                     the largest of them without saying so. Rust is the wire source of truth, so \
                     a disagreement is fixed in whichever implementation is wrong — never in \
                     this file.",
                ),
            ),
            ("protocol".to_owned(), text(APPROVAL_PROTOCOL)),
            (
                "requests".to_owned(),
                JsonValue::Array(request_cases().iter().map(request_entry).collect()),
            ),
            (
                "responses".to_owned(),
                JsonValue::Array(response_cases().iter().map(response_entry).collect()),
            ),
            (
                "rust_only_refusals".to_owned(),
                JsonValue::Array(rust_only_refusals().iter().map(rust_only_entry).collect()),
            ),
            (
                "rust_only_refusals_note".to_owned(),
                text(
                    "Payloads the Rust decoder refuses and the generated TypeScript accepts. \
                     Each breaks a rule relating two fields of a decoded message, which the \
                     generated surface does not hold. The write-once revision is deliberately \
                     absent from this list: `revision == 1` is a bound on one field's own value, \
                     the generated decoder does hold it, and decode_refusals is where that is \
                     proved from both ends. The runner asserts these decode, so the remaining \
                     gap is measured rather than described — teaching the generator one of these \
                     rules turns the suite red until the entry moves to decode_refusals.",
                ),
            ),
            (
                "version".to_owned(),
                JsonValue::Integer(i64::from(MajorVersion::FIRST.get())),
            ),
        ]);
        let mut out = String::new();
        write_pretty(&document, 0, &mut out);
        out.push('\n');
        out
    }

    /// The drift gate over the corpus, and the regeneration that closes it.
    #[test]
    fn the_checked_in_corpus_matches_regeneration() {
        let expected = corpus();
        let path = corpus_path();
        if regenerating() {
            let staging = path.with_extension("json.staging");
            std::fs::write(&staging, &expected).expect("stage the corpus");
            std::fs::rename(&staging, &path).expect("publish the corpus");
            return;
        }
        let actual = std::fs::read_to_string(&path)
            .expect("the corpus is checked in — regenerate it to create it");
        if actual != expected {
            let difference = actual
                .lines()
                .zip(expected.lines())
                .enumerate()
                .find(|(_, (left, right))| left != right)
                .map_or_else(
                    || {
                        format!(
                            "{} lines on disk, {} lines generated",
                            actual.lines().count(),
                            expected.lines().count()
                        )
                    },
                    |(index, (left, right))| {
                        let shorten = |line: &str| line.chars().take(120).collect::<String>();
                        format!(
                            "line {}: on disk {:?}, generated {:?}",
                            index + 1,
                            shorten(left),
                            shorten(right)
                        )
                    },
                );
            panic!(
                "the checked-in approval corpus no longer matches the Rust encoders: \
                 {difference}\n\nRegenerate with: {REGENERATE_COMMAND}"
            );
        }
    }

    /// Every request this protocol version defines is generated or named absent.
    #[test]
    fn every_request_kind_is_generated_or_named_as_absent() {
        let id = request_id("req-coverage-1");
        let requests = vec![
            ApprovalRequest::RecordApproval {
                request_id: id.clone(),
                decision: RecordApproval::new(
                    key("approval/1"),
                    subject("effect:one"),
                    ApprovalDecision::Granted,
                    decider("ops/oncall"),
                ),
            },
            ApprovalRequest::ListApprovals {
                request_id: id.clone(),
                query: ListApprovals::new(ApprovalCursor::START, page_size(1)),
            },
            ApprovalRequest::ApprovalDetail {
                request_id: id.clone(),
                approval_key: key("approval/1"),
            },
            ApprovalRequest::ApprovalsBySubject {
                request_id: id.clone(),
                query: ApprovalsBySubject::new(
                    subject("effect:one"),
                    ApprovalCursor::START,
                    page_size(1),
                ),
            },
            ApprovalRequest::DecideRequest {
                request_id: id,
                decision: DecideRequest::new(
                    key("apr-000102030405060708090a0b0c0d0e0f"),
                    ApprovalDecision::Granted,
                    decider("ops/oncall"),
                ),
            },
        ];
        // The match is the point: a request added to `ApprovalRequest` fails to
        // compile here rather than quietly falling outside the generated
        // surface.
        for request in &requests {
            match request {
                ApprovalRequest::RecordApproval { .. }
                | ApprovalRequest::ListApprovals { .. }
                | ApprovalRequest::ApprovalDetail { .. }
                | ApprovalRequest::ApprovalsBySubject { .. }
                | ApprovalRequest::DecideRequest { .. } => {}
            }
        }
        let encoded: BTreeSet<String> = requests
            .iter()
            .map(|request| {
                request
                    .to_message()
                    .expect("each request encodes")
                    .envelope()
                    .kind()
                    .as_str()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            encoded.len(),
            requests.len(),
            "one request per variant is required, each with its own kind"
        );

        let surface = surface();
        let mut covered: BTreeSet<String> = surface
            .requests
            .iter()
            .map(|request| request.kind.clone())
            .collect();
        for kind in &surface.request_kinds_not_generated {
            assert!(
                covered.insert(kind.clone()),
                "{kind} is both generated and named as absent"
            );
        }
        assert_eq!(
            covered, encoded,
            "the generated approval surface does not account for every request kind the Rust \
             encoders produce; regenerate with: {REGENERATE_COMMAND}"
        );
    }

    /// Every answer this protocol version defines is decoded or named undecoded.
    #[test]
    fn every_response_kind_is_decoded_or_named_as_undecoded() {
        let id = request_id("req-coverage-1");
        let responses = vec![
            ApprovalResponse::Recorded {
                request_id: id.clone(),
                receipt: ApprovalReceiptView::new(
                    1,
                    key("approval/1"),
                    ApprovalDecision::Granted,
                    ApprovalDisposition::Recorded,
                    EpochMillis::from_millis(0),
                )
                .expect("a receipt"),
            },
            ApprovalResponse::ApprovalList {
                request_id: id.clone(),
                page: ApprovalListPage::new(Vec::new(), ApprovalContinuation::Complete)
                    .expect("a page"),
            },
            ApprovalResponse::ApprovalDetail {
                request_id: id.clone(),
                record: record(Row {
                    entry_id: 1,
                    approval_key: "approval/1",
                    subject: "effect:one",
                    decision: ApprovalDecision::Granted,
                    decider: "ops/oncall",
                    decided_at_ms: 0,
                }),
            },
            ApprovalResponse::conflict(
                id.clone(),
                &presented_grant(),
                RecordedApproval {
                    entry_id: 2,
                    subject: subject("effect:publish-artifact"),
                    decision: ApprovalDecision::Denied,
                    decider: decider("ops/oncall"),
                },
            )
            .expect("a conflict"),
            ApprovalResponse::Refused {
                request_id: id,
                refusal: ApprovalRefusal::UnknownApproval,
            },
        ];
        // The match is the point: a variant added to `ApprovalResponse` fails to
        // compile here rather than slipping past a surface that ignores it.
        for response in &responses {
            match response {
                ApprovalResponse::Recorded { .. }
                | ApprovalResponse::ApprovalList { .. }
                | ApprovalResponse::ApprovalDetail { .. }
                | ApprovalResponse::Conflict { .. }
                | ApprovalResponse::Refused { .. } => {}
            }
        }
        let encoded: BTreeSet<String> = responses
            .iter()
            .map(|response| {
                response
                    .to_message()
                    .expect("each response encodes")
                    .envelope()
                    .kind()
                    .as_str()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            encoded.len(),
            responses.len(),
            "one response per variant is required, each with its own kind"
        );

        let surface = surface();
        let mut covered: BTreeSet<String> = surface
            .responses
            .iter()
            .map(|response| response.kind.clone())
            .collect();
        for kind in &surface.response_kinds_not_decoded {
            assert!(
                covered.insert(kind.clone()),
                "{kind} is both decoded and named as undecoded"
            );
        }
        assert_eq!(
            covered, encoded,
            "the generated approval surface does not account for every answer the daemon can \
             produce; regenerate with: {REGENERATE_COMMAND}"
        );
    }

    /// The four closed vocabularies, restated here rather than read back from
    /// the generator.
    ///
    /// A generator that dropped a variant would agree with itself perfectly.
    /// This is the second opinion, and it is spelled out literally: these are
    /// the words the durable ledger's `CHECK` constraints hold, and this crate
    /// does not depend on that one, so the agreement is asserted rather than
    /// derived.
    #[test]
    fn every_closed_vocabulary_carries_all_of_its_variants() {
        let generated = generated_approval();
        let expected: [(&str, &[&str]); 4] = [
            ("ApprovalConflictField", &["decider", "decision", "subject"]),
            ("ApprovalDecision", &["denied", "granted"]),
            ("ApprovalDisposition", &["already_recorded", "recorded"]),
            (
                "ApprovalRefusal",
                &[
                    "already_decided",
                    "cursor_out_of_range",
                    "invalid_field",
                    "ledger_full",
                    "request_expired",
                    "unknown_approval",
                    "unknown_request",
                ],
            ),
        ];
        for (name, values) in expected {
            let literals: Vec<String> = values.iter().map(|value| format!("\"{value}\"")).collect();
            let declaration = format!("export type {name} = {};", literals.join(" | "));
            assert!(
                generated.contains(&declaration),
                "the approval surface lost a {name} variant.\nexpected: {declaration}"
            );
            assert!(
                generated.contains(&format!(
                    "export const {name}_VALUES: readonly {name}[] = [{}];",
                    literals.join(", ")
                )),
                "the {name} table does not match its type"
            );
            assert!(
                generated.contains(&format!(
                    "export function decode{name}(value: string): {name} {{"
                )),
                "the approval surface does not refuse an undefined {name}"
            );
        }
        // The spellings themselves, read from the Rust enums rather than from
        // the literals above, so the two can never drift into agreeing with
        // each other while disagreeing with the wire.
        assert_eq!(
            ApprovalDecision::ALL.map(ApprovalDecision::as_str),
            ["granted", "denied"],
            "the decision vocabulary is the pair the ledger's CHECK stores"
        );
        assert_eq!(
            ApprovalDisposition::ALL.map(ApprovalDisposition::as_str),
            ["recorded", "already_recorded"],
            "an exact replay is a disposition and never a refusal"
        );
        assert_eq!(
            ConflictField::ALL.map(ConflictField::as_str),
            ["subject", "decision", "decider"],
            "the conflict fields are the three the ledger compares, in that order"
        );
        // A `pending` or an `expired` decision would be a decision nobody made,
        // which has no row. The generated union must not carry one.
        for absent in ["pending", "expired", "revoked", "allow", "deny"] {
            assert!(
                !generated.contains(&format!("\"{absent}\"")),
                "the approval surface carries a decision spelling this product does not \
                 define: {absent}"
            );
        }
    }

    /// The bounds in the output are the Rust constants, and they are applied.
    #[test]
    fn the_generated_approval_bounds_are_the_rust_constants() {
        let generated = generated_approval();
        for declaration in [
            format!("export const MAX_APPROVAL_PAGE_ITEMS = {MAX_APPROVAL_PAGE_ITEMS};"),
            format!(
                "export const MAX_APPROVAL_CANONICAL_BYTES = {};",
                automonique_protocol::approval_api::MAX_APPROVAL_CANONICAL_BYTES
            ),
            format!("export const ApprovalKey_MAX_BYTES = {MAX_APPROVAL_API_FIELD_BYTES};"),
            format!("export const ApprovalSubject_MAX_BYTES = {MAX_APPROVAL_API_FIELD_BYTES};"),
            format!("export const Decider_MAX_BYTES = {MAX_APPROVAL_API_FIELD_BYTES};"),
            format!("export const ApprovalPageSize_MAX = {MAX_APPROVAL_PAGE_ITEMS}n;"),
            "export const ApprovalPageSize_MIN = 1n;".to_owned(),
            "export const ApprovalCursor_MIN = 0n;".to_owned(),
            format!("export const ApprovalCursor_MAX = {}n;", i64::MAX),
            // The write-once pin: a domain of exactly one value.
            "export const ApprovalRevision_MIN = 1n;".to_owned(),
            "export const ApprovalRevision_MAX = 1n;".to_owned(),
            format!("export const APPROVAL_PROTOCOL = \"{APPROVAL_PROTOCOL}\";"),
            format!(
                "export const APPROVAL_API_SCHEMA_V1 = \"{}\";",
                automonique_protocol::approval_api::APPROVAL_API_SCHEMA_V1
            ),
        ] {
            assert!(
                generated.contains(&declaration),
                "the approval surface does not carry the Rust bound: {declaration}"
            );
        }
        // Declaring a bound is not applying it.
        for application in [
            format!(
                "  if (byteLength(value) > {MAX_APPROVAL_API_FIELD_BYTES}) throw new \
                 ValidationError(\"ApprovalKey\", \"too_long\");"
            ),
            format!(
                "  if (byteLength(value) > {MAX_APPROVAL_API_FIELD_BYTES}) throw new \
                 ValidationError(\"Decider\", \"too_long\");"
            ),
            format!(
                "  if (typeof value !== \"bigint\" || value < 1n || value > {MAX_APPROVAL_PAGE_ITEMS}n) throw new \
                 ValidationError(\"ApprovalPageSize\", \"out_of_range\");"
            ),
            "  if (typeof value !== \"bigint\" || value < 1n || value > 1n) throw new ValidationError(\"ApprovalRevision\", \
             \"out_of_range\");"
                .to_owned(),
            "bodyArray(fields, \"approvals\", APPROVAL_INVALID_BODY, MAX_APPROVAL_PAGE_ITEMS, \
             APPROVAL_PAGE_TOO_LARGE)"
                .to_owned(),
            "revision: refuse(APPROVAL_ROW_AMENDED, () => ApprovalRevision(bodyUnsigned(fields, \
             \"revision\", APPROVAL_INVALID_BODY)))"
                .to_owned(),
        ] {
            assert!(
                generated.contains(&application),
                "the approval surface declares a bound it does not apply: {application}"
            );
        }
        // The key's grammar is the ledger's own looser one, not `DurableId`'s:
        // the registry stores any bounded control-free identifier, and a wire
        // type stricter than the table would make a stored row unreadable.
        assert!(
            generated.contains("export const ApprovalKey_PATTERN = /^[^\\p{Cc}]+$/u;"),
            "the approval key does not carry the control-free grammar the durable ledger stores \
             under"
        );
        // The page bound is this lane's own, not the Runs lane's.
        assert_ne!(
            MAX_APPROVAL_PAGE_ITEMS,
            automonique_protocol::runs_api::MAX_RUN_PAGE_ITEMS,
            "this check is only worth making while the two page bounds differ"
        );
    }

    /// Every category the generated code refuses with is declared, and every
    /// declared category is a spelling Rust actually produces.
    #[test]
    fn every_refusal_category_is_declared_and_is_the_rust_spelling() {
        let surface = surface();
        let declared: BTreeMap<String, String> = surface
            .categories
            .iter()
            .map(|constant| {
                let ConstantValue::Text(value) = &constant.value else {
                    panic!("{} is a refusal category, which is text", constant.name)
                };
                (constant.name.clone(), value.clone())
            })
            .collect();

        let mut referenced = vec![
            surface.invalid_body_category.clone(),
            surface.unknown_kind_category.clone(),
            surface.oversize_category.clone(),
            surface.field_invalid_category.clone(),
            surface.field_grammar_category.clone(),
        ];
        referenced.extend(referenced_categories(&surface));
        for name in &referenced {
            assert!(
                declared.contains_key(name),
                "the approval surface refuses with {name}, which it does not declare"
            );
        }

        let generated = generated_approval();
        for (name, expected) in [
            (
                "APPROVAL_INVALID_BODY",
                ApprovalApiError::InvalidBody.category(),
            ),
            (
                "APPROVAL_UNKNOWN_KIND",
                ApprovalApiError::UnknownKind.category(),
            ),
            (
                "APPROVAL_ROW_AMENDED",
                ApprovalApiError::RowAmended { revision: 2 }.category(),
            ),
            (
                "APPROVAL_UNWRITTEN_ROW",
                ApprovalApiError::UnwrittenRow { field: "entry_id" }.category(),
            ),
            (
                "APPROVAL_PAGE_TOO_LARGE",
                ApprovalApiError::PageTooLarge {
                    max_items: 0,
                    actual_items: 0,
                }
                .category(),
            ),
            (
                "APPROVAL_PAGE_SIZE_OUT_OF_RANGE",
                ApprovalApiError::PageSizeOutOfRange {
                    max_items: 0,
                    requested: 0,
                }
                .category(),
            ),
            (
                "APPROVAL_TIME_BEFORE_EPOCH",
                ApprovalApiError::TimeBeforeEpoch {
                    field: "decided_at_ms",
                }
                .category(),
            ),
            (
                "APPROVAL_COUNTER_OUT_OF_RANGE",
                ApprovalApiError::CounterOutOfRange { field: "since" }.category(),
            ),
            (
                "APPROVAL_UNKNOWN_ENUM_VALUE",
                ApprovalApiError::Codec(
                    automonique_protocol::codec::CodecError::UnknownEnumValue { field: "decision" },
                )
                .category(),
            ),
            (
                "APPROVAL_INVALID_FIELD",
                ApprovalApiError::Field {
                    field: "approval_key",
                    error: ValueError::Empty,
                }
                .category(),
            ),
        ] {
            assert_eq!(
                declared.get(name).map(String::as_str),
                Some(expected),
                "{name} is not the category Rust reports"
            );
            assert!(
                generated.contains(&format!("export const {name} = \"{expected}\";")),
                "the generated file does not carry {name} as {expected}"
            );
        }
        // An amended write-once row and an unwritten one are different faults,
        // and a caller told the wrong one cannot act on what it was told.
        assert_ne!(
            declared.get("APPROVAL_ROW_AMENDED"),
            declared.get("APPROVAL_UNWRITTEN_ROW"),
            "a revision other than one and a row identity of zero are different faults"
        );
        assert_eq!(
            declared.get(&surface.oversize_category).map(String::as_str),
            Some("frame_size"),
            "the oversize category is the spelling a transport would report; no shipped \
             transport carries this protocol yet, so nothing pins it"
        );
    }

    /// The gap list is the whole of the gap, and the refusals absent from it are
    /// absent for a stated reason.
    ///
    /// Three of this lane's refusals never reach a decoder on *either* side:
    /// two relate an answer to the query it answers, and one is derived at the
    /// answering end from both sides of a comparison a conflict frame only
    /// carries one half of. Listing them as gaps would claim the generated
    /// surface is missing something Rust has; this asserts the opposite, so a
    /// later change that moved one of them into `ApprovalResponse::from_canonical_bytes`
    /// turns the suite red until the corpus grows an entry for it.
    #[test]
    fn the_rust_only_list_is_the_whole_of_the_gap() {
        let recorded: BTreeSet<&str> = rust_only_refusals()
            .iter()
            .map(|refusal| refusal.id)
            .collect();
        assert_eq!(
            recorded,
            BTreeSet::from([
                "continuation-incoherent",
                "continuation-rewinds",
                "page-out-of-order",
            ]),
            "the measured gap changed without the reason for it changing"
        );

        // A page longer than the query asked for: refused by the *constructor*
        // that answers a listing, not by any decoder, because a decoded frame
        // does not carry the query it answers.
        let query = ListApprovals::new(ApprovalCursor::START, page_size(1));
        let page = ApprovalListPage::new(
            vec![
                record(Row {
                    entry_id: 1,
                    approval_key: "approval/1",
                    subject: "effect:one",
                    decision: ApprovalDecision::Granted,
                    decider: "ops/oncall",
                    decided_at_ms: 0,
                }),
                record(Row {
                    entry_id: 2,
                    approval_key: "approval/2",
                    subject: "effect:one",
                    decision: ApprovalDecision::Denied,
                    decider: "ops/oncall",
                    decided_at_ms: 1,
                }),
            ],
            ApprovalContinuation::Complete,
        )
        .expect("a well-formed page");
        let refused = ApprovalResponse::listing(request_id("req-list-1"), query, page.clone())
            .expect_err("a page longer than the query asked for is refused");
        assert_eq!(refused.category(), "approval_page_above_requested_size");
        // And the same bytes decode, on both sides: the encoded form of that
        // very page carries nothing a decoder could judge it by.
        let served = ApprovalResponse::ApprovalList {
            request_id: request_id("req-list-1"),
            page,
        };
        let canonical = served
            .to_message()
            .expect("the page encodes")
            .to_canonical_bytes();
        assert!(
            ApprovalResponse::from_canonical_bytes(&canonical).is_ok(),
            "the Rust decoder judges a page against a query it cannot see"
        );

        // A conflict that names a field the two decisions agree on: refused by
        // the deriving constructor, which holds both sides. A decoder holds one.
        let presented = presented_grant();
        let replay = ApprovalResponse::conflict(
            request_id("req-record-1"),
            &presented,
            RecordedApproval {
                entry_id: 12,
                subject: subject("effect:publish-artifact"),
                decision: ApprovalDecision::Granted,
                decider: decider("ops/oncall"),
            },
        )
        .expect_err("a conflict with nothing to disagree about is refused");
        assert_eq!(replay.category(), "approval_conflict_without_disagreement");
    }

    /// The SDK has no transport, and the generated file says so.
    #[test]
    fn the_generated_surface_says_the_framing_is_excluded() {
        let generated = generated_approval();
        for statement in [
            "The length-delimited framing this protocol travels under is not applied",
            "This package has no transport.",
            "The payload is the framed transport's payload, without its length prefix.",
        ] {
            assert!(
                generated.contains(statement),
                "the generated approval surface does not state where framing lives: {statement}"
            );
        }
    }

    /// The package typecheck actually reads the new files.
    #[test]
    fn the_typecheck_reads_the_approval_surface_and_its_runner() {
        let output = Command::new("npx")
            .arg("--offline")
            .arg("tsc")
            .arg("-p")
            .arg("./tsconfig.json")
            .arg("--listFiles")
            .current_dir(package_root())
            .output();
        let Ok(output) = output else {
            record_js_gap("tsc is unavailable; the approval surface is untypechecked");
            return;
        };
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success(),
            "the protocol package does not typecheck with the approval surface:\n{combined}"
        );
        for expected in [
            "generated/approval.ts",
            "generated/runtime.ts",
            "conformance/approval-api.ts",
        ] {
            assert!(
                combined.lines().any(|line| line.trim().ends_with(expected)),
                "tsc did not read {expected}; it is outside the tsconfig include globs, so \
                 nothing typechecks it.\n{combined}"
            );
        }
    }

    /// The heart of the lane: the generated TypeScript encodes the same bytes
    /// Rust does, decodes what Rust answers, refuses what Rust refuses, and
    /// accepts exactly the cross-field payloads it is documented not to judge.
    #[test]
    fn the_generated_typescript_agrees_with_rust_byte_for_byte() {
        let Some(runtime) = javascript_runtime() else {
            record_js_gap(
                "no JavaScript runtime; the approval surface is unmeasured across languages",
            );
            return;
        };
        let directory =
            std::env::temp_dir().join(format!("automonique-approval-api-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("scratch directory");
        let produced_path = directory.join("typescript-encodings.txt");

        let output = Command::new(runtime)
            .arg(runner_path())
            .arg(corpus_path())
            .arg(&produced_path)
            .current_dir(package_root())
            .output()
            .expect("the conformance runner starts");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success(),
            "the generated approval surface disagrees with the Rust corpus under {runtime}:\n\
             {combined}"
        );

        // The second direction: the runner reports the bytes it produced, and
        // they are compared here against what Rust encodes and then fed to the
        // shipped decoder.
        let reported = std::fs::read_to_string(&produced_path)
            .expect("the runner reports the payloads it produced");
        let mut produced: BTreeMap<String, Vec<u8>> = reported
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| {
                let (id, payload) = line
                    .split_once(' ')
                    .unwrap_or_else(|| panic!("a reported line is `<id> <hex>`: {line:?}"));
                (id.to_owned(), unhex(payload))
            })
            .collect();

        for case in request_cases() {
            let expected = case
                .request
                .to_message()
                .expect("the request encodes")
                .to_canonical_bytes();
            let actual = produced
                .remove(case.id)
                .unwrap_or_else(|| panic!("the runner did not report {}", case.id));
            assert_eq!(
                actual.len(),
                expected.len(),
                "{}: {runtime} produced {} canonical bytes, Rust produced {}",
                case.id,
                actual.len(),
                expected.len()
            );
            if let Some(index) = actual
                .iter()
                .zip(expected.iter())
                .position(|(left, right)| left != right)
            {
                let window = |bytes: &[u8]| {
                    String::from_utf8_lossy(
                        &bytes[index.saturating_sub(24)..(index + 24).min(bytes.len())],
                    )
                    .into_owned()
                };
                panic!(
                    "{}: the two encodings first differ at byte {index}\n  {runtime}: {}\n  \
                     rust: {}",
                    case.id,
                    window(&actual),
                    window(&expected)
                );
            }
            assert_eq!(
                ApprovalRequest::from_canonical_bytes(&actual).unwrap_or_else(|error| panic!(
                    "{}: Rust refuses what {runtime} produced: {error}",
                    case.id
                )),
                case.request,
                "{}: Rust decodes what {runtime} produced as a different request",
                case.id
            );
        }
        assert!(
            produced.is_empty(),
            "the runner reported payloads the corpus has no cases for: {:?}",
            produced.keys().collect::<Vec<_>>()
        );
        println!(
            "approval api surface under {runtime}: {}",
            String::from_utf8_lossy(&output.stdout).trim()
        );
    }
}

/// The `automonique.batch.control` surface, measured across two languages.
///
/// The mechanism is the one [`command_surface`] established and
/// [`approval_surface`] last applied: `fixtures/batch-api-v1.json` is generated
/// from the shipped Rust constructors — every canonical byte string was produced
/// by encoding a real message and re-read through `from_canonical_bytes` before
/// it was written, every refusal category was read back from the error Rust
/// returned for that exact input, and every decoded spelling came out of
/// `BatchResponse::from_canonical_bytes` rather than out of the value this file
/// constructed.
///
/// # What this lane adds to what the four before it measured
///
/// **A discriminated body.** A concurrency policy is one wire object with two
/// keys where exactly one word carries a number, and the generated surface
/// carries it as a TypeScript discriminated union rather than as a struct with a
/// nullable field. The two shapes are not the same claim, and the difference is
/// measured from four sides: the union round-trips through both languages, a
/// `sequential` carrying a ceiling and a `bounded_parallel` without one are
/// refused on the way out *and* on the way in, and the ceiling's two ends —
/// zero, and above what a batch could ever place in flight — are different
/// refusals rather than one.
///
/// **A bounded list on the way out.** `register_batch` carries the membership
/// itself, so the generated encoder holds this lane's own ceiling: the maximal
/// registration in this corpus is `MAX_BATCH_CONTROL_MEMBERS` keys at
/// `MAX_BATCH_MEMBER_KEY_BYTES`, every character of which escapes to two
/// canonical bytes. That is the frame arithmetic
/// [`MAX_BATCH_CONTROL_MEMBERS`](automonique_protocol::batch_api::MAX_BATCH_CONTROL_MEMBERS)
/// is derived from, exercised rather than asserted — and it is built on both
/// sides from a rule rather than recorded as a 33 KiB literal, exactly as the
/// admin lane's maximal document is.
///
/// **Three vocabularies that are not this lane's.** `ConcurrencyKind`,
/// `MemberProgress` and `BatchState` come from
/// [`automonique_protocol::batch_runner`], and `MemberProgress` in turn reuses
/// [`RunState`](automonique_protocol::runs_api::RunState)'s six spellings. The
/// generated enums are asserted against those Rust arrays rather than against a
/// list retyped here, so a word cannot drift between a batch document and a
/// batch control message — there is only one word.
///
/// `rust_only_refusals` is longer here than on any lane before it, and that is
/// the honest shape of a batch: a batch *is* a relation between its members, so
/// most of what makes one believable relates two fields. The rollup that a
/// detail read carries is the one that matters most, and
/// [`the_rust_only_list_is_the_whole_of_the_gap`] holds the list to exactly what
/// it claims.
mod batch_surface {
    use std::collections::{BTreeMap, BTreeSet};

    use automonique_protocol::batch_api::{
        AdvanceMember, BATCH_CONTROL_PROTOCOL, BatchApiError, BatchContinuation, BatchCursor,
        BatchDetailResult, BatchListPage, BatchPageSize, BatchReceiptView, BatchRecordView,
        BatchRefusal, BatchRequest, BatchResponse, ListBatches, MAX_BATCH_CONTROL_CANONICAL_BYTES,
        MAX_BATCH_CONTROL_MEMBERS, MAX_BATCH_PAGE_ITEMS, MemberReceiptParts, MemberReceiptView,
        MemberView, RegisterBatch,
    };
    use automonique_protocol::batch_runner::{
        BatchId, BatchLabel, BatchMemberKey, BatchState, ConcurrencyKind, ConcurrencyPolicy,
        MAX_BATCH_ID_BYTES, MAX_BATCH_LABEL_BYTES, MAX_BATCH_MEMBER_KEY_BYTES, MAX_BATCH_MEMBERS,
        MemberProgress,
    };
    use automonique_protocol::codec::{MAX_REQUEST_ID_BYTES, MajorVersion};
    use automonique_protocol::codegen::{
        BATCH_MODULE, CommandSurface, ConstantValue, REGENERATE_COMMAND, generated_files,
        maintained_modules, module_file_name,
    };
    use automonique_protocol::primitives::{EpochMillis, ValueError};
    use automonique_protocol::runs_api::RunState;

    use super::command_surface::{count, hex, raw_message, request_id, text, unhex, write_pretty};
    use super::*;

    fn corpus_path() -> PathBuf {
        crate_root().join("fixtures/batch-api-v1.json")
    }

    fn runner_path() -> PathBuf {
        package_root().join("conformance/batch-api.ts")
    }

    fn regenerating() -> bool {
        std::env::var(automonique_protocol::codegen::REGENERATE_ENV)
            .is_ok_and(|value| !value.is_empty() && value != "0")
    }

    /// The command surface the generator describes for this protocol.
    fn surface() -> CommandSurface {
        maintained_modules()
            .into_iter()
            .find(|module| module.file_name == module_file_name(BATCH_MODULE))
            .and_then(|module| module.command_surface)
            .expect("the batch module describes a command surface")
    }

    /// The generated TypeScript of the batch module.
    fn generated_batch() -> String {
        generated_files()
            .into_iter()
            .find(|(name, _)| *name == module_file_name(BATCH_MODULE))
            .map(|(_, contents)| contents)
            .expect("the batch module is generated")
    }

    fn batch(value: &str) -> BatchId {
        BatchId::new(value).expect("a valid batch identity")
    }

    fn member(value: &str) -> BatchMemberKey {
        BatchMemberKey::new(value).expect("a valid member key")
    }

    fn label(value: &str) -> BatchLabel {
        BatchLabel::new(value).expect("a valid label")
    }

    fn page_size(items: usize) -> BatchPageSize {
        BatchPageSize::new(items).expect("a page size within the bound")
    }

    fn bounded_parallel(ceiling: u32) -> ConcurrencyPolicy {
        ConcurrencyPolicy::bounded_parallel(ceiling).expect("a ceiling a batch could reach")
    }

    /// A decimal string, because the wire carries 64-bit values and a JSON
    /// reader that used a double would round the largest of them without saying
    /// so. Every counter in this corpus travels as text for that reason.
    fn number(value: u64) -> JsonValue {
        JsonValue::String(value.to_string())
    }

    /// The wire ceiling, which a decoder carrying counters in a double rounds.
    fn wire_ceiling() -> u64 {
        u64::try_from(i64::MAX).expect("the wire ceiling is positive")
    }

    /// A batch identity carrying every escape a bounded identifier can reach, a
    /// three-byte character, a surrogate pair — and a space.
    ///
    /// The identity is opaque to this protocol: it parses nothing and derives
    /// nothing from it, so its grammar is the registry's own and admits
    /// whitespace.
    fn escaping_batch_id() -> String {
        "batch/\"nightly eval\" \\ naïve 日本語 🚀".to_owned()
    }

    fn escaping_member_key() -> String {
        "submit/\"run prod\" \\ naïve 日本語 🚀".to_owned()
    }

    fn escaping_label() -> String {
        "nightly \"eval\" \\ naïve 日本語 🚀".to_owned()
    }

    /// A value inside the UTF-16 code-unit bound and outside the UTF-8 one.
    ///
    /// Sixty-five two-byte characters: `value.length` in JavaScript counts 65,
    /// well under the bound, while the UTF-8 length Rust measures is 130 and
    /// over it. A generated constructor that measured code units would accept a
    /// value the daemon refuses, which is the one direction that matters.
    fn over_bound_by_bytes_only() -> String {
        "é".repeat(MAX_BATCH_MEMBER_KEY_BYTES / 2 + 1)
    }

    // -----------------------------------------------------------------------
    // The membership rule
    //
    // A maximal registration is a hundred and twenty-eight keys of a hundred
    // and twenty-eight bytes, which is 33 KiB of literal nobody can review. The
    // corpus carries a rule instead and each implementation builds the list
    // from it, exactly as the admin lane's maximal RunSpec document is built —
    // and that the two read the rule the same way is measured rather than
    // assumed, because the bytes the runner reports are compared against the
    // bytes Rust built from the same rule.
    // -----------------------------------------------------------------------

    struct MembershipRule {
        id: &'static str,
        note: &'static str,
        count: usize,
        /// UTF-8 bytes of each key, or zero for the short shape.
        key_bytes: usize,
    }

    fn membership_rules() -> Vec<MembershipRule> {
        vec![
            MembershipRule {
                id: "maximal",
                note: "MAX_BATCH_CONTROL_MEMBERS keys, each at MAX_BATCH_MEMBER_KEY_BYTES and \
                       filled with the one character that escapes to two canonical bytes. This is \
                       the worst case this lane's frame arithmetic budgets for, and it is why \
                       this ceiling is half the batch model's own",
                count: MAX_BATCH_CONTROL_MEMBERS,
                key_bytes: MAX_BATCH_MEMBER_KEY_BYTES,
            },
            MembershipRule {
                id: "over-bound",
                note: "one member past MAX_BATCH_CONTROL_MEMBERS. The length is judged before any \
                       key is validated, so what these keys are does not matter and the refusal \
                       names the length",
                count: MAX_BATCH_CONTROL_MEMBERS + 1,
                key_bytes: 0,
            },
        ]
    }

    /// The key at one position, spelled once and read the same way by both
    /// implementations.
    ///
    /// The three-digit index is what keeps the keys distinct: a membership that
    /// named one key twice is refused rather than collapsed, so a rule that
    /// produced a hundred and twenty-eight identical maximal keys would build a
    /// registration no daemon would admit.
    fn ruled_member_key(index: usize, key_bytes: usize) -> String {
        let prefix = format!("{index:03}");
        if key_bytes == 0 {
            return format!("member-{prefix}");
        }
        let filler = key_bytes
            .checked_sub(prefix.len())
            .expect("a ruled key is longer than its index");
        format!("{prefix}{}", "\"".repeat(filler))
    }

    fn ruled_membership(id: &str) -> Vec<String> {
        let rule = membership_rules()
            .into_iter()
            .find(|rule| rule.id == id)
            .unwrap_or_else(|| panic!("{id} is not a membership rule"));
        (0..rule.count)
            .map(|index| ruled_member_key(index, rule.key_bytes))
            .collect()
    }

    fn ruled_members(id: &str) -> Vec<BatchMemberKey> {
        ruled_membership(id).iter().map(|key| member(key)).collect()
    }

    fn membership_rule_entry(rule: &MembershipRule) -> JsonValue {
        JsonValue::Object(vec![
            ("count".to_owned(), number(rule.count as u64)),
            ("id".to_owned(), text(rule.id)),
            ("key_bytes".to_owned(), number(rule.key_bytes as u64)),
            ("note".to_owned(), text(rule.note)),
        ])
    }

    // -----------------------------------------------------------------------
    // Requests
    // -----------------------------------------------------------------------

    struct RequestCase {
        id: &'static str,
        note: &'static str,
        request: BatchRequest,
        /// Builder parameters, in the shape the runner reads for this kind.
        params: JsonValue,
    }

    /// The two-key wire shape of a concurrency policy, as the corpus spells it.
    fn concurrency_params(kind: &str, ceiling: Option<u64>) -> JsonValue {
        JsonValue::Object(vec![
            ("kind".to_owned(), text(kind)),
            (
                "max_in_flight".to_owned(),
                match ceiling {
                    Some(value) => number(value),
                    None => JsonValue::Null,
                },
            ),
        ])
    }

    fn members_params(keys: &[String]) -> JsonValue {
        JsonValue::Array(keys.iter().map(|key| text(key)).collect())
    }

    fn request_cases() -> Vec<RequestCase> {
        let maximal_request_id = format!("req-{}", "a".repeat(MAX_REQUEST_ID_BYTES - 4));
        let maximal_batch_id = "\"".repeat(MAX_BATCH_ID_BYTES);
        let maximal_label = "\"".repeat(MAX_BATCH_LABEL_BYTES);

        vec![
            RequestCase {
                id: "register-batch-maximal",
                note: "every bound at once: MAX_BATCH_CONTROL_MEMBERS members built from the \
                       membership rule, a batch identity and a label whose every character \
                       escapes to two canonical bytes, a bounded-parallel ceiling at the batch \
                       model's own membership — the largest a policy can declare, and one this \
                       lane's own membership can never reach — and a correlation identifier at \
                       MAX_REQUEST_ID_BYTES. This is the registration the frame arithmetic is \
                       derived from",
                request: BatchRequest::RegisterBatch {
                    request_id: request_id(&maximal_request_id),
                    registration: RegisterBatch::new(
                        batch(&maximal_batch_id),
                        Some(label(&maximal_label)),
                        bounded_parallel(
                            u32::try_from(MAX_BATCH_MEMBERS).expect("the ceiling fits a u32"),
                        ),
                        ruled_members("maximal"),
                    )
                    .expect("a well-formed maximal registration"),
                },
                params: JsonValue::Object(vec![
                    ("batch_id".to_owned(), text(&maximal_batch_id)),
                    (
                        "concurrency".to_owned(),
                        concurrency_params("bounded_parallel", Some(MAX_BATCH_MEMBERS as u64)),
                    ),
                    ("label".to_owned(), text(&maximal_label)),
                    ("members_rule".to_owned(), text("maximal")),
                ]),
            },
            RequestCase {
                id: "register-batch-sequential-unlabelled",
                note: "the other half of the discriminated policy: `sequential` carries no \
                       ceiling at all, and the absent label is an explicit null rather than an \
                       empty string. Sequential is not `bounded_parallel` with a ceiling of one — \
                       it also fixes the order to the declaration's, which is why the member \
                       order below is kept rather than sorted",
                request: BatchRequest::RegisterBatch {
                    request_id: request_id("req-register-1"),
                    registration: RegisterBatch::new(
                        batch(&escaping_batch_id()),
                        None,
                        ConcurrencyPolicy::Sequential,
                        vec![
                            member(&escaping_member_key()),
                            member("submit/aardvark"),
                            member("submit/zebra"),
                        ],
                    )
                    .expect("a well-formed registration"),
                },
                params: JsonValue::Object(vec![
                    ("batch_id".to_owned(), text(&escaping_batch_id())),
                    (
                        "concurrency".to_owned(),
                        concurrency_params("sequential", None),
                    ),
                    ("label".to_owned(), JsonValue::Null),
                    (
                        "members".to_owned(),
                        members_params(&[
                            escaping_member_key(),
                            "submit/aardvark".to_owned(),
                            "submit/zebra".to_owned(),
                        ]),
                    ),
                ]),
            },
            RequestCase {
                id: "register-batch-bounded-parallel-one",
                note: "a ceiling of one, which is the smallest a policy can declare and is still \
                       not `sequential`: this batch admits one member in flight and declares no \
                       order, and the two facts are recorded separately because they are separate",
                request: BatchRequest::RegisterBatch {
                    request_id: request_id("req-register-2"),
                    registration: RegisterBatch::new(
                        batch("batch/nightly-eval"),
                        Some(label(&escaping_label())),
                        bounded_parallel(1),
                        vec![member("submit/only")],
                    )
                    .expect("a well-formed registration"),
                },
                params: JsonValue::Object(vec![
                    ("batch_id".to_owned(), text("batch/nightly-eval")),
                    (
                        "concurrency".to_owned(),
                        concurrency_params("bounded_parallel", Some(1)),
                    ),
                    ("label".to_owned(), text(&escaping_label())),
                    (
                        "members".to_owned(),
                        members_params(&["submit/only".to_owned()]),
                    ),
                ]),
            },
            RequestCase {
                id: "advance-member-running-at-ceiling",
                note: "one writer's claim that a member is running, at a spool sequence and an \
                       expected revision both at the wire's integer ceiling — which a reader \
                       carrying either in a double would round to an even neighbour. What this \
                       reports is what somebody observed after reading the run index, not a \
                       reading this lane took",
                request: BatchRequest::AdvanceMember {
                    request_id: request_id("req-advance-1"),
                    advance: AdvanceMember::new(
                        batch(&escaping_batch_id()),
                        member(&escaping_member_key()),
                        wire_ceiling(),
                        MemberProgress::Run(RunState::Running),
                        wire_ceiling(),
                    )
                    .expect("a well-formed advance"),
                },
                params: JsonValue::Object(vec![
                    ("batch_id".to_owned(), text(&escaping_batch_id())),
                    ("expected_revision".to_owned(), number(wire_ceiling())),
                    ("last_sequence".to_owned(), number(wire_ceiling())),
                    ("member_key".to_owned(), text(&escaping_member_key())),
                    ("state".to_owned(), text("running")),
                ]),
            },
            RequestCase {
                id: "advance-member-ready-at-zero",
                note: "the other side of the sequence coupling: `ready` means the daemon holds a \
                       document and no event has arrived, so the sequence is zero. Rust refuses \
                       the incoherent pairs and the generated encoder does not — that gap is \
                       recorded in rust_only_encode_refusals rather than described",
                request: BatchRequest::AdvanceMember {
                    request_id: request_id("req-advance-2"),
                    advance: AdvanceMember::new(
                        batch("batch/nightly-eval"),
                        member("submit/only"),
                        1,
                        MemberProgress::Run(RunState::Ready),
                        0,
                    )
                    .expect("a well-formed advance"),
                },
                params: JsonValue::Object(vec![
                    ("batch_id".to_owned(), text("batch/nightly-eval")),
                    ("expected_revision".to_owned(), number(1)),
                    ("last_sequence".to_owned(), number(0)),
                    ("member_key".to_owned(), text("submit/only")),
                    ("state".to_owned(), text("ready")),
                ]),
            },
            RequestCase {
                id: "advance-member-timed-out",
                note: "a terminal claim carrying the one member progress spelling a run \
                       vocabulary reaches only through this lane's reuse of it",
                request: BatchRequest::AdvanceMember {
                    request_id: request_id("req-advance-3"),
                    advance: AdvanceMember::new(
                        batch("batch/nightly-eval"),
                        member("submit/zebra"),
                        4,
                        MemberProgress::Run(RunState::TimedOut),
                        99,
                    )
                    .expect("a well-formed advance"),
                },
                params: JsonValue::Object(vec![
                    ("batch_id".to_owned(), text("batch/nightly-eval")),
                    ("expected_revision".to_owned(), number(4)),
                    ("last_sequence".to_owned(), number(99)),
                    ("member_key".to_owned(), text("submit/zebra")),
                    ("state".to_owned(), text("timed_out")),
                ]),
            },
            RequestCase {
                id: "list-batches-maximal",
                note: "a cursor at the wire's integer ceiling and the largest page this protocol \
                       serves. A reader carrying the cursor in a double would encode \
                       9223372036854775808 here without a word of complaint",
                request: BatchRequest::ListBatches {
                    request_id: request_id("req-list-1"),
                    query: ListBatches::new(
                        BatchCursor::new(wire_ceiling()),
                        page_size(MAX_BATCH_PAGE_ITEMS),
                    ),
                },
                params: JsonValue::Object(vec![
                    ("page_size".to_owned(), number(MAX_BATCH_PAGE_ITEMS as u64)),
                    ("since".to_owned(), number(wire_ceiling())),
                ]),
            },
            RequestCase {
                id: "list-batches-start",
                note: "the beginning of the registry: a cursor of zero, which is a position \
                       rather than the absence of one, and the smallest page that can make \
                       progress",
                request: BatchRequest::ListBatches {
                    request_id: request_id("req-list-2"),
                    query: ListBatches::new(BatchCursor::START, page_size(1)),
                },
                params: JsonValue::Object(vec![
                    ("page_size".to_owned(), number(1)),
                    ("since".to_owned(), number(0)),
                ]),
            },
            RequestCase {
                id: "batch-detail-escaping",
                note: "one batch read by an identity carrying every reachable escape",
                request: BatchRequest::BatchDetail {
                    request_id: request_id("req-detail-1"),
                    batch_id: batch(&escaping_batch_id()),
                },
                params: JsonValue::Object(vec![(
                    "batch_id".to_owned(),
                    text(&escaping_batch_id()),
                )]),
            },
        ]
    }

    fn request_entry(case: &RequestCase) -> JsonValue {
        let message = case.request.to_message().expect("the request encodes");
        let canonical = message.to_canonical_bytes();
        // What the corpus records is checked against the shipped decoder before
        // it is written: a fixture Rust would not itself admit proves nothing.
        assert_eq!(
            BatchRequest::from_canonical_bytes(&canonical).expect("Rust admits its own encoding"),
            case.request,
            "{}: the Rust decoder does not admit the Rust encoding",
            case.id
        );
        assert!(
            canonical.len() <= MAX_BATCH_CONTROL_CANONICAL_BYTES,
            "{}: the encoding does not fit one batch control frame",
            case.id
        );
        JsonValue::Object(vec![
            ("canonical_bytes".to_owned(), count(canonical.len())),
            ("canonical_hex".to_owned(), text(&hex(&canonical))),
            ("id".to_owned(), text(case.id)),
            ("kind".to_owned(), text(message.envelope().kind().as_str())),
            ("note".to_owned(), text(case.note)),
            ("params".to_owned(), case.params.clone()),
            (
                "request_id".to_owned(),
                text(message.envelope().request_id().as_str()),
            ),
        ])
    }

    // -----------------------------------------------------------------------
    // Responses
    // -----------------------------------------------------------------------

    struct ResponseCase {
        id: &'static str,
        note: &'static str,
        response: BatchResponse,
    }

    /// One batch row's six columns, in the shape the fixtures name them.
    ///
    /// A parameter object because two bounded identifiers sit beside one
    /// another and a transposed pair would type-check into a fixture that
    /// measured the wrong thing.
    struct Row<'a> {
        entry_id: u64,
        batch_id: &'a str,
        label: Option<&'a str>,
        concurrency: ConcurrencyPolicy,
        created_at_ms: i64,
        revision: u64,
    }

    fn record(row: Row<'_>) -> BatchRecordView {
        BatchRecordView::new(
            row.entry_id,
            batch(row.batch_id),
            row.label.map(label),
            row.concurrency,
            EpochMillis::from_millis(row.created_at_ms),
            row.revision,
        )
        .expect("a well-formed batch row")
    }

    /// One member row, at the ordinal its position in the membership declares.
    fn member_row(
        ordinal: u32,
        key: &str,
        progress: MemberProgress,
        last_sequence: u64,
        revision: u64,
    ) -> MemberView {
        MemberView::new(
            member(key),
            ordinal,
            progress,
            last_sequence,
            revision,
            EpochMillis::from_millis(1_700_000_000_000 + i64::from(ordinal)),
        )
        .expect("a well-formed member row")
    }

    /// A listing answer built through the enforcement path rather than around
    /// it: `BatchResponse::listing` is what refuses a page longer than the query
    /// asked for, so a corpus entry that constructed the variant directly would
    /// record bytes no daemon could have produced.
    fn listing(id: &str, query: ListBatches, page: BatchListPage) -> BatchResponse {
        BatchResponse::listing(request_id(id), query, page)
            .expect("the page answers the query it was built for")
    }

    fn detail(id: &str, batch_row: BatchRecordView, members: Vec<MemberView>) -> BatchResponse {
        BatchResponse::BatchDetail {
            request_id: request_id(id),
            detail: BatchDetailResult::new(batch_row, members).expect("a well-formed batch detail"),
        }
    }

    fn response_cases() -> Vec<ResponseCase> {
        let whole_registry = ListBatches::new(BatchCursor::START, page_size(MAX_BATCH_PAGE_ITEMS));

        vec![
            ResponseCase {
                id: "batch-registered-maximal-membership",
                note: "a maximal membership is durable, all of it `unsubmitted` at ordinals \
                       0..member_count. `accepted` rather than `completed`: the rows are \
                       committed, and what they record has not taken effect and cannot, because \
                       registering a batch submits nothing and reserves no run identity",
                response: BatchResponse::Registered {
                    request_id: request_id("req-register-1"),
                    receipt: BatchReceiptView::new(
                        1,
                        batch(&escaping_batch_id()),
                        MAX_BATCH_CONTROL_MEMBERS,
                        1,
                        EpochMillis::from_millis(1_700_000_000_000),
                    )
                    .expect("a well-formed receipt"),
                },
            },
            ResponseCase {
                id: "batch-registered-at-ceiling",
                note: "the same answer with every counter at the wire's ceiling and the smallest \
                       membership a batch can have, which is one rather than none",
                response: BatchResponse::Registered {
                    request_id: request_id("req-register-2"),
                    receipt: BatchReceiptView::new(
                        wire_ceiling(),
                        batch("batch/nightly-eval"),
                        1,
                        wire_ceiling(),
                        EpochMillis::from_millis(i64::MAX),
                    )
                    .expect("a well-formed receipt"),
                },
            },
            ResponseCase {
                id: "member-advanced-running",
                note: "one member's row moved. The revision is the fence the *next* advance must \
                       expect, and it is two here because registration wrote one: an advance \
                       receipt at revision one would name a row no accepted advance could have \
                       left behind. The ordinal is the last position this lane's membership \
                       admits",
                response: BatchResponse::MemberAdvanced {
                    request_id: request_id("req-advance-1"),
                    receipt: MemberReceiptView::new(MemberReceiptParts {
                        batch_id: batch(&escaping_batch_id()),
                        member_key: member(&escaping_member_key()),
                        ordinal: u32::try_from(MAX_BATCH_CONTROL_MEMBERS - 1)
                            .expect("the last ordinal fits a u32"),
                        progress: MemberProgress::Run(RunState::Running),
                        last_sequence: wire_ceiling(),
                        revision: 2,
                        updated_at: EpochMillis::from_millis(i64::MAX),
                    })
                    .expect("a well-formed advance receipt"),
                },
            },
            ResponseCase {
                id: "member-advanced-cancelled",
                note: "a terminal member at a revision at the wire's ceiling: a cancellation is a \
                       decision rather than a loss, which is why a batch of nothing but \
                       cancellations rolls up to `cancelled` and not to `failed`",
                response: BatchResponse::MemberAdvanced {
                    request_id: request_id("req-advance-2"),
                    receipt: MemberReceiptView::new(MemberReceiptParts {
                        batch_id: batch("batch/nightly-eval"),
                        member_key: member("submit/only"),
                        ordinal: 0,
                        progress: MemberProgress::Run(RunState::Cancelled),
                        last_sequence: 7,
                        revision: wire_ceiling(),
                        updated_at: EpochMillis::from_millis(0),
                    })
                    .expect("a well-formed advance receipt"),
                },
            },
            ResponseCase {
                id: "batch-list-page-more",
                note: "one page carrying both concurrency shapes at once: a sequential batch with \
                       no label and no ceiling, and a bounded-parallel one at the largest ceiling \
                       a policy can declare. The last row and the continuation cursor are both at \
                       the wire's ceiling",
                response: listing(
                    "req-list-1",
                    whole_registry,
                    BatchListPage::new(
                        vec![
                            record(Row {
                                entry_id: 1,
                                batch_id: "batch/first",
                                label: None,
                                concurrency: ConcurrencyPolicy::Sequential,
                                created_at_ms: 1_700_000_000_000,
                                revision: 1,
                            }),
                            record(Row {
                                entry_id: wire_ceiling() - 1,
                                batch_id: &escaping_batch_id(),
                                label: Some(&escaping_label()),
                                concurrency: bounded_parallel(
                                    u32::try_from(MAX_BATCH_MEMBERS)
                                        .expect("the ceiling fits a u32"),
                                ),
                                created_at_ms: i64::MAX,
                                revision: wire_ceiling(),
                            }),
                        ],
                        BatchContinuation::More(BatchCursor::new(wire_ceiling())),
                    )
                    .expect("a well-formed page"),
                ),
            },
            ResponseCase {
                id: "batch-list-page-complete",
                note: "the end of the registry: `more` false and an explicit null cursor. A batch \
                       registered at the epoch, which the registry's own `created_at_ms >= 0` \
                       constraint admits and one millisecond earlier does not",
                response: listing(
                    "req-list-2",
                    whole_registry,
                    BatchListPage::new(
                        vec![record(Row {
                            entry_id: 9,
                            batch_id: "batch/only",
                            label: Some("nightly"),
                            concurrency: bounded_parallel(4),
                            created_at_ms: 0,
                            revision: 3,
                        })],
                        BatchContinuation::Complete,
                    )
                    .expect("a well-formed page"),
                ),
            },
            ResponseCase {
                id: "batch-list-page-empty-more",
                note: "an empty page that still reports more. `more` is carried explicitly rather \
                       than inferred from a short page, because a short page is not the same \
                       statement as a last page",
                response: listing(
                    "req-list-1",
                    whole_registry,
                    BatchListPage::new(Vec::new(), BatchContinuation::More(BatchCursor::new(42)))
                        .expect("an empty page may continue"),
                ),
            },
            ResponseCase {
                id: "batch-detail-mixed",
                note: "the rollup that exists to be exactly one case: every member ended, nothing \
                       was lost, and the results are neither all completions nor all \
                       cancellations. The state is not a column anywhere — the registry \
                       deliberately does not store one — and it is derived beside the members \
                       that justify it, which is why a reader can check it",
                response: detail(
                    "req-detail-1",
                    record(Row {
                        entry_id: 4,
                        batch_id: &escaping_batch_id(),
                        label: Some(&escaping_label()),
                        concurrency: bounded_parallel(2),
                        created_at_ms: 1_700_000_000_000,
                        revision: 1,
                    }),
                    vec![
                        member_row(
                            0,
                            &escaping_member_key(),
                            MemberProgress::Run(RunState::Completed),
                            12,
                            2,
                        ),
                        member_row(
                            1,
                            "submit/zebra",
                            MemberProgress::Run(RunState::Cancelled),
                            3,
                            5,
                        ),
                    ],
                ),
            },
            ResponseCase {
                id: "batch-detail-pending",
                note: "no member has begun: one was never submitted and one is held with no event \
                       arrived. `ready` is not `unsubmitted` — the first presumes a submission \
                       happened — and both carry a zero sequence, which is the coupling the Rust \
                       decoder holds and this file's generated one does not",
                response: detail(
                    "req-detail-2",
                    record(Row {
                        entry_id: 5,
                        batch_id: "batch/nightly-eval",
                        label: None,
                        concurrency: ConcurrencyPolicy::Sequential,
                        created_at_ms: 1_700_000_000_000,
                        revision: 1,
                    }),
                    vec![
                        member_row(0, "submit/aardvark", MemberProgress::Unsubmitted, 0, 1),
                        member_row(
                            1,
                            "submit/zebra",
                            MemberProgress::Run(RunState::Ready),
                            0,
                            4,
                        ),
                    ],
                ),
            },
            ResponseCase {
                id: "batch-detail-failed",
                note: "a batch that lost a member did not succeed, whatever the others did: one \
                       completion beside one timed-out member rolls up to `failed` rather than to \
                       `mixed`",
                response: detail(
                    "req-detail-3",
                    record(Row {
                        entry_id: 6,
                        batch_id: "batch/nightly-eval",
                        label: Some("nightly"),
                        concurrency: bounded_parallel(8),
                        created_at_ms: 1_700_000_000_000,
                        revision: 2,
                    }),
                    vec![
                        member_row(
                            0,
                            "submit/aardvark",
                            MemberProgress::Run(RunState::Completed),
                            9,
                            3,
                        ),
                        member_row(
                            1,
                            "submit/zebra",
                            MemberProgress::Run(RunState::TimedOut),
                            wire_ceiling(),
                            2,
                        ),
                    ],
                ),
            },
            ResponseCase {
                id: "revision-conflict",
                note: "the caller's fence was stale and nothing was written. Not a refusal: a \
                       conflict is retried against the durable revision this answer carries, \
                       where a refusal is not retried at all until the request changes",
                response: BatchResponse::conflict(request_id("req-advance-1"), 2, 7)
                    .expect("two revisions that disagree"),
            },
            ResponseCase {
                id: "revision-conflict-at-ceiling",
                note: "the same answer with the durable revision at the wire's ceiling, which a \
                       reader carrying it in a double would round",
                response: BatchResponse::conflict(request_id("req-advance-2"), 1, wire_ceiling())
                    .expect("two revisions that disagree"),
            },
            ResponseCase {
                id: "refused-unknown-batch",
                note: "no batch is registered under that identity. Distinct from `unknown_member`, \
                       because the two are fixed differently: one is a batch nobody registered, \
                       the other is a key a registered batch never named and never will",
                response: BatchResponse::Refused {
                    request_id: request_id("req-detail-1"),
                    refusal: BatchRefusal::UnknownBatch,
                },
            },
            ResponseCase {
                id: "refused-already-registered",
                note: "a repeated identity is never an overwrite: re-registering would reset \
                       member rows a writer may already have advanced, and silently discarding a \
                       batch's recorded progress is the one thing the registry exists to prevent",
                response: BatchResponse::Refused {
                    request_id: request_id("req-register-1"),
                    refusal: BatchRefusal::AlreadyRegistered,
                },
            },
            ResponseCase {
                id: "refused-illegal-transition",
                note: "the reported progress does not follow the durable one along the lattice, \
                       which is a rejection rather than a conflict: the request does not become \
                       right by being retried against a newer revision",
                response: BatchResponse::Refused {
                    request_id: request_id("req-advance-1"),
                    refusal: BatchRefusal::IllegalTransition,
                },
            },
            ResponseCase {
                id: "refused-registry-full",
                note: "capacity is a refusal and never an eviction: forgetting a batch would \
                       strand the only durable record of what it declared",
                response: BatchResponse::Refused {
                    request_id: request_id("req-register-1"),
                    refusal: BatchRefusal::RegistryFull,
                },
            },
        ]
    }

    /// How one concurrency policy is spelled, under the corpus's dotted keys.
    fn concurrency_spelling(prefix: &str, policy: ConcurrencyPolicy) -> Vec<(String, JsonValue)> {
        vec![
            (
                format!("{prefix}concurrency.kind"),
                text(policy.kind().as_str()),
            ),
            (
                format!("{prefix}concurrency.max_in_flight"),
                match policy.declared_ceiling() {
                    Some(ceiling) => number(u64::from(ceiling)),
                    None => text("null"),
                },
            ),
        ]
    }

    fn record_spelling(prefix: &str, value: &BatchRecordView) -> Vec<(String, JsonValue)> {
        let mut fields = vec![
            (format!("{prefix}batch_id"), text(value.batch_id().as_str())),
            (
                format!("{prefix}created_at_ms"),
                JsonValue::String(value.created_at().as_millis().to_string()),
            ),
            (format!("{prefix}entry_id"), number(value.entry_id())),
            (
                format!("{prefix}label"),
                match value.label() {
                    Some(label) => text(label.as_str()),
                    None => text("null"),
                },
            ),
            (format!("{prefix}revision"), number(value.revision())),
        ];
        fields.extend(concurrency_spelling(prefix, value.concurrency()));
        fields
    }

    fn member_spelling(prefix: &str, value: &MemberView) -> Vec<(String, JsonValue)> {
        vec![
            (format!("{prefix}key"), text(value.key().as_str())),
            (
                format!("{prefix}last_sequence"),
                number(value.last_sequence()),
            ),
            (
                format!("{prefix}ordinal"),
                number(u64::from(value.ordinal())),
            ),
            (format!("{prefix}revision"), number(value.revision())),
            (format!("{prefix}state"), text(value.progress().as_str())),
            (
                format!("{prefix}updated_at_ms"),
                JsonValue::String(value.updated_at().as_millis().to_string()),
            ),
        ]
    }

    /// How one decoded response is spelled in the corpus.
    ///
    /// Built from the value the *Rust decoder* recovered, and flattened with
    /// dotted keys so a nested page or membership compares field by field
    /// rather than as one opaque blob.
    fn decoded_spelling(response: &BatchResponse) -> JsonValue {
        let mut fields = vec![(
            "request_id".to_owned(),
            text(response.request_id().as_str()),
        )];
        match response {
            BatchResponse::Registered { receipt, .. } => {
                fields.push(("batch_id".to_owned(), text(receipt.batch_id().as_str())));
                fields.push((
                    "created_at_ms".to_owned(),
                    JsonValue::String(receipt.created_at().as_millis().to_string()),
                ));
                fields.push(("entry_id".to_owned(), number(receipt.entry_id())));
                fields.push((
                    "member_count".to_owned(),
                    number(receipt.member_count() as u64),
                ));
                fields.push(("revision".to_owned(), number(receipt.revision())));
            }
            BatchResponse::MemberAdvanced { receipt, .. } => {
                fields.push(("batch_id".to_owned(), text(receipt.batch_id().as_str())));
                fields.push(("last_sequence".to_owned(), number(receipt.last_sequence())));
                fields.push(("member_key".to_owned(), text(receipt.member_key().as_str())));
                fields.push(("ordinal".to_owned(), number(u64::from(receipt.ordinal()))));
                fields.push(("revision".to_owned(), number(receipt.revision())));
                fields.push(("state".to_owned(), text(receipt.progress().as_str())));
                fields.push((
                    "updated_at_ms".to_owned(),
                    JsonValue::String(receipt.updated_at().as_millis().to_string()),
                ));
            }
            BatchResponse::BatchList { page, .. } => {
                fields.push((
                    "batches.len".to_owned(),
                    number(page.entries().len() as u64),
                ));
                fields.push((
                    "more".to_owned(),
                    text(&page.continuation().has_more().to_string()),
                ));
                fields.push((
                    "next_cursor".to_owned(),
                    match page.continuation().cursor() {
                        Some(cursor) => number(cursor.position()),
                        None => text("null"),
                    },
                ));
                for (index, carried) in page.entries().iter().enumerate() {
                    fields.extend(record_spelling(&format!("batches.{index}."), carried));
                }
            }
            BatchResponse::BatchDetail { detail, .. } => {
                fields.extend(record_spelling("batch.", detail.batch()));
                fields.push((
                    "members.len".to_owned(),
                    number(detail.members().len() as u64),
                ));
                fields.push(("state".to_owned(), text(detail.rolled_up_state().as_str())));
                for (index, carried) in detail.members().iter().enumerate() {
                    fields.extend(member_spelling(&format!("members.{index}."), carried));
                }
            }
            BatchResponse::Conflict {
                expected_revision,
                durable_revision,
                ..
            } => {
                fields.push(("durable_revision".to_owned(), number(*durable_revision)));
                fields.push(("expected_revision".to_owned(), number(*expected_revision)));
            }
            BatchResponse::Refused { refusal, .. } => {
                fields.push(("refusal".to_owned(), text(refusal.as_str())));
            }
        }
        JsonValue::Object(fields)
    }

    fn response_entry(case: &ResponseCase) -> JsonValue {
        let message = case.response.to_message().expect("the response encodes");
        let canonical = message.to_canonical_bytes();
        let decoded =
            BatchResponse::from_canonical_bytes(&canonical).expect("Rust admits its own encoding");
        assert_eq!(
            decoded, case.response,
            "{}: the Rust decoder does not recover what it encoded",
            case.id
        );
        JsonValue::Object(vec![
            ("canonical_hex".to_owned(), text(&hex(&canonical))),
            ("decoded".to_owned(), decoded_spelling(&decoded)),
            ("id".to_owned(), text(case.id)),
            ("kind".to_owned(), text(message.envelope().kind().as_str())),
            ("note".to_owned(), text(case.note)),
            ("outcome".to_owned(), text(decoded.outcome().as_str())),
        ])
    }

    // -----------------------------------------------------------------------
    // Bodies, for the payloads no constructor would produce
    // -----------------------------------------------------------------------

    fn concurrency_body(kind: &str, ceiling: Option<i64>) -> JsonValue {
        JsonValue::Object(vec![
            ("kind".to_owned(), text(kind)),
            (
                "max_in_flight".to_owned(),
                match ceiling {
                    Some(value) => JsonValue::Integer(value),
                    None => JsonValue::Null,
                },
            ),
        ])
    }

    /// A well-formed batch row body, as a starting point for one that is not.
    fn record_body(overrides: &[(&str, JsonValue)]) -> JsonValue {
        let mut entries: Vec<(String, JsonValue)> = vec![
            ("batch_id".to_owned(), text("batch/nightly-eval")),
            (
                "concurrency".to_owned(),
                concurrency_body("bounded_parallel", Some(4)),
            ),
            (
                "created_at_ms".to_owned(),
                JsonValue::Integer(1_700_000_000_000),
            ),
            ("entry_id".to_owned(), JsonValue::Integer(1)),
            ("label".to_owned(), text("nightly")),
            ("revision".to_owned(), JsonValue::Integer(1)),
        ];
        for (name, value) in overrides {
            let slot = entries
                .iter_mut()
                .find(|(existing, _)| existing == name)
                .unwrap_or_else(|| panic!("{name} is not a batch row field"));
            slot.1 = value.clone();
        }
        JsonValue::Object(entries)
    }

    /// A well-formed member row body.
    fn member_body(overrides: &[(&str, JsonValue)]) -> JsonValue {
        let mut entries: Vec<(String, JsonValue)> = vec![
            ("key".to_owned(), text("submit/only")),
            ("last_sequence".to_owned(), JsonValue::Integer(7)),
            ("ordinal".to_owned(), JsonValue::Integer(0)),
            ("revision".to_owned(), JsonValue::Integer(2)),
            ("state".to_owned(), text("completed")),
            (
                "updated_at_ms".to_owned(),
                JsonValue::Integer(1_700_000_000_000),
            ),
        ];
        for (name, value) in overrides {
            let slot = entries
                .iter_mut()
                .find(|(existing, _)| existing == name)
                .unwrap_or_else(|| panic!("{name} is not a member row field"));
            slot.1 = value.clone();
        }
        JsonValue::Object(entries)
    }

    /// A well-formed advance receipt body.
    fn receipt_body(overrides: &[(&str, JsonValue)]) -> JsonValue {
        let mut entries: Vec<(String, JsonValue)> = vec![
            ("batch_id".to_owned(), text("batch/nightly-eval")),
            ("last_sequence".to_owned(), JsonValue::Integer(7)),
            ("member_key".to_owned(), text("submit/only")),
            ("ordinal".to_owned(), JsonValue::Integer(0)),
            ("revision".to_owned(), JsonValue::Integer(2)),
            ("state".to_owned(), text("running")),
            (
                "updated_at_ms".to_owned(),
                JsonValue::Integer(1_700_000_000_000),
            ),
        ];
        for (name, value) in overrides {
            let slot = entries
                .iter_mut()
                .find(|(existing, _)| existing == name)
                .unwrap_or_else(|| panic!("{name} is not an advance receipt field"));
            slot.1 = value.clone();
        }
        JsonValue::Object(entries)
    }

    /// A well-formed registration receipt body.
    fn registered_body(overrides: &[(&str, JsonValue)]) -> JsonValue {
        let mut entries: Vec<(String, JsonValue)> = vec![
            ("batch_id".to_owned(), text("batch/nightly-eval")),
            (
                "created_at_ms".to_owned(),
                JsonValue::Integer(1_700_000_000_000),
            ),
            ("entry_id".to_owned(), JsonValue::Integer(1)),
            ("member_count".to_owned(), JsonValue::Integer(2)),
            ("revision".to_owned(), JsonValue::Integer(1)),
        ];
        for (name, value) in overrides {
            let slot = entries
                .iter_mut()
                .find(|(existing, _)| existing == name)
                .unwrap_or_else(|| panic!("{name} is not a registration receipt field"));
            slot.1 = value.clone();
        }
        JsonValue::Object(entries)
    }

    fn page_body(batches: Vec<JsonValue>, more: bool, next_cursor: JsonValue) -> JsonValue {
        JsonValue::Object(vec![
            ("batches".to_owned(), JsonValue::Array(batches)),
            ("more".to_owned(), JsonValue::Bool(more)),
            ("next_cursor".to_owned(), next_cursor),
        ])
    }

    fn detail_body(members: Vec<JsonValue>, state: &str) -> JsonValue {
        JsonValue::Object(vec![
            ("batch".to_owned(), record_body(&[])),
            ("members".to_owned(), JsonValue::Array(members)),
            ("state".to_owned(), text(state)),
        ])
    }

    fn batch_message(kind: &str, id: &str, body: JsonValue) -> Vec<u8> {
        raw_message(BATCH_CONTROL_PROTOCOL, 1, kind, id, body)
    }

    /// One batch row wrapped in the smallest page that can carry it.
    fn one_row_page(row: JsonValue) -> Vec<u8> {
        batch_message(
            "batch_list_result",
            "req-list-1",
            page_body(vec![row], false, JsonValue::Null),
        )
    }

    /// One member row wrapped in the smallest detail that can carry it.
    ///
    /// The carried rollup is `completed`, which is what one completed member
    /// rolls up to: a detail whose state contradicted its members would be
    /// refused for *that* instead of for the fault under test.
    fn one_member_detail(row: JsonValue) -> Vec<u8> {
        batch_message(
            "batch_detail_result",
            "req-detail-1",
            detail_body(vec![row], "completed"),
        )
    }

    // -----------------------------------------------------------------------
    // Refusals both implementations make
    // -----------------------------------------------------------------------

    struct DecodeRefusal {
        id: &'static str,
        note: &'static str,
        payload: Vec<u8>,
    }

    fn decode_refusals() -> Vec<DecodeRefusal> {
        // The page and membership bounds are judged before any item is read, in
        // Rust and in the generated TypeScript alike, so the over-bound payloads
        // carry integers rather than bodies: what is wrong with them is length.
        let page_filler: Vec<JsonValue> = (0..=MAX_BATCH_PAGE_ITEMS)
            .map(|index| JsonValue::Integer(index as i64))
            .collect();
        let member_filler: Vec<JsonValue> = (0..=MAX_BATCH_CONTROL_MEMBERS)
            .map(|index| JsonValue::Integer(index as i64))
            .collect();

        vec![
            DecodeRefusal {
                id: "member-progress-undefined-spelling",
                note: "a member progress this build does not define fails closed rather than \
                       decoding to a default. There is no safe guess: counting it as finished \
                       invents a completion, and counting it as outstanding invents work still to \
                       do — and the rollup over it would carry the invention up to the batch",
                payload: one_member_detail(member_body(&[("state", text("skipped"))])),
            },
            DecodeRefusal {
                id: "batch-state-undefined-spelling",
                note: "a rolled-up batch state outside the six this build derives. The vocabulary \
                       is closed on both sides of the wire even though the value is derived, \
                       because a reader that retained an unnameable rollup would be holding a \
                       summary of work it cannot describe",
                payload: batch_message(
                    "batch_detail_result",
                    "req-detail-1",
                    detail_body(vec![member_body(&[])], "partial"),
                ),
            },
            DecodeRefusal {
                id: "concurrency-kind-undefined-spelling",
                note: "a concurrency word outside the two this build defines. `parallel` with no \
                       ceiling is exactly the unbounded policy this model refuses to have a \
                       spelling for",
                payload: one_row_page(record_body(&[(
                    "concurrency",
                    concurrency_body("parallel", None),
                )])),
            },
            DecodeRefusal {
                id: "refusal-undefined-spelling",
                note: "a refusal word outside the thirteen this build carries",
                payload: batch_message(
                    "refused",
                    "req-register-1",
                    JsonValue::Object(vec![("refusal".to_owned(), text("quota_exceeded"))]),
                ),
            },
            DecodeRefusal {
                id: "concurrency-sequential-with-ceiling",
                note: "the discriminated coupling, met from one side: a sequential policy that \
                       carries a number is a policy this build cannot mean, and the generated \
                       union has no shape for it either",
                payload: one_row_page(record_body(&[(
                    "concurrency",
                    concurrency_body("sequential", Some(4)),
                )])),
            },
            DecodeRefusal {
                id: "concurrency-bounded-parallel-without-ceiling",
                note: "and from the other: a bounded parallelism with no bound is an unbounded \
                       policy wearing the bounded word",
                payload: one_row_page(record_body(&[(
                    "concurrency",
                    concurrency_body("bounded_parallel", None),
                )])),
            },
            DecodeRefusal {
                id: "concurrency-ceiling-zero",
                note: "a ceiling that admits nothing in flight, refused rather than read as `no \
                       limit`. Its own category: a caller told only `invalid` cannot tell this \
                       from the ceiling above",
                payload: one_row_page(record_body(&[(
                    "concurrency",
                    concurrency_body("bounded_parallel", Some(0)),
                )])),
            },
            DecodeRefusal {
                id: "concurrency-ceiling-above-membership",
                note: "one past the members a batch can hold, which is a ceiling that can never \
                       bind — an unbounded policy with a number written on it",
                payload: one_row_page(record_body(&[(
                    "concurrency",
                    concurrency_body("bounded_parallel", Some(MAX_BATCH_MEMBERS as i64 + 1)),
                )])),
            },
            DecodeRefusal {
                id: "concurrency-ceiling-above-its-own-width",
                note: "a ceiling above the integer width it is carried in, which is a malformed \
                       body rather than an unreachable ceiling: the decoder converts before it \
                       judges the domain, and the two categories differ",
                payload: one_row_page(record_body(&[(
                    "concurrency",
                    concurrency_body("bounded_parallel", Some(i64::from(u32::MAX) + 1)),
                )])),
            },
            DecodeRefusal {
                id: "entry-id-zero",
                note: "a durable identity starts at one; zero names a row no writer produced",
                payload: one_row_page(record_body(&[("entry_id", JsonValue::Integer(0))])),
            },
            DecodeRefusal {
                id: "entry-id-negative",
                note: "a negative identity is a malformed body rather than an unwritten row: the \
                       decoder converts before it judges the domain",
                payload: one_row_page(record_body(&[("entry_id", JsonValue::Integer(-1))])),
            },
            DecodeRefusal {
                id: "batch-revision-zero",
                note: "registration writes revision one and every accepted advance writes one \
                       higher, so zero names a row this product could not have written",
                payload: one_row_page(record_body(&[("revision", JsonValue::Integer(0))])),
            },
            DecodeRefusal {
                id: "member-revision-zero",
                note: "the same pin on a member row, which the registry writes at one and \
                       advances from there",
                payload: one_member_detail(member_body(&[("revision", JsonValue::Integer(0))])),
            },
            DecodeRefusal {
                id: "advance-receipt-at-revision-one",
                note: "registration is the only writer of revision one, so an advance receipt \
                       claiming it names a row no accepted advance could have left behind. This \
                       is the durable-row rule the generated surface *does* hold, because `two or \
                       above` is a bound on one field's own value",
                payload: batch_message(
                    "member_advanced",
                    "req-advance-1",
                    receipt_body(&[("revision", JsonValue::Integer(1))]),
                ),
            },
            DecodeRefusal {
                id: "advance-receipt-at-revision-zero",
                note: "the same pin met from below, and under the same category",
                payload: batch_message(
                    "member_advanced",
                    "req-advance-1",
                    receipt_body(&[("revision", JsonValue::Integer(0))]),
                ),
            },
            DecodeRefusal {
                id: "member-ordinal-above-membership",
                note: "an ordinal past the last position this lane's membership admits. That the \
                       ordinals are contiguous is a relation between members and stays with the \
                       Rust decoder; that each one is inside the membership is a bound on its own \
                       value, and this side holds it",
                payload: batch_message(
                    "member_advanced",
                    "req-advance-1",
                    receipt_body(&[(
                        "ordinal",
                        JsonValue::Integer(MAX_BATCH_CONTROL_MEMBERS as i64),
                    )]),
                ),
            },
            DecodeRefusal {
                id: "created-at-before-epoch",
                note: "an instant the registry's own `created_at_ms >= 0` constraint cannot hold",
                payload: one_row_page(record_body(&[("created_at_ms", JsonValue::Integer(-1))])),
            },
            DecodeRefusal {
                id: "updated-at-before-epoch",
                note: "the same constraint on the instant a member row records",
                payload: one_member_detail(member_body(&[(
                    "updated_at_ms",
                    JsonValue::Integer(-1),
                )])),
            },
            DecodeRefusal {
                id: "member-count-zero",
                note: "a registration that wrote no member is a unit with nothing in it, which is \
                       the batch model's own refusal rather than this lane's — and a different \
                       one from a count above the ceiling, which is why the two ends of this \
                       domain carry different categories",
                payload: batch_message(
                    "batch_registered",
                    "req-register-1",
                    registered_body(&[("member_count", JsonValue::Integer(0))]),
                ),
            },
            DecodeRefusal {
                id: "member-count-above-bound",
                note: "one past MAX_BATCH_CONTROL_MEMBERS, which is this transport's ceiling \
                       rather than the registry's: the store still holds twice as many, and the \
                       two are deliberately not reconciled",
                payload: batch_message(
                    "batch_registered",
                    "req-register-1",
                    registered_body(&[(
                        "member_count",
                        JsonValue::Integer(MAX_BATCH_CONTROL_MEMBERS as i64 + 1),
                    )]),
                ),
            },
            DecodeRefusal {
                id: "batch-id-empty",
                note: "an empty identity names no batch",
                payload: one_row_page(record_body(&[("batch_id", text(""))])),
            },
            DecodeRefusal {
                id: "label-control-character",
                note: "a control character in an operator-supplied label, which the wire never \
                       carries raw. A space *is* admitted, which is the difference between this \
                       lane's grammar and the correlation identifier's",
                payload: one_row_page(record_body(&[("label", text("nightly\u{7}eval"))])),
            },
            DecodeRefusal {
                id: "member-key-over-bound-in-bytes-only",
                note: "65 two-byte characters: 65 UTF-16 code units, which a JavaScript `length` \
                       check would wave through, and 130 UTF-8 bytes, which is over the bound Rust \
                       and the registry both measure",
                payload: one_member_detail(member_body(&[(
                    "key",
                    text(&over_bound_by_bytes_only()),
                )])),
            },
            DecodeRefusal {
                id: "page-over-bound",
                note: "one row past MAX_BATCH_PAGE_ITEMS. The length is judged before any item is \
                       read, so what these items are does not matter",
                payload: batch_message(
                    "batch_list_result",
                    "req-list-1",
                    page_body(page_filler, false, JsonValue::Null),
                ),
            },
            DecodeRefusal {
                id: "detail-membership-over-bound",
                note: "one member past MAX_BATCH_CONTROL_MEMBERS on the way in, which is the same \
                       ceiling the registration encoder holds on the way out",
                payload: batch_message(
                    "batch_detail_result",
                    "req-detail-1",
                    detail_body(member_filler, "completed"),
                ),
            },
            DecodeRefusal {
                id: "next-cursor-negative",
                note: "a cursor below the beginning of the listing",
                payload: batch_message(
                    "batch_list_result",
                    "req-list-1",
                    page_body(Vec::new(), true, JsonValue::Integer(-1)),
                ),
            },
            DecodeRefusal {
                id: "more-not-a-boolean",
                note: "the wire carries true or false for a continuation and nothing else",
                payload: batch_message(
                    "batch_list_result",
                    "req-list-1",
                    JsonValue::Object(vec![
                        ("batches".to_owned(), JsonValue::Array(Vec::new())),
                        ("more".to_owned(), JsonValue::Integer(1)),
                        ("next_cursor".to_owned(), JsonValue::Null),
                    ]),
                ),
            },
            DecodeRefusal {
                id: "conflict-revision-zero",
                note: "a conflict naming a revision no writer produced tells a caller to retry \
                       against a row that does not exist",
                payload: batch_message(
                    "revision_conflict",
                    "req-advance-1",
                    JsonValue::Object(vec![
                        ("durable_revision".to_owned(), JsonValue::Integer(0)),
                        ("expected_revision".to_owned(), JsonValue::Integer(2)),
                    ]),
                ),
            },
            DecodeRefusal {
                id: "page-extra-field",
                note: "an unexpected key is refused rather than ignored",
                payload: batch_message(
                    "batch_list_result",
                    "req-list-1",
                    JsonValue::Object(vec![
                        ("batches".to_owned(), JsonValue::Array(Vec::new())),
                        ("more".to_owned(), JsonValue::Bool(false)),
                        ("next_cursor".to_owned(), JsonValue::Null),
                        ("total".to_owned(), JsonValue::Integer(1)),
                    ]),
                ),
            },
            DecodeRefusal {
                id: "record-missing-label",
                note: "a missing key is refused rather than defaulted, inside a nested body as \
                       much as at the top level: an absent label and a null one are different \
                       wire facts, and only the second is a batch nobody named",
                payload: one_row_page(JsonValue::Object(vec![
                    ("batch_id".to_owned(), text("batch/nightly-eval")),
                    (
                        "concurrency".to_owned(),
                        concurrency_body("sequential", None),
                    ),
                    (
                        "created_at_ms".to_owned(),
                        JsonValue::Integer(1_700_000_000_000),
                    ),
                    ("entry_id".to_owned(), JsonValue::Integer(1)),
                    ("revision".to_owned(), JsonValue::Integer(1)),
                ])),
            },
            DecodeRefusal {
                id: "concurrency-missing-ceiling-key",
                note: "the nested body's own exact key set: a policy carrying only its word is \
                       refused rather than read as a sequential one",
                payload: one_row_page(record_body(&[(
                    "concurrency",
                    JsonValue::Object(vec![("kind".to_owned(), text("sequential"))]),
                )])),
            },
            DecodeRefusal {
                id: "unknown-kind",
                note: "a kind this protocol version does not define, which is a different answer \
                       from a kind it defines and this surface does not decode",
                payload: batch_message(
                    "batch_progress_result",
                    "req-detail-1",
                    page_body(Vec::new(), false, JsonValue::Null),
                ),
            },
            DecodeRefusal {
                id: "approval-protocol-message",
                note: "the Approval lane's name on this lane's decoder, refused on the name axis \
                       so each protocol's closed kind set stays closed",
                payload: raw_message(
                    "automonique.approval",
                    1,
                    "batch_list_result",
                    "req-list-1",
                    page_body(Vec::new(), false, JsonValue::Null),
                ),
            },
            DecodeRefusal {
                id: "batch-document-schema-as-protocol",
                note: "the batch *document* schema is not this control lane's protocol name, and \
                       giving them one spelling would let a client admit either shape under the \
                       other's name",
                payload: raw_message(
                    "automonique.batch",
                    1,
                    "batch_list_result",
                    "req-list-1",
                    page_body(Vec::new(), false, JsonValue::Null),
                ),
            },
            DecodeRefusal {
                id: "unsupported-version",
                note: "this protocol at a major version neither side implements",
                payload: raw_message(
                    BATCH_CONTROL_PROTOCOL,
                    2,
                    "batch_list_result",
                    "req-list-1",
                    page_body(Vec::new(), false, JsonValue::Null),
                ),
            },
            DecodeRefusal {
                id: "non-canonical-key-order",
                note: "a payload that parses but is not canonical is refused, not normalized",
                payload: br#"{"kind":"refused","body":{"refusal":"registry_full"},"protocol":"automonique.batch.control","request_id":"req-register-1","version":1}"#.to_vec(),
            },
            DecodeRefusal {
                id: "empty-payload",
                note: "zero bytes is not an empty message",
                payload: Vec::new(),
            },
        ]
    }

    fn decode_refusal_entry(refusal: &DecodeRefusal) -> JsonValue {
        let category = BatchResponse::from_canonical_bytes(&refusal.payload)
            .err()
            .unwrap_or_else(|| panic!("{}: Rust accepted a payload it must refuse", refusal.id))
            .category()
            .to_owned();
        JsonValue::Object(vec![
            ("category".to_owned(), text(&category)),
            ("id".to_owned(), text(refusal.id)),
            ("note".to_owned(), text(refusal.note)),
            ("payload_hex".to_owned(), text(&hex(&refusal.payload))),
        ])
    }

    // -----------------------------------------------------------------------
    // The measured gap, on the way in
    // -----------------------------------------------------------------------

    /// A payload the Rust decoder refuses and the generated TypeScript accepts.
    ///
    /// Every one of these breaks a rule relating two fields of a *decoded*
    /// message — and a batch has more of those than any lane before it, because
    /// a batch is a relation between its members.
    struct RustOnlyRefusal {
        id: &'static str,
        note: &'static str,
        payload: Vec<u8>,
    }

    fn rust_only_refusals() -> Vec<RustOnlyRefusal> {
        vec![
            RustOnlyRefusal {
                id: "rollup-contradicts-members",
                note: "the rule that makes serving a derived state safe: the carried rollup is \
                       recomputed from the members beside it and refused when the two disagree. A \
                       daemon claiming `completed` over a running member cannot get that answer \
                       past its own decoder — and a client reading this file's decoder can only \
                       hold that the word is one of the six",
                payload: batch_message(
                    "batch_detail_result",
                    "req-detail-1",
                    detail_body(
                        vec![member_body(&[("state", text("running"))])],
                        "completed",
                    ),
                ),
            },
            RustOnlyRefusal {
                id: "detail-empty-membership",
                note: "a batch with no member has no state to roll up: `completed` over nothing \
                       is vacuously true, which is why the empty slice answers nothing at all. \
                       The empty *registration* is refused on the way out, because a builder \
                       holds the list it is sending",
                payload: batch_message(
                    "batch_detail_result",
                    "req-detail-1",
                    detail_body(Vec::new(), "completed"),
                ),
            },
            RustOnlyRefusal {
                id: "detail-duplicate-member",
                note: "one key named twice, refused rather than collapsed: a rollup over a \
                       membership that counted one submission twice would summarize the wrong set",
                payload: batch_message(
                    "batch_detail_result",
                    "req-detail-1",
                    detail_body(
                        vec![
                            member_body(&[]),
                            member_body(&[("ordinal", JsonValue::Integer(1))]),
                        ],
                        "completed",
                    ),
                ),
            },
            RustOnlyRefusal {
                id: "detail-members-out-of-order",
                note: "ordinals that are not `0..n` in order. Registration is the only writer of \
                       ordinals and writes exactly that, so a gap names a membership nobody \
                       declared",
                payload: batch_message(
                    "batch_detail_result",
                    "req-detail-1",
                    detail_body(
                        vec![
                            member_body(&[]),
                            member_body(&[
                                ("key", text("submit/zebra")),
                                ("ordinal", JsonValue::Integer(2)),
                            ]),
                        ],
                        "completed",
                    ),
                ),
            },
            RustOnlyRefusal {
                id: "member-sequence-coupling",
                note: "`ready` means no event has arrived, so a non-zero spool sequence beside it \
                       describes a run index row that cannot exist",
                payload: one_member_detail(member_body(&[
                    ("state", text("ready")),
                    ("last_sequence", JsonValue::Integer(5)),
                ])),
            },
            RustOnlyRefusal {
                id: "member-unsubmitted-above-first-revision",
                note: "registration is the only writer of `unsubmitted` and it always writes \
                       revision one, and the lattice has no edge back, so an unsubmitted member \
                       at revision two names a row nothing here wrote",
                payload: batch_message(
                    "batch_detail_result",
                    "req-detail-1",
                    detail_body(
                        vec![member_body(&[
                            ("state", text("unsubmitted")),
                            ("last_sequence", JsonValue::Integer(0)),
                            ("revision", JsonValue::Integer(2)),
                        ])],
                        "pending",
                    ),
                ),
            },
            RustOnlyRefusal {
                id: "advance-receipt-claims-unsubmitted",
                note: "the other half of the advance pin: the revision is believable and the \
                       progress is not, because no advance can leave a member unsubmitted",
                payload: batch_message(
                    "member_advanced",
                    "req-advance-1",
                    receipt_body(&[
                        ("state", text("unsubmitted")),
                        ("last_sequence", JsonValue::Integer(0)),
                    ]),
                ),
            },
            RustOnlyRefusal {
                id: "page-out-of-order",
                note: "rows that do not strictly increase by durable row identity, so the next \
                       page would re-serve or skip",
                payload: batch_message(
                    "batch_list_result",
                    "req-list-1",
                    page_body(
                        vec![
                            record_body(&[("entry_id", JsonValue::Integer(5))]),
                            record_body(&[("entry_id", JsonValue::Integer(2))]),
                        ],
                        false,
                        JsonValue::Null,
                    ),
                ),
            },
            RustOnlyRefusal {
                id: "continuation-incoherent",
                note: "rows follow, with no cursor to resume from",
                payload: batch_message(
                    "batch_list_result",
                    "req-list-1",
                    page_body(Vec::new(), true, JsonValue::Null),
                ),
            },
            RustOnlyRefusal {
                id: "continuation-rewinds",
                note: "a continuation cursor below the last row on the page, which would re-serve \
                       it",
                payload: batch_message(
                    "batch_list_result",
                    "req-list-1",
                    page_body(
                        vec![record_body(&[("entry_id", JsonValue::Integer(9))])],
                        true,
                        JsonValue::Integer(4),
                    ),
                ),
            },
            RustOnlyRefusal {
                id: "conflict-without-disagreement",
                note: "two revisions that agree is agreement rather than a conflict, and \
                       answering one would tell a caller to retry with the revision it already \
                       used. Unlike the approval lane's, this one *is* a decoder rule in Rust — \
                       the conflict frame carries both sides — so it is a real gap here rather \
                       than a constructor-only refusal",
                payload: batch_message(
                    "revision_conflict",
                    "req-advance-1",
                    JsonValue::Object(vec![
                        ("durable_revision".to_owned(), JsonValue::Integer(3)),
                        ("expected_revision".to_owned(), JsonValue::Integer(3)),
                    ]),
                ),
            },
        ]
    }

    fn rust_only_entry(refusal: &RustOnlyRefusal) -> JsonValue {
        let category = BatchResponse::from_canonical_bytes(&refusal.payload)
            .err()
            .unwrap_or_else(|| {
                panic!(
                    "{}: Rust accepts this, so it is not a rule the generated surface is missing",
                    refusal.id
                )
            })
            .category()
            .to_owned();
        JsonValue::Object(vec![
            ("id".to_owned(), text(refusal.id)),
            ("note".to_owned(), text(refusal.note)),
            ("payload_hex".to_owned(), text(&hex(&refusal.payload))),
            ("rust_category".to_owned(), text(&category)),
        ])
    }

    // -----------------------------------------------------------------------
    // Encode refusals
    // -----------------------------------------------------------------------

    /// A request the other implementation must refuse while building it.
    struct EncodeRefusal {
        id: &'static str,
        note: &'static str,
        kind: &'static str,
        request_id: String,
        params: JsonValue,
        category: String,
        /// The generated constructor that refuses the value on its own, the
        /// parameter it is applied to, and the violation it names.
        constructor: Option<(&'static str, &'static str, &'static str)>,
    }

    /// The category Rust reports for a request body carrying this exact value.
    ///
    /// Read back from the shipped decoder rather than constructed here.
    fn wire_category(kind: &str, body: JsonValue) -> String {
        BatchRequest::from_canonical_bytes(&batch_message(kind, "req-1", body))
            .err()
            .unwrap_or_else(|| panic!("{kind}: Rust accepted a body it must refuse"))
            .category()
            .to_owned()
    }

    /// A registration body, in the shape both the wire and the runner read.
    fn register_body(
        batch_id: &str,
        concurrency: JsonValue,
        label_value: JsonValue,
        members: Vec<JsonValue>,
    ) -> JsonValue {
        JsonValue::Object(vec![
            ("batch_id".to_owned(), text(batch_id)),
            ("concurrency".to_owned(), concurrency),
            ("label".to_owned(), label_value),
            ("members".to_owned(), JsonValue::Array(members)),
        ])
    }

    fn register_params(
        batch_id: &str,
        concurrency: JsonValue,
        label_value: JsonValue,
        members: Vec<JsonValue>,
    ) -> JsonValue {
        register_body(batch_id, concurrency, label_value, members)
    }

    fn advance_params(
        batch_id: &str,
        expected_revision: JsonValue,
        last_sequence: JsonValue,
        member_key: &str,
        state: &str,
    ) -> JsonValue {
        JsonValue::Object(vec![
            ("batch_id".to_owned(), text(batch_id)),
            ("expected_revision".to_owned(), expected_revision),
            ("last_sequence".to_owned(), last_sequence),
            ("member_key".to_owned(), text(member_key)),
            ("state".to_owned(), text(state)),
        ])
    }

    /// The same body with its counters as wire integers rather than as the
    /// decimal strings the runner reads.
    fn advance_body(
        batch_id: &str,
        expected_revision: i64,
        last_sequence: i64,
        member_key: &str,
        state: &str,
    ) -> JsonValue {
        JsonValue::Object(vec![
            ("batch_id".to_owned(), text(batch_id)),
            (
                "expected_revision".to_owned(),
                JsonValue::Integer(expected_revision),
            ),
            (
                "last_sequence".to_owned(),
                JsonValue::Integer(last_sequence),
            ),
            ("member_key".to_owned(), text(member_key)),
            ("state".to_owned(), text(state)),
        ])
    }

    fn list_params(size: JsonValue, since: JsonValue) -> JsonValue {
        JsonValue::Object(vec![
            ("page_size".to_owned(), size),
            ("since".to_owned(), since),
        ])
    }

    fn encode_refusals() -> Vec<EncodeRefusal> {
        let over_bound = over_bound_by_bytes_only();
        let long_request_id = "r".repeat(MAX_REQUEST_ID_BYTES + 1);
        let one_member = || vec![text("submit/only")];
        let sequential = || concurrency_params("sequential", None);

        let page_size_out_of_range = BatchPageSize::new(0)
            .expect_err("a page that admits nothing is refused")
            .category()
            .to_owned();
        let cursor_out_of_range = BatchRequest::ListBatches {
            request_id: request_id("req-list-1"),
            query: ListBatches::new(BatchCursor::new(wire_ceiling() + 1), page_size(1)),
        }
        .to_message()
        .expect_err("a cursor above the wire ceiling is refused")
        .category()
        .to_owned();
        let sequence_out_of_range = BatchRequest::AdvanceMember {
            request_id: request_id("req-advance-1"),
            advance: AdvanceMember::new(
                batch("batch/nightly-eval"),
                member("submit/only"),
                1,
                MemberProgress::Run(RunState::Running),
                wire_ceiling() + 1,
            )
            .expect("the coupling admits a non-zero sequence"),
        }
        .to_message()
        .expect_err("a sequence above the wire ceiling is refused")
        .category()
        .to_owned();
        let long_id_refusal = BatchApiError::Codec(
            RequestId::new(&long_request_id).expect_err("an overlong request id is refused"),
        )
        .category()
        .to_owned();
        let bad_id_refusal = BatchApiError::Codec(
            RequestId::new("req 1").expect_err("a space is outside the request id grammar"),
        )
        .category()
        .to_owned();

        vec![
            EncodeRefusal {
                id: "register-batch-empty-membership",
                note: "a batch that names no member is a unit with nothing in it. The builder \
                       holds the list, so this is refused before a frame is spent — and the \
                       refusal is the batch model's own rather than this lane's",
                kind: "register_batch",
                request_id: "req-register-1".to_owned(),
                params: register_params(
                    "batch/nightly-eval",
                    sequential(),
                    JsonValue::Null,
                    Vec::new(),
                ),
                category: wire_category(
                    "register_batch",
                    register_body(
                        "batch/nightly-eval",
                        concurrency_body("sequential", None),
                        JsonValue::Null,
                        Vec::new(),
                    ),
                ),
                constructor: None,
            },
            EncodeRefusal {
                id: "register-batch-membership-above-bound",
                note: "one member past MAX_BATCH_CONTROL_MEMBERS, built from the membership rule. \
                       The length is judged before any key is validated, so what these keys are \
                       does not matter",
                kind: "register_batch",
                request_id: "req-register-1".to_owned(),
                params: JsonValue::Object(vec![
                    ("batch_id".to_owned(), text("batch/nightly-eval")),
                    ("concurrency".to_owned(), sequential()),
                    ("label".to_owned(), JsonValue::Null),
                    ("members_rule".to_owned(), text("over-bound")),
                ]),
                category: wire_category(
                    "register_batch",
                    register_body(
                        "batch/nightly-eval",
                        concurrency_body("sequential", None),
                        JsonValue::Null,
                        ruled_membership("over-bound")
                            .iter()
                            .map(|key| text(key))
                            .collect(),
                    ),
                ),
                constructor: None,
            },
            EncodeRefusal {
                id: "register-batch-sequential-with-ceiling",
                note: "the discriminated coupling on the way out: a sequential policy carrying a \
                       ceiling is refused rather than silently dropped, because dropping it would \
                       encode a policy the caller did not ask for. A typed caller cannot even \
                       write this — the union has no such shape — so the runtime check is what \
                       catches the untyped one",
                kind: "register_batch",
                request_id: "req-register-1".to_owned(),
                params: register_params(
                    "batch/nightly-eval",
                    concurrency_params("sequential", Some(4)),
                    JsonValue::Null,
                    one_member(),
                ),
                category: wire_category(
                    "register_batch",
                    register_body(
                        "batch/nightly-eval",
                        concurrency_body("sequential", Some(4)),
                        JsonValue::Null,
                        vec![text("submit/only")],
                    ),
                ),
                constructor: None,
            },
            EncodeRefusal {
                id: "register-batch-bounded-parallel-without-ceiling",
                note: "and from the other side: the bounded word with no bound",
                kind: "register_batch",
                request_id: "req-register-1".to_owned(),
                params: register_params(
                    "batch/nightly-eval",
                    concurrency_params("bounded_parallel", None),
                    JsonValue::Null,
                    one_member(),
                ),
                category: wire_category(
                    "register_batch",
                    register_body(
                        "batch/nightly-eval",
                        concurrency_body("bounded_parallel", None),
                        JsonValue::Null,
                        vec![text("submit/only")],
                    ),
                ),
                constructor: None,
            },
            EncodeRefusal {
                id: "register-batch-ceiling-zero",
                note: "a ceiling that admits nothing in flight is a batch that never starts \
                       rather than a batch without limit",
                kind: "register_batch",
                request_id: "req-register-1".to_owned(),
                params: register_params(
                    "batch/nightly-eval",
                    concurrency_params("bounded_parallel", Some(0)),
                    JsonValue::Null,
                    one_member(),
                ),
                category: ConcurrencyPolicy::bounded_parallel(0)
                    .expect_err("a ceiling of zero is refused")
                    .category()
                    .to_owned(),
                constructor: None,
            },
            EncodeRefusal {
                id: "register-batch-ceiling-above-membership",
                note: "one past the members a batch can hold, under its own category: a caller \
                       told only `invalid ceiling` could not tell this from a ceiling of zero, \
                       and the two are fixed differently",
                kind: "register_batch",
                request_id: "req-register-1".to_owned(),
                params: register_params(
                    "batch/nightly-eval",
                    concurrency_params("bounded_parallel", Some(MAX_BATCH_MEMBERS as u64 + 1)),
                    JsonValue::Null,
                    one_member(),
                ),
                category: ConcurrencyPolicy::bounded_parallel(
                    u32::try_from(MAX_BATCH_MEMBERS + 1).expect("the ceiling fits a u32"),
                )
                .expect_err("an unreachable ceiling is refused")
                .category()
                .to_owned(),
                constructor: None,
            },
            EncodeRefusal {
                id: "register-batch-undefined-concurrency-kind",
                note: "a brand exists only in the type checker, so the builder is where an \
                       untyped caller's undefined policy word is stopped rather than put on the \
                       wire",
                kind: "register_batch",
                request_id: "req-register-1".to_owned(),
                params: register_params(
                    "batch/nightly-eval",
                    concurrency_params("unbounded", None),
                    JsonValue::Null,
                    one_member(),
                ),
                category: wire_category(
                    "register_batch",
                    register_body(
                        "batch/nightly-eval",
                        concurrency_body("unbounded", None),
                        JsonValue::Null,
                        vec![text("submit/only")],
                    ),
                ),
                constructor: None,
            },
            EncodeRefusal {
                id: "register-batch-label-empty",
                note: "empty is refused rather than read as `no label`: a batch with no name \
                       carries an explicit null, and the two are different facts",
                kind: "register_batch",
                request_id: "req-register-1".to_owned(),
                params: register_params("batch/nightly-eval", sequential(), text(""), one_member()),
                // The message-level category, not the bounded type's own: this
                // lane wraps every bounded-value refusal in one field category,
                // and a client is told what the daemon would tell it.
                category: wire_category(
                    "register_batch",
                    register_body(
                        "batch/nightly-eval",
                        concurrency_body("sequential", None),
                        text(""),
                        vec![text("submit/only")],
                    ),
                ),
                constructor: Some(("BatchLabel", "label", "empty")),
            },
            EncodeRefusal {
                id: "register-batch-member-key-over-bound",
                note: "one member key inside the UTF-16 code-unit bound and outside the UTF-8 one \
                       the registry stores under. Every key in the list is validated, not only \
                       the first",
                kind: "register_batch",
                request_id: "req-register-1".to_owned(),
                params: register_params(
                    "batch/nightly-eval",
                    sequential(),
                    JsonValue::Null,
                    vec![text("submit/only"), text(&over_bound)],
                ),
                category: wire_category(
                    "register_batch",
                    register_body(
                        "batch/nightly-eval",
                        concurrency_body("sequential", None),
                        JsonValue::Null,
                        vec![text("submit/only"), text(&over_bound)],
                    ),
                ),
                constructor: None,
            },
            EncodeRefusal {
                id: "advance-member-undefined-progress",
                note: "a member progress this build does not define, stopped at the builder. \
                       `skipped` is not a word this lattice has an edge to",
                kind: "advance_member",
                request_id: "req-advance-1".to_owned(),
                params: advance_params(
                    "batch/nightly-eval",
                    number(1),
                    number(3),
                    "submit/only",
                    "skipped",
                ),
                category: wire_category(
                    "advance_member",
                    advance_body("batch/nightly-eval", 1, 3, "submit/only", "skipped"),
                ),
                constructor: None,
            },
            EncodeRefusal {
                id: "advance-member-progress-title-case",
                note: "the spelling is exact and lowercase: `Running` is not `running`, and a \
                       vocabulary that case-folded would admit words the registry's CHECK refuses",
                kind: "advance_member",
                request_id: "req-advance-1".to_owned(),
                params: advance_params(
                    "batch/nightly-eval",
                    number(1),
                    number(3),
                    "submit/only",
                    "Running",
                ),
                category: wire_category(
                    "advance_member",
                    advance_body("batch/nightly-eval", 1, 3, "submit/only", "Running"),
                ),
                constructor: None,
            },
            EncodeRefusal {
                id: "advance-member-expected-revision-zero",
                note: "a fence against a row no writer produced. Registration writes revision \
                       one, so zero is not a revision a caller could ever be advancing from",
                kind: "advance_member",
                request_id: "req-advance-1".to_owned(),
                params: advance_params(
                    "batch/nightly-eval",
                    number(0),
                    number(3),
                    "submit/only",
                    "running",
                ),
                category: wire_category(
                    "advance_member",
                    advance_body("batch/nightly-eval", 0, 3, "submit/only", "running"),
                ),
                constructor: Some(("BatchRevision", "expected_revision", "out_of_range")),
            },
            EncodeRefusal {
                id: "advance-member-sequence-above-wire-ceiling",
                note: "a sequence one past the largest integer this wire carries, which is a \
                       counter refusal rather than a malformed body",
                kind: "advance_member",
                request_id: "req-advance-1".to_owned(),
                params: advance_params(
                    "batch/nightly-eval",
                    number(1),
                    number(wire_ceiling() + 1),
                    "submit/only",
                    "running",
                ),
                category: sequence_out_of_range,
                constructor: Some(("LastSequence", "last_sequence", "out_of_range")),
            },
            EncodeRefusal {
                id: "advance-member-key-control-character",
                note: "a control character in a member key, which the wire never carries raw",
                kind: "advance_member",
                request_id: "req-advance-1".to_owned(),
                params: advance_params(
                    "batch/nightly-eval",
                    number(1),
                    number(3),
                    "submit\u{7}only",
                    "running",
                ),
                category: wire_category(
                    "advance_member",
                    advance_body("batch/nightly-eval", 1, 3, "submit\u{7}only", "running"),
                ),
                constructor: Some(("BatchMemberKey", "member_key", "invalid_character")),
            },
            EncodeRefusal {
                id: "list-batches-page-size-zero",
                note: "a page that admits nothing cannot make progress, so zero is refused rather \
                       than treated as a default",
                kind: "list_batches",
                request_id: "req-list-1".to_owned(),
                params: list_params(number(0), number(0)),
                category: page_size_out_of_range.clone(),
                constructor: Some(("BatchPageSize", "page_size", "out_of_range")),
            },
            EncodeRefusal {
                id: "list-batches-page-size-above-bound",
                note: "one past MAX_BATCH_PAGE_ITEMS, which is a page bound derived from the \
                       frame arithmetic of the rows it carries rather than chosen",
                kind: "list_batches",
                request_id: "req-list-1".to_owned(),
                params: list_params(number(MAX_BATCH_PAGE_ITEMS as u64 + 1), number(0)),
                category: page_size_out_of_range,
                constructor: Some(("BatchPageSize", "page_size", "out_of_range")),
            },
            EncodeRefusal {
                id: "list-batches-cursor-above-wire-ceiling",
                note: "a cursor one past the largest integer this wire carries",
                kind: "list_batches",
                request_id: "req-list-1".to_owned(),
                params: list_params(number(1), number(wire_ceiling() + 1)),
                category: cursor_out_of_range,
                constructor: Some(("BatchCursor", "since", "out_of_range")),
            },
            EncodeRefusal {
                id: "batch-detail-batch-id-empty",
                note: "an empty identity names no batch to read",
                kind: "batch_detail",
                request_id: "req-detail-1".to_owned(),
                params: JsonValue::Object(vec![("batch_id".to_owned(), text(""))]),
                category: wire_category(
                    "batch_detail",
                    JsonValue::Object(vec![("batch_id".to_owned(), text(""))]),
                ),
                constructor: Some(("BatchId", "batch_id", "empty")),
            },
            EncodeRefusal {
                id: "request-id-too-long",
                note: "the envelope's fields are judged by the shared codec, whose refusal for a \
                       bound is not the one this protocol uses for a body",
                kind: "batch_detail",
                request_id: long_request_id,
                params: JsonValue::Object(vec![(
                    "batch_id".to_owned(),
                    text("batch/nightly-eval"),
                )]),
                category: long_id_refusal,
                constructor: Some(("RequestId", "request_id", "too_long")),
            },
            EncodeRefusal {
                id: "request-id-outside-grammar",
                note: "a grammar refusal is not a bounds refusal, and the categories differ. A \
                       space is outside the correlation identifier's grammar and inside the batch \
                       identity's, which is the difference this lane's looser identifier makes",
                kind: "batch_detail",
                request_id: "req 1".to_owned(),
                params: JsonValue::Object(vec![(
                    "batch_id".to_owned(),
                    text("batch/nightly eval"),
                )]),
                category: bad_id_refusal,
                constructor: Some(("RequestId", "request_id", "invalid_character")),
            },
        ]
    }

    fn encode_refusal_entry(refusal: &EncodeRefusal) -> JsonValue {
        let mut entry = vec![
            ("category".to_owned(), text(&refusal.category)),
            ("id".to_owned(), text(refusal.id)),
            ("kind".to_owned(), text(refusal.kind)),
            ("note".to_owned(), text(refusal.note)),
            ("params".to_owned(), refusal.params.clone()),
            ("request_id".to_owned(), text(&refusal.request_id)),
        ];
        if let Some((constructor, parameter, violation)) = refusal.constructor {
            // Named `refused_by` rather than `constructor`: a JSON object parsed
            // by a JavaScript reader inherits `constructor` from its prototype.
            entry.push(("refused_by".to_owned(), text(constructor)));
            entry.push(("refused_param".to_owned(), text(parameter)));
            entry.push(("violation".to_owned(), text(violation)));
        }
        JsonValue::Object(entry)
    }

    // -----------------------------------------------------------------------
    // The measured gap, on the way out
    // -----------------------------------------------------------------------

    /// A request Rust refuses to build and the generated encoder accepts.
    ///
    /// The encode side has a gap of its own on this lane, and one entry is the
    /// whole of it: the sequence coupling relates two fields of a request, and
    /// the generated encoder holds each field's own bounds. The runner asserts
    /// these *encode*, so teaching the generator the rule turns the suite red
    /// until the entry moves to `encode_refusals`.
    struct RustOnlyEncodeRefusal {
        id: &'static str,
        note: &'static str,
        kind: &'static str,
        request_id: String,
        params: JsonValue,
        /// The body Rust is asked to admit, with wire integers.
        body: JsonValue,
    }

    fn rust_only_encode_refusals() -> Vec<RustOnlyEncodeRefusal> {
        vec![
            RustOnlyEncodeRefusal {
                id: "advance-member-sequence-coupling",
                note: "`ready` means the daemon holds a document and no event has arrived, so a \
                       non-zero sequence beside it describes a run index row that cannot exist. A \
                       property of the request alone, and one the generated encoder does not hold",
                kind: "advance_member",
                request_id: "req-advance-1".to_owned(),
                params: advance_params(
                    "batch/nightly-eval",
                    number(1),
                    number(5),
                    "submit/only",
                    "ready",
                ),
                body: advance_body("batch/nightly-eval", 1, 5, "submit/only", "ready"),
            },
            RustOnlyEncodeRefusal {
                id: "advance-member-terminal-at-zero-sequence",
                note: "the coupling from the other side: a member that reached a terminal state \
                       with no spool event behind it",
                kind: "advance_member",
                request_id: "req-advance-1".to_owned(),
                params: advance_params(
                    "batch/nightly-eval",
                    number(1),
                    number(0),
                    "submit/only",
                    "completed",
                ),
                body: advance_body("batch/nightly-eval", 1, 0, "submit/only", "completed"),
            },
            RustOnlyEncodeRefusal {
                id: "register-batch-duplicate-member",
                note: "one key named twice. A caller that named a submission twice believes it \
                       asked for something it did not, so the registration is refused rather than \
                       collapsed — a relation between two items of one list, which the generated \
                       encoder's per-item bounds cannot see",
                kind: "register_batch",
                request_id: "req-register-1".to_owned(),
                params: register_params(
                    "batch/nightly-eval",
                    concurrency_params("sequential", None),
                    JsonValue::Null,
                    vec![text("submit/only"), text("submit/only")],
                ),
                body: register_body(
                    "batch/nightly-eval",
                    concurrency_body("sequential", None),
                    JsonValue::Null,
                    vec![text("submit/only"), text("submit/only")],
                ),
            },
        ]
    }

    fn rust_only_encode_entry(refusal: &RustOnlyEncodeRefusal) -> JsonValue {
        let category = BatchRequest::from_canonical_bytes(&batch_message(
            refusal.kind,
            &refusal.request_id,
            refusal.body.clone(),
        ))
        .err()
        .unwrap_or_else(|| {
            panic!(
                "{}: Rust accepts this body, so it is not a rule the generated encoder is missing",
                refusal.id
            )
        })
        .category()
        .to_owned();
        JsonValue::Object(vec![
            ("id".to_owned(), text(refusal.id)),
            ("kind".to_owned(), text(refusal.kind)),
            ("note".to_owned(), text(refusal.note)),
            ("params".to_owned(), refusal.params.clone()),
            ("request_id".to_owned(), text(&refusal.request_id)),
            ("rust_category".to_owned(), text(&category)),
        ])
    }

    // -----------------------------------------------------------------------
    // The corpus file
    // -----------------------------------------------------------------------

    fn corpus() -> String {
        let document = JsonValue::Object(vec![
            (
                "decode_refusals".to_owned(),
                JsonValue::Array(decode_refusals().iter().map(decode_refusal_entry).collect()),
            ),
            (
                "encode_refusals".to_owned(),
                JsonValue::Array(encode_refusals().iter().map(encode_refusal_entry).collect()),
            ),
            (
                "generator".to_owned(),
                text("automonique-protocol tests/codegen.rs, module batch_surface"),
            ),
            (
                "membership_rules".to_owned(),
                JsonValue::Array(
                    membership_rules()
                        .iter()
                        .map(membership_rule_entry)
                        .collect(),
                ),
            ),
            (
                "membership_rules_note".to_owned(),
                text(
                    "A maximal registration is MAX_BATCH_CONTROL_MEMBERS keys of \
                     MAX_BATCH_MEMBER_KEY_BYTES, which is 33 KiB of literal nobody can review. \
                     Each implementation builds the list from the rule instead: the key at one \
                     position is its three-digit decimal index, filled to key_bytes with the one \
                     character that escapes to two canonical bytes, or `member-NNN` where \
                     key_bytes is zero and what is being measured is the length of the list. That \
                     the two implementations read the rule the same way is measured rather than \
                     assumed, because the bytes the runner reports are compared against the bytes \
                     Rust built from the same rule.",
                ),
            ),
            (
                "note".to_owned(),
                text(
                    "Generated from the shipped Rust constructors: every canonical byte string \
                     here was produced by encoding a real message and re-read through \
                     from_canonical_bytes before it was written, and every refusal category was \
                     read back from the error Rust returned for that exact input. Counters travel \
                     as decimal strings because a JSON reader using a double would round the \
                     largest of them without saying so. Rust is the wire source of truth, so a \
                     disagreement is fixed in whichever implementation is wrong — never in this \
                     file.",
                ),
            ),
            ("protocol".to_owned(), text(BATCH_CONTROL_PROTOCOL)),
            (
                "requests".to_owned(),
                JsonValue::Array(request_cases().iter().map(request_entry).collect()),
            ),
            (
                "responses".to_owned(),
                JsonValue::Array(response_cases().iter().map(response_entry).collect()),
            ),
            (
                "rust_only_encode_refusals".to_owned(),
                JsonValue::Array(
                    rust_only_encode_refusals()
                        .iter()
                        .map(rust_only_encode_entry)
                        .collect(),
                ),
            ),
            (
                "rust_only_encode_refusals_note".to_owned(),
                text(
                    "Requests the Rust constructors refuse and the generated encoder builds. Each \
                     breaks a rule relating two fields of a request, or two items of one list, \
                     which the generated surface does not hold. The runner asserts these encode, \
                     so the gap is measured rather than described.",
                ),
            ),
            (
                "rust_only_refusals".to_owned(),
                JsonValue::Array(rust_only_refusals().iter().map(rust_only_entry).collect()),
            ),
            (
                "rust_only_refusals_note".to_owned(),
                text(
                    "Payloads the Rust decoder refuses and the generated TypeScript accepts. Each \
                     breaks a rule relating two fields of a decoded message — and a batch has \
                     more of those than any lane before it, because a batch is a relation between \
                     its members. The rolled-up state is the one that matters most: it is \
                     recomputed from the members beside it in Rust and only held to the closed \
                     vocabulary here. The advance receipt's revision is deliberately absent from \
                     this list: `two or above` is a bound on one field's own value, the generated \
                     decoder does hold it, and decode_refusals is where that is proved from both \
                     ends. The runner asserts these decode, so teaching the generator one of \
                     these rules turns the suite red until the entry moves to decode_refusals.",
                ),
            ),
            (
                "version".to_owned(),
                JsonValue::Integer(i64::from(MajorVersion::FIRST.get())),
            ),
        ]);
        let mut out = String::new();
        write_pretty(&document, 0, &mut out);
        out.push('\n');
        out
    }

    /// The drift gate over the corpus, and the regeneration that closes it.
    #[test]
    fn the_checked_in_corpus_matches_regeneration() {
        let expected = corpus();
        let path = corpus_path();
        if regenerating() {
            let staging = path.with_extension("json.staging");
            std::fs::write(&staging, &expected).expect("stage the corpus");
            std::fs::rename(&staging, &path).expect("publish the corpus");
            return;
        }
        let actual = std::fs::read_to_string(&path)
            .expect("the corpus is checked in — regenerate it to create it");
        if actual != expected {
            let difference = actual
                .lines()
                .zip(expected.lines())
                .enumerate()
                .find(|(_, (left, right))| left != right)
                .map_or_else(
                    || {
                        format!(
                            "{} lines on disk, {} lines generated",
                            actual.lines().count(),
                            expected.lines().count()
                        )
                    },
                    |(index, (left, right))| {
                        let shorten = |line: &str| line.chars().take(120).collect::<String>();
                        format!(
                            "line {}: on disk {:?}, generated {:?}",
                            index + 1,
                            shorten(left),
                            shorten(right)
                        )
                    },
                );
            panic!(
                "the checked-in batch corpus no longer matches the Rust encoders: \
                 {difference}\n\nRegenerate with: {REGENERATE_COMMAND}"
            );
        }
    }

    /// Every request this protocol version defines is generated or named absent.
    #[test]
    fn every_request_kind_is_generated_or_named_as_absent() {
        let id = request_id("req-coverage-1");
        let requests = vec![
            BatchRequest::RegisterBatch {
                request_id: id.clone(),
                registration: RegisterBatch::new(
                    batch("batch/one"),
                    None,
                    ConcurrencyPolicy::Sequential,
                    vec![member("submit/one")],
                )
                .expect("a registration"),
            },
            BatchRequest::AdvanceMember {
                request_id: id.clone(),
                advance: AdvanceMember::new(
                    batch("batch/one"),
                    member("submit/one"),
                    1,
                    MemberProgress::Run(RunState::Running),
                    2,
                )
                .expect("an advance"),
            },
            BatchRequest::ListBatches {
                request_id: id.clone(),
                query: ListBatches::new(BatchCursor::START, page_size(1)),
            },
            BatchRequest::BatchDetail {
                request_id: id,
                batch_id: batch("batch/one"),
            },
        ];
        // The match is the point: a request added to `BatchRequest` fails to
        // compile here rather than quietly falling outside the generated
        // surface.
        for request in &requests {
            match request {
                BatchRequest::RegisterBatch { .. }
                | BatchRequest::AdvanceMember { .. }
                | BatchRequest::ListBatches { .. }
                | BatchRequest::BatchDetail { .. } => {}
            }
        }
        let encoded: BTreeSet<String> = requests
            .iter()
            .map(|request| {
                request
                    .to_message()
                    .expect("each request encodes")
                    .envelope()
                    .kind()
                    .as_str()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            encoded.len(),
            requests.len(),
            "one request per variant is required, each with its own kind"
        );

        let surface = surface();
        let mut covered: BTreeSet<String> = surface
            .requests
            .iter()
            .map(|request| request.kind.clone())
            .collect();
        for kind in &surface.request_kinds_not_generated {
            assert!(
                covered.insert(kind.clone()),
                "{kind} is both generated and named as absent"
            );
        }
        assert_eq!(
            covered, encoded,
            "the generated batch surface does not account for every request kind the Rust \
             encoders produce; regenerate with: {REGENERATE_COMMAND}"
        );
    }

    /// Every answer this protocol version defines is decoded or named undecoded.
    #[test]
    fn every_response_kind_is_decoded_or_named_as_undecoded() {
        let id = request_id("req-coverage-1");
        let responses = vec![
            BatchResponse::Registered {
                request_id: id.clone(),
                receipt: BatchReceiptView::new(
                    1,
                    batch("batch/one"),
                    1,
                    1,
                    EpochMillis::from_millis(0),
                )
                .expect("a receipt"),
            },
            BatchResponse::MemberAdvanced {
                request_id: id.clone(),
                receipt: MemberReceiptView::new(MemberReceiptParts {
                    batch_id: batch("batch/one"),
                    member_key: member("submit/one"),
                    ordinal: 0,
                    progress: MemberProgress::Run(RunState::Running),
                    last_sequence: 1,
                    revision: 2,
                    updated_at: EpochMillis::from_millis(0),
                })
                .expect("an advance receipt"),
            },
            BatchResponse::BatchList {
                request_id: id.clone(),
                page: BatchListPage::new(Vec::new(), BatchContinuation::Complete).expect("a page"),
            },
            BatchResponse::BatchDetail {
                request_id: id.clone(),
                detail: BatchDetailResult::new(
                    record(Row {
                        entry_id: 1,
                        batch_id: "batch/one",
                        label: None,
                        concurrency: ConcurrencyPolicy::Sequential,
                        created_at_ms: 0,
                        revision: 1,
                    }),
                    vec![member_row(
                        0,
                        "submit/one",
                        MemberProgress::Unsubmitted,
                        0,
                        1,
                    )],
                )
                .expect("a detail"),
            },
            BatchResponse::conflict(id.clone(), 1, 2).expect("a conflict"),
            BatchResponse::Refused {
                request_id: id,
                refusal: BatchRefusal::UnknownBatch,
            },
        ];
        // The match is the point: a variant added to `BatchResponse` fails to
        // compile here rather than slipping past a surface that ignores it.
        for response in &responses {
            match response {
                BatchResponse::Registered { .. }
                | BatchResponse::MemberAdvanced { .. }
                | BatchResponse::BatchList { .. }
                | BatchResponse::BatchDetail { .. }
                | BatchResponse::Conflict { .. }
                | BatchResponse::Refused { .. } => {}
            }
        }
        let encoded: BTreeSet<String> = responses
            .iter()
            .map(|response| {
                response
                    .to_message()
                    .expect("each response encodes")
                    .envelope()
                    .kind()
                    .as_str()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            encoded.len(),
            responses.len(),
            "one response per variant is required, each with its own kind"
        );

        let surface = surface();
        let mut covered: BTreeSet<String> = surface
            .responses
            .iter()
            .map(|response| response.kind.clone())
            .collect();
        for kind in &surface.response_kinds_not_decoded {
            assert!(
                covered.insert(kind.clone()),
                "{kind} is both decoded and named as undecoded"
            );
        }
        assert_eq!(
            covered, encoded,
            "the generated batch surface does not account for every answer the daemon can \
             produce; regenerate with: {REGENERATE_COMMAND}"
        );
    }

    /// The four closed vocabularies, restated here rather than read back from
    /// the generator — and then checked against the Rust arrays themselves.
    ///
    /// Three of the four are `batch_runner`'s rather than this lane's, and
    /// `MemberProgress` is in turn `runs_api`'s six spellings plus one. A
    /// generator that dropped a variant would agree with itself perfectly; this
    /// is the second opinion, and the third is the assertion against
    /// `RunState::ALL` below, which is what makes a word impossible to drift
    /// between a batch document and a run.
    #[test]
    fn every_closed_vocabulary_carries_all_of_its_variants() {
        let generated = generated_batch();
        let expected: [(&str, &[&str]); 4] = [
            (
                "BatchRefusal",
                &[
                    "already_registered",
                    "concurrency_ceiling",
                    "cursor_out_of_range",
                    "duplicate_member",
                    "empty_batch",
                    "illegal_transition",
                    "invalid_field",
                    "registry_full",
                    "sequence_coupling",
                    "sequence_regression",
                    "too_many_members",
                    "unknown_batch",
                    "unknown_member",
                ],
            ),
            (
                "BatchState",
                &[
                    "cancelled",
                    "completed",
                    "failed",
                    "mixed",
                    "pending",
                    "running",
                ],
            ),
            ("ConcurrencyKind", &["bounded_parallel", "sequential"]),
            (
                "MemberProgress",
                &[
                    "cancelled",
                    "completed",
                    "failed",
                    "ready",
                    "running",
                    "timed_out",
                    "unsubmitted",
                ],
            ),
        ];
        for (name, values) in expected {
            let literals: Vec<String> = values.iter().map(|value| format!("\"{value}\"")).collect();
            let declaration = format!("export type {name} = {};", literals.join(" | "));
            assert!(
                generated.contains(&declaration),
                "the batch surface lost a {name} variant.\nexpected: {declaration}"
            );
            assert!(
                generated.contains(&format!(
                    "export const {name}_VALUES: readonly {name}[] = [{}];",
                    literals.join(", ")
                )),
                "the {name} table does not match its type"
            );
            assert!(
                generated.contains(&format!(
                    "export function decode{name}(value: string): {name} {{"
                )),
                "the batch surface does not refuse an undefined {name}"
            );
        }
        // The spellings themselves, read from the Rust enums rather than from
        // the literals above, so the two can never drift into agreeing with
        // each other while disagreeing with the wire.
        assert_eq!(
            ConcurrencyKind::ALL.map(ConcurrencyKind::as_str),
            ["sequential", "bounded_parallel"],
            "the concurrency vocabulary is the pair the batch model declares"
        );
        assert_eq!(
            BatchState::ALL.map(BatchState::as_str),
            [
                "pending",
                "running",
                "completed",
                "failed",
                "cancelled",
                "mixed"
            ],
            "the rollup vocabulary is the six the batch model derives"
        );
        // Six of the seven member spellings are the run states, reused rather
        // than re-spelled: this is what makes a member's word and a run's word
        // impossible to tell apart, because they are the same word.
        let progresses: Vec<&str> = MemberProgress::ALL
            .iter()
            .map(|progress| progress.as_str())
            .collect();
        let runs: Vec<&str> = RunState::ALL.iter().map(|state| state.as_str()).collect();
        assert_eq!(
            progresses[0], "unsubmitted",
            "the one member spelling a run vocabulary cannot express comes first"
        );
        assert_eq!(
            &progresses[1..],
            runs.as_slice(),
            "the member vocabulary is RunState's own spellings after the unsubmitted one"
        );
        for spelling in &runs {
            assert!(
                generated.contains(&format!("\"{spelling}\"")),
                "the batch surface lost the run spelling {spelling}, which a member reuses"
            );
        }
        // An unbounded concurrency policy has no spelling, in either language.
        for absent in ["unbounded", "parallel", "unlimited", "skipped", "partial"] {
            assert!(
                !generated.contains(&format!("\"{absent}\"")),
                "the batch surface carries a spelling this product does not define: {absent}"
            );
        }
    }

    /// The bounds in the output are the Rust constants, and they are applied.
    #[test]
    fn the_generated_batch_bounds_are_the_rust_constants() {
        let generated = generated_batch();
        for declaration in [
            format!("export const MAX_BATCH_CONTROL_MEMBERS = {MAX_BATCH_CONTROL_MEMBERS};"),
            format!("export const MAX_BATCH_PAGE_ITEMS = {MAX_BATCH_PAGE_ITEMS};"),
            format!(
                "export const MAX_BATCH_CONTROL_CANONICAL_BYTES = \
                 {MAX_BATCH_CONTROL_CANONICAL_BYTES};"
            ),
            format!("export const BatchId_MAX_BYTES = {MAX_BATCH_ID_BYTES};"),
            format!("export const BatchMemberKey_MAX_BYTES = {MAX_BATCH_MEMBER_KEY_BYTES};"),
            format!("export const BatchLabel_MAX_BYTES = {MAX_BATCH_LABEL_BYTES};"),
            format!("export const BatchPageSize_MAX = {MAX_BATCH_PAGE_ITEMS}n;"),
            "export const BatchPageSize_MIN = 1n;".to_owned(),
            "export const BatchCursor_MIN = 0n;".to_owned(),
            format!("export const BatchCursor_MAX = {}n;", i64::MAX),
            // The concurrency ceiling is the *model*'s membership, not this
            // lane's: a policy may declare more members in flight than this
            // transport can register in one frame.
            "export const ConcurrencyCeiling_MIN = 1n;".to_owned(),
            format!("export const ConcurrencyCeiling_MAX = {MAX_BATCH_MEMBERS}n;"),
            "export const BatchRevision_MIN = 1n;".to_owned(),
            // The advance pin: registration owns revision one.
            "export const AdvancedRevision_MIN = 2n;".to_owned(),
            "export const MemberOrdinal_MIN = 0n;".to_owned(),
            format!(
                "export const MemberOrdinal_MAX = {}n;",
                MAX_BATCH_CONTROL_MEMBERS - 1
            ),
            "export const MemberCount_MIN = 1n;".to_owned(),
            format!("export const MemberCount_MAX = {MAX_BATCH_CONTROL_MEMBERS}n;"),
            format!("export const BATCH_CONTROL_PROTOCOL = \"{BATCH_CONTROL_PROTOCOL}\";"),
            format!(
                "export const BATCH_CONTROL_API_SCHEMA_V1 = \"{}\";",
                automonique_protocol::batch_api::BATCH_CONTROL_API_SCHEMA_V1
            ),
        ] {
            assert!(
                generated.contains(&declaration),
                "the batch surface does not carry the Rust bound: {declaration}"
            );
        }
        // Declaring a bound is not applying it.
        for application in [
            format!(
                "  if (byteLength(value) > {MAX_BATCH_MEMBER_KEY_BYTES}) throw new \
                 ValidationError(\"BatchMemberKey\", \"too_long\");"
            ),
            format!(
                "  if (byteLength(value) > {MAX_BATCH_LABEL_BYTES}) throw new \
                 ValidationError(\"BatchLabel\", \"too_long\");"
            ),
            format!(
                "  if (typeof value !== \"bigint\" || value < 1n || value > {MAX_BATCH_PAGE_ITEMS}n) throw new \
                 ValidationError(\"BatchPageSize\", \"out_of_range\");"
            ),
            format!(
                "  if (typeof value !== \"bigint\" || value < 1n || value > {MAX_BATCH_MEMBERS}n) throw new \
                 ValidationError(\"ConcurrencyCeiling\", \"out_of_range\");"
            ),
            format!(
                "  if (typeof value !== \"bigint\" || value < 0n || value > {}n) throw new ValidationError(\"MemberOrdinal\", \
                 \"out_of_range\");",
                MAX_BATCH_CONTROL_MEMBERS - 1
            ),
            "  if (typeof value !== \"bigint\" || value < 2n || value > 9223372036854775807n) throw new \
             ValidationError(\"AdvancedRevision\", \"out_of_range\");"
                .to_owned(),
            // The membership bound is applied on the way out, over the list the
            // caller supplied, before any key in it is validated.
            "boundedItems(body.members, MAX_BATCH_CONTROL_MEMBERS, BATCH_MEMBERSHIP_TOO_LARGE, \
             BATCH_EMPTY_BATCH)"
                .to_owned(),
            // And on the way in, over the membership a detail read carries.
            "bodyArray(fields, \"members\", BATCH_INVALID_BODY, MAX_BATCH_CONTROL_MEMBERS, \
             BATCH_MEMBERSHIP_TOO_LARGE)"
                .to_owned(),
            "bodyArray(fields, \"batches\", BATCH_INVALID_BODY, MAX_BATCH_PAGE_ITEMS, \
             BATCH_PAGE_TOO_LARGE)"
                .to_owned(),
        ] {
            assert!(
                generated.contains(&application),
                "the batch surface declares a bound it does not apply: {application}"
            );
        }
        // The grammars are the registry's own looser ones, not `DurableId`'s:
        // the registry stores any bounded control-free identifier.
        for name in ["BatchId", "BatchMemberKey", "BatchLabel"] {
            assert!(
                generated.contains(&format!(
                    "export const {name}_PATTERN = /^[^\\p{{Cc}}]+$/u;"
                )),
                "{name} does not carry the control-free grammar the durable registry stores under"
            );
        }
        // This lane's membership ceiling is deliberately *not* the model's, and
        // this check is only worth making while the two differ.
        assert_ne!(
            MAX_BATCH_CONTROL_MEMBERS, MAX_BATCH_MEMBERS,
            "the transport ceiling and the model ceiling are reconciled, which the module \
             documentation says they must not be"
        );
    }

    /// The discriminated concurrency policy is a union, not a nullable field.
    ///
    /// This is the shape claim, and it is worth asserting literally: a generator
    /// that emitted `{kind: ConcurrencyKind; max_in_flight: ConcurrencyCeiling |
    /// null}` would satisfy every byte-for-byte check in this suite while
    /// type-checking a program that asked a sequential policy for its ceiling.
    #[test]
    fn the_concurrency_policy_is_carried_as_a_discriminated_union() {
        let generated = generated_batch();
        for declaration in [
            "export type BatchConcurrency =",
            "  | {readonly kind: \"bounded_parallel\"; readonly max_in_flight: \
             ConcurrencyCeiling}",
            "  | {readonly kind: \"sequential\"};",
            "export function assertNeverBatchConcurrency(value: never): never {",
            "export function encodeBatchConcurrency(value: BatchConcurrency): JsonValue {",
            "export function decodeBatchConcurrency(body: JsonValue): BatchConcurrency {",
        ] {
            assert!(
                generated.contains(declaration),
                "the concurrency policy lost part of its discriminated shape.\nexpected: \
                 {declaration}"
            );
        }
        // The coupling is refused in both directions and in both languages. The
        // categories are the ones Rust reports, which the corpus proves; these
        // are the two branches that report them.
        for refusal in [
            "throw new RefusalError(BATCH_INVALID_BODY, \"bounded_parallel declares a \
             max_in_flight\");",
            "throw new RefusalError(BATCH_INVALID_BODY, `${kind} declares no max_in_flight`);",
        ] {
            assert!(
                generated.contains(refusal),
                "the concurrency coupling is not refused: {refusal}"
            );
        }
        // A nullable ceiling would be the other shape, and it is not emitted.
        assert!(
            !generated.contains("readonly max_in_flight: ConcurrencyCeiling | null;"),
            "the concurrency policy is carried as a struct with a nullable ceiling, which \
             type-checks a program that asks a sequential policy for its bound"
        );
        // The ceiling's two ends are different faults.
        assert_ne!(
            BatchApiError::Model(
                automonique_protocol::batch_runner::BatchError::ConcurrencyCeilingZero
            )
            .category(),
            BatchApiError::Model(
                automonique_protocol::batch_runner::BatchError::ConcurrencyCeilingUnreachable {
                    max_members: 0,
                    requested: 0,
                }
            )
            .category(),
            "a ceiling of zero and an unreachable one are different mistakes"
        );
    }

    /// Every category the generated code refuses with is declared, and every
    /// declared category is a spelling Rust actually produces.
    #[test]
    fn every_refusal_category_is_declared_and_is_the_rust_spelling() {
        let surface = surface();
        let declared: BTreeMap<String, String> = surface
            .categories
            .iter()
            .map(|constant| {
                let ConstantValue::Text(value) = &constant.value else {
                    panic!("{} is a refusal category, which is text", constant.name)
                };
                (constant.name.clone(), value.clone())
            })
            .collect();

        let mut referenced = vec![
            surface.invalid_body_category.clone(),
            surface.unknown_kind_category.clone(),
            surface.oversize_category.clone(),
            surface.field_invalid_category.clone(),
            surface.field_grammar_category.clone(),
        ];
        referenced.extend(referenced_categories(&surface));
        for name in &referenced {
            assert!(
                declared.contains_key(name),
                "the batch surface refuses with {name}, which it does not declare"
            );
        }

        let generated = generated_batch();
        for (name, expected) in [
            ("BATCH_INVALID_BODY", BatchApiError::InvalidBody.category()),
            ("BATCH_UNKNOWN_KIND", BatchApiError::UnknownKind.category()),
            (
                "BATCH_UNWRITTEN_ROW",
                BatchApiError::UnwrittenRow { field: "entry_id" }.category(),
            ),
            (
                "BATCH_UNWRITTEN_REVISION",
                BatchApiError::UnwrittenRevision.category(),
            ),
            (
                "BATCH_NOT_AN_ADVANCE",
                BatchApiError::NotAnAdvance {
                    progress: MemberProgress::Unsubmitted,
                    revision: 1,
                }
                .category(),
            ),
            (
                "BATCH_MEMBERS_OUT_OF_ORDER",
                BatchApiError::MembersOutOfOrder { position: 0 }.category(),
            ),
            (
                "BATCH_MEMBERSHIP_TOO_LARGE",
                BatchApiError::MembershipTooLarge {
                    max_members: 0,
                    actual_members: 0,
                }
                .category(),
            ),
            (
                "BATCH_PAGE_TOO_LARGE",
                BatchApiError::PageTooLarge {
                    max_items: 0,
                    actual_items: 0,
                }
                .category(),
            ),
            (
                "BATCH_PAGE_SIZE_OUT_OF_RANGE",
                BatchApiError::PageSizeOutOfRange {
                    max_items: 0,
                    requested: 0,
                }
                .category(),
            ),
            (
                "BATCH_TIME_BEFORE_EPOCH",
                BatchApiError::TimeBeforeEpoch {
                    field: "created_at_ms",
                }
                .category(),
            ),
            (
                "BATCH_COUNTER_OUT_OF_RANGE",
                BatchApiError::CounterOutOfRange { field: "since" }.category(),
            ),
            (
                "BATCH_INVALID_FIELD",
                BatchApiError::Field {
                    field: "batch_id",
                    error: ValueError::Empty,
                }
                .category(),
            ),
            (
                "BATCH_UNKNOWN_ENUM_VALUE",
                BatchApiError::Codec(automonique_protocol::codec::CodecError::UnknownEnumValue {
                    field: "state",
                })
                .category(),
            ),
        ] {
            assert_eq!(
                declared.get(name).map(String::as_str),
                Some(expected),
                "{name} is not the category Rust reports"
            );
            assert!(
                generated.contains(&format!("export const {name} = \"{expected}\";")),
                "the generated file does not carry {name} as {expected}"
            );
        }
        // The three the batch *model* owns keep the model's own prefix, which is
        // how a metric says the batch was wrong rather than the frame.
        for name in [
            "BATCH_EMPTY_BATCH",
            "BATCH_CONCURRENCY_CEILING_ZERO",
            "BATCH_CONCURRENCY_CEILING_UNREACHABLE",
        ] {
            let spelling = declared
                .get(name)
                .unwrap_or_else(|| panic!("{name} is declared"));
            assert!(
                spelling.starts_with("batch_") && !spelling.starts_with("batch_control_"),
                "{name} is {spelling}, which claims this transport's prefix for the batch model's \
                 own refusal"
            );
        }
        // An unwritten row and a revision no writer produced are different
        // faults, and a caller told the wrong one cannot act on it.
        assert_ne!(
            declared.get("BATCH_UNWRITTEN_ROW"),
            declared.get("BATCH_UNWRITTEN_REVISION"),
            "a row identity of zero and a revision of zero are different faults"
        );
        assert_eq!(
            declared.get(&surface.oversize_category).map(String::as_str),
            Some("frame_size"),
            "the oversize category is the spelling the local admin transport reports for a payload \
             above its ceiling"
        );
    }

    /// The gap lists are the whole of the gap, and the refusals absent from them
    /// are absent for a stated reason.
    #[test]
    fn the_rust_only_list_is_the_whole_of_the_gap() {
        let decoded: BTreeSet<&str> = rust_only_refusals()
            .iter()
            .map(|refusal| refusal.id)
            .collect();
        assert_eq!(
            decoded,
            BTreeSet::from([
                "advance-receipt-claims-unsubmitted",
                "conflict-without-disagreement",
                "continuation-incoherent",
                "continuation-rewinds",
                "detail-duplicate-member",
                "detail-empty-membership",
                "detail-members-out-of-order",
                "member-sequence-coupling",
                "member-unsubmitted-above-first-revision",
                "page-out-of-order",
                "rollup-contradicts-members",
            ]),
            "the measured decode gap changed without the reason for it changing"
        );
        let encoded: BTreeSet<&str> = rust_only_encode_refusals()
            .iter()
            .map(|refusal| refusal.id)
            .collect();
        assert_eq!(
            encoded,
            BTreeSet::from([
                "advance-member-sequence-coupling",
                "advance-member-terminal-at-zero-sequence",
                "register-batch-duplicate-member",
            ]),
            "the measured encode gap changed without the reason for it changing"
        );

        // A page longer than the query asked for: refused by the *constructor*
        // that answers a listing, not by any decoder, because a decoded frame
        // does not carry the query it answers. Listing it as a gap would claim
        // the generated surface is missing something Rust has on the same side.
        let query = ListBatches::new(BatchCursor::START, page_size(1));
        let page = BatchListPage::new(
            vec![
                record(Row {
                    entry_id: 1,
                    batch_id: "batch/one",
                    label: None,
                    concurrency: ConcurrencyPolicy::Sequential,
                    created_at_ms: 0,
                    revision: 1,
                }),
                record(Row {
                    entry_id: 2,
                    batch_id: "batch/two",
                    label: None,
                    concurrency: ConcurrencyPolicy::Sequential,
                    created_at_ms: 0,
                    revision: 1,
                }),
            ],
            BatchContinuation::Complete,
        )
        .expect("a well-formed page");
        let refused = BatchResponse::listing(request_id("req-list-1"), query, page.clone())
            .expect_err("a page longer than the query asked for is refused");
        assert_eq!(
            refused.category(),
            "batch_control_page_above_requested_size"
        );
        // And the same bytes decode, on both sides: the encoded form of that
        // very page carries nothing a decoder could judge it by.
        let served = BatchResponse::BatchList {
            request_id: request_id("req-list-1"),
            page,
        };
        let canonical = served
            .to_message()
            .expect("the page encodes")
            .to_canonical_bytes();
        assert!(
            BatchResponse::from_canonical_bytes(&canonical).is_ok(),
            "the Rust decoder judges a page against a query it cannot see"
        );
    }

    /// The SDK has no transport, and the generated file says so.
    #[test]
    fn the_generated_surface_says_the_framing_is_excluded() {
        let generated = generated_batch();
        for statement in [
            "The length-delimited framing this protocol travels under is not applied",
            "This package has no transport.",
            "The payload is the framed transport's payload, without its length prefix.",
        ] {
            assert!(
                generated.contains(statement),
                "the generated batch surface does not state where framing lives: {statement}"
            );
        }
        // And it says what the surface does not do, which is most of what a
        // batch runner would be expected to do.
        for honesty in [
            "It submits nothing, schedules nothing and runs nothing",
            "a member's progress is a writer's claim rather than a reading of a run",
        ] {
            assert!(
                generated.contains(honesty),
                "the generated batch surface overstates what it does: {honesty}"
            );
        }
    }

    /// The package typecheck actually reads the new files.
    #[test]
    fn the_typecheck_reads_the_batch_surface_and_its_runner() {
        let output = Command::new("npx")
            .arg("--offline")
            .arg("tsc")
            .arg("-p")
            .arg("./tsconfig.json")
            .arg("--listFiles")
            .current_dir(package_root())
            .output();
        let Ok(output) = output else {
            record_js_gap("tsc is unavailable; the batch surface is untypechecked");
            return;
        };
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success(),
            "the protocol package does not typecheck with the batch surface:\n{combined}"
        );
        for expected in [
            "generated/batch.ts",
            "generated/runtime.ts",
            "conformance/batch-api.ts",
        ] {
            assert!(
                combined.lines().any(|line| line.trim().ends_with(expected)),
                "tsc did not read {expected}; it is outside the tsconfig include globs, so \
                 nothing typechecks it.\n{combined}"
            );
        }
    }

    /// The heart of the lane: the generated TypeScript encodes the same bytes
    /// Rust does, decodes what Rust answers, refuses what Rust refuses, and
    /// accepts exactly the cross-field payloads it is documented not to judge.
    #[test]
    fn the_generated_typescript_agrees_with_rust_byte_for_byte() {
        let Some(runtime) = javascript_runtime() else {
            record_js_gap(
                "no JavaScript runtime; the batch surface is unmeasured across languages",
            );
            return;
        };
        let directory =
            std::env::temp_dir().join(format!("automonique-batch-api-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("scratch directory");
        let produced_path = directory.join("typescript-encodings.txt");

        let output = Command::new(runtime)
            .arg(runner_path())
            .arg(corpus_path())
            .arg(&produced_path)
            .current_dir(package_root())
            .output()
            .expect("the conformance runner starts");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.status.success(),
            "the generated batch surface disagrees with the Rust corpus under {runtime}:\n\
             {combined}"
        );

        // The second direction: the runner reports the bytes it produced, and
        // they are compared here against what Rust encodes and then fed to the
        // shipped decoder. The maximal registration is the one that matters
        // most — both sides built its 128 members from the corpus's rule, so
        // this is where a disagreement about the rule would surface.
        let reported = std::fs::read_to_string(&produced_path)
            .expect("the runner reports the payloads it produced");
        let mut produced: BTreeMap<String, Vec<u8>> = reported
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| {
                let (id, payload) = line
                    .split_once(' ')
                    .unwrap_or_else(|| panic!("a reported line is `<id> <hex>`: {line:?}"));
                (id.to_owned(), unhex(payload))
            })
            .collect();

        for case in request_cases() {
            let expected = case
                .request
                .to_message()
                .expect("the request encodes")
                .to_canonical_bytes();
            let actual = produced
                .remove(case.id)
                .unwrap_or_else(|| panic!("the runner did not report {}", case.id));
            assert_eq!(
                actual.len(),
                expected.len(),
                "{}: {runtime} produced {} canonical bytes, Rust produced {}",
                case.id,
                actual.len(),
                expected.len()
            );
            if let Some(index) = actual
                .iter()
                .zip(expected.iter())
                .position(|(left, right)| left != right)
            {
                let window = |bytes: &[u8]| {
                    String::from_utf8_lossy(
                        &bytes[index.saturating_sub(24)..(index + 24).min(bytes.len())],
                    )
                    .into_owned()
                };
                panic!(
                    "{}: the two encodings first differ at byte {index}\n  {runtime}: {}\n  \
                     rust: {}",
                    case.id,
                    window(&actual),
                    window(&expected)
                );
            }
            assert_eq!(
                BatchRequest::from_canonical_bytes(&actual).unwrap_or_else(|error| panic!(
                    "{}: Rust refuses what {runtime} produced: {error}",
                    case.id
                )),
                case.request,
                "{}: Rust decodes what {runtime} produced as a different request",
                case.id
            );
        }
        assert!(
            produced.is_empty(),
            "the runner reported payloads the corpus has no cases for: {:?}",
            produced.keys().collect::<Vec<_>>()
        );
        println!(
            "batch control surface under {runtime}: {}",
            String::from_utf8_lossy(&output.stdout).trim()
        );
    }
}
