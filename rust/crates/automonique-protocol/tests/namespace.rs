// SPDX-License-Identifier: Elastic-2.0

//! R1-19 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `plan/contracts/R1-19.md`.
//!
//! The scan lives here rather than in the crate because
//! `automonique-protocol`'s own contract is "the crate contains values only; it
//! performs no process, filesystem, network, credential, or provider
//! operations". The gate is therefore a value judgement over a scan, and this
//! file is the scanner: ten rules, one per surface class, run against the real
//! Rust workspace. A rule that finds nothing records "scanned, none found"
//! rather than staying silent, and every rule is shown firing on a seeded tree
//! so an empty class is a measurement rather than an omission.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use automonique_protocol::compat::MigrationContract;
use automonique_protocol::namespace::{
    InventoryEntry, NamespaceGate, ScannedIdentifier, SurfaceCoverage, SurfaceInventory,
};
use automonique_protocol::namespace::{SurfaceClass, SurfaceCoverageReport};

fn contract() -> MigrationContract {
    MigrationContract::new("plan/contracts/R1-19.md").expect("valid contract")
}

fn scanned(surface: SurfaceClass, name: &str) -> ScannedIdentifier {
    ScannedIdentifier::new(surface, name, "rust/Cargo.toml").expect("valid identifier")
}

/// One identifier on every surface class, all canonical.
fn full_canonical_sweep() -> Vec<ScannedIdentifier> {
    SurfaceClass::ALL
        .into_iter()
        .map(|surface| scanned(surface, &format!("automonique-{}", surface.as_str())))
        .collect()
}

// ---------------------------------------------------------------------------
// The inventory this repository actually ships.
// ---------------------------------------------------------------------------

/// The migration contract that authorizes the legacy forwarding executable.
///
/// `docs/product-plan/reference/migration-plan.md` is where `legacyctl` is
/// specified as a forwarding entry point; `authorized_exceptions` checks that
/// the document really names it, so the citation cannot rot into a label.
const FORWARDING_CONTRACT: &str = "docs/product-plan/reference/migration-plan.md";

/// The gate as this repository configures it: one inventoried exception.
fn shipped_gate() -> NamespaceGate {
    let mut gate = NamespaceGate::new();
    gate.inventory(
        InventoryEntry::new(
            SurfaceClass::Binary,
            "legacyctl",
            MigrationContract::new(FORWARDING_CONTRACT).expect("valid contract"),
        )
        .expect("valid entry"),
    );
    gate
}

// ---------------------------------------------------------------------------
// The scan: one rule per surface class, over a real directory tree.
// ---------------------------------------------------------------------------

/// Directories the scan never descends into. Build output is not a surface and
/// version-control metadata is not product source.
const SKIPPED_DIRECTORIES: [&str; 2] = ["target", ".git"];

/// Call sites that name a metric.
///
/// Metric names are read from emission and description sites rather than from
/// the shape of a string, because a lexical rule matches every JSON field ending
/// in `_total` and would report structure as telemetry.
const METRIC_MACROS: [&str; 6] = [
    "counter!",
    "gauge!",
    "histogram!",
    "increment_counter!",
    "describe_counter!",
    "describe_gauge!",
];

/// Call sites that can carry an explicit tracing target.
const TRACING_MACROS: [&str; 7] = [
    "trace!", "debug!", "info!", "warn!", "error!", "event!", "span!",
];

/// The Rust workspace this gate governs.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

/// The repository root, for reading the authorizing migration contract.
fn repository_root() -> PathBuf {
    workspace_root().join("..")
}

/// Every file under `root`, in a deterministic order.
fn files_under(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                let name = path.file_name().and_then(OsStr::to_str).unwrap_or_default();
                if SKIPPED_DIRECTORIES.contains(&name) {
                    continue;
                }
                pending.push(path);
            } else {
                found.push(path);
            }
        }
    }
    // A first normalisation of readdir order. `distinct` normalises again per
    // class, which is the one `the_scan_does_not_depend_on_the_order_the_tree_is_walked`
    // actually pins; this one only keeps the intermediate list readable.
    found.sort();
    found
}

/// A location relative to the scanned root, so a report never carries a machine
/// path and two trees with the same shape compare equal.
fn location(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn file_stem(path: &Path) -> String {
    path.file_stem()
        .and_then(OsStr::to_str)
        .expect("utf-8 file name")
        .to_owned()
}

/// The slice of Cargo manifest syntax the gate needs.
#[derive(Default)]
struct Manifest {
    package: Option<String>,
    features: Vec<String>,
    binaries: Vec<String>,
    release_artifacts: Vec<String>,
}

fn unquote(value: &str) -> Option<String> {
    let trimmed = value.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .map(str::to_owned)
}

/// Every quoted item of a TOML array, in declaration order.
fn quoted_items(value: &str) -> Vec<String> {
    value
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

fn parse_manifest(text: &str) -> Manifest {
    let mut manifest = Manifest::default();
    let mut section = String::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(header) = line
            .strip_prefix("[[")
            .and_then(|rest| rest.strip_suffix("]]"))
            .or_else(|| {
                line.strip_prefix('[')
                    .and_then(|rest| rest.strip_suffix(']'))
            })
        {
            section = header.trim().to_owned();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().trim_matches('"');
        match section.as_str() {
            "package" if key == "name" => manifest.package = unquote(value),
            "features" => manifest.features.push(key.to_owned()),
            "bin" if key == "name" => manifest.binaries.extend(unquote(value)),
            "package.metadata.release" if key == "artifacts" => {
                manifest.release_artifacts = quoted_items(value);
            }
            _ => {}
        }
    }
    manifest
}

/// One Cargo package found in the tree.
struct Package {
    name: String,
    directory: PathBuf,
    manifest: Manifest,
    manifest_location: String,
}

impl Package {
    /// The linkable crate name Cargo derives from the package name.
    fn crate_name(&self) -> String {
        self.name.replace('-', "_")
    }
}

fn packages(root: &Path, files: &[PathBuf]) -> Vec<Package> {
    let mut found: Vec<Package> = files
        .iter()
        .filter(|path| path.file_name() == Some(OsStr::new("Cargo.toml")))
        .filter_map(|path| {
            let text = std::fs::read_to_string(path).expect("readable manifest");
            let manifest = parse_manifest(&text);
            let name = manifest.package.clone()?;
            Some(Package {
                name,
                directory: path
                    .parent()
                    .expect("manifest has a directory")
                    .to_path_buf(),
                manifest,
                manifest_location: location(root, path),
            })
        })
        .collect();
    found.sort_by(|left, right| left.directory.cmp(&right.directory));
    found
}

/// The package owning `path`, by longest directory prefix.
fn owning_package<'a>(packages: &'a [Package], path: &Path) -> Option<&'a Package> {
    packages
        .iter()
        .filter(|package| path.starts_with(&package.directory))
        .max_by_key(|package| package.directory.as_os_str().len())
}

/// The crate-qualified module path of a source file, or `None` if the file is a
/// crate root or a binary.
fn module_path(package: &Package, file: &Path) -> Option<String> {
    let relative = file.strip_prefix(package.directory.join("src")).ok()?;
    let parts: Vec<String> = relative
        .iter()
        .map(|part| part.to_string_lossy().into_owned())
        .collect();
    if parts.iter().any(|part| part == "bin") {
        return None;
    }
    let last = parts.last()?.strip_suffix(".rs")?.to_owned();
    if parts.len() == 1 && (last == "lib" || last == "main") {
        return None;
    }
    let mut segments: Vec<String> = parts[..parts.len() - 1].to_vec();
    if last != "mod" {
        segments.push(last);
    }
    if segments.is_empty() {
        return None;
    }
    Some(format!("{}::{}", package.crate_name(), segments.join("::")))
}

/// Versioned schema and protocol names in a text.
///
/// The shape this tree uses is a dotted lowercase name with a `/vN` revision,
/// written as a whole string literal: `automonique.doctor/v1`. Anchoring on the
/// opening quote is what keeps URL paths and file paths out.
///
/// This is *versioned* names only. The product also carries unversioned dotted
/// protocol, capability and operation identities, and this rule does not reach
/// them. That is a partial coverage inside a scanned class, and it is recorded
/// by `surface_coverage::unversioned_protocol_names_are_a_recorded_gap_not_a_silent_one`
/// rather than left implied.
fn schema_names(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    for (start, _) in text.match_indices("/v") {
        let mut end = start + 2;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if end == start + 2 {
            continue;
        }
        if end < bytes.len() && is_name_byte(bytes[end]) {
            continue;
        }
        let mut begin = start;
        while begin > 0 && is_name_byte(bytes[begin - 1]) {
            begin -= 1;
        }
        if begin == 0 || bytes[begin - 1] != b'"' {
            continue;
        }
        if !text[begin..start].contains('.') {
            continue;
        }
        found.push(text[begin..end].to_owned());
    }
    found
}

const fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

/// Whether `value` has the shape of a protocol, capability or operation identity.
///
/// `src/codec.rs` defines `ProtocolName` as a "Dotted lowercase protocol name,
/// such as `automonique.runner`": ASCII lowercase and digits and dots, no
/// leading digit, no trailing dot, no doubled dot. A dot is required here on top
/// of that, because the single-word case is indistinguishable from every other
/// lowercase string literal in the tree.
fn is_protocol_name(value: &str) -> bool {
    value.contains('.')
        && !value.ends_with('.')
        && !value.contains("..")
        && value.starts_with(|first: char| first.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.')
}

/// Whether `line` opens a `const` item.
///
/// A screaming-case name followed by its type annotation, which is what
/// separates `const RESERVED_CAPABILITIES: [&str; 5] = [` from `const fn code(`
/// — a `const fn` is a function, and treating one as a declaration would drag
/// its whole body's literals in.
fn opens_a_const_item(line: &str) -> bool {
    let rest = line.strip_prefix("pub").map_or(line, |after| {
        after
            .strip_prefix("(crate)")
            .or_else(|| after.strip_prefix("(super)"))
            .unwrap_or(after)
            .trim_start()
    });
    let Some(declaration) = rest.strip_prefix("const ") else {
        return false;
    };
    let Some((name, _)) = declaration.split_once(':') else {
        return false;
    };
    let name = name.trim();
    !name.is_empty()
        && name
            .chars()
            .all(|letter| letter.is_ascii_uppercase() || letter.is_ascii_digit() || letter == '_')
}

/// Every string literal that is part of a `const` item.
///
/// This is where the tree spells a protocol, capability or operation identity:
/// `RESERVED_CAPABILITIES` in `src/tools.rs`, `OPERATION` in
/// `src/interaction.rs`, `CHECK_CODE` in `automonique-cli`. Reading the
/// declaration rather than every literal is what keeps file names, git config
/// keys and JSON field paths out — `state.sqlite3`, `user.email` and
/// `unit.state` all share the unversioned dotted shape and none is a protocol.
fn const_string_literals(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut inside = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with("//") {
            continue;
        }
        if !inside && opens_a_const_item(line) {
            inside = true;
        }
        if inside {
            found.extend(quoted_items(line));
            if line.ends_with(';') {
                inside = false;
            }
        }
    }
    found
}

/// Every protocol-style identity declared as a constant in the shipped tree.
///
/// Not part of [`scan`]: see
/// `surface_coverage::unversioned_protocol_names_are_a_recorded_gap_not_a_silent_one`
/// for what the class contains and why the gate records it rather than scanning it.
fn protocol_name_declarations(root: &Path) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for file in files_under(root) {
        let here = location(root, &file);
        if file.extension().and_then(OsStr::to_str) != Some("rs") || !is_shipped(&here) {
            continue;
        }
        let text = std::fs::read_to_string(&file).expect("readable source");
        for literal in const_string_literals(&text) {
            if is_protocol_name(&literal) {
                found.push((literal, here.clone()));
            }
        }
    }
    distinct(found)
}

/// The first string-literal argument of any call to one of `macros`.
fn literal_arguments(text: &str, macros: &[&str], after_target: bool) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    for name in macros {
        for (start, _) in text.match_indices(name) {
            let mut cursor = start + name.len();
            if !expect(bytes, &mut cursor, b'(') {
                continue;
            }
            if after_target {
                if !text[cursor..].trim_start().starts_with("target") {
                    continue;
                }
                cursor += text[cursor..].len() - text[cursor..].trim_start().len() + "target".len();
                if !expect(bytes, &mut cursor, b':') {
                    continue;
                }
            }
            if !expect(bytes, &mut cursor, b'"') {
                continue;
            }
            let Some(close) = text[cursor..].find('"') else {
                continue;
            };
            found.push(text[cursor..cursor + close].to_owned());
        }
    }
    found
}

/// Skip whitespace, then consume `wanted`; report whether it was there.
fn expect(bytes: &[u8], cursor: &mut usize, wanted: u8) -> bool {
    while *cursor < bytes.len() && bytes[*cursor].is_ascii_whitespace() {
        *cursor += 1;
    }
    if *cursor < bytes.len() && bytes[*cursor] == wanted {
        *cursor += 1;
        true
    } else {
        false
    }
}

/// Collapse repeats of the same identifier, keeping its first location.
fn distinct(mut found: Vec<(String, String)>) -> Vec<(String, String)> {
    found.sort();
    found.dedup_by(|left, right| left.0 == right.0);
    found
}

/// Whether a file is part of what a package ships.
///
/// The declared surfaces live in three places: the package manifest, the crate's
/// `src/` tree and its checked-in fixture corpora. Test, bench and example trees
/// build sample identifiers as data — `tests/tools.rs` declares a hypothetical
/// tool whose input schema is `fs.write.input/v1` — and a name that exists only
/// inside a test is not a surface the product exposes. What that scope leaves
/// out is measured by `surface_coverage::the_scan_scope_leaves_out_only_test_data`
/// rather than left implied.
fn is_shipped(here: &str) -> bool {
    let segments: Vec<&str> = here.split('/').collect();
    segments.last() == Some(&"Cargo.toml")
        || segments.contains(&"fixtures")
        || segments.contains(&"src")
}

/// Scan a Rust workspace for every declared surface class.
///
/// Every class is recorded, including the ones with no members here: recording
/// an empty result is what turns "there are no metrics" from silence into a
/// measurement.
fn scan(root: &Path) -> SurfaceInventory {
    scan_scoped(root, false)
}

/// The same scan, widened to read test, bench and example trees as well.
fn scan_scoped(root: &Path, include_unshipped: bool) -> SurfaceInventory {
    scan_with(root, include_unshipped, false)
}

/// The same scan with the tree walked in the opposite order.
///
/// Filesystem iteration order is not guaranteed and cannot be varied on demand,
/// so the order is varied here instead: a scan that reads the same tree back to
/// front must produce the same inventory, or the report depends on something
/// nobody controls.
fn scan_reversed(root: &Path) -> SurfaceInventory {
    scan_with(root, false, true)
}

fn scan_with(root: &Path, include_unshipped: bool, reverse_walk: bool) -> SurfaceInventory {
    let mut files = files_under(root);
    if reverse_walk {
        files.reverse();
    }
    let packages = packages(root, &files);
    let mut inventory = SurfaceInventory::new();

    let mut package_names = Vec::new();
    let mut crate_names = Vec::new();
    let mut features = Vec::new();
    let mut binaries = Vec::new();
    let mut release_artifacts = Vec::new();
    for package in &packages {
        package_names.push((package.name.clone(), package.manifest_location.clone()));
        let library = package.directory.join("src/lib.rs");
        if library.is_file() {
            crate_names.push((package.crate_name(), location(root, &library)));
        }
        let main = package.directory.join("src/main.rs");
        if main.is_file() {
            binaries.push((package.name.clone(), location(root, &main)));
        }
        for feature in &package.manifest.features {
            features.push((feature.clone(), package.manifest_location.clone()));
        }
        for binary in &package.manifest.binaries {
            binaries.push((binary.clone(), package.manifest_location.clone()));
        }
        for artifact in &package.manifest.release_artifacts {
            release_artifacts.push((artifact.clone(), package.manifest_location.clone()));
        }
    }

    let mut modules = Vec::new();
    let mut fixtures = Vec::new();
    let mut schemas = Vec::new();
    let mut metrics = Vec::new();
    let mut tracing_targets = Vec::new();
    for file in &files {
        let extension = file.extension().and_then(OsStr::to_str).unwrap_or_default();
        let here = location(root, file);
        let owner = owning_package(&packages, file);

        if let Some(package) = owner
            && extension == "rs"
        {
            if package.directory.join("src/bin") == file.parent().unwrap_or(file) {
                binaries.push((file_stem(file), here.clone()));
            }
            if let Some(path) = module_path(package, file) {
                modules.push((path, here.clone()));
            }
        }

        if file
            .parent()
            .and_then(Path::file_name)
            .and_then(OsStr::to_str)
            == Some("fixtures")
        {
            // A fixture inside a crate has no global spelling, exactly as a
            // module does not; both are recorded crate-qualified. A fixture that
            // belongs to no crate is recorded bare, because then the bare name
            // is the whole of its identity.
            let stem = file_stem(file);
            let identifier = owner.map_or_else(
                || stem.clone(),
                |package| format!("{}::{stem}", package.crate_name()),
            );
            fixtures.push((identifier, here.clone()));
        }

        if (extension == "rs" || extension == "json") && (include_unshipped || is_shipped(&here)) {
            let text = std::fs::read_to_string(file).expect("readable source");
            for name in schema_names(&text) {
                schemas.push((name, here.clone()));
            }
            if extension == "rs" {
                for name in literal_arguments(&text, &METRIC_MACROS, false) {
                    metrics.push((name, here.clone()));
                }
                for name in literal_arguments(&text, &TRACING_MACROS, true) {
                    tracing_targets.push((name, here.clone()));
                }
            }
        }
    }

    for (surface, found) in [
        (SurfaceClass::Package, package_names),
        (SurfaceClass::Crate, crate_names),
        (SurfaceClass::Module, modules),
        (SurfaceClass::Feature, features),
        (SurfaceClass::Binary, binaries),
        (SurfaceClass::Schema, schemas),
        (SurfaceClass::Metric, metrics),
        (SurfaceClass::TracingTarget, tracing_targets),
        (SurfaceClass::Fixture, fixtures),
        (SurfaceClass::ReleaseArtifact, release_artifacts),
    ] {
        inventory
            .record(surface, &distinct(found))
            .expect("valid identifiers");
    }
    inventory
}

// ---------------------------------------------------------------------------
// Seeded trees, used to prove each rule can fire and that nothing disables it.
// ---------------------------------------------------------------------------

fn scratch(name: &str) -> PathBuf {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("scratch directory");
    directory
}

fn write(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("parent directory");
    std::fs::write(path, contents).expect("writable scratch file");
}

/// The identifiers a seeded violating tree contains, one per surface class.
struct Seeded {
    package: &'static str,
    module: String,
    feature: &'static str,
    declared_binary: &'static str,
    file_binary: &'static str,
    schema: String,
    metric: &'static str,
    tracing_target: &'static str,
    fixture: String,
    release_artifact: &'static str,
}

fn seeded() -> Seeded {
    Seeded {
        package: "legacy-runner",
        module: "legacy_runner::telemetry".to_owned(),
        feature: "legacy-feature",
        declared_binary: "legacy-declared",
        file_binary: "legacy-bin",
        // Assembled rather than written out: the gate scans its own tests, and a
        // literal schema name here would be a real identifier in the tree.
        schema: format!("legacy.corpus{}", "/v1"),
        metric: "legacy_runs_total",
        tracing_target: "legacy_runner",
        fixture: "legacy_runner::legacy-corpus".to_owned(),
        release_artifact: "legacy-bundle.tar.gz",
    }
}

/// A workspace carrying exactly one non-namespaced identifier per surface class.
fn seeded_violating_tree(name: &str) -> PathBuf {
    let seed = seeded();
    let root = scratch(name);
    let package = root.join("crates").join(seed.package);
    write(
        &root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/legacy-runner\"]\n",
    );
    write(
        &package.join("Cargo.toml"),
        &format!(
            "[package]\nname = \"{}\"\n\n[features]\n{} = []\n\n[[bin]]\nname = \"{}\"\n\n\
             [package.metadata.release]\nartifacts = [\"{}\"]\n",
            seed.package, seed.feature, seed.declared_binary, seed.release_artifact
        ),
    );
    write(&package.join("src/lib.rs"), "pub mod telemetry;\n");
    write(
        &package.join("src/telemetry.rs"),
        &format!(
            "pub const SCHEMA: &str = \"{}\";\n\npub fn emit() {{\n    {}(\"{}\");\n    {}(target: \"{}\", \"started\");\n}}\n",
            seed.schema, METRIC_MACROS[0], seed.metric, TRACING_MACROS[2], seed.tracing_target
        ),
    );
    write(
        &package
            .join("src/bin")
            .join(format!("{}.rs", seed.file_binary)),
        "fn main() {}\n",
    );
    write(&package.join("fixtures/legacy-corpus.json"), "{}\n");
    root
}

/// A *namespaced* package that nonetheless carries legacy-named surfaces.
///
/// `seeded_violating_tree` cannot show the module and fixture rules working,
/// because its package is `legacy-runner`: the crate-qualified identifiers it
/// produces are refused by their crate prefix, not by their own spelling. Every
/// package in the real workspace is `automonique-*`, so that is the case that
/// matters. Here the package, the crate and two control surfaces are canonical
/// and only the legacy-named module and fixture may be findings.
fn legacy_surfaces_in_a_namespaced_crate(name: &str) -> PathBuf {
    let root = scratch(name);
    let package = root.join("crates/automonique-seed");
    write(
        &package.join("Cargo.toml"),
        "[package]\nname = \"automonique-seed\"\n",
    );
    write(&package.join("src/lib.rs"), "pub mod codec;\n");
    write(&package.join("src/codec.rs"), "");
    write(&package.join("src/legacy_shim.rs"), "");
    write(&package.join("src/legacy_area/mod.rs"), "");
    write(&package.join("fixtures/wire-v1.json"), "{}\n");
    write(&package.join("fixtures/legacy-corpus.json"), "{}\n");
    root
}

// ---------------------------------------------------------------------------

mod surface_coverage {
    use super::*;

    #[test]
    fn every_declared_surface_class_is_covered() {
        assert_eq!(SurfaceClass::ALL.len(), 10);
        let report = NamespaceGate::new().run(&full_canonical_sweep());
        assert!(report.passed());
        assert!(
            report.unscanned_surfaces().is_empty(),
            "unscanned: {:?}",
            report.unscanned_surfaces()
        );
    }

    #[test]
    fn an_unscanned_class_is_reported_as_a_gap_not_a_pass() {
        // Scanning only packages leaves nine classes unlooked-at. The gate
        // still "passes" its findings, so the gap has to be visible separately.
        let report = NamespaceGate::new().run(&[scanned(SurfaceClass::Package, "automonique")]);
        assert!(report.findings.is_empty());
        assert_eq!(
            report.unscanned_surfaces().len(),
            9,
            "the gate must not look like it covered everything"
        );
        assert!(!report.unscanned_surfaces().contains(&SurfaceClass::Package));
    }

    #[test]
    fn surface_spellings_are_distinct() {
        let mut spellings: Vec<&str> = SurfaceClass::ALL
            .iter()
            .map(|class| class.as_str())
            .collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total);
    }

    #[test]
    fn a_class_with_no_members_is_scanned_and_reported_as_none_found() {
        let mut inventory = SurfaceInventory::new();
        inventory
            .record(
                SurfaceClass::Package,
                &[("automonique".to_owned(), "Cargo.toml".to_owned())],
            )
            .expect("valid");
        inventory
            .record(SurfaceClass::Metric, &[])
            .expect("an empty scan is still a scan");

        let report = NamespaceGate::new().run_scan(&inventory);
        assert_eq!(
            report.coverage().of(SurfaceClass::Metric),
            SurfaceCoverage::Scanned { count: 0 }
        );
        assert!(
            !report.unscanned_surfaces().contains(&SurfaceClass::Metric),
            "a class that was looked at is not a gap"
        );
        assert!(report.scanned_none_found().contains(&SurfaceClass::Metric));
        assert_eq!(
            report.coverage().of(SurfaceClass::Metric).to_string(),
            "scanned, none found"
        );
    }

    #[test]
    fn an_unrecorded_class_is_not_scanned_and_says_so() {
        // The distinction the whole row turns on: both classes hold zero
        // identifiers, and only one of them was looked at.
        let mut inventory = SurfaceInventory::new();
        inventory.record(SurfaceClass::Metric, &[]).expect("valid");

        let report = NamespaceGate::new().run_scan(&inventory);
        assert_eq!(
            report.coverage().of(SurfaceClass::Metric),
            SurfaceCoverage::Scanned { count: 0 }
        );
        assert_eq!(
            report.coverage().of(SurfaceClass::Fixture),
            SurfaceCoverage::NotScanned
        );
        assert_eq!(report.coverage().of(SurfaceClass::Fixture).count(), 0);
        assert_eq!(report.unscanned_surfaces().len(), 9);
        assert_eq!(
            report.complete_coverage().expect_err("nine gaps").len(),
            9,
            "a partial scan cannot be read as a clean one"
        );
    }

    #[test]
    fn a_coverage_report_always_answers_for_every_class() {
        // Totality by construction: the record is an array indexed by class, so
        // there is no way to build one that omits a class or leaves it unknown.
        let report = SurfaceCoverageReport::nothing_scanned();
        assert_eq!(report.rows().len(), SurfaceClass::COUNT);
        for (class, coverage) in report.rows() {
            assert_eq!(coverage, SurfaceCoverage::NotScanned, "{class:?}");
        }
        assert_eq!(report.not_scanned().len(), SurfaceClass::COUNT);
        assert!(!report.is_total());
    }

    #[test]
    fn the_real_workspace_is_scanned_for_every_surface_class() {
        let inventory = scan(&workspace_root());
        let report = shipped_gate().run_scan(&inventory);

        report
            .complete_coverage()
            .expect("every surface class is scanned against the real tree");
        assert!(report.coverage().is_total());

        // The contract asks for scanned-versus-total per class rather than one
        // pass/fail, so the table is printed as well as asserted on.
        for (class, coverage) in report.coverage().rows() {
            println!("{}: {coverage}", class.as_str());
        }

        // Lower bounds, not exact counts: a sibling adding a module must not
        // fail this row, but a scan that stopped looking must.
        for (class, least) in [
            (SurfaceClass::Package, 5),
            (SurfaceClass::Crate, 4),
            (SurfaceClass::Module, 40),
            (SurfaceClass::Binary, 4),
            (SurfaceClass::Schema, 20),
            (SurfaceClass::Fixture, 1),
        ] {
            assert!(
                report.coverage().of(class).count() >= least,
                "{class:?} scanned {} identifiers, expected at least {least}",
                report.coverage().of(class).count()
            );
        }

        // The classes this tree has no members of are measured, not assumed.
        for class in report.scanned_none_found() {
            assert!(report.coverage().of(class).was_scanned(), "{class:?}");
            assert_eq!(report.coverage().of(class).count(), 0);
        }
    }

    #[test]
    fn the_scan_scope_leaves_out_only_test_data() {
        // The scope is "what a package ships". Widening it to test, bench and
        // example trees must add nothing but identifiers that live in one, so
        // the boundary is measured rather than trusted.
        let narrow = NamespaceGate::new().run_scan(&scan(&workspace_root()));
        let wide = NamespaceGate::new().run_scan(&scan_scoped(&workspace_root(), true));

        let extra: Vec<_> = wide
            .findings
            .iter()
            .filter(|finding| !narrow.findings.contains(finding))
            .collect();
        for finding in &extra {
            assert!(
                finding.location.contains("/tests/")
                    || finding.location.contains("/benches/")
                    || finding.location.contains("/examples/"),
                "{} is outside the shipped scope but not in a test tree: {}",
                finding.identifier,
                finding.location
            );
            assert_eq!(
                finding.surface,
                SurfaceClass::Schema,
                "{} is a non-schema identifier the shipped scope missed",
                finding.identifier
            );
        }
        assert!(
            narrow
                .findings
                .iter()
                .all(|finding| wide.findings.contains(finding)),
            "widening the scope lost a finding"
        );

        // The boundary is where it is claimed to be, shown on a seeded tree so
        // the check does not depend on which literals the real tests happen to
        // hold: a schema declared in `src/` is in scope, the same schema
        // declared under `tests/` is not, and the wide scan sees both.
        let root = scratch("scan-scope");
        let package = root.join("crates/automonique-scope");
        let shipped = format!("legacy.shipped{}", "/v1");
        let unshipped = format!("legacy.unshipped{}", "/v1");
        write(
            &package.join("Cargo.toml"),
            "[package]\nname = \"automonique-scope\"\n",
        );
        write(&package.join("src/lib.rs"), "");
        write(
            &package.join("src/schemas.rs"),
            &format!("pub const S: &str = \"{shipped}\";\n"),
        );
        write(
            &package.join("tests/sample.rs"),
            &format!("const S: &str = \"{unshipped}\";\n"),
        );

        let inside = NamespaceGate::new().run_scan(&scan(&root));
        let outside = NamespaceGate::new().run_scan(&scan_scoped(&root, true));
        let names = |report: &automonique_protocol::namespace::GateReport| -> Vec<String> {
            report
                .findings
                .iter()
                .map(|finding| finding.identifier.clone())
                .collect()
        };
        assert!(names(&inside).contains(&shipped), "{:?}", inside.findings);
        assert!(
            !names(&inside).contains(&unshipped),
            "{:?}",
            inside.findings
        );
        assert!(names(&outside).contains(&shipped));
        assert!(names(&outside).contains(&unshipped));
    }

    #[test]
    fn unversioned_protocol_names_are_a_recorded_gap_not_a_silent_one() {
        // The contract's Schema row says "schema and protocol names". The rule
        // in this file reads *versioned* names, a dotted name carrying a `/vN`
        // revision, because that is the only shape a bare literal can be
        // recognised by without reporting the rest of the tree as protocol:
        // `state.sqlite3`, `user.email`, `filter.sh` and `unit.state` all share
        // the unversioned dotted shape and none of them is a protocol name.
        // This product's protocol names are unversioned — `src/codec.rs`
        // defines `ProtocolName` as a "Dotted lowercase protocol name, such as
        // `automonique.runner`" and its validator rejects `/` — so they are
        // outside what the schema rule reaches. The class is therefore
        // partially covered, and the contract's rule for that is to report it.
        // What follows is the report: the population enumerated, measured
        // against the real tree.
        let declared = protocol_name_declarations(&workspace_root());
        let names: Vec<&str> = declared.iter().map(|(name, _)| name.as_str()).collect();

        // The enumeration is not vacuous: the shipped reserved capabilities,
        // five protocol identities in `src/tools.rs`, are all in it.
        for capability in [
            "automonique.workflow.execute",
            "automonique.delegation.spawn",
            "automonique.mcp.raw",
            "automonique.approval.decide",
            "automonique.privilege.broker",
        ] {
            assert!(
                names.contains(&capability),
                "{capability} was not found: {names:?}"
            );
        }

        // And it really is a gap: not one of them is among the identifiers the
        // schema rule records, so none of this class is covered twice.
        let inventory = scan(&workspace_root());
        let scanned_schemas: Vec<&str> = inventory
            .identifiers()
            .iter()
            .filter(|identifier| identifier.surface() == SurfaceClass::Schema)
            .map(ScannedIdentifier::name)
            .collect();
        for name in &names {
            assert!(
                !scanned_schemas.contains(name),
                "{name} is covered by the schema rule after all; this record is stale"
            );
        }

        // What scanning the class would produce, measured rather than asserted
        // away: four shipped identities outside the namespace. Renaming a
        // durable identifier needs a migration contract this item does not
        // have, and none of the four is inventoried, so the gate records the
        // class instead of scanning it — and this is the record. An
        // un-namespaced protocol name added to shipped source fails here until
        // it is entered, which makes the gap a decision rather than a drift.
        let mut population = SurfaceInventory::new();
        population
            .record(SurfaceClass::Schema, &declared)
            .expect("valid identifiers");
        let outside: Vec<String> = NamespaceGate::new()
            .run_scan(&population)
            .findings
            .into_iter()
            .map(|finding| finding.identifier)
            .collect();
        assert_eq!(
            outside,
            [
                "checkpoint.create",
                "checkpoint.list",
                "checkpoint.restore",
                "supervisor.adapter",
            ],
            "the recorded gap changed: {declared:?}"
        );
    }

    #[test]
    fn every_surface_rule_can_find_a_violation() {
        // "Scanned, none found" is only worth anything if the rule could have
        // found something. Each class is seeded with exactly one offender.
        let root = seeded_violating_tree("surface-rules-fire");
        let inventory = scan(&root);
        let report = NamespaceGate::new().run_scan(&inventory);

        report.complete_coverage().expect("all ten classes scanned");
        for class in SurfaceClass::ALL {
            assert!(
                report.coverage().of(class).count() > 0,
                "{class:?} found nothing in a tree seeded with one"
            );
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.surface == class),
                "{class:?} produced no finding for its seeded identifier"
            );
        }

        let seed = seeded();
        let named: Vec<&str> = report
            .findings
            .iter()
            .map(|finding| finding.identifier.as_str())
            .collect();
        for expected in [
            seed.package,
            seed.module.as_str(),
            seed.feature,
            seed.declared_binary,
            seed.file_binary,
            seed.schema.as_str(),
            seed.metric,
            seed.tracing_target,
            seed.fixture.as_str(),
            seed.release_artifact,
            "legacy_runner",
        ] {
            assert!(named.contains(&expected), "{expected} was not reported");
        }
        assert!(!report.passed());
    }
}

mod namespace_enforcement {
    use super::*;

    #[test]
    fn the_canonical_prefixes_and_the_bare_name_are_accepted() {
        for name in ["automonique", "automonique-lab", "automonique_protocol"] {
            let report = NamespaceGate::new().run(&[scanned(SurfaceClass::Crate, name)]);
            assert!(report.findings.is_empty(), "{name} was refused");
        }
    }

    #[test]
    fn an_identifier_outside_the_namespace_fails_naming_everything() {
        let report =
            NamespaceGate::new().run(&[scanned(SurfaceClass::Metric, "legacy_runs_total")]);
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.identifier, "legacy_runs_total");
        assert_eq!(finding.location, "rust/Cargo.toml");
        assert_eq!(finding.surface, SurfaceClass::Metric);
        assert!(!report.passed());
    }

    #[test]
    fn a_near_miss_prefix_is_still_outside_the_namespace() {
        for name in [
            "automoniqu-lab",
            "auto_monique",
            "Automonique-lab",
            "xautomonique-lab",
        ] {
            let report = NamespaceGate::new().run(&[scanned(SurfaceClass::Crate, name)]);
            assert_eq!(report.findings.len(), 1, "{name} was wrongly accepted");
        }
    }

    #[test]
    fn the_dotted_spelling_is_canonical_only_where_it_is_the_convention() {
        // Schema and protocol names in this tree are dotted, so the dotted
        // spelling carries the namespace there. Nowhere else: a package called
        // `automonique.thing` is still a finding.
        let schema =
            NamespaceGate::new().run(&[scanned(SurfaceClass::Schema, "automonique.doctor/v1")]);
        assert!(schema.findings.is_empty(), "{:?}", schema.findings);

        for class in SurfaceClass::ALL {
            // Written out rather than read back from the type under test: an
            // assertion phrased as `permits_dotted_namespace()` would agree with
            // any answer that function gave.
            let dotted_is_canonical_here = class == SurfaceClass::Schema;
            assert_eq!(class.permits_dotted_namespace(), dotted_is_canonical_here);
            let report = NamespaceGate::new().run(&[scanned(class, "automonique.thing")]);
            assert_eq!(
                report.findings.is_empty(),
                dotted_is_canonical_here,
                "dotted spelling on {class:?} was judged wrongly"
            );
        }

        // The dot does not become a general escape: the root still has to match.
        // The name is assembled because the gate scans this file too, and a
        // literal here would be a real un-namespaced schema in the tree.
        let outside = format!("legacy.thing{}", "/v1");
        let foreign = NamespaceGate::new().run(&[scanned(SurfaceClass::Schema, &outside)]);
        assert_eq!(foreign.findings.len(), 1);
        assert_eq!(foreign.findings[0].identifier, outside);
    }

    #[test]
    fn a_canonical_crate_qualifier_does_not_launder_a_legacy_leaf() {
        // The module and fixture rules record crate-qualified identifiers, so
        // the prefix test is satisfied by the crate. Judged on the prefix alone
        // both classes would be unable to produce a finding anywhere in this
        // workspace, because every package here is `automonique-*`.
        for name in [
            "automonique_protocol::legacy_shim",
            "automonique_protocol::legacy_area",
            "automonique_protocol::legacy-corpus",
            "automonique_protocol::legacyctl",
            "automonique-legacy-runner",
        ] {
            let report = NamespaceGate::new().run(&[scanned(SurfaceClass::Module, name)]);
            assert_eq!(report.findings.len(), 1, "{name} was wrongly accepted");
            assert_eq!(report.findings[0].identifier, name);
        }

        // The rule reads the head of a segment, not any substring: an ordinary
        // leaf under a canonical crate is in the namespace and stays accepted,
        // and so does a word that merely ends in the legacy root.
        for name in [
            "automonique_protocol::codec",
            "automonique_protocol::wire-v1",
            "automonique_protocol::sublegacy",
        ] {
            let report = NamespaceGate::new().run(&[scanned(SurfaceClass::Module, name)]);
            assert!(report.findings.is_empty(), "{name} was wrongly refused");
        }

        // It refuses a name; it does not forbid one. The inventory is still the
        // way out, so this is a reviewable decision rather than a wall.
        let mut gate = NamespaceGate::new();
        gate.inventory(
            InventoryEntry::new(
                SurfaceClass::Module,
                "automonique_protocol::legacy_shim",
                contract(),
            )
            .expect("valid"),
        );
        assert!(
            gate.run(&[scanned(
                SurfaceClass::Module,
                "automonique_protocol::legacy_shim"
            )])
            .passed()
        );
    }

    #[test]
    fn a_legacy_module_or_fixture_inside_a_namespaced_crate_is_found_by_the_scan() {
        // The same property through the real scan rather than a constructed
        // identifier: legacy-named files dropped into a canonical crate.
        let root = legacy_surfaces_in_a_namespaced_crate("legacy-inside-namespaced-crate");
        let report = shipped_gate().run_scan(&scan(&root));

        let named: Vec<(&str, SurfaceClass)> = report
            .findings
            .iter()
            .map(|finding| (finding.identifier.as_str(), finding.surface))
            .collect();
        for expected in [
            ("automonique_seed::legacy_shim", SurfaceClass::Module),
            ("automonique_seed::legacy_area", SurfaceClass::Module),
            ("automonique_seed::legacy-corpus", SurfaceClass::Fixture),
        ] {
            assert!(
                named.contains(&expected),
                "{expected:?} was not reported: {named:?}"
            );
        }

        // Nothing here fires off the package name: the package, the crate and
        // the two ordinary surfaces are all accepted, so the module and fixture
        // findings are the module and fixture rules working.
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.surface == SurfaceClass::Package
                    || finding.surface == SurfaceClass::Crate),
            "the seeded package is canonical: {:?}",
            report.findings
        );
        for control in ["automonique_seed::codec", "automonique_seed::wire-v1"] {
            assert!(
                !named.iter().any(|(name, _)| *name == control),
                "{control} was wrongly refused: {named:?}"
            );
        }
        assert!(!report.passed());
    }

    #[test]
    fn a_violation_on_a_scanned_surface_fails_the_real_gate() {
        // The scan the workspace actually runs, plus one offender. This is the
        // shape CI sees: a finding here fails `cargo test --workspace`.
        let mut inventory = scan(&workspace_root());
        inventory
            .record(
                SurfaceClass::Metric,
                &[(
                    "legacy_runs_total".to_owned(),
                    "crates/automonique-lab/src/server.rs".to_owned(),
                )],
            )
            .expect("valid");
        let report = shipped_gate().run_scan(&inventory);
        assert!(!report.passed());
        let finding = report
            .findings
            .iter()
            .find(|finding| finding.identifier == "legacy_runs_total")
            .expect("the injected metric is named");
        assert_eq!(finding.surface, SurfaceClass::Metric);
        assert_eq!(finding.location, "crates/automonique-lab/src/server.rs");
    }
}

mod bidirectional_inventory {
    use super::*;

    #[test]
    fn an_inventoried_identifier_passes() {
        let mut gate = NamespaceGate::new();
        gate.inventory(
            InventoryEntry::new(SurfaceClass::Binary, "legacyctl", contract()).expect("valid"),
        );
        let report = gate.run(&[scanned(SurfaceClass::Binary, "legacyctl")]);
        assert!(report.passed(), "{:?}", report.findings);
    }

    #[test]
    fn an_inventory_entry_for_a_vanished_identifier_also_fails() {
        let mut gate = NamespaceGate::new();
        gate.inventory(
            InventoryEntry::new(SurfaceClass::Binary, "legacyctl", contract()).expect("valid"),
        );
        // The binary was removed; the exception outlived it.
        let report = gate.run(&[scanned(SurfaceClass::Binary, "automonique")]);
        assert!(report.findings.is_empty(), "nothing is un-namespaced");
        assert_eq!(report.orphaned_inventory, vec!["legacyctl".to_owned()]);
        assert!(
            !report.passed(),
            "an accumulating exception list must not pass"
        );
    }

    #[test]
    fn the_two_directions_are_reported_separately() {
        let mut gate = NamespaceGate::new();
        gate.inventory(
            InventoryEntry::new(SurfaceClass::Binary, "gone", contract()).expect("valid"),
        );
        let report = gate.run(&[scanned(SurfaceClass::Metric, "legacy_total")]);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.orphaned_inventory.len(), 1);
    }

    #[test]
    fn an_inventory_entry_is_scoped_to_its_surface() {
        let mut gate = NamespaceGate::new();
        gate.inventory(
            InventoryEntry::new(SurfaceClass::Binary, "legacyctl", contract()).expect("valid"),
        );
        // The same spelling on a different surface is not covered.
        let report = gate.run(&[
            scanned(SurfaceClass::Binary, "legacyctl"),
            scanned(SurfaceClass::Metric, "legacyctl"),
        ]);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].surface, SurfaceClass::Metric);
    }

    #[test]
    fn the_real_tree_needs_exactly_the_shipped_exception() {
        let inventory = scan(&workspace_root());

        // Without the inventory the forwarding executable is a violation, and
        // it is the only one: the exception list is minimal, not decorative.
        let bare = NamespaceGate::new().run_scan(&inventory);
        assert_eq!(
            bare.findings
                .iter()
                .map(|finding| (finding.identifier.as_str(), finding.surface))
                .collect::<Vec<_>>(),
            vec![("legacyctl", SurfaceClass::Binary)],
            "the real tree's un-namespaced identifiers changed"
        );

        let shipped = shipped_gate().run_scan(&inventory);
        assert!(shipped.passed(), "{:?}", shipped.findings);
        assert!(shipped.orphaned_inventory.is_empty());
    }

    #[test]
    fn a_dead_exception_against_the_real_tree_fails() {
        let inventory = scan(&workspace_root());
        let mut gate = shipped_gate();
        gate.inventory(
            InventoryEntry::new(SurfaceClass::Binary, "legacy-tui", contract()).expect("valid"),
        );
        let report = gate.run_scan(&inventory);
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert_eq!(report.orphaned_inventory, vec!["legacy-tui".to_owned()]);
        assert!(!report.passed());
    }
}

mod authorized_exceptions {
    use super::*;

    #[test]
    fn every_inventory_entry_names_its_contract() {
        let entry =
            InventoryEntry::new(SurfaceClass::Binary, "legacyctl", contract()).expect("valid");
        assert_eq!(entry.authorized_by().as_str(), "plan/contracts/R1-19.md");
        assert_eq!(entry.name(), "legacyctl");
    }

    #[test]
    fn an_entry_cannot_be_built_without_a_contract_identifier() {
        assert!(
            MigrationContract::new("").is_err(),
            "an unauthorized exception has no contract to name"
        );
    }

    #[test]
    fn the_shipped_exception_is_authorized_by_a_document_that_names_it() {
        // A contract citation that does not mention the identifier is a label,
        // not an authorization.
        let entry = InventoryEntry::new(
            SurfaceClass::Binary,
            "legacyctl",
            MigrationContract::new(FORWARDING_CONTRACT).expect("valid"),
        )
        .expect("valid");
        assert_eq!(entry.authorized_by().as_str(), FORWARDING_CONTRACT);

        let document = std::fs::read_to_string(repository_root().join(FORWARDING_CONTRACT))
            .expect("the authorizing migration contract exists");
        assert!(
            document.contains(entry.name()),
            "{FORWARDING_CONTRACT} does not name {}",
            entry.name()
        );
    }
}

mod determinism {
    use super::*;

    #[test]
    fn findings_are_ordered_independently_of_input_order() {
        let forward = vec![
            scanned(SurfaceClass::Metric, "zeta_total"),
            scanned(SurfaceClass::Metric, "alpha_total"),
            scanned(SurfaceClass::Crate, "mid_crate"),
        ];
        let mut reversed = forward.clone();
        reversed.reverse();

        let gate = NamespaceGate::new();
        let first = gate.run(&forward);
        let second = gate.run(&reversed);
        assert_eq!(first, second, "report depends on input order");

        let identifiers: Vec<&str> = first
            .findings
            .iter()
            .map(|finding| finding.identifier.as_str())
            .collect();
        let mut sorted = identifiers.clone();
        sorted.sort_unstable();
        assert_eq!(identifiers, sorted, "findings are not canonically ordered");
    }

    #[test]
    fn repeated_runs_are_identical() {
        let gate = NamespaceGate::new();
        let input = full_canonical_sweep();
        let first = gate.run(&input);
        for _ in 0..8 {
            assert_eq!(gate.run(&input), first);
        }
    }

    #[test]
    fn repeated_scans_of_the_real_tree_are_identical() {
        let gate = shipped_gate();
        let first = gate.run_scan(&scan(&workspace_root()));
        for _ in 0..4 {
            assert_eq!(gate.run_scan(&scan(&workspace_root())), first);
        }
    }

    #[test]
    fn the_scan_does_not_depend_on_the_order_the_tree_is_walked() {
        // Writing two trees in opposite orders proves nothing: on a hashed
        // directory the readdir order is the same either way, so such a test
        // passes even with every sort removed. Reversing the walk is the only
        // version of this experiment the harness controls.
        let seeded = seeded_violating_tree("determinism-walk-order");
        let gate = shipped_gate();
        for root in [seeded.as_path(), &workspace_root()] {
            assert_eq!(
                scan(root).identifiers(),
                scan_reversed(root).identifiers(),
                "the scan's own output depends on walk order"
            );
            assert_eq!(
                gate.run_scan(&scan(root)),
                gate.run_scan(&scan_reversed(root)),
                "the report depends on walk order"
            );
        }
    }
}

mod actionable_output {
    use super::*;

    #[test]
    fn every_finding_names_both_resolution_paths() {
        let report = NamespaceGate::new().run(&[scanned(SurfaceClass::Metric, "legacy_total")]);
        let finding = &report.findings[0];
        let [rename, inventory] = finding.resolutions();
        assert!(rename.contains("rename"));
        assert!(rename.contains("automonique-"));
        assert!(inventory.contains("inventory"));
        assert!(inventory.contains("migration contract"));

        let rendered = finding.to_string();
        assert!(rendered.contains("legacy_total"));
        assert!(rendered.contains("metric"));
        assert!(rendered.contains("rust/Cargo.toml"));
    }

    #[test]
    fn a_finding_from_a_real_scan_names_its_file() {
        let root = seeded_violating_tree("actionable-output");
        let report = NamespaceGate::new().run_scan(&scan(&root));
        for finding in &report.findings {
            let rendered = finding.to_string();
            assert!(rendered.contains(&finding.identifier));
            assert!(rendered.contains(finding.surface.as_str()));
            assert!(
                rendered.contains(&finding.location),
                "{rendered} does not name where it was found"
            );
            assert!(!finding.location.is_empty());
            let [rename, inventory] = finding.resolutions();
            assert!(rendered.contains(&rename));
            assert!(rendered.contains(&inventory));
        }
        let metric = report
            .findings
            .iter()
            .find(|finding| finding.surface == SurfaceClass::Metric)
            .expect("the seeded metric");
        assert_eq!(metric.location, "crates/legacy-runner/src/telemetry.rs");
    }
}

mod no_escape_hatch {
    use super::*;

    /// Files a suppression would plausibly be dropped into.
    const ALLOWLIST_FILES: [&str; 5] = [
        "namespace-allowlist.json",
        ".namespace-allowlist",
        "allowlist.json",
        ".automonique-namespace-gate.toml",
        "namespace-gate.toml",
    ];

    /// Comments a suppression would plausibly be written as.
    const SUPPRESSION_COMMENTS: [&str; 4] = [
        "// namespace-gate: allow legacy-runner",
        "// automonique-namespace-gate: ignore",
        "// gate:disable namespace",
        "// noqa: namespace",
    ];

    /// Variables a suppression would plausibly be spelled as.
    const DISABLING_VARIABLES: [&str; 6] = [
        "AUTOMONIQUE_NAMESPACE_GATE",
        "AUTOMONIQUE_GATE",
        "NAMESPACE_GATE",
        "AUTOMONIQUE_NAMESPACE_ALLOWLIST",
        "AUTOMONIQUE_SKIP_NAMESPACE_GATE",
        "CI",
    ];

    /// How the parent hands a tree to the child probe.
    ///
    /// Read by this test harness, never by the gate: `the_gate_reads_neither_the_environment_nor_the_filesystem`
    /// checks the gate's own source for any environment or file access at all.
    const PROBE_ROOT: &str = "AUTOMONIQUE_NAMESPACE_GATE_PROBE_ROOT";

    #[test]
    #[ignore = "run as a child process by an_environment_variable_cannot_disable_the_gate"]
    fn gate_probe() {
        let root = std::env::var(PROBE_ROOT).expect("probe root");
        let report = shipped_gate().run_scan(&scan(Path::new(&root)));
        println!(
            "PROBE findings={} passed={} first={}",
            report.findings.len(),
            report.passed(),
            report
                .findings
                .first()
                .map_or_else(|| "none".to_owned(), ToString::to_string)
        );
    }

    /// Run the gate in a child process with `variables` set, and return its
    /// verdict line.
    fn probe(root: &Path, variables: &[(&str, &str)]) -> String {
        let mut command = Command::new(std::env::current_exe().expect("test binary"));
        command
            .args([
                "--exact",
                "no_escape_hatch::gate_probe",
                "--ignored",
                "--nocapture",
            ])
            .env(PROBE_ROOT, root);
        for (name, value) in variables {
            command.env(name, value);
        }
        let output = command.output().expect("the probe runs");
        assert!(
            output.status.success(),
            "probe failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("utf-8 probe output")
            .lines()
            .find(|line| line.starts_with("PROBE "))
            .expect("the probe printed a verdict")
            .to_owned()
    }

    #[test]
    fn an_environment_variable_cannot_disable_the_gate() {
        let root = seeded_violating_tree("escape-hatch-environment");
        let baseline = probe(&root, &[]);
        assert!(
            baseline.contains("passed=false"),
            "the probe must start from a failing tree: {baseline}"
        );

        for name in DISABLING_VARIABLES {
            for value in ["0", "1", "off", "disable"] {
                assert_eq!(
                    probe(&root, &[(name, value)]),
                    baseline,
                    "{name}={value} changed the verdict"
                );
            }
        }
        let all: Vec<(&str, &str)> = DISABLING_VARIABLES
            .iter()
            .map(|name| (*name, "0"))
            .collect();
        assert_eq!(probe(&root, &all), baseline, "six variables at once");
    }

    #[test]
    fn a_dropped_in_allowlist_file_cannot_disable_the_gate() {
        let plain = seeded_violating_tree("escape-hatch-plain");
        let seeded = seeded_violating_tree("escape-hatch-allowlist");
        let body = "{\"allow\": [\"legacy-runner\", \"legacy-bin\", \"legacy-feature\"]}\n";
        for name in ALLOWLIST_FILES {
            write(&seeded.join(name), body);
            write(&seeded.join("crates/legacy-runner").join(name), body);
        }

        let gate = shipped_gate();
        assert_eq!(
            gate.run_scan(&scan(&seeded)),
            gate.run_scan(&scan(&plain)),
            "an allowlist file changed the verdict"
        );
    }

    #[test]
    fn a_suppression_comment_cannot_disable_the_gate() {
        let plain = seeded_violating_tree("escape-hatch-comment-free");
        let seeded = seeded_violating_tree("escape-hatch-comment");
        let telemetry = seeded.join("crates/legacy-runner/src/telemetry.rs");
        let original = std::fs::read_to_string(&telemetry).expect("seeded source");
        write(
            &telemetry,
            &format!("{}\n{original}", SUPPRESSION_COMMENTS.join("\n")),
        );
        write(
            &seeded.join("crates/legacy-runner/src/lib.rs"),
            &format!("{}\npub mod telemetry;\n", SUPPRESSION_COMMENTS.join("\n")),
        );

        let gate = shipped_gate();
        assert_eq!(
            gate.run_scan(&scan(&seeded)),
            gate.run_scan(&scan(&plain)),
            "a suppression comment changed the verdict"
        );
    }

    #[test]
    fn the_gate_reads_neither_the_environment_nor_the_filesystem() {
        // Nothing can be pointed at a gate that reads nothing. This is the
        // structural reason the three attempts above cannot succeed.
        let source = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/namespace.rs"),
        )
        .expect("the gate's source");
        for reach in [
            "std::env",
            "std::fs",
            "std::process",
            "env!",
            "option_env!",
            "include_str!",
            "include_bytes!",
        ] {
            assert!(
                !source.contains(reach),
                "the gate must not reach for {reach}"
            );
        }
    }
}

mod the_gate_can_fail {
    use super::*;

    #[test]
    fn the_real_workspace_passes_the_gate() {
        let inventory = scan(&workspace_root());
        assert!(
            inventory.identifiers().len() >= 60,
            "only {} identifiers were collected",
            inventory.identifiers().len()
        );
        let report = shipped_gate().run_scan(&inventory);
        assert!(
            report.findings.is_empty(),
            "the workspace has un-namespaced identifiers: {:?}",
            report.findings
        );
        report.complete_coverage().expect("nothing went unscanned");
    }

    #[test]
    fn a_deliberately_introduced_identifier_is_rejected() {
        // The gate is worthless if it has never failed. This injects exactly
        // what CI is meant to catch.
        let mut inventory = scan(&workspace_root());
        inventory
            .record(
                SurfaceClass::Crate,
                &[(
                    "legacy-runner".to_owned(),
                    "crates/legacy-runner".to_owned(),
                )],
            )
            .expect("valid identifier");
        let report = shipped_gate().run_scan(&inventory);
        assert!(!report.passed(), "the gate accepted a legacy crate name");
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.identifier == "legacy-runner"),
            "the injected identifier was not named"
        );
    }

    #[test]
    fn a_deliberately_introduced_file_is_rejected_by_the_scan_itself() {
        // Not an injected value this time: a real non-namespaced crate on disk,
        // found by walking the tree.
        let root = seeded_violating_tree("gate-can-fail");
        let report = shipped_gate().run_scan(&scan(&root));
        assert!(!report.passed());
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.identifier == "legacy-runner"
                    && finding.surface == SurfaceClass::Package),
            "the seeded package was not reported: {:?}",
            report.findings
        );
    }
}
