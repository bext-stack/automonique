// SPDX-License-Identifier: Elastic-2.0

//! Generate TypeScript from a Rust-owned schema description.
//!
//! The module has two halves that share one emitter.
//!
//! The first is the `R1-11` spike ([`hostile_slice`], [`emit_typescript`]),
//! kept because its verdict in `generated/VERDICT.md` and its negative
//! typecheck cases are the evidence the second half rests on. Its slice is
//! deliberately hostile rather than representative.
//!
//! The second is a maintained description of part of the shipped protocol
//! ([`generated_files`]), regenerated into `generated/` and held to a drift
//! gate in `tests/codegen.rs`.
//!
//! # What the maintained half covers
//!
//! Only a **read** surface, and only these schemas:
//!
//! - `automonique.doctor/v1` from the crate root: [`crate::ReportStatus`],
//!   [`crate::CheckStatus`], [`crate::FindingCode`], [`crate::FindingMessage`],
//!   [`crate::DoctorReason`], [`crate::DoctorCheck`], [`crate::DoctorReportV1`].
//! - The `status` read of `automonique.admin` from [`crate::admin`]:
//!   [`crate::admin::AdminInstanceId`], [`crate::admin::DaemonState`],
//!   [`crate::admin::TelegramState`], [`crate::admin::ExecutionState`],
//!   [`crate::admin::OperationalMetric`], [`crate::admin::OperationalStatus`],
//!   [`crate::admin::DaemonStatus`].
//!
//! # What it does not cover
//!
//! Everything else in the crate, including: `RunSpec` and the run surface,
//! `sandbox`, `release`, `provider`, `models`, `tools`, `interaction`,
//! `journal`, `context`, `namespace`, `connector`, `automation`, `compat`,
//! `event`, `host`, `identity`, `workspace`, and the framed [`crate::codec`]
//! envelope. Within `admin`, only the status read is described: the request
//! commands ([`crate::admin::AdminCommand`]), the synthetic intake, the
//! reconciliation and outbox evidence bodies, and the [`crate::admin::AdminResponse`]
//! refusal arms are all absent.
//!
//! Cross-field invariants are also out of scope. The generated types hold each
//! field's own shape and bounds; rules that relate two fields — a healthy
//! doctor check carrying no reason, a lease-owning Telegram state requiring a
//! poller epoch, an operational projection whose queue counts must sum to the
//! aggregate — are enforced only by the Rust constructors.
//!
//! Regenerate with the command in [`REGENERATE_COMMAND`].
//!
//! Determinism is a property of this module: every collection is emitted in
//! sorted order and nothing time-dependent, host-dependent or randomly ordered
//! reaches the output. A generator that embeds a build time cannot satisfy the
//! zero-diff regeneration rule, so there is no way to ask this one for a
//! timestamp.

use core::fmt::Write as _;

use crate::admin::{DaemonState, ExecutionState, OperationalMetric, TelegramState};
use crate::schema::EnumSensitivity;
use crate::{CheckStatus, ReportStatus};

/// A branded identifier domain in the generated surface.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BrandedId {
    /// TypeScript type name.
    pub name: String,
    /// Maximum UTF-8 byte length.
    pub max_bytes: usize,
    /// Grammar the whole value must match, in JavaScript regular expression
    /// source without delimiters. See [`BoundedString::pattern`].
    pub pattern: Option<String>,
}

/// A bounded string field.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BoundedString {
    /// TypeScript type name.
    pub name: String,
    /// Maximum UTF-8 byte length.
    pub max_bytes: usize,
    /// Grammar the whole value must match, in JavaScript regular expression
    /// source without delimiters.
    ///
    /// The emitter wraps it in a Unicode-mode literal, so it must not contain
    /// an unescaped `/`. `None` emits a length check only, which is what the
    /// spike slice uses.
    pub pattern: Option<String>,
}

/// A bounded integer field.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BoundedInteger {
    /// TypeScript type name.
    pub name: String,
    /// Inclusive minimum.
    pub min: i64,
    /// Inclusive maximum.
    pub max: i64,
}

/// One variant of a discriminated union.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UnionVariant {
    /// Discriminant value.
    pub tag: String,
    /// Payload field name and TypeScript type, or `None` for a payload-free
    /// variant.
    pub payload: Option<(String, String)>,
}

/// A discriminated union.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Union {
    /// TypeScript type name.
    pub name: String,
    /// Discriminant property name.
    pub discriminant: String,
    /// Variants, emitted in sorted order.
    pub variants: Vec<UnionVariant>,
}

/// An enumeration and how unknown values are treated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedEnum {
    /// TypeScript type name.
    pub name: String,
    /// Whether unknown values are refused or retained.
    pub sensitivity: EnumSensitivity,
    /// Declared values.
    pub values: Vec<String>,
}

/// The slice of protocol surface this spike generates.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SpikeSchema {
    /// Branded identifier domains.
    pub branded_ids: Vec<BrandedId>,
    /// Bounded strings.
    pub bounded_strings: Vec<BoundedString>,
    /// Bounded integers.
    pub bounded_integers: Vec<BoundedInteger>,
    /// Discriminated unions.
    pub unions: Vec<Union>,
    /// Enumerations.
    pub enums: Vec<GeneratedEnum>,
}

/// The deliberately hard slice this spike is judged on.
///
/// Chosen to contain the constructs codegen most often loses, not the
/// constructs it handles easily: exact const bounds, two branded domains, a
/// union with a payload-free variant, both enum sensitivities, and an
/// optional-versus-nullable distinction.
#[must_use]
pub fn hostile_slice() -> SpikeSchema {
    SpikeSchema {
        branded_ids: vec![
            BrandedId {
                name: "SessionId".to_owned(),
                max_bytes: 128,
                pattern: None,
            },
            BrandedId {
                name: "TurnId".to_owned(),
                max_bytes: 64,
                pattern: None,
            },
        ],
        bounded_strings: vec![BoundedString {
            name: "MessageKind".to_owned(),
            max_bytes: 64,
            pattern: None,
        }],
        bounded_integers: vec![BoundedInteger {
            name: "Sequence".to_owned(),
            min: 0,
            max: i64::MAX,
        }],
        unions: vec![Union {
            name: "TurnOutcome".to_owned(),
            discriminant: "kind".to_owned(),
            variants: vec![
                UnionVariant {
                    tag: "cancelled".to_owned(),
                    payload: None,
                },
                UnionVariant {
                    tag: "completed".to_owned(),
                    payload: Some(("text".to_owned(), "string".to_owned())),
                },
                UnionVariant {
                    tag: "failed".to_owned(),
                    payload: Some(("reason".to_owned(), "string".to_owned())),
                },
            ],
        }],
        enums: vec![
            GeneratedEnum {
                name: "ApprovalDecision".to_owned(),
                sensitivity: EnumSensitivity::SecuritySensitive,
                values: vec!["allow".to_owned(), "deny".to_owned()],
            },
            GeneratedEnum {
                name: "RunState".to_owned(),
                sensitivity: EnumSensitivity::ReadOnly,
                values: vec!["done".to_owned(), "running".to_owned()],
            },
        ],
    }
}

/// Emit TypeScript for a slice.
///
/// Output is a pure function of the input: collections are sorted, and no
/// clock, environment or allocation address reaches the text.
#[must_use]
pub fn emit_typescript(schema: &SpikeSchema) -> String {
    let mut out = String::new();
    out.push_str("// SPDX-License-Identifier: Apache-2.0\n\n");
    out.push_str("// GENERATED by automonique_protocol::codegen — do not edit by hand.\n");
    out.push_str("// Regenerate with: cargo test -p automonique-protocol --test codegen\n");
    out.push_str("//\n");
    out.push_str("// Rust is the wire source of truth. Hand-written SDK code may add\n");
    out.push_str("// ergonomics; it may not redefine anything in this file.\n\n");

    out.push_str("const encoder = new TextEncoder();\n");
    out.push_str("function byteLength(value: string): number {\n");
    out.push_str("  return encoder.encode(value).length;\n");
    out.push_str("}\n\n");
    out.push_str("export class ValidationError extends Error {\n");
    // Keep the output executable by runtimes that implement TypeScript by
    // erasing types only. Constructor parameter properties require a transform
    // and are rejected by Node's strip-only loader.
    out.push_str("  readonly field: string;\n");
    out.push_str("  readonly violation: string;\n");
    out.push_str("  constructor(field: string, violation: string) {\n");
    out.push_str("    super(`${field}: ${violation}`);\n");
    out.push_str("    this.name = \"ValidationError\";\n");
    out.push_str("    this.field = field;\n");
    out.push_str("    this.violation = violation;\n");
    out.push_str("  }\n");
    out.push_str("}\n");

    let mut branded = schema.branded_ids.clone();
    branded.sort();
    for id in &branded {
        emit_branded_id(&mut out, id);
    }

    let mut strings = schema.bounded_strings.clone();
    strings.sort();
    for bounded in &strings {
        emit_bounded_string(&mut out, bounded);
    }

    let mut integers = schema.bounded_integers.clone();
    integers.sort();
    for integer in &integers {
        emit_bounded_integer(&mut out, integer);
    }

    let mut unions = schema.unions.clone();
    unions.sort();
    for union in &unions {
        emit_union(&mut out, union);
    }

    let mut enums = schema.enums.clone();
    enums.sort_by(|left, right| left.name.cmp(&right.name));
    for generated in &enums {
        emit_enum(&mut out, generated);
    }

    // An event this build has never seen must survive decoding with its bounded
    // payload intact. Optional and nullable are distinct: `note` may be absent,
    // `detail` may be present-and-null.
    out.push_str(
        "\nexport interface KnownEvent {\n  \
         readonly kind: \"turn_completed\";\n  \
         readonly note?: string;\n  \
         readonly detail: string | null;\n\
         }\n\
         \n\
         export type DecodedEvent =\n  \
         | {readonly known: true; readonly event: KnownEvent}\n  \
         | {readonly known: false; readonly kind: string; readonly payload: string};\n\
         \n\
         export const MAX_UNKNOWN_EVENT_BYTES = 4096;\n\
         \n\
         export function decodeEvent(kind: string, payload: string): DecodedEvent {\n  \
         if (kind === \"turn_completed\") {\n    \
         return {known: true, event: {kind, detail: null}};\n  \
         }\n  \
         if (byteLength(payload) > MAX_UNKNOWN_EVENT_BYTES) {\n    \
         throw new ValidationError(\"event\", \"unknown_payload_too_large\");\n  \
         }\n  \
         return {known: false, kind, payload};\n\
         }\n",
    );

    out
}

// ---------------------------------------------------------------------------
// Shared emitters
//
// Both halves of this module go through these, which is what keeps a bound
// from being spelled one way in the spike and another way in the maintained
// surface.
// ---------------------------------------------------------------------------

/// Emit the checked constructor shared by branded identifiers and bounded
/// strings.
///
/// Length is measured in UTF-8 bytes because that is what the Rust bound
/// measures; `value.length` counts UTF-16 code units and would accept a
/// multibyte string the daemon refuses.
fn emit_checked_string(out: &mut String, name: &str, max_bytes: usize, pattern: Option<&str>) {
    let _ = writeln!(
        out,
        "export type {name} = string & {{readonly __brand: \"{name}\"}};"
    );
    let _ = writeln!(out, "export const {name}_MAX_BYTES = {max_bytes};");
    if let Some(pattern) = pattern {
        let _ = writeln!(out, "export const {name}_PATTERN = /{pattern}/u;");
    }
    let _ = writeln!(out, "export function {name}(value: string): {name} {{");
    let _ = writeln!(
        out,
        "  if (value.length === 0) throw new ValidationError(\"{name}\", \"empty\");"
    );
    let _ = writeln!(
        out,
        "  if (byteLength(value) > {max_bytes}) throw new ValidationError(\"{name}\", \"too_long\");"
    );
    if pattern.is_some() {
        let _ = writeln!(
            out,
            "  if (!{name}_PATTERN.test(value)) throw new ValidationError(\"{name}\", \
             \"invalid_character\");"
        );
    }
    let _ = writeln!(out, "  return value as {name};");
    out.push_str("}\n");
}

/// Emit one branded identifier domain.
fn emit_branded_id(out: &mut String, id: &BrandedId) {
    let _ = writeln!(
        out,
        "\n/** Branded identifier, at most {} UTF-8 bytes. */",
        id.max_bytes
    );
    emit_checked_string(out, &id.name, id.max_bytes, id.pattern.as_deref());
}

/// Emit one bounded string field.
fn emit_bounded_string(out: &mut String, bounded: &BoundedString) {
    let _ = writeln!(
        out,
        "\n/** Bounded string, at most {} UTF-8 bytes. */",
        bounded.max_bytes
    );
    emit_checked_string(
        out,
        &bounded.name,
        bounded.max_bytes,
        bounded.pattern.as_deref(),
    );
}

/// Emit one bounded integer field.
///
/// The carrier is `bigint`: the wire is signed 64-bit and a JavaScript
/// `number` silently loses values above 2^53.
fn emit_bounded_integer(out: &mut String, integer: &BoundedInteger) {
    let BoundedInteger { name, min, max } = integer;
    let _ = writeln!(out, "\n/** Bounded integer in [{min}, {max}]. */");
    let _ = writeln!(
        out,
        "export type {name} = bigint & {{readonly __brand: \"{name}\"}};"
    );
    let _ = writeln!(out, "export const {name}_MIN = {min}n;");
    let _ = writeln!(out, "export const {name}_MAX = {max}n;");
    let _ = writeln!(out, "export function {name}(value: bigint): {name} {{");
    let _ = writeln!(
        out,
        "  if (value < {min}n || value > {max}n) throw new ValidationError(\"{name}\", \
         \"out_of_range\");"
    );
    let _ = writeln!(out, "  return value as {name};");
    out.push_str("}\n");
}

/// Emit one discriminated union and its exhaustiveness helper.
fn emit_union(out: &mut String, union: &Union) {
    let mut variants = union.variants.clone();
    variants.sort();
    let _ = write!(out, "\nexport type {} =", union.name);
    for variant in &variants {
        let payload = variant
            .payload
            .as_ref()
            .map_or_else(String::new, |(field, ty)| {
                format!("; readonly {field}: {ty}")
            });
        let _ = write!(
            out,
            "\n  | {{readonly {discriminant}: \"{tag}\"{payload}}}",
            discriminant = union.discriminant,
            tag = variant.tag
        );
    }
    out.push_str(";\n");
    // An exhaustiveness helper: a missing variant makes `never` fail.
    let _ = write!(
        out,
        "\nexport function assertNever{name}(value: never): never {{\n  \
         throw new ValidationError(\"{name}\", `unhandled variant: ${{JSON.stringify(value)}}`);\n\
         }}\n",
        name = union.name
    );
}

/// Emit one enumeration and the decoder its sensitivity demands.
fn emit_enum(out: &mut String, generated: &GeneratedEnum) {
    let mut values = generated.values.clone();
    values.sort();
    let literals: Vec<String> = values.iter().map(|value| format!("\"{value}\"")).collect();
    let _ = write!(
        out,
        "\nexport type {name} = {union};\n\
         export const {name}_VALUES: readonly {name}[] = [{list}];\n",
        name = generated.name,
        union = literals.join(" | "),
        list = literals.join(", ")
    );
    match generated.sensitivity {
        EnumSensitivity::SecuritySensitive => {
            let _ = write!(
                out,
                "/** Security-sensitive: an undefined value is refused. */\n\
                 export function decode{name}(value: string): {name} {{\n  \
                 if (!({name}_VALUES as readonly string[]).includes(value)) {{\n    \
                 throw new ValidationError(\"{name}\", \"unknown_enum_value\");\n  \
                 }}\n  \
                 return value as {name};\n\
                 }}\n",
                name = generated.name
            );
        }
        EnumSensitivity::ReadOnly => {
            let _ = write!(
                out,
                "/** Read-only: an undefined value is retained, never given meaning. */\n\
                 export type {name}OrUnknown =\n  \
                 | {{readonly known: true; readonly value: {name}}}\n  \
                 | {{readonly known: false; readonly spelling: string}};\n\
                 export function decode{name}(value: string): {name}OrUnknown {{\n  \
                 return ({name}_VALUES as readonly string[]).includes(value)\n    \
                 ? {{known: true, value: value as {name}}}\n    \
                 : {{known: false, spelling: value}};\n\
                 }}\n",
                name = generated.name
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Maintained read surface
// ---------------------------------------------------------------------------

/// Environment variable that turns the drift gate into a regeneration.
pub const REGENERATE_ENV: &str = "AUTOMONIQUE_PROTOCOL_REGENERATE";

/// The exact command that rewrites the checked-in generated files.
///
/// It is emitted into every generated file, so a reader who finds one stale
/// does not have to guess. `tests/codegen.rs` asserts the two stay the same
/// command.
pub const REGENERATE_COMMAND: &str =
    "AUTOMONIQUE_PROTOCOL_REGENERATE=1 cargo test -p automonique-protocol --test codegen";

/// Repository-relative directory the generated files are written to.
pub const GENERATED_DIRECTORY: &str = "sdk/typescript/packages/protocol/generated";

/// Extension the generated modules are written with.
///
/// Held apart from the names below so that each name stays a bare stem. It
/// belongs to the target language rather than to any one schema, and a
/// constant spelling `"doctor.ts"` in shipped source reads as an unversioned
/// protocol name to the namespace gate in `tests/namespace.rs`, which records
/// that class rather than scanning it. A file name is not a protocol identity
/// and does not belong in that record.
const MODULE_EXTENSION: &str = ".ts";

/// Shared helpers every other generated module imports.
pub const RUNTIME_MODULE: &str = "runtime";

/// Re-exports the maintained modules as one import surface.
pub const BARREL_MODULE: &str = "index";

/// The `automonique.doctor/v1` report read surface.
pub const DOCTOR_MODULE: &str = "doctor";

/// The `automonique.admin` status read surface.
pub const ADMIN_STATUS_MODULE: &str = "admin-status";

/// The file one module is written to.
#[must_use]
pub fn module_file_name(module: &str) -> String {
    format!("{module}{MODULE_EXTENSION}")
}

/// TypeScript name of the branded counter every wire integer uses.
const WIRE_COUNTER: &str = "WireCounter";

/// Grammar for a value that must not contain a Unicode control character.
///
/// `\p{Cc}` is exactly the category `char::is_control` tests in Rust.
const NO_CONTROL_CHARACTERS: &str = "^[^\\p{Cc}]+$";

/// Whether a decoded value may be absent, and how.
///
/// Optional and nullable are different wire facts and the generated types keep
/// them different: an optional field may be missing from the object, a nullable
/// field is always present and may be `null`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Presence {
    /// Always present, never `null`.
    Required,
    /// May be absent from the object.
    Optional,
    /// Always present, possibly `null`.
    Nullable,
}

/// One field of a generated interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Field {
    /// Wire field name, kept in the wire's own spelling.
    pub name: String,
    /// TypeScript type, before any nullability suffix.
    pub type_name: String,
    /// How the field may be absent.
    pub presence: Presence,
}

/// A generated object type mirroring one wire body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Interface {
    /// TypeScript type name.
    pub name: String,
    /// One-line description emitted above the declaration.
    pub doc: String,
    /// Fields, emitted in sorted order.
    pub fields: Vec<Field>,
}

/// The value of a generated module-level constant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConstantValue {
    /// A byte or item limit, emitted as a `number`.
    Count(usize),
    /// A stable protocol string, emitted as a string literal.
    Text(String),
}

/// A generated module-level constant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Constant {
    /// TypeScript binding name.
    pub name: String,
    /// One-line description emitted above the binding.
    pub doc: String,
    /// The value.
    pub value: ConstantValue,
}

/// One generated TypeScript file.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GeneratedModule {
    /// File name within [`GENERATED_DIRECTORY`].
    pub file_name: String,
    /// One-line description emitted into the banner.
    pub doc: String,
    /// Rust path this module is derived from, emitted into the banner.
    pub source: String,
    /// Verbatim TypeScript emitted before the schema-derived declarations.
    ///
    /// This is the escape hatch for [`RUNTIME_MODULE`], whose contents are fixed
    /// prose rather than a description of a wire shape. It is empty in every
    /// other module, and a test holds it that way.
    pub preamble: String,
    /// Module-level constants.
    pub constants: Vec<Constant>,
    /// Branded identifier domains.
    pub branded_ids: Vec<BrandedId>,
    /// Bounded strings.
    pub bounded_strings: Vec<BoundedString>,
    /// Bounded integers.
    pub bounded_integers: Vec<BoundedInteger>,
    /// Enumerations.
    pub enums: Vec<GeneratedEnum>,
    /// Discriminated unions.
    pub unions: Vec<Union>,
    /// Object types.
    pub interfaces: Vec<Interface>,
}

/// A required field.
fn required(name: &str, type_name: &str) -> Field {
    Field {
        name: name.to_owned(),
        type_name: type_name.to_owned(),
        presence: Presence::Required,
    }
}

/// A field that is always present and may be `null`.
fn nullable(name: &str, type_name: &str) -> Field {
    Field {
        name: name.to_owned(),
        type_name: type_name.to_owned(),
        presence: Presence::Nullable,
    }
}

/// A required counter field.
fn counter(name: &str) -> Field {
    required(name, WIRE_COUNTER)
}

/// The declared [`ReportStatus`] spellings, pinned to the Rust wire strings.
///
/// The `match` is the point of the closure: a status added to [`ReportStatus`]
/// makes this function fail to compile, so the generated union cannot narrow
/// silently while every test still passes.
fn report_status_values() -> Vec<String> {
    [
        ReportStatus::Healthy,
        ReportStatus::Degraded,
        ReportStatus::Failed,
    ]
    .into_iter()
    .map(|status| match status {
        ReportStatus::Healthy | ReportStatus::Degraded | ReportStatus::Failed => {
            status.as_str().to_owned()
        }
    })
    .collect()
}

/// The declared [`CheckStatus`] spellings, pinned to the Rust wire strings.
fn check_status_values() -> Vec<String> {
    [
        CheckStatus::Healthy,
        CheckStatus::Finding,
        CheckStatus::Unavailable,
    ]
    .into_iter()
    .map(|status| match status {
        CheckStatus::Healthy | CheckStatus::Finding | CheckStatus::Unavailable => {
            status.as_str().to_owned()
        }
    })
    .collect()
}

/// The declared [`DaemonState`] spellings, pinned to the Rust wire strings.
fn daemon_state_values() -> Vec<String> {
    [
        DaemonState::Starting,
        DaemonState::Ready,
        DaemonState::Draining,
        DaemonState::Stopped,
        DaemonState::Failed,
    ]
    .into_iter()
    .map(|state| match state {
        DaemonState::Starting
        | DaemonState::Ready
        | DaemonState::Draining
        | DaemonState::Stopped
        | DaemonState::Failed => state.as_str().to_owned(),
    })
    .collect()
}

/// The declared [`ExecutionState`] spellings, pinned to the Rust wire strings.
fn execution_state_values() -> Vec<String> {
    [
        ExecutionState::SandboxUnavailableNoLane,
        ExecutionState::SandboxEnforceableNoLane,
    ]
    .into_iter()
    .map(|state| match state {
        ExecutionState::SandboxUnavailableNoLane | ExecutionState::SandboxEnforceableNoLane => {
            state.as_str().to_owned()
        }
    })
    .collect()
}

/// The declared [`TelegramState`] spellings, pinned to the Rust wire strings.
fn telegram_state_values() -> Vec<String> {
    [
        TelegramState::DisabledNoClient,
        TelegramState::LeaseOwnedNoClient,
    ]
    .into_iter()
    .map(|state| match state {
        TelegramState::DisabledNoClient | TelegramState::LeaseOwnedNoClient => {
            state.as_str().to_owned()
        }
    })
    .collect()
}

/// The [`OperationalMetric`] arms, pinned to the Rust discriminant spellings.
///
/// The unavailable arm carries an explicit `null`, not a zero. Substituting
/// zero for missing evidence is the mistake the Rust type exists to prevent,
/// and a generated type that widened `value` to a plain counter would hand it
/// straight back.
fn operational_metric_variants() -> Vec<UnionVariant> {
    [
        OperationalMetric::Measured(0),
        OperationalMetric::Unavailable,
    ]
    .into_iter()
    .map(|metric| {
        let payload = match metric {
            OperationalMetric::Measured(_) => WIRE_COUNTER,
            OperationalMetric::Unavailable => "null",
        };
        UnionVariant {
            tag: metric.state().to_owned(),
            payload: Some(("value".to_owned(), payload.to_owned())),
        }
    })
    .collect()
}

/// The shared runtime helpers, which are prose rather than a wire shape.
fn runtime_module() -> GeneratedModule {
    GeneratedModule {
        file_name: module_file_name(RUNTIME_MODULE),
        doc: "Helpers the generated modules share.".to_owned(),
        source: "automonique_protocol::codegen".to_owned(),
        preamble: r#"const encoder = new TextEncoder();

/** UTF-8 byte length, which is the unit every protocol bound is stated in. */
export function byteLength(value: string): number {
  return encoder.encode(value).length;
}

/** A value a generated constructor refused, and why. */
export class ValidationError extends Error {
  readonly field: string;
  readonly violation: string;
  constructor(field: string, violation: string) {
    super(`${field}: ${violation}`);
    this.name = "ValidationError";
    this.field = field;
    this.violation = violation;
  }
}

/**
 * Whether an object carries exactly the named fields and no others.
 *
 * The Rust decoders refuse a body with a missing or unexpected key rather
 * than ignoring it. The generated `_FIELDS` arrays are what let a reader
 * apply the same rule.
 */
export function hasExactFields(
  value: Readonly<Record<string, unknown>>,
  fields: readonly string[],
): boolean {
  return (
    Object.keys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field))
  );
}
"#
        .to_owned(),
        ..GeneratedModule::default()
    }
}

/// The `automonique.doctor/v1` report read surface.
fn doctor_module() -> GeneratedModule {
    GeneratedModule {
        file_name: module_file_name(DOCTOR_MODULE),
        doc: "The doctor report a client reads, and nothing it may write.".to_owned(),
        source: "automonique_protocol (crate root)".to_owned(),
        constants: vec![
            Constant {
                name: "DOCTOR_REPORT_SCHEMA_V1".to_owned(),
                doc: "Stable schema identifier for the version-one report.".to_owned(),
                value: ConstantValue::Text(crate::DOCTOR_REPORT_SCHEMA_V1.to_owned()),
            },
            Constant {
                name: "MAX_DOCTOR_CHECKS".to_owned(),
                doc: "Maximum number of checks one report may carry.".to_owned(),
                value: ConstantValue::Count(crate::MAX_DOCTOR_CHECKS),
            },
        ],
        bounded_strings: vec![
            BoundedString {
                name: "FindingCode".to_owned(),
                max_bytes: crate::MAX_FINDING_CODE_BYTES,
                pattern: Some("^[a-z][a-z0-9._-]*$".to_owned()),
            },
            BoundedString {
                name: "FindingMessage".to_owned(),
                max_bytes: crate::MAX_FINDING_MESSAGE_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
        ],
        enums: vec![
            GeneratedEnum {
                name: "CheckStatus".to_owned(),
                // Refusing an undefined severity is the conservative reading:
                // a client that retained one would have to decide what it
                // means, and the safe-looking guess is the wrong one.
                sensitivity: EnumSensitivity::SecuritySensitive,
                values: check_status_values(),
            },
            GeneratedEnum {
                name: "ReportStatus".to_owned(),
                sensitivity: EnumSensitivity::SecuritySensitive,
                values: report_status_values(),
            },
        ],
        interfaces: vec![
            Interface {
                name: "DoctorReason".to_owned(),
                doc: "Why one check is not healthy: a stable code and a bounded explanation."
                    .to_owned(),
                fields: vec![
                    required("code", "FindingCode"),
                    required("message", "FindingMessage"),
                ],
            },
            Interface {
                name: "DoctorCheck".to_owned(),
                doc: "One check outcome. Whether a reason is required follows from the status, \
                      which only the Rust constructor enforces."
                    .to_owned(),
                fields: vec![
                    required("code", "FindingCode"),
                    nullable("reason", "DoctorReason"),
                    required("status", "CheckStatus"),
                ],
            },
            Interface {
                name: "DoctorReportV1".to_owned(),
                doc: "A whole report. Checks arrive sorted by code, with no code repeated."
                    .to_owned(),
                fields: vec![
                    required("checks", "readonly DoctorCheck[]"),
                    required("schema", "typeof DOCTOR_REPORT_SCHEMA_V1"),
                    required("status", "ReportStatus"),
                ],
            },
        ],
        ..GeneratedModule::default()
    }
}

/// The `automonique.admin` status read surface.
fn admin_status_module() -> GeneratedModule {
    GeneratedModule {
        file_name: module_file_name(ADMIN_STATUS_MODULE),
        doc: "The status snapshot the local admin socket answers with.".to_owned(),
        source: "automonique_protocol::admin".to_owned(),
        constants: vec![
            Constant {
                name: "ADMIN_PROTOCOL".to_owned(),
                doc: "Stable protocol name for local daemon administration.".to_owned(),
                value: ConstantValue::Text(crate::admin::ADMIN_PROTOCOL.to_owned()),
            },
            Constant {
                name: "MAX_ADMIN_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical message bytes the local admin transport accepts."
                    .to_owned(),
                value: ConstantValue::Count(crate::admin::MAX_ADMIN_CANONICAL_BYTES),
            },
        ],
        branded_ids: vec![BrandedId {
            name: "AdminInstanceId".to_owned(),
            max_bytes: crate::admin::MAX_INSTANCE_ID_BYTES,
            pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
        }],
        bounded_integers: vec![BoundedInteger {
            // Every counter in this surface is a `u64` the wire refuses above
            // the signed ceiling, so one branded carrier covers all of them.
            name: WIRE_COUNTER.to_owned(),
            min: 0,
            max: i64::MAX,
        }],
        enums: vec![
            GeneratedEnum {
                name: "DaemonState".to_owned(),
                // `DaemonState::parse` refuses an undefined spelling with
                // `AdminError::UnknownState`; the generated decoder matches it.
                sensitivity: EnumSensitivity::SecuritySensitive,
                values: daemon_state_values(),
            },
            GeneratedEnum {
                name: "ExecutionState".to_owned(),
                sensitivity: EnumSensitivity::SecuritySensitive,
                values: execution_state_values(),
            },
            GeneratedEnum {
                name: "TelegramState".to_owned(),
                sensitivity: EnumSensitivity::SecuritySensitive,
                values: telegram_state_values(),
            },
        ],
        unions: vec![Union {
            name: "OperationalMetric".to_owned(),
            discriminant: "state".to_owned(),
            variants: operational_metric_variants(),
        }],
        interfaces: vec![
            Interface {
                name: "OperationalStatus".to_owned(),
                doc: "The low-cardinality projection observed in the same status transaction."
                    .to_owned(),
                fields: vec![
                    counter("observed_ms"),
                    counter("outbox_dead_lettered"),
                    counter("outbox_delivered"),
                    counter("outbox_in_flight_ambiguous"),
                    counter("outbox_in_flight_live"),
                    counter("outbox_oldest_ready_age_ms"),
                    counter("outbox_pending_delayed"),
                    counter("outbox_pending_ready"),
                    required("provider_available", "OperationalMetric"),
                    counter("reconciliation_pending"),
                    required("sandbox_launch_refusals", "OperationalMetric"),
                    required("telegram_offset_lag", "OperationalMetric"),
                    counter("telegram_pollers_expired"),
                    counter("telegram_pollers_live"),
                ],
            },
            Interface {
                name: "DaemonStatus".to_owned(),
                doc: "One consistent snapshot. `operational` is always present; only \
                      `telegram_poller_epoch` may be null."
                    .to_owned(),
                fields: vec![
                    required("accepting_intake", "boolean"),
                    counter("event_cursor"),
                    required("execution_state", "ExecutionState"),
                    counter("generation"),
                    counter("inbox_pending"),
                    required("instance_id", "AdminInstanceId"),
                    required("operational", "OperationalStatus"),
                    counter("outbox_pending"),
                    counter("running"),
                    required("state", "DaemonState"),
                    nullable("telegram_poller_epoch", WIRE_COUNTER),
                    required("telegram_state", "TelegramState"),
                ],
            },
        ],
        ..GeneratedModule::default()
    }
}

/// Every maintained module, in file-name order.
#[must_use]
pub fn maintained_modules() -> Vec<GeneratedModule> {
    let mut modules = vec![runtime_module(), doctor_module(), admin_status_module()];
    modules.sort_by(|left, right| left.file_name.cmp(&right.file_name));
    modules
}

/// The runtime symbols a module's declarations need, in sorted order.
///
/// Derived from what is about to be emitted rather than listed by hand, so a
/// module cannot import a helper it stopped using or miss one it started.
fn runtime_imports(module: &GeneratedModule) -> Vec<&'static str> {
    let measures_bytes = !module.branded_ids.is_empty() || !module.bounded_strings.is_empty();
    let refuses_values = measures_bytes
        || !module.bounded_integers.is_empty()
        || !module.enums.is_empty()
        || !module.unions.is_empty();
    let mut names = Vec::new();
    if refuses_values {
        names.push("ValidationError");
    }
    if measures_bytes {
        names.push("byteLength");
    }
    names.sort_unstable();
    names
}

/// Emit the header every generated file opens with.
///
/// The Apache-2.0 identifier is the licence of the SDK tree these files land
/// in, not of the Elastic-2.0 crate that writes them.
fn emit_banner(out: &mut String, source: &str, doc: &str) {
    out.push_str("// SPDX-License-Identifier: Apache-2.0\n\n");
    out.push_str("// GENERATED by automonique_protocol::codegen — do not edit by hand.\n");
    let _ = writeln!(out, "// Regenerate with: {REGENERATE_COMMAND}");
    out.push_str("//\n");
    let _ = writeln!(out, "// Source of truth: {source}");
    let _ = writeln!(out, "// {doc}");
    out.push_str("//\n");
    out.push_str("// Rust is the wire source of truth. Hand-written SDK code may add\n");
    out.push_str("// ergonomics; it may not redefine anything in this file.\n");
}

/// Emit the barrel that makes the maintained surface one import.
///
/// `spike.ts` is deliberately absent. It is evidence for a decision rather
/// than shipped surface, and its own `ValidationError` would collide with the
/// runtime module's.
fn emit_barrel(modules: &[GeneratedModule]) -> String {
    let mut out = String::new();
    emit_banner(
        &mut out,
        "automonique_protocol::codegen",
        "Every maintained module, re-exported as one import surface.",
    );
    out.push('\n');
    let mut names: Vec<&str> = modules
        .iter()
        .map(|module| module.file_name.as_str())
        .collect();
    names.sort_unstable();
    for name in names {
        let _ = writeln!(out, "export * from \"./{name}\";");
    }
    out
}

/// Emit one interface and, when the wire body has an exact field set, the
/// array that names it.
fn emit_interface(out: &mut String, interface: &Interface) {
    let mut fields = interface.fields.clone();
    fields.sort_by(|left, right| left.name.cmp(&right.name));
    let _ = writeln!(out, "\n/** {} */", interface.doc);
    let _ = writeln!(out, "export interface {} {{", interface.name);
    for field in &fields {
        let (optional, type_name) = match field.presence {
            Presence::Required => ("", field.type_name.clone()),
            Presence::Optional => ("?", field.type_name.clone()),
            Presence::Nullable => ("", format!("{} | null", field.type_name)),
        };
        let _ = writeln!(
            out,
            "  readonly {name}{optional}: {type_name};",
            name = field.name
        );
    }
    out.push_str("}\n");

    // The Rust decoders refuse a body whose key set is not exactly this one.
    // An optional field would make the array a superset of what the wire
    // carries, so a module with one gets no array rather than a misleading one.
    if fields
        .iter()
        .any(|field| field.presence == Presence::Optional)
    {
        return;
    }
    let _ = writeln!(
        out,
        "export const {}_FIELDS: readonly string[] = [",
        interface.name
    );
    for field in &fields {
        let _ = writeln!(out, "  \"{}\",", field.name);
    }
    out.push_str("];\n");
}

/// Emit one generated file.
///
/// Output is a pure function of the input: every collection is sorted and no
/// clock, environment or allocation address reaches the text.
#[must_use]
pub fn emit_module(module: &GeneratedModule) -> String {
    let mut out = String::new();
    emit_banner(&mut out, &module.source, &module.doc);

    let imports = runtime_imports(module);
    if !imports.is_empty() {
        let _ = writeln!(
            out,
            "\nimport {{{imports}}} from \"./{runtime}\";",
            imports = imports.join(", "),
            runtime = module_file_name(RUNTIME_MODULE)
        );
    }

    if !module.preamble.is_empty() {
        out.push('\n');
        out.push_str(&module.preamble);
    }

    let mut constants = module.constants.clone();
    constants.sort_by(|left, right| left.name.cmp(&right.name));
    for constant in &constants {
        let _ = writeln!(out, "\n/** {} */", constant.doc);
        match &constant.value {
            ConstantValue::Count(value) => {
                let _ = writeln!(out, "export const {} = {value};", constant.name);
            }
            ConstantValue::Text(value) => {
                let _ = writeln!(out, "export const {} = \"{value}\";", constant.name);
            }
        }
    }

    let mut branded = module.branded_ids.clone();
    branded.sort();
    for id in &branded {
        emit_branded_id(&mut out, id);
    }

    let mut strings = module.bounded_strings.clone();
    strings.sort();
    for bounded in &strings {
        emit_bounded_string(&mut out, bounded);
    }

    let mut integers = module.bounded_integers.clone();
    integers.sort();
    for integer in &integers {
        emit_bounded_integer(&mut out, integer);
    }

    let mut enums = module.enums.clone();
    enums.sort_by(|left, right| left.name.cmp(&right.name));
    for generated in &enums {
        emit_enum(&mut out, generated);
    }

    let mut unions = module.unions.clone();
    unions.sort();
    for union in &unions {
        emit_union(&mut out, union);
    }

    let mut interfaces = module.interfaces.clone();
    interfaces.sort_by(|left, right| left.name.cmp(&right.name));
    for interface in &interfaces {
        emit_interface(&mut out, interface);
    }

    out
}

/// Every generated file as `(file name, contents)`, in file-name order.
///
/// This is the whole of what [`GENERATED_DIRECTORY`] is allowed to contain
/// besides the spike's own output, and it is what the drift gate in
/// `tests/codegen.rs` compares the working tree against.
#[must_use]
pub fn generated_files() -> Vec<(String, String)> {
    let modules = maintained_modules();
    let mut files: Vec<(String, String)> = modules
        .iter()
        .map(|module| (module.file_name.clone(), emit_module(module)))
        .collect();
    files.push((module_file_name(BARREL_MODULE), emit_barrel(&modules)));
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}
