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
//! - The command surface of `automonique.admin` from [`crate::admin`]: the
//!   requests a client builds ([`crate::admin::AdminCommand::Status`],
//!   [`crate::admin::AdminCommand::SubmitRun`],
//!   [`crate::admin::AdminCommand::PauseIntake`],
//!   [`crate::admin::AdminCommand::ResumeIntake`] and
//!   [`crate::admin::AdminCommand::Shutdown`]) and the receipts it decodes
//!   ([`crate::admin::AdminResponse::RunAccepted`],
//!   [`crate::admin::AdminResponse::IntakePaused`],
//!   [`crate::admin::AdminResponse::IntakeResumed`],
//!   [`crate::admin::AdminResponse::Refused`] and
//!   [`crate::admin::AdminResponse::ShutdownAccepted`]).
//!
//! - The whole read surface of `automonique.runs` from [`crate::runs_api`]:
//!   both requests ([`crate::runs_api::RunsRequest::ListRuns`] and
//!   [`crate::runs_api::RunsRequest::RunDetail`]) and all four answers
//!   ([`crate::runs_api::RunsResponse::RunList`],
//!   [`crate::runs_api::RunsResponse::RunDetail`],
//!   [`crate::runs_api::RunsResponse::Resync`] and
//!   [`crate::runs_api::RunsResponse::Refused`]), with the bodies they nest —
//!   [`crate::runs_api::RunSummary`] and
//!   [`crate::runs_api::RunLifecycleEvent`] — and the six closed vocabularies
//!   they carry.
//!
//! # What it does not cover
//!
//! Everything else in the crate, including: `RunSpec` and the run surface,
//! `sandbox`, `release`, `provider`, `models`, `tools`, `interaction`,
//! `journal`, `context`, `namespace`, `connector`, `automation`, `compat`,
//! `event`, `host`, `identity` and `workspace`. Within `admin`, the synthetic
//! intake, the reconciliation and outbox commands, and the evidence bodies
//! their responses carry are all absent — as is the `status_result` body
//! decoder, whose *types* `admin-status.ts` carries without a decoder that
//! builds them. A generated surface that quietly ignored those kinds would be
//! indistinguishable from one that understood them, so the command surface
//! names them: a defined kind it does not decode is a distinct outcome from a
//! kind this protocol version does not define, and `tests/codegen.rs` proves
//! both lists against the Rust encoders themselves.
//!
//! There is **no transport**. These files build and read canonical payload
//! bytes; the length-delimited framing in [`crate::codec`] is deliberately
//! outside them, because a client that framed a payload the socket layer also
//! frames would be refused, and this package has no socket layer to own that
//! decision.
//!
//! Cross-field invariants are also out of scope. The generated types hold each
//! field's own shape and bounds; rules that relate two fields — a healthy
//! doctor check carrying no reason, a lease-owning Telegram state requiring a
//! poller epoch, an operational projection whose queue counts must sum to the
//! aggregate, a declared digest that names the document beside it — are
//! enforced only by the Rust constructors and by the daemon that answers.
//!
//! The Runs API brings a longer list of these, and naming it is the point: a
//! generated decoder that accepted a page the Rust decoder refuses is a real
//! gap, not a detail. These `automonique.runs` rules relate two fields, and the
//! generated surface does *not* apply them:
//!
//! - `more` agreeing with `next_cursor`
//!   ([`crate::runs_api::RunsApiError::ContinuationIncoherent`]);
//! - a continuation cursor advancing past the page ([`ContinuationRewinds`]);
//! - summaries strictly increasing by submission identity ([`PageOutOfOrder`]);
//! - lifecycle sequences strictly *increasing* ([`LifecycleOutOfOrder`] — the
//!   same variant also names a sequence of zero, which the generated surface
//!   does refuse, because that is one field's own bound);
//! - no carried sequence above `last_sequence`
//!   ([`LifecycleAboveLastSequence`]);
//! - at most one terminal event, last ([`TerminalEventNotLast`]) and only for a
//!   terminal state ([`TerminalEventContradictsState`]);
//! - the declared coverage matching what is carried ([`CoverageIncoherent`]);
//!   and
//! - a resync window that does not end before it starts ([`InvalidBody`]).
//!
//! That list is not a promise: `tests/codegen.rs` carries one payload per rule
//! in the corpus section `rust_only_refusals`, and the TypeScript runner asserts
//! each one *decodes*. So the gap is measured from both sides — a rule the Rust
//! constructors stopped enforcing fails there, and a rule the generator learns
//! fails there too, until the entry moves to `decode_refusals`. A client that
//! must be sure of these reads them from the daemon that enforced them.
//!
//! [`ContinuationRewinds`]: crate::runs_api::RunsApiError::ContinuationRewinds
//! [`PageOutOfOrder`]: crate::runs_api::RunsApiError::PageOutOfOrder
//! [`LifecycleOutOfOrder`]: crate::runs_api::RunsApiError::LifecycleOutOfOrder
//! [`LifecycleAboveLastSequence`]: crate::runs_api::RunsApiError::LifecycleAboveLastSequence
//! [`TerminalEventNotLast`]: crate::runs_api::RunsApiError::TerminalEventNotLast
//! [`TerminalEventContradictsState`]: crate::runs_api::RunsApiError::TerminalEventContradictsState
//! [`CoverageIncoherent`]: crate::runs_api::RunsApiError::CoverageIncoherent
//! [`InvalidBody`]: crate::runs_api::RunsApiError::InvalidBody
//!
//! Regenerate with the command in [`REGENERATE_COMMAND`].
//!
//! Determinism is a property of this module: every collection is emitted in
//! sorted order and nothing time-dependent, host-dependent or randomly ordered
//! reaches the output. A generator that embeds a build time cannot satisfy the
//! zero-diff regeneration rule, so there is no way to ask this one for a
//! timestamp.

use core::fmt::Write as _;

use crate::admin::{AdminError, DaemonState, ExecutionState, OperationalMetric, TelegramState};
use crate::codec::CodecError;
use crate::event::Authority;
use crate::primitives::ValueError;
use crate::runs_api::{
    LIFECYCLE_AUTHORITIES, LifecycleCoverage, RunState, RunsApiError, RunsRefusal, SpoolEventKind,
    SubmissionState,
};
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
    /// Declaration order, when the wire sorts a set of these into it.
    ///
    /// The generated `_VALUES` table is emitted sorted, because sorting is what
    /// makes the output a pure function of a set. That order is not the wire's:
    /// `RunStateFilter::only` canonicalizes into `RunState::ALL` order, which is
    /// the enum's declaration order. A surface that encodes such a set carries
    /// the second order too, or it cannot reproduce the Rust bytes.
    pub wire_order: Option<Vec<String>>,
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
                wire_order: None,
            },
            GeneratedEnum {
                name: "RunState".to_owned(),
                sensitivity: EnumSensitivity::ReadOnly,
                values: vec!["done".to_owned(), "running".to_owned()],
                wire_order: None,
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
    if let Some(order) = &generated.wire_order {
        let ordered: Vec<String> = order.iter().map(|value| format!("\"{value}\"")).collect();
        let _ = write!(
            out,
            "/**\n \
             * Declaration order, which is the order the wire carries a set of these in.\n \
             *\n \
             * `{name}_VALUES` is sorted, because a sorted table is what makes this file a\n \
             * pure function of a set. The wire is not sorted that way: the Rust\n \
             * constructor canonicalizes a filter into the order below, so a request built\n \
             * from any other order would encode different bytes.\n \
             */\n\
             export const {name}_WIRE_ORDER: readonly {name}[] = [{list}];\n",
            name = generated.name,
            list = ordered.join(", ")
        );
    }
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

/// The `automonique.admin` command surface.
pub const ADMIN_COMMAND_MODULE: &str = "admin-command";

/// The `automonique.runs` read surface.
pub const RUNS_MODULE: &str = "runs";

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

/// Names one generated module takes from another.
///
/// Type-only names are held apart from value names because the generated files
/// are executed by runtimes that implement TypeScript by erasing types: a type
/// imported as a value leaves a binding behind that does not exist at runtime.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ModuleImport {
    /// Module stem, such as [`ADMIN_STATUS_MODULE`].
    pub module: String,
    /// Value names, emitted in sorted order.
    pub values: Vec<String>,
    /// Type-only names, emitted in sorted order with the `type` modifier.
    pub types: Vec<String>,
}

/// How one request body field's value reaches the wire.
///
/// Every variant carries the refusal category the Rust peer answers for a bad
/// value of that field, rather than sharing one "invalid body" spelling. The
/// categories genuinely differ — a page size outside its range and a cursor
/// above the wire's integer ceiling are different faults with different
/// spellings — and a client told the wrong one cannot act on it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RequestValue {
    /// A checked string type generated in this module.
    ///
    /// Its constructor is re-applied when the request is built, so an untyped
    /// caller — the only kind a brand cannot reach, since brands erase at
    /// runtime — is refused rather than allowed to put an overlong value on
    /// the wire.
    Checked {
        /// Generated checked-string type.
        type_name: String,
        /// Category answered for a value the constructor refuses.
        refusal_category: String,
    },
    /// Opaque bytes carried as lowercase hexadecimal under a byte bound.
    HexBytes {
        /// Generated constant naming the bound, in raw rather than hex bytes.
        max_bytes_constant: String,
        /// Refusal category answered above the bound.
        oversize_category: String,
    },
    /// A branded bounded integer, carried as a JSON integer.
    Integer {
        /// Generated bounded-integer type.
        type_name: String,
        /// Category answered for a value outside the bound.
        refusal_category: String,
    },
    /// A branded bounded integer that is always present and may be `null`.
    ///
    /// Absent and present-and-null are different wire facts, and the Rust
    /// decoder refuses a body missing the key. The generated body type is
    /// therefore `T | null` rather than `T?`.
    NullableInteger {
        /// Generated bounded-integer type.
        type_name: String,
        /// Category answered for a value outside the bound.
        refusal_category: String,
    },
    /// A set of enum spellings canonicalized into declaration order, or `null`.
    NullableEnumSet {
        /// Generated enumeration type.
        type_name: String,
        /// Generated constant carrying the declaration order.
        order_constant: String,
        /// Category answered for a set that admits nothing.
        empty_category: String,
        /// Category answered for a set naming one value twice.
        repeat_category: String,
        /// Category answered for a spelling this build does not define.
        unknown_category: String,
    },
}

/// One field of a request body.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RequestField {
    /// Wire key, in the wire's own spelling.
    pub name: String,
    /// Field name on the generated body interface.
    ///
    /// It differs from [`Self::name`] where the wire spelling names the
    /// encoding rather than the value: a caller supplies `document`, and the
    /// wire carries `document_hex`.
    pub input_name: String,
    /// How the value reaches the wire.
    pub value: RequestValue,
}

impl RequestField {
    /// The TypeScript type a caller supplies, derived from the value kind.
    fn input_type(&self) -> String {
        match &self.value {
            RequestValue::Checked { type_name, .. } | RequestValue::Integer { type_name, .. } => {
                type_name.clone()
            }
            RequestValue::HexBytes { .. } => "Uint8Array".to_owned(),
            RequestValue::NullableInteger { type_name, .. } => format!("{type_name} | null"),
            RequestValue::NullableEnumSet { type_name, .. } => {
                format!("readonly {type_name}[] | null")
            }
        }
    }
}

/// One request a client can build.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RequestCommand {
    /// Wire message kind.
    pub kind: String,
    /// TypeScript name stem, such as `SubmitRun`.
    pub name: String,
    /// One-line description emitted above the declarations.
    pub doc: String,
    /// Body fields. An empty list is an empty object on the wire, which is
    /// what the Rust decoder requires of a command that carries no arguments.
    pub fields: Vec<RequestField>,
}

/// How one response body field is decoded.
///
/// As with [`RequestValue`], each variant that can be refused carries the
/// category the Rust decoder answers for that field: a submission identity of
/// zero is an unwritten row, an acceptance instant below the epoch is a time
/// refusal, and an undefined state spelling is an enum refusal — three
/// spellings a single "invalid body" would erase.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResponseValue {
    /// A checked string type generated in or imported into this module.
    Checked {
        /// Generated checked-string type.
        type_name: String,
        /// Category answered for a value the constructor refuses.
        refusal_category: String,
    },
    /// A bounded integer type generated in or imported into this module.
    Integer {
        /// Generated bounded-integer type.
        type_name: String,
        /// Category answered for a value outside the bound.
        refusal_category: String,
        /// Whether the Rust decoder converts to `u64` before the domain bound.
        ///
        /// Where it does, a negative value is refused as an invalid body
        /// *before* the domain is consulted, and only a non-negative value can
        /// reach the domain's own refusal. The two categories differ — a
        /// submission identity of `-1` is a malformed body, and one of `0` is
        /// an unwritten row — so a reader that applied the domain bound first
        /// would report the wrong one for every negative value.
        unsigned: bool,
    },
    /// A bounded integer that is always present and may be `null`.
    NullableInteger {
        /// Generated bounded-integer type.
        type_name: String,
        /// Category answered for a value outside the bound.
        refusal_category: String,
    },
    /// A boolean, which the wire carries as `true` or `false` and nothing else.
    Bool,
    /// A closed enumeration, refused rather than retained when undefined.
    Enum {
        /// Generated enumeration type.
        type_name: String,
        /// Category answered for a spelling this build does not define.
        unknown_category: String,
    },
    /// A nested body decoded by a [`BodyObject`] declared on the same surface.
    Object {
        /// Generated object type.
        type_name: String,
    },
    /// A bounded array of nested bodies.
    ObjectArray {
        /// Generated object type of each item.
        type_name: String,
        /// Generated constant naming the largest admissible length.
        max_items_constant: String,
        /// Category answered above that length.
        oversize_category: String,
    },
}

/// One field of a response body.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ResponseField {
    /// Wire key.
    pub name: String,
    /// How it is decoded.
    pub value: ResponseValue,
}

/// A nested wire body that is not itself a message.
///
/// A run summary is carried inside a listing page, inside a detail view, and
/// nowhere on its own. It gets its own type and its own exact-field decoder so
/// the two carriers share one reading of it rather than each spelling the body
/// out again.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BodyObject {
    /// TypeScript type name.
    pub name: String,
    /// One-line description emitted above the declarations.
    pub doc: String,
    /// Fields, emitted in sorted order.
    pub fields: Vec<ResponseField>,
}

/// One response a client can decode.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ResponseDecoder {
    /// Wire message kind.
    pub kind: String,
    /// TypeScript name of the decoded object type.
    pub name: String,
    /// One-line description emitted above the declarations.
    pub doc: String,
    /// Body fields. The correlation identifier is not among them: it lives in
    /// the envelope, and every decoded response carries it.
    pub fields: Vec<ResponseField>,
}

/// A request-building and response-decoding surface for one protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSurface {
    /// Single capitalized word naming the surface, such as `Admin`.
    ///
    /// It names the shared encoder, the response union and the constants, so
    /// the whole surface can be found from any one of them.
    pub name: String,
    /// Generated constant carrying the protocol name.
    pub protocol_constant: String,
    /// The protocol name itself, for the prose that names it.
    pub protocol: String,
    /// Major protocol version these helpers speak, and the only one they admit.
    pub version: u32,
    /// Generated constant carrying the maximum canonical message bytes.
    pub max_message_bytes_constant: String,
    /// The branded correlation-identifier type.
    pub request_id_type: String,
    /// Refusal categories, pinned to the Rust `category()` spellings.
    pub categories: Vec<Constant>,
    /// Category for a body that is not the exact shape its kind defines.
    pub invalid_body_category: String,
    /// Category for a message kind this protocol version does not define.
    pub unknown_kind_category: String,
    /// Category for a canonical payload above the transport's ceiling.
    pub oversize_category: String,
    /// Category for an envelope field that breaks the bounded-value rules.
    pub field_invalid_category: String,
    /// Category for an envelope field that breaks its own grammar.
    pub field_grammar_category: String,
    /// Nested bodies the requests and responses carry, emitted in name order.
    pub body_objects: Vec<BodyObject>,
    /// Requests, emitted in kind order.
    pub requests: Vec<RequestCommand>,
    /// Kinds this protocol version defines that no generated builder produces.
    pub request_kinds_not_generated: Vec<String>,
    /// Responses, emitted in kind order.
    pub responses: Vec<ResponseDecoder>,
    /// Kinds this protocol version defines that no generated decoder reads.
    ///
    /// These are answered with their own union arm rather than a refusal: a
    /// client that received one was not sent something undefined, and telling
    /// it otherwise would be a lie it might act on.
    pub response_kinds_not_decoded: Vec<String>,
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
    /// Names taken from sibling generated modules, emitted in sorted order.
    ///
    /// A name is declared in exactly one module and imported everywhere else:
    /// the barrel re-exports every module with `export *`, and two modules
    /// exporting one name would make it ambiguous for every consumer.
    pub imports: Vec<ModuleImport>,
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
    /// The request builders and response decoders this module carries.
    pub command_surface: Option<CommandSurface>,
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
        preamble: r#"// The canonical JSON codec is not generated twice.
//
// `src/canonical.ts` mirrors `wire.rs` byte for byte and is held to that claim
// by the cross-language corpus in `tests/cross_language.rs`, in both
// directions. A second copy emitted here would be a second thing to keep
// right, and the copy that drifted would be the one nothing measured. This
// line is the whole of the generated tree's dependency on hand-written code:
// every other generated module imports from this file and from nothing else.
export {
  WireError,
  decodeMessageAdmitted,
  encodeMessage,
  toCanonicalBytes,
  type JsonValue,
} from "../src/canonical.ts";

import {type JsonValue} from "../src/canonical.ts";

const encoder = new TextEncoder();

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

/**
 * A refusal under the stable category the Rust peer reports for it.
 *
 * `ValidationError` says a value this program built is wrong; this says a
 * message was refused, under the spelling the daemon's own logs and refusal
 * metrics use. Keeping the category rather than a sentence is what lets a
 * cross-language fixture assert that both implementations refused the same
 * input for the same reason.
 */
export class RefusalError extends Error {
  readonly category: string;
  constructor(category: string, detail: string) {
    super(`${category}: ${detail}`);
    this.name = "RefusalError";
    this.category = category;
  }
}

/**
 * Run a validating step, reporting the category the Rust peer would report.
 *
 * The generated constructors refuse a value with a `ValidationError`, which is
 * the right error for a caller who built one. Inside an encoder or a decoder
 * the same refusal is a message-level one, and the peer names it with a
 * category; this is where the first becomes the second without losing what was
 * wrong.
 */
export function refuse<T>(category: string, action: () => T): T {
  try {
    return action();
  } catch (error) {
    if (error instanceof ValidationError) {
      throw new RefusalError(category, error.message);
    }
    throw error;
  }
}

/**
 * Refuse an envelope field the way the shared codec does.
 *
 * The codec settles the bounded-value rules before it judges a grammar, and
 * reports the two under different categories: an empty, overlong or
 * control-bearing value is a bounded-value refusal, and only a value that
 * cleared those rules can be refused for its grammar. A single category here
 * would tell a peer its identifier was the wrong shape when the length was
 * what was wrong.
 */
export function refuseField<T>(
  boundsCategory: string,
  grammarCategory: string,
  action: () => T,
): T {
  try {
    return action();
  } catch (error) {
    if (error instanceof ValidationError) {
      const category = error.violation === "invalid_character" ? grammarCategory : boundsCategory;
      throw new RefusalError(category, error.message);
    }
    throw error;
  }
}

/** Lowercase hexadecimal, two digits per byte. */
export function hexEncode(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * Bound an opaque byte string before it is encoded.
 *
 * The two categories are distinct because the Rust constructor's are: a
 * document over the ceiling and an empty one are different faults, and a
 * submitter told only "invalid" cannot tell which it made.
 */
export function boundedBytes(
  value: Uint8Array,
  maxBytes: number,
  oversizeCategory: string,
  emptyCategory: string,
): Uint8Array {
  if (value.length > maxBytes) {
    throw new RefusalError(
      oversizeCategory,
      `${value.length} bytes; maximum is ${maxBytes}`,
    );
  }
  if (value.length === 0) throw new RefusalError(emptyCategory, "empty document");
  return value;
}

/**
 * Read a body whose key set must be exactly `fields`.
 *
 * The Rust decoders refuse a body with a missing or unexpected key rather than
 * ignoring it, so a body carrying one more field than it should is refused
 * here too. The returned map is what the field readers below take, so a
 * decoder cannot read a field it did not first declare.
 */
export function exactFields(
  body: JsonValue,
  fields: readonly string[],
  category: string,
): ReadonlyMap<string, JsonValue> {
  if (body.kind !== "object") throw new RefusalError(category, "body is not an object");
  const found = new Map<string, JsonValue>();
  for (const [key, value] of body.entries) {
    if (found.has(key)) throw new RefusalError(category, `duplicate field ${key}`);
    found.set(key, value);
  }
  if (found.size !== fields.length || !fields.every((field) => found.has(field))) {
    throw new RefusalError(category, "body is not the exact shape for its kind");
  }
  return found;
}

/** A string field, refused when absent or of another JSON type. */
export function bodyString(
  fields: ReadonlyMap<string, JsonValue>,
  name: string,
  category: string,
): string {
  const value = fields.get(name);
  if (value === undefined || value.kind !== "string") {
    throw new RefusalError(category, `${name} is not a string`);
  }
  return value.value;
}

/** An integer field, refused when absent or of another JSON type. */
export function bodyInteger(
  fields: ReadonlyMap<string, JsonValue>,
  name: string,
  category: string,
): bigint {
  const value = fields.get(name);
  if (value === undefined || value.kind !== "integer") {
    throw new RefusalError(category, `${name} is not an integer`);
  }
  return value.value;
}

/** A boolean field. The wire carries `true` or `false` and nothing else. */
export function bodyBool(
  fields: ReadonlyMap<string, JsonValue>,
  name: string,
  category: string,
): boolean {
  const value = fields.get(name);
  if (value === undefined || value.kind !== "bool") {
    throw new RefusalError(category, `${name} is not a boolean`);
  }
  return value.value;
}

/**
 * An integer field the Rust decoder reads through `u64`.
 *
 * A negative value is refused here, before any domain bound is applied, because
 * that is the order the Rust decoders settle it in: `unsigned()` converts and
 * fails as a malformed body, and only a non-negative value ever reaches the
 * domain's own refusal. A reader that let the domain judge the sign would
 * report "unwritten row" for a submission identity of `-1`, which is a
 * different and wrong statement about what the peer sent.
 */
export function bodyUnsigned(
  fields: ReadonlyMap<string, JsonValue>,
  name: string,
  category: string,
): bigint {
  const value = fields.get(name);
  if (value === undefined || value.kind !== "integer") {
    throw new RefusalError(category, `${name} is not an integer`);
  }
  if (value.value < 0n) throw new RefusalError(category, `${name} is negative`);
  return value.value;
}

/**
 * An integer field that is always present and may be `null`.
 *
 * Absent and present-and-null are different wire facts. The Rust decoders
 * refuse a body missing the key and accept one carrying an explicit null, so a
 * reader that treated the two alike would admit a body Rust refuses.
 */
export function bodyIntegerOrNull(
  fields: ReadonlyMap<string, JsonValue>,
  name: string,
  category: string,
): bigint | null {
  const value = fields.get(name);
  if (value === undefined) throw new RefusalError(category, `${name} is absent`);
  if (value.kind === "null") return null;
  if (value.kind !== "integer") {
    throw new RefusalError(category, `${name} is neither an integer nor null`);
  }
  return value.value;
}

/** A field carrying a nested body, handed to that body's own decoder. */
export function bodyValue(
  fields: ReadonlyMap<string, JsonValue>,
  name: string,
  category: string,
): JsonValue {
  const value = fields.get(name);
  if (value === undefined) throw new RefusalError(category, `${name} is absent`);
  return value;
}

/**
 * A bounded array field.
 *
 * The length is judged before any item is read, exactly as the Rust decoders
 * judge it: a page above its ceiling is refused for being too long, not for
 * whatever its sixty-fifth item turns out to be. The two refusals carry
 * different categories, so the order matters to the peer as well as here.
 */
export function bodyArray(
  fields: ReadonlyMap<string, JsonValue>,
  name: string,
  category: string,
  maxItems: number,
  oversizeCategory: string,
): readonly JsonValue[] {
  const value = fields.get(name);
  if (value === undefined || value.kind !== "array") {
    throw new RefusalError(category, `${name} is not an array`);
  }
  if (value.items.length > maxItems) {
    throw new RefusalError(
      oversizeCategory,
      `${name} carries ${value.items.length} items; maximum is ${maxItems}`,
    );
  }
  return value.items;
}

/** Apply a reader to a nullable field, keeping `null` the distinct fact it is. */
export function mapNullable<T, U>(value: T | null, read: (value: T) => U): U | null {
  return value === null ? null : read(value);
}

/** How a set of enum spellings is canonicalized before it reaches the wire. */
export interface EnumSetRules {
  /** Declaration order, which is the order the wire carries. */
  readonly order: readonly string[];
  /** Category for a set that admits nothing. */
  readonly empty: string;
  /** Category for a set naming one value twice. */
  readonly repeat: string;
  /** Category for a spelling this build does not define. */
  readonly unknown: string;
}

/**
 * Canonicalize a set of enum spellings the way the Rust constructor does.
 *
 * Sorted into declaration order, so a set built in any order encodes
 * identically. An empty set and a repeated value are refused rather than
 * quietly accepted: both mean the caller asked for something other than what it
 * believes it asked for, and an empty filter in particular admits nothing that
 * any listing could ever answer.
 *
 * A spelling outside the order is refused too. A brand exists only in the type
 * checker, so this is the only place an untyped caller's undefined state can be
 * stopped before it reaches the wire.
 */
export function orderedEnumSet<T extends string>(
  values: readonly T[],
  rules: EnumSetRules,
): readonly T[] {
  if (values.length === 0) throw new RefusalError(rules.empty, "a filter admits no value");
  const found: {readonly at: number; readonly value: T}[] = [];
  for (const value of values) {
    const at = rules.order.indexOf(value);
    if (at < 0) throw new RefusalError(rules.unknown, value);
    found.push({at, value});
  }
  found.sort((left, right) => left.at - right.at);
  let previous = -1;
  for (const entry of found) {
    if (entry.at === previous) throw new RefusalError(rules.repeat, entry.value);
    previous = entry.at;
  }
  return found.map((entry) => entry.value);
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
                wire_order: None,
            },
            GeneratedEnum {
                name: "ReportStatus".to_owned(),
                sensitivity: EnumSensitivity::SecuritySensitive,
                values: report_status_values(),
                wire_order: None,
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
                wire_order: None,
            },
            GeneratedEnum {
                name: "ExecutionState".to_owned(),
                sensitivity: EnumSensitivity::SecuritySensitive,
                values: execution_state_values(),
                wire_order: None,
            },
            GeneratedEnum {
                name: "TelegramState".to_owned(),
                sensitivity: EnumSensitivity::SecuritySensitive,
                values: telegram_state_values(),
                wire_order: None,
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
                    required("intake_paused", "boolean"),
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

/// A refusal category, pinned to the Rust spelling a peer reports.
fn category(name: &str, doc: &str, error: &AdminError) -> Constant {
    Constant {
        name: name.to_owned(),
        doc: doc.to_owned(),
        value: ConstantValue::Text(error.category().to_owned()),
    }
}

/// A request field whose value is a checked string.
fn checked_field(name: &str, type_name: &str, refusal_category: &str) -> RequestField {
    RequestField {
        name: name.to_owned(),
        input_name: name.to_owned(),
        value: RequestValue::Checked {
            type_name: type_name.to_owned(),
            refusal_category: refusal_category.to_owned(),
        },
    }
}

/// A response field carrying a durable row identity.
fn row_id_field(name: &str, refusal_category: &str) -> ResponseField {
    ResponseField {
        name: name.to_owned(),
        value: ResponseValue::Integer {
            type_name: DURABLE_ROW_ID.to_owned(),
            refusal_category: refusal_category.to_owned(),
            // The admin lane reports one category for both faults, so reading
            // the sign separately would change nothing a peer can observe.
            unsigned: false,
        },
    }
}

/// TypeScript name of the branded durable row identity.
const DURABLE_ROW_ID: &str = "DurableRowId";

/// The `automonique.admin` command surface: what a client sends, and what it
/// can read back.
fn admin_command_module() -> GeneratedModule {
    let digest_hex_digits = crate::digest::DIGEST_BYTES * 2;
    let digest_algorithm = crate::digest::ALGORITHM;
    GeneratedModule {
        file_name: module_file_name(ADMIN_COMMAND_MODULE),
        doc: "The admin commands a client builds and the receipts it decodes.".to_owned(),
        source: "automonique_protocol::admin".to_owned(),
        imports: vec![ModuleImport {
            module: ADMIN_STATUS_MODULE.to_owned(),
            values: vec![
                "ADMIN_PROTOCOL".to_owned(),
                "MAX_ADMIN_CANONICAL_BYTES".to_owned(),
            ],
            types: Vec::new(),
        }],
        constants: vec![Constant {
            name: "MAX_SUBMITTED_RUN_SPEC_BYTES".to_owned(),
            doc: "Maximum raw RunSpec document bytes this lane carries. The wire spends twice \
                  this, because the document travels hex-encoded."
                .to_owned(),
            value: ConstantValue::Count(crate::admin::MAX_SUBMITTED_RUN_SPEC_BYTES),
        }],
        bounded_strings: vec![
            BoundedString {
                name: "AdminRefusalCategory".to_owned(),
                max_bytes: crate::admin::MAX_ADMIN_REFUSAL_CATEGORY_BYTES,
                pattern: Some("^[a-z0-9_]+$".to_owned()),
            },
            BoundedString {
                name: "IntakeActor".to_owned(),
                max_bytes: crate::admin::MAX_INTAKE_ACTOR_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
            BoundedString {
                name: "IntakeReason".to_owned(),
                max_bytes: crate::admin::MAX_INTAKE_REASON_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
            BoundedString {
                name: "RequestId".to_owned(),
                max_bytes: crate::codec::MAX_REQUEST_ID_BYTES,
                pattern: Some("^[A-Za-z0-9._:-]+$".to_owned()),
            },
            BoundedString {
                name: "RunId".to_owned(),
                max_bytes: crate::tools::MAX_TOOL_FIELD_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
            BoundedString {
                name: "RunSubmissionKey".to_owned(),
                max_bytes: crate::admin::MAX_RUN_SUBMISSION_KEY_BYTES,
                pattern: Some(NO_CONTROL_CHARACTERS.to_owned()),
            },
            BoundedString {
                // The canonical spelling is the algorithm name, a colon and the
                // hex body, which is the only spelling `Sha256Digest::from_str`
                // accepts: uppercase is refused rather than folded, so one
                // digest has one spelling on this wire.
                name: "SpecDigest".to_owned(),
                max_bytes: digest_algorithm.len() + 1 + digest_hex_digits,
                pattern: Some(format!(
                    "^{digest_algorithm}:[0-9a-f]{{{digest_hex_digits}}}$"
                )),
            },
        ],
        bounded_integers: vec![BoundedInteger {
            // A durable row identity starts at one: the Rust encoder refuses
            // zero rather than reporting an unwritten row as committed.
            name: DURABLE_ROW_ID.to_owned(),
            min: 1,
            max: i64::MAX,
        }],
        command_surface: Some(CommandSurface {
            name: "Admin".to_owned(),
            protocol_constant: "ADMIN_PROTOCOL".to_owned(),
            protocol: crate::admin::ADMIN_PROTOCOL.to_owned(),
            version: crate::codec::MajorVersion::FIRST.get(),
            max_message_bytes_constant: "MAX_ADMIN_CANONICAL_BYTES".to_owned(),
            request_id_type: "RequestId".to_owned(),
            categories: vec![
                category(
                    "ADMIN_DOCUMENT_TOO_LARGE",
                    "A carried RunSpec document is larger than one admin frame can hold.",
                    &AdminError::DocumentTooLarge {
                        max_bytes: 0,
                        actual_bytes: 0,
                    },
                ),
                category(
                    "ADMIN_INVALID_BODY",
                    "A body was not the exact shape defined for its kind.",
                    &AdminError::InvalidBody,
                ),
                category(
                    "ADMIN_UNKNOWN_KIND",
                    "The message kind is not part of this closed protocol version.",
                    &AdminError::UnknownKind,
                ),
                Constant {
                    // The envelope's own fields are judged by the shared codec
                    // rather than by this protocol, so its categories are the
                    // ones a peer receives for them. Both are pinned to
                    // `CodecError::category` rather than spelled here.
                    name: "WIRE_FIELD_GRAMMAR".to_owned(),
                    doc: "An envelope field cleared the bounded-value rules and broke its own \
                          grammar."
                        .to_owned(),
                    value: ConstantValue::Text(
                        CodecError::Grammar {
                            field: "request_id",
                        }
                        .category()
                        .to_owned(),
                    ),
                },
                Constant {
                    name: "WIRE_FIELD_INVALID".to_owned(),
                    doc: "An envelope field was empty, too long, or carried a control character."
                        .to_owned(),
                    value: ConstantValue::Text(
                        CodecError::Field {
                            field: "request_id",
                            error: ValueError::Empty,
                        }
                        .category()
                        .to_owned(),
                    ),
                },
                Constant {
                    // This one is not an `AdminError`: it is the spelling both
                    // ends of the shipped transport report for a payload above
                    // the ceiling, before any message is built or parsed. The
                    // protocol crate has no constant for it, so nothing pins
                    // it; `automonique-daemon` and `automonique-cli` are where
                    // it is written.
                    name: "ADMIN_FRAME_SIZE".to_owned(),
                    doc: "A canonical payload above the ceiling the local transport accepts."
                        .to_owned(),
                    value: ConstantValue::Text("frame_size".to_owned()),
                },
            ],
            invalid_body_category: "ADMIN_INVALID_BODY".to_owned(),
            unknown_kind_category: "ADMIN_UNKNOWN_KIND".to_owned(),
            oversize_category: "ADMIN_FRAME_SIZE".to_owned(),
            field_invalid_category: "WIRE_FIELD_INVALID".to_owned(),
            field_grammar_category: "WIRE_FIELD_GRAMMAR".to_owned(),
            body_objects: Vec::new(),
            requests: vec![
                RequestCommand {
                    kind: "status".to_owned(),
                    name: "Status".to_owned(),
                    doc: "Read a consistent daemon status snapshot.".to_owned(),
                    fields: Vec::new(),
                },
                RequestCommand {
                    kind: "submit_run".to_owned(),
                    name: "SubmitRun".to_owned(),
                    doc: "Take durable custody of one canonical RunSpec document. Acceptance is \
                          custody, not execution."
                        .to_owned(),
                    fields: vec![
                        RequestField {
                            name: "document_hex".to_owned(),
                            input_name: "document".to_owned(),
                            value: RequestValue::HexBytes {
                                max_bytes_constant: "MAX_SUBMITTED_RUN_SPEC_BYTES".to_owned(),
                                oversize_category: "ADMIN_DOCUMENT_TOO_LARGE".to_owned(),
                            },
                        },
                        checked_field("idempotency_key", "RunSubmissionKey", "ADMIN_INVALID_BODY"),
                        checked_field("spec_digest", "SpecDigest", "ADMIN_INVALID_BODY"),
                    ],
                },
                RequestCommand {
                    kind: "pause_intake".to_owned(),
                    name: "PauseIntake".to_owned(),
                    doc: "Durably close intake for this generation, naming the deciding operator \
                          and the cause."
                        .to_owned(),
                    fields: vec![
                        checked_field("actor", "IntakeActor", "ADMIN_INVALID_BODY"),
                        checked_field("reason", "IntakeReason", "ADMIN_INVALID_BODY"),
                    ],
                },
                RequestCommand {
                    kind: "resume_intake".to_owned(),
                    name: "ResumeIntake".to_owned(),
                    doc: "Reopen intake, naming the operator who decided to.".to_owned(),
                    fields: vec![checked_field("actor", "IntakeActor", "ADMIN_INVALID_BODY")],
                },
                RequestCommand {
                    kind: "shutdown".to_owned(),
                    name: "Shutdown".to_owned(),
                    doc: "Stop intake and request an orderly shutdown.".to_owned(),
                    fields: Vec::new(),
                },
            ],
            request_kinds_not_generated: vec![
                "fail_reconciliation".to_owned(),
                "inspect_outbox".to_owned(),
                "inspect_reconciliation".to_owned(),
                "reconcile_outbox".to_owned(),
                "submit_synthetic".to_owned(),
            ],
            responses: vec![
                ResponseDecoder {
                    kind: "intake_paused".to_owned(),
                    name: "IntakePaused".to_owned(),
                    doc: "Intake is durably closed for this generation. The decision outlives \
                          the process."
                        .to_owned(),
                    fields: vec![
                        row_id_field("pause_id", "ADMIN_INVALID_BODY"),
                        row_id_field("revision", "ADMIN_INVALID_BODY"),
                    ],
                },
                ResponseDecoder {
                    kind: "intake_resumed".to_owned(),
                    name: "IntakeResumed".to_owned(),
                    doc: "A durable pause was closed and intake reopened. The pause row is \
                          retained, not deleted."
                        .to_owned(),
                    fields: vec![
                        row_id_field("pause_id", "ADMIN_INVALID_BODY"),
                        row_id_field("revision", "ADMIN_INVALID_BODY"),
                    ],
                },
                ResponseDecoder {
                    kind: "refused".to_owned(),
                    name: "Refused".to_owned(),
                    doc: "The request was definitely refused before a successful mutation."
                        .to_owned(),
                    fields: vec![ResponseField {
                        name: "category".to_owned(),
                        value: ResponseValue::Checked {
                            type_name: "AdminRefusalCategory".to_owned(),
                            refusal_category: "ADMIN_INVALID_BODY".to_owned(),
                        },
                    }],
                },
                ResponseDecoder {
                    kind: "run_accepted".to_owned(),
                    name: "RunAccepted".to_owned(),
                    doc: "One RunSpec document is durably held. Custody is all this reports: it \
                          is not an admission decision and not a launch."
                        .to_owned(),
                    fields: vec![
                        ResponseField {
                            name: "replay".to_owned(),
                            value: ResponseValue::Bool,
                        },
                        ResponseField {
                            name: "run_id".to_owned(),
                            value: ResponseValue::Checked {
                                type_name: "RunId".to_owned(),
                                refusal_category: "ADMIN_INVALID_BODY".to_owned(),
                            },
                        },
                        ResponseField {
                            name: "spec_digest".to_owned(),
                            value: ResponseValue::Checked {
                                type_name: "SpecDigest".to_owned(),
                                refusal_category: "ADMIN_INVALID_BODY".to_owned(),
                            },
                        },
                        row_id_field("submission_id", "ADMIN_INVALID_BODY"),
                    ],
                },
                ResponseDecoder {
                    kind: "shutdown_accepted".to_owned(),
                    name: "ShutdownAccepted".to_owned(),
                    doc: "The daemon accepted an orderly-shutdown request and closed intake."
                        .to_owned(),
                    fields: Vec::new(),
                },
            ],
            response_kinds_not_decoded: vec![
                "outbox_inspected".to_owned(),
                "outbox_reconciled".to_owned(),
                "reconciliation_failed".to_owned(),
                "reconciliation_inspected".to_owned(),
                "status_result".to_owned(),
                "synthetic_accepted".to_owned(),
            ],
        }),
        ..GeneratedModule::default()
    }
}

// ---------------------------------------------------------------------------
// The `automonique.runs` read surface
//
// The six closed vocabularies below are each built by mapping the Rust array
// through an exhaustive `match`. The `match` is the whole point: a variant
// added to any of these enums fails to compile here rather than dropping out of
// the generated union while every test still passes. Two of them —
// `RunState` and `SpoolEventKind` — mirror vocabularies this dependency-free
// crate cannot import, and `tests/runs_api.rs` pins those against the sibling
// crate's own source; this file inherits that pin by reading the mirror.
// ---------------------------------------------------------------------------

/// The declared [`RunState`] spellings, pinned to the Rust wire strings.
fn run_state_values() -> Vec<String> {
    RunState::ALL
        .into_iter()
        .map(|state| match state {
            RunState::Ready
            | RunState::Running
            | RunState::Completed
            | RunState::Failed
            | RunState::Cancelled
            | RunState::TimedOut => state.as_str().to_owned(),
        })
        .collect()
}

/// The declared [`SubmissionState`] spellings, pinned to the Rust wire strings.
fn submission_state_values() -> Vec<String> {
    SubmissionState::ALL
        .into_iter()
        .map(|state| match state {
            SubmissionState::Accepted => state.as_str().to_owned(),
        })
        .collect()
}

/// The declared [`SpoolEventKind`] spellings, pinned to the Rust wire strings.
fn spool_event_kind_values() -> Vec<String> {
    SpoolEventKind::ALL
        .into_iter()
        .map(|kind| match kind {
            SpoolEventKind::Started
            | SpoolEventKind::AdapterEvent
            | SpoolEventKind::SimulationEvent
            | SpoolEventKind::CancelRequested
            | SpoolEventKind::Terminal => kind.as_str().to_owned(),
        })
        .collect()
}

/// The declared [`LifecycleCoverage`] spellings, pinned to the Rust wire
/// strings.
fn lifecycle_coverage_values() -> Vec<String> {
    LifecycleCoverage::ALL
        .into_iter()
        .map(|coverage| match coverage {
            LifecycleCoverage::Complete | LifecycleCoverage::Truncated => {
                coverage.as_str().to_owned()
            }
        })
        .collect()
}

/// The declared [`RunsRefusal`] spellings, pinned to the Rust wire strings.
fn runs_refusal_values() -> Vec<String> {
    RunsRefusal::ALL
        .into_iter()
        .map(|refusal| match refusal {
            RunsRefusal::UnknownRun => refusal.as_str().to_owned(),
        })
        .collect()
}

/// The authorities a lifecycle event may carry.
///
/// Taken from [`LIFECYCLE_AUTHORITIES`] rather than from a spelling table of
/// its own, exactly as `runs_api` takes it: the spool's authority and this
/// crate's are the same two words, and writing them down a third time would be
/// a third thing to keep right.
fn lifecycle_authority_values() -> Vec<String> {
    LIFECYCLE_AUTHORITIES
        .into_iter()
        .map(|authority| match authority {
            Authority::Authoritative | Authority::Synthetic => authority.as_str().to_owned(),
        })
        .collect()
}

/// A refusal category, pinned to the spelling the Runs API reports for it.
fn runs_category(name: &str, doc: &str, error: &RunsApiError) -> Constant {
    Constant {
        name: name.to_owned(),
        doc: doc.to_owned(),
        value: ConstantValue::Text(error.category().to_owned()),
    }
}

/// A security-sensitive enumeration of the Runs API.
fn runs_enum(name: &str, values: Vec<String>, wire_order: Option<Vec<String>>) -> GeneratedEnum {
    GeneratedEnum {
        name: name.to_owned(),
        // Every vocabulary on this lane is a `SecuritySensitiveEnum` in Rust,
        // whose decoder answers `unknown_enum_value` rather than a default. A
        // generated reader that retained an undefined state would have to decide
        // what it means, and would decide wrong.
        sensitivity: EnumSensitivity::SecuritySensitive,
        values,
        wire_order,
    }
}

/// A response or nested-body field carrying a closed vocabulary.
fn enum_field(name: &str, type_name: &str) -> ResponseField {
    ResponseField {
        name: name.to_owned(),
        value: ResponseValue::Enum {
            type_name: type_name.to_owned(),
            unknown_category: "RUNS_UNKNOWN_ENUM_VALUE".to_owned(),
        },
    }
}

/// A response or nested-body field carrying a bounded integer.
///
/// `unsigned` mirrors which Rust reader the field goes through: `unsigned()`
/// converts to `u64` and refuses a negative as an invalid body before the
/// domain is consulted, while an instant is read as a signed integer and
/// refused by the domain itself. Getting this wrong reports the domain's
/// category for a malformed body.
fn runs_integer_field(
    name: &str,
    type_name: &str,
    refusal_category: &str,
    unsigned: bool,
) -> ResponseField {
    ResponseField {
        name: name.to_owned(),
        value: ResponseValue::Integer {
            type_name: type_name.to_owned(),
            refusal_category: refusal_category.to_owned(),
            unsigned,
        },
    }
}

/// TypeScript name of the branded acceptance instant.
const EPOCH_MILLIS: &str = "EpochMillis";

/// TypeScript name of the branded listing position.
const RUN_CURSOR: &str = "RunCursor";

/// The `automonique.runs` read surface: what a client asks, and what it decodes.
fn runs_module() -> GeneratedModule {
    GeneratedModule {
        file_name: module_file_name(RUNS_MODULE),
        doc: "The native Runs API read surface: list runs, read one run, turn a page.".to_owned(),
        source: "automonique_protocol::runs_api".to_owned(),
        // A name is declared in exactly one module. `RequestId`, `RunId`,
        // `SpecDigest` and `DurableRowId` are wire vocabularies rather than
        // admin ones — a run identity is the same domain on both lanes — so
        // this module reads them from where they are declared rather than
        // declaring a second, separately-drifting copy.
        imports: vec![ModuleImport {
            module: ADMIN_COMMAND_MODULE.to_owned(),
            values: vec![
                DURABLE_ROW_ID.to_owned(),
                "RequestId".to_owned(),
                "RunId".to_owned(),
                "SpecDigest".to_owned(),
            ],
            types: Vec::new(),
        }],
        constants: vec![
            Constant {
                name: "MAX_LIFECYCLE_EVENTS".to_owned(),
                doc: "Maximum lifecycle events one detail view may carry.".to_owned(),
                value: ConstantValue::Count(crate::runs_api::MAX_LIFECYCLE_EVENTS),
            },
            Constant {
                name: "MAX_RUNS_CANONICAL_BYTES".to_owned(),
                doc: "Maximum canonical message bytes this protocol will assemble or admit."
                    .to_owned(),
                value: ConstantValue::Count(crate::runs_api::MAX_RUNS_CANONICAL_BYTES),
            },
            Constant {
                name: "MAX_RUN_PAGE_ITEMS".to_owned(),
                doc: "Maximum summaries one listing page may carry. A page bound is not a paging \
                      hint: a longer page is refused rather than truncated, because a truncated \
                      page that still answered `complete` is the silent drop the retention rule \
                      forbids."
                    .to_owned(),
                value: ConstantValue::Count(crate::runs_api::MAX_RUN_PAGE_ITEMS),
            },
            Constant {
                name: "RUNS_API_SCHEMA_V1".to_owned(),
                doc: "Stable schema identifier for the version-one read surface.".to_owned(),
                value: ConstantValue::Text(crate::runs_api::RUNS_API_SCHEMA_V1.to_owned()),
            },
            Constant {
                name: "RUNS_PROTOCOL".to_owned(),
                doc: "Stable protocol name for the native Runs API.".to_owned(),
                value: ConstantValue::Text(crate::runs_api::RUNS_PROTOCOL.to_owned()),
            },
        ],
        bounded_integers: vec![
            BoundedInteger {
                // The store's `accepted_at_ms >= 0` constraint and the spool's
                // unsigned millisecond field are what this bound is: an instant
                // before the epoch is one neither can hold, and the Rust
                // constructors refuse it rather than storing it.
                name: EPOCH_MILLIS.to_owned(),
                min: 0,
                max: i64::MAX,
            },
            BoundedInteger {
                // Zero is the value the spool's status reports when a run has
                // *no* events, so it is a valid highest-sequence and an invalid
                // event sequence. The two are separate types for that reason.
                name: "LastSequence".to_owned(),
                min: 0,
                max: i64::MAX,
            },
            BoundedInteger {
                name: "PageSize".to_owned(),
                min: 1,
                max: i64::try_from(crate::runs_api::MAX_RUN_PAGE_ITEMS)
                    .expect("the page bound is within the wire range"),
            },
            BoundedInteger {
                name: RUN_CURSOR.to_owned(),
                min: 0,
                max: i64::MAX,
            },
            BoundedInteger {
                name: "SpoolSequence".to_owned(),
                min: 1,
                max: i64::MAX,
            },
        ],
        enums: vec![
            runs_enum("Authority", lifecycle_authority_values(), None),
            runs_enum("LifecycleCoverage", lifecycle_coverage_values(), None),
            // The only vocabulary whose declaration order reaches the wire: a
            // state filter is canonicalized into it.
            runs_enum("RunState", run_state_values(), Some(run_state_values())),
            runs_enum("RunsRefusal", runs_refusal_values(), None),
            runs_enum("SpoolEventKind", spool_event_kind_values(), None),
            runs_enum("SubmissionState", submission_state_values(), None),
        ],
        command_surface: Some(CommandSurface {
            name: "Runs".to_owned(),
            protocol_constant: "RUNS_PROTOCOL".to_owned(),
            protocol: crate::runs_api::RUNS_PROTOCOL.to_owned(),
            version: crate::codec::MajorVersion::FIRST.get(),
            max_message_bytes_constant: "MAX_RUNS_CANONICAL_BYTES".to_owned(),
            request_id_type: "RequestId".to_owned(),
            categories: vec![
                runs_category(
                    "RUNS_COUNTER_OUT_OF_RANGE",
                    "A counter is outside the range the integer-only wire codec carries.",
                    &RunsApiError::CounterOutOfRange { field: "since" },
                ),
                runs_category(
                    "RUNS_INVALID_BODY",
                    "A body was not the exact shape defined for its kind.",
                    &RunsApiError::InvalidBody,
                ),
                runs_category(
                    "RUNS_INVALID_FIELD",
                    "A bounded identifier was empty, over-long or control-bearing.",
                    &RunsApiError::Field {
                        field: "run_id",
                        error: ValueError::Empty,
                    },
                ),
                runs_category(
                    "RUNS_LIFECYCLE_OUT_OF_ORDER",
                    "A lifecycle sequence was zero, which names a run with no events rather \
                     than an event.",
                    &RunsApiError::LifecycleOutOfOrder,
                ),
                runs_category(
                    "RUNS_LIFECYCLE_TOO_LONG",
                    "A view carried more lifecycle events than one view holds.",
                    &RunsApiError::LifecycleTooLong {
                        max_events: 0,
                        actual_events: 0,
                    },
                ),
                runs_category(
                    "RUNS_PAGE_SIZE_OUT_OF_RANGE",
                    "A requested page size was zero — a page that admits nothing cannot make \
                     progress — or above the largest page this protocol serves.",
                    &RunsApiError::PageSizeOutOfRange {
                        max_items: 0,
                        requested: 0,
                    },
                ),
                runs_category(
                    "RUNS_PAGE_TOO_LARGE",
                    "A page carried more summaries than one page holds.",
                    &RunsApiError::PageTooLarge {
                        max_items: 0,
                        actual_items: 0,
                    },
                ),
                runs_category(
                    "RUNS_STATE_FILTER_EMPTY",
                    "A state filter admitted nothing, which no listing could ever answer.",
                    &RunsApiError::StateFilterEmpty,
                ),
                runs_category(
                    "RUNS_STATE_FILTER_REPEATS",
                    "A state filter named one state twice, which is a caller that believes it \
                     asked for something it did not.",
                    &RunsApiError::StateFilterRepeats {
                        state: RunState::Ready,
                    },
                ),
                runs_category(
                    "RUNS_TIME_BEFORE_EPOCH",
                    "A durable instant was before the epoch, which the store cannot hold.",
                    &RunsApiError::TimeBeforeEpoch {
                        field: "accepted_at_ms",
                    },
                ),
                runs_category(
                    "RUNS_UNKNOWN_KIND",
                    "The message kind is not part of this closed protocol version.",
                    &RunsApiError::UnknownKind,
                ),
                runs_category(
                    "RUNS_UNWRITTEN_ROW",
                    "A durable row identity was zero, which names a row no writer produced.",
                    &RunsApiError::UnwrittenRow {
                        field: "submission_id",
                    },
                ),
                // The three below are the shared codec's own categories, which
                // this protocol reports unchanged: `RunsApiError::Codec`
                // delegates to them rather than restating them. They are spelled
                // with this lane's prefix because one name has one declaring
                // module, and `admin-command.ts` already declares its own pair
                // of the same two spellings.
                runs_category(
                    "RUNS_FIELD_GRAMMAR",
                    "An envelope field cleared the bounded-value rules and broke its own \
                     grammar.",
                    &RunsApiError::Codec(CodecError::Grammar {
                        field: "request_id",
                    }),
                ),
                runs_category(
                    "RUNS_FIELD_INVALID",
                    "An envelope field was empty, too long, or carried a control character.",
                    &RunsApiError::Codec(CodecError::Field {
                        field: "request_id",
                        error: ValueError::Empty,
                    }),
                ),
                runs_category(
                    "RUNS_UNKNOWN_ENUM_VALUE",
                    "A state, event kind, authority, coverage, submission state or refusal this \
                     build does not define. Every vocabulary on this lane fails closed.",
                    &RunsApiError::Codec(CodecError::UnknownEnumValue { field: "state" }),
                ),
                Constant {
                    // Unlike the admin lane's, nothing pins this one: no shipped
                    // transport carries `automonique.runs` yet, so no peer
                    // reports a spelling for a payload above the ceiling. The
                    // spelling is the admin transport's, which is what a Runs
                    // transport would inherit; until one exists this is a claim
                    // about the future rather than a mirror of the present, and
                    // it says so rather than looking like the others.
                    name: "RUNS_FRAME_SIZE".to_owned(),
                    doc: "A canonical payload above this protocol's ceiling. No shipped \
                          transport carries this protocol yet, so nothing pins this spelling; it \
                          is the one the local admin transport reports for the same fault."
                        .to_owned(),
                    value: ConstantValue::Text("frame_size".to_owned()),
                },
            ],
            invalid_body_category: "RUNS_INVALID_BODY".to_owned(),
            unknown_kind_category: "RUNS_UNKNOWN_KIND".to_owned(),
            oversize_category: "RUNS_FRAME_SIZE".to_owned(),
            field_invalid_category: "RUNS_FIELD_INVALID".to_owned(),
            field_grammar_category: "RUNS_FIELD_GRAMMAR".to_owned(),
            body_objects: vec![
                BodyObject {
                    name: "RunLifecycleEvent".to_owned(),
                    doc: "One durable lifecycle event, as the runner's spool exposes it. The \
                          payload bytes and the chained digest are deliberately absent: a detail \
                          view carries the skeleton, and payload retrieval stays on the \
                          subscribe lane."
                        .to_owned(),
                    fields: vec![
                        runs_integer_field("at_ms", EPOCH_MILLIS, "RUNS_TIME_BEFORE_EPOCH", false),
                        enum_field("authority", "Authority"),
                        enum_field("kind", "SpoolEventKind"),
                        runs_integer_field(
                            "sequence",
                            "SpoolSequence",
                            "RUNS_LIFECYCLE_OUT_OF_ORDER",
                            true,
                        ),
                    ],
                },
                BodyObject {
                    name: "RunSummary".to_owned(),
                    doc: "One run, as a listing reports it. `state` is the runner spool's and \
                          `submission_state` is the store's: they answer different questions, \
                          and both travel so neither can be mistaken for the other."
                        .to_owned(),
                    fields: vec![
                        runs_integer_field(
                            "accepted_at_ms",
                            EPOCH_MILLIS,
                            "RUNS_TIME_BEFORE_EPOCH",
                            false,
                        ),
                        ResponseField {
                            name: "run_id".to_owned(),
                            value: ResponseValue::Checked {
                                type_name: "RunId".to_owned(),
                                refusal_category: "RUNS_INVALID_FIELD".to_owned(),
                            },
                        },
                        ResponseField {
                            name: "spec_digest".to_owned(),
                            value: ResponseValue::Checked {
                                type_name: "SpecDigest".to_owned(),
                                refusal_category: "RUNS_INVALID_BODY".to_owned(),
                            },
                        },
                        enum_field("state", "RunState"),
                        runs_integer_field(
                            "submission_id",
                            DURABLE_ROW_ID,
                            "RUNS_UNWRITTEN_ROW",
                            true,
                        ),
                        enum_field("submission_state", "SubmissionState"),
                    ],
                },
            ],
            requests: vec![
                RequestCommand {
                    kind: "list_runs".to_owned(),
                    name: "ListRuns".to_owned(),
                    doc: "Ask for one bounded page of runs. `states` is null for no filter, \
                          which is a different request from one naming every state; `since` is \
                          null to begin at the oldest position still retained, never at position \
                          one."
                        .to_owned(),
                    fields: vec![
                        RequestField {
                            name: "page_size".to_owned(),
                            input_name: "page_size".to_owned(),
                            value: RequestValue::Integer {
                                type_name: "PageSize".to_owned(),
                                refusal_category: "RUNS_PAGE_SIZE_OUT_OF_RANGE".to_owned(),
                            },
                        },
                        RequestField {
                            name: "since".to_owned(),
                            input_name: "since".to_owned(),
                            value: RequestValue::NullableInteger {
                                type_name: RUN_CURSOR.to_owned(),
                                refusal_category: "RUNS_COUNTER_OUT_OF_RANGE".to_owned(),
                            },
                        },
                        RequestField {
                            name: "states".to_owned(),
                            input_name: "states".to_owned(),
                            value: RequestValue::NullableEnumSet {
                                type_name: "RunState".to_owned(),
                                order_constant: "RunState_WIRE_ORDER".to_owned(),
                                empty_category: "RUNS_STATE_FILTER_EMPTY".to_owned(),
                                repeat_category: "RUNS_STATE_FILTER_REPEATS".to_owned(),
                                unknown_category: "RUNS_UNKNOWN_ENUM_VALUE".to_owned(),
                            },
                        },
                    ],
                },
                RequestCommand {
                    kind: "run_detail".to_owned(),
                    name: "RunDetail".to_owned(),
                    doc: "Read one run in full: its summary and its lifecycle skeleton.".to_owned(),
                    fields: vec![checked_field("run_id", "RunId", "RUNS_INVALID_FIELD")],
                },
            ],
            // This protocol version defines exactly the two requests above.
            // `tests/codegen.rs` proves the list against the Rust encoders
            // themselves rather than against this claim.
            request_kinds_not_generated: Vec::new(),
            responses: vec![
                ResponseDecoder {
                    kind: "run_list_result".to_owned(),
                    name: "RunListPage".to_owned(),
                    doc: "One bounded page of run summaries. `more` is carried explicitly rather \
                          than inferred from a short page: a state filter can exclude every row \
                          in a scanned window and still leave rows behind it."
                        .to_owned(),
                    fields: vec![
                        ResponseField {
                            name: "more".to_owned(),
                            value: ResponseValue::Bool,
                        },
                        ResponseField {
                            name: "next_cursor".to_owned(),
                            value: ResponseValue::NullableInteger {
                                type_name: RUN_CURSOR.to_owned(),
                                refusal_category: "RUNS_INVALID_BODY".to_owned(),
                            },
                        },
                        ResponseField {
                            name: "runs".to_owned(),
                            value: ResponseValue::ObjectArray {
                                type_name: "RunSummary".to_owned(),
                                max_items_constant: "MAX_RUN_PAGE_ITEMS".to_owned(),
                                oversize_category: "RUNS_PAGE_TOO_LARGE".to_owned(),
                            },
                        },
                    ],
                },
                ResponseDecoder {
                    kind: "run_detail_result".to_owned(),
                    name: "RunDetailView".to_owned(),
                    doc: "One run in full. `coverage` says whether the carried lifecycle is the \
                          whole log, because a bounded list with no statement about what it \
                          omits is a partial stream presented as a whole one."
                        .to_owned(),
                    fields: vec![
                        enum_field("coverage", "LifecycleCoverage"),
                        runs_integer_field(
                            "last_sequence",
                            "LastSequence",
                            "RUNS_INVALID_BODY",
                            true,
                        ),
                        ResponseField {
                            name: "lifecycle".to_owned(),
                            value: ResponseValue::ObjectArray {
                                type_name: "RunLifecycleEvent".to_owned(),
                                max_items_constant: "MAX_LIFECYCLE_EVENTS".to_owned(),
                                oversize_category: "RUNS_LIFECYCLE_TOO_LONG".to_owned(),
                            },
                        },
                        ResponseField {
                            name: "summary".to_owned(),
                            value: ResponseValue::Object {
                                type_name: "RunSummary".to_owned(),
                            },
                        },
                    ],
                },
                ResponseDecoder {
                    kind: "resync_required".to_owned(),
                    name: "RunsResync".to_owned(),
                    doc: "The caller's cursor is outside retention. It carries the window a \
                          bounded snapshot must cover and never carries rows, because a cursor \
                          outside retention receives this answer rather than a silent partial \
                          stream."
                        .to_owned(),
                    fields: vec![
                        runs_integer_field("snapshot_from", RUN_CURSOR, "RUNS_INVALID_BODY", true),
                        runs_integer_field("snapshot_to", RUN_CURSOR, "RUNS_INVALID_BODY", true),
                    ],
                },
                ResponseDecoder {
                    kind: "refused".to_owned(),
                    name: "RunsRefused".to_owned(),
                    doc: "The query was refused and nothing was read. The vocabulary is \
                          deliberately small: this slice models no actor, so it names no \
                          authorization refusal it could not have decided."
                        .to_owned(),
                    fields: vec![enum_field("refusal", "RunsRefusal")],
                },
            ],
            // Every kind this protocol version answers with is decoded above.
            response_kinds_not_decoded: Vec::new(),
        }),
        ..GeneratedModule::default()
    }
}

/// Every maintained module, in file-name order.
#[must_use]
pub fn maintained_modules() -> Vec<GeneratedModule> {
    let mut modules = vec![
        runtime_module(),
        doctor_module(),
        admin_status_module(),
        admin_command_module(),
        runs_module(),
    ];
    modules.sort_by(|left, right| left.file_name.cmp(&right.file_name));
    modules
}

/// The runtime symbols a module's declarations need, as `(values, types)` in
/// sorted order.
///
/// Derived from what is about to be emitted rather than listed by hand, so a
/// module cannot import a helper it stopped using or miss one it started. Types
/// are separated from values because the generated files are run by TypeScript
/// implementations that only erase types: a type imported as a value leaves a
/// binding behind that does not exist.
fn runtime_imports(module: &GeneratedModule) -> (Vec<&'static str>, Vec<&'static str>) {
    let measures_bytes = !module.branded_ids.is_empty() || !module.bounded_strings.is_empty();
    let mut refuses_values = measures_bytes
        || !module.bounded_integers.is_empty()
        || !module.enums.is_empty()
        || !module.unions.is_empty();
    let mut names = Vec::new();
    let mut types = Vec::new();

    if let Some(surface) = &module.command_surface {
        // A surface always refuses something: an oversized payload on the way
        // out, an undefined kind on the way in.
        names.extend(["RefusalError", "refuseField"]);
        refuses_values = true;
        let request_fields = || surface.requests.iter().flat_map(|request| &request.fields);
        if !surface.requests.is_empty() {
            names.push("encodeMessage");
            types.push("JsonValue");
        }
        for field in request_fields() {
            match &field.value {
                RequestValue::Checked { .. }
                | RequestValue::Integer { .. }
                | RequestValue::NullableInteger { .. } => names.push("refuse"),
                RequestValue::HexBytes { .. } => {
                    names.extend(["boundedBytes", "hexEncode", "refuse"]);
                }
                RequestValue::NullableEnumSet { .. } => names.push("orderedEnumSet"),
            }
        }
        if !surface.responses.is_empty() {
            names.extend(["decodeMessageAdmitted", "exactFields", "refuse"]);
            types.push("JsonValue");
        }
        if !surface.body_objects.is_empty() {
            names.push("exactFields");
            types.push("JsonValue");
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
                ResponseValue::Bool => names.push("bodyBool"),
                ResponseValue::Checked { .. } | ResponseValue::Enum { .. } => {
                    names.extend(["bodyString", "refuse"]);
                }
                ResponseValue::Integer { unsigned, .. } => {
                    names.extend([
                        if *unsigned {
                            "bodyUnsigned"
                        } else {
                            "bodyInteger"
                        },
                        "refuse",
                    ]);
                }
                ResponseValue::NullableInteger { .. } => {
                    names.extend(["bodyIntegerOrNull", "mapNullable", "refuse"]);
                }
                ResponseValue::Object { .. } => names.push("bodyValue"),
                ResponseValue::ObjectArray { .. } => names.push("bodyArray"),
            }
        }
    }

    if refuses_values {
        names.push("ValidationError");
    }
    if measures_bytes {
        names.push("byteLength");
    }
    names.sort_unstable();
    names.dedup();
    types.sort_unstable();
    types.dedup();
    (names, types)
}

/// Emit the import lines one module opens with.
fn emit_imports(out: &mut String, module: &GeneratedModule) {
    let mut lines: Vec<(String, Vec<String>, Vec<String>)> = module
        .imports
        .iter()
        .map(|import| {
            (
                module_file_name(&import.module),
                import.values.clone(),
                import.types.clone(),
            )
        })
        .collect();
    let (values, types) = runtime_imports(module);
    if !values.is_empty() || !types.is_empty() {
        lines.push((
            module_file_name(RUNTIME_MODULE),
            values.iter().map(|name| (*name).to_owned()).collect(),
            types.iter().map(|name| (*name).to_owned()).collect(),
        ));
    }
    lines.sort();
    if !lines.is_empty() {
        out.push('\n');
    }
    for (file_name, values, types) in &lines {
        let mut values = values.clone();
        values.sort();
        let mut types = types.clone();
        types.sort();
        let named: Vec<String> = values
            .into_iter()
            .chain(types.into_iter().map(|name| format!("type {name}")))
            .collect();
        let _ = writeln!(
            out,
            "import {{{names}}} from \"./{file_name}\";",
            names = named.join(", ")
        );
    }
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

// ---------------------------------------------------------------------------
// Command surface
// ---------------------------------------------------------------------------

/// The constant naming one wire kind, qualified by the surface that defines it.
///
/// Two protocols may spell one kind the same way and mean different things:
/// `automonique.admin` and `automonique.runs` both answer `refused`, and the
/// bodies differ. The barrel re-exports every module with `export *`, so an
/// unqualified `REFUSED_RESPONSE_KIND` in each would be ambiguous for every
/// consumer — which is exactly what the duplicate-name gate in
/// `tests/codegen.rs` reported when this surface was first generated.
fn kind_constant(surface: &CommandSurface, kind: &str, role: &str) -> String {
    format!(
        "{surface}_{kind}_{role}_KIND",
        surface = surface.name.to_uppercase(),
        kind = kind.to_uppercase(),
        role = role.to_uppercase()
    )
}

/// Emit a `readonly string[]` of wire names.
fn emit_name_list(out: &mut String, name: &str, doc: &str, values: &[String]) {
    let mut sorted = values.to_vec();
    sorted.sort();
    let _ = writeln!(out, "\n/** {doc} */");
    let _ = writeln!(out, "export const {name}: readonly string[] = [");
    for value in &sorted {
        let _ = writeln!(out, "  \"{value}\",");
    }
    out.push_str("];\n");
}

/// Emit the shared request encoder.
///
/// Framing is excluded and says so: these bytes are one canonical payload, and
/// the length prefix belongs to whatever writes them to a socket. A client that
/// framed them here and again at the transport would be refused by a daemon
/// reading a length that is not a length.
fn emit_request_encoder(out: &mut String, surface: &CommandSurface) {
    let CommandSurface {
        name,
        protocol,
        protocol_constant,
        request_id_type,
        max_message_bytes_constant,
        oversize_category,
        field_invalid_category,
        field_grammar_category,
        ..
    } = surface;
    let version = version_constant(surface);
    let _ = write!(
        out,
        "\n/**\n \
         * Build one canonical request payload for `{protocol}`, version {major}.\n \
         *\n \
         * The length-delimited framing this protocol travels under is not applied\n \
         * here: these are payload bytes, and the prefix belongs to the transport\n \
         * that writes them. This package has no transport.\n \
         *\n \
         * The correlation identifier is re-validated rather than trusted, because a\n \
         * brand exists only in the type checker and an untyped caller reaches this\n \
         * function with anything at all.\n \
         */\n\
         export function encode{name}Request(\n  \
         request_id: {request_id_type},\n  \
         kind: string,\n  \
         entries: readonly (readonly [string, JsonValue])[],\n\
         ): Uint8Array {{\n  \
         const payload = encodeMessage({{\n    \
         envelope: {{\n      \
         protocol: {protocol_constant},\n      \
         version: {version},\n      \
         requestId: refuseField({field_invalid_category}, {field_grammar_category}, () =>\n        \
         {request_id_type}(request_id),\n      \
         ),\n      \
         kind,\n    \
         }},\n    \
         body: {{kind: \"object\", entries}},\n  \
         }});\n  \
         if (payload.length > {max_message_bytes_constant}) {{\n    \
         throw new RefusalError(\n      \
         {oversize_category},\n      \
         `canonical payload is ${{payload.length}} bytes; maximum is \
         ${{{max_message_bytes_constant}}}`,\n    \
         );\n  \
         }}\n  \
         return payload;\n\
         }}\n",
        major = surface.version,
    );
}

/// Emit one request: its kind, its body type, and the builder that encodes it.
fn emit_request(out: &mut String, surface: &CommandSurface, request: &RequestCommand) {
    let RequestCommand {
        kind,
        name,
        doc,
        fields,
    } = request;
    let mut fields = fields.clone();
    fields.sort_by(|left, right| left.name.cmp(&right.name));
    let kind_constant = kind_constant(surface, kind, "request");
    let _ = writeln!(out, "\n/** {doc} */");
    let _ = writeln!(out, "export const {kind_constant} = \"{kind}\";");

    if !fields.is_empty() {
        let _ = writeln!(out, "export interface {name}Body {{");
        for field in &fields {
            let _ = writeln!(
                out,
                "  readonly {input}: {type_name};",
                input = field.input_name,
                type_name = field.input_type()
            );
        }
        out.push_str("}\n");
        emit_name_list(
            out,
            &format!("{name}Body_FIELDS"),
            "The exact key set this command's wire body carries.",
            &fields
                .iter()
                .map(|field| field.name.clone())
                .collect::<Vec<_>>(),
        );
    }

    let argument = if fields.is_empty() {
        String::new()
    } else {
        format!(", body: {name}Body")
    };
    let _ = writeln!(
        out,
        "\nexport function encode{name}(request_id: {request_id}{argument}): Uint8Array {{",
        request_id = surface.request_id_type
    );
    if fields.is_empty() {
        // A command with no arguments carries an empty object, which is what
        // the Rust decoder requires: it refuses a nonempty body for these
        // kinds rather than ignoring what it does not expect.
        let _ = writeln!(
            out,
            "  return encode{surface}Request(request_id, {kind_constant}, []);\n}}",
            surface = surface.name
        );
        return;
    }
    // A nullable field is read into a local before it is tested. TypeScript
    // discards the narrowing of a property access inside a closure created
    // after it — `body.since` is `RunCursor | null` again inside the arrow the
    // refusal wrapper takes — while the narrowing of a `const` survives. Without
    // this the generated file does not typecheck, which is how the package
    // typecheck found it.
    let nullable: Vec<&RequestField> = fields
        .iter()
        .filter(|field| {
            matches!(
                field.value,
                RequestValue::NullableInteger { .. } | RequestValue::NullableEnumSet { .. }
            )
        })
        .collect();
    for field in &nullable {
        let _ = writeln!(
            out,
            "  const {input} = body.{input};",
            input = field.input_name
        );
    }
    let _ = writeln!(
        out,
        "  return encode{surface}Request(request_id, {kind_constant}, [",
        surface = surface.name
    );
    for field in &fields {
        let input = &field.input_name;
        // The nullable fields read the local bound above; the rest read `body`
        // directly, which keeps every other surface's output unchanged.
        let source = if nullable.iter().any(|other| other.name == field.name) {
            String::new()
        } else {
            "body.".to_owned()
        };
        let input = &format!("{source}{input}");
        let entry = match &field.value {
            RequestValue::Checked {
                type_name,
                refusal_category,
            } => format!(
                "{{kind: \"string\", value: refuse({refusal_category}, () => \
                 {type_name}({input}))}}"
            ),
            RequestValue::HexBytes {
                max_bytes_constant,
                oversize_category,
            } => format!(
                "{{kind: \"string\", value: refuse({invalid}, () => \
                 hexEncode(boundedBytes({input}, {max_bytes_constant}, {oversize_category}, \
                 {invalid})))}}",
                invalid = surface.invalid_body_category,
            ),
            RequestValue::Integer {
                type_name,
                refusal_category,
            } => format!(
                "{{kind: \"integer\", value: refuse({refusal_category}, () => \
                 {type_name}({input}))}}"
            ),
            RequestValue::NullableInteger {
                type_name,
                refusal_category,
            } => format!(
                "{input} === null\n        ? {{kind: \"null\"}}\n        : {{kind: \
                 \"integer\", value: refuse({refusal_category}, () => {type_name}({input}))}}"
            ),
            RequestValue::NullableEnumSet {
                order_constant,
                empty_category,
                repeat_category,
                unknown_category,
                ..
            } => format!(
                "{input} === null\n        ? {{kind: \"null\"}}\n        : {{\n            \
                 kind: \"array\",\n            items: orderedEnumSet({input}, {{\n              \
                 order: {order_constant},\n              empty: {empty_category},\n              \
                 repeat: {repeat_category},\n              unknown: {unknown_category},\n            \
                 }}).map((value): JsonValue => ({{kind: \"string\", value}})),\n          }}"
            ),
        };
        let _ = writeln!(out, "    [\"{name}\", {entry}],", name = field.name);
    }
    out.push_str("  ]);\n}\n");
}

/// Emit one nested body type and the decoder that reads it.
///
/// It takes a whole [`JsonValue`] rather than a field map, because a nested
/// body is a value inside its carrier's body rather than a message of its own.
/// Its own exact field set is applied here, so a summary carrying one key too
/// many is refused wherever it is nested.
fn emit_body_object(out: &mut String, surface: &CommandSurface, object: &BodyObject) {
    let BodyObject { name, doc, fields } = object;
    let mut fields = fields.clone();
    fields.sort_by(|left, right| left.name.cmp(&right.name));
    let invalid = &surface.invalid_body_category;

    let _ = writeln!(out, "\n/** {doc} */");
    let _ = writeln!(out, "export interface {name} {{");
    for field in &fields {
        let _ = writeln!(
            out,
            "  readonly {field_name}: {type_name};",
            field_name = field.name,
            type_name = response_field_type(&field.value)
        );
    }
    out.push_str("}\n");
    emit_name_list(
        out,
        &format!("{name}_FIELDS"),
        "The exact key set this nested body carries.",
        &fields
            .iter()
            .map(|field| field.name.clone())
            .collect::<Vec<_>>(),
    );

    let _ = writeln!(
        out,
        "\nexport function decode{name}(body: JsonValue): {name} {{"
    );
    let _ = writeln!(
        out,
        "  const fields = exactFields(body, {name}_FIELDS, {invalid});"
    );
    out.push_str("  return {\n");
    for field in &fields {
        let _ = writeln!(
            out,
            "    {field_name}: {value},",
            field_name = field.name,
            value = response_field_reader(surface, field)
        );
    }
    out.push_str("  };\n}\n");
}

/// The TypeScript type one decoded response field has.
fn response_field_type(value: &ResponseValue) -> String {
    match value {
        ResponseValue::Checked { type_name, .. }
        | ResponseValue::Integer { type_name, .. }
        | ResponseValue::Enum { type_name, .. }
        | ResponseValue::Object { type_name } => type_name.clone(),
        ResponseValue::NullableInteger { type_name, .. } => format!("{type_name} | null"),
        ResponseValue::Bool => "boolean".to_owned(),
        ResponseValue::ObjectArray { type_name, .. } => format!("readonly {type_name}[]"),
    }
}

/// The expression that reads one decoded response field out of a field map.
fn response_field_reader(surface: &CommandSurface, field: &ResponseField) -> String {
    let invalid = &surface.invalid_body_category;
    let name = &field.name;
    match &field.value {
        ResponseValue::Bool => format!("bodyBool(fields, \"{name}\", {invalid})"),
        ResponseValue::Checked {
            type_name,
            refusal_category,
        } => format!(
            "refuse({refusal_category}, () => {type_name}(bodyString(fields, \"{name}\", \
             {invalid})))"
        ),
        ResponseValue::Integer {
            type_name,
            refusal_category,
            unsigned,
        } => format!(
            "refuse({refusal_category}, () => {type_name}({reader}(fields, \"{name}\", \
             {invalid})))",
            reader = if *unsigned {
                "bodyUnsigned"
            } else {
                "bodyInteger"
            }
        ),
        ResponseValue::NullableInteger {
            type_name,
            refusal_category,
        } => format!(
            "mapNullable(bodyIntegerOrNull(fields, \"{name}\", {invalid}), (value) =>\n      \
             refuse({refusal_category}, () => {type_name}(value)),\n    )"
        ),
        ResponseValue::Enum {
            type_name,
            unknown_category,
        } => format!(
            "refuse({unknown_category}, () => decode{type_name}(bodyString(fields, \"{name}\", \
             {invalid})))"
        ),
        ResponseValue::Object { type_name } => {
            format!("decode{type_name}(bodyValue(fields, \"{name}\", {invalid}))")
        }
        ResponseValue::ObjectArray {
            type_name,
            max_items_constant,
            oversize_category,
        } => format!(
            "bodyArray(fields, \"{name}\", {invalid}, {max_items_constant}, \
             {oversize_category}).map(\n      decode{type_name},\n    )"
        ),
    }
}

/// Emit one response: its kind, its decoded type, and the decoder.
///
/// The decoder takes the correlation identifier separately because it is an
/// envelope field rather than a body one. Keeping the two apart is what lets
/// the emitted `_BODY_FIELDS` array stay exactly the wire body's key set, which
/// is the set the Rust decoder requires and refuses anything else against.
fn emit_response(out: &mut String, surface: &CommandSurface, response: &ResponseDecoder) {
    let ResponseDecoder {
        kind,
        name,
        doc,
        fields,
    } = response;
    let mut fields = fields.clone();
    fields.sort_by(|left, right| left.name.cmp(&right.name));
    let invalid = &surface.invalid_body_category;
    let request_id = &surface.request_id_type;
    let kind_constant = kind_constant(surface, kind, "response");

    let _ = writeln!(out, "\n/** {doc} */");
    let _ = writeln!(out, "export const {kind_constant} = \"{kind}\";");
    let _ = writeln!(out, "export interface {name} {{");
    let mut declarations: Vec<(String, String)> = fields
        .iter()
        .map(|field| (field.name.clone(), response_field_type(&field.value)))
        .collect();
    declarations.push(("request_id".to_owned(), request_id.clone()));
    declarations.sort();
    for (field, type_name) in &declarations {
        let _ = writeln!(out, "  readonly {field}: {type_name};");
    }
    out.push_str("}\n");
    emit_name_list(
        out,
        &format!("{name}_BODY_FIELDS"),
        "The exact key set this response's wire body carries; the correlation \
         identifier is not among them, because it travels in the envelope.",
        &fields
            .iter()
            .map(|field| field.name.clone())
            .collect::<Vec<_>>(),
    );

    let _ = writeln!(
        out,
        "\nexport function decode{name}(request_id: {request_id}, body: JsonValue): {name} {{"
    );
    let binding = if fields.is_empty() {
        ""
    } else {
        "const fields = "
    };
    let _ = writeln!(
        out,
        "  {binding}exactFields(body, {name}_BODY_FIELDS, {invalid});"
    );
    out.push_str("  return {\n");
    let mut entries: Vec<(String, String)> = fields
        .iter()
        .map(|field| (field.name.clone(), response_field_reader(surface, field)))
        .collect();
    entries.push(("request_id".to_owned(), "request_id".to_owned()));
    entries.sort();
    for (field, value) in &entries {
        let _ = writeln!(out, "    {field}: {value},");
    }
    out.push_str("  };\n}\n");
}

/// The constant naming the major version this surface speaks.
fn version_constant(surface: &CommandSurface) -> String {
    format!("{}_PROTOCOL_VERSION", surface.name.to_uppercase())
}

/// Emit the union of decoded responses and the decoder that dispatches on kind.
fn emit_response_dispatch(out: &mut String, surface: &CommandSurface) {
    let CommandSurface {
        name,
        protocol_constant,
        request_id_type,
        unknown_kind_category,
        field_invalid_category,
        field_grammar_category,
        ..
    } = surface;
    let screaming = name.to_uppercase();
    let undecoded_list = format!("{screaming}_RESPONSE_KINDS_NOT_DECODED");
    let undecoded_type = format!("Undecoded{name}ResponseKind");
    let guard = format!("isUndecoded{name}ResponseKind");
    let union = format!("{name}Response");
    let version = version_constant(surface);

    let mut kinds = surface.response_kinds_not_decoded.clone();
    kinds.sort();
    let literals: Vec<String> = kinds.iter().map(|kind| format!("\"{kind}\"")).collect();
    let _ = write!(
        out,
        "\n/**\n \
         * Kinds this protocol version defines that this file does not decode.\n \
         *\n \
         * They are neither refused nor guessed at: a peer that sent one sent something\n \
         * defined, and a client told otherwise might act on the lie. The body is not\n \
         * handed back, because nothing here has validated it.\n \
         */\n\
         export const {undecoded_list} = [{list}] as const;\n\
         export type {undecoded_type} = (typeof {undecoded_list})[number];\n\
         export function {guard}(value: string): value is {undecoded_type} {{\n  \
         return ({undecoded_list} as readonly string[]).includes(value);\n\
         }}\n",
        list = literals.join(", ")
    );

    let mut arms: Vec<String> = surface
        .responses
        .iter()
        .map(|response| {
            format!(
                "  | {{readonly kind: \"{kind}\"; readonly value: {name}}}",
                kind = response.kind,
                name = response.name
            )
        })
        .chain(std::iter::once(format!(
            "  | {{readonly kind: \"undecoded\"; readonly request_id: {request_id_type}; \
             readonly response_kind: {undecoded_type}}}"
        )))
        .collect();
    arms.sort();
    let _ = write!(
        out,
        "\n/** Every response this file can hand a caller. */\nexport type {union} =\n{arms};\n",
        arms = arms.join("\n")
    );
    let _ = write!(
        out,
        "\nexport function assertNever{union}(value: never): never {{\n  \
         throw new ValidationError(\"{union}\", `unhandled variant: ${{JSON.stringify(value)}}`);\n\
         }}\n"
    );

    let _ = write!(
        out,
        "\n/**\n \
         * Decode one canonical response payload.\n \
         *\n \
         * The payload is the framed transport's payload, without its length prefix.\n \
         * The envelope is admitted first and on both axes: a name this file does not\n \
         * implement and a major version outside its range are different refusals, and\n \
         * neither is downgraded into the other.\n \
         */\n\
         export function decode{union}(payload: Uint8Array): {union} {{\n  \
         const message = decodeMessageAdmitted(payload, [\n    \
         {{protocol: {protocol_constant}, minVersion: {version}, maxVersion: {version}}},\n  \
         ]);\n  \
         const request_id = refuseField({field_invalid_category}, {field_grammar_category}, () =>\n    \
         {request_id_type}(message.envelope.requestId),\n  \
         );\n  \
         const kind = message.envelope.kind;\n  \
         if ({guard}(kind)) {{\n    \
         return {{kind: \"undecoded\", request_id, response_kind: kind}};\n  \
         }}\n  \
         switch (kind) {{\n"
    );
    let mut responses = surface.responses.clone();
    responses.sort();
    for response in &responses {
        let _ = write!(
            out,
            "    case {constant}:\n      \
             return {{kind: {constant}, value: decode{name}(request_id, message.body)}};\n",
            constant = kind_constant(surface, &response.kind, "response"),
            name = response.name
        );
    }
    let _ = write!(
        out,
        "    default:\n      \
         throw new RefusalError(\n        \
         {unknown_kind_category},\n        \
         \"message kind is not defined by this protocol version\",\n      \
         );\n  \
         }}\n\
         }}\n"
    );
}

/// Emit a whole command surface.
fn emit_command_surface(out: &mut String, surface: &CommandSurface) {
    let _ = writeln!(
        out,
        "\n/** The only major version of this protocol these helpers speak. */"
    );
    let _ = writeln!(
        out,
        "export const {} = {};",
        version_constant(surface),
        surface.version
    );

    let mut categories = surface.categories.clone();
    categories.sort_by(|left, right| left.name.cmp(&right.name));
    for constant in &categories {
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

    // Before the messages that carry them: a response decoder names its nested
    // decoders, and a reader following the file top to bottom meets each one
    // where it is defined rather than where it is used.
    let mut objects = surface.body_objects.clone();
    objects.sort_by(|left, right| left.name.cmp(&right.name));
    for object in &objects {
        emit_body_object(out, surface, object);
    }

    if !surface.requests.is_empty() {
        emit_request_encoder(out, surface);
        let mut requests = surface.requests.clone();
        requests.sort();
        for request in &requests {
            emit_request(out, surface, request);
        }
        emit_name_list(
            out,
            &format!(
                "{}_REQUEST_KINDS_NOT_GENERATED",
                surface.name.to_uppercase()
            ),
            "Command kinds this protocol version defines that no builder above \
             produces. A client needing one of these builds it by hand or waits \
             for the generator to describe it.",
            &surface.request_kinds_not_generated,
        );
    }

    if !surface.responses.is_empty() {
        let mut responses = surface.responses.clone();
        responses.sort();
        for response in &responses {
            emit_response(out, surface, response);
        }
        emit_response_dispatch(out, surface);
    }
}

/// Emit one generated file.
///
/// Output is a pure function of the input: every collection is sorted and no
/// clock, environment or allocation address reaches the text.
#[must_use]
pub fn emit_module(module: &GeneratedModule) -> String {
    let mut out = String::new();
    emit_banner(&mut out, &module.source, &module.doc);

    emit_imports(&mut out, module);

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

    if let Some(surface) = &module.command_surface {
        emit_command_surface(&mut out, surface);
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
