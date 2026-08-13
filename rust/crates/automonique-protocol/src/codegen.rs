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
use crate::primitives::ValueError;
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

/// The `automonique.admin` command surface.
pub const ADMIN_COMMAND_MODULE: &str = "admin-command";

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
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RequestValue {
    /// A checked string type generated in this module.
    ///
    /// Its constructor is re-applied when the request is built, so an untyped
    /// caller — the only kind a brand cannot reach, since brands erase at
    /// runtime — is refused rather than allowed to put an overlong value on
    /// the wire.
    Checked(String),
    /// Opaque bytes carried as lowercase hexadecimal under a byte bound.
    HexBytes {
        /// Generated constant naming the bound, in raw rather than hex bytes.
        max_bytes_constant: String,
        /// Refusal category answered above the bound.
        oversize_category: String,
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
    fn input_type(&self) -> &str {
        match &self.value {
            RequestValue::Checked(name) => name,
            RequestValue::HexBytes { .. } => "Uint8Array",
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
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResponseValue {
    /// A checked string type generated in this module.
    Checked(String),
    /// A bounded integer type generated in this module.
    Integer(String),
    /// A boolean, which the wire carries as `true` or `false` and nothing else.
    Bool,
}

/// One field of a response body.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ResponseField {
    /// Wire key.
    pub name: String,
    /// How it is decoded.
    pub value: ResponseValue,
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
fn checked_field(name: &str, type_name: &str) -> RequestField {
    RequestField {
        name: name.to_owned(),
        input_name: name.to_owned(),
        value: RequestValue::Checked(type_name.to_owned()),
    }
}

/// A response field carrying a durable row identity.
fn row_id_field(name: &str) -> ResponseField {
    ResponseField {
        name: name.to_owned(),
        value: ResponseValue::Integer(DURABLE_ROW_ID.to_owned()),
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
                        checked_field("idempotency_key", "RunSubmissionKey"),
                        checked_field("spec_digest", "SpecDigest"),
                    ],
                },
                RequestCommand {
                    kind: "pause_intake".to_owned(),
                    name: "PauseIntake".to_owned(),
                    doc: "Durably close intake for this generation, naming the deciding operator \
                          and the cause."
                        .to_owned(),
                    fields: vec![
                        checked_field("actor", "IntakeActor"),
                        checked_field("reason", "IntakeReason"),
                    ],
                },
                RequestCommand {
                    kind: "resume_intake".to_owned(),
                    name: "ResumeIntake".to_owned(),
                    doc: "Reopen intake, naming the operator who decided to.".to_owned(),
                    fields: vec![checked_field("actor", "IntakeActor")],
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
                    fields: vec![row_id_field("pause_id"), row_id_field("revision")],
                },
                ResponseDecoder {
                    kind: "intake_resumed".to_owned(),
                    name: "IntakeResumed".to_owned(),
                    doc: "A durable pause was closed and intake reopened. The pause row is \
                          retained, not deleted."
                        .to_owned(),
                    fields: vec![row_id_field("pause_id"), row_id_field("revision")],
                },
                ResponseDecoder {
                    kind: "refused".to_owned(),
                    name: "Refused".to_owned(),
                    doc: "The request was definitely refused before a successful mutation."
                        .to_owned(),
                    fields: vec![ResponseField {
                        name: "category".to_owned(),
                        value: ResponseValue::Checked("AdminRefusalCategory".to_owned()),
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
                            value: ResponseValue::Checked("RunId".to_owned()),
                        },
                        ResponseField {
                            name: "spec_digest".to_owned(),
                            value: ResponseValue::Checked("SpecDigest".to_owned()),
                        },
                        row_id_field("submission_id"),
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

/// Every maintained module, in file-name order.
#[must_use]
pub fn maintained_modules() -> Vec<GeneratedModule> {
    let mut modules = vec![
        runtime_module(),
        doctor_module(),
        admin_status_module(),
        admin_command_module(),
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
        if request_fields().any(|field| matches!(field.value, RequestValue::Checked(_))) {
            names.push("refuse");
        }
        if request_fields().any(|field| matches!(field.value, RequestValue::HexBytes { .. })) {
            names.extend(["boundedBytes", "hexEncode"]);
        }
        if !surface.responses.is_empty() {
            names.extend(["decodeMessageAdmitted", "exactFields", "refuse"]);
            types.push("JsonValue");
        }
        for field in surface
            .responses
            .iter()
            .flat_map(|response| &response.fields)
        {
            names.push(match field.value {
                ResponseValue::Bool => "bodyBool",
                ResponseValue::Checked(_) => "bodyString",
                ResponseValue::Integer(_) => "bodyInteger",
            });
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
    let kind_constant = format!("{}_REQUEST_KIND", kind.to_uppercase());
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
    let _ = writeln!(
        out,
        "  return encode{surface}Request(request_id, {kind_constant}, [",
        surface = surface.name
    );
    for field in &fields {
        let value = match &field.value {
            RequestValue::Checked(type_name) => {
                format!("{type_name}(body.{input})", input = field.input_name)
            }
            RequestValue::HexBytes {
                max_bytes_constant,
                oversize_category,
            } => format!(
                "hexEncode(boundedBytes(body.{input}, {max_bytes_constant}, {oversize_category}, \
                 {invalid}))",
                input = field.input_name,
                invalid = surface.invalid_body_category,
            ),
        };
        let _ = writeln!(
            out,
            "    [\"{name}\", {{kind: \"string\", value: refuse({invalid}, () => {value})}}],",
            name = field.name,
            invalid = surface.invalid_body_category,
        );
    }
    out.push_str("  ]);\n}\n");
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
    let kind_constant = format!("{}_RESPONSE_KIND", kind.to_uppercase());

    let _ = writeln!(out, "\n/** {doc} */");
    let _ = writeln!(out, "export const {kind_constant} = \"{kind}\";");
    let _ = writeln!(out, "export interface {name} {{");
    let mut declarations: Vec<(String, String)> = fields
        .iter()
        .map(|field| {
            let type_name = match &field.value {
                ResponseValue::Checked(name) | ResponseValue::Integer(name) => name.clone(),
                ResponseValue::Bool => "boolean".to_owned(),
            };
            (field.name.clone(), type_name)
        })
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
        .map(|field| {
            let read = |reader: &str| format!("{reader}(fields, \"{}\", {invalid})", field.name);
            let value = match &field.value {
                ResponseValue::Bool => read("bodyBool"),
                ResponseValue::Checked(type_name) => format!(
                    "refuse({invalid}, () => {type_name}({}))",
                    read("bodyString")
                ),
                ResponseValue::Integer(type_name) => format!(
                    "refuse({invalid}, () => {type_name}({}))",
                    read("bodyInteger")
                ),
            };
            (field.name.clone(), value)
        })
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
            constant = format!("{}_RESPONSE_KIND", response.kind.to_uppercase()),
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
