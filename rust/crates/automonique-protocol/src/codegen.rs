// SPDX-License-Identifier: Elastic-2.0

//! `R1-11` spike: generate TypeScript from a Rust-owned schema description.
//!
//! This exists to answer one question before `R8B` commits the SDK to
//! generation: can Rust-derived schemas produce TypeScript wire types,
//! validators and clients *reproducibly*, without losing const bounds,
//! discriminated unions, branded identifiers or unknown-event tolerance?
//!
//! It is a spike, not a shipped generator. The slice is deliberately hostile
//! rather than representative, and the recorded verdict may be negative.
//!
//! Determinism is a property of this module: every collection is emitted in
//! sorted order and nothing time-dependent, host-dependent or randomly ordered
//! reaches the output. A generator that embeds a build time cannot satisfy the
//! zero-diff regeneration rule, so there is no way to ask this one for a
//! timestamp.

use core::fmt::Write as _;

use crate::schema::EnumSensitivity;

/// A branded identifier domain in the generated surface.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BrandedId {
    /// TypeScript type name.
    pub name: String,
    /// Maximum UTF-8 byte length.
    pub max_bytes: usize,
}

/// A bounded string field.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BoundedString {
    /// TypeScript type name.
    pub name: String,
    /// Maximum UTF-8 byte length.
    pub max_bytes: usize,
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
            },
            BrandedId {
                name: "TurnId".to_owned(),
                max_bytes: 64,
            },
        ],
        bounded_strings: vec![BoundedString {
            name: "MessageKind".to_owned(),
            max_bytes: 64,
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
        let _ = write!(
            out,
            "\n/** Branded identifier, at most {} UTF-8 bytes. */\n\
             export type {name} = string & {{readonly __brand: \"{name}\"}};\n\
             export const {name}_MAX_BYTES = {max};\n\
             export function {name}(value: string): {name} {{\n  \
             if (value.length === 0) throw new ValidationError(\"{name}\", \"empty\");\n  \
             if (byteLength(value) > {max}) throw new ValidationError(\"{name}\", \"too_long\");\n  \
             return value as {name};\n\
             }}\n",
            id.max_bytes,
            name = id.name,
            max = id.max_bytes
        );
    }

    let mut strings = schema.bounded_strings.clone();
    strings.sort();
    for bounded in &strings {
        let _ = write!(
            out,
            "\n/** Bounded string, at most {max} UTF-8 bytes. */\n\
             export type {name} = string & {{readonly __brand: \"{name}\"}};\n\
             export const {name}_MAX_BYTES = {max};\n\
             export function {name}(value: string): {name} {{\n  \
             if (value.length === 0) throw new ValidationError(\"{name}\", \"empty\");\n  \
             if (byteLength(value) > {max}) throw new ValidationError(\"{name}\", \"too_long\");\n  \
             return value as {name};\n\
             }}\n",
            name = bounded.name,
            max = bounded.max_bytes
        );
    }

    let mut integers = schema.bounded_integers.clone();
    integers.sort();
    for integer in &integers {
        let _ = write!(
            out,
            "\n/** Bounded integer in [{min}, {max}]. */\n\
             export type {name} = bigint & {{readonly __brand: \"{name}\"}};\n\
             export const {name}_MIN = {min}n;\n\
             export const {name}_MAX = {max}n;\n\
             export function {name}(value: bigint): {name} {{\n  \
             if (value < {min}n || value > {max}n) throw new ValidationError(\"{name}\", \"out_of_range\");\n  \
             return value as {name};\n\
             }}\n",
            name = integer.name,
            min = integer.min,
            max = integer.max
        );
    }

    let mut unions = schema.unions.clone();
    unions.sort();
    for union in &unions {
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

    let mut enums = schema.enums.clone();
    enums.sort_by(|left, right| left.name.cmp(&right.name));
    for generated in &enums {
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
