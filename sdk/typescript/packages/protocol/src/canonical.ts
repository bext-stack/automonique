// SPDX-License-Identifier: Apache-2.0

// Canonical JSON for the Automonique local protocol.
//
// This mirrors `rust/crates/automonique-protocol/src/wire.rs`. Rust is the wire
// source of truth: where the two disagree the fix belongs in whichever side is
// wrong, never in the shared fixture corpus.
//
// Integers are `bigint` because the wire carries signed 64-bit values and a
// JavaScript `number` cannot hold them exactly. Encoding a value that decoded
// as `9223372036854775807` must reproduce those digits.

export const MAX_NESTING_DEPTH = 32;
export const MAX_JSON_STRING_BYTES = 64 * 1024;
export const MAX_JSON_ENTRIES = 4096;
export const MAX_PROTOCOL_NAME_BYTES = 64;
export const MAX_REQUEST_ID_BYTES = 128;
export const MAX_MESSAGE_KIND_BYTES = 64;
export const MAX_ENUM_VALUE_BYTES = 64;
export const LENGTH_PREFIX_BYTES = 4;
export const MAX_FRAME_BYTES = 8 * 1024 * 1024;

const I64_MIN = -(2n ** 63n);
const I64_MAX = 2n ** 63n - 1n;

/**
 * Stable refusal categories, spelled exactly as Rust's `CodecError::category`.
 *
 * The union below is derived from this array rather than written twice, so a
 * category cannot exist as a type without existing as a value the conformance
 * runner can compare a corpus entry against.
 */
export const WIRE_CATEGORIES = [
  "duplicate_key",
  "empty_frame",
  "field_grammar",
  "field_invalid",
  "frame_too_large",
  "integer_out_of_range",
  "invalid_json_value",
  "malformed_json",
  "missing_field",
  "nesting_too_deep",
  "non_canonical_json",
  "too_many_entries",
  "trailing_data",
  "unknown_enum_value",
  "unknown_protocol",
  "unsupported_version",
] as const;

export type WireCategory = (typeof WIRE_CATEGORIES)[number];

/** Whether a spelling names a category this implementation can produce. */
export function isWireCategory(value: string): value is WireCategory {
  return (WIRE_CATEGORIES as readonly string[]).includes(value);
}

export class WireError extends Error {
  readonly category: WireCategory;

  constructor(category: WireCategory, detail?: string) {
    super(detail === undefined ? category : `${category}: ${detail}`);
    this.name = "WireError";
    this.category = category;
  }
}

export type JsonValue =
  | {readonly kind: "null"}
  | {readonly kind: "bool"; readonly value: boolean}
  | {readonly kind: "integer"; readonly value: bigint}
  | {readonly kind: "string"; readonly value: string}
  | {readonly kind: "array"; readonly items: readonly JsonValue[]}
  | {readonly kind: "object"; readonly entries: readonly (readonly [string, JsonValue])[]};

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder("utf-8", {fatal: true});

/** Whether a JavaScript string can be encoded without replacing lone surrogates. */
export function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function utf8(value: string): Uint8Array {
  if (!isWellFormedUnicode(value)) throw new WireError("malformed_json", "lone surrogate");
  return encoder.encode(value);
}

/** Compare two keys by UTF-8 byte order, which is not JS string order. */
function compareKeys(left: string, right: string): number {
  const a = utf8(left);
  const b = utf8(right);
  const shared = Math.min(a.length, b.length);
  for (let index = 0; index < shared; index += 1) {
    const x = a[index] ?? 0;
    const y = b[index] ?? 0;
    if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return a.length - b.length;
}

function writeCanonicalString(value: string, out: number[]): void {
  out.push(0x22);
  for (const character of value) {
    switch (character) {
      case '"':
        out.push(0x5c, 0x22);
        continue;
      case "\\":
        out.push(0x5c, 0x5c);
        continue;
      case "\b":
        out.push(0x5c, 0x62);
        continue;
      case "\f":
        out.push(0x5c, 0x66);
        continue;
      case "\n":
        out.push(0x5c, 0x6e);
        continue;
      case "\r":
        out.push(0x5c, 0x72);
        continue;
      case "\t":
        out.push(0x5c, 0x74);
        continue;
      default:
        break;
    }
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20) {
      for (const byte of utf8(`\\u${code.toString(16).padStart(4, "0")}`)) {
        out.push(byte);
      }
    } else {
      for (const byte of utf8(character)) {
        out.push(byte);
      }
    }
  }
  out.push(0x22);
}

function writeCanonical(value: JsonValue, out: number[]): void {
  switch (value.kind) {
    case "null":
      for (const byte of utf8("null")) out.push(byte);
      return;
    case "bool":
      for (const byte of utf8(value.value ? "true" : "false")) out.push(byte);
      return;
    case "integer":
      for (const byte of utf8(value.value.toString())) out.push(byte);
      return;
    case "string":
      writeCanonicalString(value.value, out);
      return;
    case "array": {
      out.push(0x5b);
      value.items.forEach((item, index) => {
        if (index > 0) out.push(0x2c);
        writeCanonical(item, out);
      });
      out.push(0x5d);
      return;
    }
    case "object": {
      const ordered = [...value.entries].sort((left, right) => compareKeys(left[0], right[0]));
      out.push(0x7b);
      ordered.forEach(([key, entry], index) => {
        if (index > 0) out.push(0x2c);
        writeCanonicalString(key, out);
        out.push(0x3a);
        writeCanonical(entry, out);
      });
      out.push(0x7d);
      return;
    }
  }
}

export function toCanonicalBytes(value: JsonValue): Uint8Array {
  const out: number[] = [];
  writeCanonical(value, out);
  return Uint8Array.from(out);
}

export function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

// Length-delimited framing, mirroring `rust/crates/automonique-protocol/src/codec.rs`.
//
// The prefix is fixed-width and big-endian. Newline framing is deliberately
// absent: a delimiter that can appear inside a payload is not a delimiter.

/** Outcome of decoding one frame from a byte slice. */
export type FrameDecode =
  | {
      /** A complete frame was available. */
      readonly kind: "frame";
      /** Payload bytes, borrowed from the input. */
      readonly payload: Uint8Array;
      /** Bytes the caller should consume, including the length prefix. */
      readonly consumed: number;
    }
  | {
      /** The frame is incomplete; nothing was consumed. */
      readonly kind: "need_more";
      /** Further bytes required before the frame can be decoded. */
      readonly additional: number;
    };

/**
 * Append a length-delimited frame.
 *
 * Throws `empty_frame` for an empty payload and `frame_too_large` above
 * `MAX_FRAME_BYTES`.
 */
export function encodeFrame(payload: Uint8Array): Uint8Array {
  if (payload.length === 0) {
    throw new WireError("empty_frame", "frame declares a zero-length payload");
  }
  if (payload.length > MAX_FRAME_BYTES) {
    throw new WireError("frame_too_large", `maximum is ${MAX_FRAME_BYTES}`);
  }
  const out = new Uint8Array(LENGTH_PREFIX_BYTES + payload.length);
  const length = payload.length;
  out[0] = (length >>> 24) & 0xff;
  out[1] = (length >>> 16) & 0xff;
  out[2] = (length >>> 8) & 0xff;
  out[3] = length & 0xff;
  out.set(payload, LENGTH_PREFIX_BYTES);
  return out;
}

/**
 * Decode the first frame without consuming a partial one.
 *
 * The declared length is validated against `MAX_FRAME_BYTES` before it is used
 * for anything, and the payload is a view rather than a copy, so an oversized
 * prefix can never drive an allocation.
 */
export function decodeFrame(input: Uint8Array): FrameDecode {
  if (input.length < LENGTH_PREFIX_BYTES) {
    return {kind: "need_more", additional: LENGTH_PREFIX_BYTES - input.length};
  }
  // Big-endian, and the top byte is scaled rather than shifted because a shift
  // would be evaluated as a signed 32-bit operation.
  const declared =
    (input[0] ?? 0) * 0x1000000 +
    ((input[1] ?? 0) << 16) +
    ((input[2] ?? 0) << 8) +
    (input[3] ?? 0);
  if (declared === 0) {
    throw new WireError("empty_frame", "frame declares a zero-length payload");
  }
  if (declared > MAX_FRAME_BYTES) {
    throw new WireError("frame_too_large", `declared ${declared}, maximum ${MAX_FRAME_BYTES}`);
  }
  const total = LENGTH_PREFIX_BYTES + declared;
  if (input.length < total) {
    return {kind: "need_more", additional: total - input.length};
  }
  return {kind: "frame", payload: input.subarray(LENGTH_PREFIX_BYTES, total), consumed: total};
}

class Parser {
  private position = 0;
  private depth = 0;
  private readonly text: string;

  constructor(text: string) {
    this.text = text;
  }

  private peek(): string | undefined {
    return this.text[this.position];
  }

  /**
   * Whitespace is consumed here and refused by the canonical round-trip
   * comparison, so `{"a": 1}` reports `non_canonical_json` rather than a
   * syntax error.
   */
  skipWhitespace(): void {
    while (
      this.position < this.text.length &&
      (this.text[this.position] === " " ||
        this.text[this.position] === "\t" ||
        this.text[this.position] === "\n" ||
        this.text[this.position] === "\r")
    ) {
      this.position += 1;
    }
  }

  atEnd(): boolean {
    return this.position === this.text.length;
  }

  private expect(character: string): void {
    if (this.peek() !== character) {
      throw new WireError("malformed_json", `expected ${character}`);
    }
    this.position += 1;
  }

  private literal(word: string): void {
    if (!this.text.startsWith(word, this.position)) {
      throw new WireError("malformed_json", `expected ${word}`);
    }
    this.position += word.length;
  }

  parseValue(): JsonValue {
    const next = this.peek();
    if (next === undefined) throw new WireError("malformed_json", "no value");
    switch (next) {
      case "n":
        this.literal("null");
        return {kind: "null"};
      case "t":
        this.literal("true");
        return {kind: "bool", value: true};
      case "f":
        this.literal("false");
        return {kind: "bool", value: false};
      case '"':
        return {kind: "string", value: this.parseString()};
      case "[":
        return this.parseArray();
      case "{":
        return this.parseObject();
      default:
        if (next === "-" || (next >= "0" && next <= "9")) return this.parseInteger();
        throw new WireError("malformed_json", "unexpected character");
    }
  }

  private parseString(): string {
    this.expect('"');
    let value = "";
    let bytes = 0;
    const append = (fragment: string, fragmentBytes: number): void => {
      value += fragment;
      bytes += fragmentBytes;
      if (bytes > MAX_JSON_STRING_BYTES) {
        throw new WireError("field_invalid", "string exceeds its ceiling");
      }
    };
    for (;;) {
      const character = this.peek();
      if (character === undefined) throw new WireError("malformed_json", "unterminated string");
      this.position += 1;
      if (character === '"') break;
      if (character === "\\") {
        const escape = this.peek();
        if (escape === undefined) throw new WireError("malformed_json", "dangling escape");
        this.position += 1;
        switch (escape) {
          case '"':
            append('"', 1);
            break;
          case "\\":
            append("\\", 1);
            break;
          case "/":
            append("/", 1);
            break;
          case "b":
            append("\b", 1);
            break;
          case "f":
            append("\f", 1);
            break;
          case "n":
            append("\n", 1);
            break;
          case "r":
            append("\r", 1);
            break;
          case "t":
            append("\t", 1);
            break;
          case "u": {
            const hex = this.text.slice(this.position, this.position + 4);
            if (hex.length !== 4 || !/^[0-9a-fA-F]{4}$/.test(hex)) {
              throw new WireError("malformed_json", "bad unicode escape");
            }
            const code = Number.parseInt(hex, 16);
            // Rust refuses a lone surrogate; match that rather than producing
            // an unpaired code unit.
            if (code >= 0xd800 && code <= 0xdfff) {
              throw new WireError("malformed_json", "lone surrogate");
            }
            this.position += 4;
            append(String.fromCodePoint(code), code <= 0x7f ? 1 : code <= 0x7ff ? 2 : 3);
            break;
          }
          default:
            throw new WireError("malformed_json", "unknown escape");
        }
      } else {
        const codeUnit = character.charCodeAt(0);
        if (codeUnit < 0x20) throw new WireError("malformed_json", "raw control character");
        if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
          const low = this.text.charCodeAt(this.position);
          if (!(low >= 0xdc00 && low <= 0xdfff)) {
            throw new WireError("malformed_json", "lone surrogate");
          }
          append(character + this.text[this.position], 4);
          this.position += 1;
        } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
          throw new WireError("malformed_json", "lone surrogate");
        } else {
          append(character, codeUnit <= 0x7f ? 1 : codeUnit <= 0x7ff ? 2 : 3);
        }
      }
    }
    return value;
  }

  private parseInteger(): JsonValue {
    const start = this.position;
    if (this.peek() === "-") this.position += 1;
    const digitsStart = this.position;
    while (this.position < this.text.length) {
      const character = this.text[this.position] ?? "";
      if (character < "0" || character > "9") break;
      this.position += 1;
    }
    if (this.position === digitsStart) throw new WireError("malformed_json", "no digits");
    const next = this.peek();
    if (next === "." || next === "e" || next === "E") {
      throw new WireError("invalid_json_value", "json_number");
    }
    const digits = this.text.slice(digitsStart, this.position);
    if (digits.length > 1 && digits.startsWith("0")) {
      throw new WireError("non_canonical_json", "leading zero");
    }
    const text = this.text.slice(start, this.position);
    if (text === "-0") throw new WireError("non_canonical_json", "negative zero");
    const value = BigInt(text);
    if (value < I64_MIN || value > I64_MAX) {
      throw new WireError("integer_out_of_range", "outside signed 64-bit");
    }
    return {kind: "integer", value};
  }

  private enter(): void {
    if (this.depth === MAX_NESTING_DEPTH) {
      throw new WireError("nesting_too_deep", `maximum ${MAX_NESTING_DEPTH}`);
    }
    this.depth += 1;
  }

  private exit(): void {
    this.depth = Math.max(0, this.depth - 1);
  }

  private parseArray(): JsonValue {
    this.enter();
    this.expect("[");
    const items: JsonValue[] = [];
    this.skipWhitespace();
    if (this.peek() === "]") {
      this.position += 1;
      this.exit();
      return {kind: "array", items};
    }
    for (;;) {
      this.skipWhitespace();
      items.push(this.parseValue());
      this.skipWhitespace();
      if (items.length > MAX_JSON_ENTRIES) {
        throw new WireError("too_many_entries", `maximum ${MAX_JSON_ENTRIES}`);
      }
      const next = this.peek();
      if (next === ",") {
        this.position += 1;
      } else if (next === "]") {
        this.position += 1;
        break;
      } else {
        throw new WireError("malformed_json", "expected , or ]");
      }
    }
    this.exit();
    return {kind: "array", items};
  }

  private parseObject(): JsonValue {
    this.enter();
    this.expect("{");
    const entries: (readonly [string, JsonValue])[] = [];
    this.skipWhitespace();
    if (this.peek() === "}") {
      this.position += 1;
      this.exit();
      return {kind: "object", entries};
    }
    for (;;) {
      this.skipWhitespace();
      const key = this.parseString();
      this.skipWhitespace();
      if (entries.some(([existing]) => existing === key)) {
        throw new WireError("duplicate_key", "repeated object key");
      }
      this.expect(":");
      this.skipWhitespace();
      const value = this.parseValue();
      this.skipWhitespace();
      entries.push([key, value] as const);
      if (entries.length > MAX_JSON_ENTRIES) {
        throw new WireError("too_many_entries", `maximum ${MAX_JSON_ENTRIES}`);
      }
      const next = this.peek();
      if (next === ",") {
        this.position += 1;
      } else if (next === "}") {
        this.position += 1;
        break;
      } else {
        throw new WireError("malformed_json", "expected , or }");
      }
    }
    this.exit();
    return {kind: "object", entries};
  }
}

export function parseCanonical(payload: Uint8Array): JsonValue {
  let text: string;
  try {
    text = strictDecoder.decode(payload);
  } catch {
    throw new WireError("malformed_json", "not valid UTF-8");
  }
  const parser = new Parser(text);
  parser.skipWhitespace();
  const value = parser.parseValue();
  parser.skipWhitespace();
  if (!parser.atEnd()) throw new WireError("trailing_data", "bytes remain");
  if (!bytesEqual(toCanonicalBytes(value), payload)) {
    throw new WireError("non_canonical_json", "input is not canonical");
  }
  return value;
}

export interface Envelope {
  readonly protocol: string;
  readonly version: number;
  readonly requestId: string;
  readonly kind: string;
}

export interface Message {
  readonly envelope: Envelope;
  readonly body: JsonValue;
}

function objectField(value: JsonValue, field: string): JsonValue {
  if (value.kind !== "object") throw new WireError("invalid_json_value", field);
  const found = value.entries.find(([key]) => key === field);
  if (found === undefined) throw new WireError("missing_field", field);
  return found[1];
}

function requiredString(value: JsonValue, field: string, maxBytes: number): string {
  const entry = objectField(value, field);
  if (entry.kind !== "string") throw new WireError("invalid_json_value", field);
  if (utf8(entry.value).length > maxBytes) throw new WireError("field_invalid", field);
  return entry.value;
}

const CONTROL_CHARACTER = /\p{Cc}/u;

/**
 * The shared bounded-value rules, mirroring Rust's `validate_bounded_field`.
 *
 * These precede every field grammar, exactly as they do in Rust: an empty or
 * control-bearing spelling is a bounded-value refusal (`field_invalid`), and
 * only a spelling that clears the shared rules is judged against its grammar.
 */
export function validateBoundedField(value: string, maxBytes: number, field: string): void {
  if (maxBytes === 0) throw new WireError("field_invalid", `${field}: zero byte ceiling`);
  if (value.length === 0) throw new WireError("field_invalid", `${field}: empty`);
  if (utf8(value).length > maxBytes) throw new WireError("field_invalid", `${field}: too long`);
  if (CONTROL_CHARACTER.test(value)) {
    throw new WireError("field_invalid", `${field}: control character`);
  }
}

/** A closed enum whose values select behaviour with a security consequence. */
export interface EnumSpec<T extends string> {
  /** Field name reported when a value is refused or retained. */
  readonly field: string;
  /** Every spelling this build defines. */
  readonly known: readonly T[];
}

/** A read-only enum value, which may be one this build does not define. */
export type ReadOnlyValue<T extends string> =
  | {readonly kind: "known"; readonly value: T}
  | {readonly kind: "unknown"; readonly spelling: string};

/**
 * Decode a security-sensitive enum, failing closed on an undefined value.
 *
 * Throws `unknown_enum_value` rather than guessing a default. The return type
 * is the union of defined spellings, so a caller cannot receive a value this
 * build does not understand.
 */
export function decodeSecurityEnum<T extends string>(value: string, spec: EnumSpec<T>): T {
  const known = spec.known.find((candidate) => candidate === value);
  if (known === undefined) throw new WireError("unknown_enum_value", spec.field);
  return known;
}

/**
 * Decode a read-only enum, retaining an undefined spelling rather than failing.
 *
 * An unknown value keeps its spelling for display and logging without acquiring
 * meaning: the `unknown` branch carries no defined variant. The spelling is
 * still bounded, so an unbounded value cannot be retained.
 */
export function decodeReadOnlyEnum<T extends string>(
  value: string,
  spec: EnumSpec<T>,
): ReadOnlyValue<T> {
  const known = spec.known.find((candidate) => candidate === value);
  if (known !== undefined) return {kind: "known", value: known};
  validateBoundedField(value, MAX_ENUM_VALUE_BYTES, spec.field);
  return {kind: "unknown", spelling: value};
}

const PROTOCOL_GRAMMAR = /^[a-z][a-z0-9.]*$/;
const KIND_GRAMMAR = /^[a-z][a-z0-9_]*$/;
const REQUEST_ID_GRAMMAR = /^[A-Za-z0-9\-_.:]+$/;

export function decodeMessage(payload: Uint8Array): Message {
  const value = parseCanonical(payload);
  // The order below is the order Rust settles these fields in, because the
  // category a peer receives for a message with two faults must not depend on
  // which implementation refused it.
  const protocol = requiredString(value, "protocol", MAX_PROTOCOL_NAME_BYTES);
  const requestId = requiredString(value, "request_id", MAX_REQUEST_ID_BYTES);
  const kind = requiredString(value, "kind", MAX_MESSAGE_KIND_BYTES);
  const versionValue = objectField(value, "version");
  if (versionValue.kind !== "integer") throw new WireError("invalid_json_value", "version");
  // Outside u32 the value is not a version number at all, which is a type
  // refusal; zero is a u32 that is not a version, which is a value refusal.
  if (versionValue.value < 0n || versionValue.value > 0xffff_ffffn) {
    throw new WireError("invalid_json_value", "version");
  }
  const body = objectField(value, "body");

  validateBoundedField(protocol, MAX_PROTOCOL_NAME_BYTES, "protocol");
  if (!PROTOCOL_GRAMMAR.test(protocol) || protocol.endsWith(".") || protocol.includes("..")) {
    throw new WireError("field_grammar", "protocol");
  }
  if (versionValue.value === 0n) throw new WireError("field_invalid", "version");
  validateBoundedField(requestId, MAX_REQUEST_ID_BYTES, "request_id");
  if (!REQUEST_ID_GRAMMAR.test(requestId)) throw new WireError("field_grammar", "request_id");
  validateBoundedField(kind, MAX_MESSAGE_KIND_BYTES, "kind");
  if (!KIND_GRAMMAR.test(kind)) throw new WireError("field_grammar", "kind");

  return {
    envelope: {protocol, version: Number(versionValue.value), requestId, kind},
    body,
  };
}

/** One protocol this peer implements, with its supported major-version range. */
export interface SupportedProtocol {
  readonly protocol: string;
  readonly minVersion: number;
  readonly maxVersion: number;
}

/**
 * Decode a message and admit it against the protocols this peer implements.
 *
 * Shape is settled first, so a peer is never told its protocol is unimplemented
 * when its JSON is what is broken. Negotiation then fails closed on either
 * axis, and the axes stay distinct: `unknown_protocol` for a name no entry
 * carries, `unsupported_version` for a name that is carried at another major.
 * An empty `supported` list implements nothing and admits nothing.
 */
export function decodeMessageAdmitted(
  payload: Uint8Array,
  supported: readonly SupportedProtocol[],
): Message {
  const message = decodeMessage(payload);
  const offered = message.envelope.version;
  let refusal: WireCategory = "unknown_protocol";
  for (const entry of supported) {
    if (entry.protocol !== message.envelope.protocol) continue;
    if (entry.minVersion <= offered && offered <= entry.maxVersion) return message;
    if (refusal === "unknown_protocol") refusal = "unsupported_version";
  }
  // No detail carries a peer-supplied spelling, so a refusal is safe to log.
  throw new WireError(
    refusal,
    refusal === "unknown_protocol"
      ? "no implemented protocol carries this name"
      : "major version is outside the supported range",
  );
}

export function encodeMessage(message: Message): Uint8Array {
  return toCanonicalBytes({
    kind: "object",
    entries: [
      ["body", message.body] as const,
      ["kind", {kind: "string", value: message.envelope.kind}] as const,
      ["protocol", {kind: "string", value: message.envelope.protocol}] as const,
      ["request_id", {kind: "string", value: message.envelope.requestId}] as const,
      ["version", {kind: "integer", value: BigInt(message.envelope.version)}] as const,
    ],
  });
}
