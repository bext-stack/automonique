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

const I64_MIN = -(2n ** 63n);
const I64_MAX = 2n ** 63n - 1n;

/** Stable refusal categories, byte-identical to the Rust `CodecError` set. */
export type WireCategory =
  | "malformed_json"
  | "non_canonical_json"
  | "invalid_json_value"
  | "duplicate_key"
  | "trailing_data"
  | "integer_out_of_range"
  | "too_many_entries"
  | "missing_field"
  | "nesting_too_deep"
  | "field_invalid"
  | "field_grammar";

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

function utf8(value: string): Uint8Array {
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

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

class Parser {
  private position = 0;
  private depth = 0;

  constructor(private readonly text: string) {}

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
            value += '"';
            break;
          case "\\":
            value += "\\";
            break;
          case "/":
            value += "/";
            break;
          case "b":
            value += "\b";
            break;
          case "f":
            value += "\f";
            break;
          case "n":
            value += "\n";
            break;
          case "r":
            value += "\r";
            break;
          case "t":
            value += "\t";
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
            value += String.fromCodePoint(code);
            break;
          }
          default:
            throw new WireError("malformed_json", "unknown escape");
        }
      } else if (character.codePointAt(0)! < 0x20) {
        throw new WireError("malformed_json", "raw control character");
      } else {
        value += character;
      }
      if (utf8(value).length > MAX_JSON_STRING_BYTES) {
        throw new WireError("field_invalid", "string exceeds its ceiling");
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

const PROTOCOL_GRAMMAR = /^[a-z][a-z0-9.]*$/;
const KIND_GRAMMAR = /^[a-z][a-z0-9_]*$/;
const REQUEST_ID_GRAMMAR = /^[A-Za-z0-9\-_.:]+$/;

export function decodeMessage(payload: Uint8Array): Message {
  const value = parseCanonical(payload);
  const protocol = requiredString(value, "protocol", MAX_PROTOCOL_NAME_BYTES);
  const requestId = requiredString(value, "request_id", MAX_REQUEST_ID_BYTES);
  const kind = requiredString(value, "kind", MAX_MESSAGE_KIND_BYTES);
  const versionValue = objectField(value, "version");
  if (versionValue.kind !== "integer") throw new WireError("invalid_json_value", "version");
  const body = objectField(value, "body");

  if (versionValue.value <= 0n || versionValue.value > 0xffff_ffffn) {
    throw new WireError("field_invalid", "version");
  }
  if (!PROTOCOL_GRAMMAR.test(protocol) || protocol.endsWith(".") || protocol.includes("..")) {
    throw new WireError("field_grammar", "protocol");
  }
  if (!REQUEST_ID_GRAMMAR.test(requestId)) throw new WireError("field_grammar", "request_id");
  if (!KIND_GRAMMAR.test(kind)) throw new WireError("field_grammar", "kind");

  return {
    envelope: {protocol, version: Number(versionValue.value), requestId, kind},
    body,
  };
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
