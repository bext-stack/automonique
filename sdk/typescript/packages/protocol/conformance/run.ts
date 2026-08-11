// SPDX-License-Identifier: Apache-2.0

// Cross-language conformance runner for R1-06.
//
// Reads the checked-in corpus and the artifacts the Rust side produced, then
// records, per fixture, what this runtime observed:
//
//   rust_encode_bun_decode  this runtime decodes the bytes Rust produced;
//   bun_encode_rust_decode  this runtime encodes, for Rust to decode next.
//
// A direction that cannot execute is written as a gap. It is never written as a
// pass, because a corpus where one direction silently skipped proves only that
// an encoder and its own decoder share a bug.
//
// Four sections are covered, and each names what it exchanges:
//
//   fixtures            hex literals; bytes travel through the JSON artifacts.
//   generated_fixtures  bytes too large to review as a literal, built from a
//                       generator rule on both sides and exchanged as files so
//                       the comparison stays byte-for-byte.
//   enum_fixtures       drive the read-only and security-sensitive enum
//                       decoders, not the generic value parser.
//   frame_fixtures      drive the length-delimited frame codec at its edges.
//
// Usage:
//   bun run conformance/run.ts <corpus.json> <rust-encoded.json> <out.json> <exchange-dir>

import {readFileSync, writeFileSync} from "node:fs";

import {
  WireError,
  bytesEqual,
  decodeFrame,
  decodeMessageAdmitted,
  decodeReadOnlyEnum,
  decodeSecurityEnum,
  encodeFrame,
  isWireCategory,
  parseCanonical,
  toCanonicalBytes,
  type EnumSpec,
  type FrameDecode,
  type SupportedProtocol,
} from "../src/canonical.ts";

type Segment =
  | {readonly literal_hex: string}
  | {readonly count: number; readonly repeat_hex: string};

interface Fixture {
  readonly id: string;
  readonly bytes_hex: string;
  readonly outcome: "accept" | "reject";
  readonly category?: string;
  readonly note: string;
}

interface GeneratedFixture {
  readonly id: string;
  readonly segments: readonly Segment[];
  readonly outcome: "accept" | "reject";
  readonly category?: string;
  readonly note: string;
}

interface EnumDeclaration {
  readonly id: string;
  readonly field: string;
  readonly kind: "security_sensitive" | "read_only";
  readonly known: readonly string[];
  readonly note: string;
}

interface EnumFixture {
  readonly id: string;
  readonly enum: string;
  readonly bytes_hex: string;
  readonly outcome: "accept" | "reject";
  readonly category?: string;
  readonly decoded?: string;
  readonly note: string;
}

interface FrameFixture {
  readonly id: string;
  readonly note: string;
  readonly input: readonly Segment[];
  readonly decode: {
    readonly outcome: "frame" | "need_more" | "reject";
    readonly consumed?: number;
    readonly payload_bytes?: number;
    readonly additional?: number;
    readonly category?: string;
  };
  readonly encode?: {
    readonly payload: readonly Segment[];
    readonly outcome: "accept" | "reject";
    readonly category?: string;
  };
}

interface SupportedProtocolEntry {
  readonly protocol: string;
  readonly min_version: number;
  readonly max_version: number;
  readonly note: string;
}

interface Corpus {
  readonly schema: string;
  readonly envelope_ids: readonly string[];
  readonly fixtures: readonly Fixture[];
  readonly generated_fixtures: readonly GeneratedFixture[];
  readonly enums: readonly EnumDeclaration[];
  readonly enum_fixtures: readonly EnumFixture[];
  readonly frame_fixtures: readonly FrameFixture[];
  readonly supported_protocols: readonly SupportedProtocolEntry[];
}

type Status = "pass" | "fail" | "gap" | "absent";

interface DirectionResult {
  readonly status: Status;
  readonly detail?: string;
}

interface FixtureResult {
  readonly id: string;
  readonly rust_encode_bun_decode: DirectionResult;
  readonly bun_encode_rust_decode: DirectionResult;
  readonly bun_encoded_hex?: string;
  readonly observed_category?: string;
}

const PASS: DirectionResult = {status: "pass"};
const ABSENT: DirectionResult = {status: "absent"};

function fail(detail: string): DirectionResult {
  return {status: "fail", detail};
}

function gap(detail: string): DirectionResult {
  return {status: "gap", detail};
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function categoryOf(error: unknown): string {
  return error instanceof WireError ? error.category : "unexpected_exception";
}

/**
 * Build fixture bytes from a generator rule.
 *
 * A multi-megabyte literal would make the corpus unreviewable, so large
 * payloads are a rule both implementations follow. That the two rules agree is
 * then measured rather than assumed: the Rust side writes the bytes it built
 * and this runner compares them to its own, byte for byte, before decoding.
 */
function buildSegments(segments: readonly Segment[]): Uint8Array {
  let total = 0;
  for (const segment of segments) {
    total +=
      "literal_hex" in segment
        ? segment.literal_hex.length / 2
        : (segment.repeat_hex.length / 2) * segment.count;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const segment of segments) {
    if ("literal_hex" in segment) {
      const unit = fromHex(segment.literal_hex);
      out.set(unit, offset);
      offset += unit.length;
      continue;
    }
    const unit = fromHex(segment.repeat_hex);
    const first = unit[0];
    if (unit.length === 1 && first !== undefined) {
      out.fill(first, offset, offset + segment.count);
      offset += segment.count;
      continue;
    }
    for (let index = 0; index < segment.count; index += 1) {
      out.set(unit, offset);
      offset += unit.length;
    }
  }
  return out;
}

const [, , corpusPath, rustEncodedPath, outputPath, exchangeDirectory] = process.argv;
if (
  corpusPath === undefined ||
  rustEncodedPath === undefined ||
  outputPath === undefined ||
  exchangeDirectory === undefined
) {
  console.error("usage: run.ts <corpus.json> <rust-encoded.json> <out.json> <exchange-dir>");
  process.exit(2);
}

const corpus = JSON.parse(readFileSync(corpusPath, "utf8")) as Corpus;
const rustEncoded = JSON.parse(readFileSync(rustEncodedPath, "utf8")) as Record<string, string>;
const envelopeIds = new Set(corpus.envelope_ids);
const supported: readonly SupportedProtocol[] = corpus.supported_protocols.map((entry) => ({
  protocol: entry.protocol,
  minVersion: entry.min_version,
  maxVersion: entry.max_version,
}));

function exchangePath(id: string, suffix: string): string {
  return `${exchangeDirectory}/${id}.${suffix}.bin`;
}

function readExchanged(id: string, suffix: string): Uint8Array | undefined {
  try {
    return readFileSync(exchangePath(id, suffix));
  } catch {
    return undefined;
  }
}

// A category the corpus names but this implementation cannot produce would make
// every rejection fixture in that category unfalsifiable, so it is a hard error
// rather than a per-fixture mismatch.
const unknownCategories = [
  ...new Set(
    [
      ...corpus.fixtures.map((fixture) => fixture.category),
      ...corpus.generated_fixtures.map((fixture) => fixture.category),
      ...corpus.enum_fixtures.map((fixture) => fixture.category),
      ...corpus.frame_fixtures.map((fixture) => fixture.decode.category),
      ...corpus.frame_fixtures.map((fixture) => fixture.encode?.category),
    ].filter((category): category is string => category !== undefined),
  ),
].filter((category) => !isWireCategory(category));

// ---------------------------------------------------------------------------
// Value fixtures: hex literals, and the generated fixtures that are too large
// to be literals. Both are judged by the same rules.
// ---------------------------------------------------------------------------

interface ValueFixture {
  readonly id: string;
  readonly bytes: Uint8Array;
  readonly outcome: "accept" | "reject";
  readonly category?: string;
  readonly generated: boolean;
}

const valueFixtures: ValueFixture[] = [
  ...corpus.fixtures.map((fixture) => ({
    id: fixture.id,
    bytes: fromHex(fixture.bytes_hex),
    outcome: fixture.outcome,
    ...(fixture.category === undefined ? {} : {category: fixture.category}),
    generated: false,
  })),
  ...corpus.generated_fixtures.map((fixture) => ({
    id: fixture.id,
    bytes: buildSegments(fixture.segments),
    outcome: fixture.outcome,
    ...(fixture.category === undefined ? {} : {category: fixture.category}),
    generated: true,
  })),
];

const results: FixtureResult[] = valueFixtures.map((fixture) => {
  const isEnvelope = envelopeIds.has(fixture.id);
  const decode = (bytes: Uint8Array) =>
    isEnvelope ? decodeMessageAdmitted(bytes, supported) : parseCanonical(bytes);

  // A generated fixture's bytes come from a rule rather than a literal, so the
  // first thing measured is that both implementations read the rule the same
  // way. Without this the rest of the comparison would be two implementations
  // agreeing about two different inputs.
  if (fixture.generated) {
    const rustInput = readExchanged(fixture.id, "input");
    if (rustInput === undefined) {
      const missing = gap("the Rust side wrote no input artifact for this generated fixture");
      return {id: fixture.id, rust_encode_bun_decode: missing, bun_encode_rust_decode: missing};
    }
    if (!bytesEqual(rustInput, fixture.bytes)) {
      const mismatch = fail(
        `the generator rule produced ${fixture.bytes.length} bytes here and ` +
          `${rustInput.length} bytes in Rust`,
      );
      return {id: fixture.id, rust_encode_bun_decode: mismatch, bun_encode_rust_decode: mismatch};
    }
  }

  if (fixture.outcome === "reject") {
    // Rejection parity: this runtime must refuse the same bytes with the same
    // category. Failing for a different reason is a mismatch, not a pass.
    let observed: string;
    try {
      decode(fixture.bytes);
      observed = "accepted";
    } catch (error) {
      observed = categoryOf(error);
    }
    const matches = observed === fixture.category;
    const outcome: DirectionResult = matches
      ? PASS
      : fail(`expected ${fixture.category}, observed ${observed}`);
    return {
      id: fixture.id,
      // A rejected fixture exercises both decoders on the same bytes; there is
      // nothing to encode, so both directions carry the same verdict.
      rust_encode_bun_decode: outcome,
      bun_encode_rust_decode: outcome,
      observed_category: observed,
    };
  }

  // Direction one: decode exactly what Rust encoded. A generated fixture's
  // bytes are exchanged as a file, a literal fixture's as hex.
  const rustBytes = fixture.generated
    ? readExchanged(fixture.id, "rust")
    : (() => {
        const hex = rustEncoded[fixture.id];
        return hex === undefined ? undefined : fromHex(hex);
      })();
  let first: DirectionResult;
  if (rustBytes === undefined) {
    first = gap("the Rust encoder produced no artifact for this fixture");
  } else {
    try {
      // Byte agreement always goes through the value codec; an envelope
      // fixture must additionally decode, and be admitted, as an envelope.
      const reencoded = toCanonicalBytes(parseCanonical(rustBytes));
      if (isEnvelope) decodeMessageAdmitted(rustBytes, supported);
      first = bytesEqual(reencoded, fixture.bytes)
        ? PASS
        : fail(`re-encoding the Rust bytes gave ${reencoded.length} bytes that differ`);
    } catch (error) {
      first = fail(`decode refused with ${categoryOf(error)}`);
    }
  }

  // Direction two: encode here, for the Rust decoder to consume.
  let bunEncodedHex: string | undefined;
  let second: DirectionResult;
  try {
    const encoded = toCanonicalBytes(parseCanonical(fixture.bytes));
    if (fixture.generated) {
      writeFileSync(exchangePath(fixture.id, "bun"), encoded);
    } else {
      bunEncodedHex = toHex(encoded);
    }
    second = bytesEqual(encoded, fixture.bytes)
      ? PASS
      : fail(`encoding gave ${encoded.length} bytes that differ from the fixture`);
  } catch (error) {
    second = fail(`encode path refused with ${categoryOf(error)}`);
  }

  return {
    id: fixture.id,
    rust_encode_bun_decode: first,
    bun_encode_rust_decode: second,
    ...(bunEncodedHex === undefined ? {} : {bun_encoded_hex: bunEncodedHex}),
  };
});

// ---------------------------------------------------------------------------
// Enum fixtures: the read-only and security-sensitive decoders themselves.
// ---------------------------------------------------------------------------

interface EnumResult {
  readonly id: string;
  readonly status: Status;
  readonly detail?: string;
  readonly observed: string;
}

const declarations = new Map(corpus.enums.map((declaration) => [declaration.id, declaration]));

const enumResults: EnumResult[] = corpus.enum_fixtures.map((fixture) => {
  const declaration = declarations.get(fixture.enum);
  if (declaration === undefined) {
    return {
      id: fixture.id,
      status: "fail",
      detail: `the corpus declares no enum named ${fixture.enum}`,
      observed: "undeclared_enum",
    };
  }
  const spec: EnumSpec<string> = {field: declaration.field, known: declaration.known};
  let observed: string;
  try {
    const value = parseCanonical(fromHex(fixture.bytes_hex));
    if (value.kind !== "object") throw new WireError("invalid_json_value", declaration.field);
    const entry = value.entries.find(([key]) => key === declaration.field);
    if (entry === undefined) throw new WireError("missing_field", declaration.field);
    const spelling = entry[1];
    if (spelling.kind !== "string") throw new WireError("invalid_json_value", declaration.field);
    if (declaration.kind === "security_sensitive") {
      observed = `known:${decodeSecurityEnum(spelling.value, spec)}`;
    } else {
      const decoded = decodeReadOnlyEnum(spelling.value, spec);
      observed =
        decoded.kind === "known" ? `known:${decoded.value}` : `unknown:${decoded.spelling}`;
    }
  } catch (error) {
    observed = categoryOf(error);
  }
  const expected = fixture.outcome === "accept" ? fixture.decoded : fixture.category;
  return {
    id: fixture.id,
    status: observed === expected ? "pass" : "fail",
    ...(observed === expected ? {} : {detail: `expected ${expected}, observed ${observed}`}),
    observed,
  };
});

// ---------------------------------------------------------------------------
// Frame fixtures: the length-delimited codec at its declared edges.
// ---------------------------------------------------------------------------

interface FrameResult {
  readonly id: string;
  readonly input_agreement: DirectionResult;
  readonly decode: DirectionResult;
  readonly encode_rust_to_bun: DirectionResult;
  readonly encode_bun_to_rust: DirectionResult;
}

function checkDecode(fixture: FrameFixture, input: Uint8Array): DirectionResult {
  let decoded: FrameDecode;
  try {
    decoded = decodeFrame(input);
  } catch (error) {
    const category = categoryOf(error);
    if (fixture.decode.outcome !== "reject") {
      return fail(`refused with ${category}, expected ${fixture.decode.outcome}`);
    }
    return category === fixture.decode.category
      ? PASS
      : fail(`refused with ${category}, expected ${fixture.decode.category}`);
  }
  if (decoded.kind !== fixture.decode.outcome) {
    return fail(`decoded as ${decoded.kind}, expected ${fixture.decode.outcome}`);
  }
  if (decoded.kind === "frame") {
    if (decoded.consumed !== fixture.decode.consumed) {
      return fail(`consumed ${decoded.consumed}, expected ${fixture.decode.consumed}`);
    }
    if (decoded.payload.length !== fixture.decode.payload_bytes) {
      return fail(
        `payload is ${decoded.payload.length} bytes, expected ${fixture.decode.payload_bytes}`,
      );
    }
    return PASS;
  }
  return decoded.additional === fixture.decode.additional
    ? PASS
    : fail(`asked for ${decoded.additional} more bytes, expected ${fixture.decode.additional}`);
}

const frameResults: FrameResult[] = corpus.frame_fixtures.map((fixture) => {
  const input = buildSegments(fixture.input);
  const rustInput = readExchanged(fixture.id, "input");
  let agreement: DirectionResult;
  if (rustInput === undefined) {
    agreement = gap("the Rust side wrote no input artifact for this frame fixture");
  } else if (!bytesEqual(rustInput, input)) {
    agreement = fail(
      `the generator rule produced ${input.length} bytes here and ${rustInput.length} in Rust`,
    );
  } else {
    agreement = PASS;
  }

  const decode = agreement.status === "pass" ? checkDecode(fixture, input) : ABSENT;

  const encodeClause = fixture.encode;
  if (encodeClause === undefined) {
    return {
      id: fixture.id,
      input_agreement: agreement,
      decode,
      encode_rust_to_bun: ABSENT,
      encode_bun_to_rust: ABSENT,
    };
  }

  const payload = buildSegments(encodeClause.payload);
  let encoded: Uint8Array | undefined;
  let refusal: string | undefined;
  try {
    encoded = encodeFrame(payload);
  } catch (error) {
    refusal = categoryOf(error);
  }

  if (encodeClause.outcome === "reject") {
    // Nothing is exchanged when both encoders are expected to refuse; the
    // agreement that matters is the category, which Rust checks on its side.
    const matched =
      refusal === encodeClause.category
        ? PASS
        : fail(`encode gave ${refusal ?? "a frame"}, expected ${encodeClause.category}`);
    return {
      id: fixture.id,
      input_agreement: agreement,
      decode,
      encode_rust_to_bun: matched,
      encode_bun_to_rust: matched,
    };
  }

  if (encoded === undefined) {
    const refused = fail(`encode refused with ${refusal ?? "an unexpected error"}`);
    return {
      id: fixture.id,
      input_agreement: agreement,
      decode,
      encode_rust_to_bun: refused,
      encode_bun_to_rust: refused,
    };
  }

  const rustEncodedFrame = readExchanged(fixture.id, "rust");
  const first =
    rustEncodedFrame === undefined
      ? gap("the Rust encoder wrote no frame artifact")
      : bytesEqual(rustEncodedFrame, encoded)
        ? PASS
        : fail(
            `the Rust frame is ${rustEncodedFrame.length} bytes and this one ` +
              `is ${encoded.length}, or they differ byte-for-byte`,
          );
  writeFileSync(exchangePath(fixture.id, "bun"), encoded);
  return {
    id: fixture.id,
    input_agreement: agreement,
    decode,
    encode_rust_to_bun: first,
    encode_bun_to_rust: PASS,
  };
});

// ---------------------------------------------------------------------------
// Report.
// ---------------------------------------------------------------------------

function tally(statuses: readonly Status[]) {
  return {
    pass: statuses.filter((status) => status === "pass").length,
    fail: statuses.filter((status) => status === "fail").length,
    gap: statuses.filter((status) => status === "gap").length,
    absent: statuses.filter((status) => status === "absent").length,
  };
}

// Bun reports a Node version through `process.version` for compatibility, so
// naming the runtime from that alone would record the wrong one.
const runtime =
  typeof Bun === "undefined"
    ? `${process.release?.name ?? "unknown"} ${process.version}`
    : `bun ${Bun.version}`;

const document = {
  schema: "automonique.wire-conformance/v1",
  runtime,
  measured: true,
  categories_unknown_to_this_implementation: unknownCategories,
  fixtures: valueFixtures.length,
  literal_fixtures: corpus.fixtures.length,
  generated_fixtures: corpus.generated_fixtures.length,
  rust_encode_bun_decode: tally(results.map((result) => result.rust_encode_bun_decode.status)),
  bun_encode_rust_decode: tally(results.map((result) => result.bun_encode_rust_decode.status)),
  enum_fixtures: corpus.enum_fixtures.length,
  enum_tally: tally(enumResults.map((result) => result.status)),
  frame_fixtures: corpus.frame_fixtures.length,
  frame_input_agreement: tally(frameResults.map((result) => result.input_agreement.status)),
  frame_decode: tally(frameResults.map((result) => result.decode.status)),
  frame_encode_rust_to_bun: tally(frameResults.map((result) => result.encode_rust_to_bun.status)),
  frame_encode_bun_to_rust: tally(frameResults.map((result) => result.encode_bun_to_rust.status)),
  results,
  enum_results: enumResults,
  frame_results: frameResults,
};

/** Sort keys so the artifact the Rust side reads back is itself canonical. */
function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
        .map(([key, entry]) => [key, sortKeys(entry)]),
    );
  }
  return value;
}

writeFileSync(outputPath, `${JSON.stringify(sortKeys(document), null, 2)}\n`);

const problems: string[] = [];
for (const category of unknownCategories) {
  problems.push(`the corpus names category ${category}, which this implementation cannot produce`);
}
for (const result of results) {
  for (const [direction, outcome] of [
    ["rust->bun", result.rust_encode_bun_decode],
    ["bun->rust", result.bun_encode_rust_decode],
  ] as const) {
    if (outcome.status !== "pass") {
      problems.push(`${result.id}: ${direction} ${outcome.status} (${outcome.detail ?? ""})`);
    }
  }
}
for (const result of enumResults) {
  if (result.status !== "pass") {
    problems.push(`${result.id}: ${result.status} (${result.detail ?? ""})`);
  }
}
for (const result of frameResults) {
  for (const [name, outcome] of [
    ["input", result.input_agreement],
    ["decode", result.decode],
    ["encode rust->bun", result.encode_rust_to_bun],
    ["encode bun->rust", result.encode_bun_to_rust],
  ] as const) {
    if (outcome.status === "fail" || outcome.status === "gap") {
      problems.push(`${result.id}: ${name} ${outcome.status} (${outcome.detail ?? ""})`);
    }
  }
}

for (const problem of problems) console.error(problem);
console.log(
  `${results.length} value fixtures; ` +
    `rust->bun ${JSON.stringify(document.rust_encode_bun_decode)}; ` +
    `bun->rust ${JSON.stringify(document.bun_encode_rust_decode)}; ` +
    `${enumResults.length} enum fixtures ${JSON.stringify(document.enum_tally)}; ` +
    `${frameResults.length} frame fixtures decode ${JSON.stringify(document.frame_decode)}, ` +
    `encode rust->bun ${JSON.stringify(document.frame_encode_rust_to_bun)}`,
);
process.exit(problems.length === 0 ? 0 : 1);
