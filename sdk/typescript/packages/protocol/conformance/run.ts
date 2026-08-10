// SPDX-License-Identifier: Apache-2.0

// Cross-language conformance runner for R1-06.
//
// Reads the checked-in corpus and the artifact the Rust encoder produced, then
// records two directions per fixture:
//
//   rust_encode_bun_decode  this runtime decodes the bytes Rust produced;
//   bun_encode_rust_decode  this runtime encodes, for Rust to decode next.
//
// A direction that cannot execute is written as a gap. It is never written as a
// pass, because a corpus where one direction silently skipped proves only that
// an encoder and its own decoder share a bug.
//
// Usage:
//   bun run conformance/run.ts <corpus.json> <rust-encoded.json> <out.json>

import {readFileSync, writeFileSync} from "node:fs";

import {WireError, decodeMessage, parseCanonical, toCanonicalBytes} from "../src/canonical.ts";

interface Fixture {
  readonly id: string;
  readonly bytes_hex: string;
  readonly outcome: "accept" | "reject";
  readonly category?: string;
  readonly note: string;
}

interface Corpus {
  readonly schema: string;
  readonly envelope_ids: readonly string[];
  readonly fixtures: readonly Fixture[];
}

interface DirectionResult {
  readonly status: "pass" | "fail" | "gap";
  readonly detail?: string;
}

interface FixtureResult {
  readonly id: string;
  readonly rust_encode_bun_decode: DirectionResult;
  readonly bun_encode_rust_decode: DirectionResult;
  readonly bun_encoded_hex?: string;
  readonly observed_category?: string;
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

const [, , corpusPath, rustEncodedPath, outputPath] = process.argv;
if (corpusPath === undefined || rustEncodedPath === undefined || outputPath === undefined) {
  console.error("usage: run.ts <corpus.json> <rust-encoded.json> <out.json>");
  process.exit(2);
}

const corpus = JSON.parse(readFileSync(corpusPath, "utf8")) as Corpus;
const rustEncoded = JSON.parse(readFileSync(rustEncodedPath, "utf8")) as Record<string, string>;
const envelopeIds = new Set(corpus.envelope_ids);

const results: FixtureResult[] = corpus.fixtures.map((fixture) => {
  const isEnvelope = envelopeIds.has(fixture.id);
  const decode = (bytes: Uint8Array) =>
    isEnvelope ? decodeMessage(bytes) : parseCanonical(bytes);

  if (fixture.outcome === "reject") {
    // Rejection parity: this runtime must refuse the same bytes with the same
    // category. Failing for a different reason is a mismatch, not a pass.
    let observed: string;
    try {
      decode(fromHex(fixture.bytes_hex));
      observed = "accepted";
    } catch (error) {
      observed = categoryOf(error);
    }
    const matches = observed === fixture.category;
    const detail = matches ? undefined : `expected ${fixture.category}, observed ${observed}`;
    const outcome: DirectionResult = matches
      ? {status: "pass"}
      : {status: "fail", detail: detail ?? "mismatch"};
    return {
      id: fixture.id,
      // A rejected fixture exercises both decoders on the same bytes; there is
      // nothing to encode, so both directions carry the same verdict.
      rust_encode_bun_decode: outcome,
      bun_encode_rust_decode: outcome,
      observed_category: observed,
    };
  }

  // Direction one: decode exactly what Rust encoded.
  const rustHex = rustEncoded[fixture.id];
  let first: DirectionResult;
  if (rustHex === undefined) {
    first = {status: "gap", detail: "the Rust encoder produced no artifact for this fixture"};
  } else {
    try {
      // Byte agreement always goes through the value codec; an envelope
      // fixture must additionally decode as an envelope.
      const reencoded = toHex(toCanonicalBytes(parseCanonical(fromHex(rustHex))));
      if (isEnvelope) decodeMessage(fromHex(rustHex));
      first =
        reencoded === fixture.bytes_hex
          ? {status: "pass"}
          : {
              status: "fail",
              detail: `re-encoded ${reencoded} differs from the fixture ${fixture.bytes_hex}`,
            };
    } catch (error) {
      first = {status: "fail", detail: `decode refused with ${categoryOf(error)}`};
    }
  }

  // Direction two: encode here, for the Rust decoder to consume.
  let bunEncodedHex: string | undefined;
  let second: DirectionResult;
  try {
    const value = parseCanonical(fromHex(fixture.bytes_hex));
    bunEncodedHex = toHex(toCanonicalBytes(value));
    second =
      bunEncodedHex === fixture.bytes_hex
        ? {status: "pass"}
        : {
            status: "fail",
            detail: `encoded ${bunEncodedHex} differs from the fixture ${fixture.bytes_hex}`,
          };
  } catch (error) {
    second = {status: "fail", detail: `encode path refused with ${categoryOf(error)}`};
  }

  return {
    id: fixture.id,
    rust_encode_bun_decode: first,
    bun_encode_rust_decode: second,
    ...(bunEncodedHex === undefined ? {} : {bun_encoded_hex: bunEncodedHex}),
  };
});

const tally = (pick: (result: FixtureResult) => DirectionResult) => ({
  pass: results.filter((result) => pick(result).status === "pass").length,
  fail: results.filter((result) => pick(result).status === "fail").length,
  gap: results.filter((result) => pick(result).status === "gap").length,
});

const document = {
  schema: "automonique.wire-conformance/v1",
  runtime: `${process.release?.name ?? "unknown"} ${process.version}`,
  measured: true,
  fixtures: corpus.fixtures.length,
  rust_encode_bun_decode: tally((result) => result.rust_encode_bun_decode),
  bun_encode_rust_decode: tally((result) => result.bun_encode_rust_decode),
  results,
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

const failures = results.filter(
  (result) =>
    result.rust_encode_bun_decode.status !== "pass" ||
    result.bun_encode_rust_decode.status !== "pass",
);
for (const failure of failures) {
  console.error(
    `${failure.id}: ` +
      `rust->bun ${failure.rust_encode_bun_decode.status}` +
      `${failure.rust_encode_bun_decode.detail ? ` (${failure.rust_encode_bun_decode.detail})` : ""}; ` +
      `bun->rust ${failure.bun_encode_rust_decode.status}` +
      `${failure.bun_encode_rust_decode.detail ? ` (${failure.bun_encode_rust_decode.detail})` : ""}`,
  );
}
console.log(
  `${results.length} fixtures; ` +
    `rust->bun ${JSON.stringify(document.rust_encode_bun_decode)}; ` +
    `bun->rust ${JSON.stringify(document.bun_encode_rust_decode)}`,
);
process.exit(failures.length === 0 ? 0 : 1);
