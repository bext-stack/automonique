// SPDX-License-Identifier: Apache-2.0

// Cross-language conformance runner for the generated Runs API surface.
//
// The corpus at `rust/crates/automonique-protocol/fixtures/runs-api-v1.json` is
// generated from the shipped Rust constructors: every canonical byte string in
// it was produced by encoding a real message and re-read through
// `from_canonical_bytes` before it was written, and every refusal category was
// read back from the error Rust returned for that exact input. Rust is the wire
// source of truth, so a disagreement is fixed in whichever implementation is
// wrong — never in the corpus.
//
// What this runner measures, using only `../generated/`:
//
//   requests           the generated builders produce the recorded canonical
//                      bytes, byte for byte — including a state filter recorded
//                      in an order that is neither the wire's nor alphabetical,
//                      a cursor at the wire's integer ceiling, and a run
//                      identity whose every character escapes to two bytes;
//   responses          the generated decoder recovers the recorded fields of
//                      nested pages and views, including counters at the
//                      ceiling that a `number` would round;
//   decode refusals    the same payloads are refused, under the same category
//                      spellings Rust reports;
//   encode refusals    the same values are refused while building, under the
//                      same categories — and the branded constructors refuse
//                      them on their own, with the violation each names;
//   rust-only          payloads Rust refuses for a rule relating two fields are
//                      *accepted* here, because the generated surface holds each
//                      field's own shape and not the relations between them.
//                      Asserting the acceptance is what makes the gap a
//                      measurement: if this file ever learns one of those rules,
//                      this section fails until the entry moves.
//
// Every payload this runner produced is written to the file named as the second
// argument, one `<id> <hex>` line each, so the Rust side can compare the bytes
// itself and feed them back through `RunsRequest::from_canonical_bytes`.
//
// Counters travel through the corpus as decimal strings: `JSON.parse` reads
// numbers as doubles, and `9223372036854775807` would come back as
// `9223372036854775808` without a word of complaint.
//
// Usage:
//   bun run conformance/runs-api.ts <corpus.json> <produced.txt>

import {readFileSync, writeFileSync} from "node:fs";

import {
  PageSize,
  RUNS_LIST_RUNS_REQUEST_KIND,
  RUNS_PROTOCOL,
  RUNS_RUN_DETAIL_REQUEST_KIND,
  RefusalError,
  RequestId,
  RunCursor,
  RunId,
  ValidationError,
  assertNeverRunsResponse,
  decodeRunsResponse,
  encodeListRuns,
  encodeRunDetail,
  type RunState,
  type RunSummary,
  type RunsResponse,
} from "../generated/index.ts";

interface Params {
  readonly page_size?: string;
  readonly since?: string | null;
  readonly states?: readonly string[] | null;
  readonly run_id?: string;
}

interface RequestFixture {
  readonly id: string;
  readonly kind: string;
  readonly note: string;
  readonly params: Params;
  readonly request_id: string;
  readonly canonical_bytes: number;
  readonly canonical_hex: string;
}

interface ResponseFixture {
  readonly id: string;
  readonly kind: string;
  readonly note: string;
  readonly outcome: string;
  readonly canonical_hex: string;
  readonly decoded: Readonly<Record<string, string>>;
}

interface DecodeRefusalFixture {
  readonly id: string;
  readonly note: string;
  readonly category: string;
  readonly payload_hex: string;
}

interface RustOnlyFixture {
  readonly id: string;
  readonly note: string;
  readonly rust_category: string;
  readonly payload_hex: string;
}

interface EncodeRefusalFixture {
  readonly id: string;
  readonly kind: string;
  readonly note: string;
  readonly category: string;
  readonly params: Params;
  readonly request_id: string;
  // Not `constructor`: a parsed JSON object inherits that name from its
  // prototype, so an absent key would read as present on every entry.
  readonly refused_by?: string;
  readonly violation?: string;
}

interface Corpus {
  readonly protocol: string;
  readonly version: number;
  readonly requests: readonly RequestFixture[];
  readonly responses: readonly ResponseFixture[];
  readonly decode_refusals: readonly DecodeRefusalFixture[];
  readonly rust_only_refusals: readonly RustOnlyFixture[];
  readonly encode_refusals: readonly EncodeRefusalFixture[];
}

const corpusPath = process.argv[2];
const producedPath = process.argv[3];
if (corpusPath === undefined || producedPath === undefined) {
  console.error("usage: runs-api.ts <corpus.json> <produced.txt>");
  process.exit(2);
}

const corpus = JSON.parse(readFileSync(corpusPath, "utf8")) as Corpus;
const problems: string[] = [];
const produced: string[] = [];

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

function unhex(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Apply a branded constructor, or bypass it.
 *
 * Bypassing is the point of the refusal cases: a brand exists only in the type
 * checker, so the value an untyped caller reaches an encoder with is exactly
 * this cast. What the encoder does with it is what the encoder is worth.
 */
function branded<T>(make: (value: never) => T, value: unknown, brand: boolean): T {
  return brand ? make(value as never) : (value as T);
}

function requiredText(params: Params, name: "page_size" | "run_id"): string {
  const value = params[name];
  if (value === undefined) throw new Error(`fixture parameter ${name} is missing`);
  return value;
}

/** A nullable counter, read from the corpus's decimal-string encoding. */
function counter(value: string | null | undefined): bigint | null {
  if (value === undefined) throw new Error("a fixture counter is missing");
  return value === null ? null : BigInt(value);
}

function encodeFixture(
  kind: string,
  requestIdText: string,
  params: Params,
  brand: boolean,
): Uint8Array {
  const id = branded(RequestId, requestIdText, brand);
  switch (kind) {
    case RUNS_LIST_RUNS_REQUEST_KIND: {
      const states = params.states;
      if (states === undefined) throw new Error("a list_runs fixture carries a states parameter");
      return encodeListRuns(id, {
        page_size: branded(PageSize, BigInt(requiredText(params, "page_size")), brand),
        since: mapCounter(counter(params.since), brand),
        // The corpus records the caller's order, which is deliberately not the
        // wire's: the builder is what canonicalizes it.
        states: states === null ? null : (states as readonly RunState[]),
      });
    }
    case RUNS_RUN_DETAIL_REQUEST_KIND:
      return encodeRunDetail(id, {run_id: branded(RunId, requiredText(params, "run_id"), brand)});
    default:
      throw new Error(`the corpus names request kind ${kind}, which nothing here builds`);
  }
}

function mapCounter(value: bigint | null, brand: boolean): RunCursor | null {
  return value === null ? null : branded(RunCursor, value, brand);
}

/** How one decoded summary is spelled, under the corpus's dotted prefix. */
function summarySpelling(prefix: string, value: RunSummary): Record<string, string> {
  return {
    [`${prefix}accepted_at_ms`]: value.accepted_at_ms.toString(),
    [`${prefix}run_id`]: value.run_id,
    [`${prefix}spec_digest`]: value.spec_digest,
    [`${prefix}state`]: value.state,
    [`${prefix}submission_id`]: value.submission_id.toString(),
    [`${prefix}submission_state`]: value.submission_state,
  };
}

/** How one decoded response is spelled, in the corpus's own encoding. */
function spelling(response: RunsResponse): Record<string, string> {
  switch (response.kind) {
    case "run_list_result": {
      const value = response.value;
      const out: Record<string, string> = {
        more: String(value.more),
        next_cursor: value.next_cursor === null ? "null" : value.next_cursor.toString(),
        request_id: value.request_id,
        "runs.len": String(value.runs.length),
      };
      value.runs.forEach((run, index) => {
        Object.assign(out, summarySpelling(`runs.${index}.`, run));
      });
      return out;
    }
    case "run_detail_result": {
      const value = response.value;
      const out: Record<string, string> = {
        coverage: value.coverage,
        last_sequence: value.last_sequence.toString(),
        "lifecycle.len": String(value.lifecycle.length),
        request_id: value.request_id,
      };
      value.lifecycle.forEach((carried, index) => {
        out[`lifecycle.${index}.at_ms`] = carried.at_ms.toString();
        out[`lifecycle.${index}.authority`] = carried.authority;
        out[`lifecycle.${index}.kind`] = carried.kind;
        out[`lifecycle.${index}.sequence`] = carried.sequence.toString();
      });
      Object.assign(out, summarySpelling("summary.", value.summary));
      return out;
    }
    case "resync_required":
      return {
        request_id: response.value.request_id,
        snapshot_from: response.value.snapshot_from.toString(),
        snapshot_to: response.value.snapshot_to.toString(),
      };
    case "refused":
      return {refusal: response.value.refusal, request_id: response.value.request_id};
    case "undecoded":
      return {request_id: response.request_id, response_kind: response.response_kind};
    default:
      // A response arm added to the generated union without a spelling here
      // fails to compile rather than going unreported.
      return assertNeverRunsResponse(response);
  }
}

function sameSpelling(
  actual: Record<string, string>,
  expected: Readonly<Record<string, string>>,
): string | undefined {
  const actualKeys = Object.keys(actual).sort();
  const expectedKeys = Object.keys(expected).sort();
  if (actualKeys.join(",") !== expectedKeys.join(",")) {
    return `fields ${actualKeys.join(",")} decoded, ${expectedKeys.join(",")} expected`;
  }
  for (const key of actualKeys) {
    if (actual[key] !== expected[key]) {
      return `${key} decoded as ${JSON.stringify(actual[key])}, expected ${JSON.stringify(expected[key])}`;
    }
  }
  return undefined;
}

/** The category a refusal carries, whichever layer refused. */
function categoryOf(error: unknown): string | undefined {
  if (error instanceof RefusalError) return error.category;
  // The shared codec's refusals reach here unchanged, under the codec's own
  // category, which is what Rust reports for them too.
  if (error instanceof Error && "category" in error && typeof error.category === "string") {
    return error.category;
  }
  return undefined;
}

// --- requests --------------------------------------------------------------

for (const fixture of corpus.requests) {
  try {
    const payload = encodeFixture(fixture.kind, fixture.request_id, fixture.params, true);
    produced.push(`${fixture.id} ${hex(payload)}`);
    if (payload.length !== fixture.canonical_bytes) {
      problems.push(
        `${fixture.id}: encoded ${payload.length} bytes, the corpus records ${fixture.canonical_bytes}`,
      );
      continue;
    }
    if (hex(payload) !== fixture.canonical_hex) {
      const mine = hex(payload);
      let index = 0;
      while (index < mine.length && mine[index] === fixture.canonical_hex[index]) index += 1;
      problems.push(
        `${fixture.id}: the encodings first differ at hex digit ${index}: ` +
          `${mine.slice(Math.max(0, index - 24), index + 24)} vs ` +
          `${fixture.canonical_hex.slice(Math.max(0, index - 24), index + 24)}`,
      );
    }
  } catch (error) {
    problems.push(`${fixture.id}: encoding threw ${String(error)}`);
  }
}

// --- responses -------------------------------------------------------------

for (const fixture of corpus.responses) {
  try {
    const decoded = decodeRunsResponse(unhex(fixture.canonical_hex));
    if (decoded.kind !== fixture.kind) {
      problems.push(`${fixture.id}: decoded kind ${decoded.kind}, expected ${fixture.kind}`);
      continue;
    }
    const difference = sameSpelling(spelling(decoded), fixture.decoded);
    if (difference !== undefined) problems.push(`${fixture.id}: ${difference}`);
  } catch (error) {
    problems.push(`${fixture.id}: decoding threw ${String(error)}`);
  }
}

// A page and a resync are different answers, and a reader that confused them
// would serve a partial listing as a whole one. The corpus records which is
// which; this asserts the union arms stay distinguishable rather than trusting
// the kind string alone.
for (const fixture of corpus.responses) {
  if (fixture.outcome !== "resync_required") continue;
  const decoded = decodeRunsResponse(unhex(fixture.canonical_hex));
  if (decoded.kind !== "resync_required") {
    problems.push(`${fixture.id}: a resync answer decoded as ${decoded.kind}`);
  } else if ("runs" in (decoded.value as object)) {
    problems.push(`${fixture.id}: a resync answer carried rows`);
  }
}

// --- decode refusals -------------------------------------------------------

for (const fixture of corpus.decode_refusals) {
  let refusal: unknown;
  try {
    const decoded = decodeRunsResponse(unhex(fixture.payload_hex));
    problems.push(`${fixture.id}: accepted a payload Rust refuses, as ${decoded.kind}`);
    continue;
  } catch (error) {
    refusal = error;
  }
  const category = categoryOf(refusal);
  if (category !== fixture.category) {
    problems.push(
      `${fixture.id}: refused with ${category ?? String(refusal)}, Rust refuses with ${fixture.category}`,
    );
  }
}

// --- the measured gap ------------------------------------------------------

for (const fixture of corpus.rust_only_refusals) {
  try {
    decodeRunsResponse(unhex(fixture.payload_hex));
  } catch (error) {
    problems.push(
      `${fixture.id}: this file now refuses a payload the corpus records as rust-only ` +
        `(${categoryOf(error) ?? String(error)}). That is an improvement, not a failure — ` +
        `move the entry from rust_only_refusals to decode_refusals in tests/codegen.rs.`,
    );
  }
}

// --- encode refusals -------------------------------------------------------

const stringConstructors: Readonly<Record<string, (value: string) => string>> = {
  RequestId,
  RunId,
};
const counterConstructors: Readonly<Record<string, (value: bigint) => bigint>> = {
  PageSize,
  RunCursor,
};

for (const fixture of corpus.encode_refusals) {
  // The branded constructor refuses the value on its own, and names what was
  // wrong with it. This is the refusal a caller who builds a value gets; the
  // encoder's category below is what a message-level refusal looks like.
  if (fixture.refused_by !== undefined) {
    const stringMake = stringConstructors[fixture.refused_by];
    const counterMake = counterConstructors[fixture.refused_by];
    let apply: (() => unknown) | undefined;
    if (stringMake !== undefined) {
      const offending =
        fixture.refused_by === "RequestId" ? fixture.request_id : fixture.params.run_id;
      if (offending !== undefined) apply = () => stringMake(offending);
    } else if (counterMake !== undefined) {
      const offending =
        fixture.refused_by === "PageSize" ? fixture.params.page_size : fixture.params.since;
      if (offending !== undefined && offending !== null) {
        apply = () => counterMake(BigInt(offending));
      }
    }
    if (apply === undefined) {
      problems.push(`${fixture.id}: no constructor named ${fixture.refused_by} takes this value`);
    } else {
      try {
        apply();
        problems.push(`${fixture.id}: ${fixture.refused_by} accepted a value Rust refuses`);
      } catch (error) {
        if (!(error instanceof ValidationError)) {
          problems.push(`${fixture.id}: ${fixture.refused_by} threw ${String(error)}`);
        } else if (error.violation !== fixture.violation) {
          problems.push(
            `${fixture.id}: ${fixture.refused_by} refused with ${error.violation}, the corpus records ${String(fixture.violation)}`,
          );
        }
      }
    }
  }

  let refusal: unknown;
  try {
    encodeFixture(fixture.kind, fixture.request_id, fixture.params, false);
    problems.push(`${fixture.id}: built a request Rust refuses`);
    continue;
  } catch (error) {
    refusal = error;
  }
  const category = categoryOf(refusal);
  if (category !== fixture.category) {
    problems.push(
      `${fixture.id}: refused with ${category ?? String(refusal)}, Rust refuses with ${fixture.category}`,
    );
  }
}

// --- report ----------------------------------------------------------------

if (corpus.protocol !== RUNS_PROTOCOL) {
  problems.push(`the corpus is for ${corpus.protocol}, this surface speaks ${RUNS_PROTOCOL}`);
}

writeFileSync(producedPath, `${produced.join("\n")}\n`);

for (const problem of problems) console.error(problem);
console.log(
  `${corpus.requests.length} requests encoded, ` +
    `${corpus.responses.length} responses decoded, ` +
    `${corpus.decode_refusals.length} decode refusals and ` +
    `${corpus.encode_refusals.length} encode refusals matched, ` +
    `${corpus.rust_only_refusals.length} rust-only refusals accepted as recorded; ` +
    `${problems.length} problems`,
);
process.exit(problems.length === 0 ? 0 : 1);
