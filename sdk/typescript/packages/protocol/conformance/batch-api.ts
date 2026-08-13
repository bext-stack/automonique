// SPDX-License-Identifier: Apache-2.0

// Cross-language conformance runner for the generated Batch control surface.
//
// The corpus at `rust/crates/automonique-protocol/fixtures/batch-api-v1.json`
// is generated from the shipped Rust constructors: every canonical byte string
// in it was produced by encoding a real message and re-read through
// `from_canonical_bytes` before it was written, and every refusal category was
// read back from the error Rust returned for that exact input. Rust is the wire
// source of truth, so a disagreement is fixed in whichever implementation is
// wrong — never in the corpus.
//
// What this runner measures, using only `../generated/`:
//
//   requests           the generated builders produce the recorded canonical
//                      bytes, byte for byte — including a registration of
//                      MAX_BATCH_CONTROL_MEMBERS members whose every character
//                      escapes to two canonical bytes, built here from the
//                      corpus's membership rule rather than read out of it;
//   responses          the generated decoder recovers the recorded fields of
//                      pages, receipts, rows and details, including counters at
//                      the wire ceiling that a `number` would round, and the
//                      rolled-up batch state a detail read carries;
//   decode refusals    the same payloads are refused, under the same category
//                      spellings Rust reports — including all four fail-closed
//                      vocabularies, both ends of the concurrency ceiling, and
//                      both ends of the advance revision;
//   encode refusals    the same values are refused while building, under the
//                      same categories;
//   rust-only          payloads Rust refuses for a rule relating two fields of
//                      a decoded message are *accepted* here, and requests Rust
//                      refuses for a rule relating two fields of a request are
//                      *built* here. Asserting both is what makes the gap a
//                      measurement rather than a description.
//
// What this lane holds that no lane before it did: the **discriminated
// concurrency policy**. A policy is one wire object with two keys where exactly
// one word carries a number, and the generated surface carries it as a union
// rather than as a struct with a nullable ceiling — so `sequential` has no
// `max_in_flight` to read at all, and the encoder and decoder both refuse the
// two shapes the wire cannot mean. The union round-trips through the response
// spellings below, which is what proves the shape survives a decode rather than
// merely type-checking.
//
// Every payload this runner produced is written to the file named as the second
// argument, one `<id> <hex>` line each, so the Rust side can compare the bytes
// itself and feed them back through `BatchRequest::from_canonical_bytes`.
//
// Counters travel through the corpus as decimal strings: `JSON.parse` reads
// numbers as doubles, and `9223372036854775807` would come back as
// `9223372036854775808` without a word of complaint.
//
// Usage:
//   bun run conformance/batch-api.ts <corpus.json> <produced.txt>

import {readFileSync, writeFileSync} from "node:fs";

import {
  BATCH_ADVANCE_MEMBER_REQUEST_KIND,
  BATCH_BATCH_DETAIL_REQUEST_KIND,
  BATCH_CONTROL_PROTOCOL,
  BATCH_LIST_BATCHES_REQUEST_KIND,
  BATCH_REGISTER_BATCH_REQUEST_KIND,
  BatchCursor,
  BatchId,
  BatchLabel,
  BatchMemberKey,
  BatchPageSize,
  BatchRevision,
  ConcurrencyCeiling,
  LastSequence,
  RefusalError,
  RequestId,
  ValidationError,
  assertNeverBatchResponse,
  decodeBatchResponse,
  encodeAdvanceMember,
  encodeBatchDetail,
  encodeListBatches,
  encodeRegisterBatch,
  type BatchConcurrency,
  type BatchMemberRecord,
  type BatchRecord,
  type BatchResponse,
  type MemberProgress,
} from "../generated/index.ts";

/** The two-key wire shape of a concurrency policy, as the corpus spells it. */
interface ConcurrencyParam {
  readonly kind: string;
  readonly max_in_flight: string | null;
}

interface Params {
  readonly batch_id?: string;
  readonly concurrency?: ConcurrencyParam;
  readonly expected_revision?: string;
  // Present-and-null is the absent label, which is not the same fact as a
  // fixture that carries no label parameter at all.
  readonly label?: string | null;
  readonly last_sequence?: string;
  readonly member_key?: string;
  readonly members?: readonly string[];
  readonly members_rule?: string;
  readonly page_size?: string;
  readonly since?: string;
  readonly state?: string;
}

interface MembershipRule {
  readonly id: string;
  readonly note: string;
  readonly count: string;
  readonly key_bytes: string;
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
  readonly refused_param?: string;
  readonly violation?: string;
}

interface RustOnlyEncodeFixture {
  readonly id: string;
  readonly kind: string;
  readonly note: string;
  readonly params: Params;
  readonly request_id: string;
  readonly rust_category: string;
}

interface Corpus {
  readonly protocol: string;
  readonly version: number;
  readonly membership_rules: readonly MembershipRule[];
  readonly requests: readonly RequestFixture[];
  readonly responses: readonly ResponseFixture[];
  readonly decode_refusals: readonly DecodeRefusalFixture[];
  readonly rust_only_refusals: readonly RustOnlyFixture[];
  readonly encode_refusals: readonly EncodeRefusalFixture[];
  readonly rust_only_encode_refusals: readonly RustOnlyEncodeFixture[];
}

const corpusPath = process.argv[2];
const producedPath = process.argv[3];
if (corpusPath === undefined || producedPath === undefined) {
  console.error("usage: batch-api.ts <corpus.json> <produced.txt>");
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

/**
 * The membership one rule names, built here rather than read out of the corpus.
 *
 * A maximal registration is 128 keys of 128 bytes, which is 33 KiB of literal
 * nobody can review. Both implementations build the list from the rule instead,
 * and that they read it the same way is what the byte comparison on the Rust
 * side measures.
 */
function ruledMembership(id: string): string[] {
  const rule = corpus.membership_rules.find((entry) => entry.id === id);
  if (rule === undefined) throw new Error(`the corpus names no membership rule ${id}`);
  const count = Number(rule.count);
  const keyBytes = Number(rule.key_bytes);
  const keys: string[] = [];
  for (let index = 0; index < count; index += 1) {
    const prefix = String(index).padStart(3, "0");
    keys.push(keyBytes === 0 ? `member-${prefix}` : prefix + '"'.repeat(keyBytes - prefix.length));
  }
  return keys;
}

function requiredText(
  params: Params,
  name: "batch_id" | "expected_revision" | "last_sequence" | "member_key" | "page_size" | "since" | "state",
): string {
  const value = params[name];
  if (value === undefined) throw new Error(`fixture parameter ${name} is missing`);
  return value;
}

/** The label a fixture declares, which may be an explicit null. */
function requiredLabel(params: Params): string | null {
  if (params.label === undefined) throw new Error("fixture parameter label is missing");
  return params.label;
}

/** The membership a fixture declares, literally or by rule. */
function requiredMembers(params: Params): readonly string[] {
  if (params.members_rule !== undefined) return ruledMembership(params.members_rule);
  if (params.members === undefined) throw new Error("fixture parameter members is missing");
  return params.members;
}

/**
 * The discriminated policy a fixture declares.
 *
 * The incoherent shapes are built deliberately and cast: `{kind: "sequential",
 * max_in_flight: 4n}` is not a value the union admits, which is the point —
 * it is exactly what an untyped caller reaches the encoder with, and the
 * encoder is where it has to be stopped.
 */
function concurrency(params: Params, brand: boolean): BatchConcurrency {
  const declared = params.concurrency;
  if (declared === undefined) throw new Error("fixture parameter concurrency is missing");
  if (declared.max_in_flight === null) {
    return {kind: declared.kind} as BatchConcurrency;
  }
  const ceiling = BigInt(declared.max_in_flight);
  return {
    kind: declared.kind,
    max_in_flight: branded(ConcurrencyCeiling, ceiling, brand),
  } as BatchConcurrency;
}

function encodeFixture(
  kind: string,
  requestIdText: string,
  params: Params,
  brand: boolean,
): Uint8Array {
  const id = branded(RequestId, requestIdText, brand);
  switch (kind) {
    case BATCH_REGISTER_BATCH_REQUEST_KIND: {
      const label = requiredLabel(params);
      return encodeRegisterBatch(id, {
        batch_id: branded(BatchId, requiredText(params, "batch_id"), brand),
        concurrency: concurrency(params, brand),
        label: label === null ? null : branded(BatchLabel, label, brand),
        members: requiredMembers(params).map((key) => branded(BatchMemberKey, key, brand)),
      });
    }
    case BATCH_ADVANCE_MEMBER_REQUEST_KIND:
      return encodeAdvanceMember(id, {
        batch_id: branded(BatchId, requiredText(params, "batch_id"), brand),
        expected_revision: branded(
          BatchRevision,
          BigInt(requiredText(params, "expected_revision")),
          brand,
        ),
        last_sequence: branded(LastSequence, BigInt(requiredText(params, "last_sequence")), brand),
        member_key: branded(BatchMemberKey, requiredText(params, "member_key"), brand),
        // Deliberately unbranded: the vocabulary is closed and the builder is
        // where an untyped caller's undefined progress has to be stopped, since
        // nothing at runtime carries the brand that would have stopped it here.
        state: requiredText(params, "state") as MemberProgress,
      });
    case BATCH_LIST_BATCHES_REQUEST_KIND:
      return encodeListBatches(id, {
        page_size: branded(BatchPageSize, BigInt(requiredText(params, "page_size")), brand),
        since: branded(BatchCursor, BigInt(requiredText(params, "since")), brand),
      });
    case BATCH_BATCH_DETAIL_REQUEST_KIND:
      return encodeBatchDetail(id, {
        batch_id: branded(BatchId, requiredText(params, "batch_id"), brand),
      });
    default:
      throw new Error(`the corpus names request kind ${kind}, which nothing here builds`);
  }
}

/**
 * How one decoded policy is spelled, under the corpus's dotted prefix.
 *
 * This is where the union earns its keep: a sequential policy has no ceiling to
 * read, and reaching for one is a compile error rather than an `undefined` that
 * would spell as `null` and compare equal to the right answer by accident.
 */
function concurrencySpelling(
  prefix: string,
  value: BatchConcurrency,
): Record<string, string> {
  return {
    [`${prefix}concurrency.kind`]: value.kind,
    [`${prefix}concurrency.max_in_flight`]:
      value.kind === "bounded_parallel" ? value.max_in_flight.toString() : "null",
  };
}

/** How one decoded batch row is spelled. */
function recordSpelling(prefix: string, value: BatchRecord): Record<string, string> {
  return {
    [`${prefix}batch_id`]: value.batch_id,
    [`${prefix}created_at_ms`]: value.created_at_ms.toString(),
    [`${prefix}entry_id`]: value.entry_id.toString(),
    [`${prefix}label`]: value.label === null ? "null" : value.label,
    [`${prefix}revision`]: value.revision.toString(),
    ...concurrencySpelling(prefix, value.concurrency),
  };
}

/** How one decoded member row is spelled. */
function memberSpelling(prefix: string, value: BatchMemberRecord): Record<string, string> {
  return {
    [`${prefix}key`]: value.key,
    [`${prefix}last_sequence`]: value.last_sequence.toString(),
    [`${prefix}ordinal`]: value.ordinal.toString(),
    [`${prefix}revision`]: value.revision.toString(),
    [`${prefix}state`]: value.state,
    [`${prefix}updated_at_ms`]: value.updated_at_ms.toString(),
  };
}

/** How one decoded response is spelled, in the corpus's own encoding. */
function spelling(response: BatchResponse): Record<string, string> {
  switch (response.kind) {
    case "batch_registered": {
      const value = response.value;
      return {
        batch_id: value.batch_id,
        created_at_ms: value.created_at_ms.toString(),
        entry_id: value.entry_id.toString(),
        member_count: value.member_count.toString(),
        request_id: value.request_id,
        revision: value.revision.toString(),
      };
    }
    case "member_advanced": {
      const value = response.value;
      return {
        batch_id: value.batch_id,
        last_sequence: value.last_sequence.toString(),
        member_key: value.member_key,
        ordinal: value.ordinal.toString(),
        request_id: value.request_id,
        revision: value.revision.toString(),
        state: value.state,
        updated_at_ms: value.updated_at_ms.toString(),
      };
    }
    case "batch_list_result": {
      const value = response.value;
      const out: Record<string, string> = {
        "batches.len": String(value.batches.length),
        more: String(value.more),
        next_cursor: value.next_cursor === null ? "null" : value.next_cursor.toString(),
        request_id: value.request_id,
      };
      value.batches.forEach((carried, index) => {
        Object.assign(out, recordSpelling(`batches.${index}.`, carried));
      });
      return out;
    }
    case "batch_detail_result": {
      const value = response.value;
      const out: Record<string, string> = {
        "members.len": String(value.members.length),
        request_id: value.request_id,
        // The rolled-up state, which is never stored anywhere: it is derived
        // beside the members that justify it, and this side holds it to the
        // closed vocabulary rather than re-deriving it.
        state: value.state,
        ...recordSpelling("batch.", value.batch),
      };
      value.members.forEach((carried, index) => {
        Object.assign(out, memberSpelling(`members.${index}.`, carried));
      });
      return out;
    }
    case "revision_conflict": {
      const value = response.value;
      return {
        durable_revision: value.durable_revision.toString(),
        expected_revision: value.expected_revision.toString(),
        request_id: value.request_id,
      };
    }
    case "refused":
      return {refusal: response.value.refusal, request_id: response.value.request_id};
    case "undecoded":
      return {request_id: response.request_id, response_kind: response.response_kind};
    default:
      // A response arm added to the generated union without a spelling here
      // fails to compile rather than going unreported.
      return assertNeverBatchResponse(response);
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
    const decoded = decodeBatchResponse(unhex(fixture.canonical_hex));
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

/**
 * Decode one recorded response, reporting a refusal rather than raising it.
 *
 * The sweeps below re-read fixtures the loop above already decoded, so a
 * payload that stopped decoding must arrive here as a named problem beside the
 * others. An uncaught throw would end the run at whichever fixture happened to
 * come first and hide every disagreement after it.
 */
function decode(fixture: ResponseFixture): BatchResponse | undefined {
  try {
    return decodeBatchResponse(unhex(fixture.canonical_hex));
  } catch (error) {
    problems.push(`${fixture.id}: decoding threw ${String(error)}`);
    return undefined;
  }
}

// The rolled-up state a detail read carries is one of the six words and nothing
// else. The generated decoder holds the vocabulary and not the derivation, so
// this asserts exactly what this side is worth: the word survives the round trip
// and is closed.
const ROLLUPS = ["pending", "running", "completed", "failed", "cancelled", "mixed"];
const rollupsSeen = new Set<string>();
for (const fixture of corpus.responses) {
  const decoded = decode(fixture);
  if (decoded === undefined) continue;
  if (decoded.kind !== "batch_detail_result") continue;
  const state: string = decoded.value.state;
  if (!ROLLUPS.includes(state)) {
    problems.push(`${fixture.id}: a batch rolled up to ${state}, which is not one of the six`);
  }
  rollupsSeen.add(state);
  // A detail read carries the members its rollup was derived from. A page does
  // not, and must not: a listing has nothing to roll up from, so a `state` on a
  // batch row would be a summary with no evidence beside it.
  if (decoded.value.members.length === 0) {
    problems.push(`${fixture.id}: a detail carried a rollup over no member at all`);
  }
}
if (rollupsSeen.size < 3) {
  problems.push(
    `the corpus exercises ${rollupsSeen.size} rolled-up batch states; fewer than three leaves the ` +
      "rollup vocabulary barely measured",
  );
}

// Every decoded advance receipt is at revision two or above, because the
// generated type admits nothing else. Asserting it here is not redundant with
// the decode refusals: it proves the column survives the round trip rather than
// merely that a wrong one is refused.
for (const fixture of corpus.responses) {
  const decoded = decode(fixture);
  if (decoded === undefined) continue;
  if (decoded.kind !== "member_advanced") continue;
  if (decoded.value.revision < 2n) {
    problems.push(`${fixture.id}: an advance receipt decoded at revision ${decoded.value.revision}`);
  }
  if (decoded.value.state === "unsubmitted") {
    problems.push(
      `${fixture.id}: an advance receipt decoded as unsubmitted, which no advance can leave behind`,
    );
  }
}

// Both concurrency shapes survive a decode, and the union keeps them apart. A
// surface that carried a nullable ceiling would pass every byte comparison in
// this file and still let a caller ask a sequential policy for its bound.
const kindsSeen = new Set<string>();
for (const fixture of corpus.responses) {
  const decoded = decode(fixture);
  if (decoded === undefined) continue;
  const rows: readonly BatchRecord[] =
    decoded.kind === "batch_list_result"
      ? decoded.value.batches
      : decoded.kind === "batch_detail_result"
        ? [decoded.value.batch]
        : [];
  for (const row of rows) {
    kindsSeen.add(row.concurrency.kind);
    if (row.concurrency.kind === "sequential" && "max_in_flight" in row.concurrency) {
      problems.push(`${fixture.id}: a sequential policy decoded carrying a ceiling`);
    }
    if (row.concurrency.kind === "bounded_parallel" && row.concurrency.max_in_flight < 1n) {
      problems.push(`${fixture.id}: a bounded policy decoded with a ceiling that admits nothing`);
    }
  }
}
for (const kind of ["sequential", "bounded_parallel"]) {
  if (!kindsSeen.has(kind)) {
    problems.push(`no decoded response in the corpus carries a ${kind} policy`);
  }
}

// --- decode refusals -------------------------------------------------------

for (const fixture of corpus.decode_refusals) {
  let refusal: unknown;
  try {
    const decoded = decodeBatchResponse(unhex(fixture.payload_hex));
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

// --- the measured gap, on the way in ---------------------------------------

for (const fixture of corpus.rust_only_refusals) {
  try {
    decodeBatchResponse(unhex(fixture.payload_hex));
  } catch (error) {
    problems.push(
      `${fixture.id}: this file now refuses a payload the corpus records as rust-only ` +
        `(${categoryOf(error) ?? String(error)}). That is an improvement, not a failure — ` +
        `move the entry from rust_only_refusals to decode_refusals in tests/codegen.rs.`,
    );
  }
}

// --- the measured gap, on the way out --------------------------------------

for (const fixture of corpus.rust_only_encode_refusals) {
  try {
    encodeFixture(fixture.kind, fixture.request_id, fixture.params, true);
  } catch (error) {
    problems.push(
      `${fixture.id}: this file now refuses a request the corpus records as rust-only ` +
        `(${categoryOf(error) ?? String(error)}). That is an improvement, not a failure — ` +
        `move the entry from rust_only_encode_refusals to encode_refusals in tests/codegen.rs.`,
    );
  }
}

// --- encode refusals -------------------------------------------------------

const stringConstructors: Readonly<Record<string, (value: string) => string>> = {
  BatchId,
  BatchLabel,
  BatchMemberKey,
  RequestId,
};
const counterConstructors: Readonly<Record<string, (value: bigint) => bigint>> = {
  BatchCursor,
  BatchPageSize,
  BatchRevision,
  ConcurrencyCeiling,
  LastSequence,
};

/** The value a named constructor is applied to, read from the fixture. */
function refusedValue(fixture: EncodeRefusalFixture): string | undefined {
  if (fixture.refused_param === undefined) return undefined;
  if (fixture.refused_param === "request_id") return fixture.request_id;
  const value = (fixture.params as Readonly<Record<string, unknown>>)[fixture.refused_param];
  return typeof value === "string" ? value : undefined;
}

for (const fixture of corpus.encode_refusals) {
  // The branded constructor refuses the value on its own, and names what was
  // wrong with it. This is the refusal a caller who builds a value gets; the
  // encoder's category below is what a message-level refusal looks like.
  if (fixture.refused_by !== undefined) {
    const stringMake = stringConstructors[fixture.refused_by];
    const counterMake = counterConstructors[fixture.refused_by];
    const offending = refusedValue(fixture);
    let apply: (() => unknown) | undefined;
    if (offending !== undefined) {
      if (stringMake !== undefined) {
        apply = () => stringMake(offending);
      } else if (counterMake !== undefined) {
        apply = () => counterMake(BigInt(offending));
      }
    }
    if (apply === undefined) {
      problems.push(
        `${fixture.id}: no constructor named ${fixture.refused_by} takes ${String(fixture.refused_param)}`,
      );
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

if (corpus.protocol !== BATCH_CONTROL_PROTOCOL) {
  problems.push(
    `the corpus is for ${corpus.protocol}, this surface speaks ${BATCH_CONTROL_PROTOCOL}`,
  );
}

// All four vocabularies fail closed, so the corpus is required to prove each one
// of them does. A corpus that lost the batch-state case would leave a whole
// closed vocabulary unmeasured while every assertion above still passed.
const refusedSpellings = corpus.decode_refusals.map((fixture) => fixture.id);
for (const vocabulary of [
  "member-progress",
  "batch-state",
  "concurrency-kind",
  "refusal",
]) {
  if (!refusedSpellings.includes(`${vocabulary}-undefined-spelling`)) {
    problems.push(
      `the corpus exercises no undefined ${vocabulary}, so that vocabulary's closure is unmeasured`,
    );
  }
}

// Both ends of the advance pin, and both ends of the concurrency ceiling. A
// corpus carrying only one end of either would be satisfied by a decoder that
// merely required a positive number, which is not the claim either makes.
for (const [category, minimum, what] of [
  ["batch_control_not_an_advance", 2, "advance revision"],
  ["batch_concurrency_ceiling_zero", 1, "ceiling floor"],
  ["batch_concurrency_ceiling_unreachable", 1, "ceiling roof"],
] as const) {
  const seen = corpus.decode_refusals.filter((fixture) => fixture.category === category).length;
  if (seen < minimum) {
    problems.push(
      `the corpus exercises ${seen} ${category} refusals, so the ${what} is under-measured`,
    );
  }
}

// The maximal registration is the reason this lane's membership ceiling is half
// the batch model's, so a corpus that lost it would stop measuring the frame
// arithmetic the constant is derived from.
const maximal = corpus.requests.find((fixture) => fixture.params.members_rule === "maximal");
if (maximal === undefined) {
  problems.push("the corpus carries no maximal registration, so the frame arithmetic is unmeasured");
} else if (ruledMembership("maximal").length !== 128) {
  problems.push(
    `the maximal membership rule builds ${ruledMembership("maximal").length} members, not 128`,
  );
}

// Every member progress spelling reaches a decoded answer or a built request,
// not merely a refused one: a surface that could refuse `skipped` but could not
// carry `timed_out` would pass every check above.
const carried = new Set<string>();
for (const fixture of corpus.responses) {
  for (const [key, value] of Object.entries(fixture.decoded)) {
    if (key.endsWith("state") || key.endsWith(".state")) carried.add(value);
  }
}
for (const fixture of corpus.requests) {
  const state = fixture.params.state;
  if (state !== undefined) carried.add(state);
}
for (const spelled of ["unsubmitted", "ready", "running", "completed", "cancelled", "timed_out"]) {
  if (!carried.has(spelled)) {
    problems.push(`no request or decoded response in the corpus carries the member state ${spelled}`);
  }
}

writeFileSync(producedPath, `${produced.join("\n")}\n`);

for (const problem of problems) console.error(problem);
console.log(
  `${corpus.requests.length} requests encoded, ` +
    `${corpus.responses.length} responses decoded, ` +
    `${corpus.decode_refusals.length} decode refusals and ` +
    `${corpus.encode_refusals.length} encode refusals matched, ` +
    `${corpus.rust_only_refusals.length} rust-only payloads accepted and ` +
    `${corpus.rust_only_encode_refusals.length} rust-only requests built as recorded; ` +
    `${problems.length} problems`,
);
process.exit(problems.length === 0 ? 0 : 1);
