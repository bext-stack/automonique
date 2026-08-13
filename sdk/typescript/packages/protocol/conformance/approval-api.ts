// SPDX-License-Identifier: Apache-2.0

// Cross-language conformance runner for the generated Approval surface.
//
// The corpus at `rust/crates/automonique-protocol/fixtures/approval-api-v1.json`
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
//                      bytes, byte for byte — including a cursor at the wire's
//                      integer ceiling, the largest page this protocol serves,
//                      and a key whose every character escapes to two bytes;
//   responses          the generated decoder recovers the recorded fields of
//                      pages, receipts, records and conflicts, including
//                      counters at the ceiling that a `number` would round;
//   decode refusals    the same payloads are refused, under the same category
//                      spellings Rust reports — including all four fail-closed
//                      vocabularies and both ends of the write-once revision;
//   encode refusals    the same values are refused while building, under the
//                      same categories;
//   rust-only          payloads Rust refuses for a rule relating two fields of
//                      a decoded message are *accepted* here, because the
//                      generated decoders hold each field's own shape and not
//                      the relations between them. Asserting the acceptance is
//                      what makes the gap a measurement.
//
// What this lane holds that the Automation lane could not: the **write-once
// revision**. `approval_decisions.revision` is pinned to `1` by a database
// CHECK and the ledger has no update path, so "revision is one" is a bound on
// one field's own value rather than a relation between two — and the generated
// `ApprovalRevision` therefore refuses a `0` and a `2` alike, under the category
// `ApprovalRecordView::new` answers. A client can see for itself that the row it
// decoded was never amended.
//
// Every payload this runner produced is written to the file named as the second
// argument, one `<id> <hex>` line each, so the Rust side can compare the bytes
// itself and feed them back through `ApprovalRequest::from_canonical_bytes`.
//
// Counters travel through the corpus as decimal strings: `JSON.parse` reads
// numbers as doubles, and `9223372036854775807` would come back as
// `9223372036854775808` without a word of complaint.
//
// Usage:
//   bun run conformance/approval-api.ts <corpus.json> <produced.txt>

import {readFileSync, writeFileSync} from "node:fs";

import {
  APPROVAL_APPROVAL_DETAIL_REQUEST_KIND,
  APPROVAL_APPROVALS_BY_SUBJECT_REQUEST_KIND,
  APPROVAL_LIST_APPROVALS_REQUEST_KIND,
  APPROVAL_PROTOCOL,
  APPROVAL_RECORD_APPROVAL_REQUEST_KIND,
  ApprovalCursor,
  ApprovalKey,
  ApprovalPageSize,
  ApprovalSubject,
  Decider,
  RefusalError,
  RequestId,
  ValidationError,
  assertNeverApprovalResponse,
  decodeApprovalResponse,
  encodeApprovalDetail,
  encodeApprovalsBySubject,
  encodeListApprovals,
  encodeRecordApproval,
  type ApprovalDecision,
  type ApprovalRecord,
  type ApprovalResponse,
} from "../generated/index.ts";

interface Params {
  readonly approval_key?: string;
  readonly decider?: string;
  readonly decision?: string;
  readonly page_size?: string;
  readonly since?: string;
  readonly subject?: string;
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
  console.error("usage: approval-api.ts <corpus.json> <produced.txt>");
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

function requiredText(
  params: Params,
  name: "approval_key" | "decider" | "decision" | "page_size" | "since" | "subject",
): string {
  const value = params[name];
  if (value === undefined) throw new Error(`fixture parameter ${name} is missing`);
  return value;
}

function encodeFixture(
  kind: string,
  requestIdText: string,
  params: Params,
  brand: boolean,
): Uint8Array {
  const id = branded(RequestId, requestIdText, brand);
  switch (kind) {
    case APPROVAL_RECORD_APPROVAL_REQUEST_KIND:
      return encodeRecordApproval(id, {
        approval_key: branded(ApprovalKey, requiredText(params, "approval_key"), brand),
        decider: branded(Decider, requiredText(params, "decider"), brand),
        // Deliberately unbranded: the vocabulary is closed and the builder is
        // where an untyped caller's undefined decision has to be stopped, since
        // nothing at runtime carries the brand that would have stopped it here.
        decision: requiredText(params, "decision") as ApprovalDecision,
        subject: branded(ApprovalSubject, requiredText(params, "subject"), brand),
      });
    case APPROVAL_LIST_APPROVALS_REQUEST_KIND:
      return encodeListApprovals(id, {
        page_size: branded(ApprovalPageSize, BigInt(requiredText(params, "page_size")), brand),
        since: branded(ApprovalCursor, BigInt(requiredText(params, "since")), brand),
      });
    case APPROVAL_APPROVAL_DETAIL_REQUEST_KIND:
      return encodeApprovalDetail(id, {
        approval_key: branded(ApprovalKey, requiredText(params, "approval_key"), brand),
      });
    case APPROVAL_APPROVALS_BY_SUBJECT_REQUEST_KIND:
      return encodeApprovalsBySubject(id, {
        page_size: branded(ApprovalPageSize, BigInt(requiredText(params, "page_size")), brand),
        since: branded(ApprovalCursor, BigInt(requiredText(params, "since")), brand),
        subject: branded(ApprovalSubject, requiredText(params, "subject"), brand),
      });
    default:
      throw new Error(`the corpus names request kind ${kind}, which nothing here builds`);
  }
}

/** How one decoded record is spelled, under the corpus's dotted prefix. */
function recordSpelling(prefix: string, value: ApprovalRecord): Record<string, string> {
  return {
    [`${prefix}approval_key`]: value.approval_key,
    [`${prefix}decided_at_ms`]: value.decided_at_ms.toString(),
    [`${prefix}decider`]: value.decider,
    [`${prefix}decision`]: value.decision,
    [`${prefix}entry_id`]: value.entry_id.toString(),
    // Always one, and the generated type is what refuses anything else. Spelled
    // out rather than dropped: a runner that omitted it would compare equal to
    // one that never read the column at all.
    [`${prefix}revision`]: value.revision.toString(),
    [`${prefix}subject`]: value.subject,
  };
}

/** How one decoded response is spelled, in the corpus's own encoding. */
function spelling(response: ApprovalResponse): Record<string, string> {
  switch (response.kind) {
    case "approval_recorded": {
      const value = response.value;
      return {
        approval_key: value.approval_key,
        decided_at_ms: value.decided_at_ms.toString(),
        decision: value.decision,
        disposition: value.disposition,
        entry_id: value.entry_id.toString(),
        request_id: value.request_id,
      };
    }
    case "approval_list_result": {
      const value = response.value;
      const out: Record<string, string> = {
        "approvals.len": String(value.approvals.length),
        more: String(value.more),
        next_cursor: value.next_cursor === null ? "null" : value.next_cursor.toString(),
        request_id: value.request_id,
      };
      value.approvals.forEach((carried, index) => {
        Object.assign(out, recordSpelling(`approvals.${index}.`, carried));
      });
      return out;
    }
    case "approval_detail_result": {
      const value = response.value;
      return {...recordSpelling("", value), request_id: value.request_id};
    }
    case "approval_conflict": {
      const value = response.value;
      return {
        entry_id: value.entry_id.toString(),
        field: value.field,
        recorded_decider: value.recorded_decider,
        recorded_decision: value.recorded_decision,
        recorded_subject: value.recorded_subject,
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
      return assertNeverApprovalResponse(response);
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
    const decoded = decodeApprovalResponse(unhex(fixture.canonical_hex));
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
function decode(fixture: ResponseFixture): ApprovalResponse | undefined {
  try {
    return decodeApprovalResponse(unhex(fixture.canonical_hex));
  } catch (error) {
    problems.push(`${fixture.id}: decoding threw ${String(error)}`);
    return undefined;
  }
}

// A receipt and a record are different answers that share three field names.
// One says a write landed and carries the disposition that says whether *this*
// call landed it; the other reports a row an operator can read, with the subject
// and the decider the ledger stored. A reader that handed back a receipt as a
// record would be inventing the two columns it does not carry.
for (const fixture of corpus.responses) {
  if (fixture.outcome !== "accepted") continue;
  // Decoded again rather than carried over from the loop above, because that
  // loop reports a throw and moves on: this sweep must see the value or say it
  // could not, and never read a stale one.
  const decoded = decode(fixture);
  if (decoded === undefined) continue;
  if (decoded.kind !== "approval_recorded") {
    problems.push(`${fixture.id}: a recorded decision decoded as ${decoded.kind}`);
    continue;
  }
  const body = decoded.value as object;
  if ("subject" in body || "decider" in body || "revision" in body) {
    problems.push(`${fixture.id}: a receipt carried a record's columns`);
  }
  if (!("disposition" in body)) {
    problems.push(`${fixture.id}: a receipt lost the disposition, which is what it is for`);
  }
}

// Every decoded record carries revision one, because the generated type admits
// nothing else. Asserting it here is not redundant with the decode refusals: it
// proves the column survives the round trip rather than merely that a wrong one
// is refused.
for (const fixture of corpus.responses) {
  const decoded = decode(fixture);
  if (decoded === undefined) continue;
  const rows: readonly ApprovalRecord[] =
    decoded.kind === "approval_list_result"
      ? decoded.value.approvals
      : decoded.kind === "approval_detail_result"
        ? [decoded.value]
        : [];
  for (const row of rows) {
    if (row.revision !== 1n) {
      problems.push(`${fixture.id}: a write-once row decoded at revision ${row.revision}`);
    }
  }
}

// --- decode refusals -------------------------------------------------------

for (const fixture of corpus.decode_refusals) {
  let refusal: unknown;
  try {
    const decoded = decodeApprovalResponse(unhex(fixture.payload_hex));
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
    decodeApprovalResponse(unhex(fixture.payload_hex));
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
  ApprovalKey,
  ApprovalSubject,
  Decider,
  RequestId,
};
const counterConstructors: Readonly<Record<string, (value: bigint) => bigint>> = {
  ApprovalCursor,
  ApprovalPageSize,
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

if (corpus.protocol !== APPROVAL_PROTOCOL) {
  problems.push(`the corpus is for ${corpus.protocol}, this surface speaks ${APPROVAL_PROTOCOL}`);
}

// All four vocabularies fail closed, so the corpus is required to prove each one
// of them does. A corpus that lost the disposition case would leave a whole
// closed vocabulary unmeasured while every assertion above still passed.
const refusedSpellings = corpus.decode_refusals.map((fixture) => fixture.id);
for (const vocabulary of ["decision", "disposition", "conflict-field", "refusal"]) {
  if (!refusedSpellings.includes(`${vocabulary}-undefined-spelling`)) {
    problems.push(
      `the corpus exercises no undefined ${vocabulary}, so that vocabulary's closure is unmeasured`,
    );
  }
}

// Both ends of the write-once pin. A corpus carrying only the `0` case would be
// satisfied by a decoder that merely required a positive revision, which is not
// the claim this column makes.
if (corpus.decode_refusals.filter((fixture) => fixture.category === "approval_row_amended").length < 2) {
  problems.push(
    "the corpus exercises fewer than two approval_row_amended refusals, so the write-once " +
      "domain is only measured from one end",
  );
}

// Both decisions and both dispositions reach a decoded answer, not just a
// refused one: a surface that could refuse `abstained` but could not carry
// `denied` would pass every check above.
const decodedValues = corpus.responses.flatMap((fixture) => Object.values(fixture.decoded));
for (const spelled of ["granted", "denied", "recorded", "already_recorded"]) {
  if (!decodedValues.includes(spelled)) {
    problems.push(`no decoded response in the corpus carries ${spelled}`);
  }
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
