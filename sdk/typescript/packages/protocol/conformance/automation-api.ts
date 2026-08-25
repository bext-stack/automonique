// SPDX-License-Identifier: Apache-2.0

// Cross-language conformance runner for the generated Automation surface.
//
// The corpus at
// `rust/crates/automonique-protocol/fixtures/automation-api-v1.json` is
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
//                      a revision and a cursor at the wire's integer ceiling,
//                      and an automation identity whose every character escapes
//                      to two bytes;
//   responses          the generated decoder recovers the recorded fields of
//                      pages, receipts and records, including counters at the
//                      ceiling that a `number` would round, and a null cause
//                      beside a stated one in the same array;
//   decode refusals    the same payloads are refused, under the same category
//                      spellings Rust reports;
//   encode refusals    the same values are refused while building, under the
//                      same categories — including both halves of the
//                      enablement/cause coupling, which is the one cross-field
//                      rule this generated surface applies;
//   rust-only          payloads Rust refuses for a rule relating two fields of
//                      a decoded message are *accepted* here, because the
//                      generated decoders hold each field's own shape and not
//                      the relations between them. Asserting the acceptance is
//                      what makes the gap a measurement.
//
// Every payload this runner produced is written to the file named as the second
// argument, one `<id> <hex>` line each, so the Rust side can compare the bytes
// itself and feed them back through `AutomationRequest::from_canonical_bytes`.
//
// Counters travel through the corpus as decimal strings: `JSON.parse` reads
// numbers as doubles, and `9223372036854775807` would come back as
// `9223372036854775808` without a word of complaint.
//
// Usage:
//   bun run conformance/automation-api.ts <corpus.json> <produced.txt>

import {readFileSync, writeFileSync} from "node:fs";

import {
  AUTOMATION_AUTOMATION_DETAIL_REQUEST_KIND,
  AUTOMATION_LIST_AUTOMATIONS_REQUEST_KIND,
  AUTOMATION_PROTOCOL,
  AUTOMATION_REGISTER_AUTOMATION_REQUEST_KIND,
  AUTOMATION_SET_ENABLEMENT_REQUEST_KIND,
  AutomationActor,
  AutomationCursor,
  AutomationId,
  AutomationPageSize,
  AutomationPrompt,
  AutomationSchedule,
  AutomationScope,
  DurableRowId,
  PauseReason,
  RefusalError,
  RequestId,
  ScheduledAutomationId,
  ValidationError,
  assertNeverAutomationResponse,
  decodeAutomationResponse,
  encodeAutomationDetail,
  encodeListAutomations,
  encodeRegisterAutomation,
  encodeSetEnablement,
  type AutomationRecord,
  type AutomationResponse,
  type EnablementState,
} from "../generated/index.ts";

interface Params {
  readonly actor?: string;
  readonly automation_id?: string;
  readonly cause?: string | null;
  readonly expected_revision?: string;
  readonly page_size?: string;
  readonly prompt?: string;
  readonly schedule?: string;
  readonly scope?: string;
  readonly since?: string;
  readonly states?: readonly string[] | null;
  readonly target?: string;
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
  console.error("usage: automation-api.ts <corpus.json> <produced.txt>");
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
  name:
    | "actor"
    | "automation_id"
    | "expected_revision"
    | "page_size"
    | "prompt"
    | "schedule"
    | "scope"
    | "since"
    | "target",
): string {
  const value = params[name];
  if (value === undefined) throw new Error(`fixture parameter ${name} is missing`);
  return value;
}

/** A nullable cause, distinguishing an absent key from an explicit null. */
function nullableCause(params: Params, brand: boolean): PauseReason | null {
  const value = params.cause;
  if (value === undefined) throw new Error("a set_enablement fixture carries a cause parameter");
  return value === null ? null : branded(PauseReason, value, brand);
}

function encodeFixture(
  kind: string,
  requestIdText: string,
  params: Params,
  brand: boolean,
): Uint8Array {
  const id = branded(RequestId, requestIdText, brand);
  switch (kind) {
    case AUTOMATION_LIST_AUTOMATIONS_REQUEST_KIND: {
      const states = params.states;
      if (states === undefined) {
        throw new Error("a list_automations fixture carries a states parameter");
      }
      return encodeListAutomations(id, {
        page_size: branded(AutomationPageSize, BigInt(requiredText(params, "page_size")), brand),
        since: branded(AutomationCursor, BigInt(requiredText(params, "since")), brand),
        // The corpus records the caller's order, which is deliberately not the
        // wire's: the builder is what canonicalizes it.
        states: states === null ? null : (states as readonly EnablementState[]),
      });
    }
    case AUTOMATION_REGISTER_AUTOMATION_REQUEST_KIND:
      return encodeRegisterAutomation(id, {
        actor: branded(AutomationActor, requiredText(params, "actor"), brand),
        // A registration's identity is the narrower brand: the occurrence key
        // it derives has to fit the durable submit lane's key bound.
        automation_id: branded(
          ScheduledAutomationId,
          requiredText(params, "automation_id"),
          brand,
        ),
        prompt: branded(AutomationPrompt, requiredText(params, "prompt"), brand),
        schedule: branded(AutomationSchedule, requiredText(params, "schedule"), brand),
        scope: branded(AutomationScope, requiredText(params, "scope"), brand),
      });
    case AUTOMATION_SET_ENABLEMENT_REQUEST_KIND:
      return encodeSetEnablement(id, {
        actor: branded(AutomationActor, requiredText(params, "actor"), brand),
        automation_id: branded(AutomationId, requiredText(params, "automation_id"), brand),
        cause: nullableCause(params, brand),
        expected_revision: branded(
          DurableRowId,
          BigInt(requiredText(params, "expected_revision")),
          brand,
        ),
        target: requiredText(params, "target") as EnablementState,
      });
    case AUTOMATION_AUTOMATION_DETAIL_REQUEST_KIND:
      return encodeAutomationDetail(id, {
        automation_id: branded(AutomationId, requiredText(params, "automation_id"), brand),
      });
    default:
      throw new Error(`the corpus names request kind ${kind}, which nothing here builds`);
  }
}

/** How one decoded record is spelled, under the corpus's dotted prefix. */
function recordSpelling(prefix: string, value: AutomationRecord): Record<string, string> {
  return {
    [`${prefix}actor`]: value.actor,
    [`${prefix}automation_id`]: value.automation_id,
    // A resumed automation has no cause, and the corpus spells that absence
    // rather than dropping the key: a runner that omitted it would compare
    // equal to one that lost the field.
    [`${prefix}cause`]: value.cause === null ? "null" : value.cause,
    [`${prefix}created_at_ms`]: value.created_at_ms.toString(),
    [`${prefix}enablement`]: value.enablement,
    [`${prefix}entry_id`]: value.entry_id.toString(),
    // The job columns are null together for a row registered before jobs
    // existed, and an execution instant is null until there is one. Each
    // absence is spelled rather than dropped, for the reason the cause's is.
    [`${prefix}last_fired_at_ms`]:
      value.last_fired_at_ms === null ? "null" : value.last_fired_at_ms.toString(),
    [`${prefix}next_fire_at_ms`]:
      value.next_fire_at_ms === null ? "null" : value.next_fire_at_ms.toString(),
    [`${prefix}revision`]: value.revision.toString(),
    [`${prefix}schedule`]: value.schedule === null ? "null" : value.schedule,
    [`${prefix}scope`]: value.scope === null ? "null" : value.scope,
    [`${prefix}updated_at_ms`]: value.updated_at_ms.toString(),
  };
}

/** How one decoded response is spelled, in the corpus's own encoding. */
function spelling(response: AutomationResponse): Record<string, string> {
  switch (response.kind) {
    case "automation_accepted": {
      const value = response.value;
      return {
        automation_id: value.automation_id,
        enablement: value.enablement,
        entry_id: value.entry_id.toString(),
        request_id: value.request_id,
        revision: value.revision.toString(),
        updated_at_ms: value.updated_at_ms.toString(),
      };
    }
    case "automation_list_result": {
      const value = response.value;
      const out: Record<string, string> = {
        "automations.len": String(value.automations.length),
        more: String(value.more),
        next_cursor: value.next_cursor === null ? "null" : value.next_cursor.toString(),
        request_id: value.request_id,
      };
      value.automations.forEach((carried, index) => {
        Object.assign(out, recordSpelling(`automations.${index}.`, carried));
      });
      return out;
    }
    case "automation_detail_result": {
      const value = response.value;
      return {
        ...recordSpelling("", value),
        // The one column a listing omits, present exactly when the record
        // carries a job — a relation this surface does not hold and the corpus
        // records as rust-only.
        prompt: value.prompt === null ? "null" : value.prompt,
        request_id: value.request_id,
      };
    }
    case "revision_conflict":
      return {
        durable_revision: response.value.durable_revision.toString(),
        expected_revision: response.value.expected_revision.toString(),
        request_id: response.value.request_id,
      };
    case "refused":
      return {refusal: response.value.refusal, request_id: response.value.request_id};
    case "undecoded":
      return {request_id: response.request_id, response_kind: response.response_kind};
    default:
      // A response arm added to the generated union without a spelling here
      // fails to compile rather than going unreported.
      return assertNeverAutomationResponse(response);
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
    const decoded = decodeAutomationResponse(unhex(fixture.canonical_hex));
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

// A receipt and a record share five field names and are different answers: one
// says a write landed, the other reports a row an operator can read. A reader
// that handed back a receipt as a record would be inventing the registration
// instant and the cause it does not carry. The corpus records which is which;
// this asserts the two stay distinguishable rather than trusting the kind
// string alone.
for (const fixture of corpus.responses) {
  if (fixture.outcome !== "accepted") continue;
  const decoded = decodeAutomationResponse(unhex(fixture.canonical_hex));
  if (decoded.kind !== "automation_accepted") {
    problems.push(`${fixture.id}: an accepted write decoded as ${decoded.kind}`);
  } else if ("cause" in (decoded.value as object) || "created_at_ms" in (decoded.value as object)) {
    problems.push(`${fixture.id}: a receipt carried a record's columns`);
  }
}

// --- decode refusals -------------------------------------------------------

for (const fixture of corpus.decode_refusals) {
  let refusal: unknown;
  try {
    const decoded = decodeAutomationResponse(unhex(fixture.payload_hex));
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
    decodeAutomationResponse(unhex(fixture.payload_hex));
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
  AutomationActor,
  AutomationId,
  AutomationPrompt,
  AutomationSchedule,
  AutomationScope,
  PauseReason,
  RequestId,
  ScheduledAutomationId,
};
const counterConstructors: Readonly<Record<string, (value: bigint) => bigint>> = {
  AutomationCursor,
  AutomationPageSize,
  DurableRowId,
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

if (corpus.protocol !== AUTOMATION_PROTOCOL) {
  problems.push(`the corpus is for ${corpus.protocol}, this surface speaks ${AUTOMATION_PROTOCOL}`);
}

// The coupling is the one cross-field rule this surface applies, so the corpus
// is required to exercise both halves of it. A corpus that lost the `enabled`
// case would leave half the rule unmeasured while every assertion above passed.
for (const half of ["automation_cause_required", "automation_cause_forbidden"]) {
  if (!corpus.encode_refusals.some((fixture) => fixture.category === half)) {
    problems.push(`the corpus exercises no ${half} refusal, so half the coupling is unmeasured`);
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
