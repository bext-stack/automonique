// SPDX-License-Identifier: Apache-2.0

// Cross-language conformance runner for the generated admin command surface.
//
// The corpus at `rust/crates/automonique-protocol/fixtures/admin-command-v1.json`
// is generated from the shipped Rust constructors: every canonical byte string
// in it was produced by encoding a real message, and every refusal category was
// read back from the error Rust returned for that exact input. Rust is the wire
// source of truth, so a disagreement is fixed in whichever implementation is
// wrong — never in the corpus.
//
// What this runner measures, using only `../generated/`:
//
//   requests           the generated builders produce the recorded canonical
//                      bytes, byte for byte;
//   responses          the generated decoder recovers the recorded fields,
//                      including a submission identity at the wire's ceiling
//                      that a `number` would round;
//   undecoded          a kind this protocol defines and this surface does not
//                      decode is reported as such, not refused;
//   decode refusals    the same payloads are refused, under the same category
//                      spellings Rust reports;
//   encode refusals    the same values are refused while building, under the
//                      same categories — and the branded constructors refuse
//                      them on their own, with the violation each names.
//
// Every payload this runner produced is written to the file named as the second
// argument, one `<id> <hex>` line each, so the Rust side can compare the bytes
// itself and feed them back through `AdminRequest::from_canonical_bytes`. That
// second direction is the only comparison the maximal `submit_run` gets here:
// 49 KiB of hex is not a reviewable literal, so the corpus carries the rule its
// document is built from rather than the document.
//
// Usage:
//   bun run conformance/admin-command.ts <corpus.json> <produced.txt>

import {readFileSync, writeFileSync} from "node:fs";

import {
  ADMIN_PROTOCOL,
  IntakeActor,
  IntakeReason,
  PAUSE_INTAKE_REQUEST_KIND,
  RESUME_INTAKE_REQUEST_KIND,
  RefusalError,
  RequestId,
  RunSubmissionKey,
  SHUTDOWN_REQUEST_KIND,
  STATUS_REQUEST_KIND,
  SUBMIT_RUN_REQUEST_KIND,
  SpecDigest,
  ValidationError,
  assertNeverAdminResponse,
  decodeAdminResponse,
  encodePauseIntake,
  encodeResumeIntake,
  encodeShutdown,
  encodeStatus,
  encodeSubmitRun,
  type AdminResponse,
} from "../generated/index.ts";

interface DocumentRule {
  readonly seed: number;
  readonly step: number;
}

interface Params {
  readonly actor?: string;
  readonly reason?: string;
  readonly document_hex?: string;
  readonly document_length?: number;
  readonly idempotency_key?: string;
  readonly spec_digest?: string;
}

interface RequestFixture {
  readonly id: string;
  readonly kind: string;
  readonly note: string;
  readonly params: Params;
  readonly request_id: string;
  readonly canonical_bytes: number;
  readonly canonical_hex?: string;
}

interface ResponseFixture {
  readonly id: string;
  readonly kind: string;
  readonly note: string;
  readonly canonical_hex: string;
  readonly decoded: Readonly<Record<string, string>>;
}

interface UndecodedFixture {
  readonly id: string;
  readonly kind: string;
  readonly note: string;
  readonly payload_hex: string;
  readonly request_id: string;
}

interface DecodeRefusalFixture {
  readonly id: string;
  readonly note: string;
  readonly category: string;
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
  readonly document_rule: DocumentRule;
  readonly requests: readonly RequestFixture[];
  readonly responses: readonly ResponseFixture[];
  readonly undecoded_responses: readonly UndecodedFixture[];
  readonly decode_refusals: readonly DecodeRefusalFixture[];
  readonly encode_refusals: readonly EncodeRefusalFixture[];
}

const corpusPath = process.argv[2];
const producedPath = process.argv[3];
if (corpusPath === undefined || producedPath === undefined) {
  console.error("usage: admin-command.ts <corpus.json> <produced.txt>");
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

/** The document rule, read from the corpus rather than restated here. */
function ruledDocument(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    bytes[index] = (corpus.document_rule.seed + (index % 256) * corpus.document_rule.step) % 256;
  }
  return bytes;
}

function documentOf(params: Params): Uint8Array {
  if (params.document_hex !== undefined) return unhex(params.document_hex);
  if (params.document_length !== undefined) return ruledDocument(params.document_length);
  throw new Error("a submit_run fixture carries a document or the rule to build one");
}

function required(params: Params, name: "actor" | "reason" | "idempotency_key" | "spec_digest"): string {
  const value = params[name];
  if (value === undefined) throw new Error(`fixture parameter ${name} is missing`);
  return value;
}

/**
 * Apply a branded constructor, or bypass it.
 *
 * Bypassing is the point of the refusal cases: a brand exists only in the type
 * checker, so the value an untyped caller reaches an encoder with is exactly
 * this cast. What the encoder does with it is what the encoder is worth.
 */
function branded<T extends string>(make: (value: string) => T, value: string, brand: boolean): T {
  return brand ? make(value) : (value as T);
}

function encodeFixture(
  kind: string,
  requestIdText: string,
  params: Params,
  brand: boolean,
): Uint8Array {
  const id = branded(RequestId, requestIdText, brand);
  switch (kind) {
    case STATUS_REQUEST_KIND:
      return encodeStatus(id);
    case SHUTDOWN_REQUEST_KIND:
      return encodeShutdown(id);
    case PAUSE_INTAKE_REQUEST_KIND:
      return encodePauseIntake(id, {
        actor: branded(IntakeActor, required(params, "actor"), brand),
        reason: branded(IntakeReason, required(params, "reason"), brand),
      });
    case RESUME_INTAKE_REQUEST_KIND:
      return encodeResumeIntake(id, {
        actor: branded(IntakeActor, required(params, "actor"), brand),
      });
    case SUBMIT_RUN_REQUEST_KIND:
      return encodeSubmitRun(id, {
        document: documentOf(params),
        idempotency_key: branded(RunSubmissionKey, required(params, "idempotency_key"), brand),
        spec_digest: branded(SpecDigest, required(params, "spec_digest"), brand),
      });
    default:
      throw new Error(`the corpus names request kind ${kind}, which nothing here builds`);
  }
}

/** How one decoded response is spelled, in the corpus's own encoding. */
function spelling(response: AdminResponse): Record<string, string> {
  switch (response.kind) {
    case "run_accepted": {
      const value = response.value;
      return {
        replay: String(value.replay),
        request_id: value.request_id,
        run_id: value.run_id,
        spec_digest: value.spec_digest,
        submission_id: value.submission_id.toString(),
      };
    }
    case "intake_paused":
    case "intake_resumed": {
      const value = response.value;
      return {
        pause_id: value.pause_id.toString(),
        request_id: value.request_id,
        revision: value.revision.toString(),
      };
    }
    case "refused":
      return {category: response.value.category, request_id: response.value.request_id};
    case "shutdown_accepted":
      return {request_id: response.value.request_id};
    case "undecoded":
      return {request_id: response.request_id, response_kind: response.response_kind};
    default:
      // A response arm added to the generated union without a spelling here
      // fails to compile rather than going unreported.
      return assertNeverAdminResponse(response);
  }
}

function sameSpelling(actual: Record<string, string>, expected: Readonly<Record<string, string>>): string | undefined {
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
  // The shared codec's refusals reach here unchanged: an envelope this
  // protocol never sees is refused by the codec, under the codec's own
  // category, which is what Rust reports for it too.
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
    if (fixture.canonical_hex !== undefined && hex(payload) !== fixture.canonical_hex) {
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
    const decoded = decodeAdminResponse(unhex(fixture.canonical_hex));
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

for (const fixture of corpus.undecoded_responses) {
  try {
    const decoded = decodeAdminResponse(unhex(fixture.payload_hex));
    if (decoded.kind !== "undecoded") {
      problems.push(
        `${fixture.id}: a defined kind this surface does not decode was reported as ${decoded.kind}`,
      );
      continue;
    }
    if (decoded.response_kind !== fixture.kind) {
      problems.push(
        `${fixture.id}: reported ${decoded.response_kind}, the message carries ${fixture.kind}`,
      );
    }
    if (decoded.request_id !== fixture.request_id) {
      problems.push(`${fixture.id}: the correlation identifier was lost`);
    }
  } catch (error) {
    problems.push(`${fixture.id}: a defined kind was refused: ${String(error)}`);
  }
}

// --- refusals --------------------------------------------------------------

for (const fixture of corpus.decode_refusals) {
  let refusal: unknown;
  try {
    const decoded = decodeAdminResponse(unhex(fixture.payload_hex));
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

const constructors: Readonly<Record<string, (value: string) => string>> = {
  IntakeActor,
  IntakeReason,
  RequestId,
  RunSubmissionKey,
  SpecDigest,
};

for (const fixture of corpus.encode_refusals) {
  // The branded constructor refuses the value on its own, and names what was
  // wrong with it. This is the refusal a caller who builds a value gets; the
  // encoder's category below is what a message-level refusal looks like.
  if (fixture.refused_by !== undefined) {
    const make = constructors[fixture.refused_by];
    const offending =
      fixture.refused_by === "RequestId"
        ? fixture.request_id
        : fixture.refused_by === "IntakeActor"
          ? fixture.params.actor
          : fixture.refused_by === "IntakeReason"
            ? fixture.params.reason
            : fixture.params.idempotency_key;
    if (make === undefined || offending === undefined) {
      problems.push(`${fixture.id}: no constructor named ${fixture.refused_by} takes this value`);
    } else {
      try {
        make(offending);
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

if (corpus.protocol !== ADMIN_PROTOCOL) {
  problems.push(`the corpus is for ${corpus.protocol}, this surface speaks ${ADMIN_PROTOCOL}`);
}

writeFileSync(producedPath, `${produced.join("\n")}\n`);

for (const problem of problems) console.error(problem);
console.log(
  `${corpus.requests.length} requests encoded, ` +
    `${corpus.responses.length} responses decoded, ` +
    `${corpus.undecoded_responses.length} defined-but-undecoded kinds reported, ` +
    `${corpus.decode_refusals.length} decode refusals and ` +
    `${corpus.encode_refusals.length} encode refusals matched; ` +
    `${problems.length} problems`,
);
process.exit(problems.length === 0 ? 0 : 1);
