// SPDX-License-Identifier: Apache-2.0

// Runtime half of the R1-11 codegen spike.
//
// The type checker cannot prove that a generated validator enforces the Rust
// bound at runtime, or that an unknown event survives decoding. Those are
// behaviours, so they are exercised here and the process exits non-zero on any
// failure.

import {
  ApprovalDecision_VALUES,
  MAX_UNKNOWN_EVENT_BYTES,
  RunState_VALUES,
  Sequence,
  Sequence_MAX,
  SessionId,
  SessionId_MAX_BYTES,
  TurnId,
  TurnId_MAX_BYTES,
  ValidationError,
  decodeApprovalDecision,
  decodeEvent,
  decodeRunState,
} from "../generated/spike.ts";

const failures: string[] = [];

function check(name: string, condition: boolean, detail = ""): void {
  if (!condition) failures.push(detail === "" ? name : `${name}: ${detail}`);
}

function throwsValidation(name: string, run: () => unknown): void {
  try {
    run();
    failures.push(`${name}: expected a ValidationError, none was thrown`);
  } catch (error) {
    if (!(error instanceof ValidationError)) {
      failures.push(`${name}: threw ${String(error)} rather than ValidationError`);
    }
  }
}

// Bound preservation: the exact limit is accepted, one byte over is refused, in
// both directions and for both branded domains.
check("turn id at the exact limit", TurnId("t".repeat(TurnId_MAX_BYTES)).length === TurnId_MAX_BYTES);
throwsValidation("turn id one byte over", () => TurnId("t".repeat(TurnId_MAX_BYTES + 1)));
check(
  "session id at the exact limit",
  SessionId("s".repeat(SessionId_MAX_BYTES)).length === SessionId_MAX_BYTES,
);
throwsValidation("session id one byte over", () => SessionId("s".repeat(SessionId_MAX_BYTES + 1)));
throwsValidation("empty identifier", () => TurnId(""));

// The bound is measured in UTF-8 bytes, not code units: a multibyte string that
// fits by length but not by bytes must be refused.
throwsValidation("multibyte over the byte limit", () =>
  TurnId("é".repeat(TurnId_MAX_BYTES)),
);

// Brand distinctness, the half the type checker cannot show. `brand-crossing.ts`
// proves the compiler refuses a cross-domain assignment; nothing of the brand
// survives into the value, because every generated constructor ends in
// `return value as TurnId`. The contract calls a brand that holds at compile
// time and erases at runtime a *partial* pass, so the erasure is measured here
// rather than assumed, and `generated/VERDICT.md` records it as a partial. If
// the emitter is ever changed to carry the brand into the value, these checks
// fail and the verdict has to be revisited instead of quietly going stale.
const brandedTurn = TurnId("abc");
const brandedSession = SessionId("abc");
const brandProperty = (brandedTurn as unknown as {readonly __brand?: unknown}).__brand;
const crossDomainEqual = (brandedTurn as string) === (brandedSession as string);
check(
  "a branded identifier is a plain string at runtime",
  typeof brandedTurn === "string",
  `typeof is ${typeof brandedTurn}; the brand now survives, so VERDICT.md must be revisited`,
);
check(
  "the brand is not carried as a runtime property",
  brandProperty === undefined,
  `__brand is ${String(brandProperty)}; the brand now survives, so VERDICT.md must be revisited`,
);
check(
  "the same text in two domains is indistinguishable at runtime",
  crossDomainEqual,
  'TurnId("abc") and SessionId("abc") no longer compare equal; VERDICT.md must be revisited',
);
check(
  "a branded identifier serializes as a bare string",
  JSON.stringify(brandedTurn) === '"abc"',
  `serialized as ${JSON.stringify(brandedTurn)}; the brand now reaches the wire`,
);

// The compile-time pair for `conformance/negative/brand-crossing.ts`: the same
// import, the same shape of assignment, differing only in the domain. That file
// must not compile and this line must, or its failure would prove nothing about
// branding. `tests/codegen.rs` typechecks this script for exactly that reason.
const sameDomain: TurnId = brandedTurn;
check("a same-domain assignment is accepted", sameDomain === brandedTurn);

// Reported as a measurement so the Rust suite can compare what actually runs
// against what the emitter's text implies and what the verdict records.
const brandRuntimeExistence =
  typeof brandedTurn === "string" && brandProperty === undefined && crossDomainEqual
    ? "erased"
    : "carried";

// Bounded integers survive the signed 64-bit ceiling exactly.
check("sequence at i64::MAX", Sequence(Sequence_MAX) === Sequence_MAX);
throwsValidation("sequence past i64::MAX", () => Sequence(Sequence_MAX + 1n));
throwsValidation("negative sequence", () => Sequence(-1n));

// Security-sensitive enum refuses an undefined value.
check("approval values are generated", ApprovalDecision_VALUES.length === 2);
check("approval allow decodes", decodeApprovalDecision("allow") === "allow");
throwsValidation("approval unknown value", () => decodeApprovalDecision("allow_always"));

// Read-only enum retains an undefined value without giving it meaning.
check("run state values are generated", RunState_VALUES.length === 2);
const known = decodeRunState("running");
check("known run state", known.known && known.value === "running");
const unknown = decodeRunState("hibernated");
check("unknown run state is retained", !unknown.known);
check(
  "unknown run state keeps its spelling",
  !unknown.known && unknown.spelling === "hibernated",
);

// Unknown events neither throw nor vanish, and stay bounded.
const decodedKnown = decodeEvent("turn_completed", "");
check("known event decodes", decodedKnown.known);
const decodedUnknown = decodeEvent("turn_hibernated", "{\"a\":1}");
check("unknown event does not throw", !decodedUnknown.known);
check(
  "unknown event preserves its payload",
  !decodedUnknown.known && decodedUnknown.payload === "{\"a\":1}",
);
check(
  "unknown event preserves its kind",
  !decodedUnknown.known && decodedUnknown.kind === "turn_hibernated",
);
throwsValidation("unknown event payload over the ceiling", () =>
  decodeEvent("turn_hibernated", "x".repeat(MAX_UNKNOWN_EVENT_BYTES + 1)),
);

// Printed before any exit: it is a measurement, and it is most useful in the
// run where something disagrees with it.
console.log(`brand-runtime-existence: ${brandRuntimeExistence}`);

if (failures.length > 0) {
  for (const failure of failures) console.error(`FAIL ${failure}`);
  process.exit(1);
}
console.log("all runtime property checks passed");
