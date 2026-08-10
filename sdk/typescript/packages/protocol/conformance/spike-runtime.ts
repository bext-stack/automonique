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

if (failures.length > 0) {
  for (const failure of failures) console.error(`FAIL ${failure}`);
  process.exit(1);
}
console.log("all runtime property checks passed");
