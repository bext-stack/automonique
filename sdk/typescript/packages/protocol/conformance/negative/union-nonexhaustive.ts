// SPDX-License-Identifier: Apache-2.0

// Guards union exhaustiveness. A switch missing a variant must not compile.

import {assertNeverTurnOutcome, type TurnOutcome} from "../../generated/spike.ts";

export function describe(outcome: TurnOutcome): string {
  switch (outcome.kind) {
    case "completed":
      return outcome.text;
    case "failed":
      return outcome.reason;
    // "cancelled" is deliberately unhandled.
    default:
      return assertNeverTurnOutcome(outcome);
  }
}
