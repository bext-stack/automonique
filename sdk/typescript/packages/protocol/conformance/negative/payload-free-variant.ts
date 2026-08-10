// SPDX-License-Identifier: Apache-2.0

// Guards the payload-free variant. Reading a payload off "cancelled" must not
// compile; if it does, the variant degenerated into optional-payload.

import {type TurnOutcome} from "../../generated/spike.ts";

const cancelled: TurnOutcome = {kind: "cancelled"};
export const text: string = cancelled.text;
