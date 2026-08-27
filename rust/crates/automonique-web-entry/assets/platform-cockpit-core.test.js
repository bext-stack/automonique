// SPDX-License-Identifier: Elastic-2.0

import { expect, test } from "bun:test";
import "./platform-cockpit-core.js";

const cockpit = globalThis.AutomoniquePlatformCockpit;

test("decimal fences stay exact beyond Number.MAX_SAFE_INTEGER", () => {
  expect(cockpit.validDecimal("9007199254740995", false)).toBe(true);
  expect(cockpit.decimalGreater("9007199254740996", "9007199254740995")).toBe(true);
  expect(cockpit.decimalGreater("9007199254740995", "9007199254740996")).toBe(false);
  expect(cockpit.validDecimal("09007199254740995", false)).toBe(false);
  expect(cockpit.validDecimal(9007199254740995, false)).toBe(false);
});

test("uncertain receipts reconcile without replay and known refusals settle", () => {
  expect(cockpit.receiptDirective({ state: "ambiguous" })).toBe("reconcile");
  expect(cockpit.receiptDirective({ state: "receipt", receipt: { lifecycle: "pending" } })).toBe("reconcile");
  expect(cockpit.receiptDirective({ state: "receipt", receipt: { lifecycle: "terminal", outcome: "completed" } })).toBe("revision_fence");
  expect(cockpit.receiptDirective({ state: "receipt", receipt: { lifecycle: "terminal", outcome: "conflict" } })).toBe("settled");
  expect(cockpit.receiptDirective({ state: "refused", outcome: "conflict" })).toBe("settled");
});
