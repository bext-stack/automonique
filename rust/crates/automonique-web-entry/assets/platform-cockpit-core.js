// SPDX-License-Identifier: Elastic-2.0

"use strict";

((root) => {
  function validDecimal(value, allowZero = true) {
    return typeof value === "string"
      && /^(0|[1-9][0-9]*)$/.test(value)
      && (allowZero || value !== "0");
  }

  function decimalGreater(left, right) {
    if (!validDecimal(left) || !validDecimal(right)) return false;
    return left.length !== right.length ? left.length > right.length : left > right;
  }

  function receiptDirective(view) {
    if (!view || view.state === "ambiguous") return "reconcile";
    if (view.state === "refused") return "settled";
    if (view.state !== "receipt") return "invalid";
    const receipt = view.receipt || {};
    if (receipt.lifecycle === "ambiguous" || receipt.lifecycle === "pending") return "reconcile";
    if (receipt.lifecycle === "refused" || ["rejected", "conflict"].includes(receipt.outcome)) return "settled";
    return receipt.lifecycle === "terminal" ? "revision_fence" : "invalid";
  }

  root.AutomoniquePlatformCockpit = Object.freeze({
    decimalGreater,
    receiptDirective,
    validDecimal,
  });
})(globalThis);
