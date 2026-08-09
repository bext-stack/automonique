// SPDX-License-Identifier: Apache-2.0

import type {
  Capability,
  CapabilitySupport,
  InventoryProviderPolicy,
  LabBudget,
  ProviderPolicy,
} from "./protocol.ts";

export interface InventoryMode {
  readonly id: string;
  readonly unsafe: boolean;
  readonly stability: "stable" | "experimental" | "unlabelled";
  readonly capabilities: Readonly<Record<Capability, CapabilitySupport>>;
}

export interface ProviderInventoryProjection {
  readonly provider: string;
  readonly inventoryDigest: string;
  readonly surfaceDigest: string;
  readonly modes: readonly InventoryMode[];
  readonly fallbackOrder: readonly string[];
}

export type PolicyDecision =
  | {readonly allowed: true; readonly mode: string}
  | {readonly allowed: false; readonly code: string; readonly reason: string};

const DIGEST = /^[0-9a-f]{64}$/;

function denied(code: string, reason: string): PolicyDecision {
  return {allowed: false, code, reason};
}

function validBudget(budget: LabBudget): boolean {
  return (
    Number.isSafeInteger(budget.maxWallMs) && budget.maxWallMs > 0 &&
    Number.isSafeInteger(budget.maxCpuMs) && budget.maxCpuMs > 0 &&
    Number.isSafeInteger(budget.maxDiskBytes) && budget.maxDiskBytes > 0 &&
    Number.isSafeInteger(budget.maxOutputBytes) && budget.maxOutputBytes > 0 &&
    Number.isSafeInteger(budget.maxPids) && budget.maxPids > 0 &&
    Number.isSafeInteger(budget.maxModelCalls) && budget.maxModelCalls >= 0 &&
    Number.isSafeInteger(budget.maxCostMicrounits) && budget.maxCostMicrounits >= 0 &&
    (budget.enforcement === "synthetic_in_process" || budget.enforcement === "host_broker_required")
  );
}

function validateFallbacks(
  policy: InventoryProviderPolicy,
  inventory: ProviderInventoryProjection,
): PolicyDecision | null {
  if (!Array.isArray(policy.explicitFallbackModes)) {
    return denied("implicit_fallback", "Fallback modes must be an explicit array.");
  }
  if (policy.explicitFallbackModes.length !== 0) {
    return denied("fallback_disabled", "Bootstrap selection refuses provider fallback until losses are broker-validated.");
  }
  const seen = new Set<string>();
  let lastIndex = inventory.fallbackOrder.indexOf(policy.mode);
  if (lastIndex < 0) {
    return denied("mode_not_ordered", "The selected mode is absent from the inventory fallback order.");
  }
  for (const mode of policy.explicitFallbackModes) {
    const index = inventory.fallbackOrder.indexOf(mode);
    if (seen.has(mode) || index <= lastIndex) {
      return denied("fallback_order", "Fallback modes must be unique and retain inventory order.");
    }
    seen.add(mode);
    lastIndex = index;
  }
  return null;
}

export function evaluateProviderPolicy(
  policy: ProviderPolicy,
  budget: LabBudget,
  inventory?: ProviderInventoryProjection,
): PolicyDecision {
  if (!validBudget(budget)) {
    return denied("unbounded_budget", "Every resource budget must be a finite safe integer with a positive execution bound.");
  }

  if (policy.kind === "synthetic") {
    if (
      policy.driver !== "in_process_fixture" ||
      policy.network !== "deny" ||
      policy.authentication !== "none" ||
      policy.maxModelCalls !== 0 ||
      policy.maxCostMicrounits !== 0 ||
      budget.maxModelCalls !== 0 ||
      budget.maxCostMicrounits !== 0 ||
      budget.enforcement !== "synthetic_in_process"
    ) {
      return denied("unsafe_synthetic_policy", "Synthetic units must deny network, authentication, model calls and cost.");
    }
    return {allowed: true, mode: "in_process_fixture"};
  }

  if (!inventory || inventory.provider !== policy.provider) {
    return denied("inventory_missing", "The exact provider inventory projection is required.");
  }
  if (
    !DIGEST.test(policy.inventoryDigest) ||
    !DIGEST.test(policy.surfaceDigest) ||
    policy.inventoryDigest !== inventory.inventoryDigest ||
    policy.surfaceDigest !== inventory.surfaceDigest
  ) {
    return denied("inventory_drift", "Provider inventory or surface digest differs from policy.");
  }
  const mode = inventory.modes.find((candidate) => candidate.id === policy.mode);
  if (!mode) {
    return denied("mode_missing", "The requested mode is absent from the pinned inventory.");
  }
  if (mode.unsafe || mode.stability === "experimental") {
    return denied("unsafe_mode", "Unsafe or experimental provider modes are denied by the bootstrap client.");
  }
  if (budget.enforcement !== "host_broker_required") {
    return denied("missing_host_enforcement", "Provider modes require host-broker resource enforcement.");
  }
  const fallbackDenial = validateFallbacks(policy, inventory);
  if (fallbackDenial) return fallbackDenial;

  for (const capability of policy.requiredCapabilities) {
    const support = mode.capabilities[capability];
    const sufficient =
      support === "observed" ||
      (support === "advertised" && policy.minimumEvidence === "advertised");
    if (!sufficient) {
      return denied(
        "capability_evidence",
        `${capability} has ${support} evidence, below ${policy.minimumEvidence}.`,
      );
    }
  }
  return {allowed: true, mode: mode.id};
}
