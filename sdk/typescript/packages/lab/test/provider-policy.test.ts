// SPDX-License-Identifier: Apache-2.0

import {describe, expect, test} from "bun:test";
import {
  CAPABILITIES,
  evaluateProviderPolicy,
  type CapabilitySupport,
  type ProviderInventoryProjection,
} from "../src/index.ts";

const digestA = "a".repeat(64);
const digestB = "b".repeat(64);
const budget = {maxWallMs: 1_000, maxCpuMs: 500, maxDiskBytes: 16_384, maxOutputBytes: 4_096, maxPids: 2, maxModelCalls: 0, maxCostMicrounits: 0, enforcement: "synthetic_in_process"} as const;

function capabilities(overrides: Partial<Record<(typeof CAPABILITIES)[number], CapabilitySupport>> = {}) {
  return Object.fromEntries(CAPABILITIES.map((capability) => [capability, overrides[capability] ?? "unknown"])) as Record<(typeof CAPABILITIES)[number], CapabilitySupport>;
}

const inventory: ProviderInventoryProjection = {
  provider: "opencode",
  inventoryDigest: digestA,
  surfaceDigest: digestB,
  fallbackOrder: ["http_server", "acp", "json_run"],
  modes: [
    {id: "http_server", unsafe: false, stability: "unlabelled", capabilities: capabilities()},
    {id: "acp", unsafe: false, stability: "unlabelled", capabilities: capabilities()},
    {id: "json_run", unsafe: false, stability: "stable", capabilities: capabilities({create: "advertised", observe: "advertised", resume: "advertised", model: "advertised"})},
  ],
};

const synthetic = {
  kind: "synthetic",
  driver: "in_process_fixture",
  network: "deny",
  authentication: "none",
  maxModelCalls: 0,
  maxCostMicrounits: 0,
} as const;

function inventoryPolicy(overrides: Record<string, unknown> = {}) {
  return {
    kind: "inventory",
    provider: "opencode",
    mode: "json_run",
    inventoryDigest: digestA,
    surfaceDigest: digestB,
    requiredCapabilities: ["create", "observe"],
    minimumEvidence: "advertised",
    explicitFallbackModes: [],
    ...overrides,
  } as const;
}

describe("provider boundary", () => {
  test("allows only a bounded zero-call synthetic driver", () => {
    expect(evaluateProviderPolicy(synthetic, budget)).toEqual({allowed: true, mode: "in_process_fixture"});
    expect(evaluateProviderPolicy(synthetic, {...budget, maxModelCalls: 1})).toMatchObject({allowed: false, code: "unsafe_synthetic_policy"});
    expect(evaluateProviderPolicy(synthetic, {...budget, maxWallMs: Infinity})).toMatchObject({allowed: false, code: "unbounded_budget"});
  });

  test("keeps advertised evidence distinct from observed evidence", () => {
    const providerBudget = {...budget, enforcement: "host_broker_required"} as const;
    expect(evaluateProviderPolicy(inventoryPolicy(), providerBudget, inventory)).toEqual({allowed: true, mode: "json_run"});
    expect(evaluateProviderPolicy(inventoryPolicy({minimumEvidence: "observed"}), providerBudget, inventory)).toMatchObject({allowed: false, code: "capability_evidence"});
    expect(evaluateProviderPolicy(inventoryPolicy({requiredCapabilities: ["cancel"]}), providerBudget, inventory)).toMatchObject({allowed: false, code: "capability_evidence"});
  });

  test("denies digest drift, implicit fallback and reordered fallback", () => {
    const providerBudget = {...budget, enforcement: "host_broker_required"} as const;
    expect(evaluateProviderPolicy(inventoryPolicy({surfaceDigest: "c".repeat(64)}), providerBudget, inventory)).toMatchObject({allowed: false, code: "inventory_drift"});
    expect(evaluateProviderPolicy(inventoryPolicy({explicitFallbackModes: undefined}), providerBudget, inventory)).toMatchObject({allowed: false, code: "implicit_fallback"});
    expect(evaluateProviderPolicy(inventoryPolicy({mode: "http_server", explicitFallbackModes: ["json_run", "acp"]}), providerBudget, inventory)).toMatchObject({allowed: false, code: "fallback_disabled"});
  });
});
