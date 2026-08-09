// SPDX-License-Identifier: Apache-2.0

import {describe, expect, test} from "bun:test";
import {
  CAPABILITIES,
  LAB_PROTOCOL,
  LabClient,
  evaluateProviderPolicy,
  loadProviderInventoryProjection,
  type CapabilitySupport,
} from "../src/index.ts";

const providerBudget = {maxWallMs: 1_000, maxCpuMs: 500, maxDiskBytes: 16_384, maxOutputBytes: 4_096, maxPids: 2, maxModelCalls: 0, maxCostMicrounits: 0, enforcement: "host_broker_required"} as const;
const syntheticBudget = {...providerBudget, enforcement: "synthetic_in_process"} as const;
const synthetic = {kind: "synthetic", driver: "in_process_fixture", network: "deny", authentication: "none", maxModelCalls: 0, maxCostMicrounits: 0} as const;
function capabilities(overrides: Partial<Record<(typeof CAPABILITIES)[number], CapabilitySupport>> = {}) {
  return Object.fromEntries(CAPABILITIES.map((capability) => [capability, overrides[capability] ?? "unknown"]));
}
const inventoryContent = {schema: "automonique.provider-selection/v1", provider: "fixture", fallbackOrder: ["primary", "fallback", "debug", "experimental"]};
const surfaceContent = {
  schema: "automonique.provider-surface-selection/v1", provider: "fixture", version: "1.0.0",
  modes: [
    {id: "primary", purpose: "runtime", unsafe: false, stability: "stable", capabilities: capabilities({create: "observed", observe: "observed"}), lostGuarantees: []},
    {id: "fallback", purpose: "runtime", unsafe: false, stability: "stable", capabilities: capabilities({create: "advertised", observe: "advertised"}), lostGuarantees: ["no authoritative live stream"]},
    {id: "debug", purpose: "debug", unsafe: false, stability: "stable", capabilities: capabilities({create: "observed", observe: "observed"}), lostGuarantees: ["debug-only mode"]},
    {id: "experimental", purpose: "runtime", unsafe: false, stability: "experimental", capabilities: capabilities({create: "observed", observe: "observed"}), lostGuarantees: ["experimental lifecycle"]},
  ],
};
const projection = await loadProviderInventoryProjection(inventoryContent, surfaceContent);

function selection(overrides: Record<string, unknown> = {}) {
  return {kind: "inventory", provider: "fixture", mode: "primary", requiredCapabilities: ["create", "observe"], minimumEvidence: "advertised", explicitFallbacks: [], ...overrides} as const;
}

describe("closed provider projection", () => {
  test("computes canonical digests and does not accept caller digest strings", async () => {
    const reorderedInventory = {fallbackOrder: ["primary", "fallback", "debug", "experimental"], provider: "fixture", schema: "automonique.provider-selection/v1"};
    const reorderedSurface = {modes: surfaceContent.modes.map((mode) => ({lostGuarantees: mode.lostGuarantees, capabilities: mode.capabilities, stability: mode.stability, unsafe: mode.unsafe, purpose: mode.purpose, id: mode.id})), version: "1.0.0", provider: "fixture", schema: "automonique.provider-surface-selection/v1"};
    const second = await loadProviderInventoryProjection(reorderedInventory, reorderedSurface);
    expect(second.inventoryDigest).toBe(projection.inventoryDigest);
    expect(second.surfaceDigest).toBe(projection.surfaceDigest);
    expect(projection.inventoryDigest).toMatch(/^[0-9a-f]{64}$/);

    const fabricated = {...projection, inventoryDigest: "a".repeat(64)};
    expect(evaluateProviderPolicy(selection(), providerBudget, fabricated)).toMatchObject({allowed: false, code: "inventory_unvalidated"});
  });

  test("rejects open, incomplete and internally inconsistent normalized content", async () => {
    await expect(loadProviderInventoryProjection({...inventoryContent, extra: true}, surfaceContent)).rejects.toThrow("unexpected");
    const missingCapability = structuredClone(surfaceContent) as any;
    delete missingCapability.modes[0].capabilities.cancel;
    await expect(loadProviderInventoryProjection(inventoryContent, missingCapability)).rejects.toThrow("unexpected or missing");
    await expect(loadProviderInventoryProjection({...inventoryContent, fallbackOrder: ["primary", "primary"]}, surfaceContent)).rejects.toThrow("duplicates");
  });
});

describe("provider selection policy", () => {
  test("allows bounded synthetic execution and derives wire digests for inventory selection", () => {
    const syntheticDecision = evaluateProviderPolicy(synthetic, syntheticBudget);
    expect(syntheticDecision).toMatchObject({allowed: true, mode: "in_process_fixture"});
    const decision = evaluateProviderPolicy(selection(), providerBudget, projection);
    expect(decision).toMatchObject({allowed: true, mode: "primary"});
    if (decision.allowed && decision.policy.kind === "inventory") {
      expect(decision.policy.inventoryDigest).toBe(projection.inventoryDigest);
      expect(decision.policy.surfaceDigest).toBe(projection.surfaceDigest);
      expect("inventoryDigest" in selection()).toBe(false);
    }
  });

  test("client sends only loader-derived inventory coordinates to transport", async () => {
    let captured: unknown;
    const client = new LabClient({request: async (request) => {
      captured = request;
      return {protocol: LAB_PROTOCOL, requestId: request.requestId, kind: "selected", unit: {unitId: "unit-1", objectiveId: "objective", state: "selected", revision: 1, checkpointId: null, lastSequence: 0}};
    }});
    await client.select({
      requestId: "inventory-select", objectiveId: "objective", expectedBase: "1".repeat(40),
      execution: "inventory", providerPolicy: selection(), providerProjection: projection,
      budget: providerBudget,
    });
    expect(captured).toMatchObject({execution: "inventory", providerPolicy: {inventoryDigest: projection.inventoryDigest, surfaceDigest: projection.surfaceDigest}});
    expect(captured && typeof captured === "object" && "providerProjection" in captured).toBe(false);
  });

  test("denies unsafe, debug and experimental selected or fallback modes", () => {
    expect(evaluateProviderPolicy(selection({mode: "debug"}), providerBudget, projection)).toMatchObject({allowed: false, code: "unsafe_mode"});
    expect(evaluateProviderPolicy(selection({mode: "experimental"}), providerBudget, projection)).toMatchObject({allowed: false, code: "unsafe_mode"});
    expect(evaluateProviderPolicy(selection({explicitFallbacks: [{mode: "debug", acceptedLostGuarantees: ["debug-only mode"]}]}), providerBudget, projection)).toMatchObject({allowed: false, code: "unsafe_fallback"});
  });

  test("validates every fallback capability, evidence level, order and accepted loss", async () => {
    const accepted = selection({explicitFallbacks: [{mode: "fallback", acceptedLostGuarantees: ["no authoritative live stream"]}]});
    expect(evaluateProviderPolicy(accepted, providerBudget, projection)).toMatchObject({allowed: true});
    expect(evaluateProviderPolicy(selection({explicitFallbacks: [{mode: "fallback", acceptedLostGuarantees: []}]}), providerBudget, projection)).toMatchObject({allowed: false, code: "fallback_losses"});
    expect(evaluateProviderPolicy(selection({explicitFallbacks: [{mode: "experimental", acceptedLostGuarantees: ["experimental lifecycle"]}, {mode: "fallback", acceptedLostGuarantees: ["no authoritative live stream"]}]}), providerBudget, projection)).toMatchObject({allowed: false});

    const weakSurface = structuredClone(surfaceContent) as any;
    weakSurface.modes[1].capabilities.observe = "unknown";
    const weak = await loadProviderInventoryProjection(inventoryContent, weakSurface);
    expect(evaluateProviderPolicy(accepted, providerBudget, weak)).toMatchObject({allowed: false, code: "fallback_capability"});
    expect(evaluateProviderPolicy(selection({minimumEvidence: "observed", explicitFallbacks: [{mode: "fallback", acceptedLostGuarantees: ["no authoritative live stream"]}]}), providerBudget, projection)).toMatchObject({allowed: false, code: "fallback_capability"});
  });

  test("denies unbounded budgets, wrong enforcement and malformed selections", () => {
    expect(evaluateProviderPolicy(selection(), {...providerBudget, maxDiskBytes: Infinity}, projection)).toMatchObject({allowed: false, code: "unbounded_budget"});
    expect(evaluateProviderPolicy(selection(), syntheticBudget, projection)).toMatchObject({allowed: false, code: "missing_host_enforcement"});
    expect(evaluateProviderPolicy(selection({requiredCapabilities: []}), providerBudget, projection)).toMatchObject({allowed: false, code: "selection_invalid"});
    expect(evaluateProviderPolicy(selection({explicitFallbacks: undefined}), providerBudget, projection)).toMatchObject({allowed: false, code: "implicit_fallback"});
    expect(evaluateProviderPolicy({...selection(), inventoryDigest: "a".repeat(64)} as never, providerBudget, projection)).toMatchObject({allowed: false, code: "selection_invalid"});
    expect(evaluateProviderPolicy({...synthetic, extra: true} as never, syntheticBudget)).toMatchObject({allowed: false, code: "selection_invalid"});
  });
});
