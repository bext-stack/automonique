// SPDX-License-Identifier: Apache-2.0

import {
  CAPABILITIES,
  validateBudget,
  type Capability,
  type CapabilitySupport,
  type InventoryProviderPolicy,
  type InventoryProviderSelection,
  type LabBudget,
  type ProviderPolicy,
  type ProviderSelection,
} from "./protocol.ts";

export interface InventoryMode {
  readonly id: string;
  readonly purpose: "runtime" | "debug";
  readonly unsafe: boolean;
  readonly stability: "stable" | "experimental" | "unlabelled";
  readonly capabilities: Readonly<Record<Capability, CapabilitySupport>>;
  readonly lostGuarantees: readonly string[];
}
export interface ProviderInventoryProjection {
  readonly provider: string;
  readonly version: string | null;
  readonly inventoryDigest: string;
  readonly surfaceDigest: string;
  readonly modes: readonly InventoryMode[];
  readonly fallbackOrder: readonly string[];
}
export type PolicyDecision =
  | {readonly allowed: true; readonly mode: string; readonly policy: ProviderPolicy}
  | {readonly allowed: false; readonly code: string; readonly reason: string};

type JsonRecord = Record<string, unknown>;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SUPPORT = new Set(["advertised", "observed", "unknown", "unavailable"]);
const loaded = new WeakSet<object>();

function denied(code: string, reason: string): PolicyDecision { return {allowed: false, code, reason}; }
function record(value: unknown, context: string): JsonRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError(`${context} must be an object`);
  return value as JsonRecord;
}
function exact(value: JsonRecord, keys: readonly string[], context: string): void {
  const expected = new Set(keys);
  if (Object.keys(value).length !== expected.size || Object.keys(value).some((key) => !expected.has(key))) throw new TypeError(`${context} has unexpected or missing fields`);
}
function identifier(value: unknown, context: string): string {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) throw new TypeError(`${context} must be a bounded identifier`);
  return value;
}
function boundedText(value: unknown, context: string, max = 512): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max || /[\u0000-\u001f]/.test(value)) throw new TypeError(`${context} must be bounded text`);
  return value;
}
function textArray(value: unknown, context: string): readonly string[] {
  if (!Array.isArray(value) || value.length > 32) throw new TypeError(`${context} must be a bounded array`);
  return value.map((entry) => boundedText(entry, context));
}
function canonical(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const object = record(value, "canonical value");
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonical(object[key])}`).join(",")}}`;
}
async function sha256(value: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(canonical(value));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
function frozenMode(mode: InventoryMode): InventoryMode {
  return Object.freeze({...mode, capabilities: Object.freeze({...mode.capabilities}), lostGuarantees: Object.freeze([...mode.lostGuarantees])});
}

/**
 * Validate closed normalized content and derive both digests from its canonical
 * bytes. No caller-supplied digest or preconstructed projection is trusted.
 */
export async function loadProviderInventoryProjection(
  inventoryContent: unknown,
  surfaceContent: unknown,
): Promise<ProviderInventoryProjection> {
  const inventory = record(inventoryContent, "inventory content");
  exact(inventory, ["schema", "provider", "fallbackOrder"], "inventory content");
  if (inventory.schema !== "automonique.provider-selection/v1") throw new TypeError("inventory schema is unsupported");
  const provider = identifier(inventory.provider, "inventory.provider");
  if (!Array.isArray(inventory.fallbackOrder) || inventory.fallbackOrder.length < 1 || inventory.fallbackOrder.length > 16) throw new TypeError("inventory.fallbackOrder must be bounded");
  const fallbackOrder = inventory.fallbackOrder.map((entry) => identifier(entry, "inventory.fallbackOrder"));
  if (new Set(fallbackOrder).size !== fallbackOrder.length) throw new TypeError("inventory.fallbackOrder contains duplicates");

  const surface = record(surfaceContent, "surface content");
  exact(surface, ["schema", "provider", "version", "modes"], "surface content");
  if (surface.schema !== "automonique.provider-surface-selection/v1" || surface.provider !== provider) throw new TypeError("surface schema or provider does not match inventory");
  const version = surface.version === null ? null : boundedText(surface.version, "surface.version", 128);
  if (!Array.isArray(surface.modes) || surface.modes.length < 1 || surface.modes.length > 16) throw new TypeError("surface.modes must be bounded");
  const modes: InventoryMode[] = surface.modes.map((raw, index) => {
    const mode = record(raw, `surface.modes[${index}]`);
    exact(mode, ["id", "purpose", "unsafe", "stability", "capabilities", "lostGuarantees"], `surface.modes[${index}]`);
    const modeId = identifier(mode.id, `surface.modes[${index}].id`);
    if (mode.purpose !== "runtime" && mode.purpose !== "debug") throw new TypeError("mode purpose is unknown");
    if (typeof mode.unsafe !== "boolean") throw new TypeError("mode unsafe flag must be boolean");
    if (mode.stability !== "stable" && mode.stability !== "experimental" && mode.stability !== "unlabelled") throw new TypeError("mode stability is unknown");
    const rawCapabilities = record(mode.capabilities, "mode capabilities");
    exact(rawCapabilities, CAPABILITIES, "mode capabilities");
    const capabilities = Object.fromEntries(CAPABILITIES.map((capability) => {
      const support = rawCapabilities[capability];
      if (typeof support !== "string" || !SUPPORT.has(support)) throw new TypeError(`capability ${capability} has unknown support`);
      return [capability, support];
    })) as Record<Capability, CapabilitySupport>;
    return {id: modeId, purpose: mode.purpose, unsafe: mode.unsafe, stability: mode.stability, capabilities, lostGuarantees: textArray(mode.lostGuarantees, "mode lostGuarantees")};
  });
  if (new Set(modes.map((mode) => mode.id)).size !== modes.length) throw new TypeError("surface modes contain duplicate IDs");
  if (fallbackOrder.length !== modes.length || fallbackOrder.some((id) => !modes.some((mode) => mode.id === id))) throw new TypeError("fallback order must name every surface mode exactly once");

  const projection: ProviderInventoryProjection = Object.freeze({
    provider,
    version,
    inventoryDigest: await sha256(inventory),
    surfaceDigest: await sha256(surface),
    modes: Object.freeze(modes.map(frozenMode)),
    fallbackOrder: Object.freeze([...fallbackOrder]),
  });
  loaded.add(projection);
  return projection;
}

function evidenceSufficient(support: CapabilitySupport, minimum: "advertised" | "observed"): boolean {
  return support === "observed" || (support === "advertised" && minimum === "advertised");
}
function validateSelection(selection: InventoryProviderSelection): PolicyDecision | null {
  const keys = Object.keys(selection);
  const expected = new Set(["kind", "provider", "mode", "requiredCapabilities", "minimumEvidence", "explicitFallbacks"]);
  if (keys.length !== expected.size || keys.some((key) => !expected.has(key))) return denied("selection_invalid", "Inventory selection is not a closed object.");
  if (!IDENTIFIER.test(selection.provider) || !IDENTIFIER.test(selection.mode)) return denied("selection_invalid", "Provider and mode must be bounded identifiers.");
  if (selection.minimumEvidence !== "advertised" && selection.minimumEvidence !== "observed") return denied("selection_invalid", "Minimum evidence is unknown.");
  if (!Array.isArray(selection.requiredCapabilities) || selection.requiredCapabilities.length < 1 || new Set(selection.requiredCapabilities).size !== selection.requiredCapabilities.length || selection.requiredCapabilities.some((capability) => !CAPABILITIES.includes(capability))) return denied("selection_invalid", "Required capabilities are empty, duplicated or unknown.");
  if (!Array.isArray(selection.explicitFallbacks)) return denied("implicit_fallback", "Fallbacks must be an explicit array.");
  return null;
}

export function evaluateProviderPolicy(
  selection: ProviderSelection,
  budget: LabBudget,
  projection?: ProviderInventoryProjection,
): PolicyDecision {
  try { validateBudget(budget); } catch (error) { return denied("unbounded_budget", error instanceof Error ? error.message : "Budget is invalid."); }
  if (typeof selection !== "object" || selection === null || Array.isArray(selection)) return denied("selection_invalid", "Provider selection must be an object.");
  if (selection.kind === "synthetic") {
    const keys = Object.keys(selection);
    const expected = new Set(["kind", "driver", "network", "authentication", "maxModelCalls", "maxCostMicrounits"]);
    if (keys.length !== expected.size || keys.some((key) => !expected.has(key))) return denied("selection_invalid", "Synthetic selection is not a closed object.");
    if (selection.driver !== "in_process_fixture" || selection.network !== "deny" || selection.authentication !== "none" || selection.maxModelCalls !== 0 || selection.maxCostMicrounits !== 0 || budget.maxModelCalls !== 0 || budget.maxCostMicrounits !== 0 || budget.enforcement !== "synthetic_in_process") return denied("unsafe_synthetic_policy", "Synthetic execution must deny network, authentication, model calls and cost.");
    return {allowed: true, mode: "in_process_fixture", policy: selection};
  }
  if (selection.kind !== "inventory") return denied("selection_invalid", "Provider selection kind is unknown.");
  const invalid = validateSelection(selection); if (invalid) return invalid;
  if (!projection || !loaded.has(projection) || projection.provider !== selection.provider) return denied("inventory_unvalidated", "A projection returned by the closed loader is required.");
  if (budget.enforcement !== "host_broker_required") return denied("missing_host_enforcement", "Provider modes require host-broker enforcement.");
  const selected = projection.modes.find((mode) => mode.id === selection.mode);
  if (!selected) return denied("mode_missing", "Selected mode is absent from the projection.");
  if (selected.unsafe || selected.purpose === "debug" || selected.stability === "experimental") return denied("unsafe_mode", "Unsafe, debug or experimental modes are denied.");
  for (const capability of selection.requiredCapabilities) if (!evidenceSufficient(selected.capabilities[capability], selection.minimumEvidence)) return denied("capability_evidence", `${capability} is below ${selection.minimumEvidence} evidence in ${selected.id}.`);

  const selectedIndex = projection.fallbackOrder.indexOf(selected.id);
  let priorIndex = selectedIndex;
  const seen = new Set<string>();
  for (const fallback of selection.explicitFallbacks) {
    if (typeof fallback !== "object" || fallback === null || Array.isArray(fallback)) return denied("fallback_invalid", "Fallback entry is not an object.");
    const keys = Object.keys(fallback); if (keys.length !== 2 || !keys.includes("mode") || !keys.includes("acceptedLostGuarantees")) return denied("fallback_invalid", "Fallback entry is not closed.");
    const mode = projection.modes.find((candidate) => candidate.id === fallback.mode);
    const index = projection.fallbackOrder.indexOf(fallback.mode);
    if (!mode || seen.has(fallback.mode) || index <= priorIndex) return denied("fallback_order", "Fallback is missing, duplicated or out of inventory order.");
    if (mode.unsafe || mode.purpose === "debug" || mode.stability === "experimental") return denied("unsafe_fallback", `Fallback ${mode.id} is unsafe, debug or experimental.`);
    for (const capability of selection.requiredCapabilities) if (!evidenceSufficient(mode.capabilities[capability], selection.minimumEvidence)) return denied("fallback_capability", `${capability} is below ${selection.minimumEvidence} evidence in fallback ${mode.id}.`);
    if (!Array.isArray(fallback.acceptedLostGuarantees) || fallback.acceptedLostGuarantees.length !== mode.lostGuarantees.length || fallback.acceptedLostGuarantees.some((loss, position) => loss !== mode.lostGuarantees[position])) return denied("fallback_losses", `Fallback ${mode.id} lost guarantees were not accepted exactly.`);
    seen.add(mode.id); priorIndex = index;
  }
  const policy: InventoryProviderPolicy = {
    kind: "inventory", provider: selection.provider, mode: selection.mode,
    inventoryDigest: projection.inventoryDigest, surfaceDigest: projection.surfaceDigest,
    requiredCapabilities: [...selection.requiredCapabilities], minimumEvidence: selection.minimumEvidence,
    explicitFallbacks: selection.explicitFallbacks.map((fallback) => ({mode: fallback.mode, acceptedLostGuarantees: [...fallback.acceptedLostGuarantees]})),
  };
  return {allowed: true, mode: selected.id, policy};
}
