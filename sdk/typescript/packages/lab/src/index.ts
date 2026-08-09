// SPDX-License-Identifier: Apache-2.0

export {LabClient, type LabTransport} from "./client.ts";
export {evaluateProviderPolicy} from "./provider-policy.ts";
export type {
  InventoryMode,
  PolicyDecision,
  ProviderInventoryProjection,
} from "./provider-policy.ts";
export {
  CAPABILITIES,
  LAB_PROTOCOL,
  decodeLabResponse,
  type ActionReceipt,
  type ActionResult,
  type Capability,
  type CapabilitySupport,
  type LabBudget,
  type LabEvent,
  type ObserveResult,
  type ProviderPolicy,
  type SelectResult,
  type UnitSnapshot,
  type UnitState,
} from "./protocol.ts";
