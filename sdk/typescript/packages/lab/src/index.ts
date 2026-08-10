// SPDX-License-Identifier: Apache-2.0

export {
  LabClient,
  type CancelInput,
  type LabTransport,
  type ObserveInput,
  type ResumeInput,
  type SelectInput,
} from "./client.ts";
export {evaluateProviderPolicy, loadProviderInventoryProjection} from "./provider-policy.ts";
export {
  DEFAULT_LAB_REQUEST_TIMEOUT_MS,
  FrameProtocolError,
  FrameTimeoutError,
  FramedLabTransport,
  type FrameChannel,
  type FrameCloseReason,
  type FrameConnector,
  type FramedTransportOptions,
} from "./framed-transport.ts";
export {
  BunUnixSocketConnector,
  BunUnixSocketError,
  type BunUnixSocketConnectorOptions,
} from "./bun-unix-connector.ts";
export type {
  InventoryMode,
  PolicyDecision,
  ProviderInventoryProjection,
} from "./provider-policy.ts";
export {
  CAPABILITIES,
  LAB_PROTOCOL,
  decodeLabResponse,
  validateBudget,
  validateLabRequest,
  type ActionReceipt,
  type ActionResult,
  type Capability,
  type CapabilitySupport,
  type ExplicitFallback,
  type InventoryProviderSelection,
  type LabBudget,
  type LabEvent,
  type ObserveResult,
  type ProviderPolicy,
  type ProviderSelection,
  type SelectResult,
  type UnitSnapshot,
  type UnitState,
} from "./protocol.ts";
