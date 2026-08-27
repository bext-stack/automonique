// SPDX-License-Identifier: Apache-2.0

import type {
  PlatformNegotiationResponse,
  PlatformRequestId,
  PlatformV2Request,
  PlatformV2Response,
  PlatformVersionOffer,
} from "../../protocol/src/index.js";

export type PlatformV2Lane = "negotiation" | "v2";
export type PlatformV2Exchange = (
  lane: PlatformV2Lane,
  payload: Uint8Array,
  signal?: AbortSignal,
) => Promise<{readonly payload: Uint8Array; readonly status: number}>;

export interface PlatformV2CanonicalHandlers {
  readonly negotiate: (
    requestId: ReturnType<typeof PlatformRequestId>,
    offer: PlatformVersionOffer,
    signal?: AbortSignal,
  ) => Promise<PlatformNegotiationResponse>;
  readonly request: (
    requestId: ReturnType<typeof PlatformRequestId>,
    request: PlatformV2Request,
    signal?: AbortSignal,
  ) => Promise<PlatformV2Response>;
}

export type PlatformV2TransportCapability =
  | {readonly kind: "exchange"; readonly exchange: PlatformV2Exchange}
  | {readonly kind: "canonical"; readonly handlers: PlatformV2CanonicalHandlers};

const capabilities = new WeakMap<object, PlatformV2TransportCapability>();

/** Package-internal unforgeable transport registration. */
export function registerPlatformV2Transport(
  transport: object,
  capability: PlatformV2TransportCapability,
): void {
  capabilities.set(transport, capability);
}

/** Package-internal capability lookup; unregistered objects remain powerless. */
export function platformV2TransportCapability(
  transport: object,
): PlatformV2TransportCapability | undefined {
  return capabilities.get(transport);
}
