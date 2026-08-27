// SPDX-License-Identifier: Apache-2.0

import type {
  PlatformNegotiationResponse,
  PlatformRequestId,
  PlatformV2Request,
  PlatformV2Response,
  PlatformVersionOffer,
} from "../../../protocol/src/index.js";

export interface PlatformV2CanonicalTestingHandlers {
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

const canonicalTestingTransports = new WeakMap<
  PlatformV2CanonicalTestingTransport,
  PlatformV2CanonicalTestingHandlers
>();

/** Testing-only typed registration, intentionally absent from the production entry point. */
export class PlatformV2CanonicalTestingTransport {
  constructor(
    negotiate: PlatformV2CanonicalTestingHandlers["negotiate"],
    request: PlatformV2CanonicalTestingHandlers["request"],
  ) {
    canonicalTestingTransports.set(this, {negotiate, request});
  }
}

/** @internal Used by the typed client to recognize an unforgeable testing capability. */
export function platformV2CanonicalTestingHandlers(
  value: object,
): PlatformV2CanonicalTestingHandlers | undefined {
  return canonicalTestingTransports.get(value as PlatformV2CanonicalTestingTransport);
}
