// SPDX-License-Identifier: Apache-2.0

import {
  registerPlatformV2Transport,
  type PlatformV2CanonicalHandlers,
} from "../platform-v2-transport-capability.js";

export type PlatformV2CanonicalTestingHandlers = PlatformV2CanonicalHandlers;

/** Testing-only typed registration, intentionally absent from the production entry point. */
export class PlatformV2CanonicalTestingTransport {
  constructor(
    negotiate: PlatformV2CanonicalTestingHandlers["negotiate"],
    request: PlatformV2CanonicalTestingHandlers["request"],
  ) {
    registerPlatformV2Transport(this, {
      kind: "canonical",
      handlers: {negotiate, request},
    });
  }
}
