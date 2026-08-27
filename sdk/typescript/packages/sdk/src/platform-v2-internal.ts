// SPDX-License-Identifier: Apache-2.0

export type PlatformV2Lane = "negotiation" | "v2";

export interface PlatformV2ExchangeResult {
  readonly payload: Uint8Array;
  readonly status: number;
}

export type PlatformV2Exchange = (
  lane: PlatformV2Lane,
  payload: Uint8Array,
  signal?: AbortSignal,
) => Promise<PlatformV2ExchangeResult>;

const exchanges = new WeakMap<RegisteredPlatformV2Transport, PlatformV2Exchange>();

/** Package-internal nominal base for an inaccessible v2 transport capability. */
export abstract class RegisteredPlatformV2Transport {
  declare private readonly __registeredPlatformV2Transport: void;

  protected constructor(exchange: PlatformV2Exchange) {
    exchanges.set(this, exchange);
  }
}

/** Obtains the raw exchange closure without exposing it on the transport. */
export function claimPlatformV2Exchange(transport: RegisteredPlatformV2Transport): PlatformV2Exchange {
  const exchange = exchanges.get(transport);
  if (exchange === undefined) throw new TypeError("platform v2 transport capability is unavailable");
  return exchange;
}
