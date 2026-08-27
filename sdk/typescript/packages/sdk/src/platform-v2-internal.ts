// SPDX-License-Identifier: Apache-2.0

export const platformV2Exchange = Symbol("automonique.platform.v2.exchange");

export type PlatformV2Lane = "negotiation" | "v2";

export interface PlatformV2ExchangeResult {
  readonly payload: Uint8Array;
  readonly status: number;
}

/** Package-internal transport seam; it is not exported by the public package. */
export interface InternalPlatformV2Transport {
  [platformV2Exchange](
    lane: PlatformV2Lane,
    payload: Uint8Array,
    signal?: AbortSignal,
  ): Promise<PlatformV2ExchangeResult>;
}
