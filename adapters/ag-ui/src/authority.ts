// SPDX-License-Identifier: Elastic-2.0

import type {AdmittedRunInput} from "./admission.ts";
import type {NativeAdapterEvent} from "./contract.ts";

export interface PlatformOpenRequest {
  readonly input: AdmittedRunInput;
  /** Exclusive native cursor last delivered to this client. */
  readonly cursor: string | null;
}

export type PlatformOpenResult =
  | {
      readonly kind: "stream";
      /**
       * Bounded retained native prefix through the requested cursor. The
       * adapter validates this prefix to restore translation state and emit
       * any AG-UI projection suffix missed within the final native event.
       * Empty for a fresh run.
       */
      readonly replay: readonly NativeAdapterEvent[];
      /** Ordered, sanitized events read from the Platform/native authority. */
      readonly events: AsyncIterable<NativeAdapterEvent>;
    }
  | {
      readonly kind: "resync_required";
      /** Authorized snapshot cursor from which a new request can restart. */
      readonly cursor: string;
    };

export interface PlatformCancelRequest {
  readonly threadId: string;
  readonly runId: string;
  readonly idempotencyKey: string;
  readonly expectedRevision: number;
}

export interface PlatformCancelReceipt {
  readonly receiptId: string;
  readonly outcome: "accepted" | "already_applied" | "conflict" | "rejected";
}

/**
 * Least-authority runtime seam.
 *
 * Implementations must resolve thread/run coordinates under the authenticated
 * caller, retain mutation receipts, validate the complete open-interrupt set
 * and its schemas/revisions/expiry, and route cancellation through Platform
 * `stop_run`. The HTTP adapter owns none of that state.
 */
export interface PlatformRunAuthority {
  ready(signal?: AbortSignal): Promise<boolean>;
  open(request: PlatformOpenRequest, signal?: AbortSignal): Promise<PlatformOpenResult>;
  cancel(request: PlatformCancelRequest, signal?: AbortSignal): Promise<PlatformCancelReceipt>;
  /** The exact opaque adapter cursor last delivered, for subscriber metrics only. */
  disconnected?(threadId: string, runId: string, cursor: string | null): void | Promise<void>;
}
