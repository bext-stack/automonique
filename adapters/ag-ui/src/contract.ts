// SPDX-License-Identifier: Elastic-2.0

/**
 * The deliberately small, sanitized input accepted by the AG-UI translator.
 *
 * This is an adapter-internal projection of native services, not another
 * session or event authority. A future transport must construct it only from
 * authorized Platform/native SDK records.
 */
export const NATIVE_ADAPTER_SCHEMA = "automonique.ag-ui-native/v1" as const;

export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | readonly JsonValue[] | {readonly [key: string]: JsonValue};

export interface NativeEventBase {
  readonly schema: typeof NATIVE_ADAPTER_SCHEMA;
  readonly sequence: number;
  readonly cursor: string;
  /** Unix epoch milliseconds, matching AG-UI's conventional `Date.now()` value. */
  readonly timestamp: number;
  readonly threadId: string;
  readonly runId: string;
}

export type JsonPatchOperation =
  | {readonly op: "add" | "replace" | "test"; readonly path: string; readonly value: JsonValue}
  | {readonly op: "remove"; readonly path: string}
  | {readonly op: "copy" | "move"; readonly from: string; readonly path: string};

export type RefusalCode =
  | "authorization_lost"
  | "capability_unsupported"
  | "internal_failure"
  | "interrupt_expired"
  | "interrupt_invalid"
  | "policy_refused"
  | "resync_required"
  | "stale_revision";

export type NativeAdapterEvent =
  | (NativeEventBase & {
      readonly kind: "run_started";
      /** Authority-validated append-only lineage; never taken directly from the client. */
      readonly parentRunId?: string;
      /** Tool proposals from an interrupted parent run that this run may resolve. */
      readonly resumedToolCallIds?: readonly string[];
    })
  | (NativeEventBase & {
      readonly kind: "assistant_message_preview";
      readonly messageId: string;
      readonly text: string;
      readonly replace: boolean;
    })
  | (NativeEventBase & {
      readonly kind: "assistant_message_completed";
      readonly messageId: string;
      readonly text: string;
    })
  | (NativeEventBase & {
      readonly kind: "tool_call_started";
      readonly toolCallId: string;
      readonly toolName: string;
      readonly parentMessageId?: string;
    })
  | (NativeEventBase & {
      readonly kind: "tool_call_args";
      readonly toolCallId: string;
      /** A policy-filtered JSON fragment, never raw provider bytes. */
      readonly delta: string;
    })
  | (NativeEventBase & {readonly kind: "tool_call_ended"; readonly toolCallId: string})
  | (NativeEventBase & {
      readonly kind: "tool_call_result";
      readonly toolCallId: string;
      readonly resultMessageId: string;
      /** A bounded, policy-filtered public result. */
      readonly content: string;
    })
  | (NativeEventBase & {
      readonly kind: "state_snapshot";
      readonly snapshot: JsonValue;
    })
  | (NativeEventBase & {
      readonly kind: "messages_snapshot";
      readonly messages: readonly (
        | {readonly id: string; readonly role: "user" | "assistant"; readonly content: string}
        | {readonly id: string; readonly role: "tool"; readonly toolCallId: string; readonly content: string}
      )[];
    })
  | (NativeEventBase & {
      readonly kind: "state_delta";
      readonly delta: readonly JsonPatchOperation[];
    })
  | (NativeEventBase & {readonly kind: "step_started"; readonly stepName: string})
  | (NativeEventBase & {readonly kind: "step_finished"; readonly stepName: string})
  | (NativeEventBase & {
      readonly kind: "approval_requested";
      readonly approvalId: string;
      readonly reason: string;
      readonly expectedRevision: number;
      readonly message?: string;
      readonly toolCallId?: string;
      readonly responseSchema?: {readonly [key: string]: JsonValue};
      readonly expiresAt?: string;
    })
  | (NativeEventBase & {readonly kind: "control_lost"; readonly reason: string})
  | (NativeEventBase & {readonly kind: "run_finished"})
  | (NativeEventBase & {readonly kind: "run_refused"; readonly code: RefusalCode});
