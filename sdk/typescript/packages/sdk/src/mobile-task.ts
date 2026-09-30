// SPDX-License-Identifier: Apache-2.0

import {PlatformParameter, PlatformRevision, ResourceId, type JsonValue} from "../../protocol/src/index.js";

export type MobileTaskRequest =
  | {readonly action: "prepare"}
  | {readonly action: "submit"; readonly node_id: string; readonly expected_revision: string; readonly idempotency_key: string; readonly text: string}
  | {readonly action: "reconcile"; readonly node_id: string; readonly idempotency_key: string};
export type MobileTaskOutcome = "accepted" | "completed" | "conflict" | "rejected" | "resync_required" | "unknown";
export type MobileTaskView =
  | {readonly state: "ready"; readonly nodeId: string; readonly revision: string}
  | {readonly state: "receipt"; readonly outcome: MobileTaskOutcome; readonly explanation: string | null; readonly sessionId: string | null}
  | {readonly state: "refused"; readonly outcome: MobileTaskOutcome; readonly explanation: string}
  | {readonly state: "ambiguous"};

function decimal(value: unknown): string {
  if (typeof value !== "string" || !/^[1-9][0-9]{0,18}$/.test(value)) throw new Error("mobile_task_revision_invalid");
  PlatformRevision(BigInt(value));
  return value;
}
function node(value: unknown): string {
  if (typeof value !== "string" || value === "node/current") throw new Error("mobile_task_node_invalid");
  return ResourceId(value);
}
function record(value: unknown): {[key: string]: unknown} {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("mobile_task_response_invalid");
  return value as {[key: string]: unknown};
}
function plain(value: JsonValue): unknown {
  if (value.kind === "string") return value.value;
  if (value.kind === "null") return null;
  if (value.kind === "object") return Object.fromEntries(value.entries.map(([key, child]) => [key, plain(child)]));
  return undefined;
}
function wire(fields: Readonly<Record<string, string>>): JsonValue {
  return {kind: "object", entries: Object.entries(fields).map(([key, value]) => [key, {kind: "string", value}])};
}
function outcome(value: unknown): MobileTaskOutcome {
  if (!["accepted", "completed", "conflict", "rejected", "resync_required", "unknown"].includes(value as string)) throw new Error("mobile_task_outcome_invalid");
  return value as MobileTaskOutcome;
}
export function encodeMobileTaskRequest(request: MobileTaskRequest): JsonValue {
  if (request.action === "prepare") return wire({action: "prepare"});
  if (!/^[A-Za-z0-9-]{1,128}$/.test(request.idempotency_key)) throw new Error("mobile_task_key_invalid");
  const base = {action: request.action, node_id: node(request.node_id), idempotency_key: request.idempotency_key};
  if (request.action === "reconcile") return wire(base);
  if (request.action !== "submit" || request.text.trim() === "") throw new Error("mobile_task_request_invalid");
  return wire({...base, expected_revision: decimal(request.expected_revision), text: PlatformParameter(request.text)});
}
export function decodeMobileTaskView(value: JsonValue, request: MobileTaskRequest): MobileTaskView {
  const view = record(plain(value));
  if (view.schema !== "automonique.mobile-task/v1") throw new Error("mobile_task_schema_invalid");
  if (view.state === "ambiguous") return {state: "ambiguous"};
  if (view.state === "refused") {
    if (typeof view.explanation !== "string") throw new Error("mobile_task_response_invalid");
    return {state: "refused", outcome: outcome(view.outcome), explanation: view.explanation};
  }
  if (request.action === "prepare" && view.state === "ready") return {state: "ready", nodeId: node(view.node_id), revision: decimal(view.expected_revision)};
  if (request.action === "prepare" || view.state !== "receipt") throw new Error("mobile_task_response_invalid");
  const receipt = record(view.receipt ?? null);
  const target = record(receipt.target ?? null);
  if (receipt.action !== "submit_request" || target.authority !== "automonique" || target.kind !== "node" || target.id !== request.node_id) throw new Error("mobile_task_receipt_mismatch");
  const result = outcome(receipt.outcome);
  const explanation = receipt.explanation;
  if (explanation !== null && typeof explanation !== "string") throw new Error("mobile_task_response_invalid");
  let sessionId: string | null = null;
  if (view.session_id !== null) {
    if (result !== "completed" || typeof view.session_id !== "string" || !explanation?.startsWith("run=") || explanation.split(";session=")[1] !== view.session_id) throw new Error("mobile_task_session_mismatch");
    sessionId = ResourceId(view.session_id);
  }
  return {state: "receipt", outcome: result, explanation, sessionId};
}
