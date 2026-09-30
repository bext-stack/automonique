// SPDX-License-Identifier: Apache-2.0
import type {JsonValue} from "../../protocol/src/index.js";

export type MobileWorkRequest =
  | {readonly action: "snapshot" | "channel"}
  | {readonly action: "dispatch"; readonly issue_url: string; readonly idempotency_key: string}
  | {readonly action: "decide"; readonly job_id: string; readonly source_key: string; readonly idempotency_key: string; readonly decision: "approve" | "reject"; readonly reason: string};
export interface MobileWorkTicket {
  readonly job_id: string;
  readonly source_key: string;
  readonly issue_url: string;
  readonly issue_title: string;
  readonly job_status: string;
  readonly updated_at: string;
}
export type MobileWorkView =
  | {readonly kind: "queue"; readonly items: readonly MobileWorkTicket[]; readonly hasMore: boolean}
  | {readonly kind: "channel"; readonly channel: string; readonly text: string}
  | {readonly kind: "receipt"; readonly jobId: string; readonly status: string; readonly duplicate: boolean};
const statuses = ["pending_approval", "pending", "claimed", "running", "done", "failed", "cancelled"];
function text(value: unknown, max: number, empty = false): string {
  if (typeof value !== "string" || (!empty && !value) || new TextEncoder().encode(value).length > max) throw new Error("mobile_work_text_invalid");
  return value;
}
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("mobile_work_response_invalid");
  return value as Record<string, unknown>;
}
function plain(value: JsonValue): unknown {
  switch (value.kind) {
    case "string": case "bool": return value.value;
    case "null": return null;
    case "array": return value.items.map(plain);
    case "object": return Object.fromEntries(value.entries.map(([key, child]) => [key, plain(child)]));
    default: throw new Error("mobile_work_response_invalid");
  }
}
function issue(value: unknown): string {
  const url = text(value, 240);
  if (!/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/issues\/[1-9][0-9]*$/.test(url)) throw new Error("mobile_work_issue_invalid");
  return url;
}
function status(value: unknown): string {
  if (typeof value !== "string" || !statuses.includes(value)) throw new Error("mobile_work_status_invalid");
  return value;
}
function bool(value: unknown): boolean {
  if (typeof value !== "boolean") throw new Error("mobile_work_response_invalid");
  return value;
}
export function encodeMobileWorkRequest(request: MobileWorkRequest): JsonValue {
  if (request.action === "dispatch" || request.action === "decide") {
    if (!/^[A-Za-z0-9-]{1,128}$/.test(request.idempotency_key)) throw new Error("mobile_work_key_invalid");
    if (request.action === "dispatch") issue(request.issue_url);
    else {
      text(request.job_id, 256); text(request.source_key, 180);
      if (request.decision === "approve" && request.reason !== "") throw new Error("mobile_work_reason_invalid");
      if (request.decision === "reject") text(request.reason.trim(), 500);
    }
  }
  return {kind: "object", entries: Object.entries(request).map(([key, value]) => [key, {kind: "string", value}])};
}
export function decodeMobileWorkView(value: JsonValue, request: MobileWorkRequest): MobileWorkView {
  const view = record(plain(value));
  if (view.schema !== "automonique.mobile-work/v1") throw new Error("mobile_work_schema_invalid");
  if (request.action === "channel") return {kind: "channel", channel: text(view.channel, 80), text: text(view.text, 65536, true)};
  if (request.action === "snapshot") {
    if (!Array.isArray(view.items) || view.items.length > 50) throw new Error("mobile_work_queue_invalid");
    const items = view.items.map((item) => {
      const row = record(item);
      return {job_id: text(row.job_id, 256), source_key: text(row.source_key, 180), issue_url: issue(row.issue_url), issue_title: text(row.issue_title, 300), job_status: status(row.job_status), updated_at: text(row.updated_at, 80)};
    });
    if (new Set(items.map((row) => row.job_id)).size !== items.length) throw new Error("mobile_work_queue_invalid");
    return {kind: "queue", items, hasMore: bool(view.has_more)};
  }
  const jobId = text(view.job_id, 256);
  if (request.action === "decide" && jobId !== request.job_id) throw new Error("mobile_work_receipt_mismatch");
  const jobStatus = status(view.job_status);
  if (request.action === "decide" && ((request.decision === "reject" && jobStatus !== "cancelled") || (request.decision === "approve" && jobStatus === "pending_approval"))) throw new Error("mobile_work_receipt_mismatch");
  return {kind: "receipt", jobId, status: jobStatus, duplicate: bool(view.duplicate)};
}
