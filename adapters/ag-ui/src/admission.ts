// SPDX-License-Identifier: Elastic-2.0

import {RunAgentInputSchema} from "@ag-ui/core";
import type {JsonValue} from "./contract.ts";

export const MAX_RUN_INPUT_BYTES = 128 * 1024;
const MAX_IDENTIFIER_BYTES = 256;
const MAX_PROMPT_BYTES = 64 * 1024;
const MAX_RESUME_PAYLOAD_BYTES = 32 * 1024;
const MAX_RESUMES = 16;
const RUN_INPUT_FIELDS = new Set([
  "context",
  "forwardedProps",
  "messages",
  "parentRunId",
  "resume",
  "runId",
  "state",
  "threadId",
  "tools",
]);

export interface AdmittedResume {
  readonly interruptId: string;
  readonly status: "resolved" | "cancelled";
  readonly payload?: JsonValue;
}

export interface AdmittedRunInput {
  readonly threadId: string;
  readonly runId: string;
  readonly parentRunId?: string;
  /** The one new user message. Historical client messages are never authoritative. */
  readonly prompt?: string;
  readonly resume: readonly AdmittedResume[];
}

export class AdmissionError extends Error {
  public constructor(public readonly code: string, message: string) {
    super(message);
    this.name = "AdmissionError";
  }
}

export function admitRunAgentInput(value: unknown): AdmittedRunInput {
  const encoded = encodeBounded(value, MAX_RUN_INPUT_BYTES, "request_too_large");
  if (encoded.byteLength === 0) throw new AdmissionError("invalid_input", "run input is empty");
  const input = record(value, "invalid_input");
  exactFields(input, RUN_INPUT_FIELDS, "unknown_field");
  for (const field of ["threadId", "runId", "state", "messages", "tools", "context", "forwardedProps"] as const) {
    if (!Object.hasOwn(input, field)) throw new AdmissionError("missing_field", `missing ${field}`);
  }

  const official = RunAgentInputSchema.safeParse(value);
  if (!official.success) throw new AdmissionError("invalid_input", "input does not match the pinned RunAgentInput schema");

  const threadId = identifier(input.threadId, "threadId");
  const runId = identifier(input.runId, "runId");
  const parentRunId = input.parentRunId === undefined ? undefined : identifier(input.parentRunId, "parentRunId");

  if (!isEmptyRecord(input.state)) throw new AdmissionError("client_state_refused", "client state is not an authority input");
  if (!Array.isArray(input.tools) || input.tools.length !== 0) {
    throw new AdmissionError("client_tools_refused", "client-provided tools are not accepted");
  }
  if (!Array.isArray(input.context) || input.context.length !== 0) {
    throw new AdmissionError("client_context_refused", "client-provided context is not accepted");
  }
  if (!(input.forwardedProps === null || isEmptyRecord(input.forwardedProps))) {
    throw new AdmissionError("forwarded_props_refused", "forwarded properties are not accepted");
  }

  const resume = admitResume(input.resume);
  if (!Array.isArray(input.messages)) throw new AdmissionError("invalid_messages", "messages must be an array");
  if (input.messages.length > 1) {
    throw new AdmissionError("history_refused", "client message history is not an authority record");
  }
  let prompt: string | undefined;
  if (input.messages.length === 1) {
    const message = record(input.messages[0], "invalid_message");
    exactFields(message, new Set(["content", "id", "role"]), "message_field_refused");
    if (message.role !== "user" || typeof message.content !== "string") {
      throw new AdmissionError("message_role_refused", "only one plain user message is accepted");
    }
    identifier(message.id, "messageId");
    boundedText(message.content, MAX_PROMPT_BYTES, "prompt");
    prompt = message.content;
  }

  if (resume.length === 0 && prompt === undefined) {
    throw new AdmissionError("missing_prompt", "a new run requires one user message");
  }
  if (resume.length !== 0 && prompt !== undefined) {
    throw new AdmissionError("resume_with_message", "an interrupt resume cannot also submit a new message");
  }
  if (resume.length !== 0 && parentRunId === undefined) {
    throw new AdmissionError("missing_parent_run", "an interrupt resume must identify its interrupted parent run");
  }

  return {
    threadId,
    runId,
    ...(parentRunId === undefined ? {} : {parentRunId}),
    ...(prompt === undefined ? {} : {prompt}),
    resume,
  };
}

function admitResume(value: unknown): readonly AdmittedResume[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_RESUMES) {
    throw new AdmissionError("invalid_resume", "resume must be a non-empty bounded array");
  }
  const seen = new Set<string>();
  return value.map((entry) => {
    const resume = record(entry, "invalid_resume");
    exactFields(resume, new Set(["interruptId", "payload", "status"]), "resume_field_refused");
    const interruptId = identifier(resume.interruptId, "interruptId");
    if (seen.has(interruptId)) throw new AdmissionError("duplicate_interrupt", "an interrupt may be resumed once");
    seen.add(interruptId);
    if (resume.status !== "resolved" && resume.status !== "cancelled") {
      throw new AdmissionError("invalid_resume_status", "resume status must be resolved or cancelled");
    }
    if (resume.status === "cancelled" && Object.hasOwn(resume, "payload")) {
      throw new AdmissionError("cancelled_payload", "a cancelled interrupt cannot carry a payload");
    }
    if (Object.hasOwn(resume, "payload")) {
      assertJson(resume.payload);
      encodeBounded(resume.payload, MAX_RESUME_PAYLOAD_BYTES, "resume_payload_too_large");
    }
    return {
      interruptId,
      status: resume.status,
      ...(Object.hasOwn(resume, "payload") ? {payload: resume.payload as JsonValue} : {}),
    };
  });
}

function exactFields(value: Record<string, unknown>, allowed: ReadonlySet<string>, code: string): void {
  if (Object.keys(value).some((field) => !allowed.has(field))) {
    throw new AdmissionError(code, "input contains an unsupported field");
  }
}

function record(value: unknown, code: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new AdmissionError(code, "expected a plain object");
  }
  return value as Record<string, unknown>;
}

function isEmptyRecord(value: unknown): boolean {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).length === 0;
}

function identifier(value: unknown, field: string): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/u.test(value)) {
    throw new AdmissionError("invalid_identifier", `${field} is outside the identifier grammar`);
  }
  boundedText(value, MAX_IDENTIFIER_BYTES, field);
  return value;
}

function boundedText(value: string, maxBytes: number, field: string): void {
  const bytes = new TextEncoder().encode(value).byteLength;
  if (bytes === 0 || bytes > maxBytes || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)) {
    throw new AdmissionError("invalid_text", `${field} is empty, oversized, or contains a control character`);
  }
}

function assertJson(value: unknown): asserts value is JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number" && Number.isFinite(value)) return;
  if (Array.isArray(value)) {
    for (const entry of value) assertJson(entry);
    return;
  }
  if (value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    for (const entry of Object.values(value as Record<string, unknown>)) assertJson(entry);
    return;
  }
  throw new AdmissionError("invalid_json", "resume payload must be finite JSON data");
}

function encodeBounded(value: unknown, maxBytes: number, code: string): Uint8Array {
  let encoded: string;
  try {
    encoded = JSON.stringify(value);
  } catch {
    throw new AdmissionError("invalid_json", "input is not JSON serializable");
  }
  const bytes = new TextEncoder().encode(encoded);
  if (bytes.byteLength > maxBytes) throw new AdmissionError(code, "input exceeds its byte limit");
  return bytes;
}
