// SPDX-License-Identifier: Apache-2.0

import {
  IdempotencyKey,
  PlatformParameter,
  PlatformRevision,
  ReceiptId,
  type ActionReceipt,
  type MobileAction,
  type MobileAuthorization,
  type MobileServerIdentity,
  type PlatformAction,
  type ResourceCoordinate,
  type SessionApprovalDecision,
  type SessionCommandState,
} from "../../protocol/src/index.js";
import {mobilePlatformClientId} from "./mobile-auth-client.js";
import {
  PlatformTransportError,
  type PlatformAdapter,
  type PlatformClientResponse,
} from "./platform-client.js";

export interface MobileFollowUpRequest {
  readonly session: ResourceCoordinate;
  readonly expectedSessionRevision: bigint;
  readonly idempotencyKey: string;
  readonly text: string;
}

export interface MobileStopRunRequest {
  readonly session: ResourceCoordinate;
  readonly expectedSessionRevision: bigint;
  readonly run: ResourceCoordinate;
  readonly expectedRunRevision: bigint;
  readonly idempotencyKey: string;
}

export interface MobileApprovalDecisionRequest {
  readonly session: ResourceCoordinate;
  readonly expectedSessionRevision: bigint;
  readonly approval: ResourceCoordinate;
  readonly expectedApprovalRevision: bigint;
  readonly idempotencyKey: string;
  readonly decision: SessionApprovalDecision;
}

export type MobileSessionAction = Extract<
  PlatformAction,
  "decide_approval" | "follow_up" | "stop_run"
>;

interface MobileReceiptExpectation {
  readonly session: ResourceCoordinate;
  readonly expectedAction: MobileSessionAction;
  readonly expectedTarget: ResourceCoordinate;
}

export type MobileReceiptLookup = MobileReceiptExpectation & (
  | {readonly id: string; readonly idempotencyKey?: never}
  | {readonly id?: never; readonly idempotencyKey: string}
);

export class MobileSessionError extends Error {
  readonly category: string;

  constructor(category: string, options?: ErrorOptions) {
    super(`mobile session command refused: ${category}`, options);
    this.name = "MobileSessionError";
    this.category = category;
  }
}

function sameCoordinate(left: ResourceCoordinate, right: ResourceCoordinate): boolean {
  return left.authority === right.authority
    && left.kind === right.kind
    && left.id === right.id;
}

function requireCoordinate(
  coordinate: ResourceCoordinate,
  kind: "approval" | "run" | "session",
): void {
  if (coordinate.authority !== "automonique" || coordinate.kind !== kind) {
    throw new MobileSessionError(`${kind}_coordinate_invalid`);
  }
}

/**
 * React Native-safe session command facade for one exact mobile authorization.
 *
 * The underlying adapter stays private: callers cannot reach generic execute or
 * supply a different Platform client identity through this surface.
 */
export class MobileSessionClient {
  readonly authorization: MobileAuthorization;
  readonly expectedServerIdentity: MobileServerIdentity;
  readonly #transport: PlatformAdapter;
  readonly #now: () => number;

  constructor(
    transport: PlatformAdapter,
    authorization: MobileAuthorization,
    expectedServerIdentity: MobileServerIdentity,
    now: () => number = Date.now,
  ) {
    this.#transport = transport;
    this.authorization = authorization;
    this.expectedServerIdentity = expectedServerIdentity;
    this.#now = now;
    this.requireAuthorization();
  }

  async commandState(
    session: ResourceCoordinate,
    signal?: AbortSignal,
  ): Promise<SessionCommandState> {
    this.requireSession(session);
    if (!this.hasAnyAction(["follow_up", "stop_run", "decide_approval"])) {
      throw new MobileSessionError("action_not_authorized");
    }
    const response = await this.#transport.request({
      method: "session_command_state",
      request: {session},
    }, signal);
    if (response.kind === "refused") throw new MobileSessionError("remote_refusal");
    if (response.kind !== "session_command_state") {
      throw new PlatformTransportError(502, "response_kind_mismatch");
    }
    const state = response.value;
    if (!sameCoordinate(state.session.resource, session)) {
      throw new MobileSessionError("response_target_mismatch");
    }
    if (state.run !== null) {
      requireCoordinate(state.run.target, "run");
      if (!this.authorization.actions.includes("stop_run")) {
        throw new MobileSessionError("response_action_mismatch");
      }
    }
    if (state.pending_approvals.length > 0
      && !this.authorization.actions.includes("decide_approval")) {
      throw new MobileSessionError("response_action_mismatch");
    }
    const approvals = new Set<string>();
    for (const pending of state.pending_approvals) {
      requireCoordinate(pending.target, "approval");
      if (approvals.has(pending.target.id)) {
        throw new MobileSessionError("response_target_mismatch");
      }
      approvals.add(pending.target.id);
    }
    return state;
  }

  async followUp(request: MobileFollowUpRequest, signal?: AbortSignal): Promise<ActionReceipt> {
    this.requireActionAndSession("follow_up", request.session);
    const text = this.followUpText(request.text);
    const response = await this.#transport.request({
      method: "session_follow_up",
      request: {
        client: mobilePlatformClientId(this.authorization),
        expected_session_revision: this.revision(request.expectedSessionRevision),
        idempotency_key: this.idempotencyKey(request.idempotencyKey),
        session: request.session,
        text,
      },
    }, signal);
    return this.requireReceipt(response, "follow_up", request.session);
  }

  async stopRun(request: MobileStopRunRequest, signal?: AbortSignal): Promise<ActionReceipt> {
    this.requireActionAndSession("stop_run", request.session);
    requireCoordinate(request.run, "run");
    const response = await this.#transport.request({
      method: "session_run_stop",
      request: {
        client: mobilePlatformClientId(this.authorization),
        expected_run_revision: this.revision(request.expectedRunRevision),
        expected_session_revision: this.revision(request.expectedSessionRevision),
        idempotency_key: this.idempotencyKey(request.idempotencyKey),
        run: request.run,
        session: request.session,
      },
    }, signal);
    return this.requireReceipt(response, "stop_run", request.run);
  }

  async decideApproval(
    request: MobileApprovalDecisionRequest,
    signal?: AbortSignal,
  ): Promise<ActionReceipt> {
    this.requireActionAndSession("decide_approval", request.session);
    requireCoordinate(request.approval, "approval");
    if (request.decision !== "grant" && request.decision !== "deny") {
      throw new MobileSessionError("approval_decision_invalid");
    }
    const response = await this.#transport.request({
      method: "session_approval_decision",
      request: {
        approval: request.approval,
        client: mobilePlatformClientId(this.authorization),
        decision: request.decision,
        expected_approval_revision: this.revision(request.expectedApprovalRevision),
        expected_session_revision: this.revision(request.expectedSessionRevision),
        idempotency_key: this.idempotencyKey(request.idempotencyKey),
        session: request.session,
      },
    }, signal);
    return this.requireReceipt(response, "decide_approval", request.approval);
  }

  async reconcileReceipt(
    request: MobileReceiptLookup,
    signal?: AbortSignal,
  ): Promise<ActionReceipt> {
    this.requireActionAndSession(request.expectedAction, request.session);
    const byId = request.id !== undefined;
    if (byId === (request.idempotencyKey !== undefined)) {
      throw new MobileSessionError("receipt_lookup_invalid");
    }
    this.requireExpectedTarget(request.expectedAction, request.session, request.expectedTarget);
    const response = await this.#transport.request({
      method: "get_receipt",
      request: {
        client: mobilePlatformClientId(this.authorization),
        id: byId ? this.receiptId(request.id) : null,
        idempotency_key: byId ? null : this.idempotencyKey(request.idempotencyKey),
      },
    }, signal);
    return this.requireReceipt(response, request.expectedAction, request.expectedTarget);
  }

  private requireAuthorization(): void {
    const nowValue = this.#now();
    if (!Number.isSafeInteger(nowValue) || nowValue < 0) {
      throw new MobileSessionError("authorization_invalid");
    }
    const now = BigInt(nowValue);
    const authorization = this.authorization;
    if (
      authorization.server_identity !== this.expectedServerIdentity
      || authorization.issued_at_ms > now
      || authorization.issued_at_ms >= authorization.expires_at_ms
      || authorization.expires_at_ms <= now
      || authorization.actions.length === 0
      || authorization.actions.some((action) => ![
        "attach",
        "decide_approval",
        "follow_up",
        "stop_run",
      ].includes(action))
      || new Set(authorization.actions).size !== authorization.actions.length
      || new Set(authorization.session_scope).size !== authorization.session_scope.length
    ) {
      throw new MobileSessionError("authorization_invalid");
    }
  }

  private requireSession(session: ResourceCoordinate): void {
    this.requireAuthorization();
    requireCoordinate(session, "session");
    if (!this.authorization.session_scope.some((id) => String(id) === String(session.id))) {
      throw new MobileSessionError("session_not_authorized");
    }
  }

  private requireActionAndSession(action: MobileAction, session: ResourceCoordinate): void {
    this.requireSession(session);
    if (!this.authorization.actions.includes(action)) {
      throw new MobileSessionError("action_not_authorized");
    }
  }

  private hasAnyAction(actions: readonly MobileAction[]): boolean {
    return actions.some((action) => this.authorization.actions.includes(action));
  }

  private requireExpectedTarget(
    action: MobileSessionAction,
    session: ResourceCoordinate,
    target: ResourceCoordinate,
  ): void {
    switch (action) {
      case "follow_up":
        requireCoordinate(target, "session");
        if (!sameCoordinate(target, session)) {
          throw new MobileSessionError("receipt_target_invalid");
        }
        return;
      case "stop_run":
        requireCoordinate(target, "run");
        return;
      case "decide_approval":
        requireCoordinate(target, "approval");
        return;
    }
  }

  private idempotencyKey(value: string): ReturnType<typeof IdempotencyKey> {
    try {
      return IdempotencyKey(value);
    } catch (error) {
      throw new MobileSessionError("idempotency_key_invalid", {cause: error});
    }
  }

  private receiptId(value: string): ReturnType<typeof ReceiptId> {
    try {
      return ReceiptId(value);
    } catch (error) {
      throw new MobileSessionError("receipt_id_invalid", {cause: error});
    }
  }

  private revision(value: bigint): ReturnType<typeof PlatformRevision> {
    try {
      return PlatformRevision(value);
    } catch (error) {
      throw new MobileSessionError("revision_invalid", {cause: error});
    }
  }

  private followUpText(value: string): ReturnType<typeof PlatformParameter> {
    try {
      if (value.trim().length === 0) throw new Error("blank follow-up");
      const encoded = new TextEncoder().encode(value);
      if (BigInt(encoded.byteLength) > this.authorization.limits.max_follow_up_bytes) {
        throw new Error("follow-up exceeds authorization limit");
      }
      return PlatformParameter(value);
    } catch (error) {
      throw new MobileSessionError("follow_up_text_invalid", {cause: error});
    }
  }

  private requireReceipt(
    response: PlatformClientResponse,
    expectedAction: PlatformAction,
    expectedTarget: ResourceCoordinate,
  ): ActionReceipt {
    if (response.kind === "refused") throw new MobileSessionError("remote_refusal");
    if (response.kind !== "receipt") {
      throw new PlatformTransportError(502, "response_kind_mismatch");
    }
    if (
      response.value.action !== expectedAction
      || !sameCoordinate(response.value.target, expectedTarget)
    ) {
      throw new MobileSessionError("receipt_mismatch");
    }
    return response.value;
  }
}

// Compile-time guard for the security boundary promised by this facade.
type Assert<T extends true> = T;
type _MobileSessionClientHasNoExecute = Assert<
  "execute" extends keyof MobileSessionClient ? false : true
>;
