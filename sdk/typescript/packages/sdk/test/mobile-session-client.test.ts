// SPDX-License-Identifier: Apache-2.0

import {describe, expect, test} from "bun:test";

import {
  MobileActor,
  MobileCredentialId,
  MobileEpochMillis,
  MobileFollowUpBytes,
  MobilePageEvents,
  MobileRevision,
  MobileServerIdentity,
  MobileSessionId,
  PlatformEpochMillis,
  PlatformRevision,
  PlatformText,
  ReceiptId,
  ResourceId,
  type ActionReceipt,
  type MobileAction,
  type MobileAuthorization,
  type ResourceCoordinate,
  type SessionCommandState,
} from "../../protocol/src/index.ts";
import {
  MobileSessionClient,
  MobileSessionError,
} from "../src/mobile-session-client.ts";
import type {
  PlatformAdapter,
  PlatformClientResponse,
} from "../src/platform-client.ts";
import type {PlatformRequest} from "../../protocol/src/index.ts";

const identity = MobileServerIdentity(`sha256:${"a".repeat(64)}`);
const NOW = 1_700_000_000_000;
const clock = (): number => NOW;
const session: ResourceCoordinate = {
  authority: "automonique",
  id: ResourceId("session-a"),
  kind: "session",
};
const run: ResourceCoordinate = {
  authority: "automonique",
  id: ResourceId("run-a"),
  kind: "run",
};
const approval: ResourceCoordinate = {
  authority: "automonique",
  id: ResourceId("approval-a"),
  kind: "approval",
};

function authorization(
  actions: readonly MobileAction[] = ["follow_up", "stop_run", "decide_approval"],
  maxFollowUpBytes = 32n,
  expiresAt = BigInt(NOW + 60_000),
): MobileAuthorization {
  return {
    actions,
    actor: MobileActor("operator:mobile"),
    authorization_revision: MobileRevision(1n),
    credential_id: MobileCredentialId(`mc_${"E".repeat(43)}`),
    credential_revision: MobileRevision(1n),
    expires_at_ms: MobileEpochMillis(expiresAt),
    issued_at_ms: MobileEpochMillis(BigInt(NOW - 1_000)),
    limits: {
      max_follow_up_bytes: MobileFollowUpBytes(maxFollowUpBytes),
      max_page_events: MobilePageEvents(16n),
    },
    schema: "automonique.mobile-auth/v1",
    server_identity: identity,
    session_scope: [MobileSessionId("session-a")],
  };
}

function receipt(
  action: ActionReceipt["action"],
  target: ResourceCoordinate,
  id = "receipt-a",
): ActionReceipt {
  return {
    action,
    explanation: null,
    id: ReceiptId(id),
    outcome: "completed",
    recorded_at: PlatformEpochMillis(BigInt(NOW)),
    revision: PlatformRevision(1n),
    target,
  };
}

function commandState(): SessionCommandState {
  return {
    pending_approvals: [{revision: PlatformRevision(7n), target: approval}],
    run: {revision: PlatformRevision(6n), target: run},
    session: {
      freshness: {
        observed_at: PlatformEpochMillis(BigInt(NOW)),
        revision: PlatformRevision(5n),
        state: "fresh",
      },
      resource: session,
      summary: PlatformText("ready"),
    },
  };
}

class RecordingAdapter implements PlatformAdapter {
  readonly requests: PlatformRequest[] = [];
  readonly responses: PlatformClientResponse[];

  constructor(responses: PlatformClientResponse[]) {
    this.responses = responses;
  }

  request(request: PlatformRequest): Promise<PlatformClientResponse> {
    this.requests.push(request);
    const response = this.responses.shift();
    if (response === undefined) throw new Error("unexpected request");
    return Promise.resolve(response);
  }
}

describe("mobile session client", () => {
  test("derives the credential client and emits only dedicated command requests", async () => {
    const adapter = new RecordingAdapter([
      {kind: "session_command_state", value: commandState()},
      {kind: "receipt", value: receipt("follow_up", session, "receipt-follow")},
      {kind: "receipt", value: receipt("stop_run", run, "receipt-stop")},
      {kind: "receipt", value: receipt("decide_approval", approval, "receipt-approval")},
      {kind: "receipt", value: receipt("stop_run", run, "receipt-reconcile-id")},
      {kind: "receipt", value: receipt("follow_up", session, "receipt-reconcile-key")},
    ]);
    const client = new MobileSessionClient(adapter, authorization(), identity, clock);

    expect("execute" in client).toBe(false);
    expect((await client.commandState(session)).session.freshness.revision).toBe(5n);
    await client.followUp({
      session,
      expectedSessionRevision: 5n,
      idempotencyKey: "follow-1",
      text: "continue",
    });
    await client.stopRun({
      session,
      expectedSessionRevision: 5n,
      run,
      expectedRunRevision: 6n,
      idempotencyKey: "stop-1",
    });
    await client.decideApproval({
      session,
      expectedSessionRevision: 5n,
      approval,
      expectedApprovalRevision: 7n,
      idempotencyKey: "approval-1",
      decision: "grant",
    });
    await client.reconcileReceipt({
      session,
      id: "receipt-reconcile-id",
      expectedAction: "stop_run",
      expectedTarget: run,
    });
    await client.reconcileReceipt({
      session,
      idempotencyKey: "follow-1",
      expectedAction: "follow_up",
      expectedTarget: session,
    });

    expect(adapter.requests.map((request) => request.method)).toEqual([
      "session_command_state",
      "session_follow_up",
      "session_run_stop",
      "session_approval_decision",
      "get_receipt",
      "get_receipt",
    ]);
    const credentialId = authorization().credential_id;
    for (const request of adapter.requests.slice(1)) {
      if (request.method === "get_receipt"
        || request.method === "session_follow_up"
        || request.method === "session_run_stop"
        || request.method === "session_approval_decision") {
        expect(request.request.client).toBe(credentialId);
      }
    }
    expect(adapter.requests[4]).toEqual({
      method: "get_receipt",
      request: {client: credentialId, id: "receipt-reconcile-id", idempotency_key: null},
    });
    expect(adapter.requests[5]).toEqual({
      method: "get_receipt",
      request: {client: credentialId, id: null, idempotency_key: "follow-1"},
    });
  });

  test("enforces identity, expiry, action, scope, kinds, and exact revisions locally", async () => {
    const never = new RecordingAdapter([]);
    expect(() => new MobileSessionClient(
      never,
      authorization(),
      MobileServerIdentity(`sha256:${"b".repeat(64)}`),
      clock,
    )).toThrow(MobileSessionError);
    expect(() => new MobileSessionClient(
      never,
      authorization(undefined, 32n, BigInt(NOW - 1)),
      identity,
      clock,
    )).toThrow(MobileSessionError);

    const attachOnly = new MobileSessionClient(never, authorization(["attach"]), identity, clock);
    await expect(attachOnly.commandState(session))
      .rejects.toMatchObject({category: "action_not_authorized"});

    const follow = new MobileSessionClient(never, authorization(["follow_up"]), identity, clock);
    await expect(follow.followUp({
      session: {...session, id: ResourceId("session-b")},
      expectedSessionRevision: 1n,
      idempotencyKey: "follow-wrong-session",
      text: "hello",
    })).rejects.toMatchObject({category: "session_not_authorized"});
    await expect(follow.followUp({
      session,
      expectedSessionRevision: 0n,
      idempotencyKey: "follow-zero-revision",
      text: "hello",
    })).rejects.toMatchObject({category: "revision_invalid"});
    await expect(follow.stopRun({
      session,
      expectedSessionRevision: 1n,
      run,
      expectedRunRevision: 1n,
      idempotencyKey: "stop-denied",
    })).rejects.toMatchObject({category: "action_not_authorized"});
    expect(never.requests).toHaveLength(0);
  });

  test("uses the injected clock and rejects the exact expiry boundary", () => {
    const never = new RecordingAdapter([]);
    const descriptor: MobileAuthorization = {
      ...authorization(),
      issued_at_ms: MobileEpochMillis(999n),
      expires_at_ms: MobileEpochMillis(1_001n),
    };
    expect(() => new MobileSessionClient(never, descriptor, identity, () => 1_000))
      .not.toThrow();
    expect(() => new MobileSessionClient(never, descriptor, identity, () => 1_001))
      .toThrow(MobileSessionError);
    expect(() => new MobileSessionClient(
      never,
      {...descriptor, issued_at_ms: MobileEpochMillis(1_001n)},
      identity,
      () => 1_000,
    )).toThrow(MobileSessionError);
    expect(() => new MobileSessionClient(never, descriptor, identity, () => Number.NaN))
      .toThrow(MobileSessionError);
  });

  test("counts UTF-8 bytes at the authorization boundary and rejects blank text", async () => {
    const adapter = new RecordingAdapter([
      {kind: "receipt", value: receipt("follow_up", session)},
    ]);
    const client = new MobileSessionClient(
      adapter,
      authorization(["follow_up"], 4n),
      identity,
      clock,
    );
    await client.followUp({
      session,
      expectedSessionRevision: 1n,
      idempotencyKey: "four-bytes",
      text: "éé",
    });
    await expect(client.followUp({
      session,
      expectedSessionRevision: 1n,
      idempotencyKey: "five-bytes",
      text: "ééa",
    })).rejects.toMatchObject({category: "follow_up_text_invalid"});
    await expect(client.followUp({
      session,
      expectedSessionRevision: 1n,
      idempotencyKey: "blank",
      text: "  ",
    })).rejects.toMatchObject({category: "follow_up_text_invalid"});
    expect(adapter.requests).toHaveLength(1);
  });

  test("fails closed on command-state and receipt action/target mismatches", async () => {
    const wrongState = commandState();
    const adapter = new RecordingAdapter([
      {
        kind: "session_command_state",
        value: {
          ...wrongState,
          session: {...wrongState.session, resource: {...session, id: ResourceId("session-b")}},
        },
      },
      {kind: "receipt", value: receipt("stop_run", run)},
      {kind: "receipt", value: receipt("follow_up", session)},
    ]);
    const client = new MobileSessionClient(adapter, authorization(), identity, clock);
    await expect(client.commandState(session))
      .rejects.toMatchObject({category: "response_target_mismatch"});
    await expect(client.followUp({
      session,
      expectedSessionRevision: 1n,
      idempotencyKey: "wrong-action",
      text: "hello",
    })).rejects.toMatchObject({category: "receipt_mismatch"});
    await expect(client.reconcileReceipt({
      session,
      idempotencyKey: "wrong-target",
      expectedAction: "follow_up",
      expectedTarget: session,
    })).resolves.toMatchObject({action: "follow_up", target: session});
  });
});
