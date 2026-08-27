// SPDX-License-Identifier: Apache-2.0

import {readFileSync} from "node:fs";
import {
  BaseSelectorId,
  AttemptWorkspaceId,
  BranchSelectorId,
  ExternalWorkAuthorityId,
  ExternalWorkKey,
  ExternalWorkScope,
  LineageMessage,
  LineageObservedAtMs,
  LineageStaleAfterMs,
  OrchestrationDecisionGateId,
  OrchestrationDispatchId,
  OrchestrationHeartbeatId,
  OrchestrationQuestionId,
  OrchestrationRunId,
  OrchestrationTaskId,
  OrchestrationWorkerId,
  PaneId,
  PlatformVersionNumber,
  PLATFORM_SCHEMA_V2,
  SupportedPlatformVersionNumber,
  UserWorkspaceId,
  WorkSessionId,
  WorkContextRevision,
  WorkspaceIntentId,
  decodeExternalWorkProvider,
  decodeExternalWorkState,
  decodeWorkspaceIntentConflict,
  decodeLineageProjection,
  decodeWorkspaceIntent,
  decodeWorkspaceIntentOutcome,
  encodeLineageProjection,
  encodeWorkspaceIntent,
  encodeWorkspaceIntentOutcome,
  negotiatePlatformVersion,
  validateExternalWorkIdentity,
  validateExternalWorkItem,
  validateLineageFreshness,
  validateLineageProjection,
  validateOrchestrationIdentity,
  validateOrchestrationRecord,
  validateWorkspaceIntent,
  validateWorkspaceIntentOutcome,
  type ExternalWorkIdentity,
  type ExternalWorkState,
  type LineageFreshness,
  type LineageStatus,
  type OrchestrationIdentity,
  type OrchestrationRecord,
  type WorkspaceIntent,
  type WorkspaceIntentOutcome,
} from "../generated/work-context.ts";

interface RawCase {
  readonly name: string;
  readonly external_work?: {readonly provider: "github" | "gitlab" | "linear" | "jira_compatible"; readonly authority?: string; readonly scope: string; readonly key: string};
  readonly external_state?: ExternalWorkState;
  readonly workspace?: string;
  readonly moved_to?: {readonly provider: "github" | "gitlab" | "linear" | "jira_compatible"; readonly authority?: string; readonly scope: string; readonly key: string};
  readonly orchestration?: RawOrchestration;
  readonly decision_gate?: RawOrchestration;
  readonly intent?: {readonly kind: "create" | "resume"; readonly request: Readonly<Record<string, unknown>>};
  readonly outcome?: {readonly kind: "accepted" | "unknown" | "conflict" | "created" | "resumed" | "cancelled"; readonly conflict?: string; readonly workspace?: string; readonly target_intent_id?: string};
  readonly client_versions?: readonly number[];
  readonly server_versions?: readonly number[];
  readonly negotiated_version?: number;
  readonly lineage_available?: boolean;
}
interface RawOrchestration {
  readonly identity: {readonly kind: string; readonly id: string};
  readonly parent: {readonly kind: string; readonly id: string} | null;
  readonly status: {readonly kind: string; readonly reason?: string; readonly outcome?: string};
  readonly freshness?: {readonly observed_at_ms: number; readonly stale_after_ms: number; readonly state: "fresh" | "stale"};
  readonly latest_useful_message?: {readonly text: string; readonly observed_at_ms: number};
}
interface RawFixture {readonly schema: string; readonly cases: readonly RawCase[]}

const fixture = JSON.parse(readFileSync("../../../../rust/crates/automonique-protocol/fixtures/platform-v2-lineage-v1.json", "utf8")) as RawFixture;
if (fixture.schema !== "automonique.platform/v2" || fixture.cases.length !== 9) throw new Error("lineage fixture header drifted");

const external = (value: NonNullable<RawCase["external_work"]>): ExternalWorkIdentity => validateExternalWorkIdentity({
  authority: ExternalWorkAuthorityId(value.authority ?? `installation-${value.scope}`),
  key: ExternalWorkKey(value.key),
  provider: decodeExternalWorkProvider(value.provider),
  scope: ExternalWorkScope(value.scope),
});
const identity = (value: {readonly kind: string; readonly id: string}): OrchestrationIdentity => {
  switch (value.kind) {
    case "run": return validateOrchestrationIdentity({kind: value.kind, id: OrchestrationRunId(value.id)});
    case "dispatch": return validateOrchestrationIdentity({kind: value.kind, id: OrchestrationDispatchId(value.id)});
    case "worker": return validateOrchestrationIdentity({kind: value.kind, id: OrchestrationWorkerId(value.id)});
    case "heartbeat": return validateOrchestrationIdentity({kind: value.kind, id: OrchestrationHeartbeatId(value.id)});
    case "question": return validateOrchestrationIdentity({kind: value.kind, id: OrchestrationQuestionId(value.id)});
    case "decision_gate": return validateOrchestrationIdentity({kind: value.kind, id: OrchestrationDecisionGateId(value.id)});
    case "task": return validateOrchestrationIdentity({kind: value.kind, id: OrchestrationTaskId(value.id)});
    default: throw new Error(`unexpected fixture orchestration kind ${value.kind}`);
  }
};
const status = (value: RawOrchestration["status"]): LineageStatus => {
  switch (value.kind) {
    case "working": return {kind: value.kind};
    case "blocked": return {kind: value.kind, reason: LineageMessage(value.reason ?? "")};
    case "waiting": return {kind: value.kind, reason: LineageMessage(value.reason ?? "")};
    case "done": return {kind: value.kind, outcome: LineageMessage(value.outcome ?? "")};
    default: throw new Error(`unexpected fixture status ${value.kind}`);
  }
};
const freshness = (value: NonNullable<RawOrchestration["freshness"]>): LineageFreshness => validateLineageFreshness({
  observed_at_ms: LineageObservedAtMs(BigInt(value.observed_at_ms)),
  stale_after_ms: LineageStaleAfterMs(BigInt(value.stale_after_ms)),
  state: value.state,
});
const outcome = (value: NonNullable<RawCase["outcome"]>): WorkspaceIntentOutcome => {
  if (value.kind === "conflict") return validateWorkspaceIntentOutcome({kind: value.kind, conflict: decodeWorkspaceIntentConflict(value.conflict ?? "")});
  if (value.kind === "accepted" || value.kind === "unknown") return validateWorkspaceIntentOutcome({kind: value.kind});
  if (value.kind === "cancelled") return validateWorkspaceIntentOutcome({kind: value.kind, target_intent_id: WorkspaceIntentId(value.target_intent_id ?? "")});
  return validateWorkspaceIntentOutcome({kind: value.kind, workspace: UserWorkspaceId(value.workspace ?? "")});
};

const origin = (workspace: string) => ({
  attempt: AttemptWorkspaceId(`attempt-${workspace}`),
  pane: PaneId(`pane-${workspace}`),
  session: WorkSessionId(`session-${workspace}`),
  workspace: UserWorkspaceId(workspace),
});

const mustRefuse = (operation: () => unknown): void => {
  try {
    operation();
  } catch {
    return;
  }
  throw new Error("malformed lineage value was accepted");
};
const mustRefuseCategory = (category: string, operation: () => unknown): void => {
  try { operation(); } catch (error) {
    if ((error as {readonly category?: string}).category === category) return;
    throw error;
  }
  throw new Error(`missing refusal ${category}`);
};

const names = new Set<string>();
const providers = new Set<string>();
let staleHeartbeats = 0;
let questionLinks = 0;
for (const entry of fixture.cases) {
  names.add(entry.name);
  if (entry.external_work) providers.add(external(entry.external_work).provider);
  if (entry.moved_to) external(entry.moved_to);
  if (entry.external_state === "moved" && !entry.moved_to) throw new Error("moved source lost replacement identity");
  if (entry.external_state !== "moved" && entry.moved_to) throw new Error("non-moved source carried replacement identity");
  if (entry.workspace) UserWorkspaceId(entry.workspace);
  if (entry.outcome) outcome(entry.outcome);
  if (entry.external_work && entry.external_state && entry.workspace) {
    const item = validateExternalWorkItem({
      freshness: freshness(entry.orchestration?.freshness ?? {observed_at_ms: 1_700_000_000_000, stale_after_ms: 30_000, state: "fresh"}),
      identity: external(entry.external_work),
      latest_useful_message: null,
      moved_to: entry.moved_to ? external(entry.moved_to) : null,
      origin: origin(entry.workspace),
      revision: WorkContextRevision(1n),
      state: decodeExternalWorkState(entry.external_state),
      workspace: UserWorkspaceId(entry.workspace),
    });
    if (item.moved_to === null) validateLineageProjection({external_work_items: [item], orchestration: [], schema: PLATFORM_SCHEMA_V2, workspace: item.workspace});
    else {
      const target = validateExternalWorkItem({...item, identity: item.moved_to, moved_to: null, state: "open"});
      validateLineageProjection({external_work_items: [item, target], orchestration: [], schema: PLATFORM_SCHEMA_V2, workspace: item.workspace});
    }
    if (entry.name === "duplicate_intake") {
      mustRefuse(() => validateLineageProjection({external_work_items: [item, item], orchestration: [], schema: PLATFORM_SCHEMA_V2, workspace: item.workspace}));
    }
  }
  if (entry.orchestration) {
    if (!entry.workspace || !entry.external_work || !entry.orchestration.freshness) throw new Error("orchestration fixture lost workspace, external work, or freshness");
    const latest = entry.orchestration.latest_useful_message
      ? {text: LineageMessage(entry.orchestration.latest_useful_message.text), observed_at_ms: LineageObservedAtMs(BigInt(entry.orchestration.latest_useful_message.observed_at_ms))}
      : null;
    const rawRecord: OrchestrationRecord = {
      external_work: external(entry.external_work),
      freshness: freshness(entry.orchestration.freshness),
      identity: identity(entry.orchestration.identity),
      latest_useful_message: latest,
      origin: origin(entry.workspace),
      parent: entry.orchestration.parent ? identity(entry.orchestration.parent) : null,
      revision: WorkContextRevision(1n),
      status: status(entry.orchestration.status),
      workspace: UserWorkspaceId(entry.workspace),
    };
    if (entry.name === "orphan_dispatch") mustRefuse(() => validateOrchestrationRecord(rawRecord));
    else validateOrchestrationRecord(rawRecord);
    if (entry.orchestration.freshness?.state === "stale") staleHeartbeats += Number(freshness(entry.orchestration.freshness).state === "stale");
    if (entry.orchestration.identity.kind === "question") questionLinks += 1;
  }
  if (entry.decision_gate) {
    identity(entry.decision_gate.identity);
    if (!entry.decision_gate.parent || identity(entry.decision_gate.parent).kind !== "question") throw new Error("decision gate lost question parent");
    status(entry.decision_gate.status);
    questionLinks += 1;
  }
  if (entry.intent) {
    const raw = entry.intent.request;
    const common = {
      intent_id: WorkspaceIntentId(String(raw.intent_id)),
      task: OrchestrationTaskId(String(raw.task)),
    };
    const rawIntent: WorkspaceIntent = entry.intent.kind === "create"
      ? {kind: "create", request: {...common, external_work: external(raw.external_work as NonNullable<RawCase["external_work"]>), base_selector: BaseSelectorId(String(raw.base_selector)), branch_selector: BranchSelectorId(String(raw.branch_selector))}}
      : {kind: "resume", request: {...common, workspace: UserWorkspaceId(String(raw.workspace)), expected_revision: WorkContextRevision(BigInt(String(raw.expected_revision)))}};
    const checked = validateWorkspaceIntent(rawIntent);
    if (checked.kind !== entry.intent.kind) throw new Error("intent kind drifted");
  }
  if (entry.client_versions && entry.server_versions) {
    const offer = (versions: readonly number[]) => ({schema: "automonique.platform/negotiation/v1" as const, versions: versions.map((version) => PlatformVersionNumber(BigInt(version)))});
    const selected = negotiatePlatformVersion(offer(entry.client_versions), offer(entry.server_versions));
    if (selected.version !== SupportedPlatformVersionNumber(BigInt(entry.negotiated_version ?? 0))) throw new Error("mixed-version fixture drifted");
    if ((selected.version === 2n) !== entry.lineage_available) throw new Error("lineage availability drifted");
  }
}

mustRefuse(() => validateExternalWorkIdentity({authority: ExternalWorkAuthorityId("installation"), provider: "unknown" as never, scope: ExternalWorkScope("scope"), key: ExternalWorkKey("key")}));
mustRefuse(() => validateLineageFreshness({observed_at_ms: 0n as never, stale_after_ms: LineageStaleAfterMs(1n), state: "fresh"}));
const selfParent = {kind: "task" as const, id: OrchestrationTaskId("task-self")};
mustRefuse(() => validateOrchestrationRecord({
  external_work: null,
  freshness: validateLineageFreshness({observed_at_ms: LineageObservedAtMs(1n), stale_after_ms: LineageStaleAfterMs(1n), state: "fresh"}),
  identity: selfParent,
  latest_useful_message: null,
  origin: origin("workspace-self"),
  parent: selfParent,
  revision: WorkContextRevision(1n),
  status: {kind: "working"},
  workspace: UserWorkspaceId("workspace-self"),
}));

for (const required of ["duplicate_intake", "moved_source", "closed_source", "orphan_dispatch", "stale_heartbeat", "question_and_gate", "cancelled_creation", "mixed_version_downgrade", "mixed_version_recovery"]) {
  if (!names.has(required)) throw new Error(`missing fixture ${required}`);
}
const exactProjection = "{\"platform_version\":2,\"schema\":\"automonique.platform/v2\",\"value\":{\"external_work_items\":[],\"orchestration\":[],\"schema\":\"automonique.platform/v2\",\"workspace\":\"workspace-codec\"}}";
const v2Offer = {schema: "automonique.platform/negotiation/v1" as const, versions: [PlatformVersionNumber(2n)]};
const lineageV2 = negotiatePlatformVersion(v2Offer, v2Offer);
const decodedProjection = decodeLineageProjection(lineageV2, new TextEncoder().encode(exactProjection));
if (new TextDecoder().decode(encodeLineageProjection(lineageV2, decodedProjection)) !== exactProjection) throw new Error("lineage codec exact-byte drifted");
const exactIntent = "{\"platform_version\":2,\"schema\":\"automonique.platform/v2\",\"value\":{\"kind\":\"create\",\"request\":{\"base_selector\":\"base-codec\",\"branch_selector\":\"branch-codec\",\"external_work\":{\"authority\":\"installation-codec\",\"key\":\"issue-codec\",\"provider\":\"gitlab\",\"scope\":\"scope-codec\"},\"intent_id\":\"intent-codec\",\"task\":\"task-codec\"}}}";
if (new TextDecoder().decode(encodeWorkspaceIntent(lineageV2, decodeWorkspaceIntent(lineageV2, new TextEncoder().encode(exactIntent)))) !== exactIntent) throw new Error("intent codec exact-byte drifted");
const exactOutcome = "{\"platform_version\":2,\"schema\":\"automonique.platform/v2\",\"value\":{\"kind\":\"accepted\"}}";
if (new TextDecoder().decode(encodeWorkspaceIntentOutcome(lineageV2, decodeWorkspaceIntentOutcome(lineageV2, new TextEncoder().encode(exactOutcome)))) !== exactOutcome) throw new Error("outcome codec exact-byte drifted");
const exactCancel = "{\"platform_version\":2,\"schema\":\"automonique.platform/v2\",\"value\":{\"kind\":\"cancel\",\"request\":{\"expected_revision\":1,\"intent_id\":\"cancel-codec\",\"target_intent_id\":\"intent-codec\",\"workspace\":\"workspace-codec\"}}}";
if (new TextDecoder().decode(encodeWorkspaceIntent(lineageV2, decodeWorkspaceIntent(lineageV2, new TextEncoder().encode(exactCancel)))) !== exactCancel) throw new Error("cancel intent codec exact-byte drifted");
const exactCancelled = "{\"platform_version\":2,\"schema\":\"automonique.platform/v2\",\"value\":{\"kind\":\"cancelled\",\"target_intent_id\":\"intent-codec\"}}";
if (new TextDecoder().decode(encodeWorkspaceIntentOutcome(lineageV2, decodeWorkspaceIntentOutcome(lineageV2, new TextEncoder().encode(exactCancelled)))) !== exactCancelled) throw new Error("cancel outcome codec exact-byte drifted");
mustRefuse(() => validateWorkspaceIntent({kind: "cancel", request: {expected_revision: WorkContextRevision(1n), intent_id: WorkspaceIntentId("self"), target_intent_id: WorkspaceIntentId("self"), workspace: UserWorkspaceId("workspace-codec")}}));
mustRefuse(() => decodeLineageProjection(lineageV2, new TextEncoder().encode(exactProjection.replace("\"platform_version\":2", "\"platform_version\":1"))));
mustRefuse(() => decodeWorkspaceIntentOutcome(lineageV2, new TextEncoder().encode(exactOutcome.replace("accepted", "undefined"))));
const negativeObservation = "{\"platform_version\":2,\"schema\":\"automonique.platform/v2\",\"value\":{\"external_work_items\":[{\"freshness\":{\"observed_at_ms\":-1,\"stale_after_ms\":30000,\"state\":\"fresh\"},\"identity\":{\"authority\":\"installation-codec\",\"key\":\"issue-codec\",\"provider\":\"gitlab\",\"scope\":\"scope-codec\"},\"latest_useful_message\":null,\"moved_to\":null,\"origin\":{\"attempt\":null,\"pane\":null,\"session\":null,\"workspace\":\"workspace-codec\"},\"revision\":1,\"state\":\"open\",\"workspace\":\"workspace-codec\"}],\"orchestration\":[],\"schema\":\"automonique.platform/v2\",\"workspace\":\"workspace-codec\"}}";
mustRefuseCategory("work_context_counter_out_of_range", () => decodeLineageProjection(lineageV2, new TextEncoder().encode(negativeObservation)));
const exactMoved = "{\"platform_version\":2,\"schema\":\"automonique.platform/v2\",\"value\":{\"external_work_items\":[{\"freshness\":{\"observed_at_ms\":1700000000001,\"stale_after_ms\":30000,\"state\":\"fresh\"},\"identity\":{\"authority\":\"installation-self-hosted\",\"key\":\"issue-7\",\"provider\":\"gitlab\",\"scope\":\"scope-a\"},\"latest_useful_message\":null,\"moved_to\":{\"authority\":\"installation-self-hosted\",\"key\":\"issue-7\",\"provider\":\"gitlab\",\"scope\":\"scope-b\"},\"origin\":{\"attempt\":\"attempt-codec\",\"pane\":\"pane-codec\",\"session\":\"session-codec\",\"workspace\":\"workspace-codec\"},\"revision\":2,\"state\":\"moved\",\"workspace\":\"workspace-codec\"},{\"freshness\":{\"observed_at_ms\":1700000000000,\"stale_after_ms\":30000,\"state\":\"fresh\"},\"identity\":{\"authority\":\"installation-self-hosted\",\"key\":\"issue-7\",\"provider\":\"gitlab\",\"scope\":\"scope-b\"},\"latest_useful_message\":null,\"moved_to\":null,\"origin\":{\"attempt\":\"attempt-codec\",\"pane\":\"pane-codec\",\"session\":\"session-codec\",\"workspace\":\"workspace-codec\"},\"revision\":1,\"state\":\"open\",\"workspace\":\"workspace-codec\"}],\"orchestration\":[],\"schema\":\"automonique.platform/v2\",\"workspace\":\"workspace-codec\"}}";
const movedProjection = decodeLineageProjection(lineageV2, new TextEncoder().encode(exactMoved));
if (movedProjection.external_work_items.length !== 2 || movedProjection.external_work_items[0]?.origin.pane === null) throw new Error("moved lineage corpus lost origin or target");
if (new TextDecoder().decode(encodeLineageProjection(lineageV2, movedProjection)) !== exactMoved) throw new Error("moved lineage exact-byte drifted");
const movedA = movedProjection.external_work_items[0]!;
const movedB = movedProjection.external_work_items[1]!;
mustRefuse(() => validateLineageProjection({...movedProjection, external_work_items: [movedA, {...movedB, moved_to: movedA.identity, state: "moved"}]}));
console.log(JSON.stringify({cases: names.size, codec_bytes: exactProjection.length + exactIntent.length + exactOutcome.length + exactCancel.length + exactCancelled.length, providers: providers.size, question_links: questionLinks, stale_heartbeats: staleHeartbeats}));
