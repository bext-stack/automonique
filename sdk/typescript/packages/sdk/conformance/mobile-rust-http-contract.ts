// SPDX-License-Identifier: Apache-2.0

export {};

type SdkModule = typeof import("../src/index.ts");

// Keep the clean-tree typecheck independent of build output while the live
// Rust contract still exercises the package that `bun run build` emitted.
const builtSdkEntry: string = "../dist/sdk/src/index.js";
const {
  MOBILE_AUTH_MEDIA_TYPE,
  ClientId,
  IdempotencyKey,
  MobileFollowUpBytes,
  MobileCredentialPageSize,
  MobileLifecycleClient,
  MobileLifecycleError,
  MobileProtocolUnsupportedError,
  MobileSessionClient,
  MobilePageEvents,
  HttpsPlatformTransport,
  PlatformRequestId,
  MobileServerIdentity,
  MobileSessionId,
  PlatformParameter,
  SUPPORTED_MOBILE_PROTOCOL_VERSIONS,
  decodeMobileError,
  encodeMobileRefreshRequest,
  encodePlatformRequestMessage,
  parseCanonical,
  PlatformRevision,
  ResourceId,
  toCanonicalBytes,
} = await import(builtSdkEntry) as SdkModule;

declare const process: {readonly argv: readonly string[]};

const transportOrigin = process.argv[2];
if (transportOrigin === undefined) throw new Error("missing Rust mobile HTTP transport origin");
const canonicalOrigin = "https://dashboard.example.invalid";
let sawNoStore = 0;

const routeFetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
  const requested = new URL(input.toString());
  const headers = new Headers(init?.headers);
  headers.set("host", "dashboard.example.invalid");
  headers.set("x-forwarded-proto", "https");
  const response = await fetch(`${transportOrigin}${requested.pathname}${requested.search}`, {
    ...init,
    headers,
  });
  Object.defineProperty(response, "url", {value: requested.toString()});
  return response;
};

const routedFetch = (async (input: string | URL | Request, init?: RequestInit) => {
  const requested = new URL(input.toString());
  const response = await routeFetch(input, init);
  if (response.headers.get("content-type")?.trim() !== MOBILE_AUTH_MEDIA_TYPE) {
    throw new Error(`mobile media type mismatch at ${requested.pathname}`);
  }
  if (!response.headers.get("cache-control")?.toLowerCase().includes("no-store")) {
    throw new Error(`mobile response is cacheable at ${requested.pathname}`);
  }
  sawNoStore += 1;
  return response;
}) as typeof fetch;

// The discovery document the Rust server actually served, kept so the
// negotiation cases below run against a real advertisement rather than a
// hand-written fixture. Captured from the one exchange `discover` already
// makes, so the fixture server's connection budget is unchanged.
let servedDiscovery: Uint8Array | undefined;
const capturingFetch = (async (input: string | URL | Request, init?: RequestInit) => {
  const response = await routedFetch(input, init);
  servedDiscovery = new Uint8Array(await response.clone().arrayBuffer());
  return response;
}) as typeof fetch;

const client = await MobileLifecycleClient.discover(canonicalOrigin, capturingFetch);
if (client.discovery.server_identity.length !== 71) throw new Error("server identity shape mismatch");
if (servedDiscovery === undefined) throw new Error("discovery document was not captured");
const servedDiscoveryBody: Uint8Array = servedDiscovery;
const servedVersions = client.discovery.supported_versions;
const highestSupported =
  SUPPORTED_MOBILE_PROTOCOL_VERSIONS[SUPPORTED_MOBILE_PROTOCOL_VERSIONS.length - 1];
if (highestSupported === undefined) throw new Error("this build speaks no mobile protocol version");
if (client.protocolVersion !== highestSupported) {
  throw new Error(`live discovery negotiated ${client.protocolVersion}, not ${highestSupported}`);
}
if (servedVersions.length !== SUPPORTED_MOBILE_PROTOCOL_VERSIONS.length
  || servedVersions.some((version, index) => version !== SUPPORTED_MOBILE_PROTOCOL_VERSIONS[index])) {
  throw new Error("the Rust server advertised a different support range than the SDK speaks");
}

/**
 * Replay the served document with a different advertised version list.
 *
 * Everything but `supported_versions` stays exactly what Rust produced —
 * origin, endpoints, identity, media type and cache directive — so these
 * exercise the negotiation rule and nothing else.
 */
async function discoverAdvertising(versions: readonly bigint[]) {
  const served = parseCanonical(servedDiscoveryBody);
  if (served.kind !== "object") throw new Error("served discovery is not an object");
  const rewritten = {
    kind: "object" as const,
    entries: served.entries.map(([key, value]) =>
      key === "supported_versions"
        ? [key, {
          kind: "array" as const,
          items: versions.map((version) => ({kind: "integer" as const, value: version})),
        }] as const
        : [key, value] as const),
  };
  const body = new TextDecoder().decode(toCanonicalBytes(rewritten));
  const replay = (async () => new Response(body, {
    headers: {"cache-control": "no-store", "content-type": MOBILE_AUTH_MEDIA_TYPE},
  })) as typeof fetch;
  return MobileLifecycleClient.discover(canonicalOrigin, replay);
}

const unsupportedVersion = highestSupported + 1n;
const forwardCompatible = await discoverAdvertising([unsupportedVersion, highestSupported]);
if (forwardCompatible.protocolVersion !== highestSupported) {
  throw new Error("a newer advertised version displaced the highest shared one");
}
try {
  await discoverAdvertising([unsupportedVersion]);
  throw new Error("a server sharing no protocol version was admitted");
} catch (error) {
  if (!(error instanceof MobileProtocolUnsupportedError)) throw error;
  if (error.category !== "mobile_protocol_unsupported") {
    throw new Error(`no-overlap refusal changed category: ${error.category}`);
  }
  if (error.supported.length !== SUPPORTED_MOBILE_PROTOCOL_VERSIONS.length) {
    throw new Error("the refusal did not name this build's supported set");
  }
}
try {
  await discoverAdvertising([]);
  throw new Error("an empty advertisement was admitted");
} catch (error) {
  if (!(error instanceof MobileProtocolUnsupportedError)) throw error;
}
try {
  await discoverAdvertising([0n]);
  throw new Error("a malformed version value was admitted");
} catch (error) {
  if (!(error instanceof MobileLifecycleError) || error.category !== "mobile_auth_value_invalid") {
    throw new Error("a malformed version value stopped being told apart from an unsupported one");
  }
}

const dashboard = await routeFetch(`${canonicalOrigin}/`, {
  method: "GET",
  headers: {authorization: "Basic b3BzOmZpeHR1cmUtcGFzc3dvcmQ="},
});
const dashboardSession = dashboard.headers.get("set-cookie")?.split(";", 1)[0];
if (dashboard.status !== 200 || dashboardSession === undefined) {
  throw new Error("failed to establish dashboard session fixture");
}
const sessionCookie = dashboardSession;

const pairingScope = {
  actions: ["attach"] as const,
  limits: {
    max_follow_up_bytes: MobileFollowUpBytes(32n),
    max_page_events: MobilePageEvents(16n),
  },
  session_scope: [MobileSessionId("session-a")],
};

async function expectMobilePlatformDenial(token: string): Promise<void> {
  const body = encodePlatformRequestMessage(PlatformRequestId("mobile-exclusive"), {
    method: "capabilities",
  });
  const response = await routeFetch(`${canonicalOrigin}/api/platform`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      cookie: sessionCookie,
      "content-type": "application/vnd.automonique.platform.v1+json",
    },
    body: new TextDecoder().decode(body),
  });
  if (response.status !== 401) {
    throw new Error(`mobile bearer fell back to dashboard session: ${response.status}`);
  }
  const challenge = response.headers.get("www-authenticate") ?? "";
  if (!challenge.startsWith("Bearer ") || challenge.includes("Basic")) {
    throw new Error(`mobile bearer received a downgrade challenge: ${challenge}`);
  }
}

async function expectScopedPlatformDenial(
  token: string,
  suffix: string,
  request: Parameters<typeof encodePlatformRequestMessage>[1],
): Promise<void> {
  const body = encodePlatformRequestMessage(PlatformRequestId(`mobile-scope-${suffix}`), request);
  const response = await routeFetch(`${canonicalOrigin}/api/platform`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/vnd.automonique.platform.v1+json",
    },
    body: new TextDecoder().decode(body),
  });
  if (response.status !== 403) {
    throw new Error(`mobile policy admitted ${suffix}: ${response.status}`);
  }
}

await expectMobilePlatformDenial(`ma_${"Z".repeat(43)}`);

let cookieProvisionStatus = 0;
{
  const body = toCanonicalBytes({
    kind: "object",
    entries: [
      ["actions", {kind: "array", items: [{kind: "string", value: "attach"}]}],
      ["limits", {kind: "object", entries: [
        ["max_follow_up_bytes", {kind: "integer", value: 32n}],
        ["max_page_events", {kind: "integer", value: 16n}],
      ]}],
      ["session_scope", {kind: "array", items: [{kind: "string", value: "session-a"}]}],
    ],
  });
  const response = await routedFetch(`${canonicalOrigin}/api/mobile/operator-provision`, {
    method: "POST",
    headers: {
      accept: MOBILE_AUTH_MEDIA_TYPE,
      cookie: dashboardSession,
      "content-type": MOBILE_AUTH_MEDIA_TYPE,
    },
    body: new TextDecoder().decode(body),
  });
  cookieProvisionStatus = response.status;
}
if (cookieProvisionStatus !== 401) throw new Error("operator provisioning accepted a session cookie");

{
  const body = new TextDecoder().decode(toCanonicalBytes({
    kind: "object",
    entries: [
      ["actions", {kind: "array", items: [{kind: "string", value: "attach"}]}],
      ["limits", {kind: "object", entries: [
        ["max_follow_up_bytes", {kind: "integer", value: 32n}],
        ["max_page_events", {kind: "integer", value: 16n}],
      ]}],
      ["session_scope", {kind: "array", items: [{kind: "string", value: "session-a"}]}],
    ],
  }));
  const sessionDenied = await routedFetch(`${canonicalOrigin}/api/mobile/pairings`, {
    method: "POST",
    headers: {cookie: sessionCookie, "content-type": MOBILE_AUTH_MEDIA_TYPE},
    body,
  });
  if (sessionDenied.status !== 401) throw new Error("pairing creation accepted dashboard session");
  const manageDenied = await routedFetch(`${canonicalOrigin}/api/mobile/pairings`, {
    method: "POST",
    headers: {authorization: "Bearer manage-token", "content-type": MOBILE_AUTH_MEDIA_TYPE},
    body,
  });
  if (manageDenied.status !== 401) throw new Error("pairing creation accepted Manage bearer");
}

const offer = await client.createPairing(pairingScope, "Basic b3BzOmZpeHR1cmUtcGFzc3dvcmQ=");
{
  const malformed = toCanonicalBytes({
    kind: "object",
    entries: [
      ["pairing_id", {kind: "string", value: offer.pairing_id}],
      ["pairing_token", {kind: "string", value: offer.pairing_token}],
      ["server_identity", {kind: "string", value: offer.server_identity}],
      ["unexpected", {kind: "bool", value: true}],
    ],
  });
  const response = await routedFetch(client.discovery.pairing_exchange_endpoint, {
    method: "POST",
    headers: {"content-type": MOBILE_AUTH_MEDIA_TYPE},
    body: new TextDecoder().decode(malformed),
  });
  if (response.status !== 400) throw new Error("pairing exchange accepted an unknown field");
}
const paired = await client.exchangePairing({
  pairing_id: offer.pairing_id,
  pairing_token: offer.pairing_token,
  server_identity: offer.server_identity,
});
try {
  await client.exchangePairing({
    pairing_id: offer.pairing_id,
    pairing_token: offer.pairing_token,
    server_identity: offer.server_identity,
  });
  throw new Error("consumed pairing replay succeeded");
} catch (error) {
  if (!(error instanceof MobileLifecycleError) || error.status !== 401) throw error;
}
if ((await client.authorization(paired.access_token)).credential_id !== paired.authorization.credential_id) {
  throw new Error("paired credential admission mismatch");
}
{
  const body = new TextDecoder().decode(toCanonicalBytes({
    kind: "object",
    entries: [
      ["actions", {kind: "array", items: [{kind: "string", value: "attach"}]}],
      ["limits", {kind: "object", entries: [
        ["max_follow_up_bytes", {kind: "integer", value: 32n}],
        ["max_page_events", {kind: "integer", value: 16n}],
      ]}],
      ["session_scope", {kind: "array", items: [{kind: "string", value: "session-a"}]}],
    ],
  }));
  const mobileDenied = await routedFetch(`${canonicalOrigin}/api/mobile/pairings`, {
    method: "POST",
    headers: {authorization: `Bearer ${paired.access_token}`, "content-type": MOBILE_AUTH_MEDIA_TYPE},
    body,
  });
  if (mobileDenied.status !== 401) throw new Error("pairing creation accepted mobile bearer");
}
const inventory = await client.credentialInventory({
  cursor: null,
  page_size: MobileCredentialPageSize(100n),
}, "Basic b3BzOmZpeHR1cmUtcGFzc3dvcmQ=");
if (!inventory.credentials.some((entry) => entry.authorization.credential_id === paired.authorization.credential_id)) {
  throw new Error("paired credential absent from operator inventory");
}
await client.revokeCredential({credential_id: paired.authorization.credential_id}, "Basic b3BzOmZpeHR1cmUtcGFzc3dvcmQ=");
try {
  await client.authorization(paired.access_token);
  throw new Error("operator-revoked paired access succeeded");
} catch (error) {
  if (!(error instanceof MobileLifecycleError) || error.status !== 401) throw error;
}

const first = await client.provision({
  actions: ["attach", "decide_approval", "follow_up", "stop_run"],
  limits: {
    max_follow_up_bytes: MobileFollowUpBytes(4096n),
    max_page_events: MobilePageEvents(128n),
  },
  session_scope: [MobileSessionId("session-a")],
}, "Basic b3BzOmZpeHR1cmUtcGFzc3dvcmQ=");
if (first.authorization.credential_revision !== 1n) throw new Error("initial revision mismatch");
if (first.authorization.actor !== "operator:mobile-contract") throw new Error("actor mismatch");
if ((await client.authorization(first.access_token)).credential_id !== first.authorization.credential_id) {
  throw new Error("initial access admission mismatch");
}

const second = await client.refresh(first.refresh_token);
if (second.authorization.credential_revision !== 2n) throw new Error("refresh did not rotate revision");
if (second.access_token === first.access_token || second.refresh_token === first.refresh_token) {
  throw new Error("refresh did not rotate both secrets");
}

try {
  await client.authorization(first.access_token);
  throw new Error("rotated access credential succeeded");
} catch (error) {
  if (!(error instanceof MobileLifecycleError) || error.status !== 401) throw error;
}

{
  const body = toCanonicalBytes(encodeMobileRefreshRequest({
    refresh_token: second.refresh_token,
    server_identity: MobileServerIdentity(`sha256:${"f".repeat(64)}`),
  }));
  const response = await routedFetch(`${canonicalOrigin}/api/mobile/refresh`, {
    method: "POST",
    headers: {accept: MOBILE_AUTH_MEDIA_TYPE, "content-type": MOBILE_AUTH_MEDIA_TYPE},
    body: new TextDecoder().decode(body),
  });
  if (response.status !== 401) throw new Error("identity mismatch was not refused");
  const refusal = decodeMobileError(parseCanonical(new Uint8Array(await response.arrayBuffer())));
  if (refusal.error !== "mobile_server_identity_mismatch") {
    throw new Error("identity mismatch category changed");
  }
}

if ((await client.authorization(second.access_token)).credential_revision !== 2n) {
  throw new Error("rotated access admission mismatch");
}

const admittedClient = ClientId(second.authorization.credential_id);
const scopedSession = {
  authority: "automonique" as const,
  id: ResourceId("session-a"),
  kind: "session" as const,
};
await expectScopedPlatformDenial(second.access_token, "wrong-authority", {
  method: "attach",
  request: {
    client: admittedClient,
    session: {...scopedSession, authority: "provider"},
  },
});
await expectScopedPlatformDenial(second.access_token, "wrong-client", {
  method: "attach",
  request: {client: ClientId("another-client"), session: scopedSession},
});
await expectScopedPlatformDenial(second.access_token, "blind-follow-up", {
  method: "execute",
  request: {
    action: "follow_up",
    client: admittedClient,
    expected_revision: PlatformRevision(11n),
    idempotency_key: IdempotencyKey("mobile-blind-follow-up"),
    parameter: PlatformParameter("continue"),
    target: scopedSession,
  },
});

const commandClient = new MobileSessionClient(
  new HttpsPlatformTransport(
    client.discovery.platform_endpoint,
    () => second.access_token,
    routeFetch as typeof fetch,
    () => "mobile-session-contract",
  ),
  second.authorization,
  client.discovery.server_identity,
);
const commandState = await commandClient.commandState(scopedSession);
if (commandState.session.freshness.revision !== 11n) {
  throw new Error("session command state revision mismatch");
}
const ownedRun = commandState.run;
const ownedApproval = commandState.pending_approvals[0];
if (ownedRun === null || ownedRun.revision !== 12n || ownedRun.target.id !== "run-a") {
  throw new Error("owned run command state mismatch");
}
if (ownedApproval === undefined
  || ownedApproval.revision !== 13n
  || ownedApproval.target.id !== "approval-a") {
  throw new Error("owned approval command state mismatch");
}
const followReceipt = await commandClient.followUp({
  session: scopedSession,
  expectedSessionRevision: commandState.session.freshness.revision,
  idempotencyKey: "mobile-follow-up",
  text: "continue",
});
const stopReceipt = await commandClient.stopRun({
  session: scopedSession,
  expectedSessionRevision: commandState.session.freshness.revision,
  run: ownedRun.target,
  expectedRunRevision: ownedRun.revision,
  idempotencyKey: "mobile-stop-run",
});
const approvalReceipt = await commandClient.decideApproval({
  session: scopedSession,
  expectedSessionRevision: commandState.session.freshness.revision,
  approval: ownedApproval.target,
  expectedApprovalRevision: ownedApproval.revision,
  idempotencyKey: "mobile-decide-approval",
  decision: "grant",
});
if (followReceipt.id !== "receipt-follow"
  || stopReceipt.id !== "receipt-stop"
  || approvalReceipt.id !== "receipt-approval") {
  throw new Error("dedicated command receipt mismatch");
}
const reconciled = await commandClient.reconcileReceipt({
  session: scopedSession,
  idempotencyKey: "mobile-follow-up",
  expectedAction: "follow_up",
  expectedTarget: scopedSession,
});
if (reconciled.id !== followReceipt.id) {
  throw new Error("credential-bound receipt reconciliation mismatch");
}

const disjoint = await client.provision({
  actions: ["follow_up"],
  limits: {
    max_follow_up_bytes: MobileFollowUpBytes(4096n),
    max_page_events: MobilePageEvents(128n),
  },
  session_scope: [MobileSessionId("session-b")],
}, "Basic b3BzOmZpeHR1cmUtcGFzc3dvcmQ=");
await expectScopedPlatformDenial(disjoint.access_token, "disjoint-command-state", {
  method: "session_command_state",
  request: {session: scopedSession},
});
await expectScopedPlatformDenial(second.access_token, "out-of-scope", {
  method: "execute",
  request: {
    action: "follow_up",
    client: null,
    expected_revision: PlatformRevision(1n),
    idempotency_key: IdempotencyKey("mobile-out-of-scope"),
    parameter: PlatformParameter("continue"),
    target: {...scopedSession, id: ResourceId("session-outside")},
  },
});

try {
  await client.refresh(first.refresh_token);
  throw new Error("rotated refresh replay succeeded");
} catch (error) {
  if (!(error instanceof MobileLifecycleError) || error.status !== 401) throw error;
}
await expectMobilePlatformDenial(second.access_token);
try {
  await client.authorization(second.access_token);
  throw new Error("replay-revoked access credential succeeded");
} catch (error) {
  if (!(error instanceof MobileLifecycleError) || error.status !== 401) throw error;
}

const independentlyRevoked = await client.provision({
  actions: ["attach"],
  limits: {
    max_follow_up_bytes: MobileFollowUpBytes(32n),
    max_page_events: MobilePageEvents(16n),
  },
  session_scope: [MobileSessionId("session-a")],
}, "Basic b3BzOmZpeHR1cmUtcGFzc3dvcmQ=");
await client.revoke(independentlyRevoked.refresh_token);
try {
  await client.authorization(independentlyRevoked.access_token);
  throw new Error("explicitly revoked access credential succeeded");
} catch (error) {
  if (!(error instanceof MobileLifecycleError) || error.status !== 401) throw error;
}

if (sawNoStore !== 25) throw new Error(`unexpected lifecycle exchange count: ${sawNoStore}`);
console.log("TypeScript SDK passed the live Rust mobile credential lifecycle contract");
