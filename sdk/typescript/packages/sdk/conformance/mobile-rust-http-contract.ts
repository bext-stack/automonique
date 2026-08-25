// SPDX-License-Identifier: Apache-2.0

import {
  MOBILE_AUTH_MEDIA_TYPE,
  ClientId,
  IdempotencyKey,
  MobileFollowUpBytes,
  MobileLifecycleClient,
  MobileLifecycleError,
  MobilePageEvents,
  PlatformRequestId,
  MobileServerIdentity,
  MobileSessionId,
  PlatformParameter,
  decodeMobileError,
  encodeMobileRefreshRequest,
  encodePlatformRequestMessage,
  parseCanonical,
  PlatformRevision,
  ResourceId,
  toCanonicalBytes,
} from "../dist/sdk/src/index.js";

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

const client = await MobileLifecycleClient.discover(canonicalOrigin, routedFetch);
if (client.discovery.server_identity.length !== 71) throw new Error("server identity shape mismatch");

const dashboard = await routeFetch(`${canonicalOrigin}/`, {
  method: "GET",
  headers: {authorization: "Basic b3BzOmZpeHR1cmUtcGFzc3dvcmQ="},
});
const dashboardSession = dashboard.headers.get("set-cookie")?.split(";", 1)[0];
if (dashboard.status !== 200 || dashboardSession === undefined) {
  throw new Error("failed to establish dashboard session fixture");
}
const sessionCookie = dashboardSession;

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

const first = await client.provision({
  actions: ["attach", "follow_up"],
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
    expected_revision: null,
    idempotency_key: IdempotencyKey("mobile-blind-follow-up"),
    parameter: PlatformParameter("continue"),
    target: scopedSession,
  },
});
await expectScopedPlatformDenial(second.access_token, "out-of-scope", {
  method: "execute",
  request: {
    action: "follow_up",
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

if (sawNoStore !== 13) throw new Error(`unexpected lifecycle exchange count: ${sawNoStore}`);
console.log("TypeScript SDK passed the live Rust mobile credential lifecycle contract");
