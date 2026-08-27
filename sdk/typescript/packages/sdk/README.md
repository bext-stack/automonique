# `@automonique/sdk`

The canonical TypeScript client for Automonique Platform v1 and the separately
negotiated Platform v2 work-context surface. It is an ESM package for browsers,
React Native, and server-side JavaScript, with no Node- or Bun-specific runtime
imports.

## Installation

`@automonique/sdk` is not currently published to the public npm registry. A
bare `npm install @automonique/sdk` will fail until an authorized release is
published.

Until then, use the repository's verified packed-archive workflow from a
checkout pinned to the required Automonique revision. The same archive path is
exercised by CI:

```sh
cd sdk/typescript/packages/sdk
bun install --frozen-lockfile
npm run typecheck
npm test
sdk_archive_dir="$(mktemp -d)"
npm pack --pack-destination "$sdk_archive_dir"

cd /path/to/consumer
npm install "$sdk_archive_dir/automonique-sdk-0.1.0.tgz"
```

Record the source revision and packed archive checksum in the consuming
project. The archive is a source-built development artifact, not an official
registry release.

```ts
import {HttpsPlatformTransport, PlatformClient} from "@automonique/sdk";

const client = new PlatformClient(new HttpsPlatformTransport(
  "https://automonique.example/api/platform",
  () => accessToken,
));

const result = await client.capabilities();
```

Remote endpoints must use HTTPS. The transport sends and accepts the exact `application/vnd.automonique.platform.v1+json` media type, validates request/response correlation, preserves protocol refusals, and bounds streamed canonical responses before decoding. Platforms must expose a standards-compatible streaming `fetch`; a custom implementation can be passed as the transport's third constructor argument.

React Native's legacy global `fetch` does not expose a response stream. Expo applications should inject `fetch` from `expo/fetch`, which provides the `ReadableStream` needed to enforce the response limit before allocation:

```ts
import {fetch as expoFetch} from "expo/fetch";

const transport = new HttpsPlatformTransport(endpoint, token, expoFetch as typeof fetch);
```

Protocol integer fields use JavaScript `bigint` so revisions and cursor sequences remain lossless above `Number.MAX_SAFE_INTEGER`. Resource summaries are deliberately opaque strings in Platform v1; consumers must not infer structured state from them.

Platform v2 must be negotiated before any structured operation. A downgrade or
refusal remains explicit and does not enable the v2 methods:

```ts
import {
  HttpsPlatformV2Transport,
  PLATFORM_NEGOTIATION_SCHEMA_V1,
  PlatformV2Client,
  PlatformVersionNumber,
} from "@automonique/sdk";

const work = new PlatformV2Client(new HttpsPlatformV2Transport(
  "https://automonique.example/api/platform/v2",
  () => accessToken,
));
const result = await work.negotiate({
  schema: PLATFORM_NEGOTIATION_SCHEMA_V1,
  versions: [PlatformVersionNumber(1n), PlatformVersionNumber(2n)],
});
if (work.negotiated !== null) {
  const page = await work.queryWorkContexts(query);
}
```

The dedicated single-principal web bridge is Basic-only. Use its explicit,
opaque credential and transport types; the default v2 transport remains
Bearer-based for mobile and Manage endpoints:

```ts
import {
  BasicHttpsPlatformV2Transport,
  PlatformV2BasicCredential,
  PlatformV2Client,
} from "@automonique/sdk";

const credential = new PlatformV2BasicCredential(username, password);
const work = new PlatformV2Client(new BasicHttpsPlatformV2Transport(
  "https://automonique.example/api/platform/v2",
  () => credential,
));
```

Credential objects expose no username, password, encoded value, or header
accessor. Do not use this mode to translate a mobile or Manage bearer token.

The v2 facade exposes only typed work-context, lifecycle, lineage, and review
operations. Actor, tenant, and authority grants are resolved by the authenticated
server and cannot be asserted through these client methods. Both v2 HTTP lanes
use exact media types, independent response limits, strict correlation, a pinned
endpoint URL, omitted ambient credentials, and `redirect: "error"`.

Mobile applications should use the dedicated session facade instead of the
generic `PlatformClient` mutation method:

```ts
import {HttpsPlatformTransport, MobileSessionClient} from "@automonique/sdk";

const mobile = new MobileSessionClient(
  new HttpsPlatformTransport(discovery.platform_endpoint, () => accessToken),
  authorization,
  discovery.server_identity,
);
const state = await mobile.commandState(session);
await mobile.followUp({
  session,
  expectedSessionRevision: state.session.freshness.revision,
  idempotencyKey: "reply-018",
  text: "Continue with the reviewed approach.",
});
```

`MobileSessionClient` derives the Platform client identity from the admitted
credential, checks identity, expiry, action, session scope, UTF-8 limits, and
receipt bindings locally, and exposes no generic `execute` method. Its
optional fourth constructor argument is an injectable millisecond clock for
deterministic runtime integration and testing.

## Deterministic fixtures

The optional `@automonique/sdk/testing` subpath provides runtime-neutral test
fixtures without importing Bun, Node, or a test runner:

```ts
import {MobileSessionClient} from "@automonique/sdk";
import {
  DeterministicPlatformAdapter,
  createDeterministicSdkFixture,
} from "@automonique/sdk/testing";

const fixture = createDeterministicSdkFixture();
const adapter = new DeterministicPlatformAdapter(
  fixture.mutation.ambiguousThenReconciled,
);
const client = new MobileSessionClient(
  adapter,
  fixture.authorization,
  fixture.serverIdentity,
  () => fixture.now,
);
```

The fixed matrix covers exact and conflicting duplicates, cursor gaps and
expiry, stale revisions, sanitized unknown history events, unknown mutation
outcomes, and idempotency-key receipt reconciliation. The scripted adapter
records exact requests and fails closed on an unexpected order or exhausted
script.

`DeterministicPlatformV2Adapter` provides the equivalent exact-order fixture
surface for negotiation and structured v2 requests.

This package is licensed under Apache-2.0. Automonique product code outside `sdk/` has a separate licensing boundary.
