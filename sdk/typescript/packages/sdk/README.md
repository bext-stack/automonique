# `@automonique/sdk`

The canonical TypeScript client for Automonique Platform v1. It is an ESM package for browsers, React Native, and server-side JavaScript, with no Node- or Bun-specific runtime imports.

```sh
npm install @automonique/sdk
```

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

This package is licensed under Apache-2.0. Automonique product code outside `sdk/` has a separate licensing boundary.
