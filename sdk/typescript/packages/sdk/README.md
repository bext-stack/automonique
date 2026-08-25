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

This package is licensed under Apache-2.0. Automonique product code outside `sdk/` has a separate licensing boundary.
