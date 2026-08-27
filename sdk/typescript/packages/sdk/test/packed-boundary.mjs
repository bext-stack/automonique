// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import {access} from "node:fs/promises";
import {join} from "node:path";
import {pathToFileURL} from "node:url";

const packageRoot = process.argv[2];
assert.equal(typeof packageRoot, "string", "usage: packed-boundary.mjs <extracted-package-root>");

const sdkRoot = join(packageRoot, "dist", "sdk", "src");
const main = await import(pathToFileURL(join(sdkRoot, "index.js")).href);
const testing = await import(pathToFileURL(join(sdkRoot, "testing.js")).href);
const testingInternal = await import(pathToFileURL(join(sdkRoot, "testing", "internal.js")).href);
const v2 = await import(pathToFileURL(join(sdkRoot, "platform-v2-client.js")).href);

assert.equal(typeof main.PlatformV2Client, "function");
assert.equal(typeof main.HttpsPlatformV2Transport, "function");
assert.equal(typeof testing.DeterministicPlatformV2Adapter, "function");
assert.deepEqual(Object.keys(v2).sort(), [
  "BasicHttpsPlatformV2Transport",
  "HttpsPlatformV2Transport",
  "PLATFORM_NEGOTIATION_MEDIA_TYPE",
  "PLATFORM_V2_MEDIA_TYPE",
  "PlatformV2BasicCredential",
  "PlatformV2Client",
]);
assert.equal("PlatformV2CanonicalTestingTransport" in main, false);
assert.equal("PlatformV2CanonicalTestingTransport" in v2, false);
assert.equal(typeof testingInternal.PlatformV2CanonicalTestingTransport, "function");
const testingAdapter = new testing.DeterministicPlatformV2Adapter([]);
assert.equal("request" in testingAdapter, false);
assert.equal("requestCanonical" in testingAdapter, false);
assert.equal("negotiateCanonical" in testingAdapter, false);
assert.deepEqual(Reflect.ownKeys(Object.getPrototypeOf(Object.getPrototypeOf(testingAdapter))), ["constructor"]);

await assert.rejects(
  access(join(sdkRoot, "platform-v2-internal.js")),
  (error) => error?.code === "ENOENT",
);

let credentialCalls = 0;
let fetchCalls = 0;
let injectedCalls = 0;
const fetcher = async (input, init) => {
  fetchCalls += 1;
  assert.equal(String(input), "https://manage.example/api/platform/v2");
  assert.equal(new Headers(init.headers).get("authorization"), "Bearer packed-secret");
  const message = main.decodeMessage(new TextEncoder().encode(init.body));
  assert.deepEqual(
    {
      kind: message.envelope.kind,
      protocol: message.envelope.protocol,
      version: message.envelope.version,
    },
    {kind: "negotiate", protocol: "automonique.platform.negotiation", version: 1},
  );
  return new Response("{}", {
    headers: {
      "cache-control": "no-store",
      "content-type": main.PLATFORM_NEGOTIATION_MEDIA_TYPE,
    },
  });
};
const transport = new main.HttpsPlatformV2Transport(
  "https://manage.example/api/platform/v2",
  () => {
    credentialCalls += 1;
    return "packed-secret";
  },
  fetcher,
);
assert.deepEqual(Reflect.ownKeys(transport), []);
assert.deepEqual(Reflect.ownKeys(Object.getPrototypeOf(transport)), ["constructor"]);

const injectedSymbol = Symbol("arbitrary-byte-exchange");
Object.assign(transport, {
  exchange: async () => {
    injectedCalls += 1;
  },
  request: async () => {
    injectedCalls += 1;
  },
});
Object.defineProperty(transport, injectedSymbol, {
  value: async () => {
    injectedCalls += 1;
  },
});

const client = new main.PlatformV2Client(transport);
await assert.rejects(client.negotiate({
  schema: main.PLATFORM_NEGOTIATION_SCHEMA_V1,
  versions: [main.PlatformVersionNumber(2n)],
}));
assert.equal(credentialCalls, 1);
assert.equal(fetchCalls, 1);
assert.equal(injectedCalls, 0);

let basicAuthorization = "";
const basic = new main.PlatformV2BasicCredential("ops", "packed-password");
assert.deepEqual(Reflect.ownKeys(basic), []);
assert.deepEqual(Reflect.ownKeys(Object.getPrototypeOf(basic)), ["constructor"]);
const basicTransport = new main.BasicHttpsPlatformV2Transport(
  "https://manage.example/api/platform/v2",
  () => basic,
  async (_input, init) => {
    basicAuthorization = new Headers(init.headers).get("authorization");
    return new Response("{}", {
      headers: {
        "cache-control": "no-store",
        "content-type": main.PLATFORM_NEGOTIATION_MEDIA_TYPE,
      },
    });
  },
);
assert.deepEqual(Reflect.ownKeys(basicTransport), []);
await assert.rejects(new main.PlatformV2Client(basicTransport).negotiate({
  schema: main.PLATFORM_NEGOTIATION_SCHEMA_V1,
  versions: [main.PlatformVersionNumber(2n)],
}));
assert.equal(basicAuthorization, "Basic b3BzOnBhY2tlZC1wYXNzd29yZA==");
