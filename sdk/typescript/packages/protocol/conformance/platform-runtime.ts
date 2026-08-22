// SPDX-License-Identifier: Apache-2.0

import {
  ResourceId,
  decodePlatformAction,
  decodeResourceAuthority,
  decodeResourceKind,
  toCanonicalBytes,
  type JsonValue,
  type ResourceCoordinate,
} from "../generated/index.ts";

const coordinate: ResourceCoordinate = {
  authority: decodeResourceAuthority("automonique"),
  id: ResourceId("run-1"),
  kind: decodeResourceKind("run"),
};

const coordinateWire: JsonValue = {
  kind: "object",
  entries: [
    ["authority", {kind: "string", value: coordinate.authority}],
    ["id", {kind: "string", value: coordinate.id}],
    ["kind", {kind: "string", value: coordinate.kind}],
  ],
};

console.log(new TextDecoder().decode(toCanonicalBytes(coordinateWire)));

for (const rejected of [
  () => decodeResourceAuthority("dashboard"),
  () => decodePlatformAction("provider_direct_mutation"),
  () => ResourceId("x".repeat(257)),
]) {
  try {
    rejected();
    throw new Error("invalid platform value was accepted");
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    console.log(error.name);
  }
}
