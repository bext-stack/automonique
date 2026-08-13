// SPDX-License-Identifier: Apache-2.0

// The generated read surface. Its module list is generator-owned, so this is a
// wildcard rather than a hand-kept list that would go stale the first time a
// schema is added. See `generated/index.ts`.
export * from "../generated/index.ts";

export {
  MAX_JSON_ENTRIES,
  MAX_JSON_STRING_BYTES,
  MAX_MESSAGE_KIND_BYTES,
  MAX_NESTING_DEPTH,
  MAX_PROTOCOL_NAME_BYTES,
  MAX_REQUEST_ID_BYTES,
  WireError,
  decodeMessage,
  encodeMessage,
  parseCanonical,
  toCanonicalBytes,
  type Envelope,
  type JsonValue,
  type Message,
  type WireCategory,
} from "./canonical.ts";
