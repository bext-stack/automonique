// SPDX-License-Identifier: Apache-2.0

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
