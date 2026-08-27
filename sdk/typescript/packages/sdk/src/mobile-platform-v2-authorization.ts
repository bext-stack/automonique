// SPDX-License-Identifier: Apache-2.0

import {
  MobileActor,
  MobileCredentialId,
  MobileEpochMillis,
  MobileRevision,
  MobileServerIdentity,
  ProjectId,
  ValidationError,
  bodyString,
  bodyStrings,
  bodyUnsigned,
  exactFields,
  exactInputFields,
  exactString,
  refuse,
  type JsonValue,
} from "../../protocol/src/index.js";

export const MOBILE_PLATFORM_V2_AUTHORIZATION_SCHEMA =
  "automonique.mobile-platform-v2-authorization/v1" as const;
export const MOBILE_PLATFORM_V2_AUTHORIZATION_MEDIA_TYPE =
  "application/vnd.automonique.mobile-platform-v2-authorization.v1+json" as const;
export const MAX_MOBILE_V2_PROJECT_ROOTS = 32;

export const MOBILE_PLATFORM_V2_ACTIONS = [
  "query_work_contexts",
  "get_lineage",
  "prepare_mutation",
  "decide_mutation",
  "submit_mutation",
  "get_mutation_receipt",
  "submit_workspace_intent",
  "get_workspace_intent",
  "get_review",
] as const;

export type MobilePlatformV2Action =
  (typeof MOBILE_PLATFORM_V2_ACTIONS)[number];

export interface MobilePlatformV2GrantRequest {
  readonly actions: readonly MobilePlatformV2Action[];
  readonly credential_id: ReturnType<typeof MobileCredentialId>;
  readonly project_roots: readonly ReturnType<typeof ProjectId>[];
}

export interface MobilePlatformV2Authorization {
  readonly actions: readonly MobilePlatformV2Action[];
  readonly actor_id: ReturnType<typeof MobileActor>;
  readonly authorization_revision: ReturnType<typeof MobileRevision>;
  readonly credential_id: ReturnType<typeof MobileCredentialId>;
  readonly credential_revision: ReturnType<typeof MobileRevision>;
  readonly delegation_id: string;
  readonly expires_at_ms: ReturnType<typeof MobileEpochMillis>;
  readonly issued_at_ms: ReturnType<typeof MobileEpochMillis>;
  readonly principal_generation: ReturnType<typeof MobileRevision>;
  readonly project_roots: readonly ReturnType<typeof ProjectId>[];
  readonly schema: typeof MOBILE_PLATFORM_V2_AUTHORIZATION_SCHEMA;
  readonly server_identity: ReturnType<typeof MobileServerIdentity>;
  readonly tenant_id: ReturnType<typeof MobileActor>;
}

const AUTHORIZATION_FIELDS = [
  "actions",
  "actor_id",
  "authorization_revision",
  "credential_id",
  "credential_revision",
  "delegation_id",
  "expires_at_ms",
  "issued_at_ms",
  "principal_generation",
  "project_roots",
  "schema",
  "server_identity",
  "tenant_id",
] as const;

const GRANT_FIELDS = ["actions", "credential_id", "project_roots"] as const;

function action(value: string): MobilePlatformV2Action {
  if (!MOBILE_PLATFORM_V2_ACTIONS.includes(value as MobilePlatformV2Action)) {
    throw new ValidationError("MobilePlatformV2Action", "invalid_character");
  }
  return value as MobilePlatformV2Action;
}

function delegationId(value: string): string {
  if (!/^md_[A-Za-z0-9_-]{43}$/u.test(value)) {
    throw new ValidationError(
      "MobilePlatformV2DelegationId",
      "invalid_character",
    );
  }
  return value;
}

function strictlyIncreasing<T>(
  values: readonly T[],
  compare: (left: T, right: T) => number,
): boolean {
  return values.every(
    (value, index) => index === 0 || compare(values[index - 1]!, value) < 0,
  );
}

export function encodeMobilePlatformV2GrantRequest(
  value: MobilePlatformV2GrantRequest,
): JsonValue {
  exactInputFields(value, GRANT_FIELDS, "mobile_v2_authorization_invalid");
  if (
    value.actions.length === 0 ||
    value.actions.length > MOBILE_PLATFORM_V2_ACTIONS.length ||
    value.project_roots.length === 0 ||
    value.project_roots.length > MAX_MOBILE_V2_PROJECT_ROOTS
  ) {
    throw new ValidationError("MobilePlatformV2GrantRequest", "invalid_length");
  }
  const actions = [...new Set(value.actions.map((item) => action(item)))].sort(
    (left, right) =>
      MOBILE_PLATFORM_V2_ACTIONS.indexOf(left) -
      MOBILE_PLATFORM_V2_ACTIONS.indexOf(right),
  );
  const roots = [
    ...new Set(value.project_roots.map((item) => ProjectId(item))),
  ].sort();
  return {
    kind: "object",
    entries: [
      [
        "actions",
        {
          kind: "array",
          items: actions.map((item) => ({ kind: "string", value: item })),
        },
      ],
      [
        "credential_id",
        { kind: "string", value: MobileCredentialId(value.credential_id) },
      ],
      [
        "project_roots",
        {
          kind: "array",
          items: roots.map((item) => ({ kind: "string", value: item })),
        },
      ],
    ],
  };
}

export function decodeMobilePlatformV2Authorization(
  body: JsonValue,
): MobilePlatformV2Authorization {
  const fields = exactFields(
    body,
    AUTHORIZATION_FIELDS,
    "mobile_v2_authorization_invalid",
  );
  const actions = bodyStrings(
    fields,
    "actions",
    "mobile_v2_authorization_invalid",
    MOBILE_PLATFORM_V2_ACTIONS.length,
    "mobile_v2_authorization_invalid",
  ).map((item) =>
    refuse("mobile_v2_authorization_invalid", () => action(item)),
  );
  const projectRoots = bodyStrings(
    fields,
    "project_roots",
    "mobile_v2_authorization_invalid",
    MAX_MOBILE_V2_PROJECT_ROOTS,
    "mobile_v2_authorization_invalid",
  ).map((item) =>
    refuse("mobile_v2_authorization_invalid", () => ProjectId(item)),
  );
  if (
    actions.length === 0 ||
    projectRoots.length === 0 ||
    !strictlyIncreasing(
      actions,
      (left, right) =>
        MOBILE_PLATFORM_V2_ACTIONS.indexOf(left) -
        MOBILE_PLATFORM_V2_ACTIONS.indexOf(right),
    ) ||
    !strictlyIncreasing(projectRoots, (left, right) =>
      left < right ? -1 : left > right ? 1 : 0,
    )
  ) {
    throw new ValidationError("MobilePlatformV2Authorization", "invalid_order");
  }
  return {
    actions,
    actor_id: refuse("mobile_v2_authorization_invalid", () =>
      MobileActor(
        bodyString(fields, "actor_id", "mobile_v2_authorization_invalid"),
      ),
    ),
    authorization_revision: refuse("mobile_v2_authorization_invalid", () =>
      MobileRevision(
        bodyUnsigned(
          fields,
          "authorization_revision",
          "mobile_v2_authorization_invalid",
        ),
      ),
    ),
    credential_id: refuse("mobile_v2_authorization_invalid", () =>
      MobileCredentialId(
        bodyString(fields, "credential_id", "mobile_v2_authorization_invalid"),
      ),
    ),
    credential_revision: refuse("mobile_v2_authorization_invalid", () =>
      MobileRevision(
        bodyUnsigned(
          fields,
          "credential_revision",
          "mobile_v2_authorization_invalid",
        ),
      ),
    ),
    delegation_id: refuse("mobile_v2_authorization_invalid", () =>
      delegationId(
        bodyString(fields, "delegation_id", "mobile_v2_authorization_invalid"),
      ),
    ),
    expires_at_ms: refuse("mobile_v2_authorization_invalid", () =>
      MobileEpochMillis(
        bodyUnsigned(
          fields,
          "expires_at_ms",
          "mobile_v2_authorization_invalid",
        ),
      ),
    ),
    issued_at_ms: refuse("mobile_v2_authorization_invalid", () =>
      MobileEpochMillis(
        bodyUnsigned(fields, "issued_at_ms", "mobile_v2_authorization_invalid"),
      ),
    ),
    principal_generation: refuse("mobile_v2_authorization_invalid", () =>
      MobileRevision(
        bodyUnsigned(
          fields,
          "principal_generation",
          "mobile_v2_authorization_invalid",
        ),
      ),
    ),
    project_roots: projectRoots,
    schema: exactString(
      bodyString(fields, "schema", "mobile_v2_authorization_invalid"),
      MOBILE_PLATFORM_V2_AUTHORIZATION_SCHEMA,
      "mobile_v2_authorization_invalid",
      "schema",
    ),
    server_identity: refuse("mobile_v2_authorization_invalid", () =>
      MobileServerIdentity(
        bodyString(
          fields,
          "server_identity",
          "mobile_v2_authorization_invalid",
        ),
      ),
    ),
    tenant_id: refuse("mobile_v2_authorization_invalid", () =>
      MobileActor(
        bodyString(fields, "tenant_id", "mobile_v2_authorization_invalid"),
      ),
    ),
  };
}
