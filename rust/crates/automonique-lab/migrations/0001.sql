-- SPDX-License-Identifier: Elastic-2.0

CREATE TABLE automonique_lab_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    last_lease_epoch INTEGER NOT NULL CHECK (last_lease_epoch >= 0)
) STRICT;

INSERT INTO automonique_lab_meta(singleton, schema_version, last_lease_epoch)
VALUES (1, 1, 0);

CREATE TABLE attempts (
    attempt_id TEXT PRIMARY KEY,
    objective_id TEXT NOT NULL,
    base_revision TEXT NOT NULL CHECK (
        length(base_revision) = 40
        AND base_revision = lower(base_revision)
        AND base_revision NOT GLOB '*[^0-9a-f]*'
    ),
    state TEXT NOT NULL CHECK (
        state IN ('queued', 'running', 'paused', 'succeeded', 'failed', 'blocked', 'cancelled')
    ),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    last_sequence INTEGER NOT NULL CHECK (last_sequence >= 0)
) STRICT;

CREATE TABLE journal_records (
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id) ON DELETE RESTRICT,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    record_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('event', 'checkpoint', 'evidence')),
    attempt_revision INTEGER NOT NULL CHECK (attempt_revision > 0),
    authority TEXT NOT NULL CHECK (
        authority IN ('harness', 'worker', 'reviewer', 'owner')
    ),
    payload_digest TEXT NOT NULL CHECK (
        length(payload_digest) = 64
        AND payload_digest = lower(payload_digest)
        AND payload_digest NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY (attempt_id, sequence),
    UNIQUE (attempt_id, record_id)
) STRICT;

CREATE TABLE effects (
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id) ON DELETE RESTRICT,
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL CHECK (
        length(request_digest) = 64
        AND request_digest = lower(request_digest)
        AND request_digest NOT GLOB '*[^0-9a-f]*'
    ),
    status TEXT NOT NULL CHECK (status IN ('pending', 'applied', 'failed', 'unknown')),
    result_digest TEXT CHECK (
        result_digest IS NULL OR (
            length(result_digest) = 64
            AND result_digest = lower(result_digest)
            AND result_digest NOT GLOB '*[^0-9a-f]*'
        )
    ),
    intent_authority TEXT NOT NULL CHECK (
        intent_authority IN ('harness', 'worker', 'reviewer', 'owner')
    ),
    result_authority TEXT CHECK (
        result_authority IS NULL OR result_authority IN ('harness', 'worker', 'reviewer', 'owner')
    ),
    intent_revision INTEGER NOT NULL CHECK (intent_revision > 0),
    result_revision INTEGER CHECK (result_revision IS NULL OR result_revision > intent_revision),
    PRIMARY KEY (attempt_id, idempotency_key),
    CHECK (
        (status = 'pending' AND result_digest IS NULL AND result_revision IS NULL AND result_authority IS NULL)
        OR (status != 'pending' AND result_digest IS NOT NULL AND result_revision IS NOT NULL AND result_authority IS NOT NULL)
    )
) STRICT;

CREATE TABLE path_leases (
    lease_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id) ON DELETE RESTRICT,
    path TEXT NOT NULL,
    epoch INTEGER NOT NULL CHECK (epoch > 0),
    acquired_revision INTEGER NOT NULL CHECK (acquired_revision > 0),
    PRIMARY KEY (lease_id, path),
    UNIQUE (path)
) STRICT;

CREATE INDEX path_leases_attempt ON path_leases(attempt_id);

CREATE TABLE state_actions (
    action_id TEXT PRIMARY KEY,
    operation TEXT NOT NULL CHECK (operation IN ('transition', 'acquire_lease', 'release_lease')),
    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id) ON DELETE RESTRICT,
    base_revision TEXT NOT NULL,
    expected_revision INTEGER NOT NULL CHECK (expected_revision >= 0),
    target_state TEXT,
    record_digest TEXT,
    authority TEXT,
    lease_id TEXT,
    lease_epoch INTEGER,
    result_revision INTEGER NOT NULL CHECK (result_revision > 0),
    result_sequence INTEGER,
    released_lease_count INTEGER NOT NULL CHECK (released_lease_count >= 0)
) STRICT;

CREATE TABLE state_action_paths (
    action_id TEXT NOT NULL REFERENCES state_actions(action_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    path TEXT NOT NULL,
    PRIMARY KEY (action_id, ordinal),
    UNIQUE (action_id, path)
) STRICT;
