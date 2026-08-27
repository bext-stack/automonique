-- SPDX-License-Identifier: Elastic-2.0

CREATE TABLE lineage_external_work (
    tenant TEXT NOT NULL,
    provider TEXT NOT NULL CHECK (provider IN ('github','gitlab','linear','jira_compatible')),
    authority_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    work_key TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    external_state TEXT NOT NULL CHECK (external_state IN ('open','moved','closed')),
    moved_provider TEXT,
    moved_authority_id TEXT,
    moved_scope TEXT,
    moved_key TEXT,
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 1),
    stale_after_ms INTEGER NOT NULL CHECK (stale_after_ms >= 1),
    freshness_state TEXT NOT NULL CHECK (freshness_state IN ('fresh','stale')),
    latest_message TEXT,
    latest_observed_at_ms INTEGER CHECK (latest_observed_at_ms >= 1),
    origin_attempt_id TEXT,
    origin_session_id TEXT,
    origin_pane_id TEXT,
    PRIMARY KEY (tenant, provider, authority_id, scope, work_key),
    UNIQUE (tenant, provider, authority_id, scope, work_key, workspace_id),
    CHECK ((external_state = 'moved') = (moved_provider IS NOT NULL)),
    CHECK ((moved_provider IS NULL) = (moved_scope IS NULL)),
    CHECK ((moved_provider IS NULL) = (moved_authority_id IS NULL)),
    CHECK ((moved_provider IS NULL) = (moved_key IS NULL)),
    CHECK ((latest_message IS NULL) = (latest_observed_at_ms IS NULL)),
    CHECK (origin_session_id IS NULL OR origin_attempt_id IS NOT NULL),
    CHECK (origin_pane_id IS NULL OR origin_session_id IS NOT NULL)
) STRICT;

CREATE INDEX lineage_external_by_workspace
    ON lineage_external_work(tenant, workspace_id, provider, authority_id, scope, work_key);

CREATE TABLE lineage_orchestration (
    tenant TEXT NOT NULL,
    orchestration_kind TEXT NOT NULL CHECK (orchestration_kind IN
        ('run','task','dispatch','worker','heartbeat','question','decision_gate')),
    orchestration_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    external_provider TEXT,
    external_authority_id TEXT,
    external_scope TEXT,
    external_key TEXT,
    parent_kind TEXT,
    parent_id TEXT,
    status_kind TEXT NOT NULL CHECK (status_kind IN ('working','blocked','waiting','done')),
    status_message TEXT,
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 1),
    stale_after_ms INTEGER NOT NULL CHECK (stale_after_ms >= 1),
    freshness_state TEXT NOT NULL CHECK (freshness_state IN ('fresh','stale')),
    latest_message TEXT,
    latest_observed_at_ms INTEGER CHECK (latest_observed_at_ms >= 1),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    origin_attempt_id TEXT,
    origin_session_id TEXT,
    origin_pane_id TEXT,
    PRIMARY KEY (tenant, orchestration_kind, orchestration_id),
    UNIQUE (tenant, orchestration_kind, orchestration_id, workspace_id),
    FOREIGN KEY (tenant, external_provider, external_authority_id, external_scope, external_key, workspace_id)
        REFERENCES lineage_external_work(tenant, provider, authority_id, scope, work_key, workspace_id),
    FOREIGN KEY (tenant, parent_kind, parent_id, workspace_id)
        REFERENCES lineage_orchestration(tenant, orchestration_kind, orchestration_id, workspace_id),
    CHECK ((external_provider IS NULL) = (external_scope IS NULL)),
    CHECK ((external_provider IS NULL) = (external_authority_id IS NULL)),
    CHECK ((external_provider IS NULL) = (external_key IS NULL)),
    CHECK ((parent_kind IS NULL) = (parent_id IS NULL)),
    CHECK (parent_kind IS NULL OR orchestration_kind != parent_kind OR orchestration_id != parent_id),
    CHECK ((status_kind = 'working') = (status_message IS NULL)),
    CHECK ((latest_message IS NULL) = (latest_observed_at_ms IS NULL)),
    CHECK (origin_session_id IS NULL OR origin_attempt_id IS NOT NULL),
    CHECK (origin_pane_id IS NULL OR origin_session_id IS NOT NULL),
    CHECK (
        (orchestration_kind = 'run' AND parent_kind IS NULL) OR
        (orchestration_kind = 'task' AND parent_kind IN ('run','task')) OR
        (orchestration_kind = 'dispatch' AND parent_kind = 'task') OR
        (orchestration_kind = 'worker' AND parent_kind = 'dispatch') OR
        (orchestration_kind = 'heartbeat' AND parent_kind = 'worker') OR
        (orchestration_kind = 'question' AND parent_kind = 'task') OR
        (orchestration_kind = 'decision_gate' AND parent_kind IN ('question','task'))
    )
) STRICT;

CREATE INDEX lineage_orchestration_by_workspace
    ON lineage_orchestration(tenant, workspace_id, orchestration_kind, orchestration_id);

CREATE TABLE lineage_workspace_intents (
    tenant TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    intent_kind TEXT NOT NULL CHECK (intent_kind IN ('create','resume')),
    task_kind TEXT NOT NULL CHECK (task_kind = 'task'),
    task_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    external_provider TEXT,
    external_authority_id TEXT,
    external_scope TEXT,
    external_key TEXT,
    base_selector TEXT,
    branch_selector TEXT,
    expected_revision INTEGER CHECK (expected_revision >= 1),
    outcome_kind TEXT NOT NULL CHECK (outcome_kind IN ('accepted','unknown','created','resumed','conflict')),
    outcome_conflict TEXT CHECK (outcome_conflict IN
        ('duplicate_intake','task_already_bound','workspace_not_found','revision_mismatch',
         'external_work_moved','external_work_closed','orphan_dispatch','stale_heartbeat',
         'question_pending','creation_cancelled')),
    outcome_workspace_id TEXT,
    reconciliation TEXT NOT NULL CHECK (reconciliation IN ('final','poll_receipt')),
    PRIMARY KEY (tenant, intent_id),
    FOREIGN KEY (tenant, task_kind, task_id, workspace_id)
        REFERENCES lineage_orchestration(tenant, orchestration_kind, orchestration_id, workspace_id),
    FOREIGN KEY (tenant, external_provider, external_authority_id, external_scope, external_key, workspace_id)
        REFERENCES lineage_external_work(tenant, provider, authority_id, scope, work_key, workspace_id),
    CHECK (
        (intent_kind = 'create' AND external_provider IS NOT NULL AND external_authority_id IS NOT NULL AND external_scope IS NOT NULL
            AND external_key IS NOT NULL AND base_selector IS NOT NULL
            AND branch_selector IS NOT NULL AND expected_revision IS NULL) OR
        (intent_kind = 'resume' AND external_provider IS NULL AND external_authority_id IS NULL AND external_scope IS NULL
            AND external_key IS NULL AND base_selector IS NULL
            AND branch_selector IS NULL AND expected_revision IS NOT NULL)
    ),
    CHECK (
        (outcome_kind IN ('accepted','unknown') AND outcome_conflict IS NULL
            AND outcome_workspace_id IS NULL AND reconciliation = 'poll_receipt') OR
        (outcome_kind = 'conflict' AND outcome_conflict IS NOT NULL
            AND outcome_workspace_id IS NULL AND reconciliation = 'final') OR
        (outcome_kind IN ('created','resumed') AND outcome_conflict IS NULL
            AND outcome_workspace_id = workspace_id AND reconciliation = 'final')
    ),
    CHECK (
        (intent_kind = 'create' AND outcome_kind IN ('accepted','unknown','created','conflict')) OR
        (intent_kind = 'resume' AND outcome_kind IN ('accepted','unknown','resumed','conflict'))
    )
) STRICT;
