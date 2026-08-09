#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Closed synthetic controller for the proposal-only lab scenario protocol."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
from typing import Any

from tools.build_broker import BuildBroker, BuildError, BuildLimits, BuildRequest, Recipe
from tools.lab_state import (
    Attempt,
    AttemptState,
    ConflictError,
    EvidenceAuthority,
    LabStateError,
    LabStateStore,
    NotFoundError,
    RecordKind,
)
from tools.worktree_allocator import AllocationError, AllocationRequest, WorktreeAllocator


LAB_PROTOCOL = "automonique.lab-scenario/v1"
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SHA1 = re.compile(r"^[0-9a-f]{40}$")

SYNTHETIC_POLICY: dict[str, Any] = {
    "kind": "synthetic",
    "driver": "in_process_fixture",
    "network": "deny",
    "authentication": "none",
    "maxModelCalls": 0,
    "maxCostMicrounits": 0,
}
SYNTHETIC_BUDGET: dict[str, Any] = {
    "maxWallMs": 3_000,
    "maxCpuMs": 1_000,
    "maxDiskBytes": 64 * 1024 * 1024,
    "maxOutputBytes": 4_096,
    "maxPids": 1,
    "maxModelCalls": 0,
    "maxCostMicrounits": 0,
    "enforcement": "synthetic_in_process",
}
_BUILD_REQUEST = BuildRequest(
    recipe=Recipe.SUCCESS,
    limits=BuildLimits(
        wall_seconds=3,
        cpu_seconds=1,
        output_bytes=4_096,
        process_count=1,
        writable_bytes=64 * 1024 * 1024,
    ),
)
_SELECT_KEYS = frozenset(
    {
        "protocol",
        "requestId",
        "op",
        "objectiveId",
        "expectedBase",
        "execution",
        "providerPolicy",
        "budget",
    }
)
_OBSERVE_KEYS = frozenset(
    {
        "protocol",
        "requestId",
        "op",
        "objectiveId",
        "unitId",
        "afterSequence",
        "limit",
    }
)
_RESUME_KEYS = frozenset(
    {
        "protocol",
        "requestId",
        "op",
        "objectiveId",
        "unitId",
        "checkpointId",
        "expectedRevision",
        "idempotencyKey",
    }
)
_CANCEL_KEYS = frozenset(
    {
        "protocol",
        "requestId",
        "op",
        "objectiveId",
        "unitId",
        "expectedRevision",
        "idempotencyKey",
        "reason",
    }
)
_CANCEL_REASONS = frozenset(
    {"operator_request", "budget_exhausted", "policy_denied"}
)


class _Denied(Exception):
    def __init__(self, code: str, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise _Denied("invalid_request", f"{label} must be a bounded identifier")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise _Denied("invalid_request", f"{label} must be a bounded integer")
    return value


class LabController:
    """Bind closed scenario requests to durable state and fixed local brokers."""

    def __init__(
        self,
        repository: pathlib.Path,
        state_root: pathlib.Path,
        work_id: str,
        allowed_paths: tuple[str, ...] | list[str],
    ) -> None:
        self.repository = pathlib.Path(repository)
        self.state_root = pathlib.Path(state_root)
        if not IDENTIFIER.fullmatch(work_id):
            raise ValueError("work ID must be a bounded identifier")
        if not isinstance(allowed_paths, (tuple, list)) or not allowed_paths:
            raise ValueError("at least one allowed path is required")
        self.work_id = work_id
        self.allowed_paths = tuple(allowed_paths)
        self._store = LabStateStore(
            self.state_root / "state" / "lab.sqlite3", self.repository
        )
        self._allocator = WorktreeAllocator(
            self.repository, self.state_root / "allocations"
        )

    def close(self) -> None:
        self._store.close()

    def __enter__(self) -> LabController:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        request_id = self._safe_request_id(request)
        try:
            if not isinstance(request, dict):
                raise _Denied("invalid_request", "request must be an object")
            if request.get("protocol") != LAB_PROTOCOL:
                raise _Denied("unsupported_protocol", "request protocol is unsupported")
            request_id = _identifier(request.get("requestId"), "requestId")
            operation = request.get("op")
            if operation == "select":
                return self._select(request, request_id)
            if operation == "observe":
                return self._observe(request, request_id)
            if operation == "resume":
                return self._action(request, request_id, "resume")
            if operation == "cancel":
                return self._action(request, request_id, "cancel")
            raise _Denied("unsupported_operation", "operation is not supported")
        except _Denied as exc:
            return self._denied(request_id, exc.code, exc.reason)
        except (LabStateError, BuildError, AllocationError):
            return self._denied(
                request_id,
                "broker_denied",
                "a bounded local broker denied the request",
            )
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
            return self._denied(
                request_id, "invalid_request", "request could not be handled safely"
            )

    @staticmethod
    def _safe_request_id(request: object) -> str:
        if isinstance(request, dict):
            value = request.get("requestId")
            if isinstance(value, str) and IDENTIFIER.fullmatch(value):
                return value
        return "invalid_request"

    @staticmethod
    def _denied(request_id: str, code: str, reason: str) -> dict[str, Any]:
        return {
            "protocol": LAB_PROTOCOL,
            "requestId": request_id,
            "kind": "denied",
            "code": code,
            "reason": reason,
        }

    @staticmethod
    def _exact_keys(request: dict[str, Any], expected: frozenset[str]) -> None:
        if frozenset(request) != expected:
            raise _Denied(
                "invalid_request", "request has unexpected or missing fields"
            )

    def _coordinates(self, request: dict[str, Any]) -> tuple[str, str]:
        objective_id = _identifier(request.get("objectiveId"), "objectiveId")
        unit_id = _identifier(request.get("unitId"), "unitId")
        if objective_id != self.work_id:
            raise _Denied("objective_mismatch", "objective does not match controller")
        return objective_id, unit_id

    def _head(self) -> str:
        value = self._allocator._git("rev-parse", "HEAD").stdout.decode(
            "ascii", "strict"
        ).strip()
        if not SHA1.fullmatch(value):
            raise AllocationError("repository HEAD is not a full SHA-1 commit")
        return value

    @staticmethod
    def _unit_id(request: dict[str, Any]) -> str:
        coordinates = {
            "objectiveId": request["objectiveId"],
            "expectedBase": request["expectedBase"],
            "execution": request["execution"],
            "providerPolicy": request["providerPolicy"],
            "budget": request["budget"],
        }
        return "unit_" + hashlib.sha256(_canonical(coordinates)).hexdigest()[:32]

    @staticmethod
    def _allocation_request(attempt: Attempt) -> AllocationRequest:
        return AllocationRequest(
            run_id=attempt.attempt_id,
            expected_base=attempt.expected_base,
            max_materialized_bytes=int(SYNTHETIC_BUDGET["maxDiskBytes"]),
        )

    def _select(self, request: dict[str, Any], request_id: str) -> dict[str, Any]:
        self._exact_keys(request, _SELECT_KEYS)
        objective_id = _identifier(request.get("objectiveId"), "objectiveId")
        expected_base = request.get("expectedBase")
        if objective_id != self.work_id:
            raise _Denied("objective_mismatch", "objective does not match controller")
        if not isinstance(expected_base, str) or not SHA1.fullmatch(expected_base):
            raise _Denied("invalid_request", "expectedBase must be a full SHA-1 ID")
        if request.get("execution") != "synthetic":
            raise _Denied("provider_denied", "only synthetic execution is allowed")
        if request.get("providerPolicy") != SYNTHETIC_POLICY:
            raise _Denied("provider_denied", "synthetic provider policy is not exact")
        if request.get("budget") != SYNTHETIC_BUDGET:
            raise _Denied("budget_denied", "synthetic budget is not exact")
        if self._head() != expected_base:
            raise _Denied("base_drift", "repository HEAD differs from expectedBase")

        unit_id = self._unit_id(request)
        try:
            attempt = self._store.get_attempt(unit_id)
        except NotFoundError:
            attempt = self._store.create_attempt(
                unit_id, self.work_id, expected_base, self.allowed_paths
            )
        if attempt.work_id != self.work_id or attempt.expected_base != expected_base:
            raise _Denied("unit_conflict", "durable unit coordinates conflict")
        if attempt.state in {
            AttemptState.CANCELLED,
            AttemptState.SUCCEEDED,
            AttemptState.FAILED,
        }:
            raise _Denied("unit_terminal", "durable unit is terminal")

        allocation = self._allocation_request(attempt)
        allocated = False
        try:
            self._allocator.allocate(allocation)
            allocated = True
            if attempt.state is AttemptState.PAUSED:
                return self._selected(request_id, attempt)
            if attempt.state is AttemptState.RUNNING and self._was_resumed(
                attempt.attempt_id
            ):
                return self._selected(request_id, attempt)
            if attempt.state is AttemptState.QUEUED:
                attempt = self._store.transition_attempt(
                    attempt.attempt_id,
                    attempt.revision,
                    AttemptState.RUNNING,
                    reason="synthetic_selected",
                )
            result = BuildBroker(
                self.state_root / "builds" / attempt.attempt_id
            ).run(_BUILD_REQUEST)
            if result.get("outcome") != "success":
                raise BuildError("fixed synthetic success recipe did not succeed")
            self._ensure_evidence(
                attempt.attempt_id,
                "evidence_1",
                "synthetic.build",
                {
                    "operationId": result["operation_id"],
                    "outcome": "success",
                    "authority": "broker_observed",
                },
            )
            self._ensure_checkpoint(
                attempt.attempt_id,
                "checkpoint_1",
                "synthetic.ready",
                {"operationId": result["operation_id"], "step": 1},
            )
            attempt = self._store.get_attempt(attempt.attempt_id)
            if attempt.state is AttemptState.RUNNING:
                attempt = self._store.transition_attempt(
                    attempt.attempt_id,
                    attempt.revision,
                    AttemptState.PAUSED,
                    reason="checkpoint_ready",
                )
            if attempt.state is not AttemptState.PAUSED:
                raise LabStateError("selection did not reach its pause checkpoint")
        except Exception:
            current = self._store.get_attempt(attempt.attempt_id)
            if current.state in {
                AttemptState.QUEUED,
                AttemptState.RUNNING,
                AttemptState.PAUSED,
            }:
                try:
                    self._store.transition_attempt(
                        current.attempt_id,
                        current.revision,
                        AttemptState.FAILED,
                        reason="selection_failed",
                    )
                except LabStateError:
                    pass
            if allocated:
                try:
                    self._allocator.release(allocation)
                except AllocationError:
                    pass
            raise
        return self._selected(request_id, attempt)

    def _was_resumed(self, attempt_id: str) -> bool:
        return any(
            record.kind is RecordKind.EVENT
            and record.name == "attempt.state_changed"
            and record.payload.get("from") == "paused"
            and record.payload.get("to") == "running"
            for record in self._store.get_journal(attempt_id)
        )

    def _ensure_evidence(
        self, attempt_id: str, record_id: str, name: str, payload: dict[str, Any]
    ) -> None:
        records = self._store.get_journal(attempt_id)
        existing = next(
            (
                record
                for record in records
                if record.kind is RecordKind.EVIDENCE and record.record_id == record_id
            ),
            None,
        )
        if existing is not None:
            if existing.name != name or existing.payload != payload:
                raise ConflictError("evidence identifier conflicts")
            return
        self._store.append_evidence(
            attempt_id,
            record_id,
            name,
            EvidenceAuthority.BROKER_OBSERVED,
            payload,
        )

    def _ensure_checkpoint(
        self, attempt_id: str, record_id: str, name: str, payload: dict[str, Any]
    ) -> None:
        records = self._store.get_journal(attempt_id)
        existing = next(
            (
                record
                for record in records
                if record.kind is RecordKind.CHECKPOINT
                and record.record_id == record_id
            ),
            None,
        )
        if existing is not None:
            if existing.name != name or existing.payload != payload:
                raise ConflictError("checkpoint identifier conflicts")
            return
        self._store.append_checkpoint(attempt_id, record_id, name, payload)

    def _selected(self, request_id: str, attempt: Attempt) -> dict[str, Any]:
        return {
            "protocol": LAB_PROTOCOL,
            "requestId": request_id,
            "kind": "selected",
            "unit": self._unit(attempt),
        }

    def _latest_checkpoint(self, attempt_id: str) -> str | None:
        records = self._store.get_journal(attempt_id)
        checkpoints = [
            record.record_id
            for record in records
            if record.kind is RecordKind.CHECKPOINT
        ]
        return checkpoints[-1] if checkpoints else None

    def _unit(self, attempt: Attempt) -> dict[str, Any]:
        checkpoint = (
            self._latest_checkpoint(attempt.attempt_id)
            if attempt.state is AttemptState.PAUSED
            else None
        )
        return {
            "unitId": attempt.attempt_id,
            "objectiveId": attempt.work_id,
            "state": attempt.state.value,
            "revision": attempt.revision,
            "checkpointId": checkpoint,
            "lastSequence": attempt.last_sequence,
        }

    def _observe(self, request: dict[str, Any], request_id: str) -> dict[str, Any]:
        self._exact_keys(request, _OBSERVE_KEYS)
        _objective_id, unit_id = self._coordinates(request)
        after = _integer(request.get("afterSequence"), "afterSequence")
        limit = _integer(request.get("limit"), "limit", minimum=1)
        if limit > 1000:
            raise _Denied("invalid_request", "limit exceeds 1000")
        attempt = self._store.get_attempt(unit_id)
        if attempt.work_id != self.work_id:
            raise _Denied("objective_mismatch", "unit belongs to another objective")
        if after > attempt.last_sequence:
            raise _Denied("cursor_conflict", "cursor is ahead of durable state")
        records = self._store.get_journal(unit_id, after_sequence=0, limit=1000)
        if [record.sequence for record in records] != list(
            range(1, attempt.last_sequence + 1)
        ):
            raise LabStateError("durable journal is not contiguous")
        revision = 0
        events: list[dict[str, Any]] = []
        for record in records:
            event_type = record.name
            if record.name == "attempt.queued":
                event_type = "unit.selected"
            elif record.name == "attempt.state_changed":
                revision += 1
                destination = record.payload.get("to")
                source = record.payload.get("from")
                if destination == "running" and source == "paused":
                    event_type = "unit.resumed"
                elif destination == "cancelled":
                    event_type = "unit.cancelled"
                elif destination in {"succeeded", "failed"}:
                    event_type = "unit.terminal"
                else:
                    event_type = f"unit.{destination}"
            if record.sequence > after and len(events) < limit:
                events.append(
                    {
                        "type": event_type,
                        "objectiveId": attempt.work_id,
                        "unitId": attempt.attempt_id,
                        "sequence": record.sequence,
                        "revision": revision,
                    }
                )
        next_sequence = events[-1]["sequence"] if events else after
        return {
            "protocol": LAB_PROTOCOL,
            "requestId": request_id,
            "kind": "observed",
            "unit": self._unit(attempt),
            "events": events,
            "nextSequence": next_sequence,
        }

    def _action(
        self, request: dict[str, Any], request_id: str, operation: str
    ) -> dict[str, Any]:
        self._exact_keys(request, _RESUME_KEYS if operation == "resume" else _CANCEL_KEYS)
        objective_id, unit_id = self._coordinates(request)
        expected_revision = _integer(
            request.get("expectedRevision"), "expectedRevision"
        )
        idempotency_key = _identifier(
            request.get("idempotencyKey"), "idempotencyKey"
        )
        checkpoint_id: str | None = None
        if operation == "resume":
            checkpoint_id = _identifier(request.get("checkpointId"), "checkpointId")
        else:
            reason = request.get("reason")
            if reason not in _CANCEL_REASONS:
                raise _Denied("invalid_request", "cancel reason is unknown")

        attempt = self._store.get_attempt(unit_id)
        if attempt.work_id != objective_id:
            raise _Denied("objective_mismatch", "unit belongs to another objective")
        if operation == "resume" and checkpoint_id != self._latest_checkpoint(unit_id):
            return self._action_response(
                request_id,
                request,
                attempt,
                "denied",
                0,
                "checkpoint does not match durable state",
            )
        if operation == "resume":
            if self._head() != attempt.expected_base:
                return self._action_response(
                    request_id,
                    request,
                    attempt,
                    "denied",
                    0,
                    "repository base differs from durable state",
                )
            try:
                self._allocator.allocate(self._allocation_request(attempt))
            except AllocationError:
                return self._action_response(
                    request_id,
                    request,
                    attempt,
                    "denied",
                    0,
                    "isolated allocation failed verification",
                )

        semantic = {
            key: value
            for key, value in request.items()
            if key not in {"requestId", "protocol"}
        }
        digest = hashlib.sha256(_canonical(semantic)).hexdigest()
        action_id = "action_" + hashlib.sha256(
            f"{unit_id}\0{idempotency_key}".encode("utf-8")
        ).hexdigest()[:32]
        target = (
            AttemptState.RUNNING if operation == "resume" else AttemptState.CANCELLED
        )
        result = {
            "operation": operation,
            "state": target.value,
            "checkpointId": checkpoint_id,
        }
        transition_reason = (
            "checkpoint_resume"
            if operation == "resume"
            else {
                "operator_request": "operator_cancel",
                "budget_exhausted": "budget_cancel",
                "policy_denied": "policy_cancel",
            }[request["reason"]]
        )
        try:
            attempt, _effect, applied = self._store.apply_transition_effect(
                action_id,
                unit_id,
                f"unit.{operation}",
                digest,
                expected_revision,
                target,
                reason=transition_reason,
                result=result,
            )
        except (ConflictError, LabStateError):
            attempt = self._store.get_attempt(unit_id)
            return self._action_response(
                request_id,
                request,
                attempt,
                "conflict",
                0,
                "action conflicts with durable state",
                action_id=action_id,
            )

        if operation == "cancel":
            self._allocator.release(self._allocation_request(attempt))
        return self._action_response(
            request_id,
            request,
            attempt,
            "accepted" if applied else "already_applied",
            1,
            None,
            action_id=action_id,
        )

    def _action_response(
        self,
        request_id: str,
        request: dict[str, Any],
        attempt: Attempt,
        status: str,
        effect_count: int,
        reason: str | None,
        *,
        action_id: str | None = None,
    ) -> dict[str, Any]:
        operation = str(request["op"])
        if action_id is None:
            action_id = "action_" + hashlib.sha256(
                _canonical(
                    {
                        key: value
                        for key, value in request.items()
                        if key not in {"requestId", "protocol"}
                    }
                )
            ).hexdigest()[:32]
        return {
            "protocol": LAB_PROTOCOL,
            "requestId": request_id,
            "kind": "action",
            "receipt": {
                "actionId": action_id,
                "operation": operation,
                "objectiveId": request["objectiveId"],
                "unitId": request["unitId"],
                "checkpointId": request.get("checkpointId"),
                "expectedRevision": request["expectedRevision"],
                "idempotencyKey": request["idempotencyKey"],
                "status": status,
                "effectCount": effect_count,
                "reason": reason,
            },
            "unit": self._unit(attempt),
        }
