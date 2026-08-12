#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Conservative internal composition of anonymous recovery evidence."""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import os
import sys
from typing import Any

try:
    from . import anonymous_backup, anonymous_boundary, recovery_artifact
    from . import recovery_plan as plan_model
except ImportError:
    import anonymous_backup  # type: ignore[no-redef]
    import anonymous_boundary  # type: ignore[no-redef]
    import recovery_artifact  # type: ignore[no-redef]
    import recovery_plan as plan_model  # type: ignore[no-redef]


class CompositionRefusal(enum.Enum):
    PLAN_INVALID = "plan-invalid"
    PRODUCER_REFUSED = "producer-refused"
    PACKAGE_INVALID = "package-invalid"
    BOUNDARY_REFUSED = "boundary-refused"
    EVIDENCE_INVALID = "evidence-invalid"


class CompositionRefused(RuntimeError):
    def __init__(self, refusal: CompositionRefusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


@dataclasses.dataclass(frozen=True)
class MechanismMeasurement:
    id: str
    value_seconds: float
    scope: str
    objective_value_seconds: None = None
    comparison: None = None
    comparison_status: str = "out_of_scope"


@dataclasses.dataclass(frozen=True)
class CompositionResolution:
    plan: plan_model.RecoveryPlan
    receipt_set: plan_model.ReceiptSet
    assessment: plan_model.PlanAssessment
    blockers: tuple[plan_model.EvidenceBlocker, ...]
    package_receipt: recovery_artifact.PackageReceipt
    package_recovery_point: recovery_artifact.SyntheticRecoveryPoint
    boundary_json: bytes
    boundary_sha256: str
    evidence_root_sha256: str
    measurements: tuple[MechanismMeasurement, ...]
    enablement_verified_disabled: bool = False
    enablement_gate_run: bool = False
    enablement_gate_status: str = "not-run"


EXERCISED_IDS = frozenset({
    "audit-journal-through-watermark",
    "database-and-snapshot-metadata",
    "verify-database-integrity",
})

CANONICAL_IDS = (
    "artifact-metadata-and-tombstones",
    "audit-journal-through-watermark",
    "configuration-and-workspace-registry",
    "context-memory-and-automation-state",
    "corresponding-source-and-locks",
    "database-and-snapshot-metadata",
    "disconnected-start-bundle",
    "last-known-good-seed-and-verifier",
    "policy-and-bundle-hashes",
    "recoverable-secret-material",
    "release-manifests-and-schemas",
    "tool-and-extension-manifests",
    "verify-artifact-hashes",
    "verify-database-integrity",
    "verify-disconnected-start-bundle",
    "verify-manifests",
    "verify-policy-versions",
    "start-in-disconnected-recovery",
    "resolve-credential-descriptors",
    "revalidate-audiences-and-tenants",
    "enable-transports-and-provider-starts",
)
CANONICAL_TAIL = (
    (13, CANONICAL_IDS[12], "verification-step", (CANONICAL_IDS[0],), "hash-comparison"),
    (14, CANONICAL_IDS[13], "verification-step", (CANONICAL_IDS[5],), "integrity-check"),
    (15, CANONICAL_IDS[14], "verification-step", (CANONICAL_IDS[4], CANONICAL_IDS[6], CANONICAL_IDS[7]), "integrity-check"),
    (16, CANONICAL_IDS[15], "verification-step", (CANONICAL_IDS[2], CANONICAL_IDS[10]), "version-comparison"),
    (17, CANONICAL_IDS[16], "verification-step", (CANONICAL_IDS[8],), "version-comparison"),
    (18, CANONICAL_IDS[17], "verification-step", (CANONICAL_IDS[1], CANONICAL_IDS[3], CANONICAL_IDS[11], CANONICAL_IDS[12], CANONICAL_IDS[13], CANONICAL_IDS[15], CANONICAL_IDS[16]), "startup-in-disconnected-recovery"),
    (19, CANONICAL_IDS[18], "verification-step", (CANONICAL_IDS[9], CANONICAL_IDS[17]), "credential-resolution"),
    (20, CANONICAL_IDS[19], "verification-step", (CANONICAL_IDS[18],), "audience-revalidation"),
    (21, CANONICAL_IDS[20], "enablement-gate", (CANONICAL_IDS[19],), "none-recorded"),
)
CANONICAL_ENTRIES = tuple(
    (position, CANONICAL_IDS[position - 1], "recovery-set-input", (), "none-recorded")
    for position in range(1, 13)
) + CANONICAL_TAIL
CANONICAL_SOURCE = (
    "plan/inventory/surface/inventory.json",
    "0f52283cf5ce9b40754bfb12c26a4460df6a1194a5a2e80f40dceeb5ded9a602",
)
OBJECTIVE_QUOTE = "Initial acceptance objectives are RPO <= 5 minutes for durable control state and RTO <= 30 minutes on the same class of host."
CANONICAL_CITATIONS = (
    ("recovery-point-objective-control-state", "docs/product-plan/requirements/operations-and-governance.md", OBJECTIVE_QUOTE, "a92ca8f90acb61bedfcc497af8fcbeb3557bbfa5ef2e587042471c54edd15901"),
    ("recovery-time-objective-same-host-class", "docs/product-plan/requirements/operations-and-governance.md", OBJECTIVE_QUOTE, "a92ca8f90acb61bedfcc497af8fcbeb3557bbfa5ef2e587042471c54edd15901"),
)

BLOCKER_REASONS = {
    "artifact-metadata-and-tombstones": "artifact hashes were checked, but no tombstone deletion behavior was exercised",
    "configuration-and-workspace-registry": "synthetic configuration exists, but no workspace registry was restored",
    "context-memory-and-automation-state": "the package contains an empty fixed placeholder, not recovered application state",
    "corresponding-source-and-locks": "fixed digest metadata is not a restored corresponding-source payload",
    "disconnected-start-bundle": "the fixed disconnected definition is not an independently restored runnable bundle",
    "last-known-good-seed-and-verifier": "fixed seed metadata was not executed by a bootstrap verifier",
    "policy-and-bundle-hashes": "policy metadata exists, but corresponding policy bundle bytes were not restored",
    "recoverable-secret-material": "synthetic descriptor metadata is not recoverable secret material",
    "release-manifests-and-schemas": "synthetic release metadata is not current and previous release/schema recovery",
    "tool-and-extension-manifests": "empty fixed lists do not exercise enabled or quarantined tool revisions",
    "verify-artifact-hashes": "hash checks succeeded but prerequisite artifact tombstone recovery is unresolved",
    "verify-disconnected-start-bundle": "no restored bundle was checked against corresponding source and seed verifier",
    "verify-manifests": "configuration and release prerequisites remain synthetic placeholders",
    "verify-policy-versions": "no restored policy bundle bytes exist for version comparison",
    "start-in-disconnected-recovery": "the pinned worker verified package bytes only; Automonique was not started",
    "resolve-credential-descriptors": "no escrow or external secret provider resolved a credential version",
    "revalidate-audiences-and-tenants": "no resolved credential audience or tenant was revalidated",
    "enable-transports-and-provider-starts": "no recovered service existed whose transport/provider gates could be inspected",
}


def resolve_anonymous_composition() -> CompositionResolution:
    """Run the fixed producer and boundary; accept no caller evidence or policy."""
    return _run()


def _run() -> CompositionResolution:
    try:
        current_plan = plan_model.load_plan()
        _validate_closed_plan(current_plan)
    except Exception as exc:
        raise CompositionRefused(CompositionRefusal.PLAN_INVALID, f"canonical plan refused: {type(exc).__name__}: {exc}") from exc
    try:
        backup = anonymous_backup.produce_anonymous_backup()
    except Exception as exc:
        raise CompositionRefused(CompositionRefusal.PRODUCER_REFUSED, f"anonymous producer refused: {type(exc).__name__}: {exc}") from exc
    descriptor = getattr(backup, "descriptor", -1)
    if type(descriptor) is not int or descriptor < 0:
        raise CompositionRefused(CompositionRefusal.PRODUCER_REFUSED, "producer returned no owned descriptor")
    try:
        if type(backup) is not anonymous_backup.AnonymousBackup:
            raise CompositionRefused(CompositionRefusal.PRODUCER_REFUSED, "producer returned the wrong typed result")
        try:
            if not recovery_artifact.attest_package_seals(descriptor):
                raise CompositionRefused(CompositionRefusal.PACKAGE_INVALID, "package lacks the exact immutable seals")
            verified = recovery_artifact.verify_package_fd(descriptor)
            if verified.receipt != backup.receipt or verified != backup.verified or backup.concurrent_commit_observed is not True:
                raise CompositionRefused(CompositionRefusal.PACKAGE_INVALID, "producer and independent package evidence disagree")
        except CompositionRefused:
            raise
        except Exception as exc:
            raise CompositionRefused(CompositionRefusal.PACKAGE_INVALID, f"independent package verification refused: {type(exc).__name__}: {exc}") from exc
        try:
            boundary = anonymous_boundary.run(descriptor, backup.receipt)
        except Exception as exc:
            raise CompositionRefused(CompositionRefusal.BOUNDARY_REFUSED, f"boundary runner refused: {type(exc).__name__}: {exc}") from exc
        package_identity = anonymous_boundary._identity(descriptor)
        try:
            _, worker_source_identity = anonymous_boundary._read_pinned_worker()
            runtime_identity = anonymous_boundary._runtime_identity()
        except Exception as exc:
            raise CompositionRefused(CompositionRefusal.BOUNDARY_REFUSED, f"post-run trust coordinates refused: {type(exc).__name__}: {exc}") from exc
        boundary_json = _validate_boundary_result(
            boundary, package_identity, worker_source_identity, runtime_identity)
    finally:
        active_error = sys.exc_info()[0] is not None
        try:
            os.close(descriptor)
        except OSError as exc:
            if not active_error:
                raise CompositionRefused(CompositionRefusal.PACKAGE_INVALID, f"package descriptor close refused: {exc}") from exc
    boundary_sha256 = hashlib.sha256(boundary_json).hexdigest()
    boundary_evidence = json.loads(boundary_json)["evidence"]
    integrity_proven = _database_integrity_proven(boundary_evidence)
    if not integrity_proven:
        raise CompositionRefused(
            CompositionRefusal.EVIDENCE_INVALID,
            "position 14 requires exact nested database integrity evidence",
        )
    evidence_base = {
        "plan": {
            "source_path": current_plan.source_path,
            "source_sha256": current_plan.source_sha256,
            "entries": [_json_value(entry) for entry in current_plan.entries],
            "objective_citations": [_json_value(item) for item in current_plan.objective_citations],
        },
        "package": {
            "receipt": _json_value(backup.receipt),
            "recovery_point": _json_value(verified.recovery_point),
            "concurrent_commit_observed": True,
            "exact_seals": True,
        },
        "boundary_json_sha256": boundary_sha256,
        "boundary_json": boundary_json.decode("ascii"),
        "worker_pin": {
            "base_commit": anonymous_boundary.PINNED_BASE_COMMIT,
            "relative_path": anonymous_boundary.PINNED_WORKER_RELATIVE.as_posix(),
            "sha256": anonymous_boundary.PINNED_WORKER_SHA256,
            "git_blob": anonymous_boundary.PINNED_WORKER_GIT_BLOB,
            "size": anonymous_boundary.PINNED_WORKER_SIZE,
        },
    }
    evidence_root = _digest(evidence_base)
    state = plan_model.initial_state()
    receipt_hashes: dict[str, str] = {}
    receipts: list[plan_model.StepReceipt] = []
    blockers: list[plan_model.EvidenceBlocker] = []
    dispositions: dict[str, plan_model.Disposition] = {}
    for entry in current_plan.entries:
        exercised = entry.id in EXERCISED_IDS
        if entry.id == "verify-database-integrity":
            exercised = (
                integrity_proven
                and dispositions.get("database-and-snapshot-metadata")
                is plan_model.Disposition.EXERCISED
            )
            if not exercised:
                raise CompositionRefused(
                    CompositionRefusal.EVIDENCE_INVALID,
                    "position 14 prerequisite or nested proof is unresolved",
                )
        disposition = plan_model.Disposition.EXERCISED if exercised else plan_model.Disposition.REQUIRED_BUT_NOT_EXERCISED
        blocker = None if exercised else plan_model.EvidenceBlocker(entry.id, "missing-integrated-evidence", BLOCKER_REASONS[entry.id])
        if blocker is not None:
            blockers.append(blocker)
        evidence_sha256 = _digest({
            "evidence_root_sha256": evidence_root,
            "entry": _json_value(entry),
            "disposition": disposition.value,
            "blocker": None if blocker is None else _json_value(blocker),
        })
        receipt = plan_model.StepReceipt(
            entry_id=entry.id,
            disposition=disposition,
            prerequisite_receipt_hashes=tuple((required, receipt_hashes[required]) for required in entry.requires),
            evidence_sha256=evidence_sha256,
            transition=plan_model.transition_for(state, entry, disposition),
        )
        receipts.append(receipt)
        receipt_hashes[entry.id] = receipt.receipt_sha256()
        dispositions[entry.id] = disposition
        state = receipt.transition.after
    receipt_set = plan_model.ReceiptSet(tuple(receipts))
    try:
        assessment = plan_model.validate_receipts(current_plan, receipt_set)
    except CompositionRefused:
        raise
    except Exception as exc:
        raise CompositionRefused(CompositionRefusal.EVIDENCE_INVALID, f"receipt-chain validation refused: {type(exc).__name__}: {exc}") from exc
    mechanism_seconds = boundary.evidence.get("mechanism_seconds")
    if type(mechanism_seconds) not in {int, float} or mechanism_seconds < 0:
        raise CompositionRefused(CompositionRefusal.EVIDENCE_INVALID, "boundary mechanism duration is malformed")
    measurements = (
        MechanismMeasurement("rpo", verified.recovery_point.derived_rpo_seconds, "anonymous_synthetic_mechanism"),
        MechanismMeasurement("rto", float(mechanism_seconds), "same_kernel_boundary_mechanism"),
    )
    return CompositionResolution(
        current_plan, receipt_set, assessment, tuple(blockers), backup.receipt,
        verified.recovery_point, boundary_json, boundary_sha256,
        evidence_root, measurements,
    )


def _validate_closed_plan(plan: object) -> None:
    if type(plan) is not plan_model.RecoveryPlan:
        raise CompositionRefused(CompositionRefusal.PLAN_INVALID, "canonical plan has the wrong type")
    observed = tuple((entry.position, entry.id, entry.kind, entry.requires, entry.verification) for entry in plan.entries)
    citations = tuple((item.objective_id, item.path, item.quote, item.source_sha256) for item in plan.objective_citations)
    if observed != CANONICAL_ENTRIES or (plan.source_path, plan.source_sha256) != CANONICAL_SOURCE or citations != CANONICAL_CITATIONS:
        raise CompositionRefused(CompositionRefusal.PLAN_INVALID, "canonical plan entries, source, or objective citations differ")
    exercised_coordinates = tuple((entry.position, entry.id) for entry in plan.entries if entry.id in EXERCISED_IDS)
    if exercised_coordinates != ((2, CANONICAL_IDS[1]), (6, CANONICAL_IDS[5]), (14, CANONICAL_IDS[13])):
        raise CompositionRefused(CompositionRefusal.PLAN_INVALID, "exercised evidence coordinates differ from positions 2, 6, and 14")
    if set(BLOCKER_REASONS) != set(CANONICAL_IDS) - EXERCISED_IDS:
        raise CompositionRefused(CompositionRefusal.PLAN_INVALID, "closed blocker map differs from canonical non-exercised positions")


def _validate_boundary_result(
    boundary: object,
    package_identity: dict[str, int],
    worker_source_identity: dict[str, int],
    runtime_identity: dict[str, Any],
) -> bytes:
    try:
        return _validate_boundary_result_inner(
            boundary, package_identity, worker_source_identity, runtime_identity)
    except CompositionRefused:
        raise
    except Exception as exc:
        raise CompositionRefused(CompositionRefusal.BOUNDARY_REFUSED, f"boundary evidence validation refused: {type(exc).__name__}: {exc}") from exc


def _validate_boundary_result_inner(
    boundary: object,
    package_identity: dict[str, int],
    worker_source_identity: dict[str, int],
    runtime_identity: dict[str, Any],
) -> bytes:
    if type(boundary) is not anonymous_boundary.Result:
        raise CompositionRefused(CompositionRefusal.BOUNDARY_REFUSED, "boundary returned the wrong typed result")
    if boundary.outcome is not anonymous_boundary.Outcome.MECHANISM_VERIFIED or boundary.evidence is None or boundary.refusal is not None or boundary.reaped is not True or boundary.wait_status != 0:
        detail = "boundary did not return exact reaped success"
        if boundary.refusal is not None:
            detail = f"{boundary.refusal.code.value}: {boundary.refusal.detail}"
        raise CompositionRefused(CompositionRefusal.BOUNDARY_REFUSED, detail)
    evidence = boundary.evidence
    expected_keys = set(anonymous_boundary.EVIDENCE_KEYS) | {
        "mechanism_started_monotonic_ns", "mechanism_ended_monotonic_ns",
        "mechanism_seconds", "rto_objective_eligible",
    }
    if type(evidence) is not dict or set(evidence) != expected_keys:
        raise CompositionRefused(CompositionRefusal.BOUNDARY_REFUSED, "boundary evidence keys differ")
    verification = evidence["verification"]
    caps = evidence["capabilities"]
    identity_keys = {"device", "inode", "size", "mtime_ns", "ctime_ns"}
    identities = (evidence["package_memfd_identity"], evidence["worker_memfd_identity"])
    worker_source = evidence["worker_source"]
    runtime = evidence["runtime_identity"]
    maps = evidence["id_maps"]
    duration_ns = evidence["mechanism_ended_monotonic_ns"] - evidence["mechanism_started_monotonic_ns"]
    checks = (
        anonymous_boundary._verification_valid(verification),
        verification["checks"] == list(anonymous_boundary.CHECK_NAMES),
        "control_database_integrity" in verification["checks"],
        "control_database_schema_exact" in verification["checks"],
        verification["event_count"] == 4,
        verification["artifact_count"] == 4,
        evidence["package_receipt"] == anonymous_boundary._receipt_document(anonymous_boundary.EXPECTED_RECEIPT),
        evidence["package_memfd_identity"] == package_identity,
        evidence["package_seals"] == anonymous_boundary.REQUIRED_SEALS,
        evidence["worker_seals"] == anonymous_boundary.REQUIRED_SEALS,
        evidence["worker_sha256"] == anonymous_boundary.PINNED_WORKER_SHA256,
        evidence["worker_git_blob"] == anonymous_boundary.PINNED_WORKER_GIT_BLOB,
        evidence["worker_base_commit"] == anonymous_boundary.PINNED_BASE_COMMIT,
        type(worker_source) is dict and set(worker_source) == {"relative_path", "identity", "size"},
        worker_source["relative_path"] == anonymous_boundary.PINNED_WORKER_RELATIVE.as_posix(),
        worker_source["size"] == anonymous_boundary.PINNED_WORKER_SIZE,
        type(worker_source["identity"]) is dict and set(worker_source["identity"]) == identity_keys,
        worker_source["identity"] == worker_source_identity,
        all(type(value) is int and value >= 0 for value in worker_source["identity"].values()),
        all(type(item) is dict and set(item) == identity_keys for item in identities),
        all(type(value) is int and value >= 0 for item in identities for value in item.values()),
        evidence["package_memfd_identity"]["size"] == anonymous_boundary.PACKAGE_SIZE,
        evidence["worker_memfd_identity"]["size"] == anonymous_boundary.PINNED_WORKER_SIZE,
        anonymous_boundary._valid_namespaces(evidence["namespace_identities"]),
        evidence["namespace_flags"] == anonymous_boundary.cb.EXACT_NAMESPACE_FLAGS,
        evidence["pid"] == 1,
        evidence["uid"] == 0,
        evidence["no_new_privs"] == 1,
        evidence["repo_read_errno"] == 13,
        evidence["network_connect_errno"] == 13,
        evidence["open_fds"] == [anonymous_boundary.REPORT_FD, anonymous_boundary.PACKAGE_FD, anonymous_boundary.WORKER_FD],
        evidence["environment"] == ["LC_CTYPE"],
        evidence["scope"] == "pinned-anonymous-mechanism-only",
        evidence["objective_eligible"] is False,
        evidence["rto_objective_eligible"] is False,
        evidence["position_receipts_emitted"] == [],
        evidence["external_authority"] == anonymous_boundary.EXTERNAL_AUTHORITY,
        evidence["seccomp_installed"] is False,
        type(evidence["run_id"]) is str and len(evidence["run_id"]) == 32 and all(character in "0123456789abcdef" for character in evidence["run_id"]),
        type(evidence["mechanism_started_monotonic_ns"]) is int,
        type(evidence["mechanism_ended_monotonic_ns"]) is int,
        evidence["mechanism_ended_monotonic_ns"] >= evidence["mechanism_started_monotonic_ns"],
        type(evidence["mechanism_seconds"]) in {int, float} and evidence["mechanism_seconds"] >= 0,
        evidence["mechanism_seconds"] == duration_ns / 1_000_000_000,
        type(runtime) is dict and set(runtime) == {"path", "device", "inode", "size", "sha256", "implementation", "version"},
        runtime == runtime_identity,
        type(runtime["path"]) is str and type(runtime["sha256"]) is str and len(runtime["sha256"]) == 64,
        all(type(runtime[key]) is int and runtime[key] >= 0 for key in ("device", "inode", "size")),
        type(runtime["implementation"]) is str and type(runtime["version"]) is list and len(runtime["version"]) == 3 and all(type(item) is int for item in runtime["version"]),
        type(maps) is dict and set(maps) == {"uid_map", "gid_map", "supplementary_groups"},
        type(maps["uid_map"]) is str and maps["uid_map"].split() == ["0", str(os.getuid()), "1"],
        maps["gid_map"] is None and type(maps["supplementary_groups"]) is list,
    )
    if not all(checks) or type(caps) is not dict or set(caps) != {"effective", "permitted", "inheritable"} or any(words != [0, 0] for words in caps.values()):
        raise CompositionRefused(CompositionRefusal.BOUNDARY_REFUSED, "boundary evidence invariants differ")
    return (json.dumps(boundary.as_document(), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def _database_integrity_proven(evidence: object) -> bool:
    if type(evidence) is not dict or type(evidence.get("verification")) is not dict:
        return False
    verification = evidence["verification"]
    return (
        verification.get("checks") == list(anonymous_boundary.CHECK_NAMES)
        and "control_database_integrity" in verification["checks"]
        and "control_database_schema_exact" in verification["checks"]
        and verification.get("event_count") == 4
        and verification.get("artifact_count") == 4
    )


def _json_value(value: object) -> object:
    if isinstance(value, enum.Enum):
        return value.value
    if dataclasses.is_dataclass(value):
        return {field.name: _json_value(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return value


def _digest(value: object) -> str:
    encoded = json.dumps(_json_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()
