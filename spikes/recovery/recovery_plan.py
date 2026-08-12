#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Resolve real drill evidence against the canonical R0-09 recovery order.

Entry IDs, ordering, prerequisites, objective citations, and the enablement
boundary come only from the canonical document accepted by
:mod:`dependencies`.  The resolver never accepts a caller-supplied disposition:
it derives one receipt per position from a typed :class:`drill.Report` and
leaves positions incomplete when the drill did not produce their evidence.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import pathlib
import re

import dependencies as dep
import drill


SHA256 = re.compile(r"\A[0-9a-f]{64}\Z")


class Disposition(enum.Enum):
    EXERCISED = "exercised"
    VERIFIED_DISABLED = "verified-disabled"
    NOT_APPLICABLE = "not-applicable"
    REQUIRED_BUT_NOT_EXERCISED = "required-but-not-exercised"


class StartupPhase(enum.Enum):
    INITIAL = "initial"
    ASSEMBLING_RECOVERY_SET = "assembling-recovery-set"
    VERIFYING_RECOVERY_SET = "verifying-recovery-set"
    DISCONNECTED_STARTED = "disconnected-started"
    CREDENTIALS_RESOLVED = "credentials-resolved"
    AUDIENCES_REVALIDATED = "audiences-revalidated"
    ENABLEMENT_VERIFIED_DISABLED = "enablement-verified-disabled"


class ReceiptRefusal(enum.Enum):
    DEPENDENCY_CONSUMER_REFUSED = "dependency-consumer-refused"
    CONSUMER_DISAGREEMENT = "consumer-disagreement"
    MISSING_RECEIPT = "missing-receipt"
    EXTRA_RECEIPT = "extra-receipt"
    DUPLICATE_RECEIPT = "duplicate-receipt"
    WRONG_ORDER = "wrong-order"
    INVALID_DISPOSITION = "invalid-disposition"
    INVALID_NOT_APPLICABLE_REASON = "invalid-not-applicable-reason"
    PREREQUISITE_HASH_MISMATCH = "prerequisite-hash-mismatch"
    INVALID_EVIDENCE_HASH = "invalid-evidence-hash"
    INVALID_TRANSITION = "invalid-transition"
    UNRESOLVED_PREREQUISITE = "unresolved-prerequisite"
    EXTERNAL_AUTHORITY_GRANTED = "external-authority-granted"
    ENABLEMENT_NOT_DISABLED = "enablement-not-disabled"
    STALE_PLAN_SOURCE = "stale-plan-source"
    STALE_OBJECTIVE_CITATION = "stale-objective-citation"
    INVALID_DRILL_REPORT = "invalid-drill-report"
    STALE_DEPENDENCY_REPORT = "stale-dependency-report"
    MISSING_TYPED_EVIDENCE = "missing-typed-evidence"


class ReceiptRefused(Exception):
    def __init__(self, refusal: ReceiptRefusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


@dataclasses.dataclass(frozen=True)
class CanonicalEntry:
    position: int
    id: str
    kind: str
    requires: tuple[str, ...]
    verification: str


@dataclasses.dataclass(frozen=True)
class ObjectiveCitation:
    objective_id: str
    path: str
    quote: str
    source_sha256: str


@dataclasses.dataclass(frozen=True)
class RecoveryPlan:
    entries: tuple[CanonicalEntry, ...]
    source_path: str
    source_sha256: str
    objective_citations: tuple[ObjectiveCitation, ...]

    @property
    def by_id(self) -> dict[str, CanonicalEntry]:
        return {entry.id: entry for entry in self.entries}


def load_plan() -> RecoveryPlan:
    """Load IDs and authority only through the existing strict consumer."""
    report = dep.consume()
    if report["refused"] is not None:
        refusal = report["refused"]
        raise ReceiptRefused(
            ReceiptRefusal.DEPENDENCY_CONSUMER_REFUSED,
            f"{refusal['code']}: {refusal['detail']}",
        )
    document = dep.load_inventory()
    order = document["order"]
    if report["consumed_entries"] != len(order):
        raise ReceiptRefused(
            ReceiptRefusal.CONSUMER_DISAGREEMENT,
            "consume() and load_inventory() disagree on the canonical order",
        )
    citations = tuple(
        _load_objective_citation(objective) for objective in document["objectives"]
    )
    return RecoveryPlan(
        entries=tuple(
            CanonicalEntry(
                position=entry["position"],
                id=entry["id"],
                kind=entry["class"],
                requires=tuple(entry["requires"]),
                verification=entry["verification"],
            )
            for entry in order
        ),
        source_path=document["source"]["path"],
        source_sha256=document["source"]["sha256"],
        objective_citations=citations,
    )


def _load_objective_citation(objective: dict[str, object]) -> ObjectiveCitation:
    source = objective["source"]
    if type(source) is not dict:
        raise ReceiptRefused(
            ReceiptRefusal.STALE_OBJECTIVE_CITATION,
            f"objective {objective['id']!r} has no typed source",
        )
    path = source["path"]
    quote = source["quote"]
    if type(path) is not str or type(quote) is not str:
        raise ReceiptRefused(
            ReceiptRefusal.STALE_OBJECTIVE_CITATION,
            f"objective {objective['id']!r} has malformed citation coordinates",
        )
    relative = pathlib.PurePosixPath(path)
    if (
        relative.is_absolute()
        or relative.as_posix() != path
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ReceiptRefused(
            ReceiptRefusal.STALE_OBJECTIVE_CITATION,
            f"objective {objective['id']!r} source path is not canonical relative",
        )
    source_path = dep.REPOSITORY_ROOT
    for part in relative.parts:
        source_path /= part
        if source_path.is_symlink():
            raise ReceiptRefused(
                ReceiptRefusal.STALE_OBJECTIVE_CITATION,
                f"objective {objective['id']!r} source traverses a symlink",
            )
    try:
        source_bytes = source_path.read_bytes()
    except OSError as error:
        raise ReceiptRefused(
            ReceiptRefusal.STALE_OBJECTIVE_CITATION,
            f"objective {objective['id']!r} source cannot be read: {type(error).__name__}",
        ) from None
    try:
        source_text = source_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ReceiptRefused(
            ReceiptRefusal.STALE_OBJECTIVE_CITATION,
            f"objective {objective['id']!r} source is not UTF-8",
        ) from None
    if quote not in source_text:
        raise ReceiptRefused(
            ReceiptRefusal.STALE_OBJECTIVE_CITATION,
            f"objective {objective['id']!r} quote is absent from {path}",
        )
    return ObjectiveCitation(
        objective_id=str(objective["id"]),
        path=path,
        quote=quote,
        source_sha256=hashlib.sha256(source_bytes).hexdigest(),
    )


@dataclasses.dataclass(frozen=True)
class ExternalAuthorityFlags:
    transport_intake: bool = False
    outbox_delivery: bool = False
    provider_starts: bool = False
    connector_sends: bool = False
    transport_lease_acquisition: bool = False

    def granted(self) -> tuple[str, ...]:
        return tuple(
            field.name
            for field in dataclasses.fields(self)
            if getattr(self, field.name) is not False
        )


@dataclasses.dataclass(frozen=True)
class DisconnectedStartState:
    receipt_cursor: int
    phase: StartupPhase


@dataclasses.dataclass(frozen=True)
class StateTransition:
    before: DisconnectedStartState
    after: DisconnectedStartState


@dataclasses.dataclass(frozen=True)
class StepReceipt:
    entry_id: str
    disposition: Disposition
    prerequisite_receipt_hashes: tuple[tuple[str, str], ...]
    evidence_sha256: str
    transition: StateTransition
    authorities: ExternalAuthorityFlags = ExternalAuthorityFlags()

    def receipt_sha256(self) -> str:
        encoded = json.dumps(
            _json_value(self), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclasses.dataclass(frozen=True)
class ReceiptSet:
    receipts: tuple[StepReceipt, ...]


@dataclasses.dataclass(frozen=True)
class PlanAssessment:
    structurally_complete: bool
    completion_eligible: bool
    required_but_not_exercised: tuple[str, ...]
    final_state: DisconnectedStartState


@dataclasses.dataclass(frozen=True)
class EvidenceBlocker:
    entry_id: str
    code: str
    detail: str


@dataclasses.dataclass(frozen=True)
class DrillResolution:
    plan: RecoveryPlan
    report_sha256: str
    receipt_set: ReceiptSet
    assessment: PlanAssessment
    blockers: tuple[EvidenceBlocker, ...]
    enablement_verified_disabled: bool


def _json_value(value: object) -> object:
    if isinstance(value, enum.Enum):
        return value.value
    if dataclasses.is_dataclass(value):
        return {
            field.name: _json_value(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    return value


def initial_state() -> DisconnectedStartState:
    return DisconnectedStartState(0, StartupPhase.INITIAL)


def next_state(
    current: DisconnectedStartState,
    entry: CanonicalEntry,
    disposition: Disposition,
) -> DisconnectedStartState:
    """Advance the receipt cursor; advance semantics only for exercised work."""
    if entry.position != current.receipt_cursor + 1:
        raise ReceiptRefused(
            ReceiptRefusal.INVALID_TRANSITION,
            f"cannot advance from position {current.receipt_cursor} "
            f"to canonical position {entry.position}",
        )
    if disposition is Disposition.REQUIRED_BUT_NOT_EXERCISED:
        return DisconnectedStartState(entry.position, current.phase)
    if entry.kind == "recovery-set-input":
        phase = StartupPhase.ASSEMBLING_RECOVERY_SET
    elif entry.kind == "enablement-gate":
        phase = StartupPhase.ENABLEMENT_VERIFIED_DISABLED
    elif entry.verification == "startup-in-disconnected-recovery":
        phase = StartupPhase.DISCONNECTED_STARTED
    elif entry.verification == "credential-resolution":
        phase = StartupPhase.CREDENTIALS_RESOLVED
    elif entry.verification == "audience-revalidation":
        phase = StartupPhase.AUDIENCES_REVALIDATED
    else:
        phase = StartupPhase.VERIFYING_RECOVERY_SET
    return DisconnectedStartState(entry.position, phase)


def transition_for(
    current: DisconnectedStartState,
    entry: CanonicalEntry,
    disposition: Disposition,
) -> StateTransition:
    return StateTransition(current, next_state(current, entry, disposition))


def validate_receipts(plan: RecoveryPlan, receipt_set: ReceiptSet) -> PlanAssessment:
    """Validate one receipt per canonical position and its evidence chain."""
    receipts = receipt_set.receipts
    ids = [receipt.entry_id for receipt in receipts]
    duplicates = sorted({entry_id for entry_id in ids if ids.count(entry_id) > 1})
    if duplicates:
        raise ReceiptRefused(
            ReceiptRefusal.DUPLICATE_RECEIPT,
            f"duplicate receipt IDs: {duplicates}",
        )

    canonical_ids = [entry.id for entry in plan.entries]
    missing = [entry_id for entry_id in canonical_ids if entry_id not in ids]
    if missing:
        raise ReceiptRefused(
            ReceiptRefusal.MISSING_RECEIPT, f"missing receipt IDs: {missing}"
        )
    extra = [entry_id for entry_id in ids if entry_id not in plan.by_id]
    if extra:
        raise ReceiptRefused(
            ReceiptRefusal.EXTRA_RECEIPT, f"extra receipt IDs: {extra}"
        )
    if ids != canonical_ids:
        raise ReceiptRefused(
            ReceiptRefusal.WRONG_ORDER,
            "receipt order differs from the canonical dependency order",
        )

    state = initial_state()
    receipt_hashes: dict[str, str] = {}
    dispositions: dict[str, Disposition] = {}
    incomplete: list[str] = []
    for entry, receipt in zip(plan.entries, receipts, strict=True):
        if not isinstance(receipt.disposition, Disposition):
            raise ReceiptRefused(
                ReceiptRefusal.INVALID_DISPOSITION,
                f"{entry.id!r} has no typed disposition",
            )
        if receipt.disposition is Disposition.NOT_APPLICABLE:
            raise ReceiptRefused(
                ReceiptRefusal.INVALID_NOT_APPLICABLE_REASON,
                f"{entry.id!r} has no policy-authorized N/A decision",
            )

        if entry.kind == "enablement-gate":
            if receipt.disposition not in {
                Disposition.VERIFIED_DISABLED,
                Disposition.REQUIRED_BUT_NOT_EXERCISED,
            }:
                raise ReceiptRefused(
                    ReceiptRefusal.ENABLEMENT_NOT_DISABLED,
                    f"enablement gate {entry.id!r} must be verified-disabled or "
                    "record an explicit evidence blocker",
                )
        elif receipt.disposition is Disposition.VERIFIED_DISABLED:
            raise ReceiptRefused(
                ReceiptRefusal.INVALID_DISPOSITION,
                f"non-enablement position {entry.id!r} is verified-disabled",
            )

        granted = receipt.authorities.granted()
        if granted:
            raise ReceiptRefused(
                ReceiptRefusal.EXTERNAL_AUTHORITY_GRANTED,
                f"{entry.id!r} grants external authorities {list(granted)}",
            )
        if SHA256.fullmatch(receipt.evidence_sha256) is None:
            raise ReceiptRefused(
                ReceiptRefusal.INVALID_EVIDENCE_HASH,
                f"{entry.id!r} has an invalid evidence SHA-256",
            )

        expected_prerequisites = tuple(
            (required, receipt_hashes[required]) for required in entry.requires
        )
        if receipt.prerequisite_receipt_hashes != expected_prerequisites:
            raise ReceiptRefused(
                ReceiptRefusal.PREREQUISITE_HASH_MISMATCH,
                f"{entry.id!r} prerequisite hashes do not bind its canonical "
                "prerequisite receipts",
            )

        unresolved = tuple(
            required
            for required in entry.requires
            if dispositions[required]
            is Disposition.REQUIRED_BUT_NOT_EXERCISED
        )
        if unresolved and receipt.disposition is Disposition.EXERCISED:
            raise ReceiptRefused(
                ReceiptRefusal.UNRESOLVED_PREREQUISITE,
                f"{entry.id!r} claims {receipt.disposition.value} with unresolved "
                f"prerequisites {list(unresolved)}",
            )

        expected_transition = transition_for(state, entry, receipt.disposition)
        if receipt.transition != expected_transition:
            raise ReceiptRefused(
                ReceiptRefusal.INVALID_TRANSITION,
                f"{entry.id!r} transition is not {expected_transition!r}",
            )
        state = receipt.transition.after
        receipt_hashes[entry.id] = receipt.receipt_sha256()
        dispositions[entry.id] = receipt.disposition
        if receipt.disposition is Disposition.REQUIRED_BUT_NOT_EXERCISED:
            incomplete.append(entry.id)

    structurally_complete = not incomplete
    return PlanAssessment(
        structurally_complete=structurally_complete,
        # This model authenticates structure, not real execution or inventory
        # freshness across an integrated run.  A future integration resolver
        # must establish those facts; relabeling this model can never do so.
        completion_eligible=False,
        required_but_not_exercised=tuple(incomplete),
        final_state=state,
    )


def resolve_drill(*, plan: RecoveryPlan | None = None) -> DrillResolution:
    """Run the fixed drill and derive all canonical dispositions from its result.

    The caller supplies no disposition, reason, evidence hash, prerequisite
    hash, transition, authority flag, or report object. The current local
    fixture emits no direct enablement-state attestation, so its gate remains
    explicitly blocked.
    """
    return _resolve_report(drill.run(drill.Options()), plan=plan)


def _resolve_report(
    report: drill.Report, *, plan: RecoveryPlan | None = None
) -> DrillResolution:
    """Validate one internally produced report; exposed only for negatives."""
    if type(report) is not drill.Report:
        raise ReceiptRefused(
            ReceiptRefusal.INVALID_DRILL_REPORT,
            "resolver accepts only the drill.Report type",
        )
    current_plan = load_plan()
    if plan is not None and plan != current_plan:
        raise ReceiptRefused(
            ReceiptRefusal.STALE_PLAN_SOURCE,
            "supplied plan does not match the freshly rendered canonical inventory "
            "and objective citations",
        )
    plan = current_plan
    document = report.as_document()
    if document.get("schema") != drill.REPORT_SCHEMA:
        raise ReceiptRefused(
            ReceiptRefusal.INVALID_DRILL_REPORT,
            "drill report schema is not current",
        )
    current_dependency_report = dep.consume()
    if report.dependency_report != current_dependency_report:
        raise ReceiptRefused(
            ReceiptRefusal.STALE_DEPENDENCY_REPORT,
            "drill dependency evidence differs from a fresh canonical consumption",
        )
    if report.outcome is not drill.Outcome.INCOMPLETE:
        raise ReceiptRefused(
            ReceiptRefusal.INVALID_DRILL_REPORT,
            f"only a clean incomplete evidence run is resolvable; got {report.outcome.value}",
        )
    if report.fault is not drill.Fault.NONE or report.refusal is not None:
        raise ReceiptRefused(
            ReceiptRefusal.INVALID_DRILL_REPORT,
            "faulted or refused drills cannot disposition canonical recovery work",
        )
    if report.residue or not report.invariants or any(
        not result.ok for result in report.invariants
    ):
        raise ReceiptRefused(
            ReceiptRefusal.INVALID_DRILL_REPORT,
            "drill evidence is inconsistent, absent, or left residue",
        )

    report_bytes = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    report_sha256 = hashlib.sha256(report_bytes).hexdigest()
    non_exercised = _typed_non_exercise_findings(report)
    canonical_ids = {entry.id for entry in plan.entries}
    missing = sorted(canonical_ids - set(non_exercised))
    if missing:
        raise ReceiptRefused(
            ReceiptRefusal.MISSING_TYPED_EVIDENCE,
            f"drill emitted neither typed proof nor typed blocker for {missing}",
        )

    receipts: list[StepReceipt] = []
    receipt_hashes: dict[str, str] = {}
    blockers: list[EvidenceBlocker] = []
    state = initial_state()
    for entry in plan.entries:
        finding = non_exercised[entry.id]
        blocker = EvidenceBlocker(
            entry_id=entry.id,
            code=finding["code"],
            detail=finding["detail"],
        )
        blockers.append(blocker)
        evidence_sha256 = hashlib.sha256(
            json.dumps(
                {
                    "entry_id": entry.id,
                    "finding": finding,
                    "report_sha256": report_sha256,
                    "source_path": plan.source_path,
                    "source_sha256": plan.source_sha256,
                    "objective_citations": [
                        _json_value(citation) for citation in plan.objective_citations
                    ],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        disposition = Disposition.REQUIRED_BUT_NOT_EXERCISED
        receipt = StepReceipt(
            entry_id=entry.id,
            disposition=disposition,
            prerequisite_receipt_hashes=tuple(
                (required, receipt_hashes[required]) for required in entry.requires
            ),
            evidence_sha256=evidence_sha256,
            transition=transition_for(state, entry, disposition),
        )
        receipts.append(receipt)
        receipt_hashes[entry.id] = receipt.receipt_sha256()
        state = receipt.transition.after

    receipt_set = ReceiptSet(tuple(receipts))
    assessment = validate_receipts(plan, receipt_set)
    return DrillResolution(
        plan=plan,
        report_sha256=report_sha256,
        receipt_set=receipt_set,
        assessment=assessment,
        blockers=tuple(blockers),
        enablement_verified_disabled=False,
    )


def _typed_non_exercise_findings(
    report: drill.Report,
) -> dict[str, dict[str, str]]:
    findings: dict[str, dict[str, str]] = {}
    for finding in report.findings:
        if finding.code is not drill.FindingCode.DEPENDENCY_NOT_EXERCISED:
            continue
        if finding.subject in findings:
            raise ReceiptRefused(
                ReceiptRefusal.INVALID_DRILL_REPORT,
                f"drill repeats non-exercise evidence for {finding.subject!r}",
            )
        findings[finding.subject] = finding.as_document()
    return findings
