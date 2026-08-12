#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""The R0-10 baseline recovery drill.

What this measures, exactly: a consistent online backup of a synthetic control
state, a restore of that backup into an empty target that never existed before,
and eight coherence invariants over the restored state — with a writer
committing transactions *while* the backup runs, and the source destroyed
before the restore begins.

What this does not measure, exactly: a clean *host*. No host is provisioned, no
runtime is installed, no service is started, no credential descriptor is
resolved, and no disconnected-recovery-mode startup happens. The declared
objectives in `docs/product-plan/requirements/goals-and-invariants.md` are about
that larger operation, so this drill reports its recovery point and recovery
time as measured numbers whose comparison against those objectives is
`out_of_scope`, never as a pass. `Comparison.MET` is unreachable from
`Scope.LOCAL_FIXTURE` by construction, and a test holds that shut.

Run it from the repository root:

    python3 spikes/recovery/drill.py                 # the local drill
    python3 spikes/recovery/drill.py --procedure     # print the procedure only
    python3 spikes/recovery/drill.py --fault naive-backup   # a negative control

Exit codes: 0 verified, 1 failed, 3 refused, 4 inconsistent, 5 residue left.

The drill reads no environment variable directly. It reaches the platform
temporary root through `tempfile.gettempdir()` and the home directory through
`pathlib.Path.home()`, both only to *refuse* a dangerous workspace. It holds no
credential, opens no socket and starts no subprocess.
"""

from __future__ import annotations

import argparse
import enum
import json
import pathlib
import secrets
import sys
import tempfile
import time
from dataclasses import dataclass, field

HERE = pathlib.Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import dependencies as dep  # noqa: E402
import recovery_set as rs  # noqa: E402

REPOSITORY_ROOT = HERE.parent.parent
REPORT_SCHEMA = "automonique.recovery.drill-report.v1"
MARKER_NAME = ".disposable-fixture"
MARKER_SCHEMA = "automonique.recovery.disposable-marker.v1"
WORKSPACE_PREFIX = "automonique-recovery-"

SEED_EVENTS = 32
EVENTS_DURING_BACKUP = 8
EVENTS_AFTER_BACKUP = 6
PACE_SECONDS = 0.02


class Phase(enum.Enum):
    PRECONDITION = "precondition"
    SEED = "seed"
    BACKUP = "backup"
    LOSS = "loss"
    RESTORE = "restore"
    VERIFY = "verify"
    MEASURE = "measure"
    CLEANUP = "cleanup"


class Outcome(enum.Enum):
    VERIFIED = "verified"
    INCOMPLETE = "incomplete"
    REFUSED = "refused"
    INCONSISTENT = "inconsistent"
    RESIDUE_LEFT = "residue_left"
    FAILED = "failed"


EXIT_CODE = {
    Outcome.VERIFIED: 0,
    Outcome.INCOMPLETE: 2,
    Outcome.FAILED: 1,
    Outcome.REFUSED: 3,
    Outcome.INCONSISTENT: 4,
    Outcome.RESIDUE_LEFT: 5,
}


class Refusal(enum.Enum):
    """Every way the drill declines to start. Closed by construction."""

    WORKSPACE_INSIDE_REPOSITORY = "workspace_inside_repository"
    WORKSPACE_NOT_UNDER_TEMPORARY_ROOT = "workspace_not_under_temporary_root"
    WORKSPACE_IS_HOME_OR_ROOT = "workspace_is_home_or_root"
    WORKSPACE_NOT_EMPTY = "workspace_not_empty"
    MARKER_MISSING = "marker_missing"
    MARKER_TOKEN_MISMATCH = "marker_token_mismatch"


class Fault(enum.Enum):
    """Deliberate breakages used to prove each rule can fail. Test use only."""

    NONE = "none"
    UNSAFE_WORKSPACE = "unsafe-workspace"
    NAIVE_BACKUP = "naive-backup"
    LEAK_SOURCE = "leak-source"
    TAMPER_BLOB = "tamper-blob"
    CRASH_MID_RESTORE = "crash-mid-restore"
    SKIP_CLEANUP = "skip-cleanup"


class Scope(enum.Enum):
    """What a measurement was taken over."""

    LOCAL_FIXTURE = "local_fixture"
    CLEAN_HOST = "clean_host"


class Comparison(enum.Enum):
    MET = "met"
    MISSED = "missed"
    OUT_OF_SCOPE = "out_of_scope"


class FindingCode(enum.Enum):
    INVARIANT_VIOLATED = "invariant_violated"
    OBJECTIVE_MISSED = "objective_missed"
    OBJECTIVE_COMPARISON_OUT_OF_SCOPE = "objective_comparison_out_of_scope"
    DEPENDENCY_NOT_EXERCISED = "dependency_not_exercised"
    RESIDUE_LEFT = "residue_left"
    RESTORE_FAILED = "restore_failed"
    # Raised by the R0-09 consumer in `dependencies.py`. Its vocabulary is a
    # subset of this one, checked by `test_recovery_drill.py`, so a code it
    # invents cannot slip into a drill report as free text.
    INVENTORY_ABSENT = dep.DependencyFinding.INVENTORY_ABSENT.value
    DEPENDENCY_MISSING_FROM_INVENTORY = \
        dep.DependencyFinding.DEPENDENCY_MISSING_FROM_INVENTORY.value
    DEPENDENCY_ORDER_CONFLICT = \
        dep.DependencyFinding.DEPENDENCY_ORDER_CONFLICT.value
    DEPENDENCY_UNVERIFIED_IN_INVENTORY = \
        dep.DependencyFinding.DEPENDENCY_UNVERIFIED_IN_INVENTORY.value


@dataclass(frozen=True)
class Objective:
    id: str
    seconds: float
    unit: str
    source: str


DECLARED_OBJECTIVES: tuple[Objective, ...] = (
    Objective(
        id="rpo",
        seconds=300.0,
        unit="seconds",
        source="docs/product-plan/requirements/goals-and-invariants.md "
               "§ initial acceptance targets — backup recovery point "
               "objective, 5 minutes or less",
    ),
    Objective(
        id="rto",
        seconds=1800.0,
        unit="seconds",
        source="docs/product-plan/requirements/goals-and-invariants.md "
               "§ initial acceptance targets — clean-host recovery time "
               "objective, 30 minutes or less",
    ),
)

OUT_OF_SCOPE_REASON = {
    "rpo": "the measured window is the drill's own pacing between the snapshot "
           "watermark and the induced loss, not a production backup cadence; a "
           "declared RPO is a property of how often backups are taken on the "
           "real system, which this drill does not schedule",
    "rto": "the measured window covers restoring and verifying a kilobyte-scale "
           "fixture on the host that is already running; it excludes host "
           "provisioning, runtime installation, credential-descriptor "
           "resolution and disconnected-recovery-mode startup, which is what "
           "the declared clean-host objective is about",
}


class DrillRefusal(Exception):
    def __init__(self, refusal: Refusal, detail: str) -> None:
        super().__init__(f"{refusal.value}: {detail}")
        self.refusal = refusal
        self.detail = detail


@dataclass(frozen=True)
class Finding:
    code: FindingCode
    subject: str
    detail: str

    def as_document(self) -> dict[str, object]:
        return {"code": self.code.value, "subject": self.subject,
                "detail": self.detail}


@dataclass
class Measurement:
    id: str
    value_seconds: float
    scope: Scope
    method: str


def compare_to_objective(
    measurement: Measurement, objective: Objective
) -> tuple[Comparison, str]:
    """Compare a measurement to a declared objective, honestly.

    A measurement taken over a local fixture cannot decide a clean-host
    objective, so the comparison is refused rather than guessed. Only a
    `Scope.CLEAN_HOST` measurement produces `MET` or `MISSED`.
    """
    if measurement.scope is not Scope.CLEAN_HOST:
        return Comparison.OUT_OF_SCOPE, OUT_OF_SCOPE_REASON.get(
            objective.id, "measurement scope does not match the objective")
    if measurement.value_seconds <= objective.seconds:
        return Comparison.MET, (
            f"{measurement.value_seconds:.3f} {objective.unit} within the "
            f"declared {objective.seconds:.0f} {objective.unit}")
    return Comparison.MISSED, (
        f"{measurement.value_seconds:.3f} {objective.unit} exceeds the declared "
        f"{objective.seconds:.0f} {objective.unit}")


@dataclass
class Report:
    outcome: Outcome
    fault: Fault
    refusal: Refusal | None = None
    refusal_detail: str = ""
    phases: list[dict[str, object]] = field(default_factory=list)
    invariants: list[rs.InvariantResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    measurements: list[tuple[Measurement, Objective, Comparison, str]] = \
        field(default_factory=list)
    residue: list[str] = field(default_factory=list)
    reproducible: dict[str, object] = field(default_factory=dict)
    dependency_report: dict[str, object] = field(default_factory=dict)

    def as_document(self) -> dict[str, object]:
        return {
            "schema": REPORT_SCHEMA,
            "outcome": self.outcome.value,
            "fault": self.fault.value,
            "refusal": None if self.refusal is None else self.refusal.value,
            "refusal_detail": self.refusal_detail,
            "phases": self.phases,
            "invariants": [r.as_document() for r in self.invariants],
            "measurements": [
                {
                    "id": m.id,
                    "value": round(m.value_seconds, 6),
                    "unit": objective.unit,
                    "scope": m.scope.value,
                    "method": m.method,
                    "declared_objective": objective.seconds,
                    "declared_objective_source": objective.source,
                    "comparison": comparison.value,
                    "comparison_detail": detail,
                    "objective_met": (
                        None if comparison is Comparison.OUT_OF_SCOPE
                        else comparison is Comparison.MET),
                }
                for m, objective, comparison, detail in self.measurements
            ],
            "findings": [f.as_document() for f in self.findings],
            "residue": self.residue,
            "reproducible": self.reproducible,
            "dependency_agreement": self.dependency_report,
        }


# ---------------------------------------------------------------------------
# preconditions


def assert_disposable(workspace: pathlib.Path) -> None:
    """Refuse anything that is not provably disposable fixture state.

    Called before the workspace is created and again before anything is
    deleted. Every refusal names one closed `Refusal` code.
    """
    resolved = workspace.resolve()
    home = pathlib.Path.home().resolve()
    temporary_root = pathlib.Path(tempfile.gettempdir()).resolve()

    if resolved == pathlib.Path(resolved.anchor) or resolved == home:
        raise DrillRefusal(
            Refusal.WORKSPACE_IS_HOME_OR_ROOT,
            "the workspace is the filesystem root or the home directory")
    repository = REPOSITORY_ROOT.resolve()
    if resolved == repository or repository in resolved.parents:
        raise DrillRefusal(
            Refusal.WORKSPACE_INSIDE_REPOSITORY,
            "the workspace is inside the live repository, which this drill "
            "must never back up, restore over or delete")
    if temporary_root not in resolved.parents and resolved != temporary_root:
        raise DrillRefusal(
            Refusal.WORKSPACE_NOT_UNDER_TEMPORARY_ROOT,
            "the workspace is not under the platform temporary root, so it "
            "cannot be shown to be disposable fixture state")
    if resolved.exists() and any(resolved.iterdir()):
        raise DrillRefusal(
            Refusal.WORKSPACE_NOT_EMPTY,
            "the workspace already holds state this drill did not create")


def write_marker(workspace: pathlib.Path, token: str) -> None:
    rs.write_atomic(
        workspace / MARKER_NAME,
        (json.dumps({"schema": MARKER_SCHEMA, "token": token,
                     "purpose": "R0-10 baseline recovery drill fixture",
                     "production": False}, indent=2, sort_keys=True)
         + "\n").encode(),
    )


def assert_marked(workspace: pathlib.Path, token: str) -> None:
    """Refuse to destroy a directory that is not this run's own fixture."""
    marker = workspace / MARKER_NAME
    if not marker.is_file():
        raise DrillRefusal(
            Refusal.MARKER_MISSING,
            f"{workspace.name} carries no disposable-fixture marker")
    document = json.loads(marker.read_text())
    if document.get("schema") != MARKER_SCHEMA or document.get("token") != token:
        raise DrillRefusal(
            Refusal.MARKER_TOKEN_MISMATCH,
            f"{workspace.name} is marked for a different run")


# ---------------------------------------------------------------------------
# the drill


@dataclass
class Options:
    workspace: pathlib.Path | None = None
    fault: Fault = Fault.NONE
    seed_events: int = SEED_EVENTS
    events_during_backup: int = EVENTS_DURING_BACKUP
    events_after_backup: int = EVENTS_AFTER_BACKUP
    pace_seconds: float = PACE_SECONDS
    inventory: pathlib.Path | None = None


def run(options: Options) -> Report:
    token = secrets.token_hex(8)
    workspace = options.workspace or (
        pathlib.Path(tempfile.gettempdir()) / f"{WORKSPACE_PREFIX}{token}")
    if options.fault is Fault.UNSAFE_WORKSPACE:
        workspace = REPOSITORY_ROOT / "spikes" / "recovery" / "unsafe-workspace"

    report = Report(outcome=Outcome.FAILED, fault=options.fault)
    started: list[tuple[Phase, float]] = []

    def enter(phase: Phase) -> None:
        started.append((phase, time.perf_counter()))

    def leave() -> None:
        phase, at = started.pop()
        report.phases.append({"phase": phase.value,
                              "elapsed_seconds": round(time.perf_counter() - at, 6)})

    enter(Phase.PRECONDITION)
    assert_disposable(workspace)
    workspace.mkdir(parents=True, mode=0o700)
    write_marker(workspace, token)
    leave()

    source_root = workspace / "source"
    backup_root = workspace / "backup"
    target_root = workspace / "target"
    layout = rs.SourceLayout(source_root)
    writer = rs.FixtureWriter(layout)
    source_destroyed = False
    restore_failed: str | None = None
    manifest: rs.BackupManifest | None = None
    lost_events = 0
    rpo_seconds = 0.0
    rto_seconds = 0.0

    try:
        enter(Phase.SEED)
        writer.create()
        writer.commit_batch(options.seed_events)
        leave()

        enter(Phase.BACKUP)
        during = options.events_during_backup

        def concurrent_writes() -> None:
            # Runs while SQLite's online backup holds the source open. The
            # backup restarts because the source changed underneath it, which
            # is exactly the behavior that makes the finished copy one point in
            # time rather than a smear.
            writer.commit_batch(during)

        if options.fault is Fault.NAIVE_BACKUP:
            manifest = rs.take_naive_backup(layout, backup_root,
                                            between_components=concurrent_writes)
        else:
            manifest = rs.take_backup(layout, backup_root,
                                      on_first_page=concurrent_writes)
        leave()

        enter(Phase.LOSS)
        writer.commit_batch(options.events_after_backup,
                            pace_seconds=options.pace_seconds)
        lost_events = writer.events - manifest.watermark_event_id
        loss_ns = time.time_ns()
        writer.close()
        if options.fault is Fault.LEAK_SOURCE:
            # The control needs the source alive; a destroyed source cannot be
            # leaked from, which is half the reason the real procedure destroys
            # it before restoring.
            leaked = source_root / "config.json"
        else:
            assert_marked(workspace, token)
            rs.destroy(source_root)
            source_destroyed = True
            leaked = None
        rpo_seconds = max(0.0, (loss_ns - manifest.watermark_ns) / 1_000_000_000)
        leave()

        enter(Phase.RESTORE)
        restore_started = time.perf_counter()
        try:
            if options.fault is Fault.CRASH_MID_RESTORE:
                target_root.mkdir(parents=True, mode=0o700)
                raise OSError("injected failure part way through the restore")
            rs.restore(backup_root, target_root)
            if leaked is not None:
                rs.write_atomic(target_root / "leaked-from-source.json",
                                leaked.read_bytes())
            if options.fault is Fault.TAMPER_BLOB:
                blob = sorted((target_root / "blobs").rglob("*"))[-1]
                rs.write_atomic(blob, b"tampered")
        except (OSError, ValueError) as error:
            restore_failed = f"{type(error).__name__}: {error}"
        leave()

        enter(Phase.VERIFY)
        if restore_failed is None:
            report.invariants = rs.verify_restored(target_root, manifest)
        rto_seconds = time.perf_counter() - restore_started
        leave()

        enter(Phase.MEASURE)
        report.measurements = build_measurements(rpo_seconds, rto_seconds)
        leave()
    finally:
        enter(Phase.CLEANUP)
        if options.fault is not Fault.SKIP_CLEANUP and workspace.exists():
            assert_marked(workspace, token)
            rs.destroy(workspace)
        report.residue = ([workspace.name] if workspace.exists() else [])
        leave()

    report.findings = list(build_findings(report, restore_failed))
    report.dependency_report = dep.consume(options.inventory)
    for finding in report.dependency_report["findings"]:
        # `FindingCode(...)` raises on a code this report has no room for, so
        # the consumer cannot widen the drill's vocabulary from the outside.
        report.findings.append(Finding(FindingCode(finding["code"]),
                                       finding["subject"], finding["detail"]))
    report.outcome = decide(report, restore_failed)
    report.reproducible = reproducible_view(report, manifest, lost_events,
                                            source_destroyed, options)
    return report


def build_measurements(
    rpo_seconds: float, rto_seconds: float
) -> list[tuple[Measurement, Objective, Comparison, str]]:
    by_id = {o.id: o for o in DECLARED_OBJECTIVES}
    measured = [
        Measurement(
            id="rpo", value_seconds=rpo_seconds, scope=Scope.LOCAL_FIXTURE,
            method="wall-clock nanoseconds between the newest event the backup "
                   "carries and the induced loss of the source"),
        Measurement(
            id="rto", value_seconds=rto_seconds, scope=Scope.LOCAL_FIXTURE,
            method="monotonic seconds from the start of the restore to the end "
                   "of coherence verification, on the already-running host"),
    ]
    out = []
    for measurement in measured:
        objective = by_id[measurement.id]
        comparison, detail = compare_to_objective(measurement, objective)
        out.append((measurement, objective, comparison, detail))
    return out


def build_findings(report: Report, restore_failed: str | None):
    if restore_failed is not None:
        yield Finding(FindingCode.RESTORE_FAILED, "restore", restore_failed)
    for result in report.invariants:
        if not result.ok:
            yield Finding(FindingCode.INVARIANT_VIOLATED,
                          result.invariant.value, result.detail)
    for measurement, objective, comparison, detail in report.measurements:
        if comparison is Comparison.OUT_OF_SCOPE:
            yield Finding(
                FindingCode.OBJECTIVE_COMPARISON_OUT_OF_SCOPE, measurement.id,
                f"measured {measurement.value_seconds:.3f} {objective.unit} at "
                f"scope {measurement.scope.value}; declared objective "
                f"{objective.seconds:.0f} {objective.unit}; not compared "
                f"because {detail}")
        elif comparison is Comparison.MISSED:
            yield Finding(FindingCode.OBJECTIVE_MISSED, measurement.id, detail)
    for dependency in rs.RESTORE_DEPENDENCIES:
        if dependency.exercised is rs.Exercise.NOT_DRILLED:
            yield Finding(FindingCode.DEPENDENCY_NOT_EXERCISED, dependency.id,
                          dependency.note)
    if report.residue:
        yield Finding(FindingCode.RESIDUE_LEFT, "workspace",
                      "fixture state survived the run: " + ", ".join(report.residue))


def decide(report: Report, restore_failed: str | None) -> Outcome:
    if report.residue:
        return Outcome.RESIDUE_LEFT
    if restore_failed is not None:
        return Outcome.FAILED
    if not report.invariants:
        return Outcome.FAILED
    if any(not result.ok for result in report.invariants):
        return Outcome.INCONSISTENT
    if (report.dependency_report.get("refused") is not None
            or report.dependency_report.get("findings")):
        return Outcome.INCOMPLETE
    return Outcome.VERIFIED


def reproducible_view(
    report: Report,
    manifest: rs.BackupManifest | None,
    lost_events: int,
    source_destroyed: bool,
    options: Options,
) -> dict[str, object]:
    """The part of the outcome a rerun must reproduce exactly.

    Wall-clock and monotonic durations, the workspace name and the run token are
    deliberately excluded: they are the parts a rerun cannot reproduce, and
    pretending otherwise would make the rerun check vacuous.
    """
    return {
        "outcome": report.outcome.value,
        "fault": report.fault.value,
        "source_destroyed": source_destroyed,
        "seed_events": options.seed_events,
        "events_during_backup": options.events_during_backup,
        "events_after_backup": options.events_after_backup,
        "watermark_event_id": None if manifest is None else manifest.watermark_event_id,
        "event_count": None if manifest is None else manifest.event_count,
        "artifact_count": None if manifest is None else manifest.artifact_count,
        "config_revision": None if manifest is None else manifest.config_revision,
        "backup_file_count": None if manifest is None else len(manifest.files),
        "lost_events": lost_events,
        "invariants": {r.invariant.value: r.ok for r in report.invariants},
        "finding_codes": sorted({f.code.value for f in report.findings}),
        "residue": report.residue,
        "phases": [entry["phase"] for entry in report.phases],
    }


PROCEDURE = """\
R0-10 baseline recovery drill — procedure

Preconditions, all refused rather than assumed:
  1. the workspace is under the platform temporary root;
  2. the workspace is not inside the live repository, the home directory or the
     filesystem root;
  3. the workspace does not already hold state the drill did not create;
  4. nothing is deleted unless it carries this run's disposable-fixture marker.

Phases and their measurement points:
  precondition  assert disposability, create the marked workspace
  seed          build the synthetic recovery set and commit the seed events
  backup        online SQLite snapshot with a writer committing concurrently;
                the snapshot's newest event id becomes the watermark, and the
                blob set and configuration revision are derived from it
  loss          commit further events (these are the ones the backup does not
                carry), then destroy the source; RPO measurement ends here
  restore       restore into a target directory that did not exist, reading
                only the paths the backup manifest lists; RTO measurement
                starts here
  verify        eight coherence invariants over the restored state
  measure       RPO and RTO in seconds against the declared objectives
  cleanup       remove the marked workspace on success and on failure alike

What a real clean-host drill needs that this one does not have:
"""


def procedure_text() -> str:
    lines = [PROCEDURE]
    for dependency in rs.RESTORE_DEPENDENCIES:
        if dependency.exercised is rs.Exercise.NOT_DRILLED:
            lines.append(f"  {dependency.order}. {dependency.id} "
                         f"({dependency.kind.value}, from "
                         f"{dependency.source.value}) — {dependency.note}")
    lines.append("")
    lines.append("Until those exist, the recovery point and recovery time this "
                 "drill measures are\nreported at scope local_fixture and are "
                 "not compared to the declared objectives.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--fault", default=Fault.NONE.value,
                        choices=[f.value for f in Fault],
                        help="inject a deliberate breakage (test control)")
    parser.add_argument("--workspace", type=pathlib.Path,
                        help="disposable workspace; defaults to a fresh "
                             "directory under the platform temporary root")
    parser.add_argument("--inventory", type=pathlib.Path,
                        help="the R0-09 restore dependency inventory to consume")
    parser.add_argument("--seed-events", type=int, default=SEED_EVENTS)
    parser.add_argument("--events-during-backup", type=int,
                        default=EVENTS_DURING_BACKUP)
    parser.add_argument("--events-after-backup", type=int,
                        default=EVENTS_AFTER_BACKUP)
    parser.add_argument("--procedure", action="store_true",
                        help="print the procedure and exit, touching nothing")
    arguments = parser.parse_args(argv)

    if arguments.procedure:
        print(procedure_text())
        return 0

    options = Options(
        workspace=arguments.workspace,
        fault=Fault(arguments.fault),
        seed_events=arguments.seed_events,
        events_during_backup=arguments.events_during_backup,
        events_after_backup=arguments.events_after_backup,
        inventory=arguments.inventory,
    )
    try:
        report = run(options)
    except DrillRefusal as refusal:
        report = Report(outcome=Outcome.REFUSED, fault=options.fault,
                        refusal=refusal.refusal, refusal_detail=refusal.detail)
    print(json.dumps(report.as_document(), indent=2, sort_keys=True))
    return EXIT_CODE[report.outcome]


if __name__ == "__main__":
    sys.exit(main())
