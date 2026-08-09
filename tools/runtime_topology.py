#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Verify the R0-05 runtime-topology decision and its evidence binding."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_DECISION = ROOT / "plan/decisions/R0-05-runtime-topology.json"
DEFAULT_EVIDENCE = ROOT / "plan/evidence/R0-03.json"
SCHEMA = "automonique.runtime-topology-decision/v1"

ADAPTER_IDS = {"direct-process", "systemd", "launchd", "container"}
CAPABILITIES = {
    "activation",
    "restart",
    "resource_accounting",
    "readiness_translation",
    "credential_injection",
}
CORE_CONTRACTS = {
    "explicit-argv-spawn",
    "typed-start-and-readiness",
    "epoch-fenced-single-owner-activation",
    "bounded-quiesce-and-drain",
    "typed-or-signal-shutdown",
    "isolated-descendant-cleanup",
}
FAILURE_IDS = {"pre-ready", "post-ready", "drain-timeout", "restart-ownership"}
OBSERVED_FAILURES = {"pre-ready", "post-ready"}
CAPABILITY_STATUSES = {"measured", "not-required", "unmeasured"}


class TopologyError(Exception):
    """A topology decision or its bound evidence is invalid."""


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise TopologyError(f"cannot read {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise TopologyError(f"{path} root is not an object")
    return document


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def semantic_errors(
    decision: dict[str, Any], evidence: dict[str, Any], evidence_digest: str
) -> list[str]:
    errors: list[str] = []

    if decision.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA}")
    if decision.get("work_item") != "R0-05":
        errors.append("work_item must be R0-05")

    source = decision.get("source_evidence")
    if not isinstance(source, dict):
        return errors + ["source_evidence must be an object"]
    if source.get("path") != "plan/evidence/R0-03.json":
        errors.append("source evidence path must name plan/evidence/R0-03.json")
    if source.get("sha256") != evidence_digest:
        errors.append("source evidence SHA-256 differs from the current R0-03 evidence")
    if evidence.get("item") != "R0-03":
        errors.append("bound evidence must belong to R0-03")
    if source.get("base") != evidence.get("base"):
        errors.append("source evidence base differs from R0-03")
    environment = source.get("environment")
    if not isinstance(environment, dict):
        errors.append("source environment must be an object")
    else:
        if environment.get("process_mode") != "direct-foreground":
            errors.append("source process mode must be direct-foreground")
        if environment.get("service_manager") is not None:
            errors.append("R0-03 source environment must not claim a service manager")
        if not isinstance(environment.get("kernel"), str) or not environment["kernel"]:
            errors.append("source kernel must be recorded")
        if not isinstance(environment.get("python"), str) or not environment["python"]:
            errors.append("source Python version must be recorded")
        timeout = environment.get("timeout_seconds")
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            errors.append("source timeout must be positive")

    baseline = decision.get("baseline")
    if not isinstance(baseline, dict):
        errors.append("baseline must be an object")
    else:
        if baseline.get("id") != "direct-process":
            errors.append("direct-process must be the baseline")
        if baseline.get("required_for_core") is not True:
            errors.append("direct-process must be required for core")
        if baseline.get("self_daemonizes") is not False:
            errors.append("the baseline must not self-daemonize")
        if set(baseline.get("core_contracts", [])) != CORE_CONTRACTS:
            errors.append("baseline core contracts are incomplete or invented")

    adapters = decision.get("adapters")
    if not isinstance(adapters, list):
        errors.append("adapters must be a list")
        adapters = []
    adapter_by_id = {
        adapter.get("id"): adapter
        for adapter in adapters
        if isinstance(adapter, dict) and isinstance(adapter.get("id"), str)
    }
    if len(adapter_by_id) != len(adapters):
        errors.append("adapter IDs must be unique strings")
    if set(adapter_by_id) != ADAPTER_IDS:
        errors.append("adapter matrix must contain direct-process, systemd, launchd, and container")
    for adapter_id, adapter in adapter_by_id.items():
        required = adapter.get("required_for_core")
        if required is not (adapter_id == "direct-process"):
            errors.append(f"{adapter_id} has an invalid core requirement")
        expected_recommendation = (
            "portable-baseline" if adapter_id == "direct-process" else "optional-unproven"
        )
        if adapter.get("recommendation") != expected_recommendation:
            errors.append(f"{adapter_id} recommendation must be {expected_recommendation}")
        capabilities = adapter.get("capabilities")
        if not isinstance(capabilities, dict) or set(capabilities) != CAPABILITIES:
            errors.append(f"{adapter_id} capability fields are incomplete or invented")
            continue
        for name, claim in capabilities.items():
            if not isinstance(claim, dict):
                errors.append(f"{adapter_id}.{name} must be an object")
                continue
            status = claim.get("status")
            if status not in CAPABILITY_STATUSES:
                errors.append(f"{adapter_id}.{name} has invalid status {status!r}")
            if status == "measured" and not claim.get("evidence"):
                errors.append(f"{adapter_id}.{name} measured status needs evidence")
            if status != "measured" and not claim.get("reason"):
                errors.append(f"{adapter_id}.{name} {status} status needs a reason")
            if adapter_id != "direct-process" and status == "measured":
                errors.append(f"{adapter_id}.{name} cannot claim measurement from R0-03")

    failures = decision.get("failure_behavior")
    if not isinstance(failures, list):
        errors.append("failure_behavior must be a list")
        failures = []
    failure_by_id = {
        failure.get("id"): failure
        for failure in failures
        if isinstance(failure, dict) and isinstance(failure.get("id"), str)
    }
    if len(failure_by_id) != len(failures):
        errors.append("failure IDs must be unique strings")
    if set(failure_by_id) != FAILURE_IDS:
        errors.append("failure behavior must define pre-ready, post-ready, drain-timeout, and restart-ownership")
    for failure_id, failure in failure_by_id.items():
        expected_observed = failure_id in OBSERVED_FAILURES
        if failure.get("observed") is not expected_observed:
            errors.append(f"{failure_id} observed state differs from R0-03")
        if not expected_observed and not failure.get("reason"):
            errors.append(f"{failure_id} unmeasured behavior needs a reason")
        if not failure.get("owner_outcome"):
            errors.append(f"{failure_id} needs an owner outcome")
        if failure.get("allows_dual_active") is not False:
            errors.append(f"{failure_id} must prohibit dual active owners")

    portability = decision.get("portability")
    if not isinstance(portability, dict):
        errors.append("portability must be an object")
    else:
        if portability.get("core_requires_adapter_features") is not False:
            errors.append("core operation must not require adapter features")
        if portability.get("unsupported_adapter_behavior") != "run the direct foreground baseline":
            errors.append("unsupported adapters must fall back to the direct foreground baseline")
        if not portability.get("adapter_contract"):
            errors.append("adapter translation contract must be recorded")

    revisit = decision.get("revisit_rule")
    if not isinstance(revisit, dict):
        errors.append("revisit_rule must be an object")
    else:
        lower_bounds = {
            "minimum_supported_environments": 2,
            "consecutive_passes_per_environment": 30,
            "injections_per_failure_mode": 10,
        }
        for field, minimum in lower_bounds.items():
            value = revisit.get(field)
            if not isinstance(value, int) or value < minimum:
                errors.append(f"revisit {field} must be at least {minimum}")
        for field in ("maximum_ownership_violations", "maximum_orphaned_processes"):
            if revisit.get(field) != 0:
                errors.append(f"revisit {field} must be zero")
        for field in ("requires_measured_operational_benefit", "requires_direct_fallback"):
            if revisit.get(field) is not True:
                errors.append(f"revisit {field} must be true")
        if not revisit.get("required_benefit_examples") or not revisit.get("decision"):
            errors.append("revisit rule needs benefit examples and a bounded decision")

    risks = decision.get("unresolved_risks")
    if not isinstance(risks, list) or not risks:
        errors.append("unresolved risks must be recorded")
    else:
        for risk in risks:
            if not isinstance(risk, dict) or risk.get("status") != "unmeasured" or not risk.get("reason"):
                errors.append("each unresolved risk must be unmeasured with a reason")
    return errors


def verify(
    decision_path: pathlib.Path = DEFAULT_DECISION,
    evidence_path: pathlib.Path = DEFAULT_EVIDENCE,
) -> list[str]:
    decision = load_json(decision_path)
    evidence = load_json(evidence_path)
    return semantic_errors(decision, evidence, digest(evidence_path))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--decision", type=pathlib.Path, default=DEFAULT_DECISION)
    parser.add_argument("--evidence", type=pathlib.Path, default=DEFAULT_EVIDENCE)
    args = parser.parse_args()
    if not args.verify:
        parser.error("--verify is required")
    try:
        errors = verify(args.decision, args.evidence)
    except TopologyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print("ok — direct foreground baseline; 3 optional adapters; 4 failure outcomes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
