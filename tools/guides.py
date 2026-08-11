#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Generate and verify R0-18 development guides and work objectives."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools import program  # noqa: E402

GUIDE_DIR = ROOT / ".automonique/dev/guides"
GUIDE_MANIFEST = GUIDE_DIR / "manifest.json"
OBJECTIVE_SCHEMA = ROOT / ".automonique/dev/objectives.schema.json"
OBJECTIVES = ROOT / ".automonique/dev/objectives.json"
LOOP_CONFIG = ROOT / ".automonique/dev/loop.json"

GUIDE_SCHEMA = "automonique.dev-guides/v1"
OBJECTIVE_SCHEMA_ID = "automonique.dev-objectives/v1"
LOOP_SCHEMA = "automonique.dev-loop/v1"
HILL_THRESHOLD = 70

OBJECTIVE_FIELDS = (
    "id",
    "work_id",
    "objective",
    "metric",
    "baseline",
    "budget",
    "tests",
    "stop_conditions",
    "hill_climbability",
    "autonomous_eligible",
    "allowed_paths",
    "licence",
    "sources",
)

GUIDES: tuple[dict[str, Any], ...] = (
    {
        "id": "clean-room-porting",
        "title": "Clean-room porting",
        "sources": [
            "AGENTS.md",
            "docs/product-plan/reference/migration-plan.md",
            "PROVENANCE.md",
        ],
        "rules": [
            ("prior-source-access", "forbid", "Do not read, mount, clone, search, quote, paraphrase, or reconstruct prior implementation source."),
            ("permitted-input-provenance", "require", "Cite a permitted specification, public standard, structural reference, or provenance-bound black-box fixture for every behavior claim."),
            ("structural-reference-boundary", "require", "Use structural references only to locate ownership and migration destinations, never to infer the implementation behind them."),
        ],
    },
    {
        "id": "state-machines",
        "title": "State machines and recovery",
        "sources": [
            "docs/product-plan/requirements/state-and-protocols.md",
            "docs/product-plan/requirements/reload-protocol.md",
        ],
        "rules": [
            ("typed-transitions", "require", "Represent lifecycle changes as named typed transitions with invalid-state rejection."),
            ("durable-fencing", "require", "Bind ownership-changing transitions to durable identities or epochs and prove at most one active owner."),
            ("restart-evidence", "require", "Test the failure and restart boundaries named by the work contract, including cleanup and replay outcomes."),
        ],
    },
    {
        "id": "security-boundaries",
        "title": "Security and authority boundaries",
        "sources": [
            "docs/product-plan/requirements/goals-and-invariants.md",
            "docs/product-plan/requirements/sandbox-management.md",
        ],
        "rules": [
            ("least-authority", "require", "Grant only the paths, commands, network, credentials, resources, and external effects declared by the work unit."),
            ("credential-output", "forbid", "Do not place credential values in argv, logs, manifests, evidence, fixtures, or committed files."),
            ("typed-command-boundary", "require", "Execute approved argument vectors or typed APIs; never construct a shell command from model output."),
        ],
    },
    {
        "id": "naming",
        "title": "Naming and compatibility",
        "sources": [
            "docs/product-plan/requirements/target-architecture.md",
            "docs/product-plan/reference/migration-plan.md",
        ],
        "rules": [
            ("canonical-owner", "require", "Resolve canonical and compatibility names to one runtime owner and one durable identity."),
            ("compatibility-behavior", "require", "Keep compatibility entry points as forwarding or codec boundaries without duplicate domain behavior."),
            ("unapproved-rename", "forbid", "Do not rename durable identifiers or compatibility surfaces without an explicit migration contract."),
        ],
    },
    {
        "id": "test-preservation",
        "title": "Test and evidence preservation",
        "sources": [
            "docs/product-plan/requirements/verification-and-rollout.md",
            "plan/doctrine.md",
        ],
        "rules": [
            ("test-silencing", "forbid", "Do not delete, skip, ignore, weaken, stub, bulk-refresh, or broadly suppress a test to make a gate pass."),
            ("failure-paths", "require", "Exercise the contract's negative, restart, cleanup, compatibility, and fault paths rather than compilation alone."),
            ("truthful-review", "require", "Record the actual reviewer count and never claim independence for the implementing context."),
        ],
    },
    {
        "id": "metrics",
        "title": "Metrics, baselines, and budgets",
        "sources": [
            "docs/product-plan/requirements/ai-implementation-harness.md",
            "docs/product-plan/requirements/goals-and-invariants.md",
        ],
        "rules": [
            ("missing-metric", "require", "Represent unavailable or incomparable measurements as null with a reason, never as zero or pass."),
            ("judging-contract", "forbid", "Do not change the metric, baseline, test, policy, licence, or budget used to judge the same work unit."),
            ("descriptive-volume", "require", "Treat lines, commits, tokens, cost, calls, and agent count as descriptive rather than correctness rewards."),
        ],
    },
)


class GuideError(Exception):
    """A guide, objective, or generated artifact is invalid."""


def json_bytes(document: Any) -> bytes:
    return (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode()


def section(text: str, heading: str) -> str:
    match = re.search(
        rf"^## {re.escape(heading)}\s*$\n(.*?)(?=^## |\Z)", text, re.MULTILINE | re.DOTALL
    )
    if not match:
        raise GuideError(f"missing section {heading!r}")
    return match.group(1).strip()


def optional_section(text: str, heading: str) -> str | None:
    try:
        return section(text, heading)
    except GuideError:
        return None


def first_paragraph(body: str) -> str:
    paragraphs = [part.strip() for part in re.split(r"\n\s*\n", body) if part.strip()]
    if not paragraphs:
        raise GuideError("objective section is empty")
    return " ".join(line.strip() for line in paragraphs[0].splitlines())


def verification_checks(body: str) -> list[str]:
    checks: list[str] = []
    separator_seen = False
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if set("".join(cells)) <= set("-: "):
            separator_seen = True
            continue
        if separator_seen and cells and cells[0]:
            checks.append(cells[0].strip("`"))
    if not checks:
        raise GuideError("verification contract has no checks")
    return checks


def stop_conditions(body: str) -> list[str]:
    bullets = [line.strip()[2:].strip() for line in body.splitlines() if line.strip().startswith("- ")]
    if bullets:
        return bullets
    normalized = " ".join(line.strip() for line in body.splitlines() if line.strip())
    return [normalized] if normalized else []


def contract_score(text: str) -> int:
    match = re.search(r"\| Hill-climbability \|\s*(\d+)\s+—", text)
    if not match:
        raise GuideError("contract has no hill-climbability score")
    score = int(match.group(1))
    if not 0 <= score <= 100:
        raise GuideError(f"hill-climbability score {score} is outside 0..100")
    return score


def render_guide(guide: dict[str, Any]) -> bytes:
    lines = [
        "<!-- SPDX-License-Identifier: Elastic-2.0 -->",
        "",
        f"# {guide['title']}",
        "",
        "Generated by `tools/guides.py`; edit the generator, not this file.",
        "",
        "## Sources",
        "",
    ]
    lines.extend(f"- [`{source}`](../../../{source})" for source in guide["sources"])
    lines.extend(["", "## Enforced rules", ""])
    for rule_id, effect, statement in guide["rules"]:
        lines.append(f"- `{rule_id}` — **{effect}**: {statement}")
    lines.append("")
    return "\n".join(lines).encode()


def build_guides() -> tuple[dict[str, Any], dict[pathlib.Path, bytes]]:
    files: dict[pathlib.Path, bytes] = {}
    entries: list[dict[str, Any]] = []
    for guide in GUIDES:
        path = GUIDE_DIR / f"{guide['id']}.md"
        rendered = render_guide(guide)
        files[path] = rendered
        rules = []
        for rule_id, effect, statement in guide["rules"]:
            rules.append(
                {
                    "id": rule_id,
                    "subject": rule_id,
                    "effect": effect,
                    "statement": statement,
                    "location": f".automonique/dev/guides/{guide['id']}.md#{rule_id}",
                }
            )
        entries.append(
            {
                "id": guide["id"],
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(rendered).hexdigest(),
                "sources": list(guide["sources"]),
                "rules": rules,
            }
        )
    manifest = {
        "schema": GUIDE_SCHEMA,
        "hill_climbability_threshold": HILL_THRESHOLD,
        "guides": entries,
    }
    files[GUIDE_MANIFEST] = json_bytes(manifest)
    return manifest, files


def build_objective_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": OBJECTIVE_SCHEMA_ID,
        "type": "object",
        "additionalProperties": False,
        "required": ["schema", "objectives"],
        "properties": {
            "schema": {"const": OBJECTIVE_SCHEMA_ID},
            "objectives": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": list(OBJECTIVE_FIELDS),
                    "properties": {
                        "id": {"type": "string"},
                        "work_id": {"type": "string"},
                        "objective": {"type": "string"},
                        "metric": {
                            "type": "object",
                            "required": ["name", "target", "anti_regression"],
                        },
                        "baseline": {
                            "type": "object",
                            "required": ["value", "reason"],
                        },
                        "budget": {
                            "type": "object",
                            "required": [
                                "max_iterations",
                                "max_wall_seconds",
                                "max_worker_seconds",
                                "max_unchanged_results",
                                "max_failures",
                            ],
                        },
                        "tests": {"type": "array", "minItems": 1},
                        "stop_conditions": {"type": "array", "minItems": 1},
                        "hill_climbability": {"type": "integer", "minimum": 0, "maximum": 100},
                        "autonomous_eligible": {"type": "boolean"},
                        "allowed_paths": {"type": "array", "minItems": 1},
                        "licence": {"type": "string"},
                        "sources": {"type": "array", "minItems": 1},
                    },
                },
            },
        },
    }


def build_objectives(program_document: dict[str, Any]) -> dict[str, Any]:
    objectives: list[dict[str, Any]] = []
    for item in program_document["items"]:
        contract_ref = item.get("contract")
        if contract_ref is None:
            continue
        contract_path = ROOT / contract_ref
        try:
            text = contract_path.read_text()
        except OSError as exc:
            raise GuideError(f"cannot read {contract_ref}: {exc}") from exc
        score = contract_score(text)
        checks = verification_checks(section(text, "Verification contract"))
        stops = [
            "Stop if the immutable base, dependency, gate, contract, or allowed-path lease differs from the admitted packet.",
            "Stop if a required check fails and the next correction is outside the declared paths or authority.",
            "Stop when an iteration, wall-time, worker-time, unchanged-result, or failure budget is reached.",
        ]
        specific_stops = optional_section(text, "Stop conditions")
        if specific_stops is not None:
            stops.extend(stop_conditions(specific_stops))
        objectives.append(
            {
                "id": f"objective:{item['id']}",
                "work_id": item["id"],
                "objective": first_paragraph(section(text, "Objective")),
                "metric": {
                    "name": "required_contract_checks_passed",
                    "target": len(checks),
                    "anti_regression": "zero required checks failing, skipped, deleted, weakened, or omitted",
                },
                "baseline": {
                    "value": None,
                    "reason": "measure the immutable attempt base before mutation",
                },
                "budget": {
                    "max_iterations": 3,
                    "max_wall_seconds": 1800,
                    "max_worker_seconds": 1200,
                    "max_unchanged_results": 1,
                    "max_failures": 2,
                },
                "tests": checks,
                "stop_conditions": stops,
                "hill_climbability": score,
                "autonomous_eligible": score >= HILL_THRESHOLD,
                "allowed_paths": item["allowed_paths"],
                "licence": item["licence"],
                "sources": [contract_ref, "docs/product-plan/reference/work-breakdown.md"],
            }
        )
    return {"schema": OBJECTIVE_SCHEMA_ID, "objectives": objectives}


def build_loop_config() -> dict[str, Any]:
    return {
        "schema": LOOP_SCHEMA,
        # Two ceilings, because they answer two questions. Both used to be
        # called `integration_ceiling`, and this comment used to say "stamped
        # into every packet" of the repository one — which is how the loop came
        # to write packets that `program.rs` refused on sight.
        #
        # What the loop may do to the repository: under
        # `autonomous-protected-integration` a verified candidate reaches
        # `origin/main` by non-force fast-forward without owner sign-off.
        # Release signing, package publication and production deployment stay
        # outside this ceiling.
        "repository_integration_ceiling": "verified_fast_forward_main",
        # What a candidate session may do with its own work. This is the one
        # stamped into every packet, and `program.rs` requires exactly it.
        "session_integration_ceiling": "proposal_only",
        "max_workers": 1,
        "default_driver": "codex_session",
        "drivers": {
            "codex_session": {
                "native_subagents": True,
                "max_concurrent_subagents": 3,
                "recursive_agent_trees": False,
                "concurrent_writes": "disjoint_paths_only",
                "integration_owner": "primary_session",
            },
            "local_process": {
                "max_workers": 1,
                "packet_transport": "final_explicit_argv_element",
            },
        },
        "hill_climbability_threshold": HILL_THRESHOLD,
        "state_path": ".automonique/state/harness-loop.json",
        "worker_sandbox": {
            "binary": "bwrap",
            "network": "none",
            "home": "hidden",
            "git_metadata": "hidden",
            "writable_paths": "objective_allowed_paths_only",
        },
        "safety_checks": [
            ["python3", "plan/check.py", "--verify"],
            ["python3", "tools/program.py", "--verify"],
            ["python3", "tools/guides.py", "--verify"],
        ],
        "forbidden_git_operations": [
            "branch-change",
            "merge",
            "push",
            "force",
            "history-rewrite",
            "remote-edit",
            "tag",
        ],
    }


def contradictions(manifest: dict[str, Any]) -> list[str]:
    seen: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for guide in manifest.get("guides", []):
        for rule in guide.get("rules", []):
            prior = seen.get(rule.get("subject"))
            if prior is not None and prior.get("effect") != rule.get("effect"):
                errors.append(
                    f"contradictory rule {rule.get('subject')}: "
                    f"{prior.get('location')} says {prior.get('effect')}; "
                    f"{rule.get('location')} says {rule.get('effect')}"
                )
            else:
                seen[rule.get("subject")] = rule
    return errors


def validate_guides(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    expected = {guide["id"] for guide in GUIDES}
    guides = manifest.get("guides")
    if manifest.get("schema") != GUIDE_SCHEMA or not isinstance(guides, list):
        return ["guide manifest schema or guide list is invalid"]
    actual = {guide.get("id") for guide in guides if isinstance(guide, dict)}
    if actual != expected or len(guides) != len(expected):
        errors.append("guide manifest must contain each of the six required families exactly once")
    if manifest.get("hill_climbability_threshold") != HILL_THRESHOLD:
        errors.append(f"guide threshold must be {HILL_THRESHOLD}")
    for guide in guides:
        if not isinstance(guide, dict):
            errors.append("guide entry must be an object")
            continue
        for source in guide.get("sources", []):
            if not (ROOT / source).is_file():
                errors.append(f"guide {guide.get('id')} source does not exist: {source}")
        if not guide.get("rules"):
            errors.append(f"guide {guide.get('id')} has no enforceable rules")
    errors.extend(contradictions(manifest))
    return errors


def validate_objectives(
    document: dict[str, Any], program_document: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    if document.get("schema") != OBJECTIVE_SCHEMA_ID:
        errors.append(f"objective schema must be {OBJECTIVE_SCHEMA_ID}")
    entries = document.get("objectives")
    if not isinstance(entries, list):
        return errors + ["objectives must be a list"]
    by_id: dict[str, dict[str, Any]] = {}
    for objective in entries:
        if not isinstance(objective, dict):
            errors.append("objective entry must be an object")
            continue
        work_id = objective.get("work_id")
        if not isinstance(work_id, str) or work_id in by_id:
            errors.append(f"objective work ID is missing or duplicated: {work_id!r}")
            continue
        by_id[work_id] = objective
        missing = [field for field in OBJECTIVE_FIELDS if field not in objective]
        unknown = sorted(set(objective) - set(OBJECTIVE_FIELDS))
        if missing:
            errors.append(f"{work_id} objective missing fields: {', '.join(missing)}")
        if unknown:
            errors.append(f"{work_id} objective has unknown fields: {', '.join(unknown)}")
        score = objective.get("hill_climbability")
        if not isinstance(score, int) or not 0 <= score <= 100:
            errors.append(f"{work_id} hill-climbability must be an integer in 0..100")
        elif objective.get("autonomous_eligible") is not (score >= HILL_THRESHOLD):
            errors.append(
                f"{work_id} autonomous eligibility contradicts score {score} at threshold {HILL_THRESHOLD}"
            )
        metric = objective.get("metric")
        if not isinstance(metric, dict) or not {
            "name", "target", "anti_regression"
        }.issubset(metric):
            errors.append(f"{work_id} metric is incomplete")
        baseline = objective.get("baseline")
        if not isinstance(baseline, dict) or "value" not in baseline or not baseline.get("reason"):
            errors.append(f"{work_id} baseline must include value and reason")
        budget = objective.get("budget")
        required_budget = {
            "max_iterations",
            "max_wall_seconds",
            "max_worker_seconds",
            "max_unchanged_results",
            "max_failures",
        }
        if not isinstance(budget, dict) or not required_budget.issubset(budget):
            errors.append(f"{work_id} budget is incomplete")
        if not objective.get("tests"):
            errors.append(f"{work_id} has no tests")
        if not objective.get("stop_conditions"):
            errors.append(f"{work_id} has no stop conditions")
    runnable = {
        item["id"] for item in program_document.get("items", []) if item.get("runnable")
    }
    for work_id in sorted(runnable - set(by_id)):
        errors.append(f"runnable program node {work_id} has no objective")
    return errors


def expected_files() -> tuple[dict[str, Any], dict[str, Any], dict[pathlib.Path, bytes]]:
    program_document = program.parse_program(program.DEFAULT_PROGRAM.read_bytes())
    guide_manifest, files = build_guides()
    objectives = build_objectives(program_document)
    files[OBJECTIVE_SCHEMA] = json_bytes(build_objective_schema())
    files[OBJECTIVES] = json_bytes(objectives)
    files[LOOP_CONFIG] = json_bytes(build_loop_config())
    return guide_manifest, objectives, files


def verify() -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    guide_manifest, objectives, files = expected_files()
    program_document = program.parse_program(program.DEFAULT_PROGRAM.read_bytes())
    errors = validate_guides(guide_manifest)
    errors.extend(validate_objectives(objectives, program_document))
    for path, expected in files.items():
        try:
            actual = path.read_bytes()
        except OSError as exc:
            errors.append(f"cannot read generated file {path.relative_to(ROOT)}: {exc}")
            continue
        if actual != expected:
            errors.append(f"generated file differs: {path.relative_to(ROOT)}")
    return guide_manifest, objectives, errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--stdout", action="store_true")
    args = parser.parse_args()
    if args.verify and args.stdout:
        parser.error("choose at most one of --verify and --stdout")
    try:
        guide_manifest, objectives, files = expected_files()
        errors = validate_guides(guide_manifest)
        errors.extend(
            validate_objectives(
                objectives, program.parse_program(program.DEFAULT_PROGRAM.read_bytes())
            )
        )
    except (GuideError, program.ProgramError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.stdout:
        sys.stdout.buffer.write(json_bytes({"guides": guide_manifest, "objectives": objectives}))
        return 0
    if args.verify:
        _, _, drift = verify()
        errors.extend(drift)
        errors = list(dict.fromkeys(errors))
        if errors:
            for error in errors:
                print(f"error: {error}", file=sys.stderr)
            return 1
    else:
        for path, content in files.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        print(f"wrote {len(files)} guide/objective artifacts")
    runnable = sum(
        bool(item["runnable"])
        for item in program.parse_program(program.DEFAULT_PROGRAM.read_bytes())["items"]
    )
    eligible = sum(
        objective["autonomous_eligible"] for objective in objectives["objectives"]
    )
    print(
        f"ok — {len(guide_manifest['guides'])} guides, "
        f"{len(objectives['objectives'])} objectives, {runnable} runnable, "
        f"{eligible} score-eligible"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
