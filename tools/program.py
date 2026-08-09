#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Generate and verify the implementation-harness program.

The output is JSON syntax with a YAML SPDX comment. JSON is a YAML 1.2 subset,
which keeps the checked artifact dependency-free and exactly reproducible.

    python3 tools/program.py
    python3 tools/program.py --stdout
    python3 tools/program.py --verify
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import tomllib
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_GRAPH = ROOT / "plan/work-graph.toml"
DEFAULT_CONTRACTS = ROOT / "plan/contracts"
DEFAULT_PROGRAM = ROOT / ".automonique/dev/program.yaml"
SCHEMA = "automonique.dev-program/v1"
HEADER = "# SPDX-License-Identifier: Elastic-2.0\n"

PROGRAM_FIELDS = (
    "id",
    "epic",
    "track",
    "title",
    "summary",
    "depends_on",
    "blocked_by_gates",
    "licence",
    "allowed_paths",
    "closes_gate",
    "status",
    "contract",
    "runnable",
)


class ProgramError(Exception):
    """An invalid graph or generated program."""


def read_graph(path: pathlib.Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            graph = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ProgramError(f"cannot read graph {path}: {exc}") from exc
    items = graph.get("item")
    if not isinstance(items, list):
        raise ProgramError("source graph has no item list")
    if graph.get("item_count") != len(items):
        raise ProgramError(
            f"source item_count is {graph.get('item_count')}, parsed {len(items)}"
        )
    return graph


def validate_graph(items: list[dict[str, Any]]) -> None:
    ids = [item.get("id") for item in items]
    if any(not isinstance(item_id, str) or not item_id for item_id in ids):
        raise ProgramError("every source item needs a non-empty string ID")
    duplicates = sorted({item_id for item_id in ids if ids.count(item_id) > 1})
    if duplicates:
        raise ProgramError("duplicate source item(s): " + ", ".join(duplicates))
    known = set(ids)
    for item in items:
        for dependency in item.get("depends_on", []):
            if dependency not in known:
                raise ProgramError(f"{item['id']} depends on unknown item {dependency}")


def graph_digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def contract_reference(item_id: str, contracts: pathlib.Path) -> str | None:
    contract = contracts / f"{item_id}.md"
    if not contract.is_file():
        return None
    heading = contract.read_text().splitlines()[:1]
    if not heading or not heading[0].startswith(f"# {item_id} "):
        raise ProgramError(f"contract {contract} does not start with '# {item_id} '")
    try:
        return contract.relative_to(ROOT).as_posix()
    except ValueError:
        return contract.as_posix()


def build_document(
    graph_path: pathlib.Path = DEFAULT_GRAPH,
    contracts: pathlib.Path = DEFAULT_CONTRACTS,
) -> dict[str, Any]:
    graph = read_graph(graph_path)
    items: list[dict[str, Any]] = graph["item"]
    validate_graph(items)
    done = {item["id"] for item in items if item.get("status") == "done"}
    closed_gates = {
        item["closes_gate"]
        for item in items
        if item.get("status") == "done" and item.get("closes_gate")
    }

    output_items = []
    for source in items:
        item_id = source["id"]
        dependency_ids = list(source.get("depends_on", []))
        blocking_gates = list(source.get("blocked_by_gates", []))
        contract = contract_reference(item_id, contracts)
        runnable = (
            source.get("status") != "done"
            and contract is not None
            and all(dependency in done for dependency in dependency_ids)
            and all(gate in closed_gates for gate in blocking_gates)
        )
        output_items.append(
            {
                "id": item_id,
                "epic": source["epic"],
                "track": source["track"],
                "title": source["title"],
                "summary": source.get("summary"),
                "depends_on": dependency_ids,
                "blocked_by_gates": blocking_gates,
                "licence": source["licence"],
                "allowed_paths": list(source.get("allowed_paths", [])),
                "closes_gate": source.get("closes_gate"),
                "status": source["status"],
                "contract": contract,
                "runnable": runnable,
            }
        )

    return {
        "schema": SCHEMA,
        "source": {
            "graph": "plan/work-graph.toml",
            "graph_sha256": graph_digest(graph_path),
            "item_count": len(items),
        },
        "items": output_items,
    }


def render_document(document: dict[str, Any]) -> bytes:
    body = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    return (HEADER + body).encode()


def generate(
    graph_path: pathlib.Path = DEFAULT_GRAPH,
    contracts: pathlib.Path = DEFAULT_CONTRACTS,
) -> bytes:
    return render_document(build_document(graph_path, contracts))


def parse_program(data: bytes) -> dict[str, Any]:
    try:
        text = data.decode()
    except UnicodeDecodeError as exc:
        raise ProgramError("generated program is not UTF-8") from exc
    if not text.startswith(HEADER):
        raise ProgramError("generated program is missing the Elastic-2.0 SPDX header")
    try:
        document = json.loads(text[len(HEADER):])
    except json.JSONDecodeError as exc:
        raise ProgramError(f"generated program is not JSON-compatible YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise ProgramError("generated program root is not an object")
    return document


def semantic_errors(expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if actual.get("schema") != SCHEMA:
        errors.append(f"schema is {actual.get('schema')!r}, expected {SCHEMA!r}")
    if actual.get("source") != expected["source"]:
        errors.append("source metadata differs from plan/work-graph.toml")

    actual_items = actual.get("items")
    if not isinstance(actual_items, list):
        return errors + ["generated program has no item list"]
    actual_ids = [item.get("id") for item in actual_items if isinstance(item, dict)]
    duplicates = sorted({item_id for item_id in actual_ids if actual_ids.count(item_id) > 1})
    for item_id in duplicates:
        errors.append(f"duplicate generated item {item_id}")

    expected_by_id = {item["id"]: item for item in expected["items"]}
    actual_by_id = {
        item["id"]: item
        for item in actual_items
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    for item_id in sorted(expected_by_id.keys() - actual_by_id.keys()):
        errors.append(f"source-only item {item_id}")
    for item_id in sorted(actual_by_id.keys() - expected_by_id.keys()):
        errors.append(f"generated-only item {item_id}")
    for item_id in sorted(expected_by_id.keys() & actual_by_id.keys()):
        expected_item = expected_by_id[item_id]
        actual_item = actual_by_id[item_id]
        unknown = sorted(set(actual_item) - set(PROGRAM_FIELDS))
        if unknown:
            errors.append(f"item {item_id} has unknown field(s): {', '.join(unknown)}")
        for field in PROGRAM_FIELDS:
            if actual_item.get(field) != expected_item[field]:
                errors.append(f"item {item_id} field {field} differs from source")
    if actual_ids != [item["id"] for item in expected["items"]]:
        errors.append("generated item ordering differs from source graph")
    return errors


def verify(
    graph_path: pathlib.Path = DEFAULT_GRAPH,
    contracts: pathlib.Path = DEFAULT_CONTRACTS,
    program_path: pathlib.Path = DEFAULT_PROGRAM,
) -> tuple[dict[str, Any], list[str]]:
    expected = build_document(graph_path, contracts)
    try:
        actual = parse_program(program_path.read_bytes())
    except OSError as exc:
        raise ProgramError(f"cannot read generated program {program_path}: {exc}") from exc
    errors = semantic_errors(expected, actual)
    if not errors and program_path.read_bytes() != render_document(expected):
        errors.append("generated bytes are not canonical; run tools/program.py")
    return expected, errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--stdout", action="store_true")
    parser.add_argument("--graph", type=pathlib.Path, default=DEFAULT_GRAPH)
    parser.add_argument("--contracts", type=pathlib.Path, default=DEFAULT_CONTRACTS)
    parser.add_argument("--program", type=pathlib.Path, default=DEFAULT_PROGRAM)
    args = parser.parse_args()

    try:
        if args.verify:
            document, errors = verify(args.graph, args.contracts, args.program)
            if errors:
                for error in errors:
                    print(f"error: {error}", file=sys.stderr)
                return 1
            edges = sum(len(item["depends_on"]) for item in document["items"])
            runnable = sum(bool(item["runnable"]) for item in document["items"])
            print(
                f"ok — {len(document['items'])} nodes, {edges} edges, "
                f"{runnable} runnable"
            )
            return 0

        output = generate(args.graph, args.contracts)
        if args.stdout:
            sys.stdout.buffer.write(output)
        else:
            args.program.parent.mkdir(parents=True, exist_ok=True)
            args.program.write_bytes(output)
            print(f"wrote {args.program.relative_to(ROOT)}")
        return 0
    except ProgramError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
