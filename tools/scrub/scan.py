#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Scan tracked blobs and reachable commit messages for fingerprinted values."""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import hmac
import json
import os
import pathlib
import re
import subprocess
import sys
from collections.abc import Mapping
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
PUBLIC_RULES = pathlib.Path(__file__).with_name("synthetic-rules.json")
ALLOWLIST = pathlib.Path(__file__).with_name("allowlist.json")
RULE_SCHEMA = "automonique.scrub-rules/v1"
ALLOWLIST_SCHEMA = "automonique.scrub-allowlist/v1"
REQUIRED_FAMILIES = frozenset(
    {
        "legacy-name",
        "third-party-product",
        "internal-product",
        "environment-name",
    }
)
# A scan carries exactly the coverage its installed rules give it. With no
# protected rules the only values it can recognise are the four public synthetic
# ones, so a pass says the scanner works — not that the tree is scrubbed. That
# distinction is the whole difference between this gate and a green tick, and it
# is easy to lose when reading CI output, so the run states it itself.
COVERAGE_NOTE = (
    "note: no protected rules were installed, so this run could only have found "
    "the public synthetic values. It is evidence that the scanner works, not "
    "that private identifiers are absent; only a run with the protected rule "
    "bundle can support that claim. See plan/gates.md#gate-scrub."
)
RULE_ID = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\Z")
PROTECTED_RULE_ID = re.compile(r"p[12]-[0-9]{3}\Z")
HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
ENVIRONMENT_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
EXPECTED_ALLOWLIST = {
    "product-mascot": (
        "Monique",
        "plan/contracts/BOOT-003.md#allow-list--retained-by-decision",
    ),
    "repository-organization": (
        "bext-stack",
        "plan/contracts/BOOT-003.md#allow-list--retained-by-decision",
    ),
    "neutral-compatibility-prefix": ("legacy*", "plan/gates.md#gate-scrub"),
    "structural-reference-names": (
        "legacy source filenames, commands, and environment names",
        "plan/gates.md#gate-scrub",
    ),
}


class ScrubError(Exception):
    """The scan cannot produce a trustworthy result."""


@dataclasses.dataclass(frozen=True)
class Rule:
    rule_id: str
    family: str
    algorithm: str
    length: int
    digest: str


@dataclasses.dataclass(frozen=True)
class Finding:
    rule_id: str
    source: str
    location: str
    line: int


def git(repository: pathlib.Path, *args: str) -> bytes:
    completed = subprocess.run(
        ["git", *args], cwd=repository, capture_output=True, check=False
    )
    if completed.returncode != 0:
        raise ScrubError(f"Git operation failed: {' '.join(args[:2])}")
    return completed.stdout


def read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ScrubError(f"cannot load rule document {path.name}: {exc}") from exc
    if not isinstance(document, dict):
        raise ScrubError(f"rule document {path.name} must be an object")
    return document


def parse_rules(
    document: dict[str, Any], *, expected_algorithm: str, require_families: bool
) -> list[Rule]:
    if set(document) != {"schema", "rules"} or document.get("schema") != RULE_SCHEMA:
        raise ScrubError("rule document has an unsupported shape or schema")
    entries = document.get("rules")
    if not isinstance(entries, list) or not entries:
        raise ScrubError("rule document must contain at least one rule")
    rules: list[Rule] = []
    seen: set[str] = set()
    seen_fingerprints: set[tuple[str, int, str]] = set()
    required_fields = {"id", "family", "algorithm", "length", "digest"}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != required_fields:
            raise ScrubError("each rule must contain only fingerprint metadata")
        rule_id = entry.get("id")
        family = entry.get("family")
        algorithm = entry.get("algorithm")
        length = entry.get("length")
        digest = entry.get("digest")
        protected = expected_algorithm == "hmac-sha256"
        identifier_pattern = PROTECTED_RULE_ID if protected else RULE_ID
        label = "protected rule" if protected else f"rule {rule_id}"
        if not isinstance(rule_id, str) or not identifier_pattern.fullmatch(rule_id):
            raise ScrubError("rule ID must be a non-sensitive lowercase identifier")
        if rule_id in seen:
            raise ScrubError("rule document contains a duplicate rule ID")
        if family not in REQUIRED_FAMILIES:
            raise ScrubError(f"{label} has an unknown family")
        expected_pass = "p1-" if family == "legacy-name" else "p2-"
        if protected and not rule_id.startswith(expected_pass):
            raise ScrubError("protected rule ID does not match its transfer pass")
        if algorithm != expected_algorithm:
            raise ScrubError(f"{label} must use {expected_algorithm}")
        if not isinstance(length, int) or not 1 <= length <= 4096:
            raise ScrubError(f"{label} has an invalid byte length")
        if not isinstance(digest, str) or not HEX_DIGEST.fullmatch(digest):
            raise ScrubError(f"{label} has an invalid digest")
        fingerprint = (algorithm, length, digest)
        if fingerprint in seen_fingerprints:
            raise ScrubError("rule document contains a duplicate fingerprint")
        seen.add(rule_id)
        seen_fingerprints.add(fingerprint)
        rules.append(Rule(rule_id, family, algorithm, length, digest))
    present = {rule.family for rule in rules}
    if require_families and present != REQUIRED_FAMILIES:
        missing = ", ".join(sorted(REQUIRED_FAMILIES - present))
        raise ScrubError(f"rule document is missing required families: {missing}")
    return rules


def load_allowlist(path: pathlib.Path) -> list[dict[str, str]]:
    document = read_json(path)
    if set(document) != {"schema", "entries"} or document.get("schema") != ALLOWLIST_SCHEMA:
        raise ScrubError("allow list has an unsupported shape or schema")
    entries = document.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ScrubError("allow list must contain retained decisions")
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "id",
            "retained",
            "reason",
            "decision",
        }:
            raise ScrubError(
                "each allow-list entry needs an ID, retained value, reason, and decision"
            )
        if not all(isinstance(entry[field], str) and entry[field] for field in entry):
            raise ScrubError("allow-list fields must be non-empty strings")
        if entry["id"] in seen:
            raise ScrubError(f"duplicate allow-list ID: {entry['id']}")
        expected = EXPECTED_ALLOWLIST.get(entry["id"])
        if expected != (entry["retained"], entry["decision"]):
            raise ScrubError(f"allow-list entry is not authorized: {entry['id']}")
        seen.add(entry["id"])
    if seen != set(EXPECTED_ALLOWLIST):
        raise ScrubError("allow list differs from the four authorized decisions")
    return entries


def protected_rules_from_environment(
    environment: Mapping[str, str],
    *,
    rules_variable: str,
    key_variable: str,
    required: bool,
) -> tuple[list[Rule], bytes | None]:
    if not ENVIRONMENT_NAME.fullmatch(
        rules_variable
    ) or not ENVIRONMENT_NAME.fullmatch(key_variable):
        raise ScrubError("protected environment variable names are invalid")
    encoded_document = environment.get(rules_variable)
    encoded_key = environment.get(key_variable)
    if not encoded_document and not encoded_key and not required:
        return [], None
    if not encoded_document or not encoded_key:
        raise ScrubError(
            f"protected rules are required but {rules_variable} or {key_variable} is unset"
        )
    try:
        document_bytes = base64.b64decode(encoded_document, validate=True)
        key = base64.b64decode(encoded_key, validate=True)
        document = json.loads(document_bytes)
    except (ValueError, json.JSONDecodeError) as exc:
        raise ScrubError("protected rule configuration is not valid base64 JSON") from exc
    if not isinstance(document, dict):
        raise ScrubError("protected rule configuration must decode to an object")
    if len(key) < 32:
        raise ScrubError("protected fingerprint key must decode to at least 32 bytes")
    rules = parse_rules(
        document, expected_algorithm="hmac-sha256", require_families=True
    )
    return rules, key


def tracked_blobs(repository: pathlib.Path) -> list[tuple[str, str, bytes]]:
    records = git(repository, "ls-files", "--stage", "-z").split(b"\0")
    blobs: list[tuple[str, str, bytes]] = []
    seen_paths: set[str] = set()
    for record in records:
        if not record:
            continue
        try:
            header, encoded_path = record.split(b"\t", 1)
            mode, object_id, stage = header.decode("ascii").split()
        except (ValueError, UnicodeDecodeError) as exc:
            raise ScrubError("cannot parse tracked-file index") from exc
        path = os.fsdecode(encoded_path)
        if stage != "0" or path in seen_paths:
            raise ScrubError("tracked-file index contains an unresolved entry")
        if mode == "160000":
            raise ScrubError("tracked submodule cannot be scrubbed recursively")
        seen_paths.add(path)
        blobs.append((path, object_id, git(repository, "cat-file", "blob", object_id)))
    return blobs


def require_complete_history(repository: pathlib.Path) -> None:
    shallow = git(repository, "rev-parse", "--is-shallow-repository").strip()
    if shallow != b"false":
        raise ScrubError("commit-message scan requires a complete, non-shallow history")


def commit_messages(repository: pathlib.Path) -> list[tuple[str, bytes]]:
    require_complete_history(repository)
    commits = git(repository, "rev-list", "--all").decode("ascii").splitlines()
    messages: list[tuple[str, bytes]] = []
    for commit_id in commits:
        raw = git(repository, "cat-file", "commit", commit_id)
        try:
            _, message = raw.split(b"\n\n", 1)
        except ValueError as exc:
            raise ScrubError("cannot parse a reachable commit object") from exc
        messages.append((commit_id, message))
    return messages


def historical_blobs(
    repository: pathlib.Path, current_object_ids: set[str]
) -> list[tuple[str, bytes]]:
    require_complete_history(repository)
    object_ids = git(
        repository, "rev-list", "--objects", "--all", "--no-object-names"
    ).decode("ascii").splitlines()
    blobs: list[tuple[str, bytes]] = []
    for object_id in sorted(set(object_ids) - current_object_ids):
        if git(repository, "cat-file", "-t", object_id).strip() == b"blob":
            blobs.append((object_id, git(repository, "cat-file", "blob", object_id)))
    return blobs


def grouped_rules(rules: list[Rule]) -> dict[tuple[str, int], list[Rule]]:
    groups: dict[tuple[str, int], list[Rule]] = {}
    for rule in rules:
        groups.setdefault((rule.algorithm, rule.length), []).append(rule)
    return groups


def scan_bytes(
    content: bytes,
    *,
    source: str,
    location: str,
    groups: dict[tuple[str, int], list[Rule]],
    hmac_key: bytes | None,
) -> list[Finding]:
    findings: list[Finding] = []
    for (algorithm, length), candidates in groups.items():
        if length > len(content):
            continue
        if algorithm == "hmac-sha256" and hmac_key is None:
            raise ScrubError("protected rules cannot run without their fingerprint key")
        for offset in range(0, len(content) - length + 1):
            window = content[offset : offset + length]
            if algorithm == "sha256":
                digest = hashlib.sha256(window).hexdigest()
            else:
                assert hmac_key is not None
                digest = hmac.new(hmac_key, window, hashlib.sha256).hexdigest()
            for rule in candidates:
                if hmac.compare_digest(digest, rule.digest):
                    findings.append(
                        Finding(
                            rule.rule_id,
                            source,
                            location,
                            content.count(b"\n", 0, offset) + 1,
                        )
                    )
    return findings


def scan_repository(
    repository: pathlib.Path,
    rules: list[Rule],
    *,
    hmac_key: bytes | None = None,
) -> tuple[list[Finding], int, int]:
    before = repository_state(repository)
    groups = grouped_rules(rules)
    blobs = tracked_blobs(repository)
    messages = commit_messages(repository)
    current_object_ids = {object_id for _, object_id, _ in blobs}
    old_blobs = historical_blobs(repository, current_object_ids)
    findings: list[Finding] = []
    for path, _, content in blobs:
        path_findings = scan_bytes(
            os.fsencode(path),
            source="path",
            location="<redacted-path>",
            groups=groups,
            hmac_key=hmac_key,
        )
        findings.extend(path_findings)
        findings.extend(
            scan_bytes(
                content,
                source="file",
                location="<redacted-path>" if path_findings else path,
                groups=groups,
                hmac_key=hmac_key,
            )
        )
    for object_id, content in old_blobs:
        findings.extend(
            scan_bytes(
                content,
                source="historical-blob",
                location=object_id,
                groups=groups,
                hmac_key=hmac_key,
            )
        )
    for commit_id, message in messages:
        findings.extend(
            scan_bytes(
                message,
                source="commit",
                location=commit_id,
                groups=groups,
                hmac_key=hmac_key,
            )
        )
    if repository_state(repository) != before:
        raise ScrubError("repository changed during the scrub scan")
    findings.sort(key=lambda finding: dataclasses.astuple(finding))
    return findings, len(blobs) + len(old_blobs), len(messages)


def repository_state(repository: pathlib.Path) -> tuple[bytes, bytes, bytes]:
    return (
        git(repository, "rev-parse", "HEAD").strip(),
        git(repository, "write-tree").strip(),
        git(
            repository,
            "for-each-ref",
            "--format=%(refname)%00%(objectname)",
        ),
    )


def render_finding(finding: Finding) -> str:
    location = json.dumps(finding.location, ensure_ascii=True)
    return (
        f"finding rule={finding.rule_id} source={finding.source} "
        f"location={location} line={finding.line}"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=pathlib.Path, default=ROOT)
    parser.add_argument("--rules", type=pathlib.Path, default=PUBLIC_RULES)
    parser.add_argument("--allowlist", type=pathlib.Path, default=ALLOWLIST)
    parser.add_argument("--require-protected", action="store_true")
    parser.add_argument(
        "--protected-rules-env", default="AUTOMONIQUE_SCRUB_PROTECTED_RULES_B64"
    )
    parser.add_argument(
        "--hmac-key-env", default="AUTOMONIQUE_SCRUB_HMAC_KEY_B64"
    )
    args = parser.parse_args()
    try:
        public_rules = parse_rules(
            read_json(args.rules),
            expected_algorithm="sha256",
            require_families=True,
        )
        allowlist = load_allowlist(args.allowlist)
        protected, key = protected_rules_from_environment(
            os.environ,
            rules_variable=args.protected_rules_env,
            key_variable=args.hmac_key_env,
            required=args.require_protected,
        )
        findings, file_count, message_count = scan_repository(
            args.repository.resolve(), public_rules + protected, hmac_key=key
        )
    except ScrubError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    for finding in findings:
        print(render_finding(finding), file=sys.stderr)
    if findings:
        print(f"scrub: FAIL ({len(findings)} finding(s))", file=sys.stderr)
        return 1
    print(
        f"ok — scrubbed {file_count} current-or-reachable Git blobs and "
        f"{message_count} commit "
        f"messages with {len(public_rules)} synthetic and {len(protected)} "
        f"protected rules; {len(allowlist)} retained decisions"
    )
    if not protected:
        print(COVERAGE_NOTE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
