#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Scan tracked blobs and reachable commit messages for fingerprinted values.

Two scopes, because two jobs need different answers. `--scope full` is the
publication question — "is this value reachable from any ref?" — and it costs a
pass over every historical blob and every commit message. `--scope tree` is the
push question — "does the state a reviewer is about to read contain it?" — and
it reads only the tracked blobs and their path names, which is what makes it
cheap enough to run on every push. `--commits <range>` adds exactly the
messages a push introduced, so a push job can cover both without paying for the
whole history.
"""

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
# v2 adds exactly one optional per-rule field, `homes`. A value that is
# deliberately retained in a named file — the way a legacy identifier is
# retained in the classified inventory — cannot be fingerprinted at all under
# v1, because its own sanctioned home would fail the scan forever. Naming the
# home is what makes the rule installable, and naming it per rule is what keeps
# one rule's exemption from widening another's.
RULE_SCHEMA_V2 = "automonique.scrub-rules/v2"
SUPPORTED_RULE_SCHEMAS = (RULE_SCHEMA, RULE_SCHEMA_V2)
ALLOWLIST_SCHEMA = "automonique.scrub-allowlist/v1"
SCOPES = ("tree", "full")
MAX_HOMES_PER_RULE = 16
MAX_HOME_BYTES = 512
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
    "note: public synthetic rules only; use --require-protected for a publication scan"
)
# The same distinction the coverage note makes, for the other axis. A tree
# scope pass says the checkout is clean; it says nothing about what stays
# reachable in history, and a reader deciding whether a repository is safe to
# publish needs to be told which question was answered.
SCOPE_NOTE = (
    "note: tree scope; history was not scanned"
)
RULE_ID = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\Z")
PROTECTED_RULE_ID = re.compile(r"p[12]-[0-9]{3}\Z")
HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
ENVIRONMENT_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
# A commit range reaches `git rev-list` as an argument. It may name refs,
# SHAs and the range operators, and nothing that git would read as an option or
# a pathspec — a leading `-` or a `--` separator would let a caller change what
# the command does rather than which commits it walks.
COMMIT_RANGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/^~@{}-]{0,255}\Z")
EXPECTED_ALLOWLIST = {
    "product-mascot": (
        "Monique",
        "AGENTS.md#guardrails",
    ),
    "repository-organization": (
        "bext-stack",
        "SECURITY.md",
    ),
    "neutral-compatibility-prefix": ("legacy*", "PROVENANCE.md#structural-references"),
    "structural-reference-names": (
        "legacy source filenames, commands, and environment names",
        "PROVENANCE.md#structural-references",
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
    # Repository-relative paths whose *file content* this rule does not judge.
    # Deliberately narrow: a home suppresses nothing about the file's name, and
    # nothing about a historical blob or a commit message, because those are
    # not the sanctioned copy — they are the copies nobody will ever retire.
    homes: tuple[str, ...] = ()


def parse_home(value: Any, *, label: str) -> str:
    """Validate one sanctioned-home path, or refuse to install the rule.

    A home is an exemption, so a malformed one must never be interpreted
    generously. It is a repository-relative POSIX path naming one file: not
    absolute, not `..`-relative, not a directory, not a glob. `scan_repository`
    compares it against the exact path git reports, so anything that would not
    compare equal is a home that silently suppresses nothing.
    """
    if not isinstance(value, str) or not value:
        raise ScrubError(f"{label} has a home that is not a non-empty string")
    if len(value.encode("utf-8")) > MAX_HOME_BYTES:
        raise ScrubError(f"{label} has a home longer than {MAX_HOME_BYTES} bytes")
    if value != value.strip():
        raise ScrubError(f"{label} has a home with surrounding whitespace")
    if value.startswith("/") or "\\" in value:
        raise ScrubError(f"{label} has a home that is not a relative POSIX path")
    if value.endswith("/"):
        raise ScrubError(f"{label} has a home naming a directory, not a file")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ScrubError(f"{label} has a home with an empty or relative segment")
    if any(character in value for character in "*?[]"):
        raise ScrubError(f"{label} has a home containing a glob character")
    return value


def parse_homes(entry: Mapping[str, Any], *, label: str) -> tuple[str, ...]:
    listed = entry.get("homes")
    if listed is None:
        return ()
    if not isinstance(listed, list) or not listed:
        raise ScrubError(f"{label} declares an empty or non-list homes field")
    if len(listed) > MAX_HOMES_PER_RULE:
        raise ScrubError(f"{label} declares more than {MAX_HOMES_PER_RULE} homes")
    homes = tuple(parse_home(item, label=label) for item in listed)
    if len(set(homes)) != len(homes):
        raise ScrubError(f"{label} declares the same home twice")
    return homes


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
    if set(document) != {"schema", "rules"}:
        raise ScrubError("rule document has an unsupported shape or schema")
    schema = document.get("schema")
    if schema not in SUPPORTED_RULE_SCHEMAS:
        raise ScrubError("rule document has an unsupported shape or schema")
    entries = document.get("rules")
    if not isinstance(entries, list) or not entries:
        raise ScrubError("rule document must contain at least one rule")
    rules: list[Rule] = []
    seen: set[str] = set()
    seen_fingerprints: set[tuple[str, int, str]] = set()
    required_fields = {"id", "family", "algorithm", "length", "digest"}
    # `homes` is the only optional field, and only under v2. A v1 document
    # carrying it is not a v1 document a v1 reader would have understood, so it
    # is refused rather than silently upgraded.
    permitted_fields = (
        required_fields | {"homes"} if schema == RULE_SCHEMA_V2 else required_fields
    )
    for entry in entries:
        if (
            not isinstance(entry, dict)
            or not required_fields <= set(entry)
            or not set(entry) <= permitted_fields
        ):
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
        homes = parse_homes(entry, label=label)
        seen.add(rule_id)
        seen_fingerprints.add(fingerprint)
        rules.append(Rule(rule_id, family, algorithm, length, digest, homes))
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


def commit_messages(
    repository: pathlib.Path, *, revisions: str | None = None
) -> list[tuple[str, bytes]]:
    """Messages for `revisions`, or for every reachable commit when unset.

    Only the everything case needs a complete history: "no reachable commit
    carries this value" is a claim a shallow clone cannot support. A named
    range asks a smaller question, and git refuses loudly if the range is not
    present, so a shallow clone that has the range may answer it.
    """
    if revisions is None:
        require_complete_history(repository)
        selector = ["--all"]
    else:
        if not COMMIT_RANGE.fullmatch(revisions):
            raise ScrubError("commit range is not a plain revision selector")
        selector = [revisions, "--"]
    commits = git(repository, "rev-list", *selector).decode("ascii").splitlines()
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


def groups_for_file(
    groups: dict[tuple[str, int], list[Rule]], path: str
) -> tuple[dict[tuple[str, int], list[Rule]], frozenset[str]]:
    """The groups that judge `path`'s content, and the rules that do not.

    Suppression removes the rule from the group rather than filtering findings
    afterwards, so a group left empty is not hashed at all. That matters:
    hashing is per distinct `(algorithm, length)` and runs over every byte
    offset, so a sanctioned home should cost nothing rather than cost a full
    pass whose findings are then thrown away.
    """
    suppressed = frozenset(
        rule.rule_id for rules in groups.values() for rule in rules if path in rule.homes
    )
    if not suppressed:
        return groups, suppressed
    narrowed: dict[tuple[str, int], list[Rule]] = {}
    for key, rules in groups.items():
        kept = [rule for rule in rules if rule.rule_id not in suppressed]
        if kept:
            narrowed[key] = kept
    return narrowed, suppressed


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


def require_homes_exist(rules: list[Rule], tracked: set[str]) -> None:
    """Refuse a rule whose sanctioned home is not a file in this tree.

    A home that names nothing suppresses nothing, so it cannot cause a false
    pass — but it is a rule document that no longer describes this repository,
    and the next reader will believe an exemption is in force that is not. Same
    defect as an Apache licence root that does not exist on disk, and treated
    the same way: a configuration error, not a finding.

    The refusal names the rule and never the path. The rule document arrives
    from a secret and this message goes to a CI log; a rule ID is
    non-sensitive by construction, and a path from that document is not this
    function's to publish.
    """
    phantom = sorted(
        rule.rule_id
        for rule in rules
        if any(home not in tracked for home in rule.homes)
    )
    if phantom:
        raise ScrubError(
            "these rules declare a sanctioned home that is not a tracked file, so "
            f"the exemption is not in force: {', '.join(phantom)}"
        )


def scan_repository(
    repository: pathlib.Path,
    rules: list[Rule],
    *,
    hmac_key: bytes | None = None,
    scope: str = "full",
    commits: str | None = None,
) -> tuple[list[Finding], int, int]:
    if scope not in SCOPES:
        raise ScrubError(f"unknown scan scope: {scope}")
    before = repository_state(repository)
    groups = grouped_rules(rules)
    blobs = tracked_blobs(repository)
    # Tree scope answers "what would a reader of this checkout find", so it
    # reads the index and stops. Full scope answers "what is reachable", which
    # is the publication question and costs every historical blob.
    if scope == "full":
        messages = commit_messages(repository, revisions=commits)
        current_object_ids = {object_id for _, object_id, _ in blobs}
        old_blobs = historical_blobs(repository, current_object_ids)
    else:
        messages = (
            [] if commits is None else commit_messages(repository, revisions=commits)
        )
        old_blobs = []
    require_homes_exist(rules, {path for path, _, _ in blobs})
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
        file_groups, _ = groups_for_file(groups, path)
        findings.extend(
            scan_bytes(
                content,
                source="file",
                location="<redacted-path>" if path_findings else path,
                groups=file_groups,
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
        "--scope",
        choices=SCOPES,
        default="full",
        help="full: tracked blobs, path names, historical blobs and commit "
        "messages. tree: tracked blobs and path names only — what a reader of "
        "this checkout would find, without the cost of the whole history.",
    )
    parser.add_argument(
        "--commits",
        default=None,
        help="a git revision range whose commit messages are scanned. Adds the "
        "messages a push introduced to a tree-scope run; narrows a full-scope "
        "run to that range instead of every reachable commit.",
    )
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
            args.repository.resolve(),
            public_rules + protected,
            hmac_key=key,
            scope=args.scope,
            commits=args.commits,
        )
    except ScrubError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    for finding in findings:
        print(render_finding(finding), file=sys.stderr)
    if findings:
        print(f"scrub: FAIL ({len(findings)} finding(s))", file=sys.stderr)
        return 1
    described = (
        "current-or-reachable" if args.scope == "full" else "currently tracked"
    )
    print(
        f"ok — scrubbed {file_count} {described} Git blobs and "
        f"{message_count} commit "
        f"messages with {len(public_rules)} synthetic and {len(protected)} "
        f"protected rules; {len(allowlist)} retained decisions"
    )
    if args.scope == "tree":
        print(SCOPE_NOTE)
    if not protected:
        print(COVERAGE_NOTE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
