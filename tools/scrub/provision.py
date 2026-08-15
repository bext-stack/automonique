#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Turn owner-held private identifiers into protected scrub rules, in one step.

The scanner matches fingerprints, never values, so the protected rule bundle can
live in an Actions secret while the values stay with the owner. Producing that
bundle is the only part of `BOOT-003` a worker cannot do: no permitted input
contains the scrubbed values.

This tool closes that gap without ever handling the values unsafely. It reads a
private file the owner points at, derives one HMAC-SHA256 fingerprint per value
under a freshly generated key, and uploads the bundle and key straight to the
`scrub-publication` environment. Values are never printed, never written to the
repository, and never passed on a command line.

    python3 tools/scrub/provision.py --values ~/private/scrub-values.txt --upload

The values file is one `family: value` per line; `#` starts a comment:

    legacy-name: <a name the first pass removed>
    third-party-product: <a product name the second pass removed>
    internal-product: <an internal product name>
    environment-name: <AN_ENVIRONMENT_NAME>

All four families must appear at least once. Run with `--dry-run` first: it
reports the rule IDs, families and byte lengths it would upload and nothing
else.

A value that is deliberately *retained* in one or more files — the way a legacy
identifier is retained in the classified inventory it exists to classify —
names those files with a `@home` annotation, and the rule then ignores their
content:

    legacy-name: <a retained name> @home docs/some/inventory.md @home src/registry.rs

Without that, such a value cannot be fingerprinted at all: its own sanctioned
home would fail the scan on every run, forever. Each `@home` names one exact
repository-relative file. It suppresses that rule against that file's *content*
and nothing else — not the file's name, not a historical blob, not a commit
message — and a home naming a file that is not tracked is refused rather than
uploaded, because an exemption nobody can see is worse than no exemption.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import hmac
import json
import pathlib
import secrets
import subprocess
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from tools.scrub.scan import (  # noqa: E402
    REQUIRED_FAMILIES,
    RULE_SCHEMA_V2,
    ScrubError,
    parse_home,
    parse_rules,
    tracked_blobs,
)

RULES_SECRET = "AUTOMONIQUE_SCRUB_PROTECTED_RULES_B64"
KEY_SECRET = "AUTOMONIQUE_SCRUB_HMAC_KEY_B64"
ENVIRONMENT = "scrub-publication"
KEY_BYTES = 32
MAX_VALUE_BYTES = 4096
HOME_MARKER = " @home "


@dataclasses.dataclass(frozen=True)
class ValueEntry:
    """One owner-supplied value and the files that may still contain it."""

    family: str
    value: bytes
    homes: tuple[str, ...] = ()


def parse_values(text: str) -> list[ValueEntry]:
    """Parse `family: value [@home path]…` lines into ordered entries."""
    entries: list[ValueEntry] = []
    blanks: list[str] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise ScrubError(f"line {number} is not 'family: value'")
        family, _, remainder = line.partition(":")
        family = family.strip()
        value, *declared = remainder.split(HOME_MARKER)
        value = value.strip()
        if family not in REQUIRED_FAMILIES:
            raise ScrubError(f"line {number} names an unknown family")
        if not value:
            # An unfilled template line, not a typo. Collect rather than raise,
            # so a fresh template reports the whole job instead of its first line.
            blanks.append(f"line {number} ({family})")
            continue
        encoded = value.encode("utf-8")
        if len(encoded) > MAX_VALUE_BYTES:
            raise ScrubError(f"line {number} exceeds {MAX_VALUE_BYTES} bytes")
        homes = tuple(
            parse_home(home.strip(), label=f"line {number}") for home in declared
        )
        if len(set(homes)) != len(homes):
            raise ScrubError(f"line {number} names the same home twice")
        entries.append(ValueEntry(family, encoded, homes))
    if not entries:
        if blanks:
            raise ScrubError(
                "no values filled in yet — every family line is still blank: "
                + ", ".join(blanks)
                + ". Type your own identifiers after each colon and re-run."
            )
        raise ScrubError("the values file contains no rules")
    if blanks:
        raise ScrubError(
            "these lines are still blank: "
            + ", ".join(blanks)
            + ". Fill them in, or delete the line if that family needs no value."
        )
    present = {entry.family for entry in entries}
    missing = REQUIRED_FAMILIES - present
    if missing:
        raise ScrubError(f"no value for required family: {', '.join(sorted(missing))}")
    return entries


def build_bundle(entries: list[ValueEntry], key: bytes) -> dict[str, Any]:
    """Fingerprint each value. The returned document carries no value."""
    rules: list[dict[str, Any]] = []
    counters = {"p1-": 0, "p2-": 0}
    seen: set[str] = set()
    for entry in entries:
        digest = hmac.new(key, entry.value, hashlib.sha256).hexdigest()
        if digest in seen:
            raise ScrubError("two values produced the same fingerprint")
        seen.add(digest)
        prefix = "p1-" if entry.family == "legacy-name" else "p2-"
        counters[prefix] += 1
        rule: dict[str, Any] = {
            "id": f"{prefix}{counters[prefix]:03d}",
            "family": entry.family,
            "algorithm": "hmac-sha256",
            "length": len(entry.value),
            "digest": digest,
        }
        # Emitted only when there is one, so a bundle with no retained value is
        # the same document it always was, minus the schema version.
        if entry.homes:
            rule["homes"] = list(entry.homes)
        rules.append(rule)
    return {"schema": RULE_SCHEMA_V2, "rules": rules}


def unscrubbed(entries: list[ValueEntry], repository: pathlib.Path) -> list[str]:
    """Rule families whose value is still present outside its sanctioned homes.

    A value still in the repository has not been scrubbed. Uploading a rule for
    it would fail the publication job immediately, which is correct but useless
    as a first signal, so refuse and say which family — never which value.

    An occurrence inside a file that entry declares as a home is not a failure
    to scrub, it is the retention the home records; counting it would make a
    retained value unfingerprintable, which is the whole reason homes exist.
    """
    blobs = [(path, content) for path, _, content in tracked_blobs(repository)]
    live: list[str] = []
    for entry in entries:
        if any(
            entry.value in content
            for path, content in blobs
            if path not in entry.homes
        ):
            live.append(entry.family)
    return sorted(set(live))


def phantom_homes(entries: list[ValueEntry], repository: pathlib.Path) -> list[str]:
    """Declared homes that are not tracked files, by family.

    The scanner refuses these too, but it refuses them in CI after the bundle
    is already a secret. Catching a typo here costs one `--dry-run`; catching
    it there costs a re-provision.
    """
    tracked = {path for path, _, _ in tracked_blobs(repository)}
    return sorted(
        {
            entry.family
            for entry in entries
            if any(home not in tracked for home in entry.homes)
        }
    )


def put_secret(name: str, payload: str, repository: str) -> None:
    """Set one Actions secret, passing the value on stdin rather than argv."""
    result = subprocess.run(
        ["gh", "secret", "set", name, "--env", ENVIRONMENT, "--repo", repository,
         "--body-file", "-"],
        input=payload,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        # gh echoes neither the body nor stdin, so this is safe to surface.
        raise ScrubError(f"could not set {name}: {result.stderr.strip()}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--values", type=pathlib.Path, required=True)
    parser.add_argument("--repository", default="bext-stack/automonique")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--upload", action="store_true")
    mode.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()

    try:
        values_path = arguments.values.expanduser().resolve()
        if values_path.is_relative_to(ROOT):
            raise ScrubError(
                "the values file must live outside the repository so it cannot be committed"
            )
        entries = parse_values(values_path.read_text(encoding="utf-8"))

        phantom = phantom_homes(entries, ROOT)
        if phantom:
            raise ScrubError(
                "these families name a @home that is not a tracked file, so the "
                f"exemption would not be in force: {', '.join(phantom)}"
            )

        live = unscrubbed(entries, ROOT)
        if live:
            raise ScrubError(
                "these families are still present in the tracked tree outside any "
                f"declared @home and must be scrubbed before fingerprinting: "
                f"{', '.join(live)}"
            )

        key = secrets.token_bytes(KEY_BYTES)
        bundle = build_bundle(entries, key)
        # Prove the bundle satisfies the scanner before it becomes a secret.
        parse_rules(bundle, expected_algorithm="hmac-sha256", require_families=True)

        for rule in bundle["rules"]:
            homes = rule.get("homes", [])
            retained = f"  retained in {len(homes)} sanctioned file(s)" if homes else ""
            print(
                f"  {rule['id']}  {rule['family']:<20} {rule['length']} bytes{retained}"
            )
        print(f"{len(bundle['rules'])} protected rules across "
              f"{len({r['family'] for r in bundle['rules']})} families")

        if arguments.dry_run:
            print("dry run — nothing uploaded, no value printed")
            return 0

        put_secret(RULES_SECRET,
                   base64.b64encode(json.dumps(bundle).encode()).decode(), arguments.repository)
        put_secret(KEY_SECRET, base64.b64encode(key).decode(), arguments.repository)
        print(f"uploaded {RULES_SECRET} and {KEY_SECRET} to {ENVIRONMENT}")
        print("next: the publication-scrub job on main now runs with protected rules")
        return 0
    except (ScrubError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
