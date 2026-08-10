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
"""

from __future__ import annotations

import argparse
import base64
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
    ScrubError,
    parse_rules,
    tracked_blobs,
)

RULES_SECRET = "AUTOMONIQUE_SCRUB_PROTECTED_RULES_B64"
KEY_SECRET = "AUTOMONIQUE_SCRUB_HMAC_KEY_B64"
ENVIRONMENT = "scrub-publication"
KEY_BYTES = 32
MAX_VALUE_BYTES = 4096


def parse_values(text: str) -> list[tuple[str, bytes]]:
    """Parse `family: value` lines into ordered (family, value-bytes) pairs."""
    entries: list[tuple[str, bytes]] = []
    blanks: list[str] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise ScrubError(f"line {number} is not 'family: value'")
        family, _, value = line.partition(":")
        family = family.strip()
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
        entries.append((family, encoded))
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
    present = {family for family, _ in entries}
    missing = REQUIRED_FAMILIES - present
    if missing:
        raise ScrubError(f"no value for required family: {', '.join(sorted(missing))}")
    return entries


def build_bundle(entries: list[tuple[str, bytes]], key: bytes) -> dict[str, Any]:
    """Fingerprint each value. The returned document carries no value."""
    rules: list[dict[str, Any]] = []
    counters = {"p1-": 0, "p2-": 0}
    seen: set[str] = set()
    for family, value in entries:
        digest = hmac.new(key, value, hashlib.sha256).hexdigest()
        if digest in seen:
            raise ScrubError("two values produced the same fingerprint")
        seen.add(digest)
        prefix = "p1-" if family == "legacy-name" else "p2-"
        counters[prefix] += 1
        rules.append(
            {
                "id": f"{prefix}{counters[prefix]:03d}",
                "family": family,
                "algorithm": "hmac-sha256",
                "length": len(value),
                "digest": digest,
            }
        )
    return {"schema": "automonique.scrub-rules/v1", "rules": rules}


def unscrubbed(entries: list[tuple[str, bytes]], repository: pathlib.Path) -> list[str]:
    """Rule families whose value is still present in the tracked tree.

    A value still in the repository has not been scrubbed. Uploading a rule for
    it would fail the publication job immediately, which is correct but useless
    as a first signal, so refuse and say which family — never which value.
    """
    contents = [content for _, _, content in tracked_blobs(repository)]
    live: list[str] = []
    for family, value in entries:
        if any(value in content for content in contents):
            live.append(family)
    return sorted(set(live))


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

        live = unscrubbed(entries, ROOT)
        if live:
            raise ScrubError(
                "these families are still present in the tracked tree and must be "
                f"scrubbed before fingerprinting: {', '.join(live)}"
            )

        key = secrets.token_bytes(KEY_BYTES)
        bundle = build_bundle(entries, key)
        # Prove the bundle satisfies the scanner before it becomes a secret.
        parse_rules(bundle, expected_algorithm="hmac-sha256", require_families=True)

        for rule in bundle["rules"]:
            print(f"  {rule['id']}  {rule['family']:<20} {rule['length']} bytes")
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
