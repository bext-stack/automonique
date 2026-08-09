#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Capture and verify sanitized, model-free provider CLI surface artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
RAW_ROOT = ROOT / "spikes/provider-surfaces/raw"
PROVIDER_ROOT = ROOT / "spikes/provider-surfaces/providers"
INVENTORY = ROOT / "spikes/provider-surfaces/inventory.json"
SCHEMA = "automonique.provider-probe-manifest/v1"
INVENTORY_SCHEMA = "automonique.provider-inventory/v1"
CAPABILITIES = {
    "create",
    "resume",
    "observe",
    "steer",
    "cancel",
    "approval",
    "reconnect",
    "model",
    "usage",
}
SUPPORT = {"advertised", "observed", "unknown", "unavailable"}
ANSI = re.compile(rb"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
SECRET_LIKE = re.compile(
    rb"(?i)(?:bearer\s+[a-z0-9._~-]{16,}|(?:sk|gh[op])_[a-z0-9]{16,})"
)


class InventoryError(Exception):
    """A provider probe cannot be captured safely or reproducibly."""


@dataclass(frozen=True)
class Probe:
    provider: str
    artifact: str
    argv: tuple[str, ...]
    evidence: str


PROBES = (
    Probe("codex", "version", ("codex", "--version"), "version_observed"),
    Probe("codex", "root-help", ("codex", "--help"), "help_only"),
    Probe("codex", "exec-help", ("codex", "exec", "--help"), "help_only"),
    Probe(
        "codex", "mcp-server-help", ("codex", "mcp-server", "--help"), "help_only"
    ),
    Probe(
        "codex", "app-server-help", ("codex", "app-server", "--help"), "help_only"
    ),
    Probe("claude", "version", ("claude", "--version"), "version_observed"),
    Probe("claude", "root-help", ("claude", "--help"), "help_only"),
    Probe("claude", "agents-help", ("claude", "agents", "--help"), "help_only"),
    Probe(
        "claude",
        "auth-status-help",
        ("claude", "auth", "status", "--help"),
        "help_only",
    ),
    Probe(
        "jcode",
        "version",
        ("jcode", "--no-update", "version", "--json"),
        "version_observed",
    ),
    Probe("jcode", "root-help", ("jcode", "--no-update", "--help"), "help_only"),
    Probe(
        "jcode", "run-help", ("jcode", "--no-update", "run", "--help"), "help_only"
    ),
    Probe(
        "jcode",
        "api-bridge-help",
        ("jcode", "--no-update", "api-bridge", "--help"),
        "help_only",
    ),
    Probe(
        "jcode", "acp-help", ("jcode", "--no-update", "acp", "--help"), "help_only"
    ),
    Probe(
        "jcode",
        "server-help",
        ("jcode", "--no-update", "server", "--help"),
        "help_only",
    ),
    Probe(
        "opencode", "version", ("opencode", "--pure", "--version"), "version_observed"
    ),
    Probe(
        "opencode", "root-help", ("opencode", "--pure", "--help"), "help_only"
    ),
    Probe(
        "opencode",
        "serve-help",
        ("opencode", "--pure", "serve", "--help"),
        "help_only",
    ),
    Probe(
        "opencode", "acp-help", ("opencode", "--pure", "acp", "--help"), "help_only"
    ),
    Probe(
        "opencode", "run-help", ("opencode", "--pure", "run", "--help"), "help_only"
    ),
)


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sanitized(
    content: bytes, transient_paths: tuple[pathlib.Path, ...] = ()
) -> bytes:
    value = ANSI.sub(b"", content).replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    replacements = [ROOT.resolve(), pathlib.Path.home().resolve(), *transient_paths]
    for path in replacements:
        value = value.replace(os.fsencode(path), b"<REDACTED_PATH>")
    lines = [line.rstrip() for line in value.split(b"\n")]
    value = b"\n".join(lines).rstrip(b"\n") + b"\n"
    if SECRET_LIKE.search(value):
        raise InventoryError("probe output contains credential-like material")
    return value


def probe_environment(probe_home: pathlib.Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": str(probe_home),
        "XDG_CONFIG_HOME": str(probe_home / "config"),
        "XDG_DATA_HOME": str(probe_home / "data"),
        "XDG_CACHE_HOME": str(probe_home / "cache"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "CI": "1",
    }


def run_probe(probe: Probe) -> tuple[int, bytes]:
    with tempfile.TemporaryDirectory(prefix="automonique-provider-probe-") as directory:
        probe_home = pathlib.Path(directory)
        environment = probe_environment(probe_home)
        if shutil.which(probe.argv[0], path=environment["PATH"]) is None:
            return 127, b"unavailable: executable not found on PATH\n"
        completed = subprocess.run(
            list(probe.argv),
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
            check=False,
        )
        combined = completed.stdout
        if completed.stderr:
            combined += b"\n[stderr]\n" + completed.stderr
        return completed.returncode, sanitized(combined, (probe_home,))


def capture_document(capture_date: str) -> tuple[dict[str, Any], dict[pathlib.Path, bytes]]:
    if not re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}", capture_date):
        raise InventoryError("capture date must use YYYY-MM-DD")
    files: dict[pathlib.Path, bytes] = {}
    entries: list[dict[str, Any]] = []
    for probe in PROBES:
        exit_code, content = run_probe(probe)
        if exit_code != 0:
            raise InventoryError(
                f"safe provider probe failed: {probe.provider}/{probe.artifact}"
            )
        relative = pathlib.Path(probe.provider) / f"{probe.artifact}.txt"
        files[relative] = content
        entries.append(
            {
                "provider": probe.provider,
                "artifact": probe.artifact,
                "source": "installed_cli",
                "argv": list(probe.argv),
                "exit_code": exit_code,
                "evidence_level": probe.evidence,
                "sanitizers": [
                    "ansi_removed",
                    "line_endings_lf",
                    "trailing_whitespace_removed",
                    "workspace_and_home_paths_redacted",
                    "credential_like_output_refused",
                ],
                "path": relative.as_posix(),
                "sha256": sha256(content),
            }
        )
    document = {
        "schema": SCHEMA,
        "capture_date": capture_date,
        "immutable_base": "972f94894dc84921454bfdde131c9fa8efa57ec2",
        "artifacts": entries,
    }
    manifest = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    files[pathlib.Path("manifest.json")] = manifest
    return document, files


def normalized_inventory(capture_date: str) -> dict[str, Any]:
    providers: list[dict[str, Any]] = []
    expected = {"claude", "codex", "jcode", "opencode"}
    for path in sorted(PROVIDER_ROOT.glob("*.json")):
        try:
            document = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise InventoryError(f"cannot read normalized provider file {path.name}") from exc
        provider = document.get("provider")
        if provider not in expected:
            raise InventoryError(f"unexpected provider file: {path.name}")
        if document.get("schema") != "automonique.provider-surface/v1":
            raise InventoryError(f"provider schema differs: {provider}")
        if document.get("capture_date") != capture_date:
            raise InventoryError(f"provider capture date differs: {provider}")
        base = document.get("base", document.get("expected_base"))
        if base != "972f94894dc84921454bfdde131c9fa8efa57ec2":
            raise InventoryError(f"provider immutable base differs: {provider}")
        licence = document.get("licence", document.get("licence_class"))
        if licence != "Elastic-2.0":
            raise InventoryError(f"provider licence differs: {provider}")
        modes = document.get("modes")
        if not isinstance(modes, list) or not modes:
            raise InventoryError(f"provider has no modes: {provider}")
        mode_ids: set[str] = set()
        for mode in modes:
            mode_id = mode.get("id") if isinstance(mode, dict) else None
            capabilities = mode.get("capabilities") if isinstance(mode, dict) else None
            if not isinstance(mode_id, str) or mode_id in mode_ids:
                raise InventoryError(f"provider mode ID is missing or duplicated: {provider}")
            if not isinstance(capabilities, dict) or set(capabilities) != CAPABILITIES:
                raise InventoryError(f"provider capability matrix is incomplete: {provider}")
            for capability in capabilities.values():
                if (
                    not isinstance(capability, dict)
                    or capability.get("support") not in SUPPORT
                    or not capability.get("reason")
                ):
                    raise InventoryError(f"provider capability evidence is invalid: {provider}")
            mode_ids.add(mode_id)
        fallbacks = document.get("fallbacks")
        if not fallbacks:
            raise InventoryError(f"provider has no explicit fallback policy: {provider}")
        version = document.get("version")
        if isinstance(version, dict):
            version_value = version.get("value")
            version_reason = version.get("reason")
        else:
            binary_version = document.get("binary", {}).get("version")
            version_value = (
                binary_version.get("value")
                if isinstance(binary_version, dict)
                else document.get("binary", {}).get("version")
            )
            version_reason = document.get("binary", {}).get("version_reason")
        if version_value is None and not version_reason:
            raise InventoryError(f"provider version is missing without a reason: {provider}")
        authentication = document.get("authentication", {})
        auth_category = authentication.get("category", authentication.get("state"))
        if not auth_category or not authentication.get("reason"):
            raise InventoryError(f"provider authentication category is incomplete: {provider}")
        relative = path.relative_to(ROOT).as_posix()
        providers.append(
            {
                "provider": provider,
                "version": {"value": version_value, "reason": version_reason},
                "authentication_category": auth_category,
                "mode_count": len(modes),
                "capability_fields": sorted(CAPABILITIES),
                "surface_file": relative,
                "surface_sha256": sha256(path.read_bytes()),
            }
        )
    if {entry["provider"] for entry in providers} != expected:
        missing = ", ".join(sorted(expected - {entry["provider"] for entry in providers}))
        raise InventoryError(f"normalized provider files are missing: {missing}")
    return {
        "schema": INVENTORY_SCHEMA,
        "capture_date": capture_date,
        "immutable_base": "972f94894dc84921454bfdde131c9fa8efa57ec2",
        "licence": "Elastic-2.0",
        "raw_manifest": f"spikes/provider-surfaces/raw/{capture_date}/manifest.json",
        "providers": providers,
        "deferred_to": "R0-07",
        "deferred_questions": [
            "runtime lifecycle, cancellation, approval, reconnect, and usage semantics",
            "provider event and schema compatibility under real no-op fixtures",
            "authentication usability without recording account or credential identifiers",
        ],
    }


def inventory_bytes(capture_date: str) -> bytes:
    return (json.dumps(normalized_inventory(capture_date), indent=2, sort_keys=True) + "\n").encode()


def write_capture(capture_date: str) -> int:
    _, files = capture_document(capture_date)
    target = RAW_ROOT / capture_date
    for relative, content in files.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    INVENTORY.write_bytes(inventory_bytes(capture_date))
    print(f"wrote {len(files)} sanitized provider artifacts and normalized inventory")
    return 0


def verify_capture(capture_date: str) -> int:
    _, expected = capture_document(capture_date)
    target = RAW_ROOT / capture_date
    errors: list[str] = []
    expected_paths = {target / path for path in expected}
    actual_paths = {path for path in target.rglob("*") if path.is_file()} if target.exists() else set()
    for path in sorted(expected_paths | actual_paths):
        relative = path.relative_to(target)
        if path not in expected_paths:
            errors.append(f"unexpected artifact: {relative}")
        elif not path.exists():
            errors.append(f"missing artifact: {relative}")
        elif path.read_bytes() != expected[relative]:
            errors.append(f"artifact differs: {relative}")
    try:
        expected_inventory = inventory_bytes(capture_date)
    except InventoryError as exc:
        errors.append(str(exc))
    else:
        if not INVENTORY.exists():
            errors.append("missing normalized inventory")
        elif INVENTORY.read_bytes() != expected_inventory:
            errors.append("normalized inventory differs")
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"ok — {len(expected)} provider artifacts are byte-reproducible")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("capture", "verify"))
    parser.add_argument("--capture-date", required=True)
    args = parser.parse_args()
    try:
        if args.command == "capture":
            return write_capture(args.capture_date)
        return verify_capture(args.capture_date)
    except (InventoryError, OSError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
