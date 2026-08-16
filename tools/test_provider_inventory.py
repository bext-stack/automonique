#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import json
import unittest

from tools import provider_inventory

CAPTURE_DATE = "2026-08-16"


class ProviderInventoryTests(unittest.TestCase):
    def test_probe_allowlist_is_model_free_and_non_mutating(self) -> None:
        forbidden = {
            "login",
            "logout",
            "start",
            "stop",
            "reload",
            "run",
            "serve",
            "attach",
            "delete",
            "upgrade",
            "uninstall",
        }
        for probe in provider_inventory.PROBES:
            if probe.evidence == "help_only":
                self.assertEqual("--help", probe.argv[-1])
            else:
                self.assertTrue(any("version" in part for part in probe.argv[1:]))
            active = {argument for argument in probe.argv[1:] if not argument.startswith("-")}
            if "--help" not in probe.argv:
                self.assertTrue(active.isdisjoint(forbidden), probe.argv)
            self.assertNotIn("--auto", probe.argv)
            self.assertNotIn("--share", probe.argv)
            self.assertNotIn("--refresh", probe.argv)

    def test_sanitizer_removes_ansi_paths_and_normalizes_lines(self) -> None:
        raw = (
            b"\x1b[31mprobe\x1b[0m  \r\n"
            + str(provider_inventory.ROOT).encode()
            + b"\r\n"
        )
        clean = provider_inventory.sanitized(raw)
        self.assertEqual(b"probe\n<REDACTED_PATH>\n", clean)

    def test_manifest_digests_match_sanitized_artifacts(self) -> None:
        document, files = provider_inventory.capture_document(CAPTURE_DATE)
        self.assertEqual(provider_inventory.SCHEMA, document["schema"])
        for entry in document["artifacts"]:
            self.assertEqual(0, entry["exit_code"])
            content = files[provider_inventory.pathlib.Path(entry["path"])]
            self.assertEqual(provider_inventory.sha256(content), entry["sha256"])
        json.loads(files[provider_inventory.pathlib.Path("manifest.json")])

    def test_normalized_inventory_has_four_complete_provider_surfaces(self) -> None:
        document = provider_inventory.normalized_inventory(CAPTURE_DATE)
        self.assertEqual(provider_inventory.INVENTORY_SCHEMA, document["schema"])
        self.assertEqual(
            {"claude", "codex", "jcode", "opencode"},
            {entry["provider"] for entry in document["providers"]},
        )
        for entry in document["providers"]:
            self.assertEqual(
                sorted(provider_inventory.CAPABILITIES), entry["capability_fields"]
            )


if __name__ == "__main__":
    unittest.main()
