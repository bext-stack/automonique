# SPDX-License-Identifier: Elastic-2.0
"""Exercise credential changes without a configured account or service."""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


WORKER = Path(__file__).with_name("run_manage_fleet_worker.sh").read_text()


def function(name):
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}$", WORKER, re.M | re.S)
    if match is None:
        raise AssertionError(f"missing worker function {name}")
    return match.group(0)


class ProviderAuthTests(unittest.TestCase):
    def test_restart_does_not_verify_replaced_account_credentials(self):
        for provider in ("codex", "claude"):
            for changed, known_revision in ((False, True), (True, True), (False, False)):
                with self.subTest(provider=provider, changed=changed, known_revision=known_revision):
                    with tempfile.TemporaryDirectory() as directory:
                        home = Path(directory)
                        leaf = "auth.json" if provider == "codex" else ".credentials.json"
                        (home / leaf).write_text("original fixture")
                        script = "\n".join([
                            "set -euo pipefail",
                            function("credential_revision"),
                            function("initialize_auth_health"),
                            r'''
probe_local_auth() { return 0; }
auth_health_status() { printf authenticated; }
previous_verified_at() { printf 123; }
latest_job_auth_failure_reason() { return 1; }
write_auth_health() { printf '%s:%s:%s\n' "$1" "$2" "$3" >> "$selected_home/health"; }
write_auth_revision() { printf '%s' "$1" > "$auth_revision_file"; }
if [[ "$known_revision" == yes ]]; then
    write_auth_revision "$(credential_revision)"
fi
if [[ "$replace_credentials" == yes ]]; then
    printf 'replacement fixture' > "$selected_home/$credential_leaf.next"
    mv "$selected_home/$credential_leaf.next" "$selected_home/$credential_leaf"
fi
initialize_auth_health
''',
                        ])
                        subprocess.run(["bash", "-c", script], env={
                            **os.environ,
                            "selected_provider": provider,
                            "selected_account": "acct-fixture",
                            "selected_home": directory,
                            "auth_revision_file": str(home / "revision"),
                            "credential_leaf": leaf,
                            "replace_credentials": "yes" if changed else "no",
                            "known_revision": "yes" if known_revision else "no",
                        }, check=True)
                        health = home / "health"
                        if changed:
                            self.assertTrue(health.exists(), "replaced credentials kept stale authenticated status")
                            self.assertEqual(health.read_text(), "configured_unverified:credentials_changed:123\n")
                        else:
                            self.assertFalse(health.exists(), "unchanged credentials lost execution evidence")

    def test_jcode_rechecks_replaced_credentials_and_access_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            (home / "auth.json").write_text("Claude fixture")
            (home / "openai-auth.json").write_text("OpenAI fixture")
            (home / "config.toml").write_text('[provider]\ndefault_provider="openai"\n')
            script = "\n".join(
                [
                    "set -euo pipefail",
                    function("credential_revision"),
                    function("refresh_auth_after_credential_change"),
                    r'''
probe_local_auth() { printf 'probe\n' >> "$selected_home/probes"; return 0; }
previous_verified_at() { printf null; }
write_auth_health() { printf '%s:%s\n' "$1" "$2" >> "$selected_home/health"; }
write_auth_revision() { printf '%s' "$1" > "$auth_revision_file"; }
write_auth_revision "$(credential_revision)"
refresh_auth_after_credential_change
test ! -e "$selected_home/probes"
printf 'new OpenAI fixture' > "$selected_home/openai-auth.json.next"
mv "$selected_home/openai-auth.json.next" "$selected_home/openai-auth.json"
chmod 640 "$selected_home/openai-auth.json"
refresh_auth_after_credential_change
refresh_auth_after_credential_change
chmod 600 "$selected_home/openai-auth.json"
refresh_auth_after_credential_change
# JCode reapplies the same private mode during a probe; that is not a new
# credential or an access change and must not cause a probe loop.
chmod 600 "$selected_home/openai-auth.json"
refresh_auth_after_credential_change
''',
                ]
            )
            subprocess.run(
                ["bash", "-c", script],
                env={
                    **os.environ,
                    "selected_provider": "jcode",
                    "selected_home": directory,
                    "auth_revision_file": str(home / "revision"),
                },
                check=True,
            )
            self.assertEqual((home / "probes").read_text().splitlines(), ["probe"] * 2)
            self.assertEqual(
                (home / "health").read_text().splitlines(),
                ["configured_unverified:credentials_changed"] * 2,
            )
            self.assertNotIn("\n", (home / "revision").read_text())


if __name__ == "__main__":
    unittest.main()
