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
