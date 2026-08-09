<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Foreground lifecycle spike

This synthetic fixture proves generation lifecycle behavior without installing
or querying a service manager. The controller starts each generation directly,
passes one inherited Unix socket pair, and exchanges bounded typed JSON frames.

Run the integration trial from the repository root with an immutable base:

```sh
git rev-parse HEAD
python3 spikes/foreground-lifecycle/lifecycle.py --base <printed-40-character-id> --timeout 5
```

The controller uses only explicit argument arrays and never generates a command
string from fixture or model output.

The trial exercises:

- initial foreground readiness and activation;
- failure before readiness with the old generation still active;
- failure after readiness with fenced ownership returned to the old generation;
- successful readiness, atomic owner transfer, old-generation drain, and
  signal-driven shutdown;
- bounded cleanup of every isolated fixture process and temporary file.

The JSON result is ephemeral test output. Do not commit it as a log; record only
the measured assertions in `plan/evidence/R0-03.json`.
