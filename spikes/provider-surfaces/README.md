<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Provider surface inventory

This directory is the model-free `R0-06` inventory for the locally installed
Claude, Codex, Jcode and OpenCode CLIs. The normalized
[`inventory.json`](inventory.json) links one detailed provider document per
binary and the sanitized raw artifact manifest. Support is deliberately split
into `observed`, `advertised`, `unknown` and `unavailable`; help text never
becomes runtime proof.

Capture and verify with fixed explicit argument vectors:

```sh
python3 tools/provider_inventory.py capture --capture-date 2026-08-09
python3 tools/provider_inventory.py verify --capture-date 2026-08-09
python3 -m unittest tools/test_provider_inventory.py
```

The capture command runs only version and `--help` operations. It supplies a
minimal environment, disables Jcode updates and OpenCode plugins, applies a
ten-second timeout, removes ANSI and absolute workspace/home paths, refuses
credential-looking output, and hashes every committed artifact. It never
starts a server, changes authentication, reads provider state, executes a
prompt or makes a model call.

Provider documents include ordered fallbacks and the guarantees each fallback
loses. Runtime semantics—especially typed cancellation, approvals, reconnect,
usage and schema compatibility—remain explicit questions for `R0-07`; no
silent downgrade is authorized by this inventory.
