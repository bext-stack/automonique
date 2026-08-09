<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Execution-host ownership spike

This synthetic fixture proves that a direct-process execution host remains
discoverable after its first controller disconnects and that a later controller
can cancel its entire recorded descendant group through a typed local protocol.

Run it from the repository root with an immutable base:

```sh
git rev-parse HEAD
python3 spikes/execution-host/trial.py --base <printed-40-character-id> --timeout 5
python3 spikes/execution-host/test_execution_host.py
```

The controller and runner use fixed Python argument vectors. No request carries
an executable, argument list, shell fragment, credential, network destination,
or production identifier. Temporary state is mode 0700, the Unix socket and
atomic registry are mode 0600, and same-user peer credentials are checked when
the kernel supports `SO_PEERCRED`.

The trial measures controller reconnect, opaque host discovery, two-descendant
process ownership, typed cancellation latency, launch failure and cleanup.
Cgroup, systemd, container and remote-executor capabilities remain explicit
`null` values with reasons. Full JSON output is ephemeral and must not be
committed as a runtime log; retain only bounded measurements in
`plan/evidence/R0-04.json`.
