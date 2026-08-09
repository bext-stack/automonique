<!-- SPDX-License-Identifier: Elastic-2.0 -->

# R0-05 runtime topology decision

Status: accepted portable baseline. Source: `plan/evidence/R0-03.json`, SHA-256
`9d28baa7ae4978f0577693fb1a48957cc238b625cee5e82fc745cb8d53f1e191`.
The source trial ran on Linux `6.8.0-124-generic` with Python `3.12.3`, a
five-second wait bound, and no service manager.

## Decision

Direct foreground execution is the only runtime topology required for core
correctness. The invoking controller or operator owns process creation. A
generation never forks or detaches itself. Readiness, fencing, activation,
quiesce, drain, shutdown, and cleanup use the same portable typed lifecycle
whether the process was invoked directly or by an optional adapter.

An adapter may translate host activation, restart, credential, readiness, or
resource-accounting facilities, but those facilities cannot become preconditions
for core operation. Unsupported adapter behavior falls back to direct foreground
execution; it does not invalidate the product runtime.

## Capability matrix

`Measured` means R0-03 observed it. `Unmeasured` is deliberately not a claim.

| Topology | Core | Activation | Restart | Resource accounting | Readiness translation | Credential injection |
|---|---:|---|---|---|---|---|
| direct process | yes | measured typed activation | measured controller replacement/fallback | unmeasured; process cleanup only | not required | not required |
| systemd | no | unmeasured | unmeasured | unmeasured | unmeasured | unmeasured |
| launchd | no | unmeasured | unmeasured | unmeasured | unmeasured | unmeasured |
| container | no | unmeasured | unmeasured | unmeasured | unmeasured | unmeasured |

No optional row is recommended yet. The machine-readable reasons for every
unmeasured cell are in `R0-05-runtime-topology.json`.

## Ownership under failure

- Before readiness, the old generation remains active and the owner record does
  not move.
- After readiness but before successful activation, both generations remain
  fenced. Recovery writes a newer rollback epoch before reactivating only the
  old generation.
- If the old generation misses its drain deadline after the new owner commits,
  the new generation remains active. Cleanup is bounded to the old generation's
  owned process tree and the degraded cleanup is recorded.
- The controller or operator owns restart. A supervisor restart is only a new
  candidate and must rejoin the epoch-fenced protocol before it can activate.

Every path permits zero or one active owner, never two.

## Recommendation threshold

An adapter becomes recommended only for the environments actually covered by
evidence, and only after all of these are true:

1. two supported environments each pass 30 consecutive lifecycle trials;
2. every defined failure mode receives at least 10 injected trials;
3. ownership violations and orphaned processes both remain zero;
4. direct foreground fallback continues to pass;
5. the adapter demonstrates a measured operational benefit, such as bounded
   unattended recovery, stronger descendant accounting, or a smaller endpoint
   reconnect gap.

Meeting the threshold for one deployment class does not make the adapter a
portable core dependency.

## Unresolved risks

Stuck drain, controller loss during fencing, and serving-endpoint reconnect gaps
remain unmeasured. They are explicit inputs to later recovery and execution-host
work, not implicit claims attached to this decision.
