<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — R2-04 internal service boundary

| Field | Decision |
|---|---|
| Status | approved for the R2-04 contract and later implementation |
| Expected base | `ca61b935b50c5bf3c1d1f73dfc2577384e7b99a4` |
| Work ID | `R2-04` — runner control socket |
| Dependency evidence | R1-04 is done; R2-03 and R2-06 are explicit typed-input dependencies; no named gate is waived |
| Objective | pin the private runner socket's same-effective-UID service boundary without treating transport admission as operator, role or tenant authorization |
| Allowed paths | `plan/contracts/R2-04.md`, `plan/owner-decisions/2026-08-12-r2-04-internal-service-boundary.md`, `plan/generate.py`, `plan/work-graph.toml`, generated ready/program/objective/baseline artifacts |
| Licence class | `Elastic-2.0` |
| Budget | one Unix socket, one non-root runner UID, exact kernel peer credentials before parsing, eight bounded clients, no public/operator endpoint, no credential/provider/workspace/artifact or launch authority |
| Review | autonomous protected-integration candidate; actual reviewer count is recorded by the candidate report |

## Decision

R2-04 is an internal host-service protocol, not an operator protocol. The
server derives a peer policy admitting exactly its non-root effective UID. It
does not accept a caller-selected UID/GID list, wildcard, implicit root or
message-carried identity. A peer that does not match is closed before any
request byte is read.

Successful peer admission authorizes only this private transport to disclose
the bounded R2-03 status/record projection for an exact registered attempt and
to deliver an exact attempt-cancel request to the nonfabricable R2-06 service.
It is not an R1-13 role or tenant decision, is not evidence that an operator was
authorized, and does not by itself cancel or terminate a process. The daemon or
later public adapter remains responsible for authenticating the caller and
evaluating deny-by-default tenant/action policy before it uses this socket.

This boundary is intentionally no stronger than the runner's existing
same-effective-UID filesystem boundary: a malicious process already executing
as that UID is outside the confidentiality and integrity threat model for the
runner's `0700` runtime directory and `0600` spool/socket entries. R2-04 must
state this limitation and must not claim protection from same-UID `/proc`,
debugger, pathname-race or direct-file access.

## Stop conditions

Stop if product code turns R1-04 `Admission` into a user role or tenant
decision; accepts a body-supplied actor/policy; exposes the socket to another
UID, root or a public operator client; returns data for a mismatched target;
delivers cancellation without the exact R2-06 capability; claims process exit
from request delivery; or weakens the runtime directory/socket modes.
