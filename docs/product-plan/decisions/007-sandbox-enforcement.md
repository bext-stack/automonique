# ADR 007: layered sandbox enforcement and profiles

- **Status:** accepted
- **Decision date:** 2026-08-04

## Context

Landlock, seccomp, cgroups and provider permission modes solve different problems. Seccomp cannot express destination-aware network policy, a shared provider daemon may execute outside an execution-host cgroup, and a rootless user service may not be able to create every required namespace. Treating any one mechanism as “the sandbox” would overstate the boundary and produce silent differences between hosts/providers.

## Decision

- Compile every reviewed execution plan into an immutable, versioned `SandboxSpec` and persist an effective enforcement attestation.
- Use layered workspace, mount-namespace, Landlock, process/cgroup, credential and network controls. Missing required enforcement fails closed.
- Separate trusted provider-control egress from model-directed tool egress. Domain/destination policy uses a namespace plus egress broker; seccomp alone is never described as an egress allowlist.
- Run tools, MCP servers and third-party extensions in separately constrained child boundaries when their provider surface permits it. A provider unable to honor the selected profile is ineligible.
- Use standard minimum profiles and require a new reviewed revision/host for authority widening. Reload adopts, rather than recreates, the active host boundary.
- Keep deployment privilege and any namespace-setup privilege in separate minimal typed brokers. Neither accepts arbitrary commands or a root container-engine socket.
- Reject work requiring a different-kernel boundary until a conformant microVM or remote isolated-executor profile exists.

## Consequences

Sandbox support becomes a negotiated provider/host capability with visible refusal reasons. Production releases need kernel-specific enforcement tests, resource quotas, egress infrastructure and cleanup runbooks. Some provider versions or workflows will be rejected rather than silently run with a weaker boundary.

The full contract is in [Sandbox management](../sandbox-management.md).
