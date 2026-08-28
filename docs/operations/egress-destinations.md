<!-- SPDX-License-Identifier: Elastic-2.0 -->

# The destination policy is the run engine's lifeline

`egress-destinations` in the daemon's state directory reads like a security
allowlist, and it is one. It is also the only thing standing between a run and
the provider it has to reach. Removing a required line takes every task run
down. Status and doctor now detect that route mismatch from the running
generation; an individual run refusal still does not name the host.

This page exists because that happened.

## What it cost

On 2026-08-26 the file was pruned from three destinations to one. The two that
went looked like leftovers of the direct Codex run engine that
[#144](https://github.com/bext-stack/automonique/pull/144) had just retired:

```text
chatgpt.com           443  public
developers.openai.com 443  public
```

They were not leftovers. The pinned JCode engine routes on **its own**
configuration, which has nothing to do with the name of the engine we retired:
`jcode-provider/config.toml` carries `default_provider = "openai"`, so a live
run dials `chatgpt.com` with model `gpt-5.6-sol`.

Every run from that moment reached the provider, opened a session, queued a
turn, and answered `provider_fault category=rejected retryable=false` into a
terminal `failed`. Operators saw *"I couldn't complete that answer just now."*
Eleven hours later someone ran a task and went looking.

## The rule

> The destinations this file names are the ones **the configured provider
> actually dials**, not the ones the engine is called after. Read
> `jcode-provider/config.toml` before you decide a line is obsolete.

The provider's own log is the only place the truth is written down:

```sh
tail -n 200 "$STATE/runs/<run>/workspace/.jcode/logs/jcode-$(date -u +%F).log"
```

A refused destination appears there as `error sending request for url (…)` or
`failed to lookup address information: Temporary failure in name resolution`,
and in `provider-journal.sqlite3` as
`provider_requests.failure_reason = 'provider_refused'`.

## Editing it applies at the next generation, not at the next run

`ExecutionLane::open` loads the policy **once, when the daemon starts**, and the
comment there says why: what a run is admitted against is the policy this daemon
started with, not whatever the file said at the instant a request arrived. That
is the right rule and it is not going to change.

The consequence for an operator is that restoring a deleted line changes
nothing on its own. The daemon has to reach a new generation:

```sh
# A second manifest digest from the same artifacts is enough: the digest is
# derived from the plan digest, so only --plan-digest has to differ.
PLAN="sha256:$(printf 'egress-restore-%s' "$(git rev-parse HEAD)" | sha256sum | cut -d' ' -f1)"
./rust/target/release/automonique-release build \
  --state-dir "$STATE" --worktree "$PWD" --plan-digest "$PLAN" \
  --changed-path rust/crates/automonique-daemon/src/execute.rs
"$STATE/bin/automonique" reload sha256:<manifest-digest> --wait
```

A restart works too. Either way, confirm with a run rather than with the file:
an escalated `ask` that reports `route=operational_jcode` and a run that reaches
`state=completed` is the proof.

## What status and doctor now tell you

The daemon evaluates JCode's bounded `config.toml` against the destination
snapshot its execution lane admitted at startup. It fails closed for an
unknown route, unreadable configuration, partial route, wrong scope, or a
non-empty policy that belongs to another provider.

- `automonique status` prints `provider available: 1` only when the sandbox,
  executable configuration, selected JCode route, and every required admitted
  destination agree. It prints `0` for the outage described above.
- `automonique doctor` reports `provider.route-unavailable` as a finding from
  that same live snapshot. It never rereads the file and therefore cannot call
  an unapplied edit healthy.

The remaining diagnostic gap is per-run detail: the typed provider fault still
carries `category=rejected` without the destination. The provider log remains
the place to identify that host until the broker/provider protocol preserves it
in a bounded safe field.

## The Anthropic route is not a failover

`platform.claude.com` and `api.anthropic.com` are not in the policy either, so
the JCode OAuth token in `jcode-provider/auth.json` cannot be refreshed from
inside a run:

```text
OAuth token refresh failed: error sending request for url
  (https://platform.claude.com/v1/oauth/token): client error (Connect):
  tunnel error: unsuccessful
```

Production has not noticed because `default_provider = "openai"` never asks. The
consequence is worth stating plainly: **there is one working route and nothing
behind it.** This implementation does not widen the policy. If an operator
selects `anthropic`, readiness requires both `api.anthropic.com:443` and
`platform.claude.com:443` under `public`; without that explicit grant, status is
`0` and doctor records the route as unavailable rather than presenting it as
failover.
