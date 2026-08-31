# Cross-client attention live acceptance

Epic #163 ends on one milestone that fixtures cannot reach: *run and record the
cross-client live acceptance flow on deployed builds*.
`tools/run_attention_parity_acceptance.py` and
`tools/run_retained_session_acceptance.py` prove that every surface agrees about
a fixed corpus, and both leave `live_verification` at `required_not_run` because
neither talks to a deployment.

`tools/run_attention_live_acceptance.py` talks to one. It closes the part of the
gap that HTTP can close, enumerates the part that only a person at three screens
can close, and refuses to report either as the other.

## What it probes, and why those paths

Every path is read out of the route table in `automonique-web-entry`
(`route()` in `src/lib.rs`), and every schema it asserts is the literal the
corresponding handler serializes. A probe path is a claim about the deployed
build, so a guessed one would make the report fiction.

| Check | Route | What a pass establishes |
| --- | --- | --- |
| `<origin>_platform_operator_gate` | `GET /api/platform` | The deployment answers and refuses an unauthenticated read under `Basic realm="Monique Operations"`. A 200 here is a finding, not a pass. |
| `<origin>_mobile_grant_gate` | `GET /api/mobile/authorization` | The mobile grant surface fails closed under its own `Bearer realm="Automonique Mobile"` rather than inheriting the operator gate. `needs_auth` exempts this route from Basic auth on purpose; the bearer check is what stands in front of it. |
| `<origin>_mobile_discovery` | `GET /.well-known/automonique-mobile` | The build publishes the discovery document a phone reads before it holds any credential, naming the protocol, supported versions, origin, and `server_identity`. |
| `hosted_loopback_liveness` | `GET /healthz` with `Host: localhost` | The process behind the public origin is the one on this host. `handle()` computes `local_health` and exempts exactly this route under `localhost`. Present only with `--hosted-loopback`. |
| `<origin>_attention_projection` | `GET /api/platform` authorized | The attention projection the clients consume, under `automonique.dashboard.platform/v2`. |
| `<origin>_retained_session_read` | `GET /api/mobile/pairing-sessions` authorized | `WebIntegration::platform_sessions()`, under `automonique.dashboard.pairing-sessions/v2` — an authority-qualified session cursor rather than a partial page. |
| `hosted_v1_resource_inventory_available` | derived | The deployment serves its Platform v1 resource inventory, which the cockpit enriches its projection from. This says nothing about attention. |
| `hosted_attention_corpus_available` | `--attention-parity-report` | The deployment actually serves an attention corpus, so the cross-client GUI steps have a live item to agree about. Read from `tools/run_attention_live_parity.py`'s report, the only place the Platform v2 attention lane is exercised. |
| `<origin>_build_identity` | `GET /api/build` authorized | The deployment names, over its own authenticated surface, the source revision it was compiled from, under `automonique.build-identity/v1`. A 404 means the deployed build predates intrinsic self-attribution. |
| `deployed_build_attribution` | local | Every probed build can be attributed to a source revision, and the two accounts of it agree. |

### How a deployed build is attributed

The build is asked twice, because the two answers fail differently.

The binary is asked what it was built from — `--build-identity --json` on the
deployed executable, which prints and exits before the entry parses its
configuration or binds anything. That answer is a literal compiled into the
artifact, so no file laid down beside it, and no deployment procedure that
forgets to update one, can make it wrong. It is `unknown` on a build with no
git metadata and `modified` on a build made over uncommitted changes, and
neither of those is treated as a revision the deployment can be signed off
against.

Then every `manifest.json` under the release root is searched for the digest of
the running binary. That is the only check that says whether this host's release
metadata is still attached to the binary serving traffic — a release directory
whose `bin/` was replaced without moving `current` leaves a manifest that is
internally consistent about a build which is not running.

Either answer resolves attribution on its own. The two disagreeing does not: a
manifest recording these exact bytes while naming another revision is recorded
as `contradicted` and fails, because a well-sourced wrong answer is worse than
no answer.

### Why the corpus question moved

`hosted_attention_corpus_available` used to be derived from `/api/platform`: a
populated resource inventory was read as evidence that the cross-client GUI
steps had something to compare. It is not. `/api/platform` is the Platform *v1*
projection — nodes, clients, runs, sessions — and attention is a Platform *v2*
read that projection never touches. On 2026-08-30 the deployment served 48 v1
resources and refused every attention read with
`platform_v2_web_binding_unavailable`, and the check passed. It was a fence that
held nothing.

The v1 observation now answers only for v1, under its own name. The corpus
question is answered by `tools/run_attention_live_parity.py`, which reads the
attention lane with the production client, and this harness reads that report
via `--attention-parity-report`. Without the report the question was never
asked, and the check is `blocked` — which is the honest state, because an
operator cannot compare three screens against attention nobody has established
exists.

When the lane did not answer, this check carries the parity report's own reason
and its HTTP status rather than restating a refusal. The difference matters
most here: this report gates the GUI steps, and "the deployment does not serve
its attention lane" is a claim about the deployment, while a `503` from a
restarting daemon and a `400` from a request addressed to the wrong host are
claims about the moment and about the harness. See "Finding of 2026-08-31" in
`docs/attention-live-parity.md`.

`inventory.state` on that projection means a scoped read succeeded, not that
the whole inventory fit in one response. The projection names the coordinates
it needs (the serving node, the action catalogue, and the run behind each
listed session) because an unscoped request means *everything* and is refused
with `snapshot_too_large` once the inventory outgrows one response. The
projection says so in `inventory.scope`, which reads `named`.

## Reaching the gate

The hosted entry is fronted by Cloudflare, which answers 403 to the standard
library's default `Python-urllib/*` User-Agent. That reads exactly like the
deployment refusing the probe, so the harness names itself instead.

On loopback, `route()` dispatches only for the canonical host or `localhost`,
and `handle()` turns a canonical-host request without `X-Forwarded-Proto: https`
into `Route::HttpsRedirect`. `--hosted-loopback` sends both, so the probe
reaches the gate rather than a 421 or a 308.

The non-production mobile endpoint is a quick tunnel whose hostname is re-rolled
on every restart and rewritten into the non-production web entry's
`dashboard-integration.conf`. The harness discovers it from that file rather
than from a name baked into the source, and marks the recorded run reproducible
only while that tunnel instance lives.

## Credentials

Credentials are passed by *variable name*, never by value:

```bash
AUTOMONIQUE_OPS_BASIC_AUTH='user:password' \
python3 tools/run_attention_live_acceptance.py \
  --hosted-web-entry-root "$XDG_STATE_HOME/automonique/web-entry" \
  --nonprod-web-entry-root /path/to/nonprod/web-entry \
  > report.json
```

The hosted and non-production entries have different operator credentials, so
they have separate variables (`--credential-env`, `--mobile-credential-env`).
Without one, the reads behind that gate are `blocked` — never `passed`. The
report records the variable name and whether a value was present, and nothing
else about it.

## What reaches the report

Only allow-listed fields of the types the web entry serializes, gated at every
depth. Free text the daemon supplies (`summary`, `explanation`) and live work
coordinates (`id`) are not on the list; `explanation` is admitted only when it
is a bare category token such as `snapshot_too_large`. The web entry now
applies that same rule at the source, so a refusal reaching this report has
already been reduced to a token or withheld once. Identical list
projections collapse — redaction removes what made them distinct — with the true
length under `observed_counts` and the collapsed length under
`<name>.distinct_projections`. The operator's home directory is written as
`$HOME`.

`tools/test_run_attention_live_acceptance.py` holds those guarantees in place.

## The half a person has to do

Four steps are claims about GUIs rendering, and no HTTP probe establishes them:

- **LIVE-GUI-1** ShellDeck re-resolves the attention coordinate to a pane it is
  currently authorized for.
- **LIVE-GUI-2** The hosted cockpit renders the same item with the same source
  and generation, asserting no review state the source did not.
- **LIVE-GUI-3** The phone opens the generation-bound deep link, lands on the
  same session, and refuses a superseded generation.
- **LIVE-GUI-4** Retiring the item from one client converges the other two
  without a manual refresh, and a retention gap surfaces as an explicit
  resynchronization.

Each one carries a `residue_after_automation` field naming what is left of it
once everything `tools/run_attention_live_parity.py` checks against the
deployment is subtracted. That field is documentation, not a discount:
subtracting is not signing, no automated result moves a step, and the checklist
has exactly the four steps it always had.

They stay `awaiting_operator` until `--operator-signoff` names a file that
declares `automonique.attention-live-acceptance-signoff/v1`, names an operator
and an instant, and signs off every step. Copy
`tools/fixtures/attention-live-acceptance-signoff.example.json`; as shipped it
signs nothing off, so a template left in place can never read as a sign-off. A
file naming a step the harness does not define is refused outright, because that
is how a sign-off written against an older checklist silently passes a newer one.

## Reading the outcome

`live_verification.state` is one of:

- `failed` — the deployment contradicted a contract the harness checks.
- `blocked` — an observation could not be made, or was made and cannot support
  the acceptance.
- `automated_only` — every automatable check passed, the GUI steps are unsigned.
  This does not close epic #163.
- `complete` — everything above, plus a sign-off.

`passed` is true only for `complete`, and the exit status is non-zero for
anything else.
