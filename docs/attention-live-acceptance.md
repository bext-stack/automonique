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
| `hosted_attention_corpus_available` | derived | The deployment actually serves resources, so the cross-client comparison has something to compare. |
| `deployed_build_attribution` | local | Every probed build's running binary appears in a release manifest, so the record can name the revision it accepted. |

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
