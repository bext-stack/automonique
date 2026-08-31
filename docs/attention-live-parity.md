# Cross-client attention parity, against a live deployment

Epic #163 has two harnesses that stop short of each other.

`tools/run_attention_parity_acceptance.py` replays a fixture corpus through
ShellDeck, the hosted cockpit and Automonique Mobile and proves they agree.
`tools/run_attention_live_acceptance.py` probes a deployment and proves it
answers, gates and advertises what the source says it should. Between them sits
the claim nobody was making: *the three clients agree about what the deployment
is serving right now.* Parity was proven on a fixture; the live run read the
deployment but never put what it read through a client.

`tools/run_attention_live_parity.py` closes that. It takes the attention read a
deployed entry actually serves and runs it through the three clients' real
production reducers.

## The three lanes

| Client | Reducer | How it is reached |
| --- | --- | --- |
| ShellDeck | `crates/shelldeck-core/src/config/platform_attention.rs` | `tools/parity/shelldeck_live_replay`, a driver built against the ShellDeck checkout the operator names, with the `automonique-protocol` revision that checkout pins |
| hosted cockpit | `rust/crates/automonique-web-entry/src/platform_cockpit.rs` | not replayed. `POST /api/platform/cockpit` on the deployment *is* that reducer's live output |
| Automonique Mobile | `src/core/attention-source-{board,inventory,projection}.ts` | `tools/parity/mobile_live_replay.mjs`, loading the mobile checkout's own sources and its vendored `@automonique/sdk` |

Neither driver decides anything. They decode, call, and print. A driver that
re-derived a source inventory or a revision chain would be a second
implementation agreeing with itself, which proves nothing.

The hosted lane has no driver on purpose. The deployment is already running
`platform_cockpit.rs`; asking it is strictly better evidence than replaying a
copy of it here.

## Where the live bytes come from

`sdk/rust/platform-client/examples/attention_live_capture.rs` performs the read
with `automonique-platform-client` — the production client — over HTTPS with the
operator Basic credential, against `POST /api/platform/v2`. Nothing in Python
can build a canonical Platform v2 envelope without becoming a second copy of the
codec, so the reading is done where the codec lives.

Canonical bytes are carried through the pipeline as base64 and **never
re-serialized**. Each client decodes the deployment's exact bytes with its own
production decoder: `decode_work_context_page` and
`decode_attention_source_snapshot` on the ShellDeck side,
`decodeWorkContextPage` and `parseCanonical` on the Mobile side. Re-serializing
would make this harness, not the deployment, the author of what the clients
decode.

### How the read is addressed

Two arguments on the capture are load-bearing, and each was once absent in a
way that turned a fact about *how the harness asked* into a published fact
about the deployment.

`--project`. The Platform v2 wire has no project-less `query_work_contexts`:
`request_body` in `platform_v2_transport.rs` refuses to encode one. Without a
project the client's own encoder rejects the request, it never reaches the
network, and the capture records `{"state": "error", "category": "protocol"}` —
which is indistinguishable, in the report, from a deployment answering badly.
The harness takes the project from the deployment's own cockpit answer
(`projects[].id`) so the coordinate is one the deployment named; `--project`
overrides that. The capture example now refuses to run a live read without one.

`--host-header` / `--forwarded-proto`. `--hosted-loopback` sends the read to
`127.0.0.1`, and a web entry that answers only for its canonical name over TLS
answers `400` to that. The Python cockpit read has always carried both headers;
the capture could not, so `--hosted-loopback` silently meant "the lane check
cannot run" while reporting `unexpected_status` — read, reasonably, as the
deployment refusing its lane. `HttpsTransport::with_loopback_origin` supplies
them, and is gated to loopback `http://` endpoints: a `Host` a client chose for
itself is a claim about which deployment it is talking to, and on a public
origin that is name spoofing rather than a probe.

### Why the status is recorded

A refusal category is not a diagnosis. `unexpected_status` is the client's one
word for a `503` from a deployment whose daemon is restarting, a `404` at a
route that is not deployed, and the `400` above. Those are three different
findings and only one of them is about the attention lane, so
`HttpsTransport::last_exchange()` keeps the status and content type of the last
answer and the capture records them beside the category. The report then says
which happened: a deployment that answered `503` *was not reached*; one that
answered `400` was reached and said the request was addressed wrongly; only a
typed Platform v2 refusal is reported as the deployment refusing its lane.
Nothing from the request side — where the credential is — is observed.

One adapter remains and is named where it lives: the vendored SDK exposes no
standalone attention-snapshot decoder — a snapshot only ever arrives inside a
response envelope the transport owns — so `mobile_live_replay.mjs` parses the
canonical bytes with the SDK's own `parseCanonical` and maps the resulting tree
onto the snapshot interface field by field. It invents no field.

## The control, and why there is one

Three clients that decode nothing and show nothing agree perfectly. That failure
mode looks exactly like success, so no live comparison is reported until every
driver has reproduced a known-answer control: a real work-context graph and a
real two-generation succession, built with the same encoders the live capture
uses (`--control`). A driver that is not actually driving its client's reducer
cannot reach generation 2 with both items visible.

If the control does not run through every driver, the report is `blocked`, not
`passed`, whatever the live comparison said.

## What is compared

Per source: the derived inventory, the availability status and its category, the
generation, and the visible item set in order.

Not compared: the order a client holds its source inventory in, and the global
ordering of visible items across sources. The shared corpus states its
expectation per source and does not fix either, so neither is a parity claim
here. ShellDeck orders sources by kind and Mobile alphabetically; that is a
presentation choice, not a disagreement about authority.

Each dimension is compared only across the clients that can express it, and
`compared_by` on every verdict names who took part. The hosted cockpit is why:
its live answer is an inbox of *items*, so a source it inventoried, read and
found empty looks from outside exactly like a source it never had. It therefore
takes part in the item and generation comparison and not in the source-inventory
or per-source status comparison, which is between ShellDeck and Mobile.
Comparing its source set against theirs would report a disagreement about the
cockpit's wire shape every time a workspace held an idle source, and call it a
disagreement about attention. A dimension no two clients can speak to is
`not_exercised`, not agreement.

## What `not_exercised` means

`live_succession_parity` compares successive live reads. If the deployment
served the same generation for every read in a run, no succession happened and
nothing about convergence was proved. That is reported as `not_exercised` with
the reason, never as a pass: a convergence check that cannot fail is worse than
an absent one.

The same applies to the inventory and projection comparisons when the deployment
serves no attention at all.

A read that *failed* is not an empty graph, and the two are reported
differently. `work_context_reason` says "was read and names no user workspace"
only when the read succeeded; a read that errored or was refused says "none was
obtained", with its category and, where there was one, the HTTP status. The
earlier wording said the graph named no workspace whatever had happened, which
sent an operator looking for a missing workspace that was in fact there.

## Reading the outcome

`live_verification.state` is one of:

- `failed` — clients disagreed, or a driver did not reproduce the control.
- `blocked` — an observation could not be made, or the control did not run.
- `partially_exercised` — everything that could run passed, and the deployment
  did not supply the data the rest needed. The unexercised checks are named.
- `complete` — every live cross-client comparison ran and the clients agreed.

## Redaction

Identifiers observed live — projects, workspaces, attention sources and items —
are recorded as digests salted once per run. Equality inside one report is the
entire comparison and survives; the identifier does not, and a fresh salt each
run keeps a short workspace name from being recovered by guessing. Refusal
categories are admitted only as bare `[a-z0-9_]` tokens; anything else is
withheld. The operator's home directory is written as `$HOME`.

Credentials reach the harness by variable *name*. No value is read, logged, or
recorded, by this harness or by the capture example.

## Running it

```bash
AUTOMONIQUE_OPS_BASIC_AUTH='user:password' \
python3 tools/run_attention_live_parity.py \
  --shelldeck-root /path/to/shelldeck \
  --mobile-root /path/to/automonique-mobile \
  > parity.json
```

The first run builds the ShellDeck driver against `shelldeck-core`, which takes
a while and needs network for the pinned protocol revision. `--scratch-dir`
puts the rendered manifest and the cargo target directory somewhere reusable.

Then feed the report to the acceptance harness, which is the only place the
question "does this deployment serve any attention at all" is now answered:

```bash
python3 tools/run_attention_live_acceptance.py \
  --attention-parity-report parity.json \
  ... > acceptance.json
```

## What this does not do

It never marks an operator step satisfied. LIVE-GUI-1..4 stay
`awaiting_operator` in `run_attention_live_acceptance.py`, which still owns the
checklist and is not shortened by anything here. LIVE-GUI-2 is the step where
the most has been subtracted, because `--cockpit-render-check` in that harness
observes the deployed page rendering the source and generation its projection
carries, and this harness checks that projection against the other two clients.
The two meet at the projection and never at a person: what is left is that one
human saw the same item on two screens in one sitting. What this harness produces is a
per-step statement of which part of the step a machine now checks against the
deployment and which part is left, under `operator_steps` in its own report and
under `residue_after_automation` in the acceptance report. Subtracting is not
signing.

It reads. It never acts on a deployment, so it never causes the item retirement
LIVE-GUI-4 is about, and its "convergence" is convergence of reducers over reads
it issued — not of three running clients refreshing themselves.

## Finding of 2026-08-30

The first live run recorded `platform_v2_web_binding_unavailable`: both the
hosted and non-production entries refuse the Platform v2 attention lane at
negotiation, because no `platform-v2-policy.json` exists in either daemon state
directory. The deployments serve **no attention snapshot at all**.

That matters twice.

The cross-client GUI steps cannot be run against a deployment with no attention
item, so the acceptance report is `blocked` rather than `automated_only` until
one is served.

And it exposed a check that looked like a fence and held nothing. The acceptance
harness's `hosted_attention_corpus_available` concluded, from a populated
Platform *v1* resource inventory on `/api/platform`, that the deployment served
an attention corpus. Attention is a Platform *v2* read that `/api/platform` does
not touch, so the check passed against 48 v1 resources and zero attention. It
has been split: `hosted_v1_resource_inventory_available` now answers only for
what it observes, and `hosted_attention_corpus_available` reads this harness's
report, where the question can actually be answered.

## Finding of 2026-08-31

Platform v2 was bootstrapped on the non-production deployment, and the lane
still reported `blocked` with `unexpected_status`. The bridge was not the
cause; three separate things were, and each of them was a way this harness
could name a deployment for a fault that was not the deployment's.

**The loopback probe could not carry a host.** `read_lane()` dropped the
`--hosted-host` and the forwarded scheme that `--hosted-loopback` exists to
supply, and the capture example had no option to accept them. The entry answers
`400` to a request addressed to `127.0.0.1`, so `--hosted-loopback` silently
meant "this check cannot run" — reported as the deployment refusing its lane.

**The work-context read could not be encoded.** The capture walked
`query_work_contexts` with no project, which the Platform v2 wire cannot
encode; the request never left the client and the capture recorded
`{"state": "error", "category": "protocol"}`. The harness then reported *"the
deployment's work-context graph names no user workspace"* — about a graph it
had never obtained, and about a workspace that was in fact there.

**A restarting daemon looked like a refused lane.** Measured on the
non-production deployment: restarting the daemon behind the entry makes the
same lane answer `503` — `platform_v2_bridge_unavailable`, the category
`platform_v2_bridge.rs` returns when the admin socket does not answer — which
the client reports as `unexpected_status`, the same word it uses for the `400`
above. Sampled across two restarts, two reads out of forty come back
`{"state": "error", "category": "unexpected_status", "http_status": 503}` and
every other read negotiates. Nothing about the lane changed. That is why the
status is now recorded, and why `lane_reason` says "refuses its attention lane"
for nothing but a typed Platform v2 refusal.

With all three addressed, the non-production deployment serves the lane and the
three cross-client comparisons run: `live_source_inventory_parity` and
`live_projection_parity` pass, and `live_succession_parity` is `not_exercised`
because an idle deployment serves the same generation for every read.
