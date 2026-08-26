<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Identity-bound egress

A destination allowlist answers "may this workload reach the provider?". It
cannot answer "*as whom?*". The documented 2026 exfiltration pattern turns that
gap into an exit: an injected instruction persuades a workload to `POST` the
workspace to the **legitimate, allowlisted** provider host under a credential
the attacker supplied. Every destination check passes, because the destination
was never the problem.

Identity-bound egress closes it by taking the credential out of the sandbox.
The workload is given a per-session **sentinel** and a base URL pointing at a
loopback endpoint the broker owns; the broker substitutes the real credential
only for a request carrying that session's own sentinel, and refuses anything
else before it resolves or dials a thing.

**The mechanism is built and tested; the flag is off, and no deployment surface
turns it on yet.** What remains before it can be is in
[What is not enabled, and why](#what-is-not-enabled-and-why) — the short version
is that the pinned provider engine authenticates with an OAuth subscription
token that its own documentation says a base-URL override cannot redirect.

## The rule

> While a session's identity is bound, the substituting loopback endpoint is the
> **only** route to the provider host. A `CONNECT` naming that host is refused,
> and a request to the endpoint that does not carry this session's sentinel is
> refused before any packet leaves the host.

Both halves are load-bearing. Without the second there is no substitution; and
without the first the substitution is decoration, because a workload would
simply tunnel to the provider and negotiate its own TLS inside an opaque
`CONNECT`, carrying whatever credential it liked past a broker that never looked.

## What is enforced, and where

| Decision | Where it lives |
| --- | --- |
| A sentinel is `amq-egress-session-` plus 64 lowercase hex digits — 32 bytes read from `/dev/urandom`, with no fallback to a weaker source. It is compared in constant time, because the workload may present as many guesses as it likes and an early-returning comparison would leak it a byte at a time. `Debug` redacts it and `Drop` zeroizes it. | `automonique_egress_broker::identity::SessionSentinel` |
| The real credential is held by the supervisor as a `ProviderCredential` — a scheme (`x-api-key` or `Authorization: Bearer`) and a secret. Construction refuses an empty or over-long secret, and any byte that is not printable ASCII: a secret carrying `CR` or `LF` would inject header lines into every forwarded request. `Debug` redacts it and `Drop` zeroizes it. | `automonique_egress_broker::identity::ProviderCredential` |
| A configured identity binds one upstream `Destination` to one sentinel and one credential. That destination lives **only** here and never in the `CONNECT` allowlist; a configuration naming it in both is refused before the broker binds, with `BrokerError::IdentityHostAlsoTunnelled`. The same contradiction is refused a second time at admission, so a run never reaches the broker to be refused there. | `automonique_egress_broker::identity::ProviderIdentity`, `BrokerConfig::validate`, `automonique_runner::admission::AdmissionContext::new` |
| A broker with an identity binds a **second** loopback listener on its own kernel-assigned port. `provider_base_url()` is `http://127.0.0.1:<that port>`; `sentinel_token()` is what the workload is given. A broker without an identity binds nothing extra and behaves exactly as it always did. | `automonique_egress_broker::EgressBroker::start` |
| Requests on that endpoint are origin-form only. `CONNECT`, absolute-form targets, a lowercase method, a version other than `HTTP/1.1`, obs-folded or colon-less header lines, bare `CR`/`LF`, a repeated or malformed `Content-Length`, and any `Transfer-Encoding` are each refused rather than repaired — the same rule the `CONNECT` parser follows, for the same reason. Ceilings: 16 KiB of head, 64 header lines, 8 MiB of request body. | `automonique_egress_broker::substitute::ProviderRequest` |
| The credential check accepts the sentinel under either spelling, refuses a request carrying none (`401`), refuses one carrying a credential that is not the sentinel (`403`), and refuses one carrying **two** credentials (`403`) rather than picking which foreign key to ignore. Every one of these is decided before resolution and before any dial. | `ProviderRequest::authenticate` |
| The forwarded head is rebuilt field by field from parsed values, never spliced. `Host` is derived from the broker's own destination; `Connection: close` is imposed; and `authorization`, `x-api-key`, `expect`, and every hop-by-hop name are dropped **unconditionally**, so exactly one credential — the substituted one — leaves the host. | `ProviderRequest::upstream_head` |
| The forward path resolves once, filters the resolved addresses by the destination's `AddressScope`, and dials one of those materialized addresses — the same sequence the tunnel follows, so a name that answers differently on a second lookup cannot move the connection after the scope check passed. | `automonique_egress_broker::serve_provider` |
| A public destination is reached over rustls against the compiled-in webpki root set. A loopback destination is reached in the clear, because it never leaves the host; `AddressScope::requires_transport_security` is the single place that decision is written. | `automonique_egress_broker::substitute::Upstream::establish` |
| The response is **not parsed**. Every byte is copied to the workload through one fixed 16 KiB buffer, flushed after each read, until end of stream. A server-sent-event stream, a chunked body and a `Content-Length` body are the same thing here: bytes, in order, as they arrive. | `automonique_egress_broker::substitute::stream_response` |
| Every refusal is typed, counted, recorded in a bounded 64-entry ledger (with a sequence number, so a truncated ledger still shows what it dropped), and named to the client in an `x-automonique-egress-refusal` header whose value is always one of a fixed set of spellings. The ledger holds **no** payload — never a presented credential, not even truncated. | `automonique_egress_broker::identity::RefusalLedger`, `Shared::refuse_identity` |
| A launch is pointed at the endpoint only through `AdmittedLaunch::with_provider_identity(endpoint, sentinel)`, which adds exactly one `allow_connect_port` and two variables — the binding's base-URL name bound to `http://<endpoint>`, and its credential name bound to the sentinel. No socket grant, no bind port, no filesystem grant, and no provider credential. A sentinel that is not one is refused: a caller that handed a workload an empty string, a placeholder, or the real credential would have built exactly the arrangement this feature prevents, invisibly. | `automonique_runner::admission::AdmittedLaunch::with_provider_identity` |
| The flag is `AdmissionContextParts::provider_identity`, whose `Default` is `Disabled`. A launch whose spec denies egress gets no binding whatever the context asked for — a workload with no broker has nothing to be identity-bound to — and `with_provider_identity` then refuses to attach one. | `automonique_runner::admission::ProviderIdentityPolicy` |

## Why this crate now links a TLS library

`automonique-egress-broker` was dependency-free, and `relay.rs` says why: a
proxy that moves opaque bytes needs no parser and no key, and "cannot silently
become a man in the middle without the change being visible as *this crate
suddenly needs a TLS library*". That sentence has now been cashed. The
dependency is deliberate and the visibility is the point.

It is still not a man in the middle. A man in the middle intercepts a TLS
session the client believed was end to end; here the workload never establishes
one. It speaks plain HTTP to a loopback port that belongs to the supervisor,
exactly as configured, and the supervisor makes its own session onward. **No
certificate authority is minted, no certificate is forged, and nothing the
workload trusts is altered.** The `CONNECT` tunnel is untouched: it still
carries ciphertext the broker cannot read, and `relay.rs` still has no key.

`rustls` is pinned to the `ring` provider — the one already vendored for this
workspace — so the direct dependency adds no new transitive crate. The only
`Cargo.lock` change is the broker's own dependency list.

## What is not enabled, and why

Two things are missing, and neither is code that was skipped.

**1. There is no supervisor-held provider credential to substitute.** Every
credential in this system is a file below the provider's own home, reached by a
Landlock grant, and `compose.rs` says so twice in as many words: *"no secret is
copied into the environment or the run document"*, and `credentials:
CredentialDescriptors::declare(&[])`. Nothing in the daemon holds a provider
secret as a value. Building that surface is a design decision an owner should
make deliberately, not a side effect of this change.

**2. The pinned engine's OAuth route cannot be redirected.** The live pin is
`engine=jcode` with `arg=api-stdio`, authenticating from an `auth.json` in its
granted home. The engine's own embedded documentation is explicit:

> For direct environment-based configuration, `ANTHROPIC_BASE_URL` overrides the
> non-OAuth Messages endpoint and `ANTHROPIC_AUTH_TOKEN` is sent as a bearer
> token. **Claude OAuth traffic always continues to use Anthropic's official
> endpoints.**

So the knobs exist — `ANTHROPIC_BASE_URL` / `ANTHROPIC_AUTH_TOKEN`, or the
fork's `JCODE_ANTHROPIC_API_BASE` / `JCODE_ANTHROPIC_API_KEY`, and plain `http://`
to `127.0.0.1` is accepted where a public plain-HTTP base URL would be refused —
but they do not apply to the credential this deployment actually uses. `claude`
(OAuth) and `anthropic-api` (API key) are two *providers* in that engine, not a
fallback chain, and under the default `--provider auto` an OAuth account in
`$JCODE_HOME/auth.json` is selected ahead of any API-key environment variable.

Pointing the pinned engine through the override therefore means selecting the
non-OAuth route — `--provider anthropic-api`, or a `type =
"anthropic-compatible"` named profile with a `base_url` — which means giving up
the subscription credential the fleet runs on and paying per token instead.
**That is an owner decision about billing, not an implementation detail**, and it
is why the flag ships off.

Note also that `ProviderConfig::load` accepts only `engine`, `binary`, `home`,
`version` and repeated `arg`; there is no `env=` key. When the flag is turned
on, the two variables reach the workload through
`AdmittedLaunch::with_provider_identity` and not through the pin file — which is
also what keeps them out of the document, where a plan refuses one name bound
twice.

### The order to turn it on

1. Decide where the supervisor's provider credential comes from, and add that
   surface. It must never become a `LaunchPlan` variable.
2. Decide the engine's auth mode. If the answer is the API-key route, the
   binding is `ProviderIdentityBinding::new("ANTHROPIC_BASE_URL",
   "ANTHROPIC_AUTH_TOKEN", …)` with `CredentialScheme::BearerToken`, plus the
   `arg=` lines that select that provider.
3. Add the deployment surface that sets `AdmissionContextParts::provider_identity`
   to `Enabled`, and remove the provider host from the `egress-destinations`
   policy file in the same change — the two are refused together on purpose.
4. Prove it against the live engine before trusting it. Until a real
   `api-stdio` session has completed through the override, the only proof that
   exists is the hermetic one below.

## What the tests prove

| Test | Property |
| --- | --- |
| `a_sentinel_bound_request_reaches_the_provider_with_the_real_credential_substituted` | The provider receives the supervisor's credential, exactly one credential header, the body intact, and the broker's own `Host`. The sentinel does not leave the host. |
| `a_foreign_credential_is_refused_with_a_typed_error_and_never_dials_the_provider` | **The acceptance.** A foreign key is refused `403` with the typed refusal, and the provider's accept counter reads `0` — no packet, not merely no answer. |
| `a_request_with_no_credential_at_all_is_refused_before_any_dial` | `401`, typed, provider untouched. |
| `a_sentinel_beside_a_foreign_credential_is_refused_rather_than_resolved` | Two credentials are refused; the foreign one never gets to be the one forwarded. |
| `a_connect_tunnel_to_the_provider_host_is_refused_while_an_identity_is_bound` | The tunnel is closed to the provider host on **any** port, ahead of the allowlist decision, with a non-empty allowlist present so the refusal is the identity's. |
| `an_allowlist_naming_the_identity_host_is_refused_before_the_broker_binds` | The contradictory configuration does not start. |
| `an_empty_allowlist_still_refuses_every_tunnel_while_an_identity_is_bound` | The fail-closed lock still holds with an identity bound: refused before any resolution. |
| `a_streaming_response_reaches_the_workload_chunk_by_chunk_rather_than_at_the_end` | The first byte arrives inside one inter-event gap while the whole stream takes at least two — so it was not buffered. |
| `a_head_the_forwarder_cannot_read_is_refused_without_reaching_the_provider` | `CONNECT`, absolute-form, `HTTP/1.0` and chunked requests are each refused with their own typed reason, none of them dialling. |
| `a_broker_with_no_identity_binds_no_provider_endpoint_and_behaves_as_it_always_did` | The off path is the old path. |
| `a_launch_binds_no_provider_identity_unless_a_deployment_asks_for_one` | The default is off, and a launch with no broker gets no binding whatever the context asked for. |
| `an_attached_provider_identity_adds_one_port_and_two_variables_and_nothing_else` | The attachment is asserted against a plan built by hand — one port, two variables, nothing more — and a second attachment is refused. |
| `an_endpoint_or_sentinel_that_is_not_one_is_refused_before_it_enters_a_plan` | A non-loopback endpoint, a zero port, and a token that is not a sentinel are each refused. |
| `a_binding_that_would_fight_another_attachment_is_refused_when_it_is_built` | A binding naming `HTTPS_PROXY`, `HTTP_PROXY` or `TMPDIR` is refused at construction, not discovered at attachment. |
| `a_context_cannot_both_tunnel_to_the_provider_host_and_bind_its_identity` | The contradiction is refused at admission too. |
| `the_runner_and_the_broker_agree_on_the_constants_they_each_state` | The two crates that deliberately do not depend on each other still agree on the destination ceiling and the sentinel shape — and a sentinel the broker actually mints is one the runner actually accepts. |

## Honest residuals

- **A Landlock network rule names a port, not an address.** The identity grant
  is "port `Q`, anywhere" rather than "the provider endpoint", and a workload
  now has two such ports instead of one. What narrows both is unchanged: each is
  a kernel-assigned ephemeral port on `127.0.0.1`, the workload cannot resolve a
  name (no UDP grant, so no DNS), and it may not bind.
- **The endpoint forwards a request head it parsed.** That is a second HTTP
  parser, and a second parser is where smuggling lives. What bounds it is that
  the head sent upstream is rebuilt from parsed values rather than spliced,
  everything ambiguous is refused rather than repaired, and one request per
  connection means nothing can be pipelined behind a refused one.
- **The sentinel is visible to the workload**, in its environment and in
  `/proc/self/environ`. That is the design: it authorizes nothing off this host,
  at any endpoint but one, after this run ends.
- **A reviewer of the run document cannot see that the identity was bound.**
  The flag lives on the admission context, exactly like `brokered_destinations`
  beside it, and for the same reason: the sandbox spec has no field for it.
  Closing that means a wire change, deliberately not made here.
