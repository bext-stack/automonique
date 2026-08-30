<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Cockpit render-proof document provenance

`cockpit-render-proof-v1.json` exists for one purpose: to prove that
`tests/browser/live-cockpit-attention.spec.js` can fail. That check runs against
a deployment, where the document is whatever the deployment serves. A proof run
needs a document that is not the deployment's, and a document written by hand
beside the check would agree with whatever the check's author misunderstood, and
would keep agreeing after the projection it claims to represent had moved on.

So the two parts the check actually asserts on are not authored here.

* `inbox` is the output of this crate's own
  `platform_cockpit::attention_inbox()` and
  `platform_cockpit::collection_projection()`, applied to
  `automonique-protocol/fixtures/platform-v2-attention-v1.json` **verbatim** —
  no field of that fixture is overridden. The workspace passed to the projection
  is the fixture's own `user_workspace`.
* `review.document` is the `needs_you` case input of
  `automonique-protocol/fixtures/platform-v2-render-conformance-v1.json`,
  byte-for-byte. That corpus is the shared render authority all three clients
  are held to.

`platform_cockpit::tests::cockpit_render_proof_document_is_projected_not_authored`
makes both immutable: it re-runs the projection and re-reads the corpus and
requires this file to reproduce them exactly. Changing either producer fails
that test until this document is regenerated, so it cannot quietly drift into
being a hand-written stub.

Everything else in the file is scaffolding: one project, one host, one
workspace, one retained session, an empty activity collection, and the
lifecycle and review action families switched off. None of it is asserted by
the browser check. It exists only so the cockpit can select a workspace and
reach the Activity surface, and it is visibly synthetic.

## What this document is not

It is not a capture of production traffic, and it makes no claim to be one. No
credential, customer datum, real session, or real infrastructure identifier was
used to produce it. It is representative of one shape: a single
`provider_session` attention source with one `needs_you` item, and an available
review document. It is not exhaustive over attention source kinds, refusal
states, or collection coverage, and a live run remains the first test of the
document the deployment actually serves.
