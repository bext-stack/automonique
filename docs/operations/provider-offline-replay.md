<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Provider offline replay

Provider journal schema v4 retains two different forms of evidence:

- `provider_requests` keeps the existing digest and, when the producer has it,
  the exact bounded canonical request bytes used on the wire;
- `provider_replay_steps` keeps ordered command/notification pairs under
  `(step_name, occurrence_index, correlation_id)`, plus an optional exact
  `forked_from_step_id` for rerun-from-step lineage.

Each canonical payload is non-empty and at most 1 MiB. A turn holds at most
4,096 replay records. Both bounds are checked by the API and the byte bound is
also a database constraint. These rows may contain prompt or provider content,
so the journal remains private runtime state; diagnostics and metrics must not
render their bytes.

At process admission the journal pins `prompt_version`,
`tool_schema_version`, and `model_id`. A later process for the same attempt and
an offline replay both refuse a changed or legacy-incomplete tuple with
`resume_version_mismatch`. Crossing the tuple requires the caller's explicit
force flag; the historical process row is not rewritten.

`ProviderJournal::offline_replay` performs no provider, network, environment,
or clock operation. It returns an `OfflineReplayTape`. Orchestration dispatches
its canonical commands into that tape and receives the recorded notification
bytes. A reordered step, changed coordinate, changed correlation, changed
command byte, missing notification, or unconsumed suffix fails with
`replay_divergence` at the first one-based record position.

The checked-in synthetic corpus at
`rust/crates/automonique-store/tests/fixtures/provider_replay_v1.txt` is the CI
non-determinism gate. The contained provider-session host tests additionally
prove that real host turn requests and responses produce replayable pairs. No
fixture contains credentials, customer content, or a real provider response.
