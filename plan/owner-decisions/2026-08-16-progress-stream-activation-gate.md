<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Progress streaming lands complete but inert — activation is one owner-gated flag

**Status: PENDING OWNER ACTION as of 2026-08-16.** The normalized
progress-event stream (improvement-program issue **#36**, M6) is built, tested,
and merged. It captures, normalizes, persists, and replays a provider run's
progress. It does **nothing** on a production `/run` today, on purpose, because
turning it on changes the provider invocation for every run and that change
cannot be validated in this offline environment.

This is a decision record, not an authorization to build on. It exists so a
reader can tell "shipped and switched off deliberately" from "unfinished".

| Field | Value |
|---|---|
| What landed | ProgressFrame vocabulary (`automonique-protocol/src/{event.rs,progress_api.rs}`), a refusal-first normalizer projection (`automonique-agents`), best-effort spool persistence + observed-sequence accounting (`automonique-runner`), a bounded per-attempt replay ring (`automonique-daemon/src/progress_hub.rs`), and `automonique runs tail <spool-root> <run-id> [cursor]` |
| Why it is inert | Capture is gated on `execute::emits_normalized_stream(spec)`, which scans the run's argv for `PROVIDER_JSON_STREAM_ARG` (`--json`). `compose.rs::DEFAULT_ARGV` does **not** contain `--json`, so the gate is false, stdout stays `inherit()`, and no reader thread spawns. Production behaviour is byte-for-byte unchanged |
| How to activate | Add `--json` to `DEFAULT_ARGV` (or an `arg=` line in `provider.conf`). That one line flips the gate true for every provider-profile run |
| The flag exists | `codex exec --help` on the installed CLI shows `--json  Print events to stdout as JSONL`. The `automonique-agents` normalizer already models codex's `thread.*/turn.*/item.*` JSONL grammar |
| Why not flipped here | (1) It changes the reviewed provider invocation for **every** production `/run`, on the live daemon just recovered from the 2026-08-15 poller outage. (2) The installed CLI is **codex-cli 0.147.0**, two minors ahead of the repository pin **0.146.0**; the JSONL grammar cannot be confirmed against either without a real (network- and auth-bearing, token-spending) turn |
| Blast radius if activated wrong | Bounded to progress rendering. Capture is best-effort and every append is swallowed on any error, so a JSONL grammar the normalizer rejects poisons the *preview stream* and nothing else — the answer still returns through the `-o {answer}` file, and the run's outcome is unaffected. One `ProviderWarning` frame records the silence |

## The activation checklist, stated exactly

Before adding `--json` to the production argv:

1. **Reconcile the version pin.** Decide whether production runs codex 0.146.0
   (the pin) or a newer CLI, and make the installed binary match the decision.
   This is improvement-program issue **#44** (M7, "refresh provider inventory
   pins"); widening drift (0.146.0 → 0.146.1 → 0.147.0) is now recorded there.
2. **Validate the grammar with one real turn.** Run the chosen codex with
   `exec --json` against a trivial prompt and confirm the emitted JSONL parses
   through `automonique-agents`'s `ProviderEventStream` without poisoning —
   i.e. the `thread.*/turn.*/item.*` events map to `EventKind` variants and the
   terminal `result` arrives. The normalizer is refusal-first, so a grammar
   mismatch is visible immediately as a single `ProviderWarning`, not a silent
   wrong render.
3. **Flip the flag** and watch one live run's spool with `automonique runs
   tail`, confirming Recorded frames chain and the answer-file contract still
   holds.

## What this record does *not* say

- It does **not** claim #36 is incomplete. The stream is finished; only its
  production ignition is deferred, and deliberately kept to a single line so the
  deferral costs nothing to reverse.
- It does **not** license flipping `--json` without steps 1–2. The reason it is
  off is that those steps need a live provider this environment does not have.
- It does **not** apply to the CLI `runs tail` path, which reads the durable
  spool directly and works today for any run whose argv already carries the
  flag (tests drive it with a scripted provider).
