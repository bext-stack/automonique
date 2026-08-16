<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Fuzz targets

Coverage-guided fuzzing for the byte-facing decoders: the protocol crate's
canonical JSON, framing and message decoders, and the two platform-inbound
parsers that read a vendor's JSON rather than this project's wire.

## Why this is a separate crate

It is excluded from the nineteen-member workspace in `../Cargo.toml`, and it
declares its own `[workspace]`, for two reasons that are not stylistic:

- **Toolchain.** `cargo fuzz` needs nightly and a sanitizer-instrumented build.
  The pinned stable path must never acquire a nightly dependency, so the whole
  nightly requirement lives behind this boundary.
- **`unsafe_code = "forbid"`.** `libfuzzer-sys`'s entry-point macro emits an
  `extern "C"` symbol. The workspace forbids that, correctly, for shipped code.

The practical consequence is the one that matters for review: `rust/Cargo.lock`
and the lockfile-reproducibility check in CI are untouched by anything in this
directory, and `cargo build/test/clippy --workspace` never sees it.

## Running

```sh
cargo install cargo-fuzz          # once
cd rust/fuzz
cargo +nightly fuzz list          # the five targets
cargo +nightly fuzz run automonique_fuzz_parse_canonical -- -max_total_time=300
```

The five targets:

| Target | Entry point |
| --- | --- |
| `automonique_fuzz_parse_canonical` | `wire::parse_canonical` |
| `automonique_fuzz_decode_frame` | `codec::decode_frame`, then the parser on what it yields |
| `automonique_fuzz_envelope_decode` | `wire::Message` plus all twenty-one typed message decoders |
| `automonique_fuzz_telegram_updates` | `automonique_transports::parse_telegram_updates` |
| `automonique_fuzz_slack_decode` | the nine `automonique_slack_connector::decode_*` functions |

Every target asserts an invariant, not just the absence of a crash — that an
accepted payload was already canonical, that a frame lies inside its input, that
a batch never moves the acknowledged offset backwards. A fuzzer that only looks
for segfaults in safe Rust finds panics and little else; these look for the
decoder agreeing to something it should have refused.

### Replaying the corpus without fuzzing

Cheap enough for a per-PR job, and the check that a seed still decodes the way
it did when it was added:

```sh
cargo +nightly fuzz run <target> -- -runs=0
```

### Scheduled runs

`.github/workflows/fuzz.yml` is the CI shape: a weekly cron plus
`workflow_dispatch` that installs nightly and runs each target for a bounded
time, uploading `artifacts/` on failure. It is what this section used to
describe as intended.

```sh
for target in $(cargo +nightly fuzz list); do
  cargo +nightly fuzz run "$target" -- -max_total_time=300 -max_len=8192
done
```

The workflow puts each target in its own matrix job with `fail-fast: false`, so
a finding names its decoder in the run list and the other four keep fuzzing.
The corpus replay above runs on every pull request that touches this directory
or one of the three crates the targets enter.

Note that `rust/rust-toolchain.toml` pins stable for everything under `rust/`,
this directory included. That is why every command here says `+nightly`
explicitly: without it, cargo resolves the pinned stable toolchain and
`cargo fuzz` refuses.

## Corpora

`corpus/<target>/` is checked in and derives from the protocol crate's golden
fixtures. Regenerate with:

```sh
python3 rust/fuzz/seed_corpus.py
```

The script is idempotent and prints what it wrote. It skips fixtures above
8 KiB: libFuzzer mutates length as readily as content, so a multi-megabyte seed
buys nothing that a small one does not, and the ceiling cases it skips are
covered by `tests/properties.rs`, which generates them on demand.

Both refused and accepted fixtures are seeded. A refusal fixture is a byte
string that reaches deep into a decoder before being turned away, which is the
most productive neighbourhood to mutate in.

`automonique_fuzz_envelope_decode` owns the per-API fixtures
(`admin-command-v1.json` and its four siblings). They are valid input to the
canonical parser too — every one of them runs through it — but checking them in
twice would double the corpus for no extra coverage. To fuzz the parser with
them, pass both directories:

```sh
cargo +nightly fuzz run automonique_fuzz_parse_canonical \
  corpus/automonique_fuzz_parse_canonical corpus/automonique_fuzz_envelope_decode
```

The Telegram and Slack seeds are synthetic, because the protocol fixtures do not
cover a vendor's response shapes. They are transcribed from the published
response schemas with every value replaced by an obvious placeholder.

## When a target finds something

Check the crashing input in under `regressions/`, add a plain `#[test]` that
replays it through the same entry point, and fix the decoder. The regression
test belongs with the crate's own suite, not here: it should run on every PR on
stable, and nothing in this directory does.
