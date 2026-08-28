# Frozen installed Platform v1 client evidence

This corpus and its decoder are repository-contained compatibility evidence.
Tests do not read Git history or the network.

## Historical client source

- Commit: `2e428e440cb524e686141923f4070aca3a41f9b7`, the direct parent of
  `241af0dce7afe9a4c0409000de918d9aad98fd99` (`feat(protocol): define
  platform v2 work context`) and therefore the exact last repository state
  before Platform v2 existed.
- Installed Rust client path: `sdk/rust/platform-client/src/lib.rs`.
- Installed client source SHA-256:
  `758efc18d29d6f5e7ef92a52b49c975017c5547ae13aea3aa1e1df7cb06760d2`.
- Historical response decoder path:
  `rust/crates/automonique-protocol/src/platform_api.rs`.
- Historical decoder source SHA-256:
  `6efba296cb80da0c97577a7e610802c80e69f34ae86247ee19fc1291652a44b3`.

`tests/support/installed_v1_client_2e428e44.rs` is a frozen, tiny extraction
of that client's response-admission boundary for the five response families
used by an installed read/control client: capabilities, snapshot, sessions,
receipt, and refusal. It retains the historical exact envelope/body fields,
closed values, bounds, correlation grammar, and nested resource validation.
Transport I/O, request encoding, reducers, and response families absent from
this representative corpus are deliberately excluded. The extraction's
SHA-256 is
`3e40b9d9d4f457a3b1737e9f905bdabf1bc62a4d45e0419e166e7e1f0af5d6de`.

The frozen decoder imports only the generic canonical JSON value/parser. It
does not import the current `platform`, `platform_api`, or typed Platform v1
decoder, so the compatibility assertion cannot pass by decoding both sides
with today's implementation.

## Current-server transcripts

`platform-v1-installed-client-responses-2e428e44.json` contains immutable,
canonical response bytes for those five families. Its SHA-256 is
`37039d1bce74e67a8d5a526073cecf61b269ccc7348a300b8ccabd042ab7f7dd`.
The test first asks the current version negotiator to select between the
installed client's v1-only offer and the current server's v1/v2 offer, and
requires v1. It then independently constructs each response through the
current protocol's typed `PlatformResponseMessage` encoder and requires byte
equality with this corpus before passing the frozen historical decoder the
checked-in bytes. It also pins both checked-in file hashes before exercising
either side.

## Licence

- The historical SDK client source is Apache-2.0.
- The historical protocol decoder, this extracted harness, corpus, and test
  are Elastic-2.0.

No credentials, host paths, provider identifiers, or production payloads are
present; all coordinates are synthetic fixtures.
