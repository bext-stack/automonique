# Licensing boundary

This policy identifies which licence governs each part of Automonique. It does
not replace the referenced licence texts.

## Product — Elastic License 2.0

Unless a narrower directory rule below applies, repository content is licensed
under `Elastic-2.0`. This includes the server, daemon, web application, TUI,
CLI, product protocols, product build tooling, product tests, and product
documentation.

Every source file that supports comments must carry:

```text
SPDX-License-Identifier: Elastic-2.0
```

## SDKs and integration libraries — Apache License 2.0

Content below these roots is licensed under `Apache-2.0`, including its tests,
examples, generated client source, and package documentation:

- `sdk/`
- `integrations/`

Each independently distributed package must include the Apache-2.0 licence and
declare `Apache-2.0` in its package metadata. Source files that support comments
must carry:

```text
SPDX-License-Identifier: Apache-2.0
```

An integration that embeds or distributes product-core code does not become
Apache-2.0 merely by being placed below one of these roots. The licence-boundary
gate must reject such a move.

## Commercial terms

The public licences do not grant commercial hosting, OEM, partner, support, or
other negotiated rights beyond their own terms. Separate rights exist only in
a written agreement executed by the licensor. See `COMMERCIAL.md`.

## Brand assets

The Automonique name, wordmarks, logos, mascots, trade dress, domains, and other
brand identifiers are not licensed under Elastic-2.0 or Apache-2.0. Brand use is
governed by `TRADEMARKS.md` and applicable law. Brand assets must carry the
SPDX expression `LicenseRef-Automonique-Brand` and an explicit copyright notice.

## Third-party material

Third-party material retains its original licence and must be isolated under
`third_party/` with source, version, licence, modification, and provenance
records. Generated SBOM and notice output does not change those terms.

GPL-, AGPL-, SSPL-, or other reciprocal/source-available material may not be
copied into a distributed component without a separately approved compatibility
decision. Build tools used without distribution are recorded independently.
