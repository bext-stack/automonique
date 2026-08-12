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
- `connectors/`

Each independently distributed package must include the Apache-2.0 licence and
declare `Apache-2.0` in its package metadata. Source files that support comments
must carry:

```text
SPDX-License-Identifier: Apache-2.0
```

Moving product-core code below one of these roots does not relicense it. Such a
move requires owner review before distribution; the development check only
enforces the declared path and SPDX mapping.

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

Third-party material retains its original licence. Before a component that
contains third-party material is distributed, record the source, version,
licence, modifications, and required notices. Generate an SBOM when the release
contract or distribution channel requires one; development commits do not need
one.

GPL-, AGPL-, SSPL-, or other reciprocal/source-available material may not be
copied into a distributed component without a separately approved compatibility
decision. Build tools used without distribution are recorded independently.

## Development check

`python3 tools/check_licenses.py` performs the intentionally small automated
check: commentable source files must carry the SPDX identifier dictated by
their path. It is independent of the archived executable-plan verifier.
Dependency inventories, notices, SBOMs, compatibility decisions, and
cross-boundary code review belong to the first relevant distribution effort
rather than every development commit.
