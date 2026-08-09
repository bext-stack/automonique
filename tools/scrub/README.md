<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Repository scrub gate

`scan.py` checks the exact Git candidate rather than walking the filesystem. It
scans every stage-zero index blob, every additional blob reachable from any
local ref, every reachable commit message, and tracked path bytes. Historical
findings use an opaque blob ID because a deleted path can itself be sensitive.
A shallow
repository is rejected because it cannot prove history coverage. Findings show
only a non-sensitive rule ID, source kind, JSON-escaped location and line; a
matching path is replaced with `<redacted-path>`.

Development mode uses four deliberately public synthetic fingerprints tied to
the two documented sanitization passes:

| Family | Transfer pass |
|---|---|
| `legacy-name` | pass 1 system/protocol compatibility names |
| `third-party-product` | pass 2 third-party product names |
| `internal-product` | pass 2 internal product names |
| `environment-name` | pass 2 deployment environment names |

The synthetic values are base64 test vectors, not former identifiers. Their
plain SHA-256 fingerprints are safe only because the values are public and
synthetic. Protected rules must use HMAC-SHA-256 with a separate key and contain
all four families. Both the rule document and key are supplied as base64
environment values; neither is accepted through argv or printed.

Run the development gate with:

```sh
python3 -m unittest discover -s tools/scrub -p 'test_*.py'
python3 tools/scrub/scan.py
```

Publication mode additionally requires externally configured values:

```sh
python3 tools/scrub/scan.py --require-protected
```

The checked allow list is an audit record, not a suppression filter. Protected
rules always win; adding an allow-list entry cannot silence a finding. Matching
is exact bytes by design. Unicode or case normalization is not claimed and must
be versioned in a later rule schema before it can judge existing protected
rules.

The GitHub `scrub-publication` environment must be restricted to protected
`main` and require explicit owner approval. That approval is the trust boundary
for releasing protected material to the scanner revision in the pending job;
the workflow does not make candidate code intrinsically trusted. Until the
environment, protection and secrets are installed and an approved publication
job passes, `BOOT-003` and `GATE-SCRUB` remain open.
