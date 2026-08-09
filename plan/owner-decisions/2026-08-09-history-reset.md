<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — initial snapshot history reset

| Field | Decision |
|---|---|
| Status | approved for one execution |
| Requested | 2026-08-09 through the owner-controlled repository workspace |
| Repository | `bext-stack/automonique` |
| Remote and branch | `origin/main` |
| Expected remote tip | `0a33948a577869155e0f4bfe5df028599773e37a` |
| Objective | replace the existing `main` history with one root commit containing the complete verified working-tree snapshot |
| Allowed operation | create one root commit locally, move local `main` to it, and update only `origin/main` with `--force-with-lease=main:0a33948a577869155e0f4bfe5df028599773e37a` |
| Excluded operations | deleting or changing other branches, tags, remotes, settings, releases or packages |
| Licence class | existing path policy: `Elastic-2.0` except `Apache-2.0` under `sdk/` and `integrations/` |
| Verification | plan verification and self-tests, generated graph equality, Python compilation, Rust tests and Clippy, licence self-test/check, diff hygiene, credential/path scan and exact snapshot inspection |

## Authorization

The repository owner explicitly requested a commit, push and reset of all Git
history so this verified snapshot becomes the new starting point. The remote
has one branch (`main`) and no tags, so the complete authorized ref scope is
`origin/main`.

This decision delegates one force-with-lease update of that exact ref. It does
not enable `push` in `plan/authority.toml`, grant reusable integration
authority, authorize an unleased force push, or authorize changes to any other
ref or repository setting.

The expected old tip remains the recovery reference. GitHub may retain it for
a limited time, but recovery after the push is not guaranteed by this decision.

## Intended snapshot

The new root contains every tracked modification and every non-ignored new file
present in the owner-controlled working tree after the checks above, with no
path exclusions. Generated build output and ignored caches are excluded. The
staged tree object ID and new root commit object ID are reported to the owner
after publication; a commit cannot contain its own object ID.

## Stop conditions

Stop without pushing if authentication fails, the remote tip differs from the
expected tip, verification fails, the staged snapshot contains a credential,
private/customer data, a personal email address or an absolute home path, or
the operation would affect a ref other than `origin/main`.
