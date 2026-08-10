<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — rewrite three commits to the candidate identity

| Field | Decision |
|---|---|
| Status | approved by contemporaneous owner instruction |
| Remote | `origin` — `https://github.com/bext-stack/automonique.git` |
| Branch | `refs/heads/main` |
| Expected remote tip | `5df55ca4cd68132dbf38d466a3dbd3018bae804d` |
| Recovery reference | `refs/heads/recovery/pre-identity-rewrite` at the expected remote tip |
| Allowed operation | one `--force-with-lease` update of `refs/heads/main` on `origin` |
| Intended snapshot | the same three trees, reparented onto `8457c0e7d1311b99566cda0235ba58e7ca1c45c8`, authored and committed as `Automonique Candidate <candidate@automonique.invalid>`, with the `Co-Authored-By` trailers removed |
| Review | zero independent reviewers |

## What went wrong

Commits `75ab771`, `76aa528` and `5df55ca` were authored and committed as
`Benjamin Favre <ben@webdesign29.net>` and carried a `Co-Authored-By` trailer
naming an assistant. Every prior commit on `main` is authored and committed as
`Automonique Candidate <candidate@automonique.invalid>`, the identity
`tools/git_broker.py` sets for a candidate commit.

The commits were made with ordinary `git commit` rather than through the broker,
so they inherited the ambient Git configuration. The fast-forward push that
published them was inside the configured narrow path and its expected-tip check
passed; the identity was wrong before the push, and the push carried it to
`origin`.

## Why a rewrite rather than a follow-up commit

Author and committer identity is part of a commit object. A later commit cannot
correct the three already published, and the repository's own provenance rule is
that a candidate commit is attributable to the candidate identity. Leaving three
differently-attributed commits in `main` would make every future audit of "who
committed this" answer incorrectly for this range.

## Bounds

`plan/authority.toml` denies `history_rewrite`, `force_update` and general
`push`. `AGENTS.md` permits a contemporaneous owner instruction to delegate one
exact publication or history-rewrite operation outside the narrow configured
path without creating standing worker authority. This decision is that
delegation and expires with it.

The operation:

- updates only `refs/heads/main` on `origin`;
- uses `--force-with-lease` against the recorded expected remote tip, so a
  concurrent update aborts it rather than being overwritten;
- alters no other branch, tag, remote or repository setting;
- preserves the three trees exactly — only commit metadata and the trailer
  change, verified by comparing tree object IDs before and after;
- retains `refs/heads/recovery/pre-identity-rewrite` locally so the published
  state is recoverable.

## Stop conditions

Stop if the advertised remote tip differs from the recorded expected tip, if any
rewritten tree object ID differs from its original, if the rewrite would change
any ref other than `refs/heads/main`, or if the working tree is dirty at the
start of the operation.

## Standing rule this establishes

Commits to this repository are authored and committed as
`Automonique Candidate <candidate@automonique.invalid>` and carry no assistant
attribution trailer. A commit made outside `tools/git_broker.py` sets that
identity explicitly.
