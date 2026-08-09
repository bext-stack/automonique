<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Owner decision — reset and publish `main` history

| Field | Decision |
|---|---|
| Status | explicitly authorized by the repository owner |
| Remote | `origin` |
| Branch | `main` |
| Expected remote tip | `0ddbc19b48856542d699de912c4471c5bebb0769` |
| Pre-rewrite local tip and recovery commit | `b619ef2d3f8553a631fde536c37dfa3d8ac2d2ed` |
| Intended snapshot | the complete tracked tree at the pre-rewrite local tip plus this owner decision, with no other worktree changes |
| Allowed operation | create one parentless root commit for the intended snapshot, atomically replace local `main`, then force-push only `refs/heads/main` with an exact lease on the expected remote tip |
| Remote inventory | one branch, `main`; no remote tags observed immediately before the rewrite |
| Commit message | `Initial Automonique implementation baseline` |
| Recovery | retain the exact pre-rewrite commit ID above and create an out-of-repository Git bundle before moving the local ref |
| Excluded operations | no other branch, tag, remote, repository setting, release, package or deployment change |

The new root commit includes the current clean-room policy, plans, harness,
tests and implementation spikes as one baseline snapshot. The rewrite does not
change file contents other than adding this decision record.
