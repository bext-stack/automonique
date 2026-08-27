# Retained-session cross-client acceptance preparation

Issue #169 is a live acceptance gate. Deterministic fixtures can prepare it,
but cannot complete it or replace operator-visible verification on ShellDeck,
`monique.1clic.pro`, and Automonique Mobile.

## Authority fixture

`automonique-daemon/tests/retained_session_acceptance.rs` starts a real daemon
on an isolated Unix socket and seeds one synthetic retained session. It proves:

- ShellDeck, hosted-web, and mobile client identities attach to the same exact
  authority-qualified session, run, revision, and ordered sanitized history;
- observation does not grant control, and another client cannot take an active
  controller's lease;
- each scoped client submits one dedicated exact-revision follow-up;
- one response can be lost after admission and reconciled by the original
  client and idempotency key without resubmission;
- a stale revision writes no receipt;
- detachment, daemon restart, reattachment, history resume, and terminal
  receipt lookup preserve identity and do not cross client scopes;
- a compacted history cursor returns a typed replacement window, followed by a
  bounded snapshot that replaces the transcript; and
- raw provider, tool input/output, credential, hidden-reasoning, and repository
  authority sentinels never enter the canonical history response.

All payloads, identities, and paths are synthetic and temporary. The fixture
does not invoke a live provider, production transport, shell command from
session data, repository mutation, or mobile credential.

## Cross-repository runner

Run the aggregator with explicit clean worktrees containing the four dependent
implementations:

```bash
python3 tools/run_retained_session_acceptance.py \
  --hosted-root /path/to/automonique-with-issue-165 \
  --shelldeck-root /path/to/shelldeck-with-issue-126 \
  --mobile-root /path/to/automonique-mobile-with-issue-33
```

The runner uses fixed argument-vector commands, refuses absent test markers,
records each repository's exact Git revision and dirty state, and prints an
`automonique.retained-session-acceptance-report/v1` JSON report. It runs:

1. the real-daemon, three-client authority fixture;
2. the hosted cockpit's retained-session integration fixture;
3. the server-side mobile session/action allowlist fixture;
4. ShellDeck's retained-session Platform contract suite; and
5. Mobile's SDK, reconciliation, projection, reconnect, and provider suites.

The report always records live verification as `required_not_run`. Only an
explicitly authorized operator may run the remaining non-production GUI flow,
inspect the three rendered clients, and add those exact builds/endpoints/results
to issue #169.

## Live-only remainder

After all dependencies merge and deploy, an authorized operator must still:

1. identify a disposable non-production retained session and record its exact
   authority, identity, run, revision, and sanitized history;
2. compare those values visually in all three clients;
3. send and reconcile one real follow-up from each client;
4. repeat disconnect/reconnect, ambiguity, stale-revision, retention-gap,
   observer/control, and mobile-allowlist checks against that same session;
5. inspect visible history, receipts, diagnostics, caches, and logs for raw
   provider payloads, tool input/output, credentials, hidden reasoning, shell
   authority, and repository authority; and
6. record exact source revisions, deployed endpoint/app builds, commands, and
   live outcomes on issue #169.
