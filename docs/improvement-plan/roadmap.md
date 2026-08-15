# Improvement roadmap (2026-08-15)

Status: improvement program derived from the deep audit
([`audit-findings.md`](audit-findings.md)) and the external survey
([`state-of-the-art.md`](state-of-the-art.md)). It does not replace
[`../product-plan/launch-roadmap.md`](../product-plan/launch-roadmap.md) —
it corrects course *toward* it: the launch roadmap's increments remain the
product path; this program restores the gates that path depends on and
raises the engineering floor underneath it.

Each milestone below exists as a GitHub milestone; each work item as a
GitHub issue labeled with its milestone and finding reference. Work item
*N* below is GitHub issue *N+3* (items 1–53 → issues
[#4–#56](https://github.com/bext-stack/automonique/issues)). Ordering is
by risk: M1–M2 are the program's brakes (they make everything else safe to
ship); M3–M5 raise the floor; M6–M8 build forward.

Owner-decision items are marked **[owner]** — they need a decision, not
just a PR.

---

## M1 — Disclosure closure & truth reconciliation

*Why first: findings F-01, F-02, F-04, F-05 are live now; every push widens
F-01. Nothing here is large; all of it is urgent.*

1. **Scrub private client identifiers from source, docs, and UI strings**
   (F-01). Replace real hostnames/tenant/product names in the daemon's
   Slack/Telegram surfaces and the two loose docs with configuration-driven
   or neutral values; make identifier location conform to the gates file's
   own rule. **[owner]** for history rewriting; forward-only fix does not
   need it.
2. **Run the publication scrub on every push** and make the development
   scrub block the identifiers that F-01 shipped (F-01, F-09). **[owner]**:
   whether the repo stays public while the scrub is red.
3. **Reconcile the status documents with the running system** (F-04):
   `README.md`, `docs/product-plan/execution-unlock.md` (record which gates
   were opened, when, by whom), the daemon's crate-level doc comment, and
   the three connectors' method lists.
4. **Repair the authority stack** (F-05): update the precedence table in
   `docs/product-plan/README.md` to match `AGENTS.md`/`GOVERNANCE.md`;
   bring the three shipped-but-unspecified subsystems (durable memory,
   Slack v2 rollout config, self-improvement) into the requirements corpus.
5. **Resolve the Apache-2.0 connector boundary** (F-05) **[owner]**: the
   documented `connectors/`+`integrations/` roots were never created and
   the real connectors shipped Elastic-2.0. Decide move / relicense /
   re-document, then make `tools/check_licenses.py` match the decision.
6. **Reconcile the identity register and wire the identity checker**
   (periphery audit §4): register the owner identity, set the effective
   signing commit, add the missing workflow or drop the gates-file claim.

## M2 — Parity harness & shadow gate

*Why: F-03 — the strangler's one rule is currently unenforceable. This
milestone builds the mechanism the launch roadmap's parity gate names, in
the shape the 2026 state of the art prescribes (SOTA §3).*

7. **Shadow-comparison harness comparing intended-action envelopes.** The
   shadow path computes what it *would* do (reply, transition, notify) as a
   typed envelope that is recorded and diffed, never executed. Field-level
   diffing; normalization before comparison.
8. **Golden-trace fixture corpus.** Record real traffic traces (inputs,
   tool calls, outputs) with anonymization; replay both engines against
   them with a deterministic mock runner; every investigated failure
   becomes a permanent regression fixture.
9. **Weighted parity confidence score + known-deviation registry.**
   Happy ×1 / error ×2 / edge ×2 / variety ×1.5 / production-representative
   ×3, with the 0–30/31–60/61–85/86–100 bands as the go/no-go instrument;
   deviations classified parity / known-deviation (with reason) /
   regression.
10. **Specify and test the four safety properties** (launch roadmap §
    "replacement spans"): fail-closed deploy channel,
    announce-target-before-mutation, separately-authorized deletion,
    scheduler pause/cancel semantics. Spec first, conformance tests with
    them.
11. **Retroactive shadow for the already-live Slack/Support scopes.** The
    scopes shipped ahead of their gate; run them through the harness and
    either record their gate pass or scope them back. **[owner]** for
    any scope-back decision.
12. **Wire the parity ledger and identifier inventory tools into CI**
    (F-14): both are tested, green, and orphaned today.
13. **Close or re-scope GATE-ORACLE** **[owner]**: the differential-parity
    gate has zero reviewers recorded; either staff it or re-scope what the
    oracle releases.

## M3 — Approvals, authority & audit

*Why: F-06 — 16k lines of approval/automation/batch surface nothing reads,
while two Telegram verbs refuse. SOTA §2 defines exactly what a credible
approval system looks like in 2026.*

14. **Wire-or-delete decision on the automation/approval/batch triad**
    **[owner]** — the single highest-leverage product decision in the
    register. The items below assume "wire".
15. **Admin cancel verb + Telegram `/cancel`**: the daemon already owns a
    working host-wide cancellation dispatcher and a durable cancellation
    ledger sits unwired in the store crate; connect them.
16. **Approval lane end-to-end**: `/approve` and `/deny` act on real
    pending work; approvals recorded once, idempotently.
17. **Approval context binding**: bind each approval to canonical execution
    context (argv, cwd, executable digest, referenced-file hash) and deny
    if anything changed between approval and execution (TOCTOU defense).
18. **Approval TTL with auto-deny, reminder and escalation ladder**; an
    expired request that is re-wanted becomes a *new* proposal with a new
    idempotency key after re-validating state.
19. **Fail-closed headless approvals + tighten-only policy composition**:
    when no operator surface is reachable, deny; effective policy is the
    strictest of config/host/per-call and can only tighten.
20. **Hash-chained audit records**: RFC 8785 canonical JSON + SHA-256
    `prev_hash` chaining over approval/action/override records (the
    canonical-JSON and SHA-256 machinery already exists in the protocol
    crate); outcome vocabulary {success, failure, timeout, denied,
    escalated}.
21. **Idempotent approval buttons on both platforms**: opaque approval ID
    in `callback_data`/action payloads, decision recorded exactly once,
    keyboard/buttons stripped on decision so stale approvals cannot fire.

## M4 — Self-improvement governance

*Why: F-02 — the pipeline that modifies the product is gated more weakly
than the product's own CI, and activates by the restart mechanism the
product exists to eliminate.*

22. **Align the improvement executor's verification recipes with CI**: add
    `cargo check`, `clippy -D warnings`, the licence check, and the
    development scrub to the fixed recipe list.
23. **Gate release activation on CI green**, not only on local recipes: a
    candidate may open a PR when local recipes pass, but activation waits
    for the remote gate.
24. **Bring self-improvement under the self-hosting ladder**: reconcile the
    shipped workflow with the SH0–SH6 ladder and the harness requirements,
    or amend those requirements deliberately. **[owner]**
25. **Activation via generation handoff** once M8's reload lands: replace
    restart-based activation; until then, document restart as an accepted
    temporary deviation. (Depends on item 44.)

## M5 — Test depth & CI hardening

*Why: F-07, F-08, F-09 — the untrusted-input surface has no randomized
testing, credential redaction exists in triplicate, and CI passes partly by
luck.*

26. **Property + fuzz testing on the protocol crate's codecs**
    (dev-dependency-only): canonical JSON, framing, every wire parser that
    faces untrusted input; round-trip and never-panic properties.
27. **Shared connector substrate**: one crate providing credential
    redaction, JSON string escaping, bounded body reads, strict JSON,
    ureq error mapping; delete the 3–6 copies; collapse the protocol
    crate's 21 identical `bounded()` validators into one generic.
28. **Declare and pin the JS toolchain in CI**; make cross-language `GAP:`
    records fail the job (or surface as annotations); run the TS package
    tests and typechecks; embed the schema digest the SDK `VERDICT.md`
    calls for.
29. **Run the tools/ suite and derived-artifact checkers in CI** (~37 s);
    fix the one stale-fixture failure first.
30. **Supply-chain gates**: `cargo-audit`/`cargo-deny` (advisories will
    never arrive by themselves under exact pins), `rust-toolchain.toml`,
    coverage measurement.
31. **Fix or retire the plan verifier** (periphery §6): `plan/selftest.py`
    fails its own baseline control, making its 13 mutation cases vacuous;
    either repair the baseline and identifier-location rules or formally
    archive the verifier and delete the stale gate claims.
32. **Repository furniture**: CODEOWNERS, PR template, issue templates
    (including an owner-decision template), dependabot for GitHub Actions.

## M6 — Streaming UX & connector modernization

*Why: SOTA §1/§5 — both chat platforms shipped native streaming since this
product's connectors were written; progress today is text-only.*

33. **One internal normalized progress-event stream** (AG-UI-shaped
    vocabulary: text chunks, thinking/task-card steps, tool-call events,
    typed errors with retry context) emitted by the execution lane and
    consumed by every surface — this also hands the planned desktop client
    its event vocabulary.
34. **Telegram streaming via `sendMessageDraft`** (Bot API ≥ 9.5) with an
    API-call budgeter that accounts every method call and respects the
    whole-bot 429 semantics.
35. **Slack streaming** via `chat.startStream`/`appendStream`/`stopStream`
    with thinking-steps task cards; Block Kit only at stop.
36. **Session/thread lifecycle + modifier grammar**: thread-bound sessions
    with explicit verbs (new/mute/archive) and a bang-modifier grammar for
    mode/model selection composing with the existing command set.
37. **Provider adapter hardening** (SOTA §5): long-lived subprocess per
    session over NDJSON stdin; invalid line → warn and continue, missing
    terminal `result` or non-zero exit → `completed(ok=false)`;
    per-deployment failure counters with cooldown and ordered fallbacks
    (including a separate context-window fallback chain).
53. **Resumable event streams with bounded fan-out** (SOTA §6): per-client
    bounded queue + dedicated writer; on overflow drop the stale queue,
    send a terminal frame, disconnect; monotonic per-stream sequence
    accepted back as a resume cursor with time-shaped retention; a
    disconnected client is never a cancellation; a monotonic capability
    integer with per-endpoint maturity annotations on the admin protocol.

## M7 — Observability & operations

*Why: F-11, F-13 — ~45 metrics are required before rollout and none are
exportable; backup/restore exists only as a spike; deployment is
foreground-only.*

38. **Metrics exporter** (Prometheus text endpoint or OTLP push — local,
    authenticated) over the existing snapshot-derived metrics; adopt OTel
    `gen_ai.*` attributes for per-run token/cost accounting.
39. **Trace/correlation ID propagation** (`trace_id`/`correlation_id`/
    `causation_id`) through lanes, connectors, and provider runs.
40. **Productize backup/restore from the recovery spike**, including the
    two backup-ordering rules that exist only there (database snapshot
    first; blob set and config derived from it) and a clean-host restore
    drill; write the operator runbooks.
41. **Service definition**: systemd user units with `Delegate=yes`,
    XDG environment, restart policy, watchdog; refresh the stale
    provider-inventory pins and their Rust-pinned digest (F-13).
51. **Socket activation, `Type=notify-reload`, and the fd store**
    (SOTA §6): zero-drop restarts measured at ~74 ms worst-case connect;
    retires self-exec and the bind/unlink dance; watchdog pinged from the
    main loop.
52. **Doctor checks for silent no-ops; store pragma review** (SOTA §6):
    read back `cgroup.controllers` and sandbox enforcement instead of
    trusting accepted directives; journald field-landing check; adopt
    `synchronous=NORMAL` as the WAL default with FULL as operator opt-in.

## M8 — Scheduler, reload & isolation depth

*Why: F-10, F-12 and launch Increments 6–7 — the founding requirement
(reload) and the largest unpinned legacy gap (the scheduler core) plus the
two known sandbox gaps.*

42. **Scheduler core**: bounded parallelism, per-scope serialization,
    pause/cancel — specified first (M2 item 10), then implemented against
    the existing lease/outbox substrate.
43. **Generation handoff / reload**: N+1 readiness proof, transactional
    lease transfer under fencing epochs, drain, automatic return on
    failure; `reload`/`rollback`/`generations`/`reload-status` CLI verbs.
44. **Sandbox uid separation**: workload must not share the supervisor's
    uid (user namespaces where delegated, or a reviewed setuid helper);
    add rlimits/`cpu.max` to close the acknowledged unenforced budgets.
45. **Close the exec TOCTOU**: execute the hashed bytes (e.g. `execveat`
    on a sealed memfd of the verified binary), not the path the hash was
    computed from.
46. **Wire the durable cancellation ledger** into the runner control
    socket, replacing the documented in-memory ledger.
47. **Fence writes, not just work** (SOTA §6): every store mutation made
    on behalf of a lease carries `AND epoch = ?`; `flock` on a control
    lock with dev/inode verification; `(boot_id, pid, starttime)` on
    lease rows with an exact boot-mismatch startup sweep.
48. **Boot- and suspend-aware lease time** (SOTA §6): absolute
    `CLOCK_BOOTTIME` deadlines; a lease spanning a suspend is lost and
    the holder self-fences on resume; ban `Instant`/`SystemTime` from
    lease code.
49. **Journal restructure for offline replay** (SOTA §6): command /
    notification split with correlation ids; step identity
    (name, occurrence index) and journaled step inputs; pin prompt/tool
    schema/model versions per attempt and refuse cross-version resume;
    `replay(turn_id)` as an offline, zero-token regression test.
50. **Identity-bound egress** (SOTA §6): bind the provider-API allowlist
    entry in the egress broker to the session's own credential (sentinel
    substitution at the proxy), not just the hostname; parse-then-match;
    empty allowlist is the most restrictive state (asserted by test);
    resolve once, reject private ranges; close the Landlock TSYNC hole
    and extend the seccomp deny set (ptrace/process_vm_*).

---

## Sequencing and dependencies

- M1 has no dependencies and should be complete before any further
  customer-facing work ships.
- M2 gates any *new* scope takeover (launch Increments 4–6) and
  retroactively covers the scopes already live.
- M3 item 14 (wire-or-delete) precedes items 15–21.
- M4 items 22–23 are independent; item 25 depends on M8 item 43.
- M5–M7 are parallelizable behind M1.
- M8 items 42–43 are the keystones of launch Increments 6–7; the launch
  roadmap's cutover (Increment 7) remains the terminal milestone and is
  intentionally *not* re-planned here.
