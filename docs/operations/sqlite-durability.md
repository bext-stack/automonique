# SQLite runtime durability policy

Automonique has one runtime database class today: **authority-bearing**. A
committed row in any current store can affect authorization, idempotency,
external-effect reconciliation, provider/session identity, scheduling, or audit
evidence. None is treated as a disposable cache.

Every writable runtime connection therefore applies and reads back this policy
before opening its schema:

| Setting | Required value | Reason |
| --- | --- | --- |
| `journal_mode` | `WAL` | Concurrent readers and bounded writer arbitration. |
| `synchronous` | `FULL` (`2`) | Do not knowingly permit the last acknowledged authority mutation to roll back after an OS crash or power loss. |
| `foreign_keys` | `ON` (`1`) | Enforce relational custody constraints on every connection. |
| `trusted_schema` | `OFF` (`0`) | Do not let schema content invoke application-defined functions implicitly. |
| `busy_timeout` | 2,000 ms | Bound contention rather than wait indefinitely. |

The implementation is
`automonique_store::sqlite_policy::configure_authoritative`. A connection that
cannot report every value exactly fails to open. Production has no environment
or configuration override that weakens this class. The benchmark can compare
`NORMAL`, but selecting it for runtime use requires a deliberate code and
policy change plus a proven regenerable database class. An operator may not
silently trade away a committed authority mutation.

## Runtime inventory

There are 24 writable runtime database implementations. All are in the
authority-bearing class.

| Store implementations | Failure model requiring `FULL` |
| --- | --- |
| Core `Store` | Generation leases, inbox/run/outbox state, and effect reconciliation must not forget an acknowledged transition. |
| `approval_ledger`, `approval_requests`, `operator_members` | Losing a decision, pending request, or membership changes authorization after restart. |
| `automation_store`, `batch_registry`, `cancel_ledger`, `run_index`, `run_submissions` | Losing schedule, membership, cancellation, or custody state can duplicate or misreport execution. |
| `slack_ingress`, `slack_interactions`, `support_tickets` | Losing an acknowledged ingress or interaction can duplicate delivery or rewrite lifecycle state. |
| `platform_store`, `provider_deployments`, `provider_journal` | Receipts, control leases, routing, cooldowns, sessions, and ambiguous effect boundaries are authority state. |
| `audit_chain`, `generation_audit`, `shadow_comparisons`, `context_memory` | Losing committed provenance or gate evidence would make later audit and recovery claims incomplete. |
| `agent_memory`, `improvements` | Retained content and owner-directed release workflow state are not reconstructable caches. |
| Daemon `agent_lane_journal`, `managed_sessions` | Provider/tool intent ordering and exact session binding must survive restart. |
| ACP `session_store` | Compatibility coordinates must keep addressing the same canonical session across adapter restarts. |

Read-only dashboard and backup connections are not runtime writers and do not
select this policy. Backup targets deliberately use rollback-journal semantics
while being constructed and are verified before publication.

## Measurement

Run the checked-in comparison from the Rust workspace:

```console
cargo run -q -p automonique-store --example sqlite_durability_benchmark
```

The fixture performs 500 separate immediate transactions with a 1 KiB payload,
checkpoints the WAL, closes and reopens the database, counts rows, and runs
`integrity_check`. On 2026-08-25, one warm-up was discarded and five local
trials produced:

| Mode | Median elapsed | Range | Median throughput | Reopen result |
| --- | ---: | ---: | ---: | --- |
| `FULL` | 90 ms | 90–94 ms | 5,556 commits/s | 500 rows, integrity `ok` |
| `NORMAL` | 20 ms | 19–21 ms | 25,000 commits/s | 500 rows, integrity `ok` |

This fsync-heavy microbenchmark measures the expected cost boundary, not whole
daemon throughput. `NORMAL` was about 4.5 times faster here. That does not meet
the failure model: SQLite documents that WAL + `NORMAL` can roll back a
committed transaction after an OS crash or power loss, while WAL + `FULL` adds
the per-commit WAL sync used for durability. See SQLite's
[`synchronous` pragma](https://sqlite.org/pragma.html#pragma_synchronous) and
the [WAL description](https://sqlite.org/wal.html).

## Recovery evidence and limits

`tests/sqlite_policy.rs` starts a separate writer, commits 64 authority rows,
forcibly kills that process without SQLite cleanup, reopens under the selected
policy, and requires all 64 rows plus `integrity_check=ok`. Unit tests also
fault-inject `NORMAL` and require policy readback to reject it. Existing store
tests cover clean restart and schema recovery for the individual stores.

These tests prove application-process crash recovery and exact pragma
selection. They do **not** simulate kernel failure, storage-controller cache
loss, filesystem corruption, or physical power removal, so this repository
does not claim empirical coverage of those faults. The `FULL` choice for those
faults follows SQLite's VFS sync contract; deployments still require storage
whose sync implementation is truthful.
