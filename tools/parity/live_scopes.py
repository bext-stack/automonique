#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Enumerate the live effect scopes and cross-reference their shadow status (M2 #14).

Five scopes reach the outside world today without ever having been compared
against the system they replace. Retroactive shadow verification is the work of
closing that gap, and it cannot be finished in a repository: it needs days to
weeks of production traffic per scope. What *can* live here is the enumeration
itself — which scopes are live, what effect seam each one flows through, which
parity rows it answers to, and what has actually been verified about it.

The last of those is the reason this file exists. "Nothing has been verified" is
a claim that decays silently: it is true today, it stays written after it stops
being true, and nobody notices either way. So the status is not prose here. It
is derived from artifacts that must exist on disk, and a scope claiming any
status beyond `no-harness` while the harness is absent fails this check.

The enumeration is grounded in the code, deliberately, and not in
`docs/product-plan/reference/launch-roadmap.md`, whose "where we are today"
section describes several of these scopes as unbuilt. Each scope below names the
trait its effects pass through and the production implementation behind it, both
verified by exact string match on every run — a rename fails this check rather
than quietly leaving a scope pointing at nothing.

What this file does NOT record, because it is not derivable from this
repository: whether the legacy system still serves each scope. That is the input
the per-scope owner decision turns on, and it is recorded as
`owner-input-required` rather than guessed. See
`plan/owner-decisions/2026-08-15-retroactive-shadow-live-scopes.md`.

    python3 tools/parity/live_scopes.py            # verify the enumeration
    python3 tools/parity/live_scopes.py --summary  # verify and print the table

Exit code is non-zero when a declared seam has moved, a declared parity row has
left the ledger, the owner memo has fallen out of sync, the GATE-ORACLE scope
this work depends on has been withdrawn, or a scope claims a status its evidence
does not support.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

LEDGER = ROOT / "plan/ledgers/parity.json"
GATES = ROOT / "plan/gates.md"
OWNER_MEMO = "plan/owner-decisions/2026-08-15-retroactive-shadow-live-scopes.md"
GATE_SCOPE_DECISION = "plan/owner-decisions/2026-08-15-gate-oracle-scope.md"

CRATES = "rust/crates"

# The shadow-comparison harness of issue #10. Until every one of these exists,
# no scope can have been compared against anything, because there is nothing to
# record an intended action into. This is the evidence the status vocabulary
# below is checked against.
HARNESS_ARTIFACTS = (
    f"{CRATES}/automonique-protocol/src/parity.rs",
    f"{CRATES}/automonique-store/src/shadow_parity.rs",
    f"{CRATES}/automonique-daemon/src/shadow.rs",
)

# Closed status vocabulary, ordered by how much evidence each one asserts.
# `no-harness` is the only one the tree can currently support.
SHADOW_STATUSES = ("no-harness", "capturing", "scored", "decided")

# Whether the legacy system still serves a scope decides which owner option
# applies (scope back, or accept the risk). Nothing in this repository can
# answer it, so there is exactly one permitted value until an owner supplies one.
LEGACY_COVERAGE = ("owner-input-required",)


@dataclasses.dataclass(frozen=True)
class Seam:
    """An effect trait and the production implementation behind it.

    Both are checked by exact string match rather than by line number: the
    surrounding line numbers in the M2 plan had already drifted by the time this
    was written, and a citation that rots without complaining is worse than none.
    """

    trait: str
    definition_file: str
    production_impl: str
    production_file: str

    def problems(self, root: pathlib.Path) -> list[str]:
        found = []
        for label, relative, needle in (
            ("definition", self.definition_file, f"trait {self.trait}"),
            ("production implementation", self.production_file, self.production_impl),
        ):
            path = root / relative
            if not path.is_file():
                found.append(f"seam {self.trait}: {relative} does not exist")
                continue
            if needle not in path.read_text():
                found.append(
                    f"seam {self.trait}: {relative} no longer contains "
                    f"{needle!r}, so this scope's {label} citation names nothing"
                )
        return found


@dataclasses.dataclass(frozen=True)
class Scope:
    """One live outbound effect scope."""

    id: str
    description: str
    seams: tuple[Seam, ...]
    parity_rows: tuple[str, ...]
    shadow_status: str
    legacy_coverage: str


SLACK_TICKET_POSTER = Seam(
    "SlackTicketPoster",
    f"{CRATES}/automonique-daemon/src/slack.rs",
    "impl SlackTicketPoster for SlackClient",
    f"{CRATES}/automonique-daemon/src/slack.rs",
)
SLACK_API = Seam(
    "SlackApi",
    f"{CRATES}/automonique-daemon/src/slack.rs",
    "impl SlackApi for SlackClient",
    f"{CRATES}/automonique-daemon/src/slack.rs",
)
TICKET_ACTION_SURFACE = Seam(
    "TicketActionSurface",
    f"{CRATES}/automonique-daemon/src/telegram_bridge.rs",
    "impl TicketActionSurface for FleetClient",
    f"{CRATES}/automonique-daemon/src/telegram_bridge.rs",
)
EMAIL_ACTION_SURFACE = Seam(
    "EmailActionSurface",
    f"{CRATES}/automonique-daemon/src/telegram_bridge.rs",
    "impl EmailActionSurface for FleetClient",
    f"{CRATES}/automonique-daemon/src/telegram_bridge.rs",
)
GITHUB_ACTION_SURFACE = Seam(
    "GitHubActionSurface",
    f"{CRATES}/automonique-daemon/src/github.rs",
    "impl GitHubActionSurface for GitHubWorkspace",
    f"{CRATES}/automonique-daemon/src/github.rs",
)
GITHUB_SURFACE = Seam(
    "GitHubSurface",
    f"{CRATES}/automonique-daemon/src/github.rs",
    "impl GitHubSurface for GitHubWorkspace",
    f"{CRATES}/automonique-daemon/src/github.rs",
)


SCOPES: tuple[Scope, ...] = (
    Scope(
        "slack-ticket-routing",
        "Slack ticket routing, approval cards, decision updates and modals",
        (SLACK_TICKET_POSTER, TICKET_ACTION_SURFACE),
        (
            "slack-socket-mode-messages-mentions-threads-commands-and-actions",
            "human-work-approval",
            "provider-execution-approval",
        ),
        "no-harness",
        "owner-input-required",
    ),
    Scope(
        "slack-conversational-qa",
        "Slack conversational answers and GitHub-backed question answering",
        (SLACK_API, GITHUB_SURFACE),
        (
            "deterministic-query-chat-ticket-memory-chatter-clarify-routing",
            "short-contextual-follow-ups-and-pending-support-composition-intent",
        ),
        "no-harness",
        "owner-input-required",
    ),
    Scope(
        "support-ticket-intake",
        "Support-backend ticket intake, drafting and staff-published replies",
        (TICKET_ACTION_SURFACE,),
        (
            "client-request-portal",
            "internal-raw-agent-output-versus-staff-published-client-reply",
            "support-inbox-query-and-formatting",
        ),
        "no-harness",
        "owner-input-required",
    ),
    Scope(
        "github-issue-actions",
        "GitHub issue create, reply, checklist and manage actions",
        (GITHUB_ACTION_SURFACE,),
        ("github-issue-as-durable-ticket-truth",),
        "no-harness",
        "owner-input-required",
    ),
    Scope(
        "support-email-send",
        "Support outbound email composition and send",
        (EMAIL_ACTION_SURFACE,),
        ("support-email-compose-exact-sender-recipient-content-review-and-send",),
        "no-harness",
        "owner-input-required",
    ),
)


class ScopeError(Exception):
    """The enumeration disagrees with the tree it describes."""


def harness_present(root: pathlib.Path) -> bool:
    return all((root / relative).is_file() for relative in HARNESS_ARTIFACTS)


def ledger_keys(root: pathlib.Path) -> set[str]:
    path = root / LEDGER.relative_to(ROOT)
    try:
        document = json.loads(path.read_text())
    except OSError as exc:
        raise ScopeError(f"cannot read the parity ledger: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ScopeError(f"the parity ledger is not valid JSON: {exc}") from exc
    return {entry["key"] for entry in document["entries"]}


def verify(root: pathlib.Path = ROOT) -> list[str]:
    """Return every problem found, empty when the enumeration holds."""
    problems: list[str] = []

    if not SCOPES:
        raise ScopeError("the enumeration is empty; a scope list nobody maintains "
                         "is not a record of anything")

    seen: set[str] = set()
    for scope in SCOPES:
        if scope.id in seen:
            problems.append(f"scope {scope.id} is declared twice")
        seen.add(scope.id)

    keys = ledger_keys(root)
    for scope in SCOPES:
        if not scope.seams:
            problems.append(
                f"scope {scope.id} names no effect seam, so nothing identifies "
                f"where its effects leave this process"
            )
        for seam in scope.seams:
            problems.extend(seam.problems(root))

        if not scope.parity_rows:
            problems.append(
                f"scope {scope.id} maps to no parity row, so no requirement "
                f"states what its behaviour must preserve"
            )
        for row in scope.parity_rows:
            if row not in keys:
                problems.append(
                    f"scope {scope.id} cites parity row {row!r}, which the "
                    f"ledger no longer contains"
                )

        if scope.shadow_status not in SHADOW_STATUSES:
            problems.append(
                f"scope {scope.id} declares shadow status "
                f"{scope.shadow_status!r}, which is outside the closed set "
                f"{list(SHADOW_STATUSES)}"
            )
        if scope.legacy_coverage not in LEGACY_COVERAGE:
            problems.append(
                f"scope {scope.id} declares legacy coverage "
                f"{scope.legacy_coverage!r}; nothing in this repository can "
                f"establish that, so the only permitted value is "
                f"{LEGACY_COVERAGE[0]!r}"
            )

    # The load-bearing refusal. Without the #10 harness there is no envelope to
    # record and no comparison to record it against, so any status above
    # `no-harness` is an unsupported claim of verification.
    if not harness_present(root):
        for scope in SCOPES:
            if scope.shadow_status != "no-harness":
                problems.append(
                    f"scope {scope.id} claims shadow status "
                    f"{scope.shadow_status!r}, but the shadow-comparison harness "
                    f"does not exist ({', '.join(HARNESS_ARTIFACTS)}), so no "
                    f"comparison has been possible and no such status can be "
                    f"supported"
                )

    for relative in (OWNER_MEMO, GATE_SCOPE_DECISION):
        path = root / relative
        if not path.is_file():
            problems.append(f"{relative} does not exist")
            continue
        if relative == OWNER_MEMO:
            text = path.read_text()
            for scope in SCOPES:
                if scope.id not in text:
                    problems.append(
                        f"{relative} does not name scope {scope.id}; the memo "
                        f"records the decision this enumeration exists to serve, "
                        f"so a scope missing from it has no decision path"
                    )

    # Live-traffic shadow comparison is only unblocked because GATE-ORACLE's
    # blocking claim was narrowed to archive-differential work. If that
    # narrowing is ever withdrawn, this enumeration describes work that is
    # blocked again, and saying so here is cheaper than discovering it later.
    gates = root / GATES.relative_to(ROOT)
    if not gates.is_file():
        problems.append("plan/gates.md does not exist")
    else:
        text = gates.read_text()
        if "### GATE-ORACLE" not in text:
            problems.append("plan/gates.md no longer defines GATE-ORACLE")
        elif "archive-differential" not in text:
            problems.append(
                "plan/gates.md no longer narrows GATE-ORACLE to "
                "archive-differential work, so live-traffic shadow comparison "
                "is blocked again and this enumeration cannot be acted on; see "
                + GATE_SCOPE_DECISION
            )

    return problems


def summarise(root: pathlib.Path = ROOT) -> list[str]:
    out = [
        f"harness present: {'yes' if harness_present(root) else 'no'}",
        "",
        f"{'scope':<24} {'shadow status':<14} {'legacy coverage':<22} rows",
        f"{'-' * 24} {'-' * 14} {'-' * 22} ----",
    ]
    for scope in SCOPES:
        out.append(
            f"{scope.id:<24} {scope.shadow_status:<14} "
            f"{scope.legacy_coverage:<22} {len(scope.parity_rows)}"
        )
    out += ["", "seams:"]
    for scope in SCOPES:
        traits = ", ".join(seam.trait for seam in scope.seams)
        out.append(f"  {scope.id:<24} {traits}")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--summary", action="store_true",
                        help="print the scope table as well as verifying")
    arguments = parser.parse_args(argv)

    try:
        problems = verify()
    except ScopeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if problems:
        print(f"\nlive scopes: FAIL ({len(problems)} problem(s))", file=sys.stderr)
        return 1

    unverified = sum(1 for s in SCOPES if s.shadow_status == "no-harness")
    print(
        f"ok — {len(SCOPES)} live scope(s) enumerated, "
        f"{sum(len(s.parity_rows) for s in SCOPES)} parity row(s) cross-referenced, "
        f"{unverified} with no shadow comparison performed"
    )
    if unverified:
        print(
            "note: this is an enumeration, not a verification. No live scope has "
            "been compared against the system it replaces; that needs the issue "
            f"#10 harness and production traffic. See {OWNER_MEMO}."
        )
    if arguments.summary:
        for line in summarise():
            print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
