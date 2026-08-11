#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Parse and validate the R0-09 identity/data/operations surface inventory.

The inventory records *classes*, *owners* and *shapes*. It resolves no secret,
holds no credential value and grants no authorization, so this module is
written so that a forbidden value is unrepresentable rather than discouraged:

* every classifying field is a closed vocabulary and an unknown member is a
  parse refusal, not a warning;
* a credential entry has an exact key set that contains no place to put a
  value, so a credential value cannot be added without editing this file;
* a withheld fact is recorded as two enums — a shape and a reason — and carries
  no free-text field at all, which is what stops "recording the shape" from
  becoming a way to write the value down;
* a number is only accepted next to a citation whose exact words are found in
  the checked-in file it names *and* which contains that number beside its
  unit, so a recalled retention or budget figure refuses at parse.

`errors()` returns a list of human-readable findings rather than raising, so a
single run reports everything wrong with a document instead of the first thing.
"""

from __future__ import annotations

import json
import pathlib
import re
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "plan/inventory/surface/inventory.json"

SCHEMA = "automonique.surface-inventory/v1"
WORK_ITEM = "R0-09"

# The ten sections the contract requires. A section with nothing to record says
# so with a reason; it is never omitted.
SECTION_ORDER = (
    "tenants",
    "actor_mappings",
    "roles",
    "credentials",
    "artifact_classes",
    "workspaces_and_dirty_trees",
    "retention",
    "budgets",
    "backup_dependencies",
    "runbooks",
)

SECTION_TITLES = {
    "tenants": "Tenants",
    "actor_mappings": "Actor mappings",
    "roles": "Roles",
    "credentials": "Credentials",
    "artifact_classes": "Artifact classes",
    "workspaces_and_dirty_trees": "Workspaces and dirty trees",
    "retention": "Retention",
    "budgets": "Budgets",
    "backup_dependencies": "Backup dependencies",
    "runbooks": "Runbooks",
}

# What kind of thing each entry in a section is. Closed per section.
CLASS_VOCABULARY: dict[str, frozenset[str]] = {
    "tenants": frozenset({
        "durable-internal-tenant",
        "external-platform-installation",
        "development-control-plane",
        "credential-pool-boundary",
    }),
    "actor_mappings": frozenset({
        "chat-transport-identity",
        "connector-platform-identity",
        "code-forge-identity",
        "support-desk-identity",
        "sdk-client-identity",
        "local-operator-identity",
        "repository-candidate-identity",
    }),
    "roles": frozenset({
        "service-owner",
        "tenant-scoped-actor",
        "eligible-approver",
        "decision-actor",
        "operator-role-projection",
        "repository-owner",
        "development-candidate",
    }),
    "credentials": frozenset({
        "provider-account",
        "transport",
        "connector-application",
        "connector-webhook-destination",
        "release-signing",
        "protected-branch",
        "deployment",
        "development-provider",
        "recovery-key-escrow",
        "worker-capability",
    }),
    "artifact_classes": frozenset({
        "inbound-attachment",
        "generated-file",
        "media-capture",
        "build-output",
        "preview-delta",
        "log-and-stderr",
        "diagnostic-bundle",
        "backup-set",
        "remote-environment-snapshot",
        "evaluation-export",
        "candidate-build",
        "raw-provider-record",
    }),
    "workspaces_and_dirty_trees": frozenset({
        "registry-record",
        "isolated-worktree",
        "captured-snapshot",
        "dirty-source-capture",
        "workspace-lock",
        "artifact-materialization",
        "bootstrap-runtime-directory",
    }),
    "retention": frozenset({
        "business-audit",
        "transport-content",
        "conversation-and-memory",
        "provider-records",
        "preview-and-log",
        "artifact",
        "credential-session",
        "backup-and-tombstone",
        "connector-activity",
        "context-manifest",
        "automation-and-goal",
        "extension-and-client-session",
        "media-capture",
        "development-candidate",
    }),
    "budgets": frozenset({
        "concurrency",
        "quota",
        "priority-aging",
        "queue-bound",
        "provider-cost",
        "storage-watermark",
        "provider-health",
        "lock",
        "maintenance-state",
        "sandbox-resource",
        "recovery-objective",
    }),
    "backup_dependencies": frozenset({
        "recovery-set-input",
        "verification-step",
        "enablement-gate",
        "excluded-material",
    }),
    "runbooks": frozenset({
        "runtime-incident",
        "self-hosting-incident",
        "bootstrap-operation",
        "maintenance-transition",
    }),
}

# Why a required field carries `null` instead of a value. Closed, because
# "unknown" with a free-text excuse is how an unmeasured claim gets in.
GAP_REASONS = frozenset({
    # the governing policy requires the field but no checked-in document
    # assigns it
    "unassigned-in-corpus",
    # the value exists only in a running deployment this clean-room repository
    # cannot reach
    "not-reachable-from-repository",
    # recording the real value would put a private identifier in a public
    # repository, so only its shape is recorded
    "would-expose-private-identifier",
    # the policy declares the value configurable and states no default number
    "policy-configurable-no-default",
})

# The shape of a fact whose value is deliberately absent. Enum only: a withheld
# record has nowhere to write the value it is withholding.
SHAPES = frozenset({
    "opaque-identifier",
    "external-platform-identifier",
    "host-name",
    "absolute-filesystem-path",
    "email-address",
    "url",
    "secret-material",
    "numeric-quota",
    "duration",
    "display-name",
})

WITHHOLDING_REASONS = frozenset({
    "would-expose-private-identifier",
    "not-reachable-from-repository",
    "credential-value-never-recorded",
})

EXAMPLE_KINDS = frozenset({"synthetic-placeholder", "reserved-non-routable"})
SYNTHETIC_VALUE = re.compile(r"\Asynthetic-[a-z0-9-]+(?:\.(?:invalid|example))?\Z")
RESERVED_VALUE = re.compile(r"\A[a-z0-9-]+(?:@[a-z0-9.-]+)?\.(?:invalid|example|test)\Z")

IDENTIFIER = re.compile(r"\A[a-z0-9]+(?:-[a-z0-9]+)*\Z")

OWNER_KINDS = frozenset({
    "component", "role", "human-role", "external-authority",
})

RESOLVES_TO = frozenset({
    "durable-actor-and-tenant",
    "operator-role-projection",
    "commit-attribution",
})
EXTERNAL_SOURCES = frozenset({
    "slack", "telegram", "github", "support", "sdk",
    "teams", "discord", "operator-tui", "repository",
})
ROLE_AUTHORITIES = frozenset({
    "select-work", "approve-work", "decide-approval", "operate-runtime",
    "integrate-candidate", "hold-durable-authority", "none-recorded",
})
ROLE_ASSIGNMENT = frozenset({
    "policy-revision-record",
    "unix-peer-credential-projection",
    "owner-decision",
    "unassigned-in-corpus",
})
ROTATIONS = frozenset({
    "overlap-window-and-canary", "revocation-immediate", "unspecified-in-corpus",
})
STORAGE_CLASSES = frozenset({
    "systemd-credential",
    "protected-descriptor",
    "host-secret-provider",
    "external-secret-provider-reference",
    "encrypted-ciphertext-with-escrowed-key",
    "unspecified-in-corpus",
})
AUDIENCES = frozenset({
    "production-runtime",
    "connector-installation",
    "development-candidate",
    "release-authority",
    "unspecified-in-corpus",
})
VISIBILITIES = frozenset({
    "tenant-scoped", "operator-only", "published-to-client",
    "development-only", "unassigned-in-corpus",
})
PROMOTABILITY = frozenset({
    "not-promotable", "promotable", "unassigned-in-corpus",
})
DELETION_METHODS = frozenset({
    "tombstone-then-garbage-collect", "state-based-ageing", "unassigned-in-corpus",
})
ENFORCEMENT_POINTS = frozenset({
    "queue-insertion", "host-start", "both", "backup-coordinator",
    "sandbox-admission", "unassigned-in-corpus",
})
VERIFICATIONS = frozenset({
    "integrity-check", "hash-comparison", "version-comparison",
    "startup-in-disconnected-recovery", "credential-resolution",
    "audience-revalidation", "none-recorded",
})
REVERSIBILITY = frozenset({
    "read-only-no-mutation", "reversible-by-inverse-transition",
    "irreversible", "unassigned-in-corpus",
})
PROCEDURE_STATUS = frozenset({"named-in-policy-not-written", "written"})
STEP_KINDS = frozenset({"inspect", "decide", "escalate", "mutate"})
UNITS = frozenset({"minute", "hour", "day", "count", "byte"})

COMMON_FIELDS = ("id", "class", "summary", "owner", "owner_gap", "citation", "withheld")

# Per-section extra fields. `credentials` deliberately has no `example`: a
# credential is recorded by class, owner, rotation and storage class only.
SECTION_FIELDS: dict[str, tuple[str, ...]] = {
    "tenants": ("example",),
    "actor_mappings": ("external_source", "resolves_to", "confers_role", "example"),
    "roles": ("authority", "assignment"),
    "credentials": ("rotation", "storage_class", "audience"),
    "artifact_classes": ("retention_ref", "retention_gap", "visibility"),
    "workspaces_and_dirty_trees": ("release_promotability", "example"),
    "retention": ("ttl", "ttl_gap", "governing_policy", "deletion_method"),
    "budgets": ("limit", "limit_gap", "governing_policy", "enforcement_point"),
    "backup_dependencies": ("requires", "verification"),
    "runbooks": (
        "trigger", "reversibility", "production_touching",
        "documentation_only", "procedure_status", "steps",
    ),
}
OPTIONAL_FIELDS = frozenset({"example"})


class InventoryError(Exception):
    """The inventory document cannot be read at all."""


def load(path: pathlib.Path = INVENTORY) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise InventoryError(f"cannot read {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise InventoryError(f"{path} root is not an object")
    return document


def strings(value: Any, trail: str = "") -> list[tuple[str, str]]:
    """Every string in the document with the path that reaches it."""
    found: list[tuple[str, str]] = []
    if isinstance(value, str):
        found.append((trail or "<root>", value))
    elif isinstance(value, dict):
        for key in value:
            found.extend(strings(value[key], f"{trail}.{key}" if trail else str(key)))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(strings(item, f"{trail}[{index}]"))
    return found


# --- citations -------------------------------------------------------------


def check_citations(document: dict[str, Any], root: pathlib.Path) -> list[str]:
    """A citation must quote a checked-in file exactly.

    This is the whole anti-invention mechanism: an entry may only say what a
    file in this repository already says, and the check fails the moment the
    quoted words stop being there.
    """
    problems: list[str] = []
    citations = document.get("citations")
    if not isinstance(citations, dict) or not citations:
        return ["citations must be a non-empty object of citation-id -> source"]
    for name in sorted(citations):
        where = f"citations.{name}"
        if not IDENTIFIER.fullmatch(name):
            problems.append(f"{where}: citation ID must be lowercase kebab-case")
        entry = citations[name]
        if not isinstance(entry, dict) or set(entry) != {"path", "quote"}:
            problems.append(f"{where}: a citation is exactly a path and a quote")
            continue
        path, quote = entry["path"], entry["quote"]
        if not isinstance(path, str) or not isinstance(quote, str) or not quote:
            problems.append(f"{where}: path and quote must be non-empty strings")
            continue
        if path.startswith("/") or ".." in path.split("/"):
            problems.append(f"{where}: path must be repository-relative")
            continue
        target = root / path
        if not target.is_file():
            problems.append(f"{where}: cited file does not exist: {path}")
            continue
        try:
            text = target.read_text()
        except (OSError, UnicodeDecodeError) as exc:
            problems.append(f"{where}: cited file cannot be read: {exc}")
            continue
        if quote not in text:
            problems.append(
                f"{where}: quoted words are not in {path} — a citation must be "
                f"verbatim, or the fact it supports is recalled, not recorded"
            )
    return problems


def citation_map(document: dict[str, Any]) -> dict[str, Any]:
    """The citation registry, or an empty one when it is unusable.

    Rules are handed the whole registry rather than its keys, because a number
    is checked against the words its citation quotes, not merely against the
    existence of a citation.
    """
    citations = document.get("citations")
    return dict(citations) if isinstance(citations, dict) else {}


# --- owners ----------------------------------------------------------------


def check_owners(document: dict[str, Any], known_citations: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    owners = document.get("owners")
    if not isinstance(owners, dict) or not owners:
        return ["owners must be a non-empty object of owner-id -> record"]
    for name in sorted(owners):
        where = f"owners.{name}"
        if not IDENTIFIER.fullmatch(name):
            problems.append(f"{where}: owner ID must be lowercase kebab-case")
        entry = owners[name]
        if not isinstance(entry, dict) or set(entry) != {"kind", "citation"}:
            problems.append(f"{where}: an owner is exactly a kind and a citation")
            continue
        if entry["kind"] not in OWNER_KINDS:
            problems.append(
                f"{where}: unknown owner kind {entry['kind']!r}; "
                f"allowed: {', '.join(sorted(OWNER_KINDS))}"
            )
        if entry["citation"] not in known_citations:
            problems.append(f"{where}: cites unknown citation {entry['citation']!r}")
    return problems


# --- entries ---------------------------------------------------------------


def check_enum(value: Any, allowed: frozenset[str], where: str, field: str) -> list[str]:
    if value not in allowed:
        return [
            f"{where}: {field}={value!r} is not in the closed vocabulary "
            f"({', '.join(sorted(allowed))})"
        ]
    return []


def check_withheld(value: Any, where: str) -> list[str]:
    """A withheld fact is two enums and nothing else."""
    problems: list[str] = []
    if not isinstance(value, list):
        return [f"{where}: withheld must be a list"]
    seen: set[str] = set()
    for index, item in enumerate(value):
        spot = f"{where}.withheld[{index}]"
        if not isinstance(item, dict) or set(item) != {"shape", "reason"}:
            problems.append(
                f"{spot}: a withheld fact is exactly a shape and a reason — "
                f"it has no field that could hold the value it withholds"
            )
            continue
        problems += check_enum(item["shape"], SHAPES, spot, "shape")
        problems += check_enum(item["reason"], WITHHOLDING_REASONS, spot, "reason")
        if item["shape"] in seen:
            problems.append(f"{spot}: shape {item['shape']!r} is recorded twice")
        seen.add(item["shape"])
    return problems


def check_example(value: Any, where: str) -> list[str]:
    """A concrete example is a marked placeholder in a reserved namespace."""
    if not isinstance(value, dict) or set(value) != {"value", "kind"}:
        return [f"{where}.example: an example is exactly a value and a kind"]
    problems = check_enum(value["kind"], EXAMPLE_KINDS, f"{where}.example", "kind")
    text = value["value"]
    if not isinstance(text, str):
        return problems + [f"{where}.example: value must be a string"]
    if value["kind"] == "synthetic-placeholder":
        if not SYNTHETIC_VALUE.fullmatch(text):
            problems.append(
                f"{where}.example: a synthetic placeholder must be marked in the "
                f"value itself (synthetic-*, optionally .invalid/.example); "
                f"{text!r} is not, so nothing tells a reader it is not real"
            )
    elif value["kind"] == "reserved-non-routable":
        if not RESERVED_VALUE.fullmatch(text):
            problems.append(
                f"{where}.example: a reserved value must sit in a reserved, "
                f"non-routable namespace (.invalid/.example/.test); {text!r} does not"
            )
    return problems


def check_quantity(value: Any, where: str, field: str,
                   citations: dict[str, Any]) -> list[str]:
    """A number is only a fact if the words it cites contain it.

    Requiring *a* citation is not enough: any citation would do, and a recalled
    figure could be parked next to an unrelated quote. The quoted words must
    carry the number itself, beside its unit.
    """
    if not isinstance(value, dict) or set(value) != {"value", "unit", "citation"}:
        return [f"{where}.{field}: a quantity is exactly a value, a unit and a citation"]
    problems: list[str] = []
    amount = value["value"]
    if not isinstance(amount, int) or isinstance(amount, bool):
        problems.append(f"{where}.{field}: value must be an integer")
    problems += check_enum(value["unit"], UNITS, f"{where}.{field}", "unit")
    if value["citation"] not in citations:
        problems.append(
            f"{where}.{field}: cites unknown citation {value['citation']!r} — a "
            f"number without a citation is a recalled number"
        )
        return problems
    if problems:
        return problems
    quote = citations[value["citation"]]
    quote = quote.get("quote", "") if isinstance(quote, dict) else ""
    if value["unit"] == "count":
        pattern = rf"\b{amount}\b"
    else:
        pattern = rf"\b{amount}\s*{value['unit']}s?\b"
    if not re.search(pattern, quote, re.IGNORECASE):
        problems.append(
            f"{where}.{field}: {amount} {value['unit']} does not appear in the "
            f"words it cites, so the number is recalled rather than quoted"
        )
    return problems


def check_entry(section: str, entry: Any, where: str, *,
                owners: set[str], known_citations: dict[str, Any],
                retention_ids: set[str]) -> list[str]:
    problems: list[str] = []
    if not isinstance(entry, dict):
        return [f"{where}: entry must be an object"]

    required = set(COMMON_FIELDS) | set(SECTION_FIELDS[section])
    optional = required & OPTIONAL_FIELDS
    present = set(entry)
    missing = sorted(required - optional - present)
    unknown = sorted(present - required)
    if missing:
        problems.append(f"{where}: missing field(s): {', '.join(missing)}")
    if unknown:
        problems.append(
            f"{where}: unknown field(s): {', '.join(unknown)} — the section's key "
            f"set is closed so an entry cannot carry anything it was not designed to"
        )
    if missing or unknown:
        return problems

    if not isinstance(entry["id"], str) or not IDENTIFIER.fullmatch(entry["id"]):
        problems.append(f"{where}: id must be lowercase kebab-case")
    problems += check_enum(entry["class"], CLASS_VOCABULARY[section], where, "class")
    if not isinstance(entry["summary"], str) or not entry["summary"].strip():
        problems.append(f"{where}: summary must be a non-empty string")
    if entry["citation"] not in known_citations:
        problems.append(f"{where}: cites unknown citation {entry['citation']!r}")

    owner, gap = entry["owner"], entry["owner_gap"]
    if owner is None:
        if gap not in GAP_REASONS:
            problems.append(
                f"{where}: owner is null, so owner_gap must say why "
                f"({', '.join(sorted(GAP_REASONS))}); got {gap!r}"
            )
    else:
        if owner not in owners:
            problems.append(f"{where}: owner {owner!r} is not in the owner registry")
        if gap is not None:
            problems.append(f"{where}: owner is recorded, so owner_gap must be null")

    problems += check_withheld(entry["withheld"], where)
    if "example" in entry and entry["example"] is not None:
        problems += check_example(entry["example"], where)

    problems += SECTION_RULES[section](entry, where, known_citations, retention_ids)
    return problems


def rule_tenants(entry: dict, where: str, citations: dict[str, Any],
                 retention_ids: set[str]) -> list[str]:
    return []


def rule_actor_mappings(entry: dict, where: str, citations: dict[str, Any],
                        retention_ids: set[str]) -> list[str]:
    problems = check_enum(entry["external_source"], EXTERNAL_SOURCES, where,
                          "external_source")
    problems += check_enum(entry["resolves_to"], RESOLVES_TO, where, "resolves_to")
    if entry["confers_role"] is not False:
        problems.append(
            f"{where}: confers_role must be false — an external platform role, "
            f"handle, email or display name never implies an Automonique role"
        )
    return problems


def rule_roles(entry: dict, where: str, citations: dict[str, Any],
               retention_ids: set[str]) -> list[str]:
    problems: list[str] = []
    authority = entry["authority"]
    if not isinstance(authority, list) or not authority:
        problems.append(f"{where}: authority must be a non-empty list")
    else:
        for value in authority:
            problems += check_enum(value, ROLE_AUTHORITIES, where, "authority")
        if "none-recorded" in authority and len(authority) > 1:
            problems.append(
                f"{where}: authority none-recorded cannot be combined with a "
                f"recorded authority"
            )
    problems += check_enum(entry["assignment"], ROLE_ASSIGNMENT, where, "assignment")
    return problems


def rule_credentials(entry: dict, where: str, citations: dict[str, Any],
                     retention_ids: set[str]) -> list[str]:
    problems = check_enum(entry["rotation"], ROTATIONS, where, "rotation")
    problems += check_enum(entry["storage_class"], STORAGE_CLASSES, where,
                           "storage_class")
    problems += check_enum(entry["audience"], AUDIENCES, where, "audience")
    shapes = {item.get("shape") for item in entry["withheld"]
              if isinstance(item, dict)}
    if "secret-material" not in shapes:
        problems.append(
            f"{where}: a credential entry must record that its secret material is "
            f"withheld (shape secret-material), so the absence is stated rather "
            f"than assumed"
        )
    return problems


def rule_artifact_classes(entry: dict, where: str, citations: dict[str, Any],
                          retention_ids: set[str]) -> list[str]:
    problems = check_enum(entry["visibility"], VISIBILITIES, where, "visibility")
    reference, gap = entry["retention_ref"], entry["retention_gap"]
    if reference is None:
        if gap not in GAP_REASONS:
            problems.append(
                f"{where}: retention_ref is null, so retention_gap must say why")
    else:
        if reference not in retention_ids:
            problems.append(
                f"{where}: retention_ref {reference!r} names no entry in the "
                f"retention section")
        if gap is not None:
            problems.append(f"{where}: retention_ref is set, so retention_gap is null")
    return problems


def rule_workspaces(entry: dict, where: str, citations: dict[str, Any],
                    retention_ids: set[str]) -> list[str]:
    return check_enum(entry["release_promotability"], PROMOTABILITY, where,
                      "release_promotability")


def rule_retention(entry: dict, where: str, citations: dict[str, Any],
                   retention_ids: set[str]) -> list[str]:
    problems: list[str] = []
    if entry["governing_policy"] not in citations:
        problems.append(
            f"{where}: governing_policy must cite the policy that governs this "
            f"class; {entry['governing_policy']!r} is not a citation"
        )
    problems += check_enum(entry["deletion_method"], DELETION_METHODS, where,
                           "deletion_method")
    ttl, gap = entry["ttl"], entry["ttl_gap"]
    if ttl is None:
        if gap not in GAP_REASONS:
            problems.append(
                f"{where}: ttl is null, so ttl_gap must say why "
                f"({', '.join(sorted(GAP_REASONS))}); got {gap!r}")
    else:
        problems += check_quantity(ttl, where, "ttl", citations)
        if gap is not None:
            problems.append(f"{where}: ttl is recorded, so ttl_gap must be null")
    return problems


def rule_budgets(entry: dict, where: str, citations: dict[str, Any],
                 retention_ids: set[str]) -> list[str]:
    problems: list[str] = []
    if entry["governing_policy"] not in citations:
        problems.append(
            f"{where}: governing_policy must cite the policy that governs this "
            f"budget; {entry['governing_policy']!r} is not a citation")
    problems += check_enum(entry["enforcement_point"], ENFORCEMENT_POINTS, where,
                           "enforcement_point")
    limit, gap = entry["limit"], entry["limit_gap"]
    if limit is None:
        if gap not in GAP_REASONS:
            problems.append(
                f"{where}: limit is null, so limit_gap must say why "
                f"({', '.join(sorted(GAP_REASONS))}); got {gap!r}")
    else:
        problems += check_quantity(limit, where, "limit", citations)
        if gap is not None:
            problems.append(f"{where}: limit is recorded, so limit_gap must be null")
    return problems


def rule_backup_dependencies(entry: dict, where: str, citations: dict[str, Any],
                             retention_ids: set[str]) -> list[str]:
    problems = check_enum(entry["verification"], VERIFICATIONS, where, "verification")
    requires = entry["requires"]
    if not isinstance(requires, list):
        problems.append(f"{where}: requires must be a list of entry IDs")
        return problems
    if len(set(requires)) != len(requires):
        problems.append(f"{where}: requires lists the same dependency twice")
    if entry["class"] == "recovery-set-input" and requires:
        problems.append(
            f"{where}: a recovery-set input is what a restore starts from and "
            f"cannot itself require a restore step")
    if entry["class"] in {"verification-step", "enablement-gate"} and not requires:
        problems.append(
            f"{where}: a {entry['class']} with no requires puts nothing in order, "
            f"which is the one thing R0-10 needs from this section")
    if entry["class"] == "excluded-material" and requires:
        problems.append(
            f"{where}: material excluded from the recovery set cannot require "
            f"recovery inputs")
    return problems


def rule_runbooks(entry: dict, where: str, citations: dict[str, Any],
                  retention_ids: set[str]) -> list[str]:
    problems: list[str] = []
    if not isinstance(entry["trigger"], str) or not entry["trigger"].strip():
        problems.append(f"{where}: trigger must be a non-empty string")
    else:
        # The trigger is scanned on the same terms as a step: "no step is
        # executable from this inventory" is worth nothing if the command can
        # be written one field to the left.
        problems += check_step_text(entry["trigger"], f"{where}.trigger")
    problems += check_enum(entry["reversibility"], REVERSIBILITY, where,
                           "reversibility")
    if not isinstance(entry["production_touching"], bool):
        problems.append(f"{where}: production_touching must be a boolean")
    if entry["documentation_only"] is not True:
        problems.append(
            f"{where}: documentation_only must be true — this inventory records "
            f"that a runbook exists and never becomes a way to run it")
    problems += check_enum(entry["procedure_status"], PROCEDURE_STATUS, where,
                           "procedure_status")
    steps = entry["steps"]
    if not isinstance(steps, list):
        problems.append(f"{where}: steps must be a list")
        return problems
    if entry["procedure_status"] == "named-in-policy-not-written" and steps:
        problems.append(
            f"{where}: procedure_status says the runbook is not written, so it "
            f"cannot carry steps")
    for index, step in enumerate(steps):
        spot = f"{where}.steps[{index}]"
        if not isinstance(step, dict) or set(step) != {"kind", "text"}:
            problems.append(f"{spot}: a step is exactly a kind and a text")
            continue
        problems += check_enum(step["kind"], STEP_KINDS, spot, "kind")
        if not isinstance(step["text"], str) or not step["text"].strip():
            problems.append(f"{spot}: text must be a non-empty string")
            continue
        problems += check_step_text(step["text"], spot)
        if entry["production_touching"] and step["kind"] == "mutate":
            problems.append(
                f"{spot}: a production-touching runbook records no mutating step "
                f"here; it is documentation only")
    return problems


# A step is prose describing what an operator does, never something a reader or
# a script could execute. These are the spellings that turn prose into a
# command; any of them means the step has stopped being documentation.
EXECUTABLE_MARKERS = (
    (re.compile(r"(?m)^\s*[$#>]\s+\S"), "a shell prompt"),
    (re.compile(r"`[^`]*(?:sudo|rm |curl |ssh |psql|sqlite3|systemctl|kubectl)"),
     "a command in backticks"),
    (re.compile(r"\b(?:sudo|systemctl|kubectl|journalctl)\s+\S"), "a command word"),
    (re.compile(r"\brm\s+-[rf]"), "a destructive command"),
    (re.compile(r"&&|\|\||\brun:\s"), "shell chaining"),
    (re.compile(r"(?:DROP|DELETE|UPDATE|INSERT)\s+(?:TABLE|FROM|INTO)\b"),
     "an SQL statement"),
)


def check_step_text(text: str, where: str) -> list[str]:
    for pattern, description in EXECUTABLE_MARKERS:
        if pattern.search(text):
            return [
                f"{where}: step text contains {description}; a runbook step in "
                f"this inventory is documentation and is never executable from it"
            ]
    return []


SECTION_RULES = {
    "tenants": rule_tenants,
    "actor_mappings": rule_actor_mappings,
    "roles": rule_roles,
    "credentials": rule_credentials,
    "artifact_classes": rule_artifact_classes,
    "workspaces_and_dirty_trees": rule_workspaces,
    "retention": rule_retention,
    "budgets": rule_budgets,
    "backup_dependencies": rule_backup_dependencies,
    "runbooks": rule_runbooks,
}


# --- sections --------------------------------------------------------------


def check_gap(gap: Any, where: str, known_citations: dict[str, Any]) -> list[str]:
    if not isinstance(gap, dict) or set(gap) != {"id", "missing", "reason", "citation"}:
        return [f"{where}: a gap is exactly an ID, what is missing, a reason and "
                f"a citation"]
    problems: list[str] = []
    if not isinstance(gap["id"], str) or not IDENTIFIER.fullmatch(gap["id"]):
        problems.append(f"{where}: gap ID must be lowercase kebab-case")
    if not isinstance(gap["missing"], str) or not gap["missing"].strip():
        problems.append(f"{where}: missing must be a non-empty string")
    problems += check_enum(gap["reason"], GAP_REASONS, where, "reason")
    if gap["citation"] not in known_citations:
        problems.append(f"{where}: cites unknown citation {gap['citation']!r}")
    return problems


def check_sections(document: dict[str, Any], known_citations: dict[str, Any],
                   owners: set[str]) -> list[str]:
    problems: list[str] = []
    sections = document.get("sections")
    if not isinstance(sections, dict):
        return ["sections must be an object with one key per required section"]

    missing = [name for name in SECTION_ORDER if name not in sections]
    for name in missing:
        problems.append(
            f"sections.{name} is missing — all ten sections are required, and a "
            f"section with nothing to record says so with a reason instead")
    unknown = sorted(set(sections) - set(SECTION_ORDER))
    for name in unknown:
        problems.append(f"sections.{name} is not one of the ten required sections")

    retention_ids = {
        entry["id"]
        for entry in (sections.get("retention") or {}).get("entries", [])
        if isinstance(entry, dict) and isinstance(entry.get("id"), str)
    } if isinstance(sections.get("retention"), dict) else set()

    for name in SECTION_ORDER:
        if name not in sections:
            continue
        where = f"sections.{name}"
        section = sections[name]
        if not isinstance(section, dict) or set(section) != {
            "empty_reason", "entries", "gaps"
        }:
            problems.append(
                f"{where}: a section is exactly an empty_reason, its entries and "
                f"its gaps")
            continue
        entries, gaps = section["entries"], section["gaps"]
        if not isinstance(entries, list) or not isinstance(gaps, list):
            problems.append(f"{where}: entries and gaps must be lists")
            continue
        if not entries and not section["empty_reason"]:
            problems.append(
                f"{where}: the section is empty and states no reason — an empty "
                f"section says so explicitly with a reason rather than being blank")
        if entries and section["empty_reason"] is not None:
            problems.append(
                f"{where}: empty_reason is set on a section that has entries")
        seen: set[str] = set()
        for index, entry in enumerate(entries):
            spot = f"{where}.entries[{index}]"
            if isinstance(entry, dict) and isinstance(entry.get("id"), str):
                spot = f"{where}[{entry['id']}]"
                if entry["id"] in seen:
                    problems.append(f"{spot}: duplicate entry ID")
                seen.add(entry["id"])
            problems += check_entry(name, entry, spot, owners=owners,
                                    known_citations=known_citations,
                                    retention_ids=retention_ids)
        gap_ids: set[str] = set()
        for index, gap in enumerate(gaps):
            spot = f"{where}.gaps[{index}]"
            problems += check_gap(gap, spot, known_citations)
            if isinstance(gap, dict) and isinstance(gap.get("id"), str):
                if gap["id"] in gap_ids:
                    problems.append(f"{spot}: duplicate gap ID")
                gap_ids.add(gap["id"])
    return problems


# --- restore ordering ------------------------------------------------------


def restore_order(entries: list[dict]) -> tuple[list[str], list[str]]:
    """Deterministic restore order, or the reason there is not one.

    Kahn's algorithm with an alphabetical tie-break, so the order a reader sees
    is the order the file records and re-running cannot shuffle it.
    """
    nodes = {e["id"]: e for e in entries if e["class"] != "excluded-material"}
    problems: list[str] = []
    for name in sorted(nodes):
        for dependency in nodes[name]["requires"]:
            if dependency not in nodes:
                problems.append(
                    f"sections.backup_dependencies[{name}]: requires {dependency!r}, "
                    f"which is not a restorable entry in this section")
    if problems:
        return [], problems

    remaining = {name: set(nodes[name]["requires"]) for name in nodes}
    order: list[str] = []
    while remaining:
        ready = sorted(name for name, deps in remaining.items() if not deps)
        if not ready:
            stuck = ", ".join(sorted(remaining))
            return [], [
                f"sections.backup_dependencies: restore dependencies do not form "
                f"an order; these entries depend on each other: {stuck}"
            ]
        for name in ready:
            order.append(name)
            del remaining[name]
        for deps in remaining.values():
            deps.difference_update(ready)
    return order, []


def section_entries(document: dict[str, Any], name: str) -> list[dict]:
    sections = document.get("sections")
    if not isinstance(sections, dict):
        return []
    section = sections.get(name)
    if not isinstance(section, dict):
        return []
    entries = section.get("entries")
    return [e for e in entries if isinstance(e, dict)] if isinstance(entries, list) else []


# --- top level -------------------------------------------------------------


def errors(document: dict[str, Any], root: pathlib.Path = ROOT) -> list[str]:
    """Every structural, vocabulary, provenance and ordering finding."""
    problems: list[str] = []
    if document.get("schema") != SCHEMA:
        problems.append(f"schema must be {SCHEMA}")
    if document.get("work_item") != WORK_ITEM:
        problems.append(f"work_item must be {WORK_ITEM}")
    unknown = sorted(set(document) - {"schema", "work_item", "citations", "owners",
                                      "sections"})
    if unknown:
        problems.append(f"unknown top-level field(s): {', '.join(unknown)}")

    problems += check_citations(document, root)
    known = citation_map(document)
    problems += check_owners(document, known)
    owners = set(document["owners"]) if isinstance(document.get("owners"), dict) else set()
    problems += check_sections(document, known, owners)

    backup = section_entries(document, "backup_dependencies")
    if backup and all(
        isinstance(e.get("requires"), list) and e.get("class") in
        CLASS_VOCABULARY["backup_dependencies"] for e in backup
    ):
        _, ordering = restore_order(backup)
        problems += ordering
    return problems


def counts(document: dict[str, Any]) -> dict[str, dict[str, int]]:
    """Measured coverage per section: what is recorded and what is missing."""
    measured: dict[str, dict[str, int]] = {}
    for name in SECTION_ORDER:
        entries = section_entries(document, name)
        sections = document.get("sections", {})
        section = sections.get(name, {}) if isinstance(sections, dict) else {}
        gaps = section.get("gaps", []) if isinstance(section, dict) else []
        measured[name] = {
            "entries": len(entries),
            "gaps": len(gaps) if isinstance(gaps, list) else 0,
            "owner_null": sum(1 for e in entries if e.get("owner") is None),
            "withheld": sum(len(e.get("withheld") or []) for e in entries),
            "synthetic": sum(
                1 for e in entries
                if isinstance(e.get("example"), dict)
                and e["example"].get("kind") == "synthetic-placeholder"
            ),
        }
    return measured
