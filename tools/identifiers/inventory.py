#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Generate and drift-check the Automonique identifier inventory (`R0-13`).

    python3 tools/identifiers/inventory.py generate   # write the inventory
    python3 tools/identifiers/inventory.py verify     # check it, write nothing

The inventory classifies every service, path, environment variable, protocol,
package, command and external-platform name the permitted corpus names, as
`durable`, `compatibility-only` or `presentation-only`. It renames nothing,
generates no codec and closes no gate.

Three properties are what make it worth having rather than a hand list.

1. **Derived, not typed out.** Every entry is produced by a *region*: a named,
   deterministic parse of one section of one checked-in `docs/product-plan/`
   file. A region reports what it extracted, so a parser that rots stops
   extracting and the anti-vacuity guard fails rather than the inventory
   silently shrinking.

2. **Bidirectional drift.** Forward: regenerating must reproduce the checked-in
   file byte for byte, and every entry's name and evidence literal must still
   occur in every file it cites. Backward: every token a region extracts must be
   accounted for by an individual declaration, a declared family, or a withheld
   fingerprint. A source that gains a name fails; a source that loses one fails.

3. **Refused, not discouraged.** The class, kind, disposition and spelling-form
   vocabularies are closed and checked at build time. A compatibility-only entry
   without a durable counterpart, an entry citing a file outside the permitted
   corpus, an entry with no citation, and any output carrying a legacy
   identifier, an absolute home path, an email address, a bare IP address or a
   third-party host name all raise before anything is written.

Nothing here reads, mounts, clones or searches the private archive. The only
inputs are `docs/product-plan/` files, which `AGENTS.md` permits in full.

Wiring the `verify` subcommand into `plan/check.py` is the follow-up for the
integrator; this module is self-contained and standalone-runnable so that it can
be wired without being rewritten.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import sys
from dataclasses import dataclass, field
from typing import Callable

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUTPUT_RELATIVE = "plan/inventory/identifiers.json"
CORPUS = "docs/product-plan"
SCHEMA = "automonique.identifier-inventory/v1"
GENERATOR = "tools/identifiers/inventory.py"
LICENCE = "Elastic-2.0"

# --- Closed vocabularies ----------------------------------------------------
#
# `plan/contracts/R0-13.md`: "The class vocabulary is closed"; "Every entry
# records its kind ... from a closed kind set". An unknown value is refused at
# construction, so an invalid entry cannot be represented in the output.

KINDS = (
    "command",
    "environment-variable",
    "external-platform-name",
    "package",
    "path",
    "protocol",
    "service",
)

CLASSES = ("compatibility-only", "durable", "presentation-only")

# A disposition is what the declaration says to do with a derived name. The
# first three become classified entries; `unclassified` becomes a listed
# finding, and the last two become listed gaps. There is no sixth value and no
# free-text escape.
DISPOSITIONS = CLASSES + ("unclassified", "out-of-scope", "withheld")

# How the recorded spelling relates to the real identifier. `legacy-suffix`
# exists because `legacy-inventory.md` records the predecessor's product
# variables as suffixes with the prefix noted once; writing the prefix here
# would violate the location rule `plan/check.py` enforces.
SPELLING_FORMS = ("literal", "legacy-suffix", "name-family")

CLASSIFIED = frozenset(CLASSES)
GAP_DISPOSITIONS = frozenset(("out-of-scope", "withheld"))


class InventoryError(Exception):
    """The inventory cannot be derived truthfully from its permitted sources."""


# --- Scrub rules ------------------------------------------------------------
#
# `plan/contracts/R0-13.md`, Scrub hygiene: "no private identifier, personal
# address, host name or absolute home path appears in the inventory".
#
# The legacy identifier is matched by fingerprint rather than spelling, the same
# way `plan/check.py`'s `check_legacy_identifier_location` does, so that
# enforcing the rule does not violate it and no failure message ever prints the
# value. `plan/gates.md#gate-scrub` permits that identifier only inside
# `docs/product-plan/reference/legacy-inventory.md` and the name registry; this
# file is neither, so the generator refuses to emit it at all.
LEGACY_TOKEN_FINGERPRINTS = (
    {
        "length": 4,
        "digest": "4ff17bc8ee5f240c792b8a41bfa2c58af726d83b925cf696af0c811627714c85",
        "reason": "the predecessor system's identifier prefix",
    },
)
SANCTIONED_LEGACY_INVENTORY = f"{CORPUS}/reference/legacy-inventory.md"

WORD = re.compile(r"[A-Za-z][A-Za-z0-9]*")
ABSOLUTE_HOME_PATH = re.compile(r"(?:/home/|/Users/|/root/|~/)")
EMAIL_ADDRESS = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
BARE_IP = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
# `(?![\w-])` keeps `automonique.dev-metrics/v1` from reading as a `.dev` host.
HOST_NAME = re.compile(
    r"\b[A-Za-z0-9-]+\.(?:com|net|org|io|dev|app|cloud|internal|local)(?![\w-])"
)

SCRUB_PATTERNS = (
    ("absolute home path", ABSOLUTE_HOME_PATH),
    ("personal email address", EMAIL_ADDRESS),
    ("bare IP address", BARE_IP),
    ("host name", HOST_NAME),
)


def scrub(text: str, where: str) -> None:
    """Refuse text carrying anything the inventory may not publish."""
    lengths = {rule["length"] for rule in LEGACY_TOKEN_FINGERPRINTS}
    reasons = {rule["digest"]: rule["reason"] for rule in LEGACY_TOKEN_FINGERPRINTS}
    for word in WORD.findall(text):
        if len(word) not in lengths:
            continue
        reason = reasons.get(hashlib.sha256(word.lower().encode()).hexdigest())
        if reason is not None:
            raise InventoryError(
                f"{where} names a legacy identifier ({reason}); "
                f"{plan_relative_output()} is not one of the locations "
                f"plan/gates.md#gate-scrub permits it in"
            )
    for label, pattern in SCRUB_PATTERNS:
        found = pattern.search(text)
        if found is not None:
            raise InventoryError(f"{where} carries a {label}: {found.group(0)!r}")


def plan_relative_output() -> str:
    return OUTPUT_RELATIVE


# --- Region extraction ------------------------------------------------------

BACKTICKED = re.compile(r"`([^`\n]+)`")
CRATE_LINE = re.compile(r"^[\s│├└─-]*(automonique[a-z0-9-]*)/")
TWO_SPACES = re.compile(r"\s{2,}")


def read(root: pathlib.Path, relative: str) -> str:
    path = root / relative
    try:
        return path.read_text()
    except OSError as exc:
        raise InventoryError(f"cannot read permitted source {relative}: {exc}") from exc


def require_corpus_file(name: str, relative: str) -> None:
    """Refuse a citation of a file outside the permitted corpus.

    The boundary is a property of the path alone, so every caller checks it
    before reading the file. A source outside the corpus is not evidence of
    anything, so a content check applied first could only mask this refusal
    with an unrelated message.
    """
    if not relative.startswith(f"{CORPUS}/"):
        raise InventoryError(
            f"entry {name!r} cites {relative}, which is outside the permitted "
            f"corpus {CORPUS}/"
        )


def corpus_files(root: pathlib.Path) -> list[str]:
    base = root / CORPUS
    if not base.is_dir():
        raise InventoryError(f"the permitted corpus {CORPUS} does not exist")
    return sorted(
        path.relative_to(root).as_posix() for path in base.rglob("*.md") if path.is_file()
    )


def section(text: str, heading: str, relative: str) -> str:
    """The body under `heading`, up to the next heading of the same or higher level."""
    level = len(heading) - len(heading.lstrip("#"))
    lines = text.splitlines()
    try:
        start = lines.index(heading)
    except ValueError as exc:
        raise InventoryError(
            f"{relative} no longer contains the section {heading!r}; the region "
            f"that reads it would extract nothing"
        ) from exc
    body: list[str] = []
    for line in lines[start + 1:]:
        if line.startswith("#"):
            depth = len(line) - len(line.lstrip("#"))
            if depth <= level:
                break
        body.append(line)
    return "\n".join(body)


def paragraph(body: str, marker: str, relative: str, heading: str) -> str:
    """The block of non-blank lines beginning with the line that starts `marker`."""
    lines = body.splitlines()
    for index, line in enumerate(lines):
        if line.startswith(marker):
            block = [line]
            for following in lines[index + 1:]:
                if not following.strip():
                    break
                block.append(following)
            return "\n".join(block)
    raise InventoryError(
        f"{relative} {heading} no longer contains a paragraph starting {marker!r}"
    )


def fenced(body: str, relative: str, heading: str) -> str:
    """The first fenced block in `body`."""
    inside = False
    block: list[str] = []
    for line in body.splitlines():
        if line.startswith("```"):
            if inside:
                return "\n".join(block)
            inside = True
            continue
        if inside:
            block.append(line)
    raise InventoryError(f"{relative} {heading} no longer contains a fenced block")


def is_legacy_token(token: str) -> bool:
    return token.lstrip("@.").lower().startswith("legacy")


def extract_legacy_tokens(root: pathlib.Path) -> dict[str, tuple[str, ...]]:
    found: dict[str, set[str]] = {}
    for relative in corpus_files(root):
        for token in BACKTICKED.findall(read(root, relative)):
            if is_legacy_token(token):
                found.setdefault(token, set()).add(relative)
    return {token: tuple(sorted(files)) for token, files in found.items()}


def extract_automonique_packages(root: pathlib.Path) -> dict[str, tuple[str, ...]]:
    found: dict[str, set[str]] = {}
    for relative in corpus_files(root):
        for token in BACKTICKED.findall(read(root, relative)):
            if token.startswith("@automonique"):
                found.setdefault(token, set()).add(relative)
    return {token: tuple(sorted(files)) for token, files in found.items()}


def single_file(relative: str, extract: Callable[[str, str], list[str]]):
    def run(root: pathlib.Path) -> dict[str, tuple[str, ...]]:
        names = extract(read(root, relative), relative)
        if len(names) != len(set(names)):
            duplicates = sorted({n for n in names if names.count(n) > 1})
            raise InventoryError(
                f"region over {relative} extracted duplicate names: {duplicates}"
            )
        return {name: (relative,) for name in names}

    return run


def workspace_crates(text: str, relative: str) -> list[str]:
    heading = "## Target workspace layout"
    block = fenced(section(text, heading, relative), relative, heading)
    return [
        match.group(1)
        for match in (CRATE_LINE.match(line) for line in block.splitlines())
        if match is not None
    ]


def binary_subcommands(text: str, relative: str) -> list[str]:
    heading = "### One binary rule"
    block = fenced(section(text, heading, relative), relative, heading)
    names: list[str] = []
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped.startswith("automonique"):
            continue
        # A trailing description is separated from the command list by a run of
        # spaces; `reload-status` and `self-host` keep their single hyphen.
        commands = TWO_SPACES.split(stripped)[0]
        parts = [part.strip() for part in commands.split("|")]
        head = parts[0].split()
        if len(head) != 2:
            raise InventoryError(
                f"{relative} {heading} has a command line this region cannot "
                f"read deterministically: {stripped!r}"
            )
        names.append(f"automonique {head[1]}")
        names.extend(f"automonique {part}" for part in parts[1:])
    return names


def legacy_environment_suffixes(text: str, relative: str) -> list[str]:
    body = section(text, "## Configuration surface", relative)
    names: list[str] = []
    for line in body.splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 2:
            continue
        names.extend(BACKTICKED.findall(cells[1]))
    return names


def unprefixed_environment_variables(text: str, relative: str) -> list[str]:
    heading = "## Configuration surface"
    body = section(text, heading, relative)
    marker = "Unprefixed, and therefore credentials or third-party contracts:"
    return BACKTICKED.findall(paragraph(body, marker, relative, heading))


def legacy_commands(text: str, relative: str) -> list[str]:
    heading = "## Command and route vocabulary"
    body = section(text, heading, relative)
    return BACKTICKED.findall(paragraph(body, "**Commands", relative, heading))


def legacy_conversation_routes(text: str, relative: str) -> list[str]:
    heading = "## Command and route vocabulary"
    body = section(text, heading, relative)
    return BACKTICKED.findall(paragraph(body, "**Conversation routes", relative, heading))


def chat_platform_methods(text: str, relative: str) -> list[str]:
    heading = "## External effect surface"
    body = section(text, heading, relative)
    return BACKTICKED.findall(paragraph(body, "**Chat platform:**", relative, heading))


def normalized_events(text: str, relative: str) -> list[str]:
    heading = "## Normalized event model"
    body = section(text, heading, relative)
    names: list[str] = []
    for line in body.splitlines():
        if line.startswith("- `"):
            names.extend(BACKTICKED.findall(line))
    return names


# --- Declarations -----------------------------------------------------------


@dataclass(frozen=True)
class Declaration:
    """What the inventory says about one derived name."""

    disposition: str
    kind: str | None = None
    spelling_form: str | None = None
    forwards_to: str | None = None
    forwards_to_also: tuple[str, ...] = ()
    reason: str = ""
    authorized_by: str | None = None

    def validate(self, name: str) -> None:
        where = f"declaration for {name!r}"
        if self.disposition not in DISPOSITIONS:
            raise InventoryError(
                f"{where} has disposition {self.disposition!r}, which is not one of "
                f"{list(DISPOSITIONS)}"
            )
        if self.disposition in GAP_DISPOSITIONS:
            if self.kind is not None or self.spelling_form is not None:
                raise InventoryError(f"{where} is a gap and may not carry a kind")
            if not self.reason:
                raise InventoryError(f"{where} is a gap and must give a reason")
        else:
            if self.kind not in KINDS:
                raise InventoryError(
                    f"{where} has kind {self.kind!r}, which is not one of {list(KINDS)}"
                )
            if self.spelling_form not in SPELLING_FORMS:
                raise InventoryError(
                    f"{where} has spelling form {self.spelling_form!r}, which is not "
                    f"one of {list(SPELLING_FORMS)}"
                )
        if self.disposition == "compatibility-only":
            if not self.forwards_to:
                raise InventoryError(
                    f"{where} is compatibility-only and names no durable identifier "
                    f"to forward to; it would forward to nothing"
                )
            if not self.reason:
                raise InventoryError(
                    f"{where} is compatibility-only and must say why the "
                    f"compatibility surface exists"
                )
            if not self.authorized_by:
                raise InventoryError(
                    f"{where} is compatibility-only and must cite the permitted "
                    f"source that binds it to its durable counterpart"
                )
        else:
            if self.forwards_to or self.forwards_to_also:
                raise InventoryError(
                    f"{where} is not compatibility-only, so it may not forward"
                )
        if self.disposition == "unclassified" and not self.reason:
            raise InventoryError(
                f"{where} is unclassified and must say why no class in the closed "
                f"set applies"
            )


@dataclass(frozen=True)
class Region:
    """A named, deterministic parse of permitted source material."""

    id: str
    description: str
    extract: Callable[[pathlib.Path], dict[str, tuple[str, ...]]]
    default: Declaration | None = None
    overrides: dict[str, Declaration] = field(default_factory=dict)
    families: tuple[tuple[str, str, Declaration], ...] = ()
    minimum: int = 1


# Shared reasons, written once so that a hundred entries cannot drift into a
# hundred slightly different explanations.
NO_COUNTERPART = (
    "docs/product-plan/reference/legacy-inventory.md records this as a suffix of "
    "the predecessor's uniform product prefix, and no permitted source spells the "
    "canonical Automonique variable it would forward to. "
    "docs/product-plan/requirements/operations-and-governance.md states the rule "
    "that would generate the pair (canonical AUTOMONIQUE_* resolved before legacy "
    "LEGACY_* fallback) but enumerates no suffix, so classifying this "
    "compatibility-only would create the dangling forward the contract refuses, "
    "and classifying it durable would assert a rename no document has made."
)

TABLE_NOT_A_KIND = (
    "a durable database table name is not a service, path, environment variable, "
    "protocol, package, command or external-platform name; "
    "docs/product-plan/requirements/state-and-protocols.md owns the version-1 "
    "table vocabulary."
)

ROUTE_NOT_A_KIND = (
    "a conversation route label is a stored routing vocabulary, not a service, "
    "path, environment variable, protocol, package, command or external-platform "
    "name, so the closed kind set cannot represent it."
)

NAMESPACE_ROOT = (
    "a bare compatibility namespace root written as a glob, not an identifier of "
    "any of the seven kinds; the identifiers it stands for are inventoried "
    "individually."
)

PROTOCOL_NO_COUNTERPART = (
    "docs/product-plan/requirements/state-and-protocols.md calls this a version-1 "
    "compatibility surface that a compatibility release may decode but never emit, "
    "and docs/product-plan/requirements/target-architecture.md retains its codec, "
    "but no permitted source spells the canonical Automonique protocol name it "
    "would forward to; recording it compatibility-only would create the dangling "
    "forward the contract refuses."
)

FORWARDING_SHIM = (
    "docs/product-plan/requirements/target-architecture.md installs the "
    "compatibility entry points as thin forwarding shims that exec "
    "`automonique <subcommand>` and contain no logic."
)

TARGET_ARCHITECTURE = f"{CORPUS}/requirements/target-architecture.md"
MIGRATION_PLAN = f"{CORPUS}/reference/migration-plan.md"
FEATURE_PARITY = f"{CORPUS}/reference/feature-parity.md"
OPERATOR_TUI = f"{CORPUS}/requirements/operator-tui.md"
OPERATIONS = f"{CORPUS}/requirements/operations-and-governance.md"
TYPESCRIPT_SDK = f"{CORPUS}/requirements/typescript-sdk.md"
CHANNEL_INTEGRATIONS = f"{CORPUS}/requirements/channel-integrations.md"
PLAN_REVIEW = f"{CORPUS}/reference/plan-review.md"
CLIENT_SURFACES = f"{CORPUS}/requirements/client-experience-and-surfaces.md"
VERIFICATION_ROLLOUT = f"{CORPUS}/requirements/verification-and-rollout.md"
AGENT_INTEGRATIONS = f"{CORPUS}/requirements/agent-integrations.md"
LEGACY_SOURCE = SANCTIONED_LEGACY_INVENTORY


def alias(
    kind: str,
    forwards_to: str,
    reason: str,
    authorized_by: str,
    spelling_form: str = "literal",
    also: tuple[str, ...] = (),
) -> Declaration:
    return Declaration(
        disposition="compatibility-only",
        kind=kind,
        spelling_form=spelling_form,
        forwards_to=forwards_to,
        forwards_to_also=also,
        reason=reason,
        authorized_by=authorized_by,
    )


def durable(kind: str, spelling_form: str = "literal") -> Declaration:
    return Declaration(disposition="durable", kind=kind, spelling_form=spelling_form)


def unclassified(kind: str, reason: str, spelling_form: str = "literal") -> Declaration:
    return Declaration(
        disposition="unclassified", kind=kind, spelling_form=spelling_form, reason=reason
    )


def out_of_scope(reason: str) -> Declaration:
    return Declaration(disposition="out-of-scope", reason=reason)


LEGACY_TOKEN_DECLARATIONS: dict[str, Declaration] = {
    ".legacy-current": alias(
        "path",
        ".automonique-current",
        "existing installations continue to recognize the previous release "
        "selector during the compatibility window, and migration must not create "
        "two independently active release selectors.",
        TARGET_ARCHITECTURE,
    ),
    ".legacy-releases": alias(
        "path",
        ".automonique-releases",
        "existing installations continue to recognize the previous release tree "
        "during the compatibility window; migration adopts or links one verified "
        "release tree.",
        TARGET_ARCHITECTURE,
    ),
    "@legacy": alias(
        "package",
        "@automonique",
        "the current/previous SDK-release compatibility matrix covers canonical "
        "and supported forwarding package scopes together.",
        TYPESCRIPT_SDK,
        spelling_form="name-family",
    ),
    "@legacy/*": alias(
        "package",
        "@automonique",
        "existing package identifiers remain compatibility names while connectors "
        "negotiate protocol and capabilities rather than display names.",
        CHANNEL_INTEGRATIONS,
        spelling_form="name-family",
    ),
    "@legacy/sdk*": alias(
        "package",
        "@automonique/sdk*",
        "every public package is canonicalized under the Automonique scope and the "
        "previous scope is forwarding-only for the deprecation window.",
        PLAN_REVIEW,
        spelling_form="name-family",
    ),
    "@legacy/sdk/connector": alias(
        "package",
        "@automonique/sdk/connector",
        "connectors use the canonical connector package with a temporary "
        "forwarding export if needed.",
        CHANNEL_INTEGRATIONS,
    ),
    "@legacy/sdk/provider": alias(
        "package",
        "@automonique/sdk/provider",
        "the out-of-process provider adapter SPI ships under the canonical scope "
        "with a forwarding export during migration.",
        TYPESCRIPT_SDK,
    ),
    "LEGACY_*": alias(
        "environment-variable",
        "AUTOMONIQUE_*",
        "canonical configuration is resolved before the legacy fallback, and "
        "conflicting simultaneous values fail closed rather than applying a "
        "precedence rule.",
        OPERATIONS,
        spelling_form="name-family",
    ),
    "LEGACY_RUNNER": alias(
        "environment-variable",
        "AUTOMONIQUE_RUNNER",
        "the existing daemon selects the Rust runner through the canonical "
        "variable; the legacy spelling is accepted only as a recorded migration "
        "alias.",
        MIGRATION_PLAN,
    ),
    "LegacyClient": out_of_scope(
        "a TypeScript client type alias is not one of the seven inventoried kinds; "
        "docs/product-plan/requirements/typescript-sdk.md owns the SDK type surface."
    ),
    "LegacyTransport": out_of_scope(
        "a TypeScript in-memory transport type alias is not one of the seven "
        "inventoried kinds; docs/product-plan/requirements/typescript-sdk.md owns "
        "the SDK type surface."
    ),
    "legacy": out_of_scope(NAMESPACE_ROOT),
    "legacy*": out_of_scope(NAMESPACE_ROOT),
    "legacy-inventory.md": out_of_scope(
        "a document path inside this repository's own plan corpus, not a "
        "predecessor runtime identifier."
    ),
    "legacy-run.sh": unclassified(
        "path",
        "the porting map names its Rust destination (automonique-runner execution "
        "hosts) but no permitted source declares a forwarding alias or a canonical "
        "path for it, so recording it compatibility-only would create a dangling "
        "forward and recording it durable would assert a survival the plan does "
        "not state.",
    ),
    "legacy-say": alias(
        "command",
        "automonique-say",
        "the parity ledger replaces the progress-announcement helper with a "
        "canonical worker capability plus outbox and keeps a forwarding alias "
        "during migration.",
        FEATURE_PARITY,
    ),
    "legacy-shell": alias(
        "command",
        "automonique-shell",
        "the optional isolated shell subsystem keeps only a declared forwarding "
        "alias; the agent TUI is never a general shell.",
        MIGRATION_PLAN,
    ),
    "legacy-shot": alias(
        "command",
        "automonique-shot",
        "the parity ledger rebuilds the screenshot outcome under the canonical "
        "name while the implementation may remain unchanged initially.",
        FEATURE_PARITY,
    ),
    "legacy-tui": alias(
        "command",
        "automonique tui",
        "the previous terminal entry point forwards to the same client during the "
        "declared compatibility window.",
        OPERATOR_TUI,
    ),
    "legacy.*": unclassified("protocol", PROTOCOL_NO_COUNTERPART, spelling_form="name-family"),
    "legacy.db": unclassified(
        "path",
        "docs/product-plan/requirements/operator-tui.md names this only as a file "
        "the TUI never opens directly, and no permitted source spells a canonical "
        "Automonique database path it would forward to.",
    ),
    "legacy.runner.event": unclassified("protocol", PROTOCOL_NO_COUNTERPART),
    "legacy:audit": alias(
        "command",
        "automonique audit",
        "reconciliation scripts become typed reconcilers reached through the "
        "canonical subcommand; the legacy command forwards during migration.",
        MIGRATION_PLAN,
    ),
    "legacy_*": out_of_scope(TABLE_NOT_A_KIND),
    "legacyctl": alias(
        "command",
        "automonique",
        FORWARDING_SHIM
        + " The permitted sources additionally bind it to individual subcommands, "
        "which are recorded in forwards_to_also rather than collapsed into one.",
        TARGET_ARCHITECTURE,
        also=(
            "automonique audit",
            "automonique doctor",
            "automonique reload",
            "automonique rollback",
            "automonique status",
            "automonique tui",
        ),
    ),
    "legacyctl tui": alias(
        "command",
        "automonique tui",
        "the previous control command's terminal subcommand forwards to the same "
        "client during the declared compatibility window.",
        OPERATOR_TUI,
    ),
    "legacyd": alias(
        "command",
        "automonique daemon",
        FORWARDING_SHIM
        + " The daemon subcommand names the long-running control-plane role that "
        "this shim reaches.",
        TARGET_ARCHITECTURE,
    ),
}

LEGACY_TABLE_FAMILY = (
    "legacy-table-names",
    r"^legacy_[a-z][a-z0-9_]*$",
    out_of_scope(TABLE_NOT_A_KIND),
)

# `POSTMARK_TOKEN` in the sanctioned inventory names a third-party product.
# `plan/gates.md#gate-scrub`: "Client, customer and third-party product names are
# never permitted, in that file or anywhere else." It is therefore accounted for
# by fingerprint and its spelling is not copied here.
WITHHELD_ENVIRONMENT_VARIABLES = {
    "33995859639c81ae2f708a8ac6853b22301affe6260485471a5bdaebe227d35f": Declaration(
        disposition="withheld",
        reason="the unprefixed variable at this fingerprint names a third-party "
        "product. plan/gates.md#gate-scrub permits third-party product names "
        "nowhere, so the inventory accounts for the variable without copying its "
        "spelling out of the sanctioned inventory.",
    ),
}


REGIONS: tuple[Region, ...] = (
    Region(
        id="legacy-tokens",
        description=(
            "every backticked token in the permitted corpus whose first segment "
            "is the compatibility namespace root, ignoring a leading '@' or '.'"
        ),
        extract=extract_legacy_tokens,
        default=None,
        overrides=LEGACY_TOKEN_DECLARATIONS,
        families=(LEGACY_TABLE_FAMILY,),
        minimum=25,
    ),
    Region(
        id="automonique-packages",
        description=(
            "every backticked npm package token in the permitted corpus under the "
            "canonical Automonique scope"
        ),
        extract=extract_automonique_packages,
        default=durable("package"),
        overrides={"@automonique": durable("package", "name-family")},
        minimum=8,
    ),
    Region(
        id="workspace-crates",
        description=(
            "every Cargo package named by the target workspace layout tree in "
            "target-architecture.md"
        ),
        extract=single_file(TARGET_ARCHITECTURE, workspace_crates),
        default=durable("package"),
        minimum=25,
    ),
    Region(
        id="binary-subcommands",
        description=(
            "every subcommand of the single unprivileged executable, from the "
            "One binary rule dispatch block in target-architecture.md"
        ),
        extract=single_file(TARGET_ARCHITECTURE, binary_subcommands),
        default=durable("command"),
        minimum=15,
    ),
    Region(
        id="legacy-environment-suffixes",
        description=(
            "every product environment variable suffix in the Configuration "
            "surface table of legacy-inventory.md; the uniform prefix is noted "
            "once there and is never written here"
        ),
        extract=single_file(LEGACY_SOURCE, legacy_environment_suffixes),
        default=unclassified(
            "environment-variable", NO_COUNTERPART, spelling_form="legacy-suffix"
        ),
        overrides={
            "JCODE_*": unclassified(
                "environment-variable", NO_COUNTERPART, spelling_form="name-family"
            )
        },
        minimum=40,
    ),
    Region(
        id="unprefixed-environment-variables",
        description=(
            "every unprefixed environment variable in legacy-inventory.md, which "
            "that document classifies as a credential or third-party contract"
        ),
        extract=single_file(LEGACY_SOURCE, unprefixed_environment_variables),
        default=durable("environment-variable"),
        overrides={
            "CLAUDE_*": durable("environment-variable", "name-family"),
            "CODEX_*": durable("environment-variable", "name-family"),
            "OPENCODE_*": durable("environment-variable", "name-family"),
        },
        minimum=10,
    ),
    Region(
        id="legacy-commands",
        description=(
            "every direct command in the Command and route vocabulary of "
            "legacy-inventory.md; the migration plan ports the exact command "
            "registry before model-assisted routing"
        ),
        extract=single_file(LEGACY_SOURCE, legacy_commands),
        default=durable("command"),
        minimum=15,
    ),
    Region(
        id="legacy-conversation-routes",
        description=(
            "every deterministic conversation route in the Command and route "
            "vocabulary of legacy-inventory.md"
        ),
        extract=single_file(LEGACY_SOURCE, legacy_conversation_routes),
        default=out_of_scope(ROUTE_NOT_A_KIND),
        minimum=10,
    ),
    Region(
        id="chat-platform-methods",
        description=(
            "every chat-platform Web API method in the External effect surface of "
            "legacy-inventory.md, recorded by its public protocol spelling only"
        ),
        extract=single_file(LEGACY_SOURCE, chat_platform_methods),
        default=durable("external-platform-name"),
        minimum=10,
    ),
    Region(
        id="normalized-events",
        description=(
            "every normalized event name in the Normalized event model of "
            "agent-integrations.md"
        ),
        extract=single_file(AGENT_INTEGRATIONS, normalized_events),
        default=durable("protocol"),
        overrides={
            "AssistantPreviewDelta": Declaration(
                disposition="presentation-only",
                kind="protocol",
                spelling_form="literal",
            )
        },
        minimum=20,
    ),
)


@dataclass(frozen=True)
class Cited:
    """A name the corpus states directly rather than enumerating in a region."""

    name: str
    declaration: Declaration
    file: str
    evidence: str


CITED: tuple[Cited, ...] = (
    Cited(
        "automonique",
        durable("command"),
        TARGET_ARCHITECTURE,
        "unprivileged executable**, `automonique`",
    ),
    Cited(
        "automonique-say",
        durable("command"),
        FEATURE_PARITY,
        "canonical `automonique-say` worker capability",
    ),
    Cited(
        "automonique-shot",
        durable("command"),
        FEATURE_PARITY,
        "under canonical `automonique-shot`",
    ),
    Cited(
        ".automonique-current",
        durable("path"),
        TARGET_ARCHITECTURE,
        ".automonique-current -> .automonique-releases/<selected>",
    ),
    Cited(
        ".automonique-releases",
        durable("path"),
        TARGET_ARCHITECTURE,
        ".automonique-releases/<timestamp>-<revision>/",
    ),
    Cited(
        "AUTOMONIQUE_RUNNER",
        durable("environment-variable"),
        MIGRATION_PLAN,
        "canonical `AUTOMONIQUE_RUNNER=rust`",
    ),
    Cited(
        "AUTOMONIQUE_*",
        durable("environment-variable", "name-family"),
        OPERATIONS,
        "Canonical `AUTOMONIQUE_*` configuration is resolved before legacy",
    ),
    Cited(
        "Monique",
        Declaration(
            disposition="presentation-only", kind="package", spelling_form="literal"
        ),
        CLIENT_SURFACES,
        "presentation-only signed assets/animations with no tools, secrets or "
        "authority. Monique is the first-party mascot",
    ),
    Cited(
        "automonique.dev-metrics/v1",
        durable("protocol"),
        VERIFICATION_ROLLOUT,
        "every `automonique.dev-metrics/v1` manifest",
    ),
    Cited(
        "automonique daemon",
        durable("service"),
        TARGET_ARCHITECTURE,
        "`daemon` names the long-running control-plane role",
    ),
    Cited(
        "automonique runner",
        durable("service"),
        TARGET_ARCHITECTURE,
        "### `automonique runner` execution host",
    ),
    Cited(
        "automonique-shell",
        durable("service"),
        TARGET_ARCHITECTURE,
        "optional isolated interactive shell/file-transfer service",
    ),
    Cited(
        "automonique-lab",
        durable("service"),
        TARGET_ARCHITECTURE,
        "`automonique-lab` is deliberately outside the production process graph",
    ),
    Cited(
        "automonique-deploy-broker",
        durable("service"),
        TARGET_ARCHITECTURE,
        "`automonique-deploy-broker` — root-owned deployment broker",
    ),
    Cited(
        "automonique-sandbox-launcher",
        durable("service"),
        TARGET_ARCHITECTURE,
        "`automonique-sandbox-launcher` — optional root-owned namespace/routing setup",
    ),
)


# Kinds and surfaces this inventory does not reach, named rather than implied.
GAPS: tuple[dict[str, str], ...] = (
    {
        "id": "legacy-service-names",
        "statement": "no legacy name is inventoried under the service kind.",
        "reason": "docs/product-plan/reference/legacy-inventory.md describes the "
        "predecessor's two live units neutrally as 'the ticket bot and a durable "
        "tmux server' and spells neither unit name, so there is no permitted "
        "source to cite. Inventing one would be invention, not derivation.",
    },
    {
        "id": "dashboard-route-paths",
        "statement": "the 38 dashboard API routes are not inventoried.",
        "reason": "docs/product-plan/reference/legacy-inventory.md enumerates them "
        "and the plan reproduces the surface through the generated SDK, but no "
        "permitted source states whether each route path survives, forwards or is "
        "replaced, so every entry would be an unclassified finding carrying no "
        "information the source does not already carry.",
    },
    {
        "id": "canonical-wire-protocol-names",
        "statement": "no canonical Automonique wire-protocol name is inventoried "
        "beyond the development-metrics manifest schema.",
        "reason": "the corpus spells `automonique.dev-metrics/v1` and no other "
        "dotted canonical protocol name, which is why the version-1 compatibility "
        "protocol family is recorded as unclassified rather than forwarded.",
    },
    {
        "id": "legacy-command-count",
        "statement": "legacy-inventory.md heads its direct command list "
        "'Commands (21)' and then lists 19 backticked commands.",
        "reason": "the region extracts what the document spells. The discrepancy "
        "is reported rather than reconciled, because reconciling it would mean "
        "inventing two commands or editing a source outside this item's lease.",
    },
    {
        "id": "backward-scan-coverage",
        "statement": "the backward direction of the drift check covers the ten "
        "regions listed under `regions`, not the whole corpus.",
        "reason": "the compatibility half is covered corpus-wide by the "
        "`legacy-tokens` region, which reads every markdown file under "
        "docs/product-plan/. The canonical half is covered where the corpus "
        "enumerates it deterministically (workspace crates, binary subcommands, "
        "npm packages, normalized events) and by forwarding closure elsewhere: "
        "every compatibility-only entry's counterpart must exist as a durable "
        "entry. Prose that names a canonical identifier in neither an enumerated "
        "region nor a forwarding relation is not scanned.",
    },
)


CONSUMERS = {
    "R1-17": (
        "Read plan/inventory/identifiers.json. `durable_names` is the sorted set "
        "of every name classified durable; `compatibility_forwards` maps each "
        "compatibility-only name to {\"forwards_to\": <durable name>, \"also\": "
        "[<durable name>, ...]}. For the check 'no durable identifier is "
        "rewritten by this slice': every CanonicalName::spelling() in "
        "rust/crates/automonique-protocol/src/compat/generated.rs must appear in "
        "`durable_names`, and for every LegacyName the alias spelling must appear "
        "in `compatibility_forwards` with its canonical().spelling() equal to "
        "`forwards_to` or present in `also`. The inventory derives its names from "
        "docs/product-plan/ and never reads the registry, so the comparison is "
        "between two independently sourced lists rather than a restatement."
    ),
    "R1-19": (
        "`legacy_exceptions` is the sorted exception set for the namespace gate: "
        "one row per compatibility-only entry whose first segment is the "
        "compatibility namespace root, carrying name, kind, forwards_to and the "
        "authorizing permitted source. An identifier outside the namespace and "
        "outside this set is a finding; an entry here naming an identifier the "
        "corpus no longer spells fails this inventory's own forward drift check "
        "first."
    ),
}


# --- Building the document --------------------------------------------------


@dataclass
class Built:
    entries: list[dict] = field(default_factory=list)
    unclassified: list[dict] = field(default_factory=list)
    out_of_scope: list[dict] = field(default_factory=list)
    withheld: list[dict] = field(default_factory=list)
    families: list[dict] = field(default_factory=list)
    regions: list[dict] = field(default_factory=list)
    withheld_used: set[str] = field(default_factory=set)


def resolve_region(root: pathlib.Path, region: Region, built: Built) -> None:
    extracted = region.extract(root)
    if len(extracted) < region.minimum:
        raise InventoryError(
            f"region {region.id} extracted {len(extracted)} names but must extract "
            f"at least {region.minimum}; a region that stops matching makes the "
            f"backward drift check vacuous"
        )
    compiled = [
        (name, re.compile(pattern), declaration)
        for name, pattern, declaration in region.families
    ]
    absorbed: dict[str, list[str]] = {name: [] for name, _, _ in compiled}

    for name in sorted(extracted):
        files = extracted[name]
        digest = hashlib.sha256(name.encode()).hexdigest()
        # The withheld fingerprints are consulted first, because they are a scrub
        # rule: a name that may not be written here must not reach a disposition
        # that would write it, whatever the region's default says.
        declaration = WITHHELD_ENVIRONMENT_VARIABLES.get(digest)
        if declaration is not None:
            built.withheld_used.add(digest)
            record(built, name, declaration, region.id, files, name, digest)
            continue
        # An individual declaration wins, then the region's default, then a
        # declared family. A family is consulted last so that it can never
        # silently take over a name someone declared deliberately.
        declaration = region.overrides.get(name)
        if declaration is None and region.default is not None:
            declaration = region.default
        if declaration is None:
            for family_name, pattern, family_declaration in compiled:
                if pattern.match(name):
                    absorbed[family_name].append(name)
                    declaration = family_declaration
                    break
        if declaration is None:
            raise InventoryError(
                f"region {region.id} extracted {name!r} from {list(files)} and no "
                f"declaration, family or withheld fingerprint accounts for it; a "
                f"permitted source gained a name the inventory does not classify"
            )
        if declaration.disposition == "withheld":
            raise InventoryError(
                f"declaration for {name!r} is withheld but is keyed by spelling; a "
                f"withheld name is keyed by fingerprint so that its spelling never "
                f"appears in this file"
            )
        record(built, name, declaration, region.id, files, name, None)

    for name in sorted(region.overrides):
        if name not in extracted:
            raise InventoryError(
                f"region {region.id} declares {name!r} but no longer extracts it; "
                f"a permitted source lost a name the inventory still classifies"
            )
    for family_name, _, family_declaration in compiled:
        if not absorbed[family_name]:
            raise InventoryError(
                f"family {family_name} in region {region.id} absorbed nothing, so "
                f"it grants a permission nothing needs"
            )
        built.families.append(
            {
                "pattern": family_name,
                "region": region.id,
                "disposition": family_declaration.disposition,
                "reason": family_declaration.reason,
                "absorbed_count": len(absorbed[family_name]),
                "absorbed": sorted(absorbed[family_name]),
            }
        )

    built.regions.append(
        {
            "id": region.id,
            "description": region.description,
            "extracted_count": len(extracted),
            "minimum": region.minimum,
        }
    )


def record(
    built: Built,
    name: str,
    declaration: Declaration,
    region_id: str,
    files: tuple[str, ...],
    evidence: str,
    digest: str | None,
) -> None:
    declaration.validate(name)
    for relative in files:
        require_corpus_file(name, relative)
    source = {"region": region_id, "files": list(files), "evidence": evidence}
    if declaration.disposition in CLASSIFIED:
        entry = {
            "name": name,
            "kind": declaration.kind,
            "class": declaration.disposition,
            "spelling_form": declaration.spelling_form,
            "source": source,
        }
        if declaration.disposition == "compatibility-only":
            entry["forwards_to"] = declaration.forwards_to
            entry["forwards_to_also"] = list(declaration.forwards_to_also)
            entry["reason"] = declaration.reason
            entry["authorized_by"] = declaration.authorized_by
        built.entries.append(entry)
    elif declaration.disposition == "unclassified":
        built.unclassified.append(
            {
                "name": name,
                "kind": declaration.kind,
                "spelling_form": declaration.spelling_form,
                "source": source,
                "reason": declaration.reason,
            }
        )
    elif declaration.disposition == "out-of-scope":
        built.out_of_scope.append(
            {"name": name, "source": source, "reason": declaration.reason}
        )
    else:
        built.withheld.append(
            {
                "sha256": digest,
                "source": {"region": region_id, "files": list(files)},
                "reason": declaration.reason,
            }
        )


def build(root: pathlib.Path) -> dict:
    built = Built()
    for region in REGIONS:
        resolve_region(root, region, built)

    unused = sorted(set(WITHHELD_ENVIRONMENT_VARIABLES) - built.withheld_used)
    if unused:
        raise InventoryError(
            f"withheld fingerprints match nothing any region extracts: {unused}; a "
            f"withholding that protects no name is a dead permission"
        )

    for cited in CITED:
        require_corpus_file(cited.name, cited.file)
        text = read(root, cited.file)
        if cited.name not in text:
            raise InventoryError(
                f"cited entry {cited.name!r} no longer occurs in {cited.file}"
            )
        if cited.evidence not in text:
            raise InventoryError(
                f"cited entry {cited.name!r} no longer has its evidence in "
                f"{cited.file}: {cited.evidence!r}"
            )
        record(built, cited.name, cited.declaration, "cited", (cited.file,), cited.evidence, None)

    seen: set[tuple[str, str]] = set()
    for entry in built.entries:
        key = (entry["kind"], entry["name"])
        if key in seen:
            raise InventoryError(
                f"two entries share the kind/name key {key}; one name of one kind "
                f"cannot carry two classes"
            )
        seen.add(key)

    durable_names = sorted({e["name"] for e in built.entries if e["class"] == "durable"})
    durable_set = set(durable_names)

    forwards: dict[str, dict] = {}
    for entry in built.entries:
        if entry["class"] != "compatibility-only":
            continue
        targets = [entry["forwards_to"], *entry["forwards_to_also"]]
        for target in targets:
            if target not in durable_set:
                raise InventoryError(
                    f"compatibility-only entry {entry['name']!r} forwards to "
                    f"{target!r}, which is not a durable entry in this inventory; "
                    f"it would forward to nothing"
                )
        forwards[entry["name"]] = {
            "forwards_to": entry["forwards_to"],
            "also": list(entry["forwards_to_also"]),
            "kind": entry["kind"],
        }

    exceptions = sorted(
        (
            {
                "name": entry["name"],
                "kind": entry["kind"],
                "forwards_to": entry["forwards_to"],
                "authorized_by": entry["authorized_by"],
            }
            for entry in built.entries
            if entry["class"] == "compatibility-only" and is_legacy_token(entry["name"])
        ),
        key=lambda row: row["name"],
    )
    if not exceptions:
        raise InventoryError(
            "the inventory records no legacy compatibility exception, so R1-19's "
            "exception set would be empty and its inventory binding vacuous"
        )

    by_kind = {kind: 0 for kind in KINDS}
    by_class = {name: 0 for name in CLASSES}
    for entry in built.entries:
        by_kind[entry["kind"]] += 1
        by_class[entry["class"]] += 1
    unclassified_by_kind = {kind: 0 for kind in KINDS}
    for finding in built.unclassified:
        unclassified_by_kind[finding["kind"]] += 1
        by_kind[finding["kind"]] += 1

    missing = sorted(kind for kind, count in by_kind.items() if count == 0)
    if missing:
        raise InventoryError(
            f"the closed kind set is not covered; nothing is inventoried under: "
            f"{missing}"
        )
    empty_classes = sorted(name for name, count in by_class.items() if count == 0)
    if empty_classes:
        raise InventoryError(
            f"the closed class vocabulary is not exercised; no entry is classified: "
            f"{empty_classes}"
        )

    built.entries.sort(key=lambda entry: (entry["kind"], entry["name"]))
    built.unclassified.sort(key=lambda row: (row["kind"], row["name"]))
    built.out_of_scope.sort(key=lambda row: row["name"])
    built.withheld.sort(key=lambda row: row["sha256"])
    built.families.sort(key=lambda row: row["pattern"])
    built.regions.sort(key=lambda row: row["id"])

    return {
        "schema": SCHEMA,
        "generator": GENERATOR,
        "licence": LICENCE,
        "item": "R0-13",
        "permitted_corpus": CORPUS,
        "vocabulary": {
            "kinds": list(KINDS),
            "classes": list(CLASSES),
            "dispositions": list(DISPOSITIONS),
            "spelling_forms": list(SPELLING_FORMS),
        },
        "counts": {
            "entries": len(built.entries),
            "by_class": by_class,
            "by_kind_including_unclassified": by_kind,
            "unclassified": len(built.unclassified),
            "unclassified_by_kind": unclassified_by_kind,
            "out_of_scope": len(built.out_of_scope),
            "withheld": len(built.withheld),
            "families": len(built.families),
            "regions": len(built.regions),
            "durable_names": len(durable_names),
            "compatibility_forwards": len(forwards),
            "legacy_exceptions": len(exceptions),
            "gaps": len(GAPS),
        },
        "regions": built.regions,
        "families": built.families,
        "entries": built.entries,
        "unclassified": built.unclassified,
        "out_of_scope": built.out_of_scope,
        "withheld": built.withheld,
        "gaps": [dict(gap) for gap in GAPS],
        "durable_names": durable_names,
        "compatibility_forwards": forwards,
        "legacy_exceptions": exceptions,
        "consumers": dict(CONSUMERS),
    }


def render(root: pathlib.Path) -> bytes:
    document = build(root)
    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    scrub(text, plan_relative_output())
    return text.encode()


# --- Anti-vacuity guard -----------------------------------------------------


def guard_scrub_rules(root: pathlib.Path) -> None:
    """The legacy fingerprint must still match inside the sanctioned inventory.

    A fingerprint that matches nothing anywhere would let the scrub refusal pass
    on every input, including one carrying the identifier under a rotted digest.
    """
    text = read(root, SANCTIONED_LEGACY_INVENTORY)
    lengths = {rule["length"] for rule in LEGACY_TOKEN_FINGERPRINTS}
    digests = {rule["digest"] for rule in LEGACY_TOKEN_FINGERPRINTS}
    hits = sum(
        1
        for word in WORD.findall(text)
        if len(word) in lengths
        and hashlib.sha256(word.lower().encode()).hexdigest() in digests
    )
    if not hits:
        raise InventoryError(
            f"the legacy-identifier fingerprints match nothing in "
            f"{SANCTIONED_LEGACY_INVENTORY}, so the scrub rule proves nothing"
        )


# --- Commands ---------------------------------------------------------------


def generate(root: pathlib.Path) -> int:
    guard_scrub_rules(root)
    content = render(root)
    target = root / OUTPUT_RELATIVE
    target.parent.mkdir(parents=True, exist_ok=True)
    # Written to a staging path and renamed, so a reader in a parallel run never
    # observes a half-written inventory.
    staging = target.with_name(f".{target.name}.staging-{os.getpid()}")
    try:
        staging.write_bytes(content)
        os.replace(staging, target)
    finally:
        if staging.exists():
            staging.unlink()
    document = json.loads(content)
    counts = document["counts"]
    print(
        f"wrote {OUTPUT_RELATIVE}: {counts['entries']} entries, "
        f"{counts['unclassified']} unclassified, {counts['out_of_scope']} out of "
        f"scope, {counts['withheld']} withheld, over {counts['regions']} regions"
    )
    return 0


def verify(root: pathlib.Path) -> int:
    errors: list[str] = []
    expected: bytes | None = None
    try:
        guard_scrub_rules(root)
        expected = render(root)
    except InventoryError as exc:
        errors.append(str(exc))

    target = root / OUTPUT_RELATIVE
    if not target.is_file():
        errors.append(f"{OUTPUT_RELATIVE} does not exist; run 'generate'")
    elif expected is not None:
        actual = target.read_bytes()
        if actual != expected:
            errors.append(first_difference(actual, expected))

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    document = json.loads(expected or b"{}")
    counts = document["counts"]
    print(
        f"ok - {OUTPUT_RELATIVE} re-derives from {counts['regions']} regions of "
        f"{CORPUS}: {counts['entries']} entries "
        f"({counts['by_class']['durable']} durable, "
        f"{counts['by_class']['compatibility-only']} compatibility-only, "
        f"{counts['by_class']['presentation-only']} presentation-only), "
        f"{counts['unclassified']} unclassified, {counts['gaps']} named gaps"
    )
    return 0


def quotable(line: str) -> str:
    """The checked-in line, or a redaction if quoting it would publish the value.

    The whole point of matching a legacy identifier by fingerprint is that the
    enforcement never prints it. A drift message that echoes the offending line
    would put a planted identifier into a CI log, which is the same leak by a
    different route, so the checked-in side of the comparison is scrubbed before
    it is quoted. The derived side needs no scrub: it came from `render`, which
    already refused to produce anything the scrub rejects.
    """
    try:
        scrub(line, "the checked-in line")
    except InventoryError as exc:
        return f"<redacted: {exc}>"
    return repr(line.strip())


def first_difference(actual: bytes, expected: bytes) -> str:
    actual_lines = actual.decode(errors="replace").splitlines()
    expected_lines = expected.decode(errors="replace").splitlines()
    for number, (left, right) in enumerate(zip(actual_lines, expected_lines), start=1):
        if left != right:
            return (
                f"{OUTPUT_RELATIVE} line {number}: checked in {quotable(left)}, "
                f"the sources derive {right.strip()!r}"
            )
    return (
        f"{OUTPUT_RELATIVE} has {len(actual_lines)} lines, the sources derive "
        f"{len(expected_lines)}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("generate", "verify"))
    parser.add_argument("--root", default=str(ROOT))
    arguments = parser.parse_args(argv)
    root = pathlib.Path(arguments.root).resolve()
    try:
        if arguments.command == "generate":
            return generate(root)
        return verify(root)
    except InventoryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
