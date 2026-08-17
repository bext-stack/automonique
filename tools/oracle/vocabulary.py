#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""The closed vocabulary the parity boundary may release, and nothing else.

Every value that reaches agent context is a member of one of the enumerations
below or a field identifier from `fields.json`. There is no free-text slot
anywhere in the released shape, which is the whole mechanism: a channel with no
text field cannot carry source text, a credential, a path, or a traceback,
whatever the process on the other side does.

The wire therefore carries *selectors*, not content. The inside chooses which
of a finite set of clean-side constants is released; it never supplies the
bytes that are released. That makes the channel's capacity finite and
computable — `capacity_bits()` states it, because an unstated covert channel is
the one nobody budgets for.
"""

from __future__ import annotations

import dataclasses
import enum
import json
import math
import pathlib
import re
from typing import Final

RELEASE_SCHEMA: Final = "automonique.oracle-release/v1"
REGISTRY_SCHEMA: Final = "automonique.oracle-fields/v1"
REGISTRY_PATH: Final = pathlib.Path(__file__).with_name("fields.json")

# One record per comparison, and a small one. The inside refuses to emit more
# and the boundary refuses to accept more; neither trusts the other.
RECORD_LIMIT: Final = 4096

FIELD_ID = re.compile(r"[a-z][a-z0-9_]{0,62}\Z")
FIXTURE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
ENVIRONMENT_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
DESCRIPTION = re.compile(r"[ -~]{1,120}\Z")

# Names that must never be forwarded into the custody process by this side.
# A credential the inside needs is the custody host's business and reaches it
# by the custody host's own means; anything this side pushes across is a
# clean-side value entering a contaminated process.
FORBIDDEN_ENVIRONMENT_SUBSTRINGS: Final = (
    "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "PRIVATE", "SESSION", "COOKIE",
)


class VocabularyError(Exception):
    """The vocabulary or its registry cannot be trusted."""


class Outcome(enum.Enum):
    """Comparison outcomes.

    The first four are the ones
    `docs/product-plan/requirements/ai-implementation-harness.md`
    § Differential parity and shadow oracle names. The rest are operational.
    """

    EXACT = "exact"
    EQUIVALENT = "equivalent"
    INTENTIONALLY_CHANGED = "intentionally_changed"
    UNEXPLAINED = "unexplained"
    ORACLE_ERROR = "oracle_error"
    INPUT_REJECTED = "input_rejected"
    # Clean-side only. The boundary reaches these verdicts about the inside;
    # the inside may not assert them about itself.
    REFUSED = "refused"
    TIMEOUT = "timeout"


CLEAN_SIDE_ONLY: Final = frozenset({Outcome.REFUSED, Outcome.TIMEOUT})
WIRE_OUTCOMES: Final = {
    outcome.value: outcome for outcome in Outcome if outcome not in CLEAN_SIDE_ONLY
}
# An outcome constrains its own difference list, so the two cannot be varied
# independently. Fewer reachable combinations is less channel capacity.
EMPTY_DIFFERENCES_REQUIRED: Final = frozenset(
    {Outcome.EXACT, Outcome.ORACLE_ERROR, Outcome.INPUT_REJECTED}
)
DIFFERENCES_REQUIRED: Final = frozenset(
    {Outcome.EQUIVALENT, Outcome.INTENTIONALLY_CHANGED, Outcome.UNEXPLAINED}
)


class Relation(enum.Enum):
    """How a compared field differed. Never *what* it contained."""

    VALUE_DIFFERS = "value_differs"
    ABSENT_IN_CANDIDATE = "absent_in_candidate"
    ABSENT_IN_REFERENCE = "absent_in_reference"
    TYPE_DIFFERS = "type_differs"
    ORDER_DIFFERS = "order_differs"
    MASKED_NONDETERMINISTIC = "masked_nondeterministic"


class Magnitude(enum.Enum):
    """A coarse class, deliberately not a measurement.

    A timing or size measurement precise enough to reconstruct behavior is a
    failure mode, so no number crosses the
    boundary: the wire has no integer slot and a JSON number anywhere in
    a record is refused.
    """

    NONE = "none"
    MINOR = "minor"
    MODERATE = "moderate"
    MAJOR = "major"


class Refusal(enum.Enum):
    """Why the boundary released nothing. A closed set, carrying no detail.

    A refusal reason is itself a selector the inside can steer, so it is
    counted in `capacity_bits()` rather than treated as free.
    """

    NO_RECORD = "no_record"
    EMPTY_RECORD = "empty_record"
    OVERSIZE = "oversize"
    NOT_UTF8 = "not_utf8"
    NOT_JSON = "not_json"
    NOT_OBJECT = "not_object"
    UNKNOWN_KEY = "unknown_key"
    MISSING_KEY = "missing_key"
    BAD_SCHEMA = "bad_schema"
    UNKNOWN_OUTCOME = "unknown_outcome"
    RESERVED_OUTCOME = "reserved_outcome"
    DIFFERENCES_NOT_LIST = "differences_not_list"
    TOO_MANY_DIFFERENCES = "too_many_differences"
    DIFFERENCE_NOT_OBJECT = "difference_not_object"
    UNKNOWN_FIELD = "unknown_field"
    UNKNOWN_RELATION = "unknown_relation"
    UNKNOWN_MAGNITUDE = "unknown_magnitude"
    DUPLICATE_FIELD = "duplicate_field"
    MASK_NOT_REGISTERED = "mask_not_registered"
    OUTCOME_DIFFERENCES_DISAGREE = "outcome_differences_disagree"
    FIELD_NOT_REQUESTED = "field_not_requested"
    SCAN_REJECTED = "scan_rejected"
    INSIDE_FAILED = "inside_failed"
    CUSTODY_REJECTED = "custody_rejected"


class ReleasePolicy(enum.Enum):
    """How much of a validated record is allowed through.

    `OUTCOME_ONLY` is the low-capacity setting: the record is still validated
    in full, then everything except the outcome is discarded. Use it when a
    run's only question is "did it match".
    """

    OUTCOME_ONLY = "outcome_only"
    FIELD_RELATIONS = "field_relations"


class Area(enum.Enum):
    """Registry areas, from the harness requirement's comparison list."""

    STATE = "state"
    ACTION = "action"
    RECEIPT = "receipt"
    RENDERING = "rendering"
    PROVIDER_EVENT = "provider_event"
    RESOURCE = "resource"


@dataclasses.dataclass(frozen=True)
class Field:
    """One comparable field the clean side declared in advance."""

    field_id: str
    area: Area
    masked: bool
    description: str


@dataclasses.dataclass(frozen=True)
class Registry:
    """The clean side's field registry: the only field names releasable."""

    fields: tuple[Field, ...]

    def __post_init__(self) -> None:
        if not self.fields:
            raise VocabularyError("the field registry must declare at least one field")

    def get(self, field_id: object) -> Field | None:
        for field in self.fields:
            if field.field_id == field_id:
                return field
        return None

    def index(self, field_id: str) -> int:
        for position, field in enumerate(self.fields):
            if field.field_id == field_id:
                return position
        raise VocabularyError("field is not registered")

    @property
    def identifiers(self) -> tuple[str, ...]:
        return tuple(field.field_id for field in self.fields)


REQUIRED_FIELD_KEYS: Final = frozenset({"id", "area", "masked", "description"})


def parse_registry(document: object) -> Registry:
    """Parse the checked-in registry, refusing anything not exactly its shape."""
    if not isinstance(document, dict):
        raise VocabularyError("field registry must be a JSON object")
    if set(document) != {"schema", "fields"}:
        raise VocabularyError("field registry has an unsupported shape")
    if document["schema"] != REGISTRY_SCHEMA:
        raise VocabularyError("field registry has an unsupported schema")
    entries = document["fields"]
    if not isinstance(entries, list) or not entries:
        raise VocabularyError("field registry must declare at least one field")
    fields: list[Field] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != REQUIRED_FIELD_KEYS:
            raise VocabularyError(
                "each registry entry needs exactly id, area, masked, description"
            )
        field_id = entry["id"]
        if not isinstance(field_id, str) or not FIELD_ID.fullmatch(field_id):
            raise VocabularyError("registry field ID must be a lowercase identifier")
        if field_id in seen:
            raise VocabularyError(f"duplicate registry field ID: {field_id}")
        try:
            area = Area(entry["area"])
        except ValueError as exc:
            raise VocabularyError("registry field has an unknown area") from exc
        masked = entry["masked"]
        if not isinstance(masked, bool):
            raise VocabularyError("registry field mask flag must be a boolean")
        description = entry["description"]
        if not isinstance(description, str) or not DESCRIPTION.fullmatch(description):
            raise VocabularyError("registry description must be short printable ASCII")
        seen.add(field_id)
        fields.append(Field(field_id, area, masked, description))
    return Registry(tuple(fields))


def load_registry(path: pathlib.Path = REGISTRY_PATH) -> Registry:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VocabularyError(f"cannot read the field registry: {type(exc).__name__}") from exc
    return parse_registry(document)


def released_value_count(registry: Registry, policy: ReleasePolicy) -> int:
    """How many distinct verdicts the boundary can ever produce.

    This is the channel's alphabet size. Everything the inside can express is a
    choice among these, so this number — not an assurance — is what bounds a
    hostile inside.
    """
    refusals = len(Refusal) + 1  # every Refusal, plus TIMEOUT
    if policy is ReleasePolicy.OUTCOME_ONLY:
        return len(WIRE_OUTCOMES) + refusals
    per_field = 1 + len(Relation) * len(Magnitude)
    with_differences = per_field ** len(registry.fields) - 1
    total = refusals
    for outcome in WIRE_OUTCOMES.values():
        total += 1 if outcome in EMPTY_DIFFERENCES_REQUIRED else with_differences
    return total


def capacity_bits(registry: Registry, policy: ReleasePolicy) -> float:
    """Upper bound on bits a hostile inside can send per comparison."""
    return math.log2(released_value_count(registry, policy))


def check_environment_names(names: tuple[str, ...]) -> None:
    """Refuse an environment allow list that could carry a clean-side secret."""
    for name in names:
        if not isinstance(name, str) or not ENVIRONMENT_NAME.fullmatch(name):
            raise VocabularyError("environment allow-list names must be UPPER_SNAKE")
        if any(bad in name for bad in FORBIDDEN_ENVIRONMENT_SUBSTRINGS):
            raise VocabularyError(
                "environment allow list names a credential-shaped variable; "
                "custody credentials are the custody host's to supply"
            )
