# SPDX-License-Identifier: Elastic-2.0

"""Closed-vocabulary parser for shell and file-transfer usage observations.

`plan/contracts/R0-11.md` asks for a measurement this repository cannot take.
Nothing in this tree can reach a running instance of the predecessor system, so
the usage counts do not exist here and are not invented here. What does exist is
the shape the measurement must arrive in, and the rules that make a dishonest
measurement unrepresentable rather than merely discouraged:

* the usage classes are a closed enum, each one traceable to a checked-in
  planning document, so a corpus cannot quietly omit a class or invent one;
* there is **no field anywhere that can hold a captured command string**. A
  sample carries a shape drawn from a closed enum plus placeholder tokens drawn
  from a closed enum, and must mark itself synthetic. A credential, customer
  name or private host has nowhere to live even before the scanner runs;
* the only capture methods that may carry a number are log-derived. Recall has
  no capture method, which is how "measured, not recalled" is enforced;
* an `unmeasured` corpus may not contain a number and a `measured` corpus may
  not use the synthetic capture method, so a plausible sample cannot be promoted
  into evidence by editing one word;
* every string in a parsed document is scanned for credentials, absolute home
  paths, private hosts and user@host targets, as a second belt.

The parser refuses; it never repairs. Each refusal raises a typed error naming
the rule that caught it, so a test can assert the *named* failure rather than
"something raised".
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[2]

OBSERVATION_SCHEMA = "automonique.shell-usage-observations/v1"
DECISION_INPUTS_SCHEMA = "automonique.shell-decision-inputs/v1"
DECISION_SCHEMA = "automonique.shell-boundary-decision/v1"


# --- typed refusals --------------------------------------------------------


class FixtureError(Exception):
    """Base class for every refusal in this fixture."""


class VocabularyError(FixtureError):
    """A key or value outside the closed vocabulary."""


class ProvenanceError(FixtureError):
    """A number without a measurement, or a measurement without provenance."""


class SanitizationError(FixtureError):
    """A recorded string carries material that must never be recorded."""


class CompletenessError(FixtureError):
    """A usage class is missing, duplicated, or carries more than one outcome."""


class BoundarySpecificityError(FixtureError):
    """A boundary that does not say what it isolates, permits and refuses."""


class ReplacementlessRetirement(FixtureError):
    """A retirement with no replacement outcome or no path for a current user.

    `plan/contracts/R0-11.md`: "Retiring a class with no replacement path is a
    finding requiring an owner decision, never an implicit removal." The finding
    is this exception.
    """


# --- closed vocabularies ---------------------------------------------------

# Every class is a use of the current shell/file-transfer surface that a
# checked-in planning document names. `source` is where it is named; nothing
# here is derived from the private archive.
USAGE_CLASSES: dict[str, dict[str, str]] = {
    "interactive_shell_create": {
        "summary": "creating an interactive shell session on the current dashboard",
        "source": "docs/product-plan/reference/feature-parity.md",
    },
    "interactive_shell_attach": {
        "summary": "attaching to an existing session as observer or controller",
        "source": "docs/product-plan/reference/migration-plan.md",
    },
    "interactive_shell_command": {
        "summary": "commands run inside an attached session, recorded by shape only",
        "source": "docs/product-plan/reference/feature-parity.md",
    },
    "file_upload": {
        "summary": "bytes uploaded into a workspace through the shell surface",
        "source": "docs/product-plan/reference/feature-parity.md",
    },
    "file_download": {
        "summary": "bytes downloaded out of a workspace through the shell surface",
        "source": "docs/product-plan/reference/feature-parity.md",
    },
    "inline_path_bridge": {
        "summary": "the arbitrary host-path transfer bridge the migration removes",
        "source": "docs/product-plan/reference/migration-plan.md",
    },
}

# A capture method that may carry a number must be log-derived. There is
# deliberately no `operator_interview`: an interviewed frequency is recall, and
# the contract's first rule is that usage is measured, not recalled. Adding one
# here is the reviewable act.
COUNTING_CAPTURE_METHODS = (
    "audit_log_query",
    "session_table_count",
    "artifact_service_log",
    "process_accounting",
    "reverse_proxy_access_log",
)
SYNTHETIC_CAPTURE_METHOD = "synthetic_authored"
NULL_CAPTURE_METHOD = "none"
CAPTURE_METHODS = (*COUNTING_CAPTURE_METHODS, SYNTHETIC_CAPTURE_METHOD, NULL_CAPTURE_METHOD)

CORPUS_KINDS = ("measured", "synthetic", "unmeasured")
HOST_ACCESS = ("none", "live-system")
CITATION_KINDS = ("repository_document", "system_log_query", "none")

# Shapes, not commands. A shape is what a reviewer needs to draw a boundary;
# the command text is what would carry a customer's name.
COMMAND_SHAPES = (
    "package_management",
    "log_inspection",
    "service_control",
    "filesystem_inspection",
    "database_client",
    "text_editor",
    "build_or_test",
    "network_diagnostic",
    "file_transfer",
    "other_uncategorized",
)

# The only tokens a sample may contain. Every one is obviously synthetic on
# sight, which is what "marked as synthetic" has to mean in a file a stranger
# reads without the schema next to it.
PLACEHOLDER_TOKENS = (
    "SYNTHETIC_DATABASE",
    "SYNTHETIC_FILE",
    "SYNTHETIC_HOST",
    "SYNTHETIC_PATH",
    "SYNTHETIC_SERVICE",
    "SYNTHETIC_USER",
    "SYNTHETIC_WORKSPACE",
)

OUTCOMES = ("boundary", "retirement", "unresolved")
BLOCKERS = ("usage-measurement", "owner-choice")

# Words that describe a boundary without naming one. The contract says a
# boundary described only as "sandboxed" is not a boundary; this is that rule.
VAGUE_TERMS = frozenset(
    {
        "sandboxed", "sandbox", "isolated", "isolation", "secure", "secured",
        "safe", "safely", "hardened", "restricted", "locked", "lockdown",
        "protected", "audited", "controlled", "limited", "sanitized", "proper",
        "appropriate", "robust", "modern",
    }
)

# Nouns that stand where a named thing belongs. "something more secure" is not
# a replacement; it is the absence of one, spelled optimistically.
HOLLOW_TERMS = frozenset(
    {"something", "anything", "somewhere", "thing", "things", "stuff", "solution",
     "approach", "mechanism", "system", "replacement", "alternative", "way"}
)

# Ignored when deciding whether a statement said anything, so that "isolated
# and hardened" is judged on `isolated` and `hardened` rather than on `and`.
STOPWORDS = frozenset(
    {"a", "an", "the", "and", "or", "but", "of", "in", "on", "to", "for", "with",
     "is", "are", "be", "it", "its", "this", "that", "more", "less", "very",
     "fully", "properly", "just", "only", "by", "as", "at", "from", "some", "new"}
)

CORPUS_ID = re.compile(r"^\d{4}-\d{2}-\d{2}-[a-z0-9][a-z0-9-]{2,40}$")
QUERY_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
DOCUMENT_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9./_-]*(?:#[a-z0-9-]+)?$")
ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


# --- sanitization ----------------------------------------------------------

# Second belt. The first is structural: nothing in the format can hold a
# command. These rules catch material that reached a free-form field such as a
# reason or a citation reference.
SANITIZER_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "credential_assignment",
        re.compile(r"(?i)\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?key)\s*[=:]\s*\S"),
        "a credential assignment",
    ),
    (
        "bearer_token",
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{8,}"),
        "a bearer token",
    ),
    (
        "private_key_block",
        re.compile(r"-----BEGIN(?: [A-Z]+)* PRIVATE KEY-----"),
        "a private key block",
    ),
    (
        "ssh_public_key",
        re.compile(r"\bssh-(?:rsa|dss|ed25519)\s+AAAA"),
        "an SSH key",
    ),
    (
        "cloud_access_key_id",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "a cloud access key id",
    ),
    (
        "absolute_home_path",
        re.compile(r"(?:^|[\s\"'=:(,])(?:/home/|/Users/|/root/)"),
        "an absolute home path",
    ),
    (
        "tilde_home_path",
        re.compile(r"(?:^|[\s\"'=:(,])~[A-Za-z0-9_.-]*/"),
        "a home-relative path",
    ),
    (
        "user_at_host",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b"),
        "a user@host or email address",
    ),
    (
        "private_ipv4",
        re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
        ),
        "a private IPv4 address",
    ),
    (
        "private_hostname",
        re.compile(r"(?i)\b[a-z0-9][a-z0-9-]*\.(?:local|internal|intranet|lan|corp|home)\b"),
        "a private hostname",
    ),
)


def sanitize_string(value: str, *, where: str) -> str:
    """Return `value`, or refuse naming the rule and the location."""
    for rule_id, pattern, description in SANITIZER_RULES:
        if pattern.search(value):
            raise SanitizationError(
                f"{where}: rule {rule_id} matched {description}; "
                f"record the observation by shape and class instead"
            )
    return value


def sanitize_document(node: Any, *, where: str = "$") -> None:
    """Walk every string in a decoded document through the sanitizer."""
    if isinstance(node, str):
        sanitize_string(node, where=where)
    elif isinstance(node, dict):
        for key, value in node.items():
            sanitize_string(str(key), where=f"{where}.{key}")
            sanitize_document(value, where=f"{where}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            sanitize_document(value, where=f"{where}[{index}]")


# --- small helpers ---------------------------------------------------------


def _exact_keys(node: Any, required: set[str], optional: set[str], *, where: str) -> dict[str, Any]:
    if not isinstance(node, dict):
        raise VocabularyError(f"{where} must be an object, found {type(node).__name__}")
    keys = set(node)
    missing = required - keys
    if missing:
        raise VocabularyError(f"{where} is missing required key(s): {', '.join(sorted(missing))}")
    unknown = keys - required - optional
    if unknown:
        raise VocabularyError(
            f"{where} has key(s) outside the closed set: {', '.join(sorted(unknown))}"
        )
    return node


def _enum(value: Any, allowed: tuple[str, ...], *, where: str) -> str:
    if value not in allowed:
        raise VocabularyError(f"{where} must be one of {list(allowed)}, found {value!r}")
    return str(value)


def _date(value: Any, *, where: str) -> dt.date:
    if not isinstance(value, str) or not ISO_DATE.match(value):
        raise VocabularyError(f"{where} must be an ISO date YYYY-MM-DD, found {value!r}")
    try:
        return dt.date.fromisoformat(value)
    except ValueError as exc:
        raise VocabularyError(f"{where} is not a real date: {value!r}") from exc


def _nonempty_specific_list(value: Any, *, where: str) -> list[str]:
    """A list of statements, each of which says something."""
    if not isinstance(value, list) or not value:
        raise BoundarySpecificityError(f"{where} must be a non-empty list")
    out: list[str] = []
    for index, entry in enumerate(value):
        at = f"{where}[{index}]"
        if not isinstance(entry, str) or not entry.strip():
            raise BoundarySpecificityError(f"{at} must be a non-empty statement, found {entry!r}")
        words = [
            word for word in re.split(r"[^a-z]+", entry.strip().lower())
            if word and word not in STOPWORDS
        ]
        if not words or all(word in VAGUE_TERMS | HOLLOW_TERMS for word in words):
            raise BoundarySpecificityError(
                f"{at} says only {entry!r}; name what is isolated, permitted or refused "
                f"in words a reader could test, not reassuring ones"
            )
        if len(entry.strip()) < 12:
            raise BoundarySpecificityError(
                f"{at} must be a statement of at least 12 characters, found {entry!r}"
            )
        out.append(entry)
    return out


def sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- observation corpus ----------------------------------------------------

OBSERVATION_REQUIRED = {"class", "count", "capture_method", "capture_citation", "samples"}
OBSERVATION_OPTIONAL = {"reason", "window"}
CORPUS_REQUIRED = {
    "schema", "corpus_id", "kind", "captured_on", "capture_host_access", "observations",
}


def _parse_citation(node: Any, *, where: str) -> dict[str, Any]:
    citation = _exact_keys(node, {"kind", "ref"}, set(), where=where)
    kind = _enum(citation["kind"], CITATION_KINDS, where=f"{where}.kind")
    ref = citation["ref"]
    if kind == "none":
        if ref is not None:
            raise VocabularyError(f"{where}.ref must be null when kind is 'none'")
    elif kind == "repository_document":
        if not isinstance(ref, str) or not DOCUMENT_REF.match(ref):
            raise VocabularyError(f"{where}.ref must be a repository-relative path, found {ref!r}")
        target = ROOT / ref.split("#", 1)[0]
        if not target.is_file():
            raise ProvenanceError(
                f"{where}.ref cites {ref!r}, which is not a file in this repository"
            )
    else:  # system_log_query
        if not isinstance(ref, str) or not QUERY_ID.match(ref):
            raise VocabularyError(
                f"{where}.ref must be a symbolic query id matching {QUERY_ID.pattern}, "
                f"found {ref!r} — a query id, never the query text"
            )
    return {"kind": kind, "ref": ref}


def _parse_sample(node: Any, *, where: str) -> dict[str, Any]:
    sample = _exact_keys(node, {"shape", "placeholders", "synthetic"}, set(), where=where)
    shape = _enum(sample["shape"], COMMAND_SHAPES, where=f"{where}.shape")
    if sample["synthetic"] is not True:
        raise ProvenanceError(
            f"{where}.synthetic must be exactly true — every sample in this format is a "
            f"placeholder standing in for a real observation, and an unmarked placeholder "
            f"is indistinguishable from captured data"
        )
    placeholders = sample["placeholders"]
    if not isinstance(placeholders, list) or not placeholders:
        raise VocabularyError(f"{where}.placeholders must be a non-empty list")
    for index, token in enumerate(placeholders):
        _enum(token, PLACEHOLDER_TOKENS, where=f"{where}.placeholders[{index}]")
    return {"shape": shape, "placeholders": list(placeholders), "synthetic": True}


def _parse_observation(node: Any, kind: str, *, where: str) -> dict[str, Any]:
    obs = _exact_keys(node, OBSERVATION_REQUIRED, OBSERVATION_OPTIONAL, where=where)
    usage_class = _enum(obs["class"], tuple(USAGE_CLASSES), where=f"{where}.class")
    method = _enum(obs["capture_method"], CAPTURE_METHODS, where=f"{where}.capture_method")
    count = obs["count"]
    reason = obs.get("reason")
    window = obs.get("window")

    if count is not None and (not isinstance(count, int) or isinstance(count, bool) or count < 0):
        raise VocabularyError(f"{where}.count must be null or a non-negative integer")

    if count is None:
        if not isinstance(reason, str) or len(reason.strip()) < 12:
            raise ProvenanceError(
                f"{where}.count is null, so {where}.reason must say why in at least "
                f"12 characters — missing evidence is null with a reason, never absent"
            )
        if method != NULL_CAPTURE_METHOD:
            raise ProvenanceError(
                f"{where} has no count but claims capture method {method!r}; "
                f"an uncaptured class uses {NULL_CAPTURE_METHOD!r}"
            )
        if window is not None:
            raise ProvenanceError(f"{where} has no count, so it cannot carry a capture window")
    else:
        if reason is not None:
            raise VocabularyError(f"{where}.reason is only for a null count")
        if method == NULL_CAPTURE_METHOD:
            raise ProvenanceError(
                f"{where} carries the number {count} with capture method 'none'; "
                f"a number needs the method that produced it"
            )
        window_where = f"{where}.window"
        window = _exact_keys(window, {"start", "end"}, set(), where=window_where)
        start = _date(window["start"], where=f"{window_where}.start")
        end = _date(window["end"], where=f"{window_where}.end")
        if end < start:
            raise VocabularyError(f"{window_where}.end is before {window_where}.start")
        window = {"start": window["start"], "end": window["end"]}

    if kind == "unmeasured" and count is not None:
        raise ProvenanceError(
            f"{where} carries the number {count} in a corpus declared 'unmeasured'; "
            f"a recalled or estimated number presented as data is the failure this "
            f"format exists to prevent"
        )
    if kind == "synthetic" and method != SYNTHETIC_CAPTURE_METHOD:
        raise ProvenanceError(
            f"{where} is in a synthetic corpus but claims capture method {method!r}"
        )
    if kind != "synthetic" and method == SYNTHETIC_CAPTURE_METHOD:
        raise ProvenanceError(
            f"{where} claims capture method {SYNTHETIC_CAPTURE_METHOD!r} in a "
            f"{kind!r} corpus; synthetic data cannot be relabelled as capture"
        )

    citation = _parse_citation(obs["capture_citation"], where=f"{where}.capture_citation")
    if count is not None and citation["kind"] == "none":
        raise ProvenanceError(f"{where} carries a number with no cited capture")

    samples = obs["samples"]
    if not isinstance(samples, list):
        raise VocabularyError(f"{where}.samples must be a list")
    parsed_samples = [
        _parse_sample(entry, where=f"{where}.samples[{index}]") for index, entry in enumerate(samples)
    ]

    return {
        "class": usage_class,
        "count": count,
        "reason": reason,
        "capture_method": method,
        "capture_citation": citation,
        "window": window,
        "samples": parsed_samples,
    }


def parse_corpus(document: Any, *, where: str = "corpus") -> dict[str, Any]:
    """Validate one observation corpus and return its normalized form."""
    sanitize_document(document, where=where)
    corpus = _exact_keys(document, CORPUS_REQUIRED, set(), where=where)
    if corpus["schema"] != OBSERVATION_SCHEMA:
        raise VocabularyError(
            f"{where}.schema must be {OBSERVATION_SCHEMA!r}, found {corpus['schema']!r}"
        )
    corpus_id = corpus["corpus_id"]
    if not isinstance(corpus_id, str) or not CORPUS_ID.match(corpus_id):
        raise VocabularyError(f"{where}.corpus_id must match {CORPUS_ID.pattern}, found {corpus_id!r}")
    kind = _enum(corpus["kind"], CORPUS_KINDS, where=f"{where}.kind")
    captured_on = _date(corpus["captured_on"], where=f"{where}.captured_on")
    host_access = _enum(corpus["capture_host_access"], HOST_ACCESS, where=f"{where}.capture_host_access")
    if kind == "measured" and host_access != "live-system":
        raise ProvenanceError(
            f"{where} is declared measured but records no live-system access at capture"
        )
    if kind != "measured" and host_access != "none":
        raise ProvenanceError(
            f"{where} is {kind!r} but claims live-system access; only a measured corpus "
            f"is captured against a running system"
        )

    observations = corpus["observations"]
    if not isinstance(observations, list):
        raise VocabularyError(f"{where}.observations must be a list")
    parsed = [
        _parse_observation(entry, kind, where=f"{where}.observations[{index}]")
        for index, entry in enumerate(observations)
    ]

    seen = [entry["class"] for entry in parsed]
    duplicates = sorted({name for name in seen if seen.count(name) > 1})
    if duplicates:
        raise CompletenessError(f"{where} records these classes more than once: {', '.join(duplicates)}")
    missing = sorted(set(USAGE_CLASSES) - set(seen))
    if missing:
        raise CompletenessError(
            f"{where} omits usage class(es): {', '.join(missing)} — an omitted class is an "
            f"unrecorded assumption, so every class is stated even when it is null"
        )

    return {
        "corpus_id": corpus_id,
        "kind": kind,
        "captured_on": captured_on.isoformat(),
        "capture_host_access": host_access,
        "observations": sorted(parsed, key=lambda entry: entry["class"]),
    }


def load_corpus(path: pathlib.Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise VocabularyError(f"{path} is not valid JSON: {exc}") from exc
    corpus = parse_corpus(document, where=path.name)
    corpus["path"] = path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else path.name
    corpus["sha256"] = sha256_file(path)
    return corpus


# --- decision record -------------------------------------------------------

DECISION_REQUIRED = {
    "schema", "work_item", "recorded_on", "decision_inputs",
    "standing_plan_disposition", "classes",
}


def _parse_evidence(node: Any, inputs: dict[str, Any], usage_class: str, *, where: str) -> dict[str, Any]:
    """A resolved outcome must point at a measured count for its own class."""
    evidence = _exact_keys(node, {"corpus_id", "count"}, set(), where=where)
    entry = inputs["classes"][usage_class]
    if not entry["resolvable"]:
        raise ProvenanceError(
            f"{where}: class {usage_class} is resolved in the decision record, but the "
            f"decision inputs record {entry['resolvable_reason']}. A class does not take "
            f"an outcome on absent or synthetic usage data"
        )
    measured = entry["measured"]
    if evidence["corpus_id"] != measured["corpus_id"] or evidence["count"] != measured["count"]:
        raise ProvenanceError(
            f"{where} cites {evidence['corpus_id']!r}/{evidence['count']!r}; the decision "
            f"inputs record {measured['corpus_id']!r}/{measured['count']!r}"
        )
    return dict(evidence)


def _parse_draft_boundary(node: Any, *, where: str) -> dict[str, Any]:
    draft = _exact_keys(node, {"accepted", "isolates", "permits", "refuses"}, set(), where=where)
    if draft["accepted"] is not False:
        raise ProvenanceError(
            f"{where}.accepted must be exactly false — a draft attached to an unresolved "
            f"class is text for an owner to accept, not an acceptance"
        )
    return {
        "accepted": False,
        "isolates": _nonempty_specific_list(draft["isolates"], where=f"{where}.isolates"),
        "permits": _nonempty_specific_list(draft["permits"], where=f"{where}.permits"),
        "refuses": _nonempty_specific_list(draft["refuses"], where=f"{where}.refuses"),
    }


def _parse_option(node: Any, *, where: str) -> dict[str, Any]:
    option = _exact_keys(node, {"option", "evidence_required"}, set(), where=where)
    name = _enum(option["option"], ("boundary", "retirement"), where=f"{where}.option")
    required = option["evidence_required"]
    if not isinstance(required, list) or not required:
        raise CompletenessError(
            f"{where}.evidence_required must list what would resolve this option"
        )
    for index, entry in enumerate(required):
        if not isinstance(entry, str) or len(entry.strip()) < 12:
            raise CompletenessError(f"{where}.evidence_required[{index}] must be a statement")
    return {"option": name, "evidence_required": list(required)}


def _parse_outcome(node: Any, inputs: dict[str, Any], usage_class: str, *, where: str) -> dict[str, Any]:
    if not isinstance(node, dict) or "outcome" not in node:
        raise CompletenessError(f"{where} must be an object carrying exactly one 'outcome'")
    outcome = _enum(node["outcome"], OUTCOMES, where=f"{where}.outcome")

    if outcome == "boundary":
        body = _exact_keys(
            node,
            {"outcome", "isolates", "permits", "refuses", "owner", "evidence"},
            set(),
            where=where,
        )
        owner = body["owner"]
        if not isinstance(owner, str) or not owner.strip():
            raise ProvenanceError(f"{where}.owner must name who accepted the boundary")
        return {
            "outcome": outcome,
            "isolates": _nonempty_specific_list(body["isolates"], where=f"{where}.isolates"),
            "permits": _nonempty_specific_list(body["permits"], where=f"{where}.permits"),
            "refuses": _nonempty_specific_list(body["refuses"], where=f"{where}.refuses"),
            "owner": owner,
            "evidence": _parse_evidence(body["evidence"], inputs, usage_class, where=f"{where}.evidence"),
        }

    if outcome == "retirement":
        keys = set(node)
        for field in ("replacement", "user_path"):
            if field not in keys or not isinstance(node.get(field), str) or len(node[field].strip()) < 12:
                raise ReplacementlessRetirement(
                    f"{where} retires {usage_class} without a usable {field}; "
                    f"a retirement names its replacement outcome and how a current user "
                    f"reaches it, and a replacementless retirement is a finding requiring "
                    f"an owner decision"
                )
        body = _exact_keys(
            node,
            {"outcome", "replacement", "user_path", "owner", "evidence"},
            set(),
            where=where,
        )
        for field in ("replacement", "user_path"):
            try:
                _nonempty_specific_list([body[field]], where=f"{where}.{field}")
            except BoundarySpecificityError as exc:
                raise ReplacementlessRetirement(
                    f"{where}.{field} does not name a replacement a user can reach: {exc}"
                ) from exc
        owner = body["owner"]
        if not isinstance(owner, str) or not owner.strip():
            raise ProvenanceError(f"{where}.owner must name who accepted the retirement")
        return {
            "outcome": outcome,
            "replacement": body["replacement"],
            "user_path": body["user_path"],
            "owner": owner,
            "evidence": _parse_evidence(body["evidence"], inputs, usage_class, where=f"{where}.evidence"),
        }

    body = _exact_keys(
        node,
        {"outcome", "owner_decision_required", "blocked_on", "options"},
        {"draft_boundary"},
        where=where,
    )
    if body["owner_decision_required"] is not True:
        raise CompletenessError(
            f"{where}.owner_decision_required must be exactly true — an unresolved class "
            f"is unresolved because someone has to decide it"
        )
    blocked_on = body["blocked_on"]
    if not isinstance(blocked_on, list) or not blocked_on:
        raise CompletenessError(f"{where}.blocked_on must name at least one blocker")
    for index, entry in enumerate(blocked_on):
        _enum(entry, BLOCKERS, where=f"{where}.blocked_on[{index}]")
    options = body["options"]
    if not isinstance(options, list):
        raise CompletenessError(f"{where}.options must be a list")
    parsed_options = [
        _parse_option(entry, where=f"{where}.options[{index}]") for index, entry in enumerate(options)
    ]
    named = {entry["option"] for entry in parsed_options}
    if named != {"boundary", "retirement"}:
        raise CompletenessError(
            f"{where}.options must state both open options (boundary, retirement) with the "
            f"evidence each would need; found {sorted(named)}"
        )
    result = {
        "outcome": outcome,
        "owner_decision_required": True,
        "blocked_on": list(blocked_on),
        "options": parsed_options,
    }
    if "draft_boundary" in body:
        result["draft_boundary"] = _parse_draft_boundary(
            body["draft_boundary"], where=f"{where}.draft_boundary"
        )
    return result


def parse_decision(document: Any, inputs: dict[str, Any], *, where: str = "decision") -> dict[str, Any]:
    """Validate a decision record against the decision inputs it claims to use."""
    sanitize_document(document, where=where)
    record = _exact_keys(document, DECISION_REQUIRED, set(), where=where)
    if record["schema"] != DECISION_SCHEMA:
        raise VocabularyError(f"{where}.schema must be {DECISION_SCHEMA!r}")
    if record["work_item"] != "R0-11":
        raise VocabularyError(f"{where}.work_item must be 'R0-11'")
    _date(record["recorded_on"], where=f"{where}.recorded_on")

    cited = _exact_keys(record["decision_inputs"], {"path", "sha256"}, set(), where=f"{where}.decision_inputs")
    if not isinstance(cited["sha256"], str) or not SHA256.match(cited["sha256"]):
        raise VocabularyError(f"{where}.decision_inputs.sha256 must be a full SHA-256")
    if cited["path"] != inputs["path"]:
        raise ProvenanceError(
            f"{where}.decision_inputs.path is {cited['path']!r}; validated against {inputs['path']!r}"
        )
    if cited["sha256"] != inputs["sha256"]:
        raise ProvenanceError(
            f"{where} was recorded against decision inputs {cited['sha256'][:12]}… but the "
            f"checked-in inputs hash {inputs['sha256'][:12]}… — re-derive the decision"
        )

    disposition = _exact_keys(
        record["standing_plan_disposition"],
        {"source", "text", "binds_this_record"},
        set(),
        where=f"{where}.standing_plan_disposition",
    )
    if not (ROOT / str(disposition["source"]).split("#", 1)[0]).is_file():
        raise ProvenanceError(
            f"{where}.standing_plan_disposition.source cites {disposition['source']!r}, "
            f"which is not a file in this repository"
        )
    if disposition["binds_this_record"] is not False:
        raise ProvenanceError(
            f"{where}.standing_plan_disposition.binds_this_record must be exactly false — "
            f"a plan-level disposition is context; R0-11 asks for a per-class decision"
        )

    classes = record["classes"]
    if not isinstance(classes, dict):
        raise CompletenessError(f"{where}.classes must be an object keyed by usage class")
    unknown = sorted(set(classes) - set(USAGE_CLASSES))
    if unknown:
        raise VocabularyError(f"{where}.classes names unknown class(es): {', '.join(unknown)}")
    missing = sorted(set(USAGE_CLASSES) - set(classes))
    if missing:
        raise CompletenessError(
            f"{where} records no outcome for: {', '.join(missing)} — every usage class "
            f"carries exactly one outcome or stays explicitly unresolved; none defaults"
        )

    parsed = {
        name: _parse_outcome(classes[name], inputs, name, where=f"{where}.classes.{name}")
        for name in sorted(classes)
    }
    return {
        "work_item": record["work_item"],
        "recorded_on": record["recorded_on"],
        "decision_inputs": dict(cited),
        "standing_plan_disposition": dict(disposition),
        "classes": parsed,
    }


def load_decision(path: pathlib.Path, inputs: dict[str, Any]) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise VocabularyError(f"{path} is not valid JSON: {exc}") from exc
    return parse_decision(document, inputs, where=path.name)


# --- vocabulary reference --------------------------------------------------


def format_reference() -> str:
    """Print the vocabularies from the enums themselves.

    The README points here rather than restating them: a second copy of a closed
    set is a copy that drifts, and `AGENTS.md` is explicit that a fixture must
    never restate the constant it is checking.
    """
    lines = [
        f"observation schema   {OBSERVATION_SCHEMA}",
        f"decision inputs      {DECISION_INPUTS_SCHEMA}",
        f"decision schema      {DECISION_SCHEMA}",
        "",
        "usage classes",
    ]
    for name, meta in USAGE_CLASSES.items():
        lines.append(f"  {name:28} {meta['summary']}")
        lines.append(f"  {'':28} source: {meta['source']}")
    lines += [
        "",
        "corpus kinds           " + ", ".join(CORPUS_KINDS),
        "counting methods       " + ", ".join(COUNTING_CAPTURE_METHODS),
        "non-counting methods   " + ", ".join((SYNTHETIC_CAPTURE_METHOD, NULL_CAPTURE_METHOD)),
        "citation kinds         " + ", ".join(CITATION_KINDS),
        "command shapes         " + ", ".join(COMMAND_SHAPES),
        "placeholder tokens     " + ", ".join(PLACEHOLDER_TOKENS),
        "outcomes               " + ", ".join(OUTCOMES),
        "blockers               " + ", ".join(BLOCKERS),
        "sanitizer rules        " + ", ".join(rule for rule, _, _ in SANITIZER_RULES),
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--format", action="store_true", help="print the closed vocabulary")
    parser.add_argument("--validate", type=pathlib.Path, metavar="CORPUS",
                        help="validate one observation corpus and print its summary")
    args = parser.parse_args(argv)
    if not args.format and args.validate is None:
        parser.error("choose --format or --validate")
    if args.format:
        print(format_reference())
    if args.validate is not None:
        try:
            corpus = load_corpus(args.validate)
        except FixtureError as exc:
            print(f"REFUSE: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        counted = sum(1 for entry in corpus["observations"] if entry["count"] is not None)
        print(
            f"ok — {corpus['corpus_id']} ({corpus['kind']}), "
            f"{len(corpus['observations'])} class(es), {counted} counted, "
            f"{len(corpus['observations']) - counted} null-with-reason"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
