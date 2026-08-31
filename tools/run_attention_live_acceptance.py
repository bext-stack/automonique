#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Record the cross-client live acceptance flow for epic #163 on deployed builds.

`run_attention_parity_acceptance.py` and `run_retained_session_acceptance.py`
prove that every surface agrees about a fixed corpus. Neither talks to a
deployment, and both say so by leaving `live_verification` at
`required_not_run`. This harness closes as much of that gap as can be closed
honestly, and refuses to close the rest.

Three things are true about this flow, and the report says all three.

1. Part of it is automatable. A deployed web entry can be asked, over the
   network, whether it answers, whether the operator gate stands in front of the
   Platform surface, whether the mobile grant surface fails closed behind its own
   distinct realm, what protocol and schema it advertises, and — with an operator
   credential — what its attention projection and retained-session read actually
   return. Those are recorded as observed facts next to the endpoint and the
   contract each one was checked against.

2. Part of it is not. "The desktop app shows the same attention state as the
   phone" is a claim about two GUIs rendering, and no HTTP probe establishes it.
   Those steps are enumerated as an operator checklist and stay
   `awaiting_operator` until a sign-off file names every one of them. One of
   them, LIVE-GUI-2, does have a machine half: `--cockpit-render-check` drives a
   browser into the deployed cockpit and asserts what it renders against the
   deployment's own projection. That is a check in `checks`, not a signature; it
   narrows what the operator still has to look at, and does not sign for them.

3. The deployed build may not be attributable to a source revision. It is asked
   twice — the binary is asked what it was built from, and every release
   manifest under the release root is searched for its digest — and either
   answer resolves it. When neither does, the honest record is the running
   digest plus an explicit `unresolved` attribution, not a revision the harness
   cannot prove. When both answer and disagree, that is recorded as
   `contradicted` and fails, because a well-sourced wrong answer is worse than
   no answer.

Every path this harness probes is derived from the route table in
`automonique-web-entry` (`route()` in `src/lib.rs`), and every schema it asserts
is the literal that the corresponding handler serializes. A probe path is a
claim about the deployed build; a guessed one would make the report fiction.

`passed` is true only when every automated check passed *and* an operator signed
off every checklist step. A run against an unreachable deployment reports
`blocked` with the reason and exits non-zero. It never reports coverage it does
not have.

The report is the only thing on stdout; diagnostics go to stderr, so
`run_attention_live_acceptance.py ... > report.json` produces a file that parses.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


SCHEMA = "automonique.attention-live-acceptance-report/v1"
SIGNOFF_SCHEMA = "automonique.attention-live-acceptance-signoff/v1"
# Written by `tools/run_attention_live_parity.py`, the only harness that reads
# the deployment's Platform v2 attention lane.
PARITY_SCHEMA = "automonique.attention-live-parity-report/v1"

DEFAULT_HOSTED_ORIGIN = "https://monique.1clic.pro"
DEFAULT_HOSTED_HOST = "monique.1clic.pro"

# Cloudflare fronts the hosted origin and answers 403 to the standard library's
# default `Python-urllib/*` User-Agent, which reads exactly like the deployment
# refusing the probe. The harness therefore names itself.
USER_AGENT = "automonique-live-acceptance/1"

# `route()` only dispatches for the canonical host or `localhost`, and `handle()`
# turns a canonical-host request without `X-Forwarded-Proto: https` into
# `Route::HttpsRedirect`. A loopback probe has to speak both or it never reaches
# the gate: without the Host it is a 400/unknown-host, without the proto a 308.
LOOPBACK_FORWARDED_PROTO = "https"

# The one route with a `localhost` carve-out: `handle()` computes
# `local_health` and exempts it from authorization. It is the only unauthenticated
# proof available that the process behind the public origin is the local one.
HEALTH_PATH = "/healthz"
HEALTH_BODY = "ok"
LOCALHOST_HOST = "localhost"

CANONICAL_HOST_KEY = "canonical_host="

# Only these keys are ever lifted out of a deployment response, and a key is
# gated at every depth. Each one is a field of a type the web entry serializes:
# `PlatformProjectionView`, `PlatformSessionsView`, `PlatformCapabilitiesView`,
# `PlatformInventoryView`, `PlatformCursorView`, `PlatformResourceView`,
# `PlatformSessionView`, `PlatformCoordinateView` in `src/lib.rs`, and
# `MobileDiscovery` / `MobileAuthorization` in `src/mobile_auth.rs`, plus the
# `error` envelope that `json_error` and `mobile_error` emit.
#
# Deliberately absent, and they must stay absent: `summary` and `explanation`
# are free text the daemon supplies; `id` carries live work coordinates;
# `credential_id`, `credential_revision`, `authorization_revision`, `limits`,
# and `pairing_token` are credential-scoped. `explanation` is admitted only
# through `refusal_category()` below, and only when it is a bare category token.
OBSERVABLE_KEYS = frozenset(
    {
        "error",
        "schema",
        "health",
        "capabilities",
        "inventory",
        "cursor",
        "sessions_cursor",
        "resources",
        "sessions",
        "protocol",
        "methods",
        "transports",
        "state",
        "authority",
        "topic",
        "sequence",
        "resource",
        "freshness",
        "revision",
        "session",
        "run",
        "attachable",
        "controllable",
        "kind",
        "origin",
        "server_identity",
        "supported_versions",
        "actions",
        "actor",
        "session_scope",
        # `BuildIdentity` as `/api/build` serializes it. A revision is not a
        # secret and is the whole point of that surface; withholding it here
        # would leave the report unable to name what answered.
        "source_revision",
        "provenance",
        "build_target",
    }
)
SECRET_MARKERS = ("token", "secret", "password", "credential", "authorization", "cookie")

# `automonique_build_identity::BUILD_IDENTITY_SCHEMA`. The same document is
# served by `/api/build` over the network and printed by `--build-identity
# --json` on the host, so one token covers both.
BUILD_IDENTITY_SCHEMA = "automonique.build-identity/v1"
# `Provenance::Declared` and `Provenance::Committed`. A `modified` build names
# the commit its uncommitted changes sat on, which is worth recording and is not
# a revision the build can be signed off against.
ATTRIBUTABLE_PROVENANCE = frozenset({"declared", "committed"})
BUILD_IDENTITY_TIMEOUT = 10.0
CATEGORY_TOKEN = re.compile(r"\A[a-z0-9_]{1,64}\Z")
SCALAR_LIMIT = 128
LIST_LIMIT = 16
BODY_LIMIT = 262144

HOME_PLACEHOLDER = "$HOME"

# `tests/browser/live-cockpit-attention.spec.js` in `automonique-web-entry`
# signs a real browser into the deployed cockpit and asserts, against the
# `/api/platform/cockpit` document that deployment answered with during the very
# page load it is looking at, that the attention item renders with that source
# and that generation, and that no review state the document did not assert
# appears. It is the only check here that observes a GUI rather than a response
# body, and it is the automated half of LIVE-GUI-2.
#
# Its verdict is read from the evidence document it writes, never from the
# runner's exit status alone: a skipped browser test exits zero, and an
# unobserved render must not read as an observed one.
COCKPIT_RENDER_EVIDENCE_SCHEMA = "automonique.cockpit-render-evidence/v1"
COCKPIT_RENDER_EVIDENCE_FILE = "live-cockpit-attention.json"
COCKPIT_RENDER_PROJECT = "live-cockpit"
COCKPIT_RENDER_TIMEOUT = 600.0
COCKPIT_RENDER_LOG = "runner.log"
# Every value lifted out of the browser evidence is held to the shape of the
# field it came from: a revision is a canonical decimal or it is not recorded, a
# state is a bare category token, a rendered read model's key is a dotted
# semantic key. That is stricter than the response allow-list above, and it is
# what keeps a rendered free-text summary or a work coordinate out of this
# report even though the evidence file beside the screenshot carries them for
# cross-client correlation. `CATEGORY_TOKEN` above is the bare-token shape.
SEMANTIC_TOKEN = re.compile(r"\A[a-z0-9_]{1,64}(\.[a-z0-9_]{1,64}){1,3}\Z")
DECIMAL_TOKEN = re.compile(r"\A(0|[1-9][0-9]*)\Z")
COCKPIT_RENDER_ITEM_SHAPES = {
    "source_kind": CATEGORY_TOKEN,
    "source_revision": DECIMAL_TOKEN,
    "item_revision": DECIMAL_TOKEN,
    "state": CATEGORY_TOKEN,
    "reason": CATEGORY_TOKEN,
    "unread": DECIMAL_TOKEN,
}
COCKPIT_RENDER_REVIEW_SHAPES = {
    "source_state": CATEGORY_TOKEN,
    "source_revision": DECIMAL_TOKEN,
    "derived": CATEGORY_TOKEN,
}


@dataclass(frozen=True)
class Gate:
    """A surface that must refuse an unauthenticated read, and name its realm."""

    name: str
    path: str
    realm: str
    intent: str
    error_category: str | None = None


@dataclass(frozen=True)
class Open:
    """A surface the web entry serves without authorization, on purpose."""

    name: str
    path: str
    schema: str
    intent: str


@dataclass(frozen=True)
class Authorized:
    """A read behind the operator gate, performed only with a credential."""

    name: str
    path: str
    schema: str
    intent: str


@dataclass(frozen=True)
class ManualStep:
    """A step no probe can establish, to be signed off by a named operator.

    `residue` names what is left of the step once everything a machine can
    check against the deployment has been subtracted. It is documentation, not
    a discount: the step is satisfied only by a sign-off naming an operator,
    whatever `residue` says. `run_attention_live_parity.py` is what does the
    subtracting, and it can never do the signing.
    """

    identifier: str
    surface: str
    instruction: str
    evidence_required: str
    residue: str


@dataclass
class Origin:
    """A deployment target, the dialect it expects, and how it was found."""

    key: str
    url: str
    host_header: str | None = None
    forwarded_proto: str | None = None
    credential_env: str | None = None
    discovered_from: str = "operator-supplied"
    notes: list[str] = field(default_factory=list)


# `/api/platform` GET is `Route::ApiPlatform`; `handle()` places it behind the
# operator Basic gate, and `render()` answers 401 with the operations realm.
# `/api/mobile/authorization` GET is `Route::MobileAuthorization`, which
# `needs_auth` deliberately exempts from the Basic gate because it is bearer
# authority: without a mobile credential it is a 401 under its own realm.
GATES = (
    Gate(
        name="platform_operator_gate",
        path="/api/platform",
        realm='Basic realm="Monique Operations"',
        intent=(
            "the deployed Platform surface answers and refuses an unauthenticated "
            "read under the operator realm"
        ),
    ),
    Gate(
        name="mobile_grant_gate",
        path="/api/mobile/authorization",
        realm='Bearer realm="Automonique Mobile"',
        error_category="mobile_credential_invalid",
        intent=(
            "the mobile grant surface fails closed under its own bearer realm, "
            "distinct from the operator gate, rather than inheriting it"
        ),
    ),
)

# `Route::MobileDiscovery` is exempt from `needs_auth` by design: a phone has to
# read it before it holds any credential. `mobile_discovery()` serializes
# `MobileDiscovery`, whose `server_identity` is the only deployment identity
# observable from outside the host.
OPENS = (
    Open(
        name="mobile_discovery",
        path="/.well-known/automonique-mobile",
        schema="automonique.mobile-auth/v1",
        intent=(
            "the deployed build publishes its mobile discovery document, naming "
            "the protocol, supported versions, origin, and server identity a "
            "client would pair against"
        ),
    ),
)

# `/api/platform` GET behind the gate is `WebIntegration::platform()`, the same
# projection the hosted cockpit renders: capabilities, inventory, resources, and
# sessions. `/api/mobile/pairing-sessions` GET is `Route::MobilePairingSessions`,
# which `handle()` classifies as `operator_mobile` and which calls
# `WebIntegration::platform_sessions()` — the retained-session read.
AUTHORIZED = (
    Authorized(
        name="attention_projection",
        path="/api/platform",
        schema="automonique.dashboard.platform/v2",
        intent=(
            "an authorized read returns the attention projection the clients "
            "consume, under the schema the deployed build advertises"
        ),
    ),
    Authorized(
        name="build_identity",
        path="/api/build",
        schema=BUILD_IDENTITY_SCHEMA,
        intent=(
            "the deployed build names, over its own authenticated surface, the "
            "source revision it was compiled from, so this record can say which "
            "revision answered rather than only that something answered"
        ),
    ),
    Authorized(
        name="retained_session_read",
        path="/api/mobile/pairing-sessions",
        schema="automonique.dashboard.pairing-sessions/v2",
        intent=(
            "an authorized retained-session read returns an authority-qualified "
            "session cursor rather than a partial page"
        ),
    ),
)

MANUAL_STEPS = (
    ManualStep(
        identifier="LIVE-GUI-1",
        surface="ShellDeck desktop",
        instruction=(
            "Open ShellDeck against the deployed hosted entry, open the workspace "
            "carrying a live attention item, and confirm the attention badge "
            "re-resolves to a pane ShellDeck is currently authorized for."
        ),
        evidence_required=(
            "screenshot of the resolved pane, plus the workspace and session "
            "identity it resolved to"
        ),
        residue=(
            "Re-resolution against the desktop's live pane and session "
            "catalogues, which exist only inside a running GUI process. "
            "run_attention_live_parity.py checks that ShellDeck's real board "
            "derives the same source inventory, generation and item set as the "
            "other two clients from the deployment's own graph; it never "
            "starts a desktop and never sees a pane."
        ),
    ),
    ManualStep(
        identifier="LIVE-GUI-2",
        surface="monique.1clic.pro",
        instruction=(
            "Sign in to the hosted cockpit and confirm the same attention item "
            "renders with the same source and generation ShellDeck showed, with "
            "no review state the source did not assert."
        ),
        evidence_required="screenshot showing the source and the generation",
        residue=(
            "That the item on the cockpit is the item ShellDeck showed the same "
            "person, on their screen, in one sitting. Two machine checks now "
            "meet here: `--cockpit-render-check` observes the deployed page "
            "rendering the source and generation its own authorized projection "
            "carries, and run_attention_live_parity.py checks that projection "
            "names the same source and generation as ShellDeck and Mobile. "
            "Neither establishes that one human saw the same thing twice, and "
            "that is what is left."
        ),
    ),
    ManualStep(
        identifier="LIVE-GUI-3",
        surface="Automonique Mobile",
        instruction=(
            "Pair the phone against the mobile endpoint this report records, open "
            "the generation-bound deep link for the same attention item, and "
            "confirm it lands on the same session and refuses a superseded "
            "generation."
        ),
        evidence_required="screenshot of the deep-link landing and of the refusal",
        residue=(
            "All of it. Pairing, deep-link admission and the refusal of a "
            "superseded generation run through the phone's own catalogues and "
            "its paired credential. run_attention_live_parity.py checks "
            "Mobile's board and projection agree with the other two clients "
            "about the live read, which is not this step."
        ),
    ),
    ManualStep(
        identifier="LIVE-GUI-4",
        surface="cross-client",
        instruction=(
            "Retire the attention item from one client and confirm the other two "
            "converge without a manual refresh, and that a retention gap surfaces "
            "as an explicit resynchronization rather than a partial page."
        ),
        evidence_required="screenshots of all three clients after convergence",
        residue=(
            "Retiring an item from a client, and 'without a manual refresh'. "
            "run_attention_live_parity.py can replay successive live reads "
            "through all three reducers and assert convergence and the "
            "retention-gap rule when the deployment moves during a run, but it "
            "only reads: it never causes the retirement, and it never observes "
            "three running clients refreshing themselves."
        ),
    ),
)
MANUAL_IDS = frozenset(step.identifier for step in MANUAL_STEPS)


def redacted(value: str) -> str:
    """Replace the operator's home directory, which is not repository content."""
    try:
        home = str(Path.home().resolve())
    except (OSError, RuntimeError):
        return value
    return value.replace(home, HOME_PLACEHOLDER) if home else value


def redacted_path(path: Path) -> str:
    return redacted(str(path))


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    return result.stdout.strip()


def repository(root: Path | None) -> dict[str, object]:
    """Record a checkout's revision, or say why it could not be recorded.

    A missing client checkout is a fact about this host, not about the
    deployment. It is recorded as `unavailable` rather than aborting the run:
    the deployment probes are the point, and they do not need the checkout.
    """
    if root is None:
        return {"state": "unavailable", "reason": "no root supplied"}
    if not root.is_dir():
        return {
            "state": "unavailable",
            "path": redacted_path(root),
            "reason": "path is not a directory on this host",
        }
    try:
        return {
            "state": "recorded",
            "path": redacted_path(root),
            "revision": git(root, "rev-parse", "HEAD"),
            "dirty": bool(git(root, "status", "--porcelain")),
        }
    except (OSError, subprocess.CalledProcessError) as error:
        return {
            "state": "unavailable",
            "path": redacted_path(root),
            "reason": f"git could not describe this path: {type(error).__name__}",
        }


def digest(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def refusal_category(value: Any) -> str | None:
    """Admit a refusal explanation only when it is a bare category token.

    `PlatformInventoryView.explanation` carries whatever the daemon refused
    with. `snapshot_too_large` is the category that matters here, and a token
    like it is safe to record; anything else could be free text about live work,
    so it is withheld rather than reproduced.
    """
    if not isinstance(value, str):
        return None
    return value if CATEGORY_TOKEN.fullmatch(value) else "<non_category_text_withheld>"


def scrub(value: Any) -> Any:
    """Keep only allow-listed, small, non-secret values, at every depth."""
    if isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, str):
        return value if len(value) <= SCALAR_LIMIT else None
    if isinstance(value, list):
        # Redaction strips the identifiers that made list entries distinct, so a
        # list of 45 sessions projects to a handful of shapes repeated. Collapse
        # identical projections and record the true length separately: the shape
        # space is the informative part, and the count is not lost.
        distinct: list[Any] = []
        seen: set[str] = set()
        for item in value:
            cleaned = scrub(item)
            if cleaned is None:
                continue
            marker = json.dumps(cleaned, sort_keys=True, default=str)
            if marker in seen:
                continue
            seen.add(marker)
            distinct.append(cleaned)
            if len(distinct) >= LIST_LIMIT:
                break
        return distinct
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for name, item in value.items():
            lowered = name.lower()
            if any(marker in lowered for marker in SECRET_MARKERS):
                continue
            if name == "explanation":
                category = refusal_category(item)
                if category is not None:
                    result[name] = category
                continue
            if name not in OBSERVABLE_KEYS:
                continue
            cleaned = scrub(item)
            if cleaned is not None and cleaned != {} and cleaned != []:
                result[name] = cleaned
        return result
    return None


def counted(values: dict[str, Any]) -> dict[str, int]:
    """Record the length of every list value."""
    return {name: len(item) for name, item in values.items() if isinstance(item, list)}


def observable(body: bytes) -> tuple[dict[str, Any], dict[str, int]]:
    """Lift only the recognised, non-secret values out of a response body."""
    if not body.strip():
        return {}, {}
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {"body": "non_json_or_undecodable"}, {}
    if not isinstance(parsed, dict):
        return {"body": "non_object"}, {}
    observed = scrub(parsed) or {}
    counts = counted(parsed)
    kept = counted(observed)
    for name, total in list(counts.items()):
        held = kept.get(name, 0)
        if held != total:
            counts[f"{name}.distinct_projections"] = held
    return observed, counts


def credential_header(raw: str | None) -> dict[str, str]:
    """Build the Basic header. The credential never enters the report."""
    if not raw:
        return {}
    encoded = base64.b64encode(raw.encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {encoded}"}


def request(
    origin: Origin,
    path: str,
    credential: str | None,
    timeout: float,
    host_override: str | None = None,
    forwarded_proto_override: str | None = None,
    json_body: bool = True,
) -> dict[str, Any]:
    """Perform one GET and classify the outcome without ever raising."""
    url = origin.url.rstrip("/") + path
    headers: dict[str, str] = {
        "Accept": "application/json" if json_body else "*/*",
        "User-Agent": USER_AGENT,
    }
    host = host_override if host_override is not None else origin.host_header
    if host:
        headers["Host"] = host
    proto = (
        forwarded_proto_override
        if forwarded_proto_override is not None
        else origin.forwarded_proto
    )
    if proto:
        headers["X-Forwarded-Proto"] = proto
    headers.update(credential_header(credential))
    probe = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(probe, timeout=timeout) as response:
            body = response.read(BODY_LIMIT)
            outcome: dict[str, Any] = {
                "url": redacted(url),
                "http_status": response.status,
            }
            if json_body:
                observed, counts = observable(body)
                outcome["observed"] = observed
                if counts:
                    outcome["observed_counts"] = counts
            else:
                outcome["body"] = body.decode("utf-8", "replace").strip()[:SCALAR_LIMIT]
            return outcome
    except urllib.error.HTTPError as error:
        outcome = {
            "url": redacted(url),
            "http_status": error.code,
            "www_authenticate": (error.headers.get("WWW-Authenticate") or "")[
                :SCALAR_LIMIT
            ],
        }
        observed, counts = observable(error.read(BODY_LIMIT))
        outcome["observed"] = observed
        if counts:
            outcome["observed_counts"] = counts
        return outcome
    except (TimeoutError, socket.timeout):
        return {"url": redacted(url), "unreachable": "Timeout"}
    except urllib.error.URLError as error:
        return {"url": redacted(url), "unreachable": type(error.reason).__name__}
    except (ssl.SSLError, OSError, ValueError) as error:
        return {"url": redacted(url), "unreachable": type(error).__name__}


def blocked(name: str, intent: str, reason: str, **extra: Any) -> dict[str, Any]:
    return {"name": name, "intent": intent, "state": "blocked", "reason": reason, **extra}


def opened(origin: Origin, name: str, intent: str, outcome: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "name": f"{origin.key}_{name}",
        "intent": intent,
        "origin": origin.key,
        "endpoint": outcome.get("url"),
    }
    result.update({key: value for key, value in outcome.items() if key != "url"})
    return result


def unreachable(result: dict[str, Any], outcome: dict[str, Any]) -> bool:
    if "unreachable" not in outcome:
        return False
    result["state"] = "blocked"
    result["reason"] = (
        f"deployment unreachable from this host: {outcome['unreachable']}"
    )
    return True


def check_gate(origin: Origin, gate: Gate, timeout: float) -> dict[str, Any]:
    """An unauthenticated 401 under the expected realm is the desired result.

    A 200 here would mean the surface is served without authorization, which is
    a finding and not a pass. The credential is deliberately withheld: the
    observation is the gate itself, not the read behind it.
    """
    outcome = request(origin, gate.path, None, timeout)
    result = opened(origin, gate.name, gate.intent, outcome)
    result["expected_realm"] = gate.realm
    if unreachable(result, outcome):
        return result
    status = outcome.get("http_status")
    realm = outcome.get("www_authenticate", "")
    if status == 200:
        result["state"] = "failed"
        result["reason"] = "the surface was served without authorization"
        return result
    if status != 401:
        result["state"] = "failed"
        result["reason"] = f"unexpected unauthenticated status {status}"
        return result
    if not realm.startswith(gate.realm):
        result["state"] = "failed"
        result["reason"] = (
            "the gate answered 401 but did not name the expected realm, so the "
            "deployed build does not gate this surface the way the source does"
        )
        return result
    observed_error = outcome.get("observed", {}).get("error")
    if gate.error_category is not None and observed_error != gate.error_category:
        result["state"] = "failed"
        result["reason"] = (
            f"expected refusal category {gate.error_category!r}, observed "
            f"{observed_error!r}"
        )
        return result
    result["state"] = "passed"
    return result


def check_open(origin: Origin, probe: Open, timeout: float) -> dict[str, Any]:
    outcome = request(origin, probe.path, None, timeout)
    result = opened(origin, probe.name, probe.intent, outcome)
    result["expected_schema"] = probe.schema
    if unreachable(result, outcome):
        return result
    status = outcome.get("http_status")
    if status != 200:
        result["state"] = "failed"
        result["reason"] = (
            "the deployed build did not serve this deliberately unauthenticated "
            f"surface; status {status}"
        )
        return result
    observed_schema = outcome.get("observed", {}).get("schema")
    if observed_schema != probe.schema:
        result["state"] = "failed"
        result["reason"] = (
            f"expected schema {probe.schema!r}, the deployed build advertises "
            f"{observed_schema!r}"
        )
        return result
    result["state"] = "passed"
    return result


def check_liveness(origin: Origin, timeout: float) -> dict[str, Any]:
    """Prove the process behind the public origin is the one on this host.

    `/healthz` is authorized only under `Host: localhost`, so this check exists
    exactly when the operator supplied a loopback address.
    """
    outcome = request(
        origin,
        HEALTH_PATH,
        None,
        timeout,
        host_override=LOCALHOST_HOST,
        forwarded_proto_override="",
        json_body=False,
    )
    result = opened(
        origin,
        "loopback_liveness",
        (
            "the web entry process on this host answers its localhost-exempt "
            "health route, so the public origin is fronting a local process"
        ),
        outcome,
    )
    if unreachable(result, outcome):
        return result
    status = outcome.get("http_status")
    if status == 200 and outcome.get("body") == HEALTH_BODY:
        result["state"] = "passed"
        return result
    result["state"] = "failed"
    result["reason"] = f"expected 200 {HEALTH_BODY!r} on the health route, got {status}"
    return result


def check_authorized(
    origin: Origin,
    probe: Authorized,
    credential: str | None,
    credential_env: str | None,
    timeout: float,
) -> dict[str, Any]:
    name = f"{origin.key}_{probe.name}"
    if credential is None:
        return blocked(
            name,
            probe.intent,
            (
                "no credential supplied"
                + (f" in ${credential_env}" if credential_env else "")
                + "; the read behind the gate was not performed"
            ),
            origin=origin.key,
            endpoint=redacted(origin.url.rstrip("/") + probe.path),
        )
    outcome = request(origin, probe.path, credential, timeout)
    result = opened(origin, probe.name, probe.intent, outcome)
    result["expected_schema"] = probe.schema
    if unreachable(result, outcome):
        return result
    status = outcome.get("http_status")
    if status == 401:
        result["state"] = "failed"
        result["reason"] = "the supplied credential was rejected by the deployment"
        return result
    if status == 404:
        result["state"] = "failed"
        result["reason"] = (
            "the deployed build does not route this path, so it predates the "
            "surface this acceptance is about"
        )
        return result
    if status != 200:
        result["state"] = "failed"
        result["reason"] = f"unexpected status {status}"
        return result
    observed_schema = outcome.get("observed", {}).get("schema")
    if observed_schema != probe.schema:
        result["state"] = "failed"
        result["reason"] = (
            f"expected schema {probe.schema!r}, the deployed build served "
            f"{observed_schema!r}"
        )
        return result
    result["state"] = "passed"
    return result


def check_resource_inventory(projection: dict[str, Any]) -> dict[str, Any]:
    """Decide whether the deployment serves its Platform v1 resource inventory.

    Derived from the projection already read, not a second request. A refused
    inventory is the deployment behaving as `WebIntegration::platform()` says it
    should when a snapshot of everything no longer fits — the surface stays
    truthful instead of hanging.

    This check used to be called `hosted_attention_corpus_available` and used to
    say a populated resource inventory meant the cross-client GUI steps had
    something to compare. It does not. `/api/platform` is the Platform *v1*
    projection: nodes, clients, runs and sessions. Attention lives on the
    Platform v2 lane, which this projection does not touch, so a deployment
    serving 48 v1 resources and refusing every attention read passed this check
    while serving no attention at all — which is exactly what
    `run_attention_live_parity.py` found on 2026-08-30. The corpus question is
    now asked where it can be answered; see `check_attention_corpus` below.
    """
    intent = (
        "the deployed build serves its Platform v1 resource inventory, which "
        "the cockpit enriches its projection from. This says nothing about "
        "attention: attention is a Platform v2 read."
    )
    name = "hosted_v1_resource_inventory_available"
    if projection.get("state") != "passed":
        return blocked(
            name,
            intent,
            "the platform projection was not read, so its inventory is unknown",
        )
    observed = projection.get("observed", {})
    inventory = observed.get("inventory", {})
    inventory_state = inventory.get("state")
    resources = projection.get("observed_counts", {}).get("resources", 0)
    result: dict[str, Any] = {
        "name": name,
        "intent": intent,
        "endpoint": projection.get("endpoint"),
        "derived_from": projection.get("name"),
        "health": observed.get("health"),
        "inventory_state": inventory_state,
        "resource_count": resources,
        "session_count": projection.get("observed_counts", {}).get("sessions", 0),
    }
    explanation = inventory.get("explanation")
    if explanation is not None:
        result["inventory_refusal"] = explanation
    if inventory_state == "available" and resources > 0:
        result["state"] = "passed"
        return result
    if inventory_state == "available":
        result["state"] = "blocked"
        result["reason"] = (
            "the inventory is available but empty, so the cockpit has no v1 "
            "resource to enrich its projection from"
        )
        return result
    result["state"] = "blocked"
    result["reason"] = (
        "the deployed build refuses its resource inventory"
        + (f" ({explanation})" if explanation else "")
        + " and serves no resources"
    )
    return result


ATTENTION_CORPUS_INTENT = (
    "the deployed build actually serves an attention corpus, so the "
    "cross-client GUI steps have a live attention item to agree about"
)


def check_attention_corpus(parity_report: Path | None) -> dict[str, Any]:
    """Ask whether the deployment serves attention, where that can be answered.

    Nothing this harness probes over HTTP answers it. `/api/platform` is a
    Platform v1 read and the attention lane is Platform v2, whose canonical
    envelopes cannot be built here without a second implementation of the codec.
    `run_attention_live_parity.py` builds them with the production client and
    records the answer, so this check reads that record rather than guessing
    from an adjacent surface — which is how the previous version of this check
    came to pass against a deployment serving no attention at all.

    No parity report means the question was not asked. That is `blocked`, and it
    is the honest state: an operator cannot run LIVE-GUI-1..4 against attention
    nobody has established exists.
    """
    name = "hosted_attention_corpus_available"
    if parity_report is None:
        return blocked(
            name,
            ATTENTION_CORPUS_INTENT,
            "no --attention-parity-report supplied, so whether the deployment "
            "serves any attention at all was never established",
        )
    try:
        declared = json.loads(parity_report.read_bytes().decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as error:
        return blocked(
            name,
            ATTENTION_CORPUS_INTENT,
            f"the parity report could not be read: {type(error).__name__}",
            source=redacted_path(parity_report),
        )
    if not isinstance(declared, dict) or declared.get("schema") != PARITY_SCHEMA:
        return blocked(
            name,
            ATTENTION_CORPUS_INTENT,
            f"the named file does not declare {PARITY_SCHEMA!r}",
            source=redacted_path(parity_report),
        )
    checks = declared.get("checks")
    checks = checks if isinstance(checks, list) else []
    lane = next(
        (
            entry
            for entry in checks
            if isinstance(entry, dict) and entry.get("name") == "live_attention_lane"
        ),
        None,
    )
    result: dict[str, Any] = {
        "name": name,
        "intent": ATTENTION_CORPUS_INTENT,
        "source": redacted_path(parity_report),
        "derived_from": "live_attention_lane",
    }
    if lane is None:
        result["state"] = "blocked"
        result["reason"] = "the parity report records no attention lane observation"
        return result
    observed = lane.get("observed") if isinstance(lane.get("observed"), dict) else {}
    result["observed"] = {
        "state": observed.get("state"),
        "category": refusal_category(observed.get("category")),
    }
    if lane.get("state") == "passed":
        result["state"] = "passed"
        return result
    result["state"] = "blocked"
    result["reason"] = (
        "the deployment does not serve its Platform v2 attention lane, so no "
        "live attention item exists for the cross-client steps to agree about"
    )
    return result


def bounded_reason(value: str) -> str:
    """Bound a reason the browser check wrote, and say so when it was cut."""
    return value if len(value) <= SCALAR_LIMIT else value[: SCALAR_LIMIT - 1] + "\u2026"


def evidence_tokens(values: Any, shapes: dict[str, Any]) -> dict[str, str]:
    """Admit each evidence value only in the shape its own field must have."""
    if not isinstance(values, dict):
        return {}
    admitted = {}
    for key, shape in shapes.items():
        value = values.get(key)
        if isinstance(value, str) and shape.fullmatch(value):
            admitted[key] = value
    return admitted


def check_cockpit_render(
    origin: Origin,
    crate: Path | None,
    evidence_dir: Path | None,
    credential_env: str | None,
    timeout: float,
) -> dict[str, Any]:
    """Drive the browser check against the deployed cockpit and fold in its verdict.

    This is the one place in this harness where a claim about a rendered GUI is
    established rather than enumerated for an operator. It is opt-in, because it
    needs a browser toolchain this host may not have, and because a run that
    could not start one must not quietly become the reason a report says
    `blocked` for every other invocation.
    """
    intent = (
        "the deployed cockpit renders the attention item its own authorized "
        "projection carries, with that source and that generation, and asserts "
        "no review state that projection did not (epic #163 LIVE-GUI-2)"
    )
    name = f"{origin.key}_cockpit_attention_render"
    endpoint = redacted(origin.url.rstrip("/") + "/#sessions")
    if crate is None or not (crate / "playwright.config.js").is_file():
        return blocked(
            name,
            intent,
            "no automonique-web-entry crate with a browser test configuration was "
            "found on this host, so the cockpit render was not observed",
            origin=origin.key,
            endpoint=endpoint,
        )
    runner = shutil.which("bunx") or shutil.which("npx")
    if runner is None:
        return blocked(
            name,
            intent,
            "neither bunx nor npx is on PATH, so the browser check could not be "
            "started and the cockpit render was not observed",
            origin=origin.key,
            endpoint=endpoint,
        )
    # Without the pinned runner installed beside the check, `bunx` would fetch
    # whatever version it can reach and drive a browser this crate never
    # measured against. That is a different check, so it is refused rather than
    # run: `bun install && bunx playwright install chromium` in the crate first.
    if not (crate / "node_modules" / "@playwright" / "test").is_dir():
        return blocked(
            name,
            intent,
            "the pinned browser test toolchain is not installed in the crate "
            "(bun install && bunx playwright install chromium), so the cockpit "
            "render was not observed",
            origin=origin.key,
            endpoint=endpoint,
        )
    evidence_dir = evidence_dir or crate / "test-results" / "live-cockpit-evidence"
    evidence_path = evidence_dir / COCKPIT_RENDER_EVIDENCE_FILE
    try:
        evidence_dir.mkdir(parents=True, exist_ok=True)
        evidence_path.unlink(missing_ok=True)
    except OSError as error:
        return blocked(
            name,
            intent,
            f"the evidence directory is not writable: {type(error).__name__}",
            origin=origin.key,
            endpoint=endpoint,
        )
    environment = dict(os.environ)
    environment["AUTOMONIQUE_LIVE_COCKPIT_ORIGIN"] = origin.url
    environment["AUTOMONIQUE_LIVE_COCKPIT_EVIDENCE_DIR"] = str(evidence_dir)
    environment.pop("AUTOMONIQUE_LIVE_COCKPIT_PROOF_DOCUMENT", None)
    environment.pop("AUTOMONIQUE_LIVE_COCKPIT_PROOF_MUTATION", None)
    if credential_env:
        environment["AUTOMONIQUE_LIVE_COCKPIT_CREDENTIAL_ENV"] = credential_env
    try:
        completed = subprocess.run(
            [
                runner,
                "playwright",
                "test",
                f"--project={COCKPIT_RENDER_PROJECT}",
                "--reporter=line",
            ],
            cwd=crate,
            env=environment,
            check=False,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return blocked(
            name,
            intent,
            f"the browser check did not finish within {timeout:.0f}s",
            origin=origin.key,
            endpoint=endpoint,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return blocked(
            name,
            intent,
            f"the browser check could not be run: {type(error).__name__}",
            origin=origin.key,
            endpoint=endpoint,
        )

    # The runner's own output is diagnostic free text, so it is written beside
    # the evidence rather than into this report.
    log = evidence_dir / COCKPIT_RENDER_LOG
    try:
        log.write_bytes(completed.stdout + completed.stderr)
        log_recorded: str | None = redacted_path(log)
    except OSError:
        log_recorded = None

    result: dict[str, Any] = {
        "name": name,
        "intent": intent,
        "origin": origin.key,
        "endpoint": endpoint,
        "evidence": redacted_path(evidence_path),
        "runner_exit_code": completed.returncode,
    }
    if log_recorded is not None:
        result["runner_log"] = log_recorded
    try:
        raw = evidence_path.read_bytes()
    except OSError:
        result["state"] = "blocked"
        result["reason"] = (
            "the browser check wrote no evidence document, so nothing about the "
            "deployed cockpit's render was observed; the runner's own output is "
            "beside it"
        )
        return result
    result["evidence_sha256"] = hashlib.sha256(raw).hexdigest()
    try:
        declared = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        result["state"] = "failed"
        result["reason"] = "the browser check wrote an evidence document that is not JSON"
        return result
    if not isinstance(declared, dict) or declared.get("schema") != COCKPIT_RENDER_EVIDENCE_SCHEMA:
        result["state"] = "failed"
        result["reason"] = (
            f"the evidence document does not declare {COCKPIT_RENDER_EVIDENCE_SCHEMA!r}"
        )
        return result
    if declared.get("mode") != "live" or declared.get("origin") != origin.url:
        result["state"] = "failed"
        result["reason"] = (
            "the evidence document was not written by a live run against this "
            "origin, so it says nothing about the deployment this report names"
        )
        return result
    for key in ("screenshot", "review_screenshot"):
        shot = declared.get(key)
        if isinstance(shot, str) and shot and "/" not in shot and "\\" not in shot:
            result[key] = redacted_path(evidence_dir / shot)
    items = declared.get("attention_items")
    if isinstance(items, list):
        result["attention_items"] = [
            admitted
            for admitted in (
                evidence_tokens(item, COCKPIT_RENDER_ITEM_SHAPES) for item in items[:LIST_LIMIT]
            )
            if admitted
        ]
    review = declared.get("review")
    if isinstance(review, dict):
        keys = review.get("semantic_keys")
        admitted_review = evidence_tokens(review, COCKPIT_RENDER_REVIEW_SHAPES)
        if isinstance(keys, dict):
            semantic = {}
            for element, value in keys.items():
                if not isinstance(element, str) or not CATEGORY_TOKEN.fullmatch(
                    element.replace("-", "_")
                ):
                    continue
                if value is None:
                    semantic[element] = None
                    continue
                tokens = value.split(" ") if isinstance(value, str) else []
                if tokens and all(SEMANTIC_TOKEN.fullmatch(token) for token in tokens):
                    semantic[element] = tokens
            if semantic:
                admitted_review["semantic_keys"] = semantic
        if admitted_review:
            result["review"] = admitted_review

    state = declared.get("state")
    if state == "blocked":
        reason = declared.get("reason")
        result["state"] = "blocked"
        result["reason"] = (
            bounded_reason(redacted(reason))
            if isinstance(reason, str) and reason
            else "the browser check recorded that it could not observe the render"
        )
        return result
    if state != "asserted":
        result["state"] = "failed"
        result["reason"] = (
            "the browser check did not record an asserted render; the cockpit "
            "contradicted what the deployment's own projection carries"
        )
        return result
    if completed.returncode != 0:
        result["state"] = "failed"
        result["reason"] = (
            "the browser check recorded an asserted render but exited non-zero, "
            "so its own assertions did not all hold"
        )
        return result
    result["state"] = "passed"
    return result


def discover_mobile_origin(
    override: str | None, nonprod_root: Path | None
) -> tuple[Origin | None, str]:
    """The mobile endpoint is a re-rolled quick tunnel, not a fixed hostname.

    The tunnel writes its current hostname into the non-production web entry's
    integration config on every restart, so that file — not a name baked into
    this file — is the only trustworthy source for where a phone points today.
    A run recorded against it is reproducible only while that tunnel lives.
    """
    if override:
        return (
            Origin(key="nonprod", url=override, discovered_from="operator override"),
            "",
        )
    if nonprod_root is None:
        return None, "no non-production web entry root supplied"
    config = nonprod_root / "dashboard-integration.conf"
    try:
        text = config.read_text(encoding="utf-8")
    except OSError as error:
        return None, (
            f"no readable integration config at {redacted_path(config)}: "
            f"{type(error).__name__}"
        )
    for line in text.splitlines():
        if line.startswith(CANONICAL_HOST_KEY):
            host = line[len(CANONICAL_HOST_KEY) :].strip()
            if not host:
                break
            return (
                Origin(
                    key="nonprod",
                    url=f"https://{host}",
                    discovered_from=redacted_path(config),
                    notes=[
                        "ephemeral tunnel hostname, rewritten on every restart of "
                        "the non-production tunnel; this record is reproducible "
                        "only while that tunnel instance lives"
                    ],
                ),
                "",
            )
    return None, f"no canonical host recorded in {redacted_path(config)}"


def self_reported_build(binary: Path) -> dict[str, Any]:
    """Ask the deployed binary itself which revision it was built from.

    This is the answer that survives a deployment procedure replacing a binary
    and leaving the manifest beside it untouched, because nothing outside the
    artifact is consulted. `--build-identity` prints and exits before the entry
    parses its configuration or binds anything, so asking is not starting the
    service.

    A binary that predates the flag refuses it. That refusal is recorded as
    `unavailable` with the reason, never smoothed over: a deployment that cannot
    answer this question is exactly the condition being reported on.
    """
    try:
        result = subprocess.run(
            [str(binary), "--build-identity", "--json"],
            check=False,
            capture_output=True,
            timeout=BUILD_IDENTITY_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return {
            "state": "unavailable",
            "reason": f"the binary could not be asked: {type(error).__name__}",
        }
    if result.returncode != 0:
        return {
            "state": "unavailable",
            "reason": (
                "the deployed binary does not answer --build-identity, so it "
                "predates intrinsic build attribution and can only be named by "
                "a manifest"
            ),
        }
    try:
        declared = json.loads(result.stdout.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {
            "state": "unavailable",
            "reason": "the binary answered --build-identity with something that is not JSON",
        }
    if not isinstance(declared, dict):
        return {
            "state": "unavailable",
            "reason": "the binary answered --build-identity with a non-object document",
        }
    if declared.get("schema") != BUILD_IDENTITY_SCHEMA:
        return {
            "state": "unavailable",
            "reason": (
                f"the binary answered under a schema this harness does not read; "
                f"only {BUILD_IDENTITY_SCHEMA!r} is accepted"
            ),
        }
    provenance = declared.get("provenance")
    revision = declared.get("source_revision")
    provenance = provenance if isinstance(provenance, str) else None
    revision = revision if isinstance(revision, str) else None
    return {
        "state": "recorded",
        "source_revision": revision,
        "provenance": provenance,
        # The build's own rule, restated where the report can be read without
        # the crate to hand: only a declared or committed build corresponds to
        # exactly one revision.
        "attributable": provenance in ATTRIBUTABLE_PROVENANCE and revision is not None,
    }


def describe_build(root: Path | None, label: str) -> dict[str, Any]:
    """Name the build that is running, or say it cannot be named.

    Two independent answers are collected, because they fail in different ways.
    The binary is asked what it was built from, which no external file can make
    wrong. Then every manifest under the release root is searched for the
    running digest, which is the only thing that says whether the release
    metadata on this host is still attached to the binary serving traffic.

    Either one alone resolves attribution. The two disagreeing does not: a
    manifest that describes these exact bytes while naming another revision is a
    contradiction on the host, and it is reported as one rather than settled by
    preferring whichever source this harness happens to trust.
    """
    if root is None:
        return {
            "state": "unavailable",
            "reason": f"no {label} web entry release root supplied",
        }
    binary = root / "bin" / "automonique-web-entry"
    running = digest(binary)
    reported = self_reported_build(binary)
    entry: dict[str, Any] = {
        "state": "recorded",
        "release_root": redacted_path(root),
        "binary": redacted_path(binary),
        "binary_sha256": running,
        "self_reported": reported,
    }
    # `inspect_local_release()` in `automonique-cli` looks beside the binary, at
    # the release root, and through the `current` pointer. This records the
    # release-root candidate, which is the one a deployment is expected to write
    # for a binary installed at `<root>/bin/`.
    doctor_manifest = root / "manifest.json"
    entry["doctor_manifest"] = redacted_path(doctor_manifest)
    entry["doctor_manifest_present"] = doctor_manifest.is_file()
    current = root / "current"
    if current.is_symlink():
        try:
            entry["current_release"] = redacted_path(current.resolve())
        except OSError:
            entry["current_release"] = None
    if running is None:
        entry["source_attribution"] = "unresolved"
        entry["reason"] = "the running binary could not be read"
        return entry
    matches: list[dict[str, Any]] = []
    manifests = 0
    for manifest in sorted(root.rglob("manifest.json")):
        try:
            declared = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(declared, dict):
            continue
        manifests += 1
        if declared.get("binary_sha256") == running:
            matches.append(
                {
                    "manifest": redacted_path(manifest),
                    "schema": declared.get("schema"),
                    "source_sha": declared.get("source_sha"),
                }
            )
    entry["release_manifests_inspected"] = manifests
    intrinsic = reported.get("source_revision") if reported.get("attributable") else None
    contradicted = [
        match
        for match in matches
        if intrinsic is not None
        and isinstance(match.get("source_sha"), str)
        and match["source_sha"] != intrinsic
    ]
    if contradicted:
        entry["source_attribution"] = "contradicted"
        entry["contradicted_by"] = contradicted[:LIST_LIMIT]
        entry["reason"] = (
            "a release manifest records the digest of the running binary but "
            "attributes it to a revision the binary does not report for itself, "
            "so the two accounts of this deployment disagree"
        )
        return entry
    if intrinsic is not None or matches:
        entry["source_attribution"] = "resolved"
        if intrinsic is not None:
            entry["source_revision"] = intrinsic
        if matches:
            entry["attributed_by"] = matches[:LIST_LIMIT]
        return entry
    entry["source_attribution"] = "unresolved"
    entry["reason"] = (
        "the running binary does not report the revision it was built from, and "
        f"no release manifest under {redacted_path(root)} records its digest, so "
        "the deployed build cannot be attributed to a source revision"
    )
    return entry


def build_identity(hosted_root: Path | None, nonprod_root: Path | None) -> dict[str, Any]:
    hosted = describe_build(hosted_root, "hosted")
    nonprod = describe_build(nonprod_root, "non-production")
    identity: dict[str, Any] = {"hosted": hosted, "nonprod_mobile": nonprod}
    hosted_sha = hosted.get("binary_sha256")
    if hosted_sha is not None and hosted_sha == nonprod.get("binary_sha256"):
        identity["hosted_and_nonprod_identical"] = True
        identity["note"] = (
            "the hosted and non-production web entries are byte-identical, so a "
            "difference observed between them is configuration, not code"
        )
    elif hosted_sha is not None and nonprod.get("binary_sha256") is not None:
        identity["hosted_and_nonprod_identical"] = False
    return identity


def check_build_attribution(builds: dict[str, Any]) -> dict[str, Any]:
    """A build that cannot name itself cannot be signed off against a revision."""
    intent = (
        "every deployed build this run probed can be attributed to a source "
        "revision, so the record names what was accepted"
    )
    unresolved = [
        name
        for name in ("hosted", "nonprod_mobile")
        if builds.get(name, {}).get("source_attribution") == "unresolved"
    ]
    contradicted = [
        name
        for name in ("hosted", "nonprod_mobile")
        if builds.get(name, {}).get("source_attribution") == "contradicted"
    ]
    unavailable = [
        name
        for name in ("hosted", "nonprod_mobile")
        if builds.get(name, {}).get("state") == "unavailable"
    ]
    result: dict[str, Any] = {"name": "deployed_build_attribution", "intent": intent}
    if contradicted:
        # Worse than an unattributed build, and reported ahead of one: here two
        # sources both claim to name the deployment and name different things,
        # so a record written from either would look well-sourced and be wrong.
        result["state"] = "failed"
        result["reason"] = (
            "a release manifest and the binary itself disagree about which "
            "revision is deployed for " + ", ".join(contradicted)
        )
        return result
    if unresolved:
        result["state"] = "failed"
        result["reason"] = (
            "the running binary of "
            + ", ".join(unresolved)
            + " neither reports the revision it was built from nor appears in "
            "any release manifest, so this record cannot name the revision it "
            "accepted"
        )
        return result
    if unavailable:
        result["state"] = "blocked"
        result["reason"] = (
            "no release root supplied for " + ", ".join(unavailable)
        )
        return result
    result["state"] = "passed"
    return result


def operator_checklist(signoff_path: Path | None) -> dict[str, Any]:
    """Enumerate what a human must do, and record only a real sign-off."""
    steps = [
        {
            "id": step.identifier,
            "surface": step.surface,
            "instruction": step.instruction,
            "evidence_required": step.evidence_required,
            "residue_after_automation": step.residue,
            "state": "awaiting_operator",
        }
        for step in MANUAL_STEPS
    ]
    record: dict[str, Any] = {
        "why_manual": (
            "These are claims about two GUIs rendering the same thing. No HTTP "
            "probe from this harness establishes them, so the harness does not "
            "pretend to."
        ),
        "residue_note": (
            "`residue_after_automation` names what is left of each step once "
            "everything tools/run_attention_live_parity.py checks against the "
            "deployment is subtracted. Subtracting is not signing: every step "
            "stays `awaiting_operator` until a sign-off names an operator, and "
            "no automated check ever moves one."
        ),
        "signoff_schema": SIGNOFF_SCHEMA,
        "steps": steps,
        "signed_off": False,
        "state": "awaiting_operator",
    }
    if signoff_path is None:
        return record
    record["source"] = redacted_path(signoff_path)
    try:
        raw = signoff_path.read_bytes()
    except OSError as error:
        record["reason"] = f"sign-off file unreadable: {type(error).__name__}"
        return record
    record["source_sha256"] = hashlib.sha256(raw).hexdigest()
    try:
        declared = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as error:
        record["reason"] = f"sign-off file is not JSON: {type(error).__name__}"
        return record
    if not isinstance(declared, dict):
        record["reason"] = "sign-off file is not a JSON object"
        return record
    if declared.get("schema") != SIGNOFF_SCHEMA:
        record["reason"] = (
            f"sign-off file declares schema {declared.get('schema')!r}; this "
            f"harness only accepts {SIGNOFF_SCHEMA!r}"
        )
        return record
    operator = declared.get("operator")
    signed_at = declared.get("signed_at")
    claimed = declared.get("signed_off_ids")
    if not isinstance(claimed, list):
        record["reason"] = "sign-off file has no `signed_off_ids` list"
        return record
    signed = {entry for entry in claimed if isinstance(entry, str)}
    # A sign-off naming a step this harness does not define is how a stale file
    # silently passes a checklist that has since grown. Refuse it outright.
    unknown = sorted(signed - MANUAL_IDS)
    if unknown:
        record["reason"] = (
            "sign-off names steps this harness does not define: "
            + ", ".join(unknown)
            + " — it was written against a different checklist"
        )
        return record
    for step in steps:
        if step["id"] in signed:
            step["state"] = "signed_off"
    record["operator"] = operator if isinstance(operator, str) else None
    record["signed_at"] = signed_at if isinstance(signed_at, str) else None
    missing = sorted(MANUAL_IDS - signed)
    if missing:
        record["reason"] = "steps not signed off: " + ", ".join(missing)
        return record
    if not isinstance(operator, str) or not operator.strip():
        record["reason"] = "every step is signed off but no operator is named"
        return record
    if not isinstance(signed_at, str) or not signed_at.strip():
        record["reason"] = "every step is signed off but no `signed_at` is recorded"
        return record
    record["signed_off"] = True
    record["state"] = "complete"
    return record


def credential_for(name: str | None) -> str | None:
    if not name:
        return None
    value = os.environ.get(name)
    return value or None


def build_origins(args: argparse.Namespace) -> tuple[list[Origin], list[dict[str, Any]]]:
    problems: list[dict[str, Any]] = []
    if args.hosted_loopback:
        hosted = Origin(
            key="hosted",
            url=args.hosted_loopback,
            host_header=args.hosted_host,
            forwarded_proto=LOOPBACK_FORWARDED_PROTO,
            credential_env=args.credential_env,
            discovered_from="operator-supplied loopback",
            notes=[
                "probed on loopback, behind whatever proxy fronts the public "
                "origin; the public path is not exercised by this run"
            ],
        )
    else:
        hosted = Origin(
            key="hosted",
            url=args.hosted_endpoint,
            credential_env=args.credential_env,
            discovered_from="operator-supplied origin",
        )
    origins = [hosted]
    mobile, reason = discover_mobile_origin(
        args.mobile_endpoint, args.nonprod_web_entry_root
    )
    if mobile is None:
        problems.append(
            blocked(
                "mobile_endpoint_discovery",
                "the non-production mobile endpoint a phone would pair against is known",
                reason,
            )
        )
    else:
        mobile.credential_env = args.mobile_credential_env
        origins.append(mobile)
    return origins, problems


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    script_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description=(
            "Run the automatable half of the epic #163 cross-client live "
            "acceptance flow against deployed builds, and enumerate the half "
            "that needs an operator at a GUI. Never reports coverage it does "
            "not have."
        )
    )
    parser.add_argument("--automonique-root", type=Path, default=script_root)
    parser.add_argument("--hosted-root", type=Path, default=None)
    parser.add_argument("--shelldeck-root", type=Path, default=None)
    parser.add_argument("--mobile-root", type=Path, default=None)
    parser.add_argument(
        "--hosted-endpoint",
        default=DEFAULT_HOSTED_ORIGIN,
        help="public origin of the deployed hosted entry",
    )
    parser.add_argument(
        "--hosted-loopback",
        default=None,
        help=(
            "probe the hosted entry on loopback instead of through its public "
            "edge. Sends the canonical Host and asserts the TLS hop the web "
            "entry requires, so the probe reaches the gate instead of a 421/308."
        ),
    )
    parser.add_argument("--hosted-host", default=DEFAULT_HOSTED_HOST)
    parser.add_argument(
        "--hosted-web-entry-root",
        type=Path,
        default=None,
        help="release root of the deployed hosted web entry (contains bin/ and releases/)",
    )
    parser.add_argument(
        "--nonprod-web-entry-root",
        type=Path,
        default=None,
        help=(
            "release root of the non-production web entry; its "
            "dashboard-integration.conf is the only trustworthy source for the "
            "current mobile tunnel hostname"
        ),
    )
    parser.add_argument(
        "--mobile-endpoint",
        default=None,
        help="override the discovered non-production mobile endpoint",
    )
    parser.add_argument(
        "--credential-env",
        default="AUTOMONIQUE_OPS_BASIC_AUTH",
        help=(
            "name of the environment variable holding user:password for the "
            "hosted entry's operator gate. The value never enters the report."
        ),
    )
    parser.add_argument(
        "--mobile-credential-env",
        default="AUTOMONIQUE_NONPROD_BASIC_AUTH",
        help=(
            "name of the environment variable holding user:password for the "
            "non-production entry's operator gate, which is a different "
            "credential. The value never enters the report."
        ),
    )
    parser.add_argument(
        "--cockpit-render-check",
        action="store_true",
        help=(
            "drive the automonique-web-entry browser check against the hosted "
            "cockpit and fold its verdict in as the automated half of "
            "LIVE-GUI-2. Needs a browser toolchain on this host; without the "
            "flag no such check is recorded at all."
        ),
    )
    parser.add_argument(
        "--web-entry-crate",
        type=Path,
        default=script_root / "rust" / "crates" / "automonique-web-entry",
        help="crate holding the cockpit browser check",
    )
    parser.add_argument(
        "--cockpit-render-evidence",
        type=Path,
        default=None,
        help=(
            "directory the cockpit browser check writes its screenshot and "
            "machine-readable evidence into"
        ),
    )
    parser.add_argument("--operator-signoff", type=Path, default=None)
    parser.add_argument(
        "--attention-parity-report",
        type=Path,
        default=None,
        help=(
            "report written by tools/run_attention_live_parity.py. It is the "
            "only thing that establishes whether the deployment serves an "
            "attention corpus at all; without it that question is `blocked`."
        ),
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    return parser.parse_args(argv)


def run(args: argparse.Namespace) -> dict[str, Any]:
    sources = {
        "automonique": repository(args.automonique_root.resolve()),
        "hosted": repository(args.hosted_root.resolve() if args.hosted_root else None),
        "shelldeck": repository(
            args.shelldeck_root.resolve() if args.shelldeck_root else None
        ),
        "mobile": repository(args.mobile_root.resolve() if args.mobile_root else None),
    }
    origins, checks = build_origins(args)

    for origin in origins:
        credential = credential_for(origin.credential_env)
        for gate in GATES:
            checks.append(check_gate(origin, gate, args.timeout))
        for probe in OPENS:
            checks.append(check_open(origin, probe, args.timeout))
        if origin.key == "hosted" and args.hosted_loopback:
            checks.append(check_liveness(origin, args.timeout))
        for probe in AUTHORIZED:
            checks.append(
                check_authorized(
                    origin, probe, credential, origin.credential_env, args.timeout
                )
            )

    projection = next(
        (check for check in checks if check["name"] == "hosted_attention_projection"),
        None,
    )
    if projection is not None:
        checks.append(check_resource_inventory(projection))
    checks.append(check_attention_corpus(args.attention_parity_report))

    if args.cockpit_render_check:
        hosted = next((origin for origin in origins if origin.key == "hosted"), None)
        if hosted is not None:
            checks.append(
                check_cockpit_render(
                    hosted,
                    args.web_entry_crate.resolve() if args.web_entry_crate else None,
                    args.cockpit_render_evidence,
                    hosted.credential_env,
                    COCKPIT_RENDER_TIMEOUT,
                )
            )

    builds = build_identity(args.hosted_web_entry_root, args.nonprod_web_entry_root)
    checks.append(check_build_attribution(builds))

    checklist = operator_checklist(args.operator_signoff)

    failed = [check["name"] for check in checks if check["state"] == "failed"]
    stopped = [check["name"] for check in checks if check["state"] == "blocked"]
    automated_passed = not failed and not stopped
    passed = automated_passed and checklist["signed_off"]

    if failed:
        state = "failed"
        reason = (
            "the deployment contradicted a contract this harness checks; failed: "
            + ", ".join(failed)
        )
    elif stopped:
        state = "blocked"
        reason = (
            "an automated check could not be made against a deployment; blocked: "
            + ", ".join(stopped)
        )
    elif not checklist["signed_off"]:
        state = "automated_only"
        reason = (
            "every automatable check passed against the deployment, but the "
            "cross-client GUI steps are unsigned. Epic #163 is not closed by "
            "this report alone."
        )
    else:
        state = "complete"
        reason = (
            "every automatable check passed against the deployment and an "
            "operator signed off every GUI step"
        )

    return {
        "schema": SCHEMA,
        "mode": "live_deployment",
        "passed": passed,
        "sources": sources,
        "deployed_builds": builds,
        "endpoints": {
            origin.key: {
                "url": origin.url,
                "host_header": origin.host_header,
                "credential_env": origin.credential_env,
                "credential_supplied": credential_for(origin.credential_env) is not None,
                "discovered_from": origin.discovered_from,
                "notes": origin.notes,
            }
            for origin in origins
        },
        "redaction": (
            "Only allow-listed fields of the response types the web entry "
            "serializes reach this report, at every depth. Free-text and "
            "credential-scoped fields are dropped; identical list projections "
            "are collapsed, with the true length under `observed_counts` and the "
            "collapsed length under `<name>.distinct_projections`; and the "
            f"operator's home directory is written as {HOME_PLACEHOLDER}."
        ),
        "checks": checks,
        "operator_checklist": checklist,
        "live_verification": {"state": state, "reason": reason},
    }


def main(argv: list[str] | None = None) -> int:
    report = run(parse_args(argv))
    for origin_key, endpoint in report["endpoints"].items():
        if not endpoint["credential_supplied"]:
            print(
                f"no credential in ${endpoint['credential_env']} for {origin_key}; "
                "reads behind its gate are reported as blocked, never as passing",
                file=sys.stderr,
            )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
