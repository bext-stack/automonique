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
   `awaiting_operator` until a sign-off file names every one of them.

3. The deployed build may not be attributable to a source revision. When the
   running binary's digest appears in no release manifest under the release
   root, the honest record is the running digest plus an explicit `unresolved`
   attribution, not a revision the harness cannot prove.

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
    }
)
SECRET_MARKERS = ("token", "secret", "password", "credential", "authorization", "cookie")
CATEGORY_TOKEN = re.compile(r"\A[a-z0-9_]{1,64}\Z")
SCALAR_LIMIT = 128
LIST_LIMIT = 16
BODY_LIMIT = 262144

HOME_PLACEHOLDER = "$HOME"


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
    """A step no probe can establish, to be signed off by a named operator."""

    identifier: str
    surface: str
    instruction: str
    evidence_required: str


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


def check_attention_corpus(projection: dict[str, Any]) -> dict[str, Any]:
    """Decide whether the deployment has a live attention corpus to compare.

    Derived from the projection already read, not a second request. A refused
    inventory is the deployment behaving as `WebIntegration::platform()` says it
    should when a snapshot of everything no longer fits — the surface stays
    truthful instead of hanging. It is still not a corpus: with no resources,
    the cross-client GUI steps have nothing to agree about, and saying otherwise
    would be the whole failure this harness exists to prevent.
    """
    intent = (
        "the deployed build actually serves an attention corpus, so the "
        "cross-client comparison has something to compare"
    )
    name = "hosted_attention_corpus_available"
    if projection.get("state") != "passed":
        return blocked(
            name,
            intent,
            "the attention projection was not read, so its corpus is unknown",
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
            "the inventory is available but empty, so there is no live attention "
            "item for the cross-client steps to agree about"
        )
        return result
    result["state"] = "blocked"
    result["reason"] = (
        "the deployed build refuses its resource inventory"
        + (f" ({explanation})" if explanation else "")
        + " and serves no resources, so no live attention item exists to compare "
        "across clients"
    )
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


def describe_build(root: Path | None, label: str) -> dict[str, Any]:
    """Name the build that is running, or say it cannot be named.

    A release manifest is evidence only when it describes the binary on disk.
    This walks every manifest under the release root looking for the running
    digest; when none records it, the running build is not attributable to a
    revision and the report says so instead of quoting the manifest anyway.
    """
    if root is None:
        return {
            "state": "unavailable",
            "reason": f"no {label} web entry release root supplied",
        }
    binary = root / "bin" / "automonique-web-entry"
    running = digest(binary)
    entry: dict[str, Any] = {
        "state": "recorded",
        "release_root": redacted_path(root),
        "binary": redacted_path(binary),
        "binary_sha256": running,
    }
    # `inspect_local_release()` in `automonique-cli` resolves the manifest as
    # `<executable>/../../manifest.json`, so for a binary deployed at
    # `<root>/bin/` that is `<root>/manifest.json`.
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
    if matches:
        entry["source_attribution"] = "resolved"
        entry["attributed_by"] = matches[:LIST_LIMIT]
        return entry
    entry["source_attribution"] = "unresolved"
    entry["reason"] = (
        f"no release manifest under {redacted_path(root)} records the digest of "
        "the binary that is running, so the deployed build cannot be attributed "
        "to a source revision"
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
    unavailable = [
        name
        for name in ("hosted", "nonprod_mobile")
        if builds.get(name, {}).get("state") == "unavailable"
    ]
    result: dict[str, Any] = {"name": "deployed_build_attribution", "intent": intent}
    if unresolved:
        result["state"] = "failed"
        result["reason"] = (
            "the running binary of "
            + ", ".join(unresolved)
            + " appears in no release manifest, so this record cannot name the "
            "revision it accepted"
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
    parser.add_argument("--operator-signoff", type=Path, default=None)
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
        checks.append(check_attention_corpus(projection))

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
