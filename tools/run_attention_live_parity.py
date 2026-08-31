#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Run the three clients' real attention reducers over live deployment data.

`run_attention_parity_acceptance.py` proves the three clients agree about a
fixed corpus. `run_attention_live_acceptance.py` proves a deployment answers,
gates, and advertises what the source says it should. Neither one puts what the
deployment is *serving right now* through the clients' reducers, so "ShellDeck,
the hosted cockpit, and Mobile agree about the live attention state" was
asserted by nobody.

This harness asserts it, and refuses to assert more than it can.

    capture   The live read is performed by `automonique-platform-client` — the
              production client, over HTTPS, with the operator credential — via
              the `attention_live_capture` example. Canonical bytes are carried
              through base64 and never re-serialized, so each client decodes the
              deployment's bytes with its own production decoder.

    replay    ShellDeck replays through `shelldeck_core::config::
              platform_attention`, Mobile through `src/core/attention-source-*`.
              The hosted cockpit is not replayed at all: it is *read*, because
              the deployment runs `platform_cockpit.rs` itself and its answer to
              `POST /api/platform/cockpit` is that reducer's live output.

    control   Three clients that decode nothing and show nothing agree
              perfectly. So before any live comparison is reported, every driver
              must reproduce a known-answer control — a real record graph and a
              real two-generation succession, built with the same encoders —
              and the drivers must agree about it. A live agreement reached
              without that is reported as `blocked`, never as a pass.

Two things this harness will not do.

It never marks an operator step satisfied. LIVE-GUI-1..4 in
`run_attention_live_acceptance.py` each require evidence a human saw a screen.
What is proved here is the *semantic claim inside* some of those steps; the
report says, per step, exactly which part is now machine-checked against the
deployment and what residue is left for a person. Subtracting is not signing.

And it never reports a check that could not fire as one that did. A succession
comparison over a deployment whose generation never moved is `not_exercised`,
with the reason, because a check that cannot fail is worse than an absent one.

Identifiers observed live are salted per run and recorded as digests. Equality
inside one report is meaningful — that is the entire comparison — and no live
work coordinate is written down. Credentials reach this harness by variable
*name*; no value is read, logged, or recorded.

The report is the only thing on stdout; diagnostics go to stderr.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


SCHEMA = "automonique.attention-live-parity-report/v1"
CAPTURE_SCHEMA = "automonique.attention-live-capture/v1"
REPLAY_INPUT_SCHEMA = "automonique.attention-live-replay-input/v1"
PROJECTION_SCHEMA = "automonique.attention-live-projection/v1"

DEFAULT_HOSTED_ORIGIN = "https://monique.1clic.pro"
DEFAULT_HOSTED_HOST = "monique.1clic.pro"
PLATFORM_V2_PATH = "/api/platform/v2"
COCKPIT_PATH = "/api/platform/cockpit"

# Cloudflare answers 403 to `Python-urllib/*`, which reads exactly like the
# deployment refusing the probe. The same reason `run_attention_live_acceptance`
# names itself.
USER_AGENT = "automonique-live-parity/1"
LOOPBACK_FORWARDED_PROTO = "https"

BODY_LIMIT = 4 * 1024 * 1024
HOME_PLACEHOLDER = "$HOME"

# The clients under test and where each one's reducer lives. `hosted` has no
# driver on purpose: the deployment runs it.
CLIENTS = ("shelldeck", "hosted", "mobile")

# Mobile's sources are authored for a bundler. Node needs the transform flag to
# load them, and the driver installs its own resolution hook for the rest.
NODE_FLAGS = ("--experimental-transform-types", "--no-warnings")

CATEGORY_TOKEN = re.compile(r"\A[a-z0-9_]{1,64}\Z")


# --- redaction -------------------------------------------------------------


class Salt:
    """Per-run salt for identifier digests.

    Identifiers are the comparison. Recording them raw would put live work
    coordinates in a report; recording them under an unsalted digest would make
    them recoverable by guessing, because a workspace identifier is a short
    string from a small space. A per-run salt keeps equality inside one report
    exactly as informative as it has to be and nothing more.
    """

    def __init__(self) -> None:
        self._salt = secrets.token_bytes(16)

    def of(self, value: str) -> str:
        digest = hashlib.sha256(self._salt + value.encode("utf-8")).hexdigest()
        return f"#{digest[:12]}"


def category(value: Any) -> Any:
    """Admit a refusal category only when it is a bare token.

    Every category this harness reports is a compile-time constant somewhere in
    the tree. Anything else could be free text about live work, so it is
    withheld rather than reproduced — the same rule
    `run_attention_live_acceptance.py` applies to `explanation`.
    """
    if not isinstance(value, str):
        return value
    return value if CATEGORY_TOKEN.fullmatch(value) else "<non_category_text_withheld>"


def redacted(value: str) -> str:
    try:
        home = str(Path.home().resolve())
    except (OSError, RuntimeError):
        return value
    return value.replace(home, HOME_PLACEHOLDER) if home else value


# --- repositories ----------------------------------------------------------


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


def repository(root: Path | None) -> dict[str, Any]:
    if root is None:
        return {"state": "unavailable", "reason": "no root supplied"}
    if not root.is_dir():
        return {
            "state": "unavailable",
            "path": redacted(str(root)),
            "reason": "path is not a directory on this host",
        }
    try:
        return {
            "state": "recorded",
            "path": redacted(str(root)),
            "revision": git(root, "rev-parse", "HEAD"),
            "dirty": bool(git(root, "status", "--porcelain")),
        }
    except (OSError, subprocess.CalledProcessError) as error:
        return {
            "state": "unavailable",
            "path": redacted(str(root)),
            "reason": f"git could not describe this path: {type(error).__name__}",
        }


def pinned_protocol(shelldeck_root: Path) -> dict[str, Any]:
    """Read the protocol revision the ShellDeck checkout pins.

    ShellDeck consumes `automonique-protocol` from a pinned git revision, not
    from this working tree. A driver built against anything else would be
    checking a ShellDeck nobody runs, and the two revisions differing is a fact
    about the fleet worth recording rather than smoothing over.
    """
    manifest = shelldeck_root / "Cargo.toml"
    try:
        text = manifest.read_text(encoding="utf-8")
    except OSError as error:
        return {"state": "unavailable", "reason": type(error).__name__}
    match = re.search(
        r'automonique-protocol\s*=\s*\{\s*git\s*=\s*"([^"]+)"\s*,\s*rev\s*=\s*"([^"]+)"',
        text,
    )
    if match is None:
        return {
            "state": "unavailable",
            "reason": "no pinned automonique-protocol git revision in the ShellDeck manifest",
        }
    return {"state": "recorded", "git": match.group(1), "revision": match.group(2)}


# --- HTTP ------------------------------------------------------------------


def credential_header(raw: str | None) -> dict[str, str]:
    if not raw:
        return {}
    encoded = base64.b64encode(raw.encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {encoded}"}


def post(
    url: str,
    body: bytes,
    credential: str | None,
    timeout: float,
    host_header: str | None,
    forwarded_proto: str | None,
) -> dict[str, Any]:
    """Perform one POST and classify the outcome without ever raising."""
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }
    if host_header:
        headers["Host"] = host_header
    if forwarded_proto:
        headers["X-Forwarded-Proto"] = forwarded_proto
    headers.update(credential_header(credential))
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return {"http_status": response.status, "body": response.read(BODY_LIMIT)}
    except urllib.error.HTTPError as error:
        return {"http_status": error.code, "body": error.read(BODY_LIMIT)}
    except (TimeoutError, socket.timeout):
        return {"unreachable": "Timeout"}
    except urllib.error.URLError as error:
        return {"unreachable": type(error.reason).__name__}
    except (ssl.SSLError, OSError, ValueError) as error:
        return {"unreachable": type(error).__name__}


# --- subprocess lanes ------------------------------------------------------


def run_json(
    command: list[str],
    cwd: Path,
    stdin: bytes | None = None,
    timeout: float = 600.0,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run a child that prints one JSON document, and never raise."""
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return {"state": "failed", "reason": f"child could not run: {type(error).__name__}"}
    if completed.returncode != 0:
        return {
            "state": "failed",
            "exit_code": completed.returncode,
            # The child's diagnostics name the variable, never its value; the
            # tail is bounded so a chatty toolchain cannot flood the report.
            "stderr_tail": redacted(
                completed.stderr.decode("utf-8", "replace").strip()[-512:]
            ),
        }
    try:
        return {"state": "passed", "document": json.loads(completed.stdout)}
    except ValueError:
        return {"state": "failed", "reason": "child did not print a JSON document"}


# --- capture ---------------------------------------------------------------


def capture_command(repo: Path, target_dir: Path) -> list[str]:
    return [
        "cargo",
        "run",
        "--quiet",
        "--manifest-path",
        str(repo / "sdk/rust/platform-client/Cargo.toml"),
        "--target-dir",
        str(target_dir),
        "--example",
        "attention_live_capture",
        "--",
    ]


def capture(
    repo: Path,
    target_dir: Path,
    arguments: list[str],
    timeout: float,
) -> dict[str, Any]:
    return run_json(
        capture_command(repo, target_dir) + arguments,
        cwd=repo,
        timeout=timeout,
    )


# --- drivers ---------------------------------------------------------------


def render_shelldeck_manifest(
    repo: Path, shelldeck_root: Path, protocol: dict[str, Any], scratch: Path
) -> Path | None:
    template = repo / "tools/parity/shelldeck_live_replay/Cargo.toml.template"
    source = repo / "tools/parity/shelldeck_live_replay/src/main.rs"
    if protocol.get("state") != "recorded":
        return None
    try:
        rendered = (
            template.read_text(encoding="utf-8")
            .replace("@DRIVER_SOURCE@", str(source))
            .replace("@SHELLDECK_CORE@", str(shelldeck_root / "crates/shelldeck-core"))
            .replace("@PROTOCOL_GIT@", str(protocol["git"]))
            .replace("@PROTOCOL_REV@", str(protocol["revision"]))
        )
    except OSError:
        return None
    scratch.mkdir(parents=True, exist_ok=True)
    manifest = scratch / "Cargo.toml"
    manifest.write_text(rendered, encoding="utf-8")
    return manifest


def shelldeck_driver(manifest: Path, target_dir: Path) -> list[str]:
    return [
        "cargo",
        "run",
        "--quiet",
        "--manifest-path",
        str(manifest),
        "--target-dir",
        str(target_dir),
    ]


def mobile_driver(repo: Path, mobile_root: Path) -> list[str]:
    return [
        "node",
        *NODE_FLAGS,
        str(repo / "tools/parity/mobile_live_replay.mjs"),
        str(mobile_root),
    ]


# --- hosted cockpit read ---------------------------------------------------


def cockpit_read(
    origin: str,
    workspace: str | None,
    credential: str | None,
    timeout: float,
    host_header: str | None,
    forwarded_proto: str | None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"action": "read"}
    if workspace is not None:
        body["workspace_id"] = workspace
    outcome = post(
        origin.rstrip("/") + COCKPIT_PATH,
        json.dumps(body).encode("utf-8"),
        credential,
        timeout,
        host_header,
        forwarded_proto,
    )
    if "unreachable" in outcome:
        return {"state": "blocked", "reason": f"deployment unreachable: {outcome['unreachable']}"}
    if outcome.get("http_status") != 200:
        return {
            "state": "blocked",
            "reason": f"cockpit read answered {outcome.get('http_status')}",
        }
    try:
        return {"state": "passed", "document": json.loads(outcome["body"])}
    except ValueError:
        return {"state": "blocked", "reason": "cockpit read did not answer JSON"}


def hosted_projection(document: dict[str, Any], salt: Salt) -> dict[str, Any]:
    """Project the deployment's own cockpit answer into the shared shape.

    Nothing is reduced here. Every value below was decided by
    `platform_cockpit.rs` running on the deployment; this only renames its
    fields into the shape the two replayed clients print, so the comparison is
    between three projections rather than between three vocabularies.

    The hosted cockpit retains nothing between requests, so this is a
    projection, not a succession. The parity harness records that asymmetry
    rather than inventing a history for it.
    """
    mode = document.get("mode")
    attention = document.get("attention") or {}
    if mode != "v2":
        degradation = document.get("degradation") or {}
        return {
            "schema": PROJECTION_SCHEMA,
            "client": "hosted",
            "inventory": {
                "state": "refused",
                "error": category(degradation.get("category") or attention.get("category")),
            },
            "board": {"state": "absent"},
            "sources": {},
            "visible_items": [],
            "presents_attention": False,
            "coverage": {
                "state": attention.get("state"),
                "category": category(attention.get("category")),
            },
        }
    inbox = document.get("inbox") or {}
    items = inbox.get("items") or []
    sources: dict[str, Any] = {}
    visible: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        kind = item.get("source_kind")
        identifier = item.get("source_id")
        if not isinstance(kind, str) or not isinstance(identifier, str):
            continue
        key = f"{kind}:{salt.of(identifier)}"
        entry = sources.setdefault(
            key,
            {
                "status": {"kind": "available"},
                "generation": item.get("source_revision"),
                "visible_items": [],
            },
        )
        item_id = item.get("id")
        # The cockpit's inbox identifier is `kind:source:item`; the item is the
        # last component. Splitting from the right is what keeps a source
        # identifier containing a colon from stealing the item's name.
        tail = item_id.rsplit(":", 1)[-1] if isinstance(item_id, str) else None
        if tail is not None:
            entry["visible_items"].append(salt.of(tail))
            visible.append(
                {
                    "source": key,
                    "item": salt.of(tail),
                    "state": item.get("state"),
                    "reason": item.get("reason"),
                }
            )
    observation = (inbox.get("sources") or {}).get("attention") or {}
    return {
        "schema": PROJECTION_SCHEMA,
        "client": "hosted",
        "inventory": {"state": "observed", "sources": sorted(sources)},
        "board": {"state": "constructed"},
        "sources": sources,
        "visible_items": visible,
        "presents_attention": bool(visible),
        "observation": {
            "state": observation.get("state"),
            "category": category(observation.get("category")),
        },
        "coverage": {
            "state": attention.get("state"),
            "category": category(attention.get("category")),
        },
        "truncated": inbox.get("omitted") not in (None, "0"),
    }


# --- projections and comparison --------------------------------------------


def salted_projection(document: dict[str, Any], salt: Salt) -> dict[str, Any]:
    """Replace every live identifier in a driver projection with a digest."""

    def key(value: str) -> str:
        kind, _, identifier = value.partition(":")
        return f"{kind}:{salt.of(identifier)}" if identifier else value

    sources = {
        key(name): {
            "status": entry.get("status"),
            "generation": entry.get("generation"),
            "visible_items": [salt.of(item) for item in entry.get("visible_items", [])],
        }
        for name, entry in (document.get("sources") or {}).items()
    }
    inventory = document.get("inventory") or {}
    if isinstance(inventory.get("sources"), list):
        inventory = dict(inventory, sources=sorted(key(name) for name in inventory["sources"]))
    if isinstance(inventory.get("error"), str):
        inventory = dict(inventory, error=category(inventory["error"]))
    return {
        "schema": document.get("schema"),
        "client": document.get("client"),
        "inventory": inventory,
        "board": document.get("board"),
        "sources": sources,
        "visible_items": [
            {
                "source": key(entry.get("source", "")),
                "item": salt.of(entry.get("item", "")),
                "state": entry.get("state"),
                "reason": entry.get("reason"),
            }
            for entry in document.get("visible_items") or []
        ],
        "presents_attention": document.get("presents_attention"),
    }


def comparable(projection: dict[str, Any]) -> dict[str, Any]:
    """The part of a projection its client is required to agree about.

    A dimension a client cannot express is `None`, not an empty value, and a
    `None` never takes part in a comparison. That distinction is the whole
    correctness of this function.

    The hosted cockpit is the case that forces it. Its live answer is an inbox
    of *items*, so a source it inventoried and read and found empty is
    indistinguishable, from outside, from a source it never had. Comparing its
    source set against a replayed client's would report a disagreement every
    time a workspace held an idle source, which is a fact about what the
    cockpit's wire shape can say and not about attention. So `inventory` and
    per-source `status` are `None` for it, and the item sets and generations it
    *can* state are compared against everyone.

    Two things are deliberately not compared for anyone. Source-inventory order
    is a client's own business: ShellDeck holds the set by source kind and
    Mobile alphabetically. Global visible-item order across sources is not
    fixed by the shared corpus either, which states its expectation per source.
    Per-source item order is compared, because the corpus does fix that.
    """
    expresses_inventory = (projection.get("inventory") or {}).get("state") == "derived"
    sources = projection.get("sources") or {}
    return {
        "inventory": (
            sorted((projection.get("inventory") or {}).get("sources") or [])
            if expresses_inventory
            else None
        ),
        "status": (
            {name: entry.get("status") for name, entry in sources.items()}
            if expresses_inventory
            else None
        ),
        # Restricted to sources this projection shows items for, which is the
        # only shape every client can state. A source with no items contributes
        # nothing here for anyone, so the restriction removes no evidence.
        "items": {
            name: {
                "generation": entry.get("generation"),
                "visible_items": entry.get("visible_items"),
            }
            for name, entry in sources.items()
            if entry.get("visible_items")
        },
        "presents_attention": projection.get("presents_attention"),
    }


DIMENSIONS = ("inventory", "status", "items", "presents_attention")


def disagreements(projections: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Name every dimension on which the clients that can speak do not agree.

    Each dimension is compared only across the clients whose projection carries
    it. A dimension only one client expresses is not a comparison and is not
    reported as agreement either; `participants` on each finding, and
    `compared_by` from `comparison_scope`, say who took part.
    """
    reduced = {name: comparable(value) for name, value in projections.items()}
    found: list[dict[str, Any]] = []
    for dimension in DIMENSIONS:
        speakers = sorted(
            name for name, value in reduced.items() if value[dimension] is not None
        )
        if len(speakers) < 2:
            continue
        reference = speakers[0]
        for name in speakers[1:]:
            if reduced[reference][dimension] != reduced[name][dimension]:
                found.append(
                    {
                        "dimension": dimension,
                        "between": [reference, name],
                        "participants": speakers,
                        reference: reduced[reference][dimension],
                        name: reduced[name][dimension],
                    }
                )
    return found


def comparison_scope(projections: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    """Record which clients took part in each dimension.

    A dimension no two clients could speak to was not compared. Saying so is
    the difference between `passed` meaning "they agreed" and `passed` meaning
    "nobody was asked".
    """
    reduced = {name: comparable(value) for name, value in projections.items()}
    return {
        dimension: sorted(
            name for name, value in reduced.items() if value[dimension] is not None
        )
        for dimension in DIMENSIONS
    }


# --- checks ----------------------------------------------------------------


def pass_signature(entries: list[dict[str, Any]]) -> str:
    """Summarise one live read as `(source, read kind, generation)` triples.

    Two reads with the same signature are the same generation of the same
    sources, and replaying them proves nothing about succession. The generation
    is read out of the canonical snapshot bytes themselves, not out of anything
    this harness computed.
    """
    rows = []
    for entry in entries or []:
        source = entry.get("source") or {}
        key = f"{source.get('kind')}:{source.get('id')}"
        read = entry.get("read") or {}
        kind = read.get("kind")
        generation = None
        payload = read.get("snapshot_canonical_base64")
        if isinstance(payload, str):
            try:
                generation = json.loads(base64.b64decode(payload, validate=True)).get(
                    "revision"
                )
            except (ValueError, binascii.Error, AttributeError):
                generation = "<undecodable>"
        rows.append((key, kind, read.get("category"), generation))
    return json.dumps(sorted(rows), sort_keys=True, default=str)


def check(name: str, intent: str, state: str, **extra: Any) -> dict[str, Any]:
    return {"name": name, "intent": intent, "state": state, **extra}


CONTROL_INTENT = (
    "each replay driver reproduces a known-answer control, so a live agreement "
    "cannot be reached by three drivers that decode nothing and show nothing"
)


def control_matches(projection: dict[str, Any], expectation: dict[str, Any]) -> str | None:
    """Return the first way this projection fails the control, or None."""
    inventory = (projection.get("inventory") or {}).get("sources") or []
    wanted = expectation.get("inventory_contains")
    if wanted not in inventory:
        return f"the control source {wanted!r} is not in the derived inventory {inventory!r}"
    entry = (projection.get("sources") or {}).get(wanted) or {}
    if entry.get("generation") != expectation.get("final_generation"):
        return (
            f"the control ends at generation {expectation.get('final_generation')!r}; "
            f"this driver reached {entry.get('generation')!r}"
        )
    if entry.get("visible_items") != expectation.get("final_visible_items"):
        return (
            f"the control ends showing {expectation.get('final_visible_items')!r}; "
            f"this driver shows {entry.get('visible_items')!r}"
        )
    if (projection.get("status") or {}).get("kind") == "absent":
        return "the control source is absent from the board"
    return None


# --- GUI residue -----------------------------------------------------------

# What this harness proves about each operator step, and what is left over.
#
# The subtraction is deliberate and it is one-way: naming the part a machine now
# checks never marks the step done. Each step demands evidence a person saw a
# screen, and no HTTP read and no reducer replay is that evidence. These entries
# are reported next to `run_attention_live_acceptance.py`'s checklist, which is
# unchanged and still `awaiting_operator`.
GUI_RESIDUE = (
    {
        "id": "LIVE-GUI-1",
        "surface": "ShellDeck desktop",
        "machine_verified": (
            "That ShellDeck's real board derives its attention source inventory "
            "from the deployment's own work-context graph, and reaches the same "
            "source set, generation and visible items as the other two clients "
            "for the live read — including refusing to derive an inventory when "
            "the graph does not authorize a complete one."
        ),
        "residue": (
            "That a human, at the running desktop application, sees the badge "
            "re-resolve to a pane ShellDeck is authorized for at that moment. "
            "Re-resolution runs against the client's live pane and session "
            "catalogues, which exist only inside a running GUI process; this "
            "harness never starts one and never observes one."
        ),
        "reducible": False,
    },
    {
        "id": "LIVE-GUI-2",
        "surface": "monique.1clic.pro",
        "machine_verified": (
            "That the deployed hosted cockpit's own attention projection — read "
            "from the deployment, produced by the platform_cockpit.rs it is "
            "running — names the same source and the same generation as the two "
            "replayed clients, and asserts no review state the source did not."
        ),
        "residue": (
            "That the item on the cockpit is the item ShellDeck showed the same "
            "person, on their screen, in one sitting. The rendering half stopped "
            "being residue when `--cockpit-render-check` landed in "
            "run_attention_live_acceptance.py: it observes the deployed page "
            "rendering the source and generation its own authorized projection "
            "carries. That check and this one meet at the projection and never "
            "at a person, so what neither establishes is that one human saw the "
            "same thing twice."
        ),
        "reducible": False,
    },
    {
        "id": "LIVE-GUI-3",
        "surface": "Automonique Mobile",
        "machine_verified": (
            "That Mobile's real board and projection reach the same source, "
            "generation and item set as the other two for the live read."
        ),
        "residue": (
            "The whole of the step's substance: pairing a phone, opening a "
            "generation-bound deep link, landing on the session, and watching a "
            "superseded generation be refused. Deep-link admission is "
            "`attention-source-navigation.ts`, which resolves against the "
            "phone's own catalogues and its paired credential; neither exists "
            "in this harness. Nothing here reduces this step."
        ),
        "reducible": False,
    },
    {
        "id": "LIVE-GUI-4",
        "surface": "cross-client",
        "machine_verified": (
            "The succession half, when the deployment moves during a run: "
            "successive live reads are replayed through all three clients and "
            "their convergence on the new generation is asserted, as is the "
            "rule that a retention gap surfaces as an explicit resynchronization "
            "rather than a partial page. When the deployment does not move, this "
            "is reported `not_exercised` and proves nothing."
        ),
        "residue": (
            "Retiring an item *from a client*, and 'without a manual refresh'. "
            "This harness reads; it never acts on the deployment, so it never "
            "causes the retirement the step is about. And convergence here is "
            "convergence of reducers over reads this harness issued — not of "
            "three running clients refreshing themselves. The propagation is "
            "the part a person still has to see."
        ),
        "reducible": False,
    },
)


# --- run -------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    script_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description=(
            "Replay the attention read a deployment actually serves through the "
            "three clients' real reducers and record whether they agree. Never "
            "marks an operator GUI step satisfied."
        )
    )
    parser.add_argument("--automonique-root", type=Path, default=script_root)
    parser.add_argument("--shelldeck-root", type=Path, default=None)
    parser.add_argument("--mobile-root", type=Path, default=None)
    parser.add_argument("--hosted-endpoint", default=DEFAULT_HOSTED_ORIGIN)
    parser.add_argument(
        "--hosted-loopback",
        default=None,
        help=(
            "probe the hosted entry on loopback instead of through its public "
            "edge, sending the canonical Host and the TLS hop the web entry "
            "requires"
        ),
    )
    parser.add_argument("--hosted-host", default=DEFAULT_HOSTED_HOST)
    parser.add_argument(
        "--credential-env",
        default="AUTOMONIQUE_OPS_BASIC_AUTH",
        help=(
            "name of the environment variable holding user:password for the "
            "operator gate. The value never enters the report."
        ),
    )
    parser.add_argument(
        "--reads",
        type=int,
        default=3,
        help="successive live reads to replay as a succession (minimum 2)",
    )
    parser.add_argument("--interval-seconds", type=float, default=2.0)
    parser.add_argument(
        "--scratch-dir",
        type=Path,
        default=None,
        help="where rendered manifests and cargo target directories are written",
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--build-timeout", type=float, default=1800.0)
    return parser.parse_args(argv)


class Run:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.salt = Salt()
        self.repo = args.automonique_root.resolve()
        self.shelldeck = args.shelldeck_root.resolve() if args.shelldeck_root else None
        self.mobile = args.mobile_root.resolve() if args.mobile_root else None
        self.credential = os.environ.get(args.credential_env) or None
        self.checks: list[dict[str, Any]] = []
        self.scratch = (
            args.scratch_dir.resolve()
            if args.scratch_dir
            else self.repo / "target" / "attention-live-parity"
        )
        self.origin = args.hosted_loopback or args.hosted_endpoint
        self.host_header = args.hosted_host if args.hosted_loopback else None
        self.forwarded_proto = LOOPBACK_FORWARDED_PROTO if args.hosted_loopback else None
        self.protocol = (
            pinned_protocol(self.shelldeck)
            if self.shelldeck
            else {"state": "unavailable", "reason": "no ShellDeck root supplied"}
        )
        self.shelldeck_manifest: Path | None = None

    # -- driver lanes ------------------------------------------------------

    def replay(self, client: str, document: dict[str, Any]) -> dict[str, Any]:
        payload = json.dumps(document).encode("utf-8")
        if client == "shelldeck":
            if self.shelldeck_manifest is None:
                return {"state": "blocked", "reason": "the ShellDeck driver was not prepared"}
            environment = os.environ.copy()
            # ShellDeck's core links a crate whose build script needs pkg-config
            # to find the system libraries a desktop build links against.
            environment.setdefault(
                "PKG_CONFIG_PATH", "/usr/lib/x86_64-linux-gnu/pkgconfig"
            )
            return run_json(
                shelldeck_driver(self.shelldeck_manifest, self.scratch / "shelldeck-target"),
                cwd=self.scratch,
                stdin=payload,
                timeout=self.args.build_timeout,
                environment=environment,
            )
        if client == "mobile":
            if self.mobile is None:
                return {"state": "blocked", "reason": "no Automonique Mobile root supplied"}
            return run_json(
                mobile_driver(self.repo, self.mobile),
                cwd=self.mobile,
                stdin=payload,
                timeout=self.args.timeout * 10,
                environment=os.environ.copy(),
            )
        return {"state": "blocked", "reason": f"no driver for {client}"}

    # -- stages ------------------------------------------------------------

    def prepare(self) -> None:
        self.scratch.mkdir(parents=True, exist_ok=True)
        if shutil.which("cargo") is None:
            self.checks.append(
                check(
                    "toolchain_available",
                    "the harness can build the capture tool and the ShellDeck driver",
                    "blocked",
                    reason="cargo is not on PATH",
                )
            )
            return
        if self.shelldeck is not None:
            self.shelldeck_manifest = render_shelldeck_manifest(
                self.repo, self.shelldeck, self.protocol, self.scratch / "shelldeck-live-replay"
            )
        self.checks.append(
            check(
                "toolchain_available",
                "the harness can build the capture tool and the ShellDeck driver",
                "passed",
                cargo=redacted(shutil.which("cargo") or ""),
                node=redacted(shutil.which("node") or ""),
            )
        )

    def control(self) -> dict[str, dict[str, Any]]:
        """Prove every driver drives its client before any live claim is made."""
        produced = capture(
            self.repo,
            self.scratch / "capture-target",
            ["--control"],
            self.args.build_timeout,
        )
        if produced["state"] != "passed":
            self.checks.append(
                check(
                    "control_document_built",
                    CONTROL_INTENT,
                    "blocked",
                    reason="the capture tool could not produce the control document",
                    detail=produced,
                )
            )
            return {}
        document = produced["document"]
        expectation = document.get("control_expectation") or {}
        self.checks.append(
            check(
                "control_document_built",
                CONTROL_INTENT,
                "passed",
                expectation=expectation,
            )
        )
        projections: dict[str, dict[str, Any]] = {}
        for client in ("shelldeck", "mobile"):
            outcome = self.replay(client, document)
            name = f"control_replays_through_{client}"
            if outcome["state"] != "passed":
                self.checks.append(
                    check(name, CONTROL_INTENT, outcome["state"], detail=outcome)
                )
                continue
            projection = outcome["document"]
            failure = control_matches(projection, expectation)
            if failure is not None:
                self.checks.append(
                    check(name, CONTROL_INTENT, "failed", reason=failure)
                )
                continue
            projections[client] = projection
            self.checks.append(check(name, CONTROL_INTENT, "passed"))
        if len(projections) == 2:
            found = disagreements(projections)
            self.checks.append(
                check(
                    "control_cross_client_agreement",
                    "the drivers agree about the control, so a live agreement is "
                    "a fact about the deployment rather than about the harness",
                    "failed" if found else "passed",
                    compared_by=comparison_scope(projections),
                    **({"disagreements": found} if found else {}),
                )
            )
        return projections

    def read_lane(self) -> dict[str, Any]:
        """Ask the deployment, with the production client, for its attention lane."""
        arguments = [
            "--endpoint",
            self.origin.rstrip("/") + PLATFORM_V2_PATH,
            "--credential-env",
            self.args.credential_env,
        ]
        return capture(
            self.repo, self.scratch / "capture-target", arguments, self.args.build_timeout
        )

    def targets(self, pages: list[str]) -> list[tuple[str, str]]:
        """Enumerate `(project, user_workspace)` pairs in the live record graph.

        This reads the decoded page; it decides nothing about attention. Which
        sources a workspace has is each client's derivation, and this harness
        never performs it.
        """
        found: list[tuple[str, str]] = []
        for page in pages:
            try:
                decoded = json.loads(base64.b64decode(page, validate=True))
            except (ValueError, binascii.Error):
                continue
            for record in decoded.get("items") or []:
                identity = record.get("identity") or {}
                if identity.get("kind") != "user_workspace":
                    continue
                workspace = identity.get("id")
                project = next(
                    (
                        relation.get("target", {}).get("id")
                        for relation in record.get("relations") or []
                        if relation.get("kind") == "user_workspace_project"
                    ),
                    None,
                )
                if isinstance(workspace, str) and isinstance(project, str):
                    found.append((project, workspace))
        return found


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    run = Run(args)
    run.prepare()
    control = run.control()

    sources = {
        "automonique": repository(run.repo),
        "shelldeck": repository(run.shelldeck),
        "mobile": repository(run.mobile),
    }

    lane_intent = (
        "the deployed entry serves the Platform v2 attention lane its clients "
        "read, so there is a live attention state for them to agree about"
    )
    live_intent_inventory = (
        "all three clients derive the same attention source inventory from the "
        "record graph the deployment serves"
    )
    live_intent_projection = (
        "all three clients agree on source, generation and item set for the "
        "attention snapshot the deployment serves"
    )
    live_intent_succession = (
        "successive live reads move the deployment's generation and all three "
        "clients converge on it, with a retention gap surfacing as an explicit "
        "resynchronization rather than a partial page"
    )
    partial_intent = (
        "no client manufactures an attention board the deployment did not "
        "authorize: when the lane does not answer, every client withholds "
        "instead of showing a partial one"
    )

    if not run.credential:
        run.checks.append(
            check(
                "operator_credential_present",
                "the reads behind the operator gate can be performed",
                "blocked",
                reason=(
                    f"no credential in ${args.credential_env}; reads behind the "
                    "gate are reported as blocked, never as passing"
                ),
            )
        )
    else:
        run.checks.append(
            check(
                "operator_credential_present",
                "the reads behind the operator gate can be performed",
                "passed",
                credential_env=args.credential_env,
            )
        )

    lane = run.read_lane()
    lane_state: dict[str, Any] = {}
    if lane["state"] != "passed":
        run.checks.append(check("live_attention_lane", lane_intent, "blocked", detail=lane))
    else:
        document = lane["document"]
        if document.get("schema") != CAPTURE_SCHEMA:
            run.checks.append(
                check(
                    "live_attention_lane",
                    lane_intent,
                    "failed",
                    reason=f"capture answered under {document.get('schema')!r}",
                )
            )
        else:
            lane_state = document.get("lane") or {}
            state = lane_state.get("state")
            run.checks.append(
                check(
                    "live_attention_lane",
                    lane_intent,
                    "passed" if state == "negotiated" else "blocked",
                    observed=
                    {
                        "state": state,
                        "category": category(lane_state.get("category")),
                        "version": lane_state.get("version"),
                    },
                    endpoint=redacted(document.get("endpoint", "")),
                    **(
                        {}
                        if state == "negotiated"
                        else {
                            "reason": (
                                "the deployment does not serve the Platform v2 "
                                "attention lane, so it serves no attention "
                                "snapshot for the clients to agree about"
                            )
                        }
                    ),
                )
            )

    hosted_read = cockpit_read(
        run.origin, None, run.credential, args.timeout, run.host_header, run.forwarded_proto
    )
    hosted: dict[str, Any] | None = None
    if hosted_read["state"] != "passed":
        run.checks.append(
            check(
                "hosted_cockpit_read",
                "the deployment's own attention reducer answers, so its live "
                "projection can be compared rather than reimplemented",
                "blocked",
                detail=hosted_read,
            )
        )
    else:
        hosted = hosted_projection(hosted_read["document"], run.salt)
        run.checks.append(
            check(
                "hosted_cockpit_read",
                "the deployment's own attention reducer answers, so its live "
                "projection can be compared rather than reimplemented",
                "passed",
                projection=hosted,
            )
        )

    negotiated = lane_state.get("state") == "negotiated"
    projections: dict[str, dict[str, Any]] = {}
    passes_recorded = 0

    if not negotiated:
        # The lane refuses. There is no live record graph, so the inventory and
        # projection comparisons have nothing to compare, and saying otherwise
        # is exactly the failure this harness exists to prevent. What *is* live,
        # and what all three clients must still agree about, is that none of
        # them shows attention it was not given.
        withheld: dict[str, Any] = {}
        empty_input = {
            "schema": REPLAY_INPUT_SCHEMA,
            "target": {"project": "unavailable", "user_workspace": "unavailable"},
            "review_presence": "absent",
            "work_context_pages_canonical_base64": [],
            "passes": [],
        }
        for client in ("shelldeck", "mobile"):
            outcome = run.replay(client, empty_input)
            if outcome["state"] != "passed":
                withheld[client] = {"state": outcome["state"], "detail": outcome}
                continue
            withheld[client] = salted_projection(outcome["document"], run.salt)
        if hosted is not None:
            withheld["hosted"] = hosted
        usable = {
            name: value
            for name, value in withheld.items()
            if isinstance(value, dict) and value.get("schema") == PROJECTION_SCHEMA
        }
        shows = sorted(
            name for name, value in usable.items() if value.get("presents_attention")
        )
        derived = sorted(
            name
            for name, value in usable.items()
            if (value.get("inventory") or {}).get("state") in ("derived", "observed")
            and (value.get("inventory") or {}).get("sources")
        )
        run.checks.append(
            check(
                "no_client_presents_a_partial_board",
                partial_intent,
                "passed" if not shows and not derived and len(usable) == len(CLIENTS) else
                ("failed" if shows or derived else "blocked"),
                clients=sorted(usable),
                clients_presenting_attention=shows,
                clients_deriving_an_inventory=derived,
                refusals={
                    name: (value.get("inventory") or {}).get("error")
                    for name, value in usable.items()
                },
                **(
                    {}
                    if len(usable) == len(CLIENTS)
                    else {"reason": "not every client could be asked"}
                ),
                target=(
                    "nominal: the deployment named no user workspace, because it "
                    "served no record graph. The record set fed to each client is "
                    "the one the deployment served, which is empty; the target is "
                    "a placeholder for a coordinate the deployment did not give."
                ),
                note=(
                    "The three clients refuse in their own vocabulary — the "
                    "hosted cockpit names the Platform v2 category, the two "
                    "replayed clients name their own inventory-derivation "
                    "refusal. What is asserted here is the behaviour, not a "
                    "shared spelling, and the spellings are recorded so the "
                    "difference is visible rather than smoothed away."
                ),
            )
        )
        for name, intent in (
            ("live_source_inventory_parity", live_intent_inventory),
            ("live_projection_parity", live_intent_projection),
            ("live_succession_parity", live_intent_succession),
        ):
            run.checks.append(
                check(
                    name,
                    intent,
                    "not_exercised",
                    reason=(
                        "the deployment refuses its Platform v2 attention lane "
                        f"({category(lane_state.get('category'))}), so it served no "
                        "attention snapshot this run could put through the clients"
                    ),
                )
            )
    else:
        work_contexts = (lane.get("document") or {}).get("work_contexts") or {}
        pages = work_contexts.get("pages_canonical_base64") or []
        found = run.targets(pages) if work_contexts.get("state") == "available" else []
        if not found:
            for name, intent in (
                ("live_source_inventory_parity", live_intent_inventory),
                ("live_projection_parity", live_intent_projection),
                ("live_succession_parity", live_intent_succession),
            ):
                run.checks.append(
                    check(
                        name,
                        intent,
                        "not_exercised",
                        reason=(
                            "the deployment's work-context graph names no user "
                            "workspace, so no client has a target to derive an "
                            "attention inventory for"
                        ),
                        work_contexts_state=work_contexts.get("state"),
                        work_contexts_category=category(work_contexts.get("category")),
                    )
                )
        else:
            project, workspace = found[0]
            review = "absent"
            probes = capture(
                run.repo,
                run.scratch / "capture-target",
                [
                    "--endpoint",
                    run.origin.rstrip("/") + PLATFORM_V2_PATH,
                    "--credential-env",
                    args.credential_env,
                    "--project",
                    project,
                    "--user-workspace",
                    workspace,
                    "--review-probe",
                ],
                args.build_timeout,
            )
            if probes["state"] == "passed":
                for entry in (probes["document"].get("review_probes") or []):
                    outcome = entry.get("review") or {}
                    if outcome.get("state") == "available":
                        review = outcome.get("presence", "absent")
            base_input = {
                "schema": REPLAY_INPUT_SCHEMA,
                "target": {"project": project, "user_workspace": workspace},
                "review_presence": review,
                "work_context_pages_canonical_base64": pages,
                "passes": [],
            }
            inventories: dict[str, list[str]] = {}
            for client in ("shelldeck", "mobile"):
                outcome = run.replay(client, base_input)
                if outcome["state"] == "passed":
                    projections[client] = outcome["document"]
                    inventories[client] = list(
                        (outcome["document"].get("inventory") or {}).get("sources") or []
                    )
            if len(inventories) < 2:
                run.checks.append(
                    check(
                        "live_source_inventory_parity",
                        live_intent_inventory,
                        "blocked",
                        reason="not every replayed client could derive an inventory",
                    )
                )
                agreed: list[str] = []
            else:
                agreed = sorted(set().union(*(set(value) for value in inventories.values())))
                same = len({tuple(sorted(value)) for value in inventories.values()}) == 1
                run.checks.append(
                    check(
                        "live_source_inventory_parity",
                        live_intent_inventory,
                        "passed" if same else "failed",
                        inventories={
                            name: sorted(
                                f"{value.split(':', 1)[0]}:{run.salt.of(value.split(':', 1)[1])}"
                                for value in entries
                            )
                            for name, entries in inventories.items()
                        },
                    )
                )
            reads = max(2, args.reads)
            passes: list[dict[str, Any]] = []
            for index in range(reads):
                if index:
                    time.sleep(max(0.0, args.interval_seconds))
                arguments = [
                    "--endpoint",
                    run.origin.rstrip("/") + PLATFORM_V2_PATH,
                    "--credential-env",
                    args.credential_env,
                    "--project",
                    project,
                    "--user-workspace",
                    workspace,
                ]
                for source in agreed:
                    arguments += ["--source", source]
                outcome = capture(
                    run.repo, run.scratch / "capture-target", arguments, args.build_timeout
                )
                if outcome["state"] != "passed":
                    continue
                entries = outcome["document"].get("sources") or []
                passes.append({"sources": entries})
            passes_recorded = len(passes)
            replay_input = dict(base_input, passes=passes)
            for client in ("shelldeck", "mobile"):
                outcome = run.replay(client, replay_input)
                if outcome["state"] == "passed":
                    projections[client] = salted_projection(outcome["document"], run.salt)
            if hosted is not None:
                projections["hosted"] = hosted
            if len(projections) < len(CLIENTS):
                run.checks.append(
                    check(
                        "live_projection_parity",
                        live_intent_projection,
                        "blocked",
                        reason="not every client produced a projection for the live read",
                        clients=sorted(projections),
                    )
                )
            else:
                found_disagreements = disagreements(projections)
                scope = comparison_scope(projections)
                compared = [
                    dimension for dimension, who in scope.items() if len(who) >= 2
                ]
                run.checks.append(
                    check(
                        "live_projection_parity",
                        live_intent_projection,
                        "failed"
                        if found_disagreements
                        else ("passed" if compared else "not_exercised"),
                        clients=sorted(projections),
                        compared_by=scope,
                        **(
                            {"disagreements": found_disagreements}
                            if found_disagreements
                            else {}
                        ),
                        **(
                            {}
                            if compared
                            else {
                                "reason": (
                                    "no dimension was expressed by two clients, so "
                                    "nothing was compared"
                                )
                            }
                        ),
                    )
                )
            signatures = {pass_signature(record["sources"]) for record in passes}
            moved = len(signatures) > 1
            run.checks.append(
                check(
                    "live_succession_parity",
                    live_intent_succession,
                    "passed" if moved and passes_recorded >= 2 else "not_exercised",
                    reads=passes_recorded,
                    distinct_generations=len(signatures),
                    **(
                        {}
                        if moved
                        else {
                            "reason": (
                                "the deployment served the same generation for "
                                "every read in this run, so no succession was "
                                "exercised and nothing about convergence was "
                                "proved. This is reported as not exercised on "
                                "purpose: a convergence check that cannot fail "
                                "is worse than an absent one."
                            )
                        }
                    ),
                )
            )

    failed = [entry["name"] for entry in run.checks if entry["state"] == "failed"]
    blocked = [entry["name"] for entry in run.checks if entry["state"] == "blocked"]
    unexercised = [entry["name"] for entry in run.checks if entry["state"] == "not_exercised"]
    control_ok = all(
        entry["state"] == "passed"
        for entry in run.checks
        if entry["name"].startswith("control_")
    ) and any(entry["name"].startswith("control_replays_through_") for entry in run.checks)

    if failed:
        state = "failed"
        reason = "clients disagreed, or a control did not reproduce: " + ", ".join(failed)
    elif not control_ok:
        state = "blocked"
        reason = (
            "the known-answer control did not run through every driver, so no "
            "live agreement reported here would be evidence of anything"
        )
    elif blocked:
        state = "blocked"
        reason = "an observation could not be made: " + ", ".join(blocked)
    elif unexercised:
        state = "partially_exercised"
        reason = (
            "every check that could run passed, but the deployment did not "
            "supply the data these needed: " + ", ".join(unexercised)
        )
    else:
        state = "complete"
        reason = "every live cross-client comparison ran and the clients agreed"

    return {
        "schema": SCHEMA,
        "mode": "live_deployment_cross_client",
        "passed": state == "complete",
        "sources": sources,
        "shelldeck_pinned_protocol": run.protocol,
        "endpoint": {
            "origin": run.origin,
            "platform_v2_path": PLATFORM_V2_PATH,
            "cockpit_path": COCKPIT_PATH,
            "credential_env": args.credential_env,
            "credential_supplied": run.credential is not None,
        },
        "reducers": {
            "shelldeck": (
                "crates/shelldeck-core/src/config/platform_attention.rs, driven by "
                "tools/parity/shelldeck_live_replay"
            ),
            "hosted": (
                "rust/crates/automonique-web-entry/src/platform_cockpit.rs, not "
                "replayed: read from the deployment running it"
            ),
            "mobile": (
                "src/core/attention-source-{board,inventory,projection}.ts, driven "
                "by tools/parity/mobile_live_replay.mjs"
            ),
        },
        "known_asymmetry": {
            "hosted_has_no_succession": (
                "The hosted cockpit reads attention fresh per request and retains "
                "nothing across requests, so it has no succession to compare. Its "
                "parity is over the projection only, and this harness compares it "
                "as such rather than inventing a history for it."
            ),
            "hosted_states_items_not_sources": (
                "The cockpit's live answer is an inbox of items, so a source it "
                "inventoried, read and found empty looks from outside exactly "
                "like a source it never had. It therefore takes part in the item "
                "and generation comparison and not in the source-inventory or "
                "per-source status comparison, which is between ShellDeck and "
                "Mobile. `compared_by` on each verdict names who took part in "
                "each dimension."
            ),
        },
        "redaction": (
            "Identifiers observed live — projects, workspaces, attention sources "
            "and items — are recorded as digests salted once per run, so equality "
            "inside this report is meaningful and no live work coordinate is "
            "written down. Refusal categories are admitted only as bare tokens. "
            f"The operator's home directory is written as {HOME_PLACEHOLDER}."
        ),
        "checks": run.checks,
        "control_projections": {
            name: salted_projection(value, run.salt) for name, value in control.items()
        },
        "operator_steps": {
            "authority": (
                "tools/run_attention_live_acceptance.py owns the checklist. This "
                "harness does not shorten it, does not sign it, and cannot "
                "satisfy any step in it. What follows names the part of each "
                "step a machine now checks against the deployment and the part "
                "that still needs a person at a screen."
            ),
            "steps": list(GUI_RESIDUE),
        },
        "live_verification": {"state": state, "reason": reason},
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = build_report(args)
    if not report["endpoint"]["credential_supplied"]:
        print(
            f"no credential in ${args.credential_env}; reads behind the operator "
            "gate are reported as blocked, never as passing",
            file=sys.stderr,
        )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
