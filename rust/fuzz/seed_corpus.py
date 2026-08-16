#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Re-derive the checked-in fuzz corpora from the protocol's golden fixtures.

The corpora under `corpus/` are checked in, so this script is not on any build
path: it exists so a reviewer can confirm the seeds came from the fixtures
rather than from someone's imagination, and so adding a fixture is one command
away from adding a seed.

A fuzzer's corpus is a set of starting points, not a set of expectations. Both
accepted and refused fixtures are seeded: a refusal fixture is a byte string
that reaches deep into a decoder before being turned away, which is exactly the
neighbourhood worth mutating.

Run from anywhere:

    python3 rust/fuzz/seed_corpus.py

Files already present with the same contents are left alone, so the script is
idempotent and a re-run produces no diff.
"""

from __future__ import annotations

import json
import pathlib
import sys


FUZZ_ROOT = pathlib.Path(__file__).resolve().parent
FIXTURES = FUZZ_ROOT.parent / "crates" / "automonique-protocol" / "fixtures"

# Seeds are starting points, and libFuzzer mutates length as readily as content,
# so a multi-megabyte seed buys nothing a small one does not and costs every
# reviewer who clones the repository. The ceiling fixtures that exceed this are
# covered by the property suite instead, which can generate them on demand.
MAX_SEED_BYTES = 8 * 1024

# Hex-valued keys that hold a complete decoder input. Every fixture file uses
# one of these three spellings for "the bytes the decoder is handed".
PAYLOAD_KEYS = ("bytes_hex", "canonical_hex", "payload_hex")


def segments_to_bytes(segments: list[dict]) -> bytes:
    """Expand the fixture files' run-length segment encoding."""
    out = bytearray()
    for segment in segments:
        if "literal_hex" in segment:
            out += bytes.fromhex(segment["literal_hex"])
        elif "repeat_hex" in segment:
            out += bytes.fromhex(segment["repeat_hex"]) * segment["count"]
        else:
            raise ValueError(f"unrecognised segment: {segment!r}")
    return bytes(out)


def walk_payloads(node: object, path: str = "") -> list[tuple[str, bytes]]:
    """Collect every hex-encoded decoder input in a fixture document."""
    found: list[tuple[str, bytes]] = []
    if isinstance(node, dict):
        identifier = node.get("id")
        for key in PAYLOAD_KEYS:
            if isinstance(node.get(key), str):
                name = identifier if isinstance(identifier, str) else path
                found.append((name, bytes.fromhex(node[key])))
        for key, value in node.items():
            found += walk_payloads(value, f"{path}-{key}" if path else str(key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found += walk_payloads(value, f"{path}-{index}")
    return found


def wire_fixtures() -> dict[str, list[tuple[str, bytes]]]:
    """Seeds derived from `wire-v1.json`, split by which decoder they feed."""
    document = json.loads((FIXTURES / "wire-v1.json").read_text(encoding="utf-8"))
    envelope_ids = set(document["envelope_ids"])

    canonical: list[tuple[str, bytes]] = []
    envelopes: list[tuple[str, bytes]] = []
    for fixture in document["fixtures"]:
        payload = bytes.fromhex(fixture["bytes_hex"])
        canonical.append((fixture["id"], payload))
        if fixture["id"] in envelope_ids:
            envelopes.append((fixture["id"], payload))
    for fixture in document["generated_fixtures"]:
        canonical.append((fixture["id"], segments_to_bytes(fixture["segments"])))

    frames: list[tuple[str, bytes]] = []
    for fixture in document["frame_fixtures"]:
        frames.append((fixture["id"], segments_to_bytes(fixture["input"])))
    # A frame whose payload is a real envelope, so the fuzzer starts from an
    # input where unframing succeeds and the next decoder gets real work.
    for identifier, payload in envelopes:
        framed = len(payload).to_bytes(4, "big") + payload
        frames.append((f"framed-{identifier}", framed))

    return {
        "automonique_fuzz_parse_canonical": canonical,
        "automonique_fuzz_envelope_decode": envelopes,
        "automonique_fuzz_decode_frame": frames,
    }


def api_fixtures() -> list[tuple[str, bytes]]:
    """Seeds from the five per-API fixture files, which are all canonical JSON."""
    seeds: list[tuple[str, bytes]] = []
    for path in sorted(FIXTURES.glob("*-v1.json")):
        if path.name == "wire-v1.json":
            continue
        document = json.loads(path.read_text(encoding="utf-8"))
        for identifier, payload in walk_payloads(document):
            seeds.append((f"{path.stem}-{identifier}", payload))
    return seeds


# Synthetic seeds for the two platform-inbound parsers. The protocol fixtures
# do not cover them: those parsers face a vendor's JSON, not this project's
# wire, and the shapes below are transcribed from the published response schemas
# with every value replaced by an obvious placeholder.
TELEGRAM_SEEDS: dict[str, str] = {
    "empty-batch": '{"ok":true,"result":[]}',
    "message": (
        '{"ok":true,"result":[{"update_id":1,"message":{"message_id":2,'
        '"date":1,"chat":{"id":-100,"type":"group"},"from":{"id":7,'
        '"is_bot":false},"text":"placeholder"}}]}'
    ),
    "edited-message": (
        '{"ok":true,"result":[{"update_id":2,"edited_message":{"message_id":3,'
        '"date":1,"chat":{"id":-100,"type":"group"},"from":{"id":7,'
        '"is_bot":false},"text":"placeholder"}}]}'
    ),
    "callback": (
        '{"ok":true,"result":[{"update_id":3,"callback_query":{"id":"4",'
        '"from":{"id":7,"is_bot":false},"data":"placeholder"}}]}'
    ),
    "attachment": (
        '{"ok":true,"result":[{"update_id":4,"message":{"message_id":5,'
        '"date":1,"chat":{"id":-100,"type":"group"},"from":{"id":7,'
        '"is_bot":false},"caption":"placeholder","document":{"file_id":"f"}}}]}'
    ),
    "error": '{"ok":false,"error_code":401,"description":"placeholder"}',
    "unknown-update": '{"ok":true,"result":[{"update_id":5,"poll":{"id":"6"}}]}',
}

SLACK_SEEDS: dict[str, str] = {
    "auth-test": (
        '{"ok":true,"user_id":"U000000","team_id":"T000000","bot_id":"B000000",'
        '"url":"https://example.invalid/"}'
    ),
    "error": '{"ok":false,"error":"placeholder_error"}',
    "connections-open": '{"ok":true,"url":"wss://example.invalid/link"}',
    "conversations-list": (
        '{"ok":true,"channels":[{"id":"C000000","name":"placeholder",'
        '"is_channel":true,"is_private":false}],'
        '"response_metadata":{"next_cursor":""}}'
    ),
    "conversations-info": (
        '{"ok":true,"channel":{"id":"C000000","name":"placeholder",'
        '"is_channel":true,"is_private":false}}'
    ),
    "conversations-history": (
        '{"ok":true,"messages":[{"ts":"0.0","user":"U000000",'
        '"text":"placeholder"}],"has_more":false}'
    ),
    "users-info": (
        '{"ok":true,"user":{"id":"U000000","name":"placeholder",'
        '"is_bot":false,"deleted":false}}'
    ),
    "post-message": (
        '{"ok":true,"channel":"C000000","ts":"0.0",'
        '"message":{"text":"placeholder"}}'
    ),
    "ack": '{"ok":true}',
}


def write_corpus(target: str, seeds: list[tuple[str, bytes]]) -> tuple[int, int]:
    """Write one target's corpus, returning (written, skipped-as-oversized)."""
    directory = FUZZ_ROOT / "corpus" / target
    directory.mkdir(parents=True, exist_ok=True)

    seen: set[bytes] = set()
    written = 0
    oversized = 0
    for identifier, payload in seeds:
        if len(payload) > MAX_SEED_BYTES:
            oversized += 1
            continue
        if payload in seen:
            continue
        seen.add(payload)
        path = directory / f"{identifier}.bin"
        if not path.exists() or path.read_bytes() != payload:
            path.write_bytes(payload)
        written += 1
    return written, oversized


def main() -> int:
    corpora = wire_fixtures()
    # The per-API fixtures are message-shaped canonical JSON, so they belong to
    # the envelope decoder. They are *also* valid input to `parse_canonical`,
    # which every one of them runs through — but checking them in twice would
    # double the corpus for no extra coverage. `README.md` documents passing
    # both directories when fuzzing the canonical parser.
    corpora["automonique_fuzz_envelope_decode"] += api_fixtures()
    corpora["automonique_fuzz_telegram_updates"] = [
        (name, body.encode("utf-8")) for name, body in TELEGRAM_SEEDS.items()
    ]
    corpora["automonique_fuzz_slack_decode"] = [
        (name, body.encode("utf-8")) for name, body in SLACK_SEEDS.items()
    ]

    for target in sorted(corpora):
        written, oversized = write_corpus(target, corpora[target])
        note = f", {oversized} over {MAX_SEED_BYTES} bytes skipped" if oversized else ""
        print(f"{target}: {written} seeds{note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
