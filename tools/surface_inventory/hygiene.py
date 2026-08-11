#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Refuse a private identifier or secret-shaped value in the surface inventory.

`AGENTS.md` forbids committing credentials, real infrastructure identifiers,
personal email addresses and absolute home paths. `tools/scrub/scan.py` enforces
that for the whole candidate against fingerprinted known values; this enforces
it for one inventory against *shapes*, which is the half a fingerprint list
cannot do — it does not need to have seen the value before.

A finding names the rule, the JSON path and the matched span's shape. It never
prints the matched text, because printing it would put the value in a log that
is itself checked in.
"""

from __future__ import annotations

import re
from typing import Any, Callable

# Reserved, non-routable namespaces (RFC 2606 / RFC 6761) plus the file
# suffixes that make a repository-relative path look like a host name.
RESERVED_LABELS = frozenset({"invalid", "example", "test", "localhost"})
FILE_SUFFIXES = frozenset({
    "md", "json", "jsonl", "py", "rs", "toml", "yaml", "yml", "txt", "sh",
    "lock", "sql", "ts", "tsx", "cfg", "ini", "log",
})

EMAIL = re.compile(r"\b[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,24})\b")
HOSTLIKE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+([a-z]{2,24})\b(?![-.])")
HOME_PATH = re.compile(r"(?:/home/|/users/|/root/|(?:^|\s)~/)[a-z0-9._-]+")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

SECRET_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("pem-block", re.compile(r"-----BEGIN [A-Z ]+-----")),
    ("bearer-token", re.compile(r"\bBearer\s+[A-Za-z0-9._-]{10,}")),
    ("json-web-token", re.compile(r"\beyJ[A-Za-z0-9_-]{12,}")),
    ("assigned-secret", re.compile(
        r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?key|token)"
        r"\s*[:=]\s*\S")),
    ("high-entropy-run", re.compile(
        r"(?=[A-Za-z0-9+/]{28,})(?=[A-Za-z0-9+/]*[A-Z])(?=[A-Za-z0-9+/]*[a-z])"
        r"(?=[A-Za-z0-9+/]*[0-9])[A-Za-z0-9+/]{28,}={0,2}")),
)


def _reserved_domain(domain: str) -> bool:
    return domain.rsplit(".", 1)[-1] in RESERVED_LABELS


def scan_text(text: str, where: str) -> list[str]:
    """Findings for one string. The value itself is never echoed back."""
    findings: list[str] = []
    lowered = text.lower()

    for domain in EMAIL.findall(lowered):
        if not _reserved_domain(domain):
            findings.append(
                f"{where}: an email address outside a reserved non-routable "
                f"domain — a personal address never enters this repository, and a "
                f"placeholder belongs in .invalid or .example")

    for match in HOSTLIKE.finditer(lowered):
        suffix = match.group(1)
        # Only the reserved namespaces and the file suffixes that make a
        # repository-relative path look like a host are allowed. There is
        # deliberately no "it was preceded by a slash, so it is a path" escape:
        # that rule would wave through every host name inside a URL.
        if suffix in RESERVED_LABELS or suffix in FILE_SUFFIXES:
            continue
        findings.append(
            f"{where}: a host-shaped name ending .{suffix} — a real host name is "
            f"a private infrastructure identifier; record its shape instead")

    if HOME_PATH.search(lowered):
        findings.append(
            f"{where}: an absolute home path — record the shape "
            f"(absolute-filesystem-path) and its absence, not the path")

    if IPV4.search(lowered):
        findings.append(
            f"{where}: an IPv4 literal — a network address is a private "
            f"infrastructure identifier")

    for name, pattern in SECRET_MARKERS:
        if pattern.search(text):
            findings.append(
                f"{where}: matches the {name} shape — this inventory records "
                f"credential class, owner, rotation and storage class only, never "
                f"a value")
    return findings


def scan_strings(pairs: list[tuple[str, str]]) -> list[str]:
    findings: list[str] = []
    for where, text in pairs:
        findings.extend(scan_text(text, where))
    return findings


def scan_document(document: Any, walker: Callable[[Any], list[tuple[str, str]]]) -> list[str]:
    return scan_strings(walker(document))
