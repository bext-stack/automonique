#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Refuse an identity claim that Git does not support.

`AGENTS.md` § Git authority says every commit is authored *and* committed as
the candidate identity, and `plan/gates.md#gate-identity` says a gate is never
closed by an unsupported assertion. Between those two sentences sat nothing
mechanical: the repository had already published three commits under the wrong
identity before anyone read the log
(`plan/owner-decisions/2026-08-10-candidate-identity-rewrite.md`).

This is the repository-side half of `BOOT-002`. It compares three declarations
against three producers:

    .github/identity/register.toml   vs   the commit objects Git actually holds
    the register's role list        vs   GOVERNANCE.md § Roles
    the register's achieved state   vs   PROVENANCE.md § Repository identity

and it refuses `plan/evidence/*.json` that claims independent review it did not
have. It cannot see branch protection, credentials or a trust root — those are
external administrative facts, enumerated as an owner checklist in
`plan/gates.md#gate-identity` and deliberately not claimed here.

    python3 .github/identity/check_identity.py
    python3 .github/identity/check_identity.py --root /path/to/checkout

Exit code is 0 when every declaration is backed, 1 when one is not, and 2 when
the checker cannot run at all (no register, not a Git checkout, shallow
history). Wiring this into `plan/check.py` is the integrator's follow-up; it is
standalone and importable so that it can be wired without being rewritten.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import tomllib

SCHEMA = "automonique.identity-register/v1"

REGISTER = ".github/identity/register.toml"
GOVERNANCE = "GOVERNANCE.md"
PROVENANCE = "PROVENANCE.md"
EVIDENCE = "plan/evidence"

TOP_LEVEL_KEYS = {
    "schema",
    "separation_claimed",
    "rule_effective_commit",
    "signing_effective_commit",
    "identity",
    "historical_exception",
}
IDENTITY_KEYS = {
    "id", "name", "email", "roles", "separation", "signing", "fingerprint",
    "commits",
}
EXCEPTION_KEYS = {"commit", "reason"}

SEPARATION = ("shared", "dedicated")
SIGNING = ("none", "ssh", "gpg")

OID = re.compile(r"^[0-9a-f]{40}$")
IDENTITY_ID = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
EMAIL = re.compile(r"^[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+$")
FINGERPRINT = re.compile(r"^[A-Za-z0-9+/=:_.-]{8,128}$")

# The roles GOVERNANCE.md § Roles defines, read from that document rather than
# copied here. A fixture that restates the constant it is checking proves the
# implementation equals itself; this reads the real producer.
ROLE_SECTION = re.compile(r"^##+ Roles\s*$(.*?)(?=^##+ |\Z)", re.M | re.S)
ROLE_ENTRY = re.compile(r"^- \*\*([A-Z][A-Za-z ]*):\*\*", re.M)

PROVENANCE_SECTION = re.compile(
    r"^##+ Repository identity\s*$(.*?)(?=^##+ |\Z)", re.M | re.S)

# The one commit-message form this repository has actually carried and had
# rewritten. It is line-anchored and exact on purpose: a substring rule such as
# "generated with" would reject the legitimate message "Regenerated with
# plan/generate.py", and a check that blocks honest work gets deleted.
FORBIDDEN_TRAILER_PREFIX = "co-authored-by:"

# A truthy value under any of these keys is a claim of independent review.
# `plan/doctrine.md` allows self-review and requires that it never be labelled
# independent, so the claim is only refused when the reviewer count is zero.
INDEPENDENCE_KEYS = (
    "independent",
    "independent_review",
    "independently_reviewed",
    "independent_reviewers",
)

FIELD = "\x1f"
RECORD = "\x1e"


class Unrunnable(Exception):
    """The checker cannot measure anything, which is not the same as a pass."""


def git(root: pathlib.Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        raise Unrunnable(
            f"git {' '.join(args[:2])} failed: {detail[0] if detail else 'unknown error'}")
    return result.stdout


def git_ok(root: pathlib.Path, *args: str) -> bool:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True, text=True, check=False,
    ).returncode == 0


# --------------------------------------------------------------------------
# The register: a closed vocabulary, refused at parse


def load_register(root: pathlib.Path, refuse) -> dict | None:
    path = root / REGISTER
    if not path.is_file():
        raise Unrunnable(f"no identity register at {REGISTER}")
    try:
        with path.open("rb") as handle:
            register = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise Unrunnable(f"{REGISTER} cannot be read: {exc}") from exc

    if register.get("schema") != SCHEMA:
        refuse(f"{REGISTER} schema is {register.get('schema')!r}, expected {SCHEMA!r}")
        return None

    unknown = sorted(set(register) - TOP_LEVEL_KEYS)
    if unknown:
        refuse(f"{REGISTER} has unknown top-level key(s): {', '.join(unknown)} — "
               f"the key set is fixed, so a new claim is a change to the checker")
        return None
    missing = sorted(TOP_LEVEL_KEYS - set(register))
    if missing:
        refuse(f"{REGISTER} is missing required key(s): {', '.join(missing)}")
        return None

    if not isinstance(register["separation_claimed"], bool):
        refuse(f"{REGISTER} separation_claimed must be true or false")
        return None
    for key in ("rule_effective_commit",):
        if not isinstance(register[key], str) or not OID.fullmatch(register[key]):
            refuse(f"{REGISTER} {key} must be a full 40-hex commit ID")
            return None
    signing_from = register["signing_effective_commit"]
    if not isinstance(signing_from, str) or (signing_from and not OID.fullmatch(signing_from)):
        refuse(f"{REGISTER} signing_effective_commit must be a full 40-hex commit "
               f"ID, or empty when signing is not enabled")
        return None

    if not isinstance(register["identity"], list) or not register["identity"]:
        refuse(f"{REGISTER} declares no identity")
        return None
    if not isinstance(register["historical_exception"], list):
        refuse(f"{REGISTER} historical_exception must be a list")
        return None

    ok = True
    for index, identity in enumerate(register["identity"]):
        if not check_identity_entry(identity, index, refuse):
            ok = False
    for index, exception in enumerate(register["historical_exception"]):
        if not check_exception_entry(exception, index, refuse):
            ok = False
    return register if ok else None


def check_identity_entry(identity: dict, index: int, refuse) -> bool:
    label = f"{REGISTER} identity[{index}]"
    if not isinstance(identity, dict):
        refuse(f"{label} is not a table")
        return False
    unknown = sorted(set(identity) - IDENTITY_KEYS)
    if unknown:
        refuse(f"{label} has unknown key(s): {', '.join(unknown)}")
        return False
    missing = sorted(IDENTITY_KEYS - set(identity))
    if missing:
        refuse(f"{label} is missing key(s): {', '.join(missing)}")
        return False

    ok = True
    if not isinstance(identity["id"], str) or not IDENTITY_ID.fullmatch(identity["id"]):
        refuse(f"{label} id must be lowercase and dash-separated")
        ok = False
    if not isinstance(identity["name"], str) or not identity["name"].strip():
        refuse(f"{label} name must be a non-empty string")
        ok = False
    if not isinstance(identity["email"], str) or not EMAIL.fullmatch(identity["email"]):
        refuse(f"{label} email is not an address")
        ok = False
    if identity["separation"] not in SEPARATION:
        refuse(f"{label} separation is {identity['separation']!r}; "
               f"the closed set is {', '.join(SEPARATION)}")
        ok = False
    if identity["signing"] not in SIGNING:
        refuse(f"{label} signing is {identity['signing']!r}; "
               f"the closed set is {', '.join(SIGNING)}")
        ok = False
    if not isinstance(identity["commits"], bool):
        refuse(f"{label} commits must be true or false")
        ok = False
    if not isinstance(identity["roles"], list) or not identity["roles"] or not all(
        isinstance(role, str) and role for role in identity["roles"]
    ):
        refuse(f"{label} roles must be a non-empty list of role names")
        ok = False
    elif len(set(identity["roles"])) != len(identity["roles"]):
        refuse(f"{label} lists a role twice")
        ok = False
    if not isinstance(identity["fingerprint"], str):
        refuse(f"{label} fingerprint must be a string")
        ok = False
    return ok


def check_exception_entry(exception: dict, index: int, refuse) -> bool:
    label = f"{REGISTER} historical_exception[{index}]"
    if not isinstance(exception, dict):
        refuse(f"{label} is not a table")
        return False
    unknown = sorted(set(exception) - EXCEPTION_KEYS)
    if unknown:
        refuse(f"{label} has unknown key(s): {', '.join(unknown)}")
        return False
    missing = sorted(EXCEPTION_KEYS - set(exception))
    if missing:
        refuse(f"{label} is missing key(s): {', '.join(missing)}")
        return False
    ok = True
    if not isinstance(exception["commit"], str) or not OID.fullmatch(exception["commit"]):
        refuse(f"{label} commit must be a full 40-hex commit ID")
        ok = False
    if not isinstance(exception["reason"], str) or len(exception["reason"].strip()) < 16:
        refuse(f"{label} needs a reason saying why the commit is not being fixed")
        ok = False
    return ok


# --------------------------------------------------------------------------
# Declared separation


def governance_roles(root: pathlib.Path, refuse) -> set[str]:
    path = root / GOVERNANCE
    if not path.is_file():
        refuse(f"{GOVERNANCE} is missing, so the role vocabulary has no source")
        return set()
    section = ROLE_SECTION.search(path.read_text())
    if not section:
        refuse(f"{GOVERNANCE} has no '## Roles' section to take the role "
               f"vocabulary from")
        return set()
    roles = {name.strip().lower() for name in ROLE_ENTRY.findall(section.group(1))}
    if not roles:
        refuse(f"{GOVERNANCE} § Roles defines no role, so the register would be "
               f"checked against nothing")
    return roles


def check_roles(register: dict, roles: set[str], refuse) -> None:
    seen: dict[str, str] = {}
    for identity in register["identity"]:
        for role in identity["roles"]:
            if role not in roles:
                refuse(f"identity {identity['id']!r} claims role {role!r}, which "
                       f"{GOVERNANCE} § Roles does not define")
            elif role in seen:
                refuse(f"role {role!r} is assigned to both {seen[role]!r} and "
                       f"{identity['id']!r}; a role has exactly one identity")
            else:
                seen[role] = identity["id"]
    for role in sorted(roles - set(seen)):
        refuse(f"role {role!r} is defined in {GOVERNANCE} § Roles but assigned to "
               f"no identity in {REGISTER}")


def check_separation(register: dict, refuse) -> None:
    identities = register["identity"]
    by_email: dict[str, str] = {}
    by_fingerprint: dict[str, str] = {}

    for identity in identities:
        email = identity["email"]
        if email in by_email:
            refuse(f"identities {by_email[email]!r} and {identity['id']!r} share "
                   f"one address; two labels on one credential are one identity")
        else:
            by_email[email] = identity["id"]

        dedicated = identity["separation"] == "dedicated"
        fingerprint = identity["fingerprint"]
        if dedicated:
            if len(identity["roles"]) != 1:
                refuse(f"identity {identity['id']!r} is declared dedicated but "
                       f"performs {len(identity['roles'])} roles; a dedicated "
                       f"workload identity performs one")
            if identity["signing"] == "none":
                refuse(f"identity {identity['id']!r} is declared dedicated but "
                       f"signs nothing, so nothing distinguishes it from any "
                       f"other identity in the commit record")
            if not FINGERPRINT.fullmatch(fingerprint):
                refuse(f"identity {identity['id']!r} is declared dedicated but has "
                       f"no credential fingerprint")
            elif fingerprint in by_fingerprint:
                refuse(f"identities {by_fingerprint[fingerprint]!r} and "
                       f"{identity['id']!r} are both declared dedicated and share "
                       f"one fingerprint; they are one credential")
            else:
                by_fingerprint[fingerprint] = identity["id"]
        else:
            if identity["signing"] == "none" and fingerprint:
                refuse(f"identity {identity['id']!r} signs nothing but carries a "
                       f"fingerprint")
            if identity["signing"] != "none" and not FINGERPRINT.fullmatch(fingerprint):
                refuse(f"identity {identity['id']!r} declares signing "
                       f"{identity['signing']!r} with no fingerprint to verify "
                       f"against")

    if register["separation_claimed"]:
        shared = [i["id"] for i in identities if i["separation"] != "dedicated"]
        if shared:
            refuse("separation_claimed is true, but these identities are not "
                   "dedicated: " + ", ".join(sorted(shared))
                   + " — identity separation is not achieved")

    if not any(identity["commits"] for identity in identities):
        refuse(f"{REGISTER} declares no identity that may commit, so every commit "
               f"in the history is unattributable")


# --------------------------------------------------------------------------
# What Git actually records


def read_commits(root: pathlib.Path) -> list[dict]:
    fmt = FIELD.join(["%H", "%an", "%ae", "%cn", "%ce", "%G?", "%B"]) + RECORD
    out = git(root, "log", f"--format={fmt}", "HEAD")
    commits = []
    for record in out.split(RECORD):
        record = record.strip("\n")
        if not record.strip():
            continue
        parts = record.split(FIELD)
        if len(parts) != 7:
            raise Unrunnable("cannot parse the commit log")
        commits.append({
            "sha": parts[0],
            "author": f"{parts[1]} <{parts[2]}>",
            "committer": f"{parts[3]} <{parts[4]}>",
            "signature": parts[5],
            "message": parts[6],
        })
    return commits


def check_commits(root: pathlib.Path, register: dict, commits: list[dict],
                  refuse) -> dict[str, int]:
    allowed = {f"{i['name']} <{i['email']}>" for i in register["identity"]
               if i["commits"]}
    present = {commit["sha"] for commit in commits}

    rule = register["rule_effective_commit"]
    if rule not in present and not git_ok(root, "merge-base", "--is-ancestor", rule, "HEAD"):
        refuse(f"rule_effective_commit {rule[:8]} is not an ancestor of HEAD, so "
               f"the exceptions below are anchored to nothing")
        excused: set[str] = set()
    else:
        excused = check_exceptions(root, register, commits, allowed, refuse)

    wrong_identity = 0
    wrong_trailer = 0
    for commit in commits:
        if commit["sha"] not in excused:
            if commit["author"] not in allowed:
                wrong_identity += 1
                refuse(f"commit {commit['sha'][:8]} is authored by an identity "
                       f"{REGISTER} does not list; register it, or record it as a "
                       f"historical_exception with a reason")
            if commit["committer"] not in allowed:
                wrong_identity += 1
                refuse(f"commit {commit['sha'][:8]} is committed by an identity "
                       f"{REGISTER} does not list")
        for line in commit["message"].splitlines():
            if line.strip().lower().startswith(FORBIDDEN_TRAILER_PREFIX):
                wrong_trailer += 1
                refuse(f"commit {commit['sha'][:8]} carries an attribution "
                       f"trailer; AGENTS.md § Git authority allows none")
                break
    return {
        "commits": len(commits),
        "excused": len(excused),
        "wrong_identity": wrong_identity,
        "wrong_trailer": wrong_trailer,
    }


def check_exceptions(root: pathlib.Path, register: dict, commits: list[dict],
                     allowed: set[str], refuse) -> set[str]:
    """Pinned, exhaustive and self-expiring.

    An exception must name a commit that exists, still violates the rule, and
    predates the rule. The last condition is what stops the list from becoming
    a place to hide new mistakes: excusing a fresh commit would also require
    moving `rule_effective_commit`, which is a far louder edit.
    """
    by_sha = {commit["sha"]: commit for commit in commits}
    rule = register["rule_effective_commit"]
    excused: set[str] = set()
    seen: set[str] = set()

    for exception in register["historical_exception"]:
        sha = exception["commit"]
        if sha in seen:
            refuse(f"historical_exception names {sha[:8]} twice")
            continue
        seen.add(sha)
        commit = by_sha.get(sha)
        if commit is None:
            refuse(f"historical_exception {sha[:8]} is not reachable from HEAD; "
                   f"a rewritten or dropped commit leaves a stale exception")
            continue
        if not git_ok(root, "merge-base", "--is-ancestor", sha, rule):
            refuse(f"historical_exception {sha[:8]} is not an ancestor of "
                   f"rule_effective_commit {rule[:8]}, so the rule was already in "
                   f"force when it was made")
            continue
        if commit["author"] in allowed and commit["committer"] in allowed:
            refuse(f"historical_exception {sha[:8]} is stale: the commit now uses "
                   f"a registered identity. Remove the exception.")
            continue
        excused.add(sha)
    return excused


def check_signing(root: pathlib.Path, register: dict, commits: list[dict],
                  refuse) -> dict[str, int]:
    """A signing claim is verified; a claim of no signing is verified too.

    Under-claiming is still drift. The register is the record of the achieved
    state, so a signed commit under `signing = "none"` is a refusal in the same
    way an unsigned commit under `signing = "ssh"` is.
    """
    signers = {f"{i['name']} <{i['email']}>": i for i in register["identity"]
               if i["signing"] != "none"}
    signing_from = register["signing_effective_commit"]
    verified = 0

    if not signers:
        if signing_from:
            refuse(f"{REGISTER} names a signing_effective_commit but no identity "
                   f"signs anything")
        signed = [c["sha"][:8] for c in commits if c["signature"] != "N"]
        if signed:
            refuse(f"{len(signed)} commit(s) carry a signature while every identity "
                   f"declares signing = \"none\": " + ", ".join(sorted(signed)[:6])
                   + " — the register understates the achieved state")
        return {"signature_required": 0, "signature_verified": 0}

    if not signing_from:
        refuse(f"{REGISTER} declares a signing identity but no "
               f"signing_effective_commit, so nothing says which commits must "
               f"verify")
        return {"signature_required": 0, "signature_verified": 0}
    if not git_ok(root, "merge-base", "--is-ancestor", signing_from, "HEAD"):
        refuse(f"signing_effective_commit {signing_from[:8]} is not an ancestor of "
               f"HEAD")
        return {"signature_required": 0, "signature_verified": 0}

    after = {sha for sha in git(root, "rev-list", f"{signing_from}..HEAD").split()}
    after.add(signing_from)
    required = [c for c in commits if c["sha"] in after and c["author"] in signers]
    for commit in required:
        if git_ok(root, "verify-commit", commit["sha"]):
            verified += 1
        else:
            refuse(f"commit {commit['sha'][:8]} is authored by a signing identity "
                   f"but `git verify-commit` does not accept it")
    return {"signature_required": len(required), "signature_verified": verified}


# --------------------------------------------------------------------------
# The two documents that describe the achieved state


def provenance_sentence(register: dict) -> str:
    """The one line PROVENANCE.md must carry, derived from the register."""
    separation = "claimed" if register["separation_claimed"] else "not claimed"
    modes = sorted({i["signing"] for i in register["identity"]} - {"none"})
    signing = "not enabled" if not modes else "enabled (" + ", ".join(modes) + ")"
    return (f"**Declared state.** Identity separation: {separation}. "
            f"Commit signing: {signing}. "
            f"Identities of record: `{REGISTER}`.")


def check_provenance(root: pathlib.Path, register: dict, refuse) -> None:
    """The document must state the register's claim, wrapped however it likes.

    Comparison is on whitespace-collapsed text so that the paragraph can be
    hard-wrapped like every other paragraph in the file; a rule that forbade
    wrapping would be a rule about formatting rather than about truth.
    """
    path = root / PROVENANCE
    expected = provenance_sentence(register)
    if not path.is_file():
        refuse(f"{PROVENANCE} is missing")
        return
    section = PROVENANCE_SECTION.search(path.read_text())
    if not section:
        refuse(f"{PROVENANCE} has no '## Repository identity' section")
        return
    body = " ".join(section.group(1).split())
    if expected not in body:
        marker = "**Declared state.**"
        stale = body[body.index(marker):body.index(marker) + len(expected)] + "…" \
            if marker in body else ""
        detail = f"it says: {stale}" if stale else "it carries no declared state"
        refuse(f"{PROVENANCE} § Repository identity does not match {REGISTER}; "
               f"{detail}\n         expected: {expected}")


def check_evidence(root: pathlib.Path, refuse) -> dict[str, int]:
    directory = root / EVIDENCE
    if not directory.is_dir():
        return {"evidence_files": 0}
    files = sorted(directory.glob("*.json"))
    for path in files:
        label = path.relative_to(root).as_posix()
        try:
            document = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            refuse(f"{label} is not readable JSON: {exc}")
            continue
        if not isinstance(document, dict):
            refuse(f"{label} is not a JSON object")
            continue
        review = document.get("review")
        if not isinstance(review, dict):
            refuse(f"{label} has no review record")
            continue
        reviewers = review.get("reviewers")
        if not isinstance(reviewers, int) or isinstance(reviewers, bool) or reviewers < 0:
            refuse(f"{label} review.reviewers must be a non-negative integer")
            continue
        independent = review.get("independent_reviewers")
        if isinstance(independent, int) and not isinstance(independent, bool) \
                and independent > reviewers:
            refuse(f"{label} claims {independent} independent reviewer(s) out of "
                   f"{reviewers} reviewer(s)")
        if reviewers == 0:
            for key, value in independence_claims(document):
                refuse(f"{label} records zero reviewers but sets {key!r} to "
                       f"{value!r}; doctrine allows self-review and forbids "
                       f"labelling it independent")
    return {"evidence_files": len(files)}


def independence_claims(node, key: str | None = None):
    """Every truthy independence key anywhere in an evidence document."""
    if isinstance(node, dict):
        for name, value in node.items():
            yield from independence_claims(value, name)
    elif isinstance(node, list):
        for value in node:
            yield from independence_claims(value, key)
    elif key in INDEPENDENCE_KEYS and node:
        yield key, node


# --------------------------------------------------------------------------


def run(root: pathlib.Path) -> tuple[list[str], dict[str, int]]:
    refusals: list[str] = []
    counts: dict[str, int] = {}

    def refuse(message: str) -> None:
        refusals.append(message)

    if not (root / ".git").exists():
        raise Unrunnable(f"{root} is not a Git checkout, so no commit identity "
                         f"can be measured")
    if git(root, "rev-parse", "--is-shallow-repository").strip() != "false":
        raise Unrunnable("history is shallow; a truncated log cannot show that "
                         "every commit conforms")

    register = load_register(root, refuse)
    counts.update(check_evidence(root, refuse))
    if register is None:
        return refusals, counts

    counts["identities"] = len(register["identity"])
    counts["exceptions"] = len(register["historical_exception"])
    check_roles(register, governance_roles(root, refuse), refuse)
    check_separation(register, refuse)
    check_provenance(root, register, refuse)

    commits = read_commits(root)
    counts.update(check_commits(root, register, commits, refuse))
    counts.update(check_signing(root, register, commits, refuse))
    return refusals, counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=None,
                        help="repository checkout to inspect (default: this one)")
    args = parser.parse_args(argv)
    root = pathlib.Path(args.root).resolve() if args.root \
        else pathlib.Path(__file__).resolve().parents[2]

    try:
        refusals, counts = run(root)
    except Unrunnable as exc:
        print(f"UNRUNNABLE: {exc}", file=sys.stderr)
        return 2

    for message in refusals:
        print(f"FAIL: {message}", file=sys.stderr)
    if refusals:
        print(f"\n{len(refusals)} identity claim(s) unsupported", file=sys.stderr)
        return 1

    print("ok — " + ", ".join(f"{key} {value}" for key, value in counts.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
