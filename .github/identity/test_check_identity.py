#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

"""Break every identity rule on purpose, and watch the named refusal appear.

A rule that has never refused anything is a rule nobody has tested. Each
negative control below has a positive control beside it, and the fixtures build
real Git repositories with real author and committer identities rather than
restating the constants `check_identity.py` uses — the one exception is the
`PROVENANCE.md` sentence, which is written out here by hand precisely so that
the checker and the test are two independent statements of it, with
`test_repository_passes` binding both to the hand-written document in the tree.

    python3 -m unittest discover -s .github/identity -p 'test_*.py'
"""

from __future__ import annotations

import copy
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import check_identity  # noqa: E402

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

CANDIDATE = ("Automonique Candidate", "candidate@automonique.invalid")
OUTSIDER = ("Bootstrap Owner", "bootstrap@automonique.invalid")

GOVERNANCE_TEXT = """# Governance

## Roles

- **Implementer:** changes only leased paths.
- **Merger:** performs one compare-and-swap integration.

## Something else

Not a role list.
"""

# Written by hand, not derived from `check_identity.provenance_sentence`, so
# that the two agree only when both are right. `test_repository_passes` checks
# the same format against the real `PROVENANCE.md`.
PROVENANCE_SHARED = (
    "**Declared state.** Identity separation: not claimed. "
    "Commit signing: not enabled. "
    "Identities of record: `.github/identity/register.toml`."
)
PROVENANCE_SEPARATED = (
    "**Declared state.** Identity separation: claimed. "
    "Commit signing: enabled (ssh). "
    "Identities of record: `.github/identity/register.toml`."
)

EVIDENCE_HONEST = {"item": "FIX-001", "review": {"reviewers": 0}}


def scalar(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return "[" + ", ".join(scalar(entry) for entry in value) + "]"
    return json.dumps(value)


def toml_text(document: dict) -> str:
    lines = ["# SPDX-License-Identifier: Elastic-2.0"]
    for key, value in document.items():
        if key in ("identity", "historical_exception"):
            # An array of tables has no empty spelling, so an empty one is
            # written as an ordinary empty array — still the same TOML key.
            if not value:
                lines.append(f"{key} = []")
            continue
        lines.append(f"{key} = {scalar(value)}")
    for table in ("identity", "historical_exception"):
        for entry in document.get(table, []):
            lines.append("")
            lines.append(f"[[{table}]]")
            for key, value in entry.items():
                lines.append(f"{key} = {scalar(value)}")
    return "\n".join(lines) + "\n"


class Checkout:
    """A throwaway repository with exactly the commits a test needs."""

    def __init__(self, root: pathlib.Path) -> None:
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        self.environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(root),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        self._git("init", "--quiet")
        self._git("symbolic-ref", "HEAD", "refs/heads/main")
        self._clock = 0

    def _git(self, *arguments: str, environment: dict | None = None) -> str:
        merged = dict(self.environment)
        merged.update(environment or {})
        result = subprocess.run(
            ["git", "-C", str(self.root), "-c", "commit.gpgsign=false", *arguments],
            capture_output=True, text=True, env=merged, check=True,
        )
        return result.stdout.strip()

    def commit(self, subject: str, identity: tuple[str, str] = CANDIDATE,
               body: str = "") -> str:
        self._clock += 1
        stamp = f"16000000{self._clock:02d} +0000"
        name, email = identity
        message = f"{subject}\n\n{body}" if body else subject
        self._git(
            "commit", "--allow-empty", "--quiet", "-m", message,
            environment={
                "GIT_AUTHOR_NAME": name, "GIT_AUTHOR_EMAIL": email,
                "GIT_COMMITTER_NAME": name, "GIT_COMMITTER_EMAIL": email,
                "GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp,
            },
        )
        return self._git("rev-parse", "HEAD")

    def write(self, relative: str, text: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def register(self, document: dict) -> None:
        self.write(check_identity.REGISTER, toml_text(document))

    def run(self) -> tuple[list[str], dict]:
        return check_identity.run(self.root)


class IdentityCheckTest(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.tmp = pathlib.Path(self._temporary.name)

    # -- fixtures ----------------------------------------------------------

    def make(self, *, first_identity: tuple[str, str] = CANDIDATE,
             trailer: str = "") -> tuple[Checkout, dict, list[str]]:
        checkout = Checkout(self.tmp / "checkout")
        shas = [
            checkout.commit("First", identity=first_identity, body=trailer),
            checkout.commit("Second"),
            checkout.commit("Third"),
        ]
        checkout.write(check_identity.GOVERNANCE, GOVERNANCE_TEXT)
        checkout.write(
            check_identity.PROVENANCE,
            f"# Provenance\n\n## Repository identity\n\n{PROVENANCE_SHARED}\n",
        )
        checkout.write(
            f"{check_identity.EVIDENCE}/FIX-001.json",
            json.dumps(EVIDENCE_HONEST, indent=2) + "\n",
        )
        document = {
            "schema": check_identity.SCHEMA,
            "separation_claimed": False,
            "rule_effective_commit": shas[1],
            "signing_effective_commit": "",
            "identity": [{
                "id": "candidate",
                "name": CANDIDATE[0],
                "email": CANDIDATE[1],
                "roles": ["implementer", "merger"],
                "separation": "shared",
                "signing": "none",
                "fingerprint": "",
                "commits": True,
            }],
            "historical_exception": [],
        }
        checkout.register(document)
        return checkout, document, shas

    # -- helpers -----------------------------------------------------------

    def assert_passes(self, checkout: Checkout) -> None:
        refusals, _ = checkout.run()
        self.assertEqual(refusals, [])

    def assert_refuses(self, checkout: Checkout, fragment: str) -> list[str]:
        refusals, _ = checkout.run()
        self.assertTrue(
            any(fragment in message for message in refusals),
            f"expected a refusal containing {fragment!r}, got {refusals!r}",
        )
        return refusals

    # -- the tree as it stands --------------------------------------------

    def test_repository_passes(self):
        """The positive control that is not a fixture: the real repository."""
        refusals, counts = check_identity.run(REPO_ROOT)
        self.assertEqual(refusals, [])
        self.assertGreater(counts["commits"], 0)
        self.assertGreater(counts["evidence_files"], 0)

    def test_baseline_fixture_passes(self):
        checkout, _, _ = self.make()
        self.assert_passes(checkout)

    # -- the register vocabulary ------------------------------------------

    def test_unknown_top_level_key_is_refused(self):
        checkout, document, _ = self.make()
        document["separation_is_fine_honestly"] = True
        checkout.register(document)
        self.assert_refuses(checkout, "unknown top-level key")

    def test_missing_top_level_key_is_refused(self):
        checkout, document, _ = self.make()
        del document["signing_effective_commit"]
        checkout.register(document)
        self.assert_refuses(checkout, "missing required key")

    def test_unknown_identity_key_is_refused(self):
        checkout, document, _ = self.make()
        document["identity"][0]["trusted"] = True
        checkout.register(document)
        self.assert_refuses(checkout, "has unknown key(s): trusted")

    def test_unknown_separation_value_is_refused(self):
        checkout, document, _ = self.make()
        document["identity"][0]["separation"] = "mostly-separate"
        checkout.register(document)
        self.assert_refuses(checkout, "the closed set is shared, dedicated")

    def test_unknown_signing_value_is_refused(self):
        checkout, document, _ = self.make()
        document["identity"][0]["signing"] = "vibes"
        checkout.register(document)
        self.assert_refuses(checkout, "the closed set is none, ssh, gpg")

    def test_exception_without_a_reason_is_refused(self):
        checkout, document, shas = self.make()
        document["historical_exception"] = [{"commit": shas[0], "reason": "old"}]
        checkout.register(document)
        self.assert_refuses(checkout, "needs a reason")

    # -- declared separation ----------------------------------------------

    def test_separation_claimed_while_one_identity_does_everything(self):
        checkout, document, _ = self.make()
        document["separation_claimed"] = True
        checkout.register(document)
        self.assert_refuses(checkout, "identity separation is not achieved")

    def test_two_dedicated_identities_sharing_a_fingerprint(self):
        checkout, document, shas = self.make()
        checkout.write(
            check_identity.PROVENANCE,
            f"# Provenance\n\n## Repository identity\n\n{PROVENANCE_SEPARATED}\n",
        )
        document["separation_claimed"] = True
        document["signing_effective_commit"] = shas[0]
        document["identity"] = [
            dict(id="implementer", name=CANDIDATE[0], email=CANDIDATE[1],
                 roles=["implementer"], separation="dedicated", signing="ssh",
                 fingerprint="SHA256:oneandonlycredential", commits=True),
            dict(id="merger", name="Automonique Merger",
                 email="merger@automonique.invalid", roles=["merger"],
                 separation="dedicated", signing="ssh",
                 fingerprint="SHA256:oneandonlycredential", commits=True),
        ]
        checkout.register(document)
        self.assert_refuses(checkout, "share one fingerprint; they are one credential")

    def test_two_dedicated_identities_with_distinct_fingerprints(self):
        """The positive control for the test above: a real separation claim."""
        checkout, document, shas = self.make()
        checkout.write(
            check_identity.PROVENANCE,
            f"# Provenance\n\n## Repository identity\n\n{PROVENANCE_SEPARATED}\n",
        )
        document["separation_claimed"] = True
        document["signing_effective_commit"] = shas[0]
        document["identity"] = [
            dict(id="implementer", name=CANDIDATE[0], email=CANDIDATE[1],
                 roles=["implementer"], separation="dedicated", signing="ssh",
                 fingerprint="SHA256:implementercredential", commits=True),
            dict(id="merger", name="Automonique Merger",
                 email="merger@automonique.invalid", roles=["merger"],
                 separation="dedicated", signing="ssh",
                 fingerprint="SHA256:mergercredentialxxxxx", commits=False),
        ]
        checkout.register(document)
        refusals, _ = checkout.run()
        # The only outstanding refusals are the unverifiable signatures, which
        # is the honest state of a repository whose commits are not signed.
        self.assertTrue(all("verify-commit" in message for message in refusals),
                        refusals)

    def test_dedicated_identity_that_signs_nothing(self):
        checkout, document, _ = self.make()
        document["identity"][0]["separation"] = "dedicated"
        document["identity"][0]["roles"] = ["implementer"]
        document["identity"].append(
            dict(id="merger", name="Automonique Merger",
                 email="merger@automonique.invalid", roles=["merger"],
                 separation="shared", signing="none", fingerprint="",
                 commits=False))
        checkout.register(document)
        self.assert_refuses(checkout, "declared dedicated but signs nothing")

    def test_two_identities_sharing_one_address(self):
        checkout, document, _ = self.make()
        document["identity"][0]["roles"] = ["implementer"]
        document["identity"].append(
            dict(id="merger", name="Automonique Merger", email=CANDIDATE[1],
                 roles=["merger"], separation="shared", signing="none",
                 fingerprint="", commits=True))
        checkout.register(document)
        self.assert_refuses(checkout, "two labels on one credential are one identity")

    # -- roles, taken from GOVERNANCE.md ----------------------------------

    def test_governance_role_assigned_to_nobody(self):
        checkout, document, _ = self.make()
        document["identity"][0]["roles"] = ["implementer"]
        checkout.register(document)
        self.assert_refuses(checkout, "role 'merger' is defined in GOVERNANCE.md")

    def test_role_governance_does_not_define(self):
        checkout, document, _ = self.make()
        document["identity"][0]["roles"] = ["implementer", "merger", "auditor"]
        checkout.register(document)
        self.assert_refuses(checkout, "claims role 'auditor'")

    def test_role_assigned_twice(self):
        checkout, document, _ = self.make()
        document["identity"].append(
            dict(id="second", name="Automonique Merger",
                 email="merger@automonique.invalid", roles=["merger"],
                 separation="shared", signing="none", fingerprint="",
                 commits=False))
        checkout.register(document)
        self.assert_refuses(checkout, "a role has exactly one identity")

    def test_a_new_governance_role_fails_until_it_is_assigned(self):
        checkout, _, _ = self.make()
        checkout.write(
            check_identity.GOVERNANCE,
            GOVERNANCE_TEXT.replace(
                "- **Merger:**",
                "- **Auditor:** reads the record.\n- **Merger:**"),
        )
        self.assert_refuses(checkout, "role 'auditor' is defined in GOVERNANCE.md")

    # -- what Git records --------------------------------------------------

    def test_commit_by_an_unregistered_identity(self):
        checkout, _, _ = self.make(first_identity=OUTSIDER)
        refusals = self.assert_refuses(checkout, "authored by an identity")
        self.assertTrue(any("committed by an identity" in m for m in refusals))

    def test_the_same_commit_excused_by_a_pinned_exception(self):
        """The positive control: an out-of-scope historical fact, recorded."""
        checkout, document, shas = self.make(first_identity=OUTSIDER)
        document["historical_exception"] = [{
            "commit": shas[0],
            "reason": "predates the rule; rewriting history is out of scope",
        }]
        checkout.register(document)
        self.assert_passes(checkout)

    def test_a_stale_exception_is_refused(self):
        checkout, document, shas = self.make()
        document["historical_exception"] = [{
            "commit": shas[0],
            "reason": "predates the rule; rewriting history is out of scope",
        }]
        checkout.register(document)
        self.assert_refuses(checkout, "is stale: the commit now uses a registered")

    def test_an_exception_cannot_reach_past_the_rule(self):
        checkout, document, shas = self.make()
        document["historical_exception"] = [{
            "commit": shas[2],
            "reason": "predates the rule; rewriting history is out of scope",
        }]
        checkout.register(document)
        self.assert_refuses(checkout, "the rule was already in force")

    def test_an_exception_for_a_commit_that_is_not_there(self):
        checkout, document, _ = self.make()
        document["historical_exception"] = [{
            "commit": "0" * 40,
            "reason": "predates the rule; rewriting history is out of scope",
        }]
        checkout.register(document)
        self.assert_refuses(checkout, "is not reachable from HEAD")

    def test_an_attribution_trailer_is_refused(self):
        checkout, _, _ = self.make(trailer="Co-Authored-By: Some Assistant <a@b.co>")
        self.assert_refuses(checkout, "carries an attribution trailer")

    def test_a_message_that_merely_mentions_regeneration_is_fine(self):
        """The rule is line-anchored on the trailer, not a substring hunt."""
        checkout, _, _ = self.make(trailer="Regenerated with plan/generate.py")
        self.assert_passes(checkout)

    # -- signatures --------------------------------------------------------

    def test_declared_signing_over_unsigned_commits(self):
        checkout, document, shas = self.make()
        document["signing_effective_commit"] = shas[1]
        document["identity"][0]["signing"] = "ssh"
        document["identity"][0]["fingerprint"] = "SHA256:acredentialnobodyhas"
        checkout.register(document)
        self.assert_refuses(checkout, "`git verify-commit` does not accept it")

    def test_declared_signing_without_an_effective_commit(self):
        checkout, document, _ = self.make()
        document["identity"][0]["signing"] = "ssh"
        document["identity"][0]["fingerprint"] = "SHA256:acredentialnobodyhas"
        checkout.register(document)
        self.assert_refuses(checkout, "no signing_effective_commit")

    def test_a_signed_commit_under_a_no_signing_declaration(self):
        """Under-claiming is drift too.

        Exercised at the function boundary: producing a genuinely signed commit
        needs a key this environment does not have, so the commit record is
        synthesised. The rule under test is the comparison, not Git's signing.
        """
        checkout, document, _ = self.make()
        register = {**document, "identity": list(document["identity"])}
        refusals: list[str] = []
        check_identity.check_signing(
            checkout.root, register,
            [{"sha": "a" * 40, "author": f"{CANDIDATE[0]} <{CANDIDATE[1]}>",
              "committer": f"{CANDIDATE[0]} <{CANDIDATE[1]}>",
              "signature": "G", "message": "Signed"}],
            refusals.append,
        )
        self.assertTrue(any("understates the achieved state" in m for m in refusals),
                        refusals)

    def test_unsigned_commits_under_a_no_signing_declaration(self):
        """The positive control beside it, run against real commit records."""
        checkout, document, _ = self.make()
        refusals: list[str] = []
        counts = check_identity.check_signing(
            checkout.root, document, check_identity.read_commits(checkout.root),
            refusals.append,
        )
        self.assertEqual(refusals, [])
        self.assertEqual(counts["signature_required"], 0)

    # -- PROVENANCE.md -----------------------------------------------------

    def test_provenance_that_has_gone_stale(self):
        checkout, document, _ = self.make()
        document["separation_claimed"] = True
        document["identity"][0]["roles"] = ["implementer"]
        document["identity"][0]["separation"] = "dedicated"
        document["identity"][0]["signing"] = "ssh"
        document["identity"][0]["fingerprint"] = "SHA256:acredentialnobodyhas"
        document["identity"].append(
            dict(id="merger", name="Automonique Merger",
                 email="merger@automonique.invalid", roles=["merger"],
                 separation="dedicated", signing="ssh",
                 fingerprint="SHA256:anothercredentialxx", commits=False))
        checkout.register(document)
        self.assert_refuses(checkout, "does not match .github/identity/register.toml")

    def test_provenance_without_the_section(self):
        checkout, _, _ = self.make()
        checkout.write(check_identity.PROVENANCE, "# Provenance\n\nNothing here.\n")
        self.assert_refuses(checkout, "has no '## Repository identity' section")

    def test_provenance_may_be_wrapped(self):
        checkout, _, _ = self.make()
        wrapped = PROVENANCE_SHARED.replace("Identity separation:",
                                            "Identity\nseparation:")
        checkout.write(
            check_identity.PROVENANCE,
            f"# Provenance\n\n## Repository identity\n\n{wrapped}\n",
        )
        self.assert_passes(checkout)

    # -- evidence ----------------------------------------------------------

    def test_independence_claimed_with_zero_reviewers(self):
        checkout, _, _ = self.make()
        checkout.write(
            f"{check_identity.EVIDENCE}/FIX-002.json",
            json.dumps({"item": "FIX-002",
                        "review": {"reviewers": 0, "independent": True}}) + "\n",
        )
        self.assert_refuses(checkout, "records zero reviewers but sets")

    def test_independence_denied_with_zero_reviewers(self):
        """The positive control: the shape the honest evidence in this tree uses."""
        checkout, _, _ = self.make()
        checkout.write(
            f"{check_identity.EVIDENCE}/FIX-002.json",
            json.dumps({"item": "FIX-002", "review": {"reviewers": 0},
                        "adversarial_review": {"independent": False}}) + "\n",
        )
        self.assert_passes(checkout)

    def test_more_independent_reviewers_than_reviewers(self):
        checkout, _, _ = self.make()
        checkout.write(
            f"{check_identity.EVIDENCE}/FIX-002.json",
            json.dumps({"item": "FIX-002",
                        "review": {"reviewers": 1, "independent_reviewers": 2}}) + "\n",
        )
        self.assert_refuses(checkout, "independent reviewer(s) out of")

    def test_evidence_without_a_review_record(self):
        checkout, _, _ = self.make()
        checkout.write(f"{check_identity.EVIDENCE}/FIX-002.json",
                       json.dumps({"item": "FIX-002"}) + "\n")
        self.assert_refuses(checkout, "has no review record")

    # -- refusing to guess -------------------------------------------------

    def test_a_shallow_checkout_is_unrunnable_not_a_pass(self):
        checkout, _, _ = self.make()
        shallow = self.tmp / "shallow"
        subprocess.run(
            ["git", "clone", "--quiet", "--depth", "1",
             f"file://{checkout.root}", str(shallow)],
            capture_output=True, text=True, check=True, env=checkout.environment,
        )
        for relative in (check_identity.REGISTER, check_identity.GOVERNANCE,
                         check_identity.PROVENANCE):
            target = shallow / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text((checkout.root / relative).read_text())
        with self.assertRaises(check_identity.Unrunnable) as caught:
            check_identity.run(shallow)
        self.assertIn("shallow", str(caught.exception))

    def test_a_missing_register_is_unrunnable_not_a_pass(self):
        checkout, _, _ = self.make()
        (checkout.root / check_identity.REGISTER).unlink()
        with self.assertRaises(check_identity.Unrunnable):
            checkout.run()
        self.assertEqual(check_identity.main(["--root", str(checkout.root)]), 2)

    def test_exit_codes(self):
        checkout, document, _ = self.make()
        self.assertEqual(check_identity.main(["--root", str(checkout.root)]), 0)
        document["separation_claimed"] = True
        checkout.register(document)
        self.assertEqual(check_identity.main(["--root", str(checkout.root)]), 1)


if __name__ == "__main__":
    unittest.main()
