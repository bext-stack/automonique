#!/usr/bin/env python3
# SPDX-License-Identifier: Elastic-2.0

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest

from tools.worktree_allocator import AllocationError, AllocationRequest, WorktreeAllocator


def git(repository: pathlib.Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments], cwd=repository, capture_output=True, text=True, check=True
    )
    return completed.stdout.strip()


class WorktreeAllocatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        git(self.repository, "init", "-b", "main")
        git(self.repository, "config", "user.name", "Synthetic Fixture")
        git(self.repository, "config", "user.email", "fixture@example.invalid")
        (self.repository / "tracked.txt").write_text("fixture\n", encoding="utf-8")
        git(self.repository, "add", "tracked.txt")
        git(self.repository, "commit", "-m", "synthetic base")
        self.base = git(self.repository, "rev-parse", "HEAD")
        self.state = self.root / "state"
        self.allocator = WorktreeAllocator(self.repository, self.state)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def request(self, **changes: object) -> AllocationRequest:
        values = {
            "run_id": "run-001",
            "expected_base": self.base,
            "max_materialized_bytes": 4096,
        }
        values.update(changes)
        return AllocationRequest(**values)

    def test_allocate_restart_and_release_are_idempotent(self) -> None:
        request = self.request()
        first = self.allocator.allocate(request)
        checkout = self.state / "worktrees" / request.run_id / "checkout"
        self.assertEqual(self.base, git(checkout, "rev-parse", "HEAD"))
        self.assertEqual("", git(checkout, "branch", "--show-current"))
        restarted = WorktreeAllocator(self.repository, self.state)
        self.assertEqual(first, restarted.allocate(request))
        released = restarted.release(request)
        self.assertEqual("released", released["status"])
        self.assertFalse(checkout.exists())
        self.assertEqual(released, restarted.release(request))

    def test_intent_only_restart_reconciles_once(self) -> None:
        request = self.request()
        operation, intent, _receipt = self.allocator._paths(request.run_id)
        operation.mkdir(parents=True)
        digest = hashlib.sha256(
            json.dumps(request.document(), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        intent.write_text(
            json.dumps(
                {
                    "schema": "automonique.worktree-allocation/v1",
                    "status": "intent",
                    "request": request.document(),
                    "request_sha256": digest,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.assertEqual("allocated", self.allocator.allocate(request)["status"])

    def test_dirty_worktree_blocks_release_and_replay(self) -> None:
        request = self.request()
        self.allocator.allocate(request)
        checkout = self.state / "worktrees" / request.run_id / "checkout"
        (checkout / "tracked.txt").write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(AllocationError, "immutable base"):
            self.allocator.allocate(request)
        with self.assertRaisesRegex(AllocationError, "immutable base"):
            self.allocator.release(request)

    def test_release_reconciles_after_worktree_removal(self) -> None:
        request = self.request()
        self.allocator.allocate(request)
        checkout = self.state / "worktrees" / request.run_id / "checkout"
        self.allocator._git("worktree", "remove", str(checkout))
        self.assertEqual("released", self.allocator.release(request)["status"])

    def test_budget_and_invalid_coordinates_fail_before_allocation(self) -> None:
        with self.assertRaisesRegex(AllocationError, "budget"):
            self.allocator.allocate(self.request(max_materialized_bytes=1))
        with self.assertRaisesRegex(AllocationError, "run ID"):
            self.allocator.allocate(self.request(run_id="../escape"))
        self.assertFalse((self.state / "worktrees" / "escape").exists())

    def test_external_content_filter_and_submodule_fail_closed(self) -> None:
        (self.repository / ".gitattributes").write_text("*.txt filter=fixture\n", encoding="utf-8")
        git(self.repository, "add", ".gitattributes")
        git(self.repository, "commit", "-m", "synthetic filter")
        filtered = git(self.repository, "rev-parse", "HEAD")
        with self.assertRaisesRegex(AllocationError, "content filter"):
            self.allocator.allocate(self.request(expected_base=filtered))

    def test_symlink_state_root_is_rejected(self) -> None:
        target = self.root / "state-target"
        target.mkdir()
        link = self.root / "state-link"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(AllocationError, "symlink"):
            WorktreeAllocator(self.repository, link)
        with self.assertRaisesRegex(AllocationError, "symlink"):
            WorktreeAllocator(self.repository, link / "nested")


if __name__ == "__main__":
    unittest.main()
