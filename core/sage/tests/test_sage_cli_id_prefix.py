#!/usr/bin/env python3
"""Prefix-resolution tests for the raptor-sage CLI's id-taking commands.

Pre-fix ``raptor-sage list``/``backlog`` displayed memory ids truncated
to 12 characters, but ``get``, ``forget``, ``task --id``, ``link``, and
``corroborate`` passed the argument straight to the server, which 404s
on anything but the full id — the operator could not round-trip an id
from the listing back into a command. Now ``_resolve_memory_id``
prefix-matches short ids client-side against the bounded memory walk:
a unique match resolves, zero or several fail loudly, and a full-length
id passes through without a fetch.

Hermetic: a stub client stands in for the SDK; no SAGE, no docker.
"""

import importlib.machinery
import importlib.util
import os
import types
import unittest
from argparse import Namespace
from pathlib import Path

os.environ.setdefault("_RAPTOR_TRUSTED", "1")

REPO_ROOT = Path(__file__).resolve().parents[3]
CLI = REPO_ROOT / "libexec" / "raptor-sage"

FULL_A = "05cbeb35-718d-414a-89da-70ef3bf1adf2"
FULL_B = "05cbeb35-9999-414a-89da-70ef3bf1adf2"
FULL_C = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _load_cli():
    spec = importlib.util.spec_from_file_location(
        "raptor_sage_cli", CLI,
        loader=importlib.machinery.SourceFileLoader(
            "raptor_sage_cli", str(CLI)),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cli = _load_cli()


class StubClient:
    """Serves one page of stub memories; records id-taking calls."""

    def __init__(self, ids, fail_on_list=False):
        self._ids = ids
        self.fail_on_list = fail_on_list
        self.calls = []

    def list_memories(self, limit=200, offset=0):
        assert not self.fail_on_list, "unexpected memory walk"
        memories = [
            types.SimpleNamespace(memory_id=i) for i in self._ids
        ][offset:offset + limit]
        return types.SimpleNamespace(memories=memories,
                                     total=len(self._ids))

    def get_memory(self, memory_id):
        self.calls.append(("get", memory_id))
        return types.SimpleNamespace(
            memory_id=memory_id, domain_tag="methodology",
            status="committed", confidence_score=0.8,
            memory_type="fact", content="x", created_at="", tags=[],
        )

    def forget(self, memory_id, reason=None):
        self.calls.append(("forget", memory_id))

    def update_task_status(self, memory_id, status):
        self.calls.append(("task", memory_id, status))

    def corroborate(self, memory_id, evidence=None):
        self.calls.append(("corroborate", memory_id))

    def link_memories(self, source, target, link_type="related"):
        self.calls.append(("link", source, target))


class TestResolveMemoryId(unittest.TestCase):
    def test_full_id_skips_the_walk(self):
        client = StubClient([], fail_on_list=True)
        self.assertEqual(
            cli._resolve_memory_id(client, FULL_A), FULL_A)

    def test_unique_prefix_resolves(self):
        client = StubClient([FULL_A, FULL_C])
        self.assertEqual(
            cli._resolve_memory_id(client, FULL_A[:12]), FULL_A)

    def test_ambiguous_prefix_fails_loudly(self):
        client = StubClient([FULL_A, FULL_B])
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            cli._resolve_memory_id(client, "05cbeb35")

    def test_unknown_prefix_fails_loudly(self):
        client = StubClient([FULL_A])
        with self.assertRaisesRegex(ValueError, "no memory id"):
            cli._resolve_memory_id(client, "deadbeef")


class TestCommandsRoundTripTruncatedIds(unittest.TestCase):
    """Each id-taking command must hand the SERVER the full id."""

    def setUp(self):
        self.client = StubClient([FULL_A, FULL_C])

    def test_get(self):
        rc = cli.cmd_get(self.client, Namespace(memory_id=FULL_A[:12]))
        self.assertEqual(rc, 0)
        self.assertIn(("get", FULL_A), self.client.calls)

    def test_task_update(self):
        rc = cli.cmd_task(self.client, Namespace(
            content=[], id=FULL_A[:12], task_status="done", domain=None))
        self.assertEqual(rc, 0)
        self.assertIn(("task", FULL_A, "done"), self.client.calls)

    def test_forget(self):
        rc = cli.cmd_forget(self.client, Namespace(
            memory_id=FULL_A[:12], reason=None))
        self.assertEqual(rc, 0)
        self.assertIn(("forget", FULL_A), self.client.calls)

    def test_corroborate(self):
        rc = cli.cmd_corroborate(self.client, Namespace(
            memory_id=FULL_A[:12], evidence=None))
        self.assertEqual(rc, 0)
        self.assertIn(("corroborate", FULL_A), self.client.calls)

    def test_link_resolves_both_ends(self):
        rc = cli.cmd_link(self.client, Namespace(
            source=FULL_A[:12], target=FULL_C[:12], link_type=None))
        self.assertEqual(rc, 0)
        self.assertIn(("link", FULL_A, FULL_C), self.client.calls)

    def test_ambiguous_id_is_an_error_not_a_guess(self):
        client = StubClient([FULL_A, FULL_B])
        rc = cli.cmd_forget(client, Namespace(
            memory_id="05cbeb35", reason=None))
        self.assertEqual(rc, 1)
        self.assertFalse(
            [c for c in client.calls if c[0] == "forget"],
            "server must not be called with an ambiguous id")


if __name__ == "__main__":
    unittest.main()
