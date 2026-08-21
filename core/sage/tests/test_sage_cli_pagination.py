#!/usr/bin/env python3
"""Bounded-pagination tests for the raptor-sage operator CLI.

``_fetch_all_memories`` walks the store with ``total`` re-read from
every response. Nothing authenticates the server on this plain-HTTP
transport, so a hostile process bound to the SAGE port must not be
able to loop the CLI to OOM by inflating ``total`` or streaming
endless pages.
"""

import contextlib
import importlib.util
import io
import os
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[3]

_cli = None


def setUpModule():
    global _cli
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    loader = SourceFileLoader(
        "raptor_sage_cli_pagination",
        str(REPO_ROOT / "libexec" / "raptor-sage"),
    )
    spec = importlib.util.spec_from_loader(
        "raptor_sage_cli_pagination", loader,
    )
    _cli = importlib.util.module_from_spec(spec)
    loader.exec_module(_cli)


class _PagedClient:
    """Scriptable list_memories server."""

    def __init__(self, pages):
        # pages: list of (memories, total) tuples, replayed in order;
        # the last entry repeats forever.
        self._pages = pages
        self.calls = 0

    def list_memories(self, limit, offset):
        page = self._pages[min(self.calls, len(self._pages) - 1)]
        self.calls += 1
        memories, total = page
        return SimpleNamespace(memories=list(memories), total=total)


def _mem(i):
    return SimpleNamespace(memory_id=str(i), content=f"m{i}")


class TestBoundedPagination(unittest.TestCase):
    def test_normal_two_page_fetch(self):
        client = _PagedClient([
            ([_mem(i) for i in range(200)], 300),
            ([_mem(i) for i in range(200, 300)], 300),
        ])
        mems, total = _cli._fetch_all_memories(client)
        self.assertEqual(len(mems), 300)
        self.assertEqual(total, 300)
        self.assertEqual(client.calls, 2)

    def test_total_above_cap_is_protocol_error(self):
        client = _PagedClient([
            ([_mem(0)], _cli._FETCH_MAX_ROWS + 1),
        ])
        with self.assertRaisesRegex(RuntimeError, "protocol error"):
            _cli._fetch_all_memories(client)
        self.assertEqual(client.calls, 1)

    def test_total_changing_between_pages_is_protocol_error(self):
        client = _PagedClient([
            ([_mem(i) for i in range(200)], 400),
            ([_mem(i) for i in range(200, 400)], 600),
        ])
        with self.assertRaisesRegex(RuntimeError, "total changed"):
            _cli._fetch_all_memories(client)

    def test_endless_pages_hit_row_cap_with_notice(self):
        # Server always claims there is more (total == cap) and keeps
        # producing full pages — the walk must stop at the row cap.
        page = ([_mem(i) for i in range(200)], _cli._FETCH_MAX_ROWS)
        client = _PagedClient([page])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            mems, _total = _cli._fetch_all_memories(client)
        self.assertEqual(len(mems), _cli._FETCH_MAX_ROWS)
        self.assertIn("truncated", err.getvalue())
        self.assertLessEqual(client.calls, _cli._FETCH_MAX_PAGES)

    def test_page_cap_bounds_tiny_pages(self):
        # One row per page with a constant huge (but under-cap) total:
        # the page cap must end the walk long before the row cap fills.
        page = ([_mem(0)], _cli._FETCH_MAX_ROWS)
        client = _PagedClient([page])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            mems, _total = _cli._fetch_all_memories(client)
        self.assertEqual(client.calls, _cli._FETCH_MAX_PAGES)
        self.assertEqual(len(mems), _cli._FETCH_MAX_PAGES)
        self.assertIn("truncated", err.getvalue())

    def test_missing_total_breaks_after_first_page(self):
        class NoTotal:
            def __init__(self):
                self.calls = 0

            def list_memories(self, limit, offset):
                self.calls += 1
                return SimpleNamespace(memories=[_mem(offset)], total=None)

        client = NoTotal()
        mems, total = _cli._fetch_all_memories(client)
        self.assertEqual(client.calls, 1)
        self.assertEqual(total, 1)
        self.assertEqual(len(mems), 1)

    def test_empty_first_page(self):
        client = _PagedClient([([], 0)])
        mems, total = _cli._fetch_all_memories(client)
        self.assertEqual(mems, [])
        self.assertEqual(total, 0)


if __name__ == "__main__":
    unittest.main()
