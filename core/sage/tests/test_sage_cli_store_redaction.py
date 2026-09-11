#!/usr/bin/env python3
"""CLI store-path hardening.

* ``remember`` / ``task`` route content through ``redact_secrets``
  before embed+propose — a pasted token was otherwise committed
  durably to the consensus store with PUBLIC classification (the
  mechanical hooks in core/sage/hooks.py always redacted; the operator
  CLI did not).
* ``recall --min-confidence 0`` is an explicit "no floor" and must
  reach the server (falsy-zero used to drop it).
* ``_resolve_memory_id`` tolerates rows whose ``memory_id`` is None
  (the fetch walk keeps them; ``.startswith`` on None used to
  AttributeError every prefix command).
"""

import contextlib
import importlib.util
import io
import os
import sys
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[3]

_cli = None
_SDK_MODULES = ("sage_sdk", "sage_sdk.models", "sage_sdk.client",
                "sage_sdk.auth")
_saved_sdk_modules: dict[str, object] = {}


def setUpModule():
    global _cli
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    # sage_sdk is an optional dependency the CLI must tolerate missing
    # when a client is injected (the cmd_remember/cmd_task guard).
    # Poison it out of sys.modules so the sdk-absent path is exercised
    # deterministically — on a box where the sdk happens to be
    # installed, and on a runner where it never was.
    for name in _SDK_MODULES:
        _saved_sdk_modules[name] = sys.modules.pop(name, None)
        sys.modules[name] = None  # import raises ImportError
    loader = SourceFileLoader(
        "raptor_sage_cli_store_redaction",
        str(REPO_ROOT / "libexec" / "raptor-sage"),
    )
    spec = importlib.util.spec_from_loader(
        "raptor_sage_cli_store_redaction", loader,
    )
    _cli = importlib.util.module_from_spec(spec)
    loader.exec_module(_cli)


def tearDownModule():
    for name in _SDK_MODULES:
        saved = _saved_sdk_modules.pop(name, None)
        if saved is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = saved


class _RecordingClient:
    def __init__(self):
        self.proposed = []
        self.embedded = []
        self.queries = []

    def embed(self, text):
        self.embedded.append(text)
        return [0.0]

    def propose(self, **kwargs):
        self.proposed.append(kwargs)
        return SimpleNamespace(memory_id="m-1")

    def query(self, **kwargs):
        self.queries.append(kwargs)
        return SimpleNamespace(results=[])

    def get_memory(self, memory_id):
        return SimpleNamespace(memory_id=memory_id, domain_tag="general")


_SECRET = "ghp_" + "a" * 36


class TestStoreRedaction(unittest.TestCase):
    def test_remember_redacts_before_store_and_embed(self):
        client = _RecordingClient()
        args = SimpleNamespace(
            content=["deploy", "note", _SECRET],
            domain=None, type=None, confidence=None, tags=None,
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = _cli.cmd_remember(client, args)
        self.assertEqual(rc, 0)
        stored = client.proposed[0]["content"]
        self.assertNotIn(_SECRET, stored)
        self.assertIn("[REDACTED]", stored)
        # The embedding reflects what was stored.
        self.assertEqual(client.embedded, [stored])

    def test_remember_plain_content_stored_verbatim(self):
        client = _RecordingClient()
        args = SimpleNamespace(
            content=["ordinary", "observation"],
            domain=None, type=None, confidence=None, tags=None,
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(_cli.cmd_remember(client, args), 0)
        self.assertEqual(client.proposed[0]["content"],
                         "ordinary observation")

    def test_task_redacts_before_store(self):
        client = _RecordingClient()
        args = SimpleNamespace(
            content=["rotate", _SECRET], domain=None, id=None,
            task_status=None,
        )
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            _cli.cmd_task(client, args)
        stored = client.proposed[0]["content"]
        self.assertNotIn(_SECRET, stored)
        self.assertIn("[REDACTED]", stored)


class TestRecallMinConfidenceZero(unittest.TestCase):
    def test_zero_floor_reaches_server(self):
        client = _RecordingClient()
        args = SimpleNamespace(
            query=["anything"], domain=None, top=None, min_confidence=0.0,
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(_cli.cmd_recall(client, args), 0)
        self.assertEqual(client.queries[0].get("min_confidence"), 0.0)

    def test_unset_floor_omitted(self):
        client = _RecordingClient()
        args = SimpleNamespace(
            query=["anything"], domain=None, top=None, min_confidence=None,
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(_cli.cmd_recall(client, args), 0)
        self.assertNotIn("min_confidence", client.queries[0])


class TestResolveMemoryIdNoneTolerance(unittest.TestCase):
    def test_none_memory_id_rows_are_skipped(self):
        class _Client:
            def list_memories(self, limit, offset):
                rows = [
                    SimpleNamespace(memory_id=None),
                    SimpleNamespace(memory_id="abc123def456-full-id"),
                ] if offset == 0 else []
                return SimpleNamespace(
                    memories=rows, total=2, has_more=False)

        resolved = _cli._resolve_memory_id(_Client(), "abc123")
        self.assertEqual(resolved, "abc123def456-full-id")


if __name__ == "__main__":
    unittest.main()
