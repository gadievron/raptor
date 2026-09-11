#!/usr/bin/env python3
"""Error-reporting and hostile-row rendering paths of the raptor-sage CLI.

Two behaviours pinned here:

* ``status`` failure lines go to stderr like every sibling command
  (a script consuming status stdout must never ingest the error line
  as data), and the wording stays neutral — ``_fetch_all_memories``
  raises for protocol violations from a server that IS reachable, so
  labelling every failure "unreachable" mislabelled exactly the
  loud-abort cases the fetch caps exist to surface.

* ``list`` tolerates rows whose ``memory_id`` attribute exists but is
  None (a row shape the bounded fetch walk explicitly tolerates):
  slicing None used to TypeError and hide every other row from the
  operator's audit.
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


def setUpModule() -> None:
    global _cli
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    loader = SourceFileLoader(
        "raptor_sage_cli_report_paths",
        str(REPO_ROOT / "libexec" / "raptor-sage"),
    )
    spec = importlib.util.spec_from_loader(
        "raptor_sage_cli_report_paths", loader,
    )
    _cli = importlib.util.module_from_spec(spec)
    loader.exec_module(_cli)


def _row(memory_id, content="row content"):
    return SimpleNamespace(
        memory_id=memory_id,
        domain_tag="raptor-home",
        status="committed",
        memory_type="observation",
        confidence_score=0.8,
        content=content,
        tags=[],
        created_at="2026-01-01T00:00:00Z",
    )


class _FailingClient:
    def __init__(self, exc):
        self._exc = exc

    def list_memories(self, **kwargs):
        raise self._exc


class _ListingClient:
    def __init__(self, memories):
        self._memories = memories

    def list_memories(self, **kwargs):
        return SimpleNamespace(
            memories=self._memories,
            total=len(self._memories),
            has_more=False,
        )


def _list_args(**overrides):
    base = dict(domain=None, tag=None, status=None, sort=None,
                limit=None, full=False, json=False)
    base.update(overrides)
    return SimpleNamespace(**base)


def _run(fn, client, args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = fn(client, args)
    return rc, out.getvalue(), err.getvalue()


class TestStatusFailureReporting(unittest.TestCase):
    def test_failure_line_goes_to_stderr(self):
        client = _FailingClient(RuntimeError("connection refused"))
        rc, out, err = _run(_cli.cmd_status, client, SimpleNamespace())
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")
        self.assertIn("Status failed", err)
        self.assertIn("connection refused", err)

    def test_protocol_error_is_not_labelled_unreachable(self):
        """A reachable-but-protocol-violating server (the fetch caps'
        loud-abort case) must not be reported as unreachable."""
        client = _FailingClient(RuntimeError(
            "SAGE protocol error: pagination is not advancing"))
        rc, out, err = _run(_cli.cmd_status, client, SimpleNamespace())
        self.assertEqual(rc, 1)
        self.assertNotIn("unreachable", (out + err).lower())
        self.assertIn("SAGE protocol error", err)

    def test_healthy_store_still_reports_to_stdout(self):
        client = _ListingClient([_row("a" * 36)])
        rc, out, _err = _run(_cli.cmd_status, client, SimpleNamespace())
        self.assertEqual(rc, 0)
        self.assertIn("Total memories:", out)


class TestListNoneMemoryId(unittest.TestCase):
    def test_none_memory_id_row_does_not_hide_the_listing(self):
        """A row whose memory_id attribute exists but is None (impostor
        or misbehaving server) renders with an empty id cell instead of
        crashing the whole table."""
        client = _ListingClient([_row(None), _row("b" * 36, "other row")])
        rc, out, _err = _run(_cli.cmd_list, client, _list_args())
        self.assertEqual(rc, 0)
        self.assertIn("row content", out)
        self.assertIn("other row", out)

    def test_string_ids_still_truncate(self):
        client = _ListingClient([_row("c" * 36)])
        rc, out, _err = _run(_cli.cmd_list, client, _list_args())
        self.assertEqual(rc, 0)
        self.assertIn("c" * 12, out)
        self.assertNotIn("c" * 13, out)


if __name__ == "__main__":
    unittest.main()
