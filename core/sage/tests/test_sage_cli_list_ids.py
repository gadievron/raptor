#!/usr/bin/env python3
"""Full-ID recovery paths for ``raptor-sage list``.

The table view truncates memory IDs to 12 characters while ``get``,
``forget``, and ``task --id`` all require the full UUID — no CLI path
recovered a full ID. ``--full`` widens the table ID column to the
complete id; ``--json`` emits complete records for machine use
(json.dumps' default ensure_ascii keeps hostile store bytes inert on
the terminal while round-tripping them faithfully to a JSON consumer).
"""

import contextlib
import importlib.util
import io
import json
import os
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[3]

FULL_ID = "12345678-1234-5678-1234-567812345678"
HOSTILE = "evil \x1b[2K\x1b[A row \x1b]52;c;aGk=\x07 end"

_cli = None


def setUpModule():
    global _cli
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    loader = SourceFileLoader(
        "raptor_sage_cli_list_ids",
        str(REPO_ROOT / "libexec" / "raptor-sage"),
    )
    spec = importlib.util.spec_from_loader(
        "raptor_sage_cli_list_ids", loader,
    )
    _cli = importlib.util.module_from_spec(spec)
    loader.exec_module(_cli)


class _Status:
    value = "committed"


def _mem(content="hello world"):
    return SimpleNamespace(
        memory_id=FULL_ID,
        domain_tag="raptor-methodology",
        memory_type=SimpleNamespace(value="task"),
        status=_Status(),
        task_status="planned",
        confidence_score=0.8,
        content=content,
        tags=["a", "b"],
        created_at="2026-08-21T00:00:00+00:00",
    )


class _FakeClient:
    def __init__(self, memories):
        self._memories = memories

    def list_memories(self, **kwargs):
        return SimpleNamespace(
            memories=list(self._memories), total=len(self._memories))


def _args(**overrides):
    base = dict(domain=None, tag=None, status=None, sort=None,
                limit=None, full=False, json=False)
    base.update(overrides)
    return SimpleNamespace(**base)


def _run(client, args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = _cli.cmd_list(client, args)
    return rc, out.getvalue()


class TestListIdRecovery(unittest.TestCase):
    def test_default_table_still_truncates_ids(self):
        rc, out = _run(_FakeClient([_mem()]), _args())
        self.assertEqual(rc, 0)
        self.assertIn(FULL_ID[:12], out)
        self.assertNotIn(FULL_ID, out)

    def test_full_flag_shows_complete_id(self):
        rc, out = _run(_FakeClient([_mem()]), _args(full=True))
        self.assertEqual(rc, 0)
        self.assertIn(FULL_ID, out)

    def test_json_emits_complete_records(self):
        rc, out = _run(_FakeClient([_mem()]), _args(json=True))
        self.assertEqual(rc, 0)
        records = json.loads(out)
        self.assertEqual(len(records), 1)
        r = records[0]
        self.assertEqual(r["memory_id"], FULL_ID)
        self.assertEqual(r["domain_tag"], "raptor-methodology")
        self.assertEqual(r["memory_type"], "task")
        self.assertEqual(r["status"], "committed")
        self.assertEqual(r["task_status"], "planned")
        self.assertEqual(r["confidence_score"], 0.8)
        self.assertEqual(r["content"], "hello world")
        self.assertEqual(r["tags"], ["a", "b"])
        self.assertEqual(r["created_at"], "2026-08-21T00:00:00+00:00")

    def test_json_content_untruncated(self):
        long_content = "x" * 400
        rc, out = _run(
            _FakeClient([_mem(content=long_content)]), _args(json=True))
        self.assertEqual(rc, 0)
        records = json.loads(out)
        self.assertEqual(records[0]["content"], long_content)

    def test_json_hostile_bytes_inert_on_terminal_but_roundtrip(self):
        rc, out = _run(_FakeClient([_mem(content=HOSTILE)]), _args(json=True))
        self.assertEqual(rc, 0)
        # Raw stream carries no live escape bytes...
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)
        # ...yet a JSON consumer recovers the exact stored content.
        records = json.loads(out)
        self.assertEqual(records[0]["content"], HOSTILE)

    def test_json_empty_store_is_empty_array(self):
        rc, out = _run(_FakeClient([]), _args(json=True))
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out), [])

    def test_json_failure_path_unchanged(self):
        class _Boom:
            def list_memories(self, **kwargs):
                raise RuntimeError("down")

        err = io.StringIO()
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = _cli.cmd_list(_Boom(), _args(json=True))
        self.assertEqual(rc, 1)
        self.assertIn("List failed", err.getvalue())


if __name__ == "__main__":
    unittest.main()
