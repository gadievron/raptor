#!/usr/bin/env python3
"""Task-creation --status plumbing for the raptor-sage operator CLI.

``task <text> --status S`` is advertised for creation (usage and help
both list --status), but the create path used to drop it: only the
--id update branch consumed ``args.task_status``, so the requested
initial status silently fell back to the server default. The creation
path must pass the operator's status through to ``propose`` — and must
keep omitting the parameter entirely when no --status was given, so
injected clients without that keyword keep working.
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

FULL_ID = "12345678-1234-5678-1234-567812345678"

_cli = None


def setUpModule() -> None:
    global _cli
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    loader = SourceFileLoader(
        "raptor_sage_cli_task_create_status",
        str(REPO_ROOT / "libexec" / "raptor-sage"),
    )
    spec = importlib.util.spec_from_loader(
        "raptor_sage_cli_task_create_status", loader,
    )
    _cli = importlib.util.module_from_spec(spec)
    loader.exec_module(_cli)


class _FakeClient:
    def __init__(self):
        self.proposed = []
        self.updated = []

    def embed(self, text):
        return [0.1]

    def propose(self, **kwargs):
        self.proposed.append(kwargs)
        return SimpleNamespace(memory_id=FULL_ID, status="committed")

    def update_task_status(self, memory_id, task_status):
        self.updated.append((memory_id, task_status))
        return {}

    def get_memory(self, memory_id):
        return SimpleNamespace(
            memory_id=memory_id, domain_tag="raptor-home", content="t",
        )


def _args(**overrides):
    base = dict(content=["port", "the", "fix"], domain=None,
                id=None, task_status=None)
    base.update(overrides)
    return SimpleNamespace(**base)


def _run(client, args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = _cli.cmd_task(client, args)
    return rc, out.getvalue(), err.getvalue()


class TestTaskCreateStatus(unittest.TestCase):
    def test_create_with_status_reaches_propose(self):
        """The advertised `task <text> --status S` must send the
        operator's initial status to the server."""
        client = _FakeClient()
        rc, _out, _err = _run(client, _args(task_status="in_progress"))
        self.assertEqual(rc, 0)
        self.assertEqual(len(client.proposed), 1)
        self.assertEqual(client.proposed[0]["task_status"], "in_progress")
        # Creation, not the update branch.
        self.assertEqual(client.updated, [])

    def test_create_without_status_omits_parameter(self):
        """No --status: the keyword is omitted entirely (server default
        applies; injected clients without the parameter keep working)."""
        client = _FakeClient()
        rc, _out, _err = _run(client, _args())
        self.assertEqual(rc, 0)
        self.assertNotIn("task_status", client.proposed[0])

    def test_create_with_status_reports_success(self):
        client = _FakeClient()
        rc, out, _err = _run(client, _args(task_status="done"))
        self.assertEqual(rc, 0)
        self.assertIn(FULL_ID, out)

    def test_update_path_still_routes_to_update(self):
        """--id + --status stays an update, never a propose."""
        client = _FakeClient()
        rc, _out, _err = _run(
            client, _args(content=[], id=FULL_ID, task_status="done"))
        self.assertEqual(rc, 0)
        self.assertEqual(client.updated, [(FULL_ID, "done")])
        self.assertEqual(client.proposed, [])


if __name__ == "__main__":
    unittest.main()
