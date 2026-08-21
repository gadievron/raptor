#!/usr/bin/env python3
"""Task-creation domain routing and read-back verification for the
raptor-sage operator CLI.

``task`` without --domain used to hardcode ``domain_tag="general"`` —
a domain the calling identity often cannot read — and print success
without ever fetching the row back. Committed tasks were unreachable
from every read surface (backlog/list/get all 403): the success
message was unverifiable and the rows were lost. The CLI now passes
``domain_tag=None`` (server-side home-domain routing, the same mapping
the MCP layer uses), reads the committed row back with the same
identity before claiming success, and fails loudly with the full
memory id plus the caller's readable-domain list when the read-back
is refused.
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


def setUpModule():
    global _cli
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    loader = SourceFileLoader(
        "raptor_sage_cli_task_domain",
        str(REPO_ROOT / "libexec" / "raptor-sage"),
    )
    spec = importlib.util.spec_from_loader(
        "raptor_sage_cli_task_domain", loader,
    )
    _cli = importlib.util.module_from_spec(spec)
    loader.exec_module(_cli)


class _FakeClient:
    """Scriptable propose/get_memory/domain_access_sample server."""

    def __init__(self, readback_error=None, readable_domains=(),
                 sample_error=None, committed_domain="raptor-home"):
        self.proposed = []
        self.got = []
        self._readback_error = readback_error
        self._readable = list(readable_domains)
        self._sample_error = sample_error
        self._committed_domain = committed_domain

    def embed(self, text):
        return [0.1]

    def propose(self, **kwargs):
        self.proposed.append(kwargs)
        return SimpleNamespace(memory_id=FULL_ID, status="committed")

    def get_memory(self, memory_id):
        self.got.append(memory_id)
        if self._readback_error is not None:
            raise self._readback_error
        return SimpleNamespace(
            memory_id=memory_id,
            domain_tag=self._committed_domain,
            content="t",
        )

    def domain_access_sample(self):
        if self._sample_error is not None:
            raise self._sample_error
        return SimpleNamespace(readable_domains=list(self._readable))


def _args(**overrides):
    base = dict(content=["do", "the", "thing"], domain=None,
                id=None, task_status=None)
    base.update(overrides)
    return SimpleNamespace(**base)


def _run(client, args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = _cli.cmd_task(client, args)
    return rc, out.getvalue(), err.getvalue()


class TestTaskDomainRouting(unittest.TestCase):
    def test_no_domain_routes_to_server_home_domain(self):
        """Omitted --domain must send domain_tag=None (server-side
        home-domain routing), never a hardcoded 'general'."""
        client = _FakeClient()
        rc, out, _err = _run(client, _args())
        self.assertEqual(rc, 0)
        self.assertEqual(len(client.proposed), 1)
        self.assertIsNone(client.proposed[0]["domain_tag"])
        self.assertNotIn("general", out)

    def test_explicit_domain_passes_verbatim(self):
        client = _FakeClient(committed_domain="raptor-methodology")
        rc, _out, _err = _run(client, _args(domain="raptor-methodology"))
        self.assertEqual(rc, 0)
        self.assertEqual(
            client.proposed[0]["domain_tag"], "raptor-methodology")

    def test_success_reports_full_id_and_committed_domain(self):
        """Success is claimed only after the row is read back; the
        message carries the full (get-able) id and the domain the
        server actually committed to."""
        client = _FakeClient(committed_domain="raptor-home")
        rc, out, _err = _run(client, _args())
        self.assertEqual(rc, 0)
        self.assertEqual(client.got, [FULL_ID])
        self.assertIn(FULL_ID, out)
        self.assertIn("home", out)

    def test_unreadable_readback_fails_loudly_with_domain_list(self):
        client = _FakeClient(
            readback_error=RuntimeError("HTTP 403: forbidden"),
            readable_domains=["raptor-methodology", "raptor-fuzzing"],
        )
        rc, out, err = _run(client, _args(domain="general"))
        self.assertEqual(rc, 1)
        self.assertNotIn("created", out)
        self.assertIn(FULL_ID, err)
        self.assertIn("general", err)
        self.assertIn("cannot be read back", err)
        self.assertIn("raptor-methodology", err)
        self.assertIn("raptor-fuzzing", err)
        self.assertIn("--domain", err)

    def test_unreadable_readback_without_domain_names_home(self):
        client = _FakeClient(
            readback_error=RuntimeError("HTTP 403: forbidden"),
            readable_domains=["raptor-methodology"],
        )
        rc, _out, err = _run(client, _args())
        self.assertEqual(rc, 1)
        self.assertIn("<home domain>", err)

    def test_domain_sample_failure_is_tolerated(self):
        client = _FakeClient(
            readback_error=RuntimeError("HTTP 403: forbidden"),
            sample_error=RuntimeError("HTTP 403: forbidden"),
        )
        rc, _out, err = _run(client, _args())
        self.assertEqual(rc, 1)
        self.assertIn("could not list readable domains", err)

    def test_hostile_error_and_domain_text_is_escaped(self):
        """Read-back error text and domain names are server-derived —
        they must reach the terminal escaped."""
        client = _FakeClient(
            readback_error=RuntimeError("\x1b[2J\x1b[H poisoned"),
            readable_domains=["raptor-\x1b]52;c;aGk=\x07"],
        )
        rc, out, err = _run(client, _args())
        self.assertEqual(rc, 1)
        self.assertNotIn("\x1b", out + err)
        self.assertNotIn("\x07", out + err)
        self.assertIn("\\x1b", err)

    def test_propose_failure_is_loud(self):
        class _Boom(_FakeClient):
            def propose(self, **kwargs):
                raise RuntimeError("embed store down")

        rc, out, err = _run(_Boom(), _args())
        self.assertEqual(rc, 1)
        self.assertNotIn("created", out)
        self.assertIn("Task creation failed", err)

    def test_update_path_unchanged(self):
        class _Upd(_FakeClient):
            def __init__(self):
                super().__init__()
                self.updated = []

            def update_task_status(self, memory_id, task_status):
                self.updated.append((memory_id, task_status))
                return {}

        client = _Upd()
        rc, out, _err = _run(
            client, _args(content=[], id=FULL_ID, task_status="done"))
        self.assertEqual(rc, 0)
        self.assertEqual(client.updated, [(FULL_ID, "done")])
        self.assertEqual(client.proposed, [])
        self.assertIn("done", out)


if __name__ == "__main__":
    unittest.main()
