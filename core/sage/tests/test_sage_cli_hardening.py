#!/usr/bin/env python3
"""Round-2 CLI hardening: server-derived error text is escaped on
every failure path, and a hostile ``total`` cannot crash the domains
listing.

The transport is plain HTTP with no server authentication, so anything
the server (or an impostor bound to the port) returns — including the
response bodies SageError embeds verbatim in exception text — is
untrusted terminal input.
"""

import contextlib
import importlib.util
import io
import os
import re
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
        "raptor_sage_cli_hardening",
        str(REPO_ROOT / "libexec" / "raptor-sage"),
    )
    spec = importlib.util.spec_from_loader(
        "raptor_sage_cli_hardening", loader,
    )
    _cli = importlib.util.module_from_spec(spec)
    loader.exec_module(_cli)


_ANSI_CLEAR = "\x1b[2J\x1b[H"


class TestErrorPathsEscaped(unittest.TestCase):
    def test_no_failure_print_interpolates_e_raw(self):
        """Every ``{e}`` on a failure print must ride through _safe():
        SageError embeds the server response body verbatim, making
        exception text an impostor-server terminal vector."""
        src = (REPO_ROOT / "libexec" / "raptor-sage").read_text(
            encoding="utf-8")
        raw = re.findall(r'print\(f"[^"]*\{e\}[^"]*"', src)
        self.assertEqual(
            raw, [],
            f"raw exception interpolations remain: {raw}",
        )

    def test_domains_failure_output_is_escaped(self):
        class _Boom:
            def list_memories(self, **kw):
                raise RuntimeError(_ANSI_CLEAR + "poisoned body")

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = _cli.cmd_domains(_Boom(), SimpleNamespace())
        self.assertEqual(rc, 1)
        self.assertNotIn("\x1b", err.getvalue())
        self.assertIn("poisoned body", err.getvalue())


class TestDomainsTotalGuard(unittest.TestCase):
    def test_zero_total_with_rows_does_not_crash(self):
        mems = [SimpleNamespace(domain_tag="raptor-fuzzing")] * 3

        def _fake_fetch(client):
            return mems, 0

        original = _cli._fetch_all_memories
        _cli._fetch_all_memories = _fake_fetch
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = _cli.cmd_domains(object(), SimpleNamespace())
        finally:
            _cli._fetch_all_memories = original
        self.assertEqual(rc, 0)
        self.assertIn("Total: 0", out.getvalue())


if __name__ == "__main__":
    unittest.main()
