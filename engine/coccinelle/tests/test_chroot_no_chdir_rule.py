"""Fixture tests for the chroot_no_chdir rule.

The chroot call is matched in statement, assignment,
declaration-init, and if-condition form (real code checks the return
value, and the bare-statement pattern missed every checked call).
Correct shapes — chdir("/") reached on the success path — are
unflagged exception branches.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "chroot_no_chdir.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    src = tmp_path / "target.c"
    src.write_text(textwrap.dedent(source), encoding="utf-8")
    proc = subprocess.run(  # noqa: S603 — fixed local binary, fixture input
        ["spatch", "--sp-file", str(_RULE), str(src), "--no-show-diff"],
        capture_output=True, text=True, timeout=120,
    )
    results = []
    for stream in (proc.stdout, proc.stderr):
        for line in stream.splitlines():
            if line.startswith("COCCIRESULT:"):
                results.append(json.loads(line[len("COCCIRESULT:"):]))
    return results


class TestPositives:
    def test_bare_call_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int jail(const char *dir)
            {
                chroot(dir);
                return run();
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "chroot_no_chdir"

    def test_return_checked_call_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int jail(const char *dir)
            {
                if (chroot(dir) != 0)
                    return -1;
                return run();
            }
        """)
        assert len(results) == 1

    def test_assigned_call_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int jail(const char *dir)
            {
                int r;
                r = chroot(dir);
                if (r < 0)
                    return -1;
                return run();
            }
        """)
        assert len(results) == 1

    def test_declaration_init_call_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int jail(const char *dir)
            {
                int r = chroot(dir);
                if (r < 0)
                    return -1;
                return run();
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_checked_then_chdir_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int jail(const char *dir)
            {
                if (chroot(dir) != 0)
                    return -1;
                if (chdir("/") != 0)
                    return -1;
                return run();
            }
        """)
        assert results == []

    def test_chdir_inside_success_branch_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int jail(const char *dir)
            {
                if (chroot(dir) == 0) {
                    chdir("/");
                    return run();
                }
                return -1;
            }
        """)
        assert results == []

    def test_declaration_init_then_chdir_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int jail(const char *dir)
            {
                int r = chroot(dir);
                if (r < 0)
                    return -1;
                chdir("/");
                return run();
            }
        """)
        assert results == []
