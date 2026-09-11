"""Fixture tests for the stack_addr_escape rule.

The safe set must be declaration-order independent: C89 style puts
every local at the top of the function, often declaring the pointer
BEFORE the variable whose address it takes. A safe set that requires
LOCAL-before-pointer order reports the C89 shape as an escape.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "stack_addr_escape.cocci"
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
    def test_assign_to_global_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            static int *gp;

            void bug(void)
            {
                int x;
                gp = &x;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "stack_addr_escape"

    def test_write_to_outparam_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int bug(int **out)
            {
                int x;
                *out = &x;
                return 0;
            }
        """)
        assert any(r["rule"] == "stack_addr_escape_outparam" for r in results)


class TestNegatives:
    def test_local_pointer_c99_order_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(void)
            {
                int x;
                int *p;
                p = &x;
                *p = 1;
            }
        """)
        assert results == []

    def test_local_pointer_c89_order_does_not_fire(self, tmp_path):
        # Pointer declared BEFORE the target variable — same lifetime,
        # same scope, no escape.
        results = _run_rule(tmp_path, """\
            void ok(void)
            {
                int *p;
                int x;
                p = &x;
                *p = 1;
            }
        """)
        assert results == []

    def test_local_struct_member_either_order_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct holder { int *m; };

            void ok_c89(void)
            {
                struct holder h;
                int x;
                h.m = &x;
            }

            void ok_c99(void)
            {
                int x;
                struct holder h;
                h.m = &x;
            }
        """)
        assert results == []
