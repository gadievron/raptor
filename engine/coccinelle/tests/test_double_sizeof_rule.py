"""Fixture tests for the double_sizeof rule.

Pins the two implemented patterns (double sizeof in an allocation
size; explicit sizeof in already-scaled pointer arithmetic) and the
correct single-sizeof allocation staying silent.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "double_sizeof.cocci"
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
    def test_double_sizeof_in_alloc_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(int n)
            {
                char *p = malloc(n * sizeof(int) * sizeof(int));
                use(p);
            }
        """)
        assert [r["rule"] for r in results] == ["double_sizeof"]

    def test_pointer_arith_with_explicit_sizeof_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int *bug(int *p, int n)
            {
                return p + n * sizeof(*p);
            }
        """)
        assert [r["rule"] for r in results] == ["pointer_scaling_double"]


class TestNegatives:
    def test_single_sizeof_alloc_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(int n)
            {
                int *p = malloc(n * sizeof(int));
                use(p);
            }
        """)
        assert results == []

    def test_plain_pointer_arith_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int *ok(int *p, int n)
            {
                return p + n;
            }
        """)
        assert results == []
