"""Fixture tests for the free_nonbase_ptr rule.

Subtracting offsetof() is container_of-style base recovery — a
correct walk BACK to the true allocation base — and is excluded from
the subtraction leg via an unflagged exception branch.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "free_nonbase_ptr.cocci"
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
    def test_free_offset_pointer_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(char *p, int n)
            {
                free(p + n);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "free_nonbase_ptr"

    def test_free_minus_literal_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(char *p)
            {
                kfree(p - 1);
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_offsetof_base_recovery_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct wrap { int hdr; struct node node; };
            void put_node(struct node *n)
            {
                free((char *)n - offsetof(struct wrap, node));
            }
        """)
        assert results == []
