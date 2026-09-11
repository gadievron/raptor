"""Fixture tests for the division_by_zero verification-grade rule.

The rule carries ``@role: verification``, so it only reports the
in-function contradiction it can actually decide: a parameter used as
a divisor and THEN tested against zero (the later test proves the
author considers zero reachable). Negatives pin the shapes that must
stay silent — a bare unguarded division (caller-side invariant) and a
properly pre-checked division.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "division_by_zero.cocci"
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
    def test_divide_then_zero_check_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int bug(int total, int count)
            {
                int a = total / count;
                if (count == 0)
                    return 0;
                return a;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "division_by_zero_param"

    def test_modulo_then_not_check_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            unsigned int bug(unsigned int h, unsigned int nbuckets)
            {
                unsigned int i = h % nbuckets;
                if (!nbuckets)
                    return 0;
                return i;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "modulo_by_zero_param"


class TestNegatives:
    def test_bare_unguarded_division_does_not_fire(self, tmp_path):
        # No in-function zero test at all: the divisor's range is a
        # caller-side invariant the rule cannot see.
        results = _run_rule(tmp_path, """\
            int avg(int total, int count)
            {
                return total / count;
            }
        """)
        assert results == []

    def test_bare_unguarded_modulo_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            unsigned int pick(unsigned int h, unsigned int nbuckets)
            {
                return h % nbuckets;
            }
        """)
        assert results == []

    def test_prechecked_division_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int safe(int total, int count)
            {
                if (count == 0)
                    return 0;
                return total / count;
            }
        """)
        assert results == []

    def test_precheck_plus_redundant_late_check_does_not_fire(self, tmp_path):
        # A pre-division guard makes the division safe; the extra
        # late test is redundancy, not a contradiction.
        results = _run_rule(tmp_path, """\
            int safe(int total, int count)
            {
                int r;
                if (!count)
                    return 0;
                r = total / count;
                if (count == 0)
                    return r;
                return r;
            }
        """)
        assert results == []
