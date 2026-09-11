"""Fixture tests for the missing_bounds_check rule.

Negatives pin two suppression mechanisms: guard-shape recognition in
both loop directions (a decreasing ``for (i = n - 1; i >= 0; i--)``
walk is as guarded as the increasing one) and the parameter scoping —
only a parameter of the enclosing function used as an index is
reported, since locally-computed indexes flood every array-walking
helper. Positives keep the genuine target firing: an
externally-supplied parameter indexing an array with no in-function
validation.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "missing_bounds_check.cocci"
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
    def test_unvalidated_parameter_index_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int lookup(int *table, int idx)
            {
                return table[idx];
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "missing_bounds_check"

    def test_struct_member_array_parameter_index_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void set_sem(struct sem_array *sma, unsigned short sem_num, int val)
            {
                sma->sems[sem_num].semval = val;
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_decreasing_loop_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int sum_rev(int *arr, int n)
            {
                int i, s = 0;
                for (i = n - 1; i >= 0; i--)
                    s += arr[i];
                return s;
            }
        """)
        assert results == []

    def test_increasing_loop_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int sum_fwd(int *arr, int n)
            {
                int i, s = 0;
                for (i = 0; i < n; i++)
                    s += arr[i];
                return s;
            }
        """)
        assert results == []

    def test_decreasing_while_on_parameter_does_not_fire(self, tmp_path):
        # The index IS a parameter here, so only the decreasing-while
        # guard shape keeps it silent.
        results = _run_rule(tmp_path, """\
            int countdown(int *arr, int n)
            {
                int s = 0;
                while (n > 0) {
                    n--;
                    s += arr[n];
                }
                return s;
            }
        """)
        assert results == []

    def test_early_return_guard_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int guarded(int *arr, int idx, int n)
            {
                if (idx >= n)
                    return -1;
                return arr[idx];
            }
        """)
        assert results == []

    def test_local_computed_index_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int hashed(int *table, int key)
            {
                int slot = compute_slot(key);
                return table[slot];
            }
        """)
        assert results == []
