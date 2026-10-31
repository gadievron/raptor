"""Only extent-aware, two-sided guards justify excluding parameter indexes."""

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
    assert proc.returncode == 0, proc.stderr
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

    def test_decreasing_while_with_unknown_extent_is_a_candidate(self, tmp_path):
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
        assert len(results) == 1

    def test_upper_only_guard_with_unknown_extent_is_a_candidate(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int guarded(int *arr, int idx, int n)
            {
                if (idx >= n)
                    return -1;
                return arr[idx];
            }
        """)
        assert len(results) == 1

    def test_local_computed_index_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int hashed(int *table, int key)
            {
                int slot = compute_slot(key);
                return table[slot];
            }
        """)
        assert results == []


@pytest.mark.parametrize("body", [
    "if (idx <= 4) { return arr[idx]; }",
    "if (idx < 1000) { return arr[idx]; }",
    "while (idx > 0) { return arr[idx]; }",
    "if (idx < 4) { return arr[idx]; }",  # negative index
    "if (idx >= 0 && idx <= 4) { return arr[idx]; }",
    "if (idx >= 0 && idx < 1000) { return arr[idx]; }",
    "if (idx >= 0 && idx < 4) { idx = 9; return arr[idx]; }",
    "if (idx >= 0 && idx < 4) { idx += 9; return arr[idx]; }",
    "if (idx >= 0 && idx < 4) { idx++; return arr[idx]; }",
    "if (idx >= 0 && idx < 4) { --idx; return arr[idx]; }",
    "if (idx >= 0 && idx < 4) { change(&idx); return arr[idx]; }",
    "int *alias = &idx; if (idx >= 0 && idx < 4) { *alias = 9; return arr[idx]; }",
    "if (idx < 0 || idx >= 4) { return 0; } idx = 9; return arr[idx];",
    "if (idx > 4) { return 0; } return arr[idx];",
    "while (idx >= 0) { return arr[idx]; }",
    "int other[1000]; if (idx >= 0 && idx < 1000) { return arr[idx]; }",
])
def test_unsafe_guards_do_not_hide_known_array_access(tmp_path, body):
    results = _run_rule(tmp_path, f"int f(int idx) {{ int arr[4]; {body} return 0; }}")
    assert len(results) == 1
    assert results[0]["rule"] == "missing_bounds_check"


@pytest.mark.parametrize("index_type, body", [
    ("int", "if (idx >= 0 && idx < 4) { return arr[idx]; }"),
    ("int", "if (idx < 0 || idx >= 4) { return 0; } return arr[idx];"),
    ("unsigned int", "if (idx < 4) { return arr[idx]; }"),
    ("unsigned", "if (idx < 4) { return arr[idx]; }"),
    ("unsigned short", "if (idx < 4) { return arr[idx]; }"),
    ("unsigned char", "if (idx < 4) { return arr[idx]; }"),
    ("unsigned long long", "if (idx < 4) { return arr[idx]; }"),
    ("unsigned long", "if (idx >= 4) { return 0; } return arr[idx];"),
])
def test_extent_aware_guards_stay_silent(tmp_path, index_type, body):
    results = _run_rule(tmp_path, f"int f({index_type} idx) {{ int arr[4]; {body} return 0; }}")
    assert results == []


def test_guarded_access_does_not_hide_another_access(tmp_path):
    results = _run_rule(tmp_path, """
        int f(int idx) {
            int arr[4];
            if (idx >= 0 && idx < 4) { consume(arr[idx]); }
            return arr[idx];
        }
    """)
    assert len(results) == 1
    assert results[0]["line"] == 5


@pytest.mark.parametrize("body", [
    "if (idx <= 4) { return arr[idx]; }",
    "if (idx >= 4) { return 0; } idx++; return arr[idx];",
    "if (idx < 4) { idx -= 1; return arr[idx]; }",
])
def test_unsigned_guards_still_require_strict_unmodified_bound(tmp_path, body):
    results = _run_rule(tmp_path, f"int f(unsigned int idx) {{ int arr[4]; {body} return 0; }}")
    assert len(results) == 1


def test_unsigned_named_typedef_does_not_prove_unsignedness(tmp_path):
    results = _run_rule(tmp_path, """
        typedef int unsigned_index;
        int f(unsigned_index idx) {
            int arr[4];
            if (idx < 4) { return arr[idx]; }
            return 0;
        }
    """)
    assert len(results) == 1
