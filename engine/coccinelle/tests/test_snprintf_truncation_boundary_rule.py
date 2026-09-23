"""Fixture tests for the snprintf_truncation_boundary rule.

Verification-role rule (fires mint confirmed CWE-193 verdicts): the
libc contract makes ret == size a truncated result, so `ret > size`
misses the exact-fit boundary. Negatives pin the two CORRECT guard
spellings (`>=` and `> SZ - 1`) and a return value reassigned before
the comparison — none of those may be confirmed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules"
    / "snprintf_truncation_boundary.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    src = tmp_path / "target.c"
    src.write_text(textwrap.dedent(source), encoding="utf-8")
    proc = subprocess.run(  # noqa: S603 — fixed local binary, fixture input
        ["spatch", "--sp-file", str(rule), str(src), "--no-show-diff"],
        capture_output=True, text=True, timeout=120,
    )
    results = []
    for stream in (proc.stdout, proc.stderr):
        for line in stream.splitlines():
            if line.startswith("COCCIRESULT:"):
                results.append(json.loads(line[len("COCCIRESULT:"):]))
    return results


class TestPositives:
    def test_gt_guard_on_snprintf_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int fmt(char *buf, unsigned long sz, const char *s)
            {
                int n;
                n = snprintf(buf, sz, "%s", s);
                if (n > sz)
                    return -1;
                return n;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "snprintf_truncation_boundary"
        assert results[0]["line"] == 5

    def test_flipped_operands_fire(self, tmp_path):
        # SZ < ret is the same wrong boundary via the comparison
        # isomorphism the rule header documents.
        results = _run_rule(tmp_path, """\
            int fmt(char *buf, unsigned long sz, const char *s)
            {
                int n;
                n = vsnprintf(buf, sz, "%s", s);
                if (sz < n)
                    return -1;
                return n;
            }
        """)
        assert len(results) == 1
        assert results[0]["line"] == 5


class TestNegatives:
    def test_ge_guard_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int fmt(char *buf, unsigned long sz, const char *s)
            {
                int n;
                n = snprintf(buf, sz, "%s", s);
                if (n >= sz)
                    return -1;
                return n;
            }
        """)
        assert results == []

    def test_gt_size_minus_one_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int fmt(char *buf, unsigned long sz, const char *s)
            {
                int n;
                n = snprintf(buf, sz, "%s", s);
                if (n > sz - 1)
                    return -1;
                return n;
            }
        """)
        assert results == []

    def test_ret_reassigned_before_check_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int fmt(char *buf, unsigned long sz, const char *s, int m)
            {
                int n;
                n = snprintf(buf, sz, "%s", s);
                n = m;
                if (n > sz)
                    return -1;
                return n;
            }
        """)
        assert results == []

    def test_different_size_expression_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int fmt(char *buf, unsigned long sz, unsigned long lim,
                    const char *s)
            {
                int n;
                n = snprintf(buf, sz, "%s", s);
                if (n > lim)
                    return -1;
                return n;
            }
        """)
        assert results == []

    def test_separate_exact_fit_statement_does_not_fire(self, tmp_path):
        # The boundary IS handled, just as its own statement instead of
        # >= or else-if — an unidiomatic but correct spelling.
        results = _run_rule(tmp_path, """\
            int fmt(char *buf, unsigned long sz, const char *s)
            {
                int n;
                n = snprintf(buf, sz, "%s", s);
                if (n > sz)
                    return -1;
                if (n == sz)
                    return -2;
                return n;
            }
        """)
        assert results == []

    def test_exact_fit_statement_before_gt_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int fmt(char *buf, unsigned long sz, const char *s)
            {
                int n;
                n = snprintf(buf, sz, "%s", s);
                if (n == sz)
                    return -2;
                if (n > sz)
                    return -1;
                return n;
            }
        """)
        assert results == []

    def test_unrelated_eq_check_keeps_gt_firing(self, tmp_path):
        # Recall guard for the handled-boundary suppression: an ==
        # check against a DIFFERENT bound does not handle the exact
        # fit, so the > guard still fires.
        results = _run_rule(tmp_path, """\
            int fmt(char *buf, unsigned long sz, unsigned long lim,
                    const char *s)
            {
                int n;
                n = snprintf(buf, sz, "%s", s);
                if (n == lim)
                    return -2;
                if (n > sz)
                    return -1;
                return n;
            }
        """)
        assert len(results) == 1
