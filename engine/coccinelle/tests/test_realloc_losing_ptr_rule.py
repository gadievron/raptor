"""Fixture tests for the realloc_losing_ptr rule.

Verification-role rule (fires mint confirmed CWE-401 verdicts):
ptr = realloc(ptr, n) loses the only handle to the original block
when realloc fails. The positive pins the self-assignment; the
negative pins the recommended temporary-variable shape.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "realloc_losing_ptr.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_self_assignment_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int grow(char *buf, unsigned long n)
            {
                buf = realloc(buf, n);
                if (!buf)
                    return -1;
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "realloc_losing_ptr"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_temporary_variable_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int grow(char **buf, unsigned long n)
            {
                char *tmp = realloc(*buf, n);
                if (!tmp)
                    return -1;
                *buf = tmp;
                return 0;
            }
        """)
        assert results == []
