"""Fixture tests for the sizeof_array_param rule.

Verification-role rule (fires mint confirmed CWE-467 verdicts):
an array-notation parameter decays to a pointer, so sizeof() on it
returns the pointer size, not the declared array size. The
positive pins sizeof on a sized array parameter; the negative pins
sizeof on a genuine local array, where it is correct.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "sizeof_array_param.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_sizeof_on_sized_param_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void fill(char buf[256])
            {
                memset(buf, 0, sizeof(buf));
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "sizeof_array_param"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_sizeof_on_local_array_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void fill(void)
            {
                char buf[256];
                memset(buf, 0, sizeof(buf));
            }
        """)
        assert results == []
