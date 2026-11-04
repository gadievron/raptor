"""Fixture tests for the is_err_not_ptr_err rule.

Verification-role rule (fires mint confirmed CWE-253 verdicts):
returning IS_ERR(p) from an error path yields boolean 1 instead of
the embedded errno. The positive pins return IS_ERR(p) inside the
IS_ERR check; the negative pins the correct return PTR_ERR(p).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "is_err_not_ptr_err.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_return_is_err_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int setup(struct dev *d)
            {
                void *clk = get_clk(d);
                if (IS_ERR(clk)) {
                    return IS_ERR(clk);
                }
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "is_err_not_ptr_err"
        assert results[0]["line"] == 5


class TestNegatives:
    def test_return_ptr_err_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int setup(struct dev *d)
            {
                void *clk = get_clk(d);
                if (IS_ERR(clk)) {
                    return PTR_ERR(clk);
                }
                return 0;
            }
        """)
        assert results == []
