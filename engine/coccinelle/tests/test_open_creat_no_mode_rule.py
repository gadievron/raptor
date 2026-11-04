"""Fixture tests for the open_creat_no_mode rule.

Verification-role rule (fires mint confirmed CWE-732 verdicts):
open() with O_CREAT but only two arguments reads uninitialised
stack data for the permission bits. The positive pins the two-arg
O_CREAT call; the negatives pin the mode-supplied call and a
two-arg open without O_CREAT (mode legitimately omitted).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "open_creat_no_mode.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_two_arg_o_creat_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int make_log(const char *path)
            {
                return open(path, O_CREAT | O_WRONLY);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "open_creat_no_mode"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_mode_supplied_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int make_log(const char *path)
            {
                return open(path, O_CREAT | O_WRONLY, 0600);
            }
        """)
        assert results == []

    def test_rdonly_without_creat_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int read_log(const char *path)
            {
                return open(path, O_RDONLY);
            }
        """)
        assert results == []
