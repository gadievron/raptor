"""Fixture tests for the malloc_strlen_strcpy rule.

Verification-role rule (fires mint confirmed CWE-131 verdicts):
malloc(strlen(s)) is one byte short for the strcpy NUL write. The
positive pins the missing +1; the negative pins the corrected
strlen(s) + 1 allocation.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "malloc_strlen_strcpy.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_missing_plus_one_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            char *dup_name(const char *name)
            {
                char *copy = malloc(strlen(name));
                strcpy(copy, name);
                return copy;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "malloc_strlen_strcpy"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_strlen_plus_one_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            char *dup_name(const char *name)
            {
                char *copy = malloc(strlen(name) + 1);
                strcpy(copy, name);
                return copy;
            }
        """)
        assert results == []
