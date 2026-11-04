"""Fixture tests for the double_close rule.

Verification-role rule (fires mint confirmed CWE-675 verdicts):
closing the same fd twice without reassignment races against fd
reuse. The positive pins the back-to-back close pair; the negative
pins the rule's documented guard — fd reassigned (open) between
the closes.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "double_close.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_close_twice_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void teardown(int fd)
            {
                close(fd);
                close(fd);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "double_close"
        assert results[0]["line"] == 4


class TestNegatives:
    def test_reassigned_fd_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void recycle(int fd, const char *path)
            {
                close(fd);
                fd = open(path, 0);
                close(fd);
            }
        """)
        assert results == []
