"""Fixture tests for the use_after_close rule.

Verification-role rule (fires mint confirmed CWE-672 verdicts):
fd operations after close() without reassignment target a
potentially reused descriptor. The positive pins read() on the
closed fd; the negative pins the fd reassigned (open) before the
read.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "use_after_close.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_read_after_close_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int drain(int fd, char *buf, unsigned long n)
            {
                close(fd);
                return read(fd, buf, n);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "use_after_close"
        assert results[0]["line"] == 4


class TestNegatives:
    def test_reassigned_fd_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int reopen_read(int fd, const char *path, char *buf,
                            unsigned long n)
            {
                close(fd);
                fd = open(path, 0);
                return read(fd, buf, n);
            }
        """)
        assert results == []
