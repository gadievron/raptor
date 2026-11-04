"""Fixture tests for the fcntl_flag_domain rule.

Verification-role rule (fires mint confirmed CWE-688 verdicts):
FD_CLOEXEC belongs to the F_SETFD domain and O_NONBLOCK to the
F_SETFL domain — crossing them silently sets the wrong bits. The
positives pin both cross-domain directions; the negatives pin the
two correct pairings.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "fcntl_flag_domain.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_setfl_with_fd_cloexec_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int set_cloexec(int fd)
            {
                return fcntl(fd, F_SETFL, FD_CLOEXEC);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "fcntl_flag_domain"
        assert results[0]["line"] == 3

    def test_setfd_with_o_nonblock_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int set_nonblock(int fd)
            {
                return fcntl(fd, F_SETFD, O_NONBLOCK);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "fcntl_flag_domain"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_setfd_with_fd_cloexec_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int set_cloexec(int fd)
            {
                return fcntl(fd, F_SETFD, FD_CLOEXEC);
            }
        """)
        assert results == []

    def test_setfl_with_o_nonblock_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int set_nonblock(int fd)
            {
                return fcntl(fd, F_SETFL, O_NONBLOCK);
            }
        """)
        assert results == []
