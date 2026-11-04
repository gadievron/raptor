"""Fixture tests for the fdopendir_double_close rule.

Verification-role rule (fires mint confirmed CWE-675 verdicts):
closedir() on an fdopendir() stream already closes the underlying
fd, so an explicit close(fd) afterwards is a double close. The
positive pins that close; the negative pins the correct
closedir-only teardown.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "fdopendir_double_close.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_close_after_closedir_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void list_dir(int fd)
            {
                void *dir = fdopendir(fd);
                walk(dir);
                closedir(dir);
                close(fd);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "fdopendir_double_close"
        assert results[0]["line"] == 6


class TestNegatives:
    def test_closedir_only_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void list_dir(int fd)
            {
                void *dir = fdopendir(fd);
                walk(dir);
                closedir(dir);
            }
        """)
        assert results == []
