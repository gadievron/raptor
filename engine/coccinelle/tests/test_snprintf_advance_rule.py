"""Fixture tests for the snprintf_advance rule.

The rules are some-path (`exists`): an advance guarded by the WRONG
condition (`if (n > 0) buf += n;`) is still unchecked on that path,
and the direct `buf += snprintf(...)` form leaves no room for any
check at all. Paths passing through `n >= remaining` stay excluded.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "snprintf_advance.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_plain_advance_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(char *buf, int remaining)
            {
                int n;
                n = snprintf(buf, remaining, "x");
                buf += n;
            }
        """)
        assert len(results) == 1

    def test_wrongly_guarded_advance_fires(self, tmp_path):
        # `n > 0` is a guard, but not the truncation check — the
        # advance is still unchecked on the taken path.
        results = _run_rule(tmp_path, """\
            void bug(char *buf, int remaining)
            {
                int n;
                n = snprintf(buf, remaining, "x");
                if (n > 0)
                    buf += n;
            }
        """)
        assert len(results) == 1

    def test_direct_advance_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(char *buf, int remaining)
            {
                buf += snprintf(buf, remaining, "x");
            }
        """)
        assert len(results) == 1
        assert "no truncation check possible" in results[0]["message"]


class TestNegatives:
    def test_truncation_checked_advance_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(char *buf, int remaining)
            {
                int n;
                n = snprintf(buf, remaining, "x");
                if (n >= remaining)
                    return;
                buf += n;
            }
        """)
        assert results == []

    def test_unused_return_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(char *buf, int remaining)
            {
                snprintf(buf, remaining, "x");
            }
        """)
        assert results == []
