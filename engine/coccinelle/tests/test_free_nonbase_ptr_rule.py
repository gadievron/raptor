"""Fixture tests for the free_nonbase_ptr rule.

Subtracting offsetof() is container_of-style base recovery — a
correct walk BACK to the true allocation base — and is excluded from
the subtraction leg via an unflagged exception branch.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "free_nonbase_ptr.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_free_offset_pointer_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(char *p, int n)
            {
                free(p + n);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "free_nonbase_ptr"

    def test_free_minus_literal_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(char *p)
            {
                kfree(p - 1);
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_offsetof_base_recovery_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct wrap { int hdr; struct node node; };
            void put_node(struct node *n)
            {
                free((char *)n - offsetof(struct wrap, node));
            }
        """)
        assert results == []
