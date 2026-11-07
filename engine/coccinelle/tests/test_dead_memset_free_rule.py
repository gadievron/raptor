"""Fixture tests for the dead_memset_free rule.

Detection-role rule (requires sensitivity and compiler evidence):
a memset immediately before free is a dead store the compiler may
elide, silently stripping a secret-clearing write. The positive
pins the clear-then-free pair; the negative pins the intervening-read exclusion; it does not prove that
the compiler retained an erasure.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "dead_memset_free.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_clear_then_free_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void discard_key(char *key, unsigned long len)
            {
                memset(key, 0, len);
                free(key);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "dead_memset_free"
        assert results[0]["line"] == 4


class TestNegatives:
    def test_read_between_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void archive_key(char *out, char *key, unsigned long len)
            {
                memset(key, 0, len);
                memcpy(out, key, len);
                free(key);
            }
        """)
        assert results == []


@pytest.mark.parametrize("length", ["0", "0UL", "0x0"])
def test_zero_byte_clear_is_not_an_erasure_optimization_candidate(tmp_path, length):
    rows=_run_rule(tmp_path, f"void f(void *buf) {{ memset(buf, 0, {length}); free(buf); }}")
    assert rows == []
