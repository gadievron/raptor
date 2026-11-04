"""Fixture tests for the mmap_free rule.

Verification-role rule (fires mint confirmed CWE-762 verdicts):
mmap'd memory passed to free() corrupts heap allocator metadata —
it must be released with munmap(). The positive pins free on the
mapping; the negative pins the correct munmap release.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "mmap_free.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_free_of_mapping_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void load(int fd, unsigned long len)
            {
                char *map = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
                use(map);
                free(map);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "mmap_free"
        assert results[0]["line"] == 5


class TestNegatives:
    def test_munmap_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void load(int fd, unsigned long len)
            {
                char *map = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
                use(map);
                munmap(map, len);
            }
        """)
        assert results == []
