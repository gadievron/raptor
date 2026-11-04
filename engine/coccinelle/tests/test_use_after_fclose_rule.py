"""Fixture tests for the use_after_fclose rule.

Verification-role rule (fires mint confirmed CWE-416 verdicts):
stdio operations on a FILE* after fclose() are use-after-free. The
positive pins fprintf on the closed stream; the negative pins the
documented escape — the pointer reassigned (fopen) before reuse.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "use_after_fclose.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_fprintf_after_fclose_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void log_and_close(void *fp)
            {
                fclose(fp);
                fprintf(fp, "done\n");
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "use_after_fclose"
        assert results[0]["line"] == 4


class TestNegatives:
    def test_reassigned_stream_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void reopen(void *fp, const char *path)
            {
                fclose(fp);
                fp = fopen(path, "w");
                fprintf(fp, "fresh\n");
            }
        """)
        assert results == []
