"""Fixture tests for the popen_fclose rule.

Verification-role rule (fires mint confirmed CWE-404 verdicts):
a popen() stream closed with fclose() leaves the child a zombie.
The positive pins the fclose misuse; the negative pins the correct
pclose() teardown.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "popen_fclose.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    return run_rule(tmp_path, source, rule)


class TestPositives:
    def test_fclose_on_popen_stream_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int run(const char *cmd)
            {
                void *fp = popen(cmd, "r");
                if (!fp)
                    return -1;
                fclose(fp);
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "popen_fclose"
        assert results[0]["line"] == 6


class TestNegatives:
    def test_pclose_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int run(const char *cmd)
            {
                void *fp = popen(cmd, "r");
                if (!fp)
                    return -1;
                pclose(fp);
                return 0;
            }
        """)
        assert results == []
