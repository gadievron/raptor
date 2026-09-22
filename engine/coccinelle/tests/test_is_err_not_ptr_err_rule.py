"""Fixture tests for the is_err_not_ptr_err rule.

Verification-role rule (fires mint confirmed CWE-253 verdicts):
returning IS_ERR(p) from an error path yields boolean 1 instead of
the embedded errno. The positive pins return IS_ERR(p) inside the
IS_ERR check; the negative pins the correct return PTR_ERR(p).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "is_err_not_ptr_err.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(
    tmp_path: Path, source: str, rule: Path = _RULE,
) -> list[dict]:
    src = tmp_path / "target.c"
    src.write_text(textwrap.dedent(source), encoding="utf-8")
    proc = subprocess.run(  # noqa: S603 — fixed local binary, fixture input
        ["spatch", "--sp-file", str(rule), str(src), "--no-show-diff"],
        capture_output=True, text=True, timeout=120,
    )
    results = []
    for stream in (proc.stdout, proc.stderr):
        for line in stream.splitlines():
            if line.startswith("COCCIRESULT:"):
                results.append(json.loads(line[len("COCCIRESULT:"):]))
    return results


class TestPositives:
    def test_return_is_err_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int setup(struct dev *d)
            {
                void *clk = get_clk(d);
                if (IS_ERR(clk)) {
                    return IS_ERR(clk);
                }
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "is_err_not_ptr_err"
        assert results[0]["line"] == 5


class TestNegatives:
    def test_return_ptr_err_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int setup(struct dev *d)
            {
                void *clk = get_clk(d);
                if (IS_ERR(clk)) {
                    return PTR_ERR(clk);
                }
                return 0;
            }
        """)
        assert results == []
