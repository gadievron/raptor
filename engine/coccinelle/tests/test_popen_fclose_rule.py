"""Fixture tests for the popen_fclose rule.

Verification-role rule (fires mint confirmed CWE-404 verdicts):
a popen() stream closed with fclose() leaves the child a zombie.
The positive pins the fclose misuse; the negative pins the correct
pclose() teardown.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "popen_fclose.cocci"
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
