"""Fixture tests for the realloc_losing_ptr rule.

Verification-role rule (fires mint confirmed CWE-401 verdicts):
ptr = realloc(ptr, n) loses the only handle to the original block
when realloc fails. The positive pins the self-assignment; the
negative pins the recommended temporary-variable shape.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "realloc_losing_ptr.cocci"
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
    def test_self_assignment_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int grow(char *buf, unsigned long n)
            {
                buf = realloc(buf, n);
                if (!buf)
                    return -1;
                return 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "realloc_losing_ptr"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_temporary_variable_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int grow(char **buf, unsigned long n)
            {
                char *tmp = realloc(*buf, n);
                if (!tmp)
                    return -1;
                *buf = tmp;
                return 0;
            }
        """)
        assert results == []
