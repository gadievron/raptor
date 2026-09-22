"""Fixture tests for the va_arg_mismatch rule.

Verification-role rule (fires mint confirmed CWE-686 verdicts):
va_arg with a type that undergoes default argument promotion
(char/short/float) reads the wrong size from the stack. The
positive pins va_arg(ap, char) — reported id va_arg_promoted_type;
the negative pins the promoted-type va_arg(ap, int).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "va_arg_mismatch.cocci"
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
    def test_va_arg_char_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            char first_char(int count, ...)
            {
                va_list ap;
                char c;
                va_start(ap, count);
                c = va_arg(ap, char);
                va_end(ap);
                return c;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "va_arg_promoted_type"
        assert results[0]["line"] == 6


class TestNegatives:
    def test_va_arg_int_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int first_int(int count, ...)
            {
                va_list ap;
                int v;
                va_start(ap, count);
                v = va_arg(ap, int);
                va_end(ap);
                return v;
            }
        """)
        assert results == []
