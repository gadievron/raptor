"""Fixture tests for the malloc_strlen_strcpy rule.

Verification-role rule (fires mint confirmed CWE-131 verdicts):
malloc(strlen(s)) is one byte short for the strcpy NUL write. The
positive pins the missing +1; the negative pins the corrected
strlen(s) + 1 allocation.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "malloc_strlen_strcpy.cocci"
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
    def test_missing_plus_one_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            char *dup_name(const char *name)
            {
                char *copy = malloc(strlen(name));
                strcpy(copy, name);
                return copy;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "malloc_strlen_strcpy"
        assert results[0]["line"] == 3


class TestNegatives:
    def test_strlen_plus_one_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            char *dup_name(const char *name)
            {
                char *copy = malloc(strlen(name) + 1);
                strcpy(copy, name);
                return copy;
            }
        """)
        assert results == []
