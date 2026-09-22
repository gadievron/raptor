"""Fixture tests for the free_stack_array rule.

Verification-role rule (fires mint confirmed CWE-590 verdicts):
free() on a constant-size named array corrupts heap allocator
metadata. The positive pins free of a stack array; the negative
pins the legitimate malloc'd-pointer free.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "free_stack_array.cocci"
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
    def test_free_of_stack_array_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void scratch(void)
            {
                char buf[64];
                use(buf);
                free(buf);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "free_stack_array"
        assert results[0]["line"] == 5


class TestNegatives:
    def test_free_of_heap_pointer_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void scratch(void)
            {
                char *buf = malloc(64);
                use(buf);
                free(buf);
            }
        """)
        assert results == []
